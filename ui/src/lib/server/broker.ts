// Server-only client for the AgentGate broker.
// The admin and orchestrator keys live in server env vars and never reach the browser.
import { env } from '$env/dynamic/private';

export type BrokerAuth = 'admin' | 'orchestrator' | 'none' | { bearer: string };

export interface BrokerResponse<T = unknown> {
	status: number; // 0 = network error / timeout
	ok: boolean;
	data: T;
	error?: string;
}

export function brokerConfigured(): boolean {
	return Boolean(env.BROKER_URL && env.AGENTGATE_ADMIN_KEY);
}

export function demoConfigured(): boolean {
	return Boolean(env.BROKER_URL && env.AGENTGATE_ORCHESTRATOR_KEY);
}

export async function broker<T = unknown>(
	path: string,
	opts: { method?: string; body?: unknown; auth?: BrokerAuth; timeoutMs?: number; via?: string } = {}
): Promise<BrokerResponse<T>> {
	const base = (env.BROKER_URL ?? '').replace(/\/+$/, '');
	if (!base) return { status: 0, ok: false, data: null as T, error: 'BROKER_URL is not set' };

	const headers: Record<string, string> = { accept: 'application/json' };
	const auth = opts.auth ?? 'admin';
	if (auth === 'admin') headers['X-Admin-Key'] = env.AGENTGATE_ADMIN_KEY ?? '';
	else if (auth === 'orchestrator') headers['X-Orchestrator-Key'] = env.AGENTGATE_ORCHESTRATOR_KEY ?? '';
	else if (typeof auth === 'object') headers['Authorization'] = `Bearer ${auth.bearer}`;
	if (opts.body !== undefined) headers['content-type'] = 'application/json';
	// Day 12: who made an admin change, for the audit log ('admin-ui:<Auth0 sub>', see approvalVia).
	if (opts.via && auth === 'admin') headers['X-Admin-Via'] = opts.via;

	try {
		const res = await fetch(base + path, {
			method: opts.method ?? 'GET',
			headers,
			body: opts.body === undefined ? undefined : JSON.stringify(opts.body),
			// Render's free tier can take ~60 s to wake up.
			signal: AbortSignal.timeout(opts.timeoutMs ?? 55_000)
		});
		const text = await res.text();
		let data: unknown = null;
		try {
			data = text ? JSON.parse(text) : null;
		} catch {
			data = { detail: text.slice(0, 500) };
		}
		// A 401 from the broker means *our* key is wrong, not that the admin's
		// login expired. Report it as a 502 config error so the browser never
		// mistakes it for a sign-out (which caused a /login redirect loop).
		if (res.status === 401 && (auth === 'admin' || auth === 'orchestrator')) {
			const which = auth === 'admin' ? 'AGENTGATE_ADMIN_KEY' : 'AGENTGATE_ORCHESTRATOR_KEY';
			const msg = `broker rejected the UI's ${which} (check ui/.env or Vercel env, then restart)`;
			return { status: 502, ok: false, data: { detail: msg } as T, error: msg };
		}
		return { status: res.status, ok: res.ok, data: data as T };
	} catch (e) {
		const msg = e instanceof Error ? e.message : String(e);
		return { status: 0, ok: false, data: null as T, error: `broker unreachable: ${msg}` };
	}
}

/** Pull a human-readable message out of a broker error body. */
export function detail(r: BrokerResponse): string {
	const d = r.data as Record<string, unknown> | null;
	if (r.error) return r.error;
	if (d && typeof d === 'object') {
		for (const k of ['detail', 'reason', 'message', 'error']) {
			if (typeof d[k] === 'string' && d[k]) return d[k] as string;
		}
	}
	return `HTTP ${r.status}`;
}
