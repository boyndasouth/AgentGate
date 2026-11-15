// Browser-side helper for the app's own /api routes (same origin, session cookie).
export interface ApiResult<T> {
	ok: boolean;
	status: number;
	data: T;
	error?: string;
}

export async function api<T = unknown>(path: string, init: { method?: string; body?: unknown } = {}): Promise<ApiResult<T>> {
	try {
		const res = await fetch(path, {
			method: init.method ?? 'GET',
			headers: init.body === undefined ? {} : { 'content-type': 'application/json' },
			body: init.body === undefined ? undefined : JSON.stringify(init.body)
		});
		const text = await res.text();
		let data: unknown = null;
		try {
			data = text ? JSON.parse(text) : null;
		} catch {
			data = { detail: text.slice(0, 300) };
		}
		const d = data as { detail?: string; message?: string } | null;
		// Only our own hook's 401 means the admin session is gone. Redirect once.
		if (res.status === 401 && d?.detail === 'not signed in' && location.pathname !== '/login') {
			location.href = '/login';
		}
		return {
			ok: res.ok,
			status: res.status,
			data: data as T,
			error: res.ok ? undefined : (d?.detail ?? d?.message ?? `HTTP ${res.status}`)
		};
	} catch (e) {
		return { ok: false, status: 0, data: null as T, error: e instanceof Error ? e.message : String(e) };
	}
}

export function timeAgo(iso: string | undefined | null): string {
	if (!iso) return '';
	const t = Date.parse(iso);
	if (Number.isNaN(t)) return iso;
	const s = Math.round((Date.now() - t) / 1000);
	if (s < 60) return `${s}s ago`;
	if (s < 3600) return `${Math.floor(s / 60)}m ago`;
	return new Date(t).toLocaleTimeString();
}

export function clock(iso: string | undefined | null): string {
	if (!iso) return '';
	const t = Date.parse(iso);
	return Number.isNaN(t) ? iso : new Date(t).toLocaleTimeString([], { hour12: false });
}
