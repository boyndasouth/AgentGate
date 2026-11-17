// Day 12: forwarding admin writes (agents, grants, tools) to the broker.
// The browser sends a JSON body; the server checks its shape lightly, adds the admin key and
// X-Admin-Via (the signed-in Auth0 account, never taken from the browser) and returns the
// broker's answer. The broker does the real validation.
import { error, json } from '@sveltejs/kit';
import { approvalVia, type AdminIdentity } from './admin';
import { broker, detail } from './broker';

export const AGENT_ID = /^[a-z][a-z0-9_-]{1,63}$/;
export const TOOL_NAME = /^[a-z][a-z0-9_.]{1,63}$/;
export const AUTH0_CLIENT_ID = /^[A-Za-z0-9_-]{8,64}$/;   // Day 13
export const USER = /^(user:)?[a-z0-9][a-z0-9_.-]{0,63}$/;
export const TOOL_FIELDS = ['name', 'description', 'args_schema', 'risk_class', 'context_map', 'taints_session',
	'upstream', 'credential_ref', 'enabled'];

export async function readObject(request: Request): Promise<Record<string, unknown>> {
	const body = await request.json().catch(() => null);
	if (!body || typeof body !== 'object' || Array.isArray(body)) error(400, 'body must be a JSON object');
	return body as Record<string, unknown>;
}

export function pick(body: Record<string, unknown>, allowed: string[]): Record<string, unknown> {
	const extra = Object.keys(body).filter((k) => !allowed.includes(k));
	if (extra.length) error(400, `unexpected field(s): ${extra.join(', ')}`);
	return body;
}

export async function forward(admin: AdminIdentity, path: string, method: string, body?: unknown) {
	const r = await broker(path, { method, body, via: approvalVia(admin.sub) });
	if (!r.ok) return json({ detail: detail(r) }, { status: r.status || 502 });
	return json(r.data, { status: r.status });
}
