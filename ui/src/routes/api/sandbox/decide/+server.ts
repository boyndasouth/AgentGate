// POST /api/sandbox/decide  { id, approve }  →  the visitor plays the human approver. Public.
// Decided as user:demo-visitor, an approver of the sbx.* sandbox tools only (see lib/server/sandbox.ts).
import { error, json } from '@sveltejs/kit';
import { allow, decide, sandboxEnabled } from '$lib/server/sandbox';
import type { RequestHandler } from './$types';

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export const POST: RequestHandler = async ({ request, cookies, getClientAddress }) => {
	if (!sandboxEnabled()) error(404, 'the sandbox is not enabled on this deployment');
	const body = await request.json().catch(() => null);
	if (!body || typeof body.id !== 'string' || !UUID.test(body.id) || typeof body.approve !== 'boolean') {
		error(400, 'body must be { id: <approval uuid>, approve: boolean }');
	}
	const token = cookies.get('ag_sbx_token');
	if (!token) error(409, 'run a scenario first: no agent is waiting on you');
	if (!allow(getClientAddress())) error(429, 'slow down: too many requests from this address');

	const r = await decide(token, body.id, body.approve);
	if (!r.ok) return json({ detail: r.detail }, { status: r.status });
	return json({ state: r.state, agentSays: r.agentSays, reason: r.reason });
};
