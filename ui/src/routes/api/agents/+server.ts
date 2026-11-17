// GET  /api/agents  →  agent registry with grants (broker admin API).
// POST /api/agents  →  register an agent (Day 12): {id, owner, display_name?, auth0_client_id?}
import { error, json } from '@sveltejs/kit';
import { broker, detail } from '$lib/server/broker';
import { AGENT_ID, AUTH0_CLIENT_ID, USER, forward, pick, readObject } from '$lib/server/forward';
import type { RequestHandler } from './$types';

export const GET: RequestHandler = async () => {
	const r = await broker<unknown[]>('/agents');
	if (!r.ok) return json({ detail: detail(r) }, { status: r.status || 502 });
	return json(r.data);
};

export const POST: RequestHandler = async ({ request, locals }) => {
	const body = pick(await readObject(request), ['id', 'owner', 'display_name', 'auth0_client_id']);
	if (typeof body.id !== 'string' || !AGENT_ID.test(body.id)) error(400, 'id: lower-case letters, digits, - and _ (2-64)');
	if (typeof body.owner !== 'string' || !USER.test(body.owner)) error(400, "owner must look like 'user:<name>'");
	// Day 13: optional, the Auth0 M2M application the agent logs in with
	if (body.auth0_client_id !== undefined && (typeof body.auth0_client_id !== 'string' || !AUTH0_CLIENT_ID.test(body.auth0_client_id)))
		error(400, "auth0_client_id: the Auth0 application's Client ID (8-64 letters, digits, - or _)");
	return forward(locals.admin!, '/agents', 'POST', body);
};
