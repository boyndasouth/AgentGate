// Day 13: how an agent gets its tokens.
//   PATCH /api/agents/{id}  {auth0_client_id: "<Auth0 M2M Client ID>" | null}
// A client id = the agent logs in as itself (POST /tokens/agent on the broker) and the
// orchestrator key can no longer mint its tokens; null = back to orchestrator-minted tokens.
// Either change revokes the tokens the agent holds now. Only this one field is forwarded:
// the kill switch has its own route.
import { error } from '@sveltejs/kit';
import { AGENT_ID, AUTH0_CLIENT_ID, forward, pick, readObject } from '$lib/server/forward';
import type { RequestHandler } from './$types';

export const PATCH: RequestHandler = async ({ params, request, locals }) => {
	if (!AGENT_ID.test(params.id)) error(400, 'bad agent id');
	const body = pick(await readObject(request), ['auth0_client_id']);
	const client = body.auth0_client_id;
	if (client !== null && (typeof client !== 'string' || !AUTH0_CLIENT_ID.test(client)))
		error(400, 'auth0_client_id: the Auth0 application\'s Client ID (8-64 letters, digits, - or _), or null');
	return forward(locals.admin!, `/agents/${params.id}`, 'PATCH', { auth0_client_id: client });
};
