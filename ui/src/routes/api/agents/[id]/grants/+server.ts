// Day 12: an agent's grants.
//   POST   /api/agents/{id}/grants  {tool, mode?, params?}
//   DELETE /api/agents/{id}/grants  {tool, mode?}
import { error } from '@sveltejs/kit';
import { AGENT_ID, TOOL_NAME, forward, pick, readObject } from '$lib/server/forward';
import type { RequestHandler } from './$types';

export const POST: RequestHandler = async ({ params, request, locals }) => {
	if (!AGENT_ID.test(params.id)) error(400, 'bad agent id');
	const body = pick(await readObject(request), ['tool', 'mode', 'params']);
	if (typeof body.tool !== 'string' || !TOOL_NAME.test(body.tool)) error(400, 'bad tool name');
	return forward(locals.admin!, `/agents/${params.id}/grants`, 'POST', body);
};

export const DELETE: RequestHandler = async ({ params, request, locals }) => {
	if (!AGENT_ID.test(params.id)) error(400, 'bad agent id');
	const body = pick(await readObject(request), ['tool', 'mode']);
	if (typeof body.tool !== 'string' || !TOOL_NAME.test(body.tool)) error(400, 'bad tool name');
	const q = new URLSearchParams({ tool: body.tool });
	if (typeof body.mode === 'string' && /^[a-z_]{1,40}$/.test(body.mode)) q.set('mode', body.mode);
	return forward(locals.admin!, `/agents/${params.id}/grants?${q}`, 'DELETE');
};
