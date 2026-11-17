// Day 12: POST /api/tools/{name}/approvers {user}  →  who may approve this tool's escalations.
import { error } from '@sveltejs/kit';
import { TOOL_NAME, USER, forward, pick, readObject } from '$lib/server/forward';
import type { RequestHandler } from './$types';

export const POST: RequestHandler = async ({ params, request, locals }) => {
	if (!TOOL_NAME.test(params.name)) error(400, 'bad tool name');
	const body = pick(await readObject(request), ['user']);
	if (typeof body.user !== 'string' || !USER.test(body.user)) error(400, "user must look like 'user:<name>'");
	return forward(locals.admin!, `/tools/${params.name}/approvers`, 'POST', body);
};
