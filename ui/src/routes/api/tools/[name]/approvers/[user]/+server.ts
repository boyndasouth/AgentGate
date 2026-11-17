// Day 12: DELETE /api/tools/{name}/approvers/{user}
import { error } from '@sveltejs/kit';
import { TOOL_NAME, USER, forward } from '$lib/server/forward';
import type { RequestHandler } from './$types';

export const DELETE: RequestHandler = async ({ params, locals }) => {
	if (!TOOL_NAME.test(params.name) || !USER.test(params.user)) error(400, 'bad tool or user');
	return forward(locals.admin!, `/tools/${params.name}/approvers/${encodeURIComponent(params.user)}`, 'DELETE');
};
