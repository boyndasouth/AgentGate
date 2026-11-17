// Day 12: PATCH /api/tools/{name}  →  change a registry row (e.g. {enabled: false}).
import { error } from '@sveltejs/kit';
import { TOOL_FIELDS, TOOL_NAME, forward, pick, readObject } from '$lib/server/forward';
import type { RequestHandler } from './$types';

export const PATCH: RequestHandler = async ({ params, request, locals }) => {
	if (!TOOL_NAME.test(params.name)) error(400, 'bad tool name');
	const body = pick(await readObject(request), TOOL_FIELDS.filter((f) => f !== 'name'));
	return forward(locals.admin!, `/tools/${params.name}`, 'PATCH', body);
};
