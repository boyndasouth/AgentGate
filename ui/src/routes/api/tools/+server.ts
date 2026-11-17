// Day 12: the tool registry.
//   GET  /api/tools   →  every row as the gate sees it, with its problem and approvers
//   POST /api/tools   →  register a tool
import { error, json } from '@sveltejs/kit';
import { broker, detail } from '$lib/server/broker';
import { TOOL_FIELDS, TOOL_NAME, forward, pick, readObject } from '$lib/server/forward';
import type { RequestHandler } from './$types';

export const GET: RequestHandler = async () => {
	const r = await broker<unknown[]>('/tools');
	if (!r.ok) return json({ detail: detail(r) }, { status: r.status || 502 });
	return json(r.data);
};

export const POST: RequestHandler = async ({ request, locals }) => {
	const body = pick(await readObject(request), TOOL_FIELDS);
	if (typeof body.name !== 'string' || !TOOL_NAME.test(body.name)) error(400, 'name: lower-case letters, digits, _ and . (2-64)');
	return forward(locals.admin!, '/tools', 'POST', body);
};
