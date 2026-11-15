// GET /api/agents  →  agent registry from the broker (admin API).
import { json } from '@sveltejs/kit';
import { broker, detail } from '$lib/server/broker';
import type { RequestHandler } from './$types';

export const GET: RequestHandler = async () => {
	const r = await broker<unknown[]>('/agents');
	if (!r.ok) return json({ detail: detail(r) }, { status: r.status || 502 });
	return json(r.data);
};
