// GET /api/verify  →  broker recomputes the whole hash chain.
import { json } from '@sveltejs/kit';
import { broker, detail } from '$lib/server/broker';
import type { RequestHandler } from './$types';

export const GET: RequestHandler = async () => {
	const r = await broker('/audit/verify');
	if (!r.ok && r.status !== 409) return json({ detail: detail(r) }, { status: r.status || 502 });
	return json(r.data);
};
