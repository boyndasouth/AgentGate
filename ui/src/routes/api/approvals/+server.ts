// GET /api/approvals  →  pending approvals from the broker (admin API).
import { json } from '@sveltejs/kit';
import { broker, detail } from '$lib/server/broker';
import type { RequestHandler } from './$types';

export const GET: RequestHandler = async () => {
	const r = await broker<unknown[]>('/approvals?status=pending&limit=50');
	if (!r.ok) return json({ detail: detail(r) }, { status: r.status || 502 });
	return json(r.data);
};
