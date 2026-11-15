// GET /api/events?limit=50  →  newest audit events (polling fallback for Realtime).
import { json } from '@sveltejs/kit';
import { broker, detail } from '$lib/server/broker';
import type { RequestHandler } from './$types';

export const GET: RequestHandler = async ({ url }) => {
	const limit = Math.min(Math.max(Number(url.searchParams.get('limit')) || 50, 1), 200);
	const r = await broker<unknown[]>(`/audit/events?limit=${limit}`);
	if (!r.ok) return json({ detail: detail(r) }, { status: r.status || 502 });
	return json(r.data);
};
