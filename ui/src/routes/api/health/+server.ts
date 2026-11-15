// GET /api/health  →  wakes the Render broker and reports how long it took.
import { json } from '@sveltejs/kit';
import { broker, detail } from '$lib/server/broker';
import type { RequestHandler } from './$types';

export const GET: RequestHandler = async () => {
	const started = Date.now();
	const r = await broker('/health', { auth: 'none' });
	const ms = Date.now() - started;
	if (!r.ok) return json({ ok: false, ms, detail: detail(r) }, { status: 502 });
	return json({ ok: true, ms, health: r.data });
};
