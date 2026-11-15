// Kill switch: POST /api/agents/{id}/disable | /enable  →  broker admin API.
import { error, json } from '@sveltejs/kit';
import { broker, detail } from '$lib/server/broker';
import type { RequestHandler } from './$types';

const AGENT_ID = /^[a-z0-9_-]{1,64}$/;

export const POST: RequestHandler = async ({ params, locals }) => {
	const admin = locals.admin!;
	if (!AGENT_ID.test(params.id)) error(400, 'bad agent id');
	if (params.action !== 'disable' && params.action !== 'enable') error(404, 'unknown action');

	const path = `/agents/${encodeURIComponent(params.id)}/${params.action}`;
	const r =
		params.action === 'disable'
			? await broker(path, {
					method: 'POST',
					body: { reason: `kill switch (admin UI: ${admin.email ?? admin.sub})` }
				})
			: await broker(path, { method: 'POST' });

	if (!r.ok) return json({ detail: detail(r) }, { status: r.status || 502 });
	return json(r.data);
};
