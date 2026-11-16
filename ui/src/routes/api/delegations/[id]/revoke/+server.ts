// POST /api/delegations/{id}/revoke  →  broker admin API (Day 10). Revokes the delegation and
// everything granted from it; tokens using them stop working at once.
import { error, json } from '@sveltejs/kit';
import { broker, detail } from '$lib/server/broker';
import type { RequestHandler } from './$types';

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export const POST: RequestHandler = async ({ params, locals }) => {
	const admin = locals.admin!;
	if (!UUID.test(params.id)) error(400, 'bad delegation id');
	const r = await broker(`/delegations/${params.id}/revoke`, {
		method: 'POST',
		body: { reason: `revoked in the admin UI by ${admin.email ?? admin.sub}`.slice(0, 200) }
	});
	if (!r.ok) return json({ detail: detail(r) }, { status: r.status || 502 });
	return json(r.data);
};
