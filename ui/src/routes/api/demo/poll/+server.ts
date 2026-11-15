// GET /api/demo/poll?id=<approval uuid>  →  the agent's view of its pending approval.
import { error, json } from '@sveltejs/kit';
import { pollApproval } from '$lib/server/demo';
import type { RequestHandler } from './$types';

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export const GET: RequestHandler = async ({ url, cookies }) => {
	const id = url.searchParams.get('id') ?? '';
	if (!UUID.test(id)) error(400, 'bad approval id');
	const token = cookies.get('ag_demo_token');
	if (!token) error(409, 'no agent token held for this approval');
	const { raw: _, ...r } = await pollApproval(token, id);
	return json(r);
};
