// POST /api/approvals/{id}  { approve: boolean }
// The approver is never taken from the browser: it comes from the Auth0
// session → APPROVERS mapping, and the broker still asks OpenFGA whether that
// user is an approver on the tool (same check as a Slack click).
import { error, json } from '@sveltejs/kit';
import { broker, detail } from '$lib/server/broker';
import type { RequestHandler } from './$types';

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export const POST: RequestHandler = async ({ params, request, locals }) => {
	const admin = locals.admin!;
	if (!UUID.test(params.id)) error(400, 'bad approval id');
	if (!admin.fgaUser) {
		return json(
			{ detail: 'Your account has no approver mapping (APPROVERS). You can watch, but not decide.' },
			{ status: 403 }
		);
	}

	const body = await request.json().catch(() => null);
	if (!body || typeof body.approve !== 'boolean') error(400, 'body must be { approve: boolean }');

	const r = await broker(`/approvals/${params.id}/decision`, {
		method: 'POST',
		// The broker's DecisionRequest is strict ({approve, approver} only) and
		// records "user:X via admin-api".
		// TODO: record the Auth0 sub too, once the broker accepts a `via` field.
		body: { approve: body.approve, approver: `user:${admin.fgaUser}` }
	});
	if (!r.ok) return json({ detail: detail(r) }, { status: r.status || 502 });
	return json(r.data);
};
