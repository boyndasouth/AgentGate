import { error, json, redirect, type Handle } from '@sveltejs/kit';
import { sequence } from '@sveltejs/kit/hooks';
import { handle as authHandle } from './auth';
import { adminFromSession } from '$lib/server/admin';

// Paths that work without an admin session.
const PUBLIC = ['/auth', '/login', '/signout', '/denied'];

const guard: Handle = async ({ event, resolve }) => {
	const path = event.url.pathname;
	const isPublic = PUBLIC.some((p) => path === p || path.startsWith(p + '/'));
	const isApi = path.startsWith('/api/');

	// API writes must come from this origin (JSON bodies already need a CORS
	// preflight we never answer; this is a second, explicit check).
	if (isApi && event.request.method !== 'GET') {
		const origin = event.request.headers.get('origin');
		if (origin !== event.url.origin) error(403, 'cross-origin request refused');
	}

	if (isPublic) {
		event.locals.admin = null;
		return resolve(event);
	}

	const session = await event.locals.auth();
	if (!session) {
		if (isApi) return json({ detail: 'not signed in' }, { status: 401 });
		redirect(303, '/login');
	}

	const admin = adminFromSession(session);
	if (!admin) {
		if (isApi) return json({ detail: 'not an AgentGate admin' }, { status: 403 });
		redirect(303, '/denied');
	}
	event.locals.admin = admin;

	const response = await resolve(event);
	response.headers.set('cache-control', 'no-store');
	response.headers.set('x-frame-options', 'DENY');
	response.headers.set('referrer-policy', 'same-origin');
	return response;
};

export const handle = sequence(authHandle, guard);
