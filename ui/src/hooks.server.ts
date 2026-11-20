import { error, json, redirect, type Handle } from '@sveltejs/kit';
import { sequence } from '@sveltejs/kit/hooks';
import { handle as authHandle } from './auth';
import { adminFromSession } from '$lib/server/admin';
import { env } from '$env/dynamic/private';

// Fail loudly at startup on missing or malformed config instead of a stack trace at login.
const REQUIRED = ['AUTH_SECRET', 'AUTH_AUTH0_ID', 'AUTH_AUTH0_SECRET', 'AUTH_AUTH0_ISSUER', 'ADMIN_USERS', 'BROKER_URL', 'AGENTGATE_ADMIN_KEY'];
for (const name of REQUIRED) {
	if (!env[name]?.trim()) console.error(`[agentgate-ui] ${name} is not set (see ui/.env.example)`);
}
for (const name of ['AUTH_AUTH0_ISSUER', 'BROKER_URL']) {
	const v = env[name]?.trim();
	if (v && !/^https?:\/\/[^\s#]+$/.test(v)) console.error(`[agentgate-ui] ${name} is not a URL: "${v}"`);
}
if (env.AUTH_AUTH0_ISSUER && !env.AUTH_AUTH0_ISSUER.trim().endsWith('/')) {
	console.error('[agentgate-ui] AUTH_AUTH0_ISSUER should end with "/" (e.g. https://dev-xxxx.us.auth0.com/)');
}

// Paths that work without an admin session. /tour is a static replay of a recorded run: it reads no
// broker data, so it needs no key and no login. /api/sandbox is the tour's "Try it yourself" panel: fixed
// scripted runs against sandbox agents only (lib/server/sandbox.ts); off unless AGENTGATE_SANDBOX=1.
const PUBLIC = ['/auth', '/login', '/signout', '/denied', '/tour', '/api/sandbox'];

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
