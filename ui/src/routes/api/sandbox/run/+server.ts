// POST /api/sandbox/run  { scenario }  →  one fixed scripted run against the sandbox agents. Public.
// The agent token of the last run is kept in an httpOnly cookie so the same visitor can decide its approval.
import { error, json } from '@sveltejs/kit';
import { SANDBOX_SCENARIOS, allow, runSandbox, sandboxEnabled, type SandboxScenario } from '$lib/server/sandbox';
import type { RequestHandler } from './$types';

const COOKIE = 'ag_sbx_token';

export const POST: RequestHandler = async ({ request, cookies, url, getClientAddress }) => {
	if (!sandboxEnabled()) error(404, 'the sandbox is not enabled on this deployment');
	const body = await request.json().catch(() => null);
	const scenario = body?.scenario;
	if (typeof scenario !== 'string' || !(SANDBOX_SCENARIOS as readonly string[]).includes(scenario)) error(400, 'unknown scenario');
	if (!allow(getClientAddress())) error(429, 'slow down: too many runs from this address, try again in a few minutes');

	const result = await runSandbox(scenario as SandboxScenario);
	if (result.keepToken) {
		cookies.set(COOKIE, result.keepToken, {
			path: '/api/sandbox',
			httpOnly: true,
			sameSite: 'strict',
			secure: url.protocol === 'https:',
			maxAge: 600
		});
	}
	const { keepToken: _, ...publicResult } = result;
	return json(publicResult);
};
