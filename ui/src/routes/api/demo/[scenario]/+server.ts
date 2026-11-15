// POST /api/demo/{scenario}  →  scripted agent run (no LLM).
// The last agent token is kept in an httpOnly cookie scoped to /api/demo, so
// the browser can't read it; it is used for approval polling and the kill-switch retry.
import { error, json } from '@sveltejs/kit';
import { demoConfigured } from '$lib/server/broker';
import { SCENARIOS, runScenario, type Scenario } from '$lib/server/demo';
import type { RequestHandler } from './$types';

const COOKIE = 'ag_demo_token';

export const POST: RequestHandler = async ({ params, cookies, url }) => {
	if (!demoConfigured()) error(501, 'Demo runner disabled: set AGENTGATE_ORCHESTRATOR_KEY');
	if (!(SCENARIOS as readonly string[]).includes(params.scenario)) error(404, 'unknown scenario');

	const result = await runScenario(params.scenario as Scenario, cookies.get(COOKIE));
	if (result.keepToken) {
		cookies.set(COOKIE, result.keepToken, {
			path: '/api/demo',
			httpOnly: true,
			sameSite: 'strict',
			secure: url.protocol === 'https:',
			maxAge: 600
		});
	}
	const { keepToken: _, ...publicResult } = result;
	return json(publicResult);
};
