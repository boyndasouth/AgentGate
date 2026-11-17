// Smoke test: loads the UI's server modules through Vite (so $env works) and
// runs every demo beat against tests/mock_broker.py.
// Usage: python tests/mock_broker.py 8765 &  then  node tests/smoke.mjs
import { createServer } from 'vite';

process.env.BROKER_URL = 'http://127.0.0.1:8765';
process.env.AGENTGATE_ADMIN_KEY = 'admin-key';
process.env.AGENTGATE_ORCHESTRATOR_KEY = 'orch-key';
process.env.ADMIN_USERS = 'auth0|admin1,boss@example.com';
process.env.APPROVERS = 'auth0|admin1=shiwin';

const vite = await createServer({ server: { middlewareMode: true }, appType: 'custom', logLevel: 'error' });
const demo = await vite.ssrLoadModule('/src/lib/server/demo.ts');
const { broker } = await vite.ssrLoadModule('/src/lib/server/broker.ts');
const { adminFromSession, approvalVia } = await vite.ssrLoadModule('/src/lib/server/admin.ts');

let fails = 0;
const check = (name, ok, extra = '') => {
	console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${extra ? '  · ' + extra : ''}`);
	if (!ok) fails++;
};
const last = (r) => r.steps.at(-1);

// admin allowlist / approver mapping
const s = (sub, email, verified) => ({ auth0Sub: sub, emailVerified: verified, user: { email } });
check('allowlisted sub is admin + approver', adminFromSession(s('auth0|admin1', 'x@y.z', false))?.fgaUser === 'shiwin');
check('verified allowlisted email is admin', adminFromSession(s('auth0|zz', 'Boss@example.com', true))?.fgaUser === null);
check('unverified email is not admin', adminFromSession(s('auth0|zz', 'boss@example.com', false)) === null);
check('stranger is not admin', adminFromSession(s('auth0|evil', 'e@x.com', true)) === null);
check('no session is not admin', adminFromSession(null) === null);

// beat 1: $40
const pay = await demo.runScenario('pay');
check('pay $40 → allow', last(pay).outcome === 'allow', pay.agentSays);
check('pay: accounts payable adds the invoice first', pay.steps[0]?.actor === 'accounts payable' && pay.steps[0]?.outcome === 'allow', pay.steps[0]?.reason);
check('pay: the payment names that invoice', /INV-/.test(pay.agentSays), pay.agentSays);
// Day 10: grants come from the broker (OpenFGA), not a copy in the UI
const { describeGrant } = await vite.ssrLoadModule('/src/lib/grants.ts');
const ag = await broker('/agents');
const fin = ag.data?.find((a) => a.id === 'finance');
check('agents carry grants from the broker', Array.isArray(fin?.grants) && fin.grants.length === 2, JSON.stringify(fin));
check('payment grant worded from the policy', /≤ \$100.*acct_acme_supplies.*open invoice/.test(describeGrant(fin.grants[0])), describeGrant(fin.grants[0]));
check('approval grant names the approver', describeGrant(fin.grants[1]) === 'a human decides (shiwin)', describeGrant(fin.grants[1]));
check('unknown condition still shown', describeGrant({ tool: 't', mode: 'direct', condition: 'new_rule' }) === 'condition: new_rule');

// beat 2: $5,000 → escalate → deny → agent reports refusal
const big = await demo.runScenario('big');
check('pay $5,000 → escalate', last(big).outcome === 'escalate' && !!big.approvalId);
let p = await demo.pollApproval(big.keepToken, big.approvalId);
check('agent poll sees pending', p.state === 'pending');
// Day 8: the UI names the clicking Auth0 account in `via`; only 'admin-ui:…' labels are accepted
check('via label from an Auth0 sub', approvalVia('auth0|admin1') === 'admin-ui:auth0|admin1');
check('via label strips odd characters', approvalVia('waad|a b/c\n') === 'admin-ui:waad|a_b_c_');
const forged = await broker(`/approvals/${big.approvalId}/decision`, { method: 'POST', body: { approve: true, approver: 'user:shiwin', via: 'slack:U123' } });
check('forged via label is rejected', forged.status === 400, JSON.stringify(forged.data));
const dec = await broker(`/approvals/${big.approvalId}/decision`, { method: 'POST', body: { approve: false, approver: 'user:shiwin', via: approvalVia('auth0|admin1') } });
check('deny from the UI', dec.ok, JSON.stringify(dec.data));
const trail = await broker('/audit/events');
check('audit names the Auth0 account', trail.data?.[0]?.approver === 'user:shiwin via admin-ui:auth0|admin1', trail.data?.[0]?.approver);
p = await demo.pollApproval(big.keepToken, big.approvalId);
check('agent poll sees denied', p.state === 'denied', p.agentSays);

// beat 3: injection
const inj = await demo.runScenario('inject');
const read = inj.steps.find((x) => x.action.startsWith('read_web'));
check('inject: read_web allowed', read?.outcome === 'allow');
check('inject: mailer token reports taint', inj.steps.find((x) => x.actor === 'mailer' && x.action.startsWith('get token'))?.sessionTainted === true);
check('inject: exfil send_email escalates', last(inj).outcome === 'escalate' && /taint/.test(last(inj).reason), last(inj).reason);

// beat 5: kill switch on a held token
const ks = await demo.runScenario('kill-start');
check('kill-start: mailer call allowed', last(ks).outcome === 'allow');
await new Promise((r) => setTimeout(r, 20));
const dis = await broker('/agents/mailer/disable', { method: 'POST', body: { reason: 'test' } });
check('disable mailer', dis.ok);
const kr = await demo.runScenario('kill-retry', ks.keepToken);
check('kill-retry: same token denied', last(kr).outcome === 'deny', kr.agentSays);
const kr2 = await demo.runScenario('kill-retry', undefined);
check('kill-retry without token explains', kr2.steps.length === 0 && /first/.test(kr2.agentSays));
await broker('/agents/mailer/enable', { method: 'POST' });

// Day 12: registering agents and tools, grants, approvers through the UI's server routes
const admin = adminFromSession(s('auth0|admin1', 'x@y.z', false));
const call = async (file, method, { params = {}, body } = {}) => {
	const mod = await vite.ssrLoadModule(file);
	const request = new Request('http://ui.test/x', { method, headers: { 'content-type': 'application/json' }, body: body === undefined ? undefined : JSON.stringify(body) });
	try {
		const res = await mod[method]({ params, request, locals: { admin } });
		return { status: res.status, data: await res.json() };
	} catch (e) {
		return { status: e?.status ?? 500, data: e?.body ?? String(e) };
	}
};
const vias = async () => (await (await fetch('http://127.0.0.1:8765/__via', { method: 'DELETE' })).json());
let r = await call('/src/routes/api/agents/+server.ts', 'POST', { body: { id: 'support-bot', owner: 'user:shiwin', display_name: 'Support bot' } });
check('register agent → 201', r.status === 201, JSON.stringify(r.data));
check('  ... the broker got X-Admin-Via from the session', (await vias()).at(-1) === 'admin-ui:auth0|admin1');
r = await call('/src/routes/api/agents/+server.ts', 'POST', { body: { id: 'support-bot', owner: 'user:shiwin' } });
check('register it twice → 409 passed through', r.status === 409);
r = await call('/src/routes/api/agents/+server.ts', 'POST', { body: { id: 'Bad/Id', owner: 'user:shiwin' } });
check('bad agent id refused by the UI server', r.status === 400);
r = await call('/src/routes/api/agents/+server.ts', 'POST', { body: { id: 'x-bot', owner: 'user:shiwin', via: 'slack:U1' } });
check('a browser can\'t smuggle extra fields (via)', r.status === 400);
r = await call('/src/routes/api/tools/+server.ts', 'POST', { body: { name: 'crm.update_ticket', risk_class: 'write', args_schema: {}, upstream: { kind: 'http' } } });
check('register tool → 201', r.status === 201, JSON.stringify(r.data));
r = await call('/src/routes/api/agents/[id]/grants/+server.ts', 'POST', { params: { id: 'support-bot' }, body: { tool: 'send_email' } });
check('grant on an egress tool without a mode → approval', r.status === 201 && r.data.mode === 'approval' && r.data.defaulted, JSON.stringify(r.data));
r = await call('/src/routes/api/agents/[id]/grants/+server.ts', 'POST', { params: { id: 'support-bot' }, body: { tool: 'transfer_funds', mode: 'direct' } });
check('direct grant on a money tool comes back with a warning', r.status === 201 && /money/.test(r.data.warning ?? ''), JSON.stringify(r.data));
const { directWarning, defaultMode, paramsFor } = await vite.ssrLoadModule('/src/lib/grants.ts');
check('UI warns before a direct grant on a risky tool', /without a human/.test(directWarning('destructive', 'direct')) && directWarning('read', 'direct') === null);
check('UI default mode matches the broker', defaultMode('money') === 'approval' && defaultMode('write') === 'direct_if_untainted' && defaultMode('read') === 'direct');
check('params from the form', JSON.stringify(paramsFor('direct_known_payee_with_invoice', { max_amount: '100', allowed_payees: 'a, b' })) === '{"max_amount":100,"allowed_payees":["a","b"]}');
const ag2 = await broker('/agents');
const bot = ag2.data.find((a) => a.id === 'support-bot');
check('agents list shows the API grants with risk class and source', bot?.grants?.length === 2 && bot.grants.every((x) => x.source === 'api' && x.risk_class));
r = await call('/src/routes/api/agents/[id]/grants/+server.ts', 'DELETE', { params: { id: 'support-bot' }, body: { tool: 'transfer_funds', mode: 'direct' } });
check('remove a grant → 200', r.status === 200, JSON.stringify(r.data));
r = await call('/src/routes/api/tools/[name]/+server.ts', 'PATCH', { params: { name: 'send_email' }, body: { enabled: false } });
check('switch a tool off → 200', r.status === 200 && r.data.enabled === false);
r = await call('/src/routes/api/tools/[name]/+server.ts', 'PATCH', { params: { name: 'send_email' }, body: { name: 'x' } });
check('PATCH can\'t rename a tool', r.status === 400);
r = await call('/src/routes/api/tools/[name]/approvers/+server.ts', 'POST', { params: { name: 'send_email' }, body: { user: 'user:alex' } });
check('add an approver → 201', r.status === 201);
r = await call('/src/routes/api/tools/[name]/approvers/[user]/+server.ts', 'DELETE', { params: { name: 'send_email', user: 'user:alex' } });
check('remove an approver → 200', r.status === 200);
r = await call('/src/routes/api/tools/+server.ts', 'GET');
check('tools list', r.status === 200 && r.data.some((t) => t.name === 'crm.update_ticket'));

// broker down (the runner stops the mock first; $env is a startup snapshot)
await fetch('http://127.0.0.1:8765/__stop').catch(() => {});
await new Promise((r) => setTimeout(r, 300));
const down = await broker('/health', { auth: 'none' });
check('broker down → status 0, no throw', down.status === 0 && /unreachable/.test(down.error));

await vite.close();
console.log(fails ? `\n${fails} FAILED` : '\nall passed');
process.exit(fails ? 1 : 0);
