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

// broker down (the runner stops the mock first; $env is a startup snapshot)
await fetch('http://127.0.0.1:8765/__stop').catch(() => {});
await new Promise((r) => setTimeout(r, 300));
const down = await broker('/health', { auth: 'none' });
check('broker down → status 0, no throw', down.status === 0 && /unreachable/.test(down.error));

await vite.close();
console.log(fails ? `\n${fails} FAILED` : '\nall passed');
process.exit(fails ? 1 : 0);
