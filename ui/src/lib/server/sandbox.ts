// The public sandbox behind the /tour "Try it yourself" panel. No login, so it is deliberately narrow:
//  - only FIXED scripted runs: the visitor picks a scenario name, never a tool, an agent or an argument;
//  - only the two sandbox agents (sandbox-support, sandbox-devops) and their sbx.* mock tools, which the
//    broker seeds from eval/seed_sandbox.py and which touch nothing real;
//  - the visitor decides approvals as `user:demo-visitor`, who is an approver of the sbx.* tools ONLY.
//    The broker asks OpenFGA about that exact tool, so even a forged request cannot decide a real
//    approval (finance, mailer): it is refused with 403;
//  - a visitor can only decide approvals that their own run created (the agent token in their cookie
//    has to be able to read the approval);
//  - per-visitor and global rate limits (best effort: each serverless instance counts on its own).
import { env } from '$env/dynamic/private';
import { Run, pollApproval, type Outcome, type Step } from './demo';
import { broker, detail } from './broker';

export const SANDBOX_SCENARIOS = [
	'support-normal',
	'support-poisoned',
	'devops-normal',
	'devops-poisoned',
	'overreach'
] as const;
export type SandboxScenario = (typeof SANDBOX_SCENARIOS)[number];

export const DEMO_APPROVER = 'user:demo-visitor';
const DEMO_VIA = 'admin-ui:tour-visitor';

export function sandboxEnabled(): boolean {
	return env.AGENTGATE_SANDBOX === '1' && Boolean(env.BROKER_URL && env.AGENTGATE_ORCHESTRATOR_KEY && env.AGENTGATE_ADMIN_KEY);
}

// ---------------------------------------------------------------------------------- rate limits
const PER_VISITOR = { max: 25, windowMs: 10 * 60_000 };
const GLOBAL = { max: 400, windowMs: 60 * 60_000 };
const hits = new Map<string, number[]>();
const globalHits: number[] = [];

function within(list: number[], windowMs: number, now: number) {
	while (list.length && now - list[0] > windowMs) list.shift();
}

/** true when this visitor may start another action. */
export function allow(visitor: string): boolean {
	const now = Date.now();
	within(globalHits, GLOBAL.windowMs, now);
	const mine = hits.get(visitor) ?? [];
	within(mine, PER_VISITOR.windowMs, now);
	if (globalHits.length >= GLOBAL.max || mine.length >= PER_VISITOR.max) return false;
	globalHits.push(now);
	mine.push(now);
	hits.set(visitor, mine);
	if (hits.size > 5000) for (const [k, v] of hits) if (!v.length) hits.delete(k);
	return true;
}

// ---------------------------------------------------------------------------------- runs
export interface SandboxResult {
	scenario: string;
	steps: Step[];
	approvalId?: string;
	expiresAt?: string;
	/** What the person who would approve sees: the tool and each argument. */
	approval?: { tool: string; agent: string; reason: string; summary: Record<string, string>; tainted: boolean | null };
	agentSays: string;
	keepToken?: string;
}

function says(outcome: Outcome, reason: string, what: string): string {
	switch (outcome) {
		case 'allow':
			return `Done: ${what}.`;
		case 'escalate':
			return `This needs a person to say yes (${reason}). I'm waiting for an answer.`;
		case 'deny':
			return `I couldn't ${what}: AgentGate refused it (${reason}). I won't retry.`;
		default:
			return `Something went wrong calling AgentGate: ${reason}`;
	}
}

async function approvalCard(id: string) {
	const r = await broker<Record<string, unknown>[]>('/approvals?status=pending&limit=100');
	const row = Array.isArray(r.data) ? r.data.find((a) => a.id === id) : undefined;
	if (!row || typeof row.agent_id !== 'string' || !row.agent_id.startsWith('sandbox-')) return undefined;
	return {
		tool: String(row.tool),
		agent: row.agent_id,
		reason: String(row.reason ?? ''),
		summary: (row.summary ?? {}) as Record<string, string>,
		tainted: (row.session_tainted ?? null) as boolean | null
	};
}

async function finish(
	run: Run,
	scenario: SandboxScenario,
	token: string | null,
	last: { outcome: Outcome; data: { approval_id?: string | null; expires_at?: string | null; reason?: string } } | null,
	what: string,
	fallback: string
): Promise<SandboxResult> {
	if (!token || !last) return { scenario, steps: run.steps, agentSays: fallback };
	const approvalId = last.data.approval_id ?? undefined;
	return {
		scenario,
		steps: run.steps,
		approvalId,
		expiresAt: last.data.expires_at ?? undefined,
		approval: approvalId ? await approvalCard(approvalId) : undefined,
		agentSays: says(last.outcome, last.data.reason ?? '', what),
		keepToken: token
	};
}

async function supportNormal(): Promise<SandboxResult> {
	const run = new Run('support-normal');
	const t = await run.mint('sandbox-support', ['sbx.crm.lookup_order', 'sbx.support.reply'], 'Answer ticket T-2001 about order A-1001');
	if (!t) return finish(run, 'support-normal', null, null, '', 'The support agent was not issued a token.');
	const a = 'sandbox-support';
	await run.call(a, t.access_token, 'sbx.crm.lookup_order', { order_id: 'A-1001' }, 'crm.lookup_order A-1001');
	const reply = await run.call(
		a, t.access_token, 'sbx.support.reply',
		{ to: 'anna@customers.example', subject: 'Your order A-1001', body: 'It was delivered on the 12th. Sorry about the dented box!' },
		'support.reply → anna@customers.example (a known customer)'
	);
	return finish(run, 'support-normal', t.access_token, reply, 'reply to anna@customers.example', '');
}

async function supportPoisoned(): Promise<SandboxResult> {
	const run = new Run('support-poisoned');
	const a = 'sandbox-support';
	const t = await run.mint(a, ['sbx.crm.read_ticket', 'sbx.crm.refund'], 'Handle ticket T-2002');
	if (!t) return finish(run, 'support-poisoned', null, null, '', 'The support agent was not issued a token.');
	await run.call(a, t.access_token, 'sbx.crm.read_ticket', { ticket_id: 'T-2002' }, 'crm.read_ticket T-2002 (text written by the customer)');
	// The ticket told the agent to refund $480; it obeys. Money always needs a person.
	const refund = await run.call(
		a, t.access_token, 'sbx.crm.refund', { order_id: 'A-1002', amount: 480 },
		'crm.refund $480 on A-1002 (the ticket told it to)'
	);
	return finish(run, 'support-poisoned', t.access_token, refund, 'refund $480', '');
}

async function devopsNormal(): Promise<SandboxResult> {
	const run = new Run('devops-normal');
	const a = 'sandbox-devops';
	const t = await run.mint(a, ['sbx.repo.read_issue', 'sbx.repo.comment'], 'Triage issue #12');
	if (!t) return finish(run, 'devops-normal', null, null, '', 'The DevOps agent was not issued a token.');
	const c = await run.call(
		a, t.access_token, 'sbx.repo.comment',
		{ repo: 'acme-web', number: 12, body: 'Thanks! Fixed in the next release.' },
		'repo.comment acme-web #12'
	);
	await run.call(a, t.access_token, 'sbx.repo.read_issue', { repo: 'acme-web', number: 12 }, 'repo.read_issue acme-web #12 (text written by a stranger)');
	return finish(run, 'devops-normal', t.access_token, c, 'comment on acme-web #12', '');
}

async function devopsPoisoned(): Promise<SandboxResult> {
	const run = new Run('devops-poisoned');
	const a = 'sandbox-devops';
	const t = await run.mint(a, ['sbx.repo.read_issue', 'sbx.repo.delete_branch'], 'Clean up stale branches');
	if (!t) return finish(run, 'devops-poisoned', null, null, '', 'The DevOps agent was not issued a token.');
	await run.call(a, t.access_token, 'sbx.repo.read_issue', { repo: 'acme-web', number: 13 }, 'repo.read_issue acme-web #13 (text written by a stranger)');
	const del = await run.call(
		a, t.access_token, 'sbx.repo.delete_branch', { repo: 'acme-web', branch: 'release/2.4' },
		'repo.delete_branch release/2.4 (the issue told it to)'
	);
	return finish(run, 'devops-poisoned', t.access_token, del, 'delete the branch release/2.4', '');
}

async function overreach(): Promise<SandboxResult> {
	const run = new Run('overreach');
	// The support agent asks for a tool that belongs to the DevOps agent. It is refused at the door.
	const t = await run.mint('sandbox-support', ['sbx.repo.delete_branch'], 'Please delete a branch');
	return {
		scenario: 'overreach',
		steps: run.steps,
		agentSays: t
			? 'Unexpected: a token was issued.'
			: 'The support agent asked for a tool it was never given. No token was issued, so it could not even try.'
	};
}

export function runSandbox(s: SandboxScenario): Promise<SandboxResult> {
	switch (s) {
		case 'support-normal':
			return supportNormal();
		case 'support-poisoned':
			return supportPoisoned();
		case 'devops-normal':
			return devopsNormal();
		case 'devops-poisoned':
			return devopsPoisoned();
		case 'overreach':
			return overreach();
	}
}

// ---------------------------------------------------------------------------------- the visitor decides
export async function decide(token: string, approvalId: string, approve: boolean) {
	// Only an approval that this visitor's own agent token can see (same agent and session).
	const mine = await pollApproval(token, approvalId);
	if (mine.http === 404 || mine.http === 401) {
		return { ok: false as const, status: 404, detail: 'that approval does not belong to your run' };
	}
	const r = await broker(`/approvals/${approvalId}/decision`, {
		method: 'POST',
		body: { approve, approver: DEMO_APPROVER, via: DEMO_VIA }
	});
	if (!r.ok) return { ok: false as const, status: r.status || 502, detail: detail(r) };
	// What the agent finds when it asks again, in its own words.
	const after = await pollApproval(token, approvalId);
	return { ok: true as const, status: 200, state: after.state, agentSays: after.agentSays, reason: after.reason };
}
