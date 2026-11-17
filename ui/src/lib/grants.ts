// Turns an OpenFGA grant into a short note for the agents panel. Day 10: the grants themselves
// come from the broker (read live from OpenFGA), so allowlists and limits shown here can't drift
// from the policy; this file only knows how to word each condition.
import type { Grant, RiskClass } from './types';

const list = (v: unknown): string => (Array.isArray(v) ? v.join(', ') : String(v ?? '?'));

export function describeGrant(g: Grant): string {
	const c = g.context ?? {};
	const parts: string[] = [];
	if (g.taints) parts.push('taints the session');
	switch (g.condition ?? null) {
		case null:
			break;
		case 'untainted':
			parts.push('clean session only');
			break;
		case 'untainted_or_allowed_host':
			parts.push(`once tainted, only ${list(c.allowed_hosts)}`);
			break;
		case 'untainted_allowed_recipient':
			parts.push(`clean session, to @${list(c.allowed_recipient_domains)} only`);
			break;
		case 'within_limit_open_invoice':
			parts.push(`≤ $${c.max_amount}, clean session, to ${list(c.allowed_payees)}, against an open invoice`);
			break;
		default:
			parts.push(`condition: ${g.condition}`);
	}
	if (g.mode === 'approval') {
		const who = (g.approvers ?? []).map((a) => a.replace(/^user:/, '')).join(', ');
		parts.push(`a human decides${who ? ` (${who})` : ''}`);
	}
	return parts.join(' · ');
}

export function untilTime(iso: string): string {
	const d = new Date(iso);
	return Number.isNaN(d.getTime()) ? iso : d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
}

// ---------------------------------------------------------------- Day 12: grant forms

export const RISK_CLASSES: RiskClass[] = ['read', 'write', 'egress', 'money', 'destructive'];
export const RISKY: RiskClass[] = ['egress', 'money', 'destructive'];

export interface ModeSpec {
	label: string;
	params: { key: string; label: string; kind: 'list' | 'number' }[];
	/** context_map keys the tool must map, or the condition could never hold. */
	needs: string[];
	direct: boolean;
}

export const MODES: Record<string, ModeSpec> = {
	approval: { label: 'needs approval (a human decides every call)', params: [], needs: [], direct: false },
	direct: { label: 'direct, no condition', params: [], needs: [], direct: true },
	direct_if_untainted: { label: 'direct in a clean session', params: [], needs: [], direct: true },
	direct_allowlisted_recipient: {
		label: 'direct to allowlisted recipient domains',
		params: [{ key: 'allowed_recipient_domains', label: 'domains', kind: 'list' }],
		needs: ['recipient'],
		direct: true
	},
	direct_known_payee_with_invoice: {
		label: 'direct to a known payee, small amount, open invoice',
		params: [
			{ key: 'max_amount', label: 'max amount', kind: 'number' },
			{ key: 'allowed_payees', label: 'payee accounts', kind: 'list' }
		],
		needs: ['amount', 'payee', 'invoice'],
		direct: true
	},
	direct_allowed_host: {
		label: 'direct; once tainted, only allowlisted hosts',
		params: [{ key: 'allowed_hosts', label: 'hosts', kind: 'list' }],
		needs: ['url'],
		direct: true
	}
};

/** The mode the broker picks when none is named (mirrors broker/app/grants.py default_mode). */
export function defaultMode(risk: RiskClass): string {
	if (RISKY.includes(risk)) return 'approval';
	return risk === 'write' ? 'direct_if_untainted' : 'direct';
}

/** Shown before submitting: a direct grant that lets a risky tool run without a human. */
export function directWarning(risk: RiskClass | undefined, mode: string): string | null {
	if (!risk || !RISKY.includes(risk)) return null;
	if (mode === 'direct') return `${risk} tool, no condition: the agent can run it without a human, every time.`;
	if (mode === 'direct_if_untainted') return `${risk} tool: the agent can run it without a human whenever its session is clean.`;
	if (MODES[mode]?.direct) return `${risk} tool: calls inside the allowlist run without a human.`;
	return null;
}

/** Turn the form's text fields into the params object the broker expects. */
export function paramsFor(mode: string, fields: Record<string, string>): Record<string, unknown> | undefined {
	const spec = MODES[mode];
	if (!spec || !spec.params.length) return undefined;
	const out: Record<string, unknown> = {};
	for (const p of spec.params) {
		const raw = (fields[p.key] ?? '').trim();
		out[p.key] = p.kind === 'number' ? Number(raw) : raw.split(/[\s,]+/).filter(Boolean);
	}
	return out;
}
