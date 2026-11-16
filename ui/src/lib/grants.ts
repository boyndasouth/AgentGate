// Turns an OpenFGA grant into a short note for the agents panel. Day 10: the grants themselves
// come from the broker (read live from OpenFGA), so allowlists and limits shown here can't drift
// from the policy; this file only knows how to word each condition.
import type { Grant } from './types';

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
