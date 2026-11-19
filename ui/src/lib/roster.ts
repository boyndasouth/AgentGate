// The demo roster: which agents the Gate shows, in what order, under what name.
// UI-only. Nothing here touches the broker, so it can't change what any agent may do.
//
// Two groups, so the names tell one story:
//   team      orchestrator-minted tokens (the scripted demo + the injection beat)
//   external  agents that log in as themselves with an Auth0 M2M token (MCP clients)
//
// To show another agent, add its id to ROSTER. To keep one off the Gate (it is still listed in the
// Agents panel, with its kill switch), add it to OFF_GATE. Any other agent that holds at least one
// grant is appended after the roster, so a newly registered agent shows up without a code change.
import type { Agent } from '$lib/types';

export const ROSTER: { id: string; label: string; group: 'team' | 'external' }[] = [
	{ id: 'researcher', label: 'Researcher', group: 'team' },
	{ id: 'mailer', label: 'Mailer', group: 'team' },
	{ id: 'finance', label: 'Finance', group: 'team' },
	{ id: 'ext-bot', label: 'Support Bot', group: 'external' }
];

/** Test fixtures and duplicates: real rows (agents are never deleted), just not part of the story. */
export const OFF_GATE = new Set(['d12check-bot', 'suite-m2m', 'research-bot']);

export type GateAgent = Agent & { gate: boolean; group?: 'team' | 'external' };

/** Relabel, order and flag the agents. Roster first, then other granted agents, then everything else. */
export function tidy(list: Agent[]): GateAgent[] {
	const rank = (a: Agent) => {
		const i = ROSTER.findIndex((r) => r.id === a.id);
		if (i >= 0) return i;
		if (OFF_GATE.has(a.id)) return 1000;
		return (a.grants?.length ?? 0) > 0 ? 100 : 1000;
	};
	return list
		.map((a): GateAgent => {
			const r = ROSTER.find((x) => x.id === a.id);
			return { ...a, display_name: r?.label ?? a.display_name, group: r?.group, gate: rank(a) < 1000 };
		})
		.sort((a, b) => rank(a) - rank(b) || a.id.localeCompare(b.id));
}
