// What each agent may do, as written in policy/tuples.yaml (OpenFGA).
// Display only: the broker asks OpenFGA on every call, never this file.
// TODO: serve this from the broker (read tuples from OpenFGA) so it can't drift.
export type Grant = { tool: string; mode: 'direct' | 'approval'; note?: string };

export const POLICY: Record<string, Grant[]> = {
	researcher: [{ tool: 'read_web', mode: 'direct', note: 'taints the session' }],
	mailer: [
		{ tool: 'read_inbox', mode: 'direct', note: 'taints the session' },
		{ tool: 'query_customers', mode: 'direct' },
		{ tool: 'send_email', mode: 'direct', note: 'clean session only' },
		{ tool: 'send_email', mode: 'approval', note: 'tainted session' }
	],
	finance: [
		{ tool: 'transfer_funds', mode: 'direct', note: '≤ $100, clean session' },
		{ tool: 'transfer_funds', mode: 'approval', note: 'anything else' }
	]
};

export const APPROVERS: Record<string, string[]> = {
	send_email: ['user:shiwin'],
	transfer_funds: ['user:shiwin']
};
