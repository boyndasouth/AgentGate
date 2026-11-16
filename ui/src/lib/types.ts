// Shapes of broker rows as the UI uses them. Fields are optional on purpose:
// the UI must keep working if the broker adds or renames a column.
export interface AuditEvent {
	id: number;
	ts: string;
	event_type: string;
	agent_id?: string | null;
	session_id?: string | null;
	task_id?: string | null;
	jti?: string | null;
	tool?: string | null;
	args_hash?: string | null;
	decision: string;
	reason: string;
	approver?: string | null;
	session_tainted?: boolean | null;
	prev_hash?: string;
	hash?: string;
}

/** One OpenFGA grant of an agent on a tool, as the broker reads it (Day 10). */
export interface Grant {
	tool: string;
	mode: 'direct' | 'approval';
	condition?: string | null;
	context?: Record<string, unknown>;
	taints?: boolean;
	approvers?: string[];
}

/** An active delegation this agent takes part in (Day 10). */
export interface Delegation {
	id: string;
	principal: string;
	delegator: string;
	delegate: string;
	tools: string[];
	depth: number;
	parent_id?: string | null;
	expires_at: string;
	role: 'granted' | 'received';
}

export interface Agent {
	id: string;
	owner?: string;
	display_name?: string;
	status?: string;
	created_at?: string;
	/** Read live from OpenFGA by the broker; null if OpenFGA couldn't be read. */
	grants?: Grant[] | null;
	delegations?: Delegation[];
	[k: string]: unknown;
}

export interface Approval {
	id: string;
	agent_id?: string;
	tool?: string;
	reason?: string;
	status?: string;
	session_id?: string;
	session_tainted?: boolean | null;
	created_at?: string;
	expires_at?: string;
	args_summary?: unknown;
	summary?: unknown;
	args?: unknown;
	[k: string]: unknown;
}

export type FeedMode = 'connecting' | 'realtime' | 'polling' | 'offline';
