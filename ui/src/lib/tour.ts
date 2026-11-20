// Shape of ui/src/lib/tour-data.json, which eval/export_tour.py records from a real run.
export type TourOutcome = 'allow' | 'escalate' | 'deny' | 'info' | 'error';

export interface TourStep {
	actor: string;
	action: string;
	outcome: TourOutcome;
	http: number;
	reason: string;
	audit_id: number | null;
	session_tainted: boolean | null;
	ms: number | null;
}

export interface TourApproval {
	tool?: string;
	agent?: string;
	reason?: string;
	session_tainted?: boolean;
	args?: Record<string, string>;
}

export interface TourBeat {
	id: number;
	title: string;
	what: string;
	note: string;
	/** Plain-language caption; falls back to the page's own caption for the core beats. */
	plain?: string;
	outcome: TourOutcome | '';
	steps: TourStep[];
	approval?: TourApproval;
}

export interface TourAuditRow {
	id: number;
	ts: string;
	event: string;
	agent: string | null;
	tool: string | null;
	decision: string;
	reason: string;
	approver: string | null;
	tainted: boolean | null;
	hash: string;
}

/** Another kind of agent behind the same gate, recorded by eval/tour_scenarios.py. */
export interface TourScenario {
	id: string;
	title: string;
	blurb: string;
	agent: string;
	tools: string[];
	beats: TourBeat[];
	audit: TourAuditRow[];
}

export interface Tour {
	schema: number;
	recorded_at: string;
	target: string;
	approvals_by: string;
	numbers: {
		suite?: { cases: number; blocked: number; escalated: number; allowed: number; target: string; run_at: string; chain_valid: boolean; file: string };
		latency?: { p50_ms: number; p95_ms: number; run_at: string; file: string };
	};
	beats: TourBeat[];
	tamper: { row_id: number; edit_caught: boolean; first_broken_id: number; restored_valid: boolean; rows_checked: number } | null;
	audit: TourAuditRow[];
	chain: { valid: boolean; checked: number; head: string };
	/** Extra agents (support, devops, ...). Absent until eval/export_tour.py has recorded them. */
	scenarios?: TourScenario[];
}
