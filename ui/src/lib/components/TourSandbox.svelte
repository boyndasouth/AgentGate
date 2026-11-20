<script lang="ts">
	import { onMount } from 'svelte';

	interface Step { actor: string; action: string; outcome: string; http: number; reason: string; auditId?: number; sessionTainted?: boolean | null }
	interface Card { tool: string; agent: string; reason: string; summary: Record<string, string>; tainted: boolean | null }
	interface Run { scenario: string; steps: Step[]; approvalId?: string; approval?: Card; agentSays: string }

	const GROUPS = [
		{
			agent: 'Customer support agent',
			blurb: 'Looks up orders, emails known customers, can ask for refunds.',
			items: [
				{ id: 'support-normal', label: 'A normal day', hint: 'lookup + reply to a customer: no human needed' },
				{ id: 'support-poisoned', label: 'A poisoned ticket', hint: 'the ticket orders a $480 refund' }
			]
		},
		{
			agent: 'DevOps agent',
			blurb: 'Comments on issues, reads them, deletes branches.',
			items: [
				{ id: 'devops-normal', label: 'A normal day', hint: 'comment on an issue: allowed' },
				{ id: 'devops-poisoned', label: 'A poisoned issue', hint: 'the issue orders a branch deleted' }
			]
		},
		{
			agent: 'Overreach',
			blurb: 'An agent asks for a tool outside its job.',
			items: [{ id: 'overreach', label: 'Support asks to delete a branch', hint: 'refused before it starts' }]
		}
	];

	let enabled = $state(false);
	let running = $state<string | null>(null);
	let deciding = $state(false);
	let run = $state<Run | null>(null);
	let final = $state<{ state: string; says: string } | null>(null);
	let error = $state<string | null>(null);

	onMount(async () => {
		try {
			const r = await fetch('/api/sandbox/status');
			enabled = r.ok && (await r.json()).enabled === true;
		} catch {
			enabled = false;
		}
	});

	async function post<T>(url: string, body: unknown): Promise<{ ok: boolean; status: number; data: T & { detail?: string } }> {
		const r = await fetch(url, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });
		let data: unknown = {};
		try { data = await r.json(); } catch { /* not JSON */ }
		return { ok: r.ok, status: r.status, data: data as T & { detail?: string } };
	}

	async function start(id: string) {
		running = id; error = null; final = null; run = null;
		const r = await post<Run>('/api/sandbox/run', { scenario: id });
		running = null;
		if (!r.ok) {
			error = r.status === 429 ? (r.data.detail ?? 'Too many runs, try again in a few minutes.')
				: r.status === 404 ? 'The sandbox is switched off right now.'
				: (r.data.detail ?? `Something went wrong (HTTP ${r.status}). The server may be waking up: try again in a minute.`);
			return;
		}
		run = r.data;
	}

	async function decide(approve: boolean) {
		if (!run?.approvalId) return;
		deciding = true; error = null;
		const r = await post<{ state: string; agentSays?: string; reason?: string }>('/api/sandbox/decide', { id: run.approvalId, approve });
		deciding = false;
		if (!r.ok) { error = r.data.detail ?? `Could not record your decision (HTTP ${r.status}).`; return; }
		final = { state: r.data.state, says: r.data.agentSays ?? r.data.reason ?? r.data.state };
	}

	const waiting = $derived(Boolean(run?.approvalId) && !final);
</script>

{#if enabled}
	<section class="card sandbox" aria-labelledby="sbxh">
		<div class="card-head"><h2 id="sbxh">Be the approver</h2><span class="pill tiny info">live sandbox</span></div>
		<p class="lede2">
			These run against the real, deployed gate, but with mock tools (nothing real is emailed, refunded or deleted). Pick a
			situation. When the gate holds a call for a person, <b>you</b> are that person: this card is what an approver would see in Slack.
		</p>

		<div class="groups">
			{#each GROUPS as g}
				<div class="grp">
					<strong>{g.agent}</strong>
					<span class="muted small">{g.blurb}</span>
					{#each g.items as it}
						<button class="btn" disabled={running !== null || deciding} onclick={() => start(it.id)}>
							{running === it.id ? 'Running…' : it.label}
						</button>
						<span class="hint muted small">{it.hint}</span>
					{/each}
				</div>
			{/each}
		</div>

		{#if error}<p class="err small" role="alert">{error}</p>{/if}

		{#if run}
			<div class="steps" role="list" aria-live="polite">
				{#each run.steps as s}
					<div role="listitem" class="o-{s.outcome}">
						<span class="actor mono small">{s.actor}</span>
						<span class="act">{s.action}</span>
						<span class="meta">
							<span class="pill tiny {s.outcome}">{s.outcome}</span>
							{#if s.sessionTainted}<span class="pill tiny taint">tainted</span>{/if}
							<span class="muted small mono">HTTP {s.http}{#if s.auditId} · audit #{s.auditId}{/if}</span>
						</span>
						<span class="why muted small">{s.reason}</span>
					</div>
				{/each}
			</div>

			{#if waiting}
				<div class="approvalbox" class:tainted={run.approval?.tainted}>
					<div class="ab-top"><strong>Approval needed{run.approval ? ` · ${run.approval.tool}` : ''}</strong><span class="muted small mono">asked by {run.approval?.agent ?? 'the agent'}</span></div>
					{#if run.approval}
						<p class="small">{run.approval.reason}</p>
						<pre class="args">{Object.entries(run.approval.summary).map(([k, v]) => `${k}: ${v}`).join('\n')}</pre>
					{/if}
					<div class="ab-btns">
						<button class="btn allow" disabled={deciding} onclick={() => decide(true)}>Approve</button>
						<button class="btn danger" disabled={deciding} onclick={() => decide(false)}>Deny</button>
					</div>
					<p class="muted small">Approving here sends nothing real. Waiting too long counts as a no.</p>
				</div>
			{/if}

			<div class="agentsays" class:done={!waiting}>
				<span class="eyebrow">What the agent says</span>
				<p>{final ? final.says : run.agentSays}</p>
			</div>
		{/if}
	</section>
{/if}

<style>
	.lede2 { max-width: 70ch; color: #cfcec8; line-height: 1.55; margin: 0 0 16px; }
	.groups { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 14px; }
	@media (max-width: 800px) { .groups { grid-template-columns: 1fr; } }
	.grp { display: grid; align-content: start; gap: 6px; border: 1px solid var(--line); padding: 12px; }
	.grp .btn { text-align: left; margin-top: 4px; }
	.hint { margin-top: -2px; }
	.err { color: var(--deny); margin: 12px 0 0; }
	.steps { list-style: none; margin: 18px 0 0; padding: 0; display: grid; gap: 8px; }
	.steps > div { display: grid; grid-template-columns: 130px 1fr auto; gap: 4px 14px; border: 1px solid var(--line); border-left: 3px solid var(--line-strong); padding: 9px 12px; }
	.steps > div.o-allow { border-left-color: var(--allow); }
	.steps > div.o-escalate { border-left-color: var(--escalate); }
	.steps > div.o-deny { border-left-color: var(--deny); }
	.actor { text-transform: uppercase; letter-spacing: 0.06em; color: var(--muted); }
	.act { font-family: var(--mono); font-size: 13px; overflow-wrap: anywhere; }
	.meta { display: flex; gap: 8px; align-items: center; justify-self: end; flex-wrap: wrap; }
	.why { grid-column: 2 / -1; }
	@media (max-width: 700px) { .steps > div { grid-template-columns: 1fr; } .meta { justify-self: start; } .why { grid-column: 1; } }
	.approvalbox { margin-top: 16px; border: 1px solid var(--escalate); background: rgba(255, 178, 31, 0.05); padding: 14px; display: grid; gap: 8px; }
	.approvalbox.tainted { border-color: var(--taint); }
	.ab-top { display: flex; justify-content: space-between; gap: 12px; flex-wrap: wrap; }
	.approvalbox p { margin: 0; }
	.args { margin: 0; padding: 10px; background: rgba(0, 0, 0, 0.35); border: 1px solid var(--line); font: 12px var(--mono); white-space: pre-wrap; overflow-wrap: anywhere; }
	.ab-btns { display: flex; gap: 10px; }
	.agentsays { margin-top: 16px; border-left: 3px solid var(--accent); padding: 4px 0 4px 14px; }
	.agentsays p { margin: 4px 0 0; }
</style>
