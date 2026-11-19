<script lang="ts">
	import { api } from '$lib/api';

	let { enabled, onactivity }: { enabled: boolean; onactivity: () => void } = $props();

	interface Step {
		actor: string;
		action: string;
		outcome: string;
		http: number;
		reason: string;
		auditId?: number;
		sessionTainted?: boolean | null;
	}
	interface Run {
		scenario: string;
		sessionId?: string;
		steps: Step[];
		approvalId?: string;
		agentSays: string;
	}

	const BEATS = [
		{ id: 'pay', label: '① Finance pays $40', hint: 'allowed, under the $100 limit' },
		{ id: 'big', label: '② Finance pays $5,000', hint: 'escalates to Slack' },
		{ id: 'inject', label: '③ Poisoned page → exfil email', hint: 'taint turns it into an approval' },
		{ id: 'kill-start', label: '④a Mailer holds a token', hint: 'then hit its kill switch' },
		{ id: 'kill-retry', label: '④b Same token again', hint: 'fails at once' }
	] as const;

	let running = $state<string | null>(null);
	let run = $state<Run | null>(null);
	let waiting = $state<string | null>(null);
	let finalSays = $state<string | null>(null);
	let error = $state<string | null>(null);
	let pollTimer: ReturnType<typeof setTimeout> | null = null;

	function stopPolling() {
		if (pollTimer) clearTimeout(pollTimer);
		pollTimer = null;
		waiting = null;
	}

	async function poll(id: string, deadline: number) {
		const r = await api<{ state: string; agentSays?: string; reason?: string }>(`/api/demo/poll?id=${id}`);
		if (r.ok && r.data.state !== 'pending' && r.data.state !== 'error') {
			finalSays = r.data.agentSays ?? r.data.state;
			stopPolling();
			onactivity();
			return;
		}
		if (Date.now() > deadline) {
			finalSays = 'I stopped waiting; no answer counts as a no.';
			stopPolling();
			return;
		}
		pollTimer = setTimeout(() => poll(id, deadline), 2000);
	}

	async function start(id: string) {
		stopPolling();
		running = id;
		error = null;
		finalSays = null;
		run = null;
		const r = await api<Run>(`/api/demo/${id}`, { method: 'POST' });
		running = null;
		onactivity();
		if (!r.ok) {
			error = r.error ?? 'failed';
			return;
		}
		run = r.data;
		if (run.approvalId) {
			waiting = run.approvalId;
			// Agents wait out the 120 s TTL plus a little grace, like the real ones.
			poll(run.approvalId, Date.now() + 135_000);
		}
	}
</script>

<section class="card demo-card">
	<header class="card-head">
		<h2>Demo runner</h2>
		<span class="muted small">scripted agents, no LLM · real tokens, real gate calls</span>
	</header>

	{#if !enabled}
		<p class="muted small">Disabled. Set <code>AGENTGATE_ORCHESTRATOR_KEY</code> on the server to enable it.</p>
	{:else}
		<div class="beats">
			{#each BEATS as b}
				<button class="beat" disabled={running !== null} onclick={() => start(b.id)}>
					<span>{running === b.id ? 'Running…' : b.label}</span>
					<span class="muted small">{b.hint}</span>
				</button>
			{/each}
		</div>
		<p class="muted small">Tamper beat: edit any <code>audit_events</code> row in the Supabase table editor, then press Verify chain.</p>
	{/if}

	{#if error}<p class="err">{error}</p>{/if}

	{#if run}
		<ol class="steps">
			{#each run.steps as s}
				<li>
					<span class="pill tiny {s.outcome}">{s.outcome}</span>
					<strong>{s.actor}</strong> · {s.action}
					{#if s.sessionTainted}<span class="pill tiny taint">⚠ tainted</span>{/if}
					<div class="muted small">{s.reason}{s.auditId ? ` · audit #${s.auditId}` : ''}</div>
				</li>
			{/each}
		</ol>
		<blockquote class="says">
			<span class="muted small">agent says</span>
			{finalSays ?? run.agentSays}
			{#if waiting}<div class="muted small">waiting for Slack or the Approvals panel… (polling every 2 s)</div>{/if}
		</blockquote>
	{/if}
</section>
