<script lang="ts">
	import { api } from '$lib/api';
	import type { Approval } from '$lib/types';

	let {
		approvals,
		error,
		canApprove,
		now,
		ondecided
	}: { approvals: Approval[]; error: string | null; canApprove: boolean; now: number; ondecided: () => void } =
		$props();

	let busy = $state<string | null>(null);
	let actionError = $state<string | null>(null);

	function secondsLeft(a: Approval): number | null {
		if (!a.expires_at) return null;
		return Math.max(0, Math.round((Date.parse(a.expires_at) - now) / 1000));
	}

	function summary(a: Approval): string | null {
		const s = a.args_summary ?? a.summary ?? null;
		if (s == null) return null;
		return typeof s === 'string' ? s : JSON.stringify(s);
	}

	async function decide(a: Approval, approve: boolean) {
		busy = a.id;
		actionError = null;
		const r = await api(`/api/approvals/${a.id}`, { method: 'POST', body: { approve } });
		busy = null;
		if (!r.ok) actionError = r.status === 409 ? 'Already decided (Slack or timeout got there first).' : r.error ?? 'failed';
		ondecided();
	}
</script>

<section class="card">
	<header class="card-head">
		<h2>Approvals <span class="count">{approvals.length}</span></h2>
		<span class="muted small">same queue as Slack · first decision wins</span>
	</header>

	{#if error}<p class="err">{error}</p>{/if}
	{#if actionError}<p class="err">{actionError}</p>{/if}
	{#if !canApprove}
		<p class="muted small">You can watch this queue but not decide: your account has no approver mapping.</p>
	{/if}

	{#each approvals as a (a.id)}
		{@const left = secondsLeft(a)}
		<article class="approval" class:tainted={a.session_tainted}>
			<div class="approval-top">
				<div>
					<strong>agent:{a.agent_id}</strong> → <code>{a.tool}</code>
					{#if a.session_tainted}<span class="pill tiny taint">⚠ tainted</span>{/if}
				</div>
				{#if left !== null}<span class="muted small mono">{left}s left</span>{/if}
			</div>
			<p class="reason">{a.reason}</p>
			{#if summary(a)}<pre class="args">{summary(a)}</pre>{/if}
			<div class="row">
				<button class="btn allow" disabled={!canApprove || busy === a.id || left === 0} onclick={() => decide(a, true)}>Approve</button>
				<button class="btn danger" disabled={!canApprove || busy === a.id || left === 0} onclick={() => decide(a, false)}>Deny</button>
			</div>
		</article>
	{:else}
		<p class="muted empty">Nothing waiting for a human.</p>
	{/each}
</section>
