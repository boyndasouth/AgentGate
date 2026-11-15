<script lang="ts">
	import { api } from '$lib/api';
	import { POLICY } from '$lib/policy';
	import type { Agent } from '$lib/types';

	let {
		agents,
		error,
		onchange
	}: { agents: Agent[]; error: string | null; onchange: () => void } = $props();

	let busy = $state<string | null>(null);
	let actionError = $state<string | null>(null);

	async function toggle(agent: Agent) {
		const disabling = agent.status !== 'disabled';
		if (disabling && !confirm(`Kill switch: disable ${agent.id} and revoke every token it holds now?`)) return;
		busy = agent.id;
		actionError = null;
		const r = await api(`/api/agents/${agent.id}/${disabling ? 'disable' : 'enable'}`, { method: 'POST' });
		busy = null;
		if (!r.ok) actionError = `${agent.id}: ${r.error}`;
		onchange();
	}
</script>

<section class="card">
	<header class="card-head">
		<h2>Agents</h2>
		<span class="muted small">10-minute tokens · scopes from OpenFGA tuples</span>
	</header>

	{#if error}<p class="err">{error}</p>{/if}
	{#if actionError}<p class="err">{actionError}</p>{/if}

	<div class="agents">
		{#each agents as agent (agent.id)}
			{@const disabled = agent.status === 'disabled'}
			<article class="agent" class:off={disabled}>
				<div class="agent-top">
					<div>
						<div class="agent-name">{agent.display_name ?? agent.id}</div>
						<div class="muted small">agent:{agent.id} · owner {agent.owner ?? '—'}</div>
					</div>
					<span class="pill {disabled ? 'deny' : 'allow'}">{disabled ? 'disabled' : 'active'}</span>
				</div>
				<ul class="grants">
					{#each POLICY[agent.id] ?? [] as g}
						<li>
							<code>{g.tool}</code>
							<span class="pill tiny {g.mode === 'direct' ? 'allow' : 'escalate'}">{g.mode === 'direct' ? 'direct' : 'needs approval'}</span>
							{#if g.note}<span class="muted small">{g.note}</span>{/if}
						</li>
					{:else}
						<li class="muted small">no grants</li>
					{/each}
				</ul>
				<button
					class="btn {disabled ? '' : 'danger'} wide"
					disabled={busy === agent.id}
					onclick={() => toggle(agent)}
				>
					{busy === agent.id ? '…' : disabled ? 'Re-enable' : '⏻ Kill switch'}
				</button>
			</article>
		{:else}
			{#if !error}<p class="muted">Loading agents…</p>{/if}
		{/each}
	</div>
</section>
