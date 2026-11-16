<script lang="ts">
	import { api } from '$lib/api';
	import { describeGrant, untilTime } from '$lib/grants';
	import type { Agent, Delegation } from '$lib/types';

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

	// Day 10: revoke a delegation (and everything granted from it).
	async function revoke(d: Delegation) {
		if (!confirm(`Revoke ${d.delegate}'s access to ${d.tools.join(', ')} (acting for ${d.principal})? Anything granted from it is revoked too.`))
			return;
		busy = d.id;
		actionError = null;
		const r = await api(`/api/delegations/${d.id}/revoke`, { method: 'POST' });
		busy = null;
		if (!r.ok) actionError = `delegation ${d.id.slice(0, 8)}: ${r.error}`;
		onchange();
	}

	function delegationLine(agentId: string, d: Delegation): string {
		const until = `until ${untilTime(d.expires_at)}`;
		if (d.role === 'granted') return `gave ${d.tools.join(', ')} to ${d.delegate} ${until}`;
		const via = d.delegator !== d.principal ? ` via ${d.delegator}` : '';
		return `acts for ${d.principal}${via} on ${d.tools.join(', ')} ${until}`;
	}
</script>

<section class="card">
	<header class="card-head">
		<h2>Agents</h2>
		<span class="muted small">10-minute tokens · grants read live from OpenFGA</span>
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
					{#if agent.grants === null}
						<li class="muted small">grants unavailable: OpenFGA could not be read</li>
					{:else}
						{#each agent.grants ?? [] as g}
							{@const note = describeGrant(g)}
							<li>
								<code>{g.tool}</code>
								<span class="pill tiny {g.mode === 'direct' ? 'allow' : 'escalate'}">{g.mode === 'direct' ? 'direct' : 'needs approval'}</span>
								{#if note}<span class="muted small">{note}</span>{/if}
							</li>
						{:else}
							<li class="muted small">no grants</li>
						{/each}
					{/if}
				</ul>
				{#if agent.delegations?.length}
					<ul class="grants">
						{#each agent.delegations as d (d.id + d.role)}
							<li>
								<span class="pill tiny {d.role === 'received' ? 'escalate' : 'allow'}">{d.role === 'received' ? 'delegated to it' : 'delegated'}</span>
								<span class="muted small">{delegationLine(agent.id, d)}{d.depth > 1 ? ' · hop 2' : ''}</span>
								<button class="btn tiny" disabled={busy === d.id} onclick={() => revoke(d)}>{busy === d.id ? '…' : 'Revoke'}</button>
							</li>
						{/each}
					</ul>
				{/if}
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
