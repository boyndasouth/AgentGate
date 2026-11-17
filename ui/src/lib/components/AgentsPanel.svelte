<script lang="ts">
	import { api } from '$lib/api';
	import { MODES, defaultMode, describeGrant, directWarning, paramsFor, untilTime } from '$lib/grants';
	import type { Agent, Delegation, Grant, Tool } from '$lib/types';

	let {
		agents,
		tools,
		error,
		onchange
	}: { agents: Agent[]; tools: Tool[]; error: string | null; onchange: () => void } = $props();

	let busy = $state<string | null>(null);
	let actionError = $state<string | null>(null);
	let notice = $state<string | null>(null);

	// Day 12: register an agent
	let showRegister = $state(false);
	let reg = $state({ id: '', owner: 'user:shiwin', display_name: '' });

	// Day 12: add a grant (one open form at a time)
	let grantFor = $state<string | null>(null);
	let g = $state({ tool: '', mode: '', fields: {} as Record<string, string> });

	const toolByName = $derived(new Map(tools.map((t) => [t.name, t])));
	const chosen = $derived(toolByName.get(g.tool));
	const effectiveMode = $derived(g.mode || (chosen ? defaultMode(chosen.risk_class) : ''));
	const warning = $derived(chosen ? directWarning(chosen.risk_class, effectiveMode) : null);
	const missingMapping = $derived(
		chosen && MODES[effectiveMode] ? MODES[effectiveMode].needs.filter((k) => !(k in (chosen.context_map ?? {}))) : []
	);

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

	async function register(e: SubmitEvent) {
		e.preventDefault();
		busy = 'register';
		actionError = notice = null;
		const body: Record<string, string> = { id: reg.id.trim(), owner: reg.owner.trim() };
		if (reg.display_name.trim()) body.display_name = reg.display_name.trim();
		const r = await api('/api/agents', { method: 'POST', body });
		busy = null;
		if (!r.ok) {
			actionError = `register: ${r.error}`;
			return;
		}
		notice = `Registered ${body.id}. It has no grants yet, so every call it makes is denied.`;
		reg = { id: '', owner: reg.owner, display_name: '' };
		showRegister = false;
		onchange();
	}

	function openGrant(agentId: string) {
		grantFor = grantFor === agentId ? null : agentId;
		g = { tool: '', mode: '', fields: {} };
	}

	async function addGrant(e: SubmitEvent, agentId: string) {
		e.preventDefault();
		if (warning && !confirm(`${warning}\n\nAdd this grant anyway?`)) return;
		busy = `grant:${agentId}`;
		actionError = notice = null;
		const body: Record<string, unknown> = { tool: g.tool };
		if (g.mode) body.mode = g.mode;
		const params = paramsFor(effectiveMode, g.fields);
		if (params) body.params = params;
		const r = await api<{ mode: string; warning?: string | null; defaulted?: boolean }>(`/api/agents/${agentId}/grants`, {
			method: 'POST',
			body
		});
		busy = null;
		if (!r.ok) {
			actionError = `grant: ${r.error}`;
			return;
		}
		notice = `${agentId} → ${g.tool}: ${r.data.mode}${r.data.defaulted ? ' (default for its risk class)' : ''}` +
			(r.data.warning ? ` · ⚠ ${r.data.warning}` : '');
		grantFor = null;
		onchange();
	}

	async function removeGrant(agentId: string, gr: Grant) {
		if (!confirm(`Remove ${agentId}'s ${gr.grant_mode ?? gr.mode} grant on ${gr.tool}? Its next call is judged without it, even with a token it already holds.`))
			return;
		busy = `${agentId}:${gr.tool}:${gr.mode}`;
		actionError = notice = null;
		const r = await api(`/api/agents/${agentId}/grants`, {
			method: 'DELETE',
			body: { tool: gr.tool, ...(gr.grant_mode ? { mode: gr.grant_mode } : {}) }
		});
		busy = null;
		if (!r.ok) actionError = `remove grant: ${r.error}`;
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
		<span class="row">
			<span class="muted small">10-minute tokens · grants read live from OpenFGA</span>
			<button class="btn tiny" onclick={() => (showRegister = !showRegister)}>{showRegister ? 'Cancel' : '+ Register agent'}</button>
		</span>
	</header>

	{#if error}<p class="err">{error}</p>{/if}
	{#if actionError}<p class="err">{actionError}</p>{/if}
	{#if notice}<p class="note small">{notice}</p>{/if}

	{#if showRegister}
		<form class="form" onsubmit={register}>
			<label>id <input required bind:value={reg.id} placeholder="support-bot" maxlength="64" /></label>
			<label>display name <input bind:value={reg.display_name} placeholder="Support bot" maxlength="80" /></label>
			<label>owner <input required bind:value={reg.owner} placeholder="user:shiwin" /></label>
			<p class="muted small">A new agent has no grants: every call it makes is denied until you add one.</p>
			<button class="btn primary" disabled={busy === 'register'}>{busy === 'register' ? '…' : 'Register'}</button>
		</form>
	{/if}

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
						{#each agent.grants ?? [] as gr (gr.tool + gr.mode)}
							{@const note = describeGrant(gr)}
							{@const key = `${agent.id}:${gr.tool}:${gr.mode}`}
							<li>
								<code>{gr.tool}</code>
								{#if gr.risk_class}<span class="pill tiny risk {gr.risk_class}">{gr.risk_class}</span>{/if}
								<span class="pill tiny {gr.mode === 'direct' ? 'allow' : 'escalate'}">{gr.mode === 'direct' ? 'direct' : 'needs approval'}</span>
								{#if note}<span class="muted small">{note}</span>{/if}
								{#if gr.source === 'api'}
									<button class="btn tiny" disabled={busy === key} onclick={() => removeGrant(agent.id, gr)}>{busy === key ? '…' : 'Remove'}</button>
								{:else if gr.source === 'seed'}
									<span class="muted small" title="Set in policy/tuples.yaml; change it there">seed</span>
								{/if}
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

				{#if grantFor === agent.id}
					<form class="form" onsubmit={(e) => addGrant(e, agent.id)}>
						<label>
							tool
							<select required bind:value={g.tool}>
								<option value="" disabled>choose a tool</option>
								{#each tools as t (t.name)}
									<option value={t.name} disabled={!!t.problem}>{t.name} · {t.risk_class}{t.enabled ? '' : ' · off'}{t.problem ? ' · misconfigured' : ''}</option>
								{/each}
							</select>
						</label>
						<label>
							mode
							<select bind:value={g.mode}>
								<option value="">default{chosen ? ` (${defaultMode(chosen.risk_class)})` : ''}</option>
								{#each Object.entries(MODES) as [name, spec] (name)}
									<option value={name}>{spec.label}</option>
								{/each}
							</select>
						</label>
						{#each MODES[effectiveMode]?.params ?? [] as p (p.key)}
							<label>
								{p.label}
								<input required bind:value={g.fields[p.key]} placeholder={p.kind === 'number' ? '100' : 'comma-separated'} />
							</label>
						{/each}
						{#if chosen}
							<p class="small">
								<span class="pill tiny risk {chosen.risk_class}">{chosen.risk_class}</span>
								{#if chosen.taints_session}<span class="muted">taints the session</span>{/if}
							</p>
						{/if}
						{#if missingMapping.length}
							<p class="err small">{g.tool} doesn't map {missingMapping.join(', ')} in its context_map, so this condition could never hold.</p>
						{/if}
						{#if warning}<p class="warn small">⚠ {warning}</p>{/if}
						<div class="row">
							<button class="btn primary" disabled={busy === `grant:${agent.id}` || !g.tool || missingMapping.length > 0}>
								{busy === `grant:${agent.id}` ? '…' : 'Add grant'}
							</button>
							<button type="button" class="btn ghost" onclick={() => (grantFor = null)}>Cancel</button>
						</div>
					</form>
				{/if}

				<div class="row">
					<button class="btn tiny" onclick={() => openGrant(agent.id)} disabled={disabled}>{grantFor === agent.id ? 'Close' : '+ Grant'}</button>
					<button
						class="btn {disabled ? '' : 'danger'} grow"
						disabled={busy === agent.id}
						onclick={() => toggle(agent)}
					>
						{busy === agent.id ? '…' : disabled ? 'Re-enable' : '⏻ Kill switch'}
					</button>
				</div>
			</article>
		{:else}
			{#if !error}<p class="muted">Loading agents…</p>{/if}
		{/each}
	</div>
</section>
