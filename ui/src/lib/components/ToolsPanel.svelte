<script lang="ts">
	// Day 12: the tool registry. Register a tool, switch it on or off, set who approves it.
	// The broker validates every row; a refused row comes back with the reason.
	import { api } from '$lib/api';
	import { RISK_CLASSES, RISKY } from '$lib/grants';
	import type { RiskClass, Tool } from '$lib/types';

	let { tools, error, onchange }: { tools: Tool[]; error: string | null; onchange: () => void } = $props();

	let busy = $state<string | null>(null);
	let actionError = $state<string | null>(null);
	let showRegister = $state(false);
	let approverFor = $state<string | null>(null);
	let approver = $state('user:');

	const EXAMPLE_SCHEMA = `{
  "type": "object",
  "required": ["ticket_id", "status"],
  "properties": {
    "ticket_id": {"type": "string"},
    "status": {"type": "string"}
  },
  "additionalProperties": false
}`;
	const EXAMPLE_UPSTREAM = `{
  "kind": "http",
  "method": "PATCH",
  "url": "https://crm.example.com/api/tickets/{ticket_id}"
}`;
	let f = $state({
		name: '',
		description: '',
		risk_class: 'write' as RiskClass,
		taints_session: true,
		credential_ref: '',
		enabled: false,
		args_schema: EXAMPLE_SCHEMA,
		context_map: '{}',
		upstream: EXAMPLE_UPSTREAM
	});

	function where(t: Tool): string {
		const u = t.upstream ?? {};
		if (u.kind === 'http') {
			try {
				return `${u.method} ${new URL(String(u.url).replace(/[{}]/g, '')).host}`;
			} catch {
				return `${u.method} ?`;
			}
		}
		if (u.kind === 'builtin') return `built-in ${u.handler ?? t.name}`;
		return String(u.kind ?? '?');
	}

	function parse(label: string, text: string): unknown {
		try {
			return JSON.parse(text);
		} catch {
			throw new Error(`${label} is not valid JSON`);
		}
	}

	async function register(e: SubmitEvent) {
		e.preventDefault();
		actionError = null;
		let body: Record<string, unknown>;
		try {
			body = {
				name: f.name.trim(),
				description: f.description.trim(),
				risk_class: f.risk_class,
				taints_session: f.taints_session,
				enabled: f.enabled,
				args_schema: parse('args schema', f.args_schema),
				context_map: parse('context map', f.context_map),
				upstream: parse('upstream', f.upstream)
			};
			if (f.credential_ref.trim()) body.credential_ref = f.credential_ref.trim();
		} catch (err) {
			actionError = (err as Error).message;
			return;
		}
		busy = 'register';
		const r = await api('/api/tools', { method: 'POST', body });
		busy = null;
		if (!r.ok) {
			actionError = `register: ${r.error}`;
			return;
		}
		showRegister = false;
		onchange();
	}

	async function setEnabled(t: Tool, enabled: boolean) {
		if (!enabled && !confirm(`Switch ${t.name} off? Every call to it is denied at once, also with tokens already issued.`)) return;
		busy = t.name;
		actionError = null;
		const r = await api(`/api/tools/${t.name}`, { method: 'PATCH', body: { enabled } });
		busy = null;
		if (!r.ok) actionError = `${t.name}: ${r.error}`;
		onchange();
	}

	async function addApprover(e: SubmitEvent, t: Tool) {
		e.preventDefault();
		busy = `appr:${t.name}`;
		actionError = null;
		const r = await api(`/api/tools/${t.name}/approvers`, { method: 'POST', body: { user: approver.trim() } });
		busy = null;
		if (!r.ok) actionError = `${t.name}: ${r.error}`;
		else approverFor = null;
		onchange();
	}

	async function removeApprover(t: Tool, user: string) {
		if (!confirm(`${user} may no longer approve ${t.name}?`)) return;
		busy = `appr:${t.name}:${user}`;
		const r = await api(`/api/tools/${t.name}/approvers/${encodeURIComponent(user)}`, { method: 'DELETE' });
		busy = null;
		if (!r.ok) actionError = `${t.name}: ${r.error}`;
		onchange();
	}
</script>

<section class="card tools-card">
	<header class="card-head">
		<h2>Tools <span class="count">{tools.length}</span></h2>
		<button class="btn tiny" onclick={() => (showRegister = !showRegister)}>{showRegister ? 'Cancel' : '+ Register tool'}</button>
	</header>

	{#if error}<p class="err">{error}</p>{/if}
	{#if actionError}<p class="err">{actionError}</p>{/if}

	{#if showRegister}
		<form class="form" onsubmit={register}>
			<label>name <input required bind:value={f.name} placeholder="crm.update_ticket" /></label>
			<label>description <input bind:value={f.description} maxlength="500" /></label>
			<label>
				risk class
				<select bind:value={f.risk_class}>
					{#each RISK_CLASSES as r (r)}<option value={r}>{r}</option>{/each}
				</select>
			</label>
			{#if RISKY.includes(f.risk_class)}
				<p class="muted small">Grants on a {f.risk_class} tool default to "needs approval".</p>
			{/if}
			<label class="check"><input type="checkbox" bind:checked={f.taints_session} /> its output is untrusted (taints the session)</label>
			<label class="check"><input type="checkbox" bind:checked={f.enabled} /> enabled now</label>
			<label>credential env var <input bind:value={f.credential_ref} placeholder="UPSTREAM_CRM_TOKEN (the name, never the secret)" /></label>
			<label>upstream <textarea rows="5" bind:value={f.upstream} spellcheck="false"></textarea></label>
			<label>args schema (JSON Schema) <textarea rows="8" bind:value={f.args_schema} spellcheck="false"></textarea></label>
			<label>context map (policy input → argument) <textarea rows="2" bind:value={f.context_map} spellcheck="false"></textarea></label>
			<button class="btn primary" disabled={busy === 'register'}>{busy === 'register' ? '…' : 'Register'}</button>
		</form>
	{/if}

	<ul class="tools">
		{#each tools as t (t.name)}
			<li class="tool" class:off={!t.enabled || !!t.problem}>
				<div class="row">
					<code>{t.name}</code>
					<span class="pill tiny risk {t.risk_class}">{t.risk_class}</span>
					{#if t.taints_session}<span class="pill tiny taint">taints</span>{/if}
					<span class="muted small">{where(t)}{t.credential_ref ? ` · key ${t.credential_ref}` : ''}</span>
					<button class="btn tiny" disabled={busy === t.name} onclick={() => setEnabled(t, !t.enabled)}>
						{busy === t.name ? '…' : t.enabled ? 'Switch off' : 'Switch on'}
					</button>
				</div>
				{#if t.problem}<p class="err small">misconfigured, every call is denied: {t.problem}</p>{/if}
				<div class="row small">
					<span class="muted">approvers:</span>
					{#each t.approvers ?? [] as a (a.user)}
						<span class="pill tiny info">{a.user.replace(/^user:/, '')}</span>
						{#if a.source === 'api'}
							<button class="btn tiny" disabled={busy === `appr:${t.name}:${a.user}`} onclick={() => removeApprover(t, a.user)}>×</button>
						{/if}
					{:else}
						<span class="muted">{t.approvers === null ? 'unavailable' : 'none'}</span>
					{/each}
					<button class="btn tiny" onclick={() => { approverFor = approverFor === t.name ? null : t.name; approver = 'user:'; }}>+</button>
				</div>
				{#if approverFor === t.name}
					<form class="row" onsubmit={(e) => addApprover(e, t)}>
						<input required bind:value={approver} placeholder="user:shiwin" />
						<button class="btn tiny primary" disabled={busy === `appr:${t.name}`}>Add approver</button>
					</form>
				{/if}
			</li>
		{:else}
			{#if !error}<li class="muted">Loading tools…</li>{/if}
		{/each}
	</ul>
</section>
