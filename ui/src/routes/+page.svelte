<script lang="ts">
	import { onMount } from 'svelte';
	import { createClient, type RealtimeChannel, type SupabaseClient } from '@supabase/supabase-js';
	import { api } from '$lib/api';
	import type { Agent, Approval, AuditEvent, FeedMode, Tool } from '$lib/types';
	import AgentsPanel from '$lib/components/AgentsPanel.svelte';
	import ApprovalsPanel from '$lib/components/ApprovalsPanel.svelte';
	import FeedPanel from '$lib/components/FeedPanel.svelte';
	import ToolsPanel from '$lib/components/ToolsPanel.svelte';
	import VerifyPanel from '$lib/components/VerifyPanel.svelte';
	import DemoPanel from '$lib/components/DemoPanel.svelte';
	import Logo from '$lib/components/Logo.svelte';
	import GateField from '$lib/components/GateField.svelte';
	import Count from '$lib/components/Count.svelte';

	let { data } = $props();

	const MAX_EVENTS = 200;

	let agents = $state<Agent[]>([]);
	let agentsError = $state<string | null>(null);
	let tools = $state<Tool[]>([]);
	let toolsError = $state<string | null>(null);
	let approvals = $state<Approval[]>([]);
	let approvalsError = $state<string | null>(null);
	let events = $state<AuditEvent[]>([]);
	let feedError = $state<string | null>(null);
	let mode = $state<FeedMode>('connecting');
	/** Why the feed isn't on Realtime (shown under the badge). Empty when live. */
	let rtWhy = $state('');
	let fresh = $state(new Set<number>());
	let brokenId = $state<number | null>(null);
	let now = $state(Date.now());
	let broker = $state<{ state: 'waking' | 'up' | 'down'; ms?: number; detail?: string }>({ state: 'waking' });

	// Live numbers for the stat strip, taken from the events the feed already holds.
	const stats = $derived.by(() => {
		let allow = 0, escalate = 0, deny = 0;
		const tainted = new Set<string>();
		for (const e of events) {
			if (e.decision === 'allow') allow++;
			else if (e.decision === 'escalate') escalate++;
			else if (e.decision === 'deny') deny++;
			if (e.session_tainted && e.session_id) tainted.add(e.session_id);
		}
		const active = agents.filter((a) => a.status !== 'disabled').length;
		return { allow, escalate, deny, tainted: tainted.size, active, total: agents.length, spark: events.slice(0, 36).reverse() };
	});
	const initials = (s: string | undefined | null) => (s ?? '?').replace(/[^a-z0-9]/gi, ' ').trim().split(/\s+/).slice(0, 2).map((w) => w[0]).join('') || '?';

	function decodeClaims(jwt: string): Record<string, unknown> | null {
		try {
			return JSON.parse(atob(jwt.split('.')[1].replace(/-/g, '+').replace(/_/g, '/')));
		} catch {
			return null;
		}
	}
	// https://dev-abc.us.auth0.com/ → "dev-abc" / "us"
	const tenantOf = (iss: unknown) => String(iss ?? '').replace(/^https?:\/\//, '').split('.')[0];
	const regionOf = (iss: unknown) => {
		const parts = String(iss ?? '').replace(/^https?:\/\//, '').split('.');
		return parts.length > 3 ? parts[1] : '(none)';
	};

	async function loadAgents() {
		const r = await api<Agent[]>('/api/agents');
		if (r.ok) {
			agents = r.data;
			agentsError = null;
		} else agentsError = r.error ?? 'failed';
	}

	// Day 12: the tool registry (risk classes for the grant form, approvers, on/off).
	async function loadTools() {
		const r = await api<Tool[]>('/api/tools');
		if (r.ok) {
			tools = r.data;
			toolsError = null;
		} else toolsError = r.error ?? 'failed';
	}

	function loadRegistry() {
		loadAgents();
		loadTools();
	}

	async function loadApprovals() {
		const r = await api<Approval[]>('/api/approvals');
		if (r.ok) {
			approvals = r.data;
			approvalsError = null;
		} else approvalsError = r.error ?? 'failed';
	}

	/** Merge events by id, newest first; flash the new ones; react to what they mean. */
	function ingest(incoming: AuditEvent[], flash: boolean) {
		const known = new Set(events.map((e) => e.id));
		const added = incoming.filter((e) => !known.has(e.id));
		if (!added.length) return;
		events = [...added, ...events].sort((a, b) => b.id - a.id).slice(0, MAX_EVENTS);

		if (flash && known.size > 0) {
			const ids = added.map((e) => e.id);
			fresh = new Set([...fresh, ...ids]);
			setTimeout(() => {
				fresh = new Set([...fresh].filter((id) => !ids.includes(id)));
			}, 2500);
		}
		// Keep the other panels in step with what the feed just showed.
		if (added.some((e) => e.decision === 'escalate' || e.event_type.startsWith('approval'))) loadApprovals();
		if (added.some((e) => e.event_type === 'agent_disabled' || e.event_type === 'agent_enabled')) loadAgents();
		// Day 12: registry, grant and agent changes, made here, by another admin or in SQL
		const REGISTRY_EVENTS = ['registry_changed', 'grant_added', 'grant_removed', 'approver_added', 'approver_removed', 'agent_registered', 'agent_updated'];
		if (added.some((e) => REGISTRY_EVENTS.includes(e.event_type))) loadRegistry();
	}

	async function pollEvents(flash = true) {
		const r = await api<AuditEvent[]>('/api/events?limit=50');
		if (r.ok) {
			feedError = null;
			ingest(r.data, flash);
			return true;
		}
		feedError = r.error ?? 'failed';
		return false;
	}

	async function wake() {
		broker = { state: 'waking' };
		const r = await api<{ ok: boolean; ms: number; detail?: string }>('/api/health');
		broker = r.ok ? { state: 'up', ms: r.data.ms } : { state: 'down', detail: r.data?.detail ?? r.error };
		return r.ok;
	}

	function refreshAll() {
		loadRegistry();
		loadApprovals();
		pollEvents();
	}

	onMount(() => {
		let supabase: SupabaseClient | null = null;
		let channel: RealtimeChannel | null = null;
		let pollTimer: ReturnType<typeof setInterval> | null = null;
		let resyncTimer: ReturnType<typeof setInterval> | null = null;
		const tick = setInterval(() => (now = Date.now()), 1000);

		const startPolling = () => {
			if (pollTimer) return;
			mode = 'polling';
			pollTimer = setInterval(() => pollEvents(), 3000);
		};
		const stopPolling = () => {
			if (pollTimer) clearInterval(pollTimer);
			pollTimer = null;
		};

		(async () => {
			await wake(); // first request may take ~1 min on Render's free tier
			await Promise.all([loadAgents(), loadTools(), loadApprovals(), pollEvents(false)]);

			const rt = data.realtime;
			const claims = rt?.token ? decodeClaims(rt.token) : null;
			if (!rt) {
				rtWhy = 'Realtime off: PUBLIC_SUPABASE_URL / PUBLIC_SUPABASE_ANON_KEY are not set on the server (Vercel: add them, then Redeploy).';
				startPolling();
			} else if (!rt.token) {
				rtWhy = 'Realtime off: no Auth0 ID token in your session. Sign out and sign in again.';
				startPolling();
			} else if (claims?.role !== 'authenticated') {
				rtWhy =
					`Realtime off: your Auth0 ID token has no role=authenticated claim (issuer ${claims?.iss ?? '?'}). ` +
					'Deploy the "Supabase role" Action, add it to Actions → Triggers → post-login, Apply, then sign out and in.';
				startPolling();
			} else {
				rtWhy = 'Connecting to Supabase Realtime…';
				// Supabase Third-Party Auth: the Auth0 ID token is the access token.
				supabase = createClient(rt.url!, rt.key!, {
					accessToken: async () => rt.token,
					realtime: { params: { eventsPerSecond: 20 } }
				});
				channel = supabase
					.channel('audit-feed')
					.on('postgres_changes', { event: 'INSERT', schema: 'public', table: 'audit_events' }, (payload) =>
						ingest([payload.new as AuditEvent], true)
					)
					.subscribe((status, err) => {
						if (status === 'SUBSCRIBED') {
							stopPolling();
							mode = 'realtime';
							rtWhy = '';
							pollEvents(); // catch anything written while connecting
						} else if (status === 'CHANNEL_ERROR' || status === 'TIMED_OUT' || status === 'CLOSED') {
							const msg = err?.message ?? '';
							rtWhy =
								`Realtime ${status}${msg ? `: ${msg}` : ''}. ` +
								(/transport|websocket|network|connect/i.test(msg)
									? 'The browser could not open the Realtime socket: check PUBLIC_SUPABASE_URL (https://<ref>.supabase.co) and the anon key in Vercel, redeploy, or try without browser extensions.'
									: /jwt|token|issuer|signature|unauthori[sz]ed|claim/i.test(msg)
										? `Supabase rejected the Auth0 token (issuer ${claims?.iss}). Check Authentication → Third-Party Auth → Auth0: tenant "${tenantOf(claims?.iss)}", region "${regionOf(claims?.iss)}".`
										: 'Check that audit_events is in the supabase_realtime publication (deploy/supabase_ui.sql).');
							startPolling();
						}
					});
				// If Realtime hasn't connected in 8 s, poll meanwhile.
				setTimeout(() => {
					if (mode !== 'realtime') {
						if (rtWhy.startsWith('Connecting')) rtWhy = 'Realtime: no answer from Supabase in 8 s (still trying). Check the Supabase URL/key.';
						startPolling();
					}
				}, 8000);
				// Slow safety net: RLS or a dropped socket can silently drop inserts.
				resyncTimer = setInterval(() => mode === 'realtime' && pollEvents(), 20_000);
			}
		})();

		return () => {
			clearInterval(tick);
			stopPolling();
			if (resyncTimer) clearInterval(resyncTimer);
			if (channel && supabase) supabase.removeChannel(channel);
		};
	});
</script>

<svelte:head><title>AgentGate · Admin</title></svelte:head>

<div class="shell">
	<header class="topbar">
		<div class="brand"><Logo /> AgentGate <span class="muted">admin</span></div>
		<div class="row">
			<button class="status {broker.state}" onclick={wake} title={broker.detail ?? 'Click to ping the broker'}>
				<span class="dot"></span>
				{data.brokerHost ?? '(not configured)'} ·
				{broker.state === 'waking' ? 'waking…' : broker.state === 'up' ? `up · ${broker.ms} ms` : 'down'}
			</button>
			<button class="btn ghost" onclick={refreshAll}>Refresh</button>
			<span class="who" title={data.admin?.fgaUser ? `user:${data.admin.fgaUser}` : ''}>
				<i>{initials(data.admin?.name ?? data.admin?.email)}</i>{data.admin?.email ?? data.admin?.name}
			</span>
			<form method="POST" action="/signout"><button class="btn ghost">Sign out</button></form>
		</div>
	</header>

	{#if !data.brokerConfigured}
		<p class="err banner">BROKER_URL and AGENTGATE_ADMIN_KEY must be set on the server.</p>
	{/if}

	<main class="content">
		<section class="hero" aria-label="Live checkpoint">
			<div class="hero-head">
				<div>
					<p class="eyebrow"><b>●</b> live checkpoint</p>
					<h1 class="kinetic">
						<span class="w"><span style="--i:0">Every</span></span>
						<span class="w"><span style="--i:1">call</span></span>
						<span class="w"><span style="--i:2">passes</span></span>
						<span class="w"><span style="--i:3">the</span></span>
						<span class="w"><span style="--i:4"><em>gate.</em></span></span>
					</h1>
				</div>
				<div>
					<p class="boot">
						<span class="ok">GATE ONLINE</span> · {stats.active} agents · {tools.filter((t) => t.enabled).length} tools · {approvals.length} held<span class="cur"></span>
					</p>
					<div class="legend" style="margin-top: 10px">
						<span style="--c: #6dffb3"><i></i>allowed</span>
						<span style="--c: #ffb21f"><i></i>held for a human</span>
						<span style="--c: #ff3d5a"><i></i>blocked</span>
						<span style="--c: #ff7a1a"><i></i>tainted</span>
					</div>
				</div>
			</div>
			<GateField {agents} {tools} {events} {approvals} />
		</section>

		<section class="ticker" aria-label="Summary of recent events">
			<div class="t allow" class:hot={stats.allow > 0} style="--k: {Math.min(1, stats.allow / Math.max(1, events.length))}">
				<div class="label">Allowed <span>last {events.length}</span></div>
				<div class="num"><Count value={stats.allow} /></div>
				<div class="spark" aria-hidden="true">{#each stats.spark as e (e.id)}<i class={e.decision}></i>{/each}</div>
				<span class="bar"></span>
			</div>
			<div class="t escalate" class:hot={stats.escalate > 0} style="--k: {Math.min(1, stats.escalate / Math.max(1, events.length))}">
				<div class="label">Escalated</div>
				<div class="num"><Count value={stats.escalate} /></div>
				<div class="sub">sent to a human</div>
				<span class="bar"></span>
			</div>
			<div class="t deny" class:hot={stats.deny > 0} style="--k: {Math.min(1, stats.deny / Math.max(1, events.length))}">
				<div class="label">Blocked</div>
				<div class="num"><Count value={stats.deny} /></div>
				<div class="sub">stopped by the gate</div>
				<span class="bar"></span>
			</div>
			<div class="t taint" class:hot={stats.tainted > 0} style="--k: {Math.min(1, stats.tainted / 4)}">
				<div class="label">Tainted sessions</div>
				<div class="num"><Count value={stats.tainted} /></div>
				<div class="sub">saw untrusted content</div>
				<span class="bar"></span>
			</div>
			<div class="t agents" style="--k: {stats.total ? stats.active / stats.total : 0}">
				<div class="label">Agents</div>
				<div class="num"><Count value={stats.active} /><small>/ {stats.total} active</small></div>
				<div class="sub">{approvals.length} approval{approvals.length === 1 ? '' : 's'} waiting</div>
				<span class="bar"></span>
			</div>
		</section>

		<div class="grid">
			<div class="col-left">
				<FeedPanel {events} {mode} error={feedError} {fresh} {brokenId} note={rtWhy} />
				<AgentsPanel {agents} {tools} error={agentsError} onchange={loadRegistry} />
				<ToolsPanel {tools} error={toolsError} onchange={loadRegistry} />
			</div>
			<div class="col-right">
				<ApprovalsPanel
					{approvals}
					error={approvalsError}
					canApprove={Boolean(data.admin?.canApprove)}
					{now}
					ondecided={() => {
						loadApprovals();
						pollEvents();
					}}
				/>
				<DemoPanel enabled={data.demoEnabled} onactivity={() => mode === 'polling' && pollEvents()} />
				<VerifyPanel onresult={(id) => (brokenId = id)} />
			</div>
		</div>
	</main>
</div>
