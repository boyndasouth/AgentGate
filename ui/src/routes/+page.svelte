<script lang="ts">
	import { onMount } from 'svelte';
	import { createClient, type RealtimeChannel, type SupabaseClient } from '@supabase/supabase-js';
	import { api } from '$lib/api';
	import type { Agent, Approval, AuditEvent, FeedMode } from '$lib/types';
	import AgentsPanel from '$lib/components/AgentsPanel.svelte';
	import ApprovalsPanel from '$lib/components/ApprovalsPanel.svelte';
	import FeedPanel from '$lib/components/FeedPanel.svelte';
	import VerifyPanel from '$lib/components/VerifyPanel.svelte';
	import DemoPanel from '$lib/components/DemoPanel.svelte';

	let { data } = $props();

	const MAX_EVENTS = 200;

	let agents = $state<Agent[]>([]);
	let agentsError = $state<string | null>(null);
	let approvals = $state<Approval[]>([]);
	let approvalsError = $state<string | null>(null);
	let events = $state<AuditEvent[]>([]);
	let feedError = $state<string | null>(null);
	let mode = $state<FeedMode>('connecting');
	let fresh = $state(new Set<number>());
	let brokenId = $state<number | null>(null);
	let now = $state(Date.now());
	let broker = $state<{ state: 'waking' | 'up' | 'down'; ms?: number; detail?: string }>({ state: 'waking' });

	async function loadAgents() {
		const r = await api<Agent[]>('/api/agents');
		if (r.ok) {
			agents = r.data;
			agentsError = null;
		} else agentsError = r.error ?? 'failed';
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
		loadAgents();
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
			await Promise.all([loadAgents(), loadApprovals(), pollEvents(false)]);

			const rt = data.realtime;
			if (rt?.token) {
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
					.subscribe((status) => {
						if (status === 'SUBSCRIBED') {
							stopPolling();
							mode = 'realtime';
							pollEvents(); // catch anything written while connecting
						} else if (status === 'CHANNEL_ERROR' || status === 'TIMED_OUT' || status === 'CLOSED') {
							startPolling();
						}
					});
				// If Realtime hasn't connected in 8 s, poll meanwhile.
				setTimeout(() => mode !== 'realtime' && startPolling(), 8000);
				// Slow safety net: RLS or a dropped socket can silently drop inserts.
				resyncTimer = setInterval(() => mode === 'realtime' && pollEvents(), 20_000);
			} else {
				startPolling();
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
		<div class="brand"><span class="logo">⛨</span> AgentGate <span class="muted">admin</span></div>
		<div class="row">
			<button class="status {broker.state}" onclick={wake} title={broker.detail ?? ''}>
				<span class="dot"></span>
				broker {data.brokerHost ?? '(not configured)'} ·
				{broker.state === 'waking' ? 'waking…' : broker.state === 'up' ? `up (${broker.ms} ms)` : 'down'}
			</button>
			<button class="btn ghost" onclick={refreshAll}>Refresh</button>
			<span class="muted small">{data.admin?.email ?? data.admin?.name}{data.admin?.fgaUser ? ` · user:${data.admin.fgaUser}` : ''}</span>
			<form method="POST" action="/signout"><button class="btn ghost">Sign out</button></form>
		</div>
	</header>

	{#if !data.brokerConfigured}
		<p class="err banner">BROKER_URL and AGENTGATE_ADMIN_KEY must be set on the server.</p>
	{/if}

	<main class="grid">
		<div class="col-left">
			<AgentsPanel {agents} error={agentsError} onchange={loadAgents} />
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
			<VerifyPanel onresult={(id) => (brokenId = id)} />
		</div>
		<div class="col-right">
			<DemoPanel enabled={data.demoEnabled} onactivity={() => mode === 'polling' && pollEvents()} />
			<FeedPanel {events} {mode} error={feedError} {fresh} {brokenId} />
		</div>
	</main>
</div>
