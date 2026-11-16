<script lang="ts">
	import { clock } from '$lib/api';
	import type { AuditEvent, FeedMode } from '$lib/types';

	let {
		events,
		mode,
		error,
		fresh,
		brokenId,
		note = ''
	}: {
		events: AuditEvent[];
		mode: FeedMode;
		error: string | null;
		fresh: Set<number>;
		brokenId: number | null;
		note?: string;
	} = $props();

	let filter = $state<'all' | 'decisions' | 'tainted'>('all');

	const shown = $derived(
		events.filter((e) =>
			filter === 'all'
				? true
				: filter === 'tainted'
					? e.session_tainted === true
					: e.decision === 'allow' || e.decision === 'escalate' || e.decision === 'deny'
		)
	);

	const modeLabel: Record<FeedMode, string> = {
		connecting: 'connecting…',
		realtime: 'live · Supabase Realtime',
		polling: 'live · polling every 3 s',
		offline: 'offline'
	};

	function short(s: string | null | undefined, n = 8) {
		return s ? s.slice(0, n) : '';
	}
</script>

<section class="card feed">
	<header class="card-head">
		<h2>Decision feed</h2>
		<div class="row">
			<span class="mode {mode}"><span class="dot"></span>{modeLabel[mode]}</span>
			<select bind:value={filter} aria-label="Filter events">
				<option value="all">All events</option>
				<option value="decisions">Allow / escalate / deny</option>
				<option value="tainted">Tainted sessions</option>
			</select>
		</div>
	</header>

	{#if note && mode !== 'realtime'}<p class="muted small rt-note">{note}</p>{/if}
	{#if error}<p class="err">{error}</p>{/if}

	<div class="table-wrap">
		<table>
			<thead>
				<tr>
					<th>#</th><th>Time</th><th>Event</th><th>Agent</th><th>Tool</th><th>Decision</th><th>Taint</th><th>Reason</th>
				</tr>
			</thead>
			<tbody>
				{#each shown as e (e.id)}
					<tr class:fresh={fresh.has(e.id)} class:broken={brokenId === e.id} class:tainted={e.session_tainted}>
						<td class="mono muted">{e.id}</td>
						<td class="mono">{clock(e.ts)}</td>
						<td class="mono small">{e.event_type}</td>
						<td>{e.agent_id ?? '—'}</td>
						<td><code>{e.tool ?? ''}</code></td>
						<td><span class="pill {e.decision}">{e.decision}</span></td>
						<td>
							{#if e.session_tainted === true}<span class="pill tiny taint" title="session {short(e.session_id)}">⚠ tainted</span>
							{:else if e.session_tainted === false}<span class="muted small">clean</span>
							{/if}
						</td>
						<td class="reason-cell">
							{e.reason}
							{#if e.approver}<div class="muted small">by {e.approver}</div>{/if}
						</td>
					</tr>
				{:else}
					<tr><td colspan="8" class="muted empty">No events yet.</td></tr>
				{/each}
			</tbody>
		</table>
	</div>
</section>
