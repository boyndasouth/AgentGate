<script lang="ts">
	import { api } from '$lib/api';

	let { onresult }: { onresult: (brokenId: number | null) => void } = $props();

	type Raw = Record<string, unknown>;
	let busy = $state(false);
	let result = $state<{ valid: boolean; brokenId: number | null; count: unknown; reason: string | null; raw: Raw } | null>(null);
	let error = $state<string | null>(null);
	let showRaw = $state(false);

	// The broker's /audit/verify body is read defensively: different field names
	// for the same idea are all accepted.
	function normalise(d: Raw) {
		const fb = (d.first_broken ?? d.broken ?? null) as Raw | number | null;
		const brokenRaw =
			(typeof fb === 'object' && fb ? fb.id : fb) ?? d.first_broken_id ?? d.broken_at ?? d.bad_id ?? d.broken_id ?? null;
		const brokenId = brokenRaw == null ? null : Number(brokenRaw);
		const valid = Boolean(d.valid ?? d.ok ?? (brokenId === null));
		const reason =
			(typeof fb === 'object' && fb && typeof fb.reason === 'string' ? fb.reason : null) ??
			(typeof d.reason === 'string' ? d.reason : null) ??
			(typeof d.detail === 'string' ? d.detail : null);
		return { valid, brokenId, count: d.checked ?? d.count ?? d.events ?? d.length ?? null, reason, raw: d };
	}

	async function verify() {
		busy = true;
		error = null;
		const r = await api<Raw>('/api/verify');
		busy = false;
		if (!r.ok && !r.data) {
			error = r.error ?? 'failed';
			return;
		}
		result = normalise(r.data ?? {});
		onresult(result.valid ? null : result.brokenId);
	}
</script>

<section class="card verify-card">
	<header class="card-head">
		<h2>Audit chain</h2>
		<span class="muted small">sha256(prev_hash ‖ event), recomputed by the broker</span>
	</header>
	<div class="chain" class:run={busy} class:ok={!busy && result?.valid} class:bad={!busy && result && !result.valid} aria-hidden="true">
		{#each Array(12) as _, i}{#if i > 0}<span class="lnk"></span>{/if}<span class="blk" style="--i:{i}"></span>{/each}
	</div>
	<button class="btn primary wide" disabled={busy} onclick={verify}>{busy ? 'Verifying…' : 'Verify chain'}</button>

	{#if error}<p class="err">{error}</p>{/if}
	{#if result}
		{#if result.valid}
			<div class="verdict ok">✓ Chain intact{result.count != null ? ` · ${result.count} events checked` : ''}</div>
		{:else}
			<div class="verdict bad">
				✗ Chain broken{result.brokenId != null ? ` at row #${result.brokenId}` : ''}
				{#if result.reason}<div class="small">{result.reason}</div>{/if}
			</div>
		{/if}
		<button class="link small" onclick={() => (showRaw = !showRaw)}>{showRaw ? 'hide' : 'show'} raw response</button>
		{#if showRaw}<pre class="args">{JSON.stringify(result.raw, null, 2)}</pre>{/if}
	{/if}
</section>
