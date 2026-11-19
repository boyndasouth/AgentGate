<script lang="ts">
	import { onDestroy } from 'svelte';
	import Logo from '$lib/components/Logo.svelte';
	import tourData from '$lib/tour-data.json';
	import type { Tour, TourBeat } from '$lib/tour';

	const tour = tourData as unknown as Tour;
	const beats: TourBeat[] = tour.beats;
	const NUMBERS = beats.length; // the last panel, "The numbers", is not a beat in the recording

	const REPO = 'https://github.com/boyndasouth/AgentGate';
	const CODESPACES = 'https://codespaces.new/boyndasouth/AgentGate?quickstart=1';

	let sel = $state(0);
	let shown = $state(beats[0]?.steps.length ?? 0); // steps revealed in the selected beat
	let playing = $state(false);
	let hl = $state<number | null>(null);
	let timer: ReturnType<typeof setTimeout> | null = null;

	const cur = $derived(sel < NUMBERS ? beats[sel] : null);
	const reduced = () => typeof matchMedia === 'function' && matchMedia('(prefers-reduced-motion: reduce)').matches;

	function stop() {
		playing = false;
		if (timer) clearTimeout(timer);
		timer = null;
	}
	function pick(i: number) {
		stop();
		sel = i;
		shown = i < NUMBERS ? beats[i].steps.length : 0;
		hl = null;
	}
	function tick() {
		if (!playing) return;
		if (sel < NUMBERS && shown < beats[sel].steps.length) {
			shown += 1;
			const s = beats[sel].steps[shown - 1];
			hl = s.audit_id;
			timer = setTimeout(tick, 800);
		} else if (sel < NUMBERS) {
			sel += 1;
			shown = 0;
			hl = null;
			if (sel >= NUMBERS) return stop();
			timer = setTimeout(tick, 900);
		}
	}
	function play() {
		if (reduced()) return pick(0);
		stop();
		sel = 0;
		shown = 0;
		hl = null;
		playing = true;
		timer = setTimeout(tick, 400);
	}
	function showRow(id: number | null) {
		if (id == null) return;
		hl = id;
		document.getElementById(`row-${id}`)?.scrollIntoView({ block: 'nearest', behavior: reduced() ? 'auto' : 'smooth' });
	}
	onDestroy(stop);

	// Beat 4: the chain as blocks. Steps: edit, verify (broken), restore, verify (valid).
	const phase = $derived.by(() => {
		if (!cur || !tour.tamper || cur.title !== 'Tamper evidence') return 'intact';
		if (shown === 1 || shown === 3) return 'pending';
		return shown === 2 ? 'broken' : 'intact';
	});

	const when = (iso: string) => new Date(iso).toLocaleDateString('en-US', { day: 'numeric', month: 'short', year: 'numeric', timeZone: 'UTC' });
	const escalateAt = (b: TourBeat) => b.steps.findIndex((s) => s.outcome === 'escalate');
	const suite = tour.numbers.suite;
	const lat = tour.numbers.latency;
	const fmt = (n: number) => n.toFixed(1);
</script>

<svelte:head>
	<title>AgentGate · Recorded demo</title>
	<meta name="description" content="A real recorded run of AgentGate: a prompt-injected agent tries to email the customer list and is stopped at the gate. No login needed." />
</svelte:head>

<header class="topbar">
	<div class="brand"><Logo /> AgentGate <span class="muted">recorded demo</span></div>
	<nav class="row">
		<a class="btn ghost tiny" href={REPO}>Code</a>
		<a class="btn ghost tiny" href="#try">Try it</a>
		<a class="btn tiny" href="/login">Admin sign in</a>
	</nav>
</header>

<main class="tour">
	<section class="hero">
		<p class="eyebrow"><b>Recorded run</b> · {when(tour.recorded_at)} · {tour.target} stack</p>
		<h1 class="kinetic">
			<span class="w"><span style="--i: 0">A hijacked agent,</span></span>
			<span class="w"><span style="--i: 1"><em>stopped.</em></span></span>
		</h1>
		<p class="lede">
			AgentGate sits between AI agents and the tools they use. Every call is checked against a policy, risky
			ones wait for a human, and every decision goes into a hash-chained audit log. Below is a real run, played
			back step by step: a prompt-injected agent tries to email out the customer list.
		</p>
		<div class="row">
			<button class="btn primary" onclick={play}>{playing ? 'Restart' : 'Play the run'}</button>
			{#if playing}<button class="btn ghost" onclick={stop}>Pause</button>{/if}
			<span class="muted small">or pick a beat on the left</span>
		</div>
	</section>

	{#if suite && lat}
		<section class="ticker" aria-label="Headline numbers">
			<div class="t allow hot">
				<div class="label"><span>Attacks stopped</span></div>
				<div class="num">{suite.cases - suite.allowed}<small>/ {suite.cases}</small></div>
				<div class="sub">{suite.blocked} blocked · {suite.escalated} escalated · {suite.allowed} allowed</div>
				<span class="bar" style="--k: 1"></span>
			</div>
			<div class="t agents">
				<div class="label"><span>Gate overhead</span></div>
				<div class="num">+{fmt(lat.p50_ms)}<small>ms p50</small></div>
				<div class="sub">p95 +{fmt(lat.p95_ms)} ms on an allowed call</div>
			</div>
			<div class="t allow">
				<div class="label"><span>Audit chain</span></div>
				<div class="num">{tour.chain.valid ? 'valid' : 'broken'}</div>
				<div class="sub">{tour.chain.checked} rows checked after this run</div>
			</div>
		</section>
	{/if}

	<section class="player">
		<nav class="rail" aria-label="Demo beats">
			{#each beats as b, i}
				<button class="beatbtn" class:on={sel === i} aria-current={sel === i ? 'step' : undefined} onclick={() => pick(i)}>
					<span class="n">{b.id}</span>
					<span class="t1">{b.title}</span>
					{#if b.outcome}<span class="pill tiny {b.outcome}">{b.outcome}</span>{/if}
				</button>
			{/each}
			<button class="beatbtn" class:on={sel === NUMBERS} aria-current={sel === NUMBERS ? 'step' : undefined} onclick={() => pick(NUMBERS)}>
				<span class="n">{NUMBERS + 1}</span>
				<span class="t1">The numbers</span>
			</button>
		</nav>

		<div class="stage card">
			{#if cur}
				<div class="card-head"><h2>Beat {cur.id}: {cur.title}</h2></div>
				<p class="what">{cur.what}</p>

				<ol class="steps2">
					{#each cur.steps as s, i}
						{#if i < shown}
							<li class="st {s.outcome}">
								<span class="who2">{s.actor}</span>
								<span class="body">
									<span class="act">{s.action}</span>
									<span class="why muted small">{s.reason}</span>
								</span>
								<span class="meta">
									<span class="pill {s.outcome}">{s.outcome === 'info' ? 'done' : s.outcome}</span>
									{#if s.session_tainted}<span class="pill tiny taint">tainted</span>{/if}
									<span class="muted small mono">HTTP {s.http}{s.ms != null ? ` · ${fmt(s.ms)} ms` : ''}</span>
									{#if s.audit_id != null}
										<button class="link small" onclick={() => showRow(s.audit_id)}>audit #{s.audit_id}</button>
									{/if}
								</span>
							</li>
						{/if}
					{/each}
				</ol>

				{#if cur.approval?.tool && shown > escalateAt(cur)}
					<div class="approval" class:tainted={cur.approval.session_tainted}>
						<div class="approval-top">
							<strong>Approval needed · {cur.approval.tool}</strong>
							<span class="pill escalate">waiting</span>
						</div>
						<p class="reason small">{cur.approval.reason}</p>
						<pre class="args">{Object.entries(cur.approval.args ?? {}).map(([k, v]) => `${k}: ${v}`).join('\n')}</pre>
						<p class="muted small">
							What the approver sees. In the live setup this is a Slack message with Approve and Deny; here the
							decision was made through the admin API.
						</p>
					</div>
				{/if}

				{#if cur.title === 'Tamper evidence' && tour.tamper}
					<div class="chainviz" role="img" aria-label="Audit chain as blocks">
						{#each tour.audit as r, i}
							<span
								class="cb"
								class:edit={r.id === tour.tamper.row_id}
								class:broken={phase === 'broken' && r.id === tour.tamper.row_id}
								class:pending={phase === 'pending' && r.id === tour.tamper.row_id}
								title="audit #{r.id}"
							></span>
							{#if i < tour.audit.length - 1}<span class="cl"></span>{/if}
						{/each}
					</div>
					<p class="muted small">
						Each block is an audit row, and each row's hash covers the one before it. The edited row is #{tour.tamper.row_id}.
					</p>
				{/if}

				{#if shown >= cur.steps.length}
					<p class="says"><b>{cur.note}</b></p>
				{/if}
			{:else}
				<div class="card-head"><h2>Beat {NUMBERS + 1}: The numbers</h2></div>
				<p class="what">What the gate does across a full set of attacks, and what it costs.</p>
				<dl class="facts">
					{#if suite}
						<dt>Injection suite</dt>
						<dd>
							{suite.cases - suite.allowed} of {suite.cases} attacks stopped ({suite.blocked} blocked outright,
							{suite.escalated} sent to a human), assuming the model obeys every injected instruction. Run
							against the {suite.target === 'render' ? 'deployed' : suite.target} broker on {when(suite.run_at)}.
						</dd>
					{/if}
					{#if lat}
						<dt>Latency</dt>
						<dd>+{fmt(lat.p50_ms)} ms at the median and +{fmt(lat.p95_ms)} ms at p95, added to an allowed tool call (measured on a laptop with the full local stack, {when(lat.run_at)}).</dd>
					{/if}
					<dt>Not covered</dt>
					<dd>
						The suite plays worst-case calls through the gate; it doesn't measure how often a real model falls for
						an injection. The repo README covers that run, the threat model and the known limits.
					</dd>
				</dl>
				<p><a class="btn" href="{REPO}#results">Read the full results</a></p>
			{/if}
		</div>
	</section>

	<section class="card auditcard" aria-labelledby="audith">
		<div class="card-head">
			<h2 id="audith">Audit log written by this run <span class="count">{tour.audit.length}</span></h2>
			<span class="muted small mono">chain head {tour.chain.head}…</span>
		</div>
		<div class="table-wrap">
			<table>
				<thead>
					<tr><th>#</th><th>Event</th><th>Agent</th><th>Tool</th><th>Decision</th><th>Reason</th><th>Hash</th></tr>
				</thead>
				<tbody>
					{#each tour.audit as r}
						<tr id="row-{r.id}" class="d-{r.decision}" class:tainted={r.tainted} class:broken={phase === 'broken' && tour.tamper && r.id === tour.tamper.row_id} class:hl={hl === r.id}>
							<td class="mono">{r.id}</td>
							<td class="mono small">{r.event}</td>
							<td class="mono small">{r.agent ?? ''}</td>
							<td class="mono small">{r.tool ?? ''}</td>
							<td><span class="pill tiny {r.decision}">{r.decision}</span></td>
							<td class="reason-cell small">{r.reason}{#if r.approver}<br /><span class="muted">by {r.approver}</span>{/if}</td>
							<td class="mono small muted">{r.hash}</td>
						</tr>
					{/each}
				</tbody>
			</table>
		</div>
		<p class="muted small">Arguments are never stored: the log holds only keyed hashes of them. The recorded customer list is just a row count.</p>
	</section>

	<section id="try" class="trycards">
		<h2>Try it yourself</h2>
		<div class="cards3">
			<a class="card trycard" href={CODESPACES}>
				<span class="eyebrow"><b>1</b> · in your browser</span>
				<strong>Open in GitHub Codespaces</strong>
				<span class="muted small">Brings up the whole stack and runs the injection demo. Nothing to install, no accounts besides GitHub.</span>
			</a>
			<a class="card trycard" href="{REPO}#try-it">
				<span class="eyebrow"><b>2</b> · on your machine</span>
				<strong>Run it locally with Docker</strong>
				<span class="muted small">A few commands, no Slack, Auth0 or model key needed. The README has the exact steps.</span>
			</a>
			<a class="card trycard" href={REPO}>
				<span class="eyebrow"><b>3</b> · read it</span>
				<strong>Browse the code</strong>
				<span class="muted small">Policy model, broker, tests, threat model, and the results behind the numbers above.</span>
			</a>
		</div>
		<p class="muted small">
			The live admin UI behind <a href="/login">sign in</a> is invite-only: it can approve payments and flip kill
			switches. Everything on this page is a replay, so you can't change anything here.
		</p>
	</section>

	<footer class="muted small foot">
		Recorded {when(tour.recorded_at)} on a {tour.target} stack with <code>eval/export_tour.py</code>. Approvals were
		decided through the {tour.approvals_by.split(' (')[0]}; Slack was not connected.
	</footer>
</main>

<style>
	.tour { grid-template-columns: minmax(0, 1fr); max-width: 1180px; margin: 0 auto; padding: 28px 24px 70px; display: grid; gap: 28px; }
	.hero { display: grid; gap: 16px; }
	.hero .kinetic { font-size: clamp(36px, 7vw, 84px); margin-top: 4px; }
	.hero .kinetic .w { margin-right: 0.22em; }
	.lede { max-width: 66ch; color: #cfcec8; font-size: 16px; line-height: 1.55; margin: 0; }

	.ticker { grid-template-columns: repeat(3, minmax(0, 1fr)); }
	@media (max-width: 760px) {
		.ticker { grid-template-columns: 1fr; }
		.ticker :global(.t) { border-right: none; border-bottom: 1px solid var(--line); }
	}
	.ticker :global(.num) { justify-content: flex-start; }

	.player { display: grid; grid-template-columns: 230px minmax(0, 1fr); gap: 18px; align-items: start; }
	@media (max-width: 820px) { .player { grid-template-columns: 1fr; } }
	.rail { display: grid; gap: 6px; position: sticky; top: 64px; }
	@media (max-width: 820px) { .rail { position: static; grid-template-columns: repeat(2, minmax(0, 1fr)); } }
	.beatbtn {
		display: grid; grid-template-columns: 22px 1fr auto; gap: 8px; align-items: center; text-align: left; cursor: pointer;
		background: transparent; color: var(--text); border: 1px solid var(--line); padding: 10px 11px; font: 600 13px var(--sans);
		transition: border-color 0.2s, background 0.2s;
	}
	.beatbtn:hover { border-color: var(--accent); }
	.beatbtn.on { border-color: var(--accent); background: rgba(212, 255, 58, 0.06); box-shadow: inset 3px 0 0 var(--accent); }
	.beatbtn .n { font: 600 11px var(--mono); color: var(--accent); }

	.stage { min-height: 320px; min-width: 0; }
	.what { margin: 0 0 14px; color: #cfcec8; }
	.steps2 { list-style: none; margin: 0; padding: 0; display: grid; gap: 8px; }
	.st {
		display: grid; grid-template-columns: 112px minmax(0, 1fr) auto; gap: 12px; padding: 9px 11px; align-items: start;
		background: rgba(0, 0, 0, 0.3); border: 1px solid var(--line); border-left: 3px solid var(--line-strong);
		animation: rise 0.45s var(--ease) both;
	}
	.st.allow { border-left-color: var(--allow); } .st.escalate { border-left-color: var(--escalate); } .st.deny { border-left-color: var(--deny); } .st.info { border-left-color: var(--info); }
	@media (max-width: 700px) { .st { grid-template-columns: 1fr; gap: 4px; } }
	.who2 { font: 600 11px var(--mono); text-transform: uppercase; letter-spacing: 0.1em; color: var(--muted); padding-top: 2px; }
	.body { display: grid; gap: 2px; min-width: 0; }
	.act { font: 500 13px var(--mono); word-break: break-word; }
	.why { word-break: break-word; }
	.meta { display: flex; gap: 8px; align-items: center; flex-wrap: wrap; justify-content: flex-end; }
	@media (max-width: 700px) { .meta { justify-content: flex-start; } }
	.approval { margin-top: 14px; }
	.chainviz { display: flex; align-items: center; margin: 18px 0 6px; flex-wrap: nowrap; overflow-x: auto; padding-bottom: 4px; }
	.cb { flex: none; width: 14px; height: 14px; border: 1px solid var(--allow); background: rgba(109, 255, 179, 0.3); transition: background 0.3s, border-color 0.3s, box-shadow 0.3s; }
	.cl { flex: 1 0 6px; height: 1px; background: var(--allow); min-width: 6px; }
	.cb.edit { outline: 1px dashed var(--line-strong); outline-offset: 3px; }
	.cb.pending { background: rgba(255, 178, 31, 0.4); border-color: var(--escalate); }
	.cb.broken { background: rgba(255, 61, 90, 0.5); border-color: var(--deny); box-shadow: 0 0 14px var(--deny); }
	.facts { display: grid; grid-template-columns: 130px 1fr; gap: 10px 16px; margin: 0 0 16px; }
	@media (max-width: 600px) { .facts { grid-template-columns: 1fr; gap: 2px; } .facts dd { margin-bottom: 10px; } }
	.facts dt { font: 600 11px var(--mono); text-transform: uppercase; letter-spacing: 0.12em; color: var(--muted); padding-top: 3px; }
	.facts dd { margin: 0; color: #d9d8d2; }

	.auditcard :global(tr.hl td) { background: rgba(212, 255, 58, 0.12); }
	.auditcard .table-wrap { max-height: 420px; }

	.trycards { display: grid; gap: 14px; }
	.cards3 { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 14px; }
	@media (max-width: 820px) { .cards3 { grid-template-columns: 1fr; } }
	.trycard { display: grid; gap: 8px; align-content: start; text-decoration: none; color: var(--text); transition: border-color 0.2s, transform 0.2s var(--ease); }
	.trycard:hover { border-color: var(--accent); transform: translateY(-2px); }
	.trycard strong { font-size: 17px; letter-spacing: -0.01em; }
	.foot { border-top: 1px solid var(--line); padding-top: 14px; }
</style>
