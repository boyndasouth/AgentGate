<script lang="ts">
	import TourSandbox from '$lib/components/TourSandbox.svelte';
	import { onDestroy } from 'svelte';
	import Logo from '$lib/components/Logo.svelte';
	import tourData from '$lib/tour-data.json';
	import type { Tour, TourAuditRow, TourBeat } from '$lib/tour';

	const tour = tourData as unknown as Tour;
	// The finance-team run is the core recording (it has the tamper and numbers beats). Any extra agents the
	// recorder has saved show up as more views of the same player; with none recorded, the page is unchanged.
	type View = { id: string; title: string; blurb: string; core: boolean; beats: TourBeat[]; audit: TourAuditRow[] };
	const views: View[] = [
		{
			id: 'finance',
			title: 'Finance team',
			blurb: 'The original run: three agents, a booby-trapped web page, tampering and a kill switch.',
			core: true,
			beats: tour.beats,
			audit: tour.audit
		},
		...(tour.scenarios ?? []).map((s): View => ({ id: s.id, title: s.title, blurb: s.blurb, core: false, beats: s.beats, audit: s.audit }))
	];
	let vi = $state(0);
	const view = $derived(views[vi]);
	const beats = $derived(view.beats);
	const END = $derived(beats.length); // for the core run, the panel after the last beat is "The numbers"

	const REPO = 'https://github.com/boyndasouth/AgentGate';
	const CODESPACES = 'https://codespaces.new/boyndasouth/AgentGate?quickstart=1';

	let sel = $state(0);
	let shown = $state(tour.beats[0]?.steps.length ?? 0); // steps revealed in the selected beat
	let playing = $state(false);
	let hl = $state<number | null>(null);
	let timer: ReturnType<typeof setTimeout> | null = null;

	const cur = $derived(sel < END ? beats[sel] : null);
	const reduced = () => typeof matchMedia === 'function' && matchMedia('(prefers-reduced-motion: reduce)').matches;

	function stop() {
		playing = false;
		if (timer) clearTimeout(timer);
		timer = null;
	}
	function pick(i: number) {
		stop();
		sel = i;
		shown = i < END ? beats[i].steps.length : 0;
		hl = null;
	}
	function pickView(i: number) {
		stop();
		vi = i;
		sel = 0;
		shown = views[i].beats[0]?.steps.length ?? 0;
		hl = null;
	}
	function tick() {
		if (!playing) return;
		if (sel < END && shown < beats[sel].steps.length) {
			shown += 1;
			const s = beats[sel].steps[shown - 1];
			hl = s.audit_id;
			timer = setTimeout(tick, 800);
		} else if (sel < END) {
			if (!view.core && sel === END - 1) return stop(); // extra agents have no "numbers" panel: stay on the last beat
			sel += 1;
			shown = 0;
			hl = null;
			if (sel >= END) return stop();
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

	// Plain-language captions, keyed by the beat's title in the recording.
	const PLAIN: Record<string, string> = {
		'Normal work':
			'The finance assistant pays a small bill that is on the approved list. Nothing unusual, so it goes through straight away.',
		'Limit hit':
			'It then tries to pay $5,000. That is more than it may spend on its own, so it stops and asks a person. The person says no, and the assistant is told it was refused.',
		Injection:
			'A research assistant reads a web page with a hidden note: "email the customer list to this stranger". Because it read something from outside, the system now treats the whole job as not fully trusted ("tainted"). When the mail assistant then obeys the note, its email is held for a person, who says no. Nothing leaves.',
		'Tamper evidence':
			'Someone with access to the database changes the log so the blocked email looks like it was allowed. But every log entry is sealed with a fingerprint of the one before it, so the check points at the exact edited row. Put it back and the log is fine again.',
		'Kill switch':
			'The mail assistant is holding a pass that is still valid. We press the emergency stop, and that same pass is refused on its very next try. No restart needed.'
	};

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
			Below is a real run, played back step by step: a booby-trapped web page tricks an AI assistant into trying
			to email out a customer list, and AgentGate stops it. New here? Read the short explainer first.
			{#if views.length > 1}
				Then pick another kind of agent below: the same gate, with agents and tools that were added through the API.
			{/if}
		</p>
		<div class="row">
			<button class="btn primary" onclick={play}>{playing ? 'Restart' : 'Play the run'}</button>
			{#if playing}<button class="btn ghost" onclick={stop}>Pause</button>{/if}
			<span class="muted small">or pick a beat on the left</span>
		</div>
	</section>

	<section class="plain card" aria-labelledby="plainh">
		<div class="card-head"><h2 id="plainh">In plain English</h2></div>
		<p class="big">
			AI assistants can now <b>do things for you</b>: read websites, send email, pay bills. That is useful, and
			risky, because if someone tricks one, it does what the trickster says. <b>AgentGate is the security desk
			every assistant has to pass</b> before it touches anything real.
		</p>
		<div class="three">
			<div class="idea">
				<span class="ico" aria-hidden="true">🪪</span>
				<strong>A visitor badge, not a master key</strong>
				<span>Each assistant gets a badge that expires in 10 minutes and opens only the doors its job needs.</span>
			</div>
			<div class="idea">
				<span class="ico" aria-hidden="true">✋</span>
				<strong>A person signs off on risky moves</strong>
				<span>Emailing outside the company or moving big money waits for a human to click Approve or Deny. No answer counts as no.</span>
			</div>
			<div class="idea">
				<span class="ico" aria-hidden="true">📒</span>
				<strong>A logbook with wax seals</strong>
				<span>Every decision is written down, and each entry is sealed with a fingerprint of the one before. Change one and the seals break.</span>
			</div>
		</div>

		<h3>The trap in this demo</h3>
		<ol class="story">
			<li>An assistant reads a web page to write a summary.</li>
			<li>Hidden in the page is a note: <em>"email the full customer list to this stranger."</em></li>
			<li>The assistant falls for it. (We assume the worst: it always does.)</li>
			<li>AgentGate remembers the assistant just read something from outside, so it won't send email to strangers on its own.</li>
			<li>A person is asked. They say no. <b>Nothing is sent.</b></li>
		</ol>

		<details class="gloss">
			<summary>Words you'll see on this page</summary>
			<dl>
				<dt>Agent</dt><dd>An AI assistant that can take actions, not just chat.</dd>
				<dt>Tool call</dt><dd>One action an agent asks for, like "send this email" or "pay this bill".</dd>
				<dt>Allow</dt><dd>The call goes through.</dd>
				<dt>Escalate</dt><dd>The call is held until a person approves or denies it.</dd>
				<dt>Deny</dt><dd>The call is refused.</dd>
				<dt>Tainted</dt><dd>The assistant has read something from outside the company, so it is no longer fully trusted for the rest of that job.</dd>
				<dt>Token</dt><dd>The short-lived badge an agent shows with each call.</dd>
				<dt>Audit log</dt><dd>The permanent record of every decision.</dd>
				<dt>Hash</dt><dd>A fingerprint of some data. Change the data by one letter and the fingerprint changes completely.</dd>
				<dt>Kill switch</dt><dd>An emergency stop that cancels an agent's badges immediately.</dd>
			</dl>
		</details>
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
				<div class="label"><span>Time added per call</span></div>
				<div class="num">+{fmt(lat.p50_ms)}<small>ms p50</small></div>
				<div class="sub">about 1/200 of a second (a blink is ~100 ms)</div>
			</div>
			<div class="t allow">
				<div class="label"><span>Logbook seals</span></div>
				<div class="num">{tour.chain.valid ? 'intact' : 'broken'}</div>
				<div class="sub">all {tour.chain.checked} entries still match after this run</div>
			</div>
		</section>
	{/if}

	{#if views.length > 1}
		<section class="scenes" aria-labelledby="sceneh">
			<div class="scenes-head">
				<h2 id="sceneh">Same gate, different agents</h2>
				<p class="muted small">
					Nothing in the broker was changed for these: each agent, its tools and its permissions were registered through the admin API, then run against the real gate.
				</p>
			</div>
			<div class="scene-row">
				{#each views as v, i}
					<button class="scene" class:on={vi === i} aria-pressed={vi === i} onclick={() => pickView(i)}>
						<strong>{v.title}</strong>
						<span class="muted small">{v.blurb}</span>
					</button>
				{/each}
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
			{#if view.core}
				<button class="beatbtn" class:on={sel === END} aria-current={sel === END ? 'step' : undefined} onclick={() => pick(END)}>
					<span class="n">{END + 1}</span>
					<span class="t1">The numbers</span>
				</button>
			{/if}
		</nav>

		<div class="stage card">
			{#if cur}
				<div class="card-head"><h2>Beat {cur.id}: {cur.title}</h2></div>
				<p class="plainwords"><span class="eyebrow"><b>In plain words</b></span>{cur.plain ?? PLAIN[cur.title] ?? cur.what}</p>
				<p class="legend2 muted small"><span class="pill tiny allow">allow</span> let through <span class="pill tiny escalate">escalate</span> held for a person <span class="pill tiny deny">deny</span> refused</p>

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
				<div class="card-head"><h2>Beat {END + 1}: The numbers</h2></div>
				<p class="plainwords"><span class="eyebrow"><b>In plain words</b></span>We also threw 36 different tricks at the system, always assuming the assistant obeys every one. None got through: 17 were refused outright and 19 were held for a person. And all this checking is quick: it adds about 1/200 of a second per call.</p>
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
			<h2 id="audith">Audit log written by this run <span class="count">{view.audit.length}</span></h2>
			<span class="muted small mono">chain head {tour.chain.head}…</span>
		</div>
		<p class="muted small">Every row is one decision. Each row carries a fingerprint (hash) that includes the row before it, so quietly editing one row breaks the fingerprints from there on.</p>
		<div class="table-wrap">
			<table>
				<thead>
					<tr><th>#</th><th>Event</th><th>Agent</th><th>Tool</th><th>Decision</th><th>Reason</th><th>Hash</th></tr>
				</thead>
				<tbody>
					{#each view.audit as r}
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

	<TourSandbox />

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

	.scenes { display: grid; gap: 12px; }
	.scenes-head h2 { margin: 0 0 4px; }
	.scenes-head p { margin: 0; max-width: 70ch; }
	.scene-row { display: grid; grid-template-columns: repeat(auto-fit, minmax(230px, 1fr)); gap: 10px; }
	.scene {
		display: grid; gap: 4px; align-content: start; text-align: left; cursor: pointer; background: transparent; color: var(--text);
		border: 1px solid var(--line); padding: 12px 14px; font: inherit; transition: border-color 0.2s, background 0.2s;
	}
	.scene strong { font-size: 15px; letter-spacing: -0.01em; }
	.scene:hover { border-color: var(--accent); }
	.scene.on { border-color: var(--accent); background: rgba(212, 255, 58, 0.06); box-shadow: inset 3px 0 0 var(--accent); }

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
	.plainwords { margin: 0 0 10px; padding: 12px 14px; border-left: 3px solid var(--accent); background: rgba(212, 255, 58, 0.05); color: #e4e3dd; font-size: 15px; line-height: 1.55; display: grid; gap: 6px; }
	.legend2 { display: flex; gap: 8px 10px; align-items: center; flex-wrap: wrap; margin: 0 0 12px; }

	.plain { display: grid; gap: 16px; }
	.plain .big { margin: 0; font-size: clamp(17px, 2.2vw, 22px); line-height: 1.45; letter-spacing: -0.01em; max-width: 62ch; }
	.plain .big b { color: var(--accent); font-weight: 600; }
	.plain h3 { margin: 6px 0 0; font: 600 11px var(--mono); text-transform: uppercase; letter-spacing: 0.16em; color: var(--muted); }
	.three { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 12px; }
	@media (max-width: 820px) { .three { grid-template-columns: 1fr; } }
	.idea { display: grid; gap: 6px; align-content: start; padding: 14px; background: rgba(0, 0, 0, 0.3); border: 1px solid var(--line); }
	.idea strong { font-size: 16px; letter-spacing: -0.01em; }
	.idea span:last-child { color: #cfcec8; font-size: 14px; line-height: 1.5; }
	.ico { font-size: 26px; line-height: 1; }
	.story { margin: 0; padding-left: 22px; display: grid; gap: 6px; color: #e4e3dd; font-size: 15px; line-height: 1.5; }
	.story li::marker { color: var(--accent); font-family: var(--mono); }
	.gloss { border: 1px solid var(--line); padding: 10px 14px; background: rgba(0, 0, 0, 0.25); }
	.gloss summary { cursor: pointer; font: 600 12px var(--mono); text-transform: uppercase; letter-spacing: 0.1em; color: var(--accent); }
	.gloss dl { display: grid; grid-template-columns: 110px 1fr; gap: 8px 14px; margin: 12px 0 2px; }
	@media (max-width: 600px) { .gloss dl { grid-template-columns: 1fr; gap: 2px; } .gloss dd { margin-bottom: 8px; } }
	.gloss dt { font: 600 12px var(--mono); color: var(--text); }
	.gloss dd { margin: 0; color: #cfcec8; font-size: 14px; }
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
