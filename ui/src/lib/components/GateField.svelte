<script lang="ts">
	// The gate field: agents on the left, the gate in the middle, tools on the right.
	// Every audit event becomes a particle. Allowed calls pass through, blocked calls shatter against the
	// gate, escalated calls stop and wait there until a human decides. A tainted session glows orange.
	// It only draws what the feed already holds; it never calls the broker. 2D canvas, capped particle
	// count, paused when hidden or off screen, static under prefers-reduced-motion.
	import { onMount, untrack } from 'svelte';
	import type { Agent, Approval, AuditEvent, Tool } from '$lib/types';
	import { PALETTE, colorFor } from '$lib/colors';

	let { agents, tools, events, approvals }: { agents: Agent[]; tools: Tool[]; events: AuditEvent[]; approvals: Approval[] } = $props();

	const C = { text: '#f4f1ff', accent: '#8b6bff', allow: '#2effc0', escalate: '#ffd23f', deny: '#ff4d6d', taint: '#ff8a3d', info: '#19c3ff', faint: '#6c6788', line: 'rgba(255,255,255,0.22)' };
	const RISK: Record<string, string> = { read: '#19c3ff', write: '#8b6bff', egress: '#ffd23f', money: '#ff5ca8', destructive: '#ff4d6d' };
	const MAX_PARTS = 90;

	interface Part {
		agent: string; color: string; tool: string | null; outcome: 'allow' | 'deny' | 'escalate'; tainted: boolean;
		phase: 'wait' | 'toGate' | 'held' | 'toTool' | 'done'; t: number; heldFor: number;
		trail: { x: number; y: number }[]; x: number; y: number; gy: number; fromY: number;
	}
	interface Ripple { x: number; y: number; r: number; max: number; a: number; color: string }
	interface Shard { x: number; y: number; vx: number; vy: number; a: number; len: number; rot: number }
	interface Dust { x: number; y: number; vx: number; vy: number; s: number; c: string }

	let wrap: HTMLDivElement;
	let canvas: HTMLCanvasElement;
	let W = 0, H = 0, dpr = 1;
	const parts: Part[] = [];
	const ripples: Ripple[] = [];
	const shards: Shard[] = [];
	const dust: Dust[] = [];
	const flashes = new Map<number, { t: number; color: string }>(); // gate lane y -> flash
	const resolved = new Map<string, string>(); // "agent|tool" -> allow | deny, from approval_resolved events
	let ctx: CanvasRenderingContext2D | null = null;
	let primed = false, lastId = 0;
	let mouse = { x: -999, y: -999, in: false };
	let hover: string | null = null;
	let raf = 0, last = 0, onScreen = true, reduce = false;
	let heldCount = $state(0);

	const gx = () => W * 0.5;
	const inset = () => (W < 600 ? W * 0.27 : Math.min(150, W * 0.16));
	const ax = () => inset();
	const tx = () => W - inset();
	const fit = (s: string) => { const n = Math.max(4, Math.floor((inset() - 24) / 6.7)); return s.length > n ? s.slice(0, n - 1) + '…' : s; };
	const laneY = (i: number, n: number) => 46 + ((i + 0.5) * (H - 92)) / Math.max(1, n);
	const agentY = (id: string) => { const i = agents.findIndex((a) => a.id === id); return i < 0 ? H / 2 : laneY(i, agents.length); };
	const toolY = (name: string | null) => { const i = tools.findIndex((t) => t.name === name); return i < 0 ? H / 2 : laneY(i, tools.length); };
	const pending = (p: Part) => approvals.some((a) => a.agent_id === p.agent && a.tool === p.tool);
	const ease = (k: number) => (k < 0.5 ? 4 * k * k * k : 1 - Math.pow(-2 * k + 2, 3) / 2);

	function spawn(e: AuditEvent, delay: number) {
		if (reduce || !e.agent_id) return;
		const key = `${e.agent_id}|${e.tool}`;
		if (e.event_type === 'approval_resolved') {
			resolved.set(key, e.decision);
			return;
		}
		if (e.decision === 'allow' || e.decision === 'deny' || e.decision === 'escalate') {
			if (e.event_type !== 'tool_call') return;
			if (parts.length >= MAX_PARTS) return;
			const gy = toolY(e.tool ?? null), fromY = agentY(e.agent_id);
			parts.push({ agent: e.agent_id, color: colorFor(Math.max(0, agents.findIndex((a) => a.id === e.agent_id))), tool: e.tool ?? null, outcome: e.decision, tainted: e.session_tainted === true, phase: 'wait', t: -delay / 1000, heldFor: 0, trail: [], x: ax(), y: fromY, gy, fromY });
		} else if (e.event_type === 'session_tainted') {
			ripples.push({ x: ax(), y: agentY(e.agent_id), r: 4, max: 46, a: 1, color: C.taint });
		} else if (e.event_type === 'token_issued' || e.event_type.startsWith('agent_')) {
			ripples.push({ x: ax(), y: agentY(e.agent_id), r: 4, max: 30, a: 0.9, color: colorFor(Math.max(0, agents.findIndex((a) => a.id === e.agent_id))) });
		}
	}

	// New events become particles. The first batch replays the last few, so the field isn't empty on load.
	$effect(() => {
		const evs = events;
		if (!evs.length) return;
		untrack(() => {
			const top = evs[0].id;
			if (!primed) {
				primed = true;
				lastId = top;
				evs.slice(0, 14).reverse().forEach((e, i) => spawn(e, i * 380));
				return;
			}
			const fresh = evs.filter((e) => e.id > lastId).reverse();
			lastId = Math.max(lastId, top);
			fresh.forEach((e, i) => spawn(e, i * 260));
		});
	});

	function burst(x: number, y: number, n: number) {
		for (let i = 0; i < n; i++) {
			const a = Math.random() * Math.PI * 2, s = 40 + Math.random() * 140;
			shards.push({ x, y, vx: Math.cos(a) * s - 30, vy: Math.sin(a) * s, a: 1, len: 4 + Math.random() * 9, rot: a });
		}
	}

	function step(dt: number) {
		heldCount = parts.filter((p) => p.phase === 'held').length;
		for (const p of parts) {
			p.t += dt;
			if (p.phase === 'wait' && p.t >= 0) { p.phase = 'toGate'; p.t = 0; }
			if (p.phase === 'wait') continue;
			const g = gx() - 12;
			if (p.phase === 'toGate') {
				const k = Math.min(1, p.t / 1.15), e = ease(k);
				p.x = ax() + 14 + (g - ax() - 14) * e;
				p.y = p.fromY + (p.gy - p.fromY) * e - Math.sin(Math.PI * e) * 16;
				if (k >= 1) {
					if (p.outcome === 'allow') { p.phase = 'toTool'; p.t = 0; flashes.set(p.gy, { t: 0, color: C.allow }); }
					else if (p.outcome === 'deny') { burst(g, p.gy, 16); flashes.set(p.gy, { t: 0, color: C.deny }); p.phase = 'done'; }
					else { p.phase = 'held'; p.t = 0; flashes.set(p.gy, { t: 0, color: C.escalate }); }
				}
			} else if (p.phase === 'held') {
				p.heldFor += dt;
				p.x = g; p.y = p.gy;
				if (p.heldFor > 1.6 && !pending(p)) {
					const r = resolved.get(`${p.agent}|${p.tool}`);
					if (r === 'allow') { p.phase = 'toTool'; p.t = 0; flashes.set(p.gy, { t: 0, color: C.allow }); }
					else if (r === 'deny') { burst(g, p.gy, 16); flashes.set(p.gy, { t: 0, color: C.deny }); p.phase = 'done'; }
					else { ripples.push({ x: g, y: p.gy, r: 4, max: 34, a: 0.9, color: C.escalate }); p.phase = 'done'; }
				} else if (p.heldFor > 140) p.phase = 'done';
			} else if (p.phase === 'toTool') {
				const k = Math.min(1, p.t / 0.95), e = ease(k), g0 = gx() + 12;
				p.x = g0 + (tx() - 14 - g0) * e;
				p.y = p.gy;
				if (k >= 1) { ripples.push({ x: tx(), y: p.gy, r: 4, max: 44, a: 1, color: p.color }); p.phase = 'done'; }
			}
			if (p.phase !== 'done') {
				p.trail.push({ x: p.x, y: p.y });
				if (p.trail.length > (p.tainted ? 16 : 10)) p.trail.shift();
			}
		}
		for (let i = parts.length - 1; i >= 0; i--) if (parts[i].phase === 'done') parts.splice(i, 1);
		for (const r of ripples) { r.r += 60 * dt; r.a -= 1.25 * dt; }
		for (let i = ripples.length - 1; i >= 0; i--) if (ripples[i].a <= 0 || ripples[i].r > ripples[i].max) ripples.splice(i, 1);
		for (const s of shards) { s.x += s.vx * dt; s.y += s.vy * dt; s.vx *= 0.97; s.vy *= 0.97; s.a -= 0.95 * dt; }
		for (let i = shards.length - 1; i >= 0; i--) if (shards[i].a <= 0) shards.splice(i, 1);
		for (const [y, f] of flashes) { f.t += dt; if (f.t > 0.9) flashes.delete(y); }
		for (const d of dust) {
			d.x += d.vx * dt; d.y += d.vy * dt;
			if (d.x < 0) d.x = W; if (d.x > W) d.x = 0; if (d.y < 0) d.y = H; if (d.y > H) d.y = 0;
			if (mouse.in) {
				const dx = d.x - mouse.x, dy = d.y - mouse.y, q = dx * dx + dy * dy;
				if (q < 90 * 90 && q > 1) { const f = (1 - Math.sqrt(q) / 90) * 90 * dt; d.x += (dx / Math.sqrt(q)) * f; d.y += (dy / Math.sqrt(q)) * f; }
			}
		}
	}

	function node(x: number, y: number, color: string, label: string, side: 'l' | 'r', dim: boolean, key: string) {
		const c = ctx!, hot = hover === key;
		c.globalAlpha = dim ? 0.35 : 1;
		c.strokeStyle = hot ? '#fff' : color; c.lineWidth = hot ? 2 : 1.5;
		c.beginPath(); c.roundRect(x - 7, y - 7, 14, 14, 5); c.stroke();
		c.shadowColor = color; c.shadowBlur = hot ? 20 : 10; c.fillStyle = hot ? '#fff' : color; c.beginPath(); c.arc(x, y, 3, 0, Math.PI * 2); c.fill(); c.shadowBlur = 0;
		c.font = '600 12px "Space Grotesk", sans-serif'; c.textBaseline = 'middle';
		c.fillStyle = hot ? '#fff' : C.text;
		c.textAlign = side === 'l' ? 'right' : 'left';
		c.fillText(fit(dim ? label + ' ×' : label), side === 'l' ? x - 14 : x + 14, y);
		c.globalAlpha = 1;
	}

	function draw() {
		const c = ctx; if (!c) return;
		c.setTransform(dpr, 0, 0, dpr, 0, 0);
		c.clearRect(0, 0, W, H);
		// dust
		c.globalAlpha = 0.5;
		for (const d of dust) { c.fillStyle = d.c; c.fillRect(d.x, d.y, d.s, d.s); }
		c.globalAlpha = 1;
		const g = gx();
		// lanes from the gate to each tool
		c.lineWidth = 1; c.setLineDash([2, 5]); c.strokeStyle = 'rgba(236,235,230,0.12)';
		tools.forEach((t, i) => { const y = laneY(i, tools.length); c.strokeStyle = (RISK[t.risk_class] ?? C.text) + '33'; c.beginPath(); c.moveTo(g + 12, y); c.lineTo(tx() - 10, y); c.stroke(); });
		agents.forEach((a, i) => { const y = laneY(i, agents.length); c.strokeStyle = colorFor(i) + '33'; c.beginPath(); c.moveTo(ax() + 10, y); c.lineTo(g - 12, y); c.stroke(); });
		c.setLineDash([]);
		// the gate: two bars, an aperture, a flash per lane
		const top = 30, bot = H - 30;
		const grad = c.createLinearGradient(0, top, 0, bot);
		grad.addColorStop(0, 'rgba(255,92,168,0.0)'); grad.addColorStop(0.2, 'rgba(255,92,168,0.16)'); grad.addColorStop(0.5, 'rgba(139,107,255,0.2)'); grad.addColorStop(0.8, 'rgba(25,195,255,0.16)'); grad.addColorStop(1, 'rgba(25,195,255,0)');
		c.fillStyle = grad; c.fillRect(g - 11, top, 22, bot - top);
		const bar = c.createLinearGradient(0, top, 0, bot);
		bar.addColorStop(0, '#ff5ca8'); bar.addColorStop(0.5, '#8b6bff'); bar.addColorStop(1, '#19c3ff');
		c.strokeStyle = bar; c.lineWidth = 2.5; c.lineCap = 'round'; c.shadowColor = '#8b6bff'; c.shadowBlur = 16;
		for (const x of [g - 11, g + 11]) { c.beginPath(); c.moveTo(x, top); c.lineTo(x, bot); c.stroke(); }
		c.shadowBlur = 0;
		for (const [y, f] of flashes) {
			const k = 1 - f.t / 0.9; c.globalAlpha = k * 0.85; c.fillStyle = f.color; c.shadowColor = f.color; c.shadowBlur = 30; c.beginPath(); c.roundRect(g - 13, y - 15, 26, 30, 8); c.fill(); c.shadowBlur = 0; c.globalAlpha = 1;
		}
		// nodes
		agents.forEach((a, i) => node(ax(), laneY(i, agents.length), a.status === 'disabled' ? C.deny : colorFor(i), (a.display_name ?? a.id).slice(0, 14), 'l', a.status === 'disabled', 'a:' + a.id));
		tools.forEach((t, i) => node(tx(), laneY(i, tools.length), RISK[t.risk_class] ?? C.text, t.name.slice(0, 16), 'r', !t.enabled, 't:' + t.name));
		// ripples
		for (const r of ripples) { c.globalAlpha = Math.max(0, r.a); c.strokeStyle = r.color; c.lineWidth = 1.5; c.beginPath(); c.arc(r.x, r.y, r.r, 0, Math.PI * 2); c.stroke(); }
		c.globalAlpha = 1;
		// particles and trails
		for (const p of parts) {
			if (p.phase === 'wait') continue;
			const base = p.phase === 'held' ? C.escalate : p.tainted ? C.taint : p.color;
			if (p.trail.length > 1) {
				c.lineWidth = 3.5; c.lineCap = 'round';
				for (let i = 1; i < p.trail.length; i++) {
					c.globalAlpha = (i / p.trail.length) * 0.7; c.strokeStyle = base;
					c.beginPath(); c.moveTo(p.trail[i - 1].x, p.trail[i - 1].y); c.lineTo(p.trail[i].x, p.trail[i].y); c.stroke();
				}
				c.globalAlpha = 1;
			}
			c.shadowColor = base; c.shadowBlur = 22; c.fillStyle = base;
			c.beginPath(); c.arc(p.x, p.y, 4.5, 0, Math.PI * 2); c.fill();
			c.shadowBlur = 0; c.fillStyle = '#fff'; c.beginPath(); c.arc(p.x, p.y, 1.8, 0, Math.PI * 2); c.fill();
			if (p.phase === 'held') {
				const pulse = 8 + Math.sin(p.heldFor * 4) * 2.5;
				c.strokeStyle = C.escalate; c.lineWidth = 1.25; c.setLineDash([3, 3]); c.lineDashOffset = -p.heldFor * 10;
				c.beginPath(); c.arc(p.x, p.y, pulse + 6, 0, Math.PI * 2); c.stroke(); c.setLineDash([]);
				c.font = '700 10px "Space Grotesk", sans-serif'; c.textAlign = 'right'; c.textBaseline = 'middle'; c.fillStyle = C.escalate;
				c.fillText('AWAITING HUMAN', p.x - 22, p.y - 15);
			}
		}
		// shards
		c.lineWidth = 2; c.lineCap = 'round';
		for (const s of shards) { c.strokeStyle = s.rot > 0 ? '#ff4d6d' : '#ff8a3d'; c.globalAlpha = Math.max(0, s.a); c.beginPath(); c.moveTo(s.x, s.y); c.lineTo(s.x + Math.cos(s.rot) * s.len, s.y + Math.sin(s.rot) * s.len); c.stroke(); }
		c.globalAlpha = 1;
		// cursor reticle
		if (mouse.in) {
			c.strokeStyle = 'rgba(255,92,168,0.8)'; c.lineWidth = 1.25;
			c.beginPath(); c.arc(mouse.x, mouse.y, 10, 0, Math.PI * 2); c.moveTo(mouse.x - 16, mouse.y); c.lineTo(mouse.x - 5, mouse.y); c.moveTo(mouse.x + 5, mouse.y); c.lineTo(mouse.x + 16, mouse.y); c.moveTo(mouse.x, mouse.y - 16); c.lineTo(mouse.x, mouse.y - 5); c.moveTo(mouse.x, mouse.y + 5); c.lineTo(mouse.x, mouse.y + 16); c.stroke();
		}
	}

	function frame(now: number) {
		raf = 0;
		const dt = Math.min(0.05, (now - last) / 1000 || 0.016);
		last = now;
		step(dt);
		draw();
		if (onScreen && !document.hidden && !reduce) raf = requestAnimationFrame(frame);
	}
	function kick() {
		if (reduce) { draw(); return; }
		if (!raf && onScreen && !document.hidden) { last = performance.now(); raf = requestAnimationFrame(frame); }
	}

	function resize() {
		const r = wrap.getBoundingClientRect();
		W = r.width; H = r.height; dpr = Math.min(2, window.devicePixelRatio || 1);
		canvas.width = Math.round(W * dpr); canvas.height = Math.round(H * dpr);
		if (!dust.length) for (let i = 0; i < 70; i++) dust.push({ x: Math.random() * W, y: Math.random() * H, vx: (Math.random() - 0.5) * 8, vy: (Math.random() - 0.5) * 8, s: Math.random() < 0.25 ? 2.5 : 1.5, c: PALETTE[i % PALETTE.length] });
		draw();
	}

	function move(e: PointerEvent) {
		const r = canvas.getBoundingClientRect();
		mouse = { x: e.clientX - r.left, y: e.clientY - r.top, in: true };
		let best: string | null = null, bd = 26 * 26;
		const test = (x: number, y: number, key: string) => { const q = (x - mouse.x) ** 2 + (y - mouse.y) ** 2; if (q < bd) { bd = q; best = key; } };
		agents.forEach((a, i) => test(ax(), laneY(i, agents.length), 'a:' + a.id));
		tools.forEach((t, i) => test(tx(), laneY(i, tools.length), 't:' + t.name));
		hover = best;
		kick();
	}

	onMount(() => {
		ctx = canvas.getContext('2d');
		reduce = matchMedia('(prefers-reduced-motion: reduce)').matches;
		const ro = new ResizeObserver(() => { resize(); kick(); });
		ro.observe(wrap);
		const io = new IntersectionObserver(([en]) => { onScreen = en.isIntersecting; if (onScreen) kick(); });
		io.observe(wrap);
		const vis = () => kick();
		document.addEventListener('visibilitychange', vis);
		resize(); kick();
		return () => { cancelAnimationFrame(raf); ro.disconnect(); io.disconnect(); document.removeEventListener('visibilitychange', vis); };
	});

	// Re-draw (and wake the loop) when the lists change, e.g. an agent is switched off.
	$effect(() => { agents; tools; approvals; if (ctx) kick(); });
</script>

<div class="field" bind:this={wrap} role="img" aria-label="Live view of agent calls passing the gate. {heldCount} waiting for a human.">
	<canvas bind:this={canvas} onpointermove={move} onpointerleave={() => { mouse.in = false; hover = null; kick(); }}></canvas>
	<span class="tag l">agents</span>
	<span class="tag c">the gate</span>
	<span class="tag r">tools</span>
</div>
