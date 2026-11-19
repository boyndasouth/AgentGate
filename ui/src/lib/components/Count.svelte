<script lang="ts">
	// A number that counts up to its value, so the stats feel alive. Static under reduced motion.
	import { untrack } from 'svelte';
	let { value }: { value: number } = $props();
	let shown = $state(0);

	$effect(() => {
		const to = value;
		const from = untrack(() => shown);
		if (matchMedia('(prefers-reduced-motion: reduce)').matches || from === to) {
			shown = to;
			return;
		}
		const start = performance.now();
		let raf = 0;
		const tick = (t: number) => {
			const k = Math.min(1, (t - start) / 800);
			shown = Math.round(from + (to - from) * (1 - Math.pow(1 - k, 3)));
			if (k < 1) raf = requestAnimationFrame(tick);
		};
		raf = requestAnimationFrame(tick);
		return () => cancelAnimationFrame(raf);
	});
</script>

{shown}
