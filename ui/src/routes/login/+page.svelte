<script lang="ts">
	import Logo from '$lib/components/Logo.svelte';
	let { data } = $props();
</script>

<svelte:head><title>AgentGate · Sign in</title></svelte:head>

<main class="center">
	<div class="card login">
		<div class="brand"><Logo /> AgentGate</div>
		<p class="tagline">Every agent gets <b>only the access it needs</b>, and a human decides the risky calls.</p>
		<ul class="props">
			<li>Short-lived, least-privilege credentials</li>
			<li>Approvals in Slack for email, money and deletes</li>
			<li>A hash-chained audit log nobody can quietly edit</li>
		</ul>
		{#if data.error}
			<p class="err">Sign-in failed ({data.error}). Check the Auth0 callback URL and env vars.</p>
		{/if}
		<form method="POST">
			<input type="hidden" name="providerId" value="auth0" />
			<input type="hidden" name="redirectTo" value="/" />
			<button class="btn primary wide" type="submit">Sign in with Auth0</button>
		</form>
	</div>
</main>
