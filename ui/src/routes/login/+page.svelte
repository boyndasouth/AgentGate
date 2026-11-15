<script lang="ts">
	let { data } = $props();
</script>

<svelte:head><title>AgentGate · Sign in</title></svelte:head>

<main class="center">
	<div class="card login">
		<div class="brand"><span class="logo">⛨</span> AgentGate</div>
		<p class="muted">Identity &amp; permissions broker for AI agents. Admin console.</p>
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
