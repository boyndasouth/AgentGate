<script lang="ts">
	import Logo from '$lib/components/Logo.svelte';
	let { data } = $props();
</script>

<svelte:head><title>AgentGate · Not an admin</title></svelte:head>

<main class="center">
	<div class="card login">
		<div class="brand"><Logo /> AgentGate</div>
		{#if data.signedIn}
			<p>You're signed in, but this account isn't on the admin list.</p>
			<dl class="kv">
				<dt>Auth0 sub</dt><dd><code>{data.sub}</code></dd>
				<dt>Email</dt><dd>{data.email ?? '—'} {data.emailVerified ? '(verified)' : '(not verified)'}</dd>
			</dl>
			<p class="muted small">
				To grant access, add the sub to <code>ADMIN_USERS</code> (and to <code>public.ui_admins</code> for the
				live feed), then sign in again.
			</p>
			<form method="POST" action="/signout"><button class="btn wide">Sign out</button></form>
		{:else}
			<p><a href="/login">Sign in</a></p>
		{/if}
	</div>
</main>
