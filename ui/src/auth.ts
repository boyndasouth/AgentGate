// Auth.js (@auth/sveltekit) with Auth0 as the only provider.
//
// Auth.js runs the OIDC authorization-code flow on the server and keeps the
// result in an encrypted, HTTP-only session cookie. It reads these env vars on
// its own: AUTH_SECRET, AUTH_AUTH0_ID, AUTH_AUTH0_SECRET, AUTH_AUTH0_ISSUER.
//
// We keep two extra things in the session:
//   - auth0Sub: the stable Auth0 user id ("auth0|abc…"), used for the admin
//     allowlist and to record who approved what.
//   - supabaseToken: the Auth0 ID token. Supabase Third-Party Auth accepts it
//     (it carries role=authenticated via an Auth0 Action), and RLS only lets
//     subs listed in public.ui_admins read audit_events. This is what the
//     browser uses for the Realtime feed. It never grants writes.
import { SvelteKitAuth } from '@auth/sveltekit';
import Auth0 from '@auth/sveltekit/providers/auth0';

function jwtExp(jwt: string | undefined): number | undefined {
	if (!jwt) return undefined;
	try {
		const b64 = jwt.split('.')[1].replace(/-/g, '+').replace(/_/g, '/');
		const payload = JSON.parse(atob(b64));
		return typeof payload.exp === 'number' ? payload.exp : undefined;
	} catch {
		return undefined;
	}
}

export const { handle, signIn, signOut } = SvelteKitAuth({
	trustHost: true,
	providers: [Auth0],
	// Admin sessions are short on purpose; the Auth0 ID token lasts 10 h by default.
	session: { strategy: 'jwt', maxAge: 8 * 60 * 60 },
	pages: { signIn: '/login', error: '/login' },
	callbacks: {
		jwt({ token, account, profile }) {
			if (account) {
				// First call after login: copy what we need out of the OIDC response.
				token.auth0Sub = (profile?.sub as string | undefined) ?? token.sub;
				token.emailVerified = Boolean(profile?.email_verified);
				token.idToken = account.id_token;
				token.idTokenExp = jwtExp(account.id_token);
			}
			return token;
		},
		session({ session, token }) {
			session.auth0Sub = token.auth0Sub as string | undefined;
			session.emailVerified = Boolean(token.emailVerified);
			const exp = token.idTokenExp as number | undefined;
			const fresh = exp !== undefined && exp * 1000 > Date.now() + 30_000;
			// An expired ID token would just make Realtime fail; the UI then polls.
			session.supabaseToken = fresh ? (token.idToken as string) : null;
			return session;
		}
	}
});
