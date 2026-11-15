// Who may use the admin UI, and which OpenFGA user they act as.
//
// ADMIN_USERS: comma-separated Auth0 subs ("auth0|abc…") and/or verified
//              emails. Everyone else gets the /denied page.
// APPROVERS:   comma-separated "<sub or email>=<fga user name>" pairs, e.g.
//              "you@example.com=shiwin". The broker then asks OpenFGA whether
//              user:<name> is an approver on the tool, exactly like Slack does.
//              An admin without a mapping can watch and use kill switches but
//              cannot approve.
import { env } from '$env/dynamic/private';
import type { Session } from '@auth/sveltekit';

export interface AdminIdentity {
	sub: string;
	email: string | null;
	name: string;
	/** OpenFGA user name (without the "user:" prefix), if this admin may approve. */
	fgaUser: string | null;
}

function list(value: string | undefined): string[] {
	return (value ?? '')
		.split(',')
		.map((s) => s.trim())
		.filter(Boolean);
}

export function adminFromSession(session: Session | null): AdminIdentity | null {
	const sub = session?.auth0Sub;
	if (!session || !sub) return null;

	const email = session.user?.email?.toLowerCase() ?? null;
	const verifiedEmail = email && session.emailVerified ? email : null;
	const keys = [sub, verifiedEmail].filter(Boolean) as string[];

	const allowed = list(env.ADMIN_USERS).map((s) => s.toLowerCase());
	if (!keys.some((k) => allowed.includes(k.toLowerCase()))) return null;

	let fgaUser: string | null = null;
	for (const pair of list(env.APPROVERS)) {
		const [who, name] = pair.split('=').map((s) => s.trim());
		if (who && name && keys.some((k) => k.toLowerCase() === who.toLowerCase())) {
			fgaUser = name.replace(/^user:/, '');
			break;
		}
	}

	return { sub, email, name: session.user?.name ?? email ?? sub, fgaUser };
}
