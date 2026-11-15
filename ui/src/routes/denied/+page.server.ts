import type { PageServerLoad } from './$types';

// Shows the signed-in identity so the owner can copy the sub into ADMIN_USERS
// and public.ui_admins. Nothing else is readable from here.
export const load: PageServerLoad = async ({ locals }) => {
	const session = await locals.auth();
	return {
		signedIn: Boolean(session),
		sub: session?.auth0Sub ?? null,
		email: session?.user?.email ?? null,
		emailVerified: Boolean(session?.emailVerified)
	};
};
