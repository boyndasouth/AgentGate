import { redirect } from '@sveltejs/kit';
import { signIn } from '../../auth';
import type { Actions, PageServerLoad } from './$types';

export const load: PageServerLoad = async ({ locals, url }) => {
	const session = await locals.auth();
	if (session) redirect(303, '/');
	return { error: url.searchParams.get('error') };
};

// Auth.js reads `providerId` from the submitted form.
export const actions: Actions = { default: signIn };
