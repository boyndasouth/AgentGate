import { redirect } from '@sveltejs/kit';
import { signOut } from '../../auth';
import type { Actions, PageServerLoad } from './$types';

export const load: PageServerLoad = () => redirect(303, '/');

// Clears the AgentGate session cookie. The Auth0 session itself stays
// (TODO: also hit Auth0's /v2/logout if a full single sign-out is needed).
export const actions: Actions = { default: signOut };
