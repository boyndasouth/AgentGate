// Dashboard config only. Data is fetched by the page from /api/* so the page
// renders at once even while the Render broker is still waking up.
import { env as pub } from '$env/dynamic/public';
import { env } from '$env/dynamic/private';
import { brokerConfigured, demoConfigured } from '$lib/server/broker';
import type { PageServerLoad } from './$types';

export const load: PageServerLoad = async ({ locals }) => {
	const session = await locals.auth();
	const realtimeReady = Boolean(pub.PUBLIC_SUPABASE_URL && pub.PUBLIC_SUPABASE_ANON_KEY);
	return {
		brokerConfigured: brokerConfigured(),
		brokerHost: env.BROKER_URL ? new URL(env.BROKER_URL).host : null,
		demoEnabled: demoConfigured(),
		realtime: realtimeReady
			? {
					url: pub.PUBLIC_SUPABASE_URL,
					key: pub.PUBLIC_SUPABASE_ANON_KEY,
					// Auth0 ID token (role=authenticated). RLS: SELECT on audit_events for ui_admins only.
					token: session?.supabaseToken ?? null
				}
			: null
	};
};
