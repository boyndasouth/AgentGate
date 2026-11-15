// See https://svelte.dev/docs/kit/types#app.d.ts
import type { AdminIdentity } from '$lib/server/admin';

declare global {
	namespace App {
		interface Locals {
			admin: AdminIdentity | null;
		}
		interface Error {
			message: string;
		}
	}
}

declare module '@auth/core/types' {
	interface Session {
		auth0Sub?: string;
		emailVerified?: boolean;
		supabaseToken?: string | null;
	}
}

export {};
