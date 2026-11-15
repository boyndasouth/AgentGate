import type { LayoutServerLoad } from './$types';

export const load: LayoutServerLoad = async ({ locals }) => {
	const a = locals.admin;
	return {
		admin: a ? { name: a.name, email: a.email, canApprove: Boolean(a.fgaUser), fgaUser: a.fgaUser } : null
	};
};
