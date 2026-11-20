// GET /api/sandbox/status  →  { enabled }. Lets the (static) /tour page know whether to show the sandbox panel.
import { json } from '@sveltejs/kit';
import { sandboxEnabled } from '$lib/server/sandbox';
import type { RequestHandler } from './$types';

export const GET: RequestHandler = async () => json({ enabled: sandboxEnabled() }, { headers: { 'cache-control': 'no-store' } });
