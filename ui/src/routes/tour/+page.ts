// Public, no login: a replay of a real recorded run (eval/export_tour.py writes the data file the
// page imports). Prerendered, so Vercel serves it as a static page: it never wakes the broker and
// never holds a key.
export const prerender = true;
