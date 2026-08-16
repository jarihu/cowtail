/* ============================================================= *
 *  COWTAIL // historical stats (SQLite-backed /api/stats)
 * ============================================================= */

export async function fetchInsights(lo, hi) {
  const params = new URLSearchParams();
  if (lo != null) params.set("from", new Date(lo).toISOString());
  if (hi != null) params.set("to", new Date(hi).toISOString());
  const res = await fetch(`/api/history?${params.toString()}`);
  if (!res.ok) throw new Error("history request failed");
  return await res.json();
}
