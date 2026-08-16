/* ============================================================= *
 *  COWTAIL // historical stats (SQLite-backed /api/stats)
 * ============================================================= */

import { state } from "./state.js";

export async function fetchStats(lo, hi) {
  const params = new URLSearchParams();
  if (lo != null) params.set("from", new Date(lo).toISOString());
  if (hi != null) params.set("to", new Date(hi).toISOString());
  params.set("buckets", "40");
  const res = await fetch(`/api/stats?${params.toString()}`);
  if (!res.ok) throw new Error("stats request failed");
  state.history = await res.json();
  return state.history;
}
