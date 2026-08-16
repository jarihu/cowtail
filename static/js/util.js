/* ============================================================= *
 *  COWTAIL // DOM + formatting helpers
 * ============================================================= */

export const $ = (s) => document.querySelector(s);
export const $$ = (s) => Array.from(document.querySelectorAll(s));

export function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  }[c]));
}

// Human-readable relative time ("32m ago") — logs routinely span 24h+, so an
// exact HH:MM:SS is hard to place in time at a glance. The full date+time is
// still available via the element's title attribute (see relTimeAttrs/fmtDateTime).
export function timeAgo(iso) {
  if (!iso) return "—";
  const t = new Date(iso).getTime();
  if (isNaN(t)) return "—";
  let diff = Math.round((Date.now() - t) / 1000);
  const future = diff < 0;
  diff = Math.abs(diff);
  let out;
  if (diff < 5) return "just now";
  else if (diff < 60) out = `${diff}s`;
  else if (diff < 3600) out = `${Math.floor(diff / 60)}m`;
  else if (diff < 86400) out = `${Math.floor(diff / 3600)}h`;
  else if (diff < 604800) out = `${Math.floor(diff / 86400)}d`;
  else out = `${Math.floor(diff / 604800)}w`;
  return future ? `in ${out}` : `${out} ago`;
}

export function fmtDateTime(iso) {
  if (!iso) return "—";
  const d = new Date(iso);
  if (isNaN(d)) return "—";
  return d.toLocaleString("en-GB", {
    day: "2-digit", month: "2-digit", year: "numeric",
    hour: "2-digit", minute: "2-digit", second: "2-digit",
  });
}

export function fmtRange(ms) {
  const d = new Date(ms);
  return d.toLocaleString("en-GB", { month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit" });
}

// Attributes for a relative-time element: visible "32m ago" text plus a
// title tooltip with the full date+time, and a data-ts hook so the periodic
// refreshRelativeTimes() ticker can keep it fresh without a full re-render.
export function relTimeAttrs(iso) {
  const safe = escapeHtml(iso || "");
  return `class="rel-time" data-ts="${safe}" title="${escapeHtml(fmtDateTime(iso))}"`;
}

export function refreshRelativeTimes() {
  $$(".rel-time[data-ts]").forEach((el) => {
    el.textContent = timeAgo(el.dataset.ts);
  });
}

export function miniBar(value, max, color) {
  if (!max || !value) return "";
  const pct = Math.max(3, Math.round((value / max) * 100));
  return `<span class="mini-bar-wrap"><span class="mini-bar" style="width:${pct}%${color ? `;background:${color}` : ""}"></span></span>`;
}

export function flagImg(code) {
  const c = code ? String(code).toLowerCase() : "";
  if (!c || c === "xx" || c === "??") {
    return '<span class="flag flag-none"></span>';
  }
  return `<img class="flag" src="/static/vendor/flags/${c}.png" alt="" />`;
}

export function geoLocation(geo) {
  if (!geo) return "";
  const city = geo.city && geo.city !== "Local network" ? geo.city : "";
  const country = geo.country || "";
  return [city, country].filter(Boolean).join(", ");
}

export function fmtDur(ms) {
  const s = Math.round((ms || 0) / 1000);
  if (s < 60) return `${s}s`;
  if (s < 3600) return `${Math.floor(s / 60)}m ${s % 60}s`;
  return `${Math.floor(s / 3600)}h ${Math.floor((s % 3600) / 60)}m`;
}

export function shortUrl(url) {
  const u = String(url);
  if (u.length <= 46) return u;
  return u.slice(0, 30) + "…" + u.slice(-12);
}

export function bump(map, key) {
  map.set(key, (map.get(key) || 0) + 1);
}
