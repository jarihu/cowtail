/* ============================================================= *
 *  COWTAIL // country + ISP leaderboards
 * ============================================================= */

import { state } from "./state.js";
import { $, escapeHtml, flagImg } from "./util.js";

export function updateCountries() {
  const counts = new Map();
  for (const atk of state.attackers.values()) {
    const geo = state.geo.get(atk.ip);
    if (!geo) continue;
    const key = geo.country_code || geo.country || "Unknown";
    const label = geo.country || "Unknown";
    counts.set(key, { label, code: geo.country_code || null, n: (counts.get(key)?.n || 0) + 1 });
  }
  const sorted = Array.from(counts.values()).sort((a, b) => b.n - a.n).slice(0, 14);
  const max = sorted.length ? sorted[0].n : 1;
  const list = $("#countryList");
  list.innerHTML = sorted.length
    ? sorted.map((c) => `
        <div class="crow">
          ${flagImg(c.code)}
          <span class="cname">${escapeHtml(c.label)}</span>
          <span class="ccount">${c.n}</span>
          <span class="cbar-wrap"><span class="cbar" style="width:${(c.n / max) * 100}%"></span></span>
        </div>`).join("")
    : '<div class="country-empty">resolving geoip…</div>';
}

// Groups attackers by hosting-provider/ISP (see knock-knock.net for the
// kind of "who's actually hosting this abuse" leaderboard this mirrors).
// ISP attribution needs an ASN database (offline geoip-country-ipv4.csv has
// none); drop a GeoLite2-ASN.mmdb (or any *asn*.mmdb) in data/, or run with
// --online, to populate this beyond demo mode.
export function updateISPs() {
  const groups = new Map();
  let unresolved = 0;
  for (const atk of state.attackers.values()) {
    const geo = state.geo.get(atk.ip);
    const isp = geo && geo.isp ? geo.isp : "";
    if (!isp) { unresolved++; continue; }
    let g = groups.get(isp);
    if (!g) {
      g = { name: isp, ips: new Set(), countries: new Map() };
      groups.set(isp, g);
    }
    g.ips.add(atk.ip);
    if (geo.country_code) g.countries.set(geo.country_code, (g.countries.get(geo.country_code) || 0) + 1);
  }

  const sorted = Array.from(groups.values()).sort((a, b) => b.ips.size - a.ips.size).slice(0, 14);
  const max = sorted.length ? sorted[0].ips.size : 1;
  const list = $("#ispList");
  if (!list) return;

  const rows = sorted.map((g) => {
    const topCC = Array.from(g.countries.entries()).sort((a, b) => b[1] - a[1])[0];
    return `
      <div class="crow">
        ${flagImg(topCC ? topCC[0] : null)}
        <span class="cname" title="${escapeHtml(g.name)}">${escapeHtml(g.name)}</span>
        <span class="ccount">${g.ips.size}</span>
        <span class="cbar-wrap"><span class="cbar" style="width:${(g.ips.size / max) * 100}%"></span></span>
      </div>`;
  }).join("");

  if (!rows) {
    list.innerHTML = '<div class="country-empty">no ISP data yet — drop a GeoLite2-ASN.mmdb in data/, or run with --online, for ISP attribution</div>';
  } else {
    const note = unresolved
      ? `<div class="country-empty">${unresolved} attacker${unresolved === 1 ? "" : "s"} with unresolved ISP</div>`
      : "";
    list.innerHTML = rows + note;
  }
}

export function countryCount() {
  const s = new Set();
  for (const atk of state.attackers.values()) {
    const geo = state.geo.get(atk.ip);
    if (geo && geo.country_code && geo.country_code !== "XX") s.add(geo.country_code);
  }
  return s.size;
}
