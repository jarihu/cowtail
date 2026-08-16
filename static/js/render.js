/* ============================================================= *
 *  COWTAIL // render scheduler (funnels all update* functions)
 * ============================================================= */

import { state, shared } from "./state.js";
import { counters } from "./counters.js";
import { updateTimeline, updateProtocol, updateBars } from "./charts.js";
import { updateCountries, updateISPs, countryCount } from "./countries.js";
import { updateSessions } from "./sessions.js";
import { updateMalware } from "./malware.js";
import { refreshMarkers } from "./map.js";
import { $ } from "./util.js";

export function renderAll() {
  const c = state.counts;
  counters.connections.set(c.connections);
  counters.loginOk.set(c.loginOk);
  counters.loginFail.set(c.loginFail);
  counters.attackers.set(state.attackers.size);
  counters.commands.set(c.commands);
  counters.countries.set(countryCount());

  updateTimeline();
  updateProtocol();
  updateBars();
  updateCountries();
  updateISPs();
  $("#feedSub").textContent = `${state.events.length} EVENTS`;

  updateSessions();
  updateMalware();
  refreshMarkers();

  $("#sensor").textContent = `SENSOR ${state.sensor}`;
  if (shared.refreshTimebar) shared.refreshTimebar();
}
