/* ============================================================= *
 *  COWTAIL // animated KPI counters
 * ============================================================= */

import { $ } from "./util.js";

function Counter(el, card) {
  this.el = el;
  this.card = card;
  this.value = 0;
  this.target = 0;
}

Counter.prototype.set = function (n) {
  if (n === this.target) return;
  this.target = n;
  if (n !== this.value) {
    this.card.classList.remove("flash");
    void this.card.offsetWidth;
    this.card.classList.add("flash");
  }
  if (!this._anim) this._anim = requestAnimationFrame(() => this._tick());
};

Counter.prototype._tick = function () {
  const diff = this.target - this.value;
  const step = Math.max(1, Math.ceil(Math.abs(diff) / 14));
  this.value += Math.sign(diff) * Math.min(step, Math.abs(diff));
  this.el.textContent = this.value.toLocaleString();
  if (this.value !== this.target) {
    this._anim = requestAnimationFrame(() => this._tick());
  } else {
    this._anim = null;
  }
};

export const counters = {
  connections: new Counter($("#kpiConnections"), $("#kpiConnections").closest(".kpi")),
  loginOk: new Counter($("#kpiLoginOk"), $("#kpiLoginOk").closest(".kpi")),
  loginFail: new Counter($("#kpiLoginFail"), $("#kpiLoginFail").closest(".kpi")),
  attackers: new Counter($("#kpiAttackers"), $("#kpiAttackers").closest(".kpi")),
  commands: new Counter($("#kpiCommands"), $("#kpiCommands").closest(".kpi")),
  countries: new Counter($("#kpiCountries"), $("#kpiCountries").closest(".kpi")),
};

export function setHistoryCounters(h) {
  const s = h.summary || {};
  counters.connections.set(s.connections || 0);
  counters.loginOk.set(s.loginOk || 0);
  counters.loginFail.set(s.loginFail || 0);
  counters.attackers.set(s.uniqueIps || 0);
  counters.commands.set(s.commands || 0);
  counters.countries.set(s.uniqueCountries || 0);
}
