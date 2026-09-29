'use strict';

/* Honeypot XRPL – Konto-Check (Explicit Accounts), ESM-UI-Modul.
 *
 * Aufgabe: Adressfeld + „Prüfen“-Button -> serverseitig erweiterter
 * Profiling-Report einer XRPL-Adresse (GET /api/account-report?address=…):
 * Kontakte zur Threat-Liste, Muster-Befunde, Rollenbeteiligung aus der
 * Cluster-Engine, transparenter Score, Off-Ramp-Eligibility.
 *
 * Einbinde-Muster wie drilldown.js: nicht-blockierender dynamischer Import in
 * app.js, dann initAccountCheck(ctx). Der Report wird über die ctx-Gates des
 * Hosts gerendert — Adressen erscheinen NIE roh im DOM:
 *   displayAddr/isFullShownAddr  (Köder-Schutz, fail-closed: ohne Gates oder
 *                                ohne geladene Allowlist nur Kurzform),
 *   addrActionsHtml              (Kopieren + xrplcharts-Link, nur bei
 *                                erlaubter Vollanzeige).
 * Fehlt der Mount #check-root (View noch nicht verdrahtet), liefert
 * initAccountCheck ein Noop-Objekt — der Live-Betrieb läuft unberührt weiter.
 *
 * Mount: #check-root (View-Container #view-check kommt vom Verdrahtungs-
 * Agenten). CSS (account-check.css) wird vom Modul selbst idempotent als
 * <link> injiziert, falls noch nicht vorhanden.
 */

const XRPL_ADDR_RE = /^r[1-9A-HJ-NP-Za-km-z]{24,34}$/;
const ENDPOINT = '/api/account-report';

/* ---------- lokale Fallbacks (ctx hat Vorrang; Adressen bleiben fail-closed) */

function localEsc(value) {
  return String(value ?? '').replace(/[&<>"']/g, (c) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
  })[c]);
}

function localShortAddr(a) {
  const s = String(a ?? '');
  return s.length > 12 ? `${s.slice(0, 8)}…${s.slice(-4)}` : s;
}

function localFmtXrp(drops) {
  const n = Number(drops ?? 0) / 1e6;
  return n.toLocaleString('de-DE', { maximumFractionDigits: 2 });
}

function localFmtClock(value) {
  if (value === null || value === undefined || value === '') return '–';
  const d = new Date(typeof value === 'number' ? value : value);
  if (Number.isNaN(d.getTime())) return String(value);
  return d.toLocaleTimeString('de-DE');
}

/* ---------- Anzeige-Mapping (deutsch, nie Farbe ohne Text) ---------- */

const VERDICT_BADGE = {
  clean: { cls: 'badge badge-clean', text: 'sauber' },
  contact: { cls: 'risk-badge risk-suspect', text: 'risikobehaftet' },
  bad: { cls: 'risk-badge risk-malicious', text: 'bekannt maliziös' },
  unknown: { cls: 'badge badge-partial', text: 'unbekannt' },
};

const ELIGIBILITY = {
  ok: { cls: 'check-eligibility-ok', label: 'Voraussichtlich unproblematisch' },
  review: { cls: 'check-eligibility-review', label: 'Prüfungswürdig' },
  unknown: { cls: 'check-eligibility-unknown', label: 'Nicht bewertbar' },
};

function ensureStylesheet() {
  if (document.querySelector('link[data-account-check-css]')) return;
  const link = document.createElement('link');
  link.rel = 'stylesheet';
  link.href = new URL('./account-check.css', import.meta.url).href;
  link.dataset.accountCheckCss = '';
  document.head.appendChild(link);
}

/* ---------- init ---------- */

export function initAccountCheck(ctx = {}) {
  // Mount-Guard: ohne DOM (z. B. SSR/Preview) oder ohne #check-root (View noch
  // nicht verdrahtet) liefert init ein Noop-Objekt — kein Fehler, Live-Betrieb
  // der Hauptansicht läuft unberührt weiter.
  const root = typeof document === 'object' && document ? document.getElementById('check-root') : null;
  if (!root) {
    // View noch nicht verdrahtet — kein Fehler, Live-Betrieb läuft weiter.
    return { setView() {} };
  }
  ensureStylesheet();

  const esc = typeof ctx.esc === 'function' ? ctx.esc : localEsc;
  const shortAddr = typeof ctx.shortAddr === 'function' ? ctx.shortAddr : localShortAddr;
  const fmtXrp = typeof ctx.fmtXrp === 'function' ? ctx.fmtXrp : localFmtXrp;
  const fmtClock = typeof ctx.fmtClock === 'function' ? ctx.fmtClock : localFmtClock;
  // Vollanzeige ausschließlich über die Host-Gates (Köder-Schutz). Fallback ist
  // fail-closed: ohne Gates wird NUR die Kurzform gezeigt, nie die volle Adresse.
  const isFullShownAddr = (a) => (typeof ctx.isFullShownAddr === 'function' ? ctx.isFullShownAddr(a) : false);
  const displayAddr = (a) => {
    if (typeof ctx.displayAddr === 'function') return ctx.displayAddr(a);
    return isFullShownAddr(a) ? String(a ?? '') : shortAddr(a);
  };
  const addrActionsHtml = (a) => (typeof ctx.addrActionsHtml === 'function' && isFullShownAddr(a) ? ctx.addrActionsHtml(a) : '');
  const ruleName = (id) => {
    const rn = ctx.ruleNames;
    if (rn && typeof rn.get === 'function') {
      const v = rn.get(id);
      if (v) return String(v);
    } else if (rn && rn[id]) {
      return String(rn[id]);
    }
    return String(id);
  };
  const roleLabel = (role) => {
    const rl = ctx.roleLabels;
    return rl && rl[role] ? String(rl[role]) : String(role);
  };

  /* ---------- Panel-Gerüst (UI dynamisch, index.html bleibt unangetastet) */

  root.innerHTML = `
    <div class="panel-head">
      <h2 id="check-title">Konto-Check</h2>
      <span class="hint">Profiling-Report einer XRPL-Adresse gegen Threat-Liste, Muster-Erkennung und Cluster-Heuristik.</span>
    </div>
    <form id="check-form" class="check-form" novalidate>
      <label class="check-label" for="check-address">XRPL-Adresse (Pflichtfeld)</label>
      <input id="check-address" class="check-input" type="text" inputmode="latin" autocomplete="off"
             spellcheck="false" placeholder="r…" required aria-describedby="check-error">
      <button id="check-go" type="submit" class="download-btn">Prüfen</button>
    </form>
    <p class="check-error" id="check-error" aria-live="polite" hidden></p>
    <div class="check-status" id="check-status" role="status" aria-live="polite"></div>
    <div class="check-report-slot" id="check-report"></div>`;

  const form = root.querySelector('#check-form');
  const input = root.querySelector('#check-address');
  const goBtn = root.querySelector('#check-go');
  const errorEl = root.querySelector('#check-error');
  const statusEl = root.querySelector('#check-status');
  const reportEl = root.querySelector('#check-report');

  function showClientError(message) {
    errorEl.textContent = message;
    errorEl.hidden = false;
    try { input.focus(); } catch { /* Fokus nicht erzwingbar */ }
  }
  function clearClientError() {
    errorEl.textContent = '';
    errorEl.hidden = true;
  }

  function setLoading(loading) {
    goBtn.disabled = loading;
    goBtn.textContent = loading ? 'Prüfe Konto …' : 'Prüfen';
    if (loading) {
      root.setAttribute('aria-busy', 'true');
      statusEl.innerHTML = '<p class="check-loading">Prüfe Konto …</p>';
    } else {
      root.removeAttribute('aria-busy');
      statusEl.textContent = '';
    }
  }

  function renderErrorCard(title, detail) {
    statusEl.innerHTML =
      `<div class="check-card check-card-error" role="alert">` +
      `<h3 class="check-card-title">${esc(title)}</h3>` +
      (detail ? `<p class="check-card-detail">${esc(detail)}</p>` : '') +
      `</div>`;
  }

  /* ---------- Report-Rendering ---------- */

  function contactRow(c) {
    const shown = displayAddr(c.counterparty);
    const actions = addrActionsHtml(c.counterparty);
    const risk =
      c.risk === 'malicious'
        ? '<span class="risk-badge risk-malicious">maliziös</span>'
        : c.risk === 'suspect'
          ? '<span class="risk-badge risk-suspect">verdächtig</span>'
          : '<span class="cluster-table-dash">–</span>';
    return (
      `<tr>` +
      `<td class="cluster-td-addr"><span class="addr-full" title="${esc(shown)}">${esc(shown)}</span>${actions}</td>` +
      `<td>${esc(c.direction ?? '–')}</td>` +
      `<td>${esc(c.txType ?? '–')}</td>` +
      `<td>${esc(fmtClock(c.time))}</td>` +
      `<td>${risk}</td>` +
      `<td>${esc(c.note ?? '')}</td>` +
      `</tr>`
    );
  }

  function breakdownHtml(report) {
    if (!Array.isArray(report.scoreBreakdown) || report.scoreBreakdown.length === 0) return '';
    const rows = report.scoreBreakdown
      .map(
        (b) =>
          `<div class="check-breakdown-row">` +
          `<dt>${esc(b.kriterium)}</dt>` +
          `<dd><span class="check-bd-wert">${esc(String(b.wert))}</span>` +
          `<span class="check-bd-abzug">${Number(b.abzug) > 0 ? `−${esc(String(b.abzug))}` : 'kein Abzug'}</span></dd>` +
          `</div>`
      )
      .join('');
    return `<dl class="check-breakdown">${rows}</dl>`;
  }

  function metaHtml(report) {
    const parts = [`<span>Geprüfte Transaktionen: ${esc(String(report.checkedTxCount ?? 0))}</span>`];
    if (report.network) parts.push(`<span>Netzwerk: ${esc(String(report.network))}</span>`);
    if (report.checkedAt) {
      const d = new Date(report.checkedAt);
      if (!Number.isNaN(d.getTime())) parts.push(`<span>Geprüft am: ${esc(d.toLocaleString('de-DE'))}</span>`);
    }
    if (report.truncated) parts.push(`<span class="check-truncated">max. 300 Txs geprüft — Aussage begrenzt</span>`);
    return `<p class="check-meta">${parts.join('')}</p>`;
  }

  function roleHtml(report) {
    if (!report.role || !report.roleMetrics) {
      return `<p class="check-empty">Keine Rollenbeteiligung im geprüften Fenster.</p>`;
    }
    const m = report.roleMetrics;
    const swatch = `<span class="swatch swatch-${esc(String(report.role))}" aria-hidden="true"></span>`;
    const metrics =
      `<span>Eingang: ${esc(String(m.degreeIn))} Kanten (${esc(fmtXrp(m.inDrops))} XRP)</span>` +
      `<span>Ausgang: ${esc(String(m.degreeOut))} Kanten (${esc(fmtXrp(m.outDrops))} XRP)</span>`;
    return (
      `<p class="check-role">${swatch}<strong>${esc(roleLabel(report.role))}</strong></p>` +
      `<p class="check-role-metrics">${metrics}</p>` +
      `<p class="graph-note check-note">Rolle gilt nur für das geprüfte Fenster — Heuristik aus Ein-/Ausgrad und Geldfluss, kein Schuldnachweis.</p>`
    );
  }

  function patternsHtml(report) {
    const list = Array.isArray(report.patterns) ? report.patterns : [];
    if (!list.length) {
      return `<p class="check-empty">Keine bekannten Muster im geprüften Fenster.</p>`;
    }
    const chips = list.map((id) => `<span class="check-chip">${esc(ruleName(id))}</span>`).join('');
    return `<div class="check-chips">${chips}</div>`;
  }

  function contactsHtml(report) {
    const list = Array.isArray(report.contacts) ? report.contacts : [];
    if (!list.length) {
      return `<p class="check-empty">Keine Kontakte zu gelisteten Adressen im geprüften Fenster.</p>`;
    }
    return (
      `<div class="cluster-table-wrap" tabindex="0" role="region" aria-label="Kontakte zu gelisteten Adressen">` +
      `<table class="cluster-table check-contacts-table">` +
      `<thead><tr><th scope="col">Gegenpartei</th><th scope="col">Richtung</th><th scope="col">Tx-Typ</th><th scope="col">Zeit</th><th scope="col">Risiko</th><th scope="col">Notiz</th></tr></thead>` +
      `<tbody>${list.map(contactRow).join('')}</tbody>` +
      `</table></div>`
    );
  }

  function eligibilityHtml(report) {
    const e = ELIGIBILITY[report.eligibility] ?? ELIGIBILITY.unknown;
    return (
      `<p class="check-eligibility ${esc(e.cls)}">` +
      `<strong>${esc(e.label)}.</strong> ${esc(report.eligibilityReason ?? '')}` +
      `</p>`
    );
  }

  function renderReport(report) {
    const badge = VERDICT_BADGE[report.verdict] ?? VERDICT_BADGE.unknown;
    const shownAddr = displayAddr(report.address);
    const actions = addrActionsHtml(report.address);
    const scoreValue = typeof report.score === 'number' ? String(report.score) : '–';
    const disclaimers = (Array.isArray(report.disclaimers) ? report.disclaimers : [])
      .map((d) => `<li>${esc(String(d))}</li>`)
      .join('');
    const hintHtml = report.hint ? `<p class="graph-note check-hint">${esc(String(report.hint))}</p>` : '';

    reportEl.innerHTML =
      `<article class="check-report" aria-label="Prüfbericht der geprüften Adresse">` +
      `<header class="check-report-head">` +
      `<span class="${esc(badge.cls)}">${esc(badge.text)}</span>` +
      `<span class="addr-full check-report-addr" title="${esc(shownAddr)}">${esc(shownAddr)}</span>${actions}` +
      `<div class="check-score" aria-label="Score von 100">` +
      `<span class="check-score-value">${esc(scoreValue)}</span><span class="check-score-max">/ 100</span>` +
      `</div>` +
      `</header>` +
      `<p class="check-summary">${esc(report.zusammenfassung ?? '')}</p>` +
      hintHtml +
      `<section class="check-section" aria-label="Score-Zusammensetzung">` +
      `<h3 class="check-section-title">Score-Zusammensetzung</h3>` +
      breakdownHtml(report) +
      metaHtml(report) +
      `</section>` +
      `<section class="check-section" aria-label="Rollenbeteiligung">` +
      `<h3 class="check-section-title">Rollenbeteiligung</h3>` +
      roleHtml(report) +
      `</section>` +
      `<section class="check-section" aria-label="Bekannte Muster">` +
      `<h3 class="check-section-title">Bekannte Muster</h3>` +
      patternsHtml(report) +
      `</section>` +
      `<section class="check-section" aria-label="Kontakte zu gelisteten Adressen">` +
      `<h3 class="check-section-title">Kontakte zu gelisteten Adressen</h3>` +
      contactsHtml(report) +
      `</section>` +
      `<section class="check-section" aria-label="Off-Ramp-Einschätzung">` +
      `<h3 class="check-section-title">Off-Ramp-Einschätzung</h3>` +
      eligibilityHtml(report) +
      `</section>` +
      `<div class="graph-note check-disclaimers" role="note">` +
      `<ul>${disclaimers}</ul>` +
      `</div>` +
      `</article>`;
  }

  /* ---------- Anfrage ---------- */

  async function runCheck() {
    const value = String(input.value ?? '').trim();
    if (!XRPL_ADDR_RE.test(value)) {
      showClientError('Ungültige XRPL-Adresse (erwartet: r gefolgt von 24–34 Base58-Zeichen).');
      return;
    }
    clearClientError();
    setLoading(true);
    try {
      const res = await fetch(`${ENDPOINT}?address=${encodeURIComponent(value)}`, { cache: 'no-store' });
      let body = null;
      try {
        body = await res.json();
      } catch {
        body = null;
      }
      if (!res.ok || !body || typeof body !== 'object' || Array.isArray(body)) {
        if (res.status === 400) {
          renderErrorCard('Ungültige oder nicht prüfbare Adresse.', null);
        } else if (res.status === 502) {
          renderErrorCard('Ledger-Abfrage fehlgeschlagen', body && body.error ? String(body.error) : null);
        } else {
          renderErrorCard(`Unerwartete Antwort (HTTP ${res.status}).`, body && body.error ? String(body.error) : null);
        }
        return;
      }
      renderReport(body);
    } catch {
      renderErrorCard('Netzwerkfehler', 'Der Konto-Check ist derzeit nicht erreichbar — bitte später erneut versuchen.');
    } finally {
      setLoading(false);
    }
  }

  form.addEventListener('submit', (e) => {
    e.preventDefault();
    if (!goBtn.disabled) void runCheck();
  });
  input.addEventListener('input', clearClientError);

  function setView(visible) {
    if (visible && input && !String(input.value ?? '').trim()) {
      try { input.focus(); } catch { /* Fokus nicht erzwingbar */ }
    }
  }

  return { setView };
}
