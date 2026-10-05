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
 *   addrActionsHtml              (Kopieren + XRPScan-Link, nur bei
 *                                erlaubter Vollanzeige).
 * Fehlt der Mount #check-root (View noch nicht verdrahtet), liefert
 * initAccountCheck ein Noop-Objekt — der Live-Betrieb läuft unberührt weiter.
 *
 * Mount: #check-root (View-Container #view-check kommt vom Verdrahtungs-
 * Agenten). CSS (account-check.css) wird vom Modul selbst idempotent als
 * <link> injiziert, falls noch nicht vorhanden.
 */

import {
  t, ruleName as i18nRuleName, fmtNum, fmtXrp, fmtClock, fmtDateTime,
  serverPhrase, summaryText, sevText,
} from './i18n.mjs';

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

/* ---------- Anzeige-Mapping (Sprache folgt dem i18n-Lookup) ---------- */

const VERDICT_BADGE = {
  clean: { cls: 'badge badge-clean', key: 'check.verdict.clean' },
  contact: { cls: 'risk-badge risk-suspect', key: 'check.verdict.contact' },
  bad: { cls: 'risk-badge risk-malicious', key: 'check.verdict.bad' },
  unknown: { cls: 'badge badge-partial', key: 'check.verdict.unknown' },
};

const ELIGIBILITY = {
  ok: { cls: 'check-eligibility-ok', key: 'check.elig.ok' },
  review: { cls: 'check-eligibility-review', key: 'check.elig.review' },
  unknown: { cls: 'check-eligibility-unknown', key: 'check.elig.unknown' },
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
  const fmtXrpHost = typeof ctx.fmtXrp === 'function' ? ctx.fmtXrp : fmtXrp;
  const fmtClockHost = typeof ctx.fmtClock === 'function' ? ctx.fmtClock : fmtClock;
  // Vollanzeige ausschließlich über die Host-Gates (Köder-Schutz). Fallback ist
  // fail-closed: ohne Gates wird NUR die Kurzform gezeigt, nie die volle Adresse.
  const isFullShownAddr = (a) => (typeof ctx.isFullShownAddr === 'function' ? ctx.isFullShownAddr(a) : false);
  const displayAddr = (a) => {
    if (typeof ctx.displayAddr === 'function') return ctx.displayAddr(a);
    return isFullShownAddr(a) ? String(a ?? '') : shortAddr(a);
  };
  const addrActionsHtml = (a) => (typeof ctx.addrActionsHtml === 'function' && isFullShownAddr(a) ? ctx.addrActionsHtml(a) : '');
  // Namens-Badge (XRPScan-Aliase): HOST-GATE (ctx.accountNameOf aus app.js
  // liefert null für maskierte/Deny-Adressen) PLUS lokaler fail-closed-Guard
  // wie bei addrActionsHtml (:94) — Badge erscheint nur bei erlaubter
  // Vollanzeige. Fallback ohne Host-Funktion: () => null (nur kein Badge).
  const accountNameOf = (a) => (typeof ctx.accountNameOf === 'function' && isFullShownAddr(a) ? ctx.accountNameOf(a) : null);
  const nameChipHtml = (addr) => {
    const entry = accountNameOf(addr);
    if (!entry) return '';
    const label = String(entry.name ?? '').trim();
    if (!label) return '';
    const verified = entry.verified === true;
    const aria = verified ? t('name.chipAria') : t('name.unverifiedAria');
    const mark = verified ? '<span class="name-chip-verified" aria-hidden="true">✓</span>' : '';
    const domain = typeof entry.domain === 'string' && entry.domain.trim()
      ? `<span class="name-chip-domain">${esc(entry.domain.trim())}</span>`
      : '';
    return `<span class="name-chip" role="img" aria-label="${esc(aria)}" title="${esc(aria)}">${mark}${esc(label)}${domain}</span>`;
  };
  const ruleName = (id) => {
    const viaI18n = i18nRuleName(id);
    if (viaI18n !== String(id)) return viaI18n;
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
    // Rollen-Beschriftung übersetzt über die Legenden-Keys (EN: Collector,
    // DE: Kollektor); ctx-Tafel bleibt Fallback für unbekannte Rollen.
    const viaI18n = t('legend.' + role);
    if (viaI18n !== 'legend.' + role) return viaI18n;
    return rl && rl[role] ? String(rl[role]) : String(role);
  };

  /* ---------- Panel-Gerüst (UI dynamisch, index.html bleibt unangetastet) */

  root.innerHTML = `
    <div class="panel-head">
      <h2 id="check-title">${esc(t('check.title'))}</h2>
      <span class="hint">${esc(t('check.hint'))}</span>
    </div>
    <form id="check-form" class="check-form" novalidate>
      <label class="check-label" for="check-address">${esc(t('check.label'))}</label>
      <input id="check-address" class="check-input" type="text" inputmode="latin" autocomplete="off"
             spellcheck="false" placeholder="r…" required aria-describedby="check-error">
      <button id="check-go" type="submit" class="download-btn">${esc(t('check.go'))}</button>
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
  let lastReport = null; // letzter gerenderter Report — Basis für Sprach-Re-Render

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
    goBtn.textContent = loading ? t('check.loading') : t('check.go');
    if (loading) {
      root.setAttribute('aria-busy', 'true');
      statusEl.innerHTML = `<p class="check-loading">${esc(t('check.loading'))}</p>`;
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
    const nameChip = nameChipHtml(c.counterparty);
    const risk =
      c.risk === 'malicious'
        ? `<span class="risk-badge risk-malicious">${esc(sevText('malicious'))}</span>`
        : c.risk === 'suspect'
          ? `<span class="risk-badge risk-suspect">${esc(sevText('suspect'))}</span>`
          : '<span class="cluster-table-dash">–</span>';
    return (
      `<tr>` +
      `<td class="cluster-td-addr"><span class="addr-full" title="${esc(shown)}">${esc(shown)}</span>${actions}${nameChip}</td>` +
      `<td>${esc(c.direction ?? '–')}</td>` +
      `<td>${esc(c.txType ?? '–')}</td>` +
      `<td>${esc(fmtClockHost(c.time))}</td>` +
      `<td>${risk}</td>` +
      `<td>${esc(c.note ?? '')}</td>` +
      `</tr>`
    );
  }

  function breakdownHtml(report) {
    if (!Array.isArray(report.scoreBreakdown) || report.scoreBreakdown.length === 0) return '';
    // b.kriterium bleibt RAW (serverseitiger Protokollwert, durch Tests
    // assertiert — account-report.test.mjs deepEqual); nur 'kein Abzug'
    // ist clientseitiger Text und wird übersetzt.
    const rows = report.scoreBreakdown
      .map(
        (b) =>
          `<div class="check-breakdown-row">` +
          `<dt>${esc(b.kriterium)}</dt>` +
          `<dd><span class="check-bd-wert">${esc(String(b.wert))}</span>` +
          `<span class="check-bd-abzug">${Number(b.abzug) > 0 ? `−${esc(String(b.abzug))}` : esc(t('check.noAbzug'))}</span></dd>` +
          `</div>`
      )
      .join('');
    return `<dl class="check-breakdown">${rows}</dl>`;
  }

  function metaHtml(report) {
    const parts = [`<span>${esc(t('check.metaChecked'))}${esc(String(report.checkedTxCount ?? 0))}</span>`];
    if (report.network) parts.push(`<span>${esc(t('check.metaNetwork'))}${esc(String(report.network))}</span>`);
    if (report.checkedAt) {
      const d = new Date(report.checkedAt);
      if (!Number.isNaN(d.getTime())) parts.push(`<span>${esc(t('check.metaAt'))}${esc(fmtDateTime(d))}</span>`);
    }
    if (report.truncated) parts.push(`<span class="check-truncated">${esc(t('check.metaTruncated'))}</span>`);
    return `<p class="check-meta">${parts.join('')}</p>`;
  }

  function roleHtml(report) {
    if (!report.role || !report.roleMetrics) {
      return `<p class="check-empty">${esc(t('check.roleEmpty'))}</p>`;
    }
    const m = report.roleMetrics;
    const swatch = `<span class="swatch swatch-${esc(String(report.role))}" aria-hidden="true"></span>`;
    const metrics =
      `<span>${esc(t('check.roleIn', { n: fmtNum(m.degreeIn), xrp: fmtXrpHost(m.inDrops) }))}</span>` +
      `<span>${esc(t('check.roleOut', { n: fmtNum(m.degreeOut), xrp: fmtXrpHost(m.outDrops) }))}</span>`;
    return (
      `<p class="check-role">${swatch}<strong>${esc(roleLabel(report.role))}</strong></p>` +
      `<p class="check-role-metrics">${metrics}</p>` +
      `<p class="graph-note check-note">${esc(t('check.roleNote'))}</p>`
    );
  }

  function patternsHtml(report) {
    const list = Array.isArray(report.patterns) ? report.patterns : [];
    if (!list.length) {
      return `<p class="check-empty">${esc(t('check.patternsEmpty'))}</p>`;
    }
    const chips = list.map((id) => `<span class="check-chip">${esc(ruleName(id))}</span>`).join('');
    return `<div class="check-chips">${chips}</div>`;
  }

  function contactsHtml(report) {
    const list = Array.isArray(report.contacts) ? report.contacts : [];
    if (!list.length) {
      return `<p class="check-empty">${esc(t('check.contactsEmpty'))}</p>`;
    }
    return (
      `<div class="cluster-table-wrap" tabindex="0" role="region" aria-label="${esc(t('check.contactsAria'))}">` +
      `<table class="cluster-table check-contacts-table">` +
      `<thead><tr><th scope="col">${esc(t('check.thCounterparty'))}</th><th scope="col">${esc(t('check.thDirection'))}</th><th scope="col">${esc(t('check.thTxType'))}</th><th scope="col">${esc(t('check.thTime'))}</th><th scope="col">${esc(t('check.thRisk'))}</th><th scope="col">${esc(t('check.thNote'))}</th></tr></thead>` +
      `<tbody>${list.map(contactRow).join('')}</tbody>` +
      `</table></div>`
    );
  }

  function eligibilityHtml(report) {
    const e = ELIGIBILITY[report.eligibility] ?? ELIGIBILITY.unknown;
    // eligibilityReason ist serverseitiger deutscher Protokollwert — Anzeige
    // über serverPhrase() (Exact-Match), unbekannte Gründe bleiben raw.
    return (
      `<p class="check-eligibility ${esc(e.cls)}">` +
      `<strong>${esc(t(e.key))}.</strong> ${esc(serverPhrase(report.eligibilityReason ?? ''))}` +
      `</p>`
    );
  }

  // Hash-Priming über den Host (Befund 2026-09-30): isFullShownAddr entscheidet
  // synchron aus dem addrHashCache des Hosts — ohne Priming blieben die geprüfte
  // Adresse und die Kontakt-Gegenparteien auch bei geladener Bait-Allowlist in
  // der Kurzform, ohne Kopieren-/XRPScan-Aktionen (diese Adressen erscheinen
  // nur hier, nicht im Cluster-Graph, und werden dort nie geprimt). Fail-closed:
  // Ohne ctx.hashOf oder bei Priming-Fehlern bleibt die Kurzform.
  async function renderReport(report) {
    lastReport = report; // für Re-Render bei Sprachwechsel
    if (typeof ctx.hashOf === 'function') {
      const targets = [report.address];
      for (const c of Array.isArray(report.contacts) ? report.contacts : []) {
        if (c && c.counterparty) targets.push(c.counterparty);
      }
      try {
        await Promise.all(targets.map((a) => ctx.hashOf(String(a ?? ''))));
      } catch { /* Priming fehlgeschlagen: fail-closed Kurzform bleibt */ }
    }
    const badge = VERDICT_BADGE[report.verdict] ?? VERDICT_BADGE.unknown;
    const shownAddr = displayAddr(report.address);
    const actions = addrActionsHtml(report.address);
    const nameChip = nameChipHtml(report.address);
    const scoreValue = typeof report.score === 'number' ? String(report.score) : '–';
    // Disclaimers sind serverseitige deutsche Protokollwerte — Anzeige über
    // serverPhrase() (Exact-Match auf die vier bekannten Werte).
    const disclaimers = (Array.isArray(report.disclaimers) ? report.disclaimers : [])
      .map((d) => `<li>${esc(serverPhrase(String(d)))}</li>`)
      .join('');
    const hintHtml = report.hint ? `<p class="graph-note check-hint">${esc(serverPhrase(String(report.hint)))}</p>` : '';
    // Zusammenfassung: neu aufgebaut aus strukturierten Feldern (verdict/
    // score/contacts/patterns) in der aktuellen Sprache; summaryText fällt
    // nie auf rohe Server-Sätze aus — report.zusammenfassung bleibt Rohwert.
    const summary = summaryText(report);

    reportEl.innerHTML =
      `<article class="check-report" aria-label="${esc(t('check.reportAria'))}">` +
      `<header class="check-report-head">` +
      `<span class="${esc(badge.cls)}">${esc(t(badge.key))}</span>` +
      `<span class="addr-full check-report-addr" title="${esc(shownAddr)}">${esc(shownAddr)}</span>${actions}${nameChip}` +
      `<div class="check-score" aria-label="${esc(t('check.scoreAria'))}">` +
      `<span class="check-score-value">${esc(scoreValue)}</span><span class="check-score-max">/ 100</span>` +
      `</div>` +
      `</header>` +
      `<p class="check-summary">${esc(summary)}</p>` +
      hintHtml +
      `<section class="check-section" aria-label="${esc(t('check.sectionScore'))}">` +
      `<h3 class="check-section-title">${esc(t('check.sectionScore'))}</h3>` +
      breakdownHtml(report) +
      metaHtml(report) +
      `</section>` +
      `<section class="check-section" aria-label="${esc(t('check.sectionRole'))}">` +
      `<h3 class="check-section-title">${esc(t('check.sectionRole'))}</h3>` +
      roleHtml(report) +
      `</section>` +
      `<section class="check-section" aria-label="${esc(t('check.sectionPatterns'))}">` +
      `<h3 class="check-section-title">${esc(t('check.sectionPatterns'))}</h3>` +
      patternsHtml(report) +
      `</section>` +
      `<section class="check-section" aria-label="${esc(t('check.sectionContacts'))}">` +
      `<h3 class="check-section-title">${esc(t('check.sectionContacts'))}</h3>` +
      contactsHtml(report) +
      `</section>` +
      `<section class="check-section" aria-label="${esc(t('check.sectionEligibility'))}">` +
      `<h3 class="check-section-title">${esc(t('check.sectionEligibility'))}</h3>` +
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
      showClientError(t('check.errInvalidAddr'));
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
          renderErrorCard(t('check.errInvalid400'), null);
        } else if (res.status === 502) {
          // body.error bleibt raw — serverseitiger Protokollwert.
          renderErrorCard(t('check.errLedger502'), body && body.error ? String(body.error) : null);
        } else {
          renderErrorCard(t('check.errUnexpected', { status: res.status }), body && body.error ? String(body.error) : null);
        }
        return;
      }
      await renderReport(body);
    } catch {
      renderErrorCard(t('check.errNetworkTitle'), t('check.errNetworkDetail'));
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

  // Sprachwechsel: Panel-Gerüst neu bauen und letzten Report re-rendern.
  function reRender() {
    if (lastReport) void renderReport(lastReport);
  }
  if (typeof document !== 'undefined' && document && typeof document.addEventListener === 'function') {
    try { document.addEventListener('hx:langchange', reRender); } catch { /* Noop */ }
  }

  return { setView, reRender };
}
