'use strict';

/* Honeypot XRPL – Maliziöse Historie (public/history.js)
 *
 * Browser-Modul für den Log-Activity-Bereich „Maliziöse Historie“ (Mount:
 * #history-root, Muster public/drilldown.js). Zwei Aufgaben:
 *
 *   1. KOLLEKTIVER ZUWACHS (Client -> Server): onClusterRebuild(cg) gleicht
 *      maliziöse Cluster des Live-Graphen gegen eine sessionStorage-gesehene
 *      Schlüsselmenge ab; neue Schlüssel werden dezent per POST /api/history
 *      gemeldet — max. 1 POST je 10 s, ≤ 200 Cluster pro Payload, Fehler
 *      (502/503/429, Netzwerk) werden still toleriert (nächster Versuch beim
 *      nächsten neuen Schlüssel). Der Live-Betrieb bleibt unberührt.
 *   2. ANZEIGE: setView(true) lädt GET /api/history (60-s-Timer, nur solange
 *      die Ansicht sichtbar UND document.visibilityState === 'visible' ist)
 *      und rendert Suchfeld + Cluster-Karten in das #history-root-Panel.
 *
 * SICHERHEIT (Köder-Schutz, Client-Schicht):
 *   - Gemeldet wird NUR severity 'malicious' (Maximum der Mitglieder-
 *     Schweregrade aus cg.nodes, Muster clusterCardHtml in app.js:722-733);
 *     suspect/info erreichen die Persistenz nie.
 *   - Members stammen NUR aus cg.nodes und werden zusätzlich über
 *     ctx.isDeniedAddr(id) gefiltert (Hash-Deny, fail-closed).
 *   - Beim RENDERN läuft JEDE Mitglied-Adresse vor der Ausgabe erneut durch
 *     ctx.isDeniedAddr (fail-closed); Cluster ohne verbleibende Mitglieder
 *     werden komplett übersprungen. Volle Anzeige nur unter der
 *     isFullShownAddr-Politik des Hosts (Bait-Hash-Allowlist geladen, kein
 *     Deny-Treffer), sonst Kurzform — title trägt NIE die Roheadresse,
 *     sondern den Anzeigewert.
 *
 * MODULKOPF DOM-FREI: kein document-/window-Zugriff auf Top-Level —
 * Voraussetzung für den Konsistenz-Test (node --test importiert diese Datei
 * und vergleicht normalizedNameClient/historyKeyClient mit lib/history.mjs).
 * Auch der Import von './i18n.mjs' ist DOM-frei (reines ESM, Muster
 * public/attribution.mjs). Alle DOM-Zugriffe erfolgen lazily in Funktionen;
 * fehlt #history-root (Panel noch nicht gemountet), degradiert das Modul
 * still — Melden via onClusterRebuild bleibt funktionsfähig.
 */

import { t, ruleName as i18nRuleName, fmtNum, fmtXrp, fmtClock } from './i18n.mjs';

const POST_MIN_INTERVAL_MS = 10000; // max. 1 POST je 10 s pro Tab
const REFRESH_MS = 60000;           // GET-Takt, nur wenn Ansicht sichtbar
const MAX_CLUSTERS_PER_POST = 200;
const MAX_VISIBLE_MEMBERS = 8;      // sichtbare Mitglieder je Karte, Rest per <details>
const SEEN_STORAGE_KEY = 'honeypot-history-seen-keys';
const SEEN_MAX = 500;               // Obergrenze der sessionStorage-Schlüsselmenge
const SEV_RANK = { info: 0, suspect: 1, malicious: 2 };

/* Identisch zu lib/history.mjs normalizedName: je Adresse trimmen,
 * lexikographisch sortieren, mit einzelnem Zeilenumbruch (U+000A) verbinden. */
export function normalizedNameClient(members) {
  return (Array.isArray(members) ? members : [])
    .map((m) => String(m ?? '').trim())
    .sort()
    .join('\n');
}

/* historyKeyClient via WebCrypto (crypto.subtle) — dasselbe sha256-hex (klein)
 * wie serverseitig historyKey (node:crypto). */
export async function historyKeyClient(members) {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(normalizedNameClient(members)));
  let hex = '';
  for (const b of new Uint8Array(digest)) hex += b.toString(16).padStart(2, '0');
  return hex;
}

export function initHistory(ctx) {
  const host = ctx || {};
  // Sicherer Escaping-Fallback (Muster globe.js/account-check.js): Auch wenn
  // der Host kein esc übergibt (oder es wirft), wird HTML-escapet —
  // clusterCardHtml interpoliert Server-Label und Regelnamen in innerHTML
  // (Befund 2026-09-29: der bisherige Fallback war eine Identitätsfunktion).
  const escHost = typeof host.esc === 'function' ? host.esc : null;
  const esc = (v) => {
    const s = String(v ?? '');
    if (escHost) {
      try { return escHost(s); } catch { /* Fallback unten */ }
    }
    return s.replace(/[&<>"']/g, (c) => ({
      '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
    })[c]);
  };
  // Adress-Gate (2026-10-04): Kürzungs-Muster sind ausschließlich in den
  // Maskierungs-Helfern erlaubt (app.js shortAddr, account-check.js
  // localShortAddr, history-host.html shortAddr). history.js dupliziert die
  // Kürzung nicht — der hostlose Fallback gibt die vollständige Adresse
  // zurück. Im echten Host wird shortAddr immer über ctx gereicht
  // (app.js:166, fail-closed displayFindingAddr bleibt der Gate); hostlos
  // wäre die API-Antwort ohnehin serverseitig köder-gefiltert
  // (api/history.js:13-15, 59 — GET-Filter über baitLabels).
  const shortAddr = typeof host.shortAddr === 'function'
    ? host.shortAddr
    : (a) => String(a ?? '');
  const fmtXrpHost = typeof host.fmtXrp === 'function' ? host.fmtXrp : fmtXrp;
  const fmtClockHost = typeof host.fmtClock === 'function' ? host.fmtClock : fmtClock;
  const isDeniedAddr = typeof host.isDeniedAddr === 'function' ? host.isDeniedAddr : () => false;
  const isFullShownAddr = typeof host.isFullShownAddr === 'function' ? host.isFullShownAddr : () => false;
  const displayAddr = typeof host.displayAddr === 'function' ? host.displayAddr : (a) => shortAddr(a);
  const addrActionsHtml = typeof host.addrActionsHtml === 'function' ? host.addrActionsHtml : () => '';
  // Namens-Badge (XRPScan-Aliase): HOST-GATE — ctx.accountNameOf (app.js)
  // liefert null für maskierte/Deny-Adressen; lokaler Guard spiegelt die
  // isFullShownAddr-Politik von memberLine (:283). Fallback ohne Host-
  // Funktion: () => null — ohne Lookup fehlt nur das Badge, nie die Maske.
  const accountNameOf = (a) => (typeof host.accountNameOf === 'function' && isFullShownAddr(a) ? host.accountNameOf(a) : null);
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

  const numDe = (v) => fmtNum(v);

  // Regelname: i18n-Lookup (aktuelle Sprache) für die bekannten 9 ids;
  // unbekannte ids fallen auf die ctx-Tafel des Hosts und zuletzt roh.
  function ruleName(ruleId) {
    const id = String(ruleId ?? '');
    const viaI18n = i18nRuleName(id);
    if (viaI18n !== id) return viaI18n;
    const rn = host.ruleNames;
    if (typeof rn === 'function') return rn(id) ?? id;
    if (rn && typeof rn.get === 'function') return rn.get(id) ?? id;
    return id;
  }

  /* ---------- Zustand ---------- */
  let shellReady = false;
  let viewVisible = false;
  let timerId = null;
  let query = '';
  let currentClusters = [];
  let state = 'idle'; // 'loading' | 'ready' | 'empty' | 'error' | 'unconfigured'
  let errorStatus = 0;
  let seen = null;
  let pending = [];      // noch zu meldende Cluster (max. MAX_CLUSTERS_PER_POST)
  let lastPostAt = 0;

  function rootEl() {
    return typeof document === 'undefined' ? null : document.getElementById('history-root');
  }

  /* ---------- sessionStorage (seen keys) ---------- */
  function loadSeen() {
    if (seen) return seen;
    seen = new Set();
    try {
      const raw = sessionStorage.getItem(SEEN_STORAGE_KEY);
      const arr = JSON.parse(raw ?? '[]');
      if (Array.isArray(arr)) for (const k of arr) if (typeof k === 'string') seen.add(k);
    } catch { /* Private Mode / korrupter Stand: leere Menge */ }
    return seen;
  }
  function persistSeen() {
    try {
      sessionStorage.setItem(SEEN_STORAGE_KEY, JSON.stringify([...seen].slice(-SEEN_MAX)));
    } catch { /* Speicher voll/Private Mode: Meldungen werden höchstens wiederholt */ }
  }

  /* ---------- Melden (kollektiver Zuwachs) ---------- */
  function rulesFromFindings(findings, memberSet) {
    const out = new Set();
    for (const f of Array.isArray(findings) ? findings : []) {
      const a = String(f?.address ?? '');
      if (memberSet.has(a) && f?.ruleId) out.add(String(f.ruleId));
    }
    return [...out].sort();
  }

  function buildReportEntry(cluster, members, key, findings) {
    const parseOr = (iso, fallback) => {
      const t = Date.parse(iso);
      return Number.isFinite(t) ? t : fallback;
    };
    const now = Date.now();
    const num = (v) => (Number.isFinite(Number(v)) ? Math.max(0, Math.trunc(Number(v))) : 0);
    return {
      key,
      members,
      label: String(cluster?.label ?? ''),
      totalDrops: num(cluster?.totalDrops),
      txCount: num(cluster?.txCount),
      distinctAccounts: members.length,
      firstSeen: parseOr(cluster?.firstSeen, now),
      lastSeen: parseOr(cluster?.lastSeen, now),
      rules: rulesFromFindings(findings, new Set(members)),
      severity: 'malicious',
    };
  }

  async function reportNewClusters(cg, findings) {
    if (!cg || !Array.isArray(cg.nodes)) return;
    const sevByAddr = new Map();
    for (const n of cg.nodes) {
      if (n && typeof n.id === 'string') sevByAddr.set(n.id, String(n.severity ?? 'info'));
    }
    // Members NUR aus cg.nodes — und zusätzlich hash-deny-gefiltert (fail-closed).
    const nodesByCluster = new Map();
    for (const n of cg.nodes) {
      if (!n || typeof n.id !== 'string') continue;
      if (n.clusterId == null) continue;
      if (isDeniedAddr(n.id)) continue;
      if (!nodesByCluster.has(n.clusterId)) nodesByCluster.set(n.clusterId, []);
      nodesByCluster.get(n.clusterId).push(n);
    }
    loadSeen();
    const queuedKeys = new Set(pending.map((p) => p.key));
    const fresh = [];
    for (const cluster of Array.isArray(cg.clusters) ? cg.clusters : []) {
      const nodes = nodesByCluster.get(cluster?.id) ?? [];
      if (!nodes.length) continue;
      let sev = 'info'; // Maximum der Mitglieder-Schweregrade (Muster app.js:722-733)
      for (const n of nodes) {
        const s = sevByAddr.get(n.id) ?? 'info';
        if ((SEV_RANK[s] ?? 0) > (SEV_RANK[sev] ?? 0)) sev = s;
      }
      if (sev !== 'malicious') continue; // suspect/info erreichen die Persistenz NIE
      const members = nodes.map((n) => n.id).sort();
      const key = await historyKeyClient(members);
      if (seen.has(key) || queuedKeys.has(key)) continue;
      queuedKeys.add(key);
      fresh.push(buildReportEntry(cluster, members, key, findings));
    }
    if (!fresh.length) return;
    pending.push(...fresh);
    if (pending.length > MAX_CLUSTERS_PER_POST) pending = pending.slice(-MAX_CLUSTERS_PER_POST);
    await maybeReport();
  }

  async function maybeReport() {
    if (!pending.length) return;
    const now = Date.now();
    if (now - lastPostAt < POST_MIN_INTERVAL_MS) return; // max. 1 POST je 10 s
    const batch = pending.slice(0, MAX_CLUSTERS_PER_POST);
    lastPostAt = now;
    try {
      const res = await fetch('/api/history', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ clusters: batch }),
      });
      if (res.ok) {
        for (const c of batch) seen.add(c.key);
        persistSeen();
        pending = pending.filter((p) => !batch.includes(p));
      } else if (res.status === 400 || res.status === 405 || res.status === 413) {
        // Client-seitiger Fehler: Batch verwerfen statt endlos wiederholen.
        pending = pending.filter((p) => !batch.includes(p));
      }
      /* 429/5xx: still tolerieren — die Schlange bleibt für den nächsten
       * Versuch stehen (nächster Anlauf beim nächsten neuen Schlüssel). */
    } catch { /* Netzwerkfehler still tolerieren */ }
  }

  /* ---------- Ansicht / Zustände ---------- */
  function renderShell() {
    const root = rootEl();
    if (shellReady || !root) return;
    root.innerHTML = `
      <div class="panel-head">
        <h2 id="history-title">${esc(t('history.title'))}</h2>
        <span class="hint">${esc(t('history.hint'))}</span>
      </div>
      <div class="history-search">
        <label class="filter-label" for="history-search">${esc(t('history.searchLabel'))}</label>
        <input id="history-search" type="search" class="filter-select" placeholder="${esc(t('history.searchPlaceholder'))}">
      </div>
      <p class="graph-note" id="history-state" role="status" aria-live="polite">${esc(t('history.loading'))}</p>
      <ul class="cluster-list" id="history-list" aria-labelledby="history-title"></ul>`;
    root.querySelector('#history-search').addEventListener('input', (e) => {
      query = e.target.value;
      renderList();
    });
    shellReady = true;
  }

  function stateText() {
    if (state === 'loading') return t('history.loading');
    if (state === 'unconfigured') {
      return t('history.unconfigured');
    }
    if (state === 'empty') {
      return t('history.empty');
    }
    if (state === 'error') {
      return errorStatus > 0
        ? t('history.errorHttp', { status: errorStatus })
        : t('history.errorNet');
    }
    return '';
  }

  function memberLine(addr) {
    const full = isFullShownAddr(addr);
    const shown = full ? displayAddr(addr) : shortAddr(addr); // title = Anzeigewert, NIE Roheadresse
    const actions = full ? addrActionsHtml(displayAddr(addr)) : '';
    // Name nur bei erlaubter Vollanzeige und nur hinter dem Host-Gate.
    const nameChip = full ? nameChipHtml(addr) : '';
    return `<li class="history-member"><span class="addr-full" title="${esc(shown)}">${esc(shown)}</span>${actions}${nameChip}</li>`;
  }

  function clusterMatches(c, needle) {
    if (!needle) return true;
    if (String(c?.label ?? '').toLowerCase().includes(needle)) return true;
    if (Array.isArray(c?.members) && c.members.some((m) => String(m ?? '').toLowerCase().includes(needle))) return true;
    if (Array.isArray(c?.rules) && c.rules.some((r) => String(r ?? '').toLowerCase().includes(needle))) return true;
    return false;
  }

  function clusterCardHtml(c) {
    // JEDE Mitglied-Adresse VOR dem Rendern über isDeniedAddr filtern
    // (fail-closed); Cluster ohne verbleibende Mitglieder komplett überspringen.
    const members = (Array.isArray(c?.members) ? c.members : [])
      .map((m) => String(m ?? ''))
      .filter((m) => m && !isDeniedAddr(m));
    if (!members.length) return '';
    const visible = members.slice(0, MAX_VISIBLE_MEMBERS);
    const restCount = members.length - visible.length;
    const restHtml = restCount > 0
      ? `<details class="history-members-more"><summary>${esc(t('history.moreMembers', { n: numDe(restCount) }))}</summary>` +
        `<ul class="history-members">${members.slice(MAX_VISIBLE_MEMBERS).map(memberLine).join('')}</ul></details>`
      : '';
    const rules = (Array.isArray(c?.rules) ? c.rules : []).slice(0, 16);
    const ruleBadges = rules.length
      ? `<div class="history-rules">${rules.map((r) => `<span class="badge">${esc(ruleName(r))}</span>`).join('')}</div>`
      : '';
    const sightings = Math.max(1, Number(c?.sightings ?? 1));
    const sightingBadge = sightings >= 2
      ? `<span class="badge">${esc(t('history.sightings', { n: numDe(sightings) }))}</span>`
      : `<span class="badge badge-partial">${esc(t('history.unbestaetigt'))}</span>`;
    return `
      <li class="cluster-card sev-malicious">
        <div class="cluster-head">
          <span class="cluster-label">${esc(c?.label || t('cluster.labelDefault'))}</span>
          <span class="risk-badge risk-malicious">${esc(t('history.maliciousBadge'))}</span>
        </div>
        <ul class="history-members">${visible.map(memberLine).join('')}</ul>
        ${restHtml}
        <div class="cluster-metrics">
          <span class="cluster-xrp">${esc(fmtXrpHost(c?.totalDrops))} XRP</span>
          <span class="cluster-txs">${numDe(c?.txCount)} ${esc(t('cluster.txUnit'))}</span>
          <span class="cluster-accounts">${numDe(c?.distinctAccounts ?? members.length)} ${esc(t('cluster.accountUnit'))}</span>
        </div>
        ${ruleBadges}
        <div class="cluster-times">
          <span>${esc(t('cluster.firstSeen'))}${esc(fmtClockHost(c?.firstSeen))}</span>
          <span>${esc(t('cluster.lastSeen'))}${esc(fmtClockHost(c?.lastSeen))}</span>
        </div>
        <div class="history-sightings">${sightingBadge}</div>
      </li>`;
  }

  function renderList() {
    if (!shellReady) return;
    const root = rootEl();
    if (!root) return;
    const listEl = root.querySelector('#history-list');
    const stateEl = root.querySelector('#history-state');
    const needle = query.trim().toLowerCase();
    const cards = currentClusters
      .filter((c) => clusterMatches(c, needle))
      .map(clusterCardHtml)
      .filter(Boolean);
    listEl.innerHTML = cards.join('');
    stateEl.textContent = stateText();
  }

  async function refresh() {
    if (!viewVisible && !rootEl()) return; // ohne Panel kein Netz-Traffic
    try {
      const res = await fetch('/api/history', { cache: 'no-store' });
      if (!res.ok) {
        state = 'error';
        errorStatus = res.status;
        renderList();
        return;
      }
      const body = await res.json();
      // Vergleich auf dem ROHEN Server-String (api/history.js reason-Feld —
      // Protokollwert, wird nicht übersetzt); nur die Anzeige (stateText)
      // folgt der aktuellen Sprache.
      if (body && body.reason === 'Persistenz nicht konfiguriert') {
        state = 'unconfigured'; // eigener Zustand — NICHT der Leerzustand
        currentClusters = [];
        renderList();
        return;
      }
      currentClusters = Array.isArray(body?.clusters) ? body.clusters : [];
      state = currentClusters.length ? 'ready' : 'empty';
      // Hash-Priming der Mitglieder-Adressen (Befund 2026-10-04, Muster
      // account-check.js renderReport / globe.js): isFullShownAddr entscheidet
      // synchron aus dem addrHashCache des Hosts — die Cluster aus
      // GET /api/history werden vom Live-Priming (primeAddrHashes, nur
      // Cluster-Graph) nie erfasst, blieben also trotz geladener
      // Bait-Allowlist in der Kurzform. Fail-closed: ohne ctx.hashOf oder bei
      // Priming-Fehlern bleibt die Kurzform. Cap 4000 Adressen je Refresh
      // (Host-Cache ADDR_HASH_CACHE_MAX = 10000, LRU). Nach diesem Priming
      // nutzen Such-Re-Render und 60-s-Timer dieselben Cache-Einträge; der
      // Timer-Refresh primt ein neues currentClusters erneut.
      if (typeof host.hashOf === 'function') {
        const targets = new Set();
        for (const c of currentClusters) {
          for (const m of Array.isArray(c?.members) ? c.members : []) {
            const a = String(m ?? '').trim();
            if (a) targets.add(a);
          }
        }
        const list = [...targets].slice(0, 4000);
        try {
          await Promise.all(list.map((a) => host.hashOf(a)));
        } catch { /* Priming fehlgeschlagen: fail-closed Kurzform bleibt */ }
      }
      // Bereits persistierte Schlüssel gelten als gesehen — vermeidet
      // Doppel-Meldungen desselben Clusters im nächsten onClusterRebuild.
      loadSeen();
      for (const c of currentClusters) if (c?.key) seen.add(String(c.key));
      persistSeen();
      renderList();
    } catch {
      state = 'error';
      errorStatus = 0;
      renderList();
    }
  }

  function stopTimer() {
    if (timerId !== null) {
      clearInterval(timerId);
      timerId = null;
    }
  }

  function startTimer() {
    stopTimer();
    timerId = setInterval(() => {
      if (typeof document === 'undefined') return;
      if (document.visibilityState !== 'visible') return; // nur im sichtbaren Tab laden
      refresh();
    }, REFRESH_MS);
  }

  function setView(visible) {
    viewVisible = Boolean(visible);
    if (viewVisible) {
      renderShell();
      if (state === 'idle') state = 'loading';
      renderList();
      refresh();
      startTimer();
    } else {
      stopTimer(); // Views sind reine Anzeigefilter — Melden läuft weiter
    }
  }

  async function onClusterRebuild(cg, findings) {
    try {
      await reportNewClusters(cg, findings);
    } catch { /* Melden darf den Live-Betrieb nie brechen */ }
  }

  // Sprachwechsel: Shell neu bauen (statische Texte) und Liste re-rendern.
  // Guardiert — ohne document kein Listener (Node-Import bleibt sicher).
  function reRender() {
    if (shellReady) {
      shellReady = false;
      renderShell();
      renderList();
    }
  }
  if (typeof document !== 'undefined' && document && typeof document.addEventListener === 'function') {
    try { document.addEventListener('hx:langchange', reRender); } catch { /* Noop */ }
  }

  return { onClusterRebuild, setView, refresh, reRender };
}
