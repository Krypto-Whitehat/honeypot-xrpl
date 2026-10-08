'use strict';
// public/exchange-outflows.mjs — DOM-freie Aggregation "Top-10 Börsen-Zuflüsse
// aus Drainer-Kontext" aus der BESTEHENDEN /api/flow-state-View
// (Daten-Forensik 2026-10-07). KEIN neuer api/*-Endpoint (Vercel-Hobby-Limit
// 12 Functions): die Box rechnet clientseitig aus derselben 60-s-Poll-Antwort,
// Budget +0 Requests / +0 Functions (Architektur-Entscheidung A des Plans).
//
// MODUL-VERTRAG (Muster public/cluster-chips.mjs / public/cluster-views.mjs):
// DOM-frei beim Import, kein fetch, kein window/document — reine Daten-
// transformation plus Zeilen-Markup ÜBER INJIZIERTE HOST-GATES. Die Köder-
// Maske (shortAddr/displayFindingAddr/isFullShownAddr) und esc() bleiben
// Host-Sache: dieses Modul rendert nie eine rohe Adresse und nie einen rohen
// Registry-String (well-known-Namen stammen aus dem externen XRPScan-Bulk-
// Index, public/exchange-registry.mjs multiUserSnapshot — Pflicht 12: nichts
// Ungegattetes ins DOM). Ohne Host-Gates liefert exchangeOutflowRowHtml ''
// (fail-closed).
//
// QUALIFIZIERUNG je Kante (Kanten-Prädikat, NICHT Cluster-level — live
// hätten Cluster-level-Prädikate 28/28 Cluster bestanden und wären kein
// Filter; Forensik 2026-10-07):
//   (1) e.to liegt in der Börsen-Union (multiUserSnapshot: 81er-Registry ∪
//       verifizierte well-known-Namen — dieselbe Quelle wie die Tag-Chips),
//   (2) die QUELLE e.from trägt IM SELBSTEN Cluster severityByAddress[from]
//       ∈ {malicious, suspect} ODER rolesByAddress[from] === 'drainer',
//   (3) closeTime parsebar und nowMs − windowMs <= t <= nowMs mit
//       windowMs ∈ {7 d, 30 d}. Die Fenster entsprechen den Retentionen des
//       States: 7 d = FLOW_STATE_RETENTION_MS, 30 d =
//       FLOW_STATE_MALICIOUS_RETENTION_MS (lib/flow-state.mjs) — fraud-
//       Cluster bleiben mit ALLEN Kanten 30 Tage im State, daher deckt der
//       State das 30-d-Fenster für genau die hier gezählten Kanten ab.
// Kanten, die (1)+(2) erfüllen, aber kein parsebares closeTime tragen,
// fliegen raus und zählen in totals.excludedNoCloseTime (nichts wird still
// verworfen); Kanten an Nicht-Union-Ziele oder ohne Drainer-Kontext zählen
// bewusst NICHT als excluded — sie sind keine verlorenen Daten, sondern
// außerhalb der Fragestellung.
//
// EHRLICHE GRENZEN (bewusst nicht verschwiegen):
//   - Der State behält nur die 50 nach Volumen größten Kanten je Cluster
//     (maxClusterEdges, lib/ledger-walk.mjs); die Summen sind eine
//     UNTergrenze — totals.cappedClusters macht die Kappung sichtbar.
//   - Die tatsächliche Abdeckung ist min(Fenster, ältestes Cluster im
//     State) — coverageFrom (min firstSeen aller betrachteten Cluster)
//     macht die reale Tiefe sichtbar, das UI zeigt sie in der Fußnote
//     (Pflicht 11), nicht das nominelle Fenster.

// Retention-Fenster des Flow-States (Spiegel lib/flow-state.mjs
// FLOW_STATE_RETENTION_MS / FLOW_STATE_MALICIOUS_RETENTION_MS).
export const EXOUT_WINDOW_7D_MS = 7 * 24 * 60 * 60 * 1000;   // 7 d
export const EXOUT_WINDOW_30D_MS = 30 * 24 * 60 * 60 * 1000; // 30 d

// Kantendeckel des States je Cluster (Spiegel lib/ledger-walk.mjs
// maxClusterEdges) — Cluster an/nach diesem Wert sind gekappt gezählt.
export const EXOUT_EDGE_CAP = 50;

// Schweregrade, die eine Kanten-Quelle zum Betrugs-Kontext machen (Spiegel
// SEV_RANK-Familie in public/cluster-views.mjs; 'info' qualifiziert nie).
const QUALIFYING_SEVERITIES = new Set(['malicious', 'suspect']);

// Binärer String-Vergleich (Konvention viewCmpStrBin, lib/flow-state.mjs —
// localeCompare wäre locale-abhängig und damit nicht deterministisch).
function cmpStrBin(a, b) {
  const x = String(a ?? '');
  const y = String(b ?? '');
  return x < y ? -1 : x > y ? 1 : 0;
}

function bucketAcc(windowDays, windowMs) {
  return {
    windowDays,
    windowMs,
    byAddr: new Map(),
    totals: {
      qualifyingEdges: 0,
      qualifyingDrops: 0,
      excludedNoCloseTime: 0,
      clustersScanned: 0,
      cappedClusters: 0,
    },
  };
}

function finishBucket(acc, topN) {
  const rows = [...acc.byAddr.values()]
    .map((rec) => ({
      address: rec.address,
      dropsSum: rec.dropsSum,
      inEdges: rec.inEdges,
      clusterCount: rec.clusters.size,
      lastInflowMs: rec.lastInflowMs,
      transitDrops: rec.transitDrops,
      // Börsen-Identität ausschließlich aus dem Union-Entry (kein eigener
      // Lookup, keine Erfundung); well-known = verifizierter Bulk-Eintrag.
      exchange: rec.entry && typeof rec.entry.exchange === 'string' && rec.entry.exchange
        ? rec.entry.exchange
        : null,
      domain: rec.entry && typeof rec.entry.domain === 'string' && rec.entry.domain
        ? rec.entry.domain
        : null,
      wellKnown: !!(rec.entry && rec.entry.confidence === 'well-known'),
    }))
    // Totalordnung: dropsSum desc → inEdges desc → Adresse lex. asc (binär).
    .sort((a, b) =>
      b.dropsSum - a.dropsSum ||
      b.inEdges - a.inEdges ||
      cmpStrBin(a.address, b.address))
    .slice(0, topN);
  return { windowDays: acc.windowDays, rows, totals: acc.totals };
}

/* Aggregation über die /api/flow-state-View.
 *
 * view        — Rohkörper der API ({clusters:[…]}); je Cluster werden
 *               rolesByAddress, severityByAddress, edges, id, firstSeen
 *               gelesen (View-Vertrag lib/flow-state.mjs viewEdge/project-
 *               FlowStateView: Kanten mit from/to/amountDrops/closeTime/
 *               toTag/fromTag/transit).
 * exchangeMap — Map Adresse → {exchange, domain, confidence} aus
 *               multiUserSnapshot() (public/exchange-registry.mjs). Keine Map
 *               → keine qualifizierende Kante (fail-closed, leere Buckets).
 * nowMs       — Referenzzeitpunkt der Fenster (Date.now() des Hosts; injiziert
 *               für deterministische Tests).
 * opts.topN   — Listenlänge (Default 10).
 *
 * Rückgabe:
 * {
 *   seven:  { windowDays: 7,  rows, totals { qualifyingEdges, qualifyingDrops,
 *             excludedNoCloseTime, clustersScanned, cappedClusters } },
 *   thirty: { windowDays: 30, rows, totals { … } },
 *   coverageFrom,   // ISO-String|min firstSeen aller betrachteten Cluster | null
 *   generatedAt,    // nowMs (ms)
 * }
 * 7 d UND 30 d in EINEM Durchlauf (zwei Buckets, O(Kanten)) — die Buckets
 * sind eigenständig: gleiches Kantenset, unterschiedliche Fenstergrenze.
 */
export function aggregateExchangeOutflows(view, exchangeMap, nowMs, opts = {}) {
  const topN = Math.max(1, Math.floor(Number(opts && opts.topN) || 10));
  const now = Number(nowMs);
  const generatedAt = Number.isFinite(now) ? now : Date.now();
  const clusters = Array.isArray(view && view.clusters) ? view.clusters : [];
  const map = exchangeMap instanceof Map ? exchangeMap : null;

  const seven = bucketAcc(7, EXOUT_WINDOW_7D_MS);
  const thirty = bucketAcc(30, EXOUT_WINDOW_30D_MS);
  const all = bucketAcc(null, Infinity); // seit Start des States (keine Zeitgrenze)
  const buckets = [seven, thirty, all];
  let coverageFromMs = null;

  for (const c of clusters) {
    if (!c || typeof c !== 'object') continue;
    const edges = Array.isArray(c.edges) ? c.edges : [];
    if (!edges.length) continue; // ohne Kanten keine Zufluss-Evidenz
    const clusterId = String(c.id ?? '');
    const rolesByAddress = c.rolesByAddress && typeof c.rolesByAddress === 'object'
      ? c.rolesByAddress
      : {};
    const severityByAddress = c.severityByAddress && typeof c.severityByAddress === 'object'
      ? c.severityByAddress
      : {};
    const capped = edges.length >= EXOUT_EDGE_CAP;

    // Abdeckungszeitraum (Pflicht 11): min firstSeen aller betrachteten
    // Cluster — unparsebare firstSeen verlieren nie gegen parsebare.
    const fsMs = Date.parse(String(c.firstSeen ?? ''));
    if (Number.isFinite(fsMs) && (coverageFromMs === null || fsMs < coverageFromMs)) {
      coverageFromMs = fsMs;
    }

    for (const b of buckets) {
      b.totals.clustersScanned += 1;
      if (capped) b.totals.cappedClusters += 1;
    }

    for (const e of edges) {
      if (!e || typeof e !== 'object') continue;
      const from = typeof e.from === 'string' ? e.from : '';
      const to = typeof e.to === 'string' ? e.to : '';
      if (!from || !to) continue;
      // (1) Ziel muss in der Börsen-Union liegen.
      const entry = map ? map.get(to) : undefined;
      if (!entry) continue;
      // (2) Quelle im Drainer-Kontext: Severity ODER Drainer-Rolle —
      // IM SELBEN Cluster (Kanten-Prädikat, siehe Kopf).
      const sev = severityByAddress[from];
      const roleQualified = rolesByAddress[from] === 'drainer';
      const sevQualified = QUALIFYING_SEVERITIES.has(sev);
      if (!roleQualified && !sevQualified) continue;

      // (3) Fenstergrenze über closeTime (ISO-String, viewEdge). Kanten ohne
      // parsebares closeTime sind in KEINEM Fenster auswertbar → explitzit
      // gezählt statt still verworfen.
      const tMs = e.closeTime ? Date.parse(String(e.closeTime)) : NaN;
      if (!Number.isFinite(tMs)) {
        for (const b of buckets) b.totals.excludedNoCloseTime += 1;
        continue;
      }
      const amount = Number.isFinite(Number(e.amountDrops)) ? Number(e.amountDrops) : 0;

      for (const b of buckets) {
        if (tMs < generatedAt - b.windowMs || tMs > generatedAt) continue;
        b.totals.qualifyingEdges += 1;
        b.totals.qualifyingDrops += amount;
        let rec = b.byAddr.get(to);
        if (!rec) {
          rec = {
            address: to,
            dropsSum: 0,
            inEdges: 0,
            clusters: new Set(),
            lastInflowMs: 0,
            transitDrops: 0,
            entry,
          };
          b.byAddr.set(to, rec);
        }
        rec.dropsSum += amount;
        rec.inEdges += 1;
        rec.clusters.add(clusterId);
        if (tMs > rec.lastInflowMs) rec.lastInflowMs = tMs;
        if (e.transit === true) rec.transitDrops += amount;
      }
    }
  }

  return {
    seven: finishBucket(seven, topN),
    thirty: finishBucket(thirty, topN),
    all: finishBucket(all, topN),
    coverageFrom: coverageFromMs === null ? null : new Date(coverageFromMs).toISOString(),
    generatedAt,
  };
}

/* Zeilen-Markup EINER Top-10-Zeile — ausschließlich über die injizierten
 * Host-Gates (Pflicht 12: keine rohen Registry-Strings, keine rohen
 * Adressen ins DOM). Muster public/cluster-chips.mjs: das Modul wählt und
 * bettet ein, das Host gatet.
 *
 * row  — Zeile aus aggregateExchangeOutflows(...).rows
 * rank — 1-basierte Rangnummer
 * ui   — {
 *   esc,          // function(string) -> string   (Host esc, app.js)
 *   displayAddr,  // function(string) -> string   (Host displayFindingAddr:
 *                 // volle Adresse nur bei geladener Allowlist, sonst
 *                 // Kurzform — dieselbe Maske wie alle anderen Sichten)
 *   fmtXrp,       // function(number) -> string   (i18n, Locale folgt Sprache)
 *   fmtNum,       // function(number) -> string
 *   labels: {     // vorübersetzte i18n-Stücke (Host t(), Parameter interpoliert)
 *     rankAria,   // function(n) -> string  — title des Rangs
 *     inflows,    // function(n) -> string  — Kantenzahl
 *     clusters,   // function(n) -> string  — Clusterzahl
 *     transit,    // function(xrp) -> string — Transit-Badge (XRP-formatiert)
 *     wellKnown,  // string — Badge-Text des well-known-Hinweises
 *   },
 * }
 *
 * Fail-closed: ohne vollständige Gates oder ohne Zeile → '' (keine Zeile).
 * Der Betrag läuft NIE als rohe Zahl mit eigener Formatierung — fmtXrp des
 * Hosts (i18n.mjs) ist Pflicht, "Drops-Formatierung wie bestehende Beträge".
 */
export function exchangeOutflowRowHtml(row, rank, ui) {
  if (!row || typeof row !== 'object') return '';
  const g = ui && typeof ui === 'object' ? ui : null;
  if (!g
    || typeof g.esc !== 'function'
    || typeof g.displayAddr !== 'function'
    || typeof g.fmtXrp !== 'function'
    || typeof g.fmtNum !== 'function') return '';
  const labels = g.labels && typeof g.labels === 'object' ? g.labels : {};
  const rankAria = typeof labels.rankAria === 'function' ? labels.rankAria(rank) : '';
  const inflows = typeof labels.inflows === 'function' ? labels.inflows(row.inEdges) : '';
  const clusters = typeof labels.clusters === 'function' ? labels.clusters(row.clusterCount) : '';

  // Anzeige-Adresse NUR über das Host-Gate (Maske: Köder-Deny zuerst).
  const shown = String(g.displayAddr(row.address) ?? '');
  if (!shown) return ''; // Gate verweigert die Anzeige → keine Zeile
  // Börsen-Name: Registry-/Bulk-String → IMMER esc() (externer Index).
  // Ohne Namen im Union-Entry trägt die Namenszeile die gegattete Adresse.
  const name = row.exchange ? String(row.exchange) : shown;
  const domain = row.domain
    ? `<span class="exout-domain">${esc(g, row.domain)}</span>`
    : '';
  const wellKnown = row.wellKnown && typeof labels.wellKnown === 'string' && labels.wellKnown
    ? `<span class="exout-badge exout-badge-wellknown">${esc(g, labels.wellKnown)}</span>`
    : '';
  // Transit-Badge nur bei belegtem Transit-Anteil (kein leeres Badge).
  const transit = row.transitDrops > 0 && typeof labels.transit === 'function'
    ? `<span class="exout-badge exout-badge-transit" title="${esc(g, labels.transit(g.fmtXrp(row.transitDrops)))}">${esc(g, labels.transit(g.fmtXrp(row.transitDrops)))}</span>`
    : '';
  const rankTitle = rankAria ? ` title="${esc(g, rankAria)}"` : '';

  return (
    `<li class="exout-row">`
    + `<span class="exout-rank"${rankTitle}>${esc(g, String(rank))}</span>`
    + `<span class="exout-main">`
    + `<span class="exout-name">${esc(g, name)}${domain}${wellKnown}</span>`
    + `<span class="exout-addr" title="${esc(g, shown)}">${esc(g, shown)}</span>`
    + `</span>`
    + `<span class="exout-amount">${esc(g, g.fmtXrp(row.dropsSum))} XRP</span>`
    + `<span class="exout-meta">${esc(g, inflows)} · ${esc(g, clusters)}${transit}</span>`
    + `</li>`
  );
}

// esc ist Teil des injizierten Gates — lokaler Wrapper hält die Aufrufe kurz
// und hält das Modul frei von einer eigenen Escape-Logik (Host-Vertrag).
function esc(g, value) {
  return g.esc(String(value ?? ''));
}
