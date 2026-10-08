'use strict';
// public/drainer-top10.mjs — DOM-freie Aggregation "Top-10 Drainer-Konten
// nach empfangenen Mitteln" aus der BESTEHENDEN /api/flow-state-View
// (freigegebener Plan 2026-10-07). KEIN neuer api/*-Endpoint (Vercel-Hobby-
// Limit 12 Functions): die Box rechnet clientseitig aus derselben
// 60-s-Poll-Antwort wie die Börsen-Box — Budget +0 Requests / +0 Functions.
//
// MODUL-VERTRAG (Muster public/exchange-outflows.mjs / public/cluster-chips.mjs):
// DOM-frei beim Import, kein fetch, kein window/document — reine Daten-
// transformation plus Zeilen-Markup ÜBER INJIZIERTE HOST-GATES. Die Köder-
// Maske (shortAddr/displayFindingAddr/isFullShownAddr) und esc() bleiben
// Host-Sache: dieses Modul rendert nie eine rohe Adresse und nie einen
// rohen Tag-Wert (jeder String durch esc). Ohne Host-Gates liefert
// drainerTop10RowHtml '' (fail-closed). Köder-Adressen und Seeds kennt das
// Modul nicht und erbt den serverseitigen Schutz der View
// (lib/flow-state.mjs: rolesByAddress/edges ohne Köder-Endpunkte).
//
// QUALIFIZIERUNG je Kante (Kanten-Prädikat, NICHT Cluster-level):
//   (1) das ZIEL e.to trägt IM SELBEN Cluster rolesByAddress[to] === 'drainer'
//       — ausschließlich die Drainer-Rolle, NICHT severity allein (die
//       severity-Qualifikation ist bereits das Kriterium der Börsen-Box;
//       dieselbe Fragestellung hier wäre eine Kopie), NICHT collector/relay/
//       source/unknown;
//   (2) das Ziel liegt NICHT in der Börsen-Union (multiUserSnapshot) — sonst
//       stünde dasselbe Konto links als Börse und rechts als Drainer
//       (Filterentscheidung, sichtbar in totals.excludedUnionTargets und in
//       der Fußnote);
//   (3) closeTime parsebar und nowMs − windowMs <= t <= nowMs mit
//       windowMs ∈ {7 d, 30 d} (Spiegel der Retentionen lib/flow-state.mjs
//       FLOW_STATE_RETENTION_MS / FLOW_STATE_MALICIOUS_RETENTION_MS).
// Primmetrik je Drainer-Konto: SUMME e.amountDrops über die qualifizierenden
// EINGEHENDEN Kanten (e.to === addr — empfangene Beute, dasselbe Muster wie
// die inDrops-Berechnung in app.js applyFlowStateView). Ausgehende Kanten
// (e.from === addr) zählen NIE in die Primmetrik, nur als Meta outDrops
// (weitergeleitet) — analog dem Transit-Badge der Börsen-Box.
// Kanten, die (1)+(2) erfüllen, aber kein parsebares closeTime tragen,
// zählen in totals.excludedNoCloseTime (nichts wird still verworfen).
//
// EHRLICHE GRENZEN (bewusst nicht verschwiegen):
//   - Der State behält nur die 50 nach Volumen größten Kanten je Cluster
//     (maxClusterEdges, lib/ledger-walk.mjs) — totals.cappedClusters macht
//     die Kappung sichtbar, die Summen sind eine UNTergrenze.
//   - Die Rollen-/Severity-Felder des States sind je Cluster auf 300 Einträge
//     gekappt (FLOW_STATE_MEMBER_CAP, lib/flow-state.mjs capClusterFields);
//     Drainer-Rollen bleiben als Evidenz garantiert erhalten, die Grenze
//     steht statisch in der Fußnote der Box.
//   - Die Drainer-ROLLE ist eine Heuristik aus Ein-/Ausgangsgrad und
//     Geldfluss (lib/cluster.mjs roleOf), kein Schuldbeweis — der Unter-
//     titel der Box sagt das.
//   - Die tatsächliche Abdeckung ist min(Fenster, ältestes Cluster im State)
//     — coverageFrom (min firstSeen aller betrachteten Cluster) macht die
//     reale Tiefe sichtbar.

// Retention-Fenster des Flow-States (Spiegel lib/flow-state.mjs
// FLOW_STATE_RETENTION_MS / FLOW_STATE_MALICIOUS_RETENTION_MS — identisch
// zur Börsen-Box, damit beide Boxen dasselbe Fenster umschalten).
export const DROUT_WINDOW_7D_MS = 7 * 24 * 60 * 60 * 1000;   // 7 d
export const DROUT_WINDOW_30D_MS = 30 * 24 * 60 * 60 * 1000; // 30 d

// Kantendeckel des States je Cluster (Spiegel lib/ledger-walk.mjs
// maxClusterEdges und EXOUT_EDGE_CAP der Börsen-Box).
export const DROUT_EDGE_CAP = 50;

// UInt32-Obergrenze eines Destination-Tags (Spiegel lib/tag-identity.mjs
// TAG_MAX). Tag 0 ist ein ECHTER Tag ('kein Tag' ist eine eigene Identität)
// — die Validierung prüft nie auf Truthiness.
export const DROUT_TAG_MAX = 4294967295; // 2**32 - 1

// Cap der sichtbaren Tag-Chips je Zeile (Muster tagChipsHtml,
// public/cluster-chips.mjs: Cap 3 + '+'-Hinweis).
export const DROUT_TAG_CAP = 3;

// Binärer String-Vergleich (Konvention viewCmpStrBin, lib/flow-state.mjs —
// localeCompare wäre locale-abhängig und damit nicht deterministisch).
function cmpStrBin(a, b) {
  const x = String(a ?? '');
  const y = String(b ?? '');
  return x < y ? -1 : x > y ? 1 : 0;
}

// Tag-Validität (Spiegel normalizeTag, lib/tag-identity.mjs:46-60): nur
// ganzzahlige Werte 0..TAG_MAX sind Tags; defekte Werte (nicht ganzzahlig,
// negativ, außerhalb UInt32, fehlend) liefern null — NICHT 0.
function validTag(v) {
  if (typeof v !== 'number' || !Number.isInteger(v) || v < 0 || v > DROUT_TAG_MAX) return null;
  return v;
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
      excludedUnionTargets: 0,
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
      outDrops: rec.outDrops,
      clusterCount: rec.clusters.size,
      lastInflowMs: rec.lastInflowMs,
      tags: [...rec.tags].sort((a, b) => a - b), // aufsteigend (Muster tagChipsHtml)
    }))
    // Totalordnung: dropsSum desc → inEdges desc → Adresse lex. asc (binär)
    // — identisch zur Börsen-Box (finishBucket, exchange-outflows.mjs).
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
 *               rolesByAddress, edges, id, firstSeen gelesen (View-Vertrag
 *               lib/flow-state.mjs viewEdge/projectFlowStateView: Kanten mit
 *               from/to/amountDrops/closeTime/toTag).
 * exchangeMap — Map Adresse → {…} aus multiUserSnapshot() (public/exchange-
 *               registry.mjs). Nur der Membership-Test wird gebraucht; die
 *               Map steuert den Union-Ausschluss (sonst Doppelzählung mit
 *               der Börsen-Box). Keine Map → kein Ausschluss (die Box zählt
 *               dann auch Börsen-Konten — der Host ruft immer mit Union).
 * nowMs       — Referenzzeitpunkt der Fenster (Date.now() des Hosts; injiziert
 *               für deterministische Tests).
 * opts.topN   — Listenlänge (Default 10).
 *
 * Rückgabe:
 * {
 *   seven:  { windowDays: 7,  rows, totals { qualifyingEdges, qualifyingDrops,
 *             excludedNoCloseTime, excludedUnionTargets, clustersScanned,
 *             cappedClusters } },
 *   thirty: { windowDays: 30, rows, totals { … } },
 *   coverageFrom,   // ISO-String|min firstSeen aller betrachteten Cluster | null
 *   generatedAt,    // nowMs (ms)
 * }
 * 7 d UND 30 d in EINEM Durchlauf (zwei Buckets, O(Kanten)) — dasselbe
 * Muster wie aggregateExchangeOutflows.
 */
export function aggregateDrainerTop10(view, exchangeMap, nowMs, opts = {}) {
  const topN = Math.max(1, Math.floor(Number(opts && opts.topN) || 10));
  const now = Number(nowMs);
  const generatedAt = Number.isFinite(now) ? now : Date.now();
  const clusters = Array.isArray(view && view.clusters) ? view.clusters : [];
  const map = exchangeMap instanceof Map ? exchangeMap : null;

  const seven = bucketAcc(7, DROUT_WINDOW_7D_MS);
  const thirty = bucketAcc(30, DROUT_WINDOW_30D_MS);
  const all = bucketAcc(null, Infinity); // seit Start des States (keine Zeitgrenze)
  const buckets = [seven, thirty, all];
  let coverageFromMs = null;

  for (const c of clusters) {
    if (!c || typeof c !== 'object') continue;
    const edges = Array.isArray(c.edges) ? c.edges : [];
    if (!edges.length) continue; // ohne Kanten keine Fluss-Evidenz
    const clusterId = String(c.id ?? '');
    const rolesByAddress = c.rolesByAddress && typeof c.rolesByAddress === 'object'
      ? c.rolesByAddress
      : {};
    const capped = edges.length >= DROUT_EDGE_CAP;

    // Abdeckungszeitraum: min firstSeen aller betrachteten Cluster —
    // unparsebare firstSeen verlieren nie gegen parsebare.
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

      // (1) Drainer-Rolle je Kanten-Richtung im SELBEN Cluster: die Rolle
      // des Ziels qualifiziert die eingehende Kante, die Rolle der Quelle
      // die ausgehende (Meta outDrops). Severity qualifiziert hier NICHT.
      const toIsDrainer = rolesByAddress[to] === 'drainer';
      const fromIsDrainer = rolesByAddress[from] === 'drainer';
      if (!toIsDrainer && !fromIsDrainer) continue;

      // (2) Union-Ausschluss für das ZIEL der Liste: Börsen-Konten gehören
      // in die linke Box, nicht in die Drainer-Liste (sichtbar gezählt).
      if (toIsDrainer && map && map.has(to)) {
        for (const b of buckets) b.totals.excludedUnionTargets += 1;
        continue;
      }

      // (3) Fenstergrenze über closeTime. Kanten ohne parsebares closeTime
      // sind in KEINEM Fenster auswertbar → explizit gezählt statt still
      // verworfen (nur für die Primmetrik-Kanten der Fragestellung).
      const tMs = e.closeTime ? Date.parse(String(e.closeTime)) : NaN;
      if (!Number.isFinite(tMs)) {
        if (toIsDrainer) {
          for (const b of buckets) b.totals.excludedNoCloseTime += 1;
        }
        continue;
      }
      const amount = Number.isFinite(Number(e.amountDrops)) ? Number(e.amountDrops) : 0;

      for (const b of buckets) {
        if (tMs < generatedAt - b.windowMs || tMs > generatedAt) continue;

        if (toIsDrainer) {
          // Primmetrik: empfangene Beute (e.to === addr).
          b.totals.qualifyingEdges += 1;
          b.totals.qualifyingDrops += amount;
          let rec = b.byAddr.get(to);
          if (!rec) {
            rec = {
              address: to,
              dropsSum: 0,
              inEdges: 0,
              outDrops: 0,
              clusters: new Set(),
              lastInflowMs: 0,
              tags: new Set(),
            };
            b.byAddr.set(to, rec);
          }
          rec.dropsSum += amount;
          rec.inEdges += 1;
          rec.clusters.add(clusterId);
          if (tMs > rec.lastInflowMs) rec.lastInflowMs = tMs;
          // Tags sind Kantenattribute des Empängers (e.toTag); defekte
          // Werte zählen nie, Tag 0 ist ein echter Tag.
          const tag = validTag(e.toTag);
          if (tag !== null) rec.tags.add(tag);
        }

        if (fromIsDrainer) {
          // Meta: weitergeleitete Drops (e.from === addr) — NIE in der
          // Primmetrik, nur Badge bei belegtem Wert > 0. Die Zeile existiert
          // nur, wenn das Konto im Fenster auch empfangen hat (die Liste
          // rankt nach empfangenen Mitteln — ein Konto ohne Beute im Fenster
          // gehört nicht in die Rangliste).
          const rec = b.byAddr.get(from);
          if (rec) rec.outDrops += amount;
        }
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

/* Zeilen-Markup EINER Top-10-Drainer-Zeile — ausschließlich über die
 * injizierten Host-Gates (Pflicht 12: keine rohen Adressen, keine rohen
 * Tag-Werte ins DOM). Muster exchangeOutflowRowHtml: das Modul wählt und
 * bettet ein, das Host gatet.
 *
 * row  — Zeile aus aggregateDrainerTop10(...).rows
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
 *     inflows,    // function(n) -> string  — eingehende Kanten
 *     clusters,   // function(n) -> string  — Clusterzahl
 *     forwarded,  // function(xrp) -> string — Forwarded-Badge (XRP-formatiert)
 *     tagAria,    // string — Chip-Aria (NICHT 'tag.chipAria': dessen Text
 *                 // behauptet ein Börse-Hosted-Konto — für Drainer falsch)
 *   },
 * }
 *
 * Fail-closed: ohne vollständige Gates oder ohne Zeile → '' (keine Zeile).
 * Der Betrag läuft NIE als rohe Zahl mit eigener Formatierung — fmtXrp des
 * Hosts ist Pflicht; Kantenzahl/Clusterzahl über fmtNum + t()-Labels.
 */
export function drainerTop10RowHtml(row, rank, ui) {
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
  // Kein Registry-Namens-Lookup für Drainer-Konten: die Adresse erscheint
  // GENAU EINMAL (Namenszeile = gegattete Adresse + Tag-Chips). Beim Vorbild
  // exchange-outflows.mjs:276 ist die Adresszeile der Ausnahmefall ohne
  // Registry-Namen; hier wäre eine zweite Adresszeile in jeder Zeile eine
  // Duplikation desselben Werts.
  const rankTitle = rankAria ? ` title="${esc(g, rankAria)}"` : '';

  // Destination-Tag-Chips: distinct Tags aufsteigend, Cap 3 + '+'-Hinweis
  // (Muster tagChipsHtml, public/cluster-chips.mjs). Tag 0 zeigt '#0'
  // (lib/tag-identity.mjs: Tag 0 ist ein echter Tag); der Wert ist NIE
  // roher String — '#' + esc(String(tag)) durch das injizierte esc-Gate.
  const tagList = Array.isArray(row.tags) ? row.tags : [];
  const tagAria = typeof labels.tagAria === 'string' ? labels.tagAria : '';
  const tagHtml = tagList
    .slice(0, DROUT_TAG_CAP)
    .map((tg) => `<span class="tag-chip drout-tag"${tagAria ? ` role="img" aria-label="${esc(g, tagAria)}" title="${esc(g, tagAria)}"` : ''}>#${esc(g, String(tg))}</span>`)
    .join('');
  const tagMore = tagList.length > DROUT_TAG_CAP
    ? '<span class="drout-tag-more" aria-hidden="true">+</span>'
    : '';

  // Forwarded-Badge nur bei belegtem Forwarded-Anteil (kein leeres Badge).
  const forwarded = row.outDrops > 0 && typeof labels.forwarded === 'function'
    ? `<span class="drout-badge drout-badge-forwarded" title="${esc(g, labels.forwarded(g.fmtXrp(row.outDrops)))}">${esc(g, labels.forwarded(g.fmtXrp(row.outDrops)))}</span>`
    : '';

  return (
    `<li class="drout-row">`
    + `<span class="drout-rank"${rankTitle}>${esc(g, String(rank))}</span>`
    + `<span class="drout-main">`
    + `<span class="drout-name" title="${esc(g, shown)}">${esc(g, shown)}${tagHtml}${tagMore}</span>`
    + `</span>`
    + `<span class="drout-amount">${esc(g, g.fmtXrp(row.dropsSum))} XRP</span>`
    + `<span class="drout-meta">${esc(g, inflows)} · ${esc(g, clusters)}${forwarded}</span>`
    + `</li>`
  );
}

// esc ist Teil des injizierten Gates — lokaler Wrapper hält die Aufrufe kurz
// und hält das Modul frei von einer eigenen Escape-Logik (Host-Vertrag).
function esc(g, value) {
  return g.esc(String(value ?? ''));
}
