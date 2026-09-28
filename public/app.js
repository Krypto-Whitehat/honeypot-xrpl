'use strict';

/* Honeypot XRPL – Frontend (ESM-Modul)
 *
 * Hauptansicht: LIVE-BLOCK-FEED.
 *   - WebSocket auf wss://xrplcluster.com, Abo "ledger" mit transactions:true.
 *     Real gemessen (chrome-devtools, 2026-09-28): xrplcluster antwortet auf
 *     dieses Abo mit "ledgerClosed"-Events (ledger_index, ledger_time,
 *     txn_count, ledger_hash) OHNE transactions-Feld — die Spec-Annahme
 *     "Hash-Strings im Event" gilt für diesen Endpunkt nicht.
 *   - Deshalb: pro ledgerClosed wird derselbe WebSocket für EIN "ledger"-
 *     Kommando mit expand:true genutzt (verifiziert: liefert volle
 *     Tx-Objekte in result.ledger.transactions; Meta-Feld heißt dort
 *     "metaData" und wird zu {tx_json, meta} normalisiert, damit
 *     analyzeLedger es sieht). Falls ein Server trotzdem Hash-Strings
 *     liefert, greift die "tx"-Einzelauflösung (MAX_RESOLVE/PARALLEL).
 *     Unvollständig aufgelöste Ledger werden auf der Karte als "teilweise"
 *     gekennzeichnet, nie als stiller Totalausfall.
 *   - Analyse jedes Blocks mit analyzeLedger aus lib/detector.mjs —
 *     dieselbe Engine wie serverseitig (single source of truth).
 *   - Fallback: bleibt der WSS ohne Ledger-Events (in der Vercel-Sandbox
 *     nie beobachtbar), pollt der Client alle WATCHDOG_MS den verifizierten
 *     Serverpfad GET /api/ledger (JSON-RPC-Snapshot, serverseitig analysiert
 *     und sanitisiert).
 *   - Analyse-Log aller Regel-Treffer: filterbar nach Schweregrad und Regel
 *     (Regelkatalog aus ruleCatalog()), downloadbar als JSON per Blob.
 *
 * Daneben bleibt die Honeypot-Präzisionsschicht: Stats/Graph/Threats-Polling
 * (GET /api/stats, /api/graph, /api/threats) und der Selbst-Check
 * (GET /api/check/[address]).
 *
 * Anonymitätsregel: Köder (Honeypots) werden NUR als Label dargestellt.
 * Sieht ein Label trotzdem wie eine XRPL-Adresse aus, wird es defensiv durch
 * "Köder" ersetzt – Adressen von Ködern landen nie im DOM. Fund-Adressen im
 * Live-Log sind ausschließlich öffentlich im Ledger sichtbare Akteure.
 */

import { analyzeLedger, ruleCatalog } from '/lib/detector.mjs';

const POLL_MS = 5000;              // Honeypot-API-Polling (stats/graph/threats)
const WSS_URL = 'wss://xrplcluster.com';
const MAX_RESOLVE = 300;           // Tx-Budget pro Ledger (expand/Hash-Auflösung)
const LEDGER_TIMEOUT_MS = 10000;   // Timeout pro "ledger"-Kommando
const QUOTA_CALLS_PER_MIN = 14;    // sliding window: max. ledger-Kommandos/60 s
const PARALLEL = 6;                // max. parallele "tx"-Calls über den WSS
const TX_TIMEOUT_MS = 8000;        // Einzel-Timeout pro tx-Call
const FEED_CARDS = 12;             // Block-Karten im Feed
const LOG_MAX = 400;               // Log-Einträge im Speicher
const LOG_RENDER_MAX = 200;        // gerenderte Log-Zeilen
const STALL_MS = 12000;            // ohne frischen Ledger -> Snapshot-Fallback
const WATCHDOG_MS = 5000;          // Fallback-Prüfintervall
const FIRST_SEEN_MAX = 20000;      // Frische-Fenster: Konten-Obergrenze

/* ------------------------------------------------------------------ */
/* Hilfsfunktionen                                                     */
/* ------------------------------------------------------------------ */

function esc(value) {
  return String(value ?? '').replace(/[&<>"']/g, (c) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
  })[c]);
}

// XRPL-Adressmuster (Base58, beginnt mit 'r', 25–35 Zeichen)
const XRPL_ADDR_RE = /^r[1-9A-HJ-NP-Za-km-z]{24,34}$/;

// Defensiv (Defense-in-Depth): Ein Wert, der wie eine XRPL-Adresse aussieht,
// darf NIE als Köder-Bezeichnung, Evidenz-Label oder Funding-Label im DOM
// landen — der Server sanitisiert bereits, hier wird das doppelt abgesichert.
function defang(value) {
  const s = String(value ?? '');
  if (XRPL_ADDR_RE.test(s)) return 'Köder (Adresse verborgen)';
  return s;
}

// Honeypot-Knoten dürfen nie eine echte Adresse als Label/Id tragen.
function honeypotLabel(node) {
  return defang(node.label || node.id || '');
}

function fmtTime(value) {
  if (value === null || value === undefined || value === '') return '–';
  const d = new Date(typeof value === 'number' ? value : value);
  if (Number.isNaN(d.getTime())) return String(value);
  return d.toLocaleString('de-DE', { dateStyle: 'medium', timeStyle: 'medium' });
}

function fmtClock(value) {
  if (value === null || value === undefined || value === '') return '–';
  const d = new Date(typeof value === 'number' ? value : value);
  if (Number.isNaN(d.getTime())) return String(value);
  return d.toLocaleTimeString('de-DE');
}

// XRPL close_time (Sekunden seit 2000-01-01) -> ISO.
function xrplIso(closeTime, closeTimeIso) {
  if (closeTimeIso) return closeTimeIso;
  if (typeof closeTime === 'number') {
    return new Date((closeTime + 946684800) * 1000).toISOString();
  }
  return null;
}

function shortAddr(a) {
  const s = String(a ?? '');
  return s.length > 12 ? `${s.slice(0, 8)}…${s.slice(-4)}` : s;
}

async function fetchJson(path) {
  const res = await fetch(path, { cache: 'no-store' });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return res.json();
}

/* ------------------------------------------------------------------ */
/* Kopfzeilen-Stats (Honeypot-Schicht)                                 */
/* ------------------------------------------------------------------ */

function renderStats(stats) {
  document.getElementById('stat-malicious').textContent =
    Number(stats.maliciousCount ?? 0).toLocaleString('de-DE');
  document.getElementById('stat-suspect').textContent =
    Number(stats.suspectCount ?? 0).toLocaleString('de-DE');
  document.getElementById('stat-events').textContent =
    Number(stats.eventCount ?? 0).toLocaleString('de-DE');
  document.getElementById('stat-network').textContent =
    String(stats.network ?? '–');
  document.getElementById('stat-last').textContent = fmtClock(stats.lastEventTime);
}

/* ------------------------------------------------------------------ */
/* Graph (vis-network)                                                 */
/* ------------------------------------------------------------------ */

const EDGE_COLORS = {
  Payment: '#b3261e',
  TrustSet: '#b45309',
  OfferCreate: '#a16207',
  OfferCancel: '#a16207',
  AccountSet: '#1d4ed8',
  EscrowCreate: '#6d28d9',
  EscrowFinish: '#6d28d9',
  CheckCreate: '#0f766e',
  PaymentChannelCreate: '#0f766e',
  NFTokenMint: '#a21caf',
  NFTokenAcceptOffer: '#a21caf',
};
const EDGE_DEFAULT = '#62626b';

let nodesDS = null;
let edgesDS = null;
let network = null;

function initGraph() {
  if (typeof vis === 'undefined') {
    document.getElementById('graph').innerHTML =
      '<p class="graph-error">vis-network konnte nicht geladen werden (CDN nicht erreichbar).</p>';
    return false;
  }
  nodesDS = new vis.DataSet([]);
  edgesDS = new vis.DataSet([]);
  network = new vis.Network(
    document.getElementById('graph'),
    { nodes: nodesDS, edges: edgesDS },
    {
      autoResize: true,
      physics: {
        enabled: true,
        barnesHut: {
          gravitationalConstant: -4200,
          centralGravity: 0.25,
          springLength: 130,
          springConstant: 0.045,
          damping: 0.55,
        },
        stabilization: { iterations: 200 },
      },
      interaction: { hover: true, tooltipDelay: 120, zoomView: true, dragView: true },
      nodes: {
        borderWidth: 2,
        font: { color: '#141416', size: 14, face: '"JetBrains Mono", ui-monospace, Consolas, monospace' },
      },
      edges: {
        width: 2,
        smooth: { type: 'curvedCW', roundness: 0.14 },
        arrows: { to: { enabled: true, scaleFactor: 0.55 } },
      },
    }
  );
  return true;
}

function renderGraph(graph) {
  if (!network) return;

  const rawNodes = Array.isArray(graph.nodes) ? graph.nodes : [];
  const rawEdges = Array.isArray(graph.edges) ? graph.edges : [];

  // id -> Label für Kanten-Tooltips (NUR Labels, MEDIUM-5-Fix).
  const labelById = new Map(
    rawNodes.map((n) => [String(n.id), String(n.type === 'honeypot' ? honeypotLabel(n) : (n.label || n.id))])
  );

  const nextNodes = rawNodes.map((n) => {
    const isHoneypot = n.type === 'honeypot';
    const label = isHoneypot ? honeypotLabel(n) : String(n.label || n.id);
    return {
      id: String(n.id),
      label,
      // Titel-Tooltip NUR mit Labels (MEDIUM-5-Fix): Honeypot-Knoten zeigen
      // ihr Label, Angreifer-Knoten ihre (öffentliche) Adresse.
      title: label,
      shape: isHoneypot ? 'hexagon' : 'dot',
      size: isHoneypot ? 14 : 18,
      color: isHoneypot
        ? { background: '#141416', border: '#141416', highlight: { background: '#33333a', border: '#141416' } }
        : { background: '#b3261e', border: '#7f1d1d', highlight: { background: '#d03b33', border: '#7f1d1d' } },
      margin: 8,
    };
  });

  const nextEdges = rawEdges.map((e) => {
    const type = String(e.type || 'Sonstige');
    return {
      id: `${e.from}->${e.to}::${type}`,
      from: String(e.from),
      to: String(e.to),
      label: type,
      // Kanten-Tooltip nur mit Labels (MEDIUM-5-Fix).
      title: `${defang(labelById.get(String(e.from)) ?? e.from)} → ${defang(labelById.get(String(e.to)) ?? e.to)} (${type})`,
      color: { color: EDGE_COLORS[type] || EDGE_DEFAULT, highlight: '#141416', hover: '#141416' },
      font: { color: '#484850', size: 11, face: '"JetBrains Mono", ui-monospace, Consolas, monospace', strokeWidth: 0, align: 'middle' },
    };
  });

  // Inkrementell aktualisieren: bestehende Knoten/Kanten updaten, neue hinzufügen,
  // verschwundene entfernen – verhindert Flackern beim 5-Sekunden-Polling.
  nodesDS.update(nextNodes);
  const keepNodeIds = new Set(nextNodes.map((n) => n.id));
  const staleNodes = nodesDS.getIds().filter((id) => !keepNodeIds.has(id));
  if (staleNodes.length) nodesDS.remove(staleNodes);

  edgesDS.update(nextEdges);
  const keepEdgeIds = new Set(nextEdges.map((e) => e.id));
  const staleEdges = edgesDS.getIds().filter((id) => !keepEdgeIds.has(id));
  if (staleEdges.length) edgesDS.remove(staleEdges);
}

/* ------------------------------------------------------------------ */
/* Threat-Tabelle mit aufklappbarer Evidenz                            */
/* ------------------------------------------------------------------ */

const expandedAddresses = new Set(); // überlebt Neu-Renderings
let lastThreats = []; // letzte API-Liste für die clientseitige Suche

// knownBad für die Live-Engine: ausschließlich aus der API-Schiene
// (Honeypot-Evidenz + Kuratierung) — niemals als Literal im Code.
const knownBad = new Set();

function evidenceRows(evidence) {
  // Öffentliche Evidenz enthält keinen txHash mehr, nur ref/type/time/honeypot.
  const rows = (Array.isArray(evidence) ? evidence : []).map((ev) => `
      <tr>
        <td class="tx-type">${esc(ev.type ?? '–')}</td>
        <td>${esc(fmtTime(ev.time))}</td>
        <td class="ev-ref">${esc(ev.ref ?? '–')}</td>
        <td class="bait-label">${esc(defang(ev.honeypot ?? '–'))}</td>
      </tr>`).join('');
  return rows || '<tr><td colspan="4">Keine Evidenz vorhanden.</td></tr>';
}

function fundingRows(funding) {
  // Funding wird nur als Label dargestellt (der Server liefert keine Adressen);
  // defensiv wird jede adresseähnliche Angabe verschleiert (MEDIUM-4-Fix).
  const list = Array.isArray(funding) ? funding : [];
  if (!list.length) return '';
  const items = list.map((f) => {
    const labelText = defang(f.label ?? 'Funding-Quelle');
    const hiddenAddr = f.address ? ' <span class="funding-label">(Adresse nicht öffentlich)</span>' : '';
    return `<li><span class="funding-addr">${esc(labelText)}</span>${hiddenAddr}</li>`;
  });
  return `<div class="funding"><h4>Finanzierungskette</h4><ul>${items.join('')}</ul></div>`;
}

function renderThreats(threats) {
  lastThreats = Array.isArray(threats) ? threats : [];
  knownBad.clear();
  for (const t of lastThreats) {
    const a = String(t.address ?? '');
    if (XRPL_ADDR_RE.test(a)) knownBad.add(a);
  }
  applyThreatFilter();
}

function applyThreatFilter() {
  const body = document.getElementById('threat-body');
  const empty = document.getElementById('threats-empty');
  const q = (document.getElementById('threat-search').value ?? '').trim().toLowerCase();
  const list = lastThreats
    .filter((t) => t.risk === 'malicious')
    .filter((t) => !q || String(t.address ?? '').toLowerCase().includes(q) || String(t.reason ?? '').toLowerCase().includes(q));

  if (!list.length) {
    body.innerHTML = '';
    empty.hidden = false;
    return;
  }
  empty.hidden = true;

  body.innerHTML = list.map((t) => {
    const addr = String(t.address ?? '');
    const isOpen = expandedAddresses.has(addr);
    const evidenceCount = Array.isArray(t.evidence) ? t.evidence.length : 0;
    const detail = `
      <table class="evidence-table">
        <thead>
          <tr><th scope="col">Tx-Typ</th><th scope="col">Zeit</th><th scope="col">Ref</th><th scope="col">Köder</th></tr>
        </thead>
        <tbody>${evidenceRows(t.evidence)}</tbody>
      </table>
      ${fundingRows(t.funding)}`;
    return `
      <tr class="threat-row${isOpen ? ' open' : ''}" data-addr="${esc(addr)}" tabindex="0" aria-expanded="${isOpen}">
        <td class="addr">${esc(addr)}</td>
        <td>${esc(defang(t.reason ?? '–'))}</td>
        <td>${esc(fmtTime(t.firstSeen))}</td>
        <td>${evidenceCount}</td>
        <td class="col-toggle"><span class="chevron">${isOpen ? '▾' : '▸'}</span></td>
      </tr>
      <tr class="detail-row"${isOpen ? '' : ' hidden'} data-for="${esc(addr)}">
        <td colspan="5">${detail}</td>
      </tr>`;
  }).join('');
}

function toggleRow(row) {
  const addr = row.dataset.addr;
  const detail = document.querySelector(`.detail-row[data-for="${CSS.escape(addr)}"]`);
  if (!detail) return;
  const open = expandedAddresses.has(addr);
  if (open) {
    expandedAddresses.delete(addr);
    detail.hidden = true;
    row.classList.remove('open');
    row.setAttribute('aria-expanded', 'false');
    row.querySelector('.chevron').textContent = '▸';
  } else {
    expandedAddresses.add(addr);
    detail.hidden = false;
    row.classList.add('open');
    row.setAttribute('aria-expanded', 'true');
    row.querySelector('.chevron').textContent = '▾';
  }
}

function bindTable() {
  const body = document.getElementById('threat-body');
  body.addEventListener('click', (e) => {
    const row = e.target.closest('.threat-row');
    if (row) toggleRow(row);
  });
  body.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' || e.key === ' ') {
      const row = e.target.closest('.threat-row');
      if (row) { e.preventDefault(); toggleRow(row); }
    }
  });
}

/* ------------------------------------------------------------------ */
/* Selbst-Check: eigene Adresse gegen die Bedrohungsliste              */
/* ------------------------------------------------------------------ */

async function runSelfCheck(address) {
  const resultBox = document.getElementById('check-result');
  const btn = document.getElementById('check-btn');
  btn.disabled = true;
  btn.textContent = 'Prüfe …';
  resultBox.hidden = false;
  resultBox.className = 'check-result pending';
  resultBox.textContent = 'Transaktionshistorie wird auf dem Ledger geprüft …';
  try {
    const res = await fetch(`/api/check/${encodeURIComponent(address)}`, { cache: 'no-store' });
    const data = await res.json();
    if (!res.ok) {
      resultBox.className = 'check-result error';
      resultBox.textContent = (data && data.error) ? data.error : `Fehler (HTTP ${res.status}).`;
      return;
    }
    renderCheckResult(data);
  } catch (err) {
    resultBox.className = 'check-result error';
    resultBox.textContent = `Check fehlgeschlagen: ${err && err.message}`;
  } finally {
    btn.disabled = false;
    btn.textContent = 'Prüfen';
  }
}

function renderCheckResult(data) {
  const box = document.getElementById('check-result');
  const contacts = Array.isArray(data.contacts) ? data.contacts : [];
  let cls = 'clean';
  let head = '';
  if (data.verdict === 'contact') {
    cls = 'contact';
    head = contacts.length === 1
      ? '1 Kontakt zu einer bekannten Bedrohungs-Adresse gefunden:'
      : `${contacts.length} Kontakte zu bekannten Bedrohungs-Adressen gefunden:`;
  } else if (data.verdict === 'unknown') {
    cls = 'unknown';
    head = data.hint ?? 'Konto nicht gefunden.';
  } else {
    head = `Keine Kontakte zu bekannten maliziösen Adressen (geprüft: ${Number(data.checkedTxCount ?? 0).toLocaleString('de-DE')} Transaktionen${data.truncated ? ', Historie abgeschnitten' : ''}).`;
  }
  const selfNote = data.selfListed
    ? '<p class="check-self">Hinweis: Diese Adresse steht selbst auf der Bedrohungsliste.</p>'
    : '';
  const hint = data.hint && data.verdict !== 'unknown'
    ? `<p class="check-hint">${esc(data.hint)}</p>`
    : '';
  let table = '';
  if (contacts.length) {
    const rows = contacts.map((c) => `
      <tr>
        <td class="tx-type">${esc(c.txType ?? '–')}</td>
        <td>${esc(fmtTime(c.time))}</td>
        <td>${esc(c.direction ?? '–')}</td>
        <td>${esc(c.note ?? '')}</td>
        <td class="addr">${esc(c.counterparty ?? '–')}</td>
        <td><span class="risk-badge ${c.risk === 'malicious' ? 'risk-malicious' : 'risk-suspect'}">${esc(c.risk ?? '–')}</span></td>
      </tr>`).join('');
    table = `
      <table class="evidence-table">
        <thead>
          <tr><th scope="col">Tx-Typ</th><th scope="col">Zeit</th><th scope="col">Richtung</th><th scope="col">Vorgang</th><th scope="col">Gegenpartei</th><th scope="col">Risiko</th></tr>
        </thead>
        <tbody>${rows}</tbody>
      </table>`;
  }
  box.className = `check-result ${cls}`;
  box.innerHTML = `<p class="check-head">${esc(head)}</p>${selfNote}${table}${hint}`;
}

function bindSelfCheck() {
  document.getElementById('check-form').addEventListener('submit', (e) => {
    e.preventDefault();
    const addr = document.getElementById('check-address').value.trim();
    const box = document.getElementById('check-result');
    if (!XRPL_ADDR_RE.test(addr)) {
      box.hidden = false;
      box.className = 'check-result error';
      box.textContent = 'Bitte eine gültige XRPL-Adresse eingeben (beginnt mit „r", 25–35 Zeichen).';
      return;
    }
    runSelfCheck(addr);
  });
}

/* ------------------------------------------------------------------ */
/* LIVE-BLOCK-FEED: WebSocket-Engine + Snapshot-Fallback              */
/* ------------------------------------------------------------------ */

const RULE_CATALOG = ruleCatalog();
const RULE_NAME = new Map(RULE_CATALOG.map((r) => [r.id, r.name]));

const liveStats = { ledgers: 0, txs: 0, malicious: 0, suspect: 0, info: 0 };
const logEntries = [];              // {t, ledgerIndex, ruleId, severity, address, note}
const firstSeenAt = new Map();      // Konto -> Zeitstempel der ersten Sichtung (Stream-Fenster)
const seenLedgers = new Set();      // Deduplizierung WSS/Fallback
const liveFindings = { malicious: 0, suspect: 0, info: 0 };

let lastLedgerAt = 0;
let liveMode = 'init';              // 'init' | 'wss' | 'poll'
// xrplcluster drosselt JSON-Kommandos per IP-Quota (live beobachtet:
// "rate limit: units quota (10000 per 60s)"). Bei tooBusy pausiert die
// Block-Analyse sichtbar statt Karten still leer zu lassen.
let quotaCooldownUntil = 0;
const quotaWindow = [];            // Zeitstempel der ledger-Kommandos (60-s-Fenster)

function quotaBudgetOk() {
  const cutoff = Date.now() - 60000;
  while (quotaWindow.length && quotaWindow[0] < cutoff) quotaWindow.shift();
  return quotaWindow.length < QUOTA_CALLS_PER_MIN;
}

let ws = null;
let wsBackoff = 2000;
let wsAttemptTimer = null;
let reqId = 1000;
const pendingTx = new Map();        // id -> resolve-Funktion

function setConn(ok, text) {
  const dot = document.getElementById('conn-dot');
  const el = document.getElementById('conn-text');
  dot.classList.toggle('ok', ok);
  dot.classList.toggle('err', !ok);
  el.textContent = text;
}

function connLabel() {
  if (liveMode === 'wss') return 'Live – WSS verbunden';
  if (liveMode === 'poll') return 'Live – Snapshot-Fallback (WSS ohne Events)';
  return 'Live-Verbindung wird aufgebaut …';
}

function buildCtx() {
  return {
    knownBad,
    firstSeenAt,
    threats: new Map(),
    // benignIssuers/benignAccounts: die Engine bringt ihre dokumentierten
    // Gateway-Defaults mit; hier wird nichts ergänzt (keine Literale im Frontend).
  };
}

/* ---------- Frische-Fenster (ctx.firstSeenAt) ---------- */
function recordFirstSeen(entries) {
  const now = Date.now();
  for (const entry of entries) {
    const t = entry.tx_json || entry.tx || entry;
    if (!t || typeof t !== 'object') continue;
    const actors = [t.Account, t.Destination, t.LimitAmount?.issuer, t.Issuer, t.Owner];
    for (const a of actors) {
      if (typeof a === 'string' && !firstSeenAt.has(a)) {
        if (firstSeenAt.size >= FIRST_SEEN_MAX) continue; // Speicher-Obergrenze
        firstSeenAt.set(a, now);
      }
    }
  }
}

/* ---------- Block-Karten ---------- */
function addBlockCard(ledgerIndex, closeIso, txCount, state) {
  const li = document.createElement('li');
  li.className = 'block-card';
  li.innerHTML = `
    <div class="block-head">
      <span class="block-height">#${esc(ledgerIndex)}</span>
      <span class="block-time">${esc(fmtClock(closeIso))}</span>
      <span class="block-txs">${Number(txCount).toLocaleString('de-DE')} Txs</span>
    </div>
    <div class="block-badges"><span class="badge badge-analyzing">Analysiere …</span></div>`;
  const feed = document.getElementById('block-feed');
  feed.prepend(li);
  while (feed.children.length > FEED_CARDS) feed.lastElementChild.remove();
  document.getElementById('feed-empty').hidden = true;
  return li;
}

function severityBadgeHtml(counts) {
  const parts = [];
  if (counts.malicious) parts.push(`<span class="badge badge-malicious">${counts.malicious} × Maliziös</span>`);
  if (counts.suspect) parts.push(`<span class="badge badge-suspect">${counts.suspect} × Verdächtig</span>`);
  if (counts.info) parts.push(`<span class="badge badge-info">${counts.info} × Info</span>`);
  return parts.join('');
}

function finishBlockCard(card, findings, ledgerTxCount, resolvedCount) {
  const counts = { malicious: 0, suspect: 0, info: 0 };
  for (const f of findings) {
    if (counts[f.severity] != null) counts[f.severity] += 1;
  }
  const badges = [];
  const sevHtml = severityBadgeHtml(counts);
  if (sevHtml) badges.push(sevHtml);
  else badges.push('<span class="badge badge-clean">keine Funde</span>');
  if (counts.malicious) card.classList.add('has-malicious');
  else if (counts.suspect) card.classList.add('has-suspect');
  if (resolvedCount < ledgerTxCount) {
    badges.push(`<span class="badge badge-partial">${resolvedCount}/${ledgerTxCount} Txs aufgelöst</span>`);
  }
  card.querySelector('.block-badges').innerHTML = badges.join('');
}

/* ---------- Adresse im Live-Log ----------
 * Voller Akteur wird nur gezeigt, wenn die Adresse bereits öffentlich ist
 * (knownBad-Schiene /api/threats). Sonst Kurzform — identische Anonymitäts-
 * Logik wie die Kurzformen in den Engine-Notizen (lib/detector.mjs shortAddr):
 * volle Köder-Adressen landen nie im DOM, Angreifer-Kanten bleiben lesbar. */
function displayFindingAddr(address) {
  const a = String(address ?? '');
  if (!a) return '–';
  if (knownBad.has(a)) return a;
  return shortAddr(a);
}

/* ---------- Analyse-Log ---------- */
function registerFindings(findings, ledgerIndex) {
  const list = Array.isArray(findings) ? findings : [];
  for (const f of list) {
    logEntries.push({
      t: Date.now(),
      ledgerIndex,
      ruleId: String(f.ruleId ?? '–'),
      severity: String(f.severity ?? 'info'),
      address: String(f.address ?? ''),
      note: String(f.note ?? ''),
    });
    if (liveFindings[f.severity] != null) liveFindings[f.severity] += 1;
  }
  while (logEntries.length > LOG_MAX) logEntries.shift();
  renderLog();
}

function renderLog() {
  const box = document.getElementById('analysis-log');
  const empty = document.getElementById('log-empty');
  const sev = document.getElementById('log-severity').value;
  const rule = document.getElementById('log-rule').value;
  const list = logEntries
    .filter((e) => sev === 'all' || e.severity === sev)
    .filter((e) => rule === 'all' || e.ruleId === rule);

  if (!list.length) {
    box.innerHTML = '';
    empty.hidden = false;
    return;
  }
  empty.hidden = true;

  const rows = list.slice(-LOG_RENDER_MAX).reverse().map((e) => `
    <div class="log-row sev-${esc(e.severity)}">
      <span class="log-time">${esc(fmtClock(e.t))}</span>
      <span class="log-sev sev-text-${esc(e.severity)}">${esc(e.severity === 'malicious' ? 'maliziös' : e.severity === 'suspect' ? 'verdächtig' : 'info')}</span>
      <span class="log-rule">${esc(RULE_NAME.get(e.ruleId) ?? e.ruleId)}</span>
      <span class="log-addr">${esc(displayFindingAddr(e.address))}</span>
      <span class="log-note">${esc(e.note)}</span>
      <span class="log-ledger">#${esc(e.ledgerIndex)}</span>
    </div>`).join('');
  box.innerHTML = rows;
}

function buildRuleFilter() {
  const sel = document.getElementById('log-rule');
  sel.innerHTML = '<option value="all">Alle Regeln</option>' + RULE_CATALOG
    .map((r) => `<option value="${esc(r.id)}">${esc(r.name)}</option>`)
    .join('');
}

function downloadLog() {
  const payload = {
    exportedAt: new Date().toISOString(),
    source: 'Honeypot XRPL – Live-Ledger-Analyse-Log',
    network: document.getElementById('stat-network').textContent,
    note: 'Adressen in Kurzform, außer sie stehen bereits auf der öffentlichen Bedrohungsliste (knownBad). Vollständige Zuordnung über ledgerIndex auf dem öffentlichen Ledger möglich.',
    count: logEntries.length,
    entries: logEntries.map((e) => ({
      time: new Date(e.t).toISOString(),
      ledgerIndex: e.ledgerIndex,
      ruleId: e.ruleId,
      severity: e.severity,
      address: displayFindingAddr(e.address),
      note: e.note,
    })),
  };
  const blob = new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = `honeypot-xrpl-analyse-log-${new Date().toISOString().replace(/[:T]/g, '-').slice(0, 16)}.json`;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(a.href), 2000);
}

function updateLiveStats() {
  document.getElementById('live-ledgers').textContent = liveStats.ledgers.toLocaleString('de-DE');
  document.getElementById('live-txs').textContent = liveStats.txs.toLocaleString('de-DE');
  document.getElementById('live-f-malicious').textContent = liveFindings.malicious.toLocaleString('de-DE');
  document.getElementById('live-f-suspect').textContent = liveFindings.suspect.toLocaleString('de-DE');
  document.getElementById('live-f-info').textContent = liveFindings.info.toLocaleString('de-DE');
  document.getElementById('last-update').textContent =
    'Stand: ' + new Date().toLocaleTimeString('de-DE');
}

/* ---------- Volles Ledger pro Block über denselben WebSocket ---------- */
// expand:true ist live verifiziert: result.ledger.transactions enthält volle
// Tx-Objekte (flache Felder + "metaData"). Normalisierung zu {tx_json, meta}
// (lib/detector.mjs liest meta; lib/ wird nicht angetastet).
function normalizeLedgerTxEntry(e) {
  if (!e || typeof e !== 'object') return null;
  if (e.tx_json || e.tx) return e;
  if (e.TransactionType) {
    const { metaData, meta, ...txFields } = e;
    return { tx_json: txFields, meta: meta ?? metaData ?? null };
  }
  return null;
}

function wsLedgerCommand(ledgerIndex) {
  return new Promise((resolve) => {
    if (!ws || ws.readyState !== 1) { resolve(null); return; }
    const id = ++reqId;
    const settle = (result) => resolve(result);
    pendingTx.set(id, settle);
    const timer = setTimeout(() => {
      if (pendingTx.get(id) === settle) { pendingTx.delete(id); resolve(null); }
    }, LEDGER_TIMEOUT_MS);
    try {
      ws.send(JSON.stringify({ command: 'ledger', id, ledger_index: ledgerIndex, transactions: true, expand: true }));
    } catch {
      pendingTx.delete(id);
      clearTimeout(timer);
      resolve(null);
    }
  });
}

/* ---------- Hash-Auflösung über denselben WebSocket (Fallback) ---------- */
function wsTxCommand(hash) {
  return new Promise((resolve) => {
    if (!ws || ws.readyState !== 1) { resolve(null); return; }
    const id = ++reqId;
    pendingTx.set(id, resolve);
    const timer = setTimeout(() => {
      if (pendingTx.has(id)) { pendingTx.delete(id); resolve(null); }
    }, TX_TIMEOUT_MS);
    pendingTx.set(id, (result) => { clearTimeout(timer); resolve(result); });
    try {
      ws.send(JSON.stringify({ command: 'tx', id, transaction: hash }));
    } catch {
      pendingTx.delete(id);
      clearTimeout(timer);
      resolve(null);
    }
  });
}

async function resolveHashes(hashes) {
  const entries = [];
  const list = hashes.slice(0, MAX_RESOLVE);
  for (let i = 0; i < list.length; i += PARALLEL) {
    if (!ws || ws.readyState !== 1) break; // Verbindung verloren -> Rest bleibt ungelöst
    const chunk = list.slice(i, i + PARALLEL);
    const results = await Promise.all(chunk.map(wsTxCommand));
    for (const r of results) {
      // tx liefert die vollen Tx-Felder plus meta (flach oder als result.tx/result.meta).
      const norm = normalizeLedgerTxEntry(r);
      if (norm) entries.push(norm);
    }
  }
  return entries;
}

/* ---------- Ledger-Event ("ledgerClosed" bzw. "ledger" vom Abo) ---------- */
async function onLedgerEvent(msg) {
  const idx = msg.ledger_index;
  if (idx == null || seenLedgers.has(idx)) return;
  seenLedgers.add(idx);
  if (seenLedgers.size > 400) {
    const first = seenLedgers.values().next().value;
    seenLedgers.delete(first);
  }
  lastLedgerAt = Date.now();
  liveMode = 'wss';

  const eventHashes = Array.isArray(msg.transactions) ? msg.transactions : [];
  const declaredCount = Number(msg.txn_count ?? eventHashes.length ?? 0);
  const closeIso = xrplIso(msg.ledger_time ?? msg.close_time, msg.close_time_iso);
  const card = addBlockCard(idx, closeIso, declaredCount, 'analyzing');

  // Volles Ledger per expand:true holen (ein Kommando pro Block).
  let entries = [];
  let ledgerTxCount = declaredCount;
  const inCooldown = Date.now() < quotaCooldownUntil;
  const overBudget = !eventHashes.length && !inCooldown && !quotaBudgetOk();
  if (overBudget) {
    card.querySelector('.block-badges').innerHTML =
      '<span class="badge badge-partial">Quota-Budget erschöpft – Analyse übersprungen</span>';
    return;
  }
  const led = (eventHashes.length || inCooldown) ? null : await wsLedgerCommand(idx);
  if (led && !eventHashes.length) quotaWindow.push(Date.now());
  if (led?.error === 'tooBusy') {
    quotaCooldownUntil = Date.now() + 65000;
    card.querySelector('.block-badges').innerHTML =
      '<span class="badge badge-partial">Ledger-Quota erschöpft – Analyse pausiert</span>';
    return;
  }
  if (inCooldown) {
    card.querySelector('.block-badges').innerHTML =
      '<span class="badge badge-partial">Ledger-Quota erschöpft – Analyse übersprungen</span>';
    return;
  }
  const rawTxs = led?.ledger?.transactions;
  if (Array.isArray(rawTxs) && rawTxs.length) {
    ledgerTxCount = rawTxs.length;
    if (rawTxs.every((t) => typeof t === 'string')) {
      entries = await resolveHashes(rawTxs); // Hash-Strings -> tx-Einzelauflösung
    } else {
      entries = rawTxs.slice(0, MAX_RESOLVE).map(normalizeLedgerTxEntry).filter(Boolean);
    }
  } else if (eventHashes.length) {
    ledgerTxCount = eventHashes.length;
    entries = await resolveHashes(eventHashes);
  }

  recordFirstSeen(entries);
  const result = analyzeLedger({ transactions: entries }, buildCtx());

  finishBlockCard(card, result.findings, ledgerTxCount, entries.length);
  registerFindings(result.findings, idx);
  liveStats.ledgers += 1;
  liveStats.txs += ledgerTxCount;
  updateLiveStats();
  setConn(true, connLabel());
}

/* ---------- WebSocket mit Auto-Reconnect ---------- */
function connectLive() {
  if (ws && (ws.readyState === 0 || ws.readyState === 1)) return;
  try {
    ws = new WebSocket(WSS_URL);
  } catch {
    scheduleReconnect();
    return;
  }

  ws.onopen = () => {
    wsBackoff = 2000;
    try {
      ws.send(JSON.stringify({ command: 'subscribe', id: 1, streams: ['ledger'], transactions: true }));
    } catch { /* onclose behandelt es */ }
    if (liveMode !== 'poll') setConn(true, 'WSS verbunden – warte auf Ledger …');
  };

  ws.onmessage = (ev) => {
    let msg;
    try { msg = JSON.parse(ev.data); } catch { return; }
    // xrplcluster sendet "ledgerClosed" (verifiziert); "ledger" bleibt abgedeckt.
    if ((msg.type === 'ledgerClosed' || (msg.type === 'ledger' && msg.validated)) && msg.ledger_index != null) {
      onLedgerEvent(msg);
      return;
    }
    if (msg.type === 'response' && pendingTx.has(msg.id)) {
      const settle = pendingTx.get(msg.id);
      pendingTx.delete(msg.id);
      settle(msg.result ?? null);
    }
  };

  ws.onclose = () => {
    if (liveMode !== 'poll') setConn(false, `Verbindung getrennt – erneuter Versuch in ${Math.round(wsBackoff / 1000)} s`);
    scheduleReconnect();
  };

  ws.onerror = () => { /* onclose folgt unmittelbar */ };
}

function scheduleReconnect() {
  if (wsAttemptTimer) return;
  const delay = wsBackoff;
  wsBackoff = Math.min(wsBackoff * 2, 30000);
  wsAttemptTimer = setTimeout(() => {
    wsAttemptTimer = null;
    connectLive();
  }, delay);
}

/* ---------- Snapshot-Fallback (verifizierter Serverpfad /api/ledger) ---------- */
async function pollSnapshotFallback() {
  try {
    const body = await fetchJson('/api/ledger');
    const idx = body?.ledgerIndex;
    if (idx == null) return;
    if (!seenLedgers.has(idx)) {
      seenLedgers.add(idx);
      lastLedgerAt = Date.now();
      liveMode = 'poll';
      const txCount = Number(body.stats?.txs ?? 0);
      const resolved = Number(body.resolvedTxCount ?? 0);
      const findings = Array.isArray(body.findings) ? body.findings : [];
      const card = addBlockCard(idx, body.closeTime ?? null, txCount, 'done');
      finishBlockCard(card, findings, txCount, resolved);
      registerFindings(findings, idx);
      liveStats.ledgers += 1;
      liveStats.txs += txCount;
      updateLiveStats();
    }
    setConn(true, connLabel());
  } catch (err) {
    if (liveMode !== 'wss') setConn(false, `Keine Ledger-Daten erreichbar (${err && err.message})`);
  }
}

async function watchdog() {
  if (Date.now() - lastLedgerAt < STALL_MS) {
    if (liveMode === 'wss' || liveMode === 'poll') setConn(true, connLabel());
    return;
  }
  await pollSnapshotFallback();
}

function bindLive() {
  buildRuleFilter();
  document.getElementById('log-severity').addEventListener('change', renderLog);
  document.getElementById('log-rule').addEventListener('change', renderLog);
  document.getElementById('log-download').addEventListener('click', downloadLog);
}

/* ------------------------------------------------------------------ */
/* Polling (Honeypot-Präzisionsschicht)                                */
/* ------------------------------------------------------------------ */

async function poll() {
  try {
    const [stats, graph, threats] = await Promise.all([
      fetchJson('/api/stats'),
      fetchJson('/api/graph'),
      fetchJson('/api/threats'),
    ]);
    renderStats(stats);
    renderGraph(graph);
    renderThreats(threats);
  } catch {
    /* Honeypot-Schicht optional; Live-Feed arbeitet unabhängig weiter */
  }
}

/* ------------------------------------------------------------------ */
/* Start (Modulskript: DOM ist beim Ausführen bereits geparst)         */
/* ------------------------------------------------------------------ */

initGraph();
bindTable();
bindSelfCheck();
bindLive();
document.getElementById('threat-search').addEventListener('input', applyThreatFilter);
poll();
setInterval(poll, POLL_MS);
connectLive();
setInterval(watchdog, WATCHDOG_MS);
