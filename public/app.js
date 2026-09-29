'use strict';

/* Honeypot XRPL – Frontend (ESM-Modul)
 *
 * Hauptansicht: LIVE-BLOCK-FEED + AKTEUR-CLUSTERING.
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
 *   - Cluster-Schicht: rollendes Fenster der analysierten Tx-Records und
 *     Findings wird pro Ledger an buildClusterGraph()/txRecordFromEntry()
 *     aus lib/cluster.mjs übergeben (dynamischer Import mit Null-Guard;
 *     bei Import-Fehlschlag läuft der Live-Feed unverändert weiter).
 *     Graph-Panel mit Tabs "Live-Netz" (inkrementell, Echtzeit) und
 *     "Cluster" (vis-network-Clustering mit aufklappbaren Bubbles) plus
 *     Cluster-Zusammenfassungs-Karten (Rollen, Drainer→Kollektor-Kette).
 *   - Fallback: bleibt der WSS ohne Ledger-Events (in der Vercel-Sandbox
 *     nie beobachtbar), pollt der Client alle WATCHDOG_MS den verifizierten
 *     Serverpfad GET /api/ledger (JSON-RPC-Snapshot, serverseitig analysiert
 *     und sanitisiert).
 *   - Analyse-Log aller Regel-Treffer: filterbar nach Schweregrad und Regel
 *     (Regelkatalog aus ruleCatalog()), downloadbar als JSON per Blob.
 *
 * Anonymitätsregel: Köder (Honeypots) werden NUR als Label dargestellt.
 * Sieht ein Label trotzdem wie eine XRPL-Adresse aus, wird es defensiv durch
 * "Köder" ersetzt – Adressen von Ködern landen nie im DOM. Fund-Adressen im
 * Live-Log und im Graph sind ausschließlich öffentlich im Ledger sichtbare
 * Akteure und werden vollständig angezeigt, sobald die Bait-Hash-Allowlist
 * (GET /api/bait-hashes, nur SHA-256-Hashes) geladen ist und die Adresse
 * nicht auf der Deny-Liste steht; bis dahin und bei dauerhaftem Ausfall der
 * Allowlist gilt die Kurzform (fail-closed). knownBad steuert nur noch die
 * Engine-Logik (known-bad-hit), nicht mehr die Anzeige.
 */

import { analyzeLedger, ruleCatalog } from '/lib/detector.mjs';

/* Cluster-Modul: nicht-blockierender dynamischer Import. Der Live-Feed startet
 * sofort; die Cluster-Schicht aktiviert sich, sobald das Modul eintrifft
 * (Guard in onLedgerEvent). Ein Top-Level-Await würde initGraph()/connectLive()
 * um die Import-Latenz verzögern und ist bewusst nicht verwendet. */
let buildClusterGraph = null;
let txRecordFromEntry = null;
let flowPathsFn = null;
import('/lib/cluster.mjs')
  .then((m) => {
    buildClusterGraph = typeof m.buildClusterGraph === 'function' ? m.buildClusterGraph : null;
    txRecordFromEntry = typeof m.txRecordFromEntry === 'function' ? m.txRecordFromEntry : null;
    flowPathsFn = typeof m.flowPaths === 'function' ? m.flowPaths : null;
  })
  .catch(() => { /* Cluster-Funktion offline (z. B. 404); Live-Feed läuft weiter */ });

/* Drilldown-Modul (Cluster-Detailmodal): ebenfalls nicht-blockierender
 * dynamischer Import. app.js gibt dem Modul den aktuellen Cluster-Graphen
 * über ein Kontext-Objekt frei; ohne Modul bleiben Karten-/Bubble-Klicks
 * wirkungslos, der Live-Feed läuft unverändert. */
let drilldown = null;
import('./drilldown.js')
  .then((m) => {
    if (m && typeof m.initClusterDrilldown === 'function') {
      drilldown = m.initClusterDrilldown({
        getClusterGraph: () => lastClusterGraph,
        isFullShownAddr,
        displayAddr: displayFindingAddr,
        isDeniedAddr,
        shortAddr,
        esc,
        fmtXrp,
        fmtClock,
        roleColors: ROLE_COLORS,
        edgeColors: EDGE_COLORS,
        edgeDefault: EDGE_DEFAULT,
        roleLabels: ROLE_LABEL,
        physicsCluster: PHYSICS_CLUSTER,
        addrActionsHtml,
        flowPaths: () => flowPathsFn,
      });
    }
  })
  .catch(() => { /* Drilldown offline (z. B. 404); Karten-Klick bleibt ohne Wirkung */ });

/* Weltkugel, Historie und Konto-Check: dynamische Imports nach demselben
 * Muster — nicht-blockierend, mit Null-Guard (.catch). Bei 404/Fehler läuft
 * der Live-Betrieb unverändert weiter; die Module sind reine Konsumenten des
 * Host-ctx. Adressen erreichen sie ausschließlich über displayAddr /
 * isFullShownAddr / isDeniedAddr (Köder-Gates bleiben im Host) — die Module
 * rendern und melden NIE selbst roh. */
let globeMod = null;
let historyMod = null;
let checkMod = null;
import('./globe.js')
  .then((m) => {
    if (m && typeof m.initGlobe === 'function') {
      globeMod = m.initGlobe({
        getClusterGraph: () => lastClusterGraph,
        displayAddr: displayFindingAddr,
        isDeniedAddr,
        hashOf,
        shortAddr,
        esc,
        roleColors: ROLE_COLORS,
        edgeColors: EDGE_COLORS,
        edgeDefault: EDGE_DEFAULT,
        openCluster: openClusterModal,
      });
      // Trifft das Modul erst nach dem Tab-Wechsel ein, wird die Aktivierung
      // nachgezogen (activate() ist idempotent: lazy Konstruktion bzw. resume).
      if (activeGraphTab === 'globe') globeMod.activate();
    }
  })
  .catch(() => { /* Weltkugel offline (z. B. 404); Live-/Cluster-Tabs laufen weiter */ });
import('./history.js')
  .then((m) => {
    if (m && typeof m.initHistory === 'function') {
      historyMod = m.initHistory({
        displayAddr: displayFindingAddr,
        isFullShownAddr,
        isDeniedAddr,
        shortAddr,
        esc,
        fmtXrp,
        fmtClock,
        addrActionsHtml,
        ruleNames: RULE_NAME,
      });
      // Sichtbarkeit nachziehen, falls der View schon aktiv ist, bevor das
      // Modul eintrifft (sonst startet der Lade-Timer erst beim nächsten Wechsel).
      historyMod.setView(activeView === 'history');
    }
  })
  .catch(() => { /* Historie offline (z. B. 404); Melden/Anzeige entfallen still */ });
import('./account-check.js')
  .then((m) => {
    if (m && typeof m.initAccountCheck === 'function') {
      checkMod = m.initAccountCheck({
        displayAddr: displayFindingAddr,
        isFullShownAddr,
        shortAddr,
        esc,
        fmtXrp,
        fmtClock,
        addrActionsHtml,
        roleLabels: ROLE_LABEL,
        roleColors: ROLE_COLORS,
        ruleNames: RULE_NAME,
      });
      checkMod.setView(activeView === 'check');
    }
  })
  .catch(() => { /* Konto-Check offline (z. B. 404); View bleibt leer */ });

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
const TX_WINDOW_CAP = 4000;        // rollendes Tx-Fenster für das Clustering
const FINDINGS_WINDOW_CAP = 1000;  // rollendes Finding-Fenster für das Clustering
const CLUSTER_MAX_EDGES = 1200;    // Kantendeckel pro Clustering-Durchlauf

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

// Drops -> XRP (de-DE, max. 2 Nachkommastellen).
function fmtXrp(drops) {
  const n = Number(drops ?? 0) / 1e6;
  return n.toLocaleString('de-DE', { maximumFractionDigits: 2 });
}

async function fetchJson(path) {
  const res = await fetch(path, { cache: 'no-store' });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return res.json();
}

// knownBad für die Live-Engine: ausschließlich aus Live-Funden mit
// severity 'malicious' (Guard in onLedgerEvent) — niemals als Literal im Code.
// Kein clear(): monoton wachsend pro Session.
const knownBad = new Set();

/* ------------------------------------------------------------------ */
/* Bait-Hash-Allowlist: GET /api/bait-hashes (Deny-Liste, nur Hashes)  */
/* ------------------------------------------------------------------ */
/* Der Client erfährt die Klartext-Adressen der Köder nie — er erhält nur
 * deren SHA-256-Hashes (hex, Kleinbuchstaben). Eine Adresse wird nur dann
 * vollständig angezeigt, wenn die Allowlist geladen ist und ihr Hash nicht
 * auf der Deny-Liste steht; sonst Kurzform (fail-closed). Nach drei
 * Fehlschlägen bleibt die Vollanzeige dauerhaft aus.
 * Hash-Normalisierung identisch zur Serverseite: UTF-8 der rohen, nur
 * getrimmten Adresse, hex klein. */
const BAIT_HASH_ENDPOINT = '/api/bait-hashes';
const BAIT_HASH_REFETCH_MS = 60000;      // Server rotiert lokal alle 5 s; 60 s genügen
const BAIT_HASH_MIN_SPACING_MS = 15000;  // Mindestabstand zwischen Refetches
const BAIT_HASH_MAX_FAILS = 3;           // danach: Vollanzeige dauerhaft aus
const BAIT_PENDING_MAX = 2000;           // Obergrenze gepufferter knownBad-Kandidaten

const baitHashDeny = new Set();   // sha256-hex (klein) der Bait-Union
const addrHashCache = new Map();  // Adresse -> sha256-hex (synchrone Deny-Prüfung)
const pendingCandidates = [];     // knownBad-Kandidaten vor dem Deny-Load
let denyLoaded = false;
let denyFailCount = 0;
let denyPermanentlyFailed = false;
let fullDisplay = false;          // denyLoaded && !denyPermanentlyFailed
let lastDenyFetchAt = 0;

async function sha256Hex(value) {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(String(value)));
  let hex = '';
  for (const b of new Uint8Array(digest)) hex += b.toString(16).padStart(2, '0');
  return hex;
}

async function hashOf(addr) {
  const a = String(addr ?? '').trim();
  if (!a) return '';
  const cached = addrHashCache.get(a);
  if (cached) return cached;
  const hex = await sha256Hex(a);
  addrHashCache.set(a, hex);
  return hex;
}

// Synchrone Deny-Prüfung: nur gehashte Adressen können getroffen werden.
function isDeniedAddr(addr) {
  const h = addrHashCache.get(String(addr ?? '').trim());
  return h !== undefined && baitHashDeny.has(h);
}

// Asynchrone Deny-Prüfung für frische Adressen (füllt den Hash-Cache):
// clientseitiges Pendant zur baitLabels-Filterung der Serverpfade
// (server/index.mjs /api/ledger, api/ledger.js) — der Client kennt nur
// Hashes, nie Klartext-Köder-Adressen.
async function isDeniedAddrAsync(addr) {
  const a = String(addr ?? '').trim();
  if (!a) return false;
  return baitHashDeny.has(await hashOf(a));
}

// Tx-Record mit Köder-Endpunkt? (account ODER destination — dieselbe Regel
// wie server/index.mjs /api/ledger und api/ledger.js, nur hash-gestützt.)
async function recordTouchesBait(rec) {
  if (!rec || typeof rec !== 'object') return false;
  if (rec.account && (await isDeniedAddrAsync(rec.account))) return true;
  if (rec.destination && (await isDeniedAddrAsync(rec.destination))) return true;
  return false;
}

// Volle Anzeige nur bei geladener Allowlist, gehashter Adresse und
// Nicht-Treffer auf der Deny-Liste — sonst Kurzform (fail-closed).
function isFullShownAddr(addr) {
  const a = String(addr ?? '').trim();
  if (!a || !fullDisplay) return false;
  const h = addrHashCache.get(a);
  return h !== undefined && !baitHashDeny.has(h);
}

async function rebuildDisplayAndKnownBad() {
  fullDisplay = denyLoaded && !denyPermanentlyFailed;
  // knownBad nach jedem Deny-Load neu bewerten: Hash-Treffer entfernen, damit
  // known-bad-hit (Engine) nie eine Köder-Adresse trifft.
  for (const a of [...knownBad]) {
    if (baitHashDeny.has(await hashOf(a))) knownBad.delete(a);
  }
  // Vor dem Load gepufferte Kandidaten nachbewerten.
  const buffered = pendingCandidates.splice(0, pendingCandidates.length);
  for (const a of buffered) {
    if (!baitHashDeny.has(await hashOf(a))) knownBad.add(a);
  }
}

async function refetchBaitHashes(force) {
  if (denyPermanentlyFailed) return;
  const now = Date.now();
  if (!force && lastDenyFetchAt && now - lastDenyFetchAt < BAIT_HASH_MIN_SPACING_MS) return;
  lastDenyFetchAt = now;
  try {
    const body = await fetchJson(BAIT_HASH_ENDPOINT);
    const raw = Array.isArray(body?.hashes) ? body.hashes : null;
    if (!raw) throw new Error('Antwort ohne hashes-Feld');
    const next = new Set();
    for (const h of raw) {
      const s = String(h ?? '').trim().toLowerCase();
      if (s) next.add(s);
    }
    baitHashDeny.clear();
    for (const h of next) baitHashDeny.add(h);
    denyLoaded = true;
    denyFailCount = 0;
    await rebuildDisplayAndKnownBad();
  } catch (err) {
    denyFailCount += 1;
    if (denyFailCount >= BAIT_HASH_MAX_FAILS) {
      denyPermanentlyFailed = true;
      denyLoaded = false;
      fullDisplay = false;
      console.warn('Bait-Hash-Allowlist nicht erreichbar – Vollanzeige dauerhaft deaktiviert (fail-closed).', err);
      // Gepufferte Kandidaten dürfen in knownBad (known-bad-hit der Engine
      // bleibt im WSS-Pfad funktionsfähig); die Anzeige bleibt Kurzform.
      for (const a of pendingCandidates) knownBad.add(a);
      pendingCandidates.length = 0;
    } else {
      console.warn(`Bait-Hash-Allowlist: Versuch ${denyFailCount} fehlgeschlagen (${err && err.message})`);
    }
  }
}

// knownBad-Füller nur über dieses Gate: vor dem Deny-Load puffern (RACE-GATE),
// danach erst nach Hash-Prüfung hinzufügen — Köder-Adressen nie in knownBad.
async function offerKnownBadCandidate(address) {
  const a = String(address ?? '');
  if (!XRPL_ADDR_RE.test(a)) return;
  if (!denyLoaded) {
    if (pendingCandidates.length < BAIT_PENDING_MAX && !pendingCandidates.includes(a)) pendingCandidates.push(a);
    return;
  }
  if (baitHashDeny.has(await hashOf(a))) return;
  knownBad.add(a);
}

// Hashes aller Anzeigeadressen vor dem Rendern vorhalten, damit
// displayFindingAddr synchron und fail-closed entscheiden kann.
async function primeAddrHashes(cg, findings) {
  const targets = new Set();
  for (const n of cg?.nodes ?? []) {
    const a = String(n.id ?? '').trim();
    if (a && !addrHashCache.has(a)) targets.add(a);
  }
  for (const e of cg?.edges ?? []) {
    for (const a of [String(e.from ?? '').trim(), String(e.to ?? '').trim()]) {
      if (a && !addrHashCache.has(a)) targets.add(a);
    }
  }
  for (const f of findings ?? []) {
    const a = String(f.address ?? '').trim();
    if (a && !addrHashCache.has(a)) targets.add(a);
  }
  const list = [...targets].slice(0, 4000);
  if (list.length) await Promise.all(list.map((a) => hashOf(a)));
}

/* ------------------------------------------------------------------ */
/* Adresse: Kopieren + xrplcharts-Link (nur bei voller Anzeige)        */
/* ------------------------------------------------------------------ */
function addrActionsHtml(address) {
  const a = String(address ?? '');
  const href = `https://xrplcharts.com/accounts/${encodeURIComponent(a)}`;
  return (
    `<span class="addr-actions">` +
    `<button type="button" class="addr-copy" data-addr="${esc(a)}" aria-label="Adresse kopieren">Kopieren</button>` +
    `<a class="addr-link" href="${esc(href)}" target="_blank" rel="noopener noreferrer" aria-label="Auf xrplcharts.com öffnen" title="Auf xrplcharts.com öffnen">↗</a>` +
    `</span>`
  );
}

async function copyAddress(addr) {
  const a = String(addr ?? '');
  if (!a) return false;
  try {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      await navigator.clipboard.writeText(a);
      return true;
    }
  } catch { /* Fallback unten */ }
  try {
    const ta = document.createElement('textarea');
    ta.value = a;
    ta.setAttribute('readonly', '');
    ta.style.position = 'fixed';
    ta.style.left = '-9999px';
    document.body.appendChild(ta);
    ta.select();
    const ok = document.execCommand('copy');
    ta.remove();
    return Boolean(ok);
  } catch {
    return false;
  }
}

function bindAddrActions() {
  document.addEventListener('click', async (e) => {
    const btn = e.target.closest('.addr-copy');
    if (!btn) return;
    const ok = await copyAddress(btn.dataset.addr);
    btn.textContent = ok ? 'Kopiert' : 'Fehler';
    btn.setAttribute('aria-live', 'polite');
    setTimeout(() => { btn.textContent = 'Kopieren'; }, 2000);
  });
}

/* ------------------------------------------------------------------ */
/* Graph (vis-network 10.1.2)                                          */
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

// Rollen-Farbcodierung (Design-Vorgabe Astra 6): weiße/tonale Fläche,
// 1px abgedunkelter Tintenrand je Rolle.
const ROLE_COLORS = {
  source: {
    background: '#1d4ed8', border: '#1e3a8a',
    highlight: { background: '#3b63d9', border: '#1e3a8a' },
    hover: { background: '#3b63d9', border: '#1e3a8a' },
  },
  drainer: {
    background: '#b3261e', border: '#7f1d1d',
    highlight: { background: '#d03b33', border: '#7f1d1d' },
    hover: { background: '#d03b33', border: '#7f1d1d' },
  },
  collector: {
    background: '#9a5b00', border: '#713f12',
    highlight: { background: '#b8760f', border: '#713f12' },
    hover: { background: '#b8760f', border: '#713f12' },
  },
  relay: {
    background: '#62626b', border: '#3f3f46',
    highlight: { background: '#7d7d86', border: '#3f3f46' },
    hover: { background: '#7d7d86', border: '#3f3f46' },
  },
  unknown: {
    background: '#f0f0f2', border: '#62626b',
    highlight: { background: '#e2e2e6', border: '#3f3f46' },
    hover: { background: '#e2e2e6', border: '#3f3f46' },
  },
};

// Cluster-Bubble: weiße Füllung, 1px Tintenrand, Radius 12 (Astra 6).
const CLUSTER_NODE_PROPERTIES = {
  shape: 'box',
  size: 25,
  margin: 12,
  borderWidth: 1,
  borderWidthSelected: 2,
  color: {
    background: '#ffffff',
    border: '#17171b',
    highlight: { background: '#f6f6f7', border: '#141416' },
    hover: { background: '#f6f6f7', border: '#141416' },
  },
  font: { color: '#141416', size: 13, face: '"JetBrains Mono", ui-monospace, Consolas, monospace', multi: false },
  shapeProperties: { borderRadius: 12, borderDashes: false },
};

const PHYSICS_LIVE = {
  enabled: true,
  barnesHut: {
    gravitationalConstant: -4200,
    centralGravity: 0.25,
    springLength: 130,
    springConstant: 0.045,
    damping: 0.55,
  },
  stabilization: { iterations: 200 },
};
const PHYSICS_CLUSTER = {
  enabled: true,
  barnesHut: {
    gravitationalConstant: -6500,
    centralGravity: 0.2,
    springLength: 170,
    springConstant: 0.04,
    damping: 0.6,
  },
  stabilization: { iterations: 300 },
};

let nodesDS = null;
let edgesDS = null;
let network = null;
let activeGraphTab = 'live';       // 'live' | 'cluster' | 'globe'
let lastClusterGraph = null;       // Cache für Tab-Wechsel ohne Neuberechnung
const clusterByVisId = new Map();  // vis-Clusterknoten-Id -> Cluster-Objekt

// Guard um clustering.isCluster: nach openCluster kann ein Clusterknoten im
// DataSet stehen bleiben, während er aus body.nodes gelöscht wurde –
// isCluster würde dann nur eine Console-Fehlermeldung ausgeben.
function isClusterNode(id) {
  if (!network || void 0 === network.body.nodes[id]) return false;
  return network.clustering.isCluster(id);
}

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
      physics: PHYSICS_LIVE,
      interaction: { hover: true, tooltipDelay: 120, zoomView: true, dragView: true, hoverConnectedEdges: true, selectConnectedEdges: false },
      nodes: {
        shape: 'dot',
        borderWidth: 1,
        borderWidthSelected: 2,
        font: { color: '#141416', size: 13, face: '"JetBrains Mono", ui-monospace, Consolas, monospace' },
        color: {
          background: '#ffffff',
          border: '#17171b',
          highlight: { background: '#f6f6f7', border: '#141416' },
          hover: { background: '#f6f6f7', border: '#141416' },
        },
      },
      edges: {
        width: 1,
        smooth: { type: 'curvedCW', roundness: 0.14 },
        arrows: { to: { enabled: true, scaleFactor: 0.5 } },
        color: { color: '#62626b', highlight: '#141416', hover: '#141416' },
      },
    }
  );
  // Klick auf eine Cluster-Bubble öffnet das Drilldown-Modal für genau diesen
  // Cluster. BUBBLE-GUARD: network.on('click') feuert auf JEDEM Knoten —
  // Roh-Adressknoten im Live-Tab bleiben No-op (sonst bricht der Live-Tab).
  network.on('click', ({ nodes }) => {
    if (!nodes || !nodes.length) return;
    const visId = nodes[0];
    if (!isClusterNode(visId)) return;
    const c = clusterByVisId.get(visId);
    if (!c) return;
    openClusterModal(c.id);
  });
  return true;
}

/* Rohkanten/-knoten inkrementell aktualisieren (Muster aus dem bisherigen
 * renderGraph): updaten, hinzufügen, verschwundene entfernen – kein Flackern
 * bei den ~4-Sekunden-Ledger-Ereignissen. Läuft immer im Rohzustand
 * (vor dem Clustering bzw. im Live-Tab). */
function updateRawGraph(cg) {
  if (!network) return;
  const rawNodes = Array.isArray(cg.nodes) ? cg.nodes : [];
  const rawEdges = Array.isArray(cg.edges) ? cg.edges : [];

  const nextNodes = rawNodes.map((n) => {
    const role = ROLE_COLORS[n.role] ? n.role : 'unknown';
    // Knotenlabel IMMER Kurzform: vis-network zeichnet Canvas-Label ohne
    // Umbruch/maxWidth — die volle Adresse klebte am Graph-Rand (Design-Fix).
    // Die volle Anzeige bleibt im title-Tooltip (displayFindingAddr-Politik).
    const label = shortAddr(n.id);
    return {
      id: String(n.id),
      label,
      title: `${displayFindingAddr(n.id)} (${ROLE_LABEL[role]})`,
      shape: 'dot',
      size: 16,
      color: ROLE_COLORS[role],
      clusterId: n.clusterId ?? null, // Grundlage der Clustering-joinCondition
      severity: String(n.severity ?? 'info'),
      margin: 8,
    };
  });

  const nextEdges = rawEdges.map((e) => {
    const type = String(e.type || 'Sonstige');
    return {
      id: String(e.txHash || `${e.from}->${e.to}::${type}`),
      from: String(e.from),
      to: String(e.to),
      label: type,
      // Kanten-Tooltip: volle Adressen bei geladener Allowlist und Nicht-Treffer
      // auf der Deny-Liste, sonst Kurzform (displayFindingAddr, fail-closed).
      title: `${displayFindingAddr(e.from)} → ${displayFindingAddr(e.to)} (${type})`,
      color: { color: EDGE_COLORS[type] || EDGE_DEFAULT, highlight: '#141416', hover: '#141416' },
      font: { color: '#484850', size: 12, face: '"JetBrains Mono", ui-monospace, Consolas, monospace', strokeWidth: 0, align: 'middle' },
    };
  });

  nodesDS.update(nextNodes);
  const keepNodeIds = new Set(nextNodes.map((n) => n.id));
  const staleNodes = nodesDS.getIds().filter((id) => !keepNodeIds.has(id) && !isClusterNode(id));
  if (staleNodes.length) nodesDS.remove(staleNodes);

  edgesDS.update(nextEdges);
  const keepEdgeIds = new Set(nextEdges.map((e) => e.id));
  const staleEdges = edgesDS.getIds().filter((id) => !keepEdgeIds.has(id));
  if (staleEdges.length) edgesDS.remove(staleEdges);
}

function clusterBubbleLabel(c) {
  const members = Array.isArray(c.memberAddresses) ? c.memberAddresses.length : 0;
  return `${c.label ?? 'Cluster'}\n${members} Mitglieder · ${fmtXrp(c.totalDrops)} XRP`;
}

function clusterBubbleTitle(c) {
  const members = (Array.isArray(c.memberAddresses) ? c.memberAddresses : [])
    .slice(0, 8)
    .map(displayFindingAddr)
    .join(', ');
  return `${c.label ?? 'Cluster'}: ${members}`;
}

/* Cluster-Tab: alle Bubbles schließen (Rohzustand), Rohdaten aktualisieren,
 * dann je Cluster ein Clustering-Durchlauf mit joinCondition auf der vom
 * Cluster-Graph gesetzten nodeOptions.clusterId. Verwendete API (am gepinnten
 * vis-network@10.1.2-Bundle verifiziert): clustering.cluster({joinCondition,
 * clusterNodeProperties}), clustering.updateClusteredNode, clustering.openCluster,
 * clustering.isCluster. Nicht verwendet (Bundle-Grep 0 Treffer):
 * clusterByConnectionStrength, addCluster, updateCluster. */
function applyClustering(cg) {
  if (!network) return;
  openAllClusters();
  updateRawGraph(cg);
  clusterByVisId.clear();

  for (const c of cg.clusters ?? []) {
    network.clustering.cluster({
      joinCondition: (nodeOptions) => nodeOptions.clusterId === c.id,
      clusterNodeProperties: {
        ...CLUSTER_NODE_PROPERTIES,
        id: c.id, // Bundle verifiziert: clusterNodeProperties.id wird übernommen
        label: clusterBubbleLabel(c),
        title: clusterBubbleTitle(c),
      },
    });
    if (isClusterNode(c.id)) {
      clusterByVisId.set(c.id, c);
      network.clustering.updateClusteredNode(c.id, { label: clusterBubbleLabel(c) });
    }
  }

  // Cluster-zu-Cluster-Kanten dezent: 1px, gestrichelt, neutrale Töne.
  for (const e of edgesDS.get()) {
    if (isClusterNode(e.from) && isClusterNode(e.to)) {
      edgesDS.update({
        id: e.id,
        width: 1,
        dashes: [6, 4],
        color: { color: '#62626b', highlight: '#141416', hover: '#141416' },
      });
    }
  }

  network.setOptions({ physics: PHYSICS_CLUSTER });
}

// Klick-Routing: Karten und Bubbles öffnen das Drilldown-Modal (cluster.id-
// zentriert — das Modal re-looked selbst bei jedem Daten-Update). Die bisherige
// vis-Bubble-Öffnung (openClusterNode) wird dadurch ersetzt; openAllClusters
// bleibt für den Tab-Wechsel unangetastet.
function openClusterModal(clusterId) {
  if (drilldown && typeof drilldown.openCluster === 'function') {
    drilldown.openCluster(String(clusterId));
  }
}

function openAllClusters() {
  if (!network) return;
  for (const visId of [...clusterByVisId.keys()]) {
    if (isClusterNode(visId)) network.clustering.openCluster(visId, {});
  }
  clusterByVisId.clear();
  // Sicherheitsnetz für Clusterknoten, die nicht mehr in der Map stehen.
  for (const id of nodesDS.getIds()) {
    if (String(id).startsWith('cluster:') && isClusterNode(id)) {
      network.clustering.openCluster(id, {});
    }
  }
}

function renderLiveGraph(cg) {
  if (!network || !cg) return;
  if (activeGraphTab === 'cluster') {
    applyClustering(cg);
    return;
  }
  updateRawGraph(cg);
}

function setGraphTab(tab) {
  // GUARD NUR NOCH GEGEN DOPPELKLICK: Der frühere kombinierte Guard
  // (!network || …) blockierte bei vis-network-CDN-Ausfall (network===null,
  // initGraph-Fail-Pfad) auch den Weltkugel-Tab — obwohl die Kugel gerade
  // dann ohne vis läuft. Die network-Abfrage steht jetzt ausschließlich in
  // den live/cluster-Zweigen.
  if (tab === activeGraphTab) return;
  activeGraphTab = tab;
  document.getElementById('tab-live').setAttribute('aria-selected', String(tab === 'live'));
  document.getElementById('tab-cluster').setAttribute('aria-selected', String(tab === 'cluster'));
  document.getElementById('tab-globe').setAttribute('aria-selected', String(tab === 'globe'));
  const globeEl = document.getElementById('globe');
  const graphEl = document.getElementById('graph');
  const listEl = document.getElementById('cluster-list');
  const emptyEl = document.getElementById('cluster-empty');
  const hasClusters = Boolean(lastClusterGraph && Array.isArray(lastClusterGraph.clusters) && lastClusterGraph.clusters.length);
  if (tab === 'globe') {
    // GEGENSEITIGE SICHTBARKEIT der Bühnen: Kugel an, Canvas aus — sonst
    // würden zwei Bühnen gleichzeitig rendern. Der globe-Zweig läuft ohne
    // vis-network; activate() konstruiert lazy beim ersten Aufruf.
    globeEl.hidden = false;
    graphEl.hidden = true;
    listEl.hidden = true;
    emptyEl.hidden = true;
    if (globeMod && typeof globeMod.activate === 'function') globeMod.activate();
    return;
  }
  // Rückwechsel auf die vis-Bühne: Kugel pausieren (Loop stoppen), Canvas
  // zeigen und deterministisch resizen — im hiddenen Container hatte
  // vis-network Größe 0; autoResize erholt sich, der explizite resize()
  // macht die Wiederherstellung sofort reproduzierbar.
  globeEl.hidden = true;
  if (globeMod && typeof globeMod.deactivate === 'function') globeMod.deactivate();
  graphEl.hidden = false;
  if (!network) return; // vis offline: Bühnenwechsel genügt, Fehlermeldung bleibt sichtbar
  requestAnimationFrame(() => { try { network.resize(); } catch { /* egal */ } });
  if (tab === 'cluster') {
    listEl.hidden = !hasClusters;
    emptyEl.hidden = hasClusters;
    if (lastClusterGraph) applyClustering(lastClusterGraph);
  } else {
    listEl.hidden = true;
    emptyEl.hidden = true;
    openAllClusters();
    network.setOptions({ physics: PHYSICS_LIVE });
    if (lastClusterGraph) updateRawGraph(lastClusterGraph);
  }
}

/* ---------------- Cluster-Zusammenfassungs-Karten ---------------- */

const SEV_RANK = { info: 0, suspect: 1, malicious: 2 };
const ROLE_ORDER = ['drainer', 'collector', 'relay', 'source', 'unknown']; // Dominanz wie Rollenkonflikt
const ROLE_LABEL = { source: 'Source', drainer: 'Drainer', collector: 'Kollektor', relay: 'Relay', unknown: 'Unknown' };

// Flusskette als Markup: Pfade aus flowPaths (lib/cluster.mjs) werden entlang
// EBENER KANTEN mit '→' verbunden; mehrere Pfade trennt ein '·'. Volle
// Adresse + Kopier-Button + xrplcharts-Link nur bei erlaubter Vollanzeige
// (Allowlist geladen, kein Deny-Treffer); sonst Kurzform ohne beides.
function flowChainHtml(paths, opts = {}) {
  const maxChips = Number.isFinite(opts.maxChips) ? Math.max(2, Math.floor(opts.maxChips)) : 10;
  const chip = (x) => {
    const address = String(x?.id ?? '');
    const shown = displayFindingAddr(address);
    const actions = isFullShownAddr(address) ? addrActionsHtml(address) : '';
    // title trägt NUR den Anzeigewert (gerenderter displayFindingAddr-Wert),
    // nie die Roheadresse (Design-Fix, Muster drilldown.js-Konten-Tabelle).
    return `<span class="chain-node chain-${esc(x?.role ?? 'unknown')}" title="${esc(shown)}">${esc(shown)}${actions}</span>`;
  };
  const parts = [];
  let used = 0;
  for (const p of Array.isArray(paths) ? paths : []) {
    if (!Array.isArray(p) || p.length < 2 || used + p.length > maxChips) continue;
    parts.push(p.map(chip).join('<span class="chain-arrow" aria-hidden="true">→</span>'));
    used += p.length;
  }
  if (!parts.length) return '';
  return parts.join('<span class="chain-path-sep" aria-hidden="true">·</span>');
}

function clusterCardHtml(c, index) {
  // Cluster-Schweregrad = max der Mitglieder-Schweregrade aus dem Knoten-Cache.
  const sevByAddr = new Map();
  if (lastClusterGraph && Array.isArray(lastClusterGraph.nodes)) {
    for (const n of lastClusterGraph.nodes) sevByAddr.set(String(n.id), String(n.severity ?? 'info'));
  }
  let sev = 'info';
  for (const a of c.memberAddresses ?? []) {
    const s = sevByAddr.get(String(a)) ?? 'info';
    if ((SEV_RANK[s] ?? 0) > (SEV_RANK[sev] ?? 0)) sev = s;
  }

  const roleCounts = new Map();
  for (const role of Object.values(c.roles ?? {})) {
    roleCounts.set(role, (roleCounts.get(role) ?? 0) + 1);
  }
  let dominant = 'unknown';
  for (const r of ROLE_ORDER) {
    if (roleCounts.get(r)) { dominant = r; break; }
  }

  const chips = ['source', 'drainer', 'collector', 'relay', 'unknown']
    .filter((r) => roleCounts.get(r))
    .map((r) => `<span class="role-chip role-${r}"><span class="swatch swatch-${r}"></span>${roleCounts.get(r)} × ${ROLE_LABEL[r]}</span>`)
    .join('');

  // Severity-Chip nur bei malicious/suspect; 'info' wird unterdrückt.
  const badge = sev === 'malicious' || sev === 'suspect'
    ? `<span class="risk-badge risk-${esc(sev)}">${sev === 'malicious' ? 'maliziös' : 'verdächtig'}</span>`
    : '';

  // Flusskette: echte Start-bis-Ende-Pfade aus den Cluster-Kanten (flowPaths,
  // lib/cluster.mjs) — '→' verbindet nur Adressen entlang belegter
  // Transaktionen, nie rollenweise aneinandergereihte Chips ohne Kantenbezug
  // (Befund 2026-09-29).
  let chainInner = '';
  if (flowPathsFn && lastClusterGraph) {
    const memberSet = new Set((c.memberAddresses ?? []).map(String));
    const memberNodes = (Array.isArray(lastClusterGraph.nodes) ? lastClusterGraph.nodes : [])
      .filter((n) => memberSet.has(String(n.id)))
      .map((n) => ({ id: String(n.id), role: n.role }));
    const memberEdges = (Array.isArray(lastClusterGraph.edges) ? lastClusterGraph.edges : [])
      .filter((e) => memberSet.has(String(e.from)) && memberSet.has(String(e.to)))
      .map((e) => ({ from: String(e.from), to: String(e.to) }));
    chainInner = flowChainHtml(flowPathsFn(memberNodes, memberEdges, { maxPaths: 2, maxPathLen: 5 }), { maxChips: 8 });
  }
  const chainHtml = chainInner
    ? `<div class="cluster-chain" aria-label="Geldfluss: Start bis Kollektor entlang echter Kanten">${chainInner}</div>`
    : '';

  // Schaltflächen-Semantik für Screenreader: die Karte öffnet das Drilldown-
  // Modal (Klick + Enter/Leertaste) — deshalb role="button" plus sprechendes
  // aria-label (Befund 2026-09-29).
  const ariaLabel = `Details zu ${c.label ?? 'Cluster'} öffnen – ${fmtXrp(c.totalDrops)} XRP, ${Number(c.txCount ?? 0).toLocaleString('de-DE')} Tx, ${Number(c.distinctAccounts ?? 0).toLocaleString('de-DE')} Konten`;

  // data-cluster trägt NUR den Listen-Index — c.id ('cluster:<Adresse>')
  // wird nie im DOM gerendert (c.id ist ausschließlich interner Lookup-Schlüssel).
  return `
    <li class="cluster-card role-${dominant} sev-${sev}" data-cluster-index="${Number(index) || 0}" tabindex="0" role="button" aria-label="${esc(ariaLabel)}">
      <div class="cluster-head">
        <span class="cluster-label">${esc(c.label ?? 'Cluster')}</span>
        ${badge}
      </div>
      <div class="cluster-roles">${chips}</div>
      <div class="cluster-metrics">
        <span class="cluster-xrp">${esc(fmtXrp(c.totalDrops))} XRP</span>
        <span class="cluster-txs">${Number(c.txCount ?? 0).toLocaleString('de-DE')} Tx</span>
        <span class="cluster-accounts">${Number(c.distinctAccounts ?? 0).toLocaleString('de-DE')} Konten</span>
      </div>
      ${chainHtml}
      <div class="cluster-times">
        <span>Erste Sichtung: ${esc(fmtClock(c.firstSeen))}</span>
        <span>Letzte Sichtung: ${esc(fmtClock(c.lastSeen))}</span>
      </div>
    </li>`;
}

function renderClusterList(clusters) {
  const listEl = document.getElementById('cluster-list');
  const emptyEl = document.getElementById('cluster-empty');
  const arr = Array.isArray(clusters) ? clusters : [];
  const inClusterTab = activeGraphTab === 'cluster';
  if (!arr.length) {
    listEl.innerHTML = '';
    listEl.hidden = true;
    emptyEl.hidden = !inClusterTab;
    return;
  }
  emptyEl.hidden = true;
  listEl.innerHTML = arr.map((c, i) => clusterCardHtml(c, i)).join('');
  listEl.hidden = !inClusterTab;
}

function bindGraph() {
  document.getElementById('tab-live').addEventListener('click', () => setGraphTab('live'));
  document.getElementById('tab-cluster').addEventListener('click', () => setGraphTab('cluster'));
  document.getElementById('tab-globe').addEventListener('click', () => setGraphTab('globe'));
  const listEl = document.getElementById('cluster-list');
  // Index-Lookup gegen den AKTUELLEN lastClusterGraph: die Karte trägt nur
  // ihren Listen-Index; aus ihm wird die cluster.id aufgelöst, die das Modal
  // anschließend gegen spätere Graph-Updates re-looked (kein stale Index).
  const openFromCard = (card) => {
    const idx = Number(card.dataset.clusterIndex);
    if (!Number.isInteger(idx) || idx < 0) return;
    const clusters = lastClusterGraph && Array.isArray(lastClusterGraph.clusters) ? lastClusterGraph.clusters : [];
    const c = clusters[idx];
    if (!c) return;
    openClusterModal(c.id);
  };
  listEl.addEventListener('click', (e) => {
    const card = e.target.closest('.cluster-card');
    if (card) openFromCard(card);
  });
  listEl.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' || e.key === ' ') {
      const card = e.target.closest('.cluster-card');
      if (card) { e.preventDefault(); openFromCard(card); }
    }
  });
}

/* ------------------------------------------------------------------ */
/* Ansichts-Navigation (Dashboard / Historie / Konto-Check)            */
/* ------------------------------------------------------------------ */
/* Native Buttons (Klick + Enter/Leertaste) togglen das hidden-Attribut
 * der drei View-Container und spiegeln aria-selected an allen drei Tabs
 * — genau ein View ist sichtbar. Die Live-Engine (WSS-Verbindung,
 * Cluster-Rebuild, Köder-Filter) läuft in allen Views weiter: Views sind
 * reine Anzeigefilter ohne Teardown; nur der Weltkugel-Loop pausiert über
 * setGraphTab. Hash-Synchronisation (#dashboard/#history/#check) per
 * replaceState ohne Reload; ein ungültiger Hash fällt auf Dashboard
 * zurück. Fokus-Ring läuft über die globale :focus-visible-Regel. */
const VIEW_TABS = [
  { view: 'dashboard', tabId: 'view-tab-dashboard', panelId: 'view-dashboard' },
  { view: 'history', tabId: 'view-tab-history', panelId: 'view-history' },
  { view: 'check', tabId: 'view-tab-check', panelId: 'view-check' },
];
let activeView = 'dashboard';

function setView(view) {
  const target = VIEW_TABS.some((v) => v.view === view) ? view : 'dashboard';
  activeView = target;
  for (const v of VIEW_TABS) {
    const active = v.view === target;
    document.getElementById(v.tabId).setAttribute('aria-selected', String(active));
    document.getElementById(v.panelId).hidden = !active;
  }
  if (historyMod && typeof historyMod.setView === 'function') historyMod.setView(target === 'history');
  if (checkMod && typeof checkMod.setView === 'function') checkMod.setView(target === 'check');
  // Hash ohne Reload und ohne hashchange-Schleife nachziehen (replaceState
  // erzeugt weder History-Eintrag noch ein hashchange-Event).
  if (location.hash !== `#${target}`) {
    try { history.replaceState(null, '', `#${target}`); } catch { /* egal */ }
  }
}

function viewFromHash() {
  const h = String(location.hash ?? '').replace(/^#/, '').toLowerCase();
  return VIEW_TABS.some((v) => v.view === h) ? h : 'dashboard';
}

function bindViews() {
  for (const v of VIEW_TABS) {
    document.getElementById(v.tabId).addEventListener('click', () => setView(v.view));
  }
  window.addEventListener('hashchange', () => setView(viewFromHash()));
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

// Rollende Fenster für die Cluster-Schicht (Befüllung ausschließlich im
// onLedgerEvent-Guard): letzte TX_WINDOW_CAP Tx-Records / FINDINGS_WINDOW_CAP
// Findings aus dem WSS-Loop.
const txWindow = [];
const findingsWindow = [];

// Cluster-Neubau aus den rollenden Fenstern — mit clientseitigem Köder-Filter
// (Hash-Deny) als Pendant zur serverseitigen baitLabels-Filterung der
// Snapshot-Pfade: Ein Tx-Record/Finding mit Köder-Endpunkt erreicht NIE
// buildClusterGraph, damit Köder-Adressen weder Knoten-Id, Edge-Ende noch
// cluster.id-Träger (und damit nie Graph-Label, Kantentitel, Bubble-Titel,
// Karten-Kette oder Konten-Tabelle) werden können (Befund 2026-09-29). Der
// Filter läuft bei JEDEM Neubau erneut — auch über Einträge, die vor dem
// Allowlist-Load ins Fenster gelangt sind (fail-closed nachgelagert).
async function rebuildClusterGraph() {
  if (!txRecordFromEntry || !buildClusterGraph) return;
  const graphTx = [];
  for (const r of txWindow) {
    if (!(await recordTouchesBait(r))) graphTx.push(r);
  }
  const graphFindings = [];
  for (const f of findingsWindow) {
    if (!(await isDeniedAddrAsync(f?.address))) graphFindings.push(f);
  }
  const cg = buildClusterGraph(graphTx, graphFindings, { maxEdges: CLUSTER_MAX_EDGES });
  lastClusterGraph = cg;
  await primeAddrHashes(cg, graphFindings);
  renderLiveGraph(cg);
  renderClusterList(cg.clusters);
  if (drilldown && typeof drilldown.refresh === 'function') drilldown.refresh();
  // Neue Konsumenten desselben Neubau-Takts: Weltkugel (Punkte/Bögen/Ringe)
  // und Historie (Melden neuer maliziöser Cluster — nur malicious, Köder
  // wurden oben bereits aus beiden Fenstern gefiltert). Die Live-Engine
  // (WSS, Fenster, Köder-Filter) bleibt von den View-States unabhängig.
  if (globeMod && typeof globeMod.refresh === 'function') globeMod.refresh();
  if (historyMod && typeof historyMod.onClusterRebuild === 'function') {
    historyMod.onClusterRebuild(cg, graphFindings).catch(() => { /* Melden darf den Live-Betrieb nie brechen */ });
  }
}

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
 * Volle Anzeige nur, wenn die Bait-Hash-Allowlist geladen ist und der Hash
 * der Adresse nicht auf der Deny-Liste steht; sonst Kurzform (fail-closed,
 * auch für noch ungehashte Adressen). knownBad steuert nur noch die
 * Engine-Logik (known-bad-hit), nicht mehr die Anzeige. Volle Adressen sind
 * ausschließlich öffentlich im Ledger sichtbare Akteur-Adressen — Köder
 * erreichen diesen Pfad nie (Hash-Deny + serverseitige Filterung). */
function displayFindingAddr(address) {
  const a = String(address ?? '');
  if (!a) return '–';
  return isFullShownAddr(a) ? a : shortAddr(a);
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

  const rows = list.slice(-LOG_RENDER_MAX).reverse().map((e) => {
    const shown = displayFindingAddr(e.address);
    const actions = isFullShownAddr(e.address) ? addrActionsHtml(e.address) : '';
    return `
    <div class="log-row sev-${esc(e.severity)}">
      <span class="log-time">${esc(fmtClock(e.t))}</span>
      <span class="log-sev sev-text-${esc(e.severity)}">${esc(e.severity === 'malicious' ? 'maliziös' : e.severity === 'suspect' ? 'verdächtig' : 'info')}</span>
      <span class="log-rule">${esc(RULE_NAME.get(e.ruleId) ?? e.ruleId)}</span>
      <span class="log-addr" title="${esc(shown)}">${esc(shown)}${actions}</span>
      <span class="log-note">${esc(defang(e.note))}</span>
      <span class="log-ledger">#${esc(e.ledgerIndex)}</span>
    </div>`;
  }).join('');
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
    note: 'Adressen vollständig, sofern die Bait-Hash-Allowlist geladen ist und die Adresse nicht auf der Deny-Liste steht; sonst Kurzform. Köder-Adressen werden nie exportiert. Vollständige Zuordnung über ledgerIndex auf dem öffentlichen Ledger möglich.',
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
  const nowText = new Date().toLocaleTimeString('de-DE');
  document.getElementById('last-update').textContent = 'Stand: ' + nowText;
  // Kopfzeilen-Stats (IDs unverändert) aus denselben Live-Werten.
  document.getElementById('stat-malicious').textContent = liveFindings.malicious.toLocaleString('de-DE');
  document.getElementById('stat-suspect').textContent = liveFindings.suspect.toLocaleString('de-DE');
  document.getElementById('stat-events').textContent = liveStats.txs.toLocaleString('de-DE');
  document.getElementById('stat-last').textContent = nowText;
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

  // Köder-Filter (WSS-Pfad): Funde auf Köder-Adressen werden vor jeder
  // Weiterverwendung entfernt — dieselbe Regel wie im Serverpfad
  // (server/index.mjs /api/ledger: findings.filter(!baitLabels.has)), hier
  // hash-gestützt über die Bait-Hash-Allowlist. Damit erscheinen Köder nie
  // im Live-Log, im Export (downloadLog) oder im Cluster-Graphen.
  const visibleFindings = [];
  for (const f of result.findings) {
    if (await isDeniedAddrAsync(f.address)) continue;
    visibleFindings.push(f);
  }

  // Cluster-Schicht: rollendes Fenster + Neuberechnung pro validiertem Ledger.
  if (txRecordFromEntry && buildClusterGraph) {
    for (const e of entries) {
      // closeIso (Ledger-Ebene) als Fallback: expand:true-Entries tragen
      // selbst kein close_time (live verifiziert, siehe Header-Kommentar).
      const rec = txRecordFromEntry(e, closeIso);
      if (!rec) continue;
      // Köder-Endpunkte (account ODER destination) erreichen das Fenster nie —
      // clientseitiges Pendant zum Serverfilter über baitLabels.
      if (await recordTouchesBait(rec)) continue;
      txWindow.push(rec);
      if (txWindow.length > TX_WINDOW_CAP) txWindow.splice(0, txWindow.length - TX_WINDOW_CAP);
    }
    for (const f of visibleFindings) {
      findingsWindow.push(f);
      if (findingsWindow.length > FINDINGS_WINDOW_CAP) findingsWindow.splice(0, findingsWindow.length - FINDINGS_WINDOW_CAP);
      // knownBad-Füller: nur öffentlich dokumentierte Maliziös-Funde — über
      // das Deny-Gate (RACE-GATE: vor dem Allowlist-Load puffern).
      if (f.severity === 'malicious') await offerKnownBadCandidate(f.address);
    }
    await rebuildClusterGraph();
  }

  finishBlockCard(card, visibleFindings, ledgerTxCount, entries.length);
  registerFindings(visibleFindings, idx);
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
      onLedgerEvent(msg).catch((err) => { console.error('ledger event', err); });
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
  // Snapshot-Zyklus zieht die Bait-Hash-Allowlist mit (Mindestabstand beachten).
  refetchBaitHashes(false);
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
      // Cluster-Schicht auch im poll-Modus: Server liefert txRecords mit
      // (bereits serverseitig köder-gefiltert); rebuildClusterGraph zieht den
      // clientseitigen Hash-Filter als Defense-in-Depth nochmals drüber.
      if (txRecordFromEntry && buildClusterGraph) {
        for (const r of Array.isArray(body.txRecords) ? body.txRecords : []) {
          if (!r || typeof r !== 'object') continue;
          txWindow.push(r);
          if (txWindow.length > TX_WINDOW_CAP) txWindow.splice(0, txWindow.length - TX_WINDOW_CAP);
        }
        for (const f of findings) {
          findingsWindow.push(f);
          if (findingsWindow.length > FINDINGS_WINDOW_CAP) findingsWindow.splice(0, findingsWindow.length - FINDINGS_WINDOW_CAP);
        }
        await rebuildClusterGraph();
      }
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
/* Start (Modulskript: DOM ist beim Ausführen bereits geparst)         */
/* ------------------------------------------------------------------ */

initGraph();
bindGraph();
bindViews();
setView(viewFromHash()); // Deep-Link (#history/#check) anwenden, sonst Dashboard
bindLive();
bindAddrActions();
document.getElementById('stat-network').textContent = 'XRPL Mainnet (xrplcluster.com)';
connectLive();
setInterval(watchdog, WATCHDOG_MS);
// Bait-Hash-Allowlist: beim Start, alle 60 s und bei jedem Snapshot-Zyklus.
refetchBaitHashes(true);
setInterval(() => { refetchBaitHashes(true); }, BAIT_HASH_REFETCH_MS);
