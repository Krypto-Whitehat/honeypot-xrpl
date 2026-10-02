'use strict';

/* Honeypot XRPL – Frontend (ESM-Modul)
 *
 * Hauptansicht: LIVE-BLOCK-FEED + AKTEUR-CLUSTERING.
 *   - WebSocket auf wss://xrplcluster.com, Abo "ledger" mit transactions:true.
 *     Real gemessen (chrome-devtools, 2026-09-28): xrplcluster antwortet auf
 *     dieses Abo mit "ledgerClosed"-Events (ledger_index, ledger_time,
 *     txn_count, ledger_hash) OHNE transactions-Feld — die Spec-Annahme
 *     "Hash-Strings im Event" gilt für diesen Endpunkt nicht.
 *   - Deshalb: pro analysiertem ledgerClosed wird derselbe WebSocket für EIN
 *     "ledger"-Kommando (transactions:true, OHNE expand:true) genutzt —
 *     expand:true war die dokumentierte Quota-Hauptlast (lib/live-gate.mjs:7-15)
 *     und ist live verifiziert durch den Plain-Call ersetzt (2026-10-02:
 *     ledger(transactions:true) liefert Hash-Strings, error=none). Die
 *     Hash-Strings werden über die "tx"-Einzelauflösung mit Budget-Kappe
 *     (MAX_RESOLVE, strideHashes — gleichmäßige Stichprobe statt
 *     Blockanfang-Bias) aufgelöst; Blöcke werden mit ANALYZE_EVERY_N_BLOCKS
 *     gesampelt, damit ledger- + tx-Kommandos zusammen unter dem kalibrierten
 *     Deckel QUOTA_CALLS_PER_MIN bleiben. Unvollständig aufgelöste Ledger
 *     werden auf der Karte als "teilweise" gekennzeichnet, nie als stiller
 *     Totalausfall; nicht analysierte Blöcke tragen ein ehrliches Sampling-
 *     Badge.
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
import { strideHashes } from '/lib/stride.mjs';
/* i18n: statischer Import (durch vercel.json-Rewrite /i18n.mjs gedeckt).
 * EN/DE ist damit vor dem ersten Render garantiert initialisiert; ein 404
 * von /i18n.mjs würde das ganze Modul stoppen — bewusst die konsistentere
 * Alternative zum fehlertoleranten dynamischen Import (Muster globe.js). */
import {
  t, ruleName, noteText, sevText, serverPhrase,
  fmtNum, fmtXrp, fmtClock,
  applyStatic, applyLang, initLangSwitcher,
} from './i18n.mjs';

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
 * rendern und melden NIE selbst roh. hashOf (SHA-256-Cache) dient ausschließlich
 * dem Priming des addrHashCache, damit isFullShownAddr für außerhalb des
 * Cluster-Graphen geprüfte Adressen entscheiden kann (Konto-Check,
 * Befund 2026-09-30) — die Gate-Entscheidung bleibt im Host. */
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
        hashOf,
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
const MAX_RESOLVE = 6;             // Tx-Budget pro analysiertem Ledger (Hash-Auflösung,
                                   // analog api/advance.js:86 — Kappe, keine volle Auflösung)
const LEDGER_TIMEOUT_MS = 10000;   // Timeout pro "ledger"-Kommando
const QUOTA_CALLS_PER_MIN = 14;    // sliding window: max. ledger- UND tx-Kommandos/60 s
                                   // (kalibrierter Deckel, api/advance.js:73-74)
const ANALYZE_EVERY_N_BLOCKS = 7;  // Block-Sampling: 1 von N Blöcken wird analysiert.
                                   // N=7, weil nur N>=7 Headroom lässt (node-Nachrechnung
                                   // 2026-10-02: 12,63 Blöcke/min × (1 ledger + 6 tx)/N
                                   // -> N=5: 17,68, N=6: 14,74, beide > 14; N=7: 12,63).
                                   // Simulation (600 s, 4,75 s Takt): idx%7 trifft 19 von
                                   // 126 Blöcken -> ~13,3 Kommandos/min, Headroom ~0,7;
                                   // bei ≤4 s Takt greift der Guard (10,5–11,9/min).
const QUOTA_COOLDOWN_FALLBACK_MS = 65000; // tooBusy ohne parsebares retry-Delta
const QUOTA_COOLDOWN_MAX_MS = 120000;     // Cooldown-Deckel: sliding window gibt
                                         // Einheiten kontinuierlich frei — kein
                                         // striktes Warten auf die Server-Schätzung
const PARALLEL = 1;                // tx-Auflösung sequenziell (kein Burst) — Konvention
                                   // wie api/advance.js:26; Schutz vor Burst-Throttling
const TX_TIMEOUT_MS = 8000;        // Einzel-Timeout pro tx-Call
const SUBSCRIBE_ID = 1;            // feste Request-Id des ledger-Abos (reqId
                                   // startet bei 1000 — keine Kollision)
const WS_PROBE_MIN_MS = 15000;     // Untergrenze des Sonden-Abstands (billig,
                                   // aber kein Hämmern gegen das erschöpfte Quota)
const WS_PROBE_MAX_MS = 90000;     // Obergrenze (≤120 s laut Diagnose): Abstand
                                   // zweier subscribe-Versuche, von der App
                                   // selbst gesteuert statt am Server-Idle-Close
const WS_STALL_MS = 90000;         // Liveness-Schwelle der EIGENEN WS-Uhr —
                                   // bewusst ÜBER dem beobachteten 60-s-Idle-Close
const FEED_CARDS = 24;             // Block-Karten im Feed (2026-10-02: 12 reichten
                                   // bei ~12,6 Blöcken/min für nur ~57 s und bestanden
                                   // zu 11/12 aus Stichproben-Badges — 24 zeigen ~110 s
                                   // und ~3 analysierte Karten)
const LOG_MAX = 400;               // Log-Einträge im Speicher
const LOG_RENDER_MAX = 200;        // gerenderte Log-Zeilen
const STALL_MS = 12000;            // ohne frischen Ledger -> Snapshot-Fallback
const WATCHDOG_MS = 5000;          // Fallback-Prüfintervall
const POLL_BACKOFF_BASE_MS = 5000; // Snapshot-Poll: Backoff-Start nach Fehlversuch
const POLL_BACKOFF_MAX_MS = 60000; // Backoff-Deckel — ein dauerhaft fehlschlagender
                                   // oder gedrosselter Endpunkt wird entlastet,
                                   // statt im 5-s-Takt weiter belastet zu werden
                                   // (Befund 2026-09-30; Pendant zu wsBackoff)
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
  if (XRPL_ADDR_RE.test(s)) return t('defang.bait');
  return s;
}

// fmtClock/fmtXrp kommen jetzt aus ./i18n.mjs (Locale folgt der aktuellen
// Sprache); die ctx-Übergabe an drilldown/history/account-check bleibt gleich.

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

// knownBad für die Live-Engine: ausschließlich aus Live-Funden mit
// severity 'malicious' (Guard in onLedgerEvent) — niemals als Literal im Code.
// Kein clear(), aber FIFO-Kappung (Befund 2026-09-30): Bei Überschreitung des
// Deckels fällt das am längsten beigetragene Konto weg — known-bad-hit
// vergisst dann nur altste Konten; die Struktur wächst nicht mehr unbegrenzt
// pro Session (Angleichung an die Deckel der Nachbar-Strukturen).
const KNOWN_BAD_MAX = 2000; // Deckel analog BAIT_PENDING_MAX
const knownBad = new Set();

// FIFO-Add mit Kappung: Set-Iterationsfolge = Einfügefolge; alle Zugriffe
// laufen über dieses Gate.
function knownBadAdd(address) {
  knownBad.add(address);
  while (knownBad.size > KNOWN_BAD_MAX) {
    const oldest = knownBad.values().next().value;
    if (oldest === undefined) break;
    knownBad.delete(oldest);
  }
}

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
const ADDR_HASH_CACHE_MAX = 10000;       // LRU-Kappung des Hash-Caches (Befund
                                         // 2026-09-30): bewusst über dem aktiven
                                         // Fenster (TX_WINDOW_CAP 4000 +
                                         // FINDINGS_WINDOW_CAP 1000), damit
                                         // aktive Adressen nicht ständig
                                         // verdrängt und neu gehasht werden

const baitHashDeny = new Set();   // sha256-hex (klein) der Bait-Union
const addrHashCache = new Map();  // Adresse -> sha256-hex (synchrone Deny-Prüfung)
const pendingCandidates = [];     // knownBad-Kandidaten vor dem Deny-Load
let denyLoaded = false;
let denyFailCount = 0;
let denyPermanentlyFailed = false;
let fullDisplay = false;          // denyLoaded && !denyPermanentlyFailed
let lastDenyFetchAt = 0;
let lastDenySig = null;           // Signatur des letzten Deny-Sets (Rotations-Erkennung)

async function sha256Hex(value) {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(String(value)));
  let hex = '';
  for (const b of new Uint8Array(digest)) hex += b.toString(16).padStart(2, '0');
  return hex;
}

// Näherungs-LRU über die Einfügeordnung der Map (Befund 2026-09-30): Zugriff
// frischt die Position auf (get + delete + set), Einfügen kappen die ältesten
// Einträge. Fail-closed bleibt gewahrt: Eine verdrängte Adresse verliert nur
// ihren Cache-Eintrag — isDeniedAddr verneint dann (kein Hash bekannt),
// isFullShownAddr ebenso (Anzeige bleibt Kurzform), und der asynchrone Pfad
// isDeniedAddrAsync hasht die Adresse bei Bedarf einfach neu.
function addrHashCacheGet(a) {
  const v = addrHashCache.get(a);
  if (v !== undefined) {
    addrHashCache.delete(a);
    addrHashCache.set(a, v);
  }
  return v;
}

function addrHashCacheTrim() {
  while (addrHashCache.size > ADDR_HASH_CACHE_MAX) {
    const oldest = addrHashCache.keys().next().value;
    if (oldest === undefined) break;
    addrHashCache.delete(oldest);
  }
}

async function hashOf(addr) {
  const a = String(addr ?? '').trim();
  if (!a) return '';
  const cached = addrHashCacheGet(a);
  if (cached) return cached;
  const hex = await sha256Hex(a);
  addrHashCache.set(a, hex);
  addrHashCacheTrim();
  return hex;
}

// Synchrone Deny-Prüfung: nur gehashte Adressen können getroffen werden.
function isDeniedAddr(addr) {
  const h = addrHashCacheGet(String(addr ?? '').trim());
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
  const h = addrHashCacheGet(a);
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
    if (!baitHashDeny.has(await hashOf(a))) knownBadAdd(a);
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
    // Änderungssignatur: Hat die Rotation das Deny-Set tatsächlich verändert?
    const nextSig = [...next].sort().join(',');
    const denyChanged = nextSig !== lastDenySig;
    lastDenySig = nextSig;
    baitHashDeny.clear();
    for (const h of next) baitHashDeny.add(h);
    denyLoaded = true;
    denyFailCount = 0;
    await rebuildDisplayAndKnownBad();
    if (denyChanged) {
      // Köder-frische Koordination: Nach jeder Rotation (Deny-Set geändert)
      // Drilldown und Weltkugel sofort aktualisieren — das Modal prüft die
      // Member-Hashes des eingefrorenen Snapshots gegen die AKTUELLE Deny-
      // Liste (Fail-closed schlägt Alterungsanzeige); die Kugel erhält
      // refresh(true) und wendet den frischen Datensatz SOFORT an, ohne auf
      // das Fensterende des Anwendetakt-Deckels zu warten (Befund 2026-09-30:
      // sonst bliebe ein frisch aktivierter Köder bis zu Deckel-Intervall
      // länger sichtbar). Der WSS-Pfad filtert Köder rein clientseitig gegen
      // diese Liste — ihr frischer Stand ist dort das einzige Gate.
      if (drilldown && typeof drilldown.refresh === 'function') drilldown.refresh();
      if (globeMod && typeof globeMod.refresh === 'function') globeMod.refresh(true);
    }
  } catch (err) {
    denyFailCount += 1;
    if (denyFailCount >= BAIT_HASH_MAX_FAILS) {
      denyPermanentlyFailed = true;
      denyLoaded = false;
      fullDisplay = false;
      console.warn(t('log.consoleDenyFailed'), err);
      // Gepufferte Kandidaten dürfen in knownBad (known-bad-hit der Engine
      // bleibt im WSS-Pfad funktionsfähig); die Anzeige bleibt Kurzform.
      for (const a of pendingCandidates) knownBadAdd(a);
      pendingCandidates.length = 0;
    } else {
      console.warn(t('log.consoleDenyAttempt', { n: denyFailCount, err: err && err.message }));
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
  knownBadAdd(a);
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
    `<button type="button" class="addr-copy" data-addr="${esc(a)}" aria-label="${esc(t('addr.copyAria'))}">${esc(t('addr.copy'))}</button>` +
    `<a class="addr-link" href="${esc(href)}" target="_blank" rel="noopener noreferrer" aria-label="${esc(t('addr.linkAria'))}" title="${esc(t('addr.linkAria'))}">↗</a>` +
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
    btn.textContent = ok ? t('addr.copied') : t('addr.error');
    btn.setAttribute('aria-live', 'polite');
    setTimeout(() => { btn.textContent = t('addr.copy'); }, 2000);
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
      `<p class="graph-error">${esc(t('graph.visError'))}</p>`;
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
      title: `${displayFindingAddr(n.id)} (${roleLabelText(role)})`,
      shape: 'dot',
      size: 16,
      color: ROLE_COLORS[role],
      clusterId: n.clusterId ?? null, // Grundlage der Clustering-joinCondition
      severity: String(n.severity ?? 'info'),
      margin: 8,
    };
  });

  const nextEdges = rawEdges.map((e) => {
    // type bleibt ROH: Edge-Id (`${e.from}->${e.to}::${type}`) und
    // EDGE_COLORS-Lookup dürfen bei Sprachwechsel nicht wandern (sonst
    // stale Kanten im inkrementell gepflegten vis-Netz). Nur das Label
    // wird übersetzt gerendert.
    const type = String(e.type || 'Sonstige');
    const typeLabel = type === 'Sonstige' ? t('edge.other') : type;
    return {
      id: String(e.txHash || `${e.from}->${e.to}::${type}`),
      from: String(e.from),
      to: String(e.to),
      label: typeLabel,
      // Kanten-Tooltip: volle Adressen bei geladener Allowlist und Nicht-Treffer
      // auf der Deny-Liste, sonst Kurzform (displayFindingAddr, fail-closed).
      title: `${displayFindingAddr(e.from)} → ${displayFindingAddr(e.to)} (${typeLabel})`,
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
  return `${c.label ?? t('cluster.labelDefault')}\n${t('cluster.members', { n: members })} · ${fmtXrp(c.totalDrops)} XRP`;
}

function clusterBubbleTitle(c) {
  const members = (Array.isArray(c.memberAddresses) ? c.memberAddresses : [])
    .slice(0, 8)
    .map(displayFindingAddr)
    .join(', ');
  return `${c.label ?? t('cluster.labelDefault')}: ${members}`;
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
// ROLE_LABEL bleibt die kanonische (deutsche) Rollen-Tafel — ctx-Partner
// (drilldown/account-check) greifen darauf zurück. Für Anzeigen im Host
// übersetzt roleLabelText über die Legenden-Keys (EN: Collector, DE: Kollektor).
const ROLE_LABEL = { source: 'Source', drainer: 'Drainer', collector: 'Kollektor', relay: 'Relay', unknown: 'Unknown' };
const roleLabelText = (role) => t('legend.' + role);

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
    .map((r) => `<span class="role-chip role-${r}"><span class="swatch swatch-${r}"></span>${roleCounts.get(r)} × ${esc(roleLabelText(r))}</span>`)
    .join('');

  // Severity-Chip nur bei malicious/suspect; 'info' wird unterdrückt.
  const badge = sev === 'malicious' || sev === 'suspect'
    ? `<span class="risk-badge risk-${esc(sev)}">${esc(sevText(sev))}</span>`
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
    ? `<div class="cluster-chain" aria-label="${esc(t('cluster.chainAria'))}">${chainInner}</div>`
    : '';

  // Schaltflächen-Semantik für Screenreader: die Karte öffnet das Drilldown-
  // Modal (Klick + Enter/Leertaste) — deshalb role="button" plus sprechendes
  // aria-label (Befund 2026-09-29).
  const ariaLabel = t('cluster.ariaDetails', {
    label: c.label ?? t('cluster.labelDefault'),
    xrp: fmtXrp(c.totalDrops),
    txs: fmtNum(c.txCount ?? 0),
    accounts: fmtNum(c.distinctAccounts ?? 0),
  });

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
        <span class="cluster-txs">${fmtNum(c.txCount ?? 0)} ${esc(t('cluster.txUnit'))}</span>
        <span class="cluster-accounts">${fmtNum(c.distinctAccounts ?? 0)} ${esc(t('cluster.accountUnit'))}</span>
      </div>
      ${chainHtml}
      <div class="cluster-times">
        <span>${esc(t('cluster.firstSeen'))}${esc(fmtClock(c.firstSeen))}</span>
        <span>${esc(t('cluster.lastSeen'))}${esc(fmtClock(c.lastSeen))}</span>
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
  const prev = activeView;
  activeView = target;
  for (const v of VIEW_TABS) {
    const active = v.view === target;
    document.getElementById(v.tabId).setAttribute('aria-selected', String(active));
    document.getElementById(v.panelId).hidden = !active;
  }
  // Weltkugel-Pause beim Verlassen des Dashboards (Symptom 2b): Ohne diese
  // Pause lief die Kugel-Renderloop auch im versteckten View weiter (gemessen
  // ~2158 rAF/s versteckt). deactivate() ist idempotent und pausiert nur eine
  // konstruierte Kugel — der Lazy-Load-Vertrag bleibt unberührt.
  if (prev === 'dashboard' && target !== 'dashboard') {
    if (globeMod && typeof globeMod.deactivate === 'function') globeMod.deactivate();
  }
  // Rückkehr zum Dashboard: activate() NUR bei aktivem Globe-Tab (bedingtes
  // Muster wie beim Modul-Import). NIE bedingungslos activate() — das würde
  // die Kugel beim ersten Aufruf eager konstruieren (1,9-MB-CDN-Bundle) bzw.
  // bei aktiven live/cluster-Tabs eine unsichtbare Renderloop resumen.
  if (target === 'dashboard' && prev !== 'dashboard' && activeGraphTab === 'globe') {
    if (globeMod && typeof globeMod.activate === 'function') globeMod.activate();
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
let analysisInFlight = false;      // Serialisierungsguard: genau eine Block-
                                   // Analyse gleichzeitig (siehe onLedgerEvent)
const quotaWindow = [];            // Zeitstempel ALLER gesendeten ledger- UND tx-
                                   // Kommandos (60-s-Fenster, push zum Sendezeitpunkt)

// need = Anzahl Kommandos, die für die kommende Aktion noch gebraucht werden
// (Standard 1). true heißt: im 60-s-Fenster ist noch Platz dafür.
function quotaBudgetOk(need = 1) {
  const cutoff = Date.now() - 60000;
  while (quotaWindow.length && quotaWindow[0] < cutoff) quotaWindow.shift();
  return quotaWindow.length + need <= QUOTA_CALLS_PER_MIN;
}

// Ein Kommando wurde gesendet -> ins sliding window eintragen. Zählt jetzt
// ledger- UND tx-Kommandos (Befund 2026-10-02: die tx-Kommandos waren der
// blinde Fleck — ohne sie überstieg der Client die Units-Quota pro Block).
function quotaSend() {
  quotaWindow.push(Date.now());
}

let ws = null;
let wsBackoff = 2000;
let wsAttemptTimer = null;
let reqId = 1000;
const pendingTx = new Map();        // id -> resolve-Funktion

/* ---------- WSS-Diagnose: Abo-Antwort, Drosselung, Liveness ---------- */
/* xrplcluster lehnt bei erschöpfter IP-Quota das subscribe (und jedes
 * ledger-/tx-Kommando) mit error "tooBusy" + error_message
 * "… retry in ~NNNNms" ab — der Socket bleibt dabei offen und stumm. Diese
 * Zustände machen die Ablehnung sichtbar (Statuszeile + Konsole) und steuern
 * den Sonden-Rhythmus selbst, statt auf den Server-Idle-Close (~62 s) zu
 * warten. Das Quota ist ein sliding window: Einheiten werden kontinuierlich
 * frei, deshalb wird die Server-Schätzung (retry-Delta) nur als Obergrenze
 * des Probe-Abstands und im Statustext verwendet — nie strikt abgewartet. */
let lastWsMsgAt = 0;               // EIGENE WS-Uhr: onopen + JEDE onmessage
let wssSubscribeError = null;      // {error, message, retryMs, at, throttled}
let wsProbeTimer = null;           // Sonden-Timer für abgelehntes Abo
let wssSubscribeOk = false;        // aktuelles Abo wurde angenommen
let wssSubscribeOkAt = 0;          // Zeitpunkt der Abo-Annahme (Status-Fenster)
const WSS_SUBSCRIBE_OK_WINDOW_MS = 30000; // so lange gilt 'WSS verbunden' nach
                                          // Abo-Annahme auch ohne Event (der
                                          // erste ledgerClosed folgt sonst in
                                          // ~4 s; dauerhafter Event-Mangel fällt
                                          // danach ehrlich auf den Fallback-Text)

// retry-Delta aus der error_message parsen (undokumentiertes Endpunkt-Format,
// deshalb robust mit Fallback): "retry in ~1299564ms", "retry in 90 seconds".
function parseRetryMs(text) {
  const s = String(text ?? '');
  let m = s.match(/retry[^0-9]{0,24}?(\d+)\s*ms/i);
  if (m) {
    const v = Number(m[1]);
    if (Number.isFinite(v) && v > 0) return v;
  }
  m = s.match(/retry[^0-9]{0,24}?(\d+(?:\.\d+)?)\s*(s|sec|secs|second|seconds|m|min|mins|minute|minutes|h|hours)\b/i);
  if (m) {
    const v = Number(m[1]);
    if (Number.isFinite(v) && v > 0) {
      const unit = m[2].toLowerCase();
      const factor = unit.startsWith('ms') ? 1 : unit[0] === 's' ? 1000 : unit[0] === 'm' ? 60000 : 3600000;
      return v * factor;
    }
  }
  return 0;
}

function fmtDur(ms) {
  const v = Math.max(0, Math.round(ms / 1000));
  if (v < 90) return `${v} s`;
  const min = Math.round(v / 60);
  return `~${min} min`;
}

function setConn(ok, text) {
  const dot = document.getElementById('conn-dot');
  const el = document.getElementById('conn-text');
  dot.classList.toggle('ok', ok);
  dot.classList.toggle('err', !ok);
  el.textContent = text;
}

function connLabel() {
  if (liveMode === 'wss') return t('conn.wss');
  if (liveMode === 'poll') {
    if (wssSubscribeError) {
      // Volle Server-Schätzung (retry-Delta) NUR hier im Text — der
      // Sonden-Rhythmus bleibt auf min(Delta, 90 s) geklemmt.
      const rest = wssSubscribeError.retryMs
        ? Math.max(0, wssSubscribeError.at + wssSubscribeError.retryMs - Date.now())
        : 0;
      const est = rest > 0 ? t('conn.estSuffix', { dur: fmtDur(rest) }) : '';
      if (wssSubscribeError.throttled) {
        return t('conn.throttled', { est });
      }
      // Server-Fehlerwert (error) bleibt roh interpoliert — Protokollwert.
      return t('conn.rejected', { error: wssSubscribeError.error, est });
    }
    // Abo frisch angenommen: 'WSS verbunden' schon mit dem ersten erfolgreichen
    // subscribe-Versuch (Events folgen in ~4 s). Bleiben Events dauerhaft aus,
    // fällt die Anzeige danach ehrlich auf den generischen Fallback-Text.
    if (wssSubscribeOk && Date.now() - wssSubscribeOkAt < WSS_SUBSCRIBE_OK_WINDOW_MS) {
      return t('conn.wss');
    }
    return t('conn.noEvents');
  }
  return t('conn.init');
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
      <span class="block-txs">${fmtNum(txCount)} ${esc(t('block.txs'))}</span>
    </div>
    <div class="block-badges"><span class="badge badge-analyzing">${esc(t('block.analyzing'))}</span></div>`;
  const feed = document.getElementById('block-feed');
  feed.prepend(li);
  while (feed.children.length > FEED_CARDS) feed.lastElementChild.remove();
  document.getElementById('feed-empty').hidden = true;
  return li;
}

function severityBadgeHtml(counts) {
  const parts = [];
  if (counts.malicious) parts.push(`<span class="badge badge-malicious">${counts.malicious} × ${esc(t('log.filter.malicious'))}</span>`);
  if (counts.suspect) parts.push(`<span class="badge badge-suspect">${counts.suspect} × ${esc(t('log.filter.suspect'))}</span>`);
  if (counts.info) parts.push(`<span class="badge badge-info">${counts.info} × ${esc(t('log.filter.info'))}</span>`);
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
  else badges.push(`<span class="badge badge-clean">${esc(t('block.clean'))}</span>`);
  if (counts.malicious) card.classList.add('has-malicious');
  else if (counts.suspect) card.classList.add('has-suspect');
  if (resolvedCount < ledgerTxCount) {
    badges.push(`<span class="badge badge-partial">${esc(t('block.resolved', { resolved: resolvedCount, total: ledgerTxCount }))}</span>`);
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
      // Additive Übersetzungsfelder des Detectors (noteKey/noteParams):
      // ermöglichen clientseitige Re-Renderung in der aktuellen Sprache;
      // die sanitisierte note bleibt als Fallback erhalten.
      noteKey: typeof f.noteKey === 'string' ? f.noteKey : null,
      noteParams: f.noteParams && typeof f.noteParams === 'object' ? f.noteParams : null,
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
    // Note: bei noteKey/noteParams (additive Felder des Detectors) übersetzt
    // gerendert; sonst Fallback auf die sanitisierte Server-note (raw).
    const noteShown = e.noteKey ? noteText(e) : defang(e.note);
    return `
    <div class="log-row sev-${esc(e.severity)}">
      <span class="log-time">${esc(fmtClock(e.t))}</span>
      <span class="log-sev sev-text-${esc(e.severity)}">${esc(sevText(e.severity))}</span>
      <span class="log-rule">${esc(ruleName(e.ruleId))}</span>
      <span class="log-addr" title="${esc(shown)}">${esc(shown)}${actions}</span>
      <span class="log-note">${esc(defang(noteShown))}</span>
      <span class="log-ledger">#${esc(e.ledgerIndex)}</span>
    </div>`;
  }).join('');
  box.innerHTML = rows;
}

function buildRuleFilter() {
  const sel = document.getElementById('log-rule');
  sel.innerHTML = `<option value="all">${esc(t('log.filter.allRules'))}</option>` + RULE_CATALOG
    .map((r) => `<option value="${esc(r.id)}">${esc(ruleName(r.id))}</option>`)
    .join('');
}

function downloadLog() {
  const payload = {
    exportedAt: new Date().toISOString(),
    source: t('export.source'),
    network: document.getElementById('stat-network').textContent,
    note: t('export.note'),
    count: logEntries.length,
    entries: logEntries.map((e) => ({
      time: new Date(e.t).toISOString(),
      ledgerIndex: e.ledgerIndex,
      ruleId: e.ruleId,
      severity: e.severity,
      address: displayFindingAddr(e.address),
      note: e.noteKey ? noteText(e) : e.note,
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
  document.getElementById('live-ledgers').textContent = fmtNum(liveStats.ledgers);
  document.getElementById('live-txs').textContent = fmtNum(liveStats.txs);
  document.getElementById('live-f-malicious').textContent = fmtNum(liveFindings.malicious);
  document.getElementById('live-f-suspect').textContent = fmtNum(liveFindings.suspect);
  document.getElementById('live-f-info').textContent = fmtNum(liveFindings.info);
  const nowText = fmtClock(Date.now());
  document.getElementById('last-update').textContent = t('foot.updated') + nowText;
  // Kopfzeilen-Stats (IDs unverändert) aus denselben Live-Werten.
  document.getElementById('stat-malicious').textContent = fmtNum(liveFindings.malicious);
  document.getElementById('stat-suspect').textContent = fmtNum(liveFindings.suspect);
  document.getElementById('stat-events').textContent = fmtNum(liveStats.txs);
  document.getElementById('stat-last').textContent = nowText;
  // Hero-KPI-Zeile (index.html .hx-stage): dieselben Live-Werte, eigene IDs —
  // guardiert, damit die Funktion auch auf Seiten ohne Hero läuft.
  const kpiMalicious = document.getElementById('hx-kpi-malicious');
  const kpiSuspect = document.getElementById('hx-kpi-suspect');
  const kpiTxs = document.getElementById('hx-kpi-txs');
  if (kpiMalicious) kpiMalicious.textContent = fmtNum(liveFindings.malicious);
  if (kpiSuspect) kpiSuspect.textContent = fmtNum(liveFindings.suspect);
  if (kpiTxs) kpiTxs.textContent = fmtNum(liveStats.txs);
}

/* ---------- Volles Ledger pro Block über denselben WebSocket ---------- */
// OHNE expand:true (Korrektur 2026-10-02): expand:true war die dokumentierte
// Quota-Hauptlast (lib/live-gate.mjs:7-15) und ist live durch den Plain-Call
// ersetzt — ledger(transactions:true) liefert Hash-Strings (live verifiziert:
// error=none, alle Einträge Strings). Normalisierung zu {tx_json, meta} bleibt
// als Defense-in-Depth für Server, die volle Objekte (Meta-Feld "metaData")
// oder {tx_json, meta}-Form liefern (lib/detector.mjs liest meta; lib/ wird
// nicht angetastet).
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
    let timer = null;
    // settle-Wrapper mit clearTimeout (Muster wsTxCommand): Der Timeout-Timer
    // lief bisher auch nach rechtzeitiger Antwort weiter auf.
    const settle = (result) => {
      if (timer) { clearTimeout(timer); timer = null; }
      resolve(result);
    };
    pendingTx.set(id, settle);
    timer = setTimeout(() => {
      pendingTx.delete(id);
      settle(null);
    }, LEDGER_TIMEOUT_MS);
    try {
      ws.send(JSON.stringify({ command: 'ledger', id, ledger_index: ledgerIndex, transactions: true }));
    } catch {
      pendingTx.delete(id);
      settle(null);
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

/* Rückgabe: { throttled, entries, error_message }. throttled=true bricht die
 * Chunk-Schleife beim ERSTEN tooBusy/slowDown einer tx-Antwort ab — der
 * Aufrufer (onLedgerEvent) setzt dann Cooldown + Drossel-Badge und verlässt
 * die Blockkarte früh, damit finishBlockCard keine zusätzliche 0/N-Badge
 * erzeugt (Quota-Fallgrube: 0/N ist nur für echten Timeout legitim). */
async function resolveHashes(hashes) {
  const entries = [];
  // strideHashes statt slice(0, MAX_RESOLVE): gleichmäßige Stichprobe über den
  // Block statt systematischem Blockanfang-Bias (lib/stride.mjs). Jedes tx-
  // Kommando zählt ins quotaWindow (zum Sendezeitpunkt) — tx-Kommandos waren
  // vorher der blinde Fleck des Budgets.
  const list = strideHashes(hashes, MAX_RESOLVE);
  for (let i = 0; i < list.length; i += PARALLEL) {
    if (!ws || ws.readyState !== 1) break; // Verbindung verloren -> Rest bleibt ungelöst
    const chunk = list.slice(i, i + PARALLEL);
    // Harte Budget-Schranke pro tx-Kommando (gilt auch auf dem Event-Hash-
    // Pfad, der ohne vorgelagerte ledger-Budgetprüfung aufruft): ist das
    // 60-s-Fenster voll, bleibt der Rest ungelöst -> ehrliche N/M-Partial-
    // Badge, kein Quota-Übertritt.
    if (!quotaBudgetOk(chunk.length)) break;
    const results = await Promise.all(chunk.map((h) => {
      quotaSend();
      return wsTxCommand(h);
    }));
    for (const r of results) {
      if (r && typeof r === 'object' && (r.error === 'tooBusy' || r.error === 'slowDown')) {
        return { throttled: true, entries, error_message: r.error_message ?? null };
      }
      // tx liefert die vollen Tx-Felder plus meta (flach oder als result.tx/result.meta).
      const norm = normalizeLedgerTxEntry(r);
      if (norm) entries.push(norm);
    }
  }
  return { throttled: false, entries, error_message: null };
}

/* ---------- Ledger-Event ("ledgerClosed" bzw. "ledger" vom Abo) ---------- */
// Drossel-Badge + Cooldown für tooBusy/slowDown aus einer Kommando-Antwort.
// Cooldown = min(geparstes retry-Delta, 120 s) bzw. 65 s Fallback: Das Quota
// ist ein sliding window (Einheiten werden kontinuierlich frei), deshalb wird
// die Server-Punktschätzung nicht strikt abgewartet — nach Ablauf des Deckels
// probiert der nächste Ledger cheap nach.
function markQuotaThrottled(card, errorMessage) {
  const cooldownMs = Math.min(parseRetryMs(errorMessage) || QUOTA_COOLDOWN_FALLBACK_MS, QUOTA_COOLDOWN_MAX_MS);
  quotaCooldownUntil = Date.now() + cooldownMs;
  card.querySelector('.block-badges').innerHTML =
    `<span class="badge badge-partial">${esc(t('block.quotaPaused'))}</span>`;
}

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
  // Ledger-Events fließen → der Endpunkt ist wieder gesund: Den Snapshot-Poll-
  // Backoff zurücksetzen, damit der Fallback im Störungsfall sofort wieder
  // bereitsteht (Befund 2026-09-30).
  if (pollFailCount || pollBackoffUntil) {
    pollFailCount = 0;
    pollBackoffUntil = 0;
  }
  // Ledger-Events fließen → eine frühere Abo-Ablehnung ist überwunden.
  if (wssSubscribeError || wsProbeTimer) {
    wssSubscribeError = null;
    if (wsProbeTimer) { clearTimeout(wsProbeTimer); wsProbeTimer = null; }
  }
  wssSubscribeOk = true;
  wssSubscribeOkAt = Date.now();

  const eventHashes = Array.isArray(msg.transactions) ? msg.transactions : [];
  const declaredCount = Number(msg.txn_count ?? eventHashes.length ?? 0);
  const closeIso = xrplIso(msg.ledger_time ?? msg.close_time, msg.close_time_iso);

  // Block-Sampling (Policy, keine Quota-Erschöpfung): nur 1 von
  // ANALYZE_EVERY_N_BLOCKS Blöcken wird analysiert — sonst sprengen
  // 1 ledger- + 6 tx-Kommandos pro Block das kalibrierte Fenster
  // QUOTA_CALLS_PER_MIN (Nachrechnung: N=7 -> 12,63 Kommandos/min).
  // Nicht analysierte Blöcke erscheinen als Karte aus dem Event-txn_count
  // ohne jedes Kommando; seenLedgers-Dedup schließt eine Nachholung aus,
  // das Badge nennt deshalb keine Zukunfts-Zusage. liveStats bleibt unver-
  // ändert: die Kopfzeilen-Stats zählen nur analysierte Ledger.
  if (idx % ANALYZE_EVERY_N_BLOCKS !== 0) {
    const skippedCard = addBlockCard(idx, closeIso, declaredCount, 'analyzing');
    skippedCard.querySelector('.block-badges').innerHTML =
      `<span class="badge badge-partial">${esc(t('block.sampled'))}</span>`;
    return;
  }

  // Serialisierungsguard: sequenzielle tx-Auflösung (PARALLEL=1) braucht im
  // Worst case 6 × TX_TIMEOUT_MS = 48 s pro analysiertem Block. Überlappende
  // onLedgerEvent-Aufrufe (Blocktakt ~4-5 s) würden sonst Kommandos stapeln
  // und das Fenster sprengen — die nächste Analyse startet erst nach der
  // laufenden (ihre Karte bleibt bis dahin "Analysiere …").
  if (analysisInFlight) {
    const queuedCard = addBlockCard(idx, closeIso, declaredCount, 'analyzing');
    queuedCard.querySelector('.block-badges').innerHTML =
      `<span class="badge badge-partial">${esc(t('block.busy'))}</span>`;
    return;
  }
  const card = addBlockCard(idx, closeIso, declaredCount, 'analyzing');
  analysisInFlight = true;
  try {
    await analyzeLedgerBlock(idx, eventHashes, declaredCount, closeIso, card);
  } finally {
    analysisInFlight = false;
  }
}

// Analyse eines analysierten Blocks: 1 ledger-Kommando (ohne expand) + max.
// MAX_RESOLVE tx-Kommandos — alle ins quotaWindow (Sendezeitpunkt).
async function analyzeLedgerBlock(idx, eventHashes, declaredCount, closeIso, card) {
  let entries = [];
  let ledgerTxCount = declaredCount;
  const inCooldown = Date.now() < quotaCooldownUntil;
  // Budget-Prüfung jetzt VOR dem Senden (ledger- UND tx-Kommandos im Fenster):
  // ein analysierter Block kostet bis zu 1 + MAX_RESOLVE Kommandos.
  const overBudget = !eventHashes.length && !inCooldown &&
    !quotaBudgetOk(MAX_RESOLVE + 1);
  if (overBudget) {
    card.querySelector('.block-badges').innerHTML =
      `<span class="badge badge-partial">${esc(t('block.budgetSkipped'))}</span>`;
    return;
  }
  const needLedgerFetch = !eventHashes.length && !inCooldown;
  let led = null;
  if (needLedgerFetch) {
    quotaSend();
    led = await wsLedgerCommand(idx);
  }
  // Fehler-Antworten kommen seit der settle-Umstellung als {error, error_message}
  // statt null durch — der tooBusy-Zweig greift jetzt tatsächlich.
  if (led && typeof led === 'object' && (led.error === 'tooBusy' || led.error === 'slowDown')) {
    markQuotaThrottled(card, led.error_message ?? null);
    return; // Early-Return: finishBlockCard würde sonst zusätzlich 0/N erzeugen
  }
  if (inCooldown) {
    card.querySelector('.block-badges').innerHTML =
      `<span class="badge badge-partial">${esc(t('block.quotaSkipped'))}</span>`;
    return;
  }
  const rawTxs = led?.ledger?.transactions;
  let resolved = null; // Ergebnis von resolveHashes (Hash-Auflösung)
  if (Array.isArray(rawTxs) && rawTxs.length) {
    ledgerTxCount = rawTxs.length;
    if (rawTxs.every((t) => typeof t === 'string')) {
      resolved = await resolveHashes(rawTxs); // Hash-Strings -> tx-Einzelauflösung
    } else {
      // Defense-in-Depth: Server liefert volle Objekte (nach expand-Entfernung
      // nicht mehr beobachtet; live belegt allStrings=true).
      entries = strideHashes(rawTxs, MAX_RESOLVE).map(normalizeLedgerTxEntry).filter(Boolean);
    }
  } else if (eventHashes.length) {
    ledgerTxCount = eventHashes.length;
    resolved = await resolveHashes(eventHashes);
  }
  if (resolved && resolved.throttled) {
    // tooBusy auf dem tx-Pfad: Early-Return-Muster wie der ledger-Pfad —
    // Cooldown setzen, Drossel-Badge zeigen, Blockkarte früh verlassen.
    markQuotaThrottled(card, resolved.error_message);
    return;
  }
  if (resolved) entries = resolved.entries;

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
      // closeIso (Ledger-Ebene) als Fallback: Entries ohne eigenes close_time
      // (z. B. volle Ledger-Objekte ohne expand — live verifiziert) erhalten
      // die Ledger-Ebenen-Zeit.
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
// Fehler-Antworten als {error, error_message} statt null durchreichen: null
// machte tooBusy von echtem Timeout/Verbindungsverlust ununterscheidbar. Der
// Erfolgswert bleibt unverändert msg.result — die Konsumenten
// (normalizeLedgerTxEntry, led.ledger.transactions) bleiben unangetastet;
// Fehler-Objekte laufen in normalizeLedgerTxEntry als null heraus.
function settleValue(msg) {
  if (msg.error) {
    return { error: String(msg.error), error_message: msg.error_message != null ? String(msg.error_message) : null };
  }
  return msg.result ?? null;
}

// Subscribe-Antwort (id=1) auswerten — früher landete sie ungeprüft im Nirwana
// (pendingTx kennt nur ids ≥ 1001): tooBusy war unsichtbar, 0 Konsolenmeldungen.
function handleSubscribeResponse(msg) {
  if (msg.status !== 'error' && !msg.error) {
    // Abo angenommen: Drosselzustand und Sonde fallen weg; mit dem ERSTEN
    // erfolgreichen Versuch steht 'Live – WSS verbunden' (ohne Seitenreload).
    wssSubscribeError = null;
    wssSubscribeOk = true;
    wssSubscribeOkAt = Date.now();
    if (wsProbeTimer) { clearTimeout(wsProbeTimer); wsProbeTimer = null; }
    setConn(true, t('conn.wss'));
    return;
  }
  const error = String(msg.error ?? 'unbekannt');
  const message = msg.error_message != null ? String(msg.error_message) : '';
  const retryMs = parseRetryMs(message);
  const throttled = error === 'tooBusy' || error === 'slowDown' || /rate\s*limit/i.test(message);
  wssSubscribeError = { error, message, retryMs, at: Date.now(), throttled };
  wssSubscribeOk = false;
  // Ein abgelehntes Abo liefert nie Events — liveMode 'wss' wäre gelogen
  // (sticky bis zum nächsten Snapshot); der Snapshot-Fallback ist ab jetzt
  // die Datenquelle. onLedgerEvent stellt 'wss' beim ersten Event wieder her.
  if (liveMode === 'wss') liveMode = 'poll';
  const est = retryMs ? t('conn.estWarn', { dur: fmtDur(retryMs) }) : '';
  const msgSuffix = message ? `: ${message}` : '';
  console.warn(t('log.consoleSubscribeRejected', { error, msg: msgSuffix, est }));
  scheduleWssProbe(retryMs);
  setConn(liveMode !== 'init', connLabel());
}

// Sonden-Rhythmus nach abgelehntem Abo: Abstand = min(retry-Delta, 90 s)
// (Untergrenze 15 s) — bewusst NICHT die volle Server-Schätzung, weil das
// Quota ein sliding window ist und Einheiten kontinuierlich frei werden.
// Die Sonde schließt nur DEN Socket, auf dessen Ablehnung sie gehört wurde,
// und nur, solange keine Ledger-Events fließen (liveMode 'wss').
function scheduleWssProbe(retryMs) {
  if (wsProbeTimer) { clearTimeout(wsProbeTimer); wsProbeTimer = null; }
  const socket = ws;
  const delay = Math.min(Math.max(retryMs || WS_PROBE_MAX_MS, WS_PROBE_MIN_MS), WS_PROBE_MAX_MS);
  wsProbeTimer = setTimeout(() => {
    wsProbeTimer = null;
    if (socket !== ws || !ws || ws.readyState !== 1) return;
    if (liveMode === 'wss') return; // Abo aktiv, Events fließen — nichts zu sondieren
    try { ws.close(); } catch { /* onclose fehlt dann eben; watchdog übernimmt */ }
    // onclose feuert und trägt den Reconnect nach (Backoff bleibt aktiv).
  }, delay);
}

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
    lastWsMsgAt = Date.now();
    try {
      ws.send(JSON.stringify({ command: 'subscribe', id: SUBSCRIBE_ID, streams: ['ledger'], transactions: true }));
    } catch { /* onclose behandelt es */ }
    if (liveMode !== 'poll') setConn(true, t('conn.wssConnecting'));
  };

  ws.onmessage = (ev) => {
    lastWsMsgAt = Date.now(); // EIGENE WS-Uhr: JEDE Message zählt (auch Responses)
    let msg;
    try { msg = JSON.parse(ev.data); } catch { return; }
    // xrplcluster sendet "ledgerClosed" (verifiziert); "ledger" bleibt abgedeckt.
    if ((msg.type === 'ledgerClosed' || (msg.type === 'ledger' && msg.validated)) && msg.ledger_index != null) {
      onLedgerEvent(msg).catch((err) => { console.error('ledger event', err); });
      return;
    }
    if (msg.type === 'response' && msg.id === SUBSCRIBE_ID) {
      handleSubscribeResponse(msg);
      return;
    }
    if (msg.type === 'response' && pendingTx.has(msg.id)) {
      const settle = pendingTx.get(msg.id);
      pendingTx.delete(msg.id);
      settle(settleValue(msg));
    }
  };

  ws.onclose = () => {
    wssSubscribeOk = false; // ab hier kann kein Abo dieses Sockets mehr liefern
    // Socket-Tod im WSS-Live-Betrieb: 'wss' ist sticky und würde weiter
    // 'Live – WSS verbunden' zeigen, obwohl die Datenquelle ab jetzt der
    // Snapshot-Fallback ist (onLedgerEvent stellt 'wss' wieder her).
    if (liveMode === 'wss') liveMode = 'poll';
    if (liveMode !== 'poll') setConn(false, t('conn.closed', { s: Math.round(wsBackoff / 1000) }));
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
/* Fehler-Backoff (Befund 2026-09-30): Der Watchdog rief pollSnapshotFallback
 * bei dauerhaftem Fehler unverändert alle 5 s auf — der Server wiederholt je
 * Anfrage 3 RPC-Versuche, ein gedrosselter Endpunkt wurde also mit bis zu 36
 * Versuchen/min weiter belastet statt entlastet. Wie beim WSS-Reconnect
 * (wsBackoff) verdoppelt sich der Abstand je Fehlversuch (5 s → 60 s Deckel);
 * ein erfolgreicher Poll und wieder fließende WSS-Events setzen ihn zurück. */
let pollFailCount = 0;      // aufeinanderfolgende fehlgeschlagene Snapshot-Polls
let pollBackoffUntil = 0;   // bis zu diesem Zeitpunkt bleibt /api/ledger ausgesetzt

async function pollSnapshotFallback() {
  // Snapshot-Zyklus zieht die Bait-Hash-Allowlist mit (Mindestabstand beachten).
  refetchBaitHashes(false);
  try {
    const body = await fetchJson('/api/ledger');
    // Endpunkt erreichbar: Backoff zurücksetzen (auch ohne neuen Ledger-Index).
    pollFailCount = 0;
    pollBackoffUntil = 0;
    const idx = body?.ledgerIndex;
    if (idx == null) return;
    if (!seenLedgers.has(idx)) {
      seenLedgers.add(idx);
      lastLedgerAt = Date.now();
      liveMode = 'poll';
      const txCount = Number(body.stats?.txs ?? 0);
      const resolved = Number(body.resolvedTxCount ?? 0);
      // Köder-Filter (Snapshot-Pfad, Befund 2026-09-30): Der Server filtert
      // bereits über baitLabels (server/index.mjs /api/ledger, api/ledger.js),
      // aber bei leerem BAIT_ADDRESSES-ENV wäre der Server-Filter inaktiv —
      // derselbe clientseitige Hash-Deny-Recheck wie im WSS-Pfad (Köder-Filter
      // in onLedgerEvent) hält Köder-Funde aus Live-Log und JSON-Export fern.
      const findings = [];
      for (const f of Array.isArray(body.findings) ? body.findings : []) {
        if (!(await isDeniedAddrAsync(f?.address))) findings.push(f);
      }
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
    // Fehler-Backoff fortschreiben (5 s → 10 s → 20 s → 40 s → 60 s Deckel).
    pollFailCount += 1;
    pollBackoffUntil = Date.now() + Math.min(
      POLL_BACKOFF_BASE_MS * 2 ** Math.min(pollFailCount - 1, 5),
      POLL_BACKOFF_MAX_MS,
    );
    if (liveMode !== 'wss') {
      // Drosselungs-Kontext bleibt sichtbar (Befund 2026-09-30): Lehnt das
      // WSS-Abo bereits mit tooBusy/rate limit ab, wäre der generische
      // Fehltext ein Informationsverlust — connLabel() nennt die Endpunkt-
      // Drosselung samt Schätzung, der Snapshot-Fehler wird angehängt.
      const msg = err && err.message ? String(err.message) : t('conn.unknownError');
      if (liveMode === 'poll' && wssSubscribeError && wssSubscribeError.throttled) {
        setConn(false, t('conn.snapshotUnreachable', { label: connLabel(), msg }));
      } else {
        setConn(false, t('conn.noData', { msg }));
      }
    }
  }
}

async function watchdog() {
  // Liveness mit der EIGENEN WS-Uhr lastWsMsgAt (onopen + jede Message) —
  // bewusst NICHT lastLedgerAt: pollSnapshotFallback setzt das ebenfalls bei
  // jedem NEUEN Snapshot-Index (~alle 60 s), eine Kopplung an STALL_MS (12 s)
  // würde im gesunden Poll-Betrieb Dauerfeuern/Reconnect-Stürme auslösen.
  // WS_STALL_MS (90 s) liegt über dem beobachteten 60-s-Server-Idle-Close und
  // weit über dem ~4-s-Event-Takt: Ein Socket, der 90 s komplett stumm ist
  // (NAT-Timeout, Suspend/Resume ohne close-Frame, Endpunkt-Stall), ist ein
  // Zombie — auch wenn liveMode sticky 'wss' ist (live-observiert: Offline-
  // Emulation ließ die Statuszeile 'WSS verbunden' zeigen, obwohl 0 Events
  // ankamen). Aktiver close; onclose trägt den Reconnect nach (Backoff aktiv).
  if (ws && ws.readyState === 1 && Date.now() - lastWsMsgAt > WS_STALL_MS) {
    if (liveMode === 'wss') liveMode = 'poll'; // Quelle ab jetzt: Snapshot-Fallback
    try { ws.close(); } catch { /* egal — onclose fehlt dann, nächster Zyklus */ }
  }
  if (Date.now() - lastLedgerAt < STALL_MS) {
    if (liveMode === 'wss' || liveMode === 'poll') setConn(true, connLabel());
    return;
  }
  // Fehler-Backoff (Befund 2026-09-30): Während des Backoff-Fensters bleibt
  // /api/ledger ausgesetzt — der Watchdog-Takt allein darf den gedrosselten
  // Endpunkt nicht weiter im 5-s-Takt belasten.
  if (Date.now() < pollBackoffUntil) return;
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
document.getElementById('stat-network').textContent = t('net.mainnet');
connectLive();
setInterval(watchdog, WATCHDOG_MS);
// Bait-Hash-Allowlist: beim Start, alle 60 s und bei jedem Snapshot-Zyklus.
refetchBaitHashes(true);
setInterval(() => { refetchBaitHashes(true); }, BAIT_HASH_REFETCH_MS);

/* ---------- i18n-Bootstrap ----------
 * Sprache anwenden (persistiert oder Default 'en'), statische Texte des
 * index.html übersetzen, Sprachumschalter im Header einsetzen.
 * 'hx:langchange' re-rendert alle dynamischen Sichten, die der Host besitzt;
 * die Module (drilldown/globe/history/account-check) re-agieren selbst oder
 * werden über ihre refresh-API nachgezogen. */
applyLang();
applyStatic(document);
initLangSwitcher(document.getElementById('lang-switch'));
document.addEventListener('hx:langchange', () => {
  applyStatic(document);
  buildRuleFilter();
  renderLog();
  updateLiveStats();
  document.getElementById('stat-network').textContent = t('net.mainnet');
  setConn(liveMode !== 'init', connLabel());
  if (lastClusterGraph) {
    renderLiveGraph(lastClusterGraph);
    renderClusterList(lastClusterGraph.clusters);
  }
  if (drilldown && typeof drilldown.refresh === 'function') drilldown.refresh();
  if (globeMod && typeof globeMod.refresh === 'function') globeMod.refresh(true);
  if (historyMod && typeof historyMod.refresh === 'function') historyMod.refresh();
  if (checkMod && typeof checkMod.reRender === 'function') checkMod.reRender();
});
