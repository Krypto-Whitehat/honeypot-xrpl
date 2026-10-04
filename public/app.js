'use strict';

/* Honeypot XRPL – Frontend (ESM-Modul)
 *
 * Hauptansicht: BLOCK-FEED + AKTEUR-CLUSTERING, zweimodig (API-Vertrag v2,
 * 2026-10-02):
 *   - STANDARD 'history' (Serverdaten, KEIN automatischer Besucher-WSS):
 *     GET /api/block-window?range=24h|3d|7d liefert Stunden-Rollups
 *     (buckets) + geflaggte Blockdetails im Volltext (flagged) — der Feed
 *     zeigt die geflaggten Blöcke des Fensters, der Stundenchart die
 *     Vollständigkeit; ungeflaggte Blöcke sind nur zählbar (ehrliche Tiefe,
 *     lib/block-window.mjs). GET /api/flow-state liefert die serverseitig
 *     bait-gefilterte, gekappte Cluster-View (Cursor + validatedIndex).
 *     Polling 60 s, sichtbarkeits-gated; Fail-closed-200 ohne Persistenz
 *     wird als ehrlicher Leerzustand dargestellt (reason-Vergleich bleibt
 *     roh — Protokollwert, Muster public/history.js:361).
 *   - OPT-IN 'live' (Modus-Auswahl im Live-Panel): direkter WSS auf
 *     wss://honeycluster.io (offiziell gelisteter Full-History-Server,
 *     config.json:3). Abo streams:['ledger'] liefert nur Header; pro Block
 *     wird GENAU EIN "ledger"-Kommando (transactions:true, expand:true)
 *     gesendet — expand:true bringt alle Tx-Objekte (hash + metaData) in
 *     einem Request, die a.D. Hash-Auflösung (MAX_RESOLVE/strideHashes) und
 *     das Sampling (ANALYZE_EVERY_N_BLOCKS) entfallen. Jeder Request läuft
 *     über den Token-Bucket aus lib/rate-gate.mjs (10/s, Burst 50, 20
 *     Start-Tokens — honeycluster-Limits); tooBusy/slowDown behandelt der
 *     Client wie HTTP 429 (retry-Delta + Cooldown, defensiv — echte
 *     Throttle-Semantik ist UNVERIFIED).
 *   - Analyse jedes Blocks mit analyzeLedger aus lib/detector.mjs —
 *     dieselbe Engine wie serverseitig (single source of truth).
 *   - Cluster-Schicht: rollendes Fenster der analysierten Tx-Records und
 *     Findings wird pro Ledger an buildClusterGraph()/txRecordFromEntry()
 *     aus lib/cluster.mjs übergeben (dynamischer Import mit Null-Guard;
 *     bei Import-Fehlschlag läuft der Feed unverändert weiter). Im
 *     Server-Modus ersetzt die /api/flow-State-View den clientseitigen
 *     Neubau (serverseitiger baitFilter + Pruning). Graph-Panel mit Tabs
 *     "Live-Netz" (inkrementell), "Cluster" (vis-network-Clustering mit
 *     aufklappbaren Bubbles) plus Cluster-Zusammenfassungs-Karten.
 *   - Feed-Standard: letzte 5 Einträge sichtbar, 'Mehr laden' blendet je 10
 *     weitere ein (44-px-Button, i18n-Keys).
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
/* Rate-Gate (lib/rate-gate.mjs via /lib-Whitelist api/lib-detector.js:16):
 * DOM-freier Token-Bucket für den Opt-in-LIVE-Modus. Dynamischer Import mit
 * Null-Guard — ohne Gate startet der Live-Modus NICHT (fail-closed,
 * Konsole-Meldung), der Server-Standardbetrieb bleibt unberührt. */
let rateGateFactory = null;
import('/lib/rate-gate.mjs')
  .then((m) => {
    rateGateFactory = typeof m.createRateGate === 'function' ? m.createRateGate : null;
  })
  .catch(() => { /* Gate offline (z. B. 404): Live-Modus bleibt gesperrt */ });
/* i18n: statischer Import (durch vercel.json-Rewrite /i18n.mjs gedeckt).
 * EN/DE ist damit vor dem ersten Render garantiert initialisiert; ein 404
 * von /i18n.mjs würde das ganze Modul stoppen — bewusst die konsistentere
 * Alternative zum fehlertoleranten dynamischen Import (Muster globe.js). */
import {
  t, ruleName, noteText, sevText, serverPhrase,
  fmtNum, fmtXrp, fmtClock, fmtDateTime,
  applyStatic, applyLang, initLangSwitcher,
} from './i18n.mjs';

/* Cluster-Modul: nicht-blockierender dynamischer Import. Der Live-Feed startet
 * sofort; die Cluster-Schicht aktiviert sich, sobald das Modul eintrifft
 * (Guard in onLedgerEvent). Ein Top-Level-Await würde initGraph()/connectLive()
 * um die Import-Latenz verzögern und ist bewusst nicht verwendet. */
let buildClusterGraph = null;
let txRecordFromEntry = null;
let flowPathsFn = null;
let detectPeelingChainsFn = null;
import('/lib/cluster.mjs')
  .then((m) => {
    buildClusterGraph = typeof m.buildClusterGraph === 'function' ? m.buildClusterGraph : null;
    txRecordFromEntry = typeof m.txRecordFromEntry === 'function' ? m.txRecordFromEntry : null;
    flowPathsFn = typeof m.flowPaths === 'function' ? m.flowPaths : null;
    detectPeelingChainsFn = typeof m.detectPeelingChains === 'function' ? m.detectPeelingChains : null;
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
        // Asynchrone Deny-Prüfung für den JSON-Export des Modals: die synchrone
        // isDeniedAddr verneint ungehashte Adressen (LRU-Kappung möglich) — der
        // Export muss erst hashen, dann prüfen (fail-closed für ungeprüfte
        // Adressen, Kritik 2026-10-04).
        isDeniedAddrAsync,
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

/* Datenquellen-Modi (API-Vertrag v2, 2026-10-02):
 *   'history' (Standard): Server-Fenster GET /api/block-window?range=… +
 *   Cluster GET /api/flow-state — Polling 60 s, sichtbarkeits-gated, KEIN
 *   automatischer Besucher-WSS.
 *   'live' (Opt-in): WSS honeycluster.io, Abo Header-only, pro Block GENAU
 *   EIN ledger-Kommando (expand:true) über den lib-Rate-Limiter — ohne
 *   Sampling, ohne Hash-Auflösung. Die a.D. Kalibrierung
 *   (ANALYZE_EVERY_N_BLOCKS/MAX_RESOLVE/QUOTA_CALLS_PER_MIN, xrplcluster-
 *   Units-Quota) entfällt mit dem honeycluster-Vertrag: 1 Request/Block
 *   ≈ 2,5 req/s bei ~4 s Blocktakt, unter dem 10-req/s-steady-Limit. */
const WSS_URL = 'wss://honeycluster.io';
const LEDGER_TIMEOUT_MS = 10000;   // Timeout pro "ledger"-Kommando
const RATE_GATE_OPTS = { ratePerSec: 10, burstCapacity: 50, initialTokens: 20 };
                                   // honeycluster-Limits (Nutzer-Angabe
                                   // 2026-10-02; lib/rate-gate.mjs modelliert
                                   // sie konservativ: refill 10/s, Kap 50, Start 20)
const GATE_WAIT_MAX_MS = 20000;    // Gate-Warte-Deckel pro Block: länger als
                                   // 20 s zu warten heißt, der Blocktakt übersteigt
                                   // die Rate — ehrliches Skip-Badge statt Rückstau
const QUOTA_COOLDOWN_FALLBACK_MS = 65000; // tooBusy ohne parsebares retry-Delta
const QUOTA_COOLDOWN_MAX_MS = 120000;     // Cooldown-Deckel
const SUBSCRIBE_ID = 1;            // feste Request-Id des ledger-Abos (reqId
                                   // startet bei 1000 — keine Kollision)
const WS_PROBE_MIN_MS = 15000;     // Untergrenze des Sonden-Abstands (billig,
                                   // aber kein Hämmern gegen das erschöpfte Quota)
const WS_PROBE_MAX_MS = 90000;     // Obergrenze (≤120 s laut Diagnose): Abstand
                                   // zweier subscribe-Versuche, von der App
                                   // selbst gesteuert statt am Server-Idle-Close
const WS_STALL_MS = 90000;         // Liveness-Schwelle der EIGENEN WS-Uhr —
                                   // bewusst ÜBER dem beobachteten 60-s-Idle-Close
const FEED_CARDS = 24;             // Block-Karten im Feed (Live-Modus)
const FEED_INITIAL = 5;            // sichtbare Feed-Einträge (Standard, beide Modi)
const FEED_STEP = 10;              // 'Mehr laden' blendet je 10 weitere ein
const LOG_MAX = 400;               // Log-Einträge im Speicher
const LOG_RENDER_MAX = 200;        // gerenderte Log-Zeilen
const WATCHDOG_MS = 5000;          // Live-Zombie-Prüfintervall (nur im Live-Modus)
const SERVER_POLL_MS = 60000;      // 60-s-Polling flow-state + block-window (Vertrag)
const POLL_BACKOFF_BASE_MS = 5000; // Server-Poll: Backoff-Start nach Fehlversuch
const POLL_BACKOFF_MAX_MS = 60000; // Backoff-Deckel — ein dauerhaft fehlschlagender
                                   // Endpunkt wird entlastet, statt im Minutentakt
                                   // weiter belastet zu werden (Befund 2026-09-30)
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
    background: '#16305c', border: '#0f2445',
    highlight: { background: '#2a4a7c', border: '#0f2445' },
    hover: { background: '#2a4a7c', border: '#0f2445' },
  },
  drainer: {
    background: '#b3261e', border: '#7f1d1d',
    highlight: { background: '#d03b33', border: '#7f1d1d' },
    hover: { background: '#d03b33', border: '#7f1d1d' },
  },
  collector: {
    background: '#b45309', border: '#7c3a06',
    highlight: { background: '#c96a1f', border: '#7c3a06' },
    hover: { background: '#c96a1f', border: '#7c3a06' },
  },
  relay: {
    background: '#0f766e', border: '#115e59',
    highlight: { background: '#1a8d84', border: '#115e59' },
    hover: { background: '#1a8d84', border: '#115e59' },
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

// Zwei-Zeilen-Knotenlabel (B2): volle Adresse nur bei isFullShownAddr (Allowlist
// geladen, kein Deny-Treffer — dasselbe Gate wie displayFindingAddr, 1454-1458);
// bei voller Adresse Umbruch nach Zeichen 24 (vis-network 10.1.2 rendert '\n'
// im Label), sonst unverändert shortAddr (275-278) wie bisher. Die Kurzfassung
// bleibt in den dokumentierten Fail-closed-Zuständen erhalten.
function graphLabel(id) {
  const s = String(id ?? '');
  if (s && isFullShownAddr(s)) return s.length > 24 ? `${s.slice(0, 24)}\n${s.slice(24)}` : s;
  return shortAddr(s);
}

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
    // Knotenlabel (B2): volle Adresse bei geladener Allowlist und Nicht-Treffer
    // auf der Deny-Liste — sonst Kurzform wie bisher (displayFindingAddr-Gate,
    // fail-closed). Volle Adressen werden nach Zeichen 24 umgebrochen
    // (graphLabel), damit sie nicht einzeilig am Graph-Rand kleben; das
    // title-Tooltip bleibt displayFindingAddr.
    const label = graphLabel(n.id);
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
  // B4: kein .slice(0, 8) mehr — die volle Liste läuft durch
  // displayFindingAddr (volle Adresse bei geladener Allowlist und
  // Nicht-Treffer auf der Deny-Liste, sonst Kurzform; Gate unverändert).
  const members = (Array.isArray(c.memberAddresses) ? c.memberAddresses : [])
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
  // Persistierte Peeling-Ketten der Server-View (Kritik 4): die Flusskette
  // zeigt sie zusätzlich, wenn vorhanden — Kettenreihenfolge Seed→…→Ende,
  // Brückenknoten als Relay gezeichnet (sie erhalten bewusst keine eigene
  // Rolle im Graphen, nur die Ketten-Position).
  if (Array.isArray(c.peelingChains) && c.peelingChains.length) {
    const bridgeSet = new Set();
    for (const ch of c.peelingChains) for (const b of ch?.bridges ?? []) bridgeSet.add(String(b));
    const peelingPaths = c.peelingChains
      .filter((ch) => Array.isArray(ch?.addresses) && ch.addresses.length >= 2)
      .map((ch) => ch.addresses.map((a) => ({
        id: String(a),
        role: (c.roles && c.roles[String(a)]) || (bridgeSet.has(String(a)) ? 'relay' : 'unknown'),
      })));
    const peelingHtml = flowChainHtml(peelingPaths, { maxChips: 12 });
    if (peelingHtml) chainInner = chainInner ? `${chainInner}<span class="chain-path-sep" aria-hidden="true">·</span>${peelingHtml}` : peelingHtml;
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
  // A7: Export-Button für die Clusterliste — Sichtbarkeit folgt direkt dem
  // Cluster-Bestand (nicht setGraphTab: das steigt bei !network aus (900) und
  // wird von Data-Ticks (rebuildClusterGraph/applyFlowStateView) gar nicht
  // aufgerufen). hidden=true ohne Cluster — Export nur bei Cluster-Gates.
  const dlBtn = document.getElementById('cluster-list-download');
  const dlNote = document.getElementById('cluster-list-note');
  const arr = Array.isArray(clusters) ? clusters : [];
  if (dlBtn) dlBtn.hidden = arr.length === 0;
  if (dlNote) dlNote.hidden = arr.length === 0;
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

/* A6 — Export der gesamten Cluster-Liste (Blob-Download, kein api/-Endpunkt):
 * lastClusterGraph.clusters (WSS-Pfad rebuildClusterGraph bzw. Flow-State-Pfad
 * applyFlowStateView). Jede Adresse (members, edges-Enden, peelingChains —
 * letztere nur im Flow-State-View, lib/flow-state.mjs; in lib/cluster.mjs gibt
 * es sie nicht, grep 0 Treffer) wird vor dem Export asynchron durch
 * isDeniedAddrAsync geprüft; verweigerte Adressen entfallen ersatzlos. Der
 * WSS-Pfad filtert Köder bereits beim Neubau (rebuildClusterGraph), der Export
 * prüft trotzdem erneut, weil die Deny-Liste serverseitig alle 5 s rotiert. */
async function exportClusterList() {
  const clusters = lastClusterGraph && Array.isArray(lastClusterGraph.clusters) ? lastClusterGraph.clusters : [];
  if (!clusters.length) return;
  const out = [];
  for (const c of clusters) {
    const members = (Array.isArray(c.memberAddresses) ? c.memberAddresses : []).map(String);
    // Kanten je Cluster: die Server-View trägt c.edges (applyFlowStateView);
    // der WSS-Pfad (lib/cluster.mjs) führt Kanten nur global im Graph — sie
    // werden wie in clusterCardHtml gegen die Mitglieder gefiltert.
    const memberSet = new Set(members);
    const rawEdges = Array.isArray(c.edges) && c.edges.length
      ? c.edges
      : (lastClusterGraph && Array.isArray(lastClusterGraph.edges) ? lastClusterGraph.edges : [])
        .filter((e) => memberSet.has(String(e.from ?? '')) && memberSet.has(String(e.to ?? '')));
    const edges = rawEdges.map((e) => ({
      from: String(e.from ?? ''),
      to: String(e.to ?? ''),
      txHash: e.txHash != null ? String(e.txHash) : null,
      closeTime: e.closeTime != null ? String(e.closeTime) : null,
      type: String(e.type ?? ''),
    })).filter((e) => e.from && e.to);
    const chains = (Array.isArray(c.peelingChains) ? c.peelingChains : [])
      .map((ch) => ({
        seed: String(ch?.seed ?? ''),
        addresses: (Array.isArray(ch?.addresses) ? ch.addresses : []).map(String),
        bridges: (Array.isArray(ch?.bridges) ? ch.bridges : []).map(String),
        hopsCount: Number(ch?.hopsCount ?? 0) || 0,
      }))
      .filter((ch) => ch.addresses.length >= 2);
    // Deny-Nachprüfung je Adresse (async — hashen dann prüfen):
    const denied = new Set();
    const addrs = new Set(members);
    for (const e of edges) { addrs.add(e.from); addrs.add(e.to); }
    for (const ch of chains) { addrs.add(ch.seed); for (const a of ch.addresses) addrs.add(a); }
    for (const a of addrs) {
      if (await isDeniedAddrAsync(a)) denied.add(a);
    }
    const rolesByAddress = {};
    const severityByAddress = {};
    // Rollenquelle: Server-View trägt rolesByAddress, der WSS-Pfad
    // (lib/cluster.mjs) führt dieselbe Adresse->Rolle-Tafel als c.roles.
    for (const [a, role] of Object.entries(c.rolesByAddress ?? c.roles ?? {})) {
      if (!denied.has(a)) rolesByAddress[a] = String(role);
    }
    for (const [a, sev] of Object.entries(c.severityByAddress ?? {})) {
      if (!denied.has(a)) severityByAddress[a] = String(sev);
    }
    out.push({
      cluster: { id: c.id, label: c.label ?? null },
      totalDrops: Number(c.totalDrops ?? 0) || 0,
      txCount: Number(c.txCount ?? 0) || 0,
      distinctAccounts: Number(c.distinctAccounts ?? 0) || 0,
      firstSeen: c.firstSeen ?? null,
      lastSeen: c.lastSeen ?? null,
      members: members.filter((a) => !denied.has(a)),
      rolesByAddress,
      severityByAddress,
      edges: edges.filter((e) => !denied.has(e.from) && !denied.has(e.to)),
      peelingChains: chains
        .map((ch) => ({ ...ch, addresses: ch.addresses.filter((a) => !denied.has(a)) }))
        .filter((ch) => ch.addresses.length >= 2),
    });
  }
  const payload = {
    exportedAt: new Date().toISOString(),
    source: t('export.source'),
    note: t('export.clusterNote'),
    clusterCount: out.length,
    clusters: out,
  };
  const blob = new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = `honeypot-xrpl-cluster-list-${new Date().toISOString().replace(/[:T]/g, '-').slice(0, 16)}.json`;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(a.href), 2000);
}

/* C2 — PNG-Export des vis-network-Graphen (Canvas-zu-PNG, kein api/-Endpunkt):
 * vis-network rendert in einen Canvas unter #graph. vis-networks eigene
 * getCanvas() (10.1.2) wird bevorzugt, DOM-Fallback #graph canvas — die
 * API-Verfügbarkeit ist in dieser Session nicht ausgeführt, beide Pfade sind
 * guardiert. Der vis-Canvas hat transparenten Hintergrund: vor dem Export auf
 * ein weißes Ziel (Bühnenfarbe --a6-graph-canvas) gezeichnet, sonst wäre das
 * PNG schwarz. Weltkugel (#globe) und Modal-3D sind WebGL-Canvas ohne
 * preserveDrawingBuffer (grep 0 Treffer in globe.js) — ein Export würde schwarz
 * ausfallen; er ist bewusst NUR für das vis-Netz vorgesehen. */
function exportGraphPng() {
  const stage = document.getElementById('graph');
  if (!stage) return;
  let src = null;
  try {
    if (network && typeof network.getCanvas === 'function') src = network.getCanvas();
  } catch { /* getCanvas nicht verfügbar: DOM-Fallback unten */ }
  if (!src || typeof src.toBlob !== 'function') src = stage.querySelector('canvas');
  if (!src || typeof src.toBlob !== 'function') return; // kein exportierbarer Canvas
  const w = src.width || 0;
  const h = src.height || 0;
  if (!w || !h) return;
  const target = document.createElement('canvas');
  target.width = w;
  target.height = h;
  const ctx2d = target.getContext('2d');
  if (!ctx2d) return;
  ctx2d.fillStyle = '#ffffff';
  ctx2d.fillRect(0, 0, w, h);
  ctx2d.drawImage(src, 0, 0);
  target.toBlob((blob) => {
    if (!blob) return;
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = `honeypot-xrpl-graph-${new Date().toISOString().replace(/[:T]/g, '-').slice(0, 16)}.png`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(a.href), 2000);
  }, 'image/png');
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
  // A6/C1: Export-Buttons im Graph-Panel-Head (außerhalb der role="tablist" —
  // die Tablist-Struktur #tab-live/#tab-cluster/#tab-globe bleibt unverändert).
  document.getElementById('cluster-list-download').addEventListener('click', () => { void exportClusterList(); });
  document.getElementById('graph-png').addEventListener('click', exportGraphPng);
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
/* BLOCK-FEED: Server-Fenster (Standard) + Opt-in-LIVE-WSS            */
/* ------------------------------------------------------------------ */

const RULE_CATALOG = ruleCatalog();
const RULE_NAME = new Map(RULE_CATALOG.map((r) => [r.id, r.name]));

const liveStats = { ledgers: 0, txs: 0, malicious: 0, suspect: 0, info: 0 };
const logEntries = [];              // {t, ledgerIndex, ruleId, severity, address, note}
const firstSeenAt = new Map();      // Konto -> Zeitstempel der ersten Sichtung (Stream-Fenster)
// Cross-Ledger-Gedächtnis der Engine (ctx.history): Konto -> {tinyDests:Set,
// fundedAt, createdInWindow, lastLedger}. Modul-Level wie firstSeenAt —
// buildCtx wird pro Ledger-Ereignis aufgerufen, die Map überlebt die
// Aufrufe; ohne persistenten Träger wäre history auf einen Aufruf beschränkt.
// Begrenzung: ~FIRST_SEEN_MAX Konten / 200 Ledger (siehe buildCtx-Prune).
const ledgerHistory = new Map();
const HISTORY_MAX_LEDGERS = 200;
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
let feedMode = 'history';           // 'history' (Standard: Serverdaten) | 'live' (Opt-in WSS)
let feedRange = '24h';              // Fenster des Server-Modus (24h|3d|7d)
let liveMode = 'init';              // Live-Modus intern: 'init' | 'wss'
// honeycluster drosselt JSON-Kommandos (Nutzer-Angabe: 10 req/s steady,
// Burst 50/5 s, 20 Start-Tokens). Bei tooBusy/slowDown pausiert die
// Block-Analyse sichtbar statt Karten still leer zu lassen. Die echte
// Throttle-Semantik des Endpunkts ist UNVERIFIED — alle Behandlung ist
// defensiv (retry-Delta + Cooldown, wie a.D. gegen xrplcluster tooBusy).
let quotaCooldownUntil = 0;
let analysisInFlight = false;      // Serialisierungsguard: genau eine Block-
                                   // Analyse gleichzeitig (siehe onLedgerEvent)
let rateGate = null;               // Token-Bucket-Instanz (lib/rate-gate.mjs) für den Live-Modus

/* ---------- Server-Fenster-Zustand (Standard-Modus) ---------- */
let windowData = null;             // letzte /api/block-window-Antwort
let flowData = null;               // letzte /api/flow-state-Antwort
let serverPollFailCount = 0;       // aufeinanderfolgende fehlgeschlagene Polls
let serverPollBackoffUntil = 0;    // bis dahin bleiben beide Polls ausgesetzt
let serverPollTimer = null;        // 60-s-Timer, sichtbarkeits-gated
let windowRenderSig = null;        // Render-Dedup gegen identische Fensterdaten

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
  if (feedMode === 'history') {
    // Server-Standard: Status folgt dem Fenster-Poll, nicht einem Socket.
    if (windowData && windowData.reason) return t('feed.persistOff');
    if (windowData && Array.isArray(windowData.buckets) && windowData.buckets.length) return t('conn.server');
    if (windowData) return t('conn.serverNoData');
    return t('conn.serverLoading');
  }
  if (liveMode === 'wss') {
    if (wssSubscribeError) {
      // Volle Server-Schätzung (retry-Delta) NUR hier im Text — der
      // Sonden-Rhythmus bleibt auf min(Delta, 90 s) geklemmt.
      const rest = wssSubscribeError.retryMs
        ? Math.max(0, wssSubscribeError.at + wssSubscribeError.retryMs - Date.now())
        : 0;
      const est = rest > 0 ? t('conn.estSuffix', { dur: fmtDur(rest) }) : '';
      if (wssSubscribeError.throttled) {
        return t('conn.liveThrottled', { est });
      }
      // Server-Fehlerwert (error) bleibt roh interpoliert — Protokollwert.
      return t('conn.liveRejected', { error: wssSubscribeError.error, est });
    }
    // Abo frisch angenommen: 'verbunden' schon mit dem ersten erfolgreichen
    // subscribe-Versuch (Events folgen in ~4 s). Bleiben Events dauerhaft aus,
    // fällt die Anzeige danach ehrlich auf den wartenden Text.
    if (wssSubscribeOk && Date.now() - wssSubscribeOkAt < WSS_SUBSCRIBE_OK_WINDOW_MS) {
      return t('conn.wss');
    }
    return t('conn.liveNoEvents');
  }
  return t('conn.liveInit');
}

function buildCtx() {
  // history-Begrenzung: ~FIRST_SEEN_MAX Konten / 200 Ledger. Über die
  // Ledger-Spanne hinaus alte Einträge fallen raus (deterministisch nach
  // lastLedger asc).
  if (ledgerHistory.size > FIRST_SEEN_MAX) {
    let minLedger = Infinity;
    for (const h of ledgerHistory.values()) {
      const l = Number(h?.lastLedger);
      if (Number.isFinite(l) && l < minLedger) minLedger = l;
    }
    if (Number.isFinite(minLedger)) {
      for (const [addr, h] of ledgerHistory) {
        if (ledgerHistory.size <= FIRST_SEEN_MAX) break;
        if (Number(h?.lastLedger) === minLedger) ledgerHistory.delete(addr);
      }
    }
  }
  let minL = Infinity;
  let maxL = -Infinity;
  for (const h of ledgerHistory.values()) {
    const l = Number(h?.lastLedger);
    if (!Number.isFinite(l)) continue;
    if (l < minL) minL = l;
    if (l > maxL) maxL = l;
  }
  if (Number.isFinite(minL) && maxL - minL > HISTORY_MAX_LEDGERS) {
    const cutoff = maxL - HISTORY_MAX_LEDGERS;
    for (const [addr, h] of ledgerHistory) {
      if (Number(h?.lastLedger) < cutoff) ledgerHistory.delete(addr);
    }
  }
  return {
    knownBad,
    firstSeenAt,
    history: ledgerHistory,
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

/* ---------- Feed-Sichtbarkeit (Standard: letzte 5 Einträge) ---------- */
/* Der Feed zeigt standardmäßig nur die letzten FEED_INITIAL Einträge;
   'Mehr laden' (44 px, i18n) blendet je FEED_STEP weitere ein. Die Karten
   bleiben im DOM (Analyse-Badges bleiben erhalten), nur die Sichtbarkeit
   wechselt — ein Reload des Feeds ist dafür nie nötig. */
let feedVisibleCount = FEED_INITIAL;

function updateFeedVisibility() {
  const feed = document.getElementById('block-feed');
  const moreBtn = document.getElementById('feed-more');
  const cards = feed.children;
  for (let i = 0; i < cards.length; i++) cards[i].hidden = i >= feedVisibleCount;
  moreBtn.hidden = cards.length <= feedVisibleCount;
  document.getElementById('feed-empty').hidden = cards.length > 0;
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
  updateFeedVisibility();
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

async function downloadLog() {
  // B6: Adressen im exportierten JSON zusätzlich durch die asynchrone
  // Deny-Prüfung (isDeniedAddrAsync, hashen dann prüfen) — displayFindingAddr
  // allein genügt nicht, weil bei nicht geladener Allowlist die Kurzform
  // exportiert würde, die Deny-Liste aber serverseitig alle 5 s rotiert.
  // Verweigerte Adressen werden ersatzlos entfernt (nicht maskiert); der
  // count-Feld spiegelt den gefilterten Bestand.
  const kept = [];
  for (const e of logEntries) {
    if (await isDeniedAddrAsync(e.address)) continue;
    kept.push(e);
  }
  const payload = {
    exportedAt: new Date().toISOString(),
    source: t('export.source'),
    network: document.getElementById('stat-network').textContent,
    note: t('export.note'),
    count: kept.length,
    entries: kept.map((e) => ({
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

/* ================================================================== */
/* SERVER-FENSTER (Standard-Modus): GET /api/block-window + flow-state */
/* ================================================================== */
/* Polling 60 s, sichtbarkeits-gated (Muster public/history.js:391-396):
 * unsichtbare Tabs erzeugen keinen Netz-Traffic. Fehler-Backoff wie a.D.
 * (5 s → 60 s Deckel): ein fehlschlagender Endpunkt wird entlastet statt
 * weiter belastet. Fail-closed-200 ohne Persistenz (reason-Feld) ist KEIN
 * Fehler: ehrlicher Leerzustand mit Persistenz-Hinweis. Der reason-
 * Vergleich bleibt ROH — Server-Protokollwert (Muster public/history.js:361,
 * api/block-window.js:78); nur die Anzeige folgt der aktuellen Sprache. */

function windowTotals(buckets) {
  let blocks = 0, txns = 0, flaggedBlocks = 0;
  for (const b of Array.isArray(buckets) ? buckets : []) {
    blocks += Number(b?.blocks) || 0;
    txns += Number(b?.txns) || 0;
    flaggedBlocks += Number(b?.flaggedBlocks) || 0;
  }
  return { blocks, txns, flaggedBlocks };
}

function renderWindowNote() {
  const el = document.getElementById('feed-note');
  if (feedMode !== 'history' || !windowData) { el.hidden = true; return; }
  if (windowData.reason === 'Persistenz nicht konfiguriert') {
    el.textContent = t('feed.persistOff');
    el.hidden = false;
    return;
  }
  const totals = windowTotals(windowData.buckets);
  el.textContent = t('feed.windowNote', {
    range: t('range.' + (windowData.range || feedRange)),
    blocks: fmtNum(totals.blocks),
    txns: fmtNum(totals.txns),
    flagged: fmtNum(totals.flaggedBlocks),
    time: fmtDateTime(windowData.updatedAt ?? windowData.to),
  });
  el.hidden = false;
}

/* Stunden-Rollup als SVG-Balken (Muster history-host.html: selbstständig,
 * keine externe Abhängigkeit, Farben ausschließlich aus bestehenden Tokens:
 * tonale Blöcke, geflaggte Stunden in der bestehenden --a6-error-Tinte).
 * x-Achse: Zeitachse des Fensters (Lücken sichtbar — ehrliche Vollständigkeit);
 * Höhe: Txs/h; Titel je Balken: Blöcke/Txs/Flags. */
function renderWindowChart() {
  const box = document.getElementById('feed-chart');
  if (feedMode !== 'history' || !windowData || !Array.isArray(windowData.buckets) || !windowData.buckets.length) {
    box.innerHTML = '';
    box.hidden = true;
    return;
  }
  const buckets = windowData.buckets;
  const HOUR_MS = 3600 * 1000;
  const from = Number(windowData.from);
  const to = Number(windowData.to);
  const span = Number.isFinite(from) && Number.isFinite(to) && to > from ? to - from : buckets.length * HOUR_MS;
  const W = 760, H = 120, PAD = 6;
  const maxTxns = Math.max(1, ...buckets.map((b) => Number(b?.txns) || 0));
  const barW = Math.max(2, Math.min(14, (W - 2 * PAD) / (span / HOUR_MS) - 2));
  const parts = [];
  parts.push('<svg viewBox="0 0 ' + W + ' ' + H + '" role="img" aria-label="' + esc(t('chart.aria')) + '">');
  for (const b of buckets) {
    const tMs = Number(b?.t);
    if (!Number.isFinite(tMs)) continue;
    const x = PAD + ((tMs - from) / span) * (W - 2 * PAD);
    const txns = Number(b?.txns) || 0;
    const blocks = Number(b?.blocks) || 0;
    const flagged = Number(b?.flaggedBlocks) || 0;
    const h = Math.max(2, Math.round((txns / maxTxns) * (H - 2 * PAD)));
    const fill = flagged > 0 ? 'var(--a6-error)' : 'var(--a6-control-line)';
    const title = esc(fmtDateTime(tMs)) + ' · ' + fmtNum(blocks) + ' blocks · ' + fmtNum(txns) + ' txs'
      + (flagged > 0 ? ' · ' + fmtNum(flagged) + ' flagged' : '');
    parts.push('<rect x="' + Math.round(x * 100) / 100 + '" y="' + (H - PAD - h) + '" width="' + barW + '" height="' + h + '" rx="2" fill="' + fill + '" opacity="0.75"><title>' + title + '</title></rect>');
  }
  parts.push('</svg>');
  const flaggedHours = buckets.filter((b) => (Number(b?.flaggedBlocks) || 0) > 0).length;
  if (flaggedHours > 0) {
    parts.push('<p class="feed-chart-meta">' + esc(t('chart.flagged', { n: fmtNum(flaggedHours) })) + '</p>');
  }
  box.innerHTML = parts.join('');
  box.hidden = false;
}

/* Feed-Karte aus dem persistierten Fenster: geflaggte Blöcke im Volltext
 * (f = geflaggte Txs, serverseitig bait-gefiltert VOR Persistenz —
 * lib/block-window.mjs). Ungeflaggte Blöcke sind nur in Rollup/Chart
 * zählbar — ehrliche Tiefe, keine erfundenen Detailkarten. */
function renderWindowFeed() {
  const feed = document.getElementById('block-feed');
  if (feedMode !== 'history') return;
  const flagged = windowData && Array.isArray(windowData.flagged) ? windowData.flagged : [];
  feed.innerHTML = '';
  // Leer-Text des Feeds folgt dem Modus (data-i18n wird mitgeschrieben, damit
  // applyStatic bei Sprachwechsel den passenden Key erwischt).
  const emptyEl = document.getElementById('feed-empty');
  const emptyKey = windowData && windowData.reason === 'Persistenz nicht konfiguriert'
    ? 'feed.persistOff' : 'feed.serverEmpty';
  emptyEl.setAttribute('data-i18n', emptyKey);
  emptyEl.textContent = t(emptyKey);
  for (const blk of flagged) {
    const li = document.createElement('li');
    // Badge/className aus blk.maxSeverity (lib/block-window.mjs berechnet das
    // Maximum der Edge-severities): ein Block mit nur suspect/info-Funden
    // erscheint nicht mehr fix als 'malicious'.
    const maxSev = blk?.maxSeverity ?? (Array.isArray(blk?.f) && blk.f.some((e) => e?.severity === 'malicious') ? 'malicious' : 'suspect');
    li.className = `block-card has-${esc(maxSev)}`;
    const n = Number(blk?.n) || 0;
    const fCount = Array.isArray(blk?.f) ? blk.f.length : 0;
    li.innerHTML = `
      <div class="block-head">
        <span class="block-height">#${esc(blk?.i)}</span>
        <span class="block-time">${esc(fmtClock(blk?.t))}</span>
        <span class="block-txs">${fmtNum(n)} ${esc(t('block.txs'))}</span>
      </div>
      <div class="block-badges"><span class="badge badge-${esc(maxSev)}">${esc(t('block.flagged', { n: fmtNum(fCount) }))}</span></div>`;
    feed.appendChild(li);
  }
  updateFeedVisibility();
  renderWindowNote();
  renderWindowChart();
}

/* Cluster-View aus dem persistierten Flow-State (serverseitig bait-gefiltert
 * + Pruning lastSeen>7 d, Top-200 — lib/flow-state.mjs). Die View trägt
 * rolesByAddress statt memberAddresses; memberAddresses wird für die
 * bestehenden Konsumenten (renderClusterList, drilldown, globe) deterministisch
 * aus rolesByAddress abgeleitet. */
function applyFlowStateView(view) {
  const clusters = (Array.isArray(view?.clusters) ? view.clusters : []).map((c) => {
    // Die Server-View liefert roles als Rolle->Anzahl (viewRoleCounts,
    // lib/flow-state.mjs:228) und rolesByAddress als Adresse->Rolle.
    // clusterCardHtml (lib/cluster-Markup des Hosts) erwartet die
    // Adresse->Rolle-Form — sie wird aus rolesByAddress abgeleitet, die
    // Rollen-Zählung ergibt sich dort wieder automatisch.
    const rolesByAddress = c?.rolesByAddress && typeof c?.rolesByAddress === 'object' ? c.rolesByAddress : {};
    return {
      id: String(c?.id ?? ''),
      label: c?.label ?? null,
      roles: rolesByAddress,
      rolesByAddress,
      severityByAddress: c?.severityByAddress && typeof c.severityByAddress === 'object' ? c.severityByAddress : {},
      memberAddresses: Object.keys(rolesByAddress),
      edges: Array.isArray(c?.edges) ? c.edges : [],
      totalDrops: Number(c?.totalDrops) || 0,
      txCount: Number(c?.txCount) || 0,
      distinctAccounts: Number(c?.distinctAccounts) || 0,
      firstSeen: c?.firstSeen ?? null,
      lastSeen: c?.lastSeen ?? null,
      // Persistierte Peeling-Ketten der Server-View (projectFlowStateView,
      // lib/flow-state.mjs): durchgereicht an Karten-Flusskette und
      // Drilldown-Graph-Kontext.
      peelingChains: Array.isArray(c?.peelingChains) ? c.peelingChains : [],
    };
  });
  const nodes = [];
  for (const c of clusters) {
    const sevByAddr = c?.severityByAddress && typeof c.severityByAddress === 'object' ? c.severityByAddress : {};
    for (const [addr, role] of Object.entries(c.rolesByAddress)) {
      // Polling-Pfad: severity aus der serverseitig berechneten
      // severityByAddress (Malicious/Suspect/Info stimmen zwischen Polling-
      // und WSS-Pfad überein) statt hart 'info'.
      nodes.push({ id: addr, role: ROLE_COLORS[role] ? role : 'unknown', clusterId: c.id, severity: sevByAddr[addr] ?? 'info' });
    }
  }
  const edges = [];
  for (const c of clusters) {
    for (const e of c.edges) {
      if (!e || !e.from || !e.to) continue;
      edges.push({
        from: String(e.from), to: String(e.to), type: String(e.type || 'Sonstige'),
        txHash: e.txHash ? String(e.txHash) : undefined,
      });
    }
  }
  lastClusterGraph = { nodes, edges, clusters };
  renderLiveGraph(lastClusterGraph);
  renderClusterList(clusters);
  if (drilldown && typeof drilldown.refresh === 'function') drilldown.refresh();
  if (globeMod && typeof globeMod.refresh === 'function') globeMod.refresh();
}

async function pollBlockWindow() {
  const res = await fetch('/api/block-window?range=' + encodeURIComponent(feedRange), { cache: 'no-store' });
  if (!res.ok) throw new Error('HTTP ' + res.status);
  const body = await res.json();
  windowData = body;
  // Render-Dedup: identische Fenster (60-s-Server-Cache) nicht neu bauen —
  // der Feed verliert sonst bei jedem Poll seinen 'Mehr laden'-Stand.
  const sig = JSON.stringify([body?.range, body?.to, body?.updatedAt, (body?.flagged || []).length, (body?.buckets || []).length]);
  if (sig !== windowRenderSig) {
    windowRenderSig = sig;
    renderWindowFeed();
  } else {
    renderWindowNote();
  }
}

async function pollFlowState() {
  const res = await fetch('/api/flow-state', { cache: 'no-store' });
  if (!res.ok) throw new Error('HTTP ' + res.status);
  const body = await res.json();
  flowData = body;
  if (feedMode === 'history') applyFlowStateView(body);
}

async function serverPollTick() {
  if (typeof document !== 'undefined' && document && document.visibilityState !== 'visible') return;
  if (Date.now() < serverPollBackoffUntil) return;
  let failed = false;
  try {
    await pollBlockWindow();
  } catch (err) {
    failed = true;
    if (feedMode === 'history') {
      const msg = err && err.message ? String(err.message) : t('conn.unknownError');
      setConn(false, t('feed.windowError', { msg }));
    }
  }
  try {
    await pollFlowState();
  } catch {
    failed = true;
  }
  if (failed) {
    serverPollFailCount += 1;
    serverPollBackoffUntil = Date.now() + Math.min(
      POLL_BACKOFF_BASE_MS * 2 ** Math.min(serverPollFailCount - 1, 5),
      POLL_BACKOFF_MAX_MS,
    );
    return;
  }
  serverPollFailCount = 0;
  serverPollBackoffUntil = 0;
  if (feedMode === 'history') setConn(true, connLabel());
}

function startServerPolling() {
  if (serverPollTimer !== null) return;
  serverPollTimer = setInterval(() => { void serverPollTick(); }, SERVER_POLL_MS);
}

/* ---------- Modus-Umschaltung (Historie-Standard / Live-Opt-in) ---------- */
function setFeedMode(mode) {
  const target = mode === 'live' ? 'live' : 'history';
  if (target === feedMode) return;
  feedMode = target;
  document.getElementById('feed-mode-history').setAttribute('aria-selected', String(target === 'history'));
  document.getElementById('feed-mode-live').setAttribute('aria-selected', String(target === 'live'));
  const rangeSel = document.getElementById('feed-range');
  rangeSel.disabled = target !== 'history';
  if (target === 'history') {
    stopLiveMode();
    feedVisibleCount = FEED_INITIAL;
    document.getElementById('block-feed').innerHTML = '';
    windowRenderSig = null;
    renderWindowFeed();
    if (flowData) applyFlowStateView(flowData);
    setConn(true, connLabel());
    void serverPollTick(); // sofort frisches Fenster statt erst nach dem Timer-Takt
  } else {
    // Live ist Opt-in: ohne Rate-Gate (lib/rate-gate.mjs nicht erreichbar)
    // startet der Modus nicht — fail-closed, Server-Modus bleibt.
    if (!rateGateFactory) {
      console.warn(t('log.consoleLiveUnavailable'));
      setFeedMode('history');
      return;
    }
    if (!rateGate) rateGate = rateGateFactory(RATE_GATE_OPTS);
    document.getElementById('feed-note').hidden = true;
    document.getElementById('feed-chart').innerHTML = '';
    document.getElementById('feed-chart').hidden = true;
    document.getElementById('block-feed').innerHTML = '';
    feedVisibleCount = FEED_INITIAL;
    document.getElementById('feed-empty').hidden = false;
    setConn(false, t('conn.liveInit'));
    connectLive();
  }
}

function stopLiveMode() {
  if (wsProbeTimer) { clearTimeout(wsProbeTimer); wsProbeTimer = null; }
  if (wsAttemptTimer) { clearTimeout(wsAttemptTimer); wsAttemptTimer = null; }
  if (ws) {
    try { ws.close(); } catch { /* onclose kann ausbleiben; Zustand unten bereinigen */ }
  }
  ws = null;
  liveMode = 'init';
  wssSubscribeOk = false;
  wssSubscribeError = null;
  analysisInFlight = false;
  quotaCooldownUntil = 0;
}

/* ================================================================== */
/* OPT-IN-LIVE: WSS honeycluster.io, 1 ledger-Kommando/Block, kein Sampling */
/* ================================================================== */

/* ---------- Volles Ledger pro Block über denselben WebSocket ---------- */
// honeycluster-Vertrag (2026-10-02, live probiert): expand:true liefert das
// vollständige Ledger-Objekt mit allen Tx-Objekten (hash + metaData) in
// GENAU EINEM Request — keine separaten tx-Kommandos, kein Sampling.
// Normalisierung zu {tx_json, meta} bleibt als Defense-in-Depth für Server,
// die volle Objekte (Meta-Feld "metaData") oder {tx_json, meta}-Form liefern
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

// Adapter wie api/advance.js / api/ledger.js stampExpandEntry: expand-
// Einträge tragen kein meta/ledger_index/close_time_iso — die Ledger-Ebenen-
// Werte werden pro Entry gestempelt, damit txRecordFromEntry/analyzeLedger
// dieselben Felder sehen wie serverseitig.
function stampExpandEntry(e, ledgerIndex, closeIso) {
  if (!e || typeof e !== 'object') return e;
  if (e.meta == null && e.metaData != null) e.meta = e.metaData;
  if (e.ledger_index == null) e.ledger_index = ledgerIndex;
  if (e.close_time_iso == null && closeIso) e.close_time_iso = closeIso;
  return e;
}

function wsLedgerCommand(ledgerIndex) {
  return new Promise((resolve) => {
    if (!ws || ws.readyState !== 1) { resolve(null); return; }
    const id = ++reqId;
    let timer = null;
    // settle-Wrapper mit clearTimeout (Muster a.D. wsTxCommand): der
    // Timeout-Timer darf nach rechtzeitiger Antwort nicht weiterlaufen.
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
      ws.send(JSON.stringify({ command: 'ledger', id, ledger_index: ledgerIndex, transactions: true, expand: true }));
    } catch {
      pendingTx.delete(id);
      settle(null);
    }
  });
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
  // Ledger-Events fließen → eine frühere Abo-Ablehnung ist überwunden.
  if (wssSubscribeError || wsProbeTimer) {
    wssSubscribeError = null;
    if (wsProbeTimer) { clearTimeout(wsProbeTimer); wsProbeTimer = null; }
  }
  wssSubscribeOk = true;
  wssSubscribeOkAt = Date.now();

  // honeycluster-Abo streams:['ledger'] liefert NUR Header (ledger_index,
  // ledger_time, txn_count, validated_ledgers) ohne transactions — verifiziert
  // 2026-10-02. Txs braucht der Client pro Block über das ledger-Kommando.
  const declaredCount = Number(msg.txn_count ?? 0);
  const closeIso = xrplIso(msg.ledger_time ?? msg.close_time, msg.close_time_iso);

  // KEIN Sampling (Vertrag v2): jeder validierte Block wird analysiert —
  // 1 ledger-Kommando (expand:true) pro Block, pro Request durch den
  // Rate-Gate (10/s steady; ~4 s Blocktakt -> ~2,5 req/s, deutlich unter
  // dem Limit; der Gate fängt auch Burst-Spitzen ab).
  // Serialisierungsguard: eine Analyse gleichzeitig — überlappende Events
  // (Blocktakt ~4 s, Antwort-Latenz kann darüber liegen) würden Kommandos
  // stapeln; die Karte des überbrückten Blocks bleibt bis dahin "Analysiere …".
  if (analysisInFlight) {
    const queuedCard = addBlockCard(idx, closeIso, declaredCount, 'analyzing');
    queuedCard.querySelector('.block-badges').innerHTML =
      `<span class="badge badge-partial">${esc(t('block.busy'))}</span>`;
    return;
  }
  const card = addBlockCard(idx, closeIso, declaredCount, 'analyzing');
  analysisInFlight = true;
  try {
    await analyzeLedgerBlock(idx, declaredCount, closeIso, card);
  } finally {
    analysisInFlight = false;
  }
}

// Analyse eines Blocks: GENAU EIN ledger-Kommando (expand:true) — der
// Request wird vor dem Senden über den lib-Rate-Gate erworben (Token-Bucket
// 10/s, Burst 50, 20 Start-Tokens). WSS-tooBusy/slowDown behandelt der
// Client wie HTTP 429: retry-Delta + Cooldown (defensiv — die echte
// honeycluster-Throttle-Semantik ist UNVERIFIED).
async function analyzeLedgerBlock(idx, declaredCount, closeIso, card) {
  let entries = [];
  let ledgerTxCount = declaredCount;
  const inCooldown = Date.now() < quotaCooldownUntil;
  if (inCooldown) {
    card.querySelector('.block-badges').innerHTML =
      `<span class="badge badge-partial">${esc(t('block.quotaSkipped'))}</span>`;
    return;
  }
  if (!rateGate) {
    // Fail-closed: ohne Gate kein Request (der Modusstart prüft das bereits;
    // dieser Zweig fängt einen späteren Import-Ausfall ab).
    card.querySelector('.block-badges').innerHTML =
      `<span class="badge badge-partial">${esc(t('block.budgetSkipped'))}</span>`;
    return;
  }
  const gate = rateGate.tryAcquire(1);
  if (!gate.ok) {
    if (!Number.isFinite(gate.waitMs) || gate.waitMs > GATE_WAIT_MAX_MS) {
      // Der Blocktakt übersteigt die Rate (oder die Kapazität ist erschöpft):
      // ehrliches Skip-Badge statt Rückstau — der Block bleibt ungeklärt.
      card.querySelector('.block-badges').innerHTML =
        `<span class="badge badge-partial">${esc(t('block.budgetSkipped'))}</span>`;
      return;
    }
    await new Promise((res) => setTimeout(res, gate.waitMs));
  }
  if (!ws || ws.readyState !== 1) return; // Verbindung verloren — Karte ohne Analyse
  const led = await wsLedgerCommand(idx);
  // Fehler-Antworten kommen als {error, error_message} statt null durch —
  // der tooBusy-Zweig greift damit tatsächlich (a.D.-Muster, settleValue).
  if (led && typeof led === 'object' && (led.error === 'tooBusy' || led.error === 'slowDown')) {
    markQuotaThrottled(card, led.error_message ?? null);
    console.warn(t('log.consoleLiveThrottled', {
      error: led.error,
      msg: led.error_message ? ': ' + led.error_message : '',
    }));
    return; // Early-Return: finishBlockCard würde sonst zusätzlich 0/N erzeugen
  }
  const rawTxs = led?.ledger?.transactions;
  if (Array.isArray(rawTxs) && rawTxs.length) {
    ledgerTxCount = rawTxs.length;
    const ledgerIndexActual = Number(led?.ledger?.ledger_index ?? idx) || idx;
    const closeIsoActual = xrplIso(led?.ledger?.close_time, led?.ledger?.close_time_iso) ?? closeIso;
    entries = rawTxs
      .map((e) => stampExpandEntry(e, ledgerIndexActual, closeIsoActual))
      .map(normalizeLedgerTxEntry)
      .filter(Boolean);
  }

  recordFirstSeen(entries);
  const result = analyzeLedger({ transactions: entries }, buildCtx());

  // Köder-Filter (WSS-Pfad): Funde auf Köder-Adressen werden vor jeder
  // Weiterverwendung entfernt — dieselbe Regel wie im Serverpfad
  // (api/ledger.js: findings.filter(!baitLabels.has)), hier hash-gestützt
  // über die Bait-Hash-Allowlist. Damit erscheinen Köder nie im Live-Log,
  // im Export (downloadLog) oder im Cluster-Graphen.
  const visibleFindings = [];
  for (const f of result.findings) {
    if (await isDeniedAddrAsync(f.address)) continue;
    visibleFindings.push(f);
  }

  // Cluster-Schicht: rollendes Fenster + Neuberechnung pro validiertem Ledger.
  const blockRecords = [];
  if (txRecordFromEntry && buildClusterGraph) {
    for (const e of entries) {
      // closeIso (Ledger-Ebene) als Fallback: Entries ohne eigenes close_time
      // erhalten die Ledger-Ebenen-Zeit (stampExpandEntry stempelt sie bereits).
      const rec = txRecordFromEntry(e, closeIso);
      if (!rec) continue;
      // Köder-Endpunkte (account ODER destination) erreichen das Fenster nie —
      // clientseitiges Pendant zum Serverfilter über baitLabels.
      if (await recordTouchesBait(rec)) continue;
      blockRecords.push(rec);
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

  // Peeling-Ketten im Live-Pfad (Kritik 4): ohne diese Funde bliebe der
  // Regelfilter 'peeling-chain' (buildRuleFilter aus RULE_CATALOG) immer leer —
  // logEntries werden ausschließlich über registerFindings aus Analyse-Funden
  // gefüllt. detectPeelingChains läuft pro Live-Ledger auf den txRecords +
  // Fund-Adressen; Ketten werden als Fund (Seed-Adresse, severity 'suspect')
  // ins Analyse-Log geschrieben. Kein Schuldnachweis.
  if (detectPeelingChainsFn && blockRecords.length && visibleFindings.length) {
    let chains = [];
    try {
      chains = detectPeelingChainsFn(blockRecords, visibleFindings, {});
    } catch {
      chains = [];
    }
    for (const ch of chains) {
      const ratios = ch.hops.map((h) => h.ratio).filter((r) => typeof r === 'number');
      const avgPct = ratios.length ? Math.round((ratios.reduce((s, r) => s + r, 0) / ratios.length) * 100) : null;
      visibleFindings.push({
        ruleId: 'peeling-chain',
        severity: 'suspect',
        address: ch.seed,
        note: `Peeling-Kette: ${ch.hopsCount} gestaffelte Hops${avgPct != null ? ` (Ø ${avgPct} % Weiterleitung)` : ''} über ${ch.bridges.length} ungeflaggte Relays.`,
        noteKey: 'peeling-chain',
        noteParams: { hops: ch.hopsCount, ratio: avgPct },
      });
    }
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
  // Ein abgelehntes Abo liefert nie Events — liveMode 'wss' wäre gelogen.
  // onLedgerEvent stellt 'wss' beim ersten Event wieder her; bis dahin
  // bleibt der Live-Modus sichtbar im Ablehnungszustand (Sonden-Rhythmus).
  const est = retryMs ? t('conn.estWarn', { dur: fmtDur(retryMs) }) : '';
  const msgSuffix = message ? `: ${message}` : '';
  console.warn(t('log.consoleSubscribeRejected', { error, msg: msgSuffix, est }));
  scheduleWssProbe(retryMs);
  setConn(false, connLabel());
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
    // Header-only-Abo (honeycluster-Vertrag 2026-10-02): streams:['ledger']
    // liefert ledgerClosed-Header OHNE transactions — die Txs holt pro Block
    // das eine ledger-Kommando (expand:true) über den Rate-Gate.
    try {
      ws.send(JSON.stringify({ command: 'subscribe', id: SUBSCRIBE_ID, streams: ['ledger'] }));
    } catch { /* onclose behandelt es */ }
    setConn(true, t('conn.wssConnecting'));
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
    if (feedMode !== 'live') return; // stopLiveMode hat den Socket bewusst geschlossen
    liveMode = 'init'; // ohne Socket kein Live-Bild — ehrlicher Zwischenzustand
    setConn(false, t('conn.liveClosed', { s: Math.round(wsBackoff / 1000) }));
    scheduleReconnect();
  };

  ws.onerror = () => { /* onclose folgt unmittelbar */ };
}

function scheduleReconnect() {
  if (feedMode !== 'live') return; // Live ist Opt-in: ohne Modus kein Auto-Reconnect
  if (wsAttemptTimer) return;
  const delay = wsBackoff;
  wsBackoff = Math.min(wsBackoff * 2, 30000);
  wsAttemptTimer = setTimeout(() => {
    wsAttemptTimer = null;
    if (feedMode === 'live') connectLive();
  }, delay);
}

/* ---------- Live-Watchdog (nur im Opt-in-LIVE-Modus) ---------- */
/* Liveness mit der EIGENEN WS-Uhr lastWsMsgAt (onopen + jede Message).
 * WS_STALL_MS (90 s) liegt über dem beobachteten 60-s-Server-Idle-Close und
 * weit über dem ~4-s-Event-Takt: Ein Socket, der 90 s komplett stumm ist
 * (NAT-Timeout, Suspend/Resume ohne close-Frame, Endpunkt-Stall), ist ein
 * Zombie — auch wenn liveMode sticky 'wss' ist (live-observiert: Offline-
 * Emulation ließ die Statuszeile 'WSS verbunden' zeigen, obwohl 0 Events
 * ankamen). Aktiver close; onclose trägt den Reconnect nach (Backoff aktiv).
 * Der a.D. Snapshot-Fallback (GET /api/ledger im 5-s-Watchdog-Takt) entfällt:
 * Serverdaten werden im Standard-Modus über den 60-s-Poll geholt, im Live-
 * Modus gar nicht — ein Live-Tab belastet honeycluster ausschließlich über
 * sein eigenes Block-Kommando (Gate-geprüft). */
function watchdogLive() {
  if (feedMode !== 'live') return;
  if (ws && ws.readyState === 1 && Date.now() - lastWsMsgAt > WS_STALL_MS) {
    liveMode = 'init'; // Quelle ab jetzt: kein Socket — Statuszeile ehrlich
    try { ws.close(); } catch { /* egal — onclose fehlt dann, nächster Zyklus */ }
  }
  if (liveMode === 'wss' && Date.now() - lastLedgerAt < WS_STALL_MS) {
    setConn(true, connLabel());
  }
}

function bindFeed() {
  document.getElementById('feed-mode-history').addEventListener('click', () => setFeedMode('history'));
  document.getElementById('feed-mode-live').addEventListener('click', () => setFeedMode('live'));
  document.getElementById('feed-range').addEventListener('change', (e) => {
    const v = String(e.target.value ?? '24h');
    feedRange = ['24h', '3d', '7d'].includes(v) ? v : '24h';
    windowRenderSig = null; // Range-Wechsel: immer neu rendern
    if (feedMode === 'history') void serverPollTick();
  });
  document.getElementById('feed-more').addEventListener('click', () => {
    feedVisibleCount += FEED_STEP;
    updateFeedVisibility();
  });
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
bindFeed();
bindAddrActions();
document.getElementById('stat-network').textContent = t('net.mainnet');
// Standard-Dashboard: Serverdaten (60-s-Poll flow-state + block-window),
// KEIN automatischer Besucher-WSS. Der Live-Watchdog läuft nur, wenn der
// Opt-in-LIVE-Modus aktiv ist.
setConn(true, connLabel());
void serverPollTick();
startServerPolling();
setInterval(watchdogLive, WATCHDOG_MS);
// Bait-Hash-Allowlist: beim Start und alle 60 s (unabhängig vom Modus).
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
  setConn(true, connLabel());
  // Fenster-Flächen in der neuen Sprache neu bauen (Notiz/Chart/Fenster-Karten
  // tragen t()-Texte; der ROHE reason-Vergleich bleibt sprachunabhängig).
  if (feedMode === 'history') {
    windowRenderSig = null;
    renderWindowFeed();
  }
  if (lastClusterGraph) {
    renderLiveGraph(lastClusterGraph);
    renderClusterList(lastClusterGraph.clusters);
  }
  if (drilldown && typeof drilldown.refresh === 'function') drilldown.refresh();
  if (globeMod && typeof globeMod.refresh === 'function') globeMod.refresh(true);
  if (historyMod && typeof historyMod.refresh === 'function') historyMod.refresh();
  if (checkMod && typeof checkMod.reRender === 'function') checkMod.reRender();
});
