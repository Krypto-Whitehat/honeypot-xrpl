'use strict';

/* Honeypot XRPL – Frontend (ESM-Modul)
 *
 * Hauptansicht: BLOCK-FEED + AKTEUR-CLUSTERING, zweimodig (API-Vertrag v2,
 * 2026-10-02; Live-Standard-Tilt 2026-10-05):
 *   - STANDARD 'live' (direkter WSS, über den lib-Rate-Limiter gated):
 *     Sobald lib/rate-gate.mjs eintrifft und der Nutzer nicht selbst gewählt
 *     hat, kippt die Importkette auf Live (Tilt). Fail-closed: ist das Gate
 *     nicht erreichbar, bleibt 'history' Standard (Server-Fenster).
 *   - Fallback/Archiv 'history' (Serverdaten, kein Besucher-WSS; Knopf
 *     'Archiv' im Feed-Panel, Haupt-Tab 'Historie' bleibt der View-Zugang):
 *     GET /api/block-window?range=24h|3d|7d liefert Stunden-Rollups
 *     (buckets) + geflaggte Blockdetails im Volltext (flagged) — der Feed
 *     zeigt die geflaggten Blöcke des Fensters, der Stundenchart die
 *     Vollständigkeit; ungeflaggte Blöcke sind nur zählbar (ehrliche Tiefe,
 *     lib/block-window.mjs). GET /api/flow-state liefert die serverseitig
 *     bait-gefilterte, gekappte Cluster-View (Cursor + validatedIndex).
 *     Polling 60 s, sichtbarkeits-gated; Fail-closed-200 ohne Persistenz
 *     wird als ehrlicher Leerzustand dargestellt (reason-Vergleich bleibt
 *     roh — Protokollwert, Muster public/history.js:361).
 *   - 'live' (Standard-Modus, Modus-Auswahl im Feed-Panel): direkter WSS auf
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
 * DOM-freier Token-Bucket für den LIVE-Modus. Dynamischer Import mit
 * Null-Guard — ohne Gate startet der Live-Modus NICHT (fail-closed,
 * Konsole-Meldung), der Server-Betrieb bleibt unberührt.
 * Live ist heute der STANDARD-Feed-Modus: Sobald das Gate eintrifft, wird
 * auf Live gekippt (Tilt), sofern der Nutzer noch keinen Knopf gedrückt hat
 * (feedModeUserChoice). Fällt der Gate-Import, bleibt der Server-Modus
 * (history) Standard — dokumentiertes Fail-closed. */
let rateGateFactory = null;
let feedModeUserChoice = false;    // Nutzer-Klick vor Gate-Eintreffen: kein Tilt mehr
import('/lib/rate-gate.mjs')
  .then((m) => {
    rateGateFactory = typeof m.createRateGate === 'function' ? m.createRateGate : null;
    if (!feedModeUserChoice) void setFeedMode('live');
  })
  .catch(() => {
    /* Gate offline (z. B. 404): Live-Modus bleibt gesperrt, Server-Modus
     * (feedMode 'history') bleibt Standard. KEIN setFeedMode('history') —
     * bei feedMode='history' early-returnt setFeedMode (if (target ===
     * feedMode) return) und die im Markup auf Live stehende aria-selected
     * würde nie zurückgesetzt (UI zeigte 'Live' ausgewählt bei Modus
     * history, Archiv-Klick No-op). Deshalb aria-Direktsync nach dem
     * Muster der aria-Zeilen in setFeedMode. */
    document.getElementById('feed-mode-history').setAttribute('aria-selected', 'true');
    document.getElementById('feed-mode-live').setAttribute('aria-selected', 'false');
    console.warn(t('log.consoleLiveUnavailable'));
  });
/* i18n: statischer Import (durch vercel.json-Rewrite /i18n.mjs gedeckt).
 * EN/DE ist damit vor dem ersten Render garantiert initialisiert; ein 404
 * von /i18n.mjs würde das ganze Modul stoppen — bewusst die konsistentere
 * Alternative zum fehlertoleranten dynamischen Import (Muster globe.js). */
import {
  t, ruleName, noteText, sevText, serverPhrase,
  fmtNum, fmtXrp, fmtClock, fmtDateTime,
  applyStatic, applyLang, initLangSwitcher, initThemeSwitcher,
} from './i18n.mjs';
/* Adress-Chip-Zeile der Cluster-Karten (Börsen-Name + Destination-Tag):
 * DOM-freier Shared-Helfer mit public/history-host.html (Muster
 * public/drilldown.js renderTable). Das Modul wählt/sortiert/kappt nur —
 * die Chip-Funktionen (nameChipHtml/tagChipHtml) werden injiziert und
 * tragen die Host-Gates (isFullShownAddr, multiUserEntryOf). */
import { collectTagsByAddr, addrChipsRowHtml } from './cluster-chips.mjs';
/* Cluster-Akkumulation (Fix 2026-10-06, zweite Runde): DOM-freier Shared-
 * Helfer für View-Normalisierung und Fenster-/Bestands-Merge. Dedup nur
 * über die id (die frühere ≥1-Mitglied-Absorption ließ den Mega-Cluster
 * als Karte verschwinden — Live-Befund 2026-10-06); SEV_RANK single source
 * aus dem Modul (Sortierung + Severity-Union). */
import { SEV_RANK, serverClustersFromView, mergeClusterViews } from './cluster-views.mjs';
/* Knoten-Deckel der Live-Bühne + Zeitfenster-Filter (Kritik-Runde 3 2026-10-07,
 * Archiv-Graph-Parität): DOM-freier Shared-Helfer (Muster cluster-views.mjs) —
 * dreiphasiger Budget-Satz (Evidenz-Floor → Top-Kanten-Endpunkte → Auffüllung)
 * statt lexikografischem Ausschnitt, Kanten-Totalordnung als Spiegel von
 * topKEdges, Fensterfilter/Bestandstiefe für die ehrliche truncated-
 * Kennzeichnung der Fenster 24h/3d/7d/30d/90d. */
import {
  FEED_RANGES, FEED_RANGE_MS, BLOCK_WINDOW_MAX_RANGE,
  selectCappedNodes, edgesInWindow, oldestEdgeMs,
} from './graph-budget.mjs';
/* Top-10 Börsen-Zuflüsse (Daten-Forensik 2026-10-07): DOM-freie Aggregation
 * über die BESTEHENDE /api/flow-state-View (7 d + 30 d in einem Durchlauf,
 * +0 Requests/+0 Functions) plus Zeilen-Markup über injizierte Host-Gates
 * (esc/displayFindingAddr — Maskierungs-Pflicht bleibt im Host, Muster
 * cluster-chips.mjs). */
import { aggregateExchangeOutflows, exchangeOutflowRowHtml } from './exchange-outflows.mjs';
// Tx-Typ -> Kanten-Kategorie (DOM-frei, deterministisch; Modul-Vertrag im
// Kopf von edge-colors.mjs). Farb-WERTE bleiben hier (JS-Spiegel der Tokens).
import { txCategory } from './edge-colors.mjs';
/* Unikat-SVG-Sprache (Design P0, public/icons.mjs): Leerzustands-
 * illustrationen für Feed/Log/Cluster, Panel-Signet Activity Graph und der
 * Diagramm-Marker geflaggter Stunden — DOM-frei, textlos (aria-hidden),
 * i18n-unberührt. */
import { mountEmptyIllu, svgEmptyFeed, svgEmptyLog, svgEmptyCluster, panelMarkerGraph, chartMarkerFlagged } from './icons.mjs';

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
        // Theme-Thunk (Noir-Theme): der Modul-Kontext ist einmalig — als
        // Funktion liest das Drilldown EDGE_DEFAULT je Zugriff mit (die
        // Tabellen-Objekte EDGE_COLORS/ROLE_COLORS wandern by-reference und
        // sind über die In-place-Mutation ohnehin aktuell).
        edgeDefault: () => EDGE_DEFAULT,
        // Tx-Typ -> Kanten-Kategorie (edge-colors.mjs): EDGE_COLORS ist seit
        // dem Farb-Audit kategorie-geählt; die Modul-Lookups laufen über
        // edgeColors[ctx.edgeCategory(type)] || edgeDefaultOf().
        edgeCategory: txCategory,
        roleLabels: ROLE_LABEL,
        physicsCluster: PHYSICS_CLUSTER,
        addrActionsHtml,
        accountNameOf,
        // Host-Gate der Exchange-Registry (analog accountNameOf: null für
        // maskierte/Deny-Adressen und ohne Registry-Treffer — fail-closed).
        exchangeEntryOf,
        // Host-Gate der Multi-User-Union (Registry ∪ verifizierte well-known-
        // Namen) — Tag-Chips/Tooltips im Drilldown nutzen es statt des reinen
        // Registry-Lookups (Coverage-Fix 2026-10-05).
        multiUserEntryOf,
        flowPaths: () => flowPathsFn,
        // Nachladen aus dem persistierten Bestand (Stale-Overlay-Fix
        // 2026-10-06): das Drilldown kann einen node-losen Merged-Cluster
        // (Karte ohne Fenster-Knoten im Live-Graphen) aus dem akkumulierten
        // Bestand rekonstruieren — Quelle in dieser Reihenfolge:
        // lastClusterGraph → serverFlowClusters/sessionFlowClusters →
        // bedingter Refetch /api/flow-state (60-s-Cache). Köder-Gates bleiben
        // beim Host/im Drilldown (sync isDeniedAddr-Gate + Maske + Export-
        // Nachprüfung); diese Funktion liefert nur Rohbestand.
        getPersistedClusterById,
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
        // Host-Gate für Namens-Badges (accountNameOf gibt null für jede
        // maskierte/Deny-Adresse) PLUS Defense-in-Depth: isFullShownAddr
        // jetzt auch im globe-ctx (globe-ctx hatte es bisher nicht —
        // Blocker-Fix 2026-10-05), damit globe lokal selbst prüfen kann.
        accountNameOf,
        exchangeEntryOf,
        isFullShownAddr,
        hashOf,
        shortAddr,
        esc,
        roleColors: ROLE_COLORS,
        edgeColors: EDGE_COLORS,
        // Theme-Thunk (Noir-Theme, Muster drilldown-ctx): edgeDefault je
        // Zugriff lesen, damit der Globe-Neuaufbau (hx:themechange →
        // rebuildGlobe) die Noir-Fallbacks sieht.
        edgeDefault: () => EDGE_DEFAULT,
        // Tx-Typ -> Kanten-Kategorie (edge-colors.mjs), Muster drilldown-ctx.
        edgeCategory: txCategory,
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
        hashOf,
        shortAddr,
        esc,
        fmtXrp,
        fmtClock,
        addrActionsHtml,
        accountNameOf,
        exchangeEntryOf,
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
        accountNameOf,
        exchangeEntryOf,
        // Host-Gate der Multi-User-Union — Tag-Chips im Konto-Check nutzen es
        // statt des reinen Registry-Lookups (Coverage-Fix 2026-10-05).
        multiUserEntryOf,
        roleLabels: ROLE_LABEL,
        roleColors: ROLE_COLORS,
        ruleNames: RULE_NAME,
      });
      checkMod.setView(activeView === 'check');
    }
  })
  .catch(() => { /* Konto-Check offline (z. B. 404); View bleibt leer */ });

/* Namensindex (XRPScan-Well-known-Aliase, public/name-index.mjs): derselbe
 * nicht-blockierende Import-Muster mit Null-Guard. Der Modul-Import selbst
 * ist DOM-/fetch-frei und löst NOCH keinen Netzwerk-Request aus — der
 * einzige Bulk-Fetch pro Session startet lazy im ersten Cluster-Daten-Takt
 * (rebuildClusterGraph / applyFlowStateView), nie im Head und nie im
 * WSS-Takt pro Adresse. Fehlt das Modul, zeigen alle Sichten ohne Namen
 * (fail-closed, Live-Betrieb unberührt). */
let nameIndexMod = null;
import('./name-index.mjs')
  .then((m) => {
    if (m && typeof m.ensureNameIndex === 'function') nameIndexMod = m;
  })
  .catch(() => { /* Namensindex offline (z. B. 404); Karten laufen ohne Namen */ });

/* Exchange-Registry (Destination-Tag-Identität, public/exchange-registry.mjs):
 * dasselbe nicht-blockierende Import-Muster mit Null-Guard. Der Modul-Import
 * ist DOM-/fetch-frei und löst NOCH keinen Request aus — der einzige Fetch
 * pro Session startet lazy im ersten Cluster-Daten-Takt (rebuildClusterGraph),
 * nie im Head und nie im WSS-Takt. Fehlt das Modul, zeigen alle Sichten ohne
 * Tag-Chips und der Cluster-Graph läuft tag-frei (fail-closed, Live-Betrieb
 * unberührt). */
let registryMod = null;
import('./exchange-registry.mjs')
  .then((m) => {
    if (m && typeof m.ensureExchangeRegistry === 'function') registryMod = m;
  })
  .catch(() => { /* Registry offline (z. B. 404); Karten laufen ohne Tag-Chips */ });

/* Datenquellen-Modi (API-Vertrag v2, 2026-10-02; Live-Standard-Tilt 2026-10-05):
 *   'history' (Startwert + Fail-closed-Fallback, Knopf 'Archiv'):
 *   Server-Fenster GET /api/block-window?range=… + Cluster GET /api/flow-state
 *   — Polling 60 s, sichtbarkeits-gated, kein Besucher-WSS.
 *   'live' (Standard nach Gate-Eintreffen): WSS honeycluster.io, Abo Header-only, pro Block GENAU
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
// Verifiziert-vollanzeigbar (Befund 2026-10-07, Masken-Oszillation der
// Top-10-Box): Adresse -> sha256-hex. Aufnahme NUR nach echtem Hash-Vergleich
// gegen die DANN geladene Deny-Liste (denyLoaded-Pflicht in
// verifyFullShownAsync). Der Fallback in isFullShownAddr prüft den
// gespeicherten Hash IMMER live gegen das AKTUELLE baitHashDeny — eine Deny-
// Rotation maskiert einen frisch aktivierten Köder also sofort, ohne auf die
// Revalidation in rebuildDisplayAndKnownBad zu warten. Köder-Adressen werden
// nie aufgenommen (Aufnahme nur bei Nicht-Treffer); FIFO-Kappung wie beim
// Hash-Cache.
const VERIFIED_FULL_SHOWN_MAX = 12000; // > ADDR_HASH_CACHE_MAX (Gedächtnis, nicht Arbeitsvorrat)
const verifiedFullShown = new Map();   // Adresse -> sha256-hex (unverdrängbar)
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
  if (h !== undefined) return !baitHashDeny.has(h);
  // Verdrängungs-Fallback (Befund 2026-10-07): Der Hash-LRU verliert zwischen
  // zwei Renders Zeilen-Adressen (der WSS-Zufluss hasht jede Tx-Akteur-
  // Adresse) — dieselbe Zeile flackerte je Poll zwischen voller und Kurzform.
  // Verifizierte Adressen bleiben daher über verifiedFullShown vollanzeige-
  // fähig; die Deny-Prüfung läuft auch hier gegen den LIVE-Stand der Liste
  // (dieselbe Bedingung wie beim Cache-Treffer — keine Lockerung der Maske).
  const vh = verifiedFullShown.get(a);
  return vh !== undefined && !baitHashDeny.has(vh);
}

async function rebuildDisplayAndKnownBad() {
  fullDisplay = denyLoaded && !denyPermanentlyFailed;
  // Gedächtnis-Hygiene (Befund 2026-10-07): verifiziert-vollanzeigbare
  // Adressen, deren Hash die ROTIERTE Deny-Liste nun trifft, fliegen aus dem
  // Gedächtnis. Die Anzeige-Entscheidung selbst prüft live gegen baitHashDeny
  // (Fallback in isFullShownAddr) — dies räumt nur belegte Kapazität auf.
  for (const [a, h] of verifiedFullShown) {
    if (baitHashDeny.has(h)) verifiedFullShown.delete(a);
  }
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

// Verifikation EINER Adresse für die dauerhafte Vollanzeige (fail-closed):
// erst bei geladener Deny-Liste entscheiden, dann nur bei Nicht-Treffer in
// verifiedFullShown aufnehmen (Köder-Adressen kommen dort nie hinein; ein
// nach einer Rotation getroffener Eintrag wird in rebuildDisplayAndKnownBad
// entfernt und vom Live-Fallback in isFullShownAddr sofort wieder maskiert).
// Rückgabe true = Adresse ist jetzt verifiziert vollanzeigefähig.
async function verifyFullShownAsync(addr) {
  const a = String(addr ?? '').trim();
  if (!a || !denyLoaded) return false;
  const h = await hashOf(a);
  if (!h) return false;
  if (baitHashDeny.has(h)) {
    verifiedFullShown.delete(a);
    return false;
  }
  if (!verifiedFullShown.has(a)) {
    verifiedFullShown.set(a, h);
    while (verifiedFullShown.size > VERIFIED_FULL_SHOWN_MAX) {
      const oldest = verifiedFullShown.keys().next().value;
      if (oldest === undefined) break;
      verifiedFullShown.delete(oldest);
    }
  }
  return true;
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
  // Peeling-Ketten der Server-View: Ketten-Adressen und Brücken sitzen nicht
  // immer in nodes/edges (Brücken erhalten bewusst keine Graph-Rolle) — ohne
  // sie zu hashen blieben ihre Ketten-Chips in der Kurzform (Befund
  // 05.10.2026: Flow-State-Karten zeigten 7 gekürzte chain-nodes).
  for (const c of cg?.clusters ?? []) {
    for (const ch of Array.isArray(c?.peelingChains) ? c.peelingChains : []) {
      const seeds = [String(ch?.seed ?? '').trim()];
      const addrs = (Array.isArray(ch?.addresses) ? ch.addresses : []).map((a) => String(a ?? '').trim());
      const bridges = (Array.isArray(ch?.bridges) ? ch.bridges : []).map((a) => String(a ?? '').trim());
      for (const a of [...seeds, ...addrs, ...bridges]) {
        if (a && !addrHashCache.has(a)) targets.add(a);
      }
    }
  }
  const list = [...targets].slice(0, 4000);
  if (!list.length) return;
  await Promise.all(list.map((a) => hashOf(a)));
  // Zugleich für die dauerhafte Vollanzeige verifizieren (Befund 2026-10-07,
  // Masken-Oszillation): die frischen Hashes sind so gegen spätere LRU-
  // Verdrängung abgesichert. denyLoaded prüft verifyFullShownAsync selbst —
  // vor dem ersten Deny-Load bleibt alles fail-closed in der Kurzform.
  await Promise.all(list.map((a) => verifyFullShownAsync(a)));
}

/* ------------------------------------------------------------------ */
/* Adresse: Kopieren + XRPScan-Link (nur bei voller Anzeige)           */
/* ------------------------------------------------------------------ */
function addrActionsHtml(address) {
  const a = String(address ?? '');
  const href = `https://xrpscan.com/account/${encodeURIComponent(a)}`;
  return (
    `<span class="addr-actions">` +
    `<button type="button" class="addr-copy" data-addr="${esc(a)}" aria-label="${esc(t('addr.copyAria'))}">${esc(t('addr.copy'))}</button>` +
    `<a class="addr-link" href="${esc(href)}" target="_blank" rel="noopener noreferrer" aria-label="${esc(t('addr.linkAria'))}" title="${esc(t('addr.linkAria'))}">↗</a>` +
    `</span>`
  );
}

/* ------------------------------------------------------------------ */
/* XRPScan-Namens-Badges (nur ergänzt; Adresse bleibt der Anzeigewert) */
/* ------------------------------------------------------------------ */
/* HOST-GATE (primär, nicht umgehbar): accountNameOf liefert null für jede
 * maskierte oder Deny-Treffer-Adresse — auch für Module ohne eigenes
 * isFullShownAddr (globe). shortAddr/displayFindingAddr/isFullShownAddr
 * bleiben unverändert; ein Name hängt nie an einer Kurzform-Adresse.
 * Ohne Namensindex-Modul oder ohne Lookup-Treffer: null → nur kein Badge,
 * Anzeige unverändert (fail-closed wie die addr-Aktionen). */
function accountNameOf(addr) {
  const a = String(addr ?? '');
  if (!nameIndexMod || !isFullShownAddr(a)) return null;
  try {
    return nameIndexMod.lookupNameCached(a) ?? null;
  } catch {
    return null;
  }
}

/* Name-Chip-Markup (Muster .role-chip/.risk-badge): Pill mit Name,
 * verified-Häkchen und Domain; aria über die Legenden-Keys. Rein
 * ergänzend — verdrängt nie die Adresse und erscheint nie ohne Gate. */
function nameChipHtml(addr) {
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
}

/* HOST-GATE der Exchange-Registry (analog accountNameOf): exchangeEntryOf
 * liefert null für jede maskierte oder Deny-Treffer-Adresse und ohne
 * Registry-Treffer — ein Tag-Chip hängt nie an einer Kurzform-Adresse. */
function exchangeEntryOf(addr) {
  const a = String(addr ?? '');
  if (!registryMod || !isFullShownAddr(a)) return null;
  try {
    return registryMod.exchangeEntryOf(a) ?? null;
  } catch {
    return null;
  }
}

/* HOST-GATE der Multi-User-Union (Registry ∪ verifizierte well-known-Namen,
 * Coverage-Fix 2026-10-05): dasselbe Gate-Muster — null für jede maskierte
 * oder Deny-Treffer-Adresse; verifizierte XRPScan-Namen (z. B. Binance-
 * Hot-Wallets, nicht in der 81er-Registry) erhalten jetzt einen Eintrag.
 * Lookup-Synchron über den geladenen Namens-Index (kein Zusatz-Fetch). */
function multiUserEntryOf(addr) {
  const a = String(addr ?? '');
  if (!registryMod || typeof registryMod.multiUserEntryOf !== 'function' || !isFullShownAddr(a)) return null;
  try {
    return registryMod.multiUserEntryOf(a) ?? null;
  } catch {
    return null;
  }
}

/* Tag-Chip-Markup (Muster nameChipHtml): Mono-Pill '#<Tag>' nur, wenn die
 * Adresse ein Multi-User-Konto ist (Registry ODER verifizierter well-known-
 * Name, host-seitig gegatet) UND ein gültiger Tag vorliegt. Rein ergänzend —
 * verdrängt nie die Adresse. Tag 0 ist ein echter Tag (lib/tag-identity.mjs)
 * und zeigt '#0'. */
function tagChipHtml(addr, tag) {
  if (tag == null || typeof tag !== 'number' || !Number.isInteger(tag)) return '';
  if (!multiUserEntryOf(addr)) return '';
  const aria = t('tag.chipAria');
  return `<span class="tag-chip" role="img" aria-label="${esc(aria)}" title="${esc(aria)}">#${esc(String(tag))}</span>`;
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

// Kanten-Farben je Tx-KATEGORIE (txCategory, public/edge-colors.mjs) statt
// Einzelltyp-Lookup (Audit 2026-10-07: die 11 Einzeltypen deckten ~11 von
// ~60 Mainnet-Typen ab, alles andere fiel in neutralem Grau unter). Werte =
// JS-Spiegel der --a6-edge-* Tokens (style.css, Hell-Initialwerte; Noir über
// THEME_JS_COLORS.edge — applyThemeColors mutiert dieses Objekt in place).
// 'fraud' ist der Override VOR der Kategorie (Kritiker-Pflicht 4):
// severity 'malicious' — direkt auf der Kante (Live-Pfad, lib/cluster.mjs:394)
// oder an einem BEIDER Endpunkte via severityByAddress (Flow-State-Kanten
// tragen kein severity-Feld, lib/flow-state.mjs viewEdge) — max-Regel
// identisch zur Kanten-Schreibung lib/cluster.mjs:382-394.
const EDGE_COLORS = {
  fraud: '#b3261e',   // = --a6-edge-fraud = --a6-sev-malicious (Hell)
  payment: '#066348', // = --a6-edge-payment = --a6-success (Hell) — bewusste
                      // 'grün=gut'-Bundlung (Kritiker-Pflicht 6, Option a);
                      // 1.33:1 Luminanzabstand zum Check/Channel-Teal
  market: '#b45309',  // = --a6-edge-market — DEX+AMM zusammengelegt (alte
                      // Einzeltöne lagen 1.02:1 zusammen, Kritiker-Pflicht 5)
  escrow: '#6d28d9',  // = --a6-edge-escrow
  check: '#0f766e',   // = --a6-edge-check (Check* + PaymentChannel*)
  admin: '#1d4ed8',   // = --a6-edge-admin (Konten-/Protokoll-Verwaltung)
  nft: '#c026d3',     // = --a6-edge-nft — Fuchsia statt Alt-Violett: Abstand
                      // zu Escrow 1.12:1 -> 1.51:1 (Kritiker-Pflicht 6)
};

// Kanten-Schwere inkl. Cluster-Kontext (Pflichtkorrektur 4): die rohen
// Flow-Kanten tragen severity nur im Live-Pfad (lib/cluster.mjs:394, max
// BEIDER Endpunkte); Flow-State-View-Kanten tragen KEINE (viewEdge). Der
// Override liest deshalb zusätzlich die severityByAddress des Clusters
// (beide Endpunkte; Client-Kopie cluster-views.mjs:43/:98-118) mit derselben
// max-Regel. true NUR für 'malicious' — suspect/info behalten die
// Kategorie-Farbe.
const SEV_OVERRIDE_RANK = { malicious: 3, suspect: 2, info: 1 };
function edgeIsFraud(e, sevByAddr) {
  const rank = (v) => SEV_OVERRIDE_RANK[String(v ?? '')] ?? 0;
  return Math.max(
    rank(e && e.severity),
    rank(sevByAddr && sevByAddr[String((e && e.from) ?? '')]),
    rank(sevByAddr && sevByAddr[String((e && e.to) ?? '')]),
  ) >= SEV_OVERRIDE_RANK.malicious;
}
// Neutraler Kanten-Ton — let (nicht const): applyThemeColors() tauscht den
// Wert beim Theme-Wechsel (Noir #8f8da0 = --a6-edge-neutral, 5.68:1 auf der
// dunklen Bühne; #62626b wäre dort nur ~2.2:1). Unbekannte Kanten-Typen
// lesen den Wert je Render, Kontext-Verbraucher (drilldown/globe) über den
// edgeDefault-Thunk.
let EDGE_DEFAULT = '#62626b';

// Rollen-Farbcodierung (Design-Vorgabe Astra 6): tonale Fläche, 1px
// Tintenrand je Rolle. Unknown seit dem 3D-Farb-Audit 2026-10-07 KEIN
// Neutralgrau mehr: der bisherige Hell-Wert #f0f0f2 lag mit 1.14:1 unter
// der weißen Bühne (Noir #262436: 1.21:1 auf #14131f) — die 3D-Kugel ohne
// Rand-Mesh war unsichtbar. Neu: entsättigtes Stahlblau (Hell) / Eisblau
// (Noir), beides ≥3:1 gegen beide Bühnen (Werte live per WCAG gerechnet)
// und gegen alle Rollen-/Kantentöne unterschieden; dieselben Werte wie
// --a6-swatch-unknown/--a6-role-unknown (style.css) — Legende, 3D-Kugel
// und Kartenrahmen teilen sich EINE Unknown-Farbe.
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
    background: '#4a6478', border: '#dbe6f2',
    highlight: { background: '#5d788f', border: '#dbe6f2' },
    hover: { background: '#5d788f', border: '#dbe6f2' },
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

/* ------------------------------------------------------------------ */
/* Theme-JS-Palette (Noir-Theme 2026-10-06)                            */
/* ------------------------------------------------------------------ */

/* Die Canvas-Layer (vis-network 2D, 3d-force-graph, Globe) lesen CSS-Tokens
 * nicht live — ihre Farben stehen als JS-Literale. THEME_JS_COLORS ist die
 * JS-Gegentafel zu den Token-Blöcken in style.css ([data-a6] und
 * [data-a6][data-theme="noir"]; Werte dort als Kontrasttabelle geprüft,
 * Text ≥ 4.5 / UI ≥ 3 je Paar — Regeltests in design-assets.test.mjs).
 * applyThemeColors(theme) MUTIERT die bestehenden Objekte in place —
 * drilldown.js/globe.js halten Referenzen auf genau diese Objekte (ctx),
 * die Identität bleibt also gültig. Unbekannte Rolle 'unknown' ist aus-
 * drücklich Teil der Tabelle (3D-Farb-Audit 2026-10-07: Noir Eisblau
 * #bfe3ff / Rand #46587e, Hell Stahlblau #4a6478 / Rand #dbe6f2 — wie
 * --a6-swatch-unknown/--a6-role-unknown, derselbe Teller wie die CSS-Seite;
 * ≥3:1 gegen beide Bühnen --a6-graph-canvas, vorher 1.21:1 bzw. 1.14:1).
 * Layer-Regel: Kugeln = Rollenfarbe, Kanten = Tx-Kategorie — Eisblau steht
 * ausschließlich auf Knoten, Grüns nur auf Kanten (Konfliktvermeidung). */
const THEME_JS_COLORS = {
  light: {
    canvasInk: '#141416',      // = --a6-ink (Hell)
    canvasBody: '#484850',     // = --a6-body
    edgeDefault: '#62626b',    // = --a6-edge-neutral
    edgeHighlight: '#141416',
    edge: {
      // Kategorie-Schlüssel (txCategory) = --a6-edge-* Tokens (Hell).
      fraud: '#b3261e', payment: '#066348', market: '#b45309', escrow: '#6d28d9',
      check: '#0f766e', admin: '#1d4ed8', nft: '#c026d3',
    },
    roles: {
      source: { background: '#16305c', border: '#0f2445', highlight: { background: '#2a4a7c', border: '#0f2445' }, hover: { background: '#2a4a7c', border: '#0f2445' } },
      drainer: { background: '#b3261e', border: '#7f1d1d', highlight: { background: '#d03b33', border: '#7f1d1d' }, hover: { background: '#d03b33', border: '#7f1d1d' } },
      collector: { background: '#b45309', border: '#7c3a06', highlight: { background: '#c96a1f', border: '#7c3a06' }, hover: { background: '#c96a1f', border: '#7c3a06' } },
      relay: { background: '#0f766e', border: '#115e59', highlight: { background: '#1a8d84', border: '#115e59' }, hover: { background: '#1a8d84', border: '#115e59' } },
      unknown: { background: '#4a6478', border: '#dbe6f2', highlight: { background: '#5d788f', border: '#dbe6f2' }, hover: { background: '#5d788f', border: '#dbe6f2' } },
    },
    cluster: {
      color: { background: '#ffffff', border: '#17171b', highlight: { background: '#f6f6f7', border: '#141416' }, hover: { background: '#f6f6f7', border: '#141416' } },
      fontColor: '#141416',
    },
  },
  noir: {
    canvasInk: '#f2f1f8',      // = --a6-ink (Noir) 16.38 ✓
    canvasBody: '#c9c7d6',     // = --a6-body 11.05 ✓
    edgeDefault: '#8f8da0',    // = --a6-edge-neutral 5.68 ✓
    edgeHighlight: '#f2f1f8',  // 16.38 ✓
    edge: {
      // Kategorie-Schlüssel (txCategory) = --a6-edge-* Tokens (Noir-Block).
      // payment = --a6-success exakt (#4ade80): bewusste 'grün=gut'-Bundlung
      // (Kritiker-Pflicht 6, Option a) — Luminanzabstand zum Check-Teal
      // bleibt 1.11:1, dokumentiert; der nicht-farbliche Betrugskanal
      // (gestrichelte Fraud-Kanten) trägt die Unterscheidung zur Rot-Seite.
      // nft #d946ef: Abstand zu Escrow 1.08:1 -> 1.52:1, zu Payment 1.98:1.
      fraud: '#ff7a70', payment: '#4ade80', market: '#ffb45e', escrow: '#b79cff',
      check: '#3ecfbb', admin: '#8ab4ff', nft: '#d946ef',
    },
    roles: {
      source: { background: '#7d9bff', border: '#5f7ddb', highlight: { background: '#9db5ff', border: '#5f7ddb' }, hover: { background: '#9db5ff', border: '#5f7ddb' } },
      drainer: { background: '#ff7a70', border: '#d95f56', highlight: { background: '#ff9d94', border: '#d95f56' }, hover: { background: '#ff9d94', border: '#d95f56' } },
      collector: { background: '#ffb45e', border: '#c98a45', highlight: { background: '#ffcb8f', border: '#c98a45' }, hover: { background: '#ffcb8f', border: '#c98a45' } },
      relay: { background: '#3ecfbb', border: '#2fa393', highlight: { background: '#74ded0', border: '#2fa393' }, hover: { background: '#74ded0', border: '#2fa393' } },
      unknown: { background: '#bfe3ff', border: '#46587e', highlight: { background: '#d9efff', border: '#46587e' }, hover: { background: '#d9efff', border: '#46587e' } },
    },
    cluster: {
      color: { background: '#262436', border: '#f2f1f8', highlight: { background: '#322f47', border: '#f2f1f8' }, hover: { background: '#322f47', border: '#f2f1f8' } },
      fontColor: '#f2f1f8',
    },
  },
};

// Aktuell angezeigte Canvas-Tinten (von applyThemeColors gesetzt); die
// Renderpfade (updateRawGraph/initGraph) lesen diese Variablen statt
// hartcodierter Hex.
let canvasInk = '#141416';
let canvasBody = '#484850';

// Aktuell ANGEWANDES Theme (body[data-theme]; Inline-Bootstrap und
// initThemeSwitcher halten es synchron). Guard: ohne DOM/Body → Hell
// (Verhalten aller Node-Tests unverändert).
function currentJsTheme() {
  try {
    return document.body && document.body.dataset && document.body.dataset.theme === 'noir' ? 'noir' : 'light';
  } catch { return 'light'; }
}

// Tiefes Zusammenführen NUR über die in der Tabelle vorhandenen Schlüssel —
// Zielobjekte (und deren Identität) bleiben bestehen, Nested-Objekte
// (highlight/hover/color/font) werden rekursiv in place überschrieben.
function assignColorFields(target, src) {
  for (const key of Object.keys(src)) {
    const val = src[key];
    if (val && typeof val === 'object' && target[key] && typeof target[key] === 'object') {
      assignColorFields(target[key], val);
    } else {
      target[key] = val;
    }
  }
}

// Palette auf die Canvas-Objekte anwenden. Das vis-Network-Optionsobjekt
// wird bei Konstruktion gelesen — nachträgliche Mutation allein greift
// nicht, die Options-Defaults werden deshalb über network.setOptions()
// nachgeführt (etablierter Re-Set-Pfad; die DataSets färbt der Theme-
// Listener über den nächsten renderLiveGraph-Durchlauf um).
function applyThemeColors(theme) {
  const pal = THEME_JS_COLORS[theme] || THEME_JS_COLORS.light;
  canvasInk = pal.canvasInk;
  canvasBody = pal.canvasBody;
  assignColorFields(EDGE_COLORS, pal.edge);
  EDGE_DEFAULT = pal.edgeDefault;
  assignColorFields(ROLE_COLORS, pal.roles);
  assignColorFields(CLUSTER_NODE_PROPERTIES, pal.cluster);
  if (network) {
    try {
      network.setOptions({
        nodes: {
          font: { color: canvasInk },
          color: {
            background: CLUSTER_NODE_PROPERTIES.color.background,
            border: CLUSTER_NODE_PROPERTIES.color.border,
            highlight: { ...CLUSTER_NODE_PROPERTIES.color.highlight },
            hover: { ...CLUSTER_NODE_PROPERTIES.color.hover },
          },
        },
        edges: {
          color: { highlight: canvasInk, hover: canvasInk },
          font: { color: canvasBody },
        },
      });
    } catch { /* egal — der Theme-Listener zieht die DataSets separat nach */ }
  }
}

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

/* vis-network lazy (Muster globe.js:254-268 loadGlobeGl): der 652-kB-Bundle
 * war bisher das einzige eager <script> im Head (index.html alt:222) und
 * blockierte den Erstanstrich. Jetzt: lokales Bundle vendor/vis-network.min.js
 * (sha384 identisch zum bisherigen CDN-Pin — Download in dieser Session
 * verifiziert), injiziert erst beim ersten vis-Bedarf. Singleton-Promise;
 * nach Fehler kein Blink-Loop (initGraph-Guard schreibt die Fehlermeldung). */
const VIS_NETWORK_URL = 'vendor/vis-network.min.js';
const VIS_NETWORK_INTEGRITY = 'sha384-RDdG1CLOxjNlTHh4JYx/rnAueaMHbkBHmeHwrEyljMQw3LF0it4SkuNotIY/FPxD';
let visPromise = null;
function loadVisNetwork() {
  if (typeof vis !== 'undefined') return Promise.resolve(true);
  if (visPromise) return visPromise;
  visPromise = new Promise((resolve) => {
    const s = document.createElement('script');
    s.src = VIS_NETWORK_URL;
    s.integrity = VIS_NETWORK_INTEGRITY; // SRI wie beim bisherigen CDN-Pin
    s.crossOrigin = 'anonymous';
    s.async = true;
    s.onload = () => resolve(typeof vis !== 'undefined');
    s.onerror = () => resolve(false);
    document.head.appendChild(s);
  });
  return visPromise;
}

/* Erster sichtbarer vis-Bedarf (Graph-Tab live/cluster) ODER eintreffende
 * Daten (rebuildClusterGraph / applyFlowStateView → renderLiveGraph):
 * Bundle laden, Netz konstruieren, dann lastClusterGraph SOFORT nachrendern
 * — ohne diesen Re-Render bliebe die Bühne bis zum nächsten Poll-Takt leer.
 * bindGraph bleibt beim Start (seine Handler brauchen vis nicht). */
let visGraphInit = false;
function ensureVisGraph() {
  if (network || visGraphInit) return;
  visGraphInit = true;
  void loadVisNetwork().then(() => {
    if (network) return;
    initGraph(); // vis-undefined-Fehlerpfad: initGraph-Guard (graph.visError)
    if (network) {
      network.resize();
      if (lastClusterGraph) renderLiveGraph(lastClusterGraph);
    }
  }).catch(() => {
    /* Nachrendern kann werfen (z. B. vis-interne Kanten auf fehlende Knoten
     * nach dem Knoten-Deckel). visGraphInit bleibt true — kein Retry-Loop;
     * der nächste Poll-Takt (renderLiveGraph/setGraphTab) rendert erneut. */
  });
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
      // Options-Defaults theme-geführt (Noir-Theme): initGraph läuft lazy —
      // applyThemeColors(currentJsTheme()) hat zum Startzeitpunkt bereits
      // die Tafel angewandt; der Theme-Wechsel läuft später über
      // network.setOptions() (Optionsobjekt wird hier gelesen).
      nodes: {
        shape: 'dot',
        borderWidth: 1,
        borderWidthSelected: 2,
        font: { color: canvasInk, size: 13, face: '"JetBrains Mono", ui-monospace, Consolas, monospace' },
        color: {
          background: CLUSTER_NODE_PROPERTIES.color.background,
          border: CLUSTER_NODE_PROPERTIES.color.border,
          highlight: { ...CLUSTER_NODE_PROPERTIES.color.highlight },
          hover: { ...CLUSTER_NODE_PROPERTIES.color.hover },
        },
      },
      edges: {
        width: 1,
        smooth: { type: 'curvedCW', roundness: 0.14 },
        arrows: { to: { enabled: true, scaleFactor: 0.5 } },
        color: { color: EDGE_DEFAULT, highlight: canvasInk, hover: canvasInk },
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
 * (vor dem Clustering bzw. im Live-Tab).
 * maxNodes (optional, Default null = uncapped): Live-Bühnen-Deckel gegen
 * Physik-Einbruch (Diagnose: 2,8 fps ohne Cap). Der Cap darf NICHT in den
 * Cluster-Pfad: applyClustering ruft updateRawGraph und clustering.cluster
 * aggregiert genau diese nodesDS — ein Cap dort würde Cluster-Bubbles auf
 * die Top-N-Teilmenge verzerren. Deshalb uncapped aus applyClustering,
 * capped nur an den Live-Aufrufstellen (renderLiveGraph/setGraphTab).
 * Auswahl: dreiphasiger Budget-Satz in ./graph-budget.mjs (Kritik-Runde 3 —
 * Archiv-Parität): Phase A Evidenz-Floor (Rolle source/collector/drainer ODER
 * severity malicious, Rang severity desc → roleRank desc → id asc, Deckel
 * 120), Phase B Endpunkte der volumen-stärksten Kanten in topKEdges-
 * Totalordnung, Phase C Auffüllung nach Schwere → Drops-Summe → Adresse.
 * Der alte reine Schwere/Drops-Sort degenerierte im Archiv-Pfad (alle
 * malicious, keine Drops) zum lexikografischen Ausschnitt: 1/975 Kanten,
 * 596/600 Knoten 'unknown'. */
const LIVE_GRAPH_MAX_NODES = 600;
function updateRawGraph(cg, maxNodes = null) {
  if (!network) return;
  let rawNodes = Array.isArray(cg.nodes) ? cg.nodes : [];
  const rawEdgesAll = Array.isArray(cg.edges) ? cg.edges : [];
  let cappedNodeIds = null;
  if (Number.isInteger(maxNodes) && maxNodes > 0 && rawNodes.length > maxNodes) {
    rawNodes = selectCappedNodes(rawNodes, rawEdgesAll, maxNodes);
    // Kanten hängen an Knoten: ohne Filter würden Kanten auf gekappte
    // Knoten im DataSet schweben (vis-Warnung, Phantom-Kanten).
    cappedNodeIds = new Set(rawNodes.map((n) => String(n.id)));
  }
  const rawEdges = cappedNodeIds
    ? rawEdgesAll.filter((e) => cappedNodeIds.has(String(e.from)) && cappedNodeIds.has(String(e.to)))
    : rawEdgesAll;

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

  // severityByAddress über ALLE Cluster des Graphen unionen (max je Adresse,
  // SEV_RANK wie cluster-views.mjs) — Basis des Fraud-Overrides für Kanten
  // ohne eigenes severity-Feld (Kritiker-Pflichtkorrektur 4).
  const sevByAddr = {};
  for (const c of Array.isArray(cg.clusters) ? cg.clusters : []) {
    const sba = c && typeof c.severityByAddress === 'object' ? c.severityByAddress : null;
    if (!sba) continue;
    for (const [a, s] of Object.entries(sba)) {
      const v = String(s ?? '');
      if ((SEV_RANK[v] ?? 0) > (SEV_RANK[sevByAddr[a]] ?? 0)) sevByAddr[a] = v;
    }
  }
  const nextEdges = rawEdges.map((e) => {
    // type bleibt ROH: Edge-Id (`${e.from}->${e.to}::${type}`) und
    // Kategorien-Lookup dürfen bei Sprachwechsel nicht wandern (sonst
    // stale Kanten im inkrementell gepflegten vis-Netz). Nur das Label
    // wird übersetzt gerendert.
    const type = String(e.type || 'Sonstige');
    const typeLabel = type === 'Sonstige' ? t('edge.other') : type;
    // Fraud-Override VOR der Kategorie-Farbe (Kritiker-Pflichtkorrektur 4).
    const fraud = edgeIsFraud(e, sevByAddr);
    return {
      id: String(e.txHash || `${e.from}->${e.to}::${type}`),
      from: String(e.from),
      to: String(e.to),
      label: typeLabel,
      // Kanten-Tooltip: volle Adressen bei geladener Allowlist und Nicht-Treffer
      // auf der Deny-Liste, sonst Kurzform (displayFindingAddr, fail-closed).
      // Tag-Suffix nur bei Multi-User-Treffer des Ziels (Registry ODER
      // verifizierter well-known-Name, multiUserEntryOf-Gate) und belegtem
      // toTag — an der Kurzform nie (fail-closed).
      title: `${displayFindingAddr(e.from)} → ${displayFindingAddr(e.to)} (${typeLabel})`
        + (e.toTag != null && multiUserEntryOf(e.to) ? ` · #${e.toTag}` : ''),
      color: { color: fraud ? EDGE_COLORS.fraud : (EDGE_COLORS[txCategory(type)] || EDGE_DEFAULT), highlight: canvasInk, hover: canvasInk },
      // Deutan-Zweitkanal (Kritiker-Pflichtkorrektur 6): Betrugskanten
      // GESTRICHELT — Fraud-Rot und Payment-Grün liegen luminanznah (1.11:1
      // Hell) und sind auf der Rot-Grün-Achse verwechselbar, das Muster
      // bleibt. Cluster-Verbund-Kanten nutzen dieselbe Dash-Form, aber nur
      // im Cluster-Tab und in neutralen Farben (applyClustering).
      ...(fraud ? { dashes: [6, 4] } : {}),
      font: { color: canvasBody, size: 12, face: '"JetBrains Mono", ui-monospace, Consolas, monospace', strokeWidth: 0, align: 'middle' },
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
  // Transit-Hinweis im Bubble-Tooltip (tagIdentityDesign): nur bei belegter
  // transit-Kante des Clusters (c.edges aus Server-View oder Graph-Neubau).
  const transit = Array.isArray(c.edges) && c.edges.some((e) => e && e.transit === true)
    ? ` · ${t('cluster.transitNote')}`
    : '';
  return `${c.label ?? t('cluster.labelDefault')}: ${members}${transit}`;
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

  // Cluster-zu-Cluster-Kanten dezent: 1px, gestrichelt, neutrale Töne
  // (theme-geführt — EDGE_DEFAULT/canvasInk lesen applyThemeColors).
  for (const e of edgesDS.get()) {
    if (isClusterNode(e.from) && isClusterNode(e.to)) {
      edgesDS.update({
        id: e.id,
        width: 1,
        dashes: [6, 4],
        color: { color: EDGE_DEFAULT, highlight: canvasInk, hover: canvasInk },
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

/* Zeitfenster der Bühne (Kritik-Runde 3, Ask-Punkt 2): im Archiv-Modus greift
 * der gewählte Fensterwert (24h/3d/7d/30d/90d) auf die Kanten zu — nur die
 * vis-Bühne, nie lastClusterGraph selbst (Drilldown, Karten und Export halten
 * bewusst den vollen Bestand). Kanten ohne parsebares closeTime bleiben
 * (kein Zeitanspruch, Cluster-Evidenz — graph-budget.mjs). Der Cluster-Tab
 * bleibt ungefiltert: clustering.cluster aggregiert die volle Knotenmenge. */
function stageGraph(cg) {
  if (!cg || feedMode !== 'history') return cg;
  const windowMs = FEED_RANGE_MS[feedRange];
  if (windowMs == null) return cg;
  const kept = edgesInWindow(cg.edges, windowMs, Date.now());
  if (kept.length === (Array.isArray(cg.edges) ? cg.edges.length : 0)) return cg;
  return { ...cg, edges: kept };
}

/* Ehrliche truncated-Kennzeichnung des Bühnenfensters: greift der gewählte
 * Wert über den vorhandenen Bestand hinaus (älteste Kantenzeit jünger als das
 * Fenster), sagt die Notiz es — ohne Bestand/Zeitstempel wird nichts
 * behauptet (still ausgeblendet, kein Pauschal-Verdacht). */
function renderGraphWindowNote() {
  const el = document.getElementById('graph-window-note');
  if (!el) return;
  if (feedMode !== 'history' || !lastClusterGraph || !Array.isArray(lastClusterGraph.edges)) {
    el.hidden = true;
    return;
  }
  const windowMs = FEED_RANGE_MS[feedRange];
  const oldest = oldestEdgeMs(lastClusterGraph.edges);
  if (windowMs == null || oldest == null || Date.now() - oldest >= windowMs) {
    el.hidden = true;
    return;
  }
  el.textContent = t('graph.windowTruncated', {
    range: t('range.' + feedRange),
    depth: fmtDateTime(oldest),
  });
  el.hidden = false;
}

/* Archiv-Notiz mit den ehrlichen Fenstern (Kritik-Runde 3, T2.1): im
 * Archiv-Modus sichtbar — Retention und Kanten-/Rollen-Semantik des
 * persistierten Bestands; im Live-Modus ausgeblendet. */
function renderGraphArchiveNote() {
  const el = document.getElementById('graph-archive-note');
  if (!el) return;
  if (feedMode !== 'history') { el.hidden = true; return; }
  el.textContent = t('graph.noteArchive');
  el.hidden = false;
}

function renderLiveGraph(cg) {
  if (!cg) return;
  renderGraphWindowNote(); // Fenster-Notiz bei jedem Daten-Tick (auch ohne vis-Netz)
  renderGraphArchiveNote();
  if (!network) { ensureVisGraph(); return; } // eintreffende Daten: lazy-Laden anstoßen; ensureVisGraph rendert lastClusterGraph nach dem Init selbst
  if (activeGraphTab === 'cluster') {
    applyClustering(cg); // Cluster-Pfad bleibt uncapped: clustering.cluster aggregiert genau diese nodesDS
    return;
  }
  updateRawGraph(stageGraph(cg), LIVE_GRAPH_MAX_NODES); // Live-Bühne: Fensterfilter + Knoten-Deckel (Physik-Einbruch-Schutz)
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
    // PNG-Export ist bewusst nur fürs vis-Netz vorgesehen (Weltkugel ist ein
    // WebGL-Canvas ohne preserveDrawingBuffer — der Export wäre schwarz und
    // exportGraphPng early-returnt still): auf der Weltkugel wird der Button
    // versteckt statt still no-op.
    document.getElementById('graph-png').hidden = true;
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
  document.getElementById('graph-png').hidden = false; // vis-Bühne: Export wieder sichtbar
  if (!network) { ensureVisGraph(); return; } // vis noch nicht init: Bühnenwechsel genügt, lazy-Laden angestoßen; Nachrendern erfolgt in ensureVisGraph
  requestAnimationFrame(() => { try { network.resize(); } catch { /* egal */ } });
  if (tab === 'cluster') {
    listEl.hidden = !hasClusters;
    emptyEl.hidden = hasClusters;
    if (lastClusterGraph) applyClustering(lastClusterGraph); // uncapped (Cluster-Bubbles brauchen die volle Knotenmenge)
  } else {
    listEl.hidden = true;
    emptyEl.hidden = true;
    openAllClusters();
    network.setOptions({ physics: PHYSICS_LIVE });
    if (lastClusterGraph) updateRawGraph(stageGraph(lastClusterGraph), LIVE_GRAPH_MAX_NODES); // Live-Bühne: Fensterfilter + capped
  }
}

/* ---------------- Cluster-Zusammenfassungs-Karten ---------------- */

// SEV_RANK kommt jetzt aus ./cluster-views.mjs (Import oben) — single source
// für Karten-Badge und Merge-Sortierung.
const ROLE_ORDER = ['drainer', 'collector', 'relay', 'source', 'unknown']; // Dominanz wie Rollenkonflikt
// ROLE_LABEL bleibt die kanonische (deutsche) Rollen-Tafel — ctx-Partner
// (drilldown/account-check) greifen darauf zurück. Für Anzeigen im Host
// übersetzt roleLabelText über die Legenden-Keys (EN: Collector, DE: Kollektor).
const ROLE_LABEL = { source: 'Source', drainer: 'Drainer', collector: 'Kollektor', relay: 'Relay', unknown: 'Unknown' };
const roleLabelText = (role) => t('legend.' + role);

/* Verdichtungsstufen der Cluster-Karten (Design P2, nur Anzeige — keine
   Datenlogik): 'comfortable' (Default), 'compact' (engeres Karten-Polster,
   Metrik-/Zeit-Gaps 14→10 px, Zeiten einzeilig), 'dense' (zusätzlich
   Adress-Chips 5→3 und Flusskette maxPaths 2→1, Primärmetrik 20→17 px).
   Persistierung über localStorage 'hx-density' (guardiert — ohne Storage
   bleibt die Wahl flüchtig). Mega-Cluster (Mitglieder > 100 ODER
   distinctAccounts ≥ 100, Vorbild 3D-Aggregatknoten drilldown.js) erzwingen
   dense-Chips und EINEN Kettenpfad UNABHÄNGIG von der globalen Stufe —
   endlose Member-Listen werden zur Aggregat-Karte (Meta-Zeile
   cluster.megaNote, Plan-Kritik 10: genau EIN '+N weitere'-Hinweis pro
   Karte, geteilte i18n-Keys mit der Adress-Chip-Zeile). */
const DENSITY_KEY = 'hx-density';
const DENSITY_LEVELS = ['comfortable', 'compact', 'dense'];
const MEGA_MEMBER_THRESHOLD = 100;
let clusterDensity = 'comfortable';

function loadClusterDensity() {
  try {
    const v = String(localStorage.getItem(DENSITY_KEY) ?? '');
    if (DENSITY_LEVELS.includes(v)) clusterDensity = v;
  } catch { /* Storage nicht verfügbar: Default bleibt */
  }
}

// Attribut-Sync (Liste + Segment-Control): wird bei Starten und jedem
// Stufenwechsel aufgerufen; renderClusterList setzt data-density bei jedem
// Rendern zusätzlich selbstheilend neu.
function syncClusterDensityUi() {
  const listEl = document.getElementById('cluster-list');
  if (listEl) listEl.setAttribute('data-density', clusterDensity);
  for (const lvl of DENSITY_LEVELS) {
    const btn = document.getElementById('density-' + lvl);
    if (btn) btn.setAttribute('aria-pressed', String(lvl === clusterDensity));
  }
}

function setClusterDensity(level) {
  const target = DENSITY_LEVELS.includes(level) ? level : 'comfortable';
  if (target === clusterDensity) return;
  clusterDensity = target;
  try { localStorage.setItem(DENSITY_KEY, target); } catch { /* Storage optional */ }
  syncClusterDensityUi();
  // Einmaliger Neu-Aufbau der Liste (innerHTML) — dasselbe Muster wie pro
  // Daten-Tick; ohne Cluster-Bestand greift der nächste Rendertick.
  if (lastClusterGraph && Array.isArray(lastClusterGraph.clusters)) {
    renderClusterList(lastClusterGraph.clusters);
  }
}

// Flusskette als Markup: Pfade aus flowPaths (lib/cluster.mjs) werden entlang
// EBENER KANTEN mit '→' verbunden; mehrere Pfade trennt ein '·'. Volle
// Adresse + Kopier-Button + XRPScan-Link nur bei erlaubter Vollanzeige
// (Allowlist geladen, kein Deny-Treffer); sonst Kurzform ohne beides.
function flowChainHtml(paths, opts = {}) {
  const maxChips = Number.isFinite(opts.maxChips) ? Math.max(2, Math.floor(opts.maxChips)) : 10;
  // Edge-Tag-Lookup (from→to → toTag) aus dem aktuellen Cluster-Graphen:
  // Tags sind Edge-Attribute, der Chip hängt am Ziel-Knoten der Kette.
  // Persistierte Ketten ohne Kante im Graphen (Peeling-Server-View) liefern
  // keinen Treffer → kein Chip (fail-closed, erfundene Tags gibt es nicht).
  const tagByPair = new Map();
  if (lastClusterGraph && Array.isArray(lastClusterGraph.edges)) {
    for (const e of lastClusterGraph.edges) {
      if (e && e.toTag != null) tagByPair.set(`${String(e.from)}\u0001${String(e.to)}`, e.toTag);
    }
  }
  const chip = (x, prevId) => {
    const address = String(x?.id ?? '');
    const shown = displayFindingAddr(address);
    const actions = isFullShownAddr(address) ? addrActionsHtml(address) : '';
    // Name nur hinter demselben Gate (accountNameOf ist host-seitig gegatet)
    // und nur als ergänzender Chip — der Anzeigewert bleibt die Adresse.
    const nameChip = nameChipHtml(address);
    // Tag-Chip nur bei Multi-User-Treffer des Ziels (Registry ODER
    // verifizierter well-known-Name, multiUserEntryOf, gleiches Gate) und
    // belegter Kante mit toTag — nie an der Kurzform.
    const tag = prevId != null ? tagByPair.get(`${String(prevId)}\u0001${address}`) : null;
    const tagChip = tagChipHtml(address, tag);
    // title trägt NUR den Anzeigewert (gerenderter displayFindingAddr-Wert),
    // nie die Roheadresse (Design-Fix, Muster drilldown.js-Konten-Tabelle).
    return `<span class="chain-node chain-${esc(x?.role ?? 'unknown')}" title="${esc(shown)}">${esc(shown)}${actions}${nameChip}${tagChip}</span>`;
  };
  const parts = [];
  let used = 0;
  for (const p of Array.isArray(paths) ? paths : []) {
    if (!Array.isArray(p) || p.length < 2 || used + p.length > maxChips) continue;
    parts.push(p.map((x, i) => chip(x, i > 0 ? p[i - 1]?.id : null)).join('<span class="chain-arrow" aria-hidden="true">→</span>'));
    used += p.length;
  }
  if (!parts.length) return '';
  return parts.join('<span class="chain-path-sep" aria-hidden="true">·</span>');
}

function clusterCardHtml(c, index) {
  // Cluster-Schweregrad = max der Mitglieder-Schweregrade aus dem Knoten-Cache.
  // dropsByAddr (dieselbe Schleife) sortiert die Namens-Chips nach Drops.
  const sevByAddr = new Map();
  const dropsByAddr = new Map();
  if (lastClusterGraph && Array.isArray(lastClusterGraph.nodes)) {
    for (const n of lastClusterGraph.nodes) {
      sevByAddr.set(String(n.id), String(n.severity ?? 'info'));
      dropsByAddr.set(String(n.id), (Number(n.inDrops) || 0) + (Number(n.outDrops) || 0));
    }
  }
  // Schweregrad-Berechnung (Fix 2026-10-06): Knoten-Cache (WSS-Pfad) ODER
  // die eigene severityByAddress des Clusters. Persistierte Cluster aus dem
  // Flow-State-Merge (mergeClusterViews) haben Mitglieder, die NICHT im
  // Live-Knoten-Cache stehen — ohne diesen Zweig erschiene ein malicious
  // persistierter Cluster badge-los.
  const ownSev = c.severityByAddress && typeof c.severityByAddress === 'object' ? c.severityByAddress : null;
  let sev = 'info';
  const considerSev = (s) => {
    if ((SEV_RANK[s] ?? 0) > (SEV_RANK[sev] ?? 0)) sev = s;
  };
  for (const a of c.memberAddresses ?? []) {
    considerSev(sevByAddr.get(String(a)) ?? 'info');
    if (ownSev) considerSev(ownSev[String(a)] ?? 'info');
  }
  if (ownSev) {
    for (const s of Object.values(ownSev)) considerSev(s);
  }

  // Mega-/Verdichtungs-Entscheidung (Design P2, reine Anzeige): Mega-Schwellen
  // nach Plan (Mitglieder > 100 ODER distinctAccounts ≥ 100); dense-Chips und
  // EIN Kettenpfad gelten für Mega-Karten immer, für 'dense' global.
  const memberCount = (c.memberAddresses ?? []).length;
  const isMega = memberCount > MEGA_MEMBER_THRESHOLD || (Number(c.distinctAccounts) || 0) >= MEGA_MEMBER_THRESHOLD;
  const denseLevel = isMega || clusterDensity === 'dense';
  const addrCap = denseLevel ? 3 : 5;
  const maxPaths = denseLevel ? 1 : 2;

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

  // Tags je Adresse (Coverage-Fix 2026-10-06, Adress-Chip-Zeile): distinct
  // toTags der Cluster-Kanten — die Server-View trägt c.edges (ihr toTag ist
  // serverseitig bereits Registry-/verified-gegatet, lib/flow-state.mjs
  // viewEdge), der WSS-Pfad führt Kanten nur global im Graphen und wird gegen
  // die Mitglieder gefiltert (dieselbe Filterung wie die Flusskette unten).
  // Tags sind ausschließlich aufgezeichnete Kanten-Attribute
  // (lib/cluster.mjs:344-345) — nie erfunden, nie an maskierten Adressen
  // (die Chip-Funktionen gatet der Host).
  const memberSet = new Set((c.memberAddresses ?? []).map(String));
  const clusterEdges = Array.isArray(c.edges) && c.edges.length
    ? c.edges
    : (lastClusterGraph && Array.isArray(lastClusterGraph.edges) ? lastClusterGraph.edges : []);
  const tagsByAddr = collectTagsByAddr(clusterEdges, memberSet);

  // Flusskette: echte Start-bis-Ende-Pfade aus den Cluster-Kanten (flowPaths,
  // lib/cluster.mjs) — '→' verbindet nur Adressen entlang belegter
  // Transaktionen, nie rollenweise aneinandergereihte Chips ohne Kantenbezug
  // (Befund 2026-09-29).
  let chainInner = '';
  let clusterTransit = false;
  if (flowPathsFn && lastClusterGraph) {
    const memberNodes = (Array.isArray(lastClusterGraph.nodes) ? lastClusterGraph.nodes : [])
      .filter((n) => memberSet.has(String(n.id)))
      .map((n) => ({ id: String(n.id), role: n.role }));
    const memberEdges = (Array.isArray(lastClusterGraph.edges) ? lastClusterGraph.edges : [])
      .filter((e) => memberSet.has(String(e.from)) && memberSet.has(String(e.to)));
    // Transit-Hinweis (tagIdentityDesign): läuft eine Cluster-Kante über ein
    // gemeinsames Börsen-Konto mit unterschiedlichen Destination-Tags
    // (e.transit, lib/tag-identity.mjs), zeigt die Karte einen Text-Hinweis —
    // keine Score-/Topologie-Änderung, reine Anzeigeverfeinerung.
    if (memberEdges.some((e) => e.transit === true)) clusterTransit = true;
    chainInner = flowChainHtml(flowPathsFn(memberNodes, memberEdges.map((e) => ({ from: String(e.from), to: String(e.to) })), { maxPaths, maxPathLen: 5 }), { maxChips: 8 });
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

  // Adress-Chip-Zeile (Coverage-Fix 2026-10-06): Mitglieder MIT Name- ODER
  // Tag-Chip — Exchange-Konten mit belegtem Destination-Tag ohne XRPScan-
  // Namen waren bisher unsichtbar (die Zeile zeigte nur Name-Treffer), obwohl
  // genau das das Ziel der Börse/Tag-Anzeige ist. Muster Drilldown-Tabelle:
  // pro Adresse nameChipHtml + tagChipHtml (aufsteigend, Cap 3 + '+'),
  // Drops-Sortierung wie bisher (Tiebreak: Tags, dann Adresse), Cap 5 Adressen.
  // Fail-closed unverändert: nameChipHtml→accountNameOf und
  // tagChipHtml→multiUserEntryOf sind host-seitig gegatet (isFullShownAddr);
  // maskierte oder Deny-Treffer-Adressen liefern nie einen Chip, Tags kommen
  // nur aus belegtem edge.toTag. Ohne Treffer bleibt die Karte unverändert.
  // moreChip (Design P2): '+N weitere Konten'-Hinweis nur bei tatsächlich
  // gekappter Zeile, title mit der vollen Mitgliederzahl. Mega-Karten zeigen
  // bewusst KEINEN Zweit-Hinweis hier (Plan-Kritik 10) — der Callback sammelt
  // stattdessen die Zahl der gezeigten Chip-Gruppen für die Meta-Zeile ein.
  let shownChipEntries = 0;
  const namesHtml = addrChipsRowHtml({
    members: c.memberAddresses ?? [],
    tagsByAddr,
    nameChipHtml,
    tagChipHtml,
    dropsByAddr,
    cap: addrCap,
    tagCap: 3,
    sort: 'drops',
    moreChip: isMega
      ? (hidden, shown) => { shownChipEntries = shown; return ''; }
      : (hidden) => hidden > 0
        ? `<span class="cluster-addr-more" title="${esc(t('cluster.moreAccountsTitle', { n: fmtNum(memberCount) }))}">${esc(t('cluster.moreAccounts', { n: fmtNum(hidden) }))}</span>`
        : '',
  });

  // Mega-Meta-Zeile (Vorbild 3D-Aggregatknoten): 'weitere Konten' = alles,
  // was die Karte nicht einzeln als Chip zeigt — ehrlich gegen die eigene
  // Oberfläche, keine erfundenen Zähler.
  const megaNoteHtml = isMega
    ? `<div class="cluster-mega-note">${esc(t('cluster.megaNote', { n: fmtNum(Math.max(memberCount - shownChipEntries, 0)) }))}</div>`
    : '';

  // Transit-Hinweis-Zeile (tagIdentityDesign, nur bei belegter transit-Kante):
  // reiner Text unter der Namenslinie — keine Score-/Topologie-Änderung.
  const transitHtml = clusterTransit
    ? `<div class="cluster-transit-note">${esc(t('cluster.transitNote'))}</div>`
    : '';

  // Kap-Kennzeichnung (Kritik-Runde 3): die Write-Pfad-Feldkappe des Servers
  // (FLOW_STATE_MEMBER_CAP 300, lib/flow-state.mjs) hat memberAddresses/
  // rolesByAddress komprimiert — distinctAccounts ist dann der je gesehene
  // Bestand (Monotonie-Fix lib/ledger-walk.mjs), nicht die aktuelle
  // Mitgliederliste. Ehrliche Fußnote, NUR bei belegter Kappung
  // (fieldsCapped-Signal aus projectFlowStateView).
  const cappedHtml = c.fieldsCapped === true
    ? `<div class="cluster-capped-note">${esc(t('cluster.membersCapped', { n: fmtNum(c.distinctAccounts ?? 0) }))}</div>`
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

  // Metrik-Block: Standard einzeilig flexibel; Mega-Karten zweizeilig (XRP
  // prominent, Tx/Konten als kombinierte 12-px-Mono-Zeile — Design P2).
  const xrpHtml = `<span class="cluster-xrp">${esc(fmtXrp(c.totalDrops))} XRP</span>`;
  const txsHtml = `<span class="cluster-txs">${fmtNum(c.txCount ?? 0)} ${esc(t('cluster.txUnit'))}</span>`;
  const accountsHtml = `<span class="cluster-accounts">${fmtNum(c.distinctAccounts ?? 0)} ${esc(t('cluster.accountUnit'))}</span>`;
  const metricsHtml = isMega
    ? `<div class="cluster-metrics cluster-metrics-mega">${xrpHtml}<span class="cluster-metrics-sub">${txsHtml}${accountsHtml}</span></div>`
    : `<div class="cluster-metrics">${xrpHtml}${txsHtml}${accountsHtml}</div>`;

  // data-cluster trägt NUR den Listen-Index — c.id ('cluster:<Adresse>')
  // wird nie im DOM gerendert (c.id ist ausschließlich interner Lookup-Schlüssel).
  const megaAttr = isMega ? ' data-size="mega"' : '';
  return `
    <li class="cluster-card role-${dominant} sev-${sev}"${megaAttr} data-cluster-index="${Number(index) || 0}" tabindex="0" role="button" aria-label="${esc(ariaLabel)}">
      <div class="cluster-head">
        <span class="cluster-label">${esc(c.label ?? 'Cluster')}</span>
        ${badge}
      </div>
      ${megaNoteHtml}
      ${namesHtml}
      ${transitHtml}
      <div class="cluster-roles">${chips}</div>
      ${metricsHtml}
      ${cappedHtml}
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
  // Verdichtungs-Stufe am Listen-Container (Design P2): bei jedem Rendertick
  // gesetzt — selbstheilend, auch wenn ein früherer Zustand fehlt.
  listEl.setAttribute('data-density', clusterDensity);
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
  // Bühnenfarbe über den dokumentierten Token-Weg (--a6-graph-canvas, live
  // gelesen): Noir-Exporte bekommen die dunkle Bühne statt hartem Weiß.
  let stageColor = '#ffffff';
  try {
    stageColor = getComputedStyle(document.body).getPropertyValue('--a6-graph-canvas').trim() || '#ffffff';
  } catch { /* ohne CSS-Zugang: Hell-Fallback */ }
  ctx2d.fillStyle = stageColor;
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
  // Verdichtungs-Umschalter (Design P2): Segment-Control im panel-head,
  // aria-pressed-Muster wie der Sprachumschalter; die Buttons tragen die
  // .graph-tab-Basisklasse (44-px-Ziel, Fokus-Ring, reduced-motion,
  // forced-colors) — die Auswahlfläche läuft über [aria-pressed].
  for (const lvl of DENSITY_LEVELS) {
    const btn = document.getElementById('density-' + lvl);
    if (btn) btn.addEventListener('click', () => setClusterDensity(lvl));
  }
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
/* BLOCK-FEED: LIVE-WSS (Standard-Tilt) + Server-Fenster 'Archiv' (Fallback) */
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

/* Cluster-Akkumulation (Fix 2026-10-06): die Live-Liste zeigt den
 * AKKUMULIERTEN Stand, nicht nur das letzte Block-Fenster. Zwei Schichten:
 * (1) die persistierten View-Cluster aus /api/flow-state (60-s-Poll, auch im
 * Live-Modus) — persistierte Cluster verschwinden nicht, wenn sie in den
 * letzten Blöcken still waren (firstSeen/lastSeen aus dem persistierten
 * View); (2) die Session-Schicht — Fenster-Cluster, die aus dem
 * mengen-gedeckelten FIFO-Fenster (TX_WINDOW_CAP) herausrollen, bleiben
 * dieser Tab-Session erhalten (Live-Befund 2026-10-06: Kartenzahl fiel
 * 12→7→5→1, weil Fenster-Cluster beim Herausröllen verschwanden und der
 * serverseitige Bestand eingefroren war). Server-Cluster sind die dauerhafte
 * Akkumulation (sobald Advance-Ticks laufen), die Session-Schicht die
 * clientseitige Überbrückung mit harter Eintrags-Kappe.
 * serverFlowClusters: letzte normalisierte Server-Cluster (leer bis zum
 * ersten erfolgreichen Poll). Normalisierung (serverClustersFromView) und
 * Merge (mergeClusterViews) leben im DOM-freien Shared-Modul
 * ./cluster-views.mjs (Tests: public/cluster-views.test.mjs). */
let serverFlowClusters = [];

// Session-Akkumulation: id -> letzter bekannter Fenster-/Merge-Zustand des
// Clusters (frisch gewinnt, siehe rememberSessionClusters). Kappe nach
// Aktivität (lastSeen asc, dann id asc) — die Liste bleibt begrenzt, auch
// über stundenlang offene Tabs.
const sessionFlowClusters = new Map();
const SESSION_FLOW_CLUSTER_CAP = 250;

function rememberSessionClusters(clusters) {
  for (const c of Array.isArray(clusters) ? clusters : []) {
    if (!c || typeof c !== 'object') continue;
    const id = String(c?.id ?? '');
    if (!id) continue;
    sessionFlowClusters.set(id, c);
  }
  if (sessionFlowClusters.size <= SESSION_FLOW_CLUSTER_CAP) return;
  const lastSeenMs = (c) => {
    const ms = Date.parse(String(c?.lastSeen ?? ''));
    return Number.isFinite(ms) ? ms : 0;
  };
  const excess = sessionFlowClusters.size - SESSION_FLOW_CLUSTER_CAP;
  const evict = [...sessionFlowClusters.entries()]
    .sort((a, b) => lastSeenMs(a[1]) - lastSeenMs(b[1]) || (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0))
    .slice(0, excess);
  for (const [id] of evict) sessionFlowClusters.delete(id);
}

/* Merge der Fenster-Cluster (WSS, frisch) mit den akkumulierten Clustern
 * (Server-View + Session-Schicht): Dedup NUR über die id mit Statistik-
 * Union — die frühere Absorption bei ≥1 gemeinsamer Member-Adresse warf den
 * persistierten Zwilling komplett weg, und weil der Mega-Cluster (46.660
 * Accounts) mit fast jedem Fenster-Cluster ein Exchange-Konto teilt,
 * verschwand er als Karte samt akkumulierter Statistik (Live-Befund
 * 2026-10-06: Karte 04:28 vorhanden, danach abwesend, API lieferte ihn
 * weiterhin). Implementierung, Semantik-Begründung und Tests:
 * ./cluster-views.mjs + public/cluster-views.test.mjs. Sortierung nach
 * AKTIVITÄT + SCHWERE unverändert: Schweregrad desc (malicious > suspect >
 * info, max über severityByAddress), dann lastSeen desc (Aktivität — stille
 * Cluster ranken nach ihrer letzten Aktivität), dann totalDrops desc, dann
 * id asc (deterministische Totalordnung). Das Ergebnis MUSS vor
 * renderClusterList in lastClusterGraph.clusters stehen (drilldown.js
 * findCardForClusterId :419-425 indexiert die Drilldown-Karte über den
 * Array-Index dieses Caches — Liste und Cache müssen exakt übereinstimmen,
 * sonst zeigt der Klick den falschen Cluster). */

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
  // Lazy-Registry (ANDOCKSTELLE des Registry-Fetches im Live-Takt, Muster
  // Namensindex): GENAU EIN Fetch pro Session (Guard/TTL im Modul), kein
  // Await — Tags erscheinen ab dem nächsten Takt (fail-closed ohne Stand).
  // Die Multi-User-Union (Registry ∪ verifizierte well-known-Namen,
  // Coverage-Fix 2026-10-05) geht als multiUserAccounts in den Graphen
  // (lib/cluster.mjs: Tags sind reine Edge-Attribute, Topologie unverändert;
  // ohne Stand: bit-identisch zu vorher).
  if (registryMod && typeof registryMod.ensureExchangeRegistry === 'function') {
    registryMod.ensureExchangeRegistry().catch(() => { /* ohne Tags rendern */ });
  }
  const multiUserAccounts = registryMod && typeof registryMod.multiUserSnapshot === 'function'
    ? registryMod.multiUserSnapshot()
    : (registryMod && typeof registryMod.registrySnapshot === 'function'
      ? registryMod.registrySnapshot()
      : null);
  const cg = buildClusterGraph(graphTx, graphFindings, {
    maxEdges: CLUSTER_MAX_EDGES,
    ...(multiUserAccounts ? { multiUserAccounts } : {}),
  });
  // Cluster-Akkumulation (Fix 2026-10-06): die FENSTER-Cluster gehen zuerst
  // in die Session-Schicht (id -> letzter Zustand, frisch gewinnt, Kappe
  // SESSION_FLOW_CLUSTER_CAP) — rollt ein Cluster später aus dem FIFO-Fenster
  // heraus, bleibt sein letzter Stand diese Session als Karte stehen. Danach
  // mergen Server-View (serverFlowClusters, 60-s-Poll) PLUS Session-Schicht
  // VOR dem Rendern in lastClusterGraph.clusters — drilldown.js indexiert
  // die Drilldown-Karten über den Array-Index genau dieses Caches
  // (findCardForClusterId), Liste und Cache müssen exakt übereinstimmen.
  // Dedup nur über die id (Union der Statistik, cluster-views.mjs): stille
  // persistierte Cluster bleiben stehen, neue Fenster-Cluster kommen hinzu,
  // und der Mega-Cluster verschwindet nicht mehr bei Mitglied-Überlappung.
  rememberSessionClusters(cg.clusters);
  cg.clusters = mergeClusterViews(cg.clusters, [...serverFlowClusters, ...sessionFlowClusters.values()]);
  lastClusterGraph = cg;
  // Lazy-Namensindex (ANDOCKSTELLE des Bulk-Fetches im Live-Takt): der erste
  // Cluster-Daten-Takt stößt GENAU EINEN Bulk-Fetch pro Session an (Guard/TTL
  // im Modul). Kein Await — der Fetch blockiert weder Render noch WSS-Takt;
  // Namen erscheinen ab dem nächsten Takt (fail-closed ohne Index).
  if (nameIndexMod && typeof nameIndexMod.ensureNameIndex === 'function') {
    nameIndexMod.ensureNameIndex().catch(() => { /* ohne Namen rendern */ });
  }
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
let feedMode = 'history';           // Startwert bleibt 'history' (Serverdaten als Fail-closed-Fallback);
                                    // der Live-Tilt erfolgt in der Rate-Gate-Importkette (Zeile ~66)
let feedRange = '24h';              // Fenster des Server-Modus (24h|3d|7d|30d|90d)
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
  if (feedMode !== 'history' || !windowData) {
    // 30d/90d: kein Fenster-Fetch (Retention 7 d) — die ehrliche Notiz steht
    // trotzdem, auch ohne windowData (sonst fiele sie im Leerzustand weg).
    if (feedMode === 'history' && !FEED_RANGES.slice(0, 3).includes(feedRange)) {
      el.textContent = t('feed.windowBeyondBlockRetention');
      el.hidden = false;
      return;
    }
    el.hidden = true;
    return;
  }
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
    // Diagramm-Marker geflaggte Stunde (Design P0, icons.mjs): Wimpel-Rauten-
    // Pin über dem Balken — Formsignal zusätzlich zur Fehler-Tinte, relevant
    // für Minimumhöhen (h>=2), in denen die Rotführung kaum lesbar ist. Farbe
    // ist nie alleiniges Signal: <title> je Balken + Meta-Zeile
    // (chart.flagged) bleiben die tragende Auskunft.
    if (flagged > 0) {
      const mx = Math.round((x + barW / 2 - 6) * 100) / 100;
      const my = Math.max(2, Math.round((H - PAD - h - 13) * 100) / 100);
      parts.push(chartMarkerFlagged('x="' + mx + '" y="' + my + '" width="12" height="12" style="color:var(--a6-sev-malicious)"'));
    }
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
  // applyStatic bei Sprachwechsel den passenden Key erwischt). 30d/90d: das
  // Block-Fenster endet bei 7 d — der Leer-Text sagt das ehrlich statt auf
  // Füllung zu verweisen.
  const emptyEl = document.getElementById('feed-empty');
  const emptyKey = !FEED_RANGES.slice(0, 3).includes(feedRange)
    ? 'feed.windowBeyondBlockRetention'
    : (windowData && windowData.reason === 'Persistenz nicht konfiguriert'
      ? 'feed.persistOff' : 'feed.serverEmpty');
  emptyEl.setAttribute('data-i18n', emptyKey);
  emptyEl.textContent = t(emptyKey);
  // textContent räumt die Leerzustands-Illustration ab — idempotent neu mounten.
  mountEmptyIllu(emptyEl, svgEmptyFeed());
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
async function applyFlowStateView(view) {
  // Mapping in serverClustersFromView extrahiert (Fix 2026-10-06): derselbe
  // Mapping-Pfad versorgt jetzt auch die Live-Akkumulationsschicht.
  const clusters = serverClustersFromView(view);
  const nodes = [];
  for (const c of clusters) {
    const sevByAddr = c?.severityByAddress && typeof c.severityByAddress === 'object' ? c.severityByAddress : {};
    // Knoten-Volumen aus den Cluster-Kanten (Kritik-Runde 3, Archiv-Parität):
    // der Bühnen-Deckel rankt sonst gegen null-Drops und wählt lexikografisch.
    // Dieselbe Summenregel wie der Live-Pfad (lib/cluster.mjs buildClusterGraph:
    // outDrops je Kanten-Start, inDrops je Kanten-Ziel; Null/IOU zählt 0).
    const inDrops = new Map();
    const outDrops = new Map();
    for (const e of c.edges) {
      if (!e || !e.from || !e.to) continue;
      const amt = Number.isFinite(Number(e.amountDrops)) ? Math.max(0, Number(e.amountDrops)) : 0;
      if (amt > 0) {
        outDrops.set(String(e.from), (outDrops.get(String(e.from)) ?? 0) + amt);
        inDrops.set(String(e.to), (inDrops.get(String(e.to)) ?? 0) + amt);
      }
    }
    const nodeIds = new Set();
    for (const [addr, role] of Object.entries(c.rolesByAddress)) {
      // Polling-Pfad: severity aus der serverseitig berechneten
      // severityByAddress (Malicious/Suspect/Info stimmen zwischen Polling-
      // und WSS-Pfad überein) statt hart 'info'.
      nodes.push({
        id: addr, role: ROLE_COLORS[role] ? role : 'unknown', clusterId: c.id,
        severity: sevByAddr[addr] ?? 'info',
        inDrops: inDrops.get(String(addr)) ?? 0, outDrops: outDrops.get(String(addr)) ?? 0,
      });
      nodeIds.add(String(addr));
    }
    // Kanten-Endpunkte ohne Rollen-Eintrag (capClusterFields kappt Rollen auf
    // 300 Adressen, Kanten bleiben unangetastet — lib/flow-state.mjs:345):
    // ohne diese Knoten fielen ihre Kanten im vis-Netz und im Drilldown
    // (beide Enden müssen Knoten sein). Rolle 'unknown' ist ehrlich — sie
    // erfindet keine Rolle, der Knoten bleibt als Evidenz-Endpunkt sichtbar.
    for (const e of c.edges) {
      if (!e || !e.from || !e.to) continue;
      for (const addr of [String(e.from), String(e.to)]) {
        if (nodeIds.has(addr)) continue;
        nodeIds.add(addr);
        nodes.push({
          id: addr, role: 'unknown', clusterId: c.id, severity: sevByAddr[addr] ?? 'info',
          inDrops: inDrops.get(addr) ?? 0, outDrops: outDrops.get(addr) ?? 0,
        });
      }
    }
  }
  const edges = [];
  for (const c of clusters) {
    for (const e of c.edges) {
      if (!e || !e.from || !e.to) continue;
      edges.push({
        from: String(e.from), to: String(e.to), type: String(e.type || 'Sonstige'),
        txHash: e.txHash ? String(e.txHash) : undefined,
        // Zeit-/Volumenfelder der Server-View durchreichen (Kritik-Runde 3):
        // closeTime speist den Zeitfenster-Filter (24h/3d/7d/30d/90d),
        // amountDrops/ledgerSeq die Kanten-Totalordnung des Bühnen-Deckels
        // (Spiegel von topKEdges, lib/ledger-walk.mjs).
        ...(Number.isFinite(Number(e.amountDrops)) ? { amountDrops: Number(e.amountDrops) } : {}),
        ...(Number.isFinite(Number(e.ledgerSeq)) ? { ledgerSeq: Number(e.ledgerSeq) } : {}),
        ...(typeof e.closeTime === 'string' && e.closeTime ? { closeTime: e.closeTime } : {}),
        // Tag-Felder der Server-View (viewEdge, lib/flow-state.mjs) durchreichen —
        // Kanten-Tooltip und Ketten-Chips lesen sie; ohne Feld: unverändert.
        ...(e.toTag != null ? { toTag: e.toTag } : {}),
        ...(e.transit === true ? { transit: true } : {}),
      });
    }
  }
  lastClusterGraph = { nodes, edges, clusters };
  // Lazy-Namensindex im Archiv-Takt (60 s): dieselbe Guard-gedeckte
  // Andockstelle wie im Live-Takt — der In-Flight-Guard/TTL im Modul macht
  // daraus GENAU EINEN Bulk-Fetch pro Session, nie einen pro Poll.
  if (nameIndexMod && typeof nameIndexMod.ensureNameIndex === 'function') {
    nameIndexMod.ensureNameIndex().catch(() => { /* ohne Namen rendern */ });
  }
  // Vor dem Rendern hashen (displayFindingAddr/chain-Chips entscheiden
  // synchron und fail-closed): ohne Priming blieben Flow-State-Karten in der
  // Kurzform (Befund 05.10.2026).
  await primeAddrHashes(lastClusterGraph, []);
  renderLiveGraph(lastClusterGraph);
  renderClusterList(clusters);
  if (drilldown && typeof drilldown.refresh === 'function') drilldown.refresh();
  if (globeMod && typeof globeMod.refresh === 'function') globeMod.refresh();
}

/* ---------- Top-10 Börsen-Zuflüsse (Daten-Forensik 2026-10-07) ----------
 * Client-Aggregation aus der bestehenden /api/flow-state-View (KEIN neuer
 * api/*-Endpoint, Vercel-Hobby-Limit 12 Functions): je Börsen-Konto der
 * Union (multiUserSnapshot = 81er-Registry ∪ verifizierte well-known-Namen,
 * dieselbe Quelle wie die Tag-Chips) werden die eingehenden Drops aus
 * Kanten mit Drainer-Kontext aggregiert — Kanten-Prädikat (severityByAddress
 * ∈ {malicious, suspect} ODER rolesByAddress === 'drainer' der QUELLE im
 * selben Cluster), Fenster 7 d/30 d über closeTime. Fail-closed: ohne Union
 * oder ohne Daten bleibt die Box im leeren Zustand — es werden keine Zahlen
 * erfunden. Zeilen-Markup läuft ausschließlich über die Host-Gates
 * (esc + displayFindingAddr, Pflicht 12); der Abdeckungszeitraum
 * (coverageFrom→generatedAt, Pflicht 11) und der 50-Kanten-Cap-Hinweis
 * machen die Grenzen der Box sichtbar. */
let exoutWindow = 7;             // aktives Fenster des Umschalters (7 | 30)
let exoutUnionRetryDone = false; // Einmal-Guard des Nachzieh-Takts (kein Loop)
let exoutMaskRepairInFlight = false; // Einmal-Guard des Masken-Nachziehs (kein Loop)

function renderExchangeOutflows(viewData) {
  const listEl = document.getElementById('exchange-outflow-list');
  const emptyEl = document.getElementById('exout-empty');
  const coverageEl = document.getElementById('exout-coverage');
  const cappedEl = document.getElementById('exout-capped');
  if (!listEl || !emptyEl || !viewData) return; // ohne Daten nichts behaupten
  // Börsen-Union (fail-closed): null ohne Registry-Modul, leere Map ohne
  // geladenen Stand — beides endet im leeren Zustand der Box.
  const exchangeMap = registryMod && typeof registryMod.multiUserSnapshot === 'function'
    ? registryMod.multiUserSnapshot()
    : null;
  // Nachzieh-Takt: beim ersten Poll sind der lazy Registry-/Bulk-Fetch oft
  // noch in der Luft — beide Ensures anstoßen (dieselben Andockstellen wie
  // rebuildClusterGraph/applyFlowStateView, GENAU EIN Fetch pro Session über
  // Guard/TTL im Modul) und GENAU EINMAL nachziehen, sobald sie sich
  // auflösen. Der Einmal-Guard verhindert einen Microtask-Loop; jeder
  // Später-Fall ist durch den 60-s-Poll abgedeckt.
  if ((!exchangeMap || exchangeMap.size === 0) && !exoutUnionRetryDone) {
    exoutUnionRetryDone = true;
    const waiting = [];
    if (registryMod && typeof registryMod.ensureExchangeRegistry === 'function') {
      waiting.push(registryMod.ensureExchangeRegistry());
    }
    if (nameIndexMod && typeof nameIndexMod.ensureNameIndex === 'function') {
      waiting.push(nameIndexMod.ensureNameIndex());
    }
    Promise.allSettled(waiting)
      .then(() => { if (flowData) renderExchangeOutflows(flowData); })
      .catch(() => { /* fail-closed: Box bleibt leer */ });
  }
  let result = null;
  if (exchangeMap && exchangeMap.size > 0) {
    try {
      result = aggregateExchangeOutflows(viewData, exchangeMap, Date.now());
    } catch {
      result = null; // Aggregations-Fehler: leer statt erfundener Zahlen
    }
  }
  const bucket = exoutWindow === 30 ? result?.thirty : result?.seven;
  const rows = Array.isArray(bucket?.rows) ? bucket.rows : [];
  if (rows.length) {
    // Host-Gates der Zeilen (Pflicht 12): esc auf jeden Registry-String,
    // displayFindingAddr als Anzeige-Maske, fmtXrp/fmtNum aus i18n.mjs.
    const ui = {
      esc,
      displayAddr: displayFindingAddr,
      fmtXrp,
      fmtNum,
      labels: {
        rankAria: (n) => t('exout.rank', { n }),
        // Singular/Plural nach dem globe.edge1/edgeN-Muster (1 edge / 1 Kante).
        inflows: (n) => (n === 1 ? t('exout.inflows1') : t('exout.inflows', { n: fmtNum(n) })),
        clusters: (n) => (n === 1 ? t('exout.clusters1') : t('exout.clusters', { n: fmtNum(n) })),
        transit: (xrp) => t('exout.transit', { xrp }),
        wellKnown: t('exout.wellKnown'),
      },
    };
    listEl.innerHTML = rows.map((row, i) => exchangeOutflowRowHtml(row, i + 1, ui)).join('');
    listEl.hidden = false;
    emptyEl.hidden = true;
    // Masken-Nachzieh (Befund 2026-10-07: Masken-Oszillation der Top-10-Box):
    // Der Render ist bewusst synchron (displayFindingAddr entscheidet nur aus
    // gecachten Hashes) — ist der Hash einer Zeilen-Adresse gerade aus dem
    // LRU verdrängt, zeigt sie die Kurzform, obwohl sie kein Köder ist. Die
    // Zeilen-Adressen werden hier asynchron verifiziert (verifyFullShownAsync
    // füllt zugleich den Hash-LRU frisch); hat sich dadurch eine Anzeige-
    // Entscheidung geändert, läuft GENAU EIN Nachzieh-Render. Der Guard
    // verhindert Mikrotask-Loops: der zweite Durchlauf findet nichts mehr zu
    // reparieren (vorher==nachher). Budget +0 Requests — nur lokale Hashes.
    if (!exoutMaskRepairInFlight) {
      exoutMaskRepairInFlight = true;
      const before = rows.map((row) => isFullShownAddr(row.address));
      Promise.all(rows.map((row) => verifyFullShownAsync(row.address)))
        .then(() => {
          exoutMaskRepairInFlight = false;
          const after = rows.map((row) => isFullShownAddr(row.address));
          if (after.some((v, i) => v !== before[i]) && flowData) {
            renderExchangeOutflows(flowData);
          }
        })
        .catch(() => { exoutMaskRepairInFlight = false; });
    }
  } else {
    listEl.innerHTML = '';
    listEl.hidden = true;
    emptyEl.hidden = false;
  }
  // Pflicht 11: der TATSÄCHLICHE Abdeckungszeitraum (min firstSeen der
  // betrachteten Cluster bis zum Aggregationszeitpunkt) — nicht das
  // nominelle Fenster (live lag die State-Tiefe zuletzt bei ~2 Tagen).
  if (coverageEl) {
    if (result?.coverageFrom) {
      coverageEl.textContent = t('exout.coverage', {
        from: fmtDateTime(result.coverageFrom),
        to: fmtDateTime(result.generatedAt),
      });
      coverageEl.hidden = false;
    } else {
      coverageEl.textContent = '';
      coverageEl.hidden = true;
    }
  }
  // Cap-Sichtbarkeit: Cluster am 50-Kanten-Deckel des States — die Summen
  // sind eine Untergrenze (nur bei belegter Kappung, kein Dauertext).
  if (cappedEl) {
    const capped = Number(bucket?.totals?.cappedClusters) || 0;
    if (capped > 0) {
      cappedEl.textContent = t('exout.capped', { n: fmtNum(capped) });
      cappedEl.hidden = false;
    } else {
      cappedEl.textContent = '';
      cappedEl.hidden = true;
    }
  }
}

// Fenster-Umschalter der Box (aria-pressed-Muster der Cluster-Dichte, keine
// Persistenz — Default 7 Tage je Session).
function bindExchangeOutflows() {
  const b7 = document.getElementById('exout-window-7d');
  const b30 = document.getElementById('exout-window-30d');
  if (!b7 || !b30) return;
  const setWindow = (days) => {
    exoutWindow = days === 30 ? 30 : 7;
    b7.setAttribute('aria-pressed', String(exoutWindow === 7));
    b30.setAttribute('aria-pressed', String(exoutWindow === 30));
    if (flowData) renderExchangeOutflows(flowData);
  };
  b7.addEventListener('click', () => setWindow(7));
  b30.addEventListener('click', () => setWindow(30));
}

async function pollBlockWindow() {
  // 30d/90d werden NICHT gegen das Block-Fenster abgefragt: dessen Retention
  // endet bei 7 d (lib/block-window.mjs:79; api/flow-state.js lehnt 30d/90d
  // dort mit 400 ab — ein Fetch wäre ein Fenster-Versprechen auf nicht mehr
  // existierende Daten). Der Feed geht in den ehrlichen Leerzustand mit
  // Retention-Notiz; der persistierte Fraud-Bestand bleibt über Graph,
  // Karten und Drilldown sichtbar (60-s-flow-state-Poll).
  if (!FEED_RANGES.slice(0, 3).includes(feedRange)) {
    windowData = null;
    windowRenderSig = null;
    renderWindowFeed();
    return;
  }
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
  lastFlowStateAt = Date.now(); // Bestands-Zeitstempel (modal.persisted-Banner im Drilldown)
  // Top-10 Börsen-Zuflüsse: Client-Aggregation aus derselben Antwort
  // (Budget +0 Requests/+0 Functions); deckt auch den initialen Poll ab
  // (Startblock ruft void serverPollTick() sofort nach dem Binden).
  renderExchangeOutflows(body);
  if (feedMode === 'history') {
    await applyFlowStateView(body);
  } else {
    // Live-Modus (Fix 2026-10-06): die Server-View ersetzt NICHT den
    // Live-Graphen — ihre Cluster gehen in die Akkumulationsschicht
    // (serverFlowClusters) und werden beim nächsten rebuildClusterGraph-Takt
    // mit den Fenster-Clustern gemergt. Ein Live-Tab ohne eigenen
    // WSS-Nachrichten-Takt holt den Merge mit void rebuildClusterGraph().
    serverFlowClusters = serverClustersFromView(body);
    if (txWindow.length === 0) void rebuildClusterGraph();
  }
}

/* ---------- Persistierten Bestand nachladen (Stale-Overlay-Fix 2026-10-06) ----------
 * Das Drilldown-Modal kann einen Cluster öffnen, dessen Karte im akkumulierten
 * Bestand lebt (mergeClusterViews/Session-Schicht — persistierte Cluster
 * verschwinden nicht mehr, wenn sie im FIFO-Fenster still sind), dessen
 * KNOTEN aber nicht mehr im Live-Graphen liegen (cg.nodes bleibt fenster-
 * basiert). Ohne Nachladen degenerierte das offene Modal zur leeren Hülle
 * mit modal.gone-Banner (Forensik 2026-10-06: 12/30 Karten betroffen,
 * Flapping je Poll-Tick). getPersistedClusterById(id) rekonstruiert nodes/
 * edges nach dem applyFlowStateView-Muster (rolesByAddress → Knoten, edges
 * durchreichen); NICHT lieferbare Knoten-Metadaten (inDrops/outDrops/Grade)
 * werden bewusst nicht erfunden — die Tabelle zeigt '–', der Graph nutzt die
 * neutrale Minimalgröße. Köder-Sicherheit: die Funktion liefert nur
 * Rohbestand; die Gates (sync isDeniedAddr-Knoten-Gate im Drilldown,
 * Anzeige-Maske displayFindingAddr, async Export-Nachprüfung, Freeze-Recheck)
 * laufen unverändert downstream. */
let lastFlowStateAt = 0;        // Zeitpunkt des letzten erfolgreichen flow-state-Lesevorgangs
let persistedRestoreCache = null; // { at, clusters[] } — 60-s-Cache des bedingten Refetches
const PERSISTED_RESTORE_TTL_MS = 60000;

function buildPersistedClusterView(c, at) {
  const rolesByAddress = c?.rolesByAddress && typeof c.rolesByAddress === 'object'
    ? c.rolesByAddress
    : (c?.roles && typeof c.roles === 'object' ? c.roles : {});
  const severityByAddress = c?.severityByAddress && typeof c.severityByAddress === 'object'
    ? c.severityByAddress
    : {};
  const memberAddresses = (Array.isArray(c?.memberAddresses) ? c.memberAddresses : Object.keys(rolesByAddress))
    .map(String);
  const nodes = memberAddresses.map((addr) => ({
    id: addr,
    role: ROLE_COLORS[rolesByAddress[addr]] ? rolesByAddress[addr] : 'unknown',
    clusterId: c.id,
    severity: severityByAddress[addr] ?? 'info',
    // inDrops/outDrops/degreeIn/degreeOut fehlen im persistierten Bestand —
    // NICHT erfinden (Tabelle '–', Graph neutrale Größe).
  }));
  const edges = (Array.isArray(c?.edges) ? c.edges : [])
    .filter((e) => e && e.from && e.to)
    .map((e) => ({
      from: String(e.from), to: String(e.to), type: String(e.type || 'Sonstige'),
      txHash: e.txHash ? String(e.txHash) : undefined,
      // Zeit-/Volumenfelder wie in applyFlowStateView durchreichen (Kritik-
      // Runde 3: Kanten-Totalordnung und Fensterfilter lesen sie); ohne Feld:
      // unverändert.
      ...(Number.isFinite(Number(e.amountDrops)) ? { amountDrops: Number(e.amountDrops) } : {}),
      ...(Number.isFinite(Number(e.ledgerSeq)) ? { ledgerSeq: Number(e.ledgerSeq) } : {}),
      ...(typeof e.closeTime === 'string' && e.closeTime ? { closeTime: e.closeTime } : {}),
      // Tag-Felder wie in applyFlowStateView durchreichen (Kanten-Tooltip/
      // Ketten-Chips/Export lesen sie); ohne Feld: unverändert.
      ...(e.toTag != null ? { toTag: e.toTag } : {}),
      ...(e.transit === true ? { transit: true } : {}),
    }));
  return { cluster: c, nodes, edges, at };
}

async function getPersistedClusterById(id) {
  const key = String(id ?? '');
  if (!key) return null;
  // Stufe 1+2 (kein Netz): gemergte Karten im aktuellen Graphen, dann die
  // Akkumulationsschichten (Server-View + Session-Schicht).
  const cg = lastClusterGraph;
  const sources = [
    ...(cg && Array.isArray(cg.clusters) ? cg.clusters : []),
    ...serverFlowClusters,
    ...sessionFlowClusters.values(),
  ];
  let hit = sources.find((c) => c && String(c.id) === key) || null;
  // Stufe 3: bedingter Refetch (60-s-Cache, Muster pollFlowState). Auch ein
  // FEHLSCHLAG wird 60 s gecacht (clusters: []) — der Poll-Takt (~4-5 s)
  // erzeugt nie einen Refetch-Sturm.
  if (!hit && Date.now() - (persistedRestoreCache?.at ?? 0) > PERSISTED_RESTORE_TTL_MS) {
    let view = null;
    try {
      const res = await fetch('/api/flow-state', { cache: 'no-store' });
      if (res.ok) view = await res.json();
    } catch { /* Netz-Fehler: Bestand bleibt der zuletzt gecachte Stand */ }
    if (view) lastFlowStateAt = Date.now();
    persistedRestoreCache = { at: Date.now(), clusters: serverClustersFromView(view) };
  }
  if (!hit && persistedRestoreCache && Array.isArray(persistedRestoreCache.clusters)) {
    hit = persistedRestoreCache.clusters.find((c) => c && String(c.id) === key) || null;
  }
  if (!hit) return null;
  return buildPersistedClusterView(hit, lastFlowStateAt || Date.now());
}

async function serverPollTick() {
  // Live-Standard: das Block-FENSTER wird nur im Archiv-Modus gebraucht —
  // der 60-s-Poll spart sonst ~3,2 MB dekodierte Antworten pro Minute.
  // setFeedMode('history') holt das Fenster sofort nach (void
  // serverPollTick() im history-Zweig).
  // Fix 2026-10-06 (Cluster-Akkumulation): im Live-Modus läuft der
  // FLOW-STATE-Poll trotzdem — die persistierten Cluster sind die
  // Akkumulationsschicht der Live-Liste (mergeClusterViews), ohne sie zeigt
  // die Live-Liste nur das letzte Block-Fenster. BEWUSST AKZEPTIERTE KOSTEN
  // (Plan-Review-Korrektur 4): die flow-state-Antwort misst live 2.626.205 B
  // pro Poll (~2,6 MB/Minute pro sichtbarem Tab) — der Preis für eine Liste,
  // die stille persistierte Cluster nicht mehr fallen lässt.
  if (typeof document !== 'undefined' && document && document.visibilityState !== 'visible') return;
  if (Date.now() < serverPollBackoffUntil) return;
  let failed = false;
  if (feedMode === 'history') {
    try {
      await pollBlockWindow();
    } catch (err) {
      failed = true;
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

/* ---------- Modus-Umschaltung (Live-Standard / Archiv-Fallback) ---------- */
async function setFeedMode(mode) {
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
    if (flowData) await applyFlowStateView(flowData);
    setConn(true, connLabel());
    void serverPollTick(); // sofort frisches Fenster statt erst nach dem Timer-Takt
  } else {
    // Gate-Check (unverändert): ohne Rate-Gate (lib/rate-gate.mjs nicht
    // erreichbar) startet Live nicht — fail-closed zurück auf Server-Modus.
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
    // Leer-Text zurück auf den Live-Key: renderWindowFeed hat 'feed.serverEmpty'
    // bzw. 'feed.persistOff' geschrieben — ohne Reset stünde im Live-Modus der
    // Server-Text (data-i18n mitgeschrieben, damit applyStatic bei
    // Sprachwechsel den passenden Key erwischt — Gegenstück app.js:1842-1846).
    const liveEmptyEl = document.getElementById('feed-empty');
    liveEmptyEl.setAttribute('data-i18n', 'feed.empty');
    liveEmptyEl.textContent = t('feed.empty');
    // textContent räumt die Leerzustands-Illustration ab — idempotent neu mounten.
    mountEmptyIllu(liveEmptyEl, svgEmptyFeed());
    liveEmptyEl.hidden = false;
    setConn(false, t('conn.liveInit'));
    connectLive();
    // Fix 2026-10-06 (Cluster-Akkumulation): beim Wechsel nach Live geht der
    // persistierte Bestand aus flowData sofort in die Akkumulationsschicht —
    // die Liste startet nicht leer, sondern zeigt den akkumulierten Stand,
    // auch bevor die erste WSS-Transaktion den rebuildClusterGraph-Takt
    // auslöst (void rebuildClusterGraph mit leerem Fenster mergt nur die
    // persistierten Cluster).
    if (flowData) serverFlowClusters = serverClustersFromView(flowData);
    void rebuildClusterGraph();
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
  // Nutzer-Klick setzt feedModeUserChoice: ein später eintreffendes
  // Rate-Gate übersteuert die Wahl nicht mehr (kein Tilt gegen den Klick).
  document.getElementById('feed-mode-history').addEventListener('click', () => {
    feedModeUserChoice = true;
    setFeedMode('history');
  });
  document.getElementById('feed-mode-live').addEventListener('click', () => {
    feedModeUserChoice = true;
    setFeedMode('live');
  });
  document.getElementById('feed-range').addEventListener('change', (e) => {
    const v = String(e.target.value ?? '24h');
    // Fünf Fenster (Kritik-Runde 3, Ask-Punkt 2): 24h/3d/7d speisen den
    // Block-Feed (Retention 7 d, lib/block-window.mjs), 30d/90d den
    // persistierten Fraud-Bestand (Flow-State 30 d malicious / Archiv
    // 180 d registry-verknüpft, Abfragbarkeit Default 62 d) — über die
    // Bühnen-Fensterfilter und die truncated-Notizen ehrlich gekennzeichnet.
    feedRange = FEED_RANGES.includes(v) ? v : '24h';
    windowRenderSig = null; // Range-Wechsel: immer neu rendern
    if (feedMode === 'history') {
      renderGraphWindowNote();
      if (lastClusterGraph) renderLiveGraph(lastClusterGraph); // Bühne neu gefiltert
      void serverPollTick();
    }
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

// initGraph() läuft NICHT mehr beim Start: vis-network wird lazy geladen
// (ensureVisGraph — erster Graph-Tab-Bedarf live/cluster oder eintreffende
// Daten). bindGraph bleibt hier: seine Handler (Tab-Klicks, Karten, Export)
// brauchen vis nicht.
bindGraph();
// Theme-JS-Palette VOR dem ersten Canvas-Render auf das angewandte Theme
// stellen (body[data-theme]; das Inline-Bootstrap nach <body> hat bei
// persistiertem 'light' bereits zurückgeschaltet — Noir ist Markup-Default).
// Ohne diesen Aufruf bliebe die erste Graph-/Drilldown-Zeichnung in der
// Hell-Palette, obwohl die CSS-Bühne schon dunkel ist.
applyThemeColors(currentJsTheme());
// Verdichtungs-Wahl vor dem ersten listen-Rendertick anwenden (persistierte
// Stufe oder Default 'comfortable'); syncClusterDensityUi setzt data-density
// an #cluster-list und aria-pressed an der Segment-Control.
loadClusterDensity();
syncClusterDensityUi();
bindViews();
setView(viewFromHash()); // Deep-Link (#history/#check) anwenden, sonst Dashboard
bindLive();
bindFeed();
bindExchangeOutflows();
bindAddrActions();
document.getElementById('stat-network').textContent = t('net.mainnet');
// Standard-Feed ist LIVE (Tilt erfolgt in der Rate-Gate-Importkette,
// sobald lib/rate-gate.mjs eintrifft und der Nutzer noch nicht gewählt hat).
// Dieser Startblock holt trotzdem sofort Serverdaten (60-s-Poll flow-state +
// block-window): Fail-closed-Fallback — ist der Gate-Import nicht erreichbar,
// bleibt history Standard und die Daten stehen bereits; im Live-Modus dient
// das Fenster als Fallback über den Archiv-Knopf. Der Live-Watchdog läuft
// nur, wenn der Live-Modus aktiv ist.
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
initThemeSwitcher(document.getElementById('theme-switch'));
document.addEventListener('hx:langchange', () => {
  applyStatic(document);
  buildRuleFilter();
  renderLog();
  updateLiveStats();
  document.getElementById('stat-network').textContent = t('net.mainnet');
  setConn(true, connLabel());
  // Top-10-Box: Zeilen tragen t()-Texte (Kanten-/Cluster-Zähler, Badges,
  // Abdeckungszeitraum) — nach applyStatic in der neuen Sprache neu bauen.
  renderExchangeOutflows(flowData);
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

/* ---------- Theme-Bootstrap (Noir, hx:themechange) ----------
 * Die Canvas-Objekte sind bereits zur Laufzeit mutiert (applyThemeColors in
 * applyTheme-Phase oben); hier werden nach jedem Wechsel die GERENDERTEN
 * Ebenen nachgezogen: vis-DataSets über den nächsten renderLiveGraph-Durchlauf
 * (Knoten lesen ROLE_COLORS je Render, Kanten EDGE_COLORS/EDGE_DEFAULT) und
 * die Cluster-Bubbles über applyClustering (liest CLUSTER_NODE_PROPERTIES).
 * Das CSS-seitige DOM färbt sich allein über die Token-Overrides. Drilldown
 * (offenes Modal, 3D-Accessoren + Drainer-Ring-Material) und Weltkugel
 * (kompletter rebuildGlobe) re-agieren in ihren eigenen Modulen. */
document.addEventListener('hx:themechange', () => {
  applyThemeColors(currentJsTheme());
  if (lastClusterGraph) renderLiveGraph(lastClusterGraph);
});

/* ---------- Statische Illustrationen (Design P0, public/icons.mjs) ---------
 * Leerzustände der drei Dashboard-Panels + Panel-Signet Activity Graph —
 * einmalig nach DOM-Aufbau. renderWindowFeed/startLiveMode mounten die
 * Feed-Illustration nach jedem textContent-Setzen erneut (idempotent, s.o.). */
mountEmptyIllu(document.getElementById('feed-empty'), svgEmptyFeed());
mountEmptyIllu(document.getElementById('log-empty'), svgEmptyLog());
mountEmptyIllu(document.getElementById('cluster-empty'), svgEmptyCluster());
(function mountPanelMarker() {
  const h = document.getElementById('graph-title');
  if (!h) return;
  try {
    if (h.querySelector('.panel-marker')) return;
    h.insertAdjacentHTML('afterbegin', '<span class="panel-marker" aria-hidden="true">' + panelMarkerGraph() + '</span>');
  } catch { /* DOM nicht schreibbar: Signet entfällt, wirft aber nicht */ }
})();

/* ---------- Cache-Wärmung schwerer Vendoren erst nach Erstanstrich ----------
 * globe.gl (1,9 MB), 3d-force-graph (1,3 MB), topojson-client (7 kB) —
 * zusammen 3,2 MB / ~868 kB gzip. Kein Wärmefetch im HTML-Head (würde mit
 * dem FCP konkurrieren); nach window 'load' + requestIdleCallback (Fallback
 * setTimeout ~1 s) ist das Leerlauffenster frei und die Bundles liegen im
 * HTTP-Cache, wenn Globe-/3D-Tab sie lazy anfordern.
 * Audit 2026-10-07 (Preload-Warnungen): Früher über link rel=preload
 * (as=script, crossOrigin='anonymous', integrity) — öffnete der Nutzer
 * Globe/3D nie, blieb der Preload-Eintrag unkonsumiert und Chrome warnte
 * je Neuladen 2× "preloaded using link preload but not used within a few
 * seconds". Der Fetch wärmt denselben HTTP-Cache-Eintrag ohne preload-
 * Ledger (keine Warnung); die SRI-Prüfung bleibt unverändert an den
 * Consumern hängen (globe.js loadGlobeGl/loadTopojson, drilldown.js
 * loadForceGraph3D — alle mit integrity + crossOrigin, fail-closed beim
 * ersten echten Load). Der Body wird bewusst konsumiert: erst ein
 * gelesener Response landet vollständig im HTTP-Cache; Vercel-Static
 * liefert must-revalidate — der spätere Modul-Load revalidiert dann per
 * 304, statt den Body erneut zu übertragen. */
function preloadHeavyVendors() {
  const schedule = typeof requestIdleCallback === 'function'
    ? (fn) => requestIdleCallback(fn, { timeout: 2000 })
    : (fn) => setTimeout(fn, 1000);
  schedule(() => {
    for (const href of [
      'vendor/globe.gl.min.js',
      'vendor/3d-force-graph.min.js',
      'vendor/topojson-client.min.js',
    ]) {
      // Best-effort-Wärmung: Netz-/Cache-Fehler im Idle-Fenster bleiben stumm,
      // die Consumer-Loader laden im Bedarfsfall ohnehin selbst nach.
      fetch(href, { cache: 'default', credentials: 'same-origin' })
        .then((res) => { if (res.ok) return res.arrayBuffer(); return null; })
        .catch(() => { /* Wärmung ist optional — kein Fehlerpfad für den Nutzer */ });
    }
  });
}
if (document.readyState === 'complete') preloadHeavyVendors();
else window.addEventListener('load', preloadHeavyVendors, { once: true });
