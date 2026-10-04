// Vercel Function: GET /api/flow-state — Lesezweig des akkumulierten Flow-States.
// ZWEITE ROUTE (Hobby-Limit 2026-10-02: max. 12 Serverless Functions pro
// Deployment — die eigenständige api/block-window.js hätte es auf 13 gehoben):
// GET /api/block-window wird per vercel.json-Rewrite auf
// /api/flow-state?route=block-window gemappt; dieser Handler bedient beide
// Verträge. Der /api/block-window-Pfad bleibt für Clients unverändert.
//
// METHOD-TRENNSUNG: Der POST-Advance-Write-Vertrag (api/advance.js: Advance +
// {cursor, summary}, kein State-Leak) bleibt UNANTASTET. Diese Route ist strikt
// GET und liefert ausschließlich die NORMALISIERTE renderbare Projektion des
// persistierten Flow-State-Dokuments (projectFlowStateView, lib/flow-state.mjs)
// — Cluster-View-Form mit Cursor-Stand + updatedAt. Keine Roh-Internals
// (blocksProcessedTotal, lastAdvancedAt), keine ungefilterten Member-Listen,
// kein State-Leak.
//
// SICHERHEIT:
//   - FAIL-CLOSED ohne Token: ohne GITHUB_HISTORY_TOKEN liefert der Endpunkt
//     den ehrlichen Nicht-Konfiguriert-Zustand (Muster api/history.js GET:
//     HTTP 200 + reason — kein Erfolgs-Vortäuschen, aber auch kein
//     Fehlerzustand). Token NUR aus process.env, nie geloggt.
//   - Read-Fehler -> 502/503 (429 des Upstream -> 503), wie api/advance.js.
//     Neutrale Messages — keine Token-/Repo-Werte in Fehlermeldungen.
//
// GET -> { cursor, updatedAt, validatedIndex, clusters: [ {id, label, roles,
//         rolesByAddress, edges, totalDrops, txCount, distinctAccounts,
//         firstSeen, lastSeen} ] }
//         (deterministisch sortiert + gelabelt, Konvention lib/cluster.mjs;
//         edges/rolesByAddress versorgen die Flow-Graph-/Weltkugel-View)
//
// GET route=block-window -> { range, from, to, updatedAt,
//         buckets: [{t, blocks, txns, flaggedBlocks, maxSeverity}],
//         flagged: [{i, t, n, f: [...]}], cursor, validatedIndex }
//         range: "24h" | "3d" | "7d" (Default 24h; ungültig -> 400).
//         STUNDEN-ROLLUPS (<= 168 Zeilen bei 7 d) + geflaggte Blockdetails —
//         NIE 127k–154k Roh-Records. Ungeflaggte Txs nur zählbar (n im Rollup),
//         nie im Detail — ehrliche Tiefe. Adressfelder: der Bait-Filter liegt im
//         Codec lib/block-window.mjs VOR PERSISTENZ; dieser Endpunkt liefert nur
//         Gefiltertes (keine Adressen aus dem ENV in dieser Datei).
//
// validatedIndex (Neu 2026-10-02): der aktuell validierte Ledger-Index — die
// Referenz für die Rückstands-Anzeige des Flow-Hosts (validatedIndex − cursor).
// EIN rpc ledger_index:'validated'-Call (Muster api/ledger.js:131) mit
// Prozess-Cache (60 s Erfolg / 10 s Fehler, Fix 2026-10-04; Muster
// api/ledger.js:50, 122-124): begrenzt die Kosten auf
// <= 1 RPC/Minute pro warmem Prozess, unabhängig von der Besucherzahl — ohne
// Cache wäre dieser Endpunkt ein ungedeckter dritter Egress-Verbraucher im
// geteilten 10.000-Units-Fenster (Bilanz im README). Fehler/Timeout -> null
// (ehrlicher Leerzustand im Client, kein 502 — der State ist trotzdem gültig).
import {
  readFlowStateGitHub,
  projectFlowStateView,
  readArchiveGitHub,
  replayArchive,
} from "../lib/flow-state.mjs";
import {
  readBlockWindowGitHub,
  projectBlockWindow,
  dayOf,
} from "../lib/block-window.mjs";

export const maxDuration = 30;

// honeycluster-Umstellung 2026-10-02: Standard-Endpunkt ist der offiziell
// gelistete Full-History-Server (config.json:3); ENV RPC_URL/WSS_URL
// überschreibt weiterhin explizit.
const RPC_URL =
  process.env.RPC_URL ||
  (process.env.WSS_URL || "wss://honeycluster.io").replace(/^wss:/, "https:");
const VALIDATED_CACHE_MS = 60000; // 60-s-Erfolgs-Cache wie api/ledger.js:50
// Fix 2026-10-04: getrennte TTLs — ein Fehler (null) durfte den Endpunkt
// nicht 60 s im Leerzustand einfrieren (live: ein gestörter Upstream
// zementierte validatedIndex=null eine volle Minute pro Instanz). 10 s
// Negativ-TTL begrenzt das RPC-Hämmern, ohne den Leerzustand zu zementieren.
const VALIDATED_NEGATIVE_CACHE_MS = 10000;
let validatedCache = null;        // { time, index, ttl } — nur im Prozess-Speicher

// Aktuelles validiertes Ledger-Index (1 Call, Cache: 60 s Erfolg / 10 s
// Fehler; Fehler -> null, ebenfalls kurz gecacht, damit ein fehlschlagender
// Endpunkt nicht jede Anfrage erneut einen RPC kosten lässt). Exportiert für
// Fixture-Tests (lib/flow-state-validated.test.mjs)
// — Handler-intern unverändert nur über fetch auf globalThis.
export async function fetchValidatedIndex() {
  if (validatedCache && Date.now() - validatedCache.time < validatedCache.ttl) {
    return validatedCache.index;
  }
  let index = null;
  try {
    const res = await fetch(RPC_URL, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ method: "ledger", params: [{ ledger_index: "validated" }] }),
    });
    if (res.ok) {
      const data = await res.json().catch(() => null);
      const n = Number(data?.result?.ledger_index);
      if (Number.isFinite(n) && n > 0) index = Math.floor(n);
    }
  } catch {
    /* null -> ehrlicher Leerzustand im Client */
  }
  validatedCache = { time: Date.now(), index, ttl: index == null ? VALIDATED_NEGATIVE_CACHE_MS : VALIDATED_CACHE_MS };
  return index;
}

// Test-Helfer (lib/flow-state-validated.test.mjs): setzt den Prozess-Cache
// zurück, damit Fixture-Tests den Cache-Zustand unabhängig von vorangegangenen
// Tests prüfen können. Kein Handler-Pfad, keine Produktionsnutzung.
export function resetValidatedCacheForTests() {
  validatedCache = null;
}

// Fail-closed: Persistenz erfordert den Token (nur aus ENV).
const hasPersistence = () => Boolean(process.env.GITHUB_HISTORY_TOKEN);

// Bait-Labels für die Archiv-Replay-Filterung (Muster api/ledger.js:41-46 —
// Adressen nur aus ENV, nie in dieser Datei): Köder-Endpunkte in rekonstruier-
// ten Hops fallen STILL raus (B2).
const baitLabels = new Map();
(process.env.BAIT_ADDRESSES || "")
  .split(",")
  .map((a) => a.trim())
  .filter(Boolean)
  .forEach((addr, i) => baitLabels.set(addr, `HP-${i + 1}`));

// ---------- Archiv-Zweig (route=archive, Grenze 2) ----------
// GET /api/flow-state?route=archive&address=…&from=…&to=… — Rückwärts-
// Rekonstruktion über die Flow-Archiv-Tages-Chunks (replayArchive,
// lib/flow-state.mjs). from/to sind LEDGER-Indizes. 60-s-Prozess-Cache im
// Muster des Block-Fenster-Zweigs (:108-115): ein Poll/Minute pro Besucher-
// Tab bleibt unabhängig von der Besucherzahl gecacht.
// Lese-Budget (Nachprüfung: das alte Pauschal-Lesen von 31 Tagen pro Aufruf
// war ungesteuert — jetzt wird RÜCKWÄRTS in Blöcken à ARCHIVE_QUERY_DAYS
// (31) Tagen gelesen, mit harter Kappe ARCHIVE_MAX_DAY_BLOCKS Blöcken
// (Default 2 → max. 62 GitHub-Reads pro Aufruf, ENV ARCHIVE_MAX_DAY_BLOCKS
// überschreibbar). Early-Stop: sobald ein gelesener Archiv-Cluster mit
// ledgerRange.from <= fromLedger erreicht ist, ist die angefragte Fenster-
// untergrenze abgedeckt und das Lesen endet sofort (typischer Fall: ein
// einziger Block). response.truncated = true, wenn die Tages-Kappe erreicht
// wurde, ohne fromLedger abzudecken (erkennbar am minimalen
// ledgerRange.from aller gelesenen Blöcke > fromLedger); zusätzlich
// queryDays = tatsächlich gelesene Tage. DOKUMENTIERTE RESTLÜCKE (ehrlich,
// kein 'vollständig'-Versprechen): Registry-verknüpfte Cluster bleiben
// 180 d archiviert, jenseits von ARCHIVE_MAX_DAY_BLOCKS * ARCHIVE_QUERY_DAYS
// (Default 62 d) sind sie über diese Route nicht erreichbar — die
// Retention übersteigt die Abfragbarkeit.
const XRPL_ADDR_RE = /^r[1-9A-HJ-NP-Za-km-z]{24,34}$/;
const ARCHIVE_QUERY_DAYS = 31;
const ARCHIVE_MAX_DAY_BLOCKS = (() => {
  const n = Number(process.env.ARCHIVE_MAX_DAY_BLOCKS);
  return Number.isFinite(n) && n >= 1 ? Math.min(6, Math.floor(n)) : 2;
})();
const ARCHIVE_CACHE_MS = 60000;
const archiveCache = new Map(); // key -> { time, body }

// Test-Helfer (lib/flow-state-validated.test.mjs-Muster): Cache zurücksetzen.
export function resetArchiveCacheForTests() {
  archiveCache.clear();
}

async function handleArchive(req, res) {
  const address = String(req?.query?.address ?? "").trim();
  if (!XRPL_ADDR_RE.test(address)) {
    return res.status(400).json({ error: "Ungültige Adresse." });
  }
  const from = Number(req?.query?.from);
  const to = Number(req?.query?.to);
  if (!Number.isFinite(from) || !Number.isFinite(to) || from > to) {
    return res.status(400).json({ error: "Ungültiges Fenster (from/to als Ledger-Indizes)." });
  }
  if (baitLabels.has(address)) {
    // generisch — kein Oracle (Muster threats-service checkAddress)
    return res.status(400).json({ error: "Ungültige Adresse." });
  }
  if (!hasPersistence()) {
    return res.status(200).json({
      address,
      from,
      to,
      hops: [],
      truncated: false,
      reason: "Persistenz nicht konfiguriert",
    });
  }
  const cacheKey = `${address}|${from}|${to}`;
  const now = Date.now();
  const cached = archiveCache.get(cacheKey);
  if (cached && now - cached.time < ARCHIVE_CACHE_MS) {
    return res.status(200).json(cached.body);
  }
  try {
    // Rückwärts-Lesen in Blöcken à ARCHIVE_QUERY_DAYS Tagen, harte Kappe
    // ARCHIVE_MAX_DAY_BLOCKS Blöcke. Early-Stop: ein gelesener Archiv-Cluster
    // mit ledgerRange.from <= fromLedger deckt die Fensteruntergrenze ab.
    const allDocs = [];
    let covered = false;
    let minLedgerFrom = null; // Minimum der ledgerRange.from aller gelesenen Cluster
    let blocksRead = 0;
    for (let block = 0; block < ARCHIVE_MAX_DAY_BLOCKS && !covered; block++) {
      const days = [];
      for (let back = block * ARCHIVE_QUERY_DAYS; back < (block + 1) * ARCHIVE_QUERY_DAYS; back++) {
        const d = dayOf(now - back * 24 * 60 * 60 * 1000);
        if (d && !days.includes(d)) days.push(d);
      }
      const docs = await Promise.all(
        days.map(async (d) => {
          const { doc } = await readArchiveGitHub(d);
          return { day: d, doc };
        })
      );
      blocksRead++;
      allDocs.push(...docs);
      for (const { doc } of docs) {
        for (const c of Array.isArray(doc?.docs) ? doc.docs : []) {
          const f = Number(c?.ledgerRange?.from);
          if (!Number.isFinite(f)) continue;
          if (minLedgerFrom === null || f < minLedgerFrom) minLedgerFrom = f;
          if (f <= from) covered = true;
        }
      }
    }
    const { hops, truncated } = replayArchive(allDocs, { address, fromLedger: from, toLedger: to });
    // Tages-Kappe ohne Fensterabdeckung -> truncated (dokumentierte Grenze;
    // kein Archiv-Dokument erreicht fromLedger, Lesebudget ist erschöpft).
    const dayCapTruncated = !covered;
    // Bait-Filter (B2, STILL): Hop mit Köder-Endpunkt fällt raus.
    const cleanHops = hops.filter((h) => !baitLabels.has(h.from) && !baitLabels.has(h.to));
    const body = {
      address,
      from,
      to,
      hops: cleanHops,
      truncated: truncated || dayCapTruncated,
      queryDays: blocksRead * ARCHIVE_QUERY_DAYS,
    };
    archiveCache.set(cacheKey, { time: now, body });
    return res.status(200).json(body);
  } catch (err) {
    const status = err?.status === 429 ? 503 : 502;
    return res.status(status).json({ error: "Flow-Archiv nicht erreichbar." });
  }
}

// ---------- Block-Fenster-Zweig (route=block-window) ----------
// Ehemals api/block-window.js (entfernt: Hobby-Limit 12 Functions).
// 60-s-Prozess-Cache: range -> { time, body } (nur im Prozess-Speicher).
// Begrenzt die GitHub-Reads pro Function-Instanz auf <= 7/min pro Range,
// unabhängig von der Besucherzahl.
const BW_RANGES = { "24h": 24, "3d": 72, "7d": 168 }; // Stunden
const BW_CACHE_MS = 60000;
const bwCache = new Map();

// Test-Helfer (lib/block-window-endpoint.test.mjs): setzt den Cache zurück.
export function resetBlockWindowCacheForTests() {
  bwCache.clear();
}

async function handleBlockWindow(req, res) {
  const rawRange = String(req?.query?.range ?? "24h").trim();
  const hours = BW_RANGES[rawRange];
  if (!hours) {
    return res.status(400).json({ error: "Ungültiger range (24h|3d|7d)." });
  }
  if (!hasPersistence()) {
    return res.status(200).json({
      range: rawRange,
      from: null,
      to: null,
      updatedAt: null,
      buckets: [],
      flagged: [],
      cursor: 0,
      validatedIndex: null,
      reason: "Persistenz nicht konfiguriert",
    });
  }
  try {
    const now = Date.now();
    const from = now - hours * 3600 * 1000;
    const cached = bwCache.get(rawRange);
    if (cached && now - cached.time < BW_CACHE_MS) {
      // Kompletter Body gecacht (Chunks + cursor + validatedIndex): ein
      // Poll/Minute pro Besucher-Tab erzeugt pro Function-Instanz damit
      // <= 1 Chunk-Read + 1 Flow-State-Read + 1 RPC pro Minute.
      return res.status(200).json(cached.body);
    }
    // Tages-Chunks fürs Fenster lesen (max. 8 Dateien bei 7 d — der Tag
    // vor dem Fensteranfang kann Blöcke im Fenster tragen).
    const days = [];
    for (let back = 0; back <= Math.ceil(hours / 24); back++) {
      const d = dayOf(now - back * 24 * 60 * 60 * 1000);
      if (d && !days.includes(d)) days.push(d);
    }
    const docs = await Promise.all(
      days.map(async (d) => {
        const { doc } = await readBlockWindowGitHub(d);
        return { day: d, doc };
      })
    );
    const { buckets, flagged } = projectBlockWindow(docs.map((e) => e.doc), { fromMs: from, toMs: now });
    const updatedAt = docs.reduce((m, e) => Math.max(m, Number(e.doc?.updatedAt) || 0), 0) || null;
    const { doc } = await readFlowStateGitHub();
    const validatedIndex = await fetchValidatedIndex();
    const body = {
      range: rawRange,
      from,
      to: now,
      updatedAt,
      buckets,
      flagged,
      cursor: doc.cursor,
      validatedIndex,
    };
    bwCache.set(rawRange, { time: now, body });
    return res.status(200).json(body);
  } catch (err) {
    // Read-Fehler (403/429, Netzwerk) -> 502/503 (429 des Upstream -> 503).
    const status = err?.status === 429 ? 503 : 502;
    return res.status(status).json({ error: "Block-Fenster nicht erreichbar." });
  }
}

export default async function handler(req, res) {
  res.setHeader("Cache-Control", "no-store");
  const method = String(req?.method ?? "GET").toUpperCase();
  if (method !== "GET") {
    res.setHeader("Allow", "GET");
    return res.status(405).json({ error: "Methode nicht erlaubt." });
  }
  // Routen-Weiche: /api/block-window wird per Rewrite hierher gemappt.
  if (String(req?.query?.route ?? "").trim() === "block-window") {
    return handleBlockWindow(req, res);
  }
  // Dritte Route: Archiv-Rückwärtssuche (Grenze 2, ohne neue Function).
  if (String(req?.query?.route ?? "").trim() === "archive") {
    return handleArchive(req, res);
  }
  if (!hasPersistence()) {
    // Ohne Persistenz gibt es keinen Cursor, gegen den validatedIndex sinnvoll
    // wäre — der RPC bleibt in diesem Zweig komplett aus (Egress-Schonung).
    return res.status(200).json({
      cursor: 0,
      updatedAt: null,
      validatedIndex: null,
      clusters: [],
      reason: "Persistenz nicht konfiguriert",
    });
  }
  try {
    const { doc } = await readFlowStateGitHub();
    // baitLabels optional: projectFlowStateView löst ENV BAIT_ADDRESSES selbst
    // (Muster api/ledger.js) — edges/rolesByAddress/memberAddresses werden
    // serverseitig STILL gefiltert (B2; public/history-host.html rendert
    // rolesByAddress ohne eigenen Deny-Gate).
    const view = projectFlowStateView(doc);
    const validatedIndex = await fetchValidatedIndex();
    return res.status(200).json({ ...view, validatedIndex });
  } catch (err) {
    // Read-Fehler (403/429, Netzwerk) -> kein Erfolg ohne Persistenz.
    // 429 des Upstream -> 503, alles andere 502.
    const status = err?.status === 429 ? 503 : 502;
    return res.status(status).json({ error: "Flow-State nicht erreichbar." });
  }
}
