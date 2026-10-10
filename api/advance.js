// Vercel Function: POST /api/advance — Cursor-Advance-Tick (transport-agnostisch).
//
// Rückt den persistierten Ledger-Cursor um ein ENV-konfigurierbares Budget vor
// (lib/ledger-walk.mjs advance()), persistiert das Ergebnis als Flow-State-
// Dokument (lib/flow-state.mjs) UND als rollender Block-Fenster-Bestand
// (lib/block-window.mjs, data/block-window/<YYYY-MM-DD>.json) und liefert
// neuen Cursor + Summary. Der Block-Fetcher ist die Transport-Naht: er
// injiziert pro Ledger-Index einen Block {transactions, findings} oder null
// am Live-Edge. advance() selbst ist transport-agnostisch (Fetcher
// injizierbar) — hier wird nur die RPC-Implementierung der Naht angebunden.
//
// DATENQUELLE (Umstellung 2026-10-02): honeycluster.io — offiziell auf
// xrpl.org/docs/tutorials/public-servers gelisteter Mainnet-Server mit voller
// Historie (Clio, complete_ledgers ab Genesis-Nähe, live geprobt). HTTP-
// JSON-RPC-Pfad: POST {method:'ledger', params:[{ledger_index, transactions:
// true, expand:true}]}.
//
// QUOTA (honeycluster-Modell, Nutzer-Angabe 2026-10-02): 10 req/s steady,
// 20 Requests sofort beim Start, Burst 50 req pro 5-s-Fenster, Resett nach
// 30 s Inaktivität. Das Units-Modell von xrplcluster (10.000 Units/60 s,
// Kosten-Obergrenze 700/Command) ist ERSETZT durch Request-Zählung:
//   - REQUESTS_PER_SEC = 10 (steady-Limit),
//   - TICK_REQUEST_BUDGET = 250 (25 s nutzbar × 10/s, konservativ unter der
//     simulierten Obergrenze 270 — lib/rate-gate.test.mjs Simulation),
//   - 1 Request pro Block (expand:true liefert alle Tx-Objekte; kein
//     separates tx-Kommando mehr) -> worstCaseTickRequests(budget) = budget,
//   - DEFAULT_BUDGET = 140 Blöcke/Tick (ENV ADVANCE_BUDGET überschreibt).
//   Latenzgebundenes Optimum: expand:true-Latenz gemessen Ø ~0,7 s;
//   FETCH_PARALLEL = 4 -> ~5,7 req/s < 10/s steady; ohne Gate wären über
//   30-s-Ticks alle ~100 s ~16 req/s — deshalb Rate-Gate PRO REQUEST
//   (lib/rate-gate.mjs), nicht pro Tick.
//   Throttle-Semantik bei echtem Überschreiten ist UNVERIFIED (live nicht
//   bis zur Grenze belastet); 429/5xx werden behandelt wie slowDown/tooBusy.
//
// ADAPTER (expand:true-Einträge, live belegt 2026-10-02): expand-Einträge
// tragen KEIN meta, KEIN ledger_index, KEIN close_time_iso. Sie werden pro
// Entry gestempelt: e.meta = e.metaData (normalizeTxEntry liest entry.meta,
// lib/detector.mjs:174), e.ledger_index = Ledger-Ebenen-Index,
// e.close_time_iso = Ledger-Ebenen-close_time_iso — sonst degradieren
// ledgerSeq (edgeIdentity/Top-K, lib/ledger-walk.mjs) und closeTime
// (firstSeen/lastSeen, lib/cluster.mjs:322-340; 7-Tage-Pruning kann
// null-Cluster nicht einordnen). Stempel-Muster wie lib/live-gate.mjs.
//
// FETCHER-VERTRAG (live geprobt): Zukunft-Index -> HTTP 200 +
// result.error 'lgrNotFound' -> null (Walk-Ende). Gültiger Index mit 0 Txs
// -> LEERBLOCK {transactions:[], findings:[]} (truthy, Cursor rückt vor —
// Blockage-Fix: früher stoppte 0-Txs dauerhaft den Walk).
//
// KÖDERSCHUTZ (B2): Die Detector-Regeln flaggen Köder-Endpunkte, also landen
// Köder-Adressen in from/to der geflagten Txs. Vor mergeBlock und vor
// Persistenz des Block-Fensters filtert dieser Endpunkt: Entries mit
// Köder-Endpunkt (account/destination) und Findings mit Köder-Adresse fallen
// still raus; baitLabels nur aus ENV BAIT_ADDRESSES (Muster api/ledger.js),
// nie in Dateien. Der Block-Fenster-Codec filtert zusätzlich (lib/
// block-window.mjs).
//
// SICHERHEIT:
//   - FAIL-CLOSED ohne Token: ohne GITHUB_HISTORY_TOKEN wird weder gelesen
//     noch vorgeschoben noch persistiert (503) — keine Cursor-Regression ohne
//     Persistenz-Berechtigung. Token NUR aus process.env, nie geloggt.
//   - Budget aus ENV ADVANCE_BUDGET (Default 100) — Serverless-Budget.
//
// POST -> { cursor: newCursor, summary } (nur Zahl + Summary, kein State-Leak)
//         Read-/Write-Fehler -> 502/503 (kein Erfolg ohne Persistenz).
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { advance } from "../lib/ledger-walk.mjs";
import {
  readFlowStateGitHub,
  writeFlowStateGitHub,
  mergeFlowState,
  effectiveClusterCap,
  capClusterFields,
  archiveFromFlowState,
  archiveDayOf,
  appendArchiveDoc,
  capArchiveDoc,
  pruneArchiveDocs,
  readArchiveGitHub,
  writeArchiveGitHub,
  deleteArchiveGitHub,
  checkpointFromFlowState,
  hasCheckpointDoc,
  ARCHIVE_RETENTION_MALICIOUS_MS,
  ARCHIVE_RETENTION_REGISTRY_MS,
  ARCHIVE_MAX_BYTES,
  hasFraudEvidence,
} from "../lib/flow-state.mjs";
import { analyzeLedger, expandBatches } from "../lib/detector.mjs";
import { txRecordFromEntry } from "../lib/cluster.mjs";
import { createRateGate, parseRetryAfterMs } from "../lib/rate-gate.mjs";
import {
  appendBlockWindow,
  capBlockWindow,
  BLOCK_WINDOW_MAX_BYTES,
  blockRecord,
  dayOf,
  flaggedEdgesFrom,
  entitySignalsFrom,
  pruneBlockWindowDocs,
  readBlockWindowGitHub,
  writeBlockWindowGitHub,
  deleteBlockWindowGitHub,
} from "../lib/block-window.mjs";
import {
  readEntityGitHub,
  writeEntityGitHub,
  capEntityDoc,
  ENTITY_MAX_BYTES,
  fetchEntitySnapshots,
  buildEntityLinks,
  freshEvidence,
} from "../lib/entity-resolve.mjs";
import {
  readGitHubContents,
  writeGitHubContents,
  historyKey,
  historyLastWriteMs,
  HISTORY_BATCH_MS,
  pruneHistoryByAge,
  readHistoryGitHub,
  mergeHistory,
  writeHistoryGitHub,
} from "../lib/history.mjs";
import { getThreatKnowledge, buildCheckCtx, getExchangeRegistryMap, getMultiUserAccountsMap } from "../lib/threats-service.mjs";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, "..");

// Whitelists optional aus config.json (Muster api/ledger.js:30-35).
let config = { network: "mainnet", wss: "wss://honeycluster.io" };
try {
  config = { ...config, ...JSON.parse(fs.readFileSync(path.join(ROOT, "config.json"), "utf8")) };
} catch {
  /* Default bleibt */
}

export const maxDuration = 30;

const RPC_URL =
  process.env.RPC_URL ||
  (process.env.WSS_URL || config.wss || "wss://honeycluster.io").replace(/^wss:/, "https:");

// Bait-Labels für die serverseitige Filterschicht — Adressen nur aus ENV
// (Vercel), niemals Seeds. Identisches Muster wie api/ledger.js:41-46.
const baitLabels = new Map();
(process.env.BAIT_ADDRESSES || "")
  .split(",")
  .map((a) => a.trim())
  .filter(Boolean)
  .forEach((addr, i) => baitLabels.set(addr, `HP-${i + 1}`));

// ---------- Request-Budget-Modell (honeycluster; siehe Header) ----------
export const REQUESTS_PER_SEC = 10; // honeycluster steady-Limit
export const TICK_REQUEST_BUDGET = 250; // 25 s nutzbar × 10/s (konservativ)
export const FETCH_PARALLEL = 4; // 4/0,708 s ≈ 5,7 req/s < 10/s steady
// Budget-Default: 140 Blöcke/Tick (Aufhol-Beschaltung 05.10.2026) — Bilanz
// 140 + REPLAY 40 + ENTITY 20 + Seed 1 = 201 <= TICK_REQUEST_BUDGET 250;
// die 19-s-Walk-Fenster (Deadline minus PERSIST_MARGIN_MS) kappen bei live
// gemessener Latenz 1,1-1,8 s ohnehin auf ~55-108 Blöcke/Tick. ENV
// ADVANCE_BUDGET überschreibt — budgetOf klemmt JEDEN ENV-Wert gegen
// MAX_WALK_BUDGET 189 (siehe dort; Bilanz 189 + 40 + 20 + 1 = 250 <= 250,
// V7-Kalibrier-Tiefschnitt kann die Bilanz nie kippen).
export const DEFAULT_BUDGET = 140;
// Entity-Layer-Cap (Grenze 3): account_info-Calls pro Tick nach dem Block-
// Walk. Budget-Bilanz (doku, lib/advance-batch.test.mjs):
//   worstCaseTickRequests(140) + REQUESTS_PER_TICK_CAP(40) + ENTITY_TICK_CAP(20)
//   + seedCursorIfFresh (1 Request, NUR bei frischem Cursor) <= 250.
// Die GitHub-Retention-Calls (Block-Fenster/Archiv-Löschung, unten) gehören
// NICHT ins honeycluster-Budget — sie laufen gegen die GitHub-Contents-API.
export const ENTITY_TICK_CAP = 20;
// Replay-Cap (Grenze 2): account_tx-Calls pro Tick für persistierte Replay-
// Jobs (data/replay-jobs.json).
export const REPLAY_TICK_CAP = 40;

// ---------- Replay-Jobs (data/replay-jobs.json im Daten-Repo) ----------
// { jobs: [ { address, fromLedger, toLedger, marker: {ledger, seq}|null,
//             status: 'pending'|'done', updatedAt } ] }
// Marker = fortgeschrittener account_tx-Paging-Zustand (ledger_index_max +
// seq); wird nach Erreichen von toLedger entfernt. Codec-Muster
// lib/flow-state.mjs:101-118 (Dokument, Korruption wirft).
export const REPLAY_JOBS_FILE_PATH = "data/replay-jobs.json";

function normalizeReplayJobsDoc(doc) {
  let updatedAt = null;
  if (doc && doc.updatedAt !== null && doc.updatedAt !== undefined && doc.updatedAt !== "") {
    const n = Number(doc.updatedAt);
    if (Number.isFinite(n)) updatedAt = n;
  }
  const jobs = [];
  for (const j of Array.isArray(doc?.jobs) ? doc.jobs : []) {
    if (!j || typeof j !== "object" || Array.isArray(j)) continue;
    const address = typeof j.address === "string" && j.address ? j.address : null;
    if (!address) continue;
    const fromLedger = Number(j.fromLedger);
    const toLedger = Number(j.toLedger);
    const marker =
      j.marker && typeof j.marker === "object" && !Array.isArray(j.marker)
        ? {
            ledger: Number.isFinite(Number(j.marker.ledger)) ? Number(j.marker.ledger) : null,
            seq: Number.isFinite(Number(j.marker.seq)) ? Number(j.marker.seq) : null,
          }
        : null;
    const status = j.status === "done" ? "done" : "pending";
    const upd = Number(j.updatedAt);
    jobs.push({
      address,
      fromLedger: Number.isFinite(fromLedger) ? fromLedger : null,
      toLedger: Number.isFinite(toLedger) ? toLedger : null,
      marker,
      status,
      updatedAt: Number.isFinite(upd) ? upd : null,
    });
  }
  return { updatedAt, jobs };
}

export function serializeReplayJobsDoc(doc) {
  return JSON.stringify(normalizeReplayJobsDoc(doc));
}

export function parseReplayJobsText(text) {
  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch {
    throw new Error("Replay-Jobs-Bestand nicht parsebar (korrumpiert) — kein Überschreiben.");
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error("Replay-Jobs-Bestand hat unerwartetes Format — kein Überschreiben.");
  }
  return normalizeReplayJobsDoc(parsed);
}

const replayJobsCodec = { serialize: serializeReplayJobsDoc, parse: parseReplayJobsText };

// Pure: Job-Liste um einen neuen Replay-Job ergänzen (Adress-Dedup: gleiche
// Adresse + gleiches Fenster -> existing gewinnt; sonst anhängen).
export function mergeReplayJob(jobsDoc, { address, fromLedger, toLedger }, now) {
  const base = normalizeReplayJobsDoc(jobsDoc);
  const jobs = [...base.jobs];
  const idx = jobs.findIndex(
    (j) => j.address === address && j.fromLedger === fromLedger && j.toLedger === toLedger
  );
  const job = { address, fromLedger, toLedger, marker: null, status: "pending", updatedAt: now };
  if (idx >= 0) jobs[idx] = { ...jobs[idx], status: "pending", updatedAt: now };
  else jobs.push(job);
  return { updatedAt: now, jobs };
}

// Pure: Worst-Case-Request-Anzahl eines Advance-Ticks. expand:true liefert
// alle Tx-Objekte im ledger-Kommando -> GENAU 1 Request pro Block (kein
// tx-Kommando mehr). Garbage-Inputs -> 0.
export function worstCaseTickRequests(budget) {
  const b = Number(budget);
  if (!Number.isFinite(b)) return 0;
  return Math.max(0, Math.floor(b));
}

// ---------- Backoff-Parameter (Muster lib/live-gate.mjs) ----------
const RETRY_SLACK_MS = 2000; // Guard-Slack über dem genannten Fenster
const BASE_BACKOFF_MS = 2000; // exponentieller Start (ohne genanntes Fenster)
const BACKOFF_CAP_MS = 30000; // exponentielle Kappe
const MAX_DURATION_MS = maxDuration * 1000;
const GUARD_MARGIN_MS = 5000; // Restlaufzeit für Persistenz-Write + Antwort

// Persistenz-Marge für den Walk-Stopp: GUARD_MARGIN_MS allein deckt nur
// Antwort+Start-Persistenz ab. Die letzte Parallel-Runde des Walks läuft
// bis Deadline + Latenz (live gemessen bis 1,79 s) aus, danach folgen die
// Persistenz-Calls (Flow-State GET+PUT, Block-Fenster GET+PUT/Tag,
// Retention 3 GET+DELETE, Archiv-Retention 7 GET, Entity GET+PUT, Replay
// GET — live ~5-8 s). Mit Marge 6000 endet der Walk bei ~19 s:
// 19 s + ~2 s Rest-Runde + ~8 s Persistenz <= 30 s (maxDuration).
const PERSIST_MARGIN_MS = 6000;

// Checkpoint-Restlaufzeit (iii.6): der Tages-Checkpoint ist EIN GET + EIN PUT
// gegen die GitHub-Contents-API (~1-2 s live). Bei weniger Restlaufzeit bis
// tickDeadline wird er geskippt (Nachhol im nächsten Tick, Guard idempotent) —
// maxDuration 30 bleibt gewahrt, kein sechster Persistenz-Block nachträglich.
const CHECKPOINT_DEADLINE_SLACK_MS = 2000;

// Pure: genanntes Retry-Fenster (ms) aus einem RPC-Fehler-Result parsen.
// Präzedenz wie lib/live-gate.mjs: retry_after-Feld (Sekunden) vor
// "retry in ~Nms" in error_message. Kein Fenster -> null.
export function parseRetryWindowMs(result) {
  if (!result || typeof result !== "object") return null;
  const fieldMs = Number(result.retry_after) * 1000;
  const msg = String(result.error_message || result.error || "");
  const msgMs = Number(msg.match(/retry in ~?(\d+)ms/)?.[1]);
  for (const n of [fieldMs, msgMs]) {
    if (Number.isFinite(n) && n > 0) return Math.floor(n);
  }
  return null;
}

// Pure: Backoff-Dauer (ms) für Versuch i (0-basiert) bei gegebenem genanntem
// Fenster (oder null): genanntes Fenster voll aussetzen + Slack; sonst
// exponentiell BASE*2^i mit Kappe (Muster lib/live-gate.mjs).
export function backoffDelayMs(attempt, statedMs) {
  if (statedMs != null && Number.isFinite(statedMs) && statedMs > 0) {
    return Math.floor(statedMs) + RETRY_SLACK_MS;
  }
  const i = Math.max(0, Math.floor(Number(attempt) || 0));
  return Math.min(BASE_BACKOFF_MS * 2 ** i, BACKOFF_CAP_MS);
}

// Pure: Cursor-Seed für den ersten Tick. Der Walk startet NICHT bei Index 0
// (Genesis) — der Catch-up von dort wäre unendlich, und der öffentliche
// Validator liefert alte Blöcke nicht mehr (fetcher -> null, Cursor bleibt 0).
// Stattdessen startet er im REZENTEN VERGANGENEN: validatedIndex minus
// lookbackBlocks (~1 Monat), begrenzt auf >= 1. validatedIndex null/ungültig
// -> null (kein Seed, Cursor bleibt). lookbackBlocks <= 0 -> validatedIndex.
export function seedCursor(validatedIndex, lookbackBlocks) {
  const v = Number(validatedIndex);
  if (!Number.isFinite(v) || v <= 0) return null;
  const lb = Math.max(0, Math.floor(Number(lookbackBlocks) || 0));
  return Math.max(1, Math.floor(v) - lb);
}

// Tick-Deadline (Wall-Clock-Guard): gesetzt vom Handler, cleared in finally.
// rpc() wirft, wenn ein genanntes Quota-Fenster die Restlaufzeit übersteigt —
// statt die Function über maxDuration zu hämmern (Muster
// lib/live-gate.mjs). advance() behandelt einen Fetcher-Fehler als Ende des
// Walks und persistiert den Partial-Fortschritt (ledger-walk.mjs).
let tickDeadline = null;

// Test-Seams (Kritik 3): Handler-Tests gegen Fixture-rpc und injizierbare
// Uhr, ohne Live-Netzwerk/Live-Wall-Clock. Muster lib/threats-service.mjs:66-68.
// setRpcForTests(fn): rpc() delegiert an rpcImpl (Default: Produktions-rpc).
// setClockForTests(fn): tickDeadline/Sleep über injizierbare Uhr — fn ist
// entweder eine now()-Funktion oder ein Objekt { now, sleep }.
let rpcImpl = null;
let clockImpl = () => Date.now();
let sleepImpl = (ms) => new Promise((r) => setTimeout(r, ms));

export function setRpcForTests(fn) {
  rpcImpl = typeof fn === "function" ? fn : null;
}

export function setClockForTests(fn) {
  if (typeof fn === "function") {
    clockImpl = fn;
  } else if (fn && typeof fn === "object") {
    if (typeof fn.now === "function") clockImpl = fn.now;
    if (typeof fn.sleep === "function") sleepImpl = fn.sleep;
  } else {
    clockImpl = () => Date.now();
    sleepImpl = (ms) => new Promise((r) => setTimeout(r, ms));
  }
}

// Rate-Gate pro Request (honeycluster 10/s, Burst 50, Start 20): jeder
// rpc()-Call erwirbt vor dem fetch. Parallelität im Block-Fetch wird dadurch
// pro Request gekappt, nicht pro Tick.
const rateGate = createRateGate({ ratePerSec: REQUESTS_PER_SEC });

// slowDown/tooBusy/429/5xx-Backoff (429-aware, B4): ein HTTP-429 oder 5xx
// wird behandelt wie ein genanntes Quota-Fenster — retry-after-Header
// (Sekunden oder HTTP-Datum) wird voll ausgesetzt (+Slack); ohne genanntes
// Fenster exponentiell mit Kappe. Ein Fenster, das die Restlaufzeit übersteigt,
// wirft sofort (Fail-Fast -> Partial-Persist). Quota-Fenster innerhalb der
// Restlaufzeit werden AUSGESISSEN — der Tick verliert nicht still sein
// Restbudget (a.D. warf !res.ok sofort und advance() deutete den Wurf als
// Walk-Ende).
async function rpc(method, params, tries = 3) {
  // Seam (Kritik 3): Tests injizieren eine Fixture-rpc; Produktion läuft den
  // realen HTTPS-Pfad unter dem Rate-Gate.
  if (rpcImpl) return rpcImpl(method, params);
  let lastHint = null;
  for (let i = 0; i < tries; i++) {
    await rateGate.acquire(1);
    const res = await fetch(RPC_URL, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ method, params: [{ ...params }] }),
    });
    if (res.status === 429 || res.status >= 500) {
      // Drosselung/Upstream-Fehler wie slowDown/tooBusy: Fenster aus retry-
      // after-Header (oder exponentiell) aussetzen, Deadline-Guard beachten.
      const msg = `HTTP ${res.status}`;
      lastHint = msg;
      const delay = backoffDelayMs(i, parseRetryAfterMs(res.headers.get("retry-after")));
      if (tickDeadline != null && clockImpl() + delay > tickDeadline) {
        throw new Error(`RPC ${msg} — Quota-Fenster übersteigt Restlaufzeit.`);
      }
      await sleepImpl(delay);
      continue;
    }
    if (!res.ok) throw new Error(`RPC HTTP ${res.status}`);
    const data = await res.json();
    if (data?.result?.error === "slowDown" || data?.result?.error === "tooBusy") {
      const msg = String(data.result?.error_message || data.result.error);
      lastHint = msg;
      const delay = backoffDelayMs(i, parseRetryWindowMs(data.result));
      if (tickDeadline != null && clockImpl() + delay > tickDeadline) {
        throw new Error(
          `RPC error: ${data.result.error} (${msg}) — Quota-Fenster übersteigt Restlaufzeit.`
        );
      }
      await sleepImpl(delay);
      continue;
    }
    if (data?.result?.error) throw new Error(`RPC error: ${data.result.error}`);
    return data.result;
  }
  throw new Error(`RPC error: throttled${lastHint ? ` (${lastHint})` : ""}`);
}

// ctx für die Engine: knownBad aus der Honeypot-Präzisionsschicht UND den
// persistierten Quellen — merged Wissens-Layer getThreatKnowledge()
// (deriveThreats + data/history.json-Members + data/flow-state.json
// severityByAddress, Registry-ausgeschlossen via buildCheckCtx) statt nur
// getPublicThreats: war die live-Ableitung leer oder der RPC gestört
// (live gemeldet: /api/threats=[]), verlor die Engine ihre
// Präzisionsanker, obwohl die persistierte Historie malicious-Cluster enthält
// (lokal gemessen: 607 history-Members in data/history.json). Whitelists
// optional aus config.json (Muster api/ledger.js). firstSeenAt wird aus dem
// persistierten Flow-State geseedet (Cluster-firstSeen pro Adresse): die
// drainer-sweep-Regel — einzige Frische-Regel mit severity malicious —
// feuerte im Persistenzpfad bisher nie (firstSeenAt war leer); persistierte
// Beweise enthalten jetzt strukturell Drainer-Nachweise. history ist eine
// pro Tick lebende Map (buildCtx läuft EINMAL pro Tick): sie überlebt die
// ~100 Blöcke eines Ticks und wird beim Tick-Start mit tiny-Kanten und
// firstSeen aus doc.state.clusters geseedet, damit Cross-Ledger-Fenster über
// Tick-Grenzen Anschluss finden. buildCtx() läuft EINMAL pro Tick (nicht
// pro Block): ein kalter Threats-Cache (lib/threats-service.mjs, 60-s-TTL)
// würde sonst pro Block account_tx-Calls feuern — zusätzliche Request-Last.
// Die merged-Schicht selbst feuert KEINEN honeycluster-Request (nur GitHub-
// Reads, lib/threats-service.mjs getThreatKnowledge).
const XRPL_ADDR_RE = /^r[1-9A-HJ-NP-Za-km-z]{24,34}$/;
const HISTORY_FILE_PATH_ADV = "data/history.json"; // Pfad im Daten-Repo (wie HISTORY_FILE_PATH in lib/history.mjs)
// Drainer-Historie (data/history.json im privaten Daten-Repo): nur schreiben, wenn ein Cluster-
// Schlüssel NEU ist. Eine Zeitdrosselung pro Instanz griff nicht (Vercel betreibt mehrere
// Instanzen). Sichtungszähler bestehender Cluster laufen nicht mit; Cluster werden je Tick neu
// aus dem Flow-State abgeleitet. Flow-State und Block-Fenster sind cursor-gekoppelt und
// bleiben unverändert.
const HISTORY_SEED_MAX = 20000; // Speicher-Obergrenze für firstSeen/history-Seeds
// Export (Test-Seam, Muster setRpcForTests): die Handler-Tests prüfen den
// verifiedFresh-fail-open-Pfad (entityDoc null -> leeres Set) direkt.
export async function buildCtx(doc, entityDoc) {
  const knownBad = new Set();
  // Merged Wissen (fail-open je Schicht): live-Ableitung + persistierte
  // History-Members + Flow-State severityByAddress, Exchange-Registry
  // ausgeschlossen (buildCheckCtx).
  let knowledgeResult = { knowledge: new Map(), historyList: null };
  try {
    knowledgeResult = await getThreatKnowledge();
  } catch {
    /* Honeypot-/Persistenz-Schicht optional */
  }
  const engineCtx = buildCheckCtx(knowledgeResult);
  for (const addr of engineCtx.knownBad) {
    if (typeof addr === "string" && XRPL_ADDR_RE.test(addr)) knownBad.add(addr);
  }
  const firstSeenAt = new Map();
  for (const [addr, ms] of engineCtx.firstSeenAt) {
    if (typeof addr === "string" && XRPL_ADDR_RE.test(addr)) firstSeenAt.set(addr, ms);
  }
  const history = new Map();
  for (const [addr, entry] of engineCtx.history) {
    if (typeof addr === "string" && XRPL_ADDR_RE.test(addr)) history.set(addr, entry);
  }
  const clusters = doc?.state?.clusters && typeof doc.state.clusters === "object" ? doc.state.clusters : {};
  for (const c of Object.values(clusters)) {
    if (!c || typeof c !== "object") continue;
    const fsRaw = c.firstSeen;
    const fsMs = typeof fsRaw === "string" ? Date.parse(fsRaw) : Number(fsRaw);
    if (!Number.isFinite(fsMs)) continue;
    const members = Array.isArray(c.memberAddresses) ? c.memberAddresses : [];
    for (const addr of members) {
      if (typeof addr !== "string" || !XRPL_ADDR_RE.test(addr)) continue;
      if (firstSeenAt.size >= HISTORY_SEED_MAX) break;
      if (!firstSeenAt.has(addr)) firstSeenAt.set(addr, fsMs);
    }
    // history-Seed: mainDrainers/collectors-Adressen mit ihrem Volumen als
    // fundedAt-Referenz — Cross-Ledger-Sweep/Union über Tick-Grenzen.
    for (const d of Array.isArray(c.mainDrainers) ? c.mainDrainers : []) {
      if (typeof d?.address !== "string") continue;
      if (history.size >= HISTORY_SEED_MAX) break;
      if (!history.has(d.address)) {
        history.set(d.address, { tinyDests: new Set(), fundedAt: Number(d.outDrops) || null, createdInWindow: false, lastLedger: null });
      }
    }
  }
  // V5 verifiedFresh (entity-resolve.mjs freshEvidence): Entity-Dokument liegt
  // ab (i.2) vor, das Set ist reine In-Memory-Arithmetik über die Tabelle —
  // +0 honeycluster-Requests. FP-Guards über das exclude-Set: Exchange-Registry
  // (∪ multiUser — Börsen sind per Definition hochfrequent, sonst False-
  // malicious-Kaskade über known-bad-hit), config-benign-Konten und Köder
  // (Defense-in-Depth, der Persistenz-Filter hat sie bereits raus). Beide
  // Threats-Maps sind gecacht (Registry 60 s, multiUser ~10 min) — die Calls
  // treffen den Tick-Cache, keine zusätzlichen GitHub-Roundtrips. entityDoc
  // null/fehlend -> leeres Set (fail-open, Verhalten bitgleich ohne Layer).
  const excludeFresh = new Set(baitLabels.keys());
  const exchangeKeys = new Set(); // nur Börsen (ohne Köder) — für benignAccounts
  for (const a of config.benign_accounts || []) {
    if (typeof a === "string") excludeFresh.add(a);
  }
  try {
    for (const a of getExchangeRegistryMap().keys()) { excludeFresh.add(a); exchangeKeys.add(a); }
  } catch {
    /* Registry-Layer optional (fail-open) */
  }
  try {
    for (const a of (await getMultiUserAccountsMap()).keys()) { excludeFresh.add(a); exchangeKeys.add(a); }
  } catch {
    /* Multi-User-Layer optional (fail-open) */
  }
  const verifiedFresh = freshEvidence(entityDoc ?? null, { exclude: excludeFresh });
  return {
    knownBad,
    benignIssuers: new Set(config.benign_issuers || []),
    // Börsen-Einzahlungsadressen (Registry ∪ verifizierte Namen) sind keine Welle-Ziele:
    // Nutzer heben dort legitim ganze Guthaben ab (account-delete-sweep/mass-sweep-convergence).
    benignAccounts: new Set([...(config.benign_accounts || []), ...exchangeKeys]),
    // marketExcludes (Kritik-Runde 3, T1.6): derselbe Börsen-/Köder-FP-Guard
    // wie excludeFresh oben — die Market-Regeln (amm-wash-swap/
    // thin-pool-exploit/spoof-offer-cycle, lib/detector.mjs) zählen
    // Market-Maker-Aktivität; ohne Guard feuern sie auf legitimen Börsen-
    // Konten. Dasselbe Set (Börsen-Registry ∪ multiUser ∪ config-benign ∪
    // Köder), keine neuen Requests (beide Maps treffen den Tick-Cache).
    marketExcludes: excludeFresh,
    threats: new Map(),
    firstSeenAt,
    history,
    verifiedFresh,
  };
}

// Adapter: expand:true-Einträge tragen kein meta/ledger_index/close_time_iso
// (live belegt) — Stempeln der Ledger-Ebenen-Werte pro Entry, damit
// normalizeTxEntry (detector.mjs) die meta-Form sieht und txRecordFromEntry
// ledgerSeq/closeTime liefert (Muster lib/live-gate.mjs:248-257 plus
// close_time_iso).
function stampExpandEntry(e, ledgerIndex, closeIso) {
  if (!e || typeof e !== "object") return e;
  if (e.meta == null && e.metaData != null) e.meta = e.metaData;
  if (e.ledger_index == null) e.ledger_index = ledgerIndex;
  if (e.close_time_iso == null && closeIso) e.close_time_iso = closeIso;
  return e;
}

// Transport-Naht: ein Ledger-Block {transactions, findings} oder null am
// Edge. GENAU EIN Request pro Block (expand:true, alle Tx-Objekte).
// Findings PRO BLOCK via analyzeLedger (lib/detector.mjs) mit dem
// tick-globalen ctx. Köder-Filter vor mergeBlock: Entries mit Köder-
// Endpunkt und Findings mit Köder-Adresse fallen still raus (B2).
async function fetchBlock(ledgerIndex, ctx) {
  let led;
  try {
    led = await rpc("ledger", {
      ledger_index: ledgerIndex,
      transactions: true,
      expand: true,
    });
  } catch (err) {
    // lgrNotFound am (zukünftigen) Index: Live-Edge -> null (Walk-Ende).
    if (String(err?.message).includes("lgrNotFound")) return null;
    throw err; // Netzwerk-/RPC-Fehler: advance() behandelt ihn als Walk-Ende
  }
  const ledger = led?.ledger ?? {};
  const ledgerIndexActual = Number(ledger.ledger_index ?? led?.ledger_index ?? ledgerIndex);
  const closeIso =
    ledger.close_time_iso ??
    (typeof ledger.close_time === "number"
      ? new Date((ledger.close_time + 946684800) * 1000).toISOString()
      : null);
  const raw = Array.isArray(ledger.transactions) ? ledger.transactions : [];
  const stamped = raw
    .map((e) => stampExpandEntry(e, ledgerIndexActual, closeIso))
    .filter((e) => e && typeof e === "object" && (e.TransactionType || e.tx_json || e.tx));
  // Batch-Inner expandieren (XLS-56): sonst sind innere Payments für Records,
  // Flow-Edges und Köder-Filter unsichtbar. Idempotent — analyzeLedger
  // expandiert nicht nochmal.
  const entries = expandBatches(stamped);
  // Bait-Filter (serverseitig, still — kein Oracle): tx mit Köder-Endpunkt.
  const cleanEntries = entries.filter((e) => {
    const rec = txRecordFromEntry(e, closeIso);
    if (!rec) return false;
    if (rec.account && baitLabels.has(rec.account)) return false;
    if (rec.destination && baitLabels.has(rec.destination)) return false;
    return true;
  });
  const result = analyzeLedger({ transactions: cleanEntries }, ctx);
  const findings = result.findings.filter((f) => !baitLabels.has(f.address));
  // LEERBLOCK (0 Txs, kein Fehler) ist truthy: {transactions:[], findings:[]}
  // — der Cursor rückt vor (Fetcher-Vertrag, Blockage-Fix).
  return { transactions: cleanEntries, findings, txCount: raw.length, closeIso };
}

// Fail-closed: Advance/Persistenz erfordert den Token (nur aus ENV).
const hasPersistence = () => Boolean(process.env.GITHUB_HISTORY_TOKEN);

// ENV-konfigurierbares Budget (Default 140 Blöcke/Tick). KLEMME (V7/Budget-
// Korrektur 2026-10-06): budgetOf klemmt gegen die Tick-Bilanz — Walk-Budget
// + REPLAY_TICK_CAP 40 + ENTITY_TICK_CAP 20 + Seed 1 <= TICK_REQUEST_BUDGET 250
// -> Walk max. 189 (MAX_WALK_BUDGET). Ein einmaliger Kalibrier-Tiefschnitt via
// ADVANCE_BUDGET-ENV (V7-Replay-Kalibrierung: dedizierter Tick, REPLAY_TICK_CAP
// konsumiert die existierenden 40 Replay-Requests) kann die Bilanz dadurch nie
// kippen — der Deckel ist im Code (nicht nur im Bilanztest) festgeschrieben
// und in lib/advance-batch.test.mjs geprüft.
export const MAX_WALK_BUDGET = TICK_REQUEST_BUDGET - REPLAY_TICK_CAP - ENTITY_TICK_CAP - 1; // 189
export function budgetOf() {
  const n = Number(process.env.ADVANCE_BUDGET);
  const raw = Number.isFinite(n) && n > 0 ? Math.floor(n) : DEFAULT_BUDGET;
  return Math.min(raw, MAX_WALK_BUDGET);
}

// ENV-konfigurierbarer Lookback (Default 0 = Live-Edge). Ein positiver
// Lookback gibt dem Walk eine initiale Historie; mit Budget 100/Tick und
// ~100 s Tick-Abstand (3 versetzte Cron-Workflows) fängt der Walk am
// Live-Edge an und hält ihn — Catch-up von weiter zurück dauert
// (Rückstand-Blöcke / 100 pro Tick).
function lookbackBlocks() {
  const n = Number(process.env.ADVANCE_LOOKBACK);
  return Number.isFinite(n) && n >= 0 ? Math.floor(n) : 0;
}

// Cursor-Seeding-Entscheidung: ein frischer/leerer Cursor (<= 0) startet NICHT
// bei Genesis (der öffentliche Validator liefert alte Blöcke nicht mehr —
// Fetcher -> null, Cursor bleibt 0). Stattdessen wird er auf den aktuellen
// Validated-Index minus Lookback gesetzt (ein zusätzlicher RPC-Call, nur beim
// Seed). Bereits fortgeschrittene Cursor (> 0) bleiben unverändert.
async function seedCursorIfFresh(cursor) {
  if (Number(cursor) > 0) return cursor;
  const led = await rpc("ledger", { ledger_index: "validated" });
  const seed = seedCursor(Number(led?.ledger_index), lookbackBlocks());
  return seed != null ? seed : cursor;
}

// (iv.5) History-Regel-Mapping (Kritik-Runde 4, Befund 1+2): rules[]
// etikettiert die EVIDENZ DES CLUSTERS SELBST — es wird keine Regel-ID
// erfunden.
//  - mainDrainers -> drainer-sweep, peelingChains -> peeling-chain
//    (strukturelle Evidenz, unverändert),
//  - motifs.washCycles -> 'wash-cycle' (echte Katalog-ID, lib/detector.mjs
//    :109): der Wash-Zyklus ist hasFraudEvidence-Träger
//    (lib/flow-state.mjs:256, 30-Tage-maliziös-Retention + Archiv) und
//    erhält damit seine Kappungs-Priorität — HISTORY_FRAUD_RULES
//    (lib/history.mjs:116) wächst um genau diese eine ehrliche ID; die
//    drei Tx-Ebenen-Market-Regeln bleiben bewusst draußen (sie sind keine
//    hasFraudEvidence-Träger, lib/detector.mjs:114-117),
//  - severity 'malicious' -> known-bad-hit (einzige registry-abgeleitete
//    Fundquelle im Advance-Pfad, :210-212-Kommentar mergeCluster),
//  - severity 'suspect' -> KEINE Regel-ID: die Ursprungsregel
//    (amm-wash-swap/thin-pool-exploit/spoof-offer-cycle/payment-burst/
//    airdrop-trustset-spam ...) ist im persistierten Cluster nicht
//    hinterlegt; die „breiteste suspect-Fundquelle" zu benennen, schrieb
//    eine nachweislich falsche Regel-ID als dauerhafte
//    Evidenz-Etikettierung (Kritik-Runde 4, Befund 2),
//  - gar kein Evidenz-Etikett -> known-bad-hit-Fallback (collector-Rolle
//    o. Ä., unveränderter Kontext): er hält die Kappungs-Priorität, die
//    solche Cluster vor der Severity-Mapping bereits hatten — die Zuordnung,
//    wer die 200er-Kappung überlebt, verschiebt sich nicht
//    (Kritik-Runde 4, Befund 1).
export function historyRulesFromCluster(c, baitLabels) {
  const rules = new Set();
  if (!c || typeof c !== "object") return rules;
  for (const d of Array.isArray(c.mainDrainers) ? c.mainDrainers : []) rules.add("drainer-sweep");
  for (const ch of Array.isArray(c.peelingChains) ? c.peelingChains : []) {
    if (Array.isArray(ch?.addresses) && ch.addresses.length) rules.add("peeling-chain");
  }
  const motifs = c.motifs && typeof c.motifs === "object" && !Array.isArray(c.motifs) ? c.motifs : null;
  if (motifs && Array.isArray(motifs.washCycles) && motifs.washCycles.length) rules.add("wash-cycle");
  const sevByAddr =
    c.severityByAddress && typeof c.severityByAddress === "object" && !Array.isArray(c.severityByAddress)
      ? c.severityByAddress
      : {};
  for (const [addr, sev] of Object.entries(sevByAddr)) {
    if (typeof addr !== "string" || !XRPL_ADDR_RE.test(addr) || baitLabels.has(addr)) continue;
    if (sev === "malicious") rules.add("known-bad-hit");
  }
  if (!rules.size) rules.add("known-bad-hit"); // collector-Rolle o. Ä.
  return rules;
}

export default async function handler(req, res) {
  res.setHeader("Cache-Control", "no-store");
  if (!hasPersistence()) {
    return res.status(503).json({ error: "Advance-Persistenz derzeit nicht verfügbar." });
  }
  // Replay-Auslöser (Kritik 10): die drei Cron-Workflows POSTen ohne Body
  // (advance-cron.yml/-b/-c, concurrency-group advance-tick) — ein ENV-Modus
  // würde den Live-Cursor stillstellen. Replay ist daher ein POST-Auslöser:
  // {mode:'replay', address, from, to} schreibt einen Job in
  // data/replay-jobs.json und löst den normalen Tick aus (Job wird in
  // (viii) mit persistiertem Marker abgearbeitet). Ohne Body bleibt der
  // Live-Walk unverändert.
  if (req?.body?.mode === "replay" && typeof req.body.address === "string") {
    const address = req.body.address;
    if (!XRPL_ADDR_RE.test(address) || baitLabels.has(address)) {
      return res.status(400).json({ error: "Ungültige Replay-Adresse." });
    }
    const fromLedger = Number(req.body.from);
    const toLedger = Number(req.body.to);
    if (!Number.isFinite(fromLedger) || !Number.isFinite(toLedger) || fromLedger > toLedger) {
      return res.status(400).json({ error: "Ungültiges Replay-Fenster (from/to)." });
    }
    try {
      const fresh = await readGitHubContents(REPLAY_JOBS_FILE_PATH, replayJobsCodec);
      await writeGitHubContents(
        (cur) => mergeReplayJob(cur ?? { jobs: [] }, { address, fromLedger, toLedger }, Date.now()),
        REPLAY_JOBS_FILE_PATH,
        replayJobsCodec
      );
    } catch (err) {
      const status = err?.status === 429 ? 503 : 502;
      return res.status(status).json({ error: "Replay-Job nicht persistierbar." });
    }
    // Der Job wird im Tick abgearbeitet: weiter zum normalen Advance.
  }
  const now = Date.now();
  const budget = budgetOf();
  tickDeadline = clockImpl() + MAX_DURATION_MS - GUARD_MARGIN_MS;
  try {
    // (i) persistierten Cursor + Flow-State lesen (readFlowStateGitHub liefert
    // {doc, sha} — hier wird das Dokument dekonstruiert, nicht der Wrapper).
    const { doc, sha } = await readFlowStateGitHub();
    // (i.1) Seed-Guard (Wisch-Zyklus-Sperre, VOR buildCtx und VOR
    // seedCursorIfFresh — auf dem Guard-Pfad läuft kein RPC): cursor <= 0 mit
    // Fortschritt (Cluster oder blocksProcessedTotal > 0) heißt "Cursor
    // verloren, Daten da" — Seeding würde den Bestand auf Live-Edge-Kursor
    // überschreiben und die Cluster im nächsten Pruning still vernichten.
    // Seeden erlaubt: cursor <= 0 ohne jeglichen Fortschritt (legaler
    // Init-Fall — der 404-Anlege-Fall sha===null wird von readFlowStateGitHub
    // zum fortschrittslosen Leerdokument normalisiert, und eine 0-Byte-Datei
    // ist am Handler von einem cursor-0-Leerdokument nicht unterscheidbar;
    // beides ist datensicher zu seeden, nichts kann verloren gehen).
    // Gesperrt: cursor <= 0 MIT Fortschritt — auch gegen einen hypothetischen
    // sha-losen Bestand mit Daten (die Sperre ist die sichere Kante der
    // Plan-Regel). Antwort 502 (NICHT 503): die Cron-Workflows akzeptieren
    // nur 200/503 als grün (advance-cron.yml:41, -b:30, -c:30) — ein
    // dauerhafter Guard-Fall macht jeden Run sichtbar rot.
    const hasProgress =
      Object.keys(doc.state?.clusters ?? {}).length > 0 || Number(doc.state?.blocksProcessedTotal) > 0;
    if (Number(doc.cursor) <= 0 && hasProgress) {
      return res.status(502).json({ error: "Flow-State-Bestand ohne Cursor — Seeding verweigert." });
    }
    // (i.2) Entity-Tabelle lesen (Grenze 3): Snapshots + Join-Keys für die
    // Union im Walk und das x-Feld im Block-Fenster. Read-Fehler ist optional
    // — der Tick läuft ohne Entity-Layer weiter (fail-open für diesen Layer,
    // fail-closed bleibt die Persistenz selbst).
    let entityDoc = null;
    try {
      entityDoc = (await readEntityGitHub()).doc;
    } catch {
      /* Entity-Layer optional */
    }
    const entityAddresses = new Set(Object.keys(entityDoc?.addresses ?? {}));
    // (ii) Engine-Kontext EINMAL pro Tick (siehe buildCtx-Kommentar):
    // firstSeenAt/history werden aus dem persistierten Flow-State geseedet,
    // verifiedFresh aus der Entity-Tabelle (ii.2) abgeleitet.
    const ctx = await buildCtx(doc, entityDoc);
    // (ii.5) Cursor-Seeding: ein frischer/leerer Cursor startet am Live-Edge
    // (minus Lookback), nicht bei Genesis — sonst würde der Walk nie vorrücken.
    const cursor = await seedCursorIfFresh(doc.cursor);
    // (iii) Advance über das ENV-Budget; Fetcher mit Parallelität
    // FETCH_PARALLEL (4/0,7 s ≈ 5,7 req/s < 10/s steady, pro Request durch
    // den Rate-Gate gekappt). Der Wrapper sammelt die Block-Fenster-Zeilen
    // pro UTC-Tag (Persistenz-Schicht des Block-Fensters) und die Entity-
    // Signale (x-Feld: SetRegularKey/AccountSet überleben so das Pruning).
    const windowByDay = new Map(); // day -> records[]
    const entitySignals = [];
    // Ursache des Walk-Endes (Netzwerk-/RPC-Fehler statt Live-Edge) — für
    // die Summary sichtbar (neutraler Text, nie Token; Muster
    // lib/history.mjs:12).
    let walkError = null;
    // Exchange-Registry für die Severity-Pfade (flaggedEdgesFrom, :685) — die
    // REINE 81-Einträge-Registry, unverändert. Für die Tag-Kantenattribute
    // (toTag in den Block-Fenster-Edges, toTag/transit im akkumulierten
    // Flow-State, :714) läuft zusätzlich die Multi-User-Union (Registry ∪
    // verifizierte well-known-Namen, lib/threats-service.mjs getMultiUser-
    // AccountsMap) — Coverage-Fix 2026-10-05: Kanten zu z. B. rNxp4…
    // (Binance, well-known-verifiziert, nicht in der 81er-Registry) bekommen
    // jetzt ein toTag. Fail-open: Fetch-/Parse-Fehler -> Union = Registry
    // (Verhalten wie vor der Erweiterung).
    const registryMap = getExchangeRegistryMap();
    const multiUserMap = await getMultiUserAccountsMap();
    const advanceResult = await advance({
      cursor,
      budget,
      now,
      fetcher: async (idx) => {
        // Deadline-aware Walk-Ende: der Walk endet bei tickDeadline minus
        // PERSIST_MARGIN_MS, damit die letzte Parallel-Runde (Latenz bis
        // ~1,79 s, live gemessen) plus die Persistenz-Phase (15-20
        // GitHub-Contents-Calls, live ~5-8 s) innerhalb maxDuration 30 s
        // durchkommen — sonst killt Vercel die Function ohne Persistenz
        // (advance() persistiert Partial, ledger-walk.mjs:66-91).
        if (clockImpl() >= tickDeadline - PERSIST_MARGIN_MS) return null;
        let block;
        try {
          block = await fetchBlock(idx, ctx);
        } catch (err) {
          // Netzwerk-/RPC-Fehler im Walk: bisher von advance() als Ende
          // verschluckt (ledger-walk.mjs:74-75) — live 3/12 Ticks +0 ohne
          // Fehlerfeld. Hier: Ursache erfassen, null wie bisher (Walk-Ende,
          // Partial-Persist), aber sichtbar in der Summary.
          walkError = String(err?.message ?? err).slice(0, 200);
          return null;
        }
        if (block) {
          const tMs = Date.parse(String(block.closeIso ?? ""));
          const day = dayOf(Number.isFinite(tMs) ? tMs : now) ?? dayOf(now);
          const flagged = flaggedEdgesFrom(
            block.transactions.map((e) => txRecordFromEntry(e, block.closeIso)).filter(Boolean),
            block.findings,
            baitLabels,
            registryMap
          );
          // x nur für Adressen, die bereits in der Entity-Tabelle oder
          // geflaggt sind (Köder-Filter/sanitizeText im Codec).
          const allowed = new Set(entityAddresses);
          for (const f of block.findings) if (typeof f?.address === "string") allowed.add(f.address);
          const signals = entitySignalsFrom(block.transactions, allowed, baitLabels);
          const rec = blockRecord(
            {
              index: idx,
              closeTimeIso: block.closeIso,
              txCount: block.txCount ?? block.transactions.length,
              flagged,
              entity: signals,
            },
            baitLabels
          );
          if (rec) {
            if (!windowByDay.has(day)) windowByDay.set(day, []);
            windowByDay.get(day).push(rec);
          }
          for (const s of signals) entitySignals.push(s);
        }
        return block;
      },
      flowState: doc.state,
      opts: {
        parallel: FETCH_PARALLEL,
        entityLinks: entityDoc ? buildEntityLinks(entityDoc) : null,
        multiUserAccounts: multiUserMap,
      },
    });
    // (iii.3) Write-Pfad-Feldkappe (Akkumulations-Fix 2026-10-06,
    // lib/flow-state.mjs capClusterFields): Mega-Cluster mit >300 Mitgliedern
    // komprimieren memberAddresses/roles/severityByAddress auf die Top-N
    // (Severity-Rang, dann mainDrainers/collectors, dann Adresse asc;
    // distinctAccounts bleibt der wahre Stand). Ohne sie sprengt ein einziger
    // Mega-Cluster FLOW_STATE_MAX_BYTES, der effectiveClusterCap halbiert auf
    // 1, und pruneFlowState wirft in JEDEM Tick alle übrigen Cluster raus —
    // die persistierten Cluster 'verschwinden' (live: Bestand 12 -> 1).
    // Die Kappe ist der Migrationspfad des bestehenden Mega-Clusters: der
    // nächste Tick persistiert ihn komprimiert, der Cap stabilisiert sich
    // wieder nahe FLOW_STATE_MAX_CLUSTERS.
    // REIHENFOLGE (Pflicht, lib/flow-state.mjs Abschnitt 'Write-Pfad-
    // Feldkappe'): capClusterFields VOR effectiveClusterCap (der Cap muss die
    // komprimierte Größe messen) und VOR mergeFlowState; archiveFromFlowState
    // läuft auf dem UNGEKAPPTEN advanceResult.flowState — Archivzeilen
    // behalten volle memberAddresses.
    const capped = capClusterFields(advanceResult.flowState);
    // (iii.4) Effektiver Cluster-Cap EINMAL pro Tick (Byte-Cap
    // FLOW_STATE_MAX_BYTES, lib/flow-state.mjs): der Bestand darf die 1-MiB-
    // Contents-Grenze nicht wieder überschreiten (live: 1.125.252 B ->
    // content_len 0 -> Wisch-Zyklus). Gemessen wird der GEKAPPTA State
    // (iii.3) — die survivor-Menge ist cap-unabhängig identisch, pruneFlowState
    // sortiert nach Schwere/Volumen, nicht nach Mitgliederzahl. DERSSELBE Cap
    // füttert archiveFromFlowState UND mergeFlowState (Archiv-Kopplung: was
    // der Cap aus dem Bestand wirft, wird im selben Tick archiviert —
    // Betrugsevidenz bleibt im data/flow-Archiv erhalten, lib/flow-state.mjs
    // archiveFromFlowState Kappungs-Zweig).
    const clusterCap = effectiveClusterCap(capped.state, now);
    // (iii.5) Archiv VOR mergeFlowState (Grenze 2): mergeFlowState pruned
    // intern — archiviert wird auf dem UNGEKAPPTEN advanceResult.flowState
    // (volle Mitglieder in den Archivzeilen), exakt nach dem
    // pruneFlowState-Prädikat (dasselbe Prädikat, keine Differenzrechnung
    // gegen finalDoc).
    const archiveDocs = archiveFromFlowState(advanceResult.flowState, now, { maxClusters: clusterCap }).map((d) => ({
      ...d,
      archivedAt: now,
    }));
    if (archiveDocs.length) {
      const day = archiveDayOf(now) ?? dayOf(now);
      if (day) {
        await writeArchiveGitHub(day, (fresh) =>
          capArchiveDoc(appendArchiveDoc({ ...fresh, updatedAt: now }, archiveDocs), ARCHIVE_MAX_BYTES)
        );
      }
    }
    // (iii.6) TAGES-CHECKPOINT (Persistenz-Fix 2026-10-06): einmal je UTC-Tag
    // werden ALLE Betrugsevidenz-Cluster des UNGEKAPPTEN advanceResult.flowState
    // als reason:'checkpoint'-Zeilen in den heutigen Tages-Chunk geschrieben —
    // das Archiv füllt sich kontinuierlich statt nur im Verlust-Fenster (seit
    // dem Akkumulations-Fix griff kein Archivierungs-Zweig mehr, live: null
    // Archiv-Writes seit 10-05). Kopplung wie (iii.5): der Write läuft im
    // Haupt-try VOR dem Flow-State-Write — sein Scheitern 502ert den Tick ohne
    // Flow-State-Persistenz, der nächste Tick holt nach (Guard idempotent).
    // Guard (Korrektur a): Marker reason:'checkpoint' im FRISCH GELESENEN
    // Tages-Dokument — nicht 'Datei existiert', denn der Kappungs-/Zeit-Zweig
    // (iii.5) legt die Tagesdatei auch ohne Checkpoint an. Der Außen-Read ist
    // nur die schnelle Vorprüfung; autoritativ prüft der Apply-Callback auf
    // dem frischen Stand (konkurrierende Ticks überleben den 409-Retry).
    // Köder-Filter (Korrektur c, Defense-in-Depth — der State ist upstream
    // bereits köderfrei, fetchBlock B2): Mitglieder explizit filtern, ein
    // köder-reiner Checkpoint wird verworfen. Tick-Deckel (Korrektur d): bei
    // < CHECKPOINT_DEADLINE_SLACK_MS Restlaufzeit wird geskippt (Nachhol im
    // nächsten Tick, maxDuration 30 bleibt gewahrt).
    const checkpointDay = archiveDayOf(now) ?? dayOf(now);
    let checkpointRows = 0;
    if (checkpointDay && clockImpl() < tickDeadline - CHECKPOINT_DEADLINE_SLACK_MS) {
      let alreadyCheckpointed = false;
      try {
        alreadyCheckpointed = hasCheckpointDoc((await readArchiveGitHub(checkpointDay)).doc);
      } catch {
        alreadyCheckpointed = false; // Read-Fehler: Entscheidung fällt der Apply-Guard
      }
      if (!alreadyCheckpointed) {
        const checkpointDocs = checkpointFromFlowState(advanceResult.flowState)
          .map((d) => ({ ...d, archivedAt: now }))
          .map((d) => ({
            ...d,
            memberAddresses: d.memberAddresses.filter((m) => XRPL_ADDR_RE.test(m) && !baitLabels.has(m)),
          }))
          .filter((d) => d.memberAddresses.length > 0);
        if (checkpointDocs.length) {
          await writeArchiveGitHub(checkpointDay, (fresh) => {
            if (hasCheckpointDoc(fresh)) return fresh; // Guard (a) im Apply
            // Bereits vorhandene Zeilen (Verlust-Archiv aus iii.5) nicht
            // durch Checkpoint-Sichten ersetzen — deren reason darf nie auf
            // 'checkpoint' kippen (Eviction-Priorität von capArchiveDoc).
            const existing = new Set(
              (Array.isArray(fresh?.docs) ? fresh.docs : []).map((d) => d?.clusterId)
            );
            const add = checkpointDocs.filter((d) => !existing.has(d.clusterId));
            if (!add.length) return fresh;
            checkpointRows = add.length;
            return capArchiveDoc(appendArchiveDoc({ ...fresh, updatedAt: now }, add), ARCHIVE_MAX_BYTES);
          });
        }
      }
    }
    // (iv) Persistenz des Flow-State-Ergebnisses (Merge ausschließlich im
    // apply; Pruning läuft in mergeFlowState — lib/flow-state.mjs) — mit
    // demselben Cap wie das Archiv (iii.4) und dem GEKAPPTEN State (iii.3):
    // das persistierte Dokument bleibt unter FLOW_STATE_MAX_BYTES, ohne dass
    // die Archivzeilen (iii.5, ungekappt) Mitglieder verlieren.
    const finalDoc = await writeFlowStateGitHub((fresh) =>
      mergeFlowState(fresh, { ...advanceResult, flowState: capped.state }, now, { maxClusters: clusterCap })
    );
    // (iv.5) Live-Cluster in die öffentliche Maliziös-Historie (data/
    // history.json): bisher war Live-Evidenz dort nie suchbar (?q=) —
    // history.json wurde nur durch POST /api/history und den Unit-B-Append
    // gefüllt. Betrugsevidenz-Cluster des finalDoc (hasFraudEvidence,
    // lib/flow-state.mjs:267) werden über denselben Merge-/Save-Pfad
    // geschrieben (members bait-gefiltert im mergeHistory-Codec, rules aus
    // den Fundtypen der Cluster-Funde, firstSeen/lastSeen aus dem Cluster).
    // Fail-open: ein History-Write-Fehler kippt den Tick nicht (der
    // Flow-State ist bereits persistiert); ohne Token fail-closed wie oben.
    {
      const fraudClusters = [];
      for (const c of Object.values(finalDoc?.state?.clusters ?? {})) {
        if (!c || typeof c !== "object") continue;
        if (!hasFraudEvidence(c)) continue;
        const members = (Array.isArray(c.memberAddresses) ? c.memberAddresses : [])
          .filter((m) => typeof m === "string" && XRPL_ADDR_RE.test(m) && !baitLabels.has(m));
        if (!members.length) continue;
        // Fundtypen aus der Cluster-Evidenz selbst (exportierter Helper,
        // Kritik-Runde 4 Befund 1+2): suspect-Schwere erhält KEINE erfundene
        // Regel-ID mehr; wash-cycle-Cluster tragen ihre echte Katalog-ID und
        // überleben die Kappung wie vor der Mapping; collector-only-Cluster
        // bleiben beim known-bad-hit-Fallback (unveränderte Kappungsfolge).
        const rules = historyRulesFromCluster(c, baitLabels);
        const fsMs = Date.parse(String(c.firstSeen ?? ""));
        const lsMs = Date.parse(String(c.lastSeen ?? ""));
        fraudClusters.push({
          members,
          label: typeof c.id === "string" && c.id ? c.id.slice(0, 200) : "Live-Cluster",
          totalDrops: Number(c.totalDrops) || 0,
          txCount: Number(c.txCount) || 0,
          firstSeen: Number.isFinite(fsMs) ? fsMs : 0,
          lastSeen: Number.isFinite(lsMs) ? lsMs : 0,
          rules: [...rules],
          severity: "malicious",
          sightings: 1,
          lastReportedAt: now,
        });
      }
      let historyHasNewKeys = false;
      if (fraudClusters.length) {
        try {
          const known = new Set((await readHistoryGitHub()).list.map((c) => c?.key).filter(Boolean));
          historyHasNewKeys = fraudClusters.some((c) => !known.has(historyKey(c.members)));
        } catch {
          historyHasNewKeys = false;
        }
      }
      // Batching: neue Cluster werden höchstens einmal je HISTORY_BATCH_MS committet. Zurückgestellte
      // Cluster bleiben im Flow-State (30 Tage Fraud-Retention) und kommen im nächsten Fenster.
      let historyDue = false;
      if (historyHasNewKeys) {
        try {
          historyDue = now - (await historyLastWriteMs(HISTORY_FILE_PATH_ADV)) >= HISTORY_BATCH_MS;
        } catch {
          historyDue = false;
        }
      }
      if (historyDue) {
        try {
          await writeHistoryGitHub((fresh) =>
            pruneHistoryByAge(mergeHistory(fresh, fraudClusters, now, baitLabels).list, now).list
          );
        } catch {
          /* Best-effort: History-Write-Fehler kippt den Tick nicht */
        }
      }
    }
    // (v) Block-Fenster-Tages-Chunks anhängen (Index-Dedup im Codec macht
    // Retry-Ticks idempotent). Fix 2026-10-04: nur Zeilen mit Index <=
    // advanceResult.newCursor — die Parallel-Runde bricht am null
    // (lib/ledger-walk.mjs:80-90), der Fetcher aber hatte Zeilen für Blöcke
    // NACH der Lücke bereits gesammelt (live: Fensterzeile 107403037 gegen
    // Cursor 107403034). rec.i trägt den Index (lib/block-window.mjs:253-257),
    // appendBlockWindow dedupt nach rec.i (lib/block-window.mjs:288-302) —
    // ein Nachhol-Tick schreibt die gefilterten Zeilen idempotent nach.
    const windowKept = new Map();
    for (const [day, records] of windowByDay) {
      const kept = records.filter((r) => r.i <= advanceResult.newCursor);
      if (!kept.length) continue;
      windowKept.set(day, kept);
      // Byte-Cap im Live-Write-Apply (NICHT in appendBlockWindow — der
      // Restore-Pfad und die Append-Tests laufen bewusst ungekappt):
      // 2026-10-03.json wuchs auf 1.205.513 B, 2026-10-04.json wurde real
      // gewischt (ae6c6492 1.163.338 B -> c36d0b24 295.237 B).
      await writeBlockWindowGitHub(day, (fresh) =>
        capBlockWindow(appendBlockWindow({ ...fresh, updatedAt: now }, kept), BLOCK_WINDOW_MAX_BYTES)
      );
    }
    // (vi) Retention: der Tag, der seit dem letzten Tick neu aus dem 7-Tage-
    // Fenster gefallen ist (8 Tage zurück), wird gelöscht — deleteGitHubFile
    // ist 404-sicher (1 GET + ggf. 1 DELETE pro Tick). Ältere Reste holt der
    // Nachholpfad (max. 3 Löschungen), wenn Ticks ausgefallen waren; die
    // Lese-Route liest ohnehin nur Tage im angefragten Fenster.
    const staleDay = dayOf(now - 8 * 24 * 60 * 60 * 1000);
    if (staleDay) {
      await deleteBlockWindowGitHub(staleDay);
      const { staleDays } = pruneBlockWindowDocs(
        await Promise.all(
          [7, 8, 9].map((back) => {
            const d = dayOf(now - back * 24 * 60 * 60 * 1000);
            return readBlockWindowGitHub(d).then(({ doc: dd }) => ({ day: d, doc: dd }));
          })
        ),
        now
      );
      for (const d of staleDays) {
        if (d !== staleDay) await deleteBlockWindowGitHub(d);
      }
    }
    // (vi.5) Archiv-Retention (Kritik 6): eigene Retention 30 d (malicious)
    // / 180 d (registry-verknüpft), Tageslöschung exakt im Muster der Block-
    // Fenster-Löschung oben (deleteGitHubFile ist 404-sicher). Gelesen werden
    // die Retentionsgrenzen selbst (30/180 Tage zurück) plus ein Tag
    // Nachholpuffer — Archiv-Tage dazwischen sind per Definition noch nicht
    // veraltet und brauchen keinen Read. GitHub-Reads, kein honeycluster-
    // Request (Budget-Ausnahme, dokumentiert).
    {
      const archiveDays = [];
      for (const back of [
        0, 1, 2,
        Math.ceil(ARCHIVE_RETENTION_MALICIOUS_MS / (24 * 60 * 60 * 1000)),
        Math.ceil(ARCHIVE_RETENTION_MALICIOUS_MS / (24 * 60 * 60 * 1000)) + 1,
        Math.ceil(ARCHIVE_RETENTION_REGISTRY_MS / (24 * 60 * 60 * 1000)),
        Math.ceil(ARCHIVE_RETENTION_REGISTRY_MS / (24 * 60 * 60 * 1000)) + 1,
      ]) {
        const d = dayOf(now - back * 24 * 60 * 60 * 1000);
        if (d && !archiveDays.includes(d)) archiveDays.push(d);
      }
      const { staleDays: archiveStale } = pruneArchiveDocs(
        await Promise.all(
          archiveDays.map((d) => readArchiveGitHub(d).then(({ doc: dd }) => ({ day: d, doc: dd })))
        ),
        now
      );
      for (const d of archiveStale) await deleteArchiveGitHub(d);
    }
    // (vii) Entity-Layer (Grenze 3): account_info pro geflaggter Adresse,
    // parallel 4, Cap ENTITY_TICK_CAP, deadline-geprüft gegen tickDeadline
    // (Muster :215-217; nutzbare Zeit maxDuration 30 s − GUARD_MARGIN_MS
    // 5000; 100 Blöcke à ~0,7 s bei parallel 4 ≈ 17,5 s Rest). Requests
    // durch denselben rateGate (rpc()). Snapshot-TTL-Dedup: Adressen mit
    // frischem persistiertem Snapshot verbrauchen keinen Request.
    let entityRequests = 0;
    const fresh = new Map();
    {
      const flagged = new Set();
      for (const c of Object.values(advanceResult.flowState?.clusters ?? {})) {
        for (const m of Array.isArray(c?.memberAddresses) ? c.memberAddresses : []) {
          if (typeof m === "string" && XRPL_ADDR_RE.test(m) && !baitLabels.has(m)) flagged.add(m);
        }
      }
      const targets = [...flagged].sort((x, y) => (x < y ? -1 : x > y ? 1 : 0)).slice(0, ENTITY_TICK_CAP);
      if (targets.length && clockImpl() < tickDeadline - PERSIST_MARGIN_MS) {
        const queue = [...targets];
        const results = await Promise.all(
          Array.from({ length: Math.min(4, queue.length) }, async () => {
            const out = [];
            while (queue.length) {
              if (clockImpl() >= tickDeadline - PERSIST_MARGIN_MS) break; // Deadline: Partial persistieren
              const batch = queue.splice(0, 4);
              const { snapshots, requests } = await fetchEntitySnapshots(rpc, batch, {
                cap: ENTITY_TICK_CAP,
                existing: entityDoc ?? undefined,
                baitLabels,
                now,
              });
              entityRequests += requests;
              for (const [addr, snap] of snapshots) out.push([addr, snap]);
            }
            return out;
          })
        );
        for (const list of results) for (const [addr, snap] of list) fresh.set(addr, snap);
      }
    }
    // Entity-Layer (Nachprüfung: die tick-gesammelten x-Signale
    // (entitySignals, :607/:641) waren bisher dead code — die in
    // lib/block-window.mjs:47 dokumentierte Übernahme 'x überlebt
    // Pruning via Entity-Tabelle' war nie implementiert; die Tabelle
    // wurde nur aus account_info-Snapshots geschrieben). Jetzt werden
    // die aus SetRegularKey/AccountSet abgeleiteten Signale in die
    // Entity-Tabelle übernommen: regularKey-Signale ergänzen das
    // Join-Key-Feld regularKey (rk: wird in entityJoinKeys wirksam),
    // domain-Signale das Anzeige-Metadatum domain (ohne domainVerified
    // — nie Join-Key, lib/entity-resolve.mjs:220). Werte sind bereits
    // codec-gefiltert (blockRecord x: base58-geprüft, sanitizeText,
    // Köder-Filter). Snapshot-lose Adressen erhalten einen minimalen
    // Eintrag; bestehende account_info-Felder werden nicht überschrieben.
    // Der Signal-Write liegt bewusst AUSSERHALB des targets/Deadline-Gates:
    // Signale für bereits tabellierte Adressen dürfen nicht davon abhängen,
    // ob in diesem Tick account_info-Targets übrig sind (GitHub-Write, kein
    // RPC — Deadline-Gate gilt nur für die Request-Schleife).
    const signalByAddr = new Map();
    for (const s of entitySignals) {
      if (!s || typeof s.a !== "string" || !XRPL_ADDR_RE.test(s.a)) continue;
      if (baitLabels.has(s.a) || baitLabels.has(s.v)) continue; // STILL
      const entry = signalByAddr.get(s.a) ?? {};
      if (s.k === "regularKey" && XRPL_ADDR_RE.test(s.v)) entry.regularKey = s.v;
      else if (s.k === "domain" && typeof s.v === "string" && s.v) entry.domain = s.v;
      signalByAddr.set(s.a, entry);
    }
    if (fresh.size > 0 || signalByAddr.size > 0) {
      await writeEntityGitHub((cur) => {
        const addresses = { ...(cur.addresses ?? {}) };
        for (const [addr, snap] of fresh) addresses[addr] = snap;
        for (const [addr, sig] of signalByAddr) {
          const old = addresses[addr];
          if (old) {
            if (sig.regularKey && !old.regularKey) old.regularKey = sig.regularKey;
            if (sig.domain && !old.domain) old.domain = sig.domain;
          } else {
            addresses[addr] = {
              regularKey: sig.regularKey ?? null,
              domain: sig.domain ?? null,
              domainVerified: false,
              signers: [],
            };
          }
        }
        // Präventiver Byte-Cap (ENTITY_MAX_BYTES): Adressen über Cap nach
        // Snapshot-Alter raus (ältester snapshotAt zuerst) — dieselbe
        // >1-MiB-Contents-Lücke wie flow-state/block-window (live heute:
        // entity-links.json 16.926 B, trimmt also nichts Bestehendes).
        return capEntityDoc({ updatedAt: now, addresses }, ENTITY_MAX_BYTES);
      });
    }
    // (viii) Replay-Jobs (Kritik 10 + 6): POST-Auslöser schreiben Jobs nach
    // data/replay-jobs.json; der Tick arbeitet sie mit persistiertem Marker
    // ab (account_tx gegen honeycluster mit ledger_index_min/max — Datums-
    // filter wird auf diesem Server ignoriert, Recherche-Input), Cap
    // REPLAY_TICK_CAP Requests/Tick. Marker wird nach Erreichen von toLedger
    // entfernt.
    let replayProcessed = 0;
    {
      const jobsDoc = await readGitHubContents(REPLAY_JOBS_FILE_PATH, replayJobsCodec);
      const jobs = (jobsDoc.doc?.jobs ?? []).filter((j) => j.status !== "done");
      if (jobs.length) {
        let requests = 0;
        for (const job of jobs) {
          if (requests >= REPLAY_TICK_CAP || clockImpl() >= tickDeadline - PERSIST_MARGIN_MS) break;
          const toLedger = Number.isFinite(job.toLedger) ? job.toLedger : null;
          if (toLedger == null) continue;
          const fromLedger = Number.isFinite(job.fromLedger) ? job.fromLedger : 0;
          const maxLedger = Math.min(toLedger, fromLedger + 500); // Fenster pro Tick
          try {
            const res = await rpc("account_tx", {
              account: job.address,
              ledger_index_min: fromLedger,
              ledger_index_max: maxLedger,
              binary: false,
              forward: true,
              limit: 20,
            });
            requests += 1;
            const reached = maxLedger >= toLedger && !res?.marker;
            await writeGitHubContents(
              (cur) => {
                const base = normalizeReplayJobsDoc(cur);
                const list = base.jobs.map((j) => {
                  if (j.address !== job.address || j.fromLedger !== job.fromLedger || j.toLedger !== job.toLedger) return j;
                  if (reached) return { ...j, status: "done", marker: null, updatedAt: now };
                  return { ...j, marker: { ledger: maxLedger, seq: (j.marker?.seq ?? 0) + 1 }, updatedAt: now };
                });
                return { updatedAt: now, jobs: list };
              },
              REPLAY_JOBS_FILE_PATH,
              replayJobsCodec
            );
            replayProcessed += 1;
          } catch {
            /* Replay-Fehler: Job bleibt hängen (Marker unverändert), Tick läuft weiter */
          }
        }
      }
    }
    // Geflaggte Txs nur aus der tatsächlich geschriebenen Menge (windowKept,
    // Fix 2026-10-04 — konsistent zum gefilterten Fenster-Write oben).
    const flaggedTxTotal = [...windowKept.values()]
      .flat()
      .reduce((s, r) => s + (Array.isArray(r.f) ? r.f.length : 0), 0);
    return res.status(200).json({
      cursor: finalDoc.cursor,
      summary: `${advanceResult.summary}, geflaggte Txs: ${flaggedTxTotal}, Archiv-Zeilen: ${archiveDocs.length}, Checkpoint-Zeilen: ${checkpointRows}, Entity-Snapshots: ${entityRequests}, Replay-Jobs: ${replayProcessed}${walkError ? `, Fehler: ${walkError}` : ""}`,
    });
  } catch (err) {
    // Read-/Write-Fehler (409-Retry scheitert, 403/429, Netzwerk) -> kein
    // Erfolg ohne Persistenz. 429 des Upstream -> 503, alles andere 502.
    const status = err?.status === 429 ? 503 : 502;
    return res.status(status).json({ error: "Advance-Persistenz derzeit nicht verfügbar." });
  } finally {
    tickDeadline = null;
  }
}
