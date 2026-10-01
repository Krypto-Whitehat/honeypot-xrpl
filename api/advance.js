// Vercel Function: POST /api/advance — Cursor-Advance-Tick (transport-agnostisch).
//
// Rückt den persistierten Ledger-Cursor um ein ENV-konfigurierbares Budget vor
// (lib/ledger-walk.mjs advance()), persistiert das Ergebnis als Flow-State-
// Dokument (lib/flow-state.mjs) und liefert neuen Cursor + Summary. Der
// Block-Fetcher ist die Transport-Naht: er injiziert pro Ledger-Index einen
// Block {transactions, findings} oder null am Live-Edge (RPC-Muster wie
// api/ledger.js). advance() selbst ist transport-agnostisch (Fetcher
// injizierbar) — hier wird nur die RPC-Implementierung der Naht angebunden.
//
// QUOTA (Befund 2026-10-01, live verifiziert gegen xrplcluster.com):
//   - JSON-RPC-Batches werden vom Endpunkt deterministisch abgelehnt
//     (JSON-Array: "invalidParams"/31 "batched requests are not supported";
//     NDJSON: "jsonInvalid"/31) — KEIN batched RPC, ein Command pro POST.
//   - Units-Quota pro IP (Infrastruktur-Ebene, NICHT rippled — rippled-Source
//     geprüft: kein Rate-Limiter): beobachtet "rate limit: units quota
//     (10000 per 60s)" (public/app.js:1148-1149) und "(500000 per 3600s)"
//     (lib/live-gate.mjs:7-22). Unit-Kosten pro Methode sind NICHT
//     dokumentiert — die Defaults unten sind konservativ abgeleitet aus dem
//     beobachteten Fenster und der clientseitigen Kalibrierung
//     (public/app.js:169: 14 ledger-Kommandos/60 s), pessimistisch auf jeden
//     Command angewendet. expand:true (die dokumentierte Quota-Hauptlast,
//     lib/live-gate.mjs:199) wird hier nicht verwendet.
//   - Budget-Default = maxBudgetForQuota(MAX_RESOLVE) (reine Funktion,
//     getestet in lib/advance-batch.test.mjs); ADVANCE_BUDGET überschreibt.
//   - tx-Auflösung sequenziell (kein Burst) und MAX_RESOLVE reduziert.
//   - Findings pro Block via analyzeLedger (lib/detector.mjs) mit tick-
//     globalem ctx (buildCtx, Muster api/ledger.js:102-118); ein kalter
//     Threats-Cache ist ein zusätzlicher, vom Tick-Deadline-Guard begrenzter
//     Kostenposten (gleicher Kostenprofil wie der Snapshot-Pfad).
//
// SICHERHEIT:
//   - FAIL-CLOSED ohne Token: ohne GITHUB_HISTORY_TOKEN wird weder gelesen
//     noch vorgeschoben noch persistiert (503) — keine Cursor-Regression ohne
//     Persistenz-Berechtigung. Token NUR aus process.env, nie geloggt.
//   - Budget aus ENV ADVANCE_BUDGET (Default quota-konform klein) —
//     Serverless-Budget.
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
} from "../lib/flow-state.mjs";
import { analyzeLedger } from "../lib/detector.mjs";
import { getPublicThreats } from "../lib/threats-service.mjs";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, "..");

// Whitelists optional aus config.json (Muster api/ledger.js:30-35).
let config = { network: "mainnet", wss: "wss://xrplcluster.com" };
try {
  config = { ...config, ...JSON.parse(fs.readFileSync(path.join(ROOT, "config.json"), "utf8")) };
} catch {
  /* Default bleibt */
}

export const maxDuration = 30;

const RPC_URL =
  process.env.RPC_URL ||
  (process.env.WSS_URL || "wss://xrplcluster.com").replace(/^wss:/, "https:");

// ---------- Quota-Parameter (Befund 2026-10-01; siehe Header) ----------
// Beobachtetes 60-s-Units-Fenster (public/app.js:1148-1149).
const QUOTA_60S_UNITS = 10000;
// Command-Kosten-Obergrenze: clientseitige Kalibrierung public/app.js:169
// (14 ledger-Kommandos/60 s gegen das beobachtete Fenster) -> 10000/14 ≈ 714,
// abgerundet auf 700. Pessimistisch auf jeden Command angewendet — die
// tatsächlichen Unit-Kosten pro Methode sind nicht dokumentiert (Quota liegt
// auf Infrastruktur-Ebene, nicht in rippled).
export const COMMAND_COST_CEILING = 700;
// Geteilter-IP-Margin: ein Tick beansprucht höchstens die HÄLFTE des kleinsten
// Fensters — Browser-Client und andere Functions teilen das Egress-IP-Quota.
export const TICK_UNIT_BUDGET = QUOTA_60S_UNITS / 2;

// Hash-Auflösungsbudget pro Block: reduziert von 40 auf 6 (Quota). Die
// Findings-Aggregationsregeln brauchen mehrere Tx pro Block; 6 hält den
// Worst-Case-Tick (1 ledger + 6 tx = 7 Commands) innerhalb der Quota-Grenze.
export const MAX_RESOLVE = 6;

// Budget-Default: größtes Budget, dessen Worst-Case-Tick die Quota respektiert
// (reine Funktion, getestet in lib/advance-batch.test.mjs). ENV ADVANCE_BUDGET
// überschreibt explizit — ein Operator, der mehr headroom kennt, darf mehr.
export const DEFAULT_BUDGET = maxBudgetForQuota(MAX_RESOLVE);

// ---------- Backoff-Parameter (Muster lib/live-gate.mjs:110-137) ----------
const RETRY_SLACK_MS = 2000; // Guard-Slack über dem genannten Fenster
const BASE_BACKOFF_MS = 2000; // exponentieller Start (ohne genanntes Fenster)
const BACKOFF_CAP_MS = 30000; // exponentielle Kappe
const MAX_DURATION_MS = maxDuration * 1000;
const GUARD_MARGIN_MS = 5000; // Restlaufzeit für Persistenz-Write + Antwort

// Pure: genanntes Retry-Fenster (ms) aus einem RPC-Fehler-Result parsen.
// Präzedenz wie lib/live-gate.mjs:121-123: retry_after-Feld (Sekunden) vor
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
// exponentiell BASE*2^i mit Kappe (Muster lib/live-gate.mjs:134-135).
export function backoffDelayMs(attempt, statedMs) {
  if (statedMs != null && Number.isFinite(statedMs) && statedMs > 0) {
    return Math.floor(statedMs) + RETRY_SLACK_MS;
  }
  const i = Math.max(0, Math.floor(Number(attempt) || 0));
  return Math.min(BASE_BACKOFF_MS * 2 ** i, BACKOFF_CAP_MS);
}

// Pure: Worst-Case-Command-Anzahl eines Advance-Ticks (Budget × (1 ledger +
// maxResolve tx)). Garbage-Inputs -> 0.
export function worstCaseTickCommands(budget, maxResolve) {
  const b = Math.max(0, Math.floor(Number(budget) || 0));
  const m = Math.max(0, Math.floor(Number(maxResolve) || 0));
  return b * (1 + m);
}

// Pure: größtes Budget, dessen Worst-Case-Tick die Quota respektiert:
// Commands/Tick × Kosten-Obergrenze <= TICK_UNIT_BUDGET. opts überschreibt die
// Quota-Parameter (Tests).
export function maxBudgetForQuota(maxResolve, opts = {}) {
  const quotaUnits = Number.isFinite(opts?.quotaUnits) ? opts.quotaUnits : TICK_UNIT_BUDGET;
  const costCeiling = Number.isFinite(opts?.costCeiling) ? opts.costCeiling : COMMAND_COST_CEILING;
  const ceiling = Math.max(0, Math.floor(quotaUnits / costCeiling));
  const m = Math.max(0, Math.floor(Number(maxResolve) || 0));
  return Math.max(0, Math.floor(ceiling / (1 + m)));
}

// Tick-Deadline (Wall-Clock-Guard): gesetzt vom Handler, cleared in finally.
// rpc() wirft, wenn ein genanntes Quota-Fenster die Restlaufzeit übersteigt —
// statt die Function über maxDuration zu hämmern (Muster
// lib/live-gate.mjs:124-130). advance() behandelt einen Fetcher-Fehler als
// Ende des Walks und persistiert den Partial-Fortschritt (ledger-walk.mjs:40-44).
let tickDeadline = null;

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// slowDown/tooBusy-Backoff (verstärtes Muster lib/live-gate.mjs:110-137):
// genanntes Retry-Fenster (retry_after / "retry in ~Nms") wird voll ausgesetzt
// (+Slack); ohne genanntes Fenster exponentiell mit Kappe. Ein Fenster, das
// die Restlaufzeit übersteigt, wirft sofort (Fail-Fast -> Partial-Persist).
async function rpc(method, params, tries = 3) {
  let lastHint = null;
  for (let i = 0; i < tries; i++) {
    const res = await fetch(RPC_URL, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ method, params: [{ ...params }] }),
    });
    if (!res.ok) throw new Error(`RPC HTTP ${res.status}`);
    const data = await res.json();
    if (data?.result?.error === "slowDown" || data?.result?.error === "tooBusy") {
      const msg = String(data.result?.error_message || data.result.error);
      lastHint = msg;
      const delay = backoffDelayMs(i, parseRetryWindowMs(data.result));
      if (tickDeadline != null && Date.now() + delay > tickDeadline) {
        throw new Error(
          `RPC error: ${data.result.error} (${msg}) — Quota-Fenster übersteigt Restlaufzeit.`
        );
      }
      await sleep(delay);
      continue;
    }
    if (data?.result?.error) throw new Error(`RPC error: ${data.result.error}`);
    return data.result;
  }
  throw new Error(`RPC error: slowDown${lastHint ? ` (${lastHint})` : ""}`);
}

// Hash-Strings -> volle tx-Objekte (Muster api/ledger.js:82-95). SEQUENZIELL
// (kein Burst) gegen Burst-Throttling; MAX_RESOLVE begrenzt die Auflösung.
// txRecordFrom-Entry braucht volle tx-Objekte (TransactionType) — Hashes
// allein liefern null.
async function resolveHashes(hashes) {
  const entries = [];
  const list = hashes.slice(0, MAX_RESOLVE);
  for (const h of list) {
    const r = await rpc("tx", { transaction: h }).catch(() => null);
    if (r && (r.TransactionType || r.tx_json || r.tx)) entries.push(r);
  }
  return entries;
}

// ctx für die Engine: knownBad aus der Honeypot-Präzisionsschicht, Whitelists
// optional aus config.json (Muster api/ledger.js:102-118). firstSeenAt ist
// serverlos leer (kein Stream-Fenster) — Frische-Regeln feuern daher primär
// clientseitig; dokumentierte Grenze. buildCtx() läuft EINMAL pro Tick (nicht
// pro Block): ein kalter Threats-Cache (lib/threats-service.mjs, 60-s-TTL)
// würde sonst pro Block account_tx-Calls feuern — zusätzliche Quota-Last, die
// der Tick-Deadline-Guard begrenzt (dokumentierte Grenze, gleicher
// Kostenprofil wie der Snapshot-Pfad api/ledger.js).
const XRPL_ADDR_RE = /^r[1-9A-HJ-NP-Za-km-z]{24,34}$/;
async function buildCtx() {
  const knownBad = new Set();
  try {
    for (const t of await getPublicThreats()) {
      if (t?.address && XRPL_ADDR_RE.test(t.address)) knownBad.add(t.address);
    }
  } catch {
    /* Honeypot-Schicht optional */
  }
  return {
    knownBad,
    benignIssuers: new Set(config.benign_issuers || []),
    benignAccounts: new Set(config.benign_accounts || []),
    threats: new Map(),
    firstSeenAt: new Map(),
  };
}

// Transport-Naht: ein Ledger-Block {transactions, findings} oder null am
// Edge. Findings PRO BLOCK via analyzeLedger (lib/detector.mjs) mit dem
// tick-globalen ctx (Muster api/ledger.js:150).
async function fetchBlock(ledgerIndex, ctx) {
  const led = await rpc("ledger", { ledger_index: ledgerIndex, transactions: true });
  const hashes = Array.isArray(led?.ledger?.transactions) ? led.ledger.transactions : [];
  if (hashes.length === 0) return null;
  const entries = await resolveHashes(hashes);
  const result = analyzeLedger({ transactions: entries }, ctx);
  return { transactions: entries, findings: result.findings };
}

// Fail-closed: Advance/Persistenz erfordert den Token (nur aus ENV).
const hasPersistence = () => Boolean(process.env.GITHUB_HISTORY_TOKEN);

// ENV-konfigurierbares Budget (Default klein, Serverless-freundlich).
function budgetOf() {
  const n = Number(process.env.ADVANCE_BUDGET);
  return Number.isFinite(n) && n > 0 ? Math.floor(n) : DEFAULT_BUDGET;
}

export default async function handler(req, res) {
  res.setHeader("Cache-Control", "no-store");
  if (!hasPersistence()) {
    return res.status(503).json({ error: "Advance-Persistenz derzeit nicht verfügbar." });
  }
  const now = Date.now();
  const budget = budgetOf();
  tickDeadline = Date.now() + MAX_DURATION_MS - GUARD_MARGIN_MS;
  try {
    // (i) persistierten Cursor + Flow-State lesen (readFlowStateGitHub liefert
    // {doc, sha} — hier wird das Dokument dekonstruiert, nicht der Wrapper).
    const { doc } = await readFlowStateGitHub();
    // (ii) Engine-Kontext EINMAL pro Tick (siehe buildCtx-Kommentar).
    const ctx = await buildCtx();
    // (iii) transport-agnostisches Advance über das ENV-Budget.
    const advanceResult = await advance({
      cursor: doc.cursor,
      budget,
      now,
      fetcher: (idx) => fetchBlock(idx, ctx),
      flowState: doc.state,
    });
    // (iv) Persistenz des Ergebnisses (Merge ausschließlich im apply).
    const finalDoc = await writeFlowStateGitHub((fresh) =>
      mergeFlowState(fresh, advanceResult, now)
    );
    return res.status(200).json({
      cursor: finalDoc.cursor,
      summary: advanceResult.summary,
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
