// scripts/calibrate-quota.mjs — Kalibrierungsfahrt gegen das Units-Quota von
// xrplcluster.com (Befund 2026-10-02: alle Budgets beruhen auf der für
// expand:true kalibrierten 700-Units-Obergrenze aus public/app.js:169 /
// api/advance.js:73-78; die realen Kosten von plain ledger-/tx-Kommandos sind
// UNVERIFIED).
//
// Zweck: MISST real, wie viele Kommandos einer Methode pro Fenster durchgehen,
// bevor tooBusy/slowDown kommt, und leitet daraus die tatsächliche Unit-Kosten-
// Obergrenze ab (Fenster-Units / gesendete Kommandos). Ergebnis als JSON auf
// stdout — erst danach dürfen ANALYZE_EVERY_N_BLOCKS / MAX_RESOLVE /
// QUOTA_CALLS_PER_MIN erhöht werden (Ergebnis in den Kommentaren von
// public/app.js und api/advance.js verankern).
//
// Beobachtete Fenster (live erhalten 2026-10-02): "units quota (10000 per 60s)"
// und "units quota (500000 per 3600s) exhausted, retry in ~91237ms". Das
// 3600-s-Fenster ist nicht aktiv ansteuerbar — es erscheint als tooBusy-
// error_message und wird hier protokolliert.
//
// AUFRUF:
//   node scripts/calibrate-quota.mjs ledger   (plain ledger-Kommandos)
//   node scripts/calibrate-quota.mjs tx       (tx-Kommandos, ein Real-Hash)
//
// Rein lesend: kein Dateizugriff, kein Write, kein Secret. Wall-Clock-Guard
// 120 s; maximal MAX_COMMANDS Kommandos pro Lauf (knapp über dem Client-
// Deckel 14, damit das beobachtete Limit sichtbar wird).

// Import-Muster wie scripts/smoke-advance.mjs: die exportierten Budget-
// Konstanten aus api/advance.js (Top-Level dort ist nur der try/catch-gefangene
// config-Read — kein Netzwerk beim Import).
import { COMMAND_COST_CEILING, MAX_RESOLVE, TICK_UNIT_BUDGET } from "../api/advance.js";

const RPC_URL =
  process.env.RPC_URL ||
  (process.env.WSS_URL || "wss://xrplcluster.com").replace(/^wss:/, "https:");

const MAX_COMMANDS = 16; // knapp über QUOTA_CALLS_PER_MIN=14
const GUARD_MS = 120000;
const started = Date.now();

const method = String(process.argv[2] || "ledger").toLowerCase();
if (method !== "ledger" && method !== "tx") {
  console.error("Usage: node scripts/calibrate-quota.mjs [ledger|tx]");
  process.exit(2);
}

// Ein RPC-Versuch; gibt { ok, result } zurück (tooBusy/slowDown -> ok:false).
async function attempt(body) {
  const res = await fetch(RPC_URL, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!res.ok) return { ok: false, error: `HTTP ${res.status}` };
  const data = await res.json().catch(() => null);
  const err = data?.result?.error;
  if (err === "tooBusy" || err === "slowDown") {
    return { ok: false, throttled: true, error: err, message: data?.result?.error_message ?? null };
  }
  if (err) return { ok: false, error: err };
  return { ok: true, result: data?.result };
}

// Realer Hash für den tx-Zweig: aus dem aktuell validierten Block.
async function realHash() {
  const led = await attempt({ method: "ledger", params: [{ ledger_index: "validated", transactions: true }] });
  const txs = led.ok ? led.result?.ledger?.transactions : null;
  return Array.isArray(txs) && txs.length && typeof txs[0] === "string" ? txs[0] : null;
}

let sent = 0;
let throttle = null;
let sample = null;

if (method === "tx") {
  const hash = await realHash();
  if (!hash) {
    console.log(JSON.stringify({ method, ok: false, reason: "kein Real-Hash verfügbar" }));
    process.exit(1);
  }
  for (let i = 0; i < MAX_COMMANDS; i++) {
    if (Date.now() - started > GUARD_MS) break;
    const r = await attempt({ method: "tx", params: [{ transaction: hash }] });
    sent++;
    if (!r.ok) { throttle = r; break; }
    if (!sample && r.result?.TransactionType) sample = r.result.TransactionType;
  }
} else {
  for (let i = 0; i < MAX_COMMANDS; i++) {
    if (Date.now() - started > GUARD_MS) break;
    const r = await attempt({ method: "ledger", params: [{ ledger_index: "validated" }] });
    sent++;
    if (!r.ok) { throttle = r; break; }
  }
}

// Abgeleitete Obergrenze: wenn zu viele Kommandos ins 60-s-Fenster passten,
// liegt die echte Kosten-Obergrenze unter dem kalibrierten Wert 700.
const windowUnits = 10000;
const observedCeiling = sent > 0 ? Math.floor(windowUnits / sent) : null;

console.log(JSON.stringify({
  method,
  commandsSent: sent,
  throttled: throttle ? { error: throttle.error, message: throttle.message } : null,
  sampleTxType: sample,
  observed60sCommands: throttle?.throttled ? sent - 1 : sent,
  derivedUnitsPerCommandUpperBound: observedCeiling,
  calibratedCeiling: COMMAND_COST_CEILING,
  tickUnitBudget: TICK_UNIT_BUDGET,
  maxResolveDefault: MAX_RESOLVE,
  note: "derived ist Obergrenze, nicht Messwert: zu viele Kommandos -> echte Kosten unter derived; zu wenige (Throttle früh) -> Kosten über derived. 3600-s-Fenster ggf. in message.",
}, null, 2));
process.exit(0);
