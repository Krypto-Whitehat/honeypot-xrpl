// scripts/calibrate-quota.mjs — Kalibrierungsfahrt gegen die Request-Raten
// von honeycluster.io (Umstellung 2026-10-02: das xrplcluster-Units-Modell
// (10.000 Units/60 s, 700/Command) ist durch das honeycluster-Request-Modell
// ersetzt: 10 req/s steady, Burst 50/5 s, 20 initial — Nutzer-Angabe; die
// Throttle-Semantik bei echtem Überschreiten ist UNVERIFIED).
//
// Zweck: MISST real, wie viele Requests pro Fenster durchgehen, bevor HTTP
// 429/tooBusy/slowDown kommt, und protokolliert das beobachtete Verhalten
// (Status, error_message, retry-after). Ergebnis als JSON auf stdout — erst
// danach dürfen TICK_REQUEST_BUDGET/ADVANCE_BUDGET über den konservativen
// Default hinaus erhöht werden (Ergebnis in den Kommentaren von
// api/advance.js verankern).
//
// AUFRUF:
//   node scripts/calibrate-quota.mjs ledger   (plain ledger-Kommandos)
//   node scripts/calibrate-quota.mjs tx       (tx-Kommandos, ein Real-Hash)
//
// Rein lesend: kein Dateizugriff, kein Write, kein Secret. Wall-Clock-Guard
// 120 s; maximal MAX_COMMANDS Kommandos pro Lauf (knapp über dem steady-
// Limit 10/60 s, damit das beobachtete Limit sichtbar wird — bewusst NICHT
// am Burst-Limit 50/5 s ziehen, um honeycluster nicht zu belasten).

// Import-Muster wie scripts/smoke-advance.mjs: die exportierten Request-
// Budget-Konstanten aus api/advance.js (Top-Level dort ist nur der try/
// catch-gefangene config-Read — kein Netzwerk beim Import).
import { REQUESTS_PER_SEC, TICK_REQUEST_BUDGET, DEFAULT_BUDGET } from "../api/advance.js";

const RPC_URL =
  process.env.RPC_URL ||
  (process.env.WSS_URL || "wss://honeycluster.io").replace(/^wss:/, "https:");

const MAX_COMMANDS = 16; // knapp über dem steady-Limit 10/60 s
const GUARD_MS = 120000;
const started = Date.now();

const method = String(process.argv[2] || "ledger").toLowerCase();
if (method !== "ledger" && method !== "tx") {
  console.error("Usage: node scripts/calibrate-quota.mjs [ledger|tx]");
  process.exit(2);
}

// Ein RPC-Versuch; gibt { ok, result } zurück (HTTP 429/5xx oder
// tooBusy/slowDown -> ok:false, throttled:true — 429-aware Kalibrierung).
async function attempt(body) {
  const res = await fetch(RPC_URL, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });
  if (res.status === 429 || res.status >= 500) {
    return {
      ok: false,
      throttled: true,
      error: `HTTP ${res.status}`,
      retryAfter: res.headers.get("retry-after") ?? null,
      message: null,
    };
  }
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

// Abgeleitete Obergrenze: wenn zu viele Requests ins 60-s-Fenster passten,
// liegt das echte Limit über dem steady-Wert 10/s; kam die Drossel früher,
// liegt es darunter (Obergrenze, nicht Messwert).
console.log(JSON.stringify({
  method,
  commandsSent: sent,
  throttled: throttle ? { error: throttle.error, message: throttle.message ?? null, retryAfter: throttle.retryAfter ?? null } : null,
  sampleTxType: sample,
  observed60sRequests: throttle?.throttled ? sent - 1 : sent,
  steadyLimitAssumed: REQUESTS_PER_SEC,
  tickRequestBudget: TICK_REQUEST_BUDGET,
  defaultBudget: DEFAULT_BUDGET,
  note: "observed60sRequests ist Obergrenze, nicht Messwert: mehr Requests durch -> echtes Limit über 10/s; frühe Drossel -> darunter. Throttle-Semantik (429 vs tooBusy) UNVERIFIED — beide werden in api/advance.js gleich behandelt.",
}, null, 2));
process.exit(0);
