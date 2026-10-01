// scripts/smoke-advance.mjs — Smoke-Test für den Cursor-Advance-Kern (lib/ledger-walk.mjs).
//
// Zweck: END-TO-END-Verifikation gegen den ÖFFENTLICHEN Validator (kein Secret,
// keine Persistenz, kein Write): echter JSON-RPC-HTTPS-Fetcher (Muster
// api/ledger.js:62-95 bzw. api/advance.js:73-79) und ein Advance-Tick mit
// budget=1 über genau EINEN echten Block — den zuletzt validierten Ledger.
//
// Start-Cursor = currentIndex - 1, damit budget=1 exakt den aktuellen Index
// verarbeitet (ein Vorwärtsschritt über realen Daten). Erfolgskriterium:
// newCursor === currentIndex. Ohne diesen Schritt wäre der Tick leer (Index+1
// existiert noch nicht) und verifizierte nichts am Datenpfad.
//
// Ausgabe: {newCursor, ok:true} bei echtem Vorwärtsschritt; sonst
// {newCursor, ok:false} + Exit(1). Rein lesend — kein Dateizugriff, kein Write.
//
// Ausführen: node scripts/smoke-advance.mjs

import { advance } from "../lib/ledger-walk.mjs";

// Endpunkt wie api/ledger.js:36 (öffentlicher Validator, kein Secret nötig).
const RPC_URL =
  process.env.RPC_URL ||
  (process.env.WSS_URL || "wss://xrplcluster.com").replace(/^wss:/, "https:");

const MAX_RESOLVE = 40; // Hash-Auflösungsbudget pro Block (wie api/ledger.js)
const PARALLEL = 8; // max. 8 parallele tx-Calls (verifiziertes Muster)

// slowDown-Backoff: identisches RPC-Muster wie api/ledger.js:62-79.
async function rpc(method, params, tries = 3) {
  for (let i = 0; i < tries; i++) {
    const res = await fetch(RPC_URL, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ method, params: [{ ...params }] }),
    });
    if (!res.ok) throw new Error(`RPC HTTP ${res.status}`);
    const data = await res.json();
    if (data?.result?.error === "slowDown" || data?.result?.error === "tooBusy") {
      await new Promise((r) => setTimeout(r, 1500 * (i + 1)));
      continue;
    }
    if (data?.result?.error) throw new Error(`RPC error: ${data.result.error}`);
    return data.result;
  }
  throw new Error("RPC error: slowDown");
}

// Hash-Strings -> volle tx-Objekte (Muster api/ledger.js:82-95).
async function resolveHashes(hashes) {
  const entries = [];
  const list = hashes.slice(0, MAX_RESOLVE);
  for (let i = 0; i < list.length; i += PARALLEL) {
    const chunk = list.slice(i, i + PARALLEL);
    const results = await Promise.all(
      chunk.map((h) => rpc("tx", { transaction: h }).catch(() => null))
    );
    for (const r of results) {
      if (r && (r.TransactionType || r.tx_json || r.tx)) entries.push(r);
    }
  }
  return entries;
}

// Echter Fetcher: ein Ledger-Block {transactions:[...]} oder null am Edge
// (Muster api/advance.js:73-79).
async function fetchBlock(ledgerIndex) {
  const led = await rpc("ledger", { ledger_index: ledgerIndex, transactions: true });
  const hashes = Array.isArray(led?.ledger?.transactions) ? led.ledger.transactions : [];
  if (hashes.length === 0) return null;
  const entries = await resolveHashes(hashes);
  return { transactions: entries };
}

// Aktueller Index: zuletzt validierter Ledger (Muster api/ledger.js:131).
const validated = await rpc("ledger", { ledger_index: "validated" });
const currentIndex = Number(validated?.ledger_index);
if (!Number.isFinite(currentIndex) || currentIndex < 2) {
  console.log(JSON.stringify({ newCursor: null, ok: false, reason: "kein validierter Index" }));
  process.exit(1);
}

// Ein Vorwärtsschritt über den zuletzt validierten Block (budget=1).
const result = await advance({
  cursor: currentIndex - 1,
  budget: 1,
  now: Date.now(),
  fetcher: fetchBlock,
  flowState: {},
});

const ok = result.newCursor === currentIndex;
console.log(JSON.stringify({ newCursor: result.newCursor, ok }));
process.exit(ok ? 0 : 1);
