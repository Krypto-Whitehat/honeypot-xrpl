// scripts/smoke-advance.mjs — Smoke-Test für den Cursor-Advance-Kern (lib/ledger-walk.mjs).
//
// Zweck: END-TO-END-Verifikation gegen den ÖFFENTLICHEN Validator (kein Secret,
// keine Persistenz, kein Write): echter JSON-RPC-HTTPS-Fetcher gegen
// honeycluster.io mit expand:true (Muster api/advance.js fetchBlock) und ein
// Advance-Tick mit budget=1 über genau EINEN echten Block — den zuletzt
// validierten Ledger.
//
// Start-Cursor = currentIndex - 1, damit budget=1 exakt den aktuellen Index
// verarbeitet (ein Vorwärtsschritt über realen Daten). Erfolgskriterium:
// newCursor === currentIndex UND der Block liefert volle Tx-Objekte mit
// gestempelter ledgerSeq/closeTime (Adapter-Verifikation). Ohne diesen
// Schritt wäre der Tick leer (Index+1 existiert noch nicht) und verifizierte
// nichts am Datenpfad.
//
// Ausgabe: {newCursor, ok:true, txs} bei echtem Vorwärtsschritt; sonst
// {newCursor, ok:false} + Exit(1). Rein lesend — kein Dateizugriff, kein Write.
//
// Ausführen: node scripts/smoke-advance.mjs

import { advance } from "../lib/ledger-walk.mjs";
import { txRecordFromEntry } from "../lib/cluster.mjs";

// Endpunkt wie api/advance.js (honeycluster, öffentlicher Validator, kein Secret).
const RPC_URL =
  process.env.RPC_URL ||
  (process.env.WSS_URL || "wss://honeycluster.io").replace(/^wss:/, "https:");

// 429-aware Backoff: identisches RPC-Muster wie api/advance.js rpc().
async function rpc(method, params, tries = 3) {
  for (let i = 0; i < tries; i++) {
    const res = await fetch(RPC_URL, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ method, params: [{ ...params }] }),
    });
    if (res.status === 429 || res.status >= 500) {
      await new Promise((r) => setTimeout(r, 1500 * (i + 1)));
      continue;
    }
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

// Adapter wie api/advance.js stampExpandEntry: expand-Einträge tragen kein
// meta/ledger_index/close_time_iso — Ledger-Ebenen-Werte werden gestempelt.
function stampExpandEntry(e, ledgerIndex, closeIso) {
  if (!e || typeof e !== "object") return e;
  if (e.meta == null && e.metaData != null) e.meta = e.metaData;
  if (e.ledger_index == null) e.ledger_index = ledgerIndex;
  if (e.close_time_iso == null && closeIso) e.close_time_iso = closeIso;
  return e;
}

// Echter Fetcher: ein Ledger-Block {transactions:[...]} oder null am Edge
// (Fetcher-Vertrag wie api/advance.js fetchBlock: expand:true, lgrNotFound
// -> null, Leerblock truthy).
async function fetchBlock(ledgerIndex) {
  let led;
  try {
    led = await rpc("ledger", { ledger_index: ledgerIndex, transactions: true, expand: true });
  } catch (err) {
    if (String(err?.message).includes("lgrNotFound")) return null;
    throw err;
  }
  const ledger = led?.ledger ?? {};
  const closeIso =
    ledger.close_time_iso ??
    (typeof ledger.close_time === "number"
      ? new Date((ledger.close_time + 946684800) * 1000).toISOString()
      : null);
  const raw = Array.isArray(ledger.transactions) ? ledger.transactions : [];
  const idx = Number(ledger.ledger_index ?? ledgerIndex);
  const entries = raw
    .map((e) => stampExpandEntry(e, idx, closeIso))
    .filter((e) => e && typeof e === "object" && (e.TransactionType || e.tx_json || e.tx));
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
let blockTxs = 0;
let stampedRecords = 0;
const result = await advance({
  cursor: currentIndex - 1,
  budget: 1,
  now: Date.now(),
  fetcher: async (idx) => {
    const block = await fetchBlock(idx);
    if (block) {
      blockTxs = block.transactions.length;
      // Adapter-Verifikation: jeder Eintrag muss als tx-Record mit
      // ledgerSeq UND closeTime aus dem Block herauskommen.
      for (const e of block.transactions) {
        const rec = txRecordFromEntry(e, null);
        if (rec && rec.ledgerSeq != null && rec.closeTime != null) stampedRecords++;
      }
    }
    return block;
  },
  flowState: {},
});

// Erfolg: Vorwärtsschritt + (falls der Block Txs hat) vollständig gestempelte
// Records — der Adapter-Vertrag ist Teil des Smoke-Kriteriums.
const ok =
  result.newCursor === currentIndex &&
  (blockTxs === 0 || stampedRecords === blockTxs);
console.log(JSON.stringify({ newCursor: result.newCursor, ok, txs: blockTxs, stampedRecords }));
process.exit(ok ? 0 : 1);
