// Vercel Function: GET /api/ledger — Live-Ledger-Snapshot + Detektor-Analyse.
//
// Datenpfad (honeycluster-Umstellung 2026-10-02): JSON-RPC per fetch POST auf
// https://honeycluster.io (config.json:3, offiziell gelisteter Mainnet-
// Server) mit {method:'ledger', params:[{ledger_index:'validated',
// transactions:true, expand:true}]}. expand:true liefert das vollständige
// Ledger-Objekt mit allen Tx-Objekten (hash + metaData) in GENAU EINEM
// Request — die Hash-Auflösung über separate tx-Kommandos (MAX_RESOLVE/
// strideHashes/PARALLEL, a.D. 7 Requests pro Snapshot) entfällt. Ohne
// expand:true liefert honeycluster nur Hash-Strings (live belegt 2026-10-02:
// 0 volle Objekte; mit expand: alle Objekte mit metaData.AffectedNodes).
// expand-Einträge tragen kein meta/ledger_index/close_time_iso — sie werden
// pro Entry gestempelt (Adapter wie api/advance.js), bevor dieselbe Engine
// analyzeLedger läuft wie im Browser (lib/detector.mjs — single source of
// truth). Der Hash-Strings-Fallback bleibt defensiv erhalten (andere
// Endpunkte ohne expand-Support).
//
// ANONYMITÄT: Jede öffentliche Antwort läuft durch lib/sanitize.mjs
// (sanitizeText auf notes); Köder-Adressen werden zu Labels, Funde auf Köder-
// Adressen werden herausgefiltert (kein Oracle). Keine Seeds, keine Köder-
// Literale. KEIN xrpl.js (ERR_REQUIRE_ESM auf Vercel, dokumentiert in
// lib/threats-service.mjs:31-36).
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { analyzeLedger } from "../lib/detector.mjs";
import { strideHashes } from "../lib/stride.mjs";
import { txRecordFromEntry } from "../lib/cluster.mjs";
import { getPublicThreats } from "../lib/threats-service.mjs";
import { sanitizeText } from "../lib/sanitize.mjs";
import { parseRetryAfterMs } from "../lib/rate-gate.mjs";

export const maxDuration = 30;

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, "..");

let config = { network: "mainnet", wss: "wss://honeycluster.io" };
try {
  config = { ...config, ...JSON.parse(fs.readFileSync(path.join(ROOT, "config.json"), "utf8")) };
} catch {
  /* Default bleibt */
}
const RPC_URL = process.env.RPC_URL || (process.env.WSS_URL || config.wss).replace(/^wss:/, "https:");

// Bait-Labels für die Anonymitätsschicht — Adressen nur aus ENV (Vercel),
// niemals Seeds. identisches Muster wie lib/threats-service.mjs:55-60.
const baitLabels = new Map();
(process.env.BAIT_ADDRESSES || "")
  .split(",")
  .map((a) => a.trim())
  .filter(Boolean)
  .forEach((addr, i) => baitLabels.set(addr, `HP-${i + 1}`));

const XRPL_ADDR_RE = /^r[1-9A-HJ-NP-Za-km-z]{24,34}$/;
// Hash-Auflösung nur noch im defensiven Fallback (Endpunkte ohne expand-
// Support). honeycluster-Snapshots laufen mit expand:true -> 1 Request.
const MAX_RESOLVE = 6; // Fallback-Kappe (strideHashes bleibt gleichmäßig)
const PARALLEL = 8; // max. 8 parallele tx-Calls im Fallback
const CACHE_MS = 60000; // 60-s-Cache wie threats-service
const ERROR_CACHE_MS = 5000; // kurzer Negativ-Cache: Wiederholte Anfragen im
                             // Fenster bedient der Fehler, statt erneut 3
                             // RPC-Versuche zu feuern — entlastet einen
                             // gedrosselten Endpunkt zusätzlich zum
                             // clientseitigen Poll-Backoff (Befund 2026-09-30).

let snapshotCache = null; // { time, body } — nur im Prozess-Speicher
let errorCache = null; // { time } — nur im Prozess-Speicher

// slowDown/tooBusy/429/5xx-Backoff (429-aware, B4): HTTP 429 und 5xx werden
// behandelt wie ein genanntes Quota-Fenster — retry-after-Header (Sekunden
// oder HTTP-Datum) wird ausgesetzt (Cap 30 s wie der alte lineare Backoff,
// damit der Snapshot innerhalb maxDuration bleibt); ohne Fenster exponentiell
// 1,5 s/3 s/4,5 s wie bisher. a.D. warf !res.ok sofort.
async function rpc(method, params, tries = 3) {
  for (let i = 0; i < tries; i++) {
    const res = await fetch(RPC_URL, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ method, params: [{ ...params }] }),
    });
    if (res.status === 429 || res.status >= 500) {
      const stated = parseRetryAfterMs(res.headers.get("retry-after"));
      const delay = stated != null ? Math.min(stated, 30000) : 1500 * (i + 1);
      await new Promise((r) => setTimeout(r, delay));
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

// Adapter: expand:true-Einträge tragen kein meta/ledger_index/close_time_iso
// (live belegt) — Stempeln der Ledger-Ebenen-Werte pro Entry (Muster
// api/advance.js stampExpandEntry).
function stampExpandEntry(e, ledgerIndex, closeIso) {
  if (!e || typeof e !== "object") return e;
  if (e.meta == null && e.metaData != null) e.meta = e.metaData;
  if (e.ledger_index == null) e.ledger_index = ledgerIndex;
  if (e.close_time_iso == null && closeIso) e.close_time_iso = closeIso;
  return e;
}

// Hash-Strings -> volle tx-Objekte (NUR Fallback für Endpunkte ohne expand-
// Support; tx liefert Felder + meta flach in result). strideHashes statt
// slice(0, MAX_RESOLVE): gleiche Budget-Kappe, gleichmäßige Stichprobe.
async function resolveHashes(hashes) {
  const entries = [];
  const list = strideHashes(hashes, MAX_RESOLVE);
  for (let i = 0; i < list.length; i += PARALLEL) {
    const chunk = list.slice(i, i + PARALLEL);
    const results = await Promise.all(
      chunk.map((h) => rpc("tx", { transaction: h }).catch(() => null))
    );
    for (const r of results) {
      if (r && (r.TransactionType || r.tx_json || r.tx)) entries.push(r);
    }
  }
  return { entries, unresolved: hashes.length - entries.length };
}

// ctx für die Engine: knownBad aus der Honeypot-Präzisionsschicht
// (getPublicThreats lässt Angreifer-Adressen öffentlich, Köder werden zu
// Labels — sanitize.mjs:68-72), Whitelists optional aus config.json.
// firstSeenAt ist serverlos leer (kein Stream-Fenster) — Frische-Regeln
// feuern daher primär clientseitig; dokumentierte Grenze.
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

export default async function handler(req, res) {
  try {
    if (snapshotCache && Date.now() - snapshotCache.time < CACHE_MS) {
      return res.status(200).json(snapshotCache.body);
    }
    // Negativ-Cache (Befund 2026-09-30): Erfolgscache hat Vorrang; danach
    // entscheidet der kurze Fehler-Cache (max. eine RPC-Runde pro Fenster).
    if (errorCache && Date.now() - errorCache.time < ERROR_CACHE_MS) {
      return res.status(502).json({ error: "Ledger-Abfrage fehlgeschlagen." });
    }

    // expand:true: GENAU EIN Request, alle Tx-Objekte (hash + metaData).
    const led = await rpc("ledger", {
      ledger_index: "validated",
      transactions: true,
      expand: true,
    });
    const rawTxs = led?.ledger?.transactions ?? [];
    const closeTime =
      led?.ledger?.close_time_iso ??
      (typeof led?.ledger?.close_time === "number"
        ? new Date((led.ledger.close_time + 946684800) * 1000).toISOString()
        : null);

    let findings;
    let ledgerTxCount = rawTxs.length;
    let resolvedTxCount = 0;
    let unresolvedTxCount = 0;
    let txSource = [];

    if (rawTxs.length > 0 && rawTxs.every((t) => typeof t === "string")) {
      // Fallback (Endpunkt ohne expand-Support): Hash-Auflösung per tx.
      const { entries, unresolved } = await resolveHashes(rawTxs);
      resolvedTxCount = entries.length;
      unresolvedTxCount = unresolved;
      txSource = entries;
      const result = analyzeLedger({ transactions: entries }, await buildCtx());
      findings = result.findings;
    } else {
      // expand:true-Pfad: volle Objekte, Adapter stempelt meta/ledger_index/
      // close_time_iso pro Entry; analyzeLedger akzeptiert die
      // {ledger:{transactions}}-Form direkt (extractTransactions).
      const ledgerIndex = Number(led?.ledger?.ledger_index ?? led?.ledger_index) || null;
      txSource = rawTxs.map((e) => stampExpandEntry(e, ledgerIndex, closeTime));
      const result = analyzeLedger(led, await buildCtx());
      findings = result.findings;
      resolvedTxCount = ledgerTxCount;
    }

    // txRecords für den Snapshot-Fallback des Client-Graphen (poll-Modus):
    // Köder-Endpunkte werden vor der Auslieferung gefiltert.
    const txRecords = txSource
      .map((e) => txRecordFromEntry(e, closeTime))
      .filter((r) => r && !baitLabels.has(r.account) && !(r.destination && baitLabels.has(r.destination)));

    const body = {
      ledgerIndex: led?.ledger_index ?? null,
      ledgerHash: led?.ledger_hash ?? null,
      closeTime,
      network: process.env.NETWORK || config.network,
      stats: { txs: ledgerTxCount, findings: findings.length },
      resolvedTxCount,
      unresolvedTxCount,
      txRecords,
      findings: findings
        .filter((f) => !baitLabels.has(f.address)) // kein Oracle für Köder-Adressen
        .map((f) => ({
          ruleId: f.ruleId,
          severity: f.severity,
          address: sanitizeText(f.address, baitLabels), // Defense-in-Depth: auch das Adressfeld läuft durch die Anonymitätsschicht
          note: sanitizeText(f.note, baitLabels),
        })),
    };
    snapshotCache = { time: Date.now(), body };
    errorCache = null; // Erfolg verdrängt einen etwaigen Fehler-Cache
    res.status(200).json(body);
  } catch {
    errorCache = { time: Date.now() };
    res.status(502).json({ error: "Ledger-Abfrage fehlgeschlagen." });
  }
}
