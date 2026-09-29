// Vercel Function: GET /api/ledger — Live-Ledger-Snapshot + Detektor-Analyse.
//
// Datenpfad (einziger verifizierter Serverpfad, da WSS-Ledger-Events in der
// Sandbox nicht beobachtbar waren): JSON-RPC per fetch POST auf
// https://xrplcluster.com mit {method:'ledger', params:[{transactions:true}]}.
// Die Hash-Strings liegen nachweislich in result.ledger.transactions (NICHT in
// result.transactions — per Live-Call verifiziert). Sie werden mit max. 8
// parallelen {method:'tx'}-Calls aufgelöst (tx liefert die vollen tx-Felder
// plus meta flach in result), bevor dieselbe Engine analyzeLedger läuft wie im
// Browser (lib/detector.mjs — single source of truth).
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
import { txRecordFromEntry } from "../lib/cluster.mjs";
import { getPublicThreats } from "../lib/threats-service.mjs";
import { sanitizeText } from "../lib/sanitize.mjs";

export const maxDuration = 30;

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, "..");

let config = { network: "mainnet", wss: "wss://xrplcluster.com" };
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
const MAX_RESOLVE = 40; // Hash-Auflösungsbudget pro Snapshot (Serverless-Budget)
const PARALLEL = 8; // max. 8 parallele tx-Calls (verifiziertes Muster)
const CACHE_MS = 60000; // 60-s-Cache wie threats-service

let snapshotCache = null; // { time, body } — nur im Prozess-Speicher

// slowDown-Backoff: xrplcluster (Clio) drosselt bei Häufung — live beobachtet
// 2026-09-28. Ein Retry-Fenster pro Call macht den Snapshot robust.
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

// Hash-Strings -> volle tx-Objekte (tx liefert Felder + meta flach in result).
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

    const led = await rpc("ledger", { ledger_index: "validated", transactions: true });
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
      const { entries, unresolved } = await resolveHashes(rawTxs);
      resolvedTxCount = entries.length;
      unresolvedTxCount = unresolved;
      txSource = entries;
      const result = analyzeLedger({ transactions: entries }, await buildCtx());
      findings = result.findings;
    } else {
      txSource = rawTxs;
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
    res.status(200).json(body);
  } catch {
    res.status(502).json({ error: "Ledger-Abfrage fehlgeschlagen." });
  }
}
