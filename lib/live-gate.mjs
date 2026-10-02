#!/usr/bin/env node
// lib/live-gate.mjs — Echt-Gate: 6 aufeinanderfolgende validierte Ledger von
// https://honeycluster.io (Standard; config.json:3) durch analyzeLedger
// (lib/detector.mjs) und buildClusterGraph (lib/cluster.mjs) — End-to-End-
// Validierung des Export-Vertrags gegen Live-Daten.
//
// UMSTELLUNG 2026-10-02 (honeycluster.io): Ledger-Calls laufen MIT
// expand:true — GENAU EIN Request pro Block, alle Tx-Objekte mit metaData
// (live belegt: ohne expand 0 volle Objekte, mit expand vollständige
// Objekte inkl. PreviousFields.Balance). Die Hash-Auflösung über tx-Calls
// (MAX_RESOLVE/PARALLEL, a.D. 40/8) entfällt; ein defensiver Hash-Fallback
// bleibt für Endpunkte ohne expand-Support. honeycluster-Raten: 10 req/s
// steady, Burst 50/5 s (Nutzer-Angabe; Throttle-Semantik bei echtem
// Überschreiten UNVERIFIED). Der rpc-Backoff ist 429-aware: HTTP 429/5xx
// werden behandelt wie slowDown/tooBusy (retry-after-Header oder
// error_message-Fenster, Guard-Slack 2 s, exponentielle Kappe 30 s ohne
// Fenster). Dieses Gate trotzdem NUR EINMAL pro Validierungslauf fahren:
// node lib/live-gate.mjs
//
// EHRLICH (Anti-Concealment): live-gate hat KEINE Unit-Tests (kein
// lib/live-gate.test.mjs) — die Änderungen an diesem Skript sind nur durch
// Live-Lauf/Smoke gedeckt, nicht durch Gate-Tests.
//
// MUSTER (per Read verifiziert): rpc-Backoff wie api/advance.js (429-aware,
// tries=5), analyzeLedger-Aufruf wie api/ledger.js, Entry-Normalisierung wie
// public/app.js:681-689 (expand:true liefert flache Tx-Felder + metaData),
// closeTime-Fallback wie api/ledger.js (Entries per expand:true tragen kein
// close_time — die Ledger-Ebenen-close_time_iso wird als fallbackCloseIso
// übergeben, Korrektur E). Bait-Filter wie api/ledger.js: ENV BAIT_ADDRESSES ∪
// address-Feld aus bait.json (NUR address, niemals seed); Funde durch
// lib/sanitize.mjs sanitizeText.
//
// Ausgabe: JSON { ledgers, txs, findings, clusters, sample } auf stdout.
// Exit 0 nur bei gültiger Struktur (6 Ledger, jede tx mit closeTime-ISO,
// alle Cluster-Vertragsfelder, Rollen in erlaubter Menge). Sonst Exit 1 +
// Fehlerliste auf stderr. Wall-Clock-Guard ~240 s.

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { analyzeLedger } from "./detector.mjs";
import { buildClusterGraph, txRecordFromEntry, isKnownRole } from "./cluster.mjs";
import { sanitizeText } from "./sanitize.mjs";
import { parseRetryAfterMs } from "./rate-gate.mjs";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, "..");

const GUARD_MS = 240000;
const START = Date.now();
const guardTimer = setTimeout(() => {
  console.error("live-gate: Wall-Clock-Guard (240 s) überschritten.");
  process.exit(1);
}, GUARD_MS);
guardTimer.unref();
const checkGuard = () => {
  if (Date.now() - START > GUARD_MS) throw new Error("Wall-Clock-Guard (240 s) überschritten.");
};
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

let config = { network: "mainnet", wss: "wss://honeycluster.io" };
try {
  config = { ...config, ...JSON.parse(fs.readFileSync(path.join(ROOT, "config.json"), "utf8")) };
} catch {
  /* Default bleibt */
}
const RPC_URL = process.env.RPC_URL || (process.env.WSS_URL || config.wss).replace(/^wss:/, "https:");

// ---------- Bait-Union: ENV BAIT_ADDRESSES ∪ bait.json (NUR address-Feld) ----------
const baitLabels = new Map();
(process.env.BAIT_ADDRESSES || "")
  .split(",")
  .map((a) => a.trim())
  .filter(Boolean)
  .forEach((addr, i) => baitLabels.set(addr, `HP-${i + 1}`));
try {
  const bait = JSON.parse(fs.readFileSync(path.join(ROOT, "bait.json"), "utf8"));
  for (const b of Array.isArray(bait) ? bait : []) {
    if (b?.address && !baitLabels.has(b.address)) {
      baitLabels.set(b.address, typeof b.label === "string" && b.label ? b.label : `HP-${baitLabels.size + 1}`);
    }
  }
} catch {
  /* bait.json optional (z. B. Vercel — dort per .vercelignore ausgeschlossen) */
}
// threats-service liest BAIT_ADDRESSES bei Modul-Load: vor dem Import setzen,
// damit buildCtx dieselbe Köder-Union sieht wie der lokale Server.
if (!process.env.BAIT_ADDRESSES && baitLabels.size > 0) {
  process.env.BAIT_ADDRESSES = [...baitLabels.keys()].join(",");
}
const { getPublicThreats } = await import("./threats-service.mjs");

// ---------- rpc-Backoff (429-aware, tries=5) ----------
// HTTP 429 und 5xx werden behandelt wie slowDown/tooBusy (B4): genanntes
// Fenster (retry-after-Header ODER retry_after-Feld ODER error_message
// "retry in ~Nms") wird voll ausgesetzt (Guard-Slack 2 s); übersteigt es die
// Rest-Guard-Zeit, Fehler mit Quota-Hinweis statt Gegenstelle-weiterhämmern.
// Ohne genanntes Fenster exponentiell 2 s -> 30 s Cap. a.D. warf !res.ok
// sofort.
async function rpc(method, params, tries = 5) {
  let delay = 2000;
  let lastHint = null;
  for (let i = 0; i < tries; i++) {
    checkGuard();
    const res = await fetch(RPC_URL, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ method, params: [{ ...params }] }),
    });
    if (res.status === 429 || res.status >= 500) {
      lastHint = `HTTP ${res.status}`;
      const stated = parseRetryAfterMs(res.headers.get("retry-after"));
      const remaining = GUARD_MS - (Date.now() - START);
      if (stated != null) {
        if (stated + 2000 > remaining) {
          throw new Error(
            `RPC HTTP ${res.status} — Quota-Fenster übersteigt Wall-Clock-Guard.`
          );
        }
        await sleep(stated + 2000);
        continue;
      }
      delay = Math.min(delay * 2, 30000);
      await sleep(delay);
      continue;
    }
    if (!res.ok) throw new Error(`RPC HTTP ${res.status}`);
    const data = await res.json();
    if (data?.result?.error === "slowDown" || data?.result?.error === "tooBusy") {
      // KORREKTUR 2 (2026-09-29, Quota-Erschöpfung live reproduziert):
      // xrplcluster nennt sein Fenster im retry_after-Feld ODER in
      // error_message ("units quota (500000 per 3600s) exhausted,
      // retry in ~144662ms"). Die alte 30-s-Kappe unterschritt das
      // genannte Fenster (~145 s) und verbrannte alle Versuche, bevor
      // die Quota sich erholte. Jetzt: genanntes Fenster voll ausitzen
      // (Guard-Slack 2 s); übersteigt es die Rest-Guard-Zeit, Fehler
      // mit Quota-Hinweis statt Gegenstelle-weiterhämmern.
      const msg = String(data.result?.error_message || data.result.error);
      lastHint = msg;
      const fieldMs = Number(data.result?.retry_after) * 1000;
      const msgMs = Number(msg.match(/retry in ~?(\d+)ms/)?.[1]);
      const stated = [fieldMs, msgMs].find((n) => Number.isFinite(n) && n > 0);
      const remaining = GUARD_MS - (Date.now() - START);
      if (stated != null) {
        if (stated + 2000 > remaining) {
          throw new Error(
            `RPC error: ${data.result.error} (${msg}) — Quota-Fenster übersteigt Wall-Clock-Guard.`
          );
        }
        await sleep(stated + 2000);
        continue;
      }
      delay = Math.min(delay * 2, 30000);
      await sleep(delay);
      continue;
    }
    if (data?.result?.error) throw new Error(`RPC error: ${data.result.error}`);
    return data.result;
  }
  throw new Error(`RPC error: throttled${lastHint ? ` (${lastHint})` : ""}`);
}

// ---------- Hash-Auflösung (NUR Fallback für Endpunkte ohne expand-Support)
// ----------
const MAX_RESOLVE = 40;
const PARALLEL = 8;
async function resolveHashes(hashes) {
  const entries = [];
  const list = hashes.slice(0, MAX_RESOLVE);
  for (let i = 0; i < list.length; i += PARALLEL) {
    const chunk = list.slice(i, i + PARALLEL);
    const results = await Promise.all(chunk.map((h) => rpc("tx", { transaction: h }).catch(() => null)));
    for (const r of results) {
      if (r && (r.TransactionType || r.tx_json || r.tx)) entries.push(r);
    }
  }
  return { entries, unresolved: hashes.length - entries.length };
}

// ---------- Entry-Normalisierung (Muster public/app.js:681-689) ----------
function normalizeLedgerTxEntry(e) {
  if (!e || typeof e !== "object") return null;
  if (e.tx_json || e.tx) return e;
  if (e.TransactionType) {
    const { metaData, meta, ...txFields } = e;
    return { tx_json: txFields, meta: meta ?? metaData ?? null };
  }
  return null;
}

// ---------- buildCtx-Äquivalent (api/ledger.js:95-111) ----------
// firstSeenAt wird über die 6 Ledger hinweg gefüllt (Muster recordFirstSeen
// in public/app.js), damit die Frische-Regeln der Engine ein Signal haben.
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

// ---------- 6 aufeinanderfolgende validierte Ledger ----------
// expand:true: GENAU EIN Request pro Block, alle Tx-Objekte mit metaData
// (honeycluster-Standardpfad, live belegt 2026-10-02). lgrNotFound (Index
// noch nicht validiert) -> Retry nach ~5 s wie bisher.
const NOT_VALIDATED_RE = /notFound|not found|noLedger|not_validated|ledger_not_validated|lgrNotFound/i;
async function fetchLedgerValidated(idx) {
  for (let attempt = 0; ; attempt++) {
    checkGuard();
    let err;
    try {
      return await rpc("ledger", { ledger_index: idx, transactions: true, expand: true });
    } catch (e) {
      err = e;
    }
    if (!NOT_VALIDATED_RE.test(String(err?.message))) throw err;
    if (attempt >= 40) throw new Error(`Ledger ${idx} nicht validiert (Timeout).`);
    await sleep(5000); // ~4-5 s Ledger-Zeit; nächster Versuch
  }
}

const ISO_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}/;
const CLUSTER_FIELDS = [
  "id", "label", "memberAddresses", "roles", "totalDrops", "txCount",
  "distinctAccounts", "firstSeen", "lastSeen", "mainDrainers", "collectors",
];

async function main() {
  const ctx = await buildCtx();
  const allTxRecords = [];
  const allFindings = [];
  let ledgersProcessed = 0;
  let hashAttempted = 0;
  let expandExpected = 0; // expand:true-Pfad: erwartete volle Objekte pro Block

  const first = await fetchLedgerValidated("validated");
  const firstIdx = Number(first?.ledger_index);
  if (!Number.isFinite(firstIdx)) throw new Error("Keine validierte Ledger-Index erhalten.");

  let led = first;
  for (let i = 0; i < 6; i++) {
    if (i > 0) led = await fetchLedgerValidated(firstIdx + i);
    checkGuard();

    const rawTxs = led?.ledger?.transactions ?? [];
    const ledgerCloseIso =
      led?.ledger?.close_time_iso ??
      (typeof led?.ledger?.close_time === "number"
        ? new Date((led.ledger.close_time + 946684800) * 1000).toISOString()
        : null);

    let entries;
    if (rawTxs.length > 0 && rawTxs.every((t) => typeof t === "string")) {
      // Fallback (Endpunkt ohne expand-Support): Hash-Auflösung per tx.
      hashAttempted += rawTxs.length;
      entries = (await resolveHashes(rawTxs)).entries;
    } else {
      // expand:true-Standardpfad: volle Objekte erwartet.
      expandExpected += rawTxs.length;
      entries = rawTxs.map(normalizeLedgerTxEntry).filter(Boolean);
    }
    // expand:true-Entries tragen pro tx keinen ledger_index und keine
    // close_time_iso — die Ledger-Ebenen-Werte werden gestempelt, damit
    // txRecordFromEntry ledgerSeq UND closeTime liefert (noetig fuer die
    // ledgerSeq-Kappung in buildClusterGraph, firstSeen/lastSeen-Sortierung
    // und die closeTime-ISO-Strukturvalidierung unten).
    const ledgerIndex = Number(led?.ledger_index ?? firstIdx + i);
    if (Number.isFinite(ledgerIndex)) {
      for (const e of entries) {
        if (e && typeof e === "object" && e.ledger_index == null) e.ledger_index = ledgerIndex;
        if (e && typeof e === "object" && e.close_time_iso == null && ledgerCloseIso) {
          e.close_time_iso = ledgerCloseIso;
        }
      }
    }

    // Frische-Signal über die Ledger hinweg anreichern.
    for (const e of entries) {
      const t = e.tx_json ?? e.tx ?? e;
      const now = Date.now();
      if (t?.Account && !ctx.firstSeenAt.has(t.Account)) ctx.firstSeenAt.set(t.Account, now);
      if (t?.Destination && !ctx.firstSeenAt.has(t.Destination)) ctx.firstSeenAt.set(t.Destination, now);
    }

    // analyzeLedger exakt wie api/ledger.js:136.
    const result = analyzeLedger({ transactions: entries }, ctx);

    // txRecords mit Ledger-Fallback (Korrektur E: expand:true-Entries tragen
    // kein close_time — Ledger-Ebenen-close_time_iso gewinnt als Fallback).
    for (const e of entries) {
      const rec = txRecordFromEntry(e, ledgerCloseIso);
      if (rec) allTxRecords.push(rec);
    }

    // Bait-Filter + Anonymitätsschicht wie api/ledger.js:152-159.
    for (const f of result.findings) {
      if (baitLabels.has(f.address)) continue; // kein Oracle für Köder-Adressen
      allFindings.push({
        ruleId: f.ruleId,
        severity: f.severity,
        address: sanitizeText(f.address, baitLabels),
        note: sanitizeText(f.note, baitLabels),
      });
    }
    ledgersProcessed += 1;
  }

  // Anti-Concealment: Ein Block mit Txs, aus dem kein einziger tx-Record
  // wurde, ist ergebnislos — nicht still als txs:0 durchlassen. Der Check
  // deckt beide Pfade ab: (a) Hash-Fallback mit aufgelösten, aber
  // unbrauchbaren Antworten; (b) expand:true-Pfad — Entries vorhanden
  // (expandExpected), aber 0 Records (Adapter-/Form-Defekt). a.D. feuerte
  // der Check nur auf dem Hash-Pfad (hashAttempted); mit expand:true wäre
  // der Stille-0-Fall durchgelassen worden (Kritiker-Befund).
  if (hashAttempted > 0 && allTxRecords.length === 0) {
    throw new Error("Hash-Auflösung vollständig fehlgeschlagen — Quota erschöpft (slowDown)?");
  }
  if (expandExpected > 0 && allTxRecords.length === 0) {
    throw new Error("expand:true-Einträge erwartet, aber 0 tx-Records — Adapter-/Form-Defekt?");
  }

  const cg = buildClusterGraph(allTxRecords, allFindings, { maxEdges: 2000 });

  // ---------- Strukturvalidierung ----------
  const errors = [];
  if (ledgersProcessed !== 6) errors.push(`Nur ${ledgersProcessed}/6 Ledger verarbeitet.`);
  const badClose = allTxRecords.filter((r) => !(typeof r.closeTime === "string" && ISO_RE.test(r.closeTime)));
  if (badClose.length > 0) errors.push(`${badClose.length} tx-Records ohne closeTime-ISO.`);
  const badSeq = allTxRecords.filter((r) => !(typeof r.ledgerSeq === "number" && Number.isFinite(r.ledgerSeq)));
  if (badSeq.length > 0) errors.push(`${badSeq.length} tx-Records ohne ledgerSeq.`);
  for (const c of cg.clusters) {
    for (const key of CLUSTER_FIELDS) {
      if (!(key in c)) errors.push(`Cluster ${c?.id ?? "?"}: Feld ${key} fehlt.`);
    }
    if (!Array.isArray(c.memberAddresses) || c.memberAddresses.length < 2) errors.push(`Cluster ${c.id}: memberAddresses ungültig.`);
    if (typeof c.label !== "string" || !/^Cluster [A-Z]+$/.test(c.label)) errors.push(`Cluster ${c.id}: label ungültig.`);
    if (typeof c.id !== "string" || !c.id.startsWith("cluster:")) errors.push(`Cluster ${c.id}: id ungültig.`);
    for (const [addr, role] of Object.entries(c.roles ?? {})) {
      if (!isKnownRole(role)) errors.push(`Cluster ${c.id}: Rolle '${role}' für ${addr} nicht erlaubt.`);
    }
    if (!Array.isArray(c.mainDrainers) || !Array.isArray(c.collectors)) errors.push(`Cluster ${c.id}: mainDrainers/collectors keine Arrays.`);
  }
  for (const n of cg.nodes) {
    if (!isKnownRole(n.role)) errors.push(`Knoten ${n.id}: Rolle '${n.role}' nicht erlaubt.`);
  }
  for (const e of cg.edges) {
    for (const key of ["from", "to", "type", "amountDrops", "txHash", "ledgerSeq", "closeTime"]) {
      if (!(key in e)) errors.push(`Edge ${e?.txHash ?? "?"}: Feld ${key} fehlt.`);
    }
  }

  if (errors.length > 0) {
    for (const err of errors) console.error(`live-gate FEHLER: ${err}`);
    process.exit(1);
  }

  // Defense-in-Depth: die gesamte Ausgabe läuft durch sanitizeText — Köder-
  // Adressen, die als Cluster-Mitglieder oder Sample-Endpunkte auftauchen
  // könnten, werden zu Labels. Seeds werden nie gelesen.
  const body = {
    ledgers: ledgersProcessed,
    network: process.env.NETWORK || config.network,
    txs: allTxRecords.length,
    findings: allFindings,
    clusters: cg.clusters,
    sample: allTxRecords.slice(0, 5).map((r) => ({
      hash: r.hash,
      ledgerSeq: r.ledgerSeq,
      closeTime: r.closeTime,
      type: r.type,
      account: r.account,
      destination: r.destination ?? null,
      amountDrops: r.amountDrops,
    })),
  };
  const safe = JSON.parse(sanitizeText(JSON.stringify(body), baitLabels));
  console.log(JSON.stringify(safe, null, 2));
  process.exit(0);
}

main().catch((err) => {
  console.error(`live-gate FEHLER: ${err?.message ?? err}`);
  process.exit(1);
});
