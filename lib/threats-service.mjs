// lib/threats-service.mjs — serverlose Threat-Ableitung für Vercel-Functions.
//
// Auf Vercel läuft KEIN dauerhafter Monitor (Serverless kann keine
// Dauer-WebSocket-Subscription). Stattdessen leitet dieser Dienst die
// Bedrohungsliste bei Bedarf direkt aus der Transaktionshistorie der
// Köder-Konten ab (account_tx, neuste Einträge) und cached sie 60 s pro
// Function-Instanz.
//
// ANONYMITÄT: Alle öffentlichen Ausgaben laufen durch lib/sanitize.mjs —
// dieselbe Anonymitätsschicht wie der lokale Server.
//
// KÖDER auf Vercel: Adressen kommen aus der ENV-Variablen BAIT_ADDRESSES
// (Komma-getrennt). Seeds existieren auf Vercel nicht und werden nie benötigt.
//
// UNIT B (Besucher-Fang): checkAddress prüft bei einer Berührung des
// geprüften Kontos einen Köders die bestehende Drainer-Sweep-Regel
// (lib/detector.mjs) gegen die bereits abgefragte Historie — Bestätigung wie
// Unit A (monitor.mjs). Bestätigte Drainer werden zusätzlich in die
// öffentliche Historie aufgenommen (writeHistoryGitHub, fail-closed ohne
// Token/Filter); der Check selbst bleibt davon unberührt.
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { sanitizeThreat, buildGraph, computeStats } from "./sanitize.mjs";
import { analyzeLedger, DEFAULT_THRESHOLDS } from "./detector.mjs";
import { mergeHistory, writeHistoryGitHub } from "./history.mjs";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, "..");

let config = { network: "mainnet", wss: "wss://xrplcluster.com", faucet_addresses: [] };
try {
  config = { ...config, ...JSON.parse(fs.readFileSync(path.join(ROOT, "config.json"), "utf8")) };
} catch {
  /* Default bleibt */
}
const WSS = process.env.WSS_URL || config.wss;
const NETWORK = process.env.NETWORK || config.network;

// JSON-RPC über HTTPS statt xrpl.js: Vercels Serverless-Runtime scheitert an
// der CJS/ESM-Mischkette der xrpl-Abhängigkeiten (@xrplf/isomorphic →
// @noble/hashes, ERR_REQUIRE_ESM). account_tx braucht nur JSON-RPC —
// fetch ist in Node 18+ global. Der lokale Server/Monitor nutzt weiterhin
// xrpl.js per WSS; diese Datei bleibt dependency-frei.
const RPC_URL = process.env.RPC_URL || WSS.replace(/^wss:/, "https:");

async function rpc(command, params) {
  const res = await fetch(RPC_URL, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ method: command, params: [{ ...params }] }),
  });
  if (!res.ok) throw new Error(`RPC HTTP ${res.status}`);
  const data = await res.json();
  if (data?.result?.error) {
    const err = new Error(`RPC error: ${data.result.error}`);
    err.data = data.result; // checkAddress liest err.data.error (act_no_account)
    throw err;
  }
  return data.result;
}

// Testnaht: Fixture-Ersatz für den RPC-Transport (lib/threats-service.test.mjs).
// Produktion nutzt den Default (HTTPS-RPC); Tests injizieren Fixtures.
let rpcImpl = rpc;
export function setRpc(fn) {
  rpcImpl = typeof fn === "function" ? fn : rpc;
}

// Bait-Union aus ENV (Vercel) — address -> internes Label HP-n.
const baitLabels = new Map();
(process.env.BAIT_ADDRESSES || "")
  .split(",")
  .map((a) => a.trim())
  .filter(Boolean)
  .forEach((addr, i) => baitLabels.set(addr, `HP-${i + 1}`));

const faucetAddresses = new Set(
  (process.env.FAUCET_ADDRESSES || (config.faucet_addresses || []).join(","))
    .split(",")
    .map((a) => a.trim())
    .filter(Boolean)
);

const BAIT_TX_LIMIT = 50;      // neuste Transaktionen pro Köder
const FUNDING_TRACE_MAX = 5;   // Funding-Rückverfolgung für max. N Angreifer
const FUNDING_TX_LIMIT = 10;
const CACHE_MS = 60000;

async function fetchAccountTxs(account, limit) {
  const entries = [];
  let marker;
  do {
    const result = await rpcImpl("account_tx", {
      account,
      ledger_index_min: -1,
      ledger_index_max: -1,
      binary: false,
      forward: false,
      limit: 20,
      ...(marker ? { marker } : {}),
    });
    entries.push(...(result?.transactions ?? []));
    marker = result?.marker;
  } while (marker && entries.length < limit);
  return entries;
}

function timeOf(entry) {
  const tx = entry.tx_json ?? entry.tx ?? entry;
  return (
    entry.close_time_iso ??
    (typeof tx?.date === "number" && Number.isFinite(tx?.date)
      ? new Date((tx.date + 946684800) * 1000).toISOString()
      : null)
  );
}

// ---------- Threat-Ableitung aus Köder-Historie ----------
let threatsCache = null; // { time, threats }
async function deriveThreats() {
  if (threatsCache && Date.now() - threatsCache.time < CACHE_MS) return threatsCache.threats;

  const byAddress = new Map();
  const upsert = (address, patch) => {
    const existing = byAddress.get(address);
    if (existing) {
      existing.evidence.push(patch.evidence);
      if (patch.reason && !existing.reasons.includes(patch.reason)) {
        existing.reasons.push(patch.reason);
      }
      return;
    }
    byAddress.set(address, {
      address,
      risk: patch.risk,
      reasons: [patch.reason],
      evidence: [patch.evidence],
      firstSeen: patch.evidence.time,
      funding: [],
    });
  };

  for (const [baitAddr, label] of baitLabels) {
    let entries = [];
    try {
      entries = await fetchAccountTxs(baitAddr, BAIT_TX_LIMIT);
    } catch {
      continue; // Köder existiert noch nicht (act_no_account) oder Netzwerkfehler
    }
    for (const entry of entries) {
      if (entry?.validated === false) continue;
      const tx = entry.tx_json ?? entry.tx ?? entry;
      if (!tx) continue;
      const time = timeOf(entry);
      const type = tx.TransactionType;
      if (tx.Destination === baitAddr && tx.Account !== baitAddr) {
        upsert(tx.Account, {
          risk: "malicious",
          reason: `Externe ${type}-Transaktion an ${label}`,
          evidence: { type, time, honeypot: label },
        });
      } else if (tx.Account === baitAddr) {
        upsert(baitAddr, {
          risk: "malicious",
          reason: `${label} hat selbst eine Transaktion initiiert (Kompromittierungs-Alarm)`,
          evidence: { type, time, honeypot: label },
        });
      }
    }
  }

  // Funding-Rückverfolgung (Tiefe 1) für die neuesten Angreifer — Labels nur.
  const attackers = [...byAddress.values()]
    .filter((t) => !baitLabels.has(t.address))
    .slice(0, FUNDING_TRACE_MAX);
  for (const t of attackers) {
    try {
      const txs = await fetchAccountTxs(t.address, FUNDING_TX_LIMIT);
      for (const entry of txs) {
        const tx = entry.tx_json ?? entry.tx ?? entry;
        if (tx?.TransactionType === "Payment" && tx.Destination === t.address && tx.Account !== t.address) {
          t.funding.push({ address: tx.Account, label: tx.Account });
          break; // erste Finanzierung genügt (serverless Budget)
        }
      }
    } catch {
      /* Funding optional */
    }
  }

  const threats = [...byAddress.values()].map((t) => ({
    address: t.address,
    risk: t.risk,
    reason: t.reasons.join("; "),
    evidence: t.evidence,
    firstSeen: t.firstSeen,
    funding: t.funding,
  }));
  threatsCache = { time: Date.now(), threats };
  return threats;
}

const ctx = () => ({ baitLabels, faucetAddresses, faucetLabel: "Faucet (benign)" });

export async function getPublicThreats() {
  const threats = await deriveThreats();
  return threats.map((t) => sanitizeThreat(t, ctx()));
}

export async function getGraph() {
  const threats = await deriveThreats();
  return buildGraph(threats, { baitLabels });
}

export async function getStats() {
  const threats = await deriveThreats();
  return computeStats(threats, NETWORK);
}

// ---------- Unit B: Drainer-Sweep-Bestätigung (Bestand-basiert) ----------
// Gleiche Bestätigung wie Unit A (monitor.mjs checkDrainerSweep), aber ohne
// zusätzliche Abfrage: die Transaktionshistorie des geprüften Kontos liegt
// bereits vor (checkAddress hat sie für die Kontaktprüfung abgefragt).
//   (i)   gemessener Sweep-Anteil (max über ausgehende Zahlungen:
//         drops / (prevBal ?? inXrp)) — unterhalb der Schwelle: kein Fund;
//   (ii)  Bestätigung über die BESTEHENDE Drainer-Sweep-Regel
//         (lib/detector.mjs) mit firstSeenAt aus der Berührungs-Zeit —
//         ohne Frische-Signal feuert die Regel nicht.
// Rückgabe: { ratio, drops } bei Bestätigung, sonst null.
const SWEEP_TX_LIMIT = 100; // jüngste Einträge (account_tx liefert newest-first)

// Balance-Vorwert aus meta (AccountRoot ModifiedNode) — identisch zu
// lib/detector.mjs:181-191 und monitor.mjs:236-247 (Sweep-Referenz der
// bestehenden Regel; detector.mjs exportiert die Helper nicht).
function prevBalanceOf(meta) {
  const nodes = Array.isArray(meta?.AffectedNodes) ? meta.AffectedNodes : [];
  for (const n of nodes) {
    const mod = n?.ModifiedNode;
    if (mod?.LedgerEntryType === "AccountRoot" && mod.PreviousFields?.Balance != null) {
      const b = Number(mod.PreviousFields.Balance);
      if (Number.isFinite(b)) return b;
    }
  }
  return null;
}

function measureSweepRatio(entries, toucher) {
  let inXrp = 0;
  const outs = [];
  for (const entry of entries) {
    if (entry?.validated === false) continue;
    const tx = entry.tx_json ?? entry.tx ?? entry;
    if (!tx || tx.TransactionType !== "Payment") continue;
    if (tx.Destination === toucher && tx.Account !== toucher) {
      const d = Number(tx.Amount);
      if (Number.isFinite(d) && d > 0) inXrp += d;
    }
    if (tx.Account === toucher && tx.Destination) {
      const d = Number(tx.Amount);
      if (Number.isFinite(d) && d > 0) {
        outs.push({ drops: d, prevBal: prevBalanceOf(entry.meta) });
      }
    }
  }
  let best = null;
  for (const o of outs) {
    const ref = o.prevBal != null ? o.prevBal : inXrp;
    if (ref > 0) {
      const ratio = o.drops / ref;
      if (!best || ratio > best.ratio) best = { ratio, drops: o.drops };
    }
  }
  return best;
}

export function checkDrainerSweepFromEntries(entries, toucher, touchTime) {
  const recent = Array.isArray(entries) ? entries.slice(0, SWEEP_TX_LIMIT) : [];
  const measured = measureSweepRatio(recent, toucher);
  if (!measured || measured.ratio < DEFAULT_THRESHOLDS.sweepRatio) return null;
  const firstSeenAt = new Map([[toucher, Date.parse(touchTime)]]);
  const { findings } = analyzeLedger({ transactions: recent }, { firstSeenAt });
  const confirmed = findings.some(
    (f) => f?.ruleId === "drainer-sweep" && f?.address === toucher
  );
  return confirmed ? { ratio: measured.ratio, drops: measured.drops } : null;
}

// ---------- Selbst-Check (gleiche Semantik wie der lokale Server) ----------
const XRPL_ADDR_RE = /^r[1-9A-HJ-NP-Za-km-z]{24,34}$/;
const CHECK_MAX_TX = 300;
const checkCache = new Map();

function counterpartiesOf(tx, addr) {
  const out = [];
  const add = (a, dir, note) => {
    if (a && a !== addr) out.push({ address: a, dir, note });
  };
  const type = tx.TransactionType;
  if (type === "Payment") {
    if (tx.Destination === addr) add(tx.Account, "eingehend", "Zahlung erhalten von");
    if (tx.Account === addr) add(tx.Destination, "ausgehend", "Zahlung gesendet an");
  } else if (type === "TrustSet") {
    const issuer = tx.LimitAmount?.issuer;
    if (tx.Account === addr) add(issuer, "eingehend", "Trustline zu Issuer eingerichtet");
    if (issuer === addr) add(tx.Account, "ausgehend", "Trustline von dieser Adresse angefragt");
  } else if (type === "OfferCreate" || type === "OfferCancel") {
    if (tx.Account === addr) add(tx.LimitAmount?.issuer, "ausgehend", "DEX-Order (Issuer)");
    else add(tx.Account, "eingehend", "DEX-Order dieser Adresse");
  } else if (type === "EscrowCreate" || type === "CheckCreate" || type === "PaymentChannelCreate") {
    if (tx.Account === addr) add(tx.Destination, "ausgehend", `${type} gesendet an`);
    if (tx.Destination === addr) add(tx.Account, "eingehend", `${type} erhalten von`);
  } else {
    if (tx.Account === addr) add(tx.Destination, "ausgehend", type);
    else add(tx.Account, "eingehend", type);
  }
  return out;
}

export async function checkAddress(addr) {
  const invalidAnswer = { error: "Ungültige oder nicht prüfbare Adresse." };
  if (!XRPL_ADDR_RE.test(addr)) return { status: 400, body: invalidAnswer };
  if (baitLabels.has(addr)) return { status: 400, body: invalidAnswer }; // generisch — kein Oracle

  const cached = checkCache.get(addr);
  if (cached && Date.now() - cached.time < CACHE_MS) return { status: 200, body: cached.result };

  try {
    const entries = await fetchAccountTxs(addr, CHECK_MAX_TX);
    const truncated = entries.length >= CHECK_MAX_TX;
    const threats = await deriveThreats();
    const threatByAddress = new Map();
    for (const t of threats) if (t?.address) threatByAddress.set(t.address, t);

    const contacts = [];
    for (const entry of entries) {
      if (entry?.validated === false) continue;
      const tx = entry.tx_json ?? entry.tx ?? entry;
      if (!tx) continue;
      const time = timeOf(entry);
      for (const cp of counterpartiesOf(tx, addr)) {
        const t = threatByAddress.get(cp.address);
        if (!t) continue;
        contacts.push({
          txType: tx.TransactionType,
          time,
          direction: cp.dir,
          note: cp.note,
          counterparty: cp.address,
          risk: t.risk ?? "suspect",
        });
      }
    }

    // ---------- Unit B: Besucher-Fang (Drainer) ----------
    // Berührte das geprüfte Konto einen Köder (ausgehende Zahlung an einen
    // Köder), läuft die bestehende Drainer-Sweep-Regel gegen die bereits
    // abgefragte Historie — Bestätigung wie Unit A (monitor.mjs).
    let touchTime = null;
    for (const entry of entries) {
      if (entry?.validated === false) continue;
      const tx = entry.tx_json ?? entry.tx ?? entry;
      if (!tx || tx.TransactionType !== "Payment") continue;
      if (tx.Account !== addr || !baitLabels.has(tx.Destination)) continue;
      const t = timeOf(entry);
      if (t && (touchTime == null || t > touchTime)) touchTime = t;
    }
    const drainerHit = touchTime
      ? checkDrainerSweepFromEntries(entries, addr, touchTime)
      : null;

    const result = {
      address: addr,
      network: NETWORK,
      checkedTxCount: entries.length,
      truncated,
      selfListed: threatByAddress.has(addr),
      verdict: contacts.length ? "contact" : entries.length ? "clean" : "unknown",
      contacts: contacts.slice(0, 50),
      hint:
        entries.length === 0
          ? "Keine Transaktionen für diese Adresse gefunden — sie ist neu, nicht finanziert oder auf diesem Netzwerk nicht aktiviert."
          : NETWORK === "testnet"
            ? "Prüfung läuft gegen das Testnet — echte Community-Adressen existieren meist nur im Mainnet."
            : null,
    };
    if (drainerHit) {
      // Vertrag (identisch zu Unit A): drainer=true, sweepRatio, risk,
      // Reason-Marker "Drainer-Sweep:".
      result.drainer = true;
      result.sweepRatio = drainerHit.ratio;
      result.risk = "malicious";
      result.reason = `Drainer-Sweep: frisch finanziert und ${Math.round(drainerHit.ratio * 100)} % der Balance an ein Ziel abgeräumt.`;
      // Best-effort-Append in die öffentliche Historie über den BESTEHENDEN
      // Merge-/Save-Pfad (lib/history.mjs). Fail-closed ohne Token/Filter
      // (Befund 2026-09-29, Muster api/history.js:75); fehlende Persistenz
      // kippt den Check nicht.
      if (process.env.GITHUB_HISTORY_TOKEN && baitLabels.size > 0) {
        const touchMs = Date.parse(touchTime);
        const seenMs = Number.isFinite(touchMs) ? touchMs : 0;
        try {
          await writeHistoryGitHub((fresh) =>
            mergeHistory(
              fresh,
              [
                {
                  members: [addr],
                  label: "Drainer",
                  totalDrops: drainerHit.drops,
                  txCount: entries.length,
                  firstSeen: seenMs,
                  lastSeen: seenMs,
                  rules: ["drainer-sweep"],
                  severity: "malicious",
                  sightings: 1,
                  lastReportedAt: Date.now(),
                },
              ],
              Date.now(),
              baitLabels
            ).list
          );
        } catch {
          /* Best-effort: Persistenzfehler bleiben hier still (neutral). */
        }
      }
    }
    checkCache.set(addr, { time: Date.now(), result });
    return { status: 200, body: result };
  } catch (err) {
    const msg = String(err?.data?.error ?? err?.message ?? err);
    // actMalformed/actInvalid: ungültige Checksumme; act_no_account: Konto
    // existiert nicht. Beides ist ehrlich "unknown", kein Serverfehler.
    if (/act_no_account|actnotfound|not found|actmalformed|actinvalid/i.test(msg)) {
      return {
        status: 200,
        body: {
          address: addr,
          network: NETWORK,
          checkedTxCount: 0,
          truncated: false,
          selfListed: false,
          verdict: "unknown",
          contacts: [],
          hint: "Adresse ist ungültig oder das Konto existiert nicht auf dem konfigurierten Netzwerk.",
        },
      };
    }
    return { status: 502, body: { error: `Ledger-Abfrage fehlgeschlagen: ${msg}` } };
  }
}
