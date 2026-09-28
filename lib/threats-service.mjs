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
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { Client } from "xrpl";
import { sanitizeThreat, buildGraph, computeStats } from "./sanitize.mjs";

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

let client = null;
async function getClient() {
  if (client && client.isConnected()) return client;
  client = new Client(WSS);
  await client.connect();
  return client;
}

async function fetchAccountTxs(account, limit) {
  const c = await getClient();
  const entries = [];
  let marker;
  do {
    const resp = await c.request({
      command: "account_tx",
      account,
      ledger_index_min: -1,
      ledger_index_max: -1,
      binary: false,
      forward: false,
      limit: 20,
      ...(marker ? { marker } : {}),
    });
    entries.push(...(resp.result?.transactions ?? []));
    marker = resp.result?.marker;
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
    checkCache.set(addr, { time: Date.now(), result });
    return { status: 200, body: result };
  } catch (err) {
    const msg = String(err?.data?.error ?? err?.message ?? err);
    if (/act_no_account|not found/i.test(msg)) {
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
          hint: "Konto existiert nicht auf dem konfigurierten Netzwerk.",
        },
      };
    }
    return { status: 502, body: { error: `Ledger-Abfrage fehlgeschlagen: ${msg}` } };
  }
}
