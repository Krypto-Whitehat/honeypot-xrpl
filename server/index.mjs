// Honeypot XRPL — API- und Static-Server (Port 3000, same-origin, kein CORS).
// Liest den Threat-Store data/threats.json und pollt ihn per mtime.
//
// ANONYMITÄTSSCHICHT (Kernanforderung, Pflicht für JEDE öffentliche Antwort):
// Der interne Store data/threats.json ist der Wahrheitsbestand inkl.
// txHash-Evidenz und Köder-Adressen. Dieser Server liefert davon ausschließlich
// sanitisierte Ansichten aus:
//   (a) Evidence-Felder enthalten KEINEN txHash, sondern { ref, type, time,
//       honeypot } — ein öffentlicher Hash würde on-chain direkt auf die
//       Köder-Adresse aufösen (Destination-Feld).
//   (b) Jede Adresse aus der UNION bait.json + bait-history.json (aktuelle
//       UND historische Köder, z. B. als funding[].address im Store) wird
//       durch ihr Label ersetzt — in Threat-Adressen, Reason-Texten,
//       Funding-Einträgen und Graph-Knoten.
//   (c) Graph-Node-Ids sind stabile Label-Ids ("honeypot:N", "attacker:<adresse>")
//       — Honeypot-Knoten enthalten niemals Adressen.
//   (d) Funding-Einträge werden nur als Label veröffentlicht (Faucet benign,
//       "Testnet-Faucet (benign)", ohne Adresse).
// Seeds erscheinen in keiner öffentlichen Antwort (dieser Server nutzt sie
// nicht einmal intern — nur address/label der Bait-Dateien werden gelesen).
import express from "express";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { Client } from "xrpl";
import {
  sanitizeThreat,
  sanitizeText,
  buildGraph,
  computeStats,
} from "../lib/sanitize.mjs";
import { analyzeLedger } from "../lib/detector.mjs";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, "..");

const config = JSON.parse(fs.readFileSync(path.join(ROOT, "config.json"), "utf8"));

const DATA_DIR = path.join(ROOT, "data");
const THREATS_FILE = path.join(DATA_DIR, "threats.json");
const BAIT_FILE = path.join(ROOT, "bait.json");
const BAIT_HISTORY_FILE = path.join(ROOT, "bait-history.json");
const PUBLIC_DIR = path.join(ROOT, "public");

// ---------- Threat-Store: Polling per mtime ----------
let threatsCache = [];
let lastMtime = 0;

function loadThreats() {
  try {
    const st = fs.statSync(THREATS_FILE);
    if (st.mtimeMs !== lastMtime) {
      const parsed = JSON.parse(fs.readFileSync(THREATS_FILE, "utf8"));
      threatsCache = Array.isArray(parsed) ? parsed : [];
      lastMtime = st.mtimeMs;
    }
  } catch (err) {
    if (err.code !== "ENOENT") {
      console.error(`[server] threats.json nicht lesbar: ${err.message}`);
    }
    threatsCache = [];
    lastMtime = 0;
  }
}

// ---------- Bait-Union (aktuelle + historische Köder) ----------
// Nur address/label werden in den Speicher genommen — Seeds werden nie gelesen.
function loadBaitMap(file) {
  try {
    const parsed = JSON.parse(fs.readFileSync(file, "utf8"));
    const map = new Map();
    if (Array.isArray(parsed)) {
      for (const b of parsed) {
        if (b?.address) map.set(b.address, b.label ?? "Köder");
      }
    }
    return map;
  } catch (err) {
    if (err.code !== "ENOENT") {
      console.error(`[server] ${path.basename(file)} nicht lesbar: ${err.message}`);
    }
    return new Map();
  }
}

let baitLabels = new Map(); // address -> label (UNION bait.json + bait-history.json)
function reloadBait() {
  const history = loadBaitMap(BAIT_HISTORY_FILE);
  const current = loadBaitMap(BAIT_FILE);
  baitLabels = new Map([...history, ...current]); // aktuelle Label-Vergabe gewinnt
}
reloadBait();
setInterval(reloadBait, 5000); // unterstützt Köder-Rotation zur Laufzeit

const faucetAddresses = new Set(config.faucet_addresses ?? []);

loadThreats();
setInterval(loadThreats, 2000);

// ---------- Sanitisierung (zentrale Anonymitätsschicht) ----------
// Die Implementierung liegt in lib/sanitize.mjs — single source of truth für
// lokalen Server UND Vercel-Functions. Hier wird nur die jeweils aktuelle
// Bait-Union und Faucet-Liste angebunden.
function sanitizeCtx() {
  return { baitLabels, faucetAddresses, faucetLabel: "Faucet (benign)" };
}

// ---------- Express ----------
const app = express();

// Kein CORS: Das Frontend ist same-origin — fremde Webseiten können die API
// nicht mehr auslesen (LOW-13-Fix).

app.get("/api/health", (req, res) => {
  res.json({ ok: true });
});

app.get("/api/stats", (req, res) => {
  res.json(computeStats(threatsCache, config.network));
});

app.get("/api/threats", (req, res) => {
  // Interne Store-Kopie durch die Anonymitätsschicht — niemals roh ausliefern.
  let list = threatsCache.map((t) => sanitizeThreat(t, sanitizeCtx()));
  // Suche: optionaler q-Parameter filtert Adresse und Grund (Case-insensitive).
  const q = String(req.query.q ?? "").trim().toLowerCase();
  if (q) {
    list = list.filter(
      (t) => t.address.toLowerCase().includes(q) || t.reason.toLowerCase().includes(q)
    );
  }
  res.json(list);
});

app.get("/api/graph", (req, res) => {
  // Node-Ids: "attacker:<öffentliche Adresse>" bzw. "honeypot:N" —
  // Honeypot-Knoten und Kanten-Enden enthalten keine Köder-Adressen.
  res.json(buildGraph(threatsCache, { baitLabels }));
});

// ---------- Selbst-Check: Community-Adresse gegen die Threat-Liste ----------
// GET /api/check/:address — prüft die Transaktionshistorie einer Adresse auf
// Kontakte zu bekannten maliziösen/verdächtigen Adressen (Zahlungen,
// Trustlines, DEX-Orders, Escrow/Check/Payment-Kanäle, generisch Absender/Ziel).
//
// PRIVATSPHARE: Die abgefragte Adresse wird NICHT geloggt und NICHT persistiert
// (kein Eintrag in logs/ oder data/); der 60-Sekunden-Ergebnis-Cache ist rein
// im Prozess-Speicher.
//
// KÖDERSCHUTZ: Adressen aus der Bait-Union werden mit derselben generischen
// Fehlerantwort abgewiesen wie ungültige Adressen — die API gibt nicht preis,
// ob eine Adresse ein Köder ist (kein Oracle).
const XRPL_ADDR_RE = /^r[1-9A-HJ-NP-Za-km-z]{24,34}$/;
const CHECK_MAX_TX = 300;
const CHECK_CACHE_MS = 60000;

let xrplClient = null;
async function getXrplClient() {
  if (xrplClient && xrplClient.isConnected()) return xrplClient;
  xrplClient = new Client(config.wss);
  await xrplClient.connect();
  return xrplClient;
}

const checkCache = new Map(); // address -> { time, result } — nur im Speicher

// Gegenparteien einer Transaktion relativ zur geprüften Adresse.
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
    // generisch: Absender/Ziel-Beteiligung. NFToken-Käufer/Verkäufer werden
    // über die Offer-Ids nicht aufgelöst (dokumentierte Grenze, siehe README).
    if (tx.Account === addr) add(tx.Destination, "ausgehend", type);
    else add(tx.Account, "eingehend", type);
  }
  return out;
}

app.get("/api/check/:address", async (req, res) => {
  const addr = String(req.params.address ?? "").trim();
  const invalidAnswer = { error: "Ungültige oder nicht prüfbare Adresse." };
  if (!XRPL_ADDR_RE.test(addr)) return res.status(400).json(invalidAnswer);
  if (baitLabels.has(addr)) return res.status(400).json(invalidAnswer); // generisch — kein Oracle

  const cached = checkCache.get(addr);
  if (cached && Date.now() - cached.time < CHECK_CACHE_MS) return res.json(cached.result);

  try {
    const client = await getXrplClient();
    const entries = [];
    let marker;
    let truncated = false;
    do {
      const resp = await client.request({
        command: "account_tx",
        account: addr,
        ledger_index_min: -1,
        ledger_index_max: -1,
        binary: false,
        forward: false,
        limit: 20,
        ...(marker ? { marker } : {}),
      });
      entries.push(...(resp.result?.transactions ?? []));
      marker = resp.result?.marker;
    } while (marker && entries.length < CHECK_MAX_TX);
    if (marker) truncated = true;

    const threatByAddress = new Map();
    for (const t of threatsCache) if (t?.address) threatByAddress.set(t.address, t);

    const contacts = [];
    for (const entry of entries) {
      if (entry?.validated === false) continue;
      const tx = entry.tx_json ?? entry.tx ?? entry;
      if (!tx) continue;
      const time =
        entry.close_time_iso ??
        (typeof tx.date === "number" && Number.isFinite(tx.date)
          ? new Date((tx.date + 946684800) * 1000).toISOString()
          : null);
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
      network: config.network,
      checkedTxCount: entries.length,
      truncated,
      selfListed: threatByAddress.has(addr),
      verdict: contacts.length ? "contact" : entries.length ? "clean" : "unknown",
      contacts: contacts.slice(0, 50),
      hint:
        entries.length === 0
          ? "Keine Transaktionen für diese Adresse gefunden — sie ist neu, nicht finanziert oder auf diesem Netzwerk nicht aktiviert."
          : config.network === "testnet"
            ? "Prüfung läuft gegen das Testnet — echte Community-Adressen existieren meist nur im Mainnet."
            : null,
    };
    checkCache.set(addr, { time: Date.now(), result });
    res.json(result);
  } catch (err) {
    const msg = String(err?.data?.error ?? err?.message ?? err);
    // actMalformed/actInvalid: ungültige Checksumme; act_no_account: Konto
    // existiert nicht. Beides ist ehrlich "unknown", kein Serverfehler.
    if (/act_no_account|actnotfound|not found|actmalformed|actinvalid/i.test(msg)) {
      return res.json({
        address: addr,
        network: config.network,
        checkedTxCount: 0,
        truncated: false,
        selfListed: false,
        verdict: "unknown",
        contacts: [],
        hint: "Adresse ist ungültig oder das Konto existiert nicht auf dem konfigurierten Netzwerk.",
      });
    }
    res.status(502).json({ error: `Ledger-Abfrage fehlgeschlagen: ${msg}` });
  }
});

// ---------- Live-Ledger-Snapshot (identische Engine wie Browser/Vercel) ----------
// GET /api/ledger — JSON-RPC per fetch (dieselbe Logik wie api/ledger.js; KEIN
// xrpl.js für diesen Pfad), analyzeLedger aus lib/detector.mjs, Ausgabe durch
// die Anonymitätsschicht. knownBad/firstSeenAt stammen lokal aus dem Threat-Store.
const RPC_URL = (config.wss || "wss://xrplcluster.com").replace(/^wss:/, "https:");
const LEDGER_MAX_RESOLVE = 40;
const LEDGER_PARALLEL = 8;
const LEDGER_CACHE_MS = 60000;
let ledgerCache = null; // { time, body } — nur im Prozess-Speicher

// slowDown-Backoff: xrplcluster (Clio) drosselt bei Häufung — live beobachtet
// 2026-09-28. Ein Retry-Fenster pro Call macht den Snapshot robust.
async function rpcFetch(method, params, tries = 3) {
  for (let i = 0; i < tries; i++) {
    const res = await fetch(RPC_URL, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ method, params: [{ ...params }] }),
    });
    if (!res.ok) throw new Error(`RPC HTTP ${res.status}`);
    const data = await res.json();
    if (data?.result?.error === "slowDown") {
      await new Promise((r) => setTimeout(r, 1500 * (i + 1)));
      continue;
    }
    if (data?.result?.error) throw new Error(`RPC error: ${data.result.error}`);
    return data.result;
  }
  throw new Error("RPC error: slowDown");
}

async function resolveHashes(hashes) {
  const entries = [];
  const list = hashes.slice(0, LEDGER_MAX_RESOLVE);
  for (let i = 0; i < list.length; i += LEDGER_PARALLEL) {
    const chunk = list.slice(i, i + LEDGER_PARALLEL);
    const results = await Promise.all(
      chunk.map((h) => rpcFetch("tx", { transaction: h }).catch(() => null))
    );
    for (const r of results) if (r && (r.TransactionType || r.tx_json || r.tx)) entries.push(r);
  }
  return { entries, unresolved: hashes.length - entries.length };
}

function localLedgerCtx() {
  const knownBad = new Set();
  const firstSeenAt = new Map();
  for (const t of threatsCache) {
    if (!t?.address || baitLabels.has(t.address)) continue;
    knownBad.add(t.address);
    const fs0 = Date.parse(t.firstSeen ?? "");
    if (Number.isFinite(fs0)) firstSeenAt.set(t.address, fs0);
  }
  return {
    knownBad,
    benignIssuers: new Set(config.benign_issuers || []),
    benignAccounts: new Set(config.benign_accounts || []),
    threats: new Map(),
    firstSeenAt,
  };
}

app.get("/api/ledger", async (req, res) => {
  try {
    if (ledgerCache && Date.now() - ledgerCache.time < LEDGER_CACHE_MS) {
      return res.json(ledgerCache.body);
    }
    const led = await rpcFetch("ledger", { ledger_index: "validated", transactions: true });
    const rawTxs = led?.ledger?.transactions ?? [];
    const closeTime =
      led?.ledger?.close_time_iso ??
      (typeof led?.ledger?.close_time === "number"
        ? new Date((led.ledger.close_time + 946684800) * 1000).toISOString()
        : null);

    let findings;
    let resolvedTxCount = 0;
    let unresolvedTxCount = 0;
    if (rawTxs.length > 0 && rawTxs.every((t) => typeof t === "string")) {
      const { entries, unresolved } = await resolveHashes(rawTxs);
      resolvedTxCount = entries.length;
      unresolvedTxCount = unresolved;
      findings = analyzeLedger({ transactions: entries }, localLedgerCtx()).findings;
    } else {
      findings = analyzeLedger(led, localLedgerCtx()).findings;
      resolvedTxCount = rawTxs.length;
    }

    const body = {
      ledgerIndex: led?.ledger_index ?? null,
      ledgerHash: led?.ledger_hash ?? null,
      closeTime,
      network: config.network,
      stats: { txs: rawTxs.length, findings: findings.length },
      resolvedTxCount,
      unresolvedTxCount,
      findings: findings
        .filter((f) => !baitLabels.has(f.address)) // kein Oracle für Köder-Adressen
        .map((f) => ({
          ruleId: f.ruleId,
          severity: f.severity,
          address: sanitizeText(f.address, baitLabels), // Defense-in-Depth: auch das Adressfeld läuft durch die Anonymitätsschicht
          note: sanitizeText(f.note, baitLabels),
        })),
    };
    ledgerCache = { time: Date.now(), body };
    res.json(body);
  } catch (err) {
    res.status(502).json({ error: `Ledger-Abfrage fehlgeschlagen: ${err?.message ?? err}` });
  }
});

// Engine für den Browser-Import: /lib/detector.mjs (single source of truth).
app.use("/lib", express.static(path.join(ROOT, "lib")));

// Statische Files aus public/ (wird parallel von einem anderen Agenten gebaut;
// fehlt das Verzeichnis, geben die statischen Routen einfach 404 zurück).
app.use(express.static(PUBLIC_DIR));

app.listen(config.port, () => {
  console.log(`[server] Honeypot XRPL läuft auf http://localhost:${config.port} (Netz: ${config.network})`);
});
