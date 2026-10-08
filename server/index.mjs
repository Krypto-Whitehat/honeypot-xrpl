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
import { createHash } from "node:crypto";
import { fileURLToPath } from "node:url";
import { Client } from "xrpl";
import {
  sanitizeThreat,
  sanitizeText,
  buildGraph,
  computeStats,
} from "../lib/sanitize.mjs";
import { analyzeLedger } from "../lib/detector.mjs";
import { txRecordFromEntry } from "../lib/cluster.mjs";
import {
  checkDrainerSweepFromEntries,
  getThreatKnowledge,
  buildCheckCtx,
  getMultiUserAccountsMap,
} from "../lib/threats-service.mjs";
import { normalizeTag } from "../lib/tag-identity.mjs";
import {
  loadLocalHistory,
  saveLocalHistory,
  validateAndSanitizeHistoryPayload,
  mergeHistory,
  sanitizeHistoryList,
  searchHistory,
  rateLimitHistory,
  clientKeyOf,
} from "../lib/history.mjs";
import {
  parseFlowStateText,
  projectFlowStateView,
  emptyFlowStateDoc,
} from "../lib/flow-state.mjs";
import {
  parseBlockWindowText,
  projectBlockWindow,
  dayOf,
  emptyBlockWindow,
} from "../lib/block-window.mjs";

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

// ---------- Bait-Hash-Allowlist für den Client (GET /api/bait-hashes) ----------
// Der Client (public/app.js, refetchBaitHashes) gleicht Anzeige- und Graph-
// Adressen gegen die Köder-Union ab, OHNE jemals eine Klartext-Köder-Adresse
// zu erfahren: dieser Endpunkt liefert ausschließlich SHA-256-Hashes (hex,
// Kleinbuchstaben) der getrimmten UTF-8-Adresse — exakt die Normalisierung,
// die der Client in sha256Hex/hashOf verwendet. Ohne diesen Endpunkt bliebe
// die Vollanzeige dauerhaft deaktiviert (fail-closed) und der clientseitige
// Köder-Filter im WSS-Pfad leer. Köder-Rotation (reloadBait alle 5 s) wird
// pro Request frisch gehasht; Seeds werden nie gelesen.
app.get("/api/bait-hashes", (req, res) => {
  const hashes = [...baitLabels.keys()]
    .map((a) => String(a).trim())
    .filter(Boolean)
    .map((a) => createHash("sha256").update(a, "utf8").digest("hex"));
  res.setHeader("cache-control", "no-store");
  res.json({ hashes });
});

// ---------- Maliziöse Historie (GET+POST /api/history) ----------
// Persistente, kollektive Historie AUSSCHLIESSLICH als maliziös eingestufter
// Cluster; suspect/info erreichen die Persistenz nie (severity wird in
// lib/history.mjs serverseitig erzwungen). Die Suspect-Downgrades des
// Detektors (Zitat-Memo, known-bad-Issuer-Position, firstSeenAt-only-Sweep)
// halten solche Funde bewusst aus der malicious-History draußen — der
// Drainer-History-Append unten bleibt malicious, weil dort nur der per
// CreatedNode belegte Sweep gemeldet wird. Lokal gilt data/history.json
// (atomar via tmp+rename) — KEIN Netz-Call: GitHub-Persistenz läuft nur in
// der Vercel-Function api/history.js (Env GITHUB_HISTORY_TOKEN, separates
// History-Repo; Details und BETRIEBSANFORDERUNGEN im Kopf von
// lib/history.mjs). Express 4 fängt rejected Promises aus async Handlern
// NICHT ab — beide Handler laufen deshalb komplett in try/catch wie die
// Bestandsrouten (Muster /api/check, /api/ledger); Fehler -> neutrale 500
// (console.error OHNE Adressen/Token).
const HISTORY_FILE = path.join(DATA_DIR, "history.json");

app.post("/api/history", express.json({ limit: "256kb" }), async (req, res) => {
  try {
    // Rate-Limit zuerst: max 6 POSTs/60 s je Client (Sliding Window).
    const clientKey = clientKeyOf(req.headers["x-forwarded-for"], req.socket?.remoteAddress);
    if (!rateLimitHistory(clientKey, Date.now())) {
      res.setHeader("Retry-After", "60");
      return res.status(429).json({ error: "Zu viele Meldungen — bitte später erneut versuchen." });
    }
    const existing = await loadLocalHistory(HISTORY_FILE); // Parse-Fehler wirft -> 500
    const existingKeys = new Set(existing.map((c) => c?.key).filter(Boolean));
    // Köder-Filter gegen die ROTIERENDE baitLabels-Union (reloadBait alle 5 s).
    const validated = validateAndSanitizeHistoryPayload(req.body, baitLabels, existingKeys);
    const merged = mergeHistory(existing, validated.accepted, Date.now(), baitLabels);
    if (merged.changed || validated.accepted.length) {
      await saveLocalHistory(HISTORY_FILE, merged.list); // atomar
    }
    res.status(202).json({
      accepted: validated.accepted.length,
      merged: merged.list.length,
      ignored: validated.ignored,
      dropped: merged.dropped,
    });
  } catch (err) {
    console.error(`[history] POST /api/history fehlgeschlagen: ${err?.name ?? "Error"}`); // neutral
    res.status(500).json({ error: "Historie nicht verfügbar." });
  }
});

app.get("/api/history", async (req, res) => {
  try {
    res.setHeader("cache-control", "no-store");
    // Lesefilter gegen die AKTUELLE baitLabels — Rotation wirkt ohne Neustart.
    const list = searchHistory(sanitizeHistoryList(await loadLocalHistory(HISTORY_FILE), baitLabels), req.query.q);
    let updatedAt = null;
    try {
      updatedAt = fs.statSync(HISTORY_FILE).mtimeMs;
    } catch {
      /* Datei (noch) nicht vorhanden — Anlege-Fall */
    }
    res.json({ clusters: list, updatedAt });
  } catch (err) {
    console.error(`[history] GET /api/history fehlgeschlagen: ${err?.name ?? "Error"}`); // neutral
    res.status(500).json({ error: "Historie nicht verfügbar." });
  }
});

// ---------- Flow-Host (GET /api/flow-state) ----------
// Lokaler Spiegel der Vercel-Lesezweige api/flow-state.js: liest den
// akkumulierten Flow-State aus data/flow-state.json (lokale Datei-Persistenz,
// KEIN Netz-Call — die GitHub-Persistenz läuft nur in der Vercel-Function)
// und liefert die NORMALISIERTE renderbare Projektion (projectFlowStateView,
// lib/flow-state.mjs). Datei fehlt -> leeres Dokument (ehrlicher
// Leerzustand); Parse-Fehler -> neutrale 500 (Muster /api/history oben).
const FLOW_STATE_FILE = path.join(DATA_DIR, "flow-state.json");

// validatedIndex für die Rückstands-Anzeige (Kritiker-Befund 2026-10-02):
// lokal identische Semantik wie api/flow-state.js:46-67 — EIN
// ledger_index:'validated'-Call mit 60-s-Prozess-Cache; Fehler -> null
// (ehrlicher Leerzustand im Client, ebenfalls kurz gecacht).
let flowValidatedCache = null; // { time, index } — nur im Prozess-Speicher
async function fetchFlowValidatedIndex() {
  if (flowValidatedCache && Date.now() - flowValidatedCache.time < 60000) {
    return flowValidatedCache.index;
  }
  let index = null;
  try {
    const result = await rpcFetch("ledger", { ledger_index: "validated" }, 1);
    const n = Number(result?.ledger_index);
    if (Number.isFinite(n) && n > 0) index = Math.floor(n);
  } catch {
    /* null -> ehrlicher Leerzustand im Client */
  }
  flowValidatedCache = { time: Date.now(), index };
  return index;
}

app.get("/api/flow-state", async (req, res) => {
  try {
    res.setHeader("cache-control", "no-store");
    let doc;
    try {
      doc = parseFlowStateText(fs.readFileSync(FLOW_STATE_FILE, "utf8"));
    } catch (err) {
      if (err && err.code === "ENOENT") doc = emptyFlowStateDoc(); // Anlege-Fall
      else throw err; // Korruption -> neutrale 500
    }
    const validatedIndex = await fetchFlowValidatedIndex();
    res.json({ ...projectFlowStateView(doc), validatedIndex });
  } catch (err) {
    console.error(`[flow-state] GET /api/flow-state fehlgeschlagen: ${err?.name ?? "Error"}`); // neutral
    res.status(500).json({ error: "Flow-State nicht verfügbar." });
  }
});

// ---------- Block-Fenster (GET /api/block-window) ----------
// Lokaler Spiegel der Vercel-Function api/block-window.js: liest die Tages-
// Chunks aus data/block-window/<YYYY-MM-DD>.json (lokale Datei-Persistenz,
// KEIN Netz-Call) und liefert dieselbe Projektion (projectBlockWindow:
// Stunden-Rollups + Flag-Detail). Fehlende Chunks -> leerer Tag
// (emptyBlockWindow, ehrlicher Leerzustand); Parse-Fehler -> neutrale 500.
const BLOCK_WINDOW_LOCAL_DIR = path.join(DATA_DIR, "block-window");
const BW_RANGES = { "24h": 24, "3d": 72, "7d": 168 }; // Stunden

app.get("/api/block-window", async (req, res) => {
  try {
    res.setHeader("cache-control", "no-store");
    const rawRange = String(req?.query?.range ?? "24h").trim();
    const hours = BW_RANGES[rawRange];
    if (!hours) {
      return res.status(400).json({ error: "Ungültiger range (24h|3d|7d)." });
    }
    const now = Date.now();
    const from = now - hours * 3600 * 1000;
    const docs = [];
    for (let back = 0; back <= Math.ceil(hours / 24); back++) {
      const day = dayOf(now - back * 24 * 60 * 60 * 1000);
      if (!day || docs.some((e) => e.day === day)) continue;
      let doc;
      try {
        doc = parseBlockWindowText(fs.readFileSync(path.join(BLOCK_WINDOW_LOCAL_DIR, `${day}.json`), "utf8"));
      } catch (err) {
        if (err && err.code === "ENOENT") doc = emptyBlockWindow(day); // fehlender Tag -> leer
        else throw err; // Korruption -> neutrale 500
      }
      docs.push({ day, doc });
    }
    const { buckets, flagged } = projectBlockWindow(docs.map((e) => e.doc), { fromMs: from, toMs: now });
    const updatedAt = docs.reduce((m, e) => Math.max(m, Number(e.doc?.updatedAt) || 0), 0) || null;
    let cursor = 0;
    try {
      cursor = parseFlowStateText(fs.readFileSync(FLOW_STATE_FILE, "utf8")).cursor ?? 0;
    } catch {
      /* fehlende Datei -> 0 (ehrlicher Leerzustand) */
    }
    const validatedIndex = await fetchFlowValidatedIndex();
    res.json({ range: rawRange, from, to: now, updatedAt, buckets, flagged, cursor, validatedIndex });
  } catch (err) {
    console.error(`[block-window] GET /api/block-window fehlgeschlagen: ${err?.name ?? "Error"}`); // neutral
    res.status(500).json({ error: "Block-Fenster nicht verfügbar." });
  }
});

// ---------- Lokale Wissens-Reader (Runde 3: 'eine Semantik, zwei Transporte') ----------
// getThreatKnowledge/buildCheckCtx laufen lokal über Datei-Reader statt über
// RPC-Ableitung (deriveThreats) und GitHub-Transport der Vercel-Functions:
//   readThreats   -> mtime-gepollter Threat-Store data/threats.json (monitor.mjs)
//   readHistory   -> data/history.json (loadLocalHistory, atomar)
//   readFlowState -> data/flow-state.json (parseFlowStateText; fehlende Datei
//                    -> leerer State; Korruption -> Wurf, die Schicht fällt
//                    fail-open leer aus — getThreatKnowledge:403,419)
// Dieselbe Resolver-Logik (risk-Union, sources, Registry-Ausschluss in
// buildCheckCtx) wie in api/check/[address].js und api/account-report.js.
function localKnowledgeOpts() {
  return {
    readThreats: async () => threatsCache,
    readHistory: async () => ({ list: await loadLocalHistory(HISTORY_FILE) }),
    readFlowState: async () => {
      try {
        return { doc: parseFlowStateText(fs.readFileSync(FLOW_STATE_FILE, "utf8")) };
      } catch (err) {
        if (err && err.code === "ENOENT") return { doc: emptyFlowStateDoc() };
        throw err;
      }
    },
  };
}

// Generic Bridge für den Konto-Check: die Funktionsdatei gehört dem Account-
// Agenten (api/account-report.js, Vercel-Stil default-export). Ist sie (noch)
// nicht vorhanden oder lädt nicht, antwortet der Server ehrlich mit 503.
// Die rotierende baitLabels-Union (reloadBait alle 5 s) wird explizit
// durchgereicht — sonst liefe der Handler mit seiner leeren ENV-Karte und
// lieferte Köder-Adressen einen vollen Report, während /api/check dieselbe
// Adresse generisch abweist (Befund 2026-09-29; Muster /api/history oben).
// Zusätzlich die lokalen Wissens-Reader (Runde 3): ohne sie fiele der
// Bridge-Handler auf die leere ENV-basierte Threat-Ableitung zurück und
// verfehlte die persistierten Quellen history/flow-state komplett.
app.get("/api/account-report", async (req, res) => {
  try {
    const mod = await import("../api/account-report.js");
    return await mod.default(req, res, { baitLabels, ...localKnowledgeOpts() });
  } catch {
    if (!res.headersSent) res.status(503).json({ error: "Konto-Check auf diesem Server nicht verfügbar." });
    else res.end();
  }
});

// ---------- Selbst-Check: Community-Adresse gegen die Threat-Liste ----------
// GET /api/check/:address — prüft die Transaktionshistorie einer Adresse auf
// Kontakte zu bekannten maliziösen/verdächtigen Adressen (Zahlungen,
// Trustlines, DEX-Orders, Escrow/Check/Payment-Kanäle, generisch Absender/Ziel).
//
// PRIVATSPHÄRE: Die abgefragte Adresse wird NICHT geloggt; der 60-Sekunden-
// Ergebnis-Cache ist rein im Prozess-Speicher. Ausnahme (Unit B): bestätigte
// Drainer werden in die öffentliche Historie (data/history.json) aufgenommen
// — alle übrigen Checks bleiben nicht persistiert.
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

// Gegenparteien einer Transaktion relativ zur geprüften Adresse. Tag-Feld
// (additiver Vertrag, drei synchronisierte Kopien — Sync-Kommentar in
// lib/account-report.mjs:89-92): cp.tag != null, wenn die Transaktion einen
// gültigen DestinationTag trägt. Die Check-Pipeline nutzt ihn NUR auf der
// Gegenpartei-Zeile, wenn die GEGENPARTEI ein Registry-Multi-User-Konto ist
// (Sub-Konto-Hinweis); TrustSet/OfferCreate tragen per Spec keinen
// DestinationTag und erhalten nie ein Tag-Feld.
function counterpartiesOf(tx, addr) {
  const out = [];
  const add = (a, dir, note, tag) => {
    if (a && a !== addr) out.push({ address: a, dir, note, ...(tag != null ? { tag } : {}) });
  };
  const type = tx.TransactionType;
  const destTag = normalizeTag(tx.DestinationTag);
  if (type === "Payment") {
    if (tx.Destination === addr) add(tx.Account, "eingehend", "Zahlung erhalten von", destTag);
    if (tx.Account === addr) add(tx.Destination, "ausgehend", "Zahlung gesendet an", destTag);
  } else if (type === "TrustSet") {
    const issuer = tx.LimitAmount?.issuer;
    if (tx.Account === addr) add(issuer, "eingehend", "Trustline zu Issuer eingerichtet");
    if (issuer === addr) add(tx.Account, "ausgehend", "Trustline von dieser Adresse angefragt");
  } else if (type === "OfferCreate" || type === "OfferCancel") {
    if (tx.Account === addr) add(tx.LimitAmount?.issuer, "ausgehend", "DEX-Order (Issuer)");
    else add(tx.Account, "eingehend", "DEX-Order dieser Adresse");
  } else if (type === "EscrowCreate" || type === "CheckCreate" || type === "PaymentChannelCreate") {
    if (tx.Account === addr) add(tx.Destination, "ausgehend", `${type} gesendet an`, destTag);
    if (tx.Destination === addr) add(tx.Account, "eingehend", `${type} erhalten von`, destTag);
  } else {
    // generisch: Absender/Ziel-Beteiligung. NFToken-Käufer/Verkäufer werden
    // über die Offer-Ids nicht aufgelöst (dokumentierte Grenze, siehe README).
    if (tx.Account === addr) add(tx.Destination, "ausgehend", type, destTag);
    else add(tx.Account, "eingehend", type, destTag);
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

    // Merged Wissen (Runde 3): Threat-Store PLUS persistierte Quellen
    // (data/history.json Members, data/flow-state.json severityByAddress/
    // rolesByAddress) über dieselbe Resolver-Logik wie die Vercel-Checks
    // (getThreatKnowledge mit lokalen Datei-Readern). Die Map ist bereits
    // registry-bereinigt (Exchange-Registry-Ausschluss in getThreatKnowledge)
    // — legitime Exchange-Hot-Wallets aus data/history.json werden weder
    // selfListed noch als malicious-Kontakt gewertet.
    const knowledgeResult = await getThreatKnowledge(localKnowledgeOpts());
    const threatByAddress = knowledgeResult.knowledge;

    // contacts: strikt DIREKTE Gegenparteien (unveränderte Semantik).
    // Tag-Feld (additiv): ist die GEPÜFTE Adresse ein Registry-Multi-User-
    // Konto, zeigt die Gegenpartei-Zeile das Hosted-Sub-Konto — destinationTag
    // bei eingehend, sourceTag bei ausgehend (rein informativ). Auf
    // Gegenparteien-Adressen wäre ein Tag-Feld toter Code: Registry-Adressen
    // werden aus der Wissens-Map ausgeschlossen und erscheinen daher nie als
    // contact (Konsistenz zu lib/threats-service.mjs).
    const contacts = [];
    // Hosted-Selbst-Zuordnung über die Multi-User-Union (Registry ∪
    // verifizierte well-known-Namen, lib/threats-service.mjs) — Coverage-Fix
    // 2026-10-05: verifizierte well-known-Börsen erhalten jetzt hostedAccount
    // und Kontakt-Tags. Fail-open: Fetch-Fehler -> Union = reine Registry.
    const registryMap = await getMultiUserAccountsMap();
    const hostedSelf = registryMap.get(addr) ?? null;
    const hostedIdentities = new Set(); // Identitäten des geprüften Hosted-Kontos
    for (const entry of entries) {
      if (entry?.validated === false) continue;
      const tx = entry.tx_json ?? entry.tx ?? entry;
      if (!tx) continue;
      const time =
        entry.close_time_iso ??
        (typeof tx.date === "number" && Number.isFinite(tx.date)
          ? new Date((tx.date + 946684800) * 1000).toISOString()
          : null);
      const destTag = normalizeTag(tx.DestinationTag);
      const srcTag = normalizeTag(tx.SourceTag);
      if (hostedSelf && tx.TransactionType === "Payment" && tx.Destination === addr) {
        hostedIdentities.add(destTag != null ? `t${destTag}` : "none");
      }
      for (const cp of counterpartiesOf(tx, addr)) {
        const t = threatByAddress.get(cp.address);
        if (!t) continue;
        const contact = {
          txType: tx.TransactionType,
          time,
          direction: cp.dir,
          note: cp.note,
          counterparty: cp.address,
          risk: t.risk ?? "suspect",
          source: Array.isArray(t.sources) && t.sources.length ? t.sources[0] : "bait",
        };
        if (hostedSelf && cp.dir === "eingehend" && destTag != null) contact.destinationTag = destTag;
        if (hostedSelf && cp.dir === "ausgehend" && srcTag != null) contact.sourceTag = srcTag;
        contacts.push(contact);
      }
    }

    // ---------- Unit B: Besucher-Fang (Drainer) ----------
    // Berührte die geprüfte Adresse einen Köder (ausgehende Zahlung an einen
    // Köder der rotierenden UNION), läuft die bestehende Drainer-Sweep-
    // Regel gegen die bereits abgefragte Historie — Bestätigung wie Unit A
    // (monitor.mjs). Bestätigte Drainer werden zusätzlich in die öffentliche
    // Historie (data/history.json) aufgenommen — bestehender Merge-/Save-
    // Pfad, best-effort.
    let touchTime = null;
    for (const entry of entries) {
      if (entry?.validated === false) continue;
      const tx = entry.tx_json ?? entry.tx ?? entry;
      if (!tx || tx.TransactionType !== "Payment") continue;
      if (tx.Account !== addr || !baitLabels.has(tx.Destination)) continue;
      const t =
        entry.close_time_iso ??
        (typeof tx.date === "number" && Number.isFinite(tx.date)
          ? new Date((tx.date + 946684800) * 1000).toISOString()
          : null);
      if (t && (touchTime == null || t > touchTime)) touchTime = t;
    }
    const drainerHit = touchTime
      ? checkDrainerSweepFromEntries(entries, addr, touchTime)
      : null;

    const selfListed = threatByAddress.has(addr);
    const result = {
      address: addr,
      network: config.network,
      checkedTxCount: entries.length,
      truncated,
      selfListed,
      // Hosted-Account-Verfeinerung (additiv, nur bei Registry-Treffer der
      // geprüften Adresse): exchange + requireDestTag (Anzeige-Hinweis) und
      // transit (>= 2 verschiedene Tag-Identitäten eingehender Zahlungen —
      // "kein Tag" zählt als eigene Identität, lib/tag-identity.mjs).
      // Kein Score-/verdict-Einfluss (Formel unverändert).
      ...(hostedSelf
        ? {
            hostedAccount: {
              exchange: hostedSelf.exchange || null,
              requireDestTag: hostedSelf.requireDestTag === true,
              transit: hostedIdentities.size >= 2,
            },
          }
        : {}),
      // selfListed -> 'bad' VOR der contacts-Verzweigung (Runde 3, identisch
      // zu checkAddress/lib/account-report.mjs): eine selbst gelistete
      // Adresse ohne Kontakte war bisher 'clean' und widersprach dem
      // Konto-Report auf denselben Daten.
      verdict: selfListed
        ? "bad"
        : contacts.length
          ? "contact"
          : entries.length
            ? "clean"
            : "unknown",
      contacts: contacts.slice(0, 50),
      hint:
        entries.length === 0
          ? "Keine Transaktionen für diese Adresse gefunden — sie ist neu, nicht finanziert oder auf diesem Netzwerk nicht aktiviert."
          : config.network === "testnet"
            ? "Prüfung läuft gegen das Testnet — echte Community-Adressen existieren meist nur im Mainnet."
            : null,
    };
    if (drainerHit) {
      // Vertrag (identisch zu Unit A): drainer=true, sweepRatio, risk,
      // Reason-Marker "Drainer-Sweep:". risk folgt der Fund-Severity des
      // Detektors (Runde 3, identisch zu checkAddress): 'malicious' nur bei
      // CreatedNode-belegter Frische, sonst 'suspect' (lib/detector.mjs:641-642)
      // — vorher eskalierte Unit B JEDEN bestätigten Sweep auf 'malicious'.
      result.drainer = true;
      result.sweepRatio = drainerHit.ratio;
      result.risk = drainerHit.severity;
      result.reason = `Drainer-Sweep: frisch finanziert und ${Math.round(drainerHit.ratio * 100)} % der Balance an ein Ziel abgeräumt.`;
      // Best-effort-Append über den BESTEHENDEN lokalen Merge-/Save-Pfad
      // (atomar via tmp+rename) — NUR bei Fund-Severity 'malicious'
      // (Append-Gate, Konsistenz zu lib/history.mjs:40-46: suspect-Funde
      // bleiben bewusst aus der malicious-History draußen).
      // Persistenzfehler kippen den Check nicht.
      if (drainerHit.severity === "malicious") {
        const touchMs = Date.parse(touchTime);
        const seenMs = Number.isFinite(touchMs) ? touchMs : 0;
        try {
          const existing = await loadLocalHistory(HISTORY_FILE);
          const merged = mergeHistory(
            existing,
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
          );
          if (merged.changed) await saveLocalHistory(HISTORY_FILE, merged.list);
        } catch (err) {
          console.error(`[history] Drainer-Meldung fehlgeschlagen: ${err?.name ?? "Error"}`); // neutral
        }
      }
    }
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
const LEDGER_ERROR_CACHE_MS = 5000;
let ledgerErrorCache = null; // { time, message } — kurzer Negativ-Cache:
                             // Wiederholte Anfragen innerhalb des Fensters
                             // bedient der Fehler, statt erneut 3 RPC-Versuche
                             // zu feuern — entlastet einen gedrosselten
                             // Endpunkt zusätzlich zum clientseitigen
                             // Poll-Backoff (Befund 2026-09-30).

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
    if (data?.result?.error === "slowDown" || data?.result?.error === "tooBusy") {
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

// history-Träger im lokalen Snapshot-Pfad: Modul-Level-Map (überlebt
// Requests innerhalb des Prozesses) — Cross-Ledger-Regeln (Dusting-Union,
// Sweep-Referenz) feuern damit auch hier.
const localLedgerHistory = new Map();
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
    // marketExcludes (Kritik-Runde 3, T1.7): FP-Guard der Market-Regeln
    // (lib/detector.mjs amm-wash-swap/thin-pool-exploit/spoof-offer-cycle) —
    // im lokalen Snapshot-Pfad: config-benign-Konten + rotierende
    // baitLabels-Union (fail-open, dokumentierte Grenze gegenüber dem
    // Advance-Pfad mit Exchange-Registry ∪ multiUser).
    marketExcludes: new Set([...(config.benign_accounts || []), ...baitLabels.keys()]),
    threats: new Map(),
    firstSeenAt,
    history: localLedgerHistory,
  };
}

app.get("/api/ledger", async (req, res) => {
  try {
    if (ledgerCache && Date.now() - ledgerCache.time < LEDGER_CACHE_MS) {
      return res.json(ledgerCache.body);
    }
    // Negativ-Cache (Befund 2026-09-30): Der Erfolgscache hat Vorrang; erst
    // danach entscheidet der kurze Fehler-Cache. Ein Client im 5-s-Poll-Takt
    // löst so maximal eine Runde RPC-Versuche pro Fenster aus.
    if (ledgerErrorCache && Date.now() - ledgerErrorCache.time < LEDGER_ERROR_CACHE_MS) {
      return res.status(502).json({ error: ledgerErrorCache.message });
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
    let txSource = [];
    if (rawTxs.length > 0 && rawTxs.every((t) => typeof t === "string")) {
      const { entries, unresolved } = await resolveHashes(rawTxs);
      resolvedTxCount = entries.length;
      unresolvedTxCount = unresolved;
      txSource = entries;
      findings = analyzeLedger({ transactions: entries }, localLedgerCtx()).findings;
    } else {
      txSource = rawTxs;
      findings = analyzeLedger(led, localLedgerCtx()).findings;
      resolvedTxCount = rawTxs.length;
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
      network: config.network,
      stats: { txs: rawTxs.length, findings: findings.length },
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
    ledgerCache = { time: Date.now(), body };
    ledgerErrorCache = null; // Erfolg verdrängt einen etwaigen Fehler-Cache
    res.json(body);
  } catch (err) {
    const message = `Ledger-Abfrage fehlgeschlagen: ${err?.message ?? err}`;
    ledgerErrorCache = { time: Date.now(), message };
    res.status(502).json({ error: message });
  }
});

// Engine für den Browser-Import: /lib/detector.mjs (single source of truth).
// WHITELIST (identisch zu api/lib-detector.js:14): nur die vier Browser-
// Engines werden ausgeliefert — lib/history.mjs (Köder-Filter-Engine) und
// künftige Server-Dateien wie lib/account-report.mjs bleiben lokal privat.
// stride.mjs (2026-10-02): statischer Import von public/app.js:52 — fehlt er
// hier, bricht die gesamte Modul-Evaluation des Live-Dashboards (404).
// name-resolve.mjs (2026-10-05): reiner Parser für public/name-index.mjs
// (XRPScan-Well-known-Aliase) — identische Liste zu api/lib-detector.js.
// tag-identity.mjs (2026-10-05): DOM-freie Tag-Pure-Bibliothek — cluster.mjs
// importiert sie für Destination-Tag-Kantenattribute; fehlt sie hier, bricht
// die Modul-Evaluation des Browser-Clusters (404, Muster stride.mjs).
const LIB_WHITELIST = new Set(["detector.mjs", "cluster.mjs", "sanitize.mjs", "stride.mjs", "rate-gate.mjs", "name-resolve.mjs", "tag-identity.mjs", "pattern-watch.mjs"]);
app.get("/lib/:name", (req, res) => {
  if (!LIB_WHITELIST.has(req.params.name)) return res.status(404).end();
  res.sendFile(path.join(ROOT, "lib", req.params.name));
});

// Statische Files aus public/ (wird parallel von einem anderen Agenten gebaut;
// fehlt das Verzeichnis, geben die statischen Routen einfach 404 zurück).
app.use(express.static(PUBLIC_DIR));

app.listen(config.port, () => {
  console.log(`[server] Honeypot XRPL läuft auf http://localhost:${config.port} (Netz: ${config.network})`);
});
