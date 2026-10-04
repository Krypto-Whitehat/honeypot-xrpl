// Vercel Function: GET /api/account-report?address=… — serverseitig erweiterter
// Profiling-Report einer XRPL-Adresse (Kontakte zur Threat-Liste, Muster-Funde
// aus lib/detector.mjs, Rolle aus lib/cluster.mjs, transparenter Score,
// Off-Ramp-Eligibility) via buildAccountReport (lib/account-report.mjs).
//
// BRIDGE-VERTRAG (lokaler Server): server/index.mjs importiert diesen Handler
// dynamisch und mountet ihn — deshalb Vercel-(req,res)-Signatur, die Adresse
// wird AUSSCHLIESSLICH aus req.query.address gelesen (keine Pfad-Parameter).
// Nur res.status().json() und res.setHeader() (beide auf Vercel-Helper und
// Express vorhanden).
//
// DATENPFAD: JSON-RPC per fetch (account_tx, binary:false) — KEIN xrpl.js
// (ERR_REQUIRE_ESM auf Vercel, dokumentiert in lib/threats-service.mjs:31-36).
// Bedrohungsliste aus getThreatKnowledge() (lib/threats-service.mjs): merged
// Wissensschicht aus deriveThreats + data/history.json + data/flow-state.json
// + data/entity-links.json; buildCheckCtx liefert denselben Engine-ctx
// (knownBad/firstSeenAt/history) wie /api/check und der Live-Walk — der
// einzige UI-Endpunkt mit Score/Eligibility muss dasselbe Wissen sehen.
// Fail-open: ohne GITHUB_HISTORY_TOKEN (readGitHubContents wirft 'Token
// fehlt', lib/history.mjs) und ohne injizierte Reader läuft der Report mit
// deriveThreats allein — ehrlicher Leerzustand, kein 502.
//
// PRIVATSPHÄRE: Die abgefragte Adresse wird NICHT geloggt und NICHT
// persistiert; der 60-Sekunden-Ergebnis-Cache ist rein im Prozess-Speicher
// (Muster lib/threats-service.mjs:208 / server/index.mjs:185).
//
// KÖDERSCHUTZ: Adressen aus der Köder-Karte bekommen dieselbe generische
// Fehlerantwort wie ungültige Adressen — kein Oracle (server/index.mjs:219-220).
// Die Karte kommt aus opts.baitLabels (lokale Bridge: server/index.mjs reicht
// seine ROTIERENDE bait.json/bait-history.json-Union weiter, Muster /api/history)
// oder — auf Vercel, wo die Bridge-Option entfällt — aus ENV BAIT_ADDRESSES.
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { buildAccountReport } from "../lib/account-report.mjs";
import { getThreatKnowledge, buildCheckCtx } from "../lib/threats-service.mjs";

export const maxDuration = 30; // Präzedenz api/ledger.js:25

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, "..");

let config = { network: "mainnet", wss: "wss://xrplcluster.com" };
try {
  config = { ...config, ...JSON.parse(fs.readFileSync(path.join(ROOT, "config.json"), "utf8")) };
} catch {
  /* Default bleibt */
}
const NETWORK = process.env.NETWORK || config.network;
const RPC_URL = process.env.RPC_URL || (process.env.WSS_URL || config.wss).replace(/^wss:/, "https:");

const XRPL_ADDR_RE = /^r[1-9A-HJ-NP-Za-km-z]{24,34}$/;
const CHECK_MAX_TX = 300;   // Analyse-Fenster (wie server/index.mjs:174)
const CACHE_MS = 60000;     // 60-s-In-Memory-Cache wie threats-service

// Bait-Labels aus ENV — Muster api/ledger.js:40-45 / threats-service.mjs:55-60.
const baitLabels = new Map();
(process.env.BAIT_ADDRESSES || "")
  .split(",")
  .map((a) => a.trim())
  .filter(Boolean)
  .forEach((addr, i) => baitLabels.set(addr, `HP-${i + 1}`));

const reportCache = new Map(); // `${NETWORK}|${address}` -> { time, body } — nur im Speicher

// slowDown/tooBusy-Backoff nach api/ledger.js:56-73 ( xrplcluster/Clio drosselt
// bei Häufung — live beobachtet 2026-09-28). ABER mit err.data = data.result
// beim RPC-Fehler wie lib/threats-service.mjs:46-49 — der rpc() aus
// api/ledger.js (Zeile 69) setzt KEIN err.data; diese Kopie MUSS es setzen,
// damit err.data.error ?? err.message wie in threats-service.mjs:289 und
// server/index.mjs:291 funktioniert.
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
    if (data?.result?.error) {
      const err = new Error(`RPC error: ${data.result.error}`);
      err.data = data.result; // Fehlerdetails (act_no_account etc.) für die Behandlung unten
      throw err;
    }
    return data.result;
  }
  throw new Error("RPC error: slowDown");
}

// account_tx-Pagination wie lib/threats-service.mjs:74-91 / server/index.mjs
// (limit 20 pro Seite, marker-Loop). truncated = es existiert ein weiterer
// Marker nach dem Fenster (server/index.mjs:243-244); Entries werden auf
// CHECK_MAX_TX gekappt, damit Analyse-Fenster und checkedTxCount übereinstimmen.
async function fetchAccountTxs(account, limit) {
  const entries = [];
  let marker;
  do {
    const result = await rpc("account_tx", {
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
  return { entries: entries.slice(0, limit), truncated: Boolean(marker) };
}

// Merged Wissen für buildAccountReport: getThreatKnowledge liefert die Map
// Adresse -> {risk, reason, firstSeen, sources[], role, severity} aus allen
// vier Schichten (fail-open je Schicht — ohne Token bleibt sie bei
// deriveThreats, ehrlicher Leerzustand statt 502). buildCheckCtx(knowledge)
// liefert den Engine-ctx (knownBad/firstSeenAt/history) mit
// Exchange-Registry-Ausschluss. opts.readHistory/opts.readFlowState (nur
// lokale Bridge) injizieren die Datei-Reader des Servers — dieselbe Semantik,
// anderer Transport.
async function knowledge(opts = {}) {
  try {
    return await getThreatKnowledge({
      readHistory: typeof opts.readHistory === "function" ? opts.readHistory : undefined,
      readFlowState: typeof opts.readFlowState === "function" ? opts.readFlowState : undefined,
    });
  } catch {
    /* Honeypot-/Persistenz-Schicht optional — Report läuft mit leerem Wissen */
    return { knowledge: new Map(), historyList: null };
  }
}

// hint wie checkAddress (lib/threats-service.mjs:279-284).
function buildHint(entryCount) {
  if (entryCount === 0) {
    return "Keine Transaktionen für diese Adresse gefunden — sie ist neu, nicht finanziert oder auf diesem Netzwerk nicht aktiviert.";
  }
  if (NETWORK === "testnet") {
    return "Prüfung läuft gegen das Testnet — echte Community-Adressen existieren meist nur im Mainnet.";
  }
  return null;
}

// Drittes Argument opts nur für die lokale Bridge (Vercel ruft immer mit
// req, res): opts.baitLabels = Map address->label der Server-Union;
// opts.readHistory/opts.readFlowState = Datei-Reader des Servers für die
// persistierten Schichten (data/history.json, data/flow-state.json).
export default async function handler(req, res, opts = {}) {
  try {
    if (req.method !== "GET") {
      res.setHeader("Allow", "GET");
      return res.status(405).json({ error: "Method not allowed. Nur GET ist erlaubt." });
    }

    // Köder-Gate: Übergabe aus der Bridge bevorzugt, Fallback ENV (Vercel).
    // Nur so läuft der lokale Server mit derselben rotierenden Union wie
    // /api/check statt mit einer leeren ENV-Karte (Befund 2026-09-29).
    const baitMap = opts.baitLabels instanceof Map ? opts.baitLabels : baitLabels;

    // Adresse AUSSCHLIESSLICH aus dem Query-Parameter (Bridge-Vertrag).
    const address = String(req.query?.address ?? "").trim();
    const invalidAnswer = { error: "Ungültige oder nicht prüfbare Adresse." };
    if (!XRPL_ADDR_RE.test(address)) return res.status(400).json(invalidAnswer);
    if (baitMap.has(address)) return res.status(400).json(invalidAnswer); // generisch — kein Oracle

    const cacheKey = `${NETWORK}|${address}`;
    const cached = reportCache.get(cacheKey);
    if (cached && Date.now() - cached.time < CACHE_MS) {
      return res.status(200).json(cached.body);
    }

    const knowledgeResult = await knowledge(opts);
    const threatsByAddress = knowledgeResult.knowledge;
    const engineCtx = buildCheckCtx(knowledgeResult);
    let report;
    try {
      const { entries, truncated } = await fetchAccountTxs(address, CHECK_MAX_TX);
      report = buildAccountReport({
        address,
        network: NETWORK,
        entries,
        threatsByAddress,
        truncated,
        checkedTxCount: entries.length,
        hint: buildHint(entries.length),
        knownBad: engineCtx.knownBad,
        firstSeenAt: engineCtx.firstSeenAt,
        history: engineCtx.history,
      });
    } catch (err) {
      const msg = String(err?.data?.error ?? err?.message ?? err);
      // actMalformed/actInvalid: ungültige Checksumme; act_no_account: Konto
      // existiert nicht. Beides ist ehrlich "unknown", kein Serverfehler
      // (Vorlage lib/threats-service.mjs:288-308 / server/index.mjs:290-305).
      //
      // BEKANNTES TRADE-OFF (bewusst 1:1 vom Bestand übernommen,
      // server/index.mjs:294 / threats-service.mjs:292): der Regex matcht auch
      // allgemeine "not found"-Netzwerkmeldungen und liefert dann unknown
      // (200) statt 502. Konsistenz mit dem Bestand geht hier vor
      // Fehler-Granularität; eine Trennung beider Fälle wäre ein Verhalten-
      // Bruch zum vorhandenen /api/check.
      if (/act_no_account|actnotfound|not found|actmalformed|actinvalid/i.test(msg)) {
        report = buildAccountReport({
          address,
          network: NETWORK,
          entries: [],
          threatsByAddress,
          truncated: false,
          checkedTxCount: 0,
          hint: "Adresse ist ungültig oder das Konto existiert nicht auf dem konfigurierten Netzwerk.",
          knownBad: engineCtx.knownBad,
          firstSeenAt: engineCtx.firstSeenAt,
          history: engineCtx.history,
        });
      } else {
        // Fix 2026-10-04: generische Meldung statt Upstream-Detail-Interpolation
        // (Konsistenz zu lib/threats-service.mjs:905, api/check/[address].js:13).
        // msg bleibt für die actMalformed-Erkennung oben in Gebrauch.
        return res.status(502).json({ error: "Ledger-Abfrage fehlgeschlagen." });
      }
    }

    // Geprüft-am (ISO) dazu — der Report selbst bleibt uhrzeitfrei/deterministisch.
    const body = { ...report, checkedAt: new Date().toISOString() };
    reportCache.set(cacheKey, { time: Date.now(), body });
    return res.status(200).json(body);
  } catch {
    return res.status(500).json({ error: "Unerwarteter Fehler beim Konto-Check." });
  }
}
