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
// Token/Filter); der Check selbst bleibt davon unberührt. Der Append läuft
// nur bei Fund-Severity 'malicious' (CreatedNode-belegter Sweep,
// lib/detector.mjs:641-642) — ein suspect-Sweep ohne Erstellungsbeleg wird
// nicht als malicious persistiert (Konsistenz zu lib/history.mjs:40-46).
//
// WISSENS-LAYER (merged, Runde 3): getThreatKnowledge() vereinigt vier
// Schichten zu einer Map Adresse -> {risk, reason, firstSeen, sources[],
// role, severity}: (1) deriveThreats (live aus Köder-Historie), (2)
// data/history.json (readHistoryGitHub — Members der persistierten Cluster),
// (3) data/flow-state.json (readFlowStateGitHub + projectFlowStateView —
// severityByAddress/rolesByAddress), (4) data/entity-links.json
// (loadEntityTable — Anzeige-Metadatum). 60-s-Prozess-Cache, nur GitHub-/
// Datei-Reads, KEIN RPC, fail-open je Schicht (ohne Token/Read-Fehler läuft
// die Schicht leer). Reader sind optional injizierbar (opts.readHistory /
// opts.readFlowState / opts.readThreats — letzterer ersetzt die live-
// abgeleitete Schicht 1 durch den lokalen Threat-Store data/threats.json,
// den monitor.mjs schreibt; der lokale Server hat keinen GitHub-Transport
// und leitet Threats nicht selbst per RPC ab) — der lokale Server liest
// dieselbe Semantik über Datei-Reader, Vercel über den GitHub-Transport:
// eine Semantik, zwei Transporte. buildCheckCtx(knowledge) baut den
// Engine-Kontext (knownBad/firstSeenAt/history) für beide Check-Endpunkte.
//
// DOKUMENTIERTES TRADE-OFF ('malicious by listing'): die knownBad-Union aus
// history/flow-state macht alle in data/history.json persistierten Cluster-
// Members zu knownBad — history erzwingt severity 'malicious' für JELEN
// Cluster (lib/history.mjs:187). Ein known-bad-hit auf einer Gegenpartei ist
// dann Kuratierungs-Erbgut ('malicious by listing'), begrenzt nur durch den
// Exchange-Registry-Ausschluss und die config-Whitelists
// (benign_issuers/benign_accounts, detector.mjs:326). Das ist die bewusste
// Angleichung an die Live-Engine (server/index.mjs:628-633, api/advance.js
// buildCtx) — dort nehmen alle Threats unabhängig vom risk in knownBad auf.
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { sanitizeThreat, buildGraph, computeStats } from "./sanitize.mjs";
import { analyzeLedger, DEFAULT_THRESHOLDS } from "./detector.mjs";
import { mergeHistory, writeHistoryGitHub, readHistoryGitHub } from "./history.mjs";
import { readEntityGitHub, entityJoinKeys, ENTITY_JOIN_KEY_HUB } from "./entity-resolve.mjs";
import { readFlowStateGitHub, projectFlowStateView } from "./flow-state.mjs";
import { normalizeTag } from "./tag-identity.mjs";

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

// Rate-Gate (Grenze 3): die honeycluster-Last der Threat-Ableitung war bisher
// UNGEZÄHLT und ungated. setRateGate injiziert einen bestehenden
// createRateGate (lib/rate-gate.mjs:46) in rpc() — jeder Call erwirbt vor dem
// fetch. Die Caller (api/threats.js, api/check/[address].js, api/advance.js)
// injizieren denselben Bucket wie der Advance-Tick; ohne Injektion bleibt der
// bisherige ungegate Pfad (Tests nutzen die setRpc-Fixture, die das Gate
// umgeht).
let rateGate = null;
export function setRateGate(gate) {
  rateGate = gate && typeof gate.acquire === "function" ? gate : null;
}

async function rpc(command, params) {
  if (rateGate) await rateGate.acquire(1);
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

// Testnaht: leert die Prozess-Caches (threats/check/registry/entity) — Tests
// können gegen eine neue Fixture neu ableiten, ohne die 60-s-Cache-Zeit zu
// erwarten. Produktion nutzt nie diesen Pfad (kein Datenfluss, nur Cache-Reset).
export function resetCachesForTests() {
  threatsCache = null;
  checkCache.clear();
  registryCache = null;
  entityCache = null;
  knowledgeCache = null;
}

// Request-Cap pro deriveThreats-Ableitung (Grenze 3): baitAnzahl × bis zu
// 3 Seiten (BAIT_TX_LIMIT 50 / limit 20) plus FUNDING_TRACE_MAX 5 — der Cap
// hält die Worst-Case-Bilanz unter dem Advance-Tick-Budget (40 ≤ 250 − 100
// Blöcke − 20 Entity, api/advance.js).
export const REQUESTS_PER_TICK_CAP = 40;

// ---------- Exchange-Registry (Grenze 4) ----------
// exchangeLabel aus public/data/exchange-registry.json — NUR wenn der Read
// erfolgreich war; sonst Feld leer (kein Raten, kein Raten-Raten). Der Read
// ist in api/threats.js, api/check/[address].js und api/advance.js erst durch
// die includeFiles-Korrektur in vercel.json tatsächlich möglich (vorher
// dieselbe stille Bundle-Lücke wie der config.json-Read oben :32-36 —
// dokumentiert, nicht behauptet).
const REGISTRY_PATH = path.join(ROOT, "public", "data", "exchange-registry.json");
let registryCache = null; // { time, byAddress } — 60-s-Prozess-Cache
function loadExchangeRegistry() {
  if (registryCache && Date.now() - registryCache.time < CACHE_MS) return registryCache.byAddress;
  const byAddress = new Map();
  try {
    const raw = JSON.parse(fs.readFileSync(REGISTRY_PATH, "utf8"));
    for (const e of Array.isArray(raw?.entries) ? raw.entries : []) {
      if (e && typeof e.address === "string" && e.address) {
        byAddress.set(e.address, {
          exchange: typeof e.exchange === "string" ? e.exchange : "",
          tier: e.tier === "cold" ? "cold" : e.tier === "hot" ? "hot" : null,
          requireDestTag: e.requireDestTag === true,
          signers: Array.isArray(e.signers) ? e.signers : [],
        });
      }
    }
  } catch {
    /* Read-Fehler -> leere Map -> exchangeLabel bleibt leer (kein Raten) */
  }
  registryCache = { time: Date.now(), byAddress };
  return byAddress;
}

// Exchange-Registry für Dritte (api/advance.js, api/account-report.js):
// dieselbe gecachte Map wie exchangeLabel — fail-open (Read-Fehler -> leere
// Map). Dient als opts.multiUserAccounts (Kanten-Attribute toTag/transit,
// lib/tag-identity.mjs) und als Registry-Set für flaggedEdgesFrom.
export function getExchangeRegistryMap() {
  return loadExchangeRegistry();
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
const FUNDING_DEPTH = 2;       // Tiefe 2 (angleichen an monitor.mjs:151-182/470)
const CACHE_MS = 60000;

// Request-Zähler pro Ableitung (Cap REQUESTS_PER_TICK_CAP): fetchAccountTxs
// feuert keine Seite mehr, wenn der Cap erreicht ist — die Ableitung wird
// budgetiert beendet, nicht abgebrochen (bereits gesammelte Threats bleiben).
// Entries werden auf limit gekappt (slice(0,limit)) und truncated =
// Boolean(marker) — Angleichung an api/account-report.js:93-110: vorher
// konnten Seiten zu 20 auf 310 überschießen und truncated war eine
// Zähl-Heuristik (entries.length >= 300); checkedTxCount/truncated konnten
// zwischen /api/check und /api/account-report für dieselbe Adresse abweichen.
async function fetchAccountTxs(account, limit, budget) {
  const entries = [];
  let marker;
  do {
    if (budget && budget.used >= REQUESTS_PER_TICK_CAP) break;
    if (budget) budget.used += 1;
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
  return { entries: entries.slice(0, limit), truncated: Boolean(marker) };
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

  const budget = { used: 0 }; // Requests dieser Ableitung (Cap REQUESTS_PER_TICK_CAP)
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
    if (budget.used >= REQUESTS_PER_TICK_CAP) break;
    let entries = { entries: [], truncated: false };
    try {
      entries = await fetchAccountTxs(baitAddr, BAIT_TX_LIMIT, budget);
    } catch {
      continue; // Köder existiert noch nicht (act_no_account) oder Netzwerkfehler
    }
    for (const entry of entries.entries) {
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

  // Funding-Rückverfolgung (Tiefe 2, angleichen an monitor.mjs:151-182/470)
  // für die neuesten Angreifer — Labels nur. Kette A→B→C: B (Angreifer) wird
  // von A finanziert, A von C — funding trägt beide Hops.
  const attackers = [...byAddress.values()]
    .filter((t) => !baitLabels.has(t.address))
    .slice(0, FUNDING_TRACE_MAX);
  for (const t of attackers) {
    let current = t.address;
    const visited = new Set([current]);
    for (let depth = 0; depth < FUNDING_DEPTH; depth++) {
      if (budget.used >= REQUESTS_PER_TICK_CAP) break;
      try {
        const { entries: txs } = await fetchAccountTxs(current, FUNDING_TX_LIMIT, budget);
        let funder = null;
        for (const entry of txs) {
          const tx = entry.tx_json ?? entry.tx ?? entry;
          if (tx?.TransactionType === "Payment" && tx.Destination === current && tx.Account !== current) {
            funder = tx.Account;
            break; // erste Finanzierung je Ebene genügt (serverless Budget)
          }
        }
        if (!funder || visited.has(funder)) break;
        visited.add(funder);
        t.funding.push({ address: funder, label: funder });
        current = funder;
      } catch {
        /* Funding optional */
        break;
      }
    }
  }

  // Exchange-Registry (Grenze 4): exchangeLabel NUR bei erfolgreichem Read;
  // sonst leeres Feld (kein Raten). entity-Signale (Grenze 3) aus der
  // persistierten Entity-Tabelle (lib/entity-resolve.mjs) — Read optional.
  const registry = loadExchangeRegistry();
  const entityAddresses = await loadEntityTable();
  const threats = [...byAddress.values()].map((t) => {
    const reg = registry.get(t.address);
    return {
      address: t.address,
      risk: t.risk,
      reason: t.reasons.join("; "),
      evidence: t.evidence,
      firstSeen: t.firstSeen,
      funding: t.funding,
      exchangeLabel: reg?.exchange ?? "",
      entity: buildEntitySignal(t.address, entityAddresses),
    };
  });
  threatsCache = { time: Date.now(), threats };
  return threats;
}

// Entity-Tabelle (data/entity-links.json im Daten-Repo): asynchroner Read
// über den BESTEHENDEN GitHub-Transport (lib/entity-resolve.mjs), 60-s-
// Prozess-Cache, fail-open — ohne Token/Read-Fehler null (ehrlicher Leerwert,
// kein Raten). Die Tabelle wird NIE aus dem Dateisystem gelesen (sie liegt im
// GitHub-Datenrepo, nicht im Bundle).
let entityCache = null; // { time, addresses|null }
async function loadEntityTable() {
  if (entityCache && Date.now() - entityCache.time < CACHE_MS) return entityCache.addresses;
  let addresses = null;
  if (process.env.GITHUB_HISTORY_TOKEN) {
    try {
      const { doc } = await readEntityGitHub();
      addresses = doc?.addresses ?? null;
    } catch {
      addresses = null;
    }
  }
  entityCache = { time: Date.now(), addresses };
  return addresses;
}

// Entity-Signal einer Threat (Grenze 3): regularKeySharedWith = Adressen der
// Entity-Tabelle, die mit addr einen STARKEN Join-Key teilen (rk:/sg:/eh:,
// dv: nur verifiziert — entityJoinKeys lib/entity-resolve.mjs). Domain nur als
// Anzeige-Metadatum. null ohne Tabelle.
// Hub-Guard (Fix 2026-10-04): dieselbe Semantik wie buildEntityLinks
// (lib/entity-resolve.mjs:227-243) und die Union im Walk — ein Join-Key, den
// mehr als ENTITY_JOIN_KEY_HUB (20) Adressen tragen (Börsen-/Faucet-Hubs),
// vereinigt nie und wird hier ignoriert. Bisher vereinigte das Anzeige-Signal
// gegen Hubs, während der Walk sie ausschloss (Divergenz /api/check-Anzeige
// vs. Walk-Union).
// Exportiert für Fixture-Tests (lib/threats-service.test.mjs) — Muster
// api/flow-state.js:73-75 'Exportiert für Fixture-Tests'.
export function buildEntitySignal(addr, addresses) {
  if (!addresses || typeof addresses !== "object") return null;
  const snap = addresses[addr];
  if (!snap) return null;
  const own = new Set(entityJoinKeys(addr, { addresses }));
  // Besitzerzahl je Join-Key über die ganze Tabelle zählen (Hub-Erkennung).
  const keysByAddr = new Map();
  const owners = new Map(); // key -> Anzahl Adressen
  for (const a of Object.keys(addresses)) {
    const keys = entityJoinKeys(a, { addresses });
    keysByAddr.set(a, keys);
    for (const k of keys) owners.set(k, (owners.get(k) ?? 0) + 1);
  }
  const shared = [];
  for (const [other, keys] of keysByAddr) {
    if (other === addr) continue;
    if (keys.some((k) => own.has(k) && (owners.get(k) ?? 0) <= ENTITY_JOIN_KEY_HUB)) shared.push(other);
  }
  shared.sort((x, y) => (x < y ? -1 : x > y ? 1 : 0));
  return {
    regularKeySharedWith: shared,
    domain: typeof snap.domain === "string" ? snap.domain : "",
  };
}

// =====================================================================
// Wissens-Layer (merged): getThreatKnowledge + buildCheckCtx
// =====================================================================
// Vier Schichten, fail-open je Schicht (Read-Fehler/fehlender Token -> die
// Schicht liefert null und der Rest läuft weiter — ehrlicher Leerzustand,
// kein 502):
//   (1) deriveThreats()            — live aus der Köder-Historie (RPC)
//   (2) data/history.json          — Members persistierter Cluster
//   (3) data/flow-state.json       — severityByAddress/rolesByAddress
//   (4) data/entity-links.json     — loadEntityTable (nur Anzeige-Metadatum,
//       nie Flag-Quelle: entity-links fließen nie in contacts/verdict)
// Reader optional injizierbar (opts.readHistory/opts.readFlowState/
// opts.readThreats): der lokale Server (server/index.mjs) übergibt
// Datei-Reader (Threat-Store data/threats.json, data/history.json,
// data/flow-state.json), Vercel nutzt den GitHub-Transport bzw. die
// RPC-Ableitung. 60-s-Prozess-Cache wie threatsCache (:187) — nur ohne
// injizierte Reader (deren Quellen können sich lokal jederzeit ändern).
let knowledgeCache = null; // { time, knowledge } — 60-s-Prozess-Cache

const RISK_RANK = { info: 1, suspect: 2, malicious: 3 };
const SEVERITY_KEYS = new Set(["malicious", "suspect", "info"]);
const ROLE_KEYS = new Set(["source", "drainer", "collector", "relay", "unknown"]);

function isoFromMs(ms) {
  return Number.isFinite(ms) ? new Date(ms).toISOString() : null;
}

async function readHistoryLayer(readHistory) {
  try {
    const reader = typeof readHistory === "function" ? readHistory : readHistoryGitHub;
    const out = await reader();
    const list = Array.isArray(out?.list) ? out.list : Array.isArray(out) ? out : [];
    return { list };
  } catch {
    return null; // fail-open: ohne Token/bei Read-Fehler läuft der Rest weiter
  }
}

async function readFlowStateLayer(readFlowState) {
  try {
    const reader = typeof readFlowState === "function" ? readFlowState : readFlowStateGitHub;
    const out = await reader();
    const doc = out?.doc ?? out;
    if (!doc || typeof doc !== "object") return null;
    // projectFlowStateView liefert die View-Cluster inkl. bait-Filter (B2)
    // und deterministischer Sortierung — severityByAddress/rolesByAddress
    // sind die per-Adress-Werte der Live-Engine (flow-state.mjs:814-815).
    return { view: projectFlowStateView(doc) };
  } catch {
    return null; // fail-open
  }
}

export async function getThreatKnowledge(opts = {}) {
  if (
    knowledgeCache &&
    Date.now() - knowledgeCache.time < CACHE_MS &&
    typeof opts.readHistory !== "function" &&
    typeof opts.readFlowState !== "function" &&
    typeof opts.readThreats !== "function"
  ) {
    return knowledgeCache.knowledge;
  }
  const knowledge = new Map();
  const upsert = (address, patch) => {
    if (typeof address !== "string" || !address) return;
    if (baitLabels.has(address)) return; // STILL — kein Oracle, nie treffbar
    const existing = knowledge.get(address);
    if (!existing) {
      knowledge.set(address, {
        address,
        risk: patch.risk ?? "suspect",
        reason: patch.reason ?? "",
        firstSeen: patch.firstSeen ?? null,
        sources: [patch.source],
        role: patch.role ?? null,
        severity: patch.severity ?? null,
      });
      return;
    }
    if (!existing.sources.includes(patch.source)) existing.sources.push(patch.source);
    if (
      RISK_RANK[patch.risk] != null &&
      RISK_RANK[patch.risk] > (RISK_RANK[existing.risk] ?? 0)
    ) {
      existing.risk = patch.risk;
      if (patch.reason) existing.reason = patch.reason;
    }
    if (patch.severity && (!existing.severity || RISK_RANK[patch.severity] > RISK_RANK[existing.severity])) {
      existing.severity = patch.severity;
    }
    if (!existing.role && patch.role) existing.role = patch.role;
    if (patch.firstSeen && (!existing.firstSeen || patch.firstSeen < existing.firstSeen)) {
      existing.firstSeen = patch.firstSeen;
    }
  };

  // (1) deriveThreats — live-abgeleitete Threats (unverändert); lokal
  // ersetzbar durch opts.readThreats (der Server übergibt seinen
  // mtime-gepollten Threat-Store data/threats.json — derselbe
  // Wahrheitsbestand, den monitor.mjs schreibt, ohne eigene RPC-Ableitung).
  let threats = [];
  try {
    threats =
      typeof opts.readThreats === "function" ? await opts.readThreats() : await deriveThreats();
    if (!Array.isArray(threats)) threats = [];
  } catch {
    threats = [];
  }
  for (const t of threats) {
    if (!t?.address) continue;
    upsert(t.address, {
      source: "bait",
      risk: t.risk,
      reason: t.reason,
      firstSeen: t.firstSeen,
    });
  }

  // (2) data/history.json — Members persistierter Cluster. history erzwingt
  // severity 'malicious' für JELEN Cluster (lib/history.mjs:187): die
  // Members werden zu knownBad ('malicious by listing', dokumentiertes
  // Trade-off im Dateikopf). Registry-Ausschluss: Exchange-Treffer werden am
  // Ende von getThreatKnowledge aus der Map entfernt (Guard auf der
  // Wissens-Map selbst, siehe dort — nicht erst in buildCheckCtx).
  const historyLayer = await readHistoryLayer(opts.readHistory);
  if (historyLayer) {
    for (const c of historyLayer.list) {
      const members = Array.isArray(c?.members) ? c.members : [];
      const firstSeen = Number.isFinite(c?.firstSeen) && c.firstSeen > 0 ? isoFromMs(c.firstSeen) : null;
      for (const m of members) {
        upsert(m, {
          source: "history",
          risk: "malicious",
          reason: `In der öffentlichen Maliziös-Historie gelistet (${c?.label || "Cluster"}).`,
          firstSeen,
          severity: "malicious",
        });
      }
    }
  }

  // (3) data/flow-state.json — severityByAddress/rolesByAddress der Live-Engine.
  const flowLayer = await readFlowStateLayer(opts.readFlowState);
  if (flowLayer?.view) {
    for (const c of flowLayer.view.clusters) {
      const firstSeen = typeof c?.firstSeen === "string" ? c.firstSeen : null;
      const sevMap = c?.severityByAddress && typeof c.severityByAddress === "object" ? c.severityByAddress : {};
      const roleMap = c?.rolesByAddress && typeof c.rolesByAddress === "object" ? c.rolesByAddress : {};
      const addrs = new Set([...Object.keys(sevMap), ...Object.keys(roleMap)]);
      for (const addr of addrs) {
        const sev = SEVERITY_KEYS.has(sevMap[addr]) ? sevMap[addr] : null;
        const role = ROLE_KEYS.has(roleMap[addr]) ? roleMap[addr] : null;
        if (!sev && !role) continue;
        upsert(addr, {
          source: "flow-state",
          risk: sev ?? "suspect",
          reason: sev
            ? `Live-Engine: Fund-Schwere '${sev}' im persistierten Flow-State.`
            : "Live-Engine: Rolle im persistierten Flow-State.",
          firstSeen,
          severity: sev,
          role,
        });
      }
    }
  }

  // (4) data/entity-links.json — nur als Cache-Existenz; entity-Signale
  // bleiben Anzeige-Metadatum (buildEntitySignal in deriveThreats) und
  // werden HIER nie zu risk/knownBad (Regel: entity-links fließen nie in
  // contacts/verdict).
  await loadEntityTable();

  // Exchange-Registry-Ausschluss (Guard, JETZT auf der Wissens-Map selbst —
  // Prüfer-Befund 2026-10-03: der Guard existierte nur in buildCheckCtx
  // (:577), die Map, die selfListed/verdict/contacts in checkAddress,
  // server/index.mjs und buildAccountReport treibt, blieb ungefiltert;
  // legitime Exchange-Hot-Wallets, die als Members in data/history.json
  // gelandet sind, wurden als 'bad' markiert). Registry-Treffer sind per
  // Definition keine Threats: die Map wird hier für ALLE Konsumenten
  // bereinigt, buildCheckCtx behält denselben Filter als Defense-in-Depth.
  const registryMap = loadExchangeRegistry();
  if (registryMap.size > 0) {
    for (const addr of [...knowledge.keys()]) {
      if (registryMap.has(addr)) knowledge.delete(addr);
    }
  }

  const result = { knowledge, historyList: historyLayer?.list ?? null };
  if (
    typeof opts.readHistory !== "function" &&
    typeof opts.readFlowState !== "function" &&
    typeof opts.readThreats !== "function"
  ) {
    knowledgeCache = { time: Date.now(), knowledge: result };
  }
  return result;
}

// Engine-Kontext aus dem merged Wissen (beide Check-Endpunkte + Bridge):
//   knownBad   — ALLE gelisteten Adressen MINUS Exchange-Registry-Treffer
//                (Guard-Lücken-Füllung: die Registry war bisher nur
//                exchangeLabel-Quelle; der Detector-Guard in detector.mjs:326
//                ist verdrahtet, aber config.benign_* ist leer — die Registry
//                füllt diese Lücke als knownBad-Filterquelle)
//   firstSeenAt— threat-firstSeen (ISO->ms) + firstSeen aller persistierten
//                History-Cluster (Angleichung an api/advance.js:392-404:
//                Frische-Regeln brauchen das Signal für alle gelisteten Adressen)
//   history    — Seed aus Cluster-mainDrainers {tinyDests,fundedAt,
//                createdInWindow,lastLedger} wie advance.js:406-414
//                (Cross-Ledger-Sweep-Referenz für analyzeLedger)
export function buildCheckCtx(knowledgeResult) {
  const knowledge = knowledgeResult?.knowledge instanceof Map ? knowledgeResult.knowledge : new Map();
  const registry = loadExchangeRegistry();
  const knownBad = new Set();
  const firstSeenAt = new Map();
  for (const [addr, entry] of knowledge) {
    if (registry.has(addr)) continue; // Exchange-Registry-Ausschluss
    knownBad.add(addr);
    const ms = Date.parse(String(entry?.firstSeen ?? ""));
    if (Number.isFinite(ms)) firstSeenAt.set(addr, ms);
  }
  const history = new Map();
  const list = Array.isArray(knowledgeResult?.historyList) ? knowledgeResult.historyList : [];
  for (const c of list) {
    const fsRaw = c?.firstSeen;
    const fsMs = typeof fsRaw === "string" ? Date.parse(fsRaw) : Number(fsRaw);
    if (Number.isFinite(fsMs) && fsMs > 0) {
      for (const m of Array.isArray(c?.members) ? c.members : []) {
        if (typeof m !== "string" || !XRPL_ADDR_RE.test(m)) continue;
        if (baitLabels.has(m)) continue;
        if (registry.has(m)) continue; // Registry-Ausschluss konsistent auch im firstSeenAt-Seed
        if (!firstSeenAt.has(m)) firstSeenAt.set(m, fsMs);
      }
    }
    for (const d of Array.isArray(c?.mainDrainers) ? c.mainDrainers : []) {
      if (typeof d?.address !== "string" || !XRPL_ADDR_RE.test(d.address)) continue;
      if (baitLabels.has(d.address)) continue;
      if (registry.has(d.address)) continue; // dito im history-Seed (Sweep-Referenz)
      if (!history.has(d.address)) {
        history.set(d.address, {
          tinyDests: new Set(),
          fundedAt: Number(d.outDrops) || null,
          createdInWindow: false,
          lastLedger: null,
        });
      }
    }
  }
  return { knownBad, firstSeenAt, history };
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

// Rückgabe jetzt zusätzlich die Fund-Severity des bestätigten Sweeps
// (matching finding f.severity): 'malicious' nur bei CreatedNode-belegter
// Frische (lib/detector.mjs:641-642), sonst 'suspect' (reines
// firstSeenAt-Signal). checkAddress leitet daraus result.risk und das
// History-Append-Gate ab — vorher ging die Severity verloren und jeder
// bestätigte Sweep wurde als malicious eskaliert und persistiert.
export function checkDrainerSweepFromEntries(entries, toucher, touchTime) {
  const recent = Array.isArray(entries) ? entries.slice(0, SWEEP_TX_LIMIT) : [];
  const measured = measureSweepRatio(recent, toucher);
  if (!measured || measured.ratio < DEFAULT_THRESHOLDS.sweepRatio) return null;
  const firstSeenAt = new Map([[toucher, Date.parse(touchTime)]]);
  const { findings } = analyzeLedger({ transactions: recent }, { firstSeenAt });
  const confirmed = findings.find(
    (f) => f?.ruleId === "drainer-sweep" && f?.address === toucher
  );
  if (!confirmed) return null;
  const severity = confirmed.severity === "malicious" ? "malicious" : "suspect";
  return { ratio: measured.ratio, drops: measured.drops, severity };
}

// ---------- Selbst-Check (gleiche Semantik wie der lokale Server) ----------
const XRPL_ADDR_RE = /^r[1-9A-HJ-NP-Za-km-z]{24,34}$/;
const CHECK_MAX_TX = 300;
const checkCache = new Map();

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
    if (tx.Account === addr) add(tx.Destination, "ausgehend", type, destTag);
    else add(tx.Account, "eingehend", type, destTag);
  }
  return out;
}

// opts nur für den lokalen Server (server/index.mjs): injizierte Datei-Reader
// (readThreats/readHistory/readFlowState) statt RPC-Ableitung und GitHub-
// Transport — dieselbe Resolver-Logik, anderer Transport. Ohne opts:
// GitHub-Transport (Vercel).
export async function checkAddress(addr, opts = {}) {
  const invalidAnswer = { error: "Ungültige oder nicht prüfbare Adresse." };
  if (!XRPL_ADDR_RE.test(addr)) return { status: 400, body: invalidAnswer };
  if (baitLabels.has(addr)) return { status: 400, body: invalidAnswer }; // generisch — kein Oracle

  const cached = checkCache.get(addr);
  if (cached && Date.now() - cached.time < CACHE_MS) return { status: 200, body: cached.result };

  try {
    const { entries, truncated } = await fetchAccountTxs(addr, CHECK_MAX_TX);
    // Merged Wissen statt nur deriveThreats: persistierte Quellen
    // (history/flow-state) erreichen verdict/selfListed/contacts jetzt.
    const knowledgeResult = await getThreatKnowledge(opts);
    const threatByAddress = knowledgeResult.knowledge;

    // contacts: strikt DIREKTE Gegenparteien der geprüften Adresse
    // (counterpartiesOf) — entity-verknüpfte Nicht-Gegenparteien fließen
    // nie ein (bestehende Semantik, unverändert). Tag-Feld (additiv): ist
    // die GEPÜFTE Adresse ein Registry-Multi-User-Konto, zeigt die
    // Gegenpartei-Zeile das Hosted-Sub-Konto des geprüften Kontos —
    // destinationTag bei eingehend (tx.DestinationTag), sourceTag bei
    // ausgehend (SourceTag, rein informativ). Auf Gegenparteien-Adressen
    // wäre ein Tag-Feld toter Code: Registry-Adressen werden aus der
    // Wissens-Map ausgeschlossen (:573-578) und erscheinen daher nie als
    // contact — deshalb wird es hier NUR auf der geprüften Seite getragen.
    const contacts = [];
    const registryMap = loadExchangeRegistry();
    const hostedSelf = registryMap.get(addr) ?? null;
    const hostedIdentities = new Set(); // Identitäten des geprüften Hosted-Kontos
    for (const entry of entries) {
      if (entry?.validated === false) continue;
      const tx = entry.tx_json ?? entry.tx ?? entry;
      if (!tx) continue;
      const time = timeOf(entry);
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

    const selfListed = threatByAddress.has(addr);
    const result = {
      address: addr,
      network: NETWORK,
      checkedTxCount: entries.length,
      truncated,
      selfListed,
      // Hosted-Account-Verfeinerung (additiv, nur bei Registry-Treffer der
      // geprüften Adresse): exchange + requireDestTag (Anzeige-Hinweis) und
      // transit (>= 2 verschiedene Tag-Identitäten eingehender Zahlungen —
      // "kein Tag" zählt als eigene Identität, lib/tag-identity.mjs).
      // Kein Score-/verdict-Einfluss (15/5 Pkt Formel unverändert).
      ...(hostedSelf
        ? {
            hostedAccount: {
              exchange: hostedSelf.exchange || null,
              requireDestTag: hostedSelf.requireDestTag === true,
              transit: hostedIdentities.size >= 2,
            },
          }
        : {}),
      // selfListed -> 'bad' VOR der contacts-Verzweigung: eine selbst
      // gelistete Adresse ohne Kontakte war bisher 'clean' und widersprach
      // buildAccountReport (der auf denselben Daten 'bad' liefert).
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
          : NETWORK === "testnet"
            ? "Prüfung läuft gegen das Testnet — echte Community-Adressen existieren meist nur im Mainnet."
            : null,
    };
    if (drainerHit) {
      // Vertrag (identisch zu Unit A): drainer=true, sweepRatio, risk,
      // Reason-Marker "Drainer-Sweep:". risk folgt der Fund-Severity des
      // Detektors: 'malicious' nur bei CreatedNode-belegter Frische, sonst
      // 'suspect' (lib/detector.mjs:641-642) — vorher eskalierte Unit B
      // JEDEN bestätigten Sweep auf 'malicious'.
      result.drainer = true;
      result.sweepRatio = drainerHit.ratio;
      result.risk = drainerHit.severity;
      result.reason = `Drainer-Sweep: frisch finanziert und ${Math.round(drainerHit.ratio * 100)} % der Balance an ein Ziel abgeräumt.`;
      // Best-effort-Append in die öffentliche Historie über den BESTEHENDEN
      // Merge-/Save-Pfad (lib/history.mjs) — NUR bei Fund-Severity
      // 'malicious' (Append-Gate, Konsistenz zu lib/history.mjs:40-46:
      // suspect-Funde bleiben bewusst aus der malicious-History draußen).
      // Fail-closed ohne Token/Filter (Befund 2026-09-29, Muster
      // api/history.js:75); fehlende Persistenz kippt den Check nicht.
      if (drainerHit.severity === "malicious" && process.env.GITHUB_HISTORY_TOKEN && baitLabels.size > 0) {
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
    // Fix 2026-10-04: msg (Upstream-Fehlerdetails) wird nicht mehr in die
    // öffentliche Antwort interpoliert — generisch wie api/check/[address].js:13,
    // api/ledger.js:171, api/stats.js:10. msg bleibt für die actMalformed-
    // Erkennung oben (:890) in Gebrauch.
    return { status: 502, body: { error: "Ledger-Abfrage fehlgeschlagen." } };
  }
}
