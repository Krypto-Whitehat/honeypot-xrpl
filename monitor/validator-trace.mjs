// monitor/validator-trace.mjs — Dauer-Recorder für den Validator-Trace (dUNL, ledger-genau).
//
// Start: node monitor/validator-trace.mjs   (Node >= 22: globales WebSocket)
// Optional: TRACE_RUN_SECONDS=300 (Testlauf, danach sauber beenden)
//
// Quellen: Validations-Stream + Ledger-Stream von s1.ripple.com (Fallback xrplcluster.com).
// dUNL: signierte Ripple-Validator-Liste (vl.ripple.com), Abbildung über xrpscan-Registry.
// Speicher: data/validator-trace/YYYY-MM-DD.json (atomar), Aufbewahrung 365 Tage.
// Detail-Abruf (Tx-Typen/Amendments) NUR für Ledger mit Incidents, seriell, gedeckelt.
//
// Ehrlicher Rahmen: Der Recorder kann erst ab SEINEM Start beobachten. "Historie" ist die
// Zeit seit Inbetriebnahme, nicht rückwirkend. Er muss dauerhaft laufen, um lückenlos zu sein.
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { createTracker } from "../lib/validator-trace.mjs";
import { decodeValidatorList, nodePublicB58 } from "../lib/validator-health.mjs";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const DATA_DIR = path.join(ROOT, "data", "validator-trace");
const RETENTION_DAYS = 365;
const RIPPLE_EPOCH = 946684800;
const WSS = ["wss://s1.ripple.com", "wss://xrplcluster.com"];
const VL_URL = "https://vl.ripple.com";
const REGISTRY_URL = "https://api.xrpscan.com/api/v1/validatorregistry";
const DETAIL_QUEUE_MAX = 50;
const FLUSH_MS = 30000;
const RUN_SECONDS = Number(process.env.TRACE_RUN_SECONDS) || 0;

const log = (...a) => console.log(new Date().toISOString(), ...a);
const toMs = (rippleSec) => (Number(rippleSec) + RIPPLE_EPOCH) * 1000;
const dayOf = (ms) => new Date(ms).toISOString().slice(0, 10);

// ---------- dUNL-Mitglieder ----------
async function loadMembers() {
  const vlJson = await (await fetch(VL_URL, { signal: AbortSignal.timeout(10000) })).json();
  const vl = decodeValidatorList(vlJson);
  if (!vl || !vl.keys.length) throw new Error("Validator-Liste leer oder nicht lesbar");
  const reg = await (await fetch(REGISTRY_URL, { signal: AbortSignal.timeout(10000) })).json();
  const byMaster = new Map(reg.filter((r) => r && r.master_key).map((r) => [r.master_key, r]));
  const members = [];
  const ephemeralToMaster = new Map();
  const unmatched = [];
  for (const hex of vl.keys) {
    const master = nodePublicB58(hex);
    const r = master && byMaster.get(master);
    if (!r) { unmatched.push(hex.slice(0, 12)); continue; }
    members.push(master);
    if (typeof r.ephemeral_key === "string") ephemeralToMaster.set(r.ephemeral_key, master);
  }
  return { members, ephemeralToMaster, listed: vl.keys.length, sequence: vl.sequence, unmatched };
}

// ---------- Tagesdateien ----------
const days = new Map(); // date -> Tagesobjekt im Speicher
function dayObj(date) {
  if (!days.has(date)) {
    const file = path.join(DATA_DIR, date + ".json");
    let obj = null;
    try { obj = JSON.parse(fs.readFileSync(file, "utf8")); } catch { obj = null; }
    days.set(date, obj ?? { date, ledgers: 0, quorumFail: 0, validators: {}, incidents: [] });
  }
  return days.get(date);
}
let MEMBERS = [];
function recordResult(r, detailNote) {
  const d = dayObj(dayOf(r.closeMs));
  d.ledgers += 1;
  if (!r.hasQuorum) d.quorumFail += 1;
  const bad = new Set(r.incidents.map((i) => i.master));
  for (const m of MEMBERS) {
    const v = (d.validators[m] ??= { ok: 0, partial: 0, missed: 0, wrongHash: 0 });
    if (!bad.has(m)) v.ok++;
  }
  for (const inc of r.incidents) {
    const v = d.validators[inc.master];
    if (inc.type === "missed") v.missed++;
    else if (inc.type === "partial") v.partial++;
    else if (inc.type === "wrong-hash") v.wrongHash++;
    d.incidents.push({ l: r.ledgerIndex, m: inc.master, t: r.closeMs, type: inc.type, r: inc.reasons, n: detailNote || undefined });
  }
}
function flush() {
  fs.mkdirSync(DATA_DIR, { recursive: true });
  for (const [date, obj] of days) {
    const file = path.join(DATA_DIR, date + ".json");
    const tmp = file + ".tmp";
    fs.writeFileSync(tmp, JSON.stringify(obj));
    fs.renameSync(tmp, file);
  }
}
function prune() {
  if (!fs.existsSync(DATA_DIR)) return;
  const cutoff = Date.now() - RETENTION_DAYS * 86400000;
  for (const f of fs.readdirSync(DATA_DIR)) {
    if (!/^\d{4}-\d{2}-\d{2}\.json$/.test(f)) continue;
    if (Date.parse(f.slice(0, 10)) < cutoff) { fs.unlinkSync(path.join(DATA_DIR, f)); log("pruned", f); }
  }
}

// ---------- WebSocket ----------
let ws = null;
let rpcId = 100;
const rpcPending = new Map();
let tracker = null;
let stats = { validations: 0, ledgers: 0, unknown: 0, connects: 0 };
let detailQueue = [];
let detailBusy = false;

function rpc(cmd, timeoutMs = 20000) {
  return new Promise((resolve, reject) => {
    if (!ws || ws.readyState !== 1) return reject(new Error("keine Verbindung"));
    const id = ++rpcId;
    const t = setTimeout(() => { rpcPending.delete(id); reject(new Error("timeout")); }, timeoutMs);
    rpcPending.set(id, (m) => { clearTimeout(t); m.error ? reject(new Error(m.error)) : resolve(m.result); });
    ws.send(JSON.stringify({ ...cmd, id }));
  });
}

async function fetchDetail(ledgerIndex) {
  const r = await rpc({ command: "ledger", ledger_index: ledgerIndex, transactions: true, expand: true });
  const txs = Array.isArray(r?.ledger?.transactions) ? r.ledger.transactions : [];
  const types = [...new Set(txs.map((t) => t.TransactionType).filter(Boolean))];
  const amendments = txs.filter((t) => t.TransactionType === "EnableAmendment").map((t) => t.Amendment).filter(Boolean);
  const unlModify = txs.some((t) => t.TransactionType === "UNLModify");
  return { types, amendments, unlModify };
}

// Serielle Detail-Warteschlange: Ergebnisse mit Incidents bekommen Ledger-Details vor dem Speichern.
function enqueue(result) {
  if (!result.detailNeeded) { recordResult(result); return; }
  if (detailQueue.length >= DETAIL_QUEUE_MAX) { recordResult(result, "detail-skipped"); return; }
  detailQueue.push(result);
  drainDetails();
}
async function drainDetails() {
  if (detailBusy) return;
  detailBusy = true;
  while (detailQueue.length) {
    const r = detailQueue.shift();
    let note;
    try {
      const det = await fetchDetail(r.ledgerIndex);
      tracker.attachDetail(r, det);
    } catch (e) {
      tracker.attachDetail(r, { types: [], amendments: [], unlModify: false });
      note = "detail-unavailable";
    }
    recordResult(r, note);
  }
  detailBusy = false;
}

function onMessage(ev) {
  let m;
  try { m = JSON.parse(ev.data); } catch { return; }
  if (m.id && rpcPending.has(m.id)) { const cb = rpcPending.get(m.id); rpcPending.delete(m.id); cb(m); return; }
  if (m.type === "validationReceived") {
    stats.validations++;
    tracker.onValidation({
      signingKey: m.validation_public_key,
      ledgerIndex: Number(m.ledger_index),
      ledgerHash: m.ledger_hash,
      full: m.full !== false,
      t: toMs(m.signing_time),
    });
  } else if (m.type === "ledgerClosed") {
    stats.ledgers++;
    tracker.onLedger({ ledgerIndex: Number(m.ledger_index), hash: m.ledger_hash, closeMs: toMs(m.ledger_time), txCount: Number(m.txn_count) || 0 });
  }
}

function connect(urlIdx = 0, backoff = 1000) {
  const url = WSS[urlIdx % WSS.length];
  ws = new WebSocket(url);
  ws.onopen = () => {
    stats.connects++;
    log("verbunden", url);
    backoff = 1000;
    ws.send(JSON.stringify({ id: 1, command: "subscribe", streams: ["validations", "ledger"] }));
  };
  ws.onmessage = onMessage;
  ws.onclose = () => {
    log("getrennt, neuer Versuch", WSS[(urlIdx + 1) % WSS.length]);
    setTimeout(() => connect(urlIdx + 1, Math.min(backoff * 2, 60000)), backoff);
  };
  ws.onerror = () => {};
}

// ---------- Start ----------
async function main() {
  const dunl = await loadMembers();
  log("dUNL", dunl.members.length, "von", dunl.listed, "zugeordnet, Sequenz", dunl.sequence, dunl.unmatched.length ? "unzugeordnet " + dunl.unmatched.join(",") : "");
  MEMBERS = dunl.members;
  tracker = createTracker({ members: dunl.members, ephemeralToMaster: dunl.ephemeralToMaster });
  prune();
  connect();
  const evalTimer = setInterval(() => {
    for (const r of tracker.evaluate(Date.now())) enqueue(r);
  }, 5000);
  const flushTimer = setInterval(flush, FLUSH_MS);
  const statTimer = setInterval(() => {
    const s = tracker.stats();
    log(`validations=${stats.validations} ledgers=${stats.ledgers} Nicht-dUNL-Signaturen=${s.nonMemberSigners} offen=${s.pendingLedgers} bewertet=${s.lastEvaluated}`);
  }, 60000);
  const stop = () => {
    clearInterval(evalTimer); clearInterval(flushTimer); clearInterval(statTimer);
    flush();
    if (ws) ws.close();
    log("beendet, gespeichert");
    process.exit(0);
  };
  process.on("SIGINT", stop);
  process.on("SIGTERM", stop);
  if (RUN_SECONDS) setTimeout(stop, RUN_SECONDS * 1000);
}

main().catch((e) => { console.error("Fehler:", e.message); process.exit(1); });
