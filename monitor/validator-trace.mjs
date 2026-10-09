// monitor/validator-trace.mjs — Dauer-Recorder für den Validator-Trace (dUNL, ledger-genau).
//
// Start:   node monitor/validator-trace.mjs          (Node >= 22: globales WebSocket)
// Testlauf: TRACE_RUN_SECONDS=300 node monitor/validator-trace.mjs
//
// Speicher:
//   - mit GITHUB_HISTORY_TOKEN: data/validator-trace/YYYY-MM-DD.json per API im PRIVATEN Daten-Repo
//     (lib/validator-trace-store.mjs), Flush alle 5 min, nur geänderte Tage.
//   - ohne Token: Dateien in TRACE_DATA_DIR (Standard data/validator-trace), Flush alle 30 s.
//     Der Workflow klont das Daten-Repo und committet diesen Ordner per Deploy-Key.
// Lücken: Kommt nach einem Ledger-Index ein größerer Sprung, wird die fehlende Spanne als
// 'gap' gespeichert. Ohne diese Markierung sähe Stille wie 'alle Validatoren ok' aus.
// Aufbewahrung: 365 Tage (lokal: Dateien löschen, remote: pruneRemote einmal täglich).
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { createTracker } from "../lib/validator-trace.mjs";
import { decodeValidatorList, nodePublicB58 } from "../lib/validator-health.mjs";
import { saveDayRemote, loadDayRemote, pruneRemote, traceTokenConfigured } from "../lib/validator-trace-store.mjs";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const DATA_DIR = process.env.TRACE_DATA_DIR || path.join(ROOT, "data", "validator-trace");
const REMOTE = traceTokenConfigured();
const RETENTION_DAYS = 365;
const RIPPLE_EPOCH = 946684800;
const WSS = ["wss://s1.ripple.com", "wss://xrplcluster.com"];
const VL_URL = "https://vl.ripple.com";
const REGISTRY_URL = "https://api.xrpscan.com/api/v1/validatorregistry";
const DETAIL_QUEUE_MAX = 50;
const FLUSH_MS = REMOTE ? 300000 : 30000;
const RUN_SECONDS = Number(process.env.TRACE_RUN_SECONDS) || 0;

const log = (...a) => console.log(new Date().toISOString(), ...a);
const toMs = (rippleSec) => (Number(rippleSec) + RIPPLE_EPOCH) * 1000;
const dayOf = (ms) => new Date(ms).toISOString().slice(0, 10);

// ---------- dUNL-Mitglieder ----------
async function loadMembers() {
  const vl = decodeValidatorList(await (await fetch(VL_URL, { signal: AbortSignal.timeout(10000) })).json());
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

// ---------- Tagesobjekte ----------
const days = new Map();   // date -> Tagesobjekt
const dirty = new Set();  // Daten, die beim nächsten Flush geschrieben werden müssen
let lastLedger = null;    // letzter gesehener Ledger-Index (für Lückenerkennung)

function emptyDay(date) {
  return { date, ledgers: 0, quorumFail: 0, validators: {}, incidents: [], gaps: [], lastLedger: null, firstMs: null, lastMs: null, hourly: {} };
}
function dayObj(date) {
  if (!days.has(date)) {
    let obj = null;
    if (!REMOTE) {
      try { obj = JSON.parse(fs.readFileSync(path.join(DATA_DIR, date + ".json"), "utf8")); } catch { obj = null; }
    }
    if (obj) {
      obj.gaps ??= []; obj.incidents ??= []; obj.validators ??= {}; obj.ledgers ??= 0; obj.quorumFail ??= 0;
      obj.hourly ??= {}; obj.firstMs ??= null; obj.lastMs ??= null;
    }
    days.set(date, obj ?? emptyDay(date));
  }
  return days.get(date);
}
let MEMBERS = [];
function recordResult(r, detailNote) {
  const date = dayOf(r.closeMs);
  const d = dayObj(date);
  d.ledgers += 1;
  if (!r.hasQuorum) d.quorumFail += 1;
  // Aufzeichnungsspanne + Stunden-Buckets: Stundenzähler machen die Overlay-
  // Zusammenfassung fenster-genau (Tageszähler können das nicht leisten).
  if (!d.firstMs || r.closeMs < d.firstMs) d.firstMs = r.closeMs;
  if (!d.lastMs || r.closeMs > d.lastMs) d.lastMs = r.closeMs;
  const hk = Math.floor(r.closeMs / 3600000);
  const hb = (d.hourly[hk] ??= { l: 0, v: {} });
  hb.l += 1;
  const bad = new Set(r.incidents.map((i) => i.master));
  for (const m of MEMBERS) {
    const v = (d.validators[m] ??= { ok: 0, partial: 0, missed: 0, wrongHash: 0 });
    const hv = (hb.v[m] ??= { ok: 0, partial: 0, missed: 0, wrongHash: 0 });
    if (!bad.has(m)) { v.ok++; hv.ok++; }
  }
  for (const inc of r.incidents) {
    const v = d.validators[inc.master];
    const hv = hb.v[inc.master];
    if (inc.type === "missed") { v.missed++; hv.missed++; }
    else if (inc.type === "partial") { v.partial++; hv.partial++; }
    else if (inc.type === "wrong-hash") { v.wrongHash++; hv.wrongHash++; }
    d.incidents.push({ l: r.ledgerIndex, m: inc.master, t: r.closeMs, type: inc.type, r: inc.reasons, n: detailNote || undefined });
  }
  d.lastLedger = r.ledgerIndex;
  dirty.add(date);
}

// Lokal: alle Tage schreiben (atomar). Remote: nur geänderte Tage, Fehler bleiben dirty.
async function flush() {
  if (REMOTE) {
    for (const date of [...dirty]) {
      try { await saveDayRemote(days.get(date)); dirty.delete(date); }
      catch (e) { log("Speichern fehlgeschlagen (", date, "), neuer Versuch im nächsten Takt:", e.message); }
    }
    return;
  }
  fs.mkdirSync(DATA_DIR, { recursive: true });
  for (const date of dirty) {
    const file = path.join(DATA_DIR, date + ".json");
    const tmp = file + ".tmp";
    fs.writeFileSync(tmp, JSON.stringify(days.get(date)));
    fs.renameSync(tmp, file);
  }
  dirty.clear();
}

function pruneLocal() {
  if (!fs.existsSync(DATA_DIR)) return;
  const cutoff = Date.now() - RETENTION_DAYS * 86400000;
  for (const f of fs.readdirSync(DATA_DIR)) {
    if (!/^\d{4}-\d{2}-\d{2}\.json$/.test(f)) continue;
    if (Date.parse(f.slice(0, 10)) < cutoff) { fs.unlinkSync(path.join(DATA_DIR, f)); log("gelöscht (Aufbewahrung)", f); }
  }
}

// ---------- WebSocket ----------
let ws = null;
let rpcId = 100;
const rpcPending = new Map();
let tracker = null;
const stats = { validations: 0, ledgers: 0, connects: 0 };
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
      tracker.attachDetail(r, await fetchDetail(r.ledgerIndex));
    } catch {
      tracker.attachDetail(r, { types: [], amendments: [], unlModify: false });
      note = "detail-unavailable";
    }
    recordResult(r, note);
  }
  detailBusy = false;
}

function onLedgerClosed(m) {
  const idx = Number(m.ledger_index);
  if (lastLedger !== null && idx > lastLedger + 1) {
    const from = lastLedger + 1, to = idx - 1;
    const d = dayObj(dayOf(toMs(m.ledger_time)));
    d.gaps.push({ from, to, t: toMs(m.ledger_time), reason: "stream-gap" });
    dirty.add(d.date);
    log("Lücke in der Aufzeichnung:", from, "–", to);
  }
  if (lastLedger === null || idx > lastLedger) lastLedger = idx;
  tracker.onLedger({ ledgerIndex: idx, hash: m.ledger_hash, closeMs: toMs(m.ledger_time), txCount: Number(m.txn_count) || 0 });
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
    onLedgerClosed(m);
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

// Remote-Start: heutiger und gestriger Tag werden geladen, damit Lücken-Erkennung und Zähler
// über Neustarts hinweg stimmen. Ein Lesefehler stoppt den Start (keine stille Lücke).
async function preloadRemote() {
  const today = dayOf(Date.now());
  const yesterday = dayOf(Date.now() - 86400000);
  for (const date of [yesterday, today]) {
    const doc = await loadDayRemote(date);
    if (doc) { days.set(date, doc); }
    const last = doc?.lastLedger;
    if (Number.isFinite(last)) lastLedger = lastLedger === null ? last : Math.max(lastLedger, last);
  }
}

// ---------- Start ----------
async function main() {
  log(REMOTE ? "Speicher: GitHub (Daten-Repo), Flush alle 5 min" : "Speicher: lokal data/validator-trace, Flush alle 30 s");
  const dunl = await loadMembers();
  log("dUNL", dunl.members.length, "von", dunl.listed, "zugeordnet, Sequenz", dunl.sequence, dunl.unmatched.length ? "unzugeordnet " + dunl.unmatched.join(",") : "");
  MEMBERS = dunl.members;
  tracker = createTracker({ members: dunl.members, ephemeralToMaster: dunl.ephemeralToMaster });
  if (REMOTE) await preloadRemote();
  else pruneLocal();
  connect();
  const evalTimer = setInterval(() => {
    for (const r of tracker.evaluate(Date.now())) enqueue(r);
  }, 5000);
  const flushTimer = setInterval(() => { flush(); }, FLUSH_MS);
  const pruneTimer = setInterval(() => { if (REMOTE) pruneRemote().catch(() => {}); else pruneLocal(); }, 86400000);
  const statTimer = setInterval(() => {
    const s = tracker.stats();
    log(`validations=${stats.validations} ledgers=${stats.ledgers} Nicht-dUNL-Signaturen=${s.nonMemberSigners} offen=${s.pendingLedgers} bewertet=${s.lastEvaluated}`);
  }, 60000);
  let stopping = false;
  const stop = async () => {
    if (stopping) return;
    stopping = true;
    clearInterval(evalTimer); clearInterval(flushTimer); clearInterval(statTimer); clearInterval(pruneTimer);
    await flush();
    if (ws) ws.close();
    log("beendet", dirty.size ? "(" + dirty.size + " Tage nicht gespeichert)" : ", gespeichert");
    process.exit(0);
  };
  process.on("SIGINT", stop);
  process.on("SIGTERM", stop);
  if (RUN_SECONDS) setTimeout(stop, RUN_SECONDS * 1000);
}

main().catch((e) => { console.error("Fehler:", e.message); process.exit(1); });
