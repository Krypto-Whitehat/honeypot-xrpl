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
import { addLoadSample, createTracker } from "../lib/validator-trace.mjs";
import { classifyShape, createShapeTracker, SIGNATURE_TAGS } from "../lib/tx-forensics.mjs";
import { decodeValidatorList, nodePublicB58 } from "../lib/validator-health.mjs";
import { saveDayRemote, loadDayRemote, pruneRemote, traceTokenConfigured, normalizeDay } from "../lib/validator-trace-store.mjs";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const DATA_DIR = process.env.TRACE_DATA_DIR || path.join(ROOT, "data", "validator-trace");
const REMOTE = traceTokenConfigured();
const RETENTION_DAYS = 365;
const RIPPLE_EPOCH = 946684800;
// Validations-Stream: nur xrpld-Server liefern ihn (Clio wie honeycluster kann ihn
// NICHT — ein Clio-Fallback würde Ledger ohne Validations sehen und fälschlich
// 'alle verpasst' aufzeichnen). s1.ripple.com ist laut xrpl.org "not for sustained
// or business use" — ein Dauer-Stream ist genau das, daher xrplcluster (InFTF).
// Env TRACE_WSS (Komma-Liste) erlaubt einen anderen xrpld-Endpunkt ohne Code-Änderung.
const WSS = (process.env.TRACE_WSS || "wss://xrplcluster.com").split(",").map((s) => s.trim()).filter(Boolean);
const VL_URL = "https://vl.ripple.com";
const REGISTRY_URL = "https://api.xrpscan.com/api/v1/validatorregistry";
const DETAIL_QUEUE_MAX = 50;
// Transaktions-Forensik (die Form der Tx je Ledger) läuft über den "transactions"-Stream mit —
// ohne zusätzliche Ledger-Abfragen. Env TRACE_TX_SHAPE=0 schaltet sie ab (dann fehlt die Ebene
// vollständig und die Retrace weist das als Datenlücke aus, statt "keine Auffälligkeit" zu sagen).
const TX_SHAPE = process.env.TRACE_TX_SHAPE !== "0";
// Forensik-Detail je Ledger mit Abweichung. Der Deckel schützt die Tagesdatei; bei Erreichen
// wird die älteste Forensik verworfen und das offen markiert (nie still).
const LEDGER_STATS_CAP = 6000;
// Ledger-Ebene Anomalien inklusive der Transaktions-Signaturen: nur diese gehen in die
// Risikovergleichsrechnung ein (Wie oft fällt ein Ledger MIT dieser Form aus, im Vergleich zu
// Ledgern ohne sie). new-tx-type:* und type-burst:* sind über das Präfix zählbar.
const ANOMALY_TAGS = new Set(["no-quorum", "hash-split", "load-spike", "load-extreme", "close-gap", "amendment-activity", "unl-change", ...SIGNATURE_TAGS]);
const isAnomalyTag = (tag) => ANOMALY_TAGS.has(tag) || String(tag).startsWith("new-tx-type:") || String(tag).startsWith("type-burst:");
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
  return { date, ledgers: 0, quorumFail: 0, validators: {}, incidents: [], gaps: [], lastLedger: null, firstMs: null, lastMs: null, hourly: {},
    // Forensik + Anomalie-Zähler: die Grundlage jeder Retrace. Ohne sie ist die Frage
    // 'warum verpasst?' aus der Aufzeichnung nicht beantwortbar.
    ledgerStats: [], ledgerStatsTruncated: false, incidentLedgers: 0, anomaly: {}, anomalyFail: {},
    // Abdeckung der Transaktions-Forensik: wie viele Ledger wirklich eine Tx-Form haben und wie
    // viele erwartet, aber nicht erfasst wurden. Ohne diese Zähler wäre "keine Signatur" nicht
    // von "keine Beobachtung" zu trennen.
    shapeSeen: 0, shapeMissing: 0 };
}
function dayObj(date) {
  if (!days.has(date)) {
    let obj = null;
    if (!REMOTE) {
      try { obj = JSON.parse(fs.readFileSync(path.join(DATA_DIR, date + ".json"), "utf8")); } catch { obj = null; }
    }
    // Altbestand (vor der Forensik-Stufe) hat diese Felder nicht -> angleichen, damit die
    // Retrace sie nie als „beobachtet: 0“ missdeutet, sondern als „nicht erfasst“.
    if (obj) normalizeDay(obj);
    days.set(date, obj ?? emptyDay(date));
  }
  return days.get(date);
}
let MEMBERS = [];
function recordResult(r, detailNote) {
  const date = dayOf(r.closeMs);
  const d = dayObj(date);
  // Transaktions-Forensik vor der Zählung: die FORM der Tx ist die Ledger-seitige Mitursache
  // (Fächerung eines Drainers, Orderbuch-Flut, Fehlerrate, Batch-Verstärkung, Netzwerk-Ebene).
  // Sie gilt für jedes Ledger, nicht nur für die mit Abweichung — nur so ist der
  // Risikovergleich "Ausfallwahrscheinlichkeit mit Signatur gegen ohne" überhaupt möglich.
  const shapeRes = TX_SHAPE ? shapeTracker.commit(r.ledgerIndex) : null;
  const shapeTags = shapeRes ? classifyShape(shapeRes.form, shapeRes.base).map((x) => x.tag) : [];
  if (shapeRes?.sweep) shapeTags.push("sweep-window");
  if (shapeTags.length) {
    r.ledgerTags = [...new Set([...(r.ledgerTags ?? []), ...shapeTags])];
    for (const inc of r.incidents) inc.reasons = [...new Set([...(inc.reasons ?? []), ...shapeTags])];
  }
  // Ehrliche Lücke statt stiller Null: ein Ledger mit Tx, deren Form aber nicht beobachtet
  // wurde, ist "nicht erfasst" — ein Ledger ohne Tx ist dagegen wirklich leer.
  const shapeSeenNow = Boolean(shapeRes?.form);
  if (TX_SHAPE && shapeSeenNow) d.shapeSeen += 1;
  else if (TX_SHAPE && r.txCount > 0) d.shapeMissing += 1;
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
  // Last-Achse je Ledger (nicht nur je Ausfall-Ledger): die Ausfallrate pro Tx-Stufe ist die
  // einzige Zahl, die einem Betreiber sagt, ab welcher Last sein Knoten zurueckfaellt - und ob
  // dieselbe Last bei den anderen durchgeht.
  addLoadSample(d, r.txCount, [...bad]);
  for (const m of MEMBERS) {
    const v = (d.validators[m] ??= { ok: 0, partial: 0, missed: 0, wrongHash: 0, noQuorum: 0 });
    const hv = (hb.v[m] ??= { ok: 0, partial: 0, missed: 0, wrongHash: 0, noQuorum: 0 });
    if (!bad.has(m)) { v.ok++; hv.ok++; }
  }
  for (const inc of r.incidents) {
    const v = d.validators[inc.master];
    const hv = hb.v[inc.master];
    if (inc.type === "missed") { v.missed++; hv.missed++; }
    else if (inc.type === "partial") { v.partial++; hv.partial++; }
    else if (inc.type === "wrong-hash") { v.wrongHash++; hv.wrongHash++; }
    else if (inc.type === "no-quorum") { v.noQuorum = (v.noQuorum ?? 0) + 1; hv.noQuorum = (hv.noQuorum ?? 0) + 1; }
    d.incidents.push({ l: r.ledgerIndex, m: inc.master, t: r.closeMs, type: inc.type, r: inc.reasons, n: detailNote || undefined });
  }
  // Forensik je Ledger mit Abweichung: Quorum-Rand, Hash-Spaltung, Close-Abstand, Last und
  // die Betroffenheit je Typ. Das ist der Unterschied zwischen "Validator hat verpasst" und
  // "warum er verpasst hat".
  if (r.incidents.length) {
    d.incidentLedgers += 1;
    if (d.ledgerStats.length >= LEDGER_STATS_CAP) { d.ledgerStats.shift(); d.ledgerStatsTruncated = true; }
    const f = r.forensics ?? {};
    d.ledgerStats.push({
      l: r.ledgerIndex, t: r.closeMs,
      v: f.votes ?? 0, need: f.needed ?? 0, top: f.topVotes ?? 0, mg: f.margin ?? 0,
      sp: f.runnerVotes ?? 0, gap: r.closeGapMs ?? null, gmed: r.medianGap ?? null,
      tx: r.txCount ?? 0, med: r.medianTx ?? 0,
      c: f.counts ?? { missed: 0, partial: 0, wrongHash: 0, noQuorum: 0 },
      // Tx-Form und die Belege der Signaturen, die in diesem Ledger feuerten. Die Konto-Adresse
      // selbst wird nicht gespeichert: die Signatur ist eine Form-Aussage, kein Konto-Report.
      sh: shapeRes?.form ? (({ n, s, d: dst, fo, fd, fa, fl, ac, oc, nf, bt, bi, fx, fm, fs }) => ({ n, s, d: dst, fo, fd, fa, fl, ac, oc, nf, bt, bi, fx, fm, fs }))(shapeRes.form) : null,
      sev: shapeRes ? Object.fromEntries(classifyShape(shapeRes.form, shapeRes.base).map((x) => [x.tag, x.evidence])) : {},
      sweep: shapeRes?.sweep ?? null,
    });
  }
  // Anomalie-Zähler auf Ledger-Ebene: Nenner und Zähler für den Risikovergleich. Ohne sie wäre
  // jede Ursache eine Einzelbeobachtung ohne Vergleichswert.
  for (const tag of r.ledgerTags ?? []) {
    if (!isAnomalyTag(tag)) continue;
    d.anomaly[tag] = (d.anomaly[tag] ?? 0) + 1;
    if (r.incidents.length) d.anomalyFail[tag] = (d.anomalyFail[tag] ?? 0) + 1;
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
const shapeTracker = createShapeTracker();
const stats = { validations: 0, ledgers: 0, connects: 0, txShape: 0 };
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
  } else if (m.type === "transaction" && TX_SHAPE) {
    stats.txShape++;
    // Tx dem Ledger zuordnen, in dem sie validiert wurden. Fehlt die Indexangabe, gehört sie
    // zum zuletzt geschlossenen Ledger — nie zu einem erfundenen.
    shapeTracker.addTxTo(Number(m.ledger_index ?? lastLedger), m);
  }
}

function connect(urlIdx = 0, backoff = 1000) {
  const url = WSS[urlIdx % WSS.length];
  ws = new WebSocket(url);
  ws.onopen = () => {
    stats.connects++;
    log("verbunden", url);
    backoff = 1000;
    const streams = ["validations", "ledger"];
    if (TX_SHAPE) streams.push("transactions");
    ws.send(JSON.stringify({ id: 1, command: "subscribe", streams }));
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
    // Direktes Setzen umgeht dayObj(): ohne Angleichung laufen die Forensik-Zaehler
    // dieses Tages auf NaN (in der Datei als null) und die Forensik-Liste fehlt ganz.
    if (doc) { days.set(date, normalizeDay(doc)); }
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
