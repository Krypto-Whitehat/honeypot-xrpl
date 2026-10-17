import fs from "node:fs";
import path from "node:path";
import { spawn } from "node:child_process";
import { createServer } from "node:http";
import { WebSocketServer } from "ws";
import { fileURLToPath } from "node:url";
import { decodeValidatorList, nodePublicB58 } from "../lib/validator-health.mjs";
import { quorumCriticality } from "../lib/validator-diagnose.mjs";
import { CAPTURE_EVENT_KINDS } from "../lib/validator-trace.mjs";

// scripts/trace-write-proof.mjs
//
// Nachweis, dass der Rekorder seine Schliess-Felder (ch/cl/cg/ov/mm) und den Netz-Anker
// (networkQuorum) wirklich in die Tagesdatei schreibt - und dass die Diagnose-Ebene dieselben
// Bytes liest, die der Rekorder geschrieben hat.
//
// Der Rekorder laeuft als echter Kindprozess (monitor/validator-trace.mjs, unveraendert) gegen
// einen lokalen Fixture-Endpunkt. Die dUNL-Mitglieder kommen live von vl.ripple.com und dem
// Validator-Registry, damit die Validierungen echten Master-Schluesseln zugeordnet werden.
//
// Lauf: node scripts/trace-write-proof.mjs
const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const RIPPLE_EPOCH = 946684800;
const HEX64 = /^[0-9A-Fa-f]{64}$/;
const PORT = Number(process.env.TRACE_PROOF_PORT || 4477);
const WSS_URL = "ws://127.0.0.1:" + PORT;
const FIX_QUORUM = 28;

const log = (...a) => console.log(new Date().toISOString().slice(11, 23), ...a);
const hex64 = (i) => (i.toString(16).padStart(4, "0") + "A".repeat(60)).slice(0, 64).toUpperCase();
const rippleSec = (ms) => Math.floor(ms / 1000) - RIPPLE_EPOCH;

const checks = [];
const check = (name, ok, detail = "") => {
  checks.push({ name, ok, detail });
  log((ok ? "OK   " : "FEHLER ") + name + (detail ? "  " + detail : ""));
};

// ---------- echte dUNL-Mitglieder (wie der Rekorder sie liest) ----------
const vl = decodeValidatorList(await (await fetch("https://vl.ripple.com", { signal: AbortSignal.timeout(15000) })).json());
const reg = await (await fetch("https://api.xrpscan.com/api/v1/validatorregistry", { signal: AbortSignal.timeout(15000) })).json();
const byMaster = new Map(reg.filter((r) => r && r.master_key).map((r) => [r.master_key, r]));
const members = [];
const signable = [];
for (const hex of vl.keys) {
  const master = nodePublicB58(hex);
  const r = master && byMaster.get(master);
  if (!r) continue;
  members.push(master);
  if (typeof r.ephemeral_key === "string") signable.push({ master, key: r.ephemeral_key, domain: r.domain || "?" });
}
const quorum = Math.ceil(members.length * 0.8);
log("dUNL Mitglieder", members.length, "| signierbare", signable.length, "| gerechnetes Quorum", quorum);
if (members.length < 12 || signable.length < 12) { console.error("Fixture braucht mindestens 12 zuordenbare Mitglieder"); process.exit(1); }

// ---------- Fixture-Endpunkt ----------
let quorumReport = FIX_QUORUM;
let scenario = null;   // { ledgers: [...], votes: [...] }
const http = createServer();
const wss = new WebSocketServer({ server: http });
http.listen(PORT, "127.0.0.1");

function emit(ws, scenario) {
  for (const l of scenario.ledgers) {
    ws.send(JSON.stringify({ type: "ledgerClosed", ledger_index: l.index, ledger_hash: l.hash,
      ledger_time: rippleSec(l.closeMs), txn_count: l.txCount, close_resolution: 5, validated_ledgers: 1 }));
    for (const v of scenario.votes.filter((x) => x.index === l.index)) {
      ws.send(JSON.stringify({ type: "validationReceived", validation_public_key: v.key, ledger_index: v.index,
        ledger_hash: v.hash, full: true, signing_time: rippleSec(v.atMs), signature: "A".repeat(112) }));
    }
  }
}

wss.on("connection", (ws) => {
  ws.on("message", (raw) => {
    let m; try { m = JSON.parse(raw); } catch { return; }
    if (m.command === "subscribe") { ws.send(JSON.stringify({ id: m.id, result: { status: "success" }, engine_result: "tesSUCCESS" })); if (scenario) setTimeout(() => emit(ws, scenario), 300); return; }
    if (m.command === "server_info") {
      ws.send(JSON.stringify({ id: m.id, result: { info: { server_state: "full", build_version: "fixture-1.0",
        complete_ledgers: "32570-107699000", validation_quorum: quorumReport, validated_ledger: { seq: 107699000 } } }, engine_result: "tesSUCCESS" }));
      return;
    }
    if (m.command === "ledger") {
      const idx = Number(m.ledger_index);
      const l = (scenario?.ledgers ?? []).find((x) => x.index === idx);
      ws.send(JSON.stringify({ id: m.id, result: { ledger: { account_hash: hex64(9), hash: l?.hash ?? hex64(0),
        ledger_index: idx, transactions: [] } }, engine_result: "tesSUCCESS" }));
    }
  });
});

// ---------- Ersatz-Endpunkt: offen UND mit Strom (Ziel des Notrufs) ----------
// Derselbe Stoff auf einem zweiten Port: beweisbar, dass der Notruf nicht nur umschaltet,
// sondern danach wirklich wieder Ledger ankommen. Eigener Zeitanker, weil dieser Block vor
// dem Haupt-Szenario liegt.
const FIX2 = { ledgers: [], votes: [] };
const fix2Base = Date.now() - 60000;
for (let i = 0; i < 4; i++) {
  const index = 107699501 + i;
  FIX2.ledgers.push({ index, hash: hex64(index), closeMs: fix2Base + i * 1000, txCount: 10 + i });
  for (const v of signable.slice(0, quorum)) FIX2.votes.push({ index, hash: hex64(index), key: v.key, atMs: fix2Base + i * 1000 });
}
const http2 = createServer();
const wss2 = new WebSocketServer({ server: http2 });
http2.listen(PORT + 1, "127.0.0.1");
const WSS2_URL = "ws://127.0.0.1:" + (PORT + 1);
wss2.on("connection", (ws) => {
  ws.on("message", (raw) => {
    let m; try { m = JSON.parse(raw); } catch { return; }
    if (m.command === "subscribe") { ws.send(JSON.stringify({ id: m.id, result: { status: "success" }, engine_result: "tesSUCCESS" })); setTimeout(() => emit(ws, FIX2), 200); return; }
    if (m.command === "server_info") {
      ws.send(JSON.stringify({ id: m.id, result: { info: { server_state: "full", build_version: "fixture-2.0",
        complete_ledgers: "32570-107699600", validation_quorum: FIX_QUORUM, validated_ledger: { seq: 107699600 } } }, engine_result: "tesSUCCESS" }));
      return;
    }
    if (m.command === "ledger") {
      const idx = Number(m.ledger_index);
      const l = FIX2.ledgers.find((x) => x.index === idx);
      ws.send(JSON.stringify({ id: m.id, result: { ledger: { account_hash: hex64(9), hash: l?.hash ?? hex64(0),
        ledger_index: idx, transactions: [] } }, engine_result: "tesSUCCESS" }));
    }
  });
});

const waitClose = (ws) => new Promise((r) => (ws.on("close", r)));

// ---------- Rekorder-Kindprozess ----------
function runMonitor(dataDir, runSeconds, env = {}, meta = {}) {
  return new Promise((resolve) => {
    fs.rmSync(dataDir, { recursive: true, force: true });
    fs.mkdirSync(dataDir, { recursive: true });
    const child = spawn(process.execPath, [path.join(ROOT, "monitor", "validator-trace.mjs")], {
      cwd: ROOT,
      env: { ...process.env, TRACE_WSS: WSS_URL, TRACE_DATA_DIR: dataDir, TRACE_RUN_SECONDS: String(runSeconds),
        TRACE_TX_SHAPE: "0", GITHUB_HISTORY_TOKEN: "", ...env },
    });
    let out = "";
    child.stdout.on("data", (c) => { out += c; });
    child.stderr.on("data", (c) => { out += c; });
    // Der Abbruch-Weg ist ein eigener Befund: ohne den Exit-Code waere ein toter Lauf nicht
    // von einem erfolgreichen zu unterscheiden.
    child.on("exit", (code) => { meta.code = code; resolve(out); });
  });
}

const readDay = (dataDir) => {
  const files = fs.readdirSync(dataDir).filter((f) => f.endsWith(".json"));
  if (!files.length) return null;
  return JSON.parse(fs.readFileSync(path.join(dataDir, files[0]), "utf8"));
};

// ---------- Phase A: geschlossen, aber ohne beobachtetes Quorum ----------
const base = Date.now() - 90000;
const idx0 = 107699001;
scenario = { ledgers: [], votes: [] };
// Anlaufphase: 22 lueckenlose Ledger bei vollem Empfang. Die eigene Erfassungs-Basis entsteht
// erst ab voteBaselineMin (20 bewertete Ledger). Ohne sie waere der duenne Empfang in L2 eine
// Zahl ohne Vergleich - die Engine muesste ihn behaupten statt ihn zu messen.
for (let w = 22; w >= 1; w--) {
  const wIdx = idx0 - w, wClose = base - w * 5000;
  scenario.ledgers.push({ index: wIdx, hash: hex64(wIdx), closeMs: wClose, txCount: 3 });
  for (const s of signable) scenario.votes.push({ index: wIdx, key: s.key, hash: hex64(wIdx), atMs: wClose + 1000 });
}
// L0: alle signierbaren Knoten stimmen ab -> keine Abweichung (Grundlinie, kein Forensik-Eintrag)
scenario.ledgers.push({ index: idx0, hash: hex64(idx0), closeMs: base, txCount: 4 });
for (const s of signable) scenario.votes.push({ index: idx0, key: s.key, hash: hex64(idx0), atMs: base + 1000 });
// L1: Quorum steht, ein Knoten fehlt -> 'missed' bei geschlossenem Ledger
const idx1 = idx0 + 1, close1 = base + 5000;
const missing = signable[0];
scenario.ledgers.push({ index: idx1, hash: hex64(idx1), closeMs: close1, txCount: 6 });
for (const s of signable.slice(1)) scenario.votes.push({ index: idx1, key: s.key, hash: hex64(idx1), atMs: close1 + 1000 });
// L2: Ledger ist geschlossen, aber deutlich unter dem Quorum -> genau der Fall, den xrpscan
// als validiert zeigt und die Engine frueher als "network stall" etikettierte.
const idx2 = idx0 + 2, close2 = base + 10000;
const thinCount = Math.max(1, quorum - 8);
scenario.ledgers.push({ index: idx2, hash: hex64(idx2), closeMs: close2, txCount: 3 });
for (const s of signable.slice(1, 1 + thinCount)) scenario.votes.push({ index: idx2, key: s.key, hash: hex64(idx2), atMs: close2 + 1000 });
scenario.votes.push({ index: idx2, key: "rNonMemberFixtureSignerNotInTheRegistry", hash: hex64(idx2), atMs: close2 + 1200 });
// L3: zwei Indizes werden nie gesendet (idx0 + 3 und idx0 + 4 fehlen) -> Erfassungs-Luecke
// dieses Rekorders, nachgerechnet an der Index-Folge: pg = idx2, l = idx2 + 3. Der 30-s-Abstand
// bleibt als Begleitsignal stehen; er war bisher die Regel und ist live widerlegt (8 000 ms
// Abstand bei 35 von 35 gesehenen Mitgliedern, Ledger 107699231).
const idx3 = idx0 + 5, close3 = close2 + 30000;
scenario.ledgers.push({ index: idx3, hash: hex64(idx3), closeMs: close3, txCount: 2 });
for (const s of signable.slice(1, 3)) scenario.votes.push({ index: idx3, key: s.key, hash: hex64(idx3), atMs: close3 + 1000 });

const dirA = path.join(ROOT, "logs", "trace-proof-A");
const outA = await runMonitor(dirA, 30);
const dayA = readDay(dirA);
if (!dayA) { console.error("keine Tagesdatei geschrieben"); process.exit(1); }

const rows = dayA.ledgerStats ?? [];
const row = (i) => rows.find((r) => r.l === i) ?? null;
log("Forensik-Zeilen:", rows.length, "| Vorfalle:", (dayA.incidents ?? []).length);
check("Forensik-Zeilen vorhanden (L1/L2/L3)", [idx1, idx2, idx3].every((i) => row(i) !== null),
  [idx1, idx2, idx3].map((i) => "#" + i + "=" + (row(i) ? "ja" : "NEIN")).join(" "));
check("ch ist 64-stelliges Hex und gleich dem Fixture-Hash",
  [idx1, idx2, idx3].every((i) => row(i) && HEX64.test(row(i).ch ?? "") && row(i).ch === hex64(i)),
  [idx1, idx2, idx3].map((i) => "#" + i + " " + (row(i)?.ch ?? "-")).join(" "));
check("cl = true fuer alle drei Ledger (Netz hat geschlossen)",
  [idx1, idx2, idx3].every((i) => row(i)?.cl === true));
check("L2: geschlossen unter Quorum (top < need, Marge negativ)",
  row(idx2) && row(idx2).top < row(idx2).need && row(idx2).mg < 0,
  row(idx2) ? `${row(idx2).top} / ${row(idx2).need} Marge ${row(idx2).mg}` : "-");
check("L2: cg = false und pg = idx1 (lueckenlose Index-Folge, nachgerechnet)",
  row(idx2)?.cg === false && row(idx2)?.pg === idx1,
  row(idx2) ? `pg=${row(idx2).pg} l=${row(idx2).l}` : "-");
check("L3: cg = true, weil idx0+3 und idx0+4 nie gesendet wurden", row(idx3)?.cg === true,
  row(idx3) ? `pg=${row(idx3).pg} l=${row(idx3).l} gap ${row(idx3).gap} ms / Median ${row(idx3).gmed} ms` : "-");
check("L3: der Sprung ist auch als Stream-Luecke aufgezeichnet",
  (dayA.gaps ?? []).some((g) => g.reason === "stream-gap" && g.from === idx0 + 3 && g.to === idx0 + 4),
  JSON.stringify(dayA.gaps ?? []));
check("ov zaehlt Nicht-dUNL-Signierer mit (L2: ov = top + 1)",
  row(idx2) && row(idx2).ov === thinCount + 1, row(idx2) ? `ov=${row(idx2).ov} eigene=${row(idx2).v}` : "-");
check("need ist nachrechenbar: need = ceil(mm * 0.8)",
  rows.every((r) => Number.isFinite(r.mm) && r.need === Math.ceil(r.mm * 0.8)),
  rows.map((r) => `#${r.l} mm=${r.mm} need=${r.need}`).join(" "));
check("Netz-Anker geschrieben: networkQuorum = 28 vom Fixture-Endpunkt",
  dayA.networkQuorum?.quorum === FIX_QUORUM && dayA.networkQuorum?.endpoint === WSS_URL,
  JSON.stringify(dayA.networkQuorum ?? null));
check("L2 hat vote-not-observed-Vorfalle bei geschlossenem Ledger (kein Netz-Urteil)",
  (dayA.incidents ?? []).some((x) => x.l === idx2 && x.type === "vote-not-observed")
  && !(dayA.incidents ?? []).some((x) => x.l === idx2 && x.type === "no-quorum"),
  "Typen auf L2: " + [...new Set((dayA.incidents ?? []).filter((x) => x.l === idx2).map((x) => x.type))].join(", "));
check("L1 hat missed-Vorfall des fehlenden Knotens",
  (dayA.incidents ?? []).some((x) => x.l === idx1 && x.type === "missed" && x.m === missing.master),
  "Knoten " + (missing.domain || missing.master.slice(0, 10)));

// Diagnose-Ebene liest genau diese Datei: dieselben Bytes, die der Rekorder geschrieben hat.
const diag = quorumCriticality([dayA], missing.master, { range: "all" });
const byLedger = new Map(diag.rows.map((r) => [r.ledgerIndex, r]));
const verdictOf = (i) => byLedger.get(i)?.verdict ?? "-";
log("Diagnose-Verdikte:", [idx1, idx2, idx3].map((i) => "#" + i + " " + verdictOf(i)).join(" | "));
check("L1: Quorum beobachtet bei geschlossenem Ledger -> closed-quorum-observed",
  verdictOf(idx1) === "closed-quorum-observed");
check("L2: geschlossen unter Quorum, duennerer Empfang als der eigene Normalwert -> closed-reception-thin",
  verdictOf(idx2) === "closed-reception-thin");
check("L3: geschlossen mit Erfassungs-Luecke -> closed-capture-gap",
  verdictOf(idx3) === "closed-capture-gap");
check("keine Zeile behauptet 'not-closed' ohne Beleg (kein Netz-Stockungs-Befund)",
  diag.rows.every((r) => r.verdict !== "not-closed") && diag.critical === 0,
  `critical=${diag.critical}`);
check("Schliess-Bilanz: 3 geschlossen, 1 Erfassungs-Luecke, 0 offene Erfassungs-Fragen",
  diag.closed === 3 && diag.captureGaps === 1 && diag.captureGapUnknown === 0,
  `closed=${diag.closed} captureGaps=${diag.captureGaps} unknown=${diag.captureGapUnknown} unanswered=${diag.unanswered}`);
check("Erfassungs-Belege sind benannt: L2 index-basiert frei, L3 index-basiert Luecke",
  byLedger.get(idx2)?.captureGapBasis === "ledger-index" && byLedger.get(idx2)?.captureGap === false
  && byLedger.get(idx3)?.captureGapBasis === "ledger-index" && byLedger.get(idx3)?.captureGap === true,
  [idx1, idx2, idx3].map((i) => `#${i} ${byLedger.get(i)?.captureGapBasis ?? "-"}=${String(byLedger.get(i)?.captureGap)}`).join(" "));
check("Netzseite reicht bis in die Diagnose (ov = eigene + Nicht-dUNL)",
  byLedger.get(idx2)?.observedValidations === thinCount + 1,
  "ov=" + String(byLedger.get(idx2)?.observedValidations));
check("L2: eigene Empfangs-Bilanz steht in der Datei (ov, ovb, ot) und ov unter ovb",
  row(idx2)?.ov === thinCount + 1 && Number.isFinite(row(idx2)?.ovb) && row(idx2)?.ot === true && row(idx2).ov < row(idx2).ovb,
  row(idx2) ? `ov=${row(idx2).ov} ovb=${row(idx2).ovb} ot=${String(row(idx2).ot)}` : "-");
check("L1: ein fehlender Knoten ist kein duennerer Empfang (ot = false, ov = signierbare - 1)",
  row(idx1)?.ot === false && row(idx1)?.ov === signable.length - 1,
  row(idx1) ? `ov=${row(idx1).ov} ovb=${row(idx1).ovb} ot=${String(row(idx1).ot)}` : "-");
check("Erfassungs-Ereignisse werden aufgezeichnet (Art, Zeit, Index, Endpunkt)",
  (dayA.captureEvents ?? []).some((e) => typeof e.e === "string" && Number.isFinite(e.atMs) && typeof e.url === "string"),
  JSON.stringify(dayA.captureEvents ?? []));
check("Diagnose zaehlt duennen Empfang und Erfassungs-Ereignisse (L2 Empfang, L3 beides)",
  diag.receptionThin === 2 && (diag.captureEvents ?? 0) >= 1,
  `receptionThin=${diag.receptionThin} captureEvents=${diag.captureEvents}`);

// ---------- Phase B: Endpunkt meldet keinen Quorum ----------
quorumReport = 0;
scenario = null;
const dirB = path.join(ROOT, "logs", "trace-proof-B");
const outB = await runMonitor(dirB, 20, { TRACE_QUORUM_WSS: "" });
const dayB = readDay(dirB);
check("Phase B: networkQuorum bleibt null (nicht '0')", dayB?.networkQuorum === null,
  JSON.stringify(dayB?.networkQuorum ?? null));
check("Phase B: Versuch ist aufgezeichnet (attempts >= 1, samples = 0)",
  (dayB?.networkQuorumAttempts ?? 0) >= 1 && dayB?.networkQuorumSamples === 0,
  `attempts=${dayB?.networkQuorumAttempts} samples=${dayB?.networkQuorumSamples}`);
check("Phase B: Grund ist loggiert (nicht still)", /Netz-Quorum nicht meldbar/.test(outB));
check("Phase A: Grund loggiert (gemeldeter Wert)", /Netz-Quorum: 28/.test(outA));

// ---------- Phase C: Mithoerer bleibt stumm, obwohl die Verbindung offen ist ----------
// Der Betriebsbefund vom 16.10.2026: der Rekorder-Job lief, der Socket war offen, und 1 h 50
// min lang kam keine Nachricht - die Tagesdatei zeigte fuer diese Zeit nichts, und der
// Frische-Check meldete 'frisch'. Der Fixture-Endpunkt antwortet hier auf subscribe, bringt
// aber keinen Strom. Der Waechter muss die Stille erkennen, selbst trennen, neu verbinden und
// den Ausfall als Erfassungs-Ereignis 'stall' in der Tagesdatei hinterlassen.
scenario = null;
const dirC = path.join(ROOT, "logs", "trace-proof-C");
const outC = await runMonitor(dirC, 26, { TRACE_STALL_MS: "5000", TRACE_STALL_CHECK_MS: "1000", TRACE_QUORUM_WSS: "" });
const dayC = readDay(dirC);
const evC = dayC?.captureEvents ?? [];
const stallsC = evC.filter((e) => e.e === "stall");
const opensC = evC.filter((e) => e.e === "open");
const closesC = evC.filter((e) => e.e === "close");
log("Phase C Erfassungs-Ereignisse:", evC.map((e) => e.e).join(",") || "keine");
check("Phase C: Stille wird erkannt und loggiert (nicht verschluckt)", /Stream still/.test(outC),
  (outC.match(/Stream still.*/m) ?? ["(kein Log)"])[0]);
check("Phase C: 'stall' steht als Erfassungs-Ereignis in der Tagesdatei", stallsC.length >= 1,
  JSON.stringify(stallsC.slice(0, 2)));
check("Phase C: jedes Erfassungs-Ereignis gehoert zur gemeinsamen Vokabel",
  evC.length > 0 && evC.every((e) => CAPTURE_EVENT_KINDS.includes(e.e)),
  evC.map((e) => e.e).join(","));
check("Phase C: nach der Stille wird wirklich neu verbunden",
  opensC.length >= 2 && opensC.length >= stallsC.length && closesC.length >= 1,
  `open=${opensC.length} stall=${stallsC.length} close=${closesC.length}`);
check("Phase C: kein zweiter Mithoerer neben der alten Verbindung (open nie ueber stall + 1)",
  opensC.length <= stallsC.length + 1, `open=${opensC.length} stall=${stallsC.length}`);
check("Phase A/B: ohne Stille wird kein Stillstand behauptet",
  !(outA + outB).includes("Stream still") && !((readDay(dirA)?.captureEvents ?? []).some((e) => e.e === "stall")),
  "Phase A und B laufen mit der scharfen Grenze nicht in den Stillstand");

// ---------- Phase D: Haupt-Endpunkt ohne Ledger -> Ersatz-Endpunkt liefert ----------
// Betriebsbefund 2026-10-17: der Rekorder-Job lief, server_info antwortete (Netz-Quorum 28
// wurde erfasst), aber ueber eine Stunde kam kein einziger validierter Ledger. Der
// Ledger-Waechter muss auf den Ersatz umschalten und danach wieder Ledger aufzeichnen.
scenario = null;
const dirD = path.join(ROOT, "logs", "trace-proof-D");
const metaD = {};
const outD = await runMonitor(dirD, 20, { TRACE_STALL_MS: "60000", TRACE_STALL_CHECK_MS: "1000",
  TRACE_QUORUM_WSS: "", TRACE_NO_LEDGER_MS: "6000", TRACE_NO_LEDGER_EXIT_MS: "120000", TRACE_STAT_MS: "5000",
  TRACE_STREAM_FALLBACK_WSS: WSS2_URL }, metaD);
const dayD = readDay(dirD);
const evD = dayD?.captureEvents ?? [];
check("Phase D: der Notruf auf den Ersatz-Endpunkt wird loggiert", /Ersatz-Endpunkt/.test(outD),
  (outD.match(/Kein Ledger seit.*/m) ?? ["(kein Log)"])[0]);
check("Phase D: nach dem Notruf werden wieder Ledger aufgezeichnet", (dayD?.ledgers ?? 0) >= 1,
  `ledgers=${dayD?.ledgers ?? "keine"} lastLedger=${dayD?.lastLedger ?? "-"}`);
check("Phase D: der Ersatz steht in der Statistik", /Ersatz=[1-9]/.test(outD),
  (outD.match(/validations=.*Ersatz=\d+.*/m) ?? ["(kein Log)"])[0]);
check("Phase D: die Umschaltung steht als Erfassungs-Ereignis in der Tagesdatei und der Ersatz-Port ist genannt",
  evD.some((e) => e.e === "stall") && evD.some((e) => String(e.url ?? "").includes(String(PORT + 1))),
  evD.map((e) => e.e + "@" + String(e.url ?? "").split("//")[1]).join(","));
check("Phase D: der Lauf endet nicht als Abbruch, weil der Ersatz liefert", metaD.code === 0,
  "exit=" + metaD.code);

// ---------- Phase E: kein Endpunkt liefert -> der Lauf gibt die Warteschlange frei ----------
// Ein Lauf, der nichts mehr hoert, darf die Cron-Warteschlange nicht bis zum Actions-Limit
// blockieren: sonst steht das Overlay Stunden hinter der Chain. Er muss sich selbst abbrechen
// - aber erst nach dem Speichern, damit kein aufgezeichneter Stand verloren geht.
const dirE = path.join(ROOT, "logs", "trace-proof-E");
const metaE = {};
const outE = await runMonitor(dirE, 40, { TRACE_STALL_MS: "60000", TRACE_STALL_CHECK_MS: "1000",
  TRACE_QUORUM_WSS: "", TRACE_NO_LEDGER_MS: "6000", TRACE_NO_LEDGER_EXIT_MS: "9000",
  TRACE_STREAM_FALLBACK_WSS: WSS_URL }, metaE);
const dayE = readDay(dirE);
check("Phase E: ohne jeden Ledger wird der Lauf abgebrochen (kein Zombie in der Warteschlange)",
  metaE.code === 2, "exit=" + metaE.code);
check("Phase E: der Grund ist genannt, nicht verschluckt", /Abbruch: kein Ledger seit/.test(outE),
  (outE.match(/Abbruch:.*/m) ?? ["(kein Log)"])[0]);
check("Phase E: vor dem Abbruch wird gespeichert", (dayE?.captureEvents ?? []).length >= 1,
  JSON.stringify((dayE?.captureEvents ?? []).slice(0, 2)));

// ---------- Bericht ----------
console.log("");
console.log("Phase A Forensik-Zeilen (aus der geschriebenen Tagesdatei):");
for (const r of rows) {
  console.log(`  #${r.l}  ${r.top}/${r.need} Marge ${r.mg}  closed=${r.cl} cg=${r.cg} pg=${r.pg} ov=${r.ov} mm=${r.mm}  Empfang ${r.ov}/${r.ovb} ot=${r.ot}  hash ${String(r.ch).slice(0, 16)}...`);
}
console.log("");
for (const r of diag.rows) {
  console.log(`  Diagnose #${r.ledgerIndex}  ${r.verdict}  Basis ${r.closure.basis}  Erfassung ${String(r.captureGap)} (${r.captureGapBasis})  ${r.topVotes}/${r.needed} ov=${r.observedValidations}  ${r.critical ? "kritisch" : "nicht kritisch"}`);
}
const failed = checks.filter((c) => !c.ok);
console.log("");
console.log(failed.length ? `NACHWEIS FEHLERHAFT: ${failed.length} von ${checks.length}` : `NACHWEIS ERFUELLT: ${checks.length}/${checks.length}`);
http.close();
http2.close();
process.exit(failed.length ? 1 : 0);
