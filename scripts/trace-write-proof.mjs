import fs from "node:fs";
import path from "node:path";
import { spawn } from "node:child_process";
import { createServer } from "node:http";
import { WebSocketServer } from "ws";
import { fileURLToPath } from "node:url";
import { decodeValidatorList, nodePublicB58 } from "../lib/validator-health.mjs";
import { quorumCriticality } from "../lib/validator-diagnose.mjs";

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

const waitClose = (ws) => new Promise((r) => (ws.on("close", r)));

// ---------- Rekorder-Kindprozess ----------
function runMonitor(dataDir, runSeconds, env = {}) {
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
    child.on("exit", () => resolve(out));
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
// L3: Close-Abstand 30 s bei 5-s-Takt -> Erfassungs-Luecke dieses Rekorders (cg = true)
const idx3 = idx0 + 3, close3 = close2 + 30000;
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
check("L2: cg = false (kein Erfassungs-Rueckstand)", row(idx2)?.cg === false);
check("L3: cg = true (30 s Abstand bei 5 s Takt)", row(idx3)?.cg === true,
  row(idx3) ? `gap ${row(idx3).gap} ms / Median ${row(idx3).gmed} ms` : "-");
check("ov zaehlt Nicht-dUNL-Signierer mit (L2: ov = top + 1)",
  row(idx2) && row(idx2).ov === thinCount + 1, row(idx2) ? `ov=${row(idx2).ov} eigene=${row(idx2).v}` : "-");
check("need ist nachrechenbar: need = ceil(mm * 0.8)",
  rows.every((r) => Number.isFinite(r.mm) && r.need === Math.ceil(r.mm * 0.8)),
  rows.map((r) => `#${r.l} mm=${r.mm} need=${r.need}`).join(" "));
check("Netz-Anker geschrieben: networkQuorum = 28 vom Fixture-Endpunkt",
  dayA.networkQuorum?.quorum === FIX_QUORUM && dayA.networkQuorum?.endpoint === WSS_URL,
  JSON.stringify(dayA.networkQuorum ?? null));
check("L2 hat no-quorum-Vorfalle bei geschlossenem Ledger",
  (dayA.incidents ?? []).some((x) => x.l === idx2 && x.type === "no-quorum"));
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
check("L2: geschlossen unter Quorum -> closed-observation-gap (kein Netz-Befund)",
  verdictOf(idx2) === "closed-observation-gap");
check("L3: geschlossen mit Erfassungs-Luecke -> closed-capture-gap",
  verdictOf(idx3) === "closed-capture-gap");
check("keine Zeile behauptet 'not-closed' ohne Beleg (kein Netz-Stockungs-Befund)",
  diag.rows.every((r) => r.verdict !== "not-closed") && diag.critical === 0,
  `critical=${diag.critical}`);
check("Schliess-Bilanz: 3 geschlossen, 1 Erfassungs-Luecke",
  diag.closed === 3 && diag.captureGaps === 1,
  `closed=${diag.closed} captureGaps=${diag.captureGaps} unanswered=${diag.unanswered}`);
check("Netzseite reicht bis in die Diagnose (ov = eigene + Nicht-dUNL)",
  byLedger.get(idx2)?.observedValidations === thinCount + 1,
  "ov=" + String(byLedger.get(idx2)?.observedValidations));

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

// ---------- Bericht ----------
console.log("");
console.log("Phase A Forensik-Zeilen (aus der geschriebenen Tagesdatei):");
for (const r of rows) {
  console.log(`  #${r.l}  ${r.top}/${r.need} Marge ${r.mg}  closed=${r.cl} cg=${r.cg} ov=${r.ov} mm=${r.mm}  hash ${String(r.ch).slice(0, 16)}...`);
}
console.log("");
for (const r of diag.rows) {
  console.log(`  Diagnose #${r.ledgerIndex}  ${r.verdict}  Basis ${r.closure.basis}  ${r.closure.captureGap ? "Erfassungs-Luecke" : "keine Erfassungs-Luecke"}  ${r.topVotes}/${r.needed} ov=${r.observedValidations}  ${r.critical ? "kritisch" : "nicht kritisch"}`);
}
const failed = checks.filter((c) => !c.ok);
console.log("");
console.log(failed.length ? `NACHWEIS FEHLERHAFT: ${failed.length} von ${checks.length}` : `NACHWEIS ERFUELLT: ${checks.length}/${checks.length}`);
http.close();
process.exit(failed.length ? 1 : 0);
