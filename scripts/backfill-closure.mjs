// scripts/backfill-closure.mjs
//
// WAS DIESE DATEI TUTT: Sie prueft fuer jeden aufgezeichneten Ledger den Schliess-Beweis und
// traegt ihn nach, wenn er fehlt. Bewiesen gilt nur, wenn ZWEI unabhaengige Autoritaeten
// denselben Hash melden: xrpscan.com (die Referenz, die ein Betreiber selbst nachlesen kann) und
// der Ledger-Strom des Netzes selbst ueber die JSON-RPC-Schnittstelle von xrplcluster.com.
//
// WARUM nachgetragen wird: der Rekorder schreibt ch/cl/cg/ov erst seit 2026-10-16 in jede Zeile.
// Der Bestand davor hat keinen Hash. Ohne Nachtrag bleibt 'Schliess-Beweis' eine Luecke - und eine
// Luecke genau in der Akkuratz-Spalte ist das, was ein Betreiber nicht akzeptieren kann.
//
// WAS SIE NICHT TUT:
//  - Sie erfindet nichts. Geschrieben wird nur, wenn beide Quellen denselben 64er-Hash fuer genau
//    diesen Ledger-Index melden. Sonst bleibt die Zeile ohne Hash - die Luecke ist ehrlich, ein
//    unpruefbarer Hash waere eine Behauptung.
//  - Sie ueberschreibt nie einen selbst gesehenen Hash: eine Zeile ohne chSource ist eigener
//    Mithoerbeweis und wird nicht angefasst.
//  - Sie schreibt kein 'cg'. Die Erfassungs-Luecke dieses Rekorders ist eine eigene Messung;
//    ledgerClosure() leitet sie aus gap/gmed ab, wenn sie nicht gemessen wurde. Ein pauschales
//    'cg: true' aus einer Fremdquelle waere eine Behauptung ueber die eigene Beobachtung.
//  - Sie vergleicht, ohne zu ueberschreiben: Tx-Zahl und Close-Zeit der Quelle stehen als xc
//    neben der eigenen Messung, jede Abweichung wird ausgegeben.
//
// GEFUNDENE GRENZE DER QUELLE (2026-10-16 nachgerechnet): api.xrpscan.com antwortet in zwei
// Formaten. Das eine nennt tx_count und close_time als Unix-Sekunden, das andere laesst tx_count
// weg und liefert close_time in der Ripple-Epoche (946.684.800 s unter Unix). close_time * 1000
// gegen die eigene Close-Zeit zu halten ist auf der einen Haelfte falsch - die 21 scheinbaren
// Abweichungen des ersten Laufs waren genau dieses Artefakt, nicht die Daten. Verglichen wird
// deshalb ueber close_time_human (xrpscan) bzw. close_time_iso (Netzschnittstelle).
//
// Quellen: https://api.xrpscan.com/api/v1/ledger/<index> (xrpscan.com, CC BY-NC-SA 4.0) und
// POST https://xrplcluster.com { method: "ledger" } (rippled, Mainnet).
import fs from "node:fs";
import path from "node:path";

const ROOT = path.resolve(import.meta.dirname, "..");
const argv = process.argv.slice(2);
const arg = (name, dflt) => { const i = argv.indexOf("--" + name); return i === -1 ? dflt : argv[i + 1]; };
const DRY = argv.includes("--dry-run");
const DIR = path.resolve(ROOT, arg("dir", "data/validator-trace"));
const DELAY = Math.max(0, Number(arg("delay", 120)) || 0);
const HEX64 = /^[0-9A-Fa-f]{64}$/;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function get(url, options) {
  for (let attempt = 1; attempt <= 3; attempt += 1) {
    try {
      const res = await fetch(url, { ...options, signal: AbortSignal.timeout(20000) });
      if (res.status === 429) { await sleep(1500 * attempt); continue; }
      if (!res.ok) { if (attempt < 3) { await sleep(600 * attempt); continue; } return { error: "HTTP " + res.status }; }
      const j = await res.json();
      if (!j || typeof j !== "object") { if (attempt < 3) { await sleep(600 * attempt); continue; } return { error: "no object" }; }
      return { ok: true, j };
    } catch (e) {
      if (attempt < 3) { await sleep(800 * attempt); continue; }
      return { error: e instanceof Error ? e.message : String(e) };
    }
  }
  return { error: "unreachable" };
}

const scanLedger = (index) => get("https://api.xrpscan.com/api/v1/ledger/" + index, {});
const netLedger = (index) => get("https://xrplcluster.com", {
  method: "POST", headers: { "content-type": "application/json" },
  body: JSON.stringify({ method: "ledger", params: { ledger_index: index, api_version: 2 } }),
});

// close_time_human (xrpscan) und close_time_iso (rippled) sind die einzigen Close-Zeiten der
// Quellen, die ohne Epoche-Raten lesbar sind.
const isoMs = (x) => (typeof x === "string" && !Number.isNaN(Date.parse(x)) ? Date.parse(x) : null);

const files = fs.existsSync(DIR) ? fs.readdirSync(DIR).filter((f) => f.endsWith(".json")).sort() : [];
if (!files.length) { console.log("keine Tagesdateien in " + DIR); process.exit(1); }

let rows = 0, ownProof = 0, filled = 0, verified = 0, refused = 0;
let mismatchTx = 0, mismatchTime = 0, noSourceTx = 0, timeSourceDiff = 0;
let claimLedgerTotal = 0, claimRowTotal = 0, claimFilledTotal = 0, claimAlreadyTotal = 0, claimRefusedTotal = 0;
const problems = [];

for (const file of files) {
  const full = path.join(DIR, file);
  const day = JSON.parse(fs.readFileSync(full, "utf8"));
  const stats = Array.isArray(day.ledgerStats) ? day.ledgerStats : [];
  let touched = 0;
  let claimLedgerCount = 0, claimRowsTouched = 0, claimFilled = 0, claimAlready = 0, claimRefused = 0;
  for (const st of stats) {
    rows += 1;
    // Ein Hash aus der ersten Fassung dieses Skripts ist ungeprueft. Besteht er die Deckung der
    // beiden Quellen nicht, muss er weg - 'nicht erfasst' ist eine Luecke, ein unpruefbarer Hash
    // waere eine Behauptung ueber einen Ledger, den wir nie gesehen haben.
    const dropUnproven = () => {
      if (st.chSource !== "xrpscan") return;
      delete st.ch; delete st.chSource; delete st.chVerifiedBy; delete st.chAt; delete st.xc;
    };
    const index = Number(st.l);
    if (!Number.isInteger(index) || index <= 0) {
      refused += 1; dropUnproven(); problems.push(file + ": Zeile ohne Ledger-Index"); continue;
    }
    const ownHash = typeof st.ch === "string" && HEX64.test(st.ch);
    if (ownHash && st.chSource !== "xrpscan") { ownProof += 1; continue; }
    const a = await scanLedger(index);
    if (DELAY) await sleep(DELAY);
    if (!a.ok) { refused += 1; dropUnproven(); problems.push(file + " #" + index + ": xrpscan " + a.error); continue; }
    const b = await netLedger(index);
    if (DELAY) await sleep(DELAY);
    const rb = b.ok && b.j && b.j.result ? b.j.result.ledger : null;
    if (!b.ok || !rb) {
      refused += 1; dropUnproven();
      problems.push(file + " #" + index + ": xrplcluster " + (b.error || "kein ledger-Objekt")); continue;
    }
    const ha = typeof a.j.ledger_hash === "string" ? a.j.ledger_hash.toUpperCase() : null;
    const hb = typeof rb.ledger_hash === "string" ? rb.ledger_hash.toUpperCase() : null;
    if (Number(a.j.ledger_index) !== index || Number(rb.ledger_index) !== index) {
      refused += 1; dropUnproven();
      problems.push(file + " #" + index + ": Index-Vergleich " + a.j.ledger_index + " / " + rb.ledger_index); continue;
    }
    if (!ha || !HEX64.test(ha) || !hb || !HEX64.test(hb) || ha !== hb) {
      refused += 1; dropUnproven();
      problems.push(file + " #" + index + ": Hash nicht deckungsgleich (" + (ha || "keiner") + " / " + (hb || "keiner") + ")");
      continue;
    }
    const tScan = isoMs(a.j.close_time_human);
    const tNet = isoMs(rb.close_time_iso);
    const txScan = Number.isFinite(Number(a.j.tx_count)) ? Number(a.j.tx_count) : null;
    const ownTx = Number.isFinite(st.tx) ? st.tx : null;
    const ownClose = Number.isFinite(st.t) ? st.t : null;
    const txMatch = txScan === null || ownTx === null ? null : ownTx === txScan;
    const tMatch = tScan === null || ownClose === null ? null : ownClose === tScan;
    const tSources = tScan !== null && tNet !== null ? tScan === tNet : null;
    if (txMatch === false) { mismatchTx += 1; problems.push(file + " #" + index + ": Tx-Zahl eigen " + ownTx + " / xrpscan " + txScan); }
    if (tMatch === false) { mismatchTime += 1; problems.push(file + " #" + index + ": Close-Zeit eigen " + ownClose + " / xrpscan " + tScan); }
    if (txScan === null) noSourceTx += 1;
    if (tSources === false) { timeSourceDiff += 1; problems.push(file + " #" + index + ": Close-Zeit xrpscan " + tScan + " / Netz " + tNet); }
    st.ch = ha;
    st.chSource = "xrpscan";
    st.chVerifiedBy = "xrplcluster.com";
    st.chAt = st.chAt || new Date().toISOString();
    if (st.cl === undefined) st.cl = true;
    st.xc = { hashAgree: true, tx: txMatch, t: tMatch, sourcesAgree: tSources, txScan, tScan, tNet };
    if (ownHash) verified += 1; else filled += 1;
    touched += 1;
  }
  // CLAIM-GEBUNDENER NACHTRAG. Eine Zeile, die ein fehlendes Quorum behauptet, braucht den
  // Schliess-Beweis genau dieses Ledgers - sonst ist die Behauptung unpruefbar. Der Altbestand
  // vor 2026-10-16 fuehrt ledgerStats gar nicht, und ledgerStats enthaelt ausserdem nur Ledger
  // mit Detail, nicht jeden Ledger mit Incident. Deshalb wird hier ueber die Incidents gegangen,
  // nicht ueber die Stats-Zeilen, und der Beweis in 'closureProofs' abgelegt (ein eigener Satz
  // pro Ledger, nicht kopiert in jede Incident-Zeile). ledgerStats bleibt unangetastet: eine
  // Stats-Zeile ohne eigene Messwerte waere eine Detail-Zeile ohne Detail und wuerde die
  // Forensik-Abdeckung des Tages aufblasen.
  const statsLedgers = new Set();
  for (const st of stats) if (Number.isFinite(st.l)) statsLedgers.add(Number(st.l));
  const claimLedgers = new Map();
  for (const inc of Array.isArray(day.incidents) ? day.incidents : []) {
    if (!inc || typeof inc !== "object" || !Number.isInteger(inc.l) || inc.l <= 0) continue;
    if (inc.type !== "no-quorum" || statsLedgers.has(inc.l)) continue;
    claimLedgers.set(inc.l, (claimLedgers.get(inc.l) ?? 0) + 1);
  }
  const proofs = (day.closureProofs ??= []);
  const knownProof = new Set();
  for (const row of proofs) if (row && Number.isFinite(row.l) && typeof row.ch === "string" && HEX64.test(row.ch)) knownProof.add(row.l);
  for (const [index, rowsWithClaim] of [...claimLedgers.entries()].sort((a, b) => a[0] - b[0])) {
    claimLedgerCount += 1;
    claimRowsTouched += rowsWithClaim;
    if (knownProof.has(index)) { claimAlready += 1; continue; }
    const a = await scanLedger(index);
    if (DELAY) await sleep(DELAY);
    if (!a.ok) { claimRefused += 1; problems.push(file + " claim #" + index + ": xrpscan " + a.error); continue; }
    const b = await netLedger(index);
    if (DELAY) await sleep(DELAY);
    const rb = b.ok && b.j && b.j.result ? b.j.result.ledger : null;
    if (!b.ok || !rb) { claimRefused += 1; problems.push(file + " claim #" + index + ": xrplcluster " + (b.error || "kein ledger-Objekt")); continue; }
    const ha = typeof a.j.ledger_hash === "string" ? a.j.ledger_hash.toUpperCase() : null;
    const hb = typeof rb.ledger_hash === "string" ? rb.ledger_hash.toUpperCase() : null;
    if (Number(a.j.ledger_index) !== index || Number(rb.ledger_index) !== index) {
      claimRefused += 1; problems.push(file + " claim #" + index + ": Index-Vergleich " + a.j.ledger_index + " / " + rb.ledger_index); continue;
    }
    if (!ha || !HEX64.test(ha) || !hb || !HEX64.test(hb) || ha !== hb) {
      claimRefused += 1;
      problems.push(file + " claim #" + index + ": Hash nicht deckungsgleich (" + (ha || "keiner") + " / " + (hb || "keiner") + ")");
      continue;
    }
    const tScan = isoMs(a.j.close_time_human);
    const tNet = isoMs(rb.close_time_iso);
    proofs.push({ l: index, cl: true, ch: ha, chSource: "xrpscan", chVerifiedBy: "xrplcluster.com", chAt: new Date().toISOString(),
      xc: { hashAgree: true, sourcesAgree: tScan !== null && tNet !== null ? tScan === tNet : null, tScan, tNet } });
    claimFilled += 1;
    touched += 1;
  }
  claimLedgerTotal += claimLedgerCount; claimRowTotal += claimRowsTouched; claimFilledTotal += claimFilled;
  claimAlreadyTotal += claimAlready; claimRefusedTotal += claimRefused;
  if (claimLedgerCount) console.log(file + ": Claim-Ledger ohne Stats-Zeile " + claimLedgerCount + " (Incident-Zeilen " + claimRowsTouched + "), Schliess-Beweis nachgetragen " + claimFilled + ", bereits vorhanden " + claimAlready + ", ohne Nachweis " + claimRefused);
  if (touched && !DRY) {
    const tmp = full + ".backfill.tmp";
    fs.writeFileSync(tmp, JSON.stringify(day, null, 1), "utf8");
    JSON.parse(fs.readFileSync(tmp, "utf8"));
    fs.renameSync(tmp, full);
  }
  console.log(file + ": Zeilen " + stats.length + ", bewiesen " + touched);
}

console.log("");
console.log("Dateien " + files.length + " | Ledger-Zeilen " + rows + " | eigener Beweis unangetastet " + ownProof);
console.log("nachgetragen " + filled + " | gegengeprueft " + verified + " | ohne Nachweis geblieben " + refused);
console.log("Claim-Ledger ohne Stats-Zeile " + claimLedgerTotal + " (betroffene Incident-Zeilen " + claimRowTotal + ") | Schliess-Beweis nachgetragen " + claimFilledTotal + " | bereits belegt " + claimAlreadyTotal + " | ohne Nachweis " + claimRefusedTotal);
console.log("Abweichung Tx-Zahl " + mismatchTx + " | Abweichung Close-Zeit " + mismatchTime
  + " | Quelle ohne Tx-Angabe " + noSourceTx + " | Close-Zeit der beiden Quellen uneins " + timeSourceDiff);
if (DRY) console.log("Dry-Run: keine Datei geschrieben.");
if (problems.length) {
  console.log("");
  for (const p of problems.slice(0, 40)) console.log("  " + p);
  if (problems.length > 40) console.log("  +" + (problems.length - 40) + " weitere");
}
