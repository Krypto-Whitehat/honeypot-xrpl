// scripts/audit-coherence.mjs
//
// DAUER-KONTROLLE fuer innere Deckung. Kein Netz, keine Schaetzung, nichts geschrieben.
//
// Beantwortete Frage: widerspricht sich die Engine selbst? Dieselbe Ledger-Tatsache wird von
// drei Ebenen ausgesprochen - der Kritikalitaets-Zeile (Diagnose), dem Retrace-Karton und der
// Ursachen-Rangliste. Ausserdem wird dieselbe Ledger-Tatsache von 35 Validatoren-Auskuenften
// berichtet. Weicht eine Ebene ab, ist eine Zahl erfunden, nicht gemessen.
//
// Pruefungen (alle ohne Netz, aus denselben Tagesdateien):
//  A) DREIWERTIGKEIT  captureGap ist true | false | null, und die Basis passt: null nur mit
//     'not-recorded', ein Wert nur mit 'ledger-index' oder 'stream-gap'. Aus 'nicht erfasst'
//     darf nirgends 'gemessen keine Luecke' werden.
//  B) EBENEN-DECKUNG  Kritikalitaets-Zeile, Retrace-Karton und Ursachen-Kandidaten
//     (vote-not-observed, vote-coverage-thin) nennen fuer denselben Ledger denselben
//     Schliess-Hash, dieselbe Schliess-Basis und denselben captureGap-Wert samt Basis.
//  C) VALIDATOREN-DECKUNG  dieselbe Ledger-Index-Auskunft ist ueber alle angefragten Knoten
//     identisch: Hash, Schliessung, Stimmen, Ziel, Marge, Erfassungs-Aussage.
//  D) GRENZ-ARITHMETIK  genuineAbsentMax == members - needed und
//     captureArtifactMin == absent - genuineAbsentMax, nachgerechnet aus den Feldern der Zeile.
//  E) URTEILS-REGELN  critical und network-stall nur bei ausdrucklich verneinter Schliessung;
//     closed Ledger nur mit einem closed-* verdict; cause-check-network-stall nur mit Beleg
//     (verneinte Schliessung oder gemessen durchgehende Index-Folge an einem Close-Abstand).
//  F) BETROFFENHEIT  affectedCount == affectedMasters.length + 1 (der eigene Knoten zaehlt mit).
//
// Lauf:  node scripts/audit-coherence.mjs                 (30 d, alle Knoten der Aufzeichnung)
//        node scripts/audit-coherence.mjs --range=7d
//        node scripts/audit-coherence.mjs --all
// Exit 0 = kein Widerspruch. Exit 1 = mindestens ein Widerspruch (Zeile ausgegeben).
import path from "node:path";
import { fileURLToPath } from "node:url";
import { CAPTURE_GAP_BASES, TRACE_DEFAULTS } from "../lib/validator-trace.mjs";
import { loadDays, traceForValidator } from "../lib/validator-trace-query.mjs";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const DIR = process.env.TRACE_DATA_DIR || path.join(ROOT, "data", "validator-trace");
const args = process.argv.slice(2);
const QUIET = args.includes("--quiet");
const rangeArg = args.find((a) => a.startsWith("--range="));
const RANGE = rangeArg ? rangeArg.split("=")[1] : "30d";
const GAP_BASES_MEASURED = ["ledger-index", "stream-gap"];
const CLOSED_VERDICTS = new Set(["closed-capture-gap", "closed-quorum-observed", "closed-reception-thin", "closed-observation-gap"]);

const days = loadDays(DIR);
const masters = [...new Set(days.flatMap((d) => (d.incidents ?? []).map((i) => i.m)))].sort();
const problems = [];
const bad = (code, where, detail) => problems.push(`${code} ${where}: ${detail}`);
const seenLedgers = new Map();
let rowsChecked = 0;
let causeRowsChecked = 0;
let retraceRowsChecked = 0;

for (const master of masters) {
  const out = traceForValidator(days, master, { range: RANGE });
  const rows = out.diagnosis?.criticality?.rows ?? [];
  const causeByLedger = new Map((out.cause?.rows ?? []).map((r) => [r.ledgerIndex, r]));
  const retraceByLedger = new Map((out.retrace ?? []).map((r) => [r.ledgerIndex, r]));
  for (const r of rows) {
    rowsChecked += 1;
    const at = `#${r.ledgerIndex} ${master.slice(0, 10)}`;
    const cl = r.closure ?? {};
    // A) Dreiwertigkeit und Basis
    if (r.captureGap !== true && r.captureGap !== false && r.captureGap !== null) {
      bad("A", at, `captureGap ist nicht dreiwertig: ${JSON.stringify(r.captureGap)}`);
    }
    if (!CAPTURE_GAP_BASES.includes(r.captureGapBasis)) bad("A", at, `captureGapBasis unbekannt: ${r.captureGapBasis}`);
    if (r.captureGap === null && r.captureGapBasis !== "not-recorded") bad("A", at, `null mit Basis ${r.captureGapBasis}`);
    if (r.captureGap !== null && !GAP_BASES_MEASURED.includes(r.captureGapBasis)) bad("A", at, `gemessener Wert mit Basis ${r.captureGapBasis}`);
    if (cl.captureGap !== r.captureGap) bad("A", at, `captureGap der Schliess-Ebene ${String(cl.captureGap)} != Zeile ${String(r.captureGap)}`);
    // C) Validatoren-Deckung: derselbe Ledger muss jedem Knoten dieselbe Tatsache nennen
    const fact = {
      hash: cl.hash ?? null, closed: cl.closed ?? null, votes: r.votes ?? null, needed: r.needed ?? null,
      top: r.topVotes ?? null, margin: r.margin ?? null, gap: r.captureGap ?? null, basis: r.captureGapBasis ?? null,
    };
    const prior = seenLedgers.get(r.ledgerIndex);
    if (!prior) seenLedgers.set(r.ledgerIndex, { ...fact, master });
    else {
      for (const k of Object.keys(fact)) {
        if (prior[k] !== fact[k]) bad("C", `#${r.ledgerIndex}`, `${k} weicht ab: ${String(prior[k])} (${prior.master.slice(0, 10)}) != ${String(fact[k])} (${master.slice(0, 10)})`);
      }
    }
    // D) Grenz-Arithmetik
    const b = r.capture;
    if (b && b.closed === true && Number.isFinite(b.members) && Number.isFinite(b.needed) && b.members > 0 && b.needed > 0) {
      const max = Math.max(0, b.members - b.needed);
      const min = Math.max(0, (b.absentCount ?? 0) - max);
      if (b.genuineAbsentMax !== max) bad("D", at, `genuineAbsentMax ${b.genuineAbsentMax} != ${b.members} - ${b.needed} = ${max}`);
      if (b.captureArtifactMin !== min) bad("D", at, `captureArtifactMin ${b.captureArtifactMin} != ${b.absentCount} - ${max} = ${min}`);
    }
    // E) Urteilsregeln der Diagnose
    if (cl.closed === true && r.critical) bad("E", at, "critical auf einem bewiesen geschlossenen Ledger");
    if (cl.closed === true && !CLOSED_VERDICTS.has(r.verdict)) bad("E", at, `verdict ${r.verdict} auf geschlossenem Ledger`);
    if (cl.closed === false && r.verdict !== "not-closed") bad("E", at, `verdict ${r.verdict} bei verneinter Schliessung`);
    // F) Betroffenheit
    if (Number.isFinite(r.affectedCount) && Array.isArray(r.affectedMasters) && r.affectedCount !== r.affectedMasters.length + 1) {
      bad("F", at, `affectedCount ${r.affectedCount} != affectedMasters ${r.affectedMasters.length} + 1 eigener Knoten`);
    }
    // B) Ebenen-Deckung Retrace-Karton
    const card = retraceByLedger.get(r.ledgerIndex);
    if (card) {
      retraceRowsChecked += 1;
      if (card.closure && card.closure.captureGap !== r.captureGap) bad("B", at, `Retrace captureGap ${String(card.closure.captureGap)} != Diagnose ${String(r.captureGap)}`);
      if (card.closure && card.closure.hash !== cl.hash) bad("B", at, `Retrace-Hash ${String(card.closure.hash).slice(0, 12)} != Diagnose ${String(cl.hash).slice(0, 12)}`);
      if (card.quorum && card.quorum.captureGap !== r.captureGap) bad("B", at, `Retrace-Quorum captureGap ${String(card.quorum.captureGap)} != Diagnose ${String(r.captureGap)}`);
    }
    // B) Ebenen-Deckung Ursachen-Engine
    const c = causeByLedger.get(r.ledgerIndex);
    if (c) {
      causeRowsChecked += 1;
      const cands = c.candidates ?? [];
      const vno = cands.find((x) => x.tag === "vote-not-observed") ?? null;
      const vct = cands.find((x) => x.tag === "vote-coverage-thin") ?? null;
      if (vno) {
        if (vno.evidence.captureGap !== r.captureGap) bad("B", at, `Ursache vote-not-observed captureGap ${String(vno.evidence.captureGap)} != Diagnose ${String(r.captureGap)}`);
        if (vno.evidence.captureGapBasis !== r.captureGapBasis) bad("B", at, `Ursache captureGapBasis ${vno.evidence.captureGapBasis} != Diagnose ${r.captureGapBasis}`);
        if (vno.evidence.closedHash !== cl.hash) bad("B", at, `Ursache-Hash ${String(vno.evidence.closedHash).slice(0, 12)} != Schliess-Hash ${String(cl.hash).slice(0, 12)}`);
        if (vno.evidence.closureBasis !== cl.basis) bad("B", at, `Ursache closureBasis ${vno.evidence.closureBasis} != ${cl.basis}`);
      }
      if (vct) {
        if (vct.evidence.captureGap !== r.captureGap) bad("B", at, `Ursache vote-coverage-thin captureGap ${String(vct.evidence.captureGap)} != Diagnose ${String(r.captureGap)}`);
        if (vct.evidence.closedHash !== cl.hash) bad("B", at, `Ursache vote-coverage-thin Hash != Schliess-Hash`);
      }
      // E) Urteilsregeln der Ursachen-Engine
      const stall = cands.find((x) => x.tag === "network-stall") ?? null;
      if (stall && cl.closed !== false) bad("E", at, "network-stall ohne verneinte Schliessung");
      if ((c.nextCheck ?? []).includes("cause-check-network-stall")) {
        const closeGap = cands.find((x) => x.tag === "close-gap") ?? null;
        const basis = cl.closed === false || (closeGap && r.captureGap === false);
        if (!basis) bad("E", at, "cause-check-network-stall ohne Beleg (Schliessung nicht verneint, Index-Folge nicht gemessen durchgehend)");
      }
    }
  }
}

const ledgers = seenLedgers.size;
const gapsMeasured = [...seenLedgers.values()].filter((f) => f.gap === true).length;
const gapsOpen = [...seenLedgers.values()].filter((f) => f.gap === null).length;
const gapsRuledOut = [...seenLedgers.values()].filter((f) => f.gap === false).length;
if (!QUIET) {
  console.log(`KOHAEENZ (range=${RANGE}, ${days.length} Tage, ${masters.length} Knoten)`);
  console.log(`  Forensik-Zeilen: ${rowsChecked} | Ursachen-Zeilen: ${causeRowsChecked} | Retrace-Karten: ${retraceRowsChecked}`);
  console.log(`  Eindeutige Ledger: ${ledgers} | Erfassung gemessen Luecke ${gapsMeasured} | gemessen keine Luecke ${gapsRuledOut} | nicht erfasst ${gapsOpen}`);
}
if (problems.length) {
  console.log(`\nWIDERSPRUECHE (${problems.length}):`);
  for (const p of problems.slice(0, 60)) console.log("  " + p);
  if (problems.length > 60) console.log(`  ... ${problems.length - 60} weitere`);
  process.exit(1);
}
console.log("\nKein Widerspruch: jede Ebene und jeder Knoten nennt dieselbe Ledger-Tatsache.");
process.exit(0);
