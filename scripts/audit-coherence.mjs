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
//     'not-recorded', ein Wert nur mit einer gemessenen Basis ('ledger-index' Indexlauf,
//     'stream-gap' Luecken-Log des Tages, 'stream-open' erster Ledger nach einem Abo, siehe H).
//     Aus 'nicht erfasst' darf nirgends 'gemessen keine Luecke' werden.
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
//  G) ZURECHNUNG  attributableMax + artifactMin + openClaims == absenceClaims, die Obergrenze
//     bleibt in der Referenz, und die Karten des Endpunkts fuehren dieselben vier Zahlen wie die
//     Zurechnung. Eine Abweichungszahl ohne diese Nachrechnung ist eine Behauptung ueber den
//     Knoten, die aus einer Erfassungsbeobachtung kommt.
//  H) WARMLAUF-BELEG  ein 'stream-open'-Wert braucht das Abo-Ereignis in derselben
//     Tagesdatei: kein Flag ohne Abo-Offnung, kein Flag auf geschlossenem Ledger ohne
//     cg = true, keine zwei Flags hintereinander, nie mehr Flags als Abo-Ereignisse. Eine
//     abgeschnittene Ereignisliste heisst 'nicht pruefbar', nicht 'widerspruchsfrei'.
//  I) ZUORDNUNG  ein 'missed'-Vorfall ist ein Knoten-Urteil und braucht den Beleg der
//     Zuordnungsgrenze ('aa === true' am Vorfall oder an der Forensik-Zeile desselben Ledgers).
//     Ohne Beleg muss er als Erfassungs-Aussage stehen, und der Zaehler muss mitgewandert sein:
//     die Vorfallsliste und die Zaehler je Knoten derselben Datei fuehren dieselbe 'missed'-Zahl.
//  J) ZAHLER-DECKUNG  ein Vorfall, der eine Ledger-Signatur als Grund nennt, muss von dem
//     Zaehler gedeckt sein, der die Ledger MIT dieser Signatur fuehrt ('anomaly' / 'anomalyFail').
//     Deckt der Zaehler die Ausfall-Ledger nicht, ist die 2x2-Tafel keine Messung, und es darf
//     nirgends eine Rate oder ein Lift aus ihr erscheinen: die Ebene haelt sie zurueck und
//     benennt die Luecke ('count-mismatch' / 'tag-count-mismatch'). Erfassungs-Befunde
//     ('no-quorum', 'vote-not-observed') duerfen in keiner Rate, keiner Kohorte und keinem
//     Muster stehen - sie sind der Ausfall selbst, kein Merkmal des Ledgers.
//  K) QUORUM-ZAEHLER-DECKUNG  der Zaehler 'quorumFail' muss durch Forensik-Zeilen gedeckt sein.
//     'quorumFail' zaehlt jedes bewertete Ledger, dessen fuehrende dUNL-Linie unter dem Ziel
//     blieb; eine Zeile mit Ziel und fuehrender Linie gibt es nur je Abweichungs-Ledger. Ein
//     Ledger ohne Zeile hat keinen Index, keine Marge und keinen benannten Knoten - er darf
//     nirgends als Knoten-Urteil erscheinen. Die Differenz muss in der Tagesdatei als
//     'quorum-fail'-Luecke stehen und in der Leseschicht als eigene Zahl ausgewiesen sein
//     (coverage.quorumShortRows / quorumCounterUnattributed). Eine Differenz ohne benannte
//     Luecke ist eine Zahl ohne Nachschlageweg, eine benannte Luecke ohne Differenz erfunden.
//
// Lauf:  node scripts/audit-coherence.mjs                 (30 d, alle Knoten der Aufzeichnung)
//        node scripts/audit-coherence.mjs --range=7d
//        node scripts/audit-coherence.mjs --all
// Exit 0 = kein Widerspruch. Exit 1 = mindestens ein Widerspruch (Zeile ausgegeben).
import path from "node:path";
import { fileURLToPath } from "node:url";
import { CAPTURE_GAP_BASES, CAPTURE_GAP_BASES_MEASURED, TRACE_DEFAULTS, anomalyLayer, isAnomalyTag, isObservationTag } from "../lib/validator-trace.mjs";
import { loadDays, traceForValidator } from "../lib/validator-trace-query.mjs";
import { dayFileHoles } from "../lib/trace-day-coverage.mjs";
import { signatureSensitivity, signatureCohort } from "../lib/validator-sensitivity.mjs";
import { riskProfile } from "../lib/validator-retrace.mjs";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const DIR = process.env.TRACE_DATA_DIR || path.join(ROOT, "data", "validator-trace");
const args = process.argv.slice(2);
const QUIET = args.includes("--quiet");
const rangeArg = args.find((a) => a.startsWith("--range="));
const RANGE = rangeArg ? rangeArg.split("=")[1] : "30d";
// 'gemessen' ist keine zweite Liste mehr, sondern die der Bibliothek. Zwei Listen an zwei
// Orten waren die Ursache dieses Befunds: die Bibliothek bekam eine neue Basis, das Audit
// blieb bei der alten und erklaerte eine belegte Messung fuer unzulaessig.
const GAP_BASES_MEASURED = CAPTURE_GAP_BASES_MEASURED;
const CLOSED_VERDICTS = new Set(["closed-capture-gap", "closed-quorum-observed", "closed-reception-thin", "closed-observation-gap"]);

const days = loadDays(DIR);
const masters = [...new Set(days.flatMap((d) => (d.incidents ?? []).map((i) => i.m)))].sort();
const problems = [];
const bad = (code, where, detail) => problems.push(`${code} ${where}: ${detail}`);
const seenLedgers = new Map();
let rowsChecked = 0;
let causeRowsChecked = 0;
let retraceRowsChecked = 0;
let attributionChecked = 0;

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
  // G) Zurechnung der Abwesenheits-Zaehler dieses Knoten
  const a = out.attribution;
  const at = `attribution ${master.slice(0, 10)}`;
  attributionChecked += 1;
  if (!a || !Number.isFinite(a.absenceClaims)) {
    bad("G", at, "keine Zurechnung fuer die Abwesenheits-Zaehler");
  } else {
    const parts = (a.attributableMax ?? 0) + (a.artifactMin ?? 0) + (a.openClaims ?? 0);
    if (parts !== a.absenceClaims) bad("G", at, `${a.attributableMax} + ${a.artifactMin} + ${a.openClaims} = ${parts} != Behauptungen ${a.absenceClaims}`);
    if (a.state === "bounded") {
      if (!(a.attributableMax <= a.groundMissed)) bad("G", at, `Obergrenze ${a.attributableMax} uebersteigt die Referenz ${a.groundMissed}`);
      if (a.artifactMin !== a.claimsInside - a.attributableMax) bad("G", at, `artifactMin ${a.artifactMin} != claimsInside ${a.claimsInside} - attributableMax ${a.attributableMax}`);
    } else if (a.attributableMax !== null || a.artifactMin !== null) {
      bad("G", at, "offene Zurechnung fuehrt Zahlen, die eine Gegenprobe behaupten");
    }
    const w = out.inWindow;
    if (w && (w.absenceClaims !== a.absenceClaims || w.absenceAttributableMax !== a.attributableMax
      || w.absenceArtifactMin !== a.artifactMin || w.absenceOpen !== a.openClaims)) {
      bad("G", at, "die Zaehlerkarten und die Zurechnung nennen verschiedene Zahlen");
    }
  }
}

// H) WARMLAUF-BELEG  'stream-open' ist nur dann eine Messung, wenn dieselbe Tagesdatei die
// zugehoerige Abo-Offnung ausweist. Ein Flag ohne Abo-Ereignis, zwei Flags direkt
// hintereinander, oder ein Flag auf einem geschlossenen Ledger, dessen Schliess-Bilanz nicht
// 'Luecke' sagt, ist eine Behauptung ohne Beleg. Eine abgeschnittene Ereignisliste fuehrt zu
// 'nicht pruefbar', nicht zu einem erfundenen Befund und nicht zu einem erfundenen Widerspruch.
let warmFlags = 0;
let warmBacked = 0;
let warmUncheckable = 0;
let prevOpens = [];
let prevTruncated = false;
let prevCarry = 0;
let prevTrust = true;
let prevFlagged = false;
for (const d of days) {
  const rows = Array.isArray(d.ledgerStats) ? d.ledgerStats : [];
  const opens = (Array.isArray(d.captureEvents) ? d.captureEvents : []).filter((e) => e && e.e === "open");
  const truncated = d.captureEventsTruncated === true;
  const flaggedRows = rows.filter((r) => r && r.so === true);
  for (const row of rows) {
    if (!row || row.so !== true) { prevFlagged = false; continue; }
    if (prevFlagged) bad("H", `${d.date} #${row.l}`, "Warmlauf-Luecke direkt nach der vorherigen: der Abo-Status wurde nicht zurueckgesetzt");
    prevFlagged = true;
    if (row.cl !== true) continue;
    warmFlags += 1;
    const at = `${d.date} #${row.l}`;
    if (row.cg !== true) bad("H", at, `Warmlauf-Flag auf geschlossenem Ledger, aber die Schliess-Bilanz sagt cg=${String(row.cg)}`);
    const backing = [...opens, ...prevOpens].find((e) => e.l === null || (Number.isFinite(e.l) && Number.isFinite(row.l) && e.l < row.l));
    if (backing) warmBacked += 1;
    else if (truncated || prevTruncated) warmUncheckable += 1;
    else bad("H", at, "Warmlauf-Luecke ohne Abo-Ereignis in dieser oder der vorangegangenen Tagesdatei");
  }
  if (!truncated && prevTrust && flaggedRows.length > opens.length + prevCarry) {
    bad("H", `${d.date}`, `${flaggedRows.length} Warmlauf-Luecken, aber nur ${opens.length + prevCarry} Abo-Ereignisse (diese und vorangegangene Tagesdatei)`);
  }
  prevCarry = Math.max(0, opens.length + prevCarry - flaggedRows.length);
  prevTrust = !truncated;
  prevOpens = opens;
  prevTruncated = truncated;
}
// I) ZUORDNUNG  'missed' heisst: dieser Knoten hat in diesem Ledger gefehlt. Das ist ein
// Urteil ueber den Knoten, und es darf nur stehen, wenn die eigene Erfassung dafuer vollstaendig
// war - belegt durch 'aa === true' am Vorfall oder an der Forensik-Zeile desselben Ledgers.
// Der Altbestand (Bestand vor 2026-10-16) hat diesen Beleg nicht; dort stellt die Lese-Schicht
// auf 'vote-not-observed' um und verschiebt den Zaehler. Diese Regel prueft genau das: kein
// unbelegtes Knoten-Urteil, und dieselbe Datei fuehrt dieselbe Zahl in Liste und Zaehlern.
let missedProven = 0;
let missedUnproven = 0;
let missedDaysChecked = 0;
let missedCounterBad = 0;
for (const d of days) {
  const proof = new Map();
  for (const r of (Array.isArray(d.ledgerStats) ? d.ledgerStats : [])) {
    if (r && Number.isFinite(r.l) && r.aa === true) proof.set(r.l, true);
  }
  let listed = 0;
  for (const inc of (Array.isArray(d.incidents) ? d.incidents : [])) {
    if (!inc || inc.type !== "missed") continue;
    listed += 1;
    if (inc.aa === true || proof.get(inc.l) === true) { missedProven += 1; continue; }
    missedUnproven += 1;
    bad("I", `${d.date} #${inc.l} ${String(inc.m).slice(0, 12)}`, "'missed' ohne Zuordnungsbeleg: aa fehlt oder ist false");
  }
  if (!Array.isArray(d.incidents) || !d.validators || typeof d.validators !== "object") continue;
  const counted = Object.values(d.validators).reduce((sum, v) => sum + (Number.isFinite(Number(v?.missed)) ? Number(v.missed) : 0), 0);
  missedDaysChecked += 1;
  if (counted !== listed) {
    missedCounterBad += 1;
    bad("I", `${d.date}`, `Zaehler 'missed' = ${counted}, Vorfallsliste = ${listed}: eine Zahl, die niemand nachzaehlen kann`);
  }
}
// ---------- J) ZAHLER-DECKUNG  Zaehler, Vorfaelle und die veroeffentlichten Raten ----------
// Die Invariante wird an zwei Stellen geprueft: an den Tageszahlen selbst und an dem, was die
// Ebenen tatsaechlich ausweisen. Eine Rate ueber 100 % (8 von 1 Ledern) ist keine duenne
// Messung, sie ist ein Divisionsrest aus zwei Populationen - genau die Zeile, die ein Betreiber
// zu Recht als Falschaussage zurueckwies.
let rateRowsChecked = 0;
let rateRowsWithheld = 0;
let cohortRowsChecked = 0;
let riskRowsChecked = 0;
const countersRenamed = days.reduce((sum, d) => sum + (Number(d.countersRenamed) || 0), 0);
const counterGaps = [];
for (const d of days) {
  const layer = anomalyLayer(d);
  if (!layer) continue; // ein Tag ohne Signatur-Ebene wurde nie geprueft: keine Zusage, keine Luecke
  const claimLedgers = new Map();
  for (const inc of d.incidents ?? []) {
    for (const t of inc.r ?? []) {
      if (!isAnomalyTag(t) || isObservationTag(t)) continue;
      if (!claimLedgers.has(t)) claimLedgers.set(t, new Set());
      claimLedgers.get(t).add(inc.l);
    }
  }
  for (const [tag, set] of claimLedgers) {
    const c = Number(layer[tag]) || 0;
    const cf = Number((d.anomalyFail ?? {})[tag]) || 0;
    if (cf > c) bad("J", d.date + " " + tag, "anomalyFail " + cf + " > anomaly " + c + ": Ausfaelle, die ihr eigener Nenner nicht enthaelt");
    if (set.size > c) counterGaps.push(d.date + " " + tag + ": " + set.size + " Ausfall-Ledern gegen " + c + " gezehlte");
  }
}
// Der Tages-Zaehler 'incidentLedgers' wird dort erhoeht, wo derselbe Block auch die Forensik-Zeile
// schreibt (monitor/validator-trace.mjs: if (r.incidents.length) { d.incidentLedgers += 1; ...
// d.ledgerStats.push(...) }). Er ist also die Zahl der Ausfall-Ledger MIT Forensik, nicht die aller
// Ausfall-Ledger. Wer ihn fuer die Grundgesamtheit haelt, vergleicht Zaehler und Nenner aus
// verschiedenen Populationen - genau die Invariante, die lib/validator-divergence.mjs fuer ihren
// Feature-Lift braucht. Altbestand ohne diesen Zaehler bleibt ungeprueft: keine Zusage, keine Luecke.
const forensicsCoverage = [];
for (const d of days) {
  const claimed = Number(d.incidentLedgers);
  if (!Number.isFinite(claimed)) continue;
  const incidentSet = new Set((d.incidents ?? []).map((i) => i?.l));
  const statsSet = new Set((d.ledgerStats ?? []).map((x) => x?.l));
  if (claimed > incidentSet.size) {
    bad("J", d.date, `incidentLedgers ${claimed} > ${incidentSet.size} Ausfall-Ledger, die diese Datei selbst nennt`);
  }
  if (!d.ledgerStatsTruncated && claimed !== statsSet.size) {
    bad("J", d.date, `incidentLedgers ${claimed} != ${statsSet.size} Forensik-Zeilen - derselbe Schreibblock erzeugt beide`);
  }
  const without = [...incidentSet].filter((l) => !statsSet.has(l)).length;
  if (without) forensicsCoverage.push(`${d.date}: ${without} von ${incidentSet.size} Ausfall-Ledern ohne Forensik-Zeile (incidentLedgers nennt ${claimed})`);
}
for (const master of masters) {
  // topTags ist eine Anzeige-Grenze, keine Messgrenze: das Audit muss jede Zeile sehen,
  // die die Engine gerechnet hat. Sonst geht ein Zaehler-Widerspruch hinter der Kappe verloren.
  const sens = signatureSensitivity(days, master, { range: RANGE, topTags: 1000 });
  let withheldHere = 0;
  for (const r of sens.rows) {
    rateRowsChecked += 1;
    const at = String(master).slice(0, 12) + " " + r.tag;
    if (isObservationTag(r.tag)) bad("J", at, "Erfassungs-Befund steht als Signatur in der Empfindlichkeit");
    if (r.rateWith !== null && r.rateWith > 1) bad("J", at, "Rate mit Signatur " + r.rateWith + " ueber 1: mehr Ausfaelle als der Zaehler Ledger nennt");
    if (r.fails > r.exposureLedgers) {
      withheldHere += 1;
      if (r.rateWith !== null || r.lift !== null) bad("J", at, "Rate " + String(r.rateWith) + " / Lift " + String(r.lift) + " aus " + r.fails + " Ausfaellen gegen " + r.exposureLedgers + " gezehlte Ledger");
      if (r.verdict !== "count-mismatch") bad("J", at, "Urteil '" + r.verdict + "' deckt den Zaehler-Widerspruch nicht");
    }
  }
  if (withheldHere && !sens.gaps.includes("tag-count-mismatch")) bad("J", String(master).slice(0, 12), "Zaehler-Widerspruch ohne benannte Messluecke");
  rateRowsWithheld += withheldHere;
}
for (const r of signatureCohort(days, { range: RANGE, topTags: 1000 }).rows) {
  cohortRowsChecked += 1;
  if (isObservationTag(r.tag)) bad("J", "cohort " + r.tag, "Erfassungs-Befund steht als Kohorten-Signatur");
  if (r.coherent === false && (Number.isFinite(r.medianLift) || Number.isFinite(r.maxLift))) {
    bad("J", "cohort " + r.tag, "Kohorten-Lift " + String(r.medianLift) + " / " + String(r.maxLift) + " aus ungedeckter Tafel");
  }
}
for (const r of riskProfile(days).rows) {
  riskRowsChecked += 1;
  if (isObservationTag(r.tag)) bad("J", "risk " + r.tag, "Erfassungs-Befund steht als Signatur in der Risikotafel");
  if (r.rateWith !== null && r.rateWith > 1) bad("J", "risk " + r.tag, "Ausfallwahrscheinlichkeit " + r.rateWith + " ueber 1");
  if (r.anomalyFailLedgers > r.anomalyLedgers) bad("J", "risk " + r.tag, r.anomalyFailLedgers + " Ausfall-Ledger in " + r.anomalyLedgers + " gezehlten");
}
// ---------- K) QUORUM-ZAEHLER-DECKUNG  der Zaehler 'quorumFail' und die Zeilen, die ihn tragen ----------
// 'quorumFail' (monitor/validator-trace.mjs: if (!r.hasQuorum) d.quorumFail += 1) zaehlt jedes
// bewertete Ledger, dessen fuehrende dUNL-Linie unter dem Ziel blieb. Eine Forensik-Zeile mit
// Ziel und fuehrender Linie schreibt derselbe Rekorder nur je Abweichungs-Ledger
// (monitor/validator-trace.mjs: if (r.incidents.length) { d.incidentLedgers += 1; ... d.ledgerStats.push(...) }).
// Ein Ledger kann also im Zaehler stehen, ohne dass eine Zeile seine Zahlen nennt: die Linie war
// zu kurz, aber kein beobachteter Knoten wurde markiert, weil alle gesehenen Mitglieder
// vollstaendig signierten und sich die Stimmen auf mehrere Hash-Linien verteilten
// (lib/validator-trace.mjs: ein gesehenes Mitglied ohne Fehlvote erhoht 'ok', nicht die Vorfaelle).
// Live belegt: ueber die Aufzeichnung sagt der Zaehler 82, nachrechenbar sind 10 Zeilen;
// 2026-10-16 fuehrt 11 gegen 9, 2026-10-13 bis 2026-10-15 fuehren 2 + 6 + 13 ohne jede Zeile.
// Fuer eine Engine, die kein Ledger-Urteil ohne Nachschlageweg behaupten darf, ist die Forderung
// dreifach: die Tagesdatei muss die Differenz benennen, die Leseschicht muss sie ausweisen,
// und ein Ledger ohne Zeile darf in keiner Ebene zur Knoten-Aussage werden.
const quorumShortCount = (d) => (Array.isArray(d.ledgerStats) ? d.ledgerStats : []).reduce((n, ls) => {
  const top = Number(ls?.top), need = Number(ls?.need);
  return Number.isFinite(top) && Number.isFinite(need) && need > 0 && top < need ? n + 1 : n;
}, 0);
let quorumCounterSum = 0, quorumShortSum = 0, quorumDaysChecked = 0, quorumGapDays = 0;
const quorumGapRows = [];
for (const d of days) {
  const counter = Number(d.quorumFail);
  const short = quorumShortCount(d);
  if (!Number.isFinite(counter) && short === 0) continue; // weder Zaehler noch Zeile: nichts geprueft
  const known = Number.isFinite(counter) ? counter : 0;
  quorumCounterSum += known; quorumShortSum += short; quorumDaysChecked += 1;
  const declared = Number(d.quorumShortRows);
  if (Number.isFinite(declared) && declared !== short)
    bad("K", d.date, `quorumShortRows ${declared} != ${short} Zeilen mit top < need: die Nachrechnung der Lib weicht von den Zeilen ab`);
  const named = (Array.isArray(d.counterGaps) ? d.counterGaps : []).filter((g) => g && g.tag === "quorum-fail");
  const diff = Math.abs(known - short);
  if (counter === short) {
    if (named.length) bad("K", d.date, `benannte quorum-fail-Luecke, obwohl Zaehler (${known}) und Zeilen (${short}) gleich sind`);
    continue;
  }
  quorumGapDays += 1;
  if (!named.length) {
    bad("K", d.date, `quorumFail ${known} gegen ${short} Zeilen: ${diff} Ledger ohne benannte Luecke in der Tagesdatei`);
    continue;
  }
  const sum = named.reduce((n, g) => n + (Number(g.ledgers) || 0), 0);
  if (sum !== diff) bad("K", d.date, `quorum-fail-Luecke nennt ${sum} Ledger, die Nachrechnung sagt ${diff}`);
  quorumGapRows.push(`${d.date}: Zaehler ${known}, Zeilen ${short}, ohne Zeile ${diff} (${named.map((g) => g.reason).join(", ")})`);
}
for (const master of masters) {
  const c = traceForValidator(days, master, { range: RANGE }).coverage;
  const at = String(master).slice(0, 12);
  const qf = Number(c.quorumFail), qs = Number(c.quorumShortRows), rest = Number(c.quorumCounterUnattributed);
  if (!Number.isFinite(qf) || !Number.isFinite(qs) || !Number.isFinite(rest)) {
    bad("K", at, "Quorum-Deckung fehlt in der Leseschicht: quorumShortRows / quorumCounterUnattributed nicht ausgewiesen");
    continue;
  }
  if (rest !== Math.max(0, qf - qs)) bad("K", at, `quorumCounterUnattributed ${rest} != ${qf} Zaehler - ${qs} benannte Ledger`);
  if (qs > quorumShortSum) bad("K", at, `Leseschicht nennt ${qs} benannte Ledger, die Aufzeichnung fuehrt nur ${quorumShortSum}`);
}

const ledgers = seenLedgers.size;
const gapsMeasured = [...seenLedgers.values()].filter((f) => f.gap === true).length;
const gapsOpen = [...seenLedgers.values()].filter((f) => f.gap === null).length;
const gapsRuledOut = [...seenLedgers.values()].filter((f) => f.gap === false).length;
if (!QUIET) {
  console.log(`KOHAEENZ (range=${RANGE}, ${days.length} Tage, ${masters.length} Knoten)`);
  console.log(`  Forensik-Zeilen: ${rowsChecked} | Ursachen-Zeilen: ${causeRowsChecked} | Retrace-Karten: ${retraceRowsChecked} | Zurechnungen: ${attributionChecked}`);
  console.log(`  Eindeutige Ledger: ${ledgers} | Erfassung gemessen Luecke ${gapsMeasured} | gemessen keine Luecke ${gapsRuledOut} | nicht erfasst ${gapsOpen}`);
}
if (!QUIET) console.log(`  Warmlauf-Luecken (stream-open): ${warmFlags} | mit Abo-Ereignis belegt ${warmBacked} | nicht pruefbar (Ereignisliste abgeschnitten) ${warmUncheckable}`);
if (!QUIET) console.log(`  Knoten-Urteil 'missed': mit Beleg ${missedProven} | ohne Beleg ${missedUnproven} | Tage mit Zaehler-Vergleich ${missedDaysChecked}, Abweichungen ${missedCounterBad}`);
if (!QUIET) console.log(`  Raten-Zeilen: ${rateRowsChecked} Empfindlichkeit, ${cohortRowsChecked} Kohorte, ${riskRowsChecked} Risiko | ohne Rate zurueckgehalten ${rateRowsWithheld}`);
if (!QUIET) console.log(`  Zaehler-Vokabel nachgefuehrt (no-quorum -> vote-not-observed, Ledger-Zahl): ${countersRenamed}`);
if (!QUIET) console.log(`  Zaehler-Deckung: ${counterGaps.length} Tag-Signaturen mit mehr Ausfall-Ledern als der Tages-Zaehler nennt` + (counterGaps.length ? " (Rate zurueckgehalten, nicht geschaetzt)" : ""));
if (!QUIET) console.log(`  Forensik-Deckung der Ausfall-Ledger: ${forensicsCoverage.length} Tage mit Ausfall-Ledern ohne Forensik-Zeile` + (forensicsCoverage.length ? " (incidentLedgers zaehlt nur Ledger mit Forensik - kein Nenner fuer die Grundgesamtheit)" : ""));
if (!QUIET) console.log(`  Quorum-Zaehler: ${quorumCounterSum} gezaehlt | ${quorumShortSum} durch eine Zeile mit Ziel und fuehrender Linie benannt | ${quorumCounterSum - quorumShortSum} ohne solche Zeile | ${quorumDaysChecked} Tage geprueft, ${quorumGapDays} mit Differenz`);
if (forensicsCoverage.length) {
  console.log("  FORENSIK-DECKUNG (je Tag):");
  for (const g of forensicsCoverage.slice(0, 20)) console.log("    " + g);
  if (forensicsCoverage.length > 20) console.log(`    ... ${forensicsCoverage.length - 20} weitere`);
}
if (counterGaps.length) {
  console.log("  BENANNTE ZAEHLER-LUECKEN:");
  for (const g of counterGaps.slice(0, 20)) console.log("    " + g);
  if (counterGaps.length > 20) console.log(`    ... ${counterGaps.length - 20} weitere`);
}
if (quorumGapRows.length) {
  console.log("  QUORUM-ZAEHLER OHNE FORENSIK-ZEILE (je Tag, der Zaehler bleibt stehen, die Differenz ist benannt):");
  for (const g of quorumGapRows.slice(0, 20)) console.log("    " + g);
  if (quorumGapRows.length > 20) console.log(`    ... ${quorumGapRows.length - 20} weitere`);
}
if (problems.length) {
  console.log(`\nWIDERSPRUECHE (${problems.length}):`);
  for (const p of problems.slice(0, 60)) console.log("  " + p);
  if (problems.length > 60) console.log(`  ... ${problems.length - 60} weitere`);
  process.exit(1);
}

// Die Spanne ZWISCHEN Tagesdateien steht in keiner Datei, die existiert. Sie wird hier
// benannt, damit ein Rekorder-Stop nicht als Stille im Netz gelesen wird.
const holes = dayFileHoles(days);
console.log("\n  UNBEOBACHTETE SPANNEN ZWISCHEN TAGESDATEIEN: " + holes.length);
for (const h of holes) console.log("    " + h.between + ": " + h.fromIso + " -> " + h.toIso + " = " + h.ms + " ms (nicht bewertet)");
console.log("\nKein Widerspruch: jede Ebene und jeder Knoten nennt dieselbe Ledger-Tatsache.");
process.exit(0);
