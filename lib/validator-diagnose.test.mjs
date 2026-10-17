// lib/validator-diagnose.test.mjs — Serien-, Netzanteils-, Kohorten- und Kritikalitaets-Ebene.
// Alle Erwartungswerte sind von Hand nachgerechnet, nicht aus der Funktion abgeschrieben.
import test from "node:test";
import assert from "node:assert/strict";
import {
  failureRuns, failureSplit, coFailureClusters, validatorFingerprint,
  quorumCriticality, windowScan, seriesContext, applySeries, loadResponseCurve, DIAGNOSE_DEFAULTS,
  CQ_CLOSURE_BASES,
} from "./validator-diagnose.mjs";

const NOW = Date.UTC(2026, 9, 8, 12, 0, 0);
const A = "nAAA", B = "nBBB", C = "nCCC", D = "nDDD", E = "nEEE", F = "nFFF", G = "nGGG";
const inc = (l, m, type = "missed", r = []) => ({ l, m, t: NOW - 1000, type, r });
// Tagesobjekt mit vollstaendigen Zaehlern: ok = validiert, Rest = Abweichungen.
const day = (over = {}) => ({
  date: "2026-10-08", ledgers: 100, quorumFail: 0, gaps: [], incidents: [], hourly: {},
  validators: {}, ledgerStats: [], anomaly: {}, anomalyFail: {}, shapeSeen: 0, shapeMissing: 0,
  lastLedger: 1099, firstMs: NOW - 1000, lastMs: NOW - 1000, ...over,
});
// Rundet wie die Engine auf 4 Nachkommastellen, damit Raten vergleichbar bleiben.
const round2 = (x) => Math.round(x * 10 ** 4) / 10 ** 4;
const stat = (l, over = {}) => ({ l, t: NOW - 1000, v: 30, need: 28, top: 30, mg: 2, sp: 0, gap: 4000, gmed: 4000, tx: 20, med: 20, c: {}, ...over });

test("failureRuns: aufeinanderfolgende Indizes bilden eine Serie, eine Pause teilt sie", () => {
  const d = day({ incidents: [inc(100, A), inc(101, A), inc(102, A), inc(104, A)] });
  const runs = failureRuns([d], { range: "all" });
  assert.equal(runs.length, 2);
  assert.equal(runs[0].ledgers, 3);
  assert.equal(runs[0].fromLedger, 100);
  assert.equal(runs[0].toLedger, 102);
  assert.equal(runs[1].ledgers, 1);
  assert.equal(runs[1].isolated, true);
});

test("failureRuns: ein nicht aufgezeichneter Ledger dazwischen heisst Recorder-Luecke, nicht Erholung", () => {
  const d = day({ incidents: [inc(100, A), inc(101, A), inc(103, A)], gaps: [{ from: 102, to: 102, t: NOW, reason: "stream-gap" }] });
  const runs = failureRuns([d], { range: "all" });
  const first = runs.find((r) => r.fromLedger === 100);
  assert.equal(first.breakAfter.ledgers, 1);
  assert.equal(first.breakAfter.cause, "recorder-gap");
});

test("failureRuns: ein aufgezeichneter Ledger dazwischen heisst validiert", () => {
  // 100..109 aufgezeichnet (lastLedger 109, ledgers 10, keine Luecke) -> 102 ist aufgezeichnet.
  const d = day({ incidents: [inc(100, A), inc(101, A), inc(103, A)], lastLedger: 109, ledgers: 10 });
  const runs = failureRuns([d], { range: "all" });
  assert.equal(runs.find((r) => r.fromLedger === 100).breakAfter.cause, "validated");
});

test("failureRuns: Urteilsfindung nach Laenge, Typmix und gleichzeitiger Betroffenheit", () => {
  const d = day({ incidents: [
    ...[100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112].map((l) => inc(l, A)),
    ...[200, 201].map((l) => inc(l, B)),
    inc(300, C, "no-quorum"),
    inc(400, D, "missed"),
    inc(500, E, "partial"),
  ] });
  const v = (m) => failureRuns([d], { range: "all" }).find((r) => r.master === m).verdict;
  assert.equal(v(A), "offline-window");   // 13 am Stueck, ab runStrongLedgers 12
  assert.equal(v(B), "short-series");     // 2 am Stueck: unter runMinLedgers 3, noch kein Ausfallfenster
  assert.equal(v(C), "vote-not-observed"); // Einzelfall ohne Quorum: Erfassung, kein Netz-Befund
  assert.equal(v(D), "isolated-miss");
  assert.equal(v(E), "degraded-single");
});

test("failureRuns: Kohortenfenster wenn die meisten Ledger der Serie auch andere treffen", () => {
  const d = day({ incidents: [100, 101, 102].flatMap((l) => [inc(l, A), inc(l, B)]) });
  const run = failureRuns([d], { range: "all" }).find((r) => r.master === A);
  assert.equal(run.coLedgers, 3);
  assert.equal(run.coShare, 1);
  assert.equal(run.verdict, "cohort-window");
  assert.deepEqual(run.coValidators, [{ master: B, ledgers: 3 }]);
});

test("failureSplit: Netzereignis-Ledger werden von privaten Ausfaellen getrennt", () => {
  // Ledger 10..15: A,B,C,D,E -> je 5 betroffene = Netzereignis. Ledger 20: nur F -> privat.
  const d = day({ incidents: [10, 11, 12, 13, 14, 15].flatMap((l) => [inc(l, A), inc(l, B), inc(l, C), inc(l, D), inc(l, E)]).concat(inc(20, F)) });
  const s = failureSplit([d], { range: "all" });
  assert.equal(s.networkLedgers, 6);
  assert.equal(s.privateLedgers, 1);
  const a = s.rows.find((r) => r.master === A);
  assert.equal(a.networkLedgers, 6);
  assert.equal(a.privateLedgers, 0);
  assert.equal(a.networkShare, 1);
  const f = s.rows.find((r) => r.master === F);
  assert.equal(f.networkShare, 0);
});

test("coFailureClusters: privates Paar wird gefunden, Netzereignis-Paar NICHT", () => {
  // F und G fallen auf 6 privaten Ledgern gemeinsam aus. A..E fallen gemeinsam in einem
  // Netzereignis aus (5 betroffene) - das ist kein Infrastruktur-Hinweis.
  const incidents = [10, 11, 12, 13, 14, 15].flatMap((l) => [inc(l, F), inc(l, G)])
    .concat([inc(500, A), inc(500, B), inc(500, C), inc(500, D), inc(500, E)]);
  const d = day({ incidents, ledgers: 100, lastLedger: 599 });
  const c = coFailureClusters([d], { range: "all" });
  assert.equal(c.coverage.networkLedgers, 1);
  assert.equal(c.coverage.privateLedgers, 6);
  assert.equal(c.strongPairs, 1);
  assert.equal(c.clusters.length, 1);
  assert.deepEqual(c.clusters[0].members, [F, G]);
  assert.equal(c.clusters[0].sharedLedgers, 6);
  // Erwartung bei Unabhaengigkeit: 6 * 6 / (100 - 1) = 36/99 = 0,363636... Lift = 6/0,363636 = 16,5
  const pair = c.pairs.find((x) => (x.a === F && x.b === G) || (x.a === G && x.b === F));
  assert.equal(pair.expected, 0.36);
  assert.equal(pair.lift, 16.5);
  assert.equal(pair.mutual, 1);
});

test("coFailureClusters: ein Anhaenger eines grossen Stoerers ist kein Paar", () => {
  // A faellt 40mal privat, B 4mal - und alle 4 von B liegen in A's Ausfaellen.
  // mutual = min(4/40, 4/4) = 0,1 -> unter coMutualMin 0,4, weil B nur ein Mitlaeufer ist.
  const incidents = Array.from({ length: 40 }, (_, i) => inc(100 + i, A))
    .concat(Array.from({ length: 4 }, (_, i) => inc(100 + i, B)));
  const c = coFailureClusters([day({ incidents, ledgers: 100, lastLedger: 199 })], { range: "all" });
  assert.equal(c.strongPairs, 0);
  assert.equal(c.clusters.length, 0);
  const pair = c.pairs.find((x) => x.a === B || x.b === B);
  assert.equal(pair.mutual, 0.1);
});

test("coFailureClusters: Netzereignis-Kohorte wird nicht als Infrastruktur verkauft", () => {
  // Der Messfehler der ersten Fassung: 6 Knoten fallen in denselben Netzereignissen zusammen.
  // Ohne Trennung der Ledger-Klassen entsteht ein Cluster von allen - hier entsteht keiner.
  const events = [500, 501, 502];
  const incidents = events.flatMap((l) => [A, B, C, D, E, F].map((m) => inc(l, m)));
  const c = coFailureClusters([day({ incidents, ledgers: 100, lastLedger: 599 })], { range: "all" });
  assert.equal(c.coverage.networkLedgers, 3);
  assert.equal(c.coverage.privateLedgers, 0);
  assert.equal(c.clusters.length, 0);
  assert.equal(c.pairs.length, 0);
});

test("validatorFingerprint: Nenner enthaelt validierte Ledger, nicht nur die Ausfaelle", () => {
  // 100 Ledger, 10 davon aufgefallen bei A -> Rate 0,1. Ohne ok-Zaehler waeren es 1,0.
  const d = day({
    incidents: [100, 101, 102, 103, 104, 105, 106, 107, 108, 109].map((l) => inc(l, A)),
    validators: { [A]: { ok: 90, partial: 0, missed: 10, wrongHash: 0, noQuorum: 0 }, [B]: { ok: 100, partial: 0, missed: 0, wrongHash: 0, noQuorum: 0 } },
  });
  const fp = validatorFingerprint([d], A, { range: "all" });
  assert.equal(fp.ledgers, 100);
  assert.equal(fp.incidents, 10);
  assert.equal(fp.rate, 0.1);
  assert.equal(fp.counts.missed, 10);
  assert.equal(fp.seriesShare, 1);
  assert.equal(fp.verdict, "chronic-outage");
});

test("validatorFingerprint: ein Knoten, der nur in Netzereignissen faellt, ist network-driven", () => {
  const incidents = [500, 501, 502].flatMap((l) => [A, B, C, D, E].map((m) => inc(l, m)));
  const d = day({
    incidents, ledgers: 100, lastLedger: 599,
    validators: Object.fromEntries([A, B, C, D, E].map((m) => [m, { ok: 97, partial: 0, missed: 3, wrongHash: 0, noQuorum: 0 }])),
  });
  const fp = validatorFingerprint([d], A, { range: "all" });
  assert.equal(fp.networkShare, 1);
  assert.equal(fp.privateLedgers, 0);
  assert.equal(fp.verdict, "network-driven");
});

test("validatorFingerprint: ohne Vorfälle bleibt die Signatur clean", () => {
  const d = day({ validators: { [A]: { ok: 50, partial: 0, missed: 0, wrongHash: 0, noQuorum: 0 } } });
  const fp = validatorFingerprint([d], A, { range: "all" });
  assert.equal(fp.incidents, 0);
  assert.equal(fp.verdict, "clean");
  assert.equal(fp.longestRun, null);
});

test("quorumCriticality: randkritisch ist nur, wer die Schliessung verneint", () => {
  // Nachgerechnet: marginalMargin = 1 (DIAGNOSE_DEFAULTS). 0 <= 1, 5 > 1.
  const d = day({
    incidents: [inc(100, A), inc(101, A)],
    ledgerStats: [stat(100, { mg: 0, cl: false, ch: "H100" }), stat(101, { mg: 5 })],
  });
  const q = quorumCriticality([d], A, { range: "all" });
  assert.equal(q.checked, 2);
  assert.equal(q.critical, 1);
  assert.equal(q.followOn, 1);
  assert.equal(q.unanswered, 0);
  assert.equal(q.closed, 1, "nur 101 gilt als geschlossen - 100 verneint die Schliessung ausdrucklich");
  assert.equal(q.captureGaps, 0);
  // Beide Zeilen haben weder 'pg' noch eine erfasste Stream-Luecke: die Erfassungs-Frage ist offen.
  assert.equal(q.captureGapUnknown, 2, "offen ist offen, nicht 'keine Luecke'");
  assert.equal(q.rows[0].ledgerIndex, 100);
  assert.equal(q.rows[0].critical, true);
  assert.equal(q.rows[0].verdict, "not-closed");
  assert.equal(q.rows[0].closure.basis, "recorder");
  assert.equal(q.rows[0].closure.hash, "H100");
  assert.equal(q.rows[1].critical, false, "Marge 5 > marginalMargin 1");
  assert.equal(q.rows[1].verdict, "closed-quorum-observed");
  assert.equal(q.rows[1].closure.basis, "validated-ledger-stream");
});

// Der Typname muss der Schliessungs-Lage in derselben Zeile folgen. noQuorum ist der Zaehler,
// keine Aussage: auf einem bewiesen geschlossenen Ledger heisst der Befund vote-not-observed,
// und no-quorum bleibt der Zeile vorbehalten, die ihre Schliessung selbst verneint. Sonst steht
// in einer Zeile "Schliessung nicht belegt", die zugleich den bestaetigten Schliess-Hash nennt.
test("quorumCriticality: der Typname folgt dem Schliess-Beweis in derselben Zeile", () => {
  const closed = day({
    incidents: [inc(107695059, A, "no-quorum")],
    ledgerStats: [stat(107695059, { v: 16, top: 16, need: 28, mg: -12, ch: "986E8D51", cl: true, chSource: "xrpscan", chVerifiedBy: "xrplcluster.com" })],
  });
  const closedRow = quorumCriticality([closed], A, { range: "all" }).rows[0];
  assert.equal(closedRow.closure.closed, true);
  assert.equal(closedRow.type, "vote-not-observed", "geschlossener Ledger: kein Vote erfasst, nicht kein Quorum");

  const denied = day({
    incidents: [inc(100, A, "no-quorum")],
    ledgerStats: [stat(100, { v: 4, top: 4, need: 28, mg: -24, ch: "H100", cl: false })],
  });
  const deniedRow = quorumCriticality([denied], A, { range: "all" }).rows[0];
  assert.equal(deniedRow.closure.closed, false);
  assert.equal(deniedRow.type, "no-quorum", "verneinte Schliessung: no-quorum ist der ehrliche Name");
  assert.equal(deniedRow.critical, true);

  // Der umgekehrte Fall: ein als vote-not-observed geschriebener Vorfall auf einer Zeile, die
  // ihre Schliessung ausdruecklich verneint, darf nicht als "Ledger geschlossen" dastehen.
  const crossed = day({
    incidents: [inc(101, A, "vote-not-observed")],
    ledgerStats: [stat(101, { v: 4, top: 4, need: 28, mg: -24, ch: "H101", cl: false })],
  });
  assert.equal(quorumCriticality([crossed], A, { range: "all" }).rows[0].type, "no-quorum");

  // missed / partial / wrong-hash bleiben unveraendert - die Umbenennung gilt nur fuer den
  // Sammel- Zaehler, der beide Bedeutungen trug.
  const other = day({
    incidents: [inc(102, A, "missed"), inc(103, A, "partial"), inc(104, A, "wrong-hash")],
    ledgerStats: [stat(102, { mg: 4 }), stat(103, { mg: 4 }), stat(104, { mg: 4 })],
  });
  const others = new Map(quorumCriticality([other], A, { range: "all" }).rows.map((r) => [r.ledgerIndex, r.type]));
  assert.deepEqual([102, 103, 104].map((l) => others.get(l)), ["missed", "partial", "wrongHash"], "nur der Sammel-Zaehler wird umbenannt");
});
test("quorumCriticality: die drei Faelle vom 16.10.2026, von Hand nachgerechnet", () => {
  // needed = ceil(35 * 0.8) = 28 (quorumFrac in lib/validator-trace.mjs).
  //   107695059  top 16  Marge 16 - 28 = -12  gap 1 000  gmed 1 000
  //   107694001  top  0  Marge  0 - 28 = -28  gap 70 000 gmed 1 000
  //   107690236  top 20  Marge 20 - 28 = -8   gap 1 000  gmed 1 000
  // Alle drei Ledger weist xrpscan (api.xrpscan.com/api/v1/ledger/<idx>) als validiert aus:
  // 986E8D51..., 20444972..., FB3ABE4A... 'critical' muss hier 0 sein - eine negative Marge
  // beschreibt, wie viele Stimmen DIESER Rekorder sah, nie ein fehlendes Netz-Quorum.
  // Die Erfassungs-Luecke kommt aus dem Luecken-Log des Tages, nicht aus dem Abstand: der Rekorder
  // meldete fuer 107694001 den Sprung 107693984-107694000 (17 Ledger fehlten). Fuer 107695059 und
  // 107690236 meldete er keinen Sprung, und 'pg' gab es damals noch nicht - offen, nicht 'frei'.
  const rows = [
    stat(107695059, { v: 16, top: 16, need: 28, mg: -12, gap: 1000, gmed: 1000, tx: 52, ov: 16, ch: "986E8D51", cl: true }),
    stat(107694001, { v: 0, top: 0, need: 28, mg: -28, gap: 70000, gmed: 1000, tx: 93, ov: 0, ch: "20444972", cl: true }),
    stat(107690236, { v: 20, top: 20, need: 28, mg: -8, gap: 1000, gmed: 1000, tx: 27, ov: 20, ch: "FB3ABE4A", cl: true }),
  ];
  const d = day({
    incidents: rows.map((r) => inc(r.l, A, "no-quorum")), ledgerStats: rows,
    gaps: [{ from: 107693984, to: 107694000, t: NOW - 1000, reason: "stream-gap" }],
  });
  const q = quorumCriticality([d], A, { range: "all" });
  assert.equal(q.checked, 3);
  assert.equal(q.critical, 0, "kein validierter Ledger darf als Netz-Quorumausfall gelten");
  assert.equal(q.followOn, 3);
  assert.equal(q.closed, 3);
  assert.equal(q.captureGaps, 1, "nur 107694001 hat einen gemessenen Sprung: 107694000 liegt im Luecken-Log");
  assert.equal(q.captureGapUnknown, 2, "fuer die anderen beiden ist die Erfassung nicht aufgezeichnet");
  const byIdx = new Map(q.rows.map((r) => [r.ledgerIndex, r]));
  assert.equal(byIdx.get(107695059).verdict, "closed-observation-gap");
  assert.equal(byIdx.get(107695059).closure.hash, "986E8D51");
  assert.equal(byIdx.get(107695059).observedValidations, 16);
  assert.equal(byIdx.get(107695059).captureGap, null, "kein Sprung erfasst, kein pg - die Frage bleibt offen");
  assert.equal(byIdx.get(107695059).captureGapBasis, "not-recorded");
  assert.equal(byIdx.get(107694001).verdict, "closed-capture-gap");
  assert.equal(byIdx.get(107694001).captureGap, true);
  assert.equal(byIdx.get(107694001).captureGapBasis, "stream-gap", "der Beleg ist der Luecken-Log des Tages");
  assert.equal(byIdx.get(107690236).verdict, "closed-observation-gap");
  assert.equal(byIdx.get(107690236).margin, -8);
});

/* Der nachgerechnete Falsch-Positiv-Fall aus der eigenen Aufzeichnung: Ledger 107699231 meldete
 * cg === true bei 8 000 ms Abstand gegen 1 000 ms Takt - bei 35 von 35 gesehenen Mitgliedern und
 * Marge +7. Wer hier 'Erfassungs-Luecke' liest, entlastet einen Knoten zu Unrecht oder belastet
 * das Netz mit einer Stockung, die nie stattfand. */
test("quorumCriticality: der Abstandsgesetz-Falsch-Positiv von 107699231 gilt nicht mehr als Luecke", () => {
  const st = stat(107699231, { v: 35, top: 35, need: 28, mg: 7, sp: 0, gap: 8000, gmed: 1000, tx: 34, ov: 107, ch: "EA04849942", cl: true, cg: true });
  const q = quorumCriticality([day({ incidents: [inc(107699231, A, "partial")], ledgerStats: [st] })], A, { range: "all" });
  const r = q.rows[0];
  assert.equal(r.captureGap, null, "8 000 ms Abstand sind der Takt, nicht die Luecke dieses Recorders");
  assert.equal(r.captureGapBasis, "not-recorded");
  assert.equal(r.verdict, "closed-quorum-observed", "35 gesehen gegen 28 gefordert: Quorum hier gesehen");
  assert.equal(r.critical, false);
  assert.equal(q.captureGaps, 0);
  assert.equal(q.captureGapUnknown, 1);
});

/* Seit 2026-10-16 schreibt der Rekorder 'pg'. Damit ist die Erfassungs-Aussage eine Subtraktion,
 * keine Deutung: 107695059 - 107695058 = 1 heisst lueckenlos, 107695059 - 107695050 = 9 heisst
 * acht Ledger fehlen - samt ihrer Stimmen, die dann in 'votes / needed' fehlen. */
test("quorumCriticality: mit pg ist die Erfassungs-Luecke eine Subtraktion", () => {
  const cont = stat(107695059, { v: 16, top: 16, need: 28, mg: -12, ch: "986E8D51", cl: true, pg: 107695058 });
  const jump = stat(107695059, { v: 16, top: 16, need: 28, mg: -12, ch: "986E8D51", cl: true, pg: 107695050 });
  const qc = quorumCriticality([day({ incidents: [inc(107695059, A, "no-quorum")], ledgerStats: [cont] })], A, { range: "all" });
  assert.equal(qc.rows[0].captureGap, false, "107695059 = 107695058 + 1");
  assert.equal(qc.rows[0].captureGapBasis, "ledger-index");
  assert.equal(qc.rows[0].verdict, "closed-observation-gap", "16 von 28: Beobachtungsluecke, kein Netz-Quorumausfall");
  assert.equal(qc.captureGapUnknown, 0, "mit pg ist nichts offen");
  const qj = quorumCriticality([day({ incidents: [inc(107695059, A, "no-quorum")], ledgerStats: [jump] })], A, { range: "all" });
  assert.equal(qj.rows[0].captureGap, true, "107695051..107695058 fehlen");
  assert.equal(qj.rows[0].verdict, "closed-capture-gap");
  assert.equal(qj.captureGaps, 1);
});

/* Live gegengeprueft am 2026-10-16: xrpscan und xrplcluster nennen fuer 107695059 denselben
 * Hash 986E8D51A78E8B2CB53B0FDBAE613692C7D33E3C82DCEE20A2C22D5496B34602 und dieselbe Close-Zeit
 * 2026-10-16T12:34:02Z; xrpscan zaehlt 52 Tx. Der Rekorder sah 16 von 35 Mitglieder-Stimmen.
 * Nachgetragener Nachweis ist Fremdquelle - sie muss in der Diagnose benannt bleiben. */
test("quorumCriticality: nachgetragener Hash bleibt Fremdquelle mit benanntem Gegenpruefer", () => {
  const st = stat(107695059, { v: 16, top: 16, need: 28, mg: -12, gap: 1000, gmed: 1000, tx: 52,
    ch: "986E8D51A78E8B2C", chSource: "xrpscan", chVerifiedBy: "xrplcluster.com", cl: true });
  const q = quorumCriticality([day({ incidents: [inc(107695059, A, "no-quorum")], ledgerStats: [st] })], A, { range: "all" });
  const r = q.rows[0];
  assert.equal(r.closure.basis, "xrpscan", "Fremdquelle darf nicht zur eigenen Schliessung werden");
  assert.ok(CQ_CLOSURE_BASES.includes(r.closure.basis), "Basis ausserhalb der erlaubten Menge");
  assert.equal(r.closure.verifiedBy, "xrplcluster.com", "die zweite Autoritaet muss lesbar bleiben");
  assert.equal(r.critical, false, "bewiesen geschlossener Ledger ist nie Netz-Quorumausfall");
  assert.equal(r.verdict, "closed-observation-gap");
});

test("quorumCriticality: fehlender Schliess-Hash bleibt fehlend - null ist nicht 'kein Hash'", () => {
  const q = quorumCriticality([day({ incidents: [inc(100, A, "no-quorum")], ledgerStats: [stat(100, { mg: -12, top: 16, v: 16 })] })], A, { range: "all" });
  assert.equal(q.rows[0].closure.hash, null, "Altbestand ohne ch: nicht erfasst, nicht erfunden");
  assert.equal(q.rows[0].closure.basis, "validated-ledger-stream");
  assert.equal(q.rows[0].verdict, "closed-observation-gap");
  assert.equal(q.rows[0].observedValidations, null, "ov fehlt in Altdaten: null, nicht 0");
});

test("windowScan: 16 von 28 Stimmen auf geschlossenem Ledger ist Erfassung, nicht knappes Netz-Quorum", () => {
  // Nachgerechnet: 16 < 28, Marge -12 <= marginalMargin 1. Ohne Schliess-Ebene stand hier
  // 'quorum-thin' - die Behauptung, das Netz habe sein Quorum nur knapp erreicht.
  const incidents = [100, 101, 102, 103].flatMap((l) => [inc(l, A), inc(l, B)]);
  const base = { mg: -12, top: 16, v: 16, need: 28, ch: "986E8D51" };
  const w = (over) => windowScan([day({ incidents, ledgerStats: [stat(100, { ...base, ...over })] })], { range: "all" })
    .windows.find((x) => x.master === A && x.fromLedger === 100);
  const closed = w({ cl: true });
  assert.ok(closed.shapeTags.includes("vote-coverage-thin"), "gemessen: 16 von 28 Stimmen dieser Aufzeichnung");
  assert.ok(!closed.shapeTags.includes("quorum-thin"), "der Ledger ist validiert - das Netz hatte sein Quorum");
  const open = w({ cl: false });
  assert.ok(open.shapeTags.includes("quorum-thin"), "nur die verneinte Schliessung laesst die Netz-Aussage zu");
  assert.ok(!open.shapeTags.includes("vote-coverage-thin"));
});

// Nachgerechnet fuer beide Zeilen:
//   100 - mm/cb/gm/ms/ovb sind im Rekorder ausdruecklich null ("vor dieser Messung nicht
//   erfasst"). Number(null) === 0 macht daraus eine Messung, und zwar die gefaehrlichste: eine
//   dUNL-Groesse von 0 mit dem Herkunfts-Label 'recorded'.
//   101 - dieselben Groessen sind als 0 gemessen. 0 ist ein Messwert und muss 0 bleiben.
// 16 gesehene Validierungen + 0 Abwesenheiten = 16 Mitglieder (derived); 35 aufgeschriebene = 35
// (recorded). Ziel 28: ceil(35 * 0.8) = 28, echte Obergrenze 35 - 28 = 7.
test("quorumCriticality: null aus dem Rekorder ist nicht 0 - null heisst nicht gemessen", () => {
  const unrecorded = stat(100, {
    mg: -12, top: 16, v: 16, need: 28, ch: "986E8D51", ov: 41,
    mm: null, cb: null, gm: null, ms: null, ovb: null,
  });
  const q = quorumCriticality([day({ incidents: [inc(100, A, "no-quorum")], ledgerStats: [unrecorded] })], A, { range: "all" });
  const row = q.rows[0];
  assert.equal(row.observedBaseline, null, "ovb null: die eigene Empfangs-Basis wurde nicht erfasst, nicht 0");
  assert.equal(row.capture.membersSeen, null, "ms null: offen, nicht 'kein Mitglied hat abgestimmt'");
  assert.equal(row.capture.coverageBaseline, null, "cb null: kein Abdeckungs-Niveau, nicht Abdeckung 0");
  assert.equal(row.capture.genuineAbsentMaxLedger, null, "gm null: die Grenze ist offen, nicht 'null echte Ausfaelle'");
  assert.equal(row.capture.members, 16, "16 Validierungen + 0 Abwesenheiten, abgeleitet statt erfunden");
  assert.equal(row.capture.membersBasis, "derived", "ohne mm darf die dUNL-Groesse nie als 'recorded' dastehen");
  assert.equal(row.capture.genuineAbsentMax, 0, "max(0, 16 - 28) = 0: unter dem Ziel bleibt nichts echt Fehlendes uebrig");
  assert.equal(row.capture.captureArtifactMin, 0, "max(0, 0 - 0) = 0: diese Zeile weist keine Luecke nach");
  assert.equal(q.critical, 0, "ein bewiesen geschlossener Ledger ist nie quorum-kritisch");
});

test("quorumCriticality: ein gemessener 0 bleibt 0 - die Null-Sperre gilt nur fuer null", () => {
  const measuredZero = stat(101, {
    mg: -12, top: 16, v: 16, need: 28, ch: "986E8D51", cl: true, ov: 0,
    mm: 35, cb: 0, gm: 0, ms: 0, ovb: 0,
  });
  const q = quorumCriticality([day({ incidents: [inc(101, A, "no-quorum")], ledgerStats: [measuredZero] })], A, { range: "all" });
  const row = q.rows[0];
  assert.equal(row.observedBaseline, 0, "ovb 0 ist gemessen: dieser Rekorder empfing in den letzten Ledgern nichts");
  assert.equal(row.capture.members, 35, "mm 35 ist gemessen");
  assert.equal(row.capture.membersBasis, "recorded");
  assert.equal(row.capture.membersSeen, 0, "ms 0 ist gemessen: kein Mitglieder-Vote angekommen");
  assert.equal(row.capture.coverageBaseline, 0, "cb 0 ist gemessen: in keinem der letzten Ledger war die Erfassung dicht");
  assert.equal(row.capture.genuineAbsentMax, 7, "35 - 28 = 7");
  assert.equal(row.capture.neededDerived, 28, "ceil(35 * 0.8) = 28");
  assert.equal(row.capture.neededMatches, true, "das aufgezeichnete Ziel ist aus der eigenen dUNL-Groesse nachrechenbar");
});

test("quorumCriticality: ohne Forensik-Zeile ist die Frage offen, nicht ungefaehrlich", () => {
  const q = quorumCriticality([day({ incidents: [inc(100, A)] })], A, { range: "all" });
  assert.equal(q.checked, 0);
  assert.equal(q.critical, 0);
  assert.equal(q.unanswered, 1);
});

test("seriesContext: Position in der Serie und Serien-Urteil", () => {
  const d = day({ incidents: [inc(100, A), inc(101, A), inc(102, A)] });
  const runs = failureRuns([d], { range: "all" });
  const sc = seriesContext(runs, A, 101);
  assert.equal(sc.ledgers, 3);
  assert.equal(sc.position, 2);
  assert.equal(sc.verdict, "brief-outage");
  assert.equal(seriesContext(runs, B, 101), null);
});

test("applySeries: ohne Ledger-Ursache tritt die Serie an ihre Stelle - als correlated", () => {
  const d = day({ incidents: [100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112].map((l) => inc(l, A, "missed", ["no-correlated-cause"])) });
  const rows = [{ ledgerIndex: 105, type: "missed", scope: "solo", hypotheses: [{ tag: "solo-failure", strength: "cohort", evidence: {} }, { tag: "no-correlated-cause", strength: "none", evidence: {} }], guidance: ["solo-peering"] }];
  applySeries(rows, failureRuns([d], { range: "all" }), A);
  const row = rows[0];
  assert.equal(row.series.ledgers, 13);
  assert.equal(row.hypotheses[0].tag, "offline-window");
  assert.equal(row.hypotheses[0].strength, "correlated");
  assert.equal(row.hypotheses[0].evidence.ledgers, 13);
  assert.ok(row.hypotheses.some((x) => x.tag === "no-correlated-cause"), "die ehrliche Luecke bleibt stehen");
  assert.ok(row.guidance.includes("node-offline-window"));
  assert.ok(row.guidance.includes("solo-peering"));
});

test("applySeries: eine gemessene Ursache wird nicht von der Serie verdraengt", () => {
  const d = day({ incidents: [100, 101, 102].map((l) => inc(l, A, "missed", ["no-correlated-cause"])) });
  const rows = [{ ledgerIndex: 101, type: "missed", scope: "solo", hypotheses: [{ tag: "quorum-thin", strength: "measured", evidence: { margin: 0 } }], guidance: [] }];
  applySeries(rows, failureRuns([d], { range: "all" }), A);
  assert.equal(rows[0].hypotheses.length, 1);
  assert.equal(rows[0].hypotheses[0].tag, "quorum-thin");
  assert.equal(rows[0].series.ledgers, 3);
});

test("applySeries: ein Einzelfall bekommt keine Serien-Erklaerung", () => {
  const d = day({ incidents: [inc(100, A, "missed", ["no-correlated-cause"])] });
  const rows = [{ ledgerIndex: 100, type: "missed", scope: "solo", hypotheses: [{ tag: "no-correlated-cause", strength: "none", evidence: {} }], guidance: [] }];
  applySeries(rows, failureRuns([d], { range: "all" }), A);
  assert.equal(rows[0].series.isolated, true);
  assert.equal(rows[0].hypotheses.length, 1);
  assert.deepEqual(rows[0].guidance, []);
});

test("windowScan: Fenster werden nach Anteil gleichzeitiger Betroffenheit eingeordnet", () => {
  const solo = Array.from({ length: 20 }, (_, i) => inc(100 + i, A));
  const shared = Array.from({ length: 10 }, (_, i) => inc(500 + i, B)).concat(Array.from({ length: 10 }, (_, i) => inc(500 + i, C)));
  const w = windowScan([day({ incidents: solo.concat(shared), ledgers: 1000, lastLedger: 999 })], { range: "all" });
  const a = w.windows.find((x) => x.master === A);
  const b = w.windows.find((x) => x.master === B);
  assert.equal(a.classification, "targeted-outage");
  assert.equal(b.classification, "network-window");
  assert.equal(w.tally["targeted-outage"], 1);
  assert.equal(w.tally["network-window"], 2);
});

test("windowScan: ein langes Fenster mit Peer-Ueberschneidung unter Zufall bleibt targeted", () => {
  // 400 Ledger eigenes Fenster; Peer B faellt darin auf 18 davon. 18/400 = 4,5 % - aber die
  // Fenster-Laenge allein macht daraus kein Gemeinschaftsereignis: die Schwelle ist der Anteil.
  const incidents = [inc(100, A)];
  for (let l = 101; l <= 499; l++) incidents.push(inc(l, A));
  for (let l = 101; l <= 118; l++) incidents.push(inc(l, B));
  const d = day({ incidents, ledgers: 1000, lastLedger: 1099 });
  const w = windowScan([d], { range: "all" }).windows.find((x) => x.master === A);
  assert.equal(w.ledgers, 400);
  assert.equal(w.coShare, 18 / 400);
  assert.equal(w.classification, "targeted-outage");
});

test("windowScan: ab 50 % gemeinsame Ledger ist es ein Gemeinschaftsfenster", () => {
  const incidents = [];
  for (let l = 100; l <= 111; l++) { incidents.push(inc(l, A)); incidents.push(inc(l, B)); }
  const d = day({ incidents, ledgers: 1000, lastLedger: 1099 });
  const w = windowScan([d], { range: "all" }).windows.find((x) => x.master === A);
  assert.equal(w.coShare, 1);
  assert.equal(w.classification, "network-window");
});

test("coFailureClusters: Paare sind nach gemeinsamen Ledgers sortiert, nicht nach Lift", () => {
  // F/G teilen 6 private Ledger - das ist ein Beleg. F und H teilen genau 1: F hat 7 private
  // Ledger, H genau 1, also mutual = min(1/7, 1/1) = 0,143 und Lift = 1 / (7*1/999) = 142,71.
  // Rechnerisch gross, aber ein einzelner gemeinsamer Ledger ist kein Beleg.
  // Erwartung bei Unabhaengigkeit: private Ledger gesamt = 1000 - 0 Netzereignisse = 1000.
  const H = "nHHH";
  const incidents = [10, 11, 12, 13, 14, 15].flatMap((l) => [inc(l, F), inc(l, G)]).concat([inc(500, F), inc(500, H)]);
  const d = day({ incidents, ledgers: 1000, lastLedger: 1099 });
  const c = coFailureClusters([d], { range: "all" });
  assert.deepEqual([c.pairs[0].a, c.pairs[0].b].sort(), [F, G].sort());
  assert.equal(c.pairs[0].coLedgers, 6);
  const noise = c.pairs.find((p) => p.coLedgers === 1);
  assert.equal(noise.mutual, 0.143);
  assert.equal(noise.lift, 142.86);
  assert.ok(c.pairs[0].coLedgers > noise.coLedgers);
  // Nur das Paar mit Beleg wird als stark gezaehlt; das 1-Ledger-Paart bleibt Kandidat.
  assert.equal(c.strongPairs, 1);
  assert.equal(c.clusters.length, 1);
  assert.deepEqual(c.clusters[0].members, [F, G]);
});

// Last-Ausfall-Kurve. Alle Raten sind von Hand nachgerechnet:
//   Stufe 25-49 : 100 Ledger, 2 Ausfall-Ledger (A 2)          -> A 2/100  = 0,02
//   Stufe 50-99 :  60 Ledger, 1 Ausfall-Ledger (A 1)          -> A 1/60   = 0,0167
//   Stufe 100-199: 40 Ledger, 9 Ausfall-Ledger (A 8, B 1)     -> A 8/40   = 0,2   B 1/40 = 0,025
//   Stufe 200-399: 30 Ledger, 17 Ausfall-Ledger (A 15, B 2)   -> A 15/30  = 0,5   B 2/30 = 0,0667
// Nenner je Knoten ist jede Stufe voll (100/60/40/30), weil jedes dUNL-Mitglied in jedem
// aufgezeichneten Ledger bewertet wird.
const LOAD_DAY = (over = {}) => day({
  validators: { [A]: { ok: 213, missed: 17, partial: 0, wrongHash: 0, noQuorum: 0 }, [B]: { ok: 220, missed: 10, partial: 0, wrongHash: 0, noQuorum: 0 } },
  loadBuckets: [
    null, null,
    { l: 100, f: 2, v: { [A]: 2 } },
    { l: 60, f: 1, v: { [A]: 1 } },
    { l: 40, f: 9, v: { [A]: 8, [B]: 1 } },
    { l: 30, f: 17, v: { [A]: 15, [B]: 2 } },
  ],
  ledgers: 230, ...over,
});

test("loadResponseCurve: Stufen, Raten und Kohortenmedian treffen die von Hand gerechneten Werte", () => {
  const c = loadResponseCurve([LOAD_DAY()], { master: A, range: "all" });
  assert.equal(c.rows.length, 4);
  assert.deepEqual(c.rows.map((r) => r.label), ["25-49", "50-99", "100-199", "200-399"]);
  const r0 = c.rows[0];
  assert.equal(r0.ledgers, 100);
  assert.equal(r0.failLedgers, 2);
  assert.equal(r0.networkRate, 0.02);
  assert.equal(r0.validatorRate, 0.02);
  assert.equal(r0.validatorLedgers, 100);
  // Kohortenmedian aus [A 0,02, B 0] = 0,01 - die Kohorte haelt diese Last praktisch fehlerfrei.
  assert.equal(r0.cohortMedianRate, 0.01);
  assert.equal(r0.cohortSize, 2);
  const r3 = c.rows[3];
  assert.equal(r3.networkRate, round2(17 / 30));
  assert.equal(r3.validatorRate, round2(15 / 30));
  assert.equal(c.coverage.loadLedgers, 230);
  assert.equal(c.coverage.daysWithLoad, 1);
  assert.equal(c.coverage.daysWithoutLoad, 0);
  assert.equal(c.coverage.recorded, true);
});

test("loadResponseCurve: Baseline ist die dichteste Stufe, Obergrenze die erste Laststufe deutlich darueber", () => {
  const c = loadResponseCurve([LOAD_DAY()], { master: A, range: "all" });
  assert.equal(c.baseline.index, 2);
  assert.equal(c.baseline.label, "25-49");
  assert.equal(c.validator.baselineRate, 0.02);
  // 50-99 zeigt 0,0167 - unter der Urteils-Schwelle von 5 %, also keine Obergrenze.
  assert.equal(c.validator.ceiling, 4);
  assert.equal(c.validator.ceilingLabel, "100-199");
  assert.equal(c.validator.ceilingRate, 0.2);
  assert.equal(c.validator.verdict, "load-limited");
});

test("loadResponseCurve: ein Knoten, der schon im Normalbetrieb faellt, ist kein Kapazitaetsfall", () => {
  const d = LOAD_DAY({ loadBuckets: [null, null, { l: 100, f: 12, v: { [A]: 12 } }, { l: 60, f: 1, v: { [A]: 1 } }] });
  const c = loadResponseCurve([d], { master: A, range: "all" });
  assert.equal(c.validator.baselineRate, 0.12);
  assert.equal(c.validator.ceiling, null);
  assert.equal(c.validator.verdict, "always-failing");
});

test("loadResponseCurve: lastempfindliche und lastfeste Knoten werden getrennt", () => {
  const c = loadResponseCurve([LOAD_DAY()], { master: B, range: "all" });
  // B faellt erst ab 200-399 (2/30 = 0,0667); in 100-199 bleiben es 0,025 unter der Schwelle.
  assert.equal(c.validator.ceiling, 5);
  assert.equal(c.validator.ceilingLabel, "200-399");
  assert.equal(c.validator.ceilingRate, round2(2 / 30));
  const net = loadResponseCurve([LOAD_DAY()], { range: "all" });
  assert.equal(net.validator, null);
  assert.equal(net.network.ceiling, 4);
  assert.equal(net.network.verdict, "load-limited");
});

test("loadResponseCurve: duenne Stufen werden nie zur Baseline oder zur Obergrenze", () => {
  const d = LOAD_DAY({ loadBuckets: [null, null, null, null, { l: 10, f: 5, v: { [A]: 5 } }] });
  const c = loadResponseCurve([d], { master: A, range: "all" });
  assert.equal(c.rows[0].sample, "thin");
  assert.equal(c.baseline, null);
  assert.equal(c.validator.verdict, "unknown");
});

test("loadResponseCurve: Altbestand ohne Last-Achse bleibt eine Datenluecke, nicht 'lastfest'", () => {
  const c = loadResponseCurve([day()], { master: A, range: "all" });
  assert.equal(c.rows.length, 0);
  assert.equal(c.coverage.recorded, false);
  assert.equal(c.coverage.daysWithoutLoad, 1);
  assert.equal(c.network.verdict, "unknown");
  assert.equal(c.validator.verdict, "unknown");
});

test("loadResponseCurve: Tage werden ueber die Spanne gefiltert und mehrere Tage aufaddiert", () => {
  const old = LOAD_DAY({ date: "2026-09-01", firstMs: NOW - 40 * 86400000, lastMs: NOW - 39 * 86400000 });
  const c = loadResponseCurve([LOAD_DAY(), old], { master: A, range: "7d", now: NOW });
  assert.equal(c.coverage.daysWithLoad, 1);
  assert.equal(c.coverage.loadLedgers, 230);
  const both = loadResponseCurve([LOAD_DAY(), LOAD_DAY({ date: "2026-10-07" })], { master: A, range: "all" });
  assert.equal(both.coverage.loadLedgers, 460);
  assert.equal(both.rows[0].ledgers, 200);
});

test("Last-Schwellen sind gesetzt und werden durchgereicht", () => {
  assert.equal(DIAGNOSE_DEFAULTS.ceilingRate, 0.05);
  assert.equal(DIAGNOSE_DEFAULTS.ceilingMinLedgers, 20);
  assert.equal(DIAGNOSE_DEFAULTS.ceilingFactor, 2);
  const c = loadResponseCurve([LOAD_DAY()], { master: A, range: "all", ceilingRate: 0.6 });
  // 0,6 Schwelle: A faellt erst in 200-399 (0,5 reicht nicht) -> keine Obergrenze mehr.
  assert.equal(c.validator.ceiling, null);
  assert.equal(c.validator.verdict, "load-resilient");
});

test("Schwellwerte sind gesetzt und werden an die Funktionen durchgereicht", () => {
  assert.equal(DIAGNOSE_DEFAULTS.runMinLedgers, 3);
  assert.equal(DIAGNOSE_DEFAULTS.networkMinValidators, 5);
  assert.equal(DIAGNOSE_DEFAULTS.coMutualMin, 0.4);
  const d = day({ incidents: [10, 11, 12].flatMap((l) => [inc(l, F), inc(l, G)]) });
  // coMinLedgers 4 -> 3 gemeinsame Ledger reichen nicht; mit 3 doch.
  assert.equal(coFailureClusters([d], { range: "all" }).strongPairs, 0);
  assert.equal(coFailureClusters([d], { range: "all", coMinLedgers: 3 }).strongPairs, 1);
});

test("quorumCriticality: die Kohorte hat Namen - wer in diesem Ledger fehlte, ist aufzaehlbar", () => {
  // 107694001: neben A fehlen B und C. 107695059: nur A. Beides geschlossene Ledger.
  const rows = [
    stat(107694001, { v: 0, top: 0, need: 28, mg: -28, gap: 70000, gmed: 1000, ov: 0, ch: "20444972", cl: true, cg: true }),
    stat(107695059, { v: 16, top: 16, need: 28, mg: -12, gap: 1000, gmed: 1000, ov: 16, ch: "986E8D51", cl: true }),
  ];
  const d = day({
    incidents: [
      inc(107694001, A, "no-quorum"), inc(107694001, B, "no-quorum"), inc(107694001, C, "no-quorum"),
      inc(107695059, A, "missed"),
    ],
    ledgerStats: rows,
  });
  const q = quorumCriticality([d], A, { range: "all" });
  const byIdx = new Map(q.rows.map((r) => [r.ledgerIndex, r]));
  const cohort = byIdx.get(107694001);
  assert.equal(cohort.affectedCount, 3, "A, B und C fehlten in diesem Ledger");
  assert.deepEqual(cohort.affectedMasters, [B, C], "die eigene Zeile ist nicht ihr eigener Betroffener");
  assert.deepEqual(cohort.affectedTypes, ["vote-not-observed", "vote-not-observed"], "auf einem bewiesen geschlossenen Ledger nennt die Diagnose den Befund, nicht den Zaehler");
  const solo = byIdx.get(107695059);
  assert.equal(solo.affectedCount, 1);
  assert.deepEqual(solo.affectedMasters, [], "solo ist gemessen: niemand sonst fehlte, nicht 'nicht erfasst'");
});

test("quorumCriticality: Betroffenheit ist sortiert und bei gleichem Input identisch", () => {
  // Nachgerechnet: Sortierung nach Typ (alphabetisch), dann Master-Key.
  // 'missed' < 'no-quorum'; innerhalb no-quorum: nCCC < nFFF.
  const d = day({
    incidents: [
      inc(100, A, "missed"), inc(100, F, "no-quorum"), inc(100, C, "no-quorum"), inc(100, D, "missed"),
    ],
    ledgerStats: [stat(100, { mg: 4, top: 32, v: 32, ch: "H100", cl: true })],
  });
  const first = quorumCriticality([d], A, { range: "all" }).rows[0];
  const again = quorumCriticality([d], A, { range: "all" }).rows[0];
  assert.deepEqual(first.affectedMasters, [D, C, F]);
  assert.deepEqual(first.affectedTypes, ["missed", "vote-not-observed", "vote-not-observed"], "gleiche Schliessung, gleiche Typnamen");
  assert.deepEqual(again.affectedMasters, first.affectedMasters, "zwei Aufrufe muessen dieselbe Liste liefern");
  assert.equal(first.affectedCount, 4);
});

/* Die vierte Erfassungs-Aussage: der Ledger wurde gesehen, aber der Empfang war duenner als im
 * eigenen Normalwert. 'ot' kommt aus dem Rekorder (dort gemessen, bevor dieser Ledger bewertet
 * wurde) - die Engine erfindet keinen Grund, sie uebernimmt einen. */
test("quorumCriticality: duennerer Empfang als im eigenen Normalwert ist ein eigenes Urteil", () => {
  const thin = stat(107695059, { v: 16, top: 16, need: 28, mg: -12, ch: "986E8D51", cl: true, pg: 107695058, ov: 17, ovb: 38, ot: true });
  const usual = stat(107695060, { v: 34, top: 34, need: 28, mg: 6, ch: "AA00", cl: true, pg: 107695059, ov: 38, ovb: 38, ot: false });
  const d = day({ incidents: [inc(107695059, A, "no-quorum"), inc(107695060, A, "partial")], ledgerStats: [thin, usual] });
  const q = quorumCriticality([d], A, { range: "all" });
  const byIdx = new Map(q.rows.map((r) => [r.ledgerIndex, r]));
  const t = byIdx.get(107695059);
  assert.equal(t.verdict, "closed-reception-thin", "gesehener Ledger, duennerer Empfang als ueblich");
  assert.equal(t.observedValidations, 17, "16 Mitglieder-Stimmen plus ein Fremd-Signierer: gemessen wird der Empfang");
  assert.equal(t.observedBaseline, 38, "die Basis ist der eigene Empfangs-Median, nicht das Netz-Ziel");
  assert.equal(t.captureGap, false, "107695059 = 107695058 + 1: der Ledger wurde nicht verpasst");
  assert.equal(t.critical, false, "bewiesen geschlossen, also kein Netz-Quorumausfall");
  assert.equal(byIdx.get(107695060).verdict, "closed-quorum-observed");
  assert.equal(q.receptionThin, 1);
});

/* Ohne die Empfangs-Felder (aeltere Zeilen vor 2026-10-16) darf die Engine nichts erfinden: die
 * Erfassungs-Frage bleibt offen, auch wenn 'votes / needed' niedrig aussieht. */
test("quorumCriticality: ohne eigene Empfangsbasis bleibt eine niedrige Stimmenzahl offen", () => {
  const old = stat(107690236, { v: 20, top: 20, need: 28, mg: -8, ch: "FB3ABE4A", cl: true });
  const q = quorumCriticality([day({ incidents: [inc(107690236, A, "no-quorum")], ledgerStats: [old] })], A, { range: "all" });
  assert.equal(q.rows[0].receptionThin, false, "kein ot-Feld, keine Fehlstand-Behauptung");
  assert.equal(q.rows[0].observedBaseline, null, "fehlende Basis ist null, nicht null-Annahme");
  assert.equal(q.rows[0].verdict, "closed-observation-gap");
  assert.equal(q.receptionThin, 0);
});

/* Das Erfassungs-Protokoll (seit 2026-10-16): Verbindungsverlust und Wiederaufbau stehen als Zahl
 * in der Tagesdatei. Zuordenbar ist nur das NAECHSTE Ereignis mit Abstand - ein Ereignis
 * 'irgendwann an dem Tag' ist keine Erklaerung. */
test("quorumCriticality: Erfassungs-Ereignisse werden mit Abstand genannt, fehlende bleiben null", () => {
  const at = NOW - 1000;
  const d = day({
    incidents: [inc(107695059, A, "no-quorum")],
    ledgerStats: [stat(107695059, { v: 16, top: 16, need: 28, mg: -12, ch: "986E8D51", cl: true, pg: 107695058, ov: 17, ovb: 38, ot: true })],
    captureEvents: [
      { e: "close", atMs: at - 30000, l: 107695040, url: "wss://s1.ripple.com" },
      { e: "open", atMs: at + 4000, l: 107695040, url: "wss://s2.ripple.com" },
    ],
  });
  const q = quorumCriticality([d], A, { range: "all" });
  const r = q.rows[0];
  assert.equal(r.captureEvent.kind, "open", "das naechste Ereignis zaehlt, nicht das erste in der Liste");
  assert.equal(r.captureEvent.deltaMs, 4000);
  assert.equal(r.captureEvent.ledger, 107695040);
  assert.equal(q.captureEvents, 1);
  // Altbestand ohne dieses Protokoll: null heisst 'nichts aufgezeichnet', nie 'kein Ereignis'.
  const old = stat(107695059, { v: 16, top: 16, need: 28, mg: -12, ch: "986E8D51", cl: true });
  const q2 = quorumCriticality([day({ incidents: [inc(107695059, A, "no-quorum")], ledgerStats: [old] })], A, { range: "all" });
  assert.equal(q2.rows[0].captureEvent, null, "ohne Erfassungs-Protokoll wird nichts behauptet");
  assert.equal(q2.captureEvents, 0);
});

/* Die nachrechenbare Grenze (2026-10-17): ein bewiesen geschlossener Ledger hat sein Netz-Quorum
 * erreicht. Also koennen von den als 'kein Vote erfasst' gefuehrten dUNL-Knoten hoechstens
 * (dUNL - Ziel) echt gefehlt haben; der Rest ist nachweisbar Erfassungs-Luecke dieses Recorders.
 * Von Hand nachgerechnet mit den echten Zaehlern der Tagesdatei 2026-10-16 (dUNL 35,
 * Ziel ceil(35 * 0.8) = 28):
 *   107695059  v 16  top 16  noQuorum 19  ->  16 + 19 = 35, echt hoechstens 7, Luecke mind. 12
 *   107694001  v  0  top  0  noQuorum 35  ->   0 + 35 = 35, echt hoechstens 7, Luecke mind. 28
 *   107690236  v 20  top 20  noQuorum 15  ->  20 + 15 = 35, echt hoechstens 7, Luecke mind.  8
 * Summe der nachweisbaren Luecke ueber diese drei Ledger: 48.
 */
test("quorumCriticality: auf geschlossenem Ledger ist der Rest der Kohorte nachrechenbar", () => {
  const rows = [
    stat(107695059, { v: 16, top: 16, need: 28, mg: -12, ch: "986E8D51", cl: true, c: { missed: 0, partial: 0, wrongHash: 0, noQuorum: 19 } }),
    stat(107694001, { v: 0, top: 0, need: 28, mg: -28, ch: "20444972", cl: true, c: { missed: 0, partial: 0, wrongHash: 0, noQuorum: 35 } }),
    stat(107690236, { v: 20, top: 20, need: 28, mg: -8, ch: "FB3ABE4A", cl: true, c: { missed: 0, partial: 0, wrongHash: 0, noQuorum: 15 } }),
  ];
  const d = day({
    incidents: rows.map((r) => inc(r.l, A, "no-quorum")), ledgerStats: rows,
    gaps: [{ from: 107693984, to: 107694000, t: NOW - 1000, reason: "stream-gap" }],
  });
  const q = quorumCriticality([d], A, { range: "all" });
  assert.equal(q.captureIncomplete, 3, "keine Zeile hat so viele Mitglieder-Stimmen gesehen, wie das Quorum verlangt");
  assert.equal(q.captureArtifactMin, 48, "12 + 28 + 8: der Anteil, der auf einem geschlossenen Ledger nicht echt sein kann");
  const byIdx = new Map(q.rows.map((r) => [r.ledgerIndex, r]));
  for (const [l, absent, min] of [[107695059, 19, 12], [107694001, 35, 28], [107690236, 15, 8]]) {
    const b = byIdx.get(l).capture;
    assert.ok(b, "ohne Grenze waere die Betroffenheits-Zeile ein Knoten-Urteil ohne Beleg");
    assert.equal(b.closed, true, "xrpscan nennt fuer diesen Ledger einen validierten Hash");
    assert.equal(b.members, 35, "Identitaet des Rekorder-Loops: gesehene Stimmen plus Flags");
    assert.equal(b.membersBasis, "derived", "mm ist im Altbestand nicht aufgezeichnet - abgeleitet und benannt");
    assert.equal(b.needed, 28);
    assert.equal(b.absentCount, absent);
    assert.equal(b.genuineAbsentMax, 7, "35 - 28: mehr als sieben echte Nicht-Signierer widerspraeche der Schliessung");
    assert.equal(b.captureArtifactMin, min);
    assert.equal(b.captureComplete, false);
  }
  assert.equal(byIdx.get(107695059).capture.seenVotes, 16);
  assert.equal(byIdx.get(107694001).capture.seenVotes, 0);
});

test("quorumCriticality: mit aufgezeichneter dUNL-Groesse ist die Grenze direkt gemessen", () => {
  const st = stat(107699168, { v: 28, top: 28, need: 28, mg: 0, ch: "59F271F8", cl: true, mm: 35, c: { missed: 0, partial: 0, wrongHash: 0, noQuorum: 7 } });
  const q = quorumCriticality([day({ incidents: [inc(107699168, A, "no-quorum")], ledgerStats: [st] })], A, { range: "all" });
  const b = q.rows[0].capture;
  assert.equal(b.membersBasis, "recorded", "mm steht in der Datei - die Grenze braucht keine Ableitung");
  assert.equal(b.members, 35);
  assert.equal(b.genuineAbsentMax, 7);
  assert.equal(b.captureArtifactMin, 0, "7 Flags bei erlaubten 7: nichts ist nachweisbar Luecke");
  assert.equal(b.captureComplete, true, "28 gesehen gegen 28 gefordert: Quorumhier gesehen");
  assert.equal(q.captureIncomplete, 0);
  assert.equal(q.captureArtifactMin, 0);
});

test("quorumCriticality: ohne Schliessung gibt es keine Grenze - null ist keine Entlastung", () => {
  const st = stat(107695059, { v: 16, top: 16, need: 28, mg: -12, cl: false, ch: "986E8D51", c: { missed: 0, partial: 0, wrongHash: 0, noQuorum: 19 } });
  const q = quorumCriticality([day({ incidents: [inc(107695059, A, "no-quorum")], ledgerStats: [st] })], A, { range: "all" });
  const b = q.rows[0].capture;
  assert.equal(b.closed, false);
  assert.equal(b.genuineAbsentMax, null, "ohne Schliessung darf keine Obergrenze behauptet werden");
  assert.equal(b.captureArtifactMin, null);
  assert.equal(b.captureComplete, null);
  assert.equal(q.captureArtifactMin, 0, "null traegt nicht zur Summe bei");
  assert.equal(q.captureIncomplete, 0);
});

// Die Frage, die am 2026-10-16 live entschieden wurde: drei Ledger, die das Netz geschlossen hat,
// bei denen dieser Rekorder aber nur 16, 0 und 20 von 28 notwendigen Stimmen sah. 'noQuorum' ist
// sein eigener Zaehler - eine Serie daraus darf erst dann Netzstockung heissen, wenn die Schliessung
// nicht bewiesen ist.
test("failureRuns: Serie ohne Quorum auf bewiesen geschlossenen Ledgern ist ein Erfassungs-Fenster", () => {
  const ledgers = [100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111];
  const d = day({
    incidents: ledgers.map((l) => inc(l, A, "no-quorum")),
    ledgerStats: ledgers.map((l) => stat(l, { cl: true, ch: "H" + l, top: 16, v: 16, mg: -12 })),
  });
  const run = failureRuns([d], { range: "all" }).find((r) => r.master === A);
  assert.equal(run.closedLedgers, 12);
  assert.equal(run.verdict, "capture-window");
});

test("failureRuns: ohne Schliess-Beweis bleibt die Serie ein offener Netz-Kandidat, keine Entlastung", () => {
  const ledgers = [100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111];
  const d = day({ incidents: ledgers.map((l) => inc(l, A, "no-quorum")) });
  const run = failureRuns([d], { range: "all" }).find((r) => r.master === A);
  assert.equal(run.closedLedgers, 0);
  assert.equal(run.verdict, "network-window");
});

test("failureRuns: ein einziger Ledger der Serie ohne Schliess-Beweis zerstoert die Klasse", () => {
  const ledgers = [100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111];
  const d = day({
    incidents: ledgers.map((l) => inc(l, A, "no-quorum")),
    ledgerStats: ledgers.slice(0, 11).map((l) => stat(l, { cl: true, ch: "H" + l, top: 16, v: 16, mg: -12 })),
  });
  const run = failureRuns([d], { range: "all" }).find((r) => r.master === A);
  assert.equal(run.closedLedgers, 11);
  assert.equal(run.verdict, "network-window");
});

test("applySeries: die Gegenprobe einer Erfassungs-Serie ist die eigene Aufnahme, nicht die Netzstockung", () => {
  const ledgers = [100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111];
  const d = day({
    incidents: ledgers.map((l) => inc(l, A, "no-quorum")),
    ledgerStats: ledgers.map((l) => stat(l, { cl: true, ch: "H" + l, top: 16, v: 16, mg: -12 })),
  });
  const runs = failureRuns([d], { range: "all" });
  const [row] = applySeries([{ ledgerIndex: 104, hypotheses: [], guidance: [] }], runs, A);
  assert.equal(row.series.verdict, "capture-window");
  assert.ok(row.guidance.includes("capture-window"), "die Gegenprobe muss die Erfassungsseite nennen");
  assert.ok(!row.guidance.includes("network-stall"), "Netzstockung ist hier widerlegt, sie darf nicht mehr empfohlen werden");
  assert.ok(row.hypotheses.some((x) => x.tag === "capture-window" && x.strength === "correlated"));
});

/* DREI NACHGERECHNETE LIVE-LEDGER VON xrp.vet (2026-10-16), exakt so, wie der Rekorder sie
 * schrieb, und exakt so, wie xrpscan sie am 2026-10-17 gegen meldet:
 *   #107690236  hash FB3ABE4A1AD20B851C507D04375BDE442D8F47635E0CE0B3A48BCC6AFB705962  close 1792135432000  tx 27
 *   #107694001  hash 20444972846C358C955033EBFDE16AC846EA28EBFCF7D6919D29F8232A158736  close 1792149950000  tx 93
 *   #107695059  hash 986E8D51A78E8B2CB53B0FDBAE613692C7D33E3C82DCEE20A2C22D5496B34602  close 1792154042000  tx 52
 * Alle drei sind bei xrpscan UND xrplcluster als geschlossen gemeldet. Die Engine durfte sie
 * deshalb nie als "kein Quorum" fuehren - die Zahl ist die duenne Erfassung dieses Rekorders.
 * Von Hand: dUNL 35 Knoten, Ziel ceil(35 * 0,8) = 28, also hoechstens 35 - 28 = 7 echte
 * Nicht-Signierer. Alles darueber ist nachweisbar Erfassungs-Luecke dieses Recorders. */
test("quorumCriticality: drei live nachgelesene Ledger - Schliess-Beweis, Grenze und Kohorte nachgerechnet", () => {
  const dUNL = Array.from({ length: 35 }, (_, i) => "nM" + String(i + 1).padStart(2, "0"));
  const own = dUNL[0];
  const absentFor = { 107690236: 15, 107694001: 35, 107695059: 19 };
  const incidents = [];
  for (const [l, n] of Object.entries(absentFor)) {
    for (const m of dUNL.slice(0, n)) incidents.push({ l: Number(l), m, t: NOW - 1000, type: "no-quorum", r: [] });
  }
  const rows = [
    stat(107690236, { t: 1792135432000, v: 20, need: 28, top: 20, mg: -8, tx: 27, gap: 1000, gmed: 1000,
      c: { missed: 0, partial: 0, wrongHash: 0, noQuorum: 15 },
      ch: "FB3ABE4A1AD20B851C507D04375BDE442D8F47635E0CE0B3A48BCC6AFB705962", chSource: "xrpscan", chVerifiedBy: "xrplcluster.com", cl: true }),
    stat(107694001, { t: 1792149950000, v: 0, need: 28, top: 0, mg: -28, tx: 93, gap: 70000, gmed: 1000,
      c: { missed: 0, partial: 0, wrongHash: 0, noQuorum: 35 },
      ch: "20444972846C358C955033EBFDE16AC846EA28EBFCF7D6919D29F8232A158736", chSource: "xrpscan", chVerifiedBy: "xrplcluster.com", cl: true }),
    stat(107695059, { t: 1792154042000, v: 16, need: 28, top: 16, mg: -12, tx: 52, gap: 1000, gmed: 1000,
      c: { missed: 0, partial: 0, wrongHash: 0, noQuorum: 19 },
      ch: "986E8D51A78E8B2CB53B0FDBAE613692C7D33E3C82DCEE20A2C22D5496B34602", chSource: "xrpscan", chVerifiedBy: "xrplcluster.com", cl: true }),
  ];
  const d = day({ incidents, ledgerStats: rows,
    gaps: [{ from: 107693984, to: 107694000, t: 1792149950000, reason: "stream-gap" }] });
  const q = quorumCriticality([d], own, { range: "all" });
  const byIdx = new Map(q.rows.map((r) => [r.ledgerIndex, r]));
  assert.equal(q.checked, 3);
  // Kein einziger dieser Ledger ist quorum-kritikal: alle drei sind von zwei Autoritaeten
  // als geschlossen belegt. 'critical' ist der Fall verneinter Schliessung, und der liegt hier
  // bei keinem vor.
  assert.equal(q.critical, 0, "ein bewiesen geschlossener Ledger darf nicht quorum-kritikal zaehlen");
  assert.equal(q.closed, 3);
  assert.equal(q.captureGaps, 1, "nur #107694001 hat eine gemessene Erfassungs-Luecke (Luecken-Log 107693984-107694000)");
  assert.equal(q.captureGapUnknown, 2, "fuer die beiden anderen ist die Erfassungs-Frage nicht erfasst, nicht 'keine Luecke'");

  const expect = {
    107690236: { votes: 20, margin: -8, absent: 15, artifact: 8, verdict: "closed-observation-gap", gap: null, basis: "not-recorded" },
    107694001: { votes: 0, margin: -28, absent: 35, artifact: 28, verdict: "closed-capture-gap", gap: true, basis: "stream-gap" },
    107695059: { votes: 16, margin: -12, absent: 19, artifact: 12, verdict: "closed-observation-gap", gap: null, basis: "not-recorded" },
  };
  for (const [index, e] of Object.entries(expect)) {
    const r = byIdx.get(Number(index));
    assert.ok(r, "Zeile fuer #" + index + " fehlt");
    assert.equal(r.needed, 28, "ceil(35 * 0,8) = 28");
    assert.equal(r.votes, e.votes);
    assert.equal(r.topVotes, e.votes, "die fuehrende Linie ist hier dieselbe Zahl - gesehen, nicht geschlossen");
    assert.equal(r.margin, e.margin, "Marge = gesehene Stimmen - Ziel, nie ein Netz-Urteil");
    assert.equal(r.critical, false);
    assert.equal(r.type, "vote-not-observed", "geschlossener Ledger: kein Vote DIESES Recorders, nicht 'kein Quorum'");
    assert.equal(r.verdict, e.verdict);
    assert.equal(r.captureGap, e.gap);
    assert.equal(r.captureGapBasis, e.basis);
    assert.equal(r.closure.closed, true);
    assert.equal(r.closure.basis, "xrpscan", "der Hash ist nachgetragen - er muss als Fremdquelle dastehen");
    assert.equal(r.closure.verifiedBy, "xrplcluster.com", "die zweite Autoritaet muss benannt sein");
    assert.equal(r.closure.hash, rows.find((s) => s.l === Number(index)).ch);
    // Die Grenze, von Hand: 35 - 28 = 7 echte Nicht-Signierer maximal, Rest ist Erfassung.
    assert.equal(r.capture.members, 35, "35 = gesehene Mitglieder-Stimmen + ohne erfassten Vote");
    assert.equal(r.capture.membersBasis, "derived");
    assert.equal(r.capture.needed, 28);
    assert.equal(r.capture.absentCount, e.absent);
    assert.equal(r.capture.genuineAbsentMax, 7, "35 - 28 = 7");
    assert.equal(r.capture.captureArtifactMin, e.artifact, e.absent + " - 7 = " + e.artifact);
    assert.equal(r.capture.captureComplete, false, "16 von 28 Zielen ist kein vollstaendiger Empfang");
    // Die Kohorte: alle Betroffenen dieses Ledgers, ohne den eigenen Knoten.
    assert.equal(r.affectedCount, e.absent);
    assert.equal(r.affectedMasters.length, e.absent - 1, "der eigene Knoten ist nicht sein eigener Betroffener");
    assert.ok(!r.affectedMasters.includes(own));
    assert.deepEqual(r.affectedTypes, new Array(e.absent - 1).fill("vote-not-observed"));
  }
  // Die Kohorte selbst: alle Betroffenen dieses Ledgers, ohne den eigenen Knoten. Die Namen
  // haengt die Netz-Auskunft erst in lib/validator-trace-query.mjs an - getestet dort.
  const cohort = byIdx.get(107695059);
  assert.equal(cohort.affectedMasters.length, 18);
  assert.equal(new Set(cohort.affectedMasters).size, 18, "kein Knoten zaehlt zweimal");
  assert.deepEqual([...cohort.affectedMasters].sort(), cohort.affectedMasters, "die Kohorte ist deterministisch sortiert");
});
/* Dieselbe Datei, zwei Ebenen, ein Widerspruch (2026-10-16): die Ledger-Zeile nannte keine
 * Herleitung, der Tag aber hatte den Netz-Quorum 28 am Endpunkt gemessen. Die Diagnose gibt
 * die Messung an die Zeile weiter - die Zahl traegt damit ihre Herkunft bis zur Messung.
 * Wo der Tag nichts gemessen hat, bleibt die Herleitung offen; sie wird nicht erfunden. */
test("quorumCriticality: das Tag-Netz-Quorum traegt die Herleitung der Ziel-Zahl", () => {
  const d = day({
    networkQuorum: { quorum: 28, atMs: 1792169939612, endpoint: "wss://s1.ripple.com" },
    networkQuorumSamples: 17,
    incidents: [inc(107695059, A, "vote-not-observed")],
    ledgerStats: [stat(107695059, { v: 16, top: 16, need: 28, mg: -12, ch: "986E8D51", cl: true,
      chSource: "xrpscan", chVerifiedBy: "xrplcluster.com" })],
  });
  const row = quorumCriticality([d], A, { range: "all" }).rows[0];
  assert.equal(row.capture.neededBasis, "day-measured", "dieselbe Datei hat dieses Ziel gemessen, nicht nicht erfasst");
  assert.equal(row.capture.networkQuorum, 28, "der gemessene Netz-Wert steht an der Zeile");
  assert.equal(row.capture.networkQuorumBasis, "day-sample");
  assert.equal(row.capture.networkQuorumSource, "wss://s1.ripple.com", "die Zahl ist bis zur Messung zurueckverfolgbar");
  assert.equal(row.capture.networkQuorumSamples, 17, "die Samplezahl kommt aus der Datei neben dem Messwert");
  assert.equal(row.neededBasis, "day-measured", "die Zeile selbst fuehrt ihre Herleitung");
  assert.equal(row.critical, false, "ein bewiesen geschlossener Ledger ist kein randkritischer Quorum-Fall");
  const plain = day({
    incidents: [inc(107695059, A, "vote-not-observed")],
    ledgerStats: [stat(107695059, { v: 16, top: 16, need: 28, mg: -12, ch: "986E8D51", cl: true })],
  });
  const plainRow = quorumCriticality([plain], A, { range: "all" }).rows[0];
  assert.equal(plainRow.capture.neededBasis, "not-recorded", "ohne Tag-Messung bleibt die Herleitung offen");
  assert.equal(plainRow.capture.networkQuorum, null, "ohne Messung steht keine Messung da");
  assert.equal(plainRow.capture.networkQuorumSource, null, "ohne Messung wird kein Endpunkt erfunden");
});
