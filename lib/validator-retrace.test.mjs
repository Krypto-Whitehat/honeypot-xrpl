// lib/validator-retrace.test.mjs — Retrace-Engine: Kohorten-Einordnung, Quorum-Forensik,
// Risikovergleich mit Stichproben-Gates, Sammelereignisse.
import test from "node:test";
import assert from "node:assert/strict";
import { buildLedgerIndex, riskProfile, retraceIncident, retraceForValidator, attackSignals, liftFor, RETRACE_DEFAULTS } from "./validator-retrace.mjs";

const NOW = Date.UTC(2026, 9, 8, 12, 0, 0);
const A = "nAAA", B = "nBBB", C = "nCCC";
const inc = (l, m, type, r = []) => ({ l, m, t: NOW - 60000, type, r });
const stat = (l, over = {}) => ({ l, t: NOW - 60000, v: 30, need: 28, top: 30, mg: 2, sp: 0, gap: 4000, gmed: 4000, tx: 20, med: 20, c: { missed: 0, partial: 0, wrongHash: 0, noQuorum: 0 }, ...over });

test("buildLedgerIndex: Vorfälle und Forensik landen am selben LedgerIndex", () => {
  const days = [{ incidents: [inc(100, A, "missed"), inc(100, B, "missed")], ledgerStats: [stat(100, { mg: 0 })] }];
  const idx = buildLedgerIndex(days);
  const e = idx.get(100);
  assert.equal(e.incidents.length, 2);
  assert.equal(e.stats.mg, 0);
});

test("riskProfile: Risikovergleich mit von Hand nachgerechneten Werten", () => {
  // 100 Ledger, 10 davon mit Ausfall. load-spike in 20 Ledgern, davon 8 mit Ausfall.
  // MIT Anomalie: 8/20 = 0,4. OHNE: (10-8)/(100-20) = 2/80 = 0,025. Lift = 16.
  const days = [{ ledgers: 100, incidents: Array.from({ length: 10 }, (_, i) => inc(1000 + i, A, "missed")), anomaly: { "load-spike": 20 }, anomalyFail: { "load-spike": 8 } }];
  const r = riskProfile(days);
  const row = r.rows.find((x) => x.tag === "load-spike");
  assert.equal(r.totalLedgers, 100);
  assert.equal(row.anomalyLedgers, 20);
  assert.equal(row.plainLedgers, 80);
  assert.equal(row.plainFailLedgers, 2);
  assert.equal(row.rateWith, 0.4);
  assert.equal(row.rateWithout, 0.025);
  assert.equal(row.lift, 16);
  assert.equal(row.reliable, true);
  assert.equal(row.note, null);
});

test("riskProfile: zu kleine Stichprobe wird NICHT zur Aussage verdichtet", () => {
  const days = [{ ledgers: 100, incidents: [inc(1, A, "missed"), inc(2, A, "missed")], anomaly: { "load-spike": 5 }, anomalyFail: { "load-spike": 2 } }];
  const row = riskProfile(days).rows.find((x) => x.tag === "load-spike");
  assert.equal(row.reliable, false);
  assert.equal(row.note, "sample-too-small");
});

test("riskProfile: ohne Anomalie-Zähler (Altbestand) entsteht keine Scheinaussage", () => {
  const r = riskProfile([{ ledgers: 500, incidents: [inc(1, A, "missed")] }]);
  assert.equal(r.rows.length, 0);
  assert.equal(r.incidentLedgers, 1);
  assert.equal(r.daysWithStats, 0);
});

test("retraceIncident: nur dieser Validator betroffen -> solo, nicht Netzwerk", () => {
  const entry = { ledgerIndex: 10, timeMs: NOW, incidents: [{ master: A, type: "missed", reasons: [] }], stats: stat(10) };
  const d = retraceIncident(entry, { master: A, type: "missed", reasons: [], ledgerIndex: 10, timeMs: NOW }, riskProfile([]));
  assert.equal(d.scope, "solo");
  assert.equal(d.affected.others, 0);
  assert.ok(d.guidance.includes("solo-peering"));
});

test("retraceIncident: mehrere Validatoren im selben Ledger -> Kohorte (Netzwerkereignis)", () => {
  const entry = { ledgerIndex: 11, timeMs: NOW, incidents: [{ master: A, type: "missed", reasons: [] }, { master: B, type: "missed", reasons: [] }, { master: C, type: "partial", reasons: [] }], stats: stat(11) };
  const d = retraceIncident(entry, { master: A, type: "missed", reasons: [], ledgerIndex: 11, timeMs: NOW }, riskProfile([]));
  assert.equal(d.scope, "cohort");
  assert.equal(d.affected.missed, 2);
  assert.equal(d.affected.partial, 1);
  assert.equal(d.affected.others, 2);
  assert.ok(d.hypotheses.some((h) => h.tag === "cohort-event"));
  assert.ok(d.guidance.includes("cohort-network"));
});

test("retraceIncident: no-quorum ist Netzstockung, kein Einzelfehler", () => {
  const entry = { ledgerIndex: 12, timeMs: NOW, incidents: [{ master: A, type: "no-quorum", reasons: ["no-quorum"] }], stats: stat(12, { mg: -6, top: 22, v: 22 }) };
  const d = retraceIncident(entry, { master: A, type: "no-quorum", reasons: ["no-quorum"], ledgerIndex: 12, timeMs: NOW }, riskProfile([]));
  assert.equal(d.scope, "network");
  assert.ok(d.guidance.includes("network-stall"));
});

test("retraceIncident: knapper Quorum-Rand wird als Messung ausgewiesen", () => {
  const entry = { ledgerIndex: 13, timeMs: NOW, incidents: [{ master: A, type: "missed", reasons: [] }], stats: stat(13, { v: 28, top: 28, need: 28, mg: 0 }) };
  const d = retraceIncident(entry, { master: A, type: "missed", reasons: [], ledgerIndex: 13, timeMs: NOW }, riskProfile([]));
  const h = d.hypotheses.find((x) => x.tag === "quorum-thin");
  assert.ok(h, "margin 0 < thinMarginMax 2");
  assert.equal(h.strength, "measured");
  assert.deepEqual(h.evidence, { topVotes: 28, needed: 28, margin: 0 });
});

test("retraceIncident: Hash-Spaltung mit mehreren Stimmen auf dem verlierenden Hash", () => {
  const entry = { ledgerIndex: 14, timeMs: NOW, incidents: [{ master: A, type: "wrong-hash", reasons: ["signed-different-hash"] }], stats: stat(14, { sp: 3 }) };
  const d = retraceIncident(entry, { master: A, type: "wrong-hash", reasons: ["signed-different-hash"], ledgerIndex: 14, timeMs: NOW }, riskProfile([]));
  const h = d.hypotheses.find((x) => x.tag === "hash-split");
  assert.ok(h);
  assert.deepEqual(h.evidence, { runnerVotes: 3, votes: 30 });
  assert.ok(d.guidance.includes("report-split"));
  assert.ok(d.guidance.includes("version-state"));
});

test("retraceIncident: 12 x Median Last ist load-extreme, nicht nur load-spike", () => {
  const entry = { ledgerIndex: 15, timeMs: NOW, incidents: [{ master: A, type: "missed", reasons: [] }], stats: stat(15, { tx: 600, med: 50 }) };
  const d = retraceIncident(entry, { master: A, type: "missed", reasons: [], ledgerIndex: 15, timeMs: NOW }, riskProfile([]));
  assert.ok(d.hypotheses.some((h) => h.tag === "load-extreme"));
  assert.equal(d.load.ratio, 12);
  assert.ok(d.guidance.includes("load-backlog"));
});

test("retraceIncident: Close-Abstand nur bei echtem Vergleichswert", () => {
  const withBase = { ledgerIndex: 16, timeMs: NOW, incidents: [{ master: A, type: "missed", reasons: [] }], stats: stat(16, { gap: 60000, gmed: 4000 }) };
  const d1 = retraceIncident(withBase, { master: A, type: "missed", reasons: [], ledgerIndex: 16, timeMs: NOW }, riskProfile([]));
  assert.ok(d1.hypotheses.some((h) => h.tag === "close-gap"));
  // Ohne Median-Basis (Altbestand) wird kein close-gap behauptet.
  const noBase = { ledgerIndex: 17, timeMs: NOW, incidents: [{ master: A, type: "missed", reasons: [] }], stats: stat(17, { gap: 60000, gmed: null }) };
  const d2 = retraceIncident(noBase, { master: A, type: "missed", reasons: [], ledgerIndex: 17, timeMs: NOW }, riskProfile([]));
  assert.ok(!d2.hypotheses.some((h) => h.tag === "close-gap"), "kein Median -> keine close-gap-Aussage");
});

test("retraceIncident: fehlende Forensik ist eine Datenlücke, kein 'kein Grund'", () => {
  const entry = { ledgerIndex: 18, timeMs: NOW, incidents: [{ master: A, type: "missed", reasons: ["no-correlated-cause"] }], stats: null };
  const d = retraceIncident(entry, { master: A, type: "missed", reasons: ["no-correlated-cause"], ledgerIndex: 18, timeMs: NOW }, riskProfile([]));
  assert.ok(d.dataGaps.includes("forensics-not-recorded"));
  assert.ok(d.hypotheses.some((h) => h.tag === "no-correlated-cause"));
  assert.ok(d.guidance.includes("unknown-cause"));
});

test("retraceIncident: Kohorten-Einordnung allein ist keine Ursache", () => {
  const entry = { ledgerIndex: 19, timeMs: NOW, incidents: [{ master: A, type: "missed", reasons: [] }], stats: stat(19) };
  const d = retraceIncident(entry, { master: A, type: "missed", reasons: [], ledgerIndex: 19, timeMs: NOW }, riskProfile([]));
  assert.ok(d.hypotheses.some((h) => h.tag === "solo-failure"));
  assert.ok(d.hypotheses.some((h) => h.tag === "no-correlated-cause"), "Einordnung ohne Grund bleibt als ohne Grund markiert");
});

test("retraceIncident: gemessener Lift hängt am passenden Korrelations-Tag", () => {
  const days = [{ ledgers: 100, incidents: Array.from({ length: 10 }, (_, i) => inc(1000 + i, A, "missed")), anomaly: { "load-spike": 20 }, anomalyFail: { "load-spike": 8 } }];
  const risk = riskProfile(days);
  const entry = { ledgerIndex: 20, timeMs: NOW, incidents: [{ master: A, type: "missed", reasons: ["load-spike"] }], stats: stat(20, { tx: 300, med: 60 }) };
  const d = retraceIncident(entry, { master: A, type: "missed", reasons: ["load-spike"], ledgerIndex: 20, timeMs: NOW }, risk);
  const h = d.hypotheses.find((x) => x.tag === "load-spike");
  assert.ok(h);
  assert.equal(h.lift.lift, 16);
  assert.equal(liftFor("new-tx-type:WeirdType", risk), null);
});

test("retraceForValidator: nur eigene Vorfälle, neueste zuerst, im Fenster", () => {
  const days = [{
    ledgers: 40,
    incidents: [
      { l: 1, m: A, t: NOW - 10 * 86400000, type: "missed", r: [] },
      { l: 2, m: B, t: NOW - 60000, type: "missed", r: [] },
      { l: 3, m: A, t: NOW - 30 * 60000, type: "wrong-hash", r: ["signed-different-hash"] },
    ],
    ledgerStats: [stat(1, { t: NOW - 10 * 86400000 }), stat(3)],
  }];
  const out = retraceForValidator(days, A, { range: "24h", now: NOW });
  assert.deepEqual(out.map((r) => r.ledgerIndex), [3]);
  assert.equal(out[0].type, "wrong-hash");
  const all = retraceForValidator(days, A, { range: "all", now: NOW });
  assert.deepEqual(all.map((r) => r.ledgerIndex), [3, 1]);
});

test("attackSignals: Sammelereignis ab Schwellwert, nach Betroffenheit sortiert", () => {
  const many = Array.from({ length: 6 }, (_, i) => inc(500, "nV" + i, "missed"));
  const few = [inc(501, A, "missed"), inc(502, B, "missed")];
  const days = [{ ledgers: 100, incidents: [...many, ...few], ledgerStats: [stat(500, { tx: 900, med: 40, sp: 4 })] }];
  const a = attackSignals(days, { range: "all", now: NOW });
  assert.equal(a.total, 1);
  assert.equal(a.threshold, RETRACE_DEFAULTS.attackMinValidators);
  const s = a.signals[0];
  assert.equal(s.ledgerIndex, 500);
  assert.equal(s.affectedValidators, 6);
  assert.ok(s.anomalies.includes("load-extreme"));
  assert.ok(s.anomalies.includes("hash-split"));
});

test("attackSignals: no-quorum-Ledger zählt auch ohne Mindestzahl an Validatoren", () => {
  const days = [{ ledgers: 50, incidents: [inc(600, A, "no-quorum", ["no-quorum"]), inc(600, B, "no-quorum", ["no-quorum"])], ledgerStats: [stat(600, { mg: -9, top: 19, v: 19 })] }];
  const a = attackSignals(days, { range: "all", now: NOW });
  assert.equal(a.signals.length, 1);
  assert.equal(a.signals[0].counts.noQuorum, 2);
});

test("attackSignals: Einzelfall unter der Schwelle wird kein Sammelereignis", () => {
  const days = [{ ledgers: 50, incidents: [inc(700, A, "missed", [])] }];
  assert.equal(attackSignals(days, { range: "all", now: NOW }).signals.length, 0);
});