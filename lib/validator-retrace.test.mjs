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

test("buildLedgerIndex: ein fehlender Vote-Messwert bleibt null - er darf nie zu 0 ms werden", () => {
  // Number(null) === 0. Ein 0 ms als Vote-Latenz ist eine vorgetaeuschte Messung und die
  // gefaehrlichste Zahl dieser Engine: sie entlastet einen Knoten, der nie abgestimmt hat,
  // und schliesst die Datenluecke 'late-vote-window', die real offen ist.
  const days = [{ incidents: [
    { l: 100, m: A, t: NOW - 60000, type: "missed", r: [], vd: null },
    { l: 101, m: A, t: NOW - 60000, type: "partial", r: [], vd: 30000 },
    { l: 102, m: A, t: NOW - 60000, type: "missed", r: [] },
  ], ledgerStats: [] }];
  const idx = buildLedgerIndex(days);
  assert.equal(idx.get(100).incidents[0].voteDelayMs, null);
  assert.equal(idx.get(101).incidents[0].voteDelayMs, 30000);
  assert.equal(idx.get(102).incidents[0].voteDelayMs, null);
});

test("retraceIncident: gemessener Spaetvote ist eine Messung, keine Korrelation", () => {
  const entry = { ledgerIndex: 12, timeMs: NOW, incidents: [{ master: A, type: "missed", reasons: ["vote-late"] }], stats: stat(12) };
  const d = retraceIncident(entry, { master: A, type: "missed", reasons: ["vote-late"], ledgerIndex: 12, timeMs: NOW, voteDelayMs: 31000 }, riskProfile([]));
  const h = d.hypotheses.find((x) => x.tag === "vote-late");
  assert.ok(h, " Spaetvalidierung muss als eigene Hypothese erscheinen");
  assert.equal(h.strength, "measured");
  assert.equal(h.evidence.voteDelayMs, 31000);
  assert.equal(h.evidence.graceMs, 20000);
  assert.equal(d.voteDelayMs, 31000);
  assert.ok(!d.dataGaps.includes("late-vote-window"), "mit Messwert ist die Luecke geschlossen");
  assert.ok(!d.hypotheses.some((x) => x.tag === "no-correlated-cause"));
  assert.ok(d.guidance.includes("late-signing-path"));
});

test("retraceIncident: ohne Messwert bleibt die Spaet-Luecke offen, auch bei voller Forensik", () => {
  const entry = { ledgerIndex: 13, timeMs: NOW, incidents: [{ master: A, type: "missed", reasons: [] }], stats: stat(13, { sh: { n: 20 } }) };
  const d = retraceIncident(entry, { master: A, type: "missed", reasons: [], ledgerIndex: 13, timeMs: NOW, voteDelayMs: null }, riskProfile([]));
  assert.deepEqual(d.dataGaps, ["late-vote-window"]);
  assert.equal(d.voteDelayMs, null);
  assert.ok(!d.hypotheses.some((x) => x.tag === "vote-late"), "ohne Messwert darf keine Spaet-Hypothese stehen");
  // partial ist kein 'missed': dort ist der Vote belegt, die Spaet-Luecke ist keine Datenluecke.
  const p = retraceIncident({ ledgerIndex: 14, timeMs: NOW, incidents: [], stats: stat(14, { sh: { n: 20 } }) },
    { master: A, type: "partial", reasons: [], ledgerIndex: 14, timeMs: NOW, voteDelayMs: null }, riskProfile([]));
  assert.deepEqual(p.dataGaps, []);
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

test("riskProfile: Altbestand ohne Signatur-Ebene wird nicht zur Vergleichsgruppe", () => {
  // 500 Ledger, ein Ausfall - aber die Tagesdatei fuehrt keine Anomalie-Zaehler (aeltere
  // Recorder-Fassung). Diese Ledger wurden nie auf Signaturen geprueft. Sie als "Ledger ohne
  // Anomalie" in die Vergleichsgruppe zu zaehlen, prueft die Gruppe gegen sich selbst und
  // erzeugt einen Lift aus ungeprueften Ledern. Die ehrliche Aussage ist: keine Messbasis.
  const r = riskProfile([{ ledgers: 500, incidents: [inc(1, A, "missed")] }]);
  assert.equal(r.rows.length, 0);
  assert.equal(r.totalLedgers, 0, "keine Basis, keine Zahl");
  assert.equal(r.incidentLedgers, 0, "ein ungepruefter Ausfall zaehlt nicht in die Risikobasis");
  assert.equal(r.daysWithStats, 0);
  assert.equal(r.coverage.daysTotal, 1);
  assert.equal(r.coverage.daysWithAnomaly, 0);
  assert.equal(r.coverage.daysWithoutAnomaly, 1, "die Luecke ist benannt, nicht weggerechnet");
  assert.equal(r.coverage.allLedgers, 500, "die Aufzeichnung bleibt als Abdeckung sichtbar");
  assert.equal(r.coverage.allIncidentLedgers, 1);
  assert.equal(r.coverage.forensicsShare, 0, "kein Ausfall-Ledger hat Forensik");
});

test("riskProfile: leerer Anomalie-Zaehler mit Marker ist Messung, ohne Marker ist Luecke", () => {
  // anomaly: {} mit anomalyRecorded heisst "an diesem Tag wurde nach Anomalien gesehen und
  // keine gefunden" - genau das ist die Vergleichsgruppe. Ein leeres Objekt ohne Marker stammt
  // aus dem Nachfuellen beim Lesen (normalizeDay) und beschreibt einen nie geprueften Tag.
  const checked = { ledgers: 100, incidents: [inc(1, A, "missed")], anomaly: {}, anomalyFail: {}, anomalyRecorded: true };
  const legacy = { ledgers: 400, incidents: [inc(2, A, "missed"), inc(3, B, "missed")], anomaly: {}, anomalyFail: {} };
  const r = riskProfile([checked, legacy]);
  assert.equal(r.totalLedgers, 100, "nur der gepruefte Tag ist Basis");
  assert.equal(r.incidentLedgers, 1);
  assert.equal(r.coverage.daysWithAnomaly, 1);
  assert.equal(r.coverage.daysWithoutAnomaly, 1);
  assert.equal(r.coverage.allLedgers, 500);
  assert.equal(r.coverage.allIncidentLedgers, 3);
  assert.equal(r.coverage.loadShare, null, "ohne Last-Achse ist der Anteil nicht beantwortbar");
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

test("retraceIncident: no-quorum ist ledgerweit, die Messung heisst Erfassung", () => {
  // Nachgerechnet: top 22 < need 28, Marge 22 - 28 = -6.
  const entry = { ledgerIndex: 12, timeMs: NOW, incidents: [{ master: A, type: "no-quorum", reasons: ["no-quorum"] }], stats: stat(12, { mg: -6, top: 22, v: 22, ch: "H12" }) };
  const d = retraceIncident(entry, { master: A, type: "no-quorum", reasons: ["no-quorum"], ledgerIndex: 12, timeMs: NOW }, riskProfile([]));
  assert.equal(d.scope, "network", "kein Knoten ist allein: alle beobachteten Mitglieder fehlten auf diesem Ledger");
  assert.ok(d.guidance.includes("capture-window"), "geschlossener Ledger: die Gegenprobe ist die eigene Erfassung");
  assert.ok(!d.guidance.includes("network-stall"), "ein bewiesen geschlossener Ledger darf keine Netzstockung nahelegen");
  assert.equal(d.closure.closed, true);
  assert.equal(d.closure.basis, "validated-ledger-stream");
  assert.equal(d.closure.hash, "H12");
  assert.equal(d.quorum.closure, d.closure, "dieselbe Schliess-Ebene in Quorum-Forensik und Diagnose");
  assert.ok(!d.hypotheses.some((x) => x.tag === "quorum-thin"), "ein geschlossener Ledger beweist das Netz-Quorum");
  const h = d.hypotheses.find((x) => x.tag === "vote-coverage-thin");
  assert.ok(h, "gemessen ist die Erfassung: 22 von 28 Stimmen der beobachteten dUNL");
  assert.equal(h.strength, "measured");
  assert.equal(h.evidence.topVotes, 22);
  assert.equal(h.evidence.needed, 28);
  assert.equal(h.evidence.closedHash, "H12");
  // Dreiwertig: dieser Fixture-Stat fuehrt kein 'pg', die Index-Folge ist also nicht erfasst.
  // Ein false an dieser Stelle waere die Behauptung "keine Erfassungs-Luecke" ohne Beleg.
  assert.equal(h.evidence.captureGap, null, "ohne 'pg' ist die Erfassungs-Luecke nicht erfasst - nicht 'keine'");
});

test("retraceIncident: knapper Quorum-Rand wird als Messung ausgewiesen, nur bei verneinter Schliessung", () => {
  const entry = { ledgerIndex: 13, timeMs: NOW, incidents: [{ master: A, type: "missed", reasons: [] }], stats: stat(13, { v: 28, top: 28, need: 28, mg: 0, cl: false, ch: "H13" }) };
  const d = retraceIncident(entry, { master: A, type: "missed", reasons: [], ledgerIndex: 13, timeMs: NOW }, riskProfile([]));
  const h = d.hypotheses.find((x) => x.tag === "quorum-thin");
  assert.ok(h, "margin 0 < thinMarginMax 2");
  assert.equal(h.strength, "measured");
  assert.deepEqual(h.evidence, { topVotes: 28, needed: 28, margin: 0 });
});

test("retraceIncident: derselbe Rand auf geschlossenem Ledger ist weder quorum-thin noch vote-coverage-thin", () => {
  // Nachgerechnet: top 28 = need 28, Marge 0. Der Ledger ist geschlossen - 'quorum-thin' waere
  // die unzulassige Behauptung eines knappen Netz-Quorums, 'vote-coverage-thin' waere falsch,
  // weil die Erfassung das Quorum voll abdeckt.
  const entry = { ledgerIndex: 13, timeMs: NOW, incidents: [{ master: A, type: "missed", reasons: [] }], stats: stat(13, { v: 28, top: 28, need: 28, mg: 0, ch: "H13" }) };
  const d = retraceIncident(entry, { master: A, type: "missed", reasons: [], ledgerIndex: 13, timeMs: NOW }, riskProfile([]));
  assert.equal(d.closure.closed, true);
  assert.ok(!d.hypotheses.some((x) => x.tag === "quorum-thin"));
  assert.ok(!d.hypotheses.some((x) => x.tag === "vote-coverage-thin"));
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

test("retraceIncident: die anderen Betroffenen stehen namentlich an der Diagnose", () => {
  // "6 Validatoren betroffen" ist eine Zahl. Erst die Keys machen eine nachvollziehbare Spur:
  // gemeinsame Infrastruktur, gemeinsamer Anbieter, oder dieselben Knoten, die immer zusammen
  // fallen. others ist die Zahl der Vorfaelle, peerMasters die Zahl der Knoten - beides ist da.
  const entry = { ledgerIndex: 21, timeMs: NOW, incidents: [
    { master: A, type: "no-quorum", reasons: ["no-quorum"] },
    { master: "nCcc", type: "no-quorum", reasons: ["no-quorum"] },
    { master: "nBbb", type: "missed", reasons: [] },
    { master: "nBbb", type: "partial", reasons: [] },
  ], stats: stat(21) };
  const d = retraceIncident(entry, { master: A, type: "no-quorum", reasons: ["no-quorum"], ledgerIndex: 21, timeMs: NOW }, riskProfile([]));
  assert.deepEqual(d.affected.peerMasters, ["nBbb", "nCcc"], "sortiert, dedupliziert, ohne den eigenen Key");
  assert.equal(d.affected.others, 3, "drei Vorfaelle von zwei anderen Knoten");
});

test("retraceIncident: die Kohorten-Hypothese traegt dieselben Keys wie die Betroffenheit", () => {
  const entry = { ledgerIndex: 22, timeMs: NOW, incidents: [{ master: A, type: "missed", reasons: [] }, { master: B, type: "missed", reasons: [] }, { master: C, type: "missed", reasons: [] }], stats: stat(22) };
  const d = retraceIncident(entry, { master: A, type: "missed", reasons: [], ledgerIndex: 22, timeMs: NOW }, riskProfile([]));
  const hy = d.hypotheses.find((x) => x.tag === "cohort-event");
  assert.deepEqual(hy.evidence.peerMasters, [B, C]);
  assert.deepEqual(hy.evidence.sameTypeMasters, [B, C], "gleicher Typ: die Kohorte ist die Vergleichsgruppe");
});

test("retraceIncident: derselbe Vorfallstyp wird von anderen Abweichungen getrennt genannt", () => {
  // 21 von 10.289 Ledgern haben gemischte Typen. "19 andere" vermischt dort Knoten mit einem
  // anderen Problem; die Vergleichsgruppe fuer den Betreiber ist die gleiche Abweichung.
  const entry = { ledgerIndex: 26, timeMs: NOW, incidents: [
    { master: A, type: "no-quorum", reasons: ["no-quorum"] },
    { master: B, type: "no-quorum", reasons: ["no-quorum"] },
    { master: C, type: "missed", reasons: [] },
  ], stats: stat(26, { mg: -6, top: 22, v: 22 }) };
  const d = retraceIncident(entry, { master: A, type: "no-quorum", reasons: ["no-quorum"], ledgerIndex: 26, timeMs: NOW }, riskProfile([]));
  assert.deepEqual(d.affected.sameTypeMasters, [B], "nur der Knoten mit demselben Vorfallstyp");
  assert.deepEqual(d.affected.otherTypeMasters, [C], "die andere Abweichung bleibt getrennt benannt");
  const hy = d.hypotheses.find((x) => x.tag === "cohort-event");
  assert.deepEqual(hy.evidence.sameTypeMasters, [B], "die Hypothese traegt die Vergleichsgruppe");
  assert.equal(hy.evidence.sameType, 1);
  assert.deepEqual(hy.evidence.peerMasters, [B, C], "die volle Kohorte bleibt erhalten");
});

test("attackSignals: das Sammelereignis nennt die betroffenen Master-Keys", () => {
  const many = Array.from({ length: 6 }, (_, i) => inc(500, "nV" + (6 - i), "missed"));
  const days = [{ ledgers: 100, incidents: many, ledgerStats: [stat(500, { tx: 900, med: 40, sp: 4 })] }];
  const s = attackSignals(days, { range: "all", now: NOW }).signals[0];
  assert.deepEqual(s.masters, ["nV1", "nV2", "nV3", "nV4", "nV5", "nV6"], "sortiert, damit zwei Aufrufe dieselbe Liste liefern");
});
test("retraceIncident: ein netzweiter Vorfall nennt die Kohorte in den Hypothesen", () => {
  // 41 von 47 VET-Vorfällen sind no-quorum. Ohne diese Hypothese stand auf genau diesen
  // Karten "keine Korrelation in diesem Ledger", obwohl 9 bis 19 andere Knoten nachweisbar
  // auf demselben Ledger fielen: die stärkste verfügbare Aussage fehlte, das Etikett
  // "netzweit" war eine leere Hülse. affectedValidators zählt noQuorum mit - sonst steht
  // auf derselben Karte "0 Validatoren betroffen" neben "19 andere".
  const entry = { ledgerIndex: 23, timeMs: NOW, incidents: [
    { master: A, type: "no-quorum", reasons: ["no-quorum"] },
    { master: B, type: "no-quorum", reasons: ["no-quorum"] },
    { master: C, type: "no-quorum", reasons: ["no-quorum"] },
  ], stats: stat(23, { mg: -6, top: 22, v: 22 }) };
  const d = retraceIncident(entry, { master: A, type: "no-quorum", reasons: ["no-quorum"], ledgerIndex: 23, timeMs: NOW }, riskProfile([]));
  const hy = d.hypotheses.find((x) => x.tag === "cohort-event");
  assert.ok(hy, "netzweiter Vorfall ohne Kohorten-Hypothese - die Betroffenheit fehlt in der Diagnose");
  assert.equal(hy.strength, "cohort");
  assert.equal(hy.evidence.affectedValidators, 3, "alle drei Knoten fielen auf diesem Ledger");
  assert.deepEqual(hy.evidence.peerMasters, [B, C], "die Hypothese trägt dieselben Keys wie die Betroffenheit");
  assert.ok(d.hypotheses.some((x) => x.tag === "vote-coverage-thin"), "die Ledger-Messung steht weiter vorn als die Einordnung");
  assert.ok(!d.hypotheses.some((x) => x.tag === "quorum-thin"), "22 < 28 auf einem geschlossenen Ledger ist Erfassung, kein knappes Netz-Quorum");
});

test("retraceIncident: die Kohorte allein ist eine Einordnung, kein Grund", () => {
  // Nur die Kohorten-Betroffenheit, keine Ledger-Messung: die ausdruckliche Luecke muss
  // daneben stehen bleiben (Design-Absicht lib/validator-retrace.mjs - Kategorie != Ursache).
  // Sonst wirkt "die ganze Kohorte fiel hier" wie eine gefundene Ursache.
  const entry = { ledgerIndex: 25, timeMs: NOW, incidents: [
    { master: A, type: "no-quorum", reasons: ["no-quorum"] },
    { master: B, type: "no-quorum", reasons: ["no-quorum"] },
  ], stats: stat(25) };
  const d = retraceIncident(entry, { master: A, type: "no-quorum", reasons: ["no-quorum"], ledgerIndex: 25, timeMs: NOW }, riskProfile([]));
  assert.deepEqual(d.hypotheses.map((h) => h.tag), ["cohort-event", "no-correlated-cause"]);
});

test("retraceIncident: ein Netz-Ledger ohne andere Betroffene bekommt keine Kohorten-Hypothese", () => {
  const entry = { ledgerIndex: 24, timeMs: NOW, incidents: [{ master: A, type: "no-quorum", reasons: ["no-quorum"] }], stats: stat(24, { mg: -6, top: 22, v: 22 }) };
  const d = retraceIncident(entry, { master: A, type: "no-quorum", reasons: ["no-quorum"], ledgerIndex: 24, timeMs: NOW }, riskProfile([]));
  assert.equal(d.scope, "network");
  assert.ok(!d.hypotheses.some((h) => h.tag === "cohort-event"), "ohne andere Betroffene ist die Kohorte eine erfundene Aussage");
});

test("retraceIncident: die Erfassungs-Grenze steht an der Messung, nicht als Behauptung", () => {
  // Nachgerechnet am echten Ledger 107695059 (dUNL 35, Ziel 28): der Rekorder sah 16 Stimmen und
  // flaggte 19 Mitglieder ohne Vote; 16 + 19 = 35 fuehrt die Identitaet des Rekorder-Loops.
  // xrpscan und xrplcluster nennen denselben Hash 986E8D51A78E8B2C... - der Ledger ist geschlossen.
  // Also koennen hoechstens 35 - 28 = 7 echt gefehlt haben, mindestens 12 sind Erfassungs-Luecke.
  const entry = { ledgerIndex: 12, timeMs: NOW, incidents: [{ master: A, type: "no-quorum", reasons: ["no-quorum"] }],
    stats: stat(12, { v: 16, top: 16, need: 28, mg: -12, ch: "986E8D51", c: { missed: 0, partial: 0, wrongHash: 0, noQuorum: 19 } }) };
  const d = retraceIncident(entry, { master: A, type: "no-quorum", reasons: ["no-quorum"], ledgerIndex: 12, timeMs: NOW }, riskProfile([]));
  const h = d.hypotheses.find((x) => x.tag === "vote-coverage-thin");
  assert.ok(h, "16 von 28 auf geschlossenem Ledger ist eine Messung, kein Netz-Quorumausfall");
  assert.equal(h.strength, "measured");
  assert.equal(h.evidence.topVotes, 16);
  assert.equal(h.evidence.needed, 28);
  assert.equal(h.evidence.absentCount, 19);
  assert.equal(h.evidence.genuineAbsentMax, 7);
  assert.equal(h.evidence.captureArtifactMin, 12);
  assert.equal(d.capture.members, 35);
  assert.equal(d.capture.membersBasis, "derived");
  assert.equal(d.capture.captureComplete, false);
  assert.ok(!d.hypotheses.some((x) => x.tag === "quorum-thin"), "geschlossener Ledger darf kein duennes Netz-Quorum behaupten");
});

test("attackSignals: das Sammelereignis nennt seine Erfassungs-Grenze", () => {
  // 16 gesehene Mitglieder-Stimmen plus 6 missed und 13 no-quorum Flags = 35; auf geschlossenem
  // Ledger sind hoechstens 7 echt, also sind mindestens 12 der 19 Flags Luecke dieses Recorders.
  const many = Array.from({ length: 6 }, (_, i) => inc(500, "nV" + (6 - i), "missed"));
  const days = [{ ledgers: 100, incidents: many, ledgerStats: [stat(500, { v: 16, top: 16, need: 28, mg: -12, ch: "H500", c: { missed: 6, partial: 0, wrongHash: 0, noQuorum: 13 } })] }];
  const s = attackSignals(days, { range: "all", now: NOW }).signals[0];
  assert.equal(s.capture.closed, true);
  assert.equal(s.capture.members, 35);
  assert.equal(s.capture.genuineAbsentMax, 7);
  assert.equal(s.capture.absentCount, 19);
  assert.equal(s.capture.captureArtifactMin, 12);
  const noStats = [{ ledgers: 100, incidents: many, ledgerStats: [] }];
  assert.equal(attackSignals(noStats, { range: "all", now: NOW }).signals[0].capture, null, "ohne Forensik-Zeile gibt es keine Grenze");
});

/* close-gap braucht die Index-Folge als Beleg (2026-10-17): 'pg' ist der zuvor ausgewertete
 * Index. pg !== l - 1 heisst, dass der Abstand die Ledger enthaelt, die dieser Rekorder nie sah. */
test("close-gap und Index-Folge: eine eigene Luecke nimmt dem Abstand die Netz-Deutung", () => {
  const mk = (l, over) => ({ ledgerIndex: l, timeMs: NOW, incidents: [{ master: A, type: "missed", reasons: [] }], stats: stat(l, over) });
  const call = (entry) => retraceIncident(entry, { master: A, type: "missed", reasons: [], ledgerIndex: entry.ledgerIndex, timeMs: NOW }, riskProfile([]));
  // pg 14 bei l 16: zwischen den bewerteten Ledgern fehlt ein Index.
  const ownGap = call(mk(16, { gap: 70_000, gmed: 1_000, pg: 14 }));
  assert.ok(!ownGap.hypotheses.some((h) => h.tag === "close-gap"), "eigene Index-Luecke: der Abstand ist keine Netz-Taktung");
  assert.ok(!ownGap.guidance.includes("network-stall"), "ohne Netz-Befund keine Netzstockung als naechste Pruefung");
  // pg 15 bei l 16: lueckenlos - derselbe Abstand ist ein Netz-Befund.
  const netGap = call(mk(16, { gap: 70_000, gmed: 1_000, pg: 15 }));
  const h = netGap.hypotheses.find((x) => x.tag === "close-gap");
  assert.ok(h, "durchgehende Index-Folge: die Messung steht");
  assert.equal(h.evidence.indexContinuity, true, "der Beleg haengt an der Index-Folge, nicht am Abstand");
  assert.ok(netGap.guidance.includes("network-stall"));
  // Ohne 'pg' (Bestand vor 2026-10-16) bleibt die Messung, die Netz-Deutung faellt.
  const unknown = call(mk(17, { gap: 70_000, gmed: 1_000 }));
  const h2 = unknown.hypotheses.find((x) => x.tag === "close-gap");
  assert.ok(h2, "der Abstand ist gemessen");
  assert.equal(h2.evidence.indexContinuity, null, "Index-Folge nicht erfasst ist nicht 'lueckenlos'");
  assert.ok(!unknown.guidance.includes("network-stall"), "ohne Beleg keine Netz-Deutung");
});

test("attackSignals: Ledger-Karte nutzt dasselbe close-gap-Kriterium wie die Hypothesen-Ebene", () => {
  const many = Array.from({ length: 6 }, (_, i) => inc(700, "nV" + i, "missed"));
  const row = (over) => [{ ledgers: 100, incidents: many, ledgerStats: [stat(700, { tx: 20, med: 20, ...over })] }];
  const gaps = (days) => attackSignals(days, { range: "all", now: NOW }).signals[0].anomalies;
  assert.ok(gaps(row({ gap: 70_000, gmed: 1_000, pg: 699 })).includes("close-gap"), "lueckenlos und 70 x Takt -> close-gap");
  assert.ok(!gaps(row({ gap: 70_000, gmed: 1_000, pg: 698 })).includes("close-gap"), "Index-Luecke: kein close-gap in der Karte");
  assert.ok(!gaps(row({ gap: 70_000, gmed: 20_000, pg: 699 })).includes("close-gap"), "70 000 ms bei 20 000 ms Takt ist unter dem Ratio - kein Tag");
  assert.ok(!gaps(row({ gap: 12_000, gmed: 1_000, pg: 699 })).includes("close-gap"), "unter gapMinMs: kein Tag");
});

test("retraceIncident: Erfassungs-Luecke ist dreiwertig - gemessen, ausgeschlossen, nicht erfasst", () => {
  const gapOf = (over) => {
    const entry = {
      ledgerIndex: 12, timeMs: NOW,
      incidents: [{ master: A, type: "no-quorum", reasons: ["no-quorum"] }],
      stats: stat(12, { mg: -6, top: 22, v: 22, ch: "H12", ...over }),
    };
    const d = retraceIncident(entry, { master: A, type: "no-quorum", reasons: ["no-quorum"], ledgerIndex: 12, timeMs: NOW }, riskProfile([]));
    return d.hypotheses.find((x) => x.tag === "vote-coverage-thin").evidence.captureGap;
  };
  assert.equal(gapOf({ pg: 11 }), false, "pg = 12 - 1: die Index-Folge ist gemessen durchgehend");
  assert.equal(gapOf({ pg: 10 }), true, "pg = 10 vor 12: Index 11 fehlt, die Luecke ist gemessen");
  assert.equal(gapOf({}), null, "ohne pg ist die Frage nicht erfasst - weder 'keine Luecke' noch 'Luecke'");
});

test("retraceIncident: die Kohorten-Zahl traegt ihre eigene Grenze", () => {
  // Nachgerechnet am Fixture: 22 gesehene Mitglieder-Stimmen, 13 Knoten ohne erfassten Vote,
  // daraus 35 beobachtete Mitglieder, need ceil(35 * 0.8) = 28, echt fehlend hoechstens
  // 35 - 28 = 7, damit mindestens 13 - 7 = 6 Erfassungs-Luecke dieses Recorders.
  const absent = Array.from({ length: 13 }, (_, i) => ({ master: "nM" + i, type: "no-quorum", reasons: ["no-quorum"] }));
  const stats = (over) => stat(12, { mg: -6, top: 22, v: 22, ch: "H12", c: { missed: 0, partial: 0, wrongHash: 0, noQuorum: 13 }, ...over });
  const run = (st) => retraceIncident(
    { ledgerIndex: 12, timeMs: NOW, incidents: absent, stats: st },
    { master: "nM0", type: "no-quorum", reasons: ["no-quorum"], ledgerIndex: 12, timeMs: NOW },
    riskProfile([]));
  const closed = run(stats({ pg: 11 })).hypotheses.find((x) => x.tag === "cohort-event");
  assert.equal(closed.evidence.affectedValidators, 13, "13 Knoten ohne erfassten Vote auf diesem Ledger");
  assert.equal(closed.evidence.closedHash, "H12", "die Grenze haengt an der Schliessung dieses Ledgers");
  assert.equal(closed.evidence.genuineAbsentMax, 7, "mehr als 7 echte Fehlende liessen den Ledger nicht schliessen");
  assert.equal(closed.evidence.captureArtifactMin, 6, "13 - 7: mindestens 6 sind Erfassungs-Luecke");
  // Verneinte Schliessung: dieselbe Rechnung ist nicht anwendbar, also bleibt die Grenze offen.
  const open = run(stats({ cl: false })).hypotheses.find((x) => x.tag === "cohort-event");
  assert.equal(open.evidence.closedHash, null, "ohne Schliessung kein geschlossener Ledger");
  assert.equal(open.evidence.genuineAbsentMax, null, "ohne Schliessung ist die Grenze nicht belegenbar");
  assert.equal(open.evidence.captureArtifactMin, null);
});
