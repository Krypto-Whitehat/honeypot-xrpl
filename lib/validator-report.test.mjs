// lib/validator-report.test.mjs - Guard fuer den maschinenlesbaren Selbst-Report.
//
// Der Report ist die einzige Ebene, die ein Validator-Betreiber ausserhalb des Overlays
// auswerten kann. Deshalb prueft dieser Test nicht nur Form, sondern die zwei Dinge, die
// kaputtgehen koennen, ohne dass eine Zahl falsch wirkt: (1) eine Datenluecke darf nicht wie
// "keine Ursache" aussehen, (2) eine gemessene Signatur darf nicht auf "vermutet" fallen.
import test from "node:test";
import assert from "node:assert/strict";
import { REPORT_COLUMNS, reportCsv, validatorReport } from "./validator-report.mjs";

const MASTER = "nHUUgpUVNxXfxkkoyh2QDjfLfHapcut8gYwKeShnJYd3SdPui19A";
const PEER = "nHBgyVGAEhgU6GoEqoriKmkNBjzhy6WJhX9Z7cZ71yJbv28dzvVN";
const T0 = 1792100000000;

const validatorRow = (over = {}) => ({ ok: 0, partial: 0, missed: 0, wrongHash: 0, noQuorum: 0, ...over });
const day = (over = {}) => ({
  date: "2026-10-16", ledgers: 100, quorumFail: 0, validators: { [MASTER]: validatorRow(), [PEER]: validatorRow() },
  incidents: [], gaps: [], firstMs: T0, lastMs: T0 + 100000, hourly: {},
  ledgerStats: [], ledgerStatsTruncated: false, incidentLedgers: 0,
  anomaly: {}, anomalyFail: {}, loadBuckets: [], shapeSeen: 0, shapeMissing: 0, ...over,
});
const inc = (l, m, type, r) => ({ l, m, t: T0 + l, type, r });
const stat = (l, over = {}) => ({
  l, t: T0 + l, v: 30, need: 21, top: 28, mg: 7, sp: 0, gap: 5000, gmed: 5000, tx: 60, med: 55,
  c: { missed: 1, partial: 0, wrongHash: 0, noQuorum: 0 }, sh: null, sev: {}, sweep: null, ...over,
});

test("Report: eine Zeile je Vorfall, Spalten sind der Vertrag", () => {
  const days = [day({
    incidents: [inc(1000, MASTER, "missed", ["no-correlated-cause"]), inc(1001, MASTER, "no-quorum", ["no-quorum"])],
    incidentLedgers: 2,
    ledgerStats: [stat(1000), stat(1001, { mg: 0, need: 28, top: 28 })],
    anomaly: { "no-quorum": 1 }, anomalyFail: { "no-quorum": 1 },
  })];
  const r = validatorReport(days, MASTER, { range: "all", now: T0 + 200000 });
  assert.equal(r.available, true);
  assert.equal(r.rows.length, 2);
  assert.deepEqual(r.columns, REPORT_COLUMNS);
  for (const row of r.rows) {
    assert.deepEqual(Object.keys(row), REPORT_COLUMNS, "Zeile weicht von der Spaltenfolge ab");
  }
  const missed = r.rows.find((x) => x.type === "missed");
  assert.equal(missed.scope, "solo", "ohne andere Validatoren ist es ein Solo-Vorfall");
  assert.equal(missed.quorumMargin, 7, "Quorum-Rand muss in der Zeile stehen, nicht nur im Overlay");
  assert.equal(missed.txCount, 60);
});

test("Report: Datenlücke ist eine Lücke, nicht 'keine Ursache'", () => {
  // Zwei Vorfaelle: einer mit Forensik, einer aus einer Tagesdatei vor dieser Stufe.
  const days = [day({
    incidents: [inc(2000, MASTER, "missed", ["no-correlated-cause"]), inc(2001, MASTER, "missed", ["no-correlated-cause"])],
    incidentLedgers: 1,
    ledgerStats: [stat(2000)],
  })];
  const r = validatorReport(days, MASTER, { range: "all", now: T0 + 200000 });
  const blind = r.rows.find((x) => x.ledgerIndex === 2001);
  assert.match(blind.dataGaps, /forensics-not-recorded/, "ohne Forensik muss die Lücke in der Zeile stehen");
  assert.equal(blind.quorumVotes, null, "null heisst nicht erfasst, nicht 0");
  assert.match(blind.hypothesisStrength, /(^|;)none(;|$)/, "Solo ohne Forensik hat keinen Ursachen-Beleg");
  assert.doesNotMatch(blind.hypothesisStrength, /measured|correlated|cohort/, "keine Stufe darf hier stehen, die Betroffenheit oder Messung behauptet");
  assert.equal(r.coverage.daysWithStats, 1);
  assert.equal(r.coverage.daysWithoutForensics, 0, "dieser Tag HAT Forensik, nur ein Ledger fehlt");
  assert.equal(r.coverage.statsLedgers, 1);
  assert.equal(r.coverage.forensicsShare, 0.5, "1 von 2 Ausfall-Ledgern hat Forensik");
});

test("Report: gemessene Signatur bleibt gemessen, Vermutung bleibt Vermutung", () => {
  const days = [day({
    incidents: [
      inc(3000, MASTER, "missed", ["drainer-fanout"]),
      inc(3001, MASTER, "missed", ["drainer-fanout"]),
    ],
    incidentLedgers: 2,
    ledgerStats: [
      stat(3000, { sev: { "drainer-fanout": { fanoutDestinations: 41, fanoutTxs: 60 } }, sh: { n: 60, s: 3, d: 41 } }),
      stat(3001),
    ],
    anomaly: { "drainer-fanout": 40 }, anomalyFail: { "drainer-fanout": 4 },
  })];
  const r = validatorReport(days, MASTER, { range: "all", now: T0 + 200000 });
  const measured = r.rows.find((x) => x.ledgerIndex === 3000);
  const guessed = r.rows.find((x) => x.ledgerIndex === 3001);
  assert.match(measured.hypotheses, /drainer-fanout/);
  assert.match(measured.hypothesisStrength, /measured/, "Beleg in diesem Ledger ist eine Messung");
  assert.match(guessed.hypothesisStrength, /correlated/, "ohne Beleg bleibt es eine Korrelation");
  assert.ok(r.summary.hypotheses.measured >= 1);
  assert.equal(r.coverage.statsLedgers, 2, "beide Ausfall-Ledger haben Forensik");
  assert.equal(r.summary.hypotheses.measured >= 1, true);});

test("Report: Last-Achse zaelt die gezehlten Ledger, nicht die gefuellten Stufen", () => {
  // Loch in der Achse: Stufe 0 fehlt (null), weil eine alte Fassung nur Ausfall-Ledger verbuchte.
  const days = [day({
    incidents: [inc(4000, MASTER, "missed", ["no-correlated-cause"])],
    incidentLedgers: 1,
    ledgerStats: [stat(4000)],
    loadBuckets: [null, { l: 40, f: 1, v: {} }, { l: 10, f: 0, v: {} }],
  })];
  const r = validatorReport(days, MASTER, { range: "all", now: T0 + 200000 });
  assert.equal(r.coverage.loadLedgers, 50, "50 gezehlte Ledger, Stufe 0 ist ein Loch");
  assert.equal(r.coverage.loadShare, 0.5, "100 Ledger aufgezeichnet, 50 auf der Last-Achse");
});

test("Report: CSV ist Tabellenform und haegt Werte mit Komma", () => {
  const days = [day({
    incidents: [inc(5000, MASTER, "wrong-hash", ["signed-different-hash", "amendment-activity"])],
    incidentLedgers: 1,
    ledgerStats: [stat(5000)],
  })];
  const r = validatorReport(days, MASTER, { range: "all", now: T0 + 200000 });
  const csv = reportCsv(r);
  const lines = csv.trimEnd().split("\r\n");
  assert.equal(lines[0], REPORT_COLUMNS.join(","));
  assert.equal(lines.length, r.rows.length + 1);
  for (const line of lines.slice(1)) assert.equal(line.split(",").length, REPORT_COLUMNS.length);
  assert.ok(csv.includes("\r\n"), "CSV mit CRLF, damit Tabellen ohne Nachfragen lesen");
});

// Der Report ist die einzige Ebene, die ein Betreiber in ein Cron oder eine Tabelle steckt.
// Eine leere Zelle heisst dort "nicht erfasst", eine 0 heisst "gemessen: null". Nachgerechnet:
//   3000 - Schliessung verneint, dUNL-Groesse/Abdeckungs-Niveau nicht aufgezeichnet: die Grenze
//          ist offen, also drei leere Zellen.
//   3001 - geschlossen, mm 35, Ziel 28: echte Obergrenze 35 - 28 = 7, Erfassungs-Mindestwert
//          max(0, 1 Abwesenheit - 7) = 0. Diese 0 ist ein Messwert und muss als 0 erscheinen.
test("Report: leere Zelle ist nicht gemessen, 0 ist gemessen", () => {
  const days = [day({
    incidents: [inc(3000, MASTER, "no-quorum", ["no-correlated-cause"]), inc(3001, MASTER, "no-quorum", ["no-correlated-cause"])],
    incidentLedgers: 2,
    ledgerStats: [
      stat(3000, { cl: false, ov: 12, ovb: null, mm: null, cb: null, gm: null, ms: null }),
      stat(3001, { cl: true, ch: "986E8D51", ov: 16, ovb: 0, mm: 35, cb: 0, gm: 0, ms: 0, need: 28, top: 16, v: 16, mg: -12 }),
    ],
  })];
  const r = validatorReport(days, MASTER, { range: "all", now: T0 + 200000 });
  const open = r.rows.find((x) => x.ledgerIndex === 3000);
  const measured = r.rows.find((x) => x.ledgerIndex === 3001);
  assert.deepEqual([open.captureGenuineAbsentMax, open.captureArtifactMin, open.groundFalsePositiveMin], [null, null, null],
    "offene Grenzen duerfen nicht als Messwert 0 in der Auswerter-Tabelle stehen");
  assert.deepEqual([measured.captureGenuineAbsentMax, measured.captureArtifactMin], [7, 0], "35 - 28 = 7, max(0, 1 - 7) = 0");
  const cell = (line, column) => line.split(",")[REPORT_COLUMNS.indexOf(column)];
  const lines = reportCsv(r).trimEnd().split("\r\n");
  const line3000 = lines.find((l) => l.startsWith("3000,"));
  const line3001 = lines.find((l) => l.startsWith("3001,"));
  assert.equal(cell(line3000, "captureGenuineAbsentMax"), "", "leer = nicht erfasst");
  assert.equal(cell(line3000, "captureArtifactMin"), "", "leer = nicht erfasst");
  assert.equal(cell(line3000, "groundFalsePositiveMin"), "", "ohne Zeitfenster der Referenz ist die Gegenprobe offen");
  assert.equal(cell(line3001, "captureGenuineAbsentMax"), "7");
  assert.equal(cell(line3001, "captureArtifactMin"), "0", "ein gemessener 0 darf nicht leer werden");
});

test("Report: ohne Master keine Ausgabe, ohne Zeilen eine leere Tabelle", () => {
  assert.equal(validatorReport([], "", {}).available, false);
  const empty = validatorReport([day()], MASTER, { range: "all", now: T0 + 1000 });
  assert.equal(empty.rows.length, 0);
  assert.equal(empty.summary.incidents, 0);
  assert.equal(reportCsv(empty).trimEnd().split("\r\n").length, 1, "nur die Kopfzeile");
  assert.equal(empty.coverage.forensicsShare, null, "ohne Ausfall-Ledger ist der Anteil nicht beantwortbar");
});
test("Report: die Angriffsseite gehoert zum Bericht - Cluster oder benanntes Unwissen", () => {
  const days = [day({
    incidents: [inc(3000, MASTER, "missed", ["no-correlated-cause"])],
    incidentLedgers: 1,
    ledgerStats: [stat(3000)],
  })];
  const blind = validatorReport(days, MASTER, { range: "all", now: T0 + 200000 });
  assert.equal(typeof blind.impact, "object", "ohne Angriffsseite ist der Report unvollstaendig");
  assert.equal(blind.impact.verdict, "unknown", "ohne Cluster ist das benanntes Unwissen, nicht 'keine Angriffe'");
  assert.equal(blind.impact.clustersInWindow, 0);
  const cluster = {
    key: "fixture-cluster", members: ["rTESTA" + "1".repeat(26)], label: "Clusterfixture",
    totalDrops: 12, txCount: 4, distinctAccounts: 1, firstSeen: T0 + 1000, lastSeen: T0 + 60000,
    rules: ["drainer-sweep"], severity: "malicious", sightings: 1, lastReportedAt: T0 + 60000,
  };
  const armed = validatorReport(days, MASTER, { range: "all", now: T0 + 200000, clusters: [cluster] });
  assert.equal(armed.impact.clustersInWindow, 1, "die Cluster muessen im Report ankommen - sonst bleibt die Ebene blind");
  assert.ok(["unknown", "no-overlap", "thin-overlap", "no-link", "attack-linked", "node-driven"].includes(armed.impact.verdict),
    "das Urteil ist keine der zulaessigen Aussagen: " + armed.impact.verdict);
  assert.ok(armed.impact.verdictReason, "ein Urteil ohne Grund ist keine Aussage");
});

/* Benannte Knoten im Export (Retrace 2026-10-17): das Overlay nennt die betroffenen dUNL-Knoten
 * je Ledger, der CSV-Export blieb bei "6 Validatoren betroffen" stehen. Genau diese Zeile steckt
 * ein Betreiber in ein Cron oder eine Tabelle - ohne Key keine Spur, der er nachgehen kann.
 * Guard: die Keys stehen in der Zeile, und die Vergleichsgruppe "dasselbe Problem" ist getrennt
 * von Knoten, die auf demselben Ledger nur eine andere Abweichung hatten. */
test("Report: die Export-Zeile nennt die betroffenen Knoten und ihre Gruppe", () => {
  const OTHER = "nHBy1n1k8zVQp1D9Hqk1D9Hqk1D9Hqk1D9Hqk1D9Hqk1D9Hqk1D9Hq";
  const days = [day({
    incidents: [
      inc(4000, MASTER, "no-quorum", ["no-correlated-cause"]),
      inc(4000, PEER, "no-quorum", ["no-correlated-cause"]),
      inc(4000, OTHER, "wrong-hash", ["signed-different-hash"]),
    ],
    incidentLedgers: 1,
    ledgerStats: [stat(4000, { c: { missed: 0, partial: 0, wrongHash: 1, noQuorum: 2 } })],
  })];
  const r = validatorReport(days, MASTER, { range: "all", now: T0 + 200000 });
  const row = r.rows.find((x) => x.ledgerIndex === 4000);
  assert.equal(row.affectedMasters, [PEER, OTHER].sort().join(";"),
    "die anderen Knoten dieses Ledgers fehlen im Export");
  assert.equal(row.sameTypeMasters, PEER, "dasselbe Problem ist nicht dasselbe wie derselbe Ledger");
  assert.equal(row.captureOnlyMasters, PEER,
    "der Knoten mit ausschliesslich unerfasstm Eintrag muss als Erfassungs-Luecke lesbar bleiben");
  const cell = (line, column) => line.split(",")[REPORT_COLUMNS.indexOf(column)];
  const line = reportCsv(r).trimEnd().split("\r\n").find((l) => l.startsWith("4000,"));
  assert.equal(cell(line, "affectedMasters"), [PEER, OTHER].sort().join(";"), "der Export verliert die Keys");
  assert.equal(cell(line, "sameTypeMasters"), PEER);
  // Ein Master enthaelt kein Komma: die Spaltenzahl bleibt pro Zeile gleich, auch mit Keys.
  assert.equal(line.split(",").length, REPORT_COLUMNS.length, "die Keys verschieben die Spaltenfolge");
  const solo = validatorReport([day({
    incidents: [inc(4001, MASTER, "no-quorum", ["no-correlated-cause"])],
    incidentLedgers: 1,
    ledgerStats: [stat(4001)],
  })], MASTER, { range: "all", now: T0 + 200000 }).rows[0];
  assert.equal(solo.affectedMasters, "", "leer heisst gemessen: kein weiterer Knoten auf diesem Ledger");
  assert.equal(solo.sameTypeMasters, "");
  assert.equal(solo.captureOnlyMasters, "");
});
