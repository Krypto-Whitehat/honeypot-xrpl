import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import assert from "node:assert/strict";
import { fileURLToPath } from "node:url";
import {
  COUPLING_AUTHORITIES, COUPLING_AXES, COUPLING_DEFAULTS, COUPLING_GAPS,
  COUPLING_COHORT_KEYS, COUPLING_STRESS_TAGS, COUPLING_TYPES, COUPLING_VERDICTS, LOAD_TREND_VERDICTS, stressCoupling,
} from "./validator-stress-coupling.mjs";

const here = path.dirname(fileURLToPath(import.meta.url));
const NOW = 1792200000000;
const HOUR = 3600000;
const MASTER = "nHMaster";

// Die Zeit sitzt innerhalb der Spanne, nicht in der Index-Differenz: eine Fixture, deren Ledger
// elf Tage zurueckliegt, misst nichts, weil das Fenster keine Zeile findet. tx 30 faellt in die
// Stufe 25-49; gap/gmed sind erfasst, fv ist nicht erfasst - genau die Mischung der echten
// Erfassung vom 2026-10-16.
const row = (ledgerIndex, { nodes = 1, sev = {}, tx = 30 } = {}) => ({
  l: ledgerIndex, t: NOW - (ledgerIndex % 1000) * 1000, v: 20, need: 28, top: 20, mg: -8, sp: 0,
  gap: 1000, gmed: 1000, tx, med: 40,
  c: { missed: 0, partial: 0, wrongHash: 0, noQuorum: nodes },
  sh: { n: tx, s: tx, d: 0, fo: 0, fd: 0, fa: 0, fl: 0, ac: 0, oc: 0, nf: 0, bt: 0, bi: 0, fx: 0, fm: 1000, fs: 1 },
  sev, sweep: null, fv: null, lv: null, am: [], unl: false, ch: "AB" + ledgerIndex, cl: true,
});
const incident = (ledgerIndex, master = MASTER, type = "missed") => ({
  l: ledgerIndex, m: master, t: NOW - (ledgerIndex % 1000) * 1000, type, r: [type], ts: type, cb: "xrpscan",
});
const day = ({ stats = [], incidents = [], ledgers = stats.length, buckets = null }) => ({
  date: "2026-10-16", ledgers, incidents, ledgerStats: stats, loadBuckets: buckets,
  validators: {}, gaps: [], hourly: [],
});
const burst = { "sender-burst": 1 };

// Exponierte Ledger 1000000.. und Kontroll-Ledger 2000000.. in derselben Laststufe. Ohne
// dieselbe Stufe waere die Kontrolle eine Auslese und keine Gegenprobe.
const EXPOSED = Array.from({ length: 12 }, (_, i) => 1000000 + i);
const CONTROL = Array.from({ length: 12 }, (_, i) => 2000000 + i);

// 12 exponierte Ledger (8 mit Massen-Abweichung, 4 solo) gegen 12 Kontroll-Ledger ohne
// Signatur (2 mit Massen-Abweichung, 10 solo). Der eigene Knoten faellt auf 9 der exponierten
// und auf 2 der Kontroll-Ledger.
function coupledDays() {
  const stats = [
    ...EXPOSED.map((l, i) => row(l, { sev: burst, nodes: i < 8 ? 10 : 1 })),
    ...CONTROL.map((l, i) => row(l, { nodes: i < 2 ? 9 : 1 })),
  ];
  const incidents = [...EXPOSED.slice(0, 9).map((l) => incident(l)), ...CONTROL.slice(0, 2).map((l) => incident(l))];
  return [day({ stats, incidents, buckets: [null, null, { l: 24, f: 11, v: { [MASTER]: 11 } }] })];
}

test("Kopplung ueber beide Achsen: dieselbe Signatur, zwei getrennte Urteile", () => {
  const c = stressCoupling(coupledDays(), MASTER, { range: "24h", now: NOW });
  const sig = c.signatures.find((s) => s.tag === "sender-burst");
  assert.ok(sig, "die Signatur muss als eigene Zeile stehen");
  // Knoten-Achse, von Hand: 9 von 12 exponierten Ledgern, 2 von 12 Kontroll-Ledgern.
  assert.equal(sig.ledgersTotal, 12);
  assert.equal(sig.controlTotal, 12);
  assert.equal(sig.ownFailures, 9);
  assert.equal(sig.ownRateExposed, 9 / 12);
  assert.equal(sig.ownRateControl, 2 / 12);
  assert.equal(sig.ownLift, 9 / 12 - 2 / 12);
  assert.equal(sig.ownVerdict, "stress-coupled");
  assert.deepEqual(sig.ownFailureTypes, { missed: 9 });
  // Massen-Achse, von Hand: 8 von 12 exponierten Ledgern mit Massen-Abweichung, 2 von 12 Kontrolle.
  assert.equal(sig.massDeviationExposed, 8);
  assert.equal(sig.massDeviationControl, 2);
  assert.equal(sig.rateExposed, 8 / 12);
  assert.equal(sig.rateControl, 2 / 12);
  assert.equal(sig.lift, 0.5);
  assert.equal(sig.verdict, "stress-coupled");
  assert.equal(sig.authority, "measured");
  assert.equal(sig.controlRecorded, true);
  // Netz-Achse, von Hand: 8 von 10 Massen-Ledern traegen die Signatur (0.8), 4 von 14 Solo-Ledern.
  assert.equal(c.simultaneity.massLedgers, 10);
  assert.equal(c.simultaneity.soloLedgers, 14);
  assert.equal(c.simultaneity.signatureShareMass, 0.8);
  assert.equal(c.simultaneity.signatureShareSolo, 4 / 14);
  assert.equal(c.simultaneity.signatureLift, 0.8 - 4 / 14);
  assert.equal(c.axes.node, "stress-coupled");
  assert.equal(c.axes.mass, "stress-coupled");
  assert.equal(c.axes.network, "stress-coupled");
});

test("Verdikt, Achse und Begruendung kommen aus derselben Messung", () => {
  const c = stressCoupling(coupledDays(), MASTER, { range: "24h", now: NOW });
  // Staerkster Befund ist die Knoten-Achse mit 58 Punkten; die Rangliste entscheidet nach Lift.
  assert.equal(c.findings.length, 3, "knoten-, netz- und massenseitig ist je ein Befund gemessen");
  assert.deepEqual(c.findings.map((f) => f.axis), ["node", "network", "mass"], "nach Lift 0.583, 0.514, 0.5");
  assert.equal(c.findings[0].lift, 9 / 12 - 2 / 12);
  assert.equal(c.findings[0].tag, "sender-burst");
  assert.equal(c.findings[0].exposedLedgers, 12);
  assert.equal(c.findings[0].controlLedgers, 12);
  assert.equal(c.findings[0].failures, 9);
  assert.equal(c.verdict, "stress-coupled");
  assert.equal(c.verdictAxis, "node");
  assert.equal(c.verdictReason, "node-lift-plus-58-points-under-sender-burst");
  assert.equal(c.verdictAuthority, "measured");
});

test("Keine Kopplung ist ein Messergebnis: beide Achsen gemessen, beide ohne Unterschied", () => {
  const stats = [
    ...EXPOSED.map((l, i) => row(l, { sev: burst, nodes: i < 6 ? 10 : 1 })),
    ...CONTROL.map((l, i) => row(l, { nodes: i < 6 ? 10 : 1 })),
  ];
  const incidents = [...EXPOSED.slice(0, 3).map((l) => incident(l)), ...CONTROL.slice(0, 3).map((l) => incident(l))];
  const c = stressCoupling([day({ stats, incidents })], MASTER, { range: "24h", now: NOW });
  assert.equal(c.axes.node, "no-coupling-measured");
  assert.equal(c.axes.mass, "no-coupling-measured");
  assert.equal(c.axes.network, "no-coupling-measured");
  assert.equal(c.axes.networkLift, 0, "0.5 gegen 0.5 ist gemessen null, nicht offen");
  assert.equal(c.findings.length, 0);
  assert.equal(c.verdict, "no-coupling-measured");
  assert.equal(c.verdictAxis, "both");
  assert.equal(c.verdictReason, "measured-difference-below-weak-lift-on-both-axes");
  assert.equal(c.verdictAuthority, "measured", "ein gemessenes Nicht-Vorhandensein ist eine Auskunft");
});

test("Ohne Kontrolle heisst die Luecke not-recorded, nicht keine Kopplung", () => {
  const stats = EXPOSED.map((l) => row(l, { sev: burst, nodes: 1 }));
  const incidents = EXPOSED.slice(0, 8).map((l) => incident(l));
  const c = stressCoupling([day({ stats, incidents })], MASTER, { range: "24h", now: NOW });
  const sig = c.signatures.find((s) => s.tag === "sender-burst");
  assert.equal(sig.controlTotal, 0);
  assert.equal(sig.controlRecorded, false);
  assert.equal(sig.verdict, "not-recorded");
  assert.equal(sig.ownVerdict, "not-recorded");
  assert.equal(sig.lift, null, "ohne Nenner keine Rate");
  assert.equal(sig.authority, "none");
  assert.equal(c.axes.mass, "insufficient-sample", "kein Massen-Ledger heisst hier: zu wenig Nenner");
  // Die Knoten-Achse kann trotzdem sprechen: acht eigene Ausfaelle, alle unter Stress, keiner mit
  // einer Kohorte daneben - das ist der Fall, der zur Pruefung des eigenen Knotens fuehrt.
  assert.equal(c.verdict, "node-local-under-stress");
  assert.equal(c.verdictAxis, "node");
  assert.equal(c.verdictReason, "own-failures-under-stress-without-cohort");
  assert.equal(c.nodeLocal.ownFailureLedgers, 8);
  assert.equal(c.nodeLocal.ownFailureLedgersWithStress, 8);
  assert.equal(c.nodeLocal.ownFailureLedgersWithoutStress, 0);
  assert.equal(c.nodeLocal.soloUnderStress, 8);
  assert.deepEqual(c.nodeLocal.soloUnderStressTypes, { missed: 8 });
  assert.equal(c.nodeLocal.soloUnderStressLedgers[0].ledgerIndex, 1000000);
  assert.deepEqual(c.nodeLocal.soloUnderStressLedgers[0].signatures, ["sender-burst"]);
});

test("Zu wenig Nenner ist eine eigene Aussage: insufficient-sample, nicht not-recorded", () => {
  const stats = EXPOSED.slice(0, 4).map((l) => row(l, { sev: burst }));
  const c = stressCoupling([day({ stats, incidents: [incident(EXPOSED[0])] })], MASTER, { range: "24h", now: NOW });
  assert.equal(c.coverage.samples, 4);
  assert.equal(c.verdict, "insufficient-sample");
  assert.equal(c.verdictAxis, "sample");
  assert.equal(c.verdictAuthority, "derived");
  assert.ok(c.gaps.includes("sample-too-small"), "die Luecke muss benannt sein");
  assert.equal(c.signatures.find((s) => s.tag === "sender-burst").verdict, "not-recorded",
    "keine Kontrolle in dieser Laststufe ist nicht dasselbe wie zu wenig Nenner");
});

test("Ohne Forensik-Zeile beginnt die Ebene offen: not-recorded mit benannter Luecke", () => {
  const c = stressCoupling([day({ stats: [], incidents: [incident(1000000)] })], MASTER, { range: "24h", now: NOW });
  assert.equal(c.coverage.samples, 0);
  assert.equal(c.verdict, "not-recorded");
  assert.equal(c.verdictAxis, "none");
  assert.equal(c.verdictAuthority, "none");
  assert.equal(c.verdictReason, "no-ledger-forensics-row-in-this-window");
  assert.ok(c.gaps.includes("control-not-recorded"));
});

test("Die Abweichungs-Ledger ohne Zeile sind eine benannte Luecke, keine Null", () => {
  const stats = [row(1000000, { sev: burst, nodes: 9 })];
  const incidents = [1000000, 1000001, 1000002].map((l) => incident(l));
  const c = stressCoupling([day({ stats, incidents })], MASTER, { range: "24h", now: NOW });
  assert.equal(c.coverage.deviatingLedgers, 3);
  assert.equal(c.coverage.deviatingLedgersWithRow, 1);
  assert.equal(c.coverage.deviatingLedgersWithoutRow, 2, "zwei Ledger ohne jede Form, Last oder Kohorte");
  assert.ok(c.gaps.includes("forensics-row-missing"));
});

test("Massen-Ledger werden benannt, sortiert und mit Last und Schliess-Beweis ausgeliefert", () => {
  const c = stressCoupling(coupledDays(), MASTER, { range: "24h", now: NOW, opts: { peakRows: 12 } });
  assert.equal(c.simultaneity.peaks.length, 10);
  assert.deepEqual(c.simultaneity.peaks.map((p) => p.deviatingNodes),
    [10, 10, 10, 10, 10, 10, 10, 10, 9, 9], "absteigend nach Betroffenheit");
  assert.deepEqual(c.simultaneity.peaks.map((p) => p.ledgerIndex),
    [...EXPOSED.slice(0, 8), ...CONTROL.slice(0, 2)], "bei gleicher Betroffenheit nach Index");
  assert.deepEqual(c.simultaneity.peaks[0].signatures, ["sender-burst"]);
  assert.deepEqual(c.simultaneity.peaks[8].signatures, [], "die Kontrolle traegt keine Signatur");
  assert.equal(c.simultaneity.peaks[0].loadLabel, "25-49");
  assert.equal(c.simultaneity.peaks[0].closureClosed, true, "der Schliess-Beweis steht an derselben Zeile");
  assert.equal(c.simultaneity.peaks[0].needed, 28);
  assert.equal(c.simultaneity.peaks[0].margin, -8);
  assert.deepEqual(c.simultaneity.peaks[0].cohortTypes, { missed: 0, partial: 0, wrongHash: 0, noQuorum: 10 });
  assert.deepEqual(c.simultaneity.histogram,
    [{ nodes: 1, ledgers: 14 }, { nodes: 9, ledgers: 2 }, { nodes: 10, ledgers: 8 }]);
  assert.equal(c.simultaneity.massThreshold, COUPLING_DEFAULTS.simultaneityNodes);
  assert.equal(c.simultaneity.massHighLedgers, 0, "10 und 9 sind unter der Massen-Hochschwelle von 15");
});

test("Last-Achse mit vollem Nenner: die Ledger ohne Ausfall sind Teil der Auskunft", () => {
  const c = stressCoupling(coupledDays(), MASTER, { range: "24h", now: NOW });
  assert.equal(c.loadAxis.recorded, true);
  assert.deepEqual(c.loadAxis.rows.map((r) => r.label), ["25-49"]);
  assert.equal(c.loadAxis.rows[0].ledgers, 24);
  assert.equal(c.loadAxis.rows[0].fails, 11);
  assert.equal(c.loadAxis.rows[0].own, 11);
  assert.equal(c.loadAxis.rows[0].networkRate, 11 / 24);
  assert.equal(c.loadAxis.rows[0].ownRate, 11 / 24);
  assert.equal(c.loadAxis.rows[0].sample, "measured");
  const noAxis = stressCoupling([day({ stats: [row(1000000)], ledgers: 120 })], MASTER, { range: "24h", now: NOW });
  assert.equal(noAxis.loadAxis.recorded, false);
  assert.equal(noAxis.loadAxis.ledgersWithoutAxis, 120, "ohne Achse ist die Zahl offen, nicht null");
});

test("Fenster: ein Vorfall ausserhalb der Spanne wird nicht mitgerechnet", () => {
  const inside = row(1000000, { sev: burst, nodes: 9 });
  const outside = { ...row(1000001, { sev: burst, nodes: 9 }), t: NOW - 30 * HOUR };
  const incidents = [incident(1000000), { ...incident(1000001), t: NOW - 30 * HOUR }];
  const c = stressCoupling([day({ stats: [inside, outside], incidents })], MASTER, { range: "24h", now: NOW });
  assert.equal(c.coverage.forensicsRows, 2, "beide Zeilen wurden gelesen");
  assert.equal(c.coverage.samples, 1, "nur die Zeile im Fenster ist ein Sample");
  assert.equal(c.coverage.deviatingLedgers, 1, "der Vorfall ausserhalb der Spanne ist nicht dabei");
  assert.equal(c.window.hours, 24);
});

test("Auch ein Typ-Ausbruch ist eine Signatur: dieselbe Ebene, derselbe Nenner", () => {
  const stats = [
    ...EXPOSED.map((l, i) => row(l, { sev: { "type-burst:Payment": 1 }, nodes: i < 8 ? 10 : 1 })),
    ...CONTROL.map((l, i) => row(l, { nodes: i < 2 ? 9 : 1 })),
  ];
  const c = stressCoupling([day({ stats })], MASTER, { range: "24h", now: NOW });
  const sig = c.signatures.find((s) => s.tag === "type-burst:Payment");
  assert.ok(sig, "der Typ-Ausbruch muss als Signatur erkannt werden");
  assert.equal(sig.ledgersTotal, 12);
  assert.equal(sig.controlTotal, 12);
  assert.equal(sig.massDeviationExposed, 8);
  assert.equal(sig.ownFailures, 0, "ohne eigenen Ausfall keine Knoten-Achse, aber eine Massen-Achse");
  assert.equal(sig.ownFailures, sig.ownFailures);
  assert.equal(sig.ownRateExposed, 0);
  assert.equal(sig.ownRateControl, 0);
  assert.equal(sig.ownLift, 0);
  assert.equal(sig.ownVerdict, "no-coupling-measured",
    "zwei volle Nenner und null Ausfaelle auf beiden Seiten ist eine Messung, keine Duennheit");
});

test("Die betroffenen Knoten je Massen-Ledger stehen beim Namen da, nicht nur als Zahl", () => {
  const stats = [row(1000000, { sev: burst, nodes: 3 }), row(1000001, { nodes: 1 })];
  const incidents = [
    incident(1000000, MASTER, "missed"),
    incident(1000000, "nBPeerOne", "missed"),
    incident(1000000, "nCPeerTwo", "no-quorum"),
    incident(1000001, MASTER, "missed"),
  ];
  const c = stressCoupling([day({ stats, incidents })], MASTER,
    { range: "24h", now: NOW, opts: { simultaneityNodes: 3, peakMasters: 2 } });
  const peak = c.simultaneity.peaks[0];
  assert.equal(peak.ledgerIndex, 1000000);
  assert.equal(peak.deviatingNodes, 3);
  assert.equal(peak.mastersTotal, 3, "der volle Nenner: jeder abweichende Knoten dieses Ledgers");
  assert.deepEqual(peak.masters, [MASTER, "nBPeerOne"], "sortiert, gekappt auf peakMasters");
  assert.equal(c.coverage.namedMastersIncompleteRows, 0, "3 gezaehlt und 3 benannt ist keine Luecke");
  assert.ok(!c.gaps.includes("cohort-masters-incomplete"));
  assert.equal(c.simultaneity.peaks[1], undefined, "der Solo-Ledger ist unter der Massen-Schwelle");
});

test("Gezaehlte Knoten ohne Vorfalls-Zeile bleiben eine benannte Luecke", () => {
  const c = stressCoupling(coupledDays(), MASTER, { range: "24h", now: NOW });
  assert.equal(c.simultaneity.peaks[0].deviatingNodes, 10);
  assert.equal(c.simultaneity.peaks[0].mastersTotal, 1,
    "die Fixture fuehrt nur den eigenen Knoten als Vorfall - die uebrigen 9 sind unbenannt");
  // Von Hand: 8 exponierte Massen-Ledger (10 gezaehlt, 1 benannt), 2 Kontroll-Massen-Ledger
  // (9 gezaehlt, 1 benannt), 3 exponierte und 10 Kontroll-Solo-Ledger ganz ohne Vorfall.
  assert.equal(c.coverage.namedMastersIncompleteRows, 8 + 2 + 3 + 10);
  assert.ok(c.gaps.includes("cohort-masters-incomplete"), "Betroffenheit ohne Namen ist offen");
});

test("Das Vokabular ist abgeschlossen: jedes Urteil, jede Achse, jede Luecke ist deklariert", () => {
  const cases = [
    coupledDays(),
    [day({ stats: EXPOSED.map((l) => row(l, { sev: burst, nodes: 1 })), incidents: EXPOSED.slice(0, 8).map((l) => incident(l)) })],
    [day({ stats: [row(1000000)], incidents: [] })],
    [day({ stats: [], incidents: [] })],
  ];
  for (const days of cases) {
    const c = stressCoupling(days, MASTER, { range: "24h", now: NOW });
    assert.ok(COUPLING_VERDICTS.has(c.verdict), "Verdikt " + c.verdict);
    assert.ok(COUPLING_AXES.has(c.verdictAxis), "Achse " + c.verdictAxis);
    assert.ok(COUPLING_AUTHORITIES.has(c.verdictAuthority), "Autoritaet " + c.verdictAuthority);
    for (const g of c.gaps) assert.ok(COUPLING_GAPS.has(g), "Luecke " + g);
    assert.ok(LOAD_TREND_VERDICTS.has(c.loadAxis.trend.verdict), "Dosis-Verdikt " + c.loadAxis.trend.verdict);
    for (const s of c.signatures) {
      assert.ok(COUPLING_VERDICTS.has(s.verdict), "Signatur-Verdikt " + s.verdict);
      assert.ok(COUPLING_VERDICTS.has(s.ownVerdict), "Knoten-Verdikt " + s.ownVerdict);
      assert.ok(COUPLING_AUTHORITIES.has(s.authority), "Signatur-Autoritaet " + s.authority);
      for (const l of s.ledgers) assert.ok(Number.isFinite(l), "Ledger-Index " + l);
      for (const l of s.controlLedgers) assert.ok(Number.isFinite(l), "Kontroll-Ledger " + l);
      for (const t of s.loadBands) assert.ok(typeof t.label === "string" && Number.isFinite(t.ledgers), "Lastband");
    }
    for (const axis of ["node", "mass", "network"]) {
      assert.ok(COUPLING_VERDICTS.has(c.axes[axis]), "Achse " + axis + " = " + c.axes[axis]);
    }
    for (const f of c.findings) {
      assert.ok(COUPLING_AXES.has(f.axis), "Befund-Achse " + f.axis);
      assert.ok(COUPLING_VERDICTS.has(f.strength), "Befund-Staerke " + f.strength);
      assert.ok(COUPLING_STRESS_TAGS.has(f.tag) || f.tag === "signature-share-mass-vs-solo"
        || f.tag.startsWith("type-burst:"), "Befund-Tag " + f.tag);
    }
    for (const p of c.simultaneity.peaks) {
      for (const [type, n] of Object.entries(p.cohortTypes)) {
        assert.ok(COUPLING_COHORT_KEYS.has(type), "Kohorten-Zaehler " + type);
        assert.ok(Number.isFinite(n), "Kohorten-Zaehler " + type);
      }
    }
  }
});

test("Nenner und Zaehler passen zusammen: die Bilanz ist nachrechenbar, nicht plausibel", () => {
  const c = stressCoupling(coupledDays(), MASTER, { range: "24h", now: NOW });
  assert.equal(c.coverage.deviatingLedgersWithRow + c.coverage.deviatingLedgersWithoutRow,
    c.coverage.deviatingLedgers);
  assert.equal(c.coverage.samples, 24);
  assert.equal(c.coverage.cohortRows, 24);
  assert.equal(c.coverage.latencyRows, 0, "fv ist nicht erfasst - und das steht als Luecke da");
  assert.ok(c.gaps.includes("vote-latency-not-recorded"));
  assert.equal(c.simultaneity.massLedgers + c.simultaneity.soloLedgers,
    c.simultaneity.histogram.reduce((a, h) => a + h.ledgers, 0), "jede Kohorten-Breite ist gezaehlt");
  const sig = c.signatures.find((s) => s.tag === "sender-burst");
  assert.equal(Math.round((sig.rateExposed - sig.rateControl) * 100), Math.round(sig.lift * 100));
  assert.equal(Math.round((sig.ownRateExposed - sig.ownRateControl) * 100), Math.round(sig.ownLift * 100));
  assert.equal(c.thresholds.minSample, COUPLING_DEFAULTS.minSample);
  assert.equal(c.thresholds.simultaneityNodes, COUPLING_DEFAULTS.simultaneityNodes);
});

// Die echte Erfassung 2026-10-08 bis 2026-10-16: 437 Forensik-Zeilen, 11802 Abweichungs-Ledger.
// Hier werden keine Zahlen festgeschrieben (der Recorder schreibt weiter), sondern die
// Zusammenhaenge, die im Fixatur-Modell schon gelten - an denselben Funktionen.
const DATA_DIR = path.join(here, "..", "data", "validator-trace");
const dataFiles = fs.existsSync(DATA_DIR) ? fs.readdirSync(DATA_DIR).filter((f) => f.endsWith(".json")) : [];
test("Echte Erfassung: die Kopplung bleibt auch ueber neun Tage kohaerent",
  { skip: dataFiles.length ? false : "keine Trace-Daten" }, () => {
    const days = dataFiles.map((f) => JSON.parse(fs.readFileSync(path.join(DATA_DIR, f), "utf8")));
    const master = "nHBWa56Vr7csoFcCnEPzCCKVvnDQw3L28mATgHYQMGtbEfUjuYyB";
    const c = stressCoupling(days, master, { range: "30d", now: NOW });
    assert.ok(COUPLING_VERDICTS.has(c.verdict));
    assert.ok(COUPLING_AXES.has(c.verdictAxis));
    // Das Verdikt muss zu dem Befund gehoeren, der es getragen hat - sonst ist es ein Fallback.
    if (c.findings.length) {
      assert.equal(c.verdict, c.findings[0].strength);
      assert.equal(c.verdictAxis, c.findings[0].axis);
      assert.match(c.verdictReason, new RegExp("^" + c.findings[0].axis + "-lift-"));
    }
    assert.equal(c.coverage.deviatingLedgersWithRow + c.coverage.deviatingLedgersWithoutRow,
      c.coverage.deviatingLedgers);
    assert.ok(c.coverage.samples <= c.coverage.forensicsRows, "Samples sind eine Teilmenge der Zeilen");
    assert.equal(c.coverage.namedMastersIncompleteRows, 0, "jede gezaehlte Betroffenheit ist benannt");
    const peakNodes = c.simultaneity.peaks.map((p) => p.deviatingNodes);
    assert.deepEqual(peakNodes, [...peakNodes].sort((a, b) => b - a), "Peaks absteigend nach Betroffenheit");
    const rows = new Map();
    for (const d of days) for (const st of d.ledgerStats ?? []) rows.set(st.l, st);
    for (const p of c.simultaneity.peaks) {
      const st = rows.get(p.ledgerIndex);
      assert.ok(st, "Peak-Ledger #" + p.ledgerIndex + " ohne Forensik-Zeile");
      const sum = Object.values(st.c ?? {}).reduce((a, x) => a + (Number.isFinite(x) ? x : 0), 0);
      assert.equal(p.deviatingNodes, sum, "Betroffenheit = Summe der Typ-Zaehler derselben Zeile");
      assert.equal(p.txCount, st.tx, "Last = dieselbe Zahl derselben Zeile");
      assert.equal(p.closureClosed, st.cl === true, "Schliess-Beweis = dasselbe Feld derselben Zeile");
      // Die benannten Knoten muessen dieselbe Menge sein wie die gezaehlten: sonst waere die
      // Retrace-Kante eine Auswahl und keine Vollstaendigkeit.
      assert.equal(p.mastersTotal, p.deviatingNodes,
        "#" + p.ledgerIndex + ": gezaehlte und benannte Knoten sind dieselbe Menge");
      assert.ok(p.masters.length <= COUPLING_DEFAULTS.peakMasters, "benannte Teilkante bleibt im Cap");
      assert.ok(p.masters.every((m) => typeof m === "string" && m.length > 20), "Master-Keys sind benannt");
    }
  });

// Die Dosis-Achse: sechs Baender mit vollem Nenner, die Rate von Hand nachgerechnet.
// Stufe 10-24: 1/100 = 0,01 | 25-49: 4/200 = 0,02 | 50-99: 12/300 = 0,04
// 100-199: 24/400 = 0,06 | 200-399: 45/500 = 0,09 | 400-799: 66/600 = 0,11
const dose = (buckets) => stressCoupling([day({ stats: [], incidents: [], buckets })], MASTER, { range: "24h", now: NOW });
const RISING = [null,
  { l: 100, f: 1, v: { [MASTER]: 0 } }, { l: 200, f: 4, v: { [MASTER]: 1 } },
  { l: 300, f: 12, v: { [MASTER]: 2 } }, { l: 400, f: 24, v: { [MASTER]: 3 } },
  { l: 500, f: 45, v: { [MASTER]: 4 } }, { l: 600, f: 66, v: { [MASTER]: 5 } }];

test("Dosis-Kurve: das Urteil haengt an den zwei Haelften der Achse, nicht an einem Paar", () => {
  const t = dose(RISING).loadAxis.trend;
  assert.equal(t.verdict, "load-dose-rising");
  assert.equal(t.bandsMeasured, 6);
  assert.equal(t.bandsThin, 0);
  // Untere Haelfte (100+200+300 Ledger, 1+4+12 Ausfaelle) gegen obere (400+500+600, 24+45+66).
  assert.equal(t.lowerRate, 17 / 600);
  assert.equal(t.upperRate, 135 / 1500);
  assert.equal(t.halfRatio, (135 / 1500) / (17 / 600));
  assert.equal(t.ledgersMeasured, 2100);
  assert.equal(t.failsMeasured, 152);
  assert.equal(t.rateMeasured, 152 / 2100);
  assert.equal(t.ownMeasured, 15);
  assert.equal(t.ownRateMeasured, 15 / 2100);
  // Fuelf Schritte, alle steigend: die Achse ist hier streng monoton, und das wird gemeldet.
  assert.equal(t.steps, 5);
  assert.equal(t.risingSteps, 5);
  assert.equal(t.fallingSteps, 0);
  assert.equal(t.monotone, true);
  assert.equal(t.lowBand.label, "10-24");
  assert.equal(t.highBand.label, "400-799");
  assert.equal(t.peakBand.label, "400-799");
  assert.equal(t.ratio, (66 / 600) / (1 / 100));
});

test("Duenne Baender zaehlen nicht ins Dosis-Urteil: 3 von 3 Ausfaellen ist keine Rate", () => {
  const t = dose([
    { l: 3, f: 3, v: { [MASTER]: 3 } },   // 100 % Ausfall an einem Nenner von drei
    ...RISING.slice(1),
  ]).loadAxis.trend;
  assert.equal(t.bandsThin, 1);
  assert.equal(t.bandsMeasured, 6);
  // Dasselbe Urteil wie ohne das duenne Band: es traegt die Kurve nicht und verw?ssert sie nicht.
  assert.equal(t.verdict, "load-dose-rising");
  assert.equal(t.lowerRate, 17 / 600);
  assert.equal(t.upperRate, 135 / 1500);
  assert.equal(t.ledgersMeasured, 2100);
  const row = dose([
    { l: 3, f: 3, v: { [MASTER]: 3 } },
    ...RISING.slice(1),
  ]).loadAxis.rows[0];
  assert.equal(row.sample, "thin");
  assert.equal(row.networkRate, 1);
});

test("Ein Rueckgang auf einer Stufe ist keine Luecke: er wird gezaehlt, nicht getilgt", () => {
  // Dieselbe Achse, nur 100-199 faellt knapp unter 200-399 - die echte Kurve vom 2026-10-16.
  const t = dose([null,
    { l: 144, f: 1, v: {} }, { l: 2400, f: 55, v: {} }, { l: 7558, f: 197, v: {} },
    { l: 1295, f: 54, v: {} }, { l: 624, f: 26, v: {} }, { l: 293, f: 20, v: {} },
    { l: 191, f: 16, v: {} }, { l: 62, f: 8, v: {} },
  ]).loadAxis.trend;
  assert.equal(t.steps, 7);
  assert.equal(t.risingSteps, 6);
  assert.equal(t.fallingSteps, 1);
  assert.equal(t.monotone, false);
  assert.equal(t.verdict, "load-dose-rising");
  // Nachgerechnet: untere Haelfte 11397 Ledger / 307 Ausfaelle, obere 1170 / 70.
  assert.equal(t.lowerRate, 307 / 11397);
  assert.equal(t.upperRate, 70 / 1170);
  assert.equal(t.peakBand.label, "1600-3199");
});

test("Flache Achse ist eine Aussage, kein Ausfall der Ebene", () => {
  const flat = [null, ...Array.from({ length: 6 }, () => ({ l: 100, f: 1, v: {} }))];
  const t = dose(flat).loadAxis.trend;
  assert.equal(t.verdict, "load-dose-flat");
  assert.equal(t.lowerRate, 3 / 300);
  assert.equal(t.upperRate, 3 / 300);
  assert.equal(t.halfRatio, 1);
  assert.equal(t.risingSteps, 0);
  assert.equal(t.fallingSteps, 0);
  assert.equal(t.monotone, false);
});

test("Fallende Achse bekommt ihr eigenes Urteil, nicht 'kein Befund'", () => {
  const t = dose([null,
    { l: 600, f: 66, v: {} }, { l: 500, f: 45, v: {} }, { l: 400, f: 24, v: {} },
    { l: 300, f: 12, v: {} }, { l: 200, f: 4, v: {} }, { l: 100, f: 1, v: {} },
  ]).loadAxis.trend;
  assert.equal(t.verdict, "load-dose-falling");
  assert.equal(t.lowerRate, 135 / 1500);
  assert.equal(t.upperRate, 17 / 600);
  assert.equal(t.halfRatio, (17 / 600) / (135 / 1500));
});

test("Ohne Nenner in der unteren Haelfte gibt es kein Richtungsurteil", () => {
  const t = dose([null,
    { l: 100, f: 0, v: {} }, { l: 200, f: 0, v: {} }, { l: 300, f: 0, v: {} },
    { l: 400, f: 20, v: {} }, { l: 500, f: 30, v: {} }, { l: 600, f: 40, v: {} },
  ]).loadAxis.trend;
  assert.equal(t.verdict, "not-comparable");
  assert.equal(t.lowerRate, 0);
  assert.equal(t.halfRatio, null);
  assert.equal(t.ratio, null);
});

test("Zu wenige Baender mit vollem Nenner: kein Urteil, aber die Bilanz bleibt stehen", () => {
  const t = dose([null, { l: 100, f: 1, v: {} }, { l: 200, f: 4, v: {} }, { l: 300, f: 12, v: {} }]).loadAxis.trend;
  assert.equal(t.verdict, "insufficient-sample");
  assert.equal(t.bandsMeasured, 3);
  assert.equal(t.steps, 2);
  assert.equal(t.lowBand, null);
  assert.equal(t.peakBand, null);
  // Die Bilanz der drei Baender ist trotzdem nachlesbar - offen ist das Urteil, nicht die Zahl.
  assert.equal(t.ledgersMeasured, 600);
  assert.equal(t.failsMeasured, 17);
  assert.equal(t.rateMeasured, 17 / 600);
});
