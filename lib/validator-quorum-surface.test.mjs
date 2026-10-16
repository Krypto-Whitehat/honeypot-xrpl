// lib/validator-quorum-surface.test.mjs - die Arithmetik der Risikoflaeche, nachgerechnet.
//
// Diese Engine sagt einem Betreiber, an welcher Achse sein Ausfall haengt: Quorum-Reserve,
// Ledger-Last, beide zusammen, oder der eigene Knoten. Jede dieser Aussagen haengt an einer
// Rate, und jede Rate hat hier einen Nenner, der mitgezaehlt wird. Die Erwartungswerte sind
// vorweg von Hand durchgerechnet, nicht aus der Engine abgeschrieben.
import test from "node:test";
import assert from "node:assert/strict";
import {
  SURFACE_AXES, SURFACE_DEFAULTS, SURFACE_GAPS, SURFACE_REASONS, SURFACE_VERDICTS, quorumSurface,
} from "./validator-quorum-surface.mjs";
import { normalizeDay } from "./validator-trace-store.mjs";
import {
  LOAD_BUCKETS, LOAD_BUCKET_COUNT, MARGIN_BUCKETS, MARGIN_BUCKET_COUNT,
  addLedgerRiskSample, addLoadSample, addQuorumSample, addRiskCell,
  loadBucket, loadBucketLabel, marginBucket, marginBucketLabel, riskCellIndex,
} from "./validator-trace.mjs";

const NOW = 1792000000000; // 2026-10-14T23:46:40Z
const DAY_MS = 86400000;
const MASTER = "nHTEST";
const OTHER = "nHOTHER";

// Ein Randwert je Bandbreite, so wie der Recorder ihn verbucht:
// margin -1,0,1,2,3,5,8 -> Band 0..6; tx 5,15,30,60,120,250,500,1000,2000,4000 -> Stufe 0..9.
const MARGIN_EDGE = [-1, 0, 1, 2, 3, 5, 8];
const LOAD_EDGE = [5, 15, 30, 60, 120, 250, 500, 1000, 2000, 4000];

const day = (over = {}) => ({ date: "2026-10-14", ledgers: 0, quorumFail: 0, incidents: [], ledgerStats: [], hourly: {}, ...over });
const run = (days, opts = {}) => quorumSurface(days, MASTER, { range: "7d", now: NOW, ...opts });

function quorumBand(d, idx, ledgers, mineFails, netFails = 0) {
  for (let k = 0; k < ledgers; k += 1) {
    const failed = k < mineFails ? [MASTER] : (k < mineFails + netFails ? [OTHER] : []);
    addQuorumSample(d, MARGIN_EDGE[idx], failed);
  }
}
function loadBand(d, idx, ledgers, mineFails, netFails = 0) {
  for (let k = 0; k < ledgers; k += 1) {
    const failed = k < mineFails ? [MASTER] : (k < mineFails + netFails ? [OTHER] : []);
    addLoadSample(d, LOAD_EDGE[idx], failed);
  }
}
// Ledgers, die auf BEIDEN Achsen und in ihrer gemeinsamen Zelle stehen - derselbe Aufruf wie im
// Recorder. Nur so stammt die Interaktion aus derselben Ledger-Menge wie ihre zwei Randraten.
function riskLedgers(d, loadIdx, marginIdx, ledgers, mineFails, netFails = 0) {
  for (let k = 0; k < ledgers; k += 1) {
    const failed = k < mineFails ? [MASTER] : (k < mineFails + netFails ? [OTHER] : []);
    addLedgerRiskSample(d, { txCount: LOAD_EDGE[loadIdx], margin: MARGIN_EDGE[marginIdx], failedMasters: failed });
  }
}
const band = (r, axis, idx) => r.bands.find((b) => b.axis === axis && b.idx === idx);

test("Quorum-Bandbreiten: jeder Rand faellt in die richtige Bandbreite", () => {
  assert.deepEqual(MARGIN_BUCKETS, [0, 1, 2, 3, 5, 8, Infinity]);
  assert.equal(MARGIN_BUCKET_COUNT, 7);
  // Die Grenze ist "m < hi", also liegt der Wert selbst in der naechsten Bandbreite.
  assert.equal(marginBucket(-1), 0);
  assert.equal(marginBucket(0), 1);
  assert.equal(marginBucket(1), 2);
  assert.equal(marginBucket(2), 3);
  assert.equal(marginBucket(3), 4);
  assert.equal(marginBucket(4), 4); // 3-4 ist eine Bandbreite
  assert.equal(marginBucket(5), 5);
  assert.equal(marginBucket(7), 5);
  assert.equal(marginBucket(8), 6);
  assert.equal(marginBucket(1000), 6);
  assert.deepEqual([0, 1, 2, 3, 4, 5, 6].map(marginBucketLabel), ["< 0", "0-0", "1-1", "2-2", "3-4", "5-7", ">= 8"]);
});

test("Quorum-null bleibt null: 'nicht gemessen' ist nicht 'Quorum exakt erreicht'", () => {
  assert.equal(marginBucket(null), null);
  assert.equal(marginBucket(undefined), null);
  assert.equal(marginBucket(NaN), null);
  assert.equal(marginBucket("7"), 5); // Ziffern aus JSON sind Messungen, keine Nichtmessungen
});

test("Laststufen: 500 Tx liegt in Stufe 6 (400-799), nicht in Stufe 5", () => {
  assert.equal(LOAD_BUCKET_COUNT, 10);
  assert.equal(loadBucket(0), 0);
  assert.equal(loadBucket(9), 0);
  assert.equal(loadBucket(10), 1);
  assert.equal(loadBucket(25), 2);
  assert.equal(loadBucket(50), 3);
  assert.equal(loadBucket(100), 4);
  assert.equal(loadBucket(200), 5);
  assert.equal(loadBucket(400), 6); // 400 ist der Unter_rand von 400-799
  assert.equal(loadBucket(500), 6);
  assert.equal(loadBucket(800), 7);
  assert.equal(loadBucket(3200), 9);
  assert.equal(loadBucketLabel(0), "0-9");
  assert.equal(loadBucketLabel(5), "200-399");
  assert.equal(loadBucketLabel(6), "400-799");
  assert.equal(loadBucketLabel(9), ">= 3200");
});

test("Gemeinsame Zelle: der Index ist dieselbe Rechnung wie die Aufloesung der Engine", () => {
  assert.equal(riskCellIndex(5, -1), 0); // Stufe 0 * 7 + Band 0
  assert.equal(riskCellIndex(500, 1), 6 * 7 + 2); // 44
  assert.equal(riskCellIndex(4000, 8), 9 * 7 + 6); // 69
  assert.equal(riskCellIndex(500, null), null);
  const d = day();
  riskLedgers(d, 6, 1, 3, 1);
  const r = run([d]);
  const cell = r.interactions.find((x) => x.loadIdx === 6 && x.marginIdx === 1);
  assert.ok(cell, "die Zelle (Last 400-799, Margin 0-0) wird aus dem Index zurueckgefunden");
});

test("Der Nenner wird mitgezaehlt: Bandbreite ohne Ausfall ist eine Rate, nicht eine Luecke", () => {
  const d = day();
  quorumBand(d, 0, 40, 12, 8); // 40 Ledger, 12 davon mit meinem Ausfall
  quorumBand(d, 4, 160, 3, 10); // 160 Ledger, 3 mit meinem Ausfall
  const r = run([d]);
  assert.equal(r.coverage.ledgersQuorum, 200);
  assert.equal(r.coverage.ownFailLedgersByQuorum, 15);
  // 12 von 15 eigenen Ausfaellen liegen in knappen Bandbreiten, obwohl dort nur 20 % aller Ledger stehen.
  const b0 = band(r, "quorum", 0);
  assert.equal(b0.shareOfLedgers, 0.2); // 40 / 200
  assert.equal(b0.shareOfMine, 0.8); // 12 / 15
  assert.equal(b0.concentration, 4); // 0,8 / 0,2 -> viermal dichter als der Ledger-Anteil
  assert.equal(b0.reliable, true);
  assert.equal(b0.hot, true);
  const b4 = band(r, "quorum", 4);
  assert.equal(b4.shareOfLedgers, 0.8);
  assert.equal(b4.shareOfMine, 0.2);
  assert.equal(b4.concentration, 0.25);
  assert.equal(b4.hot, false);
  assert.deepEqual(r.hotspots.map((b) => [b.axis, b.idx]), [["quorum", 0]]);
  // Haeufigkeit ist nicht Dichte: die Netzrate je Band ist eine eigene Zahl.
  assert.equal(b0.networkRate, 0.5); // 20 von 40
  assert.equal(b0.mineRate, 0.3); // 12 von 40
});

test("Konzentration ist eine Invariante: die Anteile einer Achse summieren sich auf eins", () => {
  const d = day();
  quorumBand(d, 0, 20, 4, 2);
  quorumBand(d, 3, 20, 6, 2);
  quorumBand(d, 6, 20, 2, 2);
  loadBand(d, 1, 25, 5, 3);
  loadBand(d, 7, 25, 9, 4);
  const r = run([d]);
  const q = r.bands.filter((b) => b.axis === "quorum");
  const l = r.bands.filter((b) => b.axis === "load");
  // Die Invariante gilt fuer die ungerundeten Anteile. Je Band wird auf 4 Nachkommastellen
  // gerundet, und 7 Baender koennen dabei zusammen bis 3,5 * 10^-4 verlieren - die Toleranz ist
  // die Rundung, nicht eine Ausrede.
  const sum = (xs) => xs.reduce((a, b) => a + b, 0);
  const near = (x) => Math.abs(x - 1) <= 1e-3;
  assert.ok(near(sum(q.map((b) => b.shareOfMine))), "Anteil der eigenen Ausfaelle: " + sum(q.map((b) => b.shareOfMine)));
  assert.ok(near(sum(q.map((b) => b.shareOfLedgers))), "Anteil der Ledger: " + sum(q.map((b) => b.shareOfLedgers)));
  assert.ok(near(sum(l.map((b) => b.shareOfMine))), "Anteil der eigenen Ausfaelle (Last): " + sum(l.map((b) => b.shareOfMine)));
  assert.ok(near(sum(l.map((b) => b.shareOfLedgers))), "Anteil der Ledger (Last): " + sum(l.map((b) => b.shareOfLedgers)));
  assert.equal(r.bands.length, MARGIN_BUCKET_COUNT + LOAD_BUCKET_COUNT);
  assert.deepEqual(SURFACE_AXES, ["quorum", "load"]);
});

test("Duennstichproben werden gesperrt, nicht beurteilt", () => {
  const d = day();
  quorumBand(d, 0, 39, 12, 8); // ein Ledger unter der Mindestbreite
  quorumBand(d, 1, 40, 2, 8); // ein eigener Ausfall unter dem Mindestwert
  const r = run([d]);
  assert.equal(band(r, "quorum", 0).reliable, false);
  assert.equal(band(r, "quorum", 0).hot, false);
  assert.equal(band(r, "quorum", 0).note, "thin-sample");
  assert.equal(band(r, "quorum", 1).reliable, false);
  assert.equal(band(r, "quorum", 1).note, "thin-sample");
  assert.equal(r.hotspots.length, 0);
});

test("Interaktion Last x Quorum: beobachtet gegen die Rate, die Unabhaengigkeit vorhersagt", () => {
  const d = day();
  riskLedgers(d, 6, 1, 40, 20, 0); // Last 400-799, Margin 0-0: 40 Ledger, 20 eigene Ausfaelle
  riskLedgers(d, 6, 6, 60, 3, 0); // dieselbe Last, Margin >= 8: 60 Ledger, 3 eigene Ausfaelle
  riskLedgers(d, 0, 1, 40, 4, 0); // Last 0-9, Margin 0-0: 40 Ledger, 4 eigene Ausfaelle
  const r = run([d]);
  assert.equal(r.coverage.ledgersQuorum, 140);
  assert.equal(r.coverage.ledgersLoad, 140);
  assert.equal(r.coverage.cellsRecorded, 3);

  const hot = r.interactions.find((x) => x.loadIdx === 6 && x.marginIdx === 1);
  // Randraten: Laststufe 6 faellt in 23 von 100 Ledgers (0,23), Margin-Band 1 in 24 von 80 (0,3).
  assert.equal(band(r, "load", 6).networkRate, 0.23);
  assert.equal(band(r, "quorum", 1).networkRate, 0.3);
  // Unabhaengigkeit sagt 0,23 * 0,3 = 0,069 voraus. Beobachtet sind 20 von 40 = 0,5.
  assert.equal(hot.ledgers, 40);
  assert.equal(hot.failLedgers, 20);
  assert.equal(hot.rate, 0.5);
  assert.equal(hot.expected, 0.069);
  assert.equal(hot.interaction, 7.2464); // 0,5 / 0,069
  assert.equal(hot.reliable, true);
  assert.equal(hot.note, null);

  const calm = r.interactions.find((x) => x.loadIdx === 6 && x.marginIdx === 6);
  // 3 von 60 = 0,05 beobachtet gegen 0,23 * 0,05 = 0,0115 erwartet.
  assert.equal(calm.rate, 0.05);
  assert.equal(calm.expected, 0.0115);
  assert.equal(calm.interaction, 4.3478);
  const low = r.interactions.find((x) => x.loadIdx === 0 && x.marginIdx === 1);
  // 4 von 40 = 0,1 gegen 0,1 * 0,3 = 0,03.
  assert.equal(low.rate, 0.1);
  assert.equal(low.expected, 0.03);
  assert.equal(low.interaction, 3.3333);

  // Sortierung: zuerst zuverlaessig, dann staerkste Abweichung.
  assert.deepEqual(r.interactions.map((x) => [x.loadIdx, x.marginIdx]), [[6, 1], [6, 6], [0, 1]]);
});

test("Interaktion mit zu duenner Stichprobe wird nicht als Befund verkauft", () => {
  const d = day();
  riskLedgers(d, 6, 1, 6, 4, 0); // 6 Ledger, unter der Zellgrenze von 12
  const r = run([d]);
  const c = r.interactions[0];
  assert.equal(c.ledgers, 6);
  assert.equal(c.reliable, false);
  assert.equal(c.note, "interaction-sample");
  assert.ok(r.gaps.includes("interaction-sample"));
});

test("Urteil 'quorum-bound': meine Ausfaelle haengen an der Quorum-Reserve", () => {
  const d = day();
  quorumBand(d, 0, 20, 12, 0);
  quorumBand(d, 1, 20, 8, 0);
  quorumBand(d, 2, 20, 5, 0);
  quorumBand(d, 3, 20, 0, 4);
  quorumBand(d, 4, 20, 2, 0);
  quorumBand(d, 5, 20, 0, 0);
  quorumBand(d, 6, 20, 0, 0);
  const r = run([d]);
  assert.equal(r.coverage.ledgersQuorum, 140);
  assert.equal(r.coverage.ownFailLedgersByQuorum, 27);
  assert.equal(r.shares.quorumShare, 0.9259); // 25 / 27
  assert.equal(r.shares.comfortableShare, 0.0741); // 2 / 27
  assert.equal(r.verdict, "quorum-bound");
  assert.equal(r.verdictReason, "dominant-quorum");
  assert.equal(r.verdictAuthority, "measured");
});

test("Urteil 'load-bound': meine Ausfaelle haengen an der Ledger-Last", () => {
  const d = day();
  quorumBand(d, 4, 30, 2, 6);
  quorumBand(d, 6, 30, 2, 6);
  loadBand(d, 6, 30, 5, 10);
  loadBand(d, 7, 30, 4, 8);
  loadBand(d, 0, 10, 0);
  loadBand(d, 1, 10, 0);
  const r = run([d]);
  assert.equal(r.shares.comfortableShare, 1); // Quorum hatte Reserve
  assert.equal(r.shares.normalLoadShare, 0);
  assert.equal(r.shares.loadShare, 1); // 9 / 9 in Laststufen ab 400 Tx
  assert.equal(r.verdict, "load-bound");
  assert.equal(r.verdictReason, "dominant-load");
});

test("Urteil 'both-bound': beide Achse erklaeren je einen erheblichen Teil", () => {
  // Je Gruppe 40 Ledgers: die Schwelle, die das Urteil fuer eine Gruppe verlangt.
  const d = day();
  quorumBand(d, 0, 40, 6, 4);
  quorumBand(d, 4, 40, 6, 4);
  loadBand(d, 6, 40, 6, 4);
  loadBand(d, 1, 40, 6, 4);
  const r = run([d]);
  assert.equal(r.shares.quorumShare, 0.5);
  assert.equal(r.shares.loadShare, 0.5);
  assert.equal(r.shares.comfortableShare, 0.5);
  assert.equal(r.shares.normalLoadShare, 0.5);
  assert.equal(r.verdict, "both-bound");
  assert.equal(r.verdictReason, "dominant-both");
});

test("Urteil 'node-bound': knappes Quorum und niedrige Last zusammen sind der eigene Knoten", () => {
  const d = day();
  quorumBand(d, 4, 20, 3, 2);
  quorumBand(d, 5, 20, 4, 2);
  quorumBand(d, 6, 20, 5, 2);
  quorumBand(d, 0, 10, 0, 0);
  loadBand(d, 3, 20, 4, 1);
  loadBand(d, 4, 20, 5, 1);
  loadBand(d, 5, 20, 3, 1);
  const r = run([d]);
  assert.equal(r.shares.comfortableShare, 1); // 12 / 12 bei Margin >= 3
  assert.equal(r.shares.quorumShare, 0);
  assert.equal(r.shares.normalLoadShare, 1); // 12 / 12 bei Last < 400
  assert.equal(r.shares.loadShare, 0);
  assert.equal(r.verdict, "node-bound");
  assert.equal(r.verdictReason, "dominant-comfort");
});

test("Urteil 'mixed': keine Achse erklaert genug - das Werkzeug entlastet nicht", () => {
  const d = day();
  quorumBand(d, 0, 20, 4, 2);
  quorumBand(d, 3, 20, 6, 2);
  quorumBand(d, 6, 20, 2, 2);
  loadBand(d, 6, 20, 4, 1);
  loadBand(d, 3, 20, 8, 1);
  const r = run([d]);
  // 4/12 = 0,3333 liegt knapp unter der Zweitgrenze von 0,35: kein Urteil, das jemand umbaut.
  assert.equal(r.shares.quorumShare, 0.3333);
  assert.equal(r.shares.loadShare, 0.3333);
  assert.equal(r.verdict, "mixed");
  assert.equal(r.verdictReason, "no-dominant-band");
  assert.equal(r.verdictAuthority, "measured");
});

test("Duennster Bestand wird nicht als Urteil ausgegeben", () => {
  const d = day();
  quorumBand(d, 0, 10, 2, 1);
  const r = run([d]);
  assert.equal(r.verdict, "unknown");
  assert.equal(r.verdictReason, "thin-sample");
  assert.equal(r.verdictAuthority, "insufficient");
  assert.ok(r.gaps.includes("thin-sample"));
  assert.ok(!r.gaps.includes("quorum-axis-not-recorded"));
});

test("Ohne eigenen Ausfall gibt es kein Urteil in beide Richtungen", () => {
  const d = day();
  quorumBand(d, 4, 50, 0, 7);
  const r = run([d]);
  assert.equal(r.coverage.ownFailLedgersByQuorum, 0);
  assert.equal(r.verdict, "unknown");
  assert.equal(r.verdictReason, "no-own-failures");
  assert.ok(!r.gaps.includes("thin-sample"));
  assert.ok(!r.gaps.includes("quorum-axis-not-recorded"));
});

test("Alter Bestand ohne Quorum-Achse ist eine Messluecke, nicht 'Quorum war komfortabel'", () => {
  const d = day();
  loadBand(d, 6, 30, 5, 10);
  const r = run([d]);
  assert.equal(r.coverage.daysWithQuorumAxis, 0);
  assert.equal(r.coverage.quorumRecorded, false);
  assert.equal(r.coverage.ledgersQuorum, 0);
  assert.equal(r.coverage.ownFailLedgersByLoad, 5);
  assert.equal(r.verdict, "unknown");
  assert.equal(r.verdictReason, "quorum-axis-not-recorded");
  assert.ok(r.gaps.includes("quorum-axis-not-recorded"));
  // Die Last-Achse bleibt lesbar, auch wenn die Quorum-Achse fehlt.
  assert.equal(band(r, "load", 6).mineFails, 5);
});

test("Nicht verbuchbare Quorum-Werte werden gezaehlt und nicht in Band 0 geschoben", () => {
  const d = day();
  riskLedgers(d, 6, 5, 1, 1, 0); // eine Messung mit Margin 5
  addLedgerRiskSample(d, { txCount: 500, margin: null, failedMasters: [MASTER] }); // eine Nichtmessung
  const r = run([d]);
  assert.equal(r.coverage.quorumMissing, 1);
  assert.equal(r.coverage.ledgersQuorum, 1); // die Nichtmessung zaehlt nicht als Ledger mit Margin
  assert.equal(band(r, "quorum", 5).ledgers, 1);
  assert.equal(band(r, "quorum", 1).ledgers, 0); // nicht in "Margin 0-0" gelandet
  assert.ok(r.gaps.includes("quorum-margin-missing-ledgers"));
});

test("Der Tag liegt im Fenster: ein Tag vor dem Fenster kann die Rate nicht verschieben", () => {
  const out = day({ date: "2026-10-01" }); // endet vor dem 7d-Fenster
  const inn = day({ date: "2026-10-14" });
  quorumBand(out, 0, 500, 500, 0);
  quorumBand(inn, 4, 60, 4, 0);
  const r = run([out, inn]);
  assert.equal(r.coverage.days, 1);
  assert.equal(r.coverage.ledgersQuorum, 60);
  assert.equal(r.coverage.ownFailLedgersByQuorum, 4);
});

test("Jedes erzeugbare Urteil, jeder Grund und jede Luecke ist in den exportierten Mengen", () => {
  const fixtures = [
    day(), // leer
  ];
  const seenReasons = new Set();
  const seenVerdicts = new Set();
  const seenGaps = new Set();
  const cases = [
    () => { const d = day(); quorumBand(d, 0, 20, 12); quorumBand(d, 1, 20, 8); quorumBand(d, 2, 20, 5); quorumBand(d, 4, 20, 2); return d; },
    () => { const d = day(); quorumBand(d, 4, 30, 2); quorumBand(d, 6, 30, 2); loadBand(d, 6, 40, 5); return d; },
    () => { const d = day(); quorumBand(d, 0, 40, 6); quorumBand(d, 4, 40, 6); loadBand(d, 6, 40, 6); loadBand(d, 1, 40, 6); return d; },
    () => { const d = day(); quorumBand(d, 4, 20, 3); quorumBand(d, 5, 20, 4); quorumBand(d, 6, 20, 5); loadBand(d, 3, 20, 4); loadBand(d, 4, 20, 5); loadBand(d, 5, 20, 3); return d; },
    () => { const d = day(); quorumBand(d, 0, 20, 4); quorumBand(d, 3, 20, 6); quorumBand(d, 6, 20, 2); loadBand(d, 6, 20, 4); loadBand(d, 3, 20, 8); return d; },
    () => { const d = day(); quorumBand(d, 0, 10, 2); return d; },
    () => { const d = day(); quorumBand(d, 4, 50, 0, 7); return d; },
    () => { const d = day(); loadBand(d, 6, 30, 5); return d; },
  ];
  for (const make of cases) {
    const r = run([make()]);
    seenReasons.add(r.verdictReason);
    seenVerdicts.add(r.verdict);
    for (const g of r.gaps) seenGaps.add(g);
    for (const b of r.bands) if (b.note !== null) seenGaps.add(b.note);
    for (const c of r.interactions) if (c.note !== null) seenGaps.add(c.note);
    assert.ok(SURFACE_REASONS.includes(r.verdictReason), "verdictReason " + r.verdictReason);
    assert.ok(SURFACE_VERDICTS.includes(r.verdict), "verdict " + r.verdict);
    for (const g of r.gaps) assert.ok(SURFACE_GAPS.includes(g), "gap " + g);
    assert.equal(r.thresholds.minBandLedgers, SURFACE_DEFAULTS.minBandLedgers);
    assert.equal(r.overallMineRate === null || Number.isFinite(r.overallMineRate), true);
  }
  // Die sechs Urteile sind wirklich erreichbar, nicht nur deklariert.
  assert.deepEqual(SURFACE_VERDICTS.slice().sort(), [...seenVerdicts].sort());
  assert.equal(fixtures.length, 1);
});

test("Die Schwellen sind dieselben, die das Urteil benutzt", () => {
  const d = day();
  quorumBand(d, 0, 20, 12);
  quorumBand(d, 1, 20, 8);
  quorumBand(d, 2, 20, 5);
  quorumBand(d, 4, 20, 2);
  const base = run([d]);
  assert.equal(base.verdict, "quorum-bound");
  // Die Schwelle ist ein Parameter, keine versteckte Konstante: eine hohere Grenze kippt das Urteil.
  const strict = run([d], { dominantShare: 0.95 });
  assert.equal(strict.verdict, "mixed");
  assert.equal(strict.verdictReason, "no-dominant-band");
  assert.equal(strict.thresholds.dominantShare, 0.95);
});

test("Gefuellte Achse ueberholt einen ueberlieferten 'nicht erfasst'-Marker", () => {
  // Der gemessene Fall vom 2026-10-16: ein Tag aus der Zeit vor der Quorum-Achse traegt
  // quorumRecorded: false in der Datei. Der Recorder fuellt die Achse am selben Tag weiter.
  // Bliebe das false stehen, zeigte die Risikoflaeche 118 gemessene Ledger als Messluecke.
  const filled = Array.from({ length: MARGIN_BUCKET_COUNT }, () => ({ l: 0, f: 0, v: {} }));
  filled[5] = { l: 118, f: 3, v: { [MASTER]: 1 } };
  const stale = normalizeDay({ date: "2026-10-14", incidents: [], quorumRecorded: false, quorumBuckets: filled });
  const r = run([stale]);
  assert.equal(r.coverage.quorumRecorded, true);
  assert.equal(r.coverage.ledgersQuorum, 118);
  assert.equal(r.verdictReason !== "quorum-axis-not-recorded", true, "eine gefuellte Achse ist keine Luecke");
  assert.ok(!r.gaps.includes("quorum-axis-not-recorded"));
  // Umgekehrt darf eine leere Achse nicht zur Entlastung werden: ohne Buchung bleibt die Luecke stehen.
  const empty = normalizeDay({ date: "2026-10-14", incidents: [], quorumRecorded: false });
  const r2 = run([empty]);
  assert.equal(r2.coverage.quorumRecorded, false);
  assert.ok(r2.gaps.includes("quorum-axis-not-recorded"));
});

test("Leerbestand liefert ein vollstaendiges Objekt mit Luecke, kein halbes Ergebnis", () => {
  const r = run([day()]);
  for (const k of ["master", "range", "thresholds", "verdict", "verdictReason", "verdictAuthority", "shares", "overallMineRate", "bands", "hotspots", "interactions", "coverage", "gaps"]) {
    assert.ok(k in r, "Schluessel " + k);
  }
  assert.equal(r.verdict, "unknown");
  assert.equal(r.bands.length, MARGIN_BUCKET_COUNT + LOAD_BUCKET_COUNT);
  assert.equal(r.hotspots.length, 0);
  assert.equal(r.interactions.length, 0);
  assert.ok(r.gaps.includes("quorum-axis-not-recorded"));
});

test("Teilweise abgedeckte Achse: gemessene Ledger bleiben ein Urteil, die Luecke wird benannt", () => {
  // Der gemessene Fall aus dem 7d-Fenster: ein Tag traegt die Quorum-Achse, die anderen nicht.
  // Frueher kippte ein einziger Achsen-Tag das gesamte Urteil auf "nicht erfasst", obwohl 197
  // Ledger auf der Achse standen. Die Rate darf bleiben - die unvollstaendige Abdeckung muss als
  // eigene Luecke dastehen.
  const withAxis = day();
  quorumBand(withAxis, 5, 60, 4, 6);
  loadBand(withAxis, 6, 60, 4);
  const withoutAxis = day({ date: "2026-10-13" });
  loadBand(withoutAxis, 6, 30, 0);
  const r = run([withoutAxis, withAxis]);
  assert.equal(r.coverage.days, 2);
  assert.equal(r.coverage.daysWithQuorumAxis, 1);
  assert.equal(r.coverage.quorumRecorded, true);
  assert.equal(r.coverage.ledgersQuorum, 60);
  assert.equal(r.verdict, "load-bound");
  assert.equal(r.verdictReason, "dominant-load");
  assert.equal(r.verdictAuthority, "measured");
  assert.ok(r.gaps.includes("quorum-axis-partial"), "Abdeckungsluecke fehlt");
  assert.ok(!r.gaps.includes("quorum-axis-not-recorded"), "Achse ist erfasst, also keine Achsenluecke");
});

test("Gar keine Achse im Fenster bleibt eine Achsenluecke, auch mit Last-Achse", () => {
  const a = day({ date: "2026-10-13" });
  const b = day({ date: "2026-10-14" });
  loadBand(a, 6, 30, 4);
  loadBand(b, 6, 30, 4);
  const r = run([a, b]);
  assert.equal(r.coverage.daysWithQuorumAxis, 0);
  assert.equal(r.coverage.quorumRecorded, false);
  assert.equal(r.coverage.ledgersQuorum, 0);
  assert.equal(r.verdict, "unknown");
  assert.equal(r.verdictReason, "quorum-axis-not-recorded");
  assert.ok(r.gaps.includes("quorum-axis-not-recorded"));
  assert.ok(!r.gaps.includes("quorum-axis-partial"), "ohne Achse ist teilweise Abdeckung nicht die Aussage");
});

/* Der gemessene Widerspruch vom 2026-10-16: shadow.haas steht mit 3 eigenen Ausfaellen in
 * der Bandbreite "< 0" und der Achse insgesamt auf 251 Ledgers. Die Share ist 100 Prozent,
 * die tragende Gruppe aber 3 Ledgers. Frueher sagte das Panel quorum-bound und markierte
 * dieselbe Zeile als thin sample. Heute: die duenne Gruppe wird zur Luecke, nicht zum Urteil
 * - und es wird nicht zur naechstschwaecheren Aussage durchgewinkt. */
test("Eine dominante Share auf einer duennen Gruppe ist kein Urteil, sondern eine Luecke", () => {
  const d = day();
  quorumBand(d, 0, 30, 12);
  quorumBand(d, 4, 200, 1);
  const r = run([d]);
  assert.equal(r.coverage.ledgersQuorum, 230);
  assert.equal(r.coverage.ownFailLedgersByQuorum, 13);
  assert.equal(r.shares.quorumShare, 0.9231);
  assert.equal(r.coverage.bandGroups.quorumThin.ledgers, 30);
  assert.equal(r.coverage.bandGroups.quorumThin.measurable, false);
  assert.equal(r.coverage.bandGroups.quorumComfort.ledgers, 200);
  assert.equal(r.coverage.bandGroups.quorumComfort.measurable, false, "200 Ledger, aber nur 1 eigener Ausfall");
  assert.equal(r.verdict, "unknown");
  assert.equal(r.verdictReason, "thin-sample");
  assert.equal(r.verdictAuthority, "insufficient");
  assert.ok(r.gaps.includes("thin-sample"), "die duenne Gruppe muss als Luecke dastehen");
  // Die Achsen-Gesamtzahl ist nicht die Beweisgrundlage der Aussage.
  assert.ok(r.coverage.ledgersQuorum >= r.thresholds.minBandLedgers, "die Achse ist gefuellt, die Gruppe nicht");
});

test("Duenne Gruppe blockiert, die messbar gestuetzte Aussage bleibt erhalten", () => {
  // Quorum-Achse duenn, Last-Achse messbar: das Last-Urteil darf stehen, die Quorum-Share
  // muss trotzdem als Luecke genannt werden.
  const d = day();
  quorumBand(d, 0, 30, 12);
  quorumBand(d, 4, 100, 1);
  loadBand(d, 6, 80, 20);
  const r = run([d]);
  assert.equal(r.coverage.ledgersQuorum, 130);
  assert.equal(r.shares.quorumShare, 0.9231);
  assert.equal(r.shares.loadShare, 1);
  assert.equal(r.coverage.bandGroups.quorumThin.measurable, false);
  assert.equal(r.coverage.bandGroups.loadHigh.measurable, true);
  assert.equal(r.verdict, "load-bound");
  assert.equal(r.verdictReason, "dominant-load");
  assert.ok(r.gaps.includes("thin-sample"), "die duenne Quorum-Gruppe wird benannt, obwohl ein Urteil steht");
});
