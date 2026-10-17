// lib/tx-correlation.test.mjs — Korrelation: Transaktionsform eines Ledgers x Validator-Ausfall.
//
// Der eigentliche Detektor ist nicht die Identifikation (missed / partial / no-quorum /
// wrong-hash) — die leisten HoneyCluster und XRPScan auch. Der Detektor ist die Kette:
//
//   Transaktions-FORM eines Ledgers (tx-forensics)
//     -> Ledger-ZAEHLER mit und ohne diese Form (riskProfile aus anomaly / anomalyFail)
//     -> Ausfallwahrscheinlichkeit mit Form gegen ohne Form (signatureBoard)
//     -> der Beleg an genau diesem Ledger (retraceIncident: strength measured + evidence)
//     -> der naechste Pruefschritt des Betreibers (guidance attack-*)
//     -> das Intervall im 3D-Profil (profileCells: signatures je Intervall)
//
// Jede Stufe fuer sich kann "funktioniert" aussehen, ohne dass der Zusammenhang daraus
// hervorgeht. Diese Tests halten die Kette, nicht die Einzelteile.
import test from "node:test";
import assert from "node:assert/strict";
import { PROFILE_BUCKETS, profileCells } from "./validator-trace-query.mjs";
import {
  attackSignals, buildLedgerIndex, isSignatureTag, retraceForValidator, retraceIncident,
  riskProfile, signatureBoard,
} from "./validator-retrace.mjs";
import { addTx, classifyShape, emptyShape, finishShape, normalizeTx } from "./tx-forensics.mjs";

const NOW = Date.UTC(2026, 9, 8, 12, 0, 0);
const HOUR = 3600000;
const A = "nAAA";
const B = "nBBB";

const dayOf = (over = {}) => ({
  date: "2026-10-08", ledgers: 0, quorumFail: 0, shapeSeen: 0, shapeMissing: 0,
  hourly: {}, validators: {}, incidents: [], ledgerStats: [], anomaly: {}, anomalyFail: {},
  ...over,
});

// Forensik-Eintrag je Ledger, in denselben Kurzfeldern wie die Tagesdatei sie schreibt.
// Die Default-Werte feuern absichtlich keine Quorum-/Last-/Takt-Anomalie (margin 15 >= 2,
// Last 120/100 = 1.2 < 3, Close-Abstand 4000 < 15000): was dann an Hypothesen steht,
// stammt aus der Transaktions-Form, nicht aus der Infrastruktur.
const statsOf = (l, t, over = {}) => ({
  l, t, v: 100, need: 80, top: 95, mg: 15, sp: 0, gap: 4000, gmed: 4000, tx: 120, med: 100,
  c: { missed: 1, partial: 0, wrongHash: 0, noQuorum: 0 }, sh: null, sev: {}, sweep: null,
  ...over,
});

/* 1) Das Profil unterscheidet "beobachtet, nichts aufgefallen" von "hier nichts
      aufgezeichnet". Vor dieser Stufe waren beide leer und wurden identisch gezeichnet —
      der Hauptgrund, warum das Profil Luecher zeigte, wo keine waren. */
const covered = {};
for (let k = 1; k <= 24; k++) {
  if (k >= 18 && k <= 20) continue; // Aufzeichnungsluecke: drei Stunden ohne Zaehler
  covered[Math.floor(NOW / HOUR) - k] = {
    l: 900, v: { [A]: { ok: 900, partial: 0, missed: 0, wrongHash: 0, noQuorum: 0 } },
  };
}
const traceDays = [dayOf({
  date: "2026-10-07", ledgers: 21 * 900,
  hourly: covered,
  validators: { [A]: { ok: 21 * 900, partial: 0, missed: 1, wrongHash: 1, noQuorum: 0 } },
  incidents: [
    { l: 100, m: A, t: NOW - 30 * 60000, type: "missed", r: ["drainer-fanout"] },
    { l: 101, m: A, t: NOW - 2 * HOUR, type: "wrong-hash", r: ["hash-split"] },
    { l: 101, m: B, t: NOW - 2 * HOUR, type: "missed", r: ["load-spike"] },
  ],
})];

test("profileCells: Intervalle mit Abdeckung und ohne Abweichung sind messbar sauber", () => {
  const p = profileCells(traceDays, A, { range: "24h", now: NOW });
  assert.equal(p.buckets, PROFILE_BUCKETS);
  assert.equal(p.cells.length, PROFILE_BUCKETS);
  assert.equal(p.measured, true);
  assert.equal(p.from, NOW - 24 * HOUR);
  assert.equal(p.to, NOW);
  const clean = p.cells.filter((c) => c.ledgers > 0 && c.total === 0);
  const gap = p.cells.filter((c) => c.ledgers === 0 && c.total === 0);
  assert.equal(clean.length, 19, "19 Intervalle sind beobachtet und unauffaellig");
  assert.equal(gap.length, 3, "nur die drei Stunden ohne Zaehler sind eine Luecke");
  assert.ok(clean.every((c) => c.ledgers === 900), "Abdeckung je Intervall kommt aus den Stundenzaehlern");
});

test("profileCells: ohne Stundenzaehler darf kein Intervall als sauber gelten", () => {
  const p = profileCells([dayOf({ ...traceDays[0], hourly: {} })], A, { range: "24h", now: NOW });
  assert.equal(p.measured, false);
  assert.equal(p.cells.filter((c) => c.ledgers > 0 && c.total === 0).length, 0,
    "keine Abdeckung -> keine Sauber-Aussage");
  assert.equal(p.cells.filter((c) => c.ledgers === 0 && c.total === 0).length, PROFILE_BUCKETS - 2);
});

test("profileCells: Kohortenbreite ist die weiteste Betroffenheit im Intervall", () => {
  const days = [dayOf({
    incidents: [
      { l: 300, m: A, t: NOW - 5 * HOUR, type: "missed", r: [] },
      { l: 300, m: "nP1", t: NOW - 5 * HOUR, type: "missed", r: [] },
      { l: 301, m: A, t: NOW - 5 * HOUR + 1000, type: "missed", r: [] },
      { l: 301, m: "nP1", t: NOW - 5 * HOUR + 1000, type: "missed", r: [] },
      { l: 301, m: "nP2", t: NOW - 5 * HOUR + 1000, type: "missed", r: [] },
      { l: 301, m: "nP3", t: NOW - 5 * HOUR + 1000, type: "missed", r: [] },
      { l: 301, m: "nP4", t: NOW - 5 * HOUR + 1000, type: "missed", r: [] },
    ],
  })];
  // Die Achse ist an die Aufnahme geklemmt: diese Fixture hat keine Stunden-Zaehler, der
  // aelteste Vorfall liegt bei NOW - 5 h, also beginnt die Achse dort. Nachgerechnet:
  // from = NOW - 5 h, width = 18 000 000 ms, Intervall = 750 000 ms. Beide Vorfalle dieser
  // Fixture (NOW - 5 h und NOW - 5 h + 1 000) fallen in Intervall 0.
  const p = profileCells(days, A, { range: "24h", now: NOW });
  assert.equal(p.clamped, true, "24-h-Fenster vor der Aufnahme: die Achse muss geklemmt sein");
  assert.equal(p.windowFrom, NOW - 24 * HOUR);
  assert.equal(p.from, NOW - 5 * HOUR);
  const cell = p.cells[0];
  assert.equal(cell.total, 2);
  assert.equal(cell.missed, 2);
  assert.equal(cell.cohort, 5, "fuenf Validatoren auf Ledger 301 -> Netzereignis, nicht solo");
});

test("profileCells: Signatur-Zaehler nur fuer Transaktions-Signaturen, nicht fuer Quorum-Anomalien", () => {
  const p = profileCells(traceDays, A, { range: "24h", now: NOW });
  assert.equal(p.cells[23].signatures, 1, "drainer-fanout ist eine Transaktionsform");
  assert.equal(p.cells[22].signatures, 0, "hash-split ist eine Quorum-Anomalie, keine Form");
  assert.equal(p.cells[22].cohort, 2);
  assert.deepEqual(p.cells[23].tags, { "drainer-fanout": 1 });
});

test("isSignatureTag: Form-Tags ja, Quorum- und Takt-Anomalien nein", () => {
  for (const tag of ["drainer-fanout", "sweep-window", "offer-flood", "type-burst:Payment", "new-tx-type:X"]) {
    assert.equal(isSignatureTag(tag), true, tag);
  }
  for (const tag of ["hash-split", "load-spike", "close-gap", "quorum-thin", "cohort-event", ""]) {
    assert.equal(isSignatureTag(tag), false, tag);
  }
});

/* 2) Signatur-Bord: eine Form ist erst dann eine Aussage, wenn sie gegen die Gesamtheit
      aller beobachteten Ledger gerechnet ist. Ein einzelner Ledger mit Faecherung ist ein
      Fall, keine Rate. */
const incidentLedgers = Array.from({ length: 40 }, (_, i) => ({
  l: 1000 + i, m: A, t: NOW - 3 * HOUR - i * 60000, type: "missed", r: [],
}));
const boardDays = [dayOf({
  ledgers: 1000, shapeSeen: 500, shapeMissing: 20,
  anomaly: { "drainer-fanout": 60, "load-spike": 200 },
  anomalyFail: { "drainer-fanout": 12, "load-spike": 10 },
  incidents: incidentLedgers,
  ledgerStats: [
    statsOf(900, NOW - 6 * HOUR, {
      sh: { n: 150, s: 11, d: 70, fo: 30, fd: 30, fa: 30, fl: 2 },
      sev: { "drainer-fanout": { fanoutAccounts: 30, fanoutTxs: 30, ledgerTx: 150 } },
    }),
    statsOf(901, NOW - 40 * 60000, {
      sh: { n: 210, s: 20, d: 60, fo: 12, fd: 4, fa: 4, fl: 0 },
      sev: { "drainer-fanout": { fanoutAccounts: 14, fanoutTxs: 18, ledgerTx: 210 } },
    }),
    statsOf(902, NOW - 20 * 60000, {
      sh: { n: 300, s: 30, d: 90, fo: 20, fd: 6, fa: 6, fl: 0, oc: 120 },
      sev: { "offer-flood": { count: 120, baseline: 12 } },
    }),
  ],
})];

test("signatureBoard: Rate aus vollstaendigen Ledger-Zaehlern, Beleg aus dem Fenster", () => {
  const b = signatureBoard(boardDays, { range: "24h", now: NOW });
  const row = b.rows.find((r) => r.tag === "drainer-fanout");
  assert.ok(row, "drainer-fanout muss im Bord stehen");
  assert.equal(row.anomalyLedgers, 60);
  assert.equal(row.anomalyFailLedgers, 12);
  assert.equal(row.plainLedgers, 940);
  assert.equal(row.plainFailLedgers, 28);
  assert.equal(row.reliable, true);
  assert.equal(Number((row.rateWith * 100).toFixed(1)), 20, "12 von 60 Ledgern mit Faecherung fallen aus");
  assert.equal(Number((row.rateWithout * 100).toFixed(3)), 2.979, "28 von 940 ohne Faecherung");
  assert.ok(Math.abs(row.lift - 6.714285714285714) < 1e-9, "Faelcherungs-Lift = 0.2 / 0.0297872");
  assert.ok(row.sample, "Beleg-Ledger gehoert zur Zeile");
  assert.equal(row.sample.ledgerIndex, 901, "neuester Beleg im Fenster gewinnt");
  assert.equal(row.sample.evidence.fanoutAccounts, 14);
  assert.equal(row.sample.shape.txCount, 210, "die Form des Belegs ist mitgeliefert");
});

test("signatureBoard: Quorum-Anomalien gehoeren nicht ins Form-Bord", () => {
  const b = signatureBoard(boardDays, { range: "24h", now: NOW });
  assert.ok(!b.rows.some((r) => r.tag === "load-spike"), "load-spike ist Last, nicht Form");
  assert.ok(b.rows.some((r) => r.tag === "offer-flood"));
});

test("signatureBoard: Form ohne Ledger-Zaehler bleibt sichtbar, aber ohne Rate", () => {
  const b = signatureBoard(boardDays, { range: "24h", now: NOW });
  const row = b.rows.find((r) => r.tag === "offer-flood");
  assert.equal(row.reliable, false);
  assert.equal(row.note, "no-ledger-counter");
  assert.equal(row.rateWith, null);
  assert.equal(row.lift, null);
  assert.ok(row.sample, "der einzelne Fall bleibt als Fall stehen");
  assert.ok(b.rows[0].reliable, "belastbare Zeilen stehen vor unbelegten");
});

test("signatureBoard: Abdeckung der Form ist eine eigene Zahl, nicht Restmenge", () => {
  const b = signatureBoard(boardDays, { range: "24h", now: NOW });
  assert.deepEqual(b.coverage, { shapeSeen: 500, shapeMissing: 20 });
  assert.equal(b.totalLedgers, 1000);
  assert.equal(b.incidentLedgers, 40);
});

test("signatureBoard: Belege außerhalb des Zeitfensters werden nicht vorgeschoben", () => {
  const days = [dayOf({
    ledgers: 1000, shapeSeen: 10,
    anomaly: { "drainer-fanout": 30 }, anomalyFail: { "drainer-fanout": 4 },
    incidents: incidentLedgers.slice(0, 5),
    ledgerStats: [statsOf(950, NOW - 3 * 86400000, {
      sh: { n: 150, fd: 30, fa: 30 }, sev: { "drainer-fanout": { fanoutAccounts: 30, fanoutTxs: 30, ledgerTx: 150 } },
    })],
  })];
  const b = signatureBoard(days, { range: "24h", now: NOW });
  const row = b.rows.find((r) => r.tag === "drainer-fanout");
  assert.ok(row);
  assert.equal(row.sample, null, "drei Tage alt ist kein Beleg fuer heute");
});

/* 3) Retrace: die Signatur ist eine Messung an DIESEM Ledger, also measured — nicht
      eine Vermutung aus dem Kontext. Ohne gespeicherten Messwert darf sie nicht als
      Messung ausgegeben werden. */
/* Grundfall: ein Ledger, zwei betroffene Validatoren, Vorfall DIESSES Validators. Die
   Retrace-Engine liest die Signatur aus dem Vorfall und den Messwert aus dem Ledger-Eintrag -
   beide muessen dieselben reasons tragen, sonst testet man eine Zufallskombination. */
const caseOf = (reasons, st) => [
  {
    ledgerIndex: 500, timeMs: NOW - 60000, stats: st,
    incidents: [{ master: A, type: "missed", reasons }, { master: B, type: "partial", reasons }],
  },
  { master: A, type: "missed", ledgerIndex: 500, timeMs: NOW - 60000, reasons },
];

test("retraceIncident: Signatur mit Messwert ist measured, Kontext bleibt correlated", () => {
  const st = statsOf(500, NOW - 60000, {
    sh: { n: 150, fd: 30, fa: 30 },
    sev: { "drainer-fanout": { fanoutAccounts: 30, fanoutTxs: 30, ledgerTx: 150 } },
  });
  const r = retraceIncident(...caseOf(["drainer-fanout", "amendment-activity"], st), null);
  const fan = r.hypotheses.find((h) => h.tag === "drainer-fanout");
  assert.equal(fan.strength, "measured");
  assert.equal(fan.evidence.fanoutAccounts, 30);
  assert.equal(r.hypotheses.find((h) => h.tag === "amendment-activity").strength, "correlated");
  assert.ok(!r.hypotheses.some((h) => h.tag === "no-correlated-cause"));
  // Der Fall hat eine Tx-Signatur, aber keinen Vote-Messwert: ob dieser Knoten spaet abstimmte
  // oder nie, ist eine echte Datenluecke und muss benannt bleiben, auch bei sonst voller Forensik.
  assert.deepEqual(r.dataGaps, ["late-vote-window"]);
  assert.equal(r.txShape.recorded, true);
  assert.equal(r.scope, "cohort");
});

test("retraceIncident: Signatur ohne gespeicherten Messwert bleibt correlated", () => {
  const st = statsOf(500, NOW - 60000, { sh: { n: 150, fd: 30, fa: 30 }, sev: {} });
  const r = retraceIncident(...caseOf(["drainer-fanout"], st), null);
  assert.equal(r.hypotheses.find((h) => h.tag === "drainer-fanout").strength, "correlated",
    "Tag vorhanden, Messwert verloren -> keine Messung");
  assert.equal(r.txShape.recorded, true);
});

test("retraceIncident: Sweep ist ein Fenster-Ereignis und wird aus st.sweep gemessen", () => {
  const st = statsOf(500, NOW - 60000, { sh: { n: 150, fd: 5, fa: 5 }, sweep: { destinations: 21, ledgers: 14, txs: 26 } });
  const r = retraceIncident(...caseOf([], st), null);
  const sw = r.hypotheses.find((h) => h.tag === "sweep-window");
  assert.ok(sw, "Sweep-Signatur muss sichtbar werden, obwohl der Einzel-Ledger zu klein ist");
  assert.equal(sw.strength, "measured");
  assert.equal(sw.evidence.destinations, 21);
  assert.equal(r.txShape.sweep.destinations, 21);
  assert.ok(!r.hypotheses.some((h) => h.tag === "no-correlated-cause"));
});

test("retraceIncident: Datenluecken werden benannt, nicht zu 'keine Ursache' verdichtet", () => {
  const noStats = retraceIncident(...caseOf([], null), null);
  assert.deepEqual(noStats.dataGaps, ["forensics-not-recorded", "late-vote-window"]);
  assert.ok(noStats.hypotheses.some((h) => h.tag === "no-correlated-cause" && h.strength === "none"));

  const noShape = retraceIncident(...caseOf([], statsOf(500, NOW - 60000, { sh: null, sev: {} })), null);
  assert.deepEqual(noShape.dataGaps, ["tx-shape-not-recorded", "late-vote-window"]);
  assert.equal(noShape.txShape.recorded, false);
});

/* 4) Pruefschritte: eine Form-Signatur verschiebt die naechste Pruefung von Infrastruktur
      auf das, was in diesem Ledger passiert ist. */
const guidanceOf = (tag) => {
  const st = statsOf(600, NOW - 60000, { sh: { n: 150 }, sev: tag ? { [tag]: { count: 1 } } : {} });
  return retraceIncident(...caseOf(tag ? [tag] : [], st), null).guidance;
};

test("guidance: Form-Signatur -> Angriffs-Pruefung statt Infrastruktur-Pruefung", () => {
  assert.ok(guidanceOf("drainer-fanout").includes("attack-drainer"));
  assert.ok(guidanceOf("sweep-window").includes("attack-drainer"));
  assert.ok(guidanceOf("sender-burst").includes("attack-burst"));
  for (const tag of ["offer-flood", "nft-spam", "account-create-burst"]) {
    assert.ok(guidanceOf(tag).includes("attack-spam"), tag);
  }
  assert.ok(guidanceOf("failure-spike").includes("attack-failed-tx"));
  assert.ok(guidanceOf("batch-amplify").includes("attack-amplify"));
  assert.ok(guidanceOf("fee-spike").includes("attack-fee"));
  assert.ok(guidanceOf("feature-change").includes("version-state"));
  assert.ok(guidanceOf("type-burst:Payment").includes("attack-type-burst"));
});

test("guidance: ohne korrelierte Ursache steht unknown-cause, nicht eine erfundene Pruefung", () => {
  const g = guidanceOf(null);
  assert.ok(g.includes("unknown-cause"));
  assert.ok(!g.some((x) => String(x).startsWith("attack-")));
});

/* 5) Sammelereignis-Ebene: viele Validatoren, derselbe Ledger, mit der Form daneben. */
test("attackSignals: Form des Ledgers steht neben der Betroffenheit", () => {
  const masters = Array.from({ length: 6 }, (_, i) => "nM" + i);
  const days = [dayOf({
    incidents: masters.map((m) => ({ l: 700, m, t: NOW - 2 * HOUR, type: "missed", r: ["drainer-fanout"] })),
    ledgerStats: [statsOf(700, NOW - 2 * HOUR, {
      sh: { n: 400, s: 12, d: 120, fo: 60, fd: 44, fa: 60, fl: 30, bt: 6, bi: 90 },
      sev: { "drainer-fanout": { fanoutAccounts: 44, fanoutTxs: 60, ledgerTx: 400 }, "failure-spike": { failed: 30 } },
      sweep: { destinations: 30, ledgers: 16, txs: 60 },
    })],
  })];
  const a = attackSignals(days, { range: "24h", now: NOW });
  const row = a.signals.find((s) => s.ledgerIndex === 700);
  assert.ok(row);
  assert.equal(row.affectedValidators, 6);
  assert.ok(row.anomalies.includes("drainer-fanout"));
  assert.ok(row.anomalies.includes("sweep-window"), "Fenster-Signatur gehoert zum Ereignis");
  assert.equal(row.shape.fanoutDestinations, 44);
  assert.equal(row.shape.innerTx, 90);
  assert.equal(row.shape.txCount, 400);
});

/* 6) Die Kette an einem echten Drainer-Stream: Form -> Signatur -> Rate -> Beleg ->
      Pruefschritt -> Intervall. Das ist die Ebene, die ein dUNL-Betreiber selbst nachlesen kann. */
test("Kette: Draener-Faecherung wird zur messbaren Ausfallwahrscheinlichkeit und zum Pruefschritt", () => {
  const shape = emptyShape();
  for (let i = 0; i < 30; i++) {
    addTx(shape, normalizeTx({ tx: { TransactionType: "Payment", Account: "rDRAIN", Destination: "rNew" + i, Fee: 12 }, meta: { transaction_state: "tesSUCCESS" } }));
  }
  for (let i = 0; i < 120; i++) {
    addTx(shape, normalizeTx({ tx: { TransactionType: "Payment", Account: "rPeer" + (i % 10), Destination: "rOld" + (i % 40), Fee: 12 }, meta: { transaction_state: "tesSUCCESS" } }));
  }
  const form = finishShape(shape);
  const flat = () => Array.from({ length: 12 }, () => 100);
  const base = { tx: flat(), ac: Array(12).fill(0), oc: Array(12).fill(0), nf: Array(12).fill(0), fee: flat(), byType: { Payment: flat() } };
  const sigs = classifyShape(form, base);
  assert.ok(sigs.some((s) => s.tag === "drainer-fanout"), "30 Empfaenger von einem Konto in einem Ledger");
  assert.ok(!sigs.some((s) => s.tag === "sender-burst"), "Faecherung ist nicht Dominanz: 30 von 150 sind kein Burst");

  const t = NOW - 4 * HOUR - 1000;
  const sev = Object.fromEntries(sigs.map((s) => [s.tag, s.evidence]));
  const days = [dayOf({
    ledgers: 1000, shapeSeen: 640, shapeMissing: 8,
    anomaly: { "drainer-fanout": 40 }, anomalyFail: { "drainer-fanout": 9 },
    incidents: [
      { l: 800, m: A, t, type: "missed", r: ["drainer-fanout"] },
      { l: 800, m: B, t, type: "partial", r: ["drainer-fanout"] },
      ...Array.from({ length: 29 }, (_, i) => ({ l: 801 + i, m: A, t: NOW - 6 * HOUR - i * 60000, type: "missed", r: [] })),
    ],
    ledgerStats: [statsOf(800, t, { sh: form, sev })],
    hourly: { [Math.floor(t / HOUR)]: { l: 900, v: { [A]: { ok: 899, missed: 1, partial: 0, wrongHash: 0, noQuorum: 0 } } } },
  })];

  const board = signatureBoard(days, { range: "24h", now: NOW });
  const row = board.rows.find((r) => r.tag === "drainer-fanout");
  assert.equal(row.anomalyLedgers, 40);
  assert.equal(row.anomalyFailLedgers, 9);
  assert.equal(row.plainLedgers, 960);
  assert.equal(row.plainFailLedgers, 21);
  assert.ok(Math.abs(row.lift - 10.285714285714286) < 1e-9, "9/40 gegen 21/960");
  assert.equal(row.sample.ledgerIndex, 800);

  const [retrace] = retraceForValidator(days, A, { range: "24h", now: NOW });
  assert.equal(retrace.ledgerIndex, 800, "neuester Vorfall zuerst");
  const fan = retrace.hypotheses.find((h) => h.tag === "drainer-fanout");
  assert.equal(fan.strength, "measured");
  assert.equal(fan.evidence.fanoutAccounts, 30);
  assert.equal(retrace.scope, "cohort", "zwei Validatoren auf Ledger 800");
  assert.ok(retrace.guidance.includes("attack-drainer"));
  assert.ok(retrace.guidance.includes("cohort-network"));

  // Achse geklemmt auf den fruehesten eigenen Datenpunkt: die 29 Vorfalle laufen von
  // NOW - 6 h bis NOW - 6 h - 28 min (i = 0..28), die einzige Stunde mit Zaehlern beginnt bei
  // NOW - 5 h. Also from = NOW - 6 h 28 min = 05:32:00, width = 23 280 000 ms,
  // Intervall = 970 000 ms. Vorfall auf Ledger 800 (07:59:59): Abstand 8 879 000 ms /
  // 970 000 = 9,15 -> Intervall 9. Die Stunde 07:00-08:00 ueberschneidet Intervall 9 nur von
  // 07:57:30 bis 08:00 = 150 000 ms, also 900 * 150 000 / 3 600 000 = 37,5 -> 38 Ledger.
  const p = profileCells(days, A, { range: "24h", now: NOW });
  assert.equal(p.clamped, true);
  assert.equal(p.from, NOW - 6 * HOUR - 28 * 60000, "die Achse beginnt vor dem aeltesten Vorfall");
  const cell = p.cells[9];
  assert.equal(cell.total, 1, "das Intervall zaehlt die eigenen Vorfalle dieses Validators");
  assert.equal(cell.signatures, 1);
  assert.equal(cell.cohort, 2);
  assert.equal(cell.ledgers, 38, "Intervall ist beobachtet - der Nenner ist der Overlap der Stunde, nicht die ganze Stunde");
  // Kein Vorfall faellt vor die Achse: die 29 weiteren Vorfalle (06:00 bis 05:32) liegen in
  // Intervall 0 und 1 - nachgerechnet 12 + 17 = 29, dazu der eine auf Ledger 800 = 30.
  assert.equal(p.cells[0].total, 17);
  assert.equal(p.cells[1].total, 12);
  assert.equal(p.cells.reduce((a, c) => a + c.total, 0), 30, "kein Vorfall geht durch die Klemmung verloren");

  const idx = buildLedgerIndex(days);
  assert.equal(idx.get(800).stats.sev["drainer-fanout"].fanoutTxs, 30);
  const risk = riskProfile(days);
  assert.equal(risk.totalLedgers, 1000);
  assert.equal(risk.incidentLedgers, 30);
});

/* Zwei Abwesenheits-Arten, zwei Stapel (Akkuratz 2026-10-17).
 * 'vote-not-observed' heisst: dieser Rekorder hat auf einem bewiesen geschlossenen
 * Ledger keinen Vote dieses Knotens gesehen. 'no-quorum' heisst: die Schliessung ist
 * verneint. Nachgezaehlt ueber data/validator-trace trugen am 2026-10-17 alle 1.313
 * 'no-quorum'-Vorfalle einen eigenen Schliess-Beweis - die Quorum-Absage war in jedem
 * Fall falsch, und im Profil stand sie in demselben Stapel wie die Erfassungs-Luecke. */
test("profileCells: vote-not-observed und no-quorum sind getrennte Stapel", () => {
  const days = [dayOf({
    incidents: [
      { l: 400, m: A, t: NOW - 3 * HOUR, type: "vote-not-observed", r: ["vote-not-observed"] },
      { l: 401, m: A, t: NOW - 3 * HOUR + 1000, type: "vote-not-observed", r: ["vote-not-observed"] },
      { l: 402, m: A, t: NOW - 3 * HOUR + 2000, type: "no-quorum", r: ["no-quorum"] },
      { l: 402, m: B, t: NOW - 3 * HOUR + 2000, type: "no-quorum", r: ["no-quorum"] },
    ],
  })];
  const p = profileCells(days, A, { range: "24h", now: NOW });
  const cell = p.cells.find((c) => c.total === 3);
  assert.ok(cell, "drei Vorfalle dieses Knoten muessen in einem Intervall stehen");
  assert.equal(cell.voteNotObserved, 2, "die Erfassungs-Art steht nicht als eigener Stapel da");
  assert.equal(cell.noQuorum, 1, "die Quorum-Absage wird wieder in den Erfassungs-Stapel gemischt");
  assert.equal(cell.total, cell.missed + cell.partial + cell.wrongHash + cell.voteNotObserved + cell.noQuorum,
    "die Summe der Stapel ist nicht die Zahl der Vorfalle");
  // Ein Tag ohne einzige Quorum-Absage darf nirgends eine zeigen - die Absage ist ein Urteil
  // ueber das Netz, und ohne verneinte Schliessung gibt es dieses Urteil nicht.
  const onlyCapture = profileCells([dayOf({
    incidents: [{ l: 500, m: A, t: NOW - 2 * HOUR, type: "vote-not-observed", r: ["vote-not-observed"] }],
  })], A, { range: "24h", now: NOW });
  assert.equal(onlyCapture.cells.reduce((a, c) => a + c.noQuorum, 0), 0,
    "ohne verneinte Schliessung steht eine Quorum-Absage im Profil");
  assert.equal(onlyCapture.cells.reduce((a, c) => a + c.voteNotObserved, 0), 1);
});
