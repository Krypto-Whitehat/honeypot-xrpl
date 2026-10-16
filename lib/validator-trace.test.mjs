// lib/validator-trace.test.mjs — Validator-Trace-Kern: Quorum, Incident-Typen, Korrelationen, Muster.
import test from "node:test";
import assert from "node:assert/strict";
import { addLoadSample, LOAD_BUCKETS, createTracker, classifyReasons, loadBucket, loadBucketLabel, reasonsFor, aggregatePatterns, TRACE_DEFAULTS } from "./validator-trace.mjs";

const M = Array.from({ length: 35 }, (_, i) => "nMEMBER" + String(i).padStart(2, "0"));
const E = new Map(M.map((m, i) => ["nEPH" + String(i).padStart(2, "0"), m]));
const SIGN = (m) => [...E.entries()].find(([, v]) => v === m)[0];
const T0 = 1_000_000;

function setup(extra = {}) {
  return createTracker({ members: M, ephemeralToMaster: E, opts: { graceMs: 0, ...extra } });
}
const ledger = (t, idx, over = {}) => ({ ledgerIndex: idx, hash: "H" + idx, closeMs: T0 + idx, txCount: 20, ...over });
const val = (m, idx, hash = "H" + idx, full = true) => ({ signingKey: SIGN(m), ledgerIndex: idx, ledgerHash: hash, full, t: T0 + idx + 1 });

test("Quorum: 28 von 35 signieren den Hash, 7 fehlen -> 7 missed, Quorum erreicht", () => {
  const tr = setup();
  tr.onLedger(ledger(0, 100));
  for (const m of M.slice(0, 28)) tr.onValidation(val(m, 100));
  const [r] = tr.evaluate(T0 + 10_000_000);
  assert.equal(tr.quorum, 28);
  assert.equal(r.hasQuorum, true);
  assert.equal(r.okCount, 28);
  assert.equal(r.incidents.length, 7);
  assert.ok(r.incidents.every((i) => i.type === "missed"));
  assert.ok(r.incidents.every((i) => i.reasons.includes("no-correlated-cause")), "stille Ledger -> keine erfundene Ursache");
});

test("wrong-hash: ein Validator signiert anderen Hash bei Quorum -> wrong-hash mit eigenem Grund", () => {
  const tr = setup();
  tr.onLedger(ledger(0, 101));
  for (const m of M.slice(0, 34)) tr.onValidation(val(m, 101));
  tr.onValidation(val(M[34], 101, "FORK"));
  const [r] = tr.evaluate(T0 + 10_000_000);
  const inc = r.incidents.find((i) => i.master === M[34]);
  assert.equal(inc.type, "wrong-hash");
  assert.ok(inc.reasons.includes("signed-different-hash"));
});

test("partial: full=false bei korrektem Hash -> partial", () => {
  const tr = setup();
  tr.onLedger(ledger(0, 102));
  for (const m of M) tr.onValidation(val(m, 102, "H102", m !== M[0] ? true : false));
  const [r] = tr.evaluate(T0 + 10_000_000);
  assert.equal(r.incidents.length, 1);
  assert.equal(r.incidents[0].type, "partial");
  assert.ok(r.incidents[0].reasons.includes("partial-validation"));
});

test("no-quorum: nur 10 Stimmen -> Nicht-Stimmer sind Typ no-quorum, nicht missed (Netzwerkereignis)", () => {
  const tr = setup();
  tr.onLedger(ledger(0, 103));
  for (const m of M.slice(0, 10)) tr.onValidation(val(m, 103));
  const [r] = tr.evaluate(T0 + 10_000_000);
  assert.equal(r.hasQuorum, false);
  assert.equal(r.incidents.length, 25);
  assert.ok(r.incidents.every((i) => i.type === "no-quorum"), "während Stockung ist Ausbleiben kein Einzelfehler");
  assert.ok(r.incidents[0].reasons.includes("no-quorum"));
  assert.ok(!r.incidents.some((i) => i.type === "missed"), "missed bleibt den Quorum-Ledgern vorbehalten");
});

test("Korrelation Lastspitze: 300 Tx bei Median 20 -> load-spike als Hinweis", () => {
  const tags = classifyReasons({ hasQuorum: true, txCount: 300, medianTx: 20, amendments: [], unlModify: false, novelTypes: [] });
  assert.ok(tags.includes("load-spike"));
});
test("Guard: 40 Tx (unter Untergrenze 50) ist keine Lastspitze", () => {
  const tags = classifyReasons({ hasQuorum: true, txCount: 40, medianTx: 5, amendments: [], unlModify: false, novelTypes: [] });
  assert.ok(!tags.includes("load-spike"));
});
test("Korrelation Amendment + UNL-Änderung im selben Ledger", () => {
  const tags = classifyReasons({ hasQuorum: true, txCount: 20, medianTx: 20, amendments: ["AM1"], unlModify: true, novelTypes: [] });
  assert.ok(tags.includes("amendment-activity") && tags.includes("unl-change"));
});

test("Tx-Typ-Neuheit: in der Anlaufphase (< 200 Ledger) wird nichts als neu markiert", () => {
  const tr = setup();
  tr.onLedger({ ...ledger(0, 104), types: ["NewThing"] });
  for (const m of M) tr.onValidation(val(m, 104));
  const [r] = tr.evaluate(T0 + 10_000_000);
  assert.equal(r.incidents.length, 0);
});

test("Signierschlüssel-Zuordnung: unbekannte Signer werden gezählt und ignoriert", () => {
  const tr = setup();
  tr.onLedger(ledger(0, 105));
  tr.onValidation({ signingKey: "nUNKNOWN", ledgerIndex: 105, ledgerHash: "H105", full: true, t: T0 });
  assert.equal(tr.stats().nonMemberSigners, 1);
});

test("Späte Validierung für bereits bewertete Ledger wird ignoriert", () => {
  const tr = setup();
  tr.onLedger(ledger(0, 106));
  for (const m of M) tr.onValidation(val(m, 106));
  tr.evaluate(T0 + 10_000_000);
  tr.onValidation(val(M[0], 106, "LATE"));
  tr.onLedger(ledger(0, 107));
  const r2 = tr.evaluate(T0 + 20_000_000);
  assert.equal(r2.length, 1);
  assert.equal(r2[0].ledgerIndex, 107);
});

test("Gnadenfenster: Ledger wird erst nach grace bewertet", () => {
  const tr = createTracker({ members: M, ephemeralToMaster: E, opts: { graceMs: 20000 } });
  tr.onLedger(ledger(0, 108));
  assert.equal(tr.evaluate(T0 + 108 + 10000).length, 0);
  assert.equal(tr.evaluate(T0 + 108 + 30000).length, 1);
});

test("aggregatePatterns: wiederkehrende Korrelation über mehrere Validatoren wird erkannt", () => {
  const inc = [];
  for (let i = 0; i < 4; i++) inc.push({ master: M[i], ledgerIndex: 200 + i, type: "missed", reasons: ["load-spike"] });
  inc.push({ master: M[9], ledgerIndex: 300, type: "missed", reasons: ["no-correlated-cause"] });
  const p = aggregatePatterns(inc);
  const ls = p.recurring.find((r) => r.tag === "load-spike");
  assert.ok(ls);
  assert.equal(ls.validators, 4);
  assert.ok(!p.recurring.some((r) => r.tag === "no-correlated-cause"));
});

test("TRACE_DEFAULTS explizit exportiert (Tuning, kein Kampagnen-Nachweis)", () => {
  assert.equal(TRACE_DEFAULTS.quorumFrac, 0.8);
  assert.equal(reasonsFor("partial", []).includes("partial-validation"), true);
});

test("attachDetail: Amendment + neuer Tx-Typ werden nachträglich als Korrelation gesetzt", () => {
  const tr = setup();
  tr.onLedger(ledger(0, 110));
  for (const m of M.slice(0, 30)) tr.onValidation(val(m, 110));
  const [r] = tr.evaluate(T0 + 10_000_000);
  assert.equal(r.detailNeeded, true);
  tr.attachDetail(r, { types: ["Payment", "AMMDeposit"], amendments: ["AMEND"], unlModify: false });
  const inc = r.incidents[0];
  assert.ok(inc.reasons.includes("amendment-activity"));
  assert.equal(r.detailNeeded, false);
});

test("Tx-Typ-Neuheit: Standardtypen werden NIE als neu getaggt, nur wirklich neue Typen", () => {
  const tr = setup();
  // Anlaufphase überspringen: 210 bewertete Ledger, damit Neuheit aktiv ist.
  for (let i = 0; i < 210; i++) { tr.onLedger(ledger(0, i)); tr.evaluate(T0 + i + 1); }
  tr.onLedger(ledger(0, 999));
  for (const m of M.slice(0, 30)) tr.onValidation(val(m, 999));
  const [r] = tr.evaluate(T0 + 10_000_000);
  tr.attachDetail(r, { types: ["Payment", "OfferCreate", "TrulyNewTx"], amendments: [], unlModify: false });
  const reasons = r.incidents[0].reasons;
  assert.ok(reasons.includes("new-tx-type:TrulyNewTx"), "wirklich neuer Typ wird getaggt");
  assert.ok(!reasons.includes("new-tx-type:Payment") && !reasons.includes("new-tx-type:OfferCreate"),
    "Standardtypen sind nie 'neu' — gemessener Fehler an echten Incidents");
});

test("aggregatePatterns: derselbe Ledger mit vielen Ausfällen ist KEIN wiederkehrendes Muster", () => {
  const inc = M.slice(0, 13).map((m) => ({ master: m, ledgerIndex: 500, type: "missed", reasons: ["no-quorum"] }));
  const p = aggregatePatterns(inc);
  assert.equal(p.recurring.length, 0);
  assert.equal(p.tags[0].count, 13);
});
test("Forensik: Typ-Zaehler treffen die Felder der Tagesdatei (no-quorum -> noQuorum, kein NaN)", () => {
  const tr = setup();
  tr.onLedger(ledger(0, 130));
  for (const m of M.slice(0, 10)) tr.onValidation(val(m, 130));
  const [r] = tr.evaluate(T0 + 10_000_000);
  const c = r.forensics.counts;
  assert.deepEqual(Object.keys(c).sort(), ["missed", "noQuorum", "partial", "wrongHash"], "kein Zusatzschluessel 'no-quorum' neben noQuorum");
  assert.equal(c.noQuorum, 25);
  assert.equal(c.missed, 0);
  assert.ok(Object.values(c).every((x) => Number.isFinite(x)), "NaN waere in JSON null und damit eine falsche 0-Aussage");
});

test("Forensik: gemischte Typen verteilen sich ohne Rest auf die Felder", () => {
  const tr = setup();
  tr.onLedger(ledger(0, 131));
  for (const m of M.slice(0, 28)) tr.onValidation(val(m, 131));
  tr.onValidation(val(M[28], 131, "FORK"));
  tr.onValidation(val(M[29], 131, "H131", false));
  const [r] = tr.evaluate(T0 + 10_000_000);
  const c = r.forensics.counts;
  assert.equal(c.wrongHash, 1);
  assert.equal(c.partial, 1);
  assert.equal(c.missed, 5);
  assert.equal(c.noQuorum, 0);
  assert.equal(Object.values(c).reduce((a, b) => a + b, 0), r.incidents.length, "keine Vorfalle ohne Zaehler");
});

// Last-Achse: absolute Stufen, von Hand nachgerechnet an den Grenzen 10/25/50/100/200/400/800/1600/3200.
test("loadBucket: jede Stufengrenze liegt in der richtigen Stufe", () => {
  assert.equal(loadBucket(0), 0);
  assert.equal(loadBucket(9), 0);
  assert.equal(loadBucket(10), 1);
  assert.equal(loadBucket(24), 1);
  assert.equal(loadBucket(25), 2);
  assert.equal(loadBucket(49), 2);
  assert.equal(loadBucket(50), 3);
  assert.equal(loadBucket(99), 3);
  assert.equal(loadBucket(100), 4);
  assert.equal(loadBucket(3199), 8);
  assert.equal(loadBucket(3200), 9);
  assert.equal(loadBucket(999999), 9);
});

test("loadBucket: fehlende oder negative Tx-Zahl ist eine Messung mit 0, keine Luecke", () => {
  assert.equal(loadBucket(null), 0);
  assert.equal(loadBucket(undefined), 0);
  assert.equal(loadBucket(Number.NaN), 0);
  assert.equal(loadBucket(-7), 0);
});

test("loadBucketLabel: lesbare Grenzen inklusive der offenen obersten Stufe", () => {
  assert.equal(loadBucketLabel(0), "0-9");
  assert.equal(loadBucketLabel(3), "50-99");
  assert.equal(loadBucketLabel(8), "1600-3199");
  assert.equal(loadBucketLabel(LOAD_BUCKETS.length - 1), ">= 3200");
});

test("addLoadSample: jedes Ledger zaehlt, Ausfaelle nur einmal je Ledger und Validator", () => {
  const d = { date: "2026-10-08" };
  addLoadSample(d, 30, []);            // Stufe 2, kein Ausfall
  addLoadSample(d, 30, [M[0], M[0]]);      // Stufe 2, ein Ledger mit zwei Vorfällen desselben Knotens
  addLoadSample(d, 150, [M[0], M[1]]);     // Stufe 4
  const b = d.loadBuckets;
  assert.equal(b[2].l, 2);
  assert.equal(b[2].f, 1, "zwei Vorfalle desselben Knotens in einem Ledger sind ein Ausfall-Ledger");
  assert.equal(b[2].v[M[0]], 1);
  assert.equal(b[4].l, 1);
  assert.equal(b[4].f, 1);
  assert.equal(b[4].v[M[0]], 1);
  assert.equal(b[4].v[M[1]], 1);
  // Die Achse wird dicht gefuellt: eine Stufe ohne Stichprobe ist ein Bucket mit 0, nicht ein
  // Loch - JSON serialisiert Locher eines Arrays naemlich als null.
  assert.equal(b.length, LOAD_BUCKETS.length, "Last-Achse hat nicht alle Stufen");
  assert.ok(b.every((x) => x && typeof x === "object"), "Stufe ohne Stichprobe ist null");
  assert.deepEqual(JSON.parse(JSON.stringify(b)).filter((x) => x === null), [], "JSON serialisiert Locher als null");
});

// AKKURATZ-NACHWEIS 2026-10-16, an den drei Ledgers, die xrpscan als validiert ausweist:
//   107695059 hash 986E8D51B34602 close 2026-10-16T12:34:02Z tx 52 -> 16 gesehene Mitglieder-Stimmen
//   107694001 hash 20444972158736 close 2026-10-16T11:25:50Z tx 93 -> 0 gesehen, Close-Abstand 70 s
//   107690236 hash FB3ABE4A705962 close 2026-10-16T07:23:52Z tx 27 -> 20 gesehen
// needed = ceil(35 * 0.8) = 28.

test("Akkuratz 107695059: 16 von 28 gesehen, der Ledger ist geschlossen - acceptedHash ist der Hash des Netzes", () => {
  const tr = setup();
  tr.onLedger({ ledgerIndex: 107695059, hash: "986E8D51B34602", closeMs: 20_000_000, txCount: 52 });
  for (const m of M.slice(0, 16)) tr.onValidation(val(m, 107695059));
  const [r] = tr.evaluate(20_000_000 + TRACE_DEFAULTS.graceMs);
  assert.equal(tr.quorum, 28, "ceil(35 * 0.8) = 28");
  assert.equal(r.hasQuorum, false, "16 < 28: die Schwelle DIESER Aufzeichnung war nicht erreicht");
  assert.equal(r.closed, true, "der 'ledger'-Stream liefert nur validierte Ledger");
  assert.equal(r.closedHash, "986E8D51B34602");
  assert.equal(r.forensics.acceptedHash, "986E8D51B34602", "nicht die eigene Stimmenmehrheit, sondern der Hash des Netzes");
  assert.equal(r.forensics.topHash, "H107695059", "was dieser Knoten sah, bleibt getrennt ausgewiesen");
  assert.equal(r.forensics.observedValidations, 16);
  assert.equal(r.forensics.topVotes, 16);
  assert.equal(r.forensics.margin, -12, "16 - 28 = -12");
  assert.equal(r.forensics.counts.noQuorum, 19, "35 - 16 = 19 Mitglieder ohne gesehenen Vote");
  assert.equal(r.incidents.length, 19);
  assert.ok(r.incidents.every((i) => i.type === "no-quorum"));
});

test("Akkuratz 107694001: 0 gesehene Stimmen bei 70 s Abstand auf 1 s Takt ist Erfassungs-Luecke", () => {
  const tr = setup();
  // Eigenen Takt aufbauen: funf Ledger im Abstand von 1 000 ms, alle mit vollem Quorum.
  for (let i = 0; i < 5; i += 1) {
    const idx = 107693996 + i;
    tr.onLedger({ ledgerIndex: idx, hash: "H" + idx, closeMs: 30_000_000 + i * 1000, txCount: 20 });
    for (const m of M) tr.onValidation(val(m, idx));
    tr.evaluate(30_000_000 + i * 1000);
  }
  // Der Fall selbst: 70 000 ms Abstand zum letzten Close, gar keine gesehenen Stimmen.
  tr.onLedger({ ledgerIndex: 107694001, hash: "20444972158736", closeMs: 30_004_000 + 70_000, txCount: 93 });
  const [r] = tr.evaluate(30_074_000 + TRACE_DEFAULTS.graceMs);
  assert.equal(r.closeGapMs, 70_000);
  assert.equal(r.medianGap, 1000);
  assert.equal(r.captureGap, true, "70 000 >= 5 * 1 000 = 5 000 (captureGapRatio)");
  assert.equal(r.closed, true);
  assert.equal(r.closedHash, "20444972158736");
  assert.equal(r.forensics.acceptedHash, "20444972158736");
  assert.equal(r.forensics.observedValidations, 0);
  assert.equal(r.forensics.margin, -28, "0 - 28 = -28");
  assert.equal(r.forensics.counts.noQuorum, 35);
});

test("Akkuratz 107690236: 20 Mitglieder plus 4 Signierer ausserhalb = 24 beobachtete Validierungen", () => {
  const tr = setup();
  tr.onLedger({ ledgerIndex: 107690236, hash: "FB3ABE4A705962", closeMs: 40_000_000, txCount: 27 });
  for (const m of M.slice(0, 20)) tr.onValidation(val(m, 107690236));
  for (const k of ["nFREMDE1", "nFREMDE2", "nFREMDE3", "nFREMDE4"]) {
    tr.onValidation({ signingKey: k, ledgerIndex: 107690236, ledgerHash: "H107690236", full: true, t: 40_000_001 });
  }
  const [r] = tr.evaluate(40_000_000 + TRACE_DEFAULTS.graceMs);
  assert.equal(r.forensics.topVotes, 20, "nur die beobachteten dUNL-Mitglieder zaehlen in die Marge");
  assert.equal(r.forensics.margin, -8, "20 - 28 = -8");
  assert.equal(r.forensics.votes, 20);
  assert.equal(r.forensics.observedValidations, 24, "20 Mitglieder + 4 ausserhalb: die Netzseite ist mitgezaehlt");
  assert.equal(r.forensics.closedHash, "FB3ABE4A705962");
  assert.equal(r.forensics.counts.noQuorum, 15, "35 - 20 = 15");
  assert.equal(r.captureGap, false, "kein Close-Abstand dieses Rekorders");
});
