// lib/validator-trace.test.mjs — Validator-Trace-Kern: Quorum, Incident-Typen, Korrelationen, Muster.
import test from "node:test";
import assert from "node:assert/strict";
import { createTracker, classifyReasons, reasonsFor, aggregatePatterns, TRACE_DEFAULTS } from "./validator-trace.mjs";

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
