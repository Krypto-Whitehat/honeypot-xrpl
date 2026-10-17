// lib/tx-forensics.test.mjs — Guards der Transaktions-Forensik.
//
// Die entscheidende Eigenschaft dieser Ebene ist NICHT, dass sie Signaturen findet (das kann
// jeder Zähler), sondern dass sie NICHTS meldet, wenn kein Vergleichswert existiert, und dass
// sie die zwei verschiedenen Angriffsnaturen Burst (ein Konto, viele Tx) und Fächer (ein Konto,
// viele Empfänger) nicht vermischt.
import { test } from "node:test";
import assert from "node:assert/strict";
import {
  TX_FORENSICS_DEFAULTS, normalizeTx, emptyShape, addTx, finishShape, classifyShape, createShapeTracker, median,
} from "./tx-forensics.mjs";

const tx = (over = {}) => ({ TransactionType: "Payment", Account: "rA", Destination: "rB", Fee: 12, ...over });
const msg = (over = {}) => ({ tx: tx(over.tx), meta: { transaction_state: over.state ?? "tesSUCCESS" }, engine_result: "tesSUCCESS" });

test("normalizeTx: Stream-Form, Ledger-Form und engine_result-Fallback", () => {
  const a = normalizeTx(msg({ tx: { Account: "rA", Destination: "rZ", Fee: "33" } }));
  assert.equal(a.type, "Payment");
  assert.equal(a.account, "rA");
  assert.equal(a.destination, "rZ");
  assert.equal(a.fee, 33);
  assert.equal(a.success, true);
  // Ohne meta: engine_result entscheidet.
  const b = normalizeTx({ tx: tx(), engine_result: "tecPATH_DRY" });
  assert.equal(b.success, false);
  // Defekt/leer -> null, nie ein halber Datensatz.
  assert.equal(normalizeTx(null), null);
  assert.equal(normalizeTx({ tx: {} }), null);
  // Batch: Inner-Tx werden gezählt (Verstärkungs-Signal).
  const c = normalizeTx({ tx: tx({ TransactionType: "Batch", InnerTransactions: [1, 2, 3, 4] }) });
  assert.equal(c.inner, 4);
});

test("finishShape: Burst und Fächer sind verschiedene Messgrößen", () => {
  // Burst: EIN Konto, 30 Tx, aber nur 2 verschiedene Empfänger.
  const s = emptyShape();
  for (let i = 0; i < 30; i++) addTx(s, normalizeTx(msg({ tx: { Account: "rBurst", Destination: i % 2 ? "rX" : "rY" } })));
  addTx(s, normalizeTx(msg({ tx: { Account: "rOther", Destination: "rZ" } })));
  const form = finishShape(s);
  assert.equal(form.n, 31);
  assert.equal(form.fo, 30, "aktivstes Konto nach Tx-Zahl");
  assert.equal(form.fd, 2, "verschiedene Empfänger des größten Fächers");
  assert.equal(form.s, 2);
  // Fächer: EIN Konto, 12 Tx auf 12 verschiedene Empfänger.
  const s2 = emptyShape();
  for (let i = 0; i < 12; i++) addTx(s2, normalizeTx(msg({ tx: { Account: "rFan", Destination: "rD" + i } })));
  const f2 = finishShape(s2);
  assert.equal(f2.fd, 12);
  assert.equal(f2.fa, 12);
  assert.equal(f2.ta, "rFan");
  // Leerer Ledger -> null, nicht eine Form mit Nullen.
  assert.equal(finishShape(emptyShape()), null);
});

test("classifyShape: ohne Basis nur die absoluten Signaturen, keine Basis-Signatur", () => {
  const form = { n: 60, s: 20, d: 20, fo: 40, fd: 15, fa: 40, ta: "rFan", fl: 0, ac: 30, oc: 50, nf: 50, bt: 0, bi: 0, fx: 0, fm: 0, fs: 0, types: { Payment: 60 } };
  const tags = classifyShape(form, { tx: [], ac: [], oc: [], nf: [], fee: [], byType: {} }).map((r) => r.tag);
  assert.ok(tags.includes("drainer-fanout"), "Fächerung ist eine absolute Messung");
  assert.ok(tags.includes("sender-burst"), "Burst ist eine absolute Messung");
  for (const t of ["offer-flood", "nft-spam", "account-create-burst", "load-spike", "type-burst:Payment"]) {
    assert.ok(!tags.includes(t), t + " braucht eine Vergleichsbasis und darf ohne sie nicht erscheinen");
  }
});

test("classifyShape: Basis-abhängige Signaturen nur über dem Verhältnis", () => {
  const base = { tx: Array(20).fill(50), ac: Array(20).fill(1), oc: Array(20).fill(2), nf: Array(20).fill(1), fee: Array(20).fill(10), byType: { Payment: Array(20).fill(40) } };
  const quiet = { n: 50, s: 40, d: 40, fo: 3, fd: 2, fa: 3, ta: null, fl: 0, ac: 1, oc: 3, nf: 2, bt: 0, bi: 0, fx: 0, fm: 10, fs: 10, types: { Payment: 45 } };
  assert.deepEqual(classifyShape(quiet, base).map((r) => r.tag), [], "Normalbetrieb darf keine Signatur liefern");
  const loud = { ...quiet, oc: 60, nf: 50, ac: 20, n: 300, types: { Payment: 200 } };
  const tags = classifyShape(loud, base).map((r) => r.tag);
  for (const t of ["offer-flood", "nft-spam", "account-create-burst", "load-spike", "type-burst:Payment"]) {
    assert.ok(tags.includes(t), t + " fehlt");
  }
  // 10 x Median -> load-extreme statt load-spike
  const extreme = { ...loud, n: 600 };
  const t2 = classifyShape(extreme, base).map((r) => r.tag);
  assert.ok(t2.includes("load-extreme") && !t2.includes("load-spike"));
});

test("classifyShape: Fehlerrate, Batch-Verstärkung, Gebühren und Netzwerk-Ebene", () => {
  const base = { tx: Array(20).fill(50), ac: [], oc: [], nf: [], fee: [], byType: {} };
  const failing = { n: 40, s: 10, d: 10, fo: 2, fd: 1, fa: 2, ta: null, fl: 14, ac: 0, oc: 0, nf: 0, bt: 0, bi: 0, fx: 0, fm: 0, fs: 0, types: { Payment: 40 } };
  assert.ok(classifyShape(failing, base).some((r) => r.tag === "failure-spike"));
  const batch = { ...failing, fl: 0, bt: 6, bi: 90 };
  assert.ok(classifyShape(batch, base).some((r) => r.tag === "batch-amplify"));
  const fee = { ...failing, fl: 0, fm: 500000, fs: 12 };
  assert.ok(classifyShape(fee, base).some((r) => r.tag === "fee-spike"));
  const feature = { ...failing, fl: 0, fx: 2 };
  assert.ok(classifyShape(feature, base).some((r) => r.tag === "feature-change"));
  // Zu wenige fehlgeschlagene Tx, obwohl Anteil hoch: absolute Untergrenze zählt.
  const few = { ...failing, n: 8, fl: 4 };
  assert.ok(!classifyShape(few, base).some((r) => r.tag === "failure-spike"));
});

test("createShapeTracker: Form je Ledger, rollende Basis, harte Speicherdeckel", () => {
  const tr = createShapeTracker({ baselineSize: 5, minBaseline: 3, maxTrackedAccounts: 30 });
  for (let l = 100; l < 112; l++) {
    for (let i = 0; i < 6; i++) tr.addTxTo(l, msg({ tx: { Account: "rA" + l, Destination: "rD" + l + "-" + i } }));
    const res = tr.commit(l);
    assert.ok(res && res.form.n === 6);
  }
  assert.equal(tr.shapeFor(100), null, "abgeschlossene Ledger werden freigegeben");
  const st = tr.stats();
  assert.ok(st.baseline <= 6, "Basis wächst nicht über baselineSize hinaus: " + st.baseline);
  assert.ok(st.tracked <= 30, "Konto-Beobachtung ist gedeckelt: " + st.tracked);
  // Fremde Ledger-Index wird ignoriert, nie erfunden.
  assert.equal(tr.addTxTo(NaN, msg()), null);
});

test("createShapeTracker: Sweep über Ledger hinweg (Drainer-Form, die ein Einzel-Ledger versteckt)", () => {
  const tr = createShapeTracker({ baselineSize: 4, minBaseline: 2, sweepMinDestinations: 6, sweepWindowLedgers: 10 });
  let sweepSeen = null;
  for (let l = 200; l < 208; l++) {
    // Dasselbe Konto, aber pro Ledger nur 2 neue Empfänger -> unter jeder Einzel-Ledger-Schwelle.
    for (let i = 0; i < 2; i++) tr.addTxTo(l, msg({ tx: { Account: "rSweeper", Destination: "rNew" + l + "-" + i } }));
    const res = tr.commit(l);
    if (res.sweep) sweepSeen = res.sweep;
  }
  assert.ok(sweepSeen, "Sweep muss über das Ledger-Fenster hinweg erkannt werden");
  assert.ok(sweepSeen.sweepDestinations >= 6);
  assert.ok(sweepSeen.sweepTxs >= sweepSeen.sweepLedgers * 2, "sweepTxs zählt Transaktionen, nicht Ledger");
});

test("createShapeTracker: Fenster altert — altes Sweep-Konto wird nicht endlos gemeldet", () => {
  const tr = createShapeTracker({ baselineSize: 3, minBaseline: 2, sweepMinDestinations: 6, sweepWindowLedgers: 3, maxTrackedAccounts: 50 });
  for (let l = 300; l < 304; l++) {
    for (let i = 0; i < 3; i++) tr.addTxTo(l, msg({ tx: { Account: "rOld", Destination: "rOld" + l + "-" + i } }));
    tr.commit(l);
  }
  // Danach nur noch ein anderes Konto, das nichts reißt.
  let late = null;
  for (let l = 320; l < 326; l++) {
    tr.addTxTo(l, msg({ tx: { Account: "rQuiet", Destination: "rQ" } }));
    late = tr.commit(l);
  }
  assert.equal(late.sweep, null, "nach dem Fenster darf dasselbe Muster nicht erneut als Sweep erscheinen");
});

test("median: gerade Länge mittelt, leere Liste liefert 0 (kein Raten)", () => {
  assert.equal(median([1, 2, 3]), 2);
  assert.equal(median([1, 2, 3, 4]), 2.5);
  assert.equal(median([]), 0);
  assert.equal(median([5, "x", 7]), 6);
});

test("Schwellen sind explizit TUNING-DEFAULTS und überschreibbar", () => {
  assert.ok(TX_FORENSICS_DEFAULTS.fanoutMinAccounts >= 2);
  const base = { tx: Array(20).fill(50), ac: [], oc: [], nf: [], fee: [], byType: {} };
  const form = { n: 20, s: 10, d: 10, fo: 3, fd: 4, fa: 6, ta: null, fl: 0, ac: 0, oc: 0, nf: 0, bt: 0, bi: 0, fx: 0, fm: 0, fs: 0, types: { Payment: 20 } };
  assert.ok(!classifyShape(form, base).some((r) => r.tag === "drainer-fanout"), "Standard: fd 4 unter fanoutMinAccounts 8");
  assert.ok(classifyShape(form, base, { fanoutMinAccounts: 4, fanoutMinTxs: 5 }).some((r) => r.tag === "drainer-fanout"), "opts überschreiben die Schwelle");
});
// --- Regression: die echte Stream-Huelle -------------------------------------------------
// Gemessen am 2026-10-16 direkt gegen wss://xrplcluster.com: der transactions-Stream liefert
// die Tx unter "transaction" (neuere API-Stufen: "tx_json"), NICHT unter "tx". Wer nur "tx"
// liest, erhaelt null, jede Form bleibt leer, und shapeMissing steigt fuer JEDES Ledger -
// das Signatur-Bord bleibt still leer, ohne dass ein Zaehler den Fehler zeigt.
const STREAM_MSG = (over = {}) => ({
  close_time_iso: "2026-10-16T10:00:00Z",
  ctid: "C0A40001_00000001_0000",
  engine_result: "tesSUCCESS",
  engine_result_code: 0,
  engine_result_message: "The transaction was applied.",
  ledger_hash: "AA11",
  ledger_index: 107687613,
  meta: { transaction_state: "tesSUCCESS" },
  status: "closed",
  transaction: { Account: "rA", Destination: "rB", Fee: "12", TransactionType: "Payment", hash: "H1" },
  type: "transaction",
  validated: true,
  ...over,
});

test("normalizeTx: echte Stream-Huelle mit transaction-Schluessel", () => {
  const a = normalizeTx(STREAM_MSG());
  assert.equal(a.type, "Payment");
  assert.equal(a.account, "rA");
  assert.equal(a.destination, "rB");
  assert.equal(a.fee, 12);
  assert.equal(a.success, true, "meta.transaction_state entscheidet zuerst");
  // Ohne meta entscheidet engine_result (Stream liefert beides).
  const b = normalizeTx(STREAM_MSG({ meta: undefined, engine_result: "tecPATH_DRY" }));
  assert.equal(b.success, false);
  // Neuere API-Stufe: tx_json.
  const c = normalizeTx({ tx_json: { Account: "rC", TransactionType: "OfferCreate", Fee: "10" }, engine_result: "tesSUCCESS" });
  assert.equal(c.type, "OfferCreate");
  // Batch im Stream-Rohformat: RawTransactions statt InnerTransactions.
  const d = normalizeTx(STREAM_MSG({ transaction: { Account: "rB", TransactionType: "Batch", RawTransactions: ["a", "b", "c"] } }));
  assert.equal(d.inner, 3);
  // Die Huelle allein ist kein Tx-Objekt: null, nie ein halber Datensatz.
  assert.equal(normalizeTx({ ledger_index: 5, meta: {}, validated: true }), null);
});

test("Tracker: echte Stream-Nachrichten ergeben eine Form (shapeSeen, nicht shapeMissing)", () => {
  const st = createShapeTracker();
  for (let i = 0; i < 12; i++) {
    for (let j = 0; j < 3; j++) {
      st.addTxTo(100 + i, STREAM_MSG({ ledger_index: 100 + i, transaction: { Account: "rBase", Destination: "rDest" + j, Fee: "10", TransactionType: "Payment" } }));
    }
    const res = st.commit(100 + i);
    assert.ok(res.form, "Ledger " + (100 + i) + " muss eine Form haben");
    assert.equal(res.form.n, 3);
  }
  assert.equal(st.stats().baseline, 12);
});

test("Signatur ueber echte Stream-Huelle: sender-burst wird gemeldet", () => {
  const st = createShapeTracker();
  const feed = (idx, n, acc) => {
    for (let i = 0; i < n; i++) {
      st.addTxTo(idx, STREAM_MSG({ ledger_index: idx, transaction: { Account: acc, Destination: "rD" + (i % 5), Fee: "10", TransactionType: "Payment" } }));
    }
  };
  for (let i = 0; i < 12; i++) feed(200 + i, 20, "rNormal" + i);
  feed(212, 40, "rBurst");
  const out = st.commit(212);
  const tags = classifyShape(out.form, out.base).map((x) => x.tag);
  assert.ok(tags.includes("sender-burst"), "Tags: " + tags.join(","));
});


// Die Form muss Transaktionen zaehlen, nicht Nachrichten. Warum das kein Detail ist: jede
// Drainer-Signatur haengt an 'n' und an den Konto-Zahlern. Ein Doppel-Relay, der unbemerkt
// mitzaehlt, verdoppelt die Form und damit die Signatur - und die Ausgabe waere eine Zahl,
// die niemand gegen die Ledger-Autoritaet nachrechnen kann.
test("Hash ist die Identitaet: tx, tx_json und transaction liefern ihn, fehlend bleibt offen", () => {
  assert.equal(normalizeTx({ tx: tx({ hash: "H1" }) }).hash, "H1");
  assert.equal(normalizeTx({ tx_json: { ...tx(), transaction_hash: "H2" } }).hash, "H2");
  assert.equal(normalizeTx({ transaction: { ...tx(), hash: "H3" } }).hash, "H3");
  assert.equal(normalizeTx({ tx: tx() }).hash, null, "ohne Hash wird keine Identitaet erfunden");
});

test("Form je Ledger: dieselbe Tx zweimal relayt zaehlt einmal, der Doppel-Relay ist gemeldet", () => {
  const s = emptyShape();
  addTx(s, normalizeTx(msg({ tx: { hash: "A1" } })));
  addTx(s, normalizeTx(msg({ tx: { hash: "A1" } })));   // dieselbe Transaktion, erneut relayt
  addTx(s, normalizeTx(msg({ tx: { hash: "B2", Destination: "rC" } })));
  const f = finishShape(s);
  assert.equal(f.n, 2, "A1 steht einmal in der Form");
  assert.equal(f.dup, 1, "der verworfene Doppel-Relay ist eine Zahl, keine stille Korrektur");
  assert.equal(f.noHash, 0);
  // Ohne Hash ist keine Identitaet pruefbar: gezaehlt, aber als nicht nachweisbar ausgewiesen.
  const s2 = emptyShape();
  for (let i = 0; i < 5; i++) addTx(s2, normalizeTx(msg({ tx: { Destination: "rD" + i } })));
  const f2 = finishShape(s2);
  assert.equal(f2.n, 5);
  assert.equal(f2.dup, 0);
  assert.equal(f2.noHash, 5, "fuenf Tx ohne Hash duerfen nicht als Duplikate gelten");
});

test("Tracker: Doppel-Relay je Ledger und die verworfene Zahl im Statistik-Zaehler", () => {
  const tr = createShapeTracker({ baselineSize: 4, minBaseline: 2 });
  const msgOf = (idx, h) => STREAM_MSG({ ledger_index: idx, transaction: { ...tx(), hash: h } });
  tr.addTxTo(100, msgOf(100, "H1"));
  tr.addTxTo(100, msgOf(100, "H2"));
  tr.addTxTo(100, msgOf(100, "H1"));   // Netz meldet denselben Index erneut
  const res = tr.commit(100);
  assert.equal(res.form.n, 2);
  assert.equal(res.form.dup, 1);
  assert.equal(res.form.noHash, 0);
  assert.equal(tr.stats().dropped, 1, "der Rekorder meldet, wie viel er verworfen hat");
  // Ein Ledger ohne Tx liefert keine Form - 'keine Form' und 'leerer Ledger' sind verschieden.
  assert.equal(tr.commit(101), null);
});
