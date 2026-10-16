// lib/validator-trace.test.mjs — Validator-Trace-Kern: Quorum, Incident-Typen, Korrelationen, Muster.
import test from "node:test";
import assert from "node:assert/strict";
import { addLoadSample, LOAD_BUCKETS, createTracker, classifyReasons, loadBucket, loadBucketLabel, reasonsFor, aggregatePatterns, TRACE_DEFAULTS,
  ledgerClosure, CLOSURE_BASES, CAPTURE_GAP_BASES, captureBound, CAPTURE_MEMBER_BASES } from "./validator-trace.mjs";

const M = Array.from({ length: 35 }, (_, i) => "nMEMBER" + String(i).padStart(2, "0"));
const E = new Map(M.map((m, i) => ["nEPH" + String(i).padStart(2, "0"), m]));
const SIGN = (m) => [...E.entries()].find(([, v]) => v === m)[0];
const T0 = 1_000_000;

function setup(extra = {}) {
  return createTracker({ members: M, ephemeralToMaster: E, opts: { graceMs: 0, ...extra } });
}
/* Der Schliess-Beweis ist die Klammer ueber allen Stimmen-Zaehlern: Diagnose, Retrace und
 * Ursachen-Ebene lesen ausschliesslich diese Funktion. Ein nachgetragener Hash von ausserhalb
 * (scripts/backfill-closure.mjs) darf nur als das erscheinen, was er ist - Fremdquelle plus
 * benannte Gegenpruefung. Die Zahlen sind die live gegengeprueften vom 2026-10-16. */
/* Die nachrechenbare Grenze (2026-10-17): ein bewiesen geschlossener Ledger zwingt die Zahl
 * echter Nicht-Signierer nach oben. Ein Knoten akzeptiert ein valid nur ab ceil(0.8 * dUNL)
 * signierter Mitglieder - also kann es auf einem geschlossenen Ledger hoechstens
 * (dUNL - Ziel) echte Nicht-Signierer geben. Alle Zahlen unten sind die live gegengeprueften
 * vom 2026-10-16: api.xrpscan.com/api/v1/ledger/<index> bestaetigt fuer 107695059
 * 986E8D51A78E8B2CB53B0FDBAE613692C7D33E3C82DCEE20A2C22D5496B34602 / 52 Tx / close 1792154042,
 * fuer 107694001 20444972846C358C... / 93 Tx / 1792149950, fuer 107690236 FB3ABE4A1AD20B85...
 * / 27 Tx / 1792135432. Die Ledger sind validiert - die Flags darunter sind Erfassung. */
test("Erfassungs-Grenze: auf geschlossenem Ledger ist die Zahl echter Nicht-Signierer begrenzt", () => {
  // 107695059 live: Ziel ceil(35 * 0.8) = 28, gesehen 16, geflaggt 19.
  // Nachgerechnet: 35 - 28 = 7 echte Nicht-Signierer hoechstens; 19 - 7 = 12 mindestens Artefakt.
  const b = captureBound({ l: 107695059, cl: true, ch: "986E8D51", v: 16, top: 16, need: 28, mg: -12,
    c: { missed: 0, partial: 0, wrongHash: 0, noQuorum: 19 } });
  assert.equal(b.closed, true);
  assert.equal(b.members, 35, "16 gesehene Stimmen + 19 geflaggte Knoten = 35 Mitglieder");
  assert.equal(b.membersBasis, "derived");
  assert.ok(CAPTURE_MEMBER_BASES.includes(b.membersBasis));
  assert.equal(b.absentCount, 19);
  assert.equal(b.genuineAbsentMax, 7, "mehr als 7 echte Nicht-Signierer widerspraechen der Schliessung");
  assert.equal(b.captureArtifactMin, 12, "19 Flags - 7 moegliche = 12 nachweisbare Erfassungs-Artefakte");
  assert.equal(b.captureComplete, false, "16 < 28: diese Erfassung kann einen Einzelbefund nicht tragen");
});

test("Erfassungs-Grenze: 107694001 ohne eine einzige gesehene Stimme laesst 28 von 35 Flags offen", () => {
  // Luecken-Log des Tages: 107693984-107694000 fehlten, close-Abstand 70 000 ms gegen 1 000 ms Takt.
  const b = captureBound({ l: 107694001, cl: true, ch: "20444972", v: 0, top: 0, need: 28, mg: -28,
    c: { missed: 0, partial: 0, wrongHash: 0, noQuorum: 35 } }, { parentGap: true });
  assert.equal(b.closure.captureGap, true, "der Luecken-Log deckt 107694000 ab");
  assert.equal(b.seenVotes, 0);
  assert.equal(b.absentCount, 35);
  assert.equal(b.genuineAbsentMax, 7);
  assert.equal(b.captureArtifactMin, 28, "35 - 7: mindestens 28 dieser Flags sind eigene Luecke");
});

test("Erfassungs-Grenze: volle Erfassung laesst kein Artefakt uebrig - dann ist der Einzelbefund erlaubt", () => {
  // 107699168 live: 28 von 28 Stimmen gesehen, 7 Knoten als missed geflaggt, dUNL aufgezeichnet.
  const b = captureBound({ l: 107699168, cl: true, ch: "59F271F8", v: 28, top: 28, need: 28, mg: 0, mm: 35,
    c: { missed: 7, partial: 0, wrongHash: 0, noQuorum: 0 } });
  assert.equal(b.membersBasis, "recorded", "mm ist die aufgezeichnete dUNL-Groesse dieses Ledgers");
  assert.equal(b.captureComplete, true);
  assert.equal(b.genuineAbsentMax, 7);
  assert.equal(b.captureArtifactMin, 0, "7 Flags bleiben 7 moegliche Knotenbefunde - kein Artefakt nachweisbar");
});

test("Erfassungs-Grenze: ohne Schliessung oder ohne Ziel wird keine Grenze behauptet", () => {
  const open = captureBound({ l: 1, cl: false, ch: null, v: 16, top: 16, need: 28, c: { noQuorum: 19 } });
  assert.equal(open.genuineAbsentMax, null, "ein nicht geschlossener Ledger begruendet keine Grenze");
  assert.equal(open.captureArtifactMin, null);
  assert.equal(open.captureComplete, null);
  const noTarget = captureBound({ l: 2, cl: true, ch: "H", v: 16, top: 16, c: { noQuorum: 19 } });
  assert.equal(noTarget.members, 35, "16 + 19 ist die Identitaet des Rekorder-Loops");
  assert.equal(noTarget.genuineAbsentMax, null, "ohne Quorum-Ziel gibt es keine obere Grenze");
  assert.equal(noTarget.captureArtifactMin, null);
  assert.equal(captureBound(null), null, "ohne Forensik-Zeile gibt es keine Zahl");
});

test("Schliess-Beweis: eigener Hash, Fremd-Hash und Gegenpruefung sind drei verschiedene Dinge", () => {
  const own = ledgerClosure({ cl: true, ch: "986E8D51A78E8B2C" });
  assert.equal(own.basis, "validated-ledger-stream", "eigener Hash aus dem Stream ist kein Fremd-Nachweis");
  assert.equal(own.verifiedBy, null, "ohne zweite Autoritaet darf keine Gegenpruefung behauptet werden");
  const ext = ledgerClosure({ cl: true, ch: "986E8D51A78E8B2C", chSource: "xrpscan", chVerifiedBy: "xrplcluster.com" });
  assert.equal(ext.basis, "xrpscan", "nachgetragener Hash bleibt Fremdquelle");
  assert.equal(ext.verifiedBy, "xrplcluster.com", "die Gegenpruefung ist benennbar");
  assert.ok(CLOSURE_BASES.includes(ext.basis), "Basis ausserhalb der erlaubten Menge");
  const open = ledgerClosure({ cl: false, ch: null });
  assert.equal(open.closed, false);
  assert.equal(open.basis, "recorder", "ausdruecklich verneinte Schliessung ist die Messung des Rekorders");
  assert.equal(ledgerClosure(null).basis, "not-recorded");
  assert.equal(ledgerClosure(null).verifiedBy, null);
});

/* Die Erfassungs-Luecke ist eine Messung DIESES Recorders, keine Rechnung aus dem Close-Abstand.
 * Der eigene Widerlegungsnachweis vom 2026-10-16: Ledger 107699231 meldete cg === true bei
 * 8 000 ms Abstand gegen 1 000 ms Takt - bei 35 von 35 gesehenen dUNL-Mitgliedern und Marge +7.
 * Ein Abstand ist der Takt des Netzes, nicht die Luecke des Mithoerers. */
test("Erfassungs-Luecke: Index-Folge oder Luecken-Log, der Close-Abstand ist kein Beleg", () => {
  // 107695059 direkt nach 107695058 ausgewertet: 107695059 = 107695058 + 1, kein Sprung.
  const own = ledgerClosure({ cl: true, l: 107695059, pg: 107695058 });
  assert.equal(own.captureGap, false, "lueckenlose Index-Folge ist gemessen keine Luecke");
  assert.equal(own.captureGapBasis, "ledger-index");
  // 107694001 nach 107693999 ausgewertet: 107694001 - 107693999 = 2, also fehlt 107694000.
  const jump = ledgerClosure({ cl: true, l: 107694001, pg: 107693999 });
  assert.equal(jump.captureGap, true, "ein uebersprungener Index fehlt samt seinen Stimmen");
  assert.equal(jump.captureGapBasis, "ledger-index");
  // Der widerlegte Fall: cg === true aus dem alten Abstandsgesetz, ohne Index- und ohne
  // Luecken-Log-Beleg. Sie darf nicht mehr als Luecke gelesen werden.
  const stale = ledgerClosure({ cl: true, l: 107699231, cg: true, gap: 8000, gmed: 1000 });
  assert.equal(stale.captureGap, null, "8 000 ms Abstand bei 35 von 35 Stimmen ist keine Luecke");
  assert.equal(stale.captureGapBasis, "not-recorded");
  // Zweite gemessene Quelle: der Luecken-Log des Tages fuer den Bestand ohne 'pg'.
  const viaGap = ledgerClosure({ cl: true, l: 107694001 }, { parentGap: true });
  assert.equal(viaGap.captureGap, true);
  assert.equal(viaGap.captureGapBasis, "stream-gap");
  // Kein Beleg irgendwo: die Frage bleibt offen. 'keine Luecke' waere eine Entlastung ohne Grund.
  const open = ledgerClosure({ cl: true, l: 107690236, gap: 1000, gmed: 1000 });
  assert.equal(open.captureGap, null, "ohne Index-Folge und ohne Luecken-Log wird nichts behauptet");
  assert.ok(CAPTURE_GAP_BASES.includes(open.captureGapBasis), "Basis ausserhalb der erlaubten Menge");
});

const ledger = (t, idx, over = {}) => ({ ledgerIndex: idx, hash: "H" + idx, closeMs: T0 + idx, txCount: 20, ...over });
const val = (m, idx, hash = "H" + idx, full = true) => ({ signingKey: SIGN(m), ledgerIndex: idx, ledgerHash: hash, full, t: T0 + idx + 1 });

/* Der dUNL aendert sich laufend, und jeder Knoten signiert mit einem Schluessel, der in festen
 * Abstaenden neu ausgelost wird. Eine nur beim Start geladene Liste zaehlt einen gueltigen Vote
 * als Fremdsignatur - der Knoten erscheint als 'no-quorum', obwohl er abgestimmt hat. */
test("setMembers: nachgezogener dUNL zaehlt seine neuen Signierschluessel, ohne neu zu bewerten", () => {
  const tr = setup();
  const E2 = new Map(M.map((m, i) => ["nNEU" + String(i).padStart(2, "0"), m]));
  assert.deepEqual(tr.setMembers(M, E2), { added: 0, removed: 0, members: 35 }, "dieselbe Liste bewegt nichts");
  // Vor dem Nachzug waeren diese Signierschluessel Fremde gewesen.
  tr.onLedger(ledger(0, 140));
  for (const m of M.slice(0, 28)) {
    tr.onValidation({ signingKey: "nNEU" + String(M.indexOf(m)).padStart(2, "0"), ledgerIndex: 140, ledgerHash: "H140", full: true, t: T0 + 141 });
  }
  const [r] = tr.evaluate(T0 + 10_000_000);
  assert.equal(r.forensics.topVotes, 28, "die neuen Schluessel zaehlen als die Mitglieder, die sie sind");
  assert.equal(r.incidents.length, 7, "35 - 28 = 7");
  assert.equal(tr.stats().nonMemberSigners, 0, "kein Mitglied darf als Fremder gezaehlt werden");
  assert.equal(tr.stats().lastEvaluated, 140, "der Nachzug darf die Bewertung nicht auf 0 zuruecksetzen");
  // Quorum haengt an der Mitgliederzahl: 35 -> 28, 30 -> 24 (quorumFrac 0,8, aufgerundet).
  const tr2 = setup();
  assert.equal(tr2.quorum, 28, "ceil(35 * 0,8) = 28");
  assert.deepEqual(tr2.setMembers(M.slice(0, 30), E), { added: 0, removed: 5, members: 30 });
  assert.equal(tr2.quorum, 24, "ceil(30 * 0,8) = 24");
  // Eine leere Liste ist kein Nachzug: sie wuerde 35 Mitglieder durch null ersetzen.
  assert.deepEqual(tr2.setMembers([], E), { added: 0, removed: 0, members: 30 }, "leere Liste wird verworfen");
});

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

test("Akkuratz 107694001: der Index-Sprung ist die Luecke, der 70-s-Abstand nur ihr Begleitsignal", () => {
  const tr = setup();
  // Eigenen Takt aufbauen: funf Ledger im Abstand von 1 000 ms, alle mit vollem Quorum.
  for (let i = 0; i < 5; i += 1) {
    const idx = 107693995 + i;
    tr.onLedger({ ledgerIndex: idx, hash: "H" + idx, closeMs: 30_000_000 + i * 1000, txCount: 20 });
    for (const m of M) tr.onValidation(val(m, idx));
    tr.evaluate(30_000_000 + i * 1000);
  }
  // Der Fall selbst: 107694000 ist nie gesehen worden - der Rekorder hinkt genau einen Index
  // hinterher, und der Abstand zum letzten Close betraegt 70 000 ms bei 1 000 ms Takt.
  tr.onLedger({ ledgerIndex: 107694001, hash: "20444972158736", closeMs: 30_004_000 + 70_000, txCount: 93 });
  const [r] = tr.evaluate(30_074_000 + TRACE_DEFAULTS.graceMs);
  assert.equal(r.closeGapMs, 70_000);
  assert.equal(r.medianGap, 1000);
  assert.equal(r.previousLedger, 107693999, "der zuletzte ausgewertete Index ist der Beleg");
  assert.equal(r.captureGap, true, "107694001 > 107693999 + 1 -> 107694000 fehlt samt seinen Stimmen");
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
  assert.equal(r.previousLedger, null, "vorher wurde nichts ausgewertet - es gibt keinen Beleg");
  assert.equal(r.captureGap, false, "kein Index-Sprung: dieser Rekorder hat nichts uebersprungen");
});

/* Die eigene Erfassungs-Basis: 'votes / needed' unter Ziel war eine Zahl ohne Einordnung.
 * Verglichen wird dieser Rekorder mit sich selbst - nie mit dem Netz. Der widerlegte Fall vom
 * 2026-10-16 (107699231: 8 000 ms Abstand bei 35 von 35 Stimmen) zeigt, dass der Close-Abstand
 * dafuer kein Mass ist. Verglichen wird der EMPFANG - alle Validierungen inklusive der Signierer
 * ausserhalb der dUNL - weil die Zahl der dUNL-Stimmen teilweise aus der eigenen Zuordnung folgt
 * und kein Empfangsbefund ist. Live-Nachweis 2026-10-16: 103-107 Validierungen bei vollen 35
 * Mitgliedern gegen 53 bei dem Ledger, an dem nur 30 Mitglieder gesehen wurden. */
test("Erfassungs-Basis: duennerer Empfang ist gemessen, vor der Anlaufphase ist sie keine Zahl", () => {
  const tr = setup();
  const OUT = ["nFREMDE1", "nFREMDE2", "nFREMDE3"];
  const feed = (idx, voters, outsiders) => {
    tr.onLedger(ledger(T0 + idx, idx));
    for (const m of voters) tr.onValidation(val(m, idx));
    for (const k of outsiders) tr.onValidation({ signingKey: k, ledgerIndex: idx, ledgerHash: "H" + idx, full: true, t: T0 + idx + 1 });
    return tr.evaluate(T0 + idx + 500)[0];
  };
  let last = null;
  for (let i = 1; i <= 20; i++) last = feed(1000 + i, M, OUT);
  assert.equal(last.forensics.observedBaseline, null, "vor 20 bewerteten Ledgers gibt es keine eigene Basis");
  assert.equal(last.receptionThin, false, "ohne eigene Basis wird nichts behauptet");
  // 107695059 in Kleinform: der Ledger schliesst (Hash aus dem validierten Stream), aber es
  // kommen nur 16 von 35 Mitglieder-Stimmen an und ein einziger Signierer ausserhalb der dUNL.
  const thin = feed(1021, M.slice(0, 16), ["nFREMDE1"]);
  assert.equal(thin.closed, true, "bewiesen geschlossen - das Netz hatte sein Quorum");
  assert.equal(thin.forensics.votes, 16);
  assert.equal(thin.forensics.observedValidations, 17, "16 Mitglieder + 1 Fremd-Signierer: gemessen wird der Empfang");
  assert.equal(thin.forensics.observedBaseline, 38, "die Basis ist der eigene Empfangs-Median 35 + 3, nicht das Netz-Ziel");
  assert.equal(thin.receptionThin, true, "17 unter 75 Prozent des eigenen Niveaus 38 ist gemessen duenn");
  assert.equal(thin.forensics.margin, 16 - 28, "die Marge bleibt der Vergleich mit dem Netz-Ziel");
  const full = feed(1022, M, OUT);
  assert.equal(full.receptionThin, false, "voller Empfang ist kein Fehlstand");
  assert.equal(full.forensics.observedBaseline, 38, "17 in einem Ledger verschieben den Median nicht");
  const st = tr.stats();
  assert.equal(st.ownReceptionBaseline, 38, "die Basis ist ablesbar, nicht nur intern");
  assert.equal(st.receptionSamples, 22);
});
