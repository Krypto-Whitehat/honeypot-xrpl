// lib/validator-trace.test.mjs — Validator-Trace-Kern: Quorum, Incident-Typen, Korrelationen, Muster.
import test from "node:test";
import assert from "node:assert/strict";
import { addLoadSample, LOAD_BUCKETS, createTracker, classifyReasons, loadBucket, loadBucketLabel, reasonsFor, aggregatePatterns, TRACE_DEFAULTS,
  ledgerClosure, CLOSURE_BASES, CAPTURE_GAP_BASES, captureBound, CAPTURE_MEMBER_BASES, NEEDED_BASES } from "./validator-trace.mjs";

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
/* Warm-Lauf fuer die Zuordnungsgrenze: 'n' Ledger, in denen alle 35 Mitglieder abstimmen.
 * Erst damit existiert ein eigenes Abdeckungs-Niveau von 35, gegen das ein Ledger mit
 * fehlenden Mitgliedern geprueft werden kann. Ohne Warm-Lauf ist die Basis null und ein
 * fehlender Vote darf kein Knoten-Befund sein. */
function warm(tr, from, n) {
  for (let i = 0; i < n; i++) {
    const idx = from + i;
    tr.onLedger(ledger(0, idx));
    for (const m of M) tr.onValidation(val(m, idx));
    tr.evaluate(T0 + idx + 5_000);
  }
}

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

test("Zuordnung bei nachgewiesener Voll-Erfassung: 33 von 35 signieren, 2 fehlen -> 2 missed", () => {
  const tr = setup();
  warm(tr, 900, 20);
  const idx = 920;
  tr.onLedger(ledger(0, idx));
  for (const m of M.slice(0, 33)) tr.onValidation(val(m, idx));
  const [r] = tr.evaluate(T0 + idx + 10_000);
  assert.equal(tr.quorum, 28);
  assert.equal(r.hasQuorum, true);
  assert.equal(r.okCount, 33);
  assert.equal(r.forensics.membersSeen, 33);
  assert.equal(r.forensics.coverageBaseline, 35);
  assert.equal(r.forensics.genuineAbsentMaxLedger, 7, "35 - 28: mehr als 7 echte Nicht-Signierer erlaubt der Schliess-Beweis nicht");
  assert.equal(r.forensics.attributableAbsence, true, "33 >= 35 * 0,9 = 31,5 und 2 <= 7: die eigene Erfassung war vollstaendig");
  assert.equal(r.incidents.length, 2);
  assert.ok(r.incidents.every((i) => i.type === "missed"));
  assert.ok(r.incidents.every((i) => i.reasons.includes("no-correlated-cause")), "stille Ledger -> keine erfundene Ursache");
});

/* #107699168 live (2026-10-16): 28 von 35 Mitgliedern gesehen, 7 als 'missed' geflaggt, die
 * Netz-Referenz (api.xrpscan.com agreement_24h) sagt fuer jeden dieser Knoten 0 verpasste
 * Ledger von 19.473. Die Flagge war eine Erfassungs-Luecke. Genau das prueft dieser Fall. */
test("Kein Knoten-Befund bei eigener Abdeckungs-Luecke: 28 von 35 gesehen, 7 fehlen -> vote-not-observed", () => {
  const tr = setup();
  warm(tr, 940, 20);
  const idx = 960;
  tr.onLedger(ledger(0, idx));
  for (const m of M.slice(0, 28)) tr.onValidation(val(m, idx));
  const [r] = tr.evaluate(T0 + idx + 10_000);
  assert.equal(r.hasQuorum, true, "die eigene Stimmenzahl erreicht das Ziel - das ist kein Vollstaendigkeitsbeweis");
  assert.equal(r.forensics.membersSeen, 28);
  assert.equal(r.forensics.coverageBaseline, 35);
  assert.equal(r.forensics.attributableAbsence, false, "28 < 31,5: diese Erfassung hat 7 Mitglieder selbst nicht gesehen");
  assert.ok(r.incidents.every((i) => i.type === "vote-not-observed"), "kein fehlender Vote wird dem Knoten zugeschrieben");
  assert.ok(!r.incidents.some((i) => i.type === "missed"), "missed verlangt eine nachgewiesene Voll-Erfassung");
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

test("vote-not-observed: 10 von 28 Stimmen auf bewiesen geschlossenem Ledger -> Erfassungsbefund, kein Netz-Urteil", () => {
  const tr = setup();
  tr.onLedger(ledger(0, 103));
  for (const m of M.slice(0, 10)) tr.onValidation(val(m, 103));
  const [r] = tr.evaluate(T0 + 10_000_000);
  assert.equal(r.hasQuorum, false, "10 < 28: die Schwelle DIESER Aufzeichnung war nicht erreicht");
  assert.equal(r.closed, true, "der Stream liefert nur validierte Ledger - das Netz hat sein Quorum erreicht");
  assert.equal(r.incidents.length, 25, "35 - 10 = 25 Knoten ohne gesehenen Vote");
  assert.ok(r.incidents.every((i) => i.type === "vote-not-observed"), "auf geschlossenem Ledger ist Ausbleiben ein Erfassungsbefund, kein Netzwerkereignis");
  assert.ok(r.incidents[0].reasons.includes("vote-not-observed"));
  assert.ok(!r.incidents.some((i) => i.type === "no-quorum"), "no-quorum steht nicht auf einem bewiesen geschlossenen Ledger");
  assert.ok(!r.incidents.some((i) => i.type === "missed"), "missed bleibt den Ledgern mit eigener Quorum-Basis vorbehalten");
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
  warm(tr, 100, 20);
  tr.onLedger(ledger(0, 131));
  for (const m of M.slice(0, 32)) tr.onValidation(val(m, 131));
  tr.onValidation(val(M[32], 131, "FORK"));
  tr.onValidation(val(M[33], 131, "H131", false));
  const [r] = tr.evaluate(T0 + 10_000_000);
  const c = r.forensics.counts;
  assert.equal(r.forensics.membersSeen, 34, "32 auf der fuehrenden Linie + 1 eigene Linie + 1 unvollstaendig");
  assert.equal(r.forensics.attributableAbsence, true, "34 >= 31,5 und 1 fehlender Knoten <= 7");
  assert.equal(c.wrongHash, 1);
  assert.equal(c.partial, 1);
  assert.equal(c.missed, 1, "35 - 34 gesehene Mitglieder = 1 wirklicher Fehlender");
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
  assert.ok(r.incidents.every((i) => i.type === "vote-not-observed"), "geschlossener Ledger: kein Incident darf ein fehlendes Netz-Quorum behaupten");
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

/* close-gap und die Index-Folge dieses Recorders (2026-10-17): ein Abstand ist nur dann ein
 * Netz-Takt, wenn zwischen den zwei bewerteten Ledgern kein Index fehlt. Der live widerlegte Fall
 * 107694001 ist der Beweis: 70 000 ms Abstand bei 1 000 ms eigenem Takt, Index-Sprung ueber
 * 107694000 - das Netz selbst schloss 107694000 und 107694001 8 000 ms auseinander
 * (xrplcluster.com, api_version 2). Der Abstand erklaerte sich durch die eigene Erfassung. */
test("close-gap Guard: Abstand ueber die eigene Index-Luecke ist kein Netz-Takt", () => {
  const tags = classifyReasons({ hasQuorum: false, closed: true, txCount: 93, medianTx: 20, amendments: [], unlModify: false, novelTypes: [], closeGapMs: 70_000, medianGap: 1_000, indexGap: true });
  assert.ok(!tags.includes("close-gap"), "der Abstand enthaelt den uebersprungenen Ledger - kein Netz-Befund");
  assert.ok(tags.includes("vote-not-observed"), "die eigene Beobachtung bleibt stehen");
  assert.ok(!tags.includes("no-quorum"), "geschlossener Ledger: kein Tag darf ein fehlendes Netz-Quorum behaupten");
});
test("close-gap: derselbe Abstand bei durchgehender Index-Folge bleibt ein Netz-Takt", () => {
  const tags = classifyReasons({ hasQuorum: false, txCount: 93, medianTx: 20, amendments: [], unlModify: false, novelTypes: [], closeGapMs: 70_000, medianGap: 1_000, indexGap: false });
  assert.ok(tags.includes("close-gap"), "lueckenlose Index-Folge: die Taktung war wirklich langsam");
});
test("close-gap am Live-Fall 107694001: Index-Sprung -> kein close-gap an Ledger und Incident", () => {
  const tr = setup();
  for (let i = 0; i < 5; i += 1) {
    const idx = 107693995 + i;
    tr.onLedger({ ledgerIndex: idx, hash: "H" + idx, closeMs: 30_000_000 + i * 1000, txCount: 20 });
    for (const m of M) tr.onValidation(val(m, idx));
    tr.evaluate(30_000_000 + i * 1000);
  }
  tr.onLedger({ ledgerIndex: 107694001, hash: "20444972158736", closeMs: 30_074_000, txCount: 93 });
  const [r] = tr.evaluate(30_074_000 + TRACE_DEFAULTS.graceMs);
  assert.equal(r.closeGapMs, 70_000);
  assert.equal(r.medianGap, 1_000);
  assert.equal(r.captureGap, true, "107694000 fehlt samt seinen Validierungen");
  assert.ok(!r.ledgerTags.includes("close-gap"), "der Abstand ist die eigene Luecke, nicht das Netz");
  assert.ok(r.incidents.every((i) => !i.reasons.includes("close-gap")), "kein Incident darf daraus eine Netzstockung ableiten");
});
test("close-gap am Gegenfall: gleicher Abstand, Index lueckenlos -> die Taktung ist gemessen langsam", () => {
  const tr = setup();
  for (let i = 0; i < 5; i += 1) {
    const idx = 107693995 + i;
    tr.onLedger({ ledgerIndex: idx, hash: "H" + idx, closeMs: 30_000_000 + i * 1000, txCount: 20 });
    for (const m of M) tr.onValidation(val(m, idx));
    tr.evaluate(30_000_000 + i * 1000);
  }
  tr.onLedger({ ledgerIndex: 107694000, hash: "H107694000", closeMs: 30_074_000, txCount: 93 });
  for (const m of M.slice(0, 30)) tr.onValidation(val(m, 107694000));
  const [r] = tr.evaluate(30_074_000 + TRACE_DEFAULTS.graceMs);
  assert.equal(r.previousLedger, 107693999);
  assert.equal(r.captureGap, false, "107694000 = 107693999 + 1: nichts uebersprungen");
  assert.equal(r.closeGapMs, 70_000);
  assert.ok(r.ledgerTags.includes("close-gap"));
});
test("Takt-Basis: ein Abstand ueber die eigene Luecke verschiebt den Median nicht", () => {
  const tr = setup();
  for (let i = 0; i < 5; i += 1) {
    const idx = 107693995 + i;
    tr.onLedger({ ledgerIndex: idx, hash: "H" + idx, closeMs: 30_000_000 + i * 1000, txCount: 20 });
    for (const m of M) tr.onValidation(val(m, idx));
    tr.evaluate(30_000_000 + i * 1000);
  }
  tr.onLedger({ ledgerIndex: 107694001, hash: "H107694001", closeMs: 30_074_000, txCount: 20 });
  for (const m of M) tr.onValidation(val(m, 107694001));
  const [a] = tr.evaluate(30_074_000 + TRACE_DEFAULTS.graceMs);
  assert.equal(a.medianGap, 1_000);
  tr.onLedger({ ledgerIndex: 107694002, hash: "H107694002", closeMs: 30_075_000, txCount: 20 });
  for (const m of M) tr.onValidation(val(m, 107694002));
  const [b] = tr.evaluate(30_075_000 + TRACE_DEFAULTS.graceMs);
  assert.equal(b.previousLedger, 107694001);
  assert.equal(b.closeGapMs, 1_000);
  assert.equal(b.medianGap, 1_000, "der 70-s-Abstand ist nicht in die Takt-Basis geraten");
});

/* NACHRECHNUNG 2026-10-17: die drei von xrpscan.com UND xrplcluster.com verifiziert geschlossenen
 * Ledger duerfen an keiner Stelle als fehlendes Netz-Quorum erscheinen. Alle Zahlen von Hand:
 *   needed = ceil(35 * 0.8) = 28, genuineAbsentMax = 35 - 28 = 7,
 *   captureArtifactMin = absentCount - 7 = needed - top.
 *     107690236  top 20 -> absent 15, Artefakt mindestens 8   (28 - 20 = 8)
 *     107694001  top  0 -> absent 35, Artefakt mindestens 28  (28 -  0 = 28)
 *     107695059  top 16 -> absent 19, Artefakt mindestens 12  (28 - 16 = 12)
 * Schliessungs-Gegenpruefung (api.xrpscan.com/api/v1/ledger/<index>, deckungsgleich mit der
 * eigenen Forensik und von xrplcluster.com bestaetigt, Feld 'chVerifiedBy'):
 *     107690236 FB3ABE4A1AD20B851C507D04375BDE442D8F47635E0CE0B3A48BCC6AFB705962  27 Tx  1792135432
 *     107694001 20444972846C358C955033EBFDE16AC846EA28EBFCF7D6919D29F8232A158736  93 Tx  1792149950
 *     107695059 986E8D51A78E8B2CB53B0FDBAE613692C7D33E3C82DCEE20A2C22D5496B34602  52 Tx  1792154042
 * Die Zaehler unten sind dieselben, die in data/validator-trace/2026-10-16.json stehen. */
const AKKURATZ_LEDGER = [
  { idx: 107690236, top: 20, absent: 15, artifact: 8, closeMs: 1_792_135_432_000, tx: 27 },
  { idx: 107694001, top: 0, absent: 35, artifact: 28, closeMs: 1_792_149_950_000, tx: 93 },
  { idx: 107695059, top: 16, absent: 19, artifact: 12, closeMs: 1_792_154_042_000, tx: 52 },
];

test("Akkuratz-Nachrechnung: geschlossene Ledger bekommen nirgends den Namen no-quorum", () => {
  for (const c of AKKURATZ_LEDGER) {
    const tr = setup();
    tr.onLedger({ ledgerIndex: c.idx, hash: "H" + c.idx, closeMs: c.closeMs, txCount: c.tx });
    for (const m of M.slice(0, c.top)) tr.onValidation(val(m, c.idx));
    const [r] = tr.evaluate(c.closeMs + TRACE_DEFAULTS.graceMs);
    assert.equal(r.closed, true, "#" + c.idx + " kommt aus dem validierten Stream - Schliessung bewiesen");
    assert.equal(r.closedHash, "H" + c.idx, "#" + c.idx + ": der Hash des Netzes, nicht die eigene Mehrheit");
    assert.equal(r.hasQuorum, false, "#" + c.idx + ": die eigene Basis blieb unter 28");
    assert.equal(r.incidents.length, c.absent, "#" + c.idx + ": 35 - " + c.top + " = " + c.absent);
    assert.equal(r.forensics.counts.noQuorum, c.absent, "#" + c.idx + ": derselbe Zaehler wie die Tagesdatei");
    assert.equal(r.forensics.counts.missed, 0, "#" + c.idx + ": ohne eigene Quorum-Basis kein Knotenbefund");
    assert.ok(r.incidents.every((i) => i.type === "vote-not-observed"), "#" + c.idx + ": kein Incident darf ein fehlendes Netz-Quorum behaupten");
    assert.ok(!r.ledgerTags.includes("no-quorum"), "#" + c.idx + ": der Ledger-Tag behauptet kein fehlendes Netz-Quorum");
    assert.ok(r.ledgerTags.includes("vote-not-observed"), "#" + c.idx + ": der Tag nennt die eigene Erfassung");
    assert.ok(r.incidents.every((i) => i.reasons.includes("vote-not-observed")), "#" + c.idx + ": Incident und Ledger sagen dasselbe");
  }
});

test("Akkuratz-Nachrechnung: genuineAbsentMax 7 und captureArtifactMin = 28 - top, in allen drei Faellen", () => {
  for (const c of AKKURATZ_LEDGER) {
    const b = captureBound({ l: c.idx, cl: true, ch: "H" + c.idx, v: c.top, top: c.top, need: 28, mg: c.top - 28,
      c: { missed: 0, partial: 0, wrongHash: 0, noQuorum: c.absent } });
    assert.equal(b.members, 35, "#" + c.idx + ": " + c.top + " gesehen + " + c.absent + " geflaggt = 35 Mitglieder");
    assert.equal(b.genuineAbsentMax, 7, "#" + c.idx + ": 35 - 28 = 7, mehr echte Nicht-Signierer traegt die Schliessung nicht");
    assert.equal(b.captureArtifactMin, c.artifact, "#" + c.idx + ": " + c.absent + " - 7 = " + c.artifact + " = 28 - " + c.top);
    assert.equal(b.captureComplete, false, "#" + c.idx + ": " + c.top + " < 28, ein Einzelbefund ist hier nicht belegen");
  }
});

test("no-quorum bleibt dem Fall vorbehalten, dessen Schliessung nicht belegt ist", () => {
  const tr = setup();
  tr.onLedger({ ledgerIndex: 108000001, closeMs: 5_000_000_000, txCount: 10 });
  for (const m of M.slice(0, 10)) tr.onValidation(val(m, 108000001));
  const [r] = tr.evaluate(5_000_000_000 + TRACE_DEFAULTS.graceMs);
  assert.equal(r.closed, false, "ohne Schliessungs-Hash ist die Schliessung nicht belegt");
  assert.equal(r.closedHash, null);
  assert.ok(r.incidents.every((i) => i.type === "no-quorum"), "hier - und nur hier - steht no-quorum");
  assert.ok(r.ledgerTags.includes("no-quorum"));
  assert.ok(!r.ledgerTags.includes("vote-not-observed"), "ohne Schliessungsbeleg wird keine Schliessung unterstellt");
});

test("reasonsFor: vote-not-observed ohne Korrelation bleibt nicht ohne Befund", () => {
  assert.deepEqual(reasonsFor("vote-not-observed", []), ["no-correlated-cause"]);
  assert.deepEqual(reasonsFor("vote-not-observed", ["load-spike"]), ["load-spike"]);
});

/* Das Quorum-Ziel war bisher eine Rechnung: ceil(dUNL * 0,8). Gemessen wird der Wert des
 * Endpunkts (server_info -> validations.quorum) schon lange, aber er erreichte die Bewertung
 * nie. Am 2026-10-17 live nachgeprueft: vl.ripple.com nennt 35 Manifeste (Sequenz 85),
 * s1.ripple.com und s2.ripple.com melden validation_quorum 28, xrplcluster.com meldet 0.
 * 28 ist hier also gemessen, nicht gerechnet - und die Herkunft muss an der Zahl stehen. */
test("Quorum-Ziel: der gemeldete Netz-Wert ersetzt die Rechnung, und die Herkunft ist benannt", () => {
  const tr = setup();
  assert.equal(tr.quorumBasis, "derived", "ohne Messung ist das Ziel eine Herleitung, keine Messung");
  assert.equal(tr.quorum, 28, "ceil(35 * 0,8) = 28");
  assert.deepEqual(tr.setNetworkQuorum(28), { quorum: 28, basis: "measured", changed: true });
  assert.equal(tr.quorumBasis, "measured", "gemeldeter Zielwert muss als Messung ausgewiesen werden");
  // Ein gemessener Wert, der von der Rechnung abweicht, darf nicht gegen die Rechnung verlieren.
  assert.deepEqual(tr.setNetworkQuorum(24), { quorum: 24, basis: "measured", changed: true });
  assert.equal(tr.quorum, 24, "das Netz verlangt 24 - die eigene Rechnung ist nicht das Netz");
  tr.onLedger(ledger(0, 150));
  for (const m of M.slice(0, 24)) tr.onValidation(val(m, 150));
  const [r] = tr.evaluate(T0 + 10_000_000);
  assert.equal(r.forensics.needed, 24, "die Bewertung muss mit dem gemessenen Ziel rechnen");
  assert.equal(r.forensics.margin, 0, "24 gesehen - 24 verlangt = 0");
  assert.equal(r.forensics.neededBasis, "measured", "die Forensik muss ihre Ziel-Herkunft mitfuehren");
  assert.equal(r.forensics.networkQuorum, 24, "der gemessene Netz-Wert ist in der Forensik nachlesbar");
  // Ein Endpunkt ohne Wert (xrplcluster.com meldet 0) ist fehlend, nicht null: die Herleitung
  // bleibt stehen, statt dass ein Ziel von 0 jedes Ledger erfuellt.
  assert.deepEqual(tr.setNetworkQuorum(0), { quorum: 24, basis: "measured", changed: false });
  assert.deepEqual(tr.setNetworkQuorum(null), { quorum: 24, basis: "measured", changed: false });
  tr.setMembers(M, E);
  assert.equal(tr.quorumBasis, "measured", "ein dUNL-Nachzug darf eine Messung nicht in eine Rechnung zurueckverwandeln");
});

test("captureBound: die Herleitung des Ziels ist Teil der Grenze", () => {
  const base = { l: 107695059, cl: true, ch: "986E8D51", v: 16, top: 16, need: 28, mg: -12, mm: 35,
    c: { missed: 0, partial: 0, wrongHash: 0, noQuorum: 19 } };
  const measured = captureBound({ ...base, nb: "measured", nq: 28 });
  assert.equal(measured.neededBasis, "measured", "gemessenes Ziel muss als solches dastehen");
  assert.equal(measured.networkQuorum, 28, "der gemessene Netz-Wert ist nachlesbar");
  assert.equal(measured.genuineAbsentMax, 7, "35 - 28 = 7 echte Nicht-Signierer hoechstens");
  assert.equal(measured.captureArtifactMin, 12, "19 - 7 = 12 mindestens Erfassungs-Luecke");
  const derived = captureBound({ ...base, nb: "derived" });
  assert.equal(derived.neededBasis, "derived", "gerechnetes Ziel ist als Rechnung zu benennen");
  assert.equal(derived.networkQuorum, null, "ohne Messung steht keine Messung da");
  // Altbestand: nb fehlt. Das ist 'nicht erfasst', nicht 'derived' - die Rechnung ist dort
  // nie aufgezeichnet worden und laesst sich nachtraeglich nicht belegen.
  const old = captureBound(base);
  assert.equal(old.neededBasis, "not-recorded", "fehlende Herleitung darf nicht als Herleitung erscheinen");
  assert.deepEqual([...NEEDED_BASES], ["measured", "derived", "not-recorded"], "die Zustands-Menge ist die einzige, die die UI zeigen darf");
});
/* Warm-Lauf (2026-10-17, gemessen an xrplcluster.com und s1.ripple.com): der erste Ledger nach
 * einem Abo brachte 19 bis 21 von rund 107 Validierungen und 31 von 35 dUNL-Mitgliedern. Die
 * Stimmen vor dem Abo sind nie angekommen - also ist diese Zeile eine gemessene Erfassungs-
 * Luecke dieses Recorders, nicht duenner Netzempfang. */
test("Warm-Lauf: der erste Ledger nach einem Abo ist eine erfasste Erfassungs-Luecke", () => {
  const t = setup();
  t.markStreamOpen();
  t.onLedger({ ledgerIndex: 107707538, hash: "AAAA", closeMs: T0, txCount: 10 });
  for (const m of M.slice(0, 21)) t.onValidation({ signingKey: SIGN(m), ledgerIndex: 107707538, ledgerHash: "AAAA", full: true, t: T0 + 100 });
  t.onLedger({ ledgerIndex: 107707539, hash: "BBBB", closeMs: T0 + 1000, txCount: 12 });
  for (const m of M) t.onValidation({ signingKey: SIGN(m), ledgerIndex: 107707539, ledgerHash: "BBBB", full: true, t: T0 + 1100 });
  const out = t.evaluate(T0 + 60000);
  assert.equal(out.length, 2);
  assert.equal(out[0].forensics.streamOpenCapture, true, "107707538 war der erste Ledger nach dem Abo");
  assert.equal(out[0].forensics.captureGap, true, "die Luecke wird nicht als duenner Empfang verbucht");
  assert.equal(out[1].forensics.streamOpenCapture, false, "ab dem zweiten Ledger wird der volle Lauf gehoert");
  assert.equal(out[1].forensics.captureGap, false);
});

test("Erfassungs-Basis stream-open: Warm-Lauf ist Beleg, keine Schaetzung", () => {
  const warm = ledgerClosure({ cl: true, l: 107707538, so: true });
  assert.equal(warm.captureGap, true);
  assert.equal(warm.captureGapBasis, "stream-open");
  assert.ok(CAPTURE_GAP_BASES.includes(warm.captureGapBasis), "Basis ausserhalb der erlaubten Menge");
  const clean = ledgerClosure({ cl: true, l: 107707539, pg: 107707538 });
  assert.equal(clean.captureGap, false, "Index-Folge ohne Sprung und ohne Warm-Lauf: keine Luecke belegt");
  assert.equal(clean.captureGapBasis, "ledger-index");
  const b = captureBound({ l: 107707538, cl: true, ch: "AAAA", v: 21, top: 21, need: 28, mg: -7, mm: 35, so: true,
    c: { missed: 0, partial: 0, wrongHash: 0, noQuorum: 14 } });
  assert.equal(b.closure.captureGapBasis, "stream-open");
  assert.equal(b.genuineAbsentMax, 7);
  assert.equal(b.captureArtifactMin, 7, "14 Flags - 7 moegliche = 7 nachweisbare Erfassungs-Artefakte");
});

/* "16 / 28" ohne Herleitung war eine Zahl ohne Herkunft. Wo die Zeile ihre dUNL-Groesse selbst
 * traegt, ist das Ziel aus ihr nachrechenbar - neededMatches prueft genau das, es ersetzt aber
 * nicht die fehlende Herleitung. */
test("Ziel-Nachrechnung: das aufgezeichnete Ziel wird gegen die eigene dUNL-Groesse geprueft", () => {
  const ok = captureBound({ l: 107695059, cl: true, ch: "986E8D51", v: 16, top: 16, need: 28, mg: -12, mm: 35,
    c: { missed: 0, partial: 0, wrongHash: 0, noQuorum: 19 } });
  assert.equal(ok.neededDerived, 28, "ceil(35 * 0.8) = 28");
  assert.equal(ok.neededMatches, true, "das aufgezeichnete Ziel ist genau diese Ableitung");
  assert.equal(ok.neededBasis, "not-recorded", "die Nachrechnung ersetzt die fehlende Herleitung nicht");
  const off = captureBound({ l: 1, cl: true, ch: "H", v: 16, top: 16, need: 30, mg: -14, mm: 35, c: { noQuorum: 19 } });
  assert.equal(off.neededDerived, 28);
  assert.equal(off.neededMatches, false, "30 ist nicht ceil(35 * 0.8)");
  const measured = captureBound({ l: 2, cl: true, ch: "H", v: 30, top: 30, need: 22, mg: 8, mm: 35, nb: "measured", nq: 22,
    c: { missed: 5, partial: 0, wrongHash: 0, noQuorum: 0 } });
  assert.equal(measured.neededMatches, false, "ein gemessenes Ziel wird nicht als Ableitung ausgegeben");
  assert.equal(measured.neededBasis, "measured");
});
/* Die Leseschicht darf die Zuordnung nur aus den Feldern der Zeile selbst lesen: ms/cb/gm/aa
 * sind in der Tagesdatei gespeichert, alles andere waere eine Nachrechnung ohne Beleg. */
test("captureBound: die Zuordnung eines fehlenden Votes kommt aus den Feldern der Zeile", () => {
  const full = captureBound({ l: 107699168, cl: true, ch: "59F271F8", v: 28, top: 28, need: 28, mg: 0,
    mm: 35, nb: "measured", nq: 28, ms: 34, cb: 35, gm: 7, aa: true,
    c: { missed: 1, partial: 0, wrongHash: 0, noQuorum: 0 } });
  assert.equal(full.membersSeen, 34);
  assert.equal(full.coverageBaseline, 35);
  assert.equal(full.genuineAbsentMaxLedger, 7);
  assert.equal(full.attributableAbsence, true, "die Zeile traegt ihren eigenen Vollstaendigkeitsbeleg");
  const thin = captureBound({ l: 107699168, cl: true, ch: "59F271F8", v: 28, top: 28, need: 28, mg: 0,
    mm: 35, nb: "measured", nq: 28, ms: 28, cb: 35, gm: 7, aa: false,
    c: { missed: 0, partial: 0, wrongHash: 0, noQuorum: 7 } });
  assert.equal(thin.attributableAbsence, false, "28 von 35 bei Basis 35: diese Erfassung war unvollstaendig");
  assert.equal(thin.absentCount, 7);
  const old = captureBound({ l: 107699168, cl: true, ch: "59F271F8", v: 28, top: 28, need: 28, mg: 0,
    mm: 35, c: { missed: 7, partial: 0, wrongHash: 0, noQuorum: 0 } });
  assert.equal(old.attributableAbsence, null, "aeltere Zeile ohne ms/cb/aa: die Zuordnung bleibt offen");
  assert.equal(old.membersSeen, null, "keine erfundene Abdeckung");
});
