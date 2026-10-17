import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import assert from "node:assert/strict";
import { fileURLToPath } from "node:url";
import { absencesOf, closureBound, cohortTruth, cohortVerdict, compareAbsences, groundScan, groundWindow, groundWindows, groupAbsences, inWindow, referenceWindow, summarizeTruth, TRUTH_VERDICTS } from "./validator-truth.mjs";

const here = path.dirname(fileURLToPath(import.meta.url));
const read = (rel) => fs.readFileSync(path.join(here, rel), "utf8");

const HOUR = 3600000;
const AS_OF = 1792160000000;
const scan = (missed, total, extra = {}) => ({ missed, total, score: "1.00000", incomplete: false, asOfMs: AS_OF, ...extra });
const claims = (n, { type = "no-quorum", master = "nHBWa56" } = {}) =>
  Array.from({ length: n }, (_, i) => ({ master, ledgerIndex: 107690000 + i, timeMs: AS_OF - (i + 1) * HOUR, type }));

test("Grenze der Schliessung: auf einem geschlossenen Ledger kann hoechstens members - needed echt fehlen", () => {
  const b = closureBound({ members: 35, needed: 28 });
  assert.deepEqual(b, { members: 35, needed: 28, genuineAbsentMax: 7 });
  assert.equal(closureBound({ members: 35, needed: null }), null, "ohne Ziel keine Grenze");
  assert.equal(closureBound({ members: 0, needed: 28 }), null, "ohne Knoten keine Grenze");
});

test("Abwesenheit ist nicht dasselbe wie Abweichung: partial und wrong-hash zaehlen nicht", () => {
  const list = [
    { m: "A", l: 1, t: AS_OF, type: "missed" },
    { m: "A", l: 2, t: AS_OF, type: "no-quorum" },
    { m: "A", l: 3, t: AS_OF, type: "partial" },
    { m: "A", l: 4, t: AS_OF, type: "wrong-hash" },
    { m: "B", l: 5, t: AS_OF, type: "missed" },
  ];
  const a = absencesOf(list, "A");
  assert.equal(a.length, 2);
  assert.deepEqual(a.map((x) => x.type), ["missed", "no-quorum"]);
  assert.equal(absencesOf(list, "B").length, 1);
  assert.equal(absencesOf(null, "A").length, 0);
});

test("Referenz ohne Fensterzeit ist keine Gegenprobe: not-comparable, nie eine Entlastung", () => {
  const r = compareAbsences({ master: "A", claims: claims(7), scan: scan(0, 19472, { asOfMs: null }) });
  assert.equal(r.verdict, "not-comparable");
  assert.equal(r.reason, "reference-has-no-window-time");
  assert.equal(r.falsePositiveMin, null, "ohne Vergleich keine Zahl");
});

test("Unvollstaendiges Referenzfenster und eine Zahl ohne Nenner bleiben unvergleichbar", () => {
  const a = compareAbsences({ master: "A", claims: claims(7), scan: scan(0, 19472, { incomplete: true }) });
  assert.equal(a.verdict, "not-comparable");
  assert.equal(a.reason, "reference-window-incomplete");
  const b = compareAbsences({ master: "A", claims: claims(7), scan: scan(4, 0) });
  assert.equal(b.verdict, "not-comparable");
  assert.equal(b.reason, "reference-has-no-count");
});

test("Die scharfste Form: Referenz sagt 'dieser Knoten hat nichts verpasst', die Erfassung sagt sieben", () => {
  const r = compareAbsences({ master: "A", claims: claims(7), scan: scan(0, 19472) });
  assert.equal(r.verdict, "contradicted");
  assert.equal(r.claims, 7);
  assert.equal(r.groundMissed, 0);
  assert.equal(r.falsePositiveMin, 7, "alle sieben muessen auf die eigene Erfassung gehen");
  assert.equal(r.reason, "reference-says-this-node-missed-nothing-in-window");
});

test("Weichere Form: die Differenz ist die nachrechenbare Untergrenze, nicht die ganze Liste", () => {
  const r = compareAbsences({ master: "A", claims: claims(19), scan: scan(12, 19472) });
  assert.equal(r.verdict, "contradicted");
  assert.equal(r.falsePositiveMin, 7);
  assert.equal(r.reason, "own-absences-exceed-reference-misses");
});

test("Innerhalb der Referenzzahl steht kein Widerspruch - die einzelne Ledger-Zuordnung bleibt offen", () => {
  const r = compareAbsences({ master: "A", claims: claims(3), scan: scan(12, 19472) });
  assert.equal(r.verdict, "consistent");
  assert.equal(r.falsePositiveMin, 0);
  assert.equal(r.ledgerIdentity, "not-resolvable-from-aggregate");
});

test("Keine eigene Abwesenheit im Fenster ist kein Erfolg: consistent mit Begruendung", () => {
  const r = compareAbsences({ master: "A", claims: [], scan: scan(12, 19472) });
  assert.equal(r.verdict, "consistent");
  assert.equal(r.reason, "no-absence-recorded-in-window");
});

test("Fenster werden nicht vergroebert: eine Tages-Referenz deckt nur einen Tag der eigenen Sieben-Tage-Frage ab", () => {
  const own = [
    ...claims(3),
    { master: "A", ledgerIndex: 999, timeMs: AS_OF - 5 * 24 * HOUR, type: "missed" },
  ];
  const r = compareAbsences({ master: "A", claims: own, scan: scan(2, 19472), rangeHours: 168, hours: 24 });
  assert.equal(r.claims, 3, "der Claim vor fuenf Tagen liegt ausserhalb der Referenz");
  assert.equal(r.claimsOutside, 1);
  assert.equal(r.window.hours, 24);
  assert.equal(r.verdict, "contradicted", "drei eigene Abwesenheiten gegen zwei der Referenz: einer ist belegt keiner");
  assert.equal(r.falsePositiveMin, 1);
});

test("inWindow und groundWindow: die Fensterzeit kommt aus der Referenz, nicht aus dem eigenen Buch", () => {
  const w = groundWindow(scan(1, 10), 1);
  assert.deepEqual(w, { from: AS_OF - HOUR, to: AS_OF, hours: 1 });
  assert.equal(groundWindow(scan(1, 10), 5), null, "ein Fenster ohne Definition wird nicht erfunden");
  assert.equal(inWindow([{ timeMs: AS_OF - 2 * HOUR }], w).length, 0);
  assert.equal(inWindow([{ timeMs: AS_OF - 1000 }], w).length, 1);
});

test("Betriebssumme: widerlegte Knoten, Behauptungen und die offene Luecke stehen getrennt", () => {
  const results = [
    compareAbsences({ master: "A", claims: claims(7), scan: scan(0, 19472) }),
    compareAbsences({ master: "B", claims: claims(2), scan: scan(9, 19472) }),
    compareAbsences({ master: "C", claims: claims(4), scan: scan(1, 100, { asOfMs: null }) }),
  ];
  const s = summarizeTruth(results);
  assert.equal(s.nodes, 3);
  assert.equal(s.contradictedNodes, 1);
  assert.equal(s.consistentNodes, 1);
  assert.equal(s.notComparableNodes, 1);
  assert.equal(s.claims, 9, "ohne Fensterzeit werden die vier Claims dieses Knotens nicht gezaehlt");
  assert.equal(s.falsePositiveMin, 7);
  assert.equal(s.groundMissed, 10);
  assert.equal(s.groundTotal, 39044);
  assert.equal(summarizeTruth([]).nodes, 0);
  assert.equal(summarizeTruth([{ verdict: "erfunden" }]).nodes, 0, "ein unbekannter Status wird nicht gezaehlt");
});

test("Status-Vokabular ist abgeschlossen: nur die drei zustaende sind erlaubt", () => {
  assert.deepEqual([...TRUTH_VERDICTS].sort(), ["consistent", "contradicted", "not-comparable"]);
});

// Die Kohorte ist die Stelle, an der die Engine Knoten benennt. Ein Name ohne Gegenurteil ist
// eine Beschuldigung - diese Tests halten das Gegenurteil je Knoten und die Bilanz dazu fest.
test("Kohorten-Gruppierung: Abwesenheiten werden je Knoten gesammelt, Abweichungen nicht", () => {
  const list = [
    { m: "A", l: 10, t: AS_OF, type: "no-quorum" },
    { m: "A", l: 11, t: AS_OF - HOUR, type: "missed" },
    { m: "A", l: 12, t: AS_OF - HOUR, type: "partial" },
    { m: "B", l: 13, t: AS_OF - HOUR, type: "missed" },
    { m: "C", l: 14, type: "missed" },
    { l: 15, t: AS_OF, type: "missed" },
  ];
  const g = groupAbsences(list);
  assert.deepEqual([...g.keys()], ["A", "B"], "ohne Master-Key und ohne Zeit gibt es keine Zuordnung");
  assert.equal(g.get("A").length, 2, "partial ist keine Abwesenheit");
  assert.deepEqual(g.get("A")[0], { master: "A", ledgerIndex: 10, timeMs: AS_OF, type: "no-quorum" });
  assert.equal(groupAbsences(null).size, 0);
});

test("Kohorten-Gegenprobe: jeder benannte Knoten bekommt sein eigenes Urteil", () => {
  const rows = [
    { ledgerIndex: 107695059, affectedMasters: ["A", "B", "C"] },
    { ledgerIndex: 107694001, affectedMasters: ["A", "D"] },
  ];
  const incidents = [...claims(8, { master: "A" }), ...claims(6, { master: "B" }), ...claims(4, { master: "D" })];
  const ground = new Map([["A", scan(0, 19472)], ["B", scan(9, 19472)], ["D", scan(2, 19472)]]);
  const { summary, byMaster } = cohortTruth({ rows, incidents, groundByMaster: ground });
  assert.equal(summary.ledgers, 2);
  assert.equal(summary.nodes, 4, "A wird ueber zwei Ledger nur einmal gerechnet");
  assert.equal(summary.contradicted, 2, "A und D stehen ueber der Referenz");
  assert.equal(summary.consistent, 1, "B bleibt innerhalb der Referenz");
  assert.equal(summary.notComparable, 1, "C hat keine Referenz - offen, nicht gedeckt");
  assert.equal(summary.withoutReference, 1);
  assert.equal(summary.claims, 18, "8 + 6 + 4 eigene Abwesenheiten in diesem Fenster");
  assert.equal(summary.falsePositiveMin, 10, "(8 - 0) + (4 - 2) sind nachrechenbar, B traegt nichts bei");
  assert.equal(byMaster.get("A").verdict, "contradicted");
  assert.equal(byMaster.get("A").falsePositiveMin, 8);
  assert.equal(byMaster.get("C").reason, "reference-has-no-window-time");
});

test("Kohorten-Zuordnung: die Urteile stehen indexgleich an der Knotenliste der Zeile", () => {
  const rows = [{ ledgerIndex: 1, affectedMasters: ["A", "B"] }, { ledgerIndex: 2, affectedMasters: [] }];
  const { byMaster } = cohortTruth({ rows, incidents: claims(3, { master: "A" }), groundByMaster: new Map([["A", scan(0, 100)]]) });
  const aligned = rows.map((r) => (r.affectedMasters ?? []).map((m) => byMaster.get(m) ?? null));
  assert.deepEqual(aligned.map((r) => r.map((x) => x && x.verdict)), [["contradicted", "not-comparable"], []]);
  assert.equal(cohortTruth({ rows: [], incidents: [], groundByMaster: null }).summary.nodes, 0);
});

test("Fensterlage ist kein Freispruch: Abwesenheiten ausserhalb der Referenz bleiben offen", () => {
  const outside = Array.from({ length: 5 }, (_, i) => ({ master: "A", ledgerIndex: 1 + i, timeMs: AS_OF - (60 + i) * HOUR, type: "no-quorum" }));
  const tr = compareAbsences({ master: "A", claims: outside, scan: scan(0, 19472), rangeHours: 24, hours: 24 });
  assert.equal(tr.claims, 0);
  assert.equal(tr.claimsOutside, 5);
  assert.equal(tr.verdict, "consistent", "die Gegenprobe selbst sagt: in diesem Fenster nichts");
  const v = cohortVerdict(tr);
  assert.equal(v.verdict, "not-comparable", "in der Kohorte waer consistent ein Freispruch, den das Fenster nicht hergibt");
  assert.equal(v.reason, "claims-outside-reference-window");
  assert.deepEqual(cohortVerdict(null), { verdict: "not-comparable", reason: "reference-unavailable" });
  const none = compareAbsences({ master: "A", claims: [], scan: scan(0, 19472), rangeHours: 24, hours: 24 });
  assert.equal(cohortVerdict(none).verdict, "consistent", "ueberhaupt keine Meldung bleibt consistent");
});

test("Fensterwahl: die eigene Spanne bestimmt das Referenzfenster, nie weiter als noetig", () => {
  // Zurueckkommt der Fenster-Schluessel (1 h / 24 h / 30 d), nicht die Stundenzahl dahinter.
  assert.equal(referenceWindow(1), 1);
  assert.equal(referenceWindow(2), 24, "zwei Stunden brauchen das Tagesfenster - es gibt kein 2-h-Fenster");
  assert.equal(referenceWindow(24), 24);
  assert.equal(referenceWindow(168), 30, "die Sieben-Tage-Frage braucht das 30-Tage-Fenster");
  assert.equal(referenceWindow(720), 30);
  assert.equal(referenceWindow(Infinity), 30, "range=all nimmt das groesste vorhandene Fenster");
  assert.equal(referenceWindow(null), 30, "ohne Spanne wird nicht geraten");
  assert.equal(referenceWindow(0), 30);
});

test("Fenster-Karte: reduziert auf das gewaehlte Fenster; ein fehlendes Fenster ist keine Nullzahl", () => {
  const entry = { asOfMs: AS_OF, windows: {
    1: { missed: 0, total: 812, score: "1.00000", incomplete: false },
    30: { missed: 4, total: 58000, score: "0.99993", incomplete: false },
  } };
  assert.deepEqual(groundScan(entry, 1), { missed: 0, total: 812, score: "1.00000", incomplete: false, asOfMs: AS_OF,
    windowId: 1, coverage: "full", coveredHours: 1, openHours: 0 });
  assert.equal(groundScan(entry, 720), null, "eine Stundenzahl ist kein Fenster-Schluessel");
  assert.equal(groundScan(scan(0, 19472), 30), null, "die flache Tageszahl duerfen 30 Tage nicht beanspruchen");
  assert.deepEqual(groundScan(scan(0, 19472), 24), { missed: 0, total: 19472, score: "1.00000", incomplete: false, asOfMs: AS_OF,
    windowId: 24, coverage: "full", coveredHours: 24, openHours: 0 }, "die flache Eingabe bleibt gueltig");
  assert.equal(groundScan(null, 24), null);
  const peers = groundWindows(new Map([["A", entry], ["B", null]]), 30);
  assert.deepEqual([...peers.keys()], ["A"], "ein Knoten ohne Auskunft ist nicht ploetzlich ein Knoten mit Zahl");
  assert.deepEqual(peers.get("A"), { missed: 4, total: 58000, score: "0.99993", incomplete: false, asOfMs: AS_OF,
    windowId: 30, coverage: "full", coveredHours: 720, openHours: 0 });
  assert.deepEqual([...groundWindows(new Map([["A", entry]]), 24).keys()], [], "ein Fenster, das die Auskunft nicht liefert, deckt die Tagesfrage nicht");
  assert.equal(groundWindows(null, 24), null);
});

test("Unvollstaendiges Referenzfenster: die groesste vollstaendige Auskunft traegt die Gegenprobe", () => {
  // Gemessen am 2026-10-17 an api.xrpscan.com/api/v1/validators: agreement30d.incomplete ist
  // bei allen 35 beobachteten Knoten true, agreement1h und agreement24h vollstaendig. Bisher
  // blieb deshalb die 30-Tage-Gegenprobe fuer jeden Knoten bei not-comparable - die Auskunft
  // hatte eine Zahl, und die Engine durfte sie nicht benutzen, weil sie die Spanne nicht
  // abdeckt. Jetzt traegt die vollstaendige Tageszahl die Gegenprobe, und die Spanne ausserhalb
  // bleibt als offene Restspanne ausgewiesen (openHours), nicht als Antwort.
  const entry = { asOfMs: AS_OF, windows: {
    1: { missed: 0, total: 812, score: "1.00000", incomplete: false },
    24: { missed: 0, total: 20404, score: "1.00000", incomplete: false },
    30: { missed: 92061, total: 583259, score: "0.84216", incomplete: true },
  } };
  const sel = groundScan(entry, 30);
  assert.equal(sel.windowId, 24, "ein unvollstaendiges Fenster darf keine Gegenprobe tragen");
  assert.equal(sel.coverage, "partial", "die Teildeckung ist ausgewiesen, nicht unterschieben");
  assert.equal(sel.coveredHours, 24);
  assert.equal(sel.openHours, 696, "720 h Frage minus 24 h Antwort = 696 h offen");
  const claims = Array.from({ length: 5 }, (_, i) => ({ master: "A", ledgerIndex: 1 + i, timeMs: AS_OF - (i + 1) * HOUR, type: "no-quorum" }));
  const out = compareAbsences({ master: "A", claims, scan: sel, rangeHours: 720, hours: 30 });
  assert.equal(out.window.hours, 24, "gerechnet wird das Fenster der Auskunft, nicht das zuerst gewaehlte");
  assert.equal(out.claims, 5);
  assert.equal(out.verdict, "contradicted", "5 eigene Abwesenheiten gegen 0 von 20404 referenziell verpassten Ledgern");
  assert.equal(out.falsePositiveMin, 5, "die Untergrenze der Erfassungs-Luecke ist nachrechenbar");
  assert.equal(out.coverage, "partial");
  assert.equal(out.openHours, 696);
  const allBad = { asOfMs: AS_OF, windows: {
    1: { missed: 0, total: 900, incomplete: true },
    24: { missed: 1, total: 20000, incomplete: true },
    30: { missed: 9, total: 500000, incomplete: true },
  } };
  const none = groundScan(allBad, 30);
  assert.equal(none.coverage, "unusable");
  assert.equal(none.windowId, 30, "ohne Alternative bleibt das gewaehlte Fenster - erfunden wird nichts");
  assert.equal(compareAbsences({ master: "A", claims, scan: none, rangeHours: 720, hours: 30 }).verdict,
    "not-comparable", "keine vollstaendige Auskunft ist offen, nicht entlastet");
});

test("Dasselbe Buch, anderes Fenster: die 30-Tage-Frage wird gegen die 30-Tage-Zahl gerechnet", () => {
  const entry = { asOfMs: AS_OF, windows: {
    1: { missed: 0, total: 812, score: "1.00000", incomplete: false },
    30: { missed: 40, total: 58000, score: "0.99931", incomplete: false },
  } };
  const claims30 = Array.from({ length: 30 }, (_, i) => ({ master: "A", ledgerIndex: 1 + i, timeMs: AS_OF - (i * 24 + 1) * HOUR, type: "no-quorum" }));
  const wide = compareAbsences({ master: "A", claims: claims30, scan: groundScan(entry, 30), rangeHours: 720, hours: 30 });
  assert.equal(wide.claims, 30);
  assert.equal(wide.window.hours, 720);
  assert.equal(wide.verdict, "consistent", "30 eigene Abwesenheiten gegen 40 referenzielle Verpasste ist kein Widerspruch");
  const narrow = compareAbsences({ master: "A", claims: claims30, scan: groundScan(entry, 1), rangeHours: 720, hours: 1 });
  assert.equal(narrow.claims, 1, "das Stundenfenster deckt nur eine der 30 Meldungen");
  assert.equal(narrow.claimsOutside, 29, "der Rest ist offen, nicht gedeckt");
});

test("Paritaet: beide Einstiegspunkte urteilen mit derselben Gegenprobe, nicht nur der lokale Server", () => {
  const server = read("../server/index.mjs");
  const stats = read("../api/stats.js");
  for (const [name, src] of [["server/index.mjs", server], ["api/stats.js", stats]]) {
    assert.match(src, /from "\.\.\/lib\/validator-ground\.mjs"/, name + ": holt die Netz-Referenz nicht aus der gemeinsamen Quelle");
    assert.match(src, /traceForValidator\(\s*days,\s*\w+,\s*\{[^}]*\bgroundPeers:/, name + ": die Kohorte steht ohne Referenz da");
    assert.match(src, /validatorReport\(\s*days,\s*\w+,\s*\{[^}]*\bground\b/, name + ": der Selbst-Report bekommt keine Referenz");
    assert.doesNotMatch(src, /async function groundTruthMap\(/, name + ": eine eigene Referenz-Beschaffung neben der gemeinsamen ist die Divergenz vom 2026-10-16");
  }
});

test("Die Fensterwahl sitzt in der Engine, nicht in einzelnen Rufen", () => {
  const query = read("./validator-trace-query.mjs");
  const report = read("./validator-report.mjs");
  assert.match(query, /referenceWindow\(rangeHours\)/, "die Query waehlt kein Referenzfenster");
  assert.doesNotMatch(query, /hours:\s*24\b/, "die Query rechnet starr gegen das Tagesfenster");
  assert.match(query, /groundByMaster:\s*peerGround/, "die Kohorte bekommt die ungefilterte Fenster-Karte");
  assert.match(report, /groundScan\(ground, refWindow\)/, "der Report rechnet ohne gewaehltes Fenster");
  assert.match(report, /"groundVerdict"/, "der CSV-Selbst-Report fuehrt die Gegenprobe nicht");
});
