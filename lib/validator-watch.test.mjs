// lib/validator-watch.test.mjs - Beobachtungsliste: Delta seit dem letzten Besuch.
//
// Jede Zahl ist hier von Hand nachgerechnet. Alle Fixture liegen auf derselben Marke:
// NOW = 2026-10-17T10:00:00Z. Weil 10:00 Uhr eine volle Stunde ist, liegt der Besuch exakt
// auf einer Bucket-Grenze - und genau daran zeigt sich, ob eine angeschnittene Stunde als
// unbekannt ausgewiesen wird oder als Bruchteil erfunden wird.
import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { WATCH_DEFAULTS, WATCH_MAX_DAYS, WATCH_TYPES, WATCH_VERDICTS, WATCH_WINDOW_MS, watchDelta, watchEntriesFromQuery, watchRange, watchWindowCap } from "./validator-watch.mjs";

const HOUR = 3600000;
const NOW = Date.parse("2026-10-17T10:00:00.000Z");
const H0 = Math.floor(NOW / HOUR);
const VISIT = (H0 - 2) * HOUR; // Besuch 08:00 Uhr: zwei volle Stunden vor NOW
const A = "nAAA";
const B = "nBBB";
const C = "nCCC";
const D = "nDDD";
const E = "nEEE";

const c = (ok, missed = 0, noQuorum = 0, partial = 0, wrongHash = 0) =>
  ({ ok, partial, missed, wrongHash, noQuorum });
const at = (master, seenAtMs = VISIT) => ({ master, seenAtMs });

// Vier Stunden-Buckets: H0-3 liegt VOR dem Besuch, H0-2 und H0-1 darin, H0 ist die laufende
// Stunde. Je Bucket fuehrt jeder Knoten genau so viele Zaehler wie der Bucket-Ledger ausweist.
function day(over = {}) {
  const hourly = {
    [H0 - 3]: { l: 100, v: { [A]: c(100), [B]: c(100), [C]: c(100), [D]: c(100) } },
    [H0 - 2]: { l: 100, v: { [A]: c(98, 2), [B]: c(97, 3), [C]: c(100), [D]: c(100) } },
    [H0 - 1]: { l: 100, v: { [A]: c(100), [B]: c(100), [C]: c(100), [D]: c(100) } },
    [H0]: { l: 40, v: { [A]: c(38, 2), [B]: c(40), [C]: c(40), [D]: c(40) } },
  };
  return {
    date: "2026-10-17", ledgers: 340, quorumFail: 0,
    validators: { [A]: c(336, 4), [B]: c(337, 3), [C]: c(340), [D]: c(340) },
    incidents: [], gaps: [],
    firstMs: (H0 - 3) * HOUR, lastMs: NOW, hourly,
    ...over,
  };
}

test("Kohorte mit Beleg: beide Knoten verpassten denselben Ledger, beide sind zurechenbar", () => {
  const d = day({ incidents: [
    { l: 5001, m: A, t: (H0 - 1) * HOUR + 1000, type: "missed", aa: true },
    { l: 5001, m: B, t: (H0 - 1) * HOUR + 1000, type: "missed", aa: true },
  ] });
  const r = watchDelta([d], [at(A)], { now: NOW }).entries[0];
  assert.equal(r.verdict, "new-cohort");
  assert.deepEqual(r.incidents, { missed: 1, partial: 0, "wrong-hash": 0, "no-quorum": 0, "vote-not-observed": 0, total: 1 });
  assert.equal(r.incidentLedgers, 1);
  assert.equal(r.cohortLedgers, 1);
  assert.equal(r.cohortUnattributed, 0);
  assert.equal(r.cohort[0].ledgerIndex, 5001);
  assert.deepEqual(r.cohort[0].others, [B]);
  assert.deepEqual(r.cohort[0].types, ["missed"]);
  assert.equal(r.cohort[0].attributable, true);
  assert.equal(r.coverage.complete, true, "der Besuch liegt auf einer Bucket-Grenze");
  assert.equal(r.ledgers.measured, 240, "100 + 100 + 40; die Stunde vor dem Besuch nicht mitgerechnet");
  assert.equal(r.ledgers.liveBuckets, 1, "die laufende Stunde ist gezaehlt, nicht geschaetzt");
  assert.equal(r.basis.evaluatedLedgers, 240);
  assert.equal(r.basis.estimated, 0, "nichts an dieser Zeile ist geschaetzt");
});

test("Kohorte ohne Beleg: der andere Knoten ist nicht zurechenbar, also keine Mitschuld", () => {
  const d = day({ incidents: [
    { l: 5002, m: A, t: (H0 - 1) * HOUR + 2000, type: "missed", aa: true },
    { l: 5002, m: B, t: (H0 - 1) * HOUR + 2000, type: "missed", aa: false },
  ] });
  const r = watchDelta([d], [at(A)], { now: NOW }).entries[0];
  assert.equal(r.verdict, "new-incidents");
  assert.equal(r.cohortLedgers, 0);
  assert.equal(r.cohortUnattributed, 1, "bleibt eine offene Frage, keine Kohorten-Aussage");
});

test("Eigener Vorfall ohne Beleg: kein Kohorten-Anspruch, auch gegenueber einem belastbaren Knoten", () => {
  const d = day({ incidents: [
    { l: 5003, m: A, t: (H0 - 1) * HOUR + 3000, type: "missed", aa: false },
    { l: 5003, m: B, t: (H0 - 1) * HOUR + 3000, type: "missed", aa: true },
  ] });
  const r = watchDelta([d], [at(A)], { now: NOW }).entries[0];
  assert.equal(r.cohortLedgers, 0);
  assert.equal(r.cohortUnattributed, 1);
});

test("Quiet: lueckenlos erfasst und kein Vorfall - die einzige Zeile, die entlastet", () => {
  const r = watchDelta([day()], [at(C)], { now: NOW }).entries[0];
  assert.equal(r.verdict, "quiet");
  assert.equal(r.incidents.total, 0);
  assert.equal(r.coverage.complete, true);
  assert.equal(r.ledgers.measured, 240);
  assert.equal(r.firstNewIso, null);
  assert.equal(r.lastNewIso, null);
});

test("Partial-coverage: kein Vorfall, aber eine Index-Luecke - kein Freispruch", () => {
  const d = day({ gaps: [{ from: 900, to: 902, t: (H0 - 1) * HOUR + 60000, reason: "stream-gap" }] });
  const r = watchDelta([d], [at(D)], { now: NOW }).entries[0];
  assert.equal(r.verdict, "partial-coverage");
  assert.equal(r.coverage.complete, false);
  assert.equal(r.ledgers.gapCount, 1);
  assert.equal(r.ledgers.gapLedgers, 3, "902 - 900 + 1");
});

test("Luecke vor dem Besuch: sie liegt ausserhalb des Fensters und wird nicht zugerechnet", () => {
  const d = day({ gaps: [{ from: 900, to: 909, t: (H0 - 3) * HOUR + 60000, reason: "stream-gap" }] });
  const r = watchDelta([d], [at(D)], { now: NOW }).entries[0];
  assert.equal(r.ledgers.gapCount, 0);
  assert.equal(r.verdict, "quiet");
});

test("Not-evaluated: in diesem Fenster wurde ueber diesen Knoten nichts bewertet", () => {
  const r = watchDelta([day()], [at(E, (H0 - 1) * HOUR + 1800000)], { now: NOW }).entries[0];
  assert.equal(r.verdict, "not-evaluated");
  assert.equal(r.basis.evaluatedLedgers, 0);
  assert.equal(r.ledgers.partialBuckets, 1, "die Stunde, in der der Besuch liegt, ist angeschnitten");
  assert.equal(r.ledgers.unknown, 100, "ihre 100 Ledger sind weder vor noch nach dem Besuch");
  assert.equal(r.ledgers.measured, 40, "nur die laufende Stunde");
});

test("Angeschnittene Stunde: unbekannt bleibt unbekannt, kein Anteil wird erfunden", () => {
  const r = watchDelta([day()], [at(A, (H0 - 1) * HOUR + 1)], { now: NOW }).entries[0];
  assert.equal(r.verdict, "partial-coverage");
  assert.equal(r.ledgers.partialBuckets, 1);
  assert.equal(r.ledgers.unknown, 100);
  assert.equal(r.ledgers.measured, 40);
  assert.equal(r.basis.evaluatedLedgers, 40, "nur die laufende Stunde ist dem Fenster zuzuordnen");
  assert.equal(r.coverage.complete, false);
});

test("No-coverage: keine Tagesdatei in diesem Fenster", () => {
  const d = { ...day(), firstMs: (H0 - 3) * HOUR, lastMs: (H0 - 2) * HOUR };
  const r = watchDelta([d], [at(A)], { now: NOW }).entries[0];
  assert.equal(r.verdict, "no-coverage");
  assert.equal(r.ledgers.measured, 0);
  assert.equal(r.incidents.total, 0);
  assert.equal(r.coverage.complete, false, "kein Fenster, keine Deckung - kein Freispruch");
  assert.equal(r.cohort.length, 0);
});

test("Bad-entry: ohne Knoten oder ohne Besuchszeit gibt es kein Urteil", () => {
  const out = watchDelta([day()], [
    { master: "", seenAtMs: VISIT },
    { master: A, seenAtMs: "" },
    { master: A, seenAtMs: NOW + HOUR },
    { master: "n mit leerzeichen", seenAtMs: VISIT },
  ], { now: NOW });
  assert.equal(out.entries.length, 4);
  for (const r of out.entries) assert.equal(r.verdict, "bad-entry");
  assert.equal(out.entries[2].basis.reason, "der Besuch liegt in der Zukunft");
});

test("Rekorder-Stop zwischen Tagen: die Luecke steht lesbar in der Zeile", () => {
  const prev = { date: "2026-10-16", ledgers: 100, validators: {}, incidents: [], gaps: [],
    firstMs: (H0 - 5) * HOUR, lastMs: (H0 - 3) * HOUR };
  const cur = day({ firstMs: (H0 - 1) * HOUR, hourly: {
    [H0 - 1]: { l: 100, v: { [D]: c(100) } },
    [H0]: { l: 40, v: { [D]: c(40) } },
  } });
  const out = watchDelta([prev, cur], [at(D)], { now: NOW });
  const r = out.entries[0];
  assert.equal(r.verdict, "partial-coverage");
  assert.equal(r.coverage.complete, false);
  assert.equal(r.ledgers.measured, 140, "100 + 40, die unbelegte Zeit nicht als Ledger");
  assert.equal(r.coverage.holes.length, 1);
  assert.equal(r.coverage.holes[0].ms, 2 * HOUR);
  assert.equal(r.coverage.uncovered.length, 1);
  assert.equal(r.coverage.uncovered[0].fromIso, new Date(VISIT).toISOString());
  assert.equal(r.coverage.uncovered[0].ms, HOUR);
  assert.equal(out.coverage.days, 2);
  assert.equal(out.coverage.holes.length, 1);
});

test("Tag ohne Stunden-Buckets, ganze Spanne im Fenster: Tages-Koernung wird gezaehlt", () => {
  const d = { date: "2026-10-17", ledgers: 120, validators: { [A]: c(118, 2) },
    incidents: [], gaps: [], firstMs: VISIT, lastMs: NOW, hourly: {} };
  const r = watchDelta([d], [at(A)], { now: NOW }).entries[0];
  assert.equal(r.verdict, "quiet");
  assert.equal(r.ledgers.measured, 120);
  assert.equal(r.basis.evaluatedLedgers, 120);
  assert.equal(r.ledgers.partialBuckets, 0);
  assert.equal(r.coverage.dayOnlyOpenDays, 0);
  assert.equal(r.coverage.complete, true);
});

test("Tag ohne Stunden-Buckets, angeschnitten: nichts davon ist dem Fenster zuzuordnen", () => {
  const d = { date: "2026-10-17", ledgers: 120, validators: { [A]: c(118, 2) },
    incidents: [], gaps: [], firstMs: VISIT - 2 * HOUR, lastMs: NOW + HOUR, hourly: {} };
  const r = watchDelta([d], [at(A)], { now: NOW }).entries[0];
  assert.equal(r.verdict, "not-evaluated");
  assert.equal(r.ledgers.measured, 0);
  assert.equal(r.ledgers.unknown, 120);
  assert.equal(r.coverage.dayOnlyOpenDays, 1);
  assert.equal(r.coverage.complete, false);
});

test("Vorfall vor dem Besuch: er gehoert nicht zur Delta", () => {
  const d = day({ incidents: [
    { l: 4001, m: A, t: (H0 - 3) * HOUR + 1000, type: "missed", aa: true },
    { l: 4002, m: A, t: VISIT, type: "missed", aa: true },
  ] });
  const r = watchDelta([d], [at(A)], { now: NOW }).entries[0];
  assert.equal(r.incidentLedgers, 0, "die exakte Besuchszeit ist nicht 'seit' dem Besuch");
  assert.equal(r.incidents.total, 0);
  assert.equal(r.verdict, "quiet");
});

test("Typ-Vokabeln: vote-not-observed und no-quorum bleiben zwei verschiedene Tatsachen", () => {
  const d = day({ incidents: [
    { l: 6001, m: A, t: (H0 - 2) * HOUR + 1000, type: "vote-not-observed", aa: true },
    { l: 6002, m: A, t: (H0 - 1) * HOUR + 1000, type: "no-quorum", aa: true },
    { l: 6003, m: A, t: (H0 - 1) * HOUR + 2000, type: "wrong-hash", aa: true },
    { l: 6004, m: A, t: (H0 - 1) * HOUR + 3000, type: "partial", aa: true },
    { l: 6005, m: A, t: (H0 - 1) * HOUR + 4000, type: "unknown-kind", aa: true },
  ] });
  const r = watchDelta([d], [at(A)], { now: NOW }).entries[0];
  assert.deepEqual(r.incidents, { missed: 0, partial: 1, "wrong-hash": 1, "no-quorum": 1, "vote-not-observed": 1, total: 4 },
    "ein geschlossener Ledger darf nicht als Quorum-Absage gezaehlt werden");
  assert.equal(r.incidentLedgers, 4, "eine unbekannte Typ-Vokabel wird nicht gezaehlt");
  assert.equal(r.firstNewIso, new Date((H0 - 2) * HOUR + 1000).toISOString());
  assert.equal(r.lastNewIso, new Date((H0 - 1) * HOUR + 3000).toISOString());
});

test("Zwei Abweichungen am selben Ledger: eine Ledger-Zeile, beide Typen", () => {
  const d = day({ incidents: [
    { l: 8001, m: A, t: (H0 - 1) * HOUR + 1000, type: "missed", aa: true },
    { l: 8001, m: A, t: (H0 - 1) * HOUR + 5000, type: "wrong-hash", aa: true },
  ] });
  const r = watchDelta([d], [at(A)], { now: NOW }).entries[0];
  assert.equal(r.incidentLedgers, 1);
  assert.deepEqual(r.incidents, { missed: 1, partial: 0, "wrong-hash": 1, "no-quorum": 0, "vote-not-observed": 0, total: 2 });
});

test("Kohorten-Namen: benannt aus der Netz-Auskunft, sonst null - nicht 'kein Knoten'", () => {
  const d = day({ incidents: [
    { l: 6101, m: A, t: (H0 - 1) * HOUR + 1000, type: "missed", aa: true },
    { l: 6101, m: B, t: (H0 - 1) * HOUR + 1000, type: "missed", aa: true },
    { l: 6102, m: A, t: (H0 - 1) * HOUR + 2000, type: "vote-not-observed", aa: true },
    { l: 6102, m: C, t: (H0 - 1) * HOUR + 2000, type: "vote-not-observed", aa: true },
  ] });
  const peers = new Map([[A, { name: "xrp.vet" }], [B, { name: "vldxrpp.info" }], [C, { name: null }]]);
  const r = watchDelta([d], [at(A)], { now: NOW, groundPeers: peers }).entries[0];
  assert.equal(r.name, "xrp.vet", "der eigene Knoten wird benannt, wo die Auskunft einen Namen hat");
  assert.deepEqual(r.cohort[0].othersNames, [{ master: B, name: "vldxrpp.info" }]);
  assert.deepEqual(r.cohort[1].othersNames, [{ master: C, name: null }],
    "nicht benannt ist eine Auskunft, nicht die Aussage, es gebe keinen Knoten");
  assert.deepEqual(r.cohort[1].others, [C], "die Master-Liste bleibt erhalten, auch ohne Namen");
  const bare = watchDelta([d], [at(A)], { now: NOW }).entries[0];
  assert.equal(bare.name, null, "ohne Auskunft gibt es keinen Namen, auch keinen erfundenen");
  assert.deepEqual(bare.cohort[0].othersNames, [{ master: B, name: null }]);
});

test("Grenzen: maxMasters kappt die Liste, maxCohortRows kappt die Kohorte und sagt es", () => {
  const incidents = [];
  for (let i = 0; i < 3; i += 1) {
    const t = (H0 - 1) * HOUR + 1000 + i;
    incidents.push({ l: 7000 + i, m: A, t, type: "missed", aa: true });
    incidents.push({ l: 7000 + i, m: B, t, type: "missed", aa: true });
  }
  const entries = [at(A), ...Array.from({ length: 14 }, (_, i) => at("nM" + i))];
  const out = watchDelta([day({ incidents })], entries, { now: NOW, defaults: { maxCohortRows: 2 } });
  assert.equal(out.entries.length, WATCH_DEFAULTS.maxMasters);
  assert.equal(out.limits.requested, entries.length);
  const a = out.entries.find((r) => r.master === A);
  assert.equal(a.cohortLedgers, 3);
  assert.equal(a.cohort.length, 2, "die Kohorte wird auf die gesetzte Grenze gekappt");
  assert.equal(a.cohortTruncated, true);
});

test("Urteils-Vokabel: jedes Urteil gehoert zur festgelegten Liste", () => {
  const solo = day({ incidents: [{ l: 9001, m: A, t: (H0 - 1) * HOUR + 1000, type: "missed", aa: true }] });
  const out = watchDelta([solo], [at(A), at(C), { master: "", seenAtMs: VISIT }], { now: NOW });
  for (const r of out.entries) assert.ok(WATCH_VERDICTS.includes(r.verdict), r.verdict);
  assert.deepEqual(WATCH_TYPES, ["missed", "partial", "wrong-hash", "no-quorum", "vote-not-observed"]);
  assert.equal(out.entries[0].verdict, "new-incidents", "Einzelknoten ohne Kohorten-Beleg");
  assert.equal(out.entries[0].cohortUnattributed, 0, "kein anderer Knoten am Ledger, keine offene Frage");
  assert.equal(out.entries[1].verdict, "quiet", "derselbe Tag, ein anderer Knoten ohne Vorfall");
  assert.equal(out.entries[2].incidents.total, 0, "auch die abgelehnte Zeile fuehrt dieselben Felder");
});

test("Fenster und Herkunft stehen in der Zeile: Besuch, Dauer, Grundlage", () => {
  const r = watchDelta([day()], [at(A)], { now: NOW }).entries[0];
  assert.equal(r.seenAtIso, new Date(VISIT).toISOString());
  assert.equal(r.windowMs, 2 * HOUR);
  assert.equal(r.basis.estimated, 0);
  assert.equal(r.basis.source, "stunden-buckets + zeitgestempelte vorfaelle");
});

/* Produktions-Paritaet: Vercel rendert nicht server/index.mjs, sondern die Functions in api/*
 * mit Rewrite aus vercel.json. Ein Endpunkt, der nur lokal existiert, ist online eine 404 - die
 * Oberflaeche zeigt dann "nicht abrufbar", obwohl die Lib langlaeuft. Dieser Guard haelt alle
 * drei Stellen zusammen. */
test("Paritaet: Lib, lokaler Endpunkt, Vercel-Function und Rewrite haengen aneinander", () => {
  const read = (rel) => readFileSync(new URL(rel, import.meta.url), "utf8");
  const server = read("../server/index.mjs");
  const fn = read("../api/stats.js");
  const cfg = JSON.parse(read("../vercel.json"));
  assert.match(server, /app\.get\("\/api\/validator-watch"/, "der lokale Endpunkt fehlt");
  assert.match(fn, /route === "watch"/, "die Vercel-Function kennt den Zweig nicht");
  assert.match(fn, /watchDelta\(days, entries/, "die Function ruft nicht dieselbe Lib wie lokal");
  const rewrite = cfg.rewrites.find((r) => r.source === "/api/validator-watch");
  assert.ok(rewrite, "der Pfad /api/validator-watch hat keine Rewrite-Regel - online waere das eine 404");
  assert.equal(rewrite.destination, "/api/stats?route=watch");
  assert.ok(Object.keys(cfg.functions ?? {}).length < 12, "Hobby-Limit: keine zwölfte Function, der Zweig haengt an api/stats.js");
});

test("Schlechte Eingaben von aussen: kein Urteil statt Absturz", () => {
  const out = watchDelta(null, null, { now: NOW });
  assert.deepEqual(out.entries, []);
  assert.equal(out.coverage.days, 0);
  assert.equal(out.coverage.firstMs, null);
  const bad = watchDelta([day()], [at(A)], { now: "kein Datum" });
  assert.ok(Number.isFinite(bad.now), "ein kaputtes jetzt wird nicht zu NaN");
});

test("Abfrage-Form: masters und seen, ein Eintrag ohne Besuchszeit wird benannt", () => {
  const q = { masters: A + "," + B, seen: A + ":" + VISIT + "," + B + ":" + (VISIT + 1000) };
  const { entries, rejected, truncated } = watchEntriesFromQuery(q);
  assert.deepEqual(entries, [{ master: A, seenAtMs: VISIT }, { master: B, seenAtMs: VISIT + 1000 }]);
  assert.deepEqual(rejected, []);
  assert.equal(truncated, false);
});

test("Abfrage-Form: seen allein reicht, die Reihenfolge folgt masters", () => {
  const q = { masters: B + "," + A, seen: A + ":" + VISIT + "," + B + ":" + (VISIT + 1000) };
  const { entries } = watchEntriesFromQuery(q);
  assert.deepEqual(entries.map((e) => e.master), [B, A]);
});

test("Abfrage-Form: ein Knoten ohne seine Besuchszeit wird nicht still weggelassen", () => {
  const { entries, rejected } = watchEntriesFromQuery({ masters: A + "," + B, seen: A + ":" + VISIT });
  assert.deepEqual(entries, [{ master: A, seenAtMs: VISIT }]);
  assert.equal(rejected.length, 1);
  assert.equal(rejected[0].entry, B);
  assert.equal(rejected[0].reason, "keine Besuchszeit fuer diesen Knoten");
});

test("Abfrage-Form: kaputte Besuchszeiten werden mit Grund abgelehnt", () => {
  const { entries, rejected } = watchEntriesFromQuery({ seen: A + ",:" + VISIT + "," + B + ":keinezahl," + C + ":-5" });
  assert.deepEqual(entries, []);
  assert.equal(rejected.length, 4);
  assert.equal(rejected[0].reason, "keine Besuchszeit (erwartet master:millisekunden)");
  assert.equal(rejected[1].reason, "kein Knoten vor dem Doppelpunkt");
  assert.equal(rejected[2].reason, "die Besuchszeit ist keine Zahl in Millisekunden");
  assert.equal(rejected[3].reason, "die Besuchszeit ist keine Zahl in Millisekunden");
});

test("Abfrage-Form: die Knoten-Grenze wird kappt und als Kapzung gesagt", () => {
  const seen = Array.from({ length: WATCH_DEFAULTS.maxMasters + 4 }, (_, i) => "nM" + i + ":" + VISIT).join(",");
  const { entries, truncated } = watchEntriesFromQuery({ seen });
  assert.equal(entries.length, WATCH_DEFAULTS.maxMasters);
  assert.equal(truncated, true);
});

test("Ladebereich: der billigste Bereich, der das aelteste Fenster noch ganz deckt", () => {
  assert.equal(watchRange([{ seenAtMs: NOW - 30 * 60000 }], NOW), "1h");
  assert.equal(watchRange([{ seenAtMs: NOW - HOUR }], NOW), "1h");
  assert.equal(watchRange([{ seenAtMs: NOW - HOUR - 1 }], NOW), "24h");
  assert.equal(watchRange([{ seenAtMs: NOW - 24 * HOUR - 1 }], NOW), "7d");
  assert.equal(watchRange([{ seenAtMs: NOW - 7 * 24 * HOUR - 1 }], NOW), "30d");
  assert.equal(watchRange([{ seenAtMs: NOW - 30 * 24 * HOUR - 1 }], NOW), "30d");
  assert.equal(watchRange([{ seenAtMs: NOW - 30 * 24 * HOUR - 1 }, { seenAtMs: NOW - HOUR }], NOW), "30d",
    "das aelteste Fenster bestimmt den Bereich, nicht das neueste");
  assert.equal(watchRange([], NOW), "1h");
});

test("Kappe: ein Besuch aelter als 30 Tage wird ausgesprochen, nicht verschluckt", () => {
  const old = [{ seenAtMs: NOW - 31 * 24 * HOUR }];
  assert.equal(watchRange(old, NOW), "30d", "der Ladebereich endet bei 30 Tagen, niemals all");
  const cap = watchWindowCap(old, NOW);
  assert.equal(cap.days, WATCH_MAX_DAYS);
  assert.equal(cap.capped, true, "ein Teil des Fensters blieb unverglichen - das muss dastehen");
  assert.equal(cap.ageMs, 31 * 24 * HOUR);
  assert.equal(watchWindowCap([{ seenAtMs: NOW - 2 * 24 * HOUR }], NOW).capped, false);
  assert.equal(watchWindowCap([], NOW).ageMs, 0);
  assert.equal(WATCH_WINDOW_MS, WATCH_MAX_DAYS * 24 * HOUR);
});
