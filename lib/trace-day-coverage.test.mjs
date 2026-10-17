// lib/trace-day-coverage.test.mjs — Deckung der Stunden-Buckets gegen die Tageszaehler.
import test from "node:test";
import assert from "node:assert/strict";
import { dayCoverageGaps, dayFileHoles, DAY_HOLE_MS, observedOf, COUNT_KEYS, uncoveredHours, dayResidual } from "./trace-day-coverage.mjs";

const HOUR = 3600000;
const NOW = Date.parse("2026-10-16T12:00:00.000Z");
const H0 = Math.floor(NOW / HOUR);
const ALL = { from: 0, to: NOW + 1 };
const A = "nAAA";
const c = (ok, missed = 0, noQuorum = 0) => ({ ok, partial: 0, missed, wrongHash: 0, noQuorum });

/* Der Fall aus den echten Tagen: 2026-10-09 hat Tageszaehler fuer 12.896 Knoten-Ledger,
 * Stunden-Buckets erst ab 11 Uhr (8.239 Ledger) - und alle Vorfaelle liegen vor 11 Uhr. */
function halfDay() {
  const hourly = {};
  for (let i = 0; i < 12; i += 1) hourly[H0 - 12 + i] = { l: 100, v: { [A]: c(100) } };
  return {
    date: "2026-10-09", ledgers: 2400, quorumFail: 0,
    validators: { [A]: c(2375, 25) },
    incidents: [], gaps: [], firstMs: (H0 - 24) * HOUR, lastMs: NOW, hourly,
  };
}

test("Halb gedeckter Tag: der Rest aus den Tageszaehlern wird ausgewiesen", () => {
  const { gaps, hasHourly, partial, wholeDay } = dayCoverageGaps(halfDay(), ALL);
  assert.equal(hasHourly, true);
  assert.equal(partial, true);
  assert.equal(wholeDay, true, 'der Tag liegt ganz im Fenster');
  const gap = gaps.get(A);
  assert.ok(gap, "Rest darf nicht still verschwinden");
  assert.equal(observedOf(gap), 1200, '2400 Tages-Ledger - 1200 gemessene = 1200');
  assert.equal(gap.missed, 25, 'alle 25 Vorfaelle liegen in der nicht gedeckten Zeit');
  assert.equal(gap.ok, 1175);
});

test("Voll gedeckter Tag: kein Rest, die Messung bleibt die Messung", () => {
  const d = halfDay();
  d.validators = { [A]: c(1200) }; // exakt die Zwölf Stunden
  const { gaps, partial } = dayCoverageGaps(d, ALL);
  assert.equal(gaps.size, 0);
  assert.equal(partial, false);
});

test("Tag ohne Stunden-Buckets: der volle Tag ist der Rest (Tages-Fallback)", () => {
  const d = { ...halfDay(), hourly: {} };
  const { gaps, hasHourly, partial } = dayCoverageGaps(d, ALL);
  assert.equal(hasHourly, false);
  assert.equal(partial, true);
  assert.equal(observedOf(gaps.get(A)), 2400);
  assert.equal(gaps.get(A).missed, 25);
});

test("Fenster ueber nur einem Teil des Tages: wholeDay false (Tageszaehler ist kein Fensterzaehler)", () => {
  const w = { from: NOW - 6 * HOUR, to: NOW + 1 };
  const { gaps, wholeDay } = dayCoverageGaps(halfDay(), w);
  assert.equal(wholeDay, false);
  // 6 von 24 Stunden-Tagesspanne -> 2400 * 0,25 = 600 geschaetzt minus 600 gemessen = kein Rest.
  assert.equal(gaps.size, 0, 'gemessene Stunden decken den Fenster-Anteil schon ab');
});

test("Knoten ohne Stunden-Bucket-Eintrag: kein Rest, sonst waere es Doppelzaehlung", () => {
  const d = halfDay();
  d.validators = { ...d.validators, nZZZ: c(500, 5) };
  const { gaps } = dayCoverageGaps(d, ALL);
  assert.equal(gaps.has("nZZZ"), false, 'nZZZ steht in keinem Bucket - sein Tagessummen-Anteil waere eine Doppelzaehlung');
  assert.equal(gaps.get(A).missed, 25, 'der Rest der anderen Knoten bleibt davon unberuehrt');
});

test("COUNT_KEYS: Zaehler und Rest verwenden dieselben Felder", () => {
  assert.deepEqual(COUNT_KEYS, ["ok", "partial", "missed", "wrongHash", "noQuorum"]);
  assert.equal(observedOf(c(10, 2, 3)), 15);
  assert.equal(observedOf(undefined), 0);
});

/* profileCells braucht zwei Dinge: den Rest je Knoten UND die Stunden, in denen er passiert sein
 * muss. Beides liefert diese Datei, sonst steht im Profil eine Abweichung ohne Nenner. */
test("uncoveredHours: Stunden ohne Bucket, begrenzt auf die belegte Spanne", () => {
  const { hours, span } = uncoveredHours(halfDay());
  // Buckets decken H0-12..H0-1; die Tagesspanne reicht von H0-24 bis NOW.
  assert.equal(hours.length, 13, '24 Stunden-Schritte - 12 gedeckte = 13 (H0-24 ist angebrochen)');
  assert.ok(hours.includes(H0 - 24));
  assert.ok(hours.includes(H0 - 13), 'die Stunde vor dem ersten Bucket ist offen');
  assert.equal(hours.includes(H0 - 12), false, 'die erste Bucket-Stunde ist gedeckt');
  assert.equal(span.start, (H0 - 24) * HOUR);
});

test("uncoveredHours: ein Incident vor der Tagesspanne erweitert die Spanne nachweisbar", () => {
  const d = halfDay();
  // firstMs liegt bei 11:48 - der Vorfall um 00:28 desselben Tages liegt davor. Ohne diese
  // Erweiterung bekaeme die Stunde des Vorfalls nie einen Nenner.
  d.incidents = [{ l: 9, m: A, t: (H0 - 28) * HOUR + 60000, type: "missed", r: [] }];
  const { hours, span } = uncoveredHours(d);
  assert.equal(span.start, (H0 - 28) * HOUR + 60000, 'der Vorfall beweist Aktivitaet vor firstMs');
  assert.ok(hours.includes(H0 - 28), 'die Stunde des Vorfalls muss gezaehlt werden');
  assert.equal(hours.length, 17, '29 Stunden-Schritte - 12 gedeckte = 17 (4 davon vor firstMs)');
});

test("dayResidual: voller Tag unabhaengig vom Abfragefenster", () => {
  const { gaps, hours, hasHourly } = dayResidual(halfDay());
  assert.equal(hasHourly, true);
  assert.equal(observedOf(gaps.get(A)), 1200, '2400 Tages-Ledger - 1200 in Buckets');
  assert.equal(gaps.get(A).missed, 25);
  assert.ok(hours.length > 0);
});
/* Luecke ZWISCHEN Tagesdateien (gemessen auf dem Daten-Repo 2026-10-16 -> 2026-10-17):
 * 22:20:52Z letzter Close, 01:49:22Z erster Close des naechsten Tages. 3 h 28 min 30 s, in
 * denen kein Ledger bewertet wurde. Diese Spanne steht in keiner Datei, die existiert. */
const dfile = (date, firstMs, lastMs) => ({ date, firstMs, lastMs, ledgers: 10, validators: {}, incidents: [] });
const iso = (s) => Date.parse(s);

test("dayFileHoles: 8 s Abstand zwischen Tagesdateien ist kein Loch", () => {
  const holes = dayFileHoles([
    dfile("2026-10-16", iso("2026-10-16T00:00:00.000Z"), iso("2026-10-16T23:59:52.000Z")),
    dfile("2026-10-17", iso("2026-10-17T00:00:00.000Z"), iso("2026-10-17T00:10:00.000Z")),
  ]);
  assert.deepEqual(holes, [], "der normale Tageswechsel darf kein Loch sein");
});

test("dayFileHoles: der gemessene Fall auf die Sekunde", () => {
  const from = iso("2026-10-16T22:20:52.000Z"), to = iso("2026-10-17T01:49:22.000Z");
  const holes = dayFileHoles([
    dfile("2026-10-16", iso("2026-10-16T00:00:00.000Z"), from),
    dfile("2026-10-17", to, iso("2026-10-17T04:00:00.000Z")),
  ]);
  assert.equal(holes.length, 1);
  assert.equal(holes[0].ms, 12510000, "3 h 28 min 30 s = 12.510.000 ms");
  assert.equal(holes[0].ms, to - from, "die Zahl ist die Differenz, nicht ein gerundeter Stundenwert");
  assert.equal(holes[0].between, "2026-10-16->2026-10-17");
  assert.equal(holes[0].fromIso, "2026-10-16T22:20:52.000Z");
  assert.equal(holes[0].toIso, "2026-10-17T01:49:22.000Z");
});

test("dayFileHoles: ein fehlender Tag in der Mitte wird ueberspannt", () => {
  const a = dfile("2026-10-14", iso("2026-10-14T00:00:00.000Z"), iso("2026-10-14T10:00:00.000Z"));
  const b = dfile("2026-10-16", iso("2026-10-16T18:00:00.000Z"), iso("2026-10-16T20:00:00.000Z"));
  const holes = dayFileHoles([b, a]);
  assert.equal(holes.length, 1, "die Reihenfolge der Liste darf das Ergebnis nicht aendern");
  assert.equal(holes[0].between, "2026-10-14->2026-10-16");
  assert.equal(holes[0].ms, iso("2026-10-16T18:00:00.000Z") - iso("2026-10-14T10:00:00.000Z"));
});

test("dayFileHoles: fehlende Zeitmarken sind keine Aussage, nicht der Abstand null", () => {
  const holes = dayFileHoles([
    { date: "2026-10-14", ledgers: 5, validators: {}, incidents: [] },
    { date: "2026-10-15", firstMs: null, lastMs: null, ledgers: 5, validators: {}, incidents: [] },
  ]);
  assert.deepEqual(holes, [], "1970 darf nicht als Zeitpunkt entstehen");
});

test("dayFileHoles: Ueberlappung zweier Tage ist kein Loch", () => {
  const holes = dayFileHoles([
    dfile("2026-10-15", iso("2026-10-15T00:00:00.000Z"), iso("2026-10-15T23:59:00.000Z")),
    dfile("2026-10-16", iso("2026-10-15T20:00:00.000Z"), iso("2026-10-16T02:00:00.000Z")),
  ]);
  assert.deepEqual(holes, []);
});

test("dayFileHoles: Grenze und Sortierung - 300000 ms sind noch keine Luecke", () => {
  const holes = dayFileHoles([
    dfile("2026-10-14", 1000, 1000000),
    dfile("2026-10-15", 1500000, 2000000),
    dfile("2026-10-16", 3000000, 3100000),
  ]);
  assert.deepEqual(holes.map((h) => h.ms), [1000000, 500000], "die groesste Luecke zuerst");
  const exact = dayFileHoles([dfile("2026-10-14", 0, 0), dfile("2026-10-15", DAY_HOLE_MS, 9)]);
  assert.deepEqual(exact, [], "genau die Grenze ist der normale Abstand");
  const just = dayFileHoles([dfile("2026-10-14", 0, 0), dfile("2026-10-15", DAY_HOLE_MS + 1, 9)]);
  assert.equal(just.length, 1, "einen ms ueber der Grenze ist die Spanne unbeobachtet");
});

