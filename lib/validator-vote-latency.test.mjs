// lib/validator-vote-latency.test.mjs — die Arithmetik der Timing-Ebene, nachgerechnet.
//
// Diese Ebene entscheidet ueber eine Zustandsdiagnose ("Knoten spaet" gegen "Knoten nie" gegen
// "Netz spaet"). Jede dieser Entscheidungen haengt an einem Vergleich, und jeder Vergleich ist
// hier mit konkreten Zahlen durchgerechnet statt als "sollte passen" stehengelassen.
import test from "node:test";
import assert from "node:assert/strict";
import {
  LATENCY_CLASSES, LATENCY_MIN_INCIDENTS, LATENCY_REASONS, LATENCY_VERDICTS,
  LATE_GRACE_MS, LATE_RING_LEDGERS, voteLatencyProfile,
} from "./validator-vote-latency.mjs";
import { normalizeDay } from "./validator-trace-store.mjs";
import { TRACE_DEFAULTS } from "./validator-trace.mjs";

const NOW = 1792000000000;
const DAY_MS = 86400000;
const HOUR_MS = 3600000;
const T = NOW - 100000; // liegt in jedem hier getesteten Fenster
const MASTER = "nHTEST";

function day(over = {}) {
  return { date: "2026-10-16", ledgers: 0, quorumFail: 0, incidents: [], ledgerStats: [], hourly: {}, lateVotes: [], ...over };
}
const inc = (l, type, vd, t = T) => ({ l, m: MASTER, t, type, r: [], vd });
const stat = (l, fv, t = T) => ({ l, t, fv, lv: null });
function ledgers(n, type = "missed", vd = null, from = 1000) {
  return Array.from({ length: n }, (_, i) => inc(from + i, type, vd));
}
const run = (days, opts = {}) => voteLatencyProfile(days, MASTER, { range: "24h", now: NOW, ...opts });

test("Der Gnadenwert ist der des Recorders - keine zweite Zahl an derselben Stelle", () => {
  assert.equal(LATE_GRACE_MS, TRACE_DEFAULTS.graceMs);
  assert.equal(LATE_RING_LEDGERS, TRACE_DEFAULTS.lateRingSize);
  assert.equal(LATE_GRACE_MS, 20000);
  assert.equal(LATE_RING_LEDGERS, 512);
});

test("Urteils-Mengen sind vollstaendig und decken jede Klasse ab", () => {
  for (const v of ["no-deviations", "capture-only", "closure-unproven", "partially-proven", "not-recorded", "insufficient-sample", "never-signed", "node-side-late", "network-side", "mixed", "latency-not-the-cause"]) {
    assert.ok(LATENCY_VERDICTS.includes(v), "Verdikt fehlt: " + v);
  }
  assert.equal(LATENCY_VERDICTS.length, 11);
  assert.equal(LATENCY_REASONS.length, 13);
  assert.deepEqual(LATENCY_CLASSES, ["late", "never", "inWindow", "unknown"]);
});

test("spaeter Vote nach der Bewertung: knotenseitig, wenn das Netz schnell war", () => {
  const r = run([day({
    incidents: ledgers(5, "missed", 25000),
    ledgerStats: [0, 1, 2, 3, 4].map((i) => stat(1000 + i, 400)),
  })]);
  assert.equal(r.verdict, "node-side-late");
  assert.equal(r.verdictReason, "late-vote-dominant-no-network-reference");
  assert.equal(r.verdictAuthority, "trace-late-votes");
  assert.equal(r.classes.late, 5);
  assert.equal(r.classes.lateShare, 1);
  assert.equal(r.own.delay.median, 25000);
  assert.equal(r.network.onOwnIncidentLedgers.median, 400);
  // Distanz = eigene Latenz minus erster Netzvote: 25000 - 400 = 24600.
  assert.equal(r.comparison.behind.median, 24600);
  assert.equal(r.comparison.ratioOwnToNetworkMedian, 62.5);
  assert.equal(r.pattern.kind, "consistent-offset");
  assert.equal(r.pattern.spreadMs, 0);
  assert.equal(r.lateVotes.length, 5);
});

test("Gnaden-Grenze ist exclusive: 20000 ms gilt als rechtzeitig, 20001 ms als spaet", () => {
  const at = run([day({ incidents: ledgers(5, "partial", LATE_GRACE_MS) })]);
  assert.equal(at.classes.inWindow, 5);
  assert.equal(at.classes.late, 0);
  assert.equal(at.verdict, "latency-not-the-cause");
  assert.equal(at.verdictReason, "own-vote-inside-grace");
  const over = run([day({ incidents: ledgers(5, "partial", LATE_GRACE_MS + 1) })]);
  assert.equal(over.classes.late, 5);
  assert.equal(over.classes.inWindow, 0);
});

test("kein Vote: erfasste Spaetvalidierung trennt 'nie' von 'nicht erfasst'", () => {
  const recorded = run([day({ incidents: ledgers(5, "missed", null) })]);
  assert.equal(recorded.classes.never, 5);
  assert.equal(recorded.classes.unknown, 0);
  assert.equal(recorded.verdict, "never-signed");
  assert.equal(recorded.verdictReason, "never-voted-dominant");
  assert.equal(recorded.coverage.daysRecorded, 1);
  assert.equal(recorded.coverage.daysMissing, 0);

  // Altbestand ohne lateVotes-Feld: "nie" waere eine Entlastung, die niemand gemessen hat.
  const legacy = run([day({ incidents: ledgers(5, "missed", null), lateVotes: undefined })]);
  assert.equal(legacy.classes.unknown, 5);
  assert.equal(legacy.classes.never, 0);
  assert.equal(legacy.verdict, "not-recorded");
  assert.equal(legacy.verdictReason, "late-vote-recording-missing");
  assert.equal(legacy.coverage.daysRecorded, 0);
  assert.equal(legacy.coverage.daysMissing, 1);
});

test("partial und wrong-hash ohne Messwert werden nie zu 'nie abgestimmt'", () => {
  // lib/validator-trace.mjs setzt voteDelayMs nur fuer 'missed' auf null; partial und
  // wrong-hash haben eine Validation gesehen. "nie" fuer sie waere eine Beschuldigung ohne
  // Beleg - und 'never-signed' als Urteil wuerde dem Betreiber die falsche Naechstpruefung
  // (Neustart statt Timing) naehen.
  const r = run([day({ incidents: [
    inc(1000, "partial", null), inc(1001, "partial", null), inc(1002, "wrong-hash", null),
    inc(1003, "missed", null), inc(1004, "missed", null),
  ] })]);
  assert.equal(r.classes.unknown, 3);
  assert.equal(r.classes.never, 2);
  assert.equal(r.classes.late, 0);
  assert.equal(r.classes.inWindow, 0);
  assert.equal(r.classes.measurable, 2);
  assert.equal(r.classes.unknownShare, 0.6);
  // Das Urteil haelt an den Klassen, die wirklich belegenbar sind.
  assert.equal(r.verdict, "never-signed");
  assert.equal(r.verdictReason, "never-voted-dominant");
});

test("normalizeDay markiert Altbestand, damit ein geleertes Array nicht als Messung zaehlt", () => {
  const legacy = normalizeDay({ date: "2026-10-01", incidents: [] });
  assert.deepEqual(legacy.lateVotes, []);
  assert.equal(legacy.lateVotesRecorded, false);
  const fresh = normalizeDay({ date: "2026-10-16", incidents: [], lateVotes: [] });
  assert.equal(fresh.lateVotesRecorded, undefined);
  const r = run([legacy]);
  assert.equal(r.verdict, "no-deviations");
  const r2 = run([legacy, day({ incidents: ledgers(5, "missed", null) })]);
  assert.equal(r2.verdict, "never-signed");
  assert.equal(r2.coverage.daysRecorded, 1);
  assert.equal(r2.coverage.daysMissing, 1);
});

test("Spaetvote-Liste liefert die Latenz, wo der Incident selbst null fuehrt", () => {
  const r = run([day({
    incidents: ledgers(5, "missed", null),
    lateVotes: [0, 1, 2, 3, 4].map((i) => ({ l: 1000 + i, m: MASTER, ms: 30000, t: T + 30000 })),
  })]);
  assert.equal(r.classes.late, 5);
  assert.equal(r.classes.never, 0);
  assert.equal(r.own.delay.median, 30000);
  assert.equal(r.own.lateVotes, 5);
  assert.equal(r.verdict, "node-side-late");
});

test("mehrere Spaetvotes desselben Ledgers: der frueheste ist die Latenz, nicht der letzte", () => {
  const r = run([day({
    incidents: ledgers(5, "missed", null),
    lateVotes: [
      { l: 1000, m: MASTER, ms: 40000, t: T + 40000 },
      { l: 1000, m: MASTER, ms: 25000, t: T + 25000 },
      { l: 1001, m: MASTER, ms: 30000, t: T + 30000 },
      { l: 1002, m: MASTER, ms: 30000, t: T + 30000 },
      { l: 1003, m: MASTER, ms: 30000, t: T + 30000 },
      { l: 1004, m: MASTER, ms: 30000, t: T + 30000 },
    ],
  })]);
  // 25000 + 4 x 30000 = 145000; / 5 = 29000.
  assert.equal(r.own.delay.min, 25000);
  assert.equal(r.own.delay.max, 30000);
  assert.equal(r.own.delay.mean, 29000);
  assert.equal(r.own.lateVotes, 5); // Ledger 1000 zaehlt einmal, nicht zweimal
  assert.equal(r.lateVotes.length, 5);
});

test("Spaetvotes anderer Knoten gehoeren nicht in die Latenz dieses Knotens", () => {
  const r = run([day({
    incidents: ledgers(5, "missed", null),
    lateVotes: [0, 1, 2, 3, 4].map((i) => ({ l: 1000 + i, m: "nOTHER", ms: 30000, t: T + 30000 })),
  })]);
  assert.equal(r.classes.never, 5);
  assert.equal(r.classes.late, 0);
  assert.equal(r.own.lateVotes, 0);
  assert.equal(r.coverage.lateVotesSeen, 0);
});

test("kein Close-Beleg ist kein Netz-Befund: closure-unproven, nicht 'Netzstockung'", () => {
  const r = run([day({ incidents: ledgers(10, "no-quorum", null) })]);
  assert.equal(r.verdict, "closure-unproven");
  assert.equal(r.verdictReason, "no-node-attributable-failure");
  assert.equal(r.verdictAuthority, "none");
  assert.equal(r.counts.incidents, 10);
  assert.equal(r.counts.nodeIncidents, 0);
  assert.equal(r.counts.networkIncidents, 10);
  assert.deepEqual(r.closure, { incidents: 10, proven: 0, denied: 0, unknown: 10, bases: {} });
  assert.equal(r.classes, null);
  assert.equal(r.own, null);
});

test("ausdruecklich verneinte Schliessung bleibt eine offene Frage, kein Netz-Urteil", () => {
  const r = run([day({ incidents: ledgers(6, "no-quorum", null).map((i) => ({ ...i, nc: true })) })]);
  assert.equal(r.verdict, "closure-unproven");
  assert.deepEqual(r.closure, { incidents: 6, proven: 0, denied: 6, unknown: 0, bases: {} });
});

test("bewiesen geschlossene Ledger heissen Erfassungs-Luecke, nie Netzstockung", () => {
  const hash = "A".repeat(64);
  const stats = [0, 1, 2, 3, 4].map((i) => ({ l: 1000 + i, t: T, fv: 900, cl: true, ch: hash, chSource: "xrpscan" }));
  const r = run([day({ incidents: ledgers(5, "vote-not-observed", null), ledgerStats: stats })]);
  assert.equal(r.verdict, "capture-only");
  assert.equal(r.verdictReason, "capture-gap-on-closed-ledgers");
  assert.equal(r.verdictAuthority, "trace-closure-proof");
  assert.deepEqual(r.closure, { incidents: 5, proven: 5, denied: 0, unknown: 0, bases: { xrpscan: 5 } });
  assert.equal(r.classes, null);
});

test("Close-Beleg aus der Lese-Nachfuehrung (cb) zaehlt mit seiner Autoritaet", () => {
  const r = run([day({ incidents: ledgers(5, "vote-not-observed", null).map((i) => ({ ...i, cb: "validated-ledger-stream" })) })]);
  assert.equal(r.verdict, "capture-only");
  assert.deepEqual(r.closure.bases, { "validated-ledger-stream": 5 });
});

test("halb belegtes Fenster wird weder zur Ganz- noch zur Nicht-Aussage", () => {
  const hash = "B".repeat(64);
  const r = run([day({
    incidents: [
      { l: 1000, m: MASTER, t: T, type: "vote-not-observed", r: [], vd: null },
      { l: 1001, m: MASTER, t: T, type: "vote-not-observed", r: [], vd: null },
      { l: 1002, m: MASTER, t: T, type: "no-quorum", r: [], vd: null },
      { l: 1003, m: MASTER, t: T, type: "no-quorum", r: [], vd: null },
    ],
    ledgerStats: [{ l: 1000, t: T, fv: 800, cl: true, ch: hash }],
  })]);
  assert.equal(r.verdict, "partially-proven");
  assert.equal(r.verdictReason, "closure-proof-partial");
  assert.deepEqual(r.closure, { incidents: 4, proven: 2, denied: 0, unknown: 2, bases: { recorder: 1, "validated-ledger-stream": 1 } });
});

test("ein einziger knotenzurechenbarer Vorfall laesst das Schliess-Urteil nicht sprechen", () => {
  const hash = "C".repeat(64);
  const r = run([day({
    incidents: [...ledgers(5, "vote-not-observed", null), inc(1010, "missed", 30000)],
    ledgerStats: [0, 1, 2, 3, 4].map((i) => ({ l: 1000 + i, t: T, fv: 900, cl: true, ch: hash, chSource: "xrpscan" })),
  })]);
  assert.notEqual(r.verdict, "capture-only");
  assert.equal(r.counts.nodeIncidents, 1);
  // Der Schliess-Beleg der nicht-zurechenbaren Ledger bleibt auch neben einem eigenen Vorfall stehen.
  assert.deepEqual(r.closure, { incidents: 5, proven: 5, denied: 0, unknown: 0, bases: { xrpscan: 5 } });
});

test("gemischte Klassen fuehren zu gemischt, nicht zum schoensten Einzelurteil", () => {
  const r = run([day({ incidents: [
    inc(1000, "missed", 30000), inc(1001, "missed", 31000),
    inc(1002, "missed", null), inc(1003, "missed", null),
    inc(1004, "partial", 5000),
  ] })]);
  assert.equal(r.classes.late, 2);
  assert.equal(r.classes.never, 2);
  assert.equal(r.classes.inWindow, 1);
  assert.equal(r.classes.measurable, 5);
  assert.equal(r.classes.lateShare, 0.4);
  assert.equal(r.classes.neverShare, 0.4);
  assert.equal(r.classes.inWindowShare, 0.2);
  assert.equal(r.verdict, "mixed");
  assert.equal(r.verdictReason, "late-and-never-mixed");
});

test("dominante Klasse unter 60 % bei zweiter Klasse ueber 25 % ist gemischt", () => {
  // 3 late + 2 never: 3/5 = 0,6 ist NICHT unter 0,6 -> die dominante Klasse entscheidet.
  const dominant = run([day({ incidents: [
    inc(1000, "missed", 30000), inc(1001, "missed", 30000), inc(1002, "missed", 30000),
    inc(1003, "missed", null), inc(1004, "missed", null),
  ] })]);
  assert.equal(dominant.classes.late, 3);
  assert.equal(dominant.verdict, "node-side-late");
  // 2 late + 2 never + 1 unknown: zweite Klasse 2/4 = 0,5 -> gemischt. Der Tag ist erfasst,
  // die beiden fehlenden missed-Votes duerfen also als "nie" zaehlen.
  const mixed = run([day({ incidents: [
    inc(1000, "missed", 30000), inc(1001, "missed", 30000),
    inc(1002, "missed", null), inc(1003, "missed", null),
    inc(1004, "partial", null),
  ] })]);
  assert.equal(mixed.classes.late, 2);
  assert.equal(mixed.classes.never, 2);
  assert.equal(mixed.classes.unknown, 1);
  assert.equal(mixed.classes.unknownShare, 0.2);
  assert.equal(mixed.verdict, "mixed");
});

test("zu wenige Vorfaelle bekommen kein Urteil", () => {
  const r = run([day({ incidents: ledgers(LATENCY_MIN_INCIDENTS - 1, "missed", 30000) })]);
  assert.equal(r.counts.nodeIncidents, 4);
  assert.equal(r.verdict, "insufficient-sample");
  assert.equal(r.verdictReason, "below-minimum-incidents");
});

test("kein abweichender Ledger ist eine Aussage, keine Luecke", () => {
  const r = run([day({})]);
  assert.equal(r.verdict, "no-deviations");
  assert.equal(r.verdictReason, "no-incidents-in-window");
  assert.equal(r.verdictAuthority, "none");
  assert.equal(r.counts.incidents, 0);
});

test("Fenster filtert Vorfaelle und Spaetvotes, 7d reicht weiter als 24h", () => {
  const old = NOW - 3 * DAY_MS;
  const d = day({
    incidents: [inc(1000, "missed", 30000, old), ...ledgers(5, "missed", 30000, 1010)],
    lateVotes: [{ l: 1000, m: MASTER, ms: 30000, t: old },
      ...[1010, 1011, 1012, 1013, 1014].map((l) => ({ l, m: MASTER, ms: 30000, t: T + 30000 }))],
  });
  const r24 = run([d]);
  assert.equal(r24.counts.incidents, 5);
  assert.equal(r24.own.lateVotes, 5);
  assert.equal(r24.coverage.lateVotesSeen, 5);
  assert.equal(r24.classes.late, 5);
  const r7 = run([d], { range: "7d" });
  assert.equal(r7.counts.incidents, 6);
  assert.equal(r7.coverage.lateVotesSeen, 6);
  assert.equal(r7.own.lateVotes, 6);
  const none = run([day({ incidents: [inc(1000, "missed", 30000, old)] })]);
  assert.equal(none.counts.incidents, 0);
  assert.equal(none.verdict, "no-deviations");
});

test("Netz selbst spaet auf denselben Ledern: Urteil wechselt auf netzseitig", () => {
  const r = run([day({
    incidents: ledgers(5, "missed", 25000),
    ledgerStats: [0, 1, 2, 3, 4].map((i) => stat(1000 + i, 30000)),
  })]);
  assert.equal(r.verdict, "network-side");
  assert.equal(r.verdictReason, "network-first-vote-late");
  assert.equal(r.verdictAuthority, "trace-network-latency");
  // 25000 - 30000 = -5000: der Knoten war vor dem ersten Netzvote des Netzes, das Netz war nur
  // insgesamt spaet. Ein Vorzeichenwechsel ist hier die Aussage, kein Rechenfehler.
  assert.equal(r.comparison.behind.median, -5000);
});

test("Netz-Referenz aus den Stunden-Buckets macht den Vergleich moeglich", () => {
  const hk = Math.floor(T / HOUR_MS);
  const r = run([day({
    incidents: ledgers(5, "missed", 25000),
    hourly: { [hk]: { l: 100, v: {}, fvN: 100, fvS: 40000, fvX: 900, fvL: 0 } },
  })]);
  assert.equal(r.network.hourly.ledgers, 100);
  assert.equal(r.network.hourly.meanFvMs, 400); // 40000 / 100
  assert.equal(r.network.hourly.maxFvMs, 900);
  assert.equal(r.network.hourly.lateShare, 0);
  assert.equal(r.verdict, "node-side-late");
  assert.equal(r.verdictReason, "late-vote-dominant-network-fast");
});

test("Netz, dessen erster Vote mehrheitlich ausserhalb des Gnadenfensters liegt, ist das Problem", () => {
  const hk = Math.floor(T / HOUR_MS);
  const r = run([day({
    incidents: ledgers(5, "missed", 25000),
    hourly: { [hk]: { l: 100, v: {}, fvN: 100, fvS: 3000000, fvX: 60000, fvL: 60 } },
  })]);
  assert.equal(r.network.hourly.meanFvMs, 30000); // 3000000 / 100
  assert.equal(r.network.hourly.lateLedgers, 60);
  assert.equal(r.network.hourly.lateShare, 0.6);
  assert.equal(r.verdict, "network-side");
});

test("Peer-Ausfall-Leder ohne diesen Knoten sind die Kontrollgruppe", () => {
  const r = run([day({
    incidents: ledgers(5, "missed", 25000),
    ledgerStats: [
      ...[0, 1, 2, 3, 4].map((i) => stat(1000 + i, 400)),
      stat(2000, 900), stat(2001, 1100),
    ],
  })]);
  assert.equal(r.network.onOwnIncidentLedgers.n, 5);
  assert.equal(r.network.onPeerIncidentLedgers.n, 2);
  // Median von [900, 1100] = 900 + (1100 - 900) * 0,5 = 1000.
  assert.equal(r.network.onPeerIncidentLedgers.median, 1000);
});

test("Streuung der Distanz trennt konstanten Versatz von variablem Pfad", () => {
  const delays = [21000, 40000, 60000, 90000, 120000];
  const r = run([day({
    incidents: delays.map((dly, i) => inc(1000 + i, "missed", dly)),
    ledgerStats: delays.map((_, i) => stat(1000 + i, 400)),
  })]);
  // Distanzen: 20600, 39600, 59600, 89600, 119600. Median 59600;
  // P90 = a[3] + (a[4] - a[3]) * 0,6 = 89600 + 30000 * 0,6 = 107600; Streuung 48000.
  assert.equal(r.comparison.behind.median, 59600);
  assert.equal(r.comparison.behind.p90, 107600);
  assert.equal(r.pattern.kind, "variable-delay");
  assert.equal(r.pattern.spreadMs, 48000);
  assert.equal(r.pattern.samples, 5);
});

test("zu wenige eigene Votes mit Netzreferenz liefern kein Muster", () => {
  const r = run([day({ incidents: ledgers(5, "missed", null) })]);
  assert.equal(r.pattern.kind, "no-delay-data");
  assert.equal(r.pattern.samples, 0);
  assert.equal(r.comparison.behind.n, 0);
});

test("Tageslimits der Spaetvotes werden als Tage gezaehlt, nicht verschluckt", () => {
  const r = run([
    day({ incidents: ledgers(5, "missed", 30000), lateVotes: [], lateVotesTruncated: true }),
    day({ date: "2026-10-15", incidents: [], lateVotes: [], lateVotesTruncated: true }),
  ]);
  assert.equal(r.coverage.truncatedDays, 2);
  assert.equal(r.coverage.daysRecorded, 2);
  assert.equal(r.thresholds.ringLedgers, 512);
});

test("jede Klasse hat ein Ausgabefeld - UI und Engine laufen nicht auseinander", () => {
  const r = run([day({ incidents: ledgers(5, "missed", 30000) })]);
  for (const k of LATENCY_CLASSES) {
    assert.ok(k in r.classes, "Klasse ohne Feld: " + k);
    assert.ok(Number.isFinite(r.classes[k + "Share"]), "Klasse ohne Anteil: " + k);
  }
});
