import { test } from "node:test";
import assert from "node:assert/strict";
import {
  peerBenchmark, quantile, PEER_TYPES, PEER_ALL_TYPES, PEER_VERDICTS,
  PEER_AUTHORITIES, PEER_REASONS, PEER_MIN_LEDGERS, PEER_MIN_PEERS,
} from "./validator-peer-benchmark.mjs";

const HOUR = 3600000;
const NOW = Date.parse("2026-10-16T12:00:00.000Z");
const H0 = Math.floor(NOW / HOUR);
const OWN = "nOWNnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnOWN";
const PEERS = Array.from({ length: 10 }, (_, i) => "nP" + String(i + 1).padStart(2, "0") + "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx");

/* Tagesobjekt mit 24 Stunden-Buckets, die genau bis NOW reichen: Fenster 24h = 24 volle
 * Stunden, also frac 1 - jede Zahl in diesen Tests ist damit nachrechnbar. */
function day(hours, extra = {}) {
  const hourly = {};
  hours.forEach((h, i) => { hourly[H0 - 24 + i] = h; });
  return { date: "2026-10-16", ledgers: 0, quorumFail: 0, validators: {}, incidents: [], gaps: [],
    firstMs: (H0 - 24) * HOUR, lastMs: NOW, hourly, ...extra };
}
const bucket = (l, v) => ({ l, v });
const c = (ok, missed = 0, partial = 0, wrongHash = 0, noQuorum = 0) => ({ ok, partial, missed, wrongHash, noQuorum });

// 24 Stunden, je 100 Ledger: own 12 Misses je Stunde, jeder Peer 1 Miss je Stunde.
function fixture({ ownPerHour = 12, peerPerHour = 1, ownKey = "missed", peerKey = "missed" } = {}) {
  const hours = [];
  for (let i = 0; i < 24; i += 1) {
    const v = { [OWN]: c(100 - ownPerHour, ownKey === "missed" ? ownPerHour : 0, ownKey === "partial" ? ownPerHour : 0, 0, ownKey === "noQuorum" ? ownPerHour : 0) };
    for (const p of PEERS) v[p] = c(100 - peerPerHour, peerKey === "missed" ? peerPerHour : 0, peerKey === "partial" ? peerPerHour : 0, 0, peerKey === "noQuorum" ? peerPerHour : 0);
    hours.push(bucket(100, v));
  }
  return [day(hours)];
}
const run = (days, master = OWN, range = "24h") => peerBenchmark(days, master, { range, now: NOW });

test("Quantil: lineare Interpolation von Hand nachgerechnet", () => {
  const a = [0.001, 0.002, 0.003, 0.004, 0.005];
  assert.equal(quantile(a, 0.5), 0.003);
  // pos = 0.9 * 4 = 3.6 -> 0.004 + 0.6 * (0.005 - 0.004) = 0.0046
  assert.equal(Math.round(quantile(a, 0.9) * 1e6), 4600);
  assert.equal(quantile(a, 0), 0.001);
  assert.equal(quantile(a, 1), 0.005);
  assert.equal(quantile([5], 0.9), 5);
  assert.equal(quantile([], 0.5), null);
  assert.equal(quantile([9, 1, 5], 0.5), 5, 'unsortierte Eingabe wird sortiert');
});

test("Peer-Benchmark: outlier, weil die eigene Rate die Netz-Grundrate um ein Vielfaches uebersteigt", () => {
  const r = run(fixture());
  // own: 24 * 12 = 288 Misses auf 24 * 100 = 2400 beobachtete Ledger -> Rate 0,12
  assert.equal(r.own.failures, 288);
  assert.equal(r.own.observed, 2400);
  assert.equal(r.own.rate, 0.12);
  // Peers: je 24 Misses auf 2400 -> alle 0,01; median = p90 = 0,01
  assert.equal(r.peers.count, 10);
  assert.equal(r.peers.medianRate, 0.01);
  assert.equal(r.peers.p90Rate, 0.01);
  assert.equal(r.comparison.ratioToMedian, 12);
  // excess = 288 - 2400 * 0,01 = 264
  assert.equal(r.comparison.excessFailures, 264);
  // z = (288 - 24 - 0,5) / sqrt(2400 * 0,01 * 0,99) = 263,5 / 4,8744 = 54,06
  assert.ok(Math.abs(r.comparison.z - 54.058) < 0.01, 'z ' + r.comparison.z);
  assert.ok(r.comparison.pValue < 1e-6, 'pValue ' + r.comparison.pValue);
  assert.equal(r.comparison.percentile, 1);
  assert.equal(r.comparison.peersAbove, 0);
  assert.equal(r.verdict, "outlier");
  assert.equal(r.verdictReason, "rate-above-peer-p90");
  assert.equal(r.verdictAuthority, "trace-hourly");
  assert.equal(r.comparison.direction, "above-baseline");
});

/* Der Fall VET (2026-10-16): ein Knoten unter der Netz-Grundrate. Die einseitige Wahrscheinlichkeit
 * "mindestens so schlecht" war hier 1,000000 und stand als z = -17,3 p = 1,0000 da - die groesste
 * Abweichung des Fensters als keine Aussage. p ist einseitig in der RICHTUNG, die gemessen wurde. */
test("Peer-Benchmark: unter der Grundrate ist eine Richtung, kein p von 1", () => {
  const r = run(fixture({ ownPerHour: 0 }));
  // own 0 Misses auf 2400 Ledger; Peers 10 x 24 Misses auf 10 x 2400 -> pooled 240 / 24000 = 0,01
  assert.equal(r.own.failures, 0);
  assert.equal(r.peers.pooledRate, 0.01);
  // z = (0 - 2400 * 0,01 - 0,5) / sqrt(2400 * 0,01 * 0,99) = -24,5 / 4,87442 = -5,026
  assert.ok(Math.abs(r.comparison.z + 5.026) < 0.01, 'z ' + r.comparison.z);
  assert.equal(r.comparison.direction, "below-baseline");
  assert.ok(r.comparison.pValue < 1e-3, 'pValue ' + r.comparison.pValue + ' - die Abweichung nach unten ist signifikant');
  assert.ok(r.comparison.excessFailures < 0, 'weniger Ausfaelle als die Grundrate muss negativ bleiben');
  assert.equal(r.verdict, "peer-baseline");
  assert.equal(r.verdictReason, "rate-below-peer-median");
});

test("Peer-Benchmark: gleiche Rate wie der Rest ist peer-baseline, nicht 'auffaellig'", () => {
  const r = run(fixture({ ownPerHour: 1 }));
  assert.equal(r.own.rate, 0.01);
  assert.equal(r.peers.medianRate, 0.01);
  assert.equal(r.comparison.ratioToMedian, 1);
  // z = (24 - 24 - 0,5) / 4,8744 = -0,103
  assert.ok(Math.abs(r.comparison.z + 0.103) < 0.01, 'z ' + r.comparison.z);
  assert.equal(r.verdict, "peer-baseline");
  assert.equal(r.verdictReason, "rate-within-peer-band");
});

test("Stichproben-Grenze: zu wenige eigene Ledger ist ein Urteil, keine 0-Rate", () => {
  const days = [day([bucket(100, { [OWN]: c(90, 10), ...Object.fromEntries(PEERS.map((p) => [p, c(99, 1)])) })])];
  const r = run(days);
  assert.equal(r.verdict, "insufficient-sample");
  assert.equal(r.verdictReason, "below-minimum-ledgers");
  assert.equal(r.sample.observed, 100);
  assert.equal(r.peers, null, 'ohne eigene Stichprobe gibt es keinen Vergleich');
  assert.equal(r.comparison, null);
  assert.ok(PEER_MIN_LEDGERS >= 100);
});

test("Stichproben-Grenze: zu kleine Vergleichsgruppe faellt das Urteil nicht", () => {
  const hours = [];
  for (let i = 0; i < 24; i += 1) {
    const v = { [OWN]: c(88, 12), [PEERS[0]]: c(99, 1), [PEERS[1]]: c(99, 1), [PEERS[2]]: c(99, 1), nLOWxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx: c(4, 1) };
    hours.push(bucket(100, v));
  }
  const r = run([day(hours)]);
  assert.equal(r.sample.observed, 2400, 'eigene Stichprobe reicht');
  assert.equal(r.peers, null);
  assert.equal(r.verdict, "insufficient-sample");
  assert.equal(r.verdictReason, "below-minimum-peers");
  assert.equal(r.sample.peers, 3, 'der Peer mit 100 Ledgern zaehlt nicht mit (unter PEER_MIN_LEDGERS ' + PEER_MIN_LEDGERS + ')');
  assert.equal(PEER_MIN_PEERS, 5);
});

test("Keine Beobachtung: nicht-observed ist ein eigener Zustand, nicht Rate 0", () => {
  const r = run(fixture(), "nABWESENDxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx");
  assert.equal(r.verdict, "not-observed");
  assert.equal(r.verdictReason, "no-recorded-ledgers");
  assert.equal(r.verdictAuthority, "none");
  assert.equal(r.own, null);
  assert.equal(r.comparison, null);
});

test("no-quorum ist Erfassungsluecke, nicht Knotenrate: ein Knoten nur mit no-quorum ist baseline", () => {
  const r = run(fixture({ ownPerHour: 12, ownKey: "noQuorum" }));
  assert.equal(r.own.noQuorum, 288);
  assert.equal(r.own.failures, 0, 'no-quorum darf nicht in die knotenzurechenbare Rate');
  assert.equal(r.own.rate, 0);
  assert.equal(r.verdict, "peer-baseline");
  assert.equal(r.verdictReason, "rate-below-peer-median");
  assert.equal(r.network.ownNoQuorumRate, 0.12);
  assert.equal(r.network.peerMedianNoQuorumRate, 0);
  assert.match(r.network.note, /bewiesen geschlossen/, "die Begruendung muss am Stream-Beweis haengen");
  assert.match(r.network.note, /validierten Stream/);
});

test("Typ-Ebene: wrong-hash-Herausragen bleibt sichtbar, obwohl missed dominiert", () => {
  const days = fixture({ ownPerHour: 1 });
  // Eine Stunde mit 20 wrong-hash bei diesem Knoten; jeder Peer hat in derselben Stunde
  // einen wrong-hash, damit die Grundrate nicht 0 ist (gegen 0 gibt es keinen z-Wert).
  const hk = H0 - 1;
  days[0].hourly[hk].v[OWN] = c(79, 1, 0, 20);
  for (const p of PEERS) days[0].hourly[hk].v[p] = c(98, 1, 0, 1);
  const r = run(days);
  const wh = r.types.find((t) => t.type === "wrongHash");
  assert.equal(wh.own, 20);
  assert.equal(wh.abovePeerP90, true);
  // peerR = 10 / 24000; z = (20 - 2400 * peerR - 0,5) / sqrt(2400 * peerR * (1 - peerR)) = 18,5
  assert.ok(Math.abs(wh.z - 18.504) < 0.01, 'wrong-hash z ' + wh.z);
  assert.equal(wh.peerRate, 0.000417, 'peerRate auf 6 Nachkommastellen wie alle Rate-Felder');
  const missed = r.types.find((t) => t.type === "missed");
  assert.equal(missed.abovePeerP90, false, 'missed ist genau die Netz-Grundrate - kein Herausragen');
  assert.deepEqual(r.types.map((t) => t.type), PEER_TYPES);
});

test("Alleinstunden: nur die Stunde, in der die Peers sauber blieben, wird gemeldet", () => {
  const hours = [];
  for (let i = 0; i < 24; i += 1) {
    const alone = i === 0;
    const v = { [OWN]: alone ? c(95, 5) : c(95, 5) };
    for (const p of PEERS) v[p] = alone ? c(100) : c(95, 5);
    hours.push(bucket(100, v));
  }
  const r = run([day(hours)]);
  assert.equal(r.aloneHours.length, 1, 'eine Stunde ohne Peer-Ausfall');
  assert.equal(r.aloneHours[0].hourMs, (H0 - 24) * HOUR);
  assert.equal(r.aloneHours[0].ownFailures, 5);
  assert.equal(r.aloneHours[0].observedPeers, 10);
});

test("Kohoere: solo gegen getheilt wird je Vorfall-Ledger gezaehlt", () => {
  const t = (i) => (H0 - 2) * HOUR + i * 1000;
  const days = fixture();
  days[0].incidents = [
    { l: 1000, m: OWN, t: t(1), type: "missed", r: [] },
    { l: 1000, m: PEERS[0], t: t(1), type: "missed", r: [] },
    { l: 1000, m: PEERS[1], t: t(1), type: "missed", r: [] },
    { l: 1000, m: PEERS[2], t: t(1), type: "missed", r: [] },
    { l: 1001, m: OWN, t: t(2), type: "missed", r: [] },
    { l: 1002, m: OWN, t: t(3), type: "missed", r: [] },
    { l: 1003, m: PEERS[3], t: t(4), type: "missed", r: [] },
  ];
  const r = run(days);
  assert.equal(r.cohort.ledgers, 3);
  assert.equal(r.cohort.solo, 2);
  assert.equal(r.cohort.shared, 1);
  assert.equal(r.cohort.maxCohort, 4);
  assert.equal(r.cohort.medianCohort, 1);
  // 2 von 3 = 0,6667
  assert.equal(r.cohort.soloShare, 0.6667);
  assert.equal(r.cohort.unrecorded, 0);
});

test("Fenster-Grenze: eine Stunde vor dem Fenster darf nicht in die Rate", () => {
  const days = fixture();
  // Stunde H0-25 endet exakt am Fensteranfang -> overlap 0 -> raus.
  days[0].hourly[H0 - 25] = bucket(100, { [OWN]: c(50, 50), ...Object.fromEntries(PEERS.map((p) => [p, c(100)])) });
  const r = run(days);
  assert.equal(r.own.failures, 288, 'die Vorfallstunde vor dem Fenster waere ein Off-by-One');
  assert.equal(r.own.observed, 2400);
});

test("Altbestand ohne Stunden-Buckets: geschaetzt wird als geschaetzt ausgewiesen", () => {
  const validators = { [OWN]: c(900, 100) };
  for (const p of PEERS) validators[p] = c(990, 10);
  const days = [{ date: "2026-10-15", ledgers: 1000, quorumFail: 0, validators, incidents: [], gaps: [], firstMs: NOW - 10 * HOUR, lastMs: NOW - HOUR }];
  const r = run(days);
  assert.equal(r.verdictAuthority, "trace-daily");
  assert.equal(r.sample.estimated, true);
  assert.equal(r.sample.observedHourly, 0);
  assert.equal(r.sample.observedDaily, 1000);
  assert.equal(r.own.observed, 1000);
  assert.equal(r.own.failures, 100);
  // z = (100 - 10 - 0,5) / sqrt(1000 * 0,01 * 0,99) = 89,5 / 3,1463 = 28,45
  assert.ok(Math.abs(r.comparison.z - 28.446) < 0.01, 'z ' + r.comparison.z);
  assert.equal(r.verdict, "outlier");
});

test("Endliche Mengen: jedes Urteil, jede Autoritaet und jeder Grund ist deklariert", () => {
  const cases = [
    run(fixture()), run(fixture({ ownPerHour: 1 })), run(fixture({ ownKey: "noQuorum" })),
    run([day([bucket(100, { [OWN]: c(90, 10) })])]), run(fixture(), "nABWESENDxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"),
  ];
  for (const r of cases) {
    assert.ok(PEER_VERDICTS.includes(r.verdict), 'Urteil nicht deklariert: ' + r.verdict);
    assert.ok(PEER_REASONS.includes(r.verdictReason), 'Grund nicht deklariert: ' + r.verdictReason);
    assert.ok(PEER_AUTHORITIES.includes(r.verdictAuthority), 'Autoritaet nicht deklariert: ' + r.verdictAuthority);
  }
  assert.deepEqual(PEER_ALL_TYPES, [...PEER_TYPES, "noQuorum"]);
});

test("Peer-Liste: schlechteste und beste Knoten sind sortiert und ohne Doppelzaehlung des eigenen", () => {
  const r = run(fixture());
  assert.equal(r.peerList.worst.length, 8);
  assert.equal(r.peerList.best.length, 8);
  assert.ok(r.peerList.worst.every((p) => p.master !== OWN), 'der eigene Knoten ist nicht sein eigener Peer');
  assert.ok(r.peerList.worst.every((p) => p.observed >= PEER_MIN_LEDGERS));
  const rates = r.peerList.worst.map((p) => p.rate);
  assert.deepEqual(rates, [...rates].sort((a, b) => b - a));
  assert.equal(r.peerList.worst[0].master < r.peerList.worst[1].master || r.peerList.worst[0].rate > r.peerList.worst[1].rate, true);
});

test("Halb gedeckter Tag: die Vorfaelle vor den Stunden-Buckets zaehlen mit", () => {
  const days = fixture();
  for (let i = 0; i < 6; i += 1) delete days[0].hourly[H0 - 24 + i]; // sechs Stunden ohne Bucket
  days[0].validators = { [OWN]: c(2112, 288) };
  for (const p of PEERS) days[0].validators[p] = c(2376, 24);
  const r = run(days);
  assert.equal(r.sample.daysPartial, 1, "halb gedeckter Tag muss benannt sein");
  assert.equal(r.sample.observedHourly, 1800);
  assert.equal(r.sample.observedDaily, 600);
  assert.equal(r.sample.estimated, true);
  assert.equal(r.own.observed, 2400, "Nenner und Zaehler dieselbe Ledger-Menge");
  assert.equal(r.own.failures, 288, "ohne den Rest waeren es 216 - sechs Vorfallstunden fehlten still");
  assert.equal(r.peers.observed, 24000);
  assert.equal(r.peers.failures, 240);
});
