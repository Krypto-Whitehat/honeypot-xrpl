// lib/validator-divergence.test.mjs — Tests der Divergenz-Ebene (Hash-Linien, Feature-Ledger).
// Alle Zahlen sind von Hand nachgerechnet; die Kommentare tragen die Rechnung, damit ein geaenderter
// Schwellwert nicht still einen anderen Befund erzeugt.
import test from "node:test";
import assert from "node:assert/strict";
import {
  divergenceProfile, lineageOf, featureLabel,
  LINEAGES, DIVERGENCE_VERDICTS, DIVERGENCE_AUTHORITIES, DIVERGENCE_REASONS, DIVERGENCE_GAPS, DIVERGENCE_GUIDANCE,
  DIVERGENCE_DEFAULTS,
} from "./validator-divergence.mjs";

const H = (c) => c.repeat(64);
const ACCEPTED = H("a");                       // Netzmehrheit
const RUNNER = H("b");                         // zweitstaerkste Linie
const OWN1 = H("c");
const OWN2 = H("d");
const OWN3 = H("e");
const OWN4 = H("f");
const OWN5 = H("9");
// Amendment-ID im Stream ist 64 Hex-Zeichen lang; die Engine verwirft alles andere.
// H("ab") waere 128 Zeichen lang und damit kein gueltiger Hex - still ein leerer Amendment-Listeneintrag.
const AM1 = "ab".repeat(32);
const AM1KEY = "amendment:" + AM1.toUpperCase();
const MINE = "nMINE000000000000000000000000000000000000000000000000000000000";
const PEER = "nPEER0000000000000000000000000000000000000000000000000000000000";
const NOW = Date.parse("2026-10-16T12:00:00Z");
const T1 = NOW - 3600000;
const T2 = NOW - 7200000;
const OLD = NOW - 2 * 86400000;                // außerhalb 24h, innerhalb 7d

function day(o = {}) {
  return {
    date: o.date ?? "2026-10-16",
    ledgers: o.ledgers ?? 1000, quorumFail: 0, validators: {}, incidents: o.incidents ?? [], gaps: [],
    lastLedger: null, firstMs: null, lastMs: null, hourly: {},
    ledgerStats: o.ledgerStats ?? [], ledgerStatsTruncated: false,
    incidentLedgers: o.incidentLedgers ?? 0, anomaly: {}, anomalyFail: {}, loadBuckets: [],
    lateVotes: o.lateVotes ?? [], lateVotesTruncated: false,
    // featureLedgers undefined = Altbestand (Ebene nicht erfasst); {} = erfasst, kein Feature-Ledger.
    ...(o.featureLedgers === undefined ? {} : { featureLedgers: o.featureLedgers, featureFail: o.featureFail ?? {} }),
  };
}
const inc = (l, master, type, h, t = T1) => ({ l, m: master, t, type, r: [], vd: null, ...(h === undefined ? {} : { h }) });
const stat = (l, extra = {}, t = T1) => ({ l, t, v: 30, need: 24, top: 28, mg: 4, sp: 1, gap: 4000, gmed: 4000, tx: 100, med: 90, c: { missed: 0, partial: 0, wrongHash: 1, noQuorum: 0 }, sh: null, sev: {}, sweep: null, fv: 900, lv: 3000, ah: ACCEPTED, rh: RUNNER, ...(extra.ah === undefined ? {} : { ah: extra.ah }), ...(extra.rh === undefined ? {} : { rh: extra.rh }), ...(extra.am === undefined ? {} : { am: extra.am }), ...(extra.unl === undefined ? {} : { unl: extra.unl }) });

function checkEnums(r) {
  assert.ok(DIVERGENCE_VERDICTS.includes(r.verdict), "Urteil " + r.verdict + " ist nicht im Enum");
  assert.ok(DIVERGENCE_AUTHORITIES.includes(r.verdictAuthority), "Belegquelle " + r.verdictAuthority + " ist nicht im Enum");
  assert.ok(DIVERGENCE_REASONS.includes(r.verdictReason), "Grund " + r.verdictReason + " ist nicht im Enum");
  for (const g of r.dataGaps) assert.ok(DIVERGENCE_GAPS.includes(g), "Datenluecke " + g + " ist nicht im Enum");
  for (const g of r.guidance) assert.ok(DIVERGENCE_GUIDANCE.includes(g), "Pruefschritt " + g + " ist nicht im Enum");
}

test("Linie: accepted, runner, own und unknown sind verschieden, Hex wird normalisiert", () => {
  assert.equal(lineageOf(ACCEPTED, ACCEPTED, RUNNER), "accepted");
  assert.equal(lineageOf(RUNNER, ACCEPTED, RUNNER), "runner");
  assert.equal(lineageOf(OWN1, ACCEPTED, RUNNER), "own");
  assert.equal(lineageOf(OWN1, ACCEPTED, null), "own", "ohne Runner-Up ist es eine dritte Linie");
  assert.equal(lineageOf(ACCEPTED.toLowerCase(), ACCEPTED, null), "accepted", "Hex-Gross-/Kleinschreibung ist dieselbe Linie");
  assert.equal(lineageOf(null, ACCEPTED, RUNNER), "unknown", "ohne Vote-Hash ist die Frage nicht beantwortbar");
  assert.equal(lineageOf(ACCEPTED, null, null), "unknown", "ohne akzeptierte Hash ist die Frage nicht beantwortbar");
  assert.equal(lineageOf("zz", ACCEPTED, null), "unknown", "kein 64er Hex ist keine Linie");
  assert.deepEqual(LINEAGES, ["accepted", "runner", "own", "unknown"]);
});

test("Altbestand: ohne Vote-Hash und ohne akzeptierte Hash ist die Ebene nicht beantwortbar", () => {
  const d = day({ incidents: [inc(100, MINE, "wrong-hash"), inc(101, MINE, "missed")], incidentLedgers: 2, ledgerStats: [stat(100, { ah: null, rh: null })] });
  const r = divergenceProfile([d], MINE, { range: "24h", now: NOW });
  checkEnums(r);
  assert.equal(r.verdict, "not-recorded");
  assert.equal(r.verdictReason, "hash-lineage-missing");
  assert.equal(r.verdictAuthority, "none");
  assert.ok(r.dataGaps.includes("hash-lineage-not-recorded"));
  assert.ok(r.dataGaps.includes("accepted-hash-not-recorded"), "stat ohne ah ist Altbestand");
  assert.equal(r.coverage.divergences, 0, "ohne Linie darf keine Abweichung zaehlen");
});

test("Rein: Vote auf der Netzmehrheit ist keine Abweichung, auch bei vielen Vorfaellen", () => {
  const d = day({
    incidents: [inc(100, MINE, "partial", ACCEPTED), inc(101, MINE, "wrong-hash", ACCEPTED), inc(102, MINE, "partial", ACCEPTED)],
    incidentLedgers: 3, ledgerStats: [stat(100), stat(101), stat(102)],
  });
  const r = divergenceProfile([d], MINE, { range: "24h", now: NOW });
  checkEnums(r);
  assert.equal(r.verdict, "clean");
  assert.equal(r.verdictReason, "no-divergence-recorded");
  assert.equal(r.lineageCounts.accepted, 3);
  assert.equal(r.coverage.divergences, 0);
});

test("Deterministisch: dieselbe verlorene Linie mehrfach ist ein Build-Befund, kein Ausrutscher", () => {
  const d = day({
    incidents: [inc(100, MINE, "wrong-hash", OWN1), inc(101, MINE, "wrong-hash", OWN1), inc(102, MINE, "wrong-hash", OWN1), inc(103, MINE, "partial", ACCEPTED)],
    incidentLedgers: 4, ledgerStats: [stat(100), stat(101), stat(102), stat(103)],
  });
  const r = divergenceProfile([d], MINE, { range: "24h", now: NOW });
  checkEnums(r);
  assert.equal(r.verdict, "deterministic-divergence");
  assert.equal(r.verdictReason, "same-losing-lineage");
  assert.equal(r.repeated.hash, OWN1.toUpperCase(), "die Engine normalisiert die Hashes gross");
  assert.equal(r.repeated.count, 3, "drei Vorfaelle auf derselben Linie");
  assert.equal(r.coverage.distinctLosingLineages, 1);
  assert.ok(r.guidance.includes("compare-node-build"));
});

test("Geteilte Linie: derselbe verlorene Hash bei zwei Knoten ist ein Gemeinschaftsbefund", () => {
  const d = day({
    incidents: [inc(100, MINE, "wrong-hash", OWN1), inc(100, PEER, "wrong-hash", OWN1), inc(101, MINE, "wrong-hash", OWN2)],
    incidentLedgers: 2, ledgerStats: [stat(100), stat(101)],
  });
  const r = divergenceProfile([d], MINE, { range: "24h", now: NOW });
  checkEnums(r);
  assert.equal(r.verdict, "shared-lineage");
  assert.equal(r.shared.hash, OWN1.toUpperCase(), "geteilte Linie wird ebenfalls normalisiert");
  assert.equal(r.shared.masterCount, 2);
  assert.equal(r.shared.count, 2);
  assert.ok(r.shared.masters.includes(PEER));
  assert.ok(r.guidance.includes("check-peer-lineage"));
});

test("Runner-Up-Linie: Abweichung auf die zweitstaerkste Linie ist eine Netzspaltung, keine eigene Linie", () => {
  const d = day({
    incidents: [inc(100, MINE, "wrong-hash", RUNNER), inc(101, MINE, "wrong-hash", RUNNER), inc(102, MINE, "wrong-hash", RUNNER), inc(103, MINE, "wrong-hash", RUNNER), inc(104, MINE, "wrong-hash", RUNNER)],
    incidentLedgers: 5, ledgerStats: [stat(100), stat(101), stat(102), stat(103), stat(104)],
  });
  const r = divergenceProfile([d], MINE, { range: "24h", now: NOW });
  assert.equal(r.verdict, "deterministic-divergence", "dieselbe Runner-Up-Linie ist ebenfalls eine wiederholte Linie");
  assert.equal(r.lineageCounts.runner, 5);
  assert.equal(r.lineageCounts.own, 0);
});

test("Duenn: eine einzelne Abweichung ohne Wiederholung wird nicht zum Urteil verdichtet", () => {
  const d = day({
    incidents: [inc(100, MINE, "wrong-hash", OWN1), inc(101, MINE, "wrong-hash", OWN2)],
    incidentLedgers: 2, ledgerStats: [stat(100), stat(101)],
  });
  const r = divergenceProfile([d], MINE, { range: "24h", now: NOW });
  checkEnums(r);
  assert.equal(r.verdict, "insufficient-sample");
  assert.equal(r.verdictReason, "too-few-divergences");
  assert.equal(r.coverage.divergences, 2);
});

test("Verschieden: mehrere Abweichungen auf je eigener Linie bleiben eine Verteilung ohne Muster", () => {
  const d = day({
    incidents: [inc(100, MINE, "wrong-hash", OWN1), inc(101, MINE, "wrong-hash", OWN2), inc(102, MINE, "wrong-hash", OWN3), inc(103, MINE, "wrong-hash", OWN4), inc(104, MINE, "wrong-hash", OWN5)],
    incidentLedgers: 5, ledgerStats: [stat(100), stat(101), stat(102), stat(103), stat(104)],
  });
  const r = divergenceProfile([d], MINE, { range: "24h", now: NOW });
  checkEnums(r);
  assert.equal(r.verdict, "transient-divergence");
  assert.equal(r.coverage.divergences, 5);
  assert.equal(r.coverage.distinctLosingLineages, 5);
  assert.equal(r.repeated, null);
  assert.equal(r.shared, null);
});

test("Feature-Ledger: Amendment-Ledger fallen haeufiger aus, und mein Knoten divergiert dort", () => {
  // Rechnung: 200 von 1000 Ledgern traegen das Amendment, 60 davon mit Ausfall -> 0,30.
  // Vergleich: 800 Ledger ohne Amendment, 40 mit Ausfall -> 0,05. Lift = 0,30 / 0,05 = 6,00.
  const ledgers = [100, 101, 102, 103, 104];
  const d = day({
    ledgers: 1000, incidentLedgers: 100,
    incidents: ledgers.map((l, i) => inc(l, MINE, "wrong-hash", [OWN1, OWN2, OWN3, OWN4, OWN5][i])),
    ledgerStats: ledgers.map((l) => stat(l, { am: [AM1] })),
    featureLedgers: { [AM1KEY]: 200 }, featureFail: { [AM1KEY]: 60 },
  });
  const r = divergenceProfile([d], MINE, { range: "24h", now: NOW });
  checkEnums(r);
  assert.equal(r.verdict, "feature-linked");
  assert.equal(r.verdictAuthority, "trace-feature-counters");
  const f = r.features.find((x) => x.key === AM1KEY);
  assert.equal(f.ledgers, 200);
  assert.equal(f.failLedgers, 60);
  assert.equal(f.plainLedgers, 800);
  assert.equal(f.plainFailLedgers, 40);
  assert.equal(f.rateWith, 0.3);
  assert.equal(f.rateWithout, 0.05);
  assert.equal(f.lift, 6);
  assert.equal(f.reliable, true);
  assert.equal(f.mineLedgers, 5);
  assert.equal(f.mineDivergences, 5);
  assert.equal(f.amendment, AM1.toUpperCase());
  assert.ok(r.guidance.includes("check-amendment-support"));
});

test("Feature-Nenner: Tage ohne Feature-Zaehler werden nicht in die Grundgesamtheit gemischt", () => {
  const ledgers = [100, 101, 102, 103, 104];
  const withFeat = day({
    ledgers: 1000, incidentLedgers: 100,
    incidents: ledgers.map((l, i) => inc(l, MINE, "wrong-hash", [OWN1, OWN2, OWN3, OWN4, OWN5][i])),
    ledgerStats: ledgers.map((l) => stat(l, { am: [AM1] })),
    featureLedgers: { [AM1KEY]: 200 }, featureFail: { [AM1KEY]: 60 },
  });
  // Altbestand mit 5000 Ledgern: wuerde er mitgezaehlt, waere die Vergleichsgruppe 5800 und der
  // Lift 0,30 / (40/5800 = 0,0069) = 43 - eine Entlastung, die aus keiner Messung kommt.
  const legacy = day({ date: "2026-10-15", ledgers: 5000, incidentLedgers: 200 });
  const r = divergenceProfile([legacy, withFeat], MINE, { range: "7d", now: NOW });
  assert.equal(r.coverage.totalLedgers, 1000, "nur Tage mit Feature-Zaehler zaehlen");
  assert.equal(r.coverage.incidentLedgers, 100);
  assert.equal(r.coverage.daysWithFeatureCounters, 1);
  assert.equal(r.coverage.daysWithoutFeatureCounters, 1);
  const f = r.features.find((x) => x.key === AM1KEY);
  assert.equal(f.lift, 6, "der Lift bleibt die Rechnung der beobachteten Grundgesamtheit");
});

test("UNLModify: eigene Beruehrung ist eine Zahl, nicht nur ein Ledger-Fakt", () => {
  // 30 von 1000 Ledgern sind UNLModify-Ledger, 12 davon mit Ausfall -> 0,40.
  // 970 ohne, 88 mit Ausfall -> 88/970 = 0,090722. Lift = 0,40 / 0,090722 = 4,41.
  const d = day({
    ledgers: 1000, incidentLedgers: 100,
    incidents: [inc(100, MINE, "missed", null), inc(101, MINE, "missed", null), inc(102, MINE, "missed", null)],
    ledgerStats: [stat(100, { unl: true }), stat(101, { unl: true }), stat(102, { unl: true })],
    featureLedgers: { "unl-modify": 30 }, featureFail: { "unl-modify": 12 },
  });
  const r = divergenceProfile([d], MINE, { range: "24h", now: NOW });
  const f = r.features.find((x) => x.key === "unl-modify");
  assert.equal(f.label, "UNLModify");
  assert.equal(f.unlModify, true);
  assert.equal(f.lift, 4.41);
  assert.equal(f.reliable, true);
  assert.equal(f.mineLedgers, 3);
  assert.equal(f.mineLinked, true, "ab der Schwelle ist die eigene Beruehrung eine Zahl");
  assert.ok(r.guidance.includes("check-unl-handling"));
});

test("Kein Feature-Ledger: erfasste Zaehler ohne Feature sind eine Messung, keine Datenluecke", () => {
  const d = day({ incidents: [inc(100, MINE, "partial", ACCEPTED)], incidentLedgers: 1, ledgerStats: [stat(100)], featureLedgers: {}, featureFail: {} });
  const r = divergenceProfile([d], MINE, { range: "24h", now: NOW });
  assert.equal(r.coverage.daysWithFeatureCounters, 1);
  assert.ok(!r.dataGaps.includes("feature-counters-not-recorded"));
  assert.equal(r.totalFeatures, 0);
});

test("Spaeter Vote auf der Netzmehrheit: verpasst heisst hier langsam, nicht ausgefallen", () => {
  const late = [100, 101, 102, 103, 104].map((l) => ({ l, m: MINE, ms: 24000, t: NOW - 1000, h: ACCEPTED, fu: true }));
  const d = day({
    incidents: [100, 101, 102, 103, 104].map((l) => inc(l, MINE, "missed", null)),
    incidentLedgers: 5, ledgerStats: [100, 101, 102, 103, 104].map((l) => stat(l)), lateVotes: late,
  });
  const r = divergenceProfile([d], MINE, { range: "24h", now: NOW });
  checkEnums(r);
  assert.equal(r.verdict, "tip-lag");
  assert.equal(r.verdictReason, "late-votes-on-accepted-lineage");
  assert.equal(r.verdictAuthority, "trace-late-votes");
  assert.equal(r.lateLineage.accepted, 5);
  assert.equal(r.lateLineage.divergent, 0);
  assert.equal(r.lineageCounts.noVote, 5, "fuenf Vorfaelle ohne Vote sind eine Messung, kein unknown");
  assert.ok(r.guidance.includes("check-vote-path"));
});

test("Spaeter Vote auf anderer Linie: das ist ein Standproblem, kein Pfadproblem", () => {
  const late = [100, 101].map((l) => ({ l, m: MINE, ms: 21000, t: NOW - 1000, h: OWN1, fu: true }));
  const d = day({ incidents: [inc(100, MINE, "missed", null), inc(101, MINE, "missed", null)], incidentLedgers: 2, ledgerStats: [stat(100), stat(101)], lateVotes: late });
  const r = divergenceProfile([d], MINE, { range: "24h", now: NOW });
  assert.equal(r.lateLineage.divergent, 2);
  assert.equal(r.lateLineage.accepted, 0);
  assert.notEqual(r.verdict, "tip-lag", "spaete Votes auf eigener Linie sind kein Pfadproblem");
});

test("Ohne Spaetaufzeichnung bleibt die Spaet-Linie eine Luecke, nicht 'kein spaeter Vote'", () => {
  const d = day({ incidents: [inc(100, MINE, "missed", null)], incidentLedgers: 1, ledgerStats: [stat(100)] });
  delete d.lateVotes;
  const r = divergenceProfile([d], MINE, { range: "24h", now: NOW });
  assert.equal(r.lateLineage.recorded, false);
  assert.ok(r.dataGaps.includes("late-vote-lineage-not-recorded"));
});

test("Fenster: ein Vorfall vor zwei Tagen ist ausserhalb 24h und innerhalb 7d", () => {
  const d = day({
    incidents: [inc(100, MINE, "wrong-hash", OWN1, T1), inc(101, MINE, "wrong-hash", OWN2, OLD)],
    incidentLedgers: 2, ledgerStats: [stat(100), stat(101, {}, OLD)],
  });
  const r24 = divergenceProfile([d], MINE, { range: "24h", now: NOW });
  const r7 = divergenceProfile([d], MINE, { range: "7d", now: NOW });
  assert.equal(r24.coverage.incidents, 1);
  assert.equal(r7.coverage.incidents, 2);
  assert.equal(r7.coverage.divergences, 2);
});

test("Kein Vote und nicht erfasst sind verschiedene Aussagen", () => {
  const d = day({
    incidents: [inc(100, MINE, "missed", null), inc(101, MINE, "missed")],
    incidentLedgers: 2, ledgerStats: [stat(100), stat(101)],
  });
  const r = divergenceProfile([d], MINE, { range: "24h", now: NOW });
  assert.equal(r.lineageCounts.noVote, 1, "h null = gemessen, kein Vote");
  assert.equal(r.lineageCounts.unknown, 1, "h fehlend = Ebene nicht erfasst");
  assert.equal(r.coverage.incidentsWithVoteHash, 0);
});

test("Label: Amendment-ID wird nicht zu einem erfundenen Namen", () => {
  assert.equal(featureLabel("unl-modify"), "UNLModify");
  assert.equal(featureLabel(AM1KEY), "Amendment " + AM1.slice(0, 8).toUpperCase().toLowerCase());
  assert.ok(!featureLabel(AM1KEY).includes(AM1.slice(8)), "nur ein Kurzform-Kuerzel, nicht die ganze ID");
});

test("Schwellwerte sind Teil des Ergebnisses, damit ein Urteil nachpruefbar bleibt", () => {
  const r = divergenceProfile([day({})], MINE, { range: "24h", now: NOW });
  assert.deepEqual(r.thresholds, {
    minIncidents: DIVERGENCE_DEFAULTS.minIncidents, minRepeated: DIVERGENCE_DEFAULTS.minRepeated,
    minClusterMasters: DIVERGENCE_DEFAULTS.minClusterMasters, minFeatureLedgers: DIVERGENCE_DEFAULTS.minFeatureLedgers,
    minFeatureFails: DIVERGENCE_DEFAULTS.minFeatureFails, minMineLedgers: DIVERGENCE_DEFAULTS.minMineLedgers,
  });
  assert.equal(r.verdict, "not-recorded", "ein leerer Tag beantwortet nichts");
});

test("Leerlauf: null und undefined in den Tageszaehlern werden nicht zu NaN", () => {
  const d = day({});
  d.ledgers = null; d.incidentLedgers = null; d.featureLedgers = { [AM1KEY]: null }; d.featureFail = { [AM1KEY]: null };
  const r = divergenceProfile([d], MINE, { range: "24h", now: NOW });
  assert.equal(r.coverage.totalLedgers, 0);
  assert.equal(r.coverage.incidentLedgers, 0);
  const f = r.features.find((x) => x.key === AM1KEY);
  assert.equal(f.ledgers, 0);
  assert.equal(f.lift, null);
  assert.equal(f.reliable, false);
});
