// lib/validator-cause.test.mjs - die Gewichtung der Ursachen-Engine, nachgerechnet.
//
// Diese Engine entscheidet, welcher Grund einem Betreiber als wahrscheinlichster gezeigt wird
// und wie sicher er ist. Jede dieser Entscheidungen haengt an einer Gewichtssumme. Die Summen
// sind hier von Hand durchgerechnet: Grundwert der Belegstaerke, plus selbstaendige Quelle, plus
// Beobachtungsstaerke, minus Entlastung, mal Konfidenzschwelle.
import test from "node:test";
import assert from "node:assert/strict";
import {
  CAUSE_CHECKS, CAUSE_CONFIDENCE, CAUSE_DEFAULTS, CAUSE_GAPS, CAUSE_KINDS, CAUSE_LAYERS,
  CAUSE_STRENGTHS, CAUSE_TAGS, UNEXPLAINED, causeLedger, hourCells,
} from "./validator-cause.mjs";
import { SERIES_VERDICTS } from "./validator-diagnose.mjs";
import { TRACE_DEFAULTS, marginBucketLabel } from "./validator-trace.mjs";

const NOW = 1792000000000; // 2026-10-14T17:46:40Z -> UTC-Stunde 17
const T = NOW - 1000;
const MASTER = "nHTEST";

// scope 'unknown' ist der neutrale Fall: die Kohorten-Ortung soll nur urteilen, wenn der Test
// sie auch setzt. Sonst bekommt jeder Vorfall ein Lokalisierungs-Urteil aus der Default-Angabe.
const row = (over = {}) => ({ ledgerIndex: 1001, timeMs: T, type: "missed", hypotheses: [], scope: "unknown", ...over });
const hyp = (tag, strength, evidence = {}, lift = null) => ({ tag, strength, evidence, lift });
const crit = (ledgerIndex, margin, critical = false, over = {}) => ({
  ledgerIndex, margin, critical, votes: 20, needed: 18, topVotes: 19, runnerVotes: 0, ...over,
});
const qband = (idx, ledgers, failLedgers, over = {}) => ({
  axis: "quorum", idx, label: marginBucketLabel(idx), ledgers, failLedgers,
  networkRate: ledgers > 0 ? failLedgers / ledgers : null, reliable: true, ...over,
});
const surface = (bands) => ({ bands, verdict: "unknown", coverage: {} });
const curveRow = (index, over = {}) => ({
  index, label: "L" + index, ledgers: 100, failLedgers: 10, networkRate: 0.1, cohortMedianRate: 0.05,
  cohortSize: 30, validatorLedgers: 100, validatorFails: 10, validatorRate: 0.1, sample: "ok", ...over,
});
const run = (retrace, context = {}, opts = {}) => causeLedger({
  master: MASTER, range: "24h", days: [], incidents: [], retrace, ...context,
}, opts);
const cand = (r, tag) => r.candidates.find((c) => c.tag === tag) ?? null;

test("Die Belegstaerke ist die Basis des Gewichts - an echten Pfaden nachgerechnet", () => {
  // Jede Stufe wird dort abgelesen, wo die Engine sie wirklich erzeugt. Die Retrace liefert kein
  // 'corroborated' - das entsteht erst, wenn eine zweite Ebene denselben Befund bestaetigt.
  const cases = [
    { strength: "measured", weight: 4, make: () => run([row({ hypotheses: [hyp("quorum-thin", "measured")] })]).rows[0], tag: "quorum-thin" },
    { strength: "corroborated", weight: 3, make: () => run([row()], {
      diagnosis: { criticality: { rows: [crit(1001, 0)] } },
      surface: surface([qband(1, 100, 30), qband(5, 200, 4), qband(6, 100, 6)]),
    }).rows[0], tag: "quorum-band-risk" },
    { strength: "correlated", weight: 2, make: () => run([row({ hypotheses: [hyp("quorum-thin", "correlated")] })]).rows[0], tag: "quorum-thin" },
    { strength: "context", weight: 1, make: () => run([row()], { peer: { verdict: "peer-baseline", comparison: { ratioToMedian: 1.1, percentile: 55 } } }).rows[0], tag: "network-window-localization" },
    { strength: "none", weight: 0, make: () => run([row({ hypotheses: [hyp("quorum-thin", "none")] })]).rows[0], tag: "quorum-thin" },
  ];
  for (const kase of cases) {
    const r = kase.make();
    const c = cand(r, kase.tag);
    assert.ok(c, "Kandidat " + kase.tag + " fehlt");
    assert.equal(c.strength, kase.strength);
    assert.equal(c.weight, kase.weight, kase.strength + " wiegt " + kase.weight);
    const confidence = kase.weight >= 6 ? "high" : kase.weight >= 4 ? "medium" : kase.weight >= 2 ? "low" : "none";
    assert.equal(c.confidence, confidence);
  }
  assert.deepEqual(CAUSE_STRENGTHS, ["measured", "corroborated", "correlated", "context", "none"]);
  assert.deepEqual(CAUSE_CONFIDENCE, ["high", "medium", "low", "none"]);
});

test("Zwei selbstaendige Ebenen heben das Gewicht, dieselbe Ebene nicht zweimal", () => {
  // vote-late aus der Ledger-Ebene (Retrace) und aus der gemessenen Latenz (Timing-Ebene).
  const r = run([row({
    voteDelayMs: 30000,
    hypotheses: [hyp("vote-late", "measured", { voteDelayMs: 30000, graceMs: TRACE_DEFAULTS.graceMs })],
  })]).rows[0];
  const c = cand(r, "vote-late");
  assert.deepEqual(c.layers, ["ledger", "timing"]);
  assert.equal(c.weight, 5); // 4 + 1 fuer die zweite selbstaendige Quelle
  assert.equal(c.confidence, "medium");
  // Die Latenz allein reicht ebenfalls: der Messwert ist da, auch ohne Reason-Tag.
  const solo = run([row({ voteDelayMs: 30000 })]).rows[0];
  const c2 = cand(solo, "vote-late");
  assert.deepEqual(c2.layers, ["timing"]);
  assert.equal(c2.weight, 4);
  assert.equal(solo.verdict, "vote-late");
});

test("Eine Beobachtung mit zuverlaessigem Lift erreicht die hohe Konfidenz", () => {
  const r = run([row({ hypotheses: [hyp("quorum-thin", "measured", { margin: 0 }, { reliable: true })] })]).rows[0];
  const c = cand(r, "quorum-thin");
  assert.equal(c.weight, 5); // 4 + 1 Lift
  assert.equal(c.confidence, "medium");
  const two = run([row({
    voteDelayMs: 30000,
    hypotheses: [hyp("vote-late", "measured", { voteDelayMs: 30000 }, { reliable: true })],
  })]).rows[0];
  assert.equal(cand(two, "vote-late").weight, 6); // 4 + 1 Ebene + 1 Lift
  assert.equal(cand(two, "vote-late").confidence, "high");
});

test("Eine Serien-Einordnung ist nicht die Ledger-Ebene", () => {
  const r = run([row({ hypotheses: [hyp("offline-window", "correlated", { ledgers: 35 })] })]).rows[0];
  const c = cand(r, "offline-window");
  assert.deepEqual(c.layers, ["series"], "Serie darf nicht als Messwert dieses Ledgers zaehlen");
  assert.ok(SERIES_VERDICTS.includes("offline-window"));
  // Beobachtungsstaerke: 35 Ledger am Stueck sind eine Beobachtung, kein Mechanismus-Beweis.
  assert.equal(c.weight, 4); // 2 + 2 fuer >= 15 Ledger
  assert.equal(c.confidence, "medium");
  const short = run([row({ hypotheses: [hyp("brief-outage", "correlated", { ledgers: 6 })] })]).rows[0];
  assert.equal(cand(short, "brief-outage").weight, 3); // 2 + 1 fuer >= 5
  const thin = run([row({ hypotheses: [hyp("brief-outage", "correlated", { ledgers: 2 })] })]).rows[0];
  assert.equal(cand(thin, "brief-outage").weight, 2);
});

test("Ein Etikett ohne Beleg wird kein Urteil", () => {
  const r = run([row({ hypotheses: [hyp("solo-failure", "none", { others: 0 })] })]).rows[0];
  const c = cand(r, "solo-failure");
  assert.equal(c.kind, "category");
  assert.equal(c.weight, 0);
  assert.equal(c.confidence, "none");
  assert.equal(r.verdict, UNEXPLAINED);
  assert.equal(r.verdictKind, "none");
  assert.equal(r.verdictConfidence, "none");
});

test("Entlastung wird abgezogen und kann nicht zum Urteil werden", () => {
  const r = run([row({ hypotheses: [hyp("solo-failure", "none")] })], {
    diagnosis: { criticality: { rows: [crit(1001, 9, false)] } },
  }).rows[0];
  const c = cand(r, "quorum-follow-on");
  assert.equal(c.kind, "exoneration");
  assert.equal(c.strength, "measured");
  assert.equal(c.weight, 3); // 4 - 1 fuer Entlastung
  assert.equal(c.confidence, "low");
  // Die Gegenprobe entlastet, sie erklaert nicht: ohne anderen Beleg bleibt der Vorfall ungeklaert.
  assert.equal(r.verdict, UNEXPLAINED);
  assert.equal(r.verdictKind, "none");
  assert.equal(r.exonerationTally === undefined, true, "Gesamtzaehler liegt auf der Ebene, nicht der Zeile");
  const all = run([row({ hypotheses: [hyp("solo-failure", "none")] })], {
    diagnosis: { criticality: { rows: [crit(1001, 9, false)] } },
  });
  assert.equal(all.exonerationTally["quorum-follow-on"], 1);
});

test("Die Gegenprobe selbst ist gemessen: critical bringt Konsequenz, nicht critical entlastet", () => {
  const critical = run([row()], { diagnosis: { criticality: { rows: [crit(1001, -3, true)] } } }).rows[0];
  const c = cand(critical, "quorum-critical");
  assert.equal(c.kind, "consequence");
  assert.equal(c.strength, "measured");
  assert.equal(c.weight, 4);
  assert.deepEqual(c.layers, ["quorum"]);
  assert.equal(c.evidence.margin, -3);
  // consequence ist kein cause: ohne anderen Beleg bleibt das Urteil offen.
  assert.equal(critical.verdict, UNEXPLAINED);
});

test("Quorum-Band-Risiko: 3 x die Netz-Ausfallrate dieses Reservebands ist eine Netzlage", () => {
  const bands = [qband(1, 100, 30), qband(5, 200, 4), qband(6, 100, 6)];
  // overallBandRate = (30 + 4 + 6) / (100 + 200 + 100) = 40 / 400 = 0,1
  const out = run([row({ ledgerIndex: 1001 }), row({ ledgerIndex: 1002 }), row({ ledgerIndex: 1003 })], {
    diagnosis: { criticality: { rows: [crit(1001, 0), crit(1002, 5), crit(1003, 3)] } },
    surface: surface(bands),
  });
  assert.equal(out.coverage.quorumBandRate, 0.1);
  assert.equal(out.coverage.quorumBandLedgers, 400);
  const risk = out.rows[0];
  const c = cand(risk, "quorum-band-risk");
  assert.ok(c, "Band 0-0 faellt in 30 von 100 Ledgers - das ist dreimal der Durchschnitt");
  assert.equal(c.kind, "cause");
  assert.equal(c.strength, "corroborated");
  assert.equal(c.weight, 3);
  assert.equal(c.lift, 3); // 0,3 / 0,1
  assert.equal(c.evidence.marginBand, "0-0");
  assert.equal(c.evidence.bandFailRate, 0.3);
  assert.equal(c.evidence.overallFailRate, 0.1);
  assert.equal(c.evidence.bandLift, 3);
  assert.equal(c.evidence.bandLedgers, 100);

  // Band 5-7: 4 von 200 = 0,02 gegen 0,1 -> Fuenftel des Durchschnitts -> Komfortband.
  const calm = out.rows[1];
  const e = cand(calm, "quorum-band-comfort");
  assert.ok(e);
  assert.equal(e.kind, "exoneration");
  assert.equal(e.weight, 2); // 3 - 1
  assert.equal(e.lift, 0.2);
  assert.equal(e.evidence.marginBand, "5-7");

  // Band 3-4 ist hier nicht erfasst: eine Luecke, kein Urteil in irgendeine Richtung.
  const gap = out.rows[2];
  assert.ok(gap.dataGaps.includes("quorum-band-rate"));
  assert.equal(cand(gap, "quorum-band-risk"), null);
  assert.equal(cand(gap, "quorum-band-comfort"), null);
  assert.equal(out.coverage.withQuorumBandRate, 2);
  assert.equal(out.gapTally["quorum-band-rate"], 1);
});

test("Ohne Nenner der Bandbreite gibt es kein Band-Urteil", () => {
  const r = run([row()], {
    diagnosis: { criticality: { rows: [crit(1001, 0)] } },
    surface: surface([qband(1, 100, 30, { reliable: false })]), // zu duenn
  }).rows[0];
  assert.ok(r.dataGaps.includes("quorum-band-rate"));
  assert.equal(cand(r, "quorum-band-risk"), null);
  const none = run([row()], { diagnosis: { criticality: { rows: [crit(1001, 0)] } } }).rows[0];
  assert.ok(none.dataGaps.includes("quorum-band-rate"));
});

test("Die Bandschwelle ist ein Parameter: eine andere Grenze kippt das Urteil", () => {
  const bands = [qband(1, 100, 30), qband(5, 200, 4), qband(6, 100, 6)];
  const ctx = {
    diagnosis: { criticality: { rows: [crit(1001, 0)] } },
    surface: surface(bands),
  };
  assert.equal(cand(run([row()], ctx).rows[0], "quorum-band-risk").lift, 3);
  const strict = run([row()], ctx, { bandRiskLift: 4 }).rows[0];
  assert.equal(cand(strict, "quorum-band-risk"), null);
  assert.equal(cand(strict, "quorum-band-comfort"), null);
  const lenient = run([row()], ctx, { bandComfortLift: 0.5 }).rows[0];
  assert.equal(cand(lenient, "quorum-band-comfort"), null); // 3 > 0,5 ist kein Komfortband
});

test("Last-Kopplung: der Knoten faellt genau in den Stufen, die die Kohorte durchhaelt", () => {
  const diagnosis = {
    load: {
      baseline: { index: 2 },
      validator: { verdict: "load-resilient" },
      rows: [curveRow(2, { validatorRate: 0.02, validatorLedgers: 500, validatorFails: 10 }), curveRow(6, { validatorRate: 0.1, validatorLedgers: 100, validatorFails: 10 })],
    },
  };
  const r = run([row({ load: { txCount: 500, medianTx: 60, ratio: 8.3 } })], { diagnosis }).rows[0];
  const c = cand(r, "load-coupled");
  assert.ok(c, "0,1 eigene Ausfallrate gegen 0,02 in Normalbetrieb ist das Doppelte erreicht");
  assert.equal(c.kind, "cause");
  assert.equal(c.strength, "corroborated");
  assert.equal(c.weight, 3);
  assert.equal(c.evidence.txCount, 500);
  assert.equal(c.evidence.ownRate, 0.1);
  assert.equal(c.evidence.baseRate, 0.02);
  // 500 Tx liegt in Stufe 6, die Grundrate ist 0,02, die Schwelle ist das Doppelte = 0,04.
  assert.equal(c.evidence.bucket, "L6");

  // Duennstichprobe in dieser Stufe: keine Kopplung, kein Gegen-Urteil.
  const thin = run([row({ load: { txCount: 500 } })], {
    diagnosis: { load: { ...diagnosis.load, rows: [diagnosis.load.rows[0], curveRow(6, { sample: "thin" })] } },
  }).rows[0];
  assert.equal(cand(thin, "load-coupled"), null);
  assert.equal(cand(thin, "load-independent"), null);

  // Last unter Normalbetrieb: das ist eine Entlastung, keine Ursache.
  const low = run([row({ load: { txCount: 30 } })], { diagnosis }).rows[0];
  const i = cand(low, "load-independent");
  assert.ok(i);
  assert.equal(i.kind, "exoneration");
  assert.equal(i.strength, "corroborated"); // die Lastkurve sagt 'load-resilient'
  assert.equal(i.weight, 2); // 3 - 1
});

test("Lastachse fehlt: das ist eine Luecke, nicht 'Last war unkritisch'", () => {
  const r = run([row({ load: null })]).rows[0];
  assert.ok(r.dataGaps.includes("load-axis"));
  assert.equal(cand(r, "load-coupled"), null);
  assert.equal(cand(r, "load-independent"), null);
});

test("Haufung zur selben UTC-Stunde darf einer konkreten Serie nicht zuvorkommen", () => {
  const diagnosis = { fingerprint: { peakUtcHours: [{ utcHour: 17, incidents: 9, hours: [1, 2, 3] }] } };
  const r = run([row()], { diagnosis }).rows[0];
  const c = cand(r, "recurrent-hour");
  assert.ok(c);
  assert.equal(c.kind, "cause");
  assert.equal(c.strength, "correlated");
  assert.equal(c.weight, 2); // ohne die Haufungs-Verstaerkung unter 20 Vorfaelen
  assert.equal(c.evidence.utcHour, 17);
  assert.equal(c.evidence.incidents, 9);
  const strong = run([row()], {
    diagnosis: { fingerprint: { peakUtcHours: [{ utcHour: 17, incidents: 25, hours: [1, 2, 3] }] } },
  }).rows[0];
  assert.equal(cand(strong, "recurrent-hour").weight, 3); // 2 + 1 ab 20 Vorfaelen
  const thin = run([row()], {
    diagnosis: { fingerprint: { peakUtcHours: [{ utcHour: 17, incidents: 4, hours: [1] }] } },
  }).rows[0];
  assert.equal(cand(thin, "recurrent-hour"), null); // unter minPeakHourIncidents
});

test("Kohorten-Ortung: dasselbe Fenster bei vielen Knoten ist Netz, bei keinem Knoten ist es dieser", () => {
  const strong = run([row({ series: { coShare: 0.7, coValidators: 12, ledgers: 4, position: 1, verdict: "cohort-window" } })]).rows[0];
  const c = cand(strong, "network-window-localization");
  assert.equal(c.kind, "localization");
  assert.equal(c.strength, "corroborated");
  assert.equal(c.weight, 3);
  assert.equal(c.evidence.coShare, 0.7);
  const own = run([row({ series: { coShare: 0.01, coValidators: 1, ledgers: 4, position: 1, verdict: "cohort-window" } })]).rows[0];
  const o = cand(own, "node-local-window");
  assert.equal(o.kind, "localization");
  assert.equal(o.strength, "correlated");
  assert.equal(o.weight, 2);
  // Ohne Anteil entscheidet die Scope-Beobachtung.
  const solo = run([row({ scope: "solo" })]).rows[0];
  assert.equal(cand(solo, "node-local-window").evidence.others, 0);
  const net = run([row({ scope: "network", type: "no-quorum" })]).rows[0];
  assert.equal(cand(net, "network-window-localization").strength, "corroborated");
  // Ohne Schliess-Ebene in der Forensik darf die Ursachen-Ebene nichts ueber das Netz behaupten:
  // 'vote-not-observed' beschreibt die eigene Beobachtung, 'network-stall' bleibt aus.
  assert.equal(cand(net, "vote-not-observed").strength, "measured");
  assert.equal(cand(net, "vote-not-observed").kind, "cause");
  assert.equal(cand(net, "vote-not-observed").evidence.closureBasis, "not-recorded");
  assert.equal(cand(net, "network-stall"), null, "kein Beleg, keine Behauptung");
});

test("Schliess-Ebene der Ursachen: validierter Ledger heisst vote-not-observed, verneinter heisst network-stall", () => {
  // Nachgerechnet am Fall 107695059: 16 gesehene Mitglieder-Stimmen, needed 28, Marge 16 - 28 = -12.
  const closed = crit(1001, -12, false, {
    votes: 16, needed: 28, topVotes: 16, captureGap: false,
    closure: { closed: true, basis: "validated-ledger-stream", hash: "986E8D51B34602" },
  });
  const r = run([row({ type: "no-quorum", scope: "network" })], { diagnosis: { criticality: { rows: [closed] } } }).rows[0];
  const c = cand(r, "vote-not-observed");
  assert.equal(c.evidence.closedHash, "986E8D51B34602", "die Ursache haengt an einem nachpruefbaren Hash");
  assert.equal(c.evidence.closureBasis, "validated-ledger-stream");
  assert.equal(c.evidence.observedVotes, 16);
  assert.equal(c.evidence.needed, 28);
  assert.equal(c.evidence.captureGap, false);
  assert.equal(cand(r, "network-stall"), null, "der Ledger ist validiert - ein Netz-Stall waere erfunden");
  // Umgekehrt: nur die ausdruckliche Verneinung der Schliessung laesst den Netz-Stall zu.
  const open = crit(1001, -12, true, { votes: 16, needed: 28, topVotes: 16, closure: { closed: false, basis: "recorder", hash: null } });
  const r2 = run([row({ type: "no-quorum", scope: "network" })], { diagnosis: { criticality: { rows: [open] } } }).rows[0];
  assert.equal(cand(r2, "network-stall").kind, "cause");
  assert.equal(cand(r2, "quorum-critical").kind, "consequence");
  // Ohne Kritikalitaets-Zeile (die Tabelle zeigt nur zwolf Zeilen) kommt die Schliess-Ebene aus
  // der Tagesdatei selbst - sonst bekamen alle uebrigen Vorfaelle eine Aussage ohne Beleg.
  const day = { date: "2026-10-16", ledgerStats: [{ l: 1001, ch: "FB3ABE4A", cl: true, cg: false }] };
  const r3 = run([row({ type: "no-quorum", scope: "network" })], { days: [day] }).rows[0];
  assert.equal(cand(r3, "vote-not-observed").evidence.closedHash, "FB3ABE4A");
  assert.equal(cand(r3, "vote-not-observed").evidence.closureBasis, "validated-ledger-stream");
  assert.equal(cand(r3, "vote-not-observed").evidence.observedVotes, null, "keine Forensik-Zeile heisst keine Zahl, nicht 0");
  assert.equal(cand(r3, "network-stall"), null);
});

test("Pruefliste: ein bewiesen geschlossener Ledger empfiehlt keine Netzstockung", () => {
  // Derselbe Vorfall, nur die Schliess-Ebene unterscheidet ihn. Der Scope 'network' liefert den
  // Kandidaten network-window-localization, dessen Pruefschritt normalerweise die Netzstockung ist.
  const closed = crit(1001, -12, false, {
    votes: 16, needed: 28, topVotes: 16,
    closure: { closed: true, basis: "validated-ledger-stream", hash: "986E8D51B34602" },
  });
  const r = run([row({ type: "no-quorum", scope: "network" })], { diagnosis: { criticality: { rows: [closed] } } }).rows[0];
  assert.ok(!r.nextCheck.includes("cause-check-network-stall"), "geschlossener Ledger: die Netzstockung ist widerlegt, nicht zu pruefen");
  assert.ok(r.nextCheck.includes("cause-check-peer-audit"), "Erfassungs- und Peer-Gegenprobe bleiben die richtigen");
  // Der gemessene Close-Abstand ist ein eigener Beleg fuer eine verlangsamte Taktung und darf die
  // Pruefung behalten, auch bei geschlossenem Ledger.
  const gap = run([row({
    type: "no-quorum", scope: "network",
    hypotheses: [hyp("close-gap", "measured", { closeGapMs: 8000, medianGap: 1000 })],
  })], { diagnosis: { criticality: { rows: [closed] } } }).rows[0];
  assert.ok(gap.nextCheck.includes("cause-check-network-stall"), "gemessener Close-Abstand: die Takt-Pruefung bleibt");
  // Wo die Schliessung ausdrucklich verneint ist, ist die Netzstockung die naheliegende Gegenprobe.
  const open = crit(1001, -12, true, { votes: 16, needed: 28, topVotes: 16, closure: { closed: false, basis: "recorder", hash: null } });
  const r2 = run([row({ type: "no-quorum", scope: "network" })], { diagnosis: { criticality: { rows: [open] } } }).rows[0];
  assert.ok(r2.nextCheck.includes("cause-check-network-stall"), "verneinte Schliessung: Netzstockung ist die Gegenprobe");
});

test("Hash-Linie: die eigene Linie ist Ursache, die mitvalidierte Hash entlastet", () => {
  const own = run([row()], { divergence: { divergences: [{ ledgerIndex: 1001, lineage: "own", votedHash: "A", acceptedHash: "B" }] } }).rows[0];
  const c = cand(own, "hash-divergence");
  assert.equal(c.strength, "measured");
  assert.equal(c.kind, "cause");
  assert.deepEqual(c.layers, ["lineage"]);
  assert.equal(c.weight, 4);
  const accepted = run([row()], { divergence: { divergences: [{ ledgerIndex: 1001, lineage: "accepted", votedHash: "A", acceptedHash: "A" }] } }).rows[0];
  const a = cand(accepted, "signed-accepted-lineage");
  assert.equal(a.kind, "exoneration");
  assert.equal(a.weight, 3);
  assert.equal(accepted.verdict, UNEXPLAINED);
  const missing = run([row()]).rows[0];
  assert.ok(missing.dataGaps.includes("vote-lineage"));
});

test("Angriffsstunde: Signatur-ledger in dieser Stunde, mit und ohne Netz-Gegenprobe", () => {
  const hour = Math.floor(T / 3600000);
  const days = [{ date: "2026-10-14", hourly: { [hour]: { l: 120, s: 9, a: 11, tx: 4000, mx: 900, v: { [MASTER]: { missed: 3, ok: 110 } } } } }];
  const cells = hourCells(days, MASTER);
  const cell = cells.get(hour);
  assert.equal(cell.ledgers, 120);
  assert.equal(cell.signatureLedgers, 9);
  assert.equal(cell.ownFails, 3);
  assert.equal(cell.ownLedgers, 113);
  const r = run([row()], { days, impact: { verdict: "attack-linked", verdictAuthority: "history", network: { lift: 2.4, zRaw: 3.1 } } }).rows[0];
  const c = cand(r, "attack-window");
  assert.equal(c.kind, "cause");
  assert.equal(c.strength, "corroborated"); // die Gegenprobe bestaetigt
  assert.equal(c.weight, 3);
  assert.equal(c.evidence.controlVerdict, "attack-linked");
  assert.equal(c.evidence.controlLift, 2.4);
  const uncontrolled = run([row()], { days, impact: { verdict: "no-link", verdictAuthority: "trace" } }).rows[0];
  assert.equal(cand(uncontrolled, "attack-window").strength, "context"); // Zeitfenster ohne Gegenprobe
  assert.equal(cand(uncontrolled, "attack-window").weight, 1);
  const thinHour = run([row()], { days: [{ date: "2026-10-14", hourly: { [hour]: { l: 20, s: 9 } } }] }).rows[0];
  assert.equal(cand(thinHour, "attack-window"), null); // unter minCellLedgers
});

test("Fehlende Signatur-Zaehler bleiben null: 'nicht erfasst' ist nicht 'keine Angriffe'", () => {
  const hour = Math.floor(T / 3600000);
  const cells = hourCells([{ date: "2026-10-14", hourly: { [hour]: { l: 120, v: { [MASTER]: { missed: 1 } } } } }], MASTER);
  assert.equal(cells.get(hour).signatureLedgers, null);
  const out = run([row()], { days: [{ date: "2026-10-14", hourly: { [hour]: { l: 120 } } }] });
  assert.equal(out.coverage.attackHoursUnknown, 1);
  assert.equal(out.coverage.attackHours, 0);
  assert.ok(out.rows[0].dataGaps.includes("attack-hours"));
  assert.equal(out.coverage.hoursThin, 0); // 120 Ledger sind nicht duenn
  const thin = run([row()], { days: [{ date: "2026-10-14", hourly: { [hour]: { l: 10, s: 0 } } }] });
  assert.equal(thin.coverage.hoursThin, 1);
});

test("Vorher/Nachher: die Engine erklaert Vorfaelle ohne Grund, ohne welche zu erfinden", () => {
  const incidents = [
    { ledgerIndex: 1001, type: "missed", reasons: [] },
    { ledgerIndex: 1002, type: "missed", reasons: ["no-correlated-cause"] },
    { ledgerIndex: 1003, type: "missed", reasons: ["vote-late"] },
    { ledgerIndex: 1004, type: "missed", reasons: [] },
  ];
  const retrace = [
    row({ ledgerIndex: 1001, voteDelayMs: 30000 }),
    row({ ledgerIndex: 1002, voteDelayMs: 30000 }),
    row({ ledgerIndex: 1003, voteDelayMs: 30000 }),
    row({ ledgerIndex: 1004, hypotheses: [hyp("solo-failure", "none")] }),
  ];
  const out = run(retrace, { incidents });
  assert.equal(out.coverage.incidents, 4);
  assert.equal(out.coverage.rawIncidents, 4);
  assert.equal(out.coverage.matchedIncidents, 4);
  assert.equal(out.coverage.unmatchedIncidents, 0);
  assert.equal(out.reduction.rawNoCause, 3); // 1001, 1002, 1004
  assert.equal(out.reduction.resolvedByCauseEngine, 2); // 1001, 1002 erklaert
  assert.equal(out.reduction.remainingRawNoCause, 1); // 1004 bleibt ungeklaert
  assert.equal(out.reduction.unexplainedTotal, 1);
  assert.equal(out.reduction.rawNoCause + out.reduction.unexplainedTotal >= out.reduction.remainingRawNoCause, true);
  assert.equal(out.reduction.resolvedByCauseEngine <= out.reduction.rawNoCause, true);
  assert.equal(out.reduction.explainedShare, 0.75); // 3 von 4
  assert.equal(out.reduction.unexplainedShare, 0.25);
  assert.equal(out.reduction.rawNoCauseShare, 0.75);
  // Unexplained ist kein Urteil, das in der Rangliste steht.
  assert.ok(!out.verdicts.some((v) => v.tag === UNEXPLAINED));
  assert.equal(out.tally[UNEXPLAINED], 1);
});

test("Unexplained steht nur dort, wo wirklich kein Beleg liegt - mit der Liste der Luecken", () => {
  const r = run([row({ hypotheses: [] })]).rows[0];
  assert.equal(r.verdict, UNEXPLAINED);
  assert.deepEqual(r.dataGaps, ["attack-hours", "load-axis", "quorum-counterfactual", "vote-lineage", "vote-timing"]);
  assert.deepEqual(r.nextCheck, ["cause-check-unknown"]);
  for (const g of r.dataGaps) assert.ok(CAUSE_GAPS.includes(g), "Gap " + g + " ist nicht in CAUSE_GAPS");
});

test("Die Pruefliste folgt dem Urteil, nicht der Laenge nach", () => {
  const out = run([
    row({ ledgerIndex: 1001, voteDelayMs: 30000 }),
    row({ ledgerIndex: 1002, voteDelayMs: 30000 }),
    row({ ledgerIndex: 1003, voteDelayMs: 30000 }),
  ], { incidents: [] });
  assert.equal(out.checklist.length >= 1, true);
  const first = out.checklist[0];
  assert.equal(first.tag, "cause-check-clock"); // vote-late -> Uhr und Lastpfad
  assert.equal(first.incidents, 3);
  assert.equal(first.share, 1);
  assert.deepEqual(first.verdicts, ["vote-late"]);
  assert.ok(out.checklist.every((c) => c.incidents >= CAUSE_DEFAULTS.minChecklistIncidents));
  // Ein Pruefschritt, der nur einmal vorkommt, erscheint nicht als allgemeine Empfehlung.
  const once = run([row({ ledgerIndex: 1001, voteDelayMs: 30000 }), row({ ledgerIndex: 1002 }), row({ ledgerIndex: 1003 })]);
  assert.ok(!once.checklist.some((c) => c.tag === "cause-check-clock"));
}
);

test("Jeder Pruefschritt jeder Engine-Ebene ist uebersetzbar benannt", () => {
  const out = run([
    row({ ledgerIndex: 1001, voteDelayMs: 30000 }),
    row({ ledgerIndex: 1002, voteDelayMs: 30000 }),
    row({ ledgerIndex: 1003, voteDelayMs: 30000 }),
  ], {
    diagnosis: { criticality: { rows: [crit(1001, 0), crit(1002, 0), crit(1003, 0)] } },
    surface: surface([qband(1, 100, 30), qband(5, 200, 4), qband(6, 100, 6)]),
  });
  for (const r of out.rows) {
    for (const tag of r.nextCheck) assert.ok(CAUSE_CHECKS.includes(tag), "check " + tag);
    for (const c of r.candidates) {
      assert.ok(CAUSE_KINDS.includes(c.kind), "kind " + c.kind);
      for (const l of c.layers) assert.ok(CAUSE_LAYERS.includes(l), "layer " + l);
    }
  }
  // Die neuen Band-Kandidaten sind in der exportierten Menge, damit UI und Uebersetzung sie kennen.
  assert.ok(CAUSE_TAGS.includes("quorum-band-risk"));
  assert.ok(CAUSE_TAGS.includes("quorum-band-comfort"));
  assert.ok(CAUSE_GAPS.includes("quorum-band-rate"));
  assert.equal(out.thresholds.bandRiskLift, CAUSE_DEFAULTS.bandRiskLift);
  assert.equal(out.thresholds.bandComfortLift, CAUSE_DEFAULTS.bandComfortLift);
});

test("Ohne Vorfaelle ist die Ebene vollstaendig und nicht halbfertig", () => {
  const out = run([]);
  assert.equal(out.coverage.incidents, 0);
  assert.equal(out.reduction.rawNoCauseShare, null);
  assert.equal(out.reduction.explainedShare, null);
  assert.equal(out.primary, null);
  assert.deepEqual(out.verdicts, []);
  assert.deepEqual(out.checklist, []);
  assert.deepEqual(out.rows, []);
});

test("Angriffsstunde aus der Historie: die Gegenprobe erreicht die Ursachen-Engine auch ohne eigene Signatur-Zaehler", () => {
  // Aeltere Tagesdateien haben keinen stunden-genauen Signatur-Zaehler. Ohne die Stunden der
  // Gegenprobe waehre die Angriffsseite dort schlicht nicht vorhanden - obwohl die Historie die
  // Stunde fuehrt und die paired control sie bestaetigt.
  const hour = Math.floor(T / 3600000);
  const days = [{ date: "2026-10-14", hourly: { [hour]: { l: 120, v: { [MASTER]: { missed: 3, ok: 110 } } } } }];
  const impact = {
    verdict: "attack-linked", verdictAuthority: "history", network: { lift: 3.1, zRaw: 7.4 },
    hours: { cellMs: 3600000, authority: "history", attack: [hour], quiet: [], bySource: { history: [hour], trace: [] } },
  };
  const out = run([row()], { days, impact });
  const r = out.rows[0];
  const c = cand(r, "attack-window");
  assert.ok(c, "die Historien-Stunde erreicht die Ursachen-Engine nicht");
  assert.equal(c.evidence.source, "history");
  assert.equal(c.strength, "corroborated");
  assert.equal(c.evidence.signatureLedgers, null); // die eigene Messung fehlt, sie wird nicht erfunden
  assert.ok(!r.dataGaps.includes("attack-hours"), "die Stunde ist belegt, nicht unbekannt");
  assert.equal(out.coverage.attackHours, 1);
  assert.equal(out.coverage.attackHoursHistory, 1);
  assert.equal(out.coverage.attackHoursTrace, 0);
  assert.equal(out.coverage.attackHoursUnknown, 0);
  assert.equal(out.coverage.withAttackWindow, 1);
});

test("Ruhige Stunde in der Gegenprobe entlastet, statt den Angriff als offene Luecke stehen zu lassen", () => {
  const hour = Math.floor(T / 3600000);
  const days = [{ date: "2026-10-14", hourly: { [hour]: { l: 120 } } }];
  const impact = {
    verdict: "no-link", verdictAuthority: "history", network: { lift: 1, zRaw: 0.2 },
    hours: { cellMs: 3600000, authority: "history", attack: [], quiet: [hour], bySource: { history: [], trace: [] } },
  };
  const out = run([row({ hypotheses: [] })], { days, impact });
  const r = out.rows[0];
  const c = cand(r, "attack-window-clear");
  assert.ok(c, "Entlastung fehlt");
  assert.equal(c.kind, "exoneration");
  assert.equal(c.strength, "correlated"); // nur die Historie hat geprueft, die eigene Messung fehlt
  assert.equal(c.weight, 1);
  assert.equal(c.evidence.source, "history");
  assert.ok(!r.dataGaps.includes("attack-hours"));
  assert.equal(out.coverage.quietHours, 1);
  assert.equal(out.coverage.attackHoursUnknown, 0);
  // Entlastung ist keine Erklaerung: das Urteil bleibt unexplained, die Luecke ist geschlossen.
  assert.equal(r.verdict, UNEXPLAINED);
});

test("Beide Autoritaeten sehen dieselbe Stunde ruhig: die Entlastung ist bestaetigt", () => {
  const hour = Math.floor(T / 3600000);
  const days = [{ date: "2026-10-14", hourly: { [hour]: { l: 120, s: 0, a: 0 } } }];
  const impact = {
    verdict: "no-overlap", verdictAuthority: "history", network: { lift: 1, zRaw: 0.1 },
    hours: { cellMs: 3600000, authority: "history", attack: [], quiet: [hour], bySource: { history: [], trace: [] } },
  };
  const r = run([row({ hypotheses: [] })], { days, impact }).rows[0];
  const c = cand(r, "attack-window-clear");
  assert.equal(c.strength, "corroborated");
  assert.equal(c.weight, 2);
  assert.equal(c.evidence.source, "trace+history");
});

test("Eine Stunde, die keine Autoritaet fuehrt, bleibt eine Luecke - ruhig ist sie dadurch nicht", () => {
  const hour = Math.floor(T / 3600000);
  const days = [{ date: "2026-10-14", hourly: { [hour]: { l: 120 } } }];
  const impact = {
    verdict: "no-overlap", verdictAuthority: "history", network: { lift: null, zRaw: null },
    hours: { cellMs: 3600000, authority: "history", attack: [], quiet: [], bySource: { history: [], trace: [] } },
  };
  const out = run([row({ hypotheses: [] })], { days, impact });
  assert.ok(out.rows[0].dataGaps.includes("attack-hours"));
  assert.equal(out.coverage.attackHoursUnknown, 1);
  assert.equal(out.coverage.quietHours, 0);
  assert.equal(out.coverage.withAttackWindow, 0);
});

test("Duenn abgedeckte Stunden werden nicht entlastet, weil ueber ihnen kein Urteil steht", () => {
  // 12 Ledger sind zu duenn fuer eine Rate: die Stunde steht in keiner Liste der Gegenprobe,
  // also gibt es weder Angriff noch Entlastung. Sie ist als duenn ausgewiesen, nicht als ruhig.
  const hour = Math.floor(T / 3600000);
  const days = [{ date: "2026-10-14", hourly: { [hour]: { l: 12, s: 0 } } }];
  const impact = {
    verdict: "thin-overlap", verdictAuthority: "history", network: { lift: 1, zRaw: 0.1 },
    hours: { cellMs: 3600000, authority: "history", attack: [], quiet: [], bySource: { history: [], trace: [] } },
  };
  const out = run([row({ hypotheses: [] })], { days, impact });
  const r = out.rows[0];
  assert.equal(cand(r, "attack-window-clear"), null);
  assert.equal(cand(r, "attack-window"), null);
  assert.equal(out.coverage.hoursThin, 1);
  assert.equal(out.coverage.quietHours, 0);
  assert.equal(out.coverage.attackHoursUnknown, 0); // ein Zaehler ist da, die Stunde ist nur duenn
});
