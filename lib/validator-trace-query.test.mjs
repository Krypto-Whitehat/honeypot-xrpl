// lib/validator-trace-query.test.mjs — Abfrage der Trace-Tage: Zeitraum, Zusammenfassung, Muster.
import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { loadDays, traceForValidator, crossValidatorPatterns, RANGE_MS, RETRACE_ROWS_SENT } from "./validator-trace-query.mjs";
import { profileCells } from "./validator-trace-query.mjs";
import { PEER_AUTHORITIES, PEER_MIN_LEDGERS, PEER_MIN_PEERS, PEER_REASONS, PEER_VERDICTS } from "./validator-peer-benchmark.mjs";
import { CAUSE_DEFAULTS } from "./validator-cause.mjs";

const NOW = Date.UTC(2026, 9, 8, 12, 0, 0);
const A = "nAAA", B = "nBBB";
const day = (date, incidents, validators) => ({ date, ledgers: 10, quorumFail: 0, validators, incidents });

const days = [
  day("2026-10-07", [
    { l: 1, m: A, t: NOW - 2 * 86400000, type: "missed", r: ["load-spike"] },
    { l: 2, m: B, t: NOW - 2 * 86400000, type: "missed", r: ["load-spike"] },
  ], { [A]: { ok: 100, partial: 0, missed: 1, wrongHash: 0 }, [B]: { ok: 99, partial: 0, missed: 1, wrongHash: 0 } }),
  day("2026-10-08", [
    { l: 3, m: A, t: NOW - 30 * 60000, type: "wrong-hash", r: ["signed-different-hash"] },
    { l: 4, m: A, t: NOW - 10 * 60000, type: "partial", r: ["partial-validation", "amendment-activity"] },
    { l: 5, m: A, t: NOW - 9 * 60000, type: "missed", r: ["load-spike"] },
  ], { [A]: { ok: 200, partial: 1, missed: 1, wrongHash: 1 } }),
];

test("traceForValidator: Zusammenfassung über alle Tage, Zeitleiste neueste zuerst", () => {
  const t = traceForValidator(days, A, { range: "all", now: NOW });
  assert.equal(t.summary.ok, 300);
  assert.equal(t.summary.observed, 300 + 1 + 2 + 1);
  assert.equal(t.incidents[0].ledgerIndex, 5);
  assert.equal(t.incidents.length, 4);
});

test("traceForValidator: 1h-Zeitraum enthält nur die letzten Incidents", () => {
  const t = traceForValidator(days, A, { range: "1h", now: NOW });
  assert.deepEqual(t.incidents.map((i) => i.ledgerIndex), [5, 4, 3]);
});

test("traceForValidator: Muster zählen die Korrelationen des Validators", () => {
  const t = traceForValidator(days, A, { range: "all", now: NOW });
  const ls = t.patterns.find((p) => p.tag === "load-spike");
  assert.ok(ls);
  assert.equal(ls.count, 2);
});

test("traceForValidator: unbekannter Validator -> leer, nie geraten", () => {
  const t = traceForValidator(days, "nNOPE", { range: "all", now: NOW });
  assert.equal(t.summary.observed, 0);
  assert.equal(t.incidents.length, 0);
});

test("crossValidatorPatterns: wiederkehrende Ursache über Validatoren hinweg", () => {
  const p = crossValidatorPatterns(days, { range: "all", now: NOW });
  const ls = p.recurring.find((r) => r.tag === "load-spike");
  assert.ok(ls, "load-spike bei 2 Validatoren muss als wiederkehrend gelten");
  assert.equal(ls.validators, 2);
  assert.equal(p.perValidator[A].wrongHash, 1);
});

test("loadDays: liest nur Tagesdateien im Muster, sortiert, überspringt Müll", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "vt-"));
  fs.writeFileSync(path.join(dir, "2026-10-08.json"), JSON.stringify(days[1]));
  fs.writeFileSync(path.join(dir, "2026-10-07.json"), JSON.stringify(days[0]));
  fs.writeFileSync(path.join(dir, "kaputt.json"), "{}");
  fs.writeFileSync(path.join(dir, "2026-10-06.json.tmp"), "{");
  const out = loadDays(dir, NOW);
  assert.deepEqual(out.map((d) => d.date), ["2026-10-07", "2026-10-08"]);
});

test("loadDays: Aufbewahrung 365 Tage wird eingehalten", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "vt-"));
  fs.writeFileSync(path.join(dir, "2024-01-01.json"), JSON.stringify({ date: "2024-01-01", incidents: [], validators: {} }));
  fs.writeFileSync(path.join(dir, "2026-10-07.json"), JSON.stringify(days[0]));
  assert.equal(loadDays(dir, NOW).length, 1);
});

test("RANGE_MS: bekannte Zeitfenster", () => {
  assert.equal(RANGE_MS["1h"], 3600000);
  assert.equal(RANGE_MS.all, Infinity);
});

test("traceForValidator: inWindow zählt fenster-genau über Stunden-Buckets", () => {
  const hk = Math.floor((NOW - 30 * 60000) / 3600000); // Bucket der letzten Stunde
  const withHourly = [{
    ...days[1],
    firstMs: NOW - 3600000,
    lastMs: NOW - 60000,
    hourly: {
      [hk]: { l: 900, v: {} },        // volle Stunde im 1h-Fenster
      [hk - 3]: { l: 800, v: {} },    // 3 h früher: außerhalb des Fensters
    },
  }];
  const t = traceForValidator(withHourly, A, { range: "1h", now: NOW });
  assert.ok(t.inWindow, "Stundenzähler vorhanden -> fenster-genaue Zähler");
  assert.equal(t.inWindow.observed, 900);
  assert.equal(t.inWindow.missed, 1);
  assert.equal(t.inWindow.wrongHash, 1);
  assert.equal(t.inWindow.partial, 1);
  assert.equal(t.inWindow.ok, 897);
  assert.equal(t.inWindow.estimated, true);
});

test("traceForValidator: ohne Stundenzähler -> inWindow null (kein Raten), coverage aus Tagesfeldern", () => {
  const t = traceForValidator(days, A, { range: "1h", now: NOW });
  assert.equal(t.inWindow, null);
  assert.equal(t.coverage.ledgers, 20);
  assert.equal(t.coverage.days, 2);
});

test("traceForValidator: Aufzeichnungslücken werden ausgewiesen (keine Aussage dort)", () => {
  const withGap = [{ ...days[1], gaps: [{ from: 900, to: 950, t: NOW - 20 * 60000, reason: "stream-gap" }] }];
  const t2 = traceForValidator(withGap, A, { range: "1h", now: NOW });
  assert.equal(t2.gaps.length, 1);
  assert.equal(t2.gaps[0].from, 900);
  const t3 = traceForValidator(days, A, { range: "all", now: NOW });
  assert.equal(t3.gaps.length, 0);
});

// Die Zeit-Ebene: crossValidatorPatterns muss die Cluster der Betrugs-Historie an attackImpact
// durchreichen. Ohne dieses Durchreichen ist das Netzboard blind fuer Angriffswellen.
const HOUR_MS = 3600000;
function traceDaysWithAttackHours() {
  const out = [];
  for (let day = 1; day <= 8; day += 1) {
    const d = { date: "2026-10-0" + day, ledgers: 0, quorumFail: 0, validators: {}, incidents: [], hourly: {} };
    for (const [h, fails] of [[3, day <= 4 ? 200 : 20], [10, 5]]) {
      const at = Date.UTC(2026, 9, day, h, 0, 0);
      d.hourly[Math.floor(at / HOUR_MS)] = { l: 1000, v: { [A]: { ok: 1000 - fails, partial: 0, missed: fails, wrongHash: 0, noQuorum: 0 } } };
      for (let i = 0; i < fails; i += 1) {
        d.incidents.push({ l: day * 10000 + h * 100 + i, m: A, t: at + i * 1000, type: "missed", r: [] });
      }
      d.ledgers += 1000;
    }
    out.push(d);
  }
  return out;
}
function attackWaveClusters() {
  return [1, 2, 3, 4].map((day) => {
    const first = Date.UTC(2026, 9, day, 3, 20, 0);
    return {
      key: "wave-" + day, members: ["rBait1", "rBait2"], label: "Welle", totalDrops: 500000,
      txCount: 9, distinctAccounts: 3, firstSeen: first, lastSeen: first + 90000,
      rules: ["drainer-sweep"], severity: "malicious", sightings: 1,
    };
  });
}

test("crossValidatorPatterns: Angriffscluster werden zur Zeit-Ebene (impact) durchgereicht", () => {
  const traceDays = traceDaysWithAttackHours();
  const withClusters = crossValidatorPatterns(traceDays, { range: "all", now: NOW, clusters: attackWaveClusters() });
  // Dieses Fixture hat genau einen beobachteten Knoten - ein Netz-Urteil darf es nicht liefern,
  // genau dafür ist die Schwelle da. Durchgereicht sind die Cluster trotzdem (Fenster, Gegenprobe).
  assert.equal(withClusters.impact.verdict, "node-driven");
  assert.equal(withClusters.impact.network.contributingValidators, 1);
  assert.equal(withClusters.impact.coverage.clustersInWindow, 4);
  assert.equal(withClusters.impact.coverage.overlapCells, 4);
  assert.ok(withClusters.impact.matched.z >= 2, "die Gegenprobe muss den Unterschied tragen");
  assert.ok(withClusters.impact.windows.length >= 1, "Angriffsfenster mit Tx-Zahl und Drops");
  assert.equal(withClusters.impact.windows[0].txCount, 9);

  const withoutClusters = crossValidatorPatterns(traceDays, { range: "all", now: NOW });
  assert.equal(withoutClusters.impact.verdict, "unknown", "ohne Cluster-Historie kein Ueberlappungsurteil");
  assert.equal(withoutClusters.impact.coverage.clustersInWindow, 0);
});

// Der Peer-Benchmark ist die Vergleichs-Ebene: ohne sie steht eine Ausfallrate ohne Befund da.
// Guard ist die Durchreichung im Trace-Ergebnis - beide Endpunkte bauen auf diesem Rueckgabewert.
test("traceForValidator: Peer-Benchmark ist durchgereicht, Ende in den deklarierten Mengen", () => {
  const t = traceForValidator(days, A, { range: "all", now: NOW });
  const peer = t.peer;
  assert.ok(peer, "peer fehlt im Trace-Ergebnis - UI und CSV-Report haengen daran");
  assert.equal(peer.master, A);
  assert.ok(PEER_VERDICTS.includes(peer.verdict), "Urteil ausserhalb der Menge: " + peer.verdict);
  assert.ok(PEER_REASONS.includes(peer.verdictReason), "Grund ausserhalb der Menge: " + peer.verdictReason);
  assert.ok(PEER_AUTHORITIES.includes(peer.verdictAuthority), "Autoritaet ausserhalb der Menge: " + peer.verdictAuthority);
  // Dieses Fixture hat einen einzigen beobachteten Knoten: ein Peer-Urteil darf es nicht geben,
  // genau dafuer ist die Schwelle da. "zu wenig Vergleich" ist eine Aussage, keine 0-Rate.
  assert.ok(peer.sample.observed >= PEER_MIN_LEDGERS, "eigene Stichprobe ueber der Mindestgrenze: " + peer.sample.observed);
  assert.equal(peer.sample.peers, 0, "kein zweiter Knoten mit ausreichender Stichprobe");
  assert.equal(peer.verdict, "insufficient-sample");
  assert.equal(peer.verdictReason, "below-minimum-peers");
  assert.equal(peer.peers, null, "ohne Vergleichsgruppe keine Peer-Verteilung erfinden");
  assert.equal(peer.comparison, null);
  assert.ok(Array.isArray(peer.aloneHours), "Alleinstunden muessen eine Liste sein");
  assert.equal(peer.types, null, "ohne Vergleichsgruppe keine Typ-Ebene erfinden");
  assert.equal(peer.network, null, "ohne Vergleichsgruppe keine Netz-Aussetzung erfinden");
  assert.ok(Number.isFinite(peer.cohort.solo) && Number.isFinite(peer.cohort.shared), "Kohorten-Zaehlung fehlt");
  assert.equal(peer.sample.minLedgers, PEER_MIN_LEDGERS);
  assert.equal(peer.sample.minPeers, PEER_MIN_PEERS);
  assert.equal(peer.sample.estimated, true, "Tages-overlap muss als geschaetzt ausgewiesen sein");
});

test("traceForValidator: jeder Vorfall nennt die anderen betroffenen Knoten dieses Ledgers", () => {
  const withPeer = [day("2026-10-08", [
    { l: 9, m: A, t: NOW - 20 * 60000, type: "no-quorum", r: ["no-quorum"] },
    { l: 9, m: B, t: NOW - 20 * 60000, type: "no-quorum", r: ["no-quorum"] },
    { l: 9, m: B, t: NOW - 20 * 60000, type: "missed", r: [] },
    { l: 10, m: A, t: NOW - 10 * 60000, type: "missed", r: [] },
  ], {})];
  const t = traceForValidator(withPeer, A, { range: "all", now: NOW });
  const shared = t.incidents.find((i) => i.ledgerIndex === 9);
  assert.deepEqual(shared.peerMasters, [B], "zwei Vorfälle von B sind ein Knoten, nicht zwei");
  assert.equal(shared.affectedValidators, 2);
  const solo = t.incidents.find((i) => i.ledgerIndex === 10);
  assert.deepEqual(solo.peerMasters, [], "solo ist eine leere Liste, nicht null");
});

test("traceForValidator: die Signatur-Empfindlichkeit hängt am Trace", () => {
  // Ohne dieses Feld fehlen UI und CSV-Report die Ebene, die zwischen Knotenproblem und
  // Netzlage unterscheidet. Die Fixture-Tage fuehren keine Signatur-Ebene - also muss die
  // Luecke benannt sein, statt als 0-Rate zu erscheinen.
  const t = traceForValidator(days, A, { range: "all", now: NOW });
  const s = t.sensitivity;
  assert.ok(s, "sensitivity fehlt im Trace-Ergebnis");
  assert.equal(s.master, A);
  assert.ok(Array.isArray(s.rows) && Array.isArray(s.gaps) && Array.isArray(s.families));
  assert.equal(s.coverage.daysWithAnomaly, 0);
  assert.ok(s.gaps.includes("anomaly-counts"), "fehlende Signatur-Ebene ist eine Luecke");
});
test("traceForValidator: viele Vorfaelle senden die Rangliste gekuerzt und die Gesamtzahl daneben", () => {
  // Ein knotenreicher Validator hat 8.609 Vorfaelle; die volle Antwort war 25 MB JSON. Gekuerzte
  // Karten sind nur dann ehrlich, wenn retraceTotal und rowTotal die Gesamtzahl nennen und die
  // Zaehlungen (cause.coverage) weiterhin alle Vorfaelle zaehlen.
  const many = [];
  for (let i = 0; i < 260; i++) many.push({ l: 100 + i, m: A, t: NOW - i * 60000, type: "missed", r: [] });
  const heavy = [day("2026-10-08", many, { [A]: { ok: 900, partial: 0, missed: 260, wrongHash: 0 } })];
  const t = traceForValidator(heavy, A, { range: "all", now: NOW });
  assert.equal(t.retrace.length, RETRACE_ROWS_SENT, "mehr Retrace-Karten als erlaubt");
  assert.equal(t.retraceTotal, 260, "die Gesamtzahl der Retrace-Vorfaelle fehlt");
  assert.equal(t.cause.rows.length, CAUSE_DEFAULTS.rowLimit, "mehr Ursachen-Zeilen als erlaubt");
  assert.equal(t.cause.rowTotal, 260, "die Gesamtzahl der Ursachen-Zeilen fehlt");
  assert.equal(t.cause.coverage.incidents, 260, "die Zaehlungen duerfen nicht mitgekuerzt werden");
  assert.equal(t.retrace[0].ledgerIndex, 100, "neueste zuerst - die Kuerzung darf nicht die aeltesten zeigen");
});

test("traceForValidator: halb gedeckter Tag - inWindow deckt sich mit summary", () => {
  const hk = Math.floor((NOW - 30 * 60000) / 3600000);
  const d = {
    ...days[1],
    firstMs: NOW - 5 * 3600000,
    lastMs: NOW - 60000,
    hourly: { [hk]: { l: 100, v: { [A]: { ok: 100, partial: 0, missed: 0, wrongHash: 0, noQuorum: 0 } } } },
  };
  const t = traceForValidator([d], A, { range: "all", now: NOW });
  assert.equal(t.inWindow.observed, t.summary.observed, "Nenner und Zaehler dieselbe Ledger-Menge");
  assert.equal(t.inWindow.ok, t.summary.ok);
  assert.equal(t.inWindow.missed, t.summary.missed);
  assert.equal(t.inWindow.observedHourly, 100);
  assert.equal(t.inWindow.observedDayOnly, t.summary.observed - 100);
  assert.equal(t.inWindow.daysPartial, 1, "der halbe Tag muss als solcher dastehen");
});

/* Das Zeitprofil zaehlt Abweichungen aus den Incidents (zeitgestempelt, exakt) und die Ledger
 * aus den Stunden-Buckets. Ein Tag, der nur ab 11 Uhr Stunden-Buckets fuehrt, liefert fuer die
 * Vorfaelle davor keinen Nenner - das Profil zeigt dann "25 Abweichungen bei 0 Ledgern". */
test("profileCells: Abweichungen vor den Stunden-Buckets bekommen einen geschaetzten Nenner", () => {
  const HOUR = 3600000;
  const H = Math.floor(NOW / HOUR);
  const hourly = {};
  for (let i = 0; i < 12; i += 1) {
    hourly[H - 12 + i] = { l: 100, v: { [A]: { ok: 100, partial: 0, missed: 0, wrongHash: 0, noQuorum: 0 } } };
  }
  const d = {
    date: "2026-10-08", ledgers: 2400, quorumFail: 0,
    validators: { [A]: { ok: 2375, partial: 0, missed: 25, wrongHash: 0, noQuorum: 0 } },
    incidents: [{ l: 9, m: A, t: (H - 20) * HOUR + 60000, type: "missed", r: [] }],
    gaps: [], firstMs: (H - 12) * HOUR, lastMs: H * HOUR + 3599000, hourly,
  };
  const p = profileCells([d], A, { range: "all", now: NOW, buckets: 24 });
  const hit = p.cells.filter((c) => c.total > 0);
  assert.equal(hit.length, 1);
  assert.equal(hit[0].ledgers, 0, "in diesem Intervall wurde nichts in Stunden-Koernung gemessen");
  assert.ok(hit[0].ledgersEstimated > 0, "der Nenner aus Tagessummen wird ausgewiesen, nicht verschluckt");
  assert.ok(p.estimatedLedgers > 0, "das Profil nennt den geschaetzten Anteil");
  assert.ok(p.estimatedLedgers <= 1200 + 24, 'geschaetzt darf die 1200 Ledger des Tages nicht uebersteigen');
  // 12 gedeckte Stunden in einem Fenster von 20 Stunden: 15 der 24 Intervalle beruehren eine
  // Bucket-Stunde. Die uebrigen bleiben ohne gemessene Abdeckung - auch wenn Tagessummen dort
  // Ledger vermuten lassen.
  assert.equal(p.cells.filter((c) => c.ledgers > 0 && c.total === 0).length, 15,
    'nur Intervalle mit echten Stundenzählern zählen als beobachtet und unauffällig');
  assert.ok(p.cells.some((c) => c.ledgers === 0 && c.ledgersEstimated > 0 && c.total === 0),
    'ein Intervall nur aus Tagessummen bleibt eine Luecke, kein Sauber-Befund');
});

test("profileCells: voll gedeckte Tage bleiben reine Messung (ledgersEstimated 0)", () => {
  const HOUR = 3600000;
  const H = Math.floor(NOW / HOUR);
  const hourly = {};
  for (let i = 0; i < 24; i += 1) {
    hourly[H - 24 + i] = { l: 100, v: { [A]: { ok: 100, partial: 0, missed: i === 20 ? 1 : 0, wrongHash: 0, noQuorum: 0 } } };
  }
  const d = {
    date: "2026-10-08", ledgers: 2400, quorumFail: 0,
    validators: { [A]: { ok: 2399, partial: 0, missed: 1, wrongHash: 0, noQuorum: 0 } },
    incidents: [{ l: 9, m: A, t: (H - 4) * HOUR + 60000, type: "missed", r: [] }],
    gaps: [], firstMs: (H - 24) * HOUR, lastMs: H * HOUR - 1000, hourly,
  };
  const p = profileCells([d], A, { range: "all", now: NOW, buckets: 24 });
  assert.equal(p.estimatedLedgers, 0, "nichts zu schaetzen, wenn jeder Ledger ein Bucket hat");
  for (const c of p.cells) assert.equal(c.ledgersEstimated, 0);
});

/* Die API muss die Nachfuehrung belegen koennen: Typ, Ursprungstyp und die Autoritaet der
 * Schliess-Aussage stehen an der Zeile, die ein Betreiber liest. Handgerechnet: dUNL 35,
 * needed = ceil(35 * 0.8) = 28, eigener Top 16 -> Marge -12. Der Ledger #107695059 ist durch
 * xrpscan und xrplcluster.com gedeckt; 'no-quorum' waere hier eine Falschaussage uebers Netz. */
test("Nachfuehrung in der Abfrage: die Zeile nennt Typ, Ursprung und Schliess-Autoritaet", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "vt-nq-"));
  fs.writeFileSync(path.join(dir, "2026-10-08.json"), JSON.stringify({
    date: "2026-10-08", ledgers: 4, quorumFail: 1, validators: { [A]: { ok: 3, noQuorum: 1 } },
    incidents: [{ l: 107695059, m: A, t: NOW - 10 * 60000, type: "no-quorum", r: ["no-quorum"] }],
    closureProofs: [{ l: 107695059, cl: true, ch: "986E8D51A78E8B2CB53B0FDBAE613692C7D33E3C82DCEE20A2C22D5496B34602", chSource: "xrpscan", chVerifiedBy: "xrplcluster.com" }],
  }));
  const t = traceForValidator(loadDays(dir, NOW), A, { range: "all", now: NOW });
  const inc = t.incidents[0];
  assert.equal(inc.type, "vote-not-observed");
  assert.equal(inc.reasons[0], "vote-not-observed");
  assert.equal(inc.typeStored, "no-quorum");
  assert.equal(inc.closureBasis, "xrpscan");
  assert.equal(inc.closureHash, "986E8D51A78E8B2CB53B0FDBAE613692C7D33E3C82DCEE20A2C22D5496B34602");
  assert.equal(t.summary.noQuorum, 1, "der Zaehler bleibt derselbe - umgestellt wird die Aussage, nicht die Zahl");
});

/* Die Kohorte der Kritikalitaets-Tabelle ist eine Namenliste, keine Zahl. Haengt der Name allein
 * an der gerade geladenen dUNL-Liste des Browsers, ist ein Knoten, der diese Liste inzwischen
 * verlassen hat, namenlos - und eine Kohorte ohne Namen ist nicht nachverfolgbar. Die Namen
 * kommen deshalb aus derselben Auskunft, die auch die Gegenprobe traegt (lib/validator-ground.mjs,
 * xrpscan-Registry je Master-Key). Kein Name ist eine Erfindung: nicht benannt heisst null. */
test("Kohorten-Namen: jede Betroffenheits-Zeile nennt die Knoten aus der Netz-Auskunft", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "vt-names-"));
  fs.writeFileSync(path.join(dir, "2026-10-08.json"), JSON.stringify({
    date: "2026-10-08", ledgers: 3, quorumFail: 2, validators: { [A]: { ok: 1, noQuorum: 2 } },
    incidents: [
      { l: 107695059, m: A, t: NOW - 10 * 60000, type: "no-quorum", r: [] },
      { l: 107695059, m: B, t: NOW - 10 * 60000, type: "no-quorum", r: [] },
    ],
    ledgerStats: [{
      l: 107695059, t: NOW - 10 * 60000, v: 16, need: 28, top: 16, mg: -12, gap: 1000, gmed: 1000,
      c: { missed: 0, partial: 0, wrongHash: 0, noQuorum: 19 },
      ch: "986E8D51A78E8B2CB53B0FDBAE613692C7D33E3C82DCEE20A2C22D5496B34602",
      chSource: "xrpscan", chVerifiedBy: "xrplcluster.com", cl: true,
    }],
  }));
  const win = { missed: 0, total: 20404, score: "1.00000", incomplete: false };
  const named = new Map([[A, { asOfMs: NOW, name: "xrp.vet", windows: { 24: win } }], [B, { asOfMs: NOW, name: "bitso.com", windows: { 24: win } }]]);
  const rows = (groundPeers) => traceForValidator(loadDays(dir, NOW), A, { range: "all", now: NOW, groundPeers }).diagnosis.criticality.rows[0];

  const withName = rows(named);
  assert.deepEqual(withName.affectedMasters, [B]);
  assert.deepEqual(withName.affectedNames, [{ master: B, name: "bitso.com" }], "der Knoten wird beim Namen genannt, nicht als Key");
  assert.equal(withName.affectedNames.length, withName.affectedMasters.length, "Name und Key muessen indexgleich bleiben");

  // In der Auskunft, aber ohne Domain-Angabe: null. Ein Master-Key ist kein Name, und eine
  // erfundene Bezeichnung waer eine Behauptung ueber einen Knoten, die keine Quelle hergibt.
  const noDomain = new Map([[B, { asOfMs: NOW, windows: { 24: win } }]]);
  assert.deepEqual(rows(noDomain).affectedNames, [{ master: B, name: null }]);
  // Knoten fehlt in der Auskunft komplett: ebenfalls null, nicht 'kein Validator'.
  assert.deepEqual(rows(new Map([[A, { asOfMs: NOW, name: "xrp.vet", windows: { 24: win } }]])).affectedNames, [{ master: B, name: null }]);
  // Ganz ohne Auskunft: dieselbe Liste, jeder Name null.
  const blind = rows(null);
  assert.equal(blind.affectedNames.length, 1);
  assert.equal(blind.affectedNames[0].master, B);
  assert.equal(blind.affectedNames[0].name, null);
});
/* Die Spanne ZWISCHEN Tagesdateien (gemessen 2026-10-16 -> 2026-10-17 auf dem Daten-Repo:
 * 22:20:52Z letzter Close, 01:49:22Z erster Close des naechsten Tages). Sie steht in keiner
 * Datei, die existiert. Ohne eigene Zahl wirkt ein Rekorder-Stop wie nichts passiert. */
const holedDays = (firstA, lastA, firstB, lastB) => [
  { date: "2026-10-16", ledgers: 100, quorumFail: 0, incidents: [], validators: { [A]: { ok: 10, partial: 0, missed: 0, wrongHash: 0, noQuorum: 0 } },
    firstMs: Date.parse(firstA), lastMs: Date.parse(lastA) },
  { date: "2026-10-17", ledgers: 50, quorumFail: 0, incidents: [], validators: { [A]: { ok: 5, partial: 0, missed: 0, wrongHash: 0, noQuorum: 0 } },
    firstMs: Date.parse(firstB), lastMs: Date.parse(lastB) },
];

test("coverage: die unbeobachtete Spanne zwischen Tagesdateien steht als eigene Zahl da", () => {
  const t = traceForValidator(
    holedDays("2026-10-16T00:00:00.000Z", "2026-10-16T22:20:52.000Z", "2026-10-17T01:49:22.000Z", "2026-10-17T04:00:00.000Z"),
    A, { range: "7d", now: Date.parse("2026-10-17T05:00:00.000Z") });
  assert.equal(t.coverage.unobservedRanges, 1);
  assert.equal(t.coverage.unobservedMs, 12510000, "3 h 28 min 30 s, nachgerechnet aus den zwei Marken");
  assert.equal(t.coverage.unobservedLargest.between, "2026-10-16->2026-10-17");
  assert.equal(t.coverage.unobservedLargest.fromIso, "2026-10-16T22:20:52.000Z");
  assert.equal(t.coverage.unobservedLargest.toIso, "2026-10-17T01:49:22.000Z");
});

test("coverage: lückenlose Tage melden null Range, nicht eine erfundene Lücke", () => {
  const t = traceForValidator(
    holedDays("2026-10-16T00:00:00.000Z", "2026-10-16T23:59:52.000Z", "2026-10-17T00:00:00.000Z", "2026-10-17T04:00:00.000Z"),
    A, { range: "7d", now: Date.parse("2026-10-17T05:00:00.000Z") });
  assert.equal(t.coverage.unobservedRanges, 0);
  assert.equal(t.coverage.unobservedMs, 0);
  assert.equal(t.coverage.unobservedLargest, null, "keine Luecke ist nicht die Luecke null");
});


/* Benannte Kohorte (2026-10-17): die Retrace-Karte nannte die Knoten, die auf demselben Ledger
 * ebenfalls abwichen, aber ohne Gegenurteil. Ohne Gegenurteil ist "1 anderer Knoten" eine Zahl
 * ueber diese Erfassung, die als Knoten-Aussage gelesen wird. Guard ist, dass jeder benannte
 * Knoten sein Urteil traegt - und dass ohne Netz-Referenz offen dasteht, nicht gedeckt. */
test("Retrace-Kohorte: jeder benannte Knoten traegt ein Gegenurteil, ohne Referenz offen", () => {
  const peerDays = [day("2026-10-08", [
    { l: 7, m: A, t: NOW - 20 * 60000, type: "missed", r: ["load-spike"] },
    { l: 7, m: B, t: NOW - 20 * 60000, type: "missed", r: ["load-spike"] },
  ], { [A]: { ok: 50, partial: 0, missed: 1, wrongHash: 0 }, [B]: { ok: 50, partial: 0, missed: 1, wrongHash: 0 } })];
  const t = traceForValidator(peerDays, A, { range: "all", now: NOW });
  const card = t.retrace.find((r) => (r.affected?.peerMasters ?? []).includes(B));
  assert.ok(card, "Retrace-Karton ohne benannte Kohorte");
  assert.ok(card.affected.peerTruth && card.affected.peerTruth[B], "benannter Knoten ohne Gegenurteil");
  assert.equal(card.affected.peerTruth[B].verdict, "not-comparable");
  assert.equal(card.affected.peerNames[B], null, "ohne Netz-Auskunft darf kein Name stehen");
  for (const key of ["sameTypeMasters", "otherTypeMasters", "captureOnlyMasters", "openMasters"]) {
    for (const m of card.affected[key] ?? []) {
      assert.ok(card.affected.peerTruth[m] !== undefined, key + " ohne Gegenurteil fuer " + m);
      assert.ok(Object.prototype.hasOwnProperty.call(card.affected.peerNames, m), key + " ohne Namen-Schluessel fuer " + m);
    }
  }
});

/* Kohorten-Gegenurteil an Sammelblock und Massen-Peaks (2026-10-17): beide Tafeln nannten die
 * betroffenen dUNL-Knoten als Namen ohne eigenes Gegenurteil. Ohne Gegenurteil ist "12 Knoten
 * auf diesem Ledger" eine Zahl ueber diese Erfassung, die als Netz-Urteil gelesen wird. Guard
 * ist die Verdrahtung: Urteil und Registry-Name indexgleich zu masters - und ohne Netz-Referenz
 * steht null da, weil "kein Urteil" eine offene Frage ist und keine Entlastung. */
const COHORT_NOW = Date.UTC(2026, 9, 8, 12, 0, 0);
const C = "nCCC";
const LEDGERS4 = [1000000, 1000001, 1000002, 1000003];
const cohortRow = (l) => ({
  l, t: COHORT_NOW - 20 * 60000, v: 20, need: 28, top: 20, mg: -8, sp: 0,
  gap: 1000, gmed: 1000, tx: 30, med: 40,
  c: { missed: 0, partial: 0, wrongHash: 0, noQuorum: 10 },
  sev: { "sender-burst": 1 }, sweep: null, fv: null, lv: null, am: [], unl: false,
  ch: "AB" + l, cl: true,
});
const cohortDays = () => [{ date: "2026-10-08", ledgers: 4, quorumFail: 4,
  validators: { [A]: { ok: 100, noQuorum: 4 }, [B]: { ok: 100, noQuorum: 4 }, [C]: { ok: 100, noQuorum: 4 } },
  incidents: LEDGERS4.flatMap((l) => [A, B, C].map((m) => ({ l, m, t: COHORT_NOW - 20 * 60000, type: "no-quorum", r: ["no-quorum"] }))),
  ledgerStats: LEDGERS4.map(cohortRow) }];
const cohortWin = { missed: 0, total: 20404, score: "1.00000", incomplete: false };
const cohortGround = () => new Map([
  [A, { asOfMs: COHORT_NOW, name: "xrp.vet", windows: { 24: cohortWin } }],
  [B, { asOfMs: COHORT_NOW, name: "bitso.com", windows: { 24: cohortWin } }],]);

// Indexgleichheit ist die Guard-Eigenschaft: ein Urteil am falschen Knoten ist schlimmer als
// keines, weil es einen entlastet, fuer den nichts geprueft wurde.
const assertPeerEdges = (masters, truth, names, where) => {
  assert.ok(Array.isArray(masters) && masters.length > 0, where + " ohne benannte Knoten");
  assert.ok(Array.isArray(truth), where + ": Gegenurteil haengt nicht an der Kante");
  assert.ok(Array.isArray(names), where + ": Namen haengen nicht an der Kante");
  assert.equal(truth.length, masters.length, where + ": Gegenurteil und Knoten sind nicht indexgleich");
  assert.equal(names.length, masters.length, where + ": Name und Knoten sind nicht indexgleich");
  for (let i = 0; i < masters.length; i++) {
    assert.equal(names[i].master, masters[i], where + ": Name haengt am falschen Knoten");
    assert.ok(truth[i] === null || truth[i].master === masters[i], where + ": Urteil haengt am falschen Knoten");
  }
};

test("Sammelblock: jeder benannte dUNL-Knoten traegt Gegenurteil und Registry-Namen", () => {
  const q = (groundPeers) => crossValidatorPatterns(cohortDays(), { range: "24h", now: COHORT_NOW, groundPeers }).attacks.signals;
  const signal = q(cohortGround()).find((s) => s.masters.includes(B));
  assert.ok(signal, "Sammelblock ohne Kohorte");
  assertPeerEdges(signal.masters, signal.peerTruth, signal.peerNames, "Sammelblock");
  const b = signal.peerTruth[signal.masters.indexOf(B)];
  assert.equal(b.verdict, "contradicted", "die Referenz sagt 0 verpasste Ledger - die Kohorten-Zahl ist widerlegt");
  assert.equal(b.claims, 4, "vier eigene Abwesenheiten in 24 h");
  assert.equal(b.groundMissed, 0, "die Netz-Referenz fuer diesen Knoten");
  assert.equal(b.falsePositiveMin, 4, "4 eigene gegen 0 der Referenz: mindestens 4 widerlegt");
  assert.equal(signal.peerNames[signal.masters.indexOf(B)].name, "bitso.com", "der Knoten wird beim Registry-Namen genannt");
  // C steht in dieser Erfassung, aber nicht in der Auskunft: Name null, Urteil ohne Referenz.
  const ci = signal.masters.indexOf(C);
  assert.equal(signal.peerNames[ci].name, null, "ohne Auskunft darf kein Name stehen");
  assert.equal(signal.peerTruth[ci].verdict, "not-comparable");
  // Ganz ohne Auskunft: dieselbe Kantenlaenge, jeder Name null, jedes Urteil null. Kein Urteil
  // ohne Referenz ist ehrlicher als ein Urteil, das keine Referenz hergibt.
  const blind = q(null)[0];
  assertPeerEdges(blind.masters, blind.peerTruth, blind.peerNames, "Sammelblock ohne Auskunft");
  assert.ok(blind.peerNames.every((n) => n.name === null), "ohne Auskunft wird ein Master-Key zum Namen");
  assert.ok(blind.peerTruth.every((t) => t === null), "ohne Auskunft steht ein Urteil da, das keine Referenz hergibt");
});

test("Massen-Peaks: die Ledger-Zeile nennt die abweichenden Knoten mit eigenem Gegenurteil", () => {
  const peaks = (groundPeers) => traceForValidator(cohortDays(), A, { range: "24h", now: COHORT_NOW, groundPeers }).coupling.simultaneity.peaks;
  const withGround = peaks(cohortGround());
  assert.ok(withGround.length > 0, "Kopplung ohne Massen-Ledger - die Fixture prueft die falsche Ebene");
  for (const pk of withGround) {
    assertPeerEdges(pk.masters, pk.peerTruth, pk.peerNames, "Massen-Peak " + pk.ledgerIndex);
    assert.equal(pk.peerTruth[pk.masters.indexOf(A)].verdict, "contradicted", "der abgefragte Knoten ist an diesem Ledger durch die Referenz widerlegt");
    assert.equal(pk.peerNames[pk.masters.indexOf(A)].name, "xrp.vet");
    assert.equal(pk.peerTruth[pk.masters.indexOf(C)].verdict, "not-comparable", "Knoten ohne Auskunft bekommt kein Urteil, das nach einem Urteil aussieht");
  }
  for (const pk of peaks(null)) {
    assertPeerEdges(pk.masters, pk.peerTruth, pk.peerNames, "Massen-Peak ohne Auskunft " + pk.ledgerIndex);
    assert.ok(pk.peerNames.every((n) => n.name === null));
    assert.ok(pk.peerTruth.every((t) => t === null));
  }
});

/* Die Achse des Profils darf nicht vor der Aufnahme beginnen. Ein 30-Tage-Fenster auf eine
 * 10 Tage alte Aufnahme bekam 16 von 24 Intervallen im Zustand "kein Ledger aufgezeichnet",
 * obwohl der Rekorder damals noch nicht lief - nachgerechnet an der ausgelieferten Aufnahme
 * von xrp.vet (Fenster ab 09-17, aeltester Vorfall 10-09). Zwei Drittel des Profils waren
 * Vorlauf, und der Vorlauf liest sich wie Ausfall. */
// HOUR_MS und NOW sind oben im File definiert (Zeile 123) - hier wiederverwendet.
const hourKey = (k) => Math.floor(NOW / HOUR_MS) - k;
const shortRecording = [{
  date: "2026-10-08", ledgers: 7200, quorumFail: 0,
  hourly: Object.fromEntries(Array.from({ length: 8 }, (_, i) =>
    [hourKey(i + 1), { l: 900, v: { [A]: { ok: 900, partial: 0, missed: 0, wrongHash: 0, noQuorum: 0 } } }])),
  incidents: [{ l: 42, m: A, t: NOW - 2 * HOUR_MS, type: "missed", r: [] }],
}];

test("profileCells: ein Fenster vor der Aufnahme klemmt die Achse und weist die Klemmung aus", () => {
  // Nachgerechnet: 30-d-Fenster beginnt bei NOW - 30 d = 2026-09-17 12:00. Aelteste
  // Beobachtung ist die Stunde NOW - 8 h (04:00), aeltester Vorfall NOW - 2 h (10:00).
  // Achse = 04:00, width = 8 h = 28 800 000 ms, Intervall = 1 200 000 ms = 20 min.
  // Vorfall 10:00: Abstand 6 h = 21 600 000 / 1 200 000 = 18 -> Intervall 18.
  // Jedes der 24 Intervalle liegt ganz in genau einer Stunde: 900 * 1 200 000 / 3 600 000
  // = 300 Ledger je Intervall, 24 * 300 = 7 200 = die Tagessumme.
  const p = profileCells(shortRecording, A, { range: "30d", now: NOW });
  assert.equal(p.clamped, true, "das Fenster beginnt vor der Aufnahme");
  assert.equal(p.windowFrom, NOW - 30 * 86400000);
  assert.equal(p.from, NOW - 8 * HOUR_MS);
  assert.equal(p.cells.length, 24);
  assert.equal(p.cells.filter((c) => c.ledgers + c.ledgersEstimated === 0).length, 0,
    "kein Intervall behauptet eine Luecke, die vor dieser Aufnahme liegt");
  assert.equal(p.cells[18].total, 1);
  assert.equal(p.cells.reduce((a, c) => a + c.total, 0), 1);
  assert.equal(p.cells[0].ledgers, 300);
  assert.equal(p.cells.reduce((a, c) => a + c.ledgers, 0), 7200, "der Nenner verliert keine Ledger durch die Klemmung");
});

test("profileCells: eine Aufnahme, die das Fenster fuellt, bleibt beim gewaehlten Fensterbeginn", () => {
  const wide = Object.fromEntries(Array.from({ length: 24 }, (_, i) =>
    [hourKey(i + 1), { l: 900, v: { [A]: { ok: 900, partial: 0, missed: 0, wrongHash: 0, noQuorum: 0 } } }]));
  const d = [{
    date: "2026-10-07", ledgers: 21600, quorumFail: 0, hourly: wide,
    incidents: [{ l: 9, m: A, t: NOW - HOUR_MS, type: "missed", r: [] }],
  }];
  const p = profileCells(d, A, { range: "24h", now: NOW });
  assert.equal(p.clamped, false, "die Aufnahme fuellt das Fenster - die Achse bleibt am Fenster");
  assert.equal(p.windowFrom, null, "ohne Klemmung gibt es keinen abweichenden Fensterbeginn");
  assert.equal(p.from, NOW - 24 * HOUR_MS);
});

test("profileCells: die Klemmung laesst keinen Vorfall vor der Achse fallen", () => {
  const d = [{
    date: "2026-10-08", ledgers: 900, quorumFail: 0,
    hourly: { [hourKey(1)]: { l: 900, v: { [A]: { ok: 900, partial: 0, missed: 0, wrongHash: 0, noQuorum: 0 } } } },
    incidents: [{ l: 7, m: A, t: NOW - 10 * HOUR_MS, type: "missed", r: [] }, { l: 8, m: A, t: NOW - HOUR_MS, type: "missed", r: [] }],
  }];
  // Der aelteste Vorfall (NOW - 10 h) liegt vor der einzigen Beobachtungsstunde (NOW - 1 h),
  // also beginnt die Achse bei ihm: width = 10 h = 36 000 000 ms, Intervall = 1 500 000 ms.
  // Vorfall NOW - 10 h -> Intervall 0; Vorfall NOW - 1 h -> Abstand 9 h = 32 400 000 /
  // 1 500 000 = 21,6 -> Intervall 21.
  const p = profileCells(d, A, { range: "24h", now: NOW });
  assert.equal(p.from, NOW - 10 * HOUR_MS);
  assert.equal(p.cells[0].total, 1);
  assert.equal(p.cells[21].total, 1);
  assert.equal(p.cells.reduce((a, c) => a + c.total, 0), 2, "kein Vorfall faellt vor die Achse");
});
