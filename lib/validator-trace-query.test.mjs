// lib/validator-trace-query.test.mjs — Abfrage der Trace-Tage: Zeitraum, Zusammenfassung, Muster.
import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { loadDays, traceForValidator, crossValidatorPatterns, RANGE_MS } from "./validator-trace-query.mjs";
import { PEER_AUTHORITIES, PEER_MIN_LEDGERS, PEER_MIN_PEERS, PEER_REASONS, PEER_VERDICTS } from "./validator-peer-benchmark.mjs";

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
