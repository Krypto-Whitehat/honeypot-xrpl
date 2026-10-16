// lib/validator-sensitivity.test.mjs - Signatur-Empfindlichkeit: 2x2-Tafel, Kohorten-Gegenprobe,
// Urteile und die Grenzen der Messbasis.
//
// Die Zahlen sind von Hand nachgerechnet (rateWith, rateWithout, Lift, z), damit ein Fehler in
// der Tafel nicht als plausible Zahl durchgeht. Jeder Fall prueft eine andere Aussage:
// Knotenproblem / Netzlage / Signatur erklaert die Ausfaelle nicht / duenn / keine Exposition /
// Messbasis fehlt (Altbestand).
import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { ANOMALY_TAGS } from "./validator-trace.mjs";
import { SIGNATURE_TAGS } from "./tx-forensics.mjs";
import {
  SENSITIVITY_DEFAULTS, SENSITIVITY_VERDICTS, SENSITIVITY_GAPS, SENSITIVITY_HEADLINES, SENSITIVITY_FAMILIES,
  familyOf, isAnomalyTag, twoProportion, signatureSensitivity, signatureCohort,
} from "./validator-sensitivity.mjs";

const here = path.dirname(fileURLToPath(import.meta.url));
const NOW = Date.UTC(2026, 9, 8, 12, 0, 0);
const DAY = 86400000;
const A = "nAAA", B = "nBBB", C = "nCCC", D = "nDDD";

// Ein Tag, der die Signatur-Ebene fuehrt (Marker): die Basis jeder Rate.
const day = (over = {}) => ({
  date: "2026-10-08", ledgers: 1000, firstMs: NOW - DAY, lastMs: NOW,
  incidents: [], anomaly: {}, anomalyFail: {}, anomalyRecorded: true, ...over,
});
const inc = (l, m, r) => ({ l, m, t: NOW - 60000, type: "missed", r });
const many = (from, count, m, r) => Array.from({ length: count }, (_, i) => inc(from + i, m, r));
const rowOf = (s, tag) => s.rows.find((r) => r.tag === tag);

test("twoProportion: von Hand nachgerechneter Zwei-Stichproben-z", () => {
  // 10/100 gegen 5/100: gepoolt 15/200 = 0,075; sd = sqrt(0,075*0,925*(1/100+1/100)) = 0,0372492;
  // z = 0,05 / 0,0372492 = 1,34231. p zweiseitig = erfc(1,34231/sqrt(2)) = erfc(0,94916).
  // Gegenprobe von Hand: 1 - Phi(1,34231) = 0,089747, verdoppelt = 0,179494. Referenz durch
  // numerische Integration von exp(-t^2) (siehe Session): erfc(0,94916) = 0,179493900.
  const r = twoProportion(10, 100, 5, 100);
  assert.equal(r.z, 1.342);
  assert.ok(Math.abs(r.p - 0.179494) < 0.0005, "p zweiseitig: " + r.p);
  assert.deepEqual(twoProportion(1, 0, 1, 10), { z: null, p: null }, "ohne Nenner keine Testgroesse");
  assert.deepEqual(twoProportion(0, 10, 0, 10).z, null, "gepoolte Varianz 0 ist keine Testgroesse");
});

test("familyOf: jede Vokabel der Anomalie-Ebene hat eine Prueffamilie", () => {
  for (const tag of [...ANOMALY_TAGS, ...SIGNATURE_TAGS, "type-burst:Payment", "new-tx-type:WeirdType"]) {
    assert.ok(SENSITIVITY_FAMILIES.includes(familyOf(tag)), tag + " hat keine Familie (Pruefung waere leer)");
  }
  assert.equal(familyOf("no-correlated-cause"), null, "kein Grund ist keine Signatur");
  assert.equal(familyOf("vote-late"), null, " Spaetvalidierung ist keine Ledger-Signatur");
  assert.ok(isAnomalyTag("type-burst:Payment") && !isAnomalyTag("partial-validation"));
});

test("signatureSensitivity: hoher Lift nur bei dir, Kohorte unauffaellig -> Knotenproblem", () => {
  // A: 10 Ausfaelle auf 200 Ledern mit load-spike (0,05) gegen 5 auf 800 ohne (0,00625) -> Lift 8.
  // B/C/D je 1 Signatur-Ausfall: unter der Mindestzahl, also kein Kohorten-Urteil -> Kohorten-Lift null.
  const days = [day({
    anomaly: { "load-spike": 200 }, anomalyFail: { "load-spike": 10 },
    incidents: [...many(100, 10, A, ["load-spike"]), ...many(500, 5, A, []),
      inc(600, B, ["load-spike"]), inc(601, B, []), inc(602, C, ["load-spike"]), inc(603, C, []),
      inc(604, D, ["load-spike"]), inc(605, D, [])],
  })];
  const s = signatureSensitivity(days, A, { range: "all", now: NOW });
  const row = rowOf(s, "load-spike");
  assert.equal(row.exposure, 200);
  assert.equal(row.fails, 10);
  assert.equal(row.ownFailLedgers, 15, "15 eigene Ausfall-Ledger, 10 davon mit der Signatur");
  assert.equal(row.plainLedgers, 800);
  assert.equal(row.plainFails, 5);
  assert.equal(row.rateWith, 0.05);
  assert.equal(row.rateWithout, 0.00625);
  assert.equal(row.lift, 8);
  assert.equal(row.z, 4.553, "gepoolt 15/1000, sd 0,0096096, z 0,04375/0,0096096");
  assert.equal(row.significant, true);
  assert.equal(row.cohortPeers, 0);
  assert.equal(row.cohortLift, null, "ohne belastbare Kohorte wird kein Netz-Lift erfunden");
  assert.equal(row.verdict, "signature-specific");
  assert.equal(row.family, "capacity");
  assert.deepEqual(row.nextChecks, ["cause-check-load-ceiling", "cause-check-resources"]);
  assert.equal(s.headline.verdict, "capacity-shaped");
  assert.deepEqual(s.headline.tags, ["load-spike"]);
  assert.equal(s.authority, "trace");
});

test("signatureSensitivity: derselbe Lift bei der Kohorte -> Netzlage, kein Knotenproblem", () => {
  // A Lift 8 (wie oben). B/C/D je 4 Signatur-Ausfaelle auf 200 (0,02) gegen 1 auf 800 (0,00125)
  // -> Lift 16. Median 16; A bleibt unter 16 * 1,5 = 24, also trifft die Signatur alle.
  const days = [day({
    anomaly: { "load-spike": 200 }, anomalyFail: { "load-spike": 10 },
    incidents: [...many(100, 10, A, ["load-spike"]), ...many(500, 5, A, []),
      ...many(700, 4, B, ["load-spike"]), inc(710, B, []),
      ...many(720, 4, C, ["load-spike"]), inc(730, C, []),
      ...many(740, 4, D, ["load-spike"]), inc(750, D, [])],
  })];
  const s = signatureSensitivity(days, A, { range: "all", now: NOW });
  const row = rowOf(s, "load-spike");
  assert.equal(row.lift, 8);
  assert.equal(row.cohortPeers, 3);
  assert.equal(row.cohortLift, 16);
  assert.equal(row.verdict, "signature-network");
  assert.deepEqual(row.nextChecks, [], "Netzlage hat keine Knoten-Pruefung als naechsten Schritt");
  assert.equal(s.coverage.peers, 3);
  assert.equal(s.gaps.length, 0, "diese Messung hat keine Luecke");
});

test("signatureSensitivity: Lift 1 heisst 'diese Signatur erklaert deine Ausfaelle nicht'", () => {
  // A: 10/200 = 0,05 gegen 40/800 = 0,05 -> Lift 1. Die Angriffs-Hypothese ist entlastet.
  const days = [day({
    anomaly: { "load-spike": 200 }, anomalyFail: { "load-spike": 10 },
    incidents: [...many(100, 10, A, ["load-spike"]), ...many(500, 40, A, [])],
  })];
  const row = rowOf(signatureSensitivity(days, A, { range: "all", now: NOW }), "load-spike");
  assert.equal(row.lift, 1);
  assert.equal(row.verdict, "signature-blind");
  assert.deepEqual(row.nextChecks, ["cause-check-uptime"]);
});

test("signatureSensitivity: Signatur ohne Ledger-Zaehler bleibt ohne Rate", () => {
  // Der Incident traegt drainer-fanout, aber die Tagesdatei fuehrt keinen Zaehler dafuer:
  // ohne Nenner ist jede Rate eine Erfindung, also no-exposure - nicht 'kein Effekt'.
  const days = [day({
    anomaly: { "load-spike": 200 }, anomalyFail: { "load-spike": 10 },
    incidents: [...many(100, 4, A, ["drainer-fanout"]), ...many(500, 5, A, [])],
  })];
  const s = signatureSensitivity(days, A, { range: "all", now: NOW });
  const row = rowOf(s, "drainer-fanout");
  assert.equal(row.exposure, 0);
  assert.equal(row.fails, 4, "die Ausfaelle sind gezehlt");
  assert.equal(row.lift, null, "ohne Nenner keine Rate");
  assert.equal(row.verdict, "no-exposure");
  assert.equal(row.measurable, false);
});

test("signatureSensitivity: duenne Stichprobe wird nicht zur Aussage verdichtet", () => {
  const days = [day({
    anomaly: { "load-spike": 10 }, anomalyFail: { "load-spike": 4 },
    incidents: [...many(100, 4, A, ["load-spike"]), ...many(500, 5, A, [])],
  })];
  const row = rowOf(signatureSensitivity(days, A, { range: "all", now: NOW }), "load-spike");
  assert.equal(row.exposure, 10);
  assert.equal(row.measurable, false);
  assert.equal(row.verdict, "thin-sample");
  // von Hand: 4/10 = 0,4 gegen 5/(1000-10) = 0,0050505 -> Lift 0,4 * 990/5 = 79,2.
  assert.equal(row.lift, 79.2, "die Zahl steht, aber das Urteil ist duenn");
  assert.equal(row.nextChecks.length, 0);
});

test("signatureSensitivity: ein Ledger zaehlt je Signatur genau einmal", () => {
  // Zwei Vorfaelle auf demselben Ledger (missed und partial) sind ein Ausfall-Ledger, nicht zwei.
  const days = [day({
    anomaly: { "load-spike": 200, "close-gap": 200 }, anomalyFail: {},
    incidents: [{ l: 100, m: A, t: NOW - 60000, type: "missed", r: ["load-spike"] },
      { l: 100, m: A, t: NOW - 60000, type: "partial", r: ["load-spike", "close-gap"] }],
  })];
  const s = signatureSensitivity(days, A, { range: "all", now: NOW });
  assert.equal(rowOf(s, "load-spike").fails, 1);
  assert.equal(rowOf(s, "close-gap").fails, 1);
  assert.equal(s.coverage.ownFailLedgers, 1, "zwei Vorfaelle, ein Ledger");
  assert.equal(s.coverage.incidents, 2, "die Vorfaelle selbst bleiben zwei");
});

test("signatureSensitivity: Tages-Anteil am Fenster wird prorata und als geschaetzt ausgewiesen", () => {
  // Tag spannt 30 h, Fenster 24 h -> 0,8. 200 Signatur-Ledger werden zu 160, 1000 Ledger zu 800.
  const days = [day({ firstMs: NOW - 30 * 3600000, lastMs: NOW, anomaly: { "load-spike": 200 }, anomalyFail: { "load-spike": 10 } })];
  const s = signatureSensitivity(days, A, { range: "24h", now: NOW });
  const row = rowOf(s, "load-spike");
  assert.equal(row.exposure, 160);
  assert.equal(row.plainLedgers, 640);
  assert.equal(s.coverage.ledgers, 800);
  assert.equal(s.coverage.estimated, true, "Anteil eines Tages ist eine Schaetzung, keine Auszaehlung");
});

test("signatureSensitivity: Tag ohne Tagesspanne wird nicht geschaetzt, sondern als Luecke benannt", () => {
  const days = [day({ firstMs: null, lastMs: null, anomaly: { "load-spike": 200 } })];
  const s = signatureSensitivity(days, A, { range: "all", now: NOW });
  assert.equal(s.coverage.ledgers, 0);
  assert.equal(s.coverage.daysWithoutSpan, 1);
  assert.ok(s.gaps.includes("day-span"));
});

test("signatureSensitivity: Altbestand ohne Signatur-Ebene ist Basis-Luecke, nicht Null-Rate", () => {
  // normalizeDay fuellt anomaly = {} beim Lesen. Ohne Marker war dieser Tag nie geprueft -
  // seine Ledger duerfen die Vergleichsgruppe nicht fuellen (dieselbe Regel wie riskProfile).
  const days = [day({ anomaly: undefined, anomalyRecorded: undefined, incidents: [...many(100, 4, A, ["load-spike"])] })];
  const s = signatureSensitivity(days, A, { range: "all", now: NOW });
  assert.equal(s.rows.length, 0);
  assert.equal(s.coverage.ledgers, 0);
  assert.equal(s.coverage.daysWithAnomaly, 0);
  assert.equal(s.authority, "none");
  assert.ok(s.gaps.includes("anomaly-counts"));
});

test("signatureSensitivity: Vorfaelle ohne Signatur-Grund bleiben als Luecke stehen", () => {
  const days = [day({ ledgers: 1000, anomaly: { "load-spike": 200 }, incidents: many(100, 6, A, []) })];
  const s = signatureSensitivity(days, A, { range: "all", now: NOW });
  assert.equal(s.coverage.incidents, 6);
  assert.equal(s.coverage.incidentsTagged, 0);
  assert.equal(s.coverage.incidentsUntagged, 6);
  assert.ok(s.gaps.includes("incident-tags"), "ohne Grund-Tag ist die Tafel blind, nicht sauber");
  assert.ok(s.gaps.includes("own-fails") === false, "eigene Ausfaelle sind da - die Luecke ist der Grund");
});

test("signatureSensitivity: Urteile, Familien und Schwellen sind der Vertrag", () => {
  const days = [day({ anomaly: { "load-spike": 200 }, anomalyFail: { "load-spike": 10 }, incidents: many(100, 10, A, ["load-spike"]) })];
  const s = signatureSensitivity(days, A, { range: "all", now: NOW });
  assert.ok(SENSITIVITY_VERDICTS.includes(s.rows[0].verdict), "Urteil ausserhalb der Menge: " + s.rows[0].verdict);
  for (const gap of s.gaps) assert.ok(SENSITIVITY_GAPS.includes(gap), "Luecke ausserhalb der Menge: " + gap);
  assert.ok(SENSITIVITY_HEADLINES.includes(s.headline.verdict));
  assert.equal(s.thresholds.minExposure, SENSITIVITY_DEFAULTS.minExposure);
  assert.equal(s.method.length > 40, true, "die Methode muss in der Antwort stehen, nicht nur die Zahl");
  assert.equal(s.coverage.ownFailLedgers, 10);
});

test("signatureCohort: eine Signatur, die viele Knoten trifft, wird als gemeinsame Last ausgewiesen", () => {
  const days = [day({
    anomaly: { "load-spike": 200 }, anomalyFail: { "load-spike": 10 },
    incidents: [...many(100, 10, A, ["load-spike"]), ...many(500, 5, A, []),
      ...many(700, 4, B, ["load-spike"]), inc(710, B, []),
      ...many(720, 4, C, ["load-spike"]), inc(730, C, []),
      ...many(740, 4, D, ["load-spike"]), inc(750, D, [])],
  })];
  const c = signatureCohort(days, { range: "all", now: NOW });
  const row = c.rows.find((r) => r.tag === "load-spike");
  assert.equal(row.exposure, 200);
  assert.equal(row.measuredNodes, 4);
  assert.equal(row.sensitiveNodes, 4);
  assert.equal(row.medianLift, 16, "Median ueber 8, 16, 16, 16");
  assert.equal(row.maxLift, 16);
  assert.equal(row.shared, true, "drei Knoten mit hohem Lift sind eine dUNL-weite Spur");
  assert.equal(c.coverage.nodes, 4);
});

test("Vokabel-Guard: der Recorder nutzt die geteilte Anomalie-Vokabel, keine eigene Liste", () => {
  // Zwei Vokabellisten in Recorder und Engine ist derselbe Fehler, der die Tafel still fuellt:
  // der Recorder bucht einen Tag, die Engine kennt das Tag nicht (oder umgekehrt).
  const src = fs.readFileSync(path.join(here, "..", "monitor", "validator-trace.mjs"), "utf8");
  assert.match(src, /import \{[^}]*ANOMALY_TAGS[^}]*\} from "\.\.\/lib\/validator-trace\.mjs"/, "Recorder importiert die Vokabel nicht");
  assert.doesNotMatch(src, /const ANOMALY_TAGS = /, "Recorder fuehrt eine zweite Vokabelliste");
});
