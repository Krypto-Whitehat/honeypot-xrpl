// lib/pattern-watch.test.mjs — Muster-Monitor: Treffer + Guard je Muster.
import test from "node:test";
import assert from "node:assert/strict";
import { detectPatterns, traceWindow, PATTERN_DEFAULTS } from "./pattern-watch.mjs";

const T0 = Date.UTC(2026, 9, 8, 12, 0, 0);
// Stetige Basis: 40 Ledger à 4 s, 20 Tx, 0 Funde.
const base = (n = 40) => Array.from({ length: n }, (_, i) => ({
  ledgerIndex: 1000 + i, closeMs: T0 + i * 4000, txCount: 20, malicious: 0, suspect: 0,
}));

test("load-spike: 200 Tx bei Basis 20 -> Anomalie mit Zeit und Verhältnis", () => {
  const s = base();
  s.push({ ledgerIndex: 1040, closeMs: T0 + 40 * 4000, txCount: 200, malicious: 0, suspect: 0 });
  const a = detectPatterns(s).find((x) => x.type === "load-spike");
  assert.ok(a);
  assert.equal(a.ledgerIndex, 1040);
  assert.equal(a.timeMs, T0 + 40 * 4000);
  assert.equal(a.value, 200);
  assert.equal(a.baseline, 20);
  assert.equal(a.ratio, 10);
});
test("load-spike Guard: 45 Tx (unter Untergrenze 50) bleibt still", () => {
  const s = base();
  s.push({ ledgerIndex: 1040, closeMs: T0 + 160000, txCount: 45, malicious: 0, suspect: 0 });
  assert.ok(!detectPatterns(s).some((x) => x.type === "load-spike"));
});

test("close-gap: 60 s Lücke bei 4 s Takt -> Anomalie", () => {
  const s = base();
  s.push({ ledgerIndex: 1040, closeMs: T0 + 39 * 4000 + 60000, txCount: 20, malicious: 0, suspect: 0 });
  const a = detectPatterns(s).find((x) => x.type === "close-gap");
  assert.ok(a);
  assert.equal(a.value, 60000);
  assert.equal(a.baseline, 4000);
});
test("close-gap Guard: normaler 4-s-Takt bleibt still", () => {
  const s = base(); s.push({ ledgerIndex: 1040, closeMs: T0 + 40 * 4000, txCount: 20, malicious: 0, suspect: 0 });
  assert.ok(!detectPatterns(s).some((x) => x.type === "close-gap"));
});

test("fund-burst: 12 Funde bei Basis 0 -> Anomalie", () => {
  const s = base();
  s.push({ ledgerIndex: 1040, closeMs: T0 + 160000, txCount: 20, malicious: 4, suspect: 8 });
  assert.ok(detectPatterns(s).some((x) => x.type === "fund-burst" && x.value === 12));
});
test("fund-burst Guard: 3 Funde (unter Untergrenze 5) bleiben still", () => {
  const s = base();
  s.push({ ledgerIndex: 1040, closeMs: T0 + 160000, txCount: 20, malicious: 1, suspect: 2 });
  assert.ok(!detectPatterns(s).some((x) => x.type === "fund-burst"));
});

test("Mindestbasis: unter minBaseline wird NICHTS gemeldet (kein Raten)", () => {
  const s = base(5);
  s.push({ ledgerIndex: 1005, closeMs: T0 + 20000, txCount: 500, malicious: 0, suspect: 0 });
  assert.equal(detectPatterns(s).length, 0);
});

test("Eingabe: unsortiert und mit Müll-Samples robust", () => {
  const s = base().reverse();
  s.push(null, { ledgerIndex: "x" });
  assert.deepEqual(detectPatterns(s), []);
});

test("traceWindow: filtert Samples und Anomalien auf den Zeitraum", () => {
  const s = base();
  const an = [{ type: "load-spike", timeMs: T0 + 10000 }, { type: "fund-burst", timeMs: T0 + 900000 }];
  const w = traceWindow(s, an, T0, T0 + 20000);
  assert.equal(w.samples.length, 6);
  assert.equal(w.anomalies.length, 1);
  assert.equal(w.anomalies[0].type, "load-spike");
});
test("PATTERN_DEFAULTS sind exportiert und explizit (Tuning, kein Kampagnen-Nachweis)", () => {
  assert.equal(PATTERN_DEFAULTS.minBaseline, 10);
});

test("close-gap Guard: ein Abstand ueber ausgelassene Indizes ist keine Netz-Luecke", () => {
  // Dieselbe 60-s-Distanz, aber die Index-Folge springt (1039 -> 1045): die sechs fehlenden
  // Ledger stecken im Abstand, nicht das Netz.
  const s = base();
  s.push({ ledgerIndex: 1045, closeMs: T0 + 39 * 4000 + 60000, txCount: 20, malicious: 0, suspect: 0 });
  const a = detectPatterns(s);
  assert.ok(!a.some((x) => x.type === "close-gap"), "Index-Sprung: der Abstand ist keine Takt-Aussage");
  // Lueckenlos derselbe Abstand -> die Taktung ist gemessen langsam.
  const t = base();
  t.push({ ledgerIndex: 1040, closeMs: T0 + 39 * 4000 + 60000, txCount: 20, malicious: 0, suspect: 0 });
  assert.ok(detectPatterns(t).some((x) => x.type === "close-gap" && x.value === 60000));
});
