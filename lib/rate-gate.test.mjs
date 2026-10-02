// lib/rate-gate.test.mjs — node:test-Unit-Tests für den Token-Bucket
// (lib/rate-gate.mjs). KOMPLETT OFFLINE: injizierte Fake-Uhr, keine
// Netzwerk-Calls, kein setTimeout in den Simulations-Tests (tryAcquire-Pfad).
// Simulierte Grenzwerte laut Plan-RateMath (Token-Bucket 10/s, Kapazität 50,
// Start 20): 70 req in 5 s, 270 req in 25 s, 320 req in 30 s.
import test from "node:test";
import assert from "node:assert/strict";
import { createRateGate, parseRetryAfterMs } from "./rate-gate.mjs";

// ---------- Fake-Uhr ----------
// now() liefert ein mutierbares t; die Simulation rückt t selbst vor.
function fakeClock(start = 0) {
  let t = start;
  return {
    now: () => t,
    advance: (ms) => {
      t += ms;
    },
    get t() {
      return t;
    },
  };
}

// Simulation: k Requests so schnell wie möglich durch den Gate; die Fake-Uhr
// rückt pro Erfolg um stepMs, bei Ablehnung um die genannte Wartezeit.
// Rückgabe: Anzahl der Requests, die innerhalb des Fensters [0, windowMs]
// durchgelassen wurden.
function simulateThroughput(gate, clock, windowMs, stepMs = 10) {
  let count = 0;
  for (;;) {
    const r = gate.tryAcquire(1);
    if (r.ok) {
      count += 1;
      clock.advance(stepMs);
      if (clock.t > windowMs) break;
      continue;
    }
    if (!Number.isFinite(r.waitMs)) break; // Kapazität überschritten
    clock.advance(r.waitMs);
    if (clock.t > windowMs) break;
  }
  return count;
}

// ---------- Konfiguration ----------

test("createRateGate: Defaults 10/s, Kapazität 50, Start 20", () => {
  const clock = fakeClock();
  const gate = createRateGate({ now: clock.now });
  assert.equal(gate.available(), 20, "initial 20 Tokens");
  clock.advance(1000);
  assert.equal(gate.available(), 30, "Refill 10/s");
  clock.advance(10000);
  assert.equal(gate.available(), 50, "Kappung auf Burst-Kapazität 50");
});

test("createRateGate: initialTokens über Kapazität wird gekappt; Garbage -> Defaults", () => {
  const clock = fakeClock();
  assert.equal(createRateGate({ initialTokens: 999, now: clock.now }).available(), 50);
  assert.equal(createRateGate({ initialTokens: "x", now: clock.now }).available(), 20);
  assert.equal(createRateGate({ ratePerSec: -3, now: clock.now }).available(), 20);
});

// ---------- Simulierte Grenzwerte (Plan-RateMath) ----------

test("Simulation: 70 Requests in 5 s (20 Start + 50 Refill)", () => {
  const clock = fakeClock();
  const gate = createRateGate({ now: clock.now });
  assert.equal(simulateThroughput(gate, clock, 5000), 70);
});

test("Simulation: 270 Requests in 25 s (nutzbarer Advance-Tick)", () => {
  const clock = fakeClock();
  const gate = createRateGate({ now: clock.now });
  assert.equal(simulateThroughput(gate, clock, 25000), 270);
});

test("Simulation: 320 Requests in 30 s (volle maxDuration)", () => {
  const clock = fakeClock();
  const gate = createRateGate({ now: clock.now });
  assert.equal(simulateThroughput(gate, clock, 30000), 320);
});

// ---------- tryAcquire-Wartezeit ----------

test("tryAcquire: leerer Gate nennt die Refill-Wartezeit", () => {
  const clock = fakeClock();
  const gate = createRateGate({ initialTokens: 1, now: clock.now });
  assert.deepEqual(gate.tryAcquire(1), { ok: true, waitMs: 0 });
  const r = gate.tryAcquire(1);
  assert.equal(r.ok, false);
  assert.equal(r.waitMs, 100, "1 Token bei 10/s -> 100 ms");
  clock.advance(100);
  assert.deepEqual(gate.tryAcquire(1), { ok: true, waitMs: 0 });
});

test("tryAcquire: n > burstCapacity ist unmöglich (waitMs unendlich)", () => {
  const clock = fakeClock();
  const gate = createRateGate({ now: clock.now });
  const r = gate.tryAcquire(51);
  assert.equal(r.ok, false);
  assert.equal(Number.isFinite(r.waitMs), false);
});

test("tryAcquire: n Tokens auf einmal — Wartezeit skaliert linear", () => {
  const clock = fakeClock();
  const gate = createRateGate({ initialTokens: 2, now: clock.now });
  assert.deepEqual(gate.tryAcquire(2), { ok: true, waitMs: 0 });
  const r = gate.tryAcquire(4);
  assert.equal(r.ok, false);
  assert.equal(r.waitMs, 400, "4 Tokens bei 10/s -> 400 ms");
});

// ---------- Resett nach Inaktivität ----------

test("Resett nach Inaktivität: langes Sitzen füllt auf volle Kapazität", () => {
  const clock = fakeClock();
  const gate = createRateGate({ now: clock.now });
  // Leersitzen (50 Tokens) -> dann 50 Requests sofort durchlassbar.
  clock.advance(10000);
  assert.equal(gate.available(), 50);
  let immediate = 0;
  for (let i = 0; i < 50; i++) if (gate.tryAcquire(1).ok) immediate += 1;
  assert.equal(immediate, 50, "Burst von 50 ohne Warten");
  assert.equal(gate.tryAcquire(1).ok, false, "danach leer");
});

// ---------- acquire (async, echte Uhr) ----------

test("acquire: wartet die Refill-Zeit und gibt dann Tokens frei", async () => {
  const gate = createRateGate({ initialTokens: 1, ratePerSec: 20 });
  assert.equal(gate.tryAcquire(1).ok, true);
  const start = Date.now();
  await gate.acquire(1); // 1 Token bei 20/s -> ~50 ms
  assert.ok(Date.now() - start >= 40, "acquire hat gewartet");
  // Das aufgefüllte Token wurde von acquire verbraucht -> Gate wieder leer.
  assert.equal(gate.tryAcquire(1).ok, false, "Token wurde von acquire verbraucht");
});

test("acquire: n über Kapazität -> ehrlicher Fehler (kein Endlos-Warten)", async () => {
  const gate = createRateGate({ burstCapacity: 5 });
  await assert.rejects(() => gate.acquire(6), /Burst-Kapazität/);
});

// ---------- parseRetryAfterMs (retry-after-Header) ----------

test("parseRetryAfterMs: Sekunden-Form", () => {
  assert.equal(parseRetryAfterMs("30"), 30000);
  assert.equal(parseRetryAfterMs(2.5), 2500);
  assert.equal(parseRetryAfterMs("0"), 0);
  assert.equal(parseRetryAfterMs("-5"), null, "negativ -> null");
});

test("parseRetryAfterMs: HTTP-Datum-Form (Delta zur jetzigen Zeit)", () => {
  const future = new Date(Date.now() + 60000).toUTCString();
  const ms = parseRetryAfterMs(future);
  assert.ok(ms != null && ms > 50000 && ms <= 61000, `Delta plausibel: ${ms}`);
  const past = new Date(Date.now() - 60000).toUTCString();
  assert.equal(parseRetryAfterMs(past), 0, "vergangenes Datum -> 0");
});

test("parseRetryAfterMs: Garbage -> null", () => {
  assert.equal(parseRetryAfterMs(null), null);
  assert.equal(parseRetryAfterMs(undefined), null);
  assert.equal(parseRetryAfterMs(""), null);
  assert.equal(parseRetryAfterMs("kein Datum"), null);
});
