// node:test für die Request-Budget-/Backoff-Logik des Advance-Endpunkts
// (api/advance.js).
//
// NAMENSHINWEIS: "advance-batch" ist historisch — der Endpunkt lehnt
// JSON-RPC-Batches deterministisch ab (Befund 2026-10-01: "invalidParams"/31
// "batched requests are not supported"; NDJSON: "jsonInvalid"/31). Der Inhalt
// dieser Tests ist die BACKOFF-/BUDGET-LOGIK: dass der Backoff das genannte
// Retry-Fenster (retry_after / "retry in ~Nms" / HTTP retry-after-Header)
// korrekt parst und die korrekte Dauer respektiert, und dass das
// Request-Budget die honeycluster-Raten (10 req/s steady, Burst 50/5 s)
// respektiert. FIXTURE-basiert, deterministisch, KEIN Netzwerk.
//
// UMSTELLUNG 2026-10-02 (honeycluster.io): Das xrplcluster-Units-Modell
// (COMMAND_COST_CEILING/TICK_UNIT_BUDGET/maxBudgetForQuota, Budget 1 Block/
// Tick) ist ERSETZT durch Request-Zählung (1 Request/Block dank expand:true).
// Die Backoff- und seedCursor-Tests bleiben unverändert — diese Funktionen
// bleiben. Die Units-Asserts sind durch Request-Budget-Assertions mit
// echten Grenzen ersetzt (kein Test gelöscht ohne Assertions-Äquivalent).

import test from "node:test";
import assert from "node:assert/strict";
import {
  parseRetryWindowMs,
  backoffDelayMs,
  worstCaseTickRequests,
  seedCursor,
  REQUESTS_PER_SEC,
  TICK_REQUEST_BUDGET,
  FETCH_PARALLEL,
  DEFAULT_BUDGET,
} from "../api/advance.js";

// ---------- parseRetryWindowMs ----------

test("parseRetryWindowMs: retry_after-Feld (Sekunden) -> ms", () => {
  assert.equal(parseRetryWindowMs({ error: "tooBusy", retry_after: 144.662 }), 144662);
  assert.equal(parseRetryWindowMs({ error: "slowDown", retry_after: 30 }), 30000);
});

// Live-beobachtete Message-Form (lib/live-gate.mjs:18-22): Fenster nur in
// error_message genannt.
test("parseRetryWindowMs: 'retry in ~Nms' aus error_message", () => {
  const result = {
    error: "tooBusy",
    error_message: "rate limit: units quota (500000 per 3600s) exhausted, retry in ~144662ms",
  };
  assert.equal(parseRetryWindowMs(result), 144662);
});

test("parseRetryWindowMs: Präzedenz — Feld vor Message", () => {
  const result = {
    error: "tooBusy",
    retry_after: 5,
    error_message: "retry in ~99999ms",
  };
  assert.equal(parseRetryWindowMs(result), 5000, "retry_after-Feld gewinnt");
});

test("parseRetryWindowMs: ungültiges Feld fällt auf Message zurück", () => {
  const result = {
    error: "tooBusy",
    retry_after: "unparseable",
    error_message: "retry in ~12345ms",
  };
  assert.equal(parseRetryWindowMs(result), 12345);
});

test("parseRetryWindowMs: kein genanntes Fenster -> null", () => {
  assert.equal(parseRetryWindowMs({ error: "slowDown" }), null);
  assert.equal(parseRetryWindowMs({ error: "tooBusy", error_message: "rate limit: units quota (10000 per 60s)" }), null);
  assert.equal(parseRetryWindowMs({ error: "tooBusy", retry_after: 0 }), null);
  assert.equal(parseRetryWindowMs({ error: "tooBusy", retry_after: -5 }), null);
  assert.equal(parseRetryWindowMs(null), null);
  assert.equal(parseRetryWindowMs(undefined), null);
  assert.equal(parseRetryWindowMs("tooBusy"), null);
});

// ---------- backoffDelayMs ----------

test("backoffDelayMs: genanntes Fenster wird voll ausgesetzt (+Slack)", () => {
  assert.equal(backoffDelayMs(0, 144662), 146662);
  assert.equal(backoffDelayMs(2, 30000), 32000);
});

test("backoffDelayMs: ohne genanntes Fenster exponentiell mit Kappe", () => {
  assert.equal(backoffDelayMs(0, null), 2000);
  assert.equal(backoffDelayMs(1, null), 4000);
  assert.equal(backoffDelayMs(2, null), 8000);
  assert.equal(backoffDelayMs(3, null), 16000);
  assert.equal(backoffDelayMs(4, null), 30000, "Kappe greift");
  assert.equal(backoffDelayMs(5, null), 30000, "Kappe bleibt");
});

test("backoffDelayMs: nicht-positives 'Fenster' fällt in den exponentiellen Pfad", () => {
  assert.equal(backoffDelayMs(0, 0), 2000);
  assert.equal(backoffDelayMs(0, NaN), 2000);
  assert.equal(backoffDelayMs(0, -1), 2000);
  assert.equal(backoffDelayMs(-3, null), 2000, "negativer Versuch wird geklemmt");
});

// 429-Backoff (B4): der retry-after-Header eines HTTP 429 durchläuft
// dieselbe Kette parseRetryAfterMs -> backoffDelayMs (api/advance.js rpc()).
// Die Header-Parade wird gegen die echte parseRetryAfterMs aus lib/rate-gate
// geprüft, die Ketten-Semantik gegen backoffDelayMs.
test("429-Backoff: retry-after-Fenster -> volles Aussetzen (+Slack)", async () => {
  const { parseRetryAfterMs } = await import("./rate-gate.mjs");
  assert.equal(parseRetryAfterMs("30"), 30000);
  assert.equal(backoffDelayMs(0, parseRetryAfterMs("30")), 32000);
  assert.equal(backoffDelayMs(1, parseRetryAfterMs(2.5)), 4500);
  // Ohne Header -> exponentieller Pfad (HTTP-5xx ohne Fenster).
  assert.equal(parseRetryAfterMs(null), null);
  assert.equal(backoffDelayMs(0, parseRetryAfterMs(null)), 2000);
});

// ---------- worstCaseTickRequests (Request-Budget) ----------

test("worstCaseTickRequests: 1 Request pro Block (expand:true, kein tx-Kommando)", () => {
  assert.equal(worstCaseTickRequests(100), 100);
  assert.equal(worstCaseTickRequests(1), 1);
  assert.equal(worstCaseTickRequests(0), 0);
});

test("worstCaseTickRequests: Garbage-Inputs -> 0", () => {
  assert.equal(worstCaseTickRequests("x"), 0);
  assert.equal(worstCaseTickRequests(undefined), 0);
  assert.equal(worstCaseTickRequests(null), 0);
  assert.equal(worstCaseTickRequests(NaN), 0);
  assert.equal(worstCaseTickRequests(-2), 0);
  assert.equal(worstCaseTickRequests(2.9), 2, "Budget wird gefloort");
});

// ---------- Budget-Invarianten (honeycluster-Raten) ----------

test("DEFAULT_BUDGET = 100 und respektiert das Tick-Request-Budget", () => {
  assert.equal(DEFAULT_BUDGET, 100);
  assert.equal(REQUESTS_PER_SEC, 10, "honeycluster steady-Limit");
  assert.ok(
    worstCaseTickRequests(DEFAULT_BUDGET) <= TICK_REQUEST_BUDGET,
    "Worst-Case-Tick des Defaults bleibt im Request-Budget"
  );
  assert.ok(TICK_REQUEST_BUDGET <= 25 * REQUESTS_PER_SEC, "Budget passt in 25 s nutzbare Tick-Zeit");
});

test("FETCH_PARALLEL hält die Fetch-Rate unter dem steady-Limit", () => {
  // Gemessene expand:true-Latenz Ø ~0,708 s (live-Probe 2026-10-02):
  // 4 parallel -> 4/0,708 ≈ 5,66 req/s < 10 req/s steady.
  const measuredLatencyMs = 708;
  const rate = (FETCH_PARALLEL * 1000) / measuredLatencyMs;
  assert.ok(rate < REQUESTS_PER_SEC, `Fetch-Rate ${rate.toFixed(2)} req/s muss unter ${REQUESTS_PER_SEC} bleiben`);
  assert.ok(FETCH_PARALLEL >= 1 && FETCH_PARALLEL <= 8, "Parallelität im vernünftigen Rahmen");
});

// Invariante über alle tolerierten Budgets: jedes Budget bis zum ENV-Default
// respektiert das Request-Budget; das Budget über der Budget-Grenze verletzt
// es (äquivalent zur alten Quota-Respekt-Eigenschaft, jetzt in Requests).
test("Request-Budget-Respekt-Eigenschaft", () => {
  for (let b = 0; b <= DEFAULT_BUDGET; b++) {
    assert.ok(
      worstCaseTickRequests(b) <= TICK_REQUEST_BUDGET,
      `Budget ${b} muss das Request-Budget respektieren`
    );
  }
  const overBudget = TICK_REQUEST_BUDGET + 1;
  assert.ok(
    worstCaseTickRequests(overBudget) > TICK_REQUEST_BUDGET,
    `Budget ${overBudget} verletzt das Request-Budget`
  );
});

// ---------- seedCursor (Cursor-Seeding) ----------

// Der Walk startet NICHT bei Genesis (Index 0) — der öffentliche Validator
// liefert alte Blöcke nicht mehr. seedCursor setzt einen frischen Cursor auf
// den rezenten Vergangenheit: validatedIndex minus Lookback, begrenzt auf
// >= 1. Ungültiger validatedIndex -> null (kein Seed).
test("seedCursor: Live-Edge (Lookback 0) -> validatedIndex", () => {
  assert.equal(seedCursor(107000000, 0), 107000000);
  assert.equal(seedCursor(107000000, null), 107000000, "Lookback null -> 0");
  assert.equal(seedCursor(107000000, "x"), 107000000, "Garbage-Lookback -> 0");
  assert.equal(seedCursor(107000000, -5), 107000000, "negativer Lookback -> 0");
});

test("seedCursor: Lookback-Subtraktion (rezenter Vergangenheit)", () => {
  assert.equal(seedCursor(107000000, 500), 106999500, "kleiner Lookback");
  assert.equal(seedCursor(107000000, 259200), 106740800, "~1 Monat Lookback");
  assert.equal(seedCursor(10.9, 0), 10, "validatedIndex wird gefloort");
});

test("seedCursor: Lookback > validatedIndex wird auf >= 1 geklemmt", () => {
  assert.equal(seedCursor(10, 100), 1, "klemmt auf 1");
  assert.equal(seedCursor(1, 1), 1, "Gleichstand -> 1");
  assert.equal(seedCursor(5, 5), 1, "Gleichstand -> 1");
});

test("seedCursor: ungültiger validatedIndex -> null (kein Seed)", () => {
  assert.equal(seedCursor(null, 0), null);
  assert.equal(seedCursor(undefined, 0), null);
  assert.equal(seedCursor("x", 0), null);
  assert.equal(seedCursor(NaN, 0), null);
  assert.equal(seedCursor(0, 0), null, "Index 0 -> null");
  assert.equal(seedCursor(-5, 0), null, "negativer Index -> null");
});
