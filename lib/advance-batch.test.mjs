// node:test für die Quota-/Backoff-Logik des Advance-Endpunkts (api/advance.js).
//
// NAMENSHINWEIS: "advance-batch" ist historisch — der Endpunkt lehnt
// JSON-RPC-Batches deterministisch ab (Befund 2026-10-01: "invalidParams"/31
// "batched requests are not supported"; NDJSON: "jsonInvalid"/31). Der Inhalt
// dieser Tests ist daher die QUOTA-/BACKOFF-LOGIK: dass der Backoff das
// genannte Retry-Fenster (retry_after / "retry in ~Nms") korrekt parst und die
// korrekte Dauer respektiert, und dass die Budget-Größenbestimmung die
// Units-Quota respektiert. FIXTURE-basiert, deterministisch, KEIN Netzwerk.
//
// Fixtures modellieren die live beobachteten Signale (lib/live-gate.mjs:18-22,
// public/app.js:1148-1149) — keine Erfindung von Endpunkt-Verhalten.

import test from "node:test";
import assert from "node:assert/strict";
import {
  parseRetryWindowMs,
  backoffDelayMs,
  worstCaseTickCommands,
  maxBudgetForQuota,
  COMMAND_COST_CEILING,
  TICK_UNIT_BUDGET,
  MAX_RESOLVE,
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

// ---------- worstCaseTickCommands ----------

test("worstCaseTickCommands: Budget × (1 ledger + maxResolve tx)", () => {
  assert.equal(worstCaseTickCommands(5, 40), 205, "alte Default-Form (5×41)");
  assert.equal(worstCaseTickCommands(1, 6), 7, "neue Default-Form (1×7)");
  assert.equal(worstCaseTickCommands(0, 6), 0);
  assert.equal(worstCaseTickCommands(2, 3), 8);
});

test("worstCaseTickCommands: Garbage-Inputs -> 0", () => {
  assert.equal(worstCaseTickCommands("x", 6), 0);
  assert.equal(worstCaseTickCommands(3, undefined), 3);
  assert.equal(worstCaseTickCommands(-2, 6), 0);
  assert.equal(worstCaseTickCommands(2.9, 6), 2 * 7, "Budget wird gefloort");
});

// ---------- maxBudgetForQuota (Quota-Respekt) ----------

test("maxBudgetForQuota: Default-Parameter (TICK_UNIT_BUDGET/COMMAND_COST_CEILING)", () => {
  // ceiling = floor(5000/700) = 7 Commands/Tick.
  assert.equal(maxBudgetForQuota(6), 1, "floor(7/7)");
  assert.equal(maxBudgetForQuota(0), 7, "floor(7/1)");
  assert.equal(maxBudgetForQuota(2), 2, "floor(7/3)");
  assert.equal(maxBudgetForQuota(60), 0, "floor(7/61)");
  assert.equal(maxBudgetForQuota("x"), 7, "Garbage maxResolve -> 0");
});

test("maxBudgetForQuota: opts-Override der Quota-Parameter", () => {
  // floor(10000/700) = 14 Commands/Tick -> floor(14/7) = 2.
  assert.equal(maxBudgetForQuota(6, { quotaUnits: 10000, costCeiling: 700 }), 2);
  assert.equal(maxBudgetForQuota(0, { quotaUnits: 100, costCeiling: 100 }), 1);
});

// Die eigentliche Quota-Prüfung: jedes Budget bis zur Grenze respektiert die
// Quota (Commands × Kosten-Obergrenze <= TICK_UNIT_BUDGET), und das erste
// Budget darüber verletzt sie.
test("maxBudgetForQuota: Quota-Respekt-Eigenschaft", () => {
  for (const m of [0, 2, 6, 40]) {
    const limit = maxBudgetForQuota(m);
    for (let b = 0; b <= limit; b++) {
      assert.ok(
        worstCaseTickCommands(b, m) * COMMAND_COST_CEILING <= TICK_UNIT_BUDGET,
        `Budget ${b} bei maxResolve ${m} muss die Quota respektieren`
      );
    }
    if (limit > 0) {
      assert.ok(
        worstCaseTickCommands(limit + 1, m) * COMMAND_COST_CEILING > TICK_UNIT_BUDGET,
        `Budget ${limit + 1} bei maxResolve ${m} verletzt die Quota`
      );
    }
  }
});

// ---------- Derivierte Defaults ----------

test("DEFAULT_BUDGET ist aus der Quota abgeleitet und respektiert sie", () => {
  assert.equal(DEFAULT_BUDGET, maxBudgetForQuota(MAX_RESOLVE), "Default ist abgeleitet, kein Magic Number");
  assert.ok(DEFAULT_BUDGET >= 1, "Default muss tatsächlich vorrücken");
  assert.ok(
    worstCaseTickCommands(DEFAULT_BUDGET, MAX_RESOLVE) * COMMAND_COST_CEILING <= TICK_UNIT_BUDGET,
    "Worst-Case-Tick des Defaults respektiert die Quota"
  );
  assert.ok(MAX_RESOLVE < 40, "MAX_RESOLVE ist reduziert");
});
