// lib/validator-trace-store.test.mjs — Persistenz-Hilfen des Trace (pure Teile, ohne Netzwerk).
import test from "node:test";
import assert from "node:assert/strict";
import { datesBetween, datesForRange, dayPath, TRACE_RETENTION_DAYS, TRACE_DIR } from "./validator-trace-store.mjs";

test("datesBetween: alle Tage inklusive Grenzen, neueste zuerst", () => {
  const to = Date.UTC(2026, 9, 8, 12);
  const from = Date.UTC(2026, 9, 6, 1);
  assert.deepEqual(datesBetween(from, to), ["2026-10-08", "2026-10-07", "2026-10-06"]);
});
test("datesForRange: 1h deckt den heutigen Tag ab, all ist auf die Aufbewahrung begrenzt", () => {
  const now = Date.UTC(2026, 9, 8, 0, 30);
  assert.deepEqual(datesForRange("1h", now), ["2026-10-08", "2026-10-07"].slice(0, datesForRange("1h", now).length));
  assert.equal(datesForRange("all", now).length, TRACE_RETENTION_DAYS);
});
test("dayPath: Pfad im Daten-Repo, nie im Deploy-Repo-Root", () => {
  assert.equal(dayPath("2026-10-08"), TRACE_DIR + "/2026-10-08.json");
  assert.ok(TRACE_DIR.startsWith("data/"));
});
