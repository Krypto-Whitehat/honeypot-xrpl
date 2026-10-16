import fs from "node:fs";
import path from "node:path";
import { test } from "node:test";
import assert from "node:assert/strict";
import { fileURLToPath } from "node:url";
import { datesForRange, TRACE_RETENTION_DAYS } from "./validator-trace-store.mjs";
import { RANGE_MS } from "./validator-trace-query.mjs";
import { REPORT_RANGES } from "./validator-report.mjs";

/* Guard gegen die Range-Falle (gemessen 2026-10-16 auf der Live-Site): range=30d wurde im
 * Tageslader still auf 24 h gefallen - die 30-Tage-Ansicht zeigte 33.338 Ledger statt der
 * 122.078 des 7-Tage-Fensters und trug trotzdem das Label "30d". Dasselbe Muster saß in der
 * Query-, Retrace- und Divergenz-Ebene, während die neuen Engines (Diagnose, Last x Quorum,
 * Peer, Latenz, Angriff) 30d schon kannten: ein Fenster, das je Panel anders weit ist.
 * Geprüft wird die Vokabel ÜBER alle Module hinweg und das Verhalten des Laders selbst. */

const here = path.dirname(fileURLToPath(import.meta.url));
const read = (rel) => fs.readFileSync(path.join(here, rel), "utf8");

const overlay = read("../public/validator-trace.mjs");
const RANGES = JSON.parse(overlay.match(/const RANGES = (\[[^\]]*\])/)[1]);

const SPAN_MAP = /\{[^{}]*"24h":\s*86400000[^{}]*\}/g;
const mapKeys = (literal) => {
  const quoted = [...literal.matchAll(/"([0-9]+[hd])"/g)].map((m) => m[1]);
  return new Set(/\ball:/.test(literal) ? [...quoted, "all"] : quoted);
};

const MODULES = [
  "validator-trace-store.mjs", "validator-trace-query.mjs", "validator-retrace.mjs",
  "validator-divergence.mjs", "validator-diagnose.mjs", "validator-quorum-surface.mjs",
  "validator-peer-benchmark.mjs", "validator-vote-latency.mjs", "attack-impact.mjs",
  "validator-sensitivity.mjs",
];

test("Range-Vokabel: jedes Fenster des Overlays ist in jeder Span-Karte derselbe Zeitraum", () => {
  assert.ok(RANGES.includes("30d"), "das Overlay bietet kein 30-Tage-Fenster");
  for (const file of MODULES) {
    const maps = [...read(file).matchAll(SPAN_MAP)];
    assert.ok(maps.length, file + " hat keine Span-Karte");
    for (const m of maps) {
      const keys = mapKeys(m[0]);
      for (const r of RANGES) {
        assert.ok(keys.has(r), file + ": Fenster " + r + " fehlt in einer Span-Karte (es wird auf ein anderes gefallen)");
      }
    }
  }
});

test("Range-Vokabel: Overlay und Query-Ebene kennen exakt dieselben Fenster", () => {
  for (const r of RANGES) assert.ok(r === "all" || Number.isFinite(RANGE_MS[r]), "RANGE_MS ohne " + r);
  assert.equal(RANGE_MS["30d"], 30 * 86400000, "30d ist nicht 30 Tage");
});

test("Tageslader: 30d ist ein eigenes Fenster und nicht das 24-h-Fenster", () => {
  const now = Date.parse("2026-10-16T12:00:00Z");
  const d24 = datesForRange("24h", now);
  const d7 = datesForRange("7d", now);
  const d30 = datesForRange("30d", now);
  assert.equal(d24.length, 2, "24h deckt zwei Kalendertage");
  assert.equal(d7.length, 8, "7d deckt acht Kalendertage");
  assert.equal(d30.length, 31, "30d deckt einunddreissig Kalendertage");
  assert.ok(d30.length > d7.length, "30d ist nicht weiter als 7d - das Fenster ist gefallen");
  assert.ok(d30.length > d24.length, "30d ist identisch mit 24h - die Live-Falle ist noch da");
  assert.equal(d30[0], "2026-10-16", "neuester Tag fehlt");
  assert.equal(d30[d30.length - 1], "2026-09-16", "aeltester Tag des 30-Tage-Fensters fehlt");
  assert.ok(d30.every((d) => /^\d{4}-\d{2}-\d{2}$/.test(d)), "Tagesdatum nicht ISO");
  // Die Aufbewahrung begrenzt das Fenster nach unten, ohne es still zu verkleinern.
  assert.ok(datesForRange("all", now).length <= TRACE_RETENTION_DAYS, "all ueberschreitet die Aufbewahrung");
});

/* Der Report-Endpunkt waehlt sein Fenster aus REPORT_RANGES und faellt sonst still auf 7d
 * zurueck. Ein Fenster, das das Overlay anbietet, im Report aber fehlt, waere ein Export, der
 * eine andere Zahl liefert als die Seite zeigt. */
test("Report-Export: jedes Fenster des Overlays ist auch im Report dasselbe Fenster", () => {
  for (const r of RANGES) assert.ok(REPORT_RANGES.includes(r), "validator-report faellt das Fenster " + r + " still auf 7d zurueck");
});

test("Uebersetzung: jedes Fenster des Overlays hat einen Text in beiden Sprachen", () => {
  const i18n = read("../public/i18n-validator.mjs");
  for (const r of RANGES) {
    const key = "vt.range." + r;
    const hits = [...i18n.matchAll(new RegExp("'" + key.replace(/\./g, "\\.") + "'\\s*:", "g"))].length;
    assert.equal(hits, 2, key + " fehlt in einer Sprache");
  }
});
