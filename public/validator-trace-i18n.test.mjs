// public/validator-trace-i18n.test.mjs - Guard gegen rohe Schluessel im Overlay.
//
// t() gibt bei fehlendem Schluessel den Schluessel selbst zurueck. Im Overlay steht dann
// "vt.g.node-offline-window" statt eines Prüfschritts - genau die Stelle, an der ein Werkzeug
// unprofessionell wirkt. Dieser Guard prueft deshalb zwei Dinge:
//  1) jeder im UI genannte Schluessel existiert in EN und DE,
//  2) jede Urteils-Menge der Diagnose-Engine hat ein Label in beiden Sprachen.
import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { DICT } from "./i18n.mjs";
import { SERIES_VERDICTS, FINGERPRINT_VERDICTS, WINDOW_CLASSES, LOAD_VERDICTS } from "../lib/validator-diagnose.mjs";

const here = path.dirname(fileURLToPath(import.meta.url));
const src = readFileSync(path.join(here, "validator-trace.mjs"), "utf8");

const LITERAL_KEY = /h\.t\(\s*"([a-z0-9_.]+)"/g;
const PREFIX_KEY = /h\.t\(\s*"([a-z0-9_.]+\.)"\s*\+/g;

// Schlussiger Punkt = Praefix (h.t("vt.g." + tag)), kein vollständiger Schluessel.
const literals = [...src.matchAll(LITERAL_KEY)].map((m) => m[1]).filter((k) => !k.endsWith("."));
const prefixes = [...src.matchAll(PREFIX_KEY)].map((m) => m[1]);

test("UI: jeder literal genannte i18n-Schluessel existiert in EN und DE", () => {
  assert.ok(literals.length > 25, "Der Guard findet zu wenige Schluessel - Aenderung im UI?");
  const missing = [...new Set(literals)].filter((k) => DICT.en[k] === undefined || DICT.de[k] === undefined);
  assert.deepEqual(missing, [], "fehlende Uebersetzungen: " + missing.join(", "));
});

test("UI: dynamische Schluessel-Praefixe sind bekannt und vollstaendig uebersetzt", () => {
  const EXPECTED_PREFIXES = [
    "vt.datagap.", "vt.fpverdict.", "vt.g.", "vt.k.", "vt.range.", "vt.scope.",
    "vt.series.cause.", "vt.sign.", "vt.state.", "vt.strength.", "vt.type.",
    "vt.load.verdict.", "vt.verdict.", "vt.win.class.",
  ];
  // vt.metric.* und vt.tag.* tauchen im UI als vollständige Schluessel bzw. in tagLabel() auf,
  // nicht als h.t("Praefix" + ...) - sie gehoeren deshalb nicht in diese Liste.
  const found = [...new Set(prefixes)].sort();
  assert.deepEqual(found, EXPECTED_PREFIXES.slice().sort());
});

test("Urteils-Mengen der Diagnose-Engine haben ein Label in EN und DE", () => {
  const groups = [["vt.verdict.", SERIES_VERDICTS], ["vt.fpverdict.", FINGERPRINT_VERDICTS], ["vt.win.class.", WINDOW_CLASSES], ["vt.load.verdict.", LOAD_VERDICTS]];
  for (const [prefix, values] of groups) {
    assert.ok(Array.isArray(values) && values.length > 0, prefix + " ist leer");
    const missing = values.filter((v) => DICT.en[prefix + v] === undefined || DICT.de[prefix + v] === undefined);
    assert.deepEqual(missing, [], prefix + " ohne Label: " + missing.join(", "));
  }
});

test("Pruefschritte der Serien-Ebene sind uebersetzt (vt.g. wird aus der Serie ergaenzt)", () => {
  for (const tag of ["node-offline-window", "degraded-signing", "cohort-network", "network-stall", "version-state"]) {
    assert.notEqual(DICT.en["vt.g." + tag], undefined, "EN fehlt: vt.g." + tag);
    assert.notEqual(DICT.de["vt.g." + tag], undefined, "DE fehlt: vt.g." + tag);
  }
});

test("Serien-Zeile: alle drei Erholungs-Ursachen haben einen Text in EN und DE", () => {
  for (const cause of ["validated", "recorder-gap", "unknown"]) {
    assert.notEqual(DICT.en["vt.series.cause." + cause], undefined);
    assert.notEqual(DICT.de["vt.series.cause." + cause], undefined);
  }
});

test("Uebersetzte Werte sind keine Schluessel-Replikate", () => {
  const suspects = Object.entries(DICT.en).filter(([k, v]) => typeof v === "string" && v === k);
  assert.deepEqual(suspects.map(([k]) => k), []);
});
