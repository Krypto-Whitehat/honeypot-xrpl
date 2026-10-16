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
import { DICT as CORE_DICT, registerDict } from "./i18n.mjs";
import { VALIDATOR_DICT } from "./i18n-validator.mjs";

/* Der Guard prueft die Union, genau in der Reihenfolge des echten Betriebs:
 * erst Kern, dann das Overlay, das beim Laden registerDict(VALIDATOR_DICT) ruft. */
const DICT = {
  en: { ...CORE_DICT.en, ...VALIDATOR_DICT.en },
  de: { ...CORE_DICT.de, ...VALIDATOR_DICT.de },
};
import { SERIES_VERDICTS, CQ_VERDICTS, FINGERPRINT_VERDICTS, WINDOW_CLASSES, LOAD_VERDICTS } from "../lib/validator-diagnose.mjs";
import { CAPTURE_GAP_BASES } from "../lib/validator-trace.mjs";
import { IMPACT_AUTHORITIES, IMPACT_REASONS, IMPACT_VERDICTS } from "../lib/attack-impact.mjs";
import { PEER_AUTHORITIES, PEER_DIRECTIONS, PEER_REASONS, PEER_TYPES, PEER_VERDICTS } from "../lib/validator-peer-benchmark.mjs";
import { LATENCY_AUTHORITIES, LATENCY_CLASSES, LATENCY_PATTERNS, LATENCY_REASONS, LATENCY_VERDICTS } from "../lib/validator-vote-latency.mjs";
import { DIVERGENCE_AUTHORITIES, DIVERGENCE_GAPS, DIVERGENCE_GUIDANCE, DIVERGENCE_REASONS, DIVERGENCE_VERDICTS, LINEAGES } from "../lib/validator-divergence.mjs";
import { CAUSE_CHECKS, CAUSE_CONFIDENCE, CAUSE_GAPS, CAUSE_KINDS, CAUSE_LAYERS, CAUSE_STRENGTHS, CAUSE_TAGS, UNEXPLAINED } from "../lib/validator-cause.mjs";
import { SURFACE_AXES, SURFACE_GAPS, SURFACE_REASONS, SURFACE_VERDICTS } from "../lib/validator-quorum-surface.mjs";
import { SENSITIVITY_FAMILIES, SENSITIVITY_GAPS, SENSITIVITY_HEADLINES, SENSITIVITY_VERDICTS } from "../lib/validator-sensitivity.mjs";

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
    "vt.impact.authority.", "vt.impact.reason.", "vt.impact.verdict.", "vt.load.verdict.", "vt.verdict.", "vt.win.class.",
    "vt.peer.authority.", "vt.peer.direction.", "vt.peer.reason.", "vt.peer.type.", "vt.peer.verdict.",
    "vt.lat.authority.", "vt.lat.class.", "vt.lat.pattern.", "vt.lat.reason.", "vt.lat.verdict.",
    "vt.div.authority.", "vt.div.gap.", "vt.div.lineage.", "vt.div.reason.", "vt.div.verdict.",
    "vt.cause.", "vt.cause.confidence.", "vt.cause.gap.", "vt.cause.layer.", "vt.cq.verdict.",
    "vt.surface.axis.", "vt.surface.authority.", "vt.surface.gap.", "vt.surface.group.", "vt.surface.reason.", "vt.surface.verdict.",
    "vt.cq.basis.",
    "vt.sens.family.", "vt.sens.gap.", "vt.sens.head.", "vt.sens.verdict.",
  ];
  // vt.metric.* und vt.tag.* tauchen im UI als vollständige Schluessel bzw. in tagLabel() auf,
  // nicht als h.t("Praefix" + ...) - sie gehoeren deshalb nicht in diese Liste.
  const found = [...new Set(prefixes)].sort();
  assert.deepEqual(found, EXPECTED_PREFIXES.slice().sort());
});

test("Urteils-Mengen der Diagnose-Engine haben ein Label in EN und DE", () => {
  const groups = [["vt.verdict.", SERIES_VERDICTS], ["vt.fpverdict.", FINGERPRINT_VERDICTS], ["vt.win.class.", WINDOW_CLASSES], ["vt.load.verdict.", LOAD_VERDICTS], ["vt.impact.verdict.", IMPACT_VERDICTS],
  ["vt.impact.authority.", IMPACT_AUTHORITIES], ["vt.impact.reason.", IMPACT_REASONS],
  ["vt.peer.verdict.", PEER_VERDICTS], ["vt.peer.reason.", PEER_REASONS], ["vt.peer.authority.", PEER_AUTHORITIES], ["vt.peer.type.", PEER_TYPES],
  // Unter der Grundrate und darueber sind verschiedene naechste Pruefungen - die Richtung ist Teil
  // des Urteils, nicht ein Vorzeichen, das der Leser selbst deuten muss.
  ["vt.peer.direction.", PEER_DIRECTIONS]];
  const latPrefix = (suf) => "vt.lat." + suf;
  groups.push([latPrefix("verdict."), LATENCY_VERDICTS], [latPrefix("reason."), LATENCY_REASONS],
    [latPrefix("authority."), LATENCY_AUTHORITIES], [latPrefix("class."), LATENCY_CLASSES], [latPrefix("pattern."), LATENCY_PATTERNS]);
  const divPrefix = (suf) => "vt.div." + suf;
  // noVote ist keine Linie der Engine-Aufzhlung, aber eine eigene UI-Zeile: ohne Label verschwindet
  // die Aussage "kein Vote auf diesem Ledger" still aus der Tabelle.
  groups.push([divPrefix("verdict."), DIVERGENCE_VERDICTS], [divPrefix("reason."), DIVERGENCE_REASONS],
    [divPrefix("authority."), DIVERGENCE_AUTHORITIES], [divPrefix("gap."), DIVERGENCE_GAPS],
    [divPrefix("lineage."), [...LINEAGES, "noVote"]], ["vt.g.", DIVERGENCE_GUIDANCE]);
  // Cause-Engine und Risikoflaeche: jede Menge, die diese Engines erzeugen koennen, hat ein Label.
  // vt.cause.* ist doppeldeutig (Pruefschritte heissen vt.cause.cause-check-*), deshalb steht die
  // Pruefschritt-Menge explizit unter dem Praefix "vt.cause.".
  groups.push(["vt.cause.tag.", [...CAUSE_TAGS, UNEXPLAINED]], ["vt.cause.", CAUSE_CHECKS],
    ["vt.cause.gap.", CAUSE_GAPS], ["vt.cause.layer.", CAUSE_LAYERS],
    ["vt.cause.confidence.", CAUSE_CONFIDENCE], ["vt.cause.kind.", [...CAUSE_KINDS, "none"]],
    ["vt.cause.strength.", CAUSE_STRENGTHS],
    ["vt.surface.verdict.", SURFACE_VERDICTS], ["vt.surface.reason.", SURFACE_REASONS],
    ["vt.surface.gap.", SURFACE_GAPS], ["vt.surface.authority.", ["measured", "insufficient"]],
    ["vt.cq.verdict.", CQ_VERDICTS],
    // Die Erfassungs-Basis ist Teil des Urteils, nicht eine FuSSnote: 'gemessen an der Index-Folge'
    // und 'gemessen am Luecken-Log' sind verschiedene Belege, und 'not-recorded' hat keinen Beleg -
    // deshalb bekommt dieser Wert bewusst kein Label.
    ["vt.cq.basis.", CAPTURE_GAP_BASES.filter((b) => b !== "not-recorded")],
    ["vt.surface.axis.", SURFACE_AXES],
    ["vt.surface.group.", ["quorumThin", "quorumComfort", "loadHigh", "loadNormal"]]);
  // Empfindlichkeit: das Urteil beantwortet, ob DICH diese Signatur ueberproportional trifft.
  // Ohne Label stünde der rohe Schluessel genau dort, wo Betreiber entscheiden.
  groups.push(["vt.sens.verdict.", SENSITIVITY_VERDICTS], ["vt.sens.gap.", SENSITIVITY_GAPS],
    ["vt.sens.head.", SENSITIVITY_HEADLINES], ["vt.sens.family.", SENSITIVITY_FAMILIES]);
  for (const [prefix, values] of groups) {
    assert.ok(Array.isArray(values) && values.length > 0, prefix + " ist leer");
    const missing = values.filter((v) => DICT.en[prefix + v] === undefined || DICT.de[prefix + v] === undefined);
    assert.deepEqual(missing, [], prefix + " ohne Label: " + missing.join(", "));
  }
});

test("Pruefschritte der Serien-Ebene sind uebersetzt (vt.g. wird aus der Serie ergaenzt)", () => {
  for (const tag of ["node-offline-window", "degraded-signing", "cohort-network", "network-stall", "capture-window", "version-state"]) {
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

test("Empfindlichkeitstabelle: sieben Spaltentitel haben einen Text in EN und DE", () => {
  // Die Titel stehen im UI in einem Schluessel-Feld, nicht als h.t("...") - der Literal-Guard
  // sieht sie nicht, also prueft dieser Test sie direkt an der Liste aus dem UI.
  const columns = ["vt.sens.hTag", "vt.sens.hExp", "vt.sens.hFails", "vt.sens.hOwn", "vt.sens.hLift",
    "vt.sens.hCohort", "vt.sens.hVerdict", "vt.sens.famLabel"];
  const missing = columns.filter((k) => DICT.en[k] === undefined || DICT.de[k] === undefined);
  assert.deepEqual(missing, [], "fehlende Spaltentitel: " + missing.join(", "));
});

test("Uebersetzte Werte sind keine Schluessel-Replikate", () => {
  const suspects = Object.entries(DICT.en).filter(([k, v]) => typeof v === "string" && v === k);
  assert.deepEqual(suspects.map(([k]) => k), []);
});

/* Speed-Budget (2026-10-16): alle vt.*-Texte wohnen in public/i18n-validator.mjs und
 * kommen erst mit dem Overlay hinein. Ein echter Gewinn fuer die Startseite ist das
 * nur, wenn der Kern sie wirklich nicht enthaelt und das Overlay sie anmeldet. */
test("Split: der Kern traegt keine vt.*-Texte und das Overlay meldet sein Bundle an", () => {
  const coreVt = Object.keys(CORE_DICT.en).filter((k) => k.startsWith("vt."));
  assert.deepEqual(coreVt, [], "Kern-Woerterbuch traegt Overlay-Texte: " + coreVt.slice(0, 5).join(", "));
  const enKeys = Object.keys(VALIDATOR_DICT.en);
  const deKeys = Object.keys(VALIDATOR_DICT.de);
  assert.ok(enKeys.length > 200, "Overlay-Bundle fuehrt die erwarteten vt.*-Texte (gefunden: " + enKeys.length + ")");
  assert.ok(enKeys.every((k) => k.startsWith("vt.")), "Bundle ist ausschliesslich vt.*");
  assert.equal(enKeys.length, deKeys.length, "EN und DE haben dieselbe Zahl von Schluesseln (" + enKeys.length + " / " + deKeys.length + ")");
  assert.ok(src.includes("import { registerDict } from './i18n.mjs';"), "Overlay importiert registerDict");
  assert.ok(src.includes("import { VALIDATOR_DICT } from './i18n-validator.mjs';"), "Overlay importiert das Bundle");
  assert.ok(src.includes("registerDict(VALIDATOR_DICT);"), "Overlay meldet das Bundle an");
  const added = registerDict(VALIDATOR_DICT);
  assert.equal(added, enKeys.length + deKeys.length, "registerDict fuellt beide Sprachen vollstaendig");
  const missing = [...new Set(literals)].filter((k) => CORE_DICT.en[k] === undefined || CORE_DICT.de[k] === undefined);
  assert.deepEqual(missing, [], "nach der Anmeldung fehlt weiterhin nichts");
});

// Der noQuorum-Zaehler zaehlt, was DIESER Rekorder nicht gesehen hat. Ein Label, das daraus ein
// fehlendes Netz-Quorum macht, ist eine Behauptung ueber das Netz - am 2026-10-16 durch xrpscan und
// xrplcluster widerlegt (die Ledger wurden geschlossen, 28 Stimmen waren noetig und waren da).
test("Labels: der Erfassungs-Zaehler darf kein Netz-Quorum absprechen", () => {
  const keys = ["vt.bucketAria", "vt.bucketReadout", "vt.impact.typesNote", "vt.verdict.network-window"];
  for (const k of keys) {
    for (const lang of ["en", "de"]) {
      const label = DICT[lang][k];
      assert.ok(typeof label === "string" && label.length > 0, k + " fehlt in " + lang);
      assert.ok(!/no quorum|kein Quorum|ohne Quorum/i.test(label), k + " (" + lang + ") spricht ein Quorum ab: " + label);
    }
  }
});
