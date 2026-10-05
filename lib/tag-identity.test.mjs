// lib/tag-identity.test.mjs — node:test-Unit-Tests für die Tag-Identität.
// Rein offline: reine Funktionen, synthetische Adressen (rTEST…), keine
// echten Konten, kein I/O. Ausführen: node --test lib/tag-identity.test.mjs
import test from "node:test";
import assert from "node:assert/strict";
import { normalizeTag, isMultiUserAccount, computeTransitFlags, TAG_MAX } from "./tag-identity.mjs";

const EX = "rTESTexchangeAccount11111111"; // 28 Zeichen, Base58-gültig
const EX2 = "rTESTexchangeAccount22222222";
const A1 = "rTESTuserAccount111111111111";
const A2 = "rTESTuserAccount222222222222";
const A3 = "rTESTuserAccount333333333333";

const registry = new Map([
  [EX, { exchange: "Test Exchange One", tier: 1, requireDestTag: true }],
  [EX2, { exchange: "Test Exchange Two", tier: 2, requireDestTag: false }],
]);

// ---------- 1) normalizeTag ----------

test("normalizeTag: echter UInt32-Wert, 0 als echter Tag, String-Ziffern", () => {
  assert.equal(normalizeTag(111), 111);
  assert.equal(normalizeTag(0), 0, "Tag 0 ist ein echter Tag (nicht null)");
  assert.equal(normalizeTag(TAG_MAX), TAG_MAX, "Obergrenze 2**32-1 akzeptiert");
  assert.equal(normalizeTag("3125327487"), 3125327487, "Ziffern-String wird normalisiert");
  assert.equal(normalizeTag("0"), 0, "String '0' -> echter Tag 0");
  assert.equal(normalizeTag(" 42 "), 42, "Ränder werden getrimmt");
});

test("normalizeTag: fehlendes Feld und Unsinn -> null (niemals Truthiness)", () => {
  assert.equal(normalizeTag(null), null);
  assert.equal(normalizeTag(undefined), null);
  assert.equal(normalizeTag(""), null);
  assert.equal(normalizeTag("   "), null);
  assert.equal(normalizeTag(-1), null, "negativ -> null");
  assert.equal(normalizeTag(TAG_MAX + 1), null, "über UInt32-Max -> null");
  assert.equal(normalizeTag(1.5), null, "nicht ganzzahlig -> null");
  assert.equal(normalizeTag("x"), null);
  assert.equal(normalizeTag("111x"), null);
  assert.equal(normalizeTag("1e5"), null, "kein Ziffern-String -> null");
  assert.equal(normalizeTag(true), null, "kein Number/String-Typ -> null");
  assert.equal(normalizeTag(NaN), null);
  assert.equal(normalizeTag(Infinity), null);
});

// ---------- 2) isMultiUserAccount ----------

test("isMultiUserAccount: true nur bei Registry-Treffer, sonst fail-closed", () => {
  assert.equal(isMultiUserAccount(EX, registry), true);
  assert.equal(isMultiUserAccount(A1, registry), false, "nicht gelistete Adresse -> false");
  assert.equal(isMultiUserAccount(A1, null), false, "ohne Map -> false");
  assert.equal(isMultiUserAccount(A1, new Map()), false, "leere Map -> false");
  assert.equal(isMultiUserAccount(null, registry), false);
  assert.equal(isMultiUserAccount("", registry), false);
  // requireDestTag ist nur Anzeige-Hinweis: auch ohne Flag ist der Treffer true.
  assert.equal(isMultiUserAccount(EX2, registry), true, "requireDestTag false ändert den Treffer nicht");
});

// ---------- 3) computeTransitFlags ----------

test("transit: zwei verschiedene Tags an derselben Börse -> beide Kanten transit", () => {
  const edges = [
    { from: A1, to: EX, toTag: 111 },
    { from: A2, to: EX, toTag: 222 },
  ];
  computeTransitFlags(edges, registry);
  assert.equal(edges[0].transit, true);
  assert.equal(edges[1].transit, true);
});

test("kein transit: gleiche (Adresse, Tag)-Paare sind dieselbe Identität", () => {
  const edges = [
    { from: A1, to: EX, toTag: 111 },
    { from: A2, to: EX, toTag: 111 },
    { from: A3, to: EX, toTag: 111 },
  ];
  computeTransitFlags(edges, registry);
  for (const e of edges) assert.ok(!("transit" in e), "transit-Feld wird nur bei true gesetzt");
});

test("transit: 'kein Tag' zählt als eigene Identität (Tag vs. fehlender Tag)", () => {
  const edges = [
    { from: A1, to: EX, toTag: 111 },
    { from: A2, to: EX }, // kein Tag -> eigene Identität
  ];
  computeTransitFlags(edges, registry);
  assert.equal(edges[0].transit, true);
  assert.equal(edges[1].transit, true);
});

test("transit: Tag 0 vs. kein Tag sind VERSCHIEDENE Identitäten", () => {
  const edges = [
    { from: A1, to: EX, toTag: 0 },
    { from: A2, to: EX },
  ];
  computeTransitFlags(edges, registry);
  assert.equal(edges[0].transit, true, "Tag 0 ist echt — nicht mit 'kein Tag' verwechseln");
  assert.equal(edges[1].transit, true);
});

test("transit: Tags an VERSCHIEDENEN Börsen erzeugen kein transit", () => {
  const edges = [
    { from: A1, to: EX, toTag: 111 },
    { from: A2, to: EX2, toTag: 222 },
  ];
  computeTransitFlags(edges, registry);
  assert.ok(!("transit" in edges[0]));
  assert.ok(!("transit" in edges[1]));
});

test("transit: nicht gelistete Empfänger erhalten nie ein transit-Feld", () => {
  const edges = [
    { from: A1, to: A2, toTag: 111 },
    { from: A2, to: A3, toTag: 222 },
  ];
  computeTransitFlags(edges, registry);
  for (const e of edges) assert.ok(!("transit" in e));
});

test("transit: ohne Registry-Map oder mit leerer Map passiert nichts", () => {
  const edges = [
    { from: A1, to: EX, toTag: 111 },
    { from: A2, to: EX, toTag: 222 },
  ];
  computeTransitFlags(edges, null);
  computeTransitFlags(edges, new Map());
  for (const e of edges) assert.ok(!("transit" in e));
});

test("transit: cap-unabhängig — Flag bleibt, wenn nur ein Teil der Kanten betrachtet wird, aber volle Identität vorlag", () => {
  // Vollständiger Satz bestimmt die Identitäten; das Flag sitzt auf den
  // Objekten selbst und überlebt jedes nachträgliche Herausfiltern (Cap).
  const full = [
    { from: A1, to: EX, toTag: 111 },
    { from: A2, to: EX, toTag: 222 },
    { from: A3, to: EX, toTag: 333 },
  ];
  computeTransitFlags(full, registry);
  const capped = full.slice(0, 1); // Cap: nur die erste Kante überlebt
  assert.equal(capped[0].transit, true, "transit wurde vor dem Cap auf dem vollen Satz berechnet");
});

test("transit: nur Empfänger-Seite — ausgehende Kanten einer Börse bleiben ohne Flag", () => {
  const edges = [
    { from: A1, to: EX, toTag: 111 },
    { from: A2, to: EX, toTag: 222 },
    { from: EX, to: A1, fromTag: 111 }, // ausgehend: informativ, kein transit
  ];
  computeTransitFlags(edges, registry);
  assert.equal(edges[0].transit, true);
  assert.equal(edges[1].transit, true);
  assert.ok(!("transit" in edges[2]), "SourceTag erzeugt kein transit");
});

test("transit: robust gegen Unsinn im Kantensatz", () => {
  const edges = [null, undefined, 42, "kante", { from: A1 }, { to: EX }, { from: A1, to: EX, toTag: 111 }, { from: A2, to: EX, toTag: 222 }];
  computeTransitFlags(edges, registry);
  assert.equal(edges[6].transit, true);
  assert.equal(edges[7].transit, true);
  // Die taglose Kante teilt sich die Börse mit zwei verschiedenen Tags ->
  // drei Identitäten (none/111/222), also bekommt sie transit ebenfalls.
  assert.equal(edges[5].transit, true, "'kein Tag' ist Teil der Identitätsmenge");
});
