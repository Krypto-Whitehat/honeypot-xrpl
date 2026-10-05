// lib/name-resolve.test.mjs — Unit-Tests für das reine Namens-Modul
// (XRPScan well-known-Aliase). Kein DOM, kein fetch — das Modul ist in Node
// direkt importierbar (Muster lib/attribution.test.mjs). Alle Adressen sind
// synthetische rTEST…-Adressen; keine echten Konten.

import test from "node:test";
import assert from "node:assert/strict";
import {
  sanitizeName,
  parseWellKnown,
  nameFor,
  mergeNameMaps,
  nameBadge,
} from "./name-resolve.mjs";

// Gültige Base58-Adressen (Muster ^r[1-9A-HJ-NP-Za-km-z]{24,34}$ — ohne 0/O/I/l).
const A1 = "rTESTexchangeAccount11111111";   // 28 Zeichen
const A2 = "rTESTsecondAccount2222222222";   // 28 Zeichen
const A3 = "rTESTthirdAccount33333333333";   // 29 Zeichen

/* ---------- sanitizeName ---------- */

test("sanitizeName: Steuerzeichen und HTML-Zeichen werden ersetzt, Whitespace verdichtet", () => {
  assert.equal(sanitizeName("Bit\n<p>panda\r"), "Bit p panda");
  assert.equal(sanitizeName('  "Gemini"  '), "Gemini"); // Zitatzeichen entfernt, Ränder getrimmt
  // NUL und SOH (per fromCharCode, damit die Testdatei selbst reinen Text enthält)
  // werden zu Leerzeichen verdichtet:
  assert.equal(sanitizeName("a" + String.fromCharCode(0) + "b" + String.fromCharCode(1) + "c"), "a b c");
  assert.equal(sanitizeName(null), "");
  assert.equal(sanitizeName(undefined), "");
  assert.equal(sanitizeName(12345), "12345");
});

test("sanitizeName: Kappung auf maxLen (Default 48, custom möglich)", () => {
  const long = "x".repeat(100);
  assert.equal(sanitizeName(long).length, 48);
  assert.equal(sanitizeName(long, 10).length, 10);
  // Whitespace-Verdichtung vor der Kappung: hängende Leerzeichen bleiben nicht.
  assert.equal(sanitizeName("short name" + " ".repeat(60)), "short name");
});

/* ---------- parseWellKnown ---------- */

test("parseWellKnown: gültige Einträge, verified-Default false, Domain-Validierung", () => {
  const raw = [
    { account: A1, name: "Bitpanda", domain: "Bitpanda.com", twitter: "bitpanda", verified: true },
    { account: A2, name: "Gemini", domain: "not a domain!", verified: false },
    { account: A3, name: "Kraken", desc: "exchange" }, // verified fehlt -> false
  ];
  const map = parseWellKnown(raw);
  assert.equal(map.size, 3);
  const e1 = map.get(A1);
  assert.equal(e1.name, "Bitpanda");
  assert.equal(e1.domain, "bitpanda.com"); // lowercased
  assert.equal(e1.twitter, "bitpanda");
  assert.equal(e1.verified, true);
  assert.equal(map.get(A2).domain, null);  // Host-Muster verletzt -> null
  assert.equal(map.get(A2).verified, false);
  assert.equal(map.get(A3).verified, false); // fehlendes Feld -> Default false
  assert.equal(map.get(A3).twitter, null);
});

test("parseWellKnown: ungültige Adressen und namenlose Einträge fallen raus", () => {
  const raw = [
    { account: "rTESTshort", name: "Zu kurz" },                 // < 25 Zeichen
    { account: "xTESTwellKnownExchange11111111", name: "Falsches Präfix" },
    { account: "rTESTinvalid0OIl1111111111111", name: "Base58-verbotene Zeichen" }, // 0 O I l
    { account: A1, name: "   " },                                // kein brauchbarer Name
    { account: A2, name: "<script>alert(1)</script>" },          // HTML-Zeichen ersetzt, kein HTML im Namen
    null,
    "not-an-object",
  ];
  const map = parseWellKnown(raw);
  assert.equal(map.size, 1);
  assert.ok(map.has(A2));
  assert.equal(map.get(A2).name, "script alert(1) /script"); // < und > ersetzt (der Slash bleibt), kein HTML im Namen
});

test("parseWellKnown: Entries-Cap 3000", () => {
  const raw = [];
  for (let i = 0; i < 3005; i++) {
    // Eindeutige Base58-Adressen: feste 4-stellige Basis-9-Codierung (padStart
    // VOR der Digit-1-Abbildung, sonst Kollisionen wie 19/119), Ziffern 1-9
    // (0 ist in Base58 verboten), plus Füllzeichen 9 auf Länge 28.
    const code = (i + 1).toString(9).padStart(4, "0").split("").map((d) => String(Number(d) + 1)).join("");
    raw.push({ account: "rTESTcap" + code + "9".repeat(16), name: "Name " + i });
  }
  const map = parseWellKnown(raw);
  assert.equal(map.size, 3000);
});

test("parseWellKnown: Nicht-Array (null/undefined/Object) -> leere Map, kein Throw", () => {
  for (const bad of [null, undefined, 42, "text", { account: A1, name: "x" }]) {
    const map = parseWellKnown(bad);
    assert.ok(map instanceof Map);
    assert.equal(map.size, 0);
  }
});

/* ---------- nameFor ---------- */

test("nameFor: Treffer, Fehltreffer und ungültige Eingaben liefern sauber", () => {
  const map = parseWellKnown([{ account: A1, name: "Bitpanda", verified: true }]);
  assert.equal(nameFor(map, A1).name, "Bitpanda");
  assert.equal(nameFor(map, A2), null);
  assert.equal(nameFor(map, ""), null);
  assert.equal(nameFor(map, null), null);
  assert.equal(nameFor(null, A1), null);
  assert.equal(nameFor("not-a-map", A1), null);
});

/* ---------- mergeNameMaps ---------- */

test("mergeNameMaps: primary schlägt fallback; Eingaben bleiben unverändert", () => {
  const primary = new Map([[A1, { name: "XRPScan-Name", verified: true }]]);
  const fallback = new Map([[A1, { name: "Registry-Name" }], [A2, { name: "Nur-Fallback" }]]);
  const merged = mergeNameMaps(primary, fallback);
  assert.equal(merged.size, 2);
  assert.equal(merged.get(A1).name, "XRPScan-Name"); // primary gewinnt
  assert.equal(merged.get(A2).name, "Nur-Fallback");
  // Eingaben unverändert (keine Seiteneffekte).
  assert.equal(primary.size, 1);
  assert.equal(fallback.size, 2);
  assert.notEqual(merged, primary);
  assert.notEqual(merged, fallback);
  // Toleranz gegen Nicht-Map.
  assert.equal(mergeNameMaps(null, null).size, 0);
  assert.equal(mergeNameMaps(primary, null).size, 1);
});

/* ---------- nameBadge ---------- */

test("nameBadge: Deskriptor {label, verified, domain}; null-Eingaben sauber", () => {
  const badge = nameBadge(A1, { name: " Bitpanda ", verified: true, domain: "bitpanda.com" });
  assert.deepEqual(badge, { label: "Bitpanda", verified: true, domain: "bitpanda.com" });
  assert.deepEqual(nameBadge(A1, { name: "Ohne Domain" }), { label: "Ohne Domain", verified: false, domain: null });
  assert.equal(nameBadge(A1, null), null);
  assert.equal(nameBadge(A1, undefined), null);
  assert.equal(nameBadge(A1, { name: "   " }), null); // leer nach Sanitize
  assert.equal(nameBadge(null, { name: "X" }).label, "X"); // Adresse ist nur Deskriptor-Hülle
});
