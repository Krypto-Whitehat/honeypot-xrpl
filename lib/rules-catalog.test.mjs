// lib/rules-catalog.test.mjs — Schwellen-Exposition von /api/rules (api/rules.js).
// Live-Audit 2026-10-06: /api/rules lieferte nur {id,name,severity} — die
// "Regeln mit Schwellen"-Prüfung war über die API nicht erfüllbar. Die API
// mergt jetzt THRESHOLDS_BY_RULE in den Katalog; dieser Test sichert, dass die
// exponierten Schwellen IDENTISCH zu den Engine-Konstanten sind (Imports, keine
// Kopien — Drift-Schutz).
//
// Ausführen: node --test lib/rules-catalog.test.mjs
import test from "node:test";
import assert from "node:assert/strict";
import { THRESHOLDS_BY_RULE } from "../api/rules.js";
import { ruleCatalog, DEFAULT_THRESHOLDS } from "./detector.mjs";
import { PEELING_THRESHOLDS, MOTIF_THRESHOLDS } from "./cluster.mjs";
import { ENTITY_FRESH_THRESHOLDS } from "./entity-resolve.mjs";

test("ruleCatalog (Browser-Quelle) bleibt {id,name,severity} — der Schwellen-Merge lebt nur in der API", () => {
  const cat = ruleCatalog();
  assert.equal(cat.length, 12);
  for (const rule of cat) {
    assert.deepEqual(Object.keys(rule), ["id", "name", "severity"]);
  }
});

test("THRESHOLDS_BY_RULE kennt keine Phantom-Regeln und deckt genau die 10 Schwellen-Regeln ab", () => {
  const ids = new Set(ruleCatalog().map((r) => r.id));
  const keys = Object.keys(THRESHOLDS_BY_RULE);
  assert.equal(keys.length, 10);
  for (const key of keys) assert.ok(ids.has(key), `unbekannte Regel-ID: ${key}`);
  // Regeln ohne numerische Schwellen tragen bewusst keinen Eintrag:
  assert.ok(!("known-bad-hit" in THRESHOLDS_BY_RULE));
  assert.ok(!("memo-phishing" in THRESHOLDS_BY_RULE));
});

test("drainer-sweep: Schwellen == DEFAULT_THRESHOLDS; V5 verifiedFresh == ENTITY_FRESH_THRESHOLDS", () => {
  const th = THRESHOLDS_BY_RULE["drainer-sweep"];
  assert.equal(th.sweepRatio, DEFAULT_THRESHOLDS.sweepRatio);
  assert.equal(th.minAccountAgeMin, DEFAULT_THRESHOLDS.minAccountAgeMin);
  assert.equal(th.verifiedFreshGapLedgers, ENTITY_FRESH_THRESHOLDS.maxGapLedgers);
});

test("wash-cycle: Schwellen == MOTIF_THRESHOLDS (V4 Motiv-Zähler, identische Werte)", () => {
  assert.deepEqual(THRESHOLDS_BY_RULE["wash-cycle"], MOTIF_THRESHOLDS);
});

test("peeling-chain: Schwellen == PEELING_THRESHOLDS (identische Werte)", () => {
  assert.deepEqual(THRESHOLDS_BY_RULE["peeling-chain"], PEELING_THRESHOLDS);
});

test("dusting/Wash/NFT/Burst-Schwellen entsprechen den Engine-Literalkonditionen", () => {
  assert.equal(THRESHOLDS_BY_RULE["dusting"].minTinyDests, 3);
  assert.equal(THRESHOLDS_BY_RULE["dusting"].minFreshTiny, 2);
  assert.equal(THRESHOLDS_BY_RULE["dusting"].dustDrops, DEFAULT_THRESHOLDS.dustDrops);
  assert.equal(THRESHOLDS_BY_RULE["wash-self-transfer"].minSelfPays, 3);
  assert.equal(THRESHOLDS_BY_RULE["fake-nft-fraud"].minZeroAccepts, 10);
  assert.equal(THRESHOLDS_BY_RULE["fake-nft-fraud"].minOffersPerTarget, 5);
  assert.equal(THRESHOLDS_BY_RULE["escrow-check-bait"].minFreshDests, 3);
  assert.equal(THRESHOLDS_BY_RULE["payment-burst"].minDests, 5);
  assert.equal(THRESHOLDS_BY_RULE["payment-burst"].minTiny, 3);
  assert.equal(THRESHOLDS_BY_RULE["payment-burst"].tinyMajoritySlack, 2);
  assert.equal(THRESHOLDS_BY_RULE["airdrop-trustset-spam"].minAccounts, 5);
  assert.equal(THRESHOLDS_BY_RULE["offer-spam"].minOffers, 10);
  assert.equal(THRESHOLDS_BY_RULE["offer-spam"].maxFills, 0);
});
