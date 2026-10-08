// lib/validator-service.test.mjs — dUNL-Vollständigkeit: alle VL-Validatoren, Fallback sichtbar.
import test from "node:test";
import assert from "node:assert/strict";
import { validatorView, resetValidatorCacheForTests } from "./validator-service.mjs";

const KEYS = Array.from({ length: 12 }, (_, i) => "ED" + (i + 1).toString(16).padStart(2, "0") + "A".repeat(62));
// Master-Schlüssel je Hex-Key: Registry-Einträge wären nötig; hier nutzen wir die echten Vektoren
// aus validator-health.test.mjs für 2 Keys und prüfen die Mengen-Logik über listed/matched.
const vlBlob = (keys) => ({ blob: Buffer.from(JSON.stringify({ sequence: 9, expiration: 1, validators: keys.map((k) => ({ validation_public_key: k })) })).toString("base64") });
const infoFor = (mk) => ({ validation_public_key: mk, master_key: mk, signing_key: "s", domain: "d.ex", unl: "vl.ripple.com", revoked: false,
  agreement_1h: { missed: 0, total: 1000, score: "1", incomplete: false } });

test("dUNL: VL mit 12 Schlüsseln, nur 2 zuordenbar -> beide ausgewiesen, kein Limit-Abschnitt", async () => {
  resetValidatorCacheForTests();
  const reg = [
    { master_key: "nHBWa56Vr7csoFcCnEPzCCKVvnDQw3L28mATgHYQMGtbEfUjuYyB", domain: "a.ex", unl: ["vl.ripple.com"], last_seen: "x" },
    { master_key: "nHUinfdpmtfXsMUnoSoBeZ93mTwDkPkA2gmCiQTyEi1c1Ybx6unE", domain: "b.ex", unl: ["vl.ripple.com"], last_seen: "x" },
  ];
  const vlKeys = ["ED13AAFCB6A87BCB5D093C2EF37F04431C291126D674293305152D9776C6ABA4D6", "EDC4B6B0D7D8C53A21C1147C31C378923E9DAA6513283CC3FA6B2EF11B6E67279B", ...KEYS.slice(2)];
  const calls = [];
  const fetchJson = async (p) => { calls.push(p); if (p === "/validatorregistry") return reg; return infoFor(decodeURIComponent(p.split("/").pop())); };
  const body = await validatorView({ now: 1e9, fetchJson, fetchVl: async () => vlBlob(vlKeys) });
  assert.equal(body.dunl.source, "vl.ripple.com");
  assert.equal(body.dunl.listed, 12);
  assert.equal(body.dunl.matched, 2);
  assert.equal(body.dunl.unmatched.length, 10);
  assert.equal(body.validators.length, 2);
});

test("dUNL Fallback: VL nicht erreichbar -> Registry-Tags, Quelle sichtbar", async () => {
  resetValidatorCacheForTests();
  const reg = [{ master_key: "nX", domain: "x.ex", unl: ["vl.ripple.com"], last_seen: "x" }];
  const fetchJson = async (p) => (p === "/validatorregistry" ? reg : infoFor("nX"));
  const body = await validatorView({ now: 2e9, fetchJson, fetchVl: async () => { throw new Error("down"); } });
  assert.equal(body.dunl.source, "registry-tag-fallback");
  assert.equal(body.validators.length, 1);
});
