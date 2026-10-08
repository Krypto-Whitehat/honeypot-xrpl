// lib/validator-health.test.mjs — Validator-Gesundheit: Parsing, Watchlist, Alarme, Trace.
import test from "node:test";
import assert from "node:assert/strict";
import { parseValidatorInfo, selectWatchlist, healthAlerts, reportTrace, VALIDATOR_DEFAULTS } from "./validator-health.mjs";

const info = (over = {}) => ({
  validation_public_key: "nKEY1", signing_key: "nSIGN1", master_key: "nKEY1", domain: "x.example", unl: "vl.ripple.com",
  current_index: 100, revoked: false,
  agreement_1h: { missed: 0, total: 1000, score: "1.00000", incomplete: false },
  agreement_24h: { missed: 0, total: 20000, score: "1.00000", incomplete: false },
  agreement_30day: { missed: 1, total: 600000, score: "1.00000", incomplete: false },
  result: "success", ...over,
});

test("parseValidatorInfo: normalisiert xrpscan-Antwort", () => {
  const p = parseValidatorInfo(info());
  assert.equal(p.key, "nKEY1");
  assert.equal(p.agreement1h.score, 1);
  assert.equal(p.revoked, false);
});

test("parseValidatorInfo: Fehler oder leer ergibt null (fail-closed)", () => {
  assert.equal(parseValidatorInfo({ result: "error" }), null);
  assert.equal(parseValidatorInfo(null), null);
  assert.equal(parseValidatorInfo({ foo: 1 }), null);
});

test("selectWatchlist: nur UNL-Validatoren mit Domain, neueste zuerst, gedeckelt", () => {
  const reg = [
    { master_key: "a", domain: "a.ex", unl: ["vl.ripple.com"], last_seen: "2026-10-01T00:00:00Z" },
    { master_key: "b", domain: "b.ex", unl: ["other"], last_seen: "2026-10-09T00:00:00Z" },
    { master_key: "c", domain: "", unl: ["vl.xrplf.org"], last_seen: "2026-10-08T00:00:00Z" },
    { master_key: "d", domain: "d.ex", unl: ["vl.xrplf.org"], last_seen: "2026-10-08T00:00:00Z" },
  ];
  assert.deepEqual(selectWatchlist(reg).map((x) => x.masterKey), ["d", "a"]);
  assert.equal(selectWatchlist(reg, 1).length, 1);
});

test("Alarm agreement-drop: Score 0.90 bei 1000 Validierungen", () => {
  const cur = parseValidatorInfo(info({ agreement_1h: { missed: 100, total: 1000, score: "0.90000", incomplete: false } }));
  const a = healthAlerts(cur).find((x) => x.type === "agreement-drop");
  assert.ok(a);
  assert.equal(a.severity, "suspect");
});

test("Alarm missed-surge: 8 Prozent verpasst", () => {
  const cur = parseValidatorInfo(info({ agreement_1h: { missed: 80, total: 1000, score: "0.92000", incomplete: false } }));
  assert.ok(healthAlerts(cur).some((x) => x.type === "missed-surge"));
});

test("Guard: zu kleine Stichprobe (unter minTotal1h) erzeugt keinen Score-Alarm", () => {
  const cur = parseValidatorInfo(info({ agreement_1h: { missed: 90, total: 100, score: "0.10000", incomplete: false } }));
  assert.equal(healthAlerts(cur).length, 0);
});

test("Guard: unvollständige Stunde (incomplete) erzeugt keine Aussage", () => {
  const cur = parseValidatorInfo(info({ agreement_1h: { missed: 500, total: 1000, score: "0.50000", incomplete: true } }));
  assert.equal(healthAlerts(cur).length, 0);
});

test("Alarm validator-revoked ist malicious", () => {
  const cur = parseValidatorInfo(info({ revoked: true }));
  assert.equal(healthAlerts(cur).find((x) => x.type === "validator-revoked").severity, "malicious");
});

test("Alarm signing-key-rotated und unl-membership-changed gegen den vorherigen Stand", () => {
  const prev = parseValidatorInfo(info());
  const cur = parseValidatorInfo(info({ signing_key: "nSIGN2", unl: "vl.xrplf.org" }));
  const types = healthAlerts(cur, prev).map((x) => x.type);
  assert.ok(types.includes("signing-key-rotated"));
  assert.ok(types.includes("unl-membership-changed"));
});

test("Guard: unveränderter Stand erzeugt keine Wechsel-Alarme", () => {
  const prev = parseValidatorInfo(info());
  assert.equal(healthAlerts(parseValidatorInfo(info()), prev).length, 0);
});

test("reportTrace: filtert Tagesberichte in den Zeitraum, aufsteigend", () => {
  const reports = [
    { date: "2026-10-03T00:00:00.000Z", score: "1", missed: "0", total: "10" },
    { date: "2026-10-01T00:00:00.000Z", score: "0.9", missed: "5", total: "100" },
    { date: "2026-09-01T00:00:00.000Z", score: "1", missed: "0", total: "1" },
  ];
  const t = reportTrace(reports, Date.parse("2026-09-30T00:00:00Z"), Date.parse("2026-10-05T00:00:00Z"));
  assert.deepEqual(t.map((r) => r.date), ["2026-10-01T00:00:00.000Z", "2026-10-03T00:00:00.000Z"]);
  assert.equal(t[0].score, 0.9);
});

test("VALIDATOR_DEFAULTS sind explizit exportiert", () => {
  assert.equal(VALIDATOR_DEFAULTS.scoreMin, 0.95);
});

// ---------- dUNL-Abgleich (Testvektoren aus ripple-address-codec) ----------
import { nodePublicB58, decodeValidatorList, watchlistFromVl } from "./validator-health.mjs";
test("nodePublicB58: stimmt mit ripple-address-codec überein", () => {
  assert.equal(nodePublicB58("ED13AAFCB6A87BCB5D093C2EF37F04431C291126D674293305152D9776C6ABA4D6"), "nHBWa56Vr7csoFcCnEPzCCKVvnDQw3L28mATgHYQMGtbEfUjuYyB");
  assert.equal(nodePublicB58("EDC4B6B0D7D8C53A21C1147C31C378923E9DAA6513283CC3FA6B2EF11B6E67279B"), "nHUinfdpmtfXsMUnoSoBeZ93mTwDkPkA2gmCiQTyEi1c1Ybx6unE");
});
test("nodePublicB58 Guard: ungültige Hex-Länge -> null", () => {
  assert.equal(nodePublicB58("ABCD"), null);
});
test("decodeValidatorList: Blob-Base64 -> Schlüsselliste, kaputter Blob -> null", () => {
  const doc = { sequence: 85, expiration: 1, validators: [{ validation_public_key: "ED13AAFCB6A87BCB5D093C2EF37F04431C291126D674293305152D9776C6ABA4D6" }, { validation_public_key: "nope" }] };
  const vl = decodeValidatorList({ blob: Buffer.from(JSON.stringify(doc)).toString("base64") });
  assert.equal(vl.keys.length, 1);
  assert.equal(vl.sequence, 85);
  assert.equal(decodeValidatorList({ blob: "%%%" }), null);
});
test("watchlistFromVl: vollständige Zuordnung, Unzuordenbare werden ausgewiesen", () => {
  const vl = { keys: ["ED13AAFCB6A87BCB5D093C2EF37F04431C291126D674293305152D9776C6ABA4D6", "EDC4B6B0D7D8C53A21C1147C31C378923E9DAA6513283CC3FA6B2EF11B6E67279B"] };
  const reg = [{ master_key: "nHBWa56Vr7csoFcCnEPzCCKVvnDQw3L28mATgHYQMGtbEfUjuYyB", domain: "a.ex" }];
  const w = watchlistFromVl(vl, reg);
  assert.equal(w.listed, 2);
  assert.equal(w.matched, 1);
  assert.equal(w.entries[0].domain, "a.ex");
  assert.equal(w.unmatched.length, 1);
});
test("watchlistFromVl: Validator ohne Domain bleibt in der Liste (domain null)", () => {
  const vl = { keys: ["ED13AAFCB6A87BCB5D093C2EF37F04431C291126D674293305152D9776C6ABA4D6"] };
  const w = watchlistFromVl(vl, [{ master_key: "nHBWa56Vr7csoFcCnEPzCCKVvnDQw3L28mATgHYQMGtbEfUjuYyB", domain: "" }]);
  assert.equal(w.matched, 1);
  assert.equal(w.entries[0].domain, null);
});
