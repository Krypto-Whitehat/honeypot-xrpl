// public/exchange-registry.test.mjs — Contract-Tests für die Client-Seite der
// Exchange-Registry (Destination-Tag-Identität). Injizierter globalThis.fetch-
// Stub (das Modul holt fetch erst zur Aufrufzeit über globalThis — Muster
// public/name-index.test.mjs). Prüft: GENAU EIN Fetch pro Session (In-Flight-
// Guard + TTL), Fail-closed ohne Retry-Loop (Fehler -> leerer Stand bzw.
// letzter guter Stand), registrySnapshot/exchangeEntryOf gegen den letzten
// guten Stand, AbortController-Signal am Fetch. Alle Adressen synthetisch
// (rTEST…); es wird kein echter Endpunkt getroffen.
//
// Testreihenfolge ist bewusst: erst die Fail-closed-Pfade OHNE guten Stand
// (byAddressMap null), dann der erfolgreiche Fetch (danach greift der
// TTL-Guard), dann der Fail-closed-mit-gutem-Stand-Nachweis über einen
// gesetzten Zeit-Offset (TTL abgelaufen -> Fetch versucht -> Fehler ->
// letzter guter Stand bleibt).

import test from "node:test";
import assert from "node:assert/strict";
import {
  ensureExchangeRegistry,
  registrySnapshot,
  exchangeEntryOf,
  multiUserEntryOf,
  multiUserSnapshot,
  REGISTRY_TTL_MS,
} from "./exchange-registry.mjs";
import { ensureNameIndex } from "./name-index.mjs";

const REGISTRY_URL = "/data/exchange-registry.json";

// Synthetische Registry-Antwort im Format von public/data/exchange-registry.json
// ({ entries: [...] }) — Adressen Base58-gültig (ohne 0/O/I/l).
const EX1 = "rTESTexchangeAccount11111111";
const EX2 = "rTESTexchangeAccount22222222";
const REGISTRY_FIXTURE = {
  version: 2,
  entries: [
    { address: EX1, exchange: "Test Exchange One", tier: "hot", requireDestTag: true },
    { address: EX2, exchange: "Test Exchange Two", tier: "cold", requireDestTag: false },
  ],
};

/* ---------- fetch-Stub (Aufrufzähler + Response-Kontrolle) ---------- */

let fetchCalls = []; // { url, opts }
let responder = () => ({ ok: true, json: async () => REGISTRY_FIXTURE });

function installFetch() {
  const prev = globalThis.fetch;
  globalThis.fetch = async (url, opts) => {
    fetchCalls.push({ url: String(url), opts });
    if (String(url) === REGISTRY_URL) return responder();
    throw new Error("unexpected fetch url: " + url);
  };
  return () => {
    if (prev === undefined) delete globalThis.fetch;
    else globalThis.fetch = prev;
  };
}

function resetStubs() {
  fetchCalls = [];
  responder = () => ({ ok: true, json: async () => REGISTRY_FIXTURE });
}

const registryCount = () => fetchCalls.filter((c) => c.url === REGISTRY_URL).length;

// Zeit-Offset für TTL-Ablauf-Tests: das Modul ruft Date.now() zur Aufrufzeit;
// der Stub verschiebt nur die Wahrnehmung, der finally stellt her.
async function withTimeOffset(offsetMs, fn) {
  const realNow = Date.now;
  const base = realNow();
  Date.now = () => base + offsetMs;
  try {
    return await fn();
  } finally {
    Date.now = realNow;
  }
}

/* ---------- Fail-closed ohne guten Stand ---------- */

test("Fehler-Fetch: leere Map, kein Retry, Snapshot bleibt null", async () => {
  resetStubs();
  const restore = installFetch();
  try {
    responder = () => { throw new Error("netzfehler"); };
    const map = await ensureExchangeRegistry();
    assert.ok(map instanceof Map);
    assert.equal(map.size, 0, "ohne guten Stand: leere Map");
    assert.equal(registryCount(), 1, "kein Retry-Loop nach Fehler");
    assert.equal(registrySnapshot(), null, "Snapshot bleibt null ohne erfolgreichen Stand");
    assert.equal(exchangeEntryOf(EX1), null, "Lookup ohne Stand: null");
  } finally {
    restore();
  }
});

test("HTTP-Fehler (!ok): leere Map, Snapshot null", async () => {
  resetStubs();
  const restore = installFetch();
  try {
    responder = () => ({ ok: false, status: 503 });
    const map = await ensureExchangeRegistry();
    assert.equal(map.size, 0);
    assert.equal(registrySnapshot(), null);
  } finally {
    restore();
  }
});

test("ohne fetch-Umgebung: fail-closed leere Map (kein Crash)", async () => {
  resetStubs();
  const prev = globalThis.fetch;
  delete globalThis.fetch;
  try {
    const map = await ensureExchangeRegistry();
    assert.ok(map instanceof Map);
    assert.equal(map.size, 0);
  } finally {
    if (prev !== undefined) globalThis.fetch = prev;
  }
});

/* ---------- Erfolg + Session-Guard ---------- */

test("erfolgreicher Fetch: Map mit Registry-Einträgen, genau EIN Fetch pro Session", async () => {
  resetStubs();
  const restore = installFetch();
  try {
    const map = await ensureExchangeRegistry();
    assert.equal(map.size, 2);
    assert.equal(map.get(EX1).exchange, "Test Exchange One");
    assert.equal(map.get(EX1).requireDestTag, true);
    assert.equal(map.get(EX2).tier, "cold");
    // In-Flight-Guard + TTL: weitere Aufrufe fetchen nie erneut.
    const again = await ensureExchangeRegistry();
    const again2 = await ensureExchangeRegistry();
    assert.equal(registryCount(), 1, "GENAU EIN Fetch pro Session innerhalb des TTL");
    assert.equal(again, map);
    assert.equal(again2, map);
    // Synchroner Lookup gegen den letzten guten Stand.
    assert.equal(registrySnapshot(), map);
    assert.equal(exchangeEntryOf(EX1).exchange, "Test Exchange One");
    assert.equal(exchangeEntryOf(EX2).exchange, "Test Exchange Two");
    assert.equal(exchangeEntryOf("rUnbekannteAdresseX111111111"), null);
    assert.equal(exchangeEntryOf(null), null);
    assert.equal(exchangeEntryOf(""), null);
    // Fetch-Contract: AbortController-Signal + no-store (Timeout-Deckel,
    // kein Browser-Cache — Muster name-index.test.mjs:131-134).
    const call = fetchCalls.find((c) => c.url === REGISTRY_URL);
    assert.ok(call.opts?.signal instanceof AbortSignal, "AbortController-Signal fehlt");
    assert.equal(call.opts.cache, "no-store");
  } finally {
    restore();
  }
});

/* ---------- TTL abgelaufen: Fehler hält den letzten guten Stand ---------- */

test("TTL abgelaufen + Fehler: letzter guter Stand bleibt (fail-closed)", async () => {
  resetStubs();
  const restore = installFetch();
  try {
    await withTimeOffset(REGISTRY_TTL_MS + 1000, async () => {
      responder = () => { throw new Error("netzfehler nach TTL"); };
      const m1 = await ensureExchangeRegistry();
      assert.equal(registryCount(), 1, "TTL abgelaufen -> ein Fetch versucht");
      assert.equal(m1.size, 2, "letzter guter Stand bleibt bei Fehler nach TTL");
      const m2 = await ensureExchangeRegistry();
      assert.equal(registryCount(), 2, "zweiter expliziter Aufruf -> zweiter Fetch");
      assert.equal(m2, m1, "identische Map-Instanz = unveränderter Stand");
      // Kein Retry-Loop: jeder weitere Fetch entsteht nur durch einen
      // expliziten Aufruf (genau einer pro Aufruf), nie automatisch.
      const m3 = await ensureExchangeRegistry();
      assert.equal(registryCount(), 3);
      assert.equal(m3, m1);
    });
  } finally {
    restore();
  }
});

/* ---------- Multi-User-Union (Coverage-Fix 2026-10-05) ----------
 * multiUserEntryOf: Registry-Treffer zuerst, sonst verifizierter well-known-
 * Eintrag aus dem synchronen Namens-Index (lookupNameCached — KEIN Fetch aus
 * dem Lookup); unverifizierte Namen liefern null (fail-closed).
 * multiUserSnapshot: Registry ∪ verifizierte well-known-Einträge für den
 * Graphen-Neubau (app.js multiUserAccounts). */

// Base58-gültige well-known-Testadressen (kein 0/O/I/l; die Bulk-URL wird im
// Stub bedient — kein echter Endpunkt).
const WK1 = "rTESTwkVerifiedAcc11111111111";    // verified: true
const WK2 = "rTESTwkUnverifiedAcc22222222222";  // verified fehlt -> nie ein Chip
const BULK_URL = "https://api.xrpscan.com/api/v1/names/well-known";

async function seedNameIndex(fixture) {
  const prev = globalThis.fetch;
  globalThis.fetch = async (url) => {
    if (String(url) === BULK_URL) {
      return { ok: true, json: async () => fixture };
    }
    if (typeof prev === "function") return prev(url);
    throw new Error("unexpected fetch url: " + url);
  };
  try {
    await ensureNameIndex();
  } finally {
    if (prev === undefined) delete globalThis.fetch;
    else globalThis.fetch = prev;
  }
}

test("multiUserEntryOf: Registry-Treffer gewinnt (Registry-Shape bleibt)", async () => {
  resetStubs();
  const restore = installFetch();
  try {
    await ensureExchangeRegistry();
    const entry = multiUserEntryOf(EX1);
    assert.ok(entry, "Registry-Treffer liefert Eintrag");
    assert.equal(entry.exchange, "Test Exchange One");
    assert.notEqual(entry.confidence, "well-known", "Registry-Eintrag wird nicht zur Union-Form umgeformt");
  } finally {
    restore();
  }
});

test("multiUserEntryOf: verifizierter well-known-Fallback, unverifiziert fail-closed", async () => {
  resetStubs();
  const restore = installFetch();
  try {
    await ensureExchangeRegistry();
    await seedNameIndex([
      { account: WK1, name: "WK Verified Test", domain: "wk.example", verified: true },
      { account: WK2, name: "WK Unverified Test", domain: "wk2.example" },
    ]);
    const wk = multiUserEntryOf(WK1);
    assert.ok(wk, "verifizierte well-known-Adresse liefert Fallback-Eintrag");
    assert.equal(wk.exchange, "WK Verified Test");
    assert.equal(wk.confidence, "well-known");
    assert.equal(wk.domain, "wk.example");
    assert.equal(multiUserEntryOf(WK2), null, "unverifizierte well-known-Adresse: null (kein Chip)");
    assert.equal(multiUserEntryOf("rUnbekannteAdresseX111111111"), null, "ohne jeden Treffer: null");
    assert.equal(multiUserEntryOf(null), null);
    assert.equal(multiUserEntryOf(""), null);
  } finally {
    restore();
  }
});

test("multiUserSnapshot: Registry ∪ verifizierte well-known-Einträge (unverifiziert ausgeschlossen)", async () => {
  resetStubs();
  const restore = installFetch();
  try {
    await ensureExchangeRegistry();
    await seedNameIndex([
      { account: WK1, name: "WK Verified Test", domain: "wk.example", verified: true },
      { account: WK2, name: "WK Unverified Test", domain: "wk2.example" },
    ]);
    const snap = multiUserSnapshot();
    assert.ok(snap instanceof Map);
    assert.ok(snap.has(EX1) && snap.has(EX2), "Registry-Einträge vollständig enthalten");
    assert.ok(snap.has(WK1), "verifizierte well-known-Adresse enthalten");
    assert.equal(snap.get(WK1).exchange, "WK Verified Test");
    assert.equal(snap.get(WK1).confidence, "well-known");
    assert.ok(!snap.has(WK2), "unverifizierte well-known-Adresse ausgeschlossen");
    // Zweiter Aufruf: frische Kopie, identischer Inhalt (kein Stand-Verbrauch).
    const snap2 = multiUserSnapshot();
    assert.equal(snap2.size, snap.size, "Snapshot-Aufruf ist idempotent");
    assert.notEqual(snap2, snap, "jeder Aufruf liefert eine neue Kopie (Registry-Map bleibt unangetastet)");
  } finally {
    restore();
  }
});
