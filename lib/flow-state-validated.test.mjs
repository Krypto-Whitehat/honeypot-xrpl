// node:test für fetchValidatedIndex (api/flow-state.js) — die neue
// validatedIndex-Logik des Flow-State-Endpunkts (Kritiker-Befund 2026-10-02:
// bis dahin ungetestet). IN-MEMORY: globalThis.fetch wird für die Dauer des
// Tests durch einen Fixture-Stub ersetzt — KEIN Netzwerk, KEIN Dateizugriff.
// Prüft: Erfolgswert, 60-s-Prozess-Cache (zweiter Aufruf ohne neuen RPC),
// Fehler -> null und Negativ-Cache (kein RPC-Hämmern gegen einen
// gedrosselten Endpunkt), ungültige Antwort -> null, gecachte null,
// Request-Semantik (plain ledger/validated, kein expand:true).

import test from "node:test";
import assert from "node:assert/strict";
import { fetchValidatedIndex, resetValidatedCacheForTests } from "../api/flow-state.js";

// Jeder Test beginnt mit frischem Prozess-Cache (resetValidatedCacheForTests)
// — Tests sind damit unabhängig von der Reihenfolge vorangegangener Tests.

// Stub-Helfer: ersetzt globalThis.fetch, zählt Aufrufe, stellt nach dem Test
// den Originalwert wieder her.
function withFetchStub(t, impl) {
  const original = globalThis.fetch;
  let calls = 0;
  globalThis.fetch = async (url, init) => {
    calls++;
    return impl(url, init);
  };
  t.after(() => {
    globalThis.fetch = original;
  });
  return () => calls;
}

const okResponse = (body) => ({
  ok: true,
  json: async () => body,
});

test("fetchValidatedIndex: Erfolg -> numerischer ledger_index", async (t) => {
  resetValidatedCacheForTests();
  const calls = withFetchStub(t, () =>
    okResponse({ result: { ledger_index: 107373634 } })
  );
  const idx = await fetchValidatedIndex();
  assert.equal(idx, 107373634);
  assert.equal(calls(), 1, "genau ein RPC-Aufruf");
});

test("fetchValidatedIndex: 60-s-Cache — zweiter Aufruf ohne neuen RPC", async (t) => {
  resetValidatedCacheForTests();
  const calls = withFetchStub(t, () =>
    okResponse({ result: { ledger_index: 107373640 } })
  );
  const a = await fetchValidatedIndex();
  const b = await fetchValidatedIndex();
  assert.equal(a, 107373640);
  assert.equal(b, a, "Cache-Wert, kein zweiter Call");
  assert.equal(calls(), 1, "60-s-Fenster: nur ein RPC pro Prozess");
});

test("fetchValidatedIndex: fetch-Wurf -> null, Negativ-Cache (kein RPC-Hämmern)", async (t) => {
  resetValidatedCacheForTests();
  const calls = withFetchStub(t, () => {
    throw new Error("network down");
  });
  const a = await fetchValidatedIndex();
  const b = await fetchValidatedIndex();
  assert.equal(a, null, "ehrlicher Leerwert statt Fehler");
  assert.equal(b, null, "gecachte null");
  assert.equal(calls(), 1, "Fehler wird gecacht — ein RPC, nicht zwei");
});

test("fetchValidatedIndex: HTTP-Fehler (!ok) -> null, gecacht", async (t) => {
  resetValidatedCacheForTests();
  const calls = withFetchStub(t, () => ({ ok: false, status: 503, json: async () => ({}) }));
  const a = await fetchValidatedIndex();
  const b = await fetchValidatedIndex();
  assert.equal(a, null);
  assert.equal(b, null);
  assert.equal(calls(), 1, "Negativ-Cache greift auch bei HTTP-Fehler");
});

test("fetchValidatedIndex: ungültige Antwort (kein numerischer Index) -> null", async (t) => {
  resetValidatedCacheForTests();
  const calls = withFetchStub(t, () => okResponse({ result: { ledger_index: "kaputt" } }));
  const a = await fetchValidatedIndex();
  assert.equal(a, null, "kein Number -> null, keine Schätzung");
  const b = await fetchValidatedIndex();
  assert.equal(b, null);
  assert.equal(calls(), 1, "auch die null aus ungültiger Antwort wird gecacht");
});

test("fetchValidatedIndex: Request-Semantik — POST ledger/validated ohne expand", async (t) => {
  resetValidatedCacheForTests();
  let seen = null;
  const calls = withFetchStub(t, (url, init) => {
    seen = { url, init };
    return okResponse({ result: { ledger_index: 42 } });
  });
  await fetchValidatedIndex();
  assert.equal(calls(), 1);
  assert.equal(seen.init.method, "POST");
  const body = JSON.parse(seen.init.body);
  assert.equal(body.method, "ledger");
  assert.deepEqual(body.params, [{ ledger_index: "validated" }],
    "plain validated-Call — kein expand:true (Quota-Hauptlast, lib/live-gate.mjs:7-15)");
});
