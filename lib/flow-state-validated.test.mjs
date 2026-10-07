// node:test für fetchValidatedIndex (api/flow-state.js) — die neue
// validatedIndex-Logik des Flow-State-Endpunkts (Kritiker-Befund 2026-10-02:
// bis dahin ungetestet). IN-MEMORY: globalThis.fetch wird für die Dauer des
// Tests durch einen Fixture-Stub ersetzt — KEIN Netzwerk, KEIN Dateizugriff.
// Prüft: Erfolgswert, Prozess-Cache (60 s Erfolg / 10 s Fehler — zweiter
// Aufruf ohne neuen RPC), Fehler -> null und Negativ-Cache (kein RPC-Hämmern
// gegen einen gedrosselten Endpunkt), ungültige Antwort -> null, gecachte
// null, Request-Semantik (plain ledger/validated, kein expand:true).

import test from "node:test";
import assert from "node:assert/strict";
import handler, { fetchValidatedIndex, resetValidatedCacheForTests, resetArchiveCacheForTests } from "../api/flow-state.js";

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

test("fetchValidatedIndex: fetch-Wurf -> null, Negativ-Cache 10 s (kein RPC-Hämmern)", async (t) => {
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

// =====================================================================
// Archiv-Zweig (route=archive, api/flow-state.js handleArchive) — Runde 3:
// Rückwärts-Lesen in Blöcken à ARCHIVE_QUERY_DAYS (31) Tagen mit harter
// Kappe ARCHIVE_MAX_DAY_BLOCKS (Default 2 -> max. 62 GitHub-Reads pro
// Aufruf), Early-Stop bei Fensterabdeckung (cluster.ledgerRange.from <=
// from), truncated=true bei Kappe ohne Abdeckung, queryDays-Feld,
// 400-Validierung und Fail-closed ohne Token. Muster
// lib/block-window-endpoint.test.mjs: globalThis.fetch-Stubs, komplett
// offline — KEIN Netzwerk, KEIN Dateizugriff.
// =====================================================================

const DUMMY_TOKEN = "gh-dummy-test-token";
let envBackup = null;
function stubGithubEnv() {
  envBackup = {
    GITHUB_HISTORY_TOKEN: process.env.GITHUB_HISTORY_TOKEN,
    GITHUB_HISTORY_REPO: process.env.GITHUB_HISTORY_REPO,
    GITHUB_HISTORY_BRANCH: process.env.GITHUB_HISTORY_BRANCH,
  };
  process.env.GITHUB_HISTORY_TOKEN = DUMMY_TOKEN;
  process.env.GITHUB_HISTORY_REPO = "acme/history-test";
  delete process.env.GITHUB_HISTORY_BRANCH;
}
function restoreGithubEnv() {
  if (!envBackup) return;
  for (const [k, v] of Object.entries(envBackup)) {
    if (v === undefined) delete process.env[k];
    else process.env[k] = v;
  }
  envBackup = null;
}
function ghResponse(obj, status = 200) {
  return new Response(JSON.stringify(obj), { status, headers: { "content-type": "application/json" } });
}
function b64(str) {
  return Buffer.from(str, "utf8").toString("base64");
}
function installFetchStub(handlerFn) {
  const orig = globalThis.fetch;
  const calls = [];
  globalThis.fetch = async (url, init = {}) => {
    const method = String(init.method ?? "GET").toUpperCase();
    calls.push({ method, url: String(url) });
    return handlerFn(method, String(url));
  };
  return { calls, restore: () => (globalThis.fetch = orig) };
}
function makeRes() {
  const res = {
    headers: {},
    statusCode: null,
    body: null,
    setHeader(k, v) {
      this.headers[k] = v;
    },
    status(code) {
      this.statusCode = code;
      return this;
    },
    json(body) {
      this.body = body;
      return this;
    },
  };
  return res;
}
const iso = (ms) => new Date(ms).toISOString();

// Base58-sichere Zieladresse (kein 0/O/I/l) im Replay-Fenster.
const ARC_ADDR = "rSYNarcbbbbbbbbbbbbbbbbbbb1";

function archiveDocFor(day, clusters) {
  return { day, updatedAt: Date.now(), docs: clusters };
}
function clusterRow(id, edges) {
  const seqs = edges.map((e) => e.ledgerSeq).filter((n) => Number.isFinite(n));
  return {
    clusterId: id,
    memberAddresses: [...new Set(edges.flatMap((e) => [e.from, e.to]))].sort(),
    edges,
    peelingChains: [],
    entitySnapshot: null,
    firstSeen: iso(Date.now() - 3_600_000),
    lastSeen: iso(Date.now()),
    ledgerRange: { from: Math.min(...seqs), to: Math.max(...seqs) },
    archivedAt: null,
  };
}

test("archive: Early-Stop — ein Block (31 Reads) bei Fensterabdeckung, truncated false", async () => {
  stubGithubEnv();
  const today = new Date().toISOString().slice(0, 10);
  const cluster = clusterRow("cluster:arcCover", [
    { from: "rSYNarcfrom000000000000002", to: ARC_ADDR, amountDrops: 1000, txHash: "H1", ledgerSeq: 1500, closeTime: iso(Date.now()) },
    { from: "rSYNarcfrom111111111111113", to: "rSYNarcfrom000000000000002", amountDrops: 1200, txHash: "H2", ledgerSeq: 1200, closeTime: iso(Date.now()) },
  ]);
  const { calls, restore } = installFetchStub((method, url) => {
    if (method !== "GET") return ghResponse({}, 500);
    if (url.includes(`/contents/data/flow-archive/${today}.json`)) {
      return ghResponse({ sha: "a1", content: b64(JSON.stringify(archiveDocFor(today, [cluster]))) });
    }
    return ghResponse({ message: "Not Found" }, 404); // ältere Tage leer
  });
  try {
    resetArchiveCacheForTests();
    const res = makeRes();
    await handler({ method: "GET", query: { route: "archive", address: ARC_ADDR, from: "1200", to: "2000" } }, res);
    assert.equal(res.statusCode, 200);
    assert.equal(res.body.truncated, false, "ledgerRange.from 1200 <= fromLedger 1200 -> Early-Stop, keine Kappe");
    assert.equal(res.body.queryDays, 31, "ein Block à 31 Tage gelesen");
    const getReads = calls.filter((c) => c.method === "GET" && c.url.includes("/contents/data/flow-archive/"));
    assert.equal(getReads.length, 31, "genau 31 Tages-Reads, zweiter Block unterbleibt");
    assert.deepEqual(
      res.body.hops.map((h) => h.txHash),
      ["H1", "H2"],
      "Rückwärts-Rekonstruktion A<-from0<-from1 im Fenster [1200,2000]"
    );
    // 60-s-Archiv-Cache: zweiter Aufruf ohne neue Reads.
    const before = calls.length;
    const res2 = makeRes();
    await handler({ method: "GET", query: { route: "archive", address: ARC_ADDR, from: "1200", to: "2000" } }, res2);
    assert.equal(res2.statusCode, 200);
    assert.equal(calls.length, before, "Cache: keine neuen Reads im 60-s-Fenster");
  } finally {
    restore();
    restoreGithubEnv();
  }
});

test("archive: Tages-Kappe — 62 Reads, truncated true, queryDays 62 ohne Fensterabdeckung", async () => {
  stubGithubEnv();
  const today = new Date().toISOString().slice(0, 10);
  // Alle Cluster beginnen bei ledgerSeq 5000 > fromLedger 1000: kein gelesener
  // Cluster deckt die Fensteruntergrenze ab -> beide Blöcke werden gelesen.
  const cluster = clusterRow("cluster:arcFar", [
    { from: "rSYNarcfrom000000000000002", to: ARC_ADDR, amountDrops: 1000, txHash: "H1", ledgerSeq: 5100, closeTime: iso(Date.now()) },
  ]);
  const { calls, restore } = installFetchStub((method, url) => {
    if (method !== "GET") return ghResponse({}, 500);
    if (url.includes(`/contents/data/flow-archive/${today}.json`)) {
      return ghResponse({ sha: "a1", content: b64(JSON.stringify(archiveDocFor(today, [cluster]))) });
    }
    return ghResponse({ message: "Not Found" }, 404);
  });
  try {
    resetArchiveCacheForTests();
    const res = makeRes();
    await handler({ method: "GET", query: { route: "archive", address: ARC_ADDR, from: "1000", to: "6000" } }, res);
    assert.equal(res.statusCode, 200);
    assert.equal(res.body.truncated, true, "Kappe erreicht ohne fromLedger-Abdeckung -> truncated");
    assert.equal(res.body.queryDays, 62, "zwei Blöcke à 31 Tage (harte Kappe ARCHIVE_MAX_DAY_BLOCKS=2)");
    const getReads = calls.filter((c) => c.method === "GET" && c.url.includes("/contents/data/flow-archive/"));
    assert.equal(getReads.length, 62, "max. 62 GitHub-Reads pro Aufruf");
    assert.deepEqual(res.body.hops.map((h) => h.txHash), ["H1"], "Replay findet die Kante im Fenster [1000,6000]");
  } finally {
    restore();
    restoreGithubEnv();
  }
});

test("archive: 400 für ungültige Adresse und ungültiges Fenster (from > to)", async () => {
  stubGithubEnv();
  const { calls, restore } = installFetchStub(() => ghResponse({}, 500));
  try {
    const resA = makeRes();
    await handler({ method: "GET", query: { route: "archive", address: "r0OIinvalid", from: "10", to: "20" } }, resA);
    assert.equal(resA.statusCode, 400, "Adresse außerhalb XRPL_ADDR_RE (0/O/I/l) -> 400");
    const resB = makeRes();
    await handler({ method: "GET", query: { route: "archive", address: ARC_ADDR, from: "30", to: "20" } }, resB);
    assert.equal(resB.statusCode, 400, "from > to -> 400");
    const resC = makeRes();
    await handler({ method: "GET", query: { route: "archive", address: ARC_ADDR, from: "x", to: "20" } }, resC);
    assert.equal(resC.statusCode, 400, "nicht-numerischer from -> 400");
    assert.equal(calls.length, 0, "Validierung vor jedem Read — kein fetch");
  } finally {
    restore();
    restoreGithubEnv();
  }
});

// Range-Parameter (Kritik-Runde 3, Ask-Punkt 4): 30d/90d auf route=archive.
test("archive range=30d: ein Block à 31 Tage, volle Fensterabdeckung, truncated false", async () => {
  stubGithubEnv();
  const today = new Date().toISOString().slice(0, 10);
  const cluster = clusterRow("cluster:arcR30", [
    { from: "rSYNarcfrom000000000000002", to: ARC_ADDR, amountDrops: 1000, txHash: "H1", ledgerSeq: 1500, closeTime: iso(Date.now()) },
    { from: "rSYNarcfrom111111111111113", to: "rSYNarcfrom000000000000002", amountDrops: 1200, txHash: "H2", ledgerSeq: 1200, closeTime: iso(Date.now()) },
  ]);
  const { calls, restore } = installFetchStub((method, url) => {
    if (method !== "GET") return ghResponse({}, 500);
    if (url.includes(`/contents/data/flow-archive/${today}.json`)) {
      return ghResponse({ sha: "a1", content: b64(JSON.stringify(archiveDocFor(today, [cluster]))) });
    }
    return ghResponse({ message: "Not Found" }, 404);
  });
  try {
    resetArchiveCacheForTests();
    const res = makeRes();
    await handler({ method: "GET", query: { route: "archive", address: ARC_ADDR, from: "1200", to: "2000", range: "30d" } }, res);
    assert.equal(res.statusCode, 200);
    assert.equal(res.body.range, "30d", "range wird zurückgemeldet");
    assert.equal(res.body.queryDays, 31, "30 d = 1 Block à 31 Tage (ceil(30/31))");
    assert.equal(res.body.truncated, false, "30-d-Fenster voll gelesen und abgedeckt");
    const getReads = calls.filter((c) => c.method === "GET" && c.url.includes("/contents/data/flow-archive/"));
    assert.equal(getReads.length, 31, "Read-Budget: ein Block");
  } finally {
    restore();
    restoreGithubEnv();
  }
});

test("archive range=90d: Default-Kappe 2 -> 62 Reads, ehrlich truncated=true, queryDays 62", async () => {
  stubGithubEnv();
  const today = new Date().toISOString().slice(0, 10);
  const cluster = clusterRow("cluster:arcR90", [
    { from: "rSYNarcfrom000000000000002", to: ARC_ADDR, amountDrops: 1000, txHash: "H1", ledgerSeq: 1500, closeTime: iso(Date.now()) },
  ]);
  const { calls, restore } = installFetchStub((method, url) => {
    if (method !== "GET") return ghResponse({}, 500);
    if (url.includes(`/contents/data/flow-archive/${today}.json`)) {
      return ghResponse({ sha: "a1", content: b64(JSON.stringify(archiveDocFor(today, [cluster]))) });
    }
    return ghResponse({ message: "Not Found" }, 404);
  });
  try {
    resetArchiveCacheForTests();
    const res = makeRes();
    await handler({ method: "GET", query: { route: "archive", address: ARC_ADDR, from: "1200", to: "2000", range: "90d" } }, res);
    assert.equal(res.statusCode, 200);
    assert.equal(res.body.range, "90d");
    assert.equal(res.body.queryDays, 62, "ceil(90/31)=3 Blöcke nötig, harte Kappe 2 -> 62 d real");
    assert.equal(res.body.truncated, true, "90 d nicht voll abfragbar bei Default-Kappe -> ehrliches Flag");
    const getReads = calls.filter((c) => c.method === "GET" && c.url.includes("/contents/data/flow-archive/"));
    assert.equal(getReads.length, 62, "Read-Budget unverändert: max. 2 Blöcke");
  } finally {
    restore();
    restoreGithubEnv();
  }
});

test("archive range: ungültiger Wert -> 400, ohne range bitgleich zum bisherigen Vertrag (kein range-Feld)", async () => {
  stubGithubEnv();
  const { calls, restore } = installFetchStub(() => ghResponse({ message: "Not Found" }, 404));
  try {
    resetArchiveCacheForTests();
    const resBad = makeRes();
    await handler({ method: "GET", query: { route: "archive", address: ARC_ADDR, from: "10", to: "20", range: "60d" } }, resBad);
    assert.equal(resBad.statusCode, 400, "nur 30d|90d (block-window bleibt 24h|3d|7d — 7-d-Retention)");
    assert.equal(calls.length, 0, "Validierung vor jedem Read");
    const resPlain = makeRes();
    await handler({ method: "GET", query: { route: "archive", address: ARC_ADDR, from: "10", to: "20" } }, resPlain);
    assert.equal(resPlain.statusCode, 200);
    assert.ok(!("range" in resPlain.body), "ohne range kein neues Feld (Byte-Neutralität)");
    assert.equal(resPlain.body.queryDays, 62, "bisheriges Verhalten unverändert");
  } finally {
    restore();
    restoreGithubEnv();
  }
});

test("archive: ohne Token -> 200 + reason (fail-closed, kein fetch)", async () => {
  stubGithubEnv();
  delete process.env.GITHUB_HISTORY_TOKEN;
  const { calls, restore } = installFetchStub(() => {
    throw new Error("darf nicht aufgerufen werden");
  });
  try {
    const res = makeRes();
    await handler({ method: "GET", query: { route: "archive", address: ARC_ADDR, from: "1000", to: "2000" } }, res);
    assert.equal(res.statusCode, 200);
    assert.equal(res.body.reason, "Persistenz nicht konfiguriert");
    assert.deepEqual(res.body.hops, []);
    assert.equal(res.body.truncated, false);
    assert.equal(calls.length, 0, "ohne Persistenz kein einziger fetch");
  } finally {
    restore();
    restoreGithubEnv();
  }
});
