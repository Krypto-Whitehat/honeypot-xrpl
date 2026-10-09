// lib/block-window-endpoint.test.mjs — node:test für den GET-Handler-Zweig
// route=block-window in api/flow-state.js (Range-Validierung, 405, fail-closed
// 200+reason, 200-Vertragsform, 60-s-Prozess-Cache). Muster
// lib/flow-state-validated.test.mjs: die Route wird importiert und gegen
// globalThis.fetch-Stubs gefahren — KOMPLETT OFFLINE, keine echten
// Netzwerk-Calls. (Der eigene Endpunkt api/block-window.js wurde 2026-10-02 in
// api/flow-state.js zusammengeführt: Hobby-Limit max. 12 Functions/Deployment;
// der /api/block-window-Pfad bleibt via vercel.json-Rewrite erhalten.)
import test from "node:test";
import assert from "node:assert/strict";
import handler, { resetBlockWindowCacheForTests, resetValidatedCacheForTests } from "../api/flow-state.js";

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

// Minimaler req/res im Vercel-Formular.
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

// =====================================================================

test("block-window: POST -> 405 (GET-only)", async () => {
  stubGithubEnv();
  const { restore } = installFetchStub(() => ghResponse({}, 500));
  try {
    resetBlockWindowCacheForTests();
    const res = makeRes();
    await handler({ method: "POST", query: {} }, res);
    assert.equal(res.statusCode, 405);
    assert.equal(res.headers.Allow, "GET");
  } finally {
    restore();
    restoreGithubEnv();
  }
});

test("block-window: ungültiger range -> 400", async () => {
  stubGithubEnv();
  const { restore } = installFetchStub(() => ghResponse({}, 500));
  try {
    resetBlockWindowCacheForTests();
    const res = makeRes();
    await handler({ method: "GET", query: { route: "block-window", range: "14d" } }, res);
    assert.equal(res.statusCode, 400);
  } finally {
    restore();
    restoreGithubEnv();
  }
});

test("block-window: ohne Token -> 200 + reason (fail-closed, roh, kein RPC)", async () => {
  stubGithubEnv();
  delete process.env.GITHUB_HISTORY_TOKEN;
  const { calls, restore } = installFetchStub(() => {
    throw new Error("darf nicht aufgerufen werden");
  });
  try {
    resetBlockWindowCacheForTests();
    const res = makeRes();
    await handler({ method: "GET", query: { route: "block-window", range: "24h" } }, res);
    assert.equal(res.statusCode, 200);
    assert.equal(res.body.reason, "Persistenz nicht konfiguriert"); // roh, nicht übersetzt
    assert.deepEqual(res.body.buckets, []);
    assert.deepEqual(res.body.flagged, []);
    assert.equal(res.body.cursor, 0);
    assert.equal(res.body.validatedIndex, null);
    assert.equal(calls.length, 0); // ohne Persistenz kein einziger fetch
  } finally {
    restore();
    restoreGithubEnv();
  }
});

test("block-window: 200-Vertrag (buckets/flagged/cursor/validatedIndex) aus gestubbten Chunks", async () => {
  stubGithubEnv();
  const now = Date.now();
  // Blöcke in eine vollständig vergangene Stunde verankern — sonst kippt der
  // Test bei Lauf knapp nach einem Stundenwechsel (beide Blöcke in getrennten
  // Buckets). 24-h-Fenster bleibt eingehalten.
  const hourBase = Math.floor(now / 3600000) * 3600000 - 3600000;
  const day = new Date(hourBase).toISOString().slice(0, 10);
  const chunk = {
    day,
    updatedAt: now - 1000,
    blocks: [
      { i: 1000, t: iso(hourBase + 10 * 60000), n: 42 },
      { i: 1001, t: iso(hourBase + 20 * 60000), n: 55, f: [{ from: "rSYNaaaaaaaaaaaaaaaaaaaaa1", to: "rSYNaaaaaaaaaaaaaaaaaaaaa2", type: "Payment", amountDrops: 1000, txHash: "H1", ledgerSeq: 1001 }] },
    ],
  };
  const flowDoc = { cursor: 999, state: { clusters: {}, blocksProcessedTotal: 0, lastAdvancedAt: null }, updatedAt: now - 2000 };
  const { calls, restore } = installFetchStub((method, url) => {
    if (method === "POST") return ghResponse({ result: { ledger_index: 123456 } }); // validatedIndex-RPC
    if (url.includes("/contents/data/flow-state.json")) return ghResponse({ sha: "f1", content: b64(JSON.stringify(flowDoc)) });
    if (url.includes(`/contents/data/block-window/${day}.json`)) return ghResponse({ sha: "b1", content: b64(JSON.stringify(chunk)) });
    return ghResponse({ message: "Not Found" }, 404); // ältere Tage
  });
  try {
    resetBlockWindowCacheForTests();
    resetValidatedCacheForTests();
    const res = makeRes();
    await handler({ method: "GET", query: { route: "block-window", range: "24h" } }, res);
    assert.equal(res.statusCode, 200);
    assert.equal(res.body.range, "24h");
    assert.ok(Number.isFinite(res.body.from) && Number.isFinite(res.body.to) && res.body.from < res.body.to);
    assert.equal(res.body.cursor, 999);
    assert.equal(res.body.validatedIndex, 123456);
    assert.equal(res.body.updatedAt, now - 1000);
    assert.equal(res.body.buckets.length, 1, "beide Blöcke in derselben Stunde");
    assert.equal(res.body.buckets[0].blocks, 2);
    assert.equal(res.body.buckets[0].txns, 97);
    assert.equal(res.body.buckets[0].flaggedBlocks, 1);
    assert.equal(res.body.flagged.length, 1);
    assert.equal(res.body.flagged[0].i, 1001);
    assert.equal(res.body.flagged[0].f[0].txHash, "H1");
    // 60-s-Cache: zweiter Aufruf ohne neue GitHub-/RPC-Calls.
    const before = calls.length;
    const res2 = makeRes();
    await handler({ method: "GET", query: { route: "block-window", range: "24h" } }, res2);
    assert.equal(res2.statusCode, 200);
    assert.equal(calls.length, before, "Cache: keine neuen Calls im 60-s-Fenster");
  } finally {
    restore();
    restoreGithubEnv();
  }
});

test("block-window: Read-Fehler (403) -> 502, neutrale Message", async () => {
  stubGithubEnv();
  const { restore } = installFetchStub((method) => {
    if (method === "POST") return ghResponse({ result: { ledger_index: 1 } });
    return ghResponse({ message: "forbidden" }, 403);
  });
  try {
    resetBlockWindowCacheForTests();
    resetValidatedCacheForTests();
    const res = makeRes();
    await handler({ method: "GET", query: { route: "block-window", range: "3d" } }, res);
    assert.equal(res.statusCode, 502);
    assert.ok(!JSON.stringify(res.body).includes(DUMMY_TOKEN));
  } finally {
    restore();
    restoreGithubEnv();
  }
});
