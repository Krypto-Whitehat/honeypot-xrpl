// lib/history-shards.test.mjs — Shard-Logik: Lesen über Shards, Schreiben nur in den aktiven, Rollover nach Commit-Anzahl.
import test from "node:test";
import assert from "node:assert/strict";
import {
  activeShard,
  readGitHubContents,
  writeGitHubContents,
  resetShardCacheForTests,
  shardList,
  SHARD_ROLLOVER_COMMITS,
} from "./history.mjs";

const A = "Owner/shard-a";
const B = "Owner/shard-b";
const PATH = "data/x.json";
const FULL = SHARD_ROLLOVER_COMMITS; // Commit-Anzahl, ab der ein Shard voll ist
const codec = { parse: (t) => JSON.parse(t), serialize: (d) => JSON.stringify(d) };

// Fake-GitHub: pro Repo { commits, files: { path: {doc, sha} } }. Commit-Zählung über Link-Header wie bei GitHub.
function fakeGitHub(repos) {
  const log = [];
  const orig = globalThis.fetch;
  globalThis.fetch = async (url, opts = {}) => {
    const u = String(url);
    const method = (opts.method || "GET").toUpperCase();
    const m = u.match(/\/repos\/([^/]+\/[^/?]+)(\/(commits)|\/contents\/([^?]+))?/);
    if (!m) return new Response("nope", { status: 404 });
    const repo = m[1];
    const state = repos[repo];
    if (!state) return new Response("not found", { status: 404 });
    if (m[3] === "commits") {
      log.push({ method, repo, kind: "count" });
      const n = state.commits;
      const headers = n > 1 ? { link: `<https://api.github.com/repos/${repo}/commits?per_page=1&page=2>; rel="next", <https://api.github.com/repos/${repo}/commits?per_page=1&page=${n}>; rel="last"` } : {};
      return new Response(JSON.stringify(n ? [{ sha: "x" }] : []), { status: 200, headers });
    }
    const file = m[4];
    if (method === "GET") {
      log.push({ method, repo, kind: "read", file });
      const f = state.files[file];
      if (!f) return new Response("", { status: 404 });
      const b64 = Buffer.from(JSON.stringify(f.doc), "utf8").toString("base64");
      return new Response(JSON.stringify({ sha: f.sha, content: b64, size: 1 }), { status: 200 });
    }
    if (method === "PUT") {
      const body = JSON.parse(opts.body);
      log.push({ method, repo, kind: "write", file, sha: body.sha ?? null });
      const existing = state.files[file];
      if (existing && body.sha !== existing.sha) return new Response("conflict", { status: 409 });
      if (!existing && body.sha) return new Response("conflict", { status: 409 });
      const doc = JSON.parse(Buffer.from(body.content, "base64").toString("utf8"));
      const sha = "sha" + Math.random().toString(36).slice(2, 10);
      state.files[file] = { doc, sha };
      return new Response(JSON.stringify({ content: { sha } }), { status: 201 });
    }
    return new Response("bad", { status: 400 });
  };
  return { log, restore: () => { globalThis.fetch = orig; } };
}

function withEnv(vars, fn) {
  const saved = {};
  for (const k of Object.keys(vars)) { saved[k] = process.env[k]; if (vars[k] === undefined) delete process.env[k]; else process.env[k] = vars[k]; }
  return Promise.resolve().then(fn).finally(() => {
    for (const k of Object.keys(vars)) { if (saved[k] === undefined) delete process.env[k]; else process.env[k] = saved[k]; }
  });
}
const baseEnv = (shards) => ({ GITHUB_HISTORY_TOKEN: "t", GITHUB_HISTORY_SHARDS: shards });

test("Shard-Liste: ohne Env ein Repo, mit Env in fester Reihenfolge", async () => {
  await withEnv({ GITHUB_HISTORY_SHARDS: undefined }, () => assert.equal(shardList().length, 1));
  await withEnv(baseEnv(`${A},${B}`), () => assert.deepEqual(shardList(), [A, B]));
});

test("Rollover-Grenze ist eine Commit-Anzahl im Bereich um 40.000 (Richtwert aus der Messung)", () => {
  assert.ok(FULL >= 30000 && FULL <= 45000, "Grenze: " + FULL);
});

test("aktiver Shard = erster Shard unter der Grenze", async () => {
  resetShardCacheForTests();
  const gh = fakeGitHub({ [A]: { commits: FULL + 5, files: {} }, [B]: { commits: 10, files: {} } });
  try {
    await withEnv(baseEnv(`${A},${B}`), async () => {
      const act = await activeShard({ fresh: true });
      assert.equal(act.repo, B);
      assert.equal(act.index, 1);
    });
  } finally { gh.restore(); }
});

test("Lesen fällt auf ältere Shards zurück (Archiv bleibt zugreifbar)", async () => {
  resetShardCacheForTests();
  const gh = fakeGitHub({
    [A]: { commits: FULL + 5, files: { [PATH]: { doc: { old: true }, sha: "s-old" } } },
    [B]: { commits: 10, files: {} },
  });
  try {
    await withEnv(baseEnv(`${A},${B}`), async () => {
      const r = await readGitHubContents(PATH, codec);
      assert.deepEqual(r.doc, { old: true });
      assert.equal(r.repo, A);
    });
  } finally { gh.restore(); }
});

test("Schreiben landet im aktiven Shard, sha aus dem alten Shard wird NICHT übernommen", async () => {
  resetShardCacheForTests();
  const gh = fakeGitHub({
    [A]: { commits: FULL + 5, files: { [PATH]: { doc: { n: 1 }, sha: "s-old" } } },
    [B]: { commits: 10, files: {} },
  });
  try {
    await withEnv(baseEnv(`${A},${B}`), async () => {
      const out = await writeGitHubContents((doc) => ({ n: (doc?.n ?? 0) + 1 }), PATH, codec);
      assert.deepEqual(out, { n: 2 });
      const writes = gh.log.filter((e) => e.kind === "write");
      assert.deepEqual(writes.map((e) => e.repo), [B]);
      assert.equal(writes[0].sha, null, "kein sha aus dem alten Shard");
    });
  } finally { gh.restore(); }
});

test("Rollover: Shard erreicht die Grenze -> nächster Schreibvorgang wechselt, Stand wird fortgeschrieben", async () => {
  resetShardCacheForTests();
  const repos = {
    [A]: { commits: 10, files: { [PATH]: { doc: { n: 5 }, sha: "s1" } } },
    [B]: { commits: 10, files: {} },
  };
  const gh = fakeGitHub(repos);
  try {
    await withEnv(baseEnv(`${A},${B}`), async () => {
      assert.deepEqual(await writeGitHubContents((d) => ({ n: d.n + 1 }), PATH, codec), { n: 6 });
      assert.equal(gh.log.filter((e) => e.kind === "write").at(-1).repo, A);
      repos[A].commits = FULL; // A erreicht die Grenze
      gh.log.length = 0;
      assert.deepEqual(await writeGitHubContents((d) => ({ n: d.n + 1 }), PATH, codec), { n: 7 }, "Stand aus A wird fortgeschrieben");
      assert.equal(gh.log.filter((e) => e.kind === "write").at(-1).repo, B);
      assert.deepEqual(repos[B].files[PATH].doc, { n: 7 });
      assert.deepEqual(repos[A].files[PATH].doc, { n: 6 }, "Archiv in A bleibt unverändert");
    });
  } finally { gh.restore(); }
});

test("Alle Shards voll -> ehrlicher Fehler (507), kein stilles Schreiben", async () => {
  resetShardCacheForTests();
  const gh = fakeGitHub({ [A]: { commits: FULL, files: {} }, [B]: { commits: FULL + 1, files: {} } });
  try {
    await withEnv(baseEnv(`${A},${B}`), async () => {
      await assert.rejects(() => writeGitHubContents((d) => d, PATH, codec), (e) => e.status === 507);
      assert.equal(gh.log.filter((e) => e.kind === "write").length, 0);
    });
  } finally { gh.restore(); }
});

test("Ohne Token: kein Zugriff, kein stiller Shard-Wechsel", async () => {
  resetShardCacheForTests();
  await withEnv({ GITHUB_HISTORY_TOKEN: undefined, GITHUB_HISTORY_SHARDS: `${A},${B}` }, async () => {
    await assert.rejects(() => activeShard(), /Token fehlt/);
  });
});
