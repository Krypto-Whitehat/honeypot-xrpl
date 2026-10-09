// lib/history-shards.test.mjs — Shard-Ring: Lesen über Shards, Schreiben nur in den
// aktiven, Rollover nach Commit-Anzahl, selbstreinigende Ring-Rotation bei „alle voll".
import test from "node:test";
import assert from "node:assert/strict";
import {
  activeShard,
  readGitHubContents,
  writeGitHubContents,
  resetShardCacheForTests,
  shardList,
  SHARD_ROLLOVER_COMMITS,
  SHARD_MANIFEST_PATH,
} from "./history.mjs";

const P = "Owner/primary"; // Primär-Repo: Manifest-Host, wird nie recycelt
const A = "Owner/shard-a";
const B = "Owner/shard-b";
const PATH = "data/x.json";
const FULL = SHARD_ROLLOVER_COMMITS; // Commit-Anzahl, ab der ein Shard voll ist
const codec = { parse: (t) => JSON.parse(t), serialize: (d) => JSON.stringify(d) };

// Fake-GitHub: pro Repo { commits, files: { path: {doc, sha} } }. Commit-Zählung über
// Link-Header wie bei GitHub. Git-Daten-API (trees/commits/refs-PATCH) emuliert den
// Orphan-Reset: Repo-Inhalt wird durch den neuen Tree ersetzt, commits -> 1.
function fakeGitHub(repos) {
  const log = [];
  const trees = new Map();
  let treeSeq = 0;
  const orig = globalThis.fetch;
  globalThis.fetch = async (url, opts = {}) => {
    const u = String(url);
    const method = (opts.method || "GET").toUpperCase();
    const m = u.match(/\/repos\/([^/]+\/[^/?]+)(\/[^?]*)?/);
    if (!m) return new Response("nope", { status: 404 });
    const repo = m[1];
    const tail = m[2] || "";
    const state = repos[repo];
    if (!state) return new Response("not found", { status: 404 });
    if (tail === "" || tail === "/") {
      return new Response(JSON.stringify({ default_branch: "main" }), { status: 200 });
    }
    if (tail.startsWith("/commits")) {
      log.push({ method, repo, kind: "count" });
      const n = state.commits;
      const headers = n > 1 ? { link: `<https://api.github.com/repos/${repo}/commits?per_page=1&page=2>; rel="next", <https://api.github.com/repos/${repo}/commits?per_page=1&page=${n}>; rel="last"` } : {};
      return new Response(JSON.stringify(n ? [{ sha: "x" }] : []), { status: 200, headers });
    }
    if (tail.startsWith("/git/trees") && method === "POST") {
      const body = JSON.parse(opts.body);
      const sha = `tree${++treeSeq}`;
      trees.set(sha, body.tree || []);
      log.push({ method, repo, kind: "tree" });
      return new Response(JSON.stringify({ sha }), { status: 201 });
    }
    if (tail.startsWith("/git/commits") && method === "POST") {
      const body = JSON.parse(opts.body);
      state.pendingTree = trees.get(body.tree) || [];
      log.push({ method, repo, kind: "commit" });
      return new Response(JSON.stringify({ sha: "c" + treeSeq }), { status: 201 });
    }
    if (tail.startsWith("/git/refs/") && method === "PATCH") {
      const files = {};
      for (const e of state.pendingTree || []) {
        let doc = null;
        try { doc = JSON.parse(e.content); } catch { /* Marker-Datei */ }
        files[e.path] = { doc, raw: e.content, sha: "sha" + Math.random().toString(36).slice(2, 10) };
      }
      state.files = files;
      state.commits = 1;
      state.pendingTree = null;
      log.push({ method, repo, kind: "reset" });
      return new Response("{}", { status: 200 });
    }
    const file = tail.startsWith("/contents/") ? decodeURIComponent(tail.slice("/contents/".length)) : null;
    if (file === null) return new Response("bad", { status: 400 });
    if (method === "GET") {
      log.push({ method, repo, kind: "read", file });
      const f = state.files[file];
      if (!f) return new Response("", { status: 404 });
      const raw = f.raw !== undefined ? f.raw : JSON.stringify(f.doc);
      return new Response(JSON.stringify({ sha: f.sha, content: Buffer.from(raw, "utf8").toString("base64"), size: 1 }), { status: 200 });
    }
    if (method === "PUT") {
      const body = JSON.parse(opts.body);
      log.push({ method, repo, kind: "write", file, sha: body.sha ?? null });
      const existing = state.files[file];
      if (existing?.forceConflict) return new Response("conflict", { status: 409 });
      if (existing && body.sha !== existing.sha) return new Response("conflict", { status: 409 });
      if (!existing && body.sha) return new Response("conflict", { status: 409 });
      const raw = Buffer.from(body.content, "base64").toString("utf8");
      let doc = null;
      try { doc = JSON.parse(raw); } catch { /* kein JSON */ }
      const sha = "sha" + Math.random().toString(36).slice(2, 10);
      state.files[file] = { doc, raw, sha };
      state.commits += 1;
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
const baseEnv = (shards, extra = {}) => ({ GITHUB_HISTORY_TOKEN: "t", GITHUB_HISTORY_SHARDS: shards, ...extra });

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

test("Ring-Rotation: alle Shards voll -> ältester Nicht-Primär-Shard wird zurückgesetzt und zum aktiven Shard", async () => {
  resetShardCacheForTests();
  const repos = {
    [P]: { commits: FULL, files: {} },
    [A]: { commits: FULL + 5, files: { [PATH]: { doc: { n: 3 }, sha: "s-a" }, "data/entity-links.json": { doc: { links: 1 }, sha: "s-e" } } },
    [B]: { commits: FULL, files: { [PATH]: { doc: { n: 4 }, sha: "s-b" } } },
  };
  const gh = fakeGitHub(repos);
  try {
    await withEnv(baseEnv(`${P},${A},${B}`, { GITHUB_HISTORY_REPO: P }), async () => {
      const out = await writeGitHubContents((d) => ({ n: (d?.n ?? 0) + 1 }), PATH, codec);
      assert.deepEqual(out, { n: 5 }, "neuester Stand aus B wird fortgeschrieben");
      // Victim A wurde zurückgesetzt (Orphan-Reset), nicht P (Manifest-Host)
      assert.equal(gh.log.filter((e) => e.kind === "reset").length, 1);
      assert.equal(gh.log.filter((e) => e.kind === "reset")[0].repo, A);
      assert.ok(repos[A].commits < 10, "Reset-Historie + Reset-Commit + Daten-Commit, nicht mehr die volle Historie");
      // entity-links existierte NUR in A -> wurde in den Reset-Commit mitgeschleppt
      assert.ok(repos[A].files["data/entity-links.json"], "Carry: entity-links überlebt den Reset");
      assert.deepEqual(repos[A].files["data/entity-links.json"].doc, { links: 1 });
      // Der Datenschreibvorgang landet im recycelten A (jetzt neuester Ring-Shard)
      const writes = gh.log.filter((e) => e.kind === "write" && e.file === PATH);
      assert.equal(writes.at(-1).repo, A);
      assert.deepEqual(repos[A].files[PATH].doc, { n: 5 });
      // Manifest wurde im Primär-Repo geschrieben, Reihenfolge rotiert: [P, B, A]
      const manWrites = gh.log.filter((e) => e.kind === "write" && e.file === SHARD_MANIFEST_PATH);
      assert.ok(manWrites.length >= 1 && manWrites.every((w) => w.repo === P));
      assert.deepEqual(repos[P].files[SHARD_MANIFEST_PATH].doc.order, [P, B, A]);
    });
  } finally { gh.restore(); }
});

test("Ring-Rotation: abgelaufenes pendingReset wird übernommen (Gewinner abgestürzt)", async () => {
  resetShardCacheForTests();
  const staleManifest = {
    doc: {
      version: 1,
      seq: 7,
      order: [P, A, B],
      pendingReset: { repo: B, since: new Date(Date.now() - 600000).toISOString() },
      updatedAt: new Date().toISOString(),
    },
    sha: "s-m",
  };
  const repos = {
    [P]: { commits: FULL, files: { [SHARD_MANIFEST_PATH]: staleManifest } },
    [A]: { commits: FULL, files: { [PATH]: { doc: { n: 5 }, sha: "s-a" } } },
    [B]: { commits: FULL, files: { [PATH]: { doc: { n: 1 }, sha: "s-b" } } },
  };
  const gh = fakeGitHub(repos);
  try {
    await withEnv(baseEnv(`${P},${A},${B}`, { GITHUB_HISTORY_REPO: P }), async () => {
      const out = await writeGitHubContents((d) => ({ n: (d?.n ?? 0) + 1 }), PATH, codec);
      // B wird zurückgesetzt; PATH ist kein State-Singleton -> Bs Kopie verfällt,
      // fortgeschrieben wird der neuere Stand aus A ({n:5} -> 6).
      assert.deepEqual(out, { n: 6 });
      // Übernahme: B wurde zurückgesetzt und bekommt den Schreibvorgang
      assert.equal(gh.log.filter((e) => e.kind === "reset")[0].repo, B);
      assert.equal(gh.log.filter((e) => e.kind === "write" && e.file === PATH).at(-1).repo, B);
    });
  } finally { gh.restore(); }
});

test("Lesen bei 'alle voll' bleibt verfügbar (Lese-Anker = neuester Shard, nie mutierend)", async () => {
  resetShardCacheForTests();
  const repos = {
    [A]: { commits: FULL, files: { [PATH]: { doc: { v: "alt" }, sha: "s1" } } },
    [B]: { commits: FULL, files: { [PATH]: { doc: { v: "neu" }, sha: "s2" } } },
  };
  const gh = fakeGitHub(repos);
  try {
    await withEnv(baseEnv(`${A},${B}`), async () => {
      const r = await readGitHubContents(PATH, codec);
      assert.deepEqual(r.doc, { v: "neu" });
      assert.equal(r.repo, B);
      assert.equal(gh.log.filter((e) => e.kind === "reset").length, 0, "Lesen darf keinen Reset auslösen");
    });
  } finally { gh.restore(); }
});

test("Ring-Rotation scheitert nach 3 Manifest-Konflikten -> ehrlicher Fehler (507), kein stilles Schreiben", async () => {
  resetShardCacheForTests();
  const repos = {
    [P]: { commits: FULL, files: { [SHARD_MANIFEST_PATH]: { doc: { version: 1, seq: 1, order: [P, A, B] }, sha: "s-m", forceConflict: true } } },
    [A]: { commits: FULL, files: {} },
    [B]: { commits: FULL, files: {} },
  };
  const gh = fakeGitHub(repos);
  try {
    await withEnv(baseEnv(`${P},${A},${B}`, { GITHUB_HISTORY_REPO: P }), async () => {
      await assert.rejects(() => writeGitHubContents((d) => d, PATH, codec), (e) => e.status === 507);
      assert.equal(gh.log.filter((e) => e.kind === "reset").length, 0, "kein Reset ohne gewonnenen Lock");
      assert.equal(gh.log.filter((e) => e.kind === "write" && e.file === PATH).length, 0);
    });
  } finally { gh.restore(); }
});

test("Ohne Token: kein Zugriff, kein stiller Shard-Wechsel", async () => {
  resetShardCacheForTests();
  await withEnv({ GITHUB_HISTORY_TOKEN: undefined, GITHUB_HISTORY_SHARDS: `${A},${B}` }, async () => {
    await assert.rejects(() => activeShard(), /Token fehlt/);
  });
});
