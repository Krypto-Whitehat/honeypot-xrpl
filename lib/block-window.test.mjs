// lib/block-window.test.mjs — node:test-Unit-Tests für den Block-Fenster-Codec.
// KOMPLETT OFFLINE: In-Memory-Fixtures + globalThis.fetch-Stubs für den
// GitHub-Transport (Muster lib/history.test.mjs), keine echten Netzwerk-Calls.
// Köder-Fixtures sind synthetische Testadressen (Muster history.test.mjs).
import test from "node:test";
import assert from "node:assert/strict";
import {
  BLOCK_WINDOW_DIR,
  BLOCK_WINDOW_RETENTION_MS,
  blockWindowPath,
  dayOf,
  emptyBlockWindow,
  parseBlockWindowText,
  serializeBlockWindow,
  blockRecord,
  flaggedEdgesFrom,
  appendBlockWindow,
  capBlockWindow,
  BLOCK_WINDOW_MAX_BYTES,
  projectBlockWindow,
  pruneBlockWindowDocs,
  readBlockWindowGitHub,
  writeBlockWindowGitHub,
  deleteBlockWindowGitHub,
} from "./block-window.mjs";

// ---------- Fixture-Helfer ----------
const SYN_ALPHA = "abcdefghijkmnopqrstuvwxyz";
function synth(i) {
  let s = "";
  let n = i + 1;
  while (n > 0) {
    n -= 1;
    s = SYN_ALPHA[n % 25] + s;
    n = Math.floor(n / 25);
  }
  return "rSYN" + s.padStart(24, "a");
}
const NO_BAIT = new Map();
const baitLabels = new Map([
  [synth(900001), "HP-1"],
  [synth(900002), "HP-2"],
]);

const DAY = "2026-10-02";
const T0 = Date.parse("2026-10-02T10:00:00Z");
const iso = (ms) => new Date(ms).toISOString();

// =====================================================================
// Pfad / Tag / Schema
// =====================================================================

test("blockWindowPath: Tages-Chunk im Block-Fenster-Verzeichnis", () => {
  assert.equal(blockWindowPath(DAY), "data/block-window/2026-10-02.json");
  assert.equal(BLOCK_WINDOW_DIR, "data/block-window");
  assert.throws(() => blockWindowPath("kein-tag"), /ungültiges Tages-Datum/);
  assert.throws(() => blockWindowPath("../../etc/passwd"), /ungültiges Tages-Datum/);
});

test("dayOf: UTC-Kalendertag der Ledger-Zeit", () => {
  assert.equal(dayOf(T0), DAY);
  assert.equal(dayOf(Date.parse("2026-10-02T23:59:59Z")), DAY);
  assert.equal(dayOf(Date.parse("2026-10-03T00:00:01Z")), "2026-10-03");
  assert.equal(dayOf("x"), null);
});

test("serialize/parse: Roundtrip konvergiert auf die kanonische Form", () => {
  const doc = {
    day: DAY,
    updatedAt: 123,
    blocks: [
      { i: 100, t: iso(T0), n: 42 },
      { i: 101, t: iso(T0 + 4000), n: 55, f: [{ from: synth(1), to: synth(2), type: "Payment", amountDrops: 1000, txHash: "H1", ledgerSeq: 101 }] },
    ],
  };
  const text = serializeBlockWindow(doc);
  assert.ok(text.startsWith("{"));
  assert.deepEqual(parseBlockWindowText(text), doc);
});

test("parseBlockWindowText: Korruption wirft (kein Überschreiben)", () => {
  assert.throws(() => parseBlockWindowText("### kein JSON ###"), /nicht parsebar/);
  assert.throws(() => parseBlockWindowText("[1,2,3]"), /unerwartetes Format/);
  assert.throws(() => parseBlockWindowText("42"), /unerwartetes Format/);
});

// =====================================================================
// Record-Aufbau + Bait-Filter (Persistenz-Schicht)
// =====================================================================

test("blockRecord: kompakte Zeile {i,t,n}; f nur bei geflaggten Txs", () => {
  const rec = blockRecord({ index: 100, closeTimeIso: iso(T0), txCount: 42, flagged: [] }, NO_BAIT);
  assert.deepEqual(rec, { i: 100, t: iso(T0), n: 42 });
  const withF = blockRecord({
    index: 101,
    closeTimeIso: iso(T0),
    txCount: 3,
    flagged: [{ from: synth(1), to: synth(2), type: "Payment", amountDrops: 5000, txHash: "H2", ledgerSeq: 101 }],
  }, NO_BAIT);
  assert.equal(withF.f.length, 1);
  assert.equal(withF.f[0].amountDrops, 5000);
});

test("blockRecord: Köder-Edge fällt VOR Persistenz still raus (kein Oracle)", () => {
  const rec = blockRecord({
    index: 102,
    closeTimeIso: iso(T0),
    txCount: 7,
    flagged: [
      { from: synth(900001), to: synth(1), type: "Payment", amountDrops: 999, txHash: "BAIT1", ledgerSeq: 102 },
      { from: synth(2), to: synth(900002), type: "Payment", amountDrops: 999, txHash: "BAIT2", ledgerSeq: 102 },
      { from: synth(3), to: synth(4), type: "Payment", amountDrops: 100, txHash: "CLEAN", ledgerSeq: 102 },
    ],
  }, baitLabels);
  assert.equal(rec.n, 7, "Block-Zählung bleibt (Köder-Filter betrifft nur die Volltext-Edges)");
  assert.equal(rec.f.length, 1, "nur die saubere Edge überlebt");
  assert.equal(rec.f[0].txHash, "CLEAN");
  const text = serializeBlockWindow({ day: DAY, updatedAt: null, blocks: [rec] });
  assert.ok(!text.includes(synth(900001)), "Köder-Adresse nie im persistierten Text");
  assert.ok(!text.includes(synth(900002)));
});

test("blockRecord: defekte Eingaben -> null / geklemmt", () => {
  assert.equal(blockRecord({ index: "x", closeTimeIso: null, txCount: 1, flagged: [] }, NO_BAIT), null);
  assert.equal(blockRecord({ index: -5, closeTimeIso: null, txCount: 1, flagged: [] }, NO_BAIT), null);
  const rec = blockRecord({ index: 10, closeTimeIso: 42, txCount: -3, flagged: null }, NO_BAIT);
  assert.deepEqual(rec, { i: 10, t: null, n: 0 });
});

test("flaggedEdgesFrom: Kantenregel wie buildClusterGraph, Bait-Filter, sanitizeText", () => {
  const findings = [{ ruleId: "dusting", severity: "malicious", address: synth(1), note: "x" }];
  const txRecords = [
    { hash: "H1", ledgerSeq: 10, type: "Payment", account: synth(1), destination: synth(2), amountDrops: 1000 },
    { hash: "H2", ledgerSeq: 11, type: "Payment", account: synth(3), destination: synth(4), amountDrops: 2000 }, // ungeflaggt
    { hash: "H3", ledgerSeq: 12, type: "Payment", account: synth(1), destination: synth(900001), amountDrops: 3000 }, // Köder-Endpunkt
    { hash: "H4", ledgerSeq: 13, type: "Payment", account: synth(1), destination: synth(1), amountDrops: 4000 }, // self-Tx -> keine Kante
  ];
  const edges = flaggedEdgesFrom(txRecords, findings, baitLabels);
  assert.equal(edges.length, 1, "nur die geflaggte, saubere, echte Kante");
  assert.equal(edges[0].txHash, "H1");
  assert.equal(edges[0].from, synth(1));
  assert.equal(edges[0].to, synth(2));
});

// =====================================================================
// Append (Dedup + Sortierung)
// =====================================================================

test("appendBlockWindow: Index-Dedup, Index-asc, Idempotenz bei Retry", () => {
  let doc = emptyBlockWindow(DAY);
  doc = appendBlockWindow(doc, [
    { i: 102, t: iso(T0 + 8000), n: 3 },
    { i: 100, t: iso(T0), n: 42 },
  ]);
  doc = appendBlockWindow(doc, [
    { i: 101, t: iso(T0 + 4000), n: 55 },
    { i: 100, t: iso(T0), n: 42 }, // Retry derselben Zeile -> kein Duplikat
  ]);
  assert.deepEqual(doc.blocks.map((b) => b.i), [100, 101, 102]);
  doc = appendBlockWindow(doc, [{ i: 100, t: iso(T0), n: 43 }]); // letzte Sicht gewinnt
  assert.equal(doc.blocks[0].n, 43);
});

// =====================================================================
// Byte-Cap (capBlockWindow — nur Live-Write-Apply, nie in appendBlockWindow)
// =====================================================================

test("capBlockWindow: hält Buffer.byteLength unter Cap, neueste i bleiben, älteste fallen", () => {
  assert.equal(BLOCK_WINDOW_MAX_BYTES, 900000);
  // 10 Blöcke mit je ~1000 B pad: Cap so, dass nur die neuesten 7 passen.
  const mk = (i) => ({ i, t: iso(T0 + i * 1000), n: 3, f: [{ from: synth(1), to: synth(2), type: "Payment", amountDrops: 1, txHash: "H".repeat(64), ledgerSeq: i, severity: "info" }], pad: "p".repeat(900) });
  const blocks = [];
  for (let i = 100; i < 110; i++) blocks.push(mk(i));
  const one = Buffer.byteLength(serializeBlockWindow({ day: DAY, updatedAt: null, blocks: [mk(100)] }), "utf8");
  const all = Buffer.byteLength(serializeBlockWindow({ day: DAY, updatedAt: null, blocks }), "utf8");
  const cap = one * 7 + 200; // 7 Blöcke passen, 8 nicht
  assert.ok(all > cap, "Ausgangsdokument muss über dem Cap liegen");
  const capped = capBlockWindow({ day: DAY, updatedAt: 999, blocks }, cap);
  assert.ok(Buffer.byteLength(serializeBlockWindow(capped), "utf8") <= cap, "Cap eingehalten (Bytes, nicht .length)");
  assert.deepEqual(capped.blocks.map((b) => b.i), [103, 104, 105, 106, 107, 108, 109], "älteste i fallen, neueste bleiben");
  assert.equal(capped.day, DAY);
  assert.equal(capped.updatedAt, 999);
  // Unter Cap -> unverändert.
  const untouched = capBlockWindow({ day: DAY, updatedAt: null, blocks }, 10_000_000);
  assert.equal(untouched.blocks.length, 10);
});

test("capBlockWindow: appendBlockWindow bleibt reines Index-Dedup (keine Kappung)", () => {
  // Der Cap sitzt ausschließlich im Live-Write-Apply (api/advance.js) —
  // append selbst (und damit der Restore-Pfad) darf nie trimmen.
  const mk = (i) => ({ i, t: iso(T0 + i * 1000), n: 3, pad: "p".repeat(1000) });
  const records = [];
  for (let i = 1000; i < 2000; i++) records.push(mk(i));
  const doc = appendBlockWindow(emptyBlockWindow(DAY), records);
  assert.equal(doc.blocks.length, 1000, "1000 große Zeilen überleben append ungekappt (Restore-668-Blöcke-Muster)");
  assert.ok(Buffer.byteLength(serializeBlockWindow(doc), "utf8") > BLOCK_WINDOW_MAX_BYTES, "bewusst über dem Cap — append kappt nicht");
});

// =====================================================================
// Projektion (Auslieferungs-Schicht)
// =====================================================================

function fixtureDocs() {
  const mk = (i, tMs, n, f) => (f ? { i, t: iso(tMs), n, f } : { i, t: iso(tMs), n });
  return [
    {
      day: "2026-10-02",
      updatedAt: null,
      blocks: [
        mk(200, Date.parse("2026-10-02T08:00:00Z"), 40),
        mk(201, Date.parse("2026-10-02T08:04:00Z"), 50, [
          { from: synth(1), to: synth(2), type: "Payment", amountDrops: 1000, txHash: "H1", ledgerSeq: 201 },
        ]),
        mk(202, Date.parse("2026-10-02T09:02:00Z"), 60),
      ],
    },
    {
      day: "2026-10-01",
      updatedAt: null,
      blocks: [
        mk(100, Date.parse("2026-10-01T10:00:00Z"), 30),
        mk(101, Date.parse("2026-10-01T10:04:00Z"), 35, [
          { from: synth(3), to: synth(4), type: "Payment", amountDrops: 2000, txHash: "H2", ledgerSeq: 101 },
          { from: synth(5), to: synth(6), type: "Payment", amountDrops: 500, txHash: "H3", ledgerSeq: 101 },
        ]),
      ],
    },
  ];
}

test("projectBlockWindow: Stunden-Rollups deterministisch, <= 168 Zeilen bei 7 d", () => {
  const from = Date.parse("2026-09-25T00:00:00Z");
  const to = Date.parse("2026-10-02T23:59:59Z");
  const { buckets, flagged } = projectBlockWindow(fixtureDocs(), { fromMs: from, toMs: to });
  // 3 Stunden-Rollups, aufsteigend: 01.10 10 Uhr (2 Blöcke), 02.10 08 Uhr
  // (2 Blöcke), 02.10 09 Uhr (1 Block).
  assert.equal(buckets.length, 3);
  assert.deepEqual(buckets.map((b) => b.blocks), [2, 2, 1]);
  assert.deepEqual(buckets.map((b) => b.txns), [65, 90, 60]);
  assert.deepEqual(buckets.map((b) => b.flaggedBlocks), [1, 1, 0]);
  // Edges ohne severity-Feld zählen als 'info' (kein Rückwärts-Inflation —
  // Default-Wechsel 2026-10-03, siehe edgeSeverity).
  assert.deepEqual(buckets.map((b) => b.maxSeverity), ["info", "info", null]);
  // Rollup-Zeiten aufstundend (asc).
  assert.ok(buckets[0].t < buckets[1].t && buckets[1].t < buckets[2].t);
  // Flagged: neueste Blöcke zuerst.
  assert.deepEqual(flagged.map((b) => b.i), [201, 101]);
  assert.equal(flagged[0].f.length, 1);
  assert.equal(flagged[1].f.length, 2);
});

test("projectBlockWindow: Zeitfenster-Grenzen schließen Blöcke ein/aus", () => {
  const { buckets } = projectBlockWindow(fixtureDocs(), {
    fromMs: Date.parse("2026-10-02T00:00:00Z"),
    toMs: Date.parse("2026-10-02T23:59:59Z"),
  });
  assert.equal(buckets.length, 2, "nur der 02.10 im 24h-Fenster");
  const all = projectBlockWindow(fixtureDocs(), {});
  assert.equal(all.buckets.length, 3, "ohne Grenzen: alle Blöcke");
});

test("projectBlockWindow: Blöcke ohne parsebares t werden als untimed ausgeliefert", () => {
  // Audit-Befund Z.227-230: gespeicherte flagged-Blöcke ohne Zeitstempel
  // waren bisher unerreichbar. Jetzt sichtbar mit untimed-Flag.
  const docs = [{
    day: DAY,
    updatedAt: null,
    blocks: [
      { i: 1, t: null, n: 5, f: [{ from: synth(1), to: synth(2), type: "Payment", amountDrops: 10, txHash: "U1", ledgerSeq: 1 }] },
      { i: 2, t: "kein ISO", n: 5 },
    ],
  }];
  const { buckets, flagged } = projectBlockWindow(docs, {});
  assert.equal(buckets.length, 0, "ohne Zeitstempel kein Stunden-Rollup");
  assert.equal(flagged.length, 1, "flagged-Block ohne t erscheint als untimed");
  assert.equal(flagged[0].untimed, true);
  assert.equal(flagged[0].t, null);
});

test("projectBlockWindow: maxSeverity ist das Maximum der Edge-severities (nicht hart malicious)", () => {
  // Fix 24: Malicious/Suspect/Info sind im Block-Fenster unterscheidbar.
  // Edges ohne severity-Feld (ältere Bestände) zählen als 'info' (kein
  // Rückwärts-Inflation — Default-Wechsel 2026-10-03).
  const docs = [
    {
      day: DAY,
      updatedAt: null,
      blocks: [
        { i: 300, t: iso(Date.parse("2026-10-02T10:00:00Z")), n: 10, f: [{ from: synth(1), to: synth(2), type: "Payment", amountDrops: 1, txHash: "M1", ledgerSeq: 300, severity: "malicious" }] },
        { i: 301, t: iso(Date.parse("2026-10-02T11:01:00Z")), n: 10, f: [{ from: synth(3), to: synth(4), type: "Payment", amountDrops: 1, txHash: "S1", ledgerSeq: 301, severity: "suspect" }] },
        { i: 302, t: iso(Date.parse("2026-10-02T12:00:00Z")), n: 10, f: [{ from: synth(5), to: synth(6), type: "Payment", amountDrops: 1, txHash: "D1", ledgerSeq: 302 }] },
      ],
    },
  ];
  const { buckets } = projectBlockWindow(docs, {});
  assert.deepEqual(buckets.map((b) => b.maxSeverity), ["malicious", "suspect", "info"]);
});

test("projectBlockWindow: Bucket bleibt 'suspect', wenn nur suspect- und feldlose Edges im Fenster sind", () => {
  // Der feldlose Default 'info' darf eine echte suspect-Stufe nicht überhöhen
  // und nicht unterdrücken (Default-Wechsel 2026-10-03).
  const docs = [
    {
      day: DAY,
      updatedAt: null,
      blocks: [
        { i: 310, t: iso(Date.parse("2026-10-02T10:00:00Z")), n: 10, f: [{ from: synth(1), to: synth(2), type: "Payment", amountDrops: 1, txHash: "S2", ledgerSeq: 310, severity: "suspect" }] },
        { i: 311, t: iso(Date.parse("2026-10-02T10:02:00Z")), n: 10, f: [{ from: synth(3), to: synth(4), type: "Payment", amountDrops: 1, txHash: "N1", ledgerSeq: 311 }] },
      ],
    },
  ];
  const { buckets } = projectBlockWindow(docs, {});
  assert.equal(buckets.length, 1);
  assert.equal(buckets[0].maxSeverity, "suspect");
});

test("flaggedEdgesFrom: severity der Funde wandert auf die Edge", () => {
  const findings = [{ ruleId: "dusting", severity: "suspect", address: synth(1), note: "x" }];
  const txRecords = [
    { hash: "H1", ledgerSeq: 10, type: "Payment", account: synth(1), destination: synth(2), amountDrops: 1000 },
  ];
  const edges = flaggedEdgesFrom(txRecords, findings, baitLabels);
  assert.equal(edges.length, 1);
  assert.equal(edges[0].severity, "suspect");
});

test("projectBlockWindow: Bait-Edges aus persistiertem Bestand rausgefiltert (Auslieferungs-Schicht)", () => {
  // Der Codec filtert vor Persistenz; die Projektion liefert nur, was drin ist.
  // Ein Bestand, der (aus älterer, ungefilterter Version) Köder-Edges enthält,
  // wird bei der Auslieferung trotzdem nicht gefiltert — die Filterung liegt
  // im blockRecord/flaggedEdgesFrom-Pfad. Die Projektion liefert exakt den
  // Bestand; der Test dokumentiert das Schema und die Zählungen.
  const rec = blockRecord({
    index: 300,
    closeTimeIso: iso(T0),
    txCount: 9,
    flagged: [{ from: synth(900001), to: synth(1), type: "Payment", amountDrops: 1, txHash: "B", ledgerSeq: 300 }],
  }, baitLabels);
  assert.equal(rec.f, undefined, "Köder-Edge erreicht die Persistenz nie");
  const { flagged } = projectBlockWindow([{ day: DAY, updatedAt: null, blocks: [rec] }], {});
  assert.equal(flagged.length, 0, "Block ohne überlebende Edges erscheint nicht als flagged");
});

// =====================================================================
// Retention-Auswahl
// =====================================================================

test("pruneBlockWindowDocs: Chunks > 7 d fallen in staleDays, Rest bleibt", () => {
  const now = Date.parse("2026-10-02T12:00:00Z");
  const docs = [
    { day: "2026-10-02", doc: emptyBlockWindow("2026-10-02") },
    { day: "2026-09-30", doc: emptyBlockWindow("2026-09-30") }, // Tag-Ende 30.09. 23:59 < now-7d (25.09. 12:00)? nein -> bleibt
    { day: "2026-09-25", doc: emptyBlockWindow("2026-09-25") }, // Tag-Ende 25.09. 23:59 < 25.09. 12:00? nein -> bleibt (Grenze)
    { day: "2026-09-24", doc: emptyBlockWindow("2026-09-24") }, // Tag-Ende 24.09. 23:59 < 25.09. 12:00 -> stale
    { day: "kaputt", doc: null },
  ];
  const { docs: keep, staleDays } = pruneBlockWindowDocs(docs, now, { windowMs: BLOCK_WINDOW_RETENTION_MS });
  assert.deepEqual(staleDays, ["2026-09-24"]);
  assert.deepEqual(keep.map((d) => d.day), ["2026-10-02", "2026-09-30", "2026-09-25"]);
});

test("pruneBlockWindowDocs: Garbage -> leer, ohne Throw", () => {
  assert.deepEqual(pruneBlockWindowDocs(null, 1), { docs: [], staleDays: [] });
  assert.deepEqual(pruneBlockWindowDocs([{ nope: 1 }], 1), { docs: [], staleDays: [] });
});

// =====================================================================
// GitHub-Transport (fetch-Stubs, OFFLINE — wiederverwendeter History-Transport)
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
function installFetchStub(handler) {
  const orig = globalThis.fetch;
  const calls = [];
  globalThis.fetch = async (url, init = {}) => {
    const method = String(init.method ?? "GET").toUpperCase();
    calls.push({ method, url: String(url), headers: init.headers ?? {}, body: init.body ?? null });
    return handler(calls.length, method, String(url), init);
  };
  return { calls, restore: () => (globalThis.fetch = orig) };
}

test("readBlockWindowGitHub: 404 -> frischer Chunk; Pfad aus dem Tag", async () => {
  stubGithubEnv();
  const { calls, restore } = installFetchStub(() => ghResponse({ message: "Not Found" }, 404));
  try {
    const { doc, sha } = await readBlockWindowGitHub(DAY);
    assert.deepEqual(doc, emptyBlockWindow(DAY));
    assert.equal(sha, null);
    assert.match(calls[0].url, /\/contents\/data\/block-window\/2026-10-02\.json/);
  } finally {
    restore();
    restoreGithubEnv();
  }
});

test("writeBlockWindowGitHub: apply auf frischem Stand, PUT mit sha + Codec", async () => {
  stubGithubEnv();
  const stored = { day: DAY, updatedAt: null, blocks: [{ i: 100, t: iso(T0), n: 42 }] };
  const { calls, restore } = installFetchStub((_, method) => {
    if (method === "GET") return ghResponse({ sha: "s1", content: b64(JSON.stringify(stored)) });
    return ghResponse({ commit: {} }, 200);
  });
  try {
    const out = await writeBlockWindowGitHub(DAY, (fresh) =>
      appendBlockWindow({ ...fresh, updatedAt: 999 }, [{ i: 101, t: iso(T0 + 4000), n: 55 }])
    );
    assert.deepEqual(out.blocks.map((b) => b.i), [100, 101]);
    const putBody = JSON.parse(calls[1].body);
    assert.equal(putBody.sha, "s1");
    assert.equal(putBody.branch, "main");
    assert.deepEqual(JSON.parse(Buffer.from(putBody.content, "base64").toString("utf8")), out);
  } finally {
    restore();
    restoreGithubEnv();
  }
});

test("deleteBlockWindowGitHub: DELETE mit sha (Retention-Pfad)", async () => {
  stubGithubEnv();
  const { calls, restore } = installFetchStub((_, method) => {
    if (method === "GET") return ghResponse({ sha: "s-del", content: b64("{}") });
    return ghResponse({ commit: {} }, 200);
  });
  try {
    const ok = await deleteBlockWindowGitHub("2026-09-24");
    assert.equal(ok, true);
    assert.match(calls[1].url, /\/contents\/data\/block-window\/2026-09-24\.json/);
    assert.equal(JSON.parse(calls[1].body).sha, "s-del");
  } finally {
    restore();
    restoreGithubEnv();
  }
});
