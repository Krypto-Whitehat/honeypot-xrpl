// node:test für die Request-Budget-/Backoff-Logik des Advance-Endpunkts
// (api/advance.js).
//
// NAMENSHINWEIS: "advance-batch" ist historisch — der Endpunkt lehnt
// JSON-RPC-Batches deterministisch ab (Befund 2026-10-01: "invalidParams"/31
// "batched requests are not supported"; NDJSON: "jsonInvalid"/31). Der Inhalt
// dieser Tests ist die BACKOFF-/BUDGET-LOGIK: dass der Backoff das genannte
// Retry-Fenster (retry_after / "retry in ~Nms" / HTTP retry-after-Header)
// korrekt parst und die korrekte Dauer respektiert, und dass das
// Request-Budget die honeycluster-Raten (10 req/s steady, Burst 50/5 s)
// respektiert. FIXTURE-basiert, deterministisch, KEIN Netzwerk.
//
// UMSTELLUNG 2026-10-02 (honeycluster.io): Das xrplcluster-Units-Modell
// (COMMAND_COST_CEILING/TICK_UNIT_BUDGET/maxBudgetForQuota, Budget 1 Block/
// Tick) ist ERSETZT durch Request-Zählung (1 Request/Block dank expand:true).
// Die Backoff- und seedCursor-Tests bleiben unverändert — diese Funktionen
// bleiben. Die Units-Asserts sind durch Request-Budget-Assertions mit
// echten Grenzen ersetzt (kein Test gelöscht ohne Assertions-Äquivalent).

import test from "node:test";
import assert from "node:assert/strict";

// ---------- ENV vor dem Import (Handler-Tests 2026-10-03) ----------
// baitLabels wird in api/advance.js UND lib/threats-service.mjs beim
// Modulstart geparst — ENV muss VOR dem ersten Import stehen. Der Import
// wird dafür von statisch auf dynamisch umgestellt (alle Bindungen bleiben).
// Synthetische Köder-Adresse (base58-sicher); GITHUB_HISTORY_TOKEN ist nur
// Test-Dekoration — alle GitHub-Calls laufen gegen den fetch-Stub unten.
const ADV_BAIT = `rTESTADVB4Y${"A".repeat(23)}9`;
process.env.BAIT_ADDRESSES = ADV_BAIT;
process.env.GITHUB_HISTORY_TOKEN = "test-token";

const adv = await import("../api/advance.js");
const {
  parseRetryWindowMs,
  backoffDelayMs,
  worstCaseTickRequests,
  seedCursor,
  REQUESTS_PER_SEC,
  TICK_REQUEST_BUDGET,
  FETCH_PARALLEL,
  DEFAULT_BUDGET,
} = adv;

// ---------- parseRetryWindowMs ----------

test("parseRetryWindowMs: retry_after-Feld (Sekunden) -> ms", () => {
  assert.equal(parseRetryWindowMs({ error: "tooBusy", retry_after: 144.662 }), 144662);
  assert.equal(parseRetryWindowMs({ error: "slowDown", retry_after: 30 }), 30000);
});

// Live-beobachtete Message-Form (lib/live-gate.mjs:18-22): Fenster nur in
// error_message genannt.
test("parseRetryWindowMs: 'retry in ~Nms' aus error_message", () => {
  const result = {
    error: "tooBusy",
    error_message: "rate limit: units quota (500000 per 3600s) exhausted, retry in ~144662ms",
  };
  assert.equal(parseRetryWindowMs(result), 144662);
});

test("parseRetryWindowMs: Präzedenz — Feld vor Message", () => {
  const result = {
    error: "tooBusy",
    retry_after: 5,
    error_message: "retry in ~99999ms",
  };
  assert.equal(parseRetryWindowMs(result), 5000, "retry_after-Feld gewinnt");
});

test("parseRetryWindowMs: ungültiges Feld fällt auf Message zurück", () => {
  const result = {
    error: "tooBusy",
    retry_after: "unparseable",
    error_message: "retry in ~12345ms",
  };
  assert.equal(parseRetryWindowMs(result), 12345);
});

test("parseRetryWindowMs: kein genanntes Fenster -> null", () => {
  assert.equal(parseRetryWindowMs({ error: "slowDown" }), null);
  assert.equal(parseRetryWindowMs({ error: "tooBusy", error_message: "rate limit: units quota (10000 per 60s)" }), null);
  assert.equal(parseRetryWindowMs({ error: "tooBusy", retry_after: 0 }), null);
  assert.equal(parseRetryWindowMs({ error: "tooBusy", retry_after: -5 }), null);
  assert.equal(parseRetryWindowMs(null), null);
  assert.equal(parseRetryWindowMs(undefined), null);
  assert.equal(parseRetryWindowMs("tooBusy"), null);
});

// ---------- backoffDelayMs ----------

test("backoffDelayMs: genanntes Fenster wird voll ausgesetzt (+Slack)", () => {
  assert.equal(backoffDelayMs(0, 144662), 146662);
  assert.equal(backoffDelayMs(2, 30000), 32000);
});

test("backoffDelayMs: ohne genanntes Fenster exponentiell mit Kappe", () => {
  assert.equal(backoffDelayMs(0, null), 2000);
  assert.equal(backoffDelayMs(1, null), 4000);
  assert.equal(backoffDelayMs(2, null), 8000);
  assert.equal(backoffDelayMs(3, null), 16000);
  assert.equal(backoffDelayMs(4, null), 30000, "Kappe greift");
  assert.equal(backoffDelayMs(5, null), 30000, "Kappe bleibt");
});

test("backoffDelayMs: nicht-positives 'Fenster' fällt in den exponentiellen Pfad", () => {
  assert.equal(backoffDelayMs(0, 0), 2000);
  assert.equal(backoffDelayMs(0, NaN), 2000);
  assert.equal(backoffDelayMs(0, -1), 2000);
  assert.equal(backoffDelayMs(-3, null), 2000, "negativer Versuch wird geklemmt");
});

// 429-Backoff (B4): der retry-after-Header eines HTTP 429 durchläuft
// dieselbe Kette parseRetryAfterMs -> backoffDelayMs (api/advance.js rpc()).
// Die Header-Parade wird gegen die echte parseRetryAfterMs aus lib/rate-gate
// geprüft, die Ketten-Semantik gegen backoffDelayMs.
test("429-Backoff: retry-after-Fenster -> volles Aussetzen (+Slack)", async () => {
  const { parseRetryAfterMs } = await import("./rate-gate.mjs");
  assert.equal(parseRetryAfterMs("30"), 30000);
  assert.equal(backoffDelayMs(0, parseRetryAfterMs("30")), 32000);
  assert.equal(backoffDelayMs(1, parseRetryAfterMs(2.5)), 4500);
  // Ohne Header -> exponentieller Pfad (HTTP-5xx ohne Fenster).
  assert.equal(parseRetryAfterMs(null), null);
  assert.equal(backoffDelayMs(0, parseRetryAfterMs(null)), 2000);
});

// ---------- worstCaseTickRequests (Request-Budget) ----------

test("worstCaseTickRequests: 1 Request pro Block (expand:true, kein tx-Kommando)", () => {
  assert.equal(worstCaseTickRequests(100), 100);
  assert.equal(worstCaseTickRequests(1), 1);
  assert.equal(worstCaseTickRequests(0), 0);
});

test("worstCaseTickRequests: Garbage-Inputs -> 0", () => {
  assert.equal(worstCaseTickRequests("x"), 0);
  assert.equal(worstCaseTickRequests(undefined), 0);
  assert.equal(worstCaseTickRequests(null), 0);
  assert.equal(worstCaseTickRequests(NaN), 0);
  assert.equal(worstCaseTickRequests(-2), 0);
  assert.equal(worstCaseTickRequests(2.9), 2, "Budget wird gefloort");
});

// ---------- Budget-Invarianten (honeycluster-Raten) ----------

test("DEFAULT_BUDGET = 100 und respektiert das Tick-Request-Budget", () => {
  assert.equal(DEFAULT_BUDGET, 100);
  assert.equal(REQUESTS_PER_SEC, 10, "honeycluster steady-Limit");
  assert.ok(
    worstCaseTickRequests(DEFAULT_BUDGET) <= TICK_REQUEST_BUDGET,
    "Worst-Case-Tick des Defaults bleibt im Request-Budget"
  );
  assert.ok(TICK_REQUEST_BUDGET <= 25 * REQUESTS_PER_SEC, "Budget passt in 25 s nutzbare Tick-Zeit");
});

test("FETCH_PARALLEL hält die Fetch-Rate unter dem steady-Limit", () => {
  // Gemessene expand:true-Latenz Ø ~0,708 s (live-Probe 2026-10-02):
  // 4 parallel -> 4/0,708 ≈ 5,66 req/s < 10 req/s steady.
  const measuredLatencyMs = 708;
  const rate = (FETCH_PARALLEL * 1000) / measuredLatencyMs;
  assert.ok(rate < REQUESTS_PER_SEC, `Fetch-Rate ${rate.toFixed(2)} req/s muss unter ${REQUESTS_PER_SEC} bleiben`);
  assert.ok(FETCH_PARALLEL >= 1 && FETCH_PARALLEL <= 8, "Parallelität im vernünftigen Rahmen");
});

// Invariante über alle tolerierten Budgets: jedes Budget bis zum ENV-Default
// respektiert das Request-Budget; das Budget über der Budget-Grenze verletzt
// es (äquivalent zur alten Quota-Respekt-Eigenschaft, jetzt in Requests).
test("Request-Budget-Respekt-Eigenschaft", () => {
  for (let b = 0; b <= DEFAULT_BUDGET; b++) {
    assert.ok(
      worstCaseTickRequests(b) <= TICK_REQUEST_BUDGET,
      `Budget ${b} muss das Request-Budget respektieren`
    );
  }
  const overBudget = TICK_REQUEST_BUDGET + 1;
  assert.ok(
    worstCaseTickRequests(overBudget) > TICK_REQUEST_BUDGET,
    `Budget ${overBudget} verletzt das Request-Budget`
  );
});

// ---------- seedCursor (Cursor-Seeding) ----------

// Der Walk startet NICHT bei Genesis (Index 0) — der öffentliche Validator
// liefert alte Blöcke nicht mehr. seedCursor setzt einen frischen Cursor auf
// den rezenten Vergangenheit: validatedIndex minus Lookback, begrenzt auf
// >= 1. Ungültiger validatedIndex -> null (kein Seed).
test("seedCursor: Live-Edge (Lookback 0) -> validatedIndex", () => {
  assert.equal(seedCursor(107000000, 0), 107000000);
  assert.equal(seedCursor(107000000, null), 107000000, "Lookback null -> 0");
  assert.equal(seedCursor(107000000, "x"), 107000000, "Garbage-Lookback -> 0");
  assert.equal(seedCursor(107000000, -5), 107000000, "negativer Lookback -> 0");
});

test("seedCursor: Lookback-Subtraktion (rezenter Vergangenheit)", () => {
  assert.equal(seedCursor(107000000, 500), 106999500, "kleiner Lookback");
  assert.equal(seedCursor(107000000, 259200), 106740800, "~1 Monat Lookback");
  assert.equal(seedCursor(10.9, 0), 10, "validatedIndex wird gefloort");
});

test("seedCursor: Lookback > validatedIndex wird auf >= 1 geklemmt", () => {
  assert.equal(seedCursor(10, 100), 1, "klemmt auf 1");
  assert.equal(seedCursor(1, 1), 1, "Gleichstand -> 1");
  assert.equal(seedCursor(5, 5), 1, "Gleichstand -> 1");
});

test("seedCursor: ungültiger validatedIndex -> null (kein Seed)", () => {
  assert.equal(seedCursor(null, 0), null);
  assert.equal(seedCursor(undefined, 0), null);
  assert.equal(seedCursor("x", 0), null);
  assert.equal(seedCursor(NaN, 0), null);
  assert.equal(seedCursor(0, 0), null, "Index 0 -> null");
  assert.equal(seedCursor(-5, 0), null, "negativer Index -> null");
});

// ============================================================================
// Handler-Tests (Persistenz-Hälfte 2026-10-03): Budget-Bilanz über alle
// honeycluster-Layer, Replay-POST-Auslöser, Entity-Layer (Deadline-Guard +
// Snapshot-Dedup), Fail-closed ohne Token. Kein Live-Netzwerk: rpc über
// setRpcForTests, GitHub-Contents über fetch-Stub, Uhr über setClockForTests.
// ============================================================================

const {
  ENTITY_TICK_CAP,
  REPLAY_TICK_CAP,
  REPLAY_JOBS_FILE_PATH,
  mergeReplayJob,
  setRpcForTests,
  setClockForTests,
  maxDuration,
} = adv;

// ---------- GitHub-Stub (fetch-Ersatz für die Contents-API) ----------
// In-Memory-Dateisystem: GET -> 200 mit Inhalt (oder 404 Anlege-Fall),
// PUT -> 201 (Inhalt wird gespeichert — (viii) liest, was der POST-Auslöser
// in (0) schrieb), DELETE -> 204.
const ghFiles = new Map(); // path -> { sha, content }
let ghLog = []; // { method, path }
const realFetch = globalThis.fetch;
globalThis.fetch = async (url, opts) => {
  const method = opts?.method ?? "GET";
  const u = new URL(String(url));
  // Repo-Pfad enthält selbst Slashes (owner/name) — der Datei-Pfad ist alles
  // nach dem letzten /contents/.
  const m = u.pathname.match(/\/contents\/(.+)$/);
  const p = m ? decodeURIComponent(m[1]) : u.pathname;
  ghLog.push({ method, path: p });
  if (method === "GET") {
    const f = ghFiles.get(p);
    if (!f) return { ok: true, status: 404, json: async () => ({}) };
    return { ok: true, status: 200, json: async () => ({ sha: f.sha, content: f.content }) };
  }
  if (method === "PUT") {
    const body = JSON.parse(opts.body);
    ghFiles.set(p, { sha: `sha-${ghFiles.size + 1}`, content: body.content });
    return { ok: true, status: 201, json: async () => ({}) };
  }
  if (method === "DELETE") {
    ghFiles.delete(p);
    return { ok: true, status: 204, json: async () => ({}) };
  }
  return { ok: false, status: 400, json: async () => ({}) };
};
test.after(() => {
  globalThis.fetch = realFetch;
});

const decodeGh = (path) => {
  const f = ghFiles.get(path);
  return f ? JSON.parse(Buffer.from(f.content, "base64").toString("utf8")) : null;
};
const putsTo = (path) => ghLog.filter((c) => c.method === "PUT" && c.path === path);

// threats-service teilt sich den fetch-Stub; sein RPC-Transport (für
// getPublicThreats im buildCtx) wird auf leere Historie gestellt.
const svcMod = await import("./threats-service.mjs");
svcMod.setRpc(async () => ({ transactions: [] }));

// ---------- Synthetische Adressen (base58-sicher, pro Test eindeutig) ----------
// Kein I/O/0/l (XRPL_ADDR-Alphabet [1-9A-HJ-NP-Za-km-z]).
const REPLAY_ADDR = `rTESTREPLAY${"A".repeat(23)}8`;
const ENT_TA = `rTESTENT${"A".repeat(26)}8`;
const ENT_TB = `rTESTENT${"B".repeat(26)}9`;
const ENT_TC = `rTESTENT${"C".repeat(26)}7`;

// Flow-State-Fixture: Cursor fortgeschritten (kein Seeding), ein Cluster mit
// Betrugsnachweis (mainDrainers -> hasFraudEvidence -> Archivierung) und
// Entity-Zielen als Mitglieder.
function seededFlowStateDoc(members) {
  const nowMs = Date.now();
  return {
    cursor: 1000,
    updatedAt: nowMs,
    state: {
      clusters: {
        "cluster-test-1": {
          clusterId: "cluster-test-1",
          memberAddresses: members,
          mainDrainers: [{ address: members[0], outDrops: 5000 }],
          firstSeen: new Date(nowMs).toISOString(),
          lastSeen: new Date(nowMs).toISOString(),
          edges: [],
          rolesByAddress: {},
        },
      },
    },
  };
}

// RPC-Fixture: leerer Live-Edge-Walk (1001..1005 leer, 1006 lgrNotFound),
// account_info mit Domain-Snapshot, account_tx ohne Marker (Job erreicht to).
// gapAt (Lücken-Fall, Fix 2026-10-04): der genannte Index wirft lgrNotFound,
// die Indizes danach liefern weiterhin Blöcke — genau die Form einer Lücke in
// der Parallel-Runde (ledger-walk bricht am null, nachfolgende Blöcke sind
// aber schon geholt).
function makeRpcFixture({ accountInfoLedger = 1005, gapAt = null } = {}) {
  const calls = { ledger: [], account_info: [], account_tx: [] };
  const rpcFixture = async (method, params) => {
    calls[method]?.push(params);
    if (method === "ledger") {
      const idx = params?.ledger_index;
      if (idx === "validated") return { ledger_index: 1005 };
      if (gapAt != null && idx === gapAt) throw new Error("RPC error: lgrNotFound");
      if (typeof idx === "number" && idx >= 1001 && idx <= 1005) {
        return {
          ledger: {
            ledger_index: idx,
            close_time_iso: new Date().toISOString(),
            transactions: [],
          },
        };
      }
      throw new Error("RPC error: lgrNotFound");
    }
    if (method === "account_info") {
      return {
        account_data: {
          Account: params.account,
          Sequence: 3,
          Balance: "1000000",
          Domain: "6578616D706C652E636F6D", // hex("example.com")
        },
        ledger_index: accountInfoLedger,
      };
    }
    if (method === "account_tx") return { transactions: [] };
    throw new Error(`Fixture: unbekanntes Kommando ${method}`);
  };
  return { rpcFixture, calls };
}

function makeRes() {
  return {
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
    json(obj) {
      this.body = obj;
      return this;
    },
  };
}

function resetHandlerState() {
  ghFiles.clear();
  ghLog = [];
  setClockForTests(null); // Default-Uhr/Sleep wiederherstellen
  svcMod.resetCachesForTests();
}

// ---------- (a) Budget-Bilanz über alle honeycluster-Layer ----------
test("Budget-Bilanz: Walk + Replay-Cap + Entity-Cap + Seed-Call <= TICK_REQUEST_BUDGET", () => {
  assert.equal(ENTITY_TICK_CAP, 20, "Entity-Layer-Cap 20 (Grenze 3)");
  assert.equal(REPLAY_TICK_CAP, 40, "Replay-Cap 40 (Grenze 2)");
  const walk = worstCaseTickRequests(DEFAULT_BUDGET); // 100 Requests (expand:true)
  const seedCall = 1; // seedCursorIfFresh: EIN Call, NUR bei frischem Cursor
  const total = walk + REPLAY_TICK_CAP + ENTITY_TICK_CAP + seedCall;
  assert.ok(
    total <= TICK_REQUEST_BUDGET,
    `Worst-Case ${total} (Walk ${walk} + Replay ${REPLAY_TICK_CAP} + Entity ${ENTITY_TICK_CAP} + Seed ${seedCall}) muss <= ${TICK_REQUEST_BUDGET} bleiben`
  );
  // GitHub-Retention-Calls (Block-Fenster/Archiv-Löschung, Replay-Job-Read)
  // laufen gegen die GitHub-Contents-API und gehören NICHT ins honeycluster-
  // Budget — dokumentierte Ausnahme (api/advance.js Header-Kommentar).
});

// ---------- (b) Replay-POST-Auslöser ----------
test("Replay-POST schreibt Job in data/replay-jobs.json und der Tick arbeitet ihn ab", async () => {
  resetHandlerState();
  ghFiles.set("data/flow-state.json", {
    sha: "s1",
    content: Buffer.from(JSON.stringify(seededFlowStateDoc([ENT_TC]))).toString("base64"),
  });
  const { rpcFixture, calls } = makeRpcFixture();
  setRpcForTests(rpcFixture);
  const res = makeRes();
  await adv.default(
    { body: { mode: "replay", address: REPLAY_ADDR, from: 1000, to: 1200 } },
    res
  );
  assert.equal(res.statusCode, 200, `Antwort: ${JSON.stringify(res.body)}`);
  // Job wurde persistiert (POST-Auslöser) und im Tick abgearbeitet:
  const jobsDoc = decodeGh(REPLAY_JOBS_FILE_PATH);
  assert.ok(jobsDoc?.jobs?.length === 1, `Job persistiert: ${JSON.stringify(jobsDoc)}`);
  const job = jobsDoc.jobs[0];
  assert.equal(job.address, REPLAY_ADDR);
  assert.equal(job.fromLedger, 1000);
  assert.equal(job.toLedger, 1200);
  assert.equal(job.status, "done", "Fenster in einem Tick erreicht (maxLedger >= to, kein marker) -> done");
  assert.equal(job.marker, null, "Marker nach Abschluss entfernt");
  assert.equal(calls.account_tx.length, 1, "genau ein account_tx pro Tick-Fenster");
  // Der Live-Walk bleibt unverändert: Cursor aus dem Dokument, kein Seeding.
  assert.equal(calls.ledger.find((p) => p.ledger_index === "validated"), undefined, "fortgeschrittener Cursor -> kein Seed-Call");
  assert.ok(res.body.cursor >= 1005, `Cursor gerückt: ${res.body.cursor}`);
  assert.ok(String(res.body.summary).includes("Replay-Jobs: 1"), `Summary: ${res.body.summary}`);
});

test("Replay-Auslöser: Köder-Adresse und ungültiges Fenster werden abgelehnt (400, ohne Persistenz)", async () => {
  resetHandlerState();
  setRpcForTests(makeRpcFixture().rpcFixture);
  const resBait = makeRes();
  await adv.default({ body: { mode: "replay", address: ADV_BAIT, from: 1, to: 2 } }, resBait);
  assert.equal(resBait.statusCode, 400, "Köder-Adresse -> generisch 400 (kein Oracle)");
  assert.equal(putsTo(REPLAY_JOBS_FILE_PATH).length, 0, "kein Job-Write bei abgelehntem Auslöser");
  const resWindow = makeRes();
  await adv.default({ body: { mode: "replay", address: REPLAY_ADDR, from: 500, to: 400 } }, resWindow);
  assert.equal(resWindow.statusCode, 400, "from > to -> 400");
  assert.equal(putsTo(REPLAY_JOBS_FILE_PATH).length, 0, "kein Job-Write bei ungültigem Fenster");
});

test("Ohne Body bleibt der Live-Walk unverändert (kein Replay-Job-Write)", async () => {
  resetHandlerState();
  ghFiles.set("data/flow-state.json", {
    sha: "s1",
    content: Buffer.from(JSON.stringify(seededFlowStateDoc([ENT_TC]))).toString("base64"),
  });
  setRpcForTests(makeRpcFixture().rpcFixture);
  const res = makeRes();
  await adv.default({}, res);
  assert.equal(res.statusCode, 200, `Antwort: ${JSON.stringify(res.body)}`);
  assert.equal(putsTo(REPLAY_JOBS_FILE_PATH).length, 0, "Cron-Tick ohne Body schreibt keine Jobs");
  assert.ok(String(res.body.summary).includes("Replay-Jobs: 0"), `Summary: ${res.body.summary}`);
});

// ---------- (c) Entity-Layer: Deadline-Guard ----------
test("Entity-Layer: Deadline (maxDuration - Guard) bricht ab und persistiert Partial", async () => {
  resetHandlerState();
  ghFiles.set("data/flow-state.json", {
    sha: "s1",
    content: Buffer.from(JSON.stringify(seededFlowStateDoc([ENT_TA, ENT_TB]))).toString("base64"),
  });
  const { rpcFixture, calls } = makeRpcFixture();
  setRpcForTests(rpcFixture);
  // Injizierte Uhr: tickDeadline = t0 + 30000 - 5000 = t0 + 25000; die Uhr
  // springt nach dem Walk über die Deadline -> Entity-Layer muss abbrechen,
  // bevor Requests über die nutzbare Zeit hinaus feuern.
  const t0 = Date.now();
  let clockCalls = 0;
  setClockForTests({
    now: () => (clockCalls++ === 0 ? t0 : t0 + 30_000),
    sleep: async () => {},
  });
  const res = makeRes();
  await adv.default({}, res);
  setClockForTests(null);
  assert.equal(res.statusCode, 200, `Antwort: ${JSON.stringify(res.body)}`);
  assert.equal(calls.account_info.length, 0, "Deadline erreicht -> kein account_info-Request");
  assert.equal(putsTo("data/entity-links.json").length, 0, "kein Entity-Write ohne Snapshots");
  assert.ok(String(res.body.summary).includes("Entity-Snapshots: 0"), `Summary: ${res.body.summary}`);
  // Die nutzbare Zeit ist maxDuration (30 s) minus Guard-Marge — dokumentierte Grenze.
  assert.equal(maxDuration, 30);
});

// ---------- (d) Fail-closed ohne Token ----------
test("Ohne GITHUB_HISTORY_TOKEN: 503, kein RPC-Call, kein GitHub-Call", async () => {
  resetHandlerState();
  const { rpcFixture, calls } = makeRpcFixture();
  setRpcForTests(rpcFixture);
  delete process.env.GITHUB_HISTORY_TOKEN;
  try {
    const res = makeRes();
    await adv.default({}, res);
    assert.equal(res.statusCode, 503, "Persistenz ohne Token -> 503");
    assert.equal(calls.ledger.length + calls.account_info.length + calls.account_tx.length, 0, "kein honeycluster-Request");
    assert.equal(ghLog.length, 0, "kein GitHub-Call");
  } finally {
    process.env.GITHUB_HISTORY_TOKEN = "test-token";
  }
});

// ---------- (e) Snapshot-Dedup (TTL) ----------
test("Entity-Layer: frischer persistierter Snapshot verbraucht keinen Request (TTL-Dedup)", async () => {
  resetHandlerState();
  ghFiles.set("data/flow-state.json", {
    sha: "s1",
    content: Buffer.from(JSON.stringify(seededFlowStateDoc([ENT_TA, ENT_TB]))).toString("base64"),
  });
  // ENT_TA hat einen frischen Snapshot (snapshotAt ~ jetzt < 24 h TTL) —
  // nur ENT_TB darf abgefragt werden.
  ghFiles.set("data/entity-links.json", {
    sha: "s2",
    content: Buffer.from(
      JSON.stringify({
        updatedAt: Date.now(),
        addresses: {
          [ENT_TA]: {
            regularKey: null,
            domain: "example.com",
            domainVerified: false,
            emailHash: null,
            sequence: 3,
            flags: null,
            signers: [],
            signersFingerprint: null,
            snapshotLedger: 1000,
            snapshotAt: Date.now(),
          },
        },
      })
    ).toString("base64"),
  });
  const { rpcFixture, calls } = makeRpcFixture();
  setRpcForTests(rpcFixture);
  const res = makeRes();
  await adv.default({}, res);
  assert.equal(res.statusCode, 200, `Antwort: ${JSON.stringify(res.body)}`);
  assert.equal(calls.account_info.length, 1, `nur der Adressen ohne frischen Snapshot wird abgefragt, erhalten ${calls.account_info.length}`);
  assert.equal(calls.account_info[0].account, ENT_TB);
  assert.equal(calls.account_info[0].ledger_index, "validated", "account_info gegen validated, nicht -1");
  // Der neue Snapshot wird persistiert (Merge: frischer Bestand bleibt erhalten).
  const entityDoc = decodeGh("data/entity-links.json");
  assert.ok(entityDoc?.addresses?.[ENT_TB], "ENT_TB-Snapshot persistiert");
  assert.ok(entityDoc?.addresses?.[ENT_TA], "bestehender ENT_TA-Snapshot bleibt im Merge erhalten");
  assert.ok(String(res.body.summary).includes("Entity-Snapshots: 1"), `Summary: ${res.body.summary}`);
});

// ---------- (f) Lücke in der Parallel-Runde (Fix 2026-10-04) ----------
// 1003 antwortet lgrNotFound (Lücke), 1004 liefert einen Block — die
// Parallel-Runde (FETCH_PARALLEL 4) holt 1001..1004 gleichzeitig: der Walk
// muss bei 1002 stehen bleiben, und das Block-Fenster darf die Zeile 1004
// nicht enthalten (live-Befund: Fensterzeile 107403037 gegen Cursor
// 107403034 — Zeilen für Blöcke nach der Lücke wurden mitgeschrieben).
test("Lücke in der Parallel-Runde: Cursor stoppt an der Lücke, kein Fenster-Index > Cursor", async () => {
  resetHandlerState();
  ghFiles.set("data/flow-state.json", {
    sha: "s1",
    content: Buffer.from(JSON.stringify(seededFlowStateDoc([ENT_TC]))).toString("base64"),
  });
  const { rpcFixture } = makeRpcFixture({ gapAt: 1003 });
  setRpcForTests(rpcFixture);
  const res = makeRes();
  await adv.default({}, res);
  assert.equal(res.statusCode, 200, `Antwort: ${JSON.stringify(res.body)}`);
  const flowDoc = decodeGh("data/flow-state.json");
  assert.equal(flowDoc?.cursor, 1002, "Cursor stoppt an der Lücke (1003 lgrNotFound)");
  const day = new Date().toISOString().slice(0, 10);
  const windowDoc = decodeGh(`data/block-window/${day}.json`);
  assert.ok(windowDoc, "Block-Fenster wurde geschrieben");
  const indices = (windowDoc.blocks ?? []).map((b) => b.i);
  assert.ok(indices.length > 0, "Fenster-Zeilen für 1001/1002 existieren");
  assert.ok(indices.every((i) => i <= 1002), `kein Fenster-Index > Cursor 1002: ${indices.join(",")}`);
});

// ---------- (g) Seed-Guard-Matrix (Wisch-Zyklus-Sperre, api/advance.js (i.1)) ----------
// cursor-0-Dokument MIT Fortschritt -> 502 ohne Write und ohne Seed-RPC.
// 404 und cursor-0-LEERDokument (Init-Fall) -> Seeding erlaubt.
function cursorZeroDoc({ clusters = false, bpt = 0 } = {}) {
  const nowMs = Date.now();
  return {
    cursor: 0,
    updatedAt: nowMs,
    state: {
      clusters: clusters
        ? {
            "cluster-zero-1": {
              clusterId: "cluster-zero-1",
              memberAddresses: [ENT_TC],
              mainDrainers: [{ address: ENT_TC, outDrops: 100 }],
              firstSeen: new Date(nowMs).toISOString(),
              lastSeen: new Date(nowMs).toISOString(),
              edges: [],
            },
          }
        : {},
      blocksProcessedTotal: bpt,
    },
  };
}

test("Seed-Guard: 404-Bestand -> Seeding erlaubt (validated-Seed, Tick 200)", async () => {
  resetHandlerState();
  const { rpcFixture, calls } = makeRpcFixture();
  setRpcForTests(rpcFixture);
  const res = makeRes();
  await adv.default({}, res);
  assert.equal(res.statusCode, 200, `Antwort: ${JSON.stringify(res.body)}`);
  assert.ok(calls.ledger.some((p) => p.ledger_index === "validated"), "404 -> Seed-Call gegen validated");
  assert.ok(res.body.cursor >= 1005, `Cursor geseedet und gerückt: ${res.body.cursor}`);
});

test("Seed-Guard: cursor-0-Dokument MIT Clustern -> 502, kein Write, kein Seed-RPC", async () => {
  resetHandlerState();
  ghFiles.set("data/flow-state.json", {
    sha: "s-guard",
    content: Buffer.from(JSON.stringify(cursorZeroDoc({ clusters: true }))).toString("base64"),
  });
  const { rpcFixture, calls } = makeRpcFixture();
  setRpcForTests(rpcFixture);
  const res = makeRes();
  await adv.default({}, res);
  assert.equal(res.statusCode, 502, "Guard antwortet 502 (Cron-Read akzeptiert nur 200/503 -> Run wird rot)");
  assert.match(res.body.error, /Seeding verweigert/);
  assert.equal(putsTo("data/flow-state.json").length, 0, "kein Write über den Bestand hinweg");
  assert.equal(ghLog.filter((c) => c.method === "PUT" && c.path.startsWith("data/block-window/")).length, 0, "kein Fenster-Write");
  assert.equal(calls.ledger.find((p) => p.ledger_index === "validated"), undefined, "Guard vor seedCursorIfFresh -> kein Seed-RPC");
  assert.equal(calls.ledger.length, 0, "Guard vor dem Walk -> kein einziger ledger-Request");
});

test("Seed-Guard: cursor-0-Dokument MIT blocksProcessedTotal (ohne Cluster) -> 502", async () => {
  resetHandlerState();
  ghFiles.set("data/flow-state.json", {
    sha: "s-guard2",
    content: Buffer.from(JSON.stringify(cursorZeroDoc({ clusters: false, bpt: 47 }))).toString("base64"),
  });
  setRpcForTests(makeRpcFixture().rpcFixture);
  const res = makeRes();
  await adv.default({}, res);
  assert.equal(res.statusCode, 502, "Fortschritt auch ohne Cluster (bpt > 0) sperrt das Seeding");
  assert.match(res.body.error, /Seeding verweigert/);
  assert.equal(putsTo("data/flow-state.json").length, 0);
});

test("Seed-Guard: cursor-0-Leerdokument MIT sha (Init-Fall, 0-Byte nicht unterscheidbar) -> Seeding erlaubt", async () => {
  resetHandlerState();
  ghFiles.set("data/flow-state.json", {
    sha: "s-init",
    content: Buffer.from(JSON.stringify(cursorZeroDoc({ clusters: false, bpt: 0 }))).toString("base64"),
  });
  const { rpcFixture, calls } = makeRpcFixture();
  setRpcForTests(rpcFixture);
  const res = makeRes();
  await adv.default({}, res);
  assert.equal(res.statusCode, 200, `fortschrittsloses Dokument darf seeden (datensicher): ${JSON.stringify(res.body)}`);
  assert.ok(calls.ledger.some((p) => p.ledger_index === "validated"), "Init-Seed gegen validated");
  assert.ok(res.body.cursor >= 1005, `Cursor geseedet: ${res.body.cursor}`);
});

// ---------- (h) Byte-Cap im Live-Write (Block-Fenster) ----------
test("Block-Fenster-Write: capBlockWindow greift im Apply (Chunks bleiben unter Cap)", async () => {
  resetHandlerState();
  ghFiles.set("data/flow-state.json", {
    sha: "s1",
    content: Buffer.from(JSON.stringify(seededFlowStateDoc([ENT_TC]))).toString("base64"),
  });
  // Vorbelastung: der Tages-Chunk startet bereits über dem Cap (800 Zeilen
  // à ~1.2 kB), der Tick muss ihn nach dem Append unter
  // BLOCK_WINDOW_MAX_BYTES halten. close_time_iso der Fixture-Blöcke ist
  // JETZT — die Fensterzeilen landen im heutigen Chunk.
  const day = new Date().toISOString().slice(0, 10);
  const fat = [];
  // Indizes bewusst UNTER den Walk-Indizes (1001..1005): der Cap entfernt
  // die kleinsten i — die neuen Zeilen müssen überleben.
  for (let i = 100; i < 900; i++) {
    fat.push({ i, t: new Date().toISOString(), n: 3, pad: "p".repeat(1100) });
  }
  ghFiles.set(`data/block-window/${day}.json`, {
    sha: "s-win",
    content: Buffer.from(JSON.stringify({ day, updatedAt: null, blocks: fat })).toString("base64"),
  });
  setRpcForTests(makeRpcFixture().rpcFixture);
  const res = makeRes();
  await adv.default({}, res);
  assert.equal(res.statusCode, 200, `Antwort: ${JSON.stringify(res.body)}`);
  const windowDoc = decodeGh(`data/block-window/${day}.json`);
  assert.ok(windowDoc, "Fenster wurde geschrieben");
  const bytes = Buffer.byteLength(JSON.stringify(windowDoc), "utf8");
  assert.ok(bytes <= 900000, `Chunk nach Cap: ${bytes} B <= 900000`);
  const indices = windowDoc.blocks.map((b) => b.i);
  assert.ok(indices.includes(1005), "neueste Zeile (1005) bleibt — älteste fallen");
});

// ---------- mergeReplayJob (pure) ----------
test("mergeReplayJob: Adress-/Fenster-Dedup, sonst anhängen", () => {
  let doc = mergeReplayJob({ jobs: [] }, { address: REPLAY_ADDR, fromLedger: 10, toLedger: 20 }, 1000);
  assert.equal(doc.jobs.length, 1);
  assert.deepEqual(doc.jobs[0], {
    address: REPLAY_ADDR,
    fromLedger: 10,
    toLedger: 20,
    marker: null,
    status: "pending",
    updatedAt: 1000,
  });
  // Gleiches Fenster nochmal -> kein Duplikat, Status zurück auf pending.
  doc = mergeReplayJob(doc, { address: REPLAY_ADDR, fromLedger: 10, toLedger: 20 }, 2000);
  assert.equal(doc.jobs.length, 1);
  assert.equal(doc.jobs[0].updatedAt, 2000);
  // Anderes Fenster -> zweiter Job.
  doc = mergeReplayJob(doc, { address: REPLAY_ADDR, fromLedger: 30, toLedger: 40 }, 3000);
  assert.equal(doc.jobs.length, 2);
});
