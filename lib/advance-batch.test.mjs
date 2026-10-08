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
import { HISTORY_MAX_ENTRIES } from "./history.mjs";

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
const { mergeHistory } = await import("./history.mjs");
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

test("DEFAULT_BUDGET = 140 und respektiert das Tick-Request-Budget", () => {
  assert.equal(DEFAULT_BUDGET, 140);
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
// errAt (Fehlerfeld-Fall, Persistenz-Marge 2026-10-05): der genannte Index
// wirft einen NICHT-lgrNotFound-Fehler (Netzwerk-/RPC-Fehler) — der Fetcher-
// Wrapper in api/advance.js muss die Ursache erfassen (Summary ", Fehler: …")
// und null liefern (Walk-Ende, Partial-Persist) statt sie zu verschlucken.
function makeRpcFixture({ accountInfoLedger = 1005, gapAt = null, errAt = null } = {}) {
  const calls = { ledger: [], account_info: [], account_tx: [] };
  const rpcFixture = async (method, params) => {
    calls[method]?.push(params);
    if (method === "ledger") {
      const idx = params?.ledger_index;
      if (idx === "validated") return { ledger_index: 1005 };
      if (gapAt != null && idx === gapAt) throw new Error("RPC error: lgrNotFound");
      if (errAt != null && idx === errAt) throw new Error("RPC error: tooBusy (Fixture-Fehlerfeld)");
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
  const walk = worstCaseTickRequests(DEFAULT_BUDGET); // 140 Requests (expand:true)
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

// ---------- (a.1) V7/Budget-Klemme: MAX_WALK_BUDGET deckelt den ENV-Tiefschnitt ----------
const { MAX_WALK_BUDGET, budgetOf } = adv;
test("Budget-Klemme: MAX_WALK_BUDGET = 189 hält die Tick-Bilanz, budgetOf deckelt ADVANCE_BUDGET", () => {
  assert.equal(MAX_WALK_BUDGET, TICK_REQUEST_BUDGET - REPLAY_TICK_CAP - ENTITY_TICK_CAP - 1);
  assert.equal(MAX_WALK_BUDGET, 189, "250 − 40 (Replay) − 20 (Entity) − 1 (Seed)");
  assert.ok(DEFAULT_BUDGET <= MAX_WALK_BUDGET, "Default-Budget liegt unter der Klemme");
  assert.ok(
    worstCaseTickRequests(MAX_WALK_BUDGET) + REPLAY_TICK_CAP + ENTITY_TICK_CAP + 1 <= TICK_REQUEST_BUDGET,
    "selbst der geklemmte Tiefschnitt kippt die Bilanz nie"
  );
  const prev = process.env.ADVANCE_BUDGET;
  try {
    process.env.ADVANCE_BUDGET = "5000";
    assert.equal(budgetOf(), MAX_WALK_BUDGET, "V7-Kalibrier-Tiefschnitt klemmt an 189");
    process.env.ADVANCE_BUDGET = String(MAX_WALK_BUDGET + 1);
    assert.equal(budgetOf(), MAX_WALK_BUDGET, "Grenzfall +1 wird geklemmt");
    process.env.ADVANCE_BUDGET = "50";
    assert.equal(budgetOf(), 50, "kleinerer ENV-Wert bleibt unangetastet");
    delete process.env.ADVANCE_BUDGET;
    assert.equal(budgetOf(), DEFAULT_BUDGET, "ohne ENV gilt der Default");
    process.env.ADVANCE_BUDGET = "garbage";
    assert.equal(budgetOf(), DEFAULT_BUDGET, "nicht-numerischer ENV-Wert fällt auf den Default");
  } finally {
    if (prev === undefined) delete process.env.ADVANCE_BUDGET;
    else process.env.ADVANCE_BUDGET = prev;
  }
});

// ---------- (a.2) V5 verifiedFresh: buildCtx fail-open ohne Entity-Layer ----------
test("buildCtx: entityDoc null -> verifiedFresh leeres Set (fail-open, bitgleich)", async () => {
  resetHandlerState();
  const { buildCtx } = adv;
  const ctx = await buildCtx(null, null);
  assert.ok(ctx.verifiedFresh instanceof Set);
  assert.equal(ctx.verifiedFresh.size, 0, "ohne Entity-Layer kein Beleg (Verhalten bitgleich)");
});

test("buildCtx: Entity-Tabelle befüllt verifiedFresh, Köder bleibt defensiv ausgeschlossen", async () => {
  resetHandlerState();
  const { buildCtx } = adv;
  const snapLedger = 1000;
  const ctx = await buildCtx(null, {
    addresses: {
      // Frischer Beleg: Gap 10 <= 21600 (24 h) — Adresse base58-sicher, eindeutig.
      [ENT_TA]: { previousTxnLgrSeq: snapLedger - 10, snapshotLedger: snapLedger, snapshotAt: 1 },
      // Zu alt: Gap 21601 > maxGapLedgers.
      [ENT_TB]: { previousTxnLgrSeq: snapLedger - 21601, snapshotLedger: snapLedger, snapshotAt: 1 },
      // Köder (ENV BAIT_ADDRESSES): trotz Beleg ausgeschlossen (Defense-in-Depth).
      [ADV_BAIT]: { previousTxnLgrSeq: snapLedger, snapshotLedger: snapLedger, snapshotAt: 1 },
    },
  });
  assert.ok(ctx.verifiedFresh.has(ENT_TA), "Entity-Beleg trägt verifiedFresh");
  assert.ok(!ctx.verifiedFresh.has(ENT_TB), "Gap > 24 h ist kein Beleg");
  assert.ok(!ctx.verifiedFresh.has(ADV_BAIT), "Köder nie im Beleg-Set");
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

// ---------- (f.2) Persistenz-Marge und Walk-Fehlerfeld (2026-10-05) ----------
// PERSIST_MARGIN_MS (api/advance.js, nach GUARD_MARGIN_MS): der Walk endet
// bei tickDeadline − 6000 = t0 + 25000 − 6000 = t0 + 19000, damit die letzte
// Parallel-Runde plus die Persistenz-Phase innerhalb maxDuration 30 s
// durchkommen. Direkt unter der Marge wird noch gelaufen, direkt darüber nicht.
test("Persistenz-Marge: Walk läuft direkt darunter, stoppt direkt darüber (Partial-Persist)", async () => {
  // Unter der Marge: Uhr springt nach der Deadline-Setzung auf t0 + 18999
  // (< 19000) -> Fetcher läuft, 5 Blöcke (1001..1005), Edge 1006 lgrNotFound.
  resetHandlerState();
  ghFiles.set("data/flow-state.json", {
    sha: "s1",
    content: Buffer.from(JSON.stringify(seededFlowStateDoc([ENT_TC]))).toString("base64"),
  });
  let clockCalls = 0;
  const t0 = Date.now();
  setClockForTests({ now: () => (clockCalls++ === 0 ? t0 : t0 + 18_999), sleep: async () => {} });
  setRpcForTests(makeRpcFixture().rpcFixture);
  const resUnder = makeRes();
  await adv.default({}, resUnder);
  assert.equal(resUnder.statusCode, 200, `Antwort: ${JSON.stringify(resUnder.body)}`);
  assert.ok(String(resUnder.body.summary).includes("+5 Blöcke"), `unter der Marge gelaufen: ${resUnder.body.summary}`);
  assert.ok(!String(resUnder.body.summary).includes("Fehler:"), `kein Fehlerfeld ohne Fehler: ${resUnder.body.summary}`);
  const docUnder = decodeGh("data/flow-state.json");
  assert.equal(docUnder?.cursor, 1005, "Cursor unter der Marge gerückt");

  // Über der Marge: Uhr auf t0 + 19000 (>= 19000) -> Fetcher liefert sofort
  // null -> 0 Blöcke, Cursor unverändert, Entity-Layer übersprungen, Tick 200.
  resetHandlerState();
  ghFiles.set("data/flow-state.json", {
    sha: "s1",
    content: Buffer.from(JSON.stringify(seededFlowStateDoc([ENT_TC]))).toString("base64"),
  });
  clockCalls = 0;
  setClockForTests({ now: () => (clockCalls++ === 0 ? t0 : t0 + 19_000), sleep: async () => {} });
  const { rpcFixture: rpcOver, calls: callsOver } = makeRpcFixture();
  setRpcForTests(rpcOver);
  const resOver = makeRes();
  await adv.default({}, resOver);
  setClockForTests(null);
  assert.equal(resOver.statusCode, 200, `Antwort: ${JSON.stringify(resOver.body)}`);
  assert.ok(String(resOver.body.summary).includes("+0 Blöcke"), `über der Marge gestoppt: ${resOver.body.summary}`);
  assert.ok(!String(resOver.body.summary).includes("Fehler:"), `Deadline-Stop ist kein Fehler: ${resOver.body.summary}`);
  assert.equal(callsOver.ledger.length, 0, "kein ledger-Request über der Marge");
  assert.equal(callsOver.account_info.length, 0, "Entity-Layer an dieselbe Marge gebunden");
  const docOver = decodeGh("data/flow-state.json");
  assert.equal(docOver?.cursor, 1000, "Cursor unverändert (kein Block gelaufen)");
});

// Netzwerk-/RPC-Fehler im Walk (nicht lgrNotFound): advance() verschluckt ihn
// weiterhin als Walk-Ende (ledger-walk.mjs:74-75, null-Vertrag unverändert),
// aber der Fetcher-Wrapper erfasst die Ursache und die Summary zeigt sie —
// live-Befund war +0-Ticks ohne jede Fehlerursache (3/12 Runs).
test("Walk-Fehlerfeld: RPC-Fehler (nicht lgrNotFound) erscheint in der Summary, Partial persistiert", async () => {
  resetHandlerState();
  ghFiles.set("data/flow-state.json", {
    sha: "s1",
    content: Buffer.from(JSON.stringify(seededFlowStateDoc([ENT_TC]))).toString("base64"),
  });
  setRpcForTests(makeRpcFixture({ errAt: 1003 }).rpcFixture);
  const res = makeRes();
  await adv.default({}, res);
  assert.equal(res.statusCode, 200, `Partial-Persist trotz Walk-Fehler: ${JSON.stringify(res.body)}`);
  const flowDoc = decodeGh("data/flow-state.json");
  assert.equal(flowDoc?.cursor, 1002, "Walk endet am Fehler (1003), Partial 1001/1002 persistiert");
  const summary = String(res.body.summary);
  assert.ok(summary.includes("+2 Blöcke"), `Partial-Ertrag in der Summary: ${summary}`);
  assert.ok(summary.includes("Fehler: RPC error: tooBusy"), `Ursache sichtbar: ${summary}`);
});

// Live-Edge (lgrNotFound) bleibt fehlerfrei: kein Fehlerfeld bei +0 am Edge
// (Spin-Schutz der Cron-Kette unterscheidet +0-mit-Fehler von +0-Edge).
test("Live-Edge am Walk-Ende: +0 ohne Fehlerfeld (lgrNotFound ist kein Fehler)", async () => {
  resetHandlerState();
  // Cursor bereits 1005 = eine unter dem validated-Index der Fixture: 1006
  // ist lgrNotFound -> Walk +0, kein Fehlerfeld.
  const doc = seededFlowStateDoc([ENT_TC]);
  doc.cursor = 1005;
  ghFiles.set("data/flow-state.json", {
    sha: "s1",
    content: Buffer.from(JSON.stringify(doc)).toString("base64"),
  });
  setRpcForTests(makeRpcFixture().rpcFixture);
  const res = makeRes();
  await adv.default({}, res);
  assert.equal(res.statusCode, 200, `Antwort: ${JSON.stringify(res.body)}`);
  const summary = String(res.body.summary);
  assert.ok(summary.includes("+0 Blöcke"), `Edge-Walk +0: ${summary}`);
  assert.ok(!summary.includes("Fehler:"), `lgrNotFound erzeugt kein Fehlerfeld: ${summary}`);
  const flowDoc = decodeGh("data/flow-state.json");
  assert.equal(flowDoc?.cursor, 1005, "Cursor bleibt am Edge");
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

// ---------- (i) Cluster-Akkumulation: Feldkappe verhindert Cap-Kollaps ----------
// Reproduktion des Live-Befunds (2026-10-06): ein Mega-Cluster sprengt im
// Alleingang FLOW_STATE_MAX_BYTES -> effectiveClusterCap halbiert auf 1 ->
// pruneFlowState wirft in JEDEM Tick alle übrigen Cluster raus (persistierter
// Bestand 12 -> 1, Cluster 'verschwinden'). Mit capClusterFields (api/advance.js
// iii.3, lib/flow-state.mjs): der Mega-Cluster wird komprimiert persistiert
// (<=300 Mitglieder je Feld, distinctAccounts bleibt der wahre Stand), der Cap
// stabilisiert sich nahe FLOW_STATE_MAX_CLUSTERS, der benigne Cluster bleibt —
// und der 31 d alte Evidenz-Cluster landet mit VOLLEN Mitgliedern im Archiv
// (Reihenpflicht iii.5 vor iii.3: Archiv auf dem ungekürzten State).
test("Cluster-Akkumulation: Mega-Cluster kollabiert den Cap nicht auf 1 — Benign bleibt, Archiv voll", async () => {
  resetHandlerState();
  const DAY_MS = 24 * 60 * 60 * 1000;
  const nowMs = Date.now();
  // Basis-58-sichere synthetische Adresse (kein 0/O/I/l), pro Index eindeutig.
  const B58L = "ABCDEFGHJKLMNPQRSTUVWXYZ";
  const megaAddr = (i) => {
    let s = "";
    let n = i;
    for (let k = 0; k < 4; k++) { s = B58L[n % 24] + s; n = Math.floor(n / 24); }
    return `rTESTMEGA${s}${"A".repeat(15)}`;
  };
  const N = 15000;
  const members = [];
  const roles = {};
  const severityByAddress = {};
  for (let i = 0; i < N; i++) {
    const a = megaAddr(i);
    members.push(a);
    roles[a] = "relay";
    severityByAddress[a] = "suspect";
  }
  const old = new Date(nowMs - 31 * DAY_MS).toISOString();
  const recent = new Date(nowMs).toISOString();
  const benignMembers = ["rTESTBENAAA", "rTESTBENBBB", "rTESTBENCCC", "rTESTBENDDD"];
  const oldMembers = [];
  for (let i = 0; i < 350; i++) oldMembers.push(megaAddr(20000 + i));
  const seedDoc = {
    cursor: 1000,
    updatedAt: nowMs,
    state: {
      clusters: {
        // Aktiver Mega-Cluster: roles+severityByAddress je Mitglied ->
        // serialisiert ~1,8 MB > FLOW_STATE_MAX_BYTES (live: 43.157 Mitglieder).
        "cluster-mega": {
          id: "cluster-mega",
          memberAddresses: members,
          roles,
          severityByAddress,
          mainDrainers: [{ address: members[0], outDrops: 900000 }],
          collectors: [],
          edges: [],
          peelingChains: [],
          distinctAccounts: N,
          firstSeen: new Date(nowMs - 3 * DAY_MS).toISOString(),
          lastSeen: recent,
          totalDrops: 900000,
          txCount: 120,
        },
        // 31 d alter Evidenz-Cluster: fällt im Zeit-Zweig des Pruning ->
        // muss im selben Tick mit VOLLEN 350 Mitgliedern archiviert werden.
        "cluster-old": {
          id: "cluster-old",
          memberAddresses: oldMembers,
          roles: { [oldMembers[0]]: "drainer" },
          mainDrainers: [{ address: oldMembers[0], outDrops: 700000 }],
          edges: [],
          peelingChains: [],
          distinctAccounts: 350,
          firstSeen: new Date(nowMs - 40 * DAY_MS).toISOString(),
          lastSeen: old,
          totalDrops: 700000,
          txCount: 60,
        },
        // Kleiner benignen Cluster, recent — ohne die Kollaps-Reproduktion
        // wäre er der Verlierer (cap=1, Schwere vor Volumen).
        "cluster-benign": {
          id: "cluster-benign",
          memberAddresses: benignMembers,
          roles: {},
          edges: [],
          peelingChains: [],
          distinctAccounts: 4,
          firstSeen: recent,
          lastSeen: recent,
          totalDrops: 1000,
          txCount: 2,
        },
      },
      blocksProcessedTotal: 50,
      lastAdvancedAt: nowMs,
    },
  };
  ghFiles.set("data/flow-state.json", {
    sha: "s1",
    content: Buffer.from(JSON.stringify(seedDoc)).toString("base64"),
  });
  setRpcForTests(makeRpcFixture().rpcFixture); // leerer Walk 1001..1005
  const res = makeRes();
  await adv.default({}, res);
  assert.equal(res.statusCode, 200, `Antwort: ${JSON.stringify(res.body)}`);
  const flowDoc = decodeGh("data/flow-state.json");
  assert.ok(flowDoc, "Flow-State wurde geschrieben");
  const bytes = Buffer.byteLength(JSON.stringify(flowDoc), "utf8");
  assert.ok(bytes <= 900000, `persistierter Bestand unter dem Byte-Cap: ${bytes} B`);
  // Kern-Regression: der benigne Cluster überlebt den Tick (vor dem Fix warf
  // cap=1 ihn raus — 'persistierte Cluster verschwinden').
  const benign = flowDoc.state.clusters["cluster-benign"];
  assert.ok(benign, "benigner Cluster bleibt im persistierten Bestand");
  assert.deepEqual(benign.memberAddresses, benignMembers);
  // Migration: der Mega-Cluster bleibt erhalten, aber komprimiert (Kappe 300
  // je Feld; distinctAccounts nennt weiter den wahren Bestand).
  const mega = flowDoc.state.clusters["cluster-mega"];
  assert.ok(mega, "Mega-Cluster bleibt erhalten (Migration, nicht Löschung)");
  assert.equal(mega.memberAddresses.length, 300, "memberAddresses auf Top-300 komprimiert");
  assert.equal(Object.keys(mega.roles ?? {}).length, 300, "roles mitgekürzt");
  assert.equal(Object.keys(mega.severityByAddress ?? {}).length, 300, "severityByAddress mitgekürzt");
  assert.equal(mega.distinctAccounts, N, "distinctAccounts bleibt der wahre Mitgliederstand");
  assert.ok(Array.isArray(mega.mainDrainers) && mega.mainDrainers.length === 1, "Evidenz bleibt unangetastet");
  // Archiv-Kopplung: der 31-d-Cluster fällt aus dem Bestand, erscheint aber
  // mit VOLLEN 350 Mitgliedern im Tages-Archiv (capClusterFields wirkt erst
  // nach archiveFromFlowState — api/advance.js iii.5 vor iii.3). Zusätzlich
  // schreibt der TAGES-CHECKPOINT (iii.6, Persistenz-Fix 2026-10-06) den
  // aktiven Mega-Cluster als reason:'checkpoint'-Zeile — ohne Verlust-
  // Prädikat, Guard über den Marker im frisch gelesenen Day-Doc.
  assert.ok(!("cluster-old" in flowDoc.state.clusters), "alter Evidenz-Cluster fällt aus dem Bestand");
  const day = new Date().toISOString().slice(0, 10);
  const archiveDoc = decodeGh(`data/flow-archive/${day}.json`);
  assert.ok(archiveDoc?.docs, "Archiv-Tagesdokument geschrieben");
  const lossRow = archiveDoc.docs.find((d) => d.clusterId === "cluster-old");
  const ckptRow = archiveDoc.docs.find((d) => d.clusterId === "cluster-mega");
  assert.ok(lossRow, "Verlust-Zeile (Zeit-Zweig) vorhanden");
  assert.equal(lossRow.memberAddresses.length, 350, "Archiv behält alle 350 Mitglieder");
  assert.equal(lossRow.lastSeen, old);
  assert.ok(!lossRow.reason, "Verlust-Zeile trägt keinen Checkpoint-Marker");
  assert.ok(ckptRow, "Checkpoint-Zeile für den aktiven Mega-Cluster");
  assert.equal(ckptRow.reason, "checkpoint", "Checkpoint-Marker sitzt auf der Zeile");
  assert.equal(ckptRow.memberAddresses.length, N, "Checkpoint läuft auf dem UNGEKAPPTEN State (alle Mitglieder)");
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

// =====================================================================
// TAGES-CHECKPOINT (iii.6, Persistenz-Fix 2026-10-06): Guard über den Marker
// im frisch gelesenen Day-Doc — NICHT 'Datei existiert' (der Verlust-Zweig
// legt die Tagesdatei auch ohne Checkpoint an); Köder-Filter (Korrektur c);
// Idempotenz über Ticks desselben UTC-Tags.
// =====================================================================
test("Checkpoint: Guard-Marker verhindert Re-Checkpoint im selben Tag; Köder-Mitglieder gefiltert", async () => {
  resetHandlerState();
  const nowMs = Date.now();
  const day = new Date(nowMs).toISOString().slice(0, 10);
  const fraud = `rTESTCKFRAUD${"A".repeat(22)}7`;
  const other = `rTESTCKPEER${"B".repeat(23)}9`;
  const seedDoc = {
    cursor: 1000,
    updatedAt: nowMs,
    state: {
      clusters: {
        "cluster-ckpt": {
          id: "cluster-ckpt",
          memberAddresses: [fraud, other],
          roles: { [fraud]: "drainer" },
          mainDrainers: [{ address: fraud, outDrops: 5000 }],
          edges: [],
          peelingChains: [],
          distinctAccounts: 2,
          firstSeen: new Date(nowMs).toISOString(),
          lastSeen: new Date(nowMs).toISOString(),
        },
      },
    },
  };
  ghFiles.set("data/flow-state.json", {
    sha: "s1",
    content: Buffer.from(JSON.stringify(seedDoc)).toString("base64"),
  });
  setRpcForTests(makeRpcFixture().rpcFixture); // leerer Walk 1001..1005
  let res = makeRes();
  await adv.default({}, res);
  assert.equal(res.statusCode, 200, `Antwort: ${JSON.stringify(res.body)}`);
  const doc1 = decodeGh(`data/flow-archive/${day}.json`);
  assert.ok(doc1?.docs?.length === 1, "erster Tick des Tages schreibt den Checkpoint");
  assert.equal(doc1.docs[0].clusterId, "cluster-ckpt");
  assert.equal(doc1.docs[0].reason, "checkpoint");
  assert.deepEqual(doc1.docs[0].memberAddresses, [fraud, other].sort(), "Köder-freie Mitglieder vollständig");
  const putsAfterFirst = putsTo(`data/flow-archive/${day}.json`).length;

  // Zweiter Tick desselben Tages: der Marker im frisch gelesenen Day-Doc
  // verhindert den erneuten Checkpoint (kein weiterer PUT auf den Pfad).
  res = makeRes();
  await adv.default({}, res);
  assert.equal(res.statusCode, 200, `Antwort: ${JSON.stringify(res.body)}`);
  assert.equal(putsTo(`data/flow-archive/${day}.json`).length, putsAfterFirst, "Guard: kein Re-Checkpoint am selben Tag");
  const doc2 = decodeGh(`data/flow-archive/${day}.json`);
  assert.equal(doc2.docs.length, 1, "keine zweite Zeile");
});

test("Checkpoint: köder-reiner Evidenz-Cluster wird verworfen (Köder-Filter, Korrektur c)", async () => {
  resetHandlerState();
  const nowMs = Date.now();
  const day = new Date(nowMs).toISOString().slice(0, 10);
  const seedDoc = {
    cursor: 1000,
    updatedAt: nowMs,
    state: {
      clusters: {
        "cluster-bait-only": {
          id: "cluster-bait-only",
          // Köder-Adresse als einziges Mitglied (Vertauschungs-Fall: der
          // State ist upstream köderfrei — der Filter ist Defense-in-Depth).
          memberAddresses: [ADV_BAIT],
          roles: { [ADV_BAIT]: "drainer" },
          mainDrainers: [{ address: ADV_BAIT, outDrops: 5000 }],
          edges: [],
          peelingChains: [],
          distinctAccounts: 1,
          firstSeen: new Date(nowMs).toISOString(),
          lastSeen: new Date(nowMs).toISOString(),
        },
      },
    },
  };
  ghFiles.set("data/flow-state.json", {
    sha: "s1",
    content: Buffer.from(JSON.stringify(seedDoc)).toString("base64"),
  });
  setRpcForTests(makeRpcFixture().rpcFixture);
  const res = makeRes();
  await adv.default({}, res);
  assert.equal(res.statusCode, 200, `Antwort: ${JSON.stringify(res.body)}`);
  const doc = decodeGh(`data/flow-archive/${day}.json`);
  assert.ok(!doc || !doc.docs || doc.docs.length === 0, "köder-reiner Checkpoint wird nicht geschrieben");
  assert.equal(putsTo(`data/flow-archive/${day}.json`).length, 0, "kein PUT ohne relevante Zeilen");
});

// =====================================================================
// historyRulesFromCluster (Kritik-Runde 4, Befund 1+2): die History-Regeln
// etikettieren die Cluster-Evidenz selbst — suspect-Schwere erhält keine
// erfundene Regel-ID, wash-cycle-Cluster tragen die echte Katalog-ID, und
// die Kappungs-Priorität (wer die 200er-Kappung überlebt) verschiebt sich
// gegenüber dem known-bad-hit-Fallback nicht.
// =====================================================================

const { historyRulesFromCluster } = adv;
const MAP_A = "rMAPTESTA" + "1".repeat(25); // base58-konform, 34 Zeichen
const MAP_B = "rMAPTESTB" + "1".repeat(25);
const NO_MAP_BAIT = new Map();

test("historyRulesFromCluster: suspect-only-Cluster -> known-bad-hit-Fallback, KEIN erfundenes 'airdrop-trustset-spam'", () => {
  const rules = historyRulesFromCluster(
    {
      roles: { [MAP_A]: "collector", [MAP_B]: "source" },
      severityByAddress: { [MAP_A]: "suspect", [MAP_B]: "suspect" },
    },
    NO_MAP_BAIT
  );
  assert.deepEqual([...rules], ["known-bad-hit"], "Fallback wie vor der Severity-Mapping (Kappungs-Priorität bleibt)");
  assert.ok(!rules.has("airdrop-trustset-spam"), "keine erfundene Regel-ID für suspect-Schwere");
});

test("historyRulesFromCluster: wash-cycle-Cluster -> echte Katalog-ID 'wash-cycle' (Kappungs-Priorität)", () => {
  const rules = historyRulesFromCluster(
    {
      severityByAddress: { [MAP_A]: "suspect" },
      motifs: { washCycles: [{ a: MAP_A, b: MAP_B }], gatherScatter: [] },
    },
    NO_MAP_BAIT
  );
  assert.deepEqual([...rules], ["wash-cycle"], "wash-cycle trägt seine echte ID (lib/detector.mjs:109)");
  assert.ok(!rules.has("airdrop-trustset-spam"), "keine Falschattribuierung");
  assert.ok(!rules.has("known-bad-hit"), "kein Fallback, wenn echte Evidenz vorliegt");
});

test("historyRulesFromCluster: gatherScatter allein ist keine Evidenz (Motiv-Grenze, flow-state.mjs:243-245)", () => {
  const rules = historyRulesFromCluster(
    { motifs: { gatherScatter: [{ address: MAP_A }], fanInMax: 4 } },
    NO_MAP_BAIT
  );
  assert.deepEqual([...rules], ["known-bad-hit"], "nur Fallback — gatherScatter löst keine Regel aus");
});

test("historyRulesFromCluster: malicious-Schwere -> known-bad-hit; mainDrainers/peelingChains unverändert", () => {
  const rules = historyRulesFromCluster(
    {
      mainDrainers: [{ address: MAP_A, outDrops: 5 }],
      peelingChains: [{ addresses: [MAP_A, MAP_B] }],
      severityByAddress: { [MAP_A]: "malicious", [MAP_B]: "suspect" },
    },
    NO_MAP_BAIT
  );
  assert.ok(rules.has("drainer-sweep"), "mainDrainers -> drainer-sweep");
  assert.ok(rules.has("peeling-chain"), "peelingChains mit Adressen -> peeling-chain");
  assert.ok(rules.has("known-bad-hit"), "malicious-Schwere -> known-bad-hit");
  assert.equal(rules.size, 3, "suspect-Schwere (MAP_B) fügt keine weitere ID hinzu");
});

test("historyRulesFromCluster: leere peelingChains und leere washCycles lösen keine Regel aus", () => {
  const rules = historyRulesFromCluster(
    { peelingChains: [{ addresses: [] }], motifs: { washCycles: [] }, severityByAddress: { [MAP_A]: "suspect" } },
    NO_MAP_BAIT
  );
  assert.deepEqual([...rules], ["known-bad-hit"], "nur Fallback");
});

test("historyRulesFromCluster: ungültige und Köder-Adressen in severityByAddress werden ignoriert", () => {
  const baitMap = new Map([[ADV_BAIT, "HP-1"]]);
  const rules = historyRulesFromCluster(
    { severityByAddress: { [ADV_BAIT]: "malicious", notAnAddress: "malicious", [MAP_A]: "suspect" } },
    baitMap
  );
  assert.deepEqual([...rules], ["known-bad-hit"], "Köder/ungültige Adressen liefern kein known-bad-hit-Etikett, nur Fallback");
});

// Kappungs-Parität (Befund 1, Reviewer-Simulation): 200 neuere offer-spam-
// Einträge + 1 betroffener Cluster — der Cluster muss die Kappung überleben,
// genau wie vor der Severity-Mapping (ALT: rules={} -> known-bad-hit-Fallback).
const SYN_ALPHA = "abcdefghijkmnopqrstuvwxyz"; // 25 Zeichen, ohne 'l'
function synthAddr(i) {
  let s = "";
  let n = i + 1;
  while (n > 0) {
    n -= 1;
    s = SYN_ALPHA[n % 25] + s;
    n = Math.floor(n / 25);
  }
  return "rSYN" + s.padStart(24, "a");
}

test("Kappungs-Parität: suspect-only-Cluster (Mapping -> known-bad-hit) überlebt HISTORY_MAX_ENTRIES offer-spam-Einträge", () => {
  const affected = {
    roles: { [MAP_A]: "collector" },
    severityByAddress: { [MAP_A]: "suspect" },
  };
  const rules = historyRulesFromCluster(affected, NO_MAP_BAIT);
  const incoming = [
    {
      members: [MAP_A, MAP_B],
      label: "cluster:affected",
      totalDrops: 1000,
      txCount: 3,
      firstSeen: 1000,
      lastSeen: 1000,
      rules: [...rules],
      severity: "malicious",
      sightings: 1,
      lastReportedAt: 1000,
    },
  ];
  const existing = [];
  for (let i = 0; i < HISTORY_MAX_ENTRIES; i++) {
    existing.push({
      members: [synthAddr(960000 + i)],
      label: `offer-spam-${i}`,
      totalDrops: 10,
      txCount: 1,
      firstSeen: 9000 + i,
      lastSeen: 9000 + i, // alle JÜNGER als der betroffene Cluster (lastSeen 1000)
      rules: ["offer-spam"],
      severity: "malicious",
      sightings: 1,
      lastReportedAt: 9000 + i,
    });
  }
  // Der betroffene Cluster ist der ÄLTESTE (lastSeen 1000) und ohne
  // HISTORY_FRAUD_RULES-Regel würde er den HISTORY_MAX_ENTRIES Einträgen weichen.
  const { list } = mergeHistory(existing, incoming, 10_000, NO_MAP_BAIT);
  assert.equal(list.length, HISTORY_MAX_ENTRIES);
  assert.ok(list.some((c) => c.label === "cluster:affected"), "betroffener Cluster überlebt die Kappung (ALT-Parität)");
});
