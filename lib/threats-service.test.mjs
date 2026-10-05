// lib/threats-service.test.mjs — Unit B (Besucher-Fang): visitor-triggered
// Drainer-Catch + History-Append im Serverless-Pfad.
//
// Kein Live-Netzwerk: die account_tx-Abfrage wird über die setRpc-Testnaht
// durch synthetische Ledger-Fixtures ersetzt; die GitHub-Contents-API wird
// durch einen fetch-Stub bedient (GET -> 404 Anlege-Fall, PUT -> 201).
//
// Lauf: node --test lib/threats-service.test.mjs
//
// Konventionen:
//   * Synthetische Adressen (base58-sicher, klassische Länge) — pro Test
//     eindeutig, damit checkCache-/Threat-Cache-Zustände nicht
//     kreuzkontaminieren.
//   * BAIT_ADDRESSES/GITHUB_HISTORY_TOKEN werden VOR dem Import gesetzt
//     (baitLabels wird beim Modulstart geparst); der Token ist nur Test-
//     Dekoration — alle GitHub-Calls laufen gegen den fetch-Stub.
//   * Die Fixturen spiegeln die Formen von monitor/monitor.test.mjs (Unit A).

import test from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";

// ---------- ENV vor dem Import (baitLabels wird beim Modulstart geparst) ----------
// Alle synthetischen Adressen sind base58-sicher (keine 0/I/O/l) — sonst
// lehnt XRPL_ADDR_RE sie ab (400) und der Merge-Filter wirft sie weg.
const BAIT = `rTESTB4Y${"A".repeat(24)}9`;
process.env.BAIT_ADDRESSES = BAIT;
process.env.GITHUB_HISTORY_TOKEN = "test-token";

const svc = await import("./threats-service.mjs");
const {
  checkAddress,
  checkDrainerSweepFromEntries,
  setRpc,
  getPublicThreats,
  getThreatKnowledge,
  buildCheckCtx,
  buildEntitySignal,
  resetCachesForTests,
  getExchangeRegistryMap,
  getMultiUserAccountsMap,
  REQUESTS_PER_TICK_CAP,
} = svc;

// ---------- Synthetische Adressen (einzigartig pro Test, base58-sicher) ----------
const VISITOR_A = `rTESTCHECKER${"A".repeat(20)}1`;
const VISITOR_B = `rTESTCHECKER${"B".repeat(20)}2`;
const VISITOR_C = `rTESTCHECKER${"C".repeat(20)}3`;
const VISITOR_D = `rTESTCHECKER${"D".repeat(20)}4`;
const VISITOR_E = `rTESTCHECKER${"E".repeat(20)}5`;
const COLLECTOR = `rTESTSUMPX${"B".repeat(24)}6`;
const FUNDER = `rTESTFUNDER${"B".repeat(23)}7`;

// ---------- Zeitstempel ----------
const NOW_ISO = new Date(Date.now() - 30_000).toISOString(); // frisch
const OLD_ISO = new Date(Date.now() - 3 * 86_400_000).toISOString(); // 3 Tage alt

// ---------- Fixtures (dieselben Formen wie monitor/monitor.test.mjs) ----------
let seq = 0;

// Ausgehender Sweep: toucher -> COLLECTOR. prevBal (optional) wird als
// AccountRoot PreviousFields.Balance in der Meta getragen — dieselbe Form,
// die lib/detector.mjs' prevBalanceOf liest.
function sweepEntry(toucher, drops, prevBal, time) {
  seq += 1;
  return {
    hash: `TESTSWEEP${String(seq).padStart(3, "0")}`,
    ledger_index: 49_000_000 + seq,
    close_time_iso: time,
    validated: true,
    tx_json: {
      TransactionType: "Payment",
      Account: toucher,
      Destination: COLLECTOR,
      Amount: String(drops),
    },
    meta:
      prevBal != null
        ? {
            AffectedNodes: [
              {
                ModifiedNode: {
                  LedgerEntryType: "AccountRoot",
                  PreviousFields: { Balance: String(prevBal) },
                  FinalFields: { Balance: String(Math.max(0, prevBal - drops)) },
                },
              },
            ],
          }
        : null,
  };
}

// Funding: FUNDER -> toucher (Präcondition der Sweep-Regel).
// createdAccount=true ergänzt die CreatedNode AccountRoot des touchers —
// derselbe Beleg, den lib/detector.mjs createdAccountOf liest (:237-247) und
// der die Sweep-Severity von 'suspect' auf 'malicious' hebt (:641-642).
function fundingEntry(toucher, drops, time, createdAccount = false) {
  seq += 1;
  return {
    hash: `TESTFUND${String(seq).padStart(3, "0")}`,
    ledger_index: 49_000_000 + seq,
    close_time_iso: time,
    validated: true,
    tx_json: {
      TransactionType: "Payment",
      Account: FUNDER,
      Destination: toucher,
      Amount: String(drops),
    },
    meta: createdAccount
      ? {
          AffectedNodes: [
            {
              CreatedNode: {
                LedgerEntryType: "AccountRoot",
                LedgerEntry: { Account: toucher },
              },
            },
          ],
        }
      : null,
  };
}

// Berührungs-Ereignis: toucher -> Köder (der Trigger des Besucher-Fangs).
function touchEntry(toucher, time) {
  seq += 1;
  return {
    hash: `TESTTOUCH${String(seq).padStart(3, "0")}`,
    ledger_index: 49_000_000 + seq,
    close_time_iso: time,
    validated: true,
    tx_json: {
      TransactionType: "Payment",
      Account: toucher,
      Destination: BAIT,
      Amount: "1",
    },
    meta: null,
  };
}

// ---------- GitHub-Stub (fetch-Ersatz für die Contents-API) ----------
let ghCalls = [];
const realFetch = globalThis.fetch;
globalThis.fetch = async (url, opts) => {
  const method = opts?.method ?? "GET";
  ghCalls.push({ url: String(url), method, body: opts?.body ?? null });
  if (method === "PUT") return { ok: true, status: 201, json: async () => ({}) };
  return { ok: true, status: 404, json: async () => ({}) }; // GET: Anlege-Fall
};
test.after(() => {
  globalThis.fetch = realFetch;
});

// ---------- RPC-Fixture: Besucher-Historie pro Szenario, sonst leer ----------
function rpcFor(visitor, visitorEntries) {
  return async (_command, params) => {
    if (params?.account === visitor) return { transactions: visitorEntries };
    return { transactions: [] };
  };
}

// ---------- Tests ----------

test("bestätigter Drainer aus Besucher-Check -> Vertrag + History-Append", async () => {
  // CreatedNode-belegter Sweep (Funding-Eintrag trägt die CreatedNode
  // AccountRoot des touchers) -> Severity 'malicious' (detector.mjs:641-642)
  // -> Append-Gate offen. Ohne CreatedNode wäre es 'suspect' ohne Append
  // (Gegenprobe: Test 'Unit-B-Gate' unten).
  const entries = [
    touchEntry(VISITOR_A, NOW_ISO),
    sweepEntry(VISITOR_A, 95_000, 100_000, NOW_ISO),
    fundingEntry(VISITOR_A, 100_000, NOW_ISO, true),
  ];
  setRpc(rpcFor(VISITOR_A, entries));
  ghCalls = [];
  const { status, body } = await checkAddress(VISITOR_A);
  assert.equal(status, 200);
  // Vertrag (identisch zu Unit A):
  assert.equal(body.drainer, true);
  assert.equal(typeof body.sweepRatio, "number");
  assert.ok(body.sweepRatio >= 0.9, `sweepRatio ${body.sweepRatio} erwartet >= 0.9`);
  assert.equal(body.risk, "malicious");
  assert.ok(String(body.reason).startsWith("Drainer-Sweep:"), `reason: ${body.reason}`);
  assert.ok(!String(body.reason).includes(BAIT), "Reason enthält keine Köder-Adresse");
  // Der Check bleibt ansonsten unverändert:
  assert.equal(body.verdict, "clean");
  assert.equal(body.checkedTxCount, entries.length);

  // History-Append: genau ein PUT, Bestand enthält den Vertragseintrag.
  const puts = ghCalls.filter((c) => c.method === "PUT");
  assert.equal(puts.length, 1, `erwartet genau ein PUT, erhalten ${puts.length}`);
  const putBody = JSON.parse(puts[0].body);
  const merged = JSON.parse(Buffer.from(putBody.content, "base64").toString("utf8"));
  assert.equal(merged.length, 1);
  const e = merged[0];
  assert.deepEqual(e.members, [VISITOR_A]);
  assert.ok(e.rules.includes("drainer-sweep"));
  assert.equal(e.severity, "malicious");
  assert.equal(e.label, "Drainer");
  assert.equal(e.totalDrops, 95_000);
  assert.match(e.key, /^[0-9a-f]{64}$/);
  assert.equal(e.key, createHash("sha256").update(VISITOR_A).digest("hex"));
  assert.ok(Number.isFinite(e.firstSeen) && Number.isFinite(e.lastSeen));
  // Labels only: keine rohe Köder-Adresse im gemeldeten Bestand.
  assert.ok(!JSON.stringify(merged).includes(BAIT), "Bestand enthält keine Köder-Adresse");
});

test("keine Berührung -> kein Drainer-Feld, kein History-Write", async () => {
  const entries = [
    fundingEntry(VISITOR_B, 100_000, NOW_ISO),
    sweepEntry(VISITOR_B, 95_000, 100_000, NOW_ISO),
  ];
  setRpc(rpcFor(VISITOR_B, entries));
  ghCalls = [];
  const { status, body } = await checkAddress(VISITOR_B);
  assert.equal(status, 200);
  assert.equal(body.drainer, undefined);
  assert.equal(body.sweepRatio, undefined);
  assert.equal(ghCalls.filter((c) => c.method === "PUT").length, 0);
});

test("Sweep unter Schwelle -> keine Bestätigung", async () => {
  const entries = [
    touchEntry(VISITOR_C, NOW_ISO),
    sweepEntry(VISITOR_C, 50_000, 100_000, NOW_ISO),
    fundingEntry(VISITOR_C, 100_000, NOW_ISO),
  ];
  setRpc(rpcFor(VISITOR_C, entries));
  ghCalls = [];
  const { status, body } = await checkAddress(VISITOR_C);
  assert.equal(status, 200);
  assert.equal(body.drainer, undefined);
  assert.equal(ghCalls.filter((c) => c.method === "PUT").length, 0);
});

test("alte Berührung (Frische-Signal) -> keine Bestätigung", async () => {
  const entries = [
    touchEntry(VISITOR_D, OLD_ISO),
    sweepEntry(VISITOR_D, 95_000, 100_000, OLD_ISO),
    fundingEntry(VISITOR_D, 100_000, OLD_ISO),
  ];
  setRpc(rpcFor(VISITOR_D, entries));
  ghCalls = [];
  const { status, body } = await checkAddress(VISITOR_D);
  assert.equal(status, 200);
  assert.equal(body.drainer, undefined);
  assert.equal(ghCalls.filter((c) => c.method === "PUT").length, 0);
});

test("fail-closed: ohne Token kein History-Write, Check bleibt erfolgreich", async () => {
  const entries = [
    touchEntry(VISITOR_E, NOW_ISO),
    sweepEntry(VISITOR_E, 95_000, 100_000, NOW_ISO),
    fundingEntry(VISITOR_E, 100_000, NOW_ISO),
  ];
  setRpc(rpcFor(VISITOR_E, entries));
  ghCalls = [];
  delete process.env.GITHUB_HISTORY_TOKEN;
  try {
    const { status, body } = await checkAddress(VISITOR_E);
    assert.equal(status, 200);
    assert.equal(body.drainer, true);
    assert.equal(ghCalls.length, 0, "ohne Token kein GitHub-Call");
  } finally {
    process.env.GITHUB_HISTORY_TOKEN = "test-token";
  }
});

test("History-Eintrag: Köder-Mitglieder fallen im Merge-Filter (Labels only)", async () => {
  const { mergeHistory, sanitizeHistoryList } = await import("./history.mjs");
  const baitMap = new Map([[BAIT, "HP-1"]]);
  const entry = {
    members: [VISITOR_A, BAIT],
    label: "Drainer",
    totalDrops: 95_000,
    txCount: 3,
    firstSeen: Date.parse(NOW_ISO),
    lastSeen: Date.parse(NOW_ISO),
    rules: ["drainer-sweep"],
    severity: "malicious",
  };
  const merged = mergeHistory([], [entry], Date.now(), baitMap);
  assert.equal(merged.list.length, 1);
  assert.deepEqual(merged.list[0].members, [VISITOR_A]); // Köder-Adresse gefiltert
  assert.equal(merged.list[0].label, "Drainer");
  assert.ok(!JSON.stringify(merged.list).includes(BAIT));
  // köder-only-Cluster wird verworfen
  const only = sanitizeHistoryList([{ members: [BAIT], label: "Drainer" }], baitMap);
  assert.equal(only.length, 0);
});

test("checkDrainerSweepFromEntries: Bestätigung nur mit Frische-Signal UND Schwelle", () => {
  const fresh = [
    touchEntry(VISITOR_A, NOW_ISO),
    sweepEntry(VISITOR_A, 95_000, 100_000, NOW_ISO),
    fundingEntry(VISITOR_A, 100_000, NOW_ISO),
  ];
  const hit = checkDrainerSweepFromEntries(fresh, VISITOR_A, NOW_ISO);
  assert.ok(hit, "frischer Sweep über Schwelle wird bestätigt");
  assert.ok(hit.ratio >= 0.9);
  assert.equal(hit.drops, 95_000);
  const stale = checkDrainerSweepFromEntries(fresh, VISITOR_A, OLD_ISO);
  assert.equal(stale, null, "ohne Frische-Signal keine Bestätigung");
  const below = checkDrainerSweepFromEntries(
    [
      touchEntry(VISITOR_C, NOW_ISO),
      sweepEntry(VISITOR_C, 50_000, 100_000, NOW_ISO),
      fundingEntry(VISITOR_C, 100_000, NOW_ISO),
    ],
    VISITOR_C,
    NOW_ISO
  );
  assert.equal(below, null, "unterhalb der Schwelle keine Bestätigung");
});

// ============================================================================
// Persistenz-Hälfte (2026-10-03): Funding-Tiefe 2, Request-Cap pro Ableitung,
// entity-Feld durch die Anonymitätsschicht, exchangeLabel aus der Registry.
// Neue Adressen pro Test (Cache-Kreuzkontamination), resetCachesForTests vor
// jeder Ableitung (60-s-Cache würde sonst die neue Fixture ignorieren).
// ============================================================================

// Einfache Payment-Fixture (Form wie sweepEntry/fundingEntry, ohne Meta).
function payEntryFixture(from, to, time) {
  seq += 1;
  return {
    hash: `TESTPAYF${String(seq).padStart(3, "0")}`,
    ledger_index: 49_100_000 + seq,
    close_time_iso: time,
    validated: true,
    tx_json: { TransactionType: "Payment", Account: from, Destination: to, Amount: "1000" },
    meta: null,
  };
}

test("Funding-Rückverfolgung Tiefe 2: Kette A→B→C liefert beide Hops (Labels only)", async () => {
  const ATTACKER = `rTESTATTACKER${"A".repeat(21)}8`;
  const FUNDER1 = `rTESTFUND1${"A".repeat(23)}8`;
  const FUNDER2 = `rTESTFUND2${"A".repeat(23)}9`;
  // Kette: ATTACKER berührt den Köder; ATTACKER wird von FUNDER1 finanziert,
  // FUNDER1 von FUNDER2 (FUNDING_DEPTH 2, angleichen an monitor.mjs).
  const rpcFixture = async (_command, params) => {
    const acc = params?.account;
    if (acc === BAIT) return { transactions: [payEntryFixture(ATTACKER, BAIT, NOW_ISO)] };
    if (acc === ATTACKER) return { transactions: [payEntryFixture(FUNDER1, ATTACKER, NOW_ISO)] };
    if (acc === FUNDER1) return { transactions: [payEntryFixture(FUNDER2, FUNDER1, NOW_ISO)] };
    return { transactions: [] };
  };
  setRpc(rpcFixture);
  resetCachesForTests();
  const threats = await getPublicThreats();
  const t = threats.find((x) => x.address === ATTACKER);
  assert.ok(t, "Angreifer (Köder-Berührer) ist in der Ableitung");
  assert.equal(t.funding.length, 2, `Tiefe 2 erwartet beide Hops, erhalten ${t.funding.length}`);
  // Sanitized: {label} ohne Adresse (sanitizeFunding); Label = Funder-Adresse
  // (nicht-Köder, nicht Faucet bleibt als Label erhalten).
  assert.equal(t.funding[0].label, FUNDER1, "Hop 1: A finanziert B");
  assert.equal(t.funding[1].label, FUNDER2, "Hop 2: C finanziert A");
  assert.ok(!JSON.stringify(t).includes(BAIT), "Köder-Adresse taucht nirgends auf");
});

test("Request-Cap: deriveThreats feuert nie mehr als REQUESTS_PER_TICK_CAP account_tx-Calls", async () => {
  const CAP_ATK = `rTESTCAPATT${"A".repeat(22)}7`;
  let accountTxCalls = 0;
  // Schwerste Fixture, die ein einzelner Köder liefern kann: 3 Seiten je
  // 20 Einträge (BAIT_TX_LIMIT 50 -> 60 Einträge genügen), fünf Angreifer
  // (FUNDING_TRACE_MAX) mit je zwei Funding-Ebenen.
  const baitPages = [1, 2, 3].map((page) =>
    Array.from({ length: 20 }, (_, i) =>
      payEntryFixture(`rTESTCAPX${String(page)}${String(i).padStart(2, "0")}${"A".repeat(22)}`, BAIT, NOW_ISO)
    )
  );
  const rpcFixture = async (_command, params) => {
    const acc = params?.account;
    if (acc === BAIT) {
      accountTxCalls += 1;
      const page = Math.min(2, accountTxCalls - 1);
      return { transactions: baitPages[page], marker: page < 2 ? { fake: page } : undefined };
    }
    accountTxCalls += 1;
    return { transactions: [] };
  };
  setRpc(rpcFixture);
  resetCachesForTests();
  const threats = await getPublicThreats();
  assert.ok(REQUESTS_PER_TICK_CAP === 40, "Cap-Konstante 40 (Budget-Bilanz api/advance.js)");
  assert.ok(
    accountTxCalls <= REQUESTS_PER_TICK_CAP,
    `Ableitung feuerte ${accountTxCalls} Requests — Cap ${REQUESTS_PER_TICK_CAP} verletzt`
  );
  assert.ok(threats.length > 0, "Ableitung liefert trotz Budgetierung Threats");
});

test("entity-Feld überlebt sanitizeThreat — ohne Köder-Adresse, mit Join-Liste", async () => {
  const { sanitizeThreat } = await import("./sanitize.mjs");
  const baitMap = new Map([[BAIT, "HP-1"]]);
  const ENTITY_OTHER = `rTESTENTITYO${"A".repeat(22)}6`;
  const raw = {
    address: `rTESTENTTHREAT${"A".repeat(20)}5`,
    risk: "malicious",
    reason: "Externe Payment-Transaktion an HP-1",
    evidence: [],
    firstSeen: NOW_ISO,
    funding: [],
    exchangeLabel: "TestExchange",
    entity: { regularKeySharedWith: [BAIT, ENTITY_OTHER], domain: "example.com" },
  };
  const out = sanitizeThreat(raw, { baitLabels: baitMap, faucetAddresses: new Set(), faucetLabel: "Faucet (benign)" });
  assert.ok(out.entity, "entity-Feld erreicht die öffentliche Ausgabe");
  assert.ok(!out.entity.regularKeySharedWith.includes(BAIT), "Köder-Adresse ist nicht in der Join-Liste");
  assert.ok(out.entity.regularKeySharedWith.includes(ENTITY_OTHER), "Nicht-Köder-Adresse bleibt erhalten");
  assert.ok(JSON.stringify(out).includes("Köder #1"), "Köder erscheint nur als öffentliches Label");
  assert.ok(!JSON.stringify(out).includes(BAIT), "Köder-Adresse taucht nirgends auf");
  assert.equal(out.entity.domain, "example.com");
  assert.equal(out.entity.exchangeLabel, "TestExchange");
});

test("exchangeLabel: leer für Adresse ohne Registry-Treffer (kein Raten)", async () => {
  const NO_REG = `rTESTNOREG${"A".repeat(23)}4`;
  const rpcFixture = async (_command, params) => {
    if (params?.account === BAIT) return { transactions: [payEntryFixture(NO_REG, BAIT, NOW_ISO)] };
    return { transactions: [] };
  };
  setRpc(rpcFixture);
  resetCachesForTests();
  const threats = await getPublicThreats();
  const t = threats.find((x) => x.address === NO_REG);
  assert.ok(t, "Threat aus Fixture vorhanden");
  assert.equal(t.exchangeLabel, "", "ohne Registry-Treffer bleibt das Feld leer");
});

test("exchangeLabel: Registry-Treffer liefert Beschriftung (Read erfolgreich)", async () => {
  // Echte Registry-Adresse aus public/data/exchange-registry.json (nur Label-
  // Verhalten wird geprüft — die Adresse bleibt Fixture, wird nicht persistiert).
  const REG_ADDR = "rEb8TK3gBgk5auZkwc6sHnwrGVJH8DuaLh"; // Binance (1)
  const rpcFixture = async (_command, params) => {
    if (params?.account === BAIT) return { transactions: [payEntryFixture(REG_ADDR, BAIT, NOW_ISO)] };
    return { transactions: [] };
  };
  setRpc(rpcFixture);
  resetCachesForTests();
  const threats = await getPublicThreats();
  const t = threats.find((x) => x.address === REG_ADDR);
  assert.ok(t, "Threat aus Fixture vorhanden");
  assert.equal(t.exchangeLabel, "Binance", "Registry-Treffer liefert exchange-Namen");
});

// ============================================================================
// Wissens-Layer (Runde 3): getThreatKnowledge merged history/flow-state in
// beide Check-Endpunkte; buildCheckCtx liefert knownBad (mit Registry-
// Ausschluss), firstSeenAt und das Cross-Ledger-history-Seed. Reader sind
// über opts injiziert (lokale Datei-Reader) — kein GitHub-Transport, kein
// RPC für die persistierten Schichten. Neue Adressen pro Test.
// ============================================================================

// Längen: 30-33 Zeichen (XRPL_ADDR_RE: 25-35). base58-sicher: kein l/I/O
// im Präfix (HISTMEMBER/FLOWROLE/NO_TOKEN enthielten I/O — von
// XRPL_ADDR_RE abgelehnt, Befund im eigenen Testlauf).
const HIST_MEMBER = `rTESTHSTRCKUP${"A".repeat(17)}1`; // in history gelistet
const FLOW_CP = `rTESTFLWCPX${"A".repeat(20)}2`; // flow-state-Gegenpartei (suspect)
const FLOW_ROLE = `rTESTFLWDRN${"A".repeat(19)}3`; // flow-state-Rolle ohne severity
const REG_HIST = "rEb8TK3gBgk5auZkwc6sHnwrGVJH8DuaLh"; // Binance — Registry-Member
const SELF_HIST = `rTESTSELRCKUP${"A".repeat(16)}4`; // selbst gelistete Adresse
const ENTITY_LINK = `rTESTENTTYNK${"A".repeat(18)}5`; // entity-verknüpft, keine Gegenpartei

// Injizierte Reader (Form wie die lokalen Reader in server/index.mjs):
// readThreats -> Array (ersetzt die RPC-Ableitung), readHistory -> {list},
// readFlowState -> {doc}.
function knowledgeOpts(over = {}) {
  return {
    readThreats: async () => over.threats ?? [],
    readHistory: async () => ({ list: over.history ?? [] }),
    readFlowState: async () => ({ doc: over.flowDoc ?? null }),
  };
}

test("Wissens-Layer: history-Mitglied wird gelistet — verdict 'bad' statt 'clean' (selfListed)", async () => {
  const entries = [payEntryFixture(HIST_MEMBER, FLOW_CP, NOW_ISO)];
  setRpc(rpcFor(HIST_MEMBER, entries));
  const opts = knowledgeOpts({
    history: [
      {
        members: [HIST_MEMBER],
        label: "Clusterfixture",
        firstSeen: Date.parse(OLD_ISO),
        lastSeen: Date.parse(OLD_ISO),
        rules: ["drainer-sweep"],
        severity: "malicious",
      },
    ],
  });
  const { status, body } = await checkAddress(HIST_MEMBER, opts);
  assert.equal(status, 200);
  assert.equal(body.selfListed, true, "history-Mitglied ist gelistet");
  assert.equal(body.verdict, "bad", "selbst gelistet -> 'bad' VOR der contacts-Verzweigung");
  assert.equal(body.contacts.length, 0, "Gegenpartei ungelistet -> keine Kontakte");
});

test("Wissens-Layer: flow-state-Gegenpartei -> contact risk 'suspect' + knownBad im Engine-Kontext", async () => {
  const entries = [payEntryFixture(FLOW_CP, SELF_HIST, NOW_ISO)];
  setRpc(rpcFor(SELF_HIST, entries));
  const opts = knowledgeOpts({
    flowDoc: {
      cursor: 10,
      updatedAt: Date.now(),
      state: {
        clusters: {
          "cluster:flow1": {
            id: "cluster:flow1",
            totalDrops: 5000,
            txCount: 2,
            firstSeen: OLD_ISO,
            lastSeen: NOW_ISO,
            memberAddresses: [FLOW_CP, FLOW_ROLE],
            roles: { [FLOW_CP]: "relay", [FLOW_ROLE]: "collector" },
            severityByAddress: { [FLOW_CP]: "suspect" },
          },
        },
        blocksProcessedTotal: 1,
        lastAdvancedAt: Date.now(),
      },
    },
  });
  const { status, body } = await checkAddress(SELF_HIST, opts);
  assert.equal(status, 200);
  assert.equal(body.verdict, "contact");
  assert.equal(body.contacts.length, 1);
  assert.equal(body.contacts[0].counterparty, FLOW_CP);
  assert.equal(body.contacts[0].risk, "suspect", "severityByAddress speist die contact-Stufe");
  assert.equal(body.contacts[0].source, "flow-state", "Wissensquelle der Gegenpartei");

  const knowledgeResult = await getThreatKnowledge(opts);
  const ctx = buildCheckCtx(knowledgeResult);
  assert.ok(ctx.knownBad.has(FLOW_CP), "flow-state-Adresse in knownBad");
  assert.ok(ctx.knownBad.has(FLOW_ROLE), "Rolle ohne severity ist ebenfalls knownBad (alle Gelisteten)");
  assert.equal(knowledgeResult.knowledge.get(FLOW_CP).risk, "suspect");
  assert.equal(knowledgeResult.knowledge.get(FLOW_ROLE).role, "collector");
  assert.ok(ctx.firstSeenAt.get(FLOW_CP) === Date.parse(OLD_ISO), "cluster-firstSeen speist firstSeenAt");
});

test("buildCheckCtx: Exchange-Registry-Ausschluss — Registry-Adresse trotz history/flow-state NICHT in knownBad", async () => {
  const opts = knowledgeOpts({
    history: [
      {
        members: [REG_HIST, HIST_MEMBER],
        label: "Clusterfixture",
        firstSeen: Date.parse(OLD_ISO),
        lastSeen: Date.parse(OLD_ISO),
        rules: ["known-bad-hit"],
        severity: "malicious",
      },
    ],
    flowDoc: {
      cursor: 10,
      updatedAt: Date.now(),
      state: {
        clusters: {
          "cluster:flow2": {
            id: "cluster:flow2",
            totalDrops: 100,
            txCount: 1,
            firstSeen: OLD_ISO,
            lastSeen: NOW_ISO,
            memberAddresses: [REG_HIST],
            roles: { [REG_HIST]: "relay" },
            severityByAddress: { [REG_HIST]: "suspect" },
          },
        },
        blocksProcessedTotal: 1,
        lastAdvancedAt: Date.now(),
      },
    },
  });
  const knowledgeResult = await getThreatKnowledge(opts);
  // Guard auf der Wissens-Map selbst (Prüfer-Befund 2026-10-03): Registry-
  // Treffer werden in getThreatKnowledge entfernt, nicht erst in buildCheckCtx.
  assert.ok(!knowledgeResult.knowledge.has(REG_HIST), "Registry-Treffer ist aus der Wissens-Map entfernt");
  const ctx = buildCheckCtx(knowledgeResult);
  assert.ok(!ctx.knownBad.has(REG_HIST), "Registry-Treffer wird aus knownBad ausgeschlossen");
  assert.ok(!ctx.firstSeenAt.has(REG_HIST), "Registry-Member seedet auch firstSeenAt nicht");
  assert.ok(!ctx.history.has(REG_HIST), "Registry-Adresse seedet auch das history-Gedächtnis nicht");
  assert.ok(ctx.knownBad.has(HIST_MEMBER), "Nicht-Registry-Mitglied bleibt in knownBad");
});

// ---------- Registry-Guard auf verdict/contacts (False-Positive-Fix) ----------
// data/history.json enthält reale Exchange-Hot-Wallets als Members (7 Treffer
// registry∩history, Prüfer-Audit 2026-10-03). Diese Adressen sind legitime
// Infrastruktur und dürfen in KEINEM Check-Pfad als Threat erscheinen:
// weder selfListed/'bad' noch als malicious-Kontakt.

test("Registry-Guard: in history gelistete Registry-Adresse wird NICHT selfListed/'bad'", async () => {
  resetCachesForTests();
  const entries = [payEntryFixture(REG_HIST, FLOW_CP, NOW_ISO)];
  setRpc(rpcFor(REG_HIST, entries));
  const opts = knowledgeOpts({
    history: [
      {
        members: [REG_HIST],
        label: "Clusterfixture",
        firstSeen: Date.parse(OLD_ISO),
        lastSeen: Date.parse(OLD_ISO),
        rules: ["known-bad-hit"],
        severity: "malicious",
      },
    ],
  });
  const { status, body } = await checkAddress(REG_HIST, opts);
  assert.equal(status, 200);
  assert.equal(body.selfListed, false, "Registry-Treffer ist nicht gelistet (Map-Filter)");
  assert.notEqual(body.verdict, "bad", "legitime Exchange-Hot-Wallet wird nicht als 'bad' markiert");
  assert.equal(body.verdict, "clean", "Transaktionen vorhanden, keine gelistete Gegenpartei");
});

test("Registry-Guard: Registry-Gegenpartei trotz history-Listing erzeugt keinen contact", async () => {
  resetCachesForTests();
  // HIST_MEMBER erhält eine Zahlung von REG_HIST (Binance-hot, in history
  // gelistet) — der Kontakt darf nicht als Threat-Kontakt erscheinen.
  const entries = [payEntryFixture(REG_HIST, HIST_MEMBER, NOW_ISO)];
  setRpc(rpcFor(HIST_MEMBER, entries));
  const opts = knowledgeOpts({
    history: [
      {
        members: [REG_HIST],
        label: "Clusterfixture",
        firstSeen: Date.parse(OLD_ISO),
        lastSeen: Date.parse(OLD_ISO),
        rules: ["known-bad-hit"],
        severity: "malicious",
      },
    ],
  });
  const { status, body } = await checkAddress(HIST_MEMBER, opts);
  assert.equal(status, 200);
  assert.equal(body.contacts.length, 0, "Registry-Gegenpartei ist aus der Wissens-Map entfernt");
  assert.equal(body.verdict, "clean", "kein malicious-contact -> nicht 'contact'");
});

test("selfListed: 'bad' in beiden Endpunkten (checkAddress + buildAccountReport, identische Daten)", async () => {
  const { buildAccountReport } = await import("./account-report.mjs");
  const entries = [payEntryFixture(SELF_HIST, ENTITY_LINK, NOW_ISO)];
  setRpc(rpcFor(SELF_HIST, entries));
  resetCachesForTests(); // SELF_HIST wurde in einem früheren Test geprüft (checkCache)
  const opts = knowledgeOpts({
    history: [
      {
        members: [SELF_HIST],
        label: "Clusterfixture",
        firstSeen: Date.parse(OLD_ISO),
        lastSeen: Date.parse(OLD_ISO),
        rules: ["drainer-sweep"],
        severity: "malicious",
      },
    ],
  });
  const { status, body } = await checkAddress(SELF_HIST, opts);
  assert.equal(status, 200);
  assert.equal(body.verdict, "bad");
  assert.equal(body.selfListed, true);
  // Derselbe Wissensstand im Konto-Report:
  const knowledgeResult = await getThreatKnowledge(opts);
  const report = buildAccountReport({
    address: SELF_HIST,
    network: "mainnet",
    entries,
    threatsByAddress: knowledgeResult.knowledge,
    truncated: false,
    checkedTxCount: entries.length,
  });
  assert.equal(report.verdict, "bad", "Report und Check widersprechen sich nicht mehr");
  assert.equal(report.selfListed, true);
  assert.ok(report.patterns.includes("known-bad-hit"), "knownBad-Union erreicht die Detektor-Engine");
});

test("Unit-B-Gate: Sweep ohne CreatedNode -> risk 'suspect' + KEIN History-Append; mit CreatedNode -> 'malicious' + Append", async () => {
  // Gegenprobe zum ersten Test: identische Sweeps, nur der CreatedNode-Beleg
  // unterscheidet (lib/detector.mjs:641-642).
  const NO_CREATE = `rTESTNUSWEPX${"A".repeat(17)}6`; // kein l/I/O im Präfix
  const WITH_CREATE = `rTESTCREATED${"A".repeat(17)}7`;
  const noCreateEntries = [
    touchEntry(NO_CREATE, NOW_ISO),
    sweepEntry(NO_CREATE, 95_000, 100_000, NOW_ISO),
    fundingEntry(NO_CREATE, 100_000, NOW_ISO, false),
  ];
  setRpc(rpcFor(NO_CREATE, noCreateEntries));
  ghCalls = [];
  const a = await checkAddress(NO_CREATE);
  assert.equal(a.status, 200);
  assert.equal(a.body.drainer, true, "Sweep wird bestätigt");
  assert.equal(a.body.risk, "suspect", "ohne CreatedNode-Beleg kein 'malicious'");
  assert.equal(
    ghCalls.filter((c) => c.method === "PUT").length,
    0,
    "Append-Gate: suspect-Funde erreichen die malicious-History nie"
  );

  const withCreateEntries = [
    touchEntry(WITH_CREATE, NOW_ISO),
    sweepEntry(WITH_CREATE, 95_000, 100_000, NOW_ISO),
    fundingEntry(WITH_CREATE, 100_000, NOW_ISO, true),
  ];
  setRpc(rpcFor(WITH_CREATE, withCreateEntries));
  ghCalls = [];
  const b = await checkAddress(WITH_CREATE);
  assert.equal(b.status, 200);
  assert.equal(b.body.drainer, true);
  assert.equal(b.body.risk, "malicious", "CreatedNode-belegter Sweep -> 'malicious'");
  const puts = ghCalls.filter((c) => c.method === "PUT");
  assert.equal(puts.length, 1, "malicious-Append genau einmal");
  const merged = JSON.parse(Buffer.from(JSON.parse(puts[0].body).content, "base64").toString("utf8"));
  assert.deepEqual(merged[0].members, [WITH_CREATE]);
  assert.ok(merged[0].rules.includes("drainer-sweep"));
});

test("Wissens-Layer fail-open: ohne Token laufen Check und Knowledge mit injizierten Readern ohne GitHub-Call", async () => {
  const NO_TOKEN = `rTESTNGHCKX${"A".repeat(18)}8`; // kein l/I/O im Präfix
  setRpc(rpcFor(NO_TOKEN, [payEntryFixture(NO_TOKEN, FLOW_CP, NOW_ISO)]));
  ghCalls = [];
  delete process.env.GITHUB_HISTORY_TOKEN;
  try {
    const opts = knowledgeOpts({
      history: [
        {
          members: [NO_TOKEN],
          label: "Clusterfixture",
          firstSeen: Date.parse(OLD_ISO),
          lastSeen: Date.parse(OLD_ISO),
          rules: ["drainer-sweep"],
          severity: "malicious",
        },
      ],
    });
    const { status, body } = await checkAddress(NO_TOKEN, opts);
    assert.equal(status, 200, "fehlende Persistenz ist kein 502 — der Check läuft");
    assert.equal(body.selfListed, true, "injizierte Reader wirken ohne Token");
    assert.equal(ghCalls.length, 0, "injizierte Reader => kein GitHub-Call");
  } finally {
    process.env.GITHUB_HISTORY_TOKEN = "test-token";
  }
});

test("contacts bleiben strikt direkte Gegenparteien: entity-verknüpfte Nicht-Gegenparteien fließen nie ein", async () => {
  // ENTITY_LINK ist in der Entity-Tabelle (regularKey-Signal auf FLOW_CP),
  // aber NIE Gegenpartei der geprüften Adresse — weder contact noch knownBad.
  const ENTITY_ATK = `rTESTENTTYTK${"A".repeat(19)}9`;
  const entries = [payEntryFixture(ENTITY_ATK, ENTITY_LINK, NOW_ISO)];
  setRpc(async (_command, params) => {
    const acc = params?.account;
    if (acc === BAIT) return { transactions: [payEntryFixture(ENTITY_ATK, BAIT, NOW_ISO)] };
    if (acc === ENTITY_ATK || acc === ENTITY_LINK) return { transactions: entries };
    return { transactions: [] };
  });
  resetCachesForTests();
  const knowledgeResult = await getThreatKnowledge();
  assert.ok(knowledgeResult.knowledge.has(ENTITY_ATK), "Angreifer aus live-Ableitung gelistet");
  assert.ok(!knowledgeResult.knowledge.has(ENTITY_LINK), "Entity-Tabelle allein listet nie");
  const { status, body } = await checkAddress(ENTITY_LINK, { readThreats: async () => [...knowledgeResult.knowledge.values()] });
  assert.equal(status, 200);
  assert.equal(body.verdict, "contact", "nur die echte Gegenpartei (ENTITY_ATK) zählt");
  assert.equal(body.contacts.length, 1);
  assert.equal(body.contacts[0].counterparty, ENTITY_ATK);
});

// =====================================================================
// buildEntitySignal: Hub-Guard (Fix 2026-10-04) — dieselbe Semantik wie
// buildEntityLinks (lib/entity-resolve.mjs:227-243): ein Join-Key mit mehr
// als ENTITY_JOIN_KEY_HUB (20) Besitzern vereinigt nie. Unit-Test auf der
// exportierten Testnaht; bestehender sanitizeThreat-Test (:406-411) bleibt
// unberührt.
// =====================================================================

// Base58-sichere Member-Adressen (a..u ohne 'l' als Ziffer-Ersatz).
const HUB_LETTERS = "abcdefghijkmnopqrst";
const hubMembers = (n) =>
  Array.from({ length: n }, (_, i) => `rTESTHUBMEM${HUB_LETTERS[Math.floor(i / 19)]}${HUB_LETTERS[i % 19]}${"A".repeat(19)}9`);
const HUB_RK = `rTESTHUBRK${"A".repeat(22)}5`;

test("buildEntitySignal: Hub-Key (21 Adressen auf einem regularKey) vereinigt nicht — sharedWith leer", () => {
  const members = hubMembers(21);
  const addresses = {};
  for (const a of members) addresses[a] = { regularKey: HUB_RK };
  const signal = buildEntitySignal(members[0], addresses);
  assert.ok(signal, "Signal für tabellierte Adresse existiert");
  assert.deepEqual(signal.regularKeySharedWith, [], "Key mit 21 Besitzern (> ENTITY_JOIN_KEY_HUB 20) wird ignoriert");
});

test("buildEntitySignal: 2 Adressen auf einem regularKey bleiben erhalten (unter der Hub-Schwelle)", () => {
  const [a, b] = hubMembers(2);
  const addresses = { [a]: { regularKey: HUB_RK }, [b]: { regularKey: HUB_RK } };
  const signal = buildEntitySignal(a, addresses);
  assert.deepEqual(signal.regularKeySharedWith, [b], "Join-Key mit 2 Besitzern bleibt — Anzeige und Walk-Union konsistent");
});

// =====================================================================
// TAG-IDENTITÄT im Check-Pfad (hostedAccount, contacts[].destinationTag)
// =====================================================================

const TAG_CP1 = `rTESTTAGCP1${"A".repeat(20)}1`; // gelistete Gegenpartei 1
const TAG_CP2 = `rTESTTAGCP2${"A".repeat(20)}2`; // gelistete Gegenpartei 2
const TAG_CP3 = `rTESTTAGCP3${"A".repeat(20)}3`; // gelistete Gegenpartei 3

function payTagFixture(from, to, time, tag) {
  seq += 1;
  return {
    hash: `TESTTAGF${String(seq).padStart(3, "0")}`,
    ledger_index: 49_200_000 + seq,
    close_time_iso: time,
    validated: true,
    tx_json: {
      TransactionType: "Payment", Account: from, Destination: to, Amount: "1000",
      ...(tag !== undefined ? { DestinationTag: tag } : {}),
    },
    meta: null,
  };
}

test("getExchangeRegistryMap: Map mit Registry-Adressen (fail-open, kein Wurf)", () => {
  resetCachesForTests();
  const map = getExchangeRegistryMap();
  assert.ok(map instanceof Map);
  assert.ok(map.size > 0, "echte public/data/exchange-registry.json ist lesbar");
  assert.ok(map.has(REG_HIST), "Binance-Hot-Wallet (REG_HIST) ist in der Map");
  const entry = map.get(REG_HIST);
  assert.equal(entry.exchange, "Binance");
  assert.equal(typeof entry.requireDestTag, "boolean");
});

test("Check auf Registry-Konto: contacts[].destinationTag zeigt Hosted-Sub-Konto, hostedAccount.transit bei 2 Tags", async () => {
  resetCachesForTests();
  // Die GEPÜFTE Adresse ist die Binance-Hot-Wallet (Registry-Multi-User-
  // Konto); die Gegenparteien sind gelistete Test-Adressen (Kontakt nötig,
  // damit die Zeile überhaupt existiert).
  const entries = [
    payTagFixture(TAG_CP1, REG_HIST, NOW_ISO, 111),
    payTagFixture(TAG_CP2, REG_HIST, NOW_ISO, 222),
    payTagFixture(TAG_CP3, REG_HIST, NOW_ISO, undefined),
  ];
  setRpc(rpcFor(REG_HIST, entries));
  const opts = knowledgeOpts({
    threats: [
      { address: TAG_CP1, risk: "suspect", reason: "fixture", sources: ["bait"] },
      { address: TAG_CP2, risk: "suspect", reason: "fixture", sources: ["bait"] },
      { address: TAG_CP3, risk: "suspect", reason: "fixture", sources: ["bait"] },
    ],
  });
  const { status, body } = await checkAddress(REG_HIST, opts);
  assert.equal(status, 200);
  assert.ok(body.hostedAccount, "Registry-geprüfte Adresse erhält hostedAccount");
  assert.equal(body.hostedAccount.exchange, "Binance");
  assert.equal(body.hostedAccount.transit, true, "Tags 111/222/kein Tag -> >= 2 Identitäten");
  assert.equal(body.contacts.length, 3);
  const c111 = body.contacts.find((c) => c.counterparty === TAG_CP1);
  const c222 = body.contacts.find((c) => c.counterparty === TAG_CP2);
  const cNone = body.contacts.find((c) => c.counterparty === TAG_CP3);
  assert.equal(c111.destinationTag, 111, "eingehender Payment-Tag auf der Kontaktzeile");
  assert.equal(c222.destinationTag, 222);
  assert.ok(!("destinationTag" in cNone), "fehlender Tag -> kein Feld");
  assert.ok(!("sourceTag" in c111), "eingehend trägt nie sourceTag");
  // Score-/verdict-frei: hostedAccount ändert nichts am Urteil.
  assert.equal(body.verdict, "contact");
});

test("Check auf Registry-Konto ohne Tag-Historie: hostedAccount.transit false", async () => {
  resetCachesForTests();
  const entries = [payTagFixture(TAG_CP1, REG_HIST, NOW_ISO, undefined)];
  setRpc(rpcFor(REG_HIST, entries));
  const opts = knowledgeOpts({
    threats: [{ address: TAG_CP1, risk: "suspect", reason: "fixture", sources: ["bait"] }],
  });
  const { body } = await checkAddress(REG_HIST, opts);
  assert.ok(body.hostedAccount);
  assert.equal(body.hostedAccount.transit, false, "eine Identität ('kein Tag') -> kein transit");
});

test("Check auf NICHT-Registry-Adresse: kein hostedAccount, keine Tag-Felder an contacts", async () => {
  resetCachesForTests();
  const entries = [payTagFixture(TAG_CP1, HIST_MEMBER, NOW_ISO, 111)];
  setRpc(rpcFor(HIST_MEMBER, entries));
  const opts = knowledgeOpts({
    threats: [{ address: TAG_CP1, risk: "suspect", reason: "fixture", sources: ["bait"] }],
  });
  const { body } = await checkAddress(HIST_MEMBER, opts);
  assert.ok(!("hostedAccount" in body), "ohne Registry-Treffer kein hostedAccount-Feld");
  assert.equal(body.contacts.length, 1);
  assert.ok(!("destinationTag" in body.contacts[0]), "Tag-Feld nur bei Registry-geprüfter Adresse");
});

test("TrustSet/OfferCreate erhalten nie ein Tag-Feld (per Spec ohne DestinationTag)", async () => {
  resetCachesForTests();
  const entries = [
    {
      hash: "TESTTRUST1", ledger_index: 49_250_001, close_time_iso: NOW_ISO, validated: true,
      tx_json: {
        TransactionType: "TrustSet", Account: TAG_CP1,
        LimitAmount: { issuer: HIST_MEMBER, currency: "USD", value: "10" },
        DestinationTag: 111, // absichtlich fehlplatziert — darf nie durchkommen
      },
      meta: null,
    },
  ];
  setRpc(rpcFor(HIST_MEMBER, entries));
  const opts = knowledgeOpts({
    threats: [{ address: TAG_CP1, risk: "suspect", reason: "fixture", sources: ["bait"] }],
  });
  const { body } = await checkAddress(HIST_MEMBER, opts);
  assert.equal(body.contacts.length, 1);
  assert.equal(body.contacts[0].txType, "TrustSet");
  assert.ok(!("destinationTag" in body.contacts[0]), "TrustSet-Zeile bleibt tag-frei");
});

// ============================================================================
// Multi-User-Union (getMultiUserAccountsMap, Coverage-Fix 2026-10-05):
// Registry ∪ NUR-verifizierte well-known-Namen; Kollision -> Registry gewinnt;
// getExchangeRegistryMap bleibt die REINE Registry-Map. Fetch über einen
// globalThis.fetch-Stub (lib/name-resolve.mjs fetchWellKnownMap holt erst zur
// Aufrufzeit) — kein echter Endpunkt wird getroffen.
// ============================================================================

const WK_URL = "https://api.xrpscan.com/api/v1/names/well-known";
// Echte well-known-verifizierte Adresse, die NICHT in der 81-Einträge-
// Registry liegt (der gemeldete Gap-Fall: Binance-Konten ohne toTag).
const WK_VERIFIED = "rNxp4h8apvRis6mJf9Sh8C6iRxfrDWN7AV";
const WK_UNVERIFIED = `rTESTWKUNVERIF${"A".repeat(18)}8`; // verified fehlt -> nie in der Union

let wkCalls = 0;
function installWellKnownFetch(fixture) {
  const prev = globalThis.fetch;
  globalThis.fetch = async (url) => {
    if (String(url) === WK_URL) {
      wkCalls += 1;
      return { ok: true, json: async () => fixture };
    }
    if (typeof prev === "function") return prev(url);
    throw new Error("unexpected fetch url: " + url);
  };
  return () => {
    if (prev === undefined) delete globalThis.fetch;
    else globalThis.fetch = prev;
  };
}

test("getMultiUserAccountsMap: Registry ∪ verifizierte well-known-Namen, unverifizierte ausgeschlossen", async () => {
  resetCachesForTests();
  wkCalls = 0;
  const restore = installWellKnownFetch([
    { account: WK_VERIFIED, name: "Binance-Cold-Test", domain: "binance.com", verified: true },
    { account: WK_UNVERIFIED, name: "Unverified Name", domain: "example.com" },
    // Kollision mit der echten Registry (REG_HIST = Binance hot): Registry gewinnt.
    { account: REG_HIST, name: "Nicht-Registry-Name", domain: "example.org", verified: true },
  ]);
  try {
    const merged = await getMultiUserAccountsMap();
    assert.ok(merged instanceof Map);
    const wk = merged.get(WK_VERIFIED);
    assert.ok(wk, "verifizierte well-known-Adresse ist in der Union");
    assert.equal(wk.exchange, "Binance-Cold-Test");
    assert.equal(wk.confidence, "well-known");
    assert.equal(wk.requireDestTag, false);
    assert.equal(wk.tier, null);
    assert.ok(!merged.has(WK_UNVERIFIED), "unverifizierte well-known-Adresse bleibt draußen");
    assert.equal(merged.get(REG_HIST).exchange, "Binance", "Kollision: Registry-Eintrag gewinnt");
    assert.ok(!("confidence" in merged.get(REG_HIST)), "Registry-Eintrag trägt kein well-known-Feld");
    // Session-Guard (TTL ~10 min): zweiter Aufruf ohne neuen Fetch.
    const again = await getMultiUserAccountsMap();
    assert.equal(again, merged);
    assert.equal(wkCalls, 1, "GENAU EIN well-known-Fetch pro TTL-Fenster");
  } finally {
    restore();
  }
});

test("getExchangeRegistryMap bleibt Registry-only (keine well-known-Erweiterung)", () => {
  resetCachesForTests();
  const reg = getExchangeRegistryMap();
  assert.ok(reg instanceof Map);
  assert.ok(reg.has(REG_HIST), "Registry-Member weiterhin drin");
  assert.ok(!reg.has(WK_VERIFIED), "well-known-only-Adresse NICHT in der reinen Registry-Map");
  assert.equal(reg.get(REG_HIST).exchange, "Binance", "Registry-Shape unverändert");
});

test("getMultiUserAccountsMap fail-open: Fetch-Fehler -> Union == reine Registry, kein Wurf", async () => {
  resetCachesForTests();
  const prev = globalThis.fetch;
  globalThis.fetch = async () => {
    throw new Error("netz weg");
  };
  try {
    const merged = await getMultiUserAccountsMap();
    const reg = getExchangeRegistryMap();
    assert.ok(merged instanceof Map);
    assert.equal(merged.size, reg.size, "ohne well-known-Stand: Union == Registry");
    assert.ok(!merged.has(WK_VERIFIED), "keine well-known-Erweiterung ohne Stand");
  } finally {
    if (prev === undefined) delete globalThis.fetch;
    else globalThis.fetch = prev;
  }
});
