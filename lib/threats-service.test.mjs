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
const { checkAddress, checkDrainerSweepFromEntries, setRpc } = svc;

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
function fundingEntry(toucher, drops, time) {
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
    meta: null,
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
  const entries = [
    touchEntry(VISITOR_A, NOW_ISO),
    sweepEntry(VISITOR_A, 95_000, 100_000, NOW_ISO),
    fundingEntry(VISITOR_A, 100_000, NOW_ISO),
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
