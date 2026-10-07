// lib/detector.test.mjs — node:test-Unit-Tests mit synthetischen Fixtures.
// Pro Regel: mindestens ein Treffer-Fall UND ein benign-Guard-Fall.
// Zusätzlich analyzeLedger mit künstlichem Ledger + hash-only + Container-Formen.
//
// Ausführen: node --test lib/detector.test.mjs
import test from "node:test";
import assert from "node:assert/strict";
import { analyzeTx, analyzeLedger, ruleCatalog, DEFAULT_THRESHOLDS } from "./detector.mjs";

const hex = (s) => Buffer.from(s, "utf8").toString("hex");
const NOW = Date.now();
const freshMap = (...addrs) => new Map(addrs.map((a) => [a, NOW - 60_000])); // Alter 1 min < 15 min

// Synthetische Adressen (keine echten, keine Köder).
const R = {
  sender: "rTESTSENDER0000000000000000000001",
  dest: "rTESTDEST000000000000000000000002",
  bad: "rTESTBAD00000000000000000000000003",
  gateway: "rTESTGATEWAY00000000000000000004",
  collector: "rTESTCOLLECTOR00000000000000000005",
  drain: "rTESTDRAIN000000000000000000000006",
  spam: "rTESTSPAM0000000000000000000000007",
};

const has = (findings, ruleId) => findings.some((f) => f.ruleId === ruleId);
const sev = (findings, ruleId) => findings.find((f) => f.ruleId === ruleId)?.severity;

// ---------- known-bad-hit ----------
test("known-bad-hit: Treffer bei bekannt-maliziöser Adresse", () => {
  const tx = { TransactionType: "Payment", Account: R.bad, Destination: R.dest, Amount: "500000" };
  const f = analyzeTx(tx, null, { knownBad: new Set([R.bad]) });
  assert.ok(has(f, "known-bad-hit"));
  assert.equal(sev(f, "known-bad-hit"), "malicious");
});
test("known-bad-hit: Guard — unbekannte Adresse liefert keinen Fund", () => {
  const tx = { TransactionType: "Payment", Account: R.sender, Destination: R.dest, Amount: "500000" };
  const f = analyzeTx(tx, null, { knownBad: new Set() });
  assert.ok(!has(f, "known-bad-hit"));
});

// ---------- memo-phishing ----------
test("memo-phishing: Treffer URL + claim-Keyword", () => {
  const tx = {
    TransactionType: "Payment", Account: R.sender, Destination: R.dest, Amount: "100000",
    Memos: [{ Memo: { MemoData: hex("Claim your airdrop at http://evil.example/claim") } }],
  };
  const f = analyzeTx(tx, null, {});
  assert.ok(has(f, "memo-phishing"));
  assert.equal(sev(f, "memo-phishing"), "malicious");
});
test("memo-phishing: Treffer Seed-Muster", () => {
  const tx = {
    TransactionType: "Payment", Account: R.sender, Destination: R.dest, Amount: "100000",
    Memos: [{ Memo: { MemoData: hex("backup skeyA2CDEFGHJKLMNPQRSTUVWXYZ") } }],
  };
  const f = analyzeTx(tx, null, {});
  assert.ok(has(f, "memo-phishing"));
});
test("memo-phishing: Treffer modernes sEd-Seed-Muster", () => {
  const tx = {
    TransactionType: "Payment", Account: R.sender, Destination: R.dest, Amount: "100000",
    Memos: [{ Memo: { MemoData: hex("backup sEdTP9WGJLr2N8QjKZbGwDvKZ3sT") } }],
  };
  const f = analyzeTx(tx, null, {});
  assert.ok(has(f, "memo-phishing"));
});
test("memo-phishing: Guard (FP-Regression) — legitimes deutsches Geschäfts-Memo (URL + 'abheben') ist benign", () => {
  const tx = {
    TransactionType: "Payment", Account: R.sender, Destination: R.dest, Amount: "100000",
    Memos: [{ Memo: { MemoData: hex("Gehalt abheben unter https://firma.example/lohn") } }],
  };
  const f = analyzeTx(tx, null, {});
  assert.ok(!has(f, "memo-phishing"));
});
test("memo-phishing: Guard — reine Referenz-ID/JSON-Memo ist benign", () => {
  const tx = {
    TransactionType: "Payment", Account: R.sender, Destination: R.dest, Amount: "100000",
    Memos: [{ Memo: { MemoData: hex("order-12345 invoice-ref") } }],
  };
  const f = analyzeTx(tx, null, {});
  assert.ok(!has(f, "memo-phishing"));
});
test("memo-phishing: Guard — URL ohne claim-Keyword ist benign", () => {
  const tx = {
    TransactionType: "Payment", Account: R.sender, Destination: R.dest, Amount: "100000",
    Memos: [{ Memo: { MemoData: hex("https://example.com/receipt") } }],
  };
  const f = analyzeTx(tx, null, {});
  assert.ok(!has(f, "memo-phishing"));
});

// ---------- airdrop-trustset-spam (Massenmuster in analyzeLedger) ----------
test("airdrop-trustset-spam: Treffer Massenmuster — >= 5 Konten mit winzigem Limit auf denselben Issuer", () => {
  const accts = ["A1", "A2", "A3", "A4", "A5"].map((s) => `rTESTTS${s}000000000000000000000`);
  const txs = accts.map((a) => ({ TransactionType: "TrustSet", Account: a, LimitAmount: { value: "0.5", currency: "FAKE", issuer: R.spam } }));
  const r = analyzeLedger({ transactions: txs }, {});
  assert.ok(has(r.findings, "airdrop-trustset-spam"));
  assert.equal(sev(r.findings, "airdrop-trustset-spam"), "suspect");
});
test("airdrop-trustset-spam: Guard — 4 winzige TrustSets (unter Massen-Schwelle) kein Fund", () => {
  const accts = ["A1", "A2", "A3", "A4"].map((s) => `rTESTTS${s}000000000000000000000`);
  const txs = accts.map((a) => ({ TransactionType: "TrustSet", Account: a, LimitAmount: { value: "0.5", currency: "FAKE", issuer: R.spam } }));
  const r = analyzeLedger({ transactions: txs }, {});
  assert.ok(!has(r.findings, "airdrop-trustset-spam"));
});
test("airdrop-trustset-spam: Guard (FP-Regression) — Trustline-Entfernung (Limit '0', fremder Issuer) ist benign", () => {
  const tx = { TransactionType: "TrustSet", Account: R.sender, LimitAmount: { value: "0", currency: "XYZ", issuer: R.gateway } };
  const r = analyzeLedger({ transactions: [tx, tx, tx, tx, tx] }, {});
  assert.ok(!has(r.findings, "airdrop-trustset-spam"));
});
test("airdrop-trustset-spam: Guard (FP-Regression) — einzelne winzige Trustline (0.5) eines unbekannten Issuers ist benign", () => {
  const tx = { TransactionType: "TrustSet", Account: R.sender, LimitAmount: { value: "0.5", currency: "XYZ", issuer: R.gateway } };
  const f = analyzeTx(tx, null, { benignIssuers: new Set() });
  assert.ok(!has(f, "airdrop-trustset-spam"));
});
test("airdrop-trustset-spam: Guard — normales Limit (live-Guardwert 1.4785) ist benign", () => {
  const tx = { TransactionType: "TrustSet", Account: R.sender, LimitAmount: { value: "1.4785", currency: "USD", issuer: R.gateway } };
  const f = analyzeTx(tx, null, { benignIssuers: new Set() });
  assert.ok(!has(f, "airdrop-trustset-spam"));
});
test("airdrop-trustset-spam: Guard — Trustline-Entfernung (Account===issuer) ist benign", () => {
  const tx = { TransactionType: "TrustSet", Account: R.gateway, LimitAmount: { value: "0", currency: "XYZ", issuer: R.gateway } };
  const f = analyzeTx(tx, null, {});
  assert.ok(!has(f, "airdrop-trustset-spam"));
});
test("airdrop-trustset-spam: Guard — benignIssuer-Whitelist unterdrückt Massenmuster", () => {
  const accts = ["A1", "A2", "A3", "A4", "A5"].map((s) => `rTESTTS${s}000000000000000000000`);
  const txs = accts.map((a) => ({ TransactionType: "TrustSet", Account: a, LimitAmount: { value: "0.5", currency: "USDC", issuer: R.gateway } }));
  const r = analyzeLedger({ transactions: txs }, { benignIssuers: new Set([R.gateway]) });
  assert.ok(!has(r.findings, "airdrop-trustset-spam"));
});

// ---------- dusting (Ledger-Ebene; Einzel-Zahlung ist kein Fund) ----------
test("dusting: Treffer >= 2 Mini-Zahlungen an frische Ziele im Ledger", () => {
  const d1 = "rTESTDUSTFRESHA000000000000001";
  const d2 = "rTESTDUSTFRESHB000000000000002";
  const txs = [d1, d2].map((d) => ({ TransactionType: "Payment", Account: R.sender, Destination: d, Amount: "99" }));
  const r = analyzeLedger({ transactions: txs }, { firstSeenAt: freshMap(d1, d2) });
  assert.ok(has(r.findings, "dusting"));
  assert.equal(sev(r.findings, "dusting"), "suspect");
});
test("dusting: Guard (FP-Regression) — eine einzelne Mini-Zahlung an ein frisches Konto ist benign", () => {
  const txs = [{ TransactionType: "Payment", Account: R.sender, Destination: R.dest, Amount: "99" }];
  const r = analyzeLedger({ transactions: txs }, { firstSeenAt: freshMap(R.dest) });
  assert.ok(!has(r.findings, "dusting"));
});
test("dusting: Guard — ohne Frische-Signal und < 3 Ziele kein Fund", () => {
  const txs = [{ TransactionType: "Payment", Account: R.sender, Destination: R.dest, Amount: "99" }];
  const r = analyzeLedger({ transactions: txs }, { firstSeenAt: new Map() });
  assert.ok(!has(r.findings, "dusting"));
});
test("dusting: Guard — über Bagatellgrenze (1000 drops) kein Fund", () => {
  const d1 = "rTESTDUSTFRESHA000000000000001";
  const d2 = "rTESTDUSTFRESHB000000000000002";
  const txs = [d1, d2].map((d) => ({ TransactionType: "Payment", Account: R.sender, Destination: d, Amount: String(DEFAULT_THRESHOLDS.dustDrops + 1) }));
  const r = analyzeLedger({ transactions: txs }, { firstSeenAt: freshMap(d1, d2) });
  assert.ok(!has(r.findings, "dusting"));
});
test("dusting: Guard — benignAccounts-Ausnahme", () => {
  const d1 = "rTESTDUSTFRESHA000000000000001";
  const d2 = "rTESTDUSTFRESHB000000000000002";
  const txs = [d1, d2].map((d) => ({ TransactionType: "Payment", Account: R.sender, Destination: d, Amount: "99" }));
  const r = analyzeLedger({ transactions: txs }, { firstSeenAt: freshMap(d1, d2), benignAccounts: new Set([d1, d2]) });
  assert.ok(!has(r.findings, "dusting"));
});

// ---------- drainer-sweep ----------
// meta enthält CreatedNode AccountRoot für R.drain: das Konto wurde im
// Fenster erst erstellt -> echter Erstellungsbeleg -> severity 'malicious'.
// Reines firstSeenAt-Signal (ohne CreatedNode) liefert nur 'suspect'.
const drainMeta = {
  AffectedNodes: [
    { CreatedNode: { LedgerEntryType: "AccountRoot", LedgerEntry: { Account: R.drain } } },
    { ModifiedNode: { LedgerEntryType: "AccountRoot", PreviousFields: { Balance: "100000" }, FinalFields: { Balance: "5000" } } },
  ],
};
test("drainer-sweep: Treffer frisch finanziert + >=90% Sweep", () => {
  const ledger = {
    transactions: [
      { TransactionType: "Payment", Account: R.sender, Destination: R.drain, Amount: "100000" },
      { TransactionType: "Payment", Account: R.drain, Destination: R.collector, Amount: "95000", meta: drainMeta },
    ],
  };
  const r = analyzeLedger(ledger, { firstSeenAt: freshMap(R.drain) });
  assert.ok(has(r.findings, "drainer-sweep"));
  assert.equal(sev(r.findings, "drainer-sweep"), "malicious");
});
test("drainer-sweep: Guard — ohne Frische-Signal kein Fund", () => {
  const ledger = {
    transactions: [
      { TransactionType: "Payment", Account: R.sender, Destination: R.drain, Amount: "100000" },
      { TransactionType: "Payment", Account: R.drain, Destination: R.collector, Amount: "95000", meta: drainMeta },
    ],
  };
  const r = analyzeLedger(ledger, { firstSeenAt: new Map() });
  assert.ok(!has(r.findings, "drainer-sweep"));
});
test("drainer-sweep: Guard — nur 50% Sweep ist benign", () => {
  const ledger = {
    transactions: [
      { TransactionType: "Payment", Account: R.sender, Destination: R.drain, Amount: "100000" },
      { TransactionType: "Payment", Account: R.drain, Destination: R.collector, Amount: "50000", meta: drainMeta },
    ],
  };
  const r = analyzeLedger(ledger, { firstSeenAt: freshMap(R.drain) });
  assert.ok(!has(r.findings, "drainer-sweep"));
});
test("drainer-sweep: Guard (FP-Regression HIGH) — frisches Konto mit 3 Futter-Zahlungen + 83%-Zahlung ist benign", () => {
  const meta83 = { AffectedNodes: [{ ModifiedNode: { LedgerEntryType: "AccountRoot", PreviousFields: { Balance: "100000" }, FinalFields: { Balance: "17000" } } }] };
  const ledger = {
    transactions: [
      { TransactionType: "Payment", Account: R.sender, Destination: R.drain, Amount: "100" },
      { TransactionType: "Payment", Account: R.sender, Destination: R.drain, Amount: "100" },
      { TransactionType: "Payment", Account: R.sender, Destination: R.drain, Amount: "100" },
      { TransactionType: "Payment", Account: R.drain, Destination: R.collector, Amount: "83000", meta: meta83 },
    ],
  };
  const r = analyzeLedger(ledger, { firstSeenAt: freshMap(R.drain) });
  assert.ok(!has(r.findings, "drainer-sweep"));
});
test("drainer-sweep: Guard — benignAccounts-Ausnahme", () => {
  const ledger = {
    transactions: [
      { TransactionType: "Payment", Account: R.sender, Destination: R.drain, Amount: "100000" },
      { TransactionType: "Payment", Account: R.drain, Destination: R.collector, Amount: "95000", meta: drainMeta },
    ],
  };
  const r = analyzeLedger(ledger, { firstSeenAt: freshMap(R.drain), benignAccounts: new Set([R.drain]) });
  assert.ok(!has(r.findings, "drainer-sweep"));
});

// ---------- fake-nft-fraud ----------
test("fake-nft-fraud: Treffer Phishing-URI (Kurzlink/claim)", () => {
  const tx = { TransactionType: "NFTokenMint", Account: R.sender, Issuer: R.sender, URI: hex("https://bit.ly/claim-nft") };
  const f = analyzeTx(tx, null, {});
  assert.ok(has(f, "fake-nft-fraud"));
  assert.equal(sev(f, "fake-nft-fraud"), "suspect");
});
test("fake-nft-fraud: Guard — normale Galerie-URI ohne claim ist benign", () => {
  const tx = { TransactionType: "NFTokenMint", Account: R.sender, Issuer: R.sender, URI: hex("https://gallery.example/art.png") };
  const f = analyzeTx(tx, null, {});
  assert.ok(!has(f, "fake-nft-fraud"));
});
test("fake-nft-fraud: Guard — Mint ohne URI ist benign", () => {
  const tx = { TransactionType: "NFTokenMint", Account: R.sender, Issuer: R.sender };
  const f = analyzeTx(tx, null, {});
  assert.ok(!has(f, "fake-nft-fraud"));
});
test("fake-nft-fraud: Treffer Nullwert-Accept-Burst (>=10) im Ledger", () => {
  const zeroMeta = { AffectedNodes: [{ ModifiedNode: { LedgerEntryType: "NFTokenOffer", FinalFields: { Amount: "0" } } }] };
  const txs = Array.from({ length: 10 }, () => ({ TransactionType: "NFTokenAcceptOffer", Account: R.sender, NFTokenSellOffer: "ABC", meta: zeroMeta }));
  const r = analyzeLedger({ transactions: txs }, {});
  assert.ok(has(r.findings, "fake-nft-fraud"));
});
test("fake-nft-fraud: Guard (FP-Regression) — 5 Gratis-Claims unter der Schwelle sind benign", () => {
  const zeroMeta = { AffectedNodes: [{ ModifiedNode: { LedgerEntryType: "NFTokenOffer", FinalFields: { Amount: "0" } } }] };
  const txs = Array.from({ length: 5 }, () => ({ TransactionType: "NFTokenAcceptOffer", Account: R.sender, NFTokenSellOffer: "ABC", meta: zeroMeta }));
  const r = analyzeLedger({ transactions: txs }, {});
  assert.ok(!has(r.findings, "fake-nft-fraud"));
});

// ---------- offer-spam ----------
test("offer-spam: Treffer >=10 OfferCreate ohne Fill", () => {
  const txs = Array.from({ length: 10 }, () => ({ TransactionType: "OfferCreate", Account: R.spam, meta: { AffectedNodes: [] } }));
  const r = analyzeLedger({ transactions: txs }, {});
  assert.ok(has(r.findings, "offer-spam"));
  assert.equal(sev(r.findings, "offer-spam"), "info");
});
test("offer-spam: Guard (FP-Regression) — 3 Limit-Orders ohne Fill sind normaler Market-Maker-Betrieb", () => {
  const txs = [
    { TransactionType: "OfferCreate", Account: R.spam, meta: { AffectedNodes: [] } },
    { TransactionType: "OfferCancel", Account: R.spam, meta: { AffectedNodes: [] } },
    { TransactionType: "OfferCreate", Account: R.spam, meta: { AffectedNodes: [] } },
    { TransactionType: "OfferCreate", Account: R.spam, meta: { AffectedNodes: [] } },
  ];
  const r = analyzeLedger({ transactions: txs }, {});
  assert.ok(!has(r.findings, "offer-spam"));
});
test("offer-spam: Guard (FP-Regression) — OfferCancel-Kaskade ohne Creates ist benign", () => {
  const txs = [1, 2, 3, 4].map(() => ({ TransactionType: "OfferCancel", Account: R.spam, meta: { AffectedNodes: [] } }));
  const r = analyzeLedger({ transactions: txs }, {});
  assert.ok(!has(r.findings, "offer-spam"));
});
test("offer-spam: Guard — mit Fill (OfferCreated) kein Fund", () => {
  const fillMeta = { AffectedNodes: [{ CreatedNode: { LedgerEntryType: "Offer", LedgerEntry: {} } }] };
  const txs = [
    { TransactionType: "OfferCreate", Account: R.spam, meta: fillMeta },
    { TransactionType: "OfferCreate", Account: R.spam, meta: { AffectedNodes: [] } },
    { TransactionType: "OfferCreate", Account: R.spam, meta: { AffectedNodes: [] } },
  ];
  const r = analyzeLedger({ transactions: txs }, {});
  assert.ok(!has(r.findings, "offer-spam"));
});

// ---------- escrow-check-bait ----------
test("escrow-check-bait: Treffer winziger Escrow + Phishing-Memo an frisches Ziel", () => {
  const tx = {
    TransactionType: "EscrowCreate", Account: R.sender, Destination: R.dest, Amount: "99",
    Memos: [{ Memo: { MemoData: hex("verify your wallet to claim at http://phish.example") } }],
  };
  const f = analyzeTx(tx, null, { firstSeenAt: freshMap(R.dest) });
  assert.ok(has(f, "escrow-check-bait"));
  assert.equal(sev(f, "escrow-check-bait"), "suspect");
});
test("escrow-check-bait: Guard — Einzel-Escrow ohne Muster ist benign", () => {
  const tx = { TransactionType: "EscrowCreate", Account: R.sender, Destination: R.dest, Amount: "1000000000" };
  const f = analyzeTx(tx, null, { firstSeenAt: freshMap(R.dest) });
  assert.ok(!has(f, "escrow-check-bait"));
});
test("escrow-check-bait: Treffer Burst >=3 frische Ziele im Ledger", () => {
  const d1 = "rTESTESCROW00000000000000000000A1";
  const d2 = "rTESTESCROW00000000000000000000A2";
  const d3 = "rTESTESCROW00000000000000000000A3";
  const memo = [{ Memo: { MemoData: hex("verify your wallet to claim at http://phish.example") } }];
  const txs = [d1, d2, d3].map((d) => ({ TransactionType: "CheckCreate", Account: R.sender, Destination: d, Amount: "99", Memos: memo }));
  const r = analyzeLedger({ transactions: txs }, { firstSeenAt: freshMap(d1, d2, d3) });
  assert.ok(has(r.findings, "escrow-check-bait"));
});
test("escrow-check-bait: Guard (FP-Regression) — Burst winziger Escrows OHNE Phishing-Memo ist benign", () => {
  const d1 = "rTESTESCROW00000000000000000000B1";
  const d2 = "rTESTESCROW00000000000000000000B2";
  const d3 = "rTESTESCROW00000000000000000000B3";
  const txs = [d1, d2, d3].map((d) => ({ TransactionType: "CheckCreate", Account: R.sender, Destination: d, Amount: "99" }));
  const r = analyzeLedger({ transactions: txs }, { firstSeenAt: freshMap(d1, d2, d3) });
  assert.ok(!has(r.findings, "escrow-check-bait"));
});

// ---------- payment-burst ----------
test("payment-burst: Treffer >=5 Ziele mit winzigen Beträgen", () => {
  const dests = ["A1", "A2", "A3", "A4", "A5"].map((s) => `rTESTBURST00000000000000000000${s}`);
  const txs = dests.map((d) => ({ TransactionType: "Payment", Account: R.sender, Destination: d, Amount: "99" }));
  const r = analyzeLedger({ transactions: txs }, {});
  assert.ok(has(r.findings, "payment-burst"));
  assert.equal(sev(r.findings, "payment-burst"), "suspect");
});
test("payment-burst: Guard — Lohnverteilung (große Beträge, ohne Frische/knownBad) ist benign", () => {
  const dests = ["B1", "B2", "B3", "B4", "B5"].map((s) => `rTESTPAY000000000000000000000${s}`);
  const txs = dests.map((d) => ({ TransactionType: "Payment", Account: R.sender, Destination: d, Amount: "100000000" }));
  const r = analyzeLedger({ transactions: txs }, {});
  assert.ok(!has(r.findings, "payment-burst"));
});
test("payment-burst: Guard (FP-Regression) — 5 große Zahlungen, ein Ziel frisch, ist benign", () => {
  const dests = ["B1", "B2", "B3", "B4", "B5"].map((s) => `rTESTPAY000000000000000000000${s}`);
  const txs = dests.map((d) => ({ TransactionType: "Payment", Account: R.sender, Destination: d, Amount: "100000000" }));
  const r = analyzeLedger({ transactions: txs }, { firstSeenAt: freshMap(dests[0]) });
  assert.ok(!has(r.findings, "payment-burst"));
});

// ---------- analyzeLedger: hash-only + Container-Formen ----------
test("analyzeLedger: hash-only (JSON-RPC result.ledger.transactions) liefert stats ohne Funde", () => {
  const r = analyzeLedger({ result: { ledger: { transactions: ["H1", "H2", "H3"] } } }, {});
  assert.equal(r.stats.txs, 3);
  assert.equal(r.findings.length, 0);
  assert.equal(r.hashOnly, true);
});
test("analyzeLedger: rohes WSS-Event {type:'ledger', transactions:[hashes]}", () => {
  const r = analyzeLedger({ type: "ledger", ledger_index: 123, transactions: ["H1", "H2"] }, {});
  assert.equal(r.stats.txs, 2);
  assert.equal(r.hashOnly, true);
});
test("analyzeLedger: {tx_json,meta}-Container-Form wird analysiert", () => {
  const entry = { tx_json: { TransactionType: "Payment", Account: R.bad, Destination: R.dest, Amount: "1000" }, meta: null };
  const r = analyzeLedger({ transactions: [entry] }, { knownBad: new Set([R.bad]) });
  assert.ok(has(r.findings, "known-bad-hit"));
  assert.equal(r.stats.txs, 1);
});
test("analyzeLedger: künstlicher Ledger mit Dusting-Burst + Stats", () => {
  const dests = ["C1", "C2", "C3"].map((s) => `rTESTDUST000000000000000000000${s}`);
  const txs = dests.map((d) => ({ TransactionType: "Payment", Account: R.sender, Destination: d, Amount: "99" }));
  const r = analyzeLedger({ ledger: { transactions: txs } }, {});
  assert.ok(has(r.findings, "dusting"));
  assert.equal(r.stats.txs, 3);
  assert.equal(r.stats.findings, r.findings.length);
});

// ---------- ruleCatalog ----------
// 15 Regeln seit Kritik-Runde 3 (T1.2): + amm-wash-swap, thin-pool-exploit,
// spoof-offer-cycle (DEX/AMM-Manipulation, Tx-Ebene, severity 'suspect').
test("ruleCatalog: 15 Regeln mit gültigem severity-Enum", () => {
  const cat = ruleCatalog();
  assert.equal(cat.length, 15);
  for (const r of cat) {
    assert.ok(["malicious", "suspect", "info"].includes(r.severity), `severity ${r.severity}`);
    assert.ok(r.id && r.name);
  }
});

// Peeling-Plan (Grenze 1): Katalog-Konsistenz — die Regel lebt als
// Cluster-Regel (lib/cluster.mjs detectPeelingChains), der Katalogeintrag
// speist api/rules.js und den Regelfilter.
test("ruleCatalog: enthält 'peeling-chain' mit severity 'suspect'", () => {
  const cat = ruleCatalog();
  const r = cat.find((x) => x.id === "peeling-chain");
  assert.ok(r, "peeling-chain im Katalog");
  assert.equal(r.severity, "suspect");
  assert.ok(/Peeling-Kette/.test(r.name), "deutscher Katalogname");
});

// V4 (wash-cycle): Maschinerie-Präzedenz wie peeling-chain — die Motiv-
// Erkennung lebt in lib/cluster.mjs (motifCounters über die akkumulierten
// Flow-State-Kanten, lib/ledger-walk.mjs mergeCluster), analyzeTx/
// analyzeLedger bleiben unverändert; der Eintrag speist api/rules.js.
test("ruleCatalog: enthält 'wash-cycle' mit severity 'suspect'", () => {
  const cat = ruleCatalog();
  const r = cat.find((x) => x.id === "wash-cycle");
  assert.ok(r, "wash-cycle im Katalog");
  assert.equal(r.severity, "suspect");
  assert.ok(/Wash-Zyklus/.test(r.name), "deutscher Katalogname");
  assert.equal(cat.filter((x) => x.id === "wash-cycle").length, 1, "kein Duplikat");
});

// ---------- Additive Übersetzungsfelder noteKey/noteParams ----------
// Die deutsche note bleibt unverändert (Protokollwert, api/ledger.js-Sanitize);
// noteKey/noteParams rekonstruieren den Text clientseitig in der aktuellen
// Sprache (public/i18n.mjs noteText). Pro Note-Variante ein Fixture.
const one = (findings, ruleId) => {
  const f = findings.find((x) => x.ruleId === ruleId);
  assert.ok(f, `Fund ${ruleId} fehlt`);
  return f;
};

test("noteKey: known-bad-hit — note bleibt deutsch, noteKey/noteParams additiv", () => {
  const tx = { TransactionType: "Payment", Account: R.bad, Destination: R.dest, Amount: "500000" };
  const f = one(analyzeTx(tx, null, { knownBad: new Set([R.bad]) }), "known-bad-hit");
  assert.equal(f.note, "Bekannt-maliziöse Adresse beteiligt (Payment).");
  assert.equal(f.noteKey, "known-bad-hit");
  assert.deepEqual(f.noteParams, { type: "Payment" });
});

test("noteKey: memo-phishing — Seed- und URL-Variante", () => {
  const seedTx = { TransactionType: "Payment", Account: R.sender, Destination: R.dest, Amount: "100000", Memos: [{ Memo: { MemoData: hex("backup skeyA2CDEFGHJKLMNPQRSTUVWXYZ") } }] };
  const fs = one(analyzeTx(seedTx, null, {}), "memo-phishing");
  assert.equal(fs.note, "Memo enthält Seed-Muster.");
  assert.equal(fs.noteKey, "memo-phishing-seed");
  assert.equal(fs.noteParams, undefined);
  const urlTx = { TransactionType: "Payment", Account: R.sender, Destination: R.dest, Amount: "100000", Memos: [{ Memo: { MemoData: hex("Claim your airdrop at http://evil.example/claim") } }] };
  const fu = one(analyzeTx(urlTx, null, {}), "memo-phishing");
  assert.equal(fu.note, "Memo enthält URL mit claim-/airdrop-/verify-Keyword.");
  assert.equal(fu.noteKey, "memo-phishing-url");
});

test("noteKey: fake-nft-fraud URI-Variante", () => {
  const tx = { TransactionType: "NFTokenMint", Account: R.sender, Issuer: R.sender, URI: hex("https://bit.ly/claim-nft") };
  const f = one(analyzeTx(tx, null, {}), "fake-nft-fraud");
  assert.equal(f.note, "NFTokenMint-URI enthält Phishing-/claim-Muster.");
  assert.equal(f.noteKey, "fake-nft-fraud-uri");
});

test("noteKey: escrow-check-bait Einzel-Variante — type und Kurzform des Ziels", () => {
  const tx = {
    TransactionType: "EscrowCreate", Account: R.sender, Destination: R.dest, Amount: "99",
    Memos: [{ Memo: { MemoData: hex("verify your wallet to claim at http://phish.example") } }],
  };
  const f = one(analyzeTx(tx, null, { firstSeenAt: freshMap(R.dest) }), "escrow-check-bait");
  assert.equal(f.noteKey, "escrow-check-bait-single");
  assert.deepEqual(f.noteParams, { type: "EscrowCreate", addr: "rTESTDES…0002" });
  assert.ok(f.note.includes("rTESTDES…0002"), "note enthält dieselbe Kurzform wie noteParams");
});

test("noteKey: dusting — fresh- und many-Variante mit Zähler", () => {
  const d1 = "rTESTDUSTFRESHA000000000000001";
  const d2 = "rTESTDUSTFRESHB000000000000002";
  const txs = [d1, d2].map((d) => ({ TransactionType: "Payment", Account: R.sender, Destination: d, Amount: "99" }));
  const fresh = one(analyzeLedger({ transactions: txs }, { firstSeenAt: freshMap(d1, d2) }).findings, "dusting");
  assert.equal(fresh.noteKey, "dusting-fresh");
  assert.deepEqual(fresh.noteParams, { n: 2 });
  const dests = ["C1", "C2", "C3"].map((s) => `rTESTDUST000000000000000000000${s}`);
  const manyTxs = dests.map((d) => ({ TransactionType: "Payment", Account: R.sender, Destination: d, Amount: "99" }));
  const many = one(analyzeLedger({ ledger: { transactions: manyTxs } }, {}).findings, "dusting");
  assert.equal(many.noteKey, "dusting-many");
  assert.deepEqual(many.noteParams, { n: 3 });
});

test("noteKey: drainer-sweep — Sweep-Prozent in noteParams", () => {
  const ledger = {
    transactions: [
      { TransactionType: "Payment", Account: R.sender, Destination: R.drain, Amount: "100000" },
      { TransactionType: "Payment", Account: R.drain, Destination: R.collector, Amount: "95000", meta: drainMeta },
    ],
  };
  const f = one(analyzeLedger(ledger, { firstSeenAt: freshMap(R.drain) }).findings, "drainer-sweep");
  assert.equal(f.note, "Frisch finanziert und 95 % an ein Ziel abgeräumt.");
  assert.equal(f.noteKey, "drainer-sweep");
  assert.deepEqual(f.noteParams, { pct: 95 });
});

test("noteKey: offer-spam — Anzahl in noteParams", () => {
  const txs = Array.from({ length: 10 }, () => ({ TransactionType: "OfferCreate", Account: R.spam, meta: { AffectedNodes: [] } }));
  const f = one(analyzeLedger({ transactions: txs }, {}).findings, "offer-spam");
  assert.equal(f.noteKey, "offer-spam");
  assert.deepEqual(f.noteParams, { n: 10 });
});

test("noteKey: fake-nft-fraud Accept-Burst — Anzahl in noteParams", () => {
  const zeroMeta = { AffectedNodes: [{ ModifiedNode: { LedgerEntryType: "NFTokenOffer", FinalFields: { Amount: "0" } } }] };
  const txs = Array.from({ length: 10 }, () => ({ TransactionType: "NFTokenAcceptOffer", Account: R.sender, NFTokenSellOffer: "ABC", meta: zeroMeta }));
  const f = one(analyzeLedger({ transactions: txs }, {}).findings, "fake-nft-fraud");
  assert.equal(f.noteKey, "fake-nft-fraud-accept");
  assert.deepEqual(f.noteParams, { n: 10 });
});

test("noteKey: escrow-check-bait Burst — Anzahl in noteParams", () => {
  const d1 = "rTESTESCROW00000000000000000000A1";
  const d2 = "rTESTESCROW00000000000000000000A2";
  const d3 = "rTESTESCROW00000000000000000000A3";
  const memo = [{ Memo: { MemoData: hex("verify your wallet to claim at http://phish.example") } }];
  const txs = [d1, d2, d3].map((d) => ({ TransactionType: "CheckCreate", Account: R.sender, Destination: d, Amount: "99", Memos: memo }));
  const findings = analyzeLedger({ transactions: txs }, { firstSeenAt: freshMap(d1, d2, d3) }).findings;
  const f = findings.find((x) => x.ruleId === "escrow-check-bait" && x.noteKey === "escrow-check-bait-burst");
  assert.ok(f, "Burst-Fund fehlt (neben dem Einzel-Fund desselben Täters — dedupe trägt noteKey)");
  assert.deepEqual(f.noteParams, { n: 3 });
});

test("noteKey: payment-burst — Ziel- und Winzig-Zähler in noteParams", () => {
  const dests = ["A1", "A2", "A3", "A4", "A5"].map((s) => `rTESTBURST00000000000000000000${s}`);
  const txs = dests.map((d) => ({ TransactionType: "Payment", Account: R.sender, Destination: d, Amount: "99" }));
  const f = one(analyzeLedger({ transactions: txs }, {}).findings, "payment-burst");
  assert.equal(f.noteKey, "payment-burst");
  assert.deepEqual(f.noteParams, { n: 5, tiny: 5 });
});

test("noteKey: airdrop-trustset-spam — Anzahl und Issuer-Kurzform in noteParams", () => {
  const accts = ["A1", "A2", "A3", "A4", "A5"].map((s) => `rTESTTS${s}000000000000000000000`);
  const txs = accts.map((a) => ({ TransactionType: "TrustSet", Account: a, LimitAmount: { value: "0.5", currency: "FAKE", issuer: R.spam } }));
  const f = one(analyzeLedger({ transactions: txs }, {}).findings, "airdrop-trustset-spam");
  assert.equal(f.noteKey, "airdrop-trustset-spam");
  assert.deepEqual(f.noteParams, { n: 5, issuer: "rTESTSPA…0007" });
});

/* ================================================================== */
/* Regressionstests zu den Regeländerungen 2026-10-02                 */
/* Pro geänderter Regel: False-Positive-Fall (benign) UND Betrüger-   */
/* fall (erkannt).                                                    */
/* ================================================================== */

// ---------- memo-phishing: Kontext-Gate für 'claim'/'verify' ----------
test("memo-phishing: FP-Regression — 'verify' mit Bestell-Kontext ist benign", () => {
  const tx = { TransactionType: "Payment", Account: R.sender, Destination: R.dest, Amount: "100000",
    Memos: [{ Memo: { MemoData: hex("Please verify your order at https://shop.example/de") } }] };
  const f = analyzeTx(tx, null, {});
  assert.ok(!has(f, "memo-phishing"));
});
test("memo-phishing: FP-Regression — 'Warranty claim' mit Support-URL ist benign", () => {
  const tx = { TransactionType: "Payment", Account: R.sender, Destination: R.dest, Amount: "100000",
    Memos: [{ Memo: { MemoData: hex("Warranty claim: register at www.example.com/support") } }] };
  const f = analyzeTx(tx, null, {});
  assert.ok(!has(f, "memo-phishing"));
});
test("memo-phishing: FP-Regression — 'Claim ID' mit Bestell-Kontext ist benign", () => {
  const tx = { TransactionType: "Payment", Account: R.sender, Destination: R.dest, Amount: "100000",
    Memos: [{ Memo: { MemoData: hex("Claim ID 8812 for order 4471") } }] };
  const f = analyzeTx(tx, null, {});
  assert.ok(!has(f, "memo-phishing"));
});
test("memo-phishing: Betrüger — 'verify your wallet to claim reward' trifft", () => {
  const tx = { TransactionType: "Payment", Account: R.sender, Destination: R.dest, Amount: "100000",
    Memos: [{ Memo: { MemoData: hex("verify your wallet to claim reward at http://evil.example") } }] };
  const f = analyzeTx(tx, null, {});
  assert.ok(has(f, "memo-phishing"));
  assert.equal(sev(f, "memo-phishing"), "malicious");
});
test("memo-phishing: Betrüger — 'verify your account to receive tokens' trifft", () => {
  const tx = { TransactionType: "Payment", Account: R.sender, Destination: R.dest, Amount: "100000",
    Memos: [{ Memo: { MemoData: hex("verify your account to receive tokens at http://evil.example") } }] };
  const f = analyzeTx(tx, null, {});
  assert.ok(has(f, "memo-phishing"));
});
test("memo-phishing: Betrüger — Standalone-Scam-Vokabular 'airdrop' trifft ohne Kontext", () => {
  const tx = { TransactionType: "Payment", Account: R.sender, Destination: R.dest, Amount: "100000",
    Memos: [{ Memo: { MemoData: hex("free token airdrop http://evil.example") } }] };
  const f = analyzeTx(tx, null, {});
  assert.ok(has(f, "memo-phishing"));
});
test("memo-phishing: FP-Regression — zitiertes Opfer-Memo (URL in Anführungszeichen + Rückfrage) -> suspect statt malicious", () => {
  const tx = { TransactionType: "Payment", Account: R.sender, Destination: R.dest, Amount: "100000",
    Memos: [{ Memo: { MemoData: hex("Jemand schrieb mir \"Claim your airdrop at http://evil.example\" — ist das echt?") } }] };
  const f = analyzeTx(tx, null, {});
  assert.ok(has(f, "memo-phishing"), "Fund bleibt bestehen");
  assert.equal(sev(f, "memo-phishing"), "suspect", "Downgrade auf suspect (Opfer, kein Täter)");
});

// ---------- memo-phishing auf neuen tx-Typen ----------
test("memo-phishing: Betrüger — TrustSet mit Phishing-Memo, Fund-Adresse = Issuer", () => {
  const tx = { TransactionType: "TrustSet", Account: R.sender,
    LimitAmount: { value: "10", currency: "FAKE", issuer: R.spam },
    Memos: [{ Memo: { MemoData: hex("verify your wallet to claim airdrop at http://evil.example") } }] };
  const f = analyzeTx(tx, null, {});
  assert.ok(has(f, "memo-phishing"));
  const found = f.find((x) => x.ruleId === "memo-phishing");
  assert.equal(found.address, R.spam, "Fund-Adresse ist der Trustline-Issuer");
});
test("memo-phishing: FP-Regression — TrustSet mit neutralem Memo ist benign", () => {
  const tx = { TransactionType: "TrustSet", Account: R.sender,
    LimitAmount: { value: "100", currency: "USD", issuer: R.gateway },
    Memos: [{ Memo: { MemoData: hex("trustline setup ref 42") } }] };
  const f = analyzeTx(tx, null, {});
  assert.ok(!has(f, "memo-phishing"));
});
test("memo-phishing: Betrüger — PaymentChannelCreate mit Phishing-Memo trifft", () => {
  const tx = { TransactionType: "PaymentChannelCreate", Account: R.sender, Destination: R.dest, Amount: "100000",
    Memos: [{ Memo: { MemoData: hex("verify your account to claim bonus at http://evil.example") } }] };
  const f = analyzeTx(tx, null, {});
  assert.ok(has(f, "memo-phishing"));
});

// ---------- known-bad-hit: Positions-Guard + benign-Whitelist ----------
test("known-bad-hit: FP-Regression — knownBad als Trustline-Issuer (nur Position) -> suspect", () => {
  const tx = { TransactionType: "TrustSet", Account: R.sender, LimitAmount: { value: "5", currency: "FAKE", issuer: R.bad } };
  const f = analyzeTx(tx, null, { knownBad: new Set([R.bad]) });
  assert.ok(has(f, "known-bad-hit"));
  assert.equal(sev(f, "known-bad-hit"), "suspect", "Positions-Treffer ohne direkte Berührung");
});
test("known-bad-hit: FP-Regression — knownBad auf benign-Whitelist wird unterdrückt", () => {
  const tx = { TransactionType: "Payment", Account: R.sender, Destination: R.gateway, Amount: "100000" };
  const f = analyzeTx(tx, null, { knownBad: new Set([R.gateway]), benignIssuers: new Set([R.gateway]) });
  assert.ok(!has(f, "known-bad-hit"));
});
test("known-bad-hit: Betrüger — direkte Berührung bleibt malicious", () => {
  const tx = { TransactionType: "Payment", Account: R.bad, Destination: R.dest, Amount: "100000" };
  const f = analyzeTx(tx, null, { knownBad: new Set([R.bad]) });
  assert.equal(sev(f, "known-bad-hit"), "malicious");
});

// ---------- Bagatellgrenze: 99 winzig, 100 nicht mehr ----------
test("Bagatellgrenze: 99 drops ist winzig (dusting-many trifft), 100 drops nicht mehr", () => {
  const d1 = "rTESTDUST99A000000000000000001";
  const d2 = "rTESTDUST99B000000000000000002";
  const d3 = "rTESTDUST99C000000000000000003";
  const hit = analyzeLedger({ transactions: [d1, d2, d3].map((d) => ({ TransactionType: "Payment", Account: R.sender, Destination: d, Amount: "99" })) }, {});
  assert.ok(has(hit.findings, "dusting"));
  const benign = analyzeLedger({ transactions: [d1, d2, d3].map((d) => ({ TransactionType: "Payment", Account: R.sender, Destination: d, Amount: "100" })) }, {});
  assert.ok(!has(benign.findings, "dusting"), "100 drops = 0.001 XRP liegt auf der Grenze und ist benign");
});

// ---------- dusting: Cross-Ledger-Union über ctx.history ----------
test("dusting: FP-Regression — 1 Ziel pro Ledger über zwei Ledger ist noch kein Fund", () => {
  const history = new Map();
  const d1 = "rTESTDUSTX1000000000000000001";
  const d2 = "rTESTDUSTX2000000000000000002";
  const r1 = analyzeLedger({ ledger_index: 100, transactions: [{ TransactionType: "Payment", Account: R.sender, Destination: d1, Amount: "99" }] }, { history });
  assert.ok(!has(r1.findings, "dusting"));
  const r2 = analyzeLedger({ ledger_index: 101, transactions: [{ TransactionType: "Payment", Account: R.sender, Destination: d2, Amount: "99" }] }, { history });
  assert.ok(!has(r2.findings, "dusting"));
});
test("dusting: Betrüger — gestreckte Kampagne (1 Ziel pro Ledger, 3 Ledger) trifft im dritten Ledger", () => {
  const history = new Map();
  const d1 = "rTESTDUSTY1000000000000000001";
  const d2 = "rTESTDUSTY2000000000000000002";
  const d3 = "rTESTDUSTY3000000000000000003";
  analyzeLedger({ ledger_index: 200, transactions: [{ TransactionType: "Payment", Account: R.sender, Destination: d1, Amount: "99" }] }, { history });
  analyzeLedger({ ledger_index: 201, transactions: [{ TransactionType: "Payment", Account: R.sender, Destination: d2, Amount: "99" }] }, { history });
  const r3 = analyzeLedger({ ledger_index: 202, transactions: [{ TransactionType: "Payment", Account: R.sender, Destination: d3, Amount: "99" }] }, { history });
  const f = one(r3.findings, "dusting");
  assert.equal(f.noteKey, "dusting-many");
  assert.deepEqual(f.noteParams, { n: 3 });
});

// ---------- wash-self-transfer ----------
test("wash-self-transfer: FP-Regression — einzelne Selbst-Konsolidierung ist benign", () => {
  const txs = [{ TransactionType: "Payment", Account: R.sender, Destination: R.sender, Amount: "500000000" }];
  const r = analyzeLedger({ transactions: txs }, {});
  assert.ok(!has(r.findings, "wash-self-transfer"));
  assert.ok(!has(r.findings, "dusting"), "Selbsttransfer zählt nicht als dusting");
  assert.ok(!has(r.findings, "payment-burst"), "Selbsttransfer zählt nicht als payment-burst");
});
test("wash-self-transfer: Betrüger — 3+ Selbstzahlungen pro Ledger (Volumen-Washing) trifft", () => {
  const txs = Array.from({ length: 4 }, () => ({ TransactionType: "Payment", Account: R.sender, Destination: R.sender, Amount: "1000000" }));
  const r = analyzeLedger({ transactions: txs }, {});
  const f = one(r.findings, "wash-self-transfer");
  assert.equal(f.severity, "suspect");
  assert.equal(f.noteKey, "wash-self-transfer");
  assert.deepEqual(f.noteParams, { n: 4 });
});

// ---------- drainer-sweep: Frische-Härtung + Konsolidierungs-Guards ----------
test("drainer-sweep: FP-Regression — reines firstSeenAt-Signal ohne CreatedNode -> suspect statt malicious", () => {
  const ledger = {
    transactions: [
      { TransactionType: "Payment", Account: R.sender, Destination: R.drain, Amount: "100000" },
      { TransactionType: "Payment", Account: R.drain, Destination: R.collector, Amount: "95000",
        meta: { AffectedNodes: [{ ModifiedNode: { LedgerEntryType: "AccountRoot", PreviousFields: { Balance: "100000" }, FinalFields: { Balance: "5000" } } }] } },
    ],
  };
  const r = analyzeLedger(ledger, { firstSeenAt: freshMap(R.drain) });
  assert.ok(has(r.findings, "drainer-sweep"));
  assert.equal(sev(r.findings, "drainer-sweep"), "suspect", "ohne Erstellungsbeleg Downgrade auf suspect");
});

// ---------- drainer-sweep: V5 verifiedFresh (Entity-Snapshot-Zweitbeleg) ----------
// Vektor-Form des Härtungsfalls oben (gleiche Txs, kein CreatedNode): das
// Entity-Snapshot-Set trägt die malicious-Stufe als ZWEITER Belegsweg —
// Cross-Tick-Degradation (Fütterung Tick T, Sweep Tick T+1) wird abgedeckt.
const sweepLedgerNoCreated = {
  transactions: [
    { TransactionType: "Payment", Account: R.sender, Destination: R.drain, Amount: "100000" },
    { TransactionType: "Payment", Account: R.drain, Destination: R.collector, Amount: "95000",
      meta: { AffectedNodes: [{ ModifiedNode: { LedgerEntryType: "AccountRoot", PreviousFields: { Balance: "100000" }, FinalFields: { Balance: "5000" } } }] } },
  ],
};
test("drainer-sweep: verifiedFresh-Beleg ohne CreatedNode bei >=90 % Sweep -> malicious (Cross-Tick)", () => {
  const r = analyzeLedger(sweepLedgerNoCreated, {
    firstSeenAt: freshMap(R.drain),
    verifiedFresh: new Set([R.drain]),
  });
  assert.ok(has(r.findings, "drainer-sweep"));
  assert.equal(sev(r.findings, "drainer-sweep"), "malicious", "Snapshot-Beleg trägt die malicious-Stufe");
});
test("drainer-sweep: Guard — verifiedFresh allein erzeugt KEINEN Fund (zweiter Belegsweg, nie Fundquelle)", () => {
  // Ohne firstSeenAt-Frische bleibt der Fund aus, auch wenn verifiedFresh die Adresse trägt.
  const r = analyzeLedger(sweepLedgerNoCreated, {
    firstSeenAt: new Map(),
    verifiedFresh: new Set([R.drain]),
  });
  assert.ok(!has(r.findings, "drainer-sweep"), "isFresh-Gate bleibt unverändert");
});
test("drainer-sweep: Guard — verifiedFresh + Sweep-Ratio < 0,9 bleibt benign (Ratio-Guard intakt)", () => {
  const ledger50 = {
    transactions: [
      { TransactionType: "Payment", Account: R.sender, Destination: R.drain, Amount: "100000" },
      { TransactionType: "Payment", Account: R.drain, Destination: R.collector, Amount: "50000",
        meta: { AffectedNodes: [{ ModifiedNode: { LedgerEntryType: "AccountRoot", PreviousFields: { Balance: "100000" }, FinalFields: { Balance: "50000" } } }] } },
    ],
  };
  const r = analyzeLedger(ledger50, {
    firstSeenAt: freshMap(R.drain),
    verifiedFresh: new Set([R.drain]),
  });
  assert.ok(!has(r.findings, "drainer-sweep"), "50-%-Abfluss ist kein Sweep, auch mit Snapshot-Beleg");
});
test("drainer-sweep: Guard — benignAccounts ∩ verifiedFresh bleibt Skip (Whitelist gewinnt)", () => {
  const r = analyzeLedger(sweepLedgerNoCreated, {
    firstSeenAt: freshMap(R.drain),
    verifiedFresh: new Set([R.drain]),
    benignAccounts: new Set([R.drain]),
  });
  assert.ok(!has(r.findings, "drainer-sweep"));
});
test("drainer-sweep: verifiedFresh für FREMDE Adresse ändert nichts (kein Übertragen des Belegs)", () => {
  const r = analyzeLedger(sweepLedgerNoCreated, {
    firstSeenAt: freshMap(R.drain),
    verifiedFresh: new Set([R.sender]), // Beleg liegt auf dem Sender, nicht dem Drain-Konto
  });
  assert.ok(has(r.findings, "drainer-sweep"));
  assert.equal(sev(r.findings, "drainer-sweep"), "suspect", "ohne Beleg auf dem Konto selbst -> suspect");
});
test("drainer-sweep: FP-Regression — Rückführung an das eigene Konto ist kein Sweep", () => {
  const ledger = {
    transactions: [
      { TransactionType: "Payment", Account: R.sender, Destination: R.drain, Amount: "100000" },
      { TransactionType: "Payment", Account: R.drain, Destination: R.sender, Amount: "95000",
        meta: { AffectedNodes: [{ ModifiedNode: { LedgerEntryType: "AccountRoot", PreviousFields: { Balance: "100000" }, FinalFields: { Balance: "5000" } } }] } },
    ],
  };
  const r = analyzeLedger(ledger, { firstSeenAt: freshMap(R.drain) });
  assert.ok(!has(r.findings, "drainer-sweep"), "Ziel ist Gegenkonto eigener Zahlungen (Rückführung)");
});
test("drainer-sweep: Betrüger — Cross-Ledger-Sweep (Füttern in Ledger N, Abräumen in N+1) trifft", () => {
  const history = new Map();
  analyzeLedger({ ledger_index: 300, transactions: [
    { TransactionType: "Payment", Account: R.sender, Destination: R.drain, Amount: "100000" },
  ] }, { history });
  const r2 = analyzeLedger({ ledger_index: 301, transactions: [
    { TransactionType: "Payment", Account: R.drain, Destination: R.collector, Amount: "95000",
      meta: { AffectedNodes: [
        { CreatedNode: { LedgerEntryType: "AccountRoot", LedgerEntry: { Account: R.drain } } },
        { ModifiedNode: { LedgerEntryType: "AccountRoot", PreviousFields: { Balance: "100000" }, FinalFields: { Balance: "5000" } } },
      ] } },
  ] }, { firstSeenAt: freshMap(R.drain), history });
  const f = one(r2.findings, "drainer-sweep");
  assert.equal(f.severity, "malicious", "CreatedNode AccountRoot = Erstellungsbeleg");
});

// ---------- airdrop-trustset-spam: Quality-Arm nur für kleine Limits ----------
test("airdrop-trustset-spam: FP-Regression — große Trustline (1000000) mit niedriger Quality ist benign", () => {
  const accts = ["A1", "A2", "A3", "A4", "A5"].map((s) => `rTESTTSQ${s}0000000000000000000`);
  const txs = accts.map((a) => ({ TransactionType: "TrustSet", Account: a, LimitAmount: { value: "1000000", currency: "FAKE", issuer: R.spam, quality: 500000000 } }));
  const r = analyzeLedger({ transactions: txs }, {});
  assert.ok(!has(r.findings, "airdrop-trustset-spam"));
});
test("airdrop-trustset-spam: Betrüger — Mini-Limit (100) mit niedriger Quality zählt ins Massenmuster", () => {
  const accts = ["A1", "A2", "A3", "A4", "A5"].map((s) => `rTESTTST${s}0000000000000000000`);
  const txs = accts.map((a) => ({ TransactionType: "TrustSet", Account: a, LimitAmount: { value: "100", currency: "FAKE", issuer: R.spam, quality: 500000000 } }));
  const r = analyzeLedger({ transactions: txs }, {});
  assert.ok(has(r.findings, "airdrop-trustset-spam"));
});

// ---------- fake-nft-fraud: Wucher-TransferFee + CreateOffer-Burst ----------
test("fake-nft-fraud: FP-Regression — TransferFee 49999 (unter 50 %) ist benign", () => {
  const tx = { TransactionType: "NFTokenMint", Account: R.sender, Issuer: R.sender, TransferFee: 49999 };
  const f = analyzeTx(tx, null, {});
  assert.ok(!has(f, "fake-nft-fraud"));
});
test("fake-nft-fraud: Betrüger — TransferFee 50000 (50 %) ohne Phishing-URI trifft", () => {
  const tx = { TransactionType: "NFTokenMint", Account: R.sender, Issuer: R.sender, TransferFee: 50000 };
  const f = analyzeTx(tx, null, {});
  const found = one(f, "fake-nft-fraud");
  assert.equal(found.noteKey, "fake-nft-fraud-fee");
  assert.deepEqual(found.noteParams, { pct: 50 });
});
test("fake-nft-fraud: FP-Regression — 4 NFTokenCreateOffer auf dasselbe Ziel sind benign", () => {
  const txs = Array.from({ length: 4 }, () => ({ TransactionType: "NFTokenCreateOffer", Account: R.sender, Owner: R.dest, NFTokenSellOffer: undefined }));
  const r = analyzeLedger({ transactions: txs }, {});
  assert.ok(!has(r.findings, "fake-nft-fraud"));
});
test("fake-nft-fraud: Betrüger — 5 NFTokenCreateOffer auf dasselbe Ziel in einem Ledger trifft", () => {
  const txs = Array.from({ length: 5 }, () => ({ TransactionType: "NFTokenCreateOffer", Account: R.sender, Owner: R.dest }));
  const r = analyzeLedger({ transactions: txs }, {});
  const f = one(r.findings, "fake-nft-fraud");
  assert.equal(f.noteKey, "fake-nft-fraud-offer");
  assert.deepEqual(f.noteParams, { n: 5, addr: "rTESTDES…0002" });
});

// ---------- payment-burst: Mehrheits-Guard ----------
test("payment-burst: FP-Regression — Rückerstattungsmuster (4 groß + 2 winzig) ist benign", () => {
  const dests = ["B1", "B2", "B3", "B4", "B5", "B6"].map((s) => `rTESTPAYM0000000000000000000${s}`);
  const txs = [
    ...dests.slice(0, 4).map((d) => ({ TransactionType: "Payment", Account: R.sender, Destination: d, Amount: "100000000" })),
    ...dests.slice(4).map((d) => ({ TransactionType: "Payment", Account: R.sender, Destination: d, Amount: "99" })),
  ];
  const r = analyzeLedger({ transactions: txs }, {});
  assert.ok(!has(r.findings, "payment-burst"), "winzige Ziele stellen keine Mehrheit (tiny 2 < payDests 6 - 2)");
});
test("payment-burst: Betrüger — 6 Ziele, 4 winzig (Mehrheit) trifft", () => {
  const dests = ["C1", "C2", "C3", "C4", "C5", "C6"].map((s) => `rTESTBURSTM00000000000000000${s}`);
  const txs = [
    ...dests.slice(0, 2).map((d) => ({ TransactionType: "Payment", Account: R.sender, Destination: d, Amount: "100000000" })),
    ...dests.slice(2).map((d) => ({ TransactionType: "Payment", Account: R.sender, Destination: d, Amount: "99" })),
  ];
  const r = analyzeLedger({ transactions: txs }, {});
  const f = one(r.findings, "payment-burst");
  assert.deepEqual(f.noteParams, { n: 6, tiny: 4 });
});

/* ================================================================== */
/* Regressionstests 2026-10-04 (Round-1-Patch): CreatedNode-           */
/* NewFields-Form und CheckCreate-SendMax-Form                         */
/* ================================================================== */

// ---------- drainer-sweep: CreatedNode NewFields-Form (expand-Pfad) ----------
// Spiegel des LedgerEntry-Form-Tests (:692-697): live belegt hc_ledger_11/
// _13/_14 tragen CreatedNode als {LedgerEntryType, LedgerIndex, NewFields}
// ohne LedgerEntry — ohne NewFields-Fallback (detector.mjs createdAccountOf)
// fehlte der Erstellungsbeleg und die Severity fiel auf 'suspect'.
test("drainer-sweep: CreatedNode NewFields-Form (expand-Pfad) = Erstellungsbeleg malicious", () => {
  const history = new Map();
  analyzeLedger({ ledger_index: 310, transactions: [
    { TransactionType: "Payment", Account: R.sender, Destination: R.drain, Amount: "100000" },
  ] }, { history });
  const r2 = analyzeLedger({ ledger_index: 311, transactions: [
    { TransactionType: "Payment", Account: R.drain, Destination: R.collector, Amount: "95000",
      meta: { AffectedNodes: [
        { CreatedNode: { LedgerEntryType: "AccountRoot", LedgerIndex: "A1B2C3D4E5F6", NewFields: { Account: R.drain, Balance: "5000" } } },
        { ModifiedNode: { LedgerEntryType: "AccountRoot", PreviousFields: { Balance: "100000" }, FinalFields: { Balance: "5000" } } },
      ] } },
  ] }, { firstSeenAt: freshMap(R.drain), history });
  const f = one(r2.findings, "drainer-sweep");
  assert.equal(f.severity, "malicious", "CreatedNode NewFields.Account = Erstellungsbeleg");
});

// ---------- escrow-check-bait: CheckCreate SendMax-Form ----------
// XRPL-Spec: CheckCreate trägt den XRP-Betrag in SendMax (live belegt
// hc_ledger_13), nicht in Amount — Spiegel des Amount-Burst-Tests
// (:315-321) mit SendMax statt Amount.
test("escrow-check-bait: CheckCreate SendMax-Form feuert (Spiegel Amount-Burst)", () => {
  const d1 = "rTESTESCROWSM0000000000000000A1";
  const d2 = "rTESTESCROWSM0000000000000000A2";
  const d3 = "rTESTESCROWSM0000000000000000A3";
  const memo = [{ Memo: { MemoData: hex("verify your wallet to claim at http://phish.example") } }];
  const txs = [d1, d2, d3].map((d) => ({ TransactionType: "CheckCreate", Account: R.sender, Destination: d, SendMax: "99", Memos: memo }));
  const findings = analyzeLedger({ transactions: txs }, { firstSeenAt: freshMap(d1, d2, d3) }).findings;
  assert.ok(findings.some((x) => x.ruleId === "escrow-check-bait" && x.noteKey === "escrow-check-bait-single"), "Einzel-Fund über SendMax");
  assert.ok(findings.some((x) => x.ruleId === "escrow-check-bait" && x.noteKey === "escrow-check-bait-burst"), "Burst-Fund über SendMax");
});
test("escrow-check-bait: Guard — IOU-SendMax (Objekt) liefert keinen Fund", () => {
  const d1 = "rTESTESCROWIOU000000000000000A1";
  const d2 = "rTESTESCROWIOU000000000000000A2";
  const d3 = "rTESTESCROWIOU000000000000000A3";
  const memo = [{ Memo: { MemoData: hex("verify your wallet to claim at http://phish.example") } }];
  const iou = { currency: "USD", issuer: R.gateway, value: "0.01" };
  const txs = [d1, d2, d3].map((d) => ({ TransactionType: "CheckCreate", Account: R.sender, Destination: d, SendMax: iou, Memos: memo }));
  const r = analyzeLedger({ transactions: txs }, { firstSeenAt: freshMap(d1, d2, d3) });
  assert.ok(!has(r.findings, "escrow-check-bait"), "dropsOf(IOU-Objekt) = null -> kein Fund");
});

// =====================================================================
// Market-Regeln (Kritik-Runde 3, T1.2): amm-wash-swap / thin-pool-exploit /
// spoof-offer-cycle. Deterministisch, köderfrei, Tx-Ebene über expand:true-
// Meta (DeletedNode Offer = echter Fill; CreatedNode Offer = Platzierung).
// Taker-Sicht: erhält TakerGets, gibt TakerPays. Synthetische Adressen.
// =====================================================================
const M = {
  maker1: "rTESTMAKER1000000000000000000001",
  maker2: "rTESTMAKER2000000000000000000002",
  other1: "rTESTOTHER1000000000000000000001",
  other2: "rTESTOTHER2000000000000000000002",
  other3: "rTESTOTHER3000000000000000000003",
  exch: "rTESTEXCH0000000000000000000001",
};
const usd = (value) => ({ currency: "USD", issuer: R.gateway, value });
// Consumierter Fremd-Offer (DeletedNode): Taker erhält TakerGets, gibt TakerPays.
const fillMeta = (maker, takerGets, takerPays, seq = 1, book = "BD1", node = "BN1") => ({
  AffectedNodes: [
    {
      DeletedNode: {
        LedgerEntryType: "Offer",
        FinalFields: { Account: maker, Sequence: seq, BookDirectory: book, BookNode: node, TakerGets: takerGets, TakerPays: takerPays },
      },
    },
  ],
});
// Eigene platzierte Limit-Order (CreatedNode, expand-Pfad NewFields-Form).
const placeMeta = (account, seq, book, node, takerGets, takerPays) => ({
  AffectedNodes: [
    {
      CreatedNode: {
        LedgerEntryType: "Offer",
        NewFields: { Account: account, Sequence: seq, BookDirectory: book, BookNode: node, TakerGets: takerGets, TakerPays: takerPays },
      },
    },
  ],
});
const oc = (hash, ledgerIndex, account, meta) => ({ hash, ledger_index: ledgerIndex, TransactionType: "OfferCreate", Account: account, meta });
const ocan = (hash, ledgerIndex, account, meta) => ({ hash, ledger_index: ledgerIndex, TransactionType: "OfferCancel", Account: account, meta });
// Selbst-Ersatz-Quote (Kritik-Runde 4, Befund 3): OfferCreate ersetzt das
// EIGENE Offer — DeletedNode FinalFields.Account === tx.Account (alter
// Quote) plus CreatedNode NewFields.Account === tx.Account (neuer Quote).
// Kein Cross, kein Gegenpartei-Geldfluss: kein Fill (Guard offerFillNodesOf).
const replaceMeta = (account, seq, book, node, takerGets, takerPays) => ({
  AffectedNodes: [
    {
      DeletedNode: {
        LedgerEntryType: "Offer",
        FinalFields: { Account: account, Sequence: seq, BookDirectory: book, BookNode: node, TakerGets: takerGets, TakerPays: takerPays },
      },
    },
    {
      CreatedNode: {
        LedgerEntryType: "Offer",
        NewFields: { Account: account, Sequence: seq + 1, BookDirectory: book, BookNode: node, TakerGets: takerGets, TakerPays: takerPays },
      },
    },
  ],
});

// ---------- amm-wash-swap ----------
test("amm-wash-swap: Betrüger — bidirektionale Fills desselben Pairs, Volumenerhalt 100 %, Drift 0 %", () => {
  const txs = [
    // Richtung XRP->USD: Taker erhält XRP (TakerGets), gibt USD (TakerPays)
    oc("W1", 100, R.sender, fillMeta(M.maker1, "2000000", usd("2"))),
    oc("W2", 101, R.sender, fillMeta(M.maker1, "2000000", usd("2"))),
    // Richtung USD->XRP: Taker erhält USD, gibt XRP
    oc("W3", 102, R.sender, fillMeta(M.maker2, usd("2"), "2000000")),
    oc("W4", 103, R.sender, fillMeta(M.maker2, usd("2"), "2000000")),
  ];
  const r = analyzeLedger({ transactions: txs }, {});
  assert.ok(has(r.findings, "amm-wash-swap"), "Waschzyklus über OfferCreate-Fills trifft");
  assert.equal(sev(r.findings, "amm-wash-swap"), "suspect");
  const f = r.findings.find((x) => x.ruleId === "amm-wash-swap");
  assert.equal(f.address, R.sender, "Fundadresse ist tx.Account");
  assert.equal(f.noteParams.conserve, 100);
  assert.equal(f.noteParams.drift, 0);
});
test("amm-wash-swap: Guard — Positionsdrift 50 % (echter Handel, kein Wash) bleibt benign", () => {
  const txs = [
    oc("W1", 100, R.sender, fillMeta(M.maker1, "2000000", usd("2"))),
    oc("W2", 101, R.sender, fillMeta(M.maker1, "2000000", usd("2"))),
    oc("W3", 102, R.sender, fillMeta(M.maker2, usd("1"), "1000000")),
    oc("W4", 103, R.sender, fillMeta(M.maker2, usd("1"), "1000000")),
  ];
  const r = analyzeLedger({ transactions: txs }, {});
  assert.ok(!has(r.findings, "amm-wash-swap"), "min/max 1M/2M = conserve 0.5 < 0.9 -> kein Fund");
});
test("amm-wash-swap: Guard — nur eine Fill je Richtung (Refund statt Zyklus) bleibt benign", () => {
  const txs = [
    oc("W1", 100, R.sender, fillMeta(M.maker1, "2000000", usd("2"))),
    oc("W2", 101, R.sender, fillMeta(M.maker2, usd("2"), "2000000")),
  ];
  const r = analyzeLedger({ transactions: txs }, {});
  assert.ok(!has(r.findings, "amm-wash-swap"), "washMinFillsPerSide 2 nicht erreicht");
});
test("amm-wash-swap: Guard — marketExcludes (Börsen-FP-Guard) unterdrückt den Fund", () => {
  const txs = [
    oc("W1", 100, M.exch, fillMeta(M.maker1, "2000000", usd("2"))),
    oc("W2", 101, M.exch, fillMeta(M.maker1, "2000000", usd("2"))),
    oc("W3", 102, M.exch, fillMeta(M.maker2, usd("2"), "2000000")),
    oc("W4", 103, M.exch, fillMeta(M.maker2, usd("2"), "2000000")),
  ];
  const r = analyzeLedger({ transactions: txs }, { marketExcludes: new Set([M.exch]) });
  assert.ok(!has(r.findings, "amm-wash-swap"), "Exchange-Konto im Exclude-Set -> kein Fund");
});
test("amm-wash-swap: Guard — Notional unter 1 XRP je Richtung bleibt benign", () => {
  const txs = [
    oc("W1", 100, R.sender, fillMeta(M.maker1, "500", usd("2"))),
    oc("W2", 101, R.sender, fillMeta(M.maker1, "500", usd("2"))),
    oc("W3", 102, R.sender, fillMeta(M.maker2, usd("2"), "500")),
    oc("W4", 103, R.sender, fillMeta(M.maker2, usd("2"), "500")),
  ];
  const r = analyzeLedger({ transactions: txs }, {});
  assert.ok(!has(r.findings, "amm-wash-swap"), "washMinNotionalDrops 1_000_000 nicht erreicht");
});
// Kritik-Runde 4, Befund 3: reine bidirektionale Selbst-Ersatz-Quotes
// (FinalFields.Account === tx.Account, Volumenerhalt 100 %, ohne
// marketExcludes) sind legitimes DEX-Quote-Update eines nicht registrierten
// Market-Makers — ohne den Guard in offerFillNodesOf feuerte amm-wash-swap.
test("amm-wash-swap: Guard — Selbst-Ersatz-Quotes sind keine Fills (Kritik-Runde 4, Befund 3)", () => {
  const txs = [
    oc("S1", 100, R.sender, replaceMeta(R.sender, 1, "BD1", "BN1", "2000000", usd("2"))),
    oc("S2", 101, R.sender, replaceMeta(R.sender, 2, "BD1", "BN1", "2000000", usd("2"))),
    oc("S3", 102, R.sender, replaceMeta(R.sender, 3, "BD1", "BN1", usd("2"), "2000000")),
    oc("S4", 103, R.sender, replaceMeta(R.sender, 4, "BD1", "BN1", usd("2"), "2000000")),
  ];
  const r = analyzeLedger({ transactions: txs }, {});
  assert.ok(!has(r.findings, "amm-wash-swap"), "Selbst-Ersatz zählt nicht in swapPairs — kein Waschhandel-Fund");
});
test("amm-wash-swap: Guard-Präzision — Selbst-Ersatz raus, echte Fremd-Fills zählen weiter", () => {
  const txs = [
    oc("S1", 100, R.sender, replaceMeta(R.sender, 1, "BD1", "BN1", "2000000", usd("2"))),
    oc("S2", 101, R.sender, replaceMeta(R.sender, 2, "BD1", "BN1", usd("2"), "2000000")),
    oc("W1", 102, R.sender, fillMeta(M.maker1, "2000000", usd("2"))),
    oc("W2", 103, R.sender, fillMeta(M.maker1, "2000000", usd("2"))),
    oc("W3", 104, R.sender, fillMeta(M.maker2, usd("2"), "2000000")),
    oc("W4", 105, R.sender, fillMeta(M.maker2, usd("2"), "2000000")),
  ];
  const r = analyzeLedger({ transactions: txs }, {});
  assert.ok(has(r.findings, "amm-wash-swap"), "echte Cross-Fills bleiben trotz Guard sichtbar");
  const f = r.findings.find((x) => x.ruleId === "amm-wash-swap");
  assert.equal(f.noteParams.conserve, 100, "nur die vier echten Fills zählen (2 je Richtung, Volumenerhalt 100 %)");
});

// ---------- thin-pool-exploit ----------
test("thin-pool-exploit: Betrüger — 2 günstige Fills mit 40 % über Fenster-Median (5 Pair-Fills im Fenster)", () => {
  const txs = [
    // 3 Markt-Fills anderer Konten: 10M XRP je 10 USD -> rateNorm 1_000_000
    oc("T1", 100, M.other1, fillMeta(M.maker1, "10000000", usd("10"))),
    oc("T2", 101, M.other2, fillMeta(M.maker1, "10000000", usd("10"))),
    oc("T3", 102, M.other3, fillMeta(M.maker1, "10000000", usd("10"))),
    // Angreifer: 14M XRP erhalten je 10 USD gezahlt -> rateNorm 1_400_000 (+40 %)
    oc("T4", 103, R.sender, fillMeta(M.maker2, "14000000", usd("10"))),
    oc("T5", 104, R.sender, fillMeta(M.maker2, "14000000", usd("10"))),
  ];
  const r = analyzeLedger({ transactions: txs }, {});
  assert.ok(has(r.findings, "thin-pool-exploit"), "Abweichung 40 % >= 25 % in günstiger Richtung trifft");
  assert.equal(sev(r.findings, "thin-pool-exploit"), "suspect");
  const f = r.findings.find((x) => x.ruleId === "thin-pool-exploit");
  assert.equal(f.address, R.sender);
  assert.equal(f.noteParams.n, 2);
});
test("thin-pool-exploit: Guard — nur 4 beobachtete Pair-Fills ('nicht messbar statt raten')", () => {
  const txs = [
    oc("T1", 100, M.other1, fillMeta(M.maker1, "10000000", usd("10"))),
    oc("T2", 101, M.other2, fillMeta(M.maker1, "10000000", usd("10"))),
    oc("T3", 102, R.sender, fillMeta(M.maker2, "14000000", usd("10"))),
    oc("T4", 103, R.sender, fillMeta(M.maker2, "14000000", usd("10"))),
  ];
  const r = analyzeLedger({ transactions: txs }, {});
  assert.ok(!has(r.findings, "thin-pool-exploit"), "thinMinPairSamples 5 nicht erreicht");
});
test("thin-pool-exploit: Guard — günstige Richtung verfehlt (Abweichung gegen das Konto) bleibt benign", () => {
  const txs = [
    oc("T1", 100, M.other1, fillMeta(M.maker1, "10000000", usd("10"))),
    oc("T2", 101, M.other2, fillMeta(M.maker1, "10000000", usd("10"))),
    oc("T3", 102, M.other3, fillMeta(M.maker1, "10000000", usd("10"))),
    // Angreifer zahlt 14M XRP für 10 USD (TakerPays XRP): rateNorm 1_000_000,
    // Taker erhält USD (getsHi false) -> günstig wäre rateNorm < Median;
    // 1M == Median -> keine günstige Abweichung.
    oc("T4", 103, R.sender, fillMeta(M.maker2, usd("10"), "14000000")),
    oc("T5", 104, R.sender, fillMeta(M.maker2, usd("10"), "14000000")),
  ];
  const r = analyzeLedger({ transactions: txs }, {});
  assert.ok(!has(r.findings, "thin-pool-exploit"), "Preisnachteil statt -vorteil -> kein Fund");
});
test("thin-pool-exploit: Guard — Notional 9M unter 10-M-Drops-Schwelle bleibt benign", () => {
  const txs = [
    oc("T1", 100, M.other1, fillMeta(M.maker1, "10000000", usd("10"))),
    oc("T2", 101, M.other2, fillMeta(M.maker1, "10000000", usd("10"))),
    oc("T3", 102, M.other3, fillMeta(M.maker1, "10000000", usd("10"))),
    oc("T4", 103, R.sender, fillMeta(M.maker2, "9000000", usd("6.43"))),
    oc("T5", 104, R.sender, fillMeta(M.maker2, "9000000", usd("6.43"))),
  ];
  const r = analyzeLedger({ transactions: txs }, {});
  assert.ok(!has(r.findings, "thin-pool-exploit"), "thinMinNotionalDrops 10_000_000 nicht erreicht");
});
// Kritik-Runde 4, Befund 3: derselbe Zähl-Vektor wie amm-wash-swap —
// Selbst-Ersatz-Quotes erreichen thinFills nicht. Wie im Betrüger-Test, aber
// die zwei 'günstigen' Fills des Kontos sind Selbst-Ersetzungen: ohne Guard
// 5 Pair-Samples mit +40 % Abweichung -> Fund; mit Guard nur 3 Fremd-Samples
// -> thinMinPairSamples 5 nicht erreicht.
test("thin-pool-exploit: Guard — Selbst-Ersatz-Quotes zählen nicht als Pair-Fills (Kritik-Runde 4, Befund 3)", () => {
  const txs = [
    oc("T1", 100, M.other1, fillMeta(M.maker1, "10000000", usd("10"))),
    oc("T2", 101, M.other2, fillMeta(M.maker1, "10000000", usd("10"))),
    oc("T3", 102, M.other3, fillMeta(M.maker1, "10000000", usd("10"))),
    oc("S4", 103, R.sender, replaceMeta(R.sender, 1, "BD1", "BN1", "14000000", usd("10"))),
    oc("S5", 104, R.sender, replaceMeta(R.sender, 2, "BD1", "BN1", "14000000", usd("10"))),
  ];
  const r = analyzeLedger({ transactions: txs }, {});
  assert.ok(!has(r.findings, "thin-pool-exploit"), "Selbst-Ersatz erzeugt keine thinFills — kein Fund");
});

// ---------- spoof-offer-cycle ----------
test("spoof-offer-cycle: Betrüger — 3 Place-and-Pull-Zyklen, 2 Preislevel, Cancel <= 75 Ledger", () => {
  const txs = [
    oc("S1", 100, R.sender, placeMeta(R.sender, 1, "BD1", "BN1", "100000000", usd("100"))),
    oc("S2", 101, R.sender, placeMeta(R.sender, 2, "BD1", "BN2", "120000000", usd("120"))),
    oc("S3", 102, R.sender, placeMeta(R.sender, 3, "BD1", "BN1", "110000000", usd("110"))),
    ocan("S4", 110, R.sender, fillMeta(R.sender, "100000000", usd("100"), 1, "BD1", "BN1")),
    ocan("S5", 111, R.sender, fillMeta(R.sender, "120000000", usd("120"), 2, "BD1", "BN2")),
    ocan("S6", 112, R.sender, fillMeta(R.sender, "110000000", usd("110"), 3, "BD1", "BN1")),
  ];
  const r = analyzeLedger({ transactions: txs }, {});
  assert.ok(has(r.findings, "spoof-offer-cycle"), "3 Zyklen in BD1 mit 2 BookNodes treffen");
  assert.equal(sev(r.findings, "spoof-offer-cycle"), "suspect");
  const f = r.findings.find((x) => x.ruleId === "spoof-offer-cycle");
  assert.equal(f.noteParams.n, 3);
  assert.equal(f.noteParams.levels, 2);
});
test("spoof-offer-cycle: Guard — Cancel erst nach 80 Ledger (kein Pull-Muster)", () => {
  const txs = [
    oc("S1", 100, R.sender, placeMeta(R.sender, 1, "BD1", "BN1", "100000000", usd("100"))),
    oc("S2", 101, R.sender, placeMeta(R.sender, 2, "BD1", "BN2", "120000000", usd("120"))),
    oc("S3", 102, R.sender, placeMeta(R.sender, 3, "BD1", "BN1", "110000000", usd("110"))),
    ocan("S4", 180, R.sender, fillMeta(R.sender, "100000000", usd("100"), 1, "BD1", "BN1")),
    ocan("S5", 181, R.sender, fillMeta(R.sender, "120000000", usd("120"), 2, "BD1", "BN2")),
    ocan("S6", 182, R.sender, fillMeta(R.sender, "110000000", usd("110"), 3, "BD1", "BN1")),
  ];
  const r = analyzeLedger({ transactions: txs }, {});
  assert.ok(!has(r.findings, "spoof-offer-cycle"), "spoofMaxCancelLedgers 75 überschritten");
});
test("spoof-offer-cycle: Guard — nur 1 Preislevel (Legitimer Order-Ersatz) bleibt benign", () => {
  const txs = [
    oc("S1", 100, R.sender, placeMeta(R.sender, 1, "BD1", "BN1", "100000000", usd("100"))),
    oc("S2", 101, R.sender, placeMeta(R.sender, 2, "BD1", "BN1", "110000000", usd("110"))),
    oc("S3", 102, R.sender, placeMeta(R.sender, 3, "BD1", "BN1", "120000000", usd("120"))),
    ocan("S4", 110, R.sender, fillMeta(R.sender, "100000000", usd("100"), 1, "BD1", "BN1")),
    ocan("S5", 111, R.sender, fillMeta(R.sender, "110000000", usd("110"), 2, "BD1", "BN1")),
    ocan("S6", 112, R.sender, fillMeta(R.sender, "120000000", usd("120"), 3, "BD1", "BN1")),
  ];
  const r = analyzeLedger({ transactions: txs }, {});
  assert.ok(!has(r.findings, "spoof-offer-cycle"), "spoofMinPriceLevels 2 nicht erreicht");
});
test("spoof-offer-cycle: Guard — Cancel eines FREMDEN Offers (del.Account != tx.Account) zählt nicht", () => {
  const txs = [
    oc("S1", 100, R.sender, placeMeta(R.sender, 1, "BD1", "BN1", "100000000", usd("100"))),
    oc("S2", 101, R.sender, placeMeta(R.sender, 2, "BD1", "BN2", "120000000", usd("120"))),
    oc("S3", 102, R.sender, placeMeta(R.sender, 3, "BD1", "BN1", "110000000", usd("110"))),
    ocan("S4", 110, R.sender, fillMeta(M.maker1, "100000000", usd("100"), 1, "BD1", "BN1")),
    ocan("S5", 111, R.sender, fillMeta(M.maker1, "120000000", usd("120"), 2, "BD1", "BN2")),
    ocan("S6", 112, R.sender, fillMeta(M.maker1, "110000000", usd("110"), 3, "BD1", "BN1")),
  ];
  const r = analyzeLedger({ transactions: txs }, {});
  assert.ok(!has(r.findings, "spoof-offer-cycle"), "Fremde Sequence/BookDirectory matcht nicht");
});
test("Market-Regeln: Guard — reine Platzierungen ohne Cross-Fill erzeugen keine Market-Funde", () => {
  // Bestands-Konvention bleibt unverändert: offer-spam wertet CreatedNode
  // Offer als 'Fill' (hasFill, detector.mjs) -> mit Platzierungs-Meta feuert
  // offer-spam bewusst NICHT ("mit Fill (OfferCreated) kein Fund"). Die
  // Market-Regeln dagegen zählen nur DeletedNode-Offer-Fills (echter Cross,
  // Kommentar offerFillNodesOf) -> ebenfalls kein Fund.
  const txs = Array.from({ length: 12 }, (_, i) =>
    oc(`P${i}`, 100 + i, R.spam, placeMeta(R.spam, i + 1, "BD1", i % 2 ? "BN1" : "BN2", "100000000", usd("100")))
  );
  const r = analyzeLedger({ transactions: txs }, {});
  assert.ok(!has(r.findings, "offer-spam"), "Bestandsregel unverändert: CreatedNode = Fill-Guard");
  assert.ok(!has(r.findings, "spoof-offer-cycle"), "keine Cancel-Paarung -> kein Spoof-Fund");
  assert.ok(!has(r.findings, "amm-wash-swap"), "keine DeletedNode-Fills -> kein Wash-Fund");
  assert.ok(!has(r.findings, "thin-pool-exploit"), "keine DeletedNode-Fills -> kein Thin-Pool-Fund");
});
test("Market-Regeln: Guard — leere Meta (12 OfferCreate ohne jede Nodes) hält offer-spam-intakt, Market still", () => {
  const txs = Array.from({ length: 12 }, (_, i) => ({ hash: `E${i}`, ledger_index: 100 + i, TransactionType: "OfferCreate", Account: R.spam, meta: { AffectedNodes: [] } }));
  const r = analyzeLedger({ transactions: txs }, {});
  assert.ok(has(r.findings, "offer-spam"), "Bestandsregel bleibt intakt (10+ ohne Fill -> info)");
  assert.ok(!has(r.findings, "spoof-offer-cycle"));
  assert.ok(!has(r.findings, "amm-wash-swap"));
  assert.ok(!has(r.findings, "thin-pool-exploit"));
});
