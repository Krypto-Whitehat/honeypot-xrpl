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
  const txs = [d1, d2].map((d) => ({ TransactionType: "Payment", Account: R.sender, Destination: d, Amount: "100" }));
  const r = analyzeLedger({ transactions: txs }, { firstSeenAt: freshMap(d1, d2) });
  assert.ok(has(r.findings, "dusting"));
  assert.equal(sev(r.findings, "dusting"), "suspect");
});
test("dusting: Guard (FP-Regression) — eine einzelne Mini-Zahlung an ein frisches Konto ist benign", () => {
  const txs = [{ TransactionType: "Payment", Account: R.sender, Destination: R.dest, Amount: "100" }];
  const r = analyzeLedger({ transactions: txs }, { firstSeenAt: freshMap(R.dest) });
  assert.ok(!has(r.findings, "dusting"));
});
test("dusting: Guard — ohne Frische-Signal und < 3 Ziele kein Fund", () => {
  const txs = [{ TransactionType: "Payment", Account: R.sender, Destination: R.dest, Amount: "100" }];
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
  const txs = [d1, d2].map((d) => ({ TransactionType: "Payment", Account: R.sender, Destination: d, Amount: "100" }));
  const r = analyzeLedger({ transactions: txs }, { firstSeenAt: freshMap(d1, d2), benignAccounts: new Set([d1, d2]) });
  assert.ok(!has(r.findings, "dusting"));
});

// ---------- drainer-sweep ----------
const drainMeta = {
  AffectedNodes: [{ ModifiedNode: { LedgerEntryType: "AccountRoot", PreviousFields: { Balance: "100000" }, FinalFields: { Balance: "5000" } } }],
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
test("offer-spam: Treffer >=3 OfferCreate ohne Fill", () => {
  const txs = [
    { TransactionType: "OfferCreate", Account: R.spam, meta: { AffectedNodes: [] } },
    { TransactionType: "OfferCancel", Account: R.spam, meta: { AffectedNodes: [] } },
    { TransactionType: "OfferCreate", Account: R.spam, meta: { AffectedNodes: [] } },
    { TransactionType: "OfferCreate", Account: R.spam, meta: { AffectedNodes: [] } },
  ];
  const r = analyzeLedger({ transactions: txs }, {});
  assert.ok(has(r.findings, "offer-spam"));
  assert.equal(sev(r.findings, "offer-spam"), "info");
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
    TransactionType: "EscrowCreate", Account: R.sender, Destination: R.dest, Amount: "100",
    Memos: [{ Memo: { MemoData: hex("verify your claim http://phish.example") } }],
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
  const txs = [d1, d2, d3].map((d) => ({ TransactionType: "CheckCreate", Account: R.sender, Destination: d, Amount: "100" }));
  const r = analyzeLedger({ transactions: txs }, { firstSeenAt: freshMap(d1, d2, d3) });
  assert.ok(has(r.findings, "escrow-check-bait"));
});

// ---------- payment-burst ----------
test("payment-burst: Treffer >=5 Ziele mit winzigen Beträgen", () => {
  const dests = ["A1", "A2", "A3", "A4", "A5"].map((s) => `rTESTBURST00000000000000000000${s}`);
  const txs = dests.map((d) => ({ TransactionType: "Payment", Account: R.sender, Destination: d, Amount: "500" }));
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
  const txs = dests.map((d) => ({ TransactionType: "Payment", Account: R.sender, Destination: d, Amount: "100" }));
  const r = analyzeLedger({ ledger: { transactions: txs } }, {});
  assert.ok(has(r.findings, "dusting"));
  assert.equal(r.stats.txs, 3);
  assert.equal(r.stats.findings, r.findings.length);
});

// ---------- ruleCatalog ----------
test("ruleCatalog: 9 Regeln mit gültigem severity-Enum", () => {
  const cat = ruleCatalog();
  assert.equal(cat.length, 9);
  for (const r of cat) {
    assert.ok(["malicious", "suspect", "info"].includes(r.severity), `severity ${r.severity}`);
    assert.ok(r.id && r.name);
  }
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
    TransactionType: "EscrowCreate", Account: R.sender, Destination: R.dest, Amount: "100",
    Memos: [{ Memo: { MemoData: hex("verify your claim http://phish.example") } }],
  };
  const f = one(analyzeTx(tx, null, { firstSeenAt: freshMap(R.dest) }), "escrow-check-bait");
  assert.equal(f.noteKey, "escrow-check-bait-single");
  assert.deepEqual(f.noteParams, { type: "EscrowCreate", addr: "rTESTDES…0002" });
  assert.ok(f.note.includes("rTESTDES…0002"), "note enthält dieselbe Kurzform wie noteParams");
});

test("noteKey: dusting — fresh- und many-Variante mit Zähler", () => {
  const d1 = "rTESTDUSTFRESHA000000000000001";
  const d2 = "rTESTDUSTFRESHB000000000000002";
  const txs = [d1, d2].map((d) => ({ TransactionType: "Payment", Account: R.sender, Destination: d, Amount: "100" }));
  const fresh = one(analyzeLedger({ transactions: txs }, { firstSeenAt: freshMap(d1, d2) }).findings, "dusting");
  assert.equal(fresh.noteKey, "dusting-fresh");
  assert.deepEqual(fresh.noteParams, { n: 2 });
  const dests = ["C1", "C2", "C3"].map((s) => `rTESTDUST000000000000000000000${s}`);
  const manyTxs = dests.map((d) => ({ TransactionType: "Payment", Account: R.sender, Destination: d, Amount: "100" }));
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
  const txs = [
    { TransactionType: "OfferCreate", Account: R.spam, meta: { AffectedNodes: [] } },
    { TransactionType: "OfferCancel", Account: R.spam, meta: { AffectedNodes: [] } },
    { TransactionType: "OfferCreate", Account: R.spam, meta: { AffectedNodes: [] } },
    { TransactionType: "OfferCreate", Account: R.spam, meta: { AffectedNodes: [] } },
  ];
  const f = one(analyzeLedger({ transactions: txs }, {}).findings, "offer-spam");
  assert.equal(f.noteKey, "offer-spam");
  assert.deepEqual(f.noteParams, { n: 3 });
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
  const txs = [d1, d2, d3].map((d) => ({ TransactionType: "CheckCreate", Account: R.sender, Destination: d, Amount: "100" }));
  const f = one(analyzeLedger({ transactions: txs }, { firstSeenAt: freshMap(d1, d2, d3) }).findings, "escrow-check-bait");
  assert.equal(f.noteKey, "escrow-check-bait-burst");
  assert.deepEqual(f.noteParams, { n: 3 });
});

test("noteKey: payment-burst — Ziel- und Winzig-Zähler in noteParams", () => {
  const dests = ["A1", "A2", "A3", "A4", "A5"].map((s) => `rTESTBURST00000000000000000000${s}`);
  const txs = dests.map((d) => ({ TransactionType: "Payment", Account: R.sender, Destination: d, Amount: "500" }));
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
