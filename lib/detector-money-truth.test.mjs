// lib/detector-money-truth.test.mjs - Geldwahrheit in den Burst-Regeln der Engine.
// Sichert die drei live belegten Defekt-Klassen vom 2026-10-17 gegen Regression:
//   1) DeliverMax-DECKEL statt deliverierter Betrag (live Hash F4134FC4612BC711...E98E),
//   2) abgelehnte Zahlung/Koeschlung zaehlt als Geld (2583F45F4C0A4DCFE3A81F29...C9B1),
//   3) abgelehntes Angebot zaehlt als Aktivitaet (NFTokenCreateOffer E9EF081BEB2D1FAA...742E).
// Diskriminierendes Muster: derselbe Datensatz muss mit tesSUCCESS den Fund liefern
// und mit tec... KEINEN Fund. Damit haengt die Regel an der nachgewiesenen Bewegung
// und nicht am Anspruch im Transaction-Feld.
//
// Ausfuehren: node --test lib/detector-money-truth.test.mjs
import test from "node:test";
import assert from "node:assert/strict";
import { analyzeLedger, DEFAULT_THRESHOLDS } from "./detector.mjs";
import { movedIouOf, movedXrpOf } from "./tx-values.mjs";

const hex = (s) => Buffer.from(s, "utf8").toString("hex");
const NOW = Date.now();
const freshMap = (...addrs) => new Map(addrs.map((a) => [a, NOW - 60_000]));

const A = {
  s1: "rTESTMTSENDER100000000000000001",
  s2: "rTESTMTSENDER200000000000000002",
  s3: "rTESTMTSENDER300000000000000003",
  s4: "rTESTMTSENDER400000000000000004",
  s5: "rTESTMTSENDER500000000000000005",
  collector: "rTESTMTCOLLECTOR000000000000005",
  gateway: "rTESTMTGATEWAY000000000000004",
};
const D1 = "rTESTMTDUSTFRESH1000000000001";
const D2 = "rTESTMTDUSTFRESH2000000000002";
const D3 = "rTESTMTDUSTFRESH3000000000003";

// AccountRoot-Knoten in der Form, wie ledger expand:true ihn liefert
// (PreviousFields = Vorwert, FinalFields = Nachwert inkl. Gebuehr).
const acctNode = (account, prev, final) => ({
  ModifiedNode: {
    LedgerEntryType: "AccountRoot",
    LedgerEntry: { Account: account },
    PreviousFields: { Balance: String(prev) },
    FinalFields: { Account: account, Balance: String(final) },
  },
});
const hasKey = (findings, noteKey) => findings.some((f) => f.noteKey === noteKey);
const has = (findings, ruleId) => findings.some((f) => f.ruleId === ruleId);

// ---------- 1) DeliverMax-DECKEL: Burst rechnet deliveriert, nicht gefordert ----------
const ceilingTx = (dest) => ({
  TransactionType: "Payment", Account: A.s1, Destination: dest, Fee: "10",
  Amount: "100000000000000000", // 100 Mrd XRP = DeliverMax-Deckel, nicht Geld
  SendMax: { currency: "RLUSD", issuer: A.gateway, value: "1" },
  meta: {
    TransactionResult: "tesSUCCESS", delivered_amount: "34",
    AffectedNodes: [acctNode(dest, 1000, 1034)],
  },
});
test("Geldwahrheit Deckel: zwei Zahlungen an frische Ziele zaehlen 34 Drops (deliveriert), nicht 1e17", () => {
  const txs = [ceilingTx(D1), ceilingTx(D2)];
  assert.equal(movedXrpOf(txs[0], txs[0].meta), 34);
  const r = analyzeLedger({ transactions: txs }, { firstSeenAt: freshMap(D1, D2) });
  const f = r.findings.find((x) => x.noteKey === "dusting-fresh");
  assert.ok(f, "deliverierte 34 Drops < dustDrops -> Bagatellfund erwartet");
  assert.equal(f.ruleId, "dusting");
  assert.equal(f.noteParams.n, 2);
});
test("Geldwahrheit Deckel: Control mit echtem Betrag ueber der Bagatellgrenze bleibt benign", () => {
  const txs = [D1, D2].map((d) => ({
    TransactionType: "Payment", Account: A.s1, Destination: d, Amount: "150",
    meta: { TransactionResult: "tesSUCCESS", delivered_amount: "150", AffectedNodes: [acctNode(d, 1000, 1150)] },
  }));
  assert.equal(movedXrpOf(txs[0], txs[0].meta), 150);
  assert.ok(DEFAULT_THRESHOLDS.dustDrops < 150);
  const r = analyzeLedger({ transactions: txs }, { firstSeenAt: freshMap(D1, D2) });
  assert.ok(!has(r.findings, "dusting"));
});

// ---------- 2) Abgelehnte Zahlung bewegt nichts ----------
const dryTx = (dest) => ({
  TransactionType: "Payment", Account: A.s1, Destination: dest, Fee: "12", Amount: "120",
  meta: { TransactionResult: "tecPATH_DRY", AffectedNodes: [acctNode(A.s1, 1000012, 1000000)] },
});
test("Geldwahrheit tecPATH_DRY: zwei abgelehnte Zahlungen bewegen nichts, kein dusting", () => {
  const txs = [dryTx(D1), dryTx(D2)];
  assert.equal(movedXrpOf(txs[0], txs[0].meta), null);
  const r = analyzeLedger({ transactions: txs }, { firstSeenAt: freshMap(D1, D2) });
  assert.ok(!has(r.findings, "dusting"));
});

// Vollsaldo-Welle: mit tecPATH_DRY darf sich mass-sweep-convergence nicht bilden,
// obwohl Kontostand und Amount dieselben Zahlen zeigen wie im echten Sweep.
const sweepTx = (account, result) => ({
  TransactionType: "Payment", Account: account, Destination: A.collector, Fee: "12", Amount: "1000000",
  meta: {
    TransactionResult: result,
    AffectedNodes: result === "tesSUCCESS"
      ? [acctNode(account, 1000012, 12), acctNode(A.collector, 1000, 1001000)]
      : [acctNode(account, 1000012, 1000000)],
    ...(result === "tesSUCCESS" ? { delivered_amount: "1000000" } : {}),
  },
});
const sweepSet = [A.s1, A.s2, A.s3, A.s4, A.s5];
test("Geldwahrheit Welle: fuenf abgelehnte Vollsaldo-Zahlungen erzeugen keinen Sweep-Fund", () => {
  const r = analyzeLedger({ transactions: sweepSet.map((a) => sweepTx(a, "tecPATH_DRY")) }, {});
  assert.ok(!has(r.findings, "mass-sweep-convergence"));
});
test("Geldwahrheit Welle: Control - fuenf ausgefuehrte Vollsaldo-Zahlungen an ein Ziel schlagen an", () => {
  const r = analyzeLedger({ transactions: sweepSet.map((a) => sweepTx(a, "tesSUCCESS")) }, {});
  const f = r.findings.find((x) => x.noteKey === "mass-sweep-convergence");
  assert.ok(f);
  assert.equal(f.noteParams.n, 5);
});

// ---------- 3) Abgelehnte Kontoloeschung zaehlt nicht in die Welle ----------
const delTx = (account, result) => ({
  TransactionType: "AccountDelete", Account: account, Destination: A.collector, Fee: "12",
  meta: {
    TransactionResult: result,
    AffectedNodes: result === "tesSUCCESS"
      ? [{ DeletedNode: { LedgerEntryType: "AccountRoot", FinalFields: { Account: account } } }]
      : [acctNode(account, 100012, 100000)],
  },
});
test("Geldwahrheit account-delete-sweep: tecNO_PERMISSIONS zaehlt nicht mit, 2 echte Loeschungen bleiben unter der Schwelle", () => {
  const r = analyzeLedger({ transactions: [delTx(A.s1, "tesSUCCESS"), delTx(A.s2, "tesSUCCESS"), delTx(A.s3, "tecNO_PERMISSIONS")] }, {});
  assert.ok(!has(r.findings, "account-delete-sweep"));
});
test("Geldwahrheit account-delete-sweep: Control - drei ausgefuehrte Loeschungen an ein Ziel schlagen an", () => {
  const r = analyzeLedger({ transactions: [delTx(A.s1, "tesSUCCESS"), delTx(A.s2, "tesSUCCESS"), delTx(A.s3, "tesSUCCESS")] }, {});
  assert.ok(has(r.findings, "account-delete-sweep"));
});

// ---------- 4) Abgelehnte Platzierung ist kein Angebot ----------
const offerTx = (result) => ({
  TransactionType: "OfferCreate", Account: A.s1, Fee: "12",
  TakerPays: "1000000", TakerGets: { currency: "USD", issuer: A.gateway, value: "1" },
  meta: { TransactionResult: result, AffectedNodes: [acctNode(A.s1, 2000012, 2000000)] },
});
test("Geldwahrheit offer-spam: zehn abgelehnte OfferCreate sind kein Angebot", () => {
  const r = analyzeLedger({ transactions: Array.from({ length: 10 }, () => offerTx("tecNO_PERMISSIONS")) }, {});
  assert.ok(!has(r.findings, "offer-spam"));
});
test("Geldwahrheit offer-spam: Control - zehn ausgefuelle OfferCreate ohne Fill schlagen an", () => {
  const r = analyzeLedger({ transactions: Array.from({ length: 10 }, () => offerTx("tesSUCCESS")) }, {});
  assert.ok(has(r.findings, "offer-spam"));
});

// ---------- 5) Abgelehnter Escrow-Koeser zaehlt nicht ----------
const baitTx = (dest, result) => ({
  TransactionType: "EscrowCreate", Account: A.s1, Destination: dest, Fee: "10", Amount: "50",
  Memos: [{ Memo: { MemoData: hex("Claim your airdrop at http://evil.example/claim") } }],
  meta: { TransactionResult: result, AffectedNodes: [acctNode(A.s1, 100012, 100000)] },
});
test("Geldwahrheit escrow-check-bait: abgelehnte Koeser an drei frische Ziele zaehlen nicht", () => {
  const r = analyzeLedger({ transactions: [baitTx(D1, "tecNO_DST"), baitTx(D2, "tecNO_DST"), baitTx(D3, "tecNO_DST")] }, { firstSeenAt: freshMap(D1, D2, D3) });
  assert.ok(!has(r.findings, "escrow-check-bait"));
});
test("Geldwahrheit escrow-check-bait: Control - drei ausgefuehrte Koeser an frische Ziele schlagen an", () => {
  const r = analyzeLedger({ transactions: [baitTx(D1, "tesSUCCESS"), baitTx(D2, "tesSUCCESS"), baitTx(D3, "tesSUCCESS")] }, { firstSeenAt: freshMap(D1, D2, D3) });
  assert.ok(has(r.findings, "escrow-check-bait"));
});

// ---------- 6) NFTokenCreateOffer: Preis ist kein Geld, Ablehnung ist kein Angebot ----------
const nftOfferTx = (result) => ({
  TransactionType: "NFTokenCreateOffer", Account: A.s1, Owner: D1, NFTokenID: "0", Fee: "10", Amount: "6130000",
  meta: { TransactionResult: result, AffectedNodes: [acctNode(A.s1, 100012, 100000)] },
});
test("Geldwahrheit fake-nft-fraud: fuenf abgelehnte Kaufangebote sind kein Burst", () => {
  const r = analyzeLedger({ transactions: Array.from({ length: 5 }, () => nftOfferTx("tecNO_PERMISSIONS")) }, {});
  assert.ok(!hasKey(r.findings, "fake-nft-fraud-offer"));
});
test("Geldwahrheit fake-nft-fraud: Control - fuenf ausgefuehrte Kaufangebote auf dasselbe Ziel schlagen an", () => {
  const r = analyzeLedger({ transactions: Array.from({ length: 5 }, () => nftOfferTx("tesSUCCESS")) }, {});
  assert.ok(hasKey(r.findings, "fake-nft-fraud-offer"));
});

// ---------- 7) IOU-Zahlung: Beziehung ja, XRP-Claim nein ----------
const iouTx = (dest) => ({
  TransactionType: "Payment", Account: A.s1, Destination: dest, Fee: "12",
  Amount: { currency: "RLUSD", issuer: A.gateway, value: "10" },
  meta: {
    TransactionResult: "tesSUCCESS",
    delivered_amount: { currency: "RLUSD", issuer: A.gateway, value: "10" },
    AffectedNodes: [{ ModifiedNode: { LedgerEntryType: "RippleState", LedgerEntry: { HighAccount: A.gateway, LowAccount: dest } } }],
  },
});
test("Geldwahrheit IOU: Zahlung in Fremdwaehrung erzeugt keinen XRP-Tiny-Claim und kein dusting", () => {
  const txs = [iouTx(D1), iouTx(D2)];
  assert.equal(movedXrpOf(txs[0], txs[0].meta), null);
  assert.equal(movedIouOf(txs[0], txs[0].meta).value, 10);
  const r = analyzeLedger({ transactions: txs }, { firstSeenAt: freshMap(D1, D2) });
  assert.ok(!has(r.findings, "dusting"));
});
