// lib/detector-coverage.test.mjs — Abdeckungs-Regressionen der Engine
// (Audit 2026-10-08 gegen rippled transactions.macro + xrpl.js models).
// Jeder Fall: Treffer UND Guard. Synthetische Adressen, keine Köder.
import test from "node:test";
import assert from "node:assert/strict";
import { analyzeTx, analyzeLedger } from "./detector.mjs";

const B = "rTESTBADCOV000000000000000000001";
const S = "rTESTSENDCOV00000000000000000002";
const D = "rTESTDESTCOV00000000000000000003";
const K = "rTESTKEYCOV000000000000000000004";
const ctx = { knownBad: new Set([B]) };
const has = (f, id) => f.some((x) => x.ruleId === id);

test("SetRegularKey: Kontrollübergabe an bekannt-maliziöse Adresse -> malicious", () => {
  const f = analyzeTx({ TransactionType: "SetRegularKey", Account: S, RegularKey: B }, null, ctx);
  assert.ok(has(f, "known-bad-hit"));
  assert.equal(f.find((x) => x.ruleId === "known-bad-hit").severity, "malicious");
});
test("SetRegularKey Guard: Key einer unbekannten Adresse -> kein Fund", () => {
  assert.equal(analyzeTx({ TransactionType: "SetRegularKey", Account: S, RegularKey: K }, null, ctx).length, 0);
});

test("SignerListSet: bekannt-maliziöser Signer (Hintertür) -> Fund", () => {
  const tx = { TransactionType: "SignerListSet", Account: S, SignerQuorum: 1,
    SignerEntries: [{ SignerEntry: { Account: B, SignerWeight: 1 } }] };
  assert.ok(has(analyzeTx(tx, null, ctx), "known-bad-hit"));
});
test("SignerListSet Guard: Signer unbekannt -> kein Fund", () => {
  const tx = { TransactionType: "SignerListSet", Account: S, SignerQuorum: 1,
    SignerEntries: [{ SignerEntry: { Account: K, SignerWeight: 1 } }] };
  assert.equal(analyzeTx(tx, null, ctx).length, 0);
});

test("Clawback: Holder bekannt-maliziös -> suspect (nur Positions-Beteiligung)", () => {
  const tx = { TransactionType: "Clawback", Account: S, Amount: { currency: "USD", issuer: B, value: "10" } };
  const f = analyzeTx(tx, null, ctx);
  assert.ok(has(f, "known-bad-hit"));
  assert.equal(f.find((x) => x.ruleId === "known-bad-hit").severity, "suspect");
});

test("AMM: bekannt-maliziöser Pool-Asset-Issuer -> suspect", () => {
  const tx = { TransactionType: "AMMDeposit", Account: S,
    Asset: { currency: "XRP" }, Asset2: { currency: "USD", issuer: B }, Amount: "1000000" };
  const f = analyzeTx(tx, null, ctx);
  assert.ok(has(f, "known-bad-hit"));
  assert.equal(f.find((x) => x.ruleId === "known-bad-hit").severity, "suspect");
});
test("AMM Guard: Pool mit unbekanntem Issuer -> kein Fund", () => {
  const tx = { TransactionType: "AMMDeposit", Account: S,
    Asset: { currency: "XRP" }, Asset2: { currency: "USD", issuer: K }, Amount: "1000000" };
  assert.equal(analyzeTx(tx, null, ctx).length, 0);
});

test("NFTokenMint: Issuer bekannt-maliziös -> Fund (Issuer-Feld jetzt Akteur)", () => {
  const tx = { TransactionType: "NFTokenMint", Account: S, Issuer: B, NFTokenTaxon: 0 };
  assert.ok(has(analyzeTx(tx, null, ctx), "known-bad-hit"));
});

test("DepositPreauth: Authorize bekannt-maliziös -> Fund", () => {
  const tx = { TransactionType: "DepositPreauth", Account: S, Authorize: B };
  assert.ok(has(analyzeTx(tx, null, ctx), "known-bad-hit"));
});

test("Batch: Inner-Transaktion mit bekannt-maliziösem Ziel wird gefunden (XLS-56)", () => {
  const batch = { TransactionType: "Batch", Account: S, RawTransactions: [
    { RawTransaction: { TransactionType: "Payment", Account: S, Destination: B, Amount: "5000000" } },
  ] };
  const res = analyzeLedger({ result: { ledger: { ledger_index: 100, transactions: [{ tx_json: batch, meta: null }] } } }, ctx);
  assert.ok(res.findings.some((f) => f.ruleId === "known-bad-hit"), "Inner-Tx muss analysiert werden");
});
test("Batch Guard: Batch ohne Inner-Treffer bleibt ohne Fund", () => {
  const batch = { TransactionType: "Batch", Account: S, RawTransactions: [
    { RawTransaction: { TransactionType: "Payment", Account: S, Destination: D, Amount: "5000000" } },
  ] };
  const res = analyzeLedger({ result: { ledger: { ledger_index: 100, transactions: [{ tx_json: batch, meta: null }] } } }, ctx);
  assert.equal(res.findings.length, 0);
});

// ---------- Governance-Pseudotransaktionen (Validator-Sicherheit) ----------
test("UNLModify -> validator-unl-change (suspect), Pseudo-Adresse statt Täter", () => {
  const f = analyzeTx({ TransactionType: "UNLModify", Account: "rrrrrrrrrrrrrrrrrrrrrhoLvTp", UNLModifyValidator: "ED00" }, null, ctx);
  const hit = f.find((x) => x.ruleId === "validator-unl-change");
  assert.ok(hit);
  assert.equal(hit.severity, "suspect");
  assert.equal(hit.address, "rrrrrrrrrrrrrrrrrrrrrhoLvTp");
});
test("EnableAmendment -> amendment-enabled (info); SetFee -> fee-change (info)", () => {
  const a = analyzeTx({ TransactionType: "EnableAmendment", Account: "rrrrrrrrrrrrrrrrrrrrrhoLvTp" }, null, ctx);
  const b = analyzeTx({ TransactionType: "SetFee", Account: "rrrrrrrrrrrrrrrrrrrrrhoLvTp" }, null, ctx);
  assert.equal(a.find((x) => x.ruleId === "amendment-enabled")?.severity, "info");
  assert.equal(b.find((x) => x.ruleId === "fee-change")?.severity, "info");
});
test("Guard: normale Payment löst keine Governance-Regel aus", () => {
  const f = analyzeTx({ TransactionType: "Payment", Account: S, Destination: D, Amount: "1000000" }, null, ctx);
  assert.ok(!f.some((x) => ["validator-unl-change", "amendment-enabled", "fee-change"].includes(x.ruleId)));
});

// ---------- amm-pool-drain (XRP-Seite aus meta) ----------
const ammMeta = (before, after) => ({ AffectedNodes: [{ ModifiedNode: { LedgerEntryType: "AMM",
  PreviousFields: { Amount: String(before) }, FinalFields: { Amount: String(after) } } }] });
test("amm-pool-drain: AMMWithdraw leert 80 % des XRP-Pools -> Fund", () => {
  const tx = { TransactionType: "AMMWithdraw", Account: S };
  const f = analyzeTx(tx, ammMeta(100_000_000, 20_000_000), ctx);
  const hit = f.find((x) => x.ruleId === "amm-pool-drain");
  assert.ok(hit, "Abfluss >= 50 % muss gemeldet werden");
  assert.equal(hit.severity, "suspect");
});
test("amm-pool-drain Guard: 10 % Abfluss bleibt ohne Fund", () => {
  const f = analyzeTx({ TransactionType: "AMMWithdraw", Account: S }, ammMeta(100_000_000, 90_000_000), ctx);
  assert.ok(!f.some((x) => x.ruleId === "amm-pool-drain"));
});
test("amm-pool-drain Guard: Staub-Pool (< 10 XRP) bleibt ohne Fund", () => {
  const f = analyzeTx({ TransactionType: "AMMWithdraw", Account: S }, ammMeta(5_000_000, 0), ctx);
  assert.ok(!f.some((x) => x.ruleId === "amm-pool-drain"));
});
test("amm-pool-drain: reiner IOU-Pool (Amount als Objekt) wird gewertet", () => {
  const meta = { AffectedNodes: [{ ModifiedNode: { LedgerEntryType: "AMM", PreviousFields: { Amount: { value: "100" } }, FinalFields: { Amount: { value: "1" } } } }] };
  assert.ok(analyzeTx({ TransactionType: "AMMWithdraw", Account: S }, meta, ctx).some((x) => x.ruleId === "amm-pool-drain"));
});

// ---------- amm-pool-drain: IOU-Seite (Amount2 als Objekt) ----------
const ammIouMeta = (xrpB, xrpA, iouB, iouA) => ({ AffectedNodes: [{ ModifiedNode: { LedgerEntryType: "AMM",
  PreviousFields: { Amount: String(xrpB), Amount2: { currency: "USD", issuer: "rIOUISSUER000000000000000000001", value: String(iouB) } },
  FinalFields: { Amount: String(xrpA), Amount2: { currency: "USD", issuer: "rIOUISSUER000000000000000000001", value: String(iouA) } } } }] });
test("amm-pool-drain: IOU-Seite zu 80 % geleert (XRP unverändert) -> Fund mit side=IOU", () => {
  const f = analyzeTx({ TransactionType: "AMMWithdraw", Account: S }, ammIouMeta(100_000_000, 100_000_000, 500, 100), ctx);
  const hit = f.find((x) => x.ruleId === "amm-pool-drain");
  assert.ok(hit, "IOU-Abfluss >= 50 % muss gemeldet werden");
  assert.equal(hit.noteParams.side, "IOU");
});
test("amm-pool-drain Guard: IOU-Seite mit Staub-Reserve (< 10) bleibt still", () => {
  const f = analyzeTx({ TransactionType: "AMMWithdraw", Account: S }, ammIouMeta(100_000_000, 100_000_000, 5, 0), ctx);
  assert.ok(!f.some((x) => x.ruleId === "amm-pool-drain"));
});
