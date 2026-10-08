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
