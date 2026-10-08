// lib/live-edges.test.mjs — Echtzeit-Kanten: Treffer, Guards, Schweregrad.
import test from "node:test";
import assert from "node:assert/strict";
import { liveEdgesOf } from "./live-edges.mjs";

const B = "rLIVEBAD000000000000000000000001", S = "rLIVESEND00000000000000000000002", D = "rLIVEDEST00000000000000000000003";
const pay = (from, to) => ({ tx_json: { TransactionType: "Payment", Account: from, Destination: to } });

test("Kante mit malicious-Endpunkt -> malicious", () => {
  const out = liveEdgesOf([pay(B, D)], [{ severity: "malicious", address: B }]);
  assert.deepEqual(out, [{ from: B, to: D, sev: "malicious" }]);
});
test("Kante mit suspect-Endpunkt -> suspect", () => {
  assert.equal(liveEdgesOf([pay(S, B)], [{ severity: "suspect", address: B }])[0].sev, "suspect");
});
test("Guard: Transaktion ohne Fund-Beteiligung erzeugt keine Kante", () => {
  assert.deepEqual(liveEdgesOf([pay(S, D)], [{ severity: "malicious", address: B }]), []);
});
test("Guard: info-Funde erzeugen keine Echtzeit-Kanten", () => {
  assert.deepEqual(liveEdgesOf([pay(B, D)], [{ severity: "info", address: B }]), []);
});
test("Guard: Selbstzahlung und fehlende Felder werden verworfen", () => {
  assert.deepEqual(liveEdgesOf([pay(B, B), { tx: { Account: B } }], [{ severity: "malicious", address: B }]), []);
});
test("Schweregrad: malicious gewinnt gegen suspect auf derselben Kante", () => {
  const out = liveEdgesOf([pay(B, S)], [{ severity: "suspect", address: B }, { severity: "malicious", address: S }]);
  assert.equal(out[0].sev, "malicious");
});
test("Deckel: höchstens 60 Kanten je Ledger", () => {
  const many = Array.from({ length: 100 }, () => pay(B, D));
  assert.equal(liveEdgesOf(many, [{ severity: "malicious", address: B }]).length, 60);
});
