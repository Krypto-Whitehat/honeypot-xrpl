// lib/cluster-tx-amounts.test.mjs — Geldseite der Cluster-Kanten gegen Live-Autoritaet.
//
// Die Entries sind die echten expand:true-Formen aus lib/fixtures/live-tx-values.json
// (flach, Meta unter metaData) - genau so, wie api/ledger.js und der Browser-Pfad
// sie an lib/cluster.mjs geben. Synthetische Faelle nutzen rTEST…-Adressen
// (Muster lib/cluster.test.mjs:28-46: keine echten, keine Koeder).
import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { buildClusterGraph, txRecordFromEntry } from "./cluster.mjs";

const FX = JSON.parse(fs.readFileSync(path.join(path.dirname(fileURLToPath(import.meta.url)), "fixtures", "live-tx-values.json"), "utf8"));
const rec = (label) => {
  const r = FX.records.find((x) => x.label === label);
  assert.ok(r, `Fixture ${label} fehlt`);
  return r;
};
const T = {
  a: "rTESTSRC1000000000000000000000001",
  b: "rTESTDST000000000000000000000001",
  c: "rTESTOFFER000000000000000000001",
  iso: "2026-10-17T12:00:00Z",
};
const finding = (address, severity = "malicious", ruleId = "drainer-sweep") => ({ ruleId, severity, address, note: "fixture" });

// ---------- 1) jede Live-Entry: Kantensumme == delivered_amount der tx-Autoritaet ----------
test("Live-Entries: txRecordFromEntry nennt den nachgewiesenen Betrag, nicht den Anspruch", () => {
  const expect = { ceiling: 34, dry1: null, dry2: null, direct: 10, nftOffer: null, selfPay: 1213, selfPayBig: 107324910, exchange: 692324 };
  for (const [label, want] of Object.entries(expect)) {
    const r = rec(label);
    const out = txRecordFromEntry(r.entry, r.iso ?? null);
    assert.ok(out, label);
    assert.equal(out.amountDrops, want, `${label}: Amount ${JSON.stringify(r.entry.Amount)} gegen Autoritaet ${JSON.stringify(r.authority.meta.delivered_amount)}`);
    assert.equal(out.amountDrops, r.authority.meta.delivered_amount === undefined ? null : Number(r.authority.meta.delivered_amount), label);
  }
});

// ---------- 2) Der Deckel-Fall in der Kante und in der Cluster-Summe ----------
test("Deckel-Fall: Kante traegt 34 Drops, Cluster-totalDrops 34 (nicht 1e17)", () => {
  const r = rec("ceiling");
  const out = txRecordFromEntry(r.entry, null);
  const g = buildClusterGraph([out], [finding(out.account)]);
  const edge = g.edges.find((e) => e.txHash === r.hash);
  assert.ok(edge, "Kante Account -> Destination");
  assert.equal(edge.amountDrops, 34);
  assert.equal(edge.from, r.entry.Account);
  assert.equal(edge.to, r.entry.Destination);
  const cluster = g.clusters.find((c) => c.memberAddresses.includes(r.entry.Account));
  assert.ok(cluster, "Cluster um den Absender");
  assert.equal(cluster.totalDrops, 34);
});

// ---------- 3) fehlgeschlagene Zahlung: Kante ohne Geld, Summe bleibt leer ----------
test("tecPATH_DRY live: null Betrag, und als Selbstzahlung keine Bewegung-Kante", () => {
  const outs = ["dry1", "dry2"].map((label) => txRecordFromEntry(rec(label).entry, null));
  for (const out of outs) {
    assert.equal(out.amountDrops, null, "1e14 Drops Anspruch, 0 Drops Bewegung");
    assert.equal(out.account, out.destination, "live: both are path self-payments");
  }
  const g = buildClusterGraph(outs, [finding(outs[0].account)]);
  assert.equal(g.edges.length, 0, "Selbstzahlung ist keine Bewegung zwischen zwei Parteien (Self-Ref-Guard)");
});
test("Fehlgeschlagene Zahlung an ein fremdes Ziel: Kante bleibt, Geld nicht, Summe 0", () => {
  const entry = {
    hash: "TESTDRY", ledger_index: 101, TransactionType: "Payment", Account: T.a, Destination: T.b,
    Amount: "100000000000000", SendMax: { currency: "TKT", issuer: T.c, value: "1" },
    metaData: { TransactionResult: "tecPATH_DRY", AffectedNodes: [] },
  };
  const out = txRecordFromEntry(entry, T.iso);
  assert.equal(out.amountDrops, null);
  assert.equal(out.destination, T.b);
  const g = buildClusterGraph([out], [finding(T.a)]);
  assert.equal(g.edges.length, 1);
  assert.equal(g.clusters[0].totalDrops, 0);
});

// ---------- 4) Angebots-Preis darf nicht in die Geldsumme ----------
test("NFTokenCreateOffer mit Destination: Kante vorhanden, Betrag null, Summe 0", () => {
  const entry = {
    hash: "TESTNFTOFFER", ledger_index: 100, TransactionType: "NFTokenCreateOffer",
    Account: T.a, Owner: T.c, Destination: T.b, Amount: "6130000",
    metaData: { TransactionResult: "tesSUCCESS", AffectedNodes: [] },
  };
  const out = txRecordFromEntry(entry, T.iso);
  assert.equal(out.destination, T.b);
  assert.equal(out.amountDrops, null, "Preis beim CREATE ist keine Bewegung (cluster.mjs sagt das selbst)");
  const g = buildClusterGraph([out], [finding(T.a)]);
  assert.equal(g.edges[0].amountDrops, null);
  assert.equal(g.clusters[0].totalDrops, 0);
});

// ---------- 5) NFTokenAcceptOffer: Geld nur bei Erfolg ----------
const nftAcceptEntry = (result) => ({
  hash: "TESTACCEPT" + result, ledger_index: 200, TransactionType: "NFTokenAcceptOffer",
  Account: T.a, NFTokenSellOffer: "OFFER1",
  metaData: {
    TransactionResult: result,
    AffectedNodes: [{ DeletedNode: { LedgerEntryType: "NFTokenOffer", FinalFields: { Owner: T.c, Amount: "4500", NFTokenSellOffer: true } } }],
  },
});
test("NFTokenAcceptOffer: erfolgreiche Annahme zahlt Offer-Preis an den Owner", () => {
  const out = txRecordFromEntry(nftAcceptEntry("tesSUCCESS"), T.iso);
  assert.equal(out.destination, T.c);
  assert.equal(out.amountDrops, 4500);
});
test("NFTokenAcceptOffer mit tecEXPIRED: keine Kante, kein Betrag", () => {
  const out = txRecordFromEntry(nftAcceptEntry("tecEXPIRED"), T.iso);
  assert.ok(!out.destination, "keine Gegenpartei ohne Bewegung");
  assert.equal(out.amountDrops, null);
});

// ---------- 6) Meta-Rohform und gestempelte Form fuehren zum selben Betrag ----------
test("metaData-Rohform und meta-Stempel (api/advance.js:538) ergeben denselben Kantensatz", () => {
  const r = rec("ceiling");
  const raw = txRecordFromEntry({ ...r.entry, metaData: r.entry.metaData }, null);
  const stamped = txRecordFromEntry({ ...r.entry, meta: r.entry.metaData }, null);
  assert.deepEqual(raw, stamped);
  assert.equal(raw.amountDrops, 34);
  // Ohne jede Meta wird nichts erfunden: die Fremdwaehrungs-Zahlung bleibt ohne
  // XRP-Betrag (kein delivered_amount, kein Kontodelta), eine direkte
  // XRP-Zahlung behaelt ihren nach Spec exakten Amount.
  const noMeta = { ...r.entry };
  delete noMeta.metaData;
  delete noMeta.meta;
  assert.equal(txRecordFromEntry(noMeta, null).amountDrops, null, "Deckel ohne Beleg ist keine Zahl");
  const directNoMeta = { ...rec("direct").entry };
  delete directNoMeta.metaData;
  delete directNoMeta.meta;
  assert.equal(txRecordFromEntry(directNoMeta, null).amountDrops, 10);
});
