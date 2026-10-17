// lib/tx-values.test.mjs — node:test-Unit-Tests fuer die Geldseite der Engine.
//
// Fixtures (lib/fixtures/live-tx-values.json) sind ECHTE expand:true-Entries von
// xrplcluster.com, jeweils dazu die tx-Autoritaet desselben Hash (delivered_amount,
// TransactionResult, AffectedNodes). Synthetische Faelle sind als solche benannt.
// Live-Belege 2026-10-17: Deckel F4134FC4... (Amount 1e17, deliveriert 34),
// tecPATH_DRY 2583F45F.../4969980B... (je Amount 1e14, bewegt nichts),
// Selbstzahlung C92240C9... (deliveriert 1213, Kontodelta 1201 bei Fee 12).
import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { engineResultOf, isExecuted, metaOf, movedIouOf, movedXrpOf, xrpDeltaOf, TX_SUCCESS } from "./tx-values.mjs";

const FX = JSON.parse(fs.readFileSync(path.join(path.dirname(fileURLToPath(import.meta.url)), "fixtures", "live-tx-values.json"), "utf8"));
const rec = (label) => {
  const r = FX.records.find((x) => x.label === label);
  assert.ok(r, `Fixture ${label} fehlt`);
  return r;
};
const metaWithoutDelivered = (m) => {
  const copy = { ...m };
  delete copy.delivered_amount;
  delete copy.DeliveredAmount;
  return copy;
};

// ---------- 1) DeliverMax-DECKEL ist nicht das bewegte Geld ----------
test("Live-Deckel: Engine nennt deliveriert (34), nicht den Anspruch (1e17 Drops)", () => {
  const r = rec("ceiling");
  assert.equal(r.entry.TransactionType, "Payment");
  assert.equal(Number(r.entry.Amount), 100000000000000000); // der Deckel steht so im Ledger
  assert.equal(Number(r.authority.meta.delivered_amount), 34);
  const moved = movedXrpOf(r.entry, metaOf(r.entry));
  assert.equal(moved, 34);
  assert.equal(moved, Number(r.authority.meta.delivered_amount));
  // Der Fehler der alten Lesart, beziffert statt behauptet: 99.999.999.999.999.966
  // Drops zu viel, das 2.941.176.470.588.235-fache des realen Betrags.
  assert.equal(Number(r.entry.Amount) - moved, 99999999999999966);
  assert.ok(Math.abs(Number(r.entry.Amount) / moved - 2.941176470588235e15) < 1);
});

// ---------- 2) delta-Pfad ohne delivered_amount: gegen Kontodelta nachgerechnet ----------
test("Ohne delivered_amount: Engine leitet 34 aus dem Ziel-Kontodelta ab (live validiert)", () => {
  const r = rec("ceiling");
  const meta = metaWithoutDelivered(metaOf(r.entry));
  const derived = movedXrpOf(r.entry, meta);
  const delta = xrpDeltaOf(meta, r.entry.Destination);
  assert.equal(delta, 34, "Gegenprobe: Ziel-Konto 1391958 -> 1391992");
  assert.equal(derived, 34);
  assert.equal(derived, Number(r.authority.meta.delivered_amount));
});

// ---------- 3) fehlgeschlagene Zahlungen bewegen nichts ----------
test("tecPATH_DRY: zwei Live-Zahlungen mit je 1e14 Drops Anspruch liefern null", () => {
  for (const label of ["dry1", "dry2"]) {
    const r = rec(label);
    assert.equal(engineResultOf(metaOf(r.entry), r.entry), "tecPATH_DRY");
    assert.equal(isExecuted(metaOf(r.entry), r.entry), false);
    assert.equal(Number(r.entry.Amount), 100000000000000);
    assert.equal(movedXrpOf(r.entry, metaOf(r.entry)), null);
    assert.equal(movedIouOf(r.entry, metaOf(r.entry)), null);
  }
});
test("Unbekanntes Engine-Ergebnis ist kein tesSUCCESS", () => {
  assert.equal(engineResultOf({ TransactionResult: "tecNO_DST_INSUF_XRP" }, null), "tecNO_DST_INSUF_XRP");
  assert.equal(isExecuted({ TransactionResult: "tecNO_DST_INSUF_XRP" }, null), false);
  assert.equal(isExecuted({ TransactionResult: TX_SUCCESS }, null), true);
});
test("Ohne Meta-Beleg gilt die Transaktion nicht als gescheitert", () => {
  assert.equal(engineResultOf(null, null), null);
  assert.equal(isExecuted(null, null), true);
  const payment = { TransactionType: "Payment", Account: "rA", Destination: "rB", Amount: "500" };
  assert.equal(movedXrpOf(payment, null), 500);
});

// ---------- 4) direkte XRP-Zahlung: Amount ist nach Spec exakt ----------
test("Live-Direktzahlung: Amount 10 Drops == delivered_amount 10 == Ziel-Delta 10", () => {
  const r = rec("direct");
  assert.equal(r.entry.SendMax, undefined);
  assert.equal(movedXrpOf(r.entry, metaOf(r.entry)), 10);
  assert.equal(Number(r.authority.meta.delivered_amount), 10);
  assert.equal(xrpDeltaOf(metaOf(r.entry), r.entry.Destination), 10);
  // Der Sender-Delta enthaelt die Gebuehr (10 + 11 Fee) - deshalb ist das Ziel
  // die Ableitungsseite, nie die Absenderseite.
  assert.equal(xrpDeltaOf(metaOf(r.entry), r.entry.Account), -21);
  assert.equal(Number(r.entry.Fee), 11);
});

// ---------- 5) Selbstzahlung: Kontodelta ist 'deliveriert - Fee' ----------
test("Live-Selbstzahlung: delivered 1213, aber Kontodelta 1201 (Fee 12) - Engine nimmt 1213", () => {
  const r = rec("selfPay");
  assert.equal(r.entry.Account, r.entry.Destination);
  assert.equal(Number(r.entry.Amount), 1000000000000000); // Deckel
  assert.equal(Number(r.authority.meta.delivered_amount), 1213);
  assert.equal(xrpDeltaOf(metaOf(r.entry), r.entry.Destination), 1201, "Gebuehr liegt auf demselben Knoten");
  assert.equal(movedXrpOf(r.entry, metaOf(r.entry)), 1213);
});
test("Selbstzahlung ohne delivered_amount: null statt Gebuehren-Auf schaetzen", () => {
  for (const label of ["selfPay", "selfPayBig", "exchange"]) {
    const r = rec(label);
    const meta = metaWithoutDelivered(metaOf(r.entry));
    assert.equal(movedXrpOf(r.entry, meta), null, label);
  }
  const r = rec("selfPayBig");
  assert.equal(Number(r.authority.meta.delivered_amount), 107324910);
  assert.equal(xrpDeltaOf(metaOf(r.entry), r.entry.Destination), 107324889);
  assert.equal(movedXrpOf(r.entry, metaOf(r.entry)), 107324910);
});

// ---------- 6) Angebots-Preise sind kein Geld ----------
test("Live-NFTokenCreateOffer: Preis 6130000 Drops, Engine bewegt 0", () => {
  const r = rec("nftOffer");
  assert.equal(r.entry.TransactionType, "NFTokenCreateOffer");
  assert.equal(Number(r.entry.Amount), 6130000);
  assert.equal(movedXrpOf(r.entry, metaOf(r.entry)), null);
  assert.equal(movedIouOf(r.entry, metaOf(r.entry)), null);
});
test("Angebots-und-Verwaltungs-Typen liefern null (synthetisch, Spec-begruendet)", () => {
  const meta = { TransactionResult: "tesSUCCESS" };
  for (const type of ["NFTokenCreateOffer", "OfferCreate", "OfferCancel", "TrustSet", "AccountSet", "NFTokenMint", "EnableAmendment", "SetFee", "UNLModify", "EscrowCancel", "CheckCancel"]) {
    const tx = { TransactionType: type, Account: "rA", Destination: "rB", Amount: "1000000" };
    assert.equal(movedXrpOf(tx, meta), null, type);
    assert.equal(movedIouOf(tx, meta), null, type);
  }
});
test("Richtung einer Zahlung: EscrowCreate bindet XRP des Absenders (Amount zaeht)", () => {
  const tx = { TransactionType: "EscrowCreate", Account: "rA", Destination: "rB", Amount: "1000" };
  assert.equal(movedXrpOf(tx, { TransactionResult: "tesSUCCESS" }), 1000);
  assert.equal(movedXrpOf(tx, { TransactionResult: "tecNO_INVALIDATE" }), null);
});

// ---------- 7) metaOf deckt beide Lieferformen ----------
test("metaOf: flache expand-Entry (metaData), {tx_json,meta}, {tx,meta}, inner", () => {
  const r = rec("ceiling");
  assert.equal(metaOf(r.entry), r.entry.metaData);
  assert.equal(metaOf({ tx_json: { TransactionType: "Payment" }, meta: { TransactionResult: "tesSUCCESS" } }).TransactionResult, "tesSUCCESS");
  assert.equal(metaOf({ tx: { TransactionType: "Payment" }, meta: { TransactionResult: "tecPATH_DRY" } }).TransactionResult, "tecPATH_DRY");
  assert.equal(metaOf({ tx: { TransactionType: "Payment", metaData: { TransactionResult: "tesSUCCESS" } } }).TransactionResult, "tesSUCCESS");
  assert.equal(metaOf(null), null);
  assert.equal(metaOf("x"), null);
  assert.equal(metaOf({ TransactionType: "Payment" }), null);
});
test("Engine-Ergebnis wird auch aus der Transaktion selbst gelesen (WSS-Form)", () => {
  assert.equal(engineResultOf(null, { transaction_state: "tecPATH_DRY" }), "tecPATH_DRY");
  assert.equal(movedXrpOf({ TransactionType: "Payment", Account: "rA", Destination: "rB", Amount: "5", transaction_state: "tecPATH_DRY" }, null), null);
});

// ---------- 8) IOU: SendMax ist kein Abfluss, delivered_amount-Objekt schon ----------
test("Live-Deckel mit IOU-SendMax: keine IOU-Bewegung behauptet", () => {
  const r = rec("ceiling");
  assert.equal(typeof r.entry.SendMax, "object");
  assert.equal(movedIouOf(r.entry, metaOf(r.entry)), null, "SendMax ist ein Hochstbetrag");
});
test("IOU-Lieferung: delivered_amount-Objekt fuehrt die Währung, Amount-Deckel nicht", () => {
  const iou = { currency: "5553440000000000000000000000000000000000", issuer: "rIssuer", value: "12.5" };
  const tx = { TransactionType: "Payment", Account: "rA", Destination: "rB", Amount: "1000000000", SendMax: iou };
  const meta = { TransactionResult: "tesSUCCESS", delivered_amount: iou };
  assert.equal(movedXrpOf(tx, meta), null, "keine XRP-Bewegung bei IOU-Lieferung");
  assert.deepEqual(movedIouOf(tx, meta), { currency: iou.currency, issuer: iou.issuer, value: 12.5 });
  assert.equal(movedIouOf(tx, { ...meta, delivered_amount: "7" }), null, "XRP-Lieferung ist keine IOU");
});
test("Abgelehnte IOU-Zahlung liefert keine IOU-Bewegung", () => {
  const iou = { currency: "USD", issuer: "rIssuer", value: "3" };
  assert.equal(movedIouOf({ TransactionType: "Payment", Account: "rA", Destination: "rB", Amount: iou }, { TransactionResult: "tecPATH_DRY" }), null);
});

// ---------- 9) xrpDeltaOf: nur eindeutige Konto-Deltas ----------
test("xrpDeltaOf: CreatedNode, zwei Knoten desselben Kontos und IOU-Knoten liefern null", () => {
  const acc = "rDst";
  const oneNode = { AffectedNodes: [{ CreatedNode: { LedgerEntryType: "AccountRoot", FinalFields: { Account: acc, Balance: "500" } } }] };
  assert.equal(xrpDeltaOf(oneNode, acc), null, "CreatedNode hat keinen Vorwert");
  const twoNodes = { AffectedNodes: [
    { ModifiedNode: { LedgerEntryType: "AccountRoot", PreviousFields: { Balance: "10" }, FinalFields: { Account: acc, Balance: "60" } } },
    { ModifiedNode: { LedgerEntryType: "AccountRoot", PreviousFields: { Balance: "10" }, FinalFields: { Account: acc, Balance: "80" } } },
  ] };
  assert.equal(xrpDeltaOf(twoNodes, acc), null, "mehrdeutig statt geraten");
  const iouNode = { AffectedNodes: [{ ModifiedNode: { LedgerEntryType: "RippleState", PreviousFields: { Balance: { value: "1" } }, FinalFields: { Account: acc, Balance: { value: "5" } } } }] };
  assert.equal(xrpDeltaOf(iouNode, acc), null);
  assert.equal(xrpDeltaOf(null, acc), null);
  assert.equal(xrpDeltaOf({ AffectedNodes: [] }, null), null);
});

// ---------- 10) jede Live-Fixture ist gegen ihre Autoritaet geschlossen ----------
test("Alle Live-Fixtures: Engine-Betrag == Autoritaet, kein Defekt offen", () => {
  for (const r of FX.records) {
    const meta = metaOf(r.entry);
    const moved = movedXrpOf(r.entry, meta);
    const authResult = r.authority.meta.TransactionResult;
    const delivered = r.authority.meta.delivered_amount;
    if (authResult !== "tesSUCCESS") { assert.equal(moved, null, `${r.label}: fehlgeschlagen darf kein Geld sein`); continue; }
    if (r.entry.TransactionType === "NFTokenCreateOffer" || r.entry.TransactionType === "OfferCreate") { assert.equal(moved, null, `${r.label}: Angebot ist kein Geld`); continue; }
    assert.equal(moved, Number(delivered), `${r.label}: Engine gegen delivered_amount der tx-Autoritaet`);
  }
});
