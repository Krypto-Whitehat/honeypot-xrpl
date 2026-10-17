// lib/tx-values.mjs — was eine Transaktion WIRKLICH an XRP bewegt hat.
//
// WARUM ES DIESE DATEI GIBT (Ground-Truth-Runde 2026-10-17, live gemessen):
//  - Die Ledger-Antwort der oeffentlichen RPC-Endpunkte liefert bei expand:true
//    KEIN delivered_amount (live belegt auf honeycluster.io, xrplcluster.com
//    und s2.ripple.com: die Meta traegt nur AffectedNodes / TransactionIndex /
//    TransactionResult). delivered_amount gibt es dort nur im tx-Befehl.
//  - tx.Amount ist bei Zahlungen mit Fremdwaehrung oder Pfaden der
//    DeliverMax-DECKEL, nicht der bewegte Betrag. Live-Beleg Hash
//    F4134FC4612BC7114191B65328AA5AF5FA08AB45016F7B621103E1BABE79E98E:
//    Amount 100000000000000000 Drops, DeliverMin 34, SendMax IOU RLUSD,
//    deliveriert 34 Drops.
//  - Fehlgeschlagene Zahlungen stehen im validierten Ledger und bewegen nichts.
//    Live-Beleg Hash 2583F45F4C0A4DCFE3A81F292D011F767587B7CE28EB5BA0D39030593FC7C9B1
//    und 4969980B0C2345FFEE3F72EED7FE5A6558B94110C88E3DF706F95626289A2CCD:
//    tecPATH_DRY mit Amount 100000000000000 Drops.
//  - Ein Angebot bewegt kein Geld: NFTokenCreateOffer/OfferCreate nennen einen
//    Preis, die Zahlung laeuft erst bei Annahme bzw. Fill.
//
// EXAKT-REGELN — null heisst "nicht belegbar", niemals eine Schaetzung:
//  1) Engine-Ergebnis bekannt und nicht tesSUCCESS -> null.
//  2) Zahlung direkt in XRP (Amount/DeliverMax String, kein SendMax, keine
//     Paths, kein DeliverMin): der String ist nach XRPL-Spec exakt der bewegte
//     Betrag (XRP-Zahlungen sind atomar, Teillieferung gibt es nicht).
//  3) Zahlung mit Fremdwaehrung/Pfad: erst meta.delivered_amount (String =
//     Drops, Objekt = keine XRP-Bewegung), sonst das XRP-Saldo-Delta des Ziels
//     aus AffectedNodes — genau ein AccountRoot-Knoten, sonst null.
//  4) Angebots-Typen ohne Geldfluss -> null.
//
// Reine ESM-Pure-Bibliothek (DOM-frei, keine npm-Imports): wird von
// lib/detector.mjs und lib/cluster.mjs importiert und muss deshalb in
// api/lib-detector.js whitelisted sein (Muster tag-identity.mjs).

export const TX_SUCCESS = "tesSUCCESS";

// Typen, deren Amount ein Preis oder Limit ist, keine Bewegung.
const NO_MOVEMENT_TYPES = new Set([
  "NFTokenCreateOffer", "NFTokenAcceptOffer", "OfferCreate", "OfferCancel",
  "TrustSet", "AccountSet", "RegularKeySet", "NFTokenMint", "EnableAmendment",
  "SetFee", "UNLModify", "EscrowCancel", "CheckCancel",
]);

function asDrops(amount) {
  if (typeof amount !== "string") return null;
  const n = Number(amount);
  return Number.isFinite(n) ? n : null;
}

// Meta einer Entry: `meta` (Norm nach api/advance.js:538 / api/ledger.js) oder
// `metaData` ( Rohform der expand:true-Antwort). Auch {tx,meta}-Formen.
export function metaOf(entry) {
  if (!entry || typeof entry !== "object") return null;
  const direct = entry.meta ?? entry.metaData ?? null;
  if (direct !== null && direct !== undefined) return direct;
  const inner = entry.tx ?? entry.tx_json ?? null;
  if (inner && typeof inner === "object") return inner.meta ?? inner.metaData ?? null;
  return null;
}

// Engine-Ergebnis einer Transaktion (null = kein Beleg, nicht "erfolgreich").
export function engineResultOf(meta, tx) {
  for (const src of [meta, tx]) {
    if (!src || typeof src !== "object") continue;
    const raw = src.TransactionResult ?? src.transaction_state ?? src.engine_result ?? null;
    if (typeof raw === "string" && raw) return raw;
  }
  return null;
}

// Ohne Beleg gilt die Transaktion nicht als gescheitert (kein stiller
// Nachweisverlust, wenn eine Quelle die Meta nicht liefert).
export function isExecuted(meta, tx) {
  const result = engineResultOf(meta, tx);
  return result === null || result === TX_SUCCESS;
}

// XRP-Saldo-Delta eines Kontos aus der Meta. Genau ein AccountRoot-Knoten mit
// Vor- und Nachwert; CreatedNode (kein Vorwert) und IOU-Salden liefern null.
export function xrpDeltaOf(meta, account) {
  if (typeof account !== "string" || !account) return null;
  const nodes = Array.isArray(meta?.AffectedNodes) ? meta.AffectedNodes : [];
  let hits = 0;
  let delta = 0;
  for (const wrapper of nodes) {
    const node = wrapper?.ModifiedNode || wrapper?.CreatedNode || wrapper?.DeletedNode;
    if (!node || node.LedgerEntryType !== "AccountRoot") continue;
    if (node.FinalFields?.Account !== account) continue;
    const before = asDrops(node.PreviousFields?.Balance);
    const after = asDrops(node.FinalFields?.Balance);
    if (before === null || after === null) continue;
    hits += 1;
    delta += after - before;
  }
  return hits === 1 ? delta : null;
}

// Der wirklich bewegte XRP-Betrag in Drops (null = keine Bewegung belegt).
export function movedXrpOf(tx, meta) {
  if (!tx || typeof tx !== "object" || !tx.TransactionType) return null;
  if (!isExecuted(meta, tx)) return null;
  if (NO_MOVEMENT_TYPES.has(tx.TransactionType)) return null;

  if (tx.TransactionType !== "Payment") {
    // Kein SendMax: SendMax ist ein Hochstbetrag (CheckCreate), kein
    // nachgewiesener Abfluss - die Cluster-Kanten betrugen sich vorher ohne
    // SendMax, und das bleibt so.
    return asDrops(tx.Amount ?? tx.DeliverMax ?? null);
  }

  const delivered = meta?.delivered_amount;
  if (delivered !== undefined && delivered !== null) {
    if (typeof delivered === "string") return asDrops(delivered);
    return null; // deliveriert in Fremdwaehrung: keine XRP-Bewegung
  }

  const cross = (tx.SendMax !== undefined && tx.SendMax !== null)
    || (Array.isArray(tx.Paths) && tx.Paths.length > 0)
    || (tx.DeliverMin !== undefined && tx.DeliverMin !== null);
  if (!cross) return asDrops(tx.Amount ?? tx.DeliverMax ?? null);

    // Selbstzahlung: demselben AccountRoot-Knoten wird der Eingang gutgeschrieben
    // UND die Gebuehr abgezogen - das Delta ist dann 'deliveriert - Fee', nicht
    // der Betrag (live belegt 2026-10-17: C92240C9FAB1... delivered 1213,
    // Delta 1201 bei Fee 12; 4F1DDAD378DE... delivered 107324910, Delta
    // 107324889 bei Fee 21). Ohne delivered_amount wird daher bewusst null
    // zurueckgegeben statt ein Gebuehren-Aufschlag geschaetzt.
    if (tx.Account === tx.Destination) return null;
    const derived = xrpDeltaOf(meta, tx.Destination);
    return derived !== null && derived > 0 ? derived : null;
}

// Die bewegte Fremdwaehrung — nur wenn der Anspruch selbst (oder die
// delivered_amount) ein IOU-Objekt ist. SendMax bleibt ausser Acht: es ist ein
// Hochstbetrag, kein nachgewiesener Abfluss.
export function movedIouOf(tx, meta) {
  if (!tx || typeof tx !== "object") return null;
  if (!isExecuted(meta, tx)) return null;
  if (NO_MOVEMENT_TYPES.has(tx.TransactionType)) return null;
  const delivered = meta?.delivered_amount;
  const src = (delivered && typeof delivered === "object")
    ? delivered
    : (tx.Amount ?? tx.DeliverMax ?? null);
  if (!src || typeof src !== "object" || !src.currency || !src.issuer || src.value == null) return null;
  const value = Number(src.value);
  if (!Number.isFinite(value)) return null;
  return { currency: String(src.currency), issuer: String(src.issuer), value };
}
