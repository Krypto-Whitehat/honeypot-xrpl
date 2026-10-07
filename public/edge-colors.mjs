'use strict';
// public/edge-colors.mjs — DOM-freie Tx-Typ-Kategorisierung für die
// Kanten-Farbcodierung (Audit 2026-10-07: Kante = Tx-Kategorie, Knoten =
// Rolle; zuvor deckte EDGE_COLORS 11 von ~60 Mainnet-Typen ab, alles andere
// fiel in neutralem Grau unter).
//
// MODUL-VERTRAG (Muster public/cluster-views.mjs / public/name-index.mjs):
// DOM-frei beim Import, kein fetch, kein window/document — reine
// Daten-Transformation. Farb-WERTE bewusst NICHT hier: die Tokens in
// public/style.css sind die SSOT, die JS-Spiegel sind EDGE_COLORS/
// THEME_JS_COLORS in public/app.js (applyThemeColors mutiert in place).
// Konsumenten: public/app.js (nextEdges-Farblookup + ctx.edgeCategory),
// public/drilldown.js (3D-Accessor/2D-Fallback/Zeitachse),
// public/globe.js (Arc-Farbe), public/history-host.html (Flow-Graph).
//
// Kategorien (Kanten-Ebene, themenbewusst über die --a6-edge-* Tokens):
//   fraud   — Override VOR der Kategorie: severity 'malicious' (Kante oder
//             ein Endpunkt, max-Regel wie lib/cluster.mjs:382-394) —
//             Nutzervorgabe "Betrug = Rot"; nur diese Kategorie trägt den
//             gestrichelten Deutan-Zweitkanal (vis `dashes` / SVG
//             stroke-dasharray).
//   payment — Payment (Werttransfer XRP/IOU).
//   market  — Orderbuch + AMM (OfferCreate/OfferCancel/TrustSet als
//             Issuer-Trustline, AMMCreate/Deposit/Withdraw/Vote/Bid/
//             Delete/Clawback, Clawback, MPTokenIssuance*). DEX und AMM
//             sind bewusst EINE Kategorie: die alten Töne lagen bei
//             1.02:1 (Hell) / 1.05:1 (Noir) Luminanz zusammen (Audit-
//             Kritik 5) — zusammengelegt statt fast-identisch.
//   escrow  — EscrowCreate/EscrowFinish/EscrowCancel.
//   check   — CheckCreate/Cash/Cancel + PaymentChannelCreate/Fund/Claim.
//   admin   — Konten-/Protokoll-Verwaltung (AccountSet/AccountDelete,
//             SetRegularKey, SignerListSet, TicketCreate, DepositPreauth,
//             DIDSet/DIDDelete, Credential*, PermissionedDomain*,
//             XChain*, Oracle*, Vault*, Loan*, Batch/Delegate/LedgerStateFix
//             und die globalen Pseudo-Tx EnableAmendment/SetFee/UNLModify).
//   nft     — alle NFToken*-Typen (Mint/Burn/CreateOffer/CancelOffer/
//             AcceptOffer/Modify).
//   other   — Rückfall (liefert EDGE_DEFAULT/--a6-edge-neutral).
//
// Tx-Typ-Namen exakt wie im Ledger (xrpl.org-Transaktionsreferenz,
// abgerufen 2026-10-07); unbekannte Typen fallen deterministisch auf
// 'other' zurück — die Funktion erfindet keinen Typ und wirft nie.

const CATEGORIES = new Set([
  'fraud', 'payment', 'market', 'escrow', 'check', 'admin', 'nft', 'other',
]);

const CATEGORY_BY_TYPE = new Map([
  // Value/Core (xrpl.org: Payment, Escrow*, Check*, PaymentChannel*, TrustSet,
  // Clawback — https://xrpl.org/clawback.html: Account = Issuer)
  ['Payment', 'payment'],
  ['EscrowCreate', 'escrow'],
  ['EscrowFinish', 'escrow'],
  ['EscrowCancel', 'escrow'],
  ['CheckCreate', 'check'],
  ['CheckCash', 'check'],
  ['CheckCancel', 'check'],
  ['PaymentChannelCreate', 'check'],
  ['PaymentChannelFund', 'check'],
  ['PaymentChannelClaim', 'check'],
  ['TrustSet', 'market'],
  ['Clawback', 'market'],
  // DEX/Orderbuch (xrpl.org: OfferCreate/OfferCancel)
  ['OfferCreate', 'market'],
  ['OfferCancel', 'market'],
  // AMM (XLS-30; AMMClawback XLS-73 — https://xls.xrpl.org). AMMSwap fehlt
  // bewusst: nie Mainnet-fähig (früherer rippled-Platzhalter, durch
  // AMMClawback ersetzt).
  ['AMMCreate', 'market'],
  ['AMMDeposit', 'market'],
  ['AMMWithdraw', 'market'],
  ['AMMVote', 'market'],
  ['AMMBid', 'market'],
  ['AMMDelete', 'market'],
  ['AMMClawback', 'market'],
  // MPT (Multi-Purpose Tokens, XLS-33) — Issuer/Token-Familie wie TrustSet.
  ['MPTokenIssuanceCreate', 'market'],
  ['MPTokenIssuanceDestroy', 'market'],
  ['MPTokenIssuanceAuthorize', 'market'],
  ['MPTokenIssuanceSet', 'market'],
  // NFT (xrpl.org NFToken*-Referenz; NFTokenModify eingeschlossen)
  ['NFTokenMint', 'nft'],
  ['NFTokenBurn', 'nft'],
  ['NFTokenCreateOffer', 'nft'],
  ['NFTokenCancelOffer', 'nft'],
  ['NFTokenAcceptOffer', 'nft'],
  ['NFTokenModify', 'nft'],
  // Konten-/Protokoll-Verwaltung
  ['AccountSet', 'admin'],
  ['AccountDelete', 'admin'],
  ['SetRegularKey', 'admin'],
  ['SignerListSet', 'admin'],
  ['TicketCreate', 'admin'],
  ['DepositPreauth', 'admin'],
  ['DIDSet', 'admin'],
  ['DIDDelete', 'admin'],
  ['CredentialCreate', 'admin'],
  ['CredentialAccept', 'admin'],
  ['CredentialDelete', 'admin'],
  ['PermissionedDomainSet', 'admin'],
  ['PermissionedDomainDelete', 'admin'],
  ['XChainCreateBridge', 'admin'],
  ['XChainCreateClaimID', 'admin'],
  ['XChainCommit', 'admin'],
  ['XChainClaim', 'admin'],
  ['XChainAccountCreateCommit', 'admin'],
  ['XChainAddClaimAttestation', 'admin'],
  ['XChainAddAccountCreateAttestation', 'admin'],
  ['XChainModifyBridge', 'admin'],
  ['OracleSet', 'admin'],
  ['OracleDelete', 'admin'],
  // Vault (XLS-65 SingleAssetVault — Typnamen laut Audit-Inventar/https://
  // xls.xrpl.org): VaultCreate/VaultDeposit/VaultWithdraw/VaultDelete/
  // VaultSet/VaultClawback.
  ['VaultCreate', 'admin'],
  ['VaultDeposit', 'admin'],
  ['VaultWithdraw', 'admin'],
  ['VaultSet', 'admin'],
  ['VaultDelete', 'admin'],
  ['VaultClawback', 'admin'],
  // Lending (XLS-66) und Sponsorship* stehen teils noch auf 'voting' — die
  // finalen Ledger-Typnamen sind hier NICHT belegt und werden deshalb
  // bewusst NICHT inventarisiert (keine erfundenen Namen): sie fallen
  // deterministisch auf 'other', bis sie mainnet-final sind.
  ['Batch', 'admin'],
  ['DelegateSet', 'admin'],
  ['LedgerStateFix', 'admin'],
  // Globale Pseudo-Tx (kein Account, kein Köderbezug — bewusst als admin
  // kategorisiert, falls sie als Kantentyp auftauchen)
  ['EnableAmendment', 'admin'],
  ['SetFee', 'admin'],
  ['UNLModify', 'admin'],
]);

// Kategorie eines Ledger-Tx-Typen (String) — unbekannt/leer -> 'other'.
// Deterministisch: reiner Map-Lookup, keine NormalisierungCase-Fantasien
// (Ledger-Typnamen sind PascalCase; wer sie verstümmelt liefert, landet
// ehrlich auf 'other').
export function txCategory(type) {
  const ty = typeof type === 'string' ? type : String(type ?? '');
  return CATEGORY_BY_TYPE.get(ty) ?? 'other';
}

export function isKnownEdgeCategory(category) {
  return CATEGORIES.has(category);
}

// Legende-/Prüf-Reihenfolge (Kanten-Block der Legende, beide Hosts).
export const EDGE_CATEGORY_ORDER = Object.freeze([
  'fraud', 'payment', 'market', 'escrow', 'check', 'admin', 'nft', 'other',
]);
