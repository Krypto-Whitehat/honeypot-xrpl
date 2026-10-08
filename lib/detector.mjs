// lib/detector.mjs — gemeinsame Detektor-Engine (single source of truth).
//
// WIRD IMPORTIERT VON:
//   - public/app.js  (Browser, via /lib/detector.mjs)  -> analyzeLedger pro WSS-Ledger
//   - api/ledger.js  (Vercel-Function)                 -> analyzeLedger pro JSON-RPC-Ledger
//   - server/index.mjs (lokal)                         -> analyzeLedger pro Snapshot
//
// HARTEN GRENZEN (Pflicht):
//   - pure ESM, KEINE npm-Imports, KEIN Node-Global `Buffer` (existiert im
//     Browser nicht). Hex-Dekodierung manuell + globaler TextDecoder.
//   - KEINE r-Adress-Literale von Ködern. Die benign-Issuer-Whitelist ist ein
//     klar kommentiertes Konstanten-Set aus öffentlich bekannten Gateways
//     (live gemessen 2026-09-28 via xrplcluster.com), keine Köder-Adressen.
//   - severity-Enum identisch zur Honeypot-Schicht: 'malicious'|'suspect'|'info'
//     (lib/sanitize.mjs), damit Live-Funde direkt in die Threat-Liste können.
//
// SIGNATUREN (Spec):
//   analyzeTx(tx, meta, ctx)      -> Array {ruleId, severity, address, note}
//   analyzeLedger(ledgerResult, ctx) -> {findings, stats:{txs, findings}, hashOnly?}
//   ruleCatalog()                 -> Array {id, name, severity}
//
// ctx = {knownBad:Set, benignIssuers:Set, threats:Map} plus optionale
// Erweiterungen mit sicheren Defaults: firstSeenAt:Map<string,number>,
// benignAccounts:Set, thresholds:{dustDrops,minAccountAgeMin,sweepRatio}.
//
// PEELING-KATALOG-EINTRAG ('peeling-chain'): die Regel-Maschinerie lebt in
// lib/cluster.mjs detectPeelingChains (Katalog/Konsistenz halber hier als
// RULES-Eintrag für api/rules.js; analyzeTx/analyzeLedger bleiben
// unverändert). Die Schwellen PEELING_THRESHOLDS {minRatio 0.6, maxRatio
// 0.95, minHops 3, dustDrops 100} (cluster.mjs) sind ausdrücklich als
// TUNING-DEFAULTS OHNE reproduzierten Kampagnen-Fall ausgewiesen — der
// Header von cluster.mjs verlangt diese Explizitheit für neue Muster.

// ---------- Schwellen (Default; per ctx.thresholds überschreibbar) ----------
export const DEFAULT_THRESHOLDS = {
  dustDrops: 100,         // Bagatellgrenze exklusiv (Zahlung < dustDrops ist 'winzig';
                          // 1000 drops = 0.001 XRP lösen dusting/escrow-Burst nicht mehr aus
                          // — echte Dust-Angriffe liegen bei 1–10 drops)
  minAccountAgeMin: 15,   // Frische-Fenster in Minuten
  sweepRatio: 0.9,        // >= 90 % der Balance an EIN Ziel = Sweep
};

// ---------- Market-Schwellen (DEX/AMM-Manipulation, Kritik-Runde 3 T1.2) ----------
// DEX-/AMM-Regeln arbeiten auf Tx-Ebene (analyzeLedger über OfferCreate/
// OfferCancel + Ledger-Meta), NICHT in motifCounters: OfferCreate erzeugt per
// Spec keine Kante (cluster.mjs:353-355) und motifCounters ist XRP-only
// (cluster.mjs:1774) — MOTIF_THRESHOLDS ist hier der falsche Ort. Werte sind
// TUNING-DEFAULTS OHNE reproduzierten Kampagnen-Fall (Explizitheitspflicht wie
// PEELING_THRESHOLDS, cluster.mjs) — per ctx.thresholds überschreibbar.
// Fenster in LEDGER-Einheiten (XRPL ~4 s/Ledger: 150 ≈ 10 min, 300 ≈ 20 min) —
// ledgerSeq-Differenz, nie Uhrzeit; Präzedenz cluster.mjs cycleWindowMs.
export const MARKET_THRESHOLDS = {
  // amm-wash-swap (Waschhandel über OfferCreate-Selbstzyklus / AMM-Bidirektional)
  washMinFillsPerSide: 2,          // >= 2 Fills je Richtung (Refund-Guard, Muster cycleMinEdgesPerSide)
  washConserveMin: 0.9,            // min/max Volumenerhalt (enger als wash-cycle 0.8: ein Rundlauf im selben Pool verliert nur Gebühren)
  washMaxDrift: 0.1,               // Netto-Positionsdrift |fwd-bwd|/max <= 10 % (Wasch-Kern: Volumen ja, Position nein)
  washWindowLedgers: 150,          // Fenster <= 150 Ledger (~10 min)
  washMinNotionalDrops: 1000000,   // >= 1 XRP je Richtung (4 Größenordnungen über dustDrops)
  // thin-pool-exploit (Ausnutzen niedriger AMM-/Orderbuch-Liquidität)
  thinMinPairSamples: 5,           // >= 5 beobachtete Fills desselben Pairs im Fenster — sonst 'nicht messbar statt raten'
  thinMinFillsPerAccount: 2,       // >= 2 Fills desselben Pairs durch dasselbe Konto
  thinDeviationMin: 0.25,          // >= 25 % Abweichung vom Fenster-Median in die günstige Richtung
  thinWindowLedgers: 150,          // Fenster <= 150 Ledger
  thinMinNotionalDrops: 10000000,  // >= 10 XRP Notional
  // spoof-offer-cycle (Place-and-Pull / Spread-Manipulation)
  spoofMaxCancelLedgers: 75,       // Create->Cancel <= 75 Ledger (~5 min)
  spoofMinCycles: 3,               // >= 3 Zyklen desselben Kontos in derselben BookDirectory
  spoofMinPriceLevels: 2,          // >= 2 verschiedene Preislevel (BookNode)
  spoofWindowLedgers: 300,         // Fenster <= 300 Ledger (~20 min)
  spoofMinCancelNotionalDrops: 100000000, // >= 100 XRP Cancel-Notional
};

// ---------- Benign-Whitelist (KEINE Köder — öffentlich bekannte Gateways) ----------
// Live gemessen 2026-09-28 gegen https://xrplcluster.com (validierte Ledger,
// TrustSet/OfferCreate-Felder). Dient dem False-Positive-Schutz der Breiten-
// Regeln gegen legitime Stablecoin-/Gateway-Trustlines. ctx.benignIssuers wird
// damit UNIONiert; Betreiber können über config.json/ctx erweitern.
export const DEFAULT_BENIGN_ISSUERS = new Set([
  "rMxCKbEDwqr76QuheSUMdEGf4B9xJ8m5De", // RLUSD-Bridge (im Sample 123× Top-Issuer)
  "rGm7WCVp9gb4jZHWTEtGUr4dd74z2XuWhE", // USDC-Bridge
  "rcEGREd8NmkKRE8GE424sksyt1tJVFZwu",  // USDC-Bridge (zweiter Zweig)
  "rvYAfWj5gh67oV6fW32ZzP3Aw4Eubs59B",  // Bitstamp (BTC/USD/ETH, historisch bekannt)
  "rhub8VRN55s94qWKDv6jmDy1pUykJzF3wq", // EUR-Hub
  "rKiCet8SdvWxPXnAgYarFUXMh1zCPz432Y", // CNY/USD/XLM-Gateway
]);

// Exchange-/Faucet-Konten (Dusting-/Drainer-Ausnahme). Serverseitig via
// config.json/ctx befüllt; hier bewusst leer (keine Köder, keine Raten).
export const DEFAULT_BENIGN_ACCOUNTS = new Set([]);

// ---------- Regelkatalog (speist die Regelfilter-UI) ----------
const RULES = [
  { id: "known-bad-hit", name: "Known-Bad-Treffer (Honeypot-abgeleitet + Kuratierung)", severity: "malicious" },
  { id: "memo-phishing", name: "Memo-Phishing (URLs/Seed-Muster in Zahlungen)", severity: "malicious" },
  { id: "drainer-sweep", name: "Drainer — frisch finanziert, sofort abgeräumt", severity: "malicious" },
  { id: "airdrop-trustset-spam", name: "Fake-Airdrop-TrustSet-Spam", severity: "suspect" },
  { id: "dusting", name: "Dusting — Mini-XRP an frische Konten", severity: "suspect" },
  { id: "fake-nft-fraud", name: "Fake-NFT-Betrug", severity: "suspect" },
  { id: "escrow-check-bait", name: "Escrow/Check-Köder an frische Konten", severity: "suspect" },
  { id: "payment-burst", name: "Zahlungs-Burst (Airdrop-Verteilung)", severity: "suspect" },
  { id: "offer-spam", name: "Offer-Spam (OfferCreate-Kaskaden ohne Fill)", severity: "info" },
  { id: "wash-self-transfer", name: "Washing — Selbsttransfer (Volumenerzeugung)", severity: "suspect" },
  { id: "peeling-chain", name: "Peeling-Kette (gestaffelte Weiterleitung 60–90 %)", severity: "suspect" },
  // Maschinerie-Präzedenz wie 'peeling-chain' (Kommentar oben): die wash-cycle-
  // Erkennung lebt als Cluster-Regel in lib/cluster.mjs (motifCounters über
  // die akkumulierten Flow-State-Kanten, lib/ledger-walk.mjs mergeCluster);
  // der Katalog-Eintrag speist api/rules.js und den Regelfilter — analyzeTx/
  // analyzeLedger bleiben unverändert. Fundklasse 'suspect' (kein Schuldnachweis).
  { id: "wash-cycle", name: "Wash-Zyklus (Kreuz-Konto-Kreislauf mit Volumenerhalt)", severity: "suspect" },
  // DEX/AMM-Manipulation (Kritik-Runde 3 T1.2): drei deterministische Regeln
  // auf Tx-Ebene in analyzeLedger (OfferCreate/OfferCancel + Ledger-Meta,
  // expand:true liefert beides bereits — +0 Requests, kein ML, keine Köder).
  // Fundadresse ist immer tx.Account. 'suspect' (kein Schuldnachweis —
  // Volumenmuster, keine Opferzuordnung); bewusst NICHT in HISTORY_FRAUD_RULES
  // (lib/history.mjs:116 bleibt drainer-sweep/peeling-chain/known-bad-hit) und
  // ohne neue hasFraudEvidence-Träger (lib/flow-state.mjs:242-253 unverändert):
  // die 30-Tage-maliziös-Retention bleibt den harten Evidenzträgern vorbehalten.
  { id: "amm-wash-swap", name: "AMM-Washing — bidirektionaler Selbstzyklus mit Volumenerhalt", severity: "suspect" },
  { id: "thin-pool-exploit", name: "Thin-Pool-Exploit — Preisimpact in dünner Liquidität", severity: "suspect" },
  { id: "spoof-offer-cycle", name: "Spoof-Offers — Place-and-Pull-Zyklen im Orderbuch", severity: "suspect" },
];

export function ruleCatalog() {
  return RULES.map((r) => ({ id: r.id, name: r.name, severity: r.severity }));
}

// ---------- ctx-Normalisierung (sichere Defaults) ----------
function toSet(v) {
  if (v instanceof Set) return v;
  if (Array.isArray(v)) return new Set(v);
  return new Set();
}
function toMap(v) {
  if (v instanceof Map) return v;
  if (v && typeof v === "object") return new Map(Object.entries(v));
  return new Map();
}
function unionSet(a, b) {
  const out = new Set(a);
  for (const x of toSet(b)) out.add(x);
  return out;
}

function normalizeCtx(ctx) {
  const c = ctx && typeof ctx === "object" ? ctx : {};
  return {
    knownBad: toSet(c.knownBad),
    benignIssuers: unionSet(DEFAULT_BENIGN_ISSUERS, c.benignIssuers),
    benignAccounts: unionSet(DEFAULT_BENIGN_ACCOUNTS, c.benignAccounts),
    threats: toMap(c.threats),
    firstSeenAt: toMap(c.firstSeenAt),
    // history: Cross-Ledger-Gedächtnis (account -> {tinyDests:Set, fundedAt,
    // createdInWindow, lastLedger}). toMap gibt dieselbe Map-Referenz durch
    // (toMap Z.74-78), analyzeLedger schreibt sie am Ende jedes Aufrufs
    // in-place zurück — damit sehen dusting/drainer-sweep Fenster über
    // mehrere Ledger-Aufrufe hinweg.
    history: toMap(c.history),
    // verifiedFresh (V5): Adressen mit Entity-Snapshot-Beleg frischer Konto-
    // aktivität (S−P-Gap <= 24 h, lib/entity-resolve.mjs freshEvidence).
    // Sicherer Default [] — Browser-/Ledger-Pfade ohne Entity-Layer bleiben
    // bitgleich (fail-open).
    verifiedFresh: toSet(c.verifiedFresh),
    // marketExcludes (T1.6/T1.7): Exchange-Registry ∪ multiUser ∪ Köder ∪
    // config-benign — derselbe Börsen-FP-Guard, den motifCounters über
    // motifExclude (lib/ledger-walk.mjs) schon hat. Die Market-Regeln zählen
    // Market-Maker-/Börsen-Aktivität; ohne Guard feuern amm-wash-swap/
    // spoof-offer-cycle auf legitimen Börsen-Konten. Sicherer Default [] —
    // Pfade ohne Wiring bleiben bitgleich (fail-open, dokumentierte Grenze).
    marketExcludes: toSet(c.marketExcludes),
    thresholds: { ...DEFAULT_THRESHOLDS, ...MARKET_THRESHOLDS, ...(c.thresholds || {}) },
  };
}

// ---------- Hex-Dekodierung OHNE Buffer (Browser-kompatibel) ----------
function hexToText(hex) {
  const h = String(hex ?? "");
  if (!h || h.length % 2 !== 0 || !/^[0-9A-Fa-f]+$/.test(h)) return "";
  const bytes = new Uint8Array(h.length / 2);
  for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(h.slice(i * 2, i * 2 + 2), 16);
  try {
    return new TextDecoder("utf-8").decode(bytes);
  } catch {
    return "";
  }
}

// Memos einer Transaktion zu einem Textentwurf dekodieren.
function memoText(tx) {
  const memos = Array.isArray(tx?.Memos) ? tx.Memos : [];
  const parts = [];
  for (const m of memos) {
    const data = m?.Memo?.MemoData;
    if (data) parts.push(hexToText(data));
    const fmt = m?.Memo?.MemoFormat;
    if (fmt) parts.push(hexToText(fmt));
  }
  return parts.join(" ");
}

// ---------- Muster ----------
const URL_RE = /(https?:\/\/|www\.)[^\s"'<>]+/i;
// fpGuard: keine deutschen Alltagswörter — "abheben/anmelden/auszahlen" stehen
// in legitimen Geschäfts-Memos und erzeugten False-Positives. Phishing-Memos
// nutzen englisches Scam-Vokabular; Seeds werden sprachunabhängig erkannt.
// Standalone-Treffer (Scam-Vokabular ohne Kontext nötig):
const CLAIM_STANDALONE_RE = /\b(airdrop|giveaway|free[\s-]*token|freecoin)\b/i;
// 'claim'/'verify' treffen erst mit Konto-/Guthaben-Kontextwort innerhalb von
// ~40 Zeichen danach (Kontextwort selbst <= 12 Zeichen). False-Positive-
// Regression: 'Please verify your order at https://shop.example/de',
// 'Warranty claim: register at www.example.com/support', 'Claim ID 8812 for
// order …' bleiben benign; 'Claim your free airdrop token at http://evil.example',
// 'verify your wallet to claim reward', 'verify your account to receive tokens'
// treffen. Tradeoff (bewusst): 'claim your package'-Delivery-Phishing fällt
// vorübergehend raus, weil 'package' kein Konto-Kontextwort ist.
const CLAIM_CTX_RE = /\b(claim|verify)\b[\s\S]{0,28}?\b(account|wallet|token|seed|passphrase|recovery|airdrop|reward|prize|bonus)\b/i;
// sEd = modernes Seed-Format (29 Zeichen, BIP39); skey/shss/spup = alte Typen.
const SEED_RE = /\b(skey|shss|spup|sEd)[1-9A-HJ-NP-Za-km-z]{16,}\b/;
const SHORTLINK_RE = /\b(bit\.ly|t\.co|tinyurl\.com|goo\.gl|is\.gd|cutt\.ly|rb\.gy|rebrand\.ly)\b/i;

function claimHit(text) {
  return CLAIM_STANDALONE_RE.test(text) || CLAIM_CTX_RE.test(text);
}

// Zitiertes Opfer-Memo: jemand zitiert eine Phishing-URL (Anführungszeichen)
// und fragt nach ('ist das echt?', 'is this legit?' …). Das ist ein hilfesuchendes
// Opfer, kein Täter — Fund bleibt, aber severity-Downgrade auf 'suspect'.
const QUOTED_URL_RE = /["'“”«»『][^"'“”«»『]*(https?:\/\/|www\.)[^"'“”«»『]+["'“”«»『]/i;
const ASKING_RE = /\b(ist das echt|ist das sicher|is this legit|is this real|is this scam|is it safe|scam\?|fake\?|echt\?)\b/i;
function isQuotingMemo(text) {
  const t = String(text ?? "");
  return (QUOTED_URL_RE.test(t) && ASKING_RE.test(t)) || ASKING_RE.test(t);
}

function isPhishingMemo(text) {
  const t = String(text ?? "");
  if (!t) return false;
  if (SEED_RE.test(t)) return true;
  // fpGuard: reine Referenz-IDs/JSON-Memos sind benign; URL allein ohne
  // claim-Keyword ist benign.
  if (URL_RE.test(t) && claimHit(t)) return true;
  return false;
}

function isPhishingUri(uriText) {
  const u = String(uriText ?? "").trim();
  if (!u) return false; // fpGuard: URI leer -> benign
  if (SHORTLINK_RE.test(u)) return true; // URL-Kurzlink
  if (URL_RE.test(u) && claimHit(u)) return true; // Phishing-Domain + claim-Muster
  return false;
}

// ---------- Beträge ----------
function dropsOf(amount) {
  // Nur XRP (String in drops). IOU-Objekte liefern null.
  if (typeof amount === "string") {
    const n = Number(amount);
    return Number.isFinite(n) ? n : null;
  }
  return null;
}
function isIou(amount) {
  return amount && typeof amount === "object" && amount.currency && amount.issuer;
}

// ---------- Normalisierung einer Transaktions-Eingabe ----------
// Akzeptiert flache tx ODER {tx_json|tx, meta}. meta kann null sein.
function normalizeTxEntry(entry) {
  if (!entry || typeof entry !== "object") return null;
  if (entry.tx_json && typeof entry.tx_json === "object") {
    return { tx: entry.tx_json, meta: entry.meta ?? null };
  }
  if (entry.tx && typeof entry.tx === "object") {
    return { tx: entry.tx, meta: entry.meta ?? null };
  }
  if (entry.TransactionType) {
    return { tx: entry, meta: entry.meta ?? null };
  }
  return null;
}

// Balance-Vorwert aus meta (AccountRoot ModifiedNode) für Sweep-Erkennung.
function prevBalanceOf(meta) {
  const nodes = Array.isArray(meta?.AffectedNodes) ? meta.AffectedNodes : [];
  for (const n of nodes) {
    const mod = n?.ModifiedNode;
    if (mod?.LedgerEntryType === "AccountRoot" && mod.PreviousFields?.Balance != null) {
      const b = Number(mod.PreviousFields.Balance);
      if (Number.isFinite(b)) return b;
    }
  }
  return null;
}

// Frische-Härtung: CreatedNode AccountRoot in meta = Konto wurde in diesem
// Fenster erst erstellt (echtes Drainer-Konto), Muster wie prevBalanceOf.
function createdAccountOf(meta) {
  const nodes = Array.isArray(meta?.AffectedNodes) ? meta.AffectedNodes : [];
  for (const n of nodes) {
    const created = n?.CreatedNode;
    if (created?.LedgerEntryType === "AccountRoot") {
      // Fix 2026-10-04: CreatedNode trägt die Adresse je nach Pfad in
      // LedgerEntry.Account (klassisch) ODER NewFields.Account (expand-Pfad,
      // live belegt hc_ledger_11/_13/_14: CreatedNode{LedgerEntryType,
      // LedgerIndex, NewFields.Account}) — ohne Fallback blieb der
      // Erstellungsbeleg blind und drainer-sweep degradierte auf 'suspect'.
      const addr = created.LedgerEntry?.Account ?? created.NewFields?.Account;
      if (typeof addr === "string" && addr) return addr;
    }
  }
  return null;
}

// Hat diese Transaktion einen Fill (OfferCreated-Nodes)?
function hasFill(meta) {
  const nodes = Array.isArray(meta?.AffectedNodes) ? meta.AffectedNodes : [];
  for (const n of nodes) {
    const created = n?.CreatedNode;
    if (created?.LedgerEntryType === "Offer") return true;
  }
  return false;
}

// AcceptOffer ohne Zahlung: betreffen die betroffenen NFTokenOffer-Nodes einen
// Nullwert (Amount '0')? (fpGuard: kein Fund auf Mint allein, nur Null-Burst)
function acceptsWithZeroValue(meta) {
  const nodes = Array.isArray(meta?.AffectedNodes) ? meta.AffectedNodes : [];
  for (const n of nodes) {
    const node = n?.ModifiedNode ?? n?.DeletedNode ?? n?.CreatedNode;
    if (node?.LedgerEntryType !== "NFTokenOffer") continue;
    const fields = node.FinalFields ?? node.PreviousFields ?? node.LedgerEntry ?? {};
    const amount = fields.Amount;
    if (amount === "0" || (amount && typeof amount === "object" && String(amount.value) === "0")) {
      return true;
    }
  }
  return false;
}

// ---------- Market-Helfer (DEX/AMM-Regeln, T1.2) ----------
// Währungsseite eines Offer-Felds: 'XRP' (String in Drops) oder
// '<currency>:<issuer>' (IOU-Objekt). Währungscode validiert (3× A-Z oder
// 16 Hex, XRPL-Währungscodes) — ungültiges Feld liefert null und erzeugt
// keinen Fund (kein Rate auf exotischen Feldern). Muster IOU-Reads
// cluster.mjs:366-369.
function sideKey(amount) {
  if (typeof amount === "string" && amount !== "" && Number.isFinite(Number(amount))) return "XRP";
  if (amount && typeof amount === "object" && amount.currency && amount.issuer) {
    const cur = String(amount.currency);
    if (!/^[A-Z]{3}$/.test(cur) && !/^[0-9A-Fa-f]{16}$/.test(cur)) return null;
    const issuer = String(amount.issuer);
    if (!issuer) return null;
    return `${cur}:${issuer}`;
  }
  return null;
}

// Wert einer Währungsseite in XRP-Drops (XRP: String-Wert; IOU: null —
// keine erfundene XRP-Skala für IOU, Muster cluster.mjs:553 'null (IOU)
// zählt 0').
function sideDrops(amount) {
  if (typeof amount === "string") {
    const n = Number(amount);
    return Number.isFinite(n) ? n : null;
  }
  return null;
}

// Wert einer Währungsseite als vergleichbare Zahl: XRP -> Drops, IOU ->
// value-Feld. KEINE erfundene XRP-Skala für IOU (Muster cluster.mjs:586-587
// 'ratio von value zu value, keine value*1e6-Skala') — die Rate ist nur
// innerhalb desselben Pairs vergleichbar, und genau dort wird sie verwendet.
function sideValue(amount) {
  if (typeof amount === "string") {
    const n = Number(amount);
    return Number.isFinite(n) ? n : null;
  }
  if (amount && typeof amount === "object" && amount.currency && amount.issuer) {
    const v = Number(amount.value);
    return Number.isFinite(v) ? v : null;
  }
  return null;
}

// Kanonische Fill-Rate eines Pairs aus der Ledger-Meta des konsumierten
// Offer-Objekts: rateNorm = Wert(hi)/Wert(lo) mit [lo, hi] = sortierte
// Seiten des Pairs — richtungsunabhängig, identisch für beide Seiten eines
// Trades. Taker-Sicht: erhält TakerGets, gibt TakerPays (Kommentar
// offerFillNodesOf). Beide Werte > 0 nötig, sonst null (nicht messbar).
// Offer-Felder: xrpl@4.0.0 ledger/Offer.d.ts (Account/Sequence/TakerPays/
// TakerGets + BookDirectory/BookNode via Book). Kein book_offers, kein
// Preisfeed — reine In-Memory-Meta-Arithmetik.
function fillRateNormOf(fields, loSide) {
  const getsSide = sideKey(fields?.TakerGets);
  const paysSide = sideKey(fields?.TakerPays);
  if (!getsSide || !paysSide || getsSide === paysSide) return null;
  const getsVal = sideValue(fields.TakerGets);
  const paysVal = sideValue(fields.TakerPays);
  if (getsVal == null || paysVal == null || getsVal <= 0 || paysVal <= 0) return null;
  const hiSide = getsSide === loSide ? paysSide : getsSide;
  // Wert(hi)/Wert(lo)
  return getsSide === hiSide ? getsVal / paysVal : paysVal / getsVal;
}

// Consumierte/erzeugte Offer-Nodes einer OfferCreate-Tx aus der Meta:
// Echter Fill (Cross) = DeletedNode Offer — der Offer eines ANDEREN Makers
// wurde konsumiert (Guard unten: ein DeletedNode Offer desselben Kontos ist
// KEIN Fill, sondern der Ersatz des EIGENEN Quotes — Kritik-Runde 4,
// Befund 3). CreatedNode Offer = platzierte/restierende Limit-Order
// (kein Geldfluss beim Platzieren — xrpl@4.0.0 transactions/OfferCreate.d.ts
// hat kein Gegenpartei-Feld; ledger/Offer.d.ts: Account/Sequence/
// TakerPays/TakerGets + BookDirectory/BookNode). OfferCancel: DeletedNode
// Offer (FinalFields des gelöschten Offers — Muster deletedNftOfferOf
// cluster.mjs:252-261). Reine In-Memory-Meta-Auswertung, +0 Requests.
// RICHTUNG (Taker-Sicht, xrpl-Offer-Semantik): der Maker eines Offers gibt
// TakerGets und erhält TakerPays; der TAKER (tx.Account, der den Offer
// konsumiert) erhält TakerGets und gibt TakerPays — die Market-Regeln
// aggregieren pro tx.Account, also in = TakerGets, out = TakerPays.
// txAccount (optional): der Absender der OfferCreate. Ein DeletedNode Offer
// mit FinalFields.Account === txAccount ist die Ersetzung des eigenen Offers
// (Quote-Update derselben Sequenz — kein Cross, kein Gegenpartei-Geldfluss;
// Self-Trading ist auf der XRPL verhindert) und wird NICHT als Fill gezählt.
// Ohne den Guard zählten reine bidirektionale Quote-Replacements eines nicht
// registrierten Market-Makers als swapPairs/thinFills und feuerten
// amm-wash-swap/thin-pool-exploit als False-Positive.
function offerFillNodesOf(meta, txAccount) {
  const nodes = Array.isArray(meta?.AffectedNodes) ? meta.AffectedNodes : [];
  const out = [];
  for (const wrapper of nodes) {
    const del = wrapper?.DeletedNode;
    if (del?.LedgerEntryType === "Offer" && del.FinalFields && typeof del.FinalFields === "object") {
      if (typeof txAccount === "string" && del.FinalFields.Account === txAccount) continue; // Selbst-Ersatz, kein Fill
      out.push({ kind: "deleted", fields: del.FinalFields });
      continue;
    }
    const created = wrapper?.CreatedNode;
    if (created?.LedgerEntryType === "Offer") {
      const fields = created.FinalFields ?? created.NewFields ?? null;
      if (fields && typeof fields === "object") out.push({ kind: "created", fields });
    }
  }
  return out;
}

function offerCancelNodeOf(meta) {
  const nodes = Array.isArray(meta?.AffectedNodes) ? meta.AffectedNodes : [];
  for (const wrapper of nodes) {
    const del = wrapper?.DeletedNode;
    if (del?.LedgerEntryType === "Offer" && del.FinalFields && typeof del.FinalFields === "object") {
      return del.FinalFields;
    }
  }
  return null;
}

function medianOf(values) {
  const arr = [...values].sort((a, b) => a - b);
  const n = arr.length;
  if (!n) return null;
  const mid = Math.floor(n / 2);
  return n % 2 ? arr[mid] : (arr[mid - 1] + arr[mid]) / 2;
}

// ---------- Frische-Signal ----------
function isFresh(addr, ctx, now) {
  if (!addr || !ctx.firstSeenAt.has(addr)) return false; // ohne Frische-Signal kein Fund
  const seen = ctx.firstSeenAt.get(addr);
  const ageMin = (now - seen) / 60000;
  return ageMin < ctx.thresholds.minAccountAgeMin;
}

// Beteiligte Akteure einer tx (für known-bad-hit).
// Alle Adressfelder, über die eine Transaktion ein Konto berührt oder die
// Kontrolle/Position an ein Konto überträgt (XRPL-Spec: rippled
// include/xrpl/protocol/detail/transactions.macro, xrpl.js models/transactions):
//   RegularKey (SetRegularKey = Kontrollübergabe), SignerEntries (SignerListSet
//   = Hintertür über Multisig), Holder (Clawback/MPToken/Credential), Authorize
//   (DepositPreauth), Issuer (NFToken-Issuer), Asset/Asset2 (AMM-Pool-Assets),
//   Amount.issuer (IOU-Issuer bzw. Clawback-Holder).
function actorsOf(tx) {
  const out = [];
  if (tx.Account) out.push(tx.Account);
  if (tx.Destination) out.push(tx.Destination);
  if (tx.LimitAmount?.issuer) out.push(tx.LimitAmount.issuer);
  if (tx.Owner) out.push(tx.Owner); // NFTokenCreateOffer-Seller
  if (typeof tx.RegularKey === "string") out.push(tx.RegularKey);
  if (typeof tx.Holder === "string") out.push(tx.Holder);
  if (typeof tx.Authorize === "string") out.push(tx.Authorize);
  if (typeof tx.Issuer === "string") out.push(tx.Issuer);
  if (Array.isArray(tx.SignerEntries)) {
    for (const e of tx.SignerEntries) if (typeof e?.SignerEntry?.Account === "string") out.push(e.SignerEntry.Account);
  }
  for (const k of ["Asset", "Asset2"]) if (tx[k] && typeof tx[k] === "object" && typeof tx[k].issuer === "string") out.push(tx[k].issuer);
  if (tx.Amount && typeof tx.Amount === "object" && typeof tx.Amount.issuer === "string") out.push(tx.Amount.issuer);
  return out;
}

// Batch (XLS-56, rippled ttBATCH): die Inner-Transaktionen liegen in
// RawTransactions[].RawTransaction und werden sonst NIE analysiert — ein Drainer
// könnte Sweep/Hintertür darin verstecken. Jede Inner-Tx wird als eigener Eintrag
// (meta null, Ledger-Index des Batches) angehängt; der Batch-Eintrag bleibt.
function expandBatches(txs) {
  const out = [];
  for (const entry of txs) {
    out.push(entry);
    const norm = normalizeTxEntry(entry);
    if (norm?.tx?.TransactionType !== "Batch" || !Array.isArray(norm.tx.RawTransactions)) continue;
    const seq = entry.ledger_index ?? entry.ledgerSeq ?? norm.tx.ledger_index ?? norm.tx.ledgerSeq;
    for (const r of norm.tx.RawTransactions) {
      const inner = r?.RawTransaction;
      if (inner && typeof inner === "object" && inner.TransactionType) out.push({ tx: inner, meta: null, ledger_index: seq });
    }
  }
  return out;
}

// =====================================================================
// analyzeTx — Einzel-Transaktions-Regeln (kein History-Zugriff nötig).
// Burst-Regeln (aggregiert) laufen in analyzeLedger.
// =====================================================================
export function analyzeTx(tx, meta, ctx) {
  const c = normalizeCtx(ctx);
  const now = Date.now();
  const findings = [];
  const norm = normalizeTxEntry(tx) || { tx: tx && typeof tx === "object" ? tx : {}, meta: meta ?? null };
  const t = norm.tx;
  const m = norm.meta ?? meta ?? null;
  if (!t || !t.TransactionType) return findings;
  const type = t.TransactionType;

  const push = (ruleId, address, note, noteKey, noteParams, severityOverride) => {
    const rule = RULES.find((r) => r.id === ruleId);
    const finding = { ruleId, severity: severityOverride ?? (rule ? rule.severity : "info"), address, note };
    // Additive Übersetzungsfelder (public/i18n.mjs noteText): die deutsche
    // note bleibt unverändert Protokollwert; noteKey/noteParams ermöglichen
    // die clientseitige Rekonstruktion in der aktuellen Sprache.
    if (noteKey) finding.noteKey = noteKey;
    if (noteParams) finding.noteParams = noteParams;
    findings.push(finding);
  };

  // --- known-bad-hit (Präzisionsanker der Honeypot-Schicht) ---
  // fpGuard: Kuratierungs-Fehler (Exchange-/Gateway-Adresse in knownBad) darf
  // nicht jede Berührung malicious labeln — benign-Whitelist-Guard vor dem
  // push. Fund über Trustline-/NFToken-Position (LimitAmount.issuer, Owner)
  // ist nur 'suspect' (keine direkte Konto-/Zahlungsberührung); direkte
  // Berührung (Account/Destination) einer echten knownBad-Adresse bleibt
  // malicious.
  // Kontroll-Akteure: wer Signier- oder Zugriffsrechte am Konto erhält, ist
  // Berührung, keine bloße Position (RegularKey, Multisig-Signer, Preauth).
  const control = new Set([t.Account, t.Destination, t.RegularKey, t.Authorize]);
  if (Array.isArray(t.SignerEntries)) for (const e of t.SignerEntries) control.add(e?.SignerEntry?.Account);
  for (const a of actorsOf(t)) {
    if (c.benignAccounts.has(a) || c.benignIssuers.has(a)) continue;
    if (c.knownBad.has(a)) {
      const positionOnly = !control.has(a);
      push(
        "known-bad-hit",
        a,
        `Bekannt-maliziöse Adresse beteiligt (${type}).`,
        "known-bad-hit",
        { type },
        positionOnly ? "suspect" : undefined
      );
      break;
    }
  }

  // --- memo-phishing ---
  // Memos sind tx-typ-unabhängig (memoText, Z.111-121): Prüfung gilt auch für
  // TrustSet (Fund-Adresse = LimitAmount.issuer, sonst t.Account), NFTokenMint
  // (Fund-Adresse = Issuer) und PaymentChannelCreate — Scam-Trustlines mit
  // Phishing-Memo und Phishing-Memos in Zahlungskanälen waren bisher blind.
  if (type === "Payment" || type === "EscrowCreate" || type === "CheckCreate"
      || type === "TrustSet" || type === "NFTokenMint" || type === "PaymentChannelCreate") {
    const memo = memoText(t);
    if (isPhishingMemo(memo)) {
      const seed = SEED_RE.test(memo);
      // Fund-Adresse: bei TrustSet der Issuer (die Trustline-Partei, an die
      // das Limit geht), bei NFTokenMint der Issuer; sonst der Zahler.
      let addr = t.Account;
      if (type === "TrustSet") addr = t.LimitAmount?.issuer || t.Account;
      if (type === "NFTokenMint") addr = t.Issuer || t.Account;
      // fpGuard: der Zahler ist bereits knownBad -> kein zweiter memo-Fund
      // (known-bad-hit deckt ihn präziser ab).
      const payerKnownBad = c.knownBad.has(t.Account);
      if (!payerKnownBad) {
        // Zitiertes Opfer (URL in Anführungszeichen + Rückfrage) -> 'suspect'
        // statt 'malicious': das Memo stammt von einem hilfesuchenden Opfer,
        // nicht von einem Täter. Downgrade hält den Fund bewusst aus der
        // malicious-History (lib/history.mjs erzwingt 'malicious' als
        // einzigen Persistenzwert) — das ist der gewünschte FP-Effekt.
        const quoted = isQuotingMemo(memo);
        push("memo-phishing", addr, seed ? "Memo enthält Seed-Muster." : "Memo enthält URL mit claim-/airdrop-/verify-Keyword.", seed ? "memo-phishing-seed" : "memo-phishing-url", undefined, quoted ? "suspect" : undefined);
      }
    }
  }

  // --- airdrop-trustset-spam: Einzel-TrustSet liefert KEINEN Fund ---
  // fpGuard: eine einzelne winzige Trustline eines unbekannten Issuers ist
  // benign (legitime Kleinst-Trustlines), und LimitAmount-Wert "0" ist die
  // kanonische, gutartige Trustline-Entfernung (der Issuer darf eine andere
  // Adresse als das Konto sein). Fund erst als Massenmuster in analyzeLedger:
  // >= 5 verschiedene Konten mit winzigem Limit auf denselben Issuer pro
  // Ledger — das Muster von Fake-Airdrop-Kampagnen.

  // --- dusting: Einzel-Zahlung liefert KEINEN Fund ---
  // fpGuard: eine einzelne Mini-Zahlung an ein frisches Konto ist benign
  // (z. B. Startguthaben oder eine legitime Kleinstzahlung). Fund erst in
  // analyzeLedger: >= 3 Mini-Ziele desselben Senders ODER >= 2 Mini-Zahlungen
  // an frische Ziele pro Ledger.

  // --- fake-nft-fraud (URI- + Wucher-TransferFee-Teil; Null-Burst/CreateOffer-
  //     Burst in analyzeLedger) ---
  if (type === "NFTokenMint") {
    const issuer = t.Issuer ?? t.Account;
    // fpGuard: bekannte Sammlungen/Issuer über benignIssuers.
    if (!(c.benignIssuers.has(issuer) || c.benignAccounts.has(issuer))) {
      const uri = hexToText(t.URI);
      if (isPhishingUri(uri)) {
        push("fake-nft-fraud", t.Account, `NFTokenMint-URI enthält Phishing-/claim-Muster.`, "fake-nft-fraud-uri");
      }
      // Wucher-TransferFee >= 50 % (50000 per mille) auf nicht-whitelisted
      // Issuer: Fake-NFT-Betrug ohne Phishing-URI (Opfer zahlt die Hälfte
      // 'Gebühr'). Legitime Einzel-Mints bleiben benign.
      const fee = Number(t.TransferFee);
      if (Number.isFinite(fee) && fee >= 50000) {
        push("fake-nft-fraud", t.Account, `NFTokenMint mit Wucher-TransferFee (${Math.round(fee / 1000)} %).`, "fake-nft-fraud-fee", { pct: Math.round(fee / 1000) });
      }
    }
  }

  // --- escrow-check-bait (Einzel-Frische-Variante; Burst in analyzeLedger) ---
  if (type === "EscrowCreate" || type === "CheckCreate") {
    // Fix 2026-10-04: CheckCreate trägt den XRP-Betrag im Feld SendMax
    // (XRPL-Spec; live belegt hc_ledger_13), EscrowCreate in Amount —
    // dropsOf liefert für IOU-Objekte null, ein IOU-SendMax erzeugt also
    // keinen Fund (kein False-Positive).
    const d = dropsOf(t.Amount ?? t.SendMax);
    const dest = t.Destination;
    const tiny = d != null && d < c.thresholds.dustDrops; // Bagatellgrenze exklusiv
    const phishing = isPhishingMemo(memoText(t));
    // fpGuard: Einzel-Escrow ohne Muster ist benign.
    if (tiny && dest && !c.benignAccounts.has(dest) && isFresh(dest, c, now) && phishing) {
      push("escrow-check-bait", t.Account, `${type} mit winziger Summe und Phishing-Memo an frisches Ziel ${shortAddr(dest)}.`, "escrow-check-bait-single", { type, addr: shortAddr(dest) });
    }
  }

  return dedupeFindings(findings);
}

function shortAddr(a) {
  const s = String(a ?? "");
  return s.length > 12 ? `${s.slice(0, 8)}…${s.slice(-4)}` : s;
}

function dedupeFindings(findings) {
  const seen = new Set();
  const out = [];
  for (const f of findings) {
    // Dedupe-Schlüssel trägt noteKey mit: dieselbe Regel+Adresse darf in
    // verschiedenen Note-Varianten bestehen bleiben (z. B. escrow-check-bait
    // Einzel-Fund UND Burst-Fund desselben Täters — sonst verliert der
    // Burst-Fund gegen den zuerst erzeugten Einzel-Fund).
    const key = `${f.ruleId}|${f.address}|${f.noteKey ?? ""}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(f);
  }
  return out;
}

// =====================================================================
// analyzeLedger — akzeptiert JSON-RPC-Ergebnis ODER rohes WSS-Ledger-Event.
//   Container-Formen: result.ledger.transactions | ledger.transactions |
//   transactions (rohes Event {type:'ledger', ...}). Einträge: Hash-Strings
//   (dann hash-only) ODER {tx_json|tx,meta} ODER flache tx-Objekte.
// =====================================================================
function extractTransactions(ledgerResult) {
  if (!ledgerResult || typeof ledgerResult !== "object") return null;
  const candidates = [
    ledgerResult.result?.ledger?.transactions,
    ledgerResult.ledger?.transactions,
    ledgerResult.transactions,
    ledgerResult.result?.transactions,
  ];
  for (const c of candidates) if (Array.isArray(c)) return c;
  return null;
}

export function analyzeLedger(ledgerResult, ctx) {
  const c = normalizeCtx(ctx);
  const now = Date.now();
  const txs = extractTransactions(ledgerResult);

  if (!Array.isArray(txs)) {
    return { findings: [], stats: { txs: 0, findings: 0 } };
  }

  // Hash-only-Fall: Transaktionen sind Hash-Strings — Auflösung ist Sache
  // des Aufrufers (per tx-Methode). Engine liefert dann leere Funde.
  const allHashes = txs.length > 0 && txs.every((t) => typeof t === "string");
  if (allHashes) {
    return { findings: [], stats: { txs: txs.length, findings: 0 }, hashOnly: true };
  }

  const findings = [];
  // Aggregations-Fenster pro Konto für Burst-Regeln.
  const agg = new Map(); // account -> {inXrp, inDust, out:[{dest,drops,prevBal}], offers, offerFills, escrowDests:Set, acceptZero, payDests:Set, payTiny, payKnownBad, freshTiny:Set, selfPays, inFrom:Set, nftOffers:Map, swapPairs:Map, thinFills:Array, spoofOpen:Map, spoofCycles:Array}
  const acct = (a) => {
    if (!agg.has(a)) agg.set(a, { inXrp: 0, inDust: 0, out: [], offers: 0, offerFills: 0, escrowDests: new Set(), acceptZero: 0, payDests: new Set(), payTiny: false, payKnownBad: false, freshTiny: new Set(), selfPays: 0, inFrom: new Set(), nftOffers: new Map(), swapPairs: new Map(), thinFills: [], spoofOpen: new Map(), spoofCycles: [] });
    return agg.get(a);
  };
  // Issuer -> Set der Konten mit winzigem TrustSet-Limit (Massenmuster).
  const trustTiny = new Map();
  // Ledger-Seq für die history-Pflege (Cross-Ledger-Gedächtnis).
  const ledgerSeq = Number(
    ledgerResult?.result?.ledger?.ledger_index ?? ledgerResult?.ledger?.ledger_index ?? ledgerResult?.ledger_index ?? ledgerResult?.ledgerIndex
  );
  const seqNum = Number.isFinite(ledgerSeq) ? Math.floor(ledgerSeq) : null;
  const histEntry = (a) => {
    if (!c.history.has(a)) c.history.set(a, { tinyDests: new Set(), fundedAt: null, createdInWindow: false, lastLedger: null });
    return c.history.get(a);
  };

  for (const entry of expandBatches(txs)) {
    const norm = normalizeTxEntry(entry);
    if (!norm) continue;
    const t = norm.tx;
    const m = norm.meta;
    if (!t || !t.TransactionType) continue;
    const type = t.TransactionType;
    // Ledger-Index der Entry (Fenster-Berechnung der Market-Regeln,
    // ledgerSeq-Differenz — stampExpandEntry/Entries tragen ledger_index).
    const entrySeqRaw = Number(entry.ledger_index ?? entry.ledgerSeq ?? t.ledger_index ?? t.ledgerSeq);
    const entrySeq = Number.isFinite(entrySeqRaw) ? entrySeqRaw : null;

    // Einzel-Regeln
    for (const f of analyzeTx(t, m, c)) findings.push(f);

    // Aggregation für Burst-Regeln
    if (type === "Payment") {
      const d = dropsOf(t.Amount ?? t.DeliverMax);
      if (d != null) {
        const selfPay = t.Destination && t.Account === t.Destination;
        if (t.Destination && !selfPay) {
          const destA = acct(t.Destination);
          destA.inXrp += d;
          if (d < c.thresholds.dustDrops) destA.inDust += 1; // Bagatellgrenze exklusiv
          destA.inFrom.add(t.Account); // Zahlungsabsender des Kontos (drainer-sweep-Guard)
        }
        const srcA = acct(t.Account);
        if (t.Destination) {
          if (selfPay) {
            // Wash-Aggregation: Selbsttransfer (Account === Destination) zählt
            // für die wash-Regel, NICHT für dusting/payment-burst (kein
            // Doppel-Label) und nicht als Destinations-Eingang.
            srcA.selfPays += 1;
          } else {
            srcA.out.push({ dest: t.Destination, drops: d, prevBal: prevBalanceOf(m) });
            srcA.payDests.add(t.Destination);
            if (d < c.thresholds.dustDrops) {
              srcA.payTiny = true;
              histEntry(t.Account).tinyDests.add(t.Destination); // Cross-Ledger-Union
              if (isFresh(t.Destination, c, now) && !c.benignAccounts.has(t.Destination)) srcA.freshTiny.add(t.Destination);
            }
            if (c.knownBad.has(t.Destination)) srcA.payKnownBad = true;
          }
        }
      }
    } else if (type === "OfferCreate" || type === "OfferCancel") {
      const a = acct(t.Account);
      // fpGuard: nur OfferCreate zählt — OfferCancel allein ist normaler
      // Handels-Cleanup und erzeugte False-Positives auf Market-Maker.
      if (type === "OfferCreate") a.offers += 1;
      if (hasFill(m)) a.offerFills += 1;
      // Market-Aggregation (T1.2): Fills und Create->Cancel-Paarung aus der
      // bereits geladenen Meta (expand:true liefert tx_json + meta pro Block,
      // api/advance.js:529-536 / public/app.js WSS-Pfad) — reine In-Memory-
      // Arithmetik, +0 Requests. Taker-Sicht: in = TakerGets, out = TakerPays
      // (Kommentar offerFillNodesOf).
      if (type === "OfferCreate") {
        // txAccount-Guard: DeletedNode Offers des eigenen Kontos sind
        // Quote-Replacements, keine Fills (Kommentar offerFillNodesOf,
        // Kritik-Runde 4 Befund 3) — sie erreichen swapPairs/thinFills nicht.
        const nodes = offerFillNodesOf(m, t.Account);
        for (const node of nodes) {
          if (node.kind !== "deleted") continue; // CreatedNode = Platzierung, kein Fill
          const f = node.fields;
          const inSide = sideKey(f.TakerGets);
          const outSide = sideKey(f.TakerPays);
          if (!inSide || !outSide || inSide === outSide) continue;
          const pair = inSide < outSide ? `${inSide}|${outSide}` : `${outSide}|${inSide}`;
          const dir = `${inSide}>${outSide}`;
          const notional = sideDrops(f.TakerGets) ?? sideDrops(f.TakerPays) ?? 0;
          const rateNorm = fillRateNormOf(f, pair.split("|")[0]);
          const p = a.swapPairs.get(pair) ?? { dirs: new Map(), rates: [], minSeq: null, maxSeq: null };
          const d = p.dirs.get(dir) ?? { n: 0, notional: 0 };
          d.n += 1;
          d.notional += notional;
          p.dirs.set(dir, d);
          if (rateNorm != null) p.rates.push({ rateNorm, notional, seq: entrySeq });
          if (entrySeq != null) {
            if (p.minSeq == null || entrySeq < p.minSeq) p.minSeq = entrySeq;
            if (p.maxSeq == null || entrySeq > p.maxSeq) p.maxSeq = entrySeq;
          }
          a.swapPairs.set(pair, p);
          // thin-pool-Fills: getsHi merkt die Taker-Seite für die
          // Richtungs-Bewertung gegen den Pair-Median.
          if (rateNorm != null) a.thinFills.push({ pair, getsHi: inSide > outSide, rateNorm, notional, seq: entrySeq });
        }
        // Spoof-Open: eigene platzierte Limit-Order (CreatedNode Offer des
        // Makers selbst) — Cancel-Paarung über (Account, Sequence, BookDirectory).
        const own = nodes.find((x) => x.kind === "created" && x.fields.Account === t.Account);
        if (own && entrySeq != null) {
          const book = typeof own.fields.BookDirectory === "string" ? own.fields.BookDirectory : "";
          const key = `${t.Account}|${own.fields.Sequence ?? ""}|${book}`;
          a.spoofOpen.set(key, {
            seq: entrySeq,
            book,
            bookNode: typeof own.fields.BookNode === "string" ? own.fields.BookNode : null,
            notional: sideDrops(own.fields.TakerGets) ?? sideDrops(own.fields.TakerPays) ?? 0,
          });
        }
      } else {
        const del = offerCancelNodeOf(m);
        if (del && del.Account === t.Account && entrySeq != null) {
          const book = typeof del.BookDirectory === "string" ? del.BookDirectory : "";
          const key = `${t.Account}|${del.Sequence ?? ""}|${book}`;
          const open = a.spoofOpen.get(key);
          if (open) {
            a.spoofCycles.push({
              fromSeq: open.seq,
              toSeq: entrySeq,
              book,
              bookNode: (typeof del.BookNode === "string" ? del.BookNode : null) ?? open.bookNode,
              notional: (sideDrops(del.TakerGets) ?? sideDrops(del.TakerPays)) ?? open.notional,
            });
            a.spoofOpen.delete(key);
          }
        }
      }
    } else if (type === "TrustSet") {
      const la = t.LimitAmount || {};
      const issuer = la.issuer;
      // fpGuard: Trustline-Entfernung (Limit "0" oder Account===issuer) und
      // whitelisted Issuer bleiben außen vor.
      if (issuer && issuer !== t.Account && String(la.value ?? "") !== "0" && !c.benignIssuers.has(issuer) && !c.benignAccounts.has(issuer)) {
        const val = Number(la.value ?? "0");
        const quality = la.quality != null ? Number(la.quality) : null;
        // fpGuard (Korrektur): der Quality-Arm gilt nur für kleine Limits —
        // eine große legitime Trustline (value 1000000) mit niedriger Quality
        // war bisher 'winzig' und zählte ins Massenmuster. Fake-Airdrop-Muster
        // (Mini-Limits) bleiben tiny.
        const tiny = val < 1 || (quality != null && quality < 1e17 && val < 1e4);
        if (tiny) {
          if (!trustTiny.has(issuer)) trustTiny.set(issuer, new Set());
          trustTiny.get(issuer).add(t.Account);
        }
      }
    } else if (type === "NFTokenAcceptOffer") {
      // Nullwert-Burst: AcceptOffer, dessen betroffene NFTokenOffer-Nodes Amount '0' tragen.
      if (acceptsWithZeroValue(m)) acct(t.Account).acceptZero += 1;
    } else if (type === "NFTokenCreateOffer") {
      // Kaufangebots-Burst: >= 5 Offers desselben Kontos auf dasselbe Ziel
      // (NFTokenCreateOffer.Owner = Angebotsziel/Seller) pro Ledger —
      // systematische Fake-Kaufangebote ohne Phishing-URI.
      const target = t.Owner;
      if (target) {
        const a = acct(t.Account);
        a.nftOffers.set(target, (a.nftOffers.get(target) ?? 0) + 1);
      }
    } else if (type === "EscrowCreate" || type === "CheckCreate") {
      // SendMax-Fallback wie in analyzeTx (:407) — CheckCreate-SendMax-Form.
      const d = dropsOf(t.Amount ?? t.SendMax);
      const dest = t.Destination;
      // fpGuard: Burst zählt nur mit Phishing-Memo (Konsistenz zur
      // Einzel-Variante) — drei legitime Kleinst-Escrows an neue Nutzer sind
      // benign.
      if (dest && d != null && d < c.thresholds.dustDrops && isFresh(dest, c, now) && isPhishingMemo(memoText(t))) {
        acct(t.Account).escrowDests.add(dest);
      }
    }
    // Frische-Härtung: CreatedNode AccountRoot -> Konto im Fenster erstellt.
    const created = createdAccountOf(m);
    if (created) histEntry(created).createdInWindow = true;
  }

  // ---------- Burst-Regeln (ledger-aggregiert) ----------
  for (const [account, a] of agg) {
    if (c.benignAccounts.has(account)) continue;

    // dusting: >= 3 verschiedene Mini-Zahlungsziele desselben Senders ODER
    // >= 2 Mini-Zahlungen an frische Ziele (fpGuard: eine einzelne Mini-
    // Zahlung an ein frisches Konto ist benign).
    // Cross-Ledger: gewertet wird die UNION der tinyDests über das Fenster
    // (ctx.history) — eine zeitlich gestreckte Dusting-Kampagne (1 Ziel pro
    // Ledger über 3 Ledger) war bisher unsichtbar.
    const tinyDests = new Set();
    for (const o of a.out) if (o.drops < c.thresholds.dustDrops) tinyDests.add(o.dest);
    const hist = c.history.get(account);
    const unionTiny = new Set(tinyDests);
    if (hist?.tinyDests) for (const d of hist.tinyDests) unionTiny.add(d);
    if (unionTiny.size >= 3 || a.freshTiny.size >= 2) {
      const many = unionTiny.size >= 3;
      const note = many
        ? `${unionTiny.size} Mini-XRP-Zahlungen an verschiedene Ziele im Beobachtungsfenster.`
        : `${a.freshTiny.size} Mini-XRP-Zahlungen an frische Ziele in einem Ledger.`;
      findings.push({ ruleId: "dusting", severity: "suspect", address: account, note, noteKey: many ? "dusting-many" : "dusting-fresh", noteParams: { n: many ? unionTiny.size : a.freshTiny.size } });
    }

    // wash-self-transfer: >= 3 Selbstzahlungen (Account === Destination) pro
    // Ledger — Volumenerzeugung/Washing. Legitime Einzel-Konsolidierung bleibt
    // benign.
    if (a.selfPays >= 3) {
      findings.push({ ruleId: "wash-self-transfer", severity: "suspect", address: account, note: `${a.selfPays} Selbstzahlungen in einem Ledger (Volumen-Washing).`, noteKey: "wash-self-transfer", noteParams: { n: a.selfPays } });
    }

    // drainer-sweep: frisch finanziert -> >= sweepRatio an EIN Ziel
    // fpGuard (HIGH-Fix): die frühere Variante 2 (>= 3 Futter-Zahlungen +
    // beliebige ausgehende Zahlung OHNE Sweep-Ratio) labelte harmlose frische
    // Konten als malicious — entfernt. Ein Fund verlangt immer, dass die
    // ausgehende Zahlung >= sweepRatio des Kontostands erreicht.
    // fpGuard (Konsolidierung): Sweep an das eigene Konto (o.dest === account,
    // Selbsttransfer) scheidet aus; Sweep an ein Ziel, von dem das Konto
    // selbst Zahlungen erhielt (!inFrom.has(dest) falsch), ist Rückführung/
    // Gegenkonto, kein Drainer-Ziel.
    // Frische-Härtung: 'malicious' nur bei CreatedNode-Frische (Konto im
    // Fenster erst erstellt) ODER Entity-Snapshot-Beleg frischer Konto-
    // aktivität (V5 verifiedFresh, S−P-Gap <= 24 h — schließt die Cross-Tick-
    // Degradation: Fütterung Tick T, Sweep Tick T+1 seedet createdInWindow:
    // false, der Snapshot-Beleg trägt die malicious-Stufe). Reines firstSeenAt-
    // Signal (Stream-Fenster = erste Sichtung, kein Erstellungsbeleg) ->
    // Downgrade auf 'suspect'. verifiedFresh ist ZWEITER Belegsweg, nie eine
    // eigene Fundquelle und nie ein Downgrade. Cross-Ledger: fundedAt aus
    // ctx.history als zusätzliche Sweep-Referenz (Sweep in Ledger N+1 auf in
    // Ledger N gefüttertes Konto).
    if (isFresh(account, c, now)) {
      const fundedAt = hist?.fundedAt ?? null;
      const base = a.inXrp > 0 ? a.inXrp : fundedAt != null && fundedAt > 0 ? fundedAt : 0;
      const sweep = a.out.find((o) => {
        if (o.dest === account) return false; // Selbsttransfer: Konsolidierung, kein Sweep
        if (a.inFrom.has(o.dest)) return false; // Ziel ist Gegenkonto eigener Zahlungen
        const ref = o.prevBal != null ? o.prevBal : base;
        return ref > 0 && o.drops >= c.thresholds.sweepRatio * ref;
      });
      if (sweep && (a.inXrp > 0 || a.inDust >= 3 || fundedAt != null)) {
        const pct = Math.round((sweep.drops / (sweep.prevBal ?? a.inXrp ?? fundedAt)) * 100);
        const createdFresh = hist?.createdInWindow === true || c.verifiedFresh.has(account);
        findings.push({ ruleId: "drainer-sweep", severity: createdFresh ? "malicious" : "suspect", address: account, note: `Frisch finanziert und ${pct} % an ein Ziel abgeräumt.`, noteKey: "drainer-sweep", noteParams: { pct } });
      }
    }

    // offer-spam: >= 10 OfferCreate ohne einzigen Fill
    // fpGuard: 3 frische Limit-Orders in einem 4-Sekunden-Ledger sind
    // normaler Market-Maker-Betrieb; Spam-Kaskaden (10+) bleiben info.
    if (a.offers >= 10 && a.offerFills === 0) {
      findings.push({ ruleId: "offer-spam", severity: "info", address: account, note: `${a.offers} OfferCreate ohne Fill in einem Ledger.`, noteKey: "offer-spam", noteParams: { n: a.offers } });
    }

    // fake-nft-fraud Null-Burst: >= 10 AcceptOffer zu 0
    // fpGuard: gelegentliche Gratis-Claims legitimer Sammlungen sind benign;
    // Sybil-/Farming-Muster treiben große Null-Accept-Bursts pro Ledger.
    if (a.acceptZero >= 10) {
      findings.push({ ruleId: "fake-nft-fraud", severity: "suspect", address: account, note: `${a.acceptZero} NFTokenAcceptOffer ohne Zahlung in einem Ledger.`, noteKey: "fake-nft-fraud-accept", noteParams: { n: a.acceptZero } });
    }

    // fake-nft-fraud CreateOffer-Burst: >= 5 NFTokenCreateOffer desselben
    // Kontos auf dasselbe Ziel pro Ledger (systematische Kaufangebote).
    for (const [target, n] of a.nftOffers) {
      if (n >= 5) {
        findings.push({ ruleId: "fake-nft-fraud", severity: "suspect", address: account, note: `${n} NFTokenCreateOffer auf dasselbe Ziel ${shortAddr(target)} in einem Ledger.`, noteKey: "fake-nft-fraud-offer", noteParams: { n, addr: shortAddr(target) } });
        break;
      }
    }

    // escrow-check-bait Burst: >= 3 frische Ziele (nur mit Phishing-Memo,
    // siehe Aggregation — Konsistenz zur Einzel-Variante).
    if (a.escrowDests.size >= 3) {
      findings.push({ ruleId: "escrow-check-bait", severity: "suspect", address: account, note: `${a.escrowDests.size} Escrow/Check-Köder an verschiedene frische Ziele.`, noteKey: "escrow-check-bait-burst", noteParams: { n: a.escrowDests.size } });
    }

    // payment-burst: >= 5 Ziele UND (>= 3 winzige Zahlungen ODER knownBad-Kante)
    // UND die winzigen Ziele müssen die Mehrheit stellen (tinyDests >=
    // payDests - 2). fpGuard: Exchange-/Rückerstattungs-/Lohnmuster mit
    // wenigen Kleinstbeträgen zwischen großen Zahlungen bleiben benign;
    // echte Airdrop-Bursts (fast alles winzig) bleiben suspect.
    if (a.payDests.size >= 5 && (tinyDests.size >= 3 || a.payKnownBad) && tinyDests.size >= a.payDests.size - 2) {
      findings.push({ ruleId: "payment-burst", severity: "suspect", address: account, note: `${a.payDests.size} Zahlungen an verschiedene Ziele, davon ${tinyDests.size} winzig (Airdrop-Verteilungsmuster).`, noteKey: "payment-burst", noteParams: { n: a.payDests.size, tiny: tinyDests.size } });
    }

    // ---------- Market-Regeln (T1.2, Tx-Ebene, +0 Requests) ----------
    // Gemeinsamer FP-Guard: benignAccounts (wie oben) UND marketExcludes
    // (Exchange-Registry ∪ multiUser ∪ Köder ∪ config-benign — derselbe
    // Börsen-Guard, den motifCounters über motifExclude hat; Market-Maker-
    // und Börsen-Aktivität ist per Definition hochfrequent und bidirektional).
    if (c.marketExcludes.has(account)) continue;

    // amm-wash-swap: Waschhandel über OfferCreate-Selbstzyklus (Fill gegen
    // denselben Pool in beide Richtungen) — wash-cycle (Payment-Kanten) und
    // wash-self-transfer (Payment-Selbstzahlung) sehen das nicht, weil
    // OfferCreate per Spec keine Kante erzeugt (cluster.mjs:353-355) und
    // motifCounters IOU ausschließt (cluster.mjs:1774).
    for (const [pair, p] of a.swapPairs) {
      const dirs = [...p.dirs.entries()].sort((x, y) => (x[0] < y[0] ? -1 : 1)); // deterministisch
      if (dirs.length < 2) continue;
      let minN = Infinity; let maxN = 0; let minNot = Infinity; let maxNot = 0;
      for (const [, d] of dirs) {
        if (d.n < minN) minN = d.n;
        if (d.n > maxN) maxN = d.n;
        if (d.notional < minNot) minNot = d.notional;
        if (d.notional > maxNot) maxNot = d.notional;
      }
      if (minN < c.thresholds.washMinFillsPerSide) continue; // Refund-Guard
      if (maxNot <= 0) continue;
      if (minNot < c.thresholds.washMinNotionalDrops) continue;
      const conserve = minNot / maxNot;
      if (conserve < c.thresholds.washConserveMin) continue;
      const drift = (maxNot - minNot) / maxNot;
      if (drift > c.thresholds.washMaxDrift) continue;
      if (p.minSeq != null && p.maxSeq != null && p.maxSeq - p.minSeq > c.thresholds.washWindowLedgers) continue;
      findings.push({ ruleId: "amm-wash-swap", severity: "suspect", address: account, note: `Bidirektionale OfferCreate-Fills auf ${pair} im Volumen-Gleichgewicht (Volumenerhalt ${Math.round(conserve * 100)} %, Drift ${Math.round(drift * 100)} %).`, noteKey: "amm-wash-swap", noteParams: { pair, conserve: Math.round(conserve * 100), drift: Math.round(drift * 100) } });
      break; // ein Fund je Konto (Muster fake-nft-fraud CreateOffer-Burst)
    }

    // thin-pool-exploit: >= thinMinPairSamples beobachtete Fills desselben
    // Pairs im Fenster (sonst 'nicht messbar statt raten'), >= 2 Fills des
    // Kontos mit >= 25 % Abweichung vom Fenster-Median in die für das Konto
    // günstige Richtung (getsHi: rateNorm > Median günstig; getsLo:
    // rateNorm < Median günstig — Taker erhält TakerGets, Kommentar
    // offerFillNodesOf), Mindestnotional >= 10 XRP, Fenster <= 150 Ledger.
    if (a.thinFills.length >= c.thresholds.thinMinFillsPerAccount) {
      const byPair = new Map();
      for (const f of a.thinFills) {
        if (!byPair.has(f.pair)) byPair.set(f.pair, []);
        byPair.get(f.pair).push(f);
      }
      // Fenster-Median je Pair über ALLE beobachteten Fills des Pairs
      // (auch anderer Konten im selben Ledger — der Median ist der
      // Liquiditäts-Proxy, nicht die Eigenhistorie).
      const pairRates = new Map();
      for (const [account2, a2] of agg) {
        if (account2 === account) continue;
        for (const f of a2.thinFills) {
          if (!pairRates.has(f.pair)) pairRates.set(f.pair, []);
          pairRates.get(f.pair).push(f.rateNorm);
        }
      }
      for (const [pair, fills] of [...byPair.entries()].sort((x, y) => (x[0] < y[0] ? -1 : 1))) {
        const others = pairRates.get(pair) ?? [];
        const allRates = [...fills.map((f) => f.rateNorm), ...others];
        if (allRates.length < c.thresholds.thinMinPairSamples) continue;
        const median = medianOf(allRates);
        if (median == null || median <= 0) continue;
        let good = 0;
        let goodNotional = 0;
        let minSeq = null; let maxSeq = null;
        for (const f of fills) {
          if (f.notional < c.thresholds.thinMinNotionalDrops) continue;
          const dev = Math.abs(f.rateNorm - median) / median;
          if (dev < c.thresholds.thinDeviationMin) continue;
          const favorable = f.getsHi ? f.rateNorm > median : f.rateNorm < median;
          if (!favorable) continue;
          good += 1;
          goodNotional += f.notional;
          if (f.seq != null) {
            if (minSeq == null || f.seq < minSeq) minSeq = f.seq;
            if (maxSeq == null || f.seq > maxSeq) maxSeq = f.seq;
          }
        }
        if (good < c.thresholds.thinMinFillsPerAccount) continue;
        if (minSeq != null && maxSeq != null && maxSeq - minSeq > c.thresholds.thinWindowLedgers) continue;
        findings.push({ ruleId: "thin-pool-exploit", severity: "suspect", address: account, note: `${good} Fills auf ${pair} mit >= ${Math.round(c.thresholds.thinDeviationMin * 100)} % Preisabweichung vom Fenster-Median in die günstige Richtung (dünner Pool).`, noteKey: "thin-pool-exploit", noteParams: { pair, n: good, devPct: Math.round(c.thresholds.thinDeviationMin * 100) } });
        break; // ein Fund je Konto
      }
    }

    // spoof-offer-cycle: Place-and-Pull — Create->Cancel-Paarung rein aus
    // der Meta (Match-Key Account|Sequence|BookDirectory, xrpl@4.0.0
    // ledger/Offer.d.ts), Cancel-Abstand <= 75 Ledger, >= 3 Zyklen desselben
    // Kontos in derselben BookDirectory im Fenster <= 300 Ledger, >= 2
    // verschiedene Preislevel (BookNode), Cancel-Notional >= 100 XRP.
    // offer-spam ('info') zählt Offers ohne Fill, ist aber blind für
    // Cancel-Zeit, Größe und Preislevel — Spoofing ist genau diese Kombination.
    if (a.spoofCycles.length >= c.thresholds.spoofMinCycles) {
      // Gruppierung nach BookDirectory (Orderbuch des Pairs — xrpl@4.0.0
      // ledger/Offer.d.ts Book{BookDirectory,BookNode}); BookNode ist das
      // Preislevel innerhalb dieses Orderbuchs.
      const byBook = new Map();
      for (const cy of a.spoofCycles) {
        const book = cy.book ?? "";
        if (!byBook.has(book)) byBook.set(book, []);
        byBook.get(book).push(cy);
      }
      for (const [book, cycles] of [...byBook.entries()].sort((x, y) => (x[0] < y[0] ? -1 : 1))) {
        const ok = cycles.filter((cy) =>
          cy.toSeq - cy.fromSeq <= c.thresholds.spoofMaxCancelLedgers &&
          cy.notional >= c.thresholds.spoofMinCancelNotionalDrops
        );
        if (ok.length < c.thresholds.spoofMinCycles) continue;
        const levels = new Set(ok.map((cy) => cy.bookNode ?? ""));
        if (levels.size < c.thresholds.spoofMinPriceLevels) continue;
        let minSeq = null; let maxSeq = null;
        for (const cy of ok) {
          if (minSeq == null || cy.fromSeq < minSeq) minSeq = cy.fromSeq;
          if (maxSeq == null || cy.toSeq > maxSeq) maxSeq = cy.toSeq;
        }
        if (maxSeq - minSeq > c.thresholds.spoofWindowLedgers) continue;
        findings.push({ ruleId: "spoof-offer-cycle", severity: "suspect", address: account, note: `${ok.length} Place-and-Pull-Zyklen (Create->Cancel <= ${c.thresholds.spoofMaxCancelLedgers} Ledger) auf ${levels.size} Preislevel in Orderbuch ${book.slice(0, 12)}.`, noteKey: "spoof-offer-cycle", noteParams: { n: ok.length, levels: levels.size, maxCancel: c.thresholds.spoofMaxCancelLedgers } });
        break; // ein Fund je Konto
      }
    }
  }

  // airdrop-trustset-spam: Issuer erhält im selben Ledger winzige Limits von
  // >= 5 verschiedenen Konten (Massenmuster von Fake-Airdrops).
  for (const [issuer, accounts] of trustTiny) {
    if (accounts.size >= 5) {
      findings.push({ ruleId: "airdrop-trustset-spam", severity: "suspect", address: issuer, note: `${accounts.size} TrustSets mit winzigem Limit von verschiedenen Konten auf Issuer ${shortAddr(issuer)} in einem Ledger.`, noteKey: "airdrop-trustset-spam", noteParams: { n: accounts.size, issuer: shortAddr(issuer) } });
    }
  }

  // history in-place zurückschreiben (Cross-Ledger-Gedächtnis): tinyDests
  // (bereits oben gepflegt), fundedAt (Summe der XRP-Eingänge dieses Ledgers)
  // und lastLedger pro Konto. Die Map ist dieselbe Referenz wie ctx.history
  // (toMap), der Rückschreib-Pfad trägt damit über Aufrufe hinweg.
  for (const [account, a] of agg) {
    const h = histEntry(account);
    if (a.inXrp > 0) h.fundedAt = a.inXrp;
    if (seqNum != null) h.lastLedger = seqNum;
  }

  const deduped = dedupeFindings(findings);
  return { findings: deduped, stats: { txs: txs.length, findings: deduped.length } };
}
