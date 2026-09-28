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

// ---------- Schwellen (Default; per ctx.thresholds überschreibbar) ----------
export const DEFAULT_THRESHOLDS = {
  dustDrops: 1000,        // Bagatellgrenze (live kalibriert: legitime Kleinstzahlungen bis 10 drops)
  minAccountAgeMin: 15,   // Frische-Fenster in Minuten
  sweepRatio: 0.9,        // >= 90 % der Balance an EIN Ziel = Sweep
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
    thresholds: { ...DEFAULT_THRESHOLDS, ...(c.thresholds || {}) },
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
const CLAIM_RE = /\b(claim|airdrop|verify|giveaway|free[\s-]*token|freecoin)\b/i;
// sEd = modernes Seed-Format (29 Zeichen, BIP39); skey/shss/spup = alte Typen.
const SEED_RE = /\b(skey|shss|spup|sEd)[1-9A-HJ-NP-Za-km-z]{16,}\b/;
const SHORTLINK_RE = /\b(bit\.ly|t\.co|tinyurl\.com|goo\.gl|is\.gd|cutt\.ly|rb\.gy|rebrand\.ly)\b/i;

function isPhishingMemo(text) {
  const t = String(text ?? "");
  if (!t) return false;
  if (SEED_RE.test(t)) return true;
  // fpGuard: reine Referenz-IDs/JSON-Memos sind benign; URL allein ohne
  // claim-Keyword ist benign.
  if (URL_RE.test(t) && CLAIM_RE.test(t)) return true;
  return false;
}

function isPhishingUri(uriText) {
  const u = String(uriText ?? "").trim();
  if (!u) return false; // fpGuard: URI leer -> benign
  if (SHORTLINK_RE.test(u)) return true; // URL-Kurzlink
  if (URL_RE.test(u) && CLAIM_RE.test(u)) return true; // Phishing-Domain + claim-Muster
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

// ---------- Frische-Signal ----------
function isFresh(addr, ctx, now) {
  if (!addr || !ctx.firstSeenAt.has(addr)) return false; // ohne Frische-Signal kein Fund
  const seen = ctx.firstSeenAt.get(addr);
  const ageMin = (now - seen) / 60000;
  return ageMin < ctx.thresholds.minAccountAgeMin;
}

// Beteiligte Akteure einer tx (für known-bad-hit).
function actorsOf(tx) {
  const out = [];
  if (tx.Account) out.push(tx.Account);
  if (tx.Destination) out.push(tx.Destination);
  if (tx.LimitAmount?.issuer) out.push(tx.LimitAmount.issuer);
  if (tx.Owner) out.push(tx.Owner); // NFTokenCreateOffer-Seller
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

  const push = (ruleId, address, note) => {
    const rule = RULES.find((r) => r.id === ruleId);
    findings.push({ ruleId, severity: rule ? rule.severity : "info", address, note });
  };

  // --- known-bad-hit (Präzisionsanker der Honeypot-Schicht) ---
  for (const a of actorsOf(t)) {
    if (c.knownBad.has(a)) {
      push("known-bad-hit", a, `Bekannt-maliziöse Adresse beteiligt (${type}).`);
      break;
    }
  }

  // --- memo-phishing ---
  if (type === "Payment" || type === "EscrowCreate" || type === "CheckCreate") {
    const memo = memoText(t);
    if (isPhishingMemo(memo)) {
      const seed = SEED_RE.test(memo);
      push("memo-phishing", t.Account, seed ? "Memo enthält Seed-Muster." : "Memo enthält URL mit claim-/airdrop-/verify-Keyword.");
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

  // --- fake-nft-fraud (URI-Teil; Null-Burst-Teil in analyzeLedger) ---
  if (type === "NFTokenMint") {
    const issuer = t.Issuer ?? t.Account;
    // fpGuard: bekannte Sammlungen/Issuer über benignIssuers.
    if (!(c.benignIssuers.has(issuer) || c.benignAccounts.has(issuer))) {
      const uri = hexToText(t.URI);
      if (isPhishingUri(uri)) {
        push("fake-nft-fraud", t.Account, `NFTokenMint-URI enthält Phishing-/claim-Muster.`);
      }
    }
  }

  // --- escrow-check-bait (Einzel-Frische-Variante; Burst in analyzeLedger) ---
  if (type === "EscrowCreate" || type === "CheckCreate") {
    const d = dropsOf(t.Amount);
    const dest = t.Destination;
    const tiny = d != null && d <= c.thresholds.dustDrops;
    const phishing = isPhishingMemo(memoText(t));
    // fpGuard: Einzel-Escrow ohne Muster ist benign.
    if (tiny && dest && !c.benignAccounts.has(dest) && isFresh(dest, c, now) && phishing) {
      push("escrow-check-bait", t.Account, `${type} mit winziger Summe und Phishing-Memo an frisches Ziel ${shortAddr(dest)}.`);
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
    const key = `${f.ruleId}|${f.address}`;
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
  const agg = new Map(); // account -> {inXrp, inDust, out:[{dest,drops,prevBal}], offers, offerFills, escrowDests:Set, acceptZero, payDests:Set, payTiny, payKnownBad, freshTiny:Set}
  const acct = (a) => {
    if (!agg.has(a)) agg.set(a, { inXrp: 0, inDust: 0, out: [], offers: 0, offerFills: 0, escrowDests: new Set(), acceptZero: 0, payDests: new Set(), payTiny: false, payKnownBad: false, freshTiny: new Set() });
    return agg.get(a);
  };
  // Issuer -> Set der Konten mit winzigem TrustSet-Limit (Massenmuster).
  const trustTiny = new Map();

  for (const entry of txs) {
    const norm = normalizeTxEntry(entry);
    if (!norm) continue;
    const t = norm.tx;
    const m = norm.meta;
    if (!t || !t.TransactionType) continue;
    const type = t.TransactionType;

    // Einzel-Regeln
    for (const f of analyzeTx(t, m, c)) findings.push(f);

    // Aggregation für Burst-Regeln
    if (type === "Payment") {
      const d = dropsOf(t.Amount ?? t.DeliverMax);
      if (d != null) {
        if (t.Destination && t.Account !== t.Destination) {
          const destA = acct(t.Destination);
          destA.inXrp += d;
          if (d <= c.thresholds.dustDrops) destA.inDust += 1;
        }
        const srcA = acct(t.Account);
        if (t.Destination) {
          srcA.out.push({ dest: t.Destination, drops: d, prevBal: prevBalanceOf(m) });
          srcA.payDests.add(t.Destination);
          if (d <= c.thresholds.dustDrops) {
            srcA.payTiny = true;
            if (isFresh(t.Destination, c, now) && !c.benignAccounts.has(t.Destination)) srcA.freshTiny.add(t.Destination);
          }
          if (c.knownBad.has(t.Destination)) srcA.payKnownBad = true;
        }
      }
    } else if (type === "OfferCreate" || type === "OfferCancel") {
      const a = acct(t.Account);
      // fpGuard: nur OfferCreate zählt — OfferCancel allein ist normaler
      // Handels-Cleanup und erzeugte False-Positives auf Market-Maker.
      if (type === "OfferCreate") a.offers += 1;
      if (hasFill(m)) a.offerFills += 1;
    } else if (type === "TrustSet") {
      const la = t.LimitAmount || {};
      const issuer = la.issuer;
      // fpGuard: Trustline-Entfernung (Limit "0" oder Account===issuer) und
      // whitelisted Issuer bleiben außen vor.
      if (issuer && issuer !== t.Account && String(la.value ?? "") !== "0" && !c.benignIssuers.has(issuer) && !c.benignAccounts.has(issuer)) {
        const val = Number(la.value ?? "0");
        const quality = la.quality != null ? Number(la.quality) : null;
        const tiny = val < 1 || (quality != null && quality < 1e17);
        if (tiny) {
          if (!trustTiny.has(issuer)) trustTiny.set(issuer, new Set());
          trustTiny.get(issuer).add(t.Account);
        }
      }
    } else if (type === "NFTokenAcceptOffer") {
      // Nullwert-Burst: AcceptOffer, dessen betroffene NFTokenOffer-Nodes Amount '0' tragen.
      if (acceptsWithZeroValue(m)) acct(t.Account).acceptZero += 1;
    } else if (type === "EscrowCreate" || type === "CheckCreate") {
      const d = dropsOf(t.Amount);
      const dest = t.Destination;
      if (dest && d != null && d <= c.thresholds.dustDrops && isFresh(dest, c, now)) {
        acct(t.Account).escrowDests.add(dest);
      }
    }
  }

  // ---------- Burst-Regeln (ledger-aggregiert) ----------
  for (const [account, a] of agg) {
    if (c.benignAccounts.has(account)) continue;

    // dusting: >= 3 verschiedene Mini-Zahlungsziele desselben Senders ODER
    // >= 2 Mini-Zahlungen an frische Ziele (fpGuard: eine einzelne Mini-
    // Zahlung an ein frisches Konto ist benign).
    const tinyDests = new Set();
    for (const o of a.out) if (o.drops <= c.thresholds.dustDrops) tinyDests.add(o.dest);
    if (tinyDests.size >= 3 || a.freshTiny.size >= 2) {
      const note = tinyDests.size >= 3
        ? `${tinyDests.size} Mini-XRP-Zahlungen an verschiedene Ziele in einem Ledger.`
        : `${a.freshTiny.size} Mini-XRP-Zahlungen an frische Ziele in einem Ledger.`;
      findings.push({ ruleId: "dusting", severity: "suspect", address: account, note });
    }

    // drainer-sweep: frisch finanziert -> >= sweepRatio an EIN Ziel
    // fpGuard (HIGH-Fix): die frühere Variante 2 (>= 3 Futter-Zahlungen +
    // beliebige ausgehende Zahlung OHNE Sweep-Ratio) labelte harmlose frische
    // Konten als malicious — entfernt. Ein Fund verlangt immer, dass die
    // ausgehende Zahlung >= sweepRatio des Kontostands erreicht.
    if (isFresh(account, c, now)) {
      const base = a.inXrp > 0 ? a.inXrp : 0;
      const sweep = a.out.find((o) => {
        const ref = o.prevBal != null ? o.prevBal : base;
        return ref > 0 && o.drops >= c.thresholds.sweepRatio * ref;
      });
      const distinctOut = new Set(a.out.map((o) => o.dest));
      if (sweep && distinctOut.size >= 1 && (a.inXrp > 0 || a.inDust >= 3)) {
        findings.push({ ruleId: "drainer-sweep", severity: "malicious", address: account, note: `Frisch finanziert und ${Math.round((sweep.drops / (sweep.prevBal ?? a.inXrp)) * 100)} % an ein Ziel abgeräumt.` });
      }
    }

    // offer-spam: >= 3 OfferCreate ohne einzigen Fill
    if (a.offers >= 3 && a.offerFills === 0) {
      findings.push({ ruleId: "offer-spam", severity: "info", address: account, note: `${a.offers} OfferCreate ohne Fill in einem Ledger.` });
    }

    // fake-nft-fraud Null-Burst: >= 10 AcceptOffer zu 0
    // fpGuard: gelegentliche Gratis-Claims legitimer Sammlungen sind benign;
    // Sybil-/Farming-Muster treiben große Null-Accept-Bursts pro Ledger.
    if (a.acceptZero >= 10) {
      findings.push({ ruleId: "fake-nft-fraud", severity: "suspect", address: account, note: `${a.acceptZero} NFTokenAcceptOffer ohne Zahlung in einem Ledger.` });
    }

    // escrow-check-bait Burst: >= 3 frische Ziele
    if (a.escrowDests.size >= 3) {
      findings.push({ ruleId: "escrow-check-bait", severity: "suspect", address: account, note: `${a.escrowDests.size} Escrow/Check-Köder an verschiedene frische Ziele.` });
    }

    // payment-burst: >= 5 Ziele UND (>= 3 winzige Zahlungen ODER knownBad-Kante)
    // fpGuard: frische Ziele allein sind kein Fund — legitime Zahlungen an
    // neue Konten (Lohn, Kauf, Startguthaben) sind benign.
    if (a.payDests.size >= 5 && (tinyDests.size >= 3 || a.payKnownBad)) {
      findings.push({ ruleId: "payment-burst", severity: "suspect", address: account, note: `${a.payDests.size} Zahlungen an verschiedene Ziele, davon ${tinyDests.size} winzig (Airdrop-Verteilungsmuster).` });
    }
  }

  // airdrop-trustset-spam: Issuer erhält im selben Ledger winzige Limits von
  // >= 5 verschiedenen Konten (Massenmuster von Fake-Airdrops).
  for (const [issuer, accounts] of trustTiny) {
    if (accounts.size >= 5) {
      findings.push({ ruleId: "airdrop-trustset-spam", severity: "suspect", address: issuer, note: `${accounts.size} TrustSets mit winzigem Limit von verschiedenen Konten auf Issuer ${shortAddr(issuer)} in einem Ledger.` });
    }
  }

  const deduped = dedupeFindings(findings);
  return { findings: deduped, stats: { txs: txs.length, findings: deduped.length } };
}
