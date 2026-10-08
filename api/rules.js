// Vercel Function: GET /api/rules — Regelkatalog für die Regelfilter-UI der
// Live-Ansicht. Identische Katalogquelle (lib/detector.mjs ruleCatalog()) wie
// im Browser — single source of truth.
//
// Live-Audit 2026-10-06 ergänzt (budgetneutral: +0 Requests, +0 Functions,
// Payload +~1,5 KB, maxDuration unverändert):
//  - thresholds je Regel: direkte Re-Exporte der Engine-Konstanten (IMPORTS,
//    keine abgeschriebenen Kopien) — "Regeln mit Schwellen" ist damit
//    maschinenlesbar über die API prüfbar.
//  - V5 verifiedFresh als verifiedFreshGapLedgers an drainer-sweep (Zweitbeleg,
//    nie Fundquelle); V4 Motiv-Zähler als MOTIF_THRESHOLDS an wash-cycle
//    (Cluster-Regel, lib/cluster.mjs motifCounters). Beide tragen bewusst
//    keine eigenen Katalog-IDs — deshalb waren sie in /api/rules vorher
//    unsichtbar.
//  - Deploy-Nachweis im Response-Header x-deploy-commit (VERCEL_GIT_COMMIT_SHA,
//    von Vercel in Functions automatisch gesetzt) — der Commit-Claim ist ohne
//    eigenen Version-Endpoint gegen die Live-Deployment prüfbar.
import { ruleCatalog, DEFAULT_THRESHOLDS, MARKET_THRESHOLDS } from "../lib/detector.mjs";
import { PEELING_THRESHOLDS, MOTIF_THRESHOLDS } from "../lib/cluster.mjs";
import { ENTITY_FRESH_THRESHOLDS } from "../lib/entity-resolve.mjs";

export const maxDuration = 30;

// Schwellen je Regel-ID. Werte ausschließlich aus den Konstanten bzw. den in
// der Engine dokumentierten Literalkonditionen (lib/detector.mjs Burst-Block,
// lib/cluster.mjs, lib/entity-resolve.mjs). Regeln ohne numerische Schwellen
// (known-bad-hit: Registry-Treffer; memo-phishing: Mustererkennung) tragen
// bewusst KEIN thresholds-Feld.
export const THRESHOLDS_BY_RULE = {
  "dusting": {
    dustDrops: DEFAULT_THRESHOLDS.dustDrops, // Zahlung < dustDrops gilt als 'winzig'
    minTinyDests: 3, // ODER-Pfad: >= 3 verschiedene Mini-Ziele (Union über das Fenster)
    minFreshTiny: 2, // >= 2 Mini-Zahlungen an frische Ziele
  },
  "wash-self-transfer": {
    minSelfPays: 3, // >= 3 Selbstzahlungen (Account === Destination) je Ledger
  },
  "drainer-sweep": {
    sweepRatio: DEFAULT_THRESHOLDS.sweepRatio,             // >= 90 % des Stands an EIN Ziel
    minAccountAgeMin: DEFAULT_THRESHOLDS.minAccountAgeMin, // Frische-Fenster in Minuten
    minDustInflows: 3, // >= 3 Mini-Fütterungen gelten als Fütterung
    // V5 verifiedFresh (Zweitbeleg, nie alleinige Fundquelle): Entity-Snapshot
    // mit letzter Aktivität <= maxGapLedgers (~24 h) hebt suspect -> malicious.
    verifiedFreshGapLedgers: ENTITY_FRESH_THRESHOLDS.maxGapLedgers,
  },
  "airdrop-trustset-spam": {
    minAccounts: 5, // >= 5 Konten mit winzigem Limit auf denselben Issuer je Ledger
  },
  "fake-nft-fraud": {
    minZeroAccepts: 10,     // >= 10 NFTokenAcceptOffer zu 0 je Ledger
    minOffersPerTarget: 5,  // >= 5 NFTokenCreateOffer desselben Kontos auf dasselbe Ziel
  },
  "escrow-check-bait": {
    minFreshDests: 3, // >= 3 verschiedene frische Ziele (nur mit Phishing-Memo)
    dustDrops: DEFAULT_THRESHOLDS.dustDrops,
  },
  "payment-burst": {
    minDests: 5,          // >= 5 verschiedene Zahlungsziele
    minTiny: 3,           // UND >= 3 winzige Zahlungen (ODER knownBad-Kante)
    tinyMajoritySlack: 2, // winzige Ziele stellen die Mehrheit (tinyDests >= payDests - 2)
  },
  "offer-spam": {
    minOffers: 10, // >= 10 OfferCreate ohne einzigen Fill je Ledger
    maxFills: 0,
  },
  "peeling-chain": { ...PEELING_THRESHOLDS }, // minRatio/maxRatio/minHops/dustDrops
  "wash-cycle": { ...MOTIF_THRESHOLDS },      // V4 Motiv-Zähler (Gather-Scatter/Zyklen)
  // Kritik-Runde 3 (Backend-Tranche T1.5): die drei Market-Regeln (AMM/DEX)
  // tragen ihre Schwellen als DIRECTEN Re-Export aus MARKET_THRESHOLDS
  // (lib/detector.mjs) — keine abgeschriebenen Kopien. MOTIF_THRESHOLDS ist
  // hier der FALSCHE Ort: die Market-Schwellen leben in der Detector-Pipeline,
  // nicht in der Cluster-Motiv-Maschinerie. Je Regel nur die Felder, die ihre
  // Bewertung tatsächlich liest (maschinenlesbar, keine Irreführung durch
  // fremde Schlüssel).
  "amm-wash-swap": {
    minFillsPerSide: MARKET_THRESHOLDS.washMinFillsPerSide,   // >= 2 Fills je Richtung (Refund-Guard)
    conserveMin: MARKET_THRESHOLDS.washConserveMin,            // Volumenerhalt >= 90 %
    maxDrift: MARKET_THRESHOLDS.washMaxDrift,                  // Netto-Positionsdrift <= 10 %
    windowLedgers: MARKET_THRESHOLDS.washWindowLedgers,        // Fenster <= 150 Ledger
    minNotionalDrops: MARKET_THRESHOLDS.washMinNotionalDrops,  // >= 1 XRP je Richtung
  },
  "thin-pool-exploit": {
    minPairSamples: MARKET_THRESHOLDS.thinMinPairSamples,      // >= 5 Fills desselben Pairs im Fenster
    minFillsPerAccount: MARKET_THRESHOLDS.thinMinFillsPerAccount, // >= 2 Fills je Konto/Pair
    deviationMin: MARKET_THRESHOLDS.thinDeviationMin,          // >= 25 % Abweichung vom Median
    windowLedgers: MARKET_THRESHOLDS.thinWindowLedgers,        // Fenster <= 150 Ledger
    minNotionalDrops: MARKET_THRESHOLDS.thinMinNotionalDrops,  // >= 10 XRP Notional
  },
  "spoof-offer-cycle": {
    maxCancelLedgers: MARKET_THRESHOLDS.spoofMaxCancelLedgers,           // Create->Cancel <= 75 Ledger
    minCycles: MARKET_THRESHOLDS.spoofMinCycles,                         // >= 3 Zyklen je BookDirectory
    minPriceLevels: MARKET_THRESHOLDS.spoofMinPriceLevels,               // >= 2 BookNode-Preislevel
    windowLedgers: MARKET_THRESHOLDS.spoofWindowLedgers,                 // Fenster <= 300 Ledger
    minCancelNotionalDrops: MARKET_THRESHOLDS.spoofMinCancelNotionalDrops, // >= 100 XRP Cancel-Notional
  },
  "amm-pool-drain": {
    minShare: MARKET_THRESHOLDS.ammDrainMinShare,                        // >= 50 % des XRP-Pools in einer Tx
    minPoolDrops: MARKET_THRESHOLDS.ammDrainMinPoolDrops,                // Pool vorher >= 10 XRP
  },
};

export default async function handler(req, res) {
  try {
    res.setHeader("x-deploy-commit", process.env.VERCEL_GIT_COMMIT_SHA || "unknown");
    res.status(200).json(
      ruleCatalog().map((rule) => {
        const thresholds = THRESHOLDS_BY_RULE[rule.id];
        return thresholds ? { ...rule, thresholds } : rule;
      }),
    );
  } catch {
    res.status(500).json({ error: "Regelkatalog nicht verfügbar." });
  }
}
