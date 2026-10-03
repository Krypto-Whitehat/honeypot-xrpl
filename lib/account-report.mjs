// lib/account-report.mjs — Profiling-Report einer XRPL-Adresse (pure ESM).
//
// WIRD IMPORTIERT VON:
//   - api/account-report.js (Vercel-Function / lokale Bridge) — einziger Aufrufer.
//
// HARTEN GRENZEN (wie lib/detector.mjs / lib/cluster.mjs):
//   - pure ESM, KEINE npm-Imports, KEIN fs/net, kein Buffer.
//   - deterministisch: kein Date.now() und keine Uhrzeit in Vergleichspfaden;
//     alle Ausgaben sortiert (Kontakte, Muster, Evidenz). Die Engine
//     (analyzeLedger) nutzt intern Date.now() für Frische-Regeln — das ist
//     Bestandsverhalten; dieser Report vergleicht selbst keine Uhrzeiten.
//   - KEINE Secrets, KEINE Köder-Adressen. Die Anzeige-/Köder-Filterung ist
//     Sache der UI (ctx-Gates aus app.js), die Serverseite filtert Köder
//     vor dem Aufruf (generische 400, kein Oracle).
//
// SIGNATUR (Spec):
//   buildAccountReport(input) -> Report
//   input = { address, network, entries, threatsByAddress, truncated,
//             checkedTxCount, hint, knownBad, firstSeenAt, history,
//             clusterFirstSeenAt }
//     - entries: account_tx-Entries in {tx_json|tx, close_time_iso}-Form
//       (unvalidierte Entries mit validated === false werden wie im Bestand
//       übersprungen, siehe lib/threats-service.mjs:253).
//     - threatsByAddress: Map adresse -> threat {risk, reason, firstSeen,
//       sources[]} (plain Objects werden normalisiert; ALLE gelisteten
//       Adressen steuern knownBad — siehe TRADE-OFF oben).
//     - knownBad/firstSeenAt/history (optional): Engine-ctx aus
//       buildCheckCtx (lib/threats-service.mjs) — knownBad:Set,
//       firstSeenAt:Map, history:Map (Cross-Ledger-Gedächtnis wie
//       server/index.mjs:624,640 / api/advance.js:393,421). Ohne Übergabe:
//       sicherer Default (leer) — der Report läuft wie bisher.
//     - clusterFirstSeenAt (optional): Map adresse -> Epoch-ms persistierter
//       Cluster-firstSeens (Zusatz-Seed für Frische-Regeln).
//   Report = { address, network, checkedTxCount, truncated, selfListed,
//              verdict, contacts[<=50], score, scoreBreakdown, criteria,
//              patterns, role, roleMetrics, zusammenfassung, eligibility,
//              eligibilityReason, hint, disclaimers }
//
// BEWERTUNG (bewusst konservativ, kein Schuldnachweis):
//   - Score = max(0, 100 − 15·distinct malicious-Gegenparteien
//                        −  5·distinct suspect-Gegenparteien
//                        − 10 falls selfListed). Distinct über ALLE analysierten
//     Entries (nicht nur die 50 angezeigten Kontakte).
//   - verdict: selfListed -> 'bad'; sonst Kontakt zu gelisteter Adresse ->
//     'contact'; sonst VALIDIERTE, analysierte Entries > 0 -> 'clean'; sonst
//     'unknown' (Semantik wie lib/threats-service.mjs:277, erweitert um 'bad').
//     checkedTxCount (reines Abrufefenster, inkl. validated===false) trägt das
//     verdict NICHT: Sind alle abgerufenen Entries unvalidiert, wurde nichts
//     analysiert und 'clean'/Score 100 wäre vorgetäuschte Sicherheit
//     (Befund 2026-09-29).
//   - verdict 'unknown' (keine Daten) bekommt KEINEN Score (null) — 100 Punkte
//     auf leerer Datenbasis wären vorgetäuschte Sicherheit (Anti-Concealment).
//
// DOKUMENTIERTES TRADE-OFF ('malicious by listing', Runde 3): knownBad und
// firstSeenAt decken jetzt ALLE gelisteten Adressen ab (nicht nur
// risk 'malicious') — die merged Wissensschicht (getThreatKnowledge) macht
// alle in data/history.json persistierten Cluster-Members zu knownBad, weil
// history severity 'malicious' für JELEN Cluster erzwingt (lib/history.mjs:187).
// Ein known-bad-hit auf einer Gegenpartei ist dann Kuratierungs-Erbgut,
// begrenzt nur durch den Exchange-Registry-Ausschluss (im Resolver,
// lib/threats-service.mjs buildCheckCtx) und die config-Whitelists
// (benign_issuers/benign_accounts, lib/detector.mjs:326). Bewusste Angleichung
// an die Live-Engine (server/index.mjs:628-633, api/advance.js buildCtx).
// Peeling-Ketten (Neu): detectPeelingChains läuft jetzt auch im Check —
// 'peeling-chain' erscheint in patterns genau dann, wenn die GEPRÜFTE
// Adresse Seed oder geflaggter Endpunkt einer Kette ist (in chain.addresses,
// aber nicht, wenn sie nur Brückenknoten chain.bridges ist — cluster.mjs:904).
// Schwellen sind die bestehenden PEELING_THRESHOLDS 0.6/0.95/minHops 3/
// dustDrops 100 (cluster.mjs:659-664); 'peeling-chain' ist Katalogregel
// detector.mjs:73 (severity 'suspect').

import { analyzeLedger } from "./detector.mjs";
import { txRecordFromEntry, buildClusterGraph, detectPeelingChains } from "./cluster.mjs";

// ---------- feste deutsche Disclaimers (Pflicht-Block der UI) ----------
export const ACCOUNT_REPORT_DISCLAIMERS = [
  "Die Bewertung ist eine Heuristik über maximal die letzten 300 Transaktionen — ältere Kontakte und Muster sind nicht erfasst.",
  "Rollen und Muster sind Heuristiken (Ein-/Ausgrad, Geldfluss) — kein Schuldnachweis, keine Rechts- oder Haftaussage.",
  "Die Eligibility-Einschätzung ist eine Heuristik — die Entscheidung liegt beim Off-Ramp-Anbieter.",
  "Die abgefragte Adresse wird nicht gespeichert.",
];

const CONTACTS_MAX = 50;
const MALICIOUS_PENALTY = 15; // je distinct malicious-Gegenpartei
const SUSPECT_PENALTY = 5;    // je distinct suspect-Gegenpartei
const SELF_LISTED_PENALTY = 10;

// ---------- Gegenparteien (SEMANTIK 1:1 aus dem Bestand) ----------
// Diese interne Kopie folgt exakt server/index.mjs:188-214 und
// lib/threats-service.mjs:210-234 (beide Bestandsorte sind Eigentumssperre
// und werden hier nicht angetastet). Änderungen an der Gegenpartei-Semantik
// MÜSSEN an allen drei Stellen synchron erfolgen.
function counterpartiesOf(tx, addr) {
  const out = [];
  const add = (a, dir, note) => {
    if (a && a !== addr) out.push({ address: a, dir, note });
  };
  const type = tx.TransactionType;
  if (type === "Payment") {
    if (tx.Destination === addr) add(tx.Account, "eingehend", "Zahlung erhalten von");
    if (tx.Account === addr) add(tx.Destination, "ausgehend", "Zahlung gesendet an");
  } else if (type === "TrustSet") {
    const issuer = tx.LimitAmount?.issuer;
    if (tx.Account === addr) add(issuer, "eingehend", "Trustline zu Issuer eingerichtet");
    if (issuer === addr) add(tx.Account, "ausgehend", "Trustline von dieser Adresse angefragt");
  } else if (type === "OfferCreate" || type === "OfferCancel") {
    if (tx.Account === addr) add(tx.LimitAmount?.issuer, "ausgehend", "DEX-Order (Issuer)");
    else add(tx.Account, "eingehend", "DEX-Order dieser Adresse");
  } else if (type === "EscrowCreate" || type === "CheckCreate" || type === "PaymentChannelCreate") {
    if (tx.Account === addr) add(tx.Destination, "ausgehend", `${type} gesendet an`);
    if (tx.Destination === addr) add(tx.Account, "eingehend", `${type} erhalten von`);
  } else {
    if (tx.Account === addr) add(tx.Destination, "ausgehend", type);
    else add(tx.Account, "eingehend", type);
  }
  return out;
}

// Zeit-Extraktion wie lib/threats-service.mjs:93-101 (timeOf).
function timeOf(entry) {
  const tx = entry.tx_json ?? entry.tx ?? entry;
  return (
    entry.close_time_iso ??
    (typeof tx?.date === "number" && Number.isFinite(tx?.date)
      ? new Date((tx.date + 946684800) * 1000).toISOString()
      : null)
  );
}

// ---------- Normalisierung / deterministische Vergleichshelfer ----------
function toThreatMap(v) {
  if (v instanceof Map) return v;
  if (v && typeof v === "object" && !Array.isArray(v)) return new Map(Object.entries(v));
  return new Map();
}

function cmpStr(a, b) {
  return a < b ? -1 : a > b ? 1 : 0;
}

// Kontakte deterministisch: neueste zuerst (Epoch-ms), null-Zeiten ans Ende,
// dann Gegenpartei/Tx-Typ/Richtung/Notiz aufsteigend — stabil gegen jede
// Eingabereihenfolge der Entries.
function cmpContact(a, b) {
  const ea = a.time ? Date.parse(a.time) : null;
  const eb = b.time ? Date.parse(b.time) : null;
  const na = ea != null && Number.isFinite(ea) ? ea : null;
  const nb = eb != null && Number.isFinite(eb) ? eb : null;
  if (na !== null || nb !== null) {
    if (na === null && nb !== null) return 1;
    if (na !== null && nb === null) return -1;
    if (na !== null && nb !== null && na !== nb) return nb - na; // desc
  }
  return (
    cmpStr(a.counterparty ?? "", b.counterparty ?? "") ||
    cmpStr(a.txType ?? "", b.txType ?? "") ||
    cmpStr(a.direction ?? "", b.direction ?? "") ||
    cmpStr(a.note ?? "", b.note ?? "")
  );
}

function epochOfIso(iso) {
  if (typeof iso !== "string" || !iso) return null;
  const ms = Date.parse(iso);
  return Number.isFinite(ms) ? ms : null;
}

// ---------- Report ----------
export function buildAccountReport(input) {
  const address = String(input?.address ?? "");
  const network = input?.network ?? null;
  const entriesAll = Array.isArray(input?.entries) ? input.entries : [];
  const truncated = Boolean(input?.truncated);
  const checkedTxCount = Number.isFinite(input?.checkedTxCount)
    ? Number(input.checkedTxCount)
    : entriesAll.length;
  const hint = typeof input?.hint === "string" && input.hint ? input.hint : null;
  const threatsByAddress = toThreatMap(input?.threatsByAddress);

  const selfListed = threatsByAddress.has(address);
  const selfReason = selfListed ? String(threatsByAddress.get(address)?.reason ?? "").trim() : "";

  // Unvalidierte Entries überspringen (wie lib/threats-service.mjs:253 /
  // server/index.mjs:251).
  const entries = entriesAll.filter((e) => e && typeof e === "object" && e.validated !== false);

  // --- (1) Kontakte zu gelisteten Adressen (Threat-Kontakte) ---
  // contacts bleiben strikt DIREKTE Gegenparteien (counterpartiesOf) —
  // entity-verknüpfte Nicht-Gegenparteien fließen nie ein. Additiv:
  // contacts[].source = Wissensquelle der gelisteten Gegenpartei
  // ('bait'|'history'|'flow-state'|'entity'), top-level knowledgeSources =
  // Union aller Quellen. criteria/scoreBreakdown-Struktur/-Labels bleiben
  // unverändert (deepEqual-Asserts in account-report.test.mjs).
  const sourceSet = new Set();
  const contactsAll = [];
  for (const entry of entries) {
    const tx = entry.tx_json ?? entry.tx ?? entry;
    if (!tx || typeof tx !== "object") continue;
    const time = timeOf(entry);
    for (const cp of counterpartiesOf(tx, address)) {
      const t = threatsByAddress.get(cp.address);
      if (!t) continue;
      const sources = Array.isArray(t?.sources) && t.sources.length ? t.sources : [];
      const source = sources[0] ?? "bait";
      for (const s of sources) sourceSet.add(s);
      contactsAll.push({
        txType: typeof tx.TransactionType === "string" ? tx.TransactionType : null,
        time,
        direction: cp.dir,
        note: cp.note,
        counterparty: cp.address,
        risk: t.risk ?? "suspect",
        source,
      });
    }
  }
  if (selfListed) {
    const ownSources = threatsByAddress.get(address)?.sources;
    for (const s of Array.isArray(ownSources) ? ownSources : []) sourceSet.add(s);
  }
  const knowledgeSources = [...sourceSet].sort(cmpStr);
  contactsAll.sort(cmpContact);
  const contacts = contactsAll.slice(0, CONTACTS_MAX);

  // Distinct Risiko-Gegenparteien über ALLE Kontakte (Score-Basis vor dem Cap).
  const maliciousCounterparties = new Set();
  const suspectCounterparties = new Set();
  for (const c of contactsAll) {
    if (c.risk === "malicious") maliciousCounterparties.add(c.counterparty);
    else if (c.risk === "suspect") suspectCounterparties.add(c.counterparty);
  }
  const maliciousList = [...maliciousCounterparties].sort(cmpStr);
  const suspectList = [...suspectCounterparties].sort(cmpStr);

  // --- (2) Muster-Funde über die Detektor-Engine (single source of truth) ---
  // knownBad/firstSeenAt decken ALLE gelisteten Adressen ab (nicht nur
  // risk 'malicious' — Angleichung an server/index.mjs:628-633 und
  // api/advance.js:386-388). Der Exchange-Registry-Ausschluss ist im
  // Resolver verdrahtet: getThreatKnowledge bereinigt die Wissens-Map selbst
  // (lib/threats-service.mjs, Schicht-Filter nach (4)) — threatsByAddress
  // erreicht diese Datei daher bereits registry-frei; buildCheckCtx filtert
  // zusätzlich den Engine-ctx (Defense-in-Depth). input.knownBad/
  // input.firstSeenAt (Engine-ctx aus buildCheckCtx) werden mit den
  // Threat-eigenen Werten vereinigt; input.history ist das Cross-Ledger-
  // Gedächtnis (tinyDests-Union/Sweep-Referenz, wie server/index.mjs:624,640).
  const knownBad = new Set();
  const firstSeenAt = new Map();
  for (const [addr, t] of threatsByAddress) {
    if (!addr) continue;
    knownBad.add(addr);
    const ms = epochOfIso(t?.firstSeen);
    if (ms !== null) firstSeenAt.set(addr, ms);
  }
  for (const addr of input?.knownBad instanceof Set ? input.knownBad : []) {
    if (typeof addr === "string" && addr) knownBad.add(addr);
  }
  const seedFirstSeen = (map) => {
    if (!(map instanceof Map)) return;
    for (const [addr, ms] of map) {
      if (typeof addr !== "string" || !addr) continue;
      const n = Number(ms);
      if (Number.isFinite(n) && !firstSeenAt.has(addr)) firstSeenAt.set(addr, n);
    }
  };
  seedFirstSeen(input?.firstSeenAt);
  seedFirstSeen(input?.clusterFirstSeenAt);
  const history = input?.history instanceof Map ? input.history : new Map();
  const detected = analyzeLedger({ transactions: entries }, { knownBad, firstSeenAt, history });
  // txRecords einmal für Muster (Peeling) und Rolle: txRecordFromEntry(entry,
  // null) — account_tx-Entries tragen close_time_iso selbst (Fallback nicht
  // nötig).
  const txRecords = entries.map((e) => txRecordFromEntry(e, null)).filter(Boolean);
  // Nur Funde AUF der geprüften Adresse werden als Muster berichtet (Kontakte
  // zu gelisteten Adressen tragen ihren eigenen known-bad-hit-Fund).
  const patternSet = new Set(
    detected.findings.filter((f) => f?.address === address).map((f) => String(f.ruleId))
  );
  // Peeling-Ketten (Neu, Angleichung an lib/ledger-walk.mjs:164 — die Engine-
  // Fähigkeit existierte, fehlte nur im Check): detectPeelingChains über die
  // txRecords des Fensters, flaggedAddresses = detected.findings (Vertrag der
  // Engine: Seeds sind geflaggte Adressen, Ketten enden an geflaggten
  // Endpunkten — Regression lib/cluster.test.mjs:610).
  // Attributionsregel: 'peeling-chain' in patterns GENAU DANN, wenn die
  // geprüfte Adresse Seed oder geflaggter Endpunkt ist — also in
  // chain.addresses, aber NICHT, wenn sie nur Brückenknoten (chain.bridges,
  // cluster.mjs:904 — Brücken sind per Definition ungeflaggt) ist. Schwellen:
  // bestehende PEELING_THRESHOLDS (cluster.mjs:659-664, nicht überschrieben).
  const peelingChains = detectPeelingChains(txRecords, detected.findings);
  for (const ch of peelingChains) {
    const inChain = Array.isArray(ch?.addresses) && ch.addresses.includes(address);
    const isBridge = Array.isArray(ch?.bridges) && ch.bridges.includes(address);
    if (inChain && !isBridge) {
      patternSet.add("peeling-chain");
      break;
    }
  }
  const patterns = [...patternSet].sort(cmpStr);

  // --- (3) Rolle aus der Cluster-Engine (nur für das geprüfte Fenster) ---
  // buildClusterGraph mit minClusterSize:1 und maxEdges:2000 (verifiziert
  // lib/cluster.mjs:210-211; minClusterSize:1 ist valide — Math.max(1, …)).
  // Es werden ALLE Engine-Finde des Fensters übergeben (wie app.js
  // rebuildClusterGraph), weil die Kantenregel der Cluster-Engine
  // Fund-getrieben ist — ohne Fund keine Kante, ohne Kante keine Rolle.
  // Ist die Adresse nicht im Graphen, wird NICHT geraten. txRecords ist
  // dieselbe Liste, die (2) für die Peeling-Ketten verwendet.
  const cg = buildClusterGraph(txRecords, detected.findings, { minClusterSize: 1, maxEdges: 2000 });
  const node = (Array.isArray(cg?.nodes) ? cg.nodes : []).find((n) => n?.id === address) ?? null;
  const role = node ? node.role : null;
  const roleMetrics = node
    ? { degreeIn: node.degreeIn, degreeOut: node.degreeOut, inDrops: node.inDrops, outDrops: node.outDrops }
    : null;

  // --- (4) verdict + Score (exakte Formel, siehe Dateikopf) ---
  // 'clean' erfordert analysierte Entries (validated !== false), NICHT das
  // ungefilterte checkedTxCount — sonst wäre ein Konto, dessen gesamte
  // abgerufene Historie unvalidiert ist, „sauber" mit Score 100 und
  // Off-Ramp-Eligibility 'ok', obwohl null Transaktionen analysiert wurden
  // (Befund 2026-09-29).
  const verdict = selfListed
    ? "bad"
    : contactsAll.length > 0
      ? "contact"
      : entries.length > 0
        ? "clean"
        : "unknown";

  let score = null;
  let scoreBreakdown = [];
  let criteria = [];
  if (verdict !== "unknown") {
    const abzugMalicious = MALICIOUS_PENALTY * maliciousList.length;
    const abzugSuspect = SUSPECT_PENALTY * suspectList.length;
    const abzugSelf = selfListed ? SELF_LISTED_PENALTY : 0;
    score = Math.max(0, 100 - abzugMalicious - abzugSuspect - abzugSelf);
    scoreBreakdown = [
      {
        kriterium: "Kontakte zu bekannten Malicious-Adressen (verschiedene Gegenparteien)",
        wert: maliciousList.length,
        abzug: abzugMalicious,
      },
      {
        kriterium: "Kontakte zu Verdachts-Adressen (verschiedene Gegenparteien)",
        wert: suspectList.length,
        abzug: abzugSuspect,
      },
      {
        kriterium: "Adresse selbst in der Bedrohungsliste gelistet",
        wert: selfListed ? "ja" : "nein",
        abzug: abzugSelf,
      },
    ];
    criteria = [
      {
        id: "known-bad-contacts",
        label: "Kontakte zu bekannten Malicious-Adressen",
        erfuellt: maliciousList.length > 0,
        gewicht: MALICIOUS_PENALTY,
        abzug: abzugMalicious,
        evidence: maliciousList,
      },
      {
        id: "suspect-contacts",
        label: "Kontakte zu Verdachts-Adressen",
        erfuellt: suspectList.length > 0,
        gewicht: SUSPECT_PENALTY,
        abzug: abzugSuspect,
        evidence: suspectList,
      },
      {
        id: "self-listed",
        label: "Adresse selbst in der Bedrohungsliste gelistet",
        erfuellt: selfListed,
        gewicht: SELF_LISTED_PENALTY,
        abzug: abzugSelf,
        evidence: selfListed ? (selfReason ? [selfReason] : [address]) : [],
      },
    ];
  }

  // --- (6) Eligibility (Heuristik; Entscheidung liegt beim Anbieter) ---
  let eligibility;
  let eligibilityReason;
  if (verdict === "unknown") {
    eligibility = "unknown";
    eligibilityReason = "Nicht bewertbar — keine oder unvollständige Daten.";
  } else if (score >= 85 && verdict === "clean" && !selfListed) {
    eligibility = "ok";
    eligibilityReason = "Voraussichtlich unproblematisch für Off-Ramps (heuristisch).";
  } else {
    eligibility = "review";
    eligibilityReason = "Prüfungswürdig — Ablehnung oder manuelle Prüfung durch den Anbieter ist wahrscheinlich.";
  }

  // --- Zusammenfassung (deterministischer deutscher Satz) ---
  const zusammenfassung = buildSummary({
    verdict,
    score,
    maliciousList,
    suspectList,
    patterns,
  });

  return {
    address,
    network,
    checkedTxCount,
    truncated,
    selfListed,
    verdict,
    contacts,
    score,
    scoreBreakdown,
    criteria,
    patterns,
    role,
    roleMetrics,
    knowledgeSources,
    zusammenfassung,
    eligibility,
    eligibilityReason,
    hint,
    disclaimers: [...ACCOUNT_REPORT_DISCLAIMERS],
  };
}

function buildSummary({ verdict, score, maliciousList, suspectList, patterns }) {
  if (verdict === "unknown") return "Nicht bewertbar — keine oder unvollständige Daten.";
  const parts = [`Score ${score} von 100.`];
  if (verdict === "bad") parts.push("Die Adresse ist selbst in der Bedrohungsliste gelistet.");
  if (maliciousList.length > 0) {
    parts.push(`${maliciousList.length} verschiedene Gegenpartei(en) mit bekanntem Malicious-Status.`);
  }
  if (suspectList.length > 0) {
    parts.push(`${suspectList.length} verschiedene Gegenpartei(en) mit Verdachts-Status.`);
  }
  if (verdict === "clean" && maliciousList.length === 0 && suspectList.length === 0) {
    parts.push("Keine Kontakte zu gelisteten Adressen im geprüften Fenster.");
  }
  if (patterns.length > 0) parts.push(`Muster-Funde: ${patterns.join(", ")}.`);
  return parts.join(" ");
}
