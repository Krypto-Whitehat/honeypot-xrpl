// lib/cluster.mjs — Cluster-Graph-Engine über analysierte Live-Ledger-Tx.
//
// HARTEN GRENZEN (identisch zu lib/detector.mjs:9-10):
//   - pure ESM, KEINE npm-Imports, KEIN Node-Global `Buffer` (Browser-Pfad).
//   - KEINE Secrets, KEINE Köder-Adressen in dieser Datei. Defanging ist
//     Sache der UI (public/app.js defang/shortAddr).
//   - deterministisch: kein Date.now(), keine Map-Iterierungsordnung in
//     Ausgaben; alle Ausgaben sortiert.
//
// EXPORT-VERTRAG:
//   buildClusterGraph(txRecords, findings, opts) -> { clusters, nodes, edges }
//   txRecordFromEntry(entry, fallbackCloseIso)   -> txRecord | null
//   ROLE_THRESHOLDS                              -> Rollen-Heuristik-Tuning
//
// txRecord: { hash, ledgerSeq, closeTime (ISO-String), type, account,
//             destination (optional), amountDrops (number|null),
//             iouValue (optional {currency, issuer, value}),
//             destinationTag (optional number, normalisiert via
//             lib/tag-identity.mjs — nur wenn das Tx-Feld gültig war),
//             sourceTag (optional number, rein informativ) }
// finding:  { ruleId, severity, address, note (optional) } — exakt wie
//           analyzeLedger sie liefert (lib/detector.mjs).
// Edge:     { from, to, type, amountDrops, txHash, ledgerSeq, closeTime,
//             severity, iouValue (optional),
//             toTag (optional number — NUR wenn opts.multiUserAccounts die
//             Empfänger-Adresse als Börsen-Konto ausweist UND die Tx einen
//             gültigen DestinationTag trägt),
//             fromTag (optional number — SourceTag, rein informativ),
//             transit (optional true — nur gesetzt, nie false; siehe
//             lib/tag-identity.mjs: ≥2 verschiedene Tag-Identitäten am
//             Empfänger-Konto) }
// Cluster:  { id, label, memberAddresses, roles, totalDrops, txCount,
//             distinctAccounts, firstSeen, lastSeen, mainDrainers, collectors,
//             iouFlows }
// role ∈ { 'source', 'drainer', 'collector', 'relay', 'unknown' }
// opts: { maxEdges = 2000, minClusterSize = 2, thresholds?,
//         multiUserAccounts? (Map<adresse, {exchange,...}> aus der
//         Exchange-Registry; Default null -> Verhalten bitgleich ohne Tags) }
// Tag-Grenze (dokumentiert): Tags ändern KEINE Cluster-Topologie, keine
// Rollen, kein Scoring, keine Kanten-Caps — sie sind reine Kanten-Attribute
// (Identitäts-Verfeinerung für Hosted-Accounts). Union-Find, Cluster-Keys
// und Hub-Schnitt bleiben adressbasiert.
//
// False-Positive-Hinweis (dokumentiert): die Rollen sind Heuristik aus
// Ein-/Ausgrad, Fluss und GEFLAGGTEN Gegenparteien — ein harmloser
// Mehrfachempfänger ohne geflaggte Sender ist KEIN collector mehr (Test 16,
// nach der Gegenparteien-Bindung). Der Drainer-FP (benigne Durchleitung mit
// einer Ein-/Ausgangs-Kante) ist durch die distinctIn>=2-Bedingung
// ausgeschlossen (Test 17). Kein Schuldnachweis.
//
// PEELING-KETTEN (detectPeelingChains): die früher dokumentierte Auslassung
// der 2-Hop-Maschinerie ("neues Muster ohne reproduzierten Kampagnen-Fall")
// wird hier ausdrücklich aufgehoben. Die Kantenregel (nur account/destination
// als Endpunkte, :276-277) splittet eine Kette Drainer→Mixer→Mixer→Collector
// in zwei Cluster, wenn ein mittlerer Mixer nicht geflaggt ist — die
// Peeling-Erkennung läuft deshalb über die txRecords (nicht über die
// Cluster-Kanten) und bridgt ungeflaggte Mittelknoten ausdrücklich.
// FP-Schutz (neu begründet): Seeds sind ausschließlich geflaggte Adressen;
// ungeflaggte Brückenknoten werden nur als strikte 1:1-Relays (genau ein
// Eingang, genau ein Ausgang) durchwandert und erhalten NIE eine Rolle und
// NIE severityByAddress — cluster.mjs schreibt Severity nur für Fund-Adressen
// (:465), und der Hub-Schnitt (:327-333) bleibt bestehen. Fundklasse der
// Ketten ist 'suspect' (kein Schuldnachweis). Die Schwellen
// PEELING_THRESHOLDS (0.6/0.95/minHops 3/dustDrops 100) sind ausdrücklich
// Tuning-Defaults OHNE reproduzierten Kampagnen-Fall (cluster.mjs verlangt
// sonst einen).
//
// V1/V2/V3-ERWEITERUNGEN (Strategie 2026-10-06, DFRWS-kalibriert; Quelle:
// Gong/Chow/Yiu/Ting, "Analyzing the peeling chain patterns on the Bitcoin
// blockchain", DFRWS/FSI 2023 — 79 % der Ketten < 24 h, > 50 % < 1 h,
// 63,6 % der Peel-Intervalle <= 10 Blöcke, Peel-Percentage < 1 % bei 71,2 %,
// Auto-Programm-Homogenität, 42,6 % der Ketten mit 2 Runden):
//   - Remainder-Rinne (PEELING_REMAINDER_THRESHOLDS): XRPL-Peel-Analogon
//     "Großrest wandert weiter" — Hop mit out/in >= 0.95 plus BEOBACTETEM
//     kleinen Abgang (<= 1 % des Eingangs) an ein Nicht-Kettenglied.
//   - Cross-Block-Walk (detectPeelingChainsOverEdges + CROSS_BLOCK_PEELING_
//     THRESHOLDS): Kettenwanderung über die akkumulierten Flow-State-Kanten
//     statt Block-Tx — öffnet die Zeitdimension (24-h-Fenster, Hop-Gap-Deckel).
//   - Peel-Fingerprint (peelChainFingerprint + PEELING_FINGERPRINT_THRESHOLDS):
//     Homogenitäts-Score über Fee/Betrag/Intervall/Tag der Hops.
//   - Temporale Metriken (temporalMetrics + TEMPORAL_THRESHOLDS): burst/
//     medianInterarrival/velocity/ageVolume pro Konto — reine Zusatz-Attribute,
//     NIE eine eigene malicious-Quelle (Severity-Enum bleibt
//     'malicious'|'suspect'|'info').
//   - V4 Motiv-Zähler (motifCounters + MOTIF_THRESHOLDS): Gather-Scatter
//     (fanIn ≥ 3 ∧ fanOut ≥ 3 am selben Knoten — note-Attribut, nie Rollen-/
//     Severity-Änderung) und 2-Zykel-Wash-Cycle (A→B ∧ B→A, ≥ 2 Kanten je
//     Richtung, Volumenerhalt min/max ≥ 0.8, 1-h-Fenster, Börsen nie
//     Zykelglied) — kanonische Altman/LAS-GNN-Typologien als deterministische
//     Zähler (keine ML/GNN). GERECHNET ÜBER DEN AKKUMULIERTEN (gekappten,
//     maxClusterEdges) Kantensatz im mergeCluster (lib/ledger-walk.mjs) —
//     NICHT je Block: ein über Blöcke verteilter Zyklus (A→B×2 in Block 1,
//     B→A×2 in Block 2) ist je Block unter cycleMinEdgesPerSide und würde
//     blocklokal nie aufgezeichnet; im Aggregate vereint der akkumulierte
//     Kantensatz ihn (Tick-Schritt-Semantik nach applyCrossBlockPeeling).
//     Fundklasse des Zyklus 'suspect' (Katalog 'wash-cycle', detector.mjs —
//     Maschinerie-Präzedenz peeling-chain); gatherScatter ist reines
//     note-Attribut. Sichtbarkeitsgrenze (dokumentiert): Kanten entstehen nur
//     mit geflaggtem Endpunkt (buildClusterGraph-Kantenregel) — Zyklen
//     zwischen zwei NIE-geflaggten Konten sind unsichtbar (dieselbe Grenze
//     wie Cross-Block-Peeling); blocklokale Selbsttransfers deckt
//     wash-self-transfer ab (detector.mjs).
// DATENPFAD-INVARIANTE (Köderschutz B2, unverändert): alle Erweiterungen
// laufen ausschließlich über den bestehenden bait-gefilterten Eingang — der
// Block-Walk über die txRecords aus fetchBlock (api/advance.js filtert
// Köder-Endpunkte VOR der Analyse still heraus), der Cross-Block-Walk über
// die Flow-State-Kanten (die nie Köder-Endpunkte enthalten, weil der Eingang
// gefiltert war). KEINE neuen Raw-RPC-Pfade, keine zusätzlichen Requests im
// Tick-Budget (Walk-Deckel MAX_WALK_BUDGET 189, api/advance.js; Bilanz 189 +
// 40 + 20 + 1 = 250 <= 250) — V1/V3/V4 sind reine In-Memory-Arithmetik
// (motifCounters O(E) über ≤ maxClusterEdges Kanten), V2 liest tx.Fee aus
// derselben expand-Entry.
// Alle neuen Schwellen sind — wie PEELING_THRESHOLDS — aus DFRWS-Messwerten
// abgeleitete Tuning-Defaults OHNE reproduzierten XRPL-Kampagnen-Fall; der
// Kalibrierungspfad (V7) läuft über die bestehenden Replay-Jobs
// (POST /api/advance mode:'replay') mit dem ADVANCE_BUDGET-Tiefschnitt-Deckel
// MAX_WALK_BUDGET (api/advance.js).

// Tag-Identität (DestinationTag/SourceTag): reine Hilfsfunktionen ohne I/O,
// siehe lib/tag-identity.mjs für die vollen Regeln.
import { normalizeTag, computeTransitFlags } from "./tag-identity.mjs";

// ---------- Rollen-Schwellen (Tuning für Tests, app.js und live-gate) ----------
export const ROLE_THRESHOLDS = {
  sweepRatio: 0.9,        // Drainer: >= 90 % des Eingangs an EIN Ziel abgeführt
                          // (Eingang aus >= 2 verschiedenen Sendern)
  collectorMinIn: 3,      // Collector: >= 3 eingehende Kanten ...
  collectorMaxOut: 1,     // ... von verschiedenen Sendern, max. 1 ausgehende
  sourceMinOut: 3,        // Source: >= 3 ausgehende kleine Kanten
  sourceSmallDrops: 100000, // "klein" = <= 0.1 XRP pro Out-Kante
  relayBalance: 0.5,      // Relay: |in - out| <= 50 % des größeren Werts
};

const ROLE_SET = new Set(["source", "drainer", "collector", "relay", "unknown"]);
const SEVERITY_RANK = { info: 1, suspect: 2, malicious: 3 };

// ---------- Deterministische Vergleichshelfer ----------
function cmpStr(a, b) {
  return a < b ? -1 : a > b ? 1 : 0;
}
// closeTime -> Epoch-ms; null/leer/nicht parsebar -> -1 (Sentinel wie ledgerSeq).
function epochOf(iso) {
  if (typeof iso !== "string" || !iso) return -1;
  const ms = Date.parse(iso);
  return Number.isFinite(ms) ? ms : -1;
}
function cmpEdge(a, b) {
  const la = a.ledgerSeq == null ? -1 : a.ledgerSeq;
  const lb = b.ledgerSeq == null ? -1 : b.ledgerSeq;
  if (la !== lb) return la - lb;
  const h = cmpStr(String(a.txHash ?? ""), String(b.txHash ?? ""));
  if (h !== 0) return h;
  // Gleichstand auch ohne hash UND ledgerSeq: Endpunkte brechen den Fall —
  // sonst entschied die Eingabereihenfolge (Befund 2026-09-29).
  const f = cmpStr(String(a.from ?? ""), String(b.from ?? ""));
  if (f !== 0) return f;
  const t = cmpStr(String(a.to ?? ""), String(b.to ?? ""));
  if (t !== 0) return t;
  // Stufen 5-8 (Befund 2026-09-29): gleiche Endpunkte ohne hash/seq durften
  // nicht vergleichsgleich bleiben — sonst entschied die Eingabereihenfolge.
  // Totalordnung gilt für Kanten, die in einem der sieben Kantenfelder
  // differieren; exakte Duplikate liefern 0, sind aber ununterscheidbar —
  // die Ausgabearrays bleiben bei jeder Eingabereihenfolge identisch.
  const ty = cmpStr(String(a.type ?? ""), String(b.type ?? ""));
  if (ty !== 0) return ty;
  // amountDrops: null sortiert VOR jeder Zahl — auch vor -1, das adversarische
  // Daten (Amount:"-1") über dropsOf erzeugen können. Null und -1 durften NICHT
  // auf denselben Sentinel fallen: Kanten, die nur in amountDrops differieren
  // (null vs. -1), waren vergleichsgleich und die Kantenausgabe entschied die
  // Eingabereihenfolge (Befund 2026-09-29). cmp-Form statt Subtraktion, weil
  // Drops MAX_SAFE_INTEGER überschreiten können und Subtraktion dann ungenau
  // wird.
  const na = a.amountDrops == null;
  const nb = b.amountDrops == null;
  if (na !== nb) return na ? -1 : 1;
  if (!na && a.amountDrops !== b.amountDrops) return a.amountDrops < b.amountDrops ? -1 : 1;
  // closeTime chronologisch (Epoch-ms), nie Rohstring-Lexik:
  // '2026-09-28T10:00:00Z' ist chronologisch VOR '2026-09-28T10:00:00.500Z',
  // lexikalisch danach (Prüfer-Reproduktion 2026-09-29).
  const ea = epochOf(a.closeTime);
  const eb = epochOf(b.closeTime);
  if (ea !== eb) return ea < eb ? -1 : 1;
  // letzte Stufe: Rohstring, damit chronologisch gleiche, aber unterschiedlich
  // formatierte closeTime-Werte ('Z' vs '.000Z' vs '+00:00') deterministisch
  // liegen.
  return cmpStr(String(a.closeTime ?? ""), String(b.closeTime ?? ""));
}

// Label 'Cluster A', 'Cluster B', ... (27. -> 'Cluster AA'). Exportiert als
// Single Source für die Flow-State-View-Projektion (lib/flow-state.mjs), die
// dieselbe Label-Konvention nach der Sortierung anwendet.
export function clusterLabel(index) {
  let n = index;
  let s = "";
  do {
    s = String.fromCharCode(65 + (n % 26)) + s;
    n = Math.floor(n / 26) - 1;
  } while (n >= 0);
  return `Cluster ${s}`;
}

// ---------- Union-Find (pfadkomprimiert, Rang-Union) ----------
class Dsu {
  constructor() {
    this.parent = new Map();
    this.rank = new Map();
  }
  add(x) {
    if (!this.parent.has(x)) {
      this.parent.set(x, x);
      this.rank.set(x, 0);
    }
  }
  find(x) {
    this.add(x);
    let root = x;
    while (this.parent.get(root) !== root) root = this.parent.get(root);
    while (this.parent.get(x) !== root) {
      const next = this.parent.get(x);
      this.parent.set(x, root);
      x = next;
    }
    return root;
  }
  union(a, b) {
    const ra = this.find(a);
    const rb = this.find(b);
    if (ra === rb) return;
    if (this.rank.get(ra) < this.rank.get(rb)) this.parent.set(ra, rb);
    else if (this.rank.get(ra) > this.rank.get(rb)) this.parent.set(rb, ra);
    else {
      this.parent.set(rb, ra);
      this.rank.set(ra, this.rank.get(ra) + 1);
    }
  }
}

// ---------- Beträge (wie dropsOf in lib/detector.mjs:152-159) ----------
function dropsOf(amount) {
  // Nur XRP (String in drops). IOU-Objekte liefern null.
  if (typeof amount === "string") {
    const n = Number(amount);
    return Number.isFinite(n) ? n : null;
  }
  return null;
}

// NFTokenOffer-DeletedNode aus der Tx-Metadaten (erste passende Node — ein
// NFTokenAcceptOffer in direkter Sell-Annahme konsumiert genau einen Offer;
// Metadata-Format https://xrpl.org/transaction-metadata.html: AffectedNodes
// -> DeletedNode -> LedgerEntryType/FinalFields). Ohne Meta/null ohne Treffer.
function deletedNftOfferOf(meta) {
  const nodes = Array.isArray(meta?.AffectedNodes) ? meta.AffectedNodes : [];
  for (const wrapper of nodes) {
    const node = wrapper?.DeletedNode;
    if (node?.LedgerEntryType === "NFTokenOffer" && node.FinalFields && typeof node.FinalFields === "object") {
      return node.FinalFields;
    }
  }
  return null;
}

// AMM-Konto (Gegenpartei von AMMCreate/AMMDeposit) aus der Tx-Metadaten:
// AMMCreate erzeugt ein AMM-Ledger-Objekt (CreatedNode), AMMDeposit modifiziert
// ein bestehendes (ModifiedNode) — die AMM-Kontoadresse steht in
// FinalFields.Account bzw. NewFields.Account (xrpl@4.0.0 ledger/AMM.d.ts:12
// 'Account: string' = AMM-Konto; expand-Pfad-Fallback LedgerEntry/NewFields
// wie createdAccountOf detector.mjs:248-260, live belegt hc_ledger_11/_13/_14).
// Muster deletedNftOfferOf (Meta-Knoten, keine Requests, keine erfundene
// Adresse): ohne Meta/null ohne Treffer -> Tx bleibt isolierter Knoten
// (buildClusterGraph :488-498).
function ammAccountOf(meta) {
  const nodes = Array.isArray(meta?.AffectedNodes) ? meta.AffectedNodes : [];
  for (const wrapper of nodes) {
    const node = wrapper?.CreatedNode ?? wrapper?.ModifiedNode;
    if (node?.LedgerEntryType !== "AMM") continue;
    // FinalFields zuerst (kanonisches Meta-Format), dann NewFields (expand-
    // Pfad), dann LedgerEntry — jedes Kandidaten-Feld einzeln prüfen: ein
    // ModifiedNode kann FinalFields ohne Account tragen (nur Delta-Felder).
    for (const fields of [node.FinalFields, node.NewFields, node.LedgerEntry]) {
      if (fields && typeof fields === "object" && typeof fields.Account === "string" && fields.Account) {
        return fields.Account;
      }
    }
  }
  return null;
}

// =====================================================================
// txRecordFromEntry — Ledger-Entry -> txRecord.
// Akzeptiert exakt die drei Formen von normalizeTxEntry (detector.mjs:166-178):
// {tx_json, meta}, {tx, meta} und flache tx (mit TransactionType).
// closeTime-Priorität:
//   1. close_time_iso der Entry (oder der tx-Felder),
//   2. close_time (Number) -> ISO via 946684800-Offset (xrpl-RipTime,
//      Muster api/ledger.js:121-125),
//   3. fallbackCloseIso (optionaler zweiter Parameter — nötig, weil
//      expand:true-Ledger-Entries kein close_time tragen; die Ledger-Ebenen-
//      close_time_iso wird dann vom Aufrufer übergeben).
// =====================================================================
export function txRecordFromEntry(entry, fallbackCloseIso) {
  if (!entry || typeof entry !== "object") return null;
  let tx = null;
  if (entry.tx_json && typeof entry.tx_json === "object") tx = entry.tx_json;
  else if (entry.tx && typeof entry.tx === "object") tx = entry.tx;
  else if (entry.TransactionType) tx = entry;
  if (!tx || !tx.TransactionType) return null;

  const hashRaw = entry.hash ?? tx.hash ?? tx.TransactionHash ?? null;
  const hash = typeof hashRaw === "string" && hashRaw ? hashRaw : null;

  const seqRaw = entry.ledger_index ?? entry.ledgerSeq ?? tx.ledger_index ?? tx.ledgerSeq ?? null;
  const seqNum = Number(seqRaw);
  const ledgerSeq = Number.isFinite(seqNum) && seqRaw != null ? seqNum : null;

  let closeTime = null;
  const iso = entry.close_time_iso ?? tx.close_time_iso;
  if (typeof iso === "string" && iso) {
    closeTime = iso;
  } else {
    const ct = entry.close_time ?? tx.close_time;
    if (typeof ct === "number" && Number.isFinite(ct)) {
      closeTime = new Date((ct + 946684800) * 1000).toISOString();
    } else if (typeof fallbackCloseIso === "string" && fallbackCloseIso) {
      closeTime = fallbackCloseIso;
    }
  }

  const rec = {
    hash,
    ledgerSeq,
    closeTime,
    type: tx.TransactionType,
    account: typeof tx.Account === "string" ? tx.Account : null,
  };
  // Inner-Transaktion eines Batch (XLS-56): Herkunft bleibt am Record sichtbar.
  if (entry.innerOf) { rec.inner = true; rec.batchOf = entry.innerOf; }
  if (typeof tx.Destination === "string" && tx.Destination) rec.destination = tx.Destination;
  // DestinationTag/SourceTag: Identitäts-Verfeinerung für Hosted-Accounts
  // (lib/tag-identity.mjs). Tag 0 ist ein echter Tag; null nur bei fehlendem
  // Feld. Der Tag gehört zur Transaktion, NICHT zur Gegenbewegungs-Adresse:
  // der Counter-Movement-Block unten überträgt ihn bewusst nicht auf Owner/
  // VaultOwner und der NFTokenAcceptOffer-Block nicht auf den Offer-Owner
  // (EscrowFinish trägt DestinationTag nicht an den Owner — wer es trotzdem
  // tat, fälschte die Hosted-Identität).
  const destTag = normalizeTag(tx.DestinationTag);
  if (destTag != null && typeof tx.Destination === "string" && tx.Destination) rec.destinationTag = destTag;
  const srcTag = normalizeTag(tx.SourceTag);
  if (srcTag != null) rec.sourceTag = srcTag;
  // Gegenbewegungs-Typen: reale Geldbewegung ohne Destination-Feld bekommt
  // ihren Gegenpartner als destination (EscrowFinish/Cancel -> Owner).
  // Protokoll-Belege (xrpl.org-Transaktionsreferenz, live abgerufen
  // 2026-10-07, gegen die lokal installierte xrpl@4.0.0-Typdefinition
  // node_modules/xrpl/dist/npm/models nachgerechnet 2026-10-07):
  //  - EscrowFinish/EscrowCancel: Felder Account/Owner/OfferSequence
  //    (https://xrpl.org/escrowfinish.html). Die Auszahlung läuft an
  //    Escrow.Destination, das ohne Ledger-Lookup über die OfferSequence
  //    nicht erreichbar ist — die Kante zeigt bewusst zum Owner
  //    (Escrow-Ersteller); dokumentierte Vereinfachung (README).
  //  - VaultWithdraw: die Spec (xrpl@4.0.0 transactions/vaultWithdraw.d.ts)
  //    kennt NUR VaultID/Amount/Destination?/DestinationTag — ein Feld
  //    'VaultOwner' EXISTIERT NICHT (grep über node_modules/xrpl/dist/npm/
  //    models: 0 Treffer); der frühere Zweig war toter Code und ist
  //    entfernt. Die reale Gegenpartei ist tx.Destination und wirkt bereits
  //    typ-agnostisch über die Destination-Zeile oben.
  //  - CheckCash: Felder sind NUR CheckID/Amount/DeliverMin
  //    (https://xrpl.org/checkcash.html) — ein Feld 'CheckDestination'
  //    EXISTIERT NICHT; der frühere Zweig war toter Code und ist entfernt.
  //    Der Casher (tx.Account) ist selbst der Empfänger; der ursprüngliche
  //    Check-Empfänger steht nur im Check-Ledger-Objekt (Lookup nötig) —
  //    keine erfundene Adresse, bewusst kantenlos.
  //  - Clawback: Account ist der ISSUER (https://xrpl.org/clawback.html) —
  //    der frühere Zweig 'Clawback -> tx.Account' war damit immer ein
  //    Self-Ref und durch den Self-Ref-Guard unten nie kantenfähig (dritter
  //    toter Zweig, entfernt). Die reale Flussrichtung ist Holder -> Issuer
  //    und im record-Vertrag (account = Sender -> destination) ohne
  //    Signertausch nicht ausdrückbar — bewusst kantenlos statt falsch herum.
  //    Dasselbe gilt für AMMClawback/VaultClawback (xrpl@4.0.0
  //    AMMClawback.d.ts:11 'Holder: Account'): Holder -> Issuer ist im
  //    record-Vertrag ohne Signertausch nicht ausdrückbar — bewusst kantenlos.
  //  - NFTokenAcceptOffer: Felder sind NUR NFTokenSellOffer/NFTokenBuyOffer/
  //    NFTokenBrokerFee (https://xrpl.org/docs/references/protocol/
  //    transactions/types/nftokenacceptoffer — live verifiziert 2026-10-07);
  //    ein Feld 'NFTokenOfferOwner' existiert NICHT (früherer Zweig war tot).
  //    Die Gegenpartei kommt META-basiert aus dem konsumierten NFTokenOffer-
  //    Ledger-Objekt — eigener Block nach der Betrags-Normalisierung unten.
  //  - NFTokenCreateOffer: Felder Owner?/Destination?/Amount
  //    (xrpl@4.0.0 NFTokenCreateOffer.d.ts). BEWUSST KEIN Owner-Mapping:
  //    Owner ist der Buy-Offer-Adressat (Seller), beim CREATE fließt kein
  //    Geld — eine Owner-Kante wäre eine erfundene Bewegung. Ein optional
  //    gesetztes tx.Destination wirkt bereits typ-agnostisch über die
  //    Destination-Zeile oben (Probe 2026-10-07: Destination -> Kante JA,
  //    nur Owner -> keine Kante).
  //  - AMMCreate/AMMDeposit: Gegenpartei ist das AMM-Konto, meta-basiert
  //    (CreatedNode/ModifiedNode LedgerEntryType 'AMM' -> FinalFields/
  //    NewFields.Account, xrpl@4.0.0 ledger/AMM.d.ts:12) — eigener Block
  //    nach der Betrags-Normalisierung unten. AMMWithdraw/AMMDelete/
  //    AMMVote/AMMBid: die Spec (AMMWithdraw.d.ts: nur Asset/Asset2/Amount/
  //    Amount2/EPrice/LPTokenIn) hat KEIN Gegenpartei-Feld; die Richtung
  //    AMM -> tx.Account ist im record-Vertrag ohne Signertausch nicht
  //    ausdrückbar — bewusst kantenlos (Präzedenz Clawback oben).
  //  - PaymentChannelFund/Claim -> Channel: Channel ist ein Hash, keine
  //    r-Adresse — die Spec erlaubt hier keine erfundene Adresse, der Typ
  //    bleibt ohne Kante (isoliert, wenn geflaggt). TrustSet/OfferCreate
  //    erzeugen per XRPL-Spezifikation keine Geldbewegungs-Kante und bleiben
  //    bewusst nicht kantenfähig.
  if (!rec.destination) {
    const counter =
      (tx.TransactionType === "EscrowFinish" || tx.TransactionType === "EscrowCancel") && typeof tx.Owner === "string" ? tx.Owner
      : null;
    if (counter && counter !== rec.account) rec.destination = counter;
  }
  // Betrag: XRP (drops) oder IOU. Die früheren Zusatz-Reads tx.VaultAmount
  // und tx.NFTokenOfferAmount existieren in xrpl@4.0.0 nirgends (grep: 0
  // Treffer) — toter Code, entfernt. Reale VaultWithdraw-Beträge stehen in
  // tx.Amount (vaultWithdraw.d.ts), reale NFT-Offer-Beträge im Meta-Block
  // unten (FinalFields.Amount).
  const amountSrc = tx.Amount ?? tx.DeliverMax ?? null;
  rec.amountDrops = dropsOf(amountSrc);
  if (amountSrc && typeof amountSrc === "object" && amountSrc.currency && amountSrc.issuer && amountSrc.value != null) {
    const v = Number(amountSrc.value);
    if (Number.isFinite(v)) rec.iouValue = { currency: String(amountSrc.currency), issuer: String(amountSrc.issuer), value: v };
  }
  // NFTokenAcceptOffer — meta-basierte NFT-Transfer-Kante (direkte
  // Sell-Annahme): tx.Account akzeptiert einen FREMDEN Sell-Offer und zahlt
  // dessen Amount an den Offer-Owner (Verkäufer); "Funds are transferred
  // from the buyer to the seller" (https://xrpl.org/docs/references/
  // protocol/transactions/types/nftokenacceptoffer, live verifiziert
  // 2026-10-07). Gegenpartei UND Betrag stammen aus dem im selben Ledger
  // konsumierten NFTokenOffer-Objekt (DeletedNode -> FinalFields.Owner/
  // Amount; Metadata-Format https://xrpl.org/transaction-metadata.html,
  // Muster metaFindBait monitor.mjs / prevBalanceOf detector.mjs).
  // FP-Guards (deterministisch, nichts Erfundenes):
  //  - NUR direkte Sell-Annahme: NFTokenSellOffer gesetzt UND NFTokenBuyOffer
  //    abwesend. Der Brokered Mode (zusaetzlich NFTokenBrokerFee; beide
  //    Offer-Felder) konsumiert zwei Offers — die Owner-Aufloesung waere
  //    mehrdeutig, bewusst unmapped (dieselbe Doc-Quelle).
  //  - Buy-Annahme (nur NFTokenBuyOffer): Kaeufer ist der Offer-Owner, die
  //    Zahlung laeuft Owner -> Account — Richtung im record-Vertrag
  //    (account = Sender -> destination) nicht ausdrueckbar, bewusst
  //    unmapped statt falsch herum.
  //  - Ohne Meta/DeletedNode mit Owner KEINE Kante (keine Offer-IDs per
  //    ledger_entry aufloesen — keine zusaetzlichen Requests, Bilanz
  //    250 <= 250 unveraendert; reine In-Memory-Meta-Auswertung).
  //  - Self-Ref (Owner === Account) faellt durch denselben Guard wie oben.
  if (!rec.destination && tx.TransactionType === "NFTokenAcceptOffer"
    && typeof tx.NFTokenSellOffer === "string" && tx.NFTokenBuyOffer === undefined) {
    const offer = deletedNftOfferOf(entry.meta);
    const owner = offer && typeof offer.Owner === "string" ? offer.Owner : null;
    if (owner && owner !== rec.account) {
      rec.destination = owner;
      // Zahlung = Offer.Amount (XRP: String in Drops; IOU: Objekt) — dieselbe
      // Normalisierung wie der amountSrc-Block oben.
      const offerAmount = offer.Amount ?? null;
      const offerDrops = dropsOf(offerAmount);
      if (offerDrops != null) rec.amountDrops = offerDrops;
      if (offerAmount && typeof offerAmount === "object" && offerAmount.currency && offerAmount.issuer && offerAmount.value != null) {
        const v = Number(offerAmount.value);
        if (Number.isFinite(v)) rec.iouValue = { currency: String(offerAmount.currency), issuer: String(offerAmount.issuer), value: v };
      }
    }
  }
  // AMMCreate/AMMDeposit — meta-basierte AMM-Kante (Kritik-Runde 3, T1.1):
  // tx.Account finanziert das AMM-Konto (Create: Amount/Amount2 in den neu
  // erzeugten Pool; Deposit: Amount/Amount2 in einen bestehenden Pool —
  // "deposits liquidity into an AMM", xrpl@4.0.0 AMMCreate.d.ts/AMMDeposit.d.ts).
  // Gegenpartei = AMM-Konto aus der Meta (ammAccountOf, Muster
  // deletedNftOfferOf): CreatedNode (Create) / ModifiedNode (Deposit),
  // FinalFields.Account bzw. NewFields.Account (ledger/AMM.d.ts:12).
  // FP-Guards (deterministisch, nichts Erfundenes):
  //  - Ohne Meta/AMM-Knoten KEINE Kante (kein ledger_entry-Lookup — keine
  //    zusätzlichen Requests, Bilanz unverändert; isolierter Knoten wie oben).
  //  - Self-Ref (AMM-Konto === tx.Account) fällt durch denselben Guard.
  //  - Der Betrag kommt aus dem amountSrc-Block oben (tx.Amount/Amount2 sind
  //    AMM-Felder; XRP in Drops, IOU als iouValue) — keine neue Quellen-Zählung.
  //  - AMMWithdraw/AMMDelete/AMMVote/AMMBid bleiben bewusst kantenlos
  //    (kein Gegenpartei-Feld in der Spec, Richtung AMM->Account nicht
  //    ausdrückbar — Kommentarblock oben).
  if (!rec.destination && (tx.TransactionType === "AMMCreate" || tx.TransactionType === "AMMDeposit")) {
    const amm = ammAccountOf(entry.meta);
    if (amm && amm !== rec.account) rec.destination = amm;
  }
  // V2 (Peel-Fingerprint, DFRWS 2023 — Auto-Programm-Homogenität): Fee in
  // Drops (tx.Fee, String in Drops, in jeder signierten Tx vorhanden) und
  // tx.Flags als Rohstoffe der Ketten-Homogenität. Rein informativ auf dem
  // txRecord; persistierte Kanten/Hops bleiben byte-neutral — der Fingerprint
  // wird zur Detektionszeit berechnet und als {score, criteria} geführt.
  const feeDrops = dropsOf(tx.Fee);
  if (feeDrops != null) rec.feeDrops = feeDrops;
  if (tx.Flags != null) {
    const flagsNum = Number(tx.Flags);
    if (Number.isFinite(flagsNum)) rec.flags = flagsNum;
  }
  return rec;
}

// =====================================================================
// buildClusterGraph — Kantenregel, Union-Find, Rollen, deterministische Ausgabe.
// =====================================================================
export function buildClusterGraph(txRecords, findings, opts = {}) {
  const maxEdges = Number.isFinite(opts.maxEdges) ? Math.max(0, Math.floor(opts.maxEdges)) : 2000;
  const minClusterSize = Number.isFinite(opts.minClusterSize) ? Math.max(1, opts.minClusterSize) : 2;
  const th = { ...ROLE_THRESHOLDS, ...(opts.thresholds && typeof opts.thresholds === "object" ? opts.thresholds : {}) };
  // Exchange-Registry (Map<adresse, {exchange,...}>): nur für Kanten-Attribute
  // toTag/fromTag/transit. Default null -> keine Tag-Felder, Verhalten
  // bitgleich zum Stand ohne diese Funktion.
  const multiUserAccounts = opts.multiUserAccounts instanceof Map ? opts.multiUserAccounts : null;

  // 1) Findings -> flagged Adressen, severity pro Adresse = max.
  const severityOf = new Map();
  for (const f of Array.isArray(findings) ? findings : []) {
    const addr = f?.address;
    if (typeof addr !== "string" || !addr) continue;
    const sev = SEVERITY_RANK[f?.severity] ? f.severity : "info";
    const cur = severityOf.get(addr);
    if (!cur || SEVERITY_RANK[sev] > SEVERITY_RANK[cur]) severityOf.set(addr, sev);
  }

  // 2) Kantenregel: Kante für jede tx, deren account ODER destination in
  // findings vorkommt. tx ohne (andere) Destination -> Knoten ohne Kante.
  // Die Edge trägt zusätzlich die Fund-severity (max severityOf beider
  // Endpunkte) — das Block-Fenster und die Legende brauchen die Stufe.
  const edges = [];
  const isolated = new Set();
  for (const rec of Array.isArray(txRecords) ? txRecords : []) {
    if (!rec || typeof rec !== "object") continue;
    const account = typeof rec.account === "string" ? rec.account : null;
    const destination = typeof rec.destination === "string" ? rec.destination : null;
    if (!account && !destination) continue;
    const flagged = (account != null && severityOf.has(account)) || (destination != null && severityOf.has(destination));
    if (!flagged) continue;
    if (account && destination && account !== destination) {
      const sevRank = Math.max(
        SEVERITY_RANK[severityOf.get(account) ?? ""] ?? 0,
        SEVERITY_RANK[severityOf.get(destination) ?? ""] ?? 0
      );
      const edge = {
        from: account,
        to: destination,
        type: typeof rec.type === "string" ? rec.type : null,
        amountDrops: typeof rec.amountDrops === "number" && Number.isFinite(rec.amountDrops) ? rec.amountDrops : null,
        txHash: typeof rec.hash === "string" ? rec.hash : null,
        ledgerSeq: typeof rec.ledgerSeq === "number" && Number.isFinite(rec.ledgerSeq) ? rec.ledgerSeq : null,
        closeTime: typeof rec.closeTime === "string" && rec.closeTime ? rec.closeTime : null,
        severity: sevRank ? (sevRank === 3 ? "malicious" : sevRank === 2 ? "suspect" : "info") : null,
      };
      if (rec.iouValue && typeof rec.iouValue === "object") {
        const v = Number(rec.iouValue.value);
        if (Number.isFinite(v) && rec.iouValue.currency && rec.iouValue.issuer) {
          edge.iouValue = { currency: String(rec.iouValue.currency), issuer: String(rec.iouValue.issuer), value: v };
        }
      }
      // Tag-Attribute (nur Kanten-Verfeinerung, keine Topologie-Änderung):
      // toTag nur, wenn der Empfänger ein Registry-Börsen-Konto IST und die
      // Tx einen gültigen DestinationTag trägt; fromTag (SourceTag) rein
      // informativ. Fehlendes Feld -> gar kein Feld (kein null-Feld).
      if (multiUserAccounts && destination != null && multiUserAccounts.has(destination) && rec.destinationTag != null) {
        edge.toTag = rec.destinationTag;
      }
      if (rec.sourceTag != null) edge.fromTag = rec.sourceTag;
      edges.push(edge);
    } else {
      if (account != null && severityOf.has(account)) isolated.add(account);
      if (destination != null && severityOf.has(destination)) isolated.add(destination);
    }
  }

  // 2b) Geflaggte Adressen, die in KEINER txRecord-Position vorkamen (z. B.
  // der airdrop-trustset-spam-Fund auf einen TrustSet-Issuer — TrustSets
  // erzeugen per Spec keine Kante), erscheinen mindestens als isolierter
  // Fund-Knoten. Es werden dabei KEINE Kanten erfunden.
  for (const addr of severityOf.keys()) isolated.add(addr);

  // 3) Kappung: neueste Kanten nach ledgerSeq bleiben (asc sortiert, vorne
  // abgeschnitten — deterministisch bei Gleichstand via txHash asc).
  // WICHTIG (Rollen-Kappungs-Entkopplung): ROLLEN, mainDrainers/collectors
  // und Union-Find/Cluster-Mitgliedschaft werden aus dem VOLLEN Kantensatz
  // berechnet; txCount und totalDrops des Clusters bleiben aus den
  // ausgegebenen (gekappten) Kanten — der UI-Deckel erfindet keine Drainer.
  edges.sort(cmpEdge);
  const fullEdges = [...edges]; // Vollsicht für Rollen/Union (Kopie: edges wird gekappt)
  // Transit auf dem VOLLEN Kantensatz berechnen (vor dem Cap) — das Flag
  // sitzt auf den Edge-Objekten und ist damit cap-unabhängig: gekappte
  // Kanten behalten ihr transit, als wäre der volle Satz gesehen worden.
  if (multiUserAccounts) computeTransitFlags(fullEdges, multiUserAccounts);
  if (edges.length > maxEdges) edges.splice(0, edges.length - maxEdges); // Ausgabesicht (gekürzt)

  // 4) Union-Find über den VOLLEN Kantensatz -> Komponenten.
  // Hub-Union-Schutz: unflaggte Knoten mit Grad > 20 (Börsen-/Faucet-Hubs)
  // werden aus der Vereinigung herausgeschnitten — zwei unabhängige Szenen
  // verschmelzen nicht über eine gemeinsame Börse. Die Rollen der Hubs
  // bleiben erhalten (stats kommen aus fullEdges).
  const fullDegree = new Map();
  for (const e of fullEdges) {
    fullDegree.set(e.from, (fullDegree.get(e.from) ?? 0) + 1);
    fullDegree.set(e.to, (fullDegree.get(e.to) ?? 0) + 1);
  }
  const HUB_UNION_DEGREE = 20;
  const isHub = (id) => !severityOf.has(id) && (fullDegree.get(id) ?? 0) > HUB_UNION_DEGREE;
  const dsu = new Dsu();
  const nodeIds = new Set();
  for (const e of fullEdges) {
    nodeIds.add(e.from);
    nodeIds.add(e.to);
    // Hub-Kanten werden aus der Vereinigung herausgeschnitten (nicht der
    // Hub-Konten selbst): zwei unabhängige Szenen verschmelzen nicht über
    // eine gemeinsame Börse; Szenen-interne Kanten mergen normal.
    if (isHub(e.from) || isHub(e.to)) continue;
    dsu.union(e.from, e.to);
  }
  for (const a of isolated) {
    nodeIds.add(a);
    dsu.add(a);
  }

  // 5) Knotenaggregate aus dem VOLLEN Kantensatz (Rollen spiegeln den
  // Vollbild, nicht die gekappte UI-Sicht).
  const stats = new Map(); // id -> {degreeIn, degreeOut, inDrops, outDrops, distinctIn:Set, smallOut, maxOut, iouIn:Map, iouOut:Map, distinctInFlagged, distinctOutFlagged}
  const stat = (id) => {
    if (!stats.has(id)) {
      stats.set(id, { degreeIn: 0, degreeOut: 0, inDrops: 0, outDrops: 0, distinctIn: new Set(), smallOut: 0, maxOut: 0, iouIn: new Map(), iouOut: new Map(), distinctInFlagged: new Set(), distinctOutFlagged: new Set() });
    }
    return stats.get(id);
  };
  for (const id of nodeIds) stat(id);
  for (const e of fullEdges) {
    const drops = e.amountDrops ?? 0; // null (IOU) zählt 0 für XRP-Summen
    const from = stat(e.from);
    const to = stat(e.to);
    from.degreeOut += 1;
    from.outDrops += drops;
    if (drops > 0 && drops <= th.sourceSmallDrops) from.smallOut += 1; // smallOut bleibt XRP-only (IOU zählt nicht als 'klein')
    if (drops > from.maxOut) from.maxOut = drops;
    to.degreeIn += 1;
    to.inDrops += drops;
    to.distinctIn.add(e.from);
    if (severityOf.has(e.from)) to.distinctInFlagged.add(e.from);
    if (severityOf.has(e.to)) from.distinctOutFlagged.add(e.to);
    if (e.iouValue) {
      const key = `${e.iouValue.currency}|${e.iouValue.issuer}`;
      from.iouOut.set(key, (from.iouOut.get(key) ?? 0) + e.iouValue.value);
      to.iouIn.set(key, (to.iouIn.get(key) ?? 0) + e.iouValue.value);
    }
  }

  // 6) Rollen-Heuristik. Konfliktauflösung: drainer > collector > relay > source.
  // Drainer verlangt >= 2 VERSCHIEDENE Eingangs-Sender (distinctIn, impliziert
  // degreeIn >= 2): eine einzelne Ein-/Ausgangs-Kante mit >= 90 % Weiterleitung
  // ist flow-seitig nicht von benignem Durchleitungs-/Konsolidierungsfluss zu
  // unterscheiden und fällt an die Relay-Regel (Befund 2026-09-29 behoben;
  // Tests 7/11 sichern den Mehrquellen-Sweep als Drainer-Kern ab).
  // Gegenparteien-Bindung (FP-Schutz): drainer verlangt zusätzlich mindestens
  // einen GEFLAGGTEN Sender, collector ebenso (degreeOut <= 2 statt 1 — ein
  // echter Collector mit zwei Sammel-Auszahlungen bleibt erkennbar), source
  // nur wenn mindestens ein Ziel geflaggt ist. Selbstwallet-Konsolidierung,
  // Exchange-Acceptance-Knoten und Faucet-Distributoren verlieren damit die
  // Betrugslables; echte Sweeps aus geflaggten Opfer-Adressen bleiben.
  // IOU-Sichtbarkeit OHNE erfundene XRP-Skala: ist der XRP-Fluss null und
  // Ein- und Ausgänge tragen dieselbe currency+issuer, wird das Sweep-/Relay-
  // Verhältnis wertungsneutral aus den IOU-Werten berechnet (ratio von value
  // zu value, keine value*1e6-Skala).
  const iouCommonKey = (s) => {
    for (const key of s.iouIn.keys()) if (s.iouOut.has(key)) return key;
    return null;
  };
  const roleOf = (id) => {
    const s = stats.get(id);
    const key = iouCommonKey(s);
    let inVal = s.inDrops;
    let outMax = s.maxOut;
    if (key && s.inDrops === 0) {
      inVal = s.iouIn.get(key);
      outMax = Math.max(...s.iouOut.values());
    }
    if (s.distinctIn.size >= 2 && s.degreeOut >= 1 && inVal > 0 && outMax >= th.sweepRatio * inVal && s.distinctInFlagged.size >= 1) return "drainer";
    // collector: >= 3 Eingänge von geflaggten Sendern, max. 2 ausgehende
    // (echter Collector mit zwei Sammel-Auszahlungen bleibt erkennbar) UND
    // Akkumulation (inDrops >= 1.5 * outDrops) — ein ausgewogener Weiterleiter
    // mit vielen Eingängen bleibt relay, nicht collector.
    if (s.degreeIn >= th.collectorMinIn && s.distinctIn.size >= th.collectorMinIn && s.degreeOut <= 2 && s.inDrops >= 1.5 * s.outDrops && s.distinctInFlagged.size >= 1) return "collector";
    if (s.degreeIn >= 1 && s.degreeOut >= 1 && Math.abs(inVal - s.outDrops) <= th.relayBalance * Math.max(inVal, s.outDrops)) return "relay";
    if (s.degreeOut >= th.sourceMinOut && s.smallOut >= th.sourceMinOut && s.degreeIn <= 1 && s.distinctOutFlagged.size >= 1) return "source";
    return "unknown";
  };

  // 7) Komponenten -> Cluster (>= minClusterSize; sonst Knoten mit clusterId null).
  const components = new Map(); // root -> Set(ids)
  for (const id of nodeIds) {
    const root = dsu.find(id);
    if (!components.has(root)) components.set(root, new Set());
    components.get(root).add(id);
  }

  const clusters = [];
  for (const members of components.values()) {
    if (members.size < minClusterSize) continue;
    const memberAddresses = [...members].sort(cmpStr);
    const clusterEdges = edges.filter((e) => members.has(e.from)); // beide Enden in derselben Komponente (Ausgabesicht, gekappt)
    let totalDrops = 0;
    let firstSeen = null;
    let lastSeen = null;
    let firstEpoch = null;
    let lastEpoch = null;
    const iouFlowsMap = new Map(); // currency|issuer -> Summe value (IOU-Sicht ohne XRP-Skala)
    for (const e of clusterEdges) {
      totalDrops += e.amountDrops ?? 0;
      if (e.iouValue) {
        const key = `${e.iouValue.currency}|${e.iouValue.issuer}`;
        iouFlowsMap.set(key, (iouFlowsMap.get(key) ?? 0) + e.iouValue.value);
      }
      if (e.closeTime) {
        // epoch-Vergleich (Befund 2026-09-29): lexikalischer Vergleich mischt
        // closeTime-Formate falsch — firstSeen war '…10:00:00.500Z', obwohl
        // '…10:00:00Z' chronologisch früher liegt. Ausgegeben wird weiterhin
        // der Originalstring der Kante, verglichen wird in Epoch-ms.
        const ep = epochOf(e.closeTime);
        if (firstEpoch == null || ep < firstEpoch) {
          firstEpoch = ep;
          firstSeen = e.closeTime;
        }
        if (lastEpoch == null || ep > lastEpoch) {
          lastEpoch = ep;
          lastSeen = e.closeTime;
        }
      }
    }
    const roles = {};
    const severityByAddress = {};
    for (const id of memberAddresses) {
      roles[id] = roleOf(id);
      if (severityOf.has(id)) severityByAddress[id] = severityOf.get(id);
    }
    const mainDrainers = memberAddresses
      .filter((a) => roles[a] === "drainer")
      .map((a) => ({ address: a, outDrops: stats.get(a).outDrops }))
      .sort((x, y) => y.outDrops - x.outDrops || cmpStr(x.address, y.address));
    const collectors = memberAddresses
      .filter((a) => roles[a] === "collector")
      .map((a) => ({ address: a, inDrops: stats.get(a).inDrops }))
      .sort((x, y) => y.inDrops - x.inDrops || cmpStr(x.address, y.address));
    clusters.push({
      id: `cluster:${memberAddresses[0]}`,
      label: "", // wird nach der Sortierung gesetzt
      memberAddresses,
      roles,
      severityByAddress,
      totalDrops,
      txCount: clusterEdges.length,
      distinctAccounts: memberAddresses.length,
      firstSeen,
      lastSeen,
      mainDrainers,
      collectors,
      iouFlows: [...iouFlowsMap.entries()]
        .map(([key, value]) => {
          const [currency, issuer] = key.split("|");
          return { currency, issuer, value };
        })
        .sort((x, y) => cmpStr(`${x.currency}|${x.issuer}`, `${y.currency}|${y.issuer}`)),
    });
  }

  // 8) Deterministische Sortierung + Labels.
  clusters.sort(
    (a, b) =>
      b.totalDrops - a.totalDrops ||
      b.txCount - a.txCount ||
      cmpStr(a.memberAddresses[0], b.memberAddresses[0])
  );
  clusters.forEach((c, i) => {
    c.label = clusterLabel(i);
  });

  const clusterIdOf = new Map();
  for (const c of clusters) for (const a of c.memberAddresses) clusterIdOf.set(a, c.id);

  const nodes = [...nodeIds].sort(cmpStr).map((id) => ({
    id,
    role: roleOf(id),
    severity: severityOf.get(id) ?? null,
    degreeIn: stats.get(id).degreeIn,
    degreeOut: stats.get(id).degreeOut,
    inDrops: stats.get(id).inDrops,
    outDrops: stats.get(id).outDrops,
    clusterId: clusterIdOf.get(id) ?? null,
  }));

  // edges bleiben (ledgerSeq asc, txHash asc) sortiert.
  return { clusters, nodes, edges };
}

// Kleine Hilfe für Aufrufer: ist eine Rolle erlaubt?
export function isKnownRole(role) {
  return ROLE_SET.has(role);
}

// =====================================================================
// flowPaths — echte Start-bis-Ende-Flusspfade über Knoten und Kanten.
// Die UI (Drilldown-Flusskette, Cluster-Karten) darf Adressen nur entlang
// echter Kanten mit „→" verbinden — rollenweise aneinandergereihte Chips
// implizierten Transaktionen, die es im Beobachtungsfenster nicht gibt
// (Befund 2026-09-29).
// Eingabe: nodes [{ id, role }], edges [{ from, to }] (beide Enden im
//   Node-Set; Aufrufer filtert), opts { maxPaths = 4, maxPathLen = 6 }.
// Ausgabe: [[{ id, role }, ...], ...] — einfache Pfade ab Knoten ohne
//   Eingangskante (ergänzt um Source-Rollen-Knoten), beendet an Senken,
//   Kollektoren, Zykeln oder maxPathLen. Deterministisch sortiert
//   (Pfad-Signatur asc); [] wenn keine Kante existiert. Kein Schuldnachweis.
// =====================================================================
export function flowPaths(nodes, edges, opts = {}) {
  const maxPaths = Number.isFinite(opts.maxPaths) ? Math.max(1, Math.floor(opts.maxPaths)) : 4;
  const maxPathLen = Number.isFinite(opts.maxPathLen) ? Math.max(2, Math.floor(opts.maxPathLen)) : 6;

  const idSet = new Set();
  const roleById = new Map();
  for (const n of Array.isArray(nodes) ? nodes : []) {
    const id = String(n?.id ?? "");
    if (!id) continue;
    idSet.add(id);
    roleById.set(id, ROLE_SET.has(n?.role) ? n.role : "unknown");
  }
  const adj = new Map(); // id -> Nachfolger (sortiert)
  const inDeg = new Map();
  for (const e of Array.isArray(edges) ? edges : []) {
    const f = String(e?.from ?? "");
    const t = String(e?.to ?? "");
    if (!idSet.has(f) || !idSet.has(t) || f === t) continue;
    if (!adj.has(f)) adj.set(f, []);
    adj.get(f).push(t);
    inDeg.set(t, (inDeg.get(t) ?? 0) + 1);
  }
  for (const list of adj.values()) list.sort(cmpStr);
  if (!adj.size) return [];

  // Starts: Knoten ohne Eingangskante, ergänzt um Source-Rollen-Knoten.
  const starts = [...idSet]
    .filter((id) => !inDeg.has(id) || roleById.get(id) === "source")
    .sort(cmpStr);

  const paths = [];
  const seen = new Set(); // Pfad-Signatur (join ",") -> bereits aufgenommen
  const record = (acc) => {
    if (acc.length < 2 || paths.length >= maxPaths) return;
    const sig = acc.join(",");
    if (seen.has(sig)) return;
    seen.add(sig);
    paths.push([...acc]);
  };
  const walk = (id, acc) => {
    if (paths.length >= maxPaths) return;
    if (roleById.get(id) === "collector") {
      record(acc); // Kollektor: Endpunkt der Geldfluss-Heuristik
      return;
    }
    const next = adj.get(id) ?? [];
    if (!next.length || acc.length >= maxPathLen) {
      record(acc); // Senke oder Längengrenze
      return;
    }
    for (const t of next) {
      if (acc.includes(t)) {
        record(acc); // Zykel: Pfad bis hierher, Kante nicht erneut laufen
        continue;
      }
      acc.push(t);
      walk(t, acc);
      acc.pop();
      if (paths.length >= maxPaths) return;
    }
  };
  for (const s of starts) {
    walk(s, [s]);
    if (paths.length >= maxPaths) break;
  }
  paths.sort((p, q) => cmpStr(p.join(","), q.join(",")));
  return paths.map((p) => p.map((id) => ({ id, role: roleById.get(id) ?? "unknown" })));
}

// =====================================================================
// Peeling-Ketten — gestaffelte Weiterleitung 60–95 % über ungeflaggte
// 1:1-Relays. detectPeelingChains(txRecords, flaggedAddresses, opts).
//
// LÄUFT ÜBER txRecords, NICHT über die Cluster-Kanten: die Kantenregel
// (:276-277) kanntet nur tx mit geflaggtem Endpunkt und liefert die
// Mittelkante einer ungeflaggt gebridgten Kette nie — die Kettenwanderung
// braucht die volle tx-Sicht (Grenze 1 des Engine-Audits).
//
// FP-Schutz: Seeds sind ausschließlich flaggedAddresses; ungeflaggte Knoten
// werden nur als strikte 1:1-Relays durchgewandert (genau ein Eingang, genau
// ein Ausgang in der Ketten-Nachbarschaft) und erhalten nie Rolle und nie
// severityByAddress. Hub-Skala vereinheitlicht mit dem Union-Schnitt
// (:327-333): Hub-Test auf FLAGGE-Edge-Kanten (tx mit mindestens einem
// geflaggten Endpunkt), Schwelle HUB_UNION_DEGREE 20 — ein Knoten mit 21
// ungeflaggten Alltags-Tx ist KEIN Hub und darf gebridgt werden; zusätzlich
// begrenzt maxDegree (Ketten-Nachbarn, Default 4) die Wanderung.
//
// Determinismus (Kritik 4): Nachbar-Listen asc sortiert (Muster flowPaths
// adj-Sortierung :566), Ketten nach Signatur (Adressen join ',') asc, hops
// nach (ledgerSeq asc, txHash asc) — dieselbe Totalordnung wie cmpEdge
// (:69-109). Die txRecords-Reihenfolge entscheidet nie.
//
// Kappen gegen die bis zu 2000 Kanten (maxEdges :251) innerhalb maxDuration
// 30 s (api/advance.js:100): maxSeeds 50, maxChainLen 8 (Kanten je Kette),
// maxDegree 4 (Ketten-Nachbarn je Knoten), maxChains 20.
//
// Schwellen (PEELING_THRESHOLDS, Tuning-Defaults ohne Kampagnen-Fall):
//   minRatio/maxRatio — Verhältnis Weiterleitung/Eingang je Hop im Fenster;
//   minHops — Mindestzahl Kanten je Kette;
//   dustDrops 100 — Bagatellgrenie wie DEFAULT_THRESHOLDS.dustDrops
//   (lib/detector.mjs:28): ein Hop mit amountDrops <= dustDrops bricht die
//   Kette (Dust-Hops sind keine Peelings).
//
// Ausgabe: [{ addresses, hops: [{ from, to, amountDrops, ratio, txHash,
//   ledgerSeq }], seed, seedSeverity, hopsCount, bridges: [Adresse asc],
//   signature }] — sortiert nach signature asc. seedSeverity ∈
//   {'malicious','suspect','info'}. Kein Schuldnachweis.
// =====================================================================
export const PEELING_THRESHOLDS = {
  minRatio: 0.6,   // unterhalb: normale Aufteilung, kein gestaffeltes Peeling
  maxRatio: 0.95,  // oberhalb: Sweep (drainer-sweep dominiert bereits)
  minHops: 3,      // zwei Hops sind eine einfache Weiterleitung, kein Peeling
  dustDrops: 100,  // Hop <= 100 drops bricht die Kette (wie detector.mjs:28)
};

// ---------- V1b: Remainder-Rinne ("Großrest wandert weiter") ----------
// Quelle/Begründung: DFRWS 2023 (Gong et al.) — auf dem account-basierten
// XRPL ist das Analogon zur Bitcoin-Self-Change-Peel: kleiner Betrag wird
// abgeschält (der "Peel", bei 71,2 % der Ketten < 1 % des Inputs), der Rest
// (~>= 95 %) wandert an das nächste Kettenglied. Genau oberhalb des bisherigen
// maxRatio 0.95, das bewusst den Sweep-Bereich abtrennte.
// FP-Guard (der entscheidende): die Rinne verlangt den BEOBACHTETEN kleinen
// Abgang im selben Block-Fenster — nur die Weiterleitung ohne Abgang ist ein
// Sweep und bleibt alleinige Zuständigkeit von drainer-sweep (kein
// Doppel-Label). Der Abgang muss über der Bagatellgrenze dustDrops liegen
// (Dust ist kein Peel, sondern dusting-Zuständigkeit) und darf kein
// Kettenglied sein.
export const PEELING_REMAINDER_THRESHOLDS = {
  minRatio: 0.95,        // Weiterleitung >= 95 % des Relay-Eingangs
  maxRatio: 1,           // exklusiv: >= 100 % des Eingangs ist kein Peel
                         // (aufeinanderfolgende Hops können den Eingang nie
                         // übersteigen — Gebühren fehlen, nicht entstehen)
  peelMaxFraction: 0.01, // Abgeschälter <= 1 % des Eingangs (DFRWS: 71,2 %)
  minHops: 2,            // DFRWS: 42,6 % der Ketten haben 2 Runden — die
                         // Remainder-Rinne gilt ab 2 Hops; die klassische
                         // Rinne behält minHops 3
};

// ---------- V1c: Cross-Block-Fenster (Zeitdimension) ----------
// Quelle/Begründung: DFRWS 2023 — 79 % der Peel-Chains laufen innerhalb von
// 24 h ab, > 50 % innerhalb 1 h, 63,6 % der Peel-Tx-Intervalle <= 10 Blöcke
// (Bitcoin-Blöcke ~10 min). XRPL-Übersetzung: 10 Bitcoin-Blöcke ~ 100 min;
// der Hop-Gap-Deckel 900 XRPL-Ledger (~4 s/Ledger ~ 1 h) trägt das
// 63,6-%-Quantil plus Toleranz für akkumulierte Top-K-Kanten (Chrono-Anker
// können Zwischen-Hops verbergen). Tuning-Default ohne XRPL-Kampagnen-Fall.
export const CROSS_BLOCK_PEELING_THRESHOLDS = {
  ...PEELING_THRESHOLDS,   // minRatio/maxRatio/minHops/dustDrops unverändert
  windowMs: 24 * 60 * 60 * 1000, // 79-%-Quantil: Kette muss in 24 h laufen
  maxHopGapLedgers: 900,         // ~1 h Ledger-Zeit zwischen aufeinander-
                                 // folgenden Hops (63,6-%-Intervall + Toleranz)
};

// ---------- V2: Peel-Fingerprint (Auto-Programm-Homogenität) ----------
// Quelle/Begründung: DFRWS 2023 — automatisierte Peel-Programme hinterlassen
// identische Transaktionsparameter entlang der Kette; KEIN Einzelsignal
// diskriminiert, erst die Kombination. Vier Kriterien (Score 0-4):
//   'fee-constancy'      — alle Hop-Fees im selben ±10-%-Bucket um den Median
//   'amount-duplicates'  — >= 2 gleiche Werte über Hop-/Peel-Beträge (Peel-
//                          Duplikate = Programm-Verteilung; Hop-Beträge
//                          sinken streng monoton, siehe Kriterien-Kommentar)
//   'interval-regularity'— Blockabstände: Median <= 10 UND Varianz <= 36
//                          (Stddev <= 6 Blöcke), erst ab 3 Hops
//   'tag-reuse'          — gleicher Destination-/SourceTag in >= 2 Hops
//                          (nur wo Tag != null)
// FP-Guards: (1) Fee-Konstanz ALLEIN kann den Score 2 nie erreichen — die
// Fee-Defaults vieler Wallets sind identisch, Fee-Homogenität ist solo kein
// Kampagnen-Beleg (implizit durch Score >= minScore 2). (2) Das
// Intervall-Kriterium verlangt Mindest-Hopzahl 3 (2 Punkte haben 1 Abstand,
// keine Regelmäßigkeit). (3) Betrags-Duplikate laufen über Hops, die per
// Ketten-Bedingung bereits > dustDrops liegen (Bagatell-Duplikate zählen
// nicht). Der Fingerprint ist ein beschreibendes Ketten-Attribut — er ändert
// KEINE Severity (Enum bleibt 'malicious'|'suspect'|'info') und erzwingt
// nichts in hasFraudEvidence (peelingChains zählen dort bereits).
export const PEELING_FINGERPRINT_THRESHOLDS = {
  feeTolerance: 0.1,       // ±10 % um den Fee-Median
  minHopsForInterval: 3,   // Intervall-Kriterium erst ab 3 Hops
  maxMedianGapLedgers: 10, // DFRWS: 63,6 % der Peel-Intervalle <= 10 Blöcke
  maxGapVariance: 36,      // Varianz der Blockabstände <= 36 (Stddev <= 6)
  minScore: 2,             // >= 2 Kriterien: Kette gilt als geführt 'homogen'
  highScore: 3,            // >= 3 Kriterien: confidence 'high'
};

// Median einer Zahlmenge (deterministisch: sortiert, bei gerader Anzahl
// Durchschnitt der beiden Mittewerte). Leere Menge -> null.
function medianOf(nums) {
  const s = [...nums].sort((a, b) => a - b);
  if (!s.length) return null;
  const m = Math.floor(s.length / 2);
  return s.length % 2 ? s[m] : (s[m - 1] + s[m]) / 2;
}

// Rein deterministisch; liest chain.hops[].feeDrops/amountDrops/ledgerSeq/
// destinationTag/sourceTag (die beiden Tag-Felder werden im Block-Walk aus
// den txRecords befüllt, im Cross-Block-Walk aus Kanten-toTag/fromTag).
// Rückgabe: { score, criteria } — criteria in fester Reihenfolge.
export function peelChainFingerprint(chain, opts = {}) {
  const th = {
    ...PEELING_FINGERPRINT_THRESHOLDS,
    ...(opts && typeof opts === "object" ? opts : {}),
  };
  const hops = (Array.isArray(chain?.hops) ? chain.hops : []).filter((h) => h && typeof h === "object");
  const criteria = [];
  if (hops.length < 2) return { score: 0, criteria };

  // 1) Fee-Bucket-Konstanz (nur auswertbare Fee-Werte; fehlende Fees
  //    disqualifizieren das Kriterium nicht — es zählt nur, wenn ALLE
  //    vorhandenen im Bucket liegen und mindestens 2 vorliegen).
  const fees = hops
    .map((h) => (typeof h.feeDrops === "number" && Number.isFinite(h.feeDrops) && h.feeDrops > 0 ? h.feeDrops : null))
    .filter((f) => f != null);
  if (fees.length >= 2) {
    const med = medianOf(fees);
    if (med != null && fees.every((f) => Math.abs(f - med) <= th.feeTolerance * med)) {
      criteria.push("fee-constancy");
    }
  }

  // 2) Betrags-Duplikate (>= 2 gleiche Werte über Hop- UND Peel-Beträge).
  //    KETTEN-MATHEMATIK (dokumentiert): Hop-Beträge sinken streng monoton —
  //    jeder Relay-Hop fordert ratio < 1, also ist amountDrops[k+1] <
  //    amountDrops[k]. Duplikate leben deshalb in den ABGÄNGEN: identische
  //    Peel-Beträge (peelDrops, nur Remainder-Hops) sind das DFRWS-
  //    Programm-Verteilungssignal; direkte Aufrufer können zusätzlich
  //    duplizierte Hop-Beträge in beliebigen Hop-Mengen fingerprinten.
  const amountCounts = new Map();
  for (const h of hops) {
    for (const a of [h.amountDrops, h.peelDrops]) {
      if (typeof a !== "number" || !Number.isFinite(a)) continue;
      amountCounts.set(a, (amountCounts.get(a) ?? 0) + 1);
    }
  }
  for (const n of amountCounts.values()) {
    if (n >= 2) {
      criteria.push("amount-duplicates");
      break;
    }
  }

  // 3) Intervall-Regularität (erst ab minHopsForInterval Hops; alle Hops
  //    brauchen ledgerSeq — fehlt eins, ist die Reihe nicht messbar).
  if (hops.length >= th.minHopsForInterval) {
    const seqs = hops.map((h) => (typeof h.ledgerSeq === "number" && Number.isFinite(h.ledgerSeq) ? h.ledgerSeq : null));
    if (seqs.every((s) => s != null)) {
      const gaps = [];
      for (let i = 1; i < seqs.length; i++) gaps.push(Math.abs(seqs[i] - seqs[i - 1]));
      const med = medianOf(gaps);
      const mean = gaps.reduce((a, b) => a + b, 0) / gaps.length;
      const variance = gaps.reduce((a, b) => a + (b - mean) ** 2, 0) / gaps.length;
      if (med != null && med <= th.maxMedianGapLedgers && variance <= th.maxGapVariance) {
        criteria.push("interval-regularity");
      }
    }
  }

  // 4) Tag-Wiederverwendung (gleicher Tag-Wert in >= 2 Hops; Tag 0 ist ein
  //    echter Tag. Destination- und SourceTags teilen sich den Wert-Raum:
  //    ein vom Programm wiederholter Tag ist das Signal, nicht das Feld).
  const tagCounts = new Map();
  for (const h of hops) {
    for (const t of [h.destinationTag, h.sourceTag]) {
      if (typeof t === "number" && Number.isFinite(t)) tagCounts.set(t, (tagCounts.get(t) ?? 0) + 1);
    }
  }
  for (const n of tagCounts.values()) {
    if (n >= 2) {
      criteria.push("tag-reuse");
      break;
    }
  }

  return { score: criteria.length, criteria };
}

export function detectPeelingChains(txRecords, flaggedAddresses, opts = {}) {
  const th = {
    ...PEELING_THRESHOLDS,
    ...(opts.thresholds && typeof opts.thresholds === "object" ? opts.thresholds : {}),
  };
  // Remainder-Rinne (V1b): eigene Schwellegruppe, getrennt überschreibbar.
  const rth = {
    ...PEELING_REMAINDER_THRESHOLDS,
    ...(opts.remainderThresholds && typeof opts.remainderThresholds === "object" ? opts.remainderThresholds : {}),
  };
  const maxSeeds = Number.isFinite(opts.maxSeeds) ? Math.max(0, Math.floor(opts.maxSeeds)) : 50;
  const maxChainLen = Number.isFinite(opts.maxChainLen) ? Math.max(1, Math.floor(opts.maxChainLen)) : 8;
  const maxDegree = Number.isFinite(opts.maxDegree) ? Math.max(1, Math.floor(opts.maxDegree)) : 4;
  const maxChains = Number.isFinite(opts.maxChains) ? Math.max(0, Math.floor(opts.maxChains)) : 20;

  // 1) Seeds: nur geflaggte Adressen, severity pro Adresse = max.
  const severityOf = new Map();
  for (const f of Array.isArray(flaggedAddresses) ? flaggedAddresses : []) {
    const addr = typeof f?.address === "string" ? f.address : null;
    if (!addr) continue;
    const sev = SEVERITY_RANK[f?.severity] ? f.severity : "info";
    const cur = severityOf.get(addr);
    if (!cur || SEVERITY_RANK[sev] > SEVERITY_RANK[cur]) severityOf.set(addr, sev);
  }
  if (!severityOf.size) return [];

  // 2) FLAGGE-Edge-Kanten (Kantenregel wie :276-277): tx mit mindestens einem
  // geflaggten Endpunkt. Nur diese Kanten tragen den Hub-Grad (Skala wie der
  // Union-Schnitt :327-333) und begründen Seeds.
  const flagEdges = [];
  for (const rec of Array.isArray(txRecords) ? txRecords : []) {
    if (!rec || typeof rec !== "object") continue;
    const account = typeof rec.account === "string" ? rec.account : null;
    const destination = typeof rec.destination === "string" ? rec.destination : null;
    if (!account || !destination || account === destination) continue;
    if (!severityOf.has(account) && !severityOf.has(destination)) continue;
    flagEdges.push({
      from: account,
      to: destination,
      amountDrops:
        typeof rec.amountDrops === "number" && Number.isFinite(rec.amountDrops) ? rec.amountDrops : null,
      txHash: typeof rec.hash === "string" ? rec.hash : null,
      ledgerSeq:
        typeof rec.ledgerSeq === "number" && Number.isFinite(rec.ledgerSeq) ? rec.ledgerSeq : null,
    });
  }

  // 3) Hub-Test auf FLAGGE-Edge-Grad, Schwelle HUB_UNION_DEGREE 20 (identisch
  // :332-333): ungeflaggte Knoten mit > 20 FLAGGE-Kanten (Börsen-/Faucet-Hubs)
  // werden nie Seed und nie durchwandert. Ungeflaggte Alltags-Tx zählen hier
  // nicht in den Grad — Skalen-Kritik 5.
  const flagDegree = new Map();
  for (const e of flagEdges) {
    flagDegree.set(e.from, (flagDegree.get(e.from) ?? 0) + 1);
    flagDegree.set(e.to, (flagDegree.get(e.to) ?? 0) + 1);
  }
  const HUB_UNION_DEGREE = 20;
  const isHub = (id) => !severityOf.has(id) && (flagDegree.get(id) ?? 0) > HUB_UNION_DEGREE;

  // 4) Ketten-Nachbarschaft: ALLE tx mit beiden Endpunkten (auch ungeflaggte
  // Mittelkanten — genau die Kante, die die Cluster-Kantenregel nie liefert).
  // Ungeflaggte Knoten werden nur als strikte 1:1-Relays durchgewandert:
  // genau ein Eingang UND genau ein Ausgang in der KETTEN-Nachbarschaft.
  // Skala (Kritik 5, konsistent zum Hub-Test): Alltags-Tx zwischen zwei
  // ungeflaggten Knoten (keine Ketten-Kante — kein geflaggter Endpunkt und
  // kein Ketten-Nachbar) zählen NICHT in den Relay-Grad; ein Knoten mit 21
  // solchen Alltags-Tx bleibt bebridgbar, ein Knoten mit > 20 FLAGGE-Kanten
  // ist Hub und wird nie durchwandert. maxDegree (Ketten-Nachbarn) begrenzt
  // zusätzlich die Wanderung.
  const txHops = []; // normalisierte tx-Hops (Reihenfolge egal — sortiert)
  for (const rec of Array.isArray(txRecords) ? txRecords : []) {
    if (!rec || typeof rec !== "object") continue;
    const account = typeof rec.account === "string" ? rec.account : null;
    const destination = typeof rec.destination === "string" ? rec.destination : null;
    if (!account || !destination || account === destination) continue;
    const hop = {
      to: destination,
      from: account,
      amountDrops:
        typeof rec.amountDrops === "number" && Number.isFinite(rec.amountDrops) ? rec.amountDrops : null,
      txHash: typeof rec.hash === "string" ? rec.hash : null,
      ledgerSeq:
        typeof rec.ledgerSeq === "number" && Number.isFinite(rec.ledgerSeq) ? rec.ledgerSeq : null,
    };
    // V2-Fingerprint-Rohstoffe (nur In-Memory; vor der Ketten-Ausgabe wieder
    // entfernt — persistierte Hops bleiben byte-neutral zum bisherigen Vertrag):
    if (typeof rec.feeDrops === "number" && Number.isFinite(rec.feeDrops)) hop.feeDrops = rec.feeDrops;
    if (typeof rec.destinationTag === "number" && Number.isFinite(rec.destinationTag)) hop.destinationTag = rec.destinationTag;
    if (typeof rec.sourceTag === "number" && Number.isFinite(rec.sourceTag)) hop.sourceTag = rec.sourceTag;
    txHops.push(hop);
  }
  // Ketten-Nachbarschaft = Kanten auf einem gerichteten Pfad von einem
  // geflaggten Seed zu einem geflaggten Endpunkt (Forward-BFS ab Seeds über
  // alle tx, Rückwärts-BFS ab Seeds über eingehende tx). Eine tx ist
  // Ketten-Kante genau dann, wenn ihr Ursprung von einem Seed erreichbar ist
  // UND ihr Ziel einen Seed erreichen kann. Alltags-Tx (etwa 21 Zahlungen
  // eines Zwischenkontos an nie-kettenerreichbare Gegenparteien) fallen aus
  // dieser Nachbarschaft raus — sie machen aus einem Relay keinen
  // Multi-Grad-Knoten und keinen Hub (Hub bleibt der FLAGGE-Grad > 20).
  const fwdOut = new Map(); // from -> [to] (BFS-Adjazenz, alle tx)
  const fwdIn = new Map();  // to -> [from]
  for (const hop of txHops) {
    if (!fwdOut.has(hop.from)) fwdOut.set(hop.from, []);
    fwdOut.get(hop.from).push(hop.to);
    if (!fwdIn.has(hop.to)) fwdIn.set(hop.to, []);
    fwdIn.get(hop.to).push(hop.from);
  }
  const bfs = (starts, adj) => {
    const seen = new Set(starts);
    let frontier = [...seen];
    while (frontier.length) {
      const next = [];
      for (const id of frontier) {
        for (const nb of adj.get(id) ?? []) {
          if (!seen.has(nb)) {
            seen.add(nb);
            next.push(nb);
          }
        }
      }
      frontier = next;
    }
    return seen;
  };
  const seedList = [...severityOf.keys()];
  const fromSeed = bfs(seedList, fwdOut); // von einem Seed erreichbar
  const toSeed = bfs(seedList, fwdIn);    // kann einen Seed erreichen
  const chainOut = new Map();
  const chainIn = new Map();
  for (const hop of txHops) {
    if (!fromSeed.has(hop.from) || !toSeed.has(hop.to)) continue;
    if (!chainOut.has(hop.from)) chainOut.set(hop.from, []);
    chainOut.get(hop.from).push(hop);
    if (!chainIn.has(hop.to)) chainIn.set(hop.to, []);
    chainIn.get(hop.to).push(hop);
  }
  // Deterministische Totalordnung aller tx-Hops (cmpEdge-Muster :69-109:
  // ledgerSeq asc, txHash asc, Endpunkte asc) — die txRecords-Reihenfolge
  // entscheidet nie, auch nicht über die iterative Nachbarschaftsbildung.
  txHops.sort(
    (a, b) =>
      (a.ledgerSeq ?? -1) - (b.ledgerSeq ?? -1) ||
      cmpStr(String(a.txHash ?? ""), String(b.txHash ?? "")) ||
      cmpStr(a.from, b.from) ||
      cmpStr(a.to, b.to)
  );
  // Remainder-Abgangs-Sicht NACH der Totalordnung aufbauen: der Peel-Pick
  // (erster qualifizierender Abgang) läuft damit deterministisch über die
  // sortierte Liste — die txRecords-Reihenfolge entscheidet nie.
  const allOutHops = new Map(); // from -> [hop] (ALLE ausgehenden tx mit Betrag)
  for (const hop of txHops) {
    if (!allOutHops.has(hop.from)) allOutHops.set(hop.from, []);
    allOutHops.get(hop.from).push(hop);
  }
  // Nachbar-Listen asc sortiert (Muster flowPaths :566).
  const sortOut = (list) =>
    list.sort(
      (a, b) =>
        cmpStr(a.to, b.to) ||
        (a.ledgerSeq ?? -1) - (b.ledgerSeq ?? -1) ||
        cmpStr(String(a.txHash ?? ""), String(b.txHash ?? ""))
    );
  const sortIn = (list) =>
    list.sort(
      (a, b) =>
        cmpStr(a.from, b.from) ||
        (a.ledgerSeq ?? -1) - (b.ledgerSeq ?? -1) ||
        cmpStr(String(a.txHash ?? ""), String(b.txHash ?? ""))
    );
  for (const list of chainOut.values()) sortOut(list);
  for (const list of chainIn.values()) sortIn(list);

  // Striktes 1:1-Relay in der Ketten-Nachbarschaft: genau ein Ketten-Eingang
  // und genau ein Ketten-Ausgang, Grad <= maxDegree, kein Hub, nicht geflaggt.
  // Alltags-Tx (zwischen zwei nie-kettenerreichbaren Knoten) erscheinen in
  // dieser Nachbarschaft nicht und machen aus einem Relay keinen Multi-Grad-
  // Knoten; ein Knoten mit > 20 FLAGGE-Kanten ist Hub und wird nie gebridgt.
  const relayOk = (id) => {
    if (severityOf.has(id)) return false; // geflaggte Knoten enden, nie durchwandern
    if (isHub(id)) return false;
    const outN = chainOut.get(id)?.length ?? 0;
    const inN = chainIn.get(id)?.length ?? 0;
    if (outN + inN > maxDegree) return false;
    return outN === 1 && inN === 1;
  };

  // Hop-Bedingung: XRP-Betrag (IOU/null scheidet aus), über der Bagatell-
  // grenze (amountDrops <= dustDrops bricht), und Weiterleitungs-Verhältnis
  // im Fenster [minRatio, maxRatio].
  const hopOk = (hop, inDrops) => {
    const out = hop.amountDrops;
    if (typeof out !== "number" || !(out > th.dustDrops)) return null;
    if (!(inDrops > 0)) return null;
    const ratio = out / inDrops;
    if (!(ratio >= th.minRatio && ratio <= th.maxRatio)) return null;
    return ratio;
  };

  // Remainder-Rinne (V1b, PEELING_REMAINDER_THRESHOLDS): Hop qualifiziert
  // zusätzlich, wenn out/in >= rth.minRatio UND ein beobachteter kleiner
  // Abgang ("der Abgeschälte") vom selben Konto an ein NICHT-Kettenglied im
  // Block-Fenster existiert — > dustDrops (Dust ist dusting-Zuständigkeit)
  // und <= rth.peelMaxFraction des Relay-Eingangs (DFRWS Peel-Percentage).
  // FP-Guard: ohne beobachteten Abgang KEINE Remainder-Qualifikation — reine
  // Weiterleitung >= 95 % ist Sweep und bleibt drainer-sweep-Zuständigkeit.
  // Rückgabe { ratio, peelDrops }: der Peel-Betrag ist V2-Fingerprint-Rohstoff
  // (identische Peel-Beträge = Programm-Verteilungssignal; Hop-Beträge sinken
  // kettenmathematisch streng monoton und können nie duplizieren).
  const remainderHopOk = (hop, inDrops, chainAddresses) => {
    const out = hop.amountDrops;
    if (typeof out !== "number" || !(out > th.dustDrops)) return null;
    if (!(inDrops > 0)) return null;
    const ratio = out / inDrops;
    if (!(ratio >= rth.minRatio) || !(ratio < rth.maxRatio)) return null;
    const outs = allOutHops.get(hop.from) ?? [];
    let peelDrops = null;
    for (const o of outs) {
      if (o.to === hop.to || chainAddresses.includes(o.to)) continue;
      if (typeof o.amountDrops !== "number") continue;
      if (o.amountDrops > th.dustDrops && o.amountDrops <= rth.peelMaxFraction * inDrops) {
        peelDrops = o.amountDrops;
        break;
      }
    }
    return peelDrops != null ? { ratio, peelDrops } : null;
  };

  // 5) Wanderung ab Seeds (asc sortiert, maxSeeds-Kappe). Der erste Hop ist
  // die Aussendung des Seeds: nur Bagatellgrenze (amountDrops > dustDrops),
  // KEIN Ratio-Fenster — das Verhältnis wird je RELAY gemessen (out/in am
  // Zwischenknoten), der Seed hat keinen gemessenen Eingang. Ein Hop endet
  // die Kette, wenn der Zielknoten geflaggt ist (Fund-Ende) — dann zählt er
  // als Hop; sonst muss er strikter 1:1-Relay sein und wird durchwandert.
  // Hops tragen intern feeDrops/destinationTag/sourceTag für den
  // V2-Fingerprint; diese Felder werden vor der Ketten-Ausgabe entfernt
  // (persistierte Hops bleiben byte-neutral).
  const hopOut = (from, hop, ratio) => {
    const h = {
      from,
      to: hop.to,
      amountDrops: hop.amountDrops,
      ratio,
      txHash: hop.txHash,
      ledgerSeq: hop.ledgerSeq,
    };
    if (hop.feeDrops != null) h.feeDrops = hop.feeDrops;
    if (hop.destinationTag != null) h.destinationTag = hop.destinationTag;
    if (hop.sourceTag != null) h.sourceTag = hop.sourceTag;
    return h;
  };
  const chains = [];
  const seenSignatures = new Set();
  const seeds = [...severityOf.keys()].sort(cmpStr).slice(0, maxSeeds);
  for (const seed of seeds) {
    const firstOuts = chainOut.get(seed) ?? [];
    for (const firstHop of firstOuts) {
      if (chains.length >= maxChains) break;
      const inDrops = firstHop.amountDrops;
      if (typeof inDrops !== "number" || !(inDrops > th.dustDrops)) continue;
      const addresses = [seed, firstHop.to];
      const hops = [hopOut(seed, firstHop, null)]; // Seed-Hop: kein Verhältnis
      let current = firstHop.to;
      let currentIn = inDrops;
      let remainderHops = 0; // Hops der Remainder-Rinne (V1b)
      // Längengrenze maxChainLen (Kanten), Zykelschutz über addresses.
      while (hops.length < maxChainLen) {
        if (severityOf.has(current)) break; // Fund-Ende: Kette abgeschlossen
        if (!relayOk(current)) break;      // kein striktes 1:1-Relay: Abbruch
        const next = (chainOut.get(current) ?? [])[0];
        if (!next) break;
        if (addresses.includes(next.to)) break; // Zykel
        let r = hopOk(next, currentIn);
        let peelDrops = null;
        if (r == null) {
          // Remainder-Rinne (V1b): Großrest-Weiterleitung >= 95 % MIT
          // beobachtetem kleinen Abgang.
          const rem = remainderHopOk(next, currentIn, addresses);
          if (rem != null) {
            r = rem.ratio;
            peelDrops = rem.peelDrops;
            remainderHops += 1;
          }
        }
        if (r == null) break;
        addresses.push(next.to);
        const hopObj = hopOut(current, next, r);
        if (peelDrops != null) hopObj.peelDrops = peelDrops; // V2-Rohstoff (intern)
        hops.push(hopObj);
        current = next.to;
        currentIn = next.amountDrops;
      }
      // Mindest-Hopzahl: klassische Rinne th.minHops (3); Remainder-Ketten
      // (>= 1 Remainder-Hop) gelten ab rth.minHops (2) — DFRWS: 42,6 % der
      // Ketten haben 2 Runden.
      const minHopsEff = remainderHops > 0 ? rth.minHops : th.minHops;
      if (hops.length < minHopsEff) continue;
      const signature = addresses.join(",");
      if (seenSignatures.has(signature)) continue;
      seenSignatures.add(signature);
      // V2-Fingerprint auf der vollen Hop-Sicht (inkl. Fee/Tags), dann
      // interne Felder entfernen — persistierte Ketten tragen nur
      // {score, criteria} (+ confidence bei Score >= highScore).
      const fingerprint = peelChainFingerprint({ hops });
      for (const h of hops) {
        delete h.feeDrops;
        delete h.destinationTag;
        delete h.sourceTag;
        delete h.peelDrops;
      }
      chains.push({
        addresses,
        hops,
        seed,
        seedSeverity: severityOf.get(seed),
        hopsCount: hops.length,
        bridges: addresses.filter((a) => !severityOf.has(a)).sort(cmpStr),
        signature,
        ...(remainderHops > 0 ? { remainderHops } : {}),
        fingerprint,
        ...(fingerprint.score >= PEELING_FINGERPRINT_THRESHOLDS.highScore ? { confidence: "high" } : {}),
      });
    }
    if (chains.length >= maxChains) break;
  }

  // 6) Deterministische Ausgabe: Ketten nach Signatur asc; hops sind bereits
  // in Wanderordnung (chronologisch durch die sortierten Nachbar-Listen) und
  // werden auf die cmpEdge-Totalordnung (ledgerSeq asc, txHash asc) gebracht.
  chains.sort((a, b) => cmpStr(a.signature, b.signature));
  for (const c of chains) {
    c.hops.sort((a, b) => {
      const la = a.ledgerSeq == null ? -1 : a.ledgerSeq;
      const lb = b.ledgerSeq == null ? -1 : b.ledgerSeq;
      if (la !== lb) return la - lb;
      return cmpStr(String(a.txHash ?? ""), String(b.txHash ?? ""));
    });
  }
  return chains;
}

// =====================================================================
// V1a — Cross-Block-Peeling über den akkumulierten Flow-State-Kantensatz.
// detectPeelingChainsOverEdges(edges, flaggedAddresses, opts).
//
// QUELLE/BEGÜNDUNG: DFRWS 2023 (Gong et al.) — 79 % der Peel-Chains laufen
// in < 24 h ab, > 50 % in < 1 h. Der bisherige Block-Walk sieht nur den
// einzelnen 4-s-Block (L1 der Lückenanalyse): 3+ Hops derselben Kette sind
// blocklokal praktisch nie sichtbar. Dieser Walk läuft über die pro Cluster
// akkumulierten Top-K-Kanten (inkl. Chrono-Anker, lib/ledger-walk.mjs) und
// öffnet damit die Zeitdimension — aufgerufen als Tick-Schritt nach dem
// Walk in lib/ledger-walk.mjs advance().
//
// STRUKTURELLE SICHTBARKEITSGRENZE (dokumentiert, ehrlich): State-Kanten
// entstehen nur für tx mit geflaggtem Endpunkt zur Blockzeit
// (buildClusterGraph-Kantenregel). Eine Kante relay→relay zwischen zwei
// NIE geflaggten Konten ist im State unsichtbar — der Cross-Block-Walk
// überbrückt sie nicht (der Block-Walk tut es, dort aber nur blocklokal).
// Sichtbar werden Ketten, deren Hops jeweils mindestens einen (auch erst
// SPÄTER akkumuliert geflaggten) Endpunkt haben: geflaggte Zwischenknoten
// werden deshalb hier DURCHWANDERT (im Block-Walk beenden sie die Kette) —
// sie bleiben Fund-Adressen (nie bridges), nur die Kanten-Sichtbarkeit
// unterscheidet die beiden Walks.
//
// Zeitfenster (CROSS_BLOCK_PEELING_THRESHOLDS): Kanten innerhalb 24 h
// (79-%-Quantil, End-zu-Ende-Spanne über closeTime) UND Hop-Abstände
// <= maxHopGapLedgers (63,6-%-Intervall plus Toleranz). Fehlende oder
// unparsebare Werte übergehen die jeweilige Prüfung (nicht messbar statt
// raten).
//
// Remainder-Rinne (V1b) läuft hier bewusst NICHT: der kleine Abgang eines
// ungeflaggten Relays an ein ungeflagtes Ziel ist keine State-Kante — der
// beobachtete Peel ist nur im Block-Fenster sichtbar (Block-Walk).
//
// FP-Schutz: Seeds ausschließlich flaggedAddresses; striktes 1:1 je
// Zwischenknoten (genau EIN Eingang über ALLE Kanten, genau EIN Ausgang);
// Hub-Schutz (ungeflaggt, Grad > 20 über alle Kanten); Ratio-Fenster wie
// Block-Walk; Zykelschutz; Kappen maxSeeds/maxChainLen/maxDegree/maxChains.
//
// Ausgabe: Ketten-Vertrag wie detectPeelingChains (+ fingerprint; ohne
// remainderHops — siehe oben) — sortiert nach Signatur asc, hops in
// Wanderordnung. Fundklasse bleibt 'suspect' (kein Schuldnachweis).
// =====================================================================
export function detectPeelingChainsOverEdges(edges, flaggedAddresses, opts = {}) {
  const th = {
    ...CROSS_BLOCK_PEELING_THRESHOLDS,
    ...(opts.thresholds && typeof opts.thresholds === "object" ? opts.thresholds : {}),
  };
  const maxSeeds = Number.isFinite(opts.maxSeeds) ? Math.max(0, Math.floor(opts.maxSeeds)) : 50;
  const maxChainLen = Number.isFinite(opts.maxChainLen) ? Math.max(1, Math.floor(opts.maxChainLen)) : 8;
  const maxDegree = Number.isFinite(opts.maxDegree) ? Math.max(1, Math.floor(opts.maxDegree)) : 4;
  const maxChains = Number.isFinite(opts.maxChains) ? Math.max(0, Math.floor(opts.maxChains)) : 20;

  // 1) Seeds: nur geflaggte Adressen, severity pro Adresse = max.
  const severityOf = new Map();
  for (const f of Array.isArray(flaggedAddresses) ? flaggedAddresses : []) {
    const addr = typeof f?.address === "string" ? f.address : null;
    if (!addr) continue;
    const sev = SEVERITY_RANK[f?.severity] ? f.severity : "info";
    const cur = severityOf.get(addr);
    if (!cur || SEVERITY_RANK[sev] > SEVERITY_RANK[cur]) severityOf.set(addr, sev);
  }
  if (!severityOf.size) return [];

  // 2) Kanten normalisieren (State-Kanten-Vertrag: from/to/amountDrops/
  // txHash/ledgerSeq/closeTime, optional toTag/fromTag — Registry-Verfeinerung
  // für die Tag-Wiederverwendung des V2-Fingerprints).
  const hops = [];
  for (const e of Array.isArray(edges) ? edges : []) {
    if (!e || typeof e !== "object") continue;
    const from = typeof e.from === "string" && e.from ? e.from : null;
    const to = typeof e.to === "string" && e.to ? e.to : null;
    if (!from || !to || from === to) continue;
    const hop = {
      from,
      to,
      amountDrops:
        typeof e.amountDrops === "number" && Number.isFinite(e.amountDrops) ? e.amountDrops : null,
      txHash: typeof e.txHash === "string" ? e.txHash : null,
      ledgerSeq:
        typeof e.ledgerSeq === "number" && Number.isFinite(e.ledgerSeq) ? e.ledgerSeq : null,
      closeTime: typeof e.closeTime === "string" && e.closeTime ? e.closeTime : null,
    };
    if (typeof e.toTag === "number" && Number.isFinite(e.toTag)) hop.destinationTag = e.toTag;
    if (typeof e.fromTag === "number" && Number.isFinite(e.fromTag)) hop.sourceTag = e.fromTag;
    hops.push(hop);
  }
  if (!hops.length) return [];

  // Deterministische Totalordnung (cmpEdge-Muster): ledgerSeq asc, txHash asc,
  // Endpunkte asc — die Kanten-Reihenfolge entscheidet nie.
  hops.sort(
    (a, b) =>
      (a.ledgerSeq ?? -1) - (b.ledgerSeq ?? -1) ||
      cmpStr(String(a.txHash ?? ""), String(b.txHash ?? "")) ||
      cmpStr(a.from, b.from) ||
      cmpStr(a.to, b.to)
  );

  // 3) Adjazenzen: alle Aus-/Eingänge je Knoten (sortiert); Grad über ALLE
  // Kanten (Hub-Messung). Nur vorwärts erreichbare Knoten ab Seeds bilden
  // die Wanderungs-Nachbarschaft — im Gegensatz zum Block-Walk gibt es keine
  // Alltags-Tx-Flut (State-Kanten sind evidenzgetragen), und Ketten dürfen
  // an Nicht-Seed-Senken enden.
  const outAll = new Map(); // from -> [hop] (asc sortiert)
  const inAll = new Map();  // to -> [hop]
  const degree = new Map();
  for (const hop of hops) {
    if (!outAll.has(hop.from)) outAll.set(hop.from, []);
    outAll.get(hop.from).push(hop);
    if (!inAll.has(hop.to)) inAll.set(hop.to, []);
    inAll.get(hop.to).push(hop);
    degree.set(hop.from, (degree.get(hop.from) ?? 0) + 1);
    degree.set(hop.to, (degree.get(hop.to) ?? 0) + 1);
  }
  for (const list of outAll.values()) {
    list.sort(
      (a, b) =>
        cmpStr(a.to, b.to) ||
        (a.ledgerSeq ?? -1) - (b.ledgerSeq ?? -1) ||
        cmpStr(String(a.txHash ?? ""), String(b.txHash ?? ""))
    );
  }
  const HUB_DEGREE = 20; // Skala wie HUB_UNION_DEGREE (buildClusterGraph)
  const isHub = (id) => !severityOf.has(id) && (degree.get(id) ?? 0) > HUB_DEGREE;

  // Vorwärts-Erreichbarkeit ab Seeds (BFS) — begrenzt die Wanderung.
  const fwd = bfsForward([...severityOf.keys()], outAll);

  // 4) Hop-Bedingung: XRP-Betrag über Bagatellgrenze, Ratio im klassischen
  // Fenster, Hop-Gap <= maxHopGapLedgers (beide ledgerSeq vorhanden).
  const hopOk = (hop, inDrops, prevSeq) => {
    const out = hop.amountDrops;
    if (typeof out !== "number" || !(out > th.dustDrops)) return null;
    if (!(inDrops > 0)) return null;
    const ratio = out / inDrops;
    if (!(ratio >= th.minRatio && ratio <= th.maxRatio)) return null;
    if (prevSeq != null && hop.ledgerSeq != null && Math.abs(hop.ledgerSeq - prevSeq) > th.maxHopGapLedgers) {
      return null; // Zeitdimension: Hop-Abstand über dem 63,6-%-Deckel
    }
    return ratio;
  };

  // Zwischenknoten-Bedingung: striktes 1:1 über ALLE Kanten (genau ein
  // Eingang, genau ein Ausgang — Side-Inkommen bricht die Relay-Reinheit),
  // Grad <= maxDegree, kein Hub. Geflaggte Knoten sind hier durchwanderbar
  // (siehe Kopfkommentar), bleiben aber Fund-Adressen.
  const stepOk = (id) => {
    if (isHub(id)) return false;
    const outN = outAll.get(id)?.length ?? 0;
    const inN = inAll.get(id)?.length ?? 0;
    if (outN + inN > maxDegree) return false;
    return outN === 1 && inN === 1;
  };

  const epochOfHop = (hop) => epochOf(hop.closeTime);

  // 5) Wanderung ab Seeds (asc, maxSeeds-Kappe).
  const chains = [];
  const seenSignatures = new Set();
  const seeds = [...severityOf.keys()].sort(cmpStr).slice(0, maxSeeds);
  for (const seed of seeds) {
    const firstOuts = (outAll.get(seed) ?? []).filter((hop) => fwd.has(hop.to));
    for (const firstHop of firstOuts) {
      if (chains.length >= maxChains) break;
      const inDrops = firstHop.amountDrops;
      if (typeof inDrops !== "number" || !(inDrops > th.dustDrops)) continue;
      const addresses = [seed, firstHop.to];
      const outHops = [
        {
          from: seed,
          to: firstHop.to,
          amountDrops: inDrops,
          ratio: null, // Seed-Hop: kein gemessener Eingang
          txHash: firstHop.txHash,
          ledgerSeq: firstHop.ledgerSeq,
          ...(firstHop.closeTime ? { closeTime: firstHop.closeTime } : {}),
          ...(firstHop.destinationTag != null ? { destinationTag: firstHop.destinationTag } : {}),
          ...(firstHop.sourceTag != null ? { sourceTag: firstHop.sourceTag } : {}),
        },
      ];
      let current = firstHop.to;
      let currentIn = inDrops;
      let prevSeq = firstHop.ledgerSeq;
      while (outHops.length < maxChainLen) {
        if (!stepOk(current)) break;   // kein striktes 1:1 / Hub / Grad-Kappe
        const next = (outAll.get(current) ?? [])[0];
        if (!next) break;
        if (addresses.includes(next.to)) break; // Zykel
        const r = hopOk(next, currentIn, prevSeq);
        if (r == null) break;
        addresses.push(next.to);
        outHops.push({
          from: current,
          to: next.to,
          amountDrops: next.amountDrops,
          ratio: r,
          txHash: next.txHash,
          ledgerSeq: next.ledgerSeq,
          ...(next.closeTime ? { closeTime: next.closeTime } : {}),
          ...(next.destinationTag != null ? { destinationTag: next.destinationTag } : {}),
          ...(next.sourceTag != null ? { sourceTag: next.sourceTag } : {}),
        });
        current = next.to;
        currentIn = next.amountDrops;
        prevSeq = next.ledgerSeq;
      }
      if (outHops.length < th.minHops) continue;
      // 24-h-Fenster (79-%-Quantil): End-zu-Ende-Spanne der parsebaren
      // closeTimes. Weniger als 2 parsebare Zeitstempel -> nicht messbar,
      // Prüfung übergangen (dokumentierte Grenze, kein Raten).
      const epochs = outHops.map(epochOfHop).filter((ms) => ms !== -1);
      if (epochs.length >= 2 && Math.max(...epochs) - Math.min(...epochs) > th.windowMs) continue;
      const signature = addresses.join(",");
      if (seenSignatures.has(signature)) continue;
      seenSignatures.add(signature);
      // V2-Fingerprint (Kanten-Sicht: Betrag/Intervall/Tag; Fee fehlt hier
      // bewusst — State-Kanten persistieren keine Fees, Byte-Budget).
      const fingerprint = peelChainFingerprint({ hops: outHops });
      for (const h of outHops) {
        delete h.closeTime;
        delete h.destinationTag;
        delete h.sourceTag;
      }
      chains.push({
        addresses,
        hops: outHops,
        seed,
        seedSeverity: severityOf.get(seed),
        hopsCount: outHops.length,
        bridges: addresses.filter((a) => !severityOf.has(a)).sort(cmpStr),
        signature,
        fingerprint,
        ...(fingerprint.score >= PEELING_FINGERPRINT_THRESHOLDS.highScore ? { confidence: "high" } : {}),
      });
    }
    if (chains.length >= maxChains) break;
  }

  // 6) Deterministische Ausgabe wie der Block-Walk.
  chains.sort((a, b) => cmpStr(a.signature, b.signature));
  for (const c of chains) {
    c.hops.sort((a, b) => {
      const la = a.ledgerSeq == null ? -1 : a.ledgerSeq;
      const lb = b.ledgerSeq == null ? -1 : b.ledgerSeq;
      if (la !== lb) return la - lb;
      return cmpStr(String(a.txHash ?? ""), String(b.txHash ?? ""));
    });
  }
  return chains;
}

// Vorwärts-BFS ab Seeds über outAll — Mengen der erreichbaren Knoten.
function bfsForward(starts, outAll) {
  const seen = new Set(starts);
  let frontier = [...seen];
  while (frontier.length) {
    const next = [];
    for (const id of frontier) {
      for (const hop of outAll.get(id) ?? []) {
        if (!seen.has(hop.to)) {
          seen.add(hop.to);
          next.push(hop.to);
        }
      }
    }
    frontier = next;
  }
  return seen;
}

// =====================================================================
// V3 — Temporale Metriken pro Konto (rein, deterministisch, keine Requests).
// QUELLE/BEGÜNDUNG: zeitliche Merkmale sind die tragende Gruppe der
// Forschung 2024-2026 (Temporal Graph Networks, arXiv 3/2024; Event-
// Temporal-GNN, ACM 10/2025; Hawkes-Burstiness) — hier als deterministische
// Zähler ohne Lernarchitektur (Determinismus-Gebot, cluster.mjs:7-8).
//
// SERIE (von lib/ledger-walk.mjs mergeCluster akkumuliert, gedeckelt):
//   temporal: { [adresse]: { s: number[] (ledgerSeq der AUSgehenden
//   Kanten, asc, <= TEMPORAL_SERIES_CAP), out: XRP-out-Summe der Serie,
//   outN: Anzahl Aus-Kanten } } — pro Cluster maximal TEMPORAL_MAX_ADDRESSES
//   Evidenz-Adressen (severity/Rolle drainer|collector/mainDrainers/
//   collectors; FP-Guard a: kein Global-Scan). Registry-/well-known-Konten
//   werden NIE gesammelt (FP-Guard b, injizierbare multiUserAccounts-Map).
//
// METRIKEN (temporalMetrics, rein): burst (max. Anzahl Serien-Punkte in
// k=10 aufeinanderfolgenden Ledgern — DFRWS-Intervall-Quantil),
// medianInterarrival (Median der Ledger-Abstände), velocityOutPerHour
// (out normalisiert auf die Serien-Spanne in Stunden, 4 s/Ledger),
// ageVolumeScore (Spanne < 24 h UND out >= 500 XRP UND outN >= 5 —
// FP-Guard c: keine absolute Volumenschwelle ohne Alters-Normierung),
// automated (burst >= 5 UND medianInterarrival <= 2).
//
// FP-Guard d (VERPFLICHTEND): Metriken sind NUR Zusatz-Attribute für
// Analysten/View — keine eigene malicious-Quelle, kein Severity-Einfluss,
// kein Auto-Eskalations-Pfad. Das Severity-Enum bleibt
// 'malicious'|'suspect'|'info' (detector.mjs).
// =====================================================================
export const LEDGER_INTERVAL_MS = 4000; // XRPL-Konsensus ~4 s pro Ledger

export const TEMPORAL_THRESHOLDS = {
  burstWindowLedgers: 10,          // k=10 aufeinanderfolgende Blöcke (DFRWS)
  burstMin: 5,                     // burst >= 5 UND Median <= 2 -> 'automatisiert'
  medianInterarrivalMax: 2,
  dayLedgers: 21600,               // 24 h in Ledgern (4 s/Ledger)
  ageVolumeMinOutDrops: 500000000, // 500 XRP (5e8 drops)
  ageVolumeMinOutN: 5,             // fan-out ab 5 Aus-Kanten
};

export const TEMPORAL_SERIES_CAP = 16;   // Serie je Adresse (LRU: neueste)
export const TEMPORAL_MAX_ADDRESSES = 4; // Adressen je Cluster (Byte-Budget)

// Rein deterministisch; defensive Coercion (kaputte/leere Serie -> Nullwerte
// statt Wurf — persistierte Bestände können ältere Formen tragen).
export function temporalMetrics(entry, opts = {}) {
  const th = {
    ...TEMPORAL_THRESHOLDS,
    ...(opts && typeof opts === "object" ? opts : {}),
  };
  // Number(null) === 0 wäre ein gefälschter Ledger-0-Punkt — null/undefined
  // fallen VOR der Numerisch-Coercion raus (Befund aus dem Coercion-Test).
  const seqs = (Array.isArray(entry?.s) ? entry.s : [])
    .filter((v) => v != null)
    .map((v) => Number(v))
    .filter((v) => Number.isFinite(v))
    .sort((a, b) => a - b);
  const outDrops = Math.max(0, Number(entry?.out) || 0);
  const outN = Math.max(0, Math.floor(Number(entry?.outN) || 0));

  // burst: gleitendes Fenster der Breite burstWindowLedgers über die
  // aufsteigend sortierte Serie (zwei Punkte im selben Ledger zählen beide).
  let burst = 0;
  if (seqs.length) {
    for (let i = 0; i < seqs.length; i++) {
      let j = i;
      while (j < seqs.length && seqs[j] - seqs[i] <= th.burstWindowLedgers) j++;
      if (j - i > burst) burst = j - i;
    }
  }

  // medianInterarrival: Median der aufeinanderfolgenden Abstände (null bei
  // weniger als 2 Punkten — nicht messbar statt raten).
  const gaps = [];
  for (let i = 1; i < seqs.length; i++) gaps.push(seqs[i] - seqs[i - 1]);
  const medianInterarrival = gaps.length ? medianOf(gaps) : null;

  // velocityOutPerHour: out-Drops pro Stunde über die Serien-Spanne.
  let velocityOutPerHour = null;
  if (seqs.length >= 2) {
    const hours = ((seqs[seqs.length - 1] - seqs[0]) * LEDGER_INTERVAL_MS) / 3600000;
    if (hours > 0) velocityOutPerHour = outDrops / hours;
  }

  // ageVolumeScore: Konto jünger als 24 h (Serien-Spanne) UND Volumen UND
  // fan-out — nie ein Kriterium allein (FP-Guard c).
  const spanLedgers = seqs.length >= 2 ? seqs[seqs.length - 1] - seqs[0] : null;
  const ageVolumeScore =
    spanLedgers != null
      ? spanLedgers < th.dayLedgers && outDrops >= th.ageVolumeMinOutDrops && outN >= th.ageVolumeMinOutN
      : false;

  const automated = burst >= th.burstMin && medianInterarrival != null && medianInterarrival <= th.medianInterarrivalMax;

  return { burst, medianInterarrival, velocityOutPerHour, ageVolumeScore, automated };
}

// =====================================================================
// V4 — Motiv-Zähler (rein, deterministisch, +0 Requests, O(E) im Speicher).
// QUELLE/BEGÜNDUNG: kanonische AML-Typologien (Altman-GNN/LAS-GNN-Fan-In-/
// Fan-Out-Motive, Papier :208-226) als deterministische Zähler OHNE
// Lernarchitektur (Determinismus-Gebot, cluster.mjs:7-8). Zwei Motive:
//
//   gather-scatter — fanIn ≥ gatherMinFan ∧ fanOut ≥ gatherMinFan am selben
//     Knoten (mindestens je 3 VERSCHIEDENE Gegenparteien). Rein informativ:
//     note-Attribut im State/View, NIE Rollen- oder Severity-Änderung
//     (FP-Guard analog Temporal FP-Guard d).
//   wash-cycle (Katalog 'wash-cycle') — A→B ∧ B→A mit ≥ cycleMinEdgesPerSide
//     Kanten JE Richtung (Einzel-Kanten-Paare sind normale Markt-/
//     Rückerstattungs-Bewegungen und bleiben exempt), Volumenerhalt
//     conserve = min(fwdSum,bwdSum)/max(...) ≥ cycleConserveMin
//     (Gebühren-Toleranz), End-zu-Ende-Fenster ≤ cycleWindowMs über
//     closeTime (< 2 parsebare Zeitstempel -> Prüfung übergangen, "nicht
//     messbar statt raten" wie cluster.mjs:1456-1458).
//
// Kanten-Filter (FP-Guards): nur XRP-Kanten (amountDrops endlich; IOU =
// DEX-normal, ausgeschlossen), Selbstkanten ausgeschlossen (wash-self-
// transfer-Domäne, detector.mjs), Endpunkte NIE im exclude-Set (Exchange-
// Registry ∪ multiUser ∪ benign — "Registry nie Zykelglied", injizierbar
// wie multiUserAccounts).
//
// VERDRAHTUNG (Korrektur P2/Cross-Block): NICHT je Block gerechnet — der
// Aufrufer (lib/ledger-walk.mjs mergeCluster) reicht den AKKUMULIERTEN,
// gekappten Kantensatz (maxClusterEdges) hier ein, sodass ein über Blöcke
// verteilter Zyklus im Aggregate vereint wird. Signatur = 'a,b' (a<b, Dedup-
// Key); Bestands-Union mit last-wins je Signatur macht capChains (ledger-
// walk.mjs) — bereits gefundene Zyklen überleben Kantenschwund im Top-K.
// =====================================================================
export const MOTIF_THRESHOLDS = {
  gatherMinFan: 3,        // fanIn/fanOut je ≥ 3 verschiedene Gegenparteien
  cycleMinEdgesPerSide: 2, // ≥ 2 Kanten je Richtung (Refund-Guard)
  cycleConserveMin: 0.8,  // min/max-Volumenerhalt (Gebühren-Toleranz)
  cycleWindowMs: 3600000, // End-zu-Ende-Fenster 1 h über closeTime
  maxCycles: 8,           // Kappe: Zyklen je Cluster (asc nach Signatur)
  maxGather: 8,           // Kappe: Gather-Scatter-Adressen je Cluster (asc)
};

export function motifCounters(edges, opts = {}) {
  const th = { ...MOTIF_THRESHOLDS, ...(opts && typeof opts === "object" ? opts : {}) };
  const exclude =
    opts.exclude instanceof Set
      ? opts.exclude
      : new Set(Array.isArray(opts?.exclude) ? opts.exclude : []);

  // 1) Qualifizierende Kanten sammeln: XRP, keine Selbstkante, Endpunkte
  //    nicht im exclude-Set. Parallel: fanIn/fanOut als DISTINCT-Gegenpartei-
  //    Mengen je Knoten, Kanten je Adresspaar in kanonischer Ordnung (a<b).
  const fanIn = new Map();  // addr -> Set(Gegenparteien, eingehend)
  const fanOut = new Map(); // addr -> Set(Gegenparteien, ausgehend)
  const perPair = new Map(); // "a\u0000b" -> { a, b, fwd: [Kanten], bwd: [Kanten] }
  for (const e of Array.isArray(edges) ? edges : []) {
    if (!e || typeof e !== "object") continue;
    const from = typeof e.from === "string" && e.from ? e.from : null;
    const to = typeof e.to === "string" && e.to ? e.to : null;
    if (!from || !to || from === to) continue; // Selbstkante: wash-self-transfer-Domäne
    if (exclude.has(from) || exclude.has(to)) continue; // Registry nie Motiv-Glied
    if (typeof e.amountDrops !== "number" || !Number.isFinite(e.amountDrops)) continue; // nur XRP
    let fi = fanIn.get(to);
    if (!fi) fanIn.set(to, (fi = new Set()));
    fi.add(from);
    let fo = fanOut.get(from);
    if (!fo) fanOut.set(from, (fo = new Set()));
    fo.add(to);
    const a = from < to ? from : to;
    const b = from < to ? to : from;
    const key = `${a}\u0000${b}`;
    let rec = perPair.get(key);
    if (!rec) perPair.set(key, (rec = { a, b, fwd: [], bwd: [] }));
    const edge = {
      drops: e.amountDrops,
      seq: typeof e.ledgerSeq === "number" && Number.isFinite(e.ledgerSeq) ? e.ledgerSeq : null,
      ts: epochOf(e.closeTime),
    };
    (from === a ? rec.fwd : rec.bwd).push(edge);
  }

  let fanInMax = 0;
  let fanOutMax = 0;
  for (const s of fanIn.values()) if (s.size > fanInMax) fanInMax = s.size;
  for (const s of fanOut.values()) if (s.size > fanOutMax) fanOutMax = s.size;

  // 2) Gather-Scatter: beide Fans ≥ gatherMinFan am selben Knoten. Determin-
  //    istisch adresse asc, Kappe maxGather.
  const gatherScatter = [...fanIn.keys()]
    .filter((a) => fanIn.get(a).size >= th.gatherMinFan && (fanOut.get(a)?.size ?? 0) >= th.gatherMinFan)
    .sort(cmpStr)
    .slice(0, Math.max(0, Math.floor(th.maxGather)));

  // 3) Wash-Zyklen: Paare in kanonischer Ordnung (a asc, b asc — die
  //    Einfügefolge der Map entscheidet nie), Bedingungsprüfung je Paar,
  //    Kappe maxCycles.
  const pairList = [...perPair.values()].sort((x, y) => cmpStr(x.a, y.a) || cmpStr(x.b, y.b));
  const washCycles = [];
  for (const rec of pairList) {
    if (washCycles.length >= Math.max(0, Math.floor(th.maxCycles))) break;
    if (rec.fwd.length < th.cycleMinEdgesPerSide || rec.bwd.length < th.cycleMinEdgesPerSide) continue;
    let fwdDrops = 0;
    let bwdDrops = 0;
    for (const e of rec.fwd) fwdDrops += e.drops;
    for (const e of rec.bwd) bwdDrops += e.drops;
    const hi = Math.max(fwdDrops, bwdDrops);
    if (!(hi > 0)) continue; // Nullvolumen: conserve nicht messbar -> kein Zyklus
    const conserve = Math.min(fwdDrops, bwdDrops) / hi;
    if (!(conserve >= th.cycleConserveMin)) continue;
    // 1-h-Fenster über ALLE Kanten des Zyklus; < 2 parsebare Zeitstempel ->
    // Prüfung übergangen (nicht messbar statt raten).
    const ts = [...rec.fwd, ...rec.bwd].map((e) => e.ts).filter((t) => t !== -1);
    if (ts.length >= 2 && Math.max(...ts) - Math.min(...ts) > th.cycleWindowMs) continue;
    const seqs = [...rec.fwd, ...rec.bwd].map((e) => e.seq).filter((s) => s != null);
    washCycles.push({
      a: rec.a,
      b: rec.b,
      fwdDrops,
      bwdDrops,
      conserve,
      firstLedgerSeq: seqs.length ? Math.min(...seqs) : null,
      lastLedgerSeq: seqs.length ? Math.max(...seqs) : null,
      signature: `${rec.a},${rec.b}`,
    });
  }

  return { gatherScatter, washCycles, fanInMax, fanOutMax };
}
