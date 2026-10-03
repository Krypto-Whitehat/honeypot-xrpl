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
//             iouValue (optional {currency, issuer, value}) }
// finding:  { ruleId, severity, address, note (optional) } — exakt wie
//           analyzeLedger sie liefert (lib/detector.mjs).
// Edge:     { from, to, type, amountDrops, txHash, ledgerSeq, closeTime,
//             severity, iouValue (optional) }
// Cluster:  { id, label, memberAddresses, roles, totalDrops, txCount,
//             distinctAccounts, firstSeen, lastSeen, mainDrainers, collectors,
//             iouFlows }
// role ∈ { 'source', 'drainer', 'collector', 'relay', 'unknown' }
// opts: { maxEdges = 2000, minClusterSize = 2, thresholds? }
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
// Eingang, genau ein Ausgang) durchgewandert und erhalten NIE eine Rolle und
// NIE severityByAddress — cluster.mjs schreibt Severity nur für Fund-Adressen
// (:465), und der Hub-Schnitt (:327-333) bleibt bestehen. Fundklasse der
// Ketten ist 'suspect' (kein Schuldnachweis). Die Schwellen
// PEELING_THRESHOLDS (0.6/0.95/minHops 3/dustDrops 100) sind ausdrücklich
// Tuning-Defaults OHNE reproduzierten Kampagnen-Fall (cluster.mjs verlangt
// sonst einen).

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
  if (typeof tx.Destination === "string" && tx.Destination) rec.destination = tx.Destination;
  // Gegenbewegungs-Typen: reale Geldbewegung ohne Destination-Feld bekommt
  // ihren Gegenpartner als destination (EscrowFinish/Cancel -> Owner,
  // CheckCash -> CheckDestination, VaultWithdraw -> VaultOwner,
  // NFTokenAcceptOffer -> NFTokenOfferOwner, Clawback -> Account).
  // PaymentChannelFund/Claim -> Channel: Channel ist ein Hash, keine r-Adresse
  // — die Spec erlaubt hier keine erfundene Adresse, der Typ bleibt ohne
  // Kante (isoliert, wenn geflaggt). TrustSet/OfferCreate erzeugen per
  // XRPL-Spezifikation keine Geldbewegungs-Kante und bleiben bewusst
  // nicht kantenfähig.
  if (!rec.destination) {
    const counter =
      (tx.TransactionType === "EscrowFinish" || tx.TransactionType === "EscrowCancel") && typeof tx.Owner === "string" ? tx.Owner
      : tx.TransactionType === "CheckCash" && typeof tx.CheckDestination === "string" ? tx.CheckDestination
      : tx.TransactionType === "VaultWithdraw" && typeof tx.VaultOwner === "string" ? tx.VaultOwner
      : tx.TransactionType === "NFTokenAcceptOffer" && typeof tx.NFTokenOfferOwner === "string" ? tx.NFTokenOfferOwner
      : tx.TransactionType === "Clawback" && typeof tx.Account === "string" ? tx.Account
      : null;
    if (counter && counter !== rec.account) rec.destination = counter;
  }
  // Betrag: XRP (drops) oder IOU; Vault-/NFToken-Offer-Beträge zusätzlich lesen.
  const amountSrc = tx.Amount ?? tx.DeliverMax ?? tx.VaultAmount ?? tx.NFTokenOfferAmount ?? null;
  rec.amountDrops = dropsOf(amountSrc);
  if (amountSrc && typeof amountSrc === "object" && amountSrc.currency && amountSrc.issuer && amountSrc.value != null) {
    const v = Number(amountSrc.value);
    if (Number.isFinite(v)) rec.iouValue = { currency: String(amountSrc.currency), issuer: String(amountSrc.issuer), value: v };
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

export function detectPeelingChains(txRecords, flaggedAddresses, opts = {}) {
  const th = {
    ...PEELING_THRESHOLDS,
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
    txHops.push({
      to: destination,
      from: account,
      amountDrops:
        typeof rec.amountDrops === "number" && Number.isFinite(rec.amountDrops) ? rec.amountDrops : null,
      txHash: typeof rec.hash === "string" ? rec.hash : null,
      ledgerSeq:
        typeof rec.ledgerSeq === "number" && Number.isFinite(rec.ledgerSeq) ? rec.ledgerSeq : null,
    });
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

  // 5) Wanderung ab Seeds (asc sortiert, maxSeeds-Kappe). Der erste Hop ist
  // die Aussendung des Seeds: nur Bagatellgrenze (amountDrops > dustDrops),
  // KEIN Ratio-Fenster — das Verhältnis wird je RELAY gemessen (out/in am
  // Zwischenknoten), der Seed hat keinen gemessenen Eingang. Ein Hop endet
  // die Kette, wenn der Zielknoten geflaggt ist (Fund-Ende) — dann zählt er
  // als Hop; sonst muss er strikter 1:1-Relay sein und wird durchgewandert.
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
      const hops = [
        {
          from: seed,
          to: firstHop.to,
          amountDrops: inDrops,
          ratio: null, // Seed-Hop: kein gemessener Eingang, kein Verhältnis
          txHash: firstHop.txHash,
          ledgerSeq: firstHop.ledgerSeq,
        },
      ];
      let current = firstHop.to;
      let currentIn = inDrops;
      // Längengrenze maxChainLen (Kanten), Zykelschutz über addresses.
      while (hops.length < maxChainLen) {
        if (severityOf.has(current)) break; // Fund-Ende: Kette abgeschlossen
        if (!relayOk(current)) break;      // kein striktes 1:1-Relay: Abbruch
        const next = (chainOut.get(current) ?? [])[0];
        if (!next) break;
        if (addresses.includes(next.to)) break; // Zykel
        const r = hopOk(next, currentIn);
        if (r == null) break;
        addresses.push(next.to);
        hops.push({
          from: current,
          to: next.to,
          amountDrops: next.amountDrops,
          ratio: r,
          txHash: next.txHash,
          ledgerSeq: next.ledgerSeq,
        });
        current = next.to;
        currentIn = next.amountDrops;
      }
      if (hops.length < th.minHops) continue;
      const signature = addresses.join(",");
      if (seenSignatures.has(signature)) continue;
      seenSignatures.add(signature);
      chains.push({
        addresses,
        hops,
        seed,
        seedSeverity: severityOf.get(seed),
        hopsCount: hops.length,
        bridges: addresses.filter((a) => !severityOf.has(a)).sort(cmpStr),
        signature,
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
