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
//             destination (optional), amountDrops (number|null) }
// finding:  { ruleId, severity, address, note (optional) } — exakt wie
//           analyzeLedger sie liefert (lib/detector.mjs).
// Edge:     { from, to, type, amountDrops, txHash, ledgerSeq, closeTime }
// Cluster:  { id, label, memberAddresses, roles, totalDrops, txCount,
//             distinctAccounts, firstSeen, lastSeen, mainDrainers, collectors }
// role ∈ { 'source', 'drainer', 'collector', 'relay', 'unknown' }
// opts: { maxEdges = 2000, minClusterSize = 2, thresholds? }
//
// False-Positive-Hinweis (dokumentiert): die Rollen sind Heuristik aus
// Ein-/Ausgrad und Fluss — ein harmloser Mehrfachempfänger kann als collector
// erscheinen (Test 16). Der Drainer-FP (benigne Durchleitung mit einer
// Ein-/Ausgangs-Kante) ist durch die distinctIn>=2-Bedingung ausgeschlossen
// (Test 17). Kein Schuldnachweis.

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
  return cmpStr(String(a.to ?? ""), String(b.to ?? ""));
}

// Label 'Cluster A', 'Cluster B', ... (27. -> 'Cluster AA')
function clusterLabel(index) {
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
  rec.amountDrops = dropsOf(tx.Amount ?? tx.DeliverMax);
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
      edges.push({
        from: account,
        to: destination,
        type: typeof rec.type === "string" ? rec.type : null,
        amountDrops: typeof rec.amountDrops === "number" && Number.isFinite(rec.amountDrops) ? rec.amountDrops : null,
        txHash: typeof rec.hash === "string" ? rec.hash : null,
        ledgerSeq: typeof rec.ledgerSeq === "number" && Number.isFinite(rec.ledgerSeq) ? rec.ledgerSeq : null,
        closeTime: typeof rec.closeTime === "string" && rec.closeTime ? rec.closeTime : null,
      });
    } else {
      if (account != null && severityOf.has(account)) isolated.add(account);
      if (destination != null && severityOf.has(destination)) isolated.add(destination);
    }
  }

  // 3) Kappung: neueste Kanten nach ledgerSeq bleiben (asc sortiert, vorne
  // abgeschnitten — deterministisch bei Gleichstand via txHash asc).
  edges.sort(cmpEdge);
  if (edges.length > maxEdges) edges.splice(0, edges.length - maxEdges);

  // 4) Union-Find über Kanten -> Komponenten.
  const dsu = new Dsu();
  const nodeIds = new Set();
  for (const e of edges) {
    nodeIds.add(e.from);
    nodeIds.add(e.to);
    dsu.union(e.from, e.to);
  }
  for (const a of isolated) {
    nodeIds.add(a);
    dsu.add(a);
  }

  // 5) Knotenaggregate aus den gekappten Kanten.
  const stats = new Map(); // id -> {degreeIn, degreeOut, inDrops, outDrops, distinctIn:Set, smallOut, maxOut}
  const stat = (id) => {
    if (!stats.has(id)) {
      stats.set(id, { degreeIn: 0, degreeOut: 0, inDrops: 0, outDrops: 0, distinctIn: new Set(), smallOut: 0, maxOut: 0 });
    }
    return stats.get(id);
  };
  for (const id of nodeIds) stat(id);
  for (const e of edges) {
    const drops = e.amountDrops ?? 0; // null (IOU) zählt 0 für Summen
    const from = stat(e.from);
    const to = stat(e.to);
    from.degreeOut += 1;
    from.outDrops += drops;
    if (drops <= th.sourceSmallDrops) from.smallOut += 1;
    if (drops > from.maxOut) from.maxOut = drops;
    to.degreeIn += 1;
    to.inDrops += drops;
    to.distinctIn.add(e.from);
  }

  // 6) Rollen-Heuristik. Konfliktauflösung: drainer > collector > relay > source.
  // Drainer verlangt >= 2 VERSCHIEDENE Eingangs-Sender (distinctIn, impliziert
  // degreeIn >= 2): eine einzelne Ein-/Ausgangs-Kante mit >= 90 % Weiterleitung
  // ist flow-seitig nicht von benignem Durchleitungs-/Konsolidierungsfluss zu
  // unterscheiden und fällt an die Relay-Regel (Befund 2026-09-29 behoben;
  // Tests 7/11 sichern den Mehrquellen-Sweep als Drainer-Kern ab).
  const roleOf = (id) => {
    const s = stats.get(id);
    if (s.distinctIn.size >= 2 && s.degreeOut >= 1 && s.inDrops > 0 && s.maxOut >= th.sweepRatio * s.inDrops) return "drainer";
    if (s.degreeIn >= th.collectorMinIn && s.distinctIn.size >= th.collectorMinIn && s.degreeOut <= th.collectorMaxOut) return "collector";
    if (s.degreeIn >= 1 && s.degreeOut >= 1 && Math.abs(s.inDrops - s.outDrops) <= th.relayBalance * Math.max(s.inDrops, s.outDrops)) return "relay";
    if (s.degreeOut >= th.sourceMinOut && s.smallOut >= th.sourceMinOut && s.degreeIn <= 1) return "source";
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
    const clusterEdges = edges.filter((e) => members.has(e.from)); // beide Enden in derselben Komponente
    let totalDrops = 0;
    let firstSeen = null;
    let lastSeen = null;
    for (const e of clusterEdges) {
      totalDrops += e.amountDrops ?? 0;
      if (e.closeTime) {
        if (firstSeen == null || e.closeTime < firstSeen) firstSeen = e.closeTime;
        if (lastSeen == null || e.closeTime > lastSeen) lastSeen = e.closeTime;
      }
    }
    const roles = {};
    for (const id of memberAddresses) roles[id] = roleOf(id);
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
      totalDrops,
      txCount: clusterEdges.length,
      distinctAccounts: memberAddresses.length,
      firstSeen,
      lastSeen,
      mainDrainers,
      collectors,
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
