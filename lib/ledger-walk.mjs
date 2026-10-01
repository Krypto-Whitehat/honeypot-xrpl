// Cursor-Advance-Kern für den History-Host: transport-agnostisch, rein logisch.
// advance() rückt einen persistierten Ledger-Cursor um ein begrenztes Budget vor,
// berechnet pro Block den Geldfluss über die BESTEHENDEN Cluster-Module und
// akkumuliert den Cross-Block-Flow-State — inklusive BEGRENZTER Fluss-Kanten
// pro Cluster (Top-K nach akkumuliertem Volumen, dedupliziert nach
// Kanten-Identität). Findings sind PRO BLOCK Teil des Fetcher-Vertrags
// ({transactions, findings}), nicht tick-global. Kein Netzwerk, kein
// Dateizugriff hier — der Fetcher wird injiziert (Tests nutzen In-Memory-
// Fixtures).

import { txRecordFromEntry, buildClusterGraph } from "./cluster.mjs";

/**
 * Rückt den Cursor um ein begrenztes Budget vor und akkumuliert den Flow-State.
 *
 * @param {object} p
 * @param {number} p.cursor        letzter verarbeiteter Ledger-Index (Zahl)
 * @param {number} p.budget        maximal zu verarbeitende Blöcke pro Tick
 * @param {number} p.now           aktuelle Zeit (ms) für first/lastSeen
 * @param {(ledgerIndex:number)=>Promise<object|null>} p.fetcher
 *        liefert pro Block { transactions, findings } oder null am Live-Edge
 *        (injizierbar); findings sind pro Block, nicht tick-global
 * @param {object} p.flowState     bisher akkumulierter Flow-State
 * @param {object} [p.opts]        { maxClusterEdges = 50 } — Begrenzung der
 *        pro-Cluster-Fluss-Kanten im akkumulierten State
 * @returns {Promise<{newCursor:number, summary:string, flowState:object}>}
 */
export async function advance({ cursor, budget, now, fetcher, flowState, opts = {} }) {
  const start = Number(cursor) || 0;
  const maxBlocks = Math.max(0, Math.floor(Number(budget) || 0));
  const maxClusterEdges = maxClusterEdgesOf(opts);
  const state = normalizeState(flowState, maxClusterEdges);

  let processed = 0;
  let lastIndex = start;

  for (let i = 1; i <= maxBlocks; i++) {
    const index = start + i;
    let block = null;
    try {
      block = await fetcher(index);
    } catch {
      block = null; // Netzwerk-/RPC-Fehler am Edge: als Ende behandeln
    }
    if (!block) break; // Live-Edge erreicht (oder Block fehlt)

    mergeBlock(state, index, block, maxClusterEdges);
    lastIndex = index;
    processed++;
  }

  state.lastAdvancedAt = now;
  state.blocksProcessedTotal = (Number(state.blocksProcessedTotal) || 0) + processed;

  return {
    newCursor: lastIndex,
    summary: `+${processed} Blöcke bis Index ${lastIndex}`,
    flowState: state,
  };
}

// flowState-Normalisierung: null/undefined -> frisch; Plain-Object-Vertrag.
// Cluster-Keys, verarbeitete-Blöcke-Summe, letzte Advance-Zeit; pro Cluster
// wird edges auf den Kanten-Vertrag gezwungen und die Top-K-Begrenzung erneut
// angewendet — persistierte States sind damit stets begrenzt, auch wenn sie
// unter anderem K geschrieben wurden.
function normalizeState(fs, maxClusterEdges) {
  const out = { clusters: {}, blocksProcessedTotal: 0, lastAdvancedAt: null };
  if (!fs || typeof fs !== "object") return out;
  const tot = Number(fs.blocksProcessedTotal);
  out.blocksProcessedTotal = Number.isFinite(tot) ? tot : 0;
  if (fs.lastAdvancedAt != null) out.lastAdvancedAt = fs.lastAdvancedAt;
  const src = fs.clusters;
  if (src && typeof src === "object" && !Array.isArray(src)) {
    for (const [k, v] of Object.entries(src)) {
      if (!v || typeof v !== "object") continue;
      const c = { ...v };
      const raw = Array.isArray(c.edges) ? c.edges : [];
      c.edges = topKEdges(raw.map(sanitizeEdge).filter((e) => e), maxClusterEdges);
      out.clusters[k] = c;
    }
  }
  return out;
}

// Berechnet den Fluss eines einzelnen Blocks über die BESTEHENDEN Cluster-Module
// und faltet ihn in den akkumulierten State ein: Dedup nach Cluster-Key,
// Geldfluss-Summen (totalDrops/txCount) akkumulieren, first/lastSeen
// chronologisch aktualisieren. Findings sind PRO BLOCK (block.findings,
// Default []) — ohne Findings liefert buildClusterGraph keinen Graph (leere
// severityOf) und der Merge bleibt korrekt leer. Pro Cluster werden die
// Block-Kanten extrahiert und BEGRENZT akkumuliert (Top-K nach Volumen,
// dedupliziert nach Kanten-Identität).
function mergeBlock(state, index, block, maxClusterEdges) {
  const entries = Array.isArray(block?.transactions) ? block.transactions : [];
  const findings = Array.isArray(block?.findings) ? block.findings : [];
  const txRecords = [];
  for (const entry of entries) {
    try {
      txRecords.push(txRecordFromEntry(entry, null));
    } catch {
      // Einzelne kaputte Entry überspringen, nicht den ganzen Block.
    }
  }
  if (txRecords.length === 0) return;

  let graph;
  try {
    graph = buildClusterGraph(txRecords, findings, {});
  } catch {
    return;
  }
  if (!graph) return;

  const clusters = Array.isArray(graph.clusters) ? graph.clusters : [];
  const edges = Array.isArray(graph.edges) ? graph.edges : [];
  for (const c of clusters) {
    const key = typeof c?.id === "string" && c.id ? c.id : null;
    if (!key) continue;
    const members = new Set(Array.isArray(c.memberAddresses) ? c.memberAddresses : []);
    const clusterEdges = edges.filter((e) => members.has(e?.from) && members.has(e?.to));
    state.clusters[key] = mergeCluster(state.clusters[key], c, clusterEdges, maxClusterEdges);
  }
}

// Merge eines Clusters in den akkumulierten State: Dedup nach Cluster-Key,
// Summen akkumulieren, first/lastSeen chronologisch (Epoch-Vergleich, nie
// lexikalisch — Konvention wie cluster.mjs), strukturelle Felder: neueste
// Sicht gewinnt (Mitglieder wachsen monoton über die Blöcke). Fluss-Kanten:
// dedupliziert nach Kanten-Identität (die chronologisch erste gemergte Sicht
// gewinnt) und auf Top-K nach akkumuliertem Volumen begrenzt — die größten
// Flüsse sind die Geldwäsche-Signale; Volumen-Gleichstände brechen
// chronologisch (ledgerSeq asc, dann txHash/Endpunkte asc).
function mergeCluster(acc, c, blockEdges, maxClusterEdges) {
  const incoming = (Array.isArray(blockEdges) ? blockEdges : []).map((e) => ({ ...e }));
  if (!acc) {
    return {
      id: c.id,
      totalDrops: num(c.totalDrops),
      txCount: num(c.txCount),
      firstSeen: typeof c.firstSeen === "string" ? c.firstSeen : null,
      lastSeen: typeof c.lastSeen === "string" ? c.lastSeen : null,
      memberAddresses: [...(Array.isArray(c.memberAddresses) ? c.memberAddresses : [])],
      roles: { ...(c.roles && typeof c.roles === "object" ? c.roles : {}) },
      mainDrainers: (Array.isArray(c.mainDrainers) ? c.mainDrainers : []).map((x) => ({ ...x })),
      collectors: (Array.isArray(c.collectors) ? c.collectors : []).map((x) => ({ ...x })),
      distinctAccounts: num(c.distinctAccounts),
      edges: topKEdges(incoming, maxClusterEdges),
    };
  }
  acc.totalDrops += num(c.totalDrops);
  acc.txCount += num(c.txCount);
  const f = epochMs(c.firstSeen);
  if (f !== -1 && (acc.firstSeen == null || f < epochMs(acc.firstSeen))) acc.firstSeen = c.firstSeen;
  const l = epochMs(c.lastSeen);
  if (l !== -1 && (acc.lastSeen == null || l > epochMs(acc.lastSeen))) acc.lastSeen = c.lastSeen;
  acc.memberAddresses = [...(Array.isArray(c.memberAddresses) ? c.memberAddresses : [])];
  acc.roles = { ...(c.roles && typeof c.roles === "object" ? c.roles : {}) };
  acc.mainDrainers = (Array.isArray(c.mainDrainers) ? c.mainDrainers : []).map((x) => ({ ...x }));
  acc.collectors = (Array.isArray(c.collectors) ? c.collectors : []).map((x) => ({ ...x }));
  acc.distinctAccounts = num(c.distinctAccounts);
  // Kanten-Dedup: bereits akkumulierte Identitäten gewinnen (chronologisch
  // erste Sicht), neue Identitäten werden angehängt, dann Top-K nach Volumen.
  const accEdges = Array.isArray(acc.edges) ? acc.edges : [];
  const seen = new Set(accEdges.map(edgeIdentity));
  const merged = [...accEdges];
  for (const e of incoming) {
    const id = edgeIdentity(e);
    if (seen.has(id)) continue;
    seen.add(id);
    merged.push(e);
  }
  acc.edges = topKEdges(merged, maxClusterEdges);
  return acc;
}

// Epoch-ms-Vergleich für first/lastSeen-Merge — gleiche Semantik wie
// cluster.mjs:50-54 (dort nicht exportiert; der Merge braucht den Vergleich).
function epochMs(iso) {
  if (typeof iso !== "string" || !iso) return -1;
  const ms = Date.parse(iso);
  return Number.isFinite(ms) ? ms : -1;
}

function num(v) {
  const n = Number(v);
  return Number.isFinite(n) ? n : 0;
}

// Begrenzung der pro-Cluster-Fluss-Kanten im akkumulierten State: klein
// (Default 50), über opts.maxClusterEdges konfigurierbar.
const DEFAULT_MAX_CLUSTER_EDGES = 50;

function maxClusterEdgesOf(opts) {
  const n = Number(opts?.maxClusterEdges);
  return Number.isFinite(n) ? Math.max(0, Math.floor(n)) : DEFAULT_MAX_CLUSTER_EDGES;
}

// Kanten-Identität: Transaktions-Identität der Kante (Endpunkte + Hash +
// Ledger-Index). Dedup nach dieser Identität verhindert Doppelzählung, wenn
// dieselbe Transaktion in mehreren Blöcken vorkommt.
function edgeIdentity(e) {
  return [e?.from ?? "", e?.to ?? "", e?.txHash ?? "", e?.ledgerSeq ?? ""].join("\u0000");
}

// Defensive Coercion einer persistierten Kante auf den Kanten-Vertrag von
// buildClusterGraph (lib/cluster.mjs) — unbekanntes/defektes wird verworfen.
function sanitizeEdge(e) {
  if (!e || typeof e !== "object") return null;
  const out = {};
  out.from = typeof e.from === "string" && e.from ? e.from : null;
  out.to = typeof e.to === "string" && e.to ? e.to : null;
  out.type = typeof e.type === "string" ? e.type : null;
  out.amountDrops =
    typeof e.amountDrops === "number" && Number.isFinite(e.amountDrops) ? e.amountDrops : null;
  out.txHash = typeof e.txHash === "string" ? e.txHash : null;
  out.ledgerSeq =
    typeof e.ledgerSeq === "number" && Number.isFinite(e.ledgerSeq) ? e.ledgerSeq : null;
  out.closeTime = typeof e.closeTime === "string" && e.closeTime ? e.closeTime : null;
  return out;
}

// Top-K nach akkumuliertem Volumen: größte Flüsse zuerst (Geldwäsche-Signale),
// Volumen-Gleichstände brechen chronologisch (ledgerSeq asc, dann txHash asc,
// dann Endpunkte asc — Totalordnung wie cmpEdge in lib/cluster.mjs). Null
// (IOU) zählt 0. Deterministisch bei jeder Eingabereihenfolge.
function topKEdges(edges, maxClusterEdges) {
  const k = Math.max(0, Math.floor(maxClusterEdges));
  const sorted = [...edges].sort((a, b) => {
    const va = typeof a?.amountDrops === "number" && Number.isFinite(a.amountDrops) ? a.amountDrops : 0;
    const vb = typeof b?.amountDrops === "number" && Number.isFinite(b.amountDrops) ? b.amountDrops : 0;
    if (va !== vb) return va < vb ? 1 : -1; // cmp-Form: Drops können MAX_SAFE_INTEGER überschreiten
    const la = typeof a?.ledgerSeq === "number" ? a.ledgerSeq : -1;
    const lb = typeof b?.ledgerSeq === "number" ? b.ledgerSeq : -1;
    if (la !== lb) return la - lb;
    const h = cmpStr(String(a?.txHash ?? ""), String(b?.txHash ?? ""));
    if (h !== 0) return h;
    const f = cmpStr(String(a?.from ?? ""), String(b?.from ?? ""));
    if (f !== 0) return f;
    return cmpStr(String(a?.to ?? ""), String(b?.to ?? ""));
  });
  return sorted.slice(0, k);
}

// Lexikographischer String-Vergleich (deterministisch) — wie cmpStr in
// lib/cluster.mjs (dort nicht exportiert; der Tie-Break braucht den Vergleich).
function cmpStr(a, b) {
  return a < b ? -1 : a > b ? 1 : 0;
}
