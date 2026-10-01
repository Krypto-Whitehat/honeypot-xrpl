// lib/flow-state.mjs — Persistenz des Ledger-Flow-States (pure ESM).
//
// HARTE GRENZEN (identisch zu lib/history.mjs:3-12):
//   - pure ESM, KEINE npm-Imports. Erlaubt: global fetch (nur über den
//     wiederverwendeten Transport), node:crypto, node:fs/promises, node:path.
//     Läuft NIE im Browser und wird absichtlich NICHT in die /lib-Whitelist
//     (api/lib-detector.js, server/index.mjs) aufgenommen — die Datei wird
//     niemals an den Browser ausgeliefert.
//   - KEINE Secrets, KEINE Köder-Adressen in dieser Datei.
//   - Token/Repo-Werte aus ENV werden NIE geloggt und tauchen in keiner
//     Fehlermeldung auf (alle Errors tragen neutrale Messages).
//
// DATENMODELL (persistiertes Flow-State-Dokument, data/flow-state.json):
//   { cursor: number,            // letzter verarbeiteter Ledger-Index
//     state: {                   // der akkumulierte Flow-State (ledger-walk-Vertrag)
//       clusters: { [key]: {...} },
//       blocksProcessedTotal: number,
//       lastAdvancedAt: number|null },
//     updatedAt: number|null }   // letzte Persistenz-Zeit (ms)
//
// EIGENE SERIALISIERUNG/MERGE: Der Flow-State ist KEIN History-Bestand
// (Array), sondern ein Dokument {cursor, state, updatedAt}. parseFlowStateText/
// serializeFlowState/normalizeFlowStateDoc/mergeFlowState sind daher HIER
// definiert und wiederverwenden NICHT die History-Serialisierung. Der
// GITHUB-TRANSPORT (Read/Write/409-Retry/In-Flight-Lock) wird dagegen aus
// lib/history.mjs wiederverwendet (readGitHubContents/writeGitHubContents) —
// derselbe Env-Repo/Branch/Token, nur eigener Codec und eigener filePath.
//
// DOKUMENTIERTE GRENZE: Flow-State-Commits tragen den geteilten Commit-
// Message-Marker GH_COMMIT_MESSAGE ("history: merge (auto) [skip ci]") —
// Markierung, NICHT Mechanismus (lib/history.mjs). Ein eigener Marker wäre ein
// weiterer Transport-Parameter, der hier bewusst nicht angelegt wird.
//
// EXPORT-VERTRAG:
//   FLOW_STATE_FILE_PATH                            -> "data/flow-state.json"
//   freshFlowState()                                -> {clusters:{}, blocksProcessedTotal:0, lastAdvancedAt:null}
//   emptyFlowStateDoc()                             -> {cursor:0, state:fresh, updatedAt:null}
//   normalizeFlowStateDoc(doc)                      -> doc (defensiv coerced)
//   serializeFlowState(doc)                         -> JSON-String
//   parseFlowStateText(text)                        -> doc (wirft bei Korruption)
//   mergeFlowState(existingDoc, advanceResult, now) -> doc
//   readFlowStateGitHub()                           -> {doc, sha}
//   writeFlowStateGitHub(apply)                     -> newDoc
//   projectFlowStateView(doc)                       -> {cursor, updatedAt,
//                                                        clusters:[View-Form + edges + rolesByAddress]}

import { readGitHubContents, writeGitHubContents } from "./history.mjs";
import { clusterLabel } from "./cluster.mjs";

// ---------- Konstanten ----------
export const FLOW_STATE_FILE_PATH = "data/flow-state.json"; // Pfad im Daten-Repo (GitHub)

// ---------- Frischer State / leeres Dokument ----------
// freshFlowState: exakt die Form, die lib/ledger-walk.mjs normalizeState für
// null/undefined liefert — der akkumulierte Flow-State beginnt hier.
export function freshFlowState() {
  return { clusters: {}, blocksProcessedTotal: 0, lastAdvancedAt: null };
}

// emptyFlowStateDoc: persistiertes Dokument ohne jeglichen Fortschritt.
export function emptyFlowStateDoc() {
  return { cursor: 0, state: freshFlowState(), updatedAt: null };
}

// ---------- Normalisierung (defensiv, am Lese-/Serialisierungs-Rand) ----------
// Coerced das Dokument auf den festen Vertrag {cursor, state, updatedAt}.
// null/undefined/fremd -> leeres Dokument. cursor/updatedAt werden zu Zahlen
// gezwungen (NaN/Inf -> Default). state wird durchgereicht — die tiefe
// State-Normalisierung liegt bei lib/ledger-walk.mjs (advance normalisiert
// intern); hier wird nur die Dokument-Hülle gezwungen, nicht dupliziert.
export function normalizeFlowStateDoc(doc) {
  if (!doc || typeof doc !== "object" || Array.isArray(doc)) return emptyFlowStateDoc();
  const cursor = Number(doc.cursor);
  // updatedAt: null/undefined/"" bleibt null (Vertrag: number|null).
  // Number(null) === 0 würde "kein Zeitstempel" still zu Epoch-0 umdeuten —
  // sowohl im Roundtrip (Serialize) als auch in der View-Projektion.
  let updatedAt = null;
  if (doc.updatedAt !== null && doc.updatedAt !== undefined && doc.updatedAt !== "") {
    const n = Number(doc.updatedAt);
    if (Number.isFinite(n)) updatedAt = n;
  }
  const state = doc.state && typeof doc.state === "object" && !Array.isArray(doc.state)
    ? doc.state
    : freshFlowState();
  return {
    cursor: Number.isFinite(cursor) ? cursor : 0,
    state,
    updatedAt,
  };
}

// ---------- Serialisierung / Parse (eigene, NICHT History) ----------
// Serialisiert das (normalisierte) Dokument. Normalisierung vor dem Serialize
// stellt die kanonische Form her — der Roundtrip konvergiert nach einem Write.
export function serializeFlowState(doc) {
  return JSON.stringify(normalizeFlowStateDoc(doc));
}

// JSON-Objekt (Dokument) — alles andere ist Korruption und WIRFT (NIEMALS
// leer behandeln und damit ein Überschreiben des korrupten Standes auslösen).
export function parseFlowStateText(text) {
  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch {
    throw new Error("Flow-State-Bestand nicht parsebar (korrumpiert) — kein Überschreiben.");
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error("Flow-State-Bestand hat unerwartetes Format — kein Überschreiben.");
  }
  return normalizeFlowStateDoc(parsed);
}

// Flow-State-Codec: injiziert in den wiederverwendeten Transport.
const flowStateCodec = { serialize: serializeFlowState, parse: parseFlowStateText };

// ---------- Merge (eigene, Dokument-Ebene) ----------
// Verpackt das Ergebnis eines advance()-Ticks in das persistierte Dokument:
// Cursor rückt auf newCursor, state ist der bereits von advance() akkumulierte
// Flow-State, updatedAt auf now. advance() hat die eigentliche Akkumulation
// bereits vollzogen — hier erfolgt nur die Dokument-Verpackung (kein History-
// List-Merge). Fehlt advanceResult/flowState, bleibt der Bestand erhalten.
export function mergeFlowState(existingDoc, advanceResult, now) {
  const existing = normalizeFlowStateDoc(existingDoc);
  const res = advanceResult && typeof advanceResult === "object" ? advanceResult : {};
  const cursor = Number(res.newCursor);
  const state =
    res.flowState && typeof res.flowState === "object" && !Array.isArray(res.flowState)
      ? res.flowState
      : existing.state;
  const updatedAt = Number(now);
  return {
    cursor: Number.isFinite(cursor) ? cursor : existing.cursor,
    state,
    updatedAt: Number.isFinite(updatedAt) ? updatedAt : null,
  };
}

// ---------- View-Projektion (renderbare Cluster-View + Flow-Graph-View) ----------
// Normalisiert das Flow-State-Dokument auf die CLUSTER-VIEW-FORM, die die
// bestehenden Cluster-Render-Module konsumieren können: Cluster-Liste mit
// Rollen/Volumen/first-lastSeen + Cursor-Stand + updatedAt. Deterministisch:
// dieselbe Sortierung wie buildClusterGraph (lib/cluster.mjs) und dieselben
// Labels (clusterLabel, nach der Sortierung nach Listenindex vergeben).
// Nicht renderbare Roh-Internals (blocksProcessedTotal, lastAdvancedAt) und
// ungefilterte Member-Listen werden NICHT geliefert — nur die normalisierte
// Projektion. Die Rollen-Map (Adresse -> Rolle) wird auf Rollen-Zählungen
// (Rolle -> Anzahl) gefaltet; unbekannte Rollenwerte fallen nach 'unknown'.
//
// ZUSÄTZLICH für die Flow-Graph-/Weltkugel-View (public/history-host.html):
// pro Cluster die BEGRENZTEN retained Fluss-Kanten (`edges`, Kanten-Vertrag
// lib/cluster.mjs, deterministisch sortiert nach der Totalordnung von
// topKEdges/cmpEdge) und die per-Adress-Rollen (`rolesByAddress`, bekannte
// Rollen, fremde Werte -> 'unknown', deterministisch nach Adresse sortiert).
// Knoten = Adressen mit Rolle, Kanten = Flüsse mit Volumen. Die gefaltete
// Rollen-Zählung bleibt im Feld `roles` (bestehender Vertrag, Cluster-Karten).
const VIEW_ROLE_KEYS = ["source", "drainer", "collector", "relay", "unknown"];

function viewNum(v) {
  const n = Number(v);
  return Number.isFinite(n) ? n : 0;
}

function viewRoleCounts(roles) {
  const counts = {};
  if (roles && typeof roles === "object" && !Array.isArray(roles)) {
    for (const role of Object.values(roles)) {
      const r = VIEW_ROLE_KEYS.includes(role) ? role : "unknown";
      counts[r] = (counts[r] ?? 0) + 1;
    }
  }
  return counts;
}

function viewCmpStr(a, b) {
  return String(a ?? "").localeCompare(String(b ?? ""));
}

// Binärer String-Vergleich (deterministisch, locale-unabhängig) — exakt die
// Konvention cmpStr (lib/cluster.mjs:46-48). localeCompare wäre
// locale-abhängig und damit nicht deterministisch; für die Kanten-Sortierung
// gilt der binäre Vergleich.
function viewCmpStrBin(a, b) {
  const x = String(a ?? "");
  const y = String(b ?? "");
  return x < y ? -1 : x > y ? 1 : 0;
}

// Defensive Coercion einer retained Edge auf den Kanten-Vertrag (lib/cluster.mjs)
// — gleiche Semantik wie sanitizeEdge (lib/ledger-walk.mjs, dort nicht
// exportiert). Ohne beide Enden ist eine Kante nicht renderbar und wird
// verworfen (null).
function viewEdge(e) {
  if (!e || typeof e !== "object") return null;
  const from = typeof e.from === "string" && e.from ? e.from : null;
  const to = typeof e.to === "string" && e.to ? e.to : null;
  if (!from || !to) return null;
  return {
    from,
    to,
    type: typeof e.type === "string" ? e.type : null,
    amountDrops:
      typeof e.amountDrops === "number" && Number.isFinite(e.amountDrops) ? e.amountDrops : null,
    txHash: typeof e.txHash === "string" ? e.txHash : null,
    ledgerSeq:
      typeof e.ledgerSeq === "number" && Number.isFinite(e.ledgerSeq) ? e.ledgerSeq : null,
    closeTime: typeof e.closeTime === "string" && e.closeTime ? e.closeTime : null,
  };
}

// Retained edges eines Clusters: sanitized + deterministisch sortiert. Die
// Sortierung ist exakt die Totalordnung von topKEdges (lib/ledger-walk.mjs) /
// cmpEdge (lib/cluster.mjs): Volumen desc (Null/IOU zählt 0), dann ledgerSeq
// asc, txHash asc, Endpunkte asc. Deterministisch bei jeder Einfügefolge.
function viewEdges(edges) {
  const out = [];
  if (Array.isArray(edges)) {
    for (const e of edges) {
      const se = viewEdge(e);
      if (se) out.push(se);
    }
  }
  out.sort((a, b) => {
    const va = typeof a.amountDrops === "number" && Number.isFinite(a.amountDrops) ? a.amountDrops : 0;
    const vb = typeof b.amountDrops === "number" && Number.isFinite(b.amountDrops) ? b.amountDrops : 0;
    if (va !== vb) return va < vb ? 1 : -1;
    const la = typeof a.ledgerSeq === "number" ? a.ledgerSeq : -1;
    const lb = typeof b.ledgerSeq === "number" ? b.ledgerSeq : -1;
    if (la !== lb) return la - lb;
    const h = viewCmpStrBin(a.txHash, b.txHash);
    if (h !== 0) return h;
    const f = viewCmpStrBin(a.from, b.from);
    if (f !== 0) return f;
    return viewCmpStrBin(a.to, b.to);
  });
  return out;
}

// Per-Adress-Rollen (NICHT auf Zählungen gefaltet): die retained Rollen-Map
// eines Clusters, auf bekannte Rollen gezwungen (fremde Werte -> 'unknown'),
// deterministisch nach Adresse sortiert. Für die Flow-Graph-View (Knoten =
// Adressen mit Rolle). Die gefaltete Zählung bleibt im Feld `roles`.
function viewRolesByAddress(roles) {
  const out = {};
  if (roles && typeof roles === "object" && !Array.isArray(roles)) {
    for (const addr of Object.keys(roles).sort(viewCmpStrBin)) {
      const role = roles[addr];
      out[addr] = VIEW_ROLE_KEYS.includes(role) ? role : "unknown";
    }
  }
  return out;
}

export function projectFlowStateView(doc) {
  const normalized = normalizeFlowStateDoc(doc);
  const state =
    normalized.state && typeof normalized.state === "object" && !Array.isArray(normalized.state)
      ? normalized.state
      : {};
  const src =
    state.clusters && typeof state.clusters === "object" && !Array.isArray(state.clusters)
      ? state.clusters
      : {};
  const entries = [];
  for (const [key, value] of Object.entries(src)) {
    if (!value || typeof value !== "object") continue;
    // Sortierstufe: erstes Mitglied (Konvention lib/cluster.mjs) — intern,
    // wird vor der Auslieferung entfernt.
    const members = (Array.isArray(value.memberAddresses) ? value.memberAddresses : [])
      .map((a) => String(a))
      .filter(Boolean);
    entries.push({
      sortKey: members[0] ?? "",
      cluster: {
        id: typeof value.id === "string" && value.id ? value.id : `cluster:${key}`,
        label: "", // wird nach der Sortierung gesetzt (Konvention lib/cluster.mjs)
        roles: viewRoleCounts(value.roles),
        rolesByAddress: viewRolesByAddress(value.roles),
        edges: viewEdges(value.edges),
        totalDrops: viewNum(value.totalDrops),
        txCount: viewNum(value.txCount),
        distinctAccounts: viewNum(value.distinctAccounts),
        firstSeen: typeof value.firstSeen === "string" ? value.firstSeen : null,
        lastSeen: typeof value.lastSeen === "string" ? value.lastSeen : null,
      },
    });
  }
  // Deterministische Sortierung — exakt die Konvention von buildClusterGraph
  // (lib/cluster.mjs): Volumen desc, Transaktionszahl desc, erstes Mitglied
  // asc. Labels werden NACH der Sortierung nach Listenindex vergeben.
  entries.sort(
    (a, b) =>
      b.cluster.totalDrops - a.cluster.totalDrops ||
      b.cluster.txCount - a.cluster.txCount ||
      viewCmpStr(a.sortKey, b.sortKey)
  );
  const clusters = entries.map(({ cluster }, i) => {
    cluster.label = clusterLabel(i);
    return cluster;
  });
  return {
    cursor: normalized.cursor,
    updatedAt: normalized.updatedAt,
    clusters,
  };
}

// ---------- GitHub-Transport (wiederverwendet, eigener Codec + Pfad) ----------
// Read des Flow-State-Dokuments. doc null (Anlege/leer) wird hier zum leeren
// Dokument normalisiert — der Advance-Pfad kennt nur Dokumente, nie null.
export async function readFlowStateGitHub() {
  const { doc, sha } = await readGitHubContents(FLOW_STATE_FILE_PATH, flowStateCodec);
  return { doc: doc ?? emptyFlowStateDoc(), sha };
}

// Write des Flow-State-Dokuments. apply(existingDoc) liefert das neue Dokument;
// doc null (Anlege/leer) wird vor apply zum leeren Dokument normalisiert, damit
// apply stets ein Dokument erhält (Vertrag wie der History-Write).
export function writeFlowStateGitHub(apply) {
  return writeGitHubContents((doc) => apply(doc ?? emptyFlowStateDoc()), FLOW_STATE_FILE_PATH, flowStateCodec);
}
