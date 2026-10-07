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
//   mergeFlowState(existingDoc, advanceResult, now, opts?) -> doc
//     (inkl. Pruning; Cursor monoton: max(existing, newCursor))
//   FLOW_STATE_MAX_BYTES 900_000 / effectiveClusterCap(state, now, opts?)
//     -> Cluster-Kappe aus dem Byte-Cap (Halbirung ab FLOW_STATE_MAX_CLUSTERS)
//   FLOW_STATE_MEMBER_CAP 300 / capClusterFields(state, opts?)
//     -> {state, truncatedKeys}: per-Cluster-Feldkappe des WRITE-PFADS
//        (api/advance.js: nach archiveFromFlowState, vor effectiveClusterCap
//        und mergeFlowState — Archivzeilen bleiben ungekappt)
//   pruneFlowState(state, now, {windowMs, maxClusters}) -> state
//     (7-Tage-Pruning: parsebare lastSeen zu alt -> raus; lastSeen
//      undefined/null -> BEHALTEN; danach Top-200 nach Volumen)
//   readFlowStateGitHub()                           -> {doc, sha}
//   writeFlowStateGitHub(apply)                     -> newDoc
//   projectFlowStateView(doc, baitLabels?)          -> {cursor, updatedAt,
//                                                        clusters:[View-Form + edges + rolesByAddress + peelingChains + motifs
//                                                        + fieldsCapped (nur wenn Write-Pfad-Kappe griff)]}
//     baitLabels optional: Map oder ENV BAIT_ADDRESSES; Köder-Endpunkte in
//     edges/rolesByAddress/memberAddresses/peelingChains/motifs fallen STILL
//     raus (B2).
//   hasFraudEvidence(value)                         -> boolean (exportiert:
//     Archiv-/Retention-Prädikat identisch zu pruneFlowState; drainer/
//     collector/mainDrainers/peelingChains/motifs.washCycles — NIEMALS
//     motifs.gatherScatter, das note-Attribut ist keine Evidenz)
//   FLOW_ARCHIVE_DIR / archivePath(day) / archiveDayOf(ms) / emptyArchiveDoc
//   parseArchiveText / serializeArchiveDoc / appendArchiveDoc
//   archiveFromFlowState(state, now, opts?)         -> [Archiv-Zeilen] (nur
//     Cluster, die pruneFlowState im selben Tick fallen ließe — Zeitgrenze
//     UND Kappung (opts.maxClusters ?? 200; im Kappungs-Zweig auch
//     lastSeen==null; reine Benign-Cluster nie). Parität zum Live-View
//     (Kritik-Runde 3): Archivkanten tragen type/toTag/fromTag/transit,
//     Archivzeilen tragen roles/severityByAddress (begrenzt auf Endpunkte
//     der archivierten Kanten — maschinenlesbar pro Hop-Endpunkt in der
//     Archiv-ZEILE, nicht pro Hop in der replayArchive-Antwort; die
//     Antwort-Parität ist die type-Parität der README-API-Tabelle,
//     Kritik-Runde 4 Befund 4; Byte-Budget); replayArchive-Hops tragen
//     type.
//   checkpointFromFlowState(state) -> [Archiv-Zeilen] (ALLE Betrugsevidenz-
//     Cluster OHNE Verlust-Prädikat, reason 'checkpoint' — Tages-Checkpoint)
//   hasCheckpointDoc(doc)      -> boolean (Guard-Marker im Tages-Dokument)
//   ARCHIVE_MAX_BYTES 900_000 / capArchiveDoc(doc, maxBytes?)
//     -> Byte-Cap des Archiv-Tages-Dokuments (zuerst Checkpoint-Zeilen,
//     dann älteste archivedAt raus — Checkpoints verdrängen nie Verlust-
//     Evidenz)
//   pruneArchiveDocs(docs, now, {maliciousMs, registryMs}) -> {docs, staleDays}
//   replayArchive(docs, {address, fromLedger, toLedger})   -> {hops, truncated}
//   readArchiveGitHub / writeArchiveGitHub / deleteArchiveGitHub
//   ARCHIVE_MAX_EDGES 200 / ARCHIVE_RETENTION_MALICIOUS_MS 30 d /
//   ARCHIVE_RETENTION_REGISTRY_MS 180 d

import {
  readGitHubContents,
  writeGitHubContents,
  deleteGitHubFile,
} from "./history.mjs";
import { clusterLabel, TEMPORAL_MAX_ADDRESSES, temporalMetrics } from "./cluster.mjs";
import { sanitizeText } from "./sanitize.mjs";
import { normalizeTag } from "./tag-identity.mjs";

// ---------- Konstanten ----------
export const FLOW_STATE_FILE_PATH = "data/flow-state.json"; // Pfad im Daten-Repo (GitHub)

// Flow-Archiv (Grenze 2): Tages-Chunks data/flow-archive/<YYYY-MM-DD>.json
// (dayOf-Muster lib/block-window.mjs:69, Transport-Muster :459-469).
// DOKUMENTIERTE GRENZE (kein 'vollständig'-Versprechen): die Rückwärts-
// Rekonstruktion (replayArchive) gilt innerhalb der Archiv-Kante
// ARCHIVE_MAX_EDGES 200 pro Cluster-Zeile; darüber ist account_tx-Replay
// nötig. Die State-Kappe ist 50 (lib/ledger-walk.mjs:279/320-367) — das
// Archiv kappt großzügiger, damit retained-Kanten nicht doppelt verloren
// gehen.
export const FLOW_ARCHIVE_DIR = "data/flow-archive";
export const ARCHIVE_MAX_EDGES = 200;
// Retention (Kritik 6): Betrugsevidenz 30 d, Cold-Vault-/Registry-verknüpfte
// Cluster 180 d. REINE BENIGN-CLUSTER WERDEN NICHT ARCHIVIERT (see
// archiveFromFlowState).
export const ARCHIVE_RETENTION_MALICIOUS_MS = 30 * 24 * 60 * 60 * 1000;
export const ARCHIVE_RETENTION_REGISTRY_MS = 180 * 24 * 60 * 60 * 1000;

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
// Der gemergte State durchläuft pruneFlowState (Retention: 7-Tage-Pruning +
// Top-200-Kappung) — die Persistenz bleibt damit begrenzt.
// opts.maxClusters: optionale Cap-Override (effektiver Byte-Cap, siehe
// effectiveClusterCap) — ohne Übergabe Default FLOW_STATE_MAX_CLUSTERS.
// Cursor-Monotonie: max(existing.cursor, newCursor) — ein Tick mit
// kleinerem/fehlendem newCursor darf einen fortgeschrittenen Cursor nie
// zurückschieben (live-Befund Wisch-Zyklus: Cursor 107432280 -> 0 nach
// fehlgelesenem Bestand).
export function mergeFlowState(existingDoc, advanceResult, now, opts = {}) {
  const existing = normalizeFlowStateDoc(existingDoc);
  const res = advanceResult && typeof advanceResult === "object" ? advanceResult : {};
  const cursor = Number(res.newCursor);
  let state =
    res.flowState && typeof res.flowState === "object" && !Array.isArray(res.flowState)
      ? res.flowState
      : existing.state;
  const updatedAt = Number(now);
  state = pruneFlowState(state, Number.isFinite(updatedAt) ? updatedAt : now, opts);
  return {
    cursor: Number.isFinite(cursor) ? Math.max(existing.cursor, cursor) : existing.cursor,
    state,
    updatedAt: Number.isFinite(updatedAt) ? updatedAt : null,
  };
}

// ---------- Retention (7-Tage-Pruning + Top-200-Kappung) ----------
// DEFINIERTE SEMANTIK (bewusst, gegen flow-state.test.mjs-Fixture c1 ohne
// lastSeen und dessen deepEqual-Assert): Cluster mit lastSeen undefined/null
// werden BEHALTEN — ein Cluster ohne Zeitstempel ist nicht einordenbar und
// darf nicht still verschwinden. Nur Cluster mit PARSEBARER lastSeen älter
// als windowMs (Default 7 Tage) fallen raus. Danach Kappung auf maxClusters
// (Default 200) nach Volumen (totalDrops desc, txCount desc, Key asc —
// deterministische Totalordnung). Die Ist-Größe des bestehenden Bestands ist
// nicht messbar (Datenrepo privat); Pruning/Kappung ist Entwurfsentscheidung
// mit dokumentierter Grenze.
export const FLOW_STATE_RETENTION_MS = 7 * 24 * 60 * 60 * 1000;
export const FLOW_STATE_MAX_CLUSTERS = 200;
// Byte-Cap des persistierten Flow-State-Dokuments (live-Befund: die
// GitHub-Contents-API liefert für Dateien > 1 MiB keinen content — ein
// 1.125.252-B-Bestand wurde als "leer" gelesen und im nächsten Tick
// überschrieben). 900_000 B hält Abstand unter der 1-MiB-Grenze (1048576).
// Messung immer Buffer.byteLength(..., 'utf8') — String.length zählt
// UTF-16-Einheiten, keine Bytes.
export const FLOW_STATE_MAX_BYTES = 900_000;
// Retention-Verlängerung für Betrugsevidenz: Cluster mit drainer/collector-
// Rolle oder mainDrainers-Eintrag bleiben 30 statt 7 Tage (reale Drainer-
// Beweise müssen rückwärtsbewertbar bleiben — Audit-Probe: 8-Tage-Cluster
// wurde gelöscht).
export const FLOW_STATE_MALICIOUS_RETENTION_MS = 30 * 24 * 60 * 60 * 1000;

function epochMsSafe(iso) {
  if (typeof iso !== "string" || !iso) return null;
  const ms = Date.parse(iso);
  return Number.isFinite(ms) ? ms : null;
}

// Betrugsevidenz eines Clusters: drainer/collector-Rolle,
// mainDrainers-Eintrag (Rollen-Map Adresse->Rolle oder Zählungsform),
// Peeling-Kette (Grenze 1) oder Wash-Zyklus (V4 — NUR motifs.washCycles,
// nie motifs.gatherScatter: das Gather-Scatter-Motiv ist ein note-Attribut
// ohne Schuldannahme und darf keine Retention/Archivierung auslösen).
// Exportiert als hasFraudEvidence.
function hasFraudEvidenceImpl(value) {
  const roles = value?.roles;
  if (roles && typeof roles === "object" && !Array.isArray(roles)) {
    for (const r of Object.values(roles)) {
      if (r === "drainer" || r === "collector") return true;
    }
  }
  if (Array.isArray(value?.mainDrainers) && value.mainDrainers.length > 0) return true;
  if (Array.isArray(value?.peelingChains) && value.peelingChains.length > 0) return true;
  if (Array.isArray(value?.motifs?.washCycles) && value.motifs.washCycles.length > 0) return true;
  return false;
}

export function pruneFlowState(state, now, opts = {}) {
  const src = state && typeof state === "object" && !Array.isArray(state) ? state : freshFlowState();
  const clusters =
    src.clusters && typeof src.clusters === "object" && !Array.isArray(src.clusters) ? src.clusters : {};
  const windowMs = Number.isFinite(opts.windowMs) ? opts.windowMs : FLOW_STATE_RETENTION_MS;
  const fraudWindowMs = Number.isFinite(opts.fraudWindowMs) ? opts.fraudWindowMs : FLOW_STATE_MALICIOUS_RETENTION_MS;
  const maxClusters = Number.isFinite(opts.maxClusters)
    ? Math.max(0, Math.floor(opts.maxClusters))
    : FLOW_STATE_MAX_CLUSTERS;
  const base = Number(now);
  const t = Number.isFinite(base) ? base : Date.now();
  const out = { ...src, clusters: {} };
  const entries = [];
  let rawCount = 0;
  for (const [key, value] of Object.entries(clusters)) {
    if (!value || typeof value !== "object") continue;
    rawCount += 1;
    const lastMs = epochMsSafe(value.lastSeen);
    const window = hasFraudEvidence(value) ? fraudWindowMs : windowMs;
    if (lastMs != null && lastMs < t - window) continue; // veraltet, parsebar -> raus
    entries.push([key, value]); // lastSeen undefined/null -> BEHALTEN
  }
  // No-Op-Fast-Path: nichts entfernt, keine Kappung nötig -> derselbe State
  // (Referenz-Erhaltung — mergeFlowState erhält den Bestand unverändert).
  if (entries.length === rawCount && entries.length <= maxClusters) return src;
  // Kappung nach SCHWERE vor Volumen: Cluster mit Betrugsevidenz
  // (drainer/collector/mainDrainers) bleiben garantiert erhalten, danach
  // totalDrops desc — ein volumenarmer malicious-Drainer wird nicht mehr
  // von benignen Großvolumen-Clustern verdrängt (Audit-Probe M).
  entries.sort((a, b) => {
    const fa = hasFraudEvidence(a[1]) ? 1 : 0;
    const fb = hasFraudEvidence(b[1]) ? 1 : 0;
    if (fa !== fb) return fb - fa;
    const da = Number(a[1]?.totalDrops) || 0;
    const db = Number(b[1]?.totalDrops) || 0;
    if (da !== db) return db - da;
    const ta = Number(a[1]?.txCount) || 0;
    const tb = Number(b[1]?.txCount) || 0;
    if (ta !== tb) return tb - ta;
    return a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0;
  });
  for (const [key, value] of entries.slice(0, maxClusters)) out.clusters[key] = value;
  return out;
}

// Exportierte Betrugsevidenz (Testbarkeit der Archiv-/Retention-Semantik,
// flow-state.test.mjs): identisches Prädikat wie pruneFlowState.
export function hasFraudEvidence(value) {
  return hasFraudEvidenceImpl(value);
}

// ---------- Write-Pfad-Feldkappe pro Cluster (Akkumulations-Fix 2026-10-06) ----------
// Mega-Cluster (live-Befund: 43.157 Mitglieder, 468.964 Txs, View 2,6 MB)
// sprengen FLOW_STATE_MAX_BYTES: effectiveClusterCap halbiert auf 1 und
// pruneFlowState wirft in JEDEM Tick alle übrigen Cluster aus dem Bestand —
// persistierte Cluster "verschwinden", obwohl Akkumulation ihr Zweck ist.
// Die Kappe komprimiert die Felder JEDES Clusters auf die Top-N-Mitglieder,
// damit der Bestand unter der Byte-Grenze bleibt und effectiveClusterCap
// nahe FLOW_STATE_MAX_CLUSTERS hält.
//
// AUSSCHLIESSLICHER WRITE-PFAD (bewusste Abgrenzung):
//   - NICHT in normalizeState (lib/ledger-walk.mjs Read-Seite) und NICHT in
//     pruneFlowState/mergeFlowState — sonst würde ein gelesener Bestand vor
//     der Archivierung gekappt und Archivzeilen verlören Mitglieder.
//   - Aufgerufen in api/advance.js VOR effectiveClusterCap (der Cap muss die
//     komprimierte Größe messen) und VOR mergeFlowState, aber archiveFromFlowState
//     läuft auf dem UNGEKAPPTEN advanceResult.flowState — Archivzeilen
//     behalten volle memberAddresses (30-d-Retention, Grenze-2-Vertrag).
//
// DOKUMENTIERTE UNION-DURCHBRECHUNG (lib/ledger-walk.mjs:297 'eine Adresse
// verschwindet nicht dauerhaft'): die Kappe entfernt Adressen aus
// memberAddresses/roles/severityByAddress, die nicht in der Top-N-Auswahl
// stehen. Sie tauchen erst wieder auf, wenn sie in einem neuen Block
// auftreten. Bewusst außer Kraft gesetzt gegen den Merge-Kommentar — ohne
// sie kollabiert der Bestand bei jedem Mega-Cluster auf cap=1.
//
// AUSWAHLREGEL (nur aus State-Feldern berechenbar — eine pro-Adresse-
// Volumen-Kennzahl existiert im State NICHT, 'Top-N nach Volumen' ist nicht
// anwendbar): 1) Severity-Rang malicious > suspect > alles andere
// (severityByAddress), 2) mainDrainers/collectors-Mitgliedschaft plus
// drainer/collector-Rolle, 3) Adresse asc (binär, viewCmpStrBin).
// mainDrainers/collectors bleiben damit garantiert erhalten, SOLANGE die
// malicious/suspect-Menge die Kappe nicht übersteigt (dann füllt die
// Severity-Stufe die Kappe vollständig — dokumentierte Grenze der Regel).
// distinctAccounts bleibt der WAHRE Mitgliederstand (die Kappe komprimiert
// die Felder, sie lügt nicht über die Größe). firstSeen/lastSeen/edges/
// peelingChains/mainDrainers/collectors bleiben unangetastet.
export const FLOW_STATE_MEMBER_CAP = 300;
const CAP_SEV_RANK = { malicious: 3, suspect: 2 };

export function capClusterFields(state, opts = {}) {
  const src = state && typeof state === "object" && !Array.isArray(state) ? state : freshFlowState();
  const clusters =
    src.clusters && typeof src.clusters === "object" && !Array.isArray(src.clusters) ? src.clusters : {};
  const cap = Number.isFinite(opts.maxMembers)
    ? Math.max(1, Math.floor(opts.maxMembers))
    : FLOW_STATE_MEMBER_CAP;
  const out = { ...src, clusters: {} };
  const truncatedKeys = [];
  for (const [key, value] of Object.entries(clusters)) {
    if (!value || typeof value !== "object") {
      out.clusters[key] = value;
      continue;
    }
    const members = Array.isArray(value.memberAddresses)
      ? value.memberAddresses.map((a) => String(a)).filter(Boolean)
      : [];
    const roles = value.roles && typeof value.roles === "object" && !Array.isArray(value.roles) ? value.roles : null;
    const sev =
      value.severityByAddress && typeof value.severityByAddress === "object" && !Array.isArray(value.severityByAddress)
        ? value.severityByAddress
        : null;
    const evidence = new Set();
    for (const list of [value.mainDrainers, value.collectors]) {
      for (const x of Array.isArray(list) ? list : []) {
        if (x && typeof x.address === "string" && x.address) evidence.add(x.address);
      }
    }
    if (roles) {
      for (const [a, r] of Object.entries(roles)) {
        if (r === "drainer" || r === "collector") evidence.add(a);
      }
    }
    const candidates = new Set(members);
    if (roles) for (const a of Object.keys(roles)) candidates.add(a);
    if (sev) for (const a of Object.keys(sev)) candidates.add(a);
    for (const a of evidence) candidates.add(a);
    if (candidates.size <= cap) {
      out.clusters[key] = value;
      continue;
    }
    const rank = (a) => CAP_SEV_RANK[sev?.[a]] ?? 1;
    const ordered = [...candidates].sort((x, y) => {
      const rx = rank(x);
      const ry = rank(y);
      if (rx !== ry) return ry - rx;
      const ex = evidence.has(x) ? 1 : 0;
      const ey = evidence.has(y) ? 1 : 0;
      if (ex !== ey) return ey - ex;
      return viewCmpStrBin(x, y);
    });
    const keep = new Set(ordered.slice(0, cap));
    const capped = { ...value };
    if (Array.isArray(value.memberAddresses)) {
      capped.memberAddresses = members.filter((a) => keep.has(a)).sort(viewCmpStrBin);
    }
    if (roles) {
      const keptRoles = {};
      for (const a of Object.keys(roles).sort(viewCmpStrBin)) {
        if (keep.has(a)) keptRoles[a] = roles[a];
      }
      capped.roles = keptRoles;
    }
    if (sev) {
      const keptSev = {};
      for (const a of Object.keys(sev).sort(viewCmpStrBin)) {
        if (keep.has(a)) keptSev[a] = sev[a];
      }
      capped.severityByAddress = keptSev;
    }
    // V3 — temporale Serie (Evidenz-Adressen, lib/ledger-walk.mjs mergeTemporal)
    // mitkürzen: Einträge gekappter Adressen fallen raus; danach dieselbe
    // Adress-Kappe wie im Merge (TEMPORAL_MAX_ADDRESSES, deterministisch
    // Adresse asc — Byte-Kontrolle, Auswahl-Qualität macht mergeTemporal).
    if (value.temporal && typeof value.temporal === "object" && !Array.isArray(value.temporal)) {
      const keptTemporal = {};
      for (const a of Object.keys(value.temporal)
        .sort(viewCmpStrBin)
        .filter((a) => keep.has(a))
        .slice(0, TEMPORAL_MAX_ADDRESSES)) {
        keptTemporal[a] = value.temporal[a];
      }
      capped.temporal = keptTemporal;
    }
    // V4 — Motive mitkürzen (Parität zur temporal-Kappe): Zyklen/Gather-
    // Adressen, die auf gekappte Mitglieder zeigen, fallen raus; bleiben
    // beide Arrays leer, wird das Feld GELÖSCHT (der Spread oben hat das
    // ungekappte Original übernommen — feldlos bleibt feldlos).
    if (value.motifs && typeof value.motifs === "object" && !Array.isArray(value.motifs)) {
      const keptGather = (Array.isArray(value.motifs.gatherScatter) ? value.motifs.gatherScatter : [])
        .filter((a) => typeof a === "string" && keep.has(a));
      const keptCycles = (Array.isArray(value.motifs.washCycles) ? value.motifs.washCycles : [])
        .filter((cy) => cy && typeof cy === "object" && typeof cy.a === "string" && typeof cy.b === "string" && keep.has(cy.a) && keep.has(cy.b));
      if (keptGather.length || keptCycles.length) {
        capped.motifs = {
          gatherScatter: keptGather,
          washCycles: keptCycles,
          fanInMax: Math.max(0, Number(value.motifs.fanInMax) || 0),
          fanOutMax: Math.max(0, Number(value.motifs.fanOutMax) || 0),
        };
      } else {
        delete capped.motifs;
      }
    }
    out.clusters[key] = capped;
    truncatedKeys.push(key);
  }
  truncatedKeys.sort(viewCmpStrBin);
  return { state: out, truncatedKeys };
}

// Effektive Cluster-Kappe aus dem Byte-Cap: startet bei opts.maxClusters
// (Default FLOW_STATE_MAX_CLUSTERS) und halbiert, bis die serialisierte
// Flow-State-Dokument-Hülle (cursor 0 + updatedAt now — die Hülle kostet
// < 100 B, der Bestand dominiert) den Cap FLOW_STATE_MAX_BYTES nicht
// überschreitet. Mindestens 1 (ein einzelner Cluster wird nie auf 0
// gekappt; wäre selbst er zu groß, greift der Blob-Fallback des Transports
// — lib/history.mjs readGitHubContents). Der Caller füttert damit
// mergeFlowState UND archiveFromFlowState mit demselben Cap (Archiv-
// Kopplung: was der Cap aus dem Bestand wirft, muss im selben Tick
// archivierbar bleiben).
export function effectiveClusterCap(state, now, opts = {}) {
  const maxBytes = Number.isFinite(opts.maxBytes) ? opts.maxBytes : FLOW_STATE_MAX_BYTES;
  let cap = Number.isFinite(opts.maxClusters)
    ? Math.max(1, Math.floor(opts.maxClusters))
    : FLOW_STATE_MAX_CLUSTERS;
  const n = Number(now);
  const t = Number.isFinite(n) ? n : Date.now();
  while (cap > 1) {
    const candidate = pruneFlowState(state, t, { ...opts, maxClusters: cap });
    const bytes = Buffer.byteLength(serializeFlowState({ cursor: 0, state: candidate, updatedAt: t }), "utf8");
    if (bytes <= maxBytes) break;
    cap = Math.max(1, Math.floor(cap / 2));
  }
  return cap;
}

// =====================================================================
// Flow-Archiv (Grenze 2): geschrieben VOR mergeFlowState/pruneFlowState.
// archiveFromFlowState läuft auf advanceResult.flowState und archiviert die
// Cluster, deren pruneFlowState-Prädikat sie im selben Tick fallen ließe —
// in BEIDEN Hälften des Prädikats: (1) der Zeitgrenze (epochMsSafe +
// hasFraudEvidence, :237-240) und (2) der Top-200-Kappung
// (entries.slice(0, maxClusters), :261) — ein volumenarmer
// Betrugsevidenz-Cluster, der die Kappung nicht übersteht, wird archiviert,
// bevor er spurlos verschwindet (Nachprüfung: die Header-Behauptung war
// gegen die Kappung nicht erfüllt). Reine Benign-Cluster werden nicht
// archiviert (Kritik 6): ohne Betrugsevidenz kein forensischer Wert, kein
// Archiv-Eintrag. Cluster mit lastSeen == null bleiben ausgeschlossen —
// pruneFlowState behält sie unbegrenzt, es besteht kein Verlust.
// =====================================================================

// Tages-Chunks: UTC-Kalendertag (dayOf-Muster lib/block-window.mjs:69).
export function archiveDayOf(ledgerTimeMs) {
  const n = Number(ledgerTimeMs);
  if (!Number.isFinite(n)) return null;
  return new Date(n).toISOString().slice(0, 10);
}

export function archivePath(day) {
  const d = String(day ?? "");
  if (!/^\d{4}-\d{2}-\d{2}$/.test(d)) {
    throw new Error("Flow-Archiv: ungültiges Tages-Datum.");
  }
  return `${FLOW_ARCHIVE_DIR}/${d}.json`;
}

export function emptyArchiveDoc(day) {
  return { day, updatedAt: null, docs: [] };
}

function normalizeArchiveDoc(doc) {
  const day =
    doc && typeof doc.day === "string" && /^\d{4}-\d{2}-\d{2}$/.test(doc.day) ? doc.day : null;
  let updatedAt = null;
  if (doc && doc.updatedAt !== null && doc.updatedAt !== undefined && doc.updatedAt !== "") {
    const n = Number(doc.updatedAt);
    if (Number.isFinite(n)) updatedAt = n;
  }
  const docs = Array.isArray(doc?.docs)
    ? doc.docs.filter((d) => d && typeof d === "object" && !Array.isArray(d) && typeof d.clusterId === "string" && d.clusterId)
    : [];
  return { day, updatedAt, docs };
}

export function serializeArchiveDoc(doc) {
  return JSON.stringify(normalizeArchiveDoc(doc));
}

// JSON-Objekt (Dokument) — alles andere ist Korruption und WIRFT (NIEMALS
// leer behandeln und damit ein Überschreiben des korrupten Standes auslösen;
// Muster parseFlowStateText :107-118).
export function parseArchiveText(text) {
  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch {
    throw new Error("Flow-Archiv-Bestand nicht parsebar (korrumpiert) — kein Überschreiben.");
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error("Flow-Archiv-Bestand hat unerwartetes Format — kein Überschreiben.");
  }
  return normalizeArchiveDoc(parsed);
}

const archiveCodec = { serialize: serializeArchiveDoc, parse: parseArchiveText };

// Edge-Kappe des Archivs: ARCHIVE_MAX_EDGES 200 (State-Kappe 50,
// lib/ledger-walk.mjs:279). Rückwärts-Rekonstruktion gilt innerhalb dieses
// Fensters, darüber truncated=true (dokumentierte Grenze, kein
// 'vollständig'-Versprechen).
function archiveEdges(edges) {
  const out = [];
  for (const e of Array.isArray(edges) ? edges : []) {
    const from = typeof e?.from === "string" && e.from ? e.from : null;
    const to = typeof e?.to === "string" && e.to ? e.to : null;
    if (!from || !to) continue;
    const seq = typeof e.ledgerSeq === "number" && Number.isFinite(e.ledgerSeq) ? e.ledgerSeq : null;
    const row = {
      from,
      to,
      amountDrops:
        typeof e.amountDrops === "number" && Number.isFinite(e.amountDrops) ? e.amountDrops : null,
      txHash: typeof e.txHash === "string" && e.txHash ? e.txHash : null,
      ledgerSeq: seq,
      closeTime: typeof e.closeTime === "string" && e.closeTime ? e.closeTime : null,
    };
    // Parität zum Live-View (viewEdge :973-997): Tx-TYP und Tag-Attribute
    // bleibenarchiviert (Kritik-Runde 3, Ask-Punkt 3) — ohne type würden
    // archivierte NFT-/AMM-/Escrow-Kanten im Replay neutral/grau rendern
    // (EDGE_DEFAULT), obwohl der Live-Payload denselben Kantenvertrag trägt.
    // Fehlendes Feld -> gar kein Feld (Byte-Neutralität zu älteren Beständen).
    if (typeof e.type === "string" && e.type) row.type = e.type;
    const edgeToTag = normalizeTag(e.toTag);
    if (edgeToTag != null) row.toTag = edgeToTag;
    const edgeFromTag = normalizeTag(e.fromTag);
    if (edgeFromTag != null) row.fromTag = edgeFromTag;
    if (e.transit === true) row.transit = true;
    out.push(row);
  }
  // Deterministisch: cmpEdge-Totalordnung (ledgerSeq asc, txHash asc,
  // Endpunkte asc) — dann Kappe: die NEUESTEN 200 bleiben (chronologische
  // Rückwärts-Rekonstruktion braucht die jüngsten Kanten zuerst).
  out.sort((a, b) => {
    const la = a.ledgerSeq == null ? -1 : a.ledgerSeq;
    const lb = b.ledgerSeq == null ? -1 : b.ledgerSeq;
    if (la !== lb) return la - lb;
    const h = viewCmpStrBin(a.txHash, b.txHash);
    if (h !== 0) return h;
    const f = viewCmpStrBin(a.from, b.from);
    if (f !== 0) return f;
    return viewCmpStrBin(a.to, b.to);
  });
  if (out.length > ARCHIVE_MAX_EDGES) out.splice(0, out.length - ARCHIVE_MAX_EDGES);
  return out;
}

function archiveLedgerRange(edges) {
  let min = null;
  let max = null;
  for (const e of edges) {
    if (e.ledgerSeq == null) continue;
    if (min == null || e.ledgerSeq < min) min = e.ledgerSeq;
    if (max == null || e.ledgerSeq > max) max = e.ledgerSeq;
  }
  return { from: min, to: max };
}

// Archiv-Rollen/-Severity (Parität zur View-Projektion): bekannte Werte
// durchreichen, fremde Rollen -> 'unknown', fremde Schweregrade fallen raus;
// deterministisch nach Adresse sortiert. Leere Map -> null (Byte-Neutralität
// zu älteren Beständen ohne Feld).
// BEGRENZUNG AUF Kanten-Endpunkte (endpoints = from/to der archivierten
// Kanten, <= 2 * ARCHIVE_MAX_EDGES = 400 Adressen): Rollen/Severity werden
// pro Archiv-ZEILE persistiert und sind damit maschinenlesbar für jeden
// Hop-Endpunkt verfügbar (jeder Hop-Endpunkt ist Kanten-Endpunkt). Der
// Hop-Vertrag von replayArchive ist das NICHT: die route=archive-Antwort
// trägt pro Hop from/to/type/amountDrops/txHash/ledgerSeq — die in der
// Archiv-Zeile persistierten Rollen/Severity (und die Kantentags
// toTag/fromTag/transit) erscheinen NICHT pro Hop in der Antwort
// (Kritik-Runde 4, Befund 4: die frühere Behauptung 'die Parität ist
// vollständig bedient' war zu breit; dokumentierte und von der API-
// Tabelle des READMEs gedeckte Parität der Antwort ist die type-Parität).
// Adressen ohne archivierter Kante fallen raus: ohne diese Begrenzung
// sprengte allein die Rollen-/Severity-Map eines Mega-Clusters
// (live-Fixture: 15.000 Mitglieder) die ARCHIVE_MAX_BYTES 900_000 des
// Tages-Dokuments und capArchiveDoc verdrängte die komplette
// Checkpoint-Zeile (advance-batch-Regression 2026-10-07) — Evidenz-Verlust
// durch Attribut-Blähung. Dokumentierte Grenze: Archiv-Rollen/-Severity
// sind Hop-relevant, nicht vollständig.
function archiveRolesByAddress(roles, endpoints) {
  if (!roles || typeof roles !== "object" || Array.isArray(roles)) return null;
  const keys = Object.keys(roles).sort(viewCmpStrBin).filter((a) => endpoints.has(a));
  if (!keys.length) return null;
  const out = {};
  for (const addr of keys) out[addr] = VIEW_ROLE_KEYS.includes(roles[addr]) ? roles[addr] : "unknown";
  return out;
}
function archiveSeverityByAddress(sev, endpoints) {
  if (!sev || typeof sev !== "object" || Array.isArray(sev)) return null;
  const keys = Object.keys(sev).sort(viewCmpStrBin).filter((a) => endpoints.has(a));
  if (!keys.length) return null;
  const out = {};
  for (const addr of keys) {
    if (VIEW_SEVERITY_KEYS.includes(sev[addr])) out[addr] = sev[addr];
  }
  return Object.keys(out).length ? out : null;
}

// Archiv-Zeile aus einem Cluster, das im selben Tick fallen würde.
function archiveDocForCluster(key, value) {
  const edges = archiveEdges(value.edges);
  const range = archiveLedgerRange(edges);
  // Endpunkte der ARCHIVIERTEN Kanten (nach Kappe) — Begrenzungsgrundlage
  // für roles/severityByAddress (siehe archiveRolesByAddress-Kommentar).
  const edgeEndpoints = new Set();
  for (const e of edges) {
    edgeEndpoints.add(e.from);
    edgeEndpoints.add(e.to);
  }
  return {
    clusterId: typeof value.id === "string" && value.id ? value.id : `cluster:${key}`,
    memberAddresses: (Array.isArray(value.memberAddresses) ? value.memberAddresses : [])
      .map((a) => String(a))
      .filter(Boolean)
      .sort(viewCmpStrBin),
    edges,
    peelingChains: Array.isArray(value.peelingChains) ? value.peelingChains : [],
    // Parität zum Live-View (Kritik-Runde 3, Ask-Punkt 3): Rollen und
    // Severity je Adresse wandern mit in die Archivzeile — ohne sie wäre
    // das Archiv gegenüber /api/flow-state semantikfrei (Rollen-Fallback
    // 'unknown' im Replay). Auf bekannte Rollen/Schwere gezwungen
    // (viewRoleCounts/viewSeverityByAddress-Konvention), deterministisch
    // nach Adresse sortiert, BEGRENZT auf Endpunkte der archivierten Kanten
    // (Hop-Parität vollständig, Byte-Budget gewahrt — Kommentar
    // archiveRolesByAddress). Defensiv: ältere Bestände ohne Felder bleiben
    // feldlos (Byte-neutral).
    roles: archiveRolesByAddress(value.roles, edgeEndpoints),
    severityByAddress: archiveSeverityByAddress(value.severityByAddress, edgeEndpoints),
    // V4 — Motive wandern mit in die Archivzeile (washCycles sind
    // hasFraudEvidence-Beweise; ohne Durchreichung verlöre die
    // Archiv-Eligibility ihren Beleg). Defensiv: ältere Bestände ohne
    // motifs bleiben null (Byte-neutral).
    motifs:
      value.motifs && typeof value.motifs === "object" && !Array.isArray(value.motifs)
        ? value.motifs
        : null,
    entitySnapshot:
      value.entitySnapshot && typeof value.entitySnapshot === "object" && !Array.isArray(value.entitySnapshot)
        ? value.entitySnapshot
        : null,
    firstSeen: typeof value.firstSeen === "string" ? value.firstSeen : null,
    lastSeen: typeof value.lastSeen === "string" ? value.lastSeen : null,
    ledgerRange: range,
    archivedAt: null, // wird im Append gesetzt
  };
}

// Archivierung genau der Cluster, die pruneFlowState im selben Tick fallen
// ließe — und NUR Betrugsevidenz-Cluster (reine Benign-Cluster werden nicht
// archiviert). Prädikat identisch zu pruneFlowState in beiden Verlustpfaden:
// Zeitgrenze (fraud-Fenster 30 d) UND Kappung (Schwere vor Volumen; Kappe =
// opts.maxClusters ?? FLOW_STATE_MAX_CLUSTERS — derselbe Cap wie
// mergeFlowState, Archiv-Kopplung gegen den Byte-Cap).
// lastSeen == null: im ZEIT-Zweig bleibt der Ausschluss (pruneFlowState
// behält null-Cluster unbegrenzt, kein Verlust). Im KAPPUNGS-Zweig dagegen
// wird jetzt archiviert: pruneFlowState :261 wirft null-lastSeen-Cluster
// sehr wohl raus, wenn die Kappung greift (Cap < Clusterzahl) — die alte
// Begründung 'pruneFlowState behält' galt nur für den Zeitpfad und wäre mit
// effektivem Byte-Cap ein stiller Evidenz-Verlustpfad geworden.
export function archiveFromFlowState(state, now, opts = {}) {
  const src = state && typeof state === "object" && !Array.isArray(state) ? state : freshFlowState();
  const clusters =
    src.clusters && typeof src.clusters === "object" && !Array.isArray(src.clusters) ? src.clusters : {};
  const t = Number(now);
  const base = Number.isFinite(t) ? t : Date.now();
  const maxClusters = Number.isFinite(opts.maxClusters)
    ? Math.max(0, Math.floor(opts.maxClusters))
    : FLOW_STATE_MAX_CLUSTERS;
  const keys = Object.keys(clusters).sort(viewCmpStrBin); // deterministisch

  // (1) Zeitgrenze: Betrugsevidenz-Cluster außerhalb des 30-d-Fensters.
  const docs = [];
  for (const key of keys) {
    const value = clusters[key];
    if (!value || typeof value !== "object") continue;
    if (!hasFraudEvidenceImpl(value)) continue; // reine Benign-Cluster: nie
    const lastMs = epochMsSafe(value.lastSeen);
    if (lastMs == null) continue; // nicht einordenbar -> pruneFlowState behält
    if (lastMs >= base - FLOW_STATE_MALICIOUS_RETENTION_MS) continue; // bleibt -> nicht archivieren
    docs.push(archiveDocForCluster(key, value));
  }

  // (2) Kappung: dieselbe survivors-Menge und dieselbe Sortierung wie
  // pruneFlowState; alles jenseits des Caps (opts.maxClusters ??
  // FLOW_STATE_MAX_CLUSTERS) verliert im selben Tick. Betrugsevidenz-Cluster
  // darunter werden archiviert — auch mit lastSeen == null: die Kappung
  // (entries.slice(0, maxClusters) in pruneFlowState) wirft null-Cluster
  // sehr wohl raus, der Zeitpfad-Ausschluss 'pruneFlowState behält' gilt
  // für diesen Zweig nicht.
  const survivors = [];
  for (const key of keys) {
    const value = clusters[key];
    if (!value || typeof value !== "object") continue;
    const lastMs = epochMsSafe(value.lastSeen);
    const window = hasFraudEvidenceImpl(value) ? FLOW_STATE_MALICIOUS_RETENTION_MS : FLOW_STATE_RETENTION_MS;
    if (lastMs != null && lastMs < base - window) continue; // Zeitverlust -> bereits (1)
    survivors.push([key, value]);
  }
  if (survivors.length > maxClusters) {
    survivors.sort((a, b) => {
      const fa = hasFraudEvidenceImpl(a[1]) ? 1 : 0;
      const fb = hasFraudEvidenceImpl(b[1]) ? 1 : 0;
      if (fa !== fb) return fb - fa;
      const da = Number(a[1]?.totalDrops) || 0;
      const db = Number(b[1]?.totalDrops) || 0;
      if (da !== db) return db - da;
      const ta = Number(a[1]?.txCount) || 0;
      const tb = Number(b[1]?.txCount) || 0;
      if (ta !== tb) return tb - ta;
      return a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0;
    });
    for (const [key, value] of survivors.slice(maxClusters)) {
      if (!hasFraudEvidenceImpl(value)) continue; // reine Benign-Cluster: nie
      docs.push(archiveDocForCluster(key, value));
    }
  }
  return docs;
}

// Tages-Checkpoint (Persistenz-Fix 2026-10-06): ALLE Betrugsevidenz-Cluster
// des (ungekappten) Flow-States als Archiv-Zeilen — OHNE Verlust-Prädikat
// (sie sind noch live im Bestand). Grund: seit dem Akkumulations-Fix greift
// kein Archivierungs-Zweig mehr (Zeit-Zweig nie — kein Cluster ist 30 d alt;
// Kappungs-Zweig nicht — Cap 200 > Clusterzahl), das Archiv füllte sich
// ausschließlich im Kollaps-Fenster (live: 9 Zeilen am 10-05, danach null).
// Der Checkpoint macht das Archiv kontinuierlich abfragbar (route=archive),
// je UTC-Tag einmal (Guard: Marker reason:'checkpoint' im frisch gelesenen
// Tages-Dokument, siehe hasCheckpointDoc — NICHT 'Datei existiert', denn der
// Kappungs-/Zeit-Zweig legt die Tagesdatei auch ohne Checkpoint an).
// Zeilen tragen reason:'checkpoint' und fallen in capArchiveDoc bei Byte-
// Druck ZUERST raus (reproduzierbare Snapshots lebender Cluster dürfen
// Verlust-Archiv-Evidenz nie verdrängen).
export function checkpointFromFlowState(state) {
  const src = state && typeof state === "object" && !Array.isArray(state) ? state : freshFlowState();
  const clusters =
    src.clusters && typeof src.clusters === "object" && !Array.isArray(src.clusters) ? src.clusters : {};
  const keys = Object.keys(clusters).sort(viewCmpStrBin); // deterministisch
  const docs = [];
  for (const key of keys) {
    const value = clusters[key];
    if (!value || typeof value !== "object") continue;
    if (!hasFraudEvidenceImpl(value)) continue; // reine Benign-Cluster: nie
    docs.push({ ...archiveDocForCluster(key, value), reason: "checkpoint" });
  }
  return docs;
}

// Guard-Marker: hat das frisch gelesene Tages-Dokument bereits eine
// Checkpoint-Zeile? (Der Marker sitzt auf der Zeile, nicht auf dem Dokument —
// normalizeArchiveDoc erzwingt die Dokument-Hülle {day, updatedAt, docs} und
// würde ein Dokument-Feld entfernen.)
export function hasCheckpointDoc(doc) {
  return (Array.isArray(doc?.docs) ? doc.docs : []).some((d) => d?.reason === "checkpoint");
}

// Append (ClusterId-Dedup, Idempotenz bei Retry-Ticks; deterministisch nach
// clusterId asc).
export function appendArchiveDoc(doc, docs) {
  const base = normalizeArchiveDoc(doc);
  const byId = new Map();
  for (const d of base.docs) byId.set(d.clusterId, d);
  for (const d of Array.isArray(docs) ? docs : []) {
    if (!d || typeof d !== "object" || typeof d.clusterId !== "string" || !d.clusterId) continue;
    byId.set(d.clusterId, d);
  }
  const out = [...byId.values()].sort((a, b) => viewCmpStrBin(a.clusterId, b.clusterId));
  return { day: base.day, updatedAt: base.updatedAt, docs: out };
}

// Byte-Cap des Archiv-Tages-Dokuments (präventiv, Muster FLOW_STATE_MAX_BYTES):
// die Archiv-Kopplung verlagert Evidenz aus dem gekappten Bestand ins Archiv —
// dessen Volumen steigt dadurch. Über ARCHIVE_MAX_BYTES fallen zuerst
// CHECKPOINT-Zeilen (reason 'checkpoint' — reproduzierbare Snapshots noch
// lebender Cluster, jeder Tick kann sie neu schreiben) und erst danach die
// ältesten Verlust-Archiv-Einträge raus (archivedAt asc, Gleichstand:
// clusterId asc); archivedAt null (ältere Bestände ohne Append-Zeit) gilt
// als älteste. Priorität seit dem Tages-Checkpoint 2026-10-06: Checkpoints
// dürfen Verlust-Evidenz NIE verdrängen (Persistenz-Korrektur b).
export const ARCHIVE_MAX_BYTES = 900_000;

export function capArchiveDoc(doc, maxBytes) {
  const base = normalizeArchiveDoc(doc);
  const cap = Number.isFinite(maxBytes) ? maxBytes : ARCHIVE_MAX_BYTES;
  const docs = [...base.docs];
  const ageOf = (d) => {
    const a = Number(d?.archivedAt);
    return Number.isFinite(a) ? a : -1; // null/fehlend -> älteste
  };
  const evictClassOf = (d) => (d?.reason === "checkpoint" ? 0 : 1); // Checkpoint zuerst
  while (docs.length > 0 && Buffer.byteLength(serializeArchiveDoc({ ...base, docs }), "utf8") > cap) {
    let worst = 0;
    for (let i = 1; i < docs.length; i++) {
      const ci = evictClassOf(docs[i]);
      const cw = evictClassOf(docs[worst]);
      if (ci !== cw) {
        if (ci < cw) worst = i; // niedrigere Klasse = überprüfbarer = zuerst raus
        continue;
      }
      const a = ageOf(docs[i]);
      const b = ageOf(docs[worst]);
      if (a < b || (a === b && viewCmpStrBin(docs[i].clusterId, docs[worst].clusterId) < 0)) worst = i;
    }
    docs.splice(worst, 1);
  }
  return { day: base.day, updatedAt: base.updatedAt, docs };
}

// Retention/Löschung (Kritik 6): docs = [{day, doc}] — Rückgabe verbleibende
// docs + Tages-Strings zum Löschen (Muster pruneBlockWindowDocs
// lib/block-window.mjs:306-322; Tagesgrenze = Ende des UTC-Tages).
// Malicious-Retention 30 d; Cold-Vault-/Registry-verknüpfte Cluster 180 d.
function isRegistryLinked(d) {
  const snap = d?.entitySnapshot;
  if (snap && typeof snap === "object" && !Array.isArray(snap)) {
    if (snap.registryLinked === true || snap.coldVault === true || snap.registryLabel) return true;
  }
  return false;
}

export function pruneArchiveDocs(docs, now, opts = {}) {
  const maliciousMs = Number.isFinite(opts.maliciousMs) ? opts.maliciousMs : ARCHIVE_RETENTION_MALICIOUS_MS;
  const registryMs = Number.isFinite(opts.registryMs) ? opts.registryMs : ARCHIVE_RETENTION_REGISTRY_MS;
  const n = Number(now);
  const base = Number.isFinite(n) ? n : Date.now();
  const keep = [];
  const staleDays = [];
  for (const entry of Array.isArray(docs) ? docs : []) {
    const day = typeof entry?.day === "string" ? entry.day : null;
    if (!day || !/^\d{4}-\d{2}-\d{2}$/.test(day)) continue;
    const dayEndMs = Date.parse(`${day}T23:59:59.999Z`);
    if (!Number.isFinite(dayEndMs)) continue;
    const list = Array.isArray(entry?.doc?.docs) ? entry.doc.docs : [];
    const survivors = list.filter((d) => {
      const window = isRegistryLinked(d) ? registryMs : maliciousMs;
      const lastMs = epochMsSafe(d?.lastSeen);
      // Retention-Anker max(lastSeen, archivedAt) (Akkumulations-Fix
      // 2026-10-06): Genau die Cluster, die der Zeit-Zweig aus dem Bestand
      // wirft (lastSeen > 30 d), werden archiviert — ein reiner
      // lastSeen-Anker machte sie im SELBEN Tick auch im Archiv stale
      // (live-Befund: PUT + DELETE data/flow-archive/<tag>.json in einem
      // Tick, soeben archivierte Beweislage sofort vernichtet). archivedAt
      // (Append-Zeit, api/advance.js iii.5) startet das Fenster neu;
      // archivedAt null/fehlend (ältere Bestände) -> unverändert lastSeen.
      const archivedMs = Number(d?.archivedAt);
      const anchors = [
        Number.isFinite(archivedMs) && archivedMs > 0 ? archivedMs : null,
        lastMs,
      ].filter((x) => x != null);
      const ref = anchors.length ? Math.max(...anchors) : dayEndMs;
      return !(ref < base - window);
    });
    if (survivors.length === 0) {
      staleDays.push(day);
    } else if (survivors.length !== list.length) {
      keep.push({ day, doc: { ...entry.doc, docs: survivors } });
    } else {
      keep.push(entry);
    }
  }
  // Deterministische Reihenfolge der Löschliste (asc).
  staleDays.sort();
  return { docs: keep, staleDays };
}

// Rückwärts-Rekonstruktion: folgt Edges von `address` ausgehend rückwärts
// (Kante e.to === current -> next = e.from) über ledgerSeq/txHash, nur
// Kanten im Fenster [fromLedger, toLedger]. Jenseits der Edge-Kappe
// ARCHIVE_MAX_EDGES pro Cluster-Zeile: truncated=true (dokumentierte Grenze;
// darüber ist account_tx-Replay nötig). Deterministisch: Pfade nach
// (ledgerSeq asc, txHash asc, from asc).
export function replayArchive(docs, { address, fromLedger, toLedger } = {}) {
  const target = typeof address === "string" ? address : null;
  if (!target) return { hops: [], truncated: false };
  const from = Number(fromLedger);
  const to = Number(toLedger);
  const edges = [];
  for (const entry of Array.isArray(docs) ? docs : []) {
    const list = Array.isArray(entry?.doc?.docs) ? entry.doc.docs : Array.isArray(entry?.docs) ? entry.docs : [];
    for (const d of list) {
      for (const e of Array.isArray(d?.edges) ? d.edges : []) {
        if (typeof e?.from !== "string" || typeof e?.to !== "string") continue;
        const seq = typeof e.ledgerSeq === "number" ? e.ledgerSeq : null;
        if (seq != null && Number.isFinite(from) && seq < from) continue;
        if (seq != null && Number.isFinite(to) && seq > to) continue;
        edges.push(e);
      }
    }
  }
  const hops = [];
  let current = target;
  let truncated = false;
  const visited = new Set([target]);
  while (hops.length < ARCHIVE_MAX_EDGES) {
    const inEdges = edges
      .filter((e) => e.to === current && !visited.has(e.from))
      .sort(
        (a, b) =>
          (a.ledgerSeq ?? -1) - (b.ledgerSeq ?? -1) ||
          viewCmpStrBin(a.txHash, b.txHash) ||
          viewCmpStrBin(a.from, b.from)
      );
    if (!inEdges.length) break;
    const e = inEdges[0];
    // Parität zum Live-Kantenvertrag (Ask-Punkt 3): der Hop trägt den
    // Tx-Typ (archiviert seit archiveEdges type-Parität) — ältere
    // Archivbestände ohne type bleiben null (defensiv, kein Ausfall).
    hops.push({ from: e.from, to: e.to, type: typeof e.type === "string" ? e.type : null, amountDrops: e.amountDrops ?? null, txHash: e.txHash ?? null, ledgerSeq: e.ledgerSeq ?? null });
    visited.add(e.from);
    current = e.from;
  }
  // Gibt es noch weitere eingehende Kanten am Endpunkt der Rekonstruktion,
  // war die Kappe der Grund: truncated.
  if (hops.length >= ARCHIVE_MAX_EDGES) {
    const remaining = edges.filter((e) => e.to === current && !visited.has(e.from));
    if (remaining.length > 0) truncated = true;
  }
  return { hops, truncated };
}

// ---------- GitHub-Transport Archiv (wiederverwendet, eigener Codec + Pfad)
export async function readArchiveGitHub(day) {
  const { doc, sha } = await readGitHubContents(archivePath(day), archiveCodec);
  return { doc: doc ?? emptyArchiveDoc(day), sha };
}

export function writeArchiveGitHub(day, apply) {
  return writeGitHubContents(
    (doc) => apply(doc ?? emptyArchiveDoc(day)),
    archivePath(day),
    archiveCodec
  );
}

export async function deleteArchiveGitHub(day) {
  return deleteGitHubFile(archivePath(day));
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
  const out = {
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
  // Tag-Attribute (lib/tag-identity.mjs): toTag auf UInt32 zwingen (Tag 0
  // bleibt 0), defekte Werte fallen raus; transit nur als echtes true.
  const toTag = normalizeTag(e.toTag);
  if (toTag != null) out.toTag = toTag;
  const fromTag = normalizeTag(e.fromTag);
  if (fromTag != null) out.fromTag = fromTag;
  if (e.transit === true) out.transit = true;
  return out;
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
// baitLabels (optional): Köder-Adressen fallen STILL raus (kein Oracle) —
// die Flow-Graph-View rendert rolesByAddress ohne weiteren Client-Deny,
// daher filtert bereits die Server-Projektion (B2-Schließung der Lücke
// public/history-host.html:184).
function viewRolesByAddress(roles, baitLabels) {
  const out = {};
  if (roles && typeof roles === "object" && !Array.isArray(roles)) {
    for (const addr of Object.keys(roles).sort(viewCmpStrBin)) {
      if (baitLabels && baitLabels.has(addr)) continue; // STILL — kein Oracle
      const role = roles[addr];
      out[addr] = VIEW_ROLE_KEYS.includes(role) ? role : "unknown";
    }
  }
  return out;
}

// Retained edges eines Clusters (Wrapper mit baitLabels-Filter): eine Kante
// mit Köder-Endpunkt fällt still raus; die verbleibenden Textfelder laufen
// durch sanitizeText (Defense-in-Depth, Muster api/ledger.js:188).
function viewEdgesFiltered(edges, baitLabels) {
  const out = viewEdges(edges);
  if (!baitLabels || baitLabels.size === 0) return out;
  return out
    .filter((e) => !baitLabels.has(e.from) && !baitLabels.has(e.to))
    .map((e) => ({
      ...e,
      type: e.type != null ? sanitizeText(e.type, baitLabels) : null,
      txHash: e.txHash != null ? sanitizeText(e.txHash, baitLabels) : null,
    }));
}

// baitLabels-Auflösung (optional): explizite Übergabe gewinnt; sonst ENV
// BAIT_ADDRESSES (Muster api/ledger.js:41-46 — Adressen nur aus ENV, nie
// Seeds, nie aus bait.json). Ohne ENV/Übergabe bleibt die View ungefiltert
// (Test-Fixtures ohne ENV-Baits bleiben grün).
function resolveBaitLabels(baitLabels) {
  if (baitLabels instanceof Map && baitLabels.size > 0) return baitLabels;
  const env = process.env.BAIT_ADDRESSES || "";
  if (!env.trim()) return baitLabels instanceof Map ? baitLabels : null;
  const map = new Map();
  env
    .split(",")
    .map((a) => a.trim())
    .filter(Boolean)
    .forEach((addr, i) => map.set(addr, `HP-${i + 1}`));
  return map;
}

// Per-Adress-Schweregrade (Adresse -> 'malicious'|'suspect'|'info'): wird
// serverseitig bereits berechnet (cluster.mjs severityByAddress) und muss
// durch den Flow-State-Merge bis zur View durchgereicht werden — der
// Polling-Pfad (app.js applyFlowStateView) leitet daraus die Badge-Stufe ab
// statt hart 'info'. Köder-Adressen fallen STILL raus (B2).
const VIEW_SEVERITY_KEYS = ["malicious", "suspect", "info"];
function viewSeverityByAddress(sevMap, baitLabels) {
  const out = {};
  if (sevMap && typeof sevMap === "object" && !Array.isArray(sevMap)) {
    for (const addr of Object.keys(sevMap).sort(viewCmpStrBin)) {
      if (baitLabels && baitLabels.has(addr)) continue; // STILL — kein Oracle
      const sev = sevMap[addr];
      if (VIEW_SEVERITY_KEYS.includes(sev)) out[addr] = sev;
    }
  }
  return out;
}

// Peeling-Ketten der View (Kritik 4): deterministisch sortiert (Ketten-
// signatur asc, hops ledgerSeq asc/txHash asc — dieselbe Totalordnung wie
// viewEdges :306-328); Köder-Endpunkte fallen STILL raus (Muster
// viewEdgesFiltered :353-363). Eine Kette, deren Seed oder Endpunkt ein
// Köder ist, entfällt komplett; Brückenknoten-Adressen bleiben (sie sind
// keine Fund-Adressen).
function viewPeelingChains(chains, baitLabels) {
  const out = [];
  for (const ch of Array.isArray(chains) ? chains : []) {
    if (!ch || typeof ch !== "object") continue;
    const addresses = (Array.isArray(ch.addresses) ? ch.addresses : [])
      .map((a) => String(a))
      .filter(Boolean);
    if (!addresses.length) continue;
    if (baitLabels && addresses.some((a) => baitLabels.has(a))) continue; // STILL
    const hops = [];
    for (const h of Array.isArray(ch.hops) ? ch.hops : []) {
      if (!h || typeof h !== "object") continue;
      const from = typeof h.from === "string" && h.from ? h.from : null;
      const to = typeof h.to === "string" && h.to ? h.to : null;
      if (!from || !to) continue;
      hops.push({
        from,
        to,
        amountDrops:
          typeof h.amountDrops === "number" && Number.isFinite(h.amountDrops) ? h.amountDrops : null,
        ratio: typeof h.ratio === "number" && Number.isFinite(h.ratio) ? h.ratio : null,
        txHash: typeof h.txHash === "string" && h.txHash ? h.txHash : null,
        ledgerSeq:
          typeof h.ledgerSeq === "number" && Number.isFinite(h.ledgerSeq) ? h.ledgerSeq : null,
      });
    }
    hops.sort((a, b) => {
      const la = a.ledgerSeq == null ? -1 : a.ledgerSeq;
      const lb = b.ledgerSeq == null ? -1 : b.ledgerSeq;
      if (la !== lb) return la - lb;
      return viewCmpStrBin(a.txHash, b.txHash);
    });
    const seed = typeof ch.seed === "string" && ch.seed ? ch.seed : addresses[0];
    const bridges = (Array.isArray(ch.bridges) ? ch.bridges : [])
      .map((a) => String(a))
      .filter((a) => a && !(baitLabels && baitLabels.has(a)))
      .sort(viewCmpStrBin);
    // addresses bleibt in KETTENREIHENFOLGE (Seed zuerst) — die Signatur
    // (join ',') ist die Sortierbasis; sortierte Adressen würden die
    // Kettenordnung zerstören.
    // V2-Durchreichung (defensiv): fingerprint {score, criteria} und
    // confidence 'high' sind beschreibende Ketten-Attribute (keine Severity);
    // remainderHops dokumentiert die Remainder-Rinne (V1b).
    const fpRaw = ch.fingerprint && typeof ch.fingerprint === "object" && !Array.isArray(ch.fingerprint) ? ch.fingerprint : null;
    const fp =
      fpRaw != null
        ? {
            score: Math.max(0, Math.floor(Number(fpRaw.score) || 0)),
            criteria: (Array.isArray(fpRaw.criteria) ? fpRaw.criteria : []).map((x) => String(x)),
          }
        : null;
    const remainderHops = Math.max(0, Math.floor(Number(ch.remainderHops) || 0));
    out.push({
      addresses,
      hops,
      seed,
      seedSeverity: VIEW_SEVERITY_KEYS.includes(ch.seedSeverity) ? ch.seedSeverity : null,
      hopsCount: hops.length,
      bridges,
      signature: addresses.join(","),
      ...(fp ? { fingerprint: fp } : {}),
      ...(ch.confidence === "high" ? { confidence: "high" } : {}),
      ...(remainderHops > 0 ? { remainderHops } : {}),
    });
  }
  out.sort((a, b) => viewCmpStrBin(a.signature, b.signature));
  return out;
}

// V3 — temporale Projektion: Serie je Evidenz-Adresse (bait-gefiltert, STILL
// — kein Oracle) plus der abgeleiteten Metriken (temporalMetrics, rein).
// FP-Guard d bleibt gewahrt: reine Zusatz-Attribute für Analysten/API, kein
// Severity-Einfluss.
function viewTemporal(temporal, bait) {
  const out = {};
  if (temporal && typeof temporal === "object" && !Array.isArray(temporal)) {
    for (const addr of Object.keys(temporal).sort(viewCmpStrBin)) {
      if (bait && bait.has(addr)) continue; // STILL — kein Oracle
      const e = temporal[addr];
      const entry = {
        s: (Array.isArray(e?.s) ? e.s : []).map(Number).filter(Number.isFinite),
        out: viewNum(e?.out),
        outN: Math.max(0, Math.floor(viewNum(e?.outN))),
      };
      out[addr] = { ...entry, ...temporalMetrics(entry) };
    }
  }
  return out;
}

// V4 — Motiv-Projektion (Muster viewPeelingChains): deterministisch (Adresse
// asc bzw. Zyklus-Signatur asc), Köder-Endpunkte fallen STILL raus (kein
// Oracle) — ein Zyklus mit Köder-Endpunkt entfällt komplett, Gather-Scatter-
// Adressen ebenso. Reine Zahlen-Coercion; Rückgabe null bei leerer Sicht
// (ältere Bestände ohne motifs bleiben feldlos und damit bitgleich).
function viewMotifs(motifs, bait) {
  if (!motifs || typeof motifs !== "object" || Array.isArray(motifs)) return null;
  const gatherScatter = (Array.isArray(motifs.gatherScatter) ? motifs.gatherScatter : [])
    .filter((a) => typeof a === "string" && a && !(bait && bait.has(a)))
    .sort(viewCmpStrBin);
  const washCycles = [];
  for (const cy of Array.isArray(motifs.washCycles) ? motifs.washCycles : []) {
    if (!cy || typeof cy !== "object") continue;
    const a = typeof cy.a === "string" && cy.a ? cy.a : null;
    const b = typeof cy.b === "string" && cy.b ? cy.b : null;
    if (!a || !b) continue;
    if (bait && (bait.has(a) || bait.has(b))) continue; // STILL — kein Oracle
    const seqOrNull = (v) => {
      const n = Number(v);
      return v != null && Number.isFinite(n) ? n : null;
    };
    washCycles.push({
      a,
      b,
      fwdDrops: viewNum(cy.fwdDrops),
      bwdDrops: viewNum(cy.bwdDrops),
      conserve: typeof cy.conserve === "number" && Number.isFinite(cy.conserve) ? cy.conserve : null,
      firstLedgerSeq: seqOrNull(cy.firstLedgerSeq),
      lastLedgerSeq: seqOrNull(cy.lastLedgerSeq),
      signature: `${a},${b}`,
    });
  }
  washCycles.sort((x, y) => viewCmpStrBin(x.signature, y.signature));
  if (!gatherScatter.length && !washCycles.length) return null;
  return {
    gatherScatter,
    washCycles,
    fanInMax: Math.max(0, Math.floor(viewNum(motifs.fanInMax))),
    fanOutMax: Math.max(0, Math.floor(viewNum(motifs.fanOutMax))),
  };
}

export function projectFlowStateView(doc, baitLabels) {
  const bait = resolveBaitLabels(baitLabels);
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
      .filter((a) => a && !(bait && bait.has(a))); // STILL-Filter (sortKey nutzt die gefilterte Liste)
    // fieldsCapped (Kritik-Runde 3): true, wenn die Write-Pfad-Feldkappe
    // (capClusterFields, FLOW_STATE_MEMBER_CAP 300) memberAddresses gekürzt
    // hat. Vergleich BAIT-INKLUSIV und VOR dem STILL-Filter — sonst meldet
    // ein köderreicher Cluster falsch-negativ 'nicht gekappt'. distinctAccounts
    // ist seit dem Monotonie-Fix (lib/ledger-walk.mjs mergeCluster) der je
    // gesehene Bestand: memberAddresses.length < distinctAccounts ist genau
    // das Kap-Signal (die Kappe komprimiert Felder, distinctAccounts lügt
    // nicht über die Größe — flow-state.mjs:339-341). Nur gesetzt wenn
    // gekappt (feldlos = unkapped, Muster motifs/temporal — Byte-Neutralität).
    const rawMemberCount = Array.isArray(value.memberAddresses) ? value.memberAddresses.length : 0;
    const fieldsCapped = rawMemberCount < viewNum(value.distinctAccounts);
    // V4 — Motiv-Sicht (nur gesetzt, wenn nach dem Köder-Filter etwas
    // übrig bleibt; ältere Bestände ohne motifs bleiben feldlos).
    const motifs = viewMotifs(value.motifs, bait);
    entries.push({
      sortKey: members[0] ?? "",
      cluster: {
        id: typeof value.id === "string" && value.id ? value.id : `cluster:${key}`,
        label: "", // wird nach der Sortierung gesetzt (Konvention lib/cluster.mjs)
        roles: viewRoleCounts(value.roles),
        rolesByAddress: viewRolesByAddress(value.roles, bait),
        severityByAddress: viewSeverityByAddress(value.severityByAddress, bait),
        edges: viewEdgesFiltered(value.edges, bait),
        peelingChains: viewPeelingChains(value.peelingChains, bait),
        totalDrops: viewNum(value.totalDrops),
        txCount: viewNum(value.txCount),
        distinctAccounts: viewNum(value.distinctAccounts),
        firstSeen: typeof value.firstSeen === "string" ? value.firstSeen : null,
        lastSeen: typeof value.lastSeen === "string" ? value.lastSeen : null,
        ...(fieldsCapped ? { fieldsCapped: true } : {}),
        ...(motifs ? { motifs } : {}),
        // V3 — temporale Metriken (nur gesetzt, wenn das Cluster eine Serie
        // trägt; ältere Bestände bleiben feldlos und damit bitgleich).
        ...(value.temporal && typeof value.temporal === "object" && !Array.isArray(value.temporal)
          ? { temporal: viewTemporal(value.temporal, bait) }
          : {}),
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
