// public/graph-budget.mjs — DOM-freie Helfer des gekappten Live-Bühnen-Graphen
// (Kritik-Runde 3 2026-10-07: Archiv-Graph-Parität). Verbraucher: public/app.js
// (updateRawGraph-Knoten-Deckel, renderLiveGraph-Fensterfilter). MODUL-VERTRAG
// (Muster public/cluster-views.mjs): DOM-frei beim Import, kein fetch, kein
// window/document — reine Datenauswahl; die Maskierungs-Gates bleiben Host-Sache.
//
// WARUM EIN EIGENES MODUL: der bisherige Deckel (Schwere → Drops → Adresse,
// app.js) degeneriert im Archiv-Pfad zum lexikografischen Ausschnitt, weil
// Archiv-Knoten keine inDrops/outDrops tragen und fast alle severity
// 'malicious' ist — gemessen überlebten 1/975 Kanten und 596/600 Knoten
// waren Rolle 'unknown'. Der dreiphasige Budget-Satz stellt die Semantik
// wieder her: Evidenz-Knoten und Top-Kanten-Endpunkte sind garantiert im
// Budget, aufgefüllt wird mit der bisherigen Rangliste.

/* ---------- Fenster (Zeitfenster-Buttons 24h/3d/7d/30d/90d) ----------
 * EHRLICHE RETENTION (README 'Retention & Grenzen'): das Block-Fenster
 * (route=block-window) endet bei 7 d — 30 d/90 d sind dort ein Fenster-
 * Versprechen auf nicht mehr existierende Daten und werden im Feed nicht
 * abgefragt (api/flow-state.js lehnt sie dort mit 400 ab). 30 d ist ehrlich
 * für den Betrugsevidenz-Bestand des Flow-States (malicious-Retention 30 d,
 * lib/flow-state.mjs), 90 d darüber hinaus nur für archiviert registrierte
 * Evidenz (180 d), deren Abfragbarkeit über route=archive bei Default-Kappe
 * 62 d endet — beides wird über truncated-Kennzeichnungen sichtbar gemacht. */
export const FEED_RANGES = ['24h', '3d', '7d', '30d', '90d'];
export const FEED_RANGE_MS = {
  '24h': 24 * 3600 * 1000,
  '3d': 3 * 24 * 3600 * 1000,
  '7d': 7 * 24 * 3600 * 1000,
  '30d': 30 * 24 * 3600 * 1000,
  '90d': 90 * 24 * 3600 * 1000,
};
// Block-Fenster-Retention (lib/block-window.mjs:79): alles darüber zeigt der
// Feed nur noch den persistierten Fraud-Bestand, nie Block-Detailkarten.
export const BLOCK_WINDOW_MAX_RANGE = '7d';

// closeTime -> Epoch-ms; null/leer/nicht parsebar -> null (kein Zeitanspruch).
export function edgeTimeMs(e) {
  const raw = e && typeof e.closeTime === 'string' ? e.closeTime : null;
  if (!raw) return null;
  const ms = Date.parse(raw);
  return Number.isFinite(ms) ? ms : null;
}

// Kanten des gewählten Zeitfensters: Kanten mit parsebarem closeTime
// innerhalb des Fensters bleiben; Kanten OHNE parsebares closeTime bleiben
// ebenfalls (sie tragen keinen Zeitanspruch und sind Teil der Cluster-
// Evidenz — still zu verwerfen wäre ein Verlust ohne Gewinn an Wahrheit).
// Deterministisch: Reihenfolge der Eingabe bleibt erhalten.
export function edgesInWindow(edges, windowMs, nowMs) {
  const list = Array.isArray(edges) ? edges : [];
  if (!Number.isFinite(windowMs) || windowMs <= 0 || !Number.isFinite(nowMs)) return list;
  const from = nowMs - windowMs;
  return list.filter((e) => {
    const t = edgeTimeMs(e);
    return t == null || t >= from;
  });
}

// Älteste parsebare Kantenzeit des Bestands (null ohne Zeitstempel) — Basis
// der ehrlichen truncated-Kennzeichnung, wenn das Fenster über den
// vorhandenen Bestand hinausgreift.
export function oldestEdgeMs(edges) {
  let oldest = null;
  for (const e of Array.isArray(edges) ? edges : []) {
    const t = edgeTimeMs(e);
    if (t != null && (oldest == null || t < oldest)) oldest = t;
  }
  return oldest;
}

/* ---------- Knoten-Deckel: dreiphasiger Budget-Satz ---------- */
export const SEV_CAP_RANK = { malicious: 2, suspect: 1, info: 0 };
// Spiegel von ROLE_RANK_WALK (lib/ledger-walk.mjs:422) — dieselbe Rollen-
// Wertigkeit wie der Server-Merge.
export const EVIDENCE_ROLE_RANK = { unknown: 0, relay: 1, source: 2, collector: 3, drainer: 4 };
// Phase-A-Deckel: Evidenz-Knoten (Rolle source/collector/drainer ODER
// severity malicious) sind vorgeschützt, aber mit fester Obergrenze
// EVIDENCE_FLOOR_MAX = 120 Slots — bei Bühnen-Budget 600 ein Fünftel des
// Budgets. Bei kleineren Budgets greift Math.min(120, maxNodes): die Kappe
// ist dann das Budget selbst, also NICHT proportional (bei maxNodes 200
// wären 120 Slots = 60 % — Verhalten deterministisch und in
// graph-budget.test.mjs getestet; die frühere Kommentar-Beschreibung
// 'Hälfte / proportional' war falsch, Kritik-Runde 4 Befund 6).
export const EVIDENCE_FLOOR_MAX = 120;

// binärer String-Vergleich (Spiegel von viewCmpStrBin, lib/flow-state.mjs) —
// locale-frei, identische Totalordnung wie die Server-Projektion.
const cmpBin = (a, b) => (a < b ? -1 : a > b ? 1 : 0);

// Totalordnung der Kanten-Auswahl = exakt die von topKEdges (lib/ledger-walk.
// mjs:772-782) / viewEdges (lib/flow-state.mjs:1082-1094): Volumen desc
// (Null/IOU zählt 0), dann ledgerSeq asc (fehlend -> -1), txHash asc,
// from asc, to asc. Deterministisch bei jeder Einfügefolge.
export function cmpEdgeTotal(a, b) {
  const va = Number.isFinite(Number(a?.amountDrops)) ? Math.max(0, Number(a.amountDrops)) : 0;
  const vb = Number.isFinite(Number(b?.amountDrops)) ? Math.max(0, Number(b.amountDrops)) : 0;
  if (va !== vb) return vb - va;
  const la = Number.isFinite(Number(a?.ledgerSeq)) ? Number(a.ledgerSeq) : -1;
  const lb = Number.isFinite(Number(b?.ledgerSeq)) ? Number(b.ledgerSeq) : -1;
  if (la !== lb) return la - lb;
  const h = cmpBin(String(a?.txHash ?? ''), String(b?.txHash ?? ''));
  if (h !== 0) return h;
  const f = cmpBin(String(a?.from ?? ''), String(b?.from ?? ''));
  if (f !== 0) return f;
  return cmpBin(String(a?.to ?? ''), String(b?.to ?? ''));
}

const sevRankOf = (n) => SEV_CAP_RANK[String(n?.severity ?? 'info')] ?? 0;
const roleRankOf = (n) => EVIDENCE_ROLE_RANK[String(n?.role ?? 'unknown')] ?? 0;
const dropsOf = (n) => Math.max(0, Number(n?.inDrops ?? 0)) + Math.max(0, Number(n?.outDrops ?? 0));

// Dreiphasige, deterministische Knotenauswahl für den Bühnen-Deckel:
// Phase A — Evidenz-Floor (gedeckelt): Rolle ∈ {source, collector, drainer}
//   ODER severity 'malicious'; Rang severity desc → roleRank desc → id asc.
// Phase B — Kanten: Kanten in cmpEdgeTotal-Totalordnung; Endpunkte ins
//   Restbudget aufnehmen, bis es voll ist (Endpunkte, die keine Knoten sind,
//   zählen nicht — sie können nicht gezeichnet werden).
// Phase C — Auffüllung: verbleibende Knoten nach der bisherigen Rangliste
//   severity desc → inDrops+outDrops desc → id asc.
// DOKUMENTIERTER VERLUST (nicht still): ist das Budget nach Phase B erschöpft,
// fallen niedrig-rangige Knoten raus — das taten sie vorher auch; der
// Unterschied ist, dass Evidenz-Knoten und Top-Kanten-Endpunkte vorgeschützt
// sind. Ausgabe: Rohknoten in Eingabereihenfolge, gefiltert auf das Budget
// (bijektiv deterministisch: gleicher Input -> gleicher Output).
export function selectCappedNodes(rawNodes, rawEdges, maxNodes) {
  const nodes = Array.isArray(rawNodes) ? rawNodes : [];
  const edges = Array.isArray(rawEdges) ? rawEdges : [];
  if (!Number.isInteger(maxNodes) || maxNodes <= 0 || nodes.length <= maxNodes) return nodes;
  const nodeIds = new Set(nodes.map((n) => String(n?.id ?? '')));
  const budget = new Set();

  // Phase A — Evidenz-Floor.
  const evidence = nodes
    .filter((n) => String(n?.severity ?? 'info') === 'malicious'
      || String(n?.role ?? 'unknown') === 'source'
      || String(n?.role ?? 'unknown') === 'collector'
      || String(n?.role ?? 'unknown') === 'drainer')
    .sort((a, b) => sevRankOf(b) - sevRankOf(a)
      || roleRankOf(b) - roleRankOf(a)
      || cmpBin(String(a?.id ?? ''), String(b?.id ?? '')));
  const floorCap = Math.min(EVIDENCE_FLOOR_MAX, maxNodes);
  for (const n of evidence.slice(0, floorCap)) budget.add(String(n?.id ?? ''));

  // Phase B — Endpunkte der volumen-stärksten Kanten.
  const sortedEdges = edges
    .filter((e) => e && nodeIds.has(String(e.from)) && nodeIds.has(String(e.to)))
    .sort(cmpEdgeTotal);
  for (const e of sortedEdges) {
    if (budget.size >= maxNodes) break;
    const from = String(e.from);
    const to = String(e.to);
    const missing = [];
    if (!budget.has(from)) missing.push(from);
    if (!budget.has(to)) missing.push(to);
    if (!missing.length) continue;
    if (budget.size + missing.length > maxNodes) continue; // Budget voll: dokumentierter Verlust
    for (const id of missing) budget.add(id);
  }

  // Phase C — Auffüllung mit der bisherigen Rangliste.
  if (budget.size < maxNodes) {
    const rest = nodes
      .filter((n) => !budget.has(String(n?.id ?? '')))
      .sort((a, b) => sevRankOf(b) - sevRankOf(a)
        || dropsOf(b) - dropsOf(a)
        || cmpBin(String(a?.id ?? ''), String(b?.id ?? '')));
    for (const n of rest) {
      if (budget.size >= maxNodes) break;
      budget.add(String(n?.id ?? ''));
    }
  }

  return nodes.filter((n) => budget.has(String(n?.id ?? '')));
}
