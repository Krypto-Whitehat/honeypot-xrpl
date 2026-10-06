'use strict';
// public/cluster-views.mjs — DOM-freie Helfer der Cluster-Akkumulation
// (Fix 2026-10-06, zweite Runde): Normalisierung der Server-View-Cluster
// (serverClustersFromView) und Merge der Fenster-Cluster mit den
// akkumulierten Clustern (mergeClusterViews). Verbraucher:
// public/app.js (rebuildClusterGraph / pollFlowState / setFeedMode).
//
// MODUL-VERTRAG (Muster public/cluster-chips.mjs, public/name-index.mjs):
// DOM-frei beim Import, kein fetch, kein window/document — reine Daten-
// transformation. Köder-Maskierung bleibt Host-Sache (dieses Modul rendert
// nichts und filtriert nicht; die Host-Gates isFullShownAddr/
// displayFindingAddr/multiUserEntryOf greifen unverändert in app.js).
//
// MERGE-SEMANTIK (Live-Befund 2026-10-06, Mega-Cluster-Verschwinden):
// DEDUP NUR NOCH ÜBER DIE ID — die frühere ≥1-Mitglied-Überlappungs-
// Absorption verwarf den persistierten Zwilling komplett: der Mega-Cluster
// (46.660 Accounts) teilte sich mit fast JEDEM Fenster-Cluster mindestens
// eine Adresse (Exchange-Konten) und verschwand dadurch als Karte samt
// akkumulierter Statistik aus der Liste, obwohl die API ihn lieferte.
// Gleiche id (Fenster- und Server-Cluster leiten sie identisch als
// 'cluster:<Adresse>' her, lib/cluster.mjs / lib/flow-state.mjs) heißt
// jetzt: EINE Karte mit GEUNIONETER Statistik (Fenster = frische Knoten
// und Kanten, Server = akkumulierte Zähler/Zeitstempel/Mitglieder).
// Persistierte Cluster ohne Zwilling bleiben unverändert stehen.

// Schwere-Rang (Spiegel des Hosts app.js, single source für Sortierung und
// Severity-Union dieses Moduls).
export const SEV_RANK = { info: 0, suspect: 1, malicious: 2 };

// Cluster der Server-View (/api/flow-state, projectFlowStateView) in die
// Karten-/Graph-Form bringen: die Server-View trägt rolesByAddress statt
// memberAddresses; memberAddresses wird für die bestehenden Konsumenten
// (renderClusterList, drilldown, globe) deterministisch aus rolesByAddress
// abgeleitet.
export function serverClustersFromView(view) {
  return (Array.isArray(view?.clusters) ? view.clusters : []).map((c) => {
    const rolesByAddress = c?.rolesByAddress && typeof c?.rolesByAddress === 'object' ? c.rolesByAddress : {};
    return {
      id: String(c?.id ?? ''),
      label: c?.label ?? null,
      roles: rolesByAddress,
      rolesByAddress,
      severityByAddress: c?.severityByAddress && typeof c.severityByAddress === 'object' ? c.severityByAddress : {},
      memberAddresses: Object.keys(rolesByAddress),
      edges: Array.isArray(c?.edges) ? c.edges : [],
      totalDrops: Number(c?.totalDrops) || 0,
      txCount: Number(c?.txCount) || 0,
      distinctAccounts: Number(c?.distinctAccounts) || 0,
      firstSeen: c?.firstSeen ?? null,
      lastSeen: c?.lastSeen ?? null,
      peelingChains: Array.isArray(c?.peelingChains) ? c.peelingChains : [],
    };
  });
}

// Zahlen- und Zeitstempel-Helfer der Union: Zähler als Maximum (die
// Akkumulation ist monoton — Fenster- und Server-Zähler zählen dasselbe
// Ereignisvolumen über unterschiedliche Horizonte), Zeitstempel als
// earliest/latest; unparsebare Zeitstempel verlieren nie gegen parsebare.
const numOf = (v) => (Number.isFinite(Number(v)) ? Number(v) : 0);

function isoExtremum(a, b, preferEarlier) {
  const ma = Date.parse(String(a ?? ''));
  const mb = Date.parse(String(b ?? ''));
  const fa = Number.isFinite(ma);
  const fb = Number.isFinite(mb);
  if (fa && fb) {
    if (ma === mb) return a ?? b;
    return (preferEarlier ? ma < mb : ma > mb) ? a : b;
  }
  if (fa) return a;
  if (fb) return b;
  return a ?? b ?? null;
}

function edgeKeyOf(e) {
  if (!e || typeof e !== 'object') return '';
  return `${String(e.from ?? '')}>${String(e.to ?? '')}:${String(e.txHash ?? '')}:${String(e.closeTime ?? '')}`;
}

// Union EINER Fenster-Cluster mit ihrem persistierten Zwilling (gleiche id):
// Fenster-Cluster ist die Basis (ihre Knoten liegen im Live-Graphen und
// tragen clusterId === id — der Drilldown-Modal-Lookup über clusterId bleibt
// ohne Retagging korrekt, drilldown.js Knoten-Gate). Rollen des Fensters
// schlagen die persistierten (frisch), Severity unioned nach Rang.
export function unionClusterWith(windowCluster, persistedCluster) {
  const w = windowCluster && typeof windowCluster === 'object' ? windowCluster : {};
  const p = persistedCluster && typeof persistedCluster === 'object' ? persistedCluster : {};
  const members = (Array.isArray(w.memberAddresses) ? w.memberAddresses : []).map(String);
  const seen = new Set(members);
  for (const m of (Array.isArray(p.memberAddresses) ? p.memberAddresses : []).map(String)) {
    if (!seen.has(m)) { seen.add(m); members.push(m); }
  }
  const roles = {
    ...(p.rolesByAddress && typeof p.rolesByAddress === 'object' ? p.rolesByAddress : (p.roles ?? {})),
    ...(w.rolesByAddress && typeof w.rolesByAddress === 'object' ? w.rolesByAddress : (w.roles ?? {})),
  };
  const severityByAddress = {
    ...(p.severityByAddress && typeof p.severityByAddress === 'object' ? p.severityByAddress : {}),
  };
  const wSev = w.severityByAddress && typeof w.severityByAddress === 'object' ? w.severityByAddress : {};
  for (const [addr, s] of Object.entries(wSev)) {
    const prev = severityByAddress[addr];
    severityByAddress[addr] = (SEV_RANK[s] ?? 0) >= (SEV_RANK[prev] ?? 0) ? s : prev;
  }
  const edges = Array.isArray(w.edges) ? w.edges.slice() : [];
  const edgeKeys = new Set(edges.map(edgeKeyOf));
  for (const e of Array.isArray(p.edges) ? p.edges : []) {
    const key = edgeKeyOf(e);
    if (key && !edgeKeys.has(key)) { edgeKeys.add(key); edges.push(e); }
  }
  return {
    ...w,
    label: w.label || p.label || null,
    memberAddresses: members,
    roles,
    rolesByAddress: roles,
    severityByAddress,
    edges,
    totalDrops: Math.max(numOf(w.totalDrops), numOf(p.totalDrops)),
    txCount: Math.max(numOf(w.txCount), numOf(p.txCount)),
    distinctAccounts: Math.max(numOf(w.distinctAccounts), numOf(p.distinctAccounts)),
    firstSeen: isoExtremum(w.firstSeen, p.firstSeen, true),
    lastSeen: isoExtremum(w.lastSeen, p.lastSeen, false),
    peelingChains: [
      ...(Array.isArray(w.peelingChains) ? w.peelingChains : []),
      ...(Array.isArray(p.peelingChains) ? p.peelingChains : []),
    ],
  };
}

// Merge der Fenster-Cluster (WSS, frisch) mit den akkumulierten Clustern
// (Server-View plus Session-Schicht; beide sehen strukturell gleich aus).
// Dedup ausschließlich über die id (Semantik-Begründung oben); persistierte
// Cluster OHNE Fenster-Zwilling bleiben komplett stehen — auch wenn sie
// Mitglieder mit Fenster-Clustern teilen (kein Verschwinden des
// Mega-Clusters mehr). Sortierung unverändert: Schwere desc (max über
// severityByAddress), dann lastSeen desc (Aktivität), dann totalDrops desc,
// dann id asc (deterministische Totalordnung). Das Ergebnis MUSS vor
// renderClusterList in lastClusterGraph.clusters stehen (drilldown.js
// findCardForClusterId indexiert die Drilldown-Karte über den Array-Index
// dieses Caches — Liste und Cache müssen exakt übereinstimmen).
export function mergeClusterViews(windowClusters, persistedClusters) {
  const win = (Array.isArray(windowClusters) ? windowClusters : []).filter((c) => c && typeof c === 'object');
  const persisted = (Array.isArray(persistedClusters) ? persistedClusters : []).filter((c) => c && typeof c === 'object');
  const merged = win.slice();
  const indexById = new Map();
  for (let i = 0; i < merged.length; i++) {
    const id = String(merged[i]?.id ?? '');
    if (id && !indexById.has(id)) indexById.set(id, i);
  }
  for (const p of persisted) {
    const pid = String(p?.id ?? '');
    const idx = pid ? indexById.get(pid) : undefined;
    if (idx === undefined) {
      merged.push(p);
      continue;
    }
    merged[idx] = unionClusterWith(merged[idx], p);
  }
  const sevRankOf = (c) => {
    let s = 0;
    const own = c?.severityByAddress;
    if (own && typeof own === 'object') {
      for (const v of Object.values(own)) {
        const r = SEV_RANK[v] ?? 0;
        if (r > s) s = r;
      }
    }
    return s;
  };
  const lastSeenMs = (c) => {
    const ms = Date.parse(String(c?.lastSeen ?? ''));
    return Number.isFinite(ms) ? ms : 0;
  };
  merged.sort((a, b) =>
    sevRankOf(b) - sevRankOf(a) ||
    lastSeenMs(b) - lastSeenMs(a) ||
    (Number(b?.totalDrops) || 0) - (Number(a?.totalDrops) || 0) ||
    (String(a?.id ?? '') < String(b?.id ?? '') ? -1 : String(a?.id ?? '') > String(b?.id ?? '') ? 1 : 0)
  );
  return merged;
}
