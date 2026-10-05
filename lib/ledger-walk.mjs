// Cursor-Advance-Kern für den History-Host: transport-agnostisch, rein logisch.
// advance() rückt einen persistierten Ledger-Cursor um ein begrenztes Budget vor,
// berechnet pro Block den Geldfluss über die BESTEHENDEN Cluster-Module und
// akkumuliert den Cross-Block-Flow-State — inklusive BEGRENZTER Fluss-Kanten
// pro Cluster (Top-K nach akkumuliertem Volumen, dedupliziert nach
// Kanten-Identität). Findings sind PRO BLOCK Teil des Fetcher-Vertrags
// ({transactions, findings}), nicht tick-global. Kein Netzwerk, kein
// Dateizugriff hier — der Fetcher wird injiziert (Tests nutzen In-Memory-
// Fixtures).
//
// FETCHER-VERTRAG (honeycluster-Umstellung 2026-10-02, live geprobt):
//   - null NUR am Live-Edge (lgrNotFound) oder bei Netzwerk-/RPC-Fehler —
//     ein truthy Block mit transactions:[] ist ein GÜLTIGER LEERBLOCK und
//     lässt den Walk VORRÜCKEN (Blockage-Fix: früher stoppte ein 0-Tx-Block
//     den Walk dauerhaft, api/advance.js a.D. `if (hashes.length===0)
//     return null`). mergeBlock bleibt bei leerem Block korrekt leer.
//   - Stempeln (ledger_index/close_time_iso auf expand:true-Entries) ist
//     Sache des Fetchers (Adapter in api/advance.js), nicht dieses Kerns —
//     mergeBlock ruft txRecordFromEntry(entry, null); ohne gestempelte
//     Entries degradieren ledgerSeq (edgeIdentity/Top-K) und closeTime
//     (firstSeen/lastSeen).

import { txRecordFromEntry, buildClusterGraph, detectPeelingChains } from "./cluster.mjs";
import { normalizeTag, computeTransitFlags } from "./tag-identity.mjs";

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
 * @param {object} [p.opts]        { maxClusterEdges = 50, parallel = 1,
 *        entityLinks = null } —
 *        maxClusterEdges: Begrenzung der pro-Cluster-Fluss-Kanten im
 *        akkumulierten State; parallel: Anzahl Blöcke, die pro Runde
 *        GLEICHZEITIG geholt werden (1 = sequenziell wie bisher; der
 *        Advance-Endpunkt nutzt 4 gegen die honeycluster-Latenz ~0,7 s);
 *        entityLinks: INJIZIERBARE Map Adresse -> Join-Keys (string[]) für
 *        die Entity-Union zweier Cluster ohne gemeinsames Mitglied —
 *        Default null (Transport-Agnostik: kein Dateizugriff, kein Import
 *        von lib/entity-resolve.mjs, Header :7-9 bleibt gewahrt);
 *        multiUserAccounts: INJIZIERBARE Map Adresse -> {exchange,...} aus
 *        der Exchange-Registry für die Tag-Kantenattribute toTag/transit
 *        (lib/tag-identity.mjs) — Default null (kein Tag-Feld, Verhalten
 *        bitgleich; ebenfalls rein injizierbar, kein Dateizugriff)
 * @returns {Promise<{newCursor:number, summary:string, flowState:object}>}
 */
export async function advance({ cursor, budget, now, fetcher, flowState, opts = {} }) {
  const start = Number(cursor) || 0;
  const maxBlocks = Math.max(0, Math.floor(Number(budget) || 0));
  const maxClusterEdges = maxClusterEdgesOf(opts);
  const parallel = Math.max(1, Math.floor(Number(opts.parallel) || 1));
  // Entity-Union ausschließlich als injizierbare Map (Default null):
  // Adresse -> Join-Keys. Kein Dateizugriff, kein Import — der Kern bleibt
  // transport-agnostisch (Header :7-9).
  const entityLinks = opts.entityLinks instanceof Map ? opts.entityLinks : null;
  // Exchange-Registry ebenfalls nur als injizierbare Map (Default null):
  // Adressen -> Börsen-Konten für toTag/transit (lib/tag-identity.mjs).
  const multiUserAccounts = opts.multiUserAccounts instanceof Map ? opts.multiUserAccounts : null;
  const state = normalizeState(flowState, maxClusterEdges);

  let processed = 0;
  let lastIndex = start;

  // Rundenweise: bis zu `parallel` Indizes gleichzeitig holen, Merge strikt
  // aufsteigend nach Index (deterministisch, unabhängig von der
  // Antwortreihenfolge). Ein null in der Runde beendet den Walk an der
  // Lücke — die nachfolgenden Indizes der Runde werden NICHT gemergt.
  for (let base = 1; base <= maxBlocks; base += parallel) {
    const chunk = [];
    for (let i = base; i < base + parallel && i <= maxBlocks; i++) chunk.push(start + i);
    const results = await Promise.all(
      chunk.map(async (index) => {
        let block = null;
        try {
          block = await fetcher(index);
        } catch {
          block = null; // Netzwerk-/RPC-Fehler am Edge: als Ende behandeln
        }
        return { index, block };
      })
    );
    let stopped = false;
    for (const { index, block } of results) {
      if (!block) {
        stopped = true; // Live-Edge erreicht (lgrNotFound) oder Fetch-Fehler
        break;
      }
      mergeBlock(state, index, block, maxClusterEdges, block?.closeIso ?? null, entityLinks, multiUserAccounts);
      lastIndex = index;
      processed++;
    }
    if (stopped) break;
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
function mergeBlock(state, index, block, maxClusterEdges, closeIso, entityLinks, multiUserAccounts) {
  const entries = Array.isArray(block?.transactions) ? block.transactions : [];
  const findings = Array.isArray(block?.findings) ? block.findings : [];
  const txRecords = [];
  for (const entry of entries) {
    try {
      // Block-closeTime als Stempel-Fallback: ohne Stempel sind
      // firstSeen/lastSeen null und der Cluster überlebt 7-Tage-Pruning
      // zeitlos (Audit-Befund Z.132).
      txRecords.push(txRecordFromEntry(entry, closeIso ?? block?.closeIso ?? null));
    } catch {
      // Einzelne kaputte Entry überspringen, nicht den ganzen Block.
    }
  }
  if (txRecords.length === 0) return;

  let graph;
  try {
    graph = buildClusterGraph(txRecords, findings, multiUserAccounts ? { multiUserAccounts } : {});
  } catch {
    return;
  }
  if (!graph) return;

  // Peeling-Ketten über die BLOCK-txRecords plus Fund-Adressen aus
  // block.findings (detectPeelingChains läuft bewusst über txRecords, nicht
  // über die Cluster-Kanten — die Kantenregel liefert die Mittelkante nie).
  let chains = [];
  try {
    chains = detectPeelingChains(txRecords, findings, {});
  } catch {
    chains = [];
  }

  const clusters = Array.isArray(graph.clusters) ? graph.clusters : [];
  const edges = Array.isArray(graph.edges) ? graph.edges : [];
  // Registry-Verknüpfung (Produzent des entitySnapshot-Felds, Grenze 4):
  // ruleId 'known-bad-hit' ist per Konstruktion registry-abgeleitet
  // (api/advance.js buildCtx: knownBad aus getPublicThreats, :384-387). Ein
  // Cluster mit mindestens einem solchen Mitglied ist registry-verknüpft und
  // trägt entitySnapshot { registryLinked: true } — die einzige Quelle dieses
  // Felds im Produktionspfad; lib/flow-state.mjs isRegistryLinked (180-Tage-
  // Archiv-Retention) liest genau dieses Feld.
  const registryLinkedMembers = new Set();
  for (const f of findings) {
    if (f?.ruleId === "known-bad-hit" && typeof f.address === "string") {
      registryLinkedMembers.add(f.address);
    }
  }
  // Kettenzuordnung (deterministisch): eine Kette gehört zum Cluster, der als
  // Erster einen ihrer GEFLAGGTEN Endpunkte enthält — Seed zuerst, dann die
  // übrigen Fund-Endpunkte asc. Im Split-Fall (Seed und Endpunkt in
  // verschiedenen Clustern, Grenze 1) entscheidet der Seed; die Kette wird
  // nie dupliziert.
  const memberToKey = new Map();
  for (const c of clusters) {
    for (const m of Array.isArray(c?.memberAddresses) ? c.memberAddresses : []) {
      if (typeof m === "string" && !memberToKey.has(m)) memberToKey.set(m, c.id);
    }
  }
  const chainOwnerKey = new Map(); // signature -> Cluster-Key
  for (const ch of chains) {
    const bridgeSet = new Set(ch.bridges);
    const flagged = ch.addresses.filter((a) => !bridgeSet.has(a));
    for (const a of flagged) {
      const k = memberToKey.get(a);
      if (k) {
        chainOwnerKey.set(ch.signature, k);
        break;
      }
    }
  }
  for (const c of clusters) {
    const key = typeof c?.id === "string" && c.id ? c.id : null;
    if (!key) continue;
    const members = new Set(Array.isArray(c.memberAddresses) ? c.memberAddresses : []);
    const clusterEdges = edges.filter((e) => members.has(e?.from) && members.has(e?.to));
    // Member-Überschneidungs-Merge: derselbe reale Cluster, der in diesem
    // Block einen anderen Key trägt (weil ein früheres Mitglied fehlt), wird
    // in den bestehenden State-Eintrag vereinigt statt als Zweit-Eintrag mit
    // doppelter txCount/volumen geführt (Audit-Probe: 2 Cluster-IDs für
    // 3 reale Txs). Der bestehende Key wird nie umbenannt.
    let targetKey = key;
    if (!state.clusters[key]) {
      for (const [existingKey, existing] of Object.entries(state.clusters)) {
        const existingMembers = Array.isArray(existing?.memberAddresses) ? existing.memberAddresses : [];
        if (existingMembers.some((m) => members.has(m))) {
          targetKey = existingKey;
          break;
        }
      }
    }
    // Entity-Union (injizierbare opts.entityLinks, Default null): zwei
    // Cluster ohne gemeinsames Mitglied werden vereinigt, wenn sie einen
    // Join-Key teilen — zusätzlich zur Member-Überschneidung. Join-Key-Hub-
    // Schutz: ein Key, den mehr als 20 Adressen tragen (Analogie
    // HUB_UNION_DEGREE, cluster.mjs:332), vereinigt nicht.
    if (entityLinks && entityLinks.size > 0) {
      const unionKey = entityUnionKey(state, members, entityLinks);
      if (unionKey) targetKey = unionKey;
    }
    const clusterChains = chains.filter((ch) => chainOwnerKey.get(ch.signature) === key);
    const registryLinked = [...members].some((m) => registryLinkedMembers.has(m));
    state.clusters[targetKey] = mergeCluster(
      state.clusters[targetKey], c, clusterEdges, maxClusterEdges, clusterChains, registryLinked, multiUserAccounts
    );
  }
}

// Entity-Union-Kandidat: der bestehende State-Key, der mit dem Block-Cluster
// einen JOIN-KEY teilt (deterministisch: State-Keys asc). Join-Key-Filter
// (Kritik 7): nur starke Keys vereinigen — 'rk:' (RegularKey), 'sg:'
// (Signer-Fingerprint), 'eh:' (EmailHash), 'sp:' (Funding-Muster: gemeinsame
// Sponsor-Adresse = gemeinsame Funding-Quelle, lib/entity-resolve.mjs) und
// 'dv:' (Domain NACH Zwei-Wege-toml-Verifikation). Eine Domäne ohne dv:-Flag
// ist reines Anzeige-Metadatum und nie Join-Key. Hub-Ausschluss: ein Join-Key,
// den mehr als 20 Adressen tragen (Analogie HUB_UNION_DEGREE 20,
// cluster.mjs:332), vereinigt nicht — er trifft auch das Funding-Muster
// (Faucet-Sponsoring > 20 vereinigt nie).
const ENTITY_UNION_HUB = 20;
const ENTITY_JOIN_KEY_RE = /^(rk:|sg:|eh:|sp:|dv:)\S+$/;
function entityUnionKey(state, members, entityLinks) {
  // Key-Besitzer über die gesamte Links-Tabelle (Adressen, die den Key
  // tragen) — Hub-Messung unabhängig davon, ob die Adresse gerade Mitglied ist.
  const keyOwners = new Map(); // joinKey -> Anzahl Adressen
  for (const [addr, keys] of entityLinks) {
    if (typeof addr !== "string" || !Array.isArray(keys)) continue;
    const valid = new Set(keys.filter((k) => typeof k === "string" && ENTITY_JOIN_KEY_RE.test(k)));
    for (const k of valid) keyOwners.set(k, (keyOwners.get(k) ?? 0) + 1);
  }
  const keysOf = (addr) => {
    const keys = entityLinks.get(addr);
    if (!Array.isArray(keys)) return [];
    return keys.filter((k) => typeof k === "string" && ENTITY_JOIN_KEY_RE.test(k));
  };
  const stateKeys = Object.keys(state.clusters).sort((x, y) => (x < y ? -1 : x > y ? 1 : 0));
  for (const existingKey of stateKeys) {
    const existingMembers = Array.isArray(state.clusters[existingKey]?.memberAddresses)
      ? state.clusters[existingKey].memberAddresses
      : [];
    if (existingMembers.some((m) => members.has(m))) continue; // Member-Union greift schon
    for (const m of existingMembers) {
      for (const k of keysOf(m)) {
        if ((keyOwners.get(k) ?? 0) > ENTITY_UNION_HUB) continue; // Hub-Ausschluss
        return existingKey;
      }
    }
  }
  return null;
}

// Merge eines Clusters in den akkumulierten State: Dedup nach Cluster-Key,
// Summen akkumulieren, first/lastSeen chronologisch (Epoch-Vergleich, nie
// lexikalisch — Konvention wie cluster.mjs), strukturelle Felder als UNION:
// memberAddresses = Vereinigung (eine Adresse verschwindet nicht dauerhaft,
// Audit-Probe: C fehlt nach Block2), roles pro Adresse beibehalten (neueste
// Sicht nur bei gleicher/höherer Beweislage — Betrugslables verfallen nicht
// durch eine harmlosere Einzelsicht), mainDrainers/collectors als Union mit
// Dedup nach Adresse. Fluss-Kanten: dedupliziert nach Kanten-Identität (die
// chronologisch erste gemergte Sicht gewinnt) und auf Top-K nach
// akkumuliertem Volumen begrenzt — die größten Flüsse sind die
// Geldwäsche-Signale; Volumen-Gleichstände brechen chronologisch (ledgerSeq
// asc, dann txHash/Endpunkte asc).
const SEVERITY_RANK_WALK = { info: 1, suspect: 2, malicious: 3 };
const ROLE_RANK_WALK = { unknown: 0, relay: 1, source: 2, collector: 3, drainer: 4 };

function mergeCluster(acc, c, blockEdges, maxClusterEdges, chains, registryLinked, multiUserAccounts) {
  const incoming = (Array.isArray(blockEdges) ? blockEdges : []).map((e) => ({ ...e }));
  if (!acc) {
    const freshEdges = topKEdges(incoming, maxClusterEdges);
    // Transit blockübergreifend nachziehen: im Advance-Pfad läuft
    // buildClusterGraph pro BLOCK — eine Börse, die in Block 1 Tag 111 und
    // in Block 2 Tag 222 sieht, bekommt ihr transit erst über die
    // akkumulierten Cluster-Kanten. Auf dem gekappten Satz reicht das, weil
    // die Identitäten (Adresse, Tag) in jeder überlebenden Kante stecken.
    if (multiUserAccounts) computeTransitFlags(freshEdges, multiUserAccounts);
    return {
      id: c.id,
      ...(registryLinked ? { entitySnapshot: { registryLinked: true } } : {}),
      totalDrops: num(c.totalDrops),
      txCount: num(c.txCount),
      firstSeen: typeof c.firstSeen === "string" ? c.firstSeen : null,
      lastSeen: typeof c.lastSeen === "string" ? c.lastSeen : null,
      memberAddresses: [...(Array.isArray(c.memberAddresses) ? c.memberAddresses : [])],
      roles: { ...(c.roles && typeof c.roles === "object" ? c.roles : {}) },
      severityByAddress: { ...(c.severityByAddress && typeof c.severityByAddress === "object" ? c.severityByAddress : {}) },
      mainDrainers: (Array.isArray(c.mainDrainers) ? c.mainDrainers : []).map((x) => ({ ...x })),
      collectors: (Array.isArray(c.collectors) ? c.collectors : []).map((x) => ({ ...x })),
      distinctAccounts: num(c.distinctAccounts),
      edges: freshEdges,
      // Peeling-Ketten (Grenze 1): Cluster-Feld, KEINE neue Rolle — ROLE_SET
      // (cluster.mjs:56) bleibt unangetastet. Kappung analog maxClusterEdges,
      // Dedup über Adressketten-Signatur.
      peelingChains: capChains(Array.isArray(chains) ? chains : [], maxClusterEdges),
    };
  }
  acc.totalDrops += num(c.totalDrops);
  acc.txCount += num(c.txCount);
  const f = epochMs(c.firstSeen);
  if (f !== -1 && (acc.firstSeen == null || f < epochMs(acc.firstSeen))) acc.firstSeen = c.firstSeen;
  const l = epochMs(c.lastSeen);
  if (l !== -1 && (acc.lastSeen == null || l > epochMs(acc.lastSeen))) acc.lastSeen = c.lastSeen;
  // Member-Union (sortiert, deterministisch).
  const memberSet = new Set(Array.isArray(acc.memberAddresses) ? acc.memberAddresses : []);
  for (const m of Array.isArray(c.memberAddresses) ? c.memberAddresses : []) memberSet.add(m);
  acc.memberAddresses = [...memberSet].sort((x, y) => (x < y ? -1 : x > y ? 1 : 0));
  // Rollen: pro Adresse die beweisstärkere Sicht behalten.
  const roles = { ...(acc.roles && typeof acc.roles === "object" ? acc.roles : {}) };
  for (const [addr, role] of Object.entries(c.roles && typeof c.roles === "object" ? c.roles : {})) {
    const cur = roles[addr];
    if (cur == null || (ROLE_RANK_WALK[role] ?? 0) >= (ROLE_RANK_WALK[cur] ?? 0)) roles[addr] = role;
  }
  acc.roles = roles;
  // Severity pro Adresse: max.
  const sev = { ...(acc.severityByAddress && typeof acc.severityByAddress === "object" ? acc.severityByAddress : {}) };
  for (const [addr, s] of Object.entries(c.severityByAddress && typeof c.severityByAddress === "object" ? c.severityByAddress : {})) {
    if (!sev[addr] || (SEVERITY_RANK_WALK[s] ?? 0) > (SEVERITY_RANK_WALK[sev[addr]] ?? 0)) sev[addr] = s;
  }
  acc.severityByAddress = sev;
  // mainDrainers/collectors: Union mit Dedup nach Adresse (höherer Wert gewinnt).
  acc.mainDrainers = dedupByAddress(acc.mainDrainers, c.mainDrainers, "outDrops");
  acc.collectors = dedupByAddress(acc.collectors, c.collectors, "inDrops");
  acc.distinctAccounts = acc.memberAddresses.length;
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
  // Transit auf dem akkumulierten Satz neu bestimmen (blockübergreifend):
  // identisch zur Erst-Cluster-Logik oben — die Identitäten (Adresse, Tag)
  // stecken in jeder überlebenden Kante, das Flag sitzt auf den Objekten.
  if (multiUserAccounts) computeTransitFlags(acc.edges, multiUserAccounts);
  // Peeling-Ketten: Signatur-Union (deterministisch nach Signatur asc,
  // Dedup über Adressketten-Signatur, Kappung analog maxClusterEdges).
  acc.peelingChains = capChains(
    [...(Array.isArray(acc.peelingChains) ? acc.peelingChains : []), ...(Array.isArray(chains) ? chains : [])],
    maxClusterEdges
  );
  // entitySnapshot: einmal registry-verknüpft, immer registry-verknüpft
  // (Union-Semantik — ein known-bad-hit-Beweis verfällt nicht durch später
  // harmlosere Blöcke, analog zu roles/severityByAddress oben).
  if (registryLinked && !(acc.entitySnapshot && typeof acc.entitySnapshot === "object")) {
    acc.entitySnapshot = { registryLinked: true };
  }
  return acc;
}

// Kappung + Dedup der Peeling-Ketten: Signatur asc sortiert, Dedup über
// Signatur, Kappe analog maxClusterEdges (Default 50, :279). Deterministisch
// bei jeder Einfüge-/Blockreihenfolge.
function capChains(chains, maxClusterEdges) {
  const k = Math.max(0, Math.floor(maxClusterEdges));
  const bySig = new Map();
  for (const ch of chains) {
    if (!ch || typeof ch.signature !== "string" || !ch.signature) continue;
    if (!bySig.has(ch.signature)) bySig.set(ch.signature, ch);
  }
  return [...bySig.values()]
    .sort((x, y) => cmpStr(x.signature, y.signature))
    .slice(0, k);
}

function dedupByAddress(accList, incomingList, valueField) {
  const byAddr = new Map();
  for (const x of Array.isArray(accList) ? accList : []) {
    if (x && typeof x.address === "string") byAddr.set(x.address, { ...x });
  }
  for (const x of Array.isArray(incomingList) ? incomingList : []) {
    if (!x || typeof x.address !== "string") continue;
    const cur = byAddr.get(x.address);
    if (!cur || num(x[valueField]) >= num(cur[valueField])) byAddr.set(x.address, { ...x });
  }
  return [...byAddr.values()].sort((x, y) => num(y[valueField]) - num(x[valueField]) || cmpStr(x.address, y.address));
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
  // Tag-Attribute (lib/tag-identity.mjs): toTag/fromTag werden auf den
  // UInt32-Vertrag gezwungen (Tag 0 bleibt 0), defekte Werte ('x', -1,
  // 2**32) fallen ersatzlos raus. transit nur als echtes true übernehmen.
  const toTag = normalizeTag(e.toTag);
  if (toTag != null) out.toTag = toTag;
  const fromTag = normalizeTag(e.fromTag);
  if (fromTag != null) out.fromTag = fromTag;
  if (e.transit === true) out.transit = true;
  return out;
}

// Top-K nach akkumuliertem Volumen: größte Flüsse zuerst (Geldwäsche-Signale),
// Volumen-Gleichstände brechen chronologisch (ledgerSeq asc, dann txHash asc,
// dann Endpunkte asc — Totalordnung wie cmpEdge in lib/cluster.mjs). Null
// (IOU) zählt 0. Deterministisch bei jeder Eingabereihenfolge.
// Chronologie-Anker (Audit-Befund Z.259-275): nach der Volumen-Sortierung
// wird je Knoten die chronologisch älteste Kante als Anker reserviert
// (Reserve-Quota, ledgerSeq asc) — firstSeen-Anker und Drainer-Kaskaden-
// Evidenz fallen nicht aus dem persistierten State, auch wenn sie klein sind.
const CHRONO_ANCHOR_SLOTS = 10;

function topKEdges(edges, maxClusterEdges) {
  const k = Math.max(0, Math.floor(maxClusterEdges));
  const sorted = [...edges].sort((a, b) => {
    const va = typeof a?.amountDrops === "number" && Number.isFinite(a?.amountDrops) ? a.amountDrops : 0;
    const vb = typeof b?.amountDrops === "number" && Number.isFinite(b?.amountDrops) ? b.amountDrops : 0;
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
  if (sorted.length <= k) return sorted;
  // Anker-Reservierung: je Knoten, der in MEHREREN Kanten vorkommt, die
  // älteste Kante (chronologisch), insgesamt <= CHRONO_ANCHOR_SLOTS und
  // innerhalb der K Slots; danach Top-K nach Volumen für die restlichen
  // Slots. (Knoten mit nur einer Kante verlieren ihre einzige Kante ohnehin
  // nicht, wenn sie im Volumen-Fenster liegt.)
  const degree = new Map();
  for (const e of sorted) {
    for (const node of [e?.from, e?.to]) {
      if (node == null) continue;
      degree.set(node, (degree.get(node) ?? 0) + 1);
    }
  }
  const kept = new Set();
  const oldestByNode = new Map(); // node -> älteste Kante
  for (const e of sorted) {
    for (const node of [e?.from, e?.to]) {
      if (node == null || (degree.get(node) ?? 0) < 2) continue;
      const cur = oldestByNode.get(node);
      if (!cur || edgeSeqOf(e) < edgeSeqOf(cur)) oldestByNode.set(node, e);
    }
  }
  const anchors = [...new Set(oldestByNode.values())]
    .sort((a, b) => edgeSeqOf(a) - edgeSeqOf(b) || cmpStr(String(a?.txHash ?? ""), String(b?.txHash ?? "")))
    .slice(0, Math.min(CHRONO_ANCHOR_SLOTS, k));
  for (const e of anchors) kept.add(e);
  for (const e of sorted) {
    if (kept.size >= k) break;
    kept.add(e);
  }
  // Ausgabe in derselben Totalordnung wie bisher (Volumen desc, chronologisch).
  return sorted.filter((e) => kept.has(e));
}

function edgeSeqOf(e) {
  return typeof e?.ledgerSeq === "number" ? e.ledgerSeq : -1;
}

// Lexikographischer String-Vergleich (deterministisch) — wie cmpStr in
// lib/cluster.mjs (dort nicht exportiert; der Tie-Break braucht den Vergleich).
function cmpStr(a, b) {
  return a < b ? -1 : a > b ? 1 : 0;
}
