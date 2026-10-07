// public/graph-budget.test.mjs — Regressionen des dreiphasigen Knoten-Deckels
// und der Zeitfenster-Filter (Kritik-Runde 3 2026-10-07, Archiv-Graph-Parität).
// Deckt die vom Kritiker gemessene Degeneration nach: 4583 Knoten / 975 Kanten,
// fast alle severity 'malicious', Rollen überwiegend 'unknown' — der alte
// reine Schwere/Drops-Sort ließ 1/975 Kanten und 596/600 'unknown'-Knoten.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import {
  FEED_RANGES, FEED_RANGE_MS, BLOCK_WINDOW_MAX_RANGE,
  selectCappedNodes, edgesInWindow, oldestEdgeMs, cmpEdgeTotal,
  EVIDENCE_FLOOR_MAX,
} from './graph-budget.mjs';
import { serverClustersFromView, unionClusterWith } from './cluster-views.mjs';
import { DICT } from './i18n.mjs';

const here = path.dirname(fileURLToPath(import.meta.url));
const read = (rel) => readFileSync(path.join(here, rel), 'utf8');

/* ---------- Fixtures (Form nach der Live-Diagnose 2026-10-07) ---------- */
const iso = (msAgo) => new Date(Date.now() - msAgo).toISOString();

// 4583 Knoten: 600× severity malicious, Rollen fast alle 'unknown'
// (1 drainer, 1 collector, 2 source), keine Drops — exakt die degenerierte
// Archiv-Form, in der der alte Sort zum lexikografischen Ausschnitt wurde.
function archiveFixture() {
  const nodes = [];
  const edges = [];
  for (let i = 0; i < 4583; i++) {
    const id = 'rAddr' + String(i).padStart(5, '0');
    let role = 'unknown';
    if (i === 100) role = 'drainer';
    if (i === 101) role = 'collector';
    if (i === 102 || i === 103) role = 'source';
    nodes.push({ id, role, severity: 'malicious', clusterId: 'cluster:x' });
  }
  // 975 Kanten: 900 unter volumen-starken Endpunkten (rTop*), 75 an
  // volumen-schwachen Endpunkten (rLow*), 50 isolierte Fund-Knoten ohne Kante.
  for (let i = 0; i < 900; i++) {
    edges.push({
      from: 'rTop' + String(i % 40).padStart(3, '0'),
      to: 'rTop' + String((i + 7) % 40).padStart(3, '0'),
      type: 'Payment', amountDrops: 1_000_000 - i, txHash: 'H' + String(i).padStart(4, '0'),
      ledgerSeq: 1000 + i, closeTime: iso(3600_000 * i),
    });
  }
  for (let i = 0; i < 75; i++) {
    edges.push({
      from: 'rLow' + String(i % 10).padStart(2, '0'),
      to: 'rLow' + String((i + 3) % 10).padStart(2, '0'),
      type: 'NFTokenMint', amountDrops: 10 + i, txHash: 'L' + String(i).padStart(3, '0'),
      ledgerSeq: 5000 + i, closeTime: iso(3600_000 * (900 + i)),
    });
  }
  // Isolierte Fund-Knoten (malicious, ohne jede Kante): dürfen nicht dem
  // Auffüll-Lexikograf zum Opfer fallen, bevor die Evidenz-Rollen gehalten sind.
  for (let i = 0; i < 50; i++) {
    nodes.push({ id: 'rIso' + String(i).padStart(3, '0'), role: 'unknown', severity: 'malicious', clusterId: 'cluster:x' });
  }
  // Die Topologie-Knoten der Kanten müssen existieren (wie nach dem
  // applyFlowStateView-Endpunkt-Zusatz).
  const ids = new Set(nodes.map((n) => n.id));
  for (const e of edges) {
    for (const a of [e.from, e.to]) {
      if (!ids.has(a)) { ids.add(a); nodes.push({ id: a, role: 'unknown', severity: 'malicious', clusterId: 'cluster:x' }); }
    }
  }
  return { nodes, edges };
}

test('selectCappedNodes: Archiv-Form — Evidenz-Rollen gehalten, Kanten überleben, deterministisch', () => {
  const { nodes, edges } = archiveFixture();
  const kept = selectCappedNodes(nodes, edges, 600);
  assert.equal(kept.length, 600, 'Budget exakt ausgeschöpft');
  const keptIds = new Set(kept.map((n) => n.id));
  // (a) Alle Evidenz-Rollen-Knoten (drainer/collector/source) sind vorhanden.
  for (const id of ['rAddr00100', 'rAddr00101', 'rAddr00102', 'rAddr00103']) {
    assert.ok(keptIds.has(id), `Evidenz-Knoten fehlt: ${id}`);
  }
  // (b) Endpunkte der volumen-stärksten Kanten sind vorhanden — und damit
  //     überleben Kanten (alter Stand: 1/975).
  const survived = edges.filter((e) => keptIds.has(e.from) && keptIds.has(e.to));
  assert.ok(survived.length >= 900, `zu wenige Kanten überlebt: ${survived.length}`);
  for (let i = 0; i < 40; i++) {
    assert.ok(keptIds.has('rTop' + String(i).padStart(3, '0')), `Top-Kanten-Endpunkt fehlt: rTop${i}`);
  }
  // (c) Bijektiv deterministisch: zweimal gleicher Input -> gleicher Output.
  const again = selectCappedNodes(nodes, edges, 600);
  assert.deepEqual(again.map((n) => n.id), kept.map((n) => n.id));
  // Eingabe-Shuffle: dieselbe Auswahlmenge (Totalordnung, nicht Reihenfolge).
  const shuffled = [...nodes].reverse();
  const shuffledEdges = [...edges].reverse();
  const keptShuffled = new Set(selectCappedNodes(shuffled, shuffledEdges, 600).map((n) => n.id));
  assert.deepEqual([...keptIds].sort(), [...keptShuffled].sort());
});

test('selectCappedNodes: Phase-A-Deckel 120 — Rang severity desc → roleRank desc → id asc', () => {
  const nodes = [];
  // 200 malicious-Knoten (alle Rolle unknown) + 10 drainer + 10 collector.
  for (let i = 0; i < 200; i++) nodes.push({ id: 'rM' + String(i).padStart(3, '0'), role: 'unknown', severity: 'malicious' });
  for (let i = 0; i < 10; i++) nodes.push({ id: 'rD' + String(i).padStart(2, '0'), role: 'drainer', severity: 'suspect' });
  for (let i = 0; i < 10; i++) nodes.push({ id: 'rC' + String(i).padStart(2, '0'), role: 'collector', severity: 'suspect' });
  const kept = selectCappedNodes(nodes, [], 150);
  const keptIds = new Set(kept.map((n) => n.id));
  assert.equal(kept.length, 150);
  // Phase A hält max 120: malicious zuerst (severity-Rang), dann roleRank.
  assert.equal(EVIDENCE_FLOOR_MAX, 120);
  for (let i = 0; i < 120; i++) assert.ok(keptIds.has('rM' + String(i).padStart(3, '0')), `Phase-A-Slot fehlt: rM${i}`);
  // Die 30 restlichen Slots füllt Phase C (keine Kanten) nach Schwere/Drops/id:
  // die nächsten malicious-Knoten vor den suspect-Rollen-Knoten.
  for (let i = 120; i < 150; i++) assert.ok(keptIds.has('rM' + String(i).padStart(3, '0')), `Phase-C-Füllung fehlt: rM${i}`);
  assert.ok(!keptIds.has('rM150'), 'Budget hart bei 150');
  for (let i = 0; i < 10; i++) assert.ok(!keptIds.has('rD' + String(i).padStart(2, '0')), 'suspect-Knoten verdrängt malicious');
});

test('selectCappedNodes: Phase B folgt der topKEdges-Totalordnung (Volumen desc, Seq asc)', () => {
  const nodes = [];
  for (let i = 0; i < 60; i++) nodes.push({ id: 'rN' + String(i).padStart(2, '0'), role: 'unknown', severity: 'info' });
  const edges = [
    { from: 'rN00', to: 'rN01', amountDrops: 5, ledgerSeq: 10, txHash: 'a' },
    { from: 'rN02', to: 'rN03', amountDrops: 500, ledgerSeq: 20, txHash: 'b' },
    { from: 'rN04', to: 'rN05', amountDrops: 500, ledgerSeq: 15, txHash: 'c' }, // gleiches Volumen, frühere Seq
  ];
  const kept = new Set(selectCappedNodes(nodes, edges, 4).map((n) => n.id));
  // Budget 4: die beiden volumen-stärksten Kanten (500) zuerst, in Seq-Ordnung.
  assert.deepEqual([...kept].sort(), ['rN02', 'rN03', 'rN04', 'rN05']);
  assert.ok(!kept.has('rN00'), 'niedrige Volumen-Kante drängt Top-Kante');
  // cmpEdgeTotal ist dieselbe Ordnung wie viewEdges/topKEdges.
  assert.ok(cmpEdgeTotal(edges[2], edges[1]) < 0, 'ledgerSeq asc bei gleichem Volumen');
  assert.ok(cmpEdgeTotal(edges[1], edges[0]) < 0, 'amountDrops desc');
});

test('selectCappedNodes: ohne Überschreitung bitgleich unverändert (Live-Pfad-Schutz)', () => {
  const nodes = [{ id: 'a' }, { id: 'b' }];
  assert.equal(selectCappedNodes(nodes, [], 600), nodes, 'unter Budget: identisches Array');
  assert.equal(selectCappedNodes(nodes, [], null), nodes, 'maxNodes null: uncapped wie bisher');
});

test('edgesInWindow/oldestEdgeMs: Fensterfilter hält Undatierte, verwirft ältere; oldest ehrlich', () => {
  const now = Date.now();
  const edges = [
    { from: 'a', to: 'b', closeTime: new Date(now - 12 * 3600_000).toISOString() }, // in 24 h
    { from: 'b', to: 'c', closeTime: new Date(now - 40 * 3600_000).toISOString() }, // außerhalb 24 h
    { from: 'c', to: 'd' }, // undatiert: bleibt (kein Zeitanspruch)
    { from: 'd', to: 'e', closeTime: 'not-a-date' }, // unparsebar: bleibt
  ];
  const kept = edgesInWindow(edges, FEED_RANGE_MS['24h'], now);
  assert.deepEqual(kept.map((e) => `${e.from}>${e.to}`), ['a>b', 'c>d', 'd>e']);
  assert.equal(oldestEdgeMs(edges), now - 40 * 3600_000);
  assert.equal(oldestEdgeMs([{ from: 'x', to: 'y' }]), null, 'ohne Zeitstempel: null, keine Behauptung');
  // Fünf Fenster mit harten ms-Werten (24h/3d/7d/30d/90d).
  assert.deepEqual(FEED_RANGES, ['24h', '3d', '7d', '30d', '90d']);
  assert.equal(FEED_RANGE_MS['90d'], 90 * 24 * 3600_000);
  assert.equal(BLOCK_WINDOW_MAX_RANGE, '7d', 'Block-Fenster-Retention endet bei 7 d');
});

/* ---------- Verdrahtung in app.js / index.html (Muster tx-colors.test) ---------- */

test('app.js: Deckel ruft selectCappedNodes, Archiv-Knoten tragen Drops + Kanten-Endpunkte, Fensterfilter an der Bühne', () => {
  const appJs = read('app.js');
  assert.match(appJs, /from '\.\/graph-budget\.mjs'/, 'Modul-Import');
  assert.match(appJs, /rawNodes = selectCappedNodes\(rawNodes, rawEdgesAll, maxNodes\)/, 'Dreiphasen-Budget im Deckel');
  assert.match(appJs, /updateRawGraph\(stageGraph\(cg\), LIVE_GRAPH_MAX_NODES\)/, 'renderLiveGraph: Fensterfilter vor dem Deckel');
  assert.match(appJs, /updateRawGraph\(stageGraph\(lastClusterGraph\), LIVE_GRAPH_MAX_NODES\)/, 'setGraphTab live: Fensterfilter');
  assert.match(appJs, /inDrops: inDrops\.get\(String\(addr\)\) \?\? 0/, 'applyFlowStateView: Knoten-Volumen aus Cluster-Kanten');
  assert.match(appJs, /role: 'unknown', clusterId: c\.id, severity: sevByAddr\[addr\] \?\? 'info'/, 'Kanten-Endpunkte ohne Rolle werden Knoten');
  assert.match(appJs, /closeTime: e\.closeTime/, 'closeTime durchgereicht (Fensterfilter)');
  assert.match(appJs, /amountDrops: Number\(e\.amountDrops\)/, 'amountDrops durchgereicht (Kanten-Totalordnung)');
  // Fenster-Validierung folgt FEED_RANGES (fünf Werte), nicht mehr hart 3.
  assert.match(appJs, /feedRange = FEED_RANGES\.includes\(v\)/, 'bindFeed akzeptiert 24h/3d/7d/30d/90d');
  // 30d/90d werden NICHT gegen das Block-Fenster geantwortet (Retention 7 d).
  assert.match(appJs, /if \(!FEED_RANGES\.slice\(0, 3\)\.includes\(feedRange\)\) \{\s*\n\s*windowData = null;/, 'pollBlockWindow guardiert 30d/90d');
  // truncated-Kennzeichnungen: Feed-Notiz + Bühnen-Notiz + Archiv-Notiz.
  assert.match(appJs, /t\('feed\.windowBeyondBlockRetention'\)/, 'Feed-Notiz über die Block-Retention');
  assert.match(appJs, /t\('graph\.windowTruncated'/, 'Bühnen-Notiz mit {range}/{depth}');
  assert.match(appJs, /t\('graph\.noteArchive'\)/, 'Archiv-Notiz mit den ehrlichen Fenstern');
  // Karten-Kennzeichnung der Feldkappe (distinctAccounts = je gesehen).
  assert.match(appJs, /c\.fieldsCapped === true/, 'Kap-Chip nur bei belegter Kappung');
  assert.match(appJs, /t\('cluster\.membersCapped', \{ n: fmtNum\(c\.distinctAccounts \?\? 0\) \}\)/, 'Kap-Fußnote nennt den je-gesehenen Bestand');
});

test('index.html: fünf Fenster-Optionen, Fenster-/Archiv-Notiz-Elemente, Panel unter hx-stage', () => {
  const html = read('index.html');
  for (const v of ['24h', '3d', '7d', '30d', '90d']) {
    assert.ok(html.includes(`<option value="${v}" data-i18n="range.${v}">`), `Option ${v} fehlt`);
  }
  assert.match(html, /id="graph-window-note"[^>]*role="status"/, 'Fenster-Notiz-Element');
  assert.match(html, /id="graph-archive-note"/, 'Archiv-Notiz-Element');
  // Panel direkt unter der hx-stage-Bühne, vor console-grid und view-history.
  assert.ok(html.indexOf('id="exchange-outflows-panel"') > html.indexOf('class="hx-stage"'), 'Panel nach hx-stage');
  assert.ok(html.indexOf('id="exchange-outflows-panel"') < html.indexOf('console-grid'), 'Panel vor console-grid');
  assert.ok(html.indexOf('id="exchange-outflows-panel"') < html.indexOf('id="view-history"'), 'Panel vor view-history');
});

test('i18n: neue Keys in EN und DE, Platzhalter-Parität, deutsche Orthografie intakt', () => {
  const ph = (s) => (String(s).match(/\{[A-Za-z0-9_]+\}/g) ?? []).sort().join(',');
  const keys = ['range.30d', 'range.90d', 'feed.windowBeyondBlockRetention', 'graph.windowTruncated', 'graph.noteArchive', 'cluster.membersCapped', 'mode.archiveHint', 'mode.archiveAria'];
  for (const k of keys) {
    assert.equal(typeof DICT.en[k], 'string', `EN-Wert fehlt: ${k}`);
    assert.equal(typeof DICT.de[k], 'string', `DE-Wert fehlt: ${k}`);
    assert.ok(DICT.en[k].length > 0 && DICT.de[k].length > 0, `leerer Wert: ${k}`);
    assert.equal(ph(DICT.en[k]), ph(DICT.de[k]), `Platzhalter-Abweichung bei ${k}`);
    assert.ok(!/Ã/.test(DICT.de[k]) && !/Ã/.test(DICT.en[k]), `${k}: Mojibake`);
    assert.ok(!/\b(ae|oe|ue)\b/.test(DICT.de[k]), `${k}: ASCII-Umlaut-Ersatz`);
  }
  // Ehrliche Fensterwahrheit in den Texten (Retention-Wahrheit des Plans).
  assert.ok(DICT.de['feed.windowBeyondBlockRetention'].includes('Block-Fenster'), 'DE nennt das Block-Fenster');
  assert.ok(DICT.en['feed.windowBeyondBlockRetention'].includes('block window'), 'EN nennt das block window');
  assert.ok(DICT.de['graph.noteArchive'].includes('maliziös'), 'DE Archiv-Notiz nennt maliziös');
  assert.ok(DICT.de['graph.noteArchive'].includes('registry-verknüpft'), 'DE Archiv-Notiz nennt registry-verknüpft');
  assert.ok(DICT.de['cluster.membersCapped'].includes('je gesehen'), 'DE Kap-Fußnote: je gesehen');
  assert.ok(/[äöüß]/.test(DICT.de['mode.archiveHint']), 'DE Archiv-Hinweis mit Umlaut');
  // legend.unknown DE ist deutsch.
  assert.equal(DICT.de['legend.unknown'], 'Unbekannt');
  assert.equal(DICT.en['legend.unknown'], 'Unknown');
});

test('cluster-views: fieldsCapped überlebt View-Mapping und Union (Karten-Kennzeichnung)', () => {
  const view = {
    clusters: [{
      id: 'cluster:a', label: 'A', rolesByAddress: { ra: 'drainer' }, severityByAddress: { ra: 'malicious' },
      edges: [], totalDrops: 10, txCount: 2, distinctAccounts: 400, fieldsCapped: true,
    }],
  };
  const [c] = serverClustersFromView(view);
  assert.equal(c.fieldsCapped, true, 'View-Signal übernommen');
  const merged = unionClusterWith({ id: 'cluster:a', memberAddresses: ['rz'], distinctAccounts: 10 }, c);
  assert.equal(merged.fieldsCapped, true, 'persistierte Kappung überlebt die Union');
  const uncapped = serverClustersFromView({ clusters: [{ id: 'x', rolesByAddress: { ra: 'relay' } }] });
  assert.equal(uncapped[0].fieldsCapped, undefined, 'ohne Signal: feldlos (keine erfundene Kennzeichnung)');
});
