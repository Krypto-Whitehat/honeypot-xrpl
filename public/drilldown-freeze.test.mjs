// public/drilldown-freeze.test.mjs — Contract-Tests für die Inhalts-
// Einfrierung des OFFENEN Cluster-Modals (Plan 2026-10-05).
//
// Kein echter Browser: minimaler DOM-Stub (stabile querySelector-Knoten pro
// Selector), window ohne ForceGraph3D/vis, script-Injektion mit sofortigem
// onerror -> renderGraph nimmt den ehrlichen noGraph-Pfad. Sprache über
// localStorage-Stub (i18n liest erst zur Aufrufzeit). Alle Adressen
// synthetisch (rTEST…); Base58-gültig (ohne 0/O/I/l).
//
// Geprüft: (1) Freeze-Hinweis nach dem ersten Vollrender, (2) Live-Änderungen
// erreichen das offene Modal nicht mehr (Titel/Metriken bleiben, der
// Live-Graph wird im Freeze-Tick nicht mehr gelesen), (3) ein aus dem
// Beobachtungsfenster gefallener Cluster leert das offene Modal NICHT mehr
// (Akzeptanzpunkt: STALE_SNAPSHOT_MAX_MS greift das offene Modal nicht),
// (4) nachträglich Deny-gewordene Adressen fallen aus DOM und Export,
// (5) Total-Leerung bei Köder-Treffer bleibt, (6) close() (Escape) wirft den
// Freeze raus, neues Öffnen rendert den Live-Stand, (7) Sprachwechsel malt
// die Freeze-Labels neu, (8) Name-Chips nur hinter dem Host-Gate, (9) Destination-Tag-Chips nur bei
// Registry-Treffer des Ziels (exchangeEntryOf-Host-Gate, fail-closed), Transit-Hinweis nur bei belegter
// transit-Kante, Freeze-Export trägt toTag/transit additiv, (10) 3D-Layout
// deterministisch und entstapelt (Startkoordinaten ohne Math.random,
// Skalierung von Radius/Abstoßung/Link-Distanz/Warmup nach Knotenanzahl
// N=5..300, Überlappungsfreiheit nach Collide-Warmup, build3D-Verdrahtung
// mit Fake-ForceGraph3D: warmupTicks nur bei Cluster-Wechsel, Positionen
// bei Live-Updates desselben Clusters übernommen), (11) 3D-Stil (Design
// P3 2026-10-06): Kanten-Staffelung nach Typ, Drainer-Ring-Auswahl
// (deterministisch, Deckel 12), Stil-Flags (transparenter Clear, 0.85
// Deckkraft, additiver nodeThreeObjectExtend, onNodeHover), Hover-Fokus
// mit reduced-motion-Degradation und Ring-Konstruktion aus rekonstruierten
// Bundle-Klassen — Layout-Parameter unangetastet (keine Overlap-Regression),
// (12) Stale-Overlay (Forensik 2026-10-06): node-lose Merged-Karten laden aus
// dem persistierten Bestand nach (modal.persisted-Banner, ehrliche '–'-Zellen),
// drei Freeze-Ticks bleiben byte-identisch (kein modal.gone-Flapping), der
// Fallback-Anker wird durch node-loses Öffnen nicht korrumpiert, und
// Köder-Komplett-Deny bleibt in jedem Pfad (sync-Gate, async-Gate,
// Restore-Bestand, Freeze) der legitime Total-Leerungs-Terminalzustand.

import test from "node:test";
import assert from "node:assert/strict";
import {
  initClusterDrilldown,
  cluster3dLayoutParams,
  seedCluster3dPositions,
  makeCluster3dCollideForce,
  cluster3dLinkWidth,
  selectDrainerRingNodes,
  GRAPH3D_LINK_FADED,
  GRAPH3D_LINK_OPACITY,
  GRAPH3D_RING_CAP,
  DENY_RECHECK_MAX,
} from "./drilldown.js";
import { LANG_KEY, t } from "./i18n.mjs";

/* ---------------- DOM-Stub ---------------- */

function makeEl(tag) {
  const el = {
    tag: tag || "div",
    className: "",
    hidden: false,
    textContent: "",
    innerHTML: "",
    style: {},
    dataset: {},
    offsetParent: {},
    disabled: false,
    listeners: {},
    // Hover-Cursor-Klasse (Design P3.4): classList am Element-Stub.
    classList: {
      add() {},
      remove() {},
      toggle() {},
      contains() { return false; },
    },
    _q: new Map(),
    addEventListener(type, fn) { (el.listeners[type] = el.listeners[type] || []).push(fn); },
    removeEventListener() {},
    focus() {},
    querySelector(sel) {
      if (!el._q.has(sel)) el._q.set(sel, makeEl("div"));
      return el._q.get(sel);
    },
    querySelectorAll() { return []; },
    appendChild() {},
    closest() { return null; },
    click() {},   // Download-Pfad: temporäres <a download>
    remove() {},
  };
  if (tag === "canvas") el.getContext = () => null; // WebGL-Probe schlägt auf
  return el;
}

const docListeners = {};       // type -> Handler[]
const injectedScripts = [];    // per head.appendChild injizierte <script>-Stub

let appendedOverlay = null;    // das Modal-Shell (body.appendChild)

const documentStub = {
  createElement: (tag) => makeEl(tag),
  head: {
    appendChild: (s) => {
      injectedScripts.push(s);
      // Sofortiger Injektions-Fehler -> loadForceGraph3D resolves false ->
      // renderGraph nimmt den noGraph-Pfad (kein 3D, kein vis, kein fg3d).
      if (typeof s.onerror === "function") s.onerror();
    },
  },
  body: {
    appendChild: (el) => { appendedOverlay = el; },
    classList: { add() {}, remove() {} },
  },
  addEventListener: (type, fn) => { (docListeners[type] = docListeners[type] || []).push(fn); },
  activeElement: null,
  getElementById: () => null,
  querySelector: () => null,
};

const windowStub = {
  CSS: { escape: (s) => String(s) },
  matchMedia: () => ({ matches: false }),
  // bewusst KEIN ForceGraph3D und KEIN vis -> statischer noGraph-Zustand
};

/* ---------------- Sprach-Stub ---------------- */

let lang = "de";
const storageStub = {
  getItem: (k) => (k === LANG_KEY ? lang : null),
  setItem: (k, v) => { if (k === LANG_KEY) lang = String(v); },
  removeItem: (k) => { if (k === LANG_KEY) lang = null; },
};
globalThis.document = documentStub;
globalThis.window = windowStub;
globalThis.localStorage = storageStub;

const tick = () => new Promise((r) => setTimeout(r, 0));
async function settle(n = 4) { for (let i = 0; i < n; i++) await tick(); }

/* ---------------- Host-ctx (app.js-Muster) ---------------- */

const A1 = "rTESTexchangeAccount11111111"; // 28 Zeichen
const A2 = "rTESTcheckAccount8888888888";  // 28 Zeichen
const A3 = "rTESTthirdAccount33333333333"; // 29 Zeichen
const CID = "cluster:" + A1;

const denySet = new Set();
const names = new Map([
  [A1, { name: "Test Exchange One", verified: true, domain: "testone.example" }],
  [A2, { name: "Test Exchange Two", verified: false, domain: null }],
]);

function makeGraph(label = "Test Cluster", txCount = 3) {
  return {
    clusters: [{
      id: CID, label, totalDrops: 1000, txCount, distinctAccounts: 3,
      firstSeen: "2026-10-05T10:00:00Z", lastSeen: "2026-10-05T10:05:00Z",
      memberAddresses: [A1, A2, A3],
    }],
    nodes: [
      { id: A1, clusterId: CID, role: "source", inDrops: 100, outDrops: 900, degreeIn: 1, degreeOut: 2, severity: "malicious" },
      { id: A2, clusterId: CID, role: "mid", inDrops: 500, outDrops: 400, degreeIn: 2, degreeOut: 1, severity: "suspect" },
      { id: A3, clusterId: CID, role: "sink", inDrops: 400, outDrops: 0, degreeIn: 1, degreeOut: 0, severity: "info" },
    ],
    edges: [
      { from: A1, to: A2, type: "payment", txHash: "HASH1", closeTime: 1 },
      { from: A2, to: A3, type: "payment", txHash: "HASH2", closeTime: 2 },
    ],
  };
}

let liveGraph = makeGraph();
let graphCalls = 0;

function makeCtx(overrides = {}) {
  // displayAddr maskiert wie im Host (app.js): volle Adresse nur bei
  // isFullShownAddr, sonst Kurzform — der Stub bildet das Original nach.
  const fullFn = overrides.isFullShownAddr ?? ((a) => !denySet.has(String(a)));
  const shortFn = (a) => String(a).slice(0, 6) + "…" + String(a).slice(-4);
  return {
    esc: (v) => String(v ?? "").replace(/[&<>"']/g, (c) => ({
      "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
    })[c]),
    displayAddr: (a) => (fullFn(a) ? String(a) : shortFn(a)),
    isFullShownAddr: fullFn,
    isDeniedAddr: (a) => denySet.has(String(a)),
    isDeniedAddrAsync: async (a) => denySet.has(String(a)),
    flowPaths: () => null,
    fmtXrp: (v) => String(v ?? 0),
    fmtClock: () => "12:00:00",
    roleColors: {
      source: { background: "#111", highlight: { background: "#222" } },
      mid: { background: "#333", highlight: { background: "#444" } },
      sink: { background: "#555", highlight: { background: "#666" } },
      unknown: { background: "#777", highlight: { background: "#888" } },
    },
    edgeColors: {},
    edgeDefault: "#999",
    roleLabels: { source: "source", mid: "mid", sink: "sink" },
    addrActionsHtml: () => '<span class="addr-actions">act</span>',
    accountNameOf: (a) => names.get(String(a)) ?? null,
    shortAddr: shortFn,
    getClusterGraph: () => { graphCalls += 1; return liveGraph; },
    ...overrides,
  };
}

const q = (sel) => appendedOverlay.querySelector(sel);

/* ---------------- 1) Erster Vollrender setzt den Freeze ---------------- */

test("openCluster: Vollrender, Name-Chips und ehrlicher Freeze-Hinweis", async () => {
  lang = "de";
  const dd = initClusterDrilldown(makeCtx());
  dd.openCluster(CID);
  await settle();

  assert.equal(q("#cluster-modal-title").textContent, "Test Cluster");
  const table = q(".cluster-modal-table").innerHTML;
  assert.ok(table.includes(A1) && table.includes(A2) && table.includes(A3), "alle drei Mitglieder in der Tabelle");
  assert.ok(table.includes("name-chip") && table.includes("Test Exchange One"), "Name-Chip hinter Host-Gate in der Tabelle");
  assert.ok(table.includes("Test Exchange Two"), "unverifizierter Name-Chip ebenfalls");
  // Kein 3D/vis im Stub -> ehrlicher noGraph-Hinweis (kein Crash).
  assert.ok(q(".cluster-3d").innerHTML.includes("graph-note"), "noGraph-Hinweis statt Graph");
  assert.equal(injectedScripts.length, 1, "genau ein Bundle-Injektionsversuch");
  // Freeze-Hinweis (DE) mit Stand-Zeit sichtbar.
  const note = q(".cluster-modal-stale");
  assert.equal(note.hidden, false);
  assert.ok(note.textContent.includes("Momentaufnahme vom 12:00:00"), "Freeze-Hinweis zeigt Stand-Zeit: " + note.textContent);
});

/* ---------------- 2) Live-Änderungen erreichen das offene Modal nicht ---------------- */

test("refresh nach Live-Änderung: Freeze hält Titel/Metriken, Live-Graph wird nicht mehr gelesen", async () => {
  const callsBefore = graphCalls;
  liveGraph = makeGraph("Live-Label geändert", 99);
  // Jedes initClusterDrilldown hat eigenen Modal-State; appendedOverlay zeigt
  // stets das zuletzt erzeugte Shell, alle q()-Zugriffe gelten für dieses Modal.
  const dd = initClusterDrilldown(makeCtx());
  dd.openCluster(CID);
  await settle();
  const callsAtOpen = graphCalls;
  assert.ok(callsAtOpen > callsBefore, "Live-Start liest den Graphen");
  // Nach dem ersten Vollrender ist der Freeze gesetzt: weitere Live-Änderungen
  // dürfen das Modal nicht mehr erreichen.
  liveGraph = makeGraph("Noch späterer Live-Label", 123);
  dd.refresh();
  await settle();
  assert.equal(q("#cluster-modal-title").textContent, "Live-Label geändert", "Freeze-Titel bleibt");
  assert.ok(!q(".cluster-modal-metrics").innerHTML.includes("123"), "Live-Metrik 123 erreicht das Modal nicht");
  assert.equal(graphCalls, callsAtOpen, "Freeze-Tick liest den Live-Graphen nicht mehr");
});

/* ---------------- 3) Cluster fällt aus dem Fenster: offenes Modal bleibt ---------------- */

test("Cluster aus dem Beobachtungsfenster: offenes Modal leert NICHT mehr (Akzeptanzpunkt)", async () => {
  liveGraph = { clusters: [], nodes: [], edges: [] };
  // dd aus Test 2 ist module-intern nicht exportiert — jedes initClusterDrilldown
  // hat seinen eigenen State, daher wird der Ablauf hier in einem neuen Modal
  // von Hand durchgespielt: Live-Start mit Graph, dann Graph entfernen.
  liveGraph = makeGraph("Bleibt sichtbar", 7);
  const dd = initClusterDrilldown(makeCtx());
  dd.openCluster(CID);
  await settle();
  assert.equal(q("#cluster-modal-title").textContent, "Bleibt sichtbar");

  liveGraph = { clusters: [], nodes: [], edges: [] };
  dd.refresh();
  await settle();
  assert.equal(q("#cluster-modal-title").textContent, "Bleibt sichtbar", "Freeze hält auch ohne Live-Cluster");
  const note = q(".cluster-modal-stale");
  assert.ok(note.textContent.includes("Momentaufnahme"), "Freeze-Hinweis bleibt");
  assert.ok(!note.textContent.includes("nicht mehr"), "keine Alterungs-/Leerungs-Meldung im Freeze");
  assert.ok(q(".cluster-modal-table").innerHTML.includes(A1), "Tabelle bleibt vollständig erhalten");
});

/* ---------------- 4) Nachträglicher Deny-Treffer fällt aus DOM und Export ---------------- */

test("Deny-Rotation: nachträglich verweigerte Adresse fällt aus Tabelle und Freeze-Satz", async () => {
  liveGraph = makeGraph("Deny-Test", 5);
  const dd = initClusterDrilldown(makeCtx());
  dd.openCluster(CID);
  await settle();
  assert.ok(q(".cluster-modal-table").innerHTML.includes(A2));

  denySet.add(A2); // serverseitige Deny-Liste rotiert: A2 jetzt verweigert
  dd.refresh();
  await settle();
  const table = q(".cluster-modal-table").innerHTML;
  assert.ok(!table.includes(A2), "verweigerte Adresse aus der Tabelle entfernt");
  assert.ok(table.includes(A1) && table.includes(A3), "übrige Mitglieder bleiben");

  // Alle Mitglieder verweigert -> ehrliche Total-Leerung (Köder-Schutz schlägt Freeze).
  denySet.add(A1);
  denySet.add(A3);
  dd.refresh();
  await settle();
  assert.equal(q("#cluster-modal-title").textContent, t("cluster.labelDefault"), "Total-Leerung: Default-Titel");
  assert.ok(q(".cluster-3d").innerHTML.includes(t("modal.gone")), "Total-Leerung: ehrlicher Gone-Hinweis");
  assert.equal(q(".cluster-modal-table").innerHTML, "", "Tabelle leer");
  denySet.clear();
});

/* ---------------- 5) close() (Escape) wirft den Freeze raus ---------------- */

test("close per Escape: neues Öffnen rendert wieder den Live-Stand", async () => {
  liveGraph = makeGraph("Erster Stand", 1);
  const dd = initClusterDrilldown(makeCtx());
  dd.openCluster(CID);
  await settle();
  assert.equal(q("#cluster-modal-title").textContent, "Erster Stand");

  // Escape -> close() (Keydown-Listener der Shell).
  const keydown = docListeners.keydown[docListeners.keydown.length - 1];
  keydown({ key: "Escape", preventDefault() {} });
  await settle();

  // Live ändern und neu öffnen: der neue Vollrender zeigt den neuen Stand.
  liveGraph = makeGraph("Zweiter Stand", 2);
  dd.openCluster(CID);
  await settle();
  assert.equal(q("#cluster-modal-title").textContent, "Zweiter Stand", "close() hat den Freeze verworfen");
});

/* ---------------- 6) Sprachwechsel malt Freeze-Labels neu ---------------- */

test("hx:langchange: Freeze-Inhalte werden in der neuen Sprache neu gemalt", async () => {
  lang = "de";
  liveGraph = makeGraph("Sprach-Test", 8);
  const dd = initClusterDrilldown(makeCtx());
  dd.openCluster(CID);
  await settle();
  assert.ok(q(".cluster-modal-table").innerHTML.includes("Adresse"), "DE-Tabelle (Spaltentitel 'Adresse')");

  lang = "en";
  const langHandler = docListeners["hx:langchange"][docListeners["hx:langchange"].length - 1];
  langHandler();
  await settle();
  assert.ok(q(".cluster-modal-table").innerHTML.includes("Address"), "EN-Tabelle nach Sprachwechsel (Spaltentitel 'Address')");
  assert.ok(!q(".cluster-modal-table").innerHTML.includes(">Adresse<"), "alter DE-Spaltentitel weg");
  const note = q(".cluster-modal-stale");
  assert.ok(note.textContent.includes("Snapshot from 12:00:00"), "Freeze-Hinweis in EN: " + note.textContent);
  // Daten bleiben der Freeze-Satz (Live-Graph wurde nicht neu gelesen):
  liveGraph = makeGraph("Sollte uns erreichen", 42);
  langHandler();
  await settle();
  assert.equal(q("#cluster-modal-title").textContent, "Sprach-Test", "Freeze-Daten bleiben auch beim Retranslate stabil");
  lang = "de";
});

/* ---------------- 6b) Stale-Overlay (Forensik 2026-10-06): leere Hülle unmöglich ----------------
   Massenbefund: Karten im akkumulierten Bestand (mergeClusterViews/Session-
   Schicht), deren Knoten aus dem FIFO-Fenster gerollt sind, öffneten eine
   LEERE Hülle; paintCluster fror den leeren Satz ein, recheckFrozen leerte
   ihn je Tick → modal.gone-Flapping (live 12/30 Karten betroffen). Fix:
   node-los → aus dem persistierten Bestand nachladen (getPersistedClusterById),
   sonst Missing-Semantik; Köder-Komplett-Deny bleibt in jedem Pfad der
   legitime Total-Leerungs-Terminalzustand. */

// Merged-Card-Nachstellung: Karte im akkumulierten Bestand, aber der
// Live-Graph trägt KEINEN Knoten mit dieser clusterId (FIFO-Fenster gerollt).
function emptyWindowGraph(label = "Bestands-Cluster") {
  return {
    clusters: [{
      id: CID, label, totalDrops: 4400, txCount: 12, distinctAccounts: 3,
      firstSeen: "2026-10-05T10:00:00Z", lastSeen: "2026-10-05T10:09:00Z",
      memberAddresses: [A1, A2, A3],
    }],
    nodes: [],
    edges: [],
  };
}

// Persistierter Bestand (Muster getPersistedClusterById/applyFlowStateView):
// memberAddresses/rolesByAddress/severityByAddress/edges — KEINE Drops/Grade
// (genau die ehrliche '–'-Situation in der Tabelle).
function makePersistedView() {
  return {
    cluster: {
      id: CID, label: "Bestands-Cluster", totalDrops: 4400, txCount: 12, distinctAccounts: 3,
      firstSeen: "2026-10-05T10:00:00Z", lastSeen: "2026-10-05T10:09:00Z",
      memberAddresses: [A1, A2, A3],
      rolesByAddress: { [A1]: "source", [A2]: "mid", [A3]: "sink" },
      severityByAddress: { [A1]: "malicious", [A2]: "suspect", [A3]: "info" },
      edges: [
        { from: A1, to: A2, type: "Payment", txHash: "PH1", closeTime: 3 },
        { from: A2, to: A3, type: "Payment", txHash: "PH2", closeTime: 4 },
      ],
      peelingChains: [],
    },
    nodes: [
      { id: A1, clusterId: CID, role: "source", severity: "malicious" },
      { id: A2, clusterId: CID, role: "mid", severity: "suspect" },
      { id: A3, clusterId: CID, role: "sink", severity: "info" },
    ],
    edges: [
      { from: A1, to: A2, type: "Payment", txHash: "PH1", closeTime: 3 },
      { from: A2, to: A3, type: "Payment", txHash: "PH2", closeTime: 4 },
    ],
    at: Date.parse("2026-10-05T12:00:00Z"),
  };
}

test("Stale-Overlay: node-lose Merged-Karte lädt aus dem persistierten Bestand nach (Inhalt + modal.persisted, kein modal.gone)", async () => {
  lang = "de";
  denySet.clear();
  liveGraph = emptyWindowGraph();
  const dd = initClusterDrilldown(makeCtx({
    getPersistedClusterById: async () => makePersistedView(),
  }));
  dd.openCluster(CID);
  await settle();

  // Vollrender aus dem Bestand: Titel/Metriken/Rollen/Tabelle stehen.
  assert.equal(q("#cluster-modal-title").textContent, "Bestands-Cluster", "Titel aus dem Bestand");
  assert.ok(q(".cluster-modal-metrics").innerHTML.includes("4400"), "Metriken aus dem Bestand");
  assert.ok(q(".cluster-modal-roles").innerHTML.includes("role-bar-row"), "Rollen-Balken aus rolesByAddress");
  const table = q(".cluster-modal-table").innerHTML;
  assert.ok(table.includes(A1) && table.includes(A2) && table.includes(A3), "Mitglieder aus memberAddresses");
  assert.ok(table.includes("cluster-table-dash"), "fehlende Drops/Grade ehrlich '–' statt 0");
  // modal.persisted-Banner sichtbar, kein modal.gone — KEINE leere Hülle.
  const note = q(".cluster-modal-stale");
  assert.equal(note.hidden, false, "Banner sichtbar");
  assert.ok(note.textContent.includes("persistierten Bestand"), "modal.persisted-Banner (DE): " + note.textContent);
  assert.ok(!q(".cluster-3d").innerHTML.includes(t("modal.gone")), "kein Gone-Banner");
  assert.ok(table.includes("<tr"), "Kernregression: Banner-Zustand hat >0 Inhaltskinder (Tabelle gefüllt)");
  // Freeze gesetzt: der Freeze-Tick liest den Live-Graphen nicht mehr und
  // behält den persisted-Hinweis (kein Zurückwandeln zu modal.frozen nötig —
  // der Text bleibt nur konsistent).
  const callsBefore = graphCalls;
  dd.refresh();
  await settle();
  assert.equal(graphCalls, callsBefore, "Bestands-Freeze liest den Live-Graphen nicht mehr");
  assert.ok(q(".cluster-modal-stale").textContent.includes("persistierten Bestand"), "Hinweis bleibt modal.persisted je Freeze-Tick");
});

test("Stale-Overlay: drei refresh-Ticks über denselben node-losen Cluster — Modal-Inhalt byte-identisch (kein Flapping)", async () => {
  lang = "de";
  denySet.clear();
  liveGraph = emptyWindowGraph();
  const dd = initClusterDrilldown(makeCtx({
    getPersistedClusterById: async () => makePersistedView(),
  }));
  dd.openCluster(CID);
  await settle();
  const before = {
    title: q("#cluster-modal-title").textContent,
    metrics: q(".cluster-modal-metrics").innerHTML,
    roles: q(".cluster-modal-roles").innerHTML,
    chain: q(".cluster-modal-chain").innerHTML,
    table: q(".cluster-modal-table").innerHTML,
    graph: q(".cluster-3d").innerHTML,
    note: q(".cluster-modal-stale").textContent,
  };
  // Live driftet währenddessen (der alte Defekt flapp-te je Poll-Tick):
  liveGraph = makeGraph("Live-Knoten zurück", 77);
  for (let i = 0; i < 3; i++) { dd.refresh(); await settle(); }
  assert.equal(q("#cluster-modal-title").textContent, before.title, "Titel stabil");
  assert.equal(q(".cluster-modal-metrics").innerHTML, before.metrics, "Metriken byte-identisch");
  assert.equal(q(".cluster-modal-roles").innerHTML, before.roles, "Rollen byte-identisch");
  assert.equal(q(".cluster-modal-chain").innerHTML, before.chain, "Kette byte-identisch");
  assert.equal(q(".cluster-modal-table").innerHTML, before.table, "Tabelle byte-identisch");
  assert.equal(q(".cluster-3d").innerHTML, before.graph, "Graph-Note byte-identisch (kein clearToEmptyState)");
  assert.equal(q(".cluster-modal-stale").textContent, before.note, "Banner-Text stabil");
  assert.ok(!q(".cluster-3d").innerHTML.includes(t("modal.gone")), "kein modal.gone je Tick");
  assert.ok(q(".cluster-modal-table").innerHTML.includes("<tr"), "Freeze-Banner-Zustand behält Inhalt");
});

test("Stale-Overlay INVARIANTE: Live-Knoten komplett per sync-Gate verweigert → sofortige Total-Leerung (Köder-Deny gewinnt)", async () => {
  lang = "de";
  denySet.add(A1); denySet.add(A2); denySet.add(A3);
  liveGraph = makeGraph("Komplett-Deny", 3);
  const dd = initClusterDrilldown(makeCtx());
  dd.openCluster(CID);
  await settle();
  assert.equal(q("#cluster-modal-title").textContent, t("cluster.labelDefault"), "Total-Leerung: Default-Titel");
  assert.ok(q(".cluster-3d").innerHTML.includes(t("modal.gone")), "modal.gone bei sync Komplett-Deny");
  assert.equal(q(".cluster-modal-table").innerHTML, "", "Tabelle leer");
  denySet.clear();
});

test("Stale-Overlay INVARIANTE: Restore-Bestand komplett Köder → clearToEmptyState im Nachlade-Pfad (Terminalzustand, kein Reload-Loop)", async () => {
  lang = "de";
  liveGraph = emptyWindowGraph();
  const dd = initClusterDrilldown(makeCtx({
    getPersistedClusterById: async () => makePersistedView(),
  }));
  denySet.add(A1); denySet.add(A2); denySet.add(A3);
  dd.openCluster(CID);
  await settle();
  assert.equal(q("#cluster-modal-title").textContent, t("cluster.labelDefault"), "Total-Leerung: Default-Titel");
  assert.ok(q(".cluster-3d").innerHTML.includes(t("modal.gone")), "Gone-Banner (legitimer Terminalzustand Köder)");
  assert.equal(q(".cluster-modal-table").innerHTML, "", "Tabelle geleert (Invariante Köder-Deny > Nachladen)");
  // Terminalzustand hält unter unverändertem Deny: kein innerer Reload-
  // Wiederversuch, stabil leeres Modal statt Flapping.
  dd.refresh();
  await settle();
  assert.ok(q(".cluster-3d").innerHTML.includes(t("modal.gone")), "Terminalzustand hält je Tick");
  assert.equal(q("#cluster-modal-title").textContent, t("cluster.labelDefault"), "Titel bleibt Default");
  denySet.clear();
});

test("Stale-Overlay Fallback: Restore scheitert und kein Snapshot → ehrliche modal.gone-Leerung (nie halluzinieren)", async () => {
  lang = "de";
  liveGraph = emptyWindowGraph();
  let persistedCalls = 0;
  const dd = initClusterDrilldown(makeCtx({
    getPersistedClusterById: async () => { persistedCalls += 1; return null; },
  }));
  dd.openCluster(CID);
  await settle();
  assert.ok(persistedCalls >= 1, "Restore-Pfad befragt den Bestand");
  assert.equal(q("#cluster-modal-title").textContent, t("cluster.labelDefault"), "Default-Titel");
  assert.ok(q(".cluster-3d").innerHTML.includes(t("modal.gone")), "modal.gone-Fallback");
  assert.equal(q(".cluster-modal-table").innerHTML, "", "ehrliche Leerung (Inhalt existierte nie)");
});

test("Stale-Overlay: node-lose Öffnung korrumpiert den Fallback-Anker nicht (kein Fremd-Adopt, kein toter Zustand)", async () => {
  lang = "de";
  liveGraph = emptyWindowGraph();
  const dd = initClusterDrilldown(makeCtx({ getPersistedClusterById: async () => null }));
  dd.openCluster(CID);
  await settle();
  assert.ok(q(".cluster-3d").innerHTML.includes(t("modal.gone")), "Fallback-Zustand");
  // Fremder Cluster (nie gesehene Mitglieder): wird NICHT adoptiert — der
  // Anker wurde nicht aus der leeren Knotenmenge gesetzt (originMembers blieb
  // null; ohne Fix hätte render() dort ein leeres Set verankert).
  liveGraph = {
    clusters: [{
      id: "cluster:" + A3, label: "Nachfolger", totalDrops: 10, txCount: 1, distinctAccounts: 2,
      firstSeen: "2026-10-05T10:06:00Z", lastSeen: "2026-10-05T10:07:00Z",
      memberAddresses: [A3, A2],
    }],
    nodes: [
      { id: A3, clusterId: "cluster:" + A3, role: "sink", inDrops: 10, outDrops: 0, degreeIn: 1, degreeOut: 0, severity: "info" },
      { id: A2, clusterId: "cluster:" + A3, role: "mid", inDrops: 0, outDrops: 10, degreeIn: 0, degreeOut: 1, severity: "info" },
    ],
    edges: [],
  };
  dd.refresh();
  await settle();
  assert.equal(q("#cluster-modal-title").textContent, t("cluster.labelDefault"), "kein Titel-Wechsel auf den Fremd-Cluster");
  assert.ok(q(".cluster-3d").innerHTML.includes(t("modal.gone")), "kein Fremd-Adopt nach node-losem Öffnen");
  // Und der echte Cluster kommt mit Knoten zurück → vollwertiger Vollrender
  // (kein toter Zustand durch die node-lose Öffnung).
  liveGraph = makeGraph("Wieder da", 3);
  dd.refresh();
  await settle();
  assert.equal(q("#cluster-modal-title").textContent, "Wieder da", "Vollrender nach node-losem Fehlschlag");
});

/* ---------------- 7) Name-Chips nur hinter dem Host-Gate ---------------- */

test("Gate: ohne ctx.accountNameOf (Host liefert null) gibt es keine Name-Chips", async () => {
  liveGraph = makeGraph("Gate-Test", 9);
  const dd = initClusterDrilldown(makeCtx({ accountNameOf: () => null }));
  dd.openCluster(CID);
  await settle();
  const table = q(".cluster-modal-table").innerHTML;
  assert.ok(table.includes(A1), "Adressen weiterhin sichtbar");
  assert.ok(!table.includes("name-chip"), "keine Chips ohne Host-Lookup (fail-closed)");
});

test("Gate: maskierte Vollanzeige (isFullShownAddr false) zeigt Kurzform ohne Chips", async () => {
  liveGraph = makeGraph("Masken-Test", 10);
  const dd = initClusterDrilldown(makeCtx({ isFullShownAddr: () => false }));
  dd.openCluster(CID);
  await settle();
  const table = q(".cluster-modal-table").innerHTML;
  assert.ok(!table.includes(A1), "volle Adresse nicht im DOM (nur Kurzform)");
  assert.ok(table.includes(A1.slice(0, 6) + "…"), "Kurzform wie shortAddr");
  assert.ok(!table.includes("name-chip"), "kein Name-Chip an maskierter Kurzform");
});

/* ---------------- 8) Destination-Tag-Chips (tagIdentityDesign 2026-10-05) ---------------- */

// Registry-Stub: nur A2 ist Hosted-Account einer Börse (A3 ohne Treffer ->
// kein Chip, obwohl die Kante A2→A3 ein toTag trägt — Gate-Verhalten).
const registryEntryOf = (a) =>
  String(a) === A2 ? { exchange: "Test Exchange Two", requireDestTag: true } : null;
// Host-Gate-Muster (app.js exchangeEntryOf): Registry-Lookup nur bei
// erlaubter Vollanzeige (hier: nicht Deny-adressiert).
const gatedRegistry = (a) => (!denySet.has(String(a)) ? registryEntryOf(a) : null);

function makeTagGraph() {
  const g = makeGraph("Tag-Cluster", 4);
  g.edges = [
    { from: A1, to: A2, type: "payment", txHash: "HASHT1", closeTime: 1, toTag: 42 },
    { from: A2, to: A3, type: "payment", txHash: "HASHT2", closeTime: 2, toTag: 77, transit: true },
  ];
  return g;
}

// flowPaths-Stub: ein Pfad über alle Knoten in Knoten-Reihenfolge
// (A1 source → A2 mid → A3 sink) — die Kette bekommt damit prevId-Kanten.
const chainPaths = () => (nodes) => [nodes];

test("Tag-Chips: Tabelle und Kette zeigen #tag nur bei Registry-Treffer des Ziels", async () => {
  lang = "de";
  liveGraph = makeTagGraph();
  const dd = initClusterDrilldown(makeCtx({ exchangeEntryOf: gatedRegistry, flowPaths: chainPaths }));
  dd.openCluster(CID);
  await settle();

  const table = q(".cluster-modal-table").innerHTML;
  assert.ok(table.includes("tag-chip") && table.includes("#42"), "Tag-Chip #42 an A2 (Registry-Treffer)");
  assert.ok(!table.includes("#77"), "kein Chip #77 an A3 (kein Registry-Treffer, Gate fail-closed)");

  const chain = q(".cluster-modal-chain").innerHTML;
  assert.ok(chain.includes("chain-node") && chain.includes("chain-arrow"), "Kette mit echten Kanten (flowPaths)");
  assert.ok(chain.includes("#42"), "Tag-Chip #42 am Ziel-Knoten der Kette");
  assert.ok(!chain.includes("#77"), "kein Chip #77 an der Kette (Gate)");
  assert.ok(chain.includes("cluster-transit-note") && chain.includes(t("cluster.transitNote")), "Transit-Hinweis bei transit-Kante");
});

test("Tag-Chips fail-closed: ohne ctx.exchangeEntryOf keine Chips (Transit-Hinweis bleibt datengetrieben)", async () => {
  liveGraph = makeTagGraph();
  const dd = initClusterDrilldown(makeCtx({ flowPaths: chainPaths }));
  dd.openCluster(CID);
  await settle();
  const table = q(".cluster-modal-table").innerHTML;
  const chain = q(".cluster-modal-chain").innerHTML;
  assert.ok(!table.includes("tag-chip"), "keine Tag-Chips ohne Host-Lookup");
  assert.ok(!chain.includes("tag-chip"), "keine Tag-Chips in der Kette ohne Host-Lookup");
  assert.ok(chain.includes("cluster-transit-note"), "Transit-Hinweis bleibt (reine Daten-Eigenschaft der Kante)");
});

test("Tag-Chips: maskierte Tabellenzeile (isFullShownAddr false) ohne Chips, auch mit Registry-Treffer", async () => {
  liveGraph = makeTagGraph();
  // Absichtlich ungegateter exchangeEntryOf: prüft die EIGENE Defense-in-
  // Depth der Tabellenzeile (tagSet nur bei full) — die Kette ist Host-Gate-
  // Sache (app.js exchangeEntryOf prüft isFullShownAddr selbst).
  const dd = initClusterDrilldown(makeCtx({ isFullShownAddr: () => false, exchangeEntryOf: registryEntryOf }));
  dd.openCluster(CID);
  await settle();
  const table = q(".cluster-modal-table").innerHTML;
  assert.ok(!table.includes(A2), "volle Adresse nicht im DOM (nur Kurzform)");
  assert.ok(!table.includes("tag-chip"), "keine Tag-Chips an maskierter Kurzform");
});

/* ---------------- 9) Konten-Tabelle: getrennte Exchange-/Tag-Spalten (Layout-Fix 2026-10-05) ---------------- */

test("Konten-Tabelle: Exchange- und Tag-Spalten getrennt, Adress-Zelle trägt nur die Adresse", async () => {
  lang = "de";
  liveGraph = makeTagGraph();
  // Kein ctx.multiUserEntryOf: der Fallback auf ctx.exchangeEntryOf (gatedRegistry)
  // trägt die Chips — derselbe Vertrag wie vor dem Coverage-Fix.
  const dd = initClusterDrilldown(makeCtx({ exchangeEntryOf: gatedRegistry, flowPaths: chainPaths }));
  dd.openCluster(CID);
  await settle();
  const table = q(".cluster-modal-table").innerHTML;
  // Spaltenüberschriften: Adresse, Exchange, Tag (DE, korrekte Orthographie).
  assert.ok(table.includes(">Adresse<"), "DE Adress-Spalte");
  assert.ok(table.includes(">Börse<"), "DE Exchange-Spalte");
  assert.ok(table.includes(">Tag<"), "DE Tag-Spalte");
  // Chips in eigenen Zellen (Exchange-/Tag-Spalte), nicht mehr an der Adresse.
  assert.ok(table.includes('td class="cluster-td-exchange"'), "Exchange-Zelle vorhanden");
  assert.ok(table.includes('td class="cluster-td-tag"'), "Tag-Zelle vorhanden");
  assert.ok(table.includes(`<td class="cluster-td-addr" title="${A2}">${A2}</td>`), "Adress-Zelle trägt nur die Adresse (keine Chips mehr)");
  assert.ok(table.includes('class="name-chip"'), "Name-Chip weiterhin gerendert (jetzt in der Exchange-Spalte)");
  assert.ok(table.includes("#42"), "Tag-Chip #42 weiterhin gerendert (jetzt in der Tag-Spalte)");
});

test("Freeze-Export: Kanten tragen toTag/transit additiv (ohne Tag-Felder bleiben Kanten schlank)", async () => {
  liveGraph = makeGraph("Export-Ohne-Tags", 6);
  const dd = initClusterDrilldown(makeCtx({ exchangeEntryOf: gatedRegistry }));
  dd.openCluster(CID);
  await settle();

  // Download-Pfad stuben: Blob fängt den JSON-String, URL/A-Methoden no-op.
  let captured = null;
  class BlobStub {
    constructor(parts) { captured = String(parts[0]); }
  }
  const prevBlob = globalThis.Blob;
  const prevURL = globalThis.URL;
  globalThis.Blob = BlobStub;
  globalThis.URL = { createObjectURL: () => "blob:stub", revokeObjectURL: () => {} };
  const prevOverlay = appendedOverlay; // body.appendChild(<a>) überschreibt den Stub-Pointer
  try {
    const handler = q("#cluster-json-download").listeners.click[0];
    await handler();
    assert.ok(captured, "Export-JSON erzeugt");
    const payload = JSON.parse(captured);
    assert.equal(payload.edges.length, 2);
    assert.ok(!("toTag" in payload.edges[0]) && !("transit" in payload.edges[0]), "Kanten ohne Tag tragen keine Tag-Felder");
  } finally {
    appendedOverlay = prevOverlay;
    if (prevBlob === undefined) delete globalThis.Blob; else globalThis.Blob = prevBlob;
    if (prevURL === undefined) delete globalThis.URL; else globalThis.URL = prevURL;
  }

  // Jetzt mit Tags: toTag/transit additiv im Export.
  liveGraph = makeTagGraph();
  const dd2 = initClusterDrilldown(makeCtx({ exchangeEntryOf: gatedRegistry }));
  dd2.openCluster(CID);
  await settle();
  captured = null;
  globalThis.Blob = BlobStub;
  globalThis.URL = { createObjectURL: () => "blob:stub", revokeObjectURL: () => {} };
  const prevOverlay2 = appendedOverlay;
  try {
    const handler2 = q("#cluster-json-download").listeners.click[0];
    await handler2();
    const payload2 = JSON.parse(captured);
    assert.equal(payload2.edges[0].toTag, 42, "toTag im Export (Kante A1→A2)");
    assert.equal(payload2.edges[1].toTag, 77, "toTag im Export (Kante A2→A3)");
    assert.equal(payload2.edges[1].transit, true, "transit im Export");
    assert.ok(!("transit" in payload2.edges[0]), "transit nur bei belegter Kante");
  } finally {
    appendedOverlay = prevOverlay2;
    if (prevBlob === undefined) delete globalThis.Blob; else globalThis.Blob = prevBlob;
    if (prevURL === undefined) delete globalThis.URL; else globalThis.URL = prevURL;
  }
});

/* ---------------- 10) 3D-Layout: deterministisch und entstapelt ----------------
   (Entstapelung 2026-10-06: Fibonacci-Kugel-Startpositionen statt Bibliotheks-
   Phyllotaxis, Radius/Abstoßung/Link-Distanz skalieren mit cbrt(N), eigene
   Collide-Kraft, synchroner Warmup-Deckel 120 — siehe cluster3dLayoutParams
   in public/drilldown.js.) */

function layoutOverlaps(nodes, radiusOf) {
  let count = 0;
  for (let i = 0; i < nodes.length; i++) {
    for (let j = i + 1; j < nodes.length; j++) {
      const d = Math.hypot(nodes[i].x - nodes[j].x, nodes[i].y - nodes[j].y, nodes[i].z - nodes[j].z);
      if (d < radiusOf(nodes[i]) + radiusOf(nodes[j])) count++;
    }
  }
  return count;
}

test("3D-Layout: gleiche Knotenmenge -> identische Startkoordinaten (kein Math.random)", () => {
  const mkNodes = () => Array.from({ length: 64 }, (_, i) => ({ id: "rTESTnode" + i, inDrops: 1e9, outDrops: 0 }));
  const nodesA = mkNodes();
  const nodesB = mkNodes();
  const pA = cluster3dLayoutParams(nodesA);
  const pB = cluster3dLayoutParams(nodesB);
  // Random-Sperre: der Seed darf Math.random nicht anfassen (Determinismus).
  const prevRandom = Math.random;
  try {
    Math.random = () => { throw new Error("seedCluster3dPositions darf nicht randomisieren"); };
    seedCluster3dPositions(nodesA, pA.seedRadius);
    seedCluster3dPositions(nodesB, pB.seedRadius);
  } finally {
    Math.random = prevRandom;
  }
  assert.deepEqual(
    nodesA.map((n) => [n.x, n.y, n.z]),
    nodesB.map((n) => [n.x, n.y, n.z]),
    "zwei Läufe liefern identische Koordinaten",
  );
  // Alle Startpositionen liegen exakt auf der skalierten Fibonacci-Kugel.
  for (const n of nodesA) {
    assert.ok(Math.abs(Math.hypot(n.x, n.y, n.z) - pA.seedRadius) < 1e-9, "Knoten auf der Startkugel radius=seedRadius");
  }
});

test("3D-Layout: Skalierung nach Knotenanzahl (N=5/64/300) — Radius, Abstoßung, Link-Distanz, Warmup-Deckel", () => {
  const mk = (N) => Array.from({ length: N }, (_, i) => ({ id: "n" + i, inDrops: 1e9, outDrops: 0 }));
  const p5 = cluster3dLayoutParams(mk(5));
  const p64 = cluster3dLayoutParams(mk(64));
  const p300 = cluster3dLayoutParams(mk(300));
  // Exakte Formeln (k = cbrt(N)): charge = -60·k² mit Reichweite 6·maxR,
  // relSize = max(1.2, 4/k), Link-Distanz = 1.4·(Radien-Summe).
  const k5 = Math.cbrt(5);
  const k300 = Math.cbrt(300);
  assert.ok(Math.abs(p5.chargeStrength - (-60 * k5 * k5)) < 1e-9, "N=5: charge -60·cbrt(5)²");
  assert.ok(Math.abs(p64.chargeStrength - (-960)) < 1e-9, "N=64: charge -960 (Bundle-Default -60 · 4²)");
  assert.ok(Math.abs(p300.chargeStrength - (-60 * k300 * k300)) < 1e-9, "N=300: charge -60·cbrt(300)²");
  assert.ok(Math.abs(p64.chargeDistanceMax - 6 * 12.003998667406913) < 1e-6, "N=64: Abstoßungs-Reichweite 6·maxR (bbox-Deckel gegen Ketten-Streckung)");
  assert.ok(p5.nodeRelSize > 2.3 && p5.nodeRelSize < 2.4, "N=5: nodeRelSize 4/cbrt(5)≈2.34 (kleine Cluster bleiben groß)");
  assert.equal(p64.nodeRelSize, 1.2, "N=64: nodeRelSize am Deckel 1.2");
  assert.equal(p300.nodeRelSize, 1.2, "N=300: nodeRelSize am Deckel 1.2");
  // Monotonie: Abstoßung wird mit N stärker (negativer).
  assert.ok(p300.chargeStrength < p64.chargeStrength && p64.chargeStrength < p5.chargeStrength, "Abstoßung skaliert mit N");
  // Link-Distanz radien-basiert: 1.4 · (r(source) + r(target)).
  const probeLink = { source: { inDrops: 1e9, outDrops: 0 }, target: { inDrops: 1e11, outDrops: 0 } };
  const expectDist = 1.4 * (p300.radiusOf(probeLink.source) + p300.radiusOf(probeLink.target));
  assert.ok(Math.abs(p300.linkDistance(probeLink) - expectDist) < 1e-9, "Link-Distanz = 1.4·(Radien-Summe), Hub-Links weiter als Klein-Knoten-Links");
  assert.ok(p300.linkDistance(probeLink) > p300.linkDistance({ source: probeLink.source, target: probeLink.source }), "Hub-Link weiter als Kleinknoten-Link");
  // Warmup synchron im Bundle: Untergrenze 30, Deckel 120 Ticks (kein Jank).
  assert.equal(p5.warmupTicks, 30, "N=5: warmup 30 (Untergrenze)");
  assert.equal(p64.warmupTicks, 120, "N=64: warmup 120 (2N=128 -> Deckel 120)");
  assert.equal(p300.warmupTicks, 120, "N=300: warmup 120 (Deckel)");
  // valOf/radiusOf entsprechen dem nodeVal-Accessor und der Bundle-Radiusformel.
  assert.equal(p64.valOf({ inDrops: 1e9, outDrops: 0 }), 1001, "val = 1 + drops/1e6");
  assert.ok(Math.abs(p64.radiusOf({ inDrops: 1e9, outDrops: 0 }) - Math.cbrt(1001) * 1.2) < 1e-9, "Radius = nodeRelSize·cbrt(val) wie im Bundle");
});

test("3D-Layout: Startpositionen + Collide-Warmup lösen alle Überlappungen (N=5..300, reale Drops)", () => {
  const cases = [
    { name: "5 Knoten × 1 XRP", drops: Array(5).fill(1e6) },
    { name: "64 Knoten × 1000 XRP (Median-Cluster)", drops: Array(64).fill(1e9) },
    { name: "300 Knoten, Hub 100k XRP", drops: [1e11, ...Array(299).fill(1e9)] },
    { name: "300 Knoten, Hub 860k XRP (max realer totalDrops 8.6e11)", drops: [8.6e11, ...Array(299).fill(1e9)] },
  ];
  for (const c of cases) {
    const nodes = c.drops.map((d, i) => ({ id: "rTESTc" + i, inDrops: d, outDrops: 0 }));
    const p = cluster3dLayoutParams(nodes);
    seedCluster3dPositions(nodes, p.seedRadius);
    const before = layoutOverlaps(nodes, p.radiusOf);
    // Warmup wie im Bundle: Collide-Kraft + d3-Integration (velocityDecay 0.4
    // -> v *= 0.6). vx/vy/vz initialisieren wie d3-force-3d (initializeNodes
    // setzt 0) — ohne das wäre jede Kraft-Addition NaN.
    for (const n of nodes) { n.vx = 0; n.vy = 0; n.vz = 0; }
    const collide = makeCluster3dCollideForce(p.radiusOf);
    collide.initialize(nodes);
    for (let t = 0; t < p.warmupTicks; t++) {
      collide();
      for (const n of nodes) {
        n.vx *= 0.6; n.vy *= 0.6; n.vz *= 0.6;
        n.x += n.vx; n.y += n.vy; n.z += n.vz;
      }
    }
    assert.ok(nodes.every((n) => Number.isFinite(n.x) && Number.isFinite(n.y) && Number.isFinite(n.z)), c.name + ": Positionen nach Warmup endlich (kein NaN-Durchgriff)");
    assert.equal(layoutOverlaps(nodes, p.radiusOf), 0, c.name + ": keine überlappenden Paare nach Warmup (Start: " + before + ")");
  }
});

test("3D-Layout: Collide-Kraft — deterministisch, schwere Knoten bewegen sich weniger, deckungsgleiche Punkte trennen sich", () => {
  const radiusOf = (n) => n.r;
  const mkPair = () => [
    { id: "heavy", x: 0, y: 0, z: 0, vx: 0, vy: 0, vz: 0, r: 100 },
    { id: "light", x: 0, y: 0, z: 0, vx: 0, vy: 0, vz: 0, r: 10 },
  ];
  const nodesA = mkPair();
  const nodesB = mkPair();
  const fA = makeCluster3dCollideForce(radiusOf);
  const fB = makeCluster3dCollideForce(radiusOf);
  fA.initialize(nodesA);
  fB.initialize(nodesB);
  fA();
  fB();
  assert.deepEqual(nodesA.map((n) => [n.vx, n.vy, n.vz]), nodesB.map((n) => [n.vx, n.vy, n.vz]), "gleiche Eingabe -> gleiche Geschwindigkeiten");
  const mag = (n) => Math.hypot(n.vx, n.vy, n.vz);
  assert.ok(mag(nodesA[0]) > 0 && mag(nodesA[1]) > 0, "deckungsgleiche Knoten bekommen Bewegung (feste Richtung, deterministisch)");
  assert.ok(mag(nodesA[0]) < mag(nodesA[1]), "schwerer Knoten (r=100) bewegt sich weniger als leichter (r=10)");
  assert.ok(Math.sign(nodesA[0].vx) !== Math.sign(nodesA[1].vx), "Paar bewegt sich gegeneinander");
  // Nicht überlappende Paare bleiben unberührt.
  const far = [
    { id: "a", x: 0, y: 0, z: 0, vx: 0, vy: 0, vz: 0, r: 5 },
    { id: "b", x: 50, y: 0, z: 0, vx: 0, vy: 0, vz: 0, r: 5 },
  ];
  const fFar = makeCluster3dCollideForce(radiusOf);
  fFar.initialize(far);
  fFar();
  assert.deepEqual(far.map((n) => [n.vx, n.vy, n.vz]), [[0, 0, 0], [0, 0, 0]], "Abstand > Radien-Summe -> keine Kraft");
});

/* Fake-ForceGraph3D: prüft die build3D-Verdrahtung (Physik-Zugriffe,
   warmupTicks-Gate, Seed-Positionen im graphData, Freeze bleibt) ohne WebGL.
   Design P3 (2026-10-06): zusätzlich Recorder für die Stil-Flags
   (backgroundColor/linkOpacity/linkWidth/linkColor/nodeColor/
   nodeThreeObject/nodeThreeObjectExtend/onNodeHover) und ein steuerbares
   scene()-Stub (record.sceneNodes) für die Ring-Klassen-Recovery. */
// Record-Factory: gemeinsame Initialisierung für alle Fake-Fg3d-Tests
// (Design P3 erweitert die Liste um die Stil-Recorder).
function makeRecord() {
  return {
    destructorCalls: 0, resumeCalls: 0, zoomToFitCalls: 0, sceneCalls: 0,
    graphDataSets: [], warmupTicksCalls: [], cooldownTicksCalls: [],
    nodeRelSizeCalls: [], d3ForceSet: {},
    linkWidthFns: [], linkColorFns: [], nodeColorFns: [], nodeThreeObjectFns: [],
    nodeThreeObjectExtend: null, onNodeHover: null, linkOpacity: null, backgroundColor: null,
    sceneNodes: [],
  };
}

function makeFakeFg3d(record) {
  let data = { nodes: [], links: [] };
  const fakeScene = {
    traverse(cb) { for (const o of record.sceneNodes || []) cb(o); },
  };
  const self = {
    _destructor() { record.destructorCalls += 1; },
    pauseAnimation() {},
    resumeAnimation() { record.resumeCalls += 1; },
    width(w) { record.width = w; return self; },
    height(h) { record.height = h; return self; },
    backgroundColor(v) { record.backgroundColor = v; return self; },
    nodeLabel() { return self; },
    linkLabel() { return self; },
    linkWidth(fn) { record.linkWidthFns.push(fn); return self; },
    linkDirectionalArrowLength() { return self; },
    linkDirectionalParticles() { return self; },
    linkDirectionalParticleWidth() { return self; },
    linkColor(fn) { record.linkColorFns.push(fn); return self; },
    nodeColor(fn) { record.nodeColorFns.push(fn); return self; },
    nodeVal(v) { record.nodeVal = v; return self; },
    nodeRelSize(v) { record.nodeRelSizeCalls.push(v); return self; },
    nodeThreeObject(fn) { record.nodeThreeObjectFns.push(fn); return self; },
    nodeThreeObjectExtend(v) { record.nodeThreeObjectExtend = v; return self; },
    onNodeHover(fn) { record.onNodeHover = fn; return self; },
    onNodeClick() { return self; },
    linkOpacity(v) { record.linkOpacity = v; return self; },
    scene() { record.sceneCalls += 1; return fakeScene; },
    zoomToFit() { record.zoomToFitCalls += 1; return self; },
    cooldownTicks(v) { record.cooldownTicksCalls.push(v); return self; },
    warmupTicks(v) { record.warmupTicksCalls.push(v); return self; },
    graphData(...args) {
      if (args.length) { data = args[0]; record.graphDataSets.push(data); return self; }
      return data;
    },
    d3Force(name, force) {
      if (arguments.length > 1) { record.d3ForceSet[name] = force; return self; }
      return {
        strength(v) { record.chargeStrength = v; return this; },
        distanceMax(v) { record.chargeDistanceMax = v; return this; },
        distance(v) { record.linkDistance = v; return this; },
      };
    },
  };
  return self;
}

test("build3D-Verdrahtung: Physik-Konfiguration, Warmup nur bei Cluster-Wechsel, Positionen bei Live-Update übernommen, Freeze intakt", async () => {
  lang = "de";
  liveGraph = makeGraph("Layout-Cluster", 5);
  const record = makeRecord();
  const prevCreateElement = documentStub.createElement;
  const prevForceGraph3D = windowStub.ForceGraph3D;
  try {
    // WebGL-Probe bejahen + ForceGraph3D als Fake bereitstellen (sonst noGraph-Pfad).
    // Muster des echten Bundles: ForceGraph3D() gibt eine AUFRUFBARE Instanz
    // zurück — build3D ruft window.ForceGraph3D()(graphEl).
    documentStub.createElement = (tag) => (tag === "canvas" ? { getContext: () => ({ fake: true }) } : makeEl(tag));
    windowStub.ForceGraph3D = () => () => makeFakeFg3d(record);

    const dd = initClusterDrilldown(makeCtx());
    dd.openCluster(CID);
    await settle();

    // Erstrender: N=3 (makeGraph) -> k=cbrt(3); Warmup mit Untergrenze 30.
    const k3 = Math.cbrt(3);
    assert.equal(typeof record.d3ForceSet.collide, "function", "eigene Collide-Kraft per d3Force('collide', …) gesetzt");
    assert.ok(Math.abs(record.chargeStrength - (-60 * k3 * k3)) < 1e-9, "charge-Skalierung gesetzt: " + record.chargeStrength);
    assert.equal(typeof record.linkDistance, "function", "Link-Distanz als radien-basierte Funktion gesetzt");
    assert.deepEqual(record.warmupTicksCalls, [30], "warmupTicks(30) bei Cluster-Wechsel/Erstrender");
    assert.deepEqual(record.nodeRelSizeCalls, [Math.max(1.2, 4 / k3)], "nodeRelSize nach Knotenanzahl gesetzt");
    // Freeze-Physik (paintCluster cooldownTicks(0)) bleibt erhalten.
    assert.ok(record.cooldownTicksCalls.includes(0), "Freeze cooldownTicks(0) weiterhin gesetzt");
    assert.ok(record.resumeCalls >= 1, "resumeAnimation weiterhin aufgerufen");
    // Alle Knoten des graphData tragen deterministische Startkoordinaten.
    const firstData = record.graphDataSets[0];
    assert.equal(firstData.nodes.length, 3, "drei Cluster-Knoten im graphData");
    const pFirst = cluster3dLayoutParams(firstData.nodes);
    assert.ok(Math.abs(record.chargeDistanceMax - pFirst.chargeDistanceMax) < 1e-9, "Abstoßungs-Reichweite 6·maxR gesetzt (bbox-Deckel)");
    for (const n of firstData.nodes) {
      assert.ok(Number.isFinite(n.x) && Number.isFinite(n.y) && Number.isFinite(n.z), "Startkoordinaten gesetzt");
      assert.ok(Math.abs(Math.hypot(n.x, n.y, n.z) - cluster3dLayoutParams(firstData.nodes).seedRadius) < 1e-9, "Knoten auf der Startkugel");
    }

    // Sprachwechsel -> paintCluster mit demselben clusterId (sameCluster-Pfad):
    // warmupTicks(0) und die eingesessenen Koordinaten werden übernommen.
    lang = "en";
    const langHandler = docListeners["hx:langchange"][docListeners["hx:langchange"].length - 1];
    langHandler();
    await settle();
    assert.deepEqual(record.warmupTicksCalls, [30, 0], "Live-Update desselben Clusters: warmupTicks(0) (kein Jank je Poll)");
    const secondData = record.graphDataSets[1];
    assert.ok(secondData, "graphData erneut gesetzt (Alterungs-/Sprachpfad löst den Graphen)");
    const prevById = new Map(firstData.nodes.map((n) => [n.id, n]));
    for (const n of secondData.nodes) {
      const p = prevById.get(n.id);
      assert.ok(p, "Knoten weiterhin im Graphen");
      assert.equal(n.x, p.x, "x-Koordinate übernommen");
      assert.equal(n.y, p.y, "y-Koordinate übernommen");
      assert.equal(n.z, p.z, "z-Koordinate übernommen");
    }
    // nodeRelSize bleibt pro build3D korrekt gesetzt (N unverändert -> gleicher Wert).
    assert.deepEqual(record.nodeRelSizeCalls, [Math.max(1.2, 4 / k3), Math.max(1.2, 4 / k3)], "nodeRelSize pro build3D gesetzt");
    lang = "de";
  } finally {
    documentStub.createElement = prevCreateElement;
    if (prevForceGraph3D === undefined) delete windowStub.ForceGraph3D; else windowStub.ForceGraph3D = prevForceGraph3D;
  }
});

test("Riesen-Cluster: Deny-Nachprüfung auf DENY_RECHECK_MAX gedeckelt (deterministisch), 3D-Knoten-Kappe greift", async () => {
  lang = "de";
  // Live-Repro (2026-10-06): die vollständige sequenzielle Köder-Nachprüfung
  // hashte im 46.660-Knoten-Mega-Modal jede Adresse (>75 s Browser-Block,
  // dazu LRU-Verdrängung im 10.000er-Hash-Cache des Hosts). Erwartung jetzt:
  // genau DENY_RECHECK_MAX Nachprüfungen in deterministischer Reihenfolge
  // (Drops desc, dann Adresse asc) UND die bestehende 3D-Knoten-Kappe
  // (GRAPH3D_MAX_NODES 300 + Aggregatknoten) hält den Graphen klein.
  const bigN = DENY_RECHECK_MAX + 500;
  const bigNodes = Array.from({ length: bigN }, (_, i) => ({
    id: `rTESTbigNode${String(i).padStart(5, "0")}`,
    clusterId: CID,
    role: i % 3 === 0 ? "source" : (i % 3 === 1 ? "mid" : "sink"),
    inDrops: bigN - i, outDrops: 0, degreeIn: 1, degreeOut: 1, // Node 0 = höchste Drops-Summe
    severity: i % 7 === 0 ? "suspect" : "info",
  }));
  liveGraph = {
    clusters: [{
      id: CID, label: "Riesen-Cluster", totalDrops: 1000, txCount: bigN, distinctAccounts: bigN,
      firstSeen: "2026-10-05T10:00:00Z", lastSeen: "2026-10-05T10:05:00Z",
      memberAddresses: bigNodes.map((n) => n.id),
    }],
    nodes: bigNodes,
    edges: bigNodes.slice(1).map((n, i) => ({ from: bigNodes[i].id, to: n.id, type: "payment", txHash: `BH${i}`, closeTime: i })),
  };
  const denyCalls = [];
  const record = makeRecord();
  const prevCreateElement = documentStub.createElement;
  const prevForceGraph3D = windowStub.ForceGraph3D;
  try {
    documentStub.createElement = (tag) => (tag === "canvas" ? { getContext: () => ({ fake: true }) } : makeEl(tag));
    windowStub.ForceGraph3D = () => () => makeFakeFg3d(record);
    const dd = initClusterDrilldown(makeCtx({
      isDeniedAddrAsync: async (a) => { denyCalls.push(String(a)); return false; },
    }));
    dd.openCluster(CID);
    await settle();
    assert.equal(record.graphDataSets.length, 1, "graphData gesetzt");
    // 3D-Knoten-Kappe: 300 Top-Knoten + 1 Aggregatknoten — nie bigN.
    assert.equal(record.graphDataSets[0].nodes.length, 301, "GRAPH3D_MAX_NODES 300 + Aggregatknoten halten den Graphen klein");
    assert.ok(record.graphDataSets[0].nodes.some((n) => n.id === "__aggregate__"), "Aggregatknoten für die gebündelten Knoten vorhanden");
    // Nachprüfung: genau DENY_RECHECK_MAX Aufrufe, deterministische Reihenfolge
    // (höchste Drops-Summe zuerst).
    assert.equal(denyCalls.length, DENY_RECHECK_MAX, "Nachprüfung auf DENY_RECHECK_MAX gedeckelt");
    assert.equal(denyCalls[0], bigNodes[0].id, "höchste Drops-Summe zuerst (Determinismus der Auswahl)");
    assert.ok(!denyCalls.includes(bigNodes[bigN - 1].id), "Adressen jenseits der Kappe werden nicht nachgeprüft (synches Gate + Anzeige-Maske greifen weiterhin)");
    // Layout/Schutz unter dem Deckel unverändert: Collide aktiv, Warmup bei Erstrender.
    assert.equal(typeof record.d3ForceSet.collide, "function", "Collide-Kraft bleibt aktiv (3D-Knoten sind ohnehin gedeckelt)");
    assert.equal(record.warmupTicksCalls[0], 120, "Warmup-Deckel 120 bei Erstrender (N=301 nach Kappe)");
    for (const n of record.graphDataSets[0].nodes) {
      assert.ok(Number.isFinite(n.x) && Number.isFinite(n.y) && Number.isFinite(n.z), "deterministische Seed-Koordinaten auch im Riesen-Cluster");
    }
  } finally {
    documentStub.createElement = prevCreateElement;
    if (prevForceGraph3D === undefined) delete windowStub.ForceGraph3D; else windowStub.ForceGraph3D = prevForceGraph3D;
    liveGraph = makeGraph();
  }
});

/* ---------------- 11) 3D-Stil (Design P3, 2026-10-06) ----------------
   Kanten-Staffelung nach Typ, Drainer-Ring-Auswahl (deterministisch, Deckel
   12), build3D-Stil-Flags (transparenter Clear, linkOpacity, additiver
   Extend, Hover-API), Hover-Fokus mit reduced-motion-Degradation und die
   Ring-Konstruktion aus rekonstruierten Bundle-Klassen — alles ohne
   Browser/WebGL am Fake. Layout-Parameter (Entstapelung, Kollision) bleiben
   unangetastet: Die Stil-Flags dürfen keine Overlap-Regression verursachen
   (Abschnitt 10 bleibt der Regressionsschutz). */

test("Kanten-Staffelung: cluster3dLinkWidth deterministisch nach XRPL-Typ", () => {
  assert.equal(cluster3dLinkWidth("Payment"), 1.4, "Payment trägt den Geldfluss (breiteste Kante)");
  assert.equal(cluster3dLinkWidth("EscrowCreate"), 1, "Escrow strukturiert");
  assert.equal(cluster3dLinkWidth("EscrowFinish"), 1);
  assert.equal(cluster3dLinkWidth("EscrowCancel"), 1);
  assert.equal(cluster3dLinkWidth("CheckCreate"), 1, "Check strukturiert");
  assert.equal(cluster3dLinkWidth("CheckCash"), 1);
  assert.equal(cluster3dLinkWidth("NFTokenMint"), 1, "NFT strukturiert");
  assert.equal(cluster3dLinkWidth("NFTokenAcceptOffer"), 1);
  assert.equal(cluster3dLinkWidth("TrustSet"), 0.8, "Rest tritt zurück");
  assert.equal(cluster3dLinkWidth("OfferCreate"), 0.8);
  assert.equal(cluster3dLinkWidth("OfferCancel"), 0.8);
  assert.equal(cluster3dLinkWidth("AccountSet"), 0.8);
  assert.equal(cluster3dLinkWidth("PaymentChannelCreate"), 0.8);
  assert.equal(cluster3dLinkWidth(""), 0.8, "leerer Typ -> Rest");
  assert.equal(cluster3dLinkWidth(undefined), 0.8);
  assert.equal(cluster3dLinkWidth(null), 0.8);
});

test("Drainer-Ring-Auswahl: deterministisch, Deckel 12, Rollen-Gate, Aggregat ausgeschlossen", () => {
  assert.equal(GRAPH3D_RING_CAP, 12, "Halo-Deckel 12 (Performance-Schlüssel)");
  const mk = (id, role, drops) => ({ id, role, inDrops: drops, outDrops: 0 });
  // 20 Drainer mit absteigenden Drops-Summen -> genau die Top-12.
  const drain = Array.from({ length: 20 }, (_, i) => mk("rTESTd" + String(i).padStart(2, "0"), "drainer", 1000 - i));
  const sel = selectDrainerRingNodes(drain);
  assert.equal(sel.size, 12, "Auswahl auf Deckel 12 gekappt");
  assert.ok(sel.has("rTESTd00") && sel.has("rTESTd11"), "Top-12 nach Drops-Summe");
  assert.ok(!sel.has("rTESTd12") && !sel.has("rTESTd19"), "ab Rank 13 kein Ring");
  // Gleichstand: identische Drops -> Adresse asc entscheidet (Determinismus).
  const tie = Array.from({ length: 15 }, (_, i) => mk("rTESTt" + String(i).padStart(2, "0"), "drainer", 500));
  const selTie = selectDrainerRingNodes(tie);
  assert.equal(selTie.size, 12);
  assert.ok(selTie.has("rTESTt00") && selTie.has("rTESTt11") && !selTie.has("rTESTt12"), "Gleichstand bricht Adresse asc auf");
  // Nicht-Drainer bleiben draußen — auch bei riesigen Drops — und der
  // Aggregatknoten (role 'unknown') bekommt nie einen Ring.
  const mixed = [
    mk("rTESTbigSource", "source", 1e9),
    mk("rTESTdr", "drainer", 1),
    { id: "__aggregate__", role: "unknown", inDrops: 1e12, outDrops: 0, aggregateCount: 46000 },
  ];
  const selM = selectDrainerRingNodes(mixed);
  assert.equal(selM.size, 1);
  assert.ok(selM.has("rTESTdr"), "nur der Drainer");
  // Zwei Läufe über flache Kopien: identisches Ergebnis (kein Random).
  assert.deepEqual(
    [...selectDrainerRingNodes(drain)].sort(),
    [...selectDrainerRingNodes(drain.map((n) => ({ ...n })))].sort(),
  );
  assert.equal(selectDrainerRingNodes([]).size, 0, "leere Eingabe -> leere Auswahl");
});

test("build3D-Stil-Flags: transparenter Clear, linkOpacity 0.85, additiver Extend, Hover-API, Layout unverändert", async () => {
  lang = "de";
  liveGraph = makeGraph("Stil-Cluster", 5);
  const record = makeRecord();
  const prevCreateElement = documentStub.createElement;
  const prevForceGraph3D = windowStub.ForceGraph3D;
  try {
    documentStub.createElement = (tag) => (tag === "canvas" ? { getContext: () => ({ fake: true }) } : makeEl(tag));
    windowStub.ForceGraph3D = () => () => makeFakeFg3d(record);
    const dd = initClusterDrilldown(makeCtx());
    dd.openCluster(CID);
    await settle();

    // Hintergrund: transparenter Clear statt Vollweiß (Design P3.1, am
    // gepinnten Bundle Browser-verifiziert) — das CSS-Punkt-Substrat der
    // Bühne (drilldown.css) scheint dadurch.
    assert.equal(record.backgroundColor, "rgba(0,0,0,0)", "backgroundColor transparent statt '#ffffff'");
    // Kanten: Grunddeckkraft 0.85 (Bundle-Default wäre 0.2).
    assert.equal(record.linkOpacity, GRAPH3D_LINK_OPACITY);
    assert.equal(GRAPH3D_LINK_OPACITY, 0.85);
    // Ring: ADDITIV über nodeThreeObjectExtend (Plan-Kritik 8) — die
    // Default-Sphären inkl. nodeVal/nodeRelSize-Skalierung bleiben Bundle-
    // Sache, kein manueller Nachbau.
    assert.equal(record.nodeThreeObjectExtend, true, "nodeThreeObjectExtend(true) gesetzt");
    assert.equal(record.nodeThreeObjectFns.length, 1, "Ring-Accessor je build3D gesetzt");
    assert.equal(typeof record.onNodeHover, "function", "onNodeHover im Init-Block registriert");
    // Accessor ohne rekonstruierte Klassen (Szene leer) -> null, kein Crash
    // (der Retry-Rahmen setzt im Browser nach; ohne rAF bleibt es ehrlich
    // ohne Ring und ohne Legende).
    assert.equal(record.nodeThreeObjectFns[0]({ id: "rTESTdr", role: "drainer", inDrops: 1, outDrops: 1 }), null);
    // Kantenbreite: Typ-Staffelung über den Accessor verdrahtet (der Fake
    // recordet die bereits ausgewertete innere Funktion).
    const widthFn = record.linkWidthFns[record.linkWidthFns.length - 1];
    assert.equal(typeof widthFn, "function", "linkWidth-Accessor gesetzt");
    assert.equal(widthFn({ type: "Payment" }), 1.4);
    assert.equal(widthFn({ type: "EscrowFinish" }), 1);
    assert.equal(widthFn({ type: "TrustSet" }), 0.8);
    // Layout-Parameter von den Stil-Flags unberührt (keine Overlap-
    // Regression): Collide-Kraft, Warmup-Deckel und Radien-Skalierung
    // bleiben wie in Abschnitt 10 verdrahtet.
    assert.equal(typeof record.d3ForceSet.collide, "function", "Collide-Kraft bleibt gesetzt");
    assert.equal(record.warmupTicksCalls[0], 30, "Warmup unverändert (N=3 -> Untergrenze 30)");
    const k3 = Math.cbrt(3);
    assert.deepEqual(record.nodeRelSizeCalls, [Math.max(1.2, 4 / k3)], "nodeRelSize-Formel unverändert");
  } finally {
    documentStub.createElement = prevCreateElement;
    if (prevForceGraph3D === undefined) delete windowStub.ForceGraph3D; else windowStub.ForceGraph3D = prevForceGraph3D;
    liveGraph = makeGraph();
  }
});

test("Hover-Fokus: beteiligte Kanten volle Farbe ×1.5, übrige ausgegraut; Highlight über displayAddr; Reset bei Hover-Ende", async () => {
  lang = "de";
  liveGraph = makeGraph("Hover-Cluster", 5);
  const record = makeRecord();
  const prevCreateElement = documentStub.createElement;
  const prevForceGraph3D = windowStub.ForceGraph3D;
  try {
    documentStub.createElement = (tag) => (tag === "canvas" ? { getContext: () => ({ fake: true }) } : makeEl(tag));
    windowStub.ForceGraph3D = () => () => makeFakeFg3d(record);
    const dd = initClusterDrilldown(makeCtx());
    dd.openCluster(CID);
    await settle();

    const linkInvolved = { source: { id: A1 }, target: { id: A2 }, type: "payment" };
    const linkOther = { source: { id: A2 }, target: { id: A3 }, type: "payment" };

    // Grundzustand (kein Hover): volle Typfarbe — edgeColors-Stub ist leer,
    // also edgeDefault '#999'. Der Fake recordet die bereits ausgewertete
    // innere Funktion (fg3d.linkColor(linkColor3dAccessor())).
    const color0 = record.linkColorFns[record.linkColorFns.length - 1];
    assert.equal(color0(linkOther), "#999", "ohne Hover volle Typfarbe (edgeDefault)");

    // Hover auf A1: EIN Setter-Je-Wechsel für Farbe und Breite.
    const colorsBefore = record.linkColorFns.length;
    const widthsBefore = record.linkWidthFns.length;
    // Der Handler wurde im Init-Block registriert (build3D-Instanz-Aufbau).
    const hover = record.onNodeHover;
    assert.equal(typeof hover, "function", "onNodeHover-Handler registriert");
    hover({ id: A1 });
    assert.equal(record.linkColorFns.length, colorsBefore + 1, "ein linkColor-Setter je Hover-Wechsel");
    assert.equal(record.linkWidthFns.length, widthsBefore + 1, "ein linkWidth-Setter je Hover-Wechsel");
    const colorFn = record.linkColorFns[record.linkColorFns.length - 1];
    assert.equal(colorFn(linkInvolved), "#999", "beteiligte Kante behält die Typfarbe");
    assert.equal(colorFn(linkOther), GRAPH3D_LINK_FADED, "unbeteiligte Kante ausgegraut");
    const widthFn = record.linkWidthFns[record.linkWidthFns.length - 1];
    // Fixture-Typ ist kleingeschrieben ('payment') -> Staffel-Zweig 'Rest'
    // 0.8; die ×1.5-Fokussierung wirkt darauf genauso (Groß-/Kleinschreibung
    // prüft der Stil-Flags-Test mit den echten EDGE_COLORS-Typen).
    assert.ok(Math.abs(widthFn(linkInvolved) - 0.8 * 1.5) < 1e-9, "beteiligte Kante ×1.5");
    assert.equal(widthFn(linkOther), 0.8, "unbeteiligte Kante Basisbreite");
    // Knoten-Highlight über das highlightSet-Muster (displayAddr-Vergleich).
    const nodeFn = record.nodeColorFns[record.nodeColorFns.length - 1];
    assert.equal(nodeFn({ id: A1, role: "source" }), "#222", "gehoverter Knoten im Highlight-Ton");
    assert.equal(nodeFn({ id: A3, role: "sink" }), "#555", "anderer Knoten im Basis-Ton");

    // Hover-Ende: Farbe/Breite zurück auf Basis.
    hover(null);
    const colorEnd = record.linkColorFns[record.linkColorFns.length - 1];
    assert.equal(colorEnd(linkOther), "#999", "nach Hover-Ende wieder volle Typfarbe");
    assert.equal(colorEnd(linkInvolved), "#999");
    const nodeEnd = record.nodeColorFns[record.nodeColorFns.length - 1];
    assert.equal(nodeEnd({ id: A1, role: "source" }), "#111", "Highlight nach Hover-Ende entfernt");
  } finally {
    documentStub.createElement = prevCreateElement;
    if (prevForceGraph3D === undefined) delete windowStub.ForceGraph3D; else windowStub.ForceGraph3D = prevForceGraph3D;
    liveGraph = makeGraph();
  }
});

test("Hover-Fokus-Degradation: prefers-reduced-motion lässt Farb-/Breiten-Setter aus", async () => {
  lang = "de";
  liveGraph = makeGraph("Reduced-Cluster", 5);
  const record = makeRecord();
  const prevCreateElement = documentStub.createElement;
  const prevForceGraph3D = windowStub.ForceGraph3D;
  const prevMatchMedia = windowStub.matchMedia;
  try {
    documentStub.createElement = (tag) => (tag === "canvas" ? { getContext: () => ({ fake: true }) } : makeEl(tag));
    windowStub.ForceGraph3D = () => () => makeFakeFg3d(record);
    windowStub.matchMedia = () => ({ matches: true }); // reduzierte Bewegung
    const dd = initClusterDrilldown(makeCtx());
    dd.openCluster(CID);
    await settle();
    const colorsBefore = record.linkColorFns.length;
    const widthsBefore = record.linkWidthFns.length;
    const nodesBefore = record.nodeColorFns.length;
    record.onNodeHover({ id: A1 });
    assert.equal(record.linkColorFns.length, colorsBefore, "kein Farb-Fokus unter reduced motion");
    assert.equal(record.linkWidthFns.length, widthsBefore, "kein Breiten-Fokus unter reduced motion");
    assert.equal(record.nodeColorFns.length, nodesBefore, "kein Knoten-Recolor unter reduced motion");
  } finally {
    documentStub.createElement = prevCreateElement;
    if (prevForceGraph3D === undefined) delete windowStub.ForceGraph3D; else windowStub.ForceGraph3D = prevForceGraph3D;
    windowStub.matchMedia = prevMatchMedia;
    liveGraph = makeGraph();
  }
});

test("Drainer-Ring: Klassen-Recovery aus der Szene, Einheits-Band auf 1.45×Radius, opak ohne Emissive", async () => {
  lang = "de";
  // Eigener Graph mit Drainer-Rolle (makeGraph nutzt source/mid/sink) und
  // roleColors mit drainer-Eintrag wie app.js ROLE_COLORS (#b3261e =
  // --a6-role-drainer = --a6-sev-malicious).
  const A1 = "rTESTdrainerAccount1111111";
  const rcid = "cluster:" + A1;
  liveGraph = {
    clusters: [{
      id: rcid, label: "Ring-Cluster", totalDrops: 1000, txCount: 2, distinctAccounts: 3,
      firstSeen: "2026-10-05T10:00:00Z", lastSeen: "2026-10-05T10:05:00Z",
      memberAddresses: [A1, A2, A3],
    }],
    nodes: [
      { id: A1, clusterId: rcid, role: "drainer", inDrops: 0, outDrops: 1e9, degreeIn: 0, degreeOut: 2, severity: "malicious" },
      { id: A2, clusterId: rcid, role: "source", inDrops: 1e6, outDrops: 0, degreeIn: 0, degreeOut: 1, severity: "info" },
      { id: A3, clusterId: rcid, role: "collector", inDrops: 1e6, outDrops: 0, degreeIn: 1, degreeOut: 0, severity: "info" },
    ],
    edges: [
      { from: A2, to: A1, type: "Payment", txHash: "RH1", closeTime: 1 },
      { from: A1, to: A3, type: "Payment", txHash: "RH2", closeTime: 2 },
    ],
  };
  // Fake-Bundle-Klassen: der Scene-Stub liefert ein Default-Knoten-Mesh
  // (Konstruktoren = die 'Klassen', genau wie die Recovery im Browser).
  class FakeMeshCls {
    constructor(g, m) { this.geometry = g; this.material = m; this.scale = { setScalar(v) { FakeMeshCls.lastScale = v; } }; }
  }
  class FakeSphereGeometryCls { constructor(...a) { FakeSphereGeometryCls.lastArgs = a; } }
  class FakeLambertCls { constructor(o) { FakeLambertCls.lastOpts = o; } }
  const record = makeRecord();
  const prevCreateElement = documentStub.createElement;
  const prevForceGraph3D = windowStub.ForceGraph3D;
  try {
    documentStub.createElement = (tag) => (tag === "canvas" ? { getContext: () => ({ fake: true }) } : makeEl(tag));
    windowStub.ForceGraph3D = () => () => makeFakeFg3d(record);
    const protoMesh = new FakeMeshCls(new FakeSphereGeometryCls(), new FakeLambertCls({}));
    protoMesh.geometry.type = "SphereGeometry";
    protoMesh.__graphObjType = "node";
    record.sceneNodes = [protoMesh];

    const ctx = makeCtx();
    ctx.roleColors = {
      ...ctx.roleColors,
      drainer: { background: "#b3261e", border: "#7f1d1d", highlight: { background: "#d03b33" } },
    };
    const dd = initClusterDrilldown(ctx);
    dd.openCluster(rcid);
    await settle();

    assert.equal(record.nodeThreeObjectFns.length, 1, "Ring-Accessor gesetzt");
    const acc = record.nodeThreeObjectFns[0];
    // Drainer: Ring-Mesh aus den rekonstruierten Klassen, skaliert auf das
    // 1.45-Fache des Bundle-Radius (cbrt(val)·nodeRelSize, N=3).
    const mesh = acc({ id: A1, role: "drainer", inDrops: 0, outDrops: 1e9, aggregateCount: 0 });
    assert.ok(mesh instanceof FakeMeshCls, "Ring-Mesh aus der Mesh-Klasse des Bundles");
    const layout = cluster3dLayoutParams([
      { id: A1, inDrops: 0, outDrops: 1e9 },
      { id: "x", inDrops: 0, outDrops: 0 },
      { id: "y", inDrops: 0, outDrops: 0 },
    ]);
    assert.ok(
      Math.abs(FakeMeshCls.lastScale - 1.45 * layout.radiusOf({ inDrops: 0, outDrops: 1e9 })) < 1e-9,
      "Ring-Skala = 1.45 · Knotenradius (Bundle-Radiusformel)",
    );
    // Einheits-Band: eine Geometrie für alle Ringe (Radius 1, äquatorialer
    // Ausschnitt), Material opak OHNE Emissive (Plan-Kritik 7b).
    assert.deepEqual(
      FakeSphereGeometryCls.lastArgs,
      [1, 24, 1, 0, Math.PI * 2, 0.46 * Math.PI, 0.08 * Math.PI],
      "Einheits-Kugelgürtel-Geometrie",
    );
    assert.deepEqual(
      FakeLambertCls.lastOpts,
      { color: "#b3261e", transparent: true, opacity: 0.9, side: 2 },
      "Lambert-Material: Rollen-/Severity-Rot, opak 0.9, DoubleSide",
    );
    assert.ok(!("emissive" in FakeLambertCls.lastOpts), "kein Emissive (lab_graphite: kein Glow)");
    // Nicht-Drainer und Aggregatknoten: null — kein Extra-Mesh.
    assert.equal(acc({ id: A2, role: "source", inDrops: 1e6, outDrops: 0, aggregateCount: 0 }), null, "Quelle ohne Ring");
    assert.equal(acc({ id: "__aggregate__", role: "unknown", inDrops: 1e12, outDrops: 0, aggregateCount: 100 }), null, "Aggregatknoten ohne Ring");
  } finally {
    documentStub.createElement = prevCreateElement;
    if (prevForceGraph3D === undefined) delete windowStub.ForceGraph3D; else windowStub.ForceGraph3D = prevForceGraph3D;
    liveGraph = makeGraph();
  }
});
