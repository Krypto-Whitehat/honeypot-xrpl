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
// transit-Kante, Freeze-Export trägt toTag/transit additiv.

import test from "node:test";
import assert from "node:assert/strict";
import { initClusterDrilldown } from "./drilldown.js";
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
