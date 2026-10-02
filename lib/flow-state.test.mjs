// lib/flow-state.test.mjs — node:test-Unit-Tests für die Flow-State-Persistenz.
// KOMPLETT OFFLINE: nur In-Memory-Fixtures für Merge/Serialisierung, keine
// Netzwerk-Calls. Ausführen: node --test lib/flow-state.test.mjs
import test from "node:test";
import assert from "node:assert/strict";
import {
  FLOW_STATE_FILE_PATH,
  FLOW_STATE_RETENTION_MS,
  FLOW_STATE_MAX_CLUSTERS,
  emptyFlowStateDoc,
  freshFlowState,
  normalizeFlowStateDoc,
  serializeFlowState,
  parseFlowStateText,
  mergeFlowState,
  pruneFlowState,
  projectFlowStateView,
} from "./flow-state.mjs";

// ---------- Fixtures (In-Memory, KEIN Netzwerk) ----------
// Der Advance-Pfad kennt nur Dokumente; die Fixtures bilden die drei Ebenen
// (State, Dokument, advance()-Ergebnis) synthetisch ab — keine echten
// Adressen, keine Köder, keine fetch-Calls.
const NOW = 1700000000000; // feste Zeitbasis für deterministische updatedAt-Prüfungen

function fixtureState(over = {}) {
  return {
    clusters: { c1: { totalDrops: 1000, txCount: 3 } },
    blocksProcessedTotal: 47,
    lastAdvancedAt: 1699999999000,
    ...over,
  };
}

function fixtureDoc(over = {}) {
  return {
    cursor: 100,
    state: fixtureState(),
    updatedAt: 1699999999000,
    ...over,
  };
}

// advance()-Ergebnis (lib/ledger-walk.mjs-Vertrag: {newCursor, summary, flowState}).
function fixtureAdvance(over = {}) {
  return {
    newCursor: 105,
    summary: { blocksProcessed: 5, findings: 2 },
    flowState: fixtureState(),
    ...over,
  };
}

// ---------- Tests: Normalisierung + leeres Dokument ----------

test("freshFlowState: exakt die ledger-walk-Nullform", () => {
  assert.deepEqual(freshFlowState(), {
    clusters: {},
    blocksProcessedTotal: 0,
    lastAdvancedAt: null,
  });
});

test("emptyFlowStateDoc: Cursor 0, frischer State, updatedAt null", () => {
  const doc = emptyFlowStateDoc();
  assert.equal(doc.cursor, 0);
  assert.equal(doc.updatedAt, null);
  assert.deepEqual(doc.state, freshFlowState());
});

test("normalizeFlowStateDoc: null/fremd/Array -> leeres Dokument", () => {
  assert.deepEqual(normalizeFlowStateDoc(null), emptyFlowStateDoc());
  assert.deepEqual(normalizeFlowStateDoc(undefined), emptyFlowStateDoc());
  assert.deepEqual(normalizeFlowStateDoc("text"), emptyFlowStateDoc());
  assert.deepEqual(normalizeFlowStateDoc([1, 2]), emptyFlowStateDoc());
});

test("normalizeFlowStateDoc: cursor/updatedAt zu Zahlen, State durchgereicht", () => {
  const state = fixtureState();
  const doc = normalizeFlowStateDoc({
    cursor: "105",
    updatedAt: "1699999999000",
    state,
  });
  assert.equal(doc.cursor, 105);
  assert.equal(doc.updatedAt, 1699999999000);
  assert.equal(doc.state, state); // Referenz-Durchreichung, keine Kopie
  const bad = normalizeFlowStateDoc({ cursor: "x", updatedAt: "y", state });
  assert.equal(bad.cursor, 0); // nicht-finite -> Default
  assert.equal(bad.updatedAt, null);
  assert.deepEqual(normalizeFlowStateDoc({ cursor: 1 }).state, freshFlowState());
  assert.deepEqual(normalizeFlowStateDoc({ cursor: 1, state: [1] }).state, freshFlowState());
});

test("serialize/parse: Roundtrip konvergiert auf die kanonische Form", () => {
  const doc = fixtureDoc();
  const text = serializeFlowState(doc);
  assert.ok(text.startsWith("{")); // Dokument-Objekt, KEIN History-Array
  assert.ok(!text.startsWith("["));
  assert.deepEqual(parseFlowStateText(text), doc);
});

test("parseFlowStateText: Korruption wirft (kein Überschreiben)", () => {
  assert.throws(() => parseFlowStateText("### kein JSON ###"), /nicht parsebar/);
  assert.throws(() => parseFlowStateText("[1,2,3]"), /unerwartetes Format/);
  assert.throws(() => parseFlowStateText("42"), /unerwartetes Format/);
  assert.throws(() => parseFlowStateText("null"), /unerwartetes Format/);
  assert.throws(() => parseFlowStateText('"text"'), /unerwartetes Format/);
});

// ---------- Tests: Merge (Dokument-Ebene) ----------

test("mergeFlowState: Cursor rückt auf newCursor, State wird verpackt", () => {
  const out = mergeFlowState(fixtureDoc(), fixtureAdvance(), NOW);
  assert.equal(out.cursor, 105); // von newCursor, NICHT existing.cursor
  assert.equal(out.updatedAt, NOW);
  assert.equal(out.state.blocksProcessedTotal, 47);
  assert.deepEqual(out.state.clusters, { c1: { totalDrops: 1000, txCount: 3 } });
});

test("mergeFlowState: fehlender advanceResult/flowState erhält den Bestand", () => {
  const existing = fixtureDoc();
  const kept = existing.state;
  const out = mergeFlowState(existing, undefined, NOW);
  assert.equal(out.cursor, 100); // existing.cursor erhalten
  assert.equal(out.state, kept); // Referenz erhalten
  assert.equal(out.updatedAt, NOW);
  const out2 = mergeFlowState(existing, { newCursor: 110 }, NOW);
  assert.equal(out2.cursor, 110); // Cursor rückt trotzdem
  assert.equal(out2.state, kept); // State aus existing
});

test("mergeFlowState: ungültiges now -> updatedAt null, Cursor bleibt gültig", () => {
  const out = mergeFlowState(fixtureDoc(), fixtureAdvance(), "nicht-zahl");
  assert.equal(out.updatedAt, null);
  assert.equal(out.cursor, 105);
});

test("FLOW_STATE_FILE_PATH: eigener Pfad im Daten-Repo", () => {
  assert.equal(FLOW_STATE_FILE_PATH, "data/flow-state.json");
});

// ---------- Tests: View-Projektion (renderbare Cluster-View) ----------
// Die Projektion normalisiert das Dokument auf die Cluster-View-Form
// (Rollen/Volumen/first-lastSeen + Cursor + updatedAt). Komplett offline:
// synthetische Fixtures, keine echten Adressen, keine fetch-Calls.

function fixtureViewDoc() {
  return {
    cursor: 250,
    updatedAt: 1699999999000,
    state: {
      clusters: {
        "cluster:rAAA": {
          id: "cluster:rAAA",
          totalDrops: 500,
          txCount: 2,
          distinctAccounts: 3,
          firstSeen: "2023-11-14T22:00:00Z",
          lastSeen: "2023-11-15T01:00:00Z",
          memberAddresses: ["rAAA", "rBBB", "rCCC"],
          roles: { rAAA: "source", rBBB: "drainer", rCCC: "collector" },
          mainDrainers: [{ address: "rBBB", outDrops: 100 }],
          collectors: [{ address: "rCCC", inDrops: 100 }],
        },
        "cluster:rDDD": {
          id: "cluster:rDDD",
          totalDrops: 900,
          txCount: 1,
          distinctAccounts: 2,
          firstSeen: "2023-11-14T23:00:00Z",
          lastSeen: "2023-11-14T23:00:00Z",
          memberAddresses: ["rDDD", "rEEE"],
          roles: { rDDD: "drainer", rEEE: "fremd-rolle" },
        },
      },
      blocksProcessedTotal: 47,
      lastAdvancedAt: 1699999999000,
    },
  };
}

test("projectFlowStateView: leeres Dokument -> leere View", () => {
  assert.deepEqual(projectFlowStateView(emptyFlowStateDoc()), {
    cursor: 0,
    updatedAt: null,
    clusters: [],
  });
  assert.deepEqual(projectFlowStateView(null), {
    cursor: 0,
    updatedAt: null,
    clusters: [],
  });
});

test("projectFlowStateView: Sortierung nach Volumen desc, Labels nach Sortierung", () => {
  const view = projectFlowStateView(fixtureViewDoc());
  assert.equal(view.cursor, 250);
  assert.equal(view.updatedAt, 1699999999000);
  assert.equal(view.clusters.length, 2);
  // Höheres Volumen zuerst — unabhängig von der Einfügefolge.
  assert.equal(view.clusters[0].id, "cluster:rDDD");
  assert.equal(view.clusters[0].label, "Cluster A");
  assert.equal(view.clusters[1].id, "cluster:rAAA");
  assert.equal(view.clusters[1].label, "Cluster B");
});

test("projectFlowStateView: Rollen werden auf Zählungen gefaltet", () => {
  const view = projectFlowStateView(fixtureViewDoc());
  // Fremde Rollenwerte fallen nach 'unknown' (keine Durchreichung).
  assert.deepEqual(view.clusters[0].roles, { drainer: 1, unknown: 1 });
  assert.deepEqual(view.clusters[1].roles, { source: 1, drainer: 1, collector: 1 });
});

test("projectFlowStateView: Roh-Internals und Member-Listen werden nicht geliefert", () => {
  const view = projectFlowStateView(fixtureViewDoc());
  for (const c of view.clusters) {
    assert.ok(!("blocksProcessedTotal" in c));
    assert.ok(!("lastAdvancedAt" in c));
    assert.ok(!("memberAddresses" in c));
    assert.ok(!("mainDrainers" in c));
    assert.ok(!("collectors" in c));
  }
  assert.ok(!("blocksProcessedTotal" in view));
  assert.ok(!("lastAdvancedAt" in view));
  // Die View trägt exakt die renderbaren Felder (inkl. retained edges +
  // per-Adress-Rollen für die Flow-Graph-View).
  assert.deepEqual(Object.keys(view.clusters[0]).sort(), [
    "distinctAccounts",
    "edges",
    "firstSeen",
    "id",
    "label",
    "lastSeen",
    "roles",
    "rolesByAddress",
    "severityByAddress",
    "totalDrops",
    "txCount",
  ]);
});

test("projectFlowStateView: deterministisch gegenüber der Einfügefolge", () => {
  const doc = fixtureViewDoc();
  const keys = Object.keys(doc.state.clusters);
  const flipped = {
    ...doc,
    state: {
      ...doc.state,
      clusters: { [keys[1]]: doc.state.clusters[keys[1]], [keys[0]]: doc.state.clusters[keys[0]] },
    },
  };
  assert.deepEqual(projectFlowStateView(flipped), projectFlowStateView(doc));
});

test("projectFlowStateView: Label-Konvention deckt sich mit clusterLabel", () => {
  const clusters = {};
  for (let i = 0; i < 26; i += 1) {
    clusters[`c${i}`] = {
      totalDrops: 1000 - i,
      txCount: 1,
      memberAddresses: [`r${String(i).padStart(2, "0")}`],
    };
  }
  const view = projectFlowStateView({ cursor: 1, updatedAt: null, state: { clusters } });
  assert.equal(view.clusters[0].label, "Cluster A");
  assert.equal(view.clusters[25].label, "Cluster Z");
  // 27. Cluster -> 'Cluster AA' (Konvention lib/cluster.mjs)
  clusters.c26 = { totalDrops: 0, txCount: 0, memberAddresses: ["r26"] };
  const view2 = projectFlowStateView({ cursor: 1, updatedAt: null, state: { clusters } });
  assert.equal(view2.clusters[26].label, "Cluster AA");
});

test("projectFlowStateView: Coercion — nicht-numerische Werte fallen auf Defaults", () => {
  const view = projectFlowStateView({
    cursor: "x",
    updatedAt: "y",
    state: {
      clusters: {
        c1: { totalDrops: "viel", txCount: null, distinctAccounts: "3", firstSeen: 42, lastSeen: null },
      },
    },
  });
  assert.equal(view.cursor, 0);
  assert.equal(view.updatedAt, null);
  const c = view.clusters[0];
  assert.equal(c.totalDrops, 0);
  assert.equal(c.txCount, 0);
  assert.equal(c.distinctAccounts, 3);
  assert.equal(c.firstSeen, null); // keine String-Form -> null
  assert.equal(c.lastSeen, null);
  assert.equal(c.label, "Cluster A");
});

// ---------- Tests: View-Projektion — retained edges + per-Adress-Rollen ----------
// Die Flow-Graph-/Weltkugel-View (public/history-host.html) rendert den Flow
// aus den BEGRENZTEN Fluss-Kanten + Rollen, die der Walk-Core akkumuliert.
// Komplett offline: synthetische Fixtures, keine echten Adressen, keine
// fetch-Calls. Die Sortierung ist die Totalordnung von topKEdges/cmpEdge
// (Volumen desc, ledgerSeq asc, txHash asc, Endpunkte asc) — deterministisch.

// Fixture mit retained edges: bewusst UNSORTIERT + mit defensiven Fällen
// (null-Ende, Nicht-Kante, IOU-Null) — die Projektion muss deterministisch
// sortieren und Defektes verwerfen.
function fixtureEdgeDoc() {
  return {
    cursor: 300,
    updatedAt: 1699999999000,
    state: {
      clusters: {
        "cluster:rX": {
          id: "cluster:rX",
          totalDrops: 1000,
          txCount: 4,
          distinctAccounts: 3,
          firstSeen: "2023-11-14T22:00:00Z",
          lastSeen: "2023-11-15T01:00:00Z",
          memberAddresses: ["rX", "rY", "rZ"],
          roles: { rX: "source", rY: "drainer", rZ: "fremd-rolle" },
          edges: [
            { from: "rY", to: "rZ", type: "Payment", amountDrops: 500, txHash: "h2", ledgerSeq: 200, closeTime: "2023-11-14T23:00:00Z" },
            { from: "rX", to: "rY", type: "Payment", amountDrops: 900, txHash: "h1", ledgerSeq: 100, closeTime: "2023-11-14T22:00:00Z" },
            { from: "rZ", to: "rX", type: null, amountDrops: null, txHash: "h3", ledgerSeq: 300, closeTime: null },
            { from: "rX", to: "rZ", type: "Payment", amountDrops: 900, txHash: "h0", ledgerSeq: 50, closeTime: "2023-11-14T21:00:00Z" },
            { from: null, to: "rZ", type: "Payment", amountDrops: 700, txHash: "h4", ledgerSeq: 400, closeTime: null },
            { defekt: true },
          ],
        },
      },
      blocksProcessedTotal: 47,
      lastAdvancedAt: 1699999999000,
    },
  };
}

test("projectFlowStateView: retained edges werden sanitized + deterministisch sortiert", () => {
  const view = projectFlowStateView(fixtureEdgeDoc());
  const c = view.clusters[0];
  // Zwei defekte Kanten (null-Ende, Nicht-Kante) werden verworfen.
  assert.equal(c.edges.length, 4);
  // Volumen desc; Gleichstand (900) bricht chronologisch (ledgerSeq asc: 50 vor 100).
  assert.deepEqual(c.edges.map((e) => e.txHash), ["h0", "h1", "h2", "h3"]);
  assert.equal(c.edges[0].from, "rX");
  assert.equal(c.edges[0].to, "rZ");
  assert.equal(c.edges[0].amountDrops, 900);
  // IOU-Null bleibt null (zählt 0 für die Sortierung, sortiert zuletzt).
  assert.equal(c.edges[3].amountDrops, null);
  assert.equal(c.edges[3].txHash, "h3");
  // Der Kanten-Vertrag trägt exakt die renderbaren Felder.
  assert.deepEqual(Object.keys(c.edges[0]).sort(), [
    "amountDrops", "closeTime", "from", "ledgerSeq", "to", "txHash", "type",
  ]);
});

test("projectFlowStateView: edges sind deterministisch gegenüber der Einfügefolge", () => {
  const doc = fixtureEdgeDoc();
  const edges = doc.state.clusters["cluster:rX"].edges;
  const flipped = {
    ...doc,
    state: {
      ...doc.state,
      clusters: { "cluster:rX": { ...doc.state.clusters["cluster:rX"], edges: [...edges].reverse() } },
    },
  };
  assert.deepEqual(projectFlowStateView(flipped), projectFlowStateView(doc));
});

test("projectFlowStateView: per-Adress-Rollen werden geliefert (fremde Werte -> unknown)", () => {
  const view = projectFlowStateView(fixtureEdgeDoc());
  const c = view.clusters[0];
  assert.deepEqual(c.rolesByAddress, { rX: "source", rY: "drainer", rZ: "unknown" });
  // Die gefaltete Zählung bleibt im Feld `roles` (bestehender Vertrag).
  assert.deepEqual(c.roles, { source: 1, drainer: 1, unknown: 1 });
});

test("projectFlowStateView: fehlendes edges-Feld -> leere Liste, rolesByAddress aus roles", () => {
  const view = projectFlowStateView(fixtureViewDoc()); // Fixture ohne edges-Feld
  for (const c of view.clusters) assert.deepEqual(c.edges, []);
  const byId = Object.fromEntries(view.clusters.map((c) => [c.id, c]));
  assert.deepEqual(byId["cluster:rDDD"].rolesByAddress, { rDDD: "drainer", rEEE: "unknown" });
  assert.deepEqual(byId["cluster:rAAA"].rolesByAddress, { rAAA: "source", rBBB: "drainer", rCCC: "collector" });
});

// ---------- Tests: Retention-Pruning (7 Tage + Top-200) ----------
// DEFINIERTE SEMANTIK: lastSeen undefined/null -> BEHALTEN (nicht einordenbar,
// darf nicht still verschwinden — Fixture c1 ohne lastSeen bleibt grün);
// parsebare lastSeen älter als windowMs -> raus; danach Top-200 nach Volumen.

test("pruneFlowState: null/undefined-lastSeen bleibt, alte parsebare lastSeen fällt raus", () => {
  const NOW2 = Date.parse("2026-10-02T12:00:00Z");
  const state = {
    clusters: {
      fresh: { totalDrops: 10, txCount: 1, lastSeen: "2026-10-02T10:00:00Z" },
      old: { totalDrops: 20, txCount: 1, lastSeen: "2026-09-01T10:00:00Z" }, // > 7 d alt
      noStamp: { totalDrops: 30, txCount: 1 }, // lastSeen undefined -> BEHALTEN
      nullStamp: { totalDrops: 40, txCount: 1, lastSeen: null }, // null -> BEHALTEN
      badStamp: { totalDrops: 50, txCount: 1, lastSeen: "kein ISO" }, // nicht parsebar -> BEHALTEN
    },
    blocksProcessedTotal: 5,
    lastAdvancedAt: NOW2,
  };
  const out = pruneFlowState(state, NOW2);
  assert.deepEqual(Object.keys(out.clusters).sort(), ["badStamp", "fresh", "noStamp", "nullStamp"]);
  assert.ok(!("old" in out.clusters), "parsebar veralteter Cluster fällt raus");
  assert.equal(out.blocksProcessedTotal, 5, "State-Hülle bleibt erhalten");
});

test("pruneFlowState: Fenster-Grenze (7 d) und opts-Override", () => {
  const NOW2 = Date.parse("2026-10-02T12:00:00Z");
  const edge = new Date(NOW2 - FLOW_STATE_RETENTION_MS + 1000).toISOString(); // knapp innerhalb
  const justOut = new Date(NOW2 - FLOW_STATE_RETENTION_MS - 1000).toISOString(); // knapp außerhalb
  const state = {
    clusters: {
      in: { totalDrops: 1, lastSeen: edge },
      out: { totalDrops: 1, lastSeen: justOut },
    },
  };
  assert.deepEqual(Object.keys(pruneFlowState(state, NOW2).clusters), ["in"]);
  // opts.windowMs override: mit 1 d fällt auch 'in' raus.
  assert.deepEqual(Object.keys(pruneFlowState(state, NOW2, { windowMs: 24 * 3600 * 1000 }).clusters), []);
});

test("pruneFlowState: Top-K-Kappung nach Volumen (totalDrops desc, txCount desc, Key asc)", () => {
  const clusters = {};
  for (let i = 0; i < 10; i++) {
    clusters[`k${i}`] = { totalDrops: i * 100, txCount: 1 };
  }
  const out = pruneFlowState({ clusters }, 1, { maxClusters: 3 });
  assert.deepEqual(Object.keys(out.clusters), ["k9", "k8", "k7"]);
  // Default-Kappe 200: 250 Cluster -> 200 größte bleiben.
  const many = {};
  for (let i = 0; i < 250; i++) many[`m${i}`] = { totalDrops: i };
  const out2 = pruneFlowState({ clusters: many }, 1);
  assert.equal(Object.keys(out2.clusters).length, FLOW_STATE_MAX_CLUSTERS);
  assert.ok("m249" in out2.clusters && !("m0" in out2.clusters));
});

test("pruneFlowState: No-Op erhält die State-Referenz (Merge-Erhalt)", () => {
  const state = { clusters: { c1: { totalDrops: 1000, txCount: 3 } }, blocksProcessedTotal: 47, lastAdvancedAt: 1 };
  assert.equal(pruneFlowState(state, 2), state, "nichts entfernt -> dieselbe Referenz");
});

test("mergeFlowState: Pruning läuft im Merge (alter Cluster fällt, frischer bleibt)", () => {
  const NOW2 = Date.parse("2026-10-02T12:00:00Z");
  const doc = fixtureDoc({
    state: {
      clusters: {
        old: { totalDrops: 9999, txCount: 9, lastSeen: "2020-01-01T00:00:00Z" },
        fresh: { totalDrops: 1, txCount: 1, lastSeen: "2026-10-02T10:00:00Z" },
      },
      blocksProcessedTotal: 1,
      lastAdvancedAt: NOW2,
    },
  });
  const out = mergeFlowState(doc, fixtureAdvance({ flowState: doc.state }), NOW2);
  assert.ok(!("old" in out.state.clusters), "veralteter Cluster fällt beim Merge");
  assert.ok("fresh" in out.state.clusters);
});

// ---------- Tests: Bait-Filter der View-Projektion (B2) ----------
// Die Flow-Graph-View (public/history-host.html) rendert rolesByAddress/edges
// ohne weiteren Client-Deny — die Server-Projektion filtert Köder-Endpunkte
// STILL (kein Oracle). Fixtures: synthetische Köder-Adresse, baitLabels als
// explizite Übergabe (ENV bleibt im Test leer).

function fixtureBaitDoc(baitAddr) {
  return {
    cursor: 400,
    updatedAt: 1699999999000,
    state: {
      clusters: {
        "cluster:rX": {
          id: "cluster:rX",
          totalDrops: 1000,
          txCount: 3,
          distinctAccounts: 3,
          firstSeen: "2023-11-14T22:00:00Z",
          lastSeen: "2023-11-15T01:00:00Z",
          memberAddresses: ["rX", baitAddr, "rZ"],
          roles: { rX: "source", [baitAddr]: "drainer", rZ: "collector" },
          edges: [
            { from: "rX", to: baitAddr, type: "Payment", amountDrops: 900, txHash: "h1", ledgerSeq: 100, closeTime: null },
            { from: "rX", to: "rZ", type: "Payment", amountDrops: 500, txHash: "h2", ledgerSeq: 101, closeTime: null },
          ],
        },
      },
      blocksProcessedTotal: 1,
      lastAdvancedAt: 1699999999000,
    },
  };
}

test("projectFlowStateView: baitLabels filtert edges, rolesByAddress und memberAddresses still", () => {
  const BAIT = "rTESTBAIT00000000000000000001";
  const view = projectFlowStateView(fixtureBaitDoc(BAIT), new Map([[BAIT, "HP-1"]]));
  const c = view.clusters[0];
  // Edge mit Köder-Endpunkt fällt raus, saubere bleibt.
  assert.equal(c.edges.length, 1);
  assert.equal(c.edges[0].txHash, "h2");
  // rolesByAddress ohne Köder-Knoten.
  assert.deepEqual(c.rolesByAddress, { rX: "source", rZ: "collector" });
  // Die gefaltete Zählung bleibt unverändert (bestehender Vertrag).
  assert.deepEqual(c.roles, { source: 1, drainer: 1, collector: 1 });
  // Kein Köder-String in der gesamten ausgelieferten View.
  assert.ok(!JSON.stringify(view).includes(BAIT));
});

test("projectFlowStateView: ohne baitLabels/ENV bleibt die View ungefiltert (bestehender Vertrag)", () => {
  const BAIT = "rTESTBAIT00000000000000000001";
  const view = projectFlowStateView(fixtureBaitDoc(BAIT));
  assert.equal(view.clusters[0].edges.length, 2);
  assert.ok(BAIT in view.clusters[0].rolesByAddress);
});

test("projectFlowStateView: ENV BAIT_ADDRESSES wird gelesen (Muster api/ledger.js)", () => {
  const BAIT = "rTESTBAIT00000000000000000001";
  const prev = process.env.BAIT_ADDRESSES;
  process.env.BAIT_ADDRESSES = BAIT;
  try {
    const view = projectFlowStateView(fixtureBaitDoc(BAIT));
    assert.equal(view.clusters[0].edges.length, 1, "ENV-Filter greift ohne Übergabe");
    assert.ok(!JSON.stringify(view).includes(BAIT));
  } finally {
    if (prev === undefined) delete process.env.BAIT_ADDRESSES;
    else process.env.BAIT_ADDRESSES = prev;
  }
});
