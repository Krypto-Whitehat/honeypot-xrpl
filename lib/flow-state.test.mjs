// lib/flow-state.test.mjs — node:test-Unit-Tests für die Flow-State-Persistenz.
// KOMPLETT OFFLINE: nur In-Memory-Fixtures für Merge/Serialisierung, keine
// Netzwerk-Calls. Ausführen: node --test lib/flow-state.test.mjs
import test from "node:test";
import assert from "node:assert/strict";
// advance() wird für den END-TO-END-Nachweis der Registry-Retention importiert
// (Audit-Nachprüfung Grenze 4: entitySnapshot wurde bisher nur handgebaut
// getestet). Reiner In-Memory-Pfad, kein Netzwerk.
import { advance } from "./ledger-walk.mjs";
import {
  FLOW_STATE_FILE_PATH,
  FLOW_STATE_RETENTION_MS,
  FLOW_STATE_MAX_CLUSTERS,
  FLOW_ARCHIVE_DIR,
  ARCHIVE_MAX_EDGES,
  ARCHIVE_RETENTION_MALICIOUS_MS,
  ARCHIVE_RETENTION_REGISTRY_MS,
  emptyFlowStateDoc,
  freshFlowState,
  normalizeFlowStateDoc,
  serializeFlowState,
  parseFlowStateText,
  mergeFlowState,
  pruneFlowState,
  projectFlowStateView,
  hasFraudEvidence,
  archiveDayOf,
  archivePath,
  emptyArchiveDoc,
  serializeArchiveDoc,
  parseArchiveText,
  archiveFromFlowState,
  appendArchiveDoc,
  pruneArchiveDocs,
  replayArchive,
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
  // per-Adress-Rollen für die Flow-Graph-View + peelingChains — neue
  // View-Projektion des Peeling-Plans, Kritik 4).
  assert.deepEqual(Object.keys(view.clusters[0]).sort(), [
    "distinctAccounts",
    "edges",
    "firstSeen",
    "id",
    "label",
    "lastSeen",
    "peelingChains",
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

// =====================================================================
// Flow-Archiv (Grenze 2): Archiv vor dem Pruning, Retention, Replay.
// Komplett offline — keine Netzwerk-Calls.
// =====================================================================
const DAY_MS = 24 * 60 * 60 * 1000;

// ---------- A1) Archiv-Roundtrip + Korruption ----------
test("archiv: serialize/parse Roundtrip konvergiert; Korruption wirft", () => {
  const day = archiveDayOf(NOW);
  assert.equal(day, new Date(NOW).toISOString().slice(0, 10));
  assert.equal(archivePath(day), `${FLOW_ARCHIVE_DIR}/${day}.json`);
  assert.throws(() => archivePath("kein-tag"), /ungültiges Tages-Datum/);
  const doc = {
    ...emptyArchiveDoc(day),
    updatedAt: NOW,
    docs: [
      {
        clusterId: "cluster:rTESTARC100000000000000000001",
        memberAddresses: ["rTESTARC100000000000000000001", "rTESTARC200000000000000000002"],
        edges: [{ from: "rTESTARC100000000000000000001", to: "rTESTARC200000000000000000002", amountDrops: 1000, txHash: "h1", ledgerSeq: 500, closeTime: "2026-10-01T10:00:00Z" }],
        peelingChains: [],
        entitySnapshot: null,
        firstSeen: "2026-09-20T10:00:00Z",
        lastSeen: "2026-09-25T10:00:00Z",
        ledgerRange: { from: 500, to: 500 },
      },
    ],
  };
  const text = serializeArchiveDoc(doc);
  assert.ok(text.startsWith("{"));
  assert.deepEqual(parseArchiveText(text), doc);
  // Append: ClusterId-Dedup (Idempotenz bei Retry), deterministisch asc.
  const appended = appendArchiveDoc(appendArchiveDoc(emptyArchiveDoc(day), doc.docs), doc.docs);
  assert.equal(appended.docs.length, 1);
  assert.throws(() => parseArchiveText("### kein JSON ###"), /nicht parsebar/);
  assert.throws(() => parseArchiveText("[1,2]"), /unerwartetes Format/);
  assert.throws(() => parseArchiveText("42"), /unerwartetes Format/);
});

// ---------- A2) Archiv genau der Cluster, die pruneFlowState fallen ließe ----------
test("archiv: archiveFromFlowState archiviert genau die fallenden Betrugsevidenz-Cluster", () => {
  const old = new Date(NOW - 31 * DAY_MS).toISOString();
  const mid = new Date(NOW - 10 * DAY_MS).toISOString();
  const benignOld = new Date(NOW - 8 * DAY_MS).toISOString();
  const state = {
    clusters: {
      // Betrugsevidenz (drainer), 31 d alt -> pruneFlowState (30-d-Fenster)
      // lässt ihn fallen -> archiviert.
      cFall: {
        id: "cluster:cFall",
        roles: { rA: "drainer" },
        mainDrainers: [{ address: "rA", outDrops: 5000 }],
        memberAddresses: ["rA", "rB"],
        edges: [{ from: "rA", to: "rB", amountDrops: 5000, txHash: "h1", ledgerSeq: 900 }],
        peelingChains: [],
        firstSeen: old,
        lastSeen: old,
      },
      // Betrugsevidenz, 10 d alt -> bleibt (30-d-Fenster) -> nicht archiviert.
      cStay: {
        id: "cluster:cStay",
        roles: { rC: "collector" },
        memberAddresses: ["rC", "rD"],
        edges: [],
        peelingChains: [],
        firstSeen: mid,
        lastSeen: mid,
      },
      // Reiner Benign-Cluster, 8 d alt -> pruneFlowState (7 d) würde ihn
      // fallen lassen, aber reine Benign-Cluster werden NICHT archiviert.
      cBenign: {
        id: "cluster:cBenign",
        roles: { rE: "relay" },
        memberAddresses: ["rE", "rF"],
        edges: [],
        peelingChains: [],
        firstSeen: benignOld,
        lastSeen: benignOld,
      },
      // Peeling-Kette als Evidenzform, 31 d alt -> archiviert.
      cPeel: {
        id: "cluster:cPeel",
        roles: { rG: "relay" },
        memberAddresses: ["rG", "rH"],
        edges: [{ from: "rG", to: "rH", amountDrops: 8000, txHash: "h2", ledgerSeq: 800 }],
        peelingChains: [{ signature: "rG,rH", addresses: ["rG", "rH"], hops: [], seed: "rG", seedSeverity: "suspect", hopsCount: 1, bridges: [] }],
        firstSeen: old,
        lastSeen: old,
      },
    },
    blocksProcessedTotal: 1,
    lastAdvancedAt: NOW,
  };
  const docs = archiveFromFlowState(state, NOW);
  const ids = docs.map((d) => d.clusterId).sort();
  assert.deepEqual(ids, ["cluster:cFall", "cluster:cPeel"], "nur fallende Betrugsevidenz-Cluster");
  // Dasselbe Prädikat wie pruneFlowState: cFall/cPeel fallen dort wirklich.
  const pruned = pruneFlowState(state, NOW);
  assert.ok(!( "cFall" in pruned.clusters) && !("cPeel" in pruned.clusters), "pruneFlowState lässt genau diese fallen");
  assert.ok("cStay" in pruned.clusters, "cStay bleibt -> nicht archiviert");
  assert.ok(!("cBenign" in pruned.clusters), "cBenign fällt im Pruning");
  assert.equal(docs.length, 2, "aber nicht archiviert (reine Benign-Regel)");
  // Archiv-Zeile trägt den Vertrag.
  const fall = docs.find((d) => d.clusterId === "cluster:cFall");
  assert.deepEqual(fall.memberAddresses, ["rA", "rB"]);
  assert.deepEqual(fall.ledgerRange, { from: 900, to: 900 });
  assert.equal(fall.lastSeen, old);
});

// ---------- A3) replayArchive: rückwärts + truncated jenseits der Kappe ----------
test("archiv: replayArchive rekonstruiert rückwärts und meldet truncated jenseits ARCHIVE_MAX_EDGES", () => {
  assert.equal(ARCHIVE_MAX_EDGES, 200);
  // 8 Tage alte Auszahlungskette D<-C<-B<-A (Kanten A->B->C->D).
  const chainDoc = {
    day: archiveDayOf(NOW - 8 * DAY_MS),
    updatedAt: NOW,
    docs: [
      {
        clusterId: "cluster:chain",
        memberAddresses: ["rA", "rB", "rC", "rD"],
        edges: [
          { from: "rA", to: "rB", amountDrops: 10000, txHash: "h1", ledgerSeq: 1000 },
          { from: "rB", to: "rC", amountDrops: 8000, txHash: "h2", ledgerSeq: 1100 },
          { from: "rC", to: "rD", amountDrops: 6400, txHash: "h3", ledgerSeq: 1200 },
        ],
        peelingChains: [],
        entitySnapshot: null,
        firstSeen: null,
        lastSeen: null,
        ledgerRange: { from: 1000, to: 1200 },
      },
    ],
  };
  const r = replayArchive([chainDoc], { address: "rD" });
  assert.equal(r.truncated, false);
  assert.deepEqual(r.hops.map((h) => h.from), ["rC", "rB", "rA"], "rückwärts über Edges");
  assert.deepEqual(r.hops.map((h) => h.ledgerSeq), [1200, 1100, 1000]);
  // Zeitfenster: fromLedger/toLedger filtert Kanten.
  const win = replayArchive([chainDoc], { address: "rD", fromLedger: 1150, toLedger: 1250 });
  assert.equal(win.hops.length, 1, "nur die Kante im Fenster");
  // Long chain über die Kappe: 202 Kanten -> truncated=true.
  const longEdges = [];
  for (let i = 0; i < 202; i++) {
    longEdges.push({ from: `rX${String(i).padStart(3, "0")}`, to: `rX${String(i + 1).padStart(3, "0")}`, amountDrops: 1000, txHash: `L${i}`, ledgerSeq: 2000 + i });
  }
  const longDoc = {
    day: archiveDayOf(NOW),
    updatedAt: NOW,
    docs: [{ clusterId: "cluster:long", memberAddresses: [], edges: longEdges, peelingChains: [], entitySnapshot: null, firstSeen: null, lastSeen: null, ledgerRange: { from: 2000, to: 2201 } }],
  };
  const lr = replayArchive([longDoc], { address: "rX202" });
  assert.equal(lr.hops.length, ARCHIVE_MAX_EDGES, "Kappe 200");
  assert.equal(lr.truncated, true, "jenseits der Kappe: account_tx-Replay nötig");
});

// ---------- A4) pruneArchiveDocs: 30 d / 180 d Retention ----------
test("archiv: pruneArchiveDocs löscht nach 30 d (malicious) bzw. 180 d (registry) und behält jüngere", () => {
  assert.equal(ARCHIVE_RETENTION_MALICIOUS_MS, 30 * DAY_MS);
  assert.equal(ARCHIVE_RETENTION_REGISTRY_MS, 180 * DAY_MS);
  const mk = (day, lastSeen, registry = false) => ({
    day,
    doc: {
      day,
      updatedAt: NOW,
      docs: [
        {
          clusterId: `cluster:${day}`,
          memberAddresses: [],
          edges: [],
          peelingChains: [],
          entitySnapshot: registry ? { registryLinked: true } : null,
          firstSeen: null,
          lastSeen,
          ledgerRange: { from: null, to: null },
        },
      ],
    },
  });
  const dayOld = archiveDayOf(NOW - 31 * DAY_MS);
  const dayRegistryOld = archiveDayOf(NOW - 181 * DAY_MS);
  const dayRegistryMid = archiveDayOf(NOW - 100 * DAY_MS);
  const dayFresh = archiveDayOf(NOW - 5 * DAY_MS);
  const { docs, staleDays } = pruneArchiveDocs(
    [
      mk(dayOld, new Date(NOW - 31 * DAY_MS).toISOString()),
      mk(dayRegistryOld, new Date(NOW - 181 * DAY_MS).toISOString(), true),
      mk(dayRegistryMid, new Date(NOW - 100 * DAY_MS).toISOString(), true),
      mk(dayFresh, new Date(NOW - 5 * DAY_MS).toISOString()),
    ],
    NOW
  );
  assert.deepEqual(staleDays, [dayOld, dayRegistryOld].sort(), "31 d malicious + 181 d registry -> Tageslöschung");
  const kept = docs.map((d) => d.day).sort();
  assert.deepEqual(kept, [dayFresh, dayRegistryMid].sort(), "jüngere bleiben (100 d registry < 180 d)");
});

// ---------- A5) hasFraudEvidence greift für peelingChains ----------
test("archiv: hasFraudEvidence greift für peelingChains (exportiertes Prädikat)", () => {
  assert.equal(hasFraudEvidence({ peelingChains: [{ signature: "a,b" }] }), true);
  assert.equal(hasFraudEvidence({ peelingChains: [] }), false);
  assert.equal(hasFraudEvidence({ roles: { a: "drainer" } }), true);
  assert.equal(hasFraudEvidence({ roles: { a: "relay" }, mainDrainers: [], peelingChains: [] }), false);
});

// ---------- A6) View-Projektion: peelingChains deterministisch + ohne Köder ----------
test("archiv: projectFlowStateView liefert peelingChains deterministisch und ohne Köder-Endpunkte", () => {
  const BAIT = "rTESTBAIT00000000000000000001";
  const chainOk = {
    addresses: ["rX", "rM1", "rM2", "rY"],
    hops: [
      { from: "rX", to: "rM1", amountDrops: 10000, ratio: null, txHash: "h1", ledgerSeq: 10 },
      { from: "rM1", to: "rM2", amountDrops: 8000, ratio: 0.8, txHash: "h2", ledgerSeq: 11 },
      { from: "rM2", to: "rY", amountDrops: 6400, ratio: 0.8, txHash: "h3", ledgerSeq: 12 },
    ],
    seed: "rX",
    seedSeverity: "suspect",
    hopsCount: 3,
    bridges: ["rM1", "rM2"],
    signature: "rX,rM1,rM2,rY",
  };
  const chainBait = {
    addresses: ["rX", BAIT],
    hops: [{ from: "rX", to: BAIT, amountDrops: 5000, ratio: null, txHash: "h4", ledgerSeq: 20 }],
    seed: "rX",
    seedSeverity: "suspect",
    hopsCount: 1,
    bridges: [],
    signature: `rX,${BAIT}`,
  };
  const doc = {
    cursor: 1,
    state: {
      clusters: {
        k1: {
          id: "cluster:k1",
          roles: { rX: "source", rY: "collector" },
          severityByAddress: { rX: "suspect", rY: "malicious" },
          edges: [],
          peelingChains: [chainBait, chainOk],
          totalDrops: 100,
          txCount: 1,
          distinctAccounts: 2,
          firstSeen: null,
          lastSeen: null,
        },
      },
      blocksProcessedTotal: 0,
      lastAdvancedAt: null,
    },
    updatedAt: null,
  };
  const view = projectFlowStateView(doc, new Map([[BAIT, "HP-1"]]));
  const chains = view.clusters[0].peelingChains;
  assert.equal(chains.length, 1, "Köder-Kette fällt still raus");
  assert.ok(!JSON.stringify(view).includes(BAIT), "kein Köder in der View");
  assert.deepEqual(chains[0].addresses, ["rX", "rM1", "rM2", "rY"]);
  assert.deepEqual(chains[0].hops.map((h) => h.ledgerSeq), [10, 11, 12]);
  // Determinismus: Eingabereihenfolge der Ketten und Hops ist egal.
  const doc2 = JSON.parse(JSON.stringify(doc));
  doc2.state.clusters.k1.peelingChains = [chainOk, chainBait];
  doc2.state.clusters.k1.peelingChains[0].hops = [...chainOk.hops].reverse();
  const view2 = projectFlowStateView(doc2, new Map([[BAIT, "HP-1"]]));
  assert.deepEqual(view2.clusters[0].peelingChains, chains, "Ausgabe unabhängig von Eingabereihenfolge");
});

// ---------- A7) End-to-End: Produzent -> Archiv -> Registry-Retention ----------
// (Audit-Nachprüfung Grenze 4: die 180-Tage-Registry-Retention war toter Code,
// weil entitySnapshot nie produziert wurde.) Echter Pfad: advance() mit einem
// known-bad-hit-Finding (api/advance.js buildCtx speist knownBad aus der
// kuratierten Registry) -> Cluster trägt entitySnapshot { registryLinked: true }
// -> archiveFromFlowState übernimmt es in die Archiv-Zeile -> pruneArchiveDocs
// hält die registry-verknüpfte Zeile 180 d, während eine baugleiche ohne
// Verknüpfung nach 30 d fällt.
test("archiv: End-to-End advance()->Archiv->Retention — registryLinked wird produziert und wirkt", async () => {
  const oldIso = new Date(NOW - 31 * DAY_MS).toISOString();
  const S1 = "rTESTE2ES100000000000000000001";
  const S2 = "rTESTE2ES200000000000000000002";
  const S3 = "rTESTE2ES300000000000000000003";
  const B = "rTESTE2EB000000000000000000002";
  // Collector-Form (3 Eingänge, Akkumulation): Betrugsevidenz im Sinne von
  // hasFraudEvidence — der Cluster fällt nach 31 d aus dem 30-d-Fraud-Fenster.
  const blocks = [{
    transactions: [
      { hash: "E2E1", ledger_index: 500, TransactionType: "Payment", Account: S1, Destination: B, Amount: "5000", close_time_iso: oldIso },
      { hash: "E2E2", ledger_index: 501, TransactionType: "Payment", Account: S2, Destination: B, Amount: "5000", close_time_iso: oldIso },
      { hash: "E2E3", ledger_index: 502, TransactionType: "Payment", Account: S3, Destination: B, Amount: "5000", close_time_iso: oldIso },
    ],
    findings: [
      { ruleId: "known-bad-hit", severity: "malicious", address: B },
      { ruleId: "dusting", severity: "suspect", address: S1 },
      { ruleId: "dusting", severity: "suspect", address: S2 },
      { ruleId: "dusting", severity: "suspect", address: S3 },
    ],
  }];
  let i = 0;
  const res = await advance({
    cursor: 499, budget: 2, now: NOW,
    fetcher: async () => (i < blocks.length ? blocks[i++] : null),
    flowState: {},
  });
  const clusters = Object.values(res.flowState.clusters);
  assert.equal(clusters.length, 1, "ein Cluster aus dem echten advance()-Pfad");
  assert.ok(clusters[0].entitySnapshot && clusters[0].entitySnapshot.registryLinked === true,
    "Produzent: known-bad-hit setzt entitySnapshot im echten Pfad");
  // 31 d alt -> fällt aus dem 30-d-Fraud-Fenster -> Archivierung mit Feld.
  const docs = archiveFromFlowState(res.flowState, NOW);
  assert.equal(docs.length, 1, "fallender Betrugscluster wird archiviert");
  assert.ok(docs[0].entitySnapshot && docs[0].entitySnapshot.registryLinked === true,
    "Archiv-Zeile trägt die Registry-Verknüpfung");
  // Retention am echten Alter 100 d: verknüpfte Zeile überlebt (180 d),
  // baugleiche ohne Verknüpfung fällt (30 d) — derselbe Tag, beide Zeilen.
  const day = archiveDayOf(NOW - 100 * DAY_MS);
  const lastSeen100 = new Date(NOW - 100 * DAY_MS).toISOString();
  const mkRow = (snap) => ({ ...docs[0], clusterId: snap ? "cluster:linked" : "cluster:plain", entitySnapshot: snap, lastSeen: lastSeen100 });
  const { docs: kept, staleDays } = pruneArchiveDocs(
    [{ day, doc: { day, updatedAt: NOW, docs: [mkRow(docs[0].entitySnapshot), mkRow(null)] } }],
    NOW,
  );
  assert.deepEqual(staleDays, [], "Tag bleibt (eine Zeile überlebt)");
  assert.equal(kept.length, 1);
  assert.deepEqual(kept[0].doc.docs.map((d) => d.clusterId), ["cluster:linked"],
    "100 d: registryLinked bleibt (180 d), ohne Verknüpfung wäre sie nach 30 d stale");
  // Gegenprobe: nur die unverknüpfte Zeile am selben Tag -> Tageslöschung.
  const onlyPlain = pruneArchiveDocs(
    [{ day, doc: { day, updatedAt: NOW, docs: [mkRow(null)] } }],
    NOW,
  );
  assert.deepEqual(onlyPlain.staleDays, [day], "ohne Registry-Verknüpfung: 30-d-Fenster löscht den Tag");
});

// ---------- A8) Kappungs-Archivierung (Runde 3) ----------
// archiveFromFlowState deckt beide Verlustpfade von pruneFlowState ab:
// Zeitgrenze (A2) UND Top-200-Kappung. Ein volumenarmer Betrugsevidenz-
// Cluster, den die Kappung (Schwere vor Volumen) im selben Tick fallen lässt,
// wird archiviert; verdrängte reine Benign-Cluster bleiben außerhalb des
// Archivs; Cluster mit lastSeen == null werden von pruneFlowState behalten
// und nie archiviert.
test("archiv: Kappung verdrängter Betrugsevidenz-Cluster wird archiviert, verdrängte Benign-Cluster nicht", () => {
  assert.equal(FLOW_STATE_MAX_CLUSTERS, 200);
  const recent = new Date(NOW - 2 * DAY_MS).toISOString(); // fraud 30 d / benign 7 d: alle im Fenster
  const clusters = {};
  // 201 volumenreiche Drainer-Cluster (Betrugsevidenz, high totalDrops) —
  // zusammen mit f999 und fNull 203 Evidenz-Cluster: die Kappe 200 lässt
  // die drei volumenärmsten Evidenz-Cluster (f999, f199, f000) fallen.
  for (let i = 0; i < 201; i++) {
    const k = `f${String(i).padStart(3, "0")}`;
    clusters[k] = {
      id: `cluster:${k}`,
      roles: { [`r${k}`]: "drainer" },
      memberAddresses: [`r${k}`],
      edges: [],
      peelingChains: [],
      totalDrops: 10_000 + i,
      txCount: 1,
      firstSeen: recent,
      lastSeen: recent,
    };
  }
  // Der 201. Betrugsevidenz-Cluster: volumenarm -> hinter den 200 -> fällt
  // der Kappung zum Opfer (Schwere-Gruppe intern nach totalDrops desc).
  clusters.f999 = {
    id: "cluster:f999",
    roles: { r999: "drainer" },
    memberAddresses: ["r999", "r998"],
    edges: [{ from: "r999", to: "r998", amountDrops: 10, txHash: "h9", ledgerSeq: 700 }],
    peelingChains: [],
    totalDrops: 10,
    txCount: 1,
    firstSeen: recent,
    lastSeen: recent,
  };
  // Fünf volumenreiche reine Benign-Cluster (relay, kein mainDrainers/
  // peelingChains) -> ebenfalls verdrängt, aber NIE archiviert.
  for (let i = 0; i < 5; i++) {
    const k = `b${i}`;
    clusters[k] = {
      id: `cluster:${k}`,
      roles: { [`r${k}`]: "relay" },
      memberAddresses: [`r${k}`],
      edges: [],
      peelingChains: [],
      totalDrops: 50_000 + i,
      txCount: 1,
      firstSeen: recent,
      lastSeen: recent,
    };
  }
  // Betrugsevidenz mit lastSeen == null -> pruneFlowState behält (Zeitfilter
  // greift nicht; hohes Volumen hält sie zudem über der Kappung) -> trotz
  // Evidenz nie archiviert (lastSeen != null-Prädikat).
  clusters.fNull = {
    id: "cluster:fNull",
    roles: { rNull: "collector" },
    memberAddresses: ["rNull"],
    edges: [],
    peelingChains: [],
    totalDrops: 99_999,
    txCount: 1,
    firstSeen: null,
    lastSeen: null,
  };
  const state = { clusters, blocksProcessedTotal: 1, lastAdvancedAt: NOW };

  const docs = archiveFromFlowState(state, NOW);
  assert.deepEqual(docs.map((d) => d.clusterId), ["cluster:f001", "cluster:f000", "cluster:f999"],
    "genau die kappungs-verdrängten Betrugscluster (Schwere-Gruppen-Reihenfolge), kein Benign-Cluster");
  const row = docs.find((d) => d.clusterId === "cluster:f999");
  assert.deepEqual(row.memberAddresses, ["r998", "r999"]);
  assert.deepEqual(row.ledgerRange, { from: 700, to: 700 });
  assert.equal(row.lastSeen, recent);

  // Dasselbe Prädikat wie pruneFlowState: f999 und die Benign-Cluster fallen
  // dort wirklich; die 200 hochvolumigen Drainer und der null-Cluster bleiben.
  const pruned = pruneFlowState(state, NOW);
  assert.equal(Object.keys(pruned.clusters).length, FLOW_STATE_MAX_CLUSTERS);
  assert.ok(!("f999" in pruned.clusters), "f999 fällt der Kappung zum Opfer");
  assert.ok(!("b0" in pruned.clusters) && !("b4" in pruned.clusters), "Benign-Cluster fallen ebenfalls");
  assert.ok("f002" in pruned.clusters && "f200" in pruned.clusters, "199 Drainer überleben");
  assert.ok(!("f000" in pruned.clusters) && !("f001" in pruned.clusters),
    "die volumenärmsten Drainer (f000, f001) weichen — Kappe 200");
  assert.ok("f199" in pruned.clusters, "f199 (totalDrops 10199) überlebt");
  assert.ok("fNull" in pruned.clusters, "lastSeen null bleibt erhalten");
});
