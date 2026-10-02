// node:test für strideHashes (lib/stride.mjs). IN-MEMORY-Fixtures, KEIN
// Netzwerk, KEIN Dateizugriff. Prüft: Budget-Grenze, Gleichmäßigkeit (kein
// Blockanfang-Bias), Determinismus, Vollständigkeit bei budget >= length,
// Garbage-Inputs, Positions-Treue — und Kantenerhaltung über die reale
// Konsumenten-Kette txRecordFromEntry -> buildClusterGraph (lib/cluster.mjs).

import test from "node:test";
import assert from "node:assert/strict";
import { strideHashes } from "./stride.mjs";
import { txRecordFromEntry, buildClusterGraph } from "./cluster.mjs";

// Fixture: 84 Hash-Strings wie ein realer Block (55-84 Txs, Beobachtung
// 2026-10-02, Blöcke #107369720-#107369724).
const blockHashes = Array.from({ length: 84 }, (_, i) =>
  `H${String(i).padStart(3, "0")}`
);

test("Budget-Grenze: genau budget Elemente, Original-Reihenfolge, keine Duplikate", () => {
  const picked = strideHashes(blockHashes, 6);
  assert.equal(picked.length, 6);
  assert.equal(new Set(picked).size, 6, "keine Duplikate");
  const idx = picked.map((h) => blockHashes.indexOf(h));
  const sorted = [...idx].sort((a, b) => a - b);
  assert.deepEqual(idx, sorted, "Original-Reihenfolge erhalten");
});

test("Kein Blockanfang-Bias: Auswahl verteilt sich über den ganzen Block", () => {
  const picked = strideHashes(blockHashes, 6);
  // slice(0, 6) wäre ["H000".."H005"] — stride muss über 0..83 streuen.
  assert.notDeepEqual(picked, blockHashes.slice(0, 6), "nicht einfach der Blockanfang");
  assert.equal(picked[0], "H000", "erste Position bleibt erhalten");
  // stride(84, 6) -> Indizes 0,14,28,42,56,70: die Auswahl reicht bis in das
  // letzte Blockdrittel (letzte gewählte Position >= n - ceil(n/b)).
  const lastIdx = blockHashes.indexOf(picked[picked.length - 1]);
  assert.ok(lastIdx >= 84 - Math.ceil(84 / 6), "Auswahl erreicht das Blockende");
  // Maximaler Abstand zweier benachbarter gewählter Positionen <= ceil(84/6)
  const idx = picked.map((h) => blockHashes.indexOf(h));
  for (let i = 1; i < idx.length; i++) {
    assert.ok(idx[i] - idx[i - 1] <= Math.ceil(84 / 6), "gleichmäßige Verteilung");
  }
});

test("Determinismus: gleiche Eingabe -> exakt dieselbe Auswahl", () => {
  const a = strideHashes(blockHashes, 6);
  const b = strideHashes(blockHashes, 6);
  assert.deepEqual(a, b);
  // Auch bei anderer Budget-Größe stabil.
  assert.deepEqual(strideHashes(blockHashes, 7), strideHashes(blockHashes, 7));
});

test("Vollständigkeit: budget >= length -> komplette Liste als Kopie", () => {
  const full = strideHashes(blockHashes, 84);
  assert.deepEqual(full, blockHashes);
  const over = strideHashes(blockHashes, 300);
  assert.deepEqual(over, blockHashes);
  assert.notStrictEqual(over, blockHashes, "Kopie, nicht Original-Referenz");
});

test("budget == 1 -> genau das erste Element", () => {
  assert.deepEqual(strideHashes(blockHashes, 1), ["H000"]);
});

test("Garbage-Inputs -> [] (kein Throw)", () => {
  assert.deepEqual(strideHashes(null, 6), []);
  assert.deepEqual(strideHashes(undefined, 6), []);
  assert.deepEqual(strideHashes("H000", 6), [], "String ist kein Array");
  assert.deepEqual(strideHashes({}, 6), []);
  assert.deepEqual(strideHashes(blockHashes, 0), []);
  assert.deepEqual(strideHashes(blockHashes, -3), []);
  assert.deepEqual(strideHashes(blockHashes, NaN), []);
  assert.deepEqual(strideHashes(blockHashes, "abc"), []);
  assert.deepEqual(strideHashes([], 6), []);
});

test("Nicht-String-Elemente bleiben positionsgetreu erhalten (Objekt-Pfad Defense-in-Depth)", () => {
  const objs = Array.from({ length: 20 }, (_, i) => ({ n: i }));
  const picked = strideHashes(objs, 5);
  assert.equal(picked.length, 5);
  assert.equal(picked[0], objs[0]);
  assert.ok(picked.every((o) => objs.includes(o)), "Original-Objekte, keine Kopien");
});

// Kanten-End-to-End: Die gestrichene Auswahl voller tx-Objekte muss über
// txRecordFromEntry (lib/cluster.mjs:168) dieselbe Kante liefern wie die volle
// Liste — Sampling verliert keine Kantenstruktur der ausgewählten Tx.
test("Kantenerhaltung: stride-Auswahl liefert über txRecordFromEntry/buildClusterGraph dieselbe Kante", () => {
  const alpha = "rTESTALPHA000000000000000000001";
  const beta = "rTESTBETA000000000000000000001";
  const iso = "2026-10-02T10:00:00Z";
  // 84 flache tx-Objekte (Form von api/advance.js resolveHashes). Die
  // markierte Tx sitzt auf Position 42 — genau der stride-Index 3 von
  // stride(84, 6) = [0, 14, 28, 42, 56, 70], damit die Kante erhalten bleibt.
  const txs = Array.from({ length: 84 }, (_, i) => ({
    hash: `H${String(i).padStart(3, "0")}`,
    ledger_index: 107369720 + i,
    TransactionType: "Payment",
    Account: i === 42 ? alpha : `rTESTSENDER${String(i).padStart(3, "0")}0000000001`,
    Destination: i === 42 ? beta : `rTESTDEST${String(i).padStart(3, "0")}0000000001`,
    Amount: String(1000 + i),
    close_time_iso: iso,
  }));
  const findings = [{ ruleId: "dusting", severity: "suspect", address: alpha, note: "fixture" }];

  const picked = strideHashes(txs, 6);
  assert.ok(picked.some((t) => t.hash === "H042"), "stride-Auswahl enthält die markierte Tx");

  const records = picked.map((e) => txRecordFromEntry(e, iso)).filter(Boolean);
  assert.equal(records.length, 6, "alle sechs Entries werden zu txRecords");
  const graph = buildClusterGraph(records, findings, { maxEdges: 1200 });
  assert.equal(graph.clusters.length, 1, "eine Komponente aus der markierten Kante");
  // buildClusterGraph liefert edges auf Top-Level (lib/cluster.mjs:395).
  const edge = graph.edges.find((e) => e.txHash === "H042");
  assert.ok(edge, "Kante der gestrichenen Tx bleibt erhalten");
  assert.equal(edge.from, alpha);
  assert.equal(edge.to, beta);
  assert.equal(edge.amountDrops, 1042);
  assert.equal(graph.clusters[0].txCount, 1, "Cluster zählt die gestrichene Kante");
});
