// node:test für den Cursor-Advance-Kern. IN-MEMORY-Fixtures, KEIN Netzwerk,
// KEIN Dateizugriff. Die Merge-Abdeckung nutzt echte Ledger-Entry-Formen
// (Cluster-Formen aus lib/cluster.mjs) und prüft Merge-Dedup (gleicher Cluster
// über Blöcke wird dedupliziert) sowie Money-Flow-Akkumulation (Summen addieren
// sich über Blöcke) und die BEGRENZTE Fluss-Kanten-Akkumulation: Findings sind
// pro Block Teil des Fetcher-Vertrags ({transactions, findings}), erzeugen
// echte Fluss-Kanten, die Top-K nach Volumen begrenzt und nach Kanten-
// Identität dedupliziert werden.

import test from "node:test";
import assert from "node:assert/strict";
import { advance } from "./ledger-walk.mjs";

const NOW = 1700000000000;

test("leerer Fetcher: Cursor bleibt, kein Processing", async () => {
  const res = await advance({
    cursor: 100,
    budget: 10,
    now: NOW,
    fetcher: async () => null,
    flowState: {},
  });
  assert.equal(res.newCursor, 100);
  assert.ok(res.flowState && typeof res.flowState === "object");
});

test("Return-Form: newCursor/summary/flowState vorhanden", async () => {
  const res = await advance({
    cursor: 0,
    budget: 1,
    now: NOW,
    fetcher: async () => null,
    flowState: null,
  });
  assert.ok("newCursor" in res && "summary" in res && "flowState" in res);
});

test("Budget-Cap: Fetcher nicht öfter als budget-mal pro Tick", async () => {
  let served = 0;
  const res = await advance({
    cursor: 0,
    budget: 3,
    now: NOW,
    fetcher: async () => {
      served++;
      return { transactions: [{}] };
    },
    flowState: {},
  });
  assert.ok(served <= 3, "Fetcher darf nicht mehr als budget-mal aufgerufen werden");
  assert.ok(res.newCursor <= 3);
});

// Echter Fluss: zwei Blöcke mit derselben alpha->beta-Zahlung. Der Merge muss
// den Cluster nach Key deduplizieren (ein Eintrag, nicht zwei) UND die
// Geldfluss-Summe über die Blöcke akkumulieren (1000 + 2500 = 3500).
test("Merge-Dedup + Money-Flow-Akkumulation über Blöcke", async () => {
  const alpha = "rTESTALPHA000000000000000000001";
  const beta = "rTESTBETA000000000000000000001";
  const iso = "2026-10-01T10:00:00Z";
  const pay = (hash, amount) => ({
    hash,
    TransactionType: "Payment",
    Account: alpha,
    Destination: beta,
    Amount: String(amount),
    close_time_iso: iso,
  });
  const findings = [{ ruleId: "dusting", severity: "suspect", address: alpha, note: "fixture" }];
  const blocks = [
    { transactions: [pay("H1", 1000)], findings },
    { transactions: [pay("H2", 2500)], findings },
  ];
  let i = 0;
  const res = await advance({
    cursor: 10,
    budget: 5,
    now: NOW,
    fetcher: async () => (i < blocks.length ? blocks[i++] : null),
    flowState: {},
  });
  assert.ok(res.newCursor > 10, "Cursor muss vorrücken");
  const keys = Object.keys(res.flowState.clusters ?? {});
  assert.equal(keys.length, 1, "gleicher Cluster über Blöcke wird dedupliziert (ein Key)");
  const merged = res.flowState.clusters[keys[0]];
  assert.equal(merged.totalDrops, 3500, "Geldfluss-Summe addiert sich über Blöcke");
  assert.equal(merged.txCount, 2, "Tx-Zählung addiert sich über Blöcke");
});

// Pro-Block-Findings (Fetcher-Vertrag): findings reisen im Block, nicht
// tick-global. Geflaggte Adressen erzeugen echte Fluss-Kanten, die der Merge
// pro Cluster begrenzt akkumuliert; ohne Findings bleibt der Merge leer.
test("Pro-Block-Findings erzeugen Fluss-Kanten im Merge", async () => {
  const alpha = "rTESTALPHA000000000000000000001";
  const beta = "rTESTBETA000000000000000000001";
  const iso = "2026-10-01T10:00:00Z";
  const pay = (hash, amount, seq) => ({
    hash,
    ledger_index: seq,
    TransactionType: "Payment",
    Account: alpha,
    Destination: beta,
    Amount: String(amount),
    close_time_iso: iso,
  });
  const findings = [{ ruleId: "dusting", severity: "suspect", address: alpha, note: "fixture" }];
  const res = await advance({
    cursor: 20,
    budget: 1,
    now: NOW,
    fetcher: async () => ({ transactions: [pay("H1", 750, 21)], findings }),
    flowState: {},
  });
  const keys = Object.keys(res.flowState.clusters ?? {});
  assert.equal(keys.length, 1, "geflaggter Fluss bildet genau ein Cluster");
  const merged = res.flowState.clusters[keys[0]];
  assert.ok(Array.isArray(merged.edges), "Cluster trägt edges");
  assert.equal(merged.edges.length, 1, "eine Kante aus der geflaggten Transaktion");
  const e = merged.edges[0];
  assert.equal(e.from, alpha);
  assert.equal(e.to, beta);
  assert.equal(e.amountDrops, 750);
  assert.equal(e.txHash, "H1");
  assert.equal(e.ledgerSeq, 21);
  // Ohne Findings im Block: kein Graph, kein Cluster, keine Kanten.
  const resNoFindings = await advance({
    cursor: 30,
    budget: 1,
    now: NOW,
    fetcher: async () => ({ transactions: [pay("H2", 750, 31)] }),
    flowState: {},
  });
  assert.deepEqual(resNoFindings.flowState.clusters, {}, "ohne Findings: kein Graph, kein Cluster");
});

// Top-K-Volumen-Kappung: der Merge behält nur die K größten Flüsse pro Cluster
// (Geldwäsche-Signale) — auch über Blöcke hinweg (spätere große Flüsse verdrängen
// frühere kleine). Deterministisch: Volumen desc, Gleichstand bricht
// chronologisch (ledgerSeq asc).
test("Top-K-Volumen-Kappung: begrenzt, volumenabsteigend, deterministisch", async () => {
  const alpha = "rTESTALPHA000000000000000000001";
  const dest = (n) => `rTESTDEST${String(n).padStart(3, "0")}0000000000000001`;
  const iso = "2026-10-01T10:00:00Z";
  const pay = (hash, destAddr, amount, seq) => ({
    hash,
    ledger_index: seq,
    TransactionType: "Payment",
    Account: alpha,
    Destination: destAddr,
    Amount: String(amount),
    close_time_iso: iso,
  });
  const findings = [{ ruleId: "dusting", severity: "suspect", address: alpha, note: "fixture" }];
  const blocks = [
    { transactions: [pay("H1", dest(1), 1000, 42), pay("H2", dest(2), 1000, 43)], findings },
    { transactions: [pay("H3", dest(3), 9000, 44)], findings },
  ];
  const run = () => {
    let i = 0;
    return advance({
      cursor: 40,
      budget: 2,
      now: NOW,
      fetcher: async () => (i < blocks.length ? blocks[i++] : null),
      flowState: {},
      opts: { maxClusterEdges: 2 },
    });
  };
  const res = await run();
  const keys = Object.keys(res.flowState.clusters ?? {});
  assert.equal(keys.length, 1, "alle Flüsse liegen in einem Cluster");
  const edges = res.flowState.clusters[keys[0]].edges;
  assert.equal(edges.length, 2, "Top-K begrenzt auf K=2");
  assert.deepEqual(
    edges.map((e) => e.txHash),
    ["H3", "H1"],
    "größter Fluss zuerst; Gleichstand (1000) bricht chronologisch (ledgerSeq asc)"
  );
  // Determinismus: zweiter Lauf liefert exakt dieselbe Kantenauswahl.
  const res2 = await run();
  assert.deepEqual(res2.flowState.clusters[keys[0]].edges, edges, "deterministisch bei Wiederholung");
});

// Kanten-Dedup nach Identität: dieselbe Transaktion (gleiche Identität) in
// mehreren Blöcken wird einmal gezählt — das Kantenvolumen addiert sich NICHT
// doppelt, während die Cluster-Volumen-Summe wie bisher akkumuliert.
test("Kanten-Dedup nach Identität über Blöcke", async () => {
  const alpha = "rTESTALPHA000000000000000000001";
  const beta = "rTESTBETA000000000000000000001";
  const iso = "2026-10-01T10:00:00Z";
  const pay = (hash, amount, seq) => ({
    hash,
    ledger_index: seq,
    TransactionType: "Payment",
    Account: alpha,
    Destination: beta,
    Amount: String(amount),
    close_time_iso: iso,
  });
  const findings = [{ ruleId: "dusting", severity: "suspect", address: alpha, note: "fixture" }];
  const blocks = [
    { transactions: [pay("H1", 1000, 51)], findings },
    { transactions: [pay("H1", 1000, 51)], findings }, // identische Transaktion erneut
  ];
  let i = 0;
  const res = await advance({
    cursor: 50,
    budget: 5,
    now: NOW,
    fetcher: async () => (i < blocks.length ? blocks[i++] : null),
    flowState: {},
  });
  const keys = Object.keys(res.flowState.clusters ?? {});
  assert.equal(keys.length, 1, "gleicher Cluster über Blöcke");
  const merged = res.flowState.clusters[keys[0]];
  assert.equal(merged.edges.length, 1, "identische Kante wird dedupliziert");
  assert.equal(merged.edges[0].amountDrops, 1000, "Kantenvolumen wird nicht doppelt gezählt");
  assert.equal(merged.totalDrops, 2000, "Cluster-Volumen-Summe addiert sich (wie bisher)");
});
