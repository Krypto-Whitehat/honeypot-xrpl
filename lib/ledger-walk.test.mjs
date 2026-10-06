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
import { advance, MAX_STATE_CLUSTER_MEMBERS } from "./ledger-walk.mjs";
import { TEMPORAL_SERIES_CAP } from "./cluster.mjs";
// Unit-Tests für lib/entity-resolve.mjs (Audit-Nachprüfung Grenze 3: die
// Datei hatte keine). Kein Netzwerk: nur reine Funktionen + Codec; der
// GitHub-Transport (history.mjs) wird importiert, aber nie aufgerufen.
import {
  entityJoinKeys,
  buildEntityLinks,
  clusterByEntity,
  snapshotFromAccountInfo,
  serializeEntityDoc,
  parseEntityText,
  emptyEntityDoc,
  ENTITY_JOIN_KEY_HUB,
} from "./entity-resolve.mjs";

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

// Fetcher-Vertrag (honeycluster-Umstellung): ein truthy Block mit
// transactions:[] ist ein GÜLTIGER LEERBLOCK und lässt den Walk vorrücken —
// er darf den Walk nicht blockieren (a.D. `hashes.length===0 -> null`).
test("Leerblock (transactions:[]) ist gültig und lässt den Walk vorrücken", async () => {
  const seq = [];
  const blocks = [
    { transactions: [], findings: [] }, // Leerblock
    { transactions: [], findings: [] }, // zweiter Leerblock
    null, // Live-Edge erst danach
  ];
  let i = 0;
  const res = await advance({
    cursor: 100,
    budget: 5,
    now: NOW,
    fetcher: async (idx) => {
      seq.push(idx);
      return i < blocks.length ? blocks[i++] : null;
    },
    flowState: {},
  });
  assert.equal(res.newCursor, 102, "Cursor rückt über beide Leerblöcke vor");
  assert.deepEqual(seq, [101, 102, 103], "drei Fetches: zwei Leerblöcke, dann Edge");
  assert.deepEqual(res.flowState.clusters, {}, "Leerbloecke mergen leer");
});

// opts.parallel: Blöcke werden rundenweise parallel geholt, der Merge bleibt
// strikt aufsteigend nach Index (deterministisch, unabhängig von der
// Antwortreihenfolge — die langsameren Antworten trödeln in der Promise.all-
// Runde, die Merge-Reihenfolge ist indexfix).
test("opts.parallel: rundenweiser Parallel-Fetch, Merge aufsteigend nach Index", async () => {
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
  const requested = [];
  const res = await advance({
    cursor: 200,
    budget: 5,
    now: NOW,
    fetcher: async (idx) => {
      requested.push(idx);
      // Absichtlich invertierte Latenz: niedrige Indizes antworten später.
      await new Promise((r) => setTimeout(r, (300 - idx) * 2));
      if (idx > 204) return null;
      return { transactions: [pay(`H${idx}`, 1000, idx)], findings };
    },
    flowState: {},
    opts: { parallel: 4 },
  });
  assert.equal(res.newCursor, 204, "5 Indizes: Runden [201..204], [205]->null");
  assert.deepEqual(requested, [201, 202, 203, 204, 205], "Rundenbildung 4+1");
  const merged = res.flowState.clusters[Object.keys(res.flowState.clusters)[0]];
  assert.equal(merged.totalDrops, 4000, "alle vier Blöcke gemergt");
  // Gleiche Volumina -> Tie-Break ledgerSeq asc: die Kantenordnung belegt die
  // index-aufsteigende Merge-Reihenfolge trotz invertierter Antwort-Latenz.
  assert.deepEqual(
    merged.edges.map((e) => e.ledgerSeq),
    [201, 202, 203, 204],
    "Merge-Reihenfolge index-aufsteigend trotz invertierter Latenz"
  );
});

// Parallelität darf über die Budget-Grenze hinaus keine Fetches feuern.
test("opts.parallel: Budget-Cap gilt auch über Rundengrenzen", async () => {
  let served = 0;
  const res = await advance({
    cursor: 0,
    budget: 3,
    now: NOW,
    fetcher: async () => {
      served++;
      return { transactions: [], findings: [] };
    },
    flowState: {},
    opts: { parallel: 4 },
  });
  assert.equal(served, 3, "genau budget-mal Fetches (4er-Runde wird gekappt)");
  assert.equal(res.newCursor, 3);
});

// =====================================================================
// Peeling-Ketten-Persistenz + Entity-Union (Peeling-Plan, Grenzen 1+3).
// =====================================================================
const W = {
  seed: "rTESTWSEED00000000000000000001",
  end: "rTESTWEND0000000000000000000001",
  b1: "rTESTWB1000000000000000000000001",
  b2: "rTESTWB2000000000000000000000002",
  a: "rTESTWA0000000000000000000000001",
  b: "rTESTWB00000000000000000000000002",
  c: "rTESTWC0000000000000000000000003",
  d: "rTESTWD0000000000000000000000004",
};
const wIso = "2026-10-01T10:00:00Z";
const wPay = (hash, seq, account, destination, amount) => ({
  hash,
  ledger_index: seq,
  TransactionType: "Payment",
  Account: account,
  Destination: destination,
  Amount: String(amount),
  close_time_iso: wIso,
});

// (a) Kettenpersistenz über zwei Blöcke: Kette aus Block 1 überlebt Block 2
// (Signatur-Dedup, ein Eintrag), Cluster-Feld peelingChains, keine neue Rolle.
test("peelingChains: advance() persistiert Ketten über zwei Blöcke (Signatur-Dedup)", async () => {
  const findings = [
    { ruleId: "dusting", severity: "suspect", address: W.seed, note: "fixture" },
    { ruleId: "drainer-sweep", severity: "malicious", address: W.end, note: "fixture" },
  ];
  const chainTxs = [
    wPay("H1", 11, W.seed, W.b1, 10000),
    wPay("H2", 12, W.b1, W.b2, 8000),
    wPay("H3", 13, W.b2, W.end, 6400),
  ];
  const blocks = [
    { transactions: chainTxs, findings },
    { transactions: [...chainTxs, wPay("H4", 14, W.seed, W.b1, 9000)], findings },
  ];
  let i = 0;
  const res = await advance({
    cursor: 10,
    budget: 5,
    now: NOW,
    fetcher: async () => (i < blocks.length ? blocks[i++] : null),
    flowState: {},
  });
  const all = Object.values(res.flowState.clusters);
  const withChains = all.filter((c) => Array.isArray(c.peelingChains) && c.peelingChains.length > 0);
  assert.equal(withChains.length, 1, "genau ein Cluster trägt die Kette (Seed-Cluster)");
  const ch = withChains[0].peelingChains[0];
  assert.equal(ch.hopsCount, 3);
  assert.deepEqual(ch.bridges, [W.b1, W.b2]);
  assert.equal(withChains[0].peelingChains.length, 1, "Signatur-Dedup über Blöcke: ein Eintrag");
  // Keine neue Rolle 'peeler': ROLE_SET bleibt unangetastet.
  for (const role of Object.values(withChains[0].roles ?? {})) {
    assert.ok(["source", "drainer", "collector", "relay", "unknown"].includes(role), `Rolle ${role} nicht in ROLE_SET`);
  }
});

// (b) opts.entityLinks null verhält sich exakt wie bisher (Transport-
// Agnostik-Regression); mit Join-Key werden zwei Cluster ohne gemeinsames
// Mitglied vereinigt.
test("entityLinks: null verhält sich wie bisher, Join-Key vereinigt ohne Member-Überschneidung", async () => {
  const blocks = [
    { transactions: [wPay("T1", 21, W.a, W.b, 5000)], findings: [{ ruleId: "dusting", severity: "suspect", address: W.a }] },
    { transactions: [wPay("T2", 22, W.c, W.d, 5000)], findings: [{ ruleId: "dusting", severity: "suspect", address: W.c }] },
  ];
  let i = 0;
  const without = await advance({
    cursor: 20,
    budget: 5,
    now: NOW,
    fetcher: async () => (i < blocks.length ? blocks[i++] : null),
    flowState: {},
  });
  assert.equal(Object.keys(without.flowState.clusters).length, 2, "ohne entityLinks: zwei Cluster wie bisher");

  i = 0;
  const links = new Map([
    [W.a, ["rk:KEY1"]],
    [W.c, ["rk:KEY1"]],
  ]);
  const withLinks = await advance({
    cursor: 20,
    budget: 5,
    now: NOW,
    fetcher: async () => (i < blocks.length ? blocks[i++] : null),
    flowState: {},
    opts: { entityLinks: links },
  });
  const keys = Object.keys(withLinks.flowState.clusters);
  assert.equal(keys.length, 1, "Join-Key vereinigt zwei Cluster ohne gemeinsames Mitglied");
  const merged = withLinks.flowState.clusters[keys[0]];
  assert.deepEqual(merged.memberAddresses, [W.a, W.b, W.c, W.d].sort(), "Member-Union nach Entity-Union");
});

// (c) Join-Key mit > 20 geteilten Adressen vereinigt nicht (Hub-Ausschluss).
test("entityLinks: Join-Key-Hub mit 21 Adressen vereinigt nicht", async () => {
  const blocks = [
    { transactions: [wPay("T1", 21, W.a, W.b, 5000)], findings: [{ ruleId: "dusting", severity: "suspect", address: W.a }] },
    { transactions: [wPay("T2", 22, W.c, W.d, 5000)], findings: [{ ruleId: "dusting", severity: "suspect", address: W.c }] },
  ];
  const links = new Map([[W.a, ["rk:HUB"]], [W.c, ["rk:HUB"]]]);
  for (let i = 0; i < 19; i++) links.set(`rTESTWHUB${String(i).padStart(2, "0")}0000000000000000`, ["rk:HUB"]);
  let j = 0;
  const res = await advance({
    cursor: 20,
    budget: 5,
    now: NOW,
    fetcher: async () => (j < blocks.length ? blocks[j++] : null),
    flowState: {},
    opts: { entityLinks: links },
  });
  assert.equal(Object.keys(res.flowState.clusters).length, 2, "21 Adressen mit dem Key -> Hub-Ausschluss");
});

// (d) Domäne ohne dv:-Flag vereinigt nicht (Kritik 7: Domäne ist ohne
// Zwei-Wege-Verifikation reines Anzeige-Metadatum, nie Join-Key).
test("entityLinks: Domäne ohne dv:-Flag vereinigt nicht, dv: nach Verifikation schon", async () => {
  const blocks = [
    { transactions: [wPay("T1", 21, W.a, W.b, 5000)], findings: [{ ruleId: "dusting", severity: "suspect", address: W.a }] },
    { transactions: [wPay("T2", 22, W.c, W.d, 5000)], findings: [{ ruleId: "dusting", severity: "suspect", address: W.c }] },
  ];
  let i = 0;
  const rawDomain = new Map([
    [W.a, ["dm:example.com"]],
    [W.c, ["dm:example.com"]],
  ]);
  const resRaw = await advance({
    cursor: 20,
    budget: 5,
    now: NOW,
    fetcher: async () => (i < blocks.length ? blocks[i++] : null),
    flowState: {},
    opts: { entityLinks: rawDomain },
  });
  assert.equal(Object.keys(resRaw.flowState.clusters).length, 2, "dm: ist kein Join-Key");

  i = 0;
  const verified = new Map([
    [W.a, ["dv:example.com"]],
    [W.c, ["dv:example.com"]],
  ]);
  const resDv = await advance({
    cursor: 20,
    budget: 5,
    now: NOW,
    fetcher: async () => (i < blocks.length ? blocks[i++] : null),
    flowState: {},
    opts: { entityLinks: verified },
  });
  assert.equal(Object.keys(resDv.flowState.clusters).length, 1, "dv: (verifizierte Domäne) vereinigt");
});

// (e) Funding-Muster (Audit-Nachprüfung Grenze 3): 'sp:<sponsor>' — gemeinsame
// Sponsor-Adresse = gemeinsame Funding-Quelle — vereinigt; Faucet-Fall
// (21 Adressen am selben Sponsor) vereinigt NIE (Hub-Guard, False-Positive-
// Schutz am echten Muster).
test("entityLinks: sp: Funding-Muster vereinigt, Faucet-Hub (21 Sponsoring) nicht", async () => {
  const blocks = [
    { transactions: [wPay("T1", 21, W.a, W.b, 5000)], findings: [{ ruleId: "dusting", severity: "suspect", address: W.a }] },
    { transactions: [wPay("T2", 22, W.c, W.d, 5000)], findings: [{ ruleId: "dusting", severity: "suspect", address: W.c }] },
  ];
  let i = 0;
  const res = await advance({
    cursor: 20,
    budget: 5,
    now: NOW,
    fetcher: async () => (i < blocks.length ? blocks[i++] : null),
    flowState: {},
    opts: { entityLinks: new Map([[W.a, ["sp:SPONSOR1"]], [W.c, ["sp:SPONSOR1"]]]) },
  });
  assert.equal(Object.keys(res.flowState.clusters).length, 1, "sp: vereinigt über gemeinsame Funding-Quelle");

  const hubLinks = new Map([[W.a, ["sp:FAUCET"]], [W.c, ["sp:FAUCET"]]]);
  for (let k = 0; k < 19; k++) hubLinks.set(`rTESTWHUB${String(k).padStart(2, "0")}0000000000000000`, ["sp:FAUCET"]);
  let j = 0;
  const resHub = await advance({
    cursor: 20,
    budget: 5,
    now: NOW,
    fetcher: async () => (j < blocks.length ? blocks[j++] : null),
    flowState: {},
    opts: { entityLinks: hubLinks },
  });
  assert.equal(Object.keys(resHub.flowState.clusters).length, 2, "21 Adressen am selben Sponsor -> Hub-Ausschluss (Faucet-Fall)");
});

// (f) entitySnapshot-Produzent (Audit-Nachprüfung Grenze 4): ruleId
// 'known-bad-hit' (registry-abgeleitet, api/advance.js buildCtx) setzt
// entitySnapshot { registryLinked: true } auf dem Cluster — die einzige
// Produktionsquelle des Felds, das lib/flow-state.mjs isRegistryLinked liest.
// Union-Semantik: einmal gesetzt, bleibt es auch in Blöcken ohne Treffer.
// False-Positive-Fall: Cluster nur mit dusting-Finding bekommt KEIN Feld.
test("entitySnapshot: known-bad-hit setzt registryLinked, dusting allein nie, Union bleibt", async () => {
  const blocks = [
    { transactions: [wPay("T1", 21, W.a, W.b, 5000)], findings: [{ ruleId: "dusting", severity: "suspect", address: W.a }] },
    { transactions: [wPay("T2", 22, W.c, W.d, 5000)], findings: [{ ruleId: "known-bad-hit", severity: "malicious", address: W.c }] },
    { transactions: [wPay("T3", 23, W.a, W.b, 1000)], findings: [{ ruleId: "dusting", severity: "suspect", address: W.a }] },
  ];
  let i = 0;
  const res = await advance({
    cursor: 30,
    budget: 5,
    now: NOW,
    fetcher: async () => (i < blocks.length ? blocks[i++] : null),
    flowState: {},
  });
  const clusters = Object.values(res.flowState.clusters);
  assert.equal(clusters.length, 2, "zwei getrennte Cluster (a/b und c/d)");
  const clean = clusters.find((c) => c.memberAddresses.includes(W.a));
  const linked = clusters.find((c) => c.memberAddresses.includes(W.c));
  assert.ok(!clean.entitySnapshot, "dusting-Cluster ohne Registry-Treffer: kein entitySnapshot (False-Positive-Fall)");
  assert.ok(linked.entitySnapshot && linked.entitySnapshot.registryLinked === true, "known-bad-hit -> registryLinked true");
  assert.equal(linked.txCount, 1, "c/d-Cluster nur aus Block 2");
});

test("entitySnapshot: Union über Blöcke — Block ohne Treffer lässt das Feld nicht verfallen", async () => {
  const blocks = [
    { transactions: [wPay("T1", 21, W.a, W.b, 5000)], findings: [{ ruleId: "known-bad-hit", severity: "malicious", address: W.a }] },
    { transactions: [wPay("T2", 22, W.a, W.b, 2000)], findings: [{ ruleId: "dusting", severity: "suspect", address: W.a }] },
  ];
  let i = 0;
  const res = await advance({
    cursor: 40,
    budget: 5,
    now: NOW,
    fetcher: async () => (i < blocks.length ? blocks[i++] : null),
    flowState: {},
  });
  const keys = Object.keys(res.flowState.clusters);
  assert.equal(keys.length, 1, "gleicher Cluster dedupliziert");
  const c = res.flowState.clusters[keys[0]];
  assert.ok(c.entitySnapshot && c.entitySnapshot.registryLinked === true, "registryLinked bleibt nach harmloserem Block erhalten");
});

/* ---------- lib/entity-resolve.mjs Unit-Tests (Nachprüfung Grenze 3) ---------- */

// base58-konforme Synthetik (kein 0/O/I/l) — snapshotFromAccountInfo prüft
// die XRPL-Adresse-Muster für RegularKey/Sponsor/Signers.
const E1 = "rTESTEntit1111111111111111111111";
const E2 = "rTESTEntit2222222222222222222222";
const E3 = "rTESTEntit3333333333333333333333";
const RK1 = "rTESTRegKey111111111111111111111";
const SP1 = "rTESTSponsor111111111111111111111";

test("entityJoinKeys: rk:/sg:/eh:/sp: stark, dv: nur mit domainVerified", () => {
  const table = {
    addresses: {
      [E1]: { regularKey: RK1, signersFingerprint: "ab12", emailHash: "ee34", sponsor: SP1, domain: "example.com", domainVerified: false },
      [E2]: { regularKey: null, signersFingerprint: null, emailHash: null, sponsor: null, domain: "example.com", domainVerified: true },
    },
  };
  const k1 = entityJoinKeys(E1, table);
  assert.deepEqual(k1, [`rk:${RK1}`, "sg:ab12", "eh:ee34", `sp:${SP1}`], "starke Keys inkl. Funding-Muster sp:, keine Domäne ohne Flag");
  assert.deepEqual(entityJoinKeys(E2, table), ["dv:example.com"], "dv: nur nach Verifikation");
  assert.deepEqual(entityJoinKeys("rTESTX00000000000000000000000009", table), [], "unbekannte Adresse -> []");
});

test("buildEntityLinks: Hub-Key (21 Adressen) fehlt in der ausgelieferten Map", () => {
  const addresses = {};
  for (let i = 0; i < 21; i++) addresses[`rTESTEHUB${String(i).padStart(2, "0")}0000000000000000`] = { regularKey: "rTESTHubKey0000000000000000000000" };
  addresses[E1] = { regularKey: RK1 };
  const links = buildEntityLinks({ addresses });
  assert.equal(ENTITY_JOIN_KEY_HUB, 20);
  for (const keys of links.values()) {
    assert.ok(!keys.some((k) => k === "rk:rTESTHubKey0000000000000000000000"), "Hub-Key wird ausgeliefert");
  }
  assert.ok(links.get(E1)?.includes(`rk:${RK1}`), "starker Nicht-Hub-Key bleibt");
});

test("clusterByEntity: zwei Adressen mit gleichem RegularKey -> ein 2-Member-Cluster (Root-Fix)", () => {
  const clusters = clusterByEntity({
    addresses: {
      [E1]: { regularKey: RK1 },
      [E2]: { regularKey: RK1 },
    },
  });
  assert.equal(clusters.length, 1, "genau ein Cluster");
  assert.deepEqual(clusters[0], [E1, E2].sort(), "Union-Root zählt mit (vorher: [] wegen parent.keys()-Bug)");
});

test("clusterByEntity: Funding-Muster sp: vereinigt, Hub-Faucet (21) liefert [], Transitivität über Keys", () => {
  const funded = clusterByEntity({
    addresses: {
      [E1]: { sponsor: SP1 },
      [E2]: { sponsor: SP1 },
    },
  });
  assert.deepEqual(funded, [[E1, E2].sort()], "sp: Funding-Muster-Cluster");
  const faucet = {};
  for (let i = 0; i < 21; i++) faucet[`rTESTEHUB${String(i).padStart(2, "0")}0000000000000000`] = { sponsor: SP1 };
  assert.deepEqual(clusterByEntity({ addresses: faucet }), [], "Faucet-Sponsoring 21 Adressen -> keine Union (False-Positive-Fall)");
  const transitiv = clusterByEntity({
    addresses: {
      [E1]: { regularKey: RK1 },
      [E2]: { regularKey: RK1, emailHash: "ee34" },
      [E3]: { emailHash: "ee34" },
    },
  });
  assert.deepEqual(transitiv, [[E1, E2, E3].sort()], "Transitivität rk:+eh: -> ein Cluster");
});

test("snapshotFromAccountInfo: Domain-Hex, Signer-Fingerprint, Sponsor, Seed-freie Defensivwerte", () => {
  const snap = snapshotFromAccountInfo(
    { account_data: {
        RegularKey: RK1,
        Domain: "6578616D706C652E636F6D", // "example.com" hex
        Signers: [{ Account: E2 }, { Account: E1 }],
        Sponsor: E3,
        Sequence: 7, Flags: 8, PreviousTxnLgrSeq: 99,
      } },
    1234, 1700000000000,
  );
  assert.equal(snap.regularKey, RK1, "RegularKey übernommen");
  assert.equal(snap.domain, "example.com", "Hex-Domain decodiert");
  assert.equal(snap.domainVerified, false, "Verifikation ist Sache des Consumers");
  assert.deepEqual(snap.signers, [E1, E2].sort(), "Signer asc");
  assert.ok(snap.signersFingerprint && snap.signersFingerprint.length === 16, "sha256-Fingerprint 16 hex");
  assert.equal(snap.sponsor, E3, "Sponsor (Funding-Muster-Quelle) übernommen");
  assert.equal(snap.snapshotLedger, 1234);
  assert.equal(snapshotFromAccountInfo(null, 1, 2), null, "defektes Ergebnis -> null, kein Throw");
});

test("Entity-Codec: Roundtrip deterministisch, Korruption wirft (kein stilles Überschreiben)", () => {
  const doc = { updatedAt: 1700000000000, addresses: { [E1]: { regularKey: RK1, domain: "example.com" } } };
  const text = serializeEntityDoc(doc);
  const back = parseEntityText(text);
  assert.equal(back.updatedAt, 1700000000000);
  assert.equal(back.addresses[E1].regularKey, RK1, "normalizeEntityDoc behält base58-konforme Adresse");
  assert.equal(serializeEntityDoc(back), text, "Roundtrip deterministisch");
  assert.throws(() => parseEntityText("{kaputt"), /korrumpiert/);
  assert.throws(() => parseEntityText("[1,2]"), /unerwartetes Format/);
  assert.deepEqual(emptyEntityDoc(), { updatedAt: null, addresses: {} });
});

// =====================================================================
// TAG-IDENTITÄT im Advance-Pfad (opts.multiUserAccounts, sanitizeEdge)
// =====================================================================

const TAG_EX = "rTESTexchangeAccount11111111"; // 28 Zeichen, Base58-gültig
const TAG_ALPHA = "rTESTALPHA000000000000000000001";
const tagRegistry = new Map([[TAG_EX, { exchange: "Test Exchange One", tier: 1, requireDestTag: true }]]);

test("advance mit multiUserAccounts: persistierte Edge trägt toTag/transit", async () => {
  const iso = "2026-10-01T10:00:00Z";
  const pay = (hash, seq, tag) => ({
    hash, ledger_index: seq, TransactionType: "Payment",
    Account: TAG_ALPHA, Destination: TAG_EX, Amount: "1000",
    DestinationTag: tag, close_time_iso: iso,
  });
  const findings = [{ ruleId: "dusting", severity: "suspect", address: TAG_EX, note: "fixture" }];
  const blocks = [
    { transactions: [pay("H1", 31, 111)], findings },
    { transactions: [pay("H2", 32, 222)], findings },
  ];
  let i = 0;
  const res = await advance({
    cursor: 30, budget: 5, now: NOW,
    fetcher: async () => (i < blocks.length ? blocks[i++] : null),
    flowState: {},
    opts: { multiUserAccounts: tagRegistry },
  });
  const keys = Object.keys(res.flowState.clusters ?? {});
  assert.equal(keys.length, 1);
  const edges = res.flowState.clusters[keys[0]].edges;
  assert.equal(edges.length, 2);
  assert.equal(edges.find((e) => e.txHash === "H1").toTag, 111);
  assert.equal(edges.find((e) => e.txHash === "H2").toTag, 222);
  for (const e of edges) assert.equal(e.transit, true, "zwei Tag-Identitäten -> transit");
});

test("advance ohne multiUserAccounts: keine Tag-Felder (Default bitgleich)", async () => {
  const iso = "2026-10-01T10:00:00Z";
  const findings = [{ ruleId: "dusting", severity: "suspect", address: TAG_EX, note: "fixture" }];
  const res = await advance({
    cursor: 40, budget: 1, now: NOW,
    fetcher: async () => ({
      transactions: [{
        hash: "H1", ledger_index: 41, TransactionType: "Payment",
        Account: TAG_ALPHA, Destination: TAG_EX, Amount: "1000",
        DestinationTag: 111, close_time_iso: iso,
      }],
      findings,
    }),
    flowState: {},
  });
  const keys = Object.keys(res.flowState.clusters ?? {});
  const edges = res.flowState.clusters[keys[0]].edges;
  assert.equal(edges.length, 1);
  assert.ok(!("toTag" in edges[0]), "ohne Registry kein toTag");
  assert.ok(!("transit" in edges[0]));
});

test("sanitizeEdge (über normalizeState): defekte Tag-Werte fallen raus, 0 bleibt 0", async () => {
  // sanitizeEdge ist nicht exportiert — er läuft in advance über die
  // Normalisierung eines mitgegebenen Bestand-states.
  const dirty = {
    clusters: {
      "cluster:a": {
        totalDrops: 10, txCount: 3,
        edges: [
          { from: "rA", to: "rB", type: "Payment", amountDrops: 1, txHash: "T1", ledgerSeq: 1, closeTime: null, toTag: "x", fromTag: -1, transit: "ja" },
          { from: "rC", to: "rD", type: "Payment", amountDrops: 1, txHash: "T2", ledgerSeq: 2, closeTime: null, toTag: 0, transit: true },
          { from: "rE", to: "rF", type: "Payment", amountDrops: 1, txHash: "T3", ledgerSeq: 3, closeTime: null, toTag: 4294967296 },
        ],
      },
    },
    blocksProcessedTotal: 0, lastAdvancedAt: null,
  };
  const res = await advance({ cursor: 0, budget: 0, now: NOW, fetcher: async () => null, flowState: dirty });
  const edges = res.flowState.clusters["cluster:a"].edges;
  const byHash = Object.fromEntries(edges.map((e) => [e.txHash, e]));
  assert.ok(!("toTag" in byHash.T1), "toTag 'x' verworfen");
  assert.ok(!("fromTag" in byHash.T1), "fromTag -1 verworfen");
  assert.ok(!("transit" in byHash.T1), "transit 'ja' (nicht true) verworfen");
  assert.equal(byHash.T2.toTag, 0, "Tag 0 ist ein echter Wert und bleibt 0");
  assert.equal(byHash.T2.transit, true);
  assert.ok(!("toTag" in byHash.T3), "2**32 über UInt32-Max verworfen");
});

test("edgeIdentity unverändert: gleiche Tx mit/ohne Tag-Feld dedupliziert weiterhin", async () => {
  // Derselbe Payment-Hash in zwei Blöcken — einmal mit DestinationTag,
  // einmal ohne: Dedup nach [from,to,txHash,ledgerSeq] muss bei einer Kante
  // bleiben und das Tag-Feld erhalten.
  const iso = "2026-10-01T10:00:00Z";
  const findings = [{ ruleId: "dusting", severity: "suspect", address: TAG_EX, note: "fixture" }];
  const entry = (tag) => ({
    hash: "HSAME", ledger_index: 51, TransactionType: "Payment",
    Account: TAG_ALPHA, Destination: TAG_EX, Amount: "1000",
    ...(tag !== undefined ? { DestinationTag: tag } : {}),
    close_time_iso: iso,
  });
  const res = await advance({
    cursor: 50, budget: 2, now: NOW,
    fetcher: async (index) => (index === 51 ? { transactions: [entry(111)], findings } : index === 52 ? { transactions: [entry()], findings } : null),
    flowState: {},
    opts: { multiUserAccounts: tagRegistry },
  });
  const keys = Object.keys(res.flowState.clusters ?? {});
  const edges = res.flowState.clusters[keys[0]].edges;
  assert.equal(edges.length, 1, "Kanten-Identität ignoriert Tag-Felder (Dedup unverändert)");
  assert.equal(edges[0].toTag, 111, "Tag der ersten Übernahme bleibt");
});

// ============================================================================
// Absorptions-Guard (Akkumulations-Fix 2026-10-06, MAX_STATE_CLUSTER_MEMBERS)
// Live-Befund: known-bad-Collector-Adressen sind FLAGGED Knoten, der Hub-
// Schutz von buildClusterGraph gilt für sie nicht — über den Member-
// Überschneidungs-Merge absorbierte ein Mega-Cluster tickweise alle neuen
// Cluster (live: 43.157 Mitglieder), sprengte FLOW_STATE_MAX_BYTES und ließ
// pruneFlowState jeden Tick alle übrigen Cluster fallen. Die Guard-Tests
// reproduzieren genau diese Drainer-Sweep-Form und sichern die bewusste
// Fragmentierungsentscheidung ab.
// ============================================================================

const megaMembers = (n) =>
  Array.from({ length: n }, (_, i) => `rTESTMEGA${String(i).padStart(3, "0")}000000000000001`);

const megaSeed = (n) => ({
  clusters: {
    "cluster:mega": {
      id: "cluster:mega",
      memberAddresses: megaMembers(n),
      roles: { [megaMembers(n)[0]]: "collector" },
      severityByAddress: { [megaMembers(n)[0]]: "malicious" },
      mainDrainers: [],
      collectors: [{ address: megaMembers(n)[0], inDrops: 1000 }],
      peelingChains: [],
      edges: [],
      totalDrops: 1000,
      txCount: 1,
      distinctAccounts: n,
      firstSeen: "2026-10-01T10:00:00Z",
      lastSeen: "2026-10-01T10:00:00Z",
    },
  },
  blocksProcessedTotal: 1,
  lastAdvancedAt: NOW,
});

test("Absorptions-Guard: Mega-State-Cluster (>500 Mitglieder) nimmt kein neues Block-Cluster auf", async () => {
  assert.equal(MAX_STATE_CLUSTER_MEMBERS, 500);
  const iso = "2026-10-01T10:00:00Z";
  const alpha = megaMembers(501)[0]; // geteiltes Mitglied: der Collector des Mega-Clusters
  const beta = "rTESTNEWBETA00000000000000001";
  const pay = (hash, from, to, amount) => ({
    hash, ledger_index: 21, TransactionType: "Payment",
    Account: from, Destination: to, Amount: String(amount), close_time_iso: iso,
  });
  const findings = [{ ruleId: "known-bad-hit", severity: "malicious", address: alpha, note: "fixture" }];
  const res = await advance({
    cursor: 20, budget: 1, now: NOW,
    fetcher: async () => ({ transactions: [pay("H1", alpha, beta, 750)], findings }),
    flowState: megaSeed(501),
  });
  const clusters = Object.values(res.flowState.clusters ?? {});
  assert.equal(clusters.length, 2, "neuer Block-Cluster bleibt EIGENER Eintrag (keine Mega-Absorption)");
  const mega = clusters.find((c) => c.id === "cluster:mega");
  const fresh = clusters.find((c) => c.id !== "cluster:mega");
  assert.equal(mega.memberAddresses.length, 501, "Mega-Cluster wächst nicht weiter an");
  assert.equal(fresh.memberAddresses.length, 2, "neuer Cluster trägt nur seine eigenen Mitglieder");
  assert.ok(fresh.memberAddresses.includes(alpha) && fresh.memberAddresses.includes(beta));
});

test("Absorptions-Guard-Kontrolle: Cluster <=500 Mitglieder vereinigt weiterhin (Merge-Kern unverändert)", async () => {
  const iso = "2026-10-01T10:00:00Z";
  const alpha = megaMembers(500)[0];
  const beta = "rTESTNEWBETA00000000000000001";
  const pay = (hash, from, to, amount) => ({
    hash, ledger_index: 21, TransactionType: "Payment",
    Account: from, Destination: to, Amount: String(amount), close_time_iso: iso,
  });
  const findings = [{ ruleId: "known-bad-hit", severity: "malicious", address: alpha, note: "fixture" }];
  const res = await advance({
    cursor: 20, budget: 1, now: NOW,
    fetcher: async () => ({ transactions: [pay("H1", alpha, beta, 750)], findings }),
    flowState: megaSeed(500),
  });
  const clusters = Object.values(res.flowState.clusters ?? {});
  assert.equal(clusters.length, 1, "unter der Kappe greift die Member-Überschneidungs-Vereinigung wie bisher");
  assert.equal(clusters[0].id, "cluster:mega", "bestehender Key wird nie umbenannt");
  assert.equal(clusters[0].memberAddresses.length, 501, "beta wird als neues Mitglied vereinigt");
});

test("Absorptions-Guard: Entity-Union (Join-Key) erweitert keinen Mega-State-Cluster", async () => {
  const iso = "2026-10-01T10:00:00Z";
  const mega = megaMembers(501);
  const gamma = "rTESTNEWGAMMA00000000000001";
  const delta = "rTESTNEWDELTA00000000000001";
  const pay = (hash, from, to, amount) => ({
    hash, ledger_index: 21, TransactionType: "Payment",
    Account: from, Destination: to, Amount: String(amount), close_time_iso: iso,
  });
  const findings = [{ ruleId: "dusting", severity: "suspect", address: gamma, note: "fixture" }];
  // Join-Key rk: teilen Mega-Mitglied[0] und gamma (2 Besitzer < Hub 20) —
  // ohne Guard würde entityUnionKey den Block-Cluster in den Mega ziehen.
  const entityLinks = new Map([
    [mega[0], ["rk:rTESTRKKEY00000000000000001"]],
    [gamma, ["rk:rTESTRKKEY00000000000000001"]],
  ]);
  const res = await advance({
    cursor: 20, budget: 1, now: NOW,
    fetcher: async () => ({ transactions: [pay("H1", gamma, delta, 750)], findings }),
    flowState: megaSeed(501),
    opts: { entityLinks },
  });
  const clusters = Object.values(res.flowState.clusters ?? {});
  assert.equal(clusters.length, 2, "Join-Key vereinigt nicht in den Mega-Cluster");
  const megaState = clusters.find((c) => c.id === "cluster:mega");
  assert.equal(megaState.memberAddresses.length, 501);
});

// =====================================================================
// V1a — Cross-Block-Peeling: advance() wandert nach dem Walk über die
// akkumulierten State-Kanten (Tick-Schritt). Die Kette S→r1→F→r2→E verteilt
// sich über 4 Blöcke; jede Kante wird nur sichtbar, weil ihr Ziel-/Quell-
// Knoten im jeweiligen Block geflaggt ist — blocklokal wäre die Kette
// unsichtbar (DFRWS: > 50 % der Ketten laufen in > 1 h ab).
// =====================================================================
test("cross-block: advance() erkennt die über 4 Blöcke verteilte Peel-Kette", async () => {
  const S = "rTESTXBSEED000000000000000000001";
  const r1 = "rTESTXBRELAY1000000000000000001";
  const F = "rTESTXBFLAG00000000000000000001";
  const r2 = "rTESTXBRELAY2000000000000000002";
  const E = "rTESTXBEND000000000000000000001";
  const isoFor = (seq) => new Date(Date.parse("2026-10-01T10:00:00Z") + (seq - 11) * 4000).toISOString();
  const pay = (hash, seq, from, to, amount) => ({
    hash, ledger_index: seq, TransactionType: "Payment",
    Account: from, Destination: to, Amount: String(amount), close_time_iso: isoFor(seq),
  });
  const blocks = [
    { transactions: [pay("K1", 11, S, r1, 10000)], findings: [{ ruleId: "dusting", severity: "suspect", address: S, note: "fixture" }] },
    { transactions: [pay("K2", 12, r1, F, 8000)], findings: [{ ruleId: "dusting", severity: "suspect", address: F, note: "fixture" }] },
    { transactions: [pay("K3", 13, F, r2, 6400)], findings: [{ ruleId: "dusting", severity: "suspect", address: F, note: "fixture" }] },
    { transactions: [pay("K4", 14, r2, E, 5120)], findings: [{ ruleId: "drainer-sweep", severity: "malicious", address: E, note: "fixture" }] },
  ];
  let i = 0;
  const res = await advance({
    cursor: 10, budget: 10, now: NOW,
    fetcher: async () => (i < blocks.length ? blocks[i++] : null),
    flowState: {},
  });
  const clusters = Object.values(res.flowState.clusters ?? {});
  const withChains = clusters.filter((c) => Array.isArray(c.peelingChains) && c.peelingChains.length > 0);
  assert.equal(withChains.length, 1, "genau ein Cluster trägt die Cross-Block-Kette");
  const ch = withChains[0].peelingChains.find((c) => c.signature === [S, r1, F, r2, E].join(","));
  assert.ok(ch, "Ketten-Signatur S,r1,F,r2,E vorhanden");
  assert.equal(ch.hopsCount, 4, "vier Hops über die akkumulierten Kanten");
  assert.deepEqual(ch.bridges, [r1, r2], "geflaggte Zwischenknoten sind keine Brücken");
  assert.ok(ch.fingerprint && typeof ch.fingerprint.score === "number", "Fingerprint berechnet");
});

test("cross-block: Rekombination ersetzt veraltete Sichten gleicher Signatur (capChains last-wins)", async () => {
  // Vorbeladener State: die Kante K4 fehlt noch, die alte Ketten-Sicht
  // (hopsCount 3) stammt aus einer früheren Tick-Sicht. Der Tick ohne neue
  // Blöcke rechnet die Kette über den akkumulierten Kantensatz neu — die
  // frischere 4-Hop-Sicht ersetzt die veraltete (gleiche Signatur).
  const S = "rTESTXBSEED000000000000000000001";
  const r1 = "rTESTXBRELAY1000000000000000001";
  const F = "rTESTXBFLAG00000000000000000001";
  const r2 = "rTESTXBRELAY2000000000000000002";
  const E = "rTESTXBEND000000000000000000001";
  const iso = "2026-10-01T10:00:00Z";
  const signature = [S, r1, F, r2, E].join(",");
  const flowState = {
    clusters: {
      "cluster:rTESTXBSEED000000000000000000001": {
        id: "cluster:rTESTXBSEED000000000000000000001",
        memberAddresses: [E, F, S, r1, r2].sort(),
        severityByAddress: { [S]: "suspect", [F]: "suspect", [E]: "malicious" },
        roles: {},
        edges: [
          { from: S, to: r1, type: "Payment", amountDrops: 10000, txHash: "K1", ledgerSeq: 11, closeTime: iso },
          { from: r1, to: F, type: "Payment", amountDrops: 8000, txHash: "K2", ledgerSeq: 12, closeTime: iso },
          { from: F, to: r2, type: "Payment", amountDrops: 6400, txHash: "K3", ledgerSeq: 13, closeTime: iso },
          { from: r2, to: E, type: "Payment", amountDrops: 5120, txHash: "K4", ledgerSeq: 14, closeTime: iso },
        ],
        peelingChains: [
          { addresses: [S, r1, F, r2], hops: [], seed: S, seedSeverity: "suspect", hopsCount: 3, bridges: [r1, r2], signature: "ALT" },
        ],
      },
    },
  };
  const res = await advance({
    cursor: 14, budget: 1, now: NOW,
    fetcher: async () => null, // Live-Edge: kein neuer Block, nur Rekombination
    flowState,
  });
  const c = res.flowState.clusters["cluster:rTESTXBSEED000000000000000000001"];
  const same = c.peelingChains.filter((ch) => ch.signature === signature);
  assert.equal(same.length, 1, "genau eine Sicht der Signatur");
  assert.equal(same[0].hopsCount, 4, "die frischere 4-Hop-Sicht gewinnt");
  assert.ok(c.peelingChains.some((ch) => ch.signature === "ALT"), "fremde Signaturen bleiben (Evidenz-Vertrag)");
});

// =====================================================================
// V3 — Temporale Serie im Cluster-State (Evidenz-Adressen, Guard a/b,
// Serien-Kappe). Matrix über Aktivität, Evidenz und Registry-Ausschluss.
// =====================================================================
test("temporal: advance() akkumuliert die Aus-Serie der Evidenz-Adresse", async () => {
  const S = "rTESTTPSEED000000000000000000001";
  const d1 = "rTESTTPDEST10000000000000000001";
  const d2 = "rTESTTPDEST20000000000000000002";
  const iso = "2026-10-01T10:00:00Z";
  const pay = (hash, seq, from, to, amount) => ({
    hash, ledger_index: seq, TransactionType: "Payment",
    Account: from, Destination: to, Amount: String(amount), close_time_iso: iso,
  });
  const findings = [{ ruleId: "dusting", severity: "suspect", address: S, note: "fixture" }];
  const blocks = [
    { transactions: [pay("T1", 21, S, d1, 1000)], findings },
    { transactions: [pay("T2", 22, S, d2, 1500)], findings },
  ];
  let i = 0;
  const res = await advance({
    cursor: 20, budget: 5, now: NOW,
    fetcher: async () => (i < blocks.length ? blocks[i++] : null),
    flowState: {},
  });
  const c = Object.values(res.flowState.clusters ?? {})[0];
  assert.ok(c.temporal && c.temporal[S], "Evidenz-Adresse trägt eine Serie");
  assert.deepEqual(c.temporal[S].s, [21, 22], "Ledger-Indizes der Aus-Kanten asc");
  assert.equal(c.temporal[S].out, 2500, "out-Volumen addiert sich");
  assert.equal(c.temporal[S].outN, 2);
  assert.ok(!c.temporal[d1] && !c.temporal[d2], "Nur-Empfänger ohne Evidenz bekommen keine Serie (Guard a)");
});

test("temporal: Registry-/Multi-User-Adressen werden nie gesammelt (Guard b)", async () => {
  const S = "rTESTTQSEED000000000000000000001";
  const ex = "rTESTTQEXCHANGE000000000000001";
  const iso = "2026-10-01T10:00:00Z";
  const pay = (hash, seq, from, to, amount) => ({
    hash, ledger_index: seq, TransactionType: "Payment",
    Account: from, Destination: to, Amount: String(amount), close_time_iso: iso,
  });
  const findings = [
    { ruleId: "dusting", severity: "suspect", address: S, note: "fixture" },
    { ruleId: "known-bad-hit", severity: "malicious", address: ex, note: "fixture" },
  ];
  const multiUser = new Map([[ex, { exchange: "Test Exchange", tier: 1 }]]);
  // Zwei geflaggte Absender in einem Block: ex (Registry -> Guard b) und S
  // (frei -> Serie). Beide Kanten existieren (geflaggte Endpunkte).
  const dest1 = "rTESTTQDEST10000000000000000001";
  const dest2 = "rTESTTQDEST20000000000000000002";
  const res = await advance({
    cursor: 30, budget: 1, now: NOW,
    fetcher: async () => ({
      transactions: [pay("T1", 31, ex, dest1, 1000), pay("T2", 31, S, dest2, 2000)],
      findings,
    }),
    flowState: {},
    opts: { multiUserAccounts: multiUser },
  });
  const c = Object.values(res.flowState.clusters ?? {})[0];
  assert.ok(c.temporal && c.temporal[S], "freiwilliger geflaggter Absender erhält eine Serie");
  assert.deepEqual(c.temporal[S].s, [31]);
  assert.ok(!c.temporal[ex], "Registry-Adresse bekommt nie eine Serie (Guard b)");
  assert.ok(!c.temporal[dest1] && !c.temporal[dest2], "Empfänger ohne eigene Aus-Kante erhalten keine Serie");
});

test("temporal: Serien-Kappe behält die neuesten TEMPORAL_SERIES_CAP Punkte", async () => {
  const S = "rTESTTRSEED000000000000000000001";
  const iso = "2026-10-01T10:00:00Z";
  const pay = (hash, seq) => ({
    hash, ledger_index: seq, TransactionType: "Payment",
    Account: S, Destination: `rTESTTRD${String(seq).padStart(3, "0")}00000000000000000001`,
    Amount: "100", close_time_iso: iso,
  });
  const findings = [{ ruleId: "dusting", severity: "suspect", address: S, note: "fixture" }];
  const n = 20; // > TEMPORAL_SERIES_CAP
  let i = 0;
  const res = await advance({
    cursor: 40, budget: n + 2, now: NOW,
    fetcher: async () => {
      if (i >= n) return null;
      const seq = 41 + i;
      i += 1;
      return { transactions: [pay(`T${seq}`, seq)], findings };
    },
    flowState: {},
  });
  const c = Object.values(res.flowState.clusters ?? {})[0];
  assert.ok(c.temporal && c.temporal[S], "Serie vorhanden");
  assert.ok(c.temporal[S].s.length <= TEMPORAL_SERIES_CAP, "Kappe hält die Serienlänge");
  const newest = [];
  for (let seq = 41 + n - TEMPORAL_SERIES_CAP; seq < 41 + n; seq++) newest.push(seq);
  assert.deepEqual(c.temporal[S].s, newest, "die NEUESTEN Punkte überleben (LRU)");
});
