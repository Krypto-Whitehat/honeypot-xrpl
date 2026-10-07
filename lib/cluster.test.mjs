// lib/cluster.test.mjs — node:test-Unit-Tests mit synthetischen Fixtures.
// Muster wie lib/detector.test.mjs: synthetische rTEST…-Adressen (keine
// echten, keine Köder). Ausführen: node --test lib/cluster.test.mjs
import test from "node:test";
import assert from "node:assert/strict";
import {
  buildClusterGraph,
  txRecordFromEntry,
  ROLE_THRESHOLDS,
  detectPeelingChains,
  detectPeelingChainsOverEdges,
  PEELING_THRESHOLDS,
  PEELING_REMAINDER_THRESHOLDS,
  CROSS_BLOCK_PEELING_THRESHOLDS,
  peelChainFingerprint,
  PEELING_FINGERPRINT_THRESHOLDS,
  temporalMetrics,
  TEMPORAL_THRESHOLDS,
  TEMPORAL_SERIES_CAP,
  TEMPORAL_MAX_ADDRESSES,
  LEDGER_INTERVAL_MS,
  motifCounters,
  MOTIF_THRESHOLDS,
} from "./cluster.mjs";

// Synthetische Adressen (keine echten, keine Köder).
const R = {
  s1: "rTESTSRC1000000000000000000000001",
  s2: "rTESTSRC2000000000000000000000002",
  s3: "rTESTSRC3000000000000000000000003",
  drain: "rTESTDRAIN0000000000000000000001",
  coll: "rTESTCOLLECTOR0000000000000000001",
  t1: "rTESTT100000000000000000000000001",
  t2: "rTESTT200000000000000000000000002",
  t3: "rTESTT300000000000000000000000003",
  relay: "rTESTRELAY000000000000000000001",
  a1: "rTESTA100000000000000000000000001",
  a2: "rTESTA200000000000000000000000002",
  b1: "rTESTB100000000000000000000000001",
  b2: "rTESTB200000000000000000000000002",
  alpha: "rTESTALPHA000000000000000000001",
  beta: "rTESTBETA0000000000000000000001",
  gamma: "rTESTGAMMA000000000000000000001",
  x1: "rTESTX100000000000000000000000001",
  x2: "rTESTX200000000000000000000000002",
  y1: "rTESTY100000000000000000000000001",
  y2: "rTESTY200000000000000000000000002",
  iso: "2026-09-28T18:38:31Z",
};

const tx = (hash, ledgerSeq, type, account, destination, amountDrops, closeTime = R.iso) => ({
  hash, ledgerSeq, closeTime, type, account, destination, amountDrops,
});
const finding = (address, severity = "suspect", ruleId = "dusting") => ({
  ruleId, severity, address, note: "fixture",
});
const roleOf = (g, addr) => g.clusters[0]?.roles[addr] ?? g.nodes.find((n) => n.id === addr)?.role;

// ---------- 1) Leere Eingabe + Export-Form ----------
test("leere Eingabe -> leere Graph-Struktur; ROLE_THRESHOLDS vollständig", () => {
  const g = buildClusterGraph([], []);
  assert.deepEqual(g, { clusters: [], nodes: [], edges: [] });
  assert.deepEqual(Object.keys(ROLE_THRESHOLDS).sort(), [
    "collectorMaxOut", "collectorMinIn", "relayBalance", "sourceMinOut", "sourceSmallDrops", "sweepRatio",
  ]);
  assert.equal(ROLE_THRESHOLDS.sweepRatio, 0.9);
  assert.equal(ROLE_THRESHOLDS.collectorMinIn, 3);
  assert.equal(ROLE_THRESHOLDS.collectorMaxOut, 1);
  assert.equal(ROLE_THRESHOLDS.sourceMinOut, 3);
  assert.equal(ROLE_THRESHOLDS.sourceSmallDrops, 100000);
  assert.equal(ROLE_THRESHOLDS.relayBalance, 0.5);
});

// ---------- 2) Kette A->B->C + Edge-Feldvollständigkeit ----------
test("Kette A->B->C: eine Komponente, Kanten nur bei flagged Endpunkten, Edge-Felder vollständig", () => {
  const txs = [
    tx("H1", 10, "Payment", R.alpha, R.beta, 1000),
    tx("H2", 11, "Payment", R.beta, R.gamma, 900),
  ];
  const g = buildClusterGraph(txs, [finding(R.alpha), finding(R.gamma, "malicious", "drainer-sweep")]);
  assert.equal(g.edges.length, 2);
  assert.equal(g.edges[0].ledgerSeq, 10); // Sortierung ledgerSeq asc
  assert.equal(g.edges[1].ledgerSeq, 11);
  for (const e of g.edges) {
    for (const key of ["from", "to", "type", "amountDrops", "txHash", "ledgerSeq", "closeTime"]) {
      assert.ok(key in e, `Edge-Feld ${key} fehlt`);
    }
    assert.equal(e.type, "Payment");
    assert.equal(e.closeTime, R.iso);
  }
  assert.equal(g.clusters.length, 1);
  assert.deepEqual(g.clusters[0].memberAddresses, [R.alpha, R.beta, R.gamma].sort());
  assert.equal(g.clusters[0].txCount, 2);
  assert.equal(g.clusters[0].totalDrops, 1900);
  assert.equal(g.clusters[0].distinctAccounts, 3);
  // B ist nicht flagged -> severity null, aber Knoten über die Kanten.
  const nodeB = g.nodes.find((n) => n.id === R.beta);
  assert.equal(nodeB.severity, null);
  assert.equal(nodeB.clusterId, g.clusters[0].id);
  assert.equal(g.nodes.find((n) => n.id === R.gamma).severity, "malicious");
});

// ---------- 3) Kantenregel ohne Finding ----------
test("Kantenregel: tx zwischen zwei unflagged Adressen erzeugt nichts", () => {
  const txs = [tx("H1", 10, "Payment", R.alpha, R.beta, 1000)];
  const g = buildClusterGraph(txs, []);
  assert.deepEqual(g.edges, []);
  assert.deepEqual(g.nodes, []);
  assert.deepEqual(g.clusters, []);
});

// ---------- 4) Nur destination in findings ----------
test("Kantenregel: nur die destination flagged -> Kante entsteht", () => {
  const txs = [tx("H1", 10, "Payment", R.alpha, R.beta, 1000)];
  const g = buildClusterGraph(txs, [finding(R.beta)]);
  assert.equal(g.edges.length, 1);
  assert.equal(g.edges[0].from, R.alpha);
  assert.equal(g.edges[0].to, R.beta);
  assert.equal(g.nodes.length, 2);
  assert.equal(g.clusters.length, 1);
});

// ---------- 5) maxEdges-Kappung ----------
test("maxEdges-Kappung: neueste Kanten nach ledgerSeq bleiben", () => {
  const txs = [];
  for (let i = 1; i <= 10; i++) txs.push(tx(`H${i}`, i, "Payment", R.s1, R[`t${(i % 3) + 1}`], 100));
  const g = buildClusterGraph(txs, [finding(R.s1, "suspect", "payment-burst")], { maxEdges: 4 });
  assert.equal(g.edges.length, 4);
  assert.deepEqual(g.edges.map((e) => e.ledgerSeq), [7, 8, 9, 10]);
  assert.equal(g.nodes.length, 4); // s1 + die 3 Ziele der gekappten Kanten (t1,t2,t3)
  assert.equal(g.clusters[0].txCount, 4);
});

// ---------- 6) minClusterSize-Guard ----------
test("minClusterSize: 2er-Komponente nur bei Default 2, Guard bei 3 -> clusterId null", () => {
  const txs = [tx("H1", 10, "Payment", R.alpha, R.beta, 1000)];
  const gDefault = buildClusterGraph(txs, [finding(R.alpha)]);
  assert.equal(gDefault.clusters.length, 1);
  const gGuard = buildClusterGraph(txs, [finding(R.alpha)], { minClusterSize: 3 });
  assert.deepEqual(gGuard.clusters, []);
  assert.equal(gGuard.nodes.length, 2);
  for (const n of gGuard.nodes) assert.equal(n.clusterId, null);
});

// ---------- 7) Drainer-Fall ----------
test("Drainer: empfängt klein und fegt >= 90 % an EIN Ziel ab", () => {
  const txs = [
    tx("H1", 10, "Payment", R.s1, R.drain, 1000),
    tx("H2", 11, "Payment", R.s2, R.drain, 1000),
    tx("H3", 12, "Payment", R.drain, R.coll, 1900),
  ];
  // Gegenparteien-Bindung: drainer verlangt mindestens einen geflaggten
  // Sender — ohne geflaggte Opfer-Adressen ist eine Weiterleitung nicht
  // von benignem Konsolidierungsfluss zu unterscheiden.
  const g = buildClusterGraph(txs, [finding(R.drain, "malicious", "drainer-sweep"), finding(R.s1)]);
  assert.equal(roleOf(g, R.drain), "drainer");
  assert.equal(roleOf(g, R.coll), "unknown"); // nur 1 Eingang -> kein collector
  assert.deepEqual(g.clusters[0].mainDrainers, [{ address: R.drain, outDrops: 1900 }]);
  assert.deepEqual(g.clusters[0].collectors, []);
});

// ---------- 8) Collector-Fall ----------
test("Collector: >= 3 Eingänge von verschiedenen (geflaggten) Sendern, kaum ausgehend", () => {
  const txs = [
    tx("H1", 10, "Payment", R.t1, R.coll, 1000),
    tx("H2", 11, "Payment", R.t2, R.coll, 1000),
    tx("H3", 12, "Payment", R.t3, R.coll, 1000),
  ];
  // Gegenparteien-Bindung: >= 3 Eingänge von geflaggten Sendern.
  const g = buildClusterGraph(txs, [finding(R.coll), finding(R.t1)]);
  assert.equal(roleOf(g, R.coll), "collector");
  assert.deepEqual(g.clusters[0].collectors, [{ address: R.coll, inDrops: 3000 }]);
});

// ---------- 9) Source-Fall ----------
test("Source: >= 3 kleine Out-Kanten an geflaggte Ziele, kaum In", () => {
  const txs = [
    tx("H1", 10, "Payment", R.s1, R.t1, 1000),
    tx("H2", 11, "Payment", R.s1, R.t2, 1000),
    tx("H3", 12, "Payment", R.s1, R.t3, 1000),
  ];
  // Gegenparteien-Bindung: source nur, wenn mindestens ein Ziel geflaggt ist
  // (Faucet-Distributoren an unflaggte Ziele verlieren die Betrüger-Lables).
  const g = buildClusterGraph(txs, [finding(R.s1), finding(R.t1)]);
  assert.equal(roleOf(g, R.s1), "source");
  assert.equal(roleOf(g, R.t1), "unknown");
});

// ---------- 10) Relay-Fall ----------
test("Relay: ausgewogener Fluss innerhalb relayBalance (kein Sweep)", () => {
  const txs = [
    tx("H1", 10, "Payment", R.a1, R.relay, 2500),
    tx("H2", 11, "Payment", R.a2, R.relay, 2500),
    tx("H3", 12, "Payment", R.relay, R.b1, 2500),
    tx("H4", 13, "Payment", R.relay, R.b2, 2500),
  ];
  const g = buildClusterGraph(txs, [finding(R.relay)]);
  assert.equal(roleOf(g, R.relay), "relay");
});

// ---------- 11) Dusting-Quelle -> Drainer -> Kollektor (Vollcluster) ----------
test("Dusting-Cluster: 3 Quellen -> Drainer -> Kollektor, Rollen + mainDrainers/collectors + Label", () => {
  const txs = [];
  let h = 0;
  for (const s of [R.s1, R.s2, R.s3]) {
    for (let i = 0; i < 3; i++) txs.push(tx(`D${++h}`, 10 + h, "Payment", s, R.drain, 1000));
  }
  txs.push(tx("SWEEP", 30, "Payment", R.drain, R.coll, 8500));
  txs.push(tx("T1", 31, "Payment", R.t1, R.coll, 1000));
  txs.push(tx("T2", 32, "Payment", R.t2, R.coll, 1000));
  txs.push(tx("T3", 33, "Payment", R.t3, R.coll, 1000));
  const findings = [
    finding(R.s1), finding(R.s2), finding(R.s3),
    finding(R.drain, "malicious", "drainer-sweep"),
    finding(R.coll, "suspect", "payment-burst"),
  ];
  const g = buildClusterGraph(txs, findings);
  assert.equal(g.clusters.length, 1);
  const c = g.clusters[0];
  assert.equal(c.label, "Cluster A");
  assert.equal(c.id, `cluster:${[R.s1, R.s2, R.s3, R.drain, R.coll, R.t1, R.t2, R.t3].sort()[0]}`);
  assert.equal(c.memberAddresses.length, 8);
  assert.equal(c.txCount, 13);
  assert.equal(c.totalDrops, 9 * 1000 + 8500 + 3 * 1000);
  assert.equal(c.distinctAccounts, 8);
  assert.equal(c.firstSeen, R.iso);
  assert.equal(c.lastSeen, R.iso);
  assert.equal(c.roles[R.s1], "source");
  assert.equal(c.roles[R.s2], "source");
  assert.equal(c.roles[R.s3], "source");
  assert.equal(c.roles[R.drain], "drainer"); // Sweep 8500 >= 0.9 * 9000
  assert.equal(c.roles[R.coll], "collector"); // 4 Eingänge von 4 Sendern, 0 ausgehend
  assert.equal(c.roles[R.t1], "unknown");
  assert.deepEqual(c.mainDrainers, [{ address: R.drain, outDrops: 8500 }]);
  assert.deepEqual(c.collectors, [{ address: R.coll, inDrops: 11500 }]);
});

// ---------- 12) Determinismus + Labels ----------
test("Determinismus: Eingabe-Shuffle ändert die Ausgabe nicht; Labels 'Cluster A','Cluster B' nach totalDrops", () => {
  const txs = [
    tx("X1", 10, "Payment", R.x1, R.x2, 5000),
    tx("Y1", 11, "Payment", R.y1, R.y2, 1000),
  ];
  const findings = [finding(R.x1, "malicious", "known-bad-hit"), finding(R.y2)];
  const g1 = buildClusterGraph(txs, findings);
  const g2 = buildClusterGraph([...txs].reverse(), [...findings].reverse());
  assert.equal(JSON.stringify(g1), JSON.stringify(g2));
  assert.equal(g1.clusters.length, 2);
  assert.equal(g1.clusters[0].label, "Cluster A");
  assert.equal(g1.clusters[0].totalDrops, 5000);
  assert.equal(g1.clusters[1].label, "Cluster B");
  assert.equal(g1.clusters[1].totalDrops, 1000);
  // Knoten by id asc
  const ids = g1.nodes.map((n) => n.id);
  assert.deepEqual(ids, [...ids].sort());
});

// ---------- 13) txRecordFromEntry: drei Formen + closeTime-Priorität ----------
test("txRecordFromEntry: {tx_json}/{tx}/flach identisch; close_time_iso > close_time (946684800-Offset) > fallbackCloseIso", () => {
  const core = { TransactionType: "Payment", Account: R.alpha, Destination: R.beta, Amount: "500" };
  const r1 = txRecordFromEntry({ hash: "H", ledger_index: 100, tx_json: core, metaData: {} });
  const r2 = txRecordFromEntry({ hash: "H", ledger_index: 100, tx: core });
  const r3 = txRecordFromEntry({ hash: "H", ledger_index: 100, ...core });
  assert.deepEqual(r1, r2);
  assert.deepEqual(r1, r3);
  assert.deepEqual(r1, {
    hash: "H", ledgerSeq: 100, closeTime: null, type: "Payment",
    account: R.alpha, destination: R.beta, amountDrops: 500,
  });
  // Priorität 1: close_time_iso der Entry gewinnt gegen close_time UND Fallback.
  const rIso = txRecordFromEntry(
    { hash: "H", ledger_index: 100, close_time_iso: R.iso, close_time: 815020711, ...core },
    "2020-01-01T00:00:00Z"
  );
  assert.equal(rIso.closeTime, R.iso);
  // Priorität 2: close_time -> ISO via 946684800-Offset (Muster api/ledger.js:121-125).
  const rCt = txRecordFromEntry({ hash: "H", ledger_index: 100, close_time: 0, ...core }, "2020-01-01T00:00:00Z");
  assert.equal(rCt.closeTime, "2000-01-01T00:00:00.000Z");
  // Priorität 3 (Korrektur E): Entry OHNE close_time-Felder + Fallback -> Fallback.
  const rFb = txRecordFromEntry({ hash: "H", ledger_index: 100, ...core }, R.iso);
  assert.equal(rFb.closeTime, R.iso);
  // Entry MIT close_time_iso -> eigener Wert gewinnt gegen Fallback.
  const rOwn = txRecordFromEntry({ hash: "H", ledger_index: 100, close_time_iso: "2026-01-01T00:00:00Z", ...core }, R.iso);
  assert.equal(rOwn.closeTime, "2026-01-01T00:00:00Z");
  // IOU -> amountDrops null; ungueltige Entry -> null.
  const iou = txRecordFromEntry({ hash: "H", ledger_index: 1, TransactionType: "Payment", Account: R.alpha, Destination: R.beta, Amount: { currency: "USD", issuer: R.gamma, value: "10" } });
  assert.equal(iou.amountDrops, null);
  assert.equal(txRecordFromEntry(null), null);
  assert.equal(txRecordFromEntry({ Account: R.alpha }), null);
});

// ---------- 14) amountDrops null (IOU): Kante bleibt, Summen zählen 0 ----------
test("IOU-Kante: amountDrops null -> Edge vorhanden, totalDrops 0, iouFlows trägt die IOU-Summe", () => {
  const txs = [{ hash: "H1", ledgerSeq: 10, closeTime: R.iso, type: "Payment", account: R.s1, destination: R.coll, amountDrops: null, iouValue: { currency: "USD", issuer: R.gamma, value: 10 } }];
  const g = buildClusterGraph(txs, [finding(R.s1)]);
  assert.equal(g.edges.length, 1);
  assert.equal(g.edges[0].amountDrops, null);
  assert.equal(g.clusters[0].totalDrops, 0); // XRP-Skala bleibt XRP-only
  assert.equal(g.nodes.find((n) => n.id === R.s1).outDrops, 0);
  // IOU-Sicht: separater Aggregat ohne erfundene XRP-Skala.
  assert.deepEqual(g.clusters[0].iouFlows, [{ currency: "USD", issuer: R.gamma, value: 10 }]);
});

// ---------- 15) severity-Max pro Adresse ----------
test("severity-Max: suspect+info -> 'suspect'; malicious schlägt suspect", () => {
  const txs = [tx("H1", 10, "Payment", R.alpha, R.beta, 1000)];
  const g = buildClusterGraph(txs, [
    finding(R.alpha, "info", "offer-spam"),
    finding(R.alpha, "suspect", "dusting"),
    finding(R.beta, "suspect", "payment-burst"),
    finding(R.beta, "malicious", "known-bad-hit"),
  ]);
  assert.equal(g.nodes.find((n) => n.id === R.alpha).severity, "suspect");
  assert.equal(g.nodes.find((n) => n.id === R.beta).severity, "malicious");
});

// ---------- 16) False-Positive behoben (Gegenparteien-Bindung) ----------
// Der früher dokumentierte FP — ein harmloser Mehrfachempfänger mit 3
// Mini-Eingängen und einer Sammelzahlung wurde als collector klassifiziert —
// ist durch die Gegenparteien-Bindung behoben: ohne geflaggte Sender bleibt
// der harmlose Empfänger 'unknown' (keine geflaggte Gegenpartei -> kein
// collector; unausgeglichener Fluss -> kein relay).
// Der Disclaimer in index.html kennzeichnet Rollen weiterhin als Heuristik
// ohne Schuldnachweis.
test("FP behoben: harmloser Mehrfachempfänger ohne geflaggte Sender bleibt unknown", () => {
  const txs = [
    tx("H1", 10, "Payment", R.t1, R.coll, 1000),
    tx("H2", 11, "Payment", R.t2, R.coll, 1000),
    tx("H3", 12, "Payment", R.t3, R.coll, 1000),
    tx("H4", 13, "Payment", R.coll, R.gamma, 1000),
  ];
  const g = buildClusterGraph(txs, [finding(R.coll)]);
  assert.equal(roleOf(g, R.coll), "unknown");
  assert.equal(g.clusters[0].mainDrainers.length, 0);
});

// ---------- 17) Regression (Befund 2026-09-29): 1-in/1-out-Durchleitung ----------
// Eine einzelne Ein-/Ausgangs-Kante mit >= 90 % Weiterleitung ist KEIN Drainer
// mehr (nicht von benignem Durchleitungsfluss unterscheidbar) und fällt an die
// Relay-Regel; mainDrainers bleibt leer. Gleiches gilt, wenn derselbe Zufluss
// nur über denselben Sender in mehrere Kanten aufgeteilt ist (distinctIn = 1).
// Der Drainer-Kern (Sweep aus >= 2 verschiedenen Quellen, Tests 7/11) bleibt.
test("Regression: benign 1-in/1-out-Durchleitung -> relay, nicht drainer", () => {
  // 100 % Weiterleitung, ein Sender (Audit-EXP2-Form).
  const g = buildClusterGraph(
    [tx("H1", 10, "Payment", R.alpha, R.beta, 1000), tx("H2", 11, "Payment", R.beta, R.gamma, 1000)],
    [finding(R.beta)]
  );
  assert.equal(roleOf(g, R.beta), "relay");
  assert.deepEqual(g.clusters[0].mainDrainers, []);
  // 95 % Weiterleitung, aber weiterhin nur EIN Sender (Audit-EXP10-Form).
  const g95 = buildClusterGraph(
    [tx("H1", 10, "Payment", R.alpha, R.beta, 1000), tx("H2", 11, "Payment", R.beta, R.gamma, 950)],
    [finding(R.beta)]
  );
  assert.equal(roleOf(g95, R.beta), "relay");
  // Aufteilung desselben Zuflusses über denselben Sender: distinctIn = 1.
  const gSplit = buildClusterGraph(
    [
      tx("H1", 10, "Payment", R.alpha, R.beta, 1000),
      tx("H2", 11, "Payment", R.alpha, R.beta, 1000),
      tx("H3", 12, "Payment", R.beta, R.t1, 1900),
    ],
    [finding(R.beta)]
  );
  assert.equal(roleOf(gSplit, R.beta), "relay");
  // Gegenstück: Sweep aus 2 verschiedenen Quellen bleibt Drainer (Test-7-Kern)
  // — mit geflaggtem Sender (Gegenparteien-Bindung: alpha ist geflaggt).
  const gTwo = buildClusterGraph(
    [
      tx("H1", 10, "Payment", R.alpha, R.beta, 1000),
      tx("H2", 11, "Payment", R.gamma, R.beta, 1000),
      tx("H3", 12, "Payment", R.beta, R.t1, 1900),
    ],
    [finding(R.beta, "malicious", "drainer-sweep"), finding(R.alpha)]
  );
  assert.equal(roleOf(gTwo, R.beta), "drainer");
  assert.deepEqual(gTwo.clusters[0].mainDrainers, [{ address: R.beta, outDrops: 1900 }]);
});

// ---------- 18) Regression (Befund 2026-09-29): Determinismus ohne hash+seq ----------
// Kanten mit txHash=null UND ledgerSeq=null: der cmpEdge-Tie-Break über
// from/to macht die Ausgabe unabhängig von der Eingabereihenfolge.
test("Regression: Shuffle bei null hash+seq liefert identische edges", () => {
  const a = { hash: null, ledgerSeq: null, closeTime: R.iso, type: "Payment", account: R.alpha, destination: R.beta, amountDrops: 1000 };
  const b = { hash: null, ledgerSeq: null, closeTime: R.iso, type: "Payment", account: R.gamma, destination: R.beta, amountDrops: 900 };
  const g1 = buildClusterGraph([a, b], [finding(R.beta)]);
  const g2 = buildClusterGraph([b, a], [finding(R.beta)]);
  assert.deepEqual(g1.edges, g2.edges);
});

// ---------- 18b) Regression (Befund 2026-09-29): Shuffle bei IDENTISCHEN
// Endpunkten + null hash/seq, verschieden in type/amountDrops/closeTime.
// Die Stufen 5-8 der cmpEdge-Kette (type, amountDrops, closeTime chronologisch,
// closeTime-Rohstring) brechen den Fall — vor dem Fix entschied die
// Eingabereihenfolge (verifizierter Fall: zwei Kanten rA->rB, Betraege 100/200,
// Shuffle lieferte DIFFERS). Totalordnung gilt fuer Kanten, die in einem der
// sieben Kantenfelder differieren; exakte Duplikate bleiben vergleichsgleich
// (0), sind aber ununterscheidbar -> Ausgabe identisch.
test("Regression: Shuffle identischer Endpunkte mit null hash+seq, verschieden in type/amountDrops/closeTime", () => {
  const a = { hash: null, ledgerSeq: null, closeTime: "2026-09-28T10:00:00Z", type: "Payment", account: R.alpha, destination: R.beta, amountDrops: 100 };
  const b = { hash: null, ledgerSeq: null, closeTime: "2026-09-28T10:00:01Z", type: "TrustSet", account: R.alpha, destination: R.beta, amountDrops: 200 };
  const g1 = buildClusterGraph([a, b], [finding(R.beta)]);
  const g2 = buildClusterGraph([b, a], [finding(R.beta)]);
  assert.deepEqual(g1.edges, g2.edges);
  assert.deepEqual(g1, g2);
  // Deterministische Reihenfolge: Stufe 5 type asc ('Payment' < 'TrustSet').
  assert.equal(g1.edges[0].type, "Payment");
  assert.equal(g1.edges[1].type, "TrustSet");
  // Der reine Betrags-Fall (type gleich, nur Betraege 100/200 verschieden):
  const c = { hash: null, ledgerSeq: null, closeTime: "2026-09-28T10:00:00Z", type: "Payment", account: R.alpha, destination: R.beta, amountDrops: 100 };
  const d = { hash: null, ledgerSeq: null, closeTime: "2026-09-28T10:00:00Z", type: "Payment", account: R.alpha, destination: R.beta, amountDrops: 200 };
  const g3 = buildClusterGraph([c, d], [finding(R.beta)]);
  const g4 = buildClusterGraph([d, c], [finding(R.beta)]);
  assert.deepEqual(g3.edges, g4.edges);
  assert.deepEqual(g3, g4);
  assert.equal(g3.edges[0].amountDrops, 100);
  assert.equal(g3.edges[1].amountDrops, 200);
  // Exakte Duplikate: cmpEdge liefert 0, aber die Ausgabe ist identisch.
  const g5 = buildClusterGraph([c, { ...c }], [finding(R.beta)]);
  const g6 = buildClusterGraph([{ ...c }, c], [finding(R.beta)]);
  assert.deepEqual(g5, g6);
});

// ---------- 18c) Regression (Befund 2026-09-29): gemischte closeTime-Formate
// ('Z' vs '.000Z' vs '+00:00') werden chronologisch sortiert, nicht lexikalisch
// (Pruefer-Reproduktion: '2026-09-28T10:00:00Z' < '2026-09-28T10:00:00.500Z'
// lex FALSE / chronologisch TRUE).
test("Regression: gemischte closeTime-Formate chronologisch sortiert, Shuffle-stabil", () => {
  const a = { hash: null, ledgerSeq: null, closeTime: "2026-09-28T10:00:00.500Z", type: "Payment", account: R.alpha, destination: R.beta, amountDrops: 100 };
  const b = { hash: null, ledgerSeq: null, closeTime: "2026-09-28T10:00:00Z", type: "Payment", account: R.alpha, destination: R.beta, amountDrops: 100 };
  const c = { hash: null, ledgerSeq: null, closeTime: "2026-09-28T10:00:01+00:00", type: "Payment", account: R.alpha, destination: R.beta, amountDrops: 100 };
  const g1 = buildClusterGraph([a, b, c], [finding(R.beta)]);
  const g2 = buildClusterGraph([c, b, a], [finding(R.beta)]);
  assert.deepEqual(g1.edges, g2.edges);
  assert.deepEqual(g1, g2);
  assert.deepEqual(g1.edges.map((e) => e.closeTime), [
    "2026-09-28T10:00:00Z",
    "2026-09-28T10:00:00.500Z",
    "2026-09-28T10:00:01+00:00",
  ]);
});

// ---------- 18d) Regression (Befund 2026-09-29): firstSeen/lastSeen bei
// gemischten closeTime-Formaten chronologisch korrekt (vor dem Fix war
// firstSeen lexikalisch '…10:00:00.500Z' statt '…10:00:00Z').
test("Regression: firstSeen/lastSeen bei gemischten closeTime-Formaten chronologisch korrekt", () => {
  const a = { hash: null, ledgerSeq: null, closeTime: "2026-09-28T10:00:00.500Z", type: "Payment", account: R.alpha, destination: R.beta, amountDrops: 100 };
  const b = { hash: null, ledgerSeq: null, closeTime: "2026-09-28T10:00:00Z", type: "Payment", account: R.alpha, destination: R.beta, amountDrops: 100 };
  const c = { hash: null, ledgerSeq: null, closeTime: "2026-09-28T10:00:01+00:00", type: "Payment", account: R.alpha, destination: R.beta, amountDrops: 100 };
  const g1 = buildClusterGraph([a, b, c], [finding(R.beta)]);
  const g2 = buildClusterGraph([c, b, a], [finding(R.beta)]);
  assert.deepEqual(g1, g2);
  assert.equal(g1.clusters[0].firstSeen, "2026-09-28T10:00:00Z");
  assert.equal(g1.clusters[0].lastSeen, "2026-09-28T10:00:01+00:00");
});

// ---------- 19) Regression (Befund 2026-09-29): maxEdges nicht ganzzahlig ----------
test("Regression: maxEdges=4.5 trunciert auf 4 Kanten", () => {
  const txs = [
    tx("H1", 10, "Payment", R.alpha, R.beta, 1000),
    tx("H2", 11, "Payment", R.beta, R.gamma, 900),
    tx("H3", 12, "Payment", R.gamma, R.t1, 800),
    tx("H4", 13, "Payment", R.t1, R.t2, 700),
    tx("H5", 14, "Payment", R.t2, R.t3, 600),
  ];
  const g = buildClusterGraph(txs, [finding(R.beta), finding(R.gamma), finding(R.t1), finding(R.t2)], { maxEdges: 4.5 });
  assert.equal(g.edges.length, 4);
});

// ---------- 20) Isolated-Zweig: tx ohne/gleiche Destination -> Knoten ohne Kante ----------
test("Isolated: tx ohne Destination und Selbsttransaktion erzeugen Knoten ohne Kanten", () => {
  const noDest = { hash: "H1", ledgerSeq: 10, closeTime: R.iso, type: "OfferCreate", account: R.alpha, amountDrops: null };
  const selfTx = { hash: "H2", ledgerSeq: 11, closeTime: R.iso, type: "Payment", account: R.beta, destination: R.beta, amountDrops: 500 };
  const g = buildClusterGraph([noDest, selfTx], [finding(R.alpha), finding(R.beta)]);
  assert.equal(g.edges.length, 0);
  assert.equal(g.clusters.length, 0);
  const na = g.nodes.find((n) => n.id === R.alpha);
  const nb = g.nodes.find((n) => n.id === R.beta);
  assert.ok(na && nb);
  assert.equal(na.clusterId, null);
  assert.equal(nb.clusterId, null);
});

// =====================================================================
// Neue Regressionstests (Audit-Proben P2/P4/P5/P8/P11 + TrustSet-Integration)
// =====================================================================

// ---------- 21) IOU-only-Sweep derselben Währung -> drainer statt relay ----------
// Audit-Probe P4: 100 % IOU-Weiterleitung war relay mit totalDrops 0.
// Jetzt: Sweep-Verhältnis wertungsneutral aus IOU-Werten (keine value*1e6-Skala).
test("IOU-Sweep: 100 % Weiterleitung derselben currency+issuer -> drainer", () => {
  const iou = (v) => ({ currency: "usdt", issuer: R.gamma, value: v });
  const txs = [
    { hash: "H1", ledgerSeq: 10, closeTime: R.iso, type: "Payment", account: R.s1, destination: R.drain, amountDrops: null, iouValue: iou(50) },
    { hash: "H2", ledgerSeq: 11, closeTime: R.iso, type: "Payment", account: R.s2, destination: R.drain, amountDrops: null, iouValue: iou(50) },
    { hash: "H3", ledgerSeq: 12, closeTime: R.iso, type: "Payment", account: R.drain, destination: R.coll, amountDrops: null, iouValue: iou(100) },
  ];
  const g = buildClusterGraph(txs, [finding(R.s1), finding(R.s2), finding(R.drain, "malicious", "drainer-sweep")]);
  assert.equal(roleOf(g, R.drain), "drainer");
  assert.equal(g.clusters[0].totalDrops, 0, "XRP-totalDrops bleibt XRP-only");
  assert.deepEqual(g.clusters[0].iouFlows, [{ currency: "usdt", issuer: R.gamma, value: 200 }]);
});

// ---------- 22) maxEdges-Kappung darf Rollen nicht ändern ----------
// Audit-Probe (reproduzierte Kippung): HUB mit 10 Eingängen je 1 Mio und
// 2 Ausgängen je 4,9 Mio war full 'relay', cut(maxEdges=5) 'drainer' mit
// mainDrainers outDrops 9800000. Rollen werden jetzt aus dem VOLLEN
// Kantensatz berechnet; txCount/totalDrops bleiben aus der gekappten Sicht.
test("maxEdges-Kappung: Rollen bleiben stabil (relay -> kein erfundener drainer)", () => {
  const txs = [];
  for (let i = 0; i < 10; i++) txs.push(tx(`I${i}`, 10 + i, "Payment", R[`t${(i % 3) + 1}`], R.relay, 1000000));
  txs.push(tx("O1", 30, "Payment", R.relay, R.a1, 4900000));
  txs.push(tx("O2", 31, "Payment", R.relay, R.a2, 4900000));
  const findings = [finding(R.relay), finding(R.t1), finding(R.t2), finding(R.t3)];
  const full = buildClusterGraph(txs, findings, {});
  const cut = buildClusterGraph(txs, findings, { maxEdges: 5 });
  assert.equal(full.clusters[0].roles[R.relay], "relay");
  assert.equal(cut.clusters[0].roles[R.relay], "relay", "Kappung erfindet keinen drainer");
  assert.deepEqual(cut.clusters[0].mainDrainers, []);
  assert.equal(cut.edges.length, 5, "Ausgabesicht bleibt gekappt");
  assert.equal(cut.clusters[0].txCount, 5, "txCount bleibt aus der gekappten Sicht");
});

// ---------- 23) Selbstwallet-Konsolidierung ≠ drainer ----------
// Audit-Probe P2: rUser konsolidiert an die eigene neue Wallet -> bisher
// drainer + mainDrainers. Selbsttransfer (account === destination) erzeugt
// keine Kante; ein Sweep an ein eigenes, unflaggtes Ziel bleibt ohne
// geflaggte Gegenparteien unknown.
test("Selbstwallet-Konsolidierung: kein drainer", () => {
  const own = "rTESTOWNWALLET0000000000001";
  const txs = [
    tx("H1", 10, "Payment", R.s1, R.beta, 500000),
    tx("H2", 11, "Payment", R.s2, R.beta, 490000),
    tx("H3", 12, "Payment", R.beta, own, 990000), // Sweep an eigene neue Wallet
  ];
  const g = buildClusterGraph(txs, [finding(R.beta, "malicious", "drainer-sweep")]);
  assert.notEqual(roleOf(g, R.beta), "drainer", "Konsolidierung an eigene Wallet ist kein drainer");
  assert.deepEqual(g.clusters[0].mainDrainers, []);
});

// ---------- 24) Faucet ohne geflaggte Ziele ≠ source ----------
// Audit-Probe P3: Faucet-Distributoren an unflaggte Ziele verloren die
// source-Rolle nicht. Jetzt: source verlangt ein geflaggtes Ziel.
test("Faucet-Distributor ohne geflaggte Ziele bleibt unknown", () => {
  const txs = [
    tx("H1", 10, "Payment", R.s1, R.t1, 10000),
    tx("H2", 11, "Payment", R.s1, R.t2, 10000),
    tx("H3", 12, "Payment", R.s1, R.t3, 10000),
  ];
  const g = buildClusterGraph(txs, [finding(R.s1, "info", "offer-spam")]);
  assert.equal(roleOf(g, R.s1), "unknown");
});

// ---------- 25) Hub-Union-Schutz: Börse verschmilzt zwei Szenen nicht ----------
// Audit-Probe P5: zwei unabhängige Szenen wurden über eine gemeinsame Börse
// (Hub mit hohem Grad) zu einem Cluster verschmolzen. Hub-Kanten werden aus
// der Union herausgeschnitten; Szenen-interne Kanten mergen normal.
test("Hub-Union-Schutz: zwei Szenen über einen unflaggten Hub bleiben getrennt", () => {
  const txs = [
    tx("A0", 9, "Payment", R.drain, R.coll, 500), // Szene 1: interne Kante
    tx("X", 40, "Payment", R.drain, R.relay, 1200), // Szene 1 -> Börse
    tx("A1", 10, "Payment", R.alpha, R.beta, 500), // Szene 2: interne Kante
    tx("Y", 41, "Payment", R.relay, R.beta, 1200), // Börse -> Szene 2
  ];
  for (let i = 0; i < 19; i++) txs.push(tx(`B${i}`, 50 + i, "Payment", R.relay, R.coll, 100)); // Hub-Grad 21 > 20
  // Der Hub (R.relay) ist bewusst UNflaggt — nur dann greift der Union-Schnitt.
  const g = buildClusterGraph(txs, [finding(R.drain), finding(R.coll), finding(R.alpha), finding(R.beta)]);
  assert.equal(g.clusters.length, 2, "keine Verschmelzung über den Hub");
  const members = g.clusters.map((c) => c.memberAddresses);
  assert.ok(members.some((m) => m.includes(R.drain) && !m.includes(R.beta)));
  assert.ok(members.some((m) => m.includes(R.beta) && !m.includes(R.drain)));
});

// ---------- 25b) Hub-Schutz gilt nur für UNflaggte Hubs (dokumentierte Asymmetrie) ----------
// Akkumulations-Befund 2026-10-06: Bekannte-böse Collectors sind FLAGGED —
// der Union-Schnitt (cluster.mjs isHub = !severityOf.has(id) && degree > 20)
// greift für sie bewusst NICHT, sie ziehen beide Szenen in einen Cluster.
// Das ist die Live-Root-Cause des Mega-Clusters. Der Guard gegen das weitere
// Wachstum sitzt bewusst in lib/ledger-walk.mjs (MAX_STATE_CLUSTER_MEMBERS,
// siehe ledger-walk.test.mjs), NICHT hier — cluster.mjs bleibt unverändert.
test("Geflaggter Hub verschmilzt Szenen weiterhin (Union-Schutz nur für unflaggte Hubs)", () => {
  const txs = [
    tx("A0", 9, "Payment", R.drain, R.coll, 500), // Szene 1: interne Kante
    tx("X", 40, "Payment", R.drain, R.relay, 1200), // Szene 1 -> Collector
    tx("A1", 10, "Payment", R.alpha, R.beta, 500), // Szene 2: interne Kante
    tx("Y", 41, "Payment", R.relay, R.beta, 1200), // Collector -> Szene 2
  ];
  for (let i = 0; i < 19; i++) txs.push(tx(`B${i}`, 50 + i, "Payment", R.relay, R.coll, 100)); // Hub-Grad 21 > 20
  // Der Hub (R.relay) ist FLAGGED (known-bad) -> isHub-Schutz greift nicht.
  const g = buildClusterGraph(txs, [
    finding(R.drain),
    finding(R.coll),
    finding(R.alpha),
    finding(R.beta),
    finding(R.relay, "malicious", "known-bad-hit"),
  ]);
  assert.equal(g.clusters.length, 1, "flaggeder Hub verschmilzt beide Szenen (dokumentiertes Verhalten)");
  assert.ok(g.clusters[0].memberAddresses.includes(R.relay), "Collector ist Mitglied");
});

// ---------- 26) Geflaggter TrustSet-Issuer erscheint als isolierter Knoten ----------
// Audit-Integration-Probe: airdrop-trustset-spam-Fund auf einen Issuer ohne
// jede txRecord-Position ergab edges=0 clusters=0 nodes=[]. Der Issuer muss
// als isolierter Fund-Knoten erscheinen, ohne erfundene TrustSet-Kanten.
test("Geflaggter Issuer ohne txRecord-Position -> isolierter Knoten, keine erfundenen Kanten", () => {
  const issuer = "rTESTISSUER000000000000000001";
  const txs = [tx("H1", 10, "Payment", R.s1, R.t1, 100)];
  const g = buildClusterGraph(txs, [
    finding(R.s1),
    finding(issuer, "suspect", "airdrop-trustset-spam"),
  ]);
  const node = g.nodes.find((n) => n.id === issuer);
  assert.ok(node, "Issuer erscheint als Knoten");
  assert.equal(node.severity, "suspect");
  assert.equal(node.degreeIn, 0);
  assert.equal(node.degreeOut, 0);
  assert.equal(node.clusterId, null);
  assert.equal(g.edges.length, 1, "keine erfundene TrustSet-Kante");
});

// ---------- 27) Gegenbewegungs-Typen im Graph (EscrowFinish/VaultWithdraw) ----------
// Audit-Probe über 26 Tx-Typen: EscrowFinish/VaultWithdraw hatten dest='-'
// (isoliert). Jetzt erscheint die reale Geldbewegung als Kante. CheckCash
// liefert seit dem Lücken-Audit 2026-10-07 bewusst KEINE Kante mehr: das
// Feld 'CheckDestination' existiert nicht (https://xrpl.org/checkcash.html —
// Felder NUR CheckID/Amount/DeliverMin); der frühere Zweig war toter Code.
test("Gegenbewegungen: EscrowFinish/VaultWithdraw erzeugen Kanten, CheckCash bewusst nicht", () => {
  const entries = [
    { hash: "H1", ledger_index: 10, close_time_iso: R.iso, TransactionType: "EscrowFinish", Account: R.alpha, Owner: R.beta, Amount: "1000" },
    { hash: "H2", ledger_index: 11, close_time_iso: R.iso, TransactionType: "CheckCash", Account: R.beta, CheckDestination: R.gamma, Amount: "2000" },
    { hash: "H3", ledger_index: 12, close_time_iso: R.iso, TransactionType: "VaultWithdraw", Account: R.gamma, VaultOwner: R.alpha, VaultAmount: "3000" },
  ];
  const recs = entries.map((e) => txRecordFromEntry(e, null));
  assert.equal(recs[0].destination, R.beta);
  assert.equal(recs[1].destination, undefined, "CheckCash: kein Mapping über ein nicht existierendes Feld");
  assert.equal(recs[2].destination, R.alpha);
  assert.equal(recs[2].amountDrops, 3000, "VaultAmount wird als Betrag gelesen");
  const g = buildClusterGraph(recs, [finding(R.alpha), finding(R.gamma)]);
  assert.equal(g.edges.length, 2);
  assert.deepEqual(g.edges.map((e) => e.type), ["EscrowFinish", "VaultWithdraw"]);
});

// ---------- 27a) Clawback: bewusst kantenlos ----------
// Account ist der Issuer (https://xrpl.org/clawback.html) — der frühere
// 'Clawback -> tx.Account'-Zweig war immer ein Self-Ref (toter Code). Die
// reale Flussrichtung Holder -> Issuer ist im record-Vertrag (account ->
// destination) ohne Signertausch nicht ausdrückbar.
test("Clawback: kantenlos (Account = Issuer, Richtung Holder->Issuer nicht ausdrückbar)", () => {
  const rec = txRecordFromEntry(
    { hash: "H4", ledger_index: 13, close_time_iso: R.iso, TransactionType: "Clawback", Account: R.alpha, Amount: { currency: "SCAM", issuer: R.beta, value: "50" } },
    null
  );
  assert.equal(rec.destination, undefined);
  const g = buildClusterGraph([rec], [finding(R.alpha)]);
  assert.equal(g.edges.length, 0, "keine Clawback-Kante (auch kein Self-Ref)");
});

// ---------- 27b) NFTokenAcceptOffer: meta-basierte NFT-Transfer-Kante ----------
// Direkte Sell-Annahme: tx.Account (Käufer) zahlt Offer.Amount an den Offer-
// Owner (Verkäufer); Gegenpartei/Betrag aus dem DeletedNode NFTokenOffer
// (https://xrpl.org/docs/references/protocol/transactions/types/
// nftokenacceptoffer + https://xrpl.org/transaction-metadata.html).
const NFT_OFFER_META = {
  AffectedNodes: [
    {
      ModifiedNode: {
        LedgerEntryType: "AccountRoot",
        PreviousFields: { Balance: "1000000" },
        FinalFields: { Balance: "999250" },
      },
    },
    {
      DeletedNode: {
        LedgerEntryType: "NFTokenOffer",
        LedgerIndex: "OFFER00000000000000000000000000000000000000000000000000000000",
        FinalFields: { Owner: R.beta, Amount: "750", NFTokenID: "NFT0001" },
      },
    },
  ],
};
const nftEntry = (overrides) => ({
  hash: "HNFT",
  ledger_index: 14,
  close_time_iso: R.iso,
  tx_json: {
    TransactionType: "NFTokenAcceptOffer",
    Account: R.alpha,
    NFTokenSellOffer: "OFFER00000000000000000000000000000000000000000000000000000000",
    ...overrides,
  },
  meta: NFT_OFFER_META,
});

test("NFTokenAcceptOffer (Sell-Annahme): Meta-Kante Käufer -> Verkäufer mit Offer.Amount", () => {
  const rec = txRecordFromEntry(nftEntry(), null);
  assert.equal(rec.destination, R.beta, "Offer-Owner (Verkäufer) als destination");
  assert.equal(rec.amountDrops, 750, "Offer.Amount als Zahlungsbetrag");
  const g = buildClusterGraph([rec], [finding(R.alpha)]);
  assert.equal(g.edges.length, 1);
  assert.equal(g.edges[0].type, "NFTokenAcceptOffer");
  assert.equal(g.edges[0].from, R.alpha);
  assert.equal(g.edges[0].to, R.beta);
  assert.equal(g.edges[0].amountDrops, 750);
});

test("NFTokenAcceptOffer: ohne Meta/Owner keine Kante (nichts erfunden)", () => {
  const rec = txRecordFromEntry(
    { hash: "HNFT2", ledger_index: 15, close_time_iso: R.iso, TransactionType: "NFTokenAcceptOffer", Account: R.alpha, NFTokenSellOffer: "OFFER1" },
    null
  );
  assert.equal(rec.destination, undefined);
});

test("NFTokenAcceptOffer: Buy-Annahme bewusst unmapped (Zahlung liefe Owner -> Account)", () => {
  const rec = txRecordFromEntry(nftEntry({ NFTokenSellOffer: undefined, NFTokenBuyOffer: "OFFER2" }), null);
  assert.equal(rec.destination, undefined, "Owner wäre der KÄUFER — Richtung nicht ausdrückbar");
});

test("NFTokenAcceptOffer: Broker-Fall (beide Offer-Felder + NFTokenBrokerFee) bewusst unmapped", () => {
  const rec = txRecordFromEntry(nftEntry({ NFTokenBuyOffer: "OFFER2", NFTokenBrokerFee: "100" }), null);
  assert.equal(rec.destination, undefined, "zwei konsumierte Offers — Owner-Auflösung mehrdeutig");
});

test("NFTokenAcceptOffer: IOU-Amount aus dem Offer als iouValue", () => {
  const iouMeta = {
    AffectedNodes: [
      { DeletedNode: { LedgerEntryType: "NFTokenOffer", FinalFields: { Owner: R.beta, Amount: { currency: "USD", issuer: R.gamma, value: "12.5" } } } },
    ],
  };
  const rec = txRecordFromEntry(
    {
      hash: "HNFT3",
      ledger_index: 18,
      close_time_iso: R.iso,
      tx_json: { TransactionType: "NFTokenAcceptOffer", Account: R.alpha, NFTokenSellOffer: "OFFER3" },
      meta: iouMeta,
    },
    null
  );
  assert.equal(rec.destination, R.beta);
  assert.equal(rec.amountDrops, null, "IOU zählt nicht als XRP-Drops");
  assert.deepEqual(rec.iouValue, { currency: "USD", issuer: R.gamma, value: 12.5 });
});

// =====================================================================
// Peeling-Ketten (detectPeelingChains) — Regression zum Peeling-Plan.
// Synthetische Adressen, keine echten, keine Köder.
// =====================================================================
const P = {
  seed: "rTESTPSEED00000000000000000001",
  end: "rTESTPEND0000000000000000000001",
  b1: "rTESTPB1000000000000000000000001",
  b2: "rTESTPB2000000000000000000000002",
  b3: "rTESTPB3000000000000000000000003",
};
const pflag = (address, severity = "suspect") => ({ address, severity });

// ---------- P1) 4-Hop-Kette 0.8-Ratio, nur Enden geflaggt ----------
test("peeling: 4-Hop-Kette 0.8-Ratio mit nur geflaggten Enden -> eine Kette mit bridge-Markierung", () => {
  const txs = [
    tx("H1", 10, "Payment", P.seed, P.b1, 10000),
    tx("H2", 11, "Payment", P.b1, P.b2, 8000),
    tx("H3", 12, "Payment", P.b2, P.b3, 6400),
    tx("H4", 13, "Payment", P.b3, P.end, 5120),
  ];
  const chains = detectPeelingChains(txs, [pflag(P.seed), pflag(P.end, "malicious")]);
  assert.equal(chains.length, 1);
  const c = chains[0];
  assert.deepEqual(c.addresses, [P.seed, P.b1, P.b2, P.b3, P.end]);
  assert.equal(c.hopsCount, 4);
  assert.deepEqual(c.bridges, [P.b1, P.b2, P.b3]);
  assert.equal(c.seed, P.seed);
  assert.equal(c.seedSeverity, "suspect");
  assert.equal(c.signature, [P.seed, P.b1, P.b2, P.b3, P.end].join(","));
  // Hops in cmpEdge-Totalordnung (ledgerSeq asc) und mit Ratio je Relay-Hop.
  assert.deepEqual(c.hops.map((h) => h.ledgerSeq), [10, 11, 12, 13]);
  assert.equal(c.hops[0].ratio, null, "Seed-Hop hat kein Verhältnis");
  assert.equal(c.hops[1].ratio, 0.8);
  assert.equal(c.hops[2].ratio, 0.8);
  assert.equal(c.hops[3].ratio, 0.8);
});

// ---------- P2) Ratio-Fenster ----------
test("peeling: Ratio 0.5 und 0.98 außerhalb des Fensters -> keine Kette", () => {
  const low = [
    tx("H1", 10, "Payment", P.seed, P.b1, 10000),
    tx("H2", 11, "Payment", P.b1, P.b2, 5000),
    tx("H3", 12, "Payment", P.b2, P.b3, 4000),
    tx("H4", 13, "Payment", P.b3, P.end, 3200),
  ];
  assert.equal(detectPeelingChains(low, [pflag(P.seed), pflag(P.end)]).length, 0);
  const high = [
    tx("H1", 10, "Payment", P.seed, P.b1, 10000),
    tx("H2", 11, "Payment", P.b1, P.b2, 9800),
    tx("H3", 12, "Payment", P.b2, P.b3, 9604),
    tx("H4", 13, "Payment", P.b3, P.end, 9412),
  ];
  assert.equal(detectPeelingChains(high, [pflag(P.seed), pflag(P.end)]).length, 0);
  // Fenster-Grenzen selbst (0.6 / 0.95) sind einschließend.
  const edge = [
    tx("H1", 10, "Payment", P.seed, P.b1, 10000),
    tx("H2", 11, "Payment", P.b1, P.b2, 6000),
    tx("H3", 12, "Payment", P.b2, P.end, 5700),
  ];
  assert.equal(detectPeelingChains(edge, [pflag(P.seed), pflag(P.end)]).length, 1);
});

// ---------- P3) Bagatellgrenze ----------
test("peeling: Hop <= 100 drops bricht die Kette (dustDrops wie detector.mjs:28)", () => {
  assert.equal(PEELING_THRESHOLDS.dustDrops, 100);
  const txs = [
    tx("H1", 10, "Payment", P.seed, P.b1, 10000),
    tx("H2", 11, "Payment", P.b1, P.b2, 8000),
    tx("H3", 12, "Payment", P.b2, P.b3, 100), // genau die Bagatellgrenze -> bricht
    tx("H4", 13, "Payment", P.b3, P.end, 80),
  ];
  assert.equal(detectPeelingChains(txs, [pflag(P.seed), pflag(P.end)]).length, 0);
  // 101 drops überschreiten die Grenze.
  const ok = [
    tx("H1", 10, "Payment", P.seed, P.b1, 10000),
    tx("H2", 11, "Payment", P.b1, P.b2, 8000),
    tx("H3", 12, "Payment", P.b2, P.b3, 6400),
    tx("H4", 13, "Payment", P.b3, P.end, 101),
  ];
  assert.equal(detectPeelingChains(ok, [pflag(P.seed), pflag(P.end)]).length, 1);
});

// ---------- P4) Regression cluster.mjs:276-277 (Mittelkante) ----------
test("peeling: ungeflaggte Tx zwischen bekannten Knoten wird gebridgt, obwohl buildClusterGraph sie nicht kantt", () => {
  const txs = [
    tx("H1", 10, "Payment", P.seed, P.b1, 10000),
    tx("H2", 11, "Payment", P.b1, P.b2, 8000), // beide Enden ungeflaggt
    tx("H3", 12, "Payment", P.b2, P.end, 6400),
  ];
  const findings = [finding(P.seed), finding(P.end, "malicious", "drainer-sweep")];
  const g = buildClusterGraph(txs, findings);
  // Die Kantenregel splittet: die Mittelkante fehlt im Graphen.
  assert.equal(g.edges.length, 2);
  assert.ok(!g.edges.some((e) => e.from === P.b1 && e.to === P.b2), "Mittelkante nicht kantt");
  assert.equal(g.clusters.length, 2, "Split in zwei Cluster (dokumentierte Grenze)");
  // detectPeelingChains läuft über txRecords und bridgt sie trotzdem.
  const chains = detectPeelingChains(txs, findings);
  assert.equal(chains.length, 1);
  assert.deepEqual(chains[0].addresses, [P.seed, P.b1, P.b2, P.end]);
  assert.deepEqual(chains[0].bridges, [P.b1, P.b2]);
});

// ---------- P5) Hub-Skala (Kritik 5) ----------
test("peeling: Hub über FLAGGE-Edge-Grad > 20 wird nicht gebridgt, 21 ungeflaggte Alltags-Tx dagegen schon", () => {
  const H = "rTESTPHUB00000000000000000001";
  const B = "rTESTPBRIDGE0000000000000000001";
  const flagged = [pflag(P.seed), pflag(P.end, "malicious")];
  // Hub: 21 FLAGGE-Kanten (21 geflaggte Sender -> H) -> nicht bebridgt.
  const hubTxs = [
    tx("H1", 10, "Payment", P.seed, H, 10000),
    tx("H2", 11, "Payment", H, P.b2, 8000),
    tx("H3", 12, "Payment", P.b2, P.end, 6400),
  ];
  for (let i = 0; i < 21; i++) {
    const f = `rTESTPFLAG${String(i).padStart(2, "0")}0000000000000000`;
    flagged.push(pflag(f, "info"));
    hubTxs.push(tx(`F${i}`, 20 + i, "Payment", f, H, 500));
  }
  assert.equal(detectPeelingChains(hubTxs, flagged).length, 0, "Hub (21 FLAGGE-Kanten) nicht gebridgt");
  // Kein Hub: 21 ungeflaggte Alltags-Tx des Zwischenkontos (Gegenparteien
  // nie kettenerreichbar) -> Kette wird trotzdem gefunden.
  const allTxs = [
    tx("H1", 10, "Payment", P.seed, B, 10000),
    tx("H2", 11, "Payment", B, P.b2, 8000),
    tx("H3", 12, "Payment", P.b2, P.end, 6400),
  ];
  for (let i = 0; i < 21; i++) {
    allTxs.push(tx(`D${i}`, 30 + i, "Payment", B, `rTESTPDUST${String(i).padStart(2, "0")}00000000000000`, 500));
  }
  const chains = detectPeelingChains(allTxs, [pflag(P.seed), pflag(P.end, "malicious")]);
  assert.equal(chains.length, 1, "21 ungeflaggte Alltags-Tx machen keinen Hub");
  assert.ok(chains[0].bridges.includes(B));
});

// ---------- P6) Kappen ----------
test("peeling: Kappen maxChains/maxChainLen/maxSeeds/maxDegree", () => {
  // maxChains 20 bei 25 unabhängigen Ketten.
  const txs = [];
  const flagged = [];
  for (let i = 0; i < 25; i++) {
    const s = `rTESTPS${String(i).padStart(2, "0")}00000000000000000000`;
    const e = `rTESTPE${String(i).padStart(2, "0")}00000000000000000000`;
    const x = `rTESTPX${String(i).padStart(2, "0")}00000000000000000000`;
    const y = `rTESTPY${String(i).padStart(2, "0")}00000000000000000000`;
    txs.push(tx(`A${i}`, 100 + i, "Payment", s, x, 10000));
    txs.push(tx(`B${i}`, 110 + i, "Payment", x, y, 8000));
    txs.push(tx(`C${i}`, 120 + i, "Payment", y, e, 6400));
    flagged.push(pflag(s), pflag(e));
  }
  assert.equal(detectPeelingChains(txs, flagged).length, 20, "maxChains 20");
  // maxChainLen 8 bei einer 10-Hop-Kette.
  const addr = [];
  for (let i = 0; i < 11; i++) addr.push(`rTESTPL${String(i).padStart(2, "0")}000000000000000000000`);
  const long = [];
  for (let i = 0; i < 10; i++) long.push(tx(`L${i}`, 200 + i, "Payment", addr[i], addr[i + 1], 10000 - i * 700));
  const lc = detectPeelingChains(long, [pflag(addr[0]), pflag(addr[10])]);
  assert.equal(lc.length, 1);
  assert.equal(lc[0].hopsCount, 8, "maxChainLen 8");
  // maxSeeds 2: nur die zwei Seeds asc explorieren.
  const capped = detectPeelingChains(txs, flagged, { maxSeeds: 2 });
  assert.ok(capped.length <= 2, "maxSeeds begrenzt die Seed-Exploration");
  // maxDegree: ein Zwischenknoten mit zwei Ketten-Ausgängen ist kein 1:1-Relay.
  const md = [
    tx("M1", 10, "Payment", P.seed, P.b1, 10000),
    tx("M2", 11, "Payment", P.b1, P.b2, 8000),
    tx("M3", 12, "Payment", P.b1, P.end, 7000),
    tx("M4", 13, "Payment", P.b2, P.end, 6000),
  ];
  assert.equal(detectPeelingChains(md, [pflag(P.seed), pflag(P.end)]).length, 0, "kein striktes 1:1-Relay");
});

// ---------- P7) Determinismus (Kritik 4) ----------
test("peeling: txRecords-Reihenfolge und Gleichstand ohne hash/ledgerSeq ändern die Kettenausgabe nicht", () => {
  const base = [
    tx("H1", 10, "Payment", P.seed, P.b1, 10000),
    tx("H2", 11, "Payment", P.b1, P.b2, 8000),
    tx("H3", 12, "Payment", P.b2, P.b3, 6400),
    tx("H4", 13, "Payment", P.b3, P.end, 5120),
  ];
  const flagged = [pflag(P.seed), pflag(P.end, "malicious")];
  const a = JSON.stringify(detectPeelingChains(base, flagged));
  const b = JSON.stringify(detectPeelingChains([...base].reverse(), flagged));
  const c = JSON.stringify(detectPeelingChains([base[2], base[0], base[3], base[1]], flagged));
  assert.equal(a, b);
  assert.equal(a, c);
  // Gleichstand ohne hash UND ledgerSeq: Ausgabe bleibt identisch.
  const tie = [
    { hash: null, ledgerSeq: null, closeTime: R.iso, type: "Payment", account: P.seed, destination: P.b1, amountDrops: 10000 },
    { hash: null, ledgerSeq: null, closeTime: R.iso, type: "Payment", account: P.b1, destination: P.b2, amountDrops: 8000 },
    { hash: null, ledgerSeq: null, closeTime: R.iso, type: "Payment", account: P.b2, destination: P.end, amountDrops: 6400 },
  ];
  const t1 = JSON.stringify(detectPeelingChains(tie, flagged));
  const t2 = JSON.stringify(detectPeelingChains([...tie].reverse(), flagged));
  assert.equal(t1, t2);
  assert.equal(JSON.parse(t1).length, 1);
});

// ---------- P8) Brückenknoten ohne Rolle und ohne Severity ----------
test("peeling: Brückenknoten erhalten nie Rolle und nie severityByAddress", () => {
  const txs = [
    tx("H1", 10, "Payment", P.seed, P.b1, 10000),
    tx("H2", 11, "Payment", P.b1, P.b2, 8000),
    tx("H3", 12, "Payment", P.b2, P.end, 6400),
  ];
  const findings = [finding(P.seed), finding(P.end, "malicious", "drainer-sweep")];
  const chains = detectPeelingChains(txs, findings);
  assert.equal(chains.length, 1);
  const bridgeSet = new Set(chains[0].bridges);
  assert.deepEqual([...bridgeSet], [P.b1, P.b2]);
  // Kettenobjekt trägt Severity nur für den Seed.
  assert.equal(chains[0].seedSeverity, "suspect");
  // Cluster-Sicht: Severity nur für Fund-Adressen (cluster.mjs:465), die
  // Brücken bleiben severity-null und ohne Betrugslable-Rolle.
  const g = buildClusterGraph(txs, findings);
  for (const c of g.clusters) {
    for (const b of bridgeSet) {
      assert.ok(!(b in c.severityByAddress), `Brücke ${b} nicht in severityByAddress`);
      assert.ok(c.roles[b] === undefined || c.roles[b] === "unknown" || c.roles[b] === "relay", "keine Betrugslable-Rolle");
    }
  }
  for (const n of g.nodes) {
    if (bridgeSet.has(n.id)) assert.equal(n.severity, null);
  }
});

// =====================================================================
// TAG-IDENTITÄT (DestinationTag/SourceTag — lib/tag-identity.mjs)
// Reine Kanten-Verfeinerung: keine Topologie-, Rollen- oder Cap-Änderung.
// =====================================================================

const TAG_EX = "rTESTexchangeAccount11111111"; // 28 Zeichen, Base58-gültig
const tagRegistry = new Map([[TAG_EX, { exchange: "Test Exchange One", tier: 1, requireDestTag: true }]]);
const txTag = (hash, seq, type, account, destination, amount, tag) => ({
  hash, ledgerSeq: seq, closeTime: R.iso, type, account, destination, amountDrops: amount,
  ...(tag !== undefined ? { destinationTag: tag } : {}),
});

// ---------- T1) toTag nur bei Registry-Empfänger + gültigem Tag ----------
test("tag: Registry-Empfänger mit DestinationTag -> Edge.toTag gesetzt", () => {
  const txs = [txTag("H1", 10, "Payment", R.alpha, TAG_EX, 1000, 3125327487)];
  const g = buildClusterGraph(txs, [finding(R.alpha)], { multiUserAccounts: tagRegistry });
  assert.equal(g.edges.length, 1);
  assert.equal(g.edges[0].toTag, 3125327487);
});

test("tag: ohne Registry-Map bleibt die Edge tag-frei (Default bitgleich)", () => {
  const txs = [txTag("H1", 10, "Payment", R.alpha, TAG_EX, 1000, 111)];
  const gPlain = buildClusterGraph(txs, [finding(R.alpha)]);
  const gNull = buildClusterGraph(txs, [finding(R.alpha)], { multiUserAccounts: null });
  assert.deepEqual(gNull, gPlain, "opts.multiUserAccounts null == altes Verhalten");
  assert.ok(!("toTag" in gPlain.edges[0]), "kein toTag ohne Registry");
  assert.ok(!("transit" in gPlain.edges[0]));
});

test("tag: nicht gelisteter Empfänger mit DestinationTag -> kein toTag", () => {
  const txs = [txTag("H1", 10, "Payment", R.alpha, R.beta, 1000, 111)];
  const g = buildClusterGraph(txs, [finding(R.alpha)], { multiUserAccounts: tagRegistry });
  assert.ok(!("toTag" in g.edges[0]));
});

// ---------- T2) transit auf dem vollen Kantensatz ----------
test("tag: zwei verschiedene Tags an derselben Börse -> transit auf beiden Kanten", () => {
  const txs = [
    txTag("H1", 10, "Payment", R.alpha, TAG_EX, 1000, 111),
    txTag("H2", 11, "Payment", R.beta, TAG_EX, 900, 222),
  ];
  const g = buildClusterGraph(txs, [finding(R.alpha), finding(R.beta)], { multiUserAccounts: tagRegistry });
  assert.equal(g.edges[0].transit, true);
  assert.equal(g.edges[1].transit, true);
});

test("tag: gleicher Tag an derselben Börse -> kein transit (gleiche Identität)", () => {
  const txs = [
    txTag("H1", 10, "Payment", R.alpha, TAG_EX, 1000, 111),
    txTag("H2", 11, "Payment", R.beta, TAG_EX, 900, 111),
  ];
  const g = buildClusterGraph(txs, [finding(R.alpha), finding(R.beta)], { multiUserAccounts: tagRegistry });
  for (const e of g.edges) assert.ok(!("transit" in e), "transit nur bei >=2 Identitäten");
});

test("tag: Tag 0 ist ein echter Tag -> toTag 0, transit gegen Tag-111", () => {
  const txs = [
    txTag("H1", 10, "Payment", R.alpha, TAG_EX, 1000, 0),
    txTag("H2", 11, "Payment", R.beta, TAG_EX, 900, 111),
  ];
  const g = buildClusterGraph(txs, [finding(R.alpha), finding(R.beta)], { multiUserAccounts: tagRegistry });
  assert.equal(g.edges[0].toTag, 0, "Tag 0 nicht mit 'kein Tag' verwechselt");
  assert.equal(g.edges[0].transit, true);
  assert.equal(g.edges[1].transit, true);
});

test("tag: fehlender Tag an requireDestTag-Börse -> kein toTag, kein transit", () => {
  const txs = [tx("H1", 10, "Payment", R.alpha, TAG_EX, 1000)];
  const g = buildClusterGraph(txs, [finding(R.alpha)], { multiUserAccounts: tagRegistry });
  assert.ok(!("toTag" in g.edges[0]), "fehlendes Feld -> kein toTag (requireDestTag ist nur Anzeige-Hinweis)");
  assert.ok(!("transit" in g.edges[0]), "eine Identität ('kein Tag') -> kein transit");
});

test("tag: transit ist cap-unabhängig (auf vollem Satz vor maxEdges-Kappung)", () => {
  const txs = [
    txTag("H1", 10, "Payment", R.alpha, TAG_EX, 1000, 111),
    txTag("H2", 11, "Payment", R.beta, TAG_EX, 900, 222),
    txTag("H3", 12, "Payment", R.gamma, TAG_EX, 800, 333),
  ];
  const g = buildClusterGraph(txs, [finding(R.alpha), finding(R.beta), finding(R.gamma)], { multiUserAccounts: tagRegistry, maxEdges: 1 });
  assert.equal(g.edges.length, 1, "Cap hält die neueste Kante");
  assert.equal(g.edges[0].txHash, "H3");
  assert.equal(g.edges[0].transit, true, "transit wurde vor dem Cap auf dem vollen Satz berechnet");
});

// ---------- T3) txRecordFromEntry: Tag-Felder ----------
test("tag: txRecordFromEntry normalisiert DestinationTag/SourceTag (0 ist echt)", () => {
  const rec = txRecordFromEntry({
    hash: "H1", ledger_index: 5, TransactionType: "Payment",
    Account: R.alpha, Destination: TAG_EX, Amount: "1000",
    DestinationTag: "3125327487", SourceTag: 0,
  });
  assert.equal(rec.destinationTag, 3125327487, "Ziffern-String normalisiert");
  assert.equal(rec.sourceTag, 0, "SourceTag 0 ist ein echter Wert");
  const bad = txRecordFromEntry({
    hash: "H2", ledger_index: 6, TransactionType: "Payment",
    Account: R.alpha, Destination: TAG_EX, Amount: "1000",
    DestinationTag: "x", SourceTag: -1,
  });
  assert.ok(!("destinationTag" in bad), "ungültiger Tag -> kein Feld");
  assert.ok(!("sourceTag" in bad), "negativer SourceTag -> kein Feld");
});

test("tag: Gegenbewegungs-Adresse erhält keinen Tag (EscrowFinish -> Owner)", () => {
  // EscrowFinish trägt per Spec kein DestinationTag-Feld; selbst wenn eines
  // mitkommt, darf es nicht auf die abgeleitete Owner-Adresse wandern.
  const rec = txRecordFromEntry({
    hash: "H3", ledger_index: 7, TransactionType: "EscrowFinish",
    Account: R.alpha, Owner: TAG_EX, Amount: "1000", DestinationTag: 111,
  });
  assert.equal(rec.destination, TAG_EX, "Owner bleibt die Gegenbewegungs-Adresse");
  assert.ok(!("destinationTag" in rec), "Tag wird nicht auf Owner übertragen");
  const g = buildClusterGraph([rec], [finding(R.alpha)], { multiUserAccounts: tagRegistry });
  assert.ok(!("toTag" in g.edges[0]), "Edge zur Börse bleibt tag-frei");
});

test("tag: fromTag (SourceTag) ist rein informativ, auch ohne Registry", () => {
  const rec = {
    hash: "H4", ledgerSeq: 8, closeTime: R.iso, type: "Payment",
    account: TAG_EX, destination: R.beta, amountDrops: 500, sourceTag: 42,
  };
  const g = buildClusterGraph([rec], [finding(R.beta)]);
  assert.equal(g.edges[0].fromTag, 42);
  assert.ok(!("toTag" in g.edges[0]));
  assert.ok(!("transit" in g.edges[0]), "SourceTag erzeugt nie transit");
});

test("tag: Cluster-Topologie und Rollen bleiben ohne/mit Registry identisch", () => {
  const txs = [
    txTag("H1", 10, "Payment", R.alpha, TAG_EX, 1000, 111),
    txTag("H2", 11, "Payment", R.beta, TAG_EX, 900, 222),
  ];
  const findings = [finding(R.alpha), finding(R.beta)];
  const plain = buildClusterGraph(txs, findings);
  const tagged = buildClusterGraph(txs, findings, { multiUserAccounts: tagRegistry });
  // Nur die Kanten-Attribute unterscheiden sich; Struktur bleibt gleich.
  const strip = (g) => JSON.parse(JSON.stringify(g, (k, v) =>
    (k === "toTag" || k === "fromTag" || k === "transit" || k === "destinationTag" || k === "sourceTag") ? undefined : v));
  assert.deepEqual(strip(tagged), strip(plain), "Cluster-Keys, Rollen und Knoten unverändert");
});

// =====================================================================
// V1b — Remainder-Rinne ("Großrest wandert weiter", DFRWS 2023).
// Regel-Matrix über Ratio x Abgang: die Rinne feuert NUR bei beobachtetem
// kleinen Abgang (<= peelMaxFraction des Eingangs, > dustDrops) an ein
// Nicht-Kettenglied — reine >= 95-%-Weiterleitung bleibt drainer-sweep
// überlassen. Schwellen aus PEELING_REMAINDER_THRESHOLDS, keine magischen
// Testwerte: der Eingang IN wird so gewählt, dass der Abgangs-Korridor
// (dustDrops, peelMaxFraction*IN] nicht leer ist.
// =====================================================================
const PT = "rTESTPTARGET0000000000000000001"; // Abgeschälter (Nicht-Kettenglied)

test("peeling remainder: Matrix Ratio x Abgang (DFRWS Peel-Percentage)", () => {
  // Korridor-Forderung: dustDrops < peelMaxFraction * IN — sonst wäre die
  // Rinne für diesen Eingang strukturell leer und der Test meaningless.
  const IN = 1_000_000;
  assert.ok(
    PEELING_THRESHOLDS.dustDrops < PEELING_REMAINDER_THRESHOLDS.peelMaxFraction * IN,
    "Abgangs-Korridor nicht leer"
  );
  const mk = (outDrops, peelDrops, extra = []) => {
    const txs = [
      tx("R1", 10, "Payment", P.seed, P.b1, IN),
      tx("R2", 11, "Payment", P.b1, P.end, outDrops),
    ];
    if (peelDrops != null) txs.push(tx("R3", 11, "Payment", P.b1, PT, peelDrops));
    txs.push(...extra);
    return txs;
  };
  const flagged = [pflag(P.seed), pflag(P.end, "malicious")];
  const goodPeel = 0.005 * IN; // 0,5 % <= 1 % und > dustDrops

  // (1) 0,97-Weiterleitung MIT Abgang -> Remainder-Kette (2 Hops genügen).
  const withPeel = detectPeelingChains(mk(0.97 * IN, goodPeel), flagged);
  assert.equal(withPeel.length, 1, "0,97 + Abgang -> Kette");
  assert.equal(withPeel[0].remainderHops, 1, "genau ein Remainder-Hop");
  assert.equal(withPeel[0].hopsCount, 2, "Remainder-Rinne gilt ab 2 Runden (DFRWS 42,6 %)");
  assert.ok(Math.abs(withPeel[0].hops[1].ratio - 0.97) < 1e-9, "Ratio ist die Weiterleitung");
  assert.deepEqual(withPeel[0].bridges, [P.b1], "nur der Relay ist Brücke");

  // (2) Dieselbe Weiterleitung OHNE Abgang -> keine Kette (Sweep bleibt
  // drainer-sweep-Zuständigkeit — FP-Guard der Rinne).
  assert.equal(detectPeelingChains(mk(0.97 * IN, null), flagged).length, 0, "ohne Abgang keine Rinne");

  // (3) Abgang über peelMaxFraction (2 %) -> keine Kette.
  assert.equal(
    detectPeelingChains(mk(0.97 * IN, 0.02 * IN), flagged).length,
    0,
    "Abgang > 1 % des Eingangs ist kein Peel"
  );

  // (4) Abgang genau an der Bagatellgrenze -> kein Peel (exklusiv > dustDrops).
  assert.equal(
    detectPeelingChains(mk(0.97 * IN, PEELING_THRESHOLDS.dustDrops), flagged).length,
    0,
    "Abgang <= dustDrops ist Dust, kein Peel"
  );

  // (5) Ratio >= maxRatio (1) -> keine Kette, auch nicht mit Abgang.
  assert.equal(detectPeelingChains(mk(IN, goodPeel), flagged).length, 0, "100-%-Weiterleitung ist kein Peel");

  // (6) Klassische Rinne bleibt unberührt: 0,8 braucht 3 Hops (minHops),
  //     2 Hops reichen nicht — auch nicht über die Remainder-Rinne.
  const classic2 = [
    tx("R1", 10, "Payment", P.seed, P.b1, IN),
    tx("R2", 11, "Payment", P.b1, P.end, 0.8 * IN),
  ];
  assert.equal(detectPeelingChains(classic2, flagged).length, 0, "klassisch: 2 Hops reichen nicht");
  const classic3 = [
    tx("R1", 10, "Payment", P.seed, P.b1, IN),
    tx("R2", 11, "Payment", P.b1, P.b2, 0.8 * IN),
    tx("R3", 12, "Payment", P.b2, P.end, 0.8 * 0.8 * IN),
  ];
  const classic = detectPeelingChains(classic3, flagged);
  assert.equal(classic.length, 1, "klassische 3-Hop-Kette bleibt");
  assert.ok(!("remainderHops" in classic[0]), "kein remainderHops-Feld ohne Remainder-Hop");
});

test("peeling remainder: Abgang an ein Kettenglied zählt nicht (Zykel-Schutz)", () => {
  // Der Abgang geht an b2, das zeitgleich Kettenglied der klassischen
  // Fortsetzung ist — ein Kettenglied ist kein "Abgeschälter".
  const IN = 1_000_000;
  const txs = [
    tx("R1", 10, "Payment", P.seed, P.b1, IN),
    tx("R2", 11, "Payment", P.b1, P.end, 0.97 * IN),
    tx("R3", 11, "Payment", P.b1, P.end, 0.005 * IN), // gleiche Zieladresse wie der Großrest
  ];
  const flagged = [pflag(P.seed), pflag(P.end)];
  assert.equal(detectPeelingChains(txs, flagged).length, 0, "Abgang ans Kettenziel ist kein Peel");
});

// =====================================================================
// V2 — Peel-Fingerprint (Auto-Programm-Homogenität, DFRWS 2023).
// Regel-Matrix über die vier Kriterien einzeln und in Kombination;
// Schwellen aus PEELING_FINGERPRINT_THRESHOLDS abgeleitet.
// =====================================================================
const fpHop = (over) => ({
  from: "rTESTFPA000000000000000000000001",
  to: "rTESTFPB000000000000000000000001",
  amountDrops: 1000,
  ratio: 0.8,
  txHash: "h",
  ledgerSeq: 10,
  ...over,
});

test("fingerprint: Kriterien-Matrix (Fee/Betrag/Intervall/Tag einzeln und kombiniert)", () => {
  const irrSeqs = [10, 500, 900, 1300]; // Median-Abstand 400 > 10 -> kein Intervall
  // Nur Fee: homogene Fees, distincte Beträge, unregelmäßige Abstände, keine Tags.
  const feeOnly = peelChainFingerprint({
    hops: irrSeqs.map((seq, i) => fpHop({ ledgerSeq: seq, amountDrops: 10000 - i * 1000, feeDrops: 12 })),
  });
  assert.equal(feeOnly.score, 1, "Fee-Konstanz allein zählt genau ein Kriterium");
  assert.deepEqual(feeOnly.criteria, ["fee-constancy"]);
  assert.ok(feeOnly.score < PEELING_FINGERPRINT_THRESHOLDS.minScore, "Fee allein führt nie ('homogen') — Wallet-Defaults sind identisch");

  // Fee + Betrags-Duplikate: Score 2 -> geführt, aber noch keine Confidence.
  const feeDup = peelChainFingerprint({
    hops: irrSeqs.slice(0, 3).map((seq, i) => fpHop({ ledgerSeq: seq, amountDrops: i === 0 ? 10000 : 8000, feeDrops: 12 })),
  });
  assert.equal(feeDup.score, 2, "Fee + Duplikat = 2 Kriterien");
  assert.deepEqual(feeDup.criteria, ["fee-constancy", "amount-duplicates"]);

  // Fee + Duplikate + reguläres Intervall: Score 3 -> confidence-Schwelle.
  const regSeqs = [];
  for (let i = 0; i < 3; i++) regSeqs.push(10 + i * PEELING_FINGERPRINT_THRESHOLDS.maxMedianGapLedgers); // Abstände genau am Median-Deckel
  const feeDupReg = peelChainFingerprint({
    hops: regSeqs.map((seq, i) => fpHop({ ledgerSeq: seq, amountDrops: i === 0 ? 10000 : 8000, feeDrops: 12 })),
  });
  assert.equal(feeDupReg.score, 3, "Fee + Duplikat + Intervall = 3 Kriterien");
  assert.ok(feeDupReg.score >= PEELING_FINGERPRINT_THRESHOLDS.highScore, ">= highScore");

  // Intervall-Kriterium erst ab minHopsForInterval Hops: 2 Hops mit
  // perfekt regulärem Abstand zählen NICHT als Regularität.
  const twoReg = peelChainFingerprint({
    hops: [10, 10 + PEELING_FINGERPRINT_THRESHOLDS.maxMedianGapLedgers].map((seq, i) => fpHop({ ledgerSeq: seq, amountDrops: 10000 - i * 1000 })),
  });
  assert.ok(!twoReg.criteria.includes("interval-regularity"), "2 Hops haben 1 Abstand — keine Regularität");

  // Tag-Wiederverwendung: gleicher DestinationTag auf 2 Hops (sonst nichts).
  const tagOnly = peelChainFingerprint({
    hops: irrSeqs.slice(0, 3).map((seq, i) => fpHop({ ledgerSeq: seq, amountDrops: 10000 - i * 1000, destinationTag: 77 })),
  });
  assert.ok(tagOnly.criteria.includes("tag-reuse"), "Tag-Wiederverwendung zählt");
  assert.equal(tagOnly.score, 1);

  // Fee-Streuung außerhalb des Buckets: Kriterium entfällt.
  const feeSpread = peelChainFingerprint({
    hops: [0, 1, 2].map((i) => fpHop({ ledgerSeq: 10 + i, amountDrops: 10000 - i * 1000, feeDrops: 10 + i * 5 })),
  });
  assert.ok(!feeSpread.criteria.includes("fee-constancy"), "Fees außerhalb ±10 % um den Median");

  // Unterstruktur: < 2 Hops -> Score 0.
  assert.deepEqual(peelChainFingerprint({ hops: [fpHop({})] }), { score: 0, criteria: [] });
});

test("fingerprint: detectPeelingChains hängt den Fingerprint an und strippt Hop-Rohstoffe", () => {
  // Remainder-Kette mit IDENTISCHEN Peel-Abgängen (Programm-Verteilung,
  // DFRWS Auto-Programm-Homogenität), homogenen Fees und regulären Block-
  // abständen (3 liegt unter dem Median-Deckel) -> Score 3, confidence high.
  // Ketten-Mathematik: Hop-Beträge sinken streng monoton (ratio < 1) —
  // Betrags-Duplikate kommen aus den Peel-Abgängen, nicht aus den Hops.
  const IN = 1_000_000;
  const peel = 0.005 * IN; // 5000: > dustDrops, <= peelMaxFraction * IN
  const txs = [
    { ...tx("F1", 10, "Payment", P.seed, P.b1, IN), feeDrops: 12 },
    { ...tx("F2", 13, "Payment", P.b1, P.b2, 0.97 * IN), feeDrops: 12 },
    { ...tx("F3", 16, "Payment", P.b2, P.end, 0.97 * 0.97 * IN), feeDrops: 12 },
    { ...tx("F4", 13, "Payment", P.b1, PT, peel), feeDrops: 12 }, // Peel am Relay 1
    { ...tx("F5", 16, "Payment", P.b2, PT, peel), feeDrops: 12 }, // identischer Peel am Relay 2
  ];
  const chains = detectPeelingChains(txs, [pflag(P.seed), pflag(P.end)]);
  assert.equal(chains.length, 1);
  const ch = chains[0];
  assert.equal(ch.remainderHops, 2, "beide Relay-Hops laufen über die Rinne");
  assert.equal(ch.hopsCount, 3);
  assert.ok(ch.fingerprint && typeof ch.fingerprint.score === "number", "Fingerprint am Kettenobjekt");
  assert.ok(ch.fingerprint.criteria.includes("fee-constancy"), "Fee-Kriterium aus den txRecords");
  assert.ok(ch.fingerprint.criteria.includes("amount-duplicates"), "identische Peel-Beträge zählen als Duplikat");
  assert.ok(ch.fingerprint.criteria.includes("interval-regularity"), "Abstände 3/3 liegen unter dem Deckel");
  assert.equal(ch.confidence, "high", ">= 3 Kriterien -> confidence high");
  // Persistierungs-Vertrag: Hops tragen KEINE Fee-/Tag-/Peel-Felder (byte-neutral).
  for (const h of ch.hops) {
    assert.ok(!("feeDrops" in h), "feeDrops wird von der ausgegebenen Kette entfernt");
    assert.ok(!("peelDrops" in h), "peelDrops wird entfernt (nur Fingerprint-Rohstoff)");
    assert.ok(!("destinationTag" in h) && !("sourceTag" in h), "Tag-Rohstoffe werden entfernt");
  }
});

// =====================================================================
// V1a — Cross-Block-Peeling über State-Kanten (Zeitdimension, DFRWS).
// Matrix: Flag-Durchgang, 24-h-Fenster, Hop-Gap, Hub, Side-Inkommen,
// minHops, keine Remainder-Rinne, Determinismus.
// =====================================================================
const CB = {
  s: "rTESTCBS000000000000000000000001",
  r1: "rTESTCBR10000000000000000000001",
  f: "rTESTCBF00000000000000000000001",
  r2: "rTESTCBR20000000000000000000002",
  e: "rTESTCBE00000000000000000000001",
};
const cbIso = (h) => new Date(Date.parse("2026-10-01T00:00:00Z") + h * 3600 * 1000).toISOString();
const cbEdge = (hash, seq, from, to, drops, iso) => ({
  from, to, amountDrops: drops, txHash: hash, ledgerSeq: seq, closeTime: iso ?? cbIso(1),
});

test("cross-block: Matrix Flag-Durchgang/Fenster/Gap/Hub/Side-Inkommen/minHops/Remainder", () => {
  const flagged = [pflag(CB.s), pflag(CB.f), pflag(CB.e, "malicious")];
  const baseEdges = () => [
    cbEdge("K1", 10, CB.s, CB.r1, 10000),
    cbEdge("K2", 11, CB.r1, CB.f, 8000),
    cbEdge("K3", 12, CB.f, CB.r2, 6400),
    cbEdge("K4", 13, CB.r2, CB.e, 5120),
  ];

  // (1) Basiskette: geflaggte Zwischenknoten werden durchwandert (State-
  //     Kanten sind nur bei geflaggtem Endpunkt sichtbar), Brücken bleiben
  //     ungeflaggt.
  const base = detectPeelingChainsOverEdges(baseEdges(), flagged);
  assert.equal(base.length, 1, "4-Hop-Kette über State-Kanten");
  assert.deepEqual(base[0].addresses, [CB.s, CB.r1, CB.f, CB.r2, CB.e]);
  assert.deepEqual(base[0].bridges, [CB.r1, CB.r2], "nur ungeflaggte Relays sind Brücken");
  assert.equal(base[0].hopsCount, 4);
  assert.ok(base[0].fingerprint && typeof base[0].fingerprint.score === "number", "Fingerprint vorhanden");
  assert.ok(!("remainderHops" in base[0]), "keine Remainder-Rinne über State-Kanten (Peel unsichtbar)");

  // (2) 24-h-Fenster (79-%-Quantil): Spanne über dem Fenster bricht, darunter bleibt.
  const spread = (hours) => [
    cbEdge("K1", 10, CB.s, CB.r1, 10000, cbIso(0)),
    cbEdge("K2", 11, CB.r1, CB.f, 8000, cbIso(1)),
    cbEdge("K3", 12, CB.f, CB.r2, 6400, cbIso(hours - 1)),
    cbEdge("K4", 13, CB.r2, CB.e, 5120, cbIso(hours)),
  ];
  const winHours = CROSS_BLOCK_PEELING_THRESHOLDS.windowMs / (3600 * 1000);
  assert.equal(detectPeelingChainsOverEdges(spread(winHours + 1), flagged).length, 0, "Spanne über dem Fenster");
  assert.equal(detectPeelingChainsOverEdges(spread(winHours - 1), flagged).length, 1, "Spanne unter dem Fenster");

  // (3) Hop-Gap-Deckel: Abstand über maxHopGapLedgers bricht, am Deckel selbst bleibt.
  const gapOver = [
    cbEdge("K1", 10, CB.s, CB.r1, 10000),
    cbEdge("K2", 11, CB.r1, CB.f, 8000),
    cbEdge("K3", 11 + CROSS_BLOCK_PEELING_THRESHOLDS.maxHopGapLedgers + 1, CB.f, CB.r2, 6400),
    cbEdge("K4", 13, CB.r2, CB.e, 5120),
  ];
  assert.equal(detectPeelingChainsOverEdges(gapOver, flagged).length, 0, "Hop-Abstand über dem Deckel");
  const gapAt = [
    cbEdge("K1", 10, CB.s, CB.r1, 10000),
    cbEdge("K2", 11, CB.r1, CB.f, 8000),
    cbEdge("K3", 11 + CROSS_BLOCK_PEELING_THRESHOLDS.maxHopGapLedgers, CB.f, CB.r2, 6400),
    cbEdge("K4", 13, CB.r2, CB.e, 5120),
  ];
  assert.equal(detectPeelingChainsOverEdges(gapAt, flagged).length, 1, "Deckel selbst ist einschließend");

  // (4) Hub: ungeflaggter Relay mit > 20 Gesamtkanten wird nie durchwandert.
  const hubEdges = baseEdges();
  for (let i = 0; i < 21; i++) {
    hubEdges.push(cbEdge(`X${i}`, 20 + i, CB.r1, `rTESTCBDUST${String(i).padStart(2, "0")}000000000000000`, 500));
  }
  assert.equal(detectPeelingChainsOverEdges(hubEdges, flagged).length, 0, "Hub (Grad > 20) bricht");

  // (5) Side-Inkommen: ein Relay mit 2 Eingängen ist kein striktes 1:1.
  const sideEdges = [...baseEdges(), cbEdge("Y1", 9, "rTESTCBOTHER000000000000000001", CB.r1, 400)];
  assert.equal(detectPeelingChainsOverEdges(sideEdges, flagged).length, 0, "2 Eingänge brechen die 1:1-Reinheit");

  // (6) minHops 3 (klassisch): 2-Kanten-Kette reicht nicht.
  const twoHop = [cbEdge("K1", 10, CB.s, CB.r1, 10000), cbEdge("K2", 11, CB.r1, CB.e, 8000)];
  assert.equal(detectPeelingChainsOverEdges(twoHop, flagged).length, 0, "2 Hops < minHops");

  // (7) Ratio-Fenster: 0,97-Weiterleitung feuert NICHT (keine Remainder-
  //     Rinne über State-Kanten — der Peel ist dort unsichtbar).
  const sweepEdges = [
    cbEdge("K1", 10, CB.s, CB.r1, 10000),
    cbEdge("K2", 11, CB.r1, CB.f, 9700),
    cbEdge("K3", 12, CB.f, CB.r2, 7500),
    cbEdge("K4", 13, CB.r2, CB.e, 6000),
  ];
  assert.equal(detectPeelingChainsOverEdges(sweepEdges, flagged).length, 0, "0,97 liegt über maxRatio der State-Sicht");

  // (8) Determinismus: Kanten-Reihenfolge entscheidet nie.
  const a = JSON.stringify(detectPeelingChainsOverEdges(baseEdges(), flagged));
  const b = JSON.stringify(detectPeelingChainsOverEdges([...baseEdges()].reverse(), flagged));
  const c = JSON.stringify(
    detectPeelingChainsOverEdges([baseEdges()[2], baseEdges()[0], baseEdges()[3], baseEdges()[1]], flagged)
  );
  assert.equal(a, b);
  assert.equal(a, c);

  // (9) Fingerprint der State-Sicht: Intervall + Tag (Kanten-toTag/fromTag);
  //     Fee fehlt bewusst (Kanten persistieren keine Fees), Betrags-Duplikate
  //     sind kettenmathematisch unmöglich (Hop-Beträge sinken streng monoton).
  const fpEdges = [
    { ...cbEdge("K1", 10, CB.s, CB.r1, 8000), toTag: 77 },
    { ...cbEdge("K2", 13, CB.r1, CB.f, 6400), toTag: 77 },
    { ...cbEdge("K3", 16, CB.f, CB.r2, 5120), fromTag: 77 },
    { ...cbEdge("K4", 19, CB.r2, CB.e, 4096) },
  ];
  const fpChains = detectPeelingChainsOverEdges(fpEdges, flagged);
  assert.equal(fpChains.length, 1);
  assert.ok(fpChains[0].fingerprint.criteria.includes("interval-regularity"), "Abstände 3/3/3 erkannt");
  assert.ok(fpChains[0].fingerprint.criteria.includes("tag-reuse"), "Kanten-toTag/fromTag zählen als Tag-Wiederverwendung");
  assert.ok(!fpChains[0].fingerprint.criteria.includes("fee-constancy"), "Fee-Kriterium ohne Fee-Daten aus");
  assert.ok(!fpChains[0].fingerprint.criteria.includes("amount-duplicates"), "streng monotone Hop-Beträge duplizieren nie");
});

// =====================================================================
// V3 — Temporale Metriken (rein, deterministisch). Matrix über Serie,
// Volumen und fan-out; Schwellen aus TEMPORAL_THRESHOLDS abgeleitet.
// =====================================================================
test("temporal: Matrix burst/medianInterarrival/velocity/ageVolume/automated", () => {
  assert.equal(LEDGER_INTERVAL_MS, 4000, "XRPL ~4 s pro Ledger");
  // (1) Dichte Serie: 5 Punkte in k=10 Ledern -> burst 5, Median-Abstand 1.
  const dense = temporalMetrics({ s: [0, 1, 2, 3, 4], out: 6e8, outN: 5 });
  assert.equal(dense.burst, 5, "alle 5 Punkte liegen im Burst-Fenster");
  assert.equal(dense.medianInterarrival, 1);
  assert.equal(dense.automated, true, "burst >= burstMin UND Median <= medianInterarrivalMax");
  assert.equal(dense.ageVolumeScore, true, "Spanne < 24 h UND out >= 500 XRP UND outN >= 5");
  // Velocity: Spanne 4 Ledger = 16 s -> out pro Stunde riesig, aber deterministisch.
  assert.ok(dense.velocityOutPerHour > 0, "Velocity über die Serien-Spanne");

  // (2) Gestreckte Serie: Median-Abstand über der Schwelle -> nicht automatisiert.
  const spread = temporalMetrics({ s: [0, 100, 200], out: 6e8, outN: 3 });
  assert.equal(spread.medianInterarrival, 100);
  assert.equal(spread.automated, false);
  // Spanne 200 < dayLedgers und out >= 500 XRP, aber outN 3 < 5 ->
  // ageVolumeScore braucht ALLE Kriterien (FP-Guard c).
  assert.equal(spread.ageVolumeScore, false, "fan-out unter der Schwelle");

  // (3) Alte, große Serie: Spanne >= dayLedgers -> kein ageVolume trotz Volumen.
  const old = temporalMetrics({ s: [0, TEMPORAL_THRESHOLDS.dayLedgers], out: 6e8, outN: 5 });
  assert.equal(old.ageVolumeScore, false, "Alters-Normierung fehlt -> kein Score (FP-Guard c)");

  // (4) Volumen unter der Schwelle -> kein ageVolume trotz Jugend und fan-out.
  const small = temporalMetrics({ s: [0, 1, 2, 3, 4], out: 1, outN: 5 });
  assert.equal(small.ageVolumeScore, false);

  // (5) Einzelpunkt: nichts messbar (kein Raten).
  const single = temporalMetrics({ s: [42], out: 100, outN: 1 });
  assert.equal(single.burst, 1);
  assert.equal(single.medianInterarrival, null);
  assert.equal(single.velocityOutPerHour, null);
  assert.equal(single.ageVolumeScore, false);
  assert.equal(single.automated, false);

  // (6) Velocity-Normierung: 900 Ledger = 1 h -> out ist out/h.
  const hourSpan = 3600 * 1000 / LEDGER_INTERVAL_MS; // Ledger pro Stunde
  const vel = temporalMetrics({ s: [0, hourSpan], out: 3.6e6, outN: 2 });
  assert.ok(Math.abs(vel.velocityOutPerHour - 3.6e6) < 1e-6, "Spanne 1 h -> out === out pro Stunde");

  // (7) Defensive Coercion: kaputte Serie/Beträge -> Nullwerte, kein Wurf.
  const broken = temporalMetrics({ s: ["x", null, 5], out: "kaputt", outN: -1 });
  assert.equal(broken.burst, 1, "nur der eine valide Punkt zählt");
  assert.equal(broken.medianInterarrival, null, "1 Punkt -> kein Abstand messbar");
  assert.equal(broken.velocityOutPerHour, null);
  assert.equal(broken.ageVolumeScore, false);
  assert.equal(broken.automated, false);

  // (8) Kappen-Vertrag: Serie und Adressen bleiben eng (Byte-Budget Flow-State).
  assert.ok(TEMPORAL_SERIES_CAP > 0 && TEMPORAL_SERIES_CAP <= 32, "Serie <= 32 Punkte (Strategie-Vorgabe)");
  assert.ok(TEMPORAL_MAX_ADDRESSES > 0 && TEMPORAL_MAX_ADDRESSES <= 8, "Adressen <= 8 je Cluster (Byte-Budget)");
});

test("temporal: txRecordFromEntry liefert feeDrops und Flags (V2/V3-Rohstoffe)", () => {
  const rec = txRecordFromEntry({
    hash: "Z1", ledger_index: 5, TransactionType: "Payment",
    Account: R.alpha, Destination: R.beta, Amount: "1000", Fee: "12", Flags: 2147483648,
  });
  assert.equal(rec.feeDrops, 12, "Fee-String in Drops wird numerisch");
  assert.equal(rec.flags, 2147483648, "Flags werden numerisch durchgereicht");
  const bare = txRecordFromEntry({
    hash: "Z2", ledger_index: 6, TransactionType: "Payment",
    Account: R.alpha, Destination: R.beta, Amount: "1000",
  });
  assert.ok(!("feeDrops" in bare), "ohne Fee kein Feld");
  assert.ok(!("flags" in bare), "ohne Flags kein Feld");
});

// =====================================================================
// V4 — Motiv-Zähler (motifCounters): Matrix über Zyklus-/Gather-Bedingungen,
// FP-Guards (Refund, conserve, IOU, Registry-Ausschluss, Fenster) und
// Determinismus/Kappen. Synthetische Adressen (M.*) — keine echten, keine
// Köder. ma < mb lexikalisch (kanonische Paar-Ordnung a<b).
// =====================================================================
const M = {
  ma: "rTESTMOTIVA00000000000000000001",
  mb: "rTESTMOTIVB00000000000000000001",
  ex: "rTESTMOTIVEX0000000000000000001", // Börsen-Rolle im exclude-Set
  g: "rTESTMOTIVG00000000000000000001", // Gather-Scatter-Knoten
  h: "rTESTMOTIVH00000000000000000001", // fanIn 3 / fanOut 2 (kein Gather)
  p1: "rTESTMOTIVP10000000000000000001",
  p2: "rTESTMOTIVP20000000000000000001",
  p3: "rTESTMOTIVP30000000000000000001",
  q1: "rTESTMOTIVQ10000000000000000001",
  q2: "rTESTMOTIVQ20000000000000000001",
  q3: "rTESTMOTIVQ30000000000000000001",
};
const me = (hash, seq, from, to, drops, iso = "2026-10-01T10:00:00Z") => ({
  from, to, amountDrops: drops, txHash: hash, ledgerSeq: seq, closeTime: iso,
});

test("motifCounters: 2-Zykel mit Volumenerhalt 0,95 im 1-h-Fenster wird erkannt", () => {
  const res = motifCounters([
    me("W1", 11, M.ma, M.mb, 1000),
    me("W2", 12, M.ma, M.mb, 1000),
    me("W3", 13, M.mb, M.ma, 950, "2026-10-01T10:20:00Z"),
    me("W4", 14, M.mb, M.ma, 950, "2026-10-01T10:20:00Z"),
  ]);
  assert.equal(res.washCycles.length, 1, "genau ein Zyklus");
  const cy = res.washCycles[0];
  assert.equal(cy.a, M.ma, "kanonische Ordnung a<b");
  assert.equal(cy.b, M.mb);
  assert.equal(cy.fwdDrops, 2000);
  assert.equal(cy.bwdDrops, 1900);
  assert.ok(Math.abs(cy.conserve - 0.95) < 1e-9, "conserve 1900/2000");
  assert.equal(cy.firstLedgerSeq, 11);
  assert.equal(cy.lastLedgerSeq, 14);
  assert.equal(cy.signature, `${M.ma},${M.mb}`);
  assert.equal(res.gatherScatter.length, 0, "2+2-Kanten-Paar ist kein Gather-Scatter");
  assert.ok(res.fanInMax >= 1 && res.fanOutMax >= 1, "Fan-Zähler gesetzt");
});

test("motifCounters: Guard — nur 1 Kante je Richtung ist kein Zyklus (Refund-Guard)", () => {
  const res = motifCounters([
    me("W1", 11, M.ma, M.mb, 1000),
    me("W3", 13, M.mb, M.ma, 950),
  ]);
  assert.equal(res.washCycles.length, 0, "Einzelpaar = normale Markt-/Rückerstattungs-Bewegung");
});

test("motifCounters: Guard — Rückrichtung 0,3× (conserve < 0,8) ist kein Zyklus", () => {
  const res = motifCounters([
    me("W1", 11, M.ma, M.mb, 1000),
    me("W2", 12, M.ma, M.mb, 1000),
    me("W3", 13, M.mb, M.ma, 300),
    me("W4", 14, M.mb, M.ma, 300),
  ]);
  assert.equal(res.washCycles.length, 0);
});

test("motifCounters: Guard — Börsen-Endpunkt (exclude) ist nie Zykelglied und nie Gather", () => {
  const res = motifCounters([
    me("W1", 11, M.ma, M.ex, 1000),
    me("W2", 12, M.ma, M.ex, 1000),
    me("W3", 13, M.ex, M.ma, 950),
    me("W4", 14, M.ex, M.ma, 950),
    me("G1", 15, M.p1, M.ex, 100),
    me("G2", 16, M.p2, M.ex, 100),
    me("G3", 17, M.p3, M.ex, 100),
    me("G4", 18, M.ex, M.q1, 100),
    me("G5", 19, M.ex, M.q2, 100),
    me("G6", 20, M.ex, M.q3, 100),
  ], { exclude: new Set([M.ex]) });
  assert.equal(res.washCycles.length, 0, "Registry nie Zykelglied");
  assert.ok(!res.gatherScatter.includes(M.ex), "Registry nie Gather-Knoten");
  assert.equal(res.fanInMax, 0, "ausgeschlossene Kanten zählen in keine Fan-Menge");
});

test("motifCounters: Guard — nur IOU-Kanten (amountDrops null) erzeugen kein Motiv", () => {
  const iou = (hash, seq, from, to, iso) => ({ from, to, amountDrops: null, txHash: hash, ledgerSeq: seq, closeTime: iso });
  const res = motifCounters([
    iou("W1", 11, M.ma, M.mb, "2026-10-01T10:00:00Z"),
    iou("W2", 12, M.ma, M.mb, "2026-10-01T10:00:00Z"),
    iou("W3", 13, M.mb, M.ma, "2026-10-01T10:20:00Z"),
    iou("W4", 14, M.mb, M.ma, "2026-10-01T10:20:00Z"),
  ]);
  assert.equal(res.washCycles.length, 0, "IOU = DEX-normal, ausgeschlossen");
  assert.equal(res.gatherScatter.length, 0);
  assert.equal(res.fanInMax, 0);
  assert.equal(res.fanOutMax, 0);
});

test("motifCounters: Guard — 2-h-Fenster (End-zu-Ende) verhindert den Zyklus", () => {
  const res = motifCounters([
    me("W1", 11, M.ma, M.mb, 1000, "2026-10-01T10:00:00Z"),
    me("W2", 12, M.ma, M.mb, 1000, "2026-10-01T10:00:00Z"),
    me("W3", 13, M.mb, M.ma, 950, "2026-10-01T12:00:01Z"),
    me("W4", 14, M.mb, M.ma, 950, "2026-10-01T12:00:01Z"),
  ]);
  assert.equal(res.washCycles.length, 0, "Spanne > cycleWindowMs 1 h");
});

test("motifCounters: Gather-Scatter — 3 Ein-/3 Aus-Gegenparteien am selben Knoten", () => {
  const res = motifCounters([
    me("G1", 11, M.p1, M.g, 100), me("G2", 12, M.p2, M.g, 100), me("G3", 13, M.p3, M.g, 100),
    me("G4", 14, M.g, M.q1, 100), me("G5", 15, M.g, M.q2, 100), me("G6", 16, M.g, M.q3, 100),
  ]);
  assert.deepEqual(res.gatherScatter, [M.g], "fanIn 3 ∧ fanOut 3 am selben Knoten");
  assert.equal(res.fanInMax, 3);
  assert.equal(res.fanOutMax, 3);
});

test("motifCounters: Guard — fanIn 3 / fanOut 2 ist kein Gather-Scatter", () => {
  const res = motifCounters([
    me("G1", 11, M.p1, M.h, 100), me("G2", 12, M.p2, M.h, 100), me("G3", 13, M.p3, M.h, 100),
    me("G4", 14, M.h, M.q1, 100), me("G5", 15, M.h, M.q2, 100),
  ]);
  assert.equal(res.gatherScatter.length, 0);
  assert.equal(res.fanInMax, 3);
  assert.equal(res.fanOutMax, 2, "fanOutMax bleibt als note-Kennzahl erhalten");
});

test("motifCounters: Determinismus — gemischte Eingabe liefert byteidentische Ausgabe", () => {
  const base = [
    me("W1", 11, M.ma, M.mb, 1000),
    me("W2", 12, M.ma, M.mb, 1000),
    me("W3", 13, M.mb, M.ma, 950),
    me("W4", 14, M.mb, M.ma, 950),
    me("G1", 15, M.p1, M.g, 100), me("G2", 16, M.p2, M.g, 100), me("G3", 17, M.p3, M.g, 100),
    me("G4", 18, M.g, M.q1, 100), me("G5", 19, M.g, M.q2, 100), me("G6", 20, M.g, M.q3, 100),
  ];
  const shuffled = [base[7], base[0], base[9], base[2], base[5], base[1], base[8], base[3], base[6], base[4]];
  assert.deepEqual(motifCounters(shuffled), motifCounters(base), "Eingabereihenfolge entscheidet nie");
  assert.deepEqual(JSON.parse(JSON.stringify(motifCounters(base))), motifCounters(base), "JSON-Roundtrip identisch");
});

test("motifCounters: Kappe — > maxCycles 8 Zyklen -> 8, Signatur asc", () => {
  const edges = [];
  const sigs = [];
  for (let i = 0; i < 9; i++) {
    const pa = `rTESTMOTIX${String(i).padStart(2, "0")}A0000000000000000001`;
    const pb = `rTESTMOTIX${String(i).padStart(2, "0")}B0000000000000000001`;
    sigs.push(`${pa},${pb}`);
    edges.push(
      me(`C${i}a`, 100 + i * 10, pa, pb, 1000),
      me(`C${i}b`, 101 + i * 10, pa, pb, 1000),
      me(`C${i}c`, 102 + i * 10, pb, pa, 900),
      me(`C${i}d`, 103 + i * 10, pb, pa, 900)
    );
  }
  const res = motifCounters(edges);
  assert.equal(res.washCycles.length, MOTIF_THRESHOLDS.maxCycles, "auf maxCycles gekappt");
  assert.deepEqual(
    res.washCycles.map((cy) => cy.signature),
    [...sigs].sort().slice(0, MOTIF_THRESHOLDS.maxCycles),
    "die asc ersten Signaturen bleiben"
  );
});

test("motifCounters: Kappen-Vertrag konservativ (Strategie-Vorgabe, Byte-Budget)", () => {
  assert.equal(MOTIF_THRESHOLDS.gatherMinFan, 3);
  assert.equal(MOTIF_THRESHOLDS.cycleMinEdgesPerSide, 2);
  assert.equal(MOTIF_THRESHOLDS.cycleConserveMin, 0.8);
  assert.equal(MOTIF_THRESHOLDS.cycleWindowMs, 3600000);
  assert.ok(MOTIF_THRESHOLDS.maxCycles > 0 && MOTIF_THRESHOLDS.maxCycles <= 16);
  assert.ok(MOTIF_THRESHOLDS.maxGather > 0 && MOTIF_THRESHOLDS.maxGather <= 16);
});
