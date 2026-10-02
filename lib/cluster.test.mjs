// lib/cluster.test.mjs — node:test-Unit-Tests mit synthetischen Fixtures.
// Muster wie lib/detector.test.mjs: synthetische rTEST…-Adressen (keine
// echten, keine Köder). Ausführen: node --test lib/cluster.test.mjs
import test from "node:test";
import assert from "node:assert/strict";
import { buildClusterGraph, txRecordFromEntry, ROLE_THRESHOLDS } from "./cluster.mjs";

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

// ---------- 27) Gegenbewegungs-Typen im Graph (EscrowFinish/CheckCash/VaultWithdraw) ----------
// Audit-Probe über 26 Tx-Typen: EscrowFinish/CheckCash/VaultWithdraw hatten
// dest='-' (isoliert). Jetzt erscheint die reale Geldbewegung als Kante.
test("Gegenbewegungen: EscrowFinish/CheckCash/VaultWithdraw erzeugen Kanten", () => {
  const entries = [
    { hash: "H1", ledger_index: 10, close_time_iso: R.iso, TransactionType: "EscrowFinish", Account: R.alpha, Owner: R.beta, Amount: "1000" },
    { hash: "H2", ledger_index: 11, close_time_iso: R.iso, TransactionType: "CheckCash", Account: R.beta, CheckDestination: R.gamma, Amount: "2000" },
    { hash: "H3", ledger_index: 12, close_time_iso: R.iso, TransactionType: "VaultWithdraw", Account: R.gamma, VaultOwner: R.alpha, VaultAmount: "3000" },
  ];
  const recs = entries.map((e) => txRecordFromEntry(e, null));
  assert.equal(recs[0].destination, R.beta);
  assert.equal(recs[1].destination, R.gamma);
  assert.equal(recs[2].destination, R.alpha);
  assert.equal(recs[2].amountDrops, 3000, "VaultAmount wird als Betrag gelesen");
  const g = buildClusterGraph(recs, [finding(R.alpha), finding(R.gamma)]);
  assert.equal(g.edges.length, 3);
  assert.deepEqual(g.edges.map((e) => e.type), ["EscrowFinish", "CheckCash", "VaultWithdraw"]);
});
