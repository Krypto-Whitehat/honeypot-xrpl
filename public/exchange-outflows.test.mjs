// public/exchange-outflows.test.mjs — Unit-Tests für die DOM-freie
// Top-10-Börsen-Zufluss-Aggregation (public/exchange-outflows.mjs, genutzt von
// public/app.js renderExchangeOutflows) und deren Verdrahtung.
//
// Kein Browser: das Modul ist per Vertrag DOM-frei und rein funktional; die
// Zeilen-Markup-Funktion bekommt die Host-Gates (esc/displayAddr/fmtXrp/
// fmtNum/labels) als Stubs injiziert — Muster public/cluster-chips.test.mjs.
// Alle Adressen synthetisch (rTEST-…-Familie), Base58-gültig (ohne 0/O/I/l).
//
// Geprüft: (1) Aggregation deterministisch — Qualifikation über Severity ODER
// Drainer-Rolle je KANTEN-QUELLE (nicht Cluster-level), Fenster-Grenzen exakt
// (7 d/30 d inklusive Untergrenze, Zukunft ausgeschlossen), fehlendes
// closeTime → excludedNoCloseTime statt stillem Verwerfen, Ziel außerhalb der
// Börsen-Union ignoriert, Tie-Breaks dropsSum → inEdges → Adresse asc
// (binär), Default-Kappung topN = 10, Cap-Sichtbarkeit cappedClusters,
// well-known-Flag, 7d/30d-Trennung in EINEM Durchlauf, coverageFrom =
// min firstSeen, fail-closed ohne Map. (2) Box-Rendering — Zeilen-Markup
// ausschließlich über die injizierten Gates: esc() auf JEDEM Registry-String
// (Pflicht 12), displayAddr-Gate (Gate verweigert → keine Zeile), fmtXrp für
// den Betrag, Transit-/well-known-Badges nur bei belegten Werten, Rang-Nummer.
// (3) i18n — exout.*-Keys in EN und DE vorhanden, nicht leer, Platzhalter-
// Parität, deutsche Orthografie (ä ö ü ß), index.html referenziert nur
// existierende Keys, app.js/package.json verkabeln Modul, Poll und Testscript.

import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";
import {
  aggregateExchangeOutflows, exchangeOutflowRowHtml,
  EXOUT_WINDOW_7D_MS, EXOUT_WINDOW_30D_MS, EXOUT_EDGE_CAP,
} from "./exchange-outflows.mjs";
import { DICT } from "./i18n.mjs";

/* ---------------- Fixture-Adressen (Base58 ohne 0/O/I/l) ---------------- */

const SRC_MAL = "rDrainerAcc1111111111111111111";     // severity malicious
const SRC_SUS = "rSuspectAcc1111111111111111111";     // severity suspect
const SRC_DRA = "rSweeperAcc11111111111111111111";    // Rolle drainer, severity info
const SRC_PLAIN = "rPlainAcc111111111111111111111";   // weder noch (Negativkontrolle)
const TA = "rTargetAccA1111111111111111111";
const TB = "rTargetAccB1111111111111111111";
const TC = "rTargetAccC1111111111111111111";
const TD = "rTargetAccD1111111111111111111";

const iso = (ms) => new Date(ms).toISOString();
const NOW = Date.UTC(2026, 9, 7, 12, 0, 0); // 2026-10-07T12:00:00Z (feste Referenz)

function exchangeMap() {
  return new Map([
    [TA, { exchange: "Börse A", domain: "a.example", confidence: "well-known" }],
    [TB, { exchange: "Exchange <B>", domain: "b.example", confidence: "verified" }],
    [TC, { exchange: "Börse C", domain: null, confidence: "well-known" }],
    [TD, { exchange: "Börse D", domain: "d.example", confidence: "well-known" }],
  ]);
}

const view = (clusters) => ({ clusters });

// Minimales Drainer-Cluster als Fixture-Baustein.
function cluster(id, rolesByAddress, severityByAddress, firstSeen, edges) {
  return { id, rolesByAddress, severityByAddress, firstSeen, lastSeen: firstSeen, edges };
}

/* ---------------- 1) Aggregation: Qualifikation ---------------- */

test("Qualifikation je KANTEN-Quelle: Severity ODER drainer-Rolle im selben Cluster, Cluster-level-Prädikat qualifiziert NICHT", () => {
  const v = view([
    cluster("cluster:1",
      { [SRC_MAL]: "collector", [SRC_DRA]: "drainer", [SRC_SUS]: "relay", [SRC_PLAIN]: "collector" },
      { [SRC_MAL]: "malicious", [SRC_DRA]: "info", [SRC_SUS]: "suspect", [SRC_PLAIN]: "info" },
      iso(NOW - 3600e3),
      [
        { from: SRC_MAL, to: TA, amountDrops: 100, closeTime: iso(NOW - 60e3) },   // severity malicious → zählt
        { from: SRC_DRA, to: TB, amountDrops: 200, closeTime: iso(NOW - 60e3) },   // drainer-Rolle (info) → zählt
        { from: SRC_SUS, to: TC, amountDrops: 300, closeTime: iso(NOW - 60e3) },   // severity suspect → zählt
        { from: SRC_PLAIN, to: TD, amountDrops: 400, closeTime: iso(NOW - 60e3) }, // info + collector → ignoriert
        { from: "rUnknownAcc111111111111111111", to: TA, amountDrops: 500, closeTime: iso(NOW - 60e3) }, // Quelle ohne Metadaten → ignoriert
      ]),
  ]);
  const res = aggregateExchangeOutflows(v, exchangeMap(), NOW);
  assert.equal(res.seven.totals.qualifyingEdges, 3, "genau die drei kontextbelegten Kanten");
  assert.equal(res.seven.totals.qualifyingDrops, 600);
  const byAddr = new Map(res.seven.rows.map((r) => [r.address, r]));
  assert.equal(byAddr.get(TA).dropsSum, 100, "TA nur über die maliziöse Quelle");
  assert.equal(byAddr.get(TB).dropsSum, 200, "TB nur über die drainer-Rolle");
  assert.equal(byAddr.get(TC).dropsSum, 300, "TC über suspect");
  assert.equal(byAddr.has(TD), false, "TD ohne Drainer-Kontext erscheint nicht");
});

test("Ziel NICHT in der Börsen-Union → Kante ignoriert; fehlende Map/defekte View → fail-closed leer", () => {
  const v = view([
    cluster("cluster:1",
      { [SRC_MAL]: "drainer" }, { [SRC_MAL]: "malicious" }, iso(NOW - 3600e3),
      [
        { from: SRC_MAL, to: TA, amountDrops: 100, closeTime: iso(NOW - 60e3) },
        { from: SRC_MAL, to: "rOutsideAcc1111111111111111111", amountDrops: 900, closeTime: iso(NOW - 60e3) },
      ]),
  ]);
  const res = aggregateExchangeOutflows(v, exchangeMap(), NOW);
  assert.equal(res.seven.totals.qualifyingEdges, 1);
  assert.deepEqual(res.seven.rows.map((r) => r.address), [TA]);
  // Keine Union (null / leere Map): nichts qualifiziert, leere Buckets.
  const resNull = aggregateExchangeOutflows(v, null, NOW);
  assert.equal(resNull.seven.rows.length, 0);
  assert.equal(resNull.seven.totals.qualifyingEdges, 0);
  const resEmpty = aggregateExchangeOutflows(v, new Map(), NOW);
  assert.equal(resEmpty.thirty.rows.length, 0);
  // Defekte View-Formen: ebenfalls leer, nie ein Wurf.
  assert.equal(aggregateExchangeOutflows(null, exchangeMap(), NOW).seven.rows.length, 0);
  assert.equal(aggregateExchangeOutflows({}, exchangeMap(), NOW).thirty.rows.length, 0);
  assert.equal(aggregateExchangeOutflows({ clusters: [null, 42] }, exchangeMap(), NOW).seven.rows.length, 0);
});

/* ---------------- 2) Fenster-Grenzen (7d/30d, ein Durchlauf) ---------------- */

test("Fenster-Grenzen: 7d/30d inklusive Untergrenze, Zukunft/Jenseits ausgeschlossen, 7d ⊆ 30d", () => {
  const edges = [
    { from: SRC_MAL, to: TA, amountDrops: 100, closeTime: iso(NOW - 3600e3) },                    // beide
    { from: SRC_MAL, to: TA, amountDrops: 200, closeTime: iso(NOW - EXOUT_WINDOW_7D_MS) },        // exakt 7d → beide (inklusive)
    { from: SRC_MAL, to: TB, amountDrops: 300, closeTime: iso(NOW - EXOUT_WINDOW_7D_MS - 1000) }, // älter als 7d → nur 30d
    { from: SRC_MAL, to: TB, amountDrops: 400, closeTime: iso(NOW - EXOUT_WINDOW_30D_MS) },       // exakt 30d → nur 30d (inklusive)
    { from: SRC_MAL, to: TC, amountDrops: 500, closeTime: iso(NOW - EXOUT_WINDOW_30D_MS - 1000) },// älter als 30d → keins
    { from: SRC_MAL, to: TC, amountDrops: 600, closeTime: iso(NOW + 1000) },                      // Zukunft → keins
  ];
  const v = view([cluster("cluster:1",
    { [SRC_MAL]: "drainer" }, { [SRC_MAL]: "malicious" },
    iso(NOW - EXOUT_WINDOW_30D_MS - 2000), edges)]);
  const res = aggregateExchangeOutflows(v, exchangeMap(), NOW);
  assert.equal(res.seven.windowDays, 7);
  assert.equal(res.thirty.windowDays, 30);
  const seven = new Map(res.seven.rows.map((r) => [r.address, r]));
  const thirty = new Map(res.thirty.rows.map((r) => [r.address, r]));
  assert.deepEqual([...seven.keys()].sort(), [TA], "7d: nur TA (Grenzkante inklusive)");
  assert.deepEqual([...thirty.keys()].sort(), [TA, TB], "30d: zusätzlich TB, TC bleibt außen (zu alt + Zukunft)");
  assert.equal(seven.get(TA).dropsSum, 300, "TA 7d: 100+200");
  assert.equal(thirty.get(TA).dropsSum, 300, "TA 30d: dieselben zwei Kanten");
  assert.equal(thirty.get(TB).dropsSum, 700, "TB 30d: 300+400");
  assert.equal(seven.has(TB), false, "TB 7d: beide Kanten außerhalb des Fensters");
  assert.equal(thirty.has(TC), false, "TC in keinem Fenster");
  assert.equal(res.seven.totals.qualifyingEdges, 2, "7d: 100+200");
  assert.equal(res.seven.totals.qualifyingDrops, 300);
  assert.equal(res.thirty.totals.qualifyingEdges, 4, "30d: 100+200+300+400");
  assert.equal(res.thirty.totals.qualifyingDrops, 1000, ">30d und Zukunft zählen in keinem Bucket");
});

test("Fehlendes/unparsebares closeTime → excludedNoCloseTime statt stillem Verwerfen", () => {
  const v = view([
    cluster("cluster:1",
      { [SRC_MAL]: "drainer" }, { [SRC_MAL]: "malicious" }, iso(NOW - 3600e3),
      [
        { from: SRC_MAL, to: TA, amountDrops: 100, closeTime: iso(NOW - 60e3) },
        { from: SRC_MAL, to: TA, amountDrops: 200 },                          // ohne closeTime
        { from: SRC_MAL, to: TB, amountDrops: 300, closeTime: "not-a-date" }, // unparsebar
        { from: SRC_MAL, to: "rOutsideAcc1111111111111111111", amountDrops: 400 }, // außerhalb der Fragestellung → kein excluded
      ]),
  ]);
  const res = aggregateExchangeOutflows(v, exchangeMap(), NOW);
  assert.equal(res.seven.totals.excludedNoCloseTime, 2, "genau die zwei qualifizierenden Kanten ohne Zeit");
  assert.equal(res.thirty.totals.excludedNoCloseTime, 2);
  assert.equal(res.seven.totals.qualifyingEdges, 1);
});

/* ---------------- 3) Sortierung, Tie-Breaks, Kappung, Cap ---------------- */

test("Sortierung: dropsSum desc → inEdges desc → Adresse asc (binär), deterministisch", () => {
  // TA: 500 Drops / 1 Kante · TB: 500 / 2 · TC: 500 / 1 → TB vor TA vor TC
  const edges = [
    { from: SRC_MAL, to: TA, amountDrops: 500, closeTime: iso(NOW - 60e3) },
    { from: SRC_MAL, to: TB, amountDrops: 250, closeTime: iso(NOW - 60e3) },
    { from: SRC_MAL, to: TB, amountDrops: 250, closeTime: iso(NOW - 120e3) },
    { from: SRC_MAL, to: TC, amountDrops: 500, closeTime: iso(NOW - 60e3) },
  ];
  const res = aggregateExchangeOutflows(
    view([cluster("cluster:1", { [SRC_MAL]: "drainer" }, { [SRC_MAL]: "malicious" }, iso(NOW - 3600e3), edges)]),
    exchangeMap(), NOW,
  );
  assert.deepEqual(res.seven.rows.map((r) => r.address), [TB, TA, TC], "dropsSum-Gleichstand → inEdges desc → Adresse asc");
  assert.deepEqual(res.seven.rows.map((r) => r.inEdges), [2, 1, 1]);

  // Reine Adress-Tiebreaks: vier Ziele mit identischen Summen UND Kantenzahlen.
  const tied = [TD, TB, TA, TC].map((t) => ({ from: SRC_MAL, to: t, amountDrops: 100, closeTime: iso(NOW - 60e3) }));
  const res2 = aggregateExchangeOutflows(
    view([cluster("cluster:1", { [SRC_MAL]: "drainer" }, { [SRC_MAL]: "malicious" }, iso(NOW - 3600e3), tied)]),
    exchangeMap(), NOW,
  );
  assert.deepEqual(res2.seven.rows.map((r) => r.address), [TA, TB, TC, TD], "binär aufsteigend");
});

test("Default-Kappung topN = 10; opts.topN verkleinert die Liste", () => {
  // 12 Union-Ziele mit identischen Werten → Reihenfolge rein über Adresse asc.
  const chars = "123456789ABC"; // Base58-Zeichen (ohne 0/O/I/l)
  const targets = [...chars].map((c) => `rTargetGen${c}Acc11111111111111111`);
  const union = new Map(targets.map((t, i) => [t, { exchange: `Börse ${i}`, domain: null, confidence: "well-known" }]));
  const edges = targets.map((t) => ({ from: SRC_MAL, to: t, amountDrops: 100, closeTime: iso(NOW - 60e3) }));
  const v = view([cluster("cluster:1", { [SRC_MAL]: "drainer" }, { [SRC_MAL]: "malicious" }, iso(NOW - 3600e3), edges)]);
  const def = aggregateExchangeOutflows(v, union, NOW);
  assert.equal(def.seven.rows.length, 10, "Default topN = 10 trotz 12 Zielen");
  assert.deepEqual(def.seven.rows.map((r) => r.address), targets.slice(0, 10), "die zehn kleinsten Adressen (Adresse asc)");
  const two = aggregateExchangeOutflows(v, union, NOW, { topN: 2 });
  assert.equal(two.seven.rows.length, 2);
  assert.deepEqual(two.seven.rows.map((r) => r.address), targets.slice(0, 2));
});

test("Cap-Sichtbarkeit: Cluster am 50-Kanten-Deckel zählen cappedClusters, kleinere/leere nicht", () => {
  const capEdges = Array.from({ length: EXOUT_EDGE_CAP }, (_, i) => (
    { from: SRC_MAL, to: i % 2 ? TB : TA, amountDrops: 10, closeTime: iso(NOW - 60e3) }
  ));
  const smallEdges = capEdges.slice(0, EXOUT_EDGE_CAP - 1);
  const v = view([
    cluster("cluster:cap", { [SRC_MAL]: "drainer" }, { [SRC_MAL]: "malicious" }, iso(NOW - 3600e3), capEdges),
    cluster("cluster:small", { [SRC_MAL]: "drainer" }, { [SRC_MAL]: "malicious" }, iso(NOW - 3600e3), smallEdges),
    cluster("cluster:empty", { [SRC_MAL]: "drainer" }, { [SRC_MAL]: "malicious" }, iso(NOW - 3600e3), []),
  ]);
  const res = aggregateExchangeOutflows(v, exchangeMap(), NOW);
  assert.equal(res.seven.totals.clustersScanned, 2, "Cluster ohne Kanten zählen nicht als betrachtet");
  assert.equal(res.seven.totals.cappedClusters, 1, "genau das Cluster am Deckel");
  assert.equal(res.thirty.totals.cappedClusters, 1);
});

test("Zeilen-Metadaten: clusterCount, lastInflowMs, transitDrops, wellKnown-Flag, coverageFrom", () => {
  const v = view([
    cluster("cluster:1", { [SRC_MAL]: "drainer" }, { [SRC_MAL]: "malicious" }, iso(NOW - 3600e3), [
      { from: SRC_MAL, to: TA, amountDrops: 100, closeTime: iso(NOW - 120e3), transit: true },
      { from: SRC_MAL, to: TA, amountDrops: 200, closeTime: iso(NOW - 60e3) },
    ]),
    cluster("cluster:2", { [SRC_SUS]: "collector" }, { [SRC_SUS]: "suspect" }, iso(NOW - 7200e3), [
      { from: SRC_SUS, to: TA, amountDrops: 300, closeTime: iso(NOW - 300e3) },
    ]),
    cluster("cluster:3", { [SRC_MAL]: "drainer" }, { [SRC_MAL]: "malicious" }, "not-a-date", [
      { from: SRC_MAL, to: TB, amountDrops: 50, closeTime: iso(NOW - 60e3) },
    ]),
  ]);
  const res = aggregateExchangeOutflows(v, exchangeMap(), NOW);
  const row = res.seven.rows.find((r) => r.address === TA);
  assert.equal(row.clusterCount, 2, "zwei verschiedene Cluster");
  assert.equal(row.lastInflowMs, NOW - 60e3, "spätester Zufluss");
  assert.equal(row.transitDrops, 100, "nur die transit-Kante");
  assert.equal(row.wellKnown, true, "TA ist well-known (Bulk-Union)");
  assert.equal(row.exchange, "Börse A");
  assert.equal(row.domain, "a.example");
  const rowB = res.seven.rows.find((r) => r.address === TB);
  assert.equal(rowB.wellKnown, false, "Registry-Confidence bleibt kein well-known");
  assert.equal(res.coverageFrom, iso(NOW - 7200e3), "min firstSeen aller betrachteten Cluster");
  assert.equal(res.generatedAt, NOW);
  // Ohne parsebare firstSeen: coverageFrom null (keine Erfundung).
  const resNull = aggregateExchangeOutflows(
    view([cluster("cluster:9", { [SRC_MAL]: "drainer" }, { [SRC_MAL]: "malicious" }, "x", [
      { from: SRC_MAL, to: TA, amountDrops: 1, closeTime: iso(NOW - 60e3) },
    ])]),
    exchangeMap(), NOW,
  );
  assert.equal(resNull.coverageFrom, null);
});

test("Determinismus: gleiche Eingabe → identische Buckets (keine Render-Zufälle)", () => {
  const build = () => view([
    cluster("cluster:1",
      { [SRC_MAL]: "drainer", [SRC_SUS]: "collector" },
      { [SRC_MAL]: "malicious", [SRC_SUS]: "suspect" },
      iso(NOW - 3600e3),
      [
        { from: SRC_MAL, to: TA, amountDrops: 100, closeTime: iso(NOW - 60e3) },
        { from: SRC_SUS, to: TB, amountDrops: 100, closeTime: iso(NOW - 60e3) },
      ]),
  ]);
  const a = aggregateExchangeOutflows(build(), exchangeMap(), NOW);
  const b = aggregateExchangeOutflows(build(), exchangeMap(), NOW);
  assert.deepEqual(a, b);
});

/* ---------------- 4) Box-Rendering (injizierte Host-Gates) ---------------- */

// Echte esc-Semantik (Spiegel app.js esc) — so wird Pflicht 12 wirklich geprüft.
const escReal = (value) => String(value ?? "").replace(/[&<>"']/g, (c) => ({
  "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
}[c]));

function uiStub(overrides = {}) {
  return {
    esc: escReal,
    displayAddr: (a) => `${String(a).slice(0, 8)}…${String(a).slice(-4)}`, // Masken-Stub
    fmtXrp: (n) => `FMT(${n})`,
    fmtNum: (n) => `N(${n})`,
    labels: {
      rankAria: (n) => `Rank ${n}`,
      inflows: (n) => `${n} edges`,
      clusters: (n) => `${n} clusters`,
      transit: (xrp) => `Transit: ${xrp} XRP`,
      wellKnown: "well-known",
    },
    ...overrides,
  };
}

const ROW = {
  address: TB,
  dropsSum: 1234567,
  inEdges: 3,
  clusterCount: 2,
  lastInflowMs: NOW,
  transitDrops: 0,
  exchange: 'Exchange <B> & "Co"',
  domain: "b.example",
  wellKnown: false,
};

test("Box-Rendering: Rang, gegatteter Name/Domain, Anzeige über displayAddr-Gate, fmtXrp-Betrag", () => {
  const html = exchangeOutflowRowHtml(ROW, 2, uiStub());
  assert.ok(html.startsWith('<li class="exout-row">'), "Zeilen-Markup der Box");
  assert.ok(html.includes(">2</span>"), "Rang-Nummer (1-basiert)");
  assert.ok(html.includes("Exchange &lt;B&gt; &amp; &quot;Co&quot;"), "Registry-Name esc-kodiert");
  assert.ok(!html.includes("Exchange <B>"), "kein roher Registry-String im Markup");
  assert.ok(html.includes("b.example"), "Domain sichtbar");
  assert.ok(html.includes("FMT(1234567) XRP"), "Betrag über injiziertes fmtXrp (Drops-Format Host-Sache)");
  assert.ok(html.includes("3 edges"), "Kantenzahl über das injizierte Label");
  assert.ok(html.includes("2 clusters"), "Clusterzahl über das injizierte Label");
  assert.ok(!html.includes("exout-badge-transit"), "ohne transitDrops kein Transit-Badge");
  assert.ok(!html.includes("exout-badge-wellknown"), "ohne well-known-Flag kein Badge");
  assert.ok(html.includes('title="Rank 2"'), "Rang-Aria als title");
  assert.ok(html.includes("rTargetA…1111"), "Anzeige-Adresse über das Masken-Gate");
  assert.ok(!html.includes(TB), "keine rohe Adresse im Markup");
});

test("Box-Rendering: well-known- und Transit-Badge nur bei belegten Werten", () => {
  const html = exchangeOutflowRowHtml({ ...ROW, wellKnown: true, transitDrops: 5000 }, 1, uiStub());
  assert.ok(html.includes("exout-badge-wellknown"), "well-known-Badge bei Flag");
  assert.ok(html.includes("FMT(5000) XRP"), "Transit-Anteil XRP-formatiert");
  assert.ok(html.includes("exout-badge-transit"), "Transit-Badge bei Anteil > 0");
  const without = exchangeOutflowRowHtml({ ...ROW, wellKnown: false, transitDrops: 0 }, 1, uiStub());
  assert.ok(!without.includes("exout-badge-"), "keine Badges ohne Beleg");
});

test("Box-Rendering (Pflicht 12): displayAddr-Gate verweigert → keine Zeile, nichts Rohes ins DOM", () => {
  const html = exchangeOutflowRowHtml(ROW, 1, uiStub({ displayAddr: () => "" }));
  assert.equal(html, "", "Gate-'': fail-closed, keine Zeile, keine Adresse");
  // Fallback-Name (ohne exchange-Entry) trägt ebenfalls die gegattete Adresse.
  const noName = exchangeOutflowRowHtml({ ...ROW, exchange: null }, 1, uiStub());
  assert.ok(noName.includes("rTargetA…1111"), "Namenszeile zeigt die Masken-Form, nicht die Roh-Adresse");
});

test("Box-Rendering: defekte/fehlende Gates → '' (Modul erfindet kein Markup)", () => {
  assert.equal(exchangeOutflowRowHtml(null, 1, uiStub()), "");
  assert.equal(exchangeOutflowRowHtml(ROW, 1, null), "");
  assert.equal(exchangeOutflowRowHtml(ROW, 1, {}), "");
  assert.equal(exchangeOutflowRowHtml(ROW, 1, uiStub({ esc: null })), "");
  assert.equal(exchangeOutflowRowHtml(ROW, 1, uiStub({ displayAddr: null })), "");
  assert.equal(exchangeOutflowRowHtml(ROW, 1, uiStub({ fmtXrp: null })), "");
  assert.equal(exchangeOutflowRowHtml(ROW, 1, uiStub({ fmtNum: null })), "");
});

/* ---------------- 5) i18n: exout.*-Keys DE==EN + Verdrahtung ---------------- */

const EXOUT_KEYS = [
  "exout.title", "exout.subtitle", "exout.window7", "exout.window30",
  "exout.windowAria", "exout.rank", "exout.inflows", "exout.inflows1",
  "exout.clusters", "exout.clusters1",
  "exout.transit", "exout.empty", "exout.capped", "exout.coverage",
  "exout.note", "exout.aria", "exout.wellKnown",
];

test("i18n: exout.*-Keys in EN und DE vorhanden, nicht leer, Platzhalter-Parität", () => {
  const ph = (s) => (String(s).match(/\{[A-Za-z0-9_]+\}/g) ?? []).sort().join(",");
  for (const k of EXOUT_KEYS) {
    assert.equal(typeof DICT.en[k], "string", `EN-Wert fehlt: ${k}`);
    assert.equal(typeof DICT.de[k], "string", `DE-Wert fehlt: ${k}`);
    assert.ok(DICT.en[k].length > 0, `leerer EN-Wert: ${k}`);
    assert.ok(DICT.de[k].length > 0, `leerer DE-Wert: ${k}`);
    assert.equal(ph(DICT.en[k]), ph(DICT.de[k]), `Platzhalter-Abweichung bei ${k}`);
  }
});

test("i18n: deutsche Orthografie (ä ö ü ß, kein ASCII-Ersatz, kein Mojibake)", () => {
  for (const k of ["exout.subtitle", "exout.empty", "exout.note", "exout.capped", "exout.coverage", "exout.window7", "exout.window30", "exout.title"]) {
    const v = DICT.de[k];
    assert.ok(!/Ã/.test(v), `Mojibake in ${k}`);
    assert.ok(!/\b(ae|oe|ue)\b/.test(v), `ASCII-Umlaut-Ersatz in ${k}`);
  }
  assert.ok(/[äöüß]/.test(DICT.de["exout.subtitle"]), "exout.subtitle ohne Umlaut");
  assert.ok(/[äöüß]/.test(DICT.de["exout.note"]), "exout.note ohne Umlaut");
  // Ehrlicher Untertitel: Börsen explizit nicht als Täter benannt.
  assert.ok(DICT.de["exout.subtitle"].includes("Börsen"), "DE-Untertitel nennt die Börsen");
  assert.ok(DICT.en["exout.subtitle"].includes("exchanges"), "EN-Untertitel nennt die exchanges");
  assert.ok(DICT.de["exout.subtitle"].includes("nicht die Täter"), "DE-Untertitel befreit die Börsen von der Täterrolle");
});

test("Verdrahtung index.html: Panel-Markup + nur existierende exout-Keys referenziert", () => {
  const here = path.dirname(fileURLToPath(import.meta.url));
  const html = readFileSync(path.join(here, "index.html"), "utf8");
  assert.ok(html.includes('id="exchange-outflows-panel"'), "Panel-Sektion vorhanden");
  assert.ok(html.includes('id="exchange-outflow-list"'), "Listen-ID vorhanden");
  assert.ok(html.includes('id="exout-empty"'), "Empty-State-ID vorhanden");
  assert.ok(html.includes('id="exout-coverage"'), "Abdeckungszeitraum-Element vorhanden (Pflicht 11)");
  assert.ok(html.includes('id="exout-capped"'), "Cap-Hinweis-Element vorhanden");
  assert.ok(html.includes('id="exout-window-7d"') && html.includes('id="exout-window-30d"'), "Fenster-Umschalter vorhanden");
  assert.ok(html.indexOf('id="exchange-outflows-panel"') < html.indexOf('id="view-history"'), "Panel liegt VOR view-history (tab-unabhängig im Dashboard)");
  assert.ok(html.indexOf('id="exchange-outflows-panel"') > html.indexOf("console-grid"), "Panel liegt NACH dem console-grid");
  // Jede referenzierte exout-i18n-Key muss in BEIDEN Sprachen existieren.
  const refs = [...html.matchAll(/data-i18n(?:-aria)?="(exout\.[A-Za-z0-9]+)"/g)].map((m) => m[1]);
  assert.ok(refs.length >= 8, `genug statische Keys referenziert (gefunden: ${refs.length})`);
  for (const k of refs) {
    assert.ok(DICT.en[k] !== undefined, `index.html referenziert fehlenden EN-Key ${k}`);
    assert.ok(DICT.de[k] !== undefined, `index.html referenziert fehlenden DE-Key ${k}`);
  }
});

test("Verdrahtung app.js: Modul-Import, Poll-Anbindung, Umschalter, Gates, Pflicht-11/12-Render", () => {
  const here = path.dirname(fileURLToPath(import.meta.url));
  const appJs = readFileSync(path.join(here, "app.js"), "utf8");
  assert.match(appJs, /from '\.\/exchange-outflows\.mjs'/, "statischer Modul-Import");
  assert.match(appJs, /aggregateExchangeOutflows, exchangeOutflowRowHtml/, "beide Modulfunktionen importiert");
  assert.match(appJs, /function renderExchangeOutflows\(/, "Render-Funktion vorhanden");
  assert.match(appJs, /renderExchangeOutflows\(body\);/, "Aufruf im pollFlowState nach flowData = body");
  assert.match(appJs, /bindExchangeOutflows\(\);/, "Umschalter-Binding im Startblock");
  assert.match(appJs, /multiUserSnapshot/, "Börsen-Union aus der Registry-Quelle");
  assert.match(appJs, /displayFindingAddr/, "Anzeige über die bestehende Maske (Pflicht 12)");
  assert.match(appJs, /t\('exout\.coverage'/, "Abdeckungszeitraum gerendert (Pflicht 11)");
  assert.match(appJs, /t\('exout\.capped'/, "Cap-Hinweis gerendert");
});

test("Verdrahtung package.json: Testdatei in der Suite gelistet", () => {
  const here = path.dirname(fileURLToPath(import.meta.url));
  const pkg = JSON.parse(readFileSync(path.join(here, "..", "package.json"), "utf8"));
  assert.ok(pkg.scripts.test.includes("public/exchange-outflows.test.mjs"), "Testdatei im npm-test-Script");
});
