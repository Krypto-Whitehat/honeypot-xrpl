// public/drainer-top10.test.mjs — Unit-Tests für die DOM-freie Top-10-
// Drainer-Rangliste (public/drainer-top10.mjs, genutzt von public/app.js
// renderDrainerTop10) und deren Verdrahtung. Muster: exchange-outflows.test.mjs.
//
// Kein Browser: das Modul ist per Vertrag DOM-frei und rein funktional; die
// Zeilen-Markup-Funktion bekommt die Host-Gates (esc/displayAddr/fmtXrp/
// fmtNum/labels) als Stubs injiziert. Alle Adressen synthetisch
// (rTEST-Familie), Base58-gültig (ohne 0/O/I/l). Feste NOW wie in der
// Börsen-Box — deterministische Fenster-Grenzen.
//
// Geprüft: (1) Qualifikation ausschließlich über die Drainer-ROLLE des ZIELS
// im selben Cluster (Severity allein qualifiziert NICHT — Negativkontrolle
// gegen Kopie der Börsen-Box; Rollen aus anderem Cluster übertragen nicht),
// Union-Ausschluss gegen Doppelzählung, Fenstergrenzen 7 d/30d inklusive
// Untergrenze (Zukunft ausgeschlossen, ein Durchlauf), fehlendes closeTime →
// excludedNoCloseTime, Richtung (Primmetrik nur e.to === addr, outDrops nur
// Meta), Tie-Breaks dropsSum → inEdges → Adresse asc (binär), topN = 10,
// cappedClusters, coverageFrom, Tag-Sammlung (distinct, aufsteigend, Tag 0
// echt, defekte Werte raus), Determinismus. (2) Zeilen-Markup nur über
// injizierte Gates: displayAddr verweigert → keine Zeile, defekte Gates → '',
// esc auf JEDEM String (Pflicht 12), Tag-Chips '#0'/'#3'… mit Cap 3 + '+',
// kein roher Tag-Wert, Forwarded-Badge nur bei belegtem Wert. (3) i18n
// drout.*-Keys DE==EN, Platzhalter-Parität, deutsche Orthografie. (4)
// Verdrahtung index.html (Panel-IDs, Umschalter, Duo-Grid-Platzierung),
// app.js (Import, Poll-Anbindung, Umschalter, Gates) und package.json.

import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";
import {
  aggregateDrainerTop10, drainerTop10RowHtml,
  DROUT_WINDOW_7D_MS, DROUT_WINDOW_30D_MS, DROUT_EDGE_CAP,
  DROUT_TAG_MAX, DROUT_TAG_CAP,
} from "./drainer-top10.mjs";
import { DICT } from "./i18n.mjs";

/* ---------------- Fixture-Adressen (Base58 ohne 0/O/I/l) ---------------- */

const D1 = "rDrainerOne11111111111111111111";   // Rolle drainer (Ziel)
const D2 = "rDrainerTwo11111111111111111111";   // Rolle drainer
const SRC = "rSourceAcc111111111111111111111";  // severity malicious, Rolle source
const COL = "rCollectorAcc111111111111111111";  // severity malicious, Rolle collector
const REL = "rRelayAcc111111111111111111111";   // Rolle relay
const UNI = "rUnionAcc1111111111111111111111";  // Rolle drainer, ABER Börsen-Union
const PLAIN = "rPlainAcc111111111111111111111"; // keine Rolle/Metadaten

const iso = (ms) => new Date(ms).toISOString();
const NOW = Date.UTC(2026, 9, 7, 12, 0, 0); // 2026-10-07T12:00:00Z (feste Referenz)

// Börsen-Union (multiUserSnapshot-Stub): nur Membership wird gebraucht.
function exchangeMap() {
  return new Map([
    [UNI, { exchange: "Börse U", domain: "u.example", confidence: "well-known" }],
  ]);
}

const view = (clusters) => ({ clusters });

// Cluster-Fixture: Rollen im SELBEN Cluster (severityByAddress nur als
// Negativkontrolle — die Drainer-Box liest sie nicht).
function cluster(id, rolesByAddress, firstSeen, edges, severityByAddress = {}) {
  return { id, rolesByAddress, severityByAddress, firstSeen, lastSeen: firstSeen, edges };
}

/* ---------------- 1) Qualifikation: nur die Drainer-Rolle ---------------- */

test("Qualifikation: nur rolesByAddress[ZIEL] === 'drainer' im selben Cluster; Severity allein NICHT; andere Rollen NICHT", () => {
  const v = view([
    cluster("cluster:1",
      { [D1]: "drainer", [SRC]: "source", [COL]: "collector", [REL]: "relay", [D2]: "unknown" },
      iso(NOW - 3600e3),
      [
        { from: SRC, to: D1, amountDrops: 100, closeTime: iso(NOW - 60e3) },  // Ziel drainer → zählt
        { from: COL, to: SRC, amountDrops: 200, closeTime: iso(NOW - 60e3) }, // Ziel source + severity malicious → Negativkontrolle: zählt NICHT
        { from: SRC, to: COL, amountDrops: 300, closeTime: iso(NOW - 60e3) }, // Ziel collector → zählt NICHT
        { from: SRC, to: REL, amountDrops: 400, closeTime: iso(NOW - 60e3) }, // Ziel relay → zählt NICHT
        { from: SRC, to: D2, amountDrops: 500, closeTime: iso(NOW - 60e3) },  // Ziel unknown (Rolle fehlt) → zählt NICHT
        { from: SRC, to: PLAIN, amountDrops: 600, closeTime: iso(NOW - 60e3) }, // Ziel ohne Rollen-Eintrag → zählt NICHT
      ],
      { [SRC]: "malicious", [COL]: "malicious", [REL]: "suspect", [D1]: "info", [D2]: "info" }),
  ]);
  const res = aggregateDrainerTop10(v, exchangeMap(), NOW);
  assert.equal(res.seven.totals.qualifyingEdges, 1, "genau die eine Kante auf ein Drainer-Ziel");
  assert.equal(res.seven.totals.qualifyingDrops, 100);
  assert.deepEqual(res.seven.rows.map((r) => r.address), [D1], "nur D1 erscheint — Severity-/Rollen-Negativkontrollen bleiben außen");
  assert.equal(res.seven.rows[0].dropsSum, 100, "D1 trägt severity info — qualifiziert nur über die Rolle");
});

test("Rolle überträgt nicht aus anderem Cluster: Ziel mit drainer-Rolle in Cluster A, relay in Cluster B → nur Cluster-A-Kanten zählen", () => {
  const v = view([
    cluster("cluster:a", { [D1]: "drainer" }, iso(NOW - 3600e3), [
      { from: SRC, to: D1, amountDrops: 100, closeTime: iso(NOW - 60e3) },
    ]),
    cluster("cluster:b", { [D1]: "relay" }, iso(NOW - 3600e3), [
      { from: SRC, to: D1, amountDrops: 900, closeTime: iso(NOW - 60e3) }, // dieselbe Adresse, andere Rolle → ignoriert
    ]),
  ]);
  const res = aggregateDrainerTop10(v, exchangeMap(), NOW);
  assert.equal(res.seven.rows.length, 1);
  assert.equal(res.seven.rows[0].dropsSum, 100, "nur die Kante aus dem Cluster mit drainer-Rolle");
  assert.equal(res.seven.rows[0].clusterCount, 1, "clusterCount zählt nur den qualifizierenden Cluster");
});

test("Union-Ausschluss: Drainer-Konto in der Börsen-Union fällt raus und zählt excludedUnionTargets; ohne geladene Union keine Rangliste (Host-Gate)", () => {
  const v = view([cluster("cluster:1", { [UNI]: "drainer", [D1]: "drainer" }, iso(NOW - 3600e3), [
    { from: SRC, to: UNI, amountDrops: 700, closeTime: iso(NOW - 60e3) }, // Union-Konto → ausgeschlossen
    { from: SRC, to: D1, amountDrops: 100, closeTime: iso(NOW - 60e3) },
  ])]);
  const res = aggregateDrainerTop10(v, exchangeMap(), NOW);
  assert.deepEqual(res.seven.rows.map((r) => r.address), [D1], "UNI steht nicht in der Drainer-Liste (sonst Doppelzählung mit der Börsen-Box)");
  assert.equal(res.seven.totals.excludedUnionTargets, 1, "Ausschluss wird sichtbar gezählt, nicht still verworfen");
  assert.equal(res.thirty.totals.excludedUnionTargets, 1);
  // Defekte View-Formen: leer, nie ein Wurf (fail-closed wie die Börsen-Box).
  assert.equal(aggregateDrainerTop10(null, exchangeMap(), NOW).seven.rows.length, 0);
  assert.equal(aggregateDrainerTop10({}, exchangeMap(), NOW).thirty.rows.length, 0);
  assert.equal(aggregateDrainerTop10({ clusters: [null, 42] }, exchangeMap(), NOW).seven.rows.length, 0);
});

/* ---------------- 2) Richtung: Primmetrik nur eingehend ---------------- */

test("Richtung: Summe nur über e.to === addr; ausgehende Kanten des Drainers NIE in der Primmetrik, outDrops nur Meta", () => {
  const v = view([cluster("cluster:1", { [D1]: "drainer", [D2]: "drainer" }, iso(NOW - 3600e3), [
    { from: SRC, to: D1, amountDrops: 100, closeTime: iso(NOW - 60e3) },   // eingehend → Primmetrik
    { from: SRC, to: D1, amountDrops: 50, closeTime: iso(NOW - 120e3) },   // eingehend → Primmetrik
    { from: D1, to: PLAIN, amountDrops: 500, closeTime: iso(NOW - 60e3) }, // ausgehend → nur Meta outDrops
    { from: D2, to: PLAIN, amountDrops: 300, closeTime: iso(NOW - 60e3) }, // D2 ohne Beute im Fenster → keine Zeile
  ])]);
  const res = aggregateDrainerTop10(v, exchangeMap(), NOW);
  assert.deepEqual(res.seven.rows.map((r) => r.address), [D1], "D1 (150 empfangen) vor D2 (0 empfangen, nur weitergeleitet) — ohne Beute keine Zeile");
  const row = res.seven.rows[0];
  assert.equal(row.dropsSum, 150, "Primmetrik = empfangene Drops (100+50), NICHT 650");
  assert.equal(row.inEdges, 2);
  assert.equal(row.outDrops, 500, "weitergeleitete Drops nur als Meta");
  assert.equal(res.seven.totals.qualifyingEdges, 2, "ausgehende Kanten zählen nicht als qualifizierend");
  assert.equal(res.seven.totals.qualifyingDrops, 150);
});

/* ---------------- 3) Fenster-Grenzen (7d/30d, ein Durchlauf) ---------------- */

test("Fenster-Grenzen: 7d/30d inklusive Untergrenze, Zukunft/Jenseits ausgeschlossen, 7d ⊆ 30d, ein Durchlauf", () => {
  const edges = [
    { from: SRC, to: D1, amountDrops: 100, closeTime: iso(NOW - 3600e3) },                    // beide
    { from: SRC, to: D1, amountDrops: 200, closeTime: iso(NOW - DROUT_WINDOW_7D_MS) },        // exakt 7d → beide (inklusive)
    { from: SRC, to: D2, amountDrops: 300, closeTime: iso(NOW - DROUT_WINDOW_7D_MS - 1000) }, // älter als 7d → nur 30d
    { from: SRC, to: D2, amountDrops: 400, closeTime: iso(NOW - DROUT_WINDOW_30D_MS) },       // exakt 30d → nur 30d (inklusive)
    { from: SRC, to: D2, amountDrops: 500, closeTime: iso(NOW - DROUT_WINDOW_30D_MS - 1000) },// älter als 30d → keins
    { from: SRC, to: D2, amountDrops: 600, closeTime: iso(NOW + 1000) },                      // Zukunft → keins
  ];
  const v = view([cluster("cluster:1", { [D1]: "drainer", [D2]: "drainer" }, iso(NOW - DROUT_WINDOW_30D_MS - 2000), edges)]);
  const res = aggregateDrainerTop10(v, exchangeMap(), NOW);
  assert.equal(res.seven.windowDays, 7);
  assert.equal(res.thirty.windowDays, 30);
  const seven = new Map(res.seven.rows.map((r) => [r.address, r]));
  const thirty = new Map(res.thirty.rows.map((r) => [r.address, r]));
  assert.deepEqual([...seven.keys()].sort(), [D1], "7d: nur D1 (Grenzkante inklusive)");
  assert.deepEqual([...thirty.keys()].sort(), [D1, D2], "30d: zusätzlich D2, Jenseits/Zukunft in keinem Bucket");
  assert.equal(seven.get(D1).dropsSum, 300, "D1 7d: 100+200");
  assert.equal(thirty.get(D2).dropsSum, 700, "D2 30d: 300+400");
  assert.equal(seven.has(D2), false, "D2 7d: beide Kanten außerhalb des Fensters");
  assert.equal(res.seven.totals.qualifyingEdges, 2);
  assert.equal(res.thirty.totals.qualifyingEdges, 4, "30d: 100+200+300+400");
  assert.equal(res.thirty.totals.qualifyingDrops, 1000);
});

test("Fehlendes/unparsebares closeTime → excludedNoCloseTime statt stillem Verwerfen; Union-Kante ohne Zeit zählt Union-Zähler", () => {
  const v = view([cluster("cluster:1", { [D1]: "drainer", [UNI]: "drainer" }, iso(NOW - 3600e3), [
    { from: SRC, to: D1, amountDrops: 100, closeTime: iso(NOW - 60e3) },
    { from: SRC, to: D1, amountDrops: 200 },                          // ohne closeTime
    { from: SRC, to: D1, amountDrops: 300, closeTime: "not-a-date" }, // unparsebar
    { from: SRC, to: UNI, amountDrops: 400 },                          // Union-Ziel ohne Zeit → Union-Zähler, kein excludedNoCloseTime
    { from: SRC, to: PLAIN, amountDrops: 500 },                       // außerhalb der Fragestellung → kein Zähler
  ])]);
  const res = aggregateDrainerTop10(v, exchangeMap(), NOW);
  assert.equal(res.seven.totals.excludedNoCloseTime, 2, "genau die zwei Drainer-Kanten ohne Zeit");
  assert.equal(res.thirty.totals.excludedNoCloseTime, 2);
  assert.equal(res.seven.totals.excludedUnionTargets, 1);
  assert.equal(res.seven.totals.qualifyingEdges, 1);
});

/* ---------------- 4) Sortierung, Tie-Breaks, Kappung, Cap ---------------- */

test("Sortierung: dropsSum desc → inEdges desc → Adresse asc (binär), deterministisch", () => {
  // D1: 500/1 · D2: 500/2 → D2 vor D1; Adress-Tiebreak binär.
  const edges = [
    { from: SRC, to: D1, amountDrops: 500, closeTime: iso(NOW - 60e3) },
    { from: SRC, to: D2, amountDrops: 250, closeTime: iso(NOW - 60e3) },
    { from: SRC, to: D2, amountDrops: 250, closeTime: iso(NOW - 120e3) },
  ];
  const res = aggregateDrainerTop10(
    view([cluster("cluster:1", { [D1]: "drainer", [D2]: "drainer" }, iso(NOW - 3600e3), edges)]),
    exchangeMap(), NOW,
  );
  assert.deepEqual(res.seven.rows.map((r) => [r.address, r.inEdges]), [[D2, 2], [D1, 1]], "Gleichstand → inEdges desc");

  // Reine Adress-Tiebreaks: D1 < D2 binär (rDrainerOne < rDrainerTwo).
  const tied = [D2, D1].map((t) => ({ from: SRC, to: t, amountDrops: 100, closeTime: iso(NOW - 60e3) }));
  const res2 = aggregateDrainerTop10(
    view([cluster("cluster:1", { [D1]: "drainer", [D2]: "drainer" }, iso(NOW - 3600e3), tied)]),
    exchangeMap(), NOW,
  );
  assert.deepEqual(res2.seven.rows.map((r) => r.address), [D1, D2], "binär aufsteigend");
});

test("Default-Kappung topN = 10; opts.topN verkleinert die Liste", () => {
  // 12 Drainer-Ziele mit identischen Werten → Reihenfolge rein über Adresse asc.
  const chars = "123456789ABC"; // Base58-Zeichen (ohne 0/O/I/l)
  const targets = [...chars].map((c) => `rDrainGen${c}Acc1111111111111111`);
  const roles = Object.fromEntries(targets.map((t) => [t, "drainer"]));
  const edges = targets.map((t) => ({ from: SRC, to: t, amountDrops: 100, closeTime: iso(NOW - 60e3) }));
  const v = view([cluster("cluster:1", roles, iso(NOW - 3600e3), edges)]);
  const def = aggregateDrainerTop10(v, exchangeMap(), NOW);
  assert.equal(def.seven.rows.length, 10, "Default topN = 10 trotz 12 Zielen");
  assert.deepEqual(def.seven.rows.map((r) => r.address), targets.slice(0, 10), "die zehn kleinsten Adressen (Adresse asc)");
  const two = aggregateDrainerTop10(v, exchangeMap(), NOW, { topN: 2 });
  assert.equal(two.seven.rows.length, 2);
});

test("Cap-Sichtbarkeit: Cluster am 50-Kanten-Deckel zählen cappedClusters, kleinere/leere nicht", () => {
  const capEdges = Array.from({ length: DROUT_EDGE_CAP }, (_, i) => (
    { from: SRC, to: i % 2 ? D2 : D1, amountDrops: 10, closeTime: iso(NOW - 60e3) }
  ));
  const smallEdges = capEdges.slice(0, DROUT_EDGE_CAP - 1);
  const v = view([
    cluster("cluster:cap", { [D1]: "drainer", [D2]: "drainer" }, iso(NOW - 3600e3), capEdges),
    cluster("cluster:small", { [D1]: "drainer", [D2]: "drainer" }, iso(NOW - 3600e3), smallEdges),
    cluster("cluster:empty", { [D1]: "drainer" }, iso(NOW - 3600e3), []),
  ]);
  const res = aggregateDrainerTop10(v, exchangeMap(), NOW);
  assert.equal(res.seven.totals.clustersScanned, 2, "Cluster ohne Kanten zählen nicht als betrachtet");
  assert.equal(res.seven.totals.cappedClusters, 1, "genau das Cluster am Deckel");
  assert.equal(res.thirty.totals.cappedClusters, 1);
});

test("Zeilen-Metadaten: clusterCount, lastInflowMs, coverageFrom = min firstSeen (null ohne parsebare firstSeen)", () => {
  const v = view([
    cluster("cluster:1", { [D1]: "drainer" }, iso(NOW - 3600e3), [
      { from: SRC, to: D1, amountDrops: 100, closeTime: iso(NOW - 120e3) },
      { from: SRC, to: D1, amountDrops: 200, closeTime: iso(NOW - 60e3) },
    ]),
    cluster("cluster:2", { [D1]: "drainer" }, iso(NOW - 7200e3), [
      { from: COL, to: D1, amountDrops: 300, closeTime: iso(NOW - 300e3) },
    ]),
    cluster("cluster:3", { [D2]: "drainer" }, "not-a-date", [
      { from: SRC, to: D2, amountDrops: 50, closeTime: iso(NOW - 60e3) },
    ]),
  ]);
  const res = aggregateDrainerTop10(v, exchangeMap(), NOW);
  const row = res.seven.rows.find((r) => r.address === D1);
  assert.equal(row.clusterCount, 2, "zwei verschiedene Cluster");
  assert.equal(row.lastInflowMs, NOW - 60e3, "spätester Zufluss");
  assert.equal(res.coverageFrom, iso(NOW - 7200e3), "min firstSeen aller betrachteten Cluster");
  assert.equal(res.generatedAt, NOW);
  const resNull = aggregateDrainerTop10(
    view([cluster("cluster:9", { [D1]: "drainer" }, "x", [
      { from: SRC, to: D1, amountDrops: 1, closeTime: iso(NOW - 60e3) },
    ])]),
    exchangeMap(), NOW,
  );
  assert.equal(resNull.coverageFrom, null, "keine Erfundung ohne parsebare firstSeen");
});

/* ---------------- 5) Tags (Kantenattribute des Empängers) ---------------- */

test("Tags: distinct toTags aufsteigend, Tag 0 ist echt, defekte Werte und fehlende Felder zählen nie", () => {
  const v = view([cluster("cluster:1", { [D1]: "drainer" }, iso(NOW - 3600e3), [
    { from: SRC, to: D1, amountDrops: 10, closeTime: iso(NOW - 60e3), toTag: 7 },
    { from: SRC, to: D1, amountDrops: 10, closeTime: iso(NOW - 60e3), toTag: 3 },
    { from: SRC, to: D1, amountDrops: 10, closeTime: iso(NOW - 60e3), toTag: 3 },   // Duplikat → distinct
    { from: SRC, to: D1, amountDrops: 10, closeTime: iso(NOW - 60e3), toTag: 0 },   // Tag 0 ist ein ECHTER Tag
    { from: SRC, to: D1, amountDrops: 10, closeTime: iso(NOW - 60e3), toTag: 1.5 }, // nicht ganzzahlig → kein Tag
    { from: SRC, to: D1, amountDrops: 10, closeTime: iso(NOW - 60e3), toTag: -1 },  // negativ → kein Tag
    { from: SRC, to: D1, amountDrops: 10, closeTime: iso(NOW - 60e3), toTag: DROUT_TAG_MAX + 1 }, // außerhalb UInt32 → kein Tag
    { from: SRC, to: D1, amountDrops: 10, closeTime: iso(NOW - 60e3), toTag: "5" }, // String → kein Tag (View normalisiert zu number)
    { from: SRC, to: D1, amountDrops: 10, closeTime: iso(NOW - 60e3) },             // fehlendes Feld → kein Tag, NICHT '#0'
    { from: D1, to: PLAIN, amountDrops: 10, closeTime: iso(NOW - 60e3), toTag: 42 }, // Tag am Falschempfänger → zählt nicht für D1
  ])]);
  const res = aggregateDrainerTop10(v, exchangeMap(), NOW);
  const row = res.seven.rows[0];
  assert.deepEqual(row.tags, [0, 3, 7], "distinct, aufsteigend; Tag 0 echt; defekte Werte raus");
  assert.equal(row.tags.includes(42), false, "Tag einer Kante mit anderem Ziel zählt nicht");
});

/* ---------------- 6) Determinismus ---------------- */

test("Determinismus: gleiche Eingabe → identische Buckets (keine Render-Zufälle)", () => {
  const build = () => view([
    cluster("cluster:1", { [D1]: "drainer", [D2]: "drainer" }, iso(NOW - 3600e3), [
      { from: SRC, to: D1, amountDrops: 100, closeTime: iso(NOW - 60e3), toTag: 3 },
      { from: SRC, to: D2, amountDrops: 100, closeTime: iso(NOW - 60e3) },
    ]),
  ]);
  const a = aggregateDrainerTop10(build(), exchangeMap(), NOW);
  const b = aggregateDrainerTop10(build(), exchangeMap(), NOW);
  assert.deepEqual(a, b);
});

/* ---------------- 7) Zeilen-Markup (injizierte Host-Gates) ---------------- */

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
      inflows: (n) => `${n} inflows`,
      clusters: (n) => `${n} clusters`,
      forwarded: (xrp) => `Forwarded: ${xrp} XRP`,
      tagAria: 'Destination tag "recorded" on inflows',
    },
    ...overrides,
  };
}

const ROW = {
  address: D1,
  dropsSum: 1234567,
  inEdges: 3,
  outDrops: 0,
  clusterCount: 2,
  lastInflowMs: NOW,
  tags: [0, 3, 7],
};

test("Zeilen-Markup: Rang, gegattete Adresse GENAU EINMAL (Namenszeile), fmtXrp-Betrag, Tag-Chips '#0'/'#3'/'#7'", () => {
  const html = drainerTop10RowHtml(ROW, 2, uiStub());
  assert.ok(html.startsWith('<li class="drout-row">'), "Zeilen-Markup der Drainer-Box");
  assert.ok(html.includes(">2</span>"), "Rang-Nummer (1-basiert)");
  assert.ok(html.includes('title="Rank 2"'), "Rang-Aria als title");
  assert.ok(html.includes("rDrainer…1111"), "Anzeige-Adresse über das Masken-Gate (Namenszeile trägt die Maske selbst)");
  assert.ok(!html.includes('class="drout-addr"'), "keine zweite Adresszeile — Drainer-Konten haben per Konstruktion keinen Registry-Namen, eine Duplikationszeile wäre in jeder Zeile der Regelfall");
  assert.equal((html.match(/rDrainer…1111/g) ?? []).length, 2, "Maske genau einmal im Text + einmal im title (keine Verdopplung)");
  assert.ok(!html.includes(D1), "keine rohe Adresse im Markup");
  assert.ok(html.includes("FMT(1234567) XRP"), "Betrag über injiziertes fmtXrp (Drops-Format Host-Sache)");
  assert.ok(html.includes("3 inflows"), "Kantenzahl über das injizierte Label");
  assert.ok(html.includes("2 clusters"), "Clusterzahl über das injizierte Label");
  assert.ok(html.includes(">#0</span>"), "Tag 0 zeigt '#0' (echter Tag, lib/tag-identity.mjs)");
  assert.ok(html.includes(">#3</span>") && html.includes(">#7</span>"), "Tags aufsteigend als Chips");
  assert.ok(html.includes('aria-label="Destination tag &quot;recorded&quot; on inflows"'), "Tag-Aria esc-kodiert (eigener drout.tagAria-Schlüssel)");
  assert.ok(!html.includes("drout-badge-forwarded"), "ohne outDrops kein Forwarded-Badge");
});

test("Zeilen-Markup: Tag-Cap 3 + '+'-Hinweis; ohne Tags keine Chips; Forwarded-Badge nur bei belegtem Wert", () => {
  const capped = drainerTop10RowHtml({ ...ROW, tags: [1, 2, 3, 4, 5] }, 1, uiStub());
  const chipCount = (capped.match(/class="tag-chip drout-tag"/g) ?? []).length;
  assert.equal(chipCount, DROUT_TAG_CAP, "Cap 3 Chips");
  assert.ok(capped.includes('class="drout-tag-more" aria-hidden="true">+<'), "'+'-Hinweis bei mehr (Muster tagChipsHtml)");
  assert.ok(capped.includes(">#5</span>") === false, "vierter Tag nicht sichtbar");
  const noTags = drainerTop10RowHtml({ ...ROW, tags: [] }, 1, uiStub());
  assert.ok(!noTags.includes("tag-chip"), "ohne Tags keine Chips");
  const fwd = drainerTop10RowHtml({ ...ROW, outDrops: 42000 }, 1, uiStub());
  assert.ok(fwd.includes("drout-badge-forwarded"), "Forwarded-Badge bei outDrops > 0");
  assert.ok(fwd.includes("FMT(42000) XRP"), "Forwarded-Betrag XRP-formatiert");
});

test("Zeilen-Markup (Pflicht 12): displayAddr-Gate verweigert → keine Zeile; defekte/fehlende Gates → ''", () => {
  assert.equal(drainerTop10RowHtml(ROW, 1, uiStub({ displayAddr: () => "" })), "", "Gate-'': fail-closed, keine Zeile, keine Adresse");
  assert.equal(drainerTop10RowHtml(null, 1, uiStub()), "");
  assert.equal(drainerTop10RowHtml(ROW, 1, null), "");
  assert.equal(drainerTop10RowHtml(ROW, 1, {}), "");
  assert.equal(drainerTop10RowHtml(ROW, 1, uiStub({ esc: null })), "");
  assert.equal(drainerTop10RowHtml(ROW, 1, uiStub({ displayAddr: null })), "");
  assert.equal(drainerTop10RowHtml(ROW, 1, uiStub({ fmtXrp: null })), "");
  assert.equal(drainerTop10RowHtml(ROW, 1, uiStub({ fmtNum: null })), "");
  // Kein roher Tag-Wert, kein roher Label-String: alles durch esc (Stub-Labels
  // ohne Sonderzeichen → identisch; der esc-Nachweis liegt in den Aria-Checks).
  const hostile = drainerTop10RowHtml(ROW, 1, uiStub({
    labels: { rankAria: (n) => `<b>${n}</b>`, inflows: () => '<x"y>', clusters: () => "&z", forwarded: () => "", tagAria: '<t>"&' },
  }));
  assert.ok(hostile.includes("&lt;b&gt;1&lt;/b&gt;"), "Label-Strings esc-kodiert");
  assert.ok(hostile.includes("&lt;x&quot;y&gt;"), "Meta-Label esc-kodiert");
  assert.ok(!hostile.includes("<b>1</b>"), "kein roher Label-String im Markup");
});

/* ---------------- 8) i18n: drout.*-Keys DE==EN ---------------- */

const DROUT_KEYS = [
  "drout.title", "drout.subtitle", "drout.window7", "drout.window30",
  "drout.windowAria", "drout.rank", "drout.inflows", "drout.inflows1",
  "drout.clusters", "drout.clusters1", "drout.forwarded", "drout.tagAria",
  "drout.empty", "drout.capped", "drout.coverage", "drout.note", "drout.aria",
];

test("i18n: drout.*-Keys in EN und DE vorhanden, nicht leer, Platzhalter-Parität", () => {
  const ph = (s) => (String(s).match(/\{[A-Za-z0-9_]+\}/g) ?? []).sort().join(",");
  for (const k of DROUT_KEYS) {
    assert.equal(typeof DICT.en[k], "string", `EN-Wert fehlt: ${k}`);
    assert.equal(typeof DICT.de[k], "string", `DE-Wert fehlt: ${k}`);
    assert.ok(DICT.en[k].length > 0, `leerer EN-Wert: ${k}`);
    assert.ok(DICT.de[k].length > 0, `leerer DE-Wert: ${k}`);
    assert.equal(ph(DICT.en[k]), ph(DICT.de[k]), `Platzhalter-Abweichung bei ${k}`);
  }
});

test("i18n: deutsche Orthografie (ä ö ü ß, kein ASCII-Ersatz, kein Mojibake) + ehrlicher Untertitel", () => {
  for (const k of ["drout.subtitle", "drout.empty", "drout.note", "drout.capped", "drout.coverage", "drout.window7", "drout.window30", "drout.title", "drout.inflows", "drout.tagAria"]) {
    const v = DICT.de[k];
    assert.ok(!/Ã/.test(v), `Mojibake in ${k}`);
    assert.ok(!/\b(ae|oe|ue)\b/.test(v), `ASCII-Umlaut-Ersatz in ${k}`);
  }
  // Umlaut-Nachweis dort, wo die Texte sie natürlich tragen (note/empty/
  // inflows/tagAria) — der Untertitel enthält sprachlich keinen Umlaut.
  assert.ok(/[äöüß]/.test(DICT.de["drout.note"]), "drout.note ohne Umlaut");
  assert.ok(/[äöüß]/.test(DICT.de["drout.empty"]), "drout.empty ohne Umlaut");
  assert.ok(/[äöüß]/.test(DICT.de["drout.inflows"]), "drout.inflows ohne Umlaut");
  // Ehrlichkeit: Rolle als Heuristik benannt, nicht als Schuldbeweis.
  assert.ok(DICT.de["drout.subtitle"].includes("Heuristik"), "DE-Untertitel nennt die Heuristik");
  assert.ok(DICT.de["drout.subtitle"].includes("kein Schuldbeweis"), "DE-Untertitel grenzt die Rolle ehrlich ein");
  assert.ok(DICT.en["drout.subtitle"].includes("heuristic"), "EN-Untertitel nennt die Heuristik");
  // Leerer Zustand behauptet keine Abwesenheit von Drainern, nur fehlende Beute im Bestand/Fenster.
  assert.ok(DICT.de["drout.empty"].includes("im betrachteten Bestand"), "DE-Leertext ist bestandsbezogen");
  assert.ok(DICT.en["drout.empty"].includes("considered state"), "EN-Leertext ist bestandsbezogen");
});

/* ---------------- 9) CSS-Guards: Duo-Grid + Listen-Rahmen (style.css) ----------------
   Die Platzierungs-Tests oben prüfen index.html per indexOf — sie sehen das
   Ergebnis, nicht die Regel. Diese Guards lesen style.css direkt: fällt eine
   Grid-/Stapel-/Listen-Regel weg, schlagen sie fehl (Muster shine-spacing). */

const stripComments = (block) => block.replace(/\/\*[\s\S]*?\*\//g, "");

test("CSS-Guard Duo-Grid: zweispaltig minmax(0,1fr) + 22px, mobiler Stapel 760/560 px, Drainer-Box ohne Frost", () => {
  const here = path.dirname(fileURLToPath(import.meta.url));
  const styleCss = readFileSync(path.join(here, "style.css"), "utf8");
  // Basisregel: zwei gleich breite Spalten mit 0-Minimum (eine 35-Zeichen-
  // Adresse darf die Spalte nicht sprengen), gap 22 px = Panel-Rhythmus.
  const grid = styleCss.match(/\.top-duo-grid\s*\{[^}]*\}/);
  assert.ok(grid, ".top-duo-grid-Regel vorhanden");
  const gridBody = stripComments(grid[0]);
  assert.match(gridBody, /display:\s*grid/, "Grid-Display");
  assert.match(gridBody, /grid-template-columns:\s*minmax\(0,\s*1fr\)\s+minmax\(0,\s*1fr\)/, "zwei Spalten mit minmax(0,1fr)");
  assert.match(gridBody, /gap:\s*22px/, "22-px-Rhythmus");
  // Drainer-Panel: Basis-Margin wie die Börsen-Box (Bündigkeit im Grid) und
  // KEINE Frost-Schicht — die Frost-Optik bleibt ausschließlich der Börsen-Box.
  const drPanel = styleCss.match(/#drainer-outflows-panel\s*\{[^}]*\}/);
  assert.ok(drPanel, "#drainer-outflows-panel-Basisregel vorhanden");
  const drBody = stripComments(drPanel[0]);
  assert.match(drBody, /margin:\s*22px auto/, "22 px Rhythmus wie die Börsen-Box");
  assert.doesNotMatch(drBody, /backdrop-filter|frost/, "Drainer-Box bleibt matte Panel-Fläche");
  // 760-px-Block: einspaltiger Stapel, gap 0, margin-top 0 der rechten Box
  // (die Panel-Margins allein liefern den 22-px-Abstand, keine Verdopplung).
  // Im File gibt es MEHRERE 760-/560-px-Blöcke (about-defs etc.) — gezielt
  // der Block mit der Duo-Grid-Regel (Muster shine-spacing reduced-motion).
  const mediaBlocks = (w) => [...styleCss.matchAll(new RegExp(`@media \\(max-width: ${w}px\\)\\s*\\{[\\s\\S]*?\\n\\}`, "g"))].map((m) => m[0]);
  const m760 = mediaBlocks(760).find((b) => b.includes(".top-duo-grid"));
  assert.ok(m760, "760-px-Block mit Duo-Grid-Regel vorhanden");
  assert.match(m760, /\.top-duo-grid\s*\{\s*grid-template-columns:\s*minmax\(0,\s*1fr\);\s*gap:\s*0;\s*\}/, "Stapel ab 760 px: eine Spalte, gap 0");
  assert.match(m760, /#drainer-outflows-panel\s*\{\s*margin:\s*0 auto 22px;\s*\}/, "Stapel: margin-top 0 der Drainer-Box");
  // 560-px-Block: mobiler 14-px-Rhythmus beider Boxen.
  const m560 = mediaBlocks(560).find((b) => b.includes("#drainer-outflows-panel"));
  assert.ok(m560, "560-px-Block mit Drainer-Panel-Regel vorhanden");
  assert.match(m560, /#drainer-outflows-panel\s*\{\s*margin:\s*0 auto 14px;\s*\}/, "mobil 14 px (margin-top trägt die Börsen-Box)");
  assert.match(m560, /#exchange-outflows-panel\s*\{\s*margin:\s*14px auto;\s*\}/, "Börsen-Box-Mobilregel unverändert (shine-spacing-Invariante)");
});

test("CSS-Guard Listen-Rahmen: beide outflow-Listen ohne Browser-Defaults (list-style none, padding 0, grid gap 16px)", () => {
  const here = path.dirname(fileURLToPath(import.meta.url));
  const styleCss = readFileSync(path.join(here, "style.css"), "utf8");
  const rule = styleCss.match(/\.exchange-outflow-list,\s*\n\.drainer-outflow-list\s*\{[^}]*\}/);
  assert.ok(rule, "gemeinsame Listen-Regel vorhanden (Hausmuster .cluster-list)");
  const body = stripComments(rule[0]);
  assert.match(body, /list-style:\s*none/, "keine decimal-Ziffern — der Rang steht in .exout-rank/.drout-rank");
  assert.match(body, /padding:\s*0/, "kein 40-px-Default-Einzug hinter panel-head/disclaimer");
  assert.match(body, /display:\s*grid/, "Grid-Rahmen");
  assert.match(body, /gap:\s*16px/, "16 px Abstand — 1-px-Borders kleben nicht zu 2 px zusammen");
});

test("CSS-Guard Ausblend-Invariante: [hidden] schlägt display:grid (Cluster-Liste + beide Duo-Listen)", () => {
  const here = path.dirname(fileURLToPath(import.meta.url));
  const styleCss = readFileSync(path.join(here, "style.css"), "utf8");
  const guard = styleCss.match(/\.cluster-list\[hidden\],\s*\n\.exchange-outflow-list\[hidden\],\s*\n\.drainer-outflow-list\[hidden\]\s*\{[^}]*\}/);
  assert.ok(guard, "gruppierte [hidden]-Guard-Regel vorhanden (Audit 2026-10-08)");
  assert.match(stripComments(guard[0]), /display:\s*none/, "hidden-Attribut wirkt wieder: display:none schlägt display:grid");
  // Die Basisregeln bleiben davon unberührt (sonst wäre die Liste nie sichtbar):
  assert.match(styleCss, /\.cluster-list\s*\{[^}]*display:\s*grid/, "cluster-list-Basisregel bleibt grid");
});

test("CSS-Guard Sheen-Clipping: Börsen-Panel clippt den a6-sheen-Sweep (overflow:hidden)", () => {
  const here = path.dirname(fileURLToPath(import.meta.url));
  const styleCss = readFileSync(path.join(here, "style.css"), "utf8");
  const panelRule = styleCss.match(/#exchange-outflows-panel\s*\{[^}]*\}/);
  assert.ok(panelRule, "Panel-Basisregel vorhanden");
  assert.match(stripComments(panelRule[0]), /overflow:\s*hidden/, "Sheen-Band (translateX ±12 %) wird an der Panel-Grenze beschnitten — kein horizontaler Scrollüberschuss bei schmalen Viewports");
});

/* ---------------- 10) Verdrahtung ---------------- */

test("Verdrahtung index.html: Drainer-Panel-Markup + nur existierende drout-Keys referenziert", () => {
  const here = path.dirname(fileURLToPath(import.meta.url));
  const html = readFileSync(path.join(here, "index.html"), "utf8");
  assert.ok(html.includes('id="drainer-outflows-panel"'), "Panel-Sektion vorhanden");
  assert.ok(html.includes('id="drainer-outflow-list"'), "Listen-ID vorhanden");
  assert.ok(html.includes('id="drout-empty"'), "Empty-State-ID vorhanden");
  assert.ok(html.includes('id="drout-coverage"'), "Abdeckungszeitraum-Element vorhanden");
  assert.ok(html.includes('id="drout-capped"'), "Cap-Hinweis-Element vorhanden");
  assert.ok(html.includes('id="drout-window-7d"') && html.includes('id="drout-window-30d"'), "Fenster-Umschalter vorhanden");
  assert.ok(html.includes('aria-pressed="true"') && html.includes('aria-pressed="false"'), "aria-pressed-Muster der Umschalter");
  // Duo-Grid-Platzierung: Wrapper zwischen Bühne und Nav, Börse links, Drainer rechts.
  assert.ok(html.indexOf('class="top-duo-grid"') > html.indexOf('class="hx-stage"'), "Grid liegt NACH der hx-stage-Bühne");
  assert.ok(html.indexOf('class="top-duo-grid"') < html.indexOf('id="exchange-outflows-panel"'), "Grid liegt VOR dem Börsen-Panel (Wrapper)");
  assert.ok(html.indexOf('id="exchange-outflows-panel"') < html.indexOf('id="drainer-outflows-panel"'), "Börse links, Drainer rechts (Markup-Reihenfolge = Grid-Spalten)");
  assert.ok(html.indexOf('id="drainer-outflows-panel"') < html.indexOf("console-grid"), "Grid liegt VOR dem console-grid");
  // Jede referenzierte drout-i18n-Key muss in BEIDEN Sprachen existieren.
  const refs = [...html.matchAll(/data-i18n(?:-aria)?="(drout\.[A-Za-z0-9]+)"/g)].map((m) => m[1]);
  assert.ok(refs.length >= 8, `genug statische Keys referenziert (gefunden: ${refs.length})`);
  for (const k of refs) {
    assert.ok(DICT.en[k] !== undefined, `index.html referenziert fehlenden EN-Key ${k}`);
    assert.ok(DICT.de[k] !== undefined, `index.html referenziert fehlenden DE-Key ${k}`);
  }
});

test("Verdrahtung app.js: Modul-Import, Poll-Anbindung, Umschalter, Gates, Masken-Nachzieh", () => {
  const here = path.dirname(fileURLToPath(import.meta.url));
  const appJs = readFileSync(path.join(here, "app.js"), "utf8");
  assert.match(appJs, /from '\.\/drainer-top10\.mjs'/, "statischer Modul-Import");
  assert.match(appJs, /aggregateDrainerTop10, drainerTop10RowHtml/, "beide Modulfunktionen importiert");
  assert.match(appJs, /function renderDrainerTop10\(/, "Render-Funktion vorhanden");
  assert.match(appJs, /renderDrainerTop10\(body\);/, "Aufruf im pollFlowState (dieselbe Antwort, +0 Requests)");
  assert.match(appJs, /bindDrainerTop10\(\);/, "Umschalter-Binding im Startblock");
  assert.match(appJs, /renderDrainerTop10\(flowData\);/, "Nachzieh-Render im Sprach-Block/Masken-Nachzieh");
  assert.match(appJs, /drainerTop10RowHtml\(row, i \+ 1, ui\)/, "Zeilen über injizierte Host-Gates");
  assert.match(appJs, /displayAddr: displayFindingAddr/, "Anzeige über die bestehende Maske (Pflicht 12)");
  assert.match(appJs, /t\('drout\.coverage'/, "Abdeckungszeitraum gerendert");
  assert.match(appJs, /t\('drout\.capped'/, "Cap-Hinweis gerendert");
  assert.match(appJs, /t\('drout\.tagAria'\)/, "eigener Tag-Aria-Schlüssel (tag.chipAria ist für Drainer falsch)");
  assert.match(appJs, /droutMaskRepairInFlight/, "Einmal-Guard des Masken-Nachziehs");
});

test("Verdrahtung package.json: Testdatei in der Suite gelistet", () => {
  const here = path.dirname(fileURLToPath(import.meta.url));
  const pkg = JSON.parse(readFileSync(path.join(here, "..", "package.json"), "utf8"));
  assert.ok(pkg.scripts.test.includes("public/drainer-top10.test.mjs"), "Testdatei im npm-test-Script");
});
