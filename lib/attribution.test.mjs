// lib/attribution.test.mjs — node:test-Unit-Tests der Länder-Zuordnung
// (public/attribution.mjs; reines ESM ohne DOM, daher direkt in Node
// testbar). Synthetische rTEST…-Adressen und ein Mini-GeoJSON-Fixture
// statt der echten 750-KB-Natural-Earth-Datei — keine echten Adressen,
// keine Köder (bait.json/bait-history.json werden nicht gelesen), kein
// Netz, keine Datei-Lesezugriffe auf realen Daten. Ausführen:
// node --test lib/attribution.test.mjs
//
// Getestete Verträge (Auszug):
//   (1) parseExchangeRegistry — gültige Einträge, Skip ohne XRPL-Adresse,
//       Garbage -> ok:false ohne throw.
//   (2) computeCentroid — PFLICHT: Eingaberinge GeoJSON-geordnet [lng,lat],
//       Rückgabe [lat,lng] (Achsen-Tausch); Pflicht-Fixture Quadrat
//       lng 4..8 / lat 50..53 -> [51.5, 6]; MultiPolygon größter Ring;
//       degeneriert -> null.
//   (3) matchCountry — exakt, case-insensitiv, Alias, unbekannt ->
//       noPolygon:true.
//   (4) aggregateCountryFlows — null->Land und Land->Land-Flows mit
//       Severity-Zählung, unassigned-Zähler, countries-Aggregation
//       (malicious schlägt suspect), Intra-Land-Kanten erzeugen keinen
//       Flow, leere Eingaben ohne throw.
import test from "node:test";
import assert from "node:assert/strict";
import {
  parseExchangeRegistry,
  computeCentroid,
  indexCountryFeatures,
  matchCountry,
  aggregateCountryFlows,
  COUNTRY_ALIASES,
} from "../public/attribution.mjs";

// ---------- Synthetische Fixtures (keine echten Adressen, keine Köder) ----------
const ADDR_EX_A = "rTESTExchangeA1111111111111111111"; // Netherlands
const ADDR_EX_B = "rTESTExchangeB2222222222222222222"; // united kingdom (case-insensitiv)
const ADDR_EX_C = "rTESTExchangeC3333333333333333333"; // Holland (Alias -> Netherlands)
const ADDR_ATLANTIS = "rTESTExchangeL6666666666666666666"; // Atlantis (kein Polygon)
const ADDR_STRANGER = "rTESTStrangerD4444444444444444444"; // nicht in Registry
const ADDR_STRANGER_E = "rTESTStrangerE5555555555555555555"; // nur Kanten-Endpunkt, kein Node

const REGISTRY_RAW = {
  version: 1,
  entries: [
    {
      address: `  ${ADDR_EX_A}  `, // trimmen prüfen
      exchange: " TestExchange A ",
      country: "  Netherlands ",
      countryCode: "nl",
      kind: "exchange",
      confidence: "verified",
    },
    {
      address: ADDR_EX_B,
      exchange: "TestExchange B",
      country: "united kingdom",
      countryCode: "GB",
      kind: "gateway",
      confidence: "likely",
    },
    {
      address: ADDR_EX_C,
      exchange: "TestExchange C",
      country: "Holland",
      countryCode: "NL",
      kind: "exchange",
      confidence: "verified",
    },
    {
      address: ADDR_ATLANTIS,
      exchange: "TestExchange L",
      country: "Atlantis",
      countryCode: "ATL",
      kind: "issuer",
      confidence: "likely",
    },
    { exchange: "Keine Adresse", country: "Netherlands" }, // kein address-Feld
    { address: "keine-XRPL-adresse-12345678901234567890", exchange: "Muster" }, // Muster-Verstoß
    { address: 42, exchange: "Zahl" }, // kein String
  ],
};

// Mini-GeoJSON (TopoJSON-Feature-Ausgabe nachgebildet): Ringe GeoJSON-
// geordnet [lng, lat]. Quadrat-Zentroiden: NL lng 3..7/lat 51..54 ->
// [52.5, 5]; UK lng -4..1/lat 50..58 -> [54, -1.5]; USA lng -125..-66/
// lat 25..49 -> [37, -95.5].
const NL_FEATURE = {
  type: "Feature",
  properties: { name: "Netherlands" },
  geometry: { type: "Polygon", coordinates: [[[3, 51], [7, 51], [7, 54], [3, 54]]] },
};
const UK_FEATURE = {
  type: "Feature",
  properties: { name: "United Kingdom" },
  geometry: { type: "Polygon", coordinates: [[[-4, 50], [1, 50], [1, 58], [-4, 58]]] },
};
const US_FEATURE = {
  type: "Feature",
  properties: { name: "United States of America" },
  geometry: { type: "Polygon", coordinates: [[[-125, 25], [-66, 25], [-66, 49], [-125, 49]]] },
};
const COUNTRIES_GEO = {
  type: "FeatureCollection",
  features: [
    NL_FEATURE,
    UK_FEATURE,
    US_FEATURE,
    { type: "Feature", properties: {}, geometry: NL_FEATURE.geometry }, // ohne Namen
    { type: "Feature", properties: { name: "Pointland" }, geometry: { type: "Point", coordinates: [1, 2] } },
  ],
};
// Gematchtes Land mit degeneriertem Ring (kollinear, Fläche 0) -> centroid null.
const DEGENERIA_FEATURE = {
  type: "Feature",
  properties: { name: "Degeneria" },
  geometry: { type: "Polygon", coordinates: [[[0, 0], [1, 1], [2, 2], [3, 3]]] },
};

// Toleranz-Assertion für [lat, lng]-Paare (Float-Sicherheit).
function assertLatLng(actual, expected, label) {
  assert.ok(Array.isArray(actual), `${label}: Rückgabe ist kein Array`);
  assert.equal(actual.length, 2, `${label}: Länge 2 erwartet`);
  assert.ok(
    Math.abs(actual[0] - expected[0]) < 1e-9 && Math.abs(actual[1] - expected[1]) < 1e-9,
    `${label}: erwartet [${expected.join(", ")}], erhalten [${actual.join(", ")}]`
  );
}

// ---------- 1) parseExchangeRegistry ----------
test("parseExchangeRegistry: gültige Einträge (getrimmt, countryCode uppercased), Einträge ohne XRPL-Adresse werden übersprungen", () => {
  const reg = parseExchangeRegistry(REGISTRY_RAW);
  assert.equal(reg.ok, true, "ok muss true sein (byAddress nicht leer)");
  assert.equal(reg.entries.length, 4, "nur die 4 Einträge mit gültiger r…-Adresse");
  assert.equal(reg.byAddress.size, 4);
  const a = reg.byAddress.get(ADDR_EX_A);
  assert.ok(a, "Adresse A im Index (ungetrimmter Registry-Eintrag)");
  // Neu-Felder des Registry-Mergs (Grenze 4): tier/requireDestTag/signers/
  // lastTxLedger/activeWithin7d — ohne Angaben im Eintrag: Defaults
  // ('', false, [], null, null), rückwärtskompatibel.
  assert.deepEqual(a, {
    address: ADDR_EX_A,
    exchange: "TestExchange A",
    country: "Netherlands",
    countryCode: "NL",
    kind: "exchange",
    confidence: "verified",
    tier: "",
    requireDestTag: false,
    signers: [],
    lastTxLedger: null,
    activeWithin7d: null,
  });
  assert.ok(!reg.byAddress.has("keine-XRPL-adresse-12345678901234567890"), "Muster-Verstoß wurde nicht übersprungen");
  assert.ok(!reg.entries.some((e) => e.exchange === "Keine Adresse" || e.exchange === "Zahl" || e.exchange === "Muster"), "Einträge ohne Adresse dürfen nicht in entries landen");
});

test("parseExchangeRegistry: Garbage-Eingaben liefern ok:false ohne throw", () => {
  for (const garbage of [null, undefined, 42, "x", {}, { entries: 5 }, { entries: [{}, { address: "rXY" }] }]) {
    const reg = parseExchangeRegistry(garbage);
    assert.equal(reg.ok, false, `ok:false für ${JSON.stringify(garbage)}`);
    assert.deepEqual(reg.entries, []);
    assert.equal(reg.byAddress.size, 0);
  }
});

test("parseExchangeRegistry: direktes Array wird akzeptiert", () => {
  const reg = parseExchangeRegistry([{ address: ADDR_EX_A, country: "Netherlands" }]);
  assert.equal(reg.ok, true);
  assert.equal(reg.byAddress.size, 1);
  assert.equal(reg.byAddress.get(ADDR_EX_A).country, "Netherlands");
});

// ---------- 2) computeCentroid ----------
test("computeCentroid: Quadrat-Fixture in GeoJSON-Ordnung [lng,lat] liefert getauschte Rückgabe [lat,lng] — Pflicht-Fixture lng 4..8 / lat 50..53 -> [51.5, 6]", () => {
  const geometry = { type: "Polygon", coordinates: [[[4, 50], [8, 50], [8, 53], [4, 53]]] };
  const centroid = computeCentroid(geometry);
  assertLatLng(centroid, [51.5, 6], "Polygon-Zentroid");
  // Feature-Envelope (topojson liefert Features) muss identisch auflösen.
  assertLatLng(computeCentroid({ type: "Feature", properties: {}, geometry }), [51.5, 6], "Feature-Zentroid");
});

test("computeCentroid: MultiPolygon — der Ring mit der größten Fläche gewinnt (unabhängig von der Reihenfolge)", () => {
  const big = [[10, 40], [14, 40], [14, 44], [10, 44]]; // Zentroid [42, 12]
  const small = [[0, 0], [1, 0], [1, 1], [0, 1]]; // Zentroid [0.5, 0.5]
  const mp = (r1, r2) => ({ type: "MultiPolygon", coordinates: [[r1], [r2]] });
  assertLatLng(computeCentroid(mp(small, big)), [42, 12], "kleiner Ring zuerst");
  assertLatLng(computeCentroid(mp(big, small)), [42, 12], "großer Ring zuerst");
});

test("computeCentroid: degenerierte Eingaben liefern null (weniger als 4 Punkte, kollinear, falscher Typ, leer)", () => {
  assert.equal(computeCentroid(null), null, "null-Eingabe");
  assert.equal(computeCentroid({}), null, "leeres Objekt");
  assert.equal(computeCentroid({ type: "Point", coordinates: [1, 2] }), null, "Point-Geometrie");
  assert.equal(
    computeCentroid({ type: "Polygon", coordinates: [[[1, 1], [2, 2], [3, 3]]] }),
    null,
    "Ring mit nur 3 Punkten"
  );
  assert.equal(
    computeCentroid({ type: "Polygon", coordinates: [[[0, 0], [1, 1], [2, 2], [3, 3]]] }),
    null,
    "4 kollineare Punkte (Fläche 0)"
  );
  assert.equal(computeCentroid({ type: "Polygon", coordinates: [[]] }), null, "leerer Ring");
});

// ---------- 3) indexCountryFeatures ----------
test("indexCountryFeatures: nur Features mit Namen und Polygon/MultiPolygon, normalisierte Keys, unveränderter Name", () => {
  const idx = indexCountryFeatures(COUNTRIES_GEO);
  assert.equal(idx.count, 3, "Feature ohne Namen und Point-Feature werden übersprungen");
  assert.equal(idx.byName.size, 3);
  const nl = idx.byName.get("netherlands");
  assert.ok(nl, "Key normalisiert (trim/NFKC/lower)");
  assert.equal(nl.name, "Netherlands", "properties.name unverändert (englisch)");
  assert.strictEqual(nl.feature, NL_FEATURE, "Feature-Referenz wird durchgereicht");
  assertLatLng(nl.centroid, [52.5, 5], "NL-Centroid");
  assert.ok(idx.byName.get("united kingdom") && idx.byName.get("united states of america"));
  // Feature-Array direkt und Garbage-Eingaben.
  assert.equal(indexCountryFeatures(COUNTRIES_GEO.features).count, 3, "direktes Feature-Array");
  const empty = indexCountryFeatures(null);
  assert.equal(empty.count, 0);
  assert.equal(empty.byName.size, 0);
});

// ---------- 4) matchCountry ----------
test("matchCountry: exakter und case-insensitiver Match liefert kanonischen Namen und Centroid", () => {
  const idx = indexCountryFeatures(COUNTRIES_GEO);
  assert.deepEqual(matchCountry("Netherlands", idx), { name: "Netherlands", centroid: [52.5, 5], noPolygon: false });
  const ci = matchCountry("  nEtHeRlAnDs ", idx);
  assert.equal(ci.name, "Netherlands");
  assert.equal(ci.noPolygon, false);
  assert.equal(matchCountry("UNITED KINGDOM", idx).name, "United Kingdom");
});

test("matchCountry: Aliase (usa/Holland/uk) lösen auf; cayman islands bleibt ohne Polygon, wenn das Zielland fehlt", () => {
  const idx = indexCountryFeatures(COUNTRIES_GEO);
  assert.equal(matchCountry("usa", idx).name, "United States of America");
  assert.equal(matchCountry("Holland", idx).name, "Netherlands");
  assert.equal(matchCountry("uk", idx).name, "United Kingdom");
  assert.equal(COUNTRY_ALIASES["cayman islands"], "cayman is.", "Alias-Tabelle enthält cayman islands");
  assert.deepEqual(matchCountry("cayman islands", idx), { name: null, centroid: null, noPolygon: true });
});

test("matchCountry: unbekannte oder leere Eingaben -> noPolygon:true (auch ohne Index)", () => {
  const idx = indexCountryFeatures(COUNTRIES_GEO);
  for (const unknown of ["Atlantis", "", null, undefined]) {
    assert.deepEqual(matchCountry(unknown, idx), { name: null, centroid: null, noPolygon: true });
  }
  assert.deepEqual(matchCountry("Netherlands", null), { name: null, centroid: null, noPolygon: true }, "null-Index");
});

// ---------- 5) aggregateCountryFlows ----------
test("aggregateCountryFlows: unzugeordnet->Börse erzeugt null->Land, Börse->Börse erzeugt Land->Land, Land->Unbekannt erzeugt Land->null (Severity-Zählung inklusive)", () => {
  const registry = parseExchangeRegistry(REGISTRY_RAW);
  const countryIndex = indexCountryFeatures(COUNTRIES_GEO);
  const nodes = [
    { id: ADDR_STRANGER, severity: "malicious" },
    { id: ADDR_EX_A, severity: "suspect" },
    { id: ADDR_EX_B, severity: "info" },
  ];
  const edges = [
    { from: ADDR_STRANGER, to: ADDR_EX_A, type: "Payment" }, // null -> Netherlands
    { from: ADDR_EX_A, to: ADDR_EX_B, type: "Payment" }, // Netherlands -> United Kingdom
    { from: ADDR_EX_A, to: ADDR_STRANGER_E, type: "Payment" }, // Netherlands -> null (Endpunkt ohne Node -> info)
    { from: ADDR_STRANGER, to: ADDR_STRANGER_E, type: "Payment" }, // kein attribuierter Endpunkt
  ];
  const result = aggregateCountryFlows({ nodes, edges, registry, countryIndex });

  assert.equal(result.assignedByAddress.size, 2, "nur Registry-Adressen sind zugeordnet");
  assert.ok(result.assignedByAddress.has(ADDR_EX_A) && result.assignedByAddress.has(ADDR_EX_B));
  assert.ok(!result.assignedByAddress.has(ADDR_STRANGER), "unzugeordnete Adresse darf keinen Eintrag haben");

  // Sortierung: count desc, dann fromCountry asc (null vor Namen), dann toCountry asc.
  assert.deepEqual(result.flows, [
    {
      fromCountry: null,
      toCountry: "Netherlands",
      count: 1,
      severities: { malicious: 1, suspect: 0, info: 0 },
      worstSeverity: "malicious",
      exchanges: ["TestExchange A"],
    },
    {
      fromCountry: "Netherlands",
      toCountry: null,
      count: 1,
      severities: { malicious: 0, suspect: 1, info: 0 },
      worstSeverity: "suspect",
      exchanges: ["TestExchange A"],
    },
    {
      fromCountry: "Netherlands",
      toCountry: "United Kingdom",
      count: 1,
      severities: { malicious: 0, suspect: 1, info: 0 },
      worstSeverity: "suspect",
      exchanges: ["TestExchange A", "TestExchange B"],
    },
  ]);

  assert.deepEqual(result.unassigned, { addresses: 1, edges: 1 }, "ein nicht-Registry-Node, eine Kante ohne attribuierten Endpunkt");
  assert.equal(result.countries.length, 2);
  assert.equal(result.countries[0].name, "Netherlands", "activity gleich -> name asc");
  assert.equal(result.countries[0].worstSeverity, "suspect");
  assert.deepEqual(result.countries[0].severities, { malicious: 0, suspect: 1, info: 0 });
  assert.equal(result.countries[1].name, "United Kingdom");
  assert.equal(result.countries[1].worstSeverity, "info");
  // Invariante: countries[]/flows[] enthalten keine Adressen.
  assert.ok(!JSON.stringify({ c: result.countries, f: result.flows }).includes("rTEST"), "Adresse im Länder-/Fluss-Output");
});

test("aggregateCountryFlows: Intra-Land-Kanten (Börse->Börse desselben Landes) erzeugen KEINEN Flow — weder Zufluss noch Abfluss (Befund 2026-09-30)", () => {
  const registry = parseExchangeRegistry(REGISTRY_RAW);
  const countryIndex = indexCountryFeatures(COUNTRIES_GEO);
  // ADDR_EX_C („Holland") matcht über den Alias ebenfalls auf Netherlands.
  const nodes = [
    { id: ADDR_EX_A, severity: "suspect" }, // Netherlands
    { id: ADDR_EX_C, severity: "info" },    // Holland -> Alias -> Netherlands
  ];
  const edges = [
    { from: ADDR_EX_A, to: ADDR_EX_C, type: "Payment" },  // Netherlands -> Netherlands (Intra-Land)
  ];
  const result = aggregateCountryFlows({ nodes, edges, registry, countryIndex });

  assert.deepEqual(result.flows, [], "Intra-Land-Kante darf weder als Zufluss- noch als Abfluss-Flow auftauchen");
  assert.equal(result.countries.length, 1, "Beide Nodes zählen weiterhin als Aktivität ihres Landes");
  assert.equal(result.countries[0].name, "Netherlands");
  assert.equal(result.countries[0].activity, 2);
  assert.deepEqual(result.countries[0].exchanges, ["TestExchange A", "TestExchange C"]);
  assert.deepEqual(
    result.unassigned,
    { addresses: 0, edges: 0 },
    "beide Endpunkte sind zugeordnet — die Kante zählt weder als unzugeordnet noch als Fluss"
  );
});

test("aggregateCountryFlows: countries-Aggregation — Alias landet im selben Land, malicious schlägt suspect, Sortierung activity desc", () => {
  const registry = parseExchangeRegistry(REGISTRY_RAW);
  const countryIndex = indexCountryFeatures(COUNTRIES_GEO);
  const nodes = [
    { id: ADDR_EX_A, severity: "suspect" }, // Netherlands
    { id: ADDR_EX_C, severity: "malicious" }, // Holland -> Alias -> Netherlands
    { id: ADDR_EX_B, severity: "info" }, // United Kingdom
  ];
  const edges = [
    { from: ADDR_EX_A, to: ADDR_EX_B, type: "Payment" },
    { from: ADDR_EX_C, to: ADDR_EX_B, type: "Payment" },
  ];
  const result = aggregateCountryFlows({ nodes, edges, registry, countryIndex });

  assert.equal(result.countries.length, 2);
  const nl = result.countries[0];
  assert.equal(nl.name, "Netherlands", "aktivitätshöheres Land zuerst");
  assert.equal(nl.activity, 2, "activity zählt attribuierte Nodes");
  assert.deepEqual(nl.severities, { malicious: 1, suspect: 1, info: 0 });
  assert.equal(nl.worstSeverity, "malicious", "malicious schlägt suspect");
  assert.deepEqual(nl.exchanges, ["TestExchange A", "TestExchange C"], "unique und sortiert");
  assertLatLng(nl.centroid, [52.5, 5], "NL-Centroid aus GeoJSON");
  const uk = result.countries[1];
  assert.equal(uk.name, "United Kingdom");
  assert.equal(uk.activity, 1);

  // Fluss-Aggregation: zwei NL->UK-Kanten verschmelzen (count 2).
  assert.deepEqual(result.flows, [
    {
      fromCountry: "Netherlands",
      toCountry: "United Kingdom",
      count: 2,
      severities: { malicious: 1, suspect: 1, info: 0 },
      worstSeverity: "malicious",
      exchanges: ["TestExchange A", "TestExchange B", "TestExchange C"],
    },
  ]);
  assert.deepEqual(result.unassigned, { addresses: 0, edges: 0 });
  // Invariante: jeder nicht-null Ländername aus flows[] kommt in countries[] vor.
  const names = new Set(result.countries.map((c) => c.name));
  for (const flow of result.flows) {
    if (flow.fromCountry !== null) assert.ok(names.has(flow.fromCountry), `${flow.fromCountry} fehlt in countries[]`);
    if (flow.toCountry !== null) assert.ok(names.has(flow.toCountry), `${flow.toCountry} fehlt in countries[]`);
  }
});

test("aggregateCountryFlows: Kanten und Nodes ohne Registry-Zuordnung zählen nur in unassigned", () => {
  const registry = parseExchangeRegistry(REGISTRY_RAW);
  const countryIndex = indexCountryFeatures(COUNTRIES_GEO);
  const result = aggregateCountryFlows({
    nodes: [{ id: ADDR_STRANGER, severity: "info" }],
    edges: [{ from: ADDR_STRANGER, to: ADDR_STRANGER_E, type: "Payment" }],
    registry,
    countryIndex,
  });
  assert.equal(result.assignedByAddress.size, 0);
  assert.deepEqual(result.countries, []);
  assert.deepEqual(result.flows, []);
  assert.deepEqual(result.unassigned, { addresses: 1, edges: 1 });
});

test("aggregateCountryFlows: zugeordnete Adresse ohne Polygon (noPolygon) erzeugt keinen Länder-Flow und kein Land", () => {
  const registry = parseExchangeRegistry(REGISTRY_RAW);
  const countryIndex = indexCountryFeatures(COUNTRIES_GEO);
  const result = aggregateCountryFlows({
    nodes: [
      { id: ADDR_STRANGER, severity: "info" },
      { id: ADDR_ATLANTIS, severity: "suspect" },
    ],
    edges: [{ from: ADDR_STRANGER, to: ADDR_ATLANTIS, type: "Payment" }],
    registry,
    countryIndex,
  });
  const atl = result.assignedByAddress.get(ADDR_ATLANTIS);
  assert.ok(atl, "Registry-Adresse ist zugeordnet");
  assert.deepEqual(
    { country: atl.country, countryRaw: atl.countryRaw, noPolygon: atl.noPolygon, centroid: atl.centroid, exchange: atl.exchange },
    { country: null, countryRaw: "Atlantis", noPolygon: true, centroid: null, exchange: "TestExchange L" }
  );
  assert.deepEqual(result.countries, [], "kein Polygon -> kein Land-Eintrag");
  assert.deepEqual(result.flows, [], "kein Endpunkt mit gematchtem Land -> kein Flow");
  assert.deepEqual(result.unassigned, { addresses: 1, edges: 1 }, "Atlantis-Node ist zugeordnet (keine unassigned-Adresse), die Kante bleibt unzugeordnet");
});

test("aggregateCountryFlows: gematchtes Land mit degeneriertem Centroid bleibt Land mit centroid:null (kein stiller Verlust)", () => {
  const registry = parseExchangeRegistry({
    entries: [{ address: ADDR_EX_A, exchange: "TestExchange A", country: "Degeneria", countryCode: "DG", kind: "exchange", confidence: "verified" }],
  });
  const countryIndex = indexCountryFeatures([DEGENERIA_FEATURE, NL_FEATURE]);
  const result = aggregateCountryFlows({
    nodes: [{ id: ADDR_EX_A, severity: "malicious" }],
    edges: [{ from: ADDR_STRANGER_E, to: ADDR_EX_A, type: "Payment" }],
    registry,
    countryIndex,
  });
  const assigned = result.assignedByAddress.get(ADDR_EX_A);
  assert.equal(assigned.country, "Degeneria");
  assert.equal(assigned.noPolygon, false, "Land existiert — nur die Geometrie ist degeneriert");
  assert.equal(assigned.centroid, null, "degenerierter Centroid ist null");
  assert.equal(result.countries.length, 1);
  assert.equal(result.countries[0].name, "Degeneria");
  assert.equal(result.countries[0].centroid, null);
  assert.deepEqual(result.flows, [
    {
      fromCountry: null,
      toCountry: "Degeneria",
      count: 1,
      severities: { malicious: 1, suspect: 0, info: 0 },
      worstSeverity: "malicious",
      exchanges: ["TestExchange A"],
    },
  ]);
});

test("aggregateCountryFlows: leere oder fehlende Eingaben liefern ein leeres Result ohne throw", () => {
  for (const input of [null, undefined, {}, { nodes: null, edges: null, registry: null, countryIndex: null }, { nodes: [], edges: [] }]) {
    const result = aggregateCountryFlows(input);
    assert.ok(result.assignedByAddress instanceof Map);
    assert.equal(result.assignedByAddress.size, 0);
    assert.deepEqual(result.countries, []);
    assert.deepEqual(result.flows, []);
    assert.deepEqual(result.unassigned, { addresses: 0, edges: 0 });
  }
});

// ---------- 6) custodyFlows (Grenze 4, Audit-Nachprüfung) ----------
// Endhop auf einen Registry-Eintrag der tier 'cold' ist eine Custody-
// Umbuchung, KEIN Off-Ramp: sie steht in custodyFlows, nicht in flows.
// Hot-Endhop bleibt in flows (Hot-Off-Ramp-vs-Cold-Custody-Unterscheidung).
// Konsument: public/globe.js Länderpunkt-Label 'globe.custody' (custodyFlows
// werden NICHT in die I/O-Summen gemischt).
test("aggregateCountryFlows: cold-Endhop -> custodyFlows, hot-Endhop -> flows, tier '' unverändert", () => {
  const ADDR_COLD = "rTESTCstody9999999999999999999"; // base58-konform (kein l/I/O/0)
  const registry = parseExchangeRegistry({
    version: 1,
    entries: [
      { address: ADDR_EX_A, exchange: "TestExchange A", country: "Netherlands", kind: "exchange", confidence: "verified", tier: "hot" },
      { address: ADDR_COLD, exchange: "TestVault C", country: "United Kingdom", kind: "custody", confidence: "verified", tier: "cold" },
      { address: ADDR_EX_B, exchange: "TestExchange B", country: "United Kingdom", kind: "gateway", confidence: "likely" }, // tier ''
    ],
  });
  const countryIndex = indexCountryFeatures(COUNTRIES_GEO);
  const nodes = [
    { id: ADDR_STRANGER, severity: "malicious" },
    { id: ADDR_EX_A, severity: "suspect" },
    { id: ADDR_COLD, severity: "info" },
    { id: ADDR_EX_B, severity: "info" },
  ];
  const edges = [
    { from: ADDR_STRANGER, to: ADDR_COLD, type: "Payment" }, // Custody-Umbuchung: cold-Endhop
    { from: ADDR_EX_A, to: ADDR_COLD, type: "Payment" }, // Intra-Land? nein: NL -> UK, cold-Endhop
    { from: ADDR_STRANGER, to: ADDR_EX_A, type: "Payment" }, // hot-Endhop -> Off-Ramp in flows
    { from: ADDR_EX_A, to: ADDR_EX_B, type: "Payment" }, // tier '' -> unverändert flows
  ];
  const result = aggregateCountryFlows({ nodes, edges, registry, countryIndex });
  assert.deepEqual(result.flows.map((f) => [f.fromCountry, f.toCountry, f.count]), [
    [null, "Netherlands", 1],
    ["Netherlands", "United Kingdom", 1],
  ], "nur hot-/tierlose Endhops in flows — cold-Endhop fehlt");
  assert.deepEqual(result.custodyFlows.map((f) => [f.fromCountry, f.toCountry, f.count]), [
    [null, "United Kingdom", 1],
    ["Netherlands", "United Kingdom", 1],
  ], "cold-Endhops in custodyFlows (gleiche Struktur/Sortierung count desc)");
  assert.equal(result.custodyFlows[0].worstSeverity, "malicious", "Severity-Zählung wie in flows");
  assert.ok(!JSON.stringify(result.flows).includes("TestVault"), "Custody-Ziel taucht nicht als Off-Ramp auf");
  // Rückwärtskompatibilität: alter Bestand ohne tier -> custodyFlows leer.
  const legacy = aggregateCountryFlows({
    nodes, edges, registry: parseExchangeRegistry(REGISTRY_RAW), countryIndex,
  });
  assert.deepEqual(legacy.custodyFlows, [], "ohne tier-Angabe: kein Reklassifizieren");
  assert.equal(legacy.flows.length, 3, "alle Kanten bleiben in flows");
});
