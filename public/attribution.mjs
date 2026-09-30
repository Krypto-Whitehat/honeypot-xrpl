'use strict';
// public/attribution.mjs — Länder-Zuordnung (Attribution) von Börsen-
// Registry-Adressen für die Weltkugel. Reines ESM ohne DOM: kein fetch,
// kein window/document, kein console — läuft identisch in Node (Unit-Tests:
// lib/attribution.test.mjs importiert '../public/attribution.mjs') und im
// Browser (dynamischer Import aus public/globe.js, same-origin ausgeliefert
// über express.static). Alle exportierten Funktionen werfen nie; jede
// Eingabe darf null/undefined sein.
//
// Verbindliche Datenverträge (für public/globe.js):
//   parseExchangeRegistry(raw)  — raw: geparstes JSON von
//       /data/exchange-registry.json (Objekt mit entries-Array; ein
//       direktes Array wird ebenfalls akzeptiert). Ergebnis:
//       { ok, entries, byAddress: Map<adresse, RegistryEntry> }.
//   computeCentroid(geometry)   — GeoJSON-Geometry oder Feature. Eingabe-
//       ringe sind GeoJSON-geordnet [lng, lat]; Rückgabe ist [lat, lng],
//       die Achsen werden beim RETURN GETAUSCHT. Planarer Schuhband-
//       Zentroid des flächengrößten Rings (dokumentierte Grenze: planar,
//       Antimeridian-Verläufe ungenau — kein Registry-Land betroffen).
//   indexCountryFeatures(geo)   — FeatureCollection (topojson.feature-
//       Ausgabe) oder Feature-Array -> { count, byName }.
//   matchCountry(name, index)   — exakt/Case-insensitiv/Alias (COUNTRY_
//       ALIASES) -> GeoJSON-Ländername + Centroid, sonst noPolygon:true.
//   aggregateCountryFlows({...})— siehe Funktionskommentar.
//
// Länder- und Börsennamen bleiben ENGLISCH (properties.name bzw. Registry);
// nichts wird hier übersetzt. Es gibt KEINE Lesezugriffe auf bait.json/
// bait-history.json — dieses Modul kennt keine Köder.

const XRPL_ADDRESS_RE = /^r[1-9A-HJ-NP-Za-km-z]{24,34}$/;

// Severity-Rang wie public/globe.js SEV_RANK: info < suspect < malicious.
const SEV_RANK = Object.freeze({ info: 1, suspect: 2, malicious: 3 });

// Alias-Tabelle für Registry-Ländernamen -> kanonische GeoJSON-Namen
// (Natural Earth, properties.name). Keys und Werte normalisiert (trim,
// NFKC, lower). Nur Lesezugriff über matchCountry.
export const COUNTRY_ALIASES = Object.freeze({
  usa: "united states of america",
  "united states": "united states of america",
  us: "united states of america",
  uk: "united kingdom",
  "great britain": "united kingdom",
  korea: "south korea",
  "republic of korea": "south korea",
  "cayman islands": "cayman is.",
  uae: "united arab emirates",
  holland: "netherlands",
});

// ---------- interne Helfer (alle werfen nie) ----------

function trimTo(value) {
  return typeof value === "string" ? value.trim() : "";
}

function normalizeCountryKey(value) {
  return trimTo(value).normalize("NFKC").toLowerCase();
}

function clampNum(value, min, max) {
  if (value < min) return min;
  if (value > max) return max;
  return value;
}

// Flächengewichteter Zentroid EINES Rings (GeoJSON-Punkte [lng, lat]).
// Rückgabe { area: |Schuhbandfläche|, lat, lng } oder null bei: < 4
// verwertbaren Punkten, nicht-endlichen Zwischenwerten oder Fläche 0.
function ringCentroid(ring) {
  if (!Array.isArray(ring)) return null;
  const pts = [];
  for (const p of ring) {
    if (!Array.isArray(p)) continue;
    const x = p[0];
    const y = p[1];
    if (!Number.isFinite(x) || !Number.isFinite(y)) continue;
    pts.push([x, y]);
  }
  if (pts.length < 4) return null;
  const n = pts.length;
  let area2 = 0; // 2 * vorzeichenbehaftete Fläche
  let cx3 = 0; // 6A * Zentroid-lng
  let cy3 = 0; // 6A * Zentroid-lat
  for (let i = 0; i < n; i += 1) {
    const a = pts[i];
    const b = pts[(i + 1) % n]; // Ring zyklisch schließen
    const cross = a[0] * b[1] - b[0] * a[1];
    if (!Number.isFinite(cross)) return null;
    area2 += cross;
    cx3 += (a[0] + b[0]) * cross;
    cy3 += (a[1] + b[1]) * cross;
  }
  if (!Number.isFinite(area2) || !Number.isFinite(cx3) || !Number.isFinite(cy3)) return null;
  const area = area2 / 2;
  if (!(Math.abs(area) > 0)) return null; // degeneriert (kollinear) oder NaN
  const lng = cx3 / (3 * area2); // 6A === 3 * area2
  const lat = cy3 / (3 * area2);
  if (!Number.isFinite(lat) || !Number.isFinite(lng)) return null;
  return { area: Math.abs(area), lat, lng };
}

// Node-Severity normalisieren: fehlender Knoten, leerer oder unbekannter
// Wert -> 'info' (Rang wie globe.js SEV_RANK).
function nodeSeverity(node) {
  const sev = trimTo(node && node.severity).toLowerCase();
  return SEV_RANK[sev] ? sev : "info";
}

function maxSeverity(a, b) {
  return SEV_RANK[a] >= SEV_RANK[b] ? a : b;
}

function worstSeverityOf(severities) {
  if (severities.malicious > 0) return "malicious";
  if (severities.suspect > 0) return "suspect";
  return "info";
}

// Binärer Vergleich; null sortiert vor jedem Namen (stabile Gesamtordnung).
function compareCountryAsc(a, b) {
  if (a === b) return 0;
  if (a === null) return -1;
  if (b === null) return 1;
  return a < b ? -1 : 1;
}

function sortedExchanges(set) {
  return [...set].sort();
}

// ---------- (1) Registry ----------

// parseExchangeRegistry(raw) — raw: geparstes JSON von
// public/data/exchange-registry.json ({ entries: [...] }) ODER ein direktes
// Array. Einträge ohne String-Adresse, die /^r[1-9A-HJ-NP-Za-km-z]{24,34}$/
// (nach trim) entspricht, werden ÜBERSPRUNGEN. Rückgabe:
// { ok: byAddress.size > 0, entries: RegistryEntry[], byAddress: Map }
// RegistryEntry = { address, exchange, country, countryCode (uppercased),
// kind, confidence } — Strings getrimmt, nicht-Strings -> ''.
export function parseExchangeRegistry(raw) {
  const empty = { ok: false, entries: [], byAddress: new Map() };
  let list = null;
  if (Array.isArray(raw)) {
    list = raw;
  } else if (raw && typeof raw === "object" && Array.isArray(raw.entries)) {
    list = raw.entries;
  }
  if (!list) return empty;
  const entries = [];
  const byAddress = new Map();
  for (const item of list) {
    if (!item || typeof item !== "object") continue;
    const address = trimTo(item.address);
    if (!XRPL_ADDRESS_RE.test(address)) continue;
    const entry = {
      address,
      exchange: trimTo(item.exchange),
      country: trimTo(item.country),
      countryCode: trimTo(item.countryCode).toUpperCase(),
      kind: trimTo(item.kind),
      confidence: trimTo(item.confidence),
    };
    entries.push(entry);
    byAddress.set(address, entry); // Duplikat-Adresse: letzter gewinnt
  }
  return { ok: byAddress.size > 0, entries, byAddress };
}

// ---------- (2) Centroid ----------

// computeCentroid(geometry) — Eingabe: GeoJSON-Geometry
// { type: 'Polygon' | 'MultiPolygon', coordinates } oder ein Feature
// ({ geometry }). ACHSEN-REGEL: Eingaberinge sind [lng, lat]; die Rückgabe
// ist [lat, lng] — die Achsen werden beim RETURN GETAUSCHT (Klemmen:
// lat aus Eingabe-Index 1 auf [-90, 90], lng aus Index 0 auf
// [-180, 180]). Ring-Auswahl: Polygon -> Exterior-Ring coordinates[0];
// MultiPolygon -> der Ring mit der größten absoluten Schuhband-Fläche über
// ALLE Ringe aller Polygone. Unter 4 verwertbaren Ringpunkten, bei
// nicht-endlichen Werten oder Fläche 0 -> null. Planare Näherung,
// Antimeridian ungenau (kein Registry-Land betroffen).
export function computeCentroid(geometry) {
  let geom = geometry;
  if (
    geom &&
    typeof geom === "object" &&
    geom.type !== "Polygon" &&
    geom.type !== "MultiPolygon" &&
    geom.geometry &&
    typeof geom.geometry === "object"
  ) {
    geom = geom.geometry; // Feature-Envelope
  }
  if (!geom || typeof geom !== "object" || !Array.isArray(geom.coordinates)) return null;
  const rings = [];
  if (geom.type === "Polygon") {
    if (Array.isArray(geom.coordinates[0])) rings.push(geom.coordinates[0]);
  } else if (geom.type === "MultiPolygon") {
    for (const polygon of geom.coordinates) {
      if (!Array.isArray(polygon)) continue;
      for (const ring of polygon) {
        if (Array.isArray(ring)) rings.push(ring);
      }
    }
  } else {
    return null;
  }
  let best = null;
  for (const ring of rings) {
    const m = ringCentroid(ring);
    if (m === null) continue;
    if (best === null || m.area > best.area) best = m;
  }
  if (best === null) return null;
  const lat = clampNum(best.lat, -90, 90);
  const lng = clampNum(best.lng, -180, 180);
  if (!Number.isFinite(lat) || !Number.isFinite(lng)) return null;
  return [lat, lng]; // GETAUSCHT: [lat, lng] trotz [lng, lat]-Eingabe
}

// ---------- (3) Länder-Index ----------

// indexCountryFeatures(geojson) — Eingabe: GeoJSON-FeatureCollection
// (im Browser die Ausgabe von topojson.feature(topo, topo.objects.
// countries)) ODER ein Feature-Array. Rückgabe { count, byName } mit
// Key = trim().normalize('NFKC').toLowerCase() von properties.name.
// CountryInfo = { name (properties.name UNVERÄNDERT, englisch),
// centroid: [lat,lng]|null, feature }. Nur Features mit nicht-leerem
// properties.name und Geometry Polygon/MultiPolygon; bei Namens-
// Duplikaten gewinnt das ERSTE Feature (Natural Earth liefert pro Land
// ein Feature). count = Anzahl aufgenommener Features.
export function indexCountryFeatures(geojson) {
  let features = [];
  if (Array.isArray(geojson)) {
    features = geojson;
  } else if (geojson && typeof geojson === "object" && Array.isArray(geojson.features)) {
    features = geojson.features;
  }
  const byName = new Map();
  let count = 0;
  for (const feature of features) {
    if (!feature || typeof feature !== "object") continue;
    const props = feature.properties;
    if (!props || typeof props !== "object") continue;
    const name = trimTo(props.name);
    if (name === "") continue;
    const geometry = feature.geometry;
    if (
      !geometry ||
      typeof geometry !== "object" ||
      (geometry.type !== "Polygon" && geometry.type !== "MultiPolygon")
    ) {
      continue;
    }
    const key = normalizeCountryKey(name);
    if (key === "" || byName.has(key)) continue;
    byName.set(key, { name, centroid: computeCentroid(geometry), feature });
    count += 1;
  }
  return { count, byName };
}

// ---------- (4) Länder-Matching ----------

// matchCountry(countryName, countryIndex) — countryIndex: Rückgabe von
// indexCountryFeatures. Auflösung: (a) exakter normalisierter Match,
// (b) COUNTRY_ALIASES -> kanonischer GeoJSON-Name. Rückgabe bei Treffer:
// { name: kanonischer GeoJSON-Name, centroid: [lat,lng]|null (degenerierte
// Geometrie kann trotzdem null sein), noPolygon: false }; sonst
// { name: null, centroid: null, noPolygon: true }.
export function matchCountry(countryName, countryIndex) {
  const byName =
    countryIndex && countryIndex.byName instanceof Map ? countryIndex.byName : new Map();
  const key = normalizeCountryKey(countryName);
  if (key !== "") {
    const info = byName.get(key);
    if (info) return { name: info.name, centroid: info.centroid, noPolygon: false };
    const alias = COUNTRY_ALIASES[key];
    if (alias) {
      const aliased = byName.get(normalizeCountryKey(alias));
      if (aliased) return { name: aliased.name, centroid: aliased.centroid, noPolygon: false };
    }
  }
  return { name: null, centroid: null, noPolygon: true };
}

// ---------- (5) Aggregation ----------

// aggregateCountryFlows({ nodes, edges, registry, countryIndex })
//   nodes: Cluster-Graph-Nodes [{ id, role, severity, inDrops, outDrops,
//          clusterId }], edges: [{ from, to, type, closeTime, ledgerSeq }].
//   registry: parseExchangeRegistry-Ergebnis, countryIndex:
//          indexCountryFeatures-Ergebnis (beide optional/defensiv).
// Rückgabe AttributionResult:
//   assignedByAddress: Map<getrimmte Adresse, AssignedInfo> — NUR Registry-
//       Adressen; AssignedInfo = { country: GeoJSON-Name|null, countryRaw,
//       exchange, kind, confidence, centroid: [lat,lng]|null, noPolygon }.
//   countries: CountryActivity[] — activity = ANZAHL attribuierter Nodes
//       des Landes (nur activity > 0), Sortierung activity desc, name asc:
//       { name, centroid, activity, severities {malicious,suspect,info},
//       worstSeverity, exchanges (unique, sortiert, nur nicht-leere) }.
//   flows: CountryFlow[] — Aggregat je (fromCountry, toCountry)-Paar;
//       Sortierung count desc, fromCountry asc, toCountry asc (null vor
//       Namen): { fromCountry: string|null, toCountry: string|null, count,
//       severities, worstSeverity, exchanges }. NULL-SEITIGE FLOWS
//       (null -> Land, Land -> null) sind ZÄHLDATEN (Off-Ramp-Statistik):
//       sie haben per Definition keinen darstellbaren Bogen auf der
//       null-Seite; ihre Kanten werden vom Consumer als Per-Edge-Bögen
//       gerendert, die count-Werte fließen als Zufluss-/Abfluss-Summen in
//       die Länderpunkt-Labels. GLEICHLÄNDRIGE Kanten (fromCountry ===
//       toCountry !== null, Börse->Börse desselben Landes) werden NICHT
//       in flows[] aufgenommen und zählen auch nicht zu unassigned.edges:
//       Sie sind kein grenzüberschreitender Fluss — der Consumer zeichnet
//       sie weder als Land-zu-Land-Bogen (start==end) noch als Per-Edge-
//       Kante (beide Endpunkte am Centroid), ein Mitzählen als Zufluss
//       UND Abfluss hätte einen Fluss von außen behauptet, der nicht
//       existiert (Befund 2026-09-30).
//   unassigned: { addresses: Anzahl Nodes ohne assignedByAddress-Eintrag,
//       edges: Anzahl Kanten ohne attribuierten Endpunkt mit gematchtem
//       Land }.
// Kanten-Semantik: Endpunkt attribuiert = registry.byAddress.has(getrimmte
// Node-id); Kanten-Severity = max der Node-Severities beider Endpunkte
// (fehlender/unbekannter Knoten -> 'info'); eine Kante geht in flows[],
// wenn MINDESTENS ein Endpunkt attribuiert ist UND einen nicht-null
// gematchten Ländernamen hat — sonst zählt sie in unassigned.edges.
// Invariante: jeder nicht-null Ländername in flows[] kommt auch in
// countries[] vor; countries[] und flows[] enthalten KEINE Adressen.
// Effizienz: ausschließlich Map-/Set-Lookups, O(nodes + edges) — kein
// O(n²)-Scan (taugt für Tausende Adressen je Refresh).
export function aggregateCountryFlows(input) {
  const src = input && typeof input === "object" ? input : {};
  const nodes = Array.isArray(src.nodes) ? src.nodes : [];
  const edges = Array.isArray(src.edges) ? src.edges : [];
  const byAddress =
    src.registry && src.registry.byAddress instanceof Map ? src.registry.byAddress : new Map();
  const countryIndex =
    src.countryIndex && src.countryIndex.byName instanceof Map ? src.countryIndex : { byName: new Map() };

  // Knoten nach getrimmter id indexieren (erster gewinnt).
  const nodeById = new Map();
  const validNodes = [];
  for (const node of nodes) {
    if (!node || typeof node !== "object") continue;
    validNodes.push(node);
    const id = trimTo(node.id);
    if (id !== "" && !nodeById.has(id)) nodeById.set(id, node);
  }

  // Zuordnung + Länder-Aggregation aus attribuierten NODES.
  const assignedByAddress = new Map();
  const countryAcc = new Map();
  for (const node of validNodes) {
    const id = trimTo(node.id);
    const entry = id === "" ? undefined : byAddress.get(id);
    if (!entry) continue;
    const match = matchCountry(entry.country, countryIndex);
    assignedByAddress.set(id, {
      country: match.name,
      countryRaw: entry.country,
      exchange: entry.exchange,
      kind: entry.kind,
      confidence: entry.confidence,
      centroid: match.centroid,
      noPolygon: match.noPolygon,
    });
    if (match.name === null) continue;
    let acc = countryAcc.get(match.name);
    if (!acc) {
      acc = {
        name: match.name,
        centroid: match.centroid,
        activity: 0,
        severities: { malicious: 0, suspect: 0, info: 0 },
        exchanges: new Set(),
      };
      countryAcc.set(match.name, acc);
    }
    if (acc.centroid === null && match.centroid !== null) acc.centroid = match.centroid;
    acc.activity += 1;
    acc.severities[nodeSeverity(node)] += 1;
    if (entry.exchange !== "") acc.exchanges.add(entry.exchange);
  }

  // Fluss-Aggregation über Kanten (Map-Lookups je Endpunkt).
  const flowAcc = new Map();
  let unassignedEdges = 0;
  for (const edge of edges) {
    if (!edge || typeof edge !== "object") continue;
    const fromKey = trimTo(edge.from);
    const toKey = trimTo(edge.to);
    const fromInfo = fromKey === "" ? undefined : assignedByAddress.get(fromKey);
    const toInfo = toKey === "" ? undefined : assignedByAddress.get(toKey);
    const fromCountry = fromInfo ? fromInfo.country : null;
    const toCountry = toInfo ? toInfo.country : null;
    // INTRA-LAND-KANTEN (beide Endpunkte im SELBEN gematchten Land): kein
    // grenzüberschreitender Fluss — überspringen. Die Endpunkte sind
    // zugeordnet, daher zählt die Kante bewusst auch NICHT zu
    // unassigned.edges; sie bleibt nur auf der Node-Ebene (Cluster-Graph)
    // sichtbar, nicht in den Länder-Flüssen (Befund 2026-09-30: zuvor
    // blähte sie sowohl Zufluss- als auch Abfluss-Zähler des Landes auf,
    // obwohl nichts von außen floss).
    if (fromCountry !== null && fromCountry === toCountry) continue;
    const qualifies =
      (fromInfo !== undefined && fromCountry !== null) ||
      (toInfo !== undefined && toCountry !== null);
    if (!qualifies) {
      unassignedEdges += 1;
      continue;
    }
    const fromNode = fromKey === "" ? undefined : nodeById.get(fromKey);
    const toNode = toKey === "" ? undefined : nodeById.get(toKey);
    const severity = maxSeverity(nodeSeverity(fromNode), nodeSeverity(toNode));
    const key = `${fromCountry === null ? "\u0000" : fromCountry}\u0001${
      toCountry === null ? "\u0000" : toCountry
    }`;
    let acc = flowAcc.get(key);
    if (!acc) {
      acc = {
        fromCountry,
        toCountry,
        count: 0,
        severities: { malicious: 0, suspect: 0, info: 0 },
        exchanges: new Set(),
      };
      flowAcc.set(key, acc);
    }
    acc.count += 1;
    acc.severities[severity] += 1;
    if (fromInfo !== undefined && fromInfo.exchange !== "") acc.exchanges.add(fromInfo.exchange);
    if (toInfo !== undefined && toInfo.exchange !== "") acc.exchanges.add(toInfo.exchange);
  }

  // unassigned.addresses: Nodes ohne assignedByAddress-Eintrag.
  let unassignedAddresses = 0;
  for (const node of validNodes) {
    const id = trimTo(node.id);
    if (id === "" || !assignedByAddress.has(id)) unassignedAddresses += 1;
  }

  const countries = [...countryAcc.values()]
    .map((acc) => ({
      name: acc.name,
      centroid: acc.centroid,
      activity: acc.activity,
      severities: acc.severities,
      worstSeverity: worstSeverityOf(acc.severities),
      exchanges: sortedExchanges(acc.exchanges),
    }))
    .sort((a, b) => b.activity - a.activity || compareCountryAsc(a.name, b.name));

  const flows = [...flowAcc.values()]
    .map((acc) => ({
      fromCountry: acc.fromCountry,
      toCountry: acc.toCountry,
      count: acc.count,
      severities: acc.severities,
      worstSeverity: worstSeverityOf(acc.severities),
      exchanges: sortedExchanges(acc.exchanges),
    }))
    .sort(
      (a, b) =>
        b.count - a.count ||
        compareCountryAsc(a.fromCountry, b.fromCountry) ||
        compareCountryAsc(a.toCountry, b.toCountry)
    );

  return {
    assignedByAddress,
    countries,
    flows,
    unassigned: { addresses: unassignedAddresses, edges: unassignedEdges },
  };
}
