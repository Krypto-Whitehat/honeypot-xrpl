// lib/validator-sensitivity.mjs — Signatur-Empfindlichkeit: auf welchen Ledger-Signaturen
// faellt DIESER Knoten überproportional zurück, und tun die anderen Knoten dasselbe?
//
// Die Risikalebene (lib/validator-retrace.mjs) beantwortet "wie oft fällt ein Ledger mit
// dieser Anomalie überhaupt aus" - über alle Knoten zusammen. Das ist die Netzlage. Ein
// Betreiber braucht die andere Zahl, und die liefert bisher kein Werkzeug:
//   gilt das für MEINEN Knoten - und gilt es für die Kohorte auch?
// Erst diese Trennung entscheidet, ob ein verpasster Ledger ein Kapazitäts- oder
// Parser-Problem im eigenen Knoten ist, eine Netzstockung, oder Last, die gezielt auf eine
// Transaktionsform gelegt wurde (Drainer-Fächer, Orderbuch-Flut, Typ-Sturm, Batch-Verstärkung).
//
// 2x2-Tafel je (Knoten, Signatur):
//   ausgefallen auf Ledern MIT Signatur    |  ausgefallen auf Ledern OHNE Signatur
//   ausgefallen auf Ledern MIT ...         |  ...
// Rate mit / Rate ohne = Lift. Dazu die Kohorten-Gegenprobe: derselbe Lift, für jeden anderen
// Knoten desselben Fensters gemessen. Hoher Lift nur bei dir = Knotenproblem. Hoher Lift bei
// allen = Netzlage. Lift ~ 1 = diese Signatur erklärt deine Ausfälle nicht, und die
// Angriffs-Hypothese ist für diesen Knoten entlastet.
//
// Zähler und Nenner kommen aus zwei echten, verschiedenen Messungen des Recorders:
//   Nenner  d.anomaly[tag]  - JEDES Ledger mit dieser Signatur, auch die ohne jeden Ausfall
//   Zähler  incidents[].r   - die Ledger-Tags, die zum Zeitpunkt des Vorfalls aufgezeichnet
//                             wurden. Sie stehen unabhängig vom Forensik-Deckel (LEDGER_STATS_CAP)
//                             in der Tagesdatei: die Tafel ist deshalb nicht durch die
//                             Forensik-Kürzung verzerrt.
// Schwellen sind TUNING-DEFAULTS ohne Kampagnen-Nachweis, explizit ausgewiesen.
import { ANOMALY_TAGS, anomalyLayer } from "./validator-trace.mjs";
import { SIGNATURE_TAGS } from "./tx-forensics.mjs";
import { erfc } from "./validator-peer-benchmark.mjs";

export const SENSITIVITY_DEFAULTS = {
  minExposure: 25,        // Ledger mit dieser Signatur im Fenster - darunter kein Urteil
  minFails: 3,            // eigene Ausfälle auf Ledern mit dieser Signatur
  minPlainLedgers: 100,   // Nenner ohne diese Signatur
  specificLift: 2,        // ab hier koppelt die Signatur an deinen Knoten
  blindLift: 1.25,        // bis hier erklärt die Signatur deine Ausfälle nicht
  peerRatio: 1.5,         // dein Lift muss den Kohorten-Lift um dieses Maß übertreffen
  significantZ: 2,        // Zwei-Stichproben-z ab hier getrennt
  minPeers: 3,            // Kohorten-Urteil ab so vielen anderen Knoten mit Urteil
  topTags: 14,
};

export const SENSITIVITY_VERDICTS = ["signature-specific", "signature-network", "signature-blind", "no-link", "thin-sample", "no-exposure"];
export const SENSITIVITY_GAPS = ["anomaly-counts", "incident-tags", "day-span", "own-fails", "peer-baseline"];
export const SENSITIVITY_HEADLINES = ["attack-shaped", "capacity-shaped", "stall-shaped", "shape-blind", "mixed", "thin"];
export const SENSITIVITY_FAMILIES = ["attack", "capacity", "stall", "consensus"];

// Signatur -> Prüf-Familie. Ein Betreiber prüft je Familie etwas anderes: Lastdeckel, Peering,
// Version/Amendment oder die Angriffs-Ledger selbst.
const FAMILY_OF = {
  "load-spike": "capacity", "load-extreme": "capacity",
  "close-gap": "stall",
  "no-quorum": "consensus", "vote-not-observed": "consensus", "hash-split": "consensus", "amendment-activity": "consensus", "unl-change": "consensus",
};
const CHECKS_BY_FAMILY = {
  attack: ["cause-check-attack-ledger"],
  capacity: ["cause-check-load-ceiling", "cause-check-resources"],
  stall: ["cause-check-network-stall"],
  consensus: ["cause-check-version", "cause-check-quorum-settings"],
};

export function familyOf(tag) {
  const t = String(tag);
  if (FAMILY_OF[t]) return FAMILY_OF[t];
  if (t.startsWith("type-burst:") || t.startsWith("new-tx-type:")) return "attack";
  if (SIGNATURE_TAGS.has(t)) return "attack";
  return null;
}

export const isAnomalyTag = (tag) => {
  const t = String(tag);
  return ANOMALY_TAGS.has(t) || t.startsWith("new-tx-type:") || t.startsWith("type-burst:");
};

const SPAN = { "1h": 3600000, "24h": 86400000, "7d": 7 * 86400000, "30d": 30 * 86400000, all: Infinity };
const num = (x) => (Number.isFinite(Number(x)) ? Number(x) : 0);
const round = (x, d = 4) => (Number.isFinite(x) ? Math.round(x * 10 ** d) / 10 ** d : null);

function windowOf(range, now) {
  const ms = SPAN[range] ?? SPAN["24h"];
  return { from: ms === Infinity ? 0 : now - ms, to: now + 1 };
}

// Anteil eines Tages am Fenster. Ohne Tagesspanne (firstMs/lastMs) lässt sich der Tag nicht
// einordnen: er wird NICHT geschätzt, sondern als Lücke ausgewiesen.
function spanOf(v) {
  if (v === null || v === undefined || v === "") return NaN;
  const n = Number(v);
  return Number.isFinite(n) ? n : NaN;
}

function dayFraction(d, w) {
  // null ist keine Zeit: Number(null) ist 0, und 0 als Spanne hiesse "ganztags im Fenster".
  const from = spanOf(d.firstMs), to = spanOf(d.lastMs);
  if (!Number.isFinite(from) || !Number.isFinite(to)) return { frac: 0, known: false };
  const overlap = Math.min(to, w.to) - Math.max(from, w.from);
  if (overlap <= 0) return { frac: 0, known: true }; // ausserhalb des Fensters: kein Anteil
  const span = to - from;
  if (span <= 0) return { frac: 1, known: true }; // Augenblicks-Tag innerhalb des Fensters
  return { frac: Math.max(0, Math.min(1, overlap / span)), known: true };
}

// Zwei-Stichproben-z auf gepoolter Varianz. p zweiseitig über erfc (Chebyshev-Annaeherung,
// Gegenprobe gegen numerische Integration, siehe validator-peer-benchmark.mjs). Naeherung,
// keine exakte Testgröße.
export function twoProportion(x1, n1, x2, n2) {
  if (!(n1 > 0) || !(n2 > 0)) return { z: null, p: null };
  const p1 = x1 / n1, p2 = x2 / n2;
  const pooled = (x1 + x2) / (n1 + n2);
  const sd = Math.sqrt(pooled * (1 - pooled) * (1 / n1 + 1 / n2));
  if (!(sd > 0)) return { z: null, p: null };
  const z = (p1 - p2) / sd;
  // zweiseitig: p = 2 * (1 - Phi(|z|)) = erfc(|z|/sqrt(2)). Die halbe Flaeche waere einseitig
  // und haette bei z = 2 p = 0,0228 statt 0,0455 ausgewiesen - die Schwelle significantZ = 2 ist
  // aber die zweiseitige 5-%-Schwelle, also muss auch p zweiseitig sein.
  return { z: round(z, 3), p: round(erfc(Math.abs(z) / Math.SQRT2), 6) };
}

function median(values) {
  const a = values.filter((x) => Number.isFinite(x)).sort((x, y) => x - y);
  if (!a.length) return null;
  const m = Math.floor(a.length / 2);
  return a.length % 2 ? a[m] : (a[m - 1] + a[m]) / 2;
}

// Nenner (Signatur-Exposition) und Zähler (Ausfälle je Knoten und Signatur) aus denselben
// Tagesobjekten. Ein Ledger zählt je Knoten und Signatur genau einmal, auch wenn mehrere
// Vorfallstypen auf ihm lagen.
function collect(days, w) {
  const exposure = new Map();
  const nodes = new Map();
  let ledgers = 0, estimated = false, daysWithoutAnomaly = 0, daysWithoutSpan = 0, anomalyDays = 0;
  for (const d of Array.isArray(days) ? days : []) {
    const { frac, known } = dayFraction(d, w);
    if (!known) { daysWithoutSpan += 1; continue; } // ohne Tagesspanne keine Einordnung: Luecke, nicht Stille
    if (frac <= 0) continue;
    // Messbasis: nur Tage mit Signatur-Ebene. Ohne d.anomaly existiert keine Exposition -
    // die Ausfaelle eines solchen Tages in die Tafel zu nehmen, ergaebe eine Rate ohne Nenner.
    // Dieselbe Regel wie riskProfile: eine Vergleichsgruppe aus ungeprueften Ledern misst gegen
    // sich selbst, nicht gegen Ledger ohne diese Signatur.
    const anomaly = anomalyLayer(d);
    if (!anomaly) { daysWithoutAnomaly += 1; continue; }
    if (frac < 1) estimated = true;
    ledgers += num(d.ledgers) * frac;
    anomalyDays += 1;
    for (const [tag, n] of Object.entries(anomaly)) {
      if (!isAnomalyTag(tag) || familyOf(tag) === null) continue;
      const v = num(n) * frac;
      if (v <= 0) continue;
      exposure.set(tag, (exposure.get(tag) ?? 0) + v);
    }
    for (const inc of d.incidents ?? []) {
      if (!inc || !inc.m || !Number.isFinite(inc.t) || inc.t < w.from || inc.t > w.to) continue;
      const node = nodes.get(inc.m) ?? { ledgers: new Set(), byTag: new Map(), incidents: 0, tagged: 0, untagged: 0 };
      node.incidents += 1;
      node.ledgers.add(inc.l);
      const tags = new Set((inc.r ?? []).filter((t) => isAnomalyTag(t) && familyOf(t) !== null));
      if (!tags.size) node.untagged += 1;
      else node.tagged += 1;
      for (const tag of tags) {
        const set = node.byTag.get(tag) ?? new Set();
        set.add(inc.l);
        node.byTag.set(tag, set);
      }
      nodes.set(inc.m, node);
    }
  }
  return { exposure, nodes, ledgers, estimated, daysWithoutAnomaly, daysWithoutSpan, anomalyDays };
}

// Rate mit Signatur gegen Rate ohne Signatur, je Knoten. tag = Signatur, exposure = Zahl der
// Ledger dieses Fensters mit dieser Signatur. Beides getrennt zu uebergeben ist kein Formalismus:
// ein Tag als Zahl macht den Nenner zu NaN, und eine Rate ohne Nenner ist keine Rate.
function ratesOf(node, tag, exposure, totalLedgers) {
  const fails = node.byTag.get(tag)?.size ?? 0;
  const ownAll = node.ledgers.size;
  const plainFails = Math.max(0, ownAll - fails);
  const plainLedgers = Math.max(0, totalLedgers - exposure);
  const rateWith = exposure > 0 ? fails / exposure : null;
  const rateWithout = plainLedgers > 0 ? plainFails / plainLedgers : null;
  const lift = rateWith !== null && rateWithout !== null && rateWithout > 0 ? rateWith / rateWithout : null;
  return { fails, ownAll, plainFails, plainLedgers, rateWith, rateWithout, lift };
}

/**
 * Signatur-Empfindlichkeit eines Knotens gegen die Kohorte desselben Fensters.
 * days: dieselben Tagesobjekte wie in validator-trace-query.mjs.
 */
export function signatureSensitivity(days, master, { range = "24h", now = Date.now(), ...rest } = {}) {
  const p = { ...SENSITIVITY_DEFAULTS, ...rest };
  const w = windowOf(range, now);
  const c = collect(days, w);
  const own = c.nodes.get(master) ?? { ledgers: new Set(), byTag: new Map(), incidents: 0, tagged: 0, untagged: 0 };
  const gaps = new Set();
  if (!c.anomalyDays) gaps.add("anomaly-counts");
  if (c.daysWithoutAnomaly) gaps.add("anomaly-counts");
  if (c.daysWithoutSpan) gaps.add("day-span");
  if (own.incidents && !own.tagged) gaps.add("incident-tags");
  if (!own.ledgers.size) gaps.add("own-fails");

  const tags = [...new Set([...c.exposure.keys(), ...own.byTag.keys()])];
  const rows = [];
  for (const tag of tags) {
    const exposure = c.exposure.get(tag) ?? 0;
    const ownR = ratesOf(own, tag, exposure, c.ledgers);
    // Kohorte: derselbe Lift für jeden anderen Knoten mit eigenem Urteil in diesem Fenster.
    const peers = [];
    for (const [m, node] of c.nodes) {
      if (m === master || !node.ledgers.size) continue;
      const r = ratesOf(node, tag, exposure, c.ledgers);
      if (exposure < p.minExposure || r.fails < p.minFails || r.plainLedgers < p.minPlainLedgers) continue;
      if (r.lift === null) continue;
      peers.push(r.lift);
    }
    const cohortLift = peers.length >= p.minPeers ? median(peers) : null;
    const { z, p: pValue } = twoProportion(ownR.fails, exposure, ownR.plainFails, ownR.plainLedgers);
    const measurable = exposure >= p.minExposure && ownR.fails >= p.minFails && ownR.plainLedgers >= p.minPlainLedgers && ownR.lift !== null;
    let verdict;
    if (exposure <= 0) verdict = "no-exposure";
    else if (!measurable) verdict = "thin-sample";
    else if (ownR.lift <= p.blindLift) verdict = "signature-blind";
    else if (ownR.lift >= p.specificLift) {
      const aboveCohort = cohortLift === null || ownR.lift >= (cohortLift > 0 ? cohortLift * p.peerRatio : p.specificLift);
      verdict = aboveCohort ? "signature-specific" : "signature-network";
    } else verdict = "no-link";
    const family = familyOf(tag);
    rows.push({
      tag, family,
      exposure: round(exposure, 1), exposureLedgers: Math.round(exposure),
      fails: ownR.fails, ownFailLedgers: ownR.ownAll,
      plainLedgers: Math.round(ownR.plainLedgers), plainFails: ownR.plainFails,
      // Raten auf 6 Stellen: 0,00625 auf 4 Stellen zu 0,0063 ist ein Rundungsfehler von 0,8 %
      // auf einer Rate, die gerade klein ist - und kleine Raten sind der eigentliche Befund.
      rateWith: round(ownR.rateWith, 6), rateWithout: round(ownR.rateWithout, 6), lift: round(ownR.lift, 2),
      z, pValue, significant: z !== null && Math.abs(z) >= p.significantZ,
      cohortLift: round(cohortLift, 2), cohortPeers: peers.length,
      verdict, measurable,
      nextChecks: verdict === "signature-specific" ? (CHECKS_BY_FAMILY[family] ?? [])
        : verdict === "signature-blind" ? ["cause-check-uptime"] : [],
    });
  }
  rows.sort((a, b) => (Number(b.measurable) - Number(a.measurable))
    || (Number(b.verdict === "signature-specific") - Number(a.verdict === "signature-specific"))
    || ((b.lift ?? 0) - (a.lift ?? 0))
    || a.tag.localeCompare(b.tag));

  const specific = rows.filter((r) => r.verdict === "signature-specific");
  const byFamily = {};
  for (const f of SENSITIVITY_FAMILIES) {
    const inFamily = rows.filter((r) => r.family === f);
    byFamily[f] = {
      family: f, tags: inFamily.length,
      specific: inFamily.filter((r) => r.verdict === "signature-specific").length,
      network: inFamily.filter((r) => r.verdict === "signature-network").length,
      blind: inFamily.filter((r) => r.verdict === "signature-blind").length,
    };
  }
  const families = SENSITIVITY_FAMILIES.filter((f) => byFamily[f].tags > 0).map((f) => byFamily[f]);
  const specificFamilies = [...new Set(specific.map((r) => r.family))];
  let headline = "thin";
  if (specific.length && specificFamilies.length >= 2) headline = "mixed";
  else if (specific.some((r) => r.family === "attack")) headline = "attack-shaped";
  else if (specific.some((r) => r.family === "capacity")) headline = "capacity-shaped";
  else if (specific.some((r) => r.family === "stall")) headline = "stall-shaped";
  else if (rows.some((r) => r.verdict === "signature-blind") && !rows.some((r) => r.verdict === "signature-network")) headline = "shape-blind";

  return {
    master, range,
    authority: c.anomalyDays ? "trace" : "none",
    coverage: {
      ledgers: Math.round(c.ledgers), estimated: c.estimated,
      daysWithAnomaly: c.anomalyDays, daysWithoutAnomaly: c.daysWithoutAnomaly, daysWithoutSpan: c.daysWithoutSpan,
      incidents: own.incidents, incidentsTagged: own.tagged, incidentsUntagged: own.untagged,
      ownFailLedgers: own.ledgers.size, peers: c.nodes.size - 1,
    },
    gaps: [...gaps],
    rows: rows.slice(0, p.topTags),
    families,
    headline: { verdict: headline, tags: specific.map((r) => r.tag) },
    thresholds: { minExposure: p.minExposure, minFails: p.minFails, minPlainLedgers: p.minPlainLedgers, specificLift: p.specificLift, blindLift: p.blindLift, peerRatio: p.peerRatio, significantZ: p.significantZ, minPeers: p.minPeers },
    method: "2x2-Tafel je Signatur: eigene Ausfallrate auf Ledern mit Signatur gegen eigene Ausfallrate auf Ledern ohne sie; Kohorten-Lift = Median desselben Maßes über alle anderen Knoten desselben Fensters; z/p Zwei-Stichproben-test (Normalnaeherung, approximativ).",
  };
}

// Netz-Ebene: welche Signaturen koppeln im selben Fenster an WIE VIELE Knoten? Das ist die
// Antwort auf "gibt es eine Signatur, die gerade den ganzen dUNL trifft" - die Vorstufe einer
// DDoS- oder Zero-Day-Beobachtung, bevor ein einzelner Knoten sie meldet.
export function signatureCohort(days, { range = "24h", now = Date.now(), ...rest } = {}) {
  const p = { ...SENSITIVITY_DEFAULTS, ...rest };
  const w = windowOf(range, now);
  const c = collect(days, w);
  const out = [];
  for (const [tag, exposure] of c.exposure) {
    const lifts = [];
    const sensitive = [];
    for (const [m, node] of c.nodes) {
      if (!node.ledgers.size) continue;
      const r = ratesOf(node, tag, exposure, c.ledgers);
      if (exposure < p.minExposure || r.plainLedgers < p.minPlainLedgers || r.lift === null) continue;
      lifts.push(r.lift);
      if (r.fails >= p.minFails && r.lift >= p.specificLift) sensitive.push(m);
    }
    out.push({
      tag, family: familyOf(tag), exposure: Math.round(exposure),
      measuredNodes: lifts.length, sensitiveNodes: sensitive.length,
      medianLift: round(median(lifts), 2), maxLift: round(lifts.length ? Math.max(...lifts) : null, 2),
      shared: sensitive.length >= p.minPeers && sensitive.length >= Math.max(1, Math.ceil(lifts.length * 0.34)),
    });
  }
  out.sort((a, b) => (Number(b.shared) - Number(a.shared)) || (b.sensitiveNodes - a.sensitiveNodes) || ((b.medianLift ?? 0) - (a.medianLift ?? 0)) || a.tag.localeCompare(b.tag));
  return { range, coverage: { ledgers: Math.round(c.ledgers), nodes: c.nodes.size, estimated: c.estimated, daysWithAnomaly: c.anomalyDays, daysWithoutAnomaly: c.daysWithoutAnomaly }, rows: out.slice(0, p.topTags) };
}
