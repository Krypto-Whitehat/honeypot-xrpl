// lib/validator-vote-latency.mjs — Timing eines dUNL-Knotens: zu spaet abgestimmt, oder nie?
//
// Die Klassifizierung (missed / partial / no-quorum / wrong-hash) beantwortet, WELCHEN Fehler ein
// Knoten hatte. Sie beantwortet nicht, ob der Knoten ueberhaupt abgestimmt hat - nur zu spaet -
// oder ob er gar nicht abgestimmt hat. Das ist ein anderer Befund mit einer anderen naechsten
// Pruefung: zu spaet ist ein Pfad-/Ressourcenproblem, nie ist ein Ausfallproblem.
//
// Drei Messungen, drei verschiedene Aussagen:
//  1) Spaet-Validierungen (d.lateVotes): der Vote traf nach der Bewertung dieses Ledgers ein.
//     Das ist der einzige Beleg dafuer, dass ein "missed" ein Zeitproblem war.
//  2) Incident-Latenz (d.incidents[].vd): Latenz des eigenen Votes, wo es einen gab.
//  3) Netz-Latenz (d.ledgerStats[].fv und d.hourly[].fvN/fvS/fvX/fvL): wann das NETZ seinen
//     ersten Vote hatte. Ohne diese Referenz ist "mein Vote war spaet" eine Zahl ohne Vergleich.
//
// Ehrliche Grenzen, alle ausgewiesen, nie verschluckt:
//  - Die Spaet-Validierung ist juenger als der Altbestand. Ein Tag ohne lateVotes-Feld
//    beantwortet die Frage nicht: "nicht erfasst" ist nicht "keine Spaetvalidierung".
//  - Der Recorder haelt nur die letzten LATE_RING_LEDGERS bewerteten Ledger offen. Ein Vote, der
//    erst danach eintrifft, ist nicht mehr erfassbar - "nie" gilt nur innerhalb dieses Rings.
//  - d.lateVotesTruncated zeigt, dass die Liste im Tag gekuerzt wurde (aelteste verworfen).
//  - 'no-quorum' und 'vote-not-observed' sind keine Knotenlatenz: dort ist Nicht-Abstimmen kein
//    Fehler dieses Knotens (lib/validator-trace.mjs waehlt den Typ genau deshalb). Diese Vorfaelle
//    werden getrennt gefuehrt, damit die Knotenlatenz nicht damit verwassert wird.
//  - Was an ihrer Stelle steht, ist eine Schliess-Frage, keine Latenz-Frage, und sie wird nur
//    beantwortet, wofuer dieser Mithoerer einen Beleg hat: ein Ledger mit aufgezeichnetem
//    Close-Hash ('ch') ist bewiesen geschlossen, also ist das fehlende Sehen eine Erfassungs-Luecke
//    DIESES Recorders. Ohne Close-Beleg bleibt die Frage offen. 'Netzstockung' waere eine
//    Behauptung ueber das Netz, die dieser Rekorder nie belegen kann - er wertet ausschliesslich
//    Ledger aus dem validierten Strom aus (lib/validator-trace.mjs: evaluate() sieht nur Ledger,
//    die onLedger aus diesem Strom erhalten hat).

import { measured, TRACE_DEFAULTS } from "./validator-trace.mjs";
import { quantile } from "./validator-peer-benchmark.mjs";

// Kein eigener Schwellwert dieses Moduls: graceMs ist der Wert, nach dem der Recorder bewertet.
// "zu spaet" kann nichts anderes bedeuten als "nach dieser Bewertung" - zwei unabhaengige Zahlen
// an derselben Stelle waeren ein Definitionsstreit, keine Messung.
export const LATE_GRACE_MS = TRACE_DEFAULTS.graceMs;
export const LATE_RING_LEDGERS = TRACE_DEFAULTS.lateRingSize;

export const LATENCY_MIN_INCIDENTS = 5;        // unterhalb dieser Vorfallszahl kein Urteil
export const LATENCY_MIN_NETWORK_LEDGERS = 10; // unterhalb dieser Netzstichprobe kein Vergleich
export const LATENCY_NETWORK_SLOW_SHARE = 0.5; // ab dieser Anteil-Haelfte ist das Netz selbst spaet
export const LATENCY_OFFSET_TIGHT_MS = 2500;   // Streuung der Netz-Distanz unter diesem Wert = konstanter Versatz

// Die Klassen sind zugleich die Ausgabefelder und die i18n-Schluessel (vt.lat.class.*): ein
// dritter Name an derselben Stelle ist der Ort, an dem UI und Engine auseinanderlaufen.
export const LATENCY_CLASSES = ["late", "never", "inWindow", "unknown"];
export const LATENCY_VERDICTS = [
  "no-deviations", "capture-only", "closure-unproven", "partially-proven", "not-recorded",
  "insufficient-sample", "never-signed",
  "node-side-late", "network-side", "mixed", "latency-not-the-cause",
];
export const LATENCY_AUTHORITIES = ["trace-late-votes", "trace-incident-delay", "trace-network-latency", "trace-closure-proof", "none"];
export const LATENCY_REASONS = [
  "no-incidents-in-window", "no-node-attributable-failure", "capture-gap-on-closed-ledgers",
  "closure-proof-partial", "late-vote-recording-missing", "no-measurable-own-vote",
  "below-minimum-incidents", "never-voted-dominant", "late-and-never-mixed",
  "own-vote-inside-grace", "network-first-vote-late",
  "late-vote-dominant-network-fast", "late-vote-dominant-no-network-reference",
];
export const LATENCY_PATTERNS = ["consistent-offset", "variable-delay", "no-delay-data"];

const NODE_TYPES = new Set(["missed", "partial", "wrong-hash"]);
const SPAN = { "1h": 3600000, "24h": 86400000, "7d": 7 * 86400000, "30d": 30 * 86400000, all: Infinity };
const HOUR_MS = 3600000;
// num ist der Null-Vertrag: ein Incident ohne vd fuehrt zu "kein Vote gemessen", nicht zu 0 ms.
const num = measured;
const round = (x, d = 0) => (Number.isFinite(x) ? Math.round(x * 10 ** d) / 10 ** d : null);

// SCHLIESS-BELEG je Ledger, ausschliesslich aus denselben Zeilen, die der Recorder schreibt:
// 'ch' ist der Hash, den das Netz fuer diesen Index gewaehlt hat, 'cl === false' ist die einzige
// Stelle, die eine Schliessung ausdruecklich verneint. Ein Name ist ein Beleg; das Fehlen eines
// Namens ist keine Behauptung in die andere Richtung.
const HEX64 = /^[0-9A-Fa-f]{64}$/;
export const LATENCY_CLOSURE_STATES = ["proven", "denied", "unknown"];

function closureRow(map, row) {
  if (!row || typeof row !== "object" || !Number.isFinite(row.l)) return;
  const prev = map.get(row.l) ?? { denied: false, basis: null, hash: null, verifiedBy: null };
  if (row.cl === false) prev.denied = true;
  if (typeof row.ch === "string" && HEX64.test(row.ch)) {
    prev.hash = row.ch;
    prev.basis = typeof row.chSource === "string" ? row.chSource : "recorder";
    if (typeof row.chVerifiedBy === "string") prev.verifiedBy = row.chVerifiedBy;
  }
  map.set(row.l, prev);
}

// Der Zustand wird aus Belegen gebaut, nie aus dem Fehlenden: 'vote-not-observed' schreibt der
// Recorder nur auf einem bewiesen geschlossenen Ledger (lib/validator-trace.mjs), und die
// Lese-Nachfuehrung (lib/validator-trace-store.mjs) hinterlaesst mit 'cb' die Autoritaet der
// Schliess-Aussage. 'nc === true' ist die ausdrueckliche Verneinung. Ohne all das: unknown.
function closureState(inc, rows) {
  const row = rows.get(inc.ledgerIndex);
  if (inc.nc === true || (row && row.denied)) return "denied";
  if (row && row.hash) return "proven";
  if (inc.type === "vote-not-observed" || typeof inc.cb === "string") return "proven";
  return "unknown";
}

function closureSplit(incidents, rows) {
  const split = { incidents: incidents.length, proven: 0, denied: 0, unknown: 0, bases: {} };
  for (const inc of incidents) {
    const state = closureState(inc, rows);
    split[state] += 1;
    if (state !== "proven") continue;
    const row = rows.get(inc.ledgerIndex);
    const basis = row && row.hash ? row.basis : (typeof inc.cb === "string" ? inc.cb : "validated-ledger-stream");
    split.bases[basis] = (split.bases[basis] ?? 0) + 1;
  }
  return split;
}

function windowOf(range, now) {
  const ms = SPAN[range] ?? SPAN["24h"];
  return { from: ms === Infinity ? 0 : now - ms, to: now + 1 };
}

// Spaetvalidierung je Ledger: der frueheste aufgezeichnete Spaetvote dieses Knotens. Mehrere
// Spaetvotes fuerselbe Ledger sind ein Wiederholungsproblem, keine zwei Vorfaelle.
function betterLate(current, candidate) {
  if (!current) return candidate;
  if (!Number.isFinite(current.ms) && Number.isFinite(candidate.ms)) return candidate;
  if (Number.isFinite(current.ms) && Number.isFinite(candidate.ms) && candidate.ms < current.ms) return candidate;
  return current;
}

function delayStats(values) {
  const a = values.filter((x) => Number.isFinite(x)).sort((x, y) => x - y);
  if (!a.length) return { n: 0, min: null, median: null, p90: null, max: null, mean: null };
  return {
    n: a.length,
    min: round(a[0]),
    median: round(quantile(a, 0.5)),
    p90: round(quantile(a, 0.9)),
    max: round(a[a.length - 1]),
    mean: round(a.reduce((s, x) => s + x, 0) / a.length),
  };
}

// "nicht erfasst" ist ein eigener Zustand. normalizeDay() ergaenzt ein fehlendes lateVotes-Feld
// als leere Liste und setzt dann lateVotesRecorded = false - ohne diesen Marker waere ein
// Altbestandtag von einem Tag mit tatsaechlich null Spaetvotes nicht zu unterscheiden.
function lateRecorded(d) {
  if (!d || typeof d !== "object") return false;
  if (d.lateVotesRecorded === false) return false;
  return Array.isArray(d.lateVotes);
}

export function voteLatencyProfile(days, master, { range = "24h", now = Date.now() } = {}) {
  const w = windowOf(range, now);
  const dayList = Array.isArray(days) ? days : [];
  const closureRows = new Map(); // ledgerIndex -> { denied, basis, hash, verifiedBy }
  const lateMap = new Map();     // ledgerIndex -> { ms, t }
  const fvByLedger = new Map();  // ledgerIndex -> fv (Netz, erster Vote nach Close)
  const incidents = [];
  const netMine = [], netOther = [];
  const ownDelays = [], behindDelays = [];
  let lateVotesSeen = 0, truncatedDays = 0, daysRecorded = 0, daysMissing = 0;
  let hourLedgers = 0, hourSum = 0, hourMax = null, hourLate = 0, hoursSeen = 0;
  const hourRows = [];

  for (const d of dayList) {
    for (const ls of d.ledgerStats ?? []) closureRow(closureRows, ls);
    for (const cp of d.closureProofs ?? []) closureRow(closureRows, cp);
    const recorded = lateRecorded(d);
    if (recorded) daysRecorded += 1; else daysMissing += 1;
    if (recorded && d.lateVotesTruncated) truncatedDays += 1;
    const mineByLedger = new Map();
    for (const i of d.incidents ?? []) {
      if (i.m !== master) continue;
      const t = num(i.t);
      if (t === null || t < w.from || t > w.to) continue;
      mineByLedger.set(i.l, true);
      // Die Schliess-Belege des Incidents wandern mit: 'nc' ist die ausdrueckliche Verneinung,
      // 'cb' die beim Lesen nachgetragene Autoritaet. Ohne sie haette das Schliess-Urteil keine
      // Grundlage an der Stelle, die es faellt.
      incidents.push({
        ledgerIndex: i.l, timeMs: t, type: i.type, ownMs: num(i.vd), reasons: i.r ?? [], recorded,
        nc: i.nc === true, cb: typeof i.cb === "string" ? i.cb : null,
      });
    }
    for (const lv of d.lateVotes ?? []) {
      if (!lv || lv.m !== master) continue;
      const ms = num(lv.ms), t = num(lv.t);
      if (t !== null && (t < w.from || t > w.to)) continue;
      lateVotesSeen += 1;
      lateMap.set(lv.l, betterLate(lateMap.get(lv.l), { ms, t }));
    }
    for (const ls of d.ledgerStats ?? []) {
      const fv = num(ls.fv);
      if (fv === null) continue;
      const t = num(ls.t);
      if (t === null || t < w.from || t > w.to) continue;
      fvByLedger.set(ls.l, fv);
      (mineByLedger.has(ls.l) ? netMine : netOther).push(fv);
    }
    for (const [hk, hb] of Object.entries(d.hourly ?? {})) {
      const h0 = Number(hk) * HOUR_MS;
      if (!Number.isFinite(h0) || h0 + HOUR_MS < w.from || h0 > w.to) continue;
      const n = num(hb?.fvN);
      if (n === null || n <= 0) continue;
      const sum = num(hb.fvS);
      hoursSeen += 1;
      hourLedgers += n;
      if (sum !== null) hourSum += sum;
      const mx = num(hb.fvX);
      if (mx !== null) hourMax = hourMax === null ? mx : Math.max(hourMax, mx);
      hourLate += num(hb.fvL) ?? 0;
      hourRows.push({ hourMs: h0, ledgers: n, meanFvMs: round(sum === null ? null : sum / n), maxFvMs: mx, lateLedgers: num(hb.fvL) ?? 0 });
    }
  }

  hourRows.sort((a, b) => (b.lateLedgers - a.lateLedgers) || (b.ledgers - a.ledgers) || (a.hourMs - b.hourMs));

  const out = {
    master, range, window: { from: w.from, to: w.to },
    thresholds: {
      graceMs: LATE_GRACE_MS, ringLedgers: LATE_RING_LEDGERS, minIncidents: LATENCY_MIN_INCIDENTS,
      minNetworkLedgers: LATENCY_MIN_NETWORK_LEDGERS, networkSlowShare: LATENCY_NETWORK_SLOW_SHARE,
      offsetTightMs: LATENCY_OFFSET_TIGHT_MS,
    },
    coverage: {
      days, daysRecorded: 0, daysMissing: 0, lateVotesSeen: 0, truncatedDays: 0,
      networkLedgers: 0, networkHours: 0,
    },
    counts: { incidents: incidents.length, nodeIncidents: 0, networkIncidents: 0 },
    classes: null, own: null, network: null, comparison: null, pattern: null, lateVotes: [],
    closure: null,
    verdict: "not-recorded", verdictReason: "late-vote-recording-missing", verdictAuthority: "none",
  };
  out.coverage.days = dayList.length;
  out.coverage.daysRecorded = daysRecorded;
  out.coverage.daysMissing = daysMissing;
  out.coverage.lateVotesSeen = lateVotesSeen;
  out.coverage.truncatedDays = truncatedDays;
  out.coverage.networkLedgers = netMine.length + netOther.length;
  out.coverage.networkHours = hoursSeen;

  if (!incidents.length) {
    out.verdict = "no-deviations";
    out.verdictReason = "no-incidents-in-window";
    return out;
  }

  // Knotenzurechenbare Vorfaelle und die nicht-zurechenbaren bleiben getrennt: auf einem Ledger,
  // dessen Schliessung diesem Rekorder fehlt oder der bewiesen geschlossen ist, ist
  // Nicht-Abstimmen keine Spaetlatenz dieses Knoten.
  const nodeIncidents = incidents.filter((i) => NODE_TYPES.has(i.type));
  out.counts.nodeIncidents = nodeIncidents.length;
  out.counts.networkIncidents = incidents.length - nodeIncidents.length;
  // Kein knotenzurechenbarer Timing-Fehler. Was an dieser Stelle steht, ist eine Aussage ueber
  // das Netz - und die faellt nur, wofuer dieser Rekorder einen Beleg hat. Ein bewiesen
  // geschlossener Ledger hat sein Quorum erreicht: dort ist das fehlende Sehen eine Erfassungs-
  // Luecke dieses Mithoerers, kein Netz-Befund und kein Knotenfehler. Ohne Close-Beleg bleibt die
  // Frage offen; 'Netzstockung' waere dort eine Behauptung, die der eigene Mithoerstrom nie
  // hergibt. Der Datenmangel ist benannt, nicht als Luecke versteckt und nicht als Netz gefüllt.
  // Der Schliess-Beleg der nicht-zurechenbaren Vorfaelle steht auch dann da, wenn dieser Knoten
  // ausserdem spaet war: die Zahl beschreibt diese Ledger, nicht die Frage, ob es hier zusaetzlich
  // eine eigene Spaetlatenz gibt.
  const split = closureSplit(incidents.filter((i) => !NODE_TYPES.has(i.type)), closureRows);
  if (split.incidents > 0) out.closure = split;
  if (nodeIncidents.length === 0) {
    if (split.proven === incidents.length) {
      out.verdict = "capture-only";
      out.verdictReason = "capture-gap-on-closed-ledgers";
      out.verdictAuthority = "trace-closure-proof";
    } else if (split.proven === 0) {
      out.verdict = "closure-unproven";
      out.verdictReason = "no-node-attributable-failure";
    } else {
      out.verdict = "partially-proven";
      out.verdictReason = "closure-proof-partial";
      out.verdictAuthority = "trace-closure-proof";
    }
    return out;
  }

  const cls = { late: 0, never: 0, inWindow: 0, unknown: 0 };
  const rows = [];
  for (const inc of nodeIncidents) {
    const late = lateMap.get(inc.ledgerIndex);
    const ownMs = Number.isFinite(inc.ownMs) ? inc.ownMs : (late && Number.isFinite(late.ms) ? late.ms : null);
    let klass;
    if (ownMs === null) {
      // "nie" ist nur fuer 'missed' belegenbar: dort fehlte die Validation zur Bewertungszeit
      // (lib/validator-trace.mjs setzt voteDelayMs genau dort auf null). partial und wrong-hash
      // beweisen einen Vote - ohne Messwert ist nur dessen Zeitpunkt unbekannt. Sie als
      // "nie abgestimmt" zu zaehlen waere eine Beschuldigung, die der Trace nicht hergibt.
      klass = (inc.type === "missed" && inc.recorded) ? "never" : "unknown";
    } else klass = ownMs > LATE_GRACE_MS ? "late" : "inWindow";
    cls[klass] += 1;
    const fv = fvByLedger.get(inc.ledgerIndex) ?? null;
    const behind = ownMs !== null && fv !== null ? ownMs - fv : null;
    if (ownMs !== null) ownDelays.push(ownMs);
    if (behind !== null) behindDelays.push(behind);
    rows.push({
      ledgerIndex: inc.ledgerIndex, timeMs: inc.timeMs, type: inc.type, klass,
      ownMs: round(ownMs), networkFirstMs: round(fv), behindMs: round(behind),
    });
  }
  rows.sort((a, b) => b.timeMs - a.timeMs);

  const measurable = cls.late + cls.never + cls.inWindow;
  const share = (n) => (measurable > 0 ? round(n / measurable, 4) : null);
  out.classes = {
    late: cls.late, never: cls.never, inWindow: cls.inWindow, unknown: cls.unknown,
    measurable,
    lateShare: share(cls.late), neverShare: share(cls.never), inWindowShare: share(cls.inWindow),
    unknownShare: nodeIncidents.length ? round(cls.unknown / nodeIncidents.length, 4) : null,
  };
  out.own = { delay: delayStats(ownDelays), lateVotes: lateMap.size };
  out.network = {
    onOwnIncidentLedgers: delayStats(netMine),
    onPeerIncidentLedgers: delayStats(netOther),
    hourly: {
      hours: hoursSeen, ledgers: hourLedgers,
      meanFvMs: hourLedgers > 0 ? round(hourSum / hourLedgers) : null,
      maxFvMs: round(hourMax),
      lateLedgers: hourLate,
      lateShare: hourLedgers > 0 ? round(hourLate / hourLedgers, 4) : null,
    },
    worstHours: hourRows.slice(0, 6),
  };
  out.comparison = {
    behind: delayStats(behindDelays),
    ratioOwnToNetworkMedian: null,
    method: "Distanz = eigene Vote-Latenz minus erster Vote des Netzes im selben Ledger (fv). "
      + "Netzreferenz aus den Ausfall-Ledern dieses Knotens und den Ausfall-Ledern der Peers, in denen dieser Knoten nicht fiel.",
  };
  out.lateVotes = rows.filter((r) => r.klass === "late").slice(0, 12);

  const netMedian = out.network.onOwnIncidentLedgers.median;
  const ownMedian = out.own.delay.median;
  if (Number.isFinite(ownMedian) && Number.isFinite(netMedian) && netMedian > 0) {
    out.comparison.ratioOwnToNetworkMedian = round(ownMedian / netMedian, 3);
  }

  // Muster der Distanz: eine enge Streuung ist ein konstanter Versatz (Uhr/Queue), eine weite ist
  // ein variabler Pfad. Beides ist ein Kandidat, keine Behauptung - die Pruefung bleibt beim Betreiber.
  const behind = out.comparison.behind;
  if (behind.n >= 3) {
    const spread = behind.p90 - behind.median;
    out.pattern = {
      kind: spread <= LATENCY_OFFSET_TIGHT_MS ? "consistent-offset" : "variable-delay",
      spreadMs: round(spread), samples: behind.n,
      note: "Kandidat aus der Streuung, nicht aus einem Einzelwert",
    };
  } else {
    out.pattern = { kind: "no-delay-data", spreadMs: null, samples: behind.n, note: "zu wenige eigene Votes mit Netzreferenz" };
  }

  const networkSlow = (Number.isFinite(netMedian) && netMedian > LATE_GRACE_MS)
    || (out.network.hourly.ledgers >= LATENCY_MIN_NETWORK_LEDGERS
      && Number.isFinite(out.network.hourly.lateShare) && out.network.hourly.lateShare >= LATENCY_NETWORK_SLOW_SHARE);
  const networkReference = out.network.hourly.ledgers >= LATENCY_MIN_NETWORK_LEDGERS || netMine.length >= LATENCY_MIN_NETWORK_LEDGERS;

  if (measurable === 0) {
    out.verdict = "not-recorded";
    out.verdictReason = daysRecorded === 0 ? "late-vote-recording-missing" : "no-measurable-own-vote";
    return out;
  }
  if (nodeIncidents.length < LATENCY_MIN_INCIDENTS) {
    out.verdict = "insufficient-sample";
    out.verdictReason = "below-minimum-incidents";
    return out;
  }

  const ranked = LATENCY_CLASSES.filter((k) => k !== "unknown").map((k) => [k, cls[k]]).sort((a, b) => b[1] - a[1]);
  const [topClass, topN] = ranked[0];
  const secondN = ranked[1] ? ranked[1][1] : 0;
  if (topN / measurable < 0.6 && secondN / measurable >= 0.25) {
    out.verdict = "mixed";
    out.verdictReason = "late-and-never-mixed";
    out.verdictAuthority = lateMap.size > 0 ? "trace-late-votes" : "trace-incident-delay";
    return out;
  }
  if (topClass === "never") {
    out.verdict = "never-signed";
    out.verdictReason = "never-voted-dominant";
    out.verdictAuthority = "trace-late-votes";
    return out;
  }
  if (topClass === "inWindow") {
    out.verdict = "latency-not-the-cause";
    out.verdictReason = "own-vote-inside-grace";
    out.verdictAuthority = "trace-incident-delay";
    return out;
  }
  if (networkSlow) {
    out.verdict = "network-side";
    out.verdictReason = "network-first-vote-late";
    out.verdictAuthority = "trace-network-latency";
    return out;
  }
  out.verdict = "node-side-late";
  out.verdictReason = networkReference ? "late-vote-dominant-network-fast" : "late-vote-dominant-no-network-reference";
  out.verdictAuthority = "trace-late-votes";
  return out;
}
