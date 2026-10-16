// lib/validator-retrace.mjs — Retrace-Engine: WARUM ein Validator ein Ledger verpasst hat.
// Rein, ohne I/O. Eingabe: Tagesobjekte aus data/validator-trace (monitor/validator-trace.mjs).
//
// Die Aufzeichnung allein sagt WAS passierte (missed / partial / wrong-hash / no-quorum).
// Diese Ebene beantwortet, unter welchen Bedingungen derselbe Ausfall auftritt — gemessen,
// nicht geraten. Vier unabhängige Blickwinkel:
//   1. Kohorte  — haben andere Validatoren denselben Ledger ebenfalls verfehlt?
//                 Trennt Netzwerk-/Infrastruktur-Ereignis vom eigenen Knotenfehler.
//   2. Quorum   — wie knapp war das Quorum, gab es eine zweite Hash-Linie (Spaltung)?
//   3. Last/Takt — war der Ledger ein Ausreißer (Tx-Last, Close-Abstand)?
//   4. Risiko   — wie oft fällt ein Ledger aus, WENN eine Anomalie vorliegt, im Vergleich
//                 zu Ledgern ohne Anomalie. Ohne diesen Nenner ist jede "Ursache" Anekdote.
//
// Grenzen, ehrlich benannt: alles ist Korrelation im selben Ledger, kein Beweis einer Kausalität.
// Zu kleine Stichproben werden NICHT zu einer Zahl verdichtet (reliable=false + Grund).
// Fehlende Forensik (Tage vor dieser Stufe) wird als Datenlücke ausgewiesen, nie als "kein Grund".
import { TRACE_DEFAULTS } from "./validator-trace.mjs";

export const RETRACE_DEFAULTS = {
  minAnomalyLedgers: 20,   // darunter kein Risikovergleich: zu kleine Stichprobe
  minAnomalyFails: 3,      // darunter kein belastbarer Vergleich
  minPlainLedgers: 50,     // die Vergleichsgruppe muss vorhanden sein
  attackMinValidators: 5,  // gleichzeitige Ausfälle ab hier als Sammelereignis
  topAttacks: 12,
};

const TYPES = ["missed", "partial", "wrongHash", "noQuorum"];
const TYPE_OF = { missed: "missed", partial: "partial", "wrong-hash": "wrongHash", "no-quorum": "noQuorum" };
const num = (x) => (Number.isFinite(Number(x)) ? Number(x) : null);

// Ledger-Index über alle Tage: Vorfälle und Forensik je LedgerIndex.
export function buildLedgerIndex(days) {
  const idx = new Map();
  for (const d of Array.isArray(days) ? days : []) {
    for (const i of d.incidents ?? []) {
      const e = idx.get(i.l) ?? { ledgerIndex: i.l, timeMs: i.t ?? null, incidents: [], stats: null };
      e.incidents.push({ master: i.m, type: i.type, reasons: i.r ?? [] });
      if (!e.timeMs && Number.isFinite(i.t)) e.timeMs = i.t;
      idx.set(i.l, e);
    }
    for (const st of d.ledgerStats ?? []) {
      const e = idx.get(st.l) ?? { ledgerIndex: st.l, timeMs: st.t ?? null, incidents: [], stats: null };
      e.stats = st;
      if (!e.timeMs && Number.isFinite(st.t)) e.timeMs = st.t;
      idx.set(st.l, e);
    }
  }
  return idx;
}

// Risikovergleich je Anomalie: Ausfallwahrscheinlichkeit MIT Anomalie gegen OHNE Anomalie.
// Nenner und Zähler kommen aus vollständigen Tageszählern, nie aus einer Teilmenge.
export function riskProfile(days, opts = {}) {
  const p = { ...RETRACE_DEFAULTS, ...opts };
  const anomaly = new Map();
  const incidentLedgers = new Set();
  let totalLedgers = 0;
  let daysWithStats = 0;
  let truncated = false;
  for (const d of Array.isArray(days) ? days : []) {
    totalLedgers += num(d.ledgers) ?? 0;
    for (const i of d.incidents ?? []) incidentLedgers.add(i.l);
    for (const [tag, n] of Object.entries(d.anomaly ?? {})) {
      const e = anomaly.get(tag) ?? { ledgers: 0, failLedgers: 0 };
      e.ledgers += num(n) ?? 0;
      anomaly.set(tag, e);
    }
    for (const [tag, n] of Object.entries(d.anomalyFail ?? {})) {
      const e = anomaly.get(tag) ?? { ledgers: 0, failLedgers: 0 };
      e.failLedgers += num(n) ?? 0;
      anomaly.set(tag, e);
    }
    if (Array.isArray(d.ledgerStats) && d.ledgerStats.length) daysWithStats += 1;
    if (d.ledgerStatsTruncated) truncated = true;
  }
  const failTotal = incidentLedgers.size;
  const rows = [];
  for (const [tag, e] of anomaly) {
    const plainLedgers = Math.max(0, totalLedgers - e.ledgers);
    const plainFails = Math.max(0, failTotal - e.failLedgers);
    const rateWith = e.ledgers > 0 ? e.failLedgers / e.ledgers : null;
    const rateWithout = plainLedgers > 0 ? plainFails / plainLedgers : null;
    const lift = rateWith !== null && rateWithout ? rateWith / rateWithout : null;
    const reliable = e.ledgers >= p.minAnomalyLedgers && e.failLedgers >= p.minAnomalyFails && plainLedgers >= p.minPlainLedgers;
    rows.push({
      tag,
      anomalyLedgers: e.ledgers,
      anomalyFailLedgers: e.failLedgers,
      plainLedgers,
      plainFailLedgers: plainFails,
      rateWith,
      rateWithout,
      lift,
      reliable,
      note: reliable ? null : "sample-too-small",
    });
  }
  rows.sort((a, b) => (Number(b.reliable) - Number(a.reliable)) || ((b.lift ?? 0) - (a.lift ?? 0)) || a.tag.localeCompare(b.tag));
  return { totalLedgers, incidentLedgers: failTotal, rows, daysWithStats, statsTruncated: truncated };
}

// Passender Risikowert für ein Tag (exakt, sonst Präfix wie new-tx-type).
export function liftFor(tag, risk) {
  if (!tag || !risk || !Array.isArray(risk.rows)) return null;
  const exact = risk.rows.find((r) => r.tag === tag);
  if (exact) return exact;
  const base = String(tag).split(":")[0];
  return risk.rows.find((r) => r.tag === base) ?? null;
}

function countsOf(entry) {
  const c = { missed: 0, partial: 0, wrongHash: 0, noQuorum: 0 };
  for (const i of entry.incidents) if (c[TYPE_OF[i.type]] !== undefined) c[TYPE_OF[i.type]] += 1;
  return c;
}

// Ein Vorfall, ein Ledger, eine Diagnose.
// strength: measured (direkte Ledger-Messung) > cohort (Betroffenheit anderer) >
//           correlated (Ledger-Kontext) > none (nichts Korreliertes gefunden).
export function retraceIncident(entry, incident, risk) {
  const st = entry.stats ?? null;
  const counts = countsOf(entry);
  const others = entry.incidents.filter((i) => i.master !== incident.master).length;
  const type = incident.type;

  let scope = "unknown";
  if (type === "no-quorum") scope = "network";
  else if (others === 0) scope = "solo";
  else scope = "cohort";

  const quorum = st ? { votes: st.v, needed: st.need, topVotes: st.top, margin: st.mg, runnerVotes: st.sp } : null;
  const load = st ? { txCount: st.tx, medianTx: st.med, ratio: st.med > 0 ? st.tx / st.med : null } : null;
  const closeGapMs = st && Number.isFinite(st.gap) ? st.gap : null;

  const hypotheses = [];
  const add = (tag, strength, evidence) => hypotheses.push({ tag, strength, evidence, lift: liftFor(tag, risk) });

  if (quorum && quorum.needed > 0 && quorum.margin < TRACE_DEFAULTS.thinMarginMax) {
    add("quorum-thin", "measured", { topVotes: quorum.topVotes, needed: quorum.needed, margin: quorum.margin });
  }
  if (quorum && quorum.runnerVotes >= TRACE_DEFAULTS.splitMinVotes) {
    add("hash-split", "measured", { runnerVotes: quorum.runnerVotes, votes: quorum.votes });
  }
  if (load && load.txCount >= TRACE_DEFAULTS.spikeMinTx && load.medianTx > 0 && load.ratio >= TRACE_DEFAULTS.spikeRatio) {
    add(load.ratio >= TRACE_DEFAULTS.extremeRatio ? "load-extreme" : "load-spike", "measured", { txCount: load.txCount, medianTx: load.medianTx, ratio: Math.round(load.ratio * 10) / 10 });
  }
  const medianGapMs = st && Number.isFinite(st.gmed) ? st.gmed : null;
  if (closeGapMs !== null && medianGapMs !== null && medianGapMs > 0
    && closeGapMs >= TRACE_DEFAULTS.gapMinMs && closeGapMs >= TRACE_DEFAULTS.gapRatio * medianGapMs) {
    add("close-gap", "measured", { closeGapMs, medianGapMs });
  }
  if (scope === "cohort") add("cohort-event", "cohort", { affectedValidators: counts.missed + counts.partial + counts.wrongHash, others });
  if (scope === "solo") add("solo-failure", "cohort", { others: 0 });

  for (const tag of incident.reasons ?? []) {
    if (["no-correlated-cause", "partial-validation", "signed-different-hash", "no-quorum"].includes(tag)) continue;
    if (hypotheses.some((h) => h.tag === tag)) continue;
    add(tag, "correlated", {});
  }

  // Solo/Kohorte ist eine Einordnung, keine Ursache. Wenn außer dieser Einordnung nichts
  // Gemessene oder Korrelierte steht, muss das ausdrücklich da sein — sonst entsteht der
  // Eindruck, die Ursache sei gefunden, wo nur die Kategorie gefunden ist.
  if (!hypotheses.some((h) => h.strength === "measured" || h.strength === "correlated")) add("no-correlated-cause", "none", {});

  const dataGaps = [];
  if (!st) dataGaps.push("forensics-not-recorded");
  if (risk && risk.statsTruncated) dataGaps.push("forensics-truncated");

  return {
    ledgerIndex: incident.ledgerIndex,
    timeMs: entry.timeMs ?? incident.timeMs ?? null,
    type,
    scope,
    affected: { ...counts, others },
    quorum,
    load,
    closeGapMs,
    hypotheses,
    guidance: guidanceFor(type, scope, hypotheses),
    dataGaps,
  };
}

// Was ein Validator-Betreiber als Nächstes prüfen sollte — maschinelle Tags, übersetzt per i18n.
function guidanceFor(type, scope, hypotheses) {
  const tags = new Set();
  const has = (t) => hypotheses.some((h) => h.tag === t);
  const explained = hypotheses.some((h) => h.strength === "measured" || h.strength === "correlated");
  if (scope === "network") tags.add("network-stall");
  if (scope === "cohort") tags.add("cohort-network");
  if (scope === "solo") { tags.add("solo-peering"); tags.add("solo-resources"); }
  if (type === "wrong-hash") tags.add("version-state");
  if (has("hash-split")) tags.add("report-split");
  if (has("load-spike") || has("load-extreme")) tags.add("load-backlog");
  if (has("close-gap")) tags.add("network-stall");
  if (has("amendment-activity")) tags.add("version-state");
  if (has("unl-change")) tags.add("unl-membership");
  if (has("new-tx-type")) tags.add("parser-version");
  if (has("quorum-thin")) tags.add("quorum-margin");
  if (!explained) tags.add("unknown-cause");
  return [...tags];
}

// Retrace für einen Validator: Diagnose je Vorfall, neueste zuerst.
export function retraceForValidator(days, master, { range = "24h", now = Date.now(), risk = null } = {}) {
  const idx = buildLedgerIndex(days);
  const profile = risk ?? riskProfile(days);
  const span = { "1h": 3600000, "24h": 86400000, "7d": 7 * 86400000, all: Infinity }[range] ?? 86400000;
  const from = span === Infinity ? 0 : now - span;
  const out = [];
  for (const [ledgerIndex, entry] of idx) {
    for (const inc of entry.incidents) {
      if (inc.master !== master) continue;
      const timeMs = entry.timeMs ?? null;
      if (timeMs !== null && (timeMs < from || timeMs > now + 1)) continue;
      out.push(retraceIncident(entry, { master, type: inc.type, reasons: inc.reasons, ledgerIndex, timeMs }, profile));
    }
  }
  out.sort((a, b) => (b.timeMs ?? 0) - (a.timeMs ?? 0));
  return out;
}

// Sammelereignisse: viele Validatoren, dasselbe Ledger, mit Anomalie-Kontext.
// Das ist die Spur, auf der Angriffe, Netzstockungen und Versionskonflikte liegen —
// ausgewählt nach gleichzeitiger Betroffenheit und messbarer Anomalie, nicht nach Bauchgefühl.
export function attackSignals(days, { range = "24h", now = Date.now(), risk = null, ...rest } = {}) {
  const p = { ...RETRACE_DEFAULTS, ...rest };
  const idx = buildLedgerIndex(days);
  const profile = risk ?? riskProfile(days);
  const span = { "1h": 3600000, "24h": 86400000, "7d": 7 * 86400000, all: Infinity }[range] ?? 86400000;
  const from = span === Infinity ? 0 : now - span;
  const rows = [];
  for (const entry of idx.values()) {
    if (entry.timeMs !== null && (entry.timeMs < from || entry.timeMs > now + 1)) continue;
    const counts = countsOf(entry);
    const affected = counts.missed + counts.partial + counts.wrongHash;
    const validators = new Set(entry.incidents.map((i) => i.master)).size;
    if (validators < p.attackMinValidators && counts.noQuorum === 0) continue;
    const st = entry.stats;
    const anomalies = [];
    if (st) {
      if (st.sp >= TRACE_DEFAULTS.splitMinVotes) anomalies.push("hash-split");
      if (st.med > 0 && st.tx >= TRACE_DEFAULTS.spikeMinTx && st.tx / st.med >= TRACE_DEFAULTS.spikeRatio) anomalies.push(st.tx / st.med >= TRACE_DEFAULTS.extremeRatio ? "load-extreme" : "load-spike");
      if (Number.isFinite(st.gap) && st.gap >= TRACE_DEFAULTS.gapMinMs) anomalies.push("close-gap");
    }
    const tags = new Set(anomalies);
    for (const i of entry.incidents) for (const r of i.reasons ?? []) {
      if (r === "no-quorum" || r.startsWith("new-tx-type") || r === "amendment-activity" || r === "unl-change" || r === "hash-split" || r === "load-spike" || r === "load-extreme" || r === "close-gap") tags.add(r);
    }
    rows.push({
      ledgerIndex: entry.ledgerIndex,
      timeMs: entry.timeMs ?? null,
      affectedValidators: validators,
      counts,
      anomalies: [...tags],
      quorum: st ? { votes: st.v, needed: st.need, topVotes: st.top, margin: st.mg, runnerVotes: st.sp } : null,
      load: st ? { txCount: st.tx, medianTx: st.med } : null,
    });
  }
  rows.sort((a, b) => (b.affectedValidators - a.affectedValidators) || (b.anomalies.length - a.anomalies.length) || (b.timeMs ?? 0) - (a.timeMs ?? 0));
  return { signals: rows.slice(0, p.topAttacks), total: rows.length, threshold: p.attackMinValidators, risk: profile };
}