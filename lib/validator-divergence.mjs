// lib/validator-divergence.mjs — Divergenz-Engine: WARUM ein Knoten auf einer anderen Linie steht.
// Rein, ohne I/O. Eingabe: Tagesobjekte aus data/validator-trace (monitor/validator-trace.mjs).
//
// Die Retrace-Ebene (lib/validator-retrace.mjs) beantwortet, unter welchen Bedingungen ein Ausfall
// auftritt: Kohorte, Quorum-Rand, Last, Takt, Tx-Form. Diese Ebene beantwortet die andere Frage,
// die bei 'wrong-hash' und bei Serien auf Feature-Ledern entscheidet:
//
//   1. Linie    — auf welcher Hash-Linie hat DIESER Knoten abgestimmt, und auf welcher das Netz?
//                 Netzmehrheit, Runner-Up-Linie oder eine eigene dritte Linie. Das ist der
//                 Unterschied zwischen "langsam", "gespaltenes Netz" und "mein Knoten rechnet anders".
//   2. Wiederholung — dieselbe verlorene Linie mehrfach: eine deterministische Abweichung
//                 (Stand-/Build-Unterschied), nicht ein einzelner Ausrutscher.
//   3. Geteilte Linie — mehrere Knoten auf derselben verlorenen Linie: ein gemeinsamer Build,
//                 eine gemeinsame Konfiguration, nicht ein Zufall.
//   4. Feature-Ledger — Amendment- und UNLModify-Ledger sind die Ledger, auf denen sich die
//                 Bewertungsregeln des Netzes ändern. Faellt ein Knoten ausgerechnet dort, ist die
//                 Ursache eine Regel- oder Versionsdifferenz, kein Netzwerkpfad.
//
// Grenzen, ehrlich benannt: alles ist Korrelation innerhalb desselben Ledgers, kein Beweis einer
// Kausalitaet. Zu kleine Stichproben werden nicht zu einer Zahl verdichtet (reliable=false + Grund).
// Fehlende Aufzeichnung ist eine Datenluecke, nie "keine Abweichung": ein Tag ohne Vote-Hash sagt
// nichts ueber den Knoten aus.
import { measured } from "./validator-trace.mjs";

export const DIVERGENCE_DEFAULTS = {
  minIncidents: 5,        // darunter kein Urteil ueber die Abweichung dieses Knotens
  minRepeated: 3,         // gleiche verlorene Linie ab hier: deterministisch, nicht Ausrutscher
  minClusterMasters: 2,   // gleiche verlorene Linie bei so vielen Knoten: geteilte Linie
  minFeatureLedgers: 20,  // Nenner des Feature-Vergleichs
  minFeatureFails: 3,     // Zaehler des Feature-Vergleichs
  minPlainLedgers: 50,    // die Vergleichsgruppe muss vorhanden sein
  minMineLedgers: 3,      // eigene Beruehrung, damit "mein Knoten" eine Zahl ist und keine Ahnung
  // Anteil der eigenen Vorfaelle, deren Hash-Linie wirklich beurteilt werden konnte. "clean" ist
  // eine Aussage ueber den Knoten - sie braucht einen Nenner. Ohne diese Grenze war "clean" die
  // automatischste Antwort des ganzen Moduls: 2 von 126 Vorfaellen mit Vote-Hash, 117 ohne Linie,
  // und die Antwort war trotzdem "keine Abweichung". Das ist kein Befund, das ist Blindheit mit
  // gutem Gewissen.
  minLineageCoverage: 0.6,
  topDivergences: 12,
  topLineages: 8,
  topFeatures: 10,
};

export const LINEAGES = ["accepted", "runner", "own", "unknown"];
export const DIVERGENCE_VERDICTS = [
  "clean", "deterministic-divergence", "shared-lineage", "transient-divergence",
  "feature-linked", "tip-lag", "insufficient-sample", "not-recorded",
];
export const DIVERGENCE_AUTHORITIES = ["trace-hash-lineage", "trace-feature-counters", "trace-late-votes", "none"];
export const DIVERGENCE_REASONS = [
  "no-divergence-recorded", "hash-lineage-missing", "accepted-hash-missing", "too-few-divergences",
  "incident-lineage-coverage",
  "same-losing-lineage", "shared-losing-lineage", "distinct-losing-lineages",
  "feature-linked-failures", "late-votes-on-accepted-lineage", "no-feature-ledgers",
];
export const DIVERGENCE_GAPS = [
  "hash-lineage-not-recorded", "accepted-hash-not-recorded",
  "feature-counters-not-recorded", "late-vote-lineage-not-recorded",
];
export const DIVERGENCE_GUIDANCE = [
  "compare-node-build", "check-amendment-support", "check-unl-handling", "check-peer-lineage",
  "check-vote-path", "check-local-state",
];

const num = measured;
const HEX64 = /^[0-9A-Fa-f]{64}$/;
const hex = (x) => (typeof x === "string" && HEX64.test(x) ? x.toUpperCase() : null);
const round = (x, n) => (Number.isFinite(x) ? Math.round(x * 10 ** n) / 10 ** n : null);
const SPAN_MS = { "1h": 3600000, "24h": 86400000, "7d": 7 * 86400000, "30d": 30 * 86400000, all: Infinity };

function windowOf(range, now) {
  const span = SPAN_MS[range] ?? SPAN_MS["24h"];
  return { from: span === Infinity ? -Infinity : now - span, to: now + 1 };
}

// Die Klasse einer Abweichung. accepted = Netzmehrheit, runner = die zweitstaerkste Linie desselben
// Ledgers, own = eine dritte Linie. Ohne Vote-Hash oder ohne akzeptierte Hash ist die Frage nicht
// beantwortbar -> unknown (nicht "keine Abweichung").
export function lineageOf(votedHash, acceptedHash, runnerHash) {
  const v = hex(votedHash);
  const a = hex(acceptedHash);
  if (!v || !a) return "unknown";
  if (v === a) return "accepted";
  const r = hex(runnerHash);
  return r && v === r ? "runner" : "own";
}

// Kurzform eines Amendment-IDs fuer die Anzeige: der Name ist aus den Validierungsdaten nicht
// ableitbar, deshalb bleibt die ID die Aussage (kein erfundener Name).
export function featureLabel(key) {
  const k = String(key ?? "");
  if (k === "unl-modify") return "UNLModify";
  if (k.startsWith("amendment:")) return "Amendment " + k.slice(10, 18).toLowerCase();
  return k;
}

// Ledger-Fakten aus der Forensik: akzeptierte Linie, Runner-Up, Feature-Fakten.
function ledgerFacts(days, w) {
  const map = new Map();
  let daysWithLineage = 0;
  let daysWithFeatures = 0;
  for (const d of Array.isArray(days) ? days : []) {
    let lineageHere = false;
    let featureHere = false;
    for (const st of d.ledgerStats ?? []) {
      if (!st || !Number.isFinite(st.l)) continue;
      const t = num(st.t);
      if (t !== null && (t < w.from || t > w.to)) continue;
      const ah = hex(st.ah);
      const rh = hex(st.rh);
      const am = Array.isArray(st.am) ? st.am.map((x) => hex(x)).filter(Boolean) : null;
      if (am) featureHere = true;
      if (st.unl === true) featureHere = true;
      if (ah) lineageHere = true;
      const prev = map.get(st.l) ?? { ledgerIndex: st.l, timeMs: t, acceptedHash: null, runnerHash: null, amendments: null, unlModify: false, runnerVotes: null };
      if (ah) prev.acceptedHash = ah;
      if (rh) prev.runnerHash = rh;
      if (am) prev.amendments = am;
      if (st.unl === true) prev.unlModify = true;
      if (Number.isFinite(st.sp)) prev.runnerVotes = st.sp;
      if (prev.timeMs === null && t !== null) prev.timeMs = t;
      map.set(st.l, prev);
    }
    if (lineageHere) daysWithLineage += 1;
    if (featureHere) daysWithFeatures += 1;
  }
  return { map, daysWithLineage, daysWithFeatures };
}

export function divergenceProfile(days, master, { range = "24h", now = Date.now(), ...rest } = {}) {
  const p = { ...DIVERGENCE_DEFAULTS, ...rest };
  const w = windowOf(range, now);
  const facts = ledgerFacts(days, w);

  // Vorfaelle dieses Knotens im Fenster, plus die Vorfaelle aller anderen (fuer geteilte Linien).
  const mine = [];
  const all = [];
  let incidentsTotal = 0;
  let withVoteHash = 0;
  let voteHashRecorded = false;
  for (const d of Array.isArray(days) ? days : []) {
    for (const i of d.incidents ?? []) {
      if (!Number.isFinite(i.l)) continue;
      const t = num(i.t);
      if (t !== null && (t < w.from || t > w.to)) continue;
      const entry = {
        ledgerIndex: i.l, timeMs: t, master: i.m, type: i.type,
        // h ist bei Altbestand undefined (nie erfasst), bei missed null (kein Vote in diesem Ledger).
        // Beide sind verschieden: undefined beantwortet die Frage nicht, null beantwortet sie mit
        // "es gab keinen Vote".
        votedHash: i.h === undefined ? undefined : hex(i.h),
        recorded: i.h !== undefined,
      };
      all.push(entry);
      if (entry.recorded) voteHashRecorded = true;
      if (entry.recorded && entry.votedHash) withVoteHash += 1;
      if (i.m === master) { incidentsTotal += 1; mine.push(entry); }
    }
  }

  // Spaet-Validierungen dieses Knotens: der Vote kam nach der Bewertung an. Seine Linie entscheidet,
  // ob "verpasst" ein Pfadproblem ist (Linie des Netzes) oder ein Standproblem (andere Linie).
  const late = { accepted: 0, divergent: 0, unknown: 0, total: 0, recorded: false, rows: [] };
  for (const d of Array.isArray(days) ? days : []) {
    if (!Array.isArray(d.lateVotes)) continue;
    for (const lv of d.lateVotes) {
      if (!lv || lv.m !== master || !Number.isFinite(lv.l)) continue;
      const t = num(lv.t);
      if (t !== null && (t < w.from || t > w.to)) continue;
      late.recorded = true;
      late.total += 1;
      const f = facts.map.get(lv.l);
      const cls = lv.h === undefined ? "unknown" : lineageOf(lv.h, f?.acceptedHash, f?.runnerHash);
      if (cls === "accepted") late.accepted += 1;
      else if (cls === "own" || cls === "runner") late.divergent += 1;
      else late.unknown += 1;
      if (late.rows.length < p.topDivergences) {
        late.rows.push({ ledgerIndex: lv.l, timeMs: t, delayMs: num(lv.ms), lineage: cls, votedHash: hex(lv.h), acceptedHash: f?.acceptedHash ?? null });
      }
    }
  }

  // Die Linien, die im Netz verloren haben: je verlorener Hash die Zahl der Vorfaelle und die Zahl
  // der Knoten darauf. Geteilte verlorene Linien sind der starkste Beleg fuer eine gemeinsame
  // Build-/Konfigurationsdifferenz.
  const losing = new Map();
  const divergences = [];
  for (const e of all) {
    if (!e.votedHash) continue;
    const f = facts.map.get(e.ledgerIndex);
    const cls = lineageOf(e.votedHash, f?.acceptedHash, f?.runnerHash);
    if (cls === "accepted" || cls === "unknown") continue;
    const key = e.votedHash;
    const row = losing.get(key) ?? { hash: key, count: 0, masters: new Set(), mineCount: 0, ledgers: [], features: new Set() };
    row.count += 1;
    row.masters.add(e.master);
    if (e.master === master) row.mineCount += 1;
    if (row.ledgers.length < 24) row.ledgers.push(e.ledgerIndex);
    for (const a of f?.amendments ?? []) row.features.add("amendment:" + a);
    if (f?.unlModify) row.features.add("unl-modify");
    losing.set(key, row);
    if (e.master === master) {
      divergences.push({
        ledgerIndex: e.ledgerIndex, timeMs: e.timeMs, type: e.type, lineage: cls,
        votedHash: e.votedHash, acceptedHash: f?.acceptedHash ?? null, runnerHash: f?.runnerHash ?? null,
        runnerVotes: f?.runnerVotes ?? null, features: [...(f?.amendments ?? []).map((a) => "amendment:" + a), ...(f?.unlModify ? ["unl-modify"] : [])],
      });
    }
  }
  divergences.sort((a, b) => (b.timeMs ?? 0) - (a.timeMs ?? 0));

  // noVote ist eine eigene Zahl, nicht Teil der Linien: ein Vorfall ohne Vote beantwortet die
  // Linienfrage nicht, aber er ist gemessen ('dieser Knoten hat in diesem Ledger nicht abgestimmt').
  // Beides mit 'unknown' zu mischen, wuerde aus einer Messung eine Nichtmessung machen.
  const lineages = { accepted: 0, runner: 0, own: 0, unknown: 0, noVote: 0 };
  for (const e of mine) {
    if (!e.recorded) { lineages.unknown += 1; continue; }
    if (e.votedHash === null) { lineages.noVote += 1; continue; }
    const f = facts.map.get(e.ledgerIndex);
    lineages[lineageOf(e.votedHash, f?.acceptedHash, f?.runnerHash)] += 1;
  }

  const losingRows = [...losing.values()]
    .map((r) => ({
      hash: r.hash, count: r.count, masterCount: r.masters.size, masters: [...r.masters].slice(0, 12),
      mineCount: r.mineCount, ledgers: r.ledgers.sort((a, b) => b - a).slice(0, 12), features: [...r.features],
      // Die Lesbarkeit der Feature-Kuerzel gehoert zur Engine, die sie erzeugt: das Overlay soll
      // dieselbe Bezeichnung zeigen wie die Feature-Tabelle, nicht eine zweite eigene Uebersetzung.
      featureLabels: [...r.features].map(featureLabel),
    }))
    .sort((a, b) => (b.mineCount - a.mineCount) || (b.masterCount - a.masterCount) || (b.count - a.count) || a.hash.localeCompare(b.hash));
  const mineLosing = losingRows.filter((r) => r.mineCount > 0);
  const repeated = mineLosing.find((r) => r.mineCount >= p.minRepeated) ?? null;
  const shared = losingRows.find((r) => r.masterCount >= p.minClusterMasters) ?? null;

  // Feature-Vergleich: Ausfallwahrscheinlichkeit von Ledgern MIT einem Feature gegen Ledger ohne.
  // Nenner und Zaehler kommen aus den Tageszaehlern ueber alle beobachteten Ledger.
  let totalLedgers = 0;
  let incidentLedgers = 0;
  let featureDays = 0;
  let daysWithoutFeatureCounters = 0;
  const feat = new Map();
  for (const d of Array.isArray(days) ? days : []) {
    // Der Feature-Vergleich darf nur Tage zaehlen, die seine Zaehler haben. Wuerden Tage ohne
    // Feature-Ebene in den Nenner gemischt, waere die Vergleichsgruppe groesser als die beobachtete
    // Grundgesamtheit - der Lift wird systematisch zu klein, also eine Entlastung ohne Messung.
    if (d.featureLedgers === undefined) { daysWithoutFeatureCounters += 1; continue; }
    featureDays += 1;
    totalLedgers += num(d.ledgers) ?? 0;
    incidentLedgers += num(d.incidentLedgers) ?? 0;
    for (const [k, n] of Object.entries(d.featureLedgers)) {
      const e = feat.get(k) ?? { ledgers: 0, failLedgers: 0 };
      e.ledgers += num(n) ?? 0;
      feat.set(k, e);
    }
    for (const [k, n] of Object.entries(d.featureFail ?? {})) {
      const e = feat.get(k) ?? { ledgers: 0, failLedgers: 0 };
      e.failLedgers += num(n) ?? 0;
      feat.set(k, e);
    }
  }
  // Eigene Beruehrung: wie viele der Ausfall-Ledger DIESES Knotens trugen das Feature, und wie
  // viele davon waren eine Divergenz auf einer anderen Linie.
  const myIncidentLedgers = new Map();
  for (const e of mine) {
    const f = facts.map.get(e.ledgerIndex);
    if (!f) continue;
    const keys = [...(f.amendments ?? []).map((a) => "amendment:" + a), ...(f.unlModify ? ["unl-modify"] : [])];
    for (const k of keys) {
      const cur = myIncidentLedgers.get(k) ?? { ledgers: 0, divergences: 0 };
      cur.ledgers += 1;
      myIncidentLedgers.set(k, cur);
    }
  }
  for (const row of divergences) for (const k of row.features) {
    const cur = myIncidentLedgers.get(k);
    if (cur) cur.divergences += 1;
  }
  const features = [...feat.entries()].map(([key, e]) => {
    const plainLedgers = Math.max(0, totalLedgers - e.ledgers);
    const plainFails = Math.max(0, incidentLedgers - e.failLedgers);
    const rateWith = e.ledgers > 0 ? e.failLedgers / e.ledgers : null;
    const rateWithout = plainLedgers > 0 ? plainFails / plainLedgers : null;
    const reliable = e.ledgers >= p.minFeatureLedgers && e.failLedgers >= p.minFeatureFails && plainLedgers >= p.minPlainLedgers;
    const mineRow = myIncidentLedgers.get(key) ?? { ledgers: 0, divergences: 0 };
    return {
      key, label: featureLabel(key), amendment: key.startsWith("amendment:") ? key.slice(10) : null, unlModify: key === "unl-modify",
      ledgers: e.ledgers, failLedgers: e.failLedgers, plainLedgers, plainFailLedgers: plainFails,
      rateWith, rateWithout, lift: rateWith !== null && rateWithout ? round(rateWith / rateWithout, 2) : null,
      reliable, note: reliable ? null : "sample-too-small",
      mineLedgers: mineRow.ledgers, mineDivergences: mineRow.divergences,
      mineLinked: mineRow.ledgers >= p.minMineLedgers,
    };
  }).sort((a, b) => (Number(b.mineLinked) - Number(a.mineLinked)) || (Number(b.reliable) - Number(a.reliable)) || ((b.lift ?? 0) - (a.lift ?? 0)) || a.key.localeCompare(b.key));
  const featureLinked = features.find((f) => f.reliable && f.lift !== null && f.lift >= 2 && f.mineDivergences > 0) ?? null;

  // Urteil: die starkste belegte Aussage, nicht die auffaelligste Formulierung.
  const lineageRecorded = voteHashRecorded || [...facts.map.values()].some((f) => f.acceptedHash !== null);
  const divergenceCount = mineLosing.reduce((a, r) => a + r.mineCount, 0);
  const dataGaps = [];
  if (!voteHashRecorded) dataGaps.push("hash-lineage-not-recorded");
  if (![...facts.map.values()].some((f) => f.acceptedHash !== null)) dataGaps.push("accepted-hash-not-recorded");
  if (featureDays === 0) dataGaps.push("feature-counters-not-recorded");
  if (!late.recorded) dataGaps.push("late-vote-lineage-not-recorded");

  // Die Reihenfolge ist die Staerke des Belegs, nicht die Auffaelligkeit:
  //   wiederholte Linie > geteilte Linie > zu duenne Stichprobe > Feature-Korrelation > Rest.
  // Eine wiederholte verlorene Linie braucht keine Mindestzahl an Vorfallen: drei identical
  // Abweichungen sind ein Befund, auch bei nur drei Vorfallen. Die Stichprobengrenze gilt fuer die
  // Aussagen, die eine Verteilung brauchen (Feature-Lift, "alles verschieden").
  // Ohne jede Abweichung ist die Spaet-Latenz die einzige aussagefaehige Linie: spaete Votes auf
  // der Netzmehrheit sind ein Pfadproblem, spaete Votes auf einer anderen Linie ein Standproblem.
  let verdict = "not-recorded";
  let reason = "hash-lineage-missing";
  let authority = "none";
  if (!lineageRecorded) { verdict = "not-recorded"; reason = "hash-lineage-missing"; }
  else if (divergenceCount === 0) {
    authority = "trace-hash-lineage";
    // "keine Abweichung gesehen" und "nicht hingesehen" sind zwei verschiedene Saetze. Der
    // Nenner ist der Anteil der eigenen Vorfaelle, deren Linie wirklich beurteilt werden konnte:
    // ein Vote-Hash dieses Knotens auf einem Ledger mit aufgezeichneter Netzmehrheit.
    const assessable = mine.filter((e) => e.recorded && e.votedHash && facts.map.get(e.ledgerIndex)?.acceptedHash).length;
    const coverage = incidentsTotal > 0 ? assessable / incidentsTotal : 0;
    if (late.total >= p.minIncidents && late.accepted > 0 && late.divergent === 0) { verdict = "tip-lag"; reason = "late-votes-on-accepted-lineage"; authority = "trace-late-votes"; }
    else if (coverage < p.minLineageCoverage) { verdict = "insufficient-sample"; reason = "incident-lineage-coverage"; }
    else { verdict = "clean"; reason = "no-divergence-recorded"; }
  }
  else if (repeated) { verdict = "deterministic-divergence"; reason = "same-losing-lineage"; authority = "trace-hash-lineage"; }
  else if (shared) { verdict = "shared-lineage"; reason = "shared-losing-lineage"; authority = "trace-hash-lineage"; }
  else if (divergenceCount < p.minIncidents) { verdict = "insufficient-sample"; reason = "too-few-divergences"; authority = "trace-hash-lineage"; }
  else if (featureLinked) { verdict = "feature-linked"; reason = "feature-linked-failures"; authority = "trace-feature-counters"; }
  else { verdict = "transient-divergence"; reason = "distinct-losing-lineages"; authority = "trace-hash-lineage"; }

  const guidance = [];
  const add = (g) => { if (!guidance.includes(g)) guidance.push(g); };
  if (verdict === "deterministic-divergence") { add("compare-node-build"); add("check-local-state"); }
  if (verdict === "shared-lineage") { add("compare-node-build"); add("check-peer-lineage"); }
  if (verdict === "feature-linked" || (featureLinked && verdict !== "deterministic-divergence")) { add("check-amendment-support"); }
  if (features.some((f) => f.unlModify && f.mineLedgers > 0)) add("check-unl-handling");
  if (verdict === "tip-lag" || late.accepted > 0) add("check-vote-path");
  if (lineages.own > 0 && !repeated) add("check-local-state");
  if (dataGaps.length) add("check-vote-path");

  return {
    verdict, verdictReason: reason, verdictAuthority: authority,
    coverage: {
      incidents: incidentsTotal, incidentsWithVoteHash: withVoteHash,
      minLineageCoverage: p.minLineageCoverage,
      assessableIncidents: mine.filter((e) => e.recorded && e.votedHash && facts.map.get(e.ledgerIndex)?.acceptedHash).length,
      incidentLineageCoverage: incidentsTotal > 0 ? Math.round((mine.filter((e) => e.recorded && e.votedHash && facts.map.get(e.ledgerIndex)?.acceptedHash).length / incidentsTotal) * 10000) / 10000 : null,
      ledgersWithAcceptedHash: [...facts.map.values()].filter((f) => f.acceptedHash !== null).length,
      daysWithLineage: facts.daysWithLineage,
      daysWithFeatureCounters: featureDays, daysWithoutFeatureCounters,
      daysWithLedgerFeatures: facts.daysWithFeatures,
      divergences: divergenceCount, distinctLosingLineages: mineLosing.length,
      lateVotes: late.total, lateVotesWithHash: late.rows.filter((r) => r.votedHash).length,
      totalLedgers, incidentLedgers,
    },
    lineageCounts: lineages,
    divergences: divergences.slice(0, p.topDivergences),
    losingLineages: losingRows.slice(0, p.topLineages),
    repeated: repeated ? { hash: repeated.hash, count: repeated.mineCount, masters: repeated.masters.slice(0, 12), ledgers: repeated.ledgers } : null,
    shared: shared ? { hash: shared.hash, count: shared.count, masterCount: shared.masterCount, masters: shared.masters, mineCount: shared.mineCount } : null,
    lateLineage: { recorded: late.recorded, total: late.total, accepted: late.accepted, divergent: late.divergent, unknown: late.unknown, rows: late.rows },
    features: features.slice(0, p.topFeatures),
    totalFeatures: features.length,
    guidance,
    dataGaps,
    thresholds: { minIncidents: p.minIncidents, minRepeated: p.minRepeated, minClusterMasters: p.minClusterMasters, minFeatureLedgers: p.minFeatureLedgers, minFeatureFails: p.minFeatureFails, minMineLedgers: p.minMineLedgers },
  };
}
