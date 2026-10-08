// lib/validator-trace.mjs — Validator-Trace: Ledger-genaue Auswertung der dUNL (rein, ohne I/O).
//
// Datenbasis: Validations-Stream (rippled, s1.ripple.com) + Ledger-Stream. Pro validiertem
// Ledger wird je dUNL-Mitglied bewertet:
//   ok           signiert den Quorum-Hash, full=true
//   partial      signiert den Quorum-Hash, aber full=false (Teilvalidierung)
//   wrong-hash   signiert einen anderen Hash für denselben Index (Fork-/Bug-Signal)
//   missed       keine Validierung für diesen Index innerhalb des Gnadenfensters
// Quorum: >= quorumFrac * dUNL-Größe Stimmen auf denselben Hash; sonst 'no-quorum'.
//
// URSACHEN: Der Stream zeigt WAS passiert ist, nicht WARUM. Die Reason-Tags sind KORRELATIONEN
// im selben Ledger (Lastspitze, Amendment-Aktivität, neuer Tx-Typ, UNL-Änderung). Sie sind
// Hinweise für die Untersuchung, keine bewiesenen Ursachen. Ohne passende Korrelation steht
// bewusst 'no-correlated-cause'.
//
// Schwellen sind TUNING-DEFAULTS (wie PEELING_THRESHOLDS), explizit ausgewiesen.
export const TRACE_DEFAULTS = {
  graceMs: 20000,       // Validierungen dürfen bis 20 s nach dem Close eintreffen
  quorumFrac: 0.8,      // 80 % der dUNL (XRPL-Quorum)
  spikeMinTx: 50,       // Lastspitze: mindestens 50 Tx ...
  spikeRatio: 3,        // ... und mindestens 3 × Median der letzten Ledger
  baselineSize: 60,     // rollende Basis (Ledger)
  maxPending: 2000,     // Speicherdeckel für offene Ledger
};

const isIndex = (x) => Number.isFinite(Number(x));
const median = (arr) => {
  if (!arr.length) return 0;
  const s = [...arr].sort((a, b) => a - b);
  const m = Math.floor(s.length / 2);
  return s.length % 2 ? s[m] : (s[m - 1] + s[m]) / 2;
};

// members: Master-Schlüssel der dUNL; ephemeralToMaster: Map Signierschlüssel -> Master
export function createTracker({ members, ephemeralToMaster, opts = {} }) {
  const o = { ...TRACE_DEFAULTS, ...opts };
  const memberSet = new Set(members);
  const quorum = Math.ceil(members.length * o.quorumFrac);
  const ledgers = new Map();      // index -> { hash, closeMs, txCount, amendments, unlModify, types }
  const votes = new Map();        // index -> Map(master -> { hash, full, t })
  const baseline = [];            // txCount der letzten Ledger
  let lastEvaluated = 0;
  let nonMemberSigners = 0;
  const knownTypes = new Set();   // Tx-Typen aus bereits bewerteten Ledgern (Neuheit)
  let evaluatedCount = 0;

  function onLedger(l) {
    const idx = Number(l?.ledgerIndex);
    if (!isIndex(idx)) return;
    ledgers.set(idx, {
      hash: l.hash ?? null,
      closeMs: Number(l.closeMs) || Date.now(),
      txCount: Number(l.txCount) || 0,
      amendments: Array.isArray(l.amendments) ? l.amendments : [],
      unlModify: l.unlModify === true,
      types: Array.isArray(l.types) ? l.types : null,
    });
    baseline.push(Number(l.txCount) || 0);
    while (baseline.length > o.baselineSize) baseline.shift();
    while (ledgers.size > o.maxPending) ledgers.delete(ledgers.keys().next().value);
  }

  function onValidation(v) {
    const idx = Number(v?.ledgerIndex);
    if (!isIndex(idx) || idx <= lastEvaluated) return;
    const master = ephemeralToMaster.get(v.signingKey) ?? (memberSet.has(v.signingKey) ? v.signingKey : null);
    if (!master || !memberSet.has(master)) { nonMemberSigners++; return; }
    if (!votes.has(idx)) votes.set(idx, new Map());
    votes.get(idx).set(master, { hash: v.ledgerHash, full: v.full !== false, t: Number(v.t) || Date.now() });
  }

  // Bewertet alle Ledger, deren Gnadenfenster abgelaufen ist. Liefert Ergebnisse in Index-Reihenfolge.
  function evaluate(nowMs = Date.now()) {
    const due = [...ledgers.entries()]
      .filter(([idx, l]) => idx > lastEvaluated && l.closeMs + o.graceMs <= nowMs)
      .sort((a, b) => a[0] - b[0]);
    const out = [];
    for (const [idx, l] of due) {
      const seen = votes.get(idx) ?? new Map();
      const tally = new Map();
      for (const v of seen.values()) tally.set(v.hash, (tally.get(v.hash) ?? 0) + 1);
      let top = null, topN = 0;
      for (const [h, n] of tally) if (n > topN) { top = h; topN = n; }
      const hasQuorum = top !== null && topN >= quorum;
      const med = median(baseline);
      const ctx = {
        hasQuorum,
        txCount: l.txCount,
        medianTx: med,
        amendments: l.amendments,
        unlModify: l.unlModify,
        // Neuheit erst nach Anlaufphase (200 Ledger), sonst ist jeder Typ neu.
        novelTypes: l.types && evaluatedCount >= 200 ? l.types.filter((t) => !knownTypes.has(t)) : [],
      };
      const incidents = [];
      let ok = 0;
      for (const m of members) {
        const v = seen.get(m);
        let type = null;
        if (!v) type = "missed";
        else if (hasQuorum && v.hash !== top) type = "wrong-hash";
        else if (!v.full) type = "partial";
        if (type) incidents.push({ master: m, type });
        else ok++;
      }
      const reasons = classifyReasons(ctx);
      out.push({
        ledgerIndex: idx,
        hash: top,
        closeMs: l.closeMs,
        txCount: l.txCount,
        medianTx: med,
        hasQuorum,
        validators: members.length,
        okCount: ok,
        detailNeeded: incidents.length > 0 && !l.types,
        incidents: incidents.map((i) => ({ ...i, reasons: reasonsFor(i.type, reasons) })),
      });
      if (l.types) for (const t of l.types) knownTypes.add(t);
      evaluatedCount++;
      // Detail (Tx-Typen/Amendments) wird später per attachDetail nachgereicht, wenn Incidents da sind.
      lastEvaluated = idx;
      votes.delete(idx);
      ledgers.delete(idx);
    }
    return out;
  }

  // Nachträgliche Ledger-Details (Tx-Typen, Amendments, UNL-Änderung) für ein bewertetes Ledger.
  // Wird nur für Ledger mit Incidents abgerufen. Setzt Korrelations-Tags und Neuheit neu.
  function attachDetail(result, detail) {
    if (!result || !detail) return result;
    const types = Array.isArray(detail.types) ? detail.types : [];
    const novel = evaluatedCount >= 200 ? types.filter((t) => !knownTypes.has(t)) : [];
    const tags = classifyReasons({
      hasQuorum: result.hasQuorum, txCount: result.txCount, medianTx: result.medianTx,
      amendments: detail.amendments ?? [], unlModify: detail.unlModify === true, novelTypes: novel,
    });
    for (const inc of result.incidents) inc.reasons = reasonsFor(inc.type, tags);
    for (const t of types) knownTypes.add(t);
    result.detailNeeded = false;
    return result;
  }

  return { attachDetail, onLedger, onValidation, evaluate, quorum, stats: () => ({ nonMemberSigners, pendingLedgers: ledgers.size, lastEvaluated }) };
}

// Ledger-Ebene: Korrelationen aus demselben Ledger.
export function classifyReasons(ctx) {
  const tags = [];
  if (!ctx.hasQuorum) tags.push("no-quorum");
  if (ctx.txCount >= TRACE_DEFAULTS.spikeMinTx && ctx.medianTx > 0 && ctx.txCount >= TRACE_DEFAULTS.spikeRatio * ctx.medianTx) tags.push("load-spike");
  if (ctx.amendments && ctx.amendments.length) tags.push("amendment-activity");
  if (ctx.unlModify) tags.push("unl-change");
  for (const t of ctx.novelTypes ?? []) tags.push("new-tx-type:" + t);
  return tags;
}

// Incident-Ebene: Ledger-Korrelationen plus Typ-spezifische Befunde.
export function reasonsFor(type, ledgerTags) {
  const tags = [...ledgerTags];
  if (type === "wrong-hash") tags.unshift("signed-different-hash");
  if (type === "partial") tags.unshift("partial-validation");
  if (type === "missed" && !ledgerTags.length) tags.push("no-correlated-cause");
  return tags;
}

// Muster über viele Incidents: welche Korrelation taucht wie oft, bei wie vielen Validatoren auf.
export function aggregatePatterns(incidents, { minCount = 3, minValidators = 2, minLedgers = 2 } = {}) {
  const byTag = new Map();
  for (const inc of incidents) {
    for (const tag of inc.reasons ?? []) {
      if (!byTag.has(tag)) byTag.set(tag, { tag, count: 0, validators: new Set(), ledgers: new Set(), types: {} });
      const e = byTag.get(tag);
      e.count++;
      e.validators.add(inc.master);
      e.ledgers.add(inc.ledgerIndex);
      e.types[inc.type] = (e.types[inc.type] ?? 0) + 1;
    }
  }
  const rows = [...byTag.values()].map((e) => ({
    tag: e.tag, count: e.count, validators: e.validators.size, ledgers: e.ledgers.size, types: e.types,
  }));
  rows.sort((a, b) => b.count - a.count);
  // Wiederkehrend heißt: über mehrere LEDGER verteilt. 13 Ausfälle im selben Ledger sind EIN Ereignis.
  const recurring = rows.filter((r) => r.count >= minCount && r.validators >= minValidators && r.ledgers >= minLedgers && r.tag !== "no-correlated-cause");
  return { tags: rows, recurring };
}
