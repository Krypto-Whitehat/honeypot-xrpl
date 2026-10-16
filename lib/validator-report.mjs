// lib/validator-report.mjs
//
// Selbst-Report eines dUNL-Validators: eine flache, maschinenlesbare Zeile je Vorfall.
//
// Warum diese Ebene existiert: das Overlay erklärt einen Vorfall dem Menschen. Ein Betreiber,
// der seinen Knoten dauerhaft beobachten will, braucht etwas, das er einem Cron, einer Tabelle
// oder seinem eigenen Monitoring geben kann - ohne das Overlay zu öffnen. Genau dafür ist der
// Report da: Retrace (lib/validator-retrace.mjs), Serien (lib/validator-diagnose.mjs),
// Quorum-Kritikalität und Last-Kurve sind schon da; ihnen fehlt nur die eine Ausgabe-Form.
//
// Die Zeile enthält immer BEIDES: die Ursache-Hypothesen mit ihrer Stärke (gemessen /
// korreliert / keine) und die Datenlücken genau dieses Vorfalls. Ein Report, der Lücken
// verschweigt, ist ein Report, der einen Betreiber in die falsche Richtung suchen lässt.
import { retraceForValidator, riskProfile } from "./validator-retrace.mjs";
import { failureRuns, loadResponseCurve, quorumCriticality, validatorFingerprint } from "./validator-diagnose.mjs";
import { attackImpact } from "./attack-impact.mjs";

export const REPORT_RANGES = ["1h", "24h", "7d", "30d", "all"];
export const REPORT_DEFAULTS = { maxRows: 5000 };

// Spaltenreihenfolge ist Teil des Vertrags: ein Auswerter darf sich auf die Position verlassen.
export const REPORT_COLUMNS = [
  "ledgerIndex", "timeIso", "type", "scope", "affectedValidators", "peerFailures",
  "quorumVotes", "quorumNeeded", "quorumMargin", "runnerUpVotes",
  "txCount", "medianTx", "txRatio", "closeGapMs",
  "txShapeTags", "hypotheses", "hypothesisStrength", "guidance", "dataGaps",
  "seriesVerdict", "seriesLedgers", "seriesPosition",
];

const num = (x) => (Number.isFinite(Number(x)) ? Number(x) : null);
const iso = (ms) => (Number.isFinite(ms) ? new Date(ms).toISOString() : "");
const round = (v, d) => (Number.isFinite(v) ? Number(v.toFixed(d)) : null);

// Eine Hypothesenliste in zwei Spalten: die Tags und ihre Stärke, in derselben Reihenfolge.
// Getrennt, weil "drainer-fanout" und "no-correlated-cause" verschiedene Aussagen sind und ein
// Auswerter nicht raten soll, welche davon gemessen ist.
function hypothesisCells(hypotheses) {
  const list = Array.isArray(hypotheses) ? hypotheses : [];
  return [list.map((h) => h.tag).join(";"), list.map((h) => h.strength).join(";")];
}

function rowOf(r) {
  const q = r.quorum ?? null;
  const l = r.load ?? null;
  const [tags, strength] = hypothesisCells(r.hypotheses);
  const shape = r.txShape && r.txShape.form ? Object.keys(r.txShape.form).length : null;
  const series = r.series ?? null;
  return {
    ledgerIndex: r.ledgerIndex,
    timeIso: iso(r.timeMs),
    type: r.type,
    scope: r.scope,
    affectedValidators: num(r.affected?.missed) + num(r.affected?.partial) + num(r.affected?.wrongHash) || 0,
    peerFailures: num(r.affected?.others) ?? 0,
    quorumVotes: q ? q.votes : null,
    quorumNeeded: q ? q.needed : null,
    quorumMargin: q ? q.margin : null,
    runnerUpVotes: q ? q.runnerVotes : null,
    txCount: l ? l.txCount : null,
    medianTx: l ? l.medianTx : null,
    txRatio: l ? round(l.ratio, 2) : null,
    closeGapMs: r.closeGapMs,
    txShapeTags: shape === null ? null : String(shape),
    hypotheses: tags,
    hypothesisStrength: strength,
    guidance: (r.guidance ?? []).join(";"),
    dataGaps: (r.dataGaps ?? []).join(";"),
    seriesVerdict: series ? series.verdict : null,
    seriesLedgers: series ? series.ledgers : null,
    seriesPosition: series ? series.position : null,
  };
}

const csvCell = (v) => {
  const s = v === null || v === undefined ? "" : String(v);
  return /[",\r\n]/.test(s) ? '"' + s.split('"').join('""') + '"' : s;
};

export function reportCsv(report) {
  const rows = report?.rows ?? [];
  const lines = [REPORT_COLUMNS.join(",")];
  for (const r of rows) lines.push(REPORT_COLUMNS.map((c) => csvCell(r[c])).join(","));
  return lines.join("\r\n") + "\r\n";
}

// Der Report: Zusammenfassung plus flache Zeilen. Alles aus bereits verifizierten Ebenen,
// keine eigene Diagnose-Logik - der Report ist eine Ansicht, kein zweites Urteil.
export function validatorReport(days, master, { range = "7d", now = Date.now(), maxRows = REPORT_DEFAULTS.maxRows, clusters = [] } = {}) {
  const m = String(master ?? "");
  if (!m) return { available: false, reason: "master-required" };
  const risk = riskProfile(days);
  const retrace = retraceForValidator(days, m, { range, now, risk });
  const runs = failureRuns(days, { master: m, range, now });
  const fingerprint = validatorFingerprint(days, m, { range, now });
  const quorum = quorumCriticality(days, m, { range, now });
  const load = loadResponseCurve(days, { master: m, range, now });
  // Die Angriffsseite fehlte dem Report: ein Betreiber sah seine Vorfaelle, aber nicht, ob sie in
  // Stunden fielen, in denen gleichzeitig Betrugs-Cluster liefen. Ohne Cluster urteilt die Engine
  // 'unknown' - das ist benanntes Unwissen, kein sauberer Befund.
  const impact = attackImpact(days, clusters, { range, now });

  const byType = { missed: 0, partial: 0, wrongHash: 0, noQuorum: 0 };
  const strength = { measured: 0, correlated: 0, cohort: 0, none: 0 };
  const gapCount = {};
  const scopeCount = { solo: 0, cohort: 0, network: 0, unknown: 0 };
  for (const r of retrace) {
    if (byType[r.type] !== undefined) byType[r.type] += 1;
    scopeCount[r.scope] = (scopeCount[r.scope] ?? 0) + 1;
    for (const h of r.hypotheses ?? []) strength[h.strength] = (strength[h.strength] ?? 0) + 1;
    for (const g of r.dataGaps ?? []) gapCount[g] = (gapCount[g] ?? 0) + 1;
  }
  const runList = Array.isArray(runs) ? runs : (runs?.runs ?? []);
  const rows = retrace.slice(0, maxRows).map(rowOf);
  return {
    available: true,
    master: m,
    range,
    generatedMs: now,
    coverage: risk.coverage ?? null,
    fingerprint: fingerprint ? { verdict: fingerprint.verdict, strength: fingerprint.strength ?? null, metrics: fingerprint.metrics ?? null } : null,
    quorum: quorum ?? null,
    load: load ?? null,
    impact: impact ? {
      verdict: impact.verdict ?? null,
      verdictAuthority: impact.verdictAuthority ?? null,
      verdictReason: impact.verdictReason ?? null,
      attackHours: impact.coverage?.attackCells ?? null,
      overlapHours: impact.coverage?.overlapCells ?? null,
      clustersInWindow: impact.coverage?.clustersInWindow ?? null,
    } : null,
    runs: {
      total: runList.length,
      longest: runList.reduce((a, r) => Math.max(a, num(r?.ledgers) ?? 0), 0),
    },
    summary: {
      incidents: retrace.length,
      byType,
      scope: scopeCount,
      hypotheses: strength,
      dataGaps: gapCount,
      truncated: retrace.length > maxRows,
    },
    columns: REPORT_COLUMNS,
    rows,
  };
}