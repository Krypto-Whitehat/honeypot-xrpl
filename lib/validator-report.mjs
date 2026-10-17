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
import { ABSENCE_TYPES, compareAbsences, groundScan, referenceWindow } from "./validator-truth.mjs";
import { measured } from "./validator-trace.mjs";

export const REPORT_RANGES = ["1h", "24h", "7d", "30d", "all"];
export const REPORT_DEFAULTS = { maxRows: 5000 };

// Spaltenreihenfolge ist Teil des Vertrags: ein Auswerter darf sich auf die Position verlassen.
export const REPORT_COLUMNS = [
  "ledgerIndex", "timeIso", "type", "scope", "affectedValidators", "peerFailures",
  "quorumVotes", "quorumNeeded", "quorumMargin", "runnerUpVotes",
  "txCount", "medianTx", "txRatio", "closeGapMs",
  "txShapeTags", "hypotheses", "hypothesisStrength", "guidance", "dataGaps",
  "seriesVerdict", "seriesLedgers", "seriesPosition",
  // Die Grenze der eigenen Erfassung und die Gegenprobe durch die Netz-Referenz. Ohne diese
  // Spalten stünde in der Tabelle nur affectedValidators - eine Zahl ueber diese Erfassung,
  // die wie eine Aussage ueber die Knoten gelesen wird. Die Spalten sagen, wie viel davon echt
  // sein kann und was die Referenz dazu sagt. Anhaengen statt einreihen: die bestehende
  // Position ist Teil des Vertrags und bleibt unveraendert.
  "captureGenuineAbsentMax", "captureArtifactMin",
  "groundVerdict", "groundReason", "groundClaims", "groundMissed", "groundTotal",
  "groundWindowHours", "groundFalsePositiveMin",
  // Die Namen hinter den Zahlen: affectedValidators ist eine Menge, erst die Keys machen eine
  // nachvollziehbare Spur. affectedMasters nennt jeden anderen betroffenen Knoten dieses Ledgers,
  // sameTypeMasters die Vergleichsgruppe mit demselben Vorfallstyp (dasselbe Problem, nicht nur
  // derselbe Ledger), captureOnlyMasters die Knoten, deren Eintrag ausschliesslich aus der eigenen
  // Erfassungsluecke stammt - also kein Knoten-Ausfall ist. Ohne diese Spalten waere der Export
  // weniger nachverfolgbar als die Oberflaeche, die dieselben Knoten bereits namentlich zeigt.
  "affectedMasters", "sameTypeMasters", "captureOnlyMasters",
];

const num = measured;
const iso = (ms) => (Number.isFinite(ms) ? new Date(ms).toISOString() : "");
const round = (v, d) => (Number.isFinite(v) ? Number(v.toFixed(d)) : null);

// Eine Hypothesenliste in zwei Spalten: die Tags und ihre Stärke, in derselben Reihenfolge.
// Getrennt, weil "drainer-fanout" und "no-correlated-cause" verschiedene Aussagen sind und ein
// Auswerter nicht raten soll, welche davon gemessen ist.
function hypothesisCells(hypotheses) {
  const list = Array.isArray(hypotheses) ? hypotheses : [];
  return [list.map((h) => h.tag).join(";"), list.map((h) => h.strength).join(";")];
}

function rowOf(r, truth) {
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
    captureGenuineAbsentMax: r.capture ? num(r.capture.genuineAbsentMax) : null,
    captureArtifactMin: r.capture ? num(r.capture.captureArtifactMin) : null,
    groundVerdict: truth.verdict,
    groundReason: truth.reason,
    groundClaims: truth.claims,
    groundMissed: truth.groundMissed,
    groundTotal: truth.groundTotal,
    groundWindowHours: truth.window ? truth.window.hours : null,
    groundFalsePositiveMin: num(truth.falsePositiveMin),
    // Getrennt durch Semikolon: ein Master enthaelt kein Komma, die Spaltenzahl bleibt pro Zeile
    // gleich. Eine leere Zelle ist hier eine Aussage (kein weiterer Knoten auf diesem Ledger),
    // kein fehlendes Feld - deshalb steht sie leer und nicht als Schaetzung.
    affectedMasters: r.affected ? (r.affected.peerMasters ?? []).join(";") : null,
    sameTypeMasters: r.affected ? (r.affected.sameTypeMasters ?? []).join(";") : null,
    captureOnlyMasters: r.affected ? (r.affected.captureOnlyMasters ?? []).join(";") : null,
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
const RANGE_HOURS = { "1h": 1, "24h": 24, "7d": 168, "30d": 720, all: Infinity };

export function validatorReport(days, master, { range = "7d", now = Date.now(), maxRows = REPORT_DEFAULTS.maxRows, clusters = [], ground = null } = {}) {
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
  // Gegenprobe ueber den eigenen Knoten: die Referenz nennt, wie viele Ledger dieser Knoten im
  // Fenster wirklich nicht validiert hat. Steht in diesem Report mehr, ist die Differenz ein
  // Beweis ueber die Erfassung, nicht ueber den Knoten. Ohne Referenz bleibt die Aussage offen
  // - ein Report ohne Gegenprobe duerfte nie als Entlastung gelesen werden.
  const rangeHours = RANGE_HOURS[range] ?? 24;
  const refWindow = referenceWindow(rangeHours);
  const absenceClaims = retrace.filter((r) => ABSENCE_TYPES.has(r.type))
    .map((r) => ({ master: m, ledgerIndex: r.ledgerIndex, timeMs: r.timeMs, type: r.type }));
  const truth = compareAbsences({
    master: m, claims: absenceClaims, scan: groundScan(ground, refWindow), rangeHours, hours: refWindow,
  });

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
  const rows = retrace.slice(0, maxRows).map((r) => rowOf(r, truth));
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
    truth,
    columns: REPORT_COLUMNS,
    rows,
  };
}
