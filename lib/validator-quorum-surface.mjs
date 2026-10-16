// lib/validator-quorum-surface.mjs — die Risikoflaeche eines Validators: Ausfallrate je
// Quorum-Reserve und je Ledger-Last, inklusive der gemeinsamen Zellen beider Achsen.
//
// Warum diese Ebene existiert: quorumCriticality (lib/validator-diagnose.mjs) zaehlt nur Ledger
// MIT eigenem Ausfall. Ohne die Ledger derselben Bandbreite OHNE Ausfall ist die Frage
// "lag es an der Quorum-Knappe oder an meinem Knoten" nicht beantwortbar - jede Rate ware dann
// eine Selbstbestaetigung. Diese Engine nimmt den Nenner aus der Recorder-Achse
// (addQuorumSample / addRiskCell, lib/validator-trace.mjs), die fuer JEDES bewertete Ledger
// gefuellt wird.
//
// Was kein anderes XRPL-Werkzeug liefert: die Interaktion. "Last hoch" und "Quorum knapp" sind
// einzeln Erklaerungen; dass beide ZUSAMMEN schaeden, ist eine Netz- oder Lastaktion. Die
// gemeinsame Zelle vergleicht die beobachtete Ausfallrate gegen die, die Unabhaengigkeit beider
// Achsen vorhersagt (rowRate * colRate). Ein Wert ueber 1 heisst: die Kombination ist schlimmer
// als die Summe ihrer Teile.
import { LOAD_BUCKETS, LOAD_BUCKET_COUNT, MARGIN_BUCKET_COUNT, marginBucket, marginBucketLabel, loadBucket, loadBucketLabel } from "./validator-trace.mjs";

const SPAN = { "1h": 3600000, "24h": 86400000, "7d": 7 * 86400000, "30d": 30 * 86400000, all: Infinity };
const spanOf = (range) => SPAN[range] ?? 86400000;
const num = (x) => (Number.isFinite(Number(x)) ? Number(x) : null);
const round = (x, d = 4) => (Number.isFinite(x) ? Math.round(x * 10 ** d) / 10 ** d : null);

export const SURFACE_DEFAULTS = {
  minBandLedgers: 40,     // Bandbreite ohne Nenner ist keine Rate
  minBandMine: 3,         // unter drei eigenen Ausfaellen ist eine Haufung Zufall
  minCellLedgers: 12,     // gemeinsame Zelle braucht eigene Stichprobe
  hotConcentration: 1.5,  // Haefte der Anteil meiner Ausfaelle den der Ledger-Anteil -> Haufung
  dominantShare: 0.6,     // eine Achse erklaert 60 % meiner Ausfaelle
  secondaryShare: 0.35,   // beide Achse erklaeren je >= 35 % -> Wechselwirkung
  interactionLift: 1.5,   // gemeinsame Zelle >= 1,5 x Unabhaengigkeit
  thinMarginIdx: 2,       // Baender 0..2 = margin < 2 (Quorum knapp bis verfehlt)
  comfortableMarginIdx: 4, // Baender ab 4 = margin >= 3 (Netz hatte Reserve)
  highLoadIdx: 6,         // Stufen ab 6 = tx >= 400 (loadBucket(500) = 6, Stufe 5 ist 200-399)
  normalLoadIdx: 5,       // Stufen bis 5 = tx < 400
};

// Die Urteils-Mengen, die diese Engine erzeugen kann - exportiert, damit Uebersetzung und UI
// vollstaendig geprueft werden koennen statt stichprobenartig.
export const SURFACE_VERDICTS = ["quorum-bound", "load-bound", "both-bound", "node-bound", "mixed", "unknown"];
export const SURFACE_REASONS = ["quorum-axis-not-recorded", "no-own-failures", "thin-sample", "dominant-quorum", "dominant-load", "dominant-both", "dominant-comfort", "no-dominant-band"];
export const SURFACE_GAPS = ["quorum-axis-not-recorded", "quorum-axis-partial", "quorum-margin-missing-ledgers", "thin-sample", "interaction-sample"];
export const SURFACE_AXES = ["quorum", "load"];

function emptyBand() { return { l: 0, f: 0, mine: 0 }; }

// Achsen aus den Tagesdateien aufsummieren. Fehlende Achse != leere Achse: ein Tag aus einer
// aelteren Recorder-Fassung hat quorumBuckets nicht, und das ist eine Messluecke, nicht
// "Quorum war immer komfortabel".
function collect(days, master, { range, now }) {
  const span = spanOf(range);
  const from = span === Infinity ? -Infinity : now - span;
  const qb = Array.from({ length: MARGIN_BUCKET_COUNT }, emptyBand);
  const lb = Array.from({ length: LOAD_BUCKET_COUNT }, emptyBand);
  const cells = new Map();
  let daysTotal = 0;
  let daysWithQuorum = 0;
  let quorumMissing = 0;
  for (const d of Array.isArray(days) ? days : []) {
    // Das Fenster gilt auch hier: range ist ein Versprechen an den Leser, nicht nur ein Label.
    // Ein Tag, der VOR dem Fenster endet, darf die Rate nicht verschieben. Ueberlappt er mit
    // dem Fenster, bleibt er erhalten - der Aufrufer hat ihn schliesslich geladen.
    const dayStart = Date.parse(String(d.date ?? "") + "T00:00:00Z");
    if (Number.isFinite(dayStart) && dayStart + 86400000 <= from) continue;
    daysTotal += 1;
    const hasQuorum = d.quorumRecorded !== false && (Array.isArray(d.quorumBuckets) || d.quorumRecorded === true);
    if (hasQuorum) daysWithQuorum += 1;
    quorumMissing += num(d.quorumMissing) ?? 0;
    for (let i = 0; i < MARGIN_BUCKET_COUNT; i += 1) {
      const b = hasQuorum ? d.quorumBuckets[i] : null;
      if (!b) continue;
      qb[i].l += num(b.l) ?? 0;
      qb[i].f += num(b.f) ?? 0;
      qb[i].mine += (b.v && typeof b.v === "object") ? (num(b.v[master]) ?? 0) : 0;
    }
    for (let j = 0; j < LOAD_BUCKET_COUNT; j += 1) {
      const b = Array.isArray(d.loadBuckets) ? d.loadBuckets[j] : null;
      if (!b) continue;
      lb[j].l += num(b.l) ?? 0;
      lb[j].f += num(b.f) ?? 0;
      lb[j].mine += (b.v && typeof b.v === "object") ? (num(b.v[master]) ?? 0) : 0;
    }
    if (!hasQuorum || !Array.isArray(d.riskCross)) continue;
    for (const [k, c] of d.riskCross.entries()) {
      const idx = Number(k);
      if (!Number.isInteger(idx) || !c) continue;
      const e = cells.get(idx) ?? { n: 0, f: 0 };
      e.n += num(c.n) ?? 0;
      e.f += num(c.f) ?? 0;
      cells.set(idx, e);
    }
  }
  return { qb, lb, cells, daysTotal, daysWithQuorum, quorumMissing, from, now, span };
}

function rate(part, whole) { return whole > 0 ? part / whole : null; }

export function quorumSurface(days, master, { range = "7d", now = Date.now(), ...rest } = {}) {
  const p = { ...SURFACE_DEFAULTS, ...rest };
  const c = collect(days, master, { range, now });

  const ledgersQuorum = c.qb.reduce((a, b) => a + b.l, 0);
  const ledgersLoad = c.lb.reduce((a, b) => a + b.l, 0);
  const mineQuorum = c.qb.reduce((a, b) => a + b.mine, 0);
  const mineLoad = c.lb.reduce((a, b) => a + b.mine, 0);
  const overallMineRate = rate(mineQuorum, ledgersQuorum);

  const bands = [];
  for (let i = 0; i < MARGIN_BUCKET_COUNT; i += 1) {
    const b = c.qb[i];
    const shareOfLedgers = rate(b.l, ledgersQuorum);
    const shareOfMine = rate(b.mine, mineQuorum);
    const concentration = shareOfLedgers && shareOfMine !== null ? shareOfMine / shareOfLedgers : null;
    const reliable = b.l >= p.minBandLedgers && b.mine >= p.minBandMine;
    bands.push({
      axis: "quorum", idx: i, label: marginBucketLabel(i),
      ledgers: b.l, failLedgers: b.f, mineFails: b.mine,
      networkRate: round(rate(b.f, b.l)), mineRate: round(rate(b.mine, b.l)),
      overallMineRate: round(overallMineRate),
      shareOfLedgers: round(shareOfLedgers), shareOfMine: round(shareOfMine),
      concentration: round(concentration),
      reliable, hot: reliable && concentration !== null && concentration >= p.hotConcentration,
      note: reliable ? null : "thin-sample",
    });
  }
  for (let j = 0; j < LOAD_BUCKET_COUNT; j += 1) {
    const b = c.lb[j];
    const shareOfLedgers = rate(b.l, ledgersLoad);
    const shareOfMine = rate(b.mine, mineLoad);
    const concentration = shareOfLedgers && shareOfMine !== null ? shareOfMine / shareOfLedgers : null;
    const reliable = b.l >= p.minBandLedgers && b.mine >= p.minBandMine;
    bands.push({
      axis: "load", idx: j, label: loadBucketLabel(j),
      ledgers: b.l, failLedgers: b.f, mineFails: b.mine,
      networkRate: round(rate(b.f, b.l)), mineRate: round(rate(b.mine, b.l)),
      overallMineRate: round(overallMineRate),
      shareOfLedgers: round(shareOfLedgers), shareOfMine: round(shareOfMine),
      concentration: round(concentration),
      reliable, hot: reliable && concentration !== null && concentration >= p.hotConcentration,
      note: reliable ? null : "thin-sample",
    });
  }

  // Interaktion: gemeinsame Zelle gegen die Rate, die Unabhaengigkeit beider Achsen vorhersagt.
  const interactions = [];
  for (const [idx, cell] of c.cells) {
    const j = Math.floor(idx / MARGIN_BUCKET_COUNT);
    const i = idx % MARGIN_BUCKET_COUNT;
    if (j < 0 || j >= LOAD_BUCKET_COUNT) continue;
    const rowRate = rate(c.lb[j].f, c.lb[j].l);
    const colRate = rate(c.qb[i].f, c.qb[i].l);
    const observed = rate(cell.f, cell.n);
    const expected = rowRate !== null && colRate !== null ? rowRate * colRate : null;
    const reliable = cell.n >= p.minCellLedgers && rowRate !== null && colRate !== null && expected > 0 && observed !== null;
    interactions.push({
      loadIdx: j, marginIdx: i, loadLabel: loadBucketLabel(j), marginLabel: marginBucketLabel(i),
      ledgers: cell.n, failLedgers: cell.f,
      rate: round(observed), expected: round(expected),
      interaction: round(observed !== null && expected ? observed / expected : null),
      reliable,
      note: reliable ? null : "interaction-sample",
    });
  }
  interactions.sort((a, b) => (Number(b.reliable) - Number(a.reliable)) || ((b.interaction ?? 0) - (a.interaction ?? 0)) || a.loadIdx - b.loadIdx || a.marginIdx - b.marginIdx);

  const shares = {
    quorumShare: round(c.qb.slice(0, p.thinMarginIdx + 1).reduce((a, b) => a + b.mine, 0) / (mineQuorum || 1)),
    comfortableShare: round(c.qb.slice(p.comfortableMarginIdx).reduce((a, b) => a + b.mine, 0) / (mineQuorum || 1)),
    loadShare: round(c.lb.slice(p.highLoadIdx).reduce((a, b) => a + b.mine, 0) / (mineLoad || 1)),
    normalLoadShare: round(c.lb.slice(0, p.normalLoadIdx + 1).reduce((a, b) => a + b.mine, 0) / (mineLoad || 1)),
  };

  // Die Achse gilt als erfasst, sobald im Fenster messbare Quorum-Ledger stehen. Dass nicht
  // jeder Tag diese Achse hat, ist eine Abdeckungsfrage - kein Grund, 197 gemessene Ledger als
  // Messluecke auszugeben.
  const axisRecorded = c.daysWithQuorum > 0 && ledgersQuorum > 0;

  // Gruppen: dieselben Bandbereiche, aus denen die shares-Zeilen gebildet werden. Eine
  // Aussage ueber eine Achse darf nur auf einer Gruppe stehen, die fuer sich genommen
  // messbar ist, mit denselben Schwellen wie je Band. Ohne diese Pflicht behauptet das
  // Panel quorum-bound aus drei Ledgers und markiert dieselbe Zeile im selben Panel als
  // thin sample - ein Widerspruch, den der Leser nicht mehr aufloesen kann.
  const groupLedgers = {
    quorumThin: c.qb.slice(0, p.thinMarginIdx + 1).reduce((a, b) => a + b.l, 0),
    quorumComfort: c.qb.slice(p.comfortableMarginIdx).reduce((a, b) => a + b.l, 0),
    loadHigh: c.lb.slice(p.highLoadIdx).reduce((a, b) => a + b.l, 0),
    loadNormal: c.lb.slice(0, p.normalLoadIdx + 1).reduce((a, b) => a + b.l, 0),
  };
  const groupMine = {
    quorumThin: c.qb.slice(0, p.thinMarginIdx + 1).reduce((a, b) => a + b.mine, 0),
    quorumComfort: c.qb.slice(p.comfortableMarginIdx).reduce((a, b) => a + b.mine, 0),
    loadHigh: c.lb.slice(p.highLoadIdx).reduce((a, b) => a + b.mine, 0),
    loadNormal: c.lb.slice(0, p.normalLoadIdx + 1).reduce((a, b) => a + b.mine, 0),
  };
  const measurable = (group) => groupLedgers[group] >= p.minBandLedgers && groupMine[group] >= p.minBandMine;

  // Reihenfolge wie bisher: Zwei-Achsen-Aussage, dann Einzelachsen, dann beide Achsen.
  // Eine dominante Share auf einer duennen Gruppe ist kein Urteil: sie wird als Luecke
  // benannt, nicht zur naechstschwaecheren Aussage durchgewinkt.
  const claims = [
    { verdict: "node-bound", reason: "dominant-comfort", groups: ["quorumComfort", "loadNormal"],
      holds: () => shares.comfortableShare >= p.dominantShare && shares.normalLoadShare >= p.dominantShare },
    { verdict: "quorum-bound", reason: "dominant-quorum", groups: ["quorumThin"],
      holds: () => shares.quorumShare >= p.dominantShare },
    { verdict: "load-bound", reason: "dominant-load", groups: ["loadHigh"],
      holds: () => shares.loadShare >= p.dominantShare },
    { verdict: "both-bound", reason: "dominant-both", groups: ["quorumThin", "loadHigh"],
      holds: () => shares.quorumShare >= p.secondaryShare && shares.loadShare >= p.secondaryShare },
  ];
  let thinClaim = false;
  let verdict = "unknown";
  let verdictReason = "quorum-axis-not-recorded";
  if (axisRecorded) {
    if (mineQuorum === 0) { verdictReason = "no-own-failures"; }
    else if (ledgersQuorum < p.minBandLedgers || mineQuorum < p.minBandMine) { verdictReason = "thin-sample"; }
    else {
      const passing = claims.filter((cl) => cl.holds());
      const supported = passing.find((cl) => cl.groups.every(measurable));
      thinClaim = passing.some((cl) => !cl.groups.every(measurable));
      if (supported) { verdict = supported.verdict; verdictReason = supported.reason; }
      else if (passing.length) { verdictReason = "thin-sample"; }
      else { verdict = "mixed"; verdictReason = "no-dominant-band"; }
    }
  }

  const gaps = [];
  if (!axisRecorded) gaps.push("quorum-axis-not-recorded");
  else if (c.daysWithQuorum < c.daysTotal) gaps.push("quorum-axis-partial");
  if (c.quorumMissing > 0) gaps.push("quorum-margin-missing-ledgers");
  if (ledgersQuorum > 0 && mineQuorum > 0 && (ledgersQuorum < p.minBandLedgers || mineQuorum < p.minBandMine)) gaps.push("thin-sample");
  if (thinClaim) gaps.push("thin-sample");
  if (c.cells.size > 0 && !interactions.some((x) => x.reliable)) gaps.push("interaction-sample");

  return {
    master,
    range,
    thresholds: {
      minBandLedgers: p.minBandLedgers, minBandMine: p.minBandMine, minCellLedgers: p.minCellLedgers,
      hotConcentration: p.hotConcentration, dominantShare: p.dominantShare, secondaryShare: p.secondaryShare,
      interactionLift: p.interactionLift,
    },
    verdict,
    verdictReason,
    verdictAuthority: verdict === "unknown" ? "insufficient" : "measured",
    shares,
    overallMineRate: round(overallMineRate),
    bands,
    hotspots: bands.filter((b) => b.hot),
    interactions: interactions.slice(0, 6),
    coverage: {
      days: c.daysTotal,
      daysWithQuorumAxis: c.daysWithQuorum,
      quorumRecorded: axisRecorded,
      quorumMissing: c.quorumMissing,
      ledgersQuorum,
      ledgersLoad,
      ownFailLedgersByQuorum: mineQuorum,
      ownFailLedgersByLoad: mineLoad,
      cellsRecorded: c.cells.size,
      // Die vier Gruppen, nach denen das Urteil entschieden hat - damit das Panel die
      // Groeße der Beweisgrundlage neben das Urteil stellen kann statt nur die Share.
      bandGroups: Object.fromEntries(Object.keys(groupLedgers).map((g) => [g, {
        ledgers: groupLedgers[g], mineFails: groupMine[g], measurable: measurable(g),
      }])),
    },
    gaps,
  };
}
