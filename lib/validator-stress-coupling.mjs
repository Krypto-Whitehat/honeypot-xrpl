// lib/validator-stress-coupling.mjs - Last, Tx-Form und Massen-Ausfall an derselben Stelle.
//
// WELCHES PROBLEM DIESE EBENE LOEST:
// Die bisherige Angriffsseite (lib/attack-impact.mjs) vergleicht Stunden-Koerbe mit Ausfall-
// stunden, die Risikoflaeche (lib/validator-quorum-surface.mjs) vergleicht Last- und Quorum-
// BAENDER. Beide sagen, dass etwas zusammen vorkommt, aber keine sagt: in DIESEM Ledger, mit
// DIESEN Transaktionen, sind GENAU diese Knoten ausgefallen - und wie oft derselbe Knoten unter
// sonst identischer Last nicht ausgefallen ist. Genau diese ledger-genaue Gegenueberstellung
// entscheidet, ob ein Ausfall eine Netzaktion war (DDoS, Drainer-Faecherung, Orderbuch-Flut,
// Amendment-Umbau, Batch-Verstaerkung) oder ein Bug des eigenen Knotens.
//
// WIE GEGENPROBE OHNE SCHAETZUNG MOEGLICH IST:
// Der Rekorder schreibt eine Forensik-Zeile je Ledger MIT Abweichung. Eine Kopplung im Sinn von
// 'P(Ausfall | Signatur) gegen P(Ausfall | keine Signatur)' braucht dafuer nicht-signatur-
// Ledger als Kontrolle. Solange die Erfassung die nicht-signatur-Ledger nicht je Ledger hat,
// wird die Gegenprobe umgekehrt gefuehrt und bleibt arithmetisch sauber:
//   Kohorten-Seite: Ledger, in denen gleichzeitig viele Knoten abwichen, gegen Ledger, in denen
//     nur einer abwich - beide aus derselben erfassten Population. Signatur-Anteil in beiden
//     Gruppen, mit benannten Nennern.
//   Knoten-Seite: eigene Ausfall-Ledger mit Netzstress gegen eigene Ausfall-Ledger ohne
//     Netzstress, plus die Last-Bande mit vollem Nenner aus der Achse aller bewerteten Ledger.
// Sobald die Erfassung je Ledger auch die ruhigen Ledger traegt (stressRows im Rekorder), wird
// dieselbe Funktion auf die direkte Form umgestellt; bis dahin heisst die fehlende Kontrolle
// 'control-not-recorded' und nicht 'keine Kopplung'.
//
// WAS DIESE EBENE NICHT KANN:
// Sie beweist keine Kausalitaet. Sie misst, wie oft eine Ledger-Form mit einem Ausfall derselben
// Stelle zusammenfällt, wie oft sie NICHT zusammenfällt, und welche Ledger das sind. Jede Zahl
// hat ihren Nenner, jede Aussage ihre Autoritaet, jede Luecke ihren Namen.
import { SIGNATURE_TAGS } from "./tx-forensics.mjs";
import { loadBucket, loadBucketLabel, measured, TRACE_DEFAULTS } from "./validator-trace.mjs";
import { riskProfile } from "./validator-retrace.mjs";

const SPAN = { "1h": 3600000, "24h": 86400000, "7d": 7 * 86400000, "30d": 30 * 86400000, all: Infinity };
const HOUR_MS = 3600000;
const DAY_MS = 86400000;

export const COUPLING_DEFAULTS = {
  minSample: 8,             // darunter wird keine Rate ausgewiesen: ein Nenner von null ist offen
  minLift: 0.10,            // 10 Prozentpunkte Unterschied gelten als gemessene Kopplung
  weakLift: 0.04,           // darunter bleibt es eine Richtung ohne Substanz
  simultaneityNodes: 8,     // so viele dUNL-Knoten auf demselben Ledger heisst Massen-Abweichung
  massNodes: 15,            // ab hier ist die halbe beobachtete dUNL betroffen
  cadenceBreakFactor: 3,    // Close-Abstand >= 3 x eigener Median heisst Taktbruch
  peakRows: 6,              // benannte Massen-Ledger in der Antwort
  peakMasters: 40,          // benannte dUNL-Knoten je Massen-Ledger: deckt die vollstaendig
                            // beobachtete dUNL ab (35 Knoten am 2026-10-17). Eine Kurzung
                            // waehlt Knoten aus, statt sie zu nennen, und wird deshalb als
                            // Luecke 'cohort-masters-truncated' ausgewiesen, nie stillschweigend
  ledgerRows: 8,            // benannte Ledger je Signatur in der Antwort
  populationRows: 12,     // Zeilen der Bevoelkerungs-Achse in der Antwort
  trendMinBands: 4,         // darunter wird kein Dosis-Urteil gefaellt: zwei Haelfte brauchen zwei Baelnder
  trendRatio: 1.5,          // obere Haelfte / untere Haelfte ab hier gilt als steigende Dosis
};

// Die Urteils-Mengen. 'not-recorded' und 'insufficient-sample' sind verschiedene Aussagen:
// die eine sagt, die Ebene wurde nicht erfasst, die andere, sie wurde erfasst und hat zu wenig
// Nenner. Beides ist offen, aber die naechste Pruefung ist eine andere.
export const COUPLING_VERDICTS = new Set([
  "stress-coupled", "stress-linked-weak", "node-local-under-stress",
  "no-coupling-measured", "insufficient-sample", "not-recorded",
]);
export const COUPLING_AUTHORITIES = new Set(["measured", "derived", "none"]);

// Die Dosis-Urteile sind eine eigene Menge, nicht Teil der Kopplungs-Urteile: 'steigende Dosis'
// sagt etwas ueber die Lastachse, nichts ueber die Kopplung eines Knotens an eine Ledger-Form.
export const LOAD_TREND_VERDICTS = new Set([
  "load-dose-rising", "load-dose-flat", "load-dose-falling", "not-comparable", "insufficient-sample",
]);
// Die Achse, auf der das Urteil fiel. 'both' heisst: beide Achsen sind gemessen und keine
// zeigt eine Kopplung. 'sample' und 'none' heissen, dass ueberhaupt nicht gerechnet wurde.
export const COUPLING_AXES = new Set(["node", "mass", "network", "population", "both", "sample", "none"]);
export const COUPLING_GAPS = new Set([
  "forensics-row-missing", "control-not-recorded", "shape-not-recorded",
  "vote-latency-not-recorded", "cadence-not-recorded", "sample-too-small",
  "cohort-membership-derived", "cohort-masters-incomplete", "cohort-masters-truncated",
  "population-window-partial", "population-counters-missing",
  "population-counters-partial",
]);
// Die Stress-Seite eines Ledgers: die Tx-Signaturen des Forensik-Formators plus die drei
// Netz-Fakten, die dieselbe Quelle liefert (Laststufe, Close-Takt, erster Vote nach Close).
export const COUPLING_STRESS_TAGS = new Set([...SIGNATURE_TAGS, "load-extreme", "close-gap", "vote-latency-late"]);
export const COUPLING_TYPES = new Set(["missed", "partial", "wrong-hash", "vote-not-observed", "no-quorum"]);
// Die Kohorten-Zaehler derselben Forensik-Zeile heissen anders als die Vorfalls-Typen:
// missed / partial / wrongHash / noQuorum. Zwei Vokabeln in einer Menge zu vermengen war der
// Fehler, der in der Pruefung 'wrongHash' als unbekannt erscheinen liess.
export const COUPLING_COHORT_KEYS = new Set(["missed", "partial", "wrongHash", "noQuorum"]);

const ABSENCE_TYPES = new Set(["missed", "no-quorum", "vote-not-observed"]);

const rate = (part, whole) => (Number.isFinite(part) && Number.isFinite(whole) && whole > 0 ? part / whole : null);

// Die Stress-Fakten eines Ledgers, jede mit ihrem eigenen Beleg-Status. 'null' heisst hier
// 'dieser Ledger hat nichts davon aufgezeichnet', ein leeres Feld heisst 'geprueft, nichts
// gefunden' - die Unterscheidung ist der Grund, warum diese Ebene keine Schaetzungen kennt.
function stressOf(st, p) {
  const tags = Object.keys(st.sev ?? {}).filter((t) => COUPLING_STRESS_TAGS.has(t) || t.startsWith("type-burst:"));
  const gap = measured(st.gap), gmed = measured(st.gmed);
  const cadenceRecorded = gap !== null && gmed !== null && gmed > 0;
  const fv = measured(st.fv);
  return {
    txCount: measured(st.tx),
    medianTx: measured(st.med),
    loadBand: loadBucket(st.tx),
    loadLabel: loadBucketLabel(loadBucket(st.tx)),
    tags,
    sweep: st.sweep !== null && st.sweep !== undefined,
    amendment: Array.isArray(st.am) && st.am.length > 0,
    amendmentRecorded: Array.isArray(st.am),
    unl: st.unl === true,
    cadenceRecorded,
    cadenceBreak: cadenceRecorded ? gap >= p.cadenceBreakFactor * gmed : null,
    latencyRecorded: fv !== null,
    lateFirstVote: fv !== null ? fv > TRACE_DEFAULTS.graceMs : null,
    shapeRecorded: st.sh !== null && st.sh !== undefined,
  };
}

// Ein Ledger-Sample: die Stress-Seite, die Abweichungs-Seite und die Kohorten-Seite aus
// derselben Zeile. 'deviatingNodes' kommt aus den Typ-Zaehlern der Forensik-Zeile, nicht aus
// einer Schaetzung; ohne Zaehler ist die Kohorten-Seite nicht erfasst.
function sampleOf(st, ownType, cohortTypes, p) {
  const counts = cohortTypes ?? {};
  const nodes = Object.values(counts).reduce((a, x) => a + (measured(x) ?? 0), 0);
  const stress = stressOf(st, p);
  const stressPresent = stress.tags.length > 0 || stress.sweep || stress.amendment || stress.unl
    || stress.cadenceBreak === true || stress.lateFirstVote === true || stress.loadBand >= 5;
  return {
    ledgerIndex: measured(st.l), timeMs: measured(st.t),
    closureClosed: st.cl === true, captureGap: st.captureGap ?? null,
    votes: measured(st.v), needed: measured(st.need), topVotes: measured(st.top), margin: measured(st.mg),
    runnerVotes: measured(st.sp),
    stress, ownType: ownType ?? null,
    cohortTypes: counts, deviatingNodes: nodes, cohortRecorded: cohortTypes !== undefined,
    massDeviation: nodes >= p.simultaneityNodes,
    soloDeviation: nodes === 1,
    stressPresent,
  };
}

function windowOf(range, now) {
  const span = SPAN[range] ?? SPAN["24h"];
  return Number.isFinite(span) ? { from: now - span, to: now, hours: span / HOUR_MS } : { from: null, to: null, hours: null };
}

// Die Vorfaelle je Ledger, sortiert nach Ledger-Index: dieselbe Stelle, dieselben Knoten,
// dieselbe Form. Ohne diese Zuordnung waere jede Signatur eine Tageszahl.
function incidentsByLedger(days, master, window) {
  const byLedger = new Map();
  const own = new Map();
  for (const d of Array.isArray(days) ? days : []) {
    for (const i of d.incidents ?? []) {
      const l = measured(i.l ?? i.ledgerIndex);
      const t = measured(i.t ?? i.timeMs);
      if (l === null || t === null) continue;
      if (window.from !== null && (t < window.from || t > window.to)) continue;
      const m = i.m ?? i.master;
      if (!byLedger.has(l)) byLedger.set(l, new Map());
      const row = byLedger.get(l);
      const type = COUPLING_TYPES.has(i.type) ? i.type : "vote-not-observed";
      row.set(m, type);
      if (m === master) own.set(l, type);
    }
  }
  return { byLedger, own };
}

// Signatur gegen Last-Kontrolle: fuer jede Signatur die Ledger, in denen sie feuerte, und die
// Ledger mit derselben Laststufe, in der sie NICHT feuerte. Beide Gruppen stammen aus
// demselben erfassten Population, also ist der Unterschied eine gemessene Differenz und keine
// Auslese. 'controlRecorded' sagt, ob die Kontrolle ueberhaupt existiert.
function signatureCoupling(samples, p) {
  const byTag = new Map();
  for (const s of samples) {
    for (const tag of new Set(s.stress.tags)) {
      const e = byTag.get(tag) ?? { tag, exposed: [], control: [] };
      e.exposed.push(s);
      byTag.set(tag, e);
    }
  }
  const untaggedByBand = new Map();
  for (const s of samples) {
    if (s.stress.tags.length) continue;
    const list = untaggedByBand.get(s.stress.loadBand) ?? [];
    list.push(s);
    untaggedByBand.set(s.stress.loadBand, list);
  }
  const out = [];
  for (const { tag, exposed } of byTag.values()) {
    const bands = new Map();
    for (const s of exposed) bands.set(s.stress.loadBand, (bands.get(s.stress.loadBand) ?? 0) + 1);
    const control = [...bands.keys()].flatMap((b) => untaggedByBand.get(b) ?? []);
    const massExposed = exposed.filter((s) => s.massDeviation).length;
    const massControl = control.filter((s) => s.massDeviation).length;
    const rateExposed = rate(massExposed, exposed.length);
    const rateControl = rate(massControl, control.length);
    const lift = rateExposed !== null && rateControl !== null ? rateExposed - rateControl : null;
    const ownFailures = exposed.filter((s) => s.ownType !== null);
    const ownControl = control.filter((s) => s.ownType !== null);
    // Zwei Achsen, zwei Fragen: die Kohorten-Achse fragt, ob viele Knoten auf demselben
    // Ledger gleichzeitig abwichen (Netzaktion). Die Knoten-Achse fragt, ob DIESER Knoten
    // unter dieser Signatur oefter ausfiel als unter derselben Last ohne Signatur. Eine
    // Signatur kann auf einer Achse koppeln und auf der anderen nicht - das ist der Befund.
    const ownRateExposed = rate(ownFailures.length, exposed.length);
    const ownRateControl = rate(ownControl.length, control.length);
    const ownLift = ownRateExposed !== null && ownRateControl !== null ? ownRateExposed - ownRateControl : null;
    const controlRecorded = control.length > 0;
    const enough = exposed.length >= p.minSample && control.length >= p.minSample;
    const ownVerdict = !controlRecorded ? "not-recorded"
      : !enough ? "insufficient-sample"
        : ownLift >= p.minLift ? "stress-coupled"
          : ownLift >= p.weakLift ? "stress-linked-weak"
            : "no-coupling-measured";
    const types = {};
    for (const s of ownFailures) types[s.ownType] = (types[s.ownType] ?? 0) + 1;
    const verdict = !controlRecorded ? "not-recorded"
      : !enough ? "insufficient-sample"
        : lift >= p.minLift ? "stress-coupled"
          : lift >= p.weakLift ? "stress-linked-weak"
            : "no-coupling-measured";
    out.push({
      tag,
      ledgers: exposed.slice(0, p.ledgerRows).map((s) => s.ledgerIndex),
      ledgersTotal: exposed.length,
      controlLedgers: control.slice(0, p.ledgerRows).map((s) => s.ledgerIndex),
      controlTotal: control.length,
      loadBands: [...bands.entries()].sort((a, b) => a[0] - b[0]).map(([b, n]) => ({ band: b, label: loadBucketLabel(b), ledgers: n })),
      massDeviationExposed: massExposed, massDeviationControl: massControl,
      rateExposed, rateControl, lift,
      ownRateExposed, ownRateControl, ownLift, ownVerdict,
      ownFailures: ownFailures.length, ownFailureTypes: types,
      ownFailureLedgers: ownFailures.slice(0, p.ledgerRows).map((s) => s.ledgerIndex),
      cohortTypes: exposed.reduce((acc, s) => {
        for (const [k, v] of Object.entries(s.cohortTypes)) acc[k] = (acc[k] ?? 0) + (measured(v) ?? 0);
        return acc;
      }, {}),
      controlRecorded, verdict,
      authority: verdict === "stress-coupled" || verdict === "stress-linked-weak" || verdict === "no-coupling-measured"
        ? "measured" : verdict === "insufficient-sample" ? "derived" : "none",
    });
  }
  return out.sort((a, b) => (b.ownLift ?? -1) - (a.ownLift ?? -1)
    || (b.lift ?? -1) - (a.lift ?? -1)
    || (b.ownFailures - a.ownFailures)
    || (a.tag < b.tag ? -1 : 1));
}

// Massen-Abweichung je Ledger: die Zahl der Knoten, die dieser Rekorder auf GENAU diesem Ledger
// nicht sah, aufsteigend nach Betroffenheit. Die Peaks sind die Stellen, an denen eine Netz-
// aktion sichtbar wird - und die Stress-Fakten derselben Zeile sagen, was in dem Ledger war.
function simultaneity(samples, p, byLedger, master) {
  // Die benannten Knoten eines Massen-Ledgers: die Master aus der Incident-Zuordnung genau
  // dieses Ledgers. Der abgefragte Knoten steht vorn, weil die Tabelle die Frage dieses
  // Knotens beantwortet - aber nur, wenn er auf diesem Ledger wirklich abwich. Eine
  // sortierte Kante ohne ihn waere eine Auswahl, keine Auskunft.
  const named = (ledgerIndex) => {
    const row = byLedger ? byLedger.get(ledgerIndex) : null;
    if (!row) return { masters: [], total: null };
    const keys = [...row.keys()];
    const own = keys.includes(master) ? [master] : [];
    const full = [...own, ...keys.filter((m) => m !== master).sort()];
    return { masters: full.slice(0, p.peakMasters), total: full.length };
  }
  const histogram = new Map();
  for (const s of samples) {
    if (!s.cohortRecorded) continue;
    histogram.set(s.deviatingNodes, (histogram.get(s.deviatingNodes) ?? 0) + 1);
  }
  const peaks = samples.filter((s) => s.massDeviation)
    .sort((a, b) => b.deviatingNodes - a.deviatingNodes || (b.stress.txCount ?? 0) - (a.stress.txCount ?? 0) || a.ledgerIndex - b.ledgerIndex)
    .slice(0, p.peakRows)
    .map((s) => {
      const namedRow = named(s.ledgerIndex);
      return {
        ledgerIndex: s.ledgerIndex, timeMs: s.timeMs, deviatingNodes: s.deviatingNodes,
        cohortTypes: s.cohortTypes, txCount: s.stress.txCount, loadLabel: s.stress.loadLabel,
        signatures: s.stress.tags, sweep: s.stress.sweep, amendment: s.stress.amendment,
        unl: s.stress.unl, cadenceBreak: s.stress.cadenceBreak, lateFirstVote: s.stress.lateFirstVote,
        margin: s.margin, topVotes: s.topVotes, needed: s.needed, closureClosed: s.closureClosed,
        // Die Knoten selbst: dieselbe Forensik-Zeile, derselbe Ledger, dieselbe Uhrzeit. Die
        // Master kommen aus der Incident-Zuordnung desselben Ledgers - die betroffenen Knoten
        // sind damit benannt und belegt, nicht geschaetzt. mastersTotal ist der volle Nenner,
        // masters die benannte Teilkante (Cap peakMasters). Ist die Teilkante kuerzer als der
        // Nenner, fehlt ein Teil der Betroffenheit in der Antwort: namedTruncatedRows zaehlt
        // solche Ledger, namedMissingNodes zaehlt die Knoten, die dadurch ungenannt bleiben.
        masters: namedRow.masters,
        mastersTotal: namedRow.total,
      };
    });
  // Kurzung ist eine Luecke der Antwort, nicht der Erfassung: ein Peak, dessen benannte Kante
  // kuerzer ist als sein eigener Nenner, laesst abweichende Knoten ungenannt.
  const truncatedPeaks = peaks.filter((q) => Number.isFinite(q.mastersTotal) && q.masters.length < q.mastersTotal);
  const mass = samples.filter((s) => s.massDeviation);
  const solo = samples.filter((s) => s.soloDeviation);
  const taggedMass = mass.filter((s) => s.stress.tags.length > 0).length;
  const taggedSolo = solo.filter((s) => s.stress.tags.length > 0).length;
  return {
    histogram: [...histogram.entries()].sort((a, b) => a[0] - b[0]).map(([nodes, ledgers]) => ({ nodes, ledgers })),
    peaks,
    massLedgers: mass.length, soloLedgers: solo.length,
    signatureShareMass: rate(taggedMass, mass.length),
    signatureShareSolo: rate(taggedSolo, solo.length),
    signatureLift: rate(taggedMass, mass.length) !== null && rate(taggedSolo, solo.length) !== null
      ? rate(taggedMass, mass.length) - rate(taggedSolo, solo.length) : null,
    massThreshold: p.simultaneityNodes, massHighThreshold: p.massNodes,
    massHighLedgers: samples.filter((s) => s.deviatingNodes >= p.massNodes).length,
    namedTruncatedRows: truncatedPeaks.length,
    namedMissingNodes: truncatedPeaks.reduce((a, q) => a + (q.mastersTotal - q.masters.length), 0),
  };
}

// Der Fall, der einem Betreiber hilft: dieser Knoten fiel, die Kohorte fiel nicht, und der
// Ledger war trotzdem gestresst. Dann ist die naechste Pruefung der eigene Knoten - nicht das
// Netz. Die Gegenprobe ist der Anteil der eigenen Ausfall-Ledger mit Netzstress.
function nodeLocal(samples, p) {
  const own = samples.filter((s) => s.ownType !== null);
  const stressed = own.filter((s) => s.stressPresent);
  const quiet = own.filter((s) => !s.stressPresent);
  const soloStressed = stressed.filter((s) => s.soloDeviation);
  const types = {};
  for (const s of soloStressed) types[s.ownType] = (types[s.ownType] ?? 0) + 1;
  return {
    ownFailureLedgers: own.length,
    ownFailureLedgersWithStress: stressed.length,
    ownFailureLedgersWithoutStress: quiet.length,
    stressShare: rate(stressed.length, own.length),
    soloUnderStress: soloStressed.length,
    soloUnderStressTypes: types,
    soloUnderStressLedgers: soloStressed.slice(0, p.ledgerRows)
      .map((s) => ({ ledgerIndex: s.ledgerIndex, txCount: s.stress.txCount, signatures: s.stress.tags, type: s.ownType })),
    enough: own.length >= p.minSample,
  };
}

// Die Last-Achse mit vollem Nenner: die Achse aller bewerteten Ledger (loadBuckets) kennt
// Ledger OHNE Ausfall. Das ist die einzige Kontrolle, die die Erfassung heute schon je Laststufe
// liefert, und sie wird hier benannt statt durch die Ausfall-Ledger ersetzt.
function loadAxis(days, master, p) {
  const rows = [];
  let missing = 0;
  for (const d of Array.isArray(days) ? days : []) {
    const buckets = Array.isArray(d.loadBuckets) ? d.loadBuckets : null;
    if (!buckets) { missing += d.ledgers ?? 0; continue; }
    for (let i = 0; i < buckets.length; i += 1) {
      const b = buckets[i];
      if (!b) continue;
      const ledgers = measured(b.l) ?? 0;
      if (!ledgers) continue;
      const fails = measured(b.f) ?? 0;
      const own = measured(b.v?.[master]) ?? 0;
      const row = rows[i] ??= { band: i, label: loadBucketLabel(i), ledgers: 0, fails: 0, own: 0 };
      row.ledgers += ledgers; row.fails += fails; row.own += own;
    }
  }
  const list = rows.filter(Boolean).map((r) => ({
    ...r, networkRate: rate(r.fails, r.ledgers), ownRate: rate(r.own, r.ledgers),
    sample: r.ledgers >= p.minSample ? "measured" : "thin",
  }));
  return { rows: list, ledgersWithoutAxis: missing, recorded: list.length > 0, trend: loadTrend(list, p) };
}

// Die Dosis-Kurve: dieselbe Kohorten-Ausfallrate, verglichen ueber die Laststufen hinweg.
// Gerechnet wird nur ueber Baelnder mit vollem Nenner ('measured'); ein duennes Band traegt kein
// Urteil, weil seine Rate die Form des Bandes nicht erkennt. Das Urteil haengt an den zwei
// Haelften der Achse (untere Baelnder gegen obere Baelnder), nicht an einem einzelnen Paar -
// ein einzelnes Paar ist ein Zufall mit zwei Zahlen. Streng monoton wird berichtet, aber nicht
// verlangt: eine Achse mit einem einzigen Rueckgang ist trotzdem eine Kurve.
// Kein Kausalanspruch: gemessen ist, wie oft die Kohorte auf Ledgern dieser Groesse abwich, nicht
// dass die Groesse der Grund war. Der Nenner ist die Erfassung dieses Recorders.
function loadTrend(list, p) {
  const rows = list.filter((r) => r.sample === "measured" && Number.isFinite(r.networkRate));
  const total = rows.reduce((a, r) => ({ ledgers: a.ledgers + r.ledgers, fails: a.fails + r.fails, own: a.own + r.own }),
    { ledgers: 0, fails: 0, own: 0 });
  const base = {
    bandsMeasured: rows.length, bandsThin: list.length - rows.length,
    ledgersMeasured: total.ledgers, failsMeasured: total.fails, ownMeasured: total.own,
    rateMeasured: rate(total.fails, total.ledgers), ownRateMeasured: rate(total.own, total.ledgers),
  };
  const empty = {
    ...base, verdict: "insufficient-sample", steps: Math.max(rows.length - 1, 0),
    risingSteps: 0, fallingSteps: 0, monotone: null, lowBand: null, highBand: null, peakBand: null,
    ratio: null, lowerRate: null, upperRate: null, halfRatio: null,
  };
  if (rows.length < p.trendMinBands) return empty;
  let rising = 0, falling = 0;
  for (let i = 1; i < rows.length; i += 1) {
    const d = rows[i].networkRate - rows[i - 1].networkRate;
    if (d > 0) rising += 1; else if (d < 0) falling += 1;
  }
  const half = Math.floor(rows.length / 2);
  const sum = (rs) => rs.reduce((a, r) => ({ ledgers: a.ledgers + r.ledgers, fails: a.fails + r.fails }),
    { ledgers: 0, fails: 0 });
  const lower = sum(rows.slice(0, half));
  const upper = sum(rows.slice(rows.length - half));
  const lowerRate = rate(lower.fails, lower.ledgers);
  const upperRate = rate(upper.fails, upper.ledgers);
  const lowBand = rows[0];
  const highBand = rows[rows.length - 1];
  const peakBand = rows.reduce((a, r) => (r.networkRate > a.networkRate ? r : a), rows[0]);
  return {
    ...base,
    steps: rows.length - 1, risingSteps: rising, fallingSteps: falling,
    monotone: rising === rows.length - 1,
    lowBand, highBand, peakBand,
    ratio: lowBand.networkRate > 0 ? rate(highBand.networkRate, lowBand.networkRate) : null,
    lowerRate, upperRate,
    halfRatio: lowerRate !== null && lowerRate > 0 ? rate(upperRate, lowerRate) : null,
    verdict: (lowerRate === null || lowerRate <= 0 || upperRate === null) ? "not-comparable"
      : rate(upperRate, lowerRate) >= p.trendRatio ? "load-dose-rising"
        : rate(upperRate, lowerRate) <= 1 / p.trendRatio ? "load-dose-falling" : "load-dose-flat",
  };
}

// Die Bevoelkerungs-Achse: dieselbe Frage wie die zwei anderen, aber auf ALLEN erfassten
// Ledgern. Die Knoten- und die Massen-Achse koennen nur Ledger gegeneinander stellen, die eine
// Forensik-Zeile haben - und die schreibt der Rekorder nur je Abweichungs-Ledger und gedeckelt
// (LEDGER_STATS_CAP). Die Tageszaehler dagegen laufen ueber jedes bewertete Ledger:
// anomaly[tag] ist die Zahl der Ledger mit dieser Signatur, anomalyFail[tag] die Zahl davon mit
// mindestens einer Abweichung, ledgers und incidentLedgers dieselbe Population ohne die
// Signatur. Damit ist die Gegenprobe 'Ausfallrate mit Signatur gegen Ausfallrate ohne'
// eine Subtraktion gemessener Zaehler: keine Auswahl, keine Schaetzung, kein Rueckgriff auf
// die gekuerzten Zeilen. Das ist die direkte Form, die der Kopf dieser Datei verspricht.
// Die feinste Stufe dieser Zaehler ist der Tag. Ein Tag, der nur teilweise im Fenster liegt,
// traegt Zaehler von Ledgern ausserhalb des Fensters; er wird nicht anteilig gekuerzt (das
// waere eine Schaetzung), sondern ganz herausgenommen und als population-window-partial
// benannt. Ein Fenster kuerzer als ein ganzer Tag kann diese Achse nicht beantworten - es
// sagt 'not-recorded' und nicht 'keine Kopplung'.
const couplingTag = (tag) => COUPLING_STRESS_TAGS.has(tag) || String(tag).startsWith("type-burst:");

function populationCoupling(days, p, window) {
  const whole = [];
  const excluded = [];
  for (const d of Array.isArray(days) ? days : []) {
    const start = Date.parse(String(d?.date ?? "") + "T00:00:00.000Z");
    if (!Number.isFinite(start)) { excluded.push(d); continue; }
    if (window.from === null || (start >= window.from && start + DAY_MS <= window.to)) whole.push(d);
    else excluded.push(d);
  }
  const risk = whole.length ? riskProfile(whole, {
    minAnomalyLedgers: p.minSample, minAnomalyFails: 1, minPlainLedgers: p.minSample,
  }) : null;
  const rows = [];
  // Nur die Tags, die an derselben Stelle stehen wie die zwei anderen Achsen, duerfen hier
  // ein Kopplungs-Urteil tragen. Die uebrigen Bevoelkerungs-Zaehler (Lastspitze, Hash-Spaltung,
  // Amendment-Aktivitaet) fuehrt schon die Risikotafel; zweimal dasselbe beurteilen waere
  // keine zusaetzliche Auskunft, sondern eine zweite Zahl fuer denselben Befund.
  for (const r of risk?.rows ?? []) {
    if (!couplingTag(r.tag)) continue;
    const difference = r.rateWith !== null && r.rateWithout !== null ? r.rateWith - r.rateWithout : null;
    const enough = r.anomalyLedgers >= p.minSample && r.plainLedgers >= p.minSample;
    const verdict = !enough ? "insufficient-sample"
      : difference === null ? "not-recorded"
        : difference >= p.minLift ? "stress-coupled"
          : difference >= p.weakLift ? "stress-linked-weak"
            : "no-coupling-measured";
    rows.push({
      tag: r.tag,
      exposedLedgers: r.anomalyLedgers, exposedFailLedgers: r.anomalyFailLedgers,
      controlLedgers: r.plainLedgers, controlFailLedgers: r.plainFailLedgers,
      rateExposed: r.rateWith, rateControl: r.rateWithout, difference, relativeRisk: r.lift,
      verdict,
      authority: verdict === "stress-coupled" || verdict === "stress-linked-weak"
        || verdict === "no-coupling-measured" ? "measured"
        : verdict === "insufficient-sample" ? "derived" : "none",
    });
  }
  rows.sort((a, b) => (b.difference ?? -1) - (a.difference ?? -1)
    || (b.exposedLedgers - a.exposedLedgers) || (a.tag < b.tag ? -1 : 1));
  const axis = rows.some((r) => r.verdict === "stress-coupled") ? "stress-coupled"
    : rows.some((r) => r.verdict === "stress-linked-weak") ? "stress-linked-weak"
      : rows.some((r) => r.verdict === "no-coupling-measured") ? "no-coupling-measured"
        : rows.length ? "insufficient-sample" : "not-recorded";
  const gaps = [];
  if (excluded.length) gaps.push("population-window-partial");
  // Eine Ursache, ein Name: ohne ganzen Tag ist die Ursache der leeren Achse schon benannt.
  // Die Zaehler-Luecke gilt nur dort, wo ganze Tage im Fenster stehen und trotzdem kein
  // Tages-Zaehler hinter der Achse liegt - sonst stünden zwei Luecken fuer denselben Befund.
  if (!rows.length && whole.length) gaps.push("population-counters-missing");
  // Duenn, aber gerechnet: ganze Tage im Fenster, Tages-Zaehler nur an einem Teil dieser Tage.
  // Die Achse ist gemessen, ihre Grundgesamtheit nicht - das ist eine eigene benannte Luecke,
  // keine Abstufung des Urteils und keine stillschweigende Kuerzung des Nenners.
  else if (rows.length && (risk?.coverage?.daysWithAnomaly ?? 0) < whole.length) gaps.push("population-counters-partial");
  return {
    axis,
    rows: rows.slice(0, p.populationRows),
    rowsTotal: rows.length,
    coverage: {
      daysWhole: whole.length,
      daysExcluded: excluded.length,
      daysWithoutAnomaly: risk?.coverage?.daysWithoutAnomaly ?? null,
      ledgers: risk?.totalLedgers ?? 0,
      incidentLedgers: risk?.incidentLedgers ?? 0,
      baseRate: rate(risk?.incidentLedgers ?? 0, risk?.totalLedgers ?? 0),
    },
    gaps,
  };
}

export function stressCoupling(days, master, { range = "24h", now = Date.now(), opts = {} } = {}) {
  const p = { ...COUPLING_DEFAULTS, ...opts };
  const window = windowOf(range, now);
  const { byLedger, own } = incidentsByLedger(days, master, window);
  const samples = [];
  const gaps = new Set();
  let forensicsRows = 0, incidentLedgers = 0, truncated = false;
  for (const d of Array.isArray(days) ? days : []) {
    const stats = Array.isArray(d.ledgerStats) ? d.ledgerStats : [];
    if (d.ledgerStatsTruncated === true) truncated = true;
    for (const st of stats) {
      const l = measured(st?.l);
      if (l === null) continue;
      forensicsRows += 1;
      const t = measured(st.t);
      if (window.from !== null && t !== null && (t < window.from || t > window.to)) continue;
      const cohort = st.c ?? undefined;
      if (cohort === undefined) gaps.add("cohort-membership-derived");
      const devs = byLedger.get(l);
      if (devs) incidentLedgers += 1;
      samples.push(sampleOf(st, own.get(l) ?? null, cohort, p));
      if (st.sh === null || st.sh === undefined) gaps.add("shape-not-recorded");
      if (measured(st.fv) === null) gaps.add("vote-latency-not-recorded");
      if (!(measured(st.gap) !== null && measured(st.gmed) !== null && measured(st.gmed) > 0)) gaps.add("cadence-not-recorded");
    }
  }
  // Die Abweichungs-Ledger ohne Forensik-Zeile sind der Grund, warum diese Ebene heute offen
  // beginnt: ohne Zeile gibt es keine Form, keine Last, keine Kohorten-Zaehler an dieser Stelle.
  const unanswered = Math.max(0, byLedger.size - incidentLedgers);
  if (unanswered > 0) gaps.add("forensics-row-missing");
  const signatures = signatureCoupling(samples, p);
  const mass = simultaneity(samples, p, byLedger, master);
  // Gezaehlt und benannt ist nicht dasselbe: die Typ-Zaehler der Forensik-Zeile nennen die
  // Zahl der abweichenden Knoten, die Incident-Zuordnung nennt sie beim Namen. Ist die
  // benannte Menge kleiner, ist ein Teil der Betroffenheit nicht zurueckverfolgbar - und
  // das muss als Luecke dastehen, nicht als stillschweigende Teilkante.
  const namedIncomplete = samples.filter((s) => s.cohortRecorded && s.deviatingNodes > 0
    && (byLedger.get(s.ledgerIndex)?.size ?? 0) < s.deviatingNodes).length;
  if (namedIncomplete > 0) gaps.add("cohort-masters-incomplete");
  if (mass.namedTruncatedRows > 0) gaps.add("cohort-masters-truncated");
  const local = nodeLocal(samples, p);
  const load = loadAxis(days, master, p);
  const population = populationCoupling(days, p, window);
  for (const g of population.gaps) gaps.add(g);
  if (!samples.length) gaps.add("control-not-recorded");
  if (samples.length && samples.length < p.minSample) gaps.add("sample-too-small");

  // Die zwei Achsen getrennt zu beurteilen ist der Unterschied zwischen 'irgendwas hat
  // zusammen gepasst' und einer Aussage, die ein Betreiber pruefen kann: eine Netzaktion
  // trifft alle Knoten desselben Ledgers, ein Knotenfehler trifft einen allein.
  const networkLift = mass.signatureLift;
  const networkAxis = samples.length === 0 ? "not-recorded"
    : mass.massLedgers < p.minSample || mass.soloLedgers < p.minSample ? "insufficient-sample"
      : networkLift === null ? "not-recorded"
        : networkLift >= p.minLift ? "stress-coupled"
          : networkLift >= p.weakLift ? "stress-linked-weak"
            : "no-coupling-measured";
  const ownBest = signatures.find((s) => s.ownVerdict === "stress-coupled") ?? null;
  const ownWeak = signatures.find((s) => s.ownVerdict === "stress-linked-weak") ?? null;
  const massBest = signatures.find((s) => s.verdict === "stress-coupled") ?? null;
  const massWeak = signatures.find((s) => s.verdict === "stress-linked-weak") ?? null;
  const nodeAxis = ownBest ? "stress-coupled" : ownWeak ? "stress-linked-weak"
    : signatures.some((s) => s.ownVerdict === "no-coupling-measured") ? "no-coupling-measured"
      : local.enough ? "no-coupling-measured" : "insufficient-sample";
  const massAxis = massBest ? "stress-coupled" : massWeak ? "stress-linked-weak"
    : signatures.some((s) => s.verdict === "no-coupling-measured") ? "no-coupling-measured"
      : "insufficient-sample";
  // Verdikt, Begruendung und Achse kommen aus derselben Messung. Der Rangstreit entscheidet
  // nach Staerke und dann nach Lift, nie nach der Reihenfolge der Achsen. Ein Verdikt aus der
  // Massen-Achse mit einer Knoten-Begruendung war der Widerspruch, den die Akkuratz-Pruefung
  // an der Engine kritisiert hat.
  const findings = [];
  for (const r of population.rows) {
    if (r.verdict === "stress-coupled" || r.verdict === "stress-linked-weak")
      findings.push({ axis: "population", tag: r.tag, strength: r.verdict, lift: r.difference,
        exposedLedgers: r.exposedLedgers, controlLedgers: r.controlLedgers, failures: r.exposedFailLedgers });
  }
  for (const s of signatures) {
    if (s.ownVerdict === "stress-coupled" || s.ownVerdict === "stress-linked-weak")
      findings.push({ axis: "node", tag: s.tag, strength: s.ownVerdict, lift: s.ownLift,
        exposedLedgers: s.ledgersTotal, controlLedgers: s.controlTotal, failures: s.ownFailures });
  }
  for (const s of signatures) {
    if (s.verdict === "stress-coupled" || s.verdict === "stress-linked-weak")
      findings.push({ axis: "mass", tag: s.tag, strength: s.verdict, lift: s.lift,
        exposedLedgers: s.ledgersTotal, controlLedgers: s.controlTotal, failures: s.massDeviationExposed });
  }
  if (networkAxis === "stress-coupled" || networkAxis === "stress-linked-weak")
    findings.push({ axis: "network", tag: "signature-share-mass-vs-solo", strength: networkAxis,
      lift: networkLift, exposedLedgers: mass.massLedgers, controlLedgers: mass.soloLedgers,
      failures: mass.massLedgers });
  findings.sort((a, b) => (a.strength === b.strength ? (b.lift ?? -1) - (a.lift ?? -1)
    : a.strength === "stress-coupled" ? -1 : 1) || (a.tag < b.tag ? -1 : 1));
  const head = findings[0] ?? null;
  const verdict = !samples.length ? "not-recorded"
    : head ? head.strength
      : local.enough && local.soloUnderStress >= Math.max(2, Math.ceil(local.ownFailureLedgers * 0.5))
        ? "node-local-under-stress"
        : samples.length < p.minSample ? "insufficient-sample"
          : "no-coupling-measured";
  const verdictAuthority = verdict === "stress-coupled" || verdict === "stress-linked-weak"
    || verdict === "node-local-under-stress" || verdict === "no-coupling-measured" ? "measured"
    : verdict === "insufficient-sample" ? "derived" : "none";
  const bothMeasured = nodeAxis === "no-coupling-measured" && networkAxis === "no-coupling-measured";
  const verdictAxis = head ? head.axis
    : verdict === "not-recorded" ? "none"
      : verdict === "insufficient-sample" ? "sample"
        : verdict === "node-local-under-stress" ? "node"
          : bothMeasured ? "both" : "none";
  const signed = (v) => (v < 0 ? "minus-" : "plus-") + Math.abs(Math.round(v * 100)) + "-points";
  const verdictReason = !samples.length ? "no-ledger-forensics-row-in-this-window"
    : head ? head.axis + "-lift-" + signed(head.lift) + "-under-" + head.tag
      : verdict === "node-local-under-stress" ? "own-failures-under-stress-without-cohort"
        : verdict === "insufficient-sample" ? "fewer-ledger-rows-than-min-sample"
          : verdict === "no-coupling-measured" ? "measured-difference-below-weak-lift-on-both-axes"
            : "no-measurement-on-either-axis";

  return {
    master, range, window, thresholds: { minSample: p.minSample, minLift: p.minLift, weakLift: p.weakLift, simultaneityNodes: p.simultaneityNodes, massNodes: p.massNodes },
    coverage: {
      forensicsRows, forensicsRowsTruncated: truncated, deviatingLedgers: byLedger.size,
      deviatingLedgersWithRow: incidentLedgers, deviatingLedgersWithoutRow: unanswered,
      samples: samples.length, shapeRows: samples.filter((s) => s.stress.shapeRecorded).length,
      latencyRows: samples.filter((s) => s.stress.latencyRecorded).length,
      cadenceRows: samples.filter((s) => s.stress.cadenceRecorded).length,
      cohortRows: samples.filter((s) => s.cohortRecorded).length,
      namedMastersIncompleteRows: namedIncomplete,
      namedMastersTruncatedRows: mass.namedTruncatedRows,
      namedMastersMissingNodes: mass.namedMissingNodes,
      controlRecorded: samples.some((s) => s.stress.tags.length === 0),
      populationDaysWhole: population.coverage.daysWhole,
      populationDaysExcluded: population.coverage.daysExcluded,
      populationLedgers: population.coverage.ledgers,
      populationIncidentLedgers: population.coverage.incidentLedgers,
    },
    verdict, verdictReason, verdictAuthority, verdictAxis,
    axes: { node: nodeAxis, mass: massAxis, network: networkAxis, population: population.axis, networkLift },
    findings,
    signatures, simultaneity: mass, nodeLocal: local, loadAxis: load, population,
    gaps: [...gaps].sort(),
  };
}
