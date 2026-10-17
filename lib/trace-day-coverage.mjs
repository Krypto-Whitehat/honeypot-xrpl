// lib/trace-day-coverage.mjs — Deckung der Stunden-Buckets gegen die Tageszaehler.
//
// Der Recorder fuehrt je Ledger zwei Zaehler: die Tageszaehler (d.validators) und die
// Stunden-Buckets (d.hourly). Er ist aber mitten am Tag 2026-10-09 mit den Stunden-Buckets
// eingestiegen: dieser Tag traegt Tageszaehler fuer 12.896 Knoten-Ledger, Stunden-Buckets nur
// fuer 8.239 — und alle 25 Vorfaelle dieses Tages liegen in der nicht gedeckten Zeit vor 11 Uhr.
// Liest ein Pfad nur die Stunden-Buckets, verliert er diese Ledger still: der Nenner wird zu
// klein, waehrend der Zaehler aus den zeitgestempelten Incidents voll bleibt. Bei xrp.vet macht
// das aus 6 missed / 41 no-quorum eine Peer-Aussage von 3 Ausfaellen — freundlicher, als die
// Messung ist.
//
// Diese Datei berechnet je Tag und Knoten den Anteil, der nur auf Tages-Koernung existiert:
//   Rest  = Tageszaehler − Stunden-Buckets desselben TAGES   (auf Tages-Koernung exakt)
//   Deckel = moegliche Ledger dieses Tages IM FENSTER − gemessene Ledger im FENSTER
//   gap   = Rest, hochstens bis zum Deckel (Typ-Mix des Rests bleibt erhalten)
// Ein Tag ohne Stunden-Buckets ergibt den vollen Tag (wie der bisherige Tages-Fallback), ein
// voll gedeckter Tag ergibt null. wholeDay sagt, ob der Tag ganz im Fenster liegt - nur dann ist
// ein Tages-Zaehler auch ein Fenster-Zaehler. Lesepfade fuehren gemessen und geschaetzt getrennt:
// geschaetzt ist nicht gemessen.

export const HOUR_MS = 3600000;
export const DAY_MS = 86400000;
export const COUNT_KEYS = ["ok", "partial", "missed", "wrongHash", "noQuorum"];

const num = (x) => (Number.isFinite(Number(x)) ? Number(x) : 0);
const countsOf = () => { const c = {}; for (const k of COUNT_KEYS) c[k] = 0; return c; };
const sumOf = (c) => COUNT_KEYS.reduce((s, k) => s + num(c?.[k]), 0);

// null / undefined / "" ist keine Zeitmarke. Number(null) ist 0 — das waere 1970 und damit ein
// erfundener Tag, kein fehlender.
export function msOf(v) {
  if (v === null || v === undefined || v === "") return null;
  const n = Number(v);
  return Number.isFinite(n) ? n : null;
}

// Die Zeitspanne, die dieser Tag wirklich abgedeckt hat. Ohne Close-Marken hilft nur der Datums-Tag.
export function daySpanOf(d) {
  const start = msOf(d?.firstMs) ?? Date.parse(String(d?.date ?? "") + "T00:00:00.000Z");
  const end = msOf(d?.lastMs) ?? (Number.isFinite(start) ? start + DAY_MS : NaN);
  return { start, end };
}

export function observedOf(c) { return sumOf(c); }

function addCounts(target, src, frac = 1) {
  for (const k of COUNT_KEYS) target[k] += num(src?.[k]) * frac;
  return target;
}

// Stunden-Buckets dieses Tages, anteilig am Fenster-Overlap, aufsummiert je Knoten.
export function hourlyByMaster(d, w) {
  const out = new Map();
  for (const [hk, hb] of Object.entries(d?.hourly ?? {})) {
    const h0 = Number(hk) * HOUR_MS;
    if (!Number.isFinite(h0)) continue;
    const ov = Math.min(h0 + HOUR_MS, w.to) - Math.max(h0, w.from);
    if (ov <= 0) continue;
    const frac = Math.min(1, ov / HOUR_MS);
    for (const [m, hv] of Object.entries(hb?.v ?? {})) {
      if (!out.has(m)) out.set(m, countsOf());
      addCounts(out.get(m), hv, frac);
    }
  }
  return out;
}

// Dieselben Buckets ohne Fenster-Kuerzung: die Gegenprobe auf Tages-Koernung.
function dayHourlyByMaster(d) {
  const out = new Map();
  for (const hb of Object.values(d?.hourly ?? {})) {
    for (const [m, hv] of Object.entries(hb?.v ?? {})) {
      if (!out.has(m)) out.set(m, countsOf());
      addCounts(out.get(m), hv);
    }
  }
  return out;
}

// Stunden dieses Tages ohne Bucket, innerhalb der nachweisbaren Zeitspanne. Die Incidents
// dieses Tages erweitern die Spanne: ohne Buckets ist der erste Close nicht bekannt, aber ein
// Vorfall um 00:28 beweist Aktivitaet in dieser Stunde. Erfundene Stunden entstehen nicht -
// nur Stunden innerhalb der belegten Spanne werden gezaehlt.
export function uncoveredHours(d) {
  const bucketed = new Set(Object.keys(d?.hourly ?? {}).map(Number));
  const { start, end } = daySpanOf(d);
  if (!Number.isFinite(start) || !Number.isFinite(end)) return { hours: [], span: null };
  let lo = start, hi = end;
  for (const i of d.incidents ?? []) {
    const t = msOf(i?.t);
    if (t === null) continue;
    if (t < lo) lo = t;
    if (t > hi) hi = t;
  }
  const hours = [];
  for (let h = Math.floor(lo / HOUR_MS); h <= Math.floor(hi / HOUR_MS); h += 1) {
    if (!bucketed.has(h)) hours.push(h);
  }
  return { hours, span: { start: lo, end: hi } };
}

// Der Rest je Knoten auf vollem Tag (unabhaengig vom Abfragefenster) samt den Stunden, in denen
// er passiert sein muss. profileCells braucht genau das als Nenner: Ledger, die gemessen wurden,
// aber in keinem Stunden-Bucket stehen.
export function dayResidual(d) {
  const { hours, span } = uncoveredHours(d);
  if (!span) return { gaps: new Map(), hours: [], hasHourly: false };
  const { gaps, hasHourly } = dayCoverageGaps(d, { from: span.start, to: span.end });
  return { gaps, hours, hasHourly };
}

export function dayCoverageGaps(d, w) {
  const empty = { gaps: new Map(), dayObserved: 0, hourlyObserved: 0, hasHourly: false, partial: false, wholeDay: false };
  const masters = Object.entries(d?.validators ?? {});
  if (!masters.length) return empty;
  const { start, end } = daySpanOf(d);
  if (!Number.isFinite(start) || !Number.isFinite(end)) return empty;
  const ovDay = Math.min(end, w.to) - Math.max(start, w.from);
  if (ovDay <= 0) return empty;
  const fracDay = Math.max(0, Math.min(1, ovDay / Math.max(1, end - start)));
  // wholeDay: der Tag liegt ganz im Fenster. Nur dann ist ein Tages-Zaehler auch ein
  // Fenster-Zaehler; Lesepfade, die Fenster-Genauigkeit versprechen, duerfen den Rest sonst nicht.
  const wholeDay = fracDay >= 1 - 1e-9;
  const covered = hourlyByMaster(d, w);
  const dayHour = dayHourlyByMaster(d);
  const hasHourly = Object.keys(d?.hourly ?? {}).length > 0;
  const gaps = new Map();
  let dayObserved = 0, hourlyObserved = 0, partial = false;
  for (const [m, v] of masters) {
    const cov = covered.get(m);
    hourlyObserved += sumOf(cov);
    // Ein Knoten mit Tageszaehlern, der in KEINEM Stunden-Bucket des Fensters steht, ist nicht
    // unbeobachtet, sondern in anderer Koernung erfasst. Ihn zusaetzlich zum Ledger-Zaehler der
    // Stunden zu zaehlen waere Doppelzaehlung - er bleibt aussen.
    if (hasHourly && !cov) continue;
    const rest = countsOf();
    let restObserved = 0;
    const dayTot = dayHour.get(m);
    for (const k of COUNT_KEYS) {
      const r = Math.max(0, num(v?.[k]) - (dayTot?.[k] ?? 0));
      rest[k] = r;
      restObserved += r;
    }
    if (restObserved <= 1e-9) continue;
    // Deckel: geschaetzt + gemessen darf nicht ueber das hinausgehen, was dieser Tag im Fenster
    // ueberhaupt sein kann. Sonst blaeht ein Teilmengen-Fenster die Stichprobe auf.
    const possible = COUNT_KEYS.reduce((s, k) => s + num(v?.[k]) * fracDay, 0);
    const room = Math.max(0, possible - sumOf(cov));
    if (room <= 1e-9) continue;
    const share = Math.min(1, room / restObserved);
    const gap = countsOf();
    for (const k of COUNT_KEYS) gap[k] = rest[k] * share;
    dayObserved += sumOf(gap);
    gaps.set(m, gap);
    partial = true;
  }
  return { gaps, dayObserved, hourlyObserved, hasHourly, partial, wholeDay };
}
// Luecke ZWISCHEN Tagesdateien: der Rekorder steht still, der naechste Tag spaeter beginnt.
// Diese Spanne steht in keiner Datei, die existiert. 2026-10-16 endet um 22:20:52Z, 2026-10-17
// beginnt um 01:49:22Z - 3 h 28 min, in denen kein Ledger bewertet wurde. Zaehlt nur die
// Spanne innerhalb einer Datei (uncoveredHours) oder die Lücken-Eintraege darin (gapLedgers),
// wirkt ein Rekorder-Stop wie nichts passiert. Eine Aussage ueber die Aufzeichnung muss lesbar
// bleiben, auch wenn die Aufzeichnung selbst fehlt.
//
// Grenze: 5 min. Darunter liegt der normale Abstand zwischen dem letzten Close eines Tages und
// dem ersten des naechsten (Bewertungs-Gnadenfrist plus Flush-Takt). Fehlende Zeitmarken
// ergeben keinen Abstand von null - sie ergeben keine Aussage. Ueberlappung ist keine Luecke.
export const DAY_HOLE_MS = 300000;

export function dayFileHoles(days) {
  const ordered = (Array.isArray(days) ? days : [])
    .filter((d) => d && typeof d.date === "string")
    .sort((a, b) => (a.date < b.date ? -1 : a.date > b.date ? 1 : 0));
  const holes = [];
  for (let i = 1; i < ordered.length; i += 1) {
    const prevEnd = msOf(ordered[i - 1].lastMs);
    const nextStart = msOf(ordered[i].firstMs);
    if (prevEnd === null || nextStart === null) continue;
    const ms = nextStart - prevEnd;
    if (ms <= DAY_HOLE_MS) continue;
    holes.push({
      from: prevEnd, to: nextStart, ms,
      between: ordered[i - 1].date + "->" + ordered[i].date,
      fromIso: new Date(prevEnd).toISOString(),
      toIso: new Date(nextStart).toISOString(),
    });
  }
  holes.sort((a, b) => b.ms - a.ms);
  return holes;
}

