// lib/validator-diagnose.mjs — Serien-, Kohorten- und Kritikalitaets-Ebene des Validator-Trace.
// Rein, ohne I/O. Eingabe: dieselben Tagesobjekte wie die Retrace (data/validator-trace).
//
// Die Retrace erklaert einen Vorfall INNERHALB seines Ledgers (Quorum-Marge, Last, Tx-Form,
// Betroffenheit anderer). Diese Ebene erklaert die Vorfaelle, bei denen der Ledger selbst nichts
// hergibt — und das ist gemessen der Loewenanteil. In den Aufzeichnungen vom 2026-10-08 bis
// 2026-10-16 (12.811 Vorfaelle, 115.214 Ledger) tragen 10.387 Vorfaelle "no-correlated-cause";
// davon liegen 10.278 (99,0 %) in einer Serie aufeinanderfolgender Ledger. Die Ursache steht
// also nicht im Ledger, sondern in der ZEITfolge: der Knoten war eine Zeitlang weg.
//
// Vier Blickwinkel, die die Ledger-Ebene nicht leisten kann:
//   1. Serie    — aufeinanderfolgende Ledger-Indizes desselben Validators. Trennt "Knoten war
//                 offline" von "Knoten hat genau diesen einen Ledger nicht geschafft".
//   2. Muster   — persoenliche Baseline desselben Validators gegen den Netzmedian: ein Knoten mit
//                 7,47 % Ausfallrate neben einem Median von 0,04 % ist kein Netzproblem.
//   3. Kohorte  — Validatoren, die ueber Tage hinweg fast ausschliesslich GEMEINSAM ausfallen.
//                 Gemeinsame Infrastruktur, gemeinsamer Upstream, gemeinsamer Betreiber.
//   4. Gewicht  — war das eigene Fehlen quorum-kritisch (Marge am Rand) oder folgenlos.
//
// Ehrliche Grenzen: Serien, Kohorten und Muster sind wiederholte Beobachtung, kein Beweis einer
// Ursache. Eine Serie allein sagt nicht WARUM der Knoten weg war. Wo die Aufzeichnung selbst
// fehlt (stream-gap), wird das als Datenlücke ausgewiesen, nie als "der Knoten war weg".
import { LOAD_BUCKETS, TRACE_DEFAULTS, captureBound, dayGapRanges, ledgerClosure, loadBucketLabel, parentGapCovered } from "./validator-trace.mjs";

export const DIAGNOSE_DEFAULTS = {
  runMinLedgers: 3,          // ab hier Serie/Ausfall-Fenster statt Einzelfall (~15 s am Stueck)
  runStrongLedgers: 12,      // ab hier eindeutig ein Fenster (~1 Minute am Stueck)
  coMinLedgers: 4,           // Kohortenpaar: mindestens so viele gemeinsame PRIVATE Ausfall-Ledger
  coMinLift: 4,              // und mindestens diese Abweichung von unabhaengigem Verhalten
  coMutualMin: 0.4,          // der Anteil muss beiden Knoten wehtun, nicht nur dem selteneren
  networkMinValidators: 5,   // ab so vielen betroffenen Knoten gilt ein Ledger als Netzereignis
  topClusters: 8,
  topPairs: 12,
  topRuns: 12,
  ceilingRate: 0.05,         // Laststufe: ab 5 % Ausfallanteil gilt die Stufe als nicht mehr gehalten
  ceilingMinLedgers: 20,     // darunter sind zu wenige Ledger in der Stufe fuer ein Urteil
  ceilingFactor: 2,          // Laststufe muss mindestens diese Vielfache der Normalbetriebs-Rate zeigen
  marginalMargin: 1,         // Quorum-Marge <= hier: das eigene Fehlen war randkritisch
  captureEventWindowMs: 120000, // Erfassungs-Ereignis gilt als in der Nahe, wenn es innerhalb
                                // dieses Zeitraums aufgezeichnet wurde (2 Minuten = mehrere
                                // Ledger-Takte mit Gnadenfenster; groesser waere Zuordnung per Zuruf)
  peakHours: 3,              // Stoßzeiten des Validators, die fuer das Muster zaehlen
};

const TYPES = ["missed", "partial", "wrongHash", "noQuorum"];
// Die Tagesdatei zaehlt je Validator auch ok. Der Nenner einer Ausfallrate MUSS alle
// aufgezeichneten Ledger dieses Knotens enthalten - nur die Fehler zu zaehlen ergaebe 100 %.
const COUNTER_KEYS = ["ok", ...TYPES];
const TYPE_OF = { missed: "missed", partial: "partial", "wrong-hash": "wrongHash", "no-quorum": "noQuorum", "vote-not-observed": "noQuorum" };
// Der Diagnose-Key noQuorum ist eine Sammelstelle der Zaehler, keine Aussage ueber das Netz.
// Auf einem bewiesen geschlossenen Ledger ist der ehrliche Name vote-not-observed (kein Vote
// DIESES Recorders erfasst); no-quorum bleibt dem Fall vorbehalten, dessen Schliessung
// ausdruecklich verneint ist. Ohne diese Trennung behauptet die Kritikalitaets-Tabelle
// Schliessung nicht belegt in genau derselben Zeile, die den von zwei Autoritaeten
// bestaetigten Schliess-Hash nennt - ein Widerspruch, den die Zeile selbst widerlegt.
function closureTypeName(type, closure) {
  if (type !== "noQuorum") return type;
  return closure && closure.closed === false ? "no-quorum" : "vote-not-observed";
}
const SPAN = { "1h": 3600000, "24h": 86400000, "7d": 7 * 86400000, "30d": 30 * 86400000, all: Infinity };
const num = (x) => (Number.isFinite(Number(x)) ? Number(x) : null);
const round = (x, d = 2) => (Number.isFinite(x) ? Math.round(x * 10 ** d) / 10 ** d : null);
const spanOf = (range) => SPAN[range] ?? 86400000;

function emptyCounts() { const c = {}; for (const t of TYPES) c[t] = 0; return c; }

// Die Urteils-Mengen, die diese Engine erzeugen kann. Exportiert, damit Uebersetzung und UI
// vollstaendig geprueft werden koennen statt stichprobenartig: ein Urteil ohne Label steht im
// Overlay als roher Schluessel - genau das unterscheidet ein Werkzeug von einer Bastelei.
export const FINGERPRINT_VERDICTS = ["clean", "network-driven", "chronic-outage", "solo-only", "outlier-node", "intermittent", "mixed"];
export const WINDOW_CLASSES = ["cohort-under-attack", "network-window", "targeted-under-load", "overlapping-outage", "targeted-outage"];
// Last-Urteile der Last-Ausfall-Kurve. Exportiert, damit jedes Urteil ein Label haben muss.
export const LOAD_VERDICTS = ["load-limited", "load-resilient", "always-failing", "unknown"];

// Alle Vorfaelle je Validator, nach Ledger-Index sortiert. Ein Validator kann je Ledger nur
// einen Vorfall haben (der Tracker meldt je Knoten und Ledger eine Abweichung).
export function incidentsByValidator(days, { range = "all", now = Date.now() } = {}) {
  const span = spanOf(range);
  const from = span === Infinity ? -Infinity : now - span;
  const out = new Map();
  for (const d of Array.isArray(days) ? days : []) {
    for (const i of d.incidents ?? []) {
      const t = num(i.t);
      if (t !== null && (t < from || t > now + 1)) continue;
      const list = out.get(i.m) ?? [];
      list.push({ ledgerIndex: i.l, timeMs: t, type: TYPE_OF[i.type] ?? i.type, reasons: i.r ?? [] });
      out.set(i.m, list);
    }
  }
  for (const list of out.values()) list.sort((a, b) => (a.ledgerIndex ?? 0) - (b.ledgerIndex ?? 0) || (a.timeMs ?? 0) - (b.timeMs ?? 0));
  return out;
}

// Aufgezeichnete Ledger eines Tages als Bereich, plus die bekannten Luecken darin.
// Braucht man, um eine Pause in einer Serie zu unterscheiden: validierte der Knoten zwischendurch
// wirklich, oder war die AUFZEICHNUNG weg? Ohne diese Unterscheidung wird aus einer Recorder-Luecke
// ein vorgetaeuschtes Ausfall-Fenster.
// Aufgezeichnete Ledger eines Tages. Die Datei fuehrt nur lastLedger und die Anzahl, nicht den
// ersten Ledger. Der laes sich exakt zurueckrechnen, weil jede verlorene Stelle als Luecke
// vermerkt ist: letzter - (aufgezeichnete + in Luecken verlorene) + 1. Das ist eine Rechnung,
// keine Schaetzung — und sie wird als abgeleitet ausgewiesen.
function recordedRanges(days) {
  const ranges = [];
  const gaps = [];
  for (const d of Array.isArray(days) ? days : []) {
    const last = num(d.lastLedger);
    const gapLedgers = (d.gaps ?? []).reduce((a, g) => a + (Number.isFinite(g.from) && Number.isFinite(g.to) ? g.to - g.from + 1 : 0), 0);
    const count = num(d.ledgers);
    const first = num(d.firstLedger) ?? (last !== null && count !== null ? last - count - gapLedgers + 1 : null);
    if (first !== null && last !== null && last >= first) ranges.push([first, last]);
    for (const g of d.gaps ?? []) if (Number.isFinite(g.from) && Number.isFinite(g.to)) gaps.push([g.from, g.to]);
  }
  return { ranges, gaps, derived: true };
}

function inRanges(ranges, x) { return ranges.some(([a, b]) => x >= a && x <= b); }

// War dieser Ledger aufgezeichnet? Unknown, wenn die Aufzeichnungsspanne des Tages nicht bekannt ist.
function ledgerRecorded(ranges, gaps, x) {
  if (gaps.some(([a, b]) => x >= a && x <= b)) return false;
  if (!ranges.length) return null;
  return inRanges(ranges, x);
}

// Serien desselben Validators: maximale Ketten aufeinanderfolgender Ledger-Indizes.
// diff == 1 ist absichtlich streng: ein Index dazwischen unterbricht die Serie, auch wenn der
// Validator dort nicht validierte — nur so bleibt "am Stueck weg" von "verstreut" trennbar.
export function failureRuns(days, { master = null, range = "all", now = Date.now(), ...rest } = {}) {
  const p = { ...DIAGNOSE_DEFAULTS, ...rest };
  const byVal = incidentsByValidator(days, { range, now });
  const { ranges, gaps } = recordedRanges(days);
  const perLedger = ledgerIncidents(days, { range, now });
  // Schliess-Beweis je Ledger aus der Forensik-Zeile (cl kommt aus dem validierten Stream).
  // Ohne diese Menge ist 'kein Quorum gesehen' ununterscheidbar von 'Netz ohne Quorum'.
  const closedLedgers = new Set();
  for (const d of Array.isArray(days) ? days : []) {
    for (const st of d.ledgerStats ?? []) if (st.cl === true && Number.isFinite(st.l)) closedLedgers.add(Number(st.l));
  }
  const runs = [];
  for (const [m, list] of byVal) {
    if (master && m !== master) continue;
    const uniq = [];
    for (const i of list) if (!uniq.length || uniq[uniq.length - 1].ledgerIndex !== i.ledgerIndex) uniq.push(i);
    let k = 0;
    while (k < uniq.length) {
      let j = k;
      while (j + 1 < uniq.length && uniq[j + 1].ledgerIndex === uniq[j].ledgerIndex + 1) j++;
      const seg = uniq.slice(k, j + 1);
      const len = seg.length;
      const fromL = seg[0].ledgerIndex, toL = seg[seg.length - 1].ledgerIndex;
      const t0 = seg[0].timeMs, t1 = seg[seg.length - 1].timeMs;
      const counts = emptyCounts();
      const reasons = new Map();
      for (const s of seg) {
        if (counts[s.type] !== undefined) counts[s.type] += 1;
        for (const r of s.reasons) reasons.set(r, (reasons.get(r) ?? 0) + 1);
      }
      const closedCount = seg.filter((s) => closedLedgers.has(Number(s.ledgerIndex))).length;
      // Andere Validatoren in denselben Ledgern: trennt eigenes Fenster von Netz-/Kohortenfenster.
      const co = new Map();
      let coLedgers = 0;
      for (const s of seg) {
        const others = (perLedger.get(s.ledgerIndex) ?? []).filter((x) => x.master !== m);
        if (others.length) coLedgers += 1;
        for (const o of others) co.set(o.master, (co.get(o.master) ?? 0) + 1);
      }
      // Pausen innerhalb der Kette gibt es per Konstruktion nicht; Pausen ZWISCHEN Ketten desselben
      // Validators sind die eigentliche Information: validierte er dazwischen, oder fehlte die Spur?
      const next = uniq[j + 1];
      let breakAfter = null;
      if (next) {
        const between = next.ledgerIndex - toL - 1;
        if (between > 0) {
          const checked = [];
          for (let x = toL + 1; x < next.ledgerIndex && checked.length < 8; x++) checked.push(ledgerRecorded(ranges, gaps, x));
          const gapInside = checked.some((c) => c === false);
          const validated = checked.length > 0 && checked.every((c) => c === true);
          breakAfter = { ledgers: between, cause: gapInside ? "recorder-gap" : validated ? "validated" : "unknown" };
        }
      }
      runs.push({
        master: m, fromLedger: fromL, toLedger: toL, ledgers: len,
        firstMs: t0, lastMs: t1,
        durationMs: t0 !== null && t1 !== null ? t1 - t0 : null,
        counts, typesSeen: TYPES.filter((t) => counts[t] > 0),
        reasons: [...reasons.entries()].sort((a, b) => b[1] - a[1]).slice(0, 6).map(([tag, n]) => ({ tag, ledgers: n })),
        coValidators: [...co.entries()].sort((a, b) => b[1] - a[1]).slice(0, 8).map(([v, n]) => ({ master: v, ledgers: n })),
        coLedgers, coShare: len > 0 ? coLedgers / len : null,
        isolated: len === 1,
        breakAfter,
        closedLedgers: closedCount,
        verdict: runVerdict(len, counts, coLedgers, p, closedCount),
      });
      k = j + 1;
    }
  }
  runs.sort((a, b) => (b.ledgers - a.ledgers) || (b.lastMs ?? 0) - (a.lastMs ?? 0));
  return runs;
}

// Einordnung einer Serie — nach Dauer, Typmix und gleichzeitiger Betroffenheit anderer.
function runVerdict(len, counts, coLedgers, p, closedCount = 0) {
  if (len === 1) {
    if (counts.wrongHash > 0) return "hash-divergence";
    // Der Einzel-Fall ohne Quorum ist eine Erfassungs-Beobachtung, kein Netz-Befund: dieser
    // Ledger ist aus dem validierten Stream bewiesen geschlossen (lib/validator-trace.mjs).
    if (counts.noQuorum > 0) return "vote-not-observed";
    if (counts.partial > 0) return "degraded-single";
    return "isolated-miss";
  }
  const share = len > 0 ? coLedgers / len : 0;
  if (share >= 0.5) return "cohort-window";
  // Typmix vor Laenge: der Typ nennt den Mechanismus, die Laenge nur die Dauer.
  // 'noQuorum' ist der Zaehler DIESES Recorders, nicht das Urteil des Netzes. Ist jeder Ledger
  // der Serie als geschlossen belegt, hat das Netz sein Quorum erreicht - die Serie ist dann ein
  // Erfassungs-Fenster des Recorders, keine Netzstockung. Ohne Schliess-Beweis bleibt die Frage
  // offen und die bisherige Klasse steht, weil nichts geraten wird.
  if (counts.noQuorum === len) return closedCount === len ? "capture-window" : "network-window";
  if (counts.partial === len) return "degraded-window";
  if (len >= p.runStrongLedgers) return "offline-window";
  if (len >= p.runMinLedgers) return "brief-outage";
  // Zwei Ledger am Stueck bleiben unter runMinLedgers: bei ~4-5 s je Ledger ist das noch kein
  // Ausfallfenster, sondern Rauschen. Real gemessen: 2 von 1703 Serien in 9 Tagen.
  return "short-series";
}

// Vorfaelle je Ledger (alle Validatoren), fuer Betroffenheit und Kohortenbildung.
export function ledgerIncidents(days, { range = "all", now = Date.now() } = {}) {
  const span = spanOf(range);
  const from = span === Infinity ? -Infinity : now - span;
  const out = new Map();
  for (const d of Array.isArray(days) ? days : []) {
    for (const i of d.incidents ?? []) {
      const t = num(i.t);
      if (t !== null && (t < from || t > now + 1)) continue;
      const list = out.get(i.l) ?? [];
      list.push({ master: i.m, type: TYPE_OF[i.type] ?? i.type, reasons: i.r ?? [] });
      out.set(i.l, list);
    }
  }
  return out;
}

// Aufgezeichnete Ledger je Validator (Nenner der persoenlichen Rate).
function ledgersPerValidator(days) {
  const out = new Map();
  for (const d of Array.isArray(days) ? days : []) {
    for (const [m, v] of Object.entries(d.validators ?? {})) {
      if (!v || typeof v !== "object") continue;
      const tot = COUNTER_KEYS.reduce((a, t) => a + (num(v[t]) ?? 0), 0);
      out.set(m, (out.get(m) ?? 0) + tot);
    }
  }
  return out;
}

// Persoenliches Muster eines Validators: eigene Rate gegen Netz und Median, Serienanteil,
// Stoßzeiten, Typmix. Das ist die Antwort auf "ist das ein Netzproblem oder MEIN Problem".
export function validatorFingerprint(days, master, { range = "all", now = Date.now(), ...rest } = {}) {
  const p = { ...DIAGNOSE_DEFAULTS, ...rest };
  const byVal = incidentsByValidator(days, { range, now });
  const ledgers = ledgersPerValidator(days);
  const all = [...byVal.values()].flat();
  const totalLedgers = [...ledgers.values()].reduce((a, b) => a + b, 0);
  const list = byVal.get(master) ?? [];
  const ownLedgers = num(ledgers.get(master)) ?? 0;
  const rate = ownLedgers > 0 ? list.length / ownLedgers : null;
  const networkRate = totalLedgers > 0 ? all.length / totalLedgers : null;
  const rates = [...ledgers.keys()].map((m) => {
    const l = num(ledgers.get(m)) ?? 0, f = (byVal.get(m) ?? []).length;
    return l > 0 ? f / l : 0;
  }).sort((a, b) => a - b);
  const medianRate = rates.length ? rates[Math.floor(rates.length / 2)] : null;

  const counts = emptyCounts();
  for (const i of list) if (counts[i.type] !== undefined) counts[i.type] += 1;

  const runs = failureRuns(days, { master, range, now, ...rest });
  const inSeries = runs.filter((r) => r.ledgers >= p.runMinLedgers).reduce((a, r) => a + r.ledgers, 0);
  const longest = runs.find((r) => r.ledgers >= 2) ?? null;

  // Stoßzeiten aus den Stundenzaehlern: ein Knoten, der nur nachts ausfaellt, hat ein Wartungsfenster.
  const hours = new Map();
  for (const d of Array.isArray(days) ? days : []) {
    for (const [hk, hb] of Object.entries(d.hourly ?? {})) {
      const h = num(hk);
      if (h === null) continue;
      const e = hours.get(h) ?? { hour: h, ledgers: 0, incidents: 0 };
      e.ledgers += num(hb?.l) ?? 0;
      const v = hb?.v?.[master];
      if (v && typeof v === "object") e.incidents += TYPES.reduce((a, t) => a + (num(v[t]) ?? 0), 0);
      hours.set(h, e);
    }
  }
  const hourRows = [...hours.values()].filter((e) => e.incidents > 0)
    .map((e) => ({ ...e, rate: e.ledgers > 0 ? e.incidents / e.ledgers : null, utcHour: new Date(e.hour * 3600000).getUTCHours() }))
    .sort((a, b) => b.incidents - a.incidents);
  const peakIncidents = hourRows.slice(0, p.peakHours).reduce((a, e) => a + e.incidents, 0);
  const byUtc = new Map();
  for (const e of hourRows) {
    const r = byUtc.get(e.utcHour) ?? { utcHour: e.utcHour, incidents: 0, hours: 0 };
    r.incidents += e.incidents; r.hours += 1; byUtc.set(e.utcHour, r);
  }
  const peakUtcHours = [...byUtc.values()].sort((a, b) => b.incidents - a.incidents).slice(0, 4);

  const seriesShare = list.length ? inSeries / list.length : null;
  const isolated = runs.filter((r) => r.ledgers === 1).length;
  // Netzanteil: wie viel der eigenen Ausfaelle auf Ledger faellt, an denen fast das ganze Netz
  // fiel. Ein Knoten mit 80 % Netzanteil hat kein eigenes Problem - er ist ein Gesunder im Netz.
  const split = failureSplit(days, { range, now, networkMinValidators: p.networkMinValidators });
  const own = split.rows.find((r) => r.master === master) ?? null;
  const verdict = !list.length ? "clean"
    : own && own.networkShare !== null && own.networkShare >= 0.8 ? "network-driven"
      : seriesShare !== null && seriesShare >= 0.6 ? "chronic-outage"
      : own && own.privateLedgers > 0 && own.networkLedgers === 0 ? "solo-only"
      : rate !== null && medianRate !== null && medianRate > 0 && rate >= 10 * medianRate ? "outlier-node"
        : isolated >= list.length * 0.6 ? "intermittent"
          : "mixed";

  return {
    master,
    ledgers: ownLedgers,
    incidents: list.length,
    rate,
    networkRate,
    medianRate,
    ratioVsMedian: rate !== null && medianRate ? rate / medianRate : null,
    ratioVsNetwork: rate !== null && networkRate ? rate / networkRate : null,
    counts,
    seriesShare,
    isolatedIncidents: isolated,
    longestRun: longest ? { ledgers: longest.ledgers, durationMs: longest.durationMs, fromLedger: longest.fromLedger, toLedger: longest.toLedger } : null,
    peakHours: hourRows.slice(0, p.peakHours),
    peakUtcHours,
    peakShare: list.length ? peakIncidents / list.length : null,
    networkLedgers: own?.networkLedgers ?? 0,
    privateLedgers: own?.privateLedgers ?? 0,
    networkShare: own?.networkShare ?? null,
    verdict,
  };
}

// Aufgezeichnete Vorfaelle je Ledger, pro Knoten nur einmal.
function uniquePerLedger(perLedger) {
  const out = new Map();
  for (const [ledger, list] of perLedger) out.set(ledger, new Set(list.map((i) => i.master)));
  return out;
}

// Zwei Ledger-Klassen, die man trennen MUSS:
//   Netzereignis — viele Knoten gleichzeitig. Sagt etwas ueber das Netz, nicht ueber die Knoten.
//   privat       — ein oder wenige Knoten. Hier (und nur hier) steckt geteilte Infrastruktur.
// Wer beides zusammen zaehlt, findet einen Cluster von fast allen Validatoren und haelt ein
// Netzereignis fuer gemeinsame Infrastruktur. Genau das war der erste Messfehler dieser Ebene.
function splitLedgers(uniq, minValidators) {
  const network = new Map();
  const priv = new Map();
  for (const [ledger, set] of uniq) (set.size >= minValidators ? network : priv).set(ledger, set);
  return { network, private: priv };
}

function ledgerSetsByValidator(map) {
  const out = new Map();
  for (const [ledger, set] of map) for (const v of set) {
    const s = out.get(v) ?? new Set();
    s.add(ledger); out.set(v, s);
  }
  return out;
}

// Anteil der eigenen Ausfaelle, der in Netzereignissen liegt. Das ist die Trennung zwischen
// "mein Knoten ist krank" und "mein Knoten ist gesund und faellt nur, wenn das Netz wackelt".
export function failureSplit(days, { range = "all", now = Date.now(), networkMinValidators = DIAGNOSE_DEFAULTS.networkMinValidators } = {}) {
  const { network, private: priv } = splitLedgers(uniquePerLedger(ledgerIncidents(days, { range, now })), networkMinValidators);
  const netSets = ledgerSetsByValidator(network);
  const privSets = ledgerSetsByValidator(priv);
  const validators = new Set([...netSets.keys(), ...privSets.keys()]);
  const rows = [...validators].map((v) => {
    const n = (netSets.get(v) ?? new Set()).size;
    const p = (privSets.get(v) ?? new Set()).size;
    return { master: v, networkLedgers: n, privateLedgers: p, total: n + p, networkShare: n + p > 0 ? n / (n + p) : null };
  }).sort((a, b) => (b.privateLedgers - a.privateLedgers) || (b.networkLedgers - a.networkLedgers));
  return { rows, networkLedgers: network.size, privateLedgers: priv.size, threshold: networkMinValidators };
}

// Kohortenbildung: Validatoren, die ueberwiegend GEMEINSAM ausfallen, und zwar auf LEDGERN,
// an denen nicht fast das ganze Netz fiel. Erwartung bei Unabhaengigkeit = fa * fb / private
// Ledger; der Lift misst die Abweichung davon. mutual verlangt, dass die Gemeinsamkeit beiden
// Knoten entspricht — sonst ist es nur ein Anhaenger eines grossen Stoerers.
export function coFailureClusters(days, { range = "all", now = Date.now(), ...rest } = {}) {
  const p = { ...DIAGNOSE_DEFAULTS, ...rest };
  const uniq = uniquePerLedger(ledgerIncidents(days, { range, now }));
  const { network, private: priv } = splitLedgers(uniq, p.networkMinValidators);
  const privSets = ledgerSetsByValidator(priv);
  // Nenner der Unabhaengigkeits-Erwartung sind die AUFGEZEICHNETEN privaten Ledger, nicht die
  // privaten Ledger mit Ausfall. Sonst wird die Erwartung systematisch zu hoch und der Lift zu
  // klein - man erklaert echte Gemeinsamkeit fuer Zufall.
  const recordedLedgers = (Array.isArray(days) ? days : []).reduce((a, d) => a + (num(d.ledgers) ?? 0), 0);
  const totalPrivate = Math.max(1, recordedLedgers - network.size);
  const pairs = [];
  const failing = [...privSets.keys()];
  for (let a = 0; a < failing.length; a++) {
    for (let b = a + 1; b < failing.length; b++) {
      const x = failing[a], y = failing[b];
      const sx = privSets.get(x), sy = privSets.get(y);
      const [small, big] = sx.size <= sy.size ? [sx, sy] : [sy, sx];
      let co = 0;
      for (const ledger of small) if (big.has(ledger)) co += 1;
      if (!co) continue;
      const expected = (sx.size * sy.size) / (totalPrivate || 1);
      pairs.push({
        a: x, b: y, coLedgers: co, privateLedgers: { a: sx.size, b: sy.size },
        expected: round(expected, 2),
        lift: expected > 0 ? round(co / expected, 2) : null,
        mutual: round(Math.min(co / sx.size, co / sy.size), 3),
        sharedLedgers: [...small].filter((l) => big.has(l)).sort((m, n) => m - n).slice(0, 10),
      });
    }
  }
  const strong = pairs.filter((pr) =>
    pr.coLedgers >= p.coMinLedgers
    && (pr.lift === null || pr.lift >= p.coMinLift)
    && (pr.mutual ?? 0) >= p.coMutualMin);
  const parent = new Map();
  // Wurzel finden, dann Kanten direkt auf die Wurzel haengen. Die Kompression darf NICHT ueber
  // die Wurzel hinauslaufen: ihr Zeiger zeigt auf sich selbst, ein bedingungsloser Durchlauf
  // dreht dort endlos.
  const find = (v) => {
    let r = v;
    while (parent.get(r) !== undefined && parent.get(r) !== r) r = parent.get(r);
    let c = v;
    while (parent.get(c) !== undefined && parent.get(c) !== c) { const nx = parent.get(c); parent.set(c, r); c = nx; }
    return r;
  };
  const size = new Map();
  for (const pr of strong) {
    for (const v of [pr.a, pr.b]) if (!parent.has(v)) { parent.set(v, v); size.set(v, 1); }
    const ra = find(pr.a), rb = find(pr.b);
    if (ra !== rb) { parent.set(ra, rb); size.set(rb, (size.get(rb) ?? 0) + (size.get(ra) ?? 0)); size.delete(ra); }
  }
  const groups = new Map();
  for (const v of parent.keys()) { const r = find(v); const list = groups.get(r) ?? []; list.push(v); groups.set(r, list); }
  const clusters = [...groups.values()]
    .filter((members) => members.length >= 2)
    .map((members) => {
      const inner = pairs.filter((pr) => members.includes(pr.a) && members.includes(pr.b) && pr.coLedgers >= p.coMinLedgers);
      const hits = new Map();
      for (const v of members) for (const ledger of privSets.get(v) ?? []) hits.set(ledger, (hits.get(ledger) ?? 0) + 1);
      const shared = [...hits.keys()].filter((l) => (hits.get(l) ?? 0) >= 2);
      const lifts = inner.map((pr) => pr.lift).filter((x) => Number.isFinite(x));
      const mutuals = inner.map((pr) => pr.mutual).filter((x) => Number.isFinite(x));
      return {
        members, size: members.length, pairCount: inner.length,
        sharedLedgers: shared.length,
        medianLift: lifts.length ? round(lifts.sort((a, b) => a - b)[Math.floor(lifts.length / 2)], 2) : null,
        medianMutual: mutuals.length ? round(mutuals.sort((a, b) => a - b)[Math.floor(mutuals.length / 2)], 3) : null,
        sharedLedgerSample: shared.sort((a, b) => b - a).slice(0, 12),
      };
    })
    .sort((a, b) => (b.sharedLedgers - a.sharedLedgers) || (b.size - a.size));
  // Sortierung nach Belegmenge: gemeinsame Ledger zuerst. mutual/Lift bei einem einzigen
  // gemeinsamen Ledger ist arithmetisch gross, aber kein Beleg - deshalb nicht das Sortierkriterium.
  pairs.sort((a, b) => (b.coLedgers - a.coLedgers) || (b.mutual ?? 0) - (a.mutual ?? 0));
  return {
    pairs: pairs.slice(0, p.topPairs),
    strongPairs: strong.length,
    clusters: clusters.slice(0, p.topClusters),
    totalClusters: clusters.length,
    coverage: { incidentLedgers: uniq.size, networkLedgers: network.size, privateLedgers: priv.size },
    thresholds: { coMinLedgers: p.coMinLedgers, coMinLift: p.coMinLift, coMutualMin: p.coMutualMin, networkMinValidators: p.networkMinValidators },
  };
}

// War das eigene Fehlen quorum-kritisch? Marge = Vorsprung der Top-Linie ueber die Quorum-Schwelle.
// Marge 0 heisst: ohne diese Stimme haette die Linie nicht gestanden. Das ist die Antwort auf die
// Frage, die jeder Betreiber stellt — und die kein Dashboard der Welt liefert.
export function quorumCriticality(days, master, { range = "all", now = Date.now(), ...rest } = {}) {
  const p = { ...DIAGNOSE_DEFAULTS, ...rest };
  const span = spanOf(range);
  const from = span === Infinity ? -Infinity : now - span;
  const absent = new Map();
  // Alle Betroffenen je Ledger, nicht nur die dieses Knotens: 'votes / needed' ist eine
  // Ledger-Zahl, die Betroffenheit ist eine Knoten-Menge. Ohne die Namen bleibt die Kohorte eine
  // Zahl ohne Spur - und genau die soll nachvollziehbar sein, wer in diesem Ledger fehlte.
  const absentAll = new Map();
  for (const d of Array.isArray(days) ? days : []) {
    for (const i of d.incidents ?? []) {
      const type = TYPE_OF[i.type] ?? i.type;
      if (!absentAll.has(i.l)) absentAll.set(i.l, new Map());
      absentAll.get(i.l).set(i.m, type);
      if (i.m === master) absent.set(i.l, type);
    }
  }
  const rows = [];
  for (const d of Array.isArray(days) ? days : []) {
    // Luecken-Log dieses Tages: der Rekorder traegt ihn ein, sobald er im Ledger-Strom einen
    // Index-Sprung sieht ('gaps', reason 'stream-gap'). Fuer Zeilen ohne 'pg' (der Bestand vor
    // 2026-10-16) ist das der einzige gemessene Beleg dafuer, dass vor diesem Ledger Indizes
    // fehlten. Ohne diesen Beleg bleibt die Erfassungs-Frage offen - sie wird nicht geraten.
    const gaps = dayGapRanges(d);
    const parentGap = (l) => parentGapCovered(gaps, l);
    // Erfassungs-Ereignisse dieses Tages (Strom verloren / neu aufgebaut). Ein duennerer Empfang
    // in einem Ledger, der nicht verpasst wurde, ist damit einem Ereignis zuordenbar - und bleibt
    // offen, wenn in der Nahe nichts aufgezeichnet wurde. Das naechste Ereignis, nicht irgendeins.
    const events = (Array.isArray(d.captureEvents) ? d.captureEvents : [])
      .filter((e) => e && Number.isFinite(e.atMs));
    const nearEvent = (tMs) => {
      if (!Number.isFinite(tMs)) return null;
      let best = null;
      for (const e of events) {
        const deltaMs = Math.abs(e.atMs - tMs);
        if (deltaMs <= p.captureEventWindowMs && (best === null || deltaMs < best.deltaMs)) best = { e, deltaMs };
      }
      return best;
    };
    for (const st of d.ledgerStats ?? []) {
      if (!absent.has(st.l)) continue;
      const t = num(st.t);
      if (t !== null && (t < from || t > now + 1)) continue;
      const mg = num(st.mg), need = num(st.need), top = num(st.top);
      // Schliess-Ebene zuerst: der Recorder wertet ausschliesslich Ledger aus dem validierten
      // Stream aus, also ist die Schliessung belegt, solange sie nicht ausdruecklich verneint
      // wird (cl === false in einer kuenftigen Recorder-Fassung). Eine Marge unter null beschreibt
      // dann nur, wie viele Stimmen dieser Rekorder sah - niemals ein fehlendes Netz-Quorum.
      const closure = ledgerClosure(st, { parentGap: parentGap(st.l) });
      const captureGap = closure.captureGap;
      const critical = !closure.closed && mg !== null && need !== null && need > 0 && mg <= p.marginalMargin;
      // 'ot' kommt aus dem Rekorder selbst: dort wurde die eigene Empfangs-Basis gemessen,
      // bevor dieser Ledger bewertet wurde. Ein Index-Sprung ist ein Beleg fuer eine
      // verpasste Ledger-Folge; duenner Empfang gegen die eigene Basis ist der Beleg fuer
      // eine Erfassungs-Schwaeche in einem Ledger, der nicht verpasst wurde. Ohne beide
      // bleibt die Frage offen.
      const receptionThin = st.ot === true;
      const near = nearEvent(t);
      const verdict = !closure.closed ? "not-closed"
        : captureGap ? "closed-capture-gap"
          : top !== null && need !== null && top >= need ? "closed-quorum-observed"
            : receptionThin ? "closed-reception-thin"
              : "closed-observation-gap";
      // Betroffenheit sortiert deterministisch (Typ, dann Master-Key), damit zwei Aufrufe
      // dieselbe Liste liefern und eine Liste verglichen werden kann, statt sie neu zu erfinden.
      const all = absentAll.get(st.l) ?? new Map();
      const others = [...all.entries()].filter(([m]) => m !== master)
        .sort((a, b) => (a[1] < b[1] ? -1 : a[1] > b[1] ? 1 : 0) || (a[0] < b[0] ? -1 : 1));
      rows.push({
        ledgerIndex: st.l, timeMs: t, type: closureTypeName(absent.get(st.l), closure),
        votes: num(st.v), needed: need, topVotes: top, margin: mg, runnerVotes: num(st.sp),
        observedValidations: num(st.ov), closure, captureGap,
        observedBaseline: num(st.ovb), receptionThin,
        // captureEvent: das naechste aufgezeichnete Erfassungs-Ereignis mit Abstand, oder null.
        // null heisst "nichts aufgezeichnet", nie "kein Ereignis" - der Altbestand fuhr dieses
        // Protokoll nicht.
        captureEvent: near === null ? null : {
          kind: near.e.e ?? null, atMs: near.e.atMs,
          ledger: Number.isFinite(near.e.l) ? near.e.l : null, deltaMs: near.deltaMs,
        },
        // captureGapBasis benennt den Beleg: 'ledger-index' (Index-Folge dieses Recorders),
        // 'stream-gap' (Luecken-Log des Tages) oder 'not-recorded' (nichts davon vorhanden).
        captureGapBasis: closure.captureGapBasis, verdict,
        critical,
        // Die nachrechenbare Grenze dieser Zeile: wie viele der als 'kein Vote erfasst'
        // gefuehrten dUNL-Knoten auf diesem Ledger ueberhaupt echt gefehlt haben koennen, und
        // wie viele mindestens Erfassungs-Luecke dieses Recorders sind. Ohne diese Zahl ist die
        // Betroffenheits-Zeile eine Behauptung ueber die Knoten, die der Rekorder nicht belegen
        // kann - auf einem geschlossenen Ledger darf sie das nicht sein.
        capture: captureBound(st, { parentGap: parentGap(st.l) }),
        affectedCount: all.size,
        affectedMasters: others.map(([m]) => m),
        affectedTypes: others.map(([, ty]) => closureTypeName(ty, closure)),
      });
    }
  }
  // Reihenfolge nach Aussagekraft, nicht nach Index: zuerst die Faelle, in denen das Fehlen
  // den Ausgang geaendert haette, dann die mit Erfassungs-Luecke, dann die duennste beobachtete
  // Stimmenzahl. Sonst verdeckt die Sortierung genau die Ledger, um die es geht.
  rows.sort((a, b) => (Number(b.critical) - Number(a.critical))
    || (Number(b.captureGap) - Number(a.captureGap))
    || (a.margin ?? 0) - (b.margin ?? 0)
    || (b.ledgerIndex ?? 0) - (a.ledgerIndex ?? 0));
  const critical = rows.filter((r) => r.critical).length;
  return {
    checked: rows.length,
    critical,
    followOn: rows.length - critical,
    // Die Schliess-Bilanz dieser Zeilen: wie viele Ledger bewiesen geschlossen sind und wie viele
    // davon mit einer Erfassungs-Luecke dieses Rekorders. Ohne diese Zahlen waere 'critical' eine
    // Zahl ohne Erklarung, wo sie hin gehoert.
    closed: rows.filter((r) => r.closure.closed).length,
    captureGaps: rows.filter((r) => r.captureGap).length,
    // Die offene Flaeche: Zeilen, bei denen weder die Index-Folge noch der Luecken-Log etwas
    // hergeben. Das ist eine Datenluecke des Recorders, keine Aussage ueber das Netz.
    captureGapUnknown: rows.filter((r) => r.captureGap === null).length,
    // Wie viele dieser Ledger der Rekorder zwar sah, aber duenner als in seinen eigenen letzten
    // Ledgern. Das ist die einzige Erfassungs-Aussage, die auch ohne Index-Sprung gemessen ist.
    receptionThin: rows.filter((r) => r.receptionThin).length,
    // Wie viele dieser Ledger ein aufgezeichnetes Erfassungs-Ereignis in der Nahe haben. Der
    // Rest bleibt offen; "nicht erfasst" ist hier eine Zahl, keine Entlastung.
    captureEvents: rows.filter((r) => r.captureEvent !== null).length,
    // Wie viele dieser Zeilen haben eine nachweisbar unvollstaendige eigene Erfassung (weniger
    // Mitglieder-Stimmen gesehen, als das Quorum verlangt). Auf ihnen ist ein einzelner
    // 'kein Vote'-Befund kein Knoten-Urteil.
    captureIncomplete: rows.filter((r) => r.capture?.captureComplete === false).length,
    // Summe der nachweisbaren Erfassungs-Artefakte ueber alle Zeilen: die untere Grenze der
    // 'kein Vote erfasst'-Flags, die dieses Werkzeug auf geschlossenen Ledern zu viel zaehlt.
    captureArtifactMin: rows.reduce((sum, r) => sum + (r.capture?.captureArtifactMin ?? 0), 0),
    // Ohne Forensik-Zeile ist die Frage nicht beantwortbar — das ist eine Datenluecke, kein "ungefaehrlich".
    unanswered: absent.size - rows.length,
    rows: rows.slice(0, 12),
  };
}

// Zeitfenster, in denen mehrere Validatoren gleichzeitig Serien haben, plus die Tx-Form dieser
// Fenster. Das trennt gezielten Ausfall eines Knotens von einer Netz- oder Lastaktion.
export function windowScan(days, { range = "7d", now = Date.now(), ...rest } = {}) {
  const p = { ...DIAGNOSE_DEFAULTS, ...rest };
  const runs = failureRuns(days, { range, now, ...rest });
  const perLedger = ledgerIncidents(days, { range, now });
  const stats = new Map();
  for (const d of Array.isArray(days) ? days : []) for (const st of d.ledgerStats ?? []) stats.set(st.l, st);
  const windows = [];
  for (const r of runs) {
    if (r.ledgers < p.runMinLedgers) continue;
    const st = stats.get(r.fromLedger) ?? stats.get(r.toLedger) ?? null;
    const shapeTags = new Set();
    if (st) {
      for (const tag of Object.keys(st.sev ?? {})) shapeTags.add(tag);
      if (st.sweep) shapeTags.add("sweep-window");
      // Dasselbe Akkuratz-Gesetz wie in Retrace und Kritikalitaet: ein bewiesen geschlossener
      // Ledger hat sein Netz-Quorum erreicht - eine Marge am Rand beschreibt dann nur, wie viele
      // Stimmen dieser Rekorder sah. 'quorum-thin' (knappes Netz-Quorum) darf dort nicht stehen.
      const closure = ledgerClosure(st);
      if (closure.closed === false && Number.isFinite(st.mg) && st.mg <= p.marginalMargin) shapeTags.add("quorum-thin");
      else if (closure.closed && Number.isFinite(st.top) && Number.isFinite(st.need) && st.top < st.need) shapeTags.add("vote-coverage-thin");
      if (Number.isFinite(st.sp) && st.sp >= TRACE_DEFAULTS.splitMinVotes) shapeTags.add("hash-split");
      if (Number.isFinite(st.med) && st.med > 0 && Number.isFinite(st.tx) && st.tx >= TRACE_DEFAULTS.spikeMinTx && st.tx / st.med >= TRACE_DEFAULTS.spikeRatio) {
        shapeTags.add(st.tx / st.med >= TRACE_DEFAULTS.extremeRatio ? "load-extreme" : "load-spike");
      }
    }
    const attack = shapeTags.has("drainer-fanout") || shapeTags.has("sweep-window") || shapeTags.has("sender-burst")
      || shapeTags.has("failure-spike") || shapeTags.has("offer-flood") || shapeTags.has("batch-amplify");
    // coShare ist der Massstab, nicht die Zahl anderer Ausfaelle im Fenster: in einem Fenster von
    // 3.938 Ledgers findet sich Zufallsstreuung fast von selbst. Ab 50 % gemeinsamer Ledger ist es
    // ein Gemeinschaftsereignis, unter 5 % ein Fenster dieses einen Knotens.
    const share = r.coShare ?? 0;
    const classification = share >= 0.5
      ? (attack ? "cohort-under-attack" : "network-window")
      : attack ? "targeted-under-load"
        : share >= 0.05 ? "overlapping-outage" : "targeted-outage";
    windows.push({
      master: r.master, fromLedger: r.fromLedger, toLedger: r.toLedger, ledgers: r.ledgers,
      firstMs: r.firstMs, lastMs: r.lastMs, durationMs: r.durationMs,
      coShare: r.coShare, coValidators: r.coValidators.slice(0, 4),
      ledgerForensics: st ? { recorded: true, margin: st.mg, runnerVotes: st.sp, txCount: st.tx, medianTx: st.med, shape: Boolean(st.sh) } : { recorded: false },
      shapeTags: [...shapeTags],
      classification,
    });
  }
  windows.sort((a, b) => (b.ledgers - a.ledgers) || (b.lastMs ?? 0) - (a.lastMs ?? 0));
  const tally = {};
  for (const w of windows) tally[w.classification] = (tally[w.classification] ?? 0) + 1;
  return { windows: windows.slice(0, DIAGNOSE_DEFAULTS.topRuns), total: windows.length, tally, perLedgerLedgers: perLedger.size };
}

// Die Erklaerung, die der Ledger-Ebene fehlt: eine Serie. Liefert fuer einen einzelnen Vorfall
// die Serien-Einordnung, damit die Retrace-Karte nicht mehr bei "keine Ursache" stehen bleibt.
export function seriesContext(runs, master, ledgerIndex) {
  const run = runs.find((r) => r.master === master && ledgerIndex >= r.fromLedger && ledgerIndex <= r.toLedger);
  if (!run) return null;
  return {
    ledgers: run.ledgers,
    position: ledgerIndex - run.fromLedger + 1,
    fromLedger: run.fromLedger,
    toLedger: run.toLedger,
    durationMs: run.durationMs,
    isolated: run.isolated,
    coShare: run.coShare,
    verdict: run.verdict,
    breakAfter: run.breakAfter,
  };
}

// Prüfschritte, die aus einer Serien-Einordnung folgen. Neue Tags, weil die Ledger-Ebene diese
// Frage gar nicht stellt: "war mein Knoten am Stueck weg" ist keine Infrastruktur-Pruefung wie
// solo-peering, sondern eine Pruefung des Prozesses selbst.
const SERIES_GUIDANCE = {
  "offline-window": ["node-offline-window"],
  "brief-outage": ["node-offline-window"],
  "short-series": ["node-offline-window"],
  "degraded-window": ["degraded-signing"],
  "degraded-single": ["degraded-signing"],
  "cohort-window": ["cohort-network"],
  "network-window": ["network-stall"],
  "capture-window": ["capture-window"],
  "vote-not-observed": ["capture-window"],
  "hash-divergence": ["version-state"],
  "isolated-miss": [],
};
// Vor der Zuweisung gelesen, waere die Menge eine Zeitfenster-Fehlermeldung. Deshalb nachher.
export const SERIES_VERDICTS = Object.keys(SERIES_GUIDANCE);
// Die Schliess-Verdikte je Forensik-Zeile. 'not-closed' ist der einzige Zustand, in dem ein
// fehlendes Netz-Quorum behauptet werden darf; alle 'closed-*' sagen, dass das Netz geschlossen
// hat und die Stimmenzahl nur die eigene Beobachtung beschreibt.
export const CQ_VERDICTS = ["not-closed", "closed-capture-gap", "closed-quorum-observed", "closed-reception-thin", "closed-observation-gap"];
export const CQ_CLOSURE_BASES = ["recorder", "validated-ledger-stream", "xrpscan"];

// Serie in die Retrace-Karte bringen. Jeder Vorfall bekommt seine Serien-Einordnung; gab der
// Ledger selbst nichts her (nur "no-correlated-cause"), tritt die Serie als Erklaerung an seine
// Stelle - als correlated, nicht als measured: sie ist wiederholte Beobachtung derselben Spur,
// kein Messwert dieses Ledgers. Die ehrliche Grenze bleibt stehen.
export function applySeries(retraceRows, runs, master) {
  for (const row of Array.isArray(retraceRows) ? retraceRows : []) {
    const sc = seriesContext(runs, master, row.ledgerIndex);
    row.series = sc;
    if (!sc || sc.isolated) continue;
    const explained = (row.hypotheses ?? []).some((x) => x.strength === "measured" || x.strength === "correlated");
    if (!explained) {
      row.hypotheses = [
        {
          tag: sc.verdict, strength: "correlated", lift: null,
          evidence: {
            ledgers: sc.ledgers, position: sc.position, fromLedger: sc.fromLedger, toLedger: sc.toLedger,
            durationMs: sc.durationMs, coShare: sc.coShare, breakAfter: sc.breakAfter,
          },
        },
        ...(row.hypotheses ?? []),
      ];
    }
    const extra = SERIES_GUIDANCE[sc.verdict] ?? [];
    if (extra.length) row.guidance = [...new Set([...(row.guidance ?? []), ...extra])];
  }
  return retraceRows;
}

const medianOf = (values) => {
  const v = values.filter((x) => Number.isFinite(x)).sort((a, b) => a - b);
  if (!v.length) return null;
  const m = Math.floor(v.length / 2);
  return v.length % 2 ? v[m] : (v[m - 1] + v[m]) / 2;
};

// LAST-AUSFALL-KURVE. Die Frage, die ein Validator-Betreiber stellt und die kein offenes XRPL-
// Werkzeug beantwortet: ab welcher Transaktions-Last pro Ledger faellt MEIN Knoten zurueck, und
// ab welcher halten die anderen Knoten dieselbe Last durch?
//
// Getrennt werden zwei voellig verschiedene Fehlerarten, die in jeder bloegen Ausfallrate
// miteinander verschmelzen:
//   - Knoten faellt unabhaengig von der Last aus (offline, Wartung, Konfiguration, Netzwerk)
//   - Knoten faellt ERST bei Last aus (Queue-Rueckstau, Zustandsneuberechnung, CPU, Peers)
// Das zweite ist ein Kapazitaetsbefund mit Handlungsweg, das erste nicht. Deshalb gibt es eine
// Normalbetriebs-Baseline (die Stufe mit den meisten Ledgern) und eine Last-Obergrenze: die
// kleinste Stufe OBERHALB der Baseline, die deutlich ueber der Baseline liegt und die
// Urteils-Schwelle erreicht.
//
// Nenner je Stufe sind die AUFGEZEICHNETEN Ledger dieser Stufe, nicht die Ausfall-Ledger. Ohne
// die Ledger ohne Ausfall als Nenner waere jede Kurve eine Selbstbestaetigung.
export function loadResponseCurve(days, { master = null, range = "all", now = Date.now(), ...rest } = {}) {
  const p = { ...DIAGNOSE_DEFAULTS, ...rest };
  const span = spanOf(range);
  const from = span === Infinity ? -Infinity : now - span;
  const agg = new Map(); // idx -> { ledgers, failLedgers, fails: Map, seen: Map }
  let daysWithLoad = 0, daysWithoutLoad = 0, totalLedgers = 0, loadLedgers = 0;
  for (const d of Array.isArray(days) ? days : []) {
    const t0 = num(d.firstMs), t1 = num(d.lastMs);
    if (t0 !== null && t1 !== null && (t1 < from || t0 > now + 1)) continue;
    const list = Array.isArray(d.loadBuckets) ? d.loadBuckets : [];
    const members = Object.keys(d.validators ?? {});
    let counted = 0;
    for (let i = 0; i < list.length; i += 1) {
      const b = list[i];
      const ledgers = num(b?.l) ?? 0;
      if (!ledgers) continue;
      counted += ledgers;
      let e = agg.get(i);
      if (!e) { e = { ledgers: 0, failLedgers: 0, fails: new Map(), seen: new Map() }; agg.set(i, e); }
      e.ledgers += ledgers;
      e.failLedgers += num(b.f) ?? 0;
      for (const [m, n] of Object.entries(b.v ?? {})) e.fails.set(m, (e.fails.get(m) ?? 0) + (num(n) ?? 0));
      // Nenner je Knoten: jeder dUNL-Mitglied wird in jedem aufgezeichneten Ledger bewertet,
      // also auch in jedem Ledger dieser Stufe.
      for (const m of members) e.seen.set(m, (e.seen.get(m) ?? 0) + ledgers);
    }
    if (counted) daysWithLoad += 1; else daysWithoutLoad += 1;
    loadLedgers += counted;
    totalLedgers += num(d.ledgers) ?? 0;
  }
  const rows = [];
  for (let i = 0; i < LOAD_BUCKETS.length; i += 1) {
    const e = agg.get(i);
    if (!e || !e.ledgers) continue;
    const cohortRates = [...e.seen].map(([m, seen]) => (seen > 0 ? (e.fails.get(m) ?? 0) / seen : null));
    const own = master ? e.fails.get(master) ?? 0 : 0;
    const ownSeen = master ? e.seen.get(master) ?? 0 : 0;
    const networkRate = e.failLedgers / e.ledgers;
    rows.push({
      index: i, label: loadBucketLabel(i),
      ledgers: e.ledgers, failLedgers: e.failLedgers,
      networkRate: round(networkRate, 4),
      cohortMedianRate: round(medianOf(cohortRates), 4),
      cohortSize: cohortRates.length,
      validatorLedgers: master ? ownSeen : null,
      validatorFails: master ? own : null,
      validatorRate: master && ownSeen > 0 ? round(own / ownSeen, 4) : null,
      sample: e.ledgers >= p.ceilingMinLedgers ? "ok" : "thin",
    });
  }
  rows.sort((a, b) => a.index - b.index);
  const populated = rows.filter((r) => r.sample === "ok");
  // Normalbetriebs-Stufe = die am dichtesten besetzte Stufe. Sie ist der Vergleichspunkt, weil
  // sie den Knoten im Regelfall beschreibt, nicht den Ausnahmefall.
  const baseline = populated.reduce((best, r) => (best && best.ledgers >= r.ledgers ? best : r), null);
  const judge = (key) => {
    if (!baseline) return { baselineRate: null, ceiling: null, ceilingLabel: null, verdict: "unknown" };
    const baseRate = baseline[key];
    let ceiling = null;
    if (baseRate !== null && baseRate < p.ceilingRate) {
      for (const r of populated) {
        if (r.index <= baseline.index) continue;
        const rate = r[key];
        if (rate === null) continue;
        if (rate >= p.ceilingRate && rate >= p.ceilingFactor * baseRate) { ceiling = r; break; }
      }
    }
    const verdict = baseRate === null ? "unknown"
      : baseRate >= p.ceilingRate ? "always-failing"
      : ceiling ? "load-limited" : "load-resilient";
    return {
      baselineRate: baseRate,
      ceiling: ceiling ? ceiling.index : null,
      ceilingLabel: ceiling ? ceiling.label : null,
      ceilingRate: ceiling ? ceiling[key] : null,
      verdict,
    };
  };
  const worst = master ? populated.reduce((best, r) => {
    if (r.validatorRate === null || r.validatorLedgers < p.ceilingMinLedgers) return best;
    return best && best.validatorRate >= r.validatorRate ? best : r;
  }, null) : null;
  return {
    master,
    rows,
    coverage: {
      daysWithLoad, daysWithoutLoad, totalLedgers, loadLedgers,
      // Ohne einen einzigen gezehlten Ledger dieser Ebene ist die Kurve nicht beantwortbar.
      recorded: loadLedgers > 0,
    },
    baseline: baseline ? { index: baseline.index, label: baseline.label, ledgers: baseline.ledgers } : null,
    network: judge("networkRate"),
    cohort: judge("cohortMedianRate"),
    validator: master ? { ...judge("validatorRate"), worst } : null,
    thresholds: { ceilingRate: p.ceilingRate, ceilingMinLedgers: p.ceilingMinLedgers, ceilingFactor: p.ceilingFactor },
  };
}
