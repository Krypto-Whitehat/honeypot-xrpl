// lib/validator-peer-benchmark.mjs — ein dUNL-Knoten im Vergleich zum Rest des dUNL.
//
// Die Frage, die kein anderes Validator-Werkzeug beantwortet: nicht "wie viele Ledger hast du
// verpasst", sondern "ist deine Ausfallrate ein Knotenproblem - oder genau das, was in diesem
// Fenster allen passiert". Dazu wird je Knoten die Ausfallrate auf die LEDGER gerechnet, die
// dieser Knoten wirklich beobachtet hat (Nenner aus den Stunden-Buckets des Recorders), und
// gegen die Verteilung aller dUNL-Knoten desselben Fensters gestellt.
//
// Getrennt nach Zustaendigkeit: missed / partial / wrong-hash sind knotenzurechenbar.
// no-quorum ist eine Netzwerk-Stockung - lib/validator-trace.mjs waehlt 'no-quorum' genau
// deshalb, weil Nicht-Abstimmen bei fehlendem Quorum KEIN Einzelfehler ist. Die Zahl fliesst
// deshalb nicht in die Knotenrate, sondern wird als Netz-Aussetzung separat ausgewiesen.
//
// Rein und ohne Netzwerk: Eingabe sind dieselben Tagesobjekte wie in validator-trace-query.mjs.
import { dayCoverageGaps } from "./trace-day-coverage.mjs";

export const PEER_MIN_LEDGERS = 200; // unterhalb dieser eigenen Stichprobe gibt es kein Urteil
export const PEER_MIN_PEERS = 5;     // unterhalb dieser Vergleichsgruppe gibt es kein Urteil
export const PEER_MIN_OUTLIER_FAILS = 10;
export const PEER_OUTLIER_Z = 4;
export const PEER_ELEVATED_Z = 2;

export const PEER_TYPES = ["missed", "partial", "wrongHash"];
export const PEER_ALL_TYPES = [...PEER_TYPES, "noQuorum"];
export const PEER_VERDICTS = ["peer-baseline", "elevated", "outlier", "insufficient-sample", "not-observed"];
export const PEER_AUTHORITIES = ["trace-hourly", "trace-daily", "none"];
// Richtung des Abstands zur Grundrate: unter der Grundrate ist eine andere Diagnose als darueber.
export const PEER_DIRECTIONS = ["above-baseline", "below-baseline", "at-baseline"];
export const PEER_REASONS = [
  "no-recorded-ledgers", "below-minimum-ledgers", "below-minimum-peers",
  "no-peer-failures", "rate-above-peer-p90", "rate-above-peer-median",
  "rate-within-peer-band", "rate-below-peer-median",
];

const SPAN = { "1h": 3600000, "24h": 86400000, "7d": 7 * 86400000, "30d": 30 * 86400000, all: Infinity };
const HOUR_MS = 3600000;
const num = (x) => (Number.isFinite(Number(x)) ? Number(x) : 0);
const round = (x, d = 5) => (Number.isFinite(x) ? Math.round(x * 10 ** d) / 10 ** d : null);
const countsOf = () => { const c = {}; for (const k of PEER_ALL_TYPES) c[k] = 0; return c; };

function windowOf(range, now) {
  const ms = SPAN[range] ?? SPAN["24h"];
  return { from: ms === Infinity ? 0 : now - ms, to: now + 1 };
}

// Quantil mit linearer Interpolation (0 = Minimum, 1 = Maximum). Leere Liste -> null.
export function quantile(sorted, q) {
  const a = (Array.isArray(sorted) ? sorted : []).filter((x) => Number.isFinite(x)).sort((x, y) => x - y);
  if (!a.length) return null;
  const pos = Math.min(1, Math.max(0, q)) * (a.length - 1);
  const lo = Math.floor(pos), hi = Math.ceil(pos);
  return a[lo] + (a[hi] - a[lo]) * (pos - lo);
}

// erfc als Chebyshev-Annaeherung (Numerical Recipes 7.1.26, t = 1/(1+0,5z), absolute Guete
// ~1,2e-7). Gegenprobe gegen numerische Integration von exp(-t^2): erfc(0)=1, erfc(1)=0,15729921,
// erfc(2)=0,00467774. Die frühere Fassung war die erf-Polynomkette aus A&S 7.1.26 mit falscher
// Einbettung: sie lieferte systematisch ~25 % zu kleine Werte - erfc(0)=0,705 statt 1, also auch
// p-Werte um den Faktor 0,75 zu klein genau dort, wo über "auffaellig" oder "nicht auffaellig"
// entschieden wird. Die Normalnaeherung der Binomialverteilung bleibt eine Naeherung und wird als
// solche ausgewiesen, nicht als exakter Test.
export function erfc(x) {
  const z = Math.abs(x);
  const t = 1 / (1 + 0.5 * z);
  const y = t * Math.exp(-z * z - 1.26551223 + t * (1.00002368 + t * (0.37409196 + t * (0.09678418
    + t * (-0.18628806 + t * (0.27886807 + t * (-1.13520398 + t * (1.48851587 + t * (-0.82215223 + t * 0.17087277)))))))));
  return x >= 0 ? y : 2 - y;
}

/* Zaehler je Knoten im Fenster. Nenner (beobachtete Ledger) und Zaehler kommen aus
 * denselben Stunden-Buckets, damit Rate und Vorfall dieselbe Messung teilen.
 * Stunden-Buckets -> fenster-genau. Eine Tagesdatei ohne Stunden-Buckets (Altbestand) wird
 * nach dem Tages-overlap verteilt und als geschaetzt ausgewiesen: geschaetzt ist nicht gemessen. */
function collect(days, w) {
  const totals = new Map();
  const hours = new Map();
  let hourlyDays = 0, dailyDays = 0, partialDays = 0;
  const node = (master) => {
    let t = totals.get(master);
    if (!t) {
      t = { master, observed: 0, observedHourly: 0, observedDaily: 0, ...countsOf() };
      totals.set(master, t);
    }
    return t;
  };
  const add = (master, c, frac, hourly) => {
    const t = node(master);
    let failures = 0;
    for (const k of PEER_ALL_TYPES) {
      const v = num(c?.[k]) * frac;
      t[k] += v;
      if (k !== "noQuorum") failures += v;
    }
    const observed = (num(c?.ok) + failures + num(c?.noQuorum)) * frac;
    t.observed += observed;
    if (hourly) t.observedHourly += observed; else t.observedDaily += observed;
    return { failures, observed };
  };
  for (const d of Array.isArray(days) ? days : []) {
    const hourly = d.hourly && typeof d.hourly === "object" ? Object.entries(d.hourly) : [];
    if (hourly.length) {
      hourlyDays += 1;
      for (const [hk, hb] of hourly) {
        const h0 = Number(hk) * HOUR_MS;
        if (!Number.isFinite(h0)) continue;
        const ov = Math.min(h0 + HOUR_MS, w.to) - Math.max(h0, w.from);
        if (ov <= 0) continue;
        const frac = Math.min(1, ov / HOUR_MS);
        const hourKey = Math.floor(h0 / HOUR_MS);
        let hc = hours.get(hourKey);
        if (!hc) { hc = { hourMs: hourKey * HOUR_MS, ledgers: 0, v: new Map(), seen: new Map() }; hours.set(hourKey, hc); }
        hc.ledgers += num(hb?.l) * frac;
        for (const [m, hv] of Object.entries(hb?.v ?? {})) {
          const { failures, observed } = add(m, hv, frac, true);
          hc.v.set(m, (hc.v.get(m) ?? 0) + failures);
          hc.seen.set(m, (hc.seen.get(m) ?? 0) + observed);
        }
      }
    }
    // Tageszaehler, die in KEINEM Stunden-Bucket dieses Fensters liegen. Der Recorder ist am
    // 2026-10-09 mitten am Tag mit den Stunden-Buckets eingestiegen: die Vorfaelle vor 11 Uhr
    // stecken nur in den Tageszaehlern. Wer sie ueberspringt, verkleinert den Nenner, waehrend
    // die Vorfaelle aus den zeitgestempelten Incidents voll zaehlen - die Peer-Aussage wird
    // freundlicher als die Messung. Der Rest kommt als geschaetzter Tages-Anteil dazu.
    const { gaps, hasHourly } = dayCoverageGaps(d, w);
    if (!gaps.size) continue;
    if (hasHourly) partialDays += 1; else dailyDays += 1;
    for (const [m, gap] of gaps) add(m, gap, 1, false);
  }
  return { totals, hours, hourlyDays, dailyDays, partialDays };
}

/* Stunden, in denen DIESER Knoten fiel, waehrend die beobachteten Peers sauber blieben.
 * Das ist die Liste, die ein Betreiber abarbeiten kann: nicht "du hattest 3112 Misses",
 * sondern "in diesen Stunden war dein Knoten der einzige". */
function aloneHours(hours, master, minPeers) {
  const out = [];
  for (const hc of hours.values()) {
    if ((hc.v.get(master) ?? 0) < 1) continue;
    let peersSeen = 0, peersFailing = 0;
    for (const [m, f] of hc.v) {
      if (m === master) continue;
      if ((hc.seen.get(m) ?? 0) > 0) peersSeen += 1;
      if (f > 0) peersFailing += 1;
    }
    if (peersFailing > 0) continue;
    if (peersSeen < minPeers) continue;
    out.push({ hourMs: hc.hourMs, ownFailures: round(hc.v.get(master), 2), observedPeers: peersSeen, ledgers: round(hc.ledgers, 2) });
  }
  out.sort((a, b) => b.hourMs - a.hourMs);
  return out;
}

// Kohoere je Vorfall-Ledger: wie viele dUNL-Knoten auf DEMSELBEN Ledger abwichen.
// Der Solo-Anteil ist der Unterschied zwischen "mein Knoten" und "Netzereignis".
function cohortSplit(days, master, w) {
  const perLedger = new Map();
  for (const d of Array.isArray(days) ? days : []) {
    for (const i of d.incidents ?? []) {
      if (!Number.isFinite(i.t) || i.t < w.from || i.t > w.to) continue;
      const set = perLedger.get(i.l) ?? new Set();
      set.add(i.m);
      perLedger.set(i.l, set);
    }
  }
  const sizes = [];
  let solo = 0, shared = 0, total = 0, unrecorded = 0;
  for (const d of Array.isArray(days) ? days : []) {
    for (const i of d.incidents ?? []) {
      if (i.m !== master || !Number.isFinite(i.t) || i.t < w.from || i.t > w.to) continue;
      total += 1;
      const peers = perLedger.get(i.l);
      if (!peers) { unrecorded += 1; continue; }
      sizes.push(peers.size);
      if (peers.size === 1) solo += 1; else shared += 1;
    }
  }
  return {
    ledgers: total, solo, shared, unrecorded,
    maxCohort: sizes.length ? Math.max(...sizes) : null,
    medianCohort: round(quantile(sizes, 0.5), 2),
    soloShare: sizes.length ? round(solo / sizes.length, 4) : null,
  };
}

/**
 * Peer-Benchmark eines dUNL-Knotens gegen alle anderen beobachteten dUNL-Knoten desselben
 * Fensters. Kein Urteil unterhalb der Stichproben-Grenzen - "zu wenig Daten" ist eine
 * Aussage, keine 0-Rate.
 */
export function peerBenchmark(days, master, { range = "24h", now = Date.now() } = {}) {
  const w = windowOf(range, now);
  const { totals, hours, hourlyDays, dailyDays, partialDays } = collect(days, w);
  const own = totals.get(master);
  const observed = own ? own.observed : 0;
  const authority = observed <= 0 ? "none" : (own.observedHourly >= own.observedDaily ? "trace-hourly" : "trace-daily");
  const ownFailures = own ? PEER_TYPES.reduce((s, k) => s + own[k], 0) : 0;
  const ownRate = observed > 0 ? ownFailures / observed : null;

  const peerNodes = [...totals.values()]
    .filter((t) => t.master !== master && t.observed >= PEER_MIN_LEDGERS)
    .map((t) => {
      const failures = PEER_TYPES.reduce((s, k) => s + t[k], 0);
      return { master: t.master, observed: round(t.observed, 2), failures: round(failures, 2), noQuorum: round(t.noQuorum, 2), rate: round(failures / t.observed, 6), _t: t };
    })
    .sort((a, b) => (b.rate - a.rate) || (a.master < b.master ? -1 : 1));

  const out = {
    master, range, window: { from: w.from, to: w.to },
    sample: {
      observed: round(observed, 2), observedHourly: round(own?.observedHourly ?? 0, 2), observedDaily: round(own?.observedDaily ?? 0, 2),
      estimated: (own?.observedDaily ?? 0) > 0, hours: hours.size, daysHourly: hourlyDays, daysDaily: dailyDays,
      // Halbtage: Tag mit Stunden-Buckets, deren Deckung hinter den Tageszaehlern zurueckbleibt.
      // Die Zahl ist der Unterschied zwischen 'gemessen' und 'nur auf Tages-Koernung geschaetzt'.
      daysPartial: partialDays,      peers: peerNodes.length, minLedgers: PEER_MIN_LEDGERS, minPeers: PEER_MIN_PEERS,
    },
    own: observed > 0
      ? { observed: round(observed, 2), failures: round(ownFailures, 2), rate: round(ownRate, 6), ...Object.fromEntries(PEER_ALL_TYPES.map((k) => [k, round(own[k], 2)])) }
      : null,
    peers: null, comparison: null, types: null, network: null,
    cohort: cohortSplit(days, master, w),
    aloneHours: aloneHours(hours, master, PEER_MIN_PEERS),
    peerList: { worst: peerNodes.slice(0, 8).map(({ _t, ...p }) => p), best: peerNodes.slice(Math.max(0, peerNodes.length - 8)).map(({ _t, ...p }) => p) },
    verdict: "not-observed", verdictReason: "no-recorded-ledgers", verdictAuthority: authority,
  };
  if (observed <= 0) return out;
  if (observed < PEER_MIN_LEDGERS) { out.verdict = "insufficient-sample"; out.verdictReason = "below-minimum-ledgers"; return out; }
  if (peerNodes.length < PEER_MIN_PEERS) { out.verdict = "insufficient-sample"; out.verdictReason = "below-minimum-peers"; return out; }

  const rates = peerNodes.map((p) => p.rate);
  const peerObserved = peerNodes.reduce((s, p) => s + p._t.observed, 0);
  const peerFailures = peerNodes.reduce((s, p) => s + PEER_TYPES.reduce((a, k) => a + p._t[k], 0), 0);
  const pooled = peerObserved > 0 ? peerFailures / peerObserved : null;
  const median = quantile(rates, 0.5), p90 = quantile(rates, 0.9), p10 = quantile(rates, 0.1);
  const below = rates.filter((r) => r < ownRate).length;
  const ties = rates.filter((r) => r === ownRate).length;

  // Binomial-Naeherung: eigene Vorfaelle gegen die Netz-Grundrate desselben Fensters.
  // Die Richtung ist Teil der Aussage: ein Knoten UNTER der Grundrate hat eine andere naechste
  // Pruefung als einer DARUEBER. Die einseitige Wahrscheinlichkeit "mindestens so schlecht"
  // saettigt bei einem Knoten unter der Grundrate bei 1 - dann steht "z = -17,3 p = 1,0000"
  // da, als waere der Abstand unwichtig, wo er doch der groesste des Fensters ist.
  let z = null, pValue = null, direction = null;
  if (pooled !== null && pooled > 0 && pooled < 1) {
    const sd = Math.sqrt(observed * pooled * (1 - pooled));
    if (sd > 0) {
      z = (ownFailures - observed * pooled - 0.5) / sd;
      direction = z > 0 ? "above-baseline" : z < 0 ? "below-baseline" : "at-baseline";
      // einseitig in der Richtung, die wirklich beobachtet wurde: p = 1 - Phi(|z|).
      pValue = 0.5 * erfc(Math.abs(z) / Math.SQRT2);
    }
  }

  out.peers = {
    count: peerNodes.length, observed: round(peerObserved, 2), failures: round(peerFailures, 2),
    pooledRate: round(pooled, 6), medianRate: round(median, 6), p10Rate: round(p10, 6), p90Rate: round(p90, 6),
    minRate: round(Math.min(...rates), 6), maxRate: round(Math.max(...rates), 6),
  };
  out.comparison = {
    rate: round(ownRate, 6),
    ratioToMedian: median > 0 ? round(ownRate / median, 3) : null,
    ratioToPooled: pooled > 0 ? round(ownRate / pooled, 3) : null,
    percentile: round((below + 0.5 * ties) / rates.length, 4),
    peersAbove: rates.filter((r) => r > ownRate).length,
    excessFailures: pooled !== null ? round(ownFailures - observed * pooled, 2) : null,
    z: round(z, 3), pValue: round(pValue, 6), direction,
    method: "Normalnaeherung der Binomialverteilung mit Stetigkeitskorrektur 0,5; pValue einseitig in der beobachteten Richtung (approximativ, erfc Chebyshev-Annaeherung, Gegenprobe gegen numerische Integration; unabhaengige Ledger angenommen - die Peer-Streuung ist breiter, z ist eine Groessenordnung)",
  };

  // Typ-Ebene: ein Knoten, der nur bei wrong-hash herausragt, hat ein anderes Problem als
  // einer, der nur bei missed herausragt. Die Gesamtsumme verwischt das.
  out.types = PEER_TYPES.map((k) => {
    const ownC = own[k];
    const ownR = ownC / observed;
    const peerC = peerNodes.reduce((s, p) => s + p._t[k], 0);
    const peerR = peerObserved > 0 ? peerC / peerObserved : null;
    const perPeer = peerNodes.map((p) => (p._t.observed > 0 ? p._t[k] / p._t.observed : null)).filter((x) => Number.isFinite(x));
    const med = quantile(perPeer, 0.5), hi = quantile(perPeer, 0.9);
    let tz = null;
    const sd = peerR !== null && peerR > 0 && peerR < 1 ? Math.sqrt(observed * peerR * (1 - peerR)) : 0;
    if (sd > 0) tz = (ownC - observed * peerR - 0.5) / sd;
    return {
      type: k, own: round(ownC, 2), ownRate: round(ownR, 6),
      peerRate: round(peerR, 6), peerMedianRate: round(med, 6), peerP90Rate: round(hi, 6),
      ratio: med > 0 ? round(ownR / med, 3) : null, z: round(tz, 3),
      abovePeerP90: ownR > (Number.isFinite(hi) ? hi : 0) && ownC >= 1,
    };
  });

  // no-quorum ist Netz-Aussetzung, nicht Knotenfehler: sichtbar, aber ausserhalb der Rate,
  // nach der das Urteil gefaellt wird.
  const peerNQ = peerNodes.map((p) => p._t.noQuorum / p._t.observed).filter((x) => Number.isFinite(x));
  out.network = {
    ownNoQuorum: round(own.noQuorum, 2),
    ownNoQuorumRate: round(own.noQuorum / observed, 6),
    peerMedianNoQuorumRate: round(quantile(peerNQ, 0.5), 6),
    note: "no-quorum zaehlt nicht in die Knotenrate: der Ledger ist aus dem validierten Stream bewiesen geschlossen (lib/validator-trace.mjs), das Netz hat sein Quorum also erreicht. 'no-quorum' sagt nur, dass dieser Rekorder zu wenige Stimmen der beobachteten dUNL sah - ueber die Ursache des Knoten sagt er nichts",
  };

  const aboveP90 = Number.isFinite(p90) && ownRate > p90;
  const aboveMedian = Number.isFinite(median) && ownRate > median;
  const zOut = Number.isFinite(z) && z >= PEER_OUTLIER_Z;
  const zElev = Number.isFinite(z) && z >= PEER_ELEVATED_Z;

  const band = ownRate < (Number.isFinite(median) ? median : 0) ? "rate-below-peer-median" : "rate-within-peer-band";
  if (ownFailures === 0) {
    out.verdict = "peer-baseline";
    out.verdictReason = band;
  } else if (pooled === 0) {
    out.verdict = "outlier";
    out.verdictReason = "no-peer-failures";
  } else if (aboveP90 && zOut && ownFailures >= PEER_MIN_OUTLIER_FAILS) {
    out.verdict = "outlier";
    out.verdictReason = "rate-above-peer-p90";
  } else if ((aboveMedian && zElev) || (aboveP90 && ownFailures >= 3)) {
    out.verdict = "elevated";
    out.verdictReason = "rate-above-peer-median";
  } else {
    out.verdict = "peer-baseline";
    out.verdictReason = band;
  }
  return out;
}