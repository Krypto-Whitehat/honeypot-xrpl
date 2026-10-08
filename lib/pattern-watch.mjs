// lib/pattern-watch.mjs — Muster-Monitor auf Ledger-Ebene (rein, DOM-frei, ohne I/O).
//
// Erkennt ungewöhnliche Netzwerk-/Validator-Muster aus validierten Ledgern:
//   load-spike   Transaktionsdichte weit über dem Median der letzten Ledger
//   close-gap    Ledger-Abstand (Close-Zeit) deutlich über dem Median-Takt
//   fund-burst   Fraud-Funde (malicious+suspect) pro Ledger weit über Median
// Alle Schwellen sind TUNING-DEFAULTS ohne Kampagnen-Nachweis (wie PEELING_THRESHOLDS),
// explizit ausgewiesen und per opts überschreibbar. Keine Schätzung ohne Basis:
// unter MIN_BASELINE Ledgern wird NICHTS gemeldet.
//
// Eingabe-Sample: { ledgerIndex:number, closeMs:number, txCount:number,
//                   malicious:number, suspect:number }   (sortiert nach ledgerIndex)

export const PATTERN_DEFAULTS = {
  baselineSize: 60,      // rollendes Basisfenster (Ledger)
  minBaseline: 10,       // darunter keine Meldung (kein Raten)
  spikeMinTx: 50,        // absolute Untergrenze für load-spike
  spikeRatio: 3,         // txCount >= 3 × Median
  gapMinMs: 15000,       // Close-Lücke mindestens 15 s
  gapRatio: 4,           // Lücke >= 4 × Median-Takt
  burstMinFindings: 5,   // absolute Untergrenze für fund-burst
  burstRatio: 4,         // Funde >= 4 × Median
};

function median(values) {
  if (!values.length) return 0;
  const s = [...values].sort((a, b) => a - b);
  const m = Math.floor(s.length / 2);
  return s.length % 2 ? s[m] : (s[m - 1] + s[m]) / 2;
}

// Liefert Anomalien in Ledger-Reihenfolge. Jede Anomalie trägt Zeitstempel,
// beobachteten Wert, Basis (Median) und Verhältnis -> nachvollziehbar für Trace.
export function detectPatterns(samples, opts = {}) {
  const p = { ...PATTERN_DEFAULTS, ...opts };
  const rows = (Array.isArray(samples) ? samples : [])
    .filter((s) => s && Number.isFinite(s.ledgerIndex) && Number.isFinite(s.closeMs))
    .sort((a, b) => a.ledgerIndex - b.ledgerIndex);
  const out = [];
  for (let i = 0; i < rows.length; i++) {
    const cur = rows[i];
    const base = rows.slice(Math.max(0, i - p.baselineSize), i);
    if (base.length < p.minBaseline) continue;
    const meta = { ledgerIndex: cur.ledgerIndex, timeMs: cur.closeMs };

    const medTx = median(base.map((s) => Number(s.txCount) || 0));
    const tx = Number(cur.txCount) || 0;
    if (tx >= p.spikeMinTx && tx >= p.spikeRatio * medTx) {
      out.push({ ...meta, type: "load-spike", value: tx, baseline: medTx, ratio: medTx > 0 ? tx / medTx : null });
    }

    const gaps = [];
    for (let j = 1; j < base.length; j++) gaps.push(base[j].closeMs - base[j - 1].closeMs);
    const medGap = median(gaps.filter((g) => g > 0));
    const gap = i > 0 ? cur.closeMs - rows[i - 1].closeMs : 0;
    if (medGap > 0 && gap >= p.gapMinMs && gap >= p.gapRatio * medGap) {
      out.push({ ...meta, type: "close-gap", value: gap, baseline: medGap, ratio: gap / medGap });
    }

    const medF = median(base.map((s) => (Number(s.malicious) || 0) + (Number(s.suspect) || 0)));
    const f = (Number(cur.malicious) || 0) + (Number(cur.suspect) || 0);
    if (f >= p.burstMinFindings && f >= p.burstRatio * medF) {
      out.push({ ...meta, type: "fund-burst", value: f, baseline: medF, ratio: medF > 0 ? f / medF : null });
    }
  }
  return out;
}

// Trace-Fenster für spätere Validator-Untersuchungen: Samples + Anomalien im
// Zeitraum [fromMs, toMs] (inklusive). Reine Filterung, keine Neuberechnung der Basis.
export function traceWindow(samples, anomalies, fromMs, toMs) {
  const inW = (t) => t >= fromMs && t <= toMs;
  return {
    samples: (samples || []).filter((s) => inW(s.closeMs)),
    anomalies: (anomalies || []).filter((a) => inW(a.timeMs)),
  };
}
