// lib/validator-health.mjs — Validator-Gesundheit aus xrpscan (rein, ohne I/O).
// Datenquellen (xrpscan, CC BY-NC-SA 4.0 — Attribution im Panel):
//   GET /api/v1/validatorregistry      Liste aktiver Validatoren (master_key, domain, unl)
//   GET /api/v1/validator/{key}        agreement_1h / _24h / _30day, revoked, unl, signing_key
// Alarme sind deterministische Schwellen (TUNING-DEFAULTS, ausgewiesen wie
// PEELING_THRESHOLDS) und nur bei belastbarer Stichprobe (total >= minTotal).
export const VALIDATOR_DEFAULTS = {
  minTotal1h: 200,        // unter 200 Validierungen je Stunde: keine Score-Aussage
  scoreMin: 0.95,         // Agreement-Score 1 h unter 0.95 -> agreement-drop
  missedRatioMax: 0.05,   // > 5 % verpasste Validierungen je Stunde -> missed-surge
  watchlistMax: 12,       // Obergrenze der Abfragen je Takt (xrpscan-Quote schonen)
};

const num = (v) => { const n = Number(v); return Number.isFinite(n) ? n : null; };

function agreementOf(a) {
  if (!a || typeof a !== "object") return null;
  return { score: num(a.score), missed: num(a.missed), total: num(a.total), incomplete: a.incomplete === true };
}

// Normalisiert die Antwort von /api/v1/validator/{key}. Fehlerhafte Antwort -> null.
export function parseValidatorInfo(json) {
  if (!json || typeof json !== "object" || json.result === "error") return null;
  const key = typeof json.validation_public_key === "string" ? json.validation_public_key : null;
  if (!key) return null;
  return {
    key,
    masterKey: typeof json.master_key === "string" ? json.master_key : key,
    signingKey: typeof json.signing_key === "string" ? json.signing_key : null,
    domain: typeof json.domain === "string" ? json.domain : null,
    revoked: json.revoked === true,
    unl: typeof json.unl === "string" ? json.unl : (Array.isArray(json.unl) ? json.unl.join(",") : null),
    currentIndex: num(json.current_index),
    agreement1h: agreementOf(json.agreement_1h),
    agreement24h: agreementOf(json.agreement_24h),
    agreement30d: agreementOf(json.agreement_30day),
  };
}

// Watchlist aus der Registry: Validatoren der öffentlichen UNL mit Domain, zuletzt
// gesehen zuerst, gedeckelt. Ohne Domain oder UNL-Eintrag -> nicht beobachtet.
export function selectWatchlist(registry, max = VALIDATOR_DEFAULTS.watchlistMax) {
  const rows = (Array.isArray(registry) ? registry : [])
    .filter((r) => r && typeof r.master_key === "string" && typeof r.domain === "string" && r.domain
      && Array.isArray(r.unl) && r.unl.some((u) => u === "vl.ripple.com" || u === "vl.xrplf.org"));
  rows.sort((a, b) => (Date.parse(b.last_seen) || 0) - (Date.parse(a.last_seen) || 0));
  return rows.slice(0, Math.max(0, max)).map((r) => ({ masterKey: r.master_key, domain: r.domain }));
}

// Alarme aus aktuellem Stand (und optional dem vorherigen Stand für Schlüssel-/UNL-Wechsel).
// Jeder Alarm: {type, severity, key, value?, threshold?} — severity folgt der Engine-Skala.
export function healthAlerts(cur, prev = null, opts = {}) {
  const p = { ...VALIDATOR_DEFAULTS, ...opts };
  const out = [];
  if (!cur) return out;
  if (cur.revoked) out.push({ type: "validator-revoked", severity: "malicious", key: cur.key });
  const a = cur.agreement1h;
  if (a && a.total != null && a.total >= p.minTotal1h && !a.incomplete) {
    if (a.score != null && a.score < p.scoreMin) {
      out.push({ type: "agreement-drop", severity: "suspect", key: cur.key, value: a.score, threshold: p.scoreMin });
    }
    const ratio = a.missed / a.total;
    if (ratio > p.missedRatioMax) {
      out.push({ type: "missed-surge", severity: "suspect", key: cur.key, value: Math.round(ratio * 1000) / 10, threshold: p.missedRatioMax * 100 });
    }
  }
  if (prev) {
    if (prev.signingKey && cur.signingKey && prev.signingKey !== cur.signingKey) {
      out.push({ type: "signing-key-rotated", severity: "suspect", key: cur.key });
    }
    if (prev.unl && cur.unl && prev.unl !== cur.unl) {
      out.push({ type: "unl-membership-changed", severity: "suspect", key: cur.key });
    }
  }
  return out;
}

// Trace: Tagesberichte (/validator/{key}/reports) in einem Zeitraum filtern.
export function reportTrace(reports, fromMs, toMs) {
  return (Array.isArray(reports) ? reports : [])
    .map((r) => ({ date: r.date, timeMs: Date.parse(r.date), score: num(r.score), missed: num(r.missed), total: num(r.total) }))
    .filter((r) => Number.isFinite(r.timeMs) && r.timeMs >= fromMs && r.timeMs <= toMs)
    .sort((a, b) => a.timeMs - b.timeMs);
}
