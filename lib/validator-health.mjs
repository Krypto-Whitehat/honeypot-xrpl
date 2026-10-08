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

// ---------- dUNL: signierte Validator-Liste (Ripple/XRPL-Projekt) ----------
// Die VL-Antwort ist {blob, public_key, manifest, signature, version}; blob = Base64-JSON
// mit validators[].validation_public_key (Hex, Master-Schlüssel laut Ripple-VL). Die
// xrpscan-Registry indiziert Master-Schlüssel im Base58-Format "n…". Umrechnung hier, ohne
// fremde Bibliothek (Serverpfad klein halten); Testvektoren gegen ripple-address-codec.
import { createHash } from "node:crypto";
const XRPL_ALPHABET = "rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz";

export function nodePublicB58(hex) {
  if (typeof hex !== "string" || !/^[0-9A-Fa-f]{66}$/.test(hex)) return null;
  const payload = Buffer.concat([Buffer.from([0x1c]), Buffer.from(hex, "hex")]);
  const sum = createHash("sha256").update(createHash("sha256").update(payload).digest()).digest().subarray(0, 4);
  let n = BigInt("0x" + Buffer.concat([payload, sum]).toString("hex"));
  let out = "";
  while (n > 0n) { out = XRPL_ALPHABET[Number(n % 58n)] + out; n /= 58n; }
  return out;
}

export function decodeValidatorList(json) {
  if (!json || typeof json.blob !== "string") return null;
  let doc;
  try { doc = JSON.parse(Buffer.from(json.blob, "base64").toString("utf8")); } catch { return null; }
  const keys = (Array.isArray(doc?.validators) ? doc.validators : [])
    .map((v) => v?.validation_public_key)
    .filter((k) => typeof k === "string" && /^[0-9A-Fa-f]{66}$/.test(k));
  return { sequence: num(doc?.sequence), expiration: num(doc?.expiration), keys };
}

// dUNL-Watchlist: jeder VL-Schlüssel wird auf seinen Registry-Master abgebildet.
// Nicht zuordenbare Schlüssel werden ausgewiesen (listed vs. matched), nie still verworfen.
export function watchlistFromVl(vl, registry) {
  const byMaster = new Map((Array.isArray(registry) ? registry : [])
    .filter((r) => r && typeof r.master_key === "string").map((r) => [r.master_key, r]));
  const entries = [];
  const unmatched = [];
  for (const hex of vl?.keys ?? []) {
    const master = nodePublicB58(hex);
    const r = master && byMaster.get(master);
    if (r) entries.push({ masterKey: master, domain: typeof r.domain === "string" && r.domain ? r.domain : null });
    else unmatched.push(hex.slice(0, 12));
  }
  return { entries, listed: (vl?.keys ?? []).length, matched: entries.length, unmatched };
}
