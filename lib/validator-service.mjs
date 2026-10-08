// lib/validator-service.mjs — serverseitige Validator-Ansicht (dUNL vollständig).
// Quelle der Mitgliedschaft: signierte Ripple-Validator-Liste (vl.ripple.com, 1 h Cache).
// Jeder VL-Schlüssel wird auf den xrpscan-Registry-Master abgebildet; Nicht-Zuordenbare
// werden im Ergebnis ausgewiesen (dunl.listed vs. dunl.matched), nie still verworfen.
// Fallback nur, wenn die VL nicht erreichbar ist: Registry-Tags (dunl.source sagt es).
// Infos je Validator: xrpscan /api/v1/validator/{master} in 5er-Gruppen, 60 s Cache.
// Attribution: xrpscan-Daten unter CC BY-NC-SA 4.0 (wird mit ausgeliefert).
import { parseValidatorInfo, selectWatchlist, healthAlerts, decodeValidatorList, watchlistFromVl } from "./validator-health.mjs";

const XRPSCAN_API = "https://api.xrpscan.com/api/v1";
const VL_URL = "https://vl.ripple.com";
const CACHE_MS = 60000;
const VL_CACHE_MS = 3600000;
const TIMEOUT_MS = 8000;
const GROUP = 5;
let cache = null;                 // { time, body }
let vlCache = null;               // { time, vl }
const previous = new Map();       // masterKey -> letzter Stand (für Wechsel-Alarme)

async function getJson(url) {
  const res = await fetch(url, { headers: { accept: "application/json" }, signal: AbortSignal.timeout(TIMEOUT_MS) });
  if (!res.ok) throw new Error("HTTP " + res.status + " " + url);
  return res.json();
}
const xget = (path) => getJson(XRPSCAN_API + path);

export async function validatorView({ now = Date.now(), fetchJson = xget, fetchVl = () => getJson(VL_URL) } = {}) {
  if (cache && now - cache.time < CACHE_MS) return cache.body;
  const registry = await fetchJson("/validatorregistry");
  let vl = null;
  if (vlCache && now - vlCache.time < VL_CACHE_MS) vl = vlCache.vl;
  else {
    try { vl = decodeValidatorList(await fetchVl()); if (vl) vlCache = { time: now, vl }; } catch { vl = null; }
  }
  let watch;
  if (vl && vl.keys.length) {
    const w = watchlistFromVl(vl, registry);
    watch = { entries: w.entries, dunl: { source: "vl.ripple.com", sequence: vl.sequence, listed: w.listed, matched: w.matched, unmatched: w.unmatched } };
  } else {
    const fb = selectWatchlist(registry, Number.MAX_SAFE_INTEGER);
    watch = { entries: fb, dunl: { source: "registry-tag-fallback", sequence: null, listed: null, matched: fb.length, unmatched: [] } };
  }
  const infos = [];
  for (let i = 0; i < watch.entries.length; i += GROUP) {
    const part = watch.entries.slice(i, i + GROUP);
    const res = await Promise.all(part.map(async (v) => ({ v, cur: parseValidatorInfo(await fetchJson("/validator/" + encodeURIComponent(v.masterKey))) })));
    for (const { v, cur } of res) if (cur) infos.push({ cur, prev: previous.get(v.masterKey) ?? null, mk: v.masterKey });
  }
  const alerts = [];
  const validators = [];
  for (const { cur, prev, mk } of infos) {
    alerts.push(...healthAlerts(cur, prev));
    previous.set(mk, cur);
    validators.push({ key: cur.key, domain: cur.domain, revoked: cur.revoked, unl: cur.unl, agreement1h: cur.agreement1h, agreement24h: cur.agreement24h, agreement30d: cur.agreement30d });
  }
  const body = { updatedAt: now, source: "xrpscan", license: "CC BY-NC-SA 4.0", dunl: watch.dunl, validators, alerts };
  cache = { time: now, body };
  return body;
}

// Test-Helfer: Zustand zurücksetzen.
export function resetValidatorCacheForTests() {
  cache = null;
  vlCache = null;
  previous.clear();
}
