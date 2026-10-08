// lib/validator-service.mjs — serverseitige xrpscan-Abfrage für die Validator-Ansicht.
// Eine Abfrage pro Takt: Registry + höchstens watchlistMax Validator-Infos, nacheinander
// (schont die xrpscan-Quote). Ergebnis 60 s im Prozess-Cache. Fehler -> Exception an den
// Aufrufer (fail-closed: der Endpunkt liefert 502, nie geratene Werte).
// Attribution: xrpscan-Daten unter CC BY-NC-SA 4.0 (wird mit ausgeliefert).
import { parseValidatorInfo, selectWatchlist, healthAlerts } from "./validator-health.mjs";

const XRPSCAN_API = "https://api.xrpscan.com/api/v1";
const CACHE_MS = 60000;
const TIMEOUT_MS = 8000;
let cache = null;                 // { time, body }
const previous = new Map();       // masterKey -> letzter Stand (für Wechsel-Alarme)

async function xget(path) {
  const res = await fetch(XRPSCAN_API + path, { headers: { accept: "application/json" }, signal: AbortSignal.timeout(TIMEOUT_MS) });
  if (!res.ok) throw new Error("xrpscan HTTP " + res.status);
  return res.json();
}

export async function validatorView({ now = Date.now(), fetchJson = xget } = {}) {
  if (cache && now - cache.time < CACHE_MS) return cache.body;
  const registry = await fetchJson("/validatorregistry");
  const infos = [];
  for (const v of selectWatchlist(registry)) {
    const cur = parseValidatorInfo(await fetchJson("/validator/" + encodeURIComponent(v.masterKey)));
    if (cur) infos.push({ cur, prev: previous.get(v.masterKey) ?? null, mk: v.masterKey });
  }
  const alerts = [];
  const validators = [];
  for (const { cur, prev, mk } of infos) {
    alerts.push(...healthAlerts(cur, prev));
    previous.set(mk, cur);
    validators.push({
      key: cur.key,
      domain: cur.domain,
      revoked: cur.revoked,
      unl: cur.unl,
      agreement1h: cur.agreement1h,
      agreement24h: cur.agreement24h,
      agreement30d: cur.agreement30d,
    });
  }
  const body = { updatedAt: now, source: "xrpscan", license: "CC BY-NC-SA 4.0", validators, alerts };
  cache = { time: now, body };
  return body;
}

// Test-Helfer: Zustand zurücksetzen.
export function resetValidatorCacheForTests() {
  cache = null;
  previous.clear();
}
