'use strict';
// lib/name-resolve.mjs — XRPScan-Namensauflösung (well-known-Aliase) für
// Börsen-/Firmen-Konten. Reines ESM ohne DOM und ohne fetch auf Modulebene:
// läuft identisch in Node (Unit-Tests: lib/name-resolve.test.mjs) und im
// Browser (importiert von public/name-index.mjs; ausgeliefert über die
// /lib-Whitelist in api/lib-detector.js und server/index.mjs — dieselbe
// Liste, die bereits detector/cluster/sanitize/stride/rate-gate liefert).
// Alle exportierten Funktionen werfen nie; jede Eingabe darf null/undefined
// sein (Muster public/attribution.mjs).
//
// Datenquelle (Client-Seite, CORS offen — ACAO: * gemessen 2026-10-05):
//   GET https://api.xrpscan.com/api/v1/names/well-known
//   JSON-Array; Felder pro Eintrag: name, desc, account, domain, twitter,
//   verified. verified fehlt bei einem großen Teil der Einträge → Default
//   false. Lizenz der API: CC BY-NC-SA 4.0 (docs.xrpscan.com) — Attribution
//   gehört in die Oberfläche (i18n-Key 'name.sourceNote').
//
// Sicherheitsgrenze: dieses Modul kennt keine Köder und liest keine
// bait-Dateien. Namen sind reine Anzeige-Metadaten; die Gate-Entscheidung,
// ob ein Name überhaupt zeigen darf (isFullShownAddr), liegt ausschließlich
// im Host (public/app.js accountNameOf) — nie hier.

// Adress-Validierung identisch zu public/account-check.js:30.
const XRPL_ADDRESS_RE = /^r[1-9A-HJ-NP-Za-km-z]{24,34}$/;

// Kappen (Übersichtlichkeit in Chips/Labels; Name verdrängt nie die Adresse).
const NAME_MAX_LEN = 48;
const DOMAIN_MAX_LEN = 63;
const NAME_INDEX_MAX_ENTRIES = 3000;

// Domain-Form: einfache Host-Validierung (kein DNS, keine Verifikation —
// domain ist reines Anzeige-Metadatum, Muster lib/entity-resolve.mjs:32-35).
const DOMAIN_RE = /^[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)+$/;

// Name/Domäne/Twitter sanitisieren: Steuerzeichen und HTML-Zeichen entfernen,
// Whitespace verdichten, trimmen, auf maxLen kappen. Nie werfen.
export function sanitizeName(raw, maxLen = NAME_MAX_LEN) {
  let s = String(raw ?? '');
  // Steuerzeichen (inkl. \n, \r, \t) und HTML-/Zitatzeichen ersetzen.
  s = s.replace(/[\u0000-\u001F\u007F<>"]/g, ' ');
  s = s.replace(/\s+/g, ' ').trim();
  if (s.length > maxLen) s = s.slice(0, maxLen).trim();
  return s;
}

// Bulk-Antwort -> Map<account, {name, domain, twitter, verified}>.
// raw: geparstes JSON (Array) oder null/undefined. Entries-Cap 3000.
// Entries ohne gültige Adresse oder ohne brauchbaren Namen fallen raus.
export function parseWellKnown(raw) {
  const map = new Map();
  if (!Array.isArray(raw)) return map;
  for (const e of raw) {
    if (map.size >= NAME_INDEX_MAX_ENTRIES) break;
    if (!e || typeof e !== 'object') continue;
    const account = String(e.account ?? '').trim();
    if (!XRPL_ADDRESS_RE.test(account)) continue;
    const name = sanitizeName(e.name);
    if (!name) continue;
    const domainRaw = String(e.domain ?? '').trim().toLowerCase();
    const domain = domainRaw && domainRaw.length <= DOMAIN_MAX_LEN && DOMAIN_RE.test(domainRaw)
      ? domainRaw
      : null;
    const twitter = sanitizeName(e.twitter, 32) || null;
    map.set(account, {
      name,
      domain,
      twitter,
      verified: e.verified === true,
    });
  }
  return map;
}

// Lookup: Entry oder null. Nie werfen; ungültige Eingaben liefern null.
export function nameFor(map, addr) {
  if (!(map instanceof Map)) return null;
  const a = String(addr ?? '').trim();
  if (!a) return null;
  const entry = map.get(a);
  return entry ?? null;
}

// Merge mit Priorität: primary schlägt fallback (identische Adresse in
// beiden -> primary-Wert gewinnt). Ergebnis ist eine neue Map; die Eingaben
// werden nicht verändert. Reihenfolge im Ergebnis: primary zuerst.
export function mergeNameMaps(primary, fallback) {
  const merged = new Map();
  if (fallback instanceof Map) {
    for (const [k, v] of fallback) merged.set(k, v);
  }
  if (primary instanceof Map) {
    for (const [k, v] of primary) merged.set(k, v);
  }
  return merged;
}

// Badge-Deskriptor für die Oberfläche: {label, verified, domain} oder null.
// label ist der sanitisierte Name; domain nur, wenn vorhanden.
export function nameBadge(addr, entry) {
  if (!entry || typeof entry !== 'object') return null;
  const label = sanitizeName(entry.name);
  if (!label) return null;
  return {
    label,
    verified: entry.verified === true,
    domain: typeof entry.domain === 'string' && entry.domain ? entry.domain : null,
  };
}
