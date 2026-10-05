'use strict';
// public/name-index.mjs — Client-Seite der XRPScan-Namensauflösung.
//
// MODUL-VERTRAG (DOM-frei beim Import — zwingend, Muster public/i18n.mjs:6-9
// und public/attribution.mjs): kein document-/window-Zugriff auf Modulebene;
// fetch wird ausschließlich zur Aufrufzeit über globalThis.fetch geholt (nie
// auf Modulebene gebunden — sonst wäre der Injektions-Stub in
// public/name-index.test.mjs unwirksam und der 'GENAU EIN Bulk-Call'-Zähler
// nicht messbar). Der Import von '../lib/name-resolve.mjs' ist ein reiner
// ESM ohne DOM/fetch (Unit-Tests: lib/name-resolve.test.mjs).
//
// Prinzip (Plan 'client-seitige Anreicherung'): GENAU EIN Bulk-Fetch
// GET https://api.xrpscan.com/api/v1/names/well-known pro Page-Session
// (In-Flight-Guard + TTL 6 h), lazy — nie im Head, nie im WSS-Takt, nie pro
// Cluster-Adresse. Die Bulk-Liste (≈357 kB, 2772 Einträge, ACAO: * gemessen
// 2026-10-05) wird NIE persistiert (kein data/*, kein flow-state-Feld).
// Fail-closed: jeder Fehler (HTTP-Fehler, Timeout 5 s, Parse) liefert die
// leere Map bzw. den letzten guten Stand — ein xrpscan-Ausfall darf den
// Live-Betrieb nie brechen und erzeugt keinen Retry-Loop.
//
// Einzel-Konto-Ergänzung lookupAccountName(addr): GET
// /api/v1/account/{acct} NUR im Konto-Check-Pfad und NUR bei Fehlen in der
// Bulk-Map; Cache-Cap 200, TTL 24 h (analog lib/entity-resolve.mjs:334-367).
//
// Gate-Grenze: dieses Modul entscheidet NICHT, ob ein Name zeigen darf. Die
// Maske (isFullShownAddr) sitzt im Host public/app.js (accountNameOf);
// nameIndexOf liefert nur den Roh-Lookup für bereits gegatete Adressen.

import { parseWellKnown, nameFor, mergeNameMaps } from '../lib/name-resolve.mjs';

export const NAME_INDEX_TTL_MS = 6 * 60 * 60 * 1000;   // Bulk: 6 h
export const ACCOUNT_TTL_MS = 24 * 60 * 60 * 1000;     // Einzelkonto: 24 h
export const ACCOUNT_CACHE_MAX = 200;                  // Deckel des Einzel-Caches
const BULK_URL = 'https://api.xrpscan.com/api/v1/names/well-known';
const ACCOUNT_URL_BASE = 'https://api.xrpscan.com/api/v1/account/';
const FETCH_TIMEOUT_MS = 5000;
// Adress-Validierung (identisch zu lib/name-resolve.mjs): ungültige Eingaben
// lösen nie einen Netzwerk-Fetch aus (Defense-in-Depth — der Host gateet
// bereits, das Modul wirft Müll zusätzlich vor dem Fetch weg).
const XRPL_ADDRESS_RE = /^r[1-9A-HJ-NP-Za-km-z]{24,34}$/;

let bulkMap = null;              // letzter guter Bulk-Stand (null = nie erfolgreich)
let bulkFetchedAt = 0;
let bulkInFlight = null;         // In-Flight-Guard: nie zwei Bulk-Fetches zugleich
const accountCache = new Map();  // addr -> {entry, at}
const accountInFlight = new Map(); // addr -> Promise

// fetch-Resolver: erst zur Aufrufzeit (Testbarkeit durch Injektion des
// globalen fetch; ohne fetch-Umgebung → fail-closed leere Map).
function fetchImpl(url, opts) {
  if (typeof globalThis.fetch !== 'function') return Promise.reject(new Error('fetch-unavailable'));
  return globalThis.fetch(url, opts);
}

// Bulk-Index holen (lazy, genau ein Fetch pro Session innerhalb des TTL).
// Gibt die Map zurück (leere Map bei Fehler, letzter guter Stand bei
// TTL-Überschreitung mit Fehler — fail-closed, kein Retry-Loop).
export function ensureNameIndex() {
  const now = Date.now();
  if (bulkMap && now - bulkFetchedAt < NAME_INDEX_TTL_MS) return Promise.resolve(bulkMap);
  if (bulkInFlight) return bulkInFlight;
  bulkInFlight = (async () => {
    try {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);
      try {
        const res = await fetchImpl(BULK_URL, { signal: controller.signal, cache: 'no-store' });
        if (!res || !res.ok) return bulkMap ?? new Map();
        const data = await res.json();
        const map = parseWellKnown(data);
        bulkMap = map;
        bulkFetchedAt = Date.now();
        return map;
      } finally {
        clearTimeout(timer);
      }
    } catch {
      // Timeout/Netz/Parse: alter Stand bleibt, sonst leere Map. Kein Retry.
      return bulkMap ?? new Map();
    } finally {
      bulkInFlight = null;
    }
  })();
  return bulkInFlight;
}

// Synchroner Bulk-Lookup gegen den letzten guten Stand (null ohne Stand).
export function nameIndexOf(addr) {
  return bulkMap ? nameFor(bulkMap, addr) : null;
}

// Synchroner Gesamt-Lookup: Bulk zuerst, dann Einzel-Konto-Cache.
export function lookupNameCached(addr) {
  const a = String(addr ?? '').trim();
  if (!a) return null;
  const bulk = nameIndexOf(a);
  if (bulk) return bulk;
  const cached = accountCache.get(a);
  if (cached && Date.now() - cached.at < ACCOUNT_TTL_MS) return cached.entry;
  return null;
}

// Einzel-Konto-Ergänzung: nur bei Fehlen in Bulk-Map und Cache; gecacht,
// gedeckelt (Cap 200, TTL 24 h), fail-closed (Fehler -> null, kein Retry).
export function lookupAccountName(addr) {
  const a = String(addr ?? '').trim();
  if (!a || !XRPL_ADDRESS_RE.test(a)) return Promise.resolve(null);
  const known = lookupNameCached(a);
  if (known) return Promise.resolve(known);
  if (accountInFlight.has(a)) return accountInFlight.get(a);
  const p = (async () => {
    try {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);
      try {
        const res = await fetchImpl(ACCOUNT_URL_BASE + encodeURIComponent(a), { signal: controller.signal, cache: 'no-store' });
        if (!res || !res.ok) return null;
        const body = await res.json();
        const nameObj = body && typeof body === 'object' ? body.accountName : null;
        if (!nameObj || typeof nameObj !== 'object') return null;
        const entry = {
          name: String(nameObj.name ?? '').trim(),
          domain: typeof nameObj.domain === 'string' && nameObj.domain.trim() ? nameObj.domain.trim().toLowerCase() : null,
          twitter: typeof nameObj.twitter === 'string' ? nameObj.twitter.trim() : '',
          verified: nameObj.verified === true,
        };
        const map = parseWellKnown([{ account: a, ...entry }]);
        const parsed = map.get(a);
        if (!parsed) return null; // Adresse oder Name ungültig → nichts cachen
        // Deckel: ältester Eintrag fällt (Map-Einfügeordnung = Alterung).
        if (accountCache.size >= ACCOUNT_CACHE_MAX) {
          const oldest = accountCache.keys().next().value;
          if (oldest !== undefined) accountCache.delete(oldest);
        }
        accountCache.set(a, { entry: parsed, at: Date.now() });
        return parsed;
      } finally {
        clearTimeout(timer);
      }
    } catch {
      return null;
    } finally {
      accountInFlight.delete(a);
    }
  })();
  accountInFlight.set(a, p);
  return p;
}

// Merge-Helfer für den Host: Bulk-Map über statischer Registry-Fallback-Map
// (Priorität xrpscan-Bulk → Einzel-Konto → statische exchange-registry).
export function mergeWithFallback(primary, fallback) {
  return mergeNameMaps(primary, fallback);
}
