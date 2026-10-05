'use strict';
// public/exchange-registry.mjs — Client-Seite der Exchange-Registry
// (Destination-Tag-Identität, Hosted-Account-Chips).
//
// MODUL-VERTRAG (DOM-frei beim Import — zwingend, Muster
// public/name-index.mjs:4-19): kein document-/window-Zugriff auf Modulebene;
// fetch wird ausschließlich zur Aufrufzeit über globalThis.fetch geholt (nie
// auf Modulebene gebunden — Testbarkeit durch Injektion). Der Import von
// '../public/attribution.mjs' (parseExchangeRegistry) ist ein reiner ESM ohne
// DOM/fetch (Unit-Tests: lib/attribution.test.mjs).
//
// Prinzip (tagIdentityDesign 2026-10-05): GENAU EIN Fetch
// GET /data/exchange-registry.json pro Page-Session (In-Flight-Guard +
// TTL 6 h), lazy — nie im Head, nie im WSS-Takt. Die Datei ist same-origin
// (express.static / vercel.json, identische Quelle wie public/globe.js:85 und
// lib/threats-service.mjs:140). Fail-closed: jeder Fehler (HTTP-Fehler,
// Timeout 5 s, Parse) liefert die leere Map bzw. den letzten guten Stand —
// ein Ausfall darf den Live-Betrieb nie brechen und erzeugt keinen
// Retry-Loop.
//
// Gate-Grenze: dieses Modul entscheidet NICHT, ob ein Tag zeigen darf. Die
// Maske (isFullShownAddr) sitzt im Host public/app.js (exchangeEntryOf);
// exchangeEntryOfModul liefert nur den Roh-Lookup für bereits gegatete
// Adressen. Tags sind reine Edge-Attribute — die Registry liefert nur die
// Adresse->Börsen-Eintrag-Auflösung.

import { parseExchangeRegistry } from './attribution.mjs';
import { nameIndexSnapshot, lookupNameCached } from './name-index.mjs';

export const REGISTRY_TTL_MS = 6 * 60 * 60 * 1000; // 6 h — Registry ändert sich selten
const REGISTRY_URL = '/data/exchange-registry.json'; // same-origin (Muster globe.js:85)
const FETCH_TIMEOUT_MS = 5000;

let byAddressMap = null;        // letzter guter Stand (null = nie erfolgreich)
let fetchedAt = 0;
let inFlight = null;            // In-Flight-Guard: nie zwei Fetches zugleich

// fetch-Resolver: erst zur Aufrufzeit (Testbarkeit durch Injektion des
// globalen fetch; ohne fetch-Umgebung → fail-closed leere Map).
function fetchImpl(url, opts) {
  if (typeof globalThis.fetch !== 'function') return Promise.reject(new Error('fetch-unavailable'));
  return globalThis.fetch(url, opts);
}

// Registry holen (lazy, genau ein Fetch pro Session innerhalb des TTL).
// Gibt die Map zurück (leere Map bei Fehler, letzter guter Stand bei
// TTL-Überschreitung mit Fehler — fail-closed, kein Retry-Loop).
export function ensureExchangeRegistry() {
  const now = Date.now();
  if (byAddressMap && now - fetchedAt < REGISTRY_TTL_MS) return Promise.resolve(byAddressMap);
  if (inFlight) return inFlight;
  inFlight = (async () => {
    try {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);
      try {
        const res = await fetchImpl(REGISTRY_URL, { signal: controller.signal, cache: 'no-store' });
        if (!res || !res.ok) return byAddressMap ?? new Map();
        const data = await res.json();
        const parsed = parseExchangeRegistry(data);
        byAddressMap = parsed.byAddress;
        fetchedAt = Date.now();
        return byAddressMap;
      } finally {
        clearTimeout(timer);
      }
    } catch {
      // Timeout/Netz/Parse: alter Stand bleibt, sonst leere Map. Kein Retry.
      return byAddressMap ?? new Map();
    } finally {
      inFlight = null;
    }
  })();
  return inFlight;
}

// Synchroner Snapshot des letzten guten Stands (null ohne erfolgreichen
// Stand — Host behandelt null wie "kein Registry-Modul": fail-closed).
export function registrySnapshot() {
  return byAddressMap;
}

// Synchroner Einzel-Lookup gegen den letzten guten Stand (null ohne Treffer).
export function exchangeEntryOf(addr) {
  if (!byAddressMap) return null;
  const a = String(addr ?? '').trim();
  if (!a) return null;
  return byAddressMap.get(a) ?? null;
}

// ---------- Multi-User-Union (Registry ∪ verifizierte well-known-Namen) ----------
// Coverage-Fix 2026-10-05: die 81-Einträge-Registry erkennt weit weniger
// Börsen-Konten als der XRPScan-well-known-Bulk (2.772 Einträge, ~1.182
// verifiziert) — Tag-Chips blieben für z. B. rNxp4… (Binance) aus. Die
// Union formt verifizierte Bulk-Einträge in den Registry-Entry-Schema um
// ({exchange, domain, confidence:'well-known'}); bei Adress-Kollision
// gewinnt der Registry-Eintrag. KEIN Netzwerkzugriff hier: der Bulk steht
// synchron über nameIndexSnapshot() (public/name-index.mjs holt ihn lazy im
// Live-Takt), Einzel-Konto-Fetches bleiben dem Konto-Check-Pfad vorbehalten
// (dokumentierte Grenze name-index.mjs:21-23). Unverifizierte Namen tragen
// nie Chips (fail-closed).

// Gemergter Snapshot für den Graphen-Neubau (app.js multiUserAccounts):
// Registry-Map-Kopie ∪ verifizierte well-known-Einträge. Ohne guten Stand
// einer Quelle fällt die jeweilige Quelle leer aus (fail-closed).
export function multiUserSnapshot() {
  const merged = new Map(byAddressMap ?? []);
  const bulk = nameIndexSnapshot();
  if (bulk) {
    for (const [addr, entry] of bulk) {
      if (entry?.verified !== true || merged.has(addr)) continue;
      const name = String(entry.name ?? '').trim();
      if (!name) continue;
      merged.set(addr, {
        exchange: name,
        domain: typeof entry.domain === 'string' && entry.domain ? entry.domain : null,
        confidence: 'well-known',
      });
    }
  }
  return merged;
}

// Einzel-Lookup über die Union: Registry-Treffer zuerst, sonst der
// verifizierte well-known-Eintrag aus dem synchronen Namens-Index
// (Bulk zuerst, dann Einzel-Konto-Cache — lookupNameCached). Null ohne
// Treffer oder bei unverifiziertem Namen.
export function multiUserEntryOf(addr) {
  const reg = exchangeEntryOf(addr);
  if (reg) return reg;
  const a = String(addr ?? '').trim();
  if (!a) return null;
  let entry = null;
  try {
    entry = lookupNameCached(a);
  } catch {
    entry = null; // fail-closed: Index-Fehler bleibt ohne Chip
  }
  if (!entry || entry.verified !== true) return null;
  const name = String(entry.name ?? '').trim();
  if (!name) return null;
  return {
    exchange: name,
    domain: typeof entry.domain === 'string' && entry.domain ? entry.domain : null,
    confidence: 'well-known',
  };
}
