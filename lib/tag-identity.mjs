// lib/tag-identity.mjs — DestinationTag/SourceTag-Identitätsverfeinerung.
//
// HARTEN GRENZEN (identisch zu lib/cluster.mjs:3-8):
//   - pure ESM, KEINE npm-Imports, KEIN Node-Global `Buffer` (Browser-Pfad),
//     KEIN I/O, kein Date.now(): reine Funktionen über übergebene Daten.
//   - KEINE Secrets, KEINE Köder-Adressen in dieser Datei.
//
// WOVOR: Börsen-Konten (Exchange-Registry) sind Hosted-Accounts — viele
// Nutzer teilen EINE r-Adresse und werden über die DestinationTag-Nr.
// (UInt32, 0…4 294 967 295) unterschieden. Eine Kante A→Börse und eine
// Kante B→Börse sind nur dann Nachbarschaft im selben Hosted-Sub-Account,
// wenn die Tags gleich sind; verschiedene Tags (oder Tag vs. kein Tag)
// bedeuten: die Verbindung läuft über ein gemeinsames Börsen-Konto
// (transit). Tag 0 ist ein ECHTER Tag — "kein Tag" (Feld fehlt) ist eine
// eigene Identität. Deshalb niemals Truthiness (`if (tag)`), immer
// `tag != null`.
//
// EXPORT-VERTRAG:
//   normalizeTag(v)                     -> number|null   (UInt32-Grenze)
//   isMultiUserAccount(addr, registryMap) -> boolean     (nur Registry-Treffer)
//   computeTransitFlags(edges, registryMap) -> void      (setzt e.transit = true)
//
// RegistryMap-Form: Map<adresse, { exchange, tier, requireDestTag, ... }>
// (dieselbe Form wie loadExchangeRegistry in lib/threats-service.mjs).
// requireDestTag ist NUR ein Anzeige-Hinweis der Registry und erzeugt
// keine Identität — gezählt wird ausschließlich, was die Transaktion trägt.
//
// Transit-Regel (dokumentierte Entscheidung): Schlüsseldatum ist die
// EMPFÄNGER-Seite (toTag), weil DestinationTag ein festes Transaktionsfeld
// ist; SourceTag ist unzuverlässig und bleibt rein informativ. Für jede
// Registry-Adresse X werden über den vollen Kantensatz die Identitäten aller
// eingehenden Kanten (to === X) gesammelt: toTag-Wert oder "kein Tag".
// >= 2 verschiedene Identitäten -> alle eingehenden Kanten nach X erhalten
// transit: true. Gleiche (Adresse, Tag)-Paare erzeugen KEIN transit.
// Ausgehende Kanten von X werden nicht transit-markiert (kein verlässliches
// Tag-Feld). Die Funktion mutiert die übergebenen Edge-Objekte (nur das
// neue Feld transit), damit der Aufrufer (buildClusterGraph) sie vor dem
// Kanten-Cap auf den VOLLEN Satz anwenden kann — transit ist cap-unabhängig.

export const TAG_MAX = 4294967295; // 2**32 - 1 — XRPL-UInt32-Obergrenze

// Tag normalisieren: akzeptiert Number und Ziffern-String. Tag 0 ist ein
// echter Tag (gibt 0 zurück, nicht null). null nur, wenn das Feld fehlt
// (null/undefined/leer) oder ungültig ist (nicht ganzzahlig, negativ,
// > UInt32-Max, Nicht-Ziffern).
export function normalizeTag(v) {
  if (v == null) return null;
  if (typeof v === "number") {
    if (!Number.isInteger(v) || v < 0 || v > TAG_MAX) return null;
    return v;
  }
  if (typeof v === "string") {
    const s = v.trim();
    if (!/^\d+$/.test(s)) return null;
    const n = Number(s);
    if (!Number.isInteger(n) || n < 0 || n > TAG_MAX) return null;
    return n;
  }
  return null;
}

// Multi-User-Konto-Erkennung: true NUR bei Registry-Treffer (Map-Hit). Ohne Map
// oder ohne Treffer immer false — fail-closed, keine Adress-Heuristik.
export function isMultiUserAccount(addr, registryMap) {
  if (!(registryMap instanceof Map) || registryMap.size === 0) return false;
  if (typeof addr !== "string" || !addr) return false;
  return registryMap.has(addr);
}

// Transit-Flag über den vollen Kantensatz (vor jedem Cap aufrufen!).
// Siehe Kopf-Kommentar: nur Empfänger-Seite, "kein Tag" als eigene
// Identität, >= 2 Identitäten -> transit: true auf allen betroffenen
// (eingehenden) Kanten. Setzt das Feld NUR bei true (kein transit:false).
export function computeTransitFlags(edges, registryMap) {
  if (!Array.isArray(edges) || !(registryMap instanceof Map) || registryMap.size === 0) return;
  // 1) Identitäts-Sammlung pro Registry-Adresse (Eingangskanten).
  const identities = new Map(); // addr -> Set<"t<tag>" | "none">
  for (const e of edges) {
    if (!e || typeof e !== "object") continue;
    const to = typeof e.to === "string" ? e.to : null;
    if (!to || !registryMap.has(to)) continue;
    const key = e.toTag != null ? `t${e.toTag}` : "none";
    let set = identities.get(to);
    if (!set) {
      set = new Set();
      identities.set(to, set);
    }
    set.add(key);
  }
  // 2) Flag auf allen Kanten, deren Empfänger >= 2 Identitäten trägt.
  for (const e of edges) {
    if (!e || typeof e !== "object") continue;
    const to = typeof e.to === "string" ? e.to : null;
    if (!to || !registryMap.has(to)) continue;
    const set = identities.get(to);
    if (set && set.size >= 2) e.transit = true;
  }
}
