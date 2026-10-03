// lib/entity-resolve.mjs — Entity-Layer (Grenze 3): Kontrolle-Cluster über
// kryptografische Signale (RegularKey, Signer-Liste, EmailHash), serverseitig.
//
// HARTE GRENZEN (identisch zu lib/history.mjs:3-12): pure ESM, KEINE npm-
// Imports. Erlaubt: node:crypto (Signer-Fingerprint), der wiederverwendete
// GitHub-Transport aus lib/history.mjs. Läuft NIE im Browser und wird
// absichtlich NICHT in die /lib-Whitelist (api/lib-detector.js:16)
// aufgenommen — die Datei wird niemals an den Browser ausgeliefert.
// KEINE Secrets, KEINE Köder-Adressen-Literale in dieser Datei. Token/Repo-
// Werte aus ENV werden NIE geloggt (neutrale Error-Messages).
//
// TRANSPORT-AGNOSTIK DES WALK-COREs bleibt gewahrt (lib/ledger-walk.mjs:7-9):
// entity-resolve importiert NICHT in ledger-walk — die Union läuft dort
// ausschließlich über das injizierbare opts.entityLinks (Map Adresse ->
// Join-Keys). Diese Datei baut die Map und persistiert die Snapshots.
//
// DATENMODELL (data/entity-links.json im GitHub-Datenrepo):
//   { updatedAt: number|null,
//     addresses: { [addr]: {
//        regularKey, domain, domainVerified, emailHash, sequence, flags,
//        signers: [Signer-Adresse asc], signersFingerprint, sponsor,
//        previousTxnId, previousTxnLgrSeq, snapshotLedger, snapshotAt } } }
//
// JOIN-KEYS (Kritik 7): nur STARKE Keys vereinigen — 'rk:<regularKey>',
// 'sg:<sha256-Fingerprint der Signer-Liste asc>', 'eh:<emailHash>' und
// 'sp:<sponsor>' (FUNDING-MUSTER: das AccountRoot-Feld Sponsor markiert die
// Adresse, die die Kontoerstellung finanziert hat — teilen zwei Konten
// denselben Sponsor, teilen sie dieselbe Funding-Quelle; Faucets/Exchange-
// Subkonto-Massenanlage sind genau der False-Positive-Fall und werden vom
// Hub-Schutz > 20 ausgeschlossen, dieselbe Guard-Stufe wie alle anderen Keys).
// Die Domain ist das falsch-vereinigungsgefährdete Signal (Registrierung ist
// frei editierbar): sie kommt NUR als 'dv:<domain>', wenn ein Zwei-Wege-
// Match gegen https://<domain>/.well-known/xrp-ledger.toml ([[ACCOUNTS]])
// persistiert wurde (domainVerified-Flag). Ohne Flag ist die Domain reines
// Anzeige-Metadatum und nie Join-Key.
// HUB-SCHUTZ (Analogie HUB_UNION_DEGREE 20, lib/cluster.mjs:332): ein
// Join-Key, den mehr als 20 Adressen tragen (Börsen-/Faucet-Hubs), wird aus
// der Union ausgeschlossen.
// KEIN SHA-512Half-entityKey — Adressen sind bereits kanonische Keys.
//
// KÖDERSCHUTZ (B2): Köder-Adressen fallen VOR Persistenz still raus
// (Muster lib/block-window.mjs:135) — baitLabels nur als Übergabe.
//
// EXPORT-VERTRAG:
//   ENTITY_FILE_PATH / SNAPSHOT_TTL_MS (24 h) / ENTITY_JOIN_KEY_HUB (20)
//   emptyEntityDoc / normalizeEntityDoc / serializeEntityDoc / parseEntityText
//   readEntityGitHub / writeEntityGitHub            (Transport history.mjs)
//   snapshotFromAccountInfo(result, ledgerIndex, now?) -> snapshot|null
//   entityJoinKeys(addr, table) -> [Join-Keys] (nur starke rk:/sg:/eh:/sp:;
//     dv: nur verifiziert; sp: = Funding-Muster gemeinsame Sponsor-Adresse)
//   buildEntityLinks(table) -> Map addr -> [Join-Keys] (Hub-Keys > 20 raus)
//   clusterByEntity(table) -> [[addr asc] asc] (Union-Find über Join-Keys,
//     Hub-Keys ausgeschlossen; Domain ohne Flag nie)
//   fetchEntitySnapshots(rpc, addresses, {cap, existing, baitLabels, now})
//     -> {snapshots: Map addr->snapshot, requests: number}
//     Adressen mit persistiertem Snapshot jünger als SNAPSHOT_TTL_MS werden
//     übersprungen (Kritik 9: wiederkehrende Adressen verbrauchen keine
//     Requests); cap begrenzt die Requests pro Tick.

import { createHash } from "node:crypto";
import { readGitHubContents, writeGitHubContents } from "./history.mjs";

export const ENTITY_FILE_PATH = "data/entity-links.json"; // Pfad im Daten-Repo
export const SNAPSHOT_TTL_MS = 24 * 60 * 60 * 1000; // 24 h Snapshot-Dedup
export const ENTITY_JOIN_KEY_HUB = 20; // Analogie HUB_UNION_DEGREE (cluster.mjs:332)

const XRPL_ADDR_RE = /^r[1-9A-HJ-NP-Za-km-z]{24,34}$/;
const MAX_STRING_LEN = 200;

// ---------- Normalisierung / Codec ----------
export function emptyEntityDoc() {
  return { updatedAt: null, addresses: {} };
}

function cleanStr(v) {
  return typeof v === "string" && v ? v.slice(0, MAX_STRING_LEN) : null;
}

// Zahl oder null — null/undefined/'' bleiben null (Number(null) === 0 würde
// sonst einen persistierten null-Wert beim erneuten Normalisieren still zu 0
// machen, Roundtrip-Idempotenz verloren — von der Nachprüfung aufgedeckt).
function numOrNull(v) {
  if (v === null || v === undefined || v === "") return null;
  const n = Number(v);
  return Number.isFinite(n) ? n : null;
}

function normalizeSnapshot(s) {
  if (!s || typeof s !== "object" || Array.isArray(s)) return null;
  const signers = (Array.isArray(s.signers) ? s.signers : [])
    .map((a) => cleanStr(a))
    .filter((a) => a && XRPL_ADDR_RE.test(a))
    .sort((x, y) => (x < y ? -1 : x > y ? 1 : 0));
  return {
    regularKey: cleanStr(s.regularKey) && XRPL_ADDR_RE.test(s.regularKey) ? s.regularKey.slice(0, MAX_STRING_LEN) : null,
    domain: cleanStr(s.domain),
    domainVerified: s.domainVerified === true,
    emailHash: cleanStr(s.emailHash),
    sequence: numOrNull(s.sequence),
    flags: numOrNull(s.flags),
    signers,
    signersFingerprint: cleanStr(s.signersFingerprint),
    sponsor: cleanStr(s.sponsor) && XRPL_ADDR_RE.test(s.sponsor) ? s.sponsor.slice(0, MAX_STRING_LEN) : null,
    previousTxnId: cleanStr(s.previousTxnId),
    previousTxnLgrSeq: numOrNull(s.previousTxnLgrSeq),
    snapshotLedger: numOrNull(s.snapshotLedger),
    snapshotAt: numOrNull(s.snapshotAt),
  };
}

export function normalizeEntityDoc(doc) {
  let updatedAt = null;
  if (doc && doc.updatedAt !== null && doc.updatedAt !== undefined && doc.updatedAt !== "") {
    const n = Number(doc.updatedAt);
    if (Number.isFinite(n)) updatedAt = n;
  }
  const addresses = {};
  const src = doc?.addresses;
  if (src && typeof src === "object" && !Array.isArray(src)) {
    for (const [addr, snap] of Object.entries(src)) {
      if (typeof addr !== "string" || !XRPL_ADDR_RE.test(addr)) continue;
      const ns = normalizeSnapshot(snap);
      if (ns) addresses[addr] = ns;
    }
  }
  return { updatedAt, addresses };
}

export function serializeEntityDoc(doc) {
  return JSON.stringify(normalizeEntityDoc(doc));
}

// JSON-Objekt (Dokument) — alles andere ist Korruption und WIRFT (Muster
// parseFlowStateText lib/flow-state.mjs:139-150 — niemals still leer
// behandeln und den korrupten Stand überschreiben).
export function parseEntityText(text) {
  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch {
    throw new Error("Entity-Bestand nicht parsebar (korrumpiert) — kein Überschreiben.");
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error("Entity-Bestand hat unerwartetes Format — kein Überschreiben.");
  }
  return normalizeEntityDoc(parsed);
}

const entityCodec = { serialize: serializeEntityDoc, parse: parseEntityText };

export async function readEntityGitHub() {
  const { doc, sha } = await readGitHubContents(ENTITY_FILE_PATH, entityCodec);
  return { doc: doc ?? emptyEntityDoc(), sha };
}

export function writeEntityGitHub(apply) {
  return writeGitHubContents((doc) => apply(doc ?? emptyEntityDoc()), ENTITY_FILE_PATH, entityCodec);
}

// ---------- Snapshot aus account_info ----------
// result: account_info-Ergebnis ({account_data}) oder direkt account_data.
// Domain: Ledger-Feld ist Hex — decodiert zu ASCII (TextDecoder).
// Signer-Fingerprint: sha256 über die asc sortierten Signer-Adressen —
// kompakter, kanonischer Key-Inhalt (KEIN SHA-512Half-entityKey; Adressen
// selbst bleiben die kanonischen Keys).
export function snapshotFromAccountInfo(result, ledgerIndex, now) {
  const data = result?.account_data ?? result;
  if (!data || typeof data !== "object" || Array.isArray(data)) return null;
  const signers = (Array.isArray(data.Signers) ? data.Signers : [])
    .map((s) => (typeof s?.Account === "string" ? s.Account : null))
    .filter((a) => a && XRPL_ADDR_RE.test(a))
    .sort((x, y) => (x < y ? -1 : x > y ? 1 : 0));
  const signersFingerprint = signers.length
    ? createHash("sha256").update(signers.join(",")).digest("hex").slice(0, 16)
    : null;
  let domain = null;
  if (typeof data.Domain === "string" && /^[0-9A-Fa-f]+$/.test(data.Domain) && data.Domain.length % 2 === 0) {
    try {
      const bytes = new Uint8Array(data.Domain.length / 2);
      for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(data.Domain.substr(i * 2, 2), 16);
      domain = new TextDecoder("utf-8", { fatal: false }).decode(bytes).replace(/[^\x21-\x7E]/g, "").slice(0, MAX_STRING_LEN) || null;
    } catch {
      domain = null;
    }
  }
  const snapLedger = Number(ledgerIndex);
  const at = Number(now);
  const lgrSeq = Number(data.PreviousTxnLgrSeq);
  return {
    regularKey: typeof data.RegularKey === "string" && XRPL_ADDR_RE.test(data.RegularKey) ? data.RegularKey : null,
    domain,
    domainVerified: false, // Zwei-Wege-toml-Verifikation ist Sache des Consumers
    emailHash: typeof data.EmailHash === "string" ? data.EmailHash.slice(0, MAX_STRING_LEN) : null,
    sequence: Number.isFinite(Number(data.Sequence)) ? Number(data.Sequence) : null,
    flags: Number.isFinite(Number(data.Flags)) ? Number(data.Flags) : null,
    signers,
    signersFingerprint,
    sponsor: typeof data.Sponsor === "string" && XRPL_ADDR_RE.test(data.Sponsor) ? data.Sponsor : null,
    previousTxnId: typeof data.PreviousTxnId === "string" ? data.PreviousTxnId.slice(0, MAX_STRING_LEN) : null,
    previousTxnLgrSeq: Number.isFinite(lgrSeq) ? lgrSeq : null,
    snapshotLedger: Number.isFinite(snapLedger) ? snapLedger : null,
    snapshotAt: Number.isFinite(at) ? at : null,
  };
}

// ---------- Join-Keys (Kritik 7) ----------
// Nur starke Keys: rk:/sg:/eh:/sp: (sp: = Funding-Muster, gemeinsame
// Sponsor-Adresse = gemeinsame Funding-Quelle, hub-guardiert wie alle Keys).
// Domain nur als dv: NACH persistierter Zwei-Wege-Verifikation
// (domainVerified). Ohne Flag nie Join-Key — die Domain ist im Ledger frei
// editierbar und ohne Gegenprüfung nicht belastbar.
export function entityJoinKeys(addr, table) {
  const snap = table?.addresses?.[addr];
  if (!snap) return [];
  const keys = [];
  if (snap.regularKey) keys.push(`rk:${snap.regularKey}`);
  if (snap.signersFingerprint) keys.push(`sg:${snap.signersFingerprint}`);
  if (snap.emailHash) keys.push(`eh:${snap.emailHash}`);
  if (snap.sponsor) keys.push(`sp:${snap.sponsor}`);
  if (snap.domainVerified && snap.domain) keys.push(`dv:${snap.domain}`);
  return keys;
}

// Map für opts.entityLinks (lib/ledger-walk.mjs): Hub-Ausschluss — ein Key,
// den mehr als ENTITY_JOIN_KEY_HUB Adressen tragen, vereinigt nie und fehlt
// in der ausgelieferten Map.
export function buildEntityLinks(table) {
  const links = new Map();
  const owners = new Map(); // key -> Anzahl Adressen
  const perAddr = new Map();
  const addresses = table?.addresses && typeof table.addresses === "object" ? table.addresses : {};
  for (const addr of Object.keys(addresses).sort((x, y) => (x < y ? -1 : x > y ? 1 : 0))) {
    const keys = entityJoinKeys(addr, { addresses });
    if (!keys.length) continue;
    for (const k of keys) owners.set(k, (owners.get(k) ?? 0) + 1);
    perAddr.set(addr, keys);
  }
  for (const [addr, keys] of perAddr) {
    const kept = keys.filter((k) => (owners.get(k) ?? 0) <= ENTITY_JOIN_KEY_HUB);
    if (kept.length) links.set(addr, kept);
  }
  return links;
}

// Union-Find über Join-Keys (Hub-Keys > 20 ausgeschlossen, Domain ohne Flag
// nie): Cluster von Adressen, die dieselbe kryptografische Entität teilen.
// Rückgabe: Cluster-Listen asc sortiert, Cluster asc nach erstem Mitglied —
// deterministisch.
export function clusterByEntity(table) {
  const links = buildEntityLinks(table);
  const parent = new Map();
  const find = (a) => {
    let p = parent.get(a) ?? a;
    if (p !== a) {
      p = find(p);
      parent.set(a, p);
    }
    return p;
  };
  const union = (a, b) => {
    const ra = find(a);
    const rb = find(b);
    if (ra !== rb) parent.set(ra, rb);
  };
  const keyFirst = new Map(); // key -> erste Adresse
  for (const [addr, keys] of links) {
    find(addr);
    for (const k of keys) {
      if (keyFirst.has(k)) union(keyFirst.get(k), addr);
      else keyFirst.set(k, addr);
    }
  }
  // Gruppierung über ALLE Knoten der Links-Tabelle, nicht über parent.keys():
  // der Union-Root wird in union() nie selbst in parent eingetragen (nur sein
  // Root wird unter einen anderen gehängt), über parent.keys() fiele er aus
  // jeder Gruppe — ein 2-Member-Cluster würde zu einer 1er-Gruppe degradiert
  // und vom length>=2-Filter kassiert (Audit-Befund der Nachprüfung).
  const groups = new Map();
  for (const addr of links.keys()) {
    const root = find(addr);
    if (!groups.has(root)) groups.set(root, []);
    groups.get(root).push(addr);
  }
  const clusters = [...groups.values()]
    .map((list) => [...new Set(list)].sort((x, y) => (x < y ? -1 : x > y ? 1 : 0)))
    .filter((list) => list.length >= 2)
    .sort((a, b) => {
      const n = Math.min(a.length, b.length);
      for (let i = 0; i < n; i++) {
        if (a[i] !== b[i]) return a[i] < b[i] ? -1 : 1;
      }
      return a.length - b.length;
    });
  return clusters;
}

// ---------- Snapshot-Pull (Kritik 9) ----------
// rpc: injizierbarer RPC (api/advance.js rpc oder Fixture). Adressen mit
// bereits persistiertem Snapshot jünger als SNAPSHOT_TTL_MS werden
// übersprungen — wiederkehrende Adressen verbrauchen keine Requests.
// cap begrenzt die account_info-Calls pro Tick (Default 20, ENTITY_TICK_CAP).
// Köder-Adressen fallen vor Persistenz still raus (Muster block-window.mjs:135).
export async function fetchEntitySnapshots(rpc, addresses, opts = {}) {
  const cap = Number.isFinite(opts.cap) ? Math.max(0, Math.floor(opts.cap)) : 20;
  const ttl = Number.isFinite(opts.ttlMs) ? opts.ttlMs : SNAPSHOT_TTL_MS;
  const now = Number.isFinite(Number(opts.now)) ? Number(opts.now) : Date.now();
  const existing = opts.existing?.addresses && typeof opts.existing.addresses === "object" ? opts.existing.addresses : {};
  const baitLabels = opts.baitLabels instanceof Map ? opts.baitLabels : new Map();
  const snapshots = new Map();
  let requests = 0;
  const seen = new Set();
  for (const raw of Array.isArray(addresses) ? addresses : []) {
    if (requests >= cap) break;
    const addr = typeof raw === "string" ? raw : null;
    if (!addr || !XRPL_ADDR_RE.test(addr)) continue;
    if (baitLabels.has(addr)) continue; // STILL — kein Oracle, nie persistiert
    if (seen.has(addr)) continue;
    seen.add(addr);
    const old = existing[addr];
    if (old && Number.isFinite(Number(old.snapshotAt)) && now - Number(old.snapshotAt) < ttl) continue; // frisch -> kein Request
    try {
      const result = await rpc("account_info", { account: addr, ledger_index: -1 });
      const snap = snapshotFromAccountInfo(result, result?.ledger_index ?? result?.validated_ledger_index ?? null, now);
      if (snap) snapshots.set(addr, snap);
      requests += 1; // der Request wurde feuern — auch bei leerem Ergebnis
    } catch {
      requests += 1; // fehlgeschlagener Call zählt ins Budget (ehrliche Bilanz)
    }
  }
  return { snapshots, requests };
}
