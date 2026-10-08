// lib/history.mjs — Persistenz-Engine „Maliziöse Historie“ (pure ESM).
//
// HARTE GRENZEN (identisch zu lib/cluster.mjs:3-8):
//   - pure ESM, KEINE npm-Imports. Erlaubt: global fetch, node:crypto,
//     node:fs/promises, node:path. Läuft NIE im Browser und wird absichtlich
//     NICHT in die /lib-Whitelist (api/lib-detector.js, server/index.mjs)
//     aufgenommen — die Datei wird niemals an den Browser ausgeliefert.
//   - KEINE Secrets, KEINE Köder-Adressen in dieser Datei. Köder kommen nur
//     als Übergabe (baitLabels: Map address->label) herein — niemals als
//     import aus bait.json/bait-history.json.
//   - Token/Repo-Werte aus ENV werden NIE geloggt und tauchen in keiner
//     Fehlermeldung auf (alle Errors tragen neutrale Messages).
//
// EXPORT-VERTRAG:
//   normalizedName(members)                       -> string (sortiert, '\n'-Join)
//   historyKey(members)                           -> sha256-hex (klein)
//   HISTORY_MAX_ENTRIES                           -> 200
//   sanitizeHistoryCluster(cluster, baitLabels)   -> cluster | null
//   sanitizeHistoryList(list, baitLabels)         -> list (Köder-gefiltert)
//   validateAndSanitizeHistoryPayload(body, baitLabels, existingKeys)
//                                                 -> {accepted, ignored, newKeyCount}
//   mergeHistory(existing, incoming, now, baitLabels)
//                                                 -> {list, changed, dropped}
//   serializeHistoryList(list)                    -> JSON-String
//   loadLocalHistory(file) / saveLocalHistory(file, list)
//   readGitHubContents(filePath?, codec?)         -> {doc, sha}  (codec-agnostisch)
//   writeGitHubContents(apply, filePath?, codec?) -> newDoc      (codec-agnostisch)
//   deleteGitHubFile(filePath?)                   -> boolean     (Contents-DELETE,
//                                                  404 -> false; Retention-Helfer)
//   readHistoryGitHub(filePath?)                  -> {list, sha} (History-Codec, Default-Pfad)
//   writeHistoryGitHub(apply, filePath?)          -> newList     (History-Codec, Default-Pfad)
//   rateLimitHistory(clientKey, now)              -> boolean
//   clientKeyOf(xForwardedFor, remoteAddress)     -> string
//   searchHistory(list, q)                        -> list (substring, case-insensitiv)
//
// DATENMODELL (Eintrag der history-Liste, überall identisch):
//   { key, members: string[], label, totalDrops, txCount, distinctAccounts,
//     firstSeen, lastSeen (Epoch-ms), rules: string[], severity: 'malicious',
//     sightings, lastReportedAt }
//   VERTRAGSKLÄRUNG (bewusste kollektive Schicht): sanitizeHistoryCluster
//   erzwingt severity 'malicious' als EINZIGEN Persistenzwert (abgesichert
//   durch lib/history.test.mjs). Die Downgrades des Detektors (zitiertes
//   Opfer-Memo -> suspect, known-bad-Issuer-Position -> suspect,
//   firstSeenAt-only-Sweep -> suspect) halten solche Funde bewusst AUS der
//   malicious-History draußen — das ist der gewünschte False-Positive-Effekt,
//   keine stumme Semantik-Änderung an dieser test-geschützten Grenze.
//   key = sha256-hex über normalizedName(members) — stabil unabhängig von
//   cluster.id und Label-Rotation. Der Schlüssel wird IMMER serverseitig aus
//   den sanitisierten Members neu berechnet (Client-`key` wird nie vertraut).
//
// VIER-SCHICHT-KÖDERSCHUTZ über den gesamten Lebenszyklus:
//   (1) Client-Hash-Gate beim Melden (public/app.js isDeniedAddr),
//   (2) baitLabels-Filter beim POST-Annehmen (validateAndSanitizeHistoryPayload,
//       still — kein Oracle, Muster server/index.mjs:219-220),
//   (3) Merge-Selbstheilung bei Köder-Rotation (mergeHistory sanitiert
//       existing UND incoming — rotierte Köder fallen beim nächsten
//       Schreibzugriff aus dem Bestand),
//   (4) GET-Filter + Client-Render-Gate bei der Auslieferung
//       (sanitizeHistoryList in beiden GET-Routen, isDeniedAddr beim Rendern).
//
// PERSISTENZ-ORTE:
//   - Lokal (server/index.mjs): data/history.json, atomar (tmp+rename).
//     parseHistoryText wirft bei korruptem Bestand — NIEMALS [] behandeln und
//     damit ein Überschreiben des korrupten Standes auslösen.
//   - Vercel (api/history.js): GitHub-Contents-API auf data/history.json im
//     SEPARATEN Daten-Repo (Env GITHUB_HISTORY_REPO, Default
//     'Krypto-Whitehat/honeypot-xrpl-history' — VOR Betrieb anzulegen).
//
// DOKUMENTATION ZUR GIT-HISTORIE (bewusste Entscheidung):
//   data/history.json im separaten History-Repo landet BEWUSST in deren
//   Git-Historie (Auftrag: „für immer in GitHub persistieren“) und enthält
//   ausschließlich köder-gefilterte, öffentlich legitime Angreifer-Adressen.
//   Die frühere Annahme „.gitignore data/ hält die Datei aus der Git-Historie“
//   war FALSCH und ist gestrichen: .gitignore (Zeile 8 im Deploy-Repo) wirkt
//   nur auf lokale, ungetrackte Dateien. Das lokale data/history.json wird von
//   keinem Agenten git-committet; das entfernte data/history.json liegt im
//   History-Repo, nicht im Deploy-Repo (Kritiker-MUST-FIX 1: jeder Contents-PUT
//   auf den Default-Branch des Deploy-Repos wäre ein Commit auf main und
//   löste ein Full-Redeploy pro Meldung aus; „[skip ci]“ ist laut Recherche
//   github.com/vercel/vercel/discussions/5087 NICHT zuverlässig).
//
// BETRIEBSANFORDERUNGEN (zwingend vor Inbetriebnahme):
//   (a) History-Repo anlegen (Default Krypto-Whitehat/honeypot-xrpl-history).
//   (b) Fine-grained PAT (Contents: Read and write, NUR auf dieses Repo) als
//       Vercel-Env GITHUB_HISTORY_TOKEN setzen; optional GITHUB_HISTORY_REPO
//       und GITHUB_HISTORY_BRANCH. Der Token wird nie committet, nie geloggt,
//       nie in Client-Code oder Workflows eingebettet.
//   (c) ENV BAIT_ADDRESSES auf Vercel pflegen (Komma-separiert; Muster
//       api/ledger.js:40-45). Ohne diese Env fallen auf Vercel die
//       serverseitigen Filterschichten (POST-Filter, Merge-Filter, GET-Filter)
//       UND der Client-Hash-Deny gleichzeitig weg — auch /api/bait-hashes
//       (api/bait-hashes.js:17-21) hasht genau diese Env; nur der LOKALE
//       Server liefert die Union aus bait.json/bait-history.json
//       (server/index.mjs:152-159). Datenqualität der Historie bleibt dennoch
//       gewahrt: bereits persistierte Bestände sind beim Schreiben gefiltert.

import { createHash } from "node:crypto";
import fsp from "node:fs/promises";
import path from "node:path";
import { sanitizeText } from "./sanitize.mjs";

// ---------- Konstanten ----------
export const HISTORY_MAX_ENTRIES = 1000; // Sicherheitsdeckel; Betrugs-Cluster bleiben vor Nicht-Betrug (Sortierung)
// Aufbewahrung nach Status (lastSeen-Alter): Betrugs-Cluster 365 Tage, übrige 30 Tage.
export const HISTORY_RETENTION_FRAUD_MS = 365 * 86400000;
export const HISTORY_RETENTION_OTHER_MS = 30 * 86400000;
// Batching: höchstens ein Commit je Zeitfenster für data/history.json (instanzübergreifend
// über den letzten Commit-Zeitpunkt im Daten-Repo gemessen).
export const HISTORY_BATCH_MS = 5 * 60000;
export const HISTORY_FILE_PATH = "data/history.json"; // Pfad im History-Repo (GitHub)
// Betrugs-Evidenz-Regeln (Cap-Priorität, mergeHistory): Cluster mit einer
// dieser rules sind strukturelle Betrugs-Nachweise (Drainer-Sweep, Peeling-
// Kette, Known-Bad-Treffer, Wash-Zyklus) und werden vor der 200-Kappung VOR
// jüngeren Clustern ohne diese Regeln gehalten — die Kappung folgt nicht mehr
// rein lastSeen (Vergleich zu pruneFlowState, das nach Schwere vor Volumen
// kappt, lib/flow-state.mjs). known-bad-hit ist kuratierungsabhängig
// (lib/detector.mjs:327-336) und wird für die Kappungs-Priorität akzeptiert,
// da sanitizeHistoryCluster ohnehin nur severity 'malicious' zulässt (:187).
// Das history-Schema kennt nur rules[] — hasFraudEvidence aus
// lib/flow-state.mjs (prüft roles/mainDrainers/peelingChains/motifs.washCycles)
// ist hier nicht anwendbar; die Schichtung ist rules-basiert und deckt genau
// die hasFraudEvidence-Träger ab: 'wash-cycle' (Kritik-Runde 4, Befund 1) ist
// seit V4 hasFraudEvidence-Träger (lib/flow-state.mjs:256 — 30-Tage-
// maliziös-Retention + Archiv) und erhielt die Kappungs-Priorität vorher nur
// über den known-bad-hit-Fallback; die echte Katalog-ID
// (lib/detector.mjs:109) trägt sie jetzt direkt. Die drei Tx-Ebenen-Market-
// Regeln (amm-wash-swap/thin-pool-exploit/spoof-offer-cycle) bleiben bewusst
// draußen — sie sind keine hasFraudEvidence-Träger (lib/detector.mjs:114-117).
export const HISTORY_FRAUD_RULES = new Set(["drainer-sweep", "peeling-chain", "known-bad-hit", "wash-cycle"]);
const MAX_CLUSTERS_PER_PAYLOAD = 200;
const MAX_MEMBERS_PER_CLUSTER = 64;
const MAX_RULES_PER_CLUSTER = 16;
const MAX_NEW_KEYS_PER_POST = 20; // >20 NEUE Keys pro POST -> nur die ersten 20 (lastSeen desc)
const MAX_STRING_LEN = 200;
const SIGHTING_INCREMENT_MS = 6 * 60 * 60 * 1000; // sightings+=1 nur nach 6 h
const RATE_LIMIT_MAX = 6; // max POSTs je Client …
const RATE_LIMIT_WINDOW_MS = 60000; // … pro 60-s-Sliding-Window
const GH_API = "https://api.github.com";
const GH_COMMIT_MESSAGE = "history: merge (auto) [skip ci]"; // '[skip ci]' nur Markierung, NICHT Mechanismus
const XRPL_ADDR_RE = /^r[1-9A-HJ-NP-Za-km-z]{24,34}$/;

// ---------- Normalisierung + Schlüssel ----------
// Client (public/history.js normalizedNameClient) und Server verwenden
// EXAKT diese Operationen: je Adresse trimmen, lexikographisch sortieren,
// mit einzelnem Zeilenumbruch (U+000A) verbinden.
export function normalizedName(members) {
  return (Array.isArray(members) ? members : [])
    .map((m) => String(m ?? "").trim())
    .sort()
    .join("\n");
}

export function historyKey(members) {
  return createHash("sha256").update(normalizedName(members), "utf8").digest("hex");
}

// ---------- Feld-Sanitisierung ----------
function cleanNumber(value) {
  const n = Number(value);
  return Number.isFinite(n) ? Math.max(0, Math.trunc(n)) : 0;
}

function cleanLabel(value, baitLabels) {
  const s = sanitizeText(String(value ?? "").slice(0, MAX_STRING_LEN), baitLabels);
  return s.slice(0, MAX_STRING_LEN);
}

function sanitizeMembers(raw, baitLabels) {
  if (!Array.isArray(raw)) return [];
  const seen = new Set();
  const out = [];
  for (const m of raw) {
    const a = String(m ?? "").trim();
    if (!XRPL_ADDR_RE.test(a)) continue; // ungültige Member-Strings fallen raus
    if (baitLabels.has(a)) continue; // STILL gefiltert — kein Köder-Oracle
    if (seen.has(a)) continue;
    seen.add(a);
    out.push(a);
  }
  out.sort(); // deterministisch, deckungsgleich mit normalizedName
  return out.slice(0, MAX_MEMBERS_PER_CLUSTER);
}

function sanitizeRules(raw, baitLabels) {
  if (!Array.isArray(raw)) return [];
  const seen = new Set();
  for (const r of raw.slice(0, MAX_RULES_PER_CLUSTER)) {
    const s = sanitizeText(String(r ?? "").slice(0, MAX_STRING_LEN), baitLabels).trim();
    if (s) seen.add(s);
  }
  return [...seen].sort();
}

// Einzelcluster-Sanitisierung: Köder-Mitglieder raus, köder-only-Cluster null.
// Der Schlüssel wird IMMER aus den verbleibenden Members neu berechnet.
// severity wird serverseitig auf 'malicious' erzwungen (einzig erlaubter Wert
// der Persistenz — suspect/info erreichen sie nie).
export function sanitizeHistoryCluster(cluster, baitLabels) {
  if (!cluster || typeof cluster !== "object") return null;
  const members = sanitizeMembers(cluster.members, baitLabels);
  if (!members.length) return null; // köder-only/leer: still verworfen
  return {
    key: historyKey(members),
    members,
    label: cleanLabel(cluster.label, baitLabels),
    totalDrops: cleanNumber(cluster.totalDrops),
    txCount: cleanNumber(cluster.txCount),
    distinctAccounts: members.length,
    firstSeen: cleanNumber(cluster.firstSeen),
    lastSeen: cleanNumber(cluster.lastSeen),
    rules: sanitizeRules(cluster.rules, baitLabels),
    severity: "malicious",
    sightings: Math.max(1, cleanNumber(cluster.sightings) || 1),
    lastReportedAt: cleanNumber(cluster.lastReportedAt),
  };
}

// Lese-Pfad-Filter (auch nach Köder-ROTATION): Köder-Members herausfiltern,
// Cluster ohne verbleibende Members entfernen. Schlüssel-Kollisionen nach
// Member-Verlust werden per Feld-Merge (ohne Zähler) vereint.
export function sanitizeHistoryList(list, baitLabels) {
  if (!Array.isArray(list)) return [];
  const byKey = new Map();
  for (const raw of list) {
    const c = sanitizeHistoryCluster(raw, baitLabels);
    if (!c) continue;
    const prev = byKey.get(c.key);
    if (!prev) byKey.set(c.key, c);
    else byKey.set(c.key, mergeFields(prev, c, null));
  }
  return [...byKey.values()];
}

// ---------- Eingangsvalidierung (POST-Payload) ----------
// Return: { accepted: cluster[], ignored: number, newKeyCount: number }
//   accepted   — sanitisierte Cluster (Server-Schlüssel, severity erzwungen)
//   ignored    — alle verworfenen Cluster (Struktur, Köder, Caps, Duplikate)
//   newKeyCount— Anzahl NEUER Schlüssel im AKZEPTIERTEN Rest (nach Deckelung)
export function validateAndSanitizeHistoryPayload(body, baitLabels, existingKeys) {
  const exKeys = existingKeys instanceof Set ? existingKeys : new Set(existingKeys ?? []);
  const rawList = Array.isArray(body?.clusters) ? body.clusters : [];
  let ignored = 0;
  if (rawList.length > MAX_CLUSTERS_PER_PAYLOAD) {
    ignored += rawList.length - MAX_CLUSTERS_PER_PAYLOAD; // Cap: Cluster/Payload
  }
  const payloadKeys = new Set();
  const sanitized = [];
  for (const raw of rawList.slice(0, MAX_CLUSTERS_PER_PAYLOAD)) {
    const c = sanitizeHistoryCluster(raw, baitLabels);
    if (!c) {
      ignored += 1; // ungültige Struktur oder Köder-only — still ignoriert
      continue;
    }
    if (payloadKeys.has(c.key)) {
      ignored += 1; // Duplikat im selben Payload
      continue;
    }
    payloadKeys.add(c.key);
    sanitized.push(c);
  }
  const updates = sanitized.filter((c) => exKeys.has(c.key));
  const news = sanitized.filter((c) => !exKeys.has(c.key));
  if (news.length > MAX_NEW_KEYS_PER_POST) {
    // >20 neue Keys: nur die ersten 20 nach lastSeen desc (Tie-Break key asc),
    // deterministisch — der Rest zählt als ignored.
    news.sort(cmpLastSeenDescKeyAsc);
    const keep = news.splice(0, MAX_NEW_KEYS_PER_POST);
    ignored += news.length;
    news.length = 0;
    news.push(...keep);
  }
  return { accepted: [...updates, ...news], ignored, newKeyCount: news.length };
}

// ---------- Merge ----------
// Feld-Merge von `inc` in `target` (mutiert target). now !== null: Melde-Pfad
// (6-h-Regel für sightings, lastReportedAt=now). now === null: Lese-Pfad-
// Dedup (max-Semantik ohne Zähler). Rückgabe: hat sich ein Feld geändert?
function mergeFields(target, inc, now) {
  let changed = false;
  for (const field of ["totalDrops", "txCount", "distinctAccounts"]) {
    if (inc[field] !== target[field]) {
      target[field] = inc[field]; // Überschreiben (letzte Beobachtung gewinnt)
      changed = true;
    }
  }
  const fs = [target.firstSeen, inc.firstSeen].filter((v) => v > 0);
  const minFs = fs.length ? Math.min(...fs) : 0;
  if (minFs !== target.firstSeen) {
    target.firstSeen = minFs;
    changed = true;
  }
  const ls = [target.lastSeen, inc.lastSeen].filter((v) => v > 0);
  const maxLs = ls.length ? Math.max(...ls) : 0;
  if (maxLs !== target.lastSeen) {
    target.lastSeen = maxLs;
    changed = true;
  }
  const rules = [...new Set([...target.rules, ...inc.rules])].sort();
  if (rules.length !== target.rules.length || rules.some((r, i) => r !== target.rules[i])) {
    target.rules = rules; // Vereinigung (sortiert)
    changed = true;
  }
  if (inc.label && inc.label !== target.label) {
    target.label = inc.label;
    changed = true;
  }
  if (now !== null) {
    // sightings += 1 NUR wenn die letzte Meldung länger als 6 h zurückliegt;
    // sonst reiner Feld-Merge ohne Zähler. lastReportedAt immer auf now.
    if (now - target.lastReportedAt > SIGHTING_INCREMENT_MS) {
      target.sightings += 1;
      changed = true;
    }
    if (target.lastReportedAt !== now) {
      target.lastReportedAt = now;
      changed = true;
    }
  } else {
    if (inc.sightings > target.sightings) {
      target.sightings = inc.sightings;
      changed = true;
    }
    if (inc.lastReportedAt > target.lastReportedAt) {
      target.lastReportedAt = inc.lastReportedAt;
      changed = true;
    }
  }
  return changed;
}

function cmpLastSeenDescKeyAsc(a, b) {
  if (b.lastSeen !== a.lastSeen) return b.lastSeen - a.lastSeen;
  return a.key < b.key ? -1 : a.key > b.key ? 1 : 0;
}

// Cap-Sortierung (mergeHistory-Kappung): Betrugsevidenz-Cluster (mindestens
// eine HISTORY_FRAUD_RULES-Regel) zuerst, dann wie bisher lastSeen desc /
// key asc. Tie-Break innerhalb beider Gruppen bleibt deterministisch.
function hasFraudRule(c) {
  return (Array.isArray(c?.rules) ? c.rules : []).some((r) => HISTORY_FRAUD_RULES.has(r));
}

function cmpCapFraudFirstLastSeenDescKeyAsc(a, b) {
  const fa = hasFraudRule(a) ? 1 : 0;
  const fb = hasFraudRule(b) ? 1 : 0;
  if (fa !== fb) return fb - fa;
  return cmpLastSeenDescKeyAsc(a, b);
}

// Merge mit Selbstheilung: existing UND incoming werden sanitisiert — rotierte
// Köder fallen beim nächsten Schreibzugriff aus der Datei. Danach Cap
// HISTORY_MAX_ENTRIES (Betrugsevidenz-Cluster nach HISTORY_FRAUD_RULES
// zuerst, dann neueste nach lastSeen desc, Tie-Break key asc, deterministisch
// — kein Date.now in Vergleichspfaden), dropped zählt Sanitisierungs- UND
// Cap-Verluste.
export function isFraudHistoryCluster(c) {
  return Array.isArray(c?.rules) && c.rules.some((r) => HISTORY_FRAUD_RULES.has(r));
}

// Altersregel nach Status. Cluster ohne Zeitstempel bleiben (kein Verwerfen auf Verdacht).
export function pruneHistoryByAge(list, now) {
  const kept = [];
  let dropped = 0;
  for (const c of Array.isArray(list) ? list : []) {
    const ls = Number(c?.lastSeen) || Number(c?.lastReportedAt) || 0;
    if (ls <= 0) { kept.push(c); continue; }
    const limit = isFraudHistoryCluster(c) ? HISTORY_RETENTION_FRAUD_MS : HISTORY_RETENTION_OTHER_MS;
    if (now - ls > limit) { dropped++; continue; }
    kept.push(c);
  }
  return { list: kept, dropped };
}

// Zeitpunkt des letzten Commits auf data/history.json (ms). Fehler werfen: kein Schreiben auf Verdacht.
export async function historyLastWriteMs(filePath) {
  const { repo, branch, token, filePath: fp } = githubConfig(filePath);
  const url = `${GH_API}/repos/${repo}/commits?path=${encodeURIComponent(fp)}&sha=${encodeURIComponent(branch)}&per_page=1`;
  const res = await fetch(url, { headers: githubHeaders(token) });
  if (!res.ok) throw new Error("Commit-Abfrage fehlgeschlagen (HTTP " + res.status + ").");
  const data = await res.json();
  const date = Array.isArray(data) && data[0]?.commit?.committer?.date;
  return date ? Date.parse(date) : 0;
}

export function mergeHistory(existing, incoming, now, baitLabels) {
  const rawExisting = Array.isArray(existing) ? existing : [];
  const exSan = sanitizeHistoryList(existing, baitLabels);
  const inSan = sanitizeHistoryList(incoming, baitLabels);
  let dropped =
    rawExisting.length - exSan.length +
    (Array.isArray(incoming) ? incoming.length : 0) - inSan.length;
  // Selbstheilung erkennbar machen: hat die Sanitisierung den Bestand verändert
  // (rotierte Köder-Member gefallen, kanonische Form hergestellt), wird beim
  // nächsten Schreibzugriff auch OHNE inhaltliche Neuerung zurückgeschrieben.
  // Feld-Reihenfolge ist durch sanitizeHistoryCluster deterministisch, daher
  // konvergiert der Vergleich nach einem Write.
  let changed =
    dropped > 0 ||
    (rawExisting.length > 0 && JSON.stringify(rawExisting) !== JSON.stringify(exSan));
  const byKey = new Map();
  for (const c of exSan) byKey.set(c.key, c);
  for (const c of inSan) {
    const prev = byKey.get(c.key);
    if (prev) {
      if (mergeFields(prev, c, now)) changed = true; // Feld-Merge inkl. 6-h-Regel
    } else {
      byKey.set(c.key, { ...c, sightings: 1, lastReportedAt: now });
      changed = true;
    }
  }
  let list = [...byKey.values()];
  list.sort(cmpCapFraudFirstLastSeenDescKeyAsc);
  if (list.length > HISTORY_MAX_ENTRIES) {
    dropped += list.length - HISTORY_MAX_ENTRIES;
    list = list.slice(0, HISTORY_MAX_ENTRIES);
    changed = true;
  }
  return { list, changed, dropped };
}

// ---------- Serialisierung / lokaler Speicher ----------
export function serializeHistoryList(list) {
  return JSON.stringify(Array.isArray(list) ? list : []);
}

// JSON-Array (oder {list:[…]}) — alles andere ist Korruption und WIRFT
// (NIEMALS []: ein korrupter Bestand darf nicht still überschrieben werden).
function parseHistoryText(text) {
  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch {
    throw new Error("History-Bestand nicht parsebar (korrumpiert) — kein Überschreiben mit Leerliste.");
  }
  const list = Array.isArray(parsed) ? parsed : parsed && Array.isArray(parsed.list) ? parsed.list : null;
  if (!list) throw new Error("History-Bestand hat unerwartetes Format — kein Überschreiben.");
  return list;
}

export async function loadLocalHistory(file) {
  let text;
  try {
    text = await fsp.readFile(file, "utf8");
  } catch (err) {
    if (err && err.code === "ENOENT") return []; // Anlege-Fall
    throw err;
  }
  return parseHistoryText(text);
}

// Atomar schreiben: tmp-Datei + rename. Verzeichnis bei Bedarf anlegen.
export async function saveLocalHistory(file, list) {
  await fsp.mkdir(path.dirname(file), { recursive: true });
  const tmp = `${file}.tmp`;
  await fsp.writeFile(tmp, serializeHistoryList(list), "utf8");
  await fsp.rename(tmp, file);
}

// ---------- GitHub-Contents-Adapter ----------
// Repo/Branch NUR aus Env (Default: separates History-Repo, NICHT das
// Deploy-Repo — siehe DOKUMENTATION oben). Token NUR aus Env.
//
// PARAMETERISIERUNG (Runde 1): Der Transport ist CODEC-AGNOSTISCH. filePath
// (trailing optional, Default HISTORY_FILE_PATH) UND der Codec (parse/
// serialize, Default historyCodec) werden injiziert. History und Flow-State
// (lib/flow-state.mjs) teilen sich denselben Transport — Read/Write/409-
// Retry/In-Flight-Lock — und unterscheiden sich NUR im Codec und im filePath.
// Aufrufe ohne Argumente behalten data/history.json + History-Codec (alle
// bestehenden Caller übergeben nichts).
function githubConfig(filePath) {
  return {
    repo: process.env.GITHUB_HISTORY_REPO || "Krypto-Whitehat/honeypot-xrpl-history",
    branch: process.env.GITHUB_HISTORY_BRANCH || "main",
    token: process.env.GITHUB_HISTORY_TOKEN || "",
    filePath: typeof filePath === "string" && filePath ? filePath : HISTORY_FILE_PATH,
  };
}

// History-Codec: die History-spezifische Serialisierung/Parse. Der Transport
// (readGitHubContents/putGitHubContents) ist davon unabhängig; History injiziert
// diesen Codec, Flow-State injiziert seinen eigenen (lib/flow-state.mjs).
const historyCodec = { serialize: serializeHistoryList, parse: parseHistoryText };

function githubHeaders(token) {
  return {
    Authorization: `Bearer ${token}`, // Token niemals loggen/in Messages übernehmen
    Accept: "application/vnd.github+json", // JSON-Read liefert das für den PUT zwingende sha (raw tut es nicht)
    "X-GitHub-Api-Version": "2022-11-28",
  };
}

// Codec-agnostischer GET-Transport: liefert das per Codec geparste Dokument
// ({doc, sha}). doc ist null im Anlege-Fall (HTTP 404) und bei leerer Datei —
// der Consumer entscheidet, was null bedeutet (History: [], Flow-State: frisch).
// Parse-Fehler wirft der Codec (kein stiller Leerstand). Der Transport selbst
// ist payload-unabhängig; History und Flow-State teilen ihn.
export async function readGitHubContents(filePath, codec) {
  const { repo, branch, token, filePath: fp } = githubConfig(filePath);
  if (!token) throw new Error("GitHub-Persistenz nicht konfiguriert (Token fehlt).");
  const url = `${GH_API}/repos/${repo}/contents/${fp}?ref=${encodeURIComponent(branch)}`;
  let res;
  try {
    res = await fetch(url, { headers: githubHeaders(token) });
  } catch {
    throw new Error("GitHub-Contents-Read: Netzwerkfehler.");
  }
  if (res.status === 404) return { doc: null, sha: null };
  if (!res.ok) throw new Error(`GitHub-Contents-Read fehlgeschlagen (HTTP ${res.status}).`);
  let data;
  try {
    data = await res.json();
  } catch {
    throw new Error("GitHub-Contents-Read: Antwort nicht parsebar.");
  }
  const sha = typeof data?.sha === "string" && data.sha ? data.sha : null;
  const b64 = typeof data?.content === "string" ? data.content.replace(/\s+/g, "") : "";
  if (b64) return { doc: codec.parse(Buffer.from(b64, "base64").toString("utf8")), sha };
  // Leeres content-Feld: die Contents-API liefert für Dateien > 1 MiB KEINEN
  // content (live belegt: contents?ref=... {size:1050727, content_len:0,
  // encoding:"none"} — der frühere Code deutete das als "leere Datei" und
  // ließ den Caller mit doc null den Bestand im nächsten Tick überschreiben
  // (Wisch-Zyklus). Daher: size===0 ist eine echte leere Datei; size>0
  // verlangt den Blob-Fallback (git/blobs/<sha> liefert den Vollinhalt);
  // ohne verwertbaren Anker FAIL-CLOSED (502) — kein Durchfallen in den
  // Leerstands-Zweig, kein stiller Datenverlust.
  const size = Number(data?.size);
  if (size === 0) return { doc: null, sha }; // echte leere Datei im Repo -> kein Dokument
  if (!(size > 0) || !sha) {
    // size undefined/NaN (z.B. Array-Antwort auf ein Verzeichnis) oder
    // size>0 ohne sha: Inhalt nicht verifizierbar -> Fehler, kein doc null.
    const err = new Error("GitHub-Contents-Read: Bestand ohne Inhalt und ohne Blob-Anker.");
    err.status = 502;
    throw err;
  }
  // Blob-Fallback: git/blobs/<sha> (derselbe Accept — der JSON-Blob liefert
  // base64; GitHub bricht das base64 mit Newlines -> identischer Strip wie
  // das Contents-Base64 oben).
  let blobRes;
  try {
    blobRes = await fetch(`${GH_API}/repos/${repo}/git/blobs/${encodeURIComponent(sha)}`, {
      headers: githubHeaders(token),
    });
  } catch {
    const err = new Error("GitHub-Blob-Read: Netzwerkfehler.");
    err.status = 502;
    throw err;
  }
  if (!blobRes.ok) {
    const err = new Error(`GitHub-Blob-Read fehlgeschlagen (HTTP ${blobRes.status}).`);
    err.status = 502;
    throw err;
  }
  let blob;
  try {
    blob = await blobRes.json();
  } catch {
    const err = new Error("GitHub-Blob-Read: Antwort nicht parsebar.");
    err.status = 502;
    throw err;
  }
  const blobB64 = typeof blob?.content === "string" ? blob.content.replace(/\s+/g, "") : "";
  if (!blobB64) {
    const err = new Error("GitHub-Blob-Read: Blob ohne Inhalt.");
    err.status = 502;
    throw err;
  }
  return { doc: codec.parse(Buffer.from(blobB64, "base64").toString("utf8")), sha };
}

// History-Einstiegspunkt (rückwärtskompatibel): History-Codec + Default-Pfad.
// doc null (Anlege/leer) wird hier zu leerer Liste [] — der History-Vertrag
// kennt nur Bestände (Arrays), nie null.
export async function readHistoryGitHub(filePath) {
  const { doc, sha } = await readGitHubContents(filePath, historyCodec);
  return { list: doc ?? [], sha };
}

// Codec-agnostischer PUT-Transport: serialisiert das Dokument per Codec und
// schreibt es. Der Commit-Message-Marker ist transportweit geteilt (siehe
// GH_COMMIT_MESSAGE — Markierung, NICHT Mechanismus); Flow-State-Commits
// tragen denselben Marker (dokumentierte Grenze, lib/flow-state.mjs).
async function putGitHubContents(doc, sha, filePath, codec) {
  const { repo, branch, token, filePath: fp } = githubConfig(filePath);
  const url = `${GH_API}/repos/${repo}/contents/${fp}`;
  const body = {
    message: GH_COMMIT_MESSAGE,
    branch,
    content: Buffer.from(codec.serialize(doc), "utf8").toString("base64"),
  };
  if (sha) body.sha = sha; // ohne sha beim ANLEGEN der Datei
  let res;
  try {
    res = await fetch(url, { method: "PUT", headers: githubHeaders(token), body: JSON.stringify(body) });
  } catch {
    const err = new Error("GitHub-Contents-Write: Netzwerkfehler.");
    err.status = 0;
    throw err;
  }
  if (!res.ok) {
    const err = new Error(`GitHub-Contents-Write fehlgeschlagen (HTTP ${res.status}).`);
    err.status = res.status;
    throw err;
  }
  return true;
}

// Serialisierte Writes pro Instanz (In-Flight-Promise-Lock).
let writeChain = Promise.resolve();

// FRISCHER Read vor JEDEM Write (ein GET-Cache liefert nie den aktuellen sha);
// apply(freshDoc) läuft ausschließlich auf dem frischen Stand — auch im
// 409-Retry. 409 -> GENAU EIN Retry (frischer Read + apply auf dem NEUEN
// Stand + PUT), danach ehrlicher Fehler. 403/429 -> neutrale Fehleroberfläche.
// Codec-agnostisch: apply erhält das per Codec geparste frische Dokument
// (null im Anlege-Fall) und liefert das neue Dokument zurück.
export function writeGitHubContents(apply, filePath, codec) {
  const run = writeChain.then(() => performWriteContents(apply, filePath, codec));
  writeChain = run.catch(() => {}); // Kette überlebt Fehler
  return run;
}

async function performWriteContents(apply, filePath, codec) {
  const { token } = githubConfig(filePath);
  if (!token) throw new Error("GitHub-Persistenz nicht konfiguriert (Token fehlt).");
  if (typeof apply !== "function") throw new Error("writeGitHubContents: apply muss eine Funktion sein.");
  let fresh = await readGitHubContents(filePath, codec);
  let newDoc = await apply(fresh.doc);
  try {
    await putGitHubContents(newDoc, fresh.sha, filePath, codec);
    return newDoc;
  } catch (err) {
    if (err?.status !== 409) throw err;
    fresh = await readGitHubContents(filePath, codec); // frischer Stand nach Konflikt
    newDoc = await apply(fresh.doc); // apply auf dem NEUEN frischen Stand
    await putGitHubContents(newDoc, fresh.sha, filePath, codec); // scheitert -> ehrlicher Fehler
    return newDoc;
  }
}

// History-Einstiegspunkt (rückwärtskompatibel): History-Codec + Default-Pfad.
// Der History-Vertrag verlangt, dass apply eine Liste erhält — doc null
// (Anlege/leer) wird daher zu [] normalisiert, bevor apply läuft.
export function writeHistoryGitHub(apply, filePath) {
  return writeGitHubContents((doc) => apply(doc ?? []), filePath, historyCodec);
}

// ---------- Contents-DELETE (Retention, codec-agnostisch) ----------
// Löscht eine Datei im Datenrepo über die Contents-API (DELETE mit sha —
// derselbe 409-Retry-Muster wie der PUT-Pfad: frischer Read liefert den
// zwingenden sha; 409 -> GENAU EIN Retry mit frischem Read). 404 -> false
// (nichts zu löschen, kein Fehler). Fehler tragen neutrale Messages ohne
// Token-Werte; err.status für die Fehleroberfläche der Caller.
async function deleteContentsOnce(filePath, sha) {
  const { repo, branch, token } = githubConfig(filePath);
  const url = `${GH_API}/repos/${repo}/contents/${filePath}?ref=${encodeURIComponent(branch)}`;
  let res;
  try {
    res = await fetch(url, {
      method: "DELETE",
      headers: { ...githubHeaders(token), ...(sha ? {} : {}) },
      ...(sha ? { body: JSON.stringify({ message: GH_COMMIT_MESSAGE, branch, sha }) } : {}),
    });
  } catch {
    const err = new Error("GitHub-Contents-Delete: Netzwerkfehler.");
    err.status = 0;
    throw err;
  }
  if (res.status === 404) return false;
  if (!res.ok) {
    const err = new Error(`GitHub-Contents-Delete fehlgeschlagen (HTTP ${res.status}).`);
    err.status = res.status;
    throw err;
  }
  return true;
}

// In-Flight-Lock geteilt mit den Writes (Löschen und Schreiben derselben
// Datei serialisieren sich — kein Read-PUT-DELETE-Wettlauf).
export function deleteGitHubFile(filePath) {
  const run = writeChain.then(() => performDeleteContents(filePath));
  writeChain = run.catch(() => {}); // Kette überlebt Fehler
  return run;
}

// Nur-sha-Read für den Delete-Pfad (der Codec wird nicht gebraucht — der
// Inhalt wird verworfen; Parse-Fehler eines korrupten Bestands dürfen das
// Löschen nicht blockieren).
async function readGitHubSha(filePath) {
  const { repo, branch, token } = githubConfig(filePath);
  if (!token) throw new Error("GitHub-Persistenz nicht konfiguriert (Token fehlt).");
  const url = `${GH_API}/repos/${repo}/contents/${filePath}?ref=${encodeURIComponent(branch)}`;
  let res;
  try {
    res = await fetch(url, { headers: githubHeaders(token) });
  } catch {
    throw new Error("GitHub-Contents-Read: Netzwerkfehler.");
  }
  if (res.status === 404) return null;
  if (!res.ok) throw new Error(`GitHub-Contents-Read fehlgeschlagen (HTTP ${res.status}).`);
  let data;
  try {
    data = await res.json();
  } catch {
    throw new Error("GitHub-Contents-Read: Antwort nicht parsebar.");
  }
  return typeof data?.sha === "string" && data.sha ? data.sha : null;
}

async function performDeleteContents(filePath) {
  const sha = await readGitHubSha(filePath);
  if (sha == null) return false; // Datei nicht vorhanden (404/leer) -> nichts zu löschen
  try {
    return await deleteContentsOnce(filePath, sha);
  } catch (err) {
    if (err?.status !== 409) throw err;
    const fresh = await readGitHubSha(filePath);
    if (fresh == null) return false; // zwischenzeitlich verschwunden
    return await deleteContentsOnce(filePath, fresh); // scheitert -> ehrlicher Fehler
  }
}

// ---------- Rate-Limit (Sliding Window, in-memory) ----------
const rateWindows = new Map(); // clientKey -> Zeitstempel[]

export function rateLimitHistory(clientKey, now) {
  const key = String(clientKey ?? "unknown");
  const arr = (rateWindows.get(key) ?? []).filter((t) => now - t < RATE_LIMIT_WINDOW_MS);
  if (arr.length >= RATE_LIMIT_MAX) {
    rateWindows.set(key, arr);
    pruneRateWindows(now);
    return false;
  }
  arr.push(now);
  rateWindows.set(key, arr);
  pruneRateWindows(now);
  return true;
}

function pruneRateWindows(now) {
  if (rateWindows.size <= 512) return;
  for (const [k, arr] of rateWindows) {
    const keep = arr.filter((t) => now - t < RATE_LIMIT_WINDOW_MS);
    if (keep.length) rateWindows.set(k, keep);
    else rateWindows.delete(k);
  }
}

// Client-Schlüssel: LETZTER x-forwarded-for-Eintrag || remoteAddress || 'unknown'.
// XFF-Konvention: Jeder Proxy HÄNGT die IP des unmittelbaren Absenders ans
// Ende an — der letzte Eintrag stammt vom nächstgelegenen (vertrauenswürdigen)
// Proxy und ist vom Client nicht fälschbar. Der ERSTE Eintrag wäre dagegen
// client-kontrolliert: Ein eigener XFF-Header rotierte den Rate-Limit-Schlüssel
// beliebig und umging die 6-POSTs/60-s-Grenze (Befund 2026-09-29).
export function clientKeyOf(xForwardedFor, remoteAddress) {
  const last = String(xForwardedFor ?? "").split(",").pop().trim();
  if (last) return last;
  return String(remoteAddress ?? "").trim() || "unknown";
}

// ---------- Suche (GET ?q= über members/label/rules) ----------
export function searchHistory(list, q) {
  const source = Array.isArray(list) ? list : [];
  const needle = String(q ?? "").trim().toLowerCase();
  if (!needle) return source;
  return source.filter(
    (c) =>
      (Array.isArray(c?.members) && c.members.some((m) => String(m ?? "").toLowerCase().includes(needle))) ||
      String(c?.label ?? "").toLowerCase().includes(needle) ||
      (Array.isArray(c?.rules) && c.rules.some((r) => String(r ?? "").toLowerCase().includes(needle)))
  );
}
