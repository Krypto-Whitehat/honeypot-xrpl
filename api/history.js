// Vercel Function: GET/POST /api/history — „Maliziöse Historie“.
//
// Persistierte, kollektive Historie AUSSCHLIESSLICH als maliziös eingestufter
// Cluster (severity wird serverseitig erzwungen, lib/history.mjs). Speicherort
// auf Vercel: data/history.json im SEPARATEN History-Repo über die GitHub-
// Contents-API (Repo/Branch aus Env, Default Krypto-Whitehat/honeypot-xrpl-
// history) — bewusst NICHT ins Deploy-Repo (jeder Contents-PUT auf dessen
// Default-Branch wäre ein Commit auf main und löste ein Full-Redeploy pro
// Meldung aus; „[skip ci]“ ist keine zuverlässige Mechanik,
// github.com/vercel/vercel/discussions/5087).
//
// SICHERHEIT:
//   - Köder-Schutz: baitLabels aus ENV BAIT_ADDRESSES (Muster api/ledger.js:
//     40-45) wirken im POST-Annahmefilter, im Merge (Selbstheilung bei
//     Rotation) und im GET-Filter. bait.json wird auf Vercel gar nicht
//     gelesen (.vercelignore) — ohne diese Env sind alle serverseitigen
//     Schichten UND der Client-Hash-Deny (/api/bait-hashes hasht dieselbe
//     Env) gleichzeitig weg. Deshalb FAIL-CLOSED (Befund 2026-09-29): Ohne
//     gepflegte BAIT_ADDRESSES nimmt der Handler keine Persistenz vor
//     (POST -> 503, GET -> „nicht konfiguriert") — ein ungefilterter Commit
//     selbst beobachteter Köder-Cluster in die öffentliche GitHub-Historie
//     wird so strukturell verhindert statt nur dokumentiert.
//   - GITHUB_HISTORY_TOKEN NUR aus process.env — nie committet, nie geloggt,
//     nie in Fehlermeldungen (der Adapter wirft neutrale Messages).
//   - Rate-Limit: max 6 POSTs/60 s je Client (Sliding Window, in-memory).
//
// GET  -> {clusters:[Kartenfelder + sightings + lastReportedAt], updatedAt}
//         Sortierung lastSeen desc (der Bestand ist bereits deterministisch
//         sortiert), optional ?q= (Adresse/Label/Regel, substring,
//         case-insensitive). 60-s-In-Memory-Cache speichert den BEREITS
//         köder-gefilterten Stand. Ohne GITHUB_HISTORY_TOKEN: HTTP 200 mit
//         reason 'Persistenz nicht konfiguriert' (kein Erfolgs-Vortäuschen
//         gegenüber der Konfiguration, aber auch kein Fehlerzustand).
//         Read-Fehler -> 502 'Historie nicht erreichbar.' (KEIN leerer 200er).
// POST -> Adapter-Vertrag: (i) frischer Read (NICHT der GET-Cache) für
//         existingKeys, (ii) validateAndSanitizeHistoryPayload,
//         (iii) writeHistoryGitHub(apply = (fresh) => mergeHistory(fresh,
//         accepted, now, baitLabels).list) — der Merge läuft ausschließlich
//         im apply auf dem frischen Stand (auch im 409-Retry). Erfolg:
//         GET-Cache invalidieren + 202 {accepted, merged, ignored, dropped}
//         (nur Zahlen; merged = Anzahl Cluster im Bestand nach dem Merge).
//         Write-Fehler -> 502/503 'Historie-Persistenz derzeit nicht
//         verfügbar.' — KEIN 202 ohne Persistenz.
import {
  readHistoryGitHub,
  writeHistoryGitHub,
  validateAndSanitizeHistoryPayload,
  mergeHistory,
  sanitizeHistoryList,
  searchHistory,
  rateLimitHistory,
  clientKeyOf,
} from "../lib/history.mjs";

export const maxDuration = 30;

const GET_CACHE_MS = 60000;
const MAX_BODY_BYTES = 262144; // explizites Body-Limit (256 kB), siehe handlePost
let getCache = null; // { time, clusters, updatedAt } — bereits köder-gefiltert

// Bait-Labels aus ENV — identisches Muster wie api/ledger.js:40-45.
const baitLabels = new Map();
(process.env.BAIT_ADDRESSES || "")
  .split(",")
  .map((a) => a.trim())
  .filter(Boolean)
  .forEach((addr, i) => baitLabels.set(addr, `HP-${i + 1}`));

// Fail-closed (Befund 2026-09-29): Persistenz erfordert den Token UND eine
// GEPFLEGTE Köder-Filterkarte. Ist BAIT_ADDRESSES leer, würde jede leere
// baitLabels-Map nichts filtern — und da /api/bait-hashes (Client-Hash-Deny)
// dieselbe Env hasht, meldete selbst der ehrliche Normal-Client beobachtete
// Köder-Cluster, die dann dauerhaft in die öffentliche GitHub-Historie
// committet würden. Der Token allein berechtigt deshalb NICHT zur Persistenz.
const hasPersistence = () => Boolean(process.env.GITHUB_HISTORY_TOKEN) && baitLabels.size > 0;

async function handleGet(req, res) {
  if (!hasPersistence()) {
    return res
      .status(200)
      .json({ clusters: [], updatedAt: null, reason: "Persistenz nicht konfiguriert" });
  }
  if (!getCache || Date.now() - getCache.time >= GET_CACHE_MS) {
    let clusters;
    try {
      const { list } = await readHistoryGitHub();
      clusters = sanitizeHistoryList(list, baitLabels); // Cache speichert den gefilterten Stand
    } catch {
      return res.status(502).json({ error: "Historie nicht erreichbar." });
    }
    // Fix 2026-10-04: updatedAt ist der Bestandstand (max lastReportedAt über
    // die sanitizierten Cluster, null bei leerem Bestand) — nicht die Uhr des
    // Lesevorgangs. readHistoryGitHub liefert {list,sha} ohne Dokument-
    // updatedAt (lib/history.mjs:483); Date.now() suggerierte einen
    // Schreibzeitpunkt, den es auf dieser Route nie gab.
    const updatedAt = clusters.reduce((m, c) => Math.max(m, Number(c?.lastReportedAt) || 0), 0) || null;
    getCache = { time: Date.now(), clusters, updatedAt };
  }
  return res.status(200).json({
    clusters: searchHistory(getCache.clusters, req.query?.q),
    updatedAt: getCache.updatedAt,
  });
}

async function handlePost(req, res) {
  if (!hasPersistence()) {
    return res.status(503).json({ error: "Historie-Persistenz derzeit nicht verfügbar." });
  }
  const clientKey = clientKeyOf(req.headers?.["x-forwarded-for"], req.socket?.remoteAddress);
  if (!rateLimitHistory(clientKey, Date.now())) {
    res.setHeader("Retry-After", "60");
    return res.status(429).json({ error: "Zu viele Meldungen — bitte später erneut versuchen." });
  }

  // Body: Vercel liefert geparstes JSON in req.body; rohe Strings hier
  // selbst parsen (ungültig -> 400, analog zur Express-Standard-400 lokal).
  // Größenlimit 256 kB für BEIDE Body-Formen (Befund 2026-09-29): Content-
  // Length-Check und 413 bisher NUR im String-Zweig — von Vercel vor geparste
  // JSON-Objekte liefen komplett an der Prüfung vorbei.
  if (Number(req.headers?.["content-length"] ?? 0) > MAX_BODY_BYTES) {
    return res.status(413).json({ error: "Payload zu groß." });
  }
  let body = req.body;
  if (typeof body === "string") {
    if (Buffer.byteLength(body, "utf8") > MAX_BODY_BYTES) {
      return res.status(413).json({ error: "Payload zu groß." });
    }
    try {
      body = JSON.parse(body);
    } catch {
      return res.status(400).json({ error: "Ungültiger Request-Body." });
    }
  } else if (body && typeof body === "object") {
    // Vor geparstes Objekt: echte Payload-Größe nachmessen (Content-Length
    // kann fehlen oder bei Chunked-Encoding unzuverlässig sein). Das
    // Nachserialisieren ist bewusst in Kauf genommen — die Feld-Caps in
    // lib/history.mjs begrenzen Struktur, nicht die Parse-Last.
    try {
      if (Buffer.byteLength(JSON.stringify(body), "utf8") > MAX_BODY_BYTES) {
        return res.status(413).json({ error: "Payload zu groß." });
      }
    } catch {
      return res.status(400).json({ error: "Ungültiger Request-Body." });
    }
  }
  if (!body || typeof body !== "object") body = {};

  const now = Date.now();
  let validated;
  let outcome = null; // mergeHistory-Ergebnis des (letzten) apply-Laufs
  try {
    // (i) frischer Read — nicht der GET-Cache — für die existingKeys.
    const freshRead = await readHistoryGitHub();
    const existingKeys = new Set(freshRead.list.map((c) => c?.key).filter(Boolean));
    // (ii) Validierung + Köder-Filter (still, kein Oracle).
    validated = validateAndSanitizeHistoryPayload(body, baitLabels, existingKeys);
    // (iii) Nur NEUE Cluster schreiben. Jeder Browser-Tab mit Live-Funden meldet bis alle 10 s;
    // ohne diese Prüfung erzeugte jeder Besucher einen Commit im Daten-Repo (13.800+ Commits).
    // Bereits bekannte Schlüssel brauchen keinen Schreibvorgang.
    const newClusters = validated.accepted.filter((c) => c && !existingKeys.has(c.key));
    if (!newClusters.length) {
      return res.status(202).json({ accepted: validated.accepted.length, merged: freshRead.list.length, ignored: validated.ignored, dropped: 0, written: false });
    }
    // Merge ausschließlich im apply auf dem frischen Stand.
    const finalList = await writeHistoryGitHub(async (freshList) => {
      const merged = mergeHistory(freshList, validated.accepted, now, baitLabels);
      outcome = merged;
      return merged.list;
    });
    getCache = null; // GET-Cache nach erfolgreichem Write invalidieren
    return res.status(202).json({
      accepted: validated.accepted.length,
      merged: finalList.length,
      ignored: validated.ignored,
      dropped: outcome ? outcome.dropped : 0,
      written: true,
    });
  } catch (err) {
    // 409-Retry scheitert, 403/429, Netzwerk — kein 202 ohne Persistenz.
    // 429 des Upstream (GitHub-Rate-Limit) -> 503, alles andere 502.
    const status = err?.status === 429 ? 503 : 502;
    return res.status(status).json({ error: "Historie-Persistenz derzeit nicht verfügbar." });
  }
}

export default async function handler(req, res) {
  res.setHeader("Cache-Control", "no-store");
  const method = String(req?.method ?? "GET").toUpperCase();
  if (method === "GET") {
    await handleGet(req, res);
  } else if (method === "POST") {
    await handlePost(req, res);
  } else {
    res.status(405).json({ error: "Methode nicht erlaubt." });
  }
}
