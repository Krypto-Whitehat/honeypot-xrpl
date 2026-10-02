// Vercel Function: GET /api/block-window — rollender Block-Fenster-Bestand.
//
// Liefert die Server-Historie im Modus 24h/3d/7d für das Dashboard:
// STUNDEN-ROLLUPS (<= 168 Zeilen bei 7 d) + geflaggte Blockdetails im
// Volltext — NIE 127k–154k Roh-Records. Ungeflaggte Txs sind nur zählbar
// (n im Rollup), nie im Detail — ehrliche Tiefe.
//
// GET -> 200 { range, from, to, updatedAt,
//             buckets: [{t, blocks, txns, flaggedBlocks, maxSeverity}],
//             flagged: [{i, t, n, f: [{from, to, type, amountDrops, txHash, ledgerSeq}]}],
//             cursor, validatedIndex }
//   range: "24h" | "3d" | "7d" (Default 24h; ungültig -> 400)
//   from/to: Epoch-ms-Grenzen des Fensters
//   Adressfelder serverseitig baitLabels-gefiltert (Köder fallen still raus,
//   sanitizeText auf Textfelder) — der Filter liegt im Codec lib/block-
//   window.mjs VOR PERSISTENZ; dieser Endpunkt liefert nur, was bereits
//   gefiltert persistiert wurde (keine Adressen aus dem ENV in dieser Datei).
//
// SICHERHEIT (Muster api/flow-state.js):
//   - FAIL-CLOSED ohne Token: ohne GITHUB_HISTORY_TOKEN 200 +
//     reason "Persistenz nicht konfiguriert" (roh, NICHT übersetzt —
//     clientseitiger exakter Vergleich public/history.js / history-host.html;
//     Muster api/flow-state.js:95). Kein Erfolgs-Vortäuschen, kein Fehler.
//   - Read-Fehler -> 502/503 (429 des Upstream -> 503), neutrale Messages.
//   - GET-only: andere Methoden -> 405.
//   - 60-s-Prozess-Cache auf geladenen Chunks (Muster api/flow-state.js:40):
//     begrenzt die GitHub-Reads pro Function-Instanz auf <= 7/min pro Range,
//     unabhängig von der Besucherzahl.
//   - validatedIndex: EIN RPC ledger_index:'validated' mit 60-s-Cache
//     (Muster api/flow-state.js) — Fehler -> null (ehrlicher Leerzustand).
import { readFlowStateGitHub } from "../lib/flow-state.mjs";
import {
  readBlockWindowGitHub,
  projectBlockWindow,
  dayOf,
} from "../lib/block-window.mjs";
import { fetchValidatedIndex } from "./flow-state.js";

export const maxDuration = 30;

const RANGES = { "24h": 24, "3d": 72, "7d": 168 }; // Stunden
const CACHE_MS = 60000; // 60-s-Prozess-Cache wie api/flow-state.js

// Prozess-Cache: range -> { time, body }. Nur im Prozess-Speicher.
const chunkCache = new Map();

// Test-Helfer (lib/block-window-endpoint-Tests über node --test der Route
// nicht nötig — Helper für manuelle Smoke-Läufe): setzt den Cache zurück.
export function resetBlockWindowCacheForTests() {
  chunkCache.clear();
}

// Fail-closed: Persistenz erfordert den Token (nur aus ENV).
const hasPersistence = () => Boolean(process.env.GITHUB_HISTORY_TOKEN);

export default async function handler(req, res) {
  res.setHeader("Cache-Control", "no-store");
  const method = String(req?.method ?? "GET").toUpperCase();
  if (method !== "GET") {
    res.setHeader("Allow", "GET");
    return res.status(405).json({ error: "Methode nicht erlaubt." });
  }
  const rawRange = String(req?.query?.range ?? "24h").trim();
  const hours = RANGES[rawRange];
  if (!hours) {
    return res.status(400).json({ error: "Ungültiger range (24h|3d|7d)." });
  }
  if (!hasPersistence()) {
    return res.status(200).json({
      range: rawRange,
      from: null,
      to: null,
      updatedAt: null,
      buckets: [],
      flagged: [],
      cursor: 0,
      validatedIndex: null,
      reason: "Persistenz nicht konfiguriert",
    });
  }
  try {
    const now = Date.now();
    const from = now - hours * 3600 * 1000;
    const cached = chunkCache.get(rawRange);
    if (cached && now - cached.time < CACHE_MS) {
      // Kompletter Body gecacht (Chunks + cursor + validatedIndex): ein
      // Poll/Minute pro Besucher-Tab erzeugt pro Function-Instanz damit
      // <= 1 Chunk-Read + 1 Flow-State-Read + 1 RPC pro Minute.
      return res.status(200).json(cached.body);
    }
    // Tages-Chunks fürs Fenster lesen (max. 8 Dateien bei 7 d — der Tag
    // vor dem Fensteranfang kann Blöcke im Fenster tragen).
    const days = [];
    for (let back = 0; back <= Math.ceil(hours / 24); back++) {
      const d = dayOf(now - back * 24 * 60 * 60 * 1000);
      if (d && !days.includes(d)) days.push(d);
    }
    const docs = await Promise.all(
      days.map(async (d) => {
        const { doc } = await readBlockWindowGitHub(d);
        return { day: d, doc };
      })
    );
    const { buckets, flagged } = projectBlockWindow(docs.map((e) => e.doc), { fromMs: from, toMs: now });
    const updatedAt = docs.reduce((m, e) => Math.max(m, Number(e.doc?.updatedAt) || 0), 0) || null;
    const { doc } = await readFlowStateGitHub();
    const validatedIndex = await fetchValidatedIndex();
    const body = {
      range: rawRange,
      from,
      to: now,
      updatedAt,
      buckets,
      flagged,
      cursor: doc.cursor,
      validatedIndex,
    };
    chunkCache.set(rawRange, { time: now, body });
    return res.status(200).json(body);
  } catch (err) {
    // Read-Fehler (403/429, Netzwerk) -> 502/503 (429 des Upstream -> 503).
    const status = err?.status === 429 ? 503 : 502;
    return res.status(status).json({ error: "Block-Fenster nicht erreichbar." });
  }
}
