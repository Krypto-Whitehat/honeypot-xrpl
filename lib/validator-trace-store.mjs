// lib/validator-trace-store.mjs — Persistenz des Validator-Trace im PRIVATEN History-Daten-Repo.
//
// Gleicher Mechanismus wie der Historie-Button (lib/history.mjs): GitHub-Contents-API auf dem
// separaten Daten-Repo (Env GITHUB_HISTORY_REPO, Default Krypto-Whitehat/honeypot-xrpl-history),
// Token aus GITHUB_HISTORY_TOKEN. Schreiben mit frischem Read + sha + 409-Retry (readGitHubContents /
// writeGitHubContents). NIEMALS ins Deploy-Repo: jeder Commit dort würde ein Vercel-Redeploy auslösen.
//
// Pfad je Tag: data/validator-trace/YYYY-MM-DD.json. Ohne Token (lokal) liest/schreibt der Recorder
// stattdessen data/validator-trace/ im Arbeitsverzeichnis (lib/validator-trace-query.mjs).
import { readGitHubContents, writeGitHubContents } from "./history.mjs";

export const TRACE_DIR = "data/validator-trace";
// Direkt abfragbares Fenster ("seit Start"): Default 400 Tage, deckt das
// 12-Monats-Ring-Fenster der Shards ab. Env TRACE_MAX_DAYS überschreibt.
// Ältere Tagesdateien bleiben im Speicher erhalten (kein Pruning), sind aber
// nur per Datumsabfrage erreichbar.
export const TRACE_RETENTION_DAYS = Number(process.env.TRACE_MAX_DAYS) > 0 ? Math.floor(Number(process.env.TRACE_MAX_DAYS)) : 400;
const CACHE_MS = { "1h": 60000, "24h": 60000, "7d": 120000, all: 600000 };
const cache = new Map(); // range -> { time, days }

const jsonCodec = {
  serialize: (doc) => JSON.stringify(doc),
  parse: (text) => {
    const o = JSON.parse(text);
    if (!o || typeof o !== "object" || Array.isArray(o)) throw new Error("Trace-Tagesdatei hat kein gültiges Format.");
    return o;
  },
};

export function traceTokenConfigured() {
  return Boolean(process.env.GITHUB_HISTORY_TOKEN);
}

export function dayPath(date) {
  return `${TRACE_DIR}/${date}.json`;
}

// Alle Kalendertage (UTC, YYYY-MM-DD) von fromMs bis toMs, neueste zuerst, begrenzt auf die Aufbewahrung.
export function datesBetween(fromMs, toMs) {
  const out = [];
  const oldest = Date.parse(new Date(toMs).toISOString().slice(0, 10)) - (TRACE_RETENTION_DAYS - 1) * 86400000;
  let d = Date.parse(new Date(toMs).toISOString().slice(0, 10));
  const stop = Math.max(Date.parse(new Date(fromMs).toISOString().slice(0, 10)), oldest);
  while (d >= stop) {
    out.push(new Date(d).toISOString().slice(0, 10));
    d -= 86400000;
  }
  return out;
}

export function datesForRange(range, now = Date.now()) {
  const span = { "1h": 3600000, "24h": 86400000, "7d": 7 * 86400000, all: Infinity }[range] ?? 86400000;
  const from = span === Infinity ? now - (TRACE_RETENTION_DAYS - 1) * 86400000 : now - span;
  return datesBetween(from, now);
}

export async function saveDayRemote(day) {
  if (!day || !/^\d{4}-\d{2}-\d{2}$/.test(day.date)) throw new Error("saveDayRemote: ungültiges Tagesobjekt.");
  await writeGitHubContents(() => day, dayPath(day.date), jsonCodec);
  return true;
}

export async function loadDayRemote(date) {
  const { doc } = await readGitHubContents(dayPath(date), jsonCodec);
  return doc;
}

// Lädt alle Tage eines Zeitraums (parallel, begrenzt). Fehler werden NICHT verschluckt:
// ein Lesefehler bricht ab, damit nie eine unvollständige Historie als vollständig erscheint.
export async function loadDaysRemote(range, now = Date.now()) {
  const c = cache.get(range);
  if (c && now - c.time < (CACHE_MS[range] ?? 60000)) return c.days;
  const dates = datesForRange(range, now);
  const days = [];
  for (let i = 0; i < dates.length; i += 8) {
    const part = await Promise.all(dates.slice(i, i + 8).map((d) => loadDayRemote(d)));
    for (const d of part) if (d) days.push(d);
  }
  days.sort((a, b) => (a.date < b.date ? -1 : 1));
  cache.set(range, { time: now, days });
  return days;
}

// Löscht den Tag, der die Aufbewahrungsgrenze überschreitet (einmal täglich aufrufen).
// Lebenslange Speicherung: alte Tage werden NIE gelöscht (Shards halten die Historie).
export async function pruneRemote() {
  return false;
}

export function clearTraceCacheForTests() {
  cache.clear();
}
