// lib/block-window.mjs — Codec für den rollenden Block-Fenster-Bestand
// (data/block-window/<YYYY-MM-DD>.json im GitHub-Datenrepo, pure ESM).
//
// ZWECK: Dem Dashboard Historie im Modus 24h/3d/7d liefern, OHNE 127k–154k
// Roh-Records pro Tag auszuliefern. Pro Block wird nur eine kompakte Zeile
// persistiert {i,t,n} plus — nur für geflaggte Txs — deren Volltext f:[…].
// Ungeflaggte Txs sind nur ZÄHLBAR (n), nie im Detail — ehrliche Tiefe.
//
// GRÖSSENORDNUNG (gemessen 2026-10-02, Kritiker-Probe): Ø 64,2 B/Block,
// Worst 110,3 B -> 1,1–2,3 MB/Tag, 7,8–16,2 MB/7 d über 7 Tages-Chunks
// (18.187–21.960 Blöcke/Tag bei 12,63–15,25 Blöcke/min). GitHub-Contents-
// API-Grenze 100 MB/Datei — Chunks ≤ ~2,4 MB sind unkritisch.
//
// RETENTION: 7 Tage. Der Advance-Tick löscht Chunks älter als 7 Tage
// (deleteGitHubFile in lib/history.mjs); die Lese-Route wählt die Dateien
// fürs angefragte Fenster (api/block-window.js).
//
// KÖDERSCHUTZ (B2, MUST-FIX): Der Advance-Pfad filterte bisher NICHT — die
// Detector-Regeln flaggen Köder-Endpunkte, also landen Köder-Adressen in
// from/to der geflagten Txs. Dieser Codec filtert VOR PERSISTENZ UND VOR
// AUSLIEFERUNG: jede geflagte Edge mit Köder-Endpunkt fällt still raus
// (kein Oracle), Textfelder laufen durch sanitizeText. baitLabels kommen
// ausschließlich als Übergabe (ENV-Muster api/ledger.js:40-46), niemals
// import aus bait.json.
//
// HARTE GRENZEN (identisch zu lib/history.mjs:3-12): pure ESM, KEINE
// npm-Imports. Erlaubt: node:crypto (nicht nötig), keine Netzwerk-Calls
// (Transport wird wiederverwendet: readGitHubContents/writeGitHubContents/
// deleteGitHubFile aus lib/history.mjs — codec-agnostisch mit filePath).
// Läuft NIE im Browser, nicht in der /lib-Whitelist. KEINE Secrets, KEINE
// Köder-Adressen in dieser Datei. Token/Repo-Werte aus ENV nie geloggt.
//
// SCHEMA (persistierter Tages-Chunk):
//   { day: "YYYY-MM-DD", updatedAt: number|null,
//     blocks: [ { i: number, t: string|null, n: number,
//                 f?: [ { from, to, type, amountDrops, txHash, ledgerSeq } ] } ] }
//   i = Ledger-Index, t = close_time_iso, n = Tx-Anzahl des Blocks,
//   f = geflaggte Txs im Volltext (nur wenn nicht leer).
//
// EXPORT-VERTRAG:
//   BLOCK_WINDOW_DIR / blockWindowPath(day) / dayOf(ledgerTimeMs)
//   parseBlockWindowText(text) -> doc (wirft bei Korruption)
//   serializeBlockWindow(doc) -> JSON-String
//   emptyBlockWindow(day) -> doc
//   blockRecord({index, closeTimeIso, txCount, findings}, baitLabels) -> record|null
//   appendBlockWindow(doc, records) -> doc (Index-Dedup, Index-asc)
//   projectBlockWindow(docs, {fromMs, toMs}) -> {buckets, flagged}
//   pruneBlockWindowDocs(docs, now, {windowMs}) -> {docs, staleDays}
//   readBlockWindowGitHub(day) -> {doc, sha}
//   writeBlockWindowGitHub(day, apply) -> newDoc
//   deleteBlockWindowGitHub(day) -> boolean

import {
  readGitHubContents,
  writeGitHubContents,
  deleteGitHubFile,
} from "./history.mjs";
import { sanitizeText } from "./sanitize.mjs";

// ---------- Konstanten ----------
export const BLOCK_WINDOW_DIR = "data/block-window";
export const BLOCK_WINDOW_RETENTION_MS = 7 * 24 * 60 * 60 * 1000; // 7 Tage
const XRPL_ADDR_RE = /^r[1-9A-HJ-NP-Za-km-z]{24,34}$/;
const MAX_STRING_LEN = 200;
const SEVERITY_SET = new Set(["malicious", "suspect", "info"]);
const SEVERITY_RANK = { info: 1, suspect: 2, malicious: 3 };

// Tages-Chunks: UTC-Kalendertag der Ledger-Schließzeit.
export function dayOf(ledgerTimeMs) {
  const n = Number(ledgerTimeMs);
  if (!Number.isFinite(n)) return null;
  return new Date(n).toISOString().slice(0, 10);
}

export function blockWindowPath(day) {
  const d = String(day ?? "");
  if (!/^\d{4}-\d{2}-\d{2}$/.test(d)) {
    throw new Error("Block-Fenster: ungültiges Tages-Datum.");
  }
  return `${BLOCK_WINDOW_DIR}/${d}.json`;
}

// ---------- Frischer Chunk / Parse / Serialize ----------
export function emptyBlockWindow(day) {
  return { day, updatedAt: null, blocks: [] };
}

function normalizeBlockWindowDoc(doc) {
  const day =
    doc && typeof doc.day === "string" && /^\d{4}-\d{2}-\d{2}$/.test(doc.day) ? doc.day : null;
  let updatedAt = null;
  if (doc && doc.updatedAt !== null && doc.updatedAt !== undefined && doc.updatedAt !== "") {
    const n = Number(doc.updatedAt);
    if (Number.isFinite(n)) updatedAt = n;
  }
  const blocks = Array.isArray(doc?.blocks) ? doc.blocks : [];
  return { day, updatedAt, blocks };
}

export function serializeBlockWindow(doc) {
  return JSON.stringify(normalizeBlockWindowDoc(doc));
}

// JSON-Objekt (Dokument) — alles andere ist Korruption und WIRFT (NIEMALS
// leer behandeln und damit ein Überschreiben des korrupten Standes auslösen).
export function parseBlockWindowText(text) {
  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch {
    throw new Error("Block-Fenster-Bestand nicht parsebar (korrumpiert) — kein Überschreiben.");
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error("Block-Fenster-Bestand hat unerwartetes Format — kein Überschreiben.");
  }
  return normalizeBlockWindowDoc(parsed);
}

const blockWindowCodec = { serialize: serializeBlockWindow, parse: parseBlockWindowText };

// ---------- Record-Aufbau (vor PERSISTENZ, Bait-Filter Schicht 1) ----------
// findings: Funde aus analyzeLedger (Adresse im address-Feld). Eine geflagte
// Edge mit Köder in from/to wird STILL verworfen (kein Oracle); Textfelder
// der verbleibenden Edges laufen durch sanitizeText (Defense-in-Depth).
function cleanNum(v) {
  const n = Number(v);
  return Number.isFinite(n) ? n : null;
}

function flaggedFromFinding(f, baitLabels) {
  if (!f || typeof f !== "object") return null;
  const from = typeof f.from === "string" && XRPL_ADDR_RE.test(f.from) ? f.from : null;
  const to = typeof f.to === "string" && XRPL_ADDR_RE.test(f.to) ? f.to : null;
  if (!from || !to) return null;
  if (baitLabels.has(from) || baitLabels.has(to)) return null; // STILL — kein Oracle
  const txHash = typeof f.txHash === "string" && f.txHash ? f.txHash.slice(0, MAX_STRING_LEN) : null;
  const sev = SEVERITY_SET.has(f.severity) ? f.severity : null;
  return {
    from,
    to,
    type: typeof f.type === "string" ? sanitizeText(f.type, baitLabels).slice(0, MAX_STRING_LEN) : null,
    amountDrops: cleanNum(f.amountDrops),
    txHash,
    ledgerSeq: cleanNum(f.ledgerSeq),
    severity: sev,
  };
}

// Findings des Detektors (address-Feld) + zugehörige tx-Records (Kanten-
// Endpunkte) zu geflagten Edges verbinden: eine tx gilt als geflaggt, wenn
// ihr account ODER destination eine Fund-Adresse ist — exakt die Kantenregel
// von buildClusterGraph (lib/cluster.mjs:226-236), hier ohne Graph-Aufbau.
export function flaggedEdgesFrom(txRecords, findings, baitLabels) {
  const flaggedAddrs = new Map(); // addr -> max severity der Funde
  for (const f of Array.isArray(findings) ? findings : []) {
    const addr = f?.address;
    if (typeof addr !== "string" || !addr) continue;
    const sev = SEVERITY_SET.has(f?.severity) ? f.severity : "info";
    const cur = flaggedAddrs.get(addr);
    if (!cur || SEVERITY_RANK[sev] > SEVERITY_RANK[cur]) flaggedAddrs.set(addr, sev);
  }
  const out = [];
  for (const rec of Array.isArray(txRecords) ? txRecords : []) {
    const account = typeof rec?.account === "string" ? rec.account : null;
    const destination = typeof rec?.destination === "string" ? rec.destination : null;
    if (!account && !destination) continue;
    if (!(flaggedAddrs.has(account) || flaggedAddrs.has(destination))) continue;
    if (!account || !destination || account === destination) continue; // Kantenregel
    const sevRank = Math.max(
      SEVERITY_RANK[flaggedAddrs.get(account) ?? ""] ?? 0,
      SEVERITY_RANK[flaggedAddrs.get(destination) ?? ""] ?? 0
    );
    const e = flaggedFromFinding(
      {
        from: account,
        to: destination,
        type: rec.type,
        amountDrops: rec.amountDrops,
        txHash: rec.hash,
        ledgerSeq: rec.ledgerSeq,
        severity: sevRank ? (sevRank === 3 ? "malicious" : sevRank === 2 ? "suspect" : "info") : null,
      },
      baitLabels
    );
    if (e) out.push(e);
  }
  return out;
}

// Kompakte Block-Zeile {i,t,n,f?}; f nur für geflaggte Txs.
export function blockRecord({ index, closeTimeIso, txCount, flagged }, baitLabels) {  const i = Number(index);
  if (!Number.isFinite(i) || i < 0) return null;
  const rec = {
    i: Math.floor(i),
    t: typeof closeTimeIso === "string" && closeTimeIso ? closeTimeIso : null,
    n: Math.max(0, Math.floor(Number(txCount) || 0)),
  };
  const f = (Array.isArray(flagged) ? flagged : [])
    .map((e) => flaggedFromFinding(e, baitLabels))
    .filter(Boolean);
  if (f.length) rec.f = f;
  return rec;
}

// ---------- Append (Index-Dedup, Index-asc, deterministisch) ----------
export function appendBlockWindow(doc, records) {
  const base = normalizeBlockWindowDoc(doc);
  const byIndex = new Map();
  for (const b of base.blocks) {
    const i = Number(b?.i);
    if (Number.isFinite(i)) byIndex.set(Math.floor(i), b);
  }
  for (const r of Array.isArray(records) ? records : []) {
    const i = Number(r?.i);
    if (!Number.isFinite(i)) continue;
    byIndex.set(Math.floor(i), r); // letztere Sicht gewinnt (Idempotenz bei Retry)
  }
  const blocks = [...byIndex.values()].sort((a, b) => a.i - b.i);
  return { day: base.day, updatedAt: base.updatedAt, blocks };
}

// ---------- Projektion (vor AUSLIEFERUNG, Bait-Filter Schicht 2) ----------
// Stunden-Rollups (<= 168 Zeilen bei 7 d) + geflaggte Blockdetails im
// Zeitfenster [fromMs, toMs]. Blöcke ohne parsebares t können nicht
// zeitlich eingeordnet werden: sie fallen aus den Stunden-Rollups raus,
// werden aber als flagged-Eintrag mit `untimed: true` ausgeliefert —
// sichtbar statt still verworfen (Audit-Befund Z.227-230).
const HOUR_MS = 3600 * 1000;

function edgeSeverity(e) {
  // Rückwärtskompatibel: persistierte Edges ohne severity-Feld (ältere
  // Bestände) zählen als 'malicious' (Codec-Default).
  return SEVERITY_SET.has(e?.severity) ? e.severity : "malicious";
}

export function projectBlockWindow(docs, { fromMs, toMs } = {}) {
  const from = Number(fromMs);
  const to = Number(toMs);
  const buckets = new Map(); // hourMs -> {t, blocks, txns, flaggedBlocks, maxSeverity}
  const flagged = [];
  const srcList = Array.isArray(docs) ? docs : [];
  for (const doc of srcList) {
    const base = normalizeBlockWindowDoc(doc);
    for (const b of base.blocks) {
      const i = Number(b?.i);
      const tMs = Date.parse(String(b?.t ?? ""));
      if (!Number.isFinite(i)) continue;
      const f = Array.isArray(b?.f) ? b.f : [];
      if (!Number.isFinite(tMs)) {
        // Kein parsebares t: nicht in Rollups einordenbar, aber als
        // untimed-Flagged-Eintrag ausliefern (sichtbar statt verloren).
        if (f.length) {
          flagged.push({
            i: Math.floor(i),
            t: null,
            untimed: true,
            n: Math.max(0, Math.floor(Number(b?.n) || 0)),
            f,
          });
        }
        continue;
      }
      if (Number.isFinite(from) && tMs < from) continue;
      if (Number.isFinite(to) && tMs > to) continue;
      const hour = Math.floor(tMs / HOUR_MS) * HOUR_MS;
      const bucket = buckets.get(hour) ?? {
        t: hour,
        blocks: 0,
        txns: 0,
        flaggedBlocks: 0,
        maxSeverity: null,
      };
      bucket.blocks += 1;
      bucket.txns += Math.max(0, Math.floor(Number(b?.n) || 0));
      if (f.length) {
        bucket.flaggedBlocks += 1;
        // maxSeverity = Maximum der Edge-severities (Malicious/Suspect/Info
        // unterscheidbar — die alte hart 'malicious'-Sicht war nachweislich
        // falsch, RULES enthalten suspect/info).
        for (const e of f) {
          const sev = edgeSeverity(e);
          if (!bucket.maxSeverity || SEVERITY_RANK[sev] > SEVERITY_RANK[bucket.maxSeverity]) {
            bucket.maxSeverity = sev;
          }
        }
      }
      buckets.set(hour, bucket);
      if (f.length) {
        flagged.push({
          i: Math.floor(i),
          t: new Date(tMs).toISOString(),
          n: Math.max(0, Math.floor(Number(b?.n) || 0)),
          f,
        });
      }
    }
  }
  const bucketList = [...buckets.values()].sort((a, b) => a.t - b.t);
  flagged.sort((a, b) => b.i - a.i); // neueste Blöcke zuerst
  return { buckets: bucketList, flagged };
}

// ---------- Retention-Auswahl ----------
// docs: [{day, doc}] — Rückgabe: verbleibende docs + Tages-Strings, die
// älter als windowMs sind (der Caller löscht sie via deleteBlockWindowGitHub).
export function pruneBlockWindowDocs(docs, now, { windowMs = BLOCK_WINDOW_RETENTION_MS } = {}) {
  const n = Number(now);
  const base = Number.isFinite(n) ? n : Date.now();
  const keep = [];
  const staleDays = [];
  for (const entry of Array.isArray(docs) ? docs : []) {
    const day = typeof entry?.day === "string" ? entry.day : null;
    if (!day || !/^\d{4}-\d{2}-\d{2}$/.test(day)) continue;
    // Tagesgrenze: Ende des UTC-Tages; veraltet, wenn dieses Ende vor
    // now - windowMs liegt (definierte, deterministische Semantik).
    const dayEndMs = Date.parse(`${day}T23:59:59.999Z`);
    if (!Number.isFinite(dayEndMs)) continue;
    if (dayEndMs < base - windowMs) staleDays.push(day);
    else keep.push(entry);
  }
  return { docs: keep, staleDays };
}

// ---------- GitHub-Transport (wiederverwendet, eigener Codec + Pfad) ----------
export async function readBlockWindowGitHub(day) {
  const { doc, sha } = await readGitHubContents(blockWindowPath(day), blockWindowCodec);
  return { doc: doc ?? emptyBlockWindow(day), sha };
}

export function writeBlockWindowGitHub(day, apply) {
  return writeGitHubContents(
    (doc) => apply(doc ?? emptyBlockWindow(day)),
    blockWindowPath(day),
    blockWindowCodec
  );
}

export async function deleteBlockWindowGitHub(day) {
  return deleteGitHubFile(blockWindowPath(day));
}
