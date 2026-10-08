// lib/validator-trace-query.mjs — Abfrage der Trace-Tagesdateien (rein, ohne Netzwerk).
// Eingabe: Tagesobjekte aus data/validator-trace/YYYY-MM-DD.json (monitor/validator-trace.mjs).
import fs from "node:fs";
import path from "node:path";
import { aggregatePatterns } from "./validator-trace.mjs";

export const RANGE_MS = { "1h": 3600000, "24h": 86400000, "7d": 7 * 86400000, all: Infinity };
export const RETENTION_DAYS = 365;

// Liest alle Tagesdateien im Ordner (Muster YYYY-MM-DD.json), begrenzt auf die Aufbewahrung.
export function loadDays(dir, now = Date.now()) {
  if (!dir || !fs.existsSync(dir)) return [];
  const cutoff = now - RETENTION_DAYS * 86400000;
  const out = [];
  for (const f of fs.readdirSync(dir)) {
    if (!/^\d{4}-\d{2}-\d{2}\.json$/.test(f)) continue;
    if (Date.parse(f.slice(0, 10)) < cutoff) continue;
    try { out.push(JSON.parse(fs.readFileSync(path.join(dir, f), "utf8"))); } catch { /* beschädigte Tagesdatei überspringen, sichtbar über Tagesliste */ }
  }
  return out.sort((a, b) => (a.date < b.date ? -1 : 1));
}

function windowOf(range, now) {
  const ms = RANGE_MS[range] ?? RANGE_MS["24h"];
  return { from: ms === Infinity ? 0 : now - ms, to: now + 1 };
}

// Trace eines Validators: Zusammenfassung, Incident-Zeitleiste (neueste zuerst), Muster.
export function traceForValidator(days, master, { range = "24h", now = Date.now() } = {}) {
  const w = windowOf(range, now);
  const summary = { ok: 0, partial: 0, missed: 0, wrongHash: 0 };
  const incidents = [];
  for (const d of days) {
    const v = d.validators?.[master];
    if (!v) continue;
    summary.ok += v.ok; summary.partial += v.partial; summary.missed += v.missed; summary.wrongHash += v.wrongHash;
  }
  for (const d of days) {
    for (const i of d.incidents ?? []) {
      if (i.m !== master || i.t < w.from || i.t > w.to) continue;
      incidents.push({ ledgerIndex: i.l, timeMs: i.t, type: i.type, reasons: i.r ?? [], note: i.n ?? null });
    }
  }
  incidents.sort((a, b) => b.timeMs - a.timeMs);
  const patterns = aggregatePatterns(incidents.map((i) => ({ ...i, master })), { minCount: 2, minValidators: 1 });
  return { master, range, summary: { ...summary, observed: summary.ok + summary.partial + summary.missed + summary.wrongHash }, incidents, patterns: patterns.tags };
}

// Übergreifende Muster: alle Validatoren im Zeitraum, mit Zählern je Validator.
export function crossValidatorPatterns(days, { range = "24h", now = Date.now() } = {}) {
  const w = windowOf(range, now);
  const incidents = [];
  for (const d of days) {
    for (const i of d.incidents ?? []) {
      if (i.t < w.from || i.t > w.to) continue;
      incidents.push({ master: i.m, ledgerIndex: i.l, timeMs: i.t, type: i.type, reasons: i.r ?? [] });
    }
  }
  const p = aggregatePatterns(incidents, { minCount: 3, minValidators: 2 });
  const perValidator = {};
  for (const i of incidents) {
    const e = (perValidator[i.master] ??= { missed: 0, partial: 0, wrongHash: 0 });
    if (i.type === "missed") e.missed++; else if (i.type === "partial") e.partial++; else if (i.type === "wrong-hash") e.wrongHash++;
  }
  return { range, incidents: incidents.length, tags: p.tags, recurring: p.recurring, perValidator };
}
