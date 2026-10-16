// lib/validator-trace-query.mjs — Abfrage der Trace-Tagesdateien (rein, ohne Netzwerk).
// Eingabe: Tagesobjekte aus data/validator-trace/YYYY-MM-DD.json (monitor/validator-trace.mjs).
import fs from "node:fs";
import path from "node:path";
import { aggregatePatterns } from "./validator-trace.mjs";
import { retraceForValidator, riskProfile, attackSignals, signatureBoard, isSignatureTag } from "./validator-retrace.mjs";
import { failureRuns, failureSplit, validatorFingerprint, coFailureClusters, quorumCriticality, windowScan, seriesContext, applySeries, loadResponseCurve } from "./validator-diagnose.mjs";

export const RANGE_MS = { "1h": 3600000, "24h": 86400000, "7d": 7 * 86400000, all: Infinity };
export const RETENTION_DAYS = 365;
// Intervalle des Zeitprofils. Dieselbe Zahl im UI (public/validator-trace.mjs BUCKETS): die
// Achse des Profils und die Zellen dieses Profils muessen dieselbe Zeitachse sein.
export const PROFILE_BUCKETS = 24;

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
// summary = Gesamtzähler über die Aufzeichnung (Tageszähler sind nicht fenster-genau).
// inWindow = fenster-genaue Zähler: Incidents sind zeitgestempelt -> exakt; 'ok' und
// 'observed' werden aus den Stunden-Ledgerzählern (d.hourly) anteilig am Fenster-
// Overlap geschätzt. inWindow ist null, wenn kein geladener Tag Stundenzähler hat
// (ältere Tagesdateien) -> UI kennzeichnet das ehrlich statt falsche Zahlen zu zeigen.
export function traceForValidator(days, master, { range = "24h", now = Date.now() } = {}) {
  const w = windowOf(range, now);
  const summary = { ok: 0, partial: 0, missed: 0, wrongHash: 0, noQuorum: 0 };
  const incidents = [];
  // shapeSeen / shapeMissing: Abdeckung der Transaktions-Forensik. Getrennt, weil "keine
  // Signatur" und "Signatur nicht erfasst" zwei verschiedene Aussagen sind.
  const coverage = { ledgers: 0, days: 0, firstMs: null, lastMs: null, gapLedgers: 0, quorumFail: 0, shapeSeen: 0, shapeMissing: 0 };
  for (const d of days) {
    const v = d.validators?.[master];
    if (v) {
      summary.ok += v.ok; summary.partial += v.partial; summary.missed += v.missed; summary.wrongHash += v.wrongHash; summary.noQuorum += v.noQuorum ?? 0;
    }
    coverage.ledgers += d.ledgers ?? 0;
    coverage.quorumFail += d.quorumFail ?? 0;
    if (d.firstMs && (!coverage.firstMs || d.firstMs < coverage.firstMs)) coverage.firstMs = d.firstMs;
    if (d.lastMs && (!coverage.lastMs || d.lastMs > coverage.lastMs)) coverage.lastMs = d.lastMs;
    for (const g of d.gaps ?? []) coverage.gapLedgers += Math.max(0, (g.to ?? 0) - (g.from ?? 0) + 1);
    coverage.shapeSeen += d.shapeSeen ?? 0;
    coverage.shapeMissing += d.shapeMissing ?? 0;
    if (d.incidents?.length || d.ledgers) coverage.days += 1;
  }
  // dUNL-weite Betroffenheit je Ledger: alle Validatoren im Fenster, nicht nur der angefragte.
  // Diese Zahl entscheidet im 3D-Profil zwischen "solo" und "Netzereignis". Kein Eintrag heisst
  // "dazu nichts aufgezeichnet" -> null, nicht 0.
  const cohort = new Map();
  for (const d of days) {
    for (const i of d.incidents ?? []) {
      if (i.t < w.from || i.t > w.to) continue;
      const set = cohort.get(i.l) ?? new Set();
      set.add(i.m);
      cohort.set(i.l, set);
    }
  }
  for (const d of days) {
    for (const i of d.incidents ?? []) {
      if (i.m !== master || i.t < w.from || i.t > w.to) continue;
      const peers = cohort.get(i.l);
      incidents.push({ ledgerIndex: i.l, timeMs: i.t, type: i.type, reasons: i.r ?? [], note: i.n ?? null, affectedValidators: peers ? peers.size : null });
    }
  }
  incidents.sort((a, b) => b.timeMs - a.timeMs);
  const gaps = [];
  for (const d of days) for (const g of d.gaps ?? []) if (g.t >= w.from && g.t <= w.to) gaps.push({ from: g.from, to: g.to, timeMs: g.t, reason: g.reason ?? "stream-gap" });
  gaps.sort((a, b) => b.timeMs - a.timeMs);
  // Fenster-genau: Incident-Zähler exakt (zeitgestempelt); 'observed' anteilig aus den
  // Stunden-Buckets — pro Validator (hb.v[master]), falls vorhanden, sonst hb.l.
  let observed = 0;
  let hasHourly = false;
  for (const d of days) {
    for (const [hk, hb] of Object.entries(d.hourly ?? {})) {
      const h0 = Number(hk) * 3600000;
      const overlap = Math.min(h0 + 3600000, w.to) - Math.max(h0, w.from);
      if (overlap <= 0) continue;
      hasHourly = true;
      const frac = Math.min(1, overlap / 3600000);
      const hv = hb.v?.[master];
      const perV = hv ? (hv.ok || 0) + (hv.partial || 0) + (hv.missed || 0) + (hv.wrongHash || 0) + (hv.noQuorum || 0) : null;
      observed += (perV ?? hb.l ?? 0) * frac;
    }
  }
  const bad = incidents.reduce(
    (acc, i) => {
      if (i.type === "missed") acc.missed++;
      else if (i.type === "partial") acc.partial++;
      else if (i.type === "wrong-hash") acc.wrongHash++;
      else if (i.type === "no-quorum") acc.noQuorum++;
      return acc;
    },
    { missed: 0, partial: 0, wrongHash: 0, noQuorum: 0 }
  );
  observed = Math.round(observed);
  const inWindow = hasHourly
    ? { ...bad, ok: Math.max(0, observed - bad.missed - bad.partial - bad.wrongHash - bad.noQuorum), observed, estimated: true }
    : null;
  const patterns = aggregatePatterns(incidents.map((i) => ({ ...i, master })), { minCount: 2, minValidators: 1 });
  // Lücken: Zeitraum, in dem der Recorder nicht mitgeschrieben hat. Dort gibt es KEINE Aussage.
  // Retrace + Risikoprofil: je Vorfall die messbare Diagnose (Kohorte, Quorum-Rand, Last, Takt)
  // und der Vergleichswert, wie oft ein Ledger mit dieser Anomalie überhaupt ausfällt.
  const risk = riskProfile(days);
  const retrace = retraceForValidator(days, master, { range, now, risk });
  // Serien-Ebene: die Retrace erklaert einen Vorfall aus seinem Ledger. Was sie nicht leisten
  // kann, ist die Zeitfolge - und die ist gemessen die Haupterklaerung (99 % der "ohne Ursache"
  // liegen in einer Serie aufeinanderfolgender Ledger). Deshalb hier, nach der Retrace, damit
  // die Karte nicht bei "keine Ursache" stehen bleibt, wo eine Ausfallserie steht.
  const runs = failureRuns(days, { master, range, now });
  applySeries(retrace, runs, master);
  const diagnosis = {
    fingerprint: validatorFingerprint(days, master, { range, now }),
    runs: runs.slice(0, 12),
    criticality: quorumCriticality(days, master, { range, now }),
    // Last-Ausfall-Kurve: ab welcher Tx-Last dieser Knoten zurueckfaellt und ab welcher die
    // Kohorte dieselbe Last haelt. Das ist der Kapazitaetsbefund, den die Ledger-Ebene nicht
    // liefern kann, weil sie Last immer relativ zum eigenen Median desselben Ledgers sieht.
    load: loadResponseCurve(days, { master, range, now }),
  };
  return {
    master, range,
    summary: { ...summary, observed: summary.ok + summary.partial + summary.missed + summary.wrongHash + summary.noQuorum },
    inWindow, coverage, incidents, gaps, patterns: patterns.tags,
    retrace,
    diagnosis,
    profile: profileCells(days, master, { range, now }),
    risk: { totalLedgers: risk.totalLedgers, incidentLedgers: risk.incidentLedgers, rows: risk.rows, statsTruncated: risk.statsTruncated },
  };
}

// Zeitprofil je Intervall: die Abweichungen DIESSES Validators und - genauso wichtig - die
// gemessene Ledger-Abdeckung desselben Intervalls. Ohne die Abdeckung ist ein leeres Intervall
// mehrdeutig: "nichts aufgezeichnet" und "aufgezeichnet, alles in Ordnung" sahen bis hierhin
// identisch aus, und das Profil hat Luecken als "nicht erfasst" gezeichnet, wo nichts zu
// vermelden war.
//
// Abdeckung aus den Stunden-Zaehlern (d.hourly): pro Validator die eigenen Ledger dieses
// Stundenblocks, anteilig auf die Intervalle verteilt, die der Block ueerschneidet. Der
// Stundenblock ist eine Messung; die Verteilung auf Intervalle ist eine Aufteilung und wird als
// estimated ausgewiesen.
export function profileCells(days, master, { range = "24h", now = Date.now(), buckets = PROFILE_BUCKETS } = {}) {
  const w = windowOf(range, now);
  const span = RANGE_MS[range] ?? RANGE_MS["24h"];
  let from = span === Infinity ? null : now - span;
  for (const d of Array.isArray(days) ? days : []) {
    for (const i of d.incidents ?? []) {
      if (i.m !== master || !Number.isFinite(i.t) || i.t < w.from || i.t > w.to) continue;
      if (from === null || i.t < from) from = i.t;
    }
  }
  if (from === null) from = span === Infinity ? 0 : now - span;
  const width = Math.max(1, now - from);
  const cells = Array.from({ length: buckets }, (_, i) => ({
    index: i,
    from: from + (i / buckets) * width,
    to: from + ((i + 1) / buckets) * width,
    ledgers: 0, missed: 0, partial: 0, wrongHash: 0, noQuorum: 0, total: 0,
    cohort: null, tags: {}, signatures: 0,
  }));
  const cellOf = (ms) => cells[Math.min(buckets - 1, Math.max(0, Math.floor(((ms - from) / width) * buckets)))];

  let measured = false;
  for (const d of Array.isArray(days) ? days : []) {
    for (const [hk, hb] of Object.entries(d.hourly ?? {})) {
      const h0 = Number(hk) * 3600000;
      if (!Number.isFinite(h0)) continue;
      if (Math.min(h0 + 3600000, w.to) - Math.max(h0, w.from) <= 0) continue;
      const hv = hb?.v?.[master];
      const perV = hv ? (hv.ok || 0) + (hv.partial || 0) + (hv.missed || 0) + (hv.wrongHash || 0) + (hv.noQuorum || 0) : null;
      const ledgers = perV ?? hb?.l ?? 0;
      if (!ledgers) continue;
      measured = true;
      for (const cell of cells) {
        const ov = Math.min(h0 + 3600000, cell.to) - Math.max(h0, cell.from);
        if (ov <= 0) continue;
        cell.ledgers += (ledgers * ov) / 3600000;
      }
    }
  }

  const cohort = new Map();
  for (const d of Array.isArray(days) ? days : []) {
    for (const i of d.incidents ?? []) {
      if (i.t < w.from || i.t > w.to) continue;
      const set = cohort.get(i.l) ?? new Set();
      set.add(i.m);
      cohort.set(i.l, set);
    }
  }
  for (const d of Array.isArray(days) ? days : []) {
    for (const i of d.incidents ?? []) {
      if (i.m !== master || i.t < w.from || i.t > w.to) continue;
      const key = i.type === "missed" ? "missed" : i.type === "partial" ? "partial" : i.type === "wrong-hash" ? "wrongHash" : i.type === "no-quorum" ? "noQuorum" : null;
      if (!key) continue;
      const cell = cellOf(i.t);
      cell[key] += 1;
      cell.total += 1;
      const peers = cohort.get(i.l);
      const n = peers ? peers.size : null;
      if (n !== null && (cell.cohort === null || n > cell.cohort)) cell.cohort = n;
      for (const r of i.r ?? []) {
        cell.tags[r] = (cell.tags[r] ?? 0) + 1;
        if (isSignatureTag(r)) cell.signatures += 1;
      }
    }
  }
  for (const c of cells) c.ledgers = Math.round(c.ledgers);
  return { from, to: now, buckets, measured, cells };
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
    const e = (perValidator[i.master] ??= { missed: 0, partial: 0, wrongHash: 0, noQuorum: 0 });
    if (i.type === "missed") e.missed++; else if (i.type === "partial") e.partial++; else if (i.type === "wrong-hash") e.wrongHash++; else if (i.type === "no-quorum") e.noQuorum++;
  }
  const risk = riskProfile(days);
  return {
    range, incidents: incidents.length, tags: p.tags, recurring: p.recurring, perValidator,
    risk: { totalLedgers: risk.totalLedgers, incidentLedgers: risk.incidentLedgers, rows: risk.rows, statsTruncated: risk.statsTruncated },
    attacks: attackSignals(days, { range, now, risk }),
    // Netz-Sicht der Serien- und Kohortenebene: wer faellt am Stueck, wer faellt nur im Netz,
    // und ob es Knoten gibt, die privat fast immer zusammen ausfallen (geteilte Infrastruktur).
    split: failureSplit(days, { range, now }),
    clusters: coFailureClusters(days, { range, now }),
    windows: windowScan(days, { range, now }),
    // Das Signatur-Bord: welche Transaktions-Formen im Netz auffallen und wie stark sie mit
    // Validator-Ausfaellen verknuepft sind (Netz-Sicht, nicht Validator-Sicht).
    signatures: signatureBoard(days, { range, now, risk }),
    // Netz-Kurve: ab welcher Last der Durchschnitt der dUNL-Knoten zu fallen beginnt. Ohne
    // diesen Vergleich waere die Kurve eines einzelnen Knotens eine Zahl ohne Bedeutung.
    load: loadResponseCurve(days, { range, now }),
  };
}
