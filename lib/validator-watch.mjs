// lib/validator-watch.mjs - Beobachtungsliste: was seit dem letzten Besuch wirklich lief.
//
// Warum diese Datei existiert: ein Betreiber, der seinen Knoten nur selten ansieht, braucht die
// Antwort "seit deinem Besuch am ... hat sich X geaendert". Die Tageszaehler koennen das nicht
// leisten: sie zaehlen den ganzen Tag, und ein Besuch um 14:00 macht aus 300 Tages-Ledern nicht
// "300 seit dem Besuch". Gezaeht wird deshalb ueber die Stunden-Buckets (Zeitmarke je Bucket)
// und ueber die zeitgestempelten Vorfaelle. Drei Aussagen bleiben getrennt:
//   quiet            - das Fenster ist lueckenlos erfasst, und es gab keinen Vorfall
//   partial-coverage - das Fenster ist NICHT lueckenlos erfasst; "kein Vorfall" ist hier keine
//                      Entlastung, sondern eine offene Frage
//   not-evaluated    - ueber diesen Knoten wurde im Fenster nichts bewertet; das ist etwas
//                      anderes als "nichts gefunden"
// Es gibt keine Aufteilung nach Zeitanteil: ein Bucket, das nur teilweise im Fenster liegt, wird
// nicht anteilig zugerechnet, sondern als unbekannt zaehlbar ausgewiesen. Eine Zahl ohne
// Herkunft waere eine Schaetzung, und Schaetzungen ueber Ledger sind genau der Fehler, den dieses
// Werkzeug ausschliessen soll.
import { DAY_HOLE_MS, HOUR_MS, dayFileHoles, daySpanOf, msOf } from "./trace-day-coverage.mjs";

export const WATCH_TYPES = ["missed", "partial", "wrong-hash", "no-quorum"];
export const WATCH_VERDICTS = ["new-incidents", "new-cohort", "quiet", "partial-coverage",
  "not-evaluated", "no-coverage", "bad-entry"];
export const WATCH_DEFAULTS = { maxMasters: 12, maxCohortRows: 8, maxLedgerRows: 12 };

// Die Zaehler-Koernung ist ueberall dieselbe: Tageszaehler und Stunden-Buckets fuehren exakt
// diese fuenf Felder (monitor/validator-trace.mjs, addLedgerRiskSample-Zweig).
const COUNT_KEYS = ["ok", "partial", "missed", "wrongHash", "noQuorum"];
// Vorfalls-Typen in der Tagesdatei auf Tages-Koernung. 'vote-not-observed' ist die Lese-Vokabel
// derselben Tatsache; beide Schreibweisen koennen in einem Bestand stehen.
const TYPE_KEY = { missed: "missed", partial: "partial", "wrong-hash": "wrong-hash", "no-quorum": "no-quorum", "vote-not-observed": "no-quorum" };

const num = (v) => (Number.isFinite(Number(v)) ? Number(v) : 0);

function entryOf(raw) {
  if (!raw || typeof raw !== "object") return null;
  const master = typeof raw.master === "string" ? raw.master.trim() : "";
  const seenAtMs = msOf(raw.seenAtMs);
  if (!master || master.length > 128 || /\s/.test(master)) return null;
  if (seenAtMs === null) return null;
  return { master, seenAtMs };
}

// Die Vorfaelle aller Knoten, einmal je Ledger. Die Kohorte braucht die anderen Knoten desselben
// Ledgers - ohne sie waere "seit dem letzten Besuch" eine Einzelzahl ohne Einordnung.
function incidentLedgers(days) {
  const out = new Map();
  for (const d of days) {
    for (const inc of d.incidents ?? []) {
      const l = msOf(inc.l);
      const t = msOf(inc.t);
      if (l === null || t === null) continue;
      const key = TYPE_KEY[inc.type];
      if (!key) continue;
      // Der gespeicherte Vorfall fuehrt den Knoten unter 'm' (siehe monitor/validator-trace.mjs
      // beim Schreiben der Incident-Zeile). Ueber ein Feld, das in der Datei nicht existiert,
      // waere die Kohorte still leer - und 'leer' sieht aus wie 'keine Kohorte'.
      const master = typeof inc.m === 'string' ? inc.m
        : (typeof inc.master === 'string' ? inc.master : null);
      if (master === null) continue;
      const rec = out.get(l) ?? { ledgerIndex: l, timeMs: t, masters: new Map() };
      const per = rec.masters.get(master) ?? { types: new Set(), attributable: null };
      per.types.add(key);
      // aa am Vorfall ist die Zuordnungs-Grenze. Ein Vorfall ohne Beleg darf die Kohorte nicht
      // belasten, sonst wird aus einer Erfassungs-Luecke eine Mitschuld.
      if (inc.aa === true) per.attributable = true;
      else if (inc.aa === false && per.attributable !== true) per.attributable = false;
      rec.masters.set(master, per);
      if (t < rec.timeMs) rec.timeMs = t;
      out.set(l, rec);
    }
  }
  return out;
}

// Die unbeobachtete Zeit innerhalb des Fensters: Spannen zwischen Tagesdateien und Tage, die das
// Fenster nur teilweise decken. Beides ist eine Aussage ueber die Aufzeichnung.
function windowHoles(spans, holes, w) {
  const inside = holes.filter((h) => h.to > w.from && h.from < w.to);
  const covered = spans.map((s) => ({ from: Math.max(s.start, w.from), to: Math.min(s.end, w.to) }))
    .filter((s) => s.to > s.from)
    .sort((a, b) => a.from - b.from);
  const uncovered = [];
  let cursor = w.from;
  for (const s of covered) {
    if (s.from - cursor > DAY_HOLE_MS) uncovered.push({ from: cursor, to: s.from });
    if (s.to > cursor) cursor = s.to;
  }
  if (w.to - cursor > DAY_HOLE_MS) uncovered.push({ from: cursor, to: w.to });
  return { holes: inside, uncovered };
}

// Ledger und Knoten-Bewertungen aus den Stunden-Buckets. Nur ganze Bucket-Stunden werden
// gezaehlt; eine angeschnittene Stunde bleibt unbekannt und wird als solche ausgewiesen.
function windowBuckets(span, w, master) {
  const day = span.day ?? {};
  const hourly = day.hourly ?? {};
  const keys = Object.keys(hourly);
  let ledgers = 0, evaluated = 0, partial = 0, unknown = 0, live = 0;
  if (!keys.length) {
    // Tag ohne Stunden-Buckets: die Tageszaehler kennen keine Zeit. Ganzer Tag im Fenster ->
    // Tages-Koernung; angeschnittener Tag -> nichts davon ist dem Fenster zuzuordnen.
    const whole = span.start >= w.from && span.end <= w.to;
    const v = day.validators?.[master];
    if (whole && v) {
      for (const k of COUNT_KEYS) evaluated += num(v[k]);
      return { ledgers: num(day.ledgers), evaluated, partial: 0, unknown: 0, live: 0, basis: "day-only" };
    }
    return { ledgers: 0, evaluated: 0, partial: 1, unknown: num(day.ledgers), live: 0, basis: "day-only-open" };
  }
  for (const hk of keys) {
    const h0 = Number(hk) * HOUR_MS;
    const h1 = h0 + HOUR_MS;
    const hb = hourly[hk] ?? {};
    const v = hb.v?.[master];
    if (h0 >= w.from && h1 <= w.to) {
      // Ganze Stunde im Fenster, und die Stunde ist laengstens zu Ende: alles darin liegt
      // wirklich nach dem Besuch.
      ledgers += num(hb.l);
      if (v) for (const k of COUNT_KEYS) evaluated += num(v[k]);
    } else if (h0 >= w.from && h1 > w.to) {
      // Die laufende Stunde: was hier steht, liegt nach dem Besuch, und was noch fehlt,
      // ist nicht versaeumt, sondern ist schlicht noch nicht geschehen. Ein Ausfall IN
      // dieser Stunde waehlt sich als Index-Luecke in 'gaps' selbst aus - deshalb darf die
      // offene Stunde die Deckung nicht brechen.
      ledgers += num(hb.l);
      if (v) for (const k of COUNT_KEYS) evaluated += num(v[k]);
      live += 1;
    } else if (h1 > w.from && h0 < w.from) {
      // Die angeschnittene Stunde: der Besuch liegt mitten drin, und die Bucket-Koernung
      // kennt keine Minuten. Diese Ledger sind weder vor noch nach dem Besuch - sie sind
      // unbekannt, und bleiben es.
      partial += 1;
      unknown += num(hb.l);
    }
  }
  return { ledgers, evaluated, partial, unknown, live, basis: "hourly" };
}

// Eine Zeile ohne Fenster hat dieselbe Form wie eine Zeile mit Fenster. Ein Client, der
// ledgers.measured liest, darf an einer Ablehnung nicht zerbrechen - eine abgelehnte Zeile
// mit fehlenden Feldern sieht sonst im UI aus wie ein Knoten ohne Vorfaelle.
function emptyRow() {
  const counts = {};
  for (const k of WATCH_TYPES) counts[k] = 0;
  return {
    incidents: { ...counts, total: 0 },
    incidentLedgers: 0, cohortLedgers: 0, cohortUnattributed: 0, cohort: [], cohortTruncated: false,
    ledgers: { measured: 0, unknown: 0, partialBuckets: 0, liveBuckets: 0, gapLedgers: 0, gapCount: 0 },
    coverage: { complete: false, dayOnlyOpenDays: 0, holes: [], uncovered: [] },
    firstNewIso: null, lastNewIso: null,
  };
}

// Die Abfrage-Form dieser Zeile: masters=nAAA,nBBB und seen=nAAA:1792225450000,nBBB:1792221000000.
// Ein Eintrag ohne Besuchszeit wird nicht still weggelassen - er steht als Grund da, damit der
// Betreiber sieht, dass sein Knoten NICHT ausgewertet wurde, statt eine leere Liste zu bekommen.
export function watchEntriesFromQuery(query, { defaults = WATCH_DEFAULTS } = {}) {
  const lim = { ...WATCH_DEFAULTS, ...(defaults ?? {}) };
  const q = query ?? {};
  const seen = new Map();
  const rejected = [];
  for (const raw of String(q.seen ?? "").split(",")) {
    const s = raw.trim();
    if (!s) continue;
    const i = s.lastIndexOf(":");
    if (i < 0) { rejected.push({ entry: s, reason: "keine Besuchszeit (erwartet master:millisekunden)" }); continue; }
    const master = s.slice(0, i).trim();
    const rawMs = s.slice(i + 1).trim();
    if (!master) { rejected.push({ entry: s, reason: "kein Knoten vor dem Doppelpunkt" }); continue; }
    if (!rawMs) { rejected.push({ entry: s, reason: "keine Besuchszeit nach dem Doppelpunkt" }); continue; }
    const ms = Number(rawMs);
    if (!Number.isFinite(ms) || ms <= 0) { rejected.push({ entry: s, reason: "die Besuchszeit ist keine Zahl in Millisekunden" }); continue; }
    seen.set(master, ms);
  }
  const wanted = String(q.masters ?? "").split(",").map((s) => s.trim()).filter(Boolean);
  const names = wanted.length ? wanted : [...seen.keys()];
  const entries = [];
  for (const master of names) {
    const seenAtMs = seen.get(master);
    if (seenAtMs === undefined) { rejected.push({ entry: master, reason: "keine Besuchszeit fuer diesen Knoten" }); continue; }
    entries.push({ master, seenAtMs });
  }
  return { entries: entries.slice(0, lim.maxMasters), rejected, truncated: entries.length > lim.maxMasters };
}

// Der billigste Ladebereich, der das aelteste Fenster noch ganz abdeckt. Ein Fenster, das nur
// teilweise geladen waere, waehlt in watchDelta selbst partialBuckets und unknown - die Zahl
// waere dann kleiner, als die Aufzeichnung ist.
export function watchRange(entries, now = Date.now()) {
  let oldest = now;
  for (const e of (Array.isArray(entries) ? entries : [])) {
    const ms = msOf(e?.seenAtMs);
    if (ms !== null && ms < oldest) oldest = ms;
  }
  const age = now - oldest;
  if (age <= HOUR_MS) return "1h";
  if (age <= 24 * HOUR_MS) return "24h";
  if (age <= 7 * 24 * HOUR_MS) return "7d";
  if (age <= 30 * 24 * HOUR_MS) return "30d";
  return "all";
}

export function watchDelta(days, entries, { now = Date.now(), defaults = WATCH_DEFAULTS } = {}) {
  const lim = { ...WATCH_DEFAULTS, ...(defaults ?? {}) };
  const nowMs = Number.isFinite(Number(now)) ? Number(now) : Date.now();
  const list = (Array.isArray(days) ? days : [])
    .filter((d) => d && typeof d.date === "string")
    .map((d) => ({ ...daySpanOf(d), date: d.date, day: d }))
    .sort((a, b) => a.start - b.start);
  const holes = dayFileHoles(list.map((s) => s.day));
  const incidents = incidentLedgers(list.map((s) => s.day));
  const wanted = (Array.isArray(entries) ? entries : []).slice(0, lim.maxMasters);

  const rows = wanted.map((raw) => {
    const entry = entryOf(raw);
    if (!entry) {
      return { ...emptyRow(), verdict: "bad-entry", basis: { reason: "master oder seenAtMs fehlt" } };
    }
    const w = { from: entry.seenAtMs, to: nowMs };
    const base = {
      master: entry.master,
      seenAtMs: entry.seenAtMs,
      seenAtIso: new Date(entry.seenAtMs).toISOString(),
      windowMs: Math.max(0, nowMs - entry.seenAtMs),
    };
    if (w.to <= w.from) {
      return { ...base, ...emptyRow(), verdict: "bad-entry",
        basis: { reason: "der Besuch liegt in der Zukunft" } };
    }
    const spans = list.filter((s) => s.end > w.from && s.start <= w.to);
    if (!spans.length) {
      return { ...base, ...emptyRow(), verdict: "no-coverage",
        basis: { reason: "keine Tagesdatei in diesem Fenster", ledgers: 0 } };
    }

    let ledgers = 0, evaluated = 0, partialBuckets = 0, unknownLedgers = 0, gapLedgers = 0, gapCount = 0;
    let dayOnlyOpen = 0, liveBuckets = 0;
    for (const s of spans) {
      const b = windowBuckets(s, w, entry.master);
      ledgers += b.ledgers;
      evaluated += b.evaluated;
      partialBuckets += b.partial;
      unknownLedgers += b.unknown;
      liveBuckets += b.live;
      if (b.basis === "day-only-open") dayOnlyOpen += 1;
      for (const g of s.day.gaps ?? []) {
        const t = msOf(g.t);
        if (t === null || t <= w.from || t > w.to) continue;
        const from = msOf(g.from), to = msOf(g.to);
        if (from === null || to === null || to < from) continue;
        gapCount += 1;
        gapLedgers += to - from + 1;
      }
    }
    const { holes: windowHolesList, uncovered } = windowHoles(spans, holes, w);

    const mine = [...incidents.values()]
      .filter((rec) => rec.masters.has(entry.master) && rec.timeMs > w.from && rec.timeMs <= w.to)
      .sort((a, b) => a.timeMs - b.timeMs);
    const counts = { missed: 0, partial: 0, "wrong-hash": 0, "no-quorum": 0 };
    const cohort = [];
    let cohortUnattributed = 0;
    for (const rec of mine) {
      const per = rec.masters.get(entry.master);
      for (const t of per.types) counts[t] += 1;
      // Kohorte nur mit Beleg. 'aa' ist an jedem Vorfall selbst die Zuordnungs-Grenze:
      // aa false heisst, dass die Abwesenheit dieses Knoten aus dieser Zeile nicht folgt
      // (Schliess-Widerspruch, Erfassungs-Luecke, fehlendes Ziel). Ein solcher Knoten darf
      // nicht als Mit-Betroffener dastehen - das waere eine Beschuldigung aus einer eigenen
      // Erfassungs-Luecke. Ohne eigenen Beleg bleibt der Ledger eine offene Frage und wird
      // als cohortUnattributed zaehlbar, nicht als Kohorte.
      const others = [...rec.masters.keys()].filter((m) => m !== entry.master
        && rec.masters.get(m)?.attributable === true);
      if (per.attributable === true && others.length) {
        cohort.push({
          ledgerIndex: rec.ledgerIndex, timeMs: rec.timeMs,
          types: [...per.types], othersCount: others.length, others,
          attributable: true,
        });
      } else if (rec.masters.size > 1) {
        cohortUnattributed += 1;
      }
    }
    const total = WATCH_TYPES.reduce((s, k) => s + counts[k], 0);
    const coverageComplete = partialBuckets === 0 && unknownLedgers === 0 && gapCount === 0
      && windowHolesList.length === 0 && uncovered.length === 0 && dayOnlyOpen === 0;

    let verdict;
    if (evaluated === 0) verdict = "not-evaluated";
    else if (total > 0) verdict = cohort.length ? "new-cohort" : "new-incidents";
    else if (coverageComplete) verdict = "quiet";
    else verdict = "partial-coverage";

    return {
      ...base,
      verdict,
      incidents: { ...counts, total },
      incidentLedgers: mine.length,
      cohortLedgers: cohort.length,
      cohortUnattributed,
      cohort: cohort.slice(0, lim.maxCohortRows),
      cohortTruncated: cohort.length > lim.maxCohortRows,
      ledgers: { measured: ledgers, unknown: unknownLedgers, partialBuckets, liveBuckets, gapLedgers, gapCount },
      coverage: {
        complete: coverageComplete,
        dayOnlyOpenDays: dayOnlyOpen,
        holes: windowHolesList.map((h) => ({ fromIso: new Date(h.from).toISOString(), toIso: new Date(h.to).toISOString(), ms: h.ms })),
        uncovered: uncovered.map((u) => ({ fromIso: new Date(u.from).toISOString(), toIso: new Date(u.to).toISOString(), ms: u.to - u.from })),
      },
      firstNewIso: mine.length ? new Date(mine[0].timeMs).toISOString() : null,
      lastNewIso: mine.length ? new Date(mine[mine.length - 1].timeMs).toISOString() : null,
      basis: {
        source: "stunden-buckets + zeitgestempelte vorfaelle",
        evaluatedLedgers: evaluated,
        estimated: 0,
      },
    };
  });

  return {
    now: nowMs,
    entries: rows,
    coverage: {
      days: list.length,
      firstMs: list.length ? list[0].start : null,
      lastMs: list.length ? list[list.length - 1].end : null,
      holes: holes.slice(0, 4),
    },
    limits: { maxMasters: lim.maxMasters, requested: (Array.isArray(entries) ? entries.length : 0) },
  };
}
