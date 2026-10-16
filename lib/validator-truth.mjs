// lib/validator-truth.mjs — Ground-Truth-Gegenprobe je Validator (rein, ohne I/O).
//
// WELCHES PROBLEM DIESE EBENE LOEST:
// Der Rekorder ist ein Mithoerer. Wenn er in einem Ledger zu wenige Validierungen empfaengt,
// fehlt ihm die Stimme jedes einzelnen dUNL-Knoten - und dieser Mangel wird in der Erfassung als
// 'kein Vote erfasst' je Knoten sichtbar. Auf einem bewiesen geschlossenen Ledger kann das Netz
// sein Quorum trotzdem erreicht haben: die eigene duenne Erfassung ist dann kein Beweis ueber
// die Knoten. Genau diese Verwechslung hat die Akkuratz-Pruefung am 2026-10-16 gezeigt: fuer
// xrp.vet fuehrt die Erfassung Abwesenheiten, waehrend die Netz-Referenz denselben Knoten im
// selben Fenster als fehlerfrei ausweist.
//
// DIE GEGENPROBE IST ARITHMETIK, KEINE DEUTUNG:
// Die Netz-Referenz nennt je Knoten die Zahl der Ledger, die dieser Knoten in einem Fenster
// wirklich nicht validiert hat ('missed' von 'total'). Die eigene Erfassung nennt die Zahl der
// Abwesenheiten, die dieser Rekorder fuer denselben Knoten im selben Fenster notiert. Steht mehr
// in der eigenen Erfassung als in der Referenz, ist die Differenz ein Beweis dafuer, dass
// mindestens so viele der eigenen Abwesenheiten auf die eigene Erfassung zurueckgehen - nicht
// auf den Knoten. Das ist eine nachrechenbare Untergrenze, keine Schaetzung.
//
// WAS DIESE EBENE NICHT KANN:
// Die Referenz ist eine Fenster-Aggregatzahl, keine Liste je Ledger. Sie beweist also die
// ANZAHL der widerlegten Behauptungen, nicht WELCHE einzelne Ledger gemeint sind. Welche Ledger
// es sind, bleibt eine eigene offene Frage und wird als solche ausgeliefert ('ledgerIdentity').
// Eine Referenz ohne Zahl, ein unvollstaendiges Fenster oder ein Fenster, das die eigenen
// Zeitstempel nicht abdeckt, fuehrt zu 'not-comparable' - niemals zu einer Entlastung.
import { measured } from "./validator-trace.mjs";

export const TRUTH_VERDICTS = new Set(["consistent", "contradicted", "not-comparable"]);
export const TRUTH_WINDOWS = { 1: 1, 24: 24, 30: 720 };

const HOUR_MS = 3600000;

// Die Abwesenheits-Zaehler der eigenen Erfassung. 'noQuorum' und 'missed' sind beide
// Abwesenheiten im selben Sinn: fuer diesen Knoten wurde in diesem Ledger keine Validierung
// auf dem angenommenen Hash gesehen. 'partial' und 'wrong-hash' sind keine Abwesenheiten -
// dort wurde eine Validierung gesehen, nur eine andere.
export const ABSENCE_TYPES = new Set(["missed", "no-quorum"]);

export function absencesOf(incidents, master) {
  const out = [];
  for (const i of Array.isArray(incidents) ? incidents : []) {
    if (!i || i.master !== master && i.m !== master) continue;
    const type = i.type;
    if (!ABSENCE_TYPES.has(type)) continue;
    const t = measured(i.timeMs ?? i.t);
    out.push({ master, ledgerIndex: measured(i.ledgerIndex ?? i.l), timeMs: t, type });
  }
  return out;
}

// Die Referenz ist ein rollendes Fenster ab dem Zeitpunkt ihrer Auskunft. Ohne diesen Zeitpunkt
// ist die Fensterzuordnung nicht moeglich - dann wird nicht verglichen, sondern ausgewiesen.
export function groundWindow(scan, hours) {
  const h = TRUTH_WINDOWS[hours];
  const asOf = measured(scan?.asOfMs);
  if (!Number.isFinite(h) || !Number.isFinite(asOf)) return null;
  return { from: asOf - h * HOUR_MS, to: asOf, hours: h };
}

// Ein Fenster der eigenen Auswahl wird nur dann mit der Referenz verglichen, wenn die Referenz
// denselben Zeitraum abdeckt. Laenger als die Referenz darf das eigene Fenster nie sein: sonst
// vergleicht man eine Tageszahl mit einer Stunden-Zahl und die Differenz ist ein Artefakt der
// Fenster, nicht der Erfassung.
export function comparableWindow({ rangeHours, window }) {
  if (!window) return null;
  const own = Number.isFinite(rangeHours) ? Math.min(rangeHours, window.hours) : window.hours;
  return { from: Math.max(window.from, window.to - own * HOUR_MS), to: window.to, hours: own };
}

export function inWindow(claims, window) {
  if (!window) return [];
  return (Array.isArray(claims) ? claims : []).filter((c) => {
    const t = measured(c?.timeMs);
    return Number.isFinite(t) && t >= window.from && t <= window.to;
  });
}

// Die Schliess-Grenze ist die zweite, vom Netz-Stream selbst kommende Schranke: auf einem
// geschlossenen Ledger mit 'members' beobachteten dUNL-Knoten und 'needed' als Quorum-Ziel
// koennen hoechstens members - needed dieser Knoten echt gefehlt haben. Alles darueber ist
// Erfassung dieses Recorders. Diese Grenze braucht keine externe Referenz.
export function closureBound({ members, needed }) {
  const m = measured(members), n = measured(needed);
  if (!Number.isFinite(m) || !Number.isFinite(n) || m <= 0 || n <= 0) return null;
  return { members: m, needed: n, genuineAbsentMax: Math.max(0, m - n) };
}

// Die Netzauskunft kennt drei Fenster: 1 h, 24 h, 30 d. Die eigene Frage darf nur mit einem
// Fenster beantwortet werden, das sie abdeckt - die 30-Tage-Frage braucht das 30-Tage-Fenster,
// die Stunden-Frage nicht das Tagesfenster. Ein groesseres Referenzfenster als noetig macht die
// Gegenprobe nur milder, nie schaerfer; deshalb wird das kleinste Fenster gewaehlt, das die
// eigene Spanne deckt. Eine Spanne ohne Ende (range=all) nimmt das groesste.
//
// Zurueckkommt der Schluessel von TRUTH_WINDOWS (1 / 24 / 30), nicht die Stundenzahl dahinter
// (1 / 24 / 720). groundWindow rechnet nach diesem Schluessel; eine Stundenzahl an dieser Stelle
// waehlt kein Fenster, sondern macht die Gegenprobe blind - und eine 30-Tage-Erfassung gegen
// eine Tages-Referenzzahl zu stellen waere ein erfundener Widerspruch.
export function referenceWindow(rangeHours) {
  const keys = Object.keys(TRUTH_WINDOWS).map(Number).sort((a, b) => TRUTH_WINDOWS[a] - TRUTH_WINDOWS[b]);
  const own = measured(rangeHours);
  if (!Number.isFinite(own) || own <= 0) return keys[keys.length - 1];
  for (const k of keys) if (TRUTH_WINDOWS[k] >= own) return k;
  return keys[keys.length - 1];
}

// Die Auskunft kommt je Knoten mit mehreren Fenstern. Eine Fenster-Karte wird auf das gewaehlte
// Fenster reduziert. Eine flache Eingabe ist das Tagesfenster (24) und wird nur fuer dieses
// akzeptiert: eine Tageszahl einem 30-Tage-Fenster zu unterschieben waere ein Widerspruch, den
// keine Auskunft hergibt. Kein Fenster ist ein eigener Zustand, nicht eine Nullzahl.
export function groundScan(entry, windowId) {
  if (!entry) return null;
  const w = entry.windows ? entry.windows[windowId] : (windowId === 24 ? entry : null);
  if (!w) return null;
  return {
    missed: measured(w.missed), total: measured(w.total), score: w.score ?? null,
    incomplete: w.incomplete === true, asOfMs: measured(entry.asOfMs ?? w.asOfMs),
  };
}

export function groundWindows(map, windowId) {
  if (!map) return null;
  const entries = map instanceof Map ? [...map.entries()] : Object.entries(map);
  const out = new Map();
  for (const [key, entry] of entries) {
    const scan = groundScan(entry, windowId);
    if (scan) out.set(key, scan);
  }
  return out;
}

// Die Gegenprobe selbst. 'claims' ist die eigene Erfassung, 'scan' die Netz-Referenz.
export function compareAbsences({ master, claims, scan, rangeHours = 24, hours = 24 }) {
  const window = groundWindow(scan, hours);
  const own = inWindow(claims, comparableWindow({ rangeHours, window }));
  const groundMissed = measured(scan?.missed);
  const groundTotal = measured(scan?.total);
  const base = {
    master,
    claims: own.length,
    claimsOutside: (Array.isArray(claims) ? claims.length : 0) - own.length,
    groundMissed,
    groundTotal,
    groundScore: scan?.score ?? null,
    groundIncomplete: scan?.incomplete === true,
    window,
    ledgerIdentity: "not-resolvable-from-aggregate",
  };
  if (!window || groundMissed === null || groundTotal === null || groundTotal <= 0 || base.groundIncomplete) {
    return { ...base, verdict: "not-comparable", falsePositiveMin: null,
      reason: window === null ? "reference-has-no-window-time"
        : base.groundIncomplete ? "reference-window-incomplete"
          : "reference-has-no-count" };
  }
  if (own.length === 0) {
    return { ...base, verdict: "consistent", falsePositiveMin: 0, reason: "no-absence-recorded-in-window" };
  }
  if (own.length > groundMissed) {
    return { ...base, verdict: "contradicted", falsePositiveMin: own.length - groundMissed,
      reason: groundMissed === 0 ? "reference-says-this-node-missed-nothing-in-window"
        : "own-absences-exceed-reference-misses" };
  }
  return { ...base, verdict: "consistent", falsePositiveMin: 0, reason: "within-reference-count" };
}

// Eine Kohorten-Zeile nennt Knoten, nicht Zahlen: dieselbe Gegenprobe muss je Knoten stehen,
// weil die Referenz je Knoten eine andere Zahl nennt. 'incidents' ist die rohe Vorfallsliste
// aller geladenen Tage (Rekorder-Erfassung, nicht Netz). Gruppiert wird in einem Durchlauf -
// eine Kohorte von 35 Knoten darf nicht 35 Mal durch die ganze Historie laufen.
export function groupAbsences(incidents) {
  const out = new Map();
  for (const i of Array.isArray(incidents) ? incidents : []) {
    const m = i?.master ?? i?.m;
    if (!m || !ABSENCE_TYPES.has(i.type)) continue;
    const t = measured(i.timeMs ?? i.t);
    if (!Number.isFinite(t)) continue;
    const list = out.get(m) ?? [];
    list.push({ master: m, ledgerIndex: measured(i.ledgerIndex ?? i.l), timeMs: t, type: i.type });
    out.set(m, list);
  }
  return out;
}

// Ein Knoten, dessen eigene Abwesenheiten ausserhalb des Referenzfensters liegen, ist weder
// gedeckt noch widerlegt: er ist offen. 'consistent' mit claims = 0 waer an dieser Stelle ein
// Freispruch, den die Fensterlage nicht hergibt - deshalb wird er hier umgebogen.
export function cohortVerdict(truth) {
  if (!truth) return { verdict: "not-comparable", reason: "reference-unavailable" };
  if (truth.claims === 0 && truth.claimsOutside > 0) return { verdict: "not-comparable", reason: "claims-outside-reference-window" };
  return { verdict: truth.verdict, reason: truth.reason };
}

// Gegenprobe ueber eine ganze Kohorte: jede Zeile nennt die Knoten, die dieser Rekorder in
// diesem Ledger nicht sah. Fuer jeden dieser Knoten wird die eigene Abwesenheits-Zahl gegen
// die Zahl der Netz-Referenz gerechnet. Das Ergebnis haengt an der Zeile (affectedTruth),
// damit 'mehrere Validatoren betroffen' nie ohne die Zahl dasteht, die diese Behauptung traegt
// oder widerlegt. Die Zeilen selbst werden hier nicht veraendert - zurueckkommt eine Zuordnung
// nach Master-Key und eine Bilanz, die nachgerechnet werden kann.
export function cohortTruth({ rows, incidents, groundByMaster, rangeHours = 24, hours = 24 }) {
  const list = Array.isArray(rows) ? rows : [];
  const lookup = groundByMaster instanceof Map
    ? (m) => groundByMaster.get(m) ?? null
    : (m) => (groundByMaster && groundByMaster[m]) || null;
  const peers = new Set();
  for (const r of list) for (const m of r?.affectedMasters ?? []) if (m) peers.add(m);
  const summary = { ledgers: list.length, nodes: peers.size, contradicted: 0, consistent: 0,
    notComparable: 0, withoutReference: 0, claims: 0, claimsOutside: 0, falsePositiveMin: 0 };
  const byMaster = new Map();
  if (!peers.size) return { summary, byMaster };
  const claimsByMaster = groupAbsences(incidents);
  for (const m of peers) {
    const scan = lookup(m);
    const tr = compareAbsences({ master: m, claims: claimsByMaster.get(m) ?? [], scan, rangeHours, hours });
    const v = cohortVerdict(tr);
    byMaster.set(m, { master: m, verdict: v.verdict, reason: v.reason, claims: tr.claims,
      claimsOutside: tr.claimsOutside, groundMissed: tr.groundMissed, groundTotal: tr.groundTotal,
      falsePositiveMin: tr.falsePositiveMin });
    if (v.verdict === "contradicted") summary.contradicted += 1;
    else if (v.verdict === "consistent") summary.consistent += 1;
    else summary.notComparable += 1;
    if (!scan) summary.withoutReference += 1;
    summary.claims += tr.claims;
    summary.claimsOutside += tr.claimsOutside;
    if (Number.isFinite(tr.falsePositiveMin)) summary.falsePositiveMin += tr.falsePositiveMin;
  }
  return { summary, byMaster };
}

// Tageweise Zusammenfassung fuer den Betrieb: wie viele Knoten in einem Fenster widerlegt sind,
// wie viele Behauptungen das trifft, und wie viele Knoten ohne Referenz dastehen. Die letzte
// Zahl ist die Luecke, nicht der Erfolg.
export function summarizeTruth(results) {
  const out = { nodes: 0, contradictedNodes: 0, consistentNodes: 0, notComparableNodes: 0,
    claims: 0, falsePositiveMin: 0, groundMissed: 0, groundTotal: 0 };
  for (const r of Array.isArray(results) ? results : []) {
    if (!r || !TRUTH_VERDICTS.has(r.verdict)) continue;
    out.nodes += 1;
    if (r.verdict === "contradicted") out.contradictedNodes += 1;
    else if (r.verdict === "consistent") out.consistentNodes += 1;
    else out.notComparableNodes += 1;
    out.claims += r.claims ?? 0;
    if (Number.isFinite(r.falsePositiveMin)) out.falsePositiveMin += r.falsePositiveMin;
    if (Number.isFinite(r.groundMissed)) out.groundMissed += r.groundMissed;
    if (Number.isFinite(r.groundTotal)) out.groundTotal += r.groundTotal;
  }
  return out;
}
