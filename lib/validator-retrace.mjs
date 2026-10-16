// lib/validator-retrace.mjs — Retrace-Engine: WARUM ein Validator ein Ledger verpasst hat.
// Rein, ohne I/O. Eingabe: Tagesobjekte aus data/validator-trace (monitor/validator-trace.mjs).
//
// Die Aufzeichnung allein sagt WAS passierte (missed / partial / wrong-hash / no-quorum).
// Diese Ebene beantwortet, unter welchen Bedingungen derselbe Ausfall auftritt — gemessen,
// nicht geraten. Vier unabhängige Blickwinkel:
//   1. Kohorte  — haben andere Validatoren denselben Ledger ebenfalls verfehlt?
//                 Trennt Netzwerk-/Infrastruktur-Ereignis vom eigenen Knotenfehler.
//   2. Quorum   — wie knapp war das Quorum, gab es eine zweite Hash-Linie (Spaltung)?
//   3. Last/Takt — war der Ledger ein Ausreißer (Tx-Last, Close-Abstand)?
//   4. Risiko   — wie oft fällt ein Ledger aus, WENN eine Anomalie vorliegt, im Vergleich
//                 zu Ledgern ohne Anomalie. Ohne diesen Nenner ist jede "Ursache" Anekdote.
//
// Grenzen, ehrlich benannt: alles ist Korrelation im selben Ledger, kein Beweis einer Kausalität.
// Zu kleine Stichproben werden NICHT zu einer Zahl verdichtet (reliable=false + Grund).
// Fehlende Forensik (Tage vor dieser Stufe) wird als Datenlücke ausgewiesen, nie als "kein Grund".
import { measured, TRACE_DEFAULTS, anomalyLayer, captureBound, ledgerClosure } from "./validator-trace.mjs";
import { SIGNATURE_TAGS } from "./tx-forensics.mjs";

export const RETRACE_DEFAULTS = {
  minAnomalyLedgers: 20,   // darunter kein Risikovergleich: zu kleine Stichprobe
  minAnomalyFails: 3,      // darunter kein belastbarer Vergleich
  minPlainLedgers: 50,     // die Vergleichsgruppe muss vorhanden sein
  attackMinValidators: 5,  // gleichzeitige Ausfälle ab hier als Sammelereignis
  topAttacks: 12,
};

const TYPES = ["missed", "partial", "wrongHash", "noQuorum"];
const TYPE_OF = { missed: "missed", partial: "partial", "wrong-hash": "wrongHash", "no-quorum": "noQuorum" };
// Die Kohorten-Ebene braucht diese Trennung: missed/partial/wrong-hash sind einem Knoten
// zurechenbar, no-quorum ist die Beobachtung dieses Recorders auf einem Ledger, dessen
// Schliessung die Forensik traegt. Ohne die Trennung wird eine Erfassungs-Luecke zum
// Mit-Ausfall und die Kohortenzahl zur Beschuldigung von Knoten, die die eigene
// Schliessungs-Rechnung nicht traegt.
const FAULT_TYPES = new Set(["missed", "partial", "wrong-hash"]);
const num = measured;

// Ledger-Index über alle Tage: Vorfälle und Forensik je LedgerIndex.
export function buildLedgerIndex(days) {
  const idx = new Map();
  for (const d of Array.isArray(days) ? days : []) {
    for (const i of d.incidents ?? []) {
      const e = idx.get(i.l) ?? { ledgerIndex: i.l, timeMs: i.t ?? null, incidents: [], stats: null };
      e.incidents.push({ master: i.m, type: i.type, reasons: i.r ?? [], voteDelayMs: num(i.vd) });
      if (!e.timeMs && Number.isFinite(i.t)) e.timeMs = i.t;
      idx.set(i.l, e);
    }
    for (const st of d.ledgerStats ?? []) {
      const e = idx.get(st.l) ?? { ledgerIndex: st.l, timeMs: st.t ?? null, incidents: [], stats: null };
      e.stats = st;
      if (!e.timeMs && Number.isFinite(st.t)) e.timeMs = st.t;
      idx.set(st.l, e);
    }
  }
  return idx;
}

// Risikovergleich je Anomalie: Ausfallwahrscheinlichkeit MIT Anomalie gegen OHNE Anomalie.
// Messbasis sind ausschliesslich Tage, die die Signatur-Ebene fuehren (d.anomaly vorhanden; ein
// leeres Objekt zaehlt, weil es "an diesem Tag wurde nach Anomalien gesehen und keine gefunden"
// bedeutet). Tage aus einer aelteren Recorder-Fassung fuehren weder Anomalie-Zaehler noch
// Forensik: ihre Ledger und ihre Ausfaelle in die Vergleichsgruppe zu mischen, prueft die
// Gruppe gegen sich selbst - jeder Lift ware dann eine Zahl ueber ungepruefte Ledger.
// Die Gesamtzahl aller Tage bleibt als Abdeckung erhalten (coverage.allLedgers), damit die
// Basis nicht groesser wirkt, als sie gemessen ist.
export function riskProfile(days, opts = {}) {
  const p = { ...RETRACE_DEFAULTS, ...opts };
  const anomaly = new Map();
  const basisFailLedgers = new Set();
  const allFailLedgers = new Set();
  let basisLedgers = 0;
  let allLedgers = 0;
  let daysWithStats = 0;
  let truncated = false;
  let daysTotal = 0;
  let daysWithAnomaly = 0;
  let statsLedgers = 0;
  let loadLedgers = 0;
  let anomalyTags = 0;
  for (const d of Array.isArray(days) ? days : []) {
    daysTotal += 1;
    allLedgers += num(d.ledgers) ?? 0;
    for (const i of d.incidents ?? []) allFailLedgers.add(i.l);
    if (Array.isArray(d.ledgerStats)) {
      statsLedgers += d.ledgerStats.length;
      if (d.ledgerStats.length) daysWithStats += 1;
    }
    // Last-Achse: die gezehlten Ledger dieser Ebene, nicht die gefuellten Stufen. Eine
    // Tagesdatei aus einer alten Recorder-Fassung fuellt die Achse nur je Ausfall-Ledger, und
    // dann ist die Summe der Stufen kleiner als die Zahl der Ledger - ohne diese Zahl wirkt die
    // Last-Kurve vollstaendig, obwohl der Nenner fehlt.
    for (const b of d.loadBuckets ?? []) loadLedgers += num(b?.l) ?? 0;
    if (d.ledgerStatsTruncated) truncated = true;
    // Ohne Signatur-Ebene gibt es keinen Nenner je Anomalie - der Tag tragt zu keiner Rate bei,
    // auch nicht zu ihrer Vergleichsgruppe. Das ist eine Luecke, kein Befund ohne Abweichung.
    // Marker ausgewertet, nicht nur die Presence: ein Tag, dessen leere Zaehler erst beim Lesen
    // ergaenzt wurden, fuehrt die Ebene nicht - er war nie geprueft.
    const layer = anomalyLayer(d);
    if (!layer) continue;
    daysWithAnomaly += 1;
    basisLedgers += num(d.ledgers) ?? 0;
    for (const i of d.incidents ?? []) basisFailLedgers.add(i.l);
    for (const [tag, n] of Object.entries(layer)) {
      const e = anomaly.get(tag) ?? { ledgers: 0, failLedgers: 0 };
      e.ledgers += num(n) ?? 0;
      anomaly.set(tag, e);
    }
    for (const [tag, n] of Object.entries(d.anomalyFail ?? {})) {
      const e = anomaly.get(tag) ?? { ledgers: 0, failLedgers: 0 };
      e.failLedgers += num(n) ?? 0;
      anomaly.set(tag, e);
    }
    anomalyTags = Math.max(anomalyTags, anomaly.size);
  }
  const failTotal = basisFailLedgers.size;
  const allFailTotal = allFailLedgers.size;
  const rows = [];
  for (const [tag, e] of anomaly) {
    const plainLedgers = Math.max(0, basisLedgers - e.ledgers);
    const plainFails = Math.max(0, failTotal - e.failLedgers);
    const rateWith = e.ledgers > 0 ? e.failLedgers / e.ledgers : null;
    const rateWithout = plainLedgers > 0 ? plainFails / plainLedgers : null;
    const lift = rateWith !== null && rateWithout ? rateWith / rateWithout : null;
    const reliable = e.ledgers >= p.minAnomalyLedgers && e.failLedgers >= p.minAnomalyFails && plainLedgers >= p.minPlainLedgers;
    rows.push({
      tag,
      anomalyLedgers: e.ledgers,
      anomalyFailLedgers: e.failLedgers,
      plainLedgers,
      plainFailLedgers: plainFails,
      rateWith,
      rateWithout,
      lift,
      reliable,
      note: reliable ? null : "sample-too-small",
    });
  }
  rows.sort((a, b) => (Number(b.reliable) - Number(a.reliable)) || ((b.lift ?? 0) - (a.lift ?? 0)) || a.tag.localeCompare(b.tag));
  return {
    totalLedgers: basisLedgers, incidentLedgers: failTotal, rows, daysWithStats, statsTruncated: truncated,
    // Abdeckung, nicht Urteil: ohne diese Zahlen wirkt ein Lift belastbar, obwohl ein Teil der
    // Ledger gar keine Forensik hat. Fehlend ist hier nicht 'kein Effekt'.
    coverage: {
      daysTotal,
      daysWithAnomaly,
      daysWithoutAnomaly: Math.max(0, daysTotal - daysWithAnomaly),
      daysWithStats,
      daysWithoutForensics: Math.max(0, daysTotal - daysWithStats),
      statsLedgers,
      // Forensik- und Last-Abdeckung beziehen sich auf die gesamte Aufzeichnung, nicht auf die
      // Risikobasis: ihr Nenner ist deshalb die Zahl aller Ausfall-Ledger bzw. aller Ledger.
      allLedgers,
      allIncidentLedgers: allFailTotal,
      forensicsShare: allFailTotal > 0 ? Math.min(1, statsLedgers / allFailTotal) : null,
      loadLedgers,
      // Ohne gefuehrte Last-Achse ist der Anteil nicht beantwortbar: 0 waere die Aussage
      // "keiner dieser Ledger liegt in der Achse", und die hat niemand gemessen.
      loadShare: allLedgers > 0 && loadLedgers > 0 ? Math.min(1, loadLedgers / allLedgers) : null,
      anomalyTags,
    },
  };
}

// Passender Risikowert für ein Tag (exakt, sonst Präfix wie new-tx-type).
export function liftFor(tag, risk) {
  if (!tag || !risk || !Array.isArray(risk.rows)) return null;
  const exact = risk.rows.find((r) => r.tag === tag);
  if (exact) return exact;
  const base = String(tag).split(":")[0];
  return risk.rows.find((r) => r.tag === base) ?? null;
}

function countsOf(entry) {
  const c = { missed: 0, partial: 0, wrongHash: 0, noQuorum: 0 };
  for (const i of entry.incidents) if (c[TYPE_OF[i.type]] !== undefined) c[TYPE_OF[i.type]] += 1;
  return c;
}

// Ein Vorfall, ein Ledger, eine Diagnose.
// strength: measured (direkte Ledger-Messung) > cohort (Betroffenheit anderer Validatoren) >
//           correlated (Ledger-Kontext) > none (Einordnung ohne Ursachen-Beleg).
// Solo ist eine Einordnung, kein Kohorten-Befund: ein Vorfall ohne andere Betroffene darf
// nicht auf derselben Stufe stehen wie die Messung, dass mehrere Validatoren gleichzeitig fielen.
export function retraceIncident(entry, incident, risk) {
  const st = entry.stats ?? null;
  const counts = countsOf(entry);
  const others = entry.incidents.filter((i) => i.master !== incident.master).length;
  // Die anderen Betroffenen namentlich: "6 Validatoren betroffen" ist eine Zahl, erst die Keys
  // machen eine nachvollziehbare Spur - gemeinsame Infrastruktur, gemeinsamer Anbieter, oder
  // dieselben Knoten, die immer zusammen fallen. Sortiert, damit zwei Aufrufe dieselbe Liste
  // liefern. Der eigene Key ist ausgeschlossen: er steht schon als master der Diagnose.
  const peerMasters = [...new Set(entry.incidents.filter((i) => i.master !== incident.master).map((i) => i.master))].sort();
  // Dasselbe Problem, nicht nur derselbe Ledger: die Knoten, die auf diesem Ledger denselben
  // Vorfallstyp hatten, sind die eigentliche Vergleichsgruppe - dieselbe Version, derselbe
  // Anbieter, dieselbe Infrastruktur. Knoten mit einer anderen Abweichung auf demselben Ledger
  // gehoeren nicht in diese Gruppe und bleiben getrennt benannt.
  const sameTypeMasters = [...new Set(entry.incidents.filter((i) => i.master !== incident.master && i.type === incident.type).map((i) => i.master))].sort();
  const otherTypeMasters = [...new Set(entry.incidents.filter((i) => i.master !== incident.master && i.type !== incident.type).map((i) => i.master))].sort();
  const type = incident.type;

  // Kohorte heisst: andere Knoten haben auf demselben Ledger abweichend teilgenommen. Ob
  // darin ein zweiter Knoten-Ausfall steht, entscheidet der Vorfallstyp - nicht die Zahl der
  // Eintraege. no-quorum ist die Beobachtung dieses Recorders (Schliess-Ebene und Gegenprobe
  // begrenzen sie), also traegt nur faultOthers die Kohorten-Aussage. Sind alle anderen
  // ausschliesslich unerfasst, ist der Scope capture-cohort: mehrere Knoten ohne gesehenen
  // Vote, aber kein zweiter Ausfall. Unbekannte Typen bleiben bei cohort - sie werden nicht
  // entlastet, nur weil sie hier nicht zuordenbar sind.
  const othersAll = entry.incidents.filter((i) => i.master !== incident.master);
  const faultOthers = othersAll.filter((i) => FAULT_TYPES.has(i.type)).length;
  const captureOthers = othersAll.filter((i) => i.type === "no-quorum").length;
  const captureOnlyMasters = [...new Set(othersAll.filter((i) => i.type === "no-quorum").map((i) => i.master))]
    .filter((m) => !othersAll.some((i) => i.master === m && FAULT_TYPES.has(i.type)))
    .sort();

  let scope = "unknown";
  if (type === "no-quorum") scope = "network";
  else if (faultOthers > 0) scope = "cohort";
  else if (others === 0) scope = "solo";
  else if (captureOthers === others) scope = "capture-cohort";
  else scope = "cohort";

  // Schliess-Ebene dieses Ledgers: der Recorder wertet nur Ledger aus dem validierten Stream aus,
  // also ist die Schliessung belegt, solange sie nicht ausdruecklich verneint wird. ch ist der
  // Hash, an dem jede Aussage nachpruefbar ist.
  const closure = st ? ledgerClosure(st) : null;
  // Die Grenze, die aus der Schliessung folgt: auf einem geschlossenen Ledger kann hoechstens
  // (dUNL - Quorum-Ziel) der als 'kein Vote erfasst' gefuehrten Knoten echt gefehlt haben;
  // alles darueber ist nachweisbar Erfassungs-Luecke dieses Recorders. Die Zahl kommt aus den
  // aufgezeichneten Werten dieses Ledgers, nicht aus einer Schaetzung.
  const capture = st ? captureBound(st) : null;
  const quorum = st
    ? {
      votes: st.v, needed: st.need, topVotes: st.top, margin: st.mg, runnerVotes: st.sp,
      closure, captureGap: closure ? (closure.captureGap ?? null) : null,
      observedValidations: Number.isFinite(st.ov) ? st.ov : null,
    }
    : null;
  const load = st ? { txCount: st.tx, medianTx: st.med, ratio: st.med > 0 ? st.tx / st.med : null } : null;
  const closeGapMs = st && Number.isFinite(st.gap) ? st.gap : null;

  const hypotheses = [];
  const add = (tag, strength, evidence) => hypotheses.push({ tag, strength, evidence, lift: liftFor(tag, risk) });

  // 'quorum-thin' behauptet ein knappes Netz-Quorum. Das darf nur stehen, wenn die Schliess-Ebene
  // die Schliessung verneint: ein geschlossener Ledger beweist, dass das Netz sein Quorum erreicht
  // hat, und eine Marge unter null beschreibt dann ausschliesslich die eigene Beobachtung.
  if (quorum && quorum.needed > 0 && quorum.margin < TRACE_DEFAULTS.thinMarginMax && closure && !closure.closed) {
    add("quorum-thin", "measured", { topVotes: quorum.topVotes, needed: quorum.needed, margin: quorum.margin });
  }
  // Was anstelle davon gemessen ist: wie viele Stimmen der beobachteten dUNL dieser Rekorder in
  // einem bewiesen geschlossenen Ledger sah. Erfassungs-Aussage mit Zahl und Schliess-Hash.
  if (quorum && closure && closure.closed && quorum.needed > 0 && quorum.topVotes < quorum.needed) {
    add("vote-coverage-thin", "measured", {
      topVotes: quorum.topVotes, needed: quorum.needed, observedValidations: quorum.observedValidations,
      closedHash: closure.hash ?? null,
      // Erfassungs-Luecke ist dreiwertig: gemessen vorhanden (true), gemessen ausgeschlossen
      // (false), nicht aufgezeichnet (null). Aus null ein false zu machen behauptet, eine Luecke
      // sei ausgeschlossen, wo dieser Rekorder dafuer nichts aufgezeichnet hat - eine erfundene
      // Entlastung. Der Bestand vor 'pg' ist genau dieser Fall.
      captureGap: quorum.captureGap ?? null,
      // Die Grenze zur Zahl: '16 von 28 gesehen' ist erst mit der Aussage vollstaendig, wie
      // viele der nicht gesehenen Knoten auf einem geschlossenen Ledger echt fehlen koennen.
      absentCount: capture?.absentCount ?? null,
      genuineAbsentMax: capture?.genuineAbsentMax ?? null,
      captureArtifactMin: capture?.captureArtifactMin ?? null,
    });
  }
  if (quorum && quorum.runnerVotes >= TRACE_DEFAULTS.splitMinVotes) {
    add("hash-split", "measured", { runnerVotes: quorum.runnerVotes, votes: quorum.votes });
  }
  if (load && load.txCount >= TRACE_DEFAULTS.spikeMinTx && load.medianTx > 0 && load.ratio >= TRACE_DEFAULTS.spikeRatio) {
    add(load.ratio >= TRACE_DEFAULTS.extremeRatio ? "load-extreme" : "load-spike", "measured", { txCount: load.txCount, medianTx: load.medianTx, ratio: Math.round(load.ratio * 10) / 10 });
  }
  const medianGapMs = st && Number.isFinite(st.gmed) ? st.gmed : null;
  // Index-Folge dieses Recorders in drei Zustaenden: 'true' nachweislich durchgehend, 'false'
  // nachweislich gesprungen, null nicht erfasst (Bestand ohne 'pg'). close-gap behauptet eine
  // verlangsamte Netz-Taktung und faellt weg, sobald die eigene Luecke den Abstand erklaert.
  const indexContinuity = closure ? (closure.captureGap === null ? null : !closure.captureGap) : null;
  if (closeGapMs !== null && medianGapMs !== null && medianGapMs > 0 && indexContinuity !== false
    && closeGapMs >= TRACE_DEFAULTS.gapMinMs && closeGapMs >= TRACE_DEFAULTS.gapRatio * medianGapMs) {
    add("close-gap", "measured", { closeGapMs, medianGapMs, indexContinuity });
  }
  // Spaet-Validierung: der Vote ist in diesem Ledger eingetroffen und seine Latenz ist gemessen.
  // Das ist keine Korrelation aus dem Kontext, sondern die direkte Antwort auf die Frage, warum
  // dieser Ledger als missed steht - der Knoten hat abgestimmt, nur nach der Bewertung. Sie muss
  // VOR den Grund-Tags stehen: 'vote-late' liegt im Incident als Reason, und der allgemeine
  // Reason-Durchlauf wuerde sonst 'correlated' eintragen und die Messung nachher blockieren.
  const voteDelayMs = Number.isFinite(incident.voteDelayMs) ? incident.voteDelayMs : null;
  if (voteDelayMs !== null && (incident.reasons ?? []).includes("vote-late")) {
    add("vote-late", "measured", { voteDelayMs, graceMs: TRACE_DEFAULTS.graceMs });
  }
  // Netzweite Vorfälle sind die stärkste Kohorten-Aussage, die diese Ebene liefern kann:
  // hier fiel die ganze dUNL-Gruppe auf demselben Ledger. Die Messung nur als Etikett
  // "netzweit" zu zeigen und sie samt Knotenliste aus den Hypothesen zu streichen, ließ
  // die Karte "keine Korrelation in diesem Ledger" sagen, obwohl 19 andere Knoten
  // nachweisbar auf demselben Ledger fielen. affectedValidators zählt alle
  // Abweichungsarten: ohne noQuorum standen auf denselben Karten "0 Validatoren
  // betroffen" neben "19 andere" - zwei Zahlen für dasselbe Ereignis, die einander
  // widersprechen.
  if ((scope === "cohort" || scope === "network" || scope === "capture-cohort") && others > 0) {
    add("cohort-event", "cohort", {
      affectedValidators: counts.missed + counts.partial + counts.wrongHash + counts.noQuorum,
      others,
      // Dieselbe Zahl aufgeteilt: wie viele der anderen eine zurechenbare Abweichung hatten
      // und wie viele nur ohne gesehenen Vote erfasst sind. Ohne die Aufteilung vermischt
      // "19 andere" Ausfall und Erfassungs-Luecke.
      faultOthers,
      captureOthers,
      captureOnlyMasters,
      peerMasters,
      sameTypeMasters,
      sameType: sameTypeMasters.length,
      // Die Kohorte ist eine Zahl ueber die Erfassung dieses Recorders, nicht ueber die
      // Netzteilnahme. Auf einem geschlossenen Ledger beweist die Schliessung das Netz-Quorum,
      // und die Grenze sagt, wie viele der als fehlend gefuehrten Knoten ueberhaupt echt fehlen
      // koennen. Ohne sie steht "19 betroffen" als Beschuldigung von 19 Knoten da, die die
      // eigene Schliessungs-Rechnung nicht traegt.
      closedHash: closure && closure.closed === true ? (closure.hash ?? null) : null,
      genuineAbsentMax: capture ? (capture.genuineAbsentMax ?? null) : null,
      captureArtifactMin: capture ? (capture.captureArtifactMin ?? null) : null,
    });
  }
  if (scope === "solo") add("solo-failure", "none", { others: 0 });

  // Transaktions-Signaturen sind eine direkte Messung DIESSES Ledgers (die Form seiner
  // Transaktionen), keine Vermutung aus dem Kontext. st.sev enthaelt genau den Beleg, mit dem
  // die Signatur in diesem Ledger feuerte - deshalb measured statt correlated. Ohne st.sev
  // (Tage vor dieser Stufe) bleibt das Tag correlated stehen: es wurde am Incident gespeichert,
  // aber der Messwert selbst ist verloren.
  const sev = (st && st.sev) || {};
  for (const tag of incident.reasons ?? []) {
    if (["no-correlated-cause", "partial-validation", "signed-different-hash", "no-quorum"].includes(tag)) continue;
    // Bereits gemessen: der Reason-Durchlauf darf eine Messung nicht zu einer Korrelation
    // herunterstufen (und ohne Messwert bleibt er hier als correlated erhalten - ehrlich).
    if (tag === "vote-late" && voteDelayMs !== null) continue;
    if (hypotheses.some((h) => h.tag === tag)) continue;
    const hasMeasurement = (SIGNATURE_TAGS.has(tag) || String(tag).startsWith("type-burst:")) && sev[tag];
    add(tag, hasMeasurement ? "measured" : "correlated", hasMeasurement ? sev[tag] : {});
  }
  // Sweep entsteht ueber ein Ledger-Fenster, nicht in einem einzelnen Ledger: der Beleg liegt
  // in st.sweep und war bisher nirgends sichtbar.
  if (st && st.sweep && !hypotheses.some((h) => h.tag === "sweep-window")) add("sweep-window", "measured", st.sweep);

  // Solo/Kohorte ist eine Einordnung, keine Ursache. Wenn außer dieser Einordnung nichts
  // Gemessene oder Korrelierte steht, muss das ausdrücklich da sein — sonst entsteht der
  // Eindruck, die Ursache sei gefunden, wo nur die Kategorie gefunden ist.
  if (!hypotheses.some((h) => h.strength === "measured" || h.strength === "correlated")) add("no-correlated-cause", "none", {});

  const dataGaps = [];
  if (!st) dataGaps.push("forensics-not-recorded");
  else if (!st.sh) dataGaps.push("tx-shape-not-recorded");
  if (risk && risk.statsTruncated) dataGaps.push("forensics-truncated");
  // Ohne Spaet-Validierungs-Aufzeichnung ist "kein Vote" nicht von "Vote ausserhalb des Rings"
  // zu trennen. Diese Lücke gehört an die Diagnose, nicht in eine Fussnote des UI.
  if (type === "missed" && voteDelayMs === null) dataGaps.push("late-vote-window");

  return {
    ledgerIndex: incident.ledgerIndex,
    timeMs: entry.timeMs ?? incident.timeMs ?? null,
    type,
    scope,
    affected: { ...counts, others, faultOthers, captureOthers, captureOnlyMasters, peerMasters, sameTypeMasters, otherTypeMasters },
    quorum,
    closure,
    capture,
    load,
    closeGapMs,
    voteDelayMs,
    txShape: st ? { recorded: Boolean(st.sh), form: st.sh ?? null, sweep: st.sweep ?? null } : null,
    hypotheses,
    guidance: guidanceFor(type, scope, hypotheses, closure),
    dataGaps,
  };
}

// Was ein Validator-Betreiber als Nächstes prüfen sollte — maschinelle Tags, übersetzt per i18n.
function guidanceFor(type, scope, hypotheses, closure) {
  const tags = new Set();
  const has = (t) => hypotheses.some((h) => h.tag === t);
  const hasPrefix = (pre) => hypotheses.some((h) => String(h.tag).startsWith(pre));
  const explained = hypotheses.some((h) => h.strength === "measured" || h.strength === "correlated");
  // Akkuratz-Regel (2026-10-16): Netzstockung ist nur dort eine naheliegende Pruefung, wo ein
  // Beleg dafuer steht - die ausdrucklich verneinte Schliessung dieses Ledgers. Ein bewiesen
  // geschlossener Ledger hat sein Netz-Quorum erreicht, und "Schliessung nicht erfasst" ist ein
  // Datenluecke, kein Verdacht. In beiden anderen Faellen ist die naechste Pruefung die eigene
  // Erfassung: dieser Rekorder hat zu wenige Validierungen gehoert.
  const stallBasis = closure?.closed === false;
  if (scope === "network") tags.add(stallBasis ? "network-stall" : "capture-window");
  if (scope === "cohort") tags.add("cohort-network");
  // Eine Kohorte aus lauter unerfassten Knoten ist kein Netzereignis: die naechste Pruefung
  // ist die eigene Erfassung, nicht der Vergleich mit Knoten, deren Abwesenheit die Referenz
  // widerlegt.
  if (scope === "capture-cohort") tags.add("capture-window");
  if (scope === "solo") { tags.add("solo-peering"); tags.add("solo-resources"); }
  if (type === "wrong-hash") tags.add("version-state");
  if (has("hash-split")) tags.add("report-split");
  if (has("load-spike") || has("load-extreme")) tags.add("load-backlog");
  // Netzstockung nur bei nachweislich durchgehender Index-Folge: ein Abstand zwischen
  // aufeinanderfolgenden Ledgern ist ein Netz-Befund, ein Abstand ueber eine eigene Index-Luecke
  // ist ein Befund ueber den eigenen Stream. Ohne Beleg (Bestand ohne 'pg') bleibt die naechste
  // Pruefung die eigene Erfassung, sie wird nicht durch den Close-Abstand ersetzt.
  const gapHyp = hypotheses.find((h) => h.tag === "close-gap") ?? null;
  if (gapHyp && gapHyp.evidence?.indexContinuity === true) tags.add("network-stall");
  if (has("amendment-activity")) tags.add("version-state");
  if (has("unl-change")) tags.add("unl-membership");
  if (has("new-tx-type")) tags.add("parser-version");
  if (has("quorum-thin")) tags.add("quorum-margin");
  // Transaktions-Signatur im selben Ledger: die naechste Pruefung ist keine Infrastruktur-Pruefung
  // mehr, sondern eine Pruefung dessen, was in diesem Ledger passiert ist.
  if (has("drainer-fanout") || has("sweep-window")) tags.add("attack-drainer");
  if (has("sender-burst")) tags.add("attack-burst");
  if (has("offer-flood") || has("nft-spam") || has("account-create-burst")) tags.add("attack-spam");
  if (has("failure-spike")) tags.add("attack-failed-tx");
  if (has("batch-amplify")) tags.add("attack-amplify");
  if (has("fee-spike")) tags.add("attack-fee");
  if (has("feature-change")) tags.add("version-state");
  if (hasPrefix("type-burst:")) tags.add("attack-type-burst");
  if (has("vote-late")) tags.add("late-signing-path");
  if (!explained) tags.add("unknown-cause");
  return [...tags];
}

// Retrace für einen Validator: Diagnose je Vorfall, neueste zuerst.
export function retraceForValidator(days, master, { range = "24h", now = Date.now(), risk = null } = {}) {
  const idx = buildLedgerIndex(days);
  const profile = risk ?? riskProfile(days);
  const span = { "1h": 3600000, "24h": 86400000, "7d": 7 * 86400000, "30d": 30 * 86400000, all: Infinity }[range] ?? 86400000;
  const from = span === Infinity ? 0 : now - span;
  const out = [];
  for (const [ledgerIndex, entry] of idx) {
    for (const inc of entry.incidents) {
      if (inc.master !== master) continue;
      const timeMs = entry.timeMs ?? null;
      if (timeMs !== null && (timeMs < from || timeMs > now + 1)) continue;
      out.push(retraceIncident(entry, { master, type: inc.type, reasons: inc.reasons, ledgerIndex, timeMs, voteDelayMs: inc.voteDelayMs ?? null }, profile));
    }
  }
  out.sort((a, b) => (b.timeMs ?? 0) - (a.timeMs ?? 0));
  return out;
}

// Sammelereignisse: viele Validatoren, dasselbe Ledger, mit Anomalie-Kontext.
// Das ist die Spur, auf der Angriffe, Netzstockungen und Versionskonflikte liegen —
// ausgewählt nach gleichzeitiger Betroffenheit und messbarer Anomalie, nicht nach Bauchgefühl.
export function attackSignals(days, { range = "24h", now = Date.now(), risk = null, ...rest } = {}) {
  const p = { ...RETRACE_DEFAULTS, ...rest };
  const idx = buildLedgerIndex(days);
  const profile = risk ?? riskProfile(days);
  const span = { "1h": 3600000, "24h": 86400000, "7d": 7 * 86400000, "30d": 30 * 86400000, all: Infinity }[range] ?? 86400000;
  const from = span === Infinity ? 0 : now - span;
  const rows = [];
  for (const entry of idx.values()) {
    if (entry.timeMs !== null && (entry.timeMs < from || entry.timeMs > now + 1)) continue;
    const counts = countsOf(entry);
    const affected = counts.missed + counts.partial + counts.wrongHash;
    const validators = new Set(entry.incidents.map((i) => i.master)).size;
    // Dasselbe Kriterium wie in der Diagnose: die Sammelzahl traegt Knoten mit zurechenbarer
    // Abweichung und Knoten ohne gesehenen Vote getrennt. "19 Validatoren" auf einem
    // geschlossenen Ledger ist sonst eine Zahl, die die eigene Schliessungs-Rechnung nicht traegt.
    const faultMasters = [...new Set(entry.incidents.filter((i) => FAULT_TYPES.has(i.type)).map((i) => i.master))];
    const captureOnlyMasters = [...new Set(entry.incidents.filter((i) => i.type === "no-quorum").map((i) => i.master))]
      .filter((m) => !faultMasters.includes(m)).sort();
    if (validators < p.attackMinValidators && counts.noQuorum === 0) continue;
    const st = entry.stats;
    const closure = st ? ledgerClosure(st) : null;
    const anomalies = [];
    if (st) {
      if (st.sp >= TRACE_DEFAULTS.splitMinVotes) anomalies.push("hash-split");
      if (st.med > 0 && st.tx >= TRACE_DEFAULTS.spikeMinTx && st.tx / st.med >= TRACE_DEFAULTS.spikeRatio) anomalies.push(st.tx / st.med >= TRACE_DEFAULTS.extremeRatio ? "load-extreme" : "load-spike");
      // Dasselbe close-gap-Kriterium wie in der Hypothesen-Ebene: Mindestabstand UND Ratio gegen
      // den eigenen Takt, und nur wenn die Index-Folge dieses Recorders nicht nachweislich
      // gesprungen ist. Sonst zehlt die Ledger-Karte einen Erfassungs-Abstand als Netz-Anomalie.
      if (Number.isFinite(st.gap) && Number.isFinite(st.gmed) && st.gmed > 0
        && st.gap >= TRACE_DEFAULTS.gapMinMs && st.gap >= TRACE_DEFAULTS.gapRatio * st.gmed
        && closure?.captureGap !== true) anomalies.push("close-gap");
    }
    const tags = new Set(anomalies);
    // Die Transaktions-Signaturen dieses Ledgers: sev traegt sie, sweep ist ein Fenster-Ereignis.
    if (st && st.sev) for (const tag of Object.keys(st.sev)) tags.add(tag);
    if (st && st.sweep) tags.add("sweep-window");
    for (const i of entry.incidents) for (const r of i.reasons ?? []) {
      // Ein close-gap-Reason aus einem Ledger mit eigener Index-Luecke beschreibt den Abstand
      // dieses Recorders, nicht das Netz. Er darf in der Ledger-Karte nicht als Tag stehen.
      if (r === "close-gap" && closure?.captureGap === true) continue;
      if (r === "no-quorum" || r.startsWith("new-tx-type") || r.startsWith("type-burst:") || SIGNATURE_TAGS.has(r) || r === "amendment-activity" || r === "unl-change" || r === "hash-split" || r === "load-spike" || r === "load-extreme" || r === "close-gap") tags.add(r);
    }
    rows.push({
      ledgerIndex: entry.ledgerIndex,
      timeMs: entry.timeMs ?? null,
      affectedValidators: validators,
      faultValidators: faultMasters.length,
      captureOnlyValidators: captureOnlyMasters.length,
      // Wer genau: die Sammelereignis-Tabelle ohne Keys ist ein Haufungs-Befund ohne Spur.
      masters: [...new Set(entry.incidents.map((i) => i.master))].sort(),
      counts,
      anomalies: [...tags],
      quorum: st ? {
        votes: st.v, needed: st.need, topVotes: st.top, margin: st.mg, runnerVotes: st.sp,
        captureGap: closure ? (closure.captureGap ?? null) : null,
        observedValidations: Number.isFinite(st.ov) ? st.ov : null,
      } : null,
      closure,
      // Auch das Sammelereignis nennt seine Grenze: ohne sie steht '19 Validatoren betroffen'
      // als Netz-Urteil da, obwohl auf einem geschlossenen Ledger nur 7 echt sein koennen.
      capture: st ? captureBound(st) : null,
      load: st ? { txCount: st.tx, medianTx: st.med } : null,
      shape: st && st.sh ? compactShape(st.sh) : null,
    });
  }
  rows.sort((a, b) => (b.affectedValidators - a.affectedValidators) || (b.anomalies.length - a.anomalies.length) || (b.timeMs ?? 0) - (a.timeMs ?? 0));
  return { signals: rows.slice(0, p.topAttacks), total: rows.length, threshold: p.attackMinValidators, risk: profile };
}

// Kompakte Form-Ansicht fuer die API: die Kurzkeys der Tagesdatei (n, s, d, fl, bt, bi) werden zu
// lesbaren Namen. Die Konto-Adresse des groessten Fachers ist in der Tagesdatei bewusst nicht
// gespeichert - die Signatur ist eine Form-Aussage, kein Konto-Report.
function compactShape(sh) {
  return {
    txCount: sh.n ?? 0, senders: sh.s ?? 0, destinations: sh.d ?? 0, failed: sh.fl ?? 0,
    fanoutDestinations: sh.fd ?? 0, fanoutTxs: sh.fa ?? 0, topAccountTxs: sh.fo ?? 0,
    accountChanges: sh.ac ?? 0, offerChanges: sh.oc ?? 0, nftTx: sh.nf ?? 0,
    batchTx: sh.bt ?? 0, innerTx: sh.bi ?? 0, featureTx: sh.fx ?? 0,
  };
}

// Signatur-Tag: die Transaktions-Forensik (tx-forensics) und die Typ-Prafixe. Nur diese Tags
// bilden das Signatur-Bord; Quorum-/Takt-Anomalien gehoeren nicht dazu.
export function isSignatureTag(tag) {
  const t = String(tag ?? "");
  return SIGNATURE_TAGS.has(t) || t.startsWith("type-burst:") || t.startsWith("new-tx-type:");
}

// Signatur-Bord: welche Transaktions-FORMEN im Netz auffallen und wie stark sie mit
// Validator-Ausfaellen verknuepft sind. Das ist die Ebene, die ein dUNL-Betreiber braucht: nicht
// "dieser Ledger hatte 300 Tx", sondern "Ledger mit dieser Form fallen N-mal wahrscheinlicher
// aus, und hier ist ein Ledger, in dem es passiert ist".
//
// Die Zahlen kommen aus den vollstaendigen Tageszaehlern (anomaly / anomalyFail ueber ALLE
// beobachteten Ledger), nicht aus einer Teilmenge: ledgerStats enthaelt nur Ledger MIT
// Abweichung, daraus liesse sich kein Vergleichsbild bauen. Die Belege (sample) kommen aus dem
// angefragten Zeitfenster. Ohne Ledger-Zaehler bleibt eine Signatur unreliable stehen, auch
// wenn ein Beleg existiert - ein einzelner Fall ist keine Rate.
export function signatureBoard(days, { range = "24h", now = Date.now(), risk = null, top = 12 } = {}) {
  const profile = risk ?? riskProfile(days);
  const span = { "1h": 3600000, "24h": 86400000, "7d": 7 * 86400000, "30d": 30 * 86400000, all: Infinity }[range] ?? 86400000;
  const from = span === Infinity ? 0 : now - span;
  const samples = new Map();
  let shapeSeen = 0;
  let shapeMissing = 0;
  for (const d of Array.isArray(days) ? days : []) {
    shapeSeen += num(d.shapeSeen) ?? 0;
    shapeMissing += num(d.shapeMissing) ?? 0;
    for (const st of d.ledgerStats ?? []) {
      if (!st || !st.sh) continue;
      if (Number.isFinite(st.t) && (st.t < from || st.t > now + 1)) continue;
      const tags = new Set(Object.keys(st.sev ?? {}));
      if (st.sweep) tags.add("sweep-window");
      for (const tag of tags) {
        if (!isSignatureTag(tag)) continue;
        const cand = {
          tag, ledgerIndex: st.l ?? null, timeMs: st.t ?? null,
          evidence: tag === "sweep-window" ? st.sweep : (st.sev?.[tag] ?? {}),
          shape: compactShape(st.sh),
        };
        const cur = samples.get(tag);
        if (!cur || (cand.timeMs ?? 0) > (cur.timeMs ?? 0)) samples.set(tag, cand);
      }
    }
  }
  const rows = profile.rows
    .filter((r) => isSignatureTag(r.tag))
    .map((r) => ({ ...r, sample: samples.get(r.tag) ?? null }));
  // Signatur mit Beleg, aber ohne Ledger-Zaehler (Altbestand oder noch nicht gezaehlt):
  // sichtbar lassen, aber ausdruecklich ohne Rate.
  for (const [tag, sample] of samples) {
    if (rows.some((r) => r.tag === tag)) continue;
    rows.push({
      tag, anomalyLedgers: 0, anomalyFailLedgers: 0, plainLedgers: profile.totalLedgers,
      plainFailLedgers: profile.incidentLedgers, rateWith: null, rateWithout: null, lift: null,
      reliable: false, note: "no-ledger-counter", sample,
    });
  }
  rows.sort((a, b) => (Number(b.reliable) - Number(a.reliable)) || ((b.lift ?? 0) - (a.lift ?? 0)) || a.tag.localeCompare(b.tag));
  return {
    rows: rows.slice(0, top), total: rows.length,
    coverage: { shapeSeen, shapeMissing },
    totalLedgers: profile.totalLedgers,
    incidentLedgers: profile.incidentLedgers,
    statsTruncated: profile.statsTruncated,
  };
}
