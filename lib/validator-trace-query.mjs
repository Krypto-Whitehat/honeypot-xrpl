// lib/validator-trace-query.mjs — Abfrage der Trace-Tagesdateien (rein, ohne Netzwerk).
// Eingabe: Tagesobjekte aus data/validator-trace/YYYY-MM-DD.json (monitor/validator-trace.mjs).
import fs from "node:fs";
import path from "node:path";
import { absenceAttribution, aggregatePatterns, measured } from "./validator-trace.mjs";
import { retraceForValidator, riskProfile, attackSignals, signatureBoard, isSignatureTag } from "./validator-retrace.mjs";
import { failureRuns, failureSplit, validatorFingerprint, coFailureClusters, quorumCriticality, windowScan, seriesContext, applySeries, loadResponseCurve } from "./validator-diagnose.mjs";
import { attackImpact } from "./attack-impact.mjs";
import { peerBenchmark } from "./validator-peer-benchmark.mjs";
import { voteLatencyProfile } from "./validator-vote-latency.mjs";
import { causeLedger } from "./validator-cause.mjs";
import { divergenceProfile } from "./validator-divergence.mjs";
import { quorumSurface } from "./validator-quorum-surface.mjs";
import { normalizeDay } from "./validator-trace-store.mjs";
import { signatureSensitivity, signatureCohort } from "./validator-sensitivity.mjs";
import { dayCoverageGaps, dayFileHoles, observedOf, dayResidual, HOUR_MS } from "./trace-day-coverage.mjs";
import { ABSENCE_TYPES, attributeAbsences, cohortTruth, compareAbsences, groundScan, groundWindows, referenceWindow } from "./validator-truth.mjs";
import { stressCoupling } from "./validator-stress-coupling.mjs";

export const RANGE_MS = { "1h": 3600000, "24h": 86400000, "7d": 7 * 86400000, "30d": 30 * 86400000, all: Infinity };
export const RETENTION_DAYS = 365;
// Intervalle des Zeitprofils. Dieselbe Zahl im UI (public/validator-trace.mjs BUCKETS): die
// Achse des Profils und die Zellen dieses Profils muessen dieselbe Zeitachse sein.
export const PROFILE_BUCKETS = 24;
// TUNING-DEFAULT: Retrace-Karten in der Antwort (neueste zuerst). Das Overlay zeigt 12 Karten;
// 60 lassen Raum fuer eine vertiefte Ansicht, ohne dass ein Validator mit 8.609 Vorfällen
// 9 MB JSON laden muss. retraceTotal nennt die Gesamtzahl - die Kuerzung ist sichtbar.
export const RETRACE_ROWS_SENT = 60;

// Liest alle Tagesdateien im Ordner (Muster YYYY-MM-DD.json), begrenzt auf die Aufbewahrung.
export function loadDays(dir, now = Date.now()) {
  if (!dir || !fs.existsSync(dir)) return [];
  const cutoff = now - RETENTION_DAYS * 86400000;
  const out = [];
  for (const f of fs.readdirSync(dir)) {
    if (!/^\d{4}-\d{2}-\d{2}\.json$/.test(f)) continue;
    if (Date.parse(f.slice(0, 10)) < cutoff) continue;
    try { out.push(normalizeDay(JSON.parse(fs.readFileSync(path.join(dir, f), "utf8")))); } catch { /* beschädigte Tagesdatei überspringen, sichtbar über Tagesliste */ }
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
export function traceForValidator(days, master, { range = "24h", now = Date.now(), clusters = [], ground = null, groundPeers = null } = {}) {
  const w = windowOf(range, now);
  // Das Referenzfenster wird der eigenen Spanne angepasst, nicht umgekehrt: die Netzauskunft
  // kennt 1 h / 24 h / 30 d, und die Gegenprobe darf nur mit einem Fenster rechnen, das die
  // eigene Spanne deckt. Sonst wird ein Teil der eigenen Frage gar nicht geprueft.
  const rangeHours = (RANGE_MS[range] ?? RANGE_MS["24h"]) / HOUR_MS;
  const refWindow = referenceWindow(rangeHours);
  const ownGround = groundScan(ground, refWindow);
  const peerGround = groundWindows(groundPeers, refWindow);
  const summary = { ok: 0, partial: 0, missed: 0, wrongHash: 0, noQuorum: 0 };
  const incidents = [];
  // shapeSeen / shapeMissing: Abdeckung der Transaktions-Forensik. Getrennt, weil "keine
  // Signatur" und "Signatur nicht erfasst" zwei verschiedene Aussagen sind.
  const coverage = { ledgers: 0, days: 0, firstMs: null, lastMs: null, gapLedgers: 0, quorumFail: 0, quorumShortRows: 0,
    quorumCounterUnattributed: 0, shapeSeen: 0, shapeMissing: 0,
    daysWithForensics: 0, forensicsLedgers: 0, loadLedgers: 0,
    unobservedRanges: 0, unobservedMs: 0, unobservedLargest: null };
  for (const d of days) {
    const v = d.validators?.[master];
    if (v) {
      summary.ok += v.ok; summary.partial += v.partial; summary.missed += v.missed; summary.wrongHash += v.wrongHash; summary.noQuorum += v.noQuorum ?? 0;
    }
    coverage.ledgers += d.ledgers ?? 0;
    coverage.quorumFail += d.quorumFail ?? 0;
    // Der nachrechenbare Teil dieses Zaehlers: die Forensik-Zeilen, die Ziel und
    // fuehrende Linie derselben Ledger fuehren. normalizeDay hat die Zahl schon
    // ueber genau diese Zeilen gebildet; ohne sie (Rohobjekte) wird sie hier
    // aus denselben Feldern gebildet, nicht geschaetzt.
    coverage.quorumShortRows += Number.isFinite(Number(d.quorumShortRows))
      ? Number(d.quorumShortRows)
      : (d.ledgerStats ?? []).reduce((n, ls) => {
          const top = Number(ls?.top), need = Number(ls?.need);
          return Number.isFinite(top) && Number.isFinite(need) && need > 0 && top < need ? n + 1 : n;
        }, 0);
    if (d.firstMs && (!coverage.firstMs || d.firstMs < coverage.firstMs)) coverage.firstMs = d.firstMs;
    if (d.lastMs && (!coverage.lastMs || d.lastMs > coverage.lastMs)) coverage.lastMs = d.lastMs;
    for (const g of d.gaps ?? []) coverage.gapLedgers += Math.max(0, (g.to ?? 0) - (g.from ?? 0) + 1);
    coverage.shapeSeen += d.shapeSeen ?? 0;
    coverage.shapeMissing += d.shapeMissing ?? 0;
    // Forensik- und Last-Abdeckung je Tag: die Ursachen-Ebene wird erst seit Kurzem
    // aufgezeichnet. Eine Tagesdatei ohne diese Zeilen hat keine Ursache, nicht 'keine Ursache'
    // - der Unterschied ist der ganze Wert dieser Ebene.
    if (Array.isArray(d.ledgerStats)) { coverage.forensicsLedgers += d.ledgerStats.length; if (d.ledgerStats.length) coverage.daysWithForensics += 1; }
    for (const b of d.loadBuckets ?? []) coverage.loadLedgers += Number.isFinite(Number(b?.l)) ? Number(b.l) : 0;
    if (d.incidents?.length || d.ledgers) coverage.days += 1;
  }
  // Zaehler minus Zeilen: so viele Ledger behauptet der Tageszaehler, ohne dass eine Zeile
  // seine Zahlen nennt. Es ist eine Differenz, kein Ledger-Urteil, und es bleibt als
  // eigene Zahl lesbar, statt in die Kopfzeile der Aufzeichnung zu wandern.
  coverage.quorumCounterUnattributed = Math.max(0, coverage.quorumFail - coverage.quorumShortRows);
  // Zwischen den Tagesdateien liegt Zeit, in der nichts bewertet wurde. Sie steht in keiner
  // Datei, die existiert: ein Rekorder-Stop ist keine Stille im Netz. Die Spanne bleibt eine
  // eigene Zahl, damit Aufzeichnung nicht als Beobachtung gelesen wird.
  const holes = dayFileHoles(days);
  coverage.unobservedRanges = holes.length;
  coverage.unobservedMs = holes.reduce((s, h) => s + h.ms, 0);
  coverage.unobservedLargest = holes.length ? holes[0] : null;
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
      // Die anderen dUNL-Knoten dieses Ledgers, namentlich (Master-Keys): erst sie machen aus
      // der Betroffenheits-Zahl eine nachvollziehbare Spur. Das Overlay loest die Keys in die
      // Domain-Namen auf, die es aus der Validator-Liste kennt.
      const peerMasters = peers ? [...peers].filter((x) => x !== master).sort() : [];
      // voteDelayMs: die Latenz des eigenen Votes, null = kein Vote aufgezeichnet (nicht
      // "schnell abgestimmt"). Der Recorder haengt sie einem missed-Ledger an, sobald der Vote
      // nachtraeglich eintrifft, und setzt dann das Reason-Tag 'vote-late'.
      incidents.push({ ledgerIndex: i.l, timeMs: i.t, type: i.type, reasons: i.r ?? [], note: i.n ?? null, affectedValidators: peers ? peers.size : null, peerMasters, voteDelayMs: measured(i.vd),
        // closureBasis nennt, WOHER die Schliess-Aussage dieses Ledgers kommt; typeStored ist der
        // urspruenglich geschriebene Typ. Beides ist die Nachpruefbarkeit der Nachfuehrung aus
        // lib/validator-trace-store.mjs - ohne sie waere der geaenderte Typ eine Behauptung.
        closureBasis: i.cb ?? null, typeStored: i.ts ?? null, closureHash: i.ch ?? null });
    }
  }
  incidents.sort((a, b) => b.timeMs - a.timeMs);
  // Ground-Truth-Gegenprobe je Knoten: die eigene Abwesenheits-Zahl gegen die Zahl, die das
  // Netz fuer denselben Knoten im selben Fenster nennt. Steht mehr in der eigenen Erfassung,
  // ist die Differenz ein Beweis ueber diese Erfassung und nicht ueber den Knoten. Ohne
  // Referenz wird nicht gerechnet - die Aussage bleibt offen statt entlastet.
  const absenceClaims = incidents.filter((i) => ABSENCE_TYPES.has(i.type))
    .map((i) => ({ master, ledgerIndex: i.ledgerIndex, timeMs: i.timeMs, type: i.type }));
  const truth = compareAbsences({
    master, claims: absenceClaims, scan: ownGround, rangeHours, hours: refWindow,
  });
  const gaps = [];
  for (const d of days) for (const g of d.gaps ?? []) if (g.t >= w.from && g.t <= w.to) gaps.push({ from: g.from, to: g.to, timeMs: g.t, reason: g.reason ?? "stream-gap" });
  gaps.sort((a, b) => b.timeMs - a.timeMs);
  // Fenster-genau: Incident-Zähler exakt (zeitgestempelt); 'observed' anteilig aus den
  // Stunden-Buckets — pro Validator (hb.v[master]), falls vorhanden, sonst hb.l.
  let observedHourly = 0;
  let observedDayOnly = 0;
  let hasHourly = false;
  let daysPartial = 0;
  for (const d of days) {
    for (const [hk, hb] of Object.entries(d.hourly ?? {})) {
      const h0 = Number(hk) * 3600000;
      const overlap = Math.min(h0 + 3600000, w.to) - Math.max(h0, w.from);
      if (overlap <= 0) continue;
      hasHourly = true;
      const frac = Math.min(1, overlap / 3600000);
      const hv = hb.v?.[master];
      const perV = hv ? (hv.ok || 0) + (hv.partial || 0) + (hv.missed || 0) + (hv.wrongHash || 0) + (hv.noQuorum || 0) : null;
      observedHourly += (perV ?? hb.l ?? 0) * frac;
    }
    // Tageszaehler, die in KEINEM Stunden-Bucket dieses Fensters liegen (der Recorder ist am
    // 2026-10-09 mitten am Tag mit den Stunden-Buckets eingestiegen). Die Vorfaelle unten kommen
    // aus den zeitgestempelten Incidents und zaehlen voll - bleibt dieser Rest weg, steht ein
    // voller Zaehler ueber einem zu kleinen Nenner. Er kommt als geschaetzt dazu, nie still.
    const { gaps, hasHourly: dayHasHourly, wholeDay } = dayCoverageGaps(d, w);
    const gap = wholeDay ? gaps.get(master) : null;
    if (gap) {
      observedDayOnly += observedOf(gap);
      if (dayHasHourly) daysPartial += 1;
    }
  }
  const bad = incidents.reduce(
    (acc, i) => {
      if (i.type === "missed") acc.missed++;
      else if (i.type === "partial") acc.partial++;
      else if (i.type === "wrong-hash") acc.wrongHash++;
      else if (i.type === "no-quorum" || i.type === "vote-not-observed") acc.noQuorum++;
      return acc;
    },
    { missed: 0, partial: 0, wrongHash: 0, noQuorum: 0 }
  );
  const observed = Math.round(observedHourly + observedDayOnly);
  // Zurechnung der Abwesenheits-Zaehler. Die Gegenprobe (truth) ist kein Begleittext zu diesen
  // Zaehlern, sie ist ihre Grenze: auf bewiesen geschlossenen Ledern zaehlt 'kein Vote erfasst'
  // erst dann gegen den Knoten, wenn die Netz-Referenz dieselbe Abwesenheit fuer denselben Knoten
  // im selben Fenster nennt. Steht mehr in der eigenen Erfassung, ist die Differenz ein Beweis
  // ueber diese Erfassung. Ohne Gegenprobe bleibt jeder dieser Zaehler offen - offen ist weder
  // Vorwurf noch Freispruch.
  const attribution = attributeAbsences({ counts: bad, truth, observed });
  const inWindow = (hasHourly || observedDayOnly > 0)
    ? {
        ...bad,
        ok: Math.max(0, observed - bad.missed - bad.partial - bad.wrongHash - bad.noQuorum),
        absenceClaims: attribution.absenceClaims,
        absenceAttributableMax: attribution.attributableMax,
        absenceArtifactMin: attribution.artifactMin,
        absenceOpen: attribution.openClaims,
        observed,
        observedHourly: Math.round(observedHourly),
        observedDayOnly: Math.round(observedDayOnly),
        daysPartial,
        estimated: true,
      }
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
    // Timing-Ebene: die Klassifizierung sagt, welcher Fehler passierte. Sie sagt nicht, ob dieser
    // Knoten ueberhaupt abgestimmt hat - nur zu spaet - oder gar nicht. Beides hat eine andere
    // naechste Pruefung, und die Spaet-Validierung ist der einzige Beleg dafuer.
    latency: voteLatencyProfile(days, master, { range, now }),
  };
  // Kohorten-Gegenprobe: die Kritikalitaets-Tabelle nennt je Ledger die Knoten, die dieser
  // Rekorder dort nicht sah. Ohne Referenz je Knoten ist "mehrere Knoten betroffen" eine Zahl
  // ueber diese Erfassung, die wie eine Aussage ueber die Knoten gelesen wird. Deshalb wird
  // jeder benannte Knoten gegen seine eigene Referenzzahl gerechnet und das Urteil haengt an
  // der Zeile. Ohne Referenz bleibt der Knoten offen - offen ist nicht gedeckt.
  const allIncidents = [];
  for (const d of days) for (const i of d.incidents ?? []) allIncidents.push(i);
  const peerCheck = cohortTruth({
    rows: diagnosis.criticality?.rows ?? [], incidents: allIncidents, groundByMaster: peerGround,
    rangeHours, hours: refWindow,
  });
  // Namen aus derselben Auskunft, die auch die Gegenprobe traegt (xrpscan-Registry je
  // Master-Key). null heisst: in dieser Auskunft nicht benannt - nicht: kein Name.
  const peerName = (m) => {
    if (!m || !groundPeers) return null;
    const e = groundPeers instanceof Map ? groundPeers.get(m) : groundPeers[m];
    return e && typeof e.name === "string" && e.name ? e.name : null;
  };
  // Die Master-Listen, die eine Retrace-Karte als Kohorte nennt.
  const PEER_GROUPS = ["peerMasters", "sameTypeMasters", "otherTypeMasters", "captureOnlyMasters", "openMasters"];
  if (diagnosis.criticality) {
    diagnosis.criticality.affectedTruth = peerCheck.summary;
    // Namen aus derselben Auskunft, die auch die Gegenprobe traegt (xrpscan-Registry je
    // Master-Key). null heisst 'in dieser Auskunft nicht benannt' - nicht 'kein Name'.
    for (const r of diagnosis.criticality.rows ?? []) {
      r.affectedTruth = (r.affectedMasters ?? []).map((m) => peerCheck.byMaster.get(m) ?? null);
      // indexgleich zu affectedMasters: dieselbe Ordnung, derselbe Knoten, derselbe Name.
      r.affectedNames = (r.affectedMasters ?? []).map((m) => ({ master: m, name: peerName(m) }));
    }
  }
  // Retrace-Karten nennen die Kohorte beim Namen. Ohne Gegenurteil je benanntem Knoten ist
  // "24 Knoten hier unerfasst" eine Zahl ueber diese Erfassung, die als Knoten-Aussage
  // gelesen wird - dieselbe Luecke, die die Kritikalitaets-Tabelle schon schliesst. Jeder
  // Knoten, den eine gesendete Karte nennt, bekommt dasselbe Urteil aus derselben Referenz:
  // durch die Referenz widerlegt, innerhalb ihrer Zahl, oder offen. Offen ist nicht gedeckt.
  const retraceRows = retrace.slice(0, RETRACE_ROWS_SENT);
  const retracePeers = new Set();
  for (const r of retraceRows) {
    for (const key of PEER_GROUPS) for (const m of r?.affected?.[key] ?? []) if (m) retracePeers.add(m);
  }
  if (retracePeers.size) {
    const retraceCheck = cohortTruth({
      rows: [{ affectedMasters: [...retracePeers] }], incidents: allIncidents, groundByMaster: peerGround,
      rangeHours, hours: refWindow,
    });
    for (const r of retraceRows) {
      const a = r?.affected;
      if (!a) continue;
      const peerTruth = {};
      const peerNames = {};
      for (const key of PEER_GROUPS) for (const m of a[key] ?? []) {
        if (!m || peerTruth[m] !== undefined) continue;
        peerTruth[m] = retraceCheck.byMaster.get(m) ?? null;
        peerNames[m] = peerName(m);
      }
      a.peerTruth = peerTruth;
      a.peerNames = peerNames;
    }
  }
  const divergence = divergenceProfile(days, master, { range, now });
  const peer = peerBenchmark(days, master, { range, now });
  // Ursachen-Engine: die Ebenen einzeln zu lesen ist ehrlich, aber einem Betreiber hilft es
  // nicht. Diese Ebene gewichtet die Belege aller Ebenen je Vorfall und sagt, welcher Grund der
  // wahrscheinlichste ist, wie sicher er ist, und was als Naechstes zu pruefen ist. Die
  // Angriffsstunden kommen als Netz-Gegenprobe dazu: ohne sie ist "Angriffsstunde" nur ein
  // Zeitfenster, mit ihr ist es eine belegte oder widerlegte Kopplung.
  const impact = Array.isArray(clusters) && clusters.length ? attackImpact(days, clusters, { range, now }) : null;
  // Risikoflaeche: die Margin- und Last-Achse ueber ALLE bewerteten Ledger, nicht nur die mit
  // eigenem Ausfall. quorumCriticality zaehlt nur die Ausfall-Ledger und hat damit keinen Nenner;
  // erst diese Achse beantwortet, ob du auf knappen Quorums ausfaellst (Netz) oder auf komfortablen
  // (dein Knoten) - und ob Last und Quorum zusammen schaeden, was keine der beiden Achsen einzeln
  // zeigen kann.
  const surface = quorumSurface(days, master, { range, now });
  const cause = causeLedger({ days, master, range, now, retrace, diagnosis, peer, divergence, incidents, impact, surface });
  // Die Ausfall-Zaehler dieses Fensters bekommen ihren Beleg dazu: wie viele 'missed'-Zahlen
  // aus Zeilen mit eigener Abdeckungs-Messung kommen und wie viele aus dem Altbestand davor.
  // Ohne diese Aufteilung waere die Peer-Rate eine Knoten-Aussage, deren Grund offen ist.
  const absence = absenceAttribution(days.flatMap((d) => (Array.isArray(d.ledgerStats) ? d.ledgerStats : [])
    .filter((st) => Number.isFinite(st?.t) && st.t >= w.from && st.t < w.to)));
  return {
    master, range,
    summary: { ...summary, observed: summary.ok + summary.partial + summary.missed + summary.wrongHash + summary.noQuorum },
    inWindow, coverage, incidents, gaps, truth, attribution, absence, patterns: patterns.tags,
    retrace: retrace.slice(0, RETRACE_ROWS_SENT),
    retraceTotal: retrace.length,
    diagnosis,
    profile: profileCells(days, master, { range, now }),
    // Peer-Benchmark: die Zahlenebene beantwortet nicht, ob diese Rate ein Knotenproblem ist
    // oder genau das, was in diesem Fenster allen dUNL-Knoten desselben Fensters passiert.
    peer,
    // Divergenz-Ebene: die Hash-Linie dieses Knotens gegen die des Netzes, die Wiederholung einer
    // verlorenen Linie und die Feature-Ledger (Amendment / UNLModify), auf denen er ausfaellt.
    // Das ist die Ursache-Ebene fuer wrong-hash, die die reine Klassifikation nicht liefert.
    divergence,
    surface,
    cause,
    impact,
    risk: { totalLedgers: risk.totalLedgers, incidentLedgers: risk.incidentLedgers, rows: risk.rows, statsTruncated: risk.statsTruncated, coverage: risk.coverage ?? null },
    // Signatur-Empfindlichkeit: die Risikuebene sagt, wie oft ein Ledger mit dieser Signatur im
    // Netz ausfaellt. Diese Ebene sagt, ob DIESER Knoten darauf ueberproportional faellt - oder
    // ob die Kohorte dasselbe tut. Erst diese Trennung unterscheidet Knotenproblem von Netzlage.
    sensitivity: signatureSensitivity(days, master, { range, now }),
    // Kopplungs-Ebene: ledger-genau, mit benannten Knoten je Massen-Ledger und benannten
    // Kontroll-Ledern je Signatur. Sie beantwortet, ob ein Ausfall eine Netzaktion war oder
    // ein Knotenfehler - und welche Knoten genau auf demselben Ledger ausfielen.
    coupling: stressCoupling(days, master, { range, now }),
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
    ledgers: 0, ledgersEstimated: 0, missed: 0, partial: 0, wrongHash: 0, noQuorum: 0, total: 0,
    cohort: null, tags: {}, signatures: 0,
  }));
  const cellOf = (ms) => cells[Math.min(buckets - 1, Math.max(0, Math.floor(((ms - from) / width) * buckets)))];

  let measured = false;
  let estimated = false;
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
      const key = i.type === "missed" ? "missed" : i.type === "partial" ? "partial" : i.type === "wrong-hash" ? "wrongHash" : i.type === "no-quorum" || i.type === "vote-not-observed" ? "noQuorum" : null;
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
  // Nenner-Ergaenzung: Tageszaehler, die in keinem Stunden-Bucket stehen, sind Ledger, die in
  // bucketlosen Stunden beobachtet wurden. Fehlt dieser Anteil, steht im Profil eine Abweichung
  // neben "0 Ledger beobachtet" - bei xrp.vet 25 Vorfaelle ohne Nenner. Verteilt wird
  // gleichmaessig ueber die bucketlosen Stunden dieses Tages.
  // cell.ledgers bleibt die Messung: ein Intervall, dessen Abdeckung nur geschaetzt ist, darf
  // nicht als "beobachtet und unauffaellig" zaehlen - diese Aussage folgt aus Tagessummen nicht.
  // Darum getrennt: cell.ledgersEstimated. Die Abweichungen selbst bleiben gemessen (Incidents).
  let estimatedLedgers = 0;
  for (const d of Array.isArray(days) ? days : []) {
    const { gaps, hours } = dayResidual(d);
    if (!hours.length || !gaps.size) continue;
    const gap = gaps.get(master);
    if (!gap) continue;
    const perHour = observedOf(gap) / hours.length;
    if (!(perHour > 0)) continue;
    estimated = true;
    for (const hh of hours) {
      const h0 = hh * HOUR_MS;
      for (const cell of cells) {
        const ov = Math.min(h0 + HOUR_MS, cell.to) - Math.max(h0, cell.from);
        if (ov <= 0) continue;
        const share = (perHour * ov) / HOUR_MS;
        cell.ledgersEstimated += share;
        estimatedLedgers += share;
      }
    }
  }
  for (const c of cells) {
    c.ledgers = Math.round(c.ledgers);
    c.ledgersEstimated = Math.round(c.ledgersEstimated);
  }
  return { from, to: now, buckets, measured, estimated, estimatedLedgers: Math.round(estimatedLedgers), cells };
}

// Übergreifende Muster: alle Validatoren im Zeitraum, mit Zählern je Validator.
export function crossValidatorPatterns(days, { range = "24h", now = Date.now(), clusters = [] } = {}) {
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
    if (i.type === "missed") e.missed++; else if (i.type === "partial") e.partial++; else if (i.type === "wrong-hash") e.wrongHash++; else if (i.type === "no-quorum" || i.type === "vote-not-observed") e.noQuorum++;
  }
  const risk = riskProfile(days);
  return {
    range, incidents: incidents.length, tags: p.tags, recurring: p.recurring, perValidator,
    risk: { totalLedgers: risk.totalLedgers, incidentLedgers: risk.incidentLedgers, rows: risk.rows, statsTruncated: risk.statsTruncated, coverage: risk.coverage ?? null },
    attacks: attackSignals(days, { range, now, risk }),
    // Netz-Sicht der Serien- und Kohortenebene: wer faellt am Stueck, wer faellt nur im Netz,
    // und ob es Knoten gibt, die privat fast immer zusammen ausfallen (geteilte Infrastruktur).
    split: failureSplit(days, { range, now }),
    clusters: coFailureClusters(days, { range, now }),
    windows: windowScan(days, { range, now }),
    // Das Signatur-Bord: welche Transaktions-Formen im Netz auffallen und wie stark sie mit
    // Validator-Ausfaellen verknuepft sind (Netz-Sicht, nicht Validator-Sicht).
    signatures: signatureBoard(days, { range, now, risk }),
    // Welche Signaturen treffen im selben Fenster WIE VIELE Knoten? Die Vorstufe einer
    // dUNL-weiten Beobachtung, bevor ein einzelner Knoten sie meldet.
    cohortSignatures: signatureCohort(days, { range, now }),
    // Netz-Kurve: ab welcher Last der Durchschnitt der dUNL-Knoten zu fallen beginnt. Ohne
    // diesen Vergleich waere die Kurve eines einzelnen Knotens eine Zahl ohne Bedeutung.
    load: loadResponseCurve(days, { range, now }),
    // Die Zeit-Ebene: Honeypot-Angriffe gegen die Ausfallserien aller dUNL-Knoten. Die
    // Cluster der Betrugs-Historie sind die Angriffsseite; ohne sie ist diese Ebene blind.
    impact: attackImpact(days, clusters, { range, now }),
  };
}
