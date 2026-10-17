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
import { measured } from "./validator-trace.mjs";

// Der Schliess-Hash ist 64 Hex-Zeichen lang. Ohne dieses Muster ist "hat einen Hash" eine
// Behauptung ueber einen beliebigen String.
const HEX64 = /^[0-9A-Fa-f]{64}$/;
import fs from "node:fs";
import path from "node:path";

export const TRACE_DIR = "data/validator-trace";
// Direkt abfragbares Fenster ("seit Start"): Default 400 Tage, deckt das
// 12-Monats-Ring-Fenster der Shards ab. Env TRACE_MAX_DAYS überschreibt.
// Ältere Tagesdateien bleiben im Speicher erhalten (kein Pruning), sind aber
// nur per Datumsabfrage erreichbar.
export const TRACE_RETENTION_DAYS = Number(process.env.TRACE_MAX_DAYS) > 0 ? Math.floor(Number(process.env.TRACE_MAX_DAYS)) : 400;
const CACHE_MS = { "1h": 60000, "24h": 60000, "7d": 120000, "30d": 300000, all: 600000 };
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

// Ein Bestandstag kann aus einer älteren Recorder-Stufe stammen und dann Felder fehlen lassen,
// die inzwischen gezählt werden. Ein fehlender Zähler ist "nicht erfasst" - nicht "null": auf
// null oder undefined endete jede Addition auf NaN, und die Tagesdatei bekäme einen Wert, den
// niemand gemessen hat. Ebenso fehlt dann die Forensik-Liste, deren Länge gezählt wird.
export function normalizeDay(doc) {
  if (!doc || typeof doc !== "object" || Array.isArray(doc)) return doc;
  doc.gaps ??= []; doc.captureEvents ??= []; doc.captureEventsTruncated ??= false; doc.incidents ??= []; doc.validators ??= {}; doc.ledgers ??= 0; doc.quorumFail ??= 0;
  doc.hourly ??= {}; doc.firstMs ??= null; doc.lastMs ??= null;
  doc.ledgerStats ??= []; doc.ledgerStatsTruncated ??= false; doc.incidentLedgers ??= 0;
  // Anomalie-Zaehler (Signatur-Ebene) sind juenger als der Altbestand. Der Marker trennt einen
  // Tag ohne diese Zaehler von einem Tag, an dem die Ebene gefuehrt wurde und keine Abweichung
  // fand. Ohne ihn wird ein ungepruefter Tag zu "geprueft, alles sauber": ein leeres Objekt
  // waere von einem gemessenen leeren Ergebnis nicht zu unterscheiden, und die Vergleichsgruppe
  // des Risikovergleichs fuellte sich mit Ledern, die niemand geprueft hat.
  doc.anomaly ??= {}; doc.anomalyFail ??= {};
  // Zaehler sind das Produkt des Scans: wo einer steht, wurde die Ebene gefuehrt, auch wenn der
  // Marker erst spaeter eingefuegt wurde. Ohne Zaehler und ohne Marker ist nicht beweisbar, dass
  // ueberhaupt gesehen wurde - also false (Luecke), auch wenn das Nachfuellen ein leeres Objekt
  // hinterlassen hat.
  const hasAnomalyCounters = Object.keys(doc.anomaly).length > 0 || Object.keys(doc.anomalyFail).length > 0;
  if (doc.anomalyRecorded !== true) doc.anomalyRecorded = hasAnomalyCounters;
  doc.loadBuckets ??= [];
  // Spaet-Validierungen (nach der Bewertung des Leders) und die Last-Achse je Ledger. Beide
  // Ebenen sind juenger als der Altbestand: fehlend bleibt fehlend, "nicht erfasst" darf nie
  // als "keine Spaetvalidierung" gelesen werden.
  // Der Marker trennt Altbestand von einem Tag mit wirklich null Spaetvotes. Ohne ihn ist das
  // gerade eingefuegte leere Array von einem gemessenen leeren Ergebnis nicht zu unterscheiden -
  // und "nicht erfasst" wuerde als "keine Spaetvalidierung" gelesen, also als Entlastung.
  // Quorum-Margin-Achse und ihre gemeinsame Zelle mit der Last-Achse sind juenger als der
  // Altbestand. Der Marker trennt "diese Achse wurde nie erfasst" von "kein Ledger dieser
  // Bandbreite" - ohne ihn leer eine leere Achse wie "Quorum war immer komfortabel".
  const quorumPresent = Array.isArray(doc.quorumBuckets);
  const latePresent = Array.isArray(doc.lateVotes);
  const featuresPresent = doc.featureLedgers !== undefined;
  doc.quorumBuckets ??= []; doc.riskCross ??= []; doc.quorumMissing ??= 0;
  // Netz-Anker des Endpunkts ist juenger als der Altbestand. Fehlend bleibt fehlend: ein Tag ohne
  // Versuch darf nicht als "Quorum war 0" gelesen werden, und ein Tag mit fehlgeschlagenen
  // Versuchen ist etwas anderes als ein Tag, an dem die Ebene nie angefasst wurde.
  const nqPresent = doc.networkQuorum !== undefined || doc.networkQuorumSamples !== undefined
    || doc.networkQuorumAttempts !== undefined;
  doc.networkQuorum ??= null; doc.networkQuorumSamples ??= 0; doc.networkQuorumAttempts ??= 0;
  if (!Number.isFinite(doc.networkQuorumSamples)) doc.networkQuorumSamples = 0;
  if (!Number.isFinite(doc.networkQuorumAttempts)) doc.networkQuorumAttempts = 0;
  if (doc.networkQuorum !== null) {
    const q = Number(doc.networkQuorum.quorum);
    if (!Number.isFinite(q) || q <= 0) doc.networkQuorum = null;
  }
  doc.networkQuorumSampled = doc.networkQuorum !== null;
  doc.lateVotes ??= []; doc.lateVotesTruncated ??= false;
  doc.featureLedgers ??= {}; doc.featureFail ??= {};
  // Ein Marker aus einem Tag, der aelter ist als die Achse, beschreibt den Schreibvorgang von
  // damals, nicht den Bestand von heute. Wird die Achse nachtraeglich gefuellt, ist das
  // ueberlieferte 'false' eine Falschaussage ueber Messungen, die vorhanden sind - die
  // Risikoflaeche wuerde eine gefuellte Achse als Luecke zeigen. Gefuellte Daten ueberholen den
  // Marker. Leere Daten ueberholen ihn nicht, damit 'nicht erfasst' nie zur Entlastung wird.
  const quorumBooked = doc.quorumBuckets.some((b) => b && (measured(b.l) ?? 0) > 0) || (measured(doc.quorumMissing) ?? 0) > 0;
  if (doc.quorumRecorded === false && quorumBooked) doc.quorumRecorded = true;
  else if (!quorumPresent) doc.quorumRecorded = false;
  if (doc.lateVotesRecorded === false && doc.lateVotes.length > 0) doc.lateVotesRecorded = true;
  else if (!latePresent) doc.lateVotesRecorded = false;
  if (doc.featuresRecorded === false && Object.keys(doc.featureLedgers).length > 0) doc.featuresRecorded = true;
  else if (!featuresPresent) doc.featuresRecorded = false;
  // Ein Tag, dessen Datei die Ebene bereits trug, hat sie erfasst - auch wenn der Marker juenger
  // ist als die Datei. Ohne diesen Zweig blieb der Marker leer, und die Feature-Vergleichung
  // musste raten, ob ein leerer Zaehler eine Messung oder eine Luecke ist.
  else if (featuresPresent && doc.featuresRecorded === undefined) doc.featuresRecorded = true;
  for (const lv of doc.lateVotes) {
    if (!lv || typeof lv !== "object") continue;
    lv.ms = measured(lv.ms);
    lv.t = measured(lv.t);
  }
  // Feature-Zaehler (Amendment / UNLModify je Ledger) sind juenger als der Altbestand. Der Marker
  // trennt einen Tag ohne diese Zaehler von einem Tag, an dem wirklich kein Feature-Ledger lag.
  const featuresRecorded = doc.featureLedgers !== undefined;
  doc.featureLedgers ??= {}; doc.featureFail ??= {};
  if (!featuresRecorded) doc.featuresRecorded = false;
  for (const ls of doc.ledgerStats) {
    if (!ls || typeof ls !== "object") continue;
    ls.fv = measured(ls.fv);
    ls.lv = measured(ls.lv);
    // am/unl: Feature-Fakten des Ledgers. Fehlendes am ist 'nicht erfasst', ein leeres Array ist
    // 'dieser Ledger trug kein Amendment' - zwei verschiedene Aussagen.
    if (ls.am === undefined) ls.am = null;
    else if (!Array.isArray(ls.am)) ls.am = [];
    ls.unl = ls.unl === true;
    // INVARIANTE: 'cl' und 'ch' werden vom Recorder gemeinsam geschrieben
    // (monitor/validator-trace.mjs: ch = closedHash, cl = closed === true, und closed heisst
    // closedHash !== null). Eine Zeile mit cl=true ohne 64-Hex-Hash ist deshalb kein
    // Schliess-Beweis, sondern ein zerstoerter Nachtrag - der alte Flush hat den nachgetragenen
    // Hash ueberschrieben und das Flag stehen lassen. Auf null zuruecksetzen ist die ehrliche
    // Aussage ('nicht erfasst'); 'false' waere die Gegenbehauptung, der Ledger sei nicht
    // geschlossen, und die ist mit einem validierten Stream nicht belegbar.
    if (ls.cl === true && !(typeof ls.ch === "string" && HEX64.test(ls.ch))) { ls.cl = null; ls.ch = null; }
  }
  // NACHFUEHRUNG DER INCIDENT-TYPEN BEIM LESEN (2026-10-17, durch xrpscan + xrplcluster belegt).
  // 'no-quorum' wurde geschrieben, bevor der Rekorder zwischen "Quorum des Netzes fehlte" und
  // "dieser Rekorder sah zu wenige Stimmen auf einem bewiesen geschlossenen Ledger" trennte. Der
  // Rekorder wertet ausschliesslich Ledger aus dem validierten Stream (monitor/validator-trace.mjs:
  // streams = ["validations", "ledger"]); ein von ihm ausgewerteter Ledger ist geschlossen, solange
  // die Schliess-Ebene das nicht ausdruecklich verneint ('nc' am Incident, 'cl === false' am
  // Ledger). Eine Zeile, die auf einem geschlossenen Ledger ein fehlendes Netz-Quorum behauptet,
  // ist eine Falschaussage ueber das Netz - genau das warfen Betreiber zu Recht zurueck
  // (#107695059, #107694001, #107690236: beide Autoritaeten melden denselben validierten Hash).
  // Umgestellt wird beim Lesen, der gespeicherte Typ bleibt als 'ts' erhalten und 'cb' nennt die
  // Autoritaet der Schliess-Aussage: 'xrpscan' (Zwei-Quellen-Deckung, siehe closureProofs und
  // backfill-closure.mjs), 'recorder' (im Stream selbst gehoert) oder 'validated-ledger-stream'
  // (kein Hash in dieser Datei hinterlegt, Schliessung aber nie verneint).
  doc.closureProofs ??= [];
  const closureDenied = new Set();
  const closureNamed = new Map();
  const readClosureProof = (row) => {
    if (!row || typeof row !== "object" || !Number.isFinite(row.l)) return;
    if (row.cl === false) { closureDenied.add(row.l); return; }
    if (typeof row.ch === "string" && HEX64.test(row.ch)) {
      closureNamed.set(row.l, {
        hash: row.ch,
        source: typeof row.chSource === "string" ? row.chSource : "recorder",
        verifiedBy: typeof row.chVerifiedBy === "string" ? row.chVerifiedBy : null,
      });
    }
  };
  for (const ls of doc.ledgerStats) readClosureProof(ls);
  for (const cp of doc.closureProofs) readClosureProof(cp);
  for (const inc of doc.incidents) {
    if (!inc || typeof inc !== "object" || inc.type !== "no-quorum") continue;
    if (inc.nc === true || closureDenied.has(inc.l)) continue;
    inc.ts = "no-quorum";
    inc.type = "vote-not-observed";
    if (Array.isArray(inc.r)) inc.r = inc.r.map((t) => (t === "no-quorum" ? "vote-not-observed" : t));
    const named = closureNamed.get(inc.l);
    inc.cb = named ? named.source : "validated-ledger-stream";
    if (named) {
      inc.ch = named.hash;
      if (named.verifiedBy) inc.chv = named.verifiedBy;
    }
  }

  // KOHAERENZ DER TAGES-ZAEHLER ZU DIESER NACHFUEHRUNG (2026-10-17, durch die Tagesdatei selbst belegt).
  // Die Umbenennung oben gilt den Vorfaelle. Die Ledger-Zaehler 'anomaly' / 'anomalyFail' wurden
  // von derselben Regel geschrieben: monitor/validator-trace.mjs zaehlt ueber r.ledgerTags, und
  // classifyReasons schob 'no-quorum' fuer jedes Ledger ohne beobachtetes Quorum. Ein Zaehler, der
  // 'no-quorum' behauptet, waehrend jeder Vorfall desselben Tages 'vote-not-observed' heisst, ist
  // derselbe Irrtum an zweiter Stelle - und er ist der eigentliche Ursprung der falschen Rate:
  // data/validator-trace/2026-10-16.json fuehrt anomaly 'no-quorum' = 8 und anomalyFail = 8, aber
  // 0 Vorfaelle vom Typ 'no-quorum', 0 Forensik-Zeilen mit cl === false und 0 Vorfalle mit nc.
  // Umgestellt wird ueber die ganze Population, NUR die Vokabel, keine Zahl: die Tageszahl nennt
  // keine Ledger-Indizes, eine Zuordnung pro Ledger waere eine Schaetzung.
  // Voraussetzung: dieser Tag verneint die Schliessung nirgends. Sonst liegt Altbestand und ein
  // echtes 'no-quorum'-Ledger in ein- und demselben Zaehler, die Aufteilung ist erfunden, und der
  // Zaehler bleibt stehen - als benannte Luecke, nicht als Zahl.
  const closureDenials = closureDenied.size + doc.incidents.filter((i) => i && typeof i === "object" && i.nc === true).length;
  const legacyQuorum = Number(doc.anomaly?.["no-quorum"]);
  if (Number.isFinite(legacyQuorum) && legacyQuorum > 0) {
    if (closureDenials === 0) {
      for (const key of ["anomaly", "anomalyFail"]) {
        const c = doc[key];
        if (!c || typeof c !== "object") continue;
        const n = Number(c["no-quorum"]);
        if (!Number.isFinite(n) || n <= 0) continue;
        const keep = Number(c["vote-not-observed"]);
        c["vote-not-observed"] = (Number.isFinite(keep) ? keep : 0) + n;
        c["no-quorum"] = 0;
      }
      // 'countersRenamed' zaehlt LEDGER, deren Zaehler-Eintrag umgestellt wurde - nicht die Zahl
      // der beruehrten Zaehlerfelder: 'anomaly' und 'anomalyFail' beschreiben dieselbe Population
      // (alle Ledger mit diesem Tag / davon die mit Ausfall), 8 + 8 waere dieselbe Tatsache doppelt.
      doc.countersRenamed = (Number.isFinite(Number(doc.countersRenamed)) ? Number(doc.countersRenamed) : 0) + legacyQuorum;
    } else {
      doc.counterGaps = (Array.isArray(doc.counterGaps) ? doc.counterGaps : []).concat(
        [{ tag: "no-quorum", ledgers: legacyQuorum, closureDenials, reason: "closure-denied-in-same-counter" }]);
    }
  }

  // NACHFUEHRUNG DER ZUORDNUNG BEIM LESEN (2026-10-17, Gegenprobe api.xrpscan.com agreement_24h).
  // 'missed' wurde geschrieben, bevor der Rekorder die Zuordnungsgrenze kannte
  // (lib/validator-trace.mjs: attributableAbsence, vier nachpruefbare Bedingungen). Seither darf
  // ein fehlender Vote nur dann 'missed' heissen, wenn die Zeile ihren Beleg traegt. Der
  // Altbestand traegt ihn nicht: nachgezaehlt ueber data/validator-trace traegen 26 von 11.862
  // 'missed'-Vorfaelle einen Beleg, 11.836 nicht. Die Gegenprobe
  // (api.xrpscan.com/api/v1/validator/<master>) sagt fuer mehrere dieser Knoten 0 verpasste
  // Ledger im Fenster - die Zahl war Erfassungs-Luecke dieses Recorders, kein Knoten-Ausfall.
  // Peer-Rate, Serien-Urteil und Angriffsbilanz lasen sie bisher als Ausfall, weil der Typ es
  // sagte. Umgestellt wird beim Lesen: der gespeicherte Typ bleibt in 'ts', 'ma' nennt, warum der
  // Beleg fehlt, und die Zaehler wandern mit ('missed' -> 'noQuorum'). Sonst steht in derselben
  // Datei ein Vorfall 'vote-not-observed' neben einem Zaehler 'missed' - zwei Zahlen fuer
  // dieselbe Tatsache. Der Beleg ist die Forensik-Zeile ('aa') oder das Feld am Vorfall ('aa').
  // Ohne Beleg gibt es kein Knoten-Urteil - und keine Entlastung: 'ma' bleibt lesbar.
  // 'fault' = gemessen belegbar, 'capture' = gemessen unvollstaendig (die Absage ist selbst
  // eine Messung), kein Eintrag = nie gemessen. Drei Zustande, weil drei Aussagen.
  const attributionProof = new Map();
  for (const ls of doc.ledgerStats) {
    if (!ls || typeof ls !== "object" || !Number.isFinite(ls.l)) continue;
    if (ls.aa === true) attributionProof.set(ls.l, "fault");
    else if (ls.aa === false) attributionProof.set(ls.l, "capture");
  }
  const movedMissed = new Map();
  let provenMissed = 0;
  for (const inc of doc.incidents) {
    if (!inc || typeof inc !== "object" || inc.type !== "missed") continue;
    const rowProof = attributionProof.get(inc.l);
    if (inc.aa === true || rowProof === "fault") { provenMissed += 1; continue; }
    const denied = inc.nc === true || closureDenied.has(inc.l);
    const next = denied ? "no-quorum" : "vote-not-observed";
    inc.ts = "missed";
    inc.ma = (inc.aa === false || rowProof === "capture") ? "not-attributable" : "not-recorded";
    inc.type = next;
    if (Array.isArray(inc.r)) inc.r = inc.r.map((t) => (t === "missed" ? next : t));
    if (!denied) {
      const named = closureNamed.get(inc.l);
      inc.cb = named ? named.source : "validated-ledger-stream";
      if (named) {
        inc.ch = named.hash;
        if (named.verifiedBy) inc.chv = named.verifiedBy;
      }
    }
    let bucket = movedMissed.get(inc.m);
    if (!bucket) { bucket = { total: 0, hours: new Map() }; movedMissed.set(inc.m, bucket); }
    bucket.total += 1;
    if (Number.isFinite(inc.t)) {
      const hk = Math.floor(inc.t / 3600000);
      bucket.hours.set(hk, (bucket.hours.get(hk) ?? 0) + 1);
    }
  }
  let movedMissedTotal = 0;
  let missedCounterGaps = 0;
  for (const [master, bucket] of movedMissed) {
    const v = doc.validators[master];
    const own = Number.isFinite(v?.missed) ? v.missed : 0;
    const take = Math.min(bucket.total, own);
    if (v && take > 0) {
      v.missed = own - take;
      v.noQuorum = (Number.isFinite(v.noQuorum) ? v.noQuorum : 0) + take;
      v.missedOpen = (Number.isFinite(v.missedOpen) ? v.missedOpen : 0) + take;
    }
    if (take !== bucket.total) missedCounterGaps += 1;
    movedMissedTotal += take;
    for (const [hk, n] of bucket.hours) {
      const hv = doc.hourly[hk]?.v?.[master];
      if (!hv) continue;
      const have = Number.isFinite(hv.missed) ? hv.missed : 0;
      const use = Math.min(n, have);
      if (use <= 0) continue;
      hv.missed = have - use;
      hv.noQuorum = (Number.isFinite(hv.noQuorum) ? hv.noQuorum : 0) + use;
      hv.missedOpen = (Number.isFinite(hv.missedOpen) ? hv.missedOpen : 0) + use;
    }
  }
  // Das Feld beschreibt immer den aktuellen Lesedurchgang, nie einen frueheren: ein
  // ueberliefertes 'moved = 1' neben einem Durchgang ohne Verschiebung waere eine Zahl ueber
  // eine Verschiebung, die gerade nicht stattfand.
  if (movedMissedTotal > 0 || provenMissed > 0 || missedCounterGaps > 0 || doc.missedAttribution !== undefined) {
    doc.missedAttribution = { moved: movedMissedTotal, proven: provenMissed, counterGaps: missedCounterGaps };
  }

  for (let i = 0; i < doc.loadBuckets.length; i += 1) {
    const b = doc.loadBuckets[i];
    if (!b || typeof b !== "object") { doc.loadBuckets[i] = { l: 0, f: 0, v: {} }; continue; }
    b.l = Number.isFinite(Number(b.l)) ? Number(b.l) : 0;
    b.f = Number.isFinite(Number(b.f)) ? Number(b.f) : 0;
    b.v ??= {};
  }
  for (const k of ["shapeSeen", "shapeMissing"]) {
    if (doc[k] === null || doc[k] === undefined || !Number.isFinite(Number(doc[k]))) doc[k] = 0;
  }
  for (const v of Object.values(doc.validators)) if (v && typeof v === "object") v.noQuorum ??= 0;
  for (const hb of Object.values(doc.hourly)) {
    if (!hb || typeof hb !== "object") continue;
    // Netz-Vote-Latenz je Stunde: fehlend bleibt fehlend, ein value-String wird nicht zu 0.
    for (const k of ["fvN", "fvS", "fvX", "fvL"]) {
      if (hb[k] !== undefined && hb[k] !== null && !Number.isFinite(Number(hb[k]))) hb[k] = null;
    }
    for (const v of Object.values(hb.v ?? {})) if (v && typeof v === "object") v.noQuorum ??= 0;
  }
  return doc;
}

export function dayPath(date) {
  return `${TRACE_DIR}/${date}.json`;
}

// DER SCHLIESS-NACHTRAG DARF NICHT VERLOREN GEHEN.
// scripts/backfill-closure.mjs traegt fuer eine Forensik-Zeile, die der Rekorder selbst nicht
// beweisen kann, den Schliess-Hash von aussen nach ('chSource' = xrpscan, Gegenpruefer
// 'chVerifiedBy' = xrplcluster.com, Deckung 'xc'). Dieser Nachtrag ist auf solchen Zeilen die
// einzige Autoritaet fuer die Aussage "das Netz hat geschlossen" - ohne ihn faellt die Diagnose
// auf die alte Behauptung zurueck, eine negative Marge sei eine Netzstockung.
// Beide Schreibpfade des Recorders konnten ihn zerstoeren: lokal schreibt der Flush das
// In-Memory-Tag, fern gibt 'saveDayRemote' writeGitHubContents das eigene Tag zurueck statt des
// frisch gelesenen. Laeuft der Nachtrag waehrend eines laufenden Rekorders, ist er beim
// naechsten Flush weg. Deshalb wird vor JEDEM Write der Bestand gelesen und der Nachtrag
// zurueckgefuehrt.
// Regel (bewusst eng, damit kein alter Stand hochlebt): uebernommen werden nur die
// Nachtrag-Felder einer Zeile mit gleichem Ledger-Index, und nur wenn die Bestandszeile eine
// Fremdquelle ist. Ein eigener Mithoerbeweis der neuen Zeile bleibt die Autoritaet und wird
// hoechstens um den Gegenpruefer der Fremdquelle ergaenzt, nie durch deren Hash ersetzt.
// Zaehler, Incidents und Luecken bleiben ausschliesslich das, was dieser Rekorder sah.
export const ADDENDUM_SOURCE = "xrpscan";
export const ADDENDUM_FIELDS = ["ch", "chSource", "chVerifiedBy", "chAt", "xc"];

const isForeignProof = (row) => Boolean(row) && typeof row === "object"
  && row.chSource === ADDENDUM_SOURCE && typeof row.ch === "string" && row.ch.length > 0;
const isOwnProof = (row) => Boolean(row) && typeof row === "object"
  && typeof row.ch === "string" && row.ch.length > 0 && row.chSource === undefined;

// Gibt das Ziel-Tag und die Zahl der uebernommenen Zeilen zurueck. 'carried' ist die Zahl, die
// der Rekorder im Log nennt: erhaltene Nachweise sind damit erzaehlbar, statt still zu
// schweigen, wenn gar keiner da war.
export function mergeClosureAddendum(freshDoc, newDoc) {
  if (!newDoc || typeof newDoc !== "object" || Array.isArray(newDoc)) return { doc: newDoc, carried: 0 };
  const fresh = new Map();
  for (const row of Array.isArray(freshDoc?.ledgerStats) ? freshDoc.ledgerStats : []) {
    if (!isForeignProof(row) || !Number.isFinite(row.l)) continue;
    fresh.set(row.l, row);
  }
  let carried = 0;
  for (const row of Array.isArray(newDoc.ledgerStats) ? newDoc.ledgerStats : []) {
    if (!row || typeof row !== "object" || !Number.isFinite(row.l)) continue;
    const src = fresh.get(row.l);
    if (!src) continue;
    if (isOwnProof(row)) {
      // Derselbe Hash von zwei Autoritaeten ist eine Deckung, kein Ersatz: die Fremdquelle darf
      // den eigenen Beweis bestaetigen, aber nie verdraengen.
      if (src.ch === row.ch && row.chVerifiedBy === undefined && typeof src.chVerifiedBy === "string") {
        row.chVerifiedBy = src.chVerifiedBy;
        carried += 1;
      }
      continue;
    }
    if (row.chSource !== undefined) continue; // die neue Zeile traegt bereits ihre eigene Quelle
    for (const k of ADDENDUM_FIELDS) if (src[k] !== undefined) row[k] = src[k];
    carried += 1;
  }
  // Ein nachgetragener Schliess-Nachweis gehoert dem Tag, nicht dem Schreibvorgang. Ohne
  // dieses Nachtragen wuerde der naechste Flush des Recorders die von backfill-closure.mjs
  // belegten closureProofs wieder aus der Tagesdatei entfernen.
  const carriedProofs = new Map();
  for (const row of Array.isArray(newDoc.closureProofs) ? newDoc.closureProofs : []) {
    if (row && typeof row === "object" && Number.isFinite(row.l)) carriedProofs.set(row.l, row);
  }
  for (const row of Array.isArray(freshDoc?.closureProofs) ? freshDoc.closureProofs : []) {
    if (!row || typeof row !== "object" || !Number.isFinite(row.l) || carriedProofs.has(row.l)) continue;
    (newDoc.closureProofs ??= []).push(row);
    carriedProofs.set(row.l, row);
  }
  return { doc: newDoc, carried };
}

// Lokaler Schreibpfad des Recorders: Bestand lesen, Nachtrag zurueckfuehren, atomar schreiben.
// Derselbe Grund wie in lib/history.mjs: ein fester tmp-Name pro Tag verzahnt zwei gleichzeitige
// Schreibende zu einer unparsebaren Tagesdatei.
let localWriteSeq = 0;
export function writeDayLocal(dir, day) {
  if (!dir) throw new Error("writeDayLocal: kein Datenordner.");
  if (!day || !/^\d{4}-\d{2}-\d{2}$/.test(day.date)) throw new Error("writeDayLocal: ungueltiges Tagesobjekt.");
  const file = path.join(dir, day.date + ".json");
  let fresh = null;
  try { fresh = normalizeDay(JSON.parse(fs.readFileSync(file, "utf8"))); } catch { fresh = null; }
  const { carried } = mergeClosureAddendum(fresh, day);
  const text = JSON.stringify(day);
  const tmp = `${file}.${process.pid}.${Date.now()}.${++localWriteSeq}.tmp`;
  try {
    fs.writeFileSync(tmp, text);
    if (fs.statSync(tmp).size !== Buffer.byteLength(text, "utf8")) {
      throw new Error("Schreibpruefung: tmp-Datei hat eine andere Byte-Laenge.");
    }
    fs.renameSync(tmp, file);
  } catch (err) {
    fs.rmSync(tmp, { force: true });
    throw err;
  }
  return carried;
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
  const span = { "1h": 3600000, "24h": 86400000, "7d": 7 * 86400000, "30d": 30 * 86400000, all: Infinity }[range] ?? 86400000;
  const from = span === Infinity ? now - (TRACE_RETENTION_DAYS - 1) * 86400000 : now - span;
  return datesBetween(from, now);
}

export async function saveDayRemote(day) {
  if (!day || !/^\d{4}-\d{2}-\d{2}$/.test(day.date)) throw new Error("saveDayRemote: ungültiges Tagesobjekt.");
  // 'apply' erhaelt den FRISCH gelesenen Bestand: derselbe Nachtrag-Schutz wie lokal. Wer hier
  // ungeprueft das eigene Tag zurueckgibt, ueberschreibt, was ein anderer Schreibender
  // nachgetragen hat.
  await writeGitHubContents((fresh) => mergeClosureAddendum(normalizeDay(fresh), day).doc, dayPath(day.date), jsonCodec);
  return true;
}

export async function loadDayRemote(date) {
  const { doc } = await readGitHubContents(dayPath(date), jsonCodec);
  // Normalisierung ist Teil des Lesens, nicht des Schreibens: einem Tag aus einer älteren
  // Recorder-Stufe fehlen die dort nicht gezählten Werte, und jeder Leser müsste sie
  // sonst selbst ergänzen. Der Recorder tut es bereits - ein Pfad, der es nicht tut, zeigt
  // gefüllte Achsen als Lücke.
  return doc ? normalizeDay(doc) : doc;
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
