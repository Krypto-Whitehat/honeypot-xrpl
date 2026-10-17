// monitor/validator-trace.mjs — Dauer-Recorder für den Validator-Trace (dUNL, ledger-genau).
//
// Start:   node monitor/validator-trace.mjs          (Node >= 22: globales WebSocket)
// Testlauf: TRACE_RUN_SECONDS=300 node monitor/validator-trace.mjs
//
// Speicher:
//   - mit GITHUB_HISTORY_TOKEN: data/validator-trace/YYYY-MM-DD.json per API im PRIVATEN Daten-Repo
//     (lib/validator-trace-store.mjs), Flush alle 5 min, nur geänderte Tage.
//   - ohne Token: Dateien in TRACE_DATA_DIR (Standard data/validator-trace), Flush alle 30 s.
//     Der Workflow klont das Daten-Repo und committet diesen Ordner per Deploy-Key.
// Lücken: Kommt nach einem Ledger-Index ein größerer Sprung, wird die fehlende Spanne als
// 'gap' gespeichert. Ohne diese Markierung sähe Stille wie 'alle Validatoren ok' aus.
// Stillstand: ein Mithoerer kann offen bleiben, ohne noch Nachrichten zu liefern. Der
// Waechter unten erkennt das und trennt selbst; ohne ihn saesse Stille bis zum Laufende.
// Aufbewahrung: 365 Tage (lokal: Dateien löschen, remote: pruneRemote einmal täglich).
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { addLedgerRiskSample, createTracker, TRACE_DEFAULTS } from "../lib/validator-trace.mjs";
import { classifyShape, createShapeTracker, SIGNATURE_TAGS } from "../lib/tx-forensics.mjs";
import { ANOMALY_TAGS, isAnomalyTag } from "../lib/validator-trace.mjs";
import { isSignatureTag } from "../lib/validator-retrace.mjs";
import { decodeValidatorList, nodePublicB58 } from "../lib/validator-health.mjs";
import { saveDayRemote, loadDayRemote, pruneRemote, traceTokenConfigured, normalizeDay, writeDayLocal } from "../lib/validator-trace-store.mjs";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const DATA_DIR = process.env.TRACE_DATA_DIR || path.join(ROOT, "data", "validator-trace");
const REMOTE = traceTokenConfigured();
const RETENTION_DAYS = 365;
const RIPPLE_EPOCH = 946684800;
// Validations-Stream: nur xrpld-Server liefern ihn (Clio wie honeycluster kann ihn
// NICHT — ein Clio-Fallback würde Ledger ohne Validations sehen und fälschlich
// 'alle verpasst' aufzeichnen). s1.ripple.com ist laut xrpl.org "not for sustained
// or business use" — ein Dauer-Stream ist genau das, daher xrplcluster (InFTF).
// Env TRACE_WSS (Komma-Liste) erlaubt einen anderen xrpld-Endpunkt ohne Code-Änderung.
const WSS = (process.env.TRACE_WSS || "wss://xrplcluster.com").split(",").map((s) => s.trim()).filter(Boolean);
// Ersatz-Endpunkte fuer den Fall, dass der Haupt-Endpunkt nichts mehr liefert. s1/s2 sind
// xrpld und damit validations-faehig, aber laut xrpl.org nicht fuer Dauerbetrieb - sie sind
// kein gleichwertiger Stream, sondern ein Notruf, und jede Umschaltung steht als
// Erfassungs-Ereignis in der Tagesdatei. Env TRACE_STREAM_FALLBACK_WSS=0 schaltet ihn ab.
const STREAM_FALLBACK_WSS = (process.env.TRACE_STREAM_FALLBACK_WSS ?? "wss://s1.ripple.com,wss://s2.ripple.com")
  .split(",").map((s) => s.trim()).filter((s) => s && s !== "0");
// Kein Ledger ist ein harter Grund: ein Socket kann offen sein, auf server_info antworten
// und trotzdem keine validierten Ledger liefern. Ein solcher Lauf darf nicht 5 h als Zombie
// die Cron-Warteschlange blockieren - sonst faellt das Overlay hinter die Chain zurueck.
const NO_LEDGER_MS = Math.max(5000, Number(process.env.TRACE_NO_LEDGER_MS) || 300000);
const NO_LEDGER_EXIT_MS = Math.max(10000, Number(process.env.TRACE_NO_LEDGER_EXIT_MS) || 900000);
const VL_URL = "https://vl.ripple.com";
const REGISTRY_URL = "https://api.xrpscan.com/api/v1/validatorregistry";
const DETAIL_QUEUE_MAX = 50;
// Transaktions-Forensik (die Form der Tx je Ledger) läuft über den "transactions"-Stream mit —
// ohne zusätzliche Ledger-Abfragen. Env TRACE_TX_SHAPE=0 schaltet sie ab (dann fehlt die Ebene
// vollständig und die Retrace weist das als Datenlücke aus, statt "keine Auffälligkeit" zu sagen).
const TX_SHAPE = process.env.TRACE_TX_SHAPE !== "0";
// Forensik-Detail je Ledger mit Abweichung. Der Deckel schützt die Tagesdatei; bei Erreichen
// wird die älteste Forensik verworfen und das offen markiert (nie still).
const LEDGER_STATS_CAP = 6000;
// Deckel fuer das Erfassungs-Ereignis-Protokoll: eine Verbindung kann je Tag mehrfach
// fallen. 400 Zeilen sind weit ueber jedem beobachteten Tag und halten die Datei lesbar.
const CAPTURE_EVENT_CAP = 400;
// Spaet-Validierungen je Tag: 1.200 Eintraege sind bei ~20.000 Ledern ein Tag mit vielen
// spaeten Knoten. Aeltere Eintraege fallen zuerst (die jungsten sind die, die ein Betreiber
// gerade nachvollziehen will); die Verkuerzung ist markiert, nicht still.
const LATE_VOTES_CAP = 1200;
// Ledger-Ebene Anomalien inklusive der Transaktions-Signaturen: nur diese gehen in die
// Risikovergleichsrechnung ein (Wie oft fällt ein Ledger MIT dieser Form aus, im Vergleich zu
// Ledgern ohne sie). new-tx-type:* und type-burst:* sind über das Präfix zählbar.
// Die Vokabel kommt aus lib/validator-trace.mjs: Recorder und Analyse-Ebenen teilen dieselbe
// Menge, ein neuer Tag ist dort nicht nachzutragen.
const FLUSH_MS = REMOTE ? 300000 : 30000;
// dUNL-Nachzug: die Mitgliederliste aendert sich laufend, und jeder Knoten signiert mit einem
// Schluessel, der in festen Abstaenden neu ausgelost wird. Eine nur beim Start geladene Liste
// veraltet damit zwangslaeufig - ein gueltiger Vote wuerde als "kein beobachtetes Mitglied"
// gezaehlt und der Knoten als 'no-quorum' statt 'ok' gefuehrt. Env TRACE_DUNL_REFRESH_MS.
const DUNL_REFRESH_MS = Math.max(60000, Number(process.env.TRACE_DUNL_REFRESH_MS) || 600000);
const RUN_SECONDS = Number(process.env.TRACE_RUN_SECONDS) || 0;

// Stillstands-Grenze: XRPL schliesst alle 3-5 s ein Ledger, und der Validations-Strom laeuft
// dauernd. Ein Mithoerer, der ueber diese Frist gar keine Nachricht bringt, ist kein ruhiges
// Netz, sondern ein kaputter Mithoerer. Ohne diese Grenze sitzt der Rekorder bis zum
// Laufende still, und die Tagesdatei zeigt fuer die Zeit einfach nichts - das ist genau die
// Stelle, an der am 16.10.2026 1 h 50 min lang nichts aufgezeichnet wurde, waehrend der Job
// lief. Env TRACE_STALL_MS (Prueftakt: TRACE_STALL_CHECK_MS).
const STALL_MS = Math.max(5000, Number(process.env.TRACE_STALL_MS) || 90000);
const STALL_CHECK_MS = Math.max(1000, Number(process.env.TRACE_STALL_CHECK_MS) || 15000);
// Nach dem eigenen Trennen wird nur so lange auf onclose gewartet, bevor der Naechstversuch
// direkt gestartet wird - ein halb offener Socket antwortet unter Umstaenden gar nicht mehr.
const STALL_RECONNECT_MS = 20000;
// Betriebs-Bericht je STAT_MS (Env TRACE_STAT_MS): ohne ihn laeuft der Rekorder stumm, und
// ein Ersatz-Endpunkt oder eine Messung blieben unsichtbar, obwohl sie in der Datei stehen.
const STAT_MS = Math.max(5000, Number(process.env.TRACE_STAT_MS) || 60000);

const log = (...a) => console.log(new Date().toISOString(), ...a);
const toMs = (rippleSec) => (Number(rippleSec) + RIPPLE_EPOCH) * 1000;
const dayOf = (ms) => new Date(ms).toISOString().slice(0, 10);

// ---------- dUNL-Mitglieder ----------
async function loadMembers() {
  const vl = decodeValidatorList(await (await fetch(VL_URL, { signal: AbortSignal.timeout(10000) })).json());
  if (!vl || !vl.keys.length) throw new Error("Validator-Liste leer oder nicht lesbar");
  const reg = await (await fetch(REGISTRY_URL, { signal: AbortSignal.timeout(10000) })).json();
  const byMaster = new Map(reg.filter((r) => r && r.master_key).map((r) => [r.master_key, r]));
  const members = [];
  const ephemeralToMaster = new Map();
  const unmatched = [];
  for (const hex of vl.keys) {
    const master = nodePublicB58(hex);
    const r = master && byMaster.get(master);
    if (!r) { unmatched.push(hex.slice(0, 12)); continue; }
    members.push(master);
    if (typeof r.ephemeral_key === "string") ephemeralToMaster.set(r.ephemeral_key, master);
  }
  return { members, ephemeralToMaster, listed: vl.keys.length, sequence: vl.sequence, unmatched };
}

// ---------- Tagesobjekte ----------
const days = new Map();   // date -> Tagesobjekt
const dirty = new Set();  // Daten, die beim nächsten Flush geschrieben werden müssen
let lastLedger = null;    // letzter gesehener Ledger-Index (für Lückenerkennung)

function emptyDay(date) {
  return { date, ledgers: 0, quorumFail: 0, validators: {}, incidents: [], gaps: [], captureEvents: [], captureEventsTruncated: false, lastLedger: null, firstMs: null, lastMs: null, hourly: {},
    // Forensik + Anomalie-Zähler: die Grundlage jeder Retrace. Ohne sie ist die Frage
    // 'warum verpasst?' aus der Aufzeichnung nicht beantwortbar.
    ledgerStats: [], ledgerStatsTruncated: false, incidentLedgers: 0, anomaly: {}, anomalyFail: {},
    // Marker, nicht Zaehler: dieser Tag fuehrt die Signatur-Ebene. Ein Tag ohne diesen Marker
    // (Altbestand) wurde nie auf Anomalien geprueft - das ist etwas anderes als 'geprueft und
    // keine gefunden'. Die Risikuebene braucht die Unterscheidung fuer ihre Vergleichsgruppe.
    anomalyRecorded: true,
    // Abdeckung der Transaktions-Forensik: wie viele Ledger wirklich eine Tx-Form haben und wie
    // viele erwartet, aber nicht erfasst wurden. Ohne diese Zähler wäre "keine Signatur" nicht
    // von "keine Beobachtung" zu trennen.
    shapeSeen: 0, shapeMissing: 0,
    // Netz-Anker des Endpunkts, an dem dieser Rekorder haengt (server_info -> validations.quorum).
    // Ohne diesen Wert ist 'Stimmen / needed' eine eigene Zielgroesse und darf nie als Netz-Quorum
    // gelesen werden. Fehlend bleibt fehlend: null heisst 'nicht erfasst', nicht 'kein Quorum'.
    networkQuorum: null, networkQuorumSamples: 0, networkQuorumAttempts: 0,
    // Spaet-Validierungen je Tag: { l: Ledger, m: Master, ms: Latenz nach dem Close, t: Ankunft }.
    // Ohne diese Liste ist die Frage "zu spaet abgestimmt oder nie abgestimmt?" aus der
    // Aufzeichnung nicht beantwortbar.
    lateVotes: [], lateVotesTruncated: false,
    // Feature-Zähler über ALLE beobachteten Ledger: Nenner und Zähler für die Frage, ob Ledger mit
    // einem bestimmten Amendment (oder UNLModify) häufiger ausfallen. Aus der Detail-Abfrage allein
    // wären Nenner und Zähler identisch - der Lift wäre dann per Definition 1,0.
    featureLedgers: {}, featureFail: {} };
}
function dayObj(date) {
  if (!days.has(date)) {
    let obj = null;
    if (!REMOTE) {
      try { obj = JSON.parse(fs.readFileSync(path.join(DATA_DIR, date + ".json"), "utf8")); } catch { obj = null; }
    }
    // Altbestand (vor der Forensik-Stufe) hat diese Felder nicht -> angleichen, damit die
    // Retrace sie nie als „beobachtet: 0“ missdeutet, sondern als „nicht erfasst“.
    if (obj) normalizeDay(obj);
    days.set(date, obj ?? emptyDay(date));
  }
  return days.get(date);
}
let MEMBERS = [];
function recordResult(r, detailNote) {
  const date = dayOf(r.closeMs);
  const d = dayObj(date);
  // Transaktions-Forensik vor der Zählung: die FORM der Tx ist die Ledger-seitige Mitursache
  // (Fächerung eines Drainers, Orderbuch-Flut, Fehlerrate, Batch-Verstärkung, Netzwerk-Ebene).
  // Sie gilt für jedes Ledger, nicht nur für die mit Abweichung — nur so ist der
  // Risikovergleich "Ausfallwahrscheinlichkeit mit Signatur gegen ohne" überhaupt möglich.
  const shapeRes = TX_SHAPE ? shapeTracker.commit(r.ledgerIndex) : null;
  const shapeTags = shapeRes ? classifyShape(shapeRes.form, shapeRes.base).map((x) => x.tag) : [];
  if (shapeRes?.sweep) shapeTags.push("sweep-window");
  if (shapeTags.length) {
    r.ledgerTags = [...new Set([...(r.ledgerTags ?? []), ...shapeTags])];
    for (const inc of r.incidents) inc.reasons = [...new Set([...(inc.reasons ?? []), ...shapeTags])];
  }
  // Ehrliche Lücke statt stiller Null: ein Ledger mit Tx, deren Form aber nicht beobachtet
  // wurde, ist "nicht erfasst" — ein Ledger ohne Tx ist dagegen wirklich leer.
  const shapeSeenNow = Boolean(shapeRes?.form);
  if (TX_SHAPE && shapeSeenNow) d.shapeSeen += 1;
  else if (TX_SHAPE && r.txCount > 0) d.shapeMissing += 1;
  d.ledgers += 1;
  if (!r.hasQuorum) d.quorumFail += 1;
  // Feature-Ebene dieses Ledgers aus dem Transaktions-Strom. Sie gilt für JEDES Ledger, nicht nur
  // für die mit Ausfall - sonst gibt es keinen Vergleich. Die Tags bleiben aus den Incident-Gründen
  // heraus: ein Amendment ist ein Ledger-Fakt, keine Ursache, die einem Vorfall angehängt wird.
  const feats = featureSeen.get(r.ledgerIndex);
  featureSeen.delete(r.ledgerIndex);
  const featureTags = [];
  if (feats) {
    for (const id of feats.amendments) featureTags.push("amendment:" + id.toUpperCase());
    if (feats.unlModify) featureTags.push("unl-modify");
  }
  for (const tag of featureTags) {
    d.featureLedgers[tag] = (d.featureLedgers[tag] ?? 0) + 1;
    if (r.incidents.length) d.featureFail[tag] = (d.featureFail[tag] ?? 0) + 1;
  }
  // Aufzeichnungsspanne + Stunden-Buckets: Stundenzähler machen die Overlay-
  // Zusammenfassung fenster-genau (Tageszähler können das nicht leisten).
  if (!d.firstMs || r.closeMs < d.firstMs) d.firstMs = r.closeMs;
  if (!d.lastMs || r.closeMs > d.lastMs) d.lastMs = r.closeMs;
  const hk = Math.floor(r.closeMs / 3600000);
  const hb = (d.hourly[hk] ??= { l: 0, v: {} });
  hb.l += 1;
  // Angriffs- und Last-Zähler je Stunde, aus derselben Quelle wie die Ausfall-Zähler. Ohne sie
  // ist die Zeit-Ebene (lib/attack-impact.mjs) auf die client-gemeldete History angewiesen —
  // und deren Cluster tragen nur firstSeen/lastSeen, also Stunden, an denen fast nie etwas
  // aufgezeichnet ist. Diese fünf Felder machen die Angriffsseite stunden-genau und damit
  // überhaupt vergleichbar. Sie werden nie auf 0 gesetzt, wenn die Ebene fehlt: fehlend bleibt
  // fehlend (null im Lesepfad), damit "nicht erfasst" nicht wie "keine Angriffe" aussieht.
  const hourTags = r.ledgerTags ?? [];
  const hourAnomaly = hourTags.some(isAnomalyTag);
  const hourSignature = hourTags.some(isSignatureTag);
  hb.a = (hb.a ?? 0) + (hourAnomaly ? 1 : 0);
  hb.s = (hb.s ?? 0) + (hourSignature ? 1 : 0);
  if (r.incidents.length) {
    hb.af = (hb.af ?? 0) + (hourAnomaly ? 1 : 0);
    hb.sf = (hb.sf ?? 0) + (hourSignature ? 1 : 0);
  }
  hb.tx = (hb.tx ?? 0) + (Number(r.txCount) || 0);
  hb.mx = Math.max(hb.mx ?? 0, Number(r.txCount) || 0);
  // Netz-Vote-Latenz je Stunde, ueber ALLE Ledger (nicht nur die mit Abweichung): die Referenz,
  // an der "mein Vote war spaet" erst ein Vergleich hat. fvN = Ledger mit Vote-Zeitstempel,
  // fvS = Summe der Latenz des ersten Netzvotes, fvX = Maximum, fvL = Ledger, deren erster Vote
  // erst nach dem Gnadenfenster eintraf. Fehlend bleibt fehlend: ein Tag ohne diese Felder hat
  // keine Netzlatenz aufgezeichnet, nicht "Latenz null".
  const firstVote = r.forensics?.firstVoteMs;
  if (Number.isFinite(firstVote)) {
    hb.fvN = (hb.fvN ?? 0) + 1;
    hb.fvS = (hb.fvS ?? 0) + firstVote;
    hb.fvX = Math.max(hb.fvX ?? 0, firstVote);
    hb.fvL = (hb.fvL ?? 0) + (firstVote > TRACE_DEFAULTS.graceMs ? 1 : 0);
  }
  const bad = new Set(r.incidents.map((i) => i.master));
  // Last- UND Quorum-Achse je Ledger (nicht nur je Ausfall-Ledger): die Ausfallrate pro Tx-Stufe
  // sagt, ab welcher Last ein Knoten zurueckfaellt; die Ausfallrate pro Quorum-Reserve sagt, ab
  // welcher Quorum-Knappe er zurueckfaellt. Beide aus demselben Ledger, sonst vergleicht die
  // Risikoflaeche Last und Quorum auf verschiedenen Ledger-Mengen. margin kommt aus der
  // Quorum-Forensik, die fuer JEDES bewertete Ledger anfaellt - sie wurde bisher nur fuer
  // Ausfall-Ledger gespeichert, wodurch die Margin-Analyse ohne Nenner dastand.
  addLedgerRiskSample(d, { txCount: r.txCount, margin: r.forensics?.margin ?? null, failedMasters: [...bad] });
  for (const m of MEMBERS) {
    const v = (d.validators[m] ??= { ok: 0, partial: 0, missed: 0, wrongHash: 0, noQuorum: 0 });
    const hv = (hb.v[m] ??= { ok: 0, partial: 0, missed: 0, wrongHash: 0, noQuorum: 0 });
    if (!bad.has(m)) { v.ok++; hv.ok++; }
  }
  for (const inc of r.incidents) {
    const v = d.validators[inc.master];
    const hv = hb.v[inc.master];
    if (inc.type === "missed") { v.missed++; hv.missed++; }
    else if (inc.type === "partial") { v.partial++; hv.partial++; }
    else if (inc.type === "wrong-hash") { v.wrongHash++; hv.wrongHash++; }
    else if (inc.type === "no-quorum" || inc.type === "vote-not-observed") { v.noQuorum = (v.noQuorum ?? 0) + 1; hv.noQuorum = (hv.noQuorum ?? 0) + 1; }
    // vd: Latenz des eigenen Votes, wenn einer da war (partial / wrong-hash / spaeter missed-Vote).
    // null = kein Vote aufgezeichnet, nicht "schnell abgestimmt".
    // h: die Hash-Linie dieses Knotens in diesem Ledger. Ohne sie bleibt wrong-hash ein Etikett.
    d.incidents.push({ l: r.ledgerIndex, m: inc.master, t: r.closeMs, type: inc.type, r: inc.reasons, n: detailNote || undefined, vd: Number.isFinite(inc.voteDelayMs) ? inc.voteDelayMs : null, h: hexOrNull(inc.votedHash),
      // nc = die Schliess-Ebene dieses Ledgers hat die Schliessung ausdruecklich verneint. Ohne
      // dieses Feld am Incident waere die Aussage nach einem ledgerStats-Truncation nicht mehr
      // nachpruefbar, und normalizeDay duerfte 'no-quorum' nicht umstellen.
      nc: r.closed === false ? true : undefined,
      // aa am Vorfall selbst (2026-10-17): die Zuordnungs-Grenze haengt an der Forensik-Zeile,
      // und die Forensik-Liste ist gekuerzt (LEDGER_STATS_CAP). Traegt der Vorfall seinen Beleg
      // nicht mehr, wenn die Zeile herausfaellt, wird eine belegte Messung beim Lesen zur
      // offenen Frage - und eine offene Frage ist kein Knoten-Urteil. true | false | fehlend
      // sind drei verschiedene Aussagen und bleiben drei verschiedene Zustande.
      aa: r.forensics?.attributableAbsence === true ? true
        : r.forensics?.attributableAbsence === false ? false : undefined });
  }
  // Forensik je Ledger mit Abweichung: Quorum-Rand, Hash-Spaltung, Close-Abstand, Last und
  // die Betroffenheit je Typ. Das ist der Unterschied zwischen "Validator hat verpasst" und
  // "warum er verpasst hat".
  if (r.incidents.length) {
    d.incidentLedgers += 1;
    if (d.ledgerStats.length >= LEDGER_STATS_CAP) { d.ledgerStats.shift(); d.ledgerStatsTruncated = true; }
    const f = r.forensics ?? {};
    d.ledgerStats.push({
      l: r.ledgerIndex, t: r.closeMs,
      v: f.votes ?? 0, need: f.needed ?? 0, top: f.topVotes ?? 0, mg: f.margin ?? 0,
      // mm: die dUNL-Groesse, aus der 'need' gerechnet wurde (need = ceil(mm * quorumFrac)).
      // Ohne sie ist 'need' eine Zahl ohne Herleitung und die Quorum-Reserve nicht nachrechenbar.
      mm: Number.isFinite(f.members) ? f.members : null,
      // nb/nq: die Herleitung des Quorum-Ziels und der gemessene Netz-Wert dahinter. Ohne nb
      // ist need in dieser Zeile eine Zahl ohne Herkunft, und die Leseschicht muss
      // "not-recorded" sagen statt sie als Netz-Quorum zu lesen.
      nb: typeof f.neededBasis === "string" ? f.neededBasis : null,
      nq: Number.isFinite(f.networkQuorum) ? f.networkQuorum : null,
      sp: f.runnerVotes ?? 0, gap: r.closeGapMs ?? null, gmed: r.medianGap ?? null,
      // Schliess-Beweis dieses Ledgers: ch ist der Hash aus dem validierten Stream (die Autoritaet,
      // an der jede Zeile nachpruefbar ist), cl sagt, dass das Netz geschlossen hat, cg markiert die
      // Erfassungs-Luecke dieses Rekorders, ov zaehlt alle gesehenen Validierungen inklusive der
      // Signierer ausserhalb der beobachteten dUNL. Ohne diese vier Felder waere 'no vote' eine
      // Behauptung ueber das Netz statt eine Aussage ueber die eigene Beobachtung.
      ch: f.closedHash ?? null, cl: f.closed === true, cg: f.captureGap === true,
      // pg: der zuvor ausgewertete Ledger-Index. 'cg' ist damit nachrechenbar: die Luecke gilt
      // genau dann, wenn pg !== l - 1. Ohne pg waere 'cg' ein Etikett ohne Zahl, und die
      // Leseschicht (ledgerClosure) koennte die Luecke nicht gegen die Index-Folge pruefen.
      pg: Number.isFinite(f.previousLedger) ? f.previousLedger : null,
// so: dieser Ledger wurde als erster nach einem Abo ausgewertet - die Stimmen vor dem
      // Abo fehlen in dieser Zeile, und die Zeile sagt es.
      so: f.streamOpenCapture === true,
      ov: Number.isFinite(f.observedValidations) ? f.observedValidations : null,
      // Eigene Empfangs-Bilanz dieses Ledgers: ovb = Median der Validierungen, die dieser
      // Rekorder in seinen letzten Ledgern empfangen hat, ot = true wenn ov unter diesem
      // Niveau liegt. Ohne diese Felder ist '16 / 28' eine Zahl, die niemand einordnen kann -
      // mit ihnen ist sie eine gegen die eigene Messung eingeordnete Beobachtung. ov selbst
      // bleibt die Zahl dieses Ledgers; ovb ist dieselbe Groesse, nur als Median.
      ovb: Number.isFinite(f.observedBaseline) ? f.observedBaseline : null,
      ot: f.receptionThin === true,
      // Abdeckungs-Bilanz, damit 'missed' in dieser Datei eine nachrechenbare Zahl ist und keine
      // Behauptung: ms = dUNL-Mitglieder mit angekommenem Vote, cb = das eigene Abdeckungs-Niveau
      // (Median der letzten Ledger ohne eigene Erfassungs-Luecke), gm = wie viele Mitglieder laut
      // Schliess-Beweis hoechstens echt fehlen koennen, aa = true nur wenn ein fehlender Vote in
      // diesem Ledger als Knoten-Befund zaehlen darf. Fehlen diese Felder, ist die Zuordnung offen.
      ms: Number.isFinite(f.membersSeen) ? f.membersSeen : null,
      cb: Number.isFinite(f.coverageBaseline) ? f.coverageBaseline : null,
      gm: Number.isFinite(f.genuineAbsentMaxLedger) ? f.genuineAbsentMaxLedger : null,
      aa: f.attributableAbsence === true,
      tx: r.txCount ?? 0, med: r.medianTx ?? 0,
      c: f.counts ?? { missed: 0, partial: 0, wrongHash: 0, noQuorum: 0 },
      // Tx-Form und die Belege der Signaturen, die in diesem Ledger feuerten. Die Konto-Adresse
      // selbst wird nicht gespeichert: die Signatur ist eine Form-Aussage, kein Konto-Report.
      sh: shapeRes?.form ? (({ n, s, d: dst, fo, fd, fa, fl, ac, oc, nf, bt, bi, fx, fm, fs }) => ({ n, s, d: dst, fo, fd, fa, fl, ac, oc, nf, bt, bi, fx, fm, fs }))(shapeRes.form) : null,
      sev: shapeRes ? Object.fromEntries(classifyShape(shapeRes.form, shapeRes.base).map((x) => [x.tag, x.evidence])) : {},
      sweep: shapeRes?.sweep ?? null,
      // Vote-Latenz des Netzes in diesem Ledger: erster und letzter Vote nach dem Close.
      // fv ist die Referenz, an der "mein Vote war spaet" erst ein Vergleich hat.
      fv: f.firstVoteMs ?? null, lv: f.lastVoteMs ?? null,
      // ah/rh: die Netzmehrheit und die Runner-Up-Linie dieses Ledgers. Zusammen mit dem Vote-Hash
      // der Incidents ergibt sich die Divergenz-Klasse jedes Vorfalls.
      ah: hexOrNull(f.acceptedHash), rh: hexOrNull(f.runnerHash),
      // am/unl: die Feature-Fakten DIESSES Ledgers, aus dem Transaktions-Strom; falls dort nichts
      // ankam, die nachträglich abgerufenen Amendment-IDs der Detail-Abfrage.
      am: feats && feats.amendments.size ? [...feats.amendments].map((x) => x.toUpperCase())
        : (Array.isArray(r.amendments) ? r.amendments.filter((x) => typeof x === "string" && HEX64.test(x)).map((x) => x.toUpperCase()) : []),
      unl: feats ? feats.unlModify === true : false,
    });
  }
  // Anomalie-Zähler auf Ledger-Ebene: Nenner und Zähler für den Risikovergleich. Ohne sie wäre
  // jede Ursache eine Einzelbeobachtung ohne Vergleichswert.
  for (const tag of r.ledgerTags ?? []) {
    if (!isAnomalyTag(tag)) continue;
    d.anomaly[tag] = (d.anomaly[tag] ?? 0) + 1;
    if (r.incidents.length) d.anomalyFail[tag] = (d.anomalyFail[tag] ?? 0) + 1;
  }
  d.lastLedger = r.ledgerIndex;
  dirty.add(date);
}

// Spaet-Validierung: eine Validation traf ein, nachdem dieses Ledger schon bewertet war
// (Gnadenfenster abgelaufen, Ledger noch im Bewertungs-Ring). Das ist die einzige Stelle,
// die "zu spaet abgestimmt" von "nie abgestimmt" trennen kann - und sie zaehlt fuer JE DEN
// Validator, damit die Latenz eines Knotens ein Netz-Vergleich hat.
// hb.l wird hier nicht erhoeht: der Ledger ist schon gezaehlt, nur sein spaeter Vote kam an.
function recordLateVotes(list) {
  for (const lv of list ?? []) {
    if (!lv || !Number.isFinite(lv.ledgerIndex) || !lv.master || !Number.isFinite(lv.closeMs)) continue;
    const ms = Number.isFinite(lv.delayMs) ? Math.round(lv.delayMs) : null;
    const date = dayOf(lv.closeMs);
    const d = dayObj(date);
    const hk = Math.floor(lv.closeMs / 3600000);
    const hb = (d.hourly[hk] ??= { l: 0, v: {} });
    const v = (d.validators[lv.master] ??= { ok: 0, partial: 0, missed: 0, wrongHash: 0, noQuorum: 0 });
    const hv = (hb.v[lv.master] ??= { ok: 0, partial: 0, missed: 0, wrongHash: 0, noQuorum: 0 });
    v.late = (v.late ?? 0) + 1;
    hv.late = (hv.late ?? 0) + 1;
    // Der Incident bekommt die Latenz und das Reason-Tag, wenn derselbe Knoten in diesem
    // Ledger ohne Vote gefuehrt ist: aus "verpasst" wird "verpasst, aber der Vote kam
    // nach der Bewertung an". Das ist ein anderer Befund - er zeigt einen langsamen Pfad,
    // keinen ausgefallenen Knoten. Beide Zaehler meanen dasselbe fuer den Zeitpunkt der
    // Bewertung (kein Vote gesehen); ob der Knoten schuld war, entscheidet die
    // Zuordnungsgrenze in lib/validator-trace.mjs, nicht die Spaetankunft. Ein Vorfall ohne
    // diese Nachtrag-Spur behauptet in der Datei weiter "kein Vote", obwohl einer ankam.
    const inc = d.incidents.find((i) => i.l === lv.ledgerIndex && i.m === lv.master
      && (i.type === "missed" || i.type === "vote-not-observed"));
    if (inc) {
      if (ms !== null) inc.vd = ms;
      inc.r = [...new Set([...(inc.r ?? []), "vote-late"])];
    }
    if (d.lateVotes.length >= LATE_VOTES_CAP) { d.lateVotes.shift(); d.lateVotesTruncated = true; }
    // h/fu: auch der spaete Vote hat eine Linie. Ein spaeter Vote AUF der Netzmehrheit ist ein
    // langsamer Pfad; ein spaeter Vote auf einer anderen Linie heißt, der Knoten hat auf einem
    // anderen Stand abgestimmt - das ist ein anderer Fehler mit anderer naechsten Pruefung.
    d.lateVotes.push({ l: lv.ledgerIndex, m: lv.master, ms, t: Number.isFinite(lv.arrivalMs) ? lv.arrivalMs : null, h: hexOrNull(lv.hash), fu: lv.full !== false });
    dirty.add(date);
  }
}

// Lokal: alle Tage schreiben (atomar, mit Nachtrag-Schutz). Remote: nur geänderte Tage, Fehler bleiben dirty.
async function flush() {
  if (REMOTE) {
    for (const date of [...dirty]) {
      try { await saveDayRemote(days.get(date)); dirty.delete(date); }
      catch (e) { log("Speichern fehlgeschlagen (", date, "), neuer Versuch im nächsten Takt:", e.message); }
    }
    return;
  }
  fs.mkdirSync(DATA_DIR, { recursive: true });
  for (const date of dirty) {
    // writeDayLocal liest vor dem Schreiben den Bestand und fuehrt den Schliess-Nachtrag
    // (ch/chSource/chVerifiedBy/chAt/xc) zurueck. Laeuft scripts/backfill-closure.mjs waehrend
    // dieses Recorders, war sein Nachweis bisher beim naechsten Flush weg - und damit auch die
    // einzige Autoritaet, die auf diesen Zeilen "Ledger geschlossen" sagt. Ohne diesen Schutz
    // koennte die Diagnose unbemerkt auf "Netzstockung" zurueckfallen.
    const carried = writeDayLocal(DATA_DIR, days.get(date));
    if (carried) log("Schliess-Nachtrag bewahrt:", carried, "Zeile(n) in", date, "- von aussen nachgetragen, nicht selbst gesehen");
  }
  dirty.clear();
}

function pruneLocal() {
  if (!fs.existsSync(DATA_DIR)) return;
  const cutoff = Date.now() - RETENTION_DAYS * 86400000;
  for (const f of fs.readdirSync(DATA_DIR)) {
    if (!/^\d{4}-\d{2}-\d{2}\.json$/.test(f)) continue;
    if (Date.parse(f.slice(0, 10)) < cutoff) { fs.unlinkSync(path.join(DATA_DIR, f)); log("gelöscht (Aufbewahrung)", f); }
  }
}

// ---------- WebSocket ----------
let ws = null;
let lastMessageAt = 0;   // letzte Stream-Nachricht; 0 heisst 'noch keine', nie 'kein Strom'
let lastLedgerAt = 0;    // letzte validierte Ledger-Meldung; 0 heisst 'noch keine'
let streamTier = 0;      // 0 = Haupt-Endpunkte, 1 = Ersatz-Endpunkte (Notruf)
let currentUrl = null;   // Endpunkt der aktiven Verbindung (steht in den Erfassungs-Ereignissen)
let currentUrlIdx = 0;   // Position in der Endpunkt-Liste (Rotation nach einem Stillstand)
let connSeq = 0;         // Nummer der aktiven Verbindung; verhindert zwei Mithoerer nebeneinander
let rpcId = 100;
const rpcPending = new Map();
let tracker = null;
const shapeTracker = createShapeTracker();
// Feature-Ebene je Ledger, aus dem Transaktions-Strom (kein zusätzlicher Stream, keine Abfrage):
// EnableAmendment und UNLModify sind die beiden Ledger, auf denen sich die Bewertungsregeln des
// Netzes ändern. Genau dort trennt sich ein Knoten, der ein Feature nicht trägt, von einem Knoten,
// der nur langsam ist. Der Ring ist ein Deckel, keine Auswahl: was herausfällt, ist nicht erfasst.
const FEATURE_RING = 4096;
const featureSeen = new Map();   // ledgerIndex -> { amendments: Set, unlModify: boolean }
function featureEntry(idx) {
  let e = featureSeen.get(idx);
  if (!e) {
    e = { amendments: new Set(), unlModify: false };
    featureSeen.set(idx, e);
    while (featureSeen.size > FEATURE_RING) featureSeen.delete(featureSeen.keys().next().value);
  }
  return e;
}
// Hash-Prüfung vor dem Speichern: die Validierungs-Hashes kommen von außen. Ein String, der kein
// 64-stelliges Hex ist, wäre in der Divergenz-Auswertung eine Linie, die es nicht gibt.
const HEX64 = /^[0-9A-Fa-f]{64}$/;
const hexOrNull = (x) => (typeof x === "string" && HEX64.test(x) ? x.toUpperCase() : null);
const stats = { validations: 0, ledgers: 0, connects: 0, txShape: 0, stalls: 0, streamFallbacks: 0 };
// Anzeigetext fuer die Netz-Quorum-Achse: 'nicht erfasst' ist eine Aussage ueber den Rekorder,
// 'kein Quorum' waere eine Aussage ueber das Netz und wird hier nie erzeugt.
const quorumSampleState = () => {
  const d = days.get(dayOf(Date.now()));
  const nq = d?.networkQuorum;
  if (nq && Number.isFinite(nq.quorum)) {
    const t = tracker ? tracker.quorum : null;
    return `${nq.quorum} (${nq.endpoint}), Ziel dieser Bewertung: ${t} (${tracker?.quorumBasis ?? "nicht erfasst"})`;
  }
  const a = d?.networkQuorumAttempts ?? 0;
  return a > 0 ? `nicht meldbar (${a} Versuche)` : "nicht erfasst";
};
let detailQueue = [];
let detailBusy = false;

function rpc(cmd, timeoutMs = 20000) {
  return new Promise((resolve, reject) => {
    if (!ws || ws.readyState !== 1) return reject(new Error("keine Verbindung"));
    const id = ++rpcId;
    const t = setTimeout(() => { rpcPending.delete(id); reject(new Error("timeout")); }, timeoutMs);
    rpcPending.set(id, (m) => { clearTimeout(t); m.error ? reject(new Error(m.error)) : resolve(m.result); });
    ws.send(JSON.stringify({ ...cmd, id }));
  });
}

async function fetchDetail(ledgerIndex) {
  const r = await rpc({ command: "ledger", ledger_index: ledgerIndex, transactions: true, expand: true });
  const txs = Array.isArray(r?.ledger?.transactions) ? r.ledger.transactions : [];
  const types = [...new Set(txs.map((t) => t.TransactionType).filter(Boolean))];
  const amendments = txs.filter((t) => t.TransactionType === "EnableAmendment").map((t) => t.Amendment).filter(Boolean);
  const unlModify = txs.some((t) => t.TransactionType === "UNLModify");
  return { types, amendments, unlModify };
}

// Serielle Detail-Warteschlange: Ergebnisse mit Incidents bekommen Ledger-Details vor dem Speichern.
function enqueue(result) {
  if (!result.detailNeeded) { recordResult(result); return; }
  if (detailQueue.length >= DETAIL_QUEUE_MAX) { recordResult(result, "detail-skipped"); return; }
  detailQueue.push(result);
  drainDetails();
}
async function drainDetails() {
  if (detailBusy) return;
  detailBusy = true;
  while (detailQueue.length) {
    const r = detailQueue.shift();
    let note;
    try {
      tracker.attachDetail(r, await fetchDetail(r.ledgerIndex));
    } catch {
      tracker.attachDetail(r, { types: [], amendments: [], unlModify: false });
      note = "detail-unavailable";
    }
    recordResult(r, note);
  }
  detailBusy = false;
}

// Netz-Anker: der Quorum-Wert, den der Endpunkt selbst meldet. Er wird aufgezeichnet, damit die
// beobachteten Stimmen eine Vergleichsgroesse haben, die nicht aus der eigenen Mitgliederliste
// kommt. Ein Fehler hier fuehrt zu keiner Aussage, sondern laesst den Wert fehlen.
// Geprueft am 2026-10-16 an den echten Endpunkten: xrplcluster.com (rippled 3.4.1) liefert
// validation_quorum 0 und gar kein validations-Objekt, s1.ripple.com und s2.ripple.com melden 28.
// Ein 0 ist dort "dieser Endpunkt meldet keinen Quorum", nicht "der Quorum ist 0" - die zweite
// Lesart wuerde jedes Ledger zur Quorum-Erfuellung machen. Deshalb: 0 und fehlend sind
// dasselbe (kein Wert), und der Versuch selbst wird im Tag gespeichert. Abwesenheit ist dann
// ein belegter Zustand, keine stille Luecke.
const QUORUM_PROBE_WSS = (process.env.TRACE_QUORUM_WSS ?? "wss://s1.ripple.com,wss://s2.ripple.com")
  .split(",").map((s) => s.trim()).filter(Boolean);
const readQuorum = (info) => {
  const q = Number(info?.validations?.quorum ?? info?.validation_quorum);
  return Number.isFinite(q) && q > 0 ? q : null;
};
// Einmal-Abfrage eines Ersatz-Endpunkts in einem eigenen kurzen Socket: der Stream-Endpunkt
// muss dafuer nicht umgestellt werden, und die Antwort bleibt dem meldenden Endpunkt zugeordnet.
function probeQuorum(url, timeoutMs = 15000) {
  return new Promise((resolve) => {
    let ws;
    try { ws = new WebSocket(url); } catch { return resolve(null); }
    let pending = null;
    const done = (v) => { clearTimeout(t); try { ws.close(); } catch {} resolve(v); };
    const t = setTimeout(() => done(null), timeoutMs);
    ws.onopen = () => { pending = 1; ws.send(JSON.stringify({ command: "server_info", id: 1 })); };
    ws.onmessage = (ev) => {
      let m; try { m = JSON.parse(ev.data); } catch { return; }
      if (m.id === pending) done(readQuorum(m.result?.info ?? m.result?.server_info ?? {}));
    };
    ws.onerror = () => done(null);
    ws.onclose = () => done(null);
  });
}
// attempts zaehlt jeden Versuch, samples nur die mit einem Wert. attempts > 0 und samples = 0
// ist die Aufzeichnung "dieser Tag hat keinen Netz-Quorum erfassen koennen".
async function recordQuorumAttempt(q, endpoint) {
  const d = dayObj(dayOf(Date.now()));
  d.networkQuorumAttempts = (d.networkQuorumAttempts ?? 0) + 1;
  // Der gemessene Wert geht sofort in die Bewertung ein. Ohne diesen Schritt bleibt die
  // Messung in der Tagesdatei liegen, waehrend need weiter aus der dUNL-Groesse gerechnet wird.
  if (tracker) tracker.setNetworkQuorum(q);
  if (q !== null) {
    d.networkQuorumSamples = (d.networkQuorumSamples ?? 0) + 1;
    if (!d.networkQuorum || d.networkQuorum.quorum !== q) {
      d.networkQuorum = { quorum: q, atMs: Date.now(), endpoint };
      log("Netz-Quorum:", q, "gemeldet von", endpoint);
    }
    // Der Marker steht schon in der Datei, nicht erst in der Lese-Angleichung: ein Tag mit
    // Wert ist ein erfasster Tag, auch ohne den Store dazwischen.
    d.networkQuorumSampled = true;
  }
  dirty.add(d.date);
  return q !== null;
}
async function sampleNetworkQuorum() {
  let q = null;
  try {
    q = readQuorum((await rpc({ command: "server_info" }))?.info ?? {});
    if (q === null) stats.quorumNoReport = (stats.quorumNoReport ?? 0) + 1;
  } catch (e) {
    stats.quorumSamplesFailed = (stats.quorumSamplesFailed ?? 0) + 1;
    log("server_info nicht lesbar:", String(e?.message ?? e).slice(0, 80));
  }
  if (q !== null) return recordQuorumAttempt(q, WSS[0]);
  for (const url of QUORUM_PROBE_WSS) {
    const alt = await probeQuorum(url);
    if (alt !== null) return recordQuorumAttempt(alt, url);
  }
  await recordQuorumAttempt(null, WSS[0]);
  log("Netz-Quorum nicht meldbar: Stream-Endpunkt", WSS[0], "und Ersatz",
    QUORUM_PROBE_WSS.length ? QUORUM_PROBE_WSS.join(",") : "keiner konfiguriert");
}


// dUNL nachziehen: dasselbe loadMembers wie beim Start, aber nachgetragen. Tracker und
// MEMBERS muessen zusammen wechseln - 'for (const m of MEMBERS)' zaehlt die Nenner, und ein
// Incident eines neuen Mitglieds sonst in d.validators ins Leere laufen wuerde.
async function refreshMembers() {
  const dunl = await loadMembers();
  const moved = tracker.setMembers(dunl.members, dunl.ephemeralToMaster);
  MEMBERS = dunl.members;
  if (moved.added || moved.removed) {
    log("dUNL nachgezogen: +", moved.added, "-", moved.removed, "=", moved.members, "Sequenz", dunl.sequence);
  }
  return dunl;
}

// Erfassungs-Ereignis: Trennung und Wiederaufbau des Mithoerstroms werden als Zahl
// aufgezeichnet, nicht nur in die Konsole geschrieben. Ohne diese Zeilen ist ein duennerer
// Empfang in einem gesehenen Ledger ('vf') nicht rueckverfolgbar - man muesste raten, ob in
// dieser Minute der Stream weg war. 'l' ist der zuletzt gesehene Index: er sagt, wo dieser
// Mithoerer stand, als die Verbindung riss.
function recordCaptureEvent(kind, url) {
  const atMs = Date.now();
  const d = dayObj(dayOf(atMs));
  if (d.captureEvents.length >= CAPTURE_EVENT_CAP) { d.captureEvents.shift(); d.captureEventsTruncated = true; }
  d.captureEvents.push({ e: kind, atMs, l: lastLedger, url });
  dirty.add(d.date);
}

function onLedgerClosed(m) {
  const idx = Number(m.ledger_index);
  if (lastLedger !== null && idx > lastLedger + 1) {
    const from = lastLedger + 1, to = idx - 1;
    const d = dayObj(dayOf(toMs(m.ledger_time)));
    d.gaps.push({ from, to, t: toMs(m.ledger_time), reason: "stream-gap" });
    dirty.add(d.date);
    log("Lücke in der Aufzeichnung:", from, "–", to);
  }
  if (lastLedger === null || idx > lastLedger) lastLedger = idx;
  tracker.onLedger({ ledgerIndex: idx, hash: m.ledger_hash, closeMs: toMs(m.ledger_time), txCount: Number(m.txn_count) || 0 });
}

function onMessage(ev) {
  let m;
  try { m = JSON.parse(ev.data); } catch { return; }
  if (m.id && rpcPending.has(m.id)) { const cb = rpcPending.get(m.id); rpcPending.delete(m.id); cb(m); return; }
  // Ab hier gilt die Nachricht als Lebensbeweis des Mithoerers. RPC-Antworten zaehlen bewusst
  // nicht: ein Socket, der auf server_info noch antwortet, kann seine Subscription verloren haben.
  lastMessageAt = Date.now();
  if (m.type === "validationReceived") {
    stats.validations++;
    tracker.onValidation({
      signingKey: m.validation_public_key,
      ledgerIndex: Number(m.ledger_index),
      ledgerHash: m.ledger_hash,
      full: m.full !== false,
      t: toMs(m.signing_time),
    });
  } else if (m.type === "ledgerClosed") {
    stats.ledgers++;
    lastLedgerAt = Date.now();
    onLedgerClosed(m);
  } else if (m.type === "transaction" && TX_SHAPE) {
    stats.txShape++;
    // Tx dem Ledger zuordnen, in dem sie validiert wurden. Fehlt die Indexangabe, gehört sie
    // zum zuletzt geschlossenen Ledger — nie zu einem erfundenen.
    const txIdx = Number(m.ledger_index ?? lastLedger);
    shapeTracker.addTxTo(txIdx, m);
    if (Number.isFinite(txIdx)) {
      if (m.TransactionType === "EnableAmendment" && typeof m.Amendment === "string" && HEX64.test(m.Amendment)) featureEntry(txIdx).amendments.add(m.Amendment);
      else if (m.TransactionType === "UNLModify") featureEntry(txIdx).unlModify = true;
    }
  }
}

function connect(urlIdx = 0, backoff = 1000) {
  const list = streamTier === 1 && STREAM_FALLBACK_WSS.length ? STREAM_FALLBACK_WSS : WSS;
  const url = list[urlIdx % list.length];
  connSeq++;
  const mySeq = connSeq;
  currentUrl = url;
  currentUrlIdx = urlIdx % WSS.length;
  lastMessageAt = Date.now();
  ws = new WebSocket(url);
  ws.onopen = () => {
    stats.connects++;
    recordCaptureEvent("open", url);
    log("verbunden", url);
    backoff = 1000;
    lastMessageAt = Date.now();
    const streams = ["validations", "ledger"];
    if (TX_SHAPE) streams.push("transactions");
    // Der Abo-Zeitpunkt ist die Autoritaet fuer die Warm-Lauf-Luecke: nur was nach diesem
    // Abo lief, kann in diesem Ledger angekommen sein.
    if (tracker) tracker.markStreamOpen();
    ws.send(JSON.stringify({ id: 1, command: "subscribe", streams }));
    sampleNetworkQuorum();
  };
  ws.onmessage = onMessage;
  ws.onclose = () => {
    // Eine ersetzte Verbindung (Notruf nach Stillstand) darf keinen zweiten Mithoerer starten.
    if (mySeq !== connSeq) return;
    recordCaptureEvent("close", url);
    log("getrennt, neuer Versuch", list[(urlIdx + 1) % list.length]);
    setTimeout(() => {
      // Ein nachlaufender Nachzug einer ersetzten Verbindung darf keinen zweiten Mithoerer
      // oeffnen: zwei Sockets auf denselben Streams wuerden jede Nachricht zweigwaehlt
      // zaehlen. Nur die Verbindung, die noch die aktuelle ist, darf nachziehen.
      if (mySeq !== connSeq) return;
      connect(urlIdx + 1, Math.min(backoff * 2, 60000));
    }, backoff);
  };
  // Ein Fehler war bisher verschluckt. Er ist keine Aussage ueber das Netz, aber er ist ein
  // Grund, warum nichts ankommt - deshalb wird er genannt, nicht ignoriert.
  ws.onerror = (e) => { log("Stream-Fehler", url, e && e.message ? e.message : "(ohne Grund)"); };
}

// Stillstands-Waechter: prueft, ob der Mithoerer noch Nachrichten hoert. Node 22 kennt hier nur
// close() - terminate() existiert am globalen WebSocket nicht (gemessen am echten Endpunkt am
// 16.10.2026: typeof ws.terminate === undefined, close() loest onclose nach 0,5 s aus). Das
// eigene Trennen loest denselben Reconnect-Pfad aus wie ein gerissener Socket, inklusive
// Endpunkt-Rotation. Das Ereignis bleibt als Erfassungs-Ereignis 'stall' in der Tagesdatei.
function watchStream() {
  if (!ws || ws.readyState === WebSocket.CLOSING || ws.readyState === WebSocket.CLOSED) return;
  const idleMs = Date.now() - lastMessageAt;
  if (idleMs < STALL_MS) return;
  const seq = connSeq;
  stats.stalls++;
  recordCaptureEvent("stall", currentUrl);
  log("Stream still:", Math.round(idleMs / 1000), "s keine Nachricht von", currentUrl, "-> Verbindung wird neu aufgebaut");
  try { ws.close(); } catch {}
  setTimeout(() => {
    if (connSeq !== seq) return;   // onclose hat bereits neu verbunden
    log("Reconnect nach Stillstand blieb aus -> direkter Naechstversuch");
    connect(currentUrlIdx + 1, 1000);
  }, STALL_RECONNECT_MS);
}

// Abbruch mit gespeichertem Stand: ein Lauf, der nichts mehr hoert, darf keine Daten
// verlieren und darf die Cron-Warteschlange nicht als Zombie blockieren.
let bailing = false;
async function bail(code, reason) {
  if (bailing) return;
  bailing = true;
  log("Abbruch:", reason);
  try { await flush(); } catch {}
  if (ws) { try { ws.close(); } catch {} }
  process.exit(code);
}

// Ledger-Waechter: der Stillstands-Waechter hoert auf Nachrichten, dieser hoert auf Ledger.
// Ein Endpunkt kann offen bleiben, auf server_info antworten und trotzdem keine validierten
// Ledger liefern. Deshalb zuerst der Notruf auf die Ersatz-Endpunkte, dann der Abbruch.
function watchLedger() {
  const idleMs = Date.now() - lastLedgerAt;
  if (idleMs < NO_LEDGER_MS) return;
  if (streamTier === 0 && STREAM_FALLBACK_WSS.length) {
    streamTier = 1;
    stats.streamFallbacks++;
    recordCaptureEvent("stall", currentUrl);
    log("Kein Ledger seit", Math.round(idleMs / 1000), "s ueber", WSS.join(","),
      "-> Ersatz-Endpunkt", STREAM_FALLBACK_WSS.join(","), "(xrpld, Notruf, kein Dauerbetrieb)");
    if (ws) { try { ws.close(); } catch {} }
    connect(0, 1000);
    return;
  }
  if (idleMs >= NO_LEDGER_EXIT_MS) {
    bail(2, "kein Ledger seit " + Math.round(idleMs / 1000) + " s weder ueber " + WSS.join(",")
      + (STREAM_FALLBACK_WSS.length ? " noch ueber " + STREAM_FALLBACK_WSS.join(",") : "")
      + " - der naechste Cron-Lauf beginnt neu");
  }
}

// Remote-Start: heutiger und gestriger Tag werden geladen, damit Lücken-Erkennung und Zähler
// über Neustarts hinweg stimmen. Ein Lesefehler stoppt den Start (keine stille Lücke).
async function preloadRemote() {
  const today = dayOf(Date.now());
  const yesterday = dayOf(Date.now() - 86400000);
  for (const date of [yesterday, today]) {
    const doc = await loadDayRemote(date);
    // Direktes Setzen umgeht dayObj(): ohne Angleichung laufen die Forensik-Zaehler
    // dieses Tages auf NaN (in der Datei als null) und die Forensik-Liste fehlt ganz.
    if (doc) { days.set(date, normalizeDay(doc)); }
    const last = doc?.lastLedger;
    if (Number.isFinite(last)) lastLedger = lastLedger === null ? last : Math.max(lastLedger, last);
  }
}

// ---------- Start ----------
async function main() {
  log(REMOTE ? "Speicher: GitHub (Daten-Repo), Flush alle 5 min" : "Speicher: lokal data/validator-trace, Flush alle 30 s");
  log("Stillstands-Waechter:", STALL_CHECK_MS / 1000, "s Prueftakt, Grenze", STALL_MS / 1000, "s ohne Stream-Nachricht");
  log("Ledger-Waechter:", NO_LEDGER_MS / 1000, "s ohne Ledger -> Ersatz-Endpunkt",
    STREAM_FALLBACK_WSS.length ? STREAM_FALLBACK_WSS.join(",") : "keiner konfiguriert", "|",
    NO_LEDGER_EXIT_MS / 1000, "s ohne Ledger -> Abbruch dieses Laufs");
  const dunl = await loadMembers();
  log("dUNL", dunl.members.length, "von", dunl.listed, "zugeordnet, Sequenz", dunl.sequence, dunl.unmatched.length ? "unzugeordnet " + dunl.unmatched.join(",") : "");
  MEMBERS = dunl.members;
  tracker = createTracker({ members: dunl.members, ephemeralToMaster: dunl.ephemeralToMaster });
  if (REMOTE) await preloadRemote();
  else pruneLocal();  // Anlauf-Fenster: die Ledger-Grenze gilt ab Start, nicht ab "noch nie einen Ledger gesehen".
  lastLedgerAt = Date.now();
  connect();
  const evalTimer = setInterval(() => {
    for (const r of tracker.evaluate(Date.now())) enqueue(r);
    // Spaet-Validierungen nach der Bewertung abholen: derselbe Takt, damit ein Vote, der
    // zwischen zwei Bewertungen eintrifft, nicht im naechsten Ledger untergeht.
    recordLateVotes(tracker.takeLateVotes());
  }, 5000);
  const flushTimer = setInterval(() => { flush(); }, FLUSH_MS);
  const pruneTimer = setInterval(() => { if (REMOTE) pruneRemote().catch(() => {}); else pruneLocal(); }, 86400000);
  const quorumTimer = setInterval(() => { sampleNetworkQuorum().catch(() => {}); }, 3600000);
  const dunlTimer = setInterval(() => { refreshMembers().catch(() => {}); }, DUNL_REFRESH_MS);
  const stallTimer = setInterval(() => { watchStream(); }, STALL_CHECK_MS);
  const ledgerTimer = setInterval(() => { watchLedger(); }, STALL_CHECK_MS);
  const statTimer = setInterval(() => {
    const s = tracker.stats();
    log(`validations=${stats.validations} ledgers=${stats.ledgers} Stills=${stats.stalls} Ersatz=${stats.streamFallbacks} Nicht-dUNL-Signaturen=${s.nonMemberSigners} offen=${s.pendingLedgers} bewertet=${s.lastEvaluated} Spaetvotes=${s.pendingLateVotes} verworfen=${s.lateVotesDropped} Netz-Quorum=${quorumSampleState()}`);
  }, STAT_MS);
  let stopping = false;
  const stop = async () => {
    if (stopping) return;
    stopping = true;
    clearInterval(evalTimer); clearInterval(flushTimer); clearInterval(statTimer); clearInterval(pruneTimer); clearInterval(quorumTimer); clearInterval(dunlTimer); clearInterval(stallTimer); clearInterval(ledgerTimer);
    await flush();
    if (ws) ws.close();
    log("beendet", dirty.size ? "(" + dirty.size + " Tage nicht gespeichert)" : ", gespeichert");
    process.exit(0);
  };
  process.on("SIGINT", stop);
  process.on("SIGTERM", stop);
  if (RUN_SECONDS) setTimeout(stop, RUN_SECONDS * 1000);
}

main().catch((e) => { console.error("Fehler:", e.message); process.exit(1); });
