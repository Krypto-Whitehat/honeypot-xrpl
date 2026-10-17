// lib/validator-trace-store.test.mjs — Persistenz-Hilfen des Trace (pure Teile, ohne Netzwerk).
import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  datesBetween, datesForRange, dayPath, normalizeDay, TRACE_RETENTION_DAYS, TRACE_DIR,
  ADDENDUM_FIELDS, ADDENDUM_SOURCE, mergeClosureAddendum, writeDayLocal, crossCheckNote,
} from "./validator-trace-store.mjs";

test("datesBetween: alle Tage inklusive Grenzen, neueste zuerst", () => {
  const to = Date.UTC(2026, 9, 8, 12);
  const from = Date.UTC(2026, 9, 6, 1);
  assert.deepEqual(datesBetween(from, to), ["2026-10-08", "2026-10-07", "2026-10-06"]);
});
test("datesForRange: 1h deckt den heutigen Tag ab, all ist auf die Aufbewahrung begrenzt", () => {
  const now = Date.UTC(2026, 9, 8, 0, 30);
  assert.deepEqual(datesForRange("1h", now), ["2026-10-08", "2026-10-07"].slice(0, datesForRange("1h", now).length));
  assert.equal(datesForRange("all", now).length, TRACE_RETENTION_DAYS);
});
test("dayPath: Pfad im Daten-Repo, nie im Deploy-Repo-Root", () => {
  assert.equal(dayPath("2026-10-08"), TRACE_DIR + "/2026-10-08.json");
  assert.ok(TRACE_DIR.startsWith("data/"));
});

test("normalizeDay: Netz-Anker bleibt fehlend, wenn er nie erfasst wurde", () => {
  const doc = normalizeDay({ date: "2026-10-08", ledgers: 10 });
  assert.equal(doc.networkQuorum, null, "fehlend ist null, nicht 0 - ein 0 waere ein Quorum von null");
  assert.equal(doc.networkQuorumSamples, 0);
  assert.equal(doc.networkQuorumAttempts, 0);
  assert.equal(doc.networkQuorumSampled, false, "ein Tag ohne jeden Versuch gilt nicht als erfasst");
});

test("normalizeDay: fehlgeschlagene Versuche sind ein belegter Zustand, keine stille Luecke", () => {
  const doc = normalizeDay({ date: "2026-10-08", networkQuorum: null, networkQuorumSamples: 0, networkQuorumAttempts: 3 });
  assert.equal(doc.networkQuorumAttempts, 3);
  assert.equal(doc.networkQuorum, null);
  assert.equal(doc.networkQuorumSampled, false);
});

test("normalizeDay: ein gemeldeter Wert bleibt, ein 0-Wert wird zu fehlend", () => {
  const good = normalizeDay({ date: "2026-10-08", networkQuorum: { quorum: 28, endpoint: "wss://s1.ripple.com" }, networkQuorumSamples: 1, networkQuorumAttempts: 1 });
  assert.equal(good.networkQuorum.quorum, 28);
  assert.equal(good.networkQuorumSampled, true);
  const zero = normalizeDay({ date: "2026-10-08", networkQuorum: { quorum: 0, endpoint: "wss://xrplcluster.com" }, networkQuorumSamples: 1, networkQuorumAttempts: 1 });
  assert.equal(zero.networkQuorum, null, "quorum 0 ist 'Endpunkt meldet nichts', nicht 'Quorum ist 0'");
  assert.equal(zero.networkQuorumSampled, false);
});

/* NACHTRAG UND REKORDER SCHREIBEN DIESELBE DATEI.
 * scripts/backfill-closure.mjs traegt den Schliess-Beweis nach, der Rekorder haelt das Tages-
 * Objekt im Speicher und schreibt es alle 30 s neu. Laeuft der Nachtrag waehrend des Recorders,
 * war er bisher beim naechsten Flush weg - samt der einzigen Autoritaet, die auf diesen Zeilen
 * "Ledger geschlossen" sagt. Die Zahlen sind der echte Fall vom 16.10.2026: #107695059, 16 von
 * 28 erfassten Mitglieder-Stimmen, Hash 986E8D51...4602 (xrpscan, Gegenpruefer xrplcluster.com),
 * 52 Tx. */
const rowVet = (over) => ({
  l: 107695059, t: 1792154042000, v: 16, need: 28, top: 16, mg: -12, sp: 0, gap: 1000, gmed: 1000,
  tx: 52, med: 66.5, c: { missed: 0, partial: 0, wrongHash: 0, noQuorum: 19 }, ch: null, cl: true, ...over,
});
const dayDoc = (ledgerStats) => ({
  date: "2026-10-16", ledgers: 3, quorumFail: 1, gaps: [], incidents: [], hourly: {}, lastLedger: 107695059,
  validators: { nVET: { ok: 2, partial: 0, missed: 0, wrongHash: 0, noQuorum: 1 } }, ledgerStats,
});
const backfilled = (over) => ({
  ...rowVet(), ch: "986E8D51A78E8B2CB53B0FDBAE613692C7D33E3C82DCEE20A2C22D5496B34602", chSource: ADDENDUM_SOURCE, chVerifiedBy: "xrplcluster.com",
  chAt: "2026-10-16T16:43:16.765Z", xc: { hashAgree: true, tx: true, t: true, sourcesAgree: true, txScan: 52 }, ...over,
});

test("Nachtrag-Felder: genau die Nachweis-Felder, kein Zaehlerfeld", () => {
  assert.deepEqual(ADDENDUM_FIELDS, ["ch", "chSource", "chVerifiedBy", "chAt", "xc"]);
});

test("mergeClosureAddendum: der nachgetragene Schliess-Beweis ueberlebt den Flush", () => {
  const { doc, carried } = mergeClosureAddendum(dayDoc([backfilled()]), dayDoc([rowVet()]));
  const row = doc.ledgerStats[0];
  assert.equal(carried, 1);
  assert.equal(row.ch, "986E8D51A78E8B2CB53B0FDBAE613692C7D33E3C82DCEE20A2C22D5496B34602");
  assert.equal(row.chSource, ADDENDUM_SOURCE, "Fremdquelle bleibt als solche benannt");
  assert.equal(row.chVerifiedBy, "xrplcluster.com");
  assert.equal(row.xc.txScan, 52, "die Deckung der Tx-Zahl ist Teil des Nachweises");
});

test("mergeClosureAddendum: ein eigener Mithoerbeweis wird nicht von der Fremdquelle ersetzt", () => {
  const { doc, carried } = mergeClosureAddendum(dayDoc([backfilled()]), dayDoc([rowVet({ ch: "BBBBBBBBBBBBBBBB" })]));
  const row = doc.ledgerStats[0];
  assert.equal(row.ch, "BBBBBBBBBBBBBBBB", "der Hash aus dem validierten Stream ist die Autoritaet");
  assert.equal(row.chSource, undefined, "ein eigener Hash bekommt keine Fremdquelle angeheftet");
  assert.equal(row.chVerifiedBy, undefined, "ein abweichender Fremd-Hash ist keine Bestaetigung");
  assert.equal(carried, 0);
});

test("mergeClosureAddendum: derselbe Hash von beiden Autoritaeten nennt den Gegenpruefer", () => {
  const { doc, carried } = mergeClosureAddendum(
    dayDoc([backfilled()]), dayDoc([rowVet({ ch: "986E8D51A78E8B2CB53B0FDBAE613692C7D33E3C82DCEE20A2C22D5496B34602" })]));
  assert.equal(doc.ledgerStats[0].chVerifiedBy, "xrplcluster.com");
  assert.equal(doc.ledgerStats[0].chSource, undefined, "bestaetigt bleibt ein eigener Beweis mit Gegenpruefer");
  assert.equal(carried, 1);
});

test("mergeClosureAddendum: nur die Nachweis-Felder kommen zurueck, Zaehler bleiben die eigenen", () => {
  const fresh = dayDoc([backfilled()]);
  fresh.ledgers = 900; fresh.quorumFail = 77;
  fresh.validators = { nVET: { ok: 800, partial: 0, missed: 100, wrongHash: 0, noQuorum: 100 } };
  fresh.incidents = [{ l: 107695059, m: "nVET", t: 1, type: "no-quorum", r: [] }];
  const { doc } = mergeClosureAddendum(fresh, dayDoc([rowVet()]));
  assert.equal(doc.ledgers, 3, "was dieser Rekorder zaehlt, bleibt seine Zahl");
  assert.equal(doc.quorumFail, 1);
  assert.equal(doc.validators.nVET.ok, 2);
  assert.deepEqual(doc.incidents, [], "ein alter Incident-Vorrat darf nicht hochleben");
  assert.equal(doc.ledgerStats[0].ch, "986E8D51A78E8B2CB53B0FDBAE613692C7D33E3C82DCEE20A2C22D5496B34602");
});

test("writeDayLocal: der echte Flush verliert den nachgetragenen Nachweis nicht", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "vt-store-"));
  try {
    fs.writeFileSync(path.join(dir, "2026-10-16.json"), JSON.stringify(dayDoc([backfilled()]), null, 1), "utf8");
    const carried = writeDayLocal(dir, dayDoc([rowVet()]));
    assert.equal(carried, 1);
    const after = JSON.parse(fs.readFileSync(path.join(dir, "2026-10-16.json"), "utf8"));
    assert.equal(after.ledgerStats[0].ch, "986E8D51A78E8B2CB53B0FDBAE613692C7D33E3C82DCEE20A2C22D5496B34602");
    assert.equal(after.ledgerStats[0].chSource, ADDENDUM_SOURCE);
    assert.equal(after.ledgerStats[0].chVerifiedBy, "xrplcluster.com");
    assert.equal(after.ledgerStats[0].xc.txScan, 52);
    assert.equal(after.ledgers, 3, "der Nachtrag rettet keine Zaehler");
    assert.deepEqual(fs.readdirSync(dir).filter((f) => f.endsWith(".tmp")), [], "kein tmp-Uberrest");
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test("writeDayLocal: ohne Bestand wird die Zeile nicht erfunden", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "vt-store-"));
  try {
    const carried = writeDayLocal(dir, dayDoc([rowVet()]));
    assert.equal(carried, 0);
    const after = JSON.parse(fs.readFileSync(path.join(dir, "2026-10-16.json"), "utf8"));
    assert.equal(after.ledgerStats[0].ch, null, "ohne Nachweis bleibt die Zeile ohne Nachweis");
    assert.equal(after.ledgerStats[0].chSource, undefined);
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

/* Der Schutz wirkt nur, wenn der Rekorder ihn auch benutzt. Ein zweiter Schreibpfad am
 * Store vorbei waere genau der Fehler, den diese Pruefung verhindert. */
test("Recorder-Schreibpfad: der lokale Flush kennt den Nachtrag-Schutz", () => {
  const here = path.dirname(fileURLToPath(import.meta.url));
  const src = fs.readFileSync(path.join(here, "..", "monitor", "validator-trace.mjs"), "utf8");
  assert.match(src, /writeDayLocal\(DATA_DIR/, "der lokale Flush umgeht den Nachtrag-Schutz");
  assert.ok(!src.includes("fs.writeFileSync(tmp"), "der Rekorder schreibt Tagesdateien nicht mehr am Schutz vorbei");
  const store = fs.readFileSync(path.join(here, "validator-trace-store.mjs"), "utf8");
  assert.match(store, /mergeClosureAddendum\(normalizeDay\(fresh\), day\)/, "der ferne Schreibpfad ignoriert den frisch gelesenen Bestand");
});

const FULL_HASH = "986E8D51A78E8B2CB53B0FDBAE613692C7D33E3C82DCEE20A2C22D5496B34602";

/* Die Invariante des Schreibpfads: 'cl' und 'ch' entstehen aus derselben Zeile des Recorders
 * (monitor/validator-trace.mjs: ch = closedHash, cl = closed === true). Eine Zeile mit cl=true
 * ohne 64-Hex-Hash ist kein Schliess-Beweis, sondern ein zerstoerter Nachweis - genau der Fall,
 * den der alte Flush hinterliess (#107696565, repariert am 2026-10-17 durch denselben
 * Zwei-Quellen-Nachweis wie scripts/backfill-closure.mjs). */
test("normalizeDay: cl=true ohne 64-Hex-Hash wird zu 'nicht erfasst', nicht zu 'nicht geschlossen'", () => {
  const doc = normalizeDay(dayDoc([rowVet({ cl: true, ch: undefined })]));
  assert.equal(doc.ledgerStats[0].cl, null, "ohne Hash ist die Schliessung nicht erfasst");
  assert.equal(doc.ledgerStats[0].ch, null, "kein Rest eines unbekannten Werts bleibt stehen");
  const alt = normalizeDay(dayDoc([rowVet({ cl: true, ch: "986E8D51A78E8B2C" })]));
  assert.equal(alt.ledgerStats[0].cl, null, "16 Hex-Zeichen sind kein Ledger-Hash");
});

test("normalizeDay: ein 64-Hex-Hash laesst den Schliess-Beweis unangetastet", () => {
  const doc = normalizeDay(dayDoc([backfilled()]));
  assert.equal(doc.ledgerStats[0].cl, true, "Nachweis vorhanden - nichts wird demotiert");
  assert.equal(doc.ledgerStats[0].ch, FULL_HASH);
  assert.equal(doc.ledgerStats[0].chSource, ADDENDUM_SOURCE);
  assert.equal(doc.ledgerStats[0].chVerifiedBy, "xrplcluster.com");
});

test("Invariante im Bestand: keine Zeile behauptet Schliessung ohne Hash", () => {
  const here = path.dirname(fileURLToPath(import.meta.url));
  const dir = path.join(here, "..", "data", "validator-trace");
  if (!fs.existsSync(dir)) return;
  const HEX64 = /^[0-9A-Fa-f]{64}$/;
  let rows = 0, bad = 0;
  for (const f of fs.readdirSync(dir).filter((x) => x.endsWith(".json"))) {
    const doc = normalizeDay(JSON.parse(fs.readFileSync(path.join(dir, f), "utf8")));
    for (const st of doc.ledgerStats) {
      rows += 1;
      if (st.cl === true && !(typeof st.ch === "string" && HEX64.test(st.ch))) bad += 1;
    }
  }
  assert.equal(bad, 0, "keine der " + rows + " Ledger-Zeilen darf Schliessung ohne Hash behaupten");
});

/* ---------- Nachfuehrung der Incident-Typen beim Lesen (2026-10-17) ----------
 * Handgerechnet an den drei Ledgern, die ein Betreiber als "no vote / quorum-critical"
 * meldete und die xrpscan und xrplcluster.com als validiert ausweisen:
 *   #107695059  16 / 28  Marge -12  Hash 986E8D51A78E8B2C...96B34602  geschlossen
 *   #107694001   0 / 28  Marge -28  Hash 20444972846C358C...2A158736  geschlossen
 *   #107690236  20 / 28  Marge  -8  Hash FB3ABE4A1AD20B85...AFB705962  geschlossen
 * dUNL-Gruppe 35 -> needed = ceil(35 * 0.8) = 28. Marge = top - needed, also 16 - 28 = -12,
 * 0 - 28 = -28, 20 - 28 = -8. Eine Marge unter null beschreibt hier nur, wie viele Stimmen
 * DIESER Rekorder empfangen hat - niemals ein fehlendes Quorum des Netzes. */
const HASH_94001 = "20444972846C358C955033EBFDE16AC846EA28EBFCF7D6919D29F8232A158736";
const HASH_90236 = "FB3ABE4A1AD20B851C507D04375BDE442D8F47635E0CE0B3A48BCC6AFB705962";
const nqIncident = (over) => ({
  l: 107695059, m: "nVET", t: 1792154042000, type: "no-quorum", r: ["no-quorum"], vd: null, h: null, ...over,
});

test("Nachfuehrung: 'no-quorum' auf bewiesen geschlossenem Ledger wird zu 'vote-not-observed'", () => {
  const doc = normalizeDay({ ...dayDoc([backfilled()]), incidents: [nqIncident()] });
  const inc = doc.incidents[0];
  assert.equal(inc.type, "vote-not-observed", "der Ledger ist geschlossen - die Zeile darf kein Netz-Quorum verneinen");
  assert.deepEqual(inc.r, ["vote-not-observed"], "das Reason-Tag folgt dem Typ, sonst widersprechen sich Typ und Grund");
  assert.equal(inc.ts, "no-quorum", "der urspruenglich geschriebene Typ bleibt als Ursprung erhalten");
  assert.equal(inc.cb, ADDENDUM_SOURCE, "die Autoritaet der Schliess-Aussage ist benannt");
  assert.equal(inc.ch, FULL_HASH);
  assert.equal(inc.chv, "xrplcluster.com", "die zweite Autoritaet steht an der Zeile, die sie braucht");
});

test("Nachfuehrung: eine verneinte Schliessung laesst 'no-quorum' stehen", () => {
  const byLedger = normalizeDay({ ...dayDoc([rowVet({ cl: false, ch: null })]), incidents: [nqIncident()] });
  assert.equal(byLedger.incidents[0].type, "no-quorum", "wo die Schliessung verneint ist, bleibt die Aussage");
  assert.equal(byLedger.incidents[0].ts, undefined, "nichts wurde umgestellt, also gibt es keinen Ursprungstyp");
  const byIncident = normalizeDay({ ...dayDoc([backfilled()]), incidents: [nqIncident({ nc: true })] });
  assert.equal(byIncident.incidents[0].type, "no-quorum", "nc am Incident zaehlt auch gegen die Stats-Zeile");
});

test("Nachfuehrung: closureProofs benennen den Hash, auch ohne Stats-Zeile des Ledgers", () => {
  const doc = normalizeDay({
    date: "2026-10-09",
    incidents: [nqIncident({ l: 107694001 }), nqIncident({ l: 107690236 })],
    closureProofs: [
      { l: 107694001, cl: true, ch: HASH_94001, chSource: ADDENDUM_SOURCE, chVerifiedBy: "xrplcluster.com" },
      { l: 107690236, cl: true, ch: HASH_90236, chSource: ADDENDUM_SOURCE, chVerifiedBy: "xrplcluster.com" },
    ],
  });
  const [a, b] = doc.incidents;
  assert.equal(a.type, "vote-not-observed");
  assert.equal(a.ch, HASH_94001);
  assert.equal(a.cb, ADDENDUM_SOURCE);
  assert.equal(b.ch, HASH_90236);
  assert.equal(doc.closureProofs.length, 2, "die Beweise bleiben ein Satz pro Ledger, nicht kopiert in jede Zeile");
});

test("Nachfuehrung: ohne Hash in der Datei ist die Autoritaet der validierte Stream, nicht 'weiss nicht'", () => {
  const doc = normalizeDay({ date: "2026-10-09", incidents: [nqIncident()] });
  assert.equal(doc.incidents[0].type, "vote-not-observed");
  assert.equal(doc.incidents[0].cb, "validated-ledger-stream", "der Rekorder wertet nur Ledger aus dem validierten Stream - das ist die benannte Autoritaet");
  assert.equal(doc.incidents[0].ch, undefined, "ohne Hash wird keiner erfunden");
});

/* DIE ZUORDNUNGSGRENZE GILT AUCH RUECKWIRKEND (2026-10-17, Gegenprobe api.xrpscan.com).
 * 'missed' ist ein Urteil ueber den Knoten und darf nur stehen, wenn die eigene Erfassung
 * dafuer vollstaendig war - belegt durch 'aa === true'. Handgerechnet am echten Fall #107695059
 * (xrpscan Hash 986E8D51...96B34602, Gegenpruefer xrplcluster.com, 52 Tx):
 *   dUNL 35, Ziel ceil(35 * 0.8) = 28, gesehen 16, Flags 19.
 *   16 + 19 = 35; echt fehlen hoechstens 35 - 28 = 7; nachweisbar Luecke dieses Recorders
 *   mindestens 19 - 7 = 12. Welcher der 19 geflaggten Knoten wirklich nicht abgestimmt hat,
 *   ist aus dieser Zeile nicht ableitbar - also darf kein einzelner als 'missed' dastehen.
 * Die Gegenprobe (api.xrpscan.com/api/v1/validator/<master>) sagt fuer mehrere der so
 * benannten Knoten 0 verpasste Ledger im Fenster: die Zahl war Erfassungs-Luecke, kein Ausfall. */
test("Nachfuehrung: 'missed' ohne Zuordnungsbeleg wird zur Erfassungs-Aussage", () => {
  const doc = normalizeDay({
    ...dayDoc([backfilled()]),
    validators: { nVET: { ok: 2, partial: 0, missed: 1, wrongHash: 0, noQuorum: 1 } },
    incidents: [nqIncident({ type: "missed", r: ["no-correlated-cause"] })],
  });
  const inc = doc.incidents[0];
  assert.equal(inc.type, "vote-not-observed", "ohne Beleg ist die Aussage ueber diese Erfassung gemacht, nicht ueber den Knoten");
  assert.equal(inc.ts, "missed", "der geschriebene Typ bleibt als Ursprung lesbar");
  assert.equal(inc.ma, "not-recorded", "die Zeile dieses Ledgers fuehrte 'aa' noch nicht - die Zuordnung ist nicht erfasst");
  assert.deepEqual(inc.r, ["no-correlated-cause"], "ein Reason-Tag ohne Typ-Bezug wird nicht umgebogen");
  assert.equal(inc.cb, ADDENDUM_SOURCE, "die Autoritaet der Schliessung bleibt auch bei dieser Umstellung benannt");
  assert.equal(inc.ch, FULL_HASH);
  const v = doc.validators.nVET;
  assert.equal(v.missed, 0, "der Zaehler wandert mit: sonst st?nde ein Vorfall 'vote-not-observed' neben einem Zaehler 'missed'");
  assert.equal(v.noQuorum, 2, "1 vorher + 1 umgestellt");
  assert.equal(v.missedOpen, 1, "die verschobene Zahl bleibt nachzaehlbar, sie ist nicht verschwunden");
  assert.deepEqual(doc.missedAttribution, { moved: 1, proven: 0, counterGaps: 0 });
});

test("Nachfuehrung: 'missed' mit Beleg bleibt ein Knoten-Urteil", () => {
  const doc = normalizeDay({
    ...dayDoc([backfilled({ aa: true, ms: 35, cb: 35, gm: 7 })]),
    validators: { nVET: { ok: 2, partial: 0, missed: 1, wrongHash: 0, noQuorum: 1 } },
    incidents: [nqIncident({ type: "missed", aa: true })],
  });
  assert.equal(doc.incidents[0].type, "missed", "aa === true: das Urteil bleibt stehen, es wird nichts entschuldigt");
  assert.equal(doc.incidents[0].ts, undefined, "nichts umgestellt, also kein Ursprungstyp");
  assert.equal(doc.validators.nVET.missed, 1);
  assert.equal(doc.validators.nVET.missedOpen, undefined, "nichts verschoben, also nichts offenzulegen");
  assert.deepEqual(doc.missedAttribution, { moved: 0, proven: 1, counterGaps: 0 });
});

test("Nachfuehrung: der Beleg darf an der Forensik-Zeile stehen, nicht nur am Vorfall", () => {
  const doc = normalizeDay({
    ...dayDoc([backfilled({ aa: true })]),
    validators: { nVET: { ok: 2, partial: 0, missed: 1, wrongHash: 0, noQuorum: 1 } },
    incidents: [nqIncident({ type: "missed" })],
  });
  assert.equal(doc.incidents[0].type, "missed", "die Zeile traegt den Beleg - der Vorfall braucht ihn nicht doppelt");
  assert.equal(doc.missedAttribution.proven, 1);
});

test("Nachfuehrung: gemessen unvollstaendige Erfassung ist ein anderer Grund als nie gemessen", () => {
  const doc = normalizeDay({
    ...dayDoc([backfilled({ aa: false })]),
    validators: { nVET: { ok: 2, partial: 0, missed: 1, wrongHash: 0, noQuorum: 1 } },
    incidents: [nqIncident({ type: "missed" })],
  });
  assert.equal(doc.incidents[0].type, "vote-not-observed");
  assert.equal(doc.incidents[0].ma, "not-attributable", "aa === false ist eine gemessente Absage, nicht 'nie gemessen'");
});

test("Nachfuehrung: 'missed' auf verneinter Schliessung wird zu 'no-quorum', nicht zur Erfassungs-Aussage", () => {
  const doc = normalizeDay({
    ...dayDoc([rowVet({ cl: false, ch: null })]),
    validators: { nVET: { ok: 2, partial: 0, missed: 1, wrongHash: 0, noQuorum: 1 } },
    incidents: [nqIncident({ type: "missed", nc: true })],
  });
  const inc = doc.incidents[0];
  assert.equal(inc.type, "no-quorum", "wo die Schliessung verneint ist, ist die Netz-Aussage der ehrliche Name");
  assert.equal(inc.ma, "not-recorded");
  assert.equal(inc.cb, undefined, "ohne Schliessung gibt es keine Schliess-Autoritaet zu benennen");
  assert.equal(inc.ch, undefined, "ohne Hash wird keiner erfunden");
});

test("Nachfuehrung: Zaehler und Vorfallsliste divergieren - die Luecke wird gemeldet, nicht uebergangen", () => {
  const doc = normalizeDay({
    ...dayDoc([backfilled()]),
    validators: { nVET: { ok: 2, partial: 0, missed: 0, wrongHash: 0, noQuorum: 1 } },
    incidents: [nqIncident({ type: "missed" })],
  });
  assert.equal(doc.incidents[0].type, "vote-not-observed");
  assert.deepEqual(doc.missedAttribution, { moved: 0, proven: 0, counterGaps: 1 }, "nichts verschoben, aber eine Zahl, die niemand nachzaehlen kann");
  assert.equal(doc.validators.nVET.missedOpen, undefined, "ohne Zaehler wird nichts erfunden");
});

test("Nachfuehrung: die Umstellung ist idempotent - ein zweiter Lesedurchgang verschiebt nichts erneut", () => {
  const first = normalizeDay({
    ...dayDoc([backfilled()]),
    validators: { nVET: { ok: 2, partial: 0, missed: 1, wrongHash: 0, noQuorum: 1 } },
    incidents: [nqIncident({ type: "missed" })],
  });
  const second = normalizeDay(JSON.parse(JSON.stringify(first)));
  assert.equal(second.incidents[0].type, "vote-not-observed");
  assert.equal(second.incidents[0].ts, "missed", "der Ursprung bleibt genau einmal eingetragen");
  assert.equal(second.validators.nVET.missed, 0, "derselbe Vorfall darf nicht zweimal verschoben werden");
  assert.equal(second.validators.nVET.noQuorum, 2, "2 bleibt 2, auch nach dem zweiten Lesen");
  assert.deepEqual(second.missedAttribution, { moved: 0, proven: 0, counterGaps: 0 }, "im zweiten Durchgang gibt es nichts zu verschieben");
});

test("Bestand: kein 'missed'-Urteil ohne Beleg, und Zaehler gleich Vorfallsliste", () => {
  const here = path.dirname(fileURLToPath(import.meta.url));
  const dir = path.join(here, "..", "data", "validator-trace");
  if (!fs.existsSync(dir)) return;
  let listed = 0;
  let proven = 0;
  let unproven = 0;
  let counterBad = 0;
  for (const f of fs.readdirSync(dir)) {
    if (!f.endsWith(".json")) continue;
    const doc = normalizeDay(JSON.parse(fs.readFileSync(path.join(dir, f), "utf8")));
    const proof = new Map();
    for (const r of doc.ledgerStats) if (Number.isFinite(r.l) && r.aa === true) proof.set(r.l, true);
    let dayListed = 0;
    for (const inc of doc.incidents) {
      if (inc.type !== "missed") continue;
      listed += 1;
      dayListed += 1;
      if (inc.aa === true || proof.get(inc.l) === true) proven += 1;
      else { unproven += 1; }
    }
    const counted = Object.values(doc.validators).reduce((sum, v) => sum + (Number.isFinite(Number(v.missed)) ? Number(v.missed) : 0), 0);
    if (counted !== dayListed) counterBad += 1;
  }
  assert.ok(listed > 0, "die Aufzeichnung fuehrt 'missed'-Urteile - die Pruefung inspeziert also etwas Echtes");
  assert.equal(unproven, 0, "kein Knoten-Urteil ohne Zuordnungsbeleg");
  assert.equal(counterBad, 0, "Vorfallsliste und Zaehler je Knoten fuehren dieselbe Zahl");
  assert.ok(proven > 0, "belegte Urteile bleiben stehen - die Grenze entschuldigt nicht pauschal");
});

test("Nachtrag: closureProofs des Bestands ueberleben den naechsten Flush", () => {
  const fresh = {
    date: "2026-10-16", ledgerStats: [],
    closureProofs: [{ l: 107690236, cl: true, ch: HASH_90236, chSource: ADDENDUM_SOURCE, chVerifiedBy: "xrplcluster.com" }],
  };
  const next = { date: "2026-10-16", ledgerStats: [rowVet()], incidents: [] };
  const { doc } = mergeClosureAddendum(fresh, next);
  assert.equal(doc.closureProofs.length, 1, "ein nachgetragener Beweis darf nicht vom naechsten Flush verschluckt werden");
  assert.equal(doc.closureProofs[0].ch, HASH_90236);
  const twice = mergeClosureAddendum({ ...fresh, closureProofs: [...fresh.closureProofs] }, { ...next, closureProofs: [...fresh.closureProofs] });
  assert.equal(twice.doc.closureProofs.length, 1, "dasselbe Ledger wird nicht zweimal belegt");
});

test("Bestand: jede 'no-quorum'-Zeile hat einen nachpruefbaren Schliess-Grund", () => {
  const here = path.dirname(fileURLToPath(import.meta.url));
  const dir = path.join(here, "..", "data", "validator-trace");
  if (!fs.existsSync(dir)) return;
  const HEX64 = /^[0-9A-Fa-f]{64}$/;
  let claims = 0, unbacked = 0, named = 0;
  for (const f of fs.readdirSync(dir).filter((x) => x.endsWith(".json"))) {
    const raw = JSON.parse(fs.readFileSync(path.join(dir, f), "utf8"));
    const closed = new Set();
    for (const st of raw.ledgerStats ?? []) if (st && st.cl !== false && typeof st.ch === "string" && HEX64.test(st.ch)) closed.add(st.l);
    for (const cp of raw.closureProofs ?? []) if (cp && cp.cl !== false && typeof cp.ch === "string" && HEX64.test(cp.ch)) closed.add(cp.l);
    for (const inc of raw.incidents ?? []) {
      if (!inc || inc.type !== "no-quorum") continue;
      claims += 1;
      if (inc.nc === true) continue;
      if (closed.has(inc.l)) named += 1; else unbacked += 1;
    }
  }
  assert.equal(unbacked, 0, named + " von " + claims + " Zeilen sind durch einen benannten Hash gedeckt; " + unbacked + " ohne jeden Nachweis");
});

test("Schreibpfad: der Incident traegt die verneinte Schliessung selbst (nc), nicht nur die Stats-Zeile", () => {
  const here = path.dirname(fileURLToPath(import.meta.url));
  const src = fs.readFileSync(path.join(here, "..", "monitor", "validator-trace.mjs"), "utf8");
  assert.ok(src.includes("nc: r.closed === false ? true : undefined"),
    "ohne nc am Incident waere die Umstellung beim Lesen ein Rueckschluss ohne Beleg, sobald die Forensik-Zeile gekappt wurde");
});

test("Abfragepfad: closureBasis und typeStored kommen aus der Nachfuehrung, nicht aus einer Schaetzung", () => {
  const here = path.dirname(fileURLToPath(import.meta.url));
  const src = fs.readFileSync(path.join(here, "validator-trace-query.mjs"), "utf8");
  assert.ok(src.includes("closureBasis: i.cb ?? null, typeStored: i.ts ?? null, closureHash: i.ch ?? null"),
    "die API darf keine Autoritaet erfinden, die nicht in der Datei steht");
});

// --- Zaehler-Kohaerenz der Incident-Umbenennung (2026-10-17, durch 2026-10-16.json belegt) ---
test("normalizeDay: ein 'no-quorum'-Zaehler ohne Schliess-Absage wird zur Erfassungs-Vokabel", () => {
  // Nachbau des Live-Tages: anomaly 'no-quorum' = 8 und anomalyFail 'no-quorum' = 8, dazu
  // 'vote-not-observed' = 1, aber kein Vorfall vom Typ 'no-quorum', keine Forensik-Zeile mit
  // cl === false, kein Incident mit nc. Der Zaehler behauptet also ein fehlendes Netz-Quorum
  // fuer Ledger, dessen Schliessung keine Ebene dieses Tages verneint. Umgestellt wird die
  // Vokabel, die Zahl bleibt: 8 + 1 = 9, von Hand nachgerechnet.
  const doc = normalizeDay({
    date: "2026-10-16", ledgers: 20583, quorumFail: 11,
    incidents: [{ l: 107695059, m: "nAAA", t: 1, type: "vote-not-observed", r: ["vote-not-observed"] }],
    ledgerStats: [{ l: 107695059, cl: true, ch: "A".repeat(64) }],
    anomaly: { "no-quorum": 8, "vote-not-observed": 1, "load-spike": 1441 },
    anomalyFail: { "no-quorum": 8, "vote-not-observed": 1, "load-spike": 67 },
    anomalyRecorded: true,
  });
  assert.equal(doc.anomaly["no-quorum"], 0, "die Gegenbehauptung ueber das Netz bleibt stehen");
  assert.equal(doc.anomaly["vote-not-observed"], 9, "8 + 1 = 9, keine Schaetzung, nur die Vokabel wechselt");
  assert.equal(doc.anomalyFail["no-quorum"], 0);
  assert.equal(doc.anomalyFail["vote-not-observed"], 9);
  assert.equal(doc.anomaly["load-spike"], 1441, "eine echte Signatur bleibt unangetastet");
  assert.equal(doc.countersRenamed, 8, "die Umbenennung ist nachzaehlbar: 8 Ledger, nicht 8 + 8 Zaehlerfelder");
});

test("normalizeDay: ein Zaehler mit gemischter Schliessungs-Lage wird NICHT aufgeteilt", () => {
  // Hier verneint eine Forensik-Zeile die Schliessung (cl === false). Der Zaehler enthaelt dann
  // echte 'no-quorum'-Ledger und Altbestand in ein- und derselben Zahl. Welche Ledger was sind,
  // sagt die Tagesdatei nicht - eine Aufteilung waere erfunden. Also: Zahl stehen lassen und
  // die Stelle als Luecke benennen.
  const doc = normalizeDay({
    date: "2026-10-16", ledgers: 100, quorumFail: 8,
    incidents: [{ l: 200, m: "nAAA", t: 1, type: "no-quorum", r: ["no-quorum"], nc: true }],
    ledgerStats: [{ l: 200, cl: false }],
    anomaly: { "no-quorum": 8 }, anomalyFail: { "no-quorum": 8 }, anomalyRecorded: true,
  });
  assert.equal(doc.anomaly["no-quorum"], 8, "ohne Beleg fuer die Aufteilung bleibt die Zahl");
  assert.equal(doc.anomaly["vote-not-observed"], undefined, "nichts wird hinzugedichtet");
  assert.equal(doc.incidents[0].type, "no-quorum", "die verneinte Schliessung ist der ehrliche Name");
  assert.equal(doc.counterGaps.length, 2, "beide Stellen sind benannt: die Vokabel und der Quorum-Zaehler");
  const gaps = doc.counterGaps.map((g) => g.tag + "/" + g.reason + "/" + g.ledgers).sort();
  assert.deepEqual(gaps, ["no-quorum/closure-denied-in-same-counter/8", "quorum-fail/counter-without-forensics-row/8"],
    "8 Ledger Zaehler, 0 kurze Forensik-Zeile: die Differenz heisst 8, nicht 0");
});
test("normalizeDay: der Quorum-Zaehler wird gegen die Forensik-Zeilen nachgerechnet", () => {
  // Nachbau des Live-Tages 2026-10-16: Zaehler 11, Forensik-Zeilen mit top < need = 9.
  // Die 9 sind hier ausdruecklich aufgelistet (need 28 = ceil(35 * 0,8), von Hand nachgerechnet):
  // 20, 0, 24, 16, 11, 10, 23, 17, 24 sind unter 28 - das sind 9 Zeilen. Die zwei Zeilen mit
  // 28 und 34 fuehren dasselbe Ziel und bleiben aussen vor. 11 - 9 = 2 Ledger im Zaehler ohne
  // Zeile: benannt, nicht auf ein Ledger verteilt.
  const short = [20, 0, 24, 16, 11, 10, 23, 17, 24];
  const doc = normalizeDay({
    date: "2026-10-16", ledgers: 20583, quorumFail: 11,
    incidents: [], ledgerStats: [
      ...short.map((top, i) => ({ l: 107690000 + i, t: 1, top, need: 28, cl: true, ch: "A".repeat(64) })),
      { l: 107699000, t: 1, top: 28, need: 28, cl: true, ch: "B".repeat(64) },
      { l: 107699001, t: 1, top: 34, need: 28, cl: true, ch: "C".repeat(64) },
    ],
  });
  assert.equal(doc.quorumShortRows, 9, "9 kurze Zeilen, nachgezaehlt ueber die aufgelisteten Zahlen");
  const gap = (doc.counterGaps ?? []).find((g) => g.tag === "quorum-fail") ?? null;
  assert.ok(gap, "die Differenz zwischen Zaehler und Zeilen ist benannt");
  assert.equal(gap.counter, 11);
  assert.equal(gap.shortRows, 9);
  assert.equal(gap.ledgers, 2, "11 - 9 = 2, keine Aufteilung auf Ledger");
  assert.equal(gap.reason, "counter-without-forensics-row");
});

test("normalizeDay: ein Quorum-Zaehler ohne Forensik-Zeile bleibt stehen und wird benannt", () => {
  // Altbestand 2026-10-15: quorumFail = 13, die Datei hat keine Forensik-Zeile. Die Zahl ist
  // eine Messung ueber die eigene fuehrende Linie, aber kein Ledger ist ihr zuzuordnen.
  const doc = normalizeDay({ date: "2026-10-15", ledgers: 21989, quorumFail: 13, incidents: [], ledgerStats: [] });
  assert.equal(doc.quorumFail, 13, "die Zahl des Recorders bleibt seine Zahl");
  assert.equal(doc.quorumShortRows, 0, "nachrechenbar ist nichts, und nichts wird hinzugedichtet");
  const gap = (doc.counterGaps ?? []).find((g) => g.tag === "quorum-fail") ?? null;
  assert.ok(gap);
  assert.equal(gap.ledgers, 13);
  assert.equal(gap.reason, "counter-without-forensics-row");
});

test("normalizeDay: Zaehler und kurze Zeilen in Deckung lassen keine Luecke entstehen", () => {
  const doc = normalizeDay({
    date: "2026-10-17", ledgers: 6290, quorumFail: 1, incidents: [],
    ledgerStats: [
      { l: 107708086, top: 15, need: 28, cl: true, ch: "D".repeat(64) },
      { l: 107708087, top: 30, need: 28, cl: true, ch: "E".repeat(64) },
    ],
  });
  assert.equal(doc.quorumShortRows, 1);
  assert.ok(!(doc.counterGaps ?? []).some((g) => g.tag === "quorum-fail"), "1 = 1 ist Deckung, keine Luecke");
});

test("normalizeDay: mehr kurze Zeilen als Zaehler ist ein Widerspruch, keine Rundung", () => {
  const doc = normalizeDay({
    date: "2026-10-17", ledgers: 100, quorumFail: 1, incidents: [],
    ledgerStats: [
      { l: 1, top: 0, need: 28 }, { l: 2, top: 4, need: 28 }, { l: 3, top: 27, need: 28 },
    ],
  });
  assert.equal(doc.quorumShortRows, 3);
  const gap = (doc.counterGaps ?? []).find((g) => g.tag === "quorum-fail") ?? null;
  assert.ok(gap);
  assert.equal(gap.reason, "forensics-rows-exceed-counter");
  assert.equal(gap.ledgers, 2, "3 - 1 = 2");
});

test("normalizeDay: ein Ziel ohne Zahl wird nicht zur kurzen Linie erklaert", () => {
  // need = 0 heisst: dieses Ziel wurde nie aufgezeichnet. 'top < need' waere hier eine
  // Aussage ohne Nenner. Eine Zeile ohne top ist keine Messung. Beide bleiben aussen vor.
  const doc = normalizeDay({
    date: "2026-10-17", ledgers: 100, quorumFail: 4, incidents: [],
    ledgerStats: [
      { l: 1, top: 20, need: 28 }, { l: 2, top: 0, need: 0 }, { l: 3, need: 28 }, { l: 4, top: 30, need: 28 },
    ],
  });
  assert.equal(doc.quorumShortRows, 1, "nur die eine Zeile mit Ziel und Messung zaehlt");
  const gap = (doc.counterGaps ?? []).find((g) => g.tag === "quorum-fail") ?? null;
  assert.ok(gap);
  assert.equal(gap.ledgers, 3, "4 - 1 = 3, und die drei nicht beurteilbaren Zeilen werden nicht erfunden");
});

/* Eigener Schliess-Hash ohne Gegenprobe (2026-10-17): 72 Zeilen des heutigen Tages fuehren einen
 * im Stream selbst gehoerten Hash, aber keine Deckung gegen eine zweite Autoritaet (xc 0,
 * chVerifiedBy 0). Ohne Gegenprobe ist "geschlossen" die Aussage eines einzigen Hoerers. Guard
 * ist die Zwei-Quellen-Deckung genau dieser Zeilenart: der eigene Hash bleibt der Beweis der
 * Zeile, die Quellen bestaetigen oder widersprechen, und ein Widerspruch ist keine Bestaetigung. */
const OWN_HASH = "986E8D51A78E8B2CB53B0FDBAE613692C7D33E3C82DCEE20A2C22D5496B34602";
const OTHER_HASH = OWN_HASH.slice(0, 56) + "01234567";

test("crossCheckNote: der eigene Hash bleibt der Beweis, beide Quellen bestaetigen ihn", () => {
  const note = crossCheckNote({ ownHash: OWN_HASH, ha: OWN_HASH.toLowerCase(), hb: OWN_HASH,
    txMatch: true, tMatch: true, tSources: true, txScan: 52, tScan: 1792154042000, tNet: 1792154042000 });
  assert.equal(note.hashAgree, true, "xrpscan und xrplcluster melden denselben Hash wie der Rekorder (#107695059)");
  assert.equal(note.ownHash, OWN_HASH, "der eigene Mithoerbeweis bleibt der nachlesbare Beweis der Zeile");
  assert.equal(note.txScan, 52, "die Tx-Zahl der Quelle steht daneben, nicht statt der eigenen");
  assert.equal(note.tScan, 1792154042000);
  assert.equal(note.tNet, 1792154042000);
});

test("crossCheckNote: Gross und Kleinschreibung sind derselbe Hash, eine fehlende Quelle nicht", () => {
  assert.equal(crossCheckNote({ ownHash: OWN_HASH.toLowerCase(), ha: OWN_HASH, hb: OWN_HASH }).hashAgree, true,
    "Hex in Kleinbuchstaben ist kein anderer Hash");
  assert.equal(crossCheckNote({ ownHash: OWN_HASH, ha: OWN_HASH, hb: null }).hashAgree, false,
    "eine Autoritaet ohne Hash bestaetigt nichts");
  assert.equal(crossCheckNote({ ownHash: OWN_HASH, ha: OWN_HASH, hb: OTHER_HASH }).hashAgree, false,
    "zwei Quellen, die sich untereinander nicht decken, bestaetigen die Zeile nicht");
  assert.equal(crossCheckNote({ ownHash: "kein Hash", ha: OWN_HASH, hb: OWN_HASH }).hashAgree, false,
    "ein Hash, der keiner ist, kann nicht bestaetigt werden");
  assert.equal(crossCheckNote({ ownHash: true, ha: OWN_HASH, hb: OWN_HASH }).hashAgree, false,
    "ein Boolean ist kein Hash - die Gegenprobe braucht den Wert, nicht die Frage, ob einer da ist");
  assert.equal(crossCheckNote({ ownHash: OWN_HASH, ha: OTHER_HASH, hb: OTHER_HASH }).hashAgree, false,
    "der Widerspruch gegen den eigenen Hash ist ein Widerspruch, keine Entlastung");
});

test("crossCheckNote: eine gemessene Abweichung bleibt Abweichung, null bleibt nicht erfasst", () => {
  const note = crossCheckNote({ ownHash: OWN_HASH, ha: OWN_HASH, hb: OWN_HASH,
    txMatch: false, tMatch: null, tSources: true, txScan: 42, tScan: null, tNet: 1792154042000 });
  assert.equal(note.tx, false, "false ist die gemessene Abweichung, nicht das Fehlen einer Messung");
  assert.equal(note.t, null, "ohne eigene Close-Zeit bleibt die Deckung offen");
  assert.equal(note.tScan, null);
  assert.equal(note.hashAgree, true, "die Hash-Deckung haengt nicht an der Tx-Deckung");
});
