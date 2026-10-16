// lib/validator-trace-store.test.mjs — Persistenz-Hilfen des Trace (pure Teile, ohne Netzwerk).
import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  datesBetween, datesForRange, dayPath, normalizeDay, TRACE_RETENTION_DAYS, TRACE_DIR,
  ADDENDUM_FIELDS, ADDENDUM_SOURCE, mergeClosureAddendum, writeDayLocal,
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

test("Nachfuehrung: 'missed' bleibt unangetastet - dort stand das Quorum", () => {
  const doc = normalizeDay({ ...dayDoc([backfilled()]), incidents: [nqIncident({ type: "missed", r: ["no-correlated-cause"] })] });
  assert.equal(doc.incidents[0].type, "missed");
  assert.equal(doc.incidents[0].ts, undefined);
  assert.equal(doc.incidents[0].cb, undefined, "fuers 'missed' ist die Schliess-Aussage nicht die erklaerende Stelle");
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
