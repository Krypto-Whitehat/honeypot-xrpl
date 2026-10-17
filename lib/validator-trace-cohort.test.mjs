// lib/validator-trace-cohort.test.mjs - Nachrechnung der Kohorten-Karte am ausgelieferten Bestand.
//
// Warum diese Datei existiert: die drei Ledger aus lib/validator-trace-fidelity.test.mjs sind die
// Einzel-Kritikalitaet. Die Kohorten-Karte (Retrace) ist eine andere Ebene und war bisher nicht
// festgenagelt - genau die Ebene, auf der ein Betreiber "mehrere Validatoren, dasselbe Ledger" liest.
// Ledger 107699168 ist dafuer gewaehlt, weil er der schwierigste Fall ist: der Rekorder sah hier
// VOLLE 28 Stimmen (Marge 0), und trotzdem stehen sieben Knoten als abweichend da. Die Schliessung
// beweist auf diesem Ledger keine Erfassungs-Luecke - sie erlaubt hoechstens genau die sieben.
//
// Alle Erwartungswerte sind von Hand nachgerechnet (die Rechnung steht jeweils daneben), keiner ist
// aus einer Funktion abgeschrieben. Die Bytes selbst kommen aus dem Daten-Repo
// Krypto-Whitehat/honeypot-xrpl-history, Tagesdatei 2026-10-16.json.
import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { normalizeDay } from "./validator-trace-store.mjs";
import { captureBound, ledgerClosure, missedAttribution } from "./validator-trace.mjs";
import { traceForValidator } from "./validator-trace-query.mjs";

const here = path.dirname(fileURLToPath(import.meta.url));
const RAW = JSON.parse(fs.readFileSync(path.join(here, "fixtures", "trace-2026-10-16-cohort-ledger.json"), "utf8"));
const HEX64 = /^[0-9A-F]{64}$/;
const VET = "nHBWa56Vr7csoFcCnEPzCCKVvnDQw3L28mATgHYQMGtbEfUjuYyB";
const L = 107699168;
const HASH = "59F271F8EBE3C698FF41021C7EFFC38E64977099DC3C643F2615C8625CBBB10F";
const FRAC = 0.8;
// Handrechnung, die in mehreren Tests gebraucht wird:
//   gesehenes dUNL-Loch = c.missed + c.noQuorum = 7 + 0 = 7
//   dUNL-Groesse        = v + Loch = 28 + 7 = 35
//   Quorum-Ziel         = ceil(35 * 0,8) = ceil(28) = 28
//   echte Nicht-Signer  = 35 - 28 = 7
//   Erfassungs-Luecke   = 7 - 7 = 0   (die Schliessung beweist hier keine Luecke)
const MEMBERS = 35;
const NEEDED = 28;
const ABSENT = 7;
const GENUINE_MAX = 7;
const CAPTURE_ARTIFACT = 0;
const doc = normalizeDay(JSON.parse(JSON.stringify(RAW)));
doc.date = "2026-10-16";
doc.firstMs = 1792135432000;
doc.lastMs = 1792170131000;
doc.lastLedger = L;
const st = doc.ledgerStats.find((r) => r.l === L);
const inc = doc.incidents.filter((i) => i.l === L);
const trace = traceForValidator([doc], VET, { range: "all", now: 1792170131000 });
const card = trace.retrace.find((e) => e.ledgerIndex === L);

test("Fixture: es sind die ausgelieferten Bytes, und ihre Identitaet ist festgenagelt", () => {
  assert.equal(RAW.ledgerIndex, L);
  assert.equal(st.l, L);
  assert.equal(st.ch, HASH, "ein anderer Schliess-Hash ist eine geaenderte Tatsache, keine neue Messung");
  assert.match(st.ch, HEX64);
  assert.equal(st.tx, 151, "Tx-Zahl widerspricht xrpscan tx_count");
  assert.equal(st.t, 1792170131000, "Close-Zeit widerspricht der Quelle");
  assert.equal(st.chSource, "xrpscan");
  assert.equal(st.chVerifiedBy, "xrplcluster.com", "zweite unabhaengige Autoritaet fehlt");
  assert.equal(st.cl, true, "dieser Ledger ist ausdtruecklich geschlossen");
  assert.equal(st.xc.hashAgree, true);
  assert.equal(st.xc.sourcesAgree, true);
  assert.equal(st.xc.txScan, 151, "der Gegenpruef-Vermerk muss dieselbe Tx-Zahl nennen");
  assert.equal(st.xc.tScan, 1792170131000);
  assert.equal(st.xc.tNet, 1792170131000);
  // In den ausgelieferten Bytes heissen die Vorfaelle 'missed' - also Knoten-Ausfall. Genau dieser
  // Altbestand wurde geschrieben, bevor die Zuordnungsgrenze existierte.
  assert.equal(RAW.incidents.length, 7);
  assert.ok(RAW.incidents.every((i) => i.type === "missed"), "die Bytes selbst fuehren 'missed'");
  assert.equal(new Set(RAW.incidents.map((i) => i.m)).size, 7, "sieben verschiedene Knoten");
  assert.ok(RAW.incidents.some((i) => i.m === VET), "der angefragte Knoten ist selbst betroffen");
  assert.equal(st.aa, undefined, "ohne aa traegt die Zeile keinen Zuordnungsbeleg - das ist der Pruefstand");
});

test("Quorum-Zahlen: 28 von 35 gesehen, Ziel 28, Marge 0 - die Rechnung stimmt in sich", () => {
  assert.equal(st.v, 28, "gesehene dUNL-Validierungen");
  assert.equal(st.top, 28, "fuehrende Linie");
  assert.equal(st.need, 28, "Ziel der Zeile");
  assert.equal(st.mg, 0, "28 - 28 = 0, die Marge ist aufgezeichnet");
  assert.equal(st.sp, 0, "kein zweiter Hash");
  const c = captureBound(st, { parentGap: false, networkQuorum: { ...doc.networkQuorum, samples: doc.networkQuorumSamples } });
  assert.equal(c.absentCount, ABSENT, "c.missed 7 + c.noQuorum 0 = 7");
  assert.equal(c.members, MEMBERS, "28 gesehen + 7 ohne gesehenen Vote = 35");
  assert.equal(c.membersBasis, "derived", "'mm' fehlt in dieser Zeile, also darf nur die eigene Nachrechnung stehen");
  assert.equal(c.neededDerived, NEEDED, "ceil(35 * 0,8) = 28");
  assert.equal(c.neededMatches, true, "das aufgezeichnete Ziel ist genau das nachgerechnete Ziel");
  assert.equal(c.seenVotes, 28);
  // Das Ziel traegt seine Herkunft: derselbe Tag hat genau 28 am Endpunkt gemessen.
  assert.equal(c.neededBasis, "day-measured");
  assert.equal(c.networkQuorum, 28);
  assert.equal(c.networkQuorumBasis, "day-sample");
  assert.equal(c.networkQuorumSource, "wss://s1.ripple.com", "ohne benannten Endpunkt ist die Zahl nicht nachlesbar");
  assert.equal(c.networkQuorumSamples, 3);
  assert.equal(c.networkQuorumAtMs, 1792185804628, "ohne Zeitpunkt ist die Messung nicht nachpruefbar");
});

test("Schliess-Grenze: hoechstens 7 echte Nicht-Signierer, und hier ist KEINE Luecke bewiesen", () => {
  const c = captureBound(st, { parentGap: false, networkQuorum: { ...doc.networkQuorum, samples: doc.networkQuorumSamples } });
  assert.equal(c.closed, true);
  assert.equal(c.genuineAbsentMax, GENUINE_MAX, "35 - 28 = 7; mehr laesst die Schliessung nicht zu");
  assert.equal(c.captureArtifactMin, CAPTURE_ARTIFACT,
    "7 Nicht-Signierer minus 7 erlaubte = 0. Diese Zeile beweist keine Erfassungs-Luecke - sie darf auch keine behaupten");
  assert.equal(c.captureComplete, true, "28 gesehene Stimmen erreichen das Ziel von 28");
  assert.equal(c.genuineAbsentMaxLedger, null, "'gm' ist nicht aufgezeichnet, also gibt es keinen Ledger-eigenen Wert");
  assert.equal(c.attributableAbsence, null, "'aa' fehlt: keine Zuordnung, keine Entlastung");
});

test("Nachfuehrung beim Lesen: kein Vorfall dieses Ledgers darf als Knoten-Ausfall stehen", () => {
  assert.equal(missedAttribution(st), "open", "ohne aa ist die Zuordnung nicht gemessen - nicht 'fault'");
  assert.equal(inc.length, 7);
  for (const i of inc) {
    assert.equal(i.type, "vote-not-observed",
      "auf einem bewiesen geschlossenen Ledger ist 'missed' eine unbewiesene Knoten-Aussage");
    assert.equal(i.ts, "missed", "der urspruenglich gespeicherte Typ bleibt lesbar");
    assert.equal(i.ma, "not-recorded", "warum der Beleg fehlt, muss benannt sein");
    assert.equal(i.cb, "xrpscan", "der Schliess-Beweis muss an jedem Vorfall stehen");
    assert.equal(i.ch, HASH);
    assert.equal(i.chv, "xrplcluster.com");
    assert.notEqual(i.nc, true, "kein Vorfall behauptet, dieses Ledger habe kein Quorum erreicht");
  }
  assert.equal(inc.filter((i) => i.type === "missed").length, 0, "kein Rest behaelt die Knoten-Aussage");
});

test("Kohorten-Karte: 6 andere Knoten, jeder benannt, und kein zweiter Ausfall", () => {
  assert.ok(card, "die Karte muss aus denselben Bytes entstehen wie auf der Website");
  const a = card.affected;
  assert.equal(a.noQuorum, ABSENT, "7 Knoten ohne gesehenen Vote, einschliesslich des angefragten");
  assert.equal(a.missed, 0, "kein Knoten wird als Ausfall gezaehlt");
  assert.equal(a.partial, 0);
  assert.equal(a.wrongHash, 0);
  assert.equal(a.others, 6, "7 Betroffene minus der eigene Knoten = 6");
  assert.equal(a.faultOthers, 0, "kein zweiter Knoten-Ausfall - die Kohorte ist eine Erfassungs-Kohorte");
  assert.equal(a.captureOthers, 6);
  assert.equal(a.openOthers, 0);
  assert.equal(a.peerMasters.length, 6, "jeder andere Betroffene wird namentlich gefuehrt");
  assert.deepEqual(a.peerMasters, [...a.peerMasters].sort(), "sortiert, damit zwei Aufrufe dieselbe Liste liefern");
  assert.ok(!a.peerMasters.includes(VET), "der eigene Key steht schon als master der Diagnose");
  assert.equal(a.captureOnlyMasters.length, 6);
  assert.equal(a.openMasters.length, 0);
  assert.equal(a.sameTypeMasters.length, 6, "alle sechs haben denselben Vorfallstyp - das ist die Vergleichsgruppe");
  assert.equal(a.otherTypeMasters.length, 0);
  assert.deepEqual(Object.keys(a.peerNames).sort(), a.peerMasters, "zu jedem Peer gehoert ein Name-Feld");
});

test("Etikett und Schliess-Beleg: 'ledgerweit in dieser Erfassung', nicht Netzstockung", () => {
  assert.equal(card.type, "vote-not-observed");
  assert.equal(card.scope, "network", "Etikett ist 'ledgerweit in dieser Erfassung' - eine Aussage ueber den Rekorder");
  assert.notEqual(card.scope, "cohort", "ohne zweiten Ausfall darf die Karte nicht als Knoten-Kohorte stehen");
  assert.equal(card.closure.closed, true);
  assert.equal(card.closure.basis, "xrpscan");
  assert.equal(card.closure.hash, HASH);
  assert.equal(card.closure.verifiedBy, "xrplcluster.com");
  assert.equal(card.closure.captureGap, null, "kein 'pg' und keine Tages-Luecke vor 107699168: nicht erfasst, nicht 'keine Luecke'");
  assert.equal(card.closure.captureGapBasis, "not-recorded");
  assert.equal(card.capture.captureComplete, true);
  assert.equal(card.capture.genuineAbsentMax, GENUINE_MAX);
  assert.equal(card.capture.captureArtifactMin, CAPTURE_ARTIFACT);
});

test("Retrace und Diagnose lesen denselben Ledger: dieselbe Schliessung, dieselbe Grenze", () => {
  const cl = ledgerClosure(st, { parentGap: false });
  assert.equal(cl.closed, true);
  assert.equal(cl.basis, "xrpscan");
  assert.equal(cl.hash, card.closure.hash, "zwei Ebenen duerfen nicht zwei Hashes fuer denselben Ledger nennen");
  assert.equal(cl.verifiedBy, card.closure.verifiedBy);
  const own = trace.diagnosis?.criticality?.rows?.find((r) => r.ledgerIndex === L);
  if (own) {
    assert.equal(own.closure.hash, card.closure.hash);
    assert.equal(own.needed, NEEDED);
    assert.equal(own.topVotes, 28);
    assert.equal(own.margin, 0);
    assert.equal(own.critical, false, "28 von 28 ist kein kritischer Befund");
    assert.equal(own.affectedCount, ABSENT);
    assert.equal(own.affectedMasters.length, 6);
  }
});
