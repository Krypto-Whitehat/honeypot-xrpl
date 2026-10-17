// lib/validator-trace-fidelity.test.mjs - Nachrechnung an den ausgelieferten Originalbytes.
//
// Warum diese Datei existiert: die drei Ledger 107695059, 107694001 und 107690236 waren der
// live nachgewiesene Akkuratz-Fall. Die Engine zeigte sie als "no vote (network stall)" und
// "quorum-critical". xrpscan.com (api.xrpscan.com/api/v1/ledger/<index>) und xrplcluster.com
// (JSON-RPC ledger) melden fuer genau diese Indizes denselben 64er-Hash, dieselbe Tx-Zahl und
// dieselbe Close-Zeit, die die Tagesdatei nennt - die Ledger sind also geschlossen, und eine
// negative Marge beschreibt nur, wie viele Stimmen DIESER Rekorder sah.
//
// Der Unterschied zu lib/validator-diagnose.test.mjs: dort stehen nachgebaute Fixture-Zeilen.
// Hier stehen die wortwrtlichen Bytes aus dem Bestand, aus dem die Website liest
// (lib/fixtures/trace-2026-10-16-three-ledgers.json). Weicht die Engine gegen diese Bytes ab,
// schlagen diese Tests fehl - nicht ein Audit, der zufaellig laeuft.
//
// Alle Erwartungswerte sind von Hand nachgerechnet, keiner ist aus einer Funktion abgeschrieben.
import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { captureBound, ledgerClosure, TRACE_DEFAULTS } from "./validator-trace.mjs";
import { quorumCriticality } from "./validator-diagnose.mjs";

const here = path.dirname(fileURLToPath(import.meta.url));
const FIX = JSON.parse(fs.readFileSync(path.join(here, "fixtures", "trace-2026-10-16-three-ledgers.json"), "utf8"));
const HEX64 = /^[0-9A-F]{64}$/;
// xrp.vet - der Knoten, dessen Tafel diese drei Zeilen zeigt.
const VET = "nHBWa56Vr7csoFcCnEPzCCKVvnDQw3L28mATgHYQMGtbEfUjuYyB";
const FRAC = 0.8;
const MEMBERS = 35;
const NEEDED = 28;          // ceil(35 * 0,8) = 28
const GENUINE_MAX = 7;      // 35 - 28 = 7 echte Nicht-Signierer, hoechstens
const DAY_TARGET = 28;      // networkQuorum dieses Tages, gemessen bei wss://s1.ripple.com
const rows = FIX.ledgerStats;
const byIdx = new Map(rows.map((r) => [r.l, r]));
// Betroffene Knoten je Ledger, ausschliesslich aus der Vorfallsliste des Fixtures.
const flagged = (l) => new Set(FIX.incidents.filter((i) => i.l === l).map((i) => i.m));
const evidence = (l) => ({
  parentGap: (FIX.gaps ?? []).some((g) => l - 1 >= g.from && l - 1 <= g.to),
  networkQuorum: FIX.networkQuorum ? { ...FIX.networkQuorum, samples: FIX.networkQuorumSamples } : null,
});

test("Fixture: es sind die ausgelieferten Bytes, und ihre Identitaet ist festgenagelt", () => {
  assert.equal(rows.length, 3, "das Exzerpt soll genau die drei nachgewiesenen Ledger enthalten");
  assert.deepEqual(rows.map((r) => r.l), [107695059, 107694001, 107690236]);
  // Die Hashes sind die von xrpscan und xrplcluster gemeldeten - ein anderer Wert in der Datei
  // waere eine veraenderte Tatsache, keine neue Messung, und muss hier scheitern.
  const pinned = new Map([
    [107695059, ["986E8D51A78E8B2CB53B0FDBAE613692C7D33E3C82DCEE20A2C22D5496B34602", 52, 1792154042000]],
    [107694001, ["20444972846C358C955033EBFDE16AC846EA28EBFCF7D6919D29F8232A158736", 93, 1792149950000]],
    [107690236, ["FB3ABE4A1AD20B851C507D04375BDE442D8F47635E0CE0B3A48BCC6AFB705962", 27, 1792135432000]],
  ]);
  for (const [l, [hash, tx, t]] of pinned) {
    const st = byIdx.get(l);
    assert.equal(st.ch, hash, "Schliess-Hash #" + l + " ist nicht der von den Quellen gemeldete");
    assert.match(st.ch, HEX64, "64er-Hash ist Pflicht, sonst ist die Zeile nicht nachlesbar");
    assert.equal(st.tx, tx, "Tx-Zahl #" + l + " widerspricht xrpscan tx_count");
    assert.equal(st.t, t, "Close-Zeit #" + l + " widerspricht der Quelle");
    assert.notEqual(st.cl, false, "kein dieser Ledger ist ausdruecklich nicht geschlossen");
    assert.equal(st.chSource, "xrpscan");
    assert.equal(st.chVerifiedBy, "xrplcluster.com", "zweite unabhaengige Autoritaet fehlt");
    assert.ok(Number.isFinite(Date.parse(st.chAt)), "der Zeitpunkt des Nachwehrs fehlt");
    // Der in der Datei gespeicherte Gegenpruef-Vermerk muss zu den festgenagelten Werten passen.
    assert.equal(st.xc.hashAgree, true, "veralteter Gegenpruef-Vermerk ist ein Fehler, keine Entlastung");
    assert.equal(st.xc.txScan, tx);
    assert.equal(st.xc.tScan, t);
    assert.equal(st.xc.sourcesAgree, true);
  }
});

test("Kohorte: die betroffene Knotenmenge wird aus den Vorfällen gerechnet, nicht aus einem Zaehler", () => {
  assert.equal(flagged(107695059).size, 19);
  assert.equal(flagged(107694001).size, 35);
  assert.equal(flagged(107690236).size, 15);
  assert.equal(new Set(FIX.incidents.map((i) => i.m)).size, MEMBERS,
    "ueber alle drei Ledger ist dieselbe beobachtete dUNL-Menge betroffen");
  for (const l of [107695059, 107694001, 107690236]) assert.ok(flagged(l).has(VET));
  // Der Zaehler in der Forensik-Zeile und die Vorfallsliste muessten dieselbe Zahl fuehren.
  for (const st of rows) {
    assert.equal(st.c.missed, 0, "kein dieser Vorfalle ist ein belegtes Verpassen");
    assert.equal(st.c.noQuorum, flagged(st.l).size, "Zaehler und Vorfallsliste divergieren");
  }
});

test("Quorum-Ziel: 28 ist aus der dUNL-Groesse nachrechenbar, die die Zeile selbst traegt", () => {
  assert.equal(TRACE_DEFAULTS.quorumFrac, FRAC, "die nachgerechnete Bruchzahl ist nicht die der Lib");
  for (const st of rows) {
    assert.equal(st.mm, undefined, "diese aelteren Zeilen tragen die dUNL-Groesse nicht selbst");
    // Ohne mm muss die Groesse aus den eigenen Zahlen der Zeile kommen: gesehene Stimmen + ohne Vote.
    assert.equal(st.v + st.c.noQuorum, MEMBERS, "Mithoer-Identitaet der Zeile gilt nicht");
    assert.equal(Math.ceil(MEMBERS * FRAC), NEEDED);
    assert.equal(st.need, NEEDED, "das Ziel der Zeile ist nicht das nachrechenbare");
  }
});

test("Marge: fuehrende Linie minus Ziel, fuer alle drei von Hand gerechnet", () => {
  assert.equal(16 - NEEDED, -12); assert.equal(byIdx.get(107695059).mg, -12);
  assert.equal(0 - NEEDED, -28); assert.equal(byIdx.get(107694001).mg, -28);
  assert.equal(20 - NEEDED, -8); assert.equal(byIdx.get(107690236).mg, -8);
  assert.equal(byIdx.get(107694001).sp, 0, "keine zweite Linie: die fuehrende Linie ist die einzige");
});

test("Schliess-Grenze: hoechstens 7 echte Nicht-Signierer, mindestens 12 / 28 / 8 Erfassungs-Luecke", () => {
  const expect = new Map([[107695059, 19], [107694001, 35], [107690236, 15]]);
  for (const st of rows) {
    const c = captureBound(st, evidence(st.l));
    assert.equal(c.closed, true);
    assert.equal(c.members, MEMBERS, "die dUNL-Groesse kommt nicht aus den eigenen Zahlen der Zeile");
    assert.equal(c.membersBasis, "derived", "ohne mm darf nur die eigene Nachrechnung als Basis stehen");
    assert.equal(c.needed, NEEDED);
    assert.equal(c.neededDerived, NEEDED);
    assert.equal(c.neededMatches, true, "Zeilenziel und nachgerechnetes Ziel sind nicht identisch");
    assert.equal(c.absentCount, expect.get(st.l));
    assert.equal(c.genuineAbsentMax, GENUINE_MAX, "35 - 28 = 7, mehr echte Nicht-Signierer zulaesst die Schliessung nicht");
    assert.equal(c.captureArtifactMin, expect.get(st.l) - GENUINE_MAX,
      "der Rest der Nicht-Signierer ist nachweisbar Erfassungs-Luecke dieses Recorders");
    assert.equal(c.captureComplete, false, "unter 28 gesehenen Mitgliedern ist ein Einzelbefund kein Knoten-Urteil");
    const cl = ledgerClosure(st, evidence(st.l));
    assert.equal(cl.closed, true);
    assert.equal(cl.basis, "xrpscan");
    assert.equal(cl.hash, st.ch);
    assert.equal(cl.verifiedBy, "xrplcluster.com");
  }
});

test("Diagnose: auf diesen geschlossenen Ledgern gibt es kein Netz-Quorum-Urteil", () => {
  const day = {
    date: "2026-10-16", ledgers: 378, quorumFail: 0, gaps: FIX.gaps, incidents: FIX.incidents,
    hourly: {}, validators: {}, ledgerStats: rows, anomaly: {}, anomalyFail: {},
    shapeSeen: 0, shapeMissing: 0, lastLedger: 107695059,
    firstMs: 1792135432000, lastMs: 1792154042000,
    networkQuorum: FIX.networkQuorum, networkQuorumSamples: FIX.networkQuorumSamples,
  };
  const q = quorumCriticality([day], VET, { range: "all" });
  assert.equal(q.checked, 3);
  assert.equal(q.critical, 0, "kein bewiesen geschlossener Ledger darf quorum-kritisch sein");
  assert.equal(q.closed, 3);
  assert.equal(q.captureGaps, 1, "nur 107694001 hat einen gemessenen Sprung im Luecken-Log");
  assert.equal(q.captureGapUnknown, 2, " fuer die anderen beiden ist nichts aufgezeichnet - offen, nicht frei");
  assert.equal(q.unanswered, 0);
  const out = new Map(q.rows.map((r) => [r.ledgerIndex, r]));
  for (const [l, expectAbsent] of [[107695059, 19], [107694001, 35], [107690236, 15]]) {
    const r = out.get(l);
    assert.equal(r.closure.closed, true);
    assert.equal(r.critical, false);
    assert.equal(r.type, "vote-not-observed",
      "auf einem geschlossenen Ledger ist der ehrliche Name kein Vote erfasst");
    assert.match(r.verdict, /^closed-/, "closed-* ist der einzige zulaessige Verdikt");
    assert.equal(r.needed, NEEDED);
    assert.equal(r.topVotes, byIdx.get(l).top);
    assert.equal(r.margin, byIdx.get(l).mg);
    // Betroffenheit: der eigene Knoten zaehlt mit, benannt werden die anderen.
    assert.equal(r.affectedCount, expectAbsent);
    assert.equal(r.affectedMasters.length, expectAbsent - 1);
    assert.deepEqual(r.affectedTypes, new Array(expectAbsent - 1).fill("vote-not-observed"));
  }
  assert.equal(out.get(107694001).verdict, "closed-capture-gap");
  assert.equal(out.get(107694001).captureGap, true);
  assert.equal(out.get(107694001).captureGapBasis, "stream-gap", "der Beleg ist der Luecken-Log des Tages");
  for (const l of [107695059, 107690236]) {
    assert.equal(out.get(l).captureGap, null, "kein Sprung erfasst und kein pg: die Frage bleibt offen");
    assert.equal(out.get(l).captureGapBasis, "not-recorded");
  }
});

test("Ziel-Herkunft: ein Tagesziel darf nur eintreten wenn es genau das Ziel dieser Zeile ist", () => {
  const own = captureBound(byIdx.get(107695059), evidence(107695059));
  assert.equal(own.neededBasis, "day-measured");
  assert.equal(own.networkQuorum, DAY_TARGET);
  assert.equal(own.networkQuorumBasis, "day-sample");
  assert.equal(own.networkQuorumSource, "wss://s1.ripple.com", "ohne benannten Endpunkt ist die Zahl nicht nachlesbar");
  assert.equal(own.networkQuorumSamples, 3);
  assert.ok(Number.isFinite(own.networkQuorumAtMs), "der Zeitpunkt der Messung fehlt");
  // Gegenfall: ein fremdes Ziel desselben Tages darf nicht geliehen werden - eine Grenze aus
  // einem fremden Ziel waere eine Schaetzung, keine Messung.
  const foreign = captureBound(byIdx.get(107695059), {
    parentGap: false, networkQuorum: { quorum: 30, atMs: 1792185804628, endpoint: "wss://s1.ripple.com", samples: 3 },
  });
  assert.equal(foreign.neededBasis, "not-recorded", "ein fremdes Ziel wird nicht zum eigenen Ziel erklaert");
  assert.equal(foreign.networkQuorum, null);
  assert.equal(foreign.networkQuorumBasis, null);
  assert.equal(foreign.genuineAbsentMax, GENUINE_MAX, "die Grenze rechnet weiter mit dem Ziel der Zeile selbst");
});
