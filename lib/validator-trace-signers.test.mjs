// lib/validator-trace-signers.test.mjs - Signer-Beleg je Ledger: wer hat wirklich abgestimmt.
//
// Warum diese Datei existiert: die Kritikalitaets-Tafel nannte je Ledger die Knoten, die dieser
// Rekorder NICHT sah, und benannte sie. Die Gegenseite fehlte - die Knoten, die auf demselben
// Ledger abgestimmt haben. Ohne sie ist "6 Knoten fehlten hier" eine Zahl ohne Entlastungsseite:
// ob das Netz in diesem Ledger fuer andere erreichbar war, musste der Leser raten. Diese Datei
// nagelt die Beobachtung fest (Tracker), ihre Speicherung als Bitfeld (Diagnose-Lesepfad) und
// ihre Grenzen (Altbestand ohne Beleg ist nicht "niemand hat abgestimmt").
import test from "node:test";
import { readFileSync } from "node:fs";
import assert from "node:assert/strict";
import { createTracker } from "./validator-trace.mjs";
import { normalizeDay } from "./validator-trace-store.mjs";
import { quorumCriticality, VOTER_BASES } from "./validator-diagnose.mjs";
import { traceForValidator } from "./validator-trace-query.mjs";

const M = Array.from({ length: 35 }, (_, i) => "nMEMBER" + String(i).padStart(2, "0"));
const E = new Map(M.map((m, i) => ["nEPH" + String(i).padStart(2, "0"), m]));
const SIGN = (m) => [...E.entries()].find(([, v]) => v === m)[0];
const T0 = 1_000_000;
const HEX = (c) => c.repeat(64);
const setup = () => createTracker({ members: M, ephemeralToMaster: E, opts: { graceMs: 0 } });
const ledger = (idx, hash) => ({ ledgerIndex: idx, hash, closeMs: T0 + idx, txCount: 20 });
const val = (m, idx, hash, t) => ({ signingKey: SIGN(m), ledgerIndex: idx, ledgerHash: hash, full: true, t: t ?? T0 + idx + 1 });
// Abdeckungs-Basis: erst ab voteBaselineMin (20) bewerteten Ledgern ist der eigene Median eine
// Zahl. Ohne Warm-Lauf duerfte 'missed' gar nicht zugeschrieben werden - ein Test ohne Warm-Lauf
// bewiese eine Regel, die gar nicht geprueft wird.
function warm(tr, from, n = 24) {
  for (let i = 0; i < n; i++) {
    const idx = from + i;
    tr.onLedger(ledger(idx, HEX("a")));
    for (const m of M) tr.onValidation(val(m, idx, HEX("a")));
    tr.evaluate(T0 + idx + 5_000);
  }
}

test("signerMasters: die Knoten mit angekommener Validierung stehen namentlich da", () => {
  const tr = setup();
  tr.onLedger(ledger(101, HEX("a")));
  for (const m of M.slice(0, 12)) tr.onValidation(val(m, 101, HEX("a")));
  const [r] = tr.evaluate(T0 + 101 + 5_000);
  assert.deepEqual(r.forensics.signerMasters, M.slice(0, 12));
  assert.equal(r.forensics.signerMasters.length, r.forensics.membersSeen,
    "die benannte Menge und die Zahl der gesehenen Mitglieder duerfen nie auseinanderlaufen");
});

test("signerMasters: die Reihenfolge folgt der Mitgliederliste, nicht der Ankunft", () => {
  const tr = setup();
  tr.onLedger(ledger(102, HEX("b")));
  tr.onValidation(val(M[30], 102, HEX("b"), T0 + 102 + 1));
  tr.onValidation(val(M[3], 102, HEX("b"), T0 + 102 + 2));
  tr.onValidation(val(M[17], 102, HEX("b"), T0 + 102 + 3));
  const [r] = tr.evaluate(T0 + 102 + 5_000);
  assert.deepEqual(r.forensics.signerMasters, [M[3], M[17], M[30]],
    "Ankunftsreihenfolge in einer Datei waere eine Zuordnung, die niemand nachlesen kann");
});

test("closureConflict: gesehene Mehrheit weicht vom Schliess-Hash ab - kein Knoten-Urteil darauf", () => {
  const tr = setup();
  warm(tr, 100);
  // Das Netz schliesst 134 mit 'c', dieser Rekorder sieht 30 Stimmen auf 'd'. Beides steht in
  // seiner eigenen Aufzeichnung; der Widerspruch ist gemessen, nicht geschaetzt.
  tr.onLedger(ledger(134, HEX("c")));
  for (const m of M.slice(0, 30)) tr.onValidation(val(m, 134, HEX("d")));
  const [r] = tr.evaluate(T0 + 134 + 5_000);
  assert.equal(r.forensics.topHash, HEX("d"));
  assert.equal(r.forensics.closedHash, HEX("c"));
  assert.equal(r.forensics.closureConflict, true);
  assert.equal(r.hasQuorum, true, "die eigene Mehrheit erreicht das Ziel - und ist trotzdem nicht die Linie des Netzes");
  assert.equal(r.forensics.attributableAbsence, false,
    "auf einer Sicht, die dem Schliess-Beweis widerspricht, darf kein fehlender Vote ein Knoten-Befund sein");
  assert.ok(!r.incidents.some((i) => i.type === "missed"), "kein 'missed' auf einem Ledger mit Schliess-Widerspruch");
  assert.equal(r.incidents.length, 5);
  assert.ok(r.incidents.every((i) => i.type === "vote-not-observed"));
});

test("closureConflict: ohne Widerspruch bleibt die Zurechnung moeglich", () => {
  const tr = setup();
  warm(tr, 100);
  // 32 von 35 gesehen: ueber dem eigenen Abdeckungs-Niveau (35 * 0,9 = 31,5), und die drei
  // fehlenden passen in den Schliess-Beweis (35 - 28 = 7). Damit ist die Zurechnung offen und
  // nicht durch einen Widerspruch gesperrt.
  // 124 folgt direkt auf den Warm-Lauf (100..123): ohne eigene Index-Luecke, sonst waere die
  // Zurechnung aus einem anderen Grund gesperrt und der Fall wuerde eine andere Regel pruefen.
  tr.onLedger(ledger(124, HEX("c")));
  for (const m of M.slice(0, 32)) tr.onValidation(val(m, 124, HEX("c")));
  const [r] = tr.evaluate(T0 + 124 + 5_000);
  assert.equal(r.previousLedger, 123, "124 = 123 + 1: diese Erfassung hat keinen Index uebersprungen");
  assert.equal(r.captureGap, false);
  assert.equal(r.forensics.closureConflict, false);
  assert.equal(r.forensics.attributableAbsence, true);
  assert.equal(r.incidents.filter((i) => i.type === "missed").length, 3);
});

/* #107717666 live (2026-10-17): previousLedger 107717663, also zwei nie gesehene Indizes. Das
 * Netz schloss diesen Ledger 1000 ms nach seinem Vater (api.xrpscan.com close_time 1792241722,
 * parent_close_time 1792241721), diese Erfassung mass 11000 ms. 33 von 35 Mitgliedern kamen an -
 * uber dem eigenen Abdeckungs-Niveau - und zwei Knoten standen als 'missed' da, die Netz-Referenz
 * nennt fuer beide 0 verpasste Ledger von 22276. Ueber eine Index-Luecke kann sich die dUNL
 * geaendert haben, ohne dass diese Erfassung die Aenderung sah, und die Gnadenfrist war nach dem
 * Nachziehen kuerzer. Deshalb: eigene Erfassungs-Luecke sperrt die Zurechnung. */
test("Eigene Index-Luecke sperrt die Zurechnung: 32 von 35 gesehen, zwei Indizes fehlen -> vote-not-observed", () => {
  const tr = setup();
  warm(tr, 100);
  tr.onLedger(ledger(126, HEX("c")));
  for (const m of M.slice(0, 32)) tr.onValidation(val(m, 126, HEX("c")));
  const [r] = tr.evaluate(T0 + 126 + 5_000);
  assert.equal(r.previousLedger, 123, "124 und 125 wurden nie ausgewertet");
  assert.equal(r.captureGap, true, "ein uebersprungener Index ist eine gemessene Erfassungs-Luecke");
  assert.equal(r.hasQuorum, true, "32 >= 28: das Ziel ist erreicht - und traegt den Befund trotzdem nicht");
  assert.equal(r.forensics.membersSeen, 32, "32 >= 35 * 0,9 = 31,5: die Abdeckung allein waere zu milde");
  assert.equal(r.forensics.genuineAbsentMaxLedger, 7, "3 <= 7: auch der Schliess-Beweis waere zu milde");
  assert.equal(r.forensics.attributableAbsence, false,
    "auf einem Ledger mit eigener Index-Luecke darf kein fehlender Vote ein Knoten-Befund sein");
  assert.equal(r.incidents.length, 3);
  assert.ok(r.incidents.every((i) => i.type === "vote-not-observed"), "kein 'missed' auf eigener Luecke");
  assert.equal(r.forensics.counts.missed, 0, "der Zaehler darf keine Knoten-Absenz behaupten");
  assert.equal(r.forensics.counts.noQuorum, 3, "drei Nicht-Beobachtungen, benannt als solche");
});

/* ---------- Lesepfad: Bitfeld -> Namen ---------- */
const NOW = Date.UTC(2026, 9, 16, 12, 0, 0);
const VET = "nMEMBER00";
const stat = (l, over = {}) => ({
  l, t: NOW - 1000, v: 30, need: 28, top: 30, mg: 2, sp: 0, gap: 4000, gmed: 4000,
  tx: 20, med: 20, c: {}, cl: true, ch: HEX("a"), ms: 30, ...over,
});
const dayOf = (over = {}) => ({
  date: "2026-10-16", ledgers: 100, quorumFail: 0, gaps: [], incidents: [], hourly: {},
  validators: {}, ledgerStats: [], anomaly: {}, anomalyFail: {}, shapeSeen: 0, shapeMissing: 0,
  lastLedger: 199, firstMs: NOW - 1000, lastMs: NOW - 1000, ...over,
});
// Dasselbe Bitfeld wie der Rekorder: arithmetisch gesetzt, weil Bitoperatoren in JavaScript bei
// 32 Stellen enden und die dUNL 35 Mitglieder hat.
const maskOf = (list, picked) => picked.reduce((acc, m) => {
  const i = list.indexOf(m);
  if (i < 0) throw new Error("Signierer ausserhalb der Mitgliederliste: " + m);
  return acc + 2 ** i;
}, 0);

test("Kritikalitaets-Zeile: das Bitfeld wird auf die Bewertungsliste zurueckgelesen", () => {
  // Rueckgabe in Mitgliederreihenfolge: das Bitfeld wird Stelle fuer Stelle gelesen, also ist
  // die Ordnung die der Liste, nicht die der Auswahl.
  const picked = [M[0], M[4], M[11], M[12], M[33], M[34]];
  const d = dayOf({
    memberSets: [{ m: [...M] }],
    incidents: [{ l: 150, m: VET, t: NOW - 1000, type: "vote-not-observed", r: [] }],
    ledgerStats: [stat(150, { sgn: picked.length, sgm: maskOf(M, picked), sgs: 0, ms: picked.length })],
  });
  normalizeDay(d);
  const rows = quorumCriticality([d], VET, { range: "all", now: NOW }).rows;
  assert.equal(rows.length, 1);
  assert.deepEqual(rows[0].voters, picked);
  assert.equal(rows[0].voterCount, picked.length);
  assert.equal(rows[0].voterBasis, "bitfield");
});

test("Bitfeld jenseits von 32 Stellen: die dUNL hat 35 Mitglieder, Bitoperatoren enden bei 32", () => {
  const picked = [M[31], M[32], M[33], M[34]];
  const d = dayOf({
    memberSets: [{ m: [...M] }],
    incidents: [{ l: 151, m: VET, t: NOW - 1000, type: "vote-not-observed", r: [] }],
    ledgerStats: [stat(151, { sgn: picked.length, sgm: maskOf(M, picked), sgs: 0, ms: picked.length })],
  });
  normalizeDay(d);
  const [row] = quorumCriticality([d], VET, { range: "all", now: NOW }).rows;
  assert.deepEqual(row.voters, picked, "Stelle 32 bis 34 duerfen nicht still verschwinden");
});

test("Ohne Mitgliederliste ist das Bitfeld eine Zahl ohne Zuordnung - nicht 'niemand'", () => {
  const d = dayOf({
    memberSets: [{ m: [] }],
    incidents: [{ l: 152, m: VET, t: NOW - 1000, type: "vote-not-observed", r: [] }],
    ledgerStats: [stat(152, { sgn: 6, sgm: 63, sgs: 0, ms: 6 })],
  });
  normalizeDay(d);
  const [row] = quorumCriticality([d], VET, { range: "all", now: NOW }).rows;
  assert.equal(row.voters, null);
  assert.equal(row.voterCount, null);
  assert.equal(row.voterBasis, "not-recorded", "dieser Tag fuehrt den Beleg, diese Zeile traegt ihn nicht");
});

test("Altbestand vor dem Signer-Beleg heisst 'nicht erhoben', nicht 'nicht erfasst'", () => {
  const d = dayOf({
    incidents: [{ l: 153, m: VET, t: NOW - 1000, type: "vote-not-observed", r: [] }],
    ledgerStats: [stat(153)],
  });
  normalizeDay(d);
  assert.equal(d.memberSetsRecorded, false, "ohne memberSets in der Datei wurde diese Ebene nie gefuehrt");
  const [row] = quorumCriticality([d], VET, { range: "all", now: NOW }).rows;
  assert.equal(row.voters, null);
  assert.equal(row.voterBasis, "not-collected");
});

test("Notsignal ueber 50 Mitglieder: die Keys stehen ausgeschrieben, das Bitfeld wird nicht erraten", () => {
  const wide = Array.from({ length: 60 }, (_, i) => "nWIDE" + String(i).padStart(2, "0"));
  const picked = [wide[5], wide[59]];
  const d = dayOf({
    memberSets: [{ m: wide }],
    incidents: [{ l: 154, m: VET, t: NOW - 1000, type: "vote-not-observed", r: [] }],
    ledgerStats: [stat(154, { sgn: picked.length, sgm: null, sgs: null, sg: picked, ms: picked.length })],
  });
  normalizeDay(d);
  const [row] = quorumCriticality([d], VET, { range: "all", now: NOW }).rows;
  assert.deepEqual(row.voters, picked);
  assert.equal(row.voterBasis, "recorded-keys");
});

test("Schliess-Widerspruch an der Zeile: das Quorum-Urteil darf eine widerlegte Einigung nicht belegen", () => {
  const d = dayOf({
    memberSets: [{ m: [...M] }],
    incidents: [{ l: 155, m: VET, t: NOW - 1000, type: "vote-not-observed", r: [] }],
    ledgerStats: [stat(155, { cc: true, th: HEX("d"), ah: HEX("c") })],
  });
  normalizeDay(d);
  const [row] = quorumCriticality([d], VET, { range: "all", now: NOW }).rows;
  assert.equal(row.lineConflict, true);
  assert.equal(row.verdict, "closed-line-conflict",
    "'closed - quorum seen here' auf einer Linie, die das Netz nicht gewaehlt hat, waere ein Beleg ohne Halt");
});

test("Zeile ohne Widerspruch behaelt ihr Quorum-Urteil", () => {
  const d = dayOf({
    memberSets: [{ m: [...M] }],
    incidents: [{ l: 156, m: VET, t: NOW - 1000, type: "vote-not-observed", r: [] }],
    ledgerStats: [stat(156, { th: HEX("a"), ah: HEX("a") })],
  });
  normalizeDay(d);
  const [row] = quorumCriticality([d], VET, { range: "all", now: NOW }).rows;
  assert.equal(row.lineConflict, false);
  assert.equal(row.verdict, "closed-quorum-observed");
});

test("Benennung der Abgestimmten kommt aus derselben Auskunft wie die der Fehlenden", () => {
  const picked = [M[0], M[7]];
  const d = dayOf({
    memberSets: [{ m: [...M] }],
    incidents: [{ l: 157, m: VET, t: NOW - 1000, type: "vote-not-observed", r: [] }],
    ledgerStats: [stat(157, { sgn: picked.length, sgm: maskOf(M, picked), sgs: 0, ms: picked.length })],
  });
  normalizeDay(d);
  const groundPeers = new Map([[M[0], { name: "ripple.com" }]]);
  const t = traceForValidator([d], VET, { range: "all", now: NOW, groundPeers });
  const row = t.diagnosis.criticality.rows[0];
  assert.deepEqual(row.voterNames, [{ master: M[0], name: "ripple.com" }, { master: M[7], name: null }]);
});

test("Ohne Beleg wird keine Namensliste erfunden", () => {
  const d = dayOf({
    incidents: [{ l: 158, m: VET, t: NOW - 1000, type: "vote-not-observed", r: [] }],
    ledgerStats: [stat(158)],
  });
  normalizeDay(d);
  const t = traceForValidator([d], VET, { range: "all", now: NOW, groundPeers: new Map([[M[0], { name: "ripple.com" }]]) });
  const row = t.diagnosis.criticality.rows[0];
  assert.equal(row.voters, null);
  assert.equal(row.voterNames, undefined, "eine leere Liste waere die Aussage 'niemand hat abgestimmt'");
});

test("Die vier Herkunfte des Signer-Belegs sind eine abgeschlossene Menge", () => {
  assert.deepEqual(VOTER_BASES.slice().sort(), ["bitfield", "not-collected", "not-recorded", "recorded-keys"]);
});

/* Schreibseite (2026-10-17): der Rekorder ist der einzige Ort, der den Signer-Beleg erzeugt.
 * Bisher fuehrte kein Test diesen Pfad. Ein stiller Wegfall der Felder waere in den ausgelieferten
 * Dateien erst sichtbar geworden, wenn jemand die Tafel liest und 'not-collected' sieht. Diese
 * Zeile haelt die Schreibseite an die Leseseite: dieselben Feldnamen, dieselbe Bit-Stellung,
 * dieselbe Mitgliederliste. */
test("Schreibseite: der Rekorder schreibt genau die Felder, die die Diagnose-Lesung sucht", () => {
  const rec = readFileSync(new URL("../monitor/validator-trace.mjs", import.meta.url), "utf8");
  const diag = readFileSync(new URL("./validator-diagnose.mjs", import.meta.url), "utf8");
  for (const field of ["sgn:", "sgm:", "sgs:", "sg:"]) {
    assert.ok(rec.includes(field), "der Rekorder schreibt " + field + " nicht mehr in die Ledger-Zeile");
  }
  assert.ok(rec.includes("f.signerMasters"), "der Rekorder nimmt den Beleg nicht mehr aus der Forensik-Zeile");
  assert.ok(rec.includes("d.memberSets.push({ m:"), "die Mitgliederliste verlaesst ihren Schluessel 'm'");
  assert.ok(rec.includes("mask += 2 ** i"), "die Bit-Stellung ist nicht mehr 2 ** i je Mitglied");
  for (const k of ["st.sg", "st.sgm", "st.sgs", "memberSets"]) {
    assert.ok(diag.includes(k), "die Leseseite sucht " + k + " nicht mehr");
  }
  assert.ok(diag.includes("sets[idx]?.m"), "die Leseseite liest die Liste unter einem anderen Schluessel");
});
