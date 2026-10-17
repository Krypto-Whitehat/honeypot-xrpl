// lib/validator-trace-quorum-rows.test.mjs - Nachrechnung der restlichen Tafel-Zeilen.
//
// Warum diese Datei existiert: lib/validator-trace-fidelity.test.mjs nagelt die drei Ledger fest,
// die ein Betreiber als "no vote (network stall)" und "quorum-critical" gesehen hatte. Die live
// ausgelieferte Kritikalitaets-Tafel von xrp.vet fuehrt im 30-Tage-Fenster neun Zeilen. Vier davon
// stecken in den bestehenden Fixtures (drei in trace-2026-10-16-three-ledgers.json, eine in
// trace-2026-10-16-cohort-ledger.json). Diese Datei nagelt die anderen fuenf fest - an denselben
// ausgelieferten Bytes, mit denselben Grenzen, und an der Zeile, die als erste alles selbst traegt
// (mm/nb/nq/so/ms/gm/aa).
//
// Alle Erwartungswerte sind von Hand nachgerechnet. Hash, Tx-Zahl und Close-Zeit jeder Zeile sind
// am 2026-10-17 bei api.xrpscan.com/api/v1/ledger/<index> nachgelesen und stimmen mit der Datei.
import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { captureBound, ledgerClosure, parentGapCovered, dayGapRanges, TRACE_DEFAULTS } from "./validator-trace.mjs";
import { normalizeDay } from "./validator-trace-store.mjs";
import { quorumCriticality } from "./validator-diagnose.mjs";

const here = path.dirname(fileURLToPath(import.meta.url));
const FIX = JSON.parse(fs.readFileSync(path.join(here, "fixtures", "trace-2026-10-16-17-vet-quorum-rows.json"), "utf8"));
const HEX64 = /^[0-9A-F]{64}$/;
const VET = "nHBWa56Vr7csoFcCnEPzCCKVvnDQw3L28mATgHYQMGtbEfUjuYyB";
const FRAC = 0.8;
const MEMBERS = 35;
const NEEDED = 28;        // ceil(35 * 0,8) = 28
const GENUINE_MAX = 7;    // 35 - 28 = 7 echte Nicht-Signierer, hoechstens

// Handgerechnete Tafel: Index -> [gesehene Stimmen, Ziel, Marge, als fehlend geflaggte Mitglieder,
// Schliess-Grenze, daraus nachweisbare Erfassungs-Luecke, Verdikt, Beleg der Erfassungs-Luecke].
const EXPECT = new Map([
  // 11 - 28 = -17 | 0 + 24 = 24 fehlend | 24 - 7 = 17 | kein pg, 107695738 nicht im Luecken-Log
  [107695739, [11, 28, -17, 24, 17, "closed-observation-gap", "not-recorded"]],
  // 25 - 28 = -3 | 0 + 10 = 10 | 10 - 7 = 3 | 107698040 liegt im Luecken-Log 107698023-107698040
  [107698041, [25, 28, -3, 10, 3, "closed-capture-gap", "stream-gap"]],
  // 16 - 28 = -12 | 0 + 19 = 19 | 19 - 7 = 12 | 107699072 nicht im Log (der Log nennt 107699074)
  [107699073, [16, 28, -12, 19, 12, "closed-observation-gap", "not-recorded"]],
  // 18 - 28 = -10 | 0 + 17 = 17 | 17 - 7 = 10 | 107699399 nicht im Log
  [107699400, [18, 28, -10, 17, 10, "closed-observation-gap", "not-recorded"]],
  // 10 - 28 = -18 | 0 + 25 = 25 | 25 - 7 = 18 | so true: erster Ledger nach einem Abo
  [107709532, [10, 28, -18, 25, 18, "closed-capture-gap", "stream-open"]],
]);
// Die von xrpscan am 2026-10-17 gemeldeten Fakten: Hash, tx_count, close_time (Unix-Sekunden * 1000).
const SOURCE = new Map([
  [107695739, ["5766218C0581E6BF42CC64079065257FD9BB80D6AF4E8B587EE82C33765F96F3", 42, 1792156691000]],
  [107698041, ["7B4A34FAAA07C05EFE80EA37FCBAEF2AE2D4BD3B2EFA432A82042496AFE8B5AA", 73, 1792165712000]],
  [107699073, ["7D3097E9B011AC120B3BEEBE5C6A837A5AEADA2B0028668537858B13E9F1AB2D", null, 1792169761000]],
  [107699400, ["B14494D749617E35DF56ADFDB6B4840DCA24376235FF81D045FA3C77B5ACB770", 99, 1792171040000]],
  [107709532, ["DCBC00B5EBB3708C0EE9A126CA2DBAA24138FBEF356C3845D56423EFF73C6903", 31, 1792210322000]],
]);

const days = FIX.days.map((d) => normalizeDay(JSON.parse(JSON.stringify(d))));
const rows = days.flatMap((d) => d.ledgerStats);
const byIdx = new Map(rows.map((r) => [r.l, r]));
const dayOf = (l) => days.find((d) => d.ledgerStats.some((s) => s.l === l));
const flagged = (l) => new Set(FIX.days.flatMap((d) => d.incidents).filter((i) => i.l === l).map((i) => i.m));
const evidence = (l) => {
  const d = dayOf(l);
  return {
    parentGap: parentGapCovered(dayGapRanges(d), l),
    networkQuorum: d.networkQuorum ? { ...d.networkQuorum, samples: d.networkQuorumSamples } : null,
  };
};

test("Fixture: es sind die ausgelieferten Bytes, und ihre Identitaet ist festgenagelt", () => {
  assert.deepEqual(rows.map((r) => r.l), [107695739, 107698041, 107699073, 107699400, 107709532]);
  assert.equal(FIX.master, VET, "das Exzerpt gehoert zu xrp.vet");
  for (const [l, [hash, tx, t]] of SOURCE) {
    const st = byIdx.get(l);
    assert.equal(st.ch, hash, "#" + l + ": Schliess-Hash ist nicht der von xrpscan gemeldete");
    assert.match(st.ch, HEX64, "#" + l + ": ohne 64er-Hash ist die Zeile nicht nachlesbar");
    assert.equal(st.t, t, "#" + l + ": Close-Zeit widerspricht der Quelle");
    if (tx !== null) assert.equal(st.tx, tx, "#" + l + ": Tx-Zahl widerspricht xrpscan tx_count");
    assert.notEqual(st.cl, false, "#" + l + ": die Schliessung ist nicht verneint");
  }
});

test("dUNL-Groesse: 35 steht in der neuen Zeile, in den alten folgt sie aus den eigenen Zahlen", () => {
  assert.equal(TRACE_DEFAULTS.quorumFrac, FRAC, "die nachgerechnete Bruchzahl ist nicht die der Lib");
  assert.equal(Math.ceil(MEMBERS * FRAC), NEEDED, "35 * 0,8 = 28, genau 28, kein Aufrunden");
  for (const st of rows) {
    const absent = (st.c.missed ?? 0) + (st.c.noQuorum ?? 0);
    assert.equal(st.v + absent, MEMBERS, "#" + st.l + ": Mithoer-Identitaet gilt nicht");
    assert.equal(st.need, NEEDED, "#" + st.l + ": Zeilenziel ist nicht das nachrechenbare");
  }
  // Die neue Zeile traegt die Groesse selbst; die alten muessen sie rechnen. Beides muss
  // auf dieselbe Zahl fuehren, sonst waere 'members' je nach Build eine andere Tatsache.
  assert.equal(byIdx.get(107709532).mm, MEMBERS, "die neue Zeile traegt mm nicht");
  assert.equal(byIdx.get(107709532).nb, "measured", "das Ziel dieser Zeile ist am Endpunkt gemessen");
  assert.equal(byIdx.get(107709532).nq, NEEDED, "der gemessene Netz-Wert ist nicht das Zeilenziel");
  for (const l of [107695739, 107698041, 107699073, 107699400]) {
    assert.equal(byIdx.get(l).mm, undefined, "#" + l + ": diese aeltere Zeile darf mm nicht erfinden");
  }
});

test("Marge: fuehrende Linie minus Ziel, fuer alle fuenf von Hand gerechnet", () => {
  for (const [l, [top, need, margin]] of EXPECT) {
    const st = byIdx.get(l);
    assert.equal(top - need, margin, "#" + l + ": die handgerechnete Marge stimmt nicht");
    assert.equal(st.top, top, "#" + l + ": fuehrende Linie weicht ab");
    assert.equal(st.mg, margin, "#" + l + ": die Marge der Zeile weicht ab");
    assert.equal(st.sp, 0, "#" + l + ": keine zweite Linie aufgezeichnet");
  }
});

test("Schliess-Grenze: hoechstens 7 echte Nicht-Signierer, der Rest ist nachweisbar Luecke", () => {
  for (const [l, [, , , absent, artifactMin]] of EXPECT) {
    const c = captureBound(byIdx.get(l), evidence(l));
    assert.equal(c.closed, true, "#" + l + ": Schliessung nicht belegt");
    assert.equal(c.members, MEMBERS, "#" + l + ": dUNL-Groesse kommt nicht aus der Zeile");
    assert.equal(c.needed, NEEDED);
    assert.equal(c.neededDerived, NEEDED);
    assert.equal(c.neededMatches, true, "#" + l + ": Zeilenziel und nachgerechnetes Ziel divergieren");
    assert.equal(c.seenVotes, byIdx.get(l).top);
    assert.equal(c.absentCount, absent, "#" + l + ": fehlende Mitglieder sind nicht die geflaggten");
    assert.equal(c.genuineAbsentMax, GENUINE_MAX, "#" + l + ": 35 - 28 = 7, mehr zulaesst die Schliessung nicht");
    assert.equal(c.captureArtifactMin, artifactMin, "#" + l + ": " + absent + " - 7 = " + artifactMin);
    assert.equal(c.captureComplete, false, "#" + l + ": unter dem Ziel ist ein Einzelbefund kein Knoten-Urteil");
  }
  // Die Grenze ist eine Grenze, keine Zuordnung: welche der geflaggten Knoten wirklich fehlten,
  // steht nirgends in der Datei und darf nicht gesetzt werden.
  for (const [l, [, , , absent]] of EXPECT) {
    const c = captureBound(byIdx.get(l), evidence(l));
    assert.equal(flagged(l).size, absent, "#" + l + ": Vorfallsliste und Zaehler divergieren");
    assert.ok(c.genuineAbsentMax < absent, "#" + l + ": ohne Luecke waere die Grenze eine Entlastung ohne Grund");
  }
});

test("Erfassungs-Luecke: drei Zustande, jeder mit benanntem Beleg", () => {
  for (const [l, e] of EXPECT) {
    const basis = e[6];
    const cl = ledgerClosure(byIdx.get(l), evidence(l));
    assert.equal(cl.captureGapBasis, basis, "#" + l + ": die Herleitung der Erfassungs-Luecke ist eine andere");
    const expected = basis === "not-recorded" ? null : true;
    assert.equal(cl.captureGap, expected, "#" + l + ": 'nicht erfasst' und 'Luecke' duerfen nicht vermischt werden");
  }
  // 'cg' allein ist kein Beleg mehr: die neue Zeile traegt cg true, der Beleg ist 'so'.
  assert.equal(byIdx.get(107709532).cg, true, "die neue Zeile meldet die Warm-Lauf-Luecke");
  assert.equal(byIdx.get(107709532).so, true, "der Beleg dafoer ist das eigene Abo, nicht der Takt");
  assert.equal(byIdx.get(107709532).pg, null, "vor dem ersten ausgewerteten Ledger gibt es keine Index-Folge");
});

test("Schliess-Beleg: vier Zeilen mit xrpscan-Hash und xrplcluster-Gegenpruefung, eine aus dem Stream", () => {
  for (const l of [107695739, 107698041, 107699073, 107699400]) {
    const st = byIdx.get(l);
    const cl = ledgerClosure(st, evidence(l));
    assert.equal(cl.basis, "xrpscan", "#" + l + ": die Autoritaet ist nicht benannt");
    assert.equal(cl.hash, st.ch, "#" + l + ": der Beleg-Hash ist nicht der der Zeile");
    assert.equal(cl.verifiedBy, "xrplcluster.com", "#" + l + ": die zweite unabhaengige Autoritaet fehlt");
  }
  // Die neue Zeile nennt keinen chSource - ihr Hash stammt aus dem validierten Stream selbst.
  // Er ist trotzdem derselbe, den xrpscan meldet: die Gegenprobe gilt auch ohne nachgetragene Quelle.
  const st = byIdx.get(107709532);
  const cl = ledgerClosure(st, evidence(107709532));
  assert.equal(cl.basis, "validated-ledger-stream", "ohne chSource darf keine Fremd-Quelle behauptet werden");
  assert.equal(cl.hash, SOURCE.get(107709532)[0], "der Stream-Hash ist nicht der von xrpscan gemeldete");
  assert.equal(cl.verifiedBy, null, "ohne Gegenpruefung steht keine zweite Autoritaet da");
});

test("Diagnose: auf keiner dieser Zeilen steht ein Netz-Quorum-Urteil", () => {
  const q = quorumCriticality(days, VET, { range: "all" });
  assert.equal(q.checked, 5, "nicht jede der fuenf Zeilen erreicht die Tafel");
  assert.equal(q.critical, 0, "kein bewiesen geschlossener Ledger darf quorum-kritisch sein");
  assert.equal(q.closed, 5);
  assert.equal(q.captureGaps, 2, "107698041 (Luecken-Log) und 107709532 (Abo) sind gemessen");
  assert.equal(q.captureGapUnknown, 3, "fuer die anderen drei ist nichts aufgezeichnet - offen, nicht frei");
  const byQ = new Map(q.rows.map((r) => [r.ledgerIndex, r]));
  for (const [l, [top, need, margin, absent, artifactMin, verdict]] of EXPECT) {
    const r = byQ.get(l);
    assert.equal(r.verdict, verdict, "#" + l + ": das Verdikt ist ein anderes als nachgerechnet");
    assert.equal(r.margin, margin);
    assert.equal(r.topVotes, top);
    assert.equal(r.needed, need);
    assert.equal(r.capture.absentCount, absent);
    assert.equal(r.capture.genuineAbsentMax, GENUINE_MAX);
    assert.equal(r.capture.captureArtifactMin, artifactMin);
    assert.equal(r.critical, false, "#" + l + ": geschlossene Schliessung wird zum Netz-Urteil");
  }
});

test("Herkunft des Ziels: gemessen bleibt gemessen, sonst tritt die Tagesmessung ein", () => {
  const q = quorumCriticality(days, VET, { range: "all" });
  const byQ = new Map(q.rows.map((r) => [r.ledgerIndex, r]));
  const own = byQ.get(107709532).capture;
  assert.equal(own.neededBasis, "measured", "die Zeile traegt ihre eigene Messung und muss sie behalten");
  assert.equal(own.networkQuorumBasis, "ledger-row");
  assert.equal(own.membersBasis, "recorded", "mm ist aufgezeichnet, nicht gerechnet");
  for (const l of [107695739, 107698041, 107699073, 107699400]) {
    const c = byQ.get(l).capture;
    assert.equal(c.membersBasis, "derived", "#" + l + ": ohne mm darf nur die eigene Nachrechnung stehen");
    // Kein nb in der Zeile: das Ziel kommt aus der Messung desselben Tages, und nur weil ihr
    // gemessener Wert genau 28 ist - derselbe Wert wie das Zeilenziel.
    assert.equal(c.neededBasis, "day-measured", "#" + l + ": ein Ziel ohne eigene Herleitung bleibt offen");
    assert.equal(c.networkQuorum, NEEDED, "#" + l + ": die Tagesmessung ist nicht 28");
    assert.equal(c.networkQuorumBasis, "day-sample");
    assert.equal(c.networkQuorumSource, "wss://s1.ripple.com", "#" + l + ": der Endpunkt der Messung fehlt");
    assert.ok(Number.isFinite(c.networkQuorumAtMs), "#" + l + ": der Zeitpunkt der Messung fehlt");
  }
});

test("Zuordnung: die neue Zeile traegt ms/gm/aa, die alten lassen die Frage offen", () => {
  const st = byIdx.get(107709532);
  const c = captureBound(st, evidence(107709532));
  assert.equal(c.membersSeen, 10, "ms = gesehene Mitglieder, nicht gesehene Validierungen");
  assert.equal(st.ov, 38, "ov = alle empfangenen Validierungen, eine andere Zahl als die Mitgliederstimmen");
  assert.equal(c.seenVotes, 10, "seenVotes ist die Mitglieder-Linie, nicht der Empfang");
  assert.equal(c.coverageBaseline, null, "cb fehlt in dieser Zeile: kein Abdeckungs-Niveau, keine Entlastung");
  assert.equal(c.genuineAbsentMaxLedger, 7, "gm = 35 - 28 = 7");
  assert.equal(c.attributableAbsence, false,
    "10 gesehene Mitglieder bei 35 und fehlender Abdeckungs-Basis: kein fehlender Vote darf dem Knoten gehoeren");
  for (const l of [107695739, 107698041, 107699073, 107699400]) {
    const x = captureBound(byIdx.get(l), evidence(l));
    assert.equal(x.membersSeen, null, "#" + l + ": ms ist nicht aufgezeichnet und darf nicht gerechnet werden");
    assert.equal(x.coverageBaseline, null);
    assert.equal(x.genuineAbsentMaxLedger, null);
    assert.equal(x.attributableAbsence, null, "#" + l + ": offen ist weder Befund noch Entlastung");
  }
});

test("Nachfuehrung beim Lesen: alt wird umgefuehrt und belegt, neu bleibt unangetastet", () => {
  const LEGACY = [107695739, 107698041, 107699073, 107699400];
  // Altbestand: der Rekorder schrieb 'no-quorum' - eine Aussage ueber das Netz.
  for (const d of FIX.days) {
    for (const i of d.incidents) {
      if (LEGACY.includes(i.l)) assert.equal(i.type, "no-quorum", "#" + i.l + ": der Bestand schreibt nicht no-quorum");
    }
  }
  // Beim Lesen: Vokabel und Beleg, keine neue Zahl. Der geschriebene Typ bleibt in 'ts' lesbar.
  for (const d of days) {
    for (const i of d.incidents) {
      if (!LEGACY.includes(i.l)) continue;
      assert.equal(i.type, "vote-not-observed", "#" + i.l + ": ein bewiesen geschlossener Ledger bleibt ein Netz-Urteil");
      assert.equal(i.ts, "no-quorum", "#" + i.l + ": der urspruenglich geschriebene Typ ist nicht mehr lesbar");
      assert.deepEqual(i.r, ["vote-not-observed"], "#" + i.l + ": das Reason-Tag ist nicht mitgestellt");
      assert.equal(i.cb, "xrpscan", "#" + i.l + ": die Schliess-Aussage hat keine benannte Quelle");
      assert.match(i.ch, HEX64, "#" + i.l + ": der Schliess-Hash fehlt am Vorfall");
      assert.equal(i.chv, "xrplcluster.com", "#" + i.l + ": die Gegenpruefung fehlt am Vorfall");
      assert.equal(i.nc, undefined, "#" + i.l + ": diese Zeile verneint die Schliessung nirgends");
    }
  }
  // Neu: der Rekorder schreibt den Erfassungstyp selbst. Die Leseschicht darf ihn nicht nochmal
  // umstellen und keinen 'ts' erfinden - ein ts ohne Umstellung waere eine Behauptung ueber einen
  // Durchgang, der nicht stattfand. Der Beleg aber ist dieselbe Tatsache wie in der Forensik-Zeile
  // und muss am Vorfall genauso dastehen, sonst liest jemand 'Schliessung unbekannt' fuer einen
  // Ledger, den diese Auskunft selbst bewiesen hat.
  const fresh = days.flatMap((d) => d.incidents).find((i) => i.l === 107709532 && i.m === VET);
  const freshRow = byIdx.get(107709532);
  assert.equal(fresh.type, "vote-not-observed", "die neue Zeile schreibt den Erfassungstyp selbst");
  assert.equal(fresh.ts, undefined, "ohne Umstellung darf kein 'zuvor geschriebener Typ' dastehen");
  assert.equal(fresh.ch, SOURCE.get(107709532)[0], "der Vorfall nennt nicht denselben Hash wie die Zeile");
  assert.equal(fresh.cb, ledgerClosure(freshRow, evidence(107709532)).basis,
    "Vorfall und Zeile nennen dieselbe Autoritaet mit demselben Wort");
  assert.equal(fresh.chv, undefined, "fuer diese Zeile wurde keine zweite Autoritaet gehoert - also darf keine behauptet werden");
  assert.equal(freshRow.ch, SOURCE.get(107709532)[0], "der Beleg steht in der Zeile und muss dort stehen");
  assert.equal(freshRow.cl, true, "die Zeile sagt, dass das Netz geschlossen hat");
});

test("Beleg am Vorfall: jede Umstellung und jeder Eigen-Typ nennt die Schliess-Autoritaet desselben Ledgers", () => {
  // Kein Vorfall dieser Tafel darf ohne Schliess-Autoritaet dastehen, obwohl die Tagesdatei sie hat.
  const rows = new Map(days.flatMap((d) => d.ledgerStats).map((r) => [r.l, r]));
  const eigen = days.flatMap((d) => d.incidents).filter((i) => i.type === "vote-not-observed");
  let belegt = 0;
  for (const i of eigen) {
      const row = rows.get(i.l);
      assert.ok(row, "#" + i.l + ": ein Vorfall ohne Forensik-Zeile kann keinen Beleg tragen - die Luecke muss bleiben");
      assert.notEqual(row.cl, false, "#" + i.l + ": hier wird die Schliessung verneint, also keine Schliess-Autoritaet");
      assert.equal(i.cb, ledgerClosure(row, evidence(i.l)).basis, "#" + i.l + ": zwei Woerter fuer eine Autoritaet");
      if (typeof row.ch === "string" && HEX64.test(row.ch)) {
        assert.equal(i.ch, row.ch, "#" + i.l + ": der Vorfall nennt einen anderen Hash als die Zeile");
        assert.equal(i.chv ?? null, row.chVerifiedBy ?? null, "#" + i.l + ": die Gegenpruefung weicht ab");
      }
      belegt += 1;
  }
  // 70 Vorfaelle am 16.10. plus 25 am 17.10.: jeder einzelne steht auf einem Ledger, dessen
  // Schliessung diese Auskunft weis. Keiner darf ohne Autoritaet bleiben.
  assert.equal(eigen.length, 95, "70 + 25 Vorfaelle in diesem Exzerpt");
  assert.equal(belegt, eigen.length, "ein Vorfall bleibt ohne Schliess-Autoritaet, obwohl die Zeile sie hat");
});

test("Exzerpt-Grenze: der Tages-Zaehler ist in diesem Schnitt nicht deckbar und wird benannt", () => {
  const d16 = days.find((d) => d.date === "2026-10-16");
  assert.equal(d16.quorumFail, 11, "der ausgelieferte Zaehler ist nicht 11");
  assert.equal(d16.ledgerStats.length, 4, "dieses Exzerpt fuehrt vier Zeilen");
  const gap = d16.counterGaps.find((g) => g.tag === "quorum-fail");
  assert.ok(gap, "ein Zaehler ohne deckbare Forensik-Zeile wird nicht als Luecke ausgewiesen");
  assert.equal(gap.counter, 11);
  assert.equal(gap.shortRows, 4, "11 Zaehler gegen 4 Zeilen in diesem Schnitt");
  assert.equal(gap.ledgers, 7, "11 - 4 = 7");
  assert.equal(gap.reason, "counter-without-forensics-row");
});
