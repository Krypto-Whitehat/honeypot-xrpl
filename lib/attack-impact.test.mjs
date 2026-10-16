// lib/attack-impact.test.mjs — Prueft die Angriffswirkung gegen ihre eigenen Fallen.
//
// Die Engine darf drei Dinge nicht: (1) einen Zusammenhang erfinden, wenn Angriffsstunden und
// Aufzeichnungsstunden nie zusammentreffen; (2) die Tageszeit fuer den Angriff halten; (3) eine
// unbeobachtete Stunde als ruhige Stunde in die Gegenprobe nehmen. Jeder Fall ist durchgerechnet.
import test from "node:test";
import assert from "node:assert/strict";
import { IMPACT_DEFAULTS, IMPACT_VERDICTS, attackImpact } from "./attack-impact.mjs";

const HOUR = 3600000;
// Funf Knoten: vier mit Ausfaellen, einer, der nie faellt. Ein Netz-Urteil braucht mehrere
// tragende Knoten - ein Fixture mit genau einem faellenden Knoten darf keins liefern.
const MEMBERS = ["mA", "mB", "mC", "mD", "mE"];
const FAILERS = ["mA", "mB", "mC", "mD"];
const NOW = Date.parse("2026-10-09T00:00:00.000Z");
let ledgerSeq = 100000;

// Eine Stunde mit Ledger-Nenner und Ausfaellen. Jeder Ausfall trifft einen eigenen
// Ledger-Index, distinct Ausfall-Ledger = Anzahl Vorfaelle.
function hourCell(at, ledgers, fails = {}) {
  return { at: Date.parse(at), ledgers, fails };
}

function makeDay(date, cells) {
  const d = {
    date, ledgers: 0, quorumFail: 0, validators: {}, incidents: [], gaps: [], hourly: {},
    firstMs: null, lastMs: null,
  };
  for (const c of cells) {
    const hk = Math.floor(c.at / HOUR);
    const hb = (d.hourly[hk] ??= { l: 0, v: {} });
    hb.l += c.ledgers;
    for (const m of MEMBERS) hb.v[m] ??= { ok: 0, partial: 0, missed: 0, wrongHash: 0, noQuorum: 0 };
    const failsBy = new Map(FAILERS.map((m) => [m, 0]));
    let failed = 0;
    for (const [type, count] of Object.entries(c.fails)) {
      const key = type === "wrong-hash" ? "wrongHash" : type === "no-quorum" ? "noQuorum" : type;
      for (let i = 0; i < count; i += 1) {
        const m = FAILERS[failed % FAILERS.length]; // Ausfaelle treffen die Kohorte, nicht einen Knoten
        ledgerSeq += 1;
        d.incidents.push({ l: ledgerSeq, m, t: c.at + i * 1000, type, r: [] });
        hb.v[m][key] += 1;
        failsBy.set(m, failsBy.get(m) + 1);
        failed += 1;
      }
    }
    for (const m of MEMBERS) hb.v[m].ok += c.ledgers - (failsBy.get(m) ?? 0);
    d.ledgers += c.ledgers;
    if (d.firstMs === null || c.at < d.firstMs) d.firstMs = c.at;
    if (d.lastMs === null || c.at > d.lastMs) d.lastMs = c.at;
  }
  return d;
}

// Acht Tage mit je zwei gemessenen Stunden (03 UTC und 10 UTC, je 1.000 Ledger). 03 UTC ist die
// stoesste Stunde des Netzes, 10 UTC die ruhige - die Falle liegt in genau diesem Unterschied.
function daysWith({ attackDays, rateAt3, rateAt10 }) {
  const days = [];
  for (let day = 1; day <= 8; day += 1) {
    const iso = (h) => `2026-10-0${day}T${String(h).padStart(2, "0")}:00:00.000Z`;
    const attacked = attackDays.includes(day);
    days.push(makeDay(`2026-10-0${day}`, [
      hourCell(iso(3), 1000, { missed: Math.round((attacked ? rateAt3.attack : rateAt3.quiet) * 1000) }),
      hourCell(iso(10), 1000, { missed: Math.round((attacked ? rateAt10.attack : rateAt10.quiet) * 1000) }),
    ]));
  }
  return days;
}

function clustersFor({ hours = [3], days: which = [1, 2, 3, 4] } = {}) {
  const out = [];
  for (const day of which) {
    for (const h of hours) {
      const first = Date.parse(`2026-10-0${day}T${String(h).padStart(2, "0")}:20:00.000Z`);
      out.push({
        key: `c-${day}-${h}`, members: ["rBait1", "rBait2"], label: "Cluster", totalDrops: 1000000,
        txCount: 12, distinctAccounts: 4, firstSeen: first, lastSeen: first + 120000,
        rules: ["drainer-sweep", "dusting"], severity: "malicious", sightings: 1,
      });
    }
  }
  return out;
}

test("Urteils-Mengen sind vollstaendig und eindeutig", () => {
  assert.deepEqual(IMPACT_VERDICTS, ["attack-linked", "node-driven", "no-link", "thin-overlap", "no-overlap", "unknown"]);
  assert.equal(new Set(IMPACT_VERDICTS).size, IMPACT_VERDICTS.length);
});

// Angriffsstunden 03 UTC (Tage 1-4): 200 von 1.000 Ledgers fallen, verteilt auf vier Knoten.
// Gepaarte Ruhe 03 UTC (Tage 5-8): 20 von 1.000. Nenner sind Knoten-Slots: 5 Knoten x 1.000
// Ledger = 5.000 je Stunde, also 20.000 je Gruppe.
// ratio = 800/20.000 gegen 80/20.000 = 0,04 / 0,004 = 10.
// z nachgerechnet: p1=0,04 p2=0,004 pooled=0,022 se=sqrt(0,022*0,978*(1/20000+1/20000))=0,00146683
// z = 0,036 / 0,00146683 = 24,54
test("Zusammenhang wird gefunden: 20 % in Angriffsstunden gegen 2 % in derselben UTC-Stunde", () => {
  const days = daysWith({
    attackDays: [1, 2, 3, 4],
    rateAt3: { attack: 0.2, quiet: 0.02 },
    rateAt10: { attack: 0.02, quiet: 0.005 },
  });
  const r = attackImpact(days, clustersFor(), { range: "all", now: NOW });
  assert.equal(r.verdict, "attack-linked");
  assert.equal(r.coverage.overlapCells, 4);
  assert.equal(r.coverage.attackLedgers, 4000);
  assert.equal(r.network.rateWith, 0.04);
  assert.equal(r.network.ledgerRateWith, 0.2, "Ledger-Ebene bleibt daneben lesbar");
  assert.equal(r.matched.rateAttack, 0.04);
  assert.equal(r.matched.rateMatched, 0.004);
  assert.equal(r.matched.ratio, 10);
  assert.equal(r.matched.cells, 4);
  assert.equal(r.matched.uncontrolledCells, 0);
  assert.ok(Math.abs(r.matched.z - 24.54) < 0.05, "z-Wert passt nicht zur Handrechnung: " + r.matched.z);
  assert.ok(r.network.lift > 3);
  assert.equal(r.network.contributingValidators, 4, "vier Knoten tragen den Effekt - das ist ein Netz-Befund");
});

// Die 03-Uhr-Stunde faellt im Netz IMMER mit 2 % aus. Die Angriffswellen liegen alle um 03 UTC.
// Roher Vergleich gegen alle ruhigen Stunden (inklusive 10 UTC mit 0,5 %): 0,02 / 0,01 = Lift 2
// und ein z weit ueber der Schwelle. Die gepaarte Gegenprobe sagt 1,0 -> kein Angriffsurteil.
test("Tageszeit-Falle: roher Lift 2,0, gepaarter Lift 1,0 -> kein Angriffsurteil", () => {
  const days = daysWith({
    attackDays: [1, 2, 3, 4],
    rateAt3: { attack: 0.02, quiet: 0.02 },
    rateAt10: { attack: 0.005, quiet: 0.005 },
  });
  const r = attackImpact(days, clustersFor(), { range: "all", now: NOW });
  assert.equal(r.verdict, "no-link");
  assert.equal(r.network.rateWithout, 0.002);
  assert.equal(r.network.lift, 2);
  assert.ok(Math.abs(r.network.zRaw) > 2, "der rohe z-Wert muss die Falle zeigen: " + r.network.zRaw);
  assert.equal(r.matched.ratio, 1);
  assert.equal(r.matched.rateMatched, 0.004);
  assert.ok(Math.abs(r.matched.z) < 0.01, "gepaarter z-Wert muss null sein: " + r.matched.z);
});

test("Keine Ueberlappung wird als solche benannt, nicht als 'kein Zusammenhang'", () => {
  const days = daysWith({
    attackDays: [],
    rateAt3: { attack: 0.02, quiet: 0.02 },
    rateAt10: { attack: 0.005, quiet: 0.005 },
  });
  const clusters = clustersFor({ hours: [21] }); // 21 UTC: nie aufgezeichnet
  const r = attackImpact(days, clusters, { range: "all", now: NOW });
  assert.equal(r.verdict, "no-overlap");
  assert.equal(r.coverage.overlapCells, 0);
  assert.equal(r.coverage.attackCells, 4);
  assert.equal(r.coverage.clustersInWindow, 4);
  assert.equal(r.coverage.clustersOutsideRecording, 4);
  assert.equal(r.network.rateWith, null, "ohne Angriffs-Ledger darf keine Rate stehen");
  assert.equal(r.network.rateWithout, 0.0025);
});

test("Duennueberlappung wird nicht zum Urteil, auch bei grossem Effekt", () => {
  const days = daysWith({
    attackDays: [1, 2],
    rateAt3: { attack: 0.4, quiet: 0.02 },
    rateAt10: { attack: 0.02, quiet: 0.005 },
  });
  const r = attackImpact(days, clustersFor({ days: [1, 2] }), { range: "all", now: NOW });
  assert.equal(r.verdict, "thin-overlap");
  assert.equal(r.coverage.overlapCells, 2);
  assert.ok(r.matched.ratio > 5, "der Effekt ist gross - und darf trotzdem kein Urteil sein");
});

test("Unbeobachtete Stunde zaehlt nicht als ruhige Stunde", () => {
  const days = daysWith({
    attackDays: [1, 2, 3, 4],
    rateAt3: { attack: 0.2, quiet: 0.02 },
    rateAt10: { attack: 0.02, quiet: 0.005 },
  });
  // 21 UTC: nur 10 Ledger aufgezeichnet, aber 5 Vorfaelle -> 50 % Rate. Duenn, also raus.
  days.push(makeDay("2026-10-05", [hourCell("2026-10-05T21:00:00.000Z", 10, { missed: 5 })]));
  const r = attackImpact(days, clustersFor(), { range: "all", now: NOW });
  assert.equal(r.coverage.thinCells, 1);
  assert.equal(r.coverage.quietLedgers, 12000, "die 10-Ledger-Stunde darf nicht in den Nenner");
  assert.equal(r.coverage.incidentsOutsideMeasuredCells, 5);
  // Ruhe: 03 UTC (Tage 5-8) 4x20 + 10 UTC (Tage 1-4) 4x20 + 10 UTC (Tage 5-8) 4x5 = 180
  assert.equal(r.network.incidentLedgersWithout, 180);
  assert.equal(r.network.rateWithout, 0.003);
});

test("Vorfaelle in einer nicht gemessenen Stunde werden ausgewiesen, nicht verschluckt", () => {
  const days = [makeDay("2026-10-01", [hourCell("2026-10-01T03:00:00.000Z", 20, { missed: 6 })])];
  const r = attackImpact(days, clustersFor({ days: [1] }), { range: "all", now: NOW });
  assert.equal(r.verdict, "unknown");
  assert.equal(r.coverage.measuredCells, 0);
  assert.equal(r.coverage.incidentsOutsideMeasuredCells, 6);
});

// Acht Tage, je vier Stunden: 02 UTC 1 %, 03 UTC 20 % (nur Tage 1-4 angegriffen, sonst 1 %),
// 04 UTC 12 %, 10 UTC 1 %. Die Nachwirkung ist separat lesbar, weil 04 UTC nicht dazugehoert.
test("Lag: die Rate nach der Welle ist separat sichtbar", () => {
  const days = [];
  for (let day = 1; day <= 8; day += 1) {
    const attacked = day <= 4;
    const iso = (h) => `2026-10-0${day}T${String(h).padStart(2, "0")}:00:00.000Z`;
    days.push(makeDay(`2026-10-0${day}`, [
      hourCell(iso(2), 1000, { missed: 10 }),
      hourCell(iso(3), 1000, { missed: attacked ? 200 : 10 }),
      hourCell(iso(4), 1000, { missed: 120 }),
      hourCell(iso(10), 1000, { missed: 10 }),
    ]));
  }
  const r = attackImpact(days, clustersFor(), { range: "all", now: NOW });
  assert.equal(r.verdict, "attack-linked");
  assert.equal(r.lag.cells, 4);
  assert.equal(r.lag.before, 0.002);
  assert.equal(r.lag.during, 0.04);
  assert.equal(r.lag.after, 0.024);
  assert.ok(r.lag.after > r.lag.before, "Nachwirkung muss als Nachwirkung lesbar bleiben");
  assert.equal(r.matched.rateMatched, 0.002);
  assert.equal(r.matched.ratio, 20);
});

test("Ein Cluster belegt eine Stunde genau einmal und ist eine Sichtung, nicht drei", () => {
  const days = daysWith({
    attackDays: [1, 2, 3, 4],
    rateAt3: { attack: 0.2, quiet: 0.02 },
    rateAt10: { attack: 0.02, quiet: 0.005 },
  });
  const wide = {
    key: "wide", members: ["r1"], totalDrops: 5, txCount: 2, distinctAccounts: 2,
    firstSeen: Date.parse("2026-10-01T03:05:00.000Z"), lastSeen: Date.parse("2026-10-01T05:55:00.000Z"),
    rules: ["drainer-sweep", "dusting", "known-bad-hit"], severity: "malicious",
  };
  const r = attackImpact(days, [wide], { range: "all", now: NOW });
  assert.equal(r.coverage.attackCells, 3);            // 03, 04, 05 UTC belegt
  assert.equal(r.coverage.overlapCells, 1);           // nur 03 UTC ist aufgezeichnet
  assert.equal(r.coverage.clustersInWindow, 1);
  assert.equal(r.coverage.clustersOutsideRecording, 0, "derselbe Cluster darf nicht doppelt zaehlen");
  assert.equal(r.verdict, "thin-overlap", "eine einzige Ueberlappungsstunde ist kein Urteil");
  const sweep = r.rules.find((x) => x.rule === "drainer-sweep");
  assert.equal(sweep.clustersSeen, 1);
  assert.equal(sweep.clustersInRecording, 1);
  assert.equal(sweep.share, 1);
});

test("Angriffsfenster sind nach Clusterzahl sortiert und tragen die Vorfallstypen", () => {
  const days = daysWith({
    attackDays: [1, 2, 3, 4],
    rateAt3: { attack: 0.2, quiet: 0.02 },
    rateAt10: { attack: 0.02, quiet: 0.005 },
  });
  const clusters = [...clustersFor(), {
    key: "extra", members: ["r9"], totalDrops: 10, txCount: 3, distinctAccounts: 2,
    firstSeen: Date.parse("2026-10-02T03:30:00.000Z"), lastSeen: Date.parse("2026-10-02T03:31:00.000Z"),
    rules: ["dusting"], severity: "malicious",
  }];
  const r = attackImpact(days, clusters, { range: "all", now: NOW });
  assert.equal(r.windows.length, 4);
  assert.equal(r.windows[0].timeMs, Date.parse("2026-10-02T03:00:00.000Z"));
  assert.equal(r.windows[0].clusters, 2);
  assert.equal(r.windows[0].incidentLedgers, 200);
  assert.equal(r.windows[0].types.missed, 200);
  assert.equal(r.windows[0].rate, 0.04);
  assert.equal(r.windows[0].ledgerRate, 0.2);
  assert.ok(r.windows[0].rules[0].count >= 1);
});

test("Je Validator: Angriffsstunde gegen dieselbe UTC-Stunde in ruhigen Tagen", () => {
  const days = daysWith({
    attackDays: [1, 2, 3, 4],
    rateAt3: { attack: 0.2, quiet: 0.02 },
    rateAt10: { attack: 0.02, quiet: 0.005 },
  });
  const r = attackImpact(days, clustersFor(), { range: "all", now: NOW });
  const a = r.validators.find((v) => v.master === "mA");
  const clean = r.validators.find((v) => v.master === "mE");
  // mA faellt in jeder Angriffsstunde 50 von 1.000 Ledgern (200 Ausfaelle auf vier Knoten).
  assert.equal(a.ledgersWith, 4000);
  assert.equal(a.incidentsWith, 200);
  assert.equal(a.rateWith, 0.05);
  assert.equal(a.ledgersMatched, 4000);
  assert.equal(a.incidentsMatched, 20);
  assert.equal(a.rateMatched, 0.005);
  assert.equal(a.liftMatched, 10);
  assert.equal(a.reliable, true);
  // Roher Wert daneben: 0,05 gegen 0,004 ueber alle ruhigen Stunden - groesser als der gepaarte.
  assert.equal(a.rateWithout, 0.004);
  assert.equal(a.lift, 12.5);
  assert.ok(a.lift > a.liftMatched, "ohne Paarung wuerde der Validator sich schlimmer sehen");
  assert.equal(clean.incidentsWith, 0);
  assert.equal(clean.rateWith, 0);
  assert.equal(clean.lift, null, "ohne Ausfall keine Steigerung - auch nicht als 0er Lift");
  assert.equal(clean.reliable, false);
});

test("Schwellen sind ueberschreibbar und werden im Ergebnis ausgewiesen", () => {
  const days = daysWith({
    attackDays: [1, 2],
    rateAt3: { attack: 0.4, quiet: 0.02 },
    rateAt10: { attack: 0.02, quiet: 0.005 },
  });
  const r = attackImpact(days, clustersFor({ days: [1, 2] }), {
    range: "all", now: NOW, minAttackCells: 2, minGroupPairs: 1000, minContributingValidators: 1,
  });
  assert.equal(r.verdict, "attack-linked");
  assert.equal(r.thresholds.minAttackCells, 2);
  assert.equal(r.thresholds.minGroupPairs, 1000);
  assert.equal(r.thresholds.minContributingValidators, 1);
  assert.equal(r.thresholds.minCellLedgers, IMPACT_DEFAULTS.minCellLedgers);
});

test("Leerzustand: ohne Trace und ohne Cluster kein Urteil aus dem Nichts", () => {
  const r = attackImpact([], [], { range: "7d", now: NOW });
  assert.equal(r.verdict, "unknown");
  assert.equal(r.coverage.measuredCells, 0);
  assert.equal(r.coverage.clustersTotal, 0);
  assert.equal(r.network.rateWith, null);
  assert.deepEqual(r.windows, []);
  assert.deepEqual(r.validators, []);
});

test("Ohne Angriffssichtung im Fenster ist das Unwissen, keine saubere Ueberlappungsbilanz", () => {
  const days = daysWith({
    attackDays: [1, 2, 3, 4],
    rateAt3: { attack: 0.2, quiet: 0.02 },
    rateAt10: { attack: 0.02, quiet: 0.005 },
  });
  const r = attackImpact(days, [], { range: "all", now: NOW });
  assert.equal(r.verdict, "unknown", "leere Historie darf nicht wie 'Angriffe, die nie zusammentrafen' aussehen");
  assert.equal(r.coverage.clustersInWindow, 0);
  assert.equal(r.coverage.clustersOutsideRecording, 0);
  assert.equal(r.coverage.attackCells, 0);
  assert.equal(r.network.rateWith, null);
});

// Die Ehrlichkeits-Schwelle: ein Netz-Urteil braucht mehrere tragende Knoten. Beide Faelle sind
// der echte Befund aus data/validator-trace - ein einzelner Knoten, der am 14.10.2026 zwischen
// 05 und 09 UTC jeden einzelnen Ledger verpasste, machte die Ledger-Ebene dort zu 100 %.
const COHORT = ["rSOLO"].concat(Array.from({ length: 34 }, (_, i) => "rN" + String(i).padStart(2, "0")));

// 35 Knoten, 1.000 Ledger je Stunde. Die `failers` verpassen in dieser Stunde JELEN Ledger -
// dieselben Ledger fuer alle, weil ein Ledger von mehreren Knoten gleichzeitig verpasst wird.
// Die uebrigen Knoten verpassen in jeder Stunde 5 Ledger.
function cohortDay(date, hours) {
  const d = {
    date, ledgers: 0, quorumFail: 0, validators: {}, incidents: [], gaps: [], hourly: {},
    firstMs: null, lastMs: null,
  };
  for (const { at, failers } of hours) {
    const hk = Math.floor(at / HOUR);
    const hb = (d.hourly[hk] ??= { l: 0, v: {} });
    hb.l += 1000;
    ledgerSeq += 1000;
    const base = ledgerSeq - 999;
    for (const m of COHORT) {
      hb.v[m] ??= { ok: 0, partial: 0, missed: 0, wrongHash: 0, noQuorum: 0 };
      const out = failers.includes(m) ? 1000 : 5;
      hb.v[m].missed += out;
      hb.v[m].ok += 1000 - out;
      for (let i = 0; i < out; i += 1) {
        d.incidents.push({ l: base + i, m, t: at + i * 1000, type: "missed", r: [] });
      }
    }
    d.ledgers += 1000;
    if (d.firstMs === null || at < d.firstMs) d.firstMs = at;
    if (d.lastMs === null || at > d.lastMs) d.lastMs = at;
  }
  return d;
}

function cohortDays(failers) {
  const days = [];
  for (let day = 1; day <= 8; day += 1) {
    const attacked = day <= 4;
    days.push(cohortDay("2026-10-0" + day, [
      { at: Date.parse(`2026-10-0${day}T03:00:00.000Z`), failers: attacked ? failers : [] },
      { at: Date.parse(`2026-10-0${day}T10:00:00.000Z`), failers: [] },
    ]));
  }
  return days;
}

test("Traegt nur ein Knoten den Effekt, ist es eine Knoten-Diagnose (node-driven)", () => {
  const r = attackImpact(cohortDays(["rSOLO"]), clustersFor(), { range: "all", now: NOW });
  assert.equal(r.verdict, "node-driven");
  assert.equal(r.network.contributingValidators, 1);
  assert.equal(r.network.observedValidators, 35);
  // Ledger-Ebene: 100 % - jeder Ledger der Angriffsstunde fiel, weil EIN Knoten ihn verpasste.
  assert.equal(r.network.ledgerRateWith, 1);
  // Paarebene: 35 Knoten, einer faellt komplett, die 34 andern wie immer 5 Ledger. Nachgerechnet:
  // (1.000 + 34 x 5) x 4 Stunden / (35 x 1.000 x 4) = 4.680 / 140.000 = 0,033429.
  // Das ist 1/35 plus Grundrauschen, nicht der Zusammenbruch des Netzes.
  assert.equal(r.network.rateWith, 0.033429);
  assert.equal(r.matched.rateMatched, 0.005);
  assert.ok(r.matched.z >= 2, "der Unterschied ist echt - er ist nur nicht das Netz: " + r.matched.z);
});

test("Traegt die Kohorte den Effekt, ist es ein Netz-Befund (attack-linked)", () => {
  const five = ["rSOLO", "rN00", "rN01", "rN02", "rN03"];
  const r = attackImpact(cohortDays(five), clustersFor(), { range: "all", now: NOW });
  assert.equal(r.verdict, "attack-linked");
  assert.equal(r.network.contributingValidators, 5);
  assert.equal(r.network.ledgerRateWith, 1);
  // (5 x 1.000 + 30 x 5) x 4 / 140.000 = 20.600 / 140.000 = 0,147143
  assert.equal(r.network.rateWith, 0.147143);
});

// --- Zwei Autoritaeten: die client-gemeldete Historie und der eigene Trace -------------------

// Die Zeit-Ebene war bisher blind, weil die Historie nur firstSeen/lastSeen kennt: gemessen traf
// eine Clusterstunde in 7 Tagen genau eine einzige aufgezeichnete Stunde. Der Trace fuehrt
// Signatur-Tags selbst, stunden-genau, in derselben Stunden-Zelle wie die Ausfall-Zaehler
// (hb.s / hb.a / hb.tx / hb.mx). Deshalb werden die Zahler hier gesetzt und nicht im Fixture.
function withAttack(days, { attackDays, sig, tx = 900 }) {
  days.forEach((d, i) => {
    const attacked = attackDays.includes(i + 1);
    for (const [hk, hb] of Object.entries(d.hourly)) {
      const hod = new Date(Number(hk) * 3600000).getUTCHours();
      const on = hod === 3 && attacked;
      hb.s = on ? sig : 0;
      hb.a = on ? sig : 0;
      hb.tx = on ? tx : 120;
      hb.mx = on ? tx : 120;
    }
  });
  return days;
}

const BUSY = {
  attackDays: [1, 2, 3, 4],
  rateAt3: { attack: 0.2, quiet: 0.02 },
  rateAt10: { attack: 0.02, quiet: 0.005 },
};

test("Trace-Autoritaet: Urteil aus Signatur-Stunden ohne einen einzigen Cluster", () => {
  const days = withAttack(daysWith(BUSY), { attackDays: BUSY.attackDays, sig: 5 });
  const r = attackImpact(days, [], { range: "all", now: NOW });
  assert.equal(r.verdictAuthority, "trace");
  assert.equal(r.verdictReason, "paired-control");
  assert.equal(r.verdict, "attack-linked");
  assert.equal(r.sources.history.available, false);
  assert.equal(r.sources.trace.available, true);
  assert.equal(r.sources.trace.signatureThreshold, 3);
  assert.equal(r.coverage.overlapCells, 4);
  assert.equal(r.coverage.attackCells, 4, "Kopfzeilen-Autoritaet bestimmt, was als Angriffsstunde zaehlt");
  assert.equal(r.coverage.traceForensicsHours, 16, "alle 16 gemessenen Stunden fuehren die Signatur-Ebene");
  assert.equal(r.sources.trace.signatureLedgers, 20, "4 x 5 Signatur-Ledger, der Rest ist 0 und nicht fehlend");
  assert.equal(r.matched.ratio, 10);
  assert.ok(Math.abs(r.matched.z - 24.54) < 0.05, "dieselbe Statistik wie auf Cluster-Seite: " + r.matched.z);
  assert.equal(r.thresholds.minTraceSignatureLedgers, 3);
});

// Fehlend ist nicht ruhig. Eine Stunde ohne Signatur-Feld darf nicht als "Angriff? keiner"
// gelesen werden - das ist die stille Variante desselben Fehlers, den diese Ebene abschaffen soll.
test("Fehlende Signatur-Ebene bleibt fehlend, nicht 'ruhige Stunde'", () => {
  const r = attackImpact(daysWith(BUSY), clustersFor(), { range: "all", now: NOW });
  assert.equal(r.verdictAuthority, "history");
  assert.equal(r.sources.trace.available, false);
  assert.equal(r.sources.trace.signatureLedgers, null, "null, nicht 0");
  assert.equal(r.sources.trace.signatureFailLedgers, null);
  assert.equal(r.sources.trace.analysis, null);
  assert.equal(r.coverage.traceForensicsHours, 0);
  assert.equal(r.coverage.signatureCells, 0);
  assert.equal(r.verdict, "attack-linked", "die Historie traegt das Urteil weiterhin allein");
});

// Signatur-Ledger unter der Schwelle sind keine Angriffsstunde - sonst wird jedes Rauschen zur Welle.
test("Signaturstunde unter der Schwelle wird keine Angriffsstunde", () => {
  const days = withAttack(daysWith(BUSY), { attackDays: BUSY.attackDays, sig: 2 });
  const r = attackImpact(days, [], { range: "all", now: NOW });
  assert.equal(r.sources.trace.available, true, "die Ebene ist erfasst, nur ohne Angriffsstunde");
  assert.equal(r.coverage.signatureCells, 0);
  assert.equal(r.verdict, "unknown");
  assert.equal(r.verdictReason, "no-attack-sighting");
});

// Die Trace-Autoritaet schlaegt eine Historie, deren Stunden nie mit der Aufzeichnung zusammentrafen.
test("Trace schlaegt Historie ohne Ueberlappung - und die Historie bleibt lesbar", () => {
  const days = withAttack(daysWith(BUSY), { attackDays: BUSY.attackDays, sig: 5 });
  // Cluster ausschliesslich um 21 UTC: nie aufgezeichnet, also historisch ohne Ueberlappungswert.
  const r = attackImpact(days, clustersFor({ hours: [21] }), { range: "all", now: NOW });
  assert.equal(r.verdictAuthority, "trace");
  assert.equal(r.verdict, "attack-linked");
  assert.equal(r.sources.history.available, true);
  assert.equal(r.sources.history.overlapCells, 0);
  assert.equal(r.coverage.clustersInWindow, 4);
  assert.equal(r.coverage.clustersOutsideRecording, 4);
  assert.equal(r.sources.history.analysis.rateMatched, null, "ohne Ueberlappung darf die Historie keine Rate haben");
  assert.equal(r.rules.length, 0, "Cluster-Regeln gehoeren nicht zur Kopfzeilen-Autoritaet");
  assert.equal(r.sources.history.rules.length, 2, "sie bleiben als eigene Quelle lesbar");
});

// Ein Fenster ohne die Ledger-Seite ist eine Zahl ohne Erklaerung. Mit ihr sieht der Betreiber,
// was in dieser Stunde wirklich los war.
test("Fenster nennen Signatur-Ledger und Tx-Last derselben Stunde", () => {
  const days = withAttack(daysWith(BUSY), { attackDays: BUSY.attackDays, sig: 5, tx: 1666 });
  const r = attackImpact(days, [], { range: "all", now: NOW });
  assert.equal(r.windows.length, 4);
  assert.equal(r.windows[0].signatureLedgers, 5);
  assert.equal(r.windows[0].anomalyLedgers, 5);
  assert.equal(r.windows[0].ledgerTxSum, 1666);
  assert.equal(r.windows[0].ledgerTxMax, 1666);
  assert.equal(r.windows[0].clusters, null, "der Trace erfindet keine Cluster");
  assert.equal(r.windows[0].txCount, 1666, "ohne Cluster ist die Ledger-Last die Tx-Angabe des Fensters");
});

// Ohne aufgezeichnete Stunde gibt es kein Urteil - und der Grund muss benannt sein, weil
// "no-overlap" aus einem Messartefakt genauso gefaehrlich ist wie ein erfundener Zusammenhang.
test("Keine gemessene Stunde: Grund heisst no-recorded-hour, nicht no-overlap", () => {
  const r = attackImpact([], clustersFor(), { range: "all", now: NOW });
  assert.equal(r.verdict, "unknown");
  assert.equal(r.verdictReason, "no-recorded-hour");
  assert.equal(r.verdictAuthority, "history");
});

// Die Historie-Statistik darf durch den neuen Pfad nicht verrutschen: identische Fixture,
// identische Zahlen wie vor dem Zwei-Autoritaeten-Refaktor.
test("Cluster-Pfad bleibt numerisch unveraendert (Regression)", () => {
  const r = attackImpact(daysWith(BUSY), clustersFor(), { range: "all", now: NOW });
  assert.equal(r.verdictAuthority, "history");
  assert.equal(r.coverage.overlapCells, 4);
  assert.equal(r.coverage.attackLedgers, 4000);
  assert.equal(r.network.rateWith, 0.04);
  assert.equal(r.matched.z, 24.54);
  assert.equal(r.network.contributingValidators, 4);
});
