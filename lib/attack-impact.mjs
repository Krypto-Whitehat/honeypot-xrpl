// lib/attack-impact.mjs — Angriffswirkung: Honeypot-Angriffe gegen die Ausfaelle jedes Validators.
// Rein, ohne I/O. Eingabe: Tagesobjekte aus data/validator-trace und die Cluster der
// Betrugs-Historie (data/history.json).
//
// Alle bisherigen Ebenen fragen den LEDGER (Quorum-Marge, Last, Tx-Form dieses einen Ledgers).
// Diese Ebene fragt die ZEIT: In den Fenstern, in denen der Honeypot Drainer, Dusting-Wellen und
// Sweeps sieht, steigt die Ausfallrate der dUNL-Knoten - oder sie steigt nicht.
//
// Das beantwortet eine Frage, die kein anderes XRPL-Werkzeug stellt: xrpscan und Honeycluster
// zeigen, DASS ein Ledger verpasst wurde. Ob der eigene Knoten waehrend einer Angriffswelle
// faellt, kann ein Betreiber allein nicht sehen - er sieht nur seinen eigenen Knoten.
//
// Zwei Fallen, die diese Engine ausdruecklich entschärft:
//   1. Tageszeit. Angriffe und Ausfälle haben beide Stoßzeiten. Der rohe Vergleich
//      "Angriffsstunden gegen alle ruhigen Stunden" verwechselt Uhrzeit mit Angriff (gemessene
//      Netz-Ausfallrate: 9,56 % im Schnitt, aber nicht stundenkonstant). Das URTEIL haengt
//      deshalb an der gepaarten Gegenprobe: Angriffsstunden gegen ruhige Stunden derselben
//      UTC-Stunde. Der rohe Wert bleibt sichtbar, weil er die Falle zeigen soll.
//   3. Ein einzelner Knoten. Auf LEDGER-Ebene zählt „mindestens ein Knoten fiel“. Ein Knoten,
//      der eine Stunde komplett verpasst, macht diese Rate auf 100 % und lässt jede
//      Angriffsstunde wie einen Netz-Zusammenbruch aussehen (gemessen: ein Knoten, der am
//      14.10.2026 zwischen 05 und 09 UTC jeden einzelnen Ledger verpasste). Gemessen wird
//      deshalb auf VALIDATOR-LEDGER-PAAREN: Nenner = alle beobachteten Knoten-Slots der
//      Stunde, Zähler = die Slots, die zurückfielen. Die Ledger-Ebene bleibt sichtbar
//      (ledgerRateWith/Without), weil sie die Knoten-Diagnose ist - aber sie trägt kein
//      Netz-Urteil. Traegt nur eine Minderheit der Knoten den Effekt, heisst das Urteil
//      “node-driven” und nicht “attack-linked”.
//   2. Aufzeichnungs-Loecher. Der Recorder ist nicht 24/7 unterwegs. Eine Stunde ohne Ledger ist
//      keine ruhige Stunde, sondern eine unbeobachtete. Sie darf die Gegenprobe nicht verwässern.
import { TRACE_DEFAULTS } from "./validator-trace.mjs";

export const IMPACT_DEFAULTS = {
  cellMs: 3600000,        // Stunden-Zelle: die feinste Achse, die der Trace fenster-genau liefert
  minCellLedgers: 60,     // darunter gilt die Stunde als zu duenn fuer eine Rate
  minAttackCells: 4,      // darunter sind es Einzelbeobachtungen, kein Vergleich
  minGroupPairs: 600,     // pro Gruppe (Angriff / gepaarte Ruhe) mindestens so viele Knoten-Slots
  zThreshold: 2,          // |z| >= 2: Unterschied jenseits von Zufallsstreuung
  minContributingValidators: 3, // traegt nur ein Knoten den Effekt, ist es kein Netz-Urteil
  minTraceSignatureLedgers: 3, // ab so vielen signatur-markierten Ledgern gilt eine Stunde als Angriffsstunde
  topWindows: 8,
  topValidators: 12,
};

// Die Urteile, die diese Ebene fällen kann. Exportiert, damit jedes Urteil ein Label haben muss.
export const IMPACT_VERDICTS = ["attack-linked", "node-driven", "no-link", "thin-overlap", "no-overlap", "unknown"];
// Welche Zeit-Autoritaet dem Urteil den Grund gibt, und warum genau diese Menge (oder ihre
// Luecke) das Urteil traegt. Beides ist eine endliche Menge und muss uebersetzt sein.
export const IMPACT_AUTHORITIES = ["history", "trace"];
export const IMPACT_REASONS = ["no-recorded-hour", "no-attack-sighting",
  "attack-hours-outside-recorded-hours", "overlap-too-thin", "paired-control"];

const TYPES = ["missed", "partial", "wrongHash", "noQuorum"];
const COUNTER_KEYS = ["ok", ...TYPES];
const TYPE_OF = { missed: "missed", partial: "partial", "wrong-hash": "wrongHash", "no-quorum": "noQuorum" };
const SPAN = { "1h": 3600000, "24h": 86400000, "7d": 7 * 86400000, "30d": 30 * 86400000, all: Infinity };
const num = (x) => (Number.isFinite(Number(x)) ? Number(x) : null);
const round = (x, d = 4) => (Number.isFinite(x) ? Math.round(x * 10 ** d) / 10 ** d : null);
const emptyCounts = () => { const c = {}; for (const t of TYPES) c[t] = 0; return c; };
const hodOf = (hourMs) => new Date(hourMs).getUTCHours();

function windowOf(range, now) {
  const ms = SPAN[range] ?? 86400000;
  return { from: ms === Infinity ? 0 : now - ms, to: now + 1 };
}

// Stunden-Zellen aus dem Trace: Nenner (Ledger, je Validator) aus den Stunden-Buckets, Zaehler
// (Vorfaelle) aus den zeitgestempelten Incidents. Eine Stunde ohne Bucket ist nicht ruhig,
// sondern unbeobachtet.
function traceCells(days, w, cellMs) {
  const cells = new Map();
  const cell = (h) => {
    let c = cells.get(h);
    if (c === undefined) {
      c = {
        hour: h, hourMs: h * cellMs, ledgers: 0, denominators: new Map(), incidents: new Map(),
        incLedgers: new Set(), types: emptyCounts(), incidentCount: 0, members: new Set(),
        pairs: 0, pairFails: 0,
        // Angriffsseite aus dem Trace selbst. null heisst "diese Ebene wurde in dieser Stunde nicht
        // erfasst" - niemals 0, denn 0 wuerde wie "ruhige Stunde ohne Angriffe" gelesen.
        anomalyLedgers: null, signatureLedgers: null, anomalyFailLedgers: null, signatureFailLedgers: null,
        txSum: null, txMax: null,
      };
      cells.set(h, c);
    }
    return c;
  };
  for (const d of Array.isArray(days) ? days : []) {
    for (const [hk, hb] of Object.entries(d?.hourly ?? {})) {
      const h = Number(hk);
      if (Number.isFinite(h) === false) continue;
      const c = cell(h);
      c.ledgers += num(hb?.l) ?? 0;
      for (const [m, v] of Object.entries(hb?.v ?? {})) {
        c.members.add(m);
        const seen = COUNTER_KEYS.reduce((a, k) => a + (num(v?.[k]) ?? 0), 0);
        c.denominators.set(m, (c.denominators.get(m) ?? 0) + seen);
        c.pairs += seen;
      }
      const add = (key, val) => { const v = num(val); if (v !== null) c[key] = (c[key] ?? 0) + v; };
      add("anomalyLedgers", hb?.a); add("signatureLedgers", hb?.s);
      add("anomalyFailLedgers", hb?.af); add("signatureFailLedgers", hb?.sf);
      add("txSum", hb?.tx);
      const mx = num(hb?.mx);
      if (mx !== null) c.txMax = Math.max(c.txMax ?? 0, mx);
    }
  }
  for (const d of Array.isArray(days) ? days : []) {
    for (const i of d?.incidents ?? []) {
      const t = num(i?.t);
      if (t === null || t < w.from || t > w.to) continue;
      const c = cell(Math.floor(t / cellMs));
      c.incidentCount += 1;
      if (Number.isFinite(i.l)) c.incLedgers.add(i.l);
      const type = TYPE_OF[i?.type];
      if (type) c.types[type] += 1;
      if (i?.m) {
        c.incidents.set(i.m, (c.incidents.get(i.m) ?? 0) + 1);
        c.pairFails += 1;
      }
    }
  }
  return { cells };
}

// Angriffs-Zellen aus der Cluster-Historie: ein Cluster belegt jede Stunde, die sein
// Beobachtungszeitraum streift. firstSeen/lastSeen sind die einzigen Zeitstempel der Historie.
function attackCells(clusters, w, cellMs) {
  const cells = new Map();
  const rules = new Map();
  let inWindow = 0;
  for (const c of Array.isArray(clusters) ? clusters : []) {
    const a = num(c?.firstSeen);
    if (a === null || a < w.from || a > w.to) continue;
    inWindow += 1;
    // Regel-Zaehler auf Cluster-Ebene: ein Cluster, das drei Stunden belegt, ist eine
    // Drainer-Sichtung, nicht drei.
    for (const r of c?.rules ?? []) rules.set(r, (rules.get(r) ?? 0) + 1);
    const b = Math.max(num(c?.lastSeen) ?? a, a);
    const h0 = Math.floor(a / cellMs), h1 = Math.floor(b / cellMs);
    const key = c?.key ?? [...(c?.members ?? [])].join(",") + "|" + a;
    for (let h = h0; h <= h1; h += 1) {
      let e = cells.get(h);
      if (e === undefined) {
        e = { hour: h, hourMs: h * cellMs, clusters: 0, clusterKeys: new Set(), rules: new Map(), drops: 0, txCount: 0, accounts: 0 };
        cells.set(h, e);
      }
      if (e.clusterKeys.has(key)) continue; // derselbe Cluster belegt dieselbe Stunde nur einmal
      e.clusterKeys.add(key);
      e.clusters += 1;
      e.drops += num(c?.totalDrops) ?? 0;
      e.txCount += num(c?.txCount) ?? 0;
      e.accounts += num(c?.distinctAccounts) ?? 0;
      for (const r of c?.rules ?? []) e.rules.set(r, (e.rules.get(r) ?? 0) + 1);
    }
  }
  return { cells, rules, inWindow };
}

// Zwei Proportionen, ein z-Wert. Ohne beide Nenner kein Wert - kein Rate-Default.
function proportion(x, n) { return Number.isFinite(x) && Number.isFinite(n) && n > 0 ? x / n : null; }
function zScore(x1, n1, x2, n2) {
  const p1 = proportion(x1, n1), p2 = proportion(x2, n2);
  if (p1 === null || p2 === null) return null;
  const pooled = (x1 + x2) / (n1 + n2);
  const se = Math.sqrt(pooled * (1 - pooled) * (1 / n1 + 1 / n2));
  if (se > 0 === false) return null;
  return (p1 - p2) / se;
}

// Tageszeit-Kontrolle: Angriffsstunden gegen ruhige Stunden derselben UTC-Stunde. Ohne diese
// Paarung ist der Lift ein Artefakt der Uhrzeit. Stunden ohne ruhigen Gegenwert bleiben
// unkontrolliert und werden ausgezaehlt, nicht geraten.
function daypartMatch(attack, quiet) {
  const attackHods = new Set(attack.map((c) => hodOf(c.hourMs)));
  const matched = quiet.filter((c) => attackHods.has(hodOf(c.hourMs)));
  const quietHods = new Set(matched.map((c) => hodOf(c.hourMs)));
  const uncontrolled = attack.filter((c) => quietHods.has(hodOf(c.hourMs)) === false);
  const A = attack.reduce((a, c) => ({ ledgers: a.ledgers + c.ledgers, incLedgers: a.incLedgers + c.incLedgers.size, pairs: a.pairs + c.pairs, pairFails: a.pairFails + c.pairFails }), { ledgers: 0, incLedgers: 0, pairs: 0, pairFails: 0 });
  const M = matched.reduce((a, c) => ({ ledgers: a.ledgers + c.ledgers, incLedgers: a.incLedgers + c.incLedgers.size, pairs: a.pairs + c.pairs, pairFails: a.pairFails + c.pairFails }), { ledgers: 0, incLedgers: 0, pairs: 0, pairFails: 0 });
  const rateAttack = proportion(A.pairFails, A.pairs);
  const rateMatched = proportion(M.pairFails, M.pairs);
  return {
    cells: attack.length, matchedCells: matched.length, uncontrolledCells: uncontrolled.length,
    ledgers: A.ledgers, matchedLedgers: M.ledgers, pairs: A.pairs, matchedPairs: M.pairs,
    incidentLedgers: A.incLedgers, matchedIncidentLedgers: M.incLedgers,
    pairFails: A.pairFails, matchedPairFails: M.pairFails,
    rateAttack: round(rateAttack, 6), rateMatched: round(rateMatched, 6),
    ratio: (rateAttack !== null && rateMatched !== null && rateMatched > 0) ? round(rateAttack / rateMatched, 3) : null,
    z: round(zScore(A.pairFails, A.pairs, M.pairFails, M.pairs), 2),
  };
}

// Eine Autoritaet = eine Angriffsseite plus dieselbe Statistik. Die Statistik ist bewusst geteilt:
// waere sie quellenabhaengig, hinge das Urteil davon ab, welche Quelle zufaellig gefuellt ist.
function analyseAuthority(measured, attackSet, p) {
  const attackGroup = measured.filter((c) => attackSet.has(c.hour));
  const quietGroup = measured.filter((c) => !attackSet.has(c.hour));
  const sum = (group) => group.reduce((a, c) => ({
    ledgers: a.ledgers + c.ledgers, incLedgers: a.incLedgers + c.incLedgers.size, incidents: a.incidents + c.incidentCount,
    pairs: a.pairs + c.pairs, pairFails: a.pairFails + c.pairFails,
    types: TYPES.reduce((t, k) => { t[k] = a.types[k] + c.types[k]; return t; }, emptyCounts()),
  }), { ledgers: 0, incLedgers: 0, incidents: 0, pairs: 0, pairFails: 0, types: emptyCounts() });
  const overlapClusters = new Set();
  for (const c of attackGroup) for (const k of attackSet.get(c.hour).clusterKeys) overlapClusters.add(k);
  const A = sum(attackGroup), Q = sum(quietGroup);

  // Kohorten-Maess: Anteil der Validator-Ledger-Paare, die zurueckfallen. Die Ledger-Ebene
  // ("mindestens ein Knoten fiel") bleibt sichtbar, weil sie von einem einzigen Knoten dominiert
  // werden kann: ein Knoten, der eine Stunde komplett verpasst, macht sie zu 1,0 und laesst jede
  // Angriffsstunde wie einen Netz-Zusammenbruch aussehen.
  const rateWith = proportion(A.pairFails, A.pairs);
  const rateWithout = proportion(Q.pairFails, Q.pairs);
  const zRaw = zScore(A.pairFails, A.pairs, Q.pairFails, Q.pairs);
  const ledgerRateWith = proportion(A.incLedgers, A.ledgers);
  const ledgerRateWithout = proportion(Q.incLedgers, Q.ledgers);
  const matched = daypartMatch(attackGroup, quietGroup);

  // Lag: steigt die Rate NACH der Angriffswelle? Nur gemessene Nachbarn zaehlen.
  const byHour = new Map(measured.map((c) => [c.hour, c]));
  const rateOf = (h) => { const c = byHour.get(h); return c !== undefined && c.pairs > 0 ? c.pairFails / c.pairs : null; };
  const lag = { before: null, during: null, after: null, cells: 0 };
  {
    let b = 0, d = 0, a = 0, n = 0;
    for (const c of attackGroup) {
      const rb = rateOf(c.hour - 1), ra = rateOf(c.hour + 1);
      if (rb === null && ra === null) continue;
      n += 1;
      if (rb !== null) b += rb;
      d += c.pairs > 0 ? c.pairFails / c.pairs : 0;
      if (ra !== null) a += ra;
    }
    if (n > 0) { lag.cells = n; lag.before = round(b / n, 6); lag.during = round(d / n, 6); lag.after = round(a / n, 6); }
  }

  // Je Validator dieselbe Paarung wie im Netzurteil. Der rohe Wert bleibt sichtbar, weil auch
  // hier die Tageszeit sonst als Angriff durchgeht.
  const attackHods = new Set(attackGroup.map((c) => hodOf(c.hourMs)));
  const masters = new Map();
  for (const c of measured) {
    const isAttack = attackSet.has(c.hour);
    const isMatched = isAttack === false && attackHods.has(hodOf(c.hourMs));
    for (const m of c.members) {
      const e = masters.get(m) ?? { with: { n: 0, x: 0 }, without: { n: 0, x: 0 }, matched: { n: 0, x: 0 } };
      const bucket = isAttack ? e.with : e.without;
      bucket.n += c.denominators.get(m) ?? 0;
      bucket.x += c.incidents.get(m) ?? 0;
      if (isMatched) { e.matched.n += c.denominators.get(m) ?? 0; e.matched.x += c.incidents.get(m) ?? 0; }
      masters.set(m, e);
    }
  }
  const validators = [...masters.entries()].map(([master, e]) => {
    const r1 = proportion(e.with.x, e.with.n), r2 = proportion(e.without.x, e.without.n);
    const rm = proportion(e.matched.x, e.matched.n);
    const vz = zScore(e.with.x, e.with.n, e.matched.x, e.matched.n);
    const reliable = e.with.n >= p.minGroupPairs && e.matched.n >= p.minGroupPairs
      && vz !== null && Math.abs(vz) >= p.zThreshold;
    return {
      master, ledgersWith: e.with.n, ledgersWithout: e.without.n,
      incidentsWith: e.with.x, incidentsWithout: e.without.x,
      rateWith: round(r1, 6), rateWithout: round(r2, 6),
      lift: (r1 !== null && r2 !== null && r2 > 0) ? round(r1 / r2, 2) : null,
      ledgersMatched: e.matched.n, incidentsMatched: e.matched.x, rateMatched: round(rm, 6),
      liftMatched: (r1 !== null && rm !== null && rm > 0) ? round(r1 / rm, 2) : null,
      zMatched: round(vz, 2), reliable,
    };
  }).filter((v) => v.ledgersWith > 0 || v.ledgersWithout > 0);
  validators.sort((a, b) => (Number(b.reliable) - Number(a.reliable))
    || ((b.liftMatched ?? 0) - (a.liftMatched ?? 0)) || (b.ledgersWith - a.ledgersWith));

  const windows = attackGroup.map((c) => {
    const a = attackSet.get(c.hour);
    return {
      timeMs: c.hourMs, clusters: a.clusters, ledgers: c.ledgers, incidentLedgers: c.incLedgers.size,
      rate: round(proportion(c.pairFails, c.pairs), 6), ledgerRate: round(proportion(c.incLedgers.size, c.ledgers), 6), types: { ...c.types },
      drops: a.drops, txCount: a.txCount ?? c.txSum, accounts: a.accounts,
      // Die Ledger-Seite derselben Stunde: Signatur-Tags und Tx-Last. Ohne sie ist ein Fenster
      // nur "eine Stunde mit Clustern"; mit ihm ist es "eine Stunde mit 1.666 Tx und 4
      // offer-flood-Ledgern, in der 120 von 1.000 Knoten-Slots zurueckfielen".
      signatureLedgers: c.signatureLedgers, anomalyLedgers: c.anomalyLedgers,
      ledgerTxSum: c.txSum, ledgerTxMax: c.txMax,
      rules: [...a.rules.entries()].sort((x, y) => y[1] - x[1]).map(([rule, count]) => ({ rule, count })),
    };
  }).sort((x, y) => ((y.clusters ?? 0) - (x.clusters ?? 0)) || ((y.signatureLedgers ?? 0) - (x.signatureLedgers ?? 0))
    || (y.rate ?? 0) - (x.rate ?? 0));

  // Wer traegt den Effekt? Ein Urteil, das nur von einem einzigen Knoten getragen wird, ist eine
  // Knoten-Diagnose, kein Netz-Befund - und ein Netz-Befund aus einem Knoten ist der schnellste
  // Weg, das Vertrauen der Validatoren in dieses Werkzeug zu verlieren.
  const contributing = validators.filter((v) => v.reliable && (v.rateWith ?? 0) > (v.rateMatched ?? 0));
  return {
    attackGroup, quietGroup, A, Q, overlapClusters, contributing,
    rateWith, rateWithout, zRaw, ledgerRateWith, ledgerRateWithout, matched, lag, validators, windows,
  };
}

// Kurzprofil einer Autoritaet, damit beide Neben dem Kopfzeilen-Urteil lesbar bleiben und der
// Leser selbst entscheiden kann, welcher Quelle er fuer diesen Knoten glaubt.
function authoritySummary(a, basis) {
  return {
    basis, overlapCells: a.attackGroup.length, quietCells: a.quietGroup.length,
    attackPairs: a.A.pairs, quietPairs: a.Q.pairs,
    rateWith: round(a.rateWith, 6), rateMatched: a.matched.rateMatched, ratio: a.matched.ratio,
    zMatched: a.matched.z, contributingValidators: a.contributing.length,
  };
}

export function attackImpact(days, clusters, { range = "7d", now = Date.now(), ...rest } = {}) {
  const p = { ...IMPACT_DEFAULTS, ...rest };
  const cellMs = p.cellMs;
  const w = windowOf(range, now);
  const trace = traceCells(days, w, cellMs);
  const atk = attackCells(clusters, w, cellMs);
  const measured = [...trace.cells.values()].filter((c) => c.ledgers >= p.minCellLedgers);
  const recorded = (h) => { const c = trace.cells.get(h); return c !== undefined && c.ledgers >= p.minCellLedgers; };

  // Autoritaet 1: die client-gemeldeten Cluster. Ihre einzige Zeitangabe ist firstSeen/lastSeen.
  const historyAttack = new Map([...atk.cells.entries()].filter(([h]) => recorded(h)));

  // Autoritaet 2: der Trace selbst. Signatur-Tags (drainer-fanout, offer-flood, sweep-window,
  // failure-spike ...) sind stunden-genau und brauchen keine Client-Rueckmeldung. Das ist der
  // Grund, warum diese Ebene ueberhaupt existiert: gemessen traf eine Clusterstunde in 7 Tagen
  // genau eine einzige aufgezeichnete Stunde - die Zeit-Ebene war blind, nicht ruhig.
  const traceAttackAll = new Map();
  for (const [h, c] of trace.cells) {
    if (c.signatureLedgers === null || c.signatureLedgers < p.minTraceSignatureLedgers) continue;
    traceAttackAll.set(h, {
      hour: h, hourMs: c.hourMs, clusters: null, clusterKeys: new Set(), rules: new Map(),
      drops: null, txCount: c.txSum, accounts: null,
      signatureLedgers: c.signatureLedgers, anomalyLedgers: c.anomalyLedgers,
    });
  }
  const traceAttack = new Map([...traceAttackAll.entries()].filter(([h]) => recorded(h)));
  const traceForensicsHours = measured.filter((c) => c.signatureLedgers !== null).length;
  const traceAvailable = traceForensicsHours > 0;

  const hist = analyseAuthority(measured, historyAttack, p);
  const tr = traceAvailable ? analyseAuthority(measured, traceAttack, p) : null;

  // Kopfzeile = die Autoritaet mit der meisten echten Ueberlappung. "Cluster" ist kein Guetekriterium:
  // eine Stunde mit Signatur-Ledgern im eigenen Trace schlaegt eine Historie, deren Stunden nie
  // mit der Aufzeichnung zusammenfielen. Bei Gleichstand entscheidet der groessere Nenner.
  const candidates = [{ label: "history", a: hist, basis: atk.inWindow }];
  if (tr !== null) candidates.push({ label: "trace", a: tr, basis: traceAttackAll.size });
  let head = candidates[0];
  for (const c of candidates) {
    if (c.a.attackGroup.length > head.a.attackGroup.length
      || (c.a.attackGroup.length === head.a.attackGroup.length && c.a.A.pairs > head.a.A.pairs)) head = c;
  }
  const a = head.a;
  const basis = head.basis;

  // Vorfaelle in Stunden, die es in keine Gruppe schaffen, werden ausgewiesen statt verschluckt -
  // sonst wirkt die Gegenprobe vollstaendig, obwohl sie es nicht ist.
  let outsideMeasured = 0;
  for (const c of trace.cells.values()) if (c.ledgers < p.minCellLedgers) outsideMeasured += c.incidentCount;

  const ruleRows = [...atk.rules.entries()].map(([rule, clustersSeen]) => {
    const overlap = hist.attackGroup.reduce((n, c) => n + (historyAttack.get(c.hour).rules.get(rule) ?? 0), 0);
    return { rule, clustersSeen, clustersInRecording: overlap, share: clustersSeen > 0 ? round(overlap / clustersSeen, 4) : null };
  }).sort((x, y) => (y.clustersInRecording - x.clustersInRecording) || (y.clustersSeen - x.clustersSeen));

  // Das Urteil haengt an der tageszeit-gepaarten Gegenprobe, nicht am rohen Lift. Jede Verweige-
  // rung nennt ihren Grund, weil "no-overlap" aus einem Messartefakt genauso gefaehrlich ist wie
  // ein erfundener Zusammenhang.
  let verdict, verdictReason;
  // Ohne Angriffssichtung im Fenster gibt es keine Vergleichsbasis: das ist Unwissen, nicht
  // "Angriffe, die nie mit der Aufzeichnung zusammentrafen". Beides zu vermischen waere die
  // teuerste Luege dieser Ebene, weil sie eine leere Historie wie einen sauberen Befund aussehen
  // laesst.
  if (measured.length === 0) { verdict = "unknown"; verdictReason = "no-recorded-hour"; }
  else if (basis === 0) { verdict = "unknown"; verdictReason = "no-attack-sighting"; }
  else if (a.attackGroup.length === 0) { verdict = "no-overlap"; verdictReason = "attack-hours-outside-recorded-hours"; }
  else if (a.attackGroup.length < p.minAttackCells || a.A.pairs < p.minGroupPairs
    || a.matched.matchedPairs < p.minGroupPairs || a.Q.pairs < p.minGroupPairs) { verdict = "thin-overlap"; verdictReason = "overlap-too-thin"; }
  else if (a.matched.z !== null && a.matched.z >= p.zThreshold && (a.matched.rateAttack ?? 0) > (a.matched.rateMatched ?? 0)) {
    verdict = a.contributing.length >= p.minContributingValidators ? "attack-linked" : "node-driven";
    verdictReason = "paired-control";
  } else { verdict = "no-link"; verdictReason = "paired-control"; }

  const sumField = (key) => {
    let total = 0, seen = false;
    for (const c of measured) if (c[key] !== null) { seen = true; total += c[key]; }
    return seen ? total : null;
  };

  return {
    verdict, verdictAuthority: head.label, verdictReason,
    range,
    window: { fromMs: w.from === 0 ? null : w.from, toMs: w.to },
    // Beide Autoritaeten nebeneinander: die eine ist Behauptung des Clients, die andere eigene
    // Messung. Ein Validator soll sehen, dass sie sich widersprechen duerfen - und warum.
    sources: {
      history: {
        available: atk.inWindow > 0,
        clustersTotal: Array.isArray(clusters) ? clusters.length : 0,
        clustersInWindow: atk.inWindow,
        attackCells: atk.cells.size,
        overlapCells: hist.attackGroup.length,
        rules: ruleRows,
        analysis: authoritySummary(hist, atk.inWindow),
      },
      trace: {
        available: traceAvailable,
        recordedHours: traceForensicsHours,
        signatureThreshold: p.minTraceSignatureLedgers,
        signatureCells: traceAttackAll.size,
        signatureLedgers: sumField("signatureLedgers"),
        signatureFailLedgers: sumField("signatureFailLedgers"),
        anomalyLedgers: sumField("anomalyLedgers"),
        overlapCells: tr === null ? 0 : tr.attackGroup.length,
        analysis: tr === null ? null : authoritySummary(tr, traceAttackAll.size),
      },
    },
    coverage: {
      cellMs, measuredCells: measured.length, thinCells: trace.cells.size - measured.length,
      attackCells: head.label === "history" ? atk.cells.size : traceAttackAll.size,
      overlapCells: a.attackGroup.length, quietCells: a.quietGroup.length,
      recordedLedgers: a.Q.ledgers + a.A.ledgers, attackLedgers: a.A.ledgers, quietLedgers: a.Q.ledgers,
      clustersTotal: Array.isArray(clusters) ? clusters.length : 0,
      clustersInWindow: atk.inWindow,
      clustersOutsideRecording: atk.inWindow - hist.overlapClusters.size,
      incidentsOutsideMeasuredCells: outsideMeasured,
      attackPairs: a.A.pairs, quietPairs: a.Q.pairs,
      traceForensicsHours, signatureCells: traceAttackAll.size,
    },
    network: {
      rateWith: round(a.rateWith, 6), rateWithout: round(a.rateWithout, 6),
      lift: (a.rateWith !== null && a.rateWithout !== null && a.rateWithout > 0) ? round(a.rateWith / a.rateWithout, 2) : null,
      zRaw: round(a.zRaw, 2),
      incidentLedgersWith: a.A.incLedgers, incidentLedgersWithout: a.Q.incLedgers,
      pairsWith: a.A.pairs, pairsWithout: a.Q.pairs, pairFailsWith: a.A.pairFails, pairFailsWithout: a.Q.pairFails,
      ledgerRateWith: round(a.ledgerRateWith, 6), ledgerRateWithout: round(a.ledgerRateWithout, 6),
      contributingValidators: a.contributing.length,
      observedValidators: a.validators.length,
      contributingMasters: a.contributing.slice(0, 6).map((v) => v.master),
      typesWith: a.A.types, typesWithout: a.Q.types,
    },
    matched: a.matched,
    lag: a.lag,
    windows: a.windows.slice(0, p.topWindows),
    rules: head.label === "history" ? ruleRows : [],
    validators: a.validators.slice(0, p.topValidators),
    thresholds: {
      minCellLedgers: p.minCellLedgers, minAttackCells: p.minAttackCells,
      minGroupPairs: p.minGroupPairs, zThreshold: p.zThreshold,
      minContributingValidators: p.minContributingValidators,
      minTraceSignatureLedgers: p.minTraceSignatureLedgers,
      networkMinValidators: TRACE_DEFAULTS.networkMinValidators ?? null,
    },
  };
}
