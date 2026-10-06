// public/cluster-chips.test.mjs — Unit-Tests für die DOM-freien Helfer der
// Adress-Chip-Zeile in Cluster-Karten (public/cluster-chips.mjs, genutzt von
// public/app.js clusterCardHtml und public/history-host.html clusterCardHtml).
//
// Kein Browser: das Modul ist per Vertrag DOM-frei und rein funktional; die
// Chip-Markup-Funktionen werden als Stub injiziert (Host-Gate-Muster:
// app.js nameChipHtml/tagChipHtml mit isFullShownAddr + multiUserEntryOf,
// history-host verified===true). Alle Adressen synthetisch (rTEST…),
// Base58-gültig (ohne 0/O/I/l).
//
// Geprüft: (1) collectTagsByAddr: distinct toTags je Ziel, Kanten ohne toTag
// übersprungen, memberSet-Filter (WSS-Pfad: globale Graph-Kanten), (2)
// tagChipsHtml: aufsteigend, Cap 3 + '+'-Hinweis, fail-closed ohne Host-
// Funktion, (3) addrChipsRowHtml: Mitglieder mit Name- ODER Tag-Chip
// (Coverage-Fix: Exchange-Konto mit Tag ohne Name wird sichtbar), Mitglieder
// ohne jeden Chip entfallen, harter Cap mit deterministischer Auswahl
// (sort 'drops' und sort 'tags'), leerer Rückwert ohne Treffer, (4)
// Gate-Simulation: maskierte Adresse (Chip-Funktion liefert '') bekommt
// keinen Chip, obwohl ihre Kante ein toTag trägt — Tags werden nie erfunden.

import test from "node:test";
import assert from "node:assert/strict";
import {
  collectTagsByAddr, tagChipsHtml, addrChipsRowHtml,
} from "./cluster-chips.mjs";

const A1 = "rTESTexchangeAccount11111111"; // Börse mit Tags, ohne Namen
const A2 = "rTESTnamedAccount222222222222"; // Börse mit Name UND Tag
const A3 = "rTESTplainAccount333333333333"; // Privat: kein Name, kein Treffer
const A4 = "rTESToutsideAccount4444444444"; // Nicht-Mitglied (memberSet-Filter)

/* ---------------- 1) collectTagsByAddr ---------------- */

test("collectTagsByAddr: distinct toTags je Ziel, Kanten ohne toTag übersprungen", () => {
  const edges = [
    { from: A3, to: A1, toTag: 42 },
    { from: A3, to: A1, toTag: 42 }, // Duplikat -> bleibt distinct
    { from: A3, to: A1, toTag: 7 },  // zweiter Tag
    { from: A3, to: A1 },            // ohne toTag -> übersprungen
    { from: A1, to: A2, toTag: 0 },  // Tag 0 ist ein echter Tag (lib/tag-identity.mjs)
    null,                            // kaputte Kante -> übersprungen
    { from: A1, to: "" },            // Ziel leer -> übersprungen
  ];
  const m = collectTagsByAddr(edges);
  assert.deepEqual([...m.get(A1)].sort((a, b) => a - b), [7, 42]);
  assert.deepEqual([...m.get(A2)], [0]);
  assert.equal(m.has(A3), false, "kein Treffer für Adressen ohne toTag-Kante");
});

test("collectTagsByAddr: memberSet-Filter hält externe Kanten raus (WSS-Pfad)", () => {
  const memberSet = new Set([A1, A2, A3]);
  const edges = [
    { from: A1, to: A4, toTag: 99 }, // Ziel nicht Mitglied -> raus
    { from: A4, to: A1, toTag: 5 },  // Ziel Mitglied -> bleibt (Quelle egal)
  ];
  const m = collectTagsByAddr(edges, memberSet);
  assert.equal(m.has(A4), false, "Nicht-Mitglied bekommt keine Tags");
  assert.deepEqual([...m.get(A1)], [5]);
});

test("collectTagsByAddr: keine/leere Kanten -> leere Map (fail-closed)", () => {
  assert.equal(collectTagsByAddr(undefined).size, 0);
  assert.equal(collectTagsByAddr([]).size, 0);
});

/* ---------------- 2) tagChipsHtml ---------------- */

const tagStub = (addr, tag) =>
  typeof tag === "number" && Number.isInteger(tag) ? `<i class="tag-chip">#${tag}</i>` : "";

test("tagChipsHtml: aufsteigend sortiert, Cap 3, '+'-Hinweis bei mehr", () => {
  const html = tagChipsHtml(A1, new Set([9, 3, 77, 12, 4]), tagStub, 3);
  assert.ok(html.includes("#3") && html.includes("#4") && html.includes("#9"), "die drei kleinsten Tags");
  assert.ok(!html.includes("#12") && !html.includes("#77"), "Tags jenseits Cap 3 entfallen");
  assert.ok(html.includes("cluster-addr-more"), "'+'-Hinweis bei mehr als Cap 3");
  assert.ok(html.indexOf("#3") < html.indexOf("#4") && html.indexOf("#4") < html.indexOf("#9"), "aufsteigend");
});

test("tagChipsHtml: ohne Tag-Set oder ohne Host-Funktion kein Markup (fail-closed)", () => {
  assert.equal(tagChipsHtml(A1, null, tagStub), "");
  assert.equal(tagChipsHtml(A1, new Set(), tagStub), "");
  assert.equal(tagChipsHtml(A1, new Set([1]), undefined), "", "ohne injizierte Host-Funktion nichts");
});

test("tagChipsHtml: Host-Funktion liefert '' (Gate ohne Treffer) -> kein Chip", () => {
  // Muster app.js tagChipHtml: ohne multiUserEntryOf-Treffer '' — das Modul
  // erfindet kein eigenes Chip-Markup.
  const gated = (addr, tag) => (addr === A1 ? "" : tagStub(addr, tag));
  assert.equal(tagChipsHtml(A1, new Set([42]), gated), "");
});

/* ---------------- 3) addrChipsRowHtml ---------------- */

const nameStubMap = new Map([[A2, "<i class=\"name-chip\">Börse Zwei</i>"]]);
const nameStub = (addr) => nameStubMap.get(addr) ?? "";

test("Coverage-Fix: Exchange-Konto mit Tag OHNE Name erscheint in der Zeile", () => {
  const tagsByAddr = new Map([[A1, new Set([42])]]);
  const html = addrChipsRowHtml({
    members: [A1, A3], tagsByAddr, nameChipHtml: nameStub, tagChipHtml: tagStub,
  });
  assert.ok(html.includes("cluster-names"), "Zeile mit bestehender Klasse");
  assert.ok(html.includes("cluster-addr-chips"), "Gruppen-Wrap je Adresse");
  assert.ok(html.includes("#42"), "Tag-Chip am Exchange-Konto ohne Namen");
  assert.ok(!html.includes(A3), "Mitglied ohne Name UND ohne Tag entfällt");
});

test("addrChipsRowHtml: ohne jeden Chip leerer Rückwert (Karte unverändert)", () => {
  const html = addrChipsRowHtml({
    members: [A1, A3], tagsByAddr: new Map(), nameChipHtml: nameStub, tagChipHtml: tagStub,
  });
  assert.equal(html, "");
  assert.equal(addrChipsRowHtml({}), "", "ohne Argumente leer");
});

test("addrChipsRowHtml sort 'drops': Drops desc, dann Tags desc, dann Adresse asc", () => {
  const tagsByAddr = new Map([
    [A1, new Set([1])],
    [A2, new Set([2])],
  ]);
  const dropsByAddr = new Map([[A1, 10], [A2, 50]]);
  const html = addrChipsRowHtml({
    members: [A1, A2], tagsByAddr, nameChipHtml: () => "", tagChipHtml: tagStub,
    dropsByAddr, sort: "drops",
  });
  assert.ok(html.indexOf("#2") < html.indexOf("#1"), "höhere Drops zuerst (A2 vor A1)");
});

test("addrChipsRowHtml sort 'drops': gleicher Drops-Wert -> Tags desc, dann Adresse asc", () => {
  const B1 = "rTESTaaaAccount5555555555555555";
  const B2 = "rTESTbbbAccount6666666666666666";
  const B3 = "rTESTcccAccount7777777777777777";
  const tagsByAddr = new Map([[B1, new Set([1])], [B2, new Set([2, 3])]]);
  const dropsByAddr = new Map([[B1, 5], [B2, 5]]); // gleicher Drops-Wert
  const html = addrChipsRowHtml({
    members: [B1, B2], tagsByAddr, nameChipHtml: () => "", tagChipHtml: tagStub,
    dropsByAddr, sort: "drops",
  });
  assert.ok(html.indexOf("#2") < html.indexOf("#1"), "mehr Tags zuerst (B2 vor B1)");
  // Adresse als letzter Tiebreak: B1 ohne Tag, B3 ohne Tag -> beide entfallen
  // nicht wegen Adresse, sondern weil sie ohne Chip gar nicht antreten.
  const html2 = addrChipsRowHtml({
    members: [B3, B1], tagsByAddr: new Map([[B3, new Set([9])], [B1, new Set([8])]]),
    nameChipHtml: () => "", tagChipHtml: tagStub, sort: "drops",
  });
  assert.ok(html2.indexOf("#8") < html2.indexOf("#9"), "ohne Drops/Tags: Adresse asc (B1 vor B3)");
});

test("addrChipsRowHtml sort 'tags': Tags desc, dann Adresse asc, harter Cap", () => {
  const many = [];
  const tagsByAddr = new Map();
  // 8 Adressen mit je 1 Tag, eine mit 3 Tags, eine ohne Chip.
  for (let i = 0; i < 8; i++) {
    const a = `rTESTcap${i}Account88888888888888`;
    many.push(a);
    tagsByAddr.set(a, new Set([i + 1]));
  }
  const rich = "rTESTrichAccount999999999999999";
  many.push(rich);
  tagsByAddr.set(rich, new Set([101, 102, 103]));
  const html = addrChipsRowHtml({
    members: many, tagsByAddr, nameChipHtml: () => "", tagChipHtml: tagStub,
    cap: 5, sort: "tags",
  });
  const groups = html.match(/cluster-addr-chips/g) ?? [];
  assert.equal(groups.length, 5, "harter Cap: genau 5 Adress-Gruppen");
  assert.ok(html.includes("#101") && html.includes("#102") && html.includes("#103"), "Adresse mit meisten Tags zuerst");
  // Deterministisch: gleiche Eingabe -> identisches Markup.
  const html2 = addrChipsRowHtml({
    members: many, tagsByAddr, nameChipHtml: () => "", tagChipHtml: tagStub,
    cap: 5, sort: "tags",
  });
  assert.equal(html, html2, "deterministische Totalordnung");
});

test("addrChipsRowHtml: tagCap 3 + '+' pro Adresse, Name- UND Tag-Chip gruppiert", () => {
  const tagsByAddr = new Map([[A2, new Set([5, 6, 7, 8])]]);
  const html = addrChipsRowHtml({
    members: [A2], tagsByAddr, nameChipHtml: nameStub, tagChipHtml: tagStub,
  });
  assert.ok(html.includes("name-chip") && html.includes("Börse Zwei"), "Name-Chip in der Gruppe");
  assert.ok(html.includes("#5") && html.includes("#6") && html.includes("#7"), "Tags bis Cap 3");
  assert.ok(!html.includes("#8"), "vierter Tag entfällt");
  assert.ok(html.includes("cluster-addr-more"), "'+'-Hinweis");
  const group = html.match(/<span class="cluster-addr-chips">([\s\S]*?)<\/span>/);
  assert.ok(group && group[1].includes("name-chip") && group[1].includes("#5"), "Name und Tags in EINER Gruppe");
});

/* ---------------- 4) Gate-Simulation (fail-closed wie im Host) ---------------- */

test("Gate-Simulation: maskierte Adresse (Chip-Funktion '') bekommt keinen Chip, obwohl die Kante toTag trägt", () => {
  // Muster app.js: tagChipHtml gatet über isFullShownAddr (in multiUserEntryOf)
  // — hier simuliert eine Chip-Funktion, die für A1 (maskiert) '' liefert.
  const masked = (addr, tag) => (addr === A1 ? "" : tagStub(addr, tag));
  const tagsByAddr = collectTagsByAddr([{ from: A3, to: A1, toTag: 42 }]);
  const html = addrChipsRowHtml({
    members: [A1], tagsByAddr, nameChipHtml: () => "", tagChipHtml: masked,
  });
  assert.equal(html, "", "kein Chip an maskierter Adresse, kein erfundener Tag");
});

test("Gate-Simulation: Chip-Funktion ohne Lookup (Host-Modul nicht geladen) -> leere Zeile", () => {
  const tagsByAddr = collectTagsByAddr([{ from: A3, to: A2, toTag: 42 }]);
  const html = addrChipsRowHtml({
    members: [A2], tagsByAddr, nameChipHtml: () => "", tagChipHtml: () => "",
  });
  assert.equal(html, "", "fail-closed: ohne Host-Lookup keine Chips");
});

/* ---------------- 5) moreChip (Design P2: '+N weitere Konten') ---------------- */

// Sieben Chip-tragende Mitglieder (je 1 Tag — kein Tag-Level-'+', damit die
// Assertion auf Zeilenebene eindeutig bleibt).
const moreAddrs = [];
const moreTags = new Map();
for (let i = 0; i < 7; i++) {
  const a = `rTESTmore${i}Accountbbbbbbbbbbbbbb`;
  moreAddrs.push(a);
  moreTags.set(a, new Set([i + 1]));
}

test("moreChip: Aufruf mit (hidden, shown) bei Kappung, Markup hängt am Zeilenende", () => {
  const calls = [];
  const html = addrChipsRowHtml({
    members: moreAddrs, tagsByAddr: moreTags, nameChipHtml: () => "", tagChipHtml: tagStub,
    cap: 5,
    moreChip: (hidden, shown) => { calls.push([hidden, shown]); return `<span class="cluster-addr-more">+${hidden}</span>`; },
  });
  assert.deepEqual(calls, [[2, 5]], "genau ein Aufruf: hidden=2, shown=5");
  assert.equal((html.match(/cluster-addr-chips/g) ?? []).length, 5, "weiterhin genau 5 Gruppen");
  assert.ok(
    html.endsWith('<span class="cluster-addr-more">+2</span></div>'),
    "Hinweis nach dem letzten Chip, direkt vor Zeilenende",
  );
});

test("moreChip: ohne Kappung Aufruf mit hidden=0 — Markup bleibt beim alten Vertrag (Host-Filter)", () => {
  // Abwärtskompatibilität Flow-Host (history-host.html ruft ohne moreChip):
  // unterhalb des Caps ruft das Modul mit hidden=0; der Host-Filter
  // (hidden > 0, Muster app.js) hält das exakte alte Markup stabil — der
  // Callback entscheidet, nicht das Modul.
  const calls = [];
  const opts = {
    members: [A1], tagsByAddr: new Map([[A1, new Set([42])]]),
    nameChipHtml: () => "", tagChipHtml: tagStub,
    moreChip: (hidden, shown) => { calls.push([hidden, shown]); return hidden > 0 ? "SOLLTE-NICHT-ERSCHEINEN" : ""; },
  };
  const withCb = addrChipsRowHtml(opts);
  const without = addrChipsRowHtml({ ...opts, moreChip: null });
  assert.deepEqual(calls, [[0, 1]], "Aufruf mit hidden=0, shown=1");
  assert.equal(withCb, without, "Markup unverändert gegenüber dem Vertrag ohne moreChip");
  assert.ok(!withCb.includes("SOLLTE-NICHT-ERSCHEINEN"), "kein Hinweis-Markup unter dem Cap");
});

test("moreChip: leere Chip-Zeile ruft nicht (fail-closed, keine Erfundung)", () => {
  let called = false;
  addrChipsRowHtml({
    members: [A3], tagsByAddr: new Map(), nameChipHtml: () => "", tagChipHtml: tagStub,
    moreChip: () => { called = true; return "X"; },
  });
  assert.equal(called, false, "ohne Chip-Eintrag kein Aufruf");
});

test("moreChip: ''-Rückwert (Mega-Muster) hängt nichts an, liefert aber shown", () => {
  // Muster app.js Mega-Karten (Plan-Kritik 10): die Chip-Zeile zeigt KEINEN
  // Zweit-Hinweis neben der Mega-Meta-Zeile — moreChip sammelt nur die Zahl
  // der gezeigten Gruppen und liefert '' zurück.
  let seen = -1;
  const html = addrChipsRowHtml({
    members: moreAddrs, tagsByAddr: moreTags, nameChipHtml: () => "", tagChipHtml: tagStub,
    cap: 3,
    moreChip: (hidden, shown) => { seen = shown; return ""; },
  });
  assert.equal(seen, 3, "shown=3 (Mega-/dense-Cap)");
  assert.equal((html.match(/cluster-addr-chips/g) ?? []).length, 3, "drei Gruppen");
  assert.ok(!html.includes("cluster-addr-more"), "kein Zeilen-Hinweis in der Mega-Karte");
});
