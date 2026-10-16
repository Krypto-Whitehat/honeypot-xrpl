// lib/history-integrity.test.mjs — Guards fuer die zwei Befunde von 2026-10-16:
// (1) Schluesselkollision in sanitizeHistoryList machte aus einem Cluster ein
//     boolean, und der naechste Ladevorgang verwarf es still — verlorene
//     Betrugsevidenz bis in den GitHub-Bestand.
// (2) Ein fester tmp-Pfad in saveLocalHistory liess zwei gleichzeitige
//     Schreibende in dieselbe Datei schreiben: valider Kopf plus Fremdschwanz,
//     die Datei nicht mehr parsebar (data/history.json, zweimal).
import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import {
  historyKey,
  sanitizeHistoryList,
  mergeHistory,
  serializeHistoryList,
  loadLocalHistory,
  saveLocalHistory,
} from "./history.mjs";

const NO_BAIT = new Map();
const R = {
  a: "rTESTA" + "1".repeat(26),
  b: "rTESTA2" + "1".repeat(25),
  c: "rTESTB1" + "1".repeat(26),
};

function cluster(members, over = {}) {
  return {
    members,
    label: "Clusterfixture",
    totalDrops: 1000,
    txCount: 3,
    distinctAccounts: 0,
    firstSeen: 1000,
    lastSeen: 2000,
    rules: ["dusting"],
    severity: "malicious",
    sightings: 1,
    lastReportedAt: 3000,
    ...over,
  };
}

// saveLocalHistory schreibt den Bestand unveraendert — die Eintraege müssen
// also die kanonische Form aus dem Merge-Pfad haben (mit Schluessel).
function stored(members, over = {}) {
  return sanitizeHistoryList([cluster(members, over)], NO_BAIT)[0];
}

async function tmpFile(name) {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), "hx-integrity-"));
  return { dir, file: path.join(dir, name) };
}

test("sanitizeHistoryList: eine Schluesselkollision erhaelt den Cluster (kein boolean)", () => {
  const a = cluster([R.a, R.b], { label: "Cluster A", totalDrops: 4, txCount: 9, firstSeen: 100, lastSeen: 200, rules: ["dusting"], sightings: 2, lastReportedAt: 3000 });
  const b = cluster([R.a, R.b], { label: "Cluster B", totalDrops: 7, txCount: 3, firstSeen: 50, lastSeen: 260, rules: ["drainer-sweep"], sightings: 5, lastReportedAt: 4000 });
  const out = sanitizeHistoryList([a, b], NO_BAIT);
  assert.equal(out.length, 1);
  assert.equal(typeof out[0], "object");
  assert.ok(out[0] && !Array.isArray(out[0]));
  assert.equal(out[0].key, historyKey([R.a, R.b].slice().sort()));
  assert.deepEqual(out[0].rules, ["drainer-sweep", "dusting"]); // Vereinigung
  assert.equal(out[0].sightings, 5); // max, kein boolean
  assert.equal(out[0].lastReportedAt, 4000);
  assert.equal(out[0].firstSeen, 50);
  assert.equal(out[0].lastSeen, 260);
});

test("mergeHistory: eine Kollision im Bestand kostet keine Betrugsevidenz", () => {
  const a = cluster([R.a, R.b], { rules: ["dusting"] });
  const b = cluster([R.a, R.b], { rules: ["known-bad-hit"], sightings: 3 });
  const { list } = mergeHistory([a, b], [], 5000, NO_BAIT);
  assert.equal(list.length, 1);
  assert.equal(typeof list[0], "object");
  assert.deepEqual(list[0].rules, ["dusting", "known-bad-hit"]);
  const text = serializeHistoryList(list);
  assert.ok(!text.includes("true"), "boolean-Eintrag waere ein Cluster-Verlust: " + text);
});

test("serializeHistoryList: ein Nicht-Cluster-Eintrag schreibt nichts in die Datei", () => {
  assert.throws(() => serializeHistoryList([true]), /kein Cluster/);
  assert.throws(() => serializeHistoryList([{ key: "x" }]), /kein Cluster/);
  assert.equal(serializeHistoryList(null), "[]");
});

test("saveLocalHistory: zwei gleichzeitige Speicherungen enden als ganzes Array", async () => {
  const { dir, file } = await tmpFile("history.json");
  const big = Array.from({ length: 30 }, (_, i) => stored([R.a, R.b, R.c].slice(0, (i % 3) + 1), { label: "A" + i }));
  const small = [stored([R.a], { label: "B0" }), stored([R.b], { label: "B1" }), stored([R.c], { label: "B2" })];
  await Promise.all([saveLocalHistory(file, big), saveLocalHistory(file, small)]);
  const back = await loadLocalHistory(file); // parseHistoryText: wirft bei Korruption
  const shapes = [big, small].map((l) => JSON.stringify(serializeHistoryList(l)));
  assert.ok(shapes.includes(JSON.stringify(serializeHistoryList(back))), "Bestand ist weder die eine noch die andere Liste — verzahnter Schreibvorgang");
  const leftovers = (await fs.readdir(dir)).filter((f) => f.endsWith(".tmp"));
  assert.deepEqual(leftovers, [], "tmp-Dateien bleiben zurueck: " + leftovers.join(", "));
});

test("saveLocalHistory: ein fehlerhafter Bestand ersetzt den bisherigen nicht", async () => {
  const { file } = await tmpFile("history.json");
  const good = [stored([R.a, R.b], { label: "Cluster A" })];
  await saveLocalHistory(file, good);
  const before = await fs.readFile(file, "utf8");
  await assert.rejects(() => saveLocalHistory(file, [true]), /kein Cluster/);
  const after = await fs.readFile(file, "utf8");
  assert.equal(after, before, "Bestand darf nach einem fehlgeschlagenen Schreibvorgang unveraendert sein");
  assert.equal((await loadLocalHistory(file)).length, 1);
});
