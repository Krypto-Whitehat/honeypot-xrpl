// lib/history.test.mjs — node:test-Unit-Tests für die Historie-Engine.
// Muster wie lib/cluster.test.mjs: synthetische rTEST…-Adressen (keine echten,
// keine Köder — die „Köder“-Fixtures sind ebenfalls synthetische Testadressen).
// KOMPLETT OFFLINE: der GitHub-Adapter läuft gegen globalThis.fetch-Stubs,
// es gibt keine Netzwerk-Calls. Ausführen: node --test lib/history.test.mjs
import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import {
  normalizedName,
  historyKey,
  HISTORY_MAX_ENTRIES,
  sanitizeHistoryCluster,
  sanitizeHistoryList,
  validateAndSanitizeHistoryPayload,
  mergeHistory,
  serializeHistoryList,
  loadLocalHistory,
  saveLocalHistory,
  readHistoryGitHub,
  writeHistoryGitHub,
  deleteGitHubFile,
  rateLimitHistory,
  clientKeyOf,
  searchHistory,
} from "./history.mjs";
import { normalizedNameClient, historyKeyClient } from "../public/history.js";

// ---------- Fixture-Helfer ----------
// Basis58-konforme synthetische Adressen (Zeichensatz ohne 0, O, I, l).
// Injektive Bijective-Base-25-Kodierung (nur Kleinbuchstaben ohne 'l') —
// eine direkte toString(36)-Umsetzung wäre NICHT injektiv (Ziffer-'0' und
// Buchstabe-'a' kollidieren nach Ersetzen), was Duplikat-Adressen erzeugte.
const SYN_ALPHA = "abcdefghijkmnopqrstuvwxyz"; // 25 Zeichen, ohne 'l'
function synth(i) {
  let s = "";
  let n = i + 1;
  while (n > 0) {
    n -= 1;
    s = SYN_ALPHA[n % 25] + s;
    n = Math.floor(n / 25);
  }
  return "rSYN" + s.padStart(24, "a"); // 4 + 24 = 28 Zeichen (Regel: 25-35)
}
const R = {
  a: "rTESTA" + "1".repeat(26),
  b: "rTESTA2" + "1".repeat(25),
  c: "rTESTB1" + "1".repeat(26),
  d: "rTESTB2" + "1".repeat(25),
};
const XRPL_ADDR_RE = /^r[1-9A-HJ-NP-Za-km-z]{24,34}$/;
const NO_BAIT = new Map();
const baitLabels = new Map([
  [synth(900001), "HP-1"],
  [synth(900002), "HP-2"],
]);

function rawCluster(members, over = {}) {
  return {
    members,
    label: "Clusterfixture",
    totalDrops: 1000,
    txCount: 3,
    distinctAccounts: 99, // wird serverseitig aus members.length bestimmt
    firstSeen: 1000,
    lastSeen: 2000,
    rules: ["dusting"],
    severity: "malicious",
    ...over,
  };
}

// ---------- GitHub-Stub-Umgebung ----------
const DUMMY_TOKEN = "gh-dummy-test-token"; // synthetisch, kein echtes Secret
let envBackup = null;
function stubGithubEnv() {
  envBackup = {
    GITHUB_HISTORY_TOKEN: process.env.GITHUB_HISTORY_TOKEN,
    GITHUB_HISTORY_REPO: process.env.GITHUB_HISTORY_REPO,
    GITHUB_HISTORY_BRANCH: process.env.GITHUB_HISTORY_BRANCH,
  };
  process.env.GITHUB_HISTORY_TOKEN = DUMMY_TOKEN;
  process.env.GITHUB_HISTORY_REPO = "acme/history-test";
  delete process.env.GITHUB_HISTORY_BRANCH;
}
function restoreGithubEnv() {
  if (!envBackup) return;
  for (const [k, v] of Object.entries(envBackup)) {
    if (v === undefined) delete process.env[k];
    else process.env[k] = v;
  }
  envBackup = null;
}

function ghResponse(obj, status = 200) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { "content-type": "application/json" },
  });
}
function b64(str) {
  return Buffer.from(str, "utf8").toString("base64");
}

// installFetchStub(handler) — handler(callIndex, method, url, init) -> Response.
function installFetchStub(handler) {
  const orig = globalThis.fetch;
  const calls = [];
  globalThis.fetch = async (url, init = {}) => {
    const method = String(init.method ?? "GET").toUpperCase();
    calls.push({ method, url: String(url), headers: init.headers ?? {}, body: init.body ?? null });
    return handler(calls.length, method, String(url), init);
  };
  return { calls, restore: () => (globalThis.fetch = orig) };
}

// =====================================================================
// Normalisierung + Schlüssel
// =====================================================================

test("synth: Fixture-Adressen matchen XRPL_ADDR_RE", () => {
  for (const i of [0, 1, 42, 900001, 12800]) assert.match(synth(i), XRPL_ADDR_RE);
});

test("normalizedName/historyKey: fixer Vektor (trim + Sortierung + U+000A-join)", () => {
  const members = [R.b, `  ${R.c}  `, R.a];
  assert.equal(normalizedName(members), `${R.a}\n${R.b}\n${R.c}`);
  assert.equal(normalizedName([]), "");
  assert.equal(historyKey(members), "29a4fd4337b901c38810df27f536d6fae4458991b5ee753f02e60f926cfecdf1");
});

test("normalizedName/historyKey: Key-Stabilität bei Reihenfolge-Shuffle", () => {
  const base = [R.a, R.b, R.c, R.d];
  const k0 = historyKey(base);
  assert.equal(historyKey([R.d, R.a, R.c, R.b]), k0);
  assert.equal(historyKey([R.c, R.d, R.b, R.a]), k0);
  assert.equal(historyKey(base.map((x) => ` ${x} `)), k0); // trim zählt nicht
});

test("Client/Server: normalizedNameClient === normalizedName, historyKeyClient === historyKey", async () => {
  const shuffled = [R.d, ` ${R.b}`, R.a, R.c];
  assert.equal(normalizedNameClient(shuffled), normalizedName(shuffled));
  assert.equal(await historyKeyClient(shuffled), historyKey(shuffled));
  assert.equal(await historyKeyClient([R.a, R.b]), historyKey([R.b, R.a]));
});

// =====================================================================
// Sanitisierung (Köder-Filter)
// =====================================================================

test("sanitizeHistoryCluster: Köder-Mitglieder raus, Struktur sanitiert", () => {
  const out = sanitizeHistoryCluster(
        rawCluster([R.a, synth(900001), `  ${R.b}  `, "rX", 42, null], {
          severity: "suspect",
          totalDrops: -5,
          txCount: 12.7,
          rules: ["dusting", "dusting", ""],
        }),
        baitLabels);
  assert.ok(out);
  assert.deepEqual(out.members, [R.a, R.b]); // sortiert, getrimmt, Köder/ungültig raus
  assert.equal(out.severity, "malicious"); // serverseitig erzwungen
  assert.equal(out.totalDrops, 0); // negative -> 0
  assert.equal(out.txCount, 12); // trunc
  assert.deepEqual(out.rules, ["dusting"]); // dedupliziert, leer raus
  assert.equal(out.distinctAccounts, 2); // aus members.length, nicht Client-Wert 99
  assert.equal(out.key, historyKey([R.a, R.b])); // Serverschlüssel über sanitizierte Members
});

test("sanitizeHistoryCluster: Köder-Label wird im Text ersetzt (sanitizeText)", () => {
  const out = sanitizeHistoryCluster(
        rawCluster([R.a], { label: `Kontakt ${synth(900001)} auffällig` }),
        baitLabels);
  assert.ok(out);
  assert.ok(out.label.includes("Köder #1"));
  assert.ok(!out.label.includes(synth(900001)));
});

test("sanitizeHistoryCluster: köder-only-Cluster wird still verworfen", () => {
  assert.equal(sanitizeHistoryCluster(rawCluster([synth(900001), synth(900002)]), baitLabels), null);
  assert.equal(sanitizeHistoryCluster(null, baitLabels), null);
  assert.equal(sanitizeHistoryCluster({ members: "kein array" }, baitLabels), null);
});

test("sanitizeHistoryList: nachträglich rotierte Köder fallen aus existing heraus", () => {
  const stored = [
    rawCluster([R.a, synth(900001)]), // Rotation: synth(900001) ist jetzt Köder
    rawCluster([synth(900001), synth(900002)]), // komplett Köder -> weg
    rawCluster([R.c, R.d]),
  ];
  const out = sanitizeHistoryList(stored, baitLabels);
  assert.equal(out.length, 2);
  assert.deepEqual(out[0].members, [R.a]);
  assert.equal(out[0].key, historyKey([R.a])); // Schlüssel neu berechnet
  assert.deepEqual(out[1].members, [R.c, R.d]);
});

// =====================================================================
// validateAndSanitizeHistoryPayload (POST-Annehmen)
// =====================================================================

test("validate: severity erzwungen, Köder-Filter beim POST (teilweise)", () => {
  const body = { clusters: [rawCluster([R.a, synth(900001)], { severity: "suspect" })] };
  const out = validateAndSanitizeHistoryPayload(body, baitLabels, new Set());
  assert.equal(out.accepted.length, 1);
  assert.equal(out.ignored, 0);
  assert.deepEqual(out.accepted[0].members, [R.a]);
  assert.equal(out.accepted[0].severity, "malicious");
  assert.equal(out.newKeyCount, 1);
});

test("validate: Köder-only-Cluster still ignoriert (kein Oracle)", () => {
  const body = { clusters: [rawCluster([synth(900001)]), rawCluster([R.a, R.b])] };
  const out = validateAndSanitizeHistoryPayload(body, baitLabels, new Set());
  assert.equal(out.accepted.length, 1);
  assert.equal(out.ignored, 1);
});

test("validate: Caps — 201 Cluster/Payload -> 200 + ignored", () => {
  const clusters = [];
  for (let i = 0; i < 201; i++) clusters.push(rawCluster([synth(i), synth(i + 30000)]));
  // Bestehende Keys für die ersten 181: der Test isoliert die PAYLOAD-Cap —
  // ohne vorhandene Keys griffe zusätzlich die 20-Neu-Keys-Deckelung.
  const existing = new Set(clusters.slice(0, 181).map((c) => historyKey(c.members)));
  const out = validateAndSanitizeHistoryPayload({ clusters }, NO_BAIT, existing);
  assert.equal(out.accepted.length, 200);
  assert.equal(out.ignored, 1);
});

test("validate: Caps — >64 Members je Cluster werden gekappt, >16 Rules dedupliziert", () => {
  const members = [];
  for (let i = 0; i < 70; i++) members.push(synth(i + 100000));
  const rules = [];
  for (let i = 0; i < 20; i++) rules.push(`rule-${i}`);
  const out = validateAndSanitizeHistoryPayload({ clusters: [rawCluster(members, { rules })] }, NO_BAIT, new Set());
  assert.equal(out.accepted[0].members.length, 64);
  assert.equal(out.accepted[0].rules.length, 16);
});

test("validate: >20 NEUE Keys -> Deckelung auf die 20 neuesten (lastSeen desc)", () => {
  const clusters = [];
  for (let i = 0; i < 25; i++) {
    clusters.push(rawCluster([synth(i + 200000), synth(i + 250000)], { lastSeen: 1000 + i }));
  }
  const out = validateAndSanitizeHistoryPayload({ clusters }, NO_BAIT, new Set());
  assert.equal(out.accepted.length, 20);
  assert.equal(out.newKeyCount, 20);
  assert.equal(out.ignored, 5);
  // Die 5 mit dem KLEINSTEN lastSeen sind verworfen:
  for (const c of out.accepted) assert.ok(c.lastSeen >= 1005);
});

test("validate: bestehende Keys zählen nicht gegen die 20er-Neu-Grenze", () => {
  const clusters = [];
  const existing = new Set();
  for (let i = 0; i < 25; i++) {
    const c = rawCluster([synth(i + 400000), synth(i + 450000)], { lastSeen: 1000 + i });
    clusters.push(c);
    if (i < 10) existing.add(historyKey(c.members));
  }
  const out = validateAndSanitizeHistoryPayload({ clusters }, NO_BAIT, existing);
  assert.equal(out.accepted.length, 25); // 10 Updates + 15 neue Keys
  assert.equal(out.newKeyCount, 15);
  assert.equal(out.ignored, 0);
});

test("validate: Duplikat-Schlüssel im selben Payload zählt als ignored", () => {
  const body = { clusters: [rawCluster([R.a, R.b]), rawCluster([R.b, R.a])] };
  const out = validateAndSanitizeHistoryPayload(body, NO_BAIT, new Set());
  assert.equal(out.accepted.length, 1);
  assert.equal(out.ignored, 1);
});

// =====================================================================
// mergeHistory
// =====================================================================

test("merge: Feld-Merge — Überschreiben, min/max, Regel-Vereinigung, 6-h-Zähler", () => {
  const existing = [
    {
      key: historyKey([R.a, R.b]),
      members: [R.a, R.b],
      label: "Cluster A",
      totalDrops: 100,
      txCount: 2,
      distinctAccounts: 2,
      firstSeen: 1000,
      lastSeen: 2000,
      rules: ["dusting"],
      severity: "malicious",
      sightings: 2,
      lastReportedAt: 5000,
    },
  ];
  const incoming = [rawCluster([R.b, R.a], {
    label: "Cluster B",
    totalDrops: 500,
    txCount: 9,
    firstSeen: 500,
    lastSeen: 4000,
    rules: ["drainer-sweep"],
  })];
  const now = 5000 + 7 * 3600 * 1000; // > 6 h seit lastReportedAt
  const { list, changed, dropped } = mergeHistory(existing, incoming, now, NO_BAIT);
  assert.equal(changed, true);
  assert.equal(dropped, 0);
  assert.equal(list.length, 1);
  const e = list[0];
  assert.equal(e.totalDrops, 500); // überschrieben
  assert.equal(e.txCount, 9); // überschrieben
  assert.equal(e.distinctAccounts, 2);
  assert.equal(e.firstSeen, 500); // min
  assert.equal(e.lastSeen, 4000); // max
  assert.deepEqual(e.rules, ["drainer-sweep", "dusting"]); // Vereinigung, sortiert
  assert.equal(e.label, "Cluster B");
  assert.equal(e.sightings, 3); // +1 nach > 6 h
  assert.equal(e.lastReportedAt, now);
});

test("merge: sightings-Inkrement NUR nach 6-h-Frist", () => {
  const base = (lastReportedAt) => [
    {
      key: historyKey([R.c]),
      members: [R.c],
      label: "C",
      totalDrops: 1,
      txCount: 1,
      distinctAccounts: 1,
      firstSeen: 100,
      lastSeen: 200,
      rules: [],
      severity: "malicious",
      sightings: 2,
      lastReportedAt,
    },
  ];
  const inc = [rawCluster([R.c])];
  const exactly6h = mergeHistory(base(5000), inc, 5000 + 6 * 3600 * 1000, NO_BAIT);
  assert.equal(exactly6h.list[0].sightings, 2); // NICHT > 6 h -> Feld-Merge ohne Zähler
  const over6h = mergeHistory(base(5000), inc, 5000 + 6 * 3600 * 1000 + 1, NO_BAIT);
  assert.equal(over6h.list[0].sightings, 3);
});

test("merge: neuer Eintrag -> sightings=1, lastReportedAt=now", () => {
  const now = 123456;
  const { list, changed } = mergeHistory([], [rawCluster([R.d])], now, NO_BAIT);
  assert.equal(changed, true);
  assert.equal(list.length, 1);
  assert.equal(list[0].sightings, 1);
  assert.equal(list[0].lastReportedAt, now);
  assert.equal(list[0].severity, "malicious");
});

test("merge: Selbstheilung — rotierter Köder fällt beim Schreibzugriff raus", () => {
  const stored = [rawCluster([R.a, synth(900002)])];
  const { list, changed, dropped } = mergeHistory(stored, [], 999999, baitLabels);
  // Cluster überlebt mit dem verbleibenden Mitglied; der Köder fällt aus der
  // Serialisierung, changed=true sorgt für den selbstheilenden Write-Back.
  assert.equal(list.length, 1);
  assert.deepEqual(list[0].members, [R.a]);
  assert.equal(list[0].key, historyKey([R.a]));
  assert.equal(dropped, 0); // kein ganzer Cluster verloren — nur das Member
  assert.equal(changed, true); // Sanitize-Veränderung wird zurückgeschrieben
});

test("merge: Selbstheilung — köder-only Bestandscluster verschwindet ganz", () => {
  const stored = [rawCluster([synth(900001), synth(900002)])];
  const { list, changed, dropped } = mergeHistory(stored, [], 999999, baitLabels);
  assert.equal(list.length, 0);
  assert.equal(dropped, 1);
  assert.equal(changed, true);
});

test("merge: No-Op -> changed=false, dropped=0", () => {
  const clean = sanitizeHistoryList([rawCluster([R.a, R.b])], NO_BAIT); // kanonischer Bestand
  const { list, changed, dropped } = mergeHistory(clean, [], 1, NO_BAIT);
  assert.equal(changed, false);
  assert.equal(dropped, 0);
  assert.equal(list.length, 1);
});

test("merge: Cap 200 mit dropped-Zählung (lastSeen desc, Tie-Break key asc)", () => {
  const existing = [];
  for (let i = 0; i < HISTORY_MAX_ENTRIES + 5; i++) {
    existing.push(rawCluster([synth(i + 500000)], { lastSeen: 1000 + i }));
  }
  const { list, changed, dropped } = mergeHistory(existing, [], 1, NO_BAIT);
  assert.equal(list.length, HISTORY_MAX_ENTRIES);
  assert.equal(dropped, 5);
  assert.equal(changed, true);
  assert.ok(list[0].lastSeen >= list[1].lastSeen); // desc
});

test("merge: Serialisierung von 200 Clustern à 64 Members bleibt < 1.000.000 Bytes", () => {
  const incoming = [];
  let n = 0;
  for (let i = 0; i < 200; i++) {
    const members = [];
    for (let j = 0; j < 64; j++) members.push(synth(n++));
    incoming.push(rawCluster(members, { lastSeen: 1000 + i }));
  }
  const { list } = mergeHistory([], incoming, 42, NO_BAIT);
  assert.equal(list.length, 200);
  const size = Buffer.byteLength(serializeHistoryList(list), "utf8");
  assert.ok(size < 1000000, `serialize zu groß: ${size}`);
});

// =====================================================================
// Lokaler Speicher (atomar, ENOENT, Parse-Fehler)
// =====================================================================

test("loadLocalHistory: ENOENT -> [], Roundtrip über saveLocalHistory", async () => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), "hx-history-"));
  const file = path.join(dir, "history.json");
  assert.deepEqual(await loadLocalHistory(file), []); // ENOENT -> []
  const list = mergeHistory([], [rawCluster([R.a, R.b])], 42, NO_BAIT).list;
  await saveLocalHistory(file, list);
  const back = await loadLocalHistory(file);
  assert.deepEqual(back, list);
  const files = await fs.readdir(dir);
  assert.ok(!files.some((f) => f.endsWith(".tmp")), "tmp-Datei muss weg sein (atomar)");
  await fs.rm(dir, { recursive: true, force: true });
});

test("loadLocalHistory: Parse-Fehler WIRFT (kein Überschreiben mit [])", async () => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), "hx-history-"));
  const file = path.join(dir, "history.json");
  await fs.writeFile(file, "### kein JSON ###", "utf8");
  await assert.rejects(() => loadLocalHistory(file), /nicht parsebar/);
  await fs.rm(dir, { recursive: true, force: true });
});

// =====================================================================
// Rate-Limit + Client-Key
// =====================================================================

test("rateLimitHistory: max 6 POSTs/60 s je Client (Sliding Window)", () => {
  const key = `rl-${Date.now()}`;
  for (let i = 0; i < 6; i++) assert.equal(rateLimitHistory(key, i * 1000), true);
  assert.equal(rateLimitHistory(key, 59000), false); // 7. innerhalb des Fensters
  assert.equal(rateLimitHistory(key, 61000), true); // Treffer bei t=1000 verjährt
});

test("clientKeyOf: LETZTER x-forwarded-for || remoteAddress || unknown (XFF-Spoof-resistent)", () => {
  // Letzter Eintrag statt erster (Befund 2026-09-29): Jeder Proxy hängt die
  // IP des unmittelbaren Absenders ans ENDE — der letzte Eintrag ist vom
  // Client nicht fälschbar, der erste wäre per eigenem XFF-Header rotierbar.
  assert.equal(clientKeyOf("1.2.3.4, 5.6.7.8", "9.9.9.9"), "5.6.7.8");
  assert.equal(clientKeyOf("1.2.3.4", "9.9.9.9"), "1.2.3.4");
  assert.equal(clientKeyOf("", "9.9.9.9"), "9.9.9.9");
  assert.equal(clientKeyOf(undefined, undefined), "unknown");
  // Spoof-Versuch: Client rotiert vorangestellte IPs — der Schlüssel bleibt
  // die vom Proxy angehängte echte Absender-IP, das Rate-Limit hält.
  assert.equal(clientKeyOf("198.51.100.1, 10.0.0.1", "203.0.113.7"), "10.0.0.1");
  assert.equal(clientKeyOf("198.51.100.2, 10.0.0.1", "203.0.113.7"), "10.0.0.1");
});

// =====================================================================
// Suche
// =====================================================================

test("searchHistory: substring über members/label/rules, case-insensitive", () => {
  const list = sanitizeHistoryList([rawCluster([R.a], { label: "Cluster A", rules: ["dusting"] })], NO_BAIT);
  assert.equal(searchHistory(list, "testa1").length, 1); // member
  assert.equal(searchHistory(list, "CLUSTER a").length, 1); // label
  assert.equal(searchHistory(list, "DUST").length, 1); // rule
  assert.equal(searchHistory(list, "zzz").length, 0);
  assert.equal(searchHistory(list, "").length, 1); // leerer q -> alles
});

// =====================================================================
// Cap-Priorität (Runde 3): HISTORY_FRAUD_RULES — Betrugsevidenz-Cluster
// (drainer-sweep/peeling-chain/known-bad-hit) überleben die 200er-Kappung
// vor jüngeren Nicht-Betrugs-Clustern; Tie-Break bleibt lastSeen desc /
// key asc. rawCluster trägt per Default rules ['dusting'] (keine
// Betrugsevidenz) — die bestehenden Kappungs-Tests bleiben unberührt.
// =====================================================================

test("Cap-Priorität: Betrugsevidenz-Cluster überleben die Kappung vor jüngeren dusting-Clustern", () => {
  const existing = [];
  for (let i = 0; i < HISTORY_MAX_ENTRIES + 5; i++) {
    existing.push(rawCluster([synth(i + 700000)], { lastSeen: 1000 + i })); // dusting, lastSeen aufsteigend
  }
  // Ältester Cluster des Bestands trägt Betrugsevidenz -> muss überleben,
  // die fünf jüngsten dusting-Cluster fallen.
  existing[0].rules = ["drainer-sweep"];
  const { list, dropped } = mergeHistory(existing, [], 1, NO_BAIT);
  assert.equal(list.length, HISTORY_MAX_ENTRIES);
  assert.equal(dropped, 5);
  assert.ok(list.some((c) => c.rules.includes("drainer-sweep")), "Betrugsevidenz überlebt die jüngste Welle");
  const fallenKeys = new Set(
    [500000, 500001, 500002, 500003, 500004].map((n) => historyKey([synth(n)]))
  );
  assert.equal(list.filter((c) => fallenKeys.has(c.key)).length, 0, "die fünf jüngsten dusting-Cluster fallen");
});

test("Cap-Priorität: Tie-Break innerhalb der Betrugsevidenz-Gruppe bleibt lastSeen desc / key asc", () => {
  const existing = [];
  for (let i = 0; i < HISTORY_MAX_ENTRIES + 3; i++) {
    existing.push(rawCluster([synth(i + 800000)], { lastSeen: 5000, rules: ["known-bad-hit"] }));
  }
  const { list, dropped } = mergeHistory(existing, [], 1, NO_BAIT);
  assert.equal(list.length, HISTORY_MAX_ENTRIES);
  assert.equal(dropped, 3);
  assert.ok(list.every((c) => c.rules.includes("known-bad-hit")), "alle Betrugsevidenz — eine Gruppe");
  assert.ok(list[0].lastSeen >= list[1].lastSeen, "lastSeen desc bleibt Determinismus-Stufe");
  assert.ok(list[0].key <= list[1].key, "Gleichstand -> key asc");
});

test("Cap-Priorität: dusting- und payment-burst-Welle verdrängt drainer-sweep und peeling-chain nicht", () => {
  const existing = [
    rawCluster([synth(900100)], { lastSeen: 100, rules: ["drainer-sweep"] }),
    rawCluster([synth(900101)], { lastSeen: 100, rules: ["peeling-chain"] }),
  ];
  // 199 Nicht-Betrugs-Cluster (dusting, lastSeen 9000..91198) + ein
  // payment-burst-Cluster mit der jüngsten lastSeen überhaupt: 202 Cluster,
  // Kappe 200 -> es fallen genau die zwei ÄLTESTEN Nicht-Betrugs-Cluster
  // (dusting i=0/i=1); die Betrugsevidenz (lastSeen 100, also die ältesten
  // Cluster überhaupt) überlebt trotzdem. Index 910200 ist bewusst gewählt:
  // synth() ist bijektive Base-25-Codierung und kollidiert bei Index-
  // Abständen von 25^4 = 25000 (synth(920000) === synth(910197) hätte die
  // Cluster verschmolzen und dropped auf 1 sinken lassen).
  for (let i = 0; i < HISTORY_MAX_ENTRIES - 1; i++) {
    existing.push(rawCluster([synth(i + 910000)], { lastSeen: 9000 + i, rules: ["dusting"] }));
  }
  existing.push(rawCluster([synth(910200)], { lastSeen: 99_000, rules: ["payment-burst"] }));
  const { list, dropped } = mergeHistory(existing, [], 1, NO_BAIT);
  assert.equal(list.length, HISTORY_MAX_ENTRIES);
  assert.equal(dropped, 2);
  assert.ok(list.some((c) => c.rules.includes("drainer-sweep")), "drainer-sweep überlebt");
  assert.ok(list.some((c) => c.rules.includes("peeling-chain")), "peeling-chain überlebt");
  assert.ok(list.some((c) => c.rules.includes("payment-burst")), "jüngster Nicht-Betrugs-Cluster bleibt");
  assert.ok(!list.some((c) => c.key === historyKey([synth(910000)])), "ältester dusting-Cluster fällt");
  assert.ok(!list.some((c) => c.key === historyKey([synth(910001)])), "zweitältester dusting-Cluster fällt");
  assert.ok(list.some((c) => c.key === historyKey([synth(910002)])), "drittältester dusting-Cluster bleibt");
});

// Kritik-Runde 4, Befund 1: 'wash-cycle' ist hasFraudEvidence-Träger
// (lib/flow-state.mjs:256) und trägt HISTORY_FRAUD_RULES seit der Mapping-
// Korrektur als echte Katalog-ID — ein wash-cycle-Cluster ohne
// mainDrainers/peelingChains muss die 200er-Kappung vor einer jüngeren
// offer-spam-Welle überleben (die Zuordnung der Kappungs-Priorität darf sich
// gegenüber dem known-bad-hit-Fallback nicht verschieben).
test("Cap-Priorität: wash-cycle-Cluster überlebt die Kappung vor jüngerer offer-spam-Welle", () => {
  const existing = [];
  for (let i = 0; i < HISTORY_MAX_ENTRIES + 5; i++) {
    existing.push(rawCluster([synth(i + 950000)], { lastSeen: 1000 + i, rules: ["offer-spam"] }));
  }
  // Ältester Cluster des Bestands: wash-cycle ohne drainer/peeling — die
  // neue Mapping schreibt ihm die echte Katalog-ID (api/advance.js
  // historyRulesFromCluster), nicht mehr den known-bad-hit-Fallback.
  existing[0].rules = ["wash-cycle"];
  const { list, dropped } = mergeHistory(existing, [], 1, NO_BAIT);
  assert.equal(list.length, HISTORY_MAX_ENTRIES);
  assert.equal(dropped, 5);
  assert.ok(list.some((c) => c.rules.includes("wash-cycle")), "wash-cycle überlebt die jüngste Welle");
  // existing[0] (synth(950000), lastSeen 1000) ist der wash-cycle-Cluster —
  // er überlebt; es fallen die fünf ältesten NICHT-Betrugs-Cluster
  // (i=1..5, lastSeen 1001..1005) — sie dürfen in der gekappten Liste
  // nicht mehr vorkommen.
  const fallenKeys = new Set(
    [950001, 950002, 950003, 950004, 950005].map((n) => historyKey([synth(n)]))
  );
  assert.equal(list.filter((c) => fallenKeys.has(c.key)).length, 0, "die fünf ältesten Nicht-Betrugs-Cluster sind entfernt");
  assert.ok(list.some((c) => c.key === historyKey([synth(950000)])), "wash-cycle-Cluster (ältester) bleibt");
});

// =====================================================================
// GitHub-Contents-Adapter (globalThis.fetch-Stubs, OFFLINE)
// =====================================================================

test("GitHub-Adapter: 404 -> {list:[], sha:null}; Authorization aus Env", async () => {
  stubGithubEnv();
  const { calls, restore } = installFetchStub(() => ghResponse({ message: "Not Found" }, 404));
  try {
    const r = await readHistoryGitHub();
    assert.deepEqual(r, { list: [], sha: null });
    assert.equal(calls.length, 1);
    assert.match(calls[0].url, /\/repos\/acme\/history-test\/contents\/data\/history\.json/);
    assert.equal(calls[0].headers.Authorization, `Bearer ${DUMMY_TOKEN}`);
    assert.equal(calls[0].headers.Accept, "application/vnd.github+json");
  } finally {
    restore();
    restoreGithubEnv();
  }
});

test("GitHub-Adapter: JSON-Read liefert sha und decodiert Base64 (inkl. Zeilenumbrüche)", async () => {
  stubGithubEnv();
  const stored = [rawCluster([R.a, R.b])];
  const content = b64(JSON.stringify(stored)).replace(/(.{60})/g, "$1\n"); // GitHub bricht um
  const { restore } = installFetchStub(() => ghResponse({ sha: "s1", content }));
  try {
    const r = await readHistoryGitHub();
    assert.equal(r.sha, "s1");
    assert.equal(r.list.length, 1);
    assert.deepEqual(r.list[0].members, [R.a, R.b]);
  } finally {
    restore();
    restoreGithubEnv();
  }
});

test("GitHub-Adapter: Parse-Fehler im Remote-Bestand wirft", async () => {
  stubGithubEnv();
  const { restore } = installFetchStub(() => ghResponse({ sha: "s1", content: b64("kein json") }));
  try {
    await assert.rejects(() => readHistoryGitHub(), /nicht parsebar/);
  } finally {
    restore();
    restoreGithubEnv();
  }
});

test("GitHub-Adapter: fehlender Token -> Fehler (GET und Write)", async () => {
  stubGithubEnv();
  delete process.env.GITHUB_HISTORY_TOKEN;
  let applyCalled = false;
  const { restore } = installFetchStub(() => {
    throw new Error("darf nicht aufgerufen werden");
  });
  try {
    await assert.rejects(() => readHistoryGitHub(), /Token fehlt/);
    await assert.rejects(() =>
      writeHistoryGitHub(async () => {
        applyCalled = true;
        return [];
      }), /Token fehlt/);
    assert.equal(applyCalled, false);
  } finally {
    restore();
    restoreGithubEnv();
  }
});

test("GitHub-Adapter: Write = frischer Read -> apply -> PUT mit sha und Commit-Message", async () => {
  stubGithubEnv();
  const stored = [rawCluster([R.a])];
  let getCount = 0;
  const applyCalls = [];
  const { calls, restore } = installFetchStub((_, method) => {
    if (method === "GET") {
      getCount += 1;
      return ghResponse({ sha: `s${getCount}`, content: b64(JSON.stringify(stored)) });
    }
    return ghResponse({ commit: { sha: "c1" } }, 200);
  });
  try {
    const out = await writeHistoryGitHub(async (fresh) => {
      applyCalls.push(fresh);
      return [...fresh, rawCluster([R.b])];
    });
    assert.equal(out.length, 2);
    assert.equal(applyCalls.length, 1);
    assert.equal(applyCalls[0].length, 1); // apply lief auf dem FRISCH gelesenen Stand
    assert.equal(calls.length, 2);
    assert.equal(calls[0].method, "GET");
    assert.equal(calls[1].method, "PUT");
    const putBody = JSON.parse(calls[1].body);
    assert.equal(putBody.sha, "s1");
    assert.equal(putBody.message, "history: merge (auto) [skip ci]");
    assert.equal(putBody.branch, "main");
    assert.equal(Buffer.from(putBody.content, "base64").toString("utf8"), serializeHistoryList(out));
  } finally {
    restore();
    restoreGithubEnv();
  }
});

test("GitHub-Adapter: Anlegen ohne sha (nach 404-Read)", async () => {
  stubGithubEnv();
  const { calls, restore } = installFetchStub((_, method) => {
    if (method === "GET") return ghResponse({ message: "Not Found" }, 404);
    return ghResponse({ commit: {} }, 201);
  });
  try {
    const out = await writeHistoryGitHub(async (fresh) => {
      assert.deepEqual(fresh, []);
      return [rawCluster([R.a])];
    });
    assert.equal(out.length, 1);
    const putBody = JSON.parse(calls[1].body);
    assert.equal("sha" in putBody, false); // beim ANLEGEN kein sha
  } finally {
    restore();
    restoreGithubEnv();
  }
});

test("GitHub-Adapter: 409 -> GENAU EIN Retry mit frischem Read, apply auf NEUEM Stand", async () => {
  stubGithubEnv();
  const stateV1 = [rawCluster([R.a], { lastSeen: 100 })];
  const stateV2 = [rawCluster([R.a], { lastSeen: 200 }), rawCluster([R.b], { lastSeen: 300 })];
  let getCount = 0;
  const applyCalls = [];
  const { calls, restore } = installFetchStub((_, method) => {
    if (method === "GET") {
      getCount += 1;
      return ghResponse({ sha: `sha-${getCount}`, content: b64(JSON.stringify(getCount === 1 ? stateV1 : stateV2)) });
    }
    return getCount === 1 ? ghResponse({ message: "conflict" }, 409) : ghResponse({ commit: {} }, 200);
  });
  try {
    const out = await writeHistoryGitHub(async (fresh) => {
      applyCalls.push(JSON.parse(JSON.stringify(fresh)));
      return fresh;
    });
    assert.equal(calls.length, 4); // GET, PUT(409), GET, PUT — kein dritter Versuch
    assert.deepEqual(calls.map((c) => c.method), ["GET", "PUT", "GET", "PUT"]);
    assert.equal(applyCalls.length, 2);
    assert.deepEqual(applyCalls[0], stateV1);
    assert.deepEqual(applyCalls[1], stateV2); // apply auf dem NEUEN frischen Stand
    assert.equal(JSON.parse(calls[3].body).sha, "sha-2");
    assert.equal(out.length, 2);
  } finally {
    restore();
    restoreGithubEnv();
  }
});

test("GitHub-Adapter: 409 zweimal -> ehrlicher Fehler, keine dritte Runde", async () => {
  stubGithubEnv();
  let getCount = 0;
  const { calls, restore } = installFetchStub((_, method) => {
    if (method === "GET") {
      getCount += 1;
      return ghResponse({ sha: `sha-${getCount}`, content: b64(JSON.stringify([])) });
    }
    return ghResponse({ message: "conflict" }, 409);
  });
  try {
    await assert.rejects(() => writeHistoryGitHub(async (fresh) => fresh), /HTTP 409/);
    assert.equal(calls.length, 4); // genau EIN Retry
  } finally {
    restore();
    restoreGithubEnv();
  }
});

test("GitHub-Adapter: 429 -> Fehleroberfläche mit neutralisierter Message (kein Token-Leak)", async () => {
  stubGithubEnv();
  const { restore } = installFetchStub((_, method) => {
    if (method === "GET") return ghResponse({ sha: "s1", content: b64("[]") });
    return ghResponse({ message: "rate limit" }, 429);
  });
  try {
    await assert.rejects(
      () => writeHistoryGitHub(async (fresh) => fresh),
      (err) => {
        assert.equal(err.status, 429);
        assert.match(err.message, /HTTP 429/);
        assert.ok(!err.message.includes(DUMMY_TOKEN)); // Token nie in der Message
        return true;
      }
    );
  } finally {
    restore();
    restoreGithubEnv();
  }
});

test("GitHub-Adapter: In-Flight-Lock serialisiert Writes (GET,PUT,GET,PUT)", async () => {
  stubGithubEnv();
  let getCount = 0;
  const { calls, restore } = installFetchStub((_, method) => {
    if (method === "GET") {
      getCount += 1;
      return ghResponse({ sha: `s${getCount}`, content: b64(JSON.stringify([])) });
    }
    return ghResponse({ commit: {} }, 200);
  });
  try {
    const apply = async (fresh) => [...fresh, rawCluster([synth(getCount)], { label: `W${getCount}` })];
    const [r1, r2] = await Promise.all([writeHistoryGitHub(apply), writeHistoryGitHub(apply)]);
    assert.equal(r1.length, 1);
    assert.equal(r2.length, 1);
    assert.deepEqual(calls.map((c) => c.method), ["GET", "PUT", "GET", "PUT"]);
  } finally {
    restore();
    restoreGithubEnv();
  }
});

// =====================================================================
// Blob-Fallback (Contents-API ohne content bei > 1 MiB — Wisch-Zyklus-Fix)
// live belegt: contents?ref=... {size:1050727, content_len:0, encoding:"none"}
// =====================================================================

test("Blob-Fallback: Contents {size>0, content:''} + Blob (base64 mit Newlines) -> doc geparst, sha erhalten", async () => {
  stubGithubEnv();
  const stored = [rawCluster([R.a, R.b])];
  const blobB64 = b64(JSON.stringify(stored)).replace(/(.{60})/g, "$1\n"); // GitHub bricht Blob-base64 um
  const { calls, restore } = installFetchStub((_, method, url) => {
    if (url.includes("/git/blobs/")) {
      return ghResponse({ sha: "blob1", size: 1125252, encoding: "base64", content: blobB64 });
    }
    return ghResponse({ sha: "s1", size: 1125252, encoding: "none", content: "" });
  });
  try {
    const r = await readHistoryGitHub();
    assert.equal(r.sha, "s1", "Contents-sha bleibt der PUT-Anker (Blob-sha nicht übernommen)");
    assert.equal(r.list.length, 1);
    assert.deepEqual(r.list[0].members, [R.a, R.b]);
    assert.deepEqual(calls.map((c) => c.method), ["GET", "GET"]);
    assert.match(calls[1].url, /\/repos\/acme\/history-test\/git\/blobs\/s1/);
    assert.equal(calls[1].headers.Authorization, `Bearer ${DUMMY_TOKEN}`);
    assert.equal(calls[1].headers.Accept, "application/vnd.github+json");
  } finally {
    restore();
    restoreGithubEnv();
  }
});

test("Blob-Fallback: Contents leer + Blob 404 -> Wurf err.status 502 (kein doc null)", async () => {
  stubGithubEnv();
  const { calls, restore } = installFetchStub((_, method, url) => {
    if (url.includes("/git/blobs/")) return ghResponse({ message: "Not Found" }, 404);
    return ghResponse({ sha: "s1", size: 1050727, encoding: "none", content: "" });
  });
  try {
    await assert.rejects(() => readHistoryGitHub(), (err) => {
      assert.equal(err.status, 502);
      assert.match(err.message, /Blob-Read/);
      assert.ok(!err.message.includes(DUMMY_TOKEN));
      return true;
    });
    assert.equal(calls.length, 2);
  } finally {
    restore();
    restoreGithubEnv();
  }
});

test("Blob-Fallback: echte leere Datei {size:0, content:''} -> {list:[], sha}, kein Blob-Read", async () => {
  stubGithubEnv();
  const { calls, restore } = installFetchStub(() => ghResponse({ sha: "s0", size: 0, encoding: "none", content: "" }));
  try {
    const r = await readHistoryGitHub();
    assert.deepEqual(r, { list: [], sha: "s0" });
    assert.equal(calls.length, 1, "size 0 -> Leerstand ohne Fallback-Request");
  } finally {
    restore();
    restoreGithubEnv();
  }
});

test("Blob-Fallback FAIL-CLOSED: size>0 ohne sha -> 502; Array-Antwort (size undefined) -> 502", async () => {
  stubGithubEnv();
  const stub1 = installFetchStub(() => ghResponse({ size: 1050727, encoding: "none", content: "" }));
  try {
    await assert.rejects(() => readHistoryGitHub(), (err) => {
      assert.equal(err.status, 502);
      assert.match(err.message, /Blob-Anker/);
      return true;
    });
  } finally {
    stub1.restore();
    restoreGithubEnv();
  }
  stubGithubEnv();
  const stub2 = installFetchStub(() => ghResponse([{ name: "data" }], 200)); // Verzeichnis-Antwort
  try {
    await assert.rejects(() => readHistoryGitHub(), (err) => {
      assert.equal(err.status, 502);
      return true;
    });
  } finally {
    stub2.restore();
    restoreGithubEnv();
  }
});

test("Blob-Fallback: Write-Frisch-Read auf >1MB-Bestand -> apply erhält echten Bestand, PUT-sha aus Contents", async () => {
  stubGithubEnv();
  const stored = [rawCluster([R.a])];
  const blobB64 = b64(JSON.stringify(stored));
  const applyCalls = [];
  const { calls, restore } = installFetchStub((_, method, url) => {
    if (method === "GET") {
      if (url.includes("/git/blobs/")) return ghResponse({ sha: "blob1", size: 1125252, encoding: "base64", content: blobB64 });
      return ghResponse({ sha: "s1", size: 1125252, encoding: "none", content: "" });
    }
    return ghResponse({ commit: {} }, 200);
  });
  try {
    const out = await writeHistoryGitHub(async (fresh) => {
      applyCalls.push(fresh);
      return [...fresh, rawCluster([R.b])];
    });
    assert.equal(applyCalls.length, 1);
    assert.equal(applyCalls[0].length, 1, "apply lief auf dem per Blob-Fallback gelesenen Bestand (nicht [])");
    assert.equal(out.length, 2);
    const put = calls.find((c) => c.method === "PUT");
    assert.equal(JSON.parse(put.body).sha, "s1", "PUT-Anker ist der Contents-sha");
  } finally {
    restore();
    restoreGithubEnv();
  }
});

// =====================================================================
// Contents-DELETE (deleteGitHubFile — Retention-Helfer)
// =====================================================================

test("deleteGitHubFile: Read -> DELETE mit sha; true", async () => {
  stubGithubEnv();
  const { calls, restore } = installFetchStub((_, method) => {
    if (method === "GET") return ghResponse({ sha: "sha-del", content: b64("[]") });
    return ghResponse({ commit: {} }, 200);
  });
  try {
    const ok = await deleteGitHubFile("data/block-window/2026-09-25.json");
    assert.equal(ok, true);
    assert.deepEqual(calls.map((c) => c.method), ["GET", "DELETE"]);
    assert.match(calls[1].url, /\/repos\/acme\/history-test\/contents\/data\/block-window\/2026-09-25\.json/);
    const delBody = JSON.parse(calls[1].body);
    assert.equal(delBody.sha, "sha-del"); // DELETE braucht den sha aus dem frischen Read
    assert.equal(delBody.branch, "main");
    assert.equal(delBody.message, "history: merge (auto) [skip ci]");
    assert.equal(calls[1].headers.Authorization, `Bearer ${DUMMY_TOKEN}`);
  } finally {
    restore();
    restoreGithubEnv();
  }
});

test("deleteGitHubFile: 404 -> false (nichts zu löschen, kein Fehler)", async () => {
  stubGithubEnv();
  const { calls, restore } = installFetchStub((_, method) => {
    if (method === "GET") return ghResponse({ message: "Not Found" }, 404);
    return ghResponse({}, 500); // darf nie erreicht werden
  });
  try {
    const ok = await deleteGitHubFile("data/block-window/2026-09-20.json");
    assert.equal(ok, false);
    assert.deepEqual(calls.map((c) => c.method), ["GET"]); // kein DELETE nach 404-Read
  } finally {
    restore();
    restoreGithubEnv();
  }
});

test("deleteGitHubFile: 409 -> GENAU EIN Retry mit frischem sha", async () => {
  stubGithubEnv();
  let getCount = 0;
  const { calls, restore } = installFetchStub((_, method) => {
    if (method === "GET") {
      getCount += 1;
      return ghResponse({ sha: `sha-${getCount}`, content: b64("[]") });
    }
    return getCount === 1 ? ghResponse({ message: "conflict" }, 409) : ghResponse({ commit: {} }, 200);
  });
  try {
    const ok = await deleteGitHubFile("data/block-window/2026-09-25.json");
    assert.equal(ok, true);
    assert.deepEqual(calls.map((c) => c.method), ["GET", "DELETE", "GET", "DELETE"]);
    assert.equal(JSON.parse(calls[3].body).sha, "sha-2"); // Retry auf frischem sha
  } finally {
    restore();
    restoreGithubEnv();
  }
});

test("deleteGitHubFile: 429 -> Fehler mit status, neutrale Message (kein Token-Leak)", async () => {
  stubGithubEnv();
  const { restore } = installFetchStub((_, method) => {
    if (method === "GET") return ghResponse({ sha: "s1", content: b64("[]") });
    return ghResponse({ message: "rate limit" }, 429);
  });
  try {
    await assert.rejects(
      () => deleteGitHubFile("data/block-window/2026-09-25.json"),
      (err) => {
        assert.equal(err.status, 429);
        assert.match(err.message, /HTTP 429/);
        assert.ok(!err.message.includes(DUMMY_TOKEN));
        return true;
      }
    );
  } finally {
    restore();
    restoreGithubEnv();
  }
});

test("deleteGitHubFile: fehlender Token -> Fehler, kein fetch", async () => {
  stubGithubEnv();
  delete process.env.GITHUB_HISTORY_TOKEN;
  const { calls, restore } = installFetchStub(() => {
    throw new Error("darf nicht aufgerufen werden");
  });
  try {
    await assert.rejects(() => deleteGitHubFile("data/block-window/2026-09-25.json"), /Token fehlt/);
    assert.equal(calls.length, 0);
  } finally {
    restore();
    restoreGithubEnv();
  }
});
