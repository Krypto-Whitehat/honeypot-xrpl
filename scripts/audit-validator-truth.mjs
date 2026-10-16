// scripts/audit-validator-truth.mjs
//
// DAUER-KONTROLLE fuer die Akkuratz je VALIDATOR. Kein Nachtrag, nichts geschrieben.
//
// Die Ledger-Kontrolle (scripts/audit-ground-truth.mjs) prueft, ob ein Ledger und seine Stimmen
// stimmen. Diese Kontrolle prueft die andere Haelfte: stimmt die Aussage, die die Engine ueber
// EINEN KNOTEN macht, mit der Netz-Referenz ueberein, die ein Betreiber selbst nachlesen kann?
//
// Warum das noetig ist: der Rekorder hoert zu. Empfaengt er in einem Ledger zu wenige
// Validierungen, fehlt ihm die Stimme jedes Knoten, und die Erfassung zeigt das als
// 'kein Vote erfasst' je Knoten. Auf einem bewiesen geschlossenen Ledger hat das Netz sein
// Quorum trotzdem erreicht. Ohne Gegenprobe wird die eigene duenne Erfassung zur Aussage ueber
// die Knoten - und das ist genau die Klasse von Fehler, die ein Betrugserkennungs-Werkzeug
// nicht haben darf.
//
// Zwei unabhaengige Grenzen:
//  A) NETZ-REFERENZ  api.xrpscan.com/api/v1/validator/<master>: 'missed' und 'total' je Fenster.
//     Die Referenz sagt, wie viele Ledger DIESEN Knoten das Netz nicht validieren sah. Steht in
//     der eigenen Erfassung mehr, ist die Differenz ein Beweis ueber die eigene Erfassung.
//  B) SCHLIESS-GRENZE ohne jede externe Quelle: auf einem geschlossenen Ledger mit 'members'
//     beobachteten dUNL-Knoten und 'needed' als Ziel koennen hoechstens members - needed echt
//     gefehlt haben.
//
// Lauf:  node scripts/audit-validator-truth.mjs              (24-h-Fenster, alle Knoten mit Anspruch)
//        node scripts/audit-validator-truth.mjs --hours=1    (Stunde-Fenster)
//        node scripts/audit-validator-truth.mjs --max=20     (Deckel je Tag beim Einlesen)
// Exit 0 = kein Widerspruch: jede Knoten-Aussage bleibt innerhalb ihrer beiden Grenzen.
// Exit 1 = mindestens ein Widerspruch: die Erfassung behauptet mehr Abwesenheiten als die Referenz.
// Exit 2 = kein Widerspruch gefunden, aber Knoten blieben ungeprueft, weil die Referenz nicht
//         erreichbar oder ohne Zahl war. Ungeprueft ist keine Entlastung.
import fs from "node:fs";
import path from "node:path";
import { TRACE_DEFAULTS } from "../lib/validator-trace.mjs";
import { fileURLToPath } from "node:url";
import { absencesOf, closureBound, compareAbsences, summarizeTruth } from "../lib/validator-truth.mjs";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const DIR = process.env.TRACE_DATA_DIR || path.join(ROOT, "data", "validator-trace");
const args = process.argv.slice(2);
const HOURS = Number(args.find((a) => a.startsWith("--hours="))?.split("=")[1]) || 24;
const maxArg = args.find((a) => a.startsWith("--max="));
const MAX_PER_DAY = maxArg ? Math.max(1, Number(maxArg.split("=")[1])) : Infinity;
const DELAY = Number(process.env.AUDIT_DELAY_MS ?? 250);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function get(url) {
  for (let attempt = 0; attempt < 3; attempt += 1) {
    try {
      const res = await fetch(url, { headers: { accept: "application/json" } });
      if (res.status === 429) { await sleep(1500 * (attempt + 1)); continue; }
      if (!res.ok) return { error: "HTTP " + res.status };
      return { json: await res.json() };
    } catch (e) {
      await sleep(600 * (attempt + 1));
    }
  }
  return { error: "not reachable" };
}

const DAY = /^\d{4}-\d{2}-\d{2}\.json$/;
const files = fs.existsSync(DIR) ? fs.readdirSync(DIR).filter((f) => DAY.test(f)).sort() : [];
if (!files.length) {
  console.log("Kein Trace-Speicher unter " + DIR + " - nichts zu pruefen. (TRACE_DATA_DIR setzen.)");
  process.exit(2);
}

const claimsByMaster = new Map();
const ledgerRows = new Map();
let incidents = 0;
for (const f of files) {
  let doc;
  try { doc = JSON.parse(fs.readFileSync(path.join(DIR, f), "utf8")); } catch { continue; }
  const list = (Array.isArray(doc.incidents) ? doc.incidents : []).slice(-MAX_PER_DAY);
  incidents += list.length;
  for (const i of list) {
    if (!i || !i.m) continue;
    const list2 = claimsByMaster.get(i.m) ?? [];
    list2.push({ master: i.m, ledgerIndex: i.l, timeMs: i.t, type: i.type });
    claimsByMaster.set(i.m, list2);
  }
  for (const s of doc.ledgerStats ?? []) {
    if (!s || !Number.isFinite(s.l)) continue;
    ledgerRows.set(s.l, s);
  }
}

const names = new Map();
const listRes = await get("https://api.xrpscan.com/api/v1/validators");
if (listRes.json && Array.isArray(listRes.json)) {
  for (const v of listRes.json) if (v?.master_key) names.set(v.master_key, v.domain || "");
}

// Grenze B zuerst, ganz ohne Netz: die Schliessung selbst begrenzt, wie viele Knoten echt
// gefehlt haben koennen. Eine Zeile, die mehr Nicht-Signierer zaehlt als diese Grenze zulaesst,
// widerlegt sich selbst.
let boundRows = 0, boundBroken = 0, boundArtifactMin = 0;
for (const [index, s] of ledgerRows) {
  const closed = s.cl === true || (typeof s.ch === "string" && s.cl !== false);
  if (!closed) continue;
  const members = Number.isFinite(s.mm) && s.mm > 0 ? s.mm
    : Math.ceil((Number(s.need) || 0) / TRACE_DEFAULTS.quorumFrac);
  const b = closureBound({ members, needed: s.need });
  if (!b) continue;
  const c = s.c ?? {};
  const absent = (c.missed ?? 0) + (c.noQuorum ?? 0);
  if (absent === 0) continue;
  boundRows += 1;
  boundArtifactMin += Math.max(0, absent - b.genuineAbsentMax);
  if (absent > b.genuineAbsentMax) boundBroken += 1;
}

const results = [];
let unreachable = 0;
const masters = [...claimsByMaster.keys()];
console.log("Knoten mit Abwesenheits-Behauptungen:", masters.length, "| Vorfaelle gelesen:", incidents);
console.log("Fenster der Gegenprobe:", HOURS, "h | Referenz: api.xrpscan.com/api/v1/validator/<master>");
console.log("");

for (const master of masters) {
  const all = absencesOf(claimsByMaster.get(master), master);
  if (!all.length) continue;
  const asOf = Date.now();
  const res = await get("https://api.xrpscan.com/api/v1/validator/" + master);
  if (!res.json) { unreachable += 1; results.push({ master, verdict: "not-comparable", claims: all.length, reason: res.error }); continue; }
  const scan = {
    missed: res.json.agreement_24h?.missed ?? null,
    total: res.json.agreement_24h?.total ?? null,
    score: res.json.agreement_24h?.score ?? null,
    incomplete: res.json.agreement_24h?.incomplete === true,
    asOfMs: asOf,
  };
  const hours = HOURS === 1 ? 1 : 24;
  if (hours === 1) {
    scan.missed = res.json.agreement_1h?.missed ?? null;
    scan.total = res.json.agreement_1h?.total ?? null;
    scan.score = res.json.agreement_1h?.score ?? null;
    scan.incomplete = res.json.agreement_1h?.incomplete === true;
  }
  const r = compareAbsences({ master, claims: all, scan, rangeHours: hours, hours });
  r.domain = names.get(master) || "";
  results.push(r);
  const flag = r.verdict === "contradicted" ? "WIDERLEGT" : r.verdict === "consistent" ? "innerhalb" : "keine Referenz";
  console.log("  " + (r.domain || master.slice(0, 12)).padEnd(34)
    + " eigene " + String(r.claims).padStart(5)
    + "  Referenz " + String(r.groundMissed ?? "-").padStart(5) + "/" + String(r.groundTotal ?? "-").padStart(6)
    + "  mindestens eigene " + String(r.falsePositiveMin ?? "-").padStart(5)
    + "  " + flag);
  await sleep(DELAY);
}

const s = summarizeTruth(results);
console.log("");
console.log("BEFUND");
console.log("  Knoten geprueft:", s.nodes, "| widerlegt:", s.contradictedNodes,
  "| innerhalb der Referenz:", s.consistentNodes, "| ohne verwertbare Referenz:", s.notComparableNodes);
console.log("  Eigene Abwesenheiten im Fenster:", s.claims, "| davon nachweisbar eigene Erfassung:", s.falsePositiveMin);
console.log("  Referenz sagt fuer dieselbe Menge:", s.groundMissed, "von", s.groundTotal, "Knoten-Ledern");
console.log("  Schliess-Grenze (ohne externe Quelle):", boundRows, "Zeilen mit Nicht-Signierern,",
  boundBroken, "widerlegen sich selbst, nachrechenbare Erfassungs-Luecke:", boundArtifactMin, "Knoten-Ledger");
console.log("  Identitaet je Ledger bleibt offen: die Referenz ist eine Fensterzahl, keine Liste.");

const problems = results.filter((r) => r.verdict === "contradicted");
if (problems.length) {
  console.log("");
  console.log("ABWEICHUNGEN (die Erfassung behauptet mehr Abwesenheiten als die Referenz zulaesst):");
  for (const r of problems.slice(0, 25)) {
    console.log("  - " + (r.domain || r.master) + ": eigene " + r.claims + ", Referenz " + r.groundMissed
      + "/" + r.groundTotal + " -> mindestens " + r.falsePositiveMin + " gehen auf diese Erfassung zurueck (" + r.reason + ")");
  }
  if (problems.length > 25) console.log("  - ... weitere " + (problems.length - 25) + " Knoten");
  if (boundBroken) console.log("  - " + boundBroken + " Forensik-Zeilen zaehlen mehr Nicht-Signierer als ihre eigene Schliessung zulaesst");
  process.exit(1);
}
if (unreachable || s.notComparableNodes) {
  console.log("");
  console.log("OFFENE PRUEFUNGEN (kein Befund und keine Entlastung):");
  for (const r of results.filter((x) => x.verdict === "not-comparable").slice(0, 20)) {
    console.log("  - " + (r.domain || r.master) + ": " + (r.reason || "keine Referenz"));
  }
  process.exit(2);
}
console.log("");
console.log("Kein Widerspruch: jede Knoten-Aussage bleibt innerhalb der Referenz und innerhalb ihrer Schliessung.");
