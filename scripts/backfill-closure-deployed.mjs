// scripts/backfill-closure-deployed.mjs
//
// WAS DIESE DATEI TUTT: Sie tragt den Schliess-Beweis fuer jede Quorum-Behauptung in den
// Bestand nach, aus dem die Website tatsaechlich liest (GITHUB_HISTORY_REPO). Bewiesen gilt nur,
// wenn ZWEI unabhaengige Autoritaeten denselben 64er-Hash fuer genau diesen Ledger-Index melden:
// xrpscan.com (die Referenz, die ein Betreiber selbst nachlesen kann) und der Ledger-Strom des
// Netzes selbst ueber die JSON-RPC-Schnittstelle von xrplcluster.com.
//
// WARUM EIGENES SKRIPT: scripts/backfill-closure.mjs arbeitet auf einem lokalen Ordner. Der
// ausgelieferte Bestand liegt in einem privaten Repo und wird von einem anderen Mithoer-Lauf
// geschrieben. Ohne diesen Weg bleibt der Nachtrag, was lokal laengst belegt ist, auf der Website
// eine Luecke - und eine Luecke in der Akkuratz-Spalte ist genau das, was ein Betreiber nicht
// akzeptieren kann.
//
// WAS SIE NICHT TUT:
//  - Sie erfindet nichts. Geschrieben wird nur nach Deckung beider Quellen; sonst bleibt die
//    Behauptung offen und wird als offen ausgegeben.
//  - Sie ersetzt nichts. appendClosureProofs lehnt jeden Index ab, fuer den der Tag schon eine
//    Autoritaet hat (eigener Mithoerbeweis in ledgerStats oder bestehender closureProof).
//  - Sie schreibt nie in ledgerStats, nie Zaehler, nie Incidents, nie Luecken. Nur closureProofs.
//  - Sie laeuft gegen den FRISCH gelesenen Stand: writeGitHubContents liesst vor jedem Write (auch
//    im 409-Retry), damit ein gleichzeitiger Flush des Recorders nicht ueberschrieben wird.
//
// GEFUNDENE GRENZE DER QUELLE (2026-10-16 nachgerechnet): api.xrpscan.com antwortet in zwei
// Formaten - das eine nennt close_time in Unix-Sekunden, das andere in der Ripple-Epoche
// (946.684.800 s unter Unix) und laesst tx_count weg. Verglichen wird deshalb ueber
// close_time_human bzw. close_time_iso, und eine fehlende Tx-Zahl der Quelle ist 'nicht
// vergleichbar', nie eine Abweichung.
//
// Lauf:  node scripts/backfill-closure-deployed.mjs --dry-run
//        node scripts/backfill-closure-deployed.mjs --days=30d
//        node scripts/backfill-closure-deployed.mjs --dates=2026-10-09,2026-10-15 --max=20
import fs from "node:fs";
import { readGitHubContents, writeGitHubContents } from "../lib/history.mjs";
import { dayPath, datesForRange, claimLedgersWithoutProof, appendClosureProofs } from "../lib/validator-trace-store.mjs";

const argv = process.argv.slice(2);
const arg = (name, dflt) => { const i = argv.indexOf("--" + name); return i === -1 ? dflt : argv[i + 1]; };
const DRY = argv.includes("--dry-run");
const RANGE = arg("days", "30d");
const DATES = arg("dates") ? arg("dates").split(",").map((d) => d.trim()).filter(Boolean) : datesForRange(RANGE);
const maxArg = arg("max", "");
const MAX_PER_DAY = maxArg ? Math.max(1, Number(maxArg)) : Infinity;
const DELAY = Math.max(0, Number(arg("delay", 250)) || 0);
const HEX64 = /^[0-9A-Fa-f]{64}$/;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

if (!process.env.GITHUB_HISTORY_TOKEN) {
  console.log("Kein GITHUB_HISTORY_TOKEN: Nachtrag setzt Schreibzugriff auf das Daten-Repo voraus.");
  process.exit(1);
}

const codec = {
  serialize: (doc) => JSON.stringify(doc),
  parse: (text) => {
    const o = JSON.parse(text);
    if (!o || typeof o !== "object" || Array.isArray(o)) throw new Error("Trace-Tagesdatei hat kein gueltiges Format.");
    return o;
  },
};

async function get(url, options) {
  for (let attempt = 1; attempt <= 4; attempt += 1) {
    try {
      const res = await fetch(url, { ...options, signal: AbortSignal.timeout(20000) });
      if (res.status === 429) { if (attempt < 4) { await sleep(2500 * attempt); continue; } return { error: "HTTP 429" }; }
      if (!res.ok) { if (attempt < 4) { await sleep(700 * attempt); continue; } return { error: "HTTP " + res.status }; }
      const j = await res.json();
      if (!j || typeof j !== "object") { if (attempt < 4) { await sleep(600 * attempt); continue; } return { error: "no object" }; }
      const err = j.error || (j.result && j.result.error);
      if (err) {
        const message = (j.result && j.result.error_message) || j.error_message || String(err);
        if (attempt < 4 && /slow|rate|quota|limit|temporar/i.test(message)) { await sleep(3000 * attempt); continue; }
        return { error: message };
      }
      return { ok: true, j };
    } catch (e) { if (attempt === 4) return { error: e instanceof Error ? e.message : String(e) }; }
  }
  return { error: "unreachable" };
}
const scanLedger = (index) => get("https://api.xrpscan.com/api/v1/ledger/" + index, {});
async function netLedger(index) {
  const call = () => get("https://xrplcluster.com", {
    method: "POST", headers: { "content-type": "application/json" },
    body: JSON.stringify({ method: "ledger", params: { ledger_index: index, api_version: 2 } }),
  });
  let last = null;
  for (let pool = 1; pool <= 3; pool += 1) {
    const r = await call();
    if (r.ok && r.j && r.j.result && r.j.result.ledger) return { ok: true, ledger: r.j.result.ledger };
    last = r;
    if (r.ok) await sleep(400);
  }
  return { error: (last && last.error) || "kein ledger-Objekt" };
}
const isoMs = (x) => (typeof x === "string" && !Number.isNaN(Date.parse(x)) ? Date.parse(x) : null);

let claimTotal = 0, provenTotal = 0, openTotal = 0, writtenDays = 0;
const problems = [];

for (const date of [...DATES].sort()) {
  let res;
  try { res = await readGitHubContents(dayPath(date), codec); } catch (e) { problems.push(date + ": Lesefehler " + e.message); continue; }
  if (!res.doc) continue;
  const claims = claimLedgersWithoutProof(res.doc);
  if (!claims.length) continue;
  claimTotal += claims.length;
  const proofs = [];
  for (const { ledgerIndex, incidents } of claims.slice(0, MAX_PER_DAY)) {
    const a = await scanLedger(ledgerIndex);
    if (DELAY) await sleep(DELAY);
    if (!a.ok) { openTotal += 1; problems.push(date + " #" + ledgerIndex + ": xrpscan " + a.error); continue; }
    const b = await netLedger(ledgerIndex);
    if (DELAY) await sleep(DELAY);
    if (!b.ok) { openTotal += 1; problems.push(date + " #" + ledgerIndex + ": xrplcluster " + b.error); continue; }
    const ha = typeof a.j.ledger_hash === "string" ? a.j.ledger_hash.toUpperCase() : null;
    const hb = typeof b.ledger.ledger_hash === "string" ? b.ledger.ledger_hash.toUpperCase() : null;
    if (Number(a.j.ledger_index) !== ledgerIndex || Number(b.ledger.ledger_index) !== ledgerIndex) {
      openTotal += 1; problems.push(date + " #" + ledgerIndex + ": Index-Vergleich " + a.j.ledger_index + " / " + b.ledger.ledger_index); continue;
    }
    if (!ha || !HEX64.test(ha) || !hb || !HEX64.test(hb) || ha !== hb) {
      openTotal += 1;
      problems.push(date + " #" + ledgerIndex + ": Hash nicht deckungsgleich (" + (ha || "keiner") + " / " + (hb || "keiner") + ")");
      continue;
    }
    const tScan = isoMs(a.j.close_time_human);
    const tNet = isoMs(b.ledger.close_time_iso);
    proofs.push({
      l: ledgerIndex, cl: true, ch: ha, chSource: "xrpscan", chVerifiedBy: "xrplcluster.com",
      chAt: new Date().toISOString(),
      xc: { hashAgree: true, sourcesAgree: tScan !== null && tNet !== null ? tScan === tNet : null, tScan, tNet },
    });
    provenTotal += 1;
    console.log(date, "#" + ledgerIndex, "Incidents", incidents, "-> Schliess-Beweis belegt", ha.slice(0, 12),
      "| close", tScan !== null ? new Date(tScan).toISOString() : "-", "| Netz deckt zu:", tScan === tNet);
  }
  if (claims.length > MAX_PER_DAY) openTotal += claims.length - MAX_PER_DAY;
  if (!proofs.length) continue;
  if (DRY) { console.log(date + ": dry-run, " + proofs.length + " Nachweise nicht geschrieben"); continue; }
  const merge = await writeGitHubContents((fresh) => {
    const out = appendClosureProofs(fresh, proofs);
    return out.doc;
  }, dayPath(date), codec);
  writtenDays += 1;
  void merge;
  const after = await readGitHubContents(dayPath(date), codec);
  const stillOpen = claimLedgersWithoutProof(after.doc ?? null).length;
  console.log(date + ": geschrieben, offene Quorum-Behauptungen danach " + stillOpen + " (vorher " + claims.length + ")");
}

console.log("");
console.log("BEFUND");
console.log("  Quorum-Behauptungen ohne Forensik-Zeile:", claimTotal);
console.log("  davon mit Zwei-Quellen-Nachweis belegt:", provenTotal);
console.log("  offen geblieben (Quelle ablehnte oder Hash uneins):", openTotal);
console.log("  Tage geschrieben:", writtenDays, DRY ? "(dry-run, nichts geschrieben)" : "");
if (problems.length) {
  console.log("");
  console.log("OFFENE NACHWEISE:");
  for (const p of problems.slice(0, 40)) console.log("  " + p);
  if (problems.length > 40) console.log("  ... weitere " + (problems.length - 40));
}
process.exit(openTotal > 0 ? 2 : 0);
