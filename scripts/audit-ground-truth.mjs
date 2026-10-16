// scripts/audit-ground-truth.mjs
//
// DAUER-KONTROLLE fuer die Akkuratz der Engine. Kein Nachtrag, keine Schaetzung, nichts geschrieben.
//
// Beantwortete Frage: stimmt jede Zahl, die die Engine ueber einen Ledger und seine Stimmen
// auswirft, (a) mit den Rechenregeln ueberein, die die Engine selbst anlegt, und (b) mit den
// Quellen, die ein Betreiber selbst nachlesen kann?
//
// Drei Pruefungen:
//  A) INVARIANZ  je Forensik-Zeile, ohne Netz: need == ceil(members * quorumFrac), mg == top - need,
//     die Identitaet des Rekorder-Loops (gesehene Mitglieder-Stimmen + ohne Vote = members),
//     top <= v, und ein als geschlossen gefuehrter Ledger hat einen 64-Hex-Hash.
//  B) DECKUNG    jede Zeile, die einen abstreitbaren Vote-Anspruch erhebt (top < need), wird
//     index-gleich bei xrpscan.com UND xrplcluster.com nachgelesen: Hash, Tx-Zahl, Close-Zeit.
//     Ein gespeicherter Gegenpruef-Vermerk (xc) wird dabei erneut geprueft - ein veralteter
//     Vermerk ist ein Fehler, keine Entlastung.
//  C) GRENZE     die aus der Schliessung folgende Obergrenze echter Nicht-Signierer und die
//     Mindestzahl nachweisbarer Erfassungs-Luecke dieses Recorders, nachgerechnet aus denselben
//     Zahlen, die die UI zeigt.
//
// Lauf:  node scripts/audit-ground-truth.mjs            (alle Anspruch-Zeilen)
//        node scripts/audit-ground-truth.mjs --max=40   (Deckel je Tag, fuer schnelle Laeufe)
//        node scripts/audit-ground-truth.mjs --all      (jede Forensik-Zeile, nicht nur Anspruch-Zeilen)
// Exit 0 = keine Abweichung, jede Zeile gegen mindestens eine Quelle geprueft.
// Exit 1 = mindestens eine echte Abweichung (Zahl oder Hash widerspricht der Quelle oder sich selbst).
// Exit 2 = keine Abweichung gefunden, aber Zeilen blieben ungeprueft, weil keine Quelle erreichbar war.
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { TRACE_DEFAULTS, captureBound, ledgerClosure } from "../lib/validator-trace.mjs";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const DIR = process.env.TRACE_DATA_DIR || path.join(ROOT, "data", "validator-trace");
const HEX64 = /^[0-9A-F]{64}$/;
const args = process.argv.slice(2);
const ALL = args.includes("--all");
const QUIET = args.includes("--quiet");
const maxArg = args.find((a) => a.startsWith("--max="));
const MAX_PER_DAY = maxArg ? Math.max(1, Number(maxArg.split("=")[1])) : Infinity;
const DELAY = Number(process.env.AUDIT_DELAY_MS ?? 350);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// Eine Quelle, die ablehnt, ist keine Abweichung. 'slowDown' von xrplcluster (10 000 Einheiten
// je 60 s) wurde im Voll-Lauf ueber 30 Ledger als 'kein ledger-Objekt' gelesen - das waere ein
// Fehlalarm ueber Daten, die in Wahrheit deckungsgleich sind. Abgelehnte Abfragen werden
// zurueckgehalten und zaehlen als 'nicht erreichbar', nie als Befund.
async function get(url, init) {
  for (let attempt = 1; attempt <= 4; attempt += 1) {
    try {
      const r = await fetch(url, { ...init, signal: AbortSignal.timeout(20000) });
      if (r.status === 429) { if (attempt < 4) { await sleep(2500 * attempt); continue; } return { error: "HTTP 429" }; }
      if (!r.ok) { if (attempt < 4) { await sleep(700 * attempt); continue; } return { error: "HTTP " + r.status }; }
      const j = await r.json();
      const err = j && (j.error || (j.result && j.result.error));
      if (err) {
        const message = (j.result && j.result.error_message) || (j && j.error_message) || String(err);
        if (attempt < 4 && /slow|rate|quota|limit|temporar/i.test(message)) { await sleep(3000 * attempt); continue; }
        // 'ledgerNotFound' ist eine Antwort, kein Transportfehler. Bei xrplcluster heisst es
        // 'dieser Pool-Knoten hat den Ledger nicht', nicht 'der Ledger existiert nicht': derselbe
        // Pool antwortete am 2026-10-17 fuer #107698656 kurz darauf mit dem Ledger. Absenz wird
        // deshalb mehrfach bei verschiedenen Knoten geholt, bevor sie als Absenz gilt.
        if (/not\s*found/i.test(message)) return { absent: true, error: message };
        return { error: message };
      }
      return { j };
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
    if (r.j) return r;
    last = r;
    if (!r.absent) return r; // Transportfehler: ein weiterer Knoten aendert nichts am Grund
    if (DELAY) await sleep(DELAY);
  }
  return last;
}
const isoMs = (x) => (typeof x === "string" && !Number.isNaN(Date.parse(x)) ? Date.parse(x) : null);
const num = (x) => (Number.isFinite(Number(x)) ? Number(x) : null);

const files = fs.existsSync(DIR) ? fs.readdirSync(DIR).filter((f) => f.endsWith(".json")).sort() : [];
if (!files.length) { console.log("keine Tagesdateien in " + DIR); process.exit(1); }

const problems = [];
const say = (...a) => { if (!QUIET) console.log(...a); };
let rows = 0, claims = 0, checked = 0, unreachable = 0;
let invNeed = 0, invMargin = 0, invLoop = 0, invTop = 0, invHash = 0, staleXc = 0;
let agree = 0, disagree = 0, openRows = 0, artifactMinSum = 0, incomplete = 0, openNotes = 0;
let unchecked = 0, singleSource = 0;
const openChecks = [];

for (const file of files) {
  const day = JSON.parse(fs.readFileSync(path.join(DIR, file), "utf8"));
  const stats = Array.isArray(day.ledgerStats) ? day.ledgerStats : [];
  const flagged = new Set((Array.isArray(day.incidents) ? day.incidents : []).map((i) => i.l));
  const claimRows = stats.filter((st) => Number.isFinite(st.top) && Number.isFinite(st.need) && st.top < st.need);
  const auditRows = ALL ? stats : claimRows;
  rows += stats.length;
  claims += claimRows.length;
  openRows += [...flagged].filter((l) => !stats.some((st) => st.l === l)).length;
  say("");
  say("== " + file + " | Forensik-Zeilen " + stats.length + " | Vote-Anspruch (top < need) " + claimRows.length
    + " | Vorfaelle ohne Forensik-Zeile " + [...flagged].filter((l) => !stats.some((st) => st.l === l)).length);

  // ---------- A) INVARIANZ ----------
  for (const st of stats) {
    const l = Number(st.l);
    const v = num(st.v) ?? 0, need = num(st.need), top = num(st.top) ?? 0, mg = num(st.mg);
    const c = st.c ?? {};
    const absent = (num(c.missed) ?? 0) + (num(c.noQuorum) ?? 0);
    const recorded = num(st.mm);
    const members = recorded ?? v + absent;
    if (recorded !== null && recorded !== v + absent) {
      invLoop += 1; problems.push(file + " #" + l + ": Rekorder-Identitaet " + v + " + " + absent + " != mm " + recorded);
    }
    if (members > 0 && need !== null && need !== Math.ceil(members * TRACE_DEFAULTS.quorumFrac)) {
      invNeed += 1;
      problems.push(file + " #" + l + ": need " + need + " != ceil(" + members + " * " + TRACE_DEFAULTS.quorumFrac + ")");
    }
    if (need !== null && mg !== null && mg !== top - need) {
      invMargin += 1; problems.push(file + " #" + l + ": mg " + mg + " != top " + top + " - need " + need);
    }
    if (top > v) { invTop += 1; problems.push(file + " #" + l + ": top " + top + " > gesehene Mitglieder-Stimmen " + v); }
    if (st.cl === true && !(typeof st.ch === "string" && HEX64.test(st.ch.toUpperCase()))) {
      invHash += 1; problems.push(file + " #" + l + ": cl=true ohne 64-Hex-Hash");
    }
    const b = captureBound(st);
    if (b && b.closed && Number.isFinite(b.captureArtifactMin)) {
      artifactMinSum += b.captureArtifactMin;
      if (b.captureComplete === false) incomplete += 1;
      if (top < need) {
        say("   #" + l + "  gesehen " + top + "/" + need + "  ohne-Vote-Flags " + b.absentCount
          + "  dUNL " + b.members + " (" + b.membersBasis + ")  echt hoechstens " + b.genuineAbsentMax
          + "  Erfassungs-Luecke mind. " + b.captureArtifactMin);
      }
    }
  }

  // ---------- B) DECKUNG ----------
  let done = 0;
  for (const st of auditRows) {
    if (done >= MAX_PER_DAY) { say("   --max erreicht: " + (auditRows.length - done) + " Zeilen ungeprueft"); break; }
    done += 1; checked += 1;
    const index = Number(st.l);
    const a = await scanLedger(index);
    if (DELAY) await sleep(DELAY);
    const b = await netLedger(index);
    if (DELAY) await sleep(DELAY);
    const rb = b.j && b.j.result ? b.j.result.ledger : null;
    // Beide Quellen werden unabhaengig gehalten. Eine erreichbare Quelle prueft die Zeile auch
    // dann, wenn die andere ablehnt - sonst verschenkt der Lauf Deckung, die er haben koennte.
    if (!a.j && !rb) {
      unreachable += 1;
      if (a.absent === true && b.absent === true && st.cl === true) {
        disagree += 1;
        problems.push(file + " #" + index + ": cl=true, aber beide Quellen melden den Ledger nicht (" + a.error + " / " + b.error + ")");
      } else {
        unchecked += 1;
        openChecks.push(file + " #" + index + ": xrpscan " + (a.error || "keine Antwort") + " / xrplcluster " + (b.error || "kein ledger-Objekt"));
      }
      continue;
    }
    if (!a.j || !rb) singleSource += 1;
    const ha = a.j && typeof a.j.ledger_hash === "string" ? a.j.ledger_hash.toUpperCase() : null;
    const hb = typeof rb.ledger_hash === "string" ? rb.ledger_hash.toUpperCase() : null;
    const ownHash = typeof st.ch === "string" ? st.ch.toUpperCase() : null;
    const tScan = a.j ? isoMs(a.j.close_time_human) : null, tNet = isoMs(rb.close_time_iso), ownT = num(st.t);
    const txScan = a.j ? num(a.j.tx_count) : null, ownTx = num(st.tx);
    const bad = [];
    // Die Facetten einzeln, weil 'nicht erfasst' eine dritte Antwort ist. Ein xc-Feld mit null
    // heisst 'diese Quelle hatte in dem Moment keinen Wert' - das ist keine behauptete Abweichung
    // und darf auch nicht als eine gezählt werden (am 2026-10-17 an #107699073 gesehen: xrpscan
    // nannte keine Tx-Zahl, die live-Pruefung findet sie deckungsgleich).
    const live = {
      hash: ownHash && ha && hb ? (ownHash === ha && ownHash === hb ? true : false) : null,
      tx: ownTx !== null && txScan !== null ? (ownTx === txScan ? true : false) : null,
      t: ownT !== null && tScan !== null ? (ownT === tScan ? true : false) : null,
    };
    if (a.j && Number(a.j.ledger_index) !== index) bad.push("Index xrpscan " + a.j.ledger_index);
    if (Number(rb.ledger_index) !== index) bad.push("Index Netz " + rb.ledger_index);
    if (a.j && (!ha || !HEX64.test(ha))) bad.push("Hash xrpscan ungueltig");
    if (!hb || !HEX64.test(hb)) bad.push("Hash Netz ungueltig");
    if (ha && hb && ha !== hb) bad.push("Quellen uneins " + ha.slice(0, 12) + " / " + hb.slice(0, 12));
    if (ownHash && ha && ownHash !== ha) bad.push("eigener Hash " + ownHash.slice(0, 12) + " != xrpscan " + ha.slice(0, 12));
    if (ownHash && hb && ownHash !== hb) bad.push("eigener Hash " + ownHash.slice(0, 12) + " != Netz " + hb.slice(0, 12));
    if (ownTx !== null && txScan !== null && ownTx !== txScan) bad.push("Tx eigen " + ownTx + " != xrpscan " + txScan);
    if (ownT !== null && tScan !== null && ownT !== tScan) bad.push("Close eigen " + ownT + " != xrpscan " + tScan);
    if (tScan !== null && tNet !== null && tScan !== tNet) bad.push("Close xrpscan " + tScan + " != Netz " + tNet);
    // Ein gespeicherter Vermerk wird facettenweise gegen die live-Pruefung gehalten. Ein
    // Vermerk, der einer Facette einen Wert zuschreibt und die live-Pruefung das Gegenteil zeigt,
    // ist eine Behauptung, die nicht mehr steht. Ein Vermerk mit null ist offen, nicht falsch.
    const NOTE_KEY = { hashAgree: "hash", tx: "tx", t: "t" };
    if (st.xc) {
      for (const [key, facet] of Object.entries(NOTE_KEY)) {
        const note = st.xc[key], now = live[facet];
        if (typeof note !== "boolean") { if (now !== null) openNotes += 1; continue; }
        if (now === null) continue;
        if (note !== now) {
          staleXc += 1;
          problems.push(file + " #" + index + ": xc." + key + " sagt " + note + ", live-Pruefung zeigt " + now);
        }
      }
    }
    if (bad.length) { disagree += 1; problems.push(file + " #" + index + ": " + bad.join(" | ")); }
    else agree += 1;
    say("   #" + index + "  " + (bad.length ? "ABWEICHUNG: " + bad.join(" | ") : "deckungsgleich")
      + "  hash " + (ha || "-").slice(0, 12) + "  tx " + (txScan ?? "-") + "  close "
      + (tScan !== null ? new Date(tScan).toISOString() : "-"));
  }
}

console.log("");
console.log("BEFUND");
console.log("  Forensik-Zeilen gesamt:", rows, "| davon Vote-Anspruch (top < need):", claims);
console.log("  Invariantzen: need", invNeed, "| Marge", invMargin, "| Rekorder-Identitaet", invLoop,
  "| top > Stimmen", invTop, "| Schliess-Hash", invHash);
console.log("  Quellen-Deckung (xrpscan + xrplcluster, Hash/Tx/Close):", agree, "deckungsgleich,", disagree, "abweichend,",
  checked, "geprueft,", singleSource, "einquellig gedeckt,", unchecked, "ungeprueft (Quelle nicht erreichbar)");
console.log("  Veraltete Gegenpruef-Vermerke (xc):", staleXc, "| offene Vermerke, die live jetzt beantwortet sind:", openNotes);
console.log("  Vorfaelle ohne Forensik-Zeile (Frage offen, nicht beantwortet):", openRows);
console.log("  Nachrechenbare Erfassungs-Luecke ueber alle geschlossenen Zeilen:", artifactMinSum, "Knoten-Ledger");
console.log("  Zeilen mit gesehenen Stimmen unter Ziel:", incomplete);
if (problems.length) {
  console.log("");
  console.log("ABWEICHUNGEN:");
  for (const p of problems) console.log("  - " + p);
  process.exit(1);
}
if (openChecks.length) {
  console.log("");
  console.log("OFFENE PRUEFUNGEN (kein Befund und keine Entlastung - diese Zeilen blieben ungeprueft):");
  for (const p of openChecks) console.log("  - " + p);
  process.exit(2);
}
console.log("");
console.log("Keine Abweichung: jede gepruefte Zahl deckt sich mit ihrer Quelle und mit sich selbst.");
