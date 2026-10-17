// scripts/audit-tx-shape.mjs
//
// AEussere Gegenprobe der Tx-Form: jeder Zaehler in 'sh' (die Messgroesse hinter jeder
// Drainer-Signatur) wird aus einer anderen Quelle neu gerechnet und mit dem Wert verglichen,
// der in der Tagesdatei steht. Ohne diese Ebene ist die Drainer-Auswertung eine Zahl aus einem
// einzigen Mithoerer - sie ist dann nicht nachvollziehbar, nur geglaubt.
//
// Was vergleichbar ist und was nicht, wird benannt: die Quell-Liste von api.xrpscan.com fuehrt
// die Innen-Transaktionen eines Batch nicht. 'bt' und 'bi' bleiben daher einseitig gemessen und
// werden als solche ausgegeben, nie als Deckung und nie als Widerspruch.
//
// Zweite Ebene: jede gespeicherte Signatur ('sev') wird gegen ihre eigene Form zurueckgerechnet.
// Eine Signatur, deren Belegwerte nicht die Zaehler derselben Zeile nennen, ist ein Fehler der
// Auswertung, nicht der Quelle.
//
// Lauf: TRACE_DATA_DIR=<ordner> node scripts/audit-tx-shape.mjs [--max=12]
import fs from "node:fs";
import path from "node:path";

const DIR = process.env.TRACE_DATA_DIR || "";
const MAX = Math.max(1, Number(process.env.TX_SHAPE_MAX || 0) || 12);
const DAY = /^\d{4}-\d{2}-\d{2}\.json$/;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// Die Zaehler, die beide Quellen gleich definieren. bt/bi fehlen bewusst: die Quell-Liste zeigt
// die Innen-Tx eines Batch nicht, also gibt es dafuer keine zweite Messung.
const COMPARE = ["n", "s", "d", "fo", "fd", "fa", "fl", "ac", "oc", "nf", "fx", "fm", "fs"];
const ONE_SIDED = ["bt", "bi"];
const median = (a) => {
  const v = (Array.isArray(a) ? a : []).filter((x) => Number.isFinite(x));
  if (!v.length) return 0;
  const b = [...v].sort((x, y) => x - y);
  const m = b.length >> 1;
  return b.length % 2 ? b[m] : (b[m - 1] + b[m]) / 2;
};

// Die Form wird hier absichtlich selbst gerechnet - nicht ueber lib/tx-forensics.mjs. Sonst
// bestaetigt sich dieselbe Implementierung selbst, statt dass eine zweite Quelle spricht.
function recompute(list) {
  const senders = new Set(), destinations = new Set();
  const byAccount = new Map(), byAccountDest = new Map(), byType = new Map(), fees = [];
  let failed = 0;
  for (const t of list) {
    const type = t.TransactionType ?? t.tx_json?.TransactionType ?? null;
    if (!type) continue;
    const account = typeof t.Account === "string" ? t.Account : null;
    const destination = typeof t.Destination === "string" ? t.Destination : null;
    const result = t.meta?.TransactionResult ?? t.meta?.transaction_state ?? null;
    const raw = t.Fee ?? 0;
    const fee = Number(typeof raw === "string" ? raw.replace(/[^\d.]/g, "") : raw);
    byType.set(type, (byType.get(type) ?? 0) + 1);
    if (account) {
      senders.add(account);
      byAccount.set(account, (byAccount.get(account) ?? 0) + 1);
      if (destination) {
        const set = byAccountDest.get(account) ?? new Set();
        set.add(destination);
        byAccountDest.set(account, set);
      }
    }
    if (destination) destinations.add(destination);
    if (Number.isFinite(fee) && fee > 0) fees.push(fee);
    if (result && result !== "tesSUCCESS") failed += 1;
  }
  let fo = 0, fd = 0, fa = 0;
  for (const [acc, n] of byAccount) {
    const dests = byAccountDest.get(acc)?.size ?? 0;
    if (n > fo) fo = n;
    if (dests > fd) { fd = dests; fa = n; }
  }
  const countOf = (...ts) => ts.reduce((a, t) => a + (byType.get(t) ?? 0), 0);
  return {
    n: list.length, s: senders.size, d: destinations.size, fo, fd, fa, fl: failed,
    ac: countOf("AccountCreate", "AccountDelete"),
    oc: countOf("OfferCreate", "OfferCancel"),
    nf: countOf("NFTokenCreateOffer", "NFTokenMint", "NFTokenAcceptOffer", "NFTokenCancelOffer"),
    fx: countOf("EnableAmendment", "SetFee", "UNLModify", "EnableFeature"),
    fm: fees.length ? Math.max(...fees) : 0, fs: median(fees),
  };
}

// Die Signatur muss die Zaehler ihrer eigenen Zeile nennen. Die Basis (median/baseline) wohnt im
// Rekorder und ist aus der Tagesdatei nicht rekonstruierbar - sie wird ausgegeben, nicht geprueft.
const SIGNATURE_FIELDS = {
  "drainer-fanout": { fanoutAccounts: "fd", fanoutTxs: "fa", ledgerTx: "n" },
  "sender-burst": { accountTx: "fo", ledgerTx: "n" },
  "failure-spike": { failed: "fl", ledgerTx: "n" },
  "batch-amplify": { batchTx: "bt", innerTx: "bi" },
  "fee-spike": { maxFee: "fm", medianFee: "fs" },
  "feature-change": { featureTx: "fx" },
  "account-create-burst": { count: "ac" },
  "offer-flood": { count: "oc" },
  "nft-spam": { count: "nf" },
  "load-spike": { ledgerTx: "n" },
  "load-extreme": { ledgerTx: "n" },
};
function signatureMismatch(sev, sh) {
  const out = [];
  for (const [tag, ev] of Object.entries(sev ?? {})) {
    const map = SIGNATURE_FIELDS[tag] ?? (tag.startsWith("type-burst:") ? { count: null } : null);
    if (!map) { out.push(`${tag}: keine Rueckrechnung definiert`); continue; }
    for (const [field, shapeKey] of Object.entries(map)) {
      if (shapeKey === null) continue;
      if (Number(ev?.[field]) !== Number(sh?.[shapeKey])) {
        out.push(`${tag}.${field}=${ev?.[field]} nennt sh.${shapeKey}=${sh?.[shapeKey]}`);
      }
    }
  }
  return out;
}

const files = fs.existsSync(DIR) ? fs.readdirSync(DIR).filter((f) => DAY.test(f)).sort() : [];
if (!files.length) {
  console.log("Kein Trace-Speicher unter " + DIR + " - nichts zu pruefen. (TRACE_DATA_DIR setzen.)");
  process.exit(2);
}

const rows = [];
for (const f of files) {
  let doc;
  try { doc = JSON.parse(fs.readFileSync(path.join(DIR, f), "utf8")); } catch { continue; }
  for (const r of (Array.isArray(doc.ledgerStats) ? doc.ledgerStats : [])) {
    if (r && Number.isFinite(r.l) && r.sh && Number.isFinite(r.sh.n) && r.sh.n > 0) rows.push({ date: doc.date ?? f, row: r });
  }
}
if (!rows.length) {
  console.log("Keine Zeile mit Tx-Form in diesem Speicher - nichts zu pruefen.");
  process.exit(2);
}
/* Bestandsebene: jede gespeicherte Form gegen die Tx-Zahl ihres eigenen Ledgers. Keine Auswahl,
 * keine Fremdquelle, kein Netz. Eine Verdopplung ist hier eine Zahl, kein Verdacht.
 * Altbestand (Zeilen ohne dup-Feld, erfasst vor der Dedupe-Stufe) bleibt erhalten und wird
 * getrennt gefuehrt: die Abweichung ist echt, aber nachtraeglich nicht mehr aufloesbar. Sie darf
 * weder als laufender Fehler ausgegeben noch verschwiegen werden. */
const store = {
  ok: 0, explained: 0, noAuthority: 0, noHashRows: 0, dupDropped: 0,
  legacyOver: 0, legacyUnder: 0, legacyDelta: 0, badOver: 0, badUnder: 0,
};
const storeLines = [];
for (const { date, row } of rows) {
  const dup = Number.isFinite(row.sh.dup) ? row.sh.dup : null;   // null = Zeile vor der Dedupe-Stufe
  const legacy = dup === null;
  if (Number.isFinite(row.sh.nh) && row.sh.nh > 0) store.noHashRows += 1;
  if (dup) store.dupDropped += dup;
  if (!Number.isFinite(row.tx)) {
    store.noAuthority += 1;
    storeLines.push(`#${row.l} (${date}): keine Tx-Zahl gespeichert - die Form hat keine Autoritaet`);
    continue;
  }
  const delta = row.sh.n - row.tx;
  if (delta === 0) { store.ok += 1; continue; }
  // Unter der Autoritaet ist erklaert, wenn die Zeile selbst ihre Erfassungsluecke nennt:
  // cg (Luecke in der Index-Folge), so (erster Ledger nach dem Abo) oder pg != l - 1.
  const explained = row.cg === true || row.so === true || (Number.isFinite(row.pg) && row.pg !== row.l - 1);
  if (delta < 0 && explained) { store.explained += 1; continue; }
  if (delta > 0) { if (legacy) store.legacyOver += 1; else store.badOver += 1; }
  else { if (legacy) store.legacyUnder += 1; else store.badUnder += 1; }
  if (legacy) store.legacyDelta += delta;
  if (storeLines.length < 60) {
    storeLines.push(`#${row.l} (${date}) ${legacy ? "Altbestand" : "Dedupe-Stufe"}: Form ${row.sh.n} gegen Autoritaet ${row.tx} (${delta > 0 ? "+" : ""}${delta}${explained ? ", Erfassungs-Luecke cg/so/pg" : ", unerklaert"})`);
  }
}
console.log("TX-FORM-GEGENPROBE");
console.log("BESTAND (jede Form-Zeile gegen die Tx-Zahl ihres eigenen Ledgers, ohne Fremdquelle):");
console.log("  Form-Zeilen im Speicher:", rows.length);
console.log("  deckungsgleich:", store.ok, "| unter der Autoritaet, erklaert durch cg/so/pg:", store.explained);
console.log("  ohne gespeicherte Autoritaet:", store.noAuthority);
console.log("  Altbestand vor der Dedupe-Stufe (dup-Feld fehlt):", store.legacyOver, "ueber der Autoritaet,",
  store.legacyUnder, "darunter, Netto-Tx-Differenz", store.legacyDelta);
console.log("  Abweichung nach der Dedupe-Stufe:", store.badOver, "ueber der Autoritaet,", store.badUnder, "unerklaert darunter");
console.log("  verworfene Doppel-Relays aller Zeilen mit dup-Feld:", store.dupDropped);
console.log("  Zeilen mit Tx ohne pruefbaren Hash (nh):", store.noHashRows);
console.log("");

const picked = rows.slice(-MAX);
console.log("GEGENPROBE GEGEN DIE FREMDQUELLE (die neuesten Zeilen):");
console.log("  Zeilen mit Form:", rows.length, "| geprueft (die neuesten):", picked.length);
console.log("  Quelle: api.xrpscan.com/api/v1/ledger/<index>/transactions");
console.log("  Vergleichbare Zaehler:", COMPARE.join(","));
console.log("  Einseitig gemessen (Quelle zeigt Batch-Innen-Tx nicht):", ONE_SIDED.join(","));
console.log("");

let agreed = 0, deviations = 0, unreadable = 0, singleSource = 0, sigBad = 0, sigOk = 0, legacySource = 0;
const details = [];
const legacyDetails = [];
for (const { date, row } of picked) {
  let list;
  try {
    const res = await fetch(`https://api.xrpscan.com/api/v1/ledger/${row.l}/transactions`);
    if (res.status !== 200) { unreadable += 1; details.push(`#${row.l} (${date}): Quelle HTTP ${res.status}`); await sleep(700); continue; }
    list = await res.json();
  } catch (e) { unreadable += 1; details.push(`#${row.l} (${date}): Quelle nicht erreichbar (${e.message})`); await sleep(700); continue; }
  if (!Array.isArray(list)) { unreadable += 1; details.push(`#${row.l} (${date}): keine Liste von der Quelle`); await sleep(700); continue; }
  const mine = recompute(list);
  const diff = COMPARE.filter((k) => Number(mine[k]) !== Number(row.sh[k]));
  const txRow = Number.isFinite(row.tx) && Number(row.tx) !== mine.n ? [`row.tx=${row.tx} gegen n=${mine.n}`] : [];
  const sig = signatureMismatch(row.sev, row.sh);
  if (sig.length) sigBad += 1; else if (Object.keys(row.sev ?? {}).length) sigOk += 1;
  // Ein reiner 'n'-Abstand auf einer Zeile ohne dup-Feld, dessen eigene Autoritaet mit der
  // Fremdquelle deckt, ist die Doppelrelay-Luecke des Altbestands: benannt, aber kein Fehler
  // der laufenden Engine. Ohne diese Trennung waere der Audit fuer alle Ewigkeit rot und
  // damit wertlos - und der eigentliche Fehler waere nicht mehr sichtbar.
  const legacyDedupe = diff.length === 1 && diff[0] === "n"
    && !Number.isFinite(row.sh.dup) && Number(row.tx) === mine.n;
  if (!diff.length && !txRow.length && !sig.length) { agreed += 1; }
  else if (legacyDedupe) {
    legacySource += 1;
    legacyDetails.push(`#${row.l} (${date}): Altbestand - Form ${row.sh.n} gegen Quelle ${mine.n}; die gespeicherte Autoritaet row.tx=${row.tx} deckt sich mit der Quelle, die Form wurde vor der Dedupe-Stufe aus Nachrichten gezaehlt`);
  }
  else {
    deviations += 1;
    if (diff.length) {
      singleSource += 1;
      details.push(`#${row.l} (${date}): Form-Abweichung ` + diff.map((k) => `${k} engine=${row.sh[k]} quelle=${mine[k]}`).join(" "));
    }
    if (txRow.length) details.push(`#${row.l} (${date}): Tx-Zahl der Zeile weicht ab: ${txRow.join(", ")}`);
    if (sig.length) details.push(`#${row.l} (${date}): Signatur-Widerspruch: ${sig.join(" | ")}`);
  }
  await sleep(700);
}

console.log("BEFUND");
console.log("  deckungsgleich (13 vergleichbare Zaehler + Zeilen-Tx + Signaturen):", agreed);
console.log("  Zeilen mit Abweichung:", deviations, "| davon Form-Abweichung gegen die Quelle:", singleSource);
console.log("  Altbestand gegen die Quelle (nur 'n', Autoritaet deckt die Quelle):", legacySource);
console.log("  Signaturen gegen eigene Form nachgerechnet:", sigOk, "in Ordnung,", sigBad, "widerspruechlich");
console.log("  ungeprueft (Quelle nicht erreichbar oder ohne Liste):", unreadable);
console.log("  'bt'/'bi' (Batch-Innen-Tx) bleiben einseitig: nur der Mithoerer sieht sie, die");
console.log("  Quell-Liste fuehrt sie nicht. Belegt ist diese Ebene nur durch ihre eigenen Tests");
console.log("  (lib/tx-forensics.test.mjs, Rohformat 'RawTransactions' und 'InnerTransactions').");
if (storeLines.length) {
  console.log("");
  console.log("BESTAND-ABWEICHUNGEN (Altbestand ist als Altbestand benannt, kein laufender Fehler):");
  for (const line of storeLines.slice(0, 30)) console.log("  - " + line);
  if (storeLines.length > 30) console.log(`  - ... weitere ${storeLines.length - 30} Zeilen`);
}
if (details.length) {
  console.log("");
  console.log("ABWEICHUNGEN GEGEN DIE FREMDQUELLE:");
  for (const line of details.slice(0, 30)) console.log("  - " + line);
  if (details.length > 30) console.log(`  - ... weitere ${details.length - 30} Zeilen`);
}
if (legacyDetails.length) {
  console.log("");
  console.log("ALTBESTAND GEGEN DIE FREMDQUELLE (Form aus Nachrichten, nicht Transaktionen; die gespeicherte Autoritaet deckt sich mit der Quelle):");
  for (const line of legacyDetails.slice(0, 20)) console.log("  - " + line);
}
if (store.badOver > 0 || store.badUnder > 0) {
  console.log("");
  console.log(`FEHLER NACH DER DEDUPE-STUFE: ${store.badOver} Form(en) ueber der Tx-Zahl ihres Ledgers, ${store.badUnder} unerklaert darunter. Eine Form darf die Autoritaet ihres Ledgers nicht uebersteigen - das ist keine Rundung.`);
  process.exit(1);
}
if (details.length) process.exit(1);
if (unreadable === picked.length) process.exit(2);
console.log("");
console.log("Kein Fehler: jede Form seit der Dedupe-Stufe deckt die Tx-Zahl ihres Ledgers, und jeder gepruefte Form-Zaehler ist dieselbe Zahl wie in der Fremdquelle.");
process.exit(0);
