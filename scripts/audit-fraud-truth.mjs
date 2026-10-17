// scripts/audit-fraud-truth.mjs
//
// Gegenprobe der GELDSEITE der Betrugserkennung: jeder Betrag, den die Engine einer
// Transaktion zuschreibt (lib/cluster.mjs Kante, lib/detector.mjs Aggregation), wird
// gegen eine zweite Quelle nachgerechnet. Wie in scripts/audit-tx-shape.mjs gilt:
// die Autoritaet wird HIER selbst gerechnet, nicht ueber lib/tx-values.mjs - sonst
// bestaetigt sich dieselbe Implementierung selbst.
//
// Drei Defekt-Klassen, die 2026-10-17 live gefunden wurden (alle belegt):
//  1) Deckel statt Geld: tx.Amount ist bei Zahlungen mit Pfaden/Fremdwaehrung der
//     DeliverMax-Deckel. Hash F4134FC4612BC7114191B65328AA5AF5FA08AB45016F7B621103E1BABE79E98E
//     Amount 100000000000000000, deliveriert 34 (Faktor 3e15).
//  2) Fehlgeschlagene Zahlung als Geld: tecPATH_DRY
//     2583F45F4C0A4DCFE3A81F292D011F767587B7CE28EB5BA0D39030593FC7C9B1 und
//     4969980B0C2345FFEE3F72EED7FE5A6558B94110C88E3DF706F95626289A2CCD, je Amount
//     100000000000000, bewegen kein Geld.
//  3) Angebots-Preis als Geld: NFTokenCreateOffer/OfferCreate nennen einen Preis;
//     beim CREATE fließt kein Geld (lib/cluster.mjs sagt das selbst).
//
// Autoritaets-Hierarchie (unabhaengig vom Engine-Code):
//  A1 XRP-Delta des Ziels aus den AffectedNodes (eigene Implementierung unten)
//  A2 delivered_amount des tx-Befehls von ANDEREM Host als A1-Host
//  A3 sonst unverifizierbar - nie eine Schaetzung
//
// Lauf:
//   node scripts/audit-fraud-truth.mjs                 Phase A (Fixtures) + Phase B (live)
//   node scripts/audit-fraud-truth.mjs --fixtures      nur Phase A, offline
//   node scripts/audit-fraud-truth.mjs --ledgers=24    Umfang von Phase B
//   node scripts/audit-fraud-truth.mjs --flow          Phase C: deployte flow-state-Kanten
// Exit 0 keine bestaetigte Abweichung | 1 bestaetigte Abweichung | 2 Quellen unerreichbar
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { metaOf, movedXrpOf } from "../lib/tx-values.mjs";

const ROOT = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const FIXTURE = path.join(ROOT, "lib", "fixtures", "live-tx-values.json");
const ENGINE_HOST = "https://xrplcluster.com";
const AUTH_HOSTS = ["https://s2.ripple.com", "https://xrplcluster.com"];
const PRICE_TYPES = new Set(["NFTokenCreateOffer", "OfferCreate"]);
const numArg = (name, dflt) => { const a = process.argv.find((x) => x.startsWith(name)); const v = Number(a?.slice(name.length)); return Number.isFinite(v) && v > 0 ? v : dflt; };
const LEDGERS = numArg("--ledgers=", 24);
const MAX_AUTH_CALLS = numArg("--auth=", 150);
const FLOW_URL = process.env.FLOW_STATE_URL || "https://honeypot-xrpl.vercel.app/api/flow-state";

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
let unreachable = 0;
// tooBusy ist ein Kontingent, kein Defekt: zurueckhalten und erneut fragen, nie
// ein Ledger-Stueck still ueberspringen (sonst ist die Stichprobe verzerrt).
async function rpc(host, method, params) {
  let last = null;
  for (let attempt = 0; attempt < 4; attempt++) {
    const res = await fetch(host, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ method, params: [params] }) });
    const j = await res.json();
    if (j?.result && !j.result.error) return j.result;
    last = JSON.stringify(j).slice(0, 160);
    if (!/tooBusy|rate limit|notFound|slowAPI/i.test(last)) break;
    await sleep(2500 * (attempt + 1));
  }
  throw new Error(`rpc ${method}: ${last}`);
}
async function tryHosts(method, params) {
  for (const host of AUTH_HOSTS) { try { return { host, result: await rpc(host, method, params) }; } catch (e) { unreachable += 1; } }
  return null;
}

// ---------- Autoritaet, hier selbst gerechnet (Bewusst nicht lib/tx-values.mjs) ----------
function drops(v) {
  if (typeof v !== "string" || v === "") return null;
  const n = Number(v);
  return Number.isFinite(n) ? n : null;
}
function engineResult(meta) { return meta?.TransactionResult ?? meta?.transaction_state ?? null; }
function delivered(meta) { return meta?.delivered_amount ?? meta?.DeliveredAmount ?? null; }
// XRP-Delta eines Kontos aus AffectedNodes: genau ein AccountRoot mit Vor- und
// Nachwert; CreatedNode/DeletedNode und IOU-Salden liefern bewusst null.
function deltaOf(meta, account) {
  if (typeof account !== "string" || !account) return null;
  let hits = 0, delta = 0;
  for (const w of Array.isArray(meta?.AffectedNodes) ? meta.AffectedNodes : []) {
    const n = w?.ModifiedNode ?? w?.CreatedNode ?? w?.DeletedNode;
    if (!n || n.LedgerEntryType !== "AccountRoot") continue;
    if (n.FinalFields?.Account !== account) continue;
    const b = drops(n.PreviousFields?.Balance), a = drops(n.FinalFields?.Balance);
    if (b == null || a == null) continue;
    hits += 1; delta += a - b;
  }
  return hits === 1 ? delta : null;
}
// Die alte (fehlerhafte) Lesart, nur als Vergleichsgroesse: Amount/DeliverMax blind.
// Fremdwaehrungs-Anspruch: Amount/DeliverMax oder delivered_amount als IOU-Objekt.
// Solche Zahlungen bewegen kein XRP - ein Engine-Betrag dazu waere erfunden.
function isIou(v) {
  return Boolean(v && typeof v === "object" && v.currency && v.issuer);
}

// Die LESART VOR DEM FIX: Amount/DeliverMax blind, ohne Engine-Ergebnis, ohne
// Angebots-Ausnahme. Nur als Vergleichsgroesse, damit der Fix beziffert ist.
function legacyAmount(tx) {
  return drops(tx?.Amount ?? tx?.DeliverMax ?? null);
}

function judge({ tx, meta, engine, authorityMeta, authorityDelivered }) {
  const result = engineResult(meta);
  const knownFailed = result != null && result !== "tesSUCCESS";
  if (PRICE_TYPES.has(tx?.TransactionType)) {
    if (engine == null) return { label: "ok-angebot", authority: null };
    return { label: "DEFEKT-angebot-als-geld", authority: 0 };
  }
  if (knownFailed) {
    if (engine == null) return { label: "ok-fehlgeschlagen", authority: 0 };
    return { label: "DEFEKT-fehlgeschlagen-als-geld", authority: 0 };
  }
  // A1 gilt nur, wenn die Gebuehr den Ziel-Knoten nicht selbst trifft. Bei
  // Selbstzahlungen (und wenn der Ziel-Kontoinhaber die Gebuehr zahlt) ist das
  // Delta 'deliveriert - Fee' und darf nicht als Betrag-Autoritaet gelten -
  // sonst meldet die Gegenprobe einen Deckel, wo keiner ist.
  const feePayer = typeof tx?.FeePayer === "string" ? tx.FeePayer : tx?.Account;
  const contaminated = feePayer != null && feePayer === tx?.Destination;
  const delta = contaminated ? null : deltaOf(meta, tx?.Destination);
  let authority = delta != null && delta > 0 ? delta : null;
  let source = "A1 Delta";
  if (authority == null) {
    const d = delivered(authorityMeta) ?? delivered(meta);
    const dd = typeof d === "string" ? drops(d) : null;
    if (dd != null) { authority = dd; source = "A2 delivered_amount"; }
  }
  if (isIou(tx?.Amount ?? tx?.DeliverMax) || isIou(meta?.delivered_amount)) {
    if (engine == null) return { label: "ok-fremdwaehrung", authority: null };
    return { label: "DEFEKT-fremdwaehrung-als-xrp", authority: 0 };
  }
  if (authority == null) return { label: "unverifizierbar", authority: null };
  if (engine == null) return { label: "DEFEKT-geld-verloren", authority, source };
  if (engine !== authority) {
    return { label: engine > authority ? "DEFEKT-deckel" : "DEFEKT-falsche-zahl", authority, source };
  }
  return { label: "exakt", authority, source };
}

const tally = new Map();
const defects = [];
function note(label, hash, extra) {
  tally.set(label, (tally.get(label) ?? 0) + 1);
  if (label.startsWith("DEFEKT")) defects.push({ label, hash, ...extra });
}

// ---------------- Phase A: Fixtures (offline, echte Live-Daten) ----------------
function phaseA() {
  const fx = JSON.parse(fs.readFileSync(FIXTURE, "utf8"));
  console.log("== Phase A: Fixtures aus " + fx.source);
  let confirmed = 0, unver = 0;
  for (const rec of fx.records) {
    const tx = rec.entry ?? {};
    const meta = metaOf(rec.entry);
    const engine = movedXrpOf(tx, meta);
    const legacy = legacyAmount(tx);
    const j = judge({ tx, meta, engine, authorityMeta: rec.authority?.meta, authorityDelivered: null });
    note(j.label, rec.hash, { ledger: rec.ledgerIndex, engine, legacy });
    const oldText = legacy == null ? "kein Geld" : legacy.toLocaleString("en-US");
    const newText = engine == null ? "kein Geld" : engine.toLocaleString("en-US");
    const authText = j.authority == null ? "unverifizierbar" : j.authority.toLocaleString("en-US") + " (" + (j.source ?? "?") + ")";
    console.log(`  ${rec.label.padEnd(12)} alt ${oldText.padStart(21)}  engine ${newText.padStart(14)}  Autoritaet ${authText.padStart(28)}  -> ${j.label}`);
    if (j.label === "exakt") confirmed += 1;
    if (j.label === "unverifizierbar") unver += 1;
  }
  // Regel-3-Pfad ohne delivered_amount: dieselbe Entry, Meta ohne delivered-Feld.
  const ceil = fx.records.find((r) => r.label === "ceiling");
  if (ceil) {
    const meta = { ...metaOf(ceil.entry) };
    delete meta.delivered_amount; delete meta.DeliveredAmount;
    const derived = movedXrpOf(ceil.entry, meta);
    const auth = deltaOf(ceil.authority.meta, ceil.entry.Destination);
    const ok = derived === auth && derived === 34;
    console.log(`  delta-Pfad   ohne delivered_amount: engine ${derived} gegen Delta ${auth} (Autoritaet delivered_amount 34) -> ${ok ? "exakt" : "DEFEKT-abgeleitet"}`);
    if (!ok) defects.push({ label: "DEFEKT-abgeleitet", hash: ceil.hash });
    note(ok ? "exakt" : "DEFEKT-abgeleitet", ceil.hash, {});
  }
  console.log(`  Phase A: ${confirmed} exakt bestaetigt, ${unver} unverifizierbar`);
}

// ---------------- Phase B: aktuelle Ledger, Engine gegen Delta + tx-Autoritaet ----------------
async function phaseB() {
  const head = await rpc(ENGINE_HOST, "ledger", {});
  const last = Number(head.ledger?.ledger_index ?? head.ledger_index);
  if (!Number.isFinite(last)) throw new Error("kein validated ledger_index");
  console.log(`== Phase B: ${LEDGERS} Ledger ab ${last} (Engine-Eingang ${ENGINE_HOST}, Autoritaet auch ${AUTH_HOSTS[0]})`);
  let payments = 0, authCalls = 0, checked = 0, sumLegacy = 0, sumEngine = 0, sumAuthority = 0;
  const needAuth = [];
  // Faelle, in denen die blinde Lesart einen Deckel genannt haette: genau die
  // Klasse, die 100 Mrd XRP in einen Cluster geschrieben hat.
  const corrected = [];
  for (let i = 0; i < LEDGERS; i++) {
    const li = last - i;
    const lg = await rpc(ENGINE_HOST, "ledger", { ledger_index: li, expand: true, transactions: true });
    for (const entry of lg.ledger?.transactions ?? []) {
      const tx = entry.tx_json ?? entry;
      if (!tx?.TransactionType) continue;
      const meta = entry.metaData ?? entry.meta ?? null;
      const engine = movedXrpOf(tx, meta);
      const legacy = legacyAmount(tx);
      const isMoney = tx.TransactionType === "Payment" || PRICE_TYPES.has(tx.TransactionType);
      if (!isMoney) continue;
      if (tx.TransactionType === "Payment") payments += 1;
      // Summen entstehen ausschliesslich ueber die geprueften Kanten: sonst
      // stuerbe ein unverifizierter Betrag still in eine Vergleichssumme.
      const j = judge({ tx, meta, engine, authorityMeta: null });
      if (j.label === "unverifizierbar" || j.label.startsWith("DEFEKT")) {
        if (needAuth.length < MAX_AUTH_CALLS) needAuth.push({ entry, tx, meta, engine, legacy });
        else note("budget-offen", entry.hash, { ledger: li, engine, legacy });
        continue;
      }
      if (tx.TransactionType === "Payment" && legacy != null && engine != null && legacy !== engine) {
        corrected.push({ ledger: li, hash: entry.hash, legacy, engine, authority: j.authority, source: j.source });
      }
      note(j.label, entry.hash, { ledger: li, engine, legacy });
      if (j.authority != null) {
        checked += 1;
        sumAuthority += j.authority;
        sumEngine += engine ?? 0;
        sumLegacy += legacy ?? 0;
      }
    }
    await sleep(1200);
  }
  for (const item of needAuth) {
    const got = await tryHosts("tx", { transaction: item.entry.hash, binary: false });
    authCalls += 1;
    await sleep(700);
    if (!got) { note("quelle-fehlt", item.entry.hash, {}); continue; }
    const j = judge({ tx: item.tx, meta: item.meta, engine: item.engine, authorityMeta: got.result?.meta });
    note(j.label, item.entry.hash, { ledger: item.entry.ledger_index ?? item.tx.ledger_index, engine: item.engine, legacy: item.legacy, host: got.host, authority: j.authority, source: j.source });
    if (j.authority != null) {
      checked += 1;
      sumAuthority += j.authority;
      sumEngine += item.engine ?? 0;
      sumLegacy += item.legacy ?? 0;
      if (item.tx.TransactionType === "Payment" && item.legacy != null && item.engine != null && item.legacy !== item.engine) {
        corrected.push({ ledger: item.entry.ledger_index, hash: item.entry.hash, legacy: item.legacy, engine: item.engine, authority: j.authority, source: j.source });
      }
    }
  }
  for (const c of corrected.slice(0, 8)) {
    console.log(`  Deckel korrigiert ledger ${c.ledger} ${c.hash.slice(0, 12)}: blind ${c.legacy.toLocaleString("en-US")} -> nachgewiesen ${c.engine.toLocaleString("en-US")} (Autoritaet ${c.authority ?? "-"} ${c.source ?? ""})`);
  }
  const fmt = (n) => n.toLocaleString("en-US", { maximumFractionDigits: 3 }) + " Drops";
  console.log(`  Pruefung: ${checked} gepruefte Geld-Kanten, ${payments} Zahlungen, ${authCalls} tx-Autoritaeten von anderem Host`);
  console.log(`  Summen ueber dieselben geprueften Kanten: alte Lesart ${fmt(sumLegacy)} | Engine ${fmt(sumEngine)} | Autoritaet ${fmt(sumAuthority)}`);
  if (sumAuthority > 0 && sumEngine > sumAuthority * 1.000001) {
    defects.push({ label: "DEFEKT-summen", hash: "phase-b", engine: sumEngine, authority: sumAuthority });
  }
}

// ---------------- Phase C: deployte flow-state-Kanten gegen tx-Autoritaet ----------------
async function phaseC() {
  console.log("== Phase C: deployte Kanten " + FLOW_URL);
  const res = await fetch(FLOW_URL);
  const doc = await res.json();
  const clusters = Array.isArray(doc.clusters) ? doc.clusters : Array.isArray(doc?.state?.clusters) ? doc.state.clusters : [];
  if (!clusters.length) { console.log("  keine Cluster in der Antwort (Struktur benennen, nicht raten)"); return; }
  let edges = 0, calls = 0;
  for (const cluster of clusters) {
    const list = Array.isArray(cluster.edges) ? cluster.edges : [];
    let sumEngine = 0, sumAuth = 0, unver = 0, ok = 0;
    for (const edge of list) {
      edges += 1;
      if (typeof edge.amountDrops === "number") sumEngine += edge.amountDrops;
      if (calls >= MAX_AUTH_CALLS) { unver += 1; continue; }
      if (!edge.txHash) { unver += 1; continue; }
      const got = await tryHosts("tx", { transaction: edge.txHash, binary: false });
      calls += 1;
      if (!got) { unver += 1; continue; }
      const a = got.result;
      const tx = a.tx_json ?? a;
      const meta = a.meta ?? null;
      const d = delivered(meta);
      const auth = typeof d === "string" ? drops(d) : null;
      const res2 = engineResult(meta);
      const isPrice = PRICE_TYPES.has(tx.TransactionType);
      const knownFailed = res2 != null && res2 !== "tesSUCCESS";
      const want = isPrice || knownFailed ? 0 : (auth != null ? auth : null);
      if (want == null) { unver += 1; continue; }
      const have = typeof edge.amountDrops === "number" ? edge.amountDrops : 0;
      sumAuth += want;
      if (have === want) ok += 1;
      else note(have > want ? "DEFEKT-deckel" : "DEFEKT-falsche-zahl", edge.txHash, { cluster: cluster.key ?? cluster.id, engine: have, authority: want });
    }
    const clusterLabel = cluster.key ?? cluster.id ?? "?";
    console.log(`  ${clusterLabel}: ${list.length} Kanten, ${ok} exakt, ${unver} unverifizierbar, Engine ${sumEngine.toLocaleString("en-US")} Drops, Autoritaet ${sumAuth.toLocaleString("en-US")} Drops`);
  }
  console.log(`  Phase C: ${edges} Kanten geprueft, ${calls} tx-Autoritaeten`);
}

const runFlow = process.argv.includes("--flow");
const fixturesOnly = process.argv.includes("--fixtures");
phaseA();
if (!fixturesOnly) {
  try { await phaseB(); } catch (e) { console.log("  Phase B nicht moeglich: " + String(e).slice(0, 200)); unreachable += 1; }
}
if (runFlow) {
  try { await phaseC(); } catch (e) { console.log("  Phase C nicht moeglich: " + String(e).slice(0, 200)); unreachable += 1; }
}
console.log("== Auswertung");
for (const [label, n] of [...tally.entries()].sort((a, b) => b[1] - a[1])) console.log(`  ${label.padEnd(30)} ${n}`);
if (defects.length) {
  console.log("  BESTAETIGTE ABWEICHUNGEN:");
  for (const d of defects.slice(0, 30)) {
    console.log(`   ${d.label} ${d.hash} ledger=${d.ledger ?? "-"} engine=${d.engine ?? "-"} autoritaet=${d.authority ?? "-"} quelle=${d.source ?? d.host ?? "-"} alte Lesart=${d.legacy ?? "-"}`);
  }
}
if (unreachable > 0 && tally.size === 0) process.exit(2);
process.exit(defects.length ? 1 : 0);
