// scripts/verify-vote-capture.mjs
//
// GROUND-TRUTH-PROBE fuer die Vote-Erfassung.
//
// Beantwortete Frage: wenn der Rekorder auf einem Ledger nur 16, 20 oder 0 Stimmen der
// beobachteten dUNL sieht, waehlt das Netz dann zu wenig Quorum - oder sieht nur DIESER
// Rekorder zu wenig?
//
// Methode (keine Schaetzung, alles nachrechenbar):
//   1. dUNL live von vl.ripple.com, Master-Schluessel ueber lib/validator-health.mjs.
//   2. Ephemeral -> Master ueber das Validator-Registry (dieselbe Zuordnung wie der Rekorder).
//   3. Eigener Mithoerlauf auf einem oeffentlichen Endpunkt: ledger- und validations-Stream.
//   4. Je Ledger: gesehene Mitglieder-Stimmen, Nicht-dUNL-Signierer, Close-Abstand, Median-Takt.
//   5. Derselbe Ledger index-gleich bei xrpscan nachgeprueft (Hash, Tx-Zahl, Close-Zeit).
//
// Lauf: node scripts/verify-vote-capture.mjs [anzahlLedger]
import { WebSocket } from "ws";
import { decodeValidatorList, nodePublicB58 } from "../lib/validator-health.mjs";
import { TRACE_DEFAULTS, ledgerClosure } from "../lib/validator-trace.mjs";

const RIPPLE_EPOCH = 946684800;
const ENDPOINT = process.env.VERIFY_WSS || "wss://xrplcluster.com";
const TARGET = Math.max(3, Math.min(20, Number(process.argv[2] || 8)));
const toMs = (rippleSec) => (Number(rippleSec) + RIPPLE_EPOCH) * 1000;

const log = (...a) => console.log(new Date().toISOString().slice(11, 23), ...a);

async function json(url) {
  const r = await fetch(url, { signal: AbortSignal.timeout(20000) });
  if (!r.ok) throw new Error(url + " -> HTTP " + r.status);
  return r.json();
}

// ---------- 1+2: dUNL und Ephemeral-Zuordnung, genau wie der Rekorder ----------
const vl = decodeValidatorList(await json("https://vl.ripple.com"));
const registry = await json("https://api.xrpscan.com/api/v1/validatorregistry");
const byMaster = new Map((registry || []).filter((r) => r && r.master_key).map((r) => [r.master_key, r]));
const members = [];
const meta = new Map();
const ephemeralToMaster = new Map();
for (const hex of vl.keys) {
  const master = nodePublicB58(hex);
  if (!master) continue;
  const rec = byMaster.get(master);
  members.push(master);
  meta.set(master, { domain: rec?.domain ?? "?", name: rec?.name ?? "?", ephemeral: rec?.ephemeral_key ?? null });
  if (rec?.ephemeral_key) ephemeralToMaster.set(rec.ephemeral_key, master);
}
const derivedNeed = Math.ceil(members.length * TRACE_DEFAULTS.quorumFrac);
let need = derivedNeed;
let needBasis = "derived";
log("dUNL", vl.keys.length, "| Master gemaht", members.length, "| Ephemeral zuordenbar", ephemeralToMaster.size,
  "| Quorum-Ziel aus der dUNL-Liste gerechnet ceil(" + members.length + " * 0.8) =", need);

// ---------- 3: eigener Mithoerlauf ----------
const ledgers = new Map();   // index -> { hash, closeMs, tx, seenMs }
const votes = new Map();     // index -> Map(master -> { hash, full, arrivalMs, signingMs })
const outside = new Map();   // index -> Map(signingKey -> anzahl)
let lastCloseMs = null;
let closedCount = 0;
const gapSamples = [];

const ws = new WebSocket(ENDPOINT);
await new Promise((res, rej) => { ws.on("open", res); ws.on("error", rej); });
ws.send(JSON.stringify({ command: "subscribe", streams: ["ledger", "validations"] }));
ws.send(JSON.stringify({ command: "server_info", id: 1 }));

const info = await new Promise((res) => {
  const timer = setTimeout(() => res(null), 15000);
  const onMsg = (raw) => {
    let m; try { m = JSON.parse(raw); } catch { return; }
    if (m.id === 1) { clearTimeout(timer); ws.off("message", onMsg); res(m.result?.info ?? m.result?.server_info ?? {}); }
  };
  ws.on("message", onMsg);
});
log("server_info:", info?.server_state, "| validation_quorum:", info?.validation_quorum,
  "| validierte Ledger:", info?.validated_ledgers ?? info?.complete_ledgers);
// Das gemeldete Netz-Ziel gewinnt gegen die eigene Rechnung: ceil(dUNL * 0,8) ist eine
// Herleitung, validation_quorum ist die Zahl, die das Netz selbst an diesem Endpunkt verlangt.
const reported = Number(info?.validation_quorum);
if (Number.isFinite(reported) && reported > 0) {
  need = reported;
  needBasis = "measured";
  log("Quorum-Ziel gemessen am Endpunkt:", reported,
    reported === derivedNeed ? "bestaetigt die Rechnung " + derivedNeed : "ersetzt die Rechnung " + derivedNeed);
} else {
  log("Quorum-Ziel am Endpunkt nicht meldbar (validation_quorum:", info?.validation_quorum ?? "fehlt",
    ") - gehalten wird die gerechnete Zahl", need);
}

ws.on("message", (raw) => {
  let m; try { m = JSON.parse(raw); } catch { return; }
  // Die oeffentlichen xrpld-Endpunkte melden "ledgerClosed" und "validationReceived" -
  // dasselbe Raster, das auch monitor/validator-trace.mjs benutzt.
  if (m.type === "ledgerClosed" || m.type === "ledger") {
    const idx = Number(m.ledger_index);
    if (!Number.isFinite(idx)) return;
    const closeMs = toMs(m.ledger_time);
    if (lastCloseMs !== null) gapSamples.push(closeMs - lastCloseMs);
    lastCloseMs = closeMs;
    ledgers.set(idx, { hash: m.ledger_hash, closeMs, tx: Number(m.txn_count) || 0, seenMs: Date.now() });
    closedCount += 1;
    return;
  }
  if (m.type === "validationReceived") {
    const v = m;
    const idx = Number(v.ledger_index);
    const key = v.validation_public_key;
    if (!Number.isFinite(idx) || typeof key !== "string") return;
    const master = ephemeralToMaster.get(key);
    if (!master) {
      const prev = outside.get(idx) ?? new Map();
      prev.set(key, (prev.get(key) ?? 0) + 1);
      outside.set(idx, prev);
      return;
    }
    if (!votes.has(idx)) votes.set(idx, new Map());
    votes.get(idx).set(master, {
      hash: v.ledger_hash, full: v.full !== false, arrivalMs: Date.now(),
      signingMs: Number.isFinite(v.signing_time) ? toMs(v.signing_time) : null,
    });
  }
});

const deadline = Date.now() + 120000;
while (closedCount < TARGET && Date.now() < deadline) await new Promise((r) => setTimeout(r, 500));
ws.close();

// ---------- 4+5: nachrechnen und gegen xrpscan decken ----------
const gaps = gapSamples.filter((g) => Number.isFinite(g)).sort((a, b) => a - b);
const medianGap = gaps.length ? gaps[Math.floor(gaps.length / 2)] : null;
const rows = [...ledgers.entries()].sort((a, b) => a[0] - b[0]).slice(-TARGET);

console.log("");
console.log("Ledger         Mitglieder-Stimmen  Nicht-dUNL  Ziel  Marge  Close-Abstand  Median-Takt  Erfassungs-Luecke  Schliess-Basis");
const report = [];
for (const [idx, l] of rows) {
  const seen = votes.get(idx) ?? new Map();
  const out = [...(outside.get(idx) ?? new Map()).values()].reduce((a, n) => a + n, 0);
  const tally = new Map();
  for (const v of seen.values()) tally.set(v.hash, (tally.get(v.hash) ?? 0) + 1);
  let top = 0; for (const n of tally.values()) if (n > top) top = n;
  // 'prev' ist der zuletzte Gesehene in der beobachteten Folge, nicht der erwartete Index.
  // Genau daraus lebt die Erfassungs-Aussage: pg !== idx - 1 heisst, dass zwischen zwei gesehenen
  // Ledgern Indizes fehlen. Der Close-Abstand ist hier nur noch eine Spalte zum Lesen - er war
  // bisher die Regel und ist am 2026-10-16 live widerlegt (8 000 ms Abstand, alle Mitglieder gesehen).
  const pos = rows.findIndex((x) => x[0] === idx);
  const prev = pos > 0 ? rows[pos - 1] : null;
  const gap = prev ? l.closeMs - prev[1].closeMs : null;
  const closure = ledgerClosure({ cl: true, ch: l.hash, l: idx, pg: prev ? prev[0] : null });
  report.push({ idx, memberVotes: seen.size, outsideSigners: out, top, need, margin: top - need, gap, closure });
  console.log(
    "#" + String(idx).padEnd(12),
    String(seen.size).padStart(9), String(out).padStart(11), String(need).padStart(5),
    String(top - need).padStart(6),
    (Number.isFinite(gap) ? gap + " ms" : "-").padStart(14),
    (medianGap !== null ? medianGap + " ms" : "-").padStart(12),
    (closure.captureGap === true ? "JA" : closure.captureGap === false ? "nein" : "nicht erfasst").padStart(18),
    " " + closure.basis);
}

console.log("");
console.log("--- xrpscan-Deckung derselben Ledger (Hash / Tx / Close-Zeit) ---");
let agree = 0;
for (const r of report) {
  const own = ledgers.get(r.idx);
  try {
    const s = await json("https://api.xrpscan.com/api/v1/ledger/" + r.idx);
    const okHash = (s.ledger_hash || "").toUpperCase() === (r.closure.hash || "").toUpperCase();
    const okTx = s.tx_count === own.tx;
    // xrpscan antwortet in zwei Formaten: das eine nennt close_time in Unix-Sekunden, das andere
    // in der Ripple-Epoche (946.684.800 s unter Unix). Ueber close_time gegenzuhalten ist auf der
    // einen Haelfte falsch - dieselbe Erkenntnis wie in scripts/backfill-closure.mjs. Verglichen
    // wird deshalb ueber close_time_human, und eine Abweichung wird mit beiden Zeiten ausgedruckt.
    const scanMs = s.close_time_human ? Date.parse(s.close_time_human) : null;
    const okTime = scanMs !== null && scanMs === own.closeMs;
    if (okHash && okTx && okTime) agree += 1;
    console.log("#" + r.idx, "hash", okHash ? "gleich" : "ABWEICHEND",
      "| tx", okTx ? String(s.tx_count) : s.tx_count + " vs " + own.tx,
      "| close", okTime ? "gleich" : "ABWEICHEND " + new Date(own.closeMs).toISOString()
        + " vs " + (s.close_time_human || "keine ISO-Angabe von xrpscan"));
  } catch (e) { console.log("#" + r.idx, "xrpscan nicht erreichbar:", e.message); }
}

const thin = report.filter((r) => r.top < r.need).length;
const captureGaps = report.filter((r) => r.closure.captureGap).length;
console.log("");
console.log("BEFUND");
console.log("  Mithoer-Laeufe:", report.length,
  "| Ledger mit gesehenen Stimmen unter Ziel:", thin,
  "| davon mit Erfassungs-Luecke dieses Mithoerers:", captureGaps);
console.log("  Ziel-Herleitung:", needBasis === "measured"
  ? "gemessen am Endpunkt: das Netz verlangt " + need
  : "aus der dUNL-Liste gerechnet: " + members.length + " Knoten, Ziel " + need + " (Endpunkt meldete keinen Wert)");
console.log("  Medianer Close-Abstand im Live-Stream:", medianGap, "ms");
console.log("  xrpscan-Deckung (Hash + Tx + Close identisch):", agree, "von", report.length);
console.log("  Bedeutet: ein bewiesen geschlossener Ledger mit gesehenen Stimmen unter Ziel ist");
console.log("  eine Erfassungs-Luecke DIESES Mithoerers, nie ein zu kleines Netz-Quorum.");
