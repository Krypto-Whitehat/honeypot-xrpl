// scripts/eval/eval-rules.mjs — Auswertung der Engine gegen gelabelte Fälle.
//
// Aufruf: node scripts/eval/eval-rules.mjs <positives.json> [benign-ledgers.json]
//   positives.json : { knownBadAttackers?: [adr], cases: [{ id, label:"malicious", ledger:{ledger_index, transactions} }] }
//   benign-ledgers : { ledgers:[{ledger:{ledger_index, transactions}}] } oder JSON-Array gleicher Form
//
// Zwei Modi, bewusst getrennt ausgewiesen:
//   kalt  — knownBad leer (kein Wissen über Angreifer): ehrlicher Erkennungswert der Regeln
//   warm  — knownBad = knownBadAttackers: ZIRKULÄR (die Angreifer sind per Definition bekannt),
//           nur die Konsistenz der Pipeline, kein Präzisionsnachweis.
// Metriken: Trefferquote (Fälle mit mind. einem malicious/suspect-Fund) je Modus,
// Funde je Regel auf benignen Ledgern, Falsch-Positive pro 1000 Transaktionen.
import fs from "node:fs";
import { analyzeLedger, DEFAULT_BENIGN_ISSUERS } from "../../lib/detector.mjs";

const [, , posPath, benignPath] = process.argv;
if (!posPath) {
  console.error("Aufruf: node scripts/eval/eval-rules.mjs <positives.json> [benign-ledgers.json]");
  process.exit(2);
}
const pos = JSON.parse(fs.readFileSync(posPath, "utf8"));
const ctxBase = { benignIssuers: DEFAULT_BENIGN_ISSUERS };
const flagged = (r) => r.findings.filter((f) => f.severity === "malicious" || f.severity === "suspect");

function runPositives(knownBad) {
  const perRule = {};
  let hit = 0;
  for (const c of pos.cases) {
    const r = analyzeLedger({ result: { ledger: c.ledger } }, { ...ctxBase, knownBad });
    const f = flagged(r);
    if (f.length) hit++;
    for (const x of new Set(f.map((y) => y.ruleId))) perRule[x] = (perRule[x] ?? 0) + 1;
  }
  return { hit, total: pos.cases.length, perRule };
}

const cold = runPositives(new Set());
const warm = runPositives(new Set(pos.knownBadAttackers ?? []));

console.log(`\nPositive Fälle: ${pos.cases.length}`);
console.log(`  kalt  (knownBad leer)       : ${cold.hit}/${cold.total} erkannt   Regeln ${JSON.stringify(cold.perRule)}`);
console.log(`  warm  (ZIRKULÄR, bekannt)   : ${warm.hit}/${warm.total} erkannt   Regeln ${JSON.stringify(warm.perRule)}`);

if (benignPath) {
  const raw = JSON.parse(fs.readFileSync(benignPath, "utf8"));
  const ledgers = Array.isArray(raw) ? raw : raw.ledgers;
  const perRule = {};
  let txs = 0;
  for (const l of ledgers) {
    const entries = l.ledger.transactions;
    txs += entries.length;
    const r = analyzeLedger({ result: { ledger: l.ledger } }, { ...ctxBase, knownBad: new Set() });
    for (const f of r.findings) {
      const k = `${f.ruleId}|${f.severity}`;
      perRule[k] = (perRule[k] ?? 0) + 1;
    }
  }
  const total = Object.values(perRule).reduce((a, b) => a + b, 0);
  console.log(`\nBenigne Ledger: ${ledgers.length}, Transaktionen: ${txs}`);
  for (const [k, v] of Object.entries(perRule).sort((a, b) => b[1] - a[1])) console.log(`  ${k.padEnd(32)} ${v}`);
  console.log(`  Funde gesamt: ${total}  →  ${(total / txs * 1000).toFixed(2)} pro 1000 Transaktionen`);
  console.log("  (Benigne Ledger sind nicht unabhängig verifiziert: jeder Fund ist ein Prüfkandidat, kein bestätigter Fehlalarm.)");
}
