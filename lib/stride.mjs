// lib/stride.mjs — reine Stichproben-Auswahl (Block-Sampling mit Kappe).
//
// HINTERGRUND (Befund 2026-10-02): xrplcluster drosselt pro Egress-IP per
// Units-Quota ("units quota (10000 per 60s)", public/app.js:1148-1150;
// "(500000 per 3600s)", lib/live-gate.mjs:7-10). Volle Tx-Auflösung pro Block
// (bis 84 tx-Kommandos bei 4-5 s Blocktakt) sprengt das 60-s-Fenster. Deshalb
// wird mit MAX_RESOLVE (public/app.js, api/advance.js:86, api/ledger.js) eine
// Kappe gesetzt. slice(0, MAX_RESOLVE) wählt dabei stets den BLOCKANFANG —
// systematischer Bias: die ersten N Transaktionen eines Blocks werden immer
// aufgelöst, der Rest nie. strideHashes verteilt dasselbe Budget gleichmäßig
// über den Block (gleicher Budget, gleiche Kosten, keine Anfangs-Bias).
//
// VERTRAG:
//   strideHashes(list, budget) -> gleichmäßig verteilte Auswahl (Original-
//   Reihenfolge erhalten, keine Duplikate).
//   - Garbage-Inputs (kein Array, negatives/NaN-Budget) -> []
//   - budget >= length -> vollständige Liste (Kopie, Original-Referenz)
//   - budget <= 0 -> []
//   - Determinismus: gleiche Eingabe -> gleiche Auswahl (kein Zufall).
//
// Die Auswahl ist rein positionsbasiert; sie kennt keine Tx-Inhalte und
// filtert nichts — Konsumenten (resolveHashes, txRecordFromEntry,
// buildClusterGraph in lib/cluster.mjs) bleiben unverändert.

export function strideHashes(list, budget) {
  if (!Array.isArray(list)) return [];
  const b = Math.floor(Number(budget));
  if (!Number.isFinite(b) || b <= 0) return [];
  const n = list.length;
  if (n === 0) return [];
  if (b >= n) return list.slice();
  const out = [];
  for (let k = 0; k < b; k++) {
    out.push(list[Math.floor((k * n) / b)]);
  }
  return out;
}
