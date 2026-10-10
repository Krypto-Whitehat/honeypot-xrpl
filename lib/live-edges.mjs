// lib/live-edges.mjs — Echtzeit-Kanten für den Globe (rein, DOM-frei).
// Kanten aus den Transaktionen eines validierten Ledgers, deren einer Endpunkt
// ein Fund dieses Ledgers ist. Schweregrad = schlimmster beteiligter Fund.
// Nutzt ausschließlich bereits köder-gefilterte Funde (visibleFindings).
// Batch-Inner werden expandiert — ein Drain in einem Batch erzeugt seine Linie
// genauso wie eine normale Zahlung (expandBatches ist idempotent).
import { expandBatches } from "./detector.mjs";

export function liveEdgesOf(entries, findings) {
  const bad = new Map();
  for (const f of findings || []) {
    if (f.severity !== "malicious" && f.severity !== "suspect") continue;
    const prev = bad.get(f.address);
    if (!prev || f.severity === "malicious") bad.set(f.address, f.severity);
  }
  if (!bad.size) return [];
  const out = [];
  for (const e of expandBatches(Array.isArray(entries) ? entries : [])) {
    const tx = e?.tx_json ?? e?.tx ?? e;
    const from = tx?.Account, to = tx?.Destination;
    if (!from || !to || from === to) continue;
    const sevs = [bad.get(from), bad.get(to)].filter(Boolean);
    if (!sevs.length) continue;
    out.push({ from, to, sev: sevs.includes("malicious") ? "malicious" : "suspect" });
  }
  return out.slice(-60);
}
