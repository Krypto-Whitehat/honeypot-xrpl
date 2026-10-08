// Vercel Function: GET /api/stats — Live-Statistiken.
// Route ?route=validators (Rewrite /api/validators): Validator-Gesundheit aus xrpscan
// (lib/validator-service.mjs). Eine Funktion mehr wäre über das Hobby-Limit (12).
import { getStats } from "../lib/threats-service.mjs";
import { validatorView } from "../lib/validator-service.mjs";
import { loadDays, traceForValidator, crossValidatorPatterns } from "../lib/validator-trace-query.mjs";
import path from "node:path";
import { fileURLToPath } from "node:url";
const TRACE_DIR = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "data", "validator-trace");

export const maxDuration = 30;

export default async function handler(req, res) {
  try {
    if (req.query?.route === "validators") {
      return res.status(200).json(await validatorView());
    }
    if (req.query?.route === "trace") {
      const days = loadDays(TRACE_DIR);
      const range = String(req.query.range || "24h");
      if (!days.length) return res.status(200).json({ available: false, note: "Kein Trace-Speicher auf diesem Host (Recorder läuft nicht hier)." });
      const body = req.query.patterns ? crossValidatorPatterns(days, { range }) : traceForValidator(days, String(req.query.master || ""), { range });
      return res.status(200).json({ available: true, days: days.length, ...body });
    }
    res.status(200).json(await getStats());
  } catch (err) {
    res.status(502).json({ error: "Ledger-Abfrage fehlgeschlagen." });
  }
}
