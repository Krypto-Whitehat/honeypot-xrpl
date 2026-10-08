// Vercel Function: GET /api/stats — Live-Statistiken.
// Route ?route=validators (Rewrite /api/validators): Validator-Gesundheit aus xrpscan
// (lib/validator-service.mjs). Eine Funktion mehr wäre über das Hobby-Limit (12).
import { getStats } from "../lib/threats-service.mjs";
import { validatorView } from "../lib/validator-service.mjs";

export const maxDuration = 30;

export default async function handler(req, res) {
  try {
    if (req.query?.route === "validators") {
      return res.status(200).json(await validatorView());
    }
    res.status(200).json(await getStats());
  } catch (err) {
    res.status(502).json({ error: "Ledger-Abfrage fehlgeschlagen." });
  }
}
