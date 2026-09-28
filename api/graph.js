// Vercel Function: GET /api/graph — anonymisierter Aktivitäts-Graph.
import { getGraph } from "../lib/threats-service.mjs";

export const maxDuration = 30;

export default async function handler(req, res) {
  try {
    res.status(200).json(await getGraph());
  } catch (err) {
    res.status(502).json({ error: "Ledger-Abfrage fehlgeschlagen." });
  }
}
