// Vercel Function: GET /api/rules — Regelkatalog für die Regelfilter-UI der
// Live-Ansicht. Identische Katalogquelle (lib/detector.mjs ruleCatalog()) wie
// im Browser — single source of truth.
import { ruleCatalog } from "../lib/detector.mjs";

export const maxDuration = 30;

export default async function handler(req, res) {
  try {
    res.status(200).json(ruleCatalog());
  } catch {
    res.status(500).json({ error: "Regelkatalog nicht verfügbar." });
  }
}
