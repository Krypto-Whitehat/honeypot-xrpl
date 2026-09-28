// Vercel Function: GET /api/threats?q=<text> — sanitisierte Bedrohungsliste.
import { getPublicThreats } from "../lib/threats-service.mjs";

export const maxDuration = 30;

export default async function handler(req, res) {
  try {
    let list = await getPublicThreats();
    const q = String(req.query?.q ?? "").trim().toLowerCase();
    if (q) {
      list = list.filter(
        (t) => t.address.toLowerCase().includes(q) || t.reason.toLowerCase().includes(q)
      );
    }
    res.status(200).json(list);
  } catch (err) {
    res.status(502).json({ error: "Ledger-Abfrage fehlgeschlagen." });
  }
}
