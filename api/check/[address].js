// Vercel Function: GET /api/check/:address — Selbst-Check.
// Privatsphäre: die Adresse wird nicht geloggt und nicht persistiert.
import { checkAddress } from "../../lib/threats-service.mjs";

export const maxDuration = 30;

export default async function handler(req, res) {
  const addr = String(req.query?.address ?? "").trim();
  try {
    const { status, body } = await checkAddress(addr);
    res.status(status).json(body);
  } catch (err) {
    res.status(502).json({ error: "Ledger-Abfrage fehlgeschlagen." });
  }
}
