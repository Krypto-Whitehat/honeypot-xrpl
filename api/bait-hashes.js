// Vercel Function: GET /api/bait-hashes — SHA-256-Hashes der Bait-Union.
//
// Pendant zur Express-Route in server/index.mjs ("/api/bait-hashes"): Der
// Client (public/app.js, refetchBaitHashes) erkennt Köder-Adressen ausschließlich
// über deren SHA-256-Hashes (hex, Kleinbuchstaben) der getrimmten UTF-8-Adresse
// — dieselbe Normalisierung wie clientseitig in sha256Hex/hashOf. Klartext-
// Adressen und Seeds verlässt niemals diese Funktion.
//
// Auf Vercel stammt die Köder-Union ausschließlich aus ENV BAIT_ADDRESSES
// (Komma-separiert) — bait.json/bait-history.json sind per .vercelignore vom
// Upload ausgeschlossen (identisches Muster wie api/ledger.js). Ohne ENV ist
// die Liste leer; der Client (refetchBaitHashes) behandelt die leere Antwort
// als geladene Allowlist mit leerer Deny-Liste und zeigt Adressen dann in
// VOLLFORM — es sind ja keine Köder konfiguriert (Befund 2026-09-30: die
// frühere Kommentar-Behauptung „weiterhin Kurzform“ war gegen den Client-Code
// unzutreffend). Köder-Schutz auf Vercel entsteht somit ausschließlich durch
// gesetztes ENV; leer bedeutet „keine Köder“, nicht fail-closed.
import { createHash } from "node:crypto";

export default function handler(req, res) {
  const hashes = (process.env.BAIT_ADDRESSES || "")
    .split(",")
    .map((a) => a.trim())
    .filter(Boolean)
    .map((addr) => createHash("sha256").update(addr, "utf8").digest("hex"));
  res.setHeader("cache-control", "no-store");
  res.status(200).json({ hashes });
}
