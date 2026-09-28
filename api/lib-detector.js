// Vercel Function: GET /lib/detector.mjs — liefert die gemeinsame Detektor-
// Engine an den Browser (public/app.js importiert '/lib/detector.mjs').
// Grund: Vercel served nur public/ statisch; lib/ ist auf Vercel über diese
// Funktion erreichbar (Rewrite in vercel.json). Der Deploy-Bundle enthält
// lib/ (api/ledger.js importiert dieselbe Datei — im Live-Betrieb verifiziert).
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ENGINE = path.resolve(__dirname, "../lib/detector.mjs");

export default async function handler(req, res) {
  try {
    const body = fs.readFileSync(ENGINE, "utf8");
    res.setHeader("content-type", "text/javascript; charset=utf-8");
    res.setHeader("cache-control", "public, max-age=60");
    res.status(200).send(body);
  } catch {
    res.status(404).json({ error: "Engine nicht gefunden." });
  }
}
