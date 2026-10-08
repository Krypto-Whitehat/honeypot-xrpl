// Vercel Function: GET /lib/<name> — liefert die Browser-Bibliotheken aus lib/
// an den Browser (public/app.js importiert '/lib/detector.mjs' und
// '/lib/cluster.mjs'). Grund: Vercel served nur public/ statisch; lib/ ist auf
// Vercel über diese Funktion erreichbar (Rewrites in vercel.json +
// functions.includeFiles "lib/**" — der computed readFileSync wird im
// Deploy-Bundle nicht getrackt, cluster.mjs hat keinen api-Importer).
// WHITELIST: nur die genannten Dateinamen; der Request-Pfad wird niemals an
// readFileSync gereicht (kein Pfad-Traversierung).
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
// rate-gate.mjs (2026-10-02): DOM-freie Token-Bucket-Bibliothek für den
// Opt-in-LIVE-Modus des Browsers (public/app.js importiert '/lib/rate-gate.mjs').
// name-resolve.mjs (2026-10-05): DOM-freie Namens-Pure-Bibliothek für
// public/name-index.mjs (XRPScan-Well-known-Aliase; reiner Parser, kein fetch).
// tag-identity.mjs (2026-10-05): DOM-freie Tag-Pure-Bibliothek — cluster.mjs
// importiert sie für Destination-Tag-Kantenattribute (normalizeTag,
// computeTransitFlags); fehlt sie hier, bricht die Modul-Evaluation des
// Browser-Clusters (404, Muster stride.mjs in server/index.mjs).
const ALLOWED = new Set(["detector.mjs", "cluster.mjs", "sanitize.mjs", "stride.mjs", "rate-gate.mjs", "name-resolve.mjs", "tag-identity.mjs", "pattern-watch.mjs"]);

export default async function handler(req, res) {
  try {
    const name = req.query?.name ?? "detector.mjs";
    if (!ALLOWED.has(name)) {
      return res.status(404).json({ error: "Engine nicht gefunden." });
    }
    const body = fs.readFileSync(path.resolve(__dirname, "../lib", name), "utf8");
    res.setHeader("content-type", "text/javascript; charset=utf-8");
    res.setHeader("cache-control", "public, max-age=60");
    res.status(200).send(body);
  } catch {
    res.status(404).json({ error: "Engine nicht gefunden." });
  }
}
