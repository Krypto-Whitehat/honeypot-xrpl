// scripts/fetch-deployed-store.mjs
//
// WAS DIESE DATEI TUTT: Sie holt die Trace-Tagesdateien aus dem Daten-Repo, aus dem die Website
// tatsächlich liest (GITHUB_HISTORY_REPO, Default Krypto-Whitehat/honeypot-xrpl-history), in einen
// lokalen Ordner - unveraendert, ohne Normalisierung, ohne eigenen Wert.
//
// WARUM: Der lokale Recorder-Spiegel (data/validator-trace) und der ausgelieferte Bestand sind
// verschiedene Mithoer-Laeufe. Ein Audit, das nur den Spiegel liest, bestaetigt Zahlen, die auf der
// Website gar nicht stehen. Erst mit diesem Abruf laeuft audit:truth gegen genau dem Bestand, den
// ein Betreiber sieht.
//
// WAS SIE NICHT TUT: Sie schreibt nichts in das Daten-Repo zurueck, sie normalisiert nichts
// (normalizeDay benennt Vorfaelle um - das waere hier eine Veraenderung des Geprueften), und sie
// erfindet keine fehlenden Tage: ein Tag, der im Daten-Repo fehlt, wird als fehlend gemeldet.
//
// Lauf:  node scripts/fetch-deployed-store.mjs
//        node scripts/fetch-deployed-store.mjs --out=.tmp-deployed --days=30d
// Danach: TRACE_DATA_DIR=.tmp-deployed node scripts/audit-ground-truth.mjs
import fs from "node:fs";
import path from "node:path";
import { readGitHubContents } from "../lib/history.mjs";
import { dayPath, TRACE_DIR, datesForRange } from "../lib/validator-trace-store.mjs";

const argv = process.argv.slice(2);
const arg = (name, dflt) => { const i = argv.indexOf("--" + name); return i === -1 ? dflt : argv[i + 1]; };
const OUT = path.resolve(arg("out", ".tmp-deployed"));
const RANGE = arg("days", "30d");
const DATES = arg("dates") ? arg("dates").split(",").map((d) => d.trim()).filter(Boolean) : datesForRange(RANGE);

if (!process.env.GITHUB_HISTORY_TOKEN) {
  console.log("Kein GITHUB_HISTORY_TOKEN: das Daten-Repo ist privat und ohne Token nicht lesbar.");
  console.log("Lokal reicht: gh auth login, dann GITHUB_HISTORY_TOKEN=gh auth token setzen.");
  process.exit(1);
}

const codec = {
  serialize: (doc) => JSON.stringify(doc),
  parse: (text) => {
    const o = JSON.parse(text);
    if (!o || typeof o !== "object" || Array.isArray(o)) throw new Error("Trace-Tagesdatei hat kein gueltiges Format.");
    return o;
  },
};

fs.mkdirSync(OUT, { recursive: true });
let fetched = 0, missing = 0, bytes = 0;
for (const date of [...DATES].sort()) {
  let res;
  try { res = await readGitHubContents(dayPath(date), codec); } catch (e) { console.log(date, "Lesefehler:", e.message); missing += 1; continue; }
  if (!res.doc) { console.log(date, "fehlt im Daten-Repo"); missing += 1; continue; }
  const text = JSON.stringify(res.doc);
  fs.writeFileSync(path.join(OUT, `${date}.json`), text, "utf8");
  bytes += Buffer.byteLength(text, "utf8");
  fetched += 1;
  const d = res.doc;
  console.log(date, "ledgers", d.ledgers, "Forensik-Zeilen", (d.ledgerStats ?? []).length,
    "Vorfaelle", (d.incidents ?? []).length, "closureProofs", (d.closureProofs ?? []).length);
}
console.log("");
console.log("BEFUND");
console.log("  Tage aus dem Daten-Repo:", fetched, "| fehlend:", missing, "| Bytes:", bytes);
console.log("  Ordner:", OUT, "| Quelle:", process.env.GITHUB_HISTORY_REPO || "Krypto-Whitehat/honeypot-xrpl-history", "| Pfad:", TRACE_DIR);
console.log("  Audit dagegen laufen lassen: TRACE_DATA_DIR=" + OUT + " node scripts/audit-ground-truth.mjs");
