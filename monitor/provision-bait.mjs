// Honeypot XRPL — Provisionierung der drei Köder-Konten.
// Erzeugt auf dem Testnet drei Wallets via xrpl.js client.fundWallet()
// (Finanzierung über das Testnet-Faucet) und schreibt bait.json:
//   [{ "address": "...", "seed": "...", "label": "HP-1" }, ...]
//
// ROTATION (Anonymität): Existiert bait.json bereits, werden die alten
// Köder-Einträge VOR dem Überschreiben in bait-history.json verschoben
// (gleiche .gitignore-Regel wie bait.json). Server und Monitor sanitieren
// gegen die UNION aus bait.json + bait-history.json — damit bleibt auch die
// ALTE Köder-Adresse (z. B. als funding[].address im Threat-Store) nicht
// öffentlich auslieferbar.
//
// bait.json / bait-history.json sind durch .gitignore geschützt und werden
// von Server/Monitor nie öffentlich ausgeliefert. Seeds werden hier nur
// lokal geschrieben, nie auf die Konsole ausgegeben. Auf stdout erscheint
// nur Label + letzte 4 Zeichen der Adresse.
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { Client } from "xrpl";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, "..");

const config = JSON.parse(fs.readFileSync(path.join(ROOT, "config.json"), "utf8"));
const BAIT_FILE = path.join(ROOT, "bait.json");
const BAIT_HISTORY_FILE = path.join(ROOT, "bait-history.json");

if (config.network !== "testnet") {
  console.error(
    "provision-bait.mjs ist nur für das Testnet vorgesehen (fundWallet über das Faucet).\n" +
      "Für Mainnet: bait.json manuell mit vorab finanzierten Konten anlegen (siehe README)."
  );
  process.exit(1);
}

function maskAddress(address) {
  const s = String(address ?? "");
  return s.length > 4 ? `…${s.slice(-4)}` : "…";
}

function loadBaitFile(file) {
  try {
    const parsed = JSON.parse(fs.readFileSync(file, "utf8"));
    return Array.isArray(parsed) ? parsed : [];
  } catch (err) {
    if (err.code !== "ENOENT") {
      console.error(`WARNUNG: ${path.basename(file)} nicht lesbar (${err.message}) — wird ignoriert.`);
    }
    return [];
  }
}

// Rotation: alte Köder in die History verschieben, bevor bait.json neu geschrieben wird.
if (fs.existsSync(BAIT_FILE)) {
  const oldBait = loadBaitFile(BAIT_FILE);
  const history = loadBaitFile(BAIT_HISTORY_FILE);
  const retiredAt = new Date().toISOString();
  for (const entry of oldBait) {
    history.push({ ...entry, retiredAt });
  }
  fs.writeFileSync(BAIT_HISTORY_FILE, JSON.stringify(history, null, 2), { mode: 0o600 });
  console.log(
    `Rotation: ${oldBait.length} alte Köder-Einträge nach bait-history.json verschoben ` +
      `(Labels: ${oldBait.map((b) => `${b.label ?? "?"} ${maskAddress(b.address)}`).join(", ")}).`
  );
}

const client = new Client(config.wss);
await client.connect();
console.log(`Verbunden mit ${config.network} (${config.wss})`);

const existingLabels = new Set(
  [...loadBaitFile(BAIT_HISTORY_FILE)].map((b) => b.label)
);
// Fortlaufende Nummerierung über Rotationen hinweg: honeypot:N-Ids im
// öffentlichen Graph bleiben dadurch eindeutig (alt ≠ neu).
let maxN = 0;
for (const label of existingLabels) {
  const m = /^HP-(\d+)$/.exec(String(label));
  if (m) maxN = Math.max(maxN, Number(m[1]));
}
const bait = [];
let n = maxN + 1;
for (let i = 1; i <= 3; i += 1) {
  let label = `HP-${n}`;
  while (existingLabels.has(label)) {
    n += 1;
    label = `HP-${n}`;
  }
  existingLabels.add(label);
  n += 1;
  const { wallet, balance } = await client.fundWallet();
  bait.push({ address: wallet.address, seed: wallet.seed, label });
  // Nur Label + letzte 4 Zeichen — die volle Adresse verlässt dieses Skript nicht.
  console.log(`Köder ${label}: ${maskAddress(wallet.address)} · Guthaben: ${balance} XRP`);
}

fs.writeFileSync(BAIT_FILE, JSON.stringify(bait, null, 2), { mode: 0o600 });
console.log(`bait.json geschrieben (${bait.length} Köder-Konten). Datei liegt in .gitignore — niemals committen.`);
if (process.platform === "win32") {
  console.log(
    "Hinweis (Windows): NTFS ignoriert mode 0o600. Dateirechte beschränken mit:\n" +
      `  icacls "${BAIT_FILE}" /inheritance:r /grant:r "%USERNAME%:F"\n` +
      `  icacls "${BAIT_HISTORY_FILE}" /inheritance:r /grant:r "%USERNAME%:F"`
  );
}

await client.disconnect();
