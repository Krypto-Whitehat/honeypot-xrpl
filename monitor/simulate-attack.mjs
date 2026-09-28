// Honeypot XRPL — simulierter Angreifer (Testnet-Demo).
// Erzeugt ein frisch über das Testnet-Faucet finanziertes Konto und sendet
// 1 XRP Payment an Köder #1 (HP-1). Der Monitor erfasst die Gegenpartei
// daraufhin als Threat (risk "malicious").
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { Client } from "xrpl";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, "..");

const config = JSON.parse(fs.readFileSync(path.join(ROOT, "config.json"), "utf8"));
const BAIT_FILE = path.join(ROOT, "bait.json");

if (config.network !== "testnet") {
  console.error("simulate-attack.mjs ist nur für das Testnet vorgesehen (echtes Geld auf Mainnet).");
  process.exit(1);
}
if (!fs.existsSync(BAIT_FILE)) {
  console.error("bait.json fehlt — zuerst `npm run provision` ausführen.");
  process.exit(1);
}

const bait = JSON.parse(fs.readFileSync(BAIT_FILE, "utf8"));
const target = bait.find((b) => b.label === "HP-1") ?? bait[0];

const client = new Client(config.wss);
await client.connect();
console.log(`Verbunden mit ${config.network} (${config.wss})`);

// Angreifer-Konto frisch über das Faucet finanzieren.
const { wallet: attacker, balance } = await client.fundWallet();
console.log(`Simulierter Angreifer: ${attacker.address} · Faucet-Guthaben: ${balance} XRP`);

// 1 XRP Payment an Köder #1.
const tx = await client.autofill({
  TransactionType: "Payment",
  Account: attacker.address,
  Destination: target.address,
  Amount: "1", // XRP-Betrag als String (xrpl 4.x: {currency,value} ist nur für IOU)
});
const result = await client.submitAndWait(tx, { wallet: attacker });

const meta = result.result.meta ?? result.result.metas?.[0];
const outcome = typeof meta === "string" ? meta : meta?.TransactionResult;
console.log(`Payment an ${target.label} gesendet: ${outcome}`);
console.log(`Tx-Hash: ${result.result.hash}`);

if (outcome !== "tesSUCCESS") {
  console.error("Payment fehlgeschlagen.");
  await client.disconnect();
  process.exit(1);
}

await client.disconnect();
