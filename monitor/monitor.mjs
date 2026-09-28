// Honeypot XRPL — Monitor.
// Verbindet sich per xrpl.js WSS-Client (in xrpl.js 4.x: die Client-Klasse,
// ein WebSocket-Client mit Event-Emitter: client.on('transaction', ...);
// ein separat exportiertes "WSSClient" existiert in xrpl 4.6.0 nicht)
// mit dem konfigurierten Netz, abonniert alle Köder-Konten aus bait.json
// UND bait-history.json (UNION — nach einer Rotation bleiben auch alte
// Köder-Adressen überwacht/anonymisiert) und erfasst jede validierte
// Transaktion, die ein Köder-Konto berührt, als Threat im Store
// data/threats.json.
//
// Klassifikation:
//   risk "malicious" — Payment/TrustSet von extern gegen ein Köder-Konto
//                      ODER Kompromittierungs-Alarm: ein Köder-Konto hat
//                      selbst eine Transaktion initiiert (Zieladresse wird
//                      bewusst NICHT im Reason-Text genannt)
//   risk "suspect"   — jede andere Transaktion, die ein Köder-Konto berührt
//                      (u. a. DEX-Offer-Berührung, NFToken-Angebote)
// Funding-Kette via account_tx rückverfolgt (Tiefe 2, paginiert); das
// Testnet-Faucet-Konto gilt als benign und wird nur gelabelt, nicht als
// Threat gelistet. Bekannte Grenze: Path-Payment-Zwischenhops werden nicht
// als Gegenpartei erfasst (siehe README, "Bekannte Grenzen").
//
// ANONYMITÄT: threats.json und alle Logs nennen Köder-Konten ausschließlich
// über ihre Labels (HP-1, ...). Seeds werden nie gelesen, nie geschrieben.
// Der SERVER (nicht dieser Prozess) baut die öffentliche Anonymitätsschicht;
// dieser Store ist der interne Wahrheitsbestand inkl. txHash-Evidenz.
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { Client } from "xrpl";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, "..");

const config = JSON.parse(fs.readFileSync(path.join(ROOT, "config.json"), "utf8"));

const BAIT_FILE = path.join(ROOT, "bait.json");
const BAIT_HISTORY_FILE = path.join(ROOT, "bait-history.json");
const DATA_DIR = path.join(ROOT, "data");
const THREATS_FILE = path.join(DATA_DIR, "threats.json");
const LOGS_DIR = path.join(ROOT, "logs");

// ---------- Bait-Union (aktuelle + historische Köder) ----------
function loadBaitFile(file) {
  try {
    const parsed = JSON.parse(fs.readFileSync(file, "utf8"));
    return Array.isArray(parsed) ? parsed : [];
  } catch (err) {
    if (err.code !== "ENOENT") {
      console.error(`[monitor] ${path.basename(file)} nicht lesbar: ${err.message}`);
    }
    return [];
  }
}

if (!fs.existsSync(BAIT_FILE)) {
  console.error("bait.json fehlt — zuerst `npm run provision` ausführen.");
  process.exit(1);
}
// UNION aus bait.json + bait-history.json: nach einer Köder-Rotation ist die
// alte Adresse nicht mehr in bait.json, taucht aber noch als funding[].address
// im Store auf — sie muss weiterhin erkannt (und vom Server anonymisiert) werden.
const bait = [
  ...loadBaitFile(BAIT_HISTORY_FILE),
  ...loadBaitFile(BAIT_FILE),
];
const baitByAddress = new Map(bait.map((b) => [b.address, b.label]));

// Faucet- und Betriebs-Adressen aus config.json (siehe README):
// faucet_addresses: benign, werden nur gelabelt (Adresse bleibt intern).
// operator_addresses: eigene Sweep-/Cold-Wallets des Betreibers — Zahlungen
// der Köder dorthin erzeugen KEINEN Threat (False-Positive-Schutz).
const faucetAddresses = new Set(config.faucet_addresses ?? []);
const operatorAddresses = new Set(config.operator_addresses ?? []);

// ---------- Threat-Store ----------
const threats = new Map(); // address -> threat
const seenTxHashes = new Set(); // Deduplizierung bereits verarbeiteter Transaktionen

// Vorhandenen Store beim Start laden, damit Historie erhalten bleibt.
if (fs.existsSync(THREATS_FILE)) {
  try {
    const existing = JSON.parse(fs.readFileSync(THREATS_FILE, "utf8"));
    if (Array.isArray(existing)) {
      for (const t of existing) if (t?.address) threats.set(t.address, t);
    }
  } catch {
    console.error("[monitor] Vorhandene threats.json nicht lesbar — Start mit leerem Store.");
  }
}

function saveThreats() {
  fs.mkdirSync(DATA_DIR, { recursive: true });
  const tmp = `${THREATS_FILE}.${process.pid}.tmp`;
  fs.writeFileSync(tmp, JSON.stringify([...threats.values()], null, 2));
  fs.renameSync(tmp, THREATS_FILE); // atomar: temp + rename
}

function log(msg) {
  const line = `[${new Date().toISOString()}] ${msg}`;
  console.log(line);
  try {
    fs.mkdirSync(LOGS_DIR, { recursive: true });
    fs.appendFileSync(path.join(LOGS_DIR, "monitor.log"), `${line}\n`);
  } catch {
    /* Logging darf den Monitor nicht kippen */
  }
}

// Zeit der Transaktion: Stream-Nachricht liefert close_time_iso (ISO),
// Fallback: XRP-Epoch (Sekunden seit 2000-01-01T00:00:00Z) -> ISO.
function eventTime(event, tx) {
  if (typeof event.close_time_iso === "string") return event.close_time_iso;
  if (typeof tx.date === "number" && Number.isFinite(tx.date)) {
    return new Date((tx.date + 946684800) * 1000).toISOString();
  }
  return new Date().toISOString();
}

// ---------- WSS-Client ----------
const client = new Client(config.wss);

// account_tx mit Pagination (marker), bis max-Einheiten gelesen sind —
// sonst bleibt die Funding-Quelle bei Konten mit vielen Transaktionen unsichtbar.
async function fetchAccountTxs(address, maxEntries) {
  const entries = [];
  let marker;
  do {
    const resp = await client.request({
      command: "account_tx",
      account: address,
      ledger_index_min: -1,
      ledger_index_max: -1,
      binary: false,
      forward: false, // neueste zuerst
      limit: 20,
      ...(marker ? { marker } : {}),
    });
    entries.push(...(resp.result?.transactions ?? []));
    marker = resp.result?.marker;
  } while (marker && entries.length < maxEntries);
  return entries.slice(0, maxEntries);
}

// Funding-Kette eines Kontos rückverfolgen (Tiefe depth, max. 2 pro Vorgabe).
async function traceFunding(address, depth) {
  const out = [];
  if (depth <= 0) return out;
  try {
    const entries = await fetchAccountTxs(address, 100);
    for (const entry of entries) {
      if (entry?.validated === false) continue; // nur validierte Ledger-Einträge
      const tx = entry.tx_json ?? entry.tx ?? entry; // xrpl 4.x: {tx_json, meta, validated}
      if (!tx || tx.TransactionType !== "Payment") continue;
      if (tx.Destination !== address) continue; // nur eingehende Zahlungen als Funding
      const funder = tx.Account;
      if (!funder || funder === address) continue;
      if (baitByAddress.has(funder)) continue; // interne Köder-zu-Köder-Bewegung ausblenden
      if (faucetAddresses.has(funder)) {
        out.push({ address: funder, label: "Testnet-Faucet (benign)" });
        continue; // Faucet nicht weiter rückverfolgen
      }
      const known = threats.get(funder);
      out.push({
        address: funder,
        label: known ? `Funding-Quelle (${known.risk})` : "Funding-Quelle",
      });
      const deeper = await traceFunding(funder, depth - 1);
      for (const d of deeper) {
        if (!out.some((o) => o.address === d.address)) out.push(d);
      }
    }
  } catch (err) {
    log(`account_tx für ${address} fehlgeschlagen: ${err.message}`);
  }
  return out.slice(0, 8);
}

// Meta-Scan: berührt ein Ledger-Objekt (Offer / NFTokenOffer) ein Köder-Konto?
// Gibt das Label des ersten betroffenen Köders zurück oder null.
function metaFindBait(event) {
  const affected = event?.meta?.AffectedNodes;
  if (!Array.isArray(affected)) return null;
  for (const wrapper of affected) {
    for (const key of ["CreatedNode", "ModifiedNode", "DeletedNode"]) {
      const node = wrapper?.[key];
      if (!node) continue;
      const fields = {
        ...(node.PreviousFields ?? {}),
        ...(node.FinalFields ?? {}),
        ...(node.NewFields ?? {}),
      };
      if (node.LedgerEntryType === "Offer" && fields.Account && baitByAddress.has(fields.Account)) {
        return baitByAddress.get(fields.Account);
      }
      if (node.LedgerEntryType === "NFTokenOffer" && fields.Owner && baitByAddress.has(fields.Owner)) {
        return baitByAddress.get(fields.Owner);
      }
    }
  }
  return null;
}

// Race-sicheres Anlegen/Aktualisieren eines Threats (MEDIUM 11):
// Das Objekt wird synchron in die Map eingefügt und danach IN PLACE
// mutiert — ein paralleler handleTx-Aufruf liest dasselbe Objekt und
// mergt seine Evidenz hinein, statt es zu ersetzen. Das await von
// traceFunding kann so keine Evidence mehr verlieren.
function upsertThreat({ address, risk, reason, evidence, time }) {
  let t = threats.get(address);
  let isNew = false;
  let escalated = false;
  let fundingNeeded = false;
  if (!t) {
    t = { address, risk, reason, evidence: [], firstSeen: time, funding: [] };
    threats.set(address, t);
    isNew = true;
    fundingNeeded = true;
  } else {
    if (risk === "malicious" && t.risk !== "malicious") {
      t.risk = "malicious";
      t.reason = reason;
      escalated = true;
      fundingNeeded = true; // Funding-Label bei Hochstufung auffrischen (MEDIUM 12)
    }
    // firstSeen = Ledger-Zeit der frühesten Evidence (MEDIUM 16)
    if (time && (!t.firstSeen || time < t.firstSeen)) t.firstSeen = time;
  }
  if (!t.evidence.some((e) => e.txHash === evidence.txHash)) {
    t.evidence.push(evidence);
  }
  if (!Array.isArray(t.funding) || t.funding.length === 0) fundingNeeded = true;
  return { isNew, escalated, fundingNeeded };
}

async function handleTx(event) {
  // xrpl.js 4.x liefert im 'transaction'-Event die rohe Stream-Nachricht:
  // { hash, tx_json: {...}, meta, close_time_iso, validated, ... }.
  if (!event) return;
  if (event.validated !== true) return; // MEDIUM 8: nur validierte Transaktionen
  const tx = event.tx_json ?? event;
  const txHash = event.hash ?? tx.hash ?? tx.Hash;
  if (!txHash) return;
  if (seenTxHashes.has(txHash)) return; // MEDIUM 8: Deduplizierung pro txHash
  seenTxHashes.add(txHash);

  const txType = tx.TransactionType;
  const isBait = (a) => baitByAddress.has(a);
  const time = eventTime(event, tx);
  const shortHash = String(txHash).slice(0, 8);

  // ---------- Fall A: ein Köder-Konto hat selbst initiiert ----------
  if (isBait(tx.Account)) {
    const hpLabel = baitByAddress.get(tx.Account);

    // Interne Bewegung Köder -> Köder: ignorieren.
    if (tx.Destination && isBait(tx.Destination)) return;

    // Betriebszahlung an eigene Infrastruktur des Betreibers: kein Threat
    // (LOW 15 — False-Positive-Schutz für Sweep-/Cold-Wallets).
    if (tx.Destination && operatorAddresses.has(tx.Destination)) {
      log(`Betriebszahlung ignoriert: ${hpLabel} -> Operator-Adresse (${txType}, hash=${shortHash})`);
      return;
    }

    // DEX-Aktivität des Köders: Gegenpartei unbekannt -> suspect, Reason
    // ohne Adressen (MEDIUM 9b).
    if (txType === "OfferCreate" || txType === "OfferCancel") {
      const rec = upsertThreat({
        address: tx.Account, // intern die Köder-Adresse; der Server ersetzt sie öffentlich durch das Label
        risk: "suspect",
        reason: `${hpLabel} initiierte ${txType} gegen das DEX-Orderbuch (Gegenpartei unbekannt)`,
        evidence: { txHash, type: txType, time, honeypot: hpLabel },
        time,
      });
      saveThreats();
      log(`Ereignis: ${txType} · risk=suspect · honeypot=${hpLabel} (Orderbuch, Gegenpartei unbekannt) · hash=${shortHash} · neu=${rec.isNew}`);
      return;
    }

    // Kompromittierungs-Alarm (MEDIUM 9a): Köder initiiert selbst
    // (Payment an extern, AccountSet, AccountDelete, SetRegularKey, ...).
    // Die Zieladresse wird bewusst NICHT öffentlich — Reason-Text ohne Adresse.
    const rec = upsertThreat({
      address: tx.Account,
      risk: "malicious",
      reason: `${hpLabel} initiierte ${txType}-Transaktion selbst (mögliche Kompromittierung)`,
      evidence: { txHash, type: txType, time, honeypot: hpLabel },
      time,
    });
    if (rec.fundingNeeded) {
      // Köder-Konten wurden vom Faucet finanziert — Funding ist benign/leer;
      // kein traceFunding nötig. Feld bleibt explizit leer.
      threats.get(tx.Account).funding = [];
    }
    saveThreats();
    log(`ALARM: ${hpLabel} initiierte ${txType} selbst (mögliche Kompromittierung) · risk=malicious · hash=${shortHash} · neu=${rec.isNew}`);
    return;
  }

  // ---------- Fall B: externe Transaktion berührt ein Köder-Konto ----------
  let hpLabel = null;
  let viaOrderbook = false;
  if (tx.Destination && isBait(tx.Destination)) {
    hpLabel = baitByAddress.get(tx.Destination);
  } else if (tx.LimitAmount?.issuer && isBait(tx.LimitAmount.issuer)) {
    hpLabel = baitByAddress.get(tx.LimitAmount.issuer); // TrustSet gegen Köder-Issuer
  } else {
    hpLabel = metaFindBait(event); // Offer/NFTokenOffer-Ledger-Objekte des Köders (MEDIUM 9b/9c)
    viaOrderbook = hpLabel !== null;
  }
  // Erreicht keine der Regeln den Köder (z. B. Path-Payment-Zwischenhop),
  // wird nichts erfasst — dokumentierte Grenze, siehe README.
  if (!hpLabel) return;

  const counterparty = tx.Account;
  if (!counterparty || isBait(counterparty)) return; // interne Bewegung zwischen Ködern ignorieren

  const malicious = txType === "Payment" || txType === "TrustSet";
  const risk = malicious ? "malicious" : "suspect";
  const reason = viaOrderbook
    ? `Externe ${txType}-Transaktion gegen das Orderbuch von ${hpLabel}`
    : `Externe ${txType}-Transaktion an ${hpLabel}`;

  const rec = upsertThreat({
    address: counterparty,
    risk,
    reason,
    evidence: { txHash, type: txType, time, honeypot: hpLabel },
    time,
  });

  // Funding NACH dem synchronen Upsert — das Store-Objekt wird danach
  // erneut aus der Map gelesen und gemergt (Race-Schutz, MEDIUM 11).
  if (rec.fundingNeeded) {
    const funding = await traceFunding(counterparty, 2);
    const fresh = threats.get(counterparty); // erneut lesen statt ersetzen
    if (fresh) {
      if (rec.escalated || !fresh.funding?.length) fresh.funding = funding;
    }
  }

  saveThreats();
  log(`Ereignis: ${txType} · risk=${risk} · Gegenpartei=${counterparty} · honeypot=${hpLabel}${viaOrderbook ? " (Orderbuch)" : ""} · hash=${shortHash}`);
}

async function main() {
  await client.connect();
  log(`Verbunden mit ${config.network} (${config.wss})`);
  log(
    `Beobachte ${baitByAddress.size} Köder-Konten (UNION bait.json + bait-history.json, ` +
      `Labels: ${[...baitByAddress.values()].join(", ")})`
  );

  client.on("transaction", (tx) => {
    handleTx(tx).catch((err) => log(`Fehler bei Transaktionsverarbeitung: ${err.message}`));
  });
  client.on("error", (err) => log(`WSS-Fehler: ${err?.message ?? String(err)}`));

  await client.request({
    command: "subscribe",
    accounts: [...baitByAddress.keys()],
  });
  log("Alle Köder-Konten abonniert. Monitor läuft.");
}

process.on("SIGINT", () => {
  log("Monitor beendet (SIGINT).");
  try {
    client.disconnect();
  } catch {
    /* ignore */
  }
  saveThreats();
  process.exit(0);
});

main().catch((err) => {
  console.error(`[monitor] Start fehlgeschlagen: ${err.message}`);
  process.exit(1);
});
