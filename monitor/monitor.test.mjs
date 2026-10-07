// monitor.test.mjs — Unit A: Touch-to-Sweep-Loop (Offline-Fixtures)
//
// Prüft die Drainer-Eskalation des kontinuierlichen Monitors OHNE Live-
// Netzwerk: die account_tx-Abfrage wird über setSweepFetch durch
// synthetische Ledger-Fixtures ersetzt. Der xrpl-Client bleibt dabei
// unverbunden (Client.request lehnt sofort mit NotConnectedError ab, den
// der Monitor bereits fängt) — es findet kein Netzwerkzugriff statt.
//
// Lauf: node --test monitor/monitor.test.mjs
//
// Konventionen:
//   * Synthetische Adressen (base58-sicher, klassische Länge) — pro Test
//     eindeutig, damit seenTxHashes-/Threat-Store-Zustände nicht
//     kreuzkontaminieren.
//   * data/threats.json wird nach dem Lauf wiederhergestellt.
//   * Köder-Adresse und -Label werden zur Laufzeit aus bait.json gelesen
//     (nur address/label — Seeds bleiben unangetastet).

import test from "node:test";
import assert from "node:assert";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

const monitor = await import("./monitor.mjs");
const {
  handleTx,
  checkDrainerSweep,
  measureSweepRatio,
  getThreat,
  setSweepFetch,
} = monitor;

// ---------- Köder (nur address/label — Seeds bleiben unangetastet) ----------
const baitFile = JSON.parse(fs.readFileSync(path.join(ROOT, "bait.json"), "utf8"));
const BAIT = baitFile[0].address;
const BAIT_LABEL = baitFile[0].label;

// ---------- Threat-Store: Originalstand sichern, nach dem Lauf wiederherstellen ----------
const THREATS_FILE = path.join(ROOT, "data", "threats.json");
const originalThreats = fs.readFileSync(THREATS_FILE, "utf8");
test.after(() => {
  fs.writeFileSync(THREATS_FILE, originalThreats);
});

// ---------- Synthetische Adressen (einzigartig pro Test, base58-sicher) ----------
const TOUCHER_A = `rTESTSWEEPER${"A".repeat(21)}1`;
const TOUCHER_B = `rTESTSWEEPER${"B".repeat(21)}2`;
const TOUCHER_C = `rTESTSWEEPER${"C".repeat(21)}3`;
const TOUCHER_D = `rTESTSWEEPER${"D".repeat(21)}4`;
const TOUCHER_E = `rTESTSWEEPER${"E".repeat(21)}5`;
const COLLECTOR = `rTESTSUMPX${"A".repeat(24)}6`;
const FUNDER = `rTESTFUNDER${"A".repeat(23)}7`;
const NFT_MINTER = `rTESTNFTMINTR${"A".repeat(22)}8`;

// ---------- Zeitstempel ----------
const NOW_ISO = new Date(Date.now() - 30_000).toISOString(); // frisch
const OLD_ISO = new Date(Date.now() - 3 * 86_400_000).toISOString(); // 3 Tage alt

// ---------- Fixtures ----------
let seq = 0;

// Ausgehender Sweep: toucher -> COLLECTOR. prevBal (optional) wird als
// AccountRoot PreviousFields.Balance in der Meta getragen — dieselbe Form,
// die lib/detector.mjs' prevBalanceOf liest.
function sweepEntry(toucher, drops, prevBal, time) {
  seq += 1;
  const tx = {
    TransactionType: "Payment",
    Account: toucher,
    Destination: COLLECTOR,
    Amount: String(drops),
  };
  return {
    hash: `TESTSWEEP${String(seq).padStart(3, "0")}`,
    ledger_index: 49_000_000 + seq,
    close_time_iso: time,
    validated: true,
    tx_json: tx,
    meta:
      prevBal != null
        ? {
            AffectedNodes: [
              {
                ModifiedNode: {
                  LedgerEntryType: "AccountRoot",
                  PreviousFields: { Balance: String(prevBal) },
                  FinalFields: { Balance: String(Math.max(0, prevBal - drops)) },
                },
              },
            ],
          }
        : null,
  };
}

// Funding: FUNDER -> toucher (Präcondition der Sweep-Regel).
function fundingEntry(toucher, drops, time) {
  seq += 1;
  return {
    hash: `TESTFUND${String(seq).padStart(3, "0")}`,
    ledger_index: 49_000_000 + seq,
    close_time_iso: time,
    validated: true,
    tx_json: {
      TransactionType: "Payment",
      Account: FUNDER,
      Destination: toucher,
      Amount: String(drops),
    },
    meta: null,
  };
}

// Berührungs-Ereignis: toucher -> Köder (der Trigger des Monitors).
function touchEvent(toucher, hash, time) {
  return {
    hash,
    validated: true,
    close_time_iso: time,
    tx_json: {
      TransactionType: "Payment",
      Account: toucher,
      Destination: BAIT,
      Amount: "1",
    },
  };
}

// ---------- Tests ----------

test("touch -> ausgehender Sweep >= 0.9 -> CONFIRMED Drainer (Unit-Vertrag)", async () => {
  const entries = [
    sweepEntry(TOUCHER_A, 95_000, 100_000, NOW_ISO),
    fundingEntry(TOUCHER_A, 100_000, NOW_ISO),
  ];
  setSweepFetch(async () => entries);
  await handleTx(touchEvent(TOUCHER_A, "TESTTOUCHHASH0001", NOW_ISO));
  const t = getThreat(TOUCHER_A);
  assert.ok(t, "Threat-Eintrag für den Berührer existiert");
  assert.equal(t.risk, "malicious");
  assert.equal(t.drainer, true);
  assert.equal(typeof t.sweepRatio, "number");
  assert.ok(t.sweepRatio >= 0.9, `sweepRatio ${t.sweepRatio} erwartet >= 0.9`);
  assert.ok(t.reason.startsWith("Drainer-Sweep:"), `reason: ${t.reason}`);
  assert.ok(!t.reason.includes(BAIT), "Reason enthält keine Köder-Adresse");
  assert.ok(!t.reason.includes(BAIT_LABEL), "Reason enthält kein Köder-Label");
});

test("touch -> niedriger ausgehender Sweep -> bleibt malicious, KEIN Drainer", async () => {
  const entries = [
    sweepEntry(TOUCHER_B, 50_000, 100_000, NOW_ISO),
    fundingEntry(TOUCHER_B, 100_000, NOW_ISO),
  ];
  setSweepFetch(async () => entries);
  await handleTx(touchEvent(TOUCHER_B, "TESTTOUCHHASH0002", NOW_ISO));
  const t = getThreat(TOUCHER_B);
  assert.ok(t, "Threat-Eintrag für den Berührer existiert");
  assert.equal(t.risk, "malicious");
  assert.equal(t.drainer, undefined);
  assert.equal(t.sweepRatio, undefined);
  assert.ok(!String(t.reason).startsWith("Drainer-Sweep:"), `reason: ${t.reason}`);
});

// Fake-Mint im Namen eines Köders: NFTokenMint mit optionalem Issuer-Feld
// ("The issuer of the token, if the sender of the account is issuing it on
// behalf of another account", xrpl.org NFTokenMint-Referenz) — Spiegel der
// Detector-Regel (lib/detector.mjs:371, Fund-Adresse = Issuer), die der
// Touch-Pfad seit dem Lücken-Audit 2026-10-07 ebenfalls trägt.
function nftMintEvent(minter, hash, time) {
  return {
    hash,
    validated: true,
    close_time_iso: time,
    tx_json: {
      TransactionType: "NFTokenMint",
      Account: minter,
      Issuer: BAIT,
      NFTokenTaxon: 1,
    },
  };
}

test("NFTokenMint mit Köder-Issuer -> suspect Threat für den Minter (fake NFT im Ködernamen)", async () => {
  await handleTx(nftMintEvent(NFT_MINTER, "TESTNFTMINTHASH001", NOW_ISO));
  const t = getThreat(NFT_MINTER);
  assert.ok(t, "Threat-Eintrag für den Minter existiert");
  assert.equal(t.risk, "suspect", "NFTokenMint ist kein malicious-Pfad (nur Payment/TrustSet)");
  assert.ok(
    t.evidence.some((e) => e.type === "NFTokenMint"),
    "Evidenz trägt den Tx-Typ NFTokenMint"
  );
  assert.ok(!t.reason.includes(BAIT), "Reason enthält keine Köder-Adresse");
  assert.ok(
    t.evidence.some((e) => e.txHash === "TESTNFTMINTHASH001"),
    "txHash-Evidenz bleibt erhalten"
  );
});

test("Sweep >= 0.9 ohne Funding im Fenster -> keine Bestätigung (Präcondition)", async () => {
  const entries = [sweepEntry(TOUCHER_C, 95_000, 100_000, NOW_ISO)];
  setSweepFetch(async () => entries);
  const ratio = await checkDrainerSweep(TOUCHER_C, NOW_ISO);
  assert.equal(ratio, null);
});

test("alter Touch-Zeitstempel -> Frische-Präcondition nicht erfüllt -> keine Bestätigung", async () => {
  const entries = [
    sweepEntry(TOUCHER_D, 95_000, 100_000, OLD_ISO),
    fundingEntry(TOUCHER_D, 100_000, OLD_ISO),
  ];
  setSweepFetch(async () => entries);
  const ratio = await checkDrainerSweep(TOUCHER_D, OLD_ISO);
  assert.equal(ratio, null);
});

test("measureSweepRatio: prevBal-Referenz, inXrp-Fallback, leere Liste -> null", () => {
  assert.equal(
    measureSweepRatio([sweepEntry(TOUCHER_E, 90_000, 100_000, NOW_ISO)], TOUCHER_E),
    0.9
  );
  assert.equal(
    measureSweepRatio(
      [fundingEntry(TOUCHER_E, 100_000, NOW_ISO), sweepEntry(TOUCHER_E, 90_000, null, NOW_ISO)],
      TOUCHER_E
    ),
    0.9
  );
  assert.equal(measureSweepRatio([], TOUCHER_E), null);
});
