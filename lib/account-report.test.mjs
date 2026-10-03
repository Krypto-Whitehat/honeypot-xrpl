// lib/account-report.test.mjs — Unit-Tests für buildAccountReport.
// Offline: keine Netzwerk-Calls, nur synthetische Fixtures (rTEST…-Adressen).
// Entry-Form {tx_json, close_time_iso, hash, ledger_index, validated} wie
// account_tx (binary:false). Keine Köder-Adressen, keine Seeds, keine Literale
// aus bait.json/bait-history.json.
import test from "node:test";
import assert from "node:assert/strict";
import { buildAccountReport, ACCOUNT_REPORT_DISCLAIMERS } from "./account-report.mjs";
import { getThreatKnowledge, buildCheckCtx } from "./threats-service.mjs";

// ---------- Fixtures ----------
const T = "rTESTTARGET000000000000000000000A"; // geprüfte Adresse
const M1 = "rTESTMALICIOUS000000000000000001B"; // gelistet: malicious
const M2 = "rTESTMALICIOUS000000000000000002B";
const S1 = "rTESTSUSPECT0000000000000000003C"; // gelistet: suspect
const P1 = "rTESTPEER0000000000000000000004D"; // ungelistet
const P2 = "rTESTPEER0000000000000000000005D";
const P3 = "rTESTPEER0000000000000000000006D";
const P4 = "rTESTPEER0000000000000000000007D";
const A = "rTESTSENDER0000000000000000008E";
const B = "rTESTSENDER0000000000000000009E";
const C = "rTESTSENDER0000000000000000010E";
const EX = "rTESTEXFIL00000000000000000011F";

let seq = 0;
function payEntry(from, to, amount, opts = {}) {
  seq += 1;
  const tx = {
    TransactionType: "Payment",
    Account: from,
    Destination: to,
    Amount: String(amount),
  };
  if (opts.memos) tx.Memos = opts.memos;
  if (opts.validated === false) {
    return { hash: `H${seq}`, ledger_index: 49000000 + seq, validated: false, tx_json: tx };
  }
  return {
    hash: `H${String(seq).padStart(4, "0")}`,
    ledger_index: 49000000 + seq,
    close_time_iso: opts.time ?? `2026-09-28T10:00:0${seq % 10}Z`,
    validated: true,
    tx_json: tx,
  };
}

function hex(s) {
  let out = "";
  for (let i = 0; i < s.length; i++) out += s.charCodeAt(i).toString(16).padStart(2, "0");
  return out.toUpperCase();
}
const PHISH_MEMO = [{ Memo: { MemoData: hex("claim your airdrop now http://scam.example") } }];

function threats(map) {
  return new Map(Object.entries(map));
}
function mal(reason = "Externe Payment-Transaktion an Köder #1", firstSeen = null) {
  return { risk: "malicious", reason, firstSeen };
}

// Deterministischer Pseudo-Shuffle (LCG, fester Seed) für den
// Eingabereihenfolge-Test — kein Math.random (nicht deterministisch).
function seededShuffle(arr, seed) {
  const a = [...arr];
  let s = seed;
  for (let i = a.length - 1; i > 0; i--) {
    s = (s * 1103515245 + 12345) % 2147483648;
    const j = s % (i + 1);
    [a[i], a[j]] = [a[j], a[i]];
  }
  return a;
}

// ---------- Tests ----------

test("sauberes Konto: Score 100, verdict clean, eligibility ok, keine Muster/Rolle", () => {
  const entries = [
    payEntry(T, P1, "25000000"),
    payEntry(T, P2, "25000000"),
    payEntry(P3, T, "18000000"),
  ];
  const r = buildAccountReport({
    address: T,
    network: "mainnet",
    entries,
    threatsByAddress: threats({}),
    truncated: false,
    checkedTxCount: entries.length,
  });
  assert.equal(r.address, T);
  assert.equal(r.network, "mainnet");
  assert.equal(r.checkedTxCount, 3);
  assert.equal(r.truncated, false);
  assert.equal(r.selfListed, false);
  assert.equal(r.verdict, "clean");
  assert.equal(r.score, 100);
  assert.deepEqual(r.contacts, []);
  assert.deepEqual(r.patterns, []);
  assert.equal(r.role, null);
  assert.equal(r.roleMetrics, null);
  assert.equal(r.eligibility, "ok");
  assert.equal(r.eligibilityReason, "Voraussichtlich unproblematisch für Off-Ramps (heuristisch).");
  assert.deepEqual(r.disclaimers, ACCOUNT_REPORT_DISCLAIMERS);
  assert.equal(r.disclaimers.length, 4);
});

test("15/5-Abzüge je DISTINCT Risiko-Gegenpartei (nicht je Transaktion)", () => {
  const entries = [
    payEntry(T, M1, "1000000"),
    payEntry(T, M1, "2000000"), // zweite Zahlung an dieselbe Adresse
    payEntry(T, S1, "1000000"),
  ];
  const r = buildAccountReport({
    address: T,
    network: "mainnet",
    entries,
    threatsByAddress: threats({ [M1]: mal(), [S1]: { risk: "suspect", reason: "Verdacht", firstSeen: null } }),
    truncated: false,
    checkedTxCount: entries.length,
  });
  assert.equal(r.verdict, "contact");
  assert.equal(r.score, 80); // 100 − 15·1 − 5·1
  assert.equal(r.contacts.length, 3);
  assert.deepEqual(r.criteria[0].evidence, [M1]);
  assert.deepEqual(r.criteria[1].evidence, [S1]);
  assert.deepEqual(r.scoreBreakdown, [
    { kriterium: "Kontakte zu bekannten Malicious-Adressen (verschiedene Gegenparteien)", wert: 1, abzug: 15 },
    { kriterium: "Kontakte zu Verdachts-Adressen (verschiedene Gegenparteien)", wert: 1, abzug: 5 },
    { kriterium: "Adresse selbst in der Bedrohungsliste gelistet", wert: "nein", abzug: 0 },
  ]);
  assert.equal(r.eligibility, "review");
});

test("selfListed: verdict bad, −10 Punkte, known-bad-hit-Muster, Evidenz = Reason", () => {
  const entries = [payEntry(T, P1, "1000000")];
  const r = buildAccountReport({
    address: T,
    network: "mainnet",
    entries,
    threatsByAddress: threats({ [T]: mal("Externe Payment-Transaktion an Köder #2") }),
    truncated: false,
    checkedTxCount: entries.length,
  });
  assert.equal(r.selfListed, true);
  assert.equal(r.verdict, "bad");
  assert.equal(r.score, 90); // 100 − 10
  assert.deepEqual(r.patterns, ["known-bad-hit"]);
  assert.equal(r.eligibility, "review");
  assert.deepEqual(r.criteria[2].evidence, ["Externe Payment-Transaktion an Köder #2"]);
});

test("Untergrenze 0 und Kontakt-Cap: 60 distinct malicious-Gegenparteien", () => {
  const entries = [];
  const map = {};
  for (let i = 0; i < 60; i++) {
    const addr = `rTESTMAL${String(i).padStart(43, "0")}X`;
    map[addr] = mal();
    entries.push(payEntry(T, addr, "10000000"));
  }
  const r = buildAccountReport({
    address: T,
    network: "mainnet",
    entries,
    threatsByAddress: threats(map),
    truncated: false,
    checkedTxCount: entries.length,
  });
  assert.equal(r.score, 0); // max(0, 100 − 15·60)
  assert.equal(r.contacts.length, 50); // Anzeige-Cap
  assert.equal(r.criteria[0].evidence.length, 60); // Score-Basis bleibt vollständig
  assert.equal(r.verdict, "contact");
});

test("verdict-Mapping: bad / contact / clean / unknown", () => {
  const mk = (over = {}) =>
    buildAccountReport({
      address: T,
      network: "mainnet",
      entries: [payEntry(T, P1, "1000000")],
      threatsByAddress: threats({}),
      truncated: false,
      checkedTxCount: 1,
      ...over,
    });
  assert.equal(mk().verdict, "clean");
  assert.equal(mk({ threatsByAddress: threats({ [M1]: mal() }), entries: [payEntry(T, M1, "1")] }).verdict, "contact");
  assert.equal(mk({ threatsByAddress: threats({ [T]: mal() }) }).verdict, "bad");
  assert.equal(mk({ entries: [], checkedTxCount: 0 }).verdict, "unknown");
});

test("leere Historie: unknown statt sauber — Score null, keine Kriterien, eligibility unknown", () => {
  const r = buildAccountReport({
    address: T,
    network: "testnet",
    entries: [],
    threatsByAddress: threats({}),
    truncated: false,
    checkedTxCount: 0,
    hint: "Keine Transaktionen für diese Adresse gefunden — sie ist neu, nicht finanziert oder auf diesem Netzwerk nicht aktiviert.",
  });
  assert.equal(r.verdict, "unknown");
  assert.equal(r.score, null);
  assert.deepEqual(r.scoreBreakdown, []);
  assert.deepEqual(r.criteria, []);
  assert.equal(r.eligibility, "unknown");
  assert.equal(r.eligibilityReason, "Nicht bewertbar — keine oder unvollständige Daten.");
  assert.equal(r.zusammenfassung, "Nicht bewertbar — keine oder unvollständige Daten.");
  assert.deepEqual(r.contacts, []);
  assert.deepEqual(r.patterns, []);
  assert.equal(r.role, null);
  assert.equal(r.hint, "Keine Transaktionen für diese Adresse gefunden — sie ist neu, nicht finanziert oder auf diesem Netzwerk nicht aktiviert.");
  assert.equal(r.network, "testnet");
});

test("Rolle drainer aus Mini-Graph: 2 geflaggte Sender rein, ≥90 % an ein Ziel raus", () => {
  // Gegenparteien-Bindung (lib/cluster.mjs roleOf): ein Drainer-Fund verlangt
  // mindestens einen GEFLAGGTEN Sender — ein Konto, das nur von ungelisteten
  // Peer-Adressen erhält und weiterleitet, ist flow-seitig ein Relay.
  // Honeypot-real sind die Opfer-Geber gelistet (Kontakt zu Köder -> Fund).
  const entries = [
    payEntry(A, T, "100000000"),
    payEntry(B, T, "100000000"),
    payEntry(T, EX, "190000000"),
  ];
  const r = buildAccountReport({
    address: T,
    network: "mainnet",
    entries,
    threatsByAddress: threats({ [T]: mal(), [A]: mal(), [B]: mal() }), // Adresse gelistet -> Kanten sichtbar
    truncated: false,
    checkedTxCount: entries.length,
  });
  assert.equal(r.role, "drainer");
  assert.deepEqual(r.roleMetrics, { degreeIn: 2, degreeOut: 1, inDrops: 200000000, outDrops: 190000000 });
  assert.equal(r.verdict, "bad");
});
test("Rolle relay (FP-Regression): gleiche Form, aber alle Sender ungelistet -> kein Drainer-Label", () => {
  const entries = [
    payEntry(A, T, "100000000"),
    payEntry(B, T, "100000000"),
    payEntry(T, EX, "190000000"),
  ];
  const r = buildAccountReport({
    address: T,
    network: "mainnet",
    entries,
    threatsByAddress: threats({ [T]: mal() }), // nur T gelistet, Sender ungelistet
    truncated: false,
    checkedTxCount: entries.length,
  });
  assert.equal(r.role, "relay");
});
test("Rolle collector aus Mini-Graph: 3 verschiedene geflaggte Sender, keine ausgehende Kante", () => {
  const entries = [payEntry(A, T, "5000000"), payEntry(B, T, "5000000"), payEntry(C, T, "5000000")];
  const r = buildAccountReport({
    address: T,
    network: "mainnet",
    entries,
    threatsByAddress: threats({ [T]: mal(), [A]: mal(), [B]: mal(), [C]: mal() }),
    truncated: false,
    checkedTxCount: entries.length,
  });
  assert.equal(r.role, "collector");
  assert.deepEqual(r.roleMetrics, { degreeIn: 3, degreeOut: 0, inDrops: 15000000, outDrops: 0 });
});
test("Rolle FP-Regression: Mehrfachempfänger nur aus ungelisteten Sendern ist KEIN collector", () => {
  const entries = [payEntry(A, T, "5000000"), payEntry(B, T, "5000000"), payEntry(C, T, "5000000")];
  const r = buildAccountReport({
    address: T,
    network: "mainnet",
    entries,
    threatsByAddress: threats({ [T]: mal() }),
    truncated: false,
    checkedTxCount: entries.length,
  });
  assert.equal(r.role, "unknown");
});

test("Rolle null, wenn die Adresse nicht im Fund-Graphen steht (nicht raten)", () => {
  // Keine Findings, keine gelistete Beteiligung -> keine Kante -> kein Knoten.
  const entries = [payEntry(T, P1, "1000000"), payEntry(P2, T, "1000000")];
  const r = buildAccountReport({
    address: T,
    network: "mainnet",
    entries,
    threatsByAddress: threats({}),
    truncated: false,
    checkedTxCount: entries.length,
  });
  assert.equal(r.role, null);
  assert.equal(r.roleMetrics, null);
});

test("patterns: Dedup (mehrere Treffer gleicher Regel) und Sortierung", () => {
  const entries = [
    payEntry(T, P1, "10", { memos: PHISH_MEMO }), // tiny + Phishing-Memo
    payEntry(T, P2, "10"),                        // tiny
    payEntry(T, P3, "10", { memos: PHISH_MEMO }), // tiny + Phishing-Memo (2. Treffer)
    payEntry(T, P4, "1000000"),                   // groß (kein Dusting-Ziel)
  ];
  const r = buildAccountReport({
    address: T,
    network: "mainnet",
    entries,
    threatsByAddress: threats({}),
    truncated: false,
    checkedTxCount: entries.length,
  });
  assert.deepEqual(r.patterns, ["dusting", "memo-phishing"]); // sortiert, je Regel genau einmal
  assert.equal(new Set(r.patterns).size, r.patterns.length);
});

test("Kontakt-Felder: Richtung, Notiz, Risiko, Zeit; unvalidierte Entries werden übersprungen", () => {
  const entries = [
    payEntry(M2, T, "1000000", { time: "2026-09-28T12:00:00Z" }), // eingehend
    payEntry(T, S1, "1000000", { time: "2026-09-28T11:00:00Z" }), // ausgehend
    payEntry(T, P1, "1000000", { validated: false }),             // unvalidiert
  ];
  const r = buildAccountReport({
    address: T,
    network: "mainnet",
    entries,
    threatsByAddress: threats({
      [M2]: mal(),
      [S1]: { risk: "suspect", reason: "Verdacht", firstSeen: null },
    }),
    truncated: false,
    checkedTxCount: entries.length,
  });
  assert.equal(r.contacts.length, 2); // unvalidierte Payment zählt nicht
  // Sortierung: neueste Zeit zuerst
  assert.equal(r.contacts[0].counterparty, M2);
  assert.equal(r.contacts[0].direction, "eingehend");
  assert.equal(r.contacts[0].note, "Zahlung erhalten von");
  assert.equal(r.contacts[0].risk, "malicious");
  assert.equal(r.contacts[0].txType, "Payment");
  assert.equal(r.contacts[0].time, "2026-09-28T12:00:00Z");
  assert.equal(r.contacts[1].counterparty, S1);
  assert.equal(r.contacts[1].direction, "ausgehend");
  assert.equal(r.contacts[1].note, "Zahlung gesendet an");
  assert.equal(r.contacts[1].risk, "suspect");
});

test("{tx}-Container-Form wird wie {tx_json} akzeptiert", () => {
  const entries = [
    {
      hash: "TXFORM1",
      ledger_index: 49000001,
      close_time_iso: "2026-09-28T13:00:00Z",
      validated: true,
      tx: { TransactionType: "Payment", Account: T, Destination: M1, Amount: "1000000" },
    },
  ];
  const r = buildAccountReport({
    address: T,
    network: "mainnet",
    entries,
    threatsByAddress: threats({ [M1]: mal() }),
    truncated: false,
    checkedTxCount: 1,
  });
  assert.equal(r.verdict, "contact");
  assert.equal(r.contacts[0].counterparty, M1);
});

test("truncated-Flag und checkedTxCount werden durchgereicht", () => {
  const r = buildAccountReport({
    address: T,
    network: "mainnet",
    entries: [],
    threatsByAddress: threats({}),
    truncated: true,
    checkedTxCount: 300,
  });
  assert.equal(r.truncated, true);
  assert.equal(r.checkedTxCount, 300); // Abrufefenster bleibt durchgereicht
  // verdict 'unknown' statt 'clean': checkedTxCount zählt das ABRUFEFENSTER,
  // das verdict nur analysierte Entries — 300 abgerufene, 0 validierte
  // bedeuten null analysierte Transaktionen (Befund 2026-09-29).
  assert.equal(r.verdict, "unknown");
});

test("alle Entries unvalidiert -> verdict unknown, Score null, eligibility unknown", () => {
  // Selbst Kontakte zu Malicious-Adressen in unvalidierten Entries dürfen kein
  // 'clean'/Score 100 erzeugen: Es wurde nichts analysiert (Befund 2026-09-29).
  const entries = [
    payEntry(T, M1, "1000000", { validated: false }),
    payEntry(T, S1, "500000", { validated: false }),
  ];
  const r = buildAccountReport({
    address: T,
    network: "mainnet",
    entries,
    threatsByAddress: threats({
      [M1]: mal(),
      [S1]: { risk: "suspect", reason: "Verdacht", firstSeen: null },
    }),
    truncated: false,
    checkedTxCount: entries.length, // wie api/account-report.js (rohe Liste)
  });
  assert.equal(r.verdict, "unknown");
  assert.equal(r.score, null);
  assert.deepEqual(r.scoreBreakdown, []);
  assert.deepEqual(r.criteria, []);
  assert.equal(r.eligibility, "unknown");
  assert.deepEqual(r.contacts, []);
  assert.equal(r.checkedTxCount, 2); // Abrufefenster bleibt sichtbar und ehrlich
});

test("deterministische Ausgabe bei Entry-Shuffle (Reversal, Rotation, Seed-Shuffle)", () => {
  const entries = [
    payEntry(T, M1, "1000000", { time: "2026-09-28T09:00:00Z" }),
    payEntry(M1, T, "1000000", { time: "2026-09-28T09:05:00Z" }),
    payEntry(T, S1, "500000", { time: "2026-09-28T09:10:00Z" }),
    payEntry(T, P1, "7000000", { time: "2026-09-28T09:15:00Z" }),
    payEntry(P2, T, "3000000", { time: "2026-09-28T09:20:00Z" }),
    payEntry(T, M2, "2000000", { time: "2026-09-28T09:25:00Z" }),
    payEntry(S1, T, "800000", { time: "2026-09-28T09:30:00Z" }),
  ];
  const input = {
    address: T,
    network: "mainnet",
    threatsByAddress: threats({
      [M1]: mal(),
      [M2]: mal(),
      [S1]: { risk: "suspect", reason: "Verdacht", firstSeen: null },
    }),
    truncated: false,
    checkedTxCount: entries.length,
  };
  const base = JSON.stringify(buildAccountReport({ ...input, entries }));
  const reversed = JSON.stringify(buildAccountReport({ ...input, entries: [...entries].reverse() }));
  const rotated = JSON.stringify(buildAccountReport({ ...input, entries: [...entries.slice(3), ...entries.slice(0, 3)] }));
  const shuffled = JSON.stringify(buildAccountReport({ ...input, entries: seededShuffle(entries, 42) }));
  assert.equal(reversed, base);
  assert.equal(rotated, base);
  assert.equal(shuffled, base);
});

// ============================================================================
// Wissens-Layer (Runde 3): knownBad/firstSeenAt/history aus buildCheckCtx,
// Peeling-Ketten in patterns, contacts[].source + knowledgeSources.
// criteria/scoreBreakdown-Struktur/-Labels bleiben unverändert (Regression).
// ============================================================================

// base58-sicher (kein 0/O/I/l) und 25-35 Zeichen — XRPL_ADDR-Konvention.
const PC1 = "rTESTPEKSEEDAAAAAAAAAAAAAA1"; // Seed der Peeling-Kette
const PC2 = "rTESTPEKB1AAAAAAAAAAAAAAA2"; // Brücke 1
const PC3 = "rTESTPEKB2AAAAAAAAAAAAAAA3"; // Brücke 2
const PC4 = "rTESTPEKB3AAAAAAAAAAAAAAA4"; // Brücke 3
const PC5 = "rTESTPEKENDAAAAAAAAAAAAAA5"; // geflaggter Endpunkt
const FRESH1 = "rTESTFRESH1AAAAAAAAAAAAAA6"; // frisch finanziert (history-Seed)
const SWEEPTO = "rTESTSWEEPTXAAAAAAAAAAAA7";
const DUST1 = "rTESTDUSTTGTAAAAAAAAAAAAA8"; // frisches Dusting-Ziel
const DUST2 = "rTESTDUSTTGTAAAAAAAAAAAA9";
const DUST3 = "rTESTDUSTTGTAAAAAAAAAAAAB";
const HISTONLY = "rTESTHISTRCKAAAAAAAAAAAA9"; // nur über history gelistet

// Payment-Eintrag mit Meta (CreatedNode AccountRoot) — Form wie
// lib/threats-service.test.mjs fundingEntry.
function payEntryWithCreate(from, to, amount, opts = {}) {
  seq += 1;
  return {
    hash: `H${String(seq).padStart(4, "0")}`,
    ledger_index: 49000000 + seq,
    close_time_iso: opts.time ?? `2026-09-28T10:00:0${seq % 10}Z`,
    validated: true,
    tx_json: { TransactionType: "Payment", Account: from, Destination: to, Amount: String(amount) },
    meta: {
      AffectedNodes: [
        { CreatedNode: { LedgerEntryType: "AccountRoot", LedgerEntry: { Account: to } } },
      ],
    },
  };
}

test("knownBad aus Engine-ctx: suspect-Gegenpartei -> known-bad-hit auf GEGENPARTEI (nicht auf T), Score-Abzug bleibt 5", () => {
  // knownBad-Union erreicht die Detektor-Engine: der Fund trägt die Adresse
  // der gelisteten Gegenpartei (detector.mjs:325-338, actorsOf) — Muster auf
  // T bleiben davon unberührt (Attributionsgrenze, Muster-Bericht nur für
  // Funde auf der geprüften Adresse).
  const entries = [payEntry(T, S1, "1000000")];
  const r = buildAccountReport({
    address: T,
    network: "mainnet",
    entries,
    threatsByAddress: threats({ [S1]: { risk: "suspect", reason: "Verdacht", firstSeen: null } }),
    knownBad: new Set([S1]),
    truncated: false,
    checkedTxCount: entries.length,
  });
  assert.equal(r.verdict, "contact");
  assert.equal(r.score, 95); // 100 − 5·1 (suspect-Gegenpartei, kein malicious-Abzug)
  assert.deepEqual(r.patterns, [], "kein Fund auf T — known-bad-hit trägt S1");
  assert.deepEqual(r.scoreBreakdown, [
    { kriterium: "Kontakte zu bekannten Malicious-Adressen (verschiedene Gegenparteien)", wert: 0, abzug: 0 },
    { kriterium: "Kontakte zu Verdachts-Adressen (verschiedene Gegenparteien)", wert: 1, abzug: 5 },
    { kriterium: "Adresse selbst in der Bedrohungsliste gelistet", wert: "nein", abzug: 0 },
  ]);
});

test("Peeling-Kette: geprüfte Adresse ist Seed -> 'peeling-chain' in patterns (PEELING_THRESHOLDS unverändert)", () => {
  // 4 Hops, Ratio 0.8 je Relay (Fenster [0.6, 0.95]). Kettenregel
  // (lib/cluster.mjs:746-753): eine Kette verläuft von Seed zu geflaggtem
  // ENDpunkt — beide Enden müssen Funde tragen (Regression P1 in
  // lib/cluster.test.mjs:610). Beide Enden sind hier gelistet -> Funde auf
  // Seed und Endpunkt; die geprüfte Adresse ist der Seed.
  const entries = [
    payEntry(PC1, PC2, "10000"),
    payEntry(PC2, PC3, "8000"),
    payEntry(PC3, PC4, "6400"),
    payEntry(PC4, PC5, "5120"),
  ];
  const r = buildAccountReport({
    address: PC1,
    network: "mainnet",
    entries,
    threatsByAddress: threats({
      [PC1]: { risk: "suspect", reason: "Verdacht", firstSeen: null },
      [PC5]: { risk: "suspect", reason: "Verdacht", firstSeen: null },
    }),
    truncated: false,
    checkedTxCount: entries.length,
  });
  assert.ok(r.patterns.includes("peeling-chain"), `patterns: ${JSON.stringify(r.patterns)}`);
});

test("Peeling-Kette: geprüfte Adresse nur Brückenknoten -> KEIN 'peeling-chain' (Attribution, bridges sind ungeflaggt)", () => {
  // Dieselbe Kette mit geflaggten Enden — die geprüfte Adresse PC3 ist nur
  // Brücke (chain.bridges, cluster.mjs:904: Brücken sind per Definition
  // ungeflaggt, PC3 ist hier NICHT gelistet).
  const entries = [
    payEntry(PC1, PC2, "10000"),
    payEntry(PC2, PC3, "8000"),
    payEntry(PC3, PC4, "6400"),
    payEntry(PC4, PC5, "5120"),
  ];
  const r = buildAccountReport({
    address: PC3, // nur Brücke in der Kette PC1→…→PC5
    network: "mainnet",
    entries,
    threatsByAddress: threats({
      [PC1]: { risk: "suspect", reason: "Verdacht", firstSeen: null },
      [PC5]: { risk: "suspect", reason: "Verdacht", firstSeen: null },
    }),
    truncated: false,
    checkedTxCount: entries.length,
  });
  assert.ok(!r.patterns.includes("peeling-chain"), `Brücke darf nicht attribuieren: ${JSON.stringify(r.patterns)}`);
});

test("history-Seed fundedAt: Sweep im Fenster auf früher gefüttertes Konto -> drainer-sweep (Cross-Ledger)", () => {
  // Die Finanzierung selbst liegt AUSSERHALB des Fensters; nur der Sweep
  // (95 % der 100 000 drops aus ctx.history.fundedAt) ist im Fenster.
  const entries = [payEntry(FRESH1, SWEEPTO, "95000")];
  const r = buildAccountReport({
    address: FRESH1,
    network: "mainnet",
    entries,
    threatsByAddress: threats({}),
    knownBad: new Set([FRESH1]),
    firstSeenAt: new Map([[FRESH1, Date.now() - 60_000]]),
    history: new Map([[FRESH1, { tinyDests: new Set(), fundedAt: 100_000, createdInWindow: true, lastLedger: null }]]),
    truncated: false,
    checkedTxCount: entries.length,
  });
  assert.ok(r.patterns.includes("drainer-sweep"), `patterns: ${JSON.stringify(r.patterns)}`);
});

test("clusterFirstSeenAt: Frische-Signal für ungelistete Adresse -> dusting-fresh (2 frische Mini-Zahlungen)", () => {
  const entries = [
    payEntry(T, DUST1, "10"),
    payEntry(T, DUST2, "10"),
  ];
  const r = buildAccountReport({
    address: T,
    network: "mainnet",
    entries,
    threatsByAddress: threats({}),
    clusterFirstSeenAt: new Map([
      [T, Date.now() - 60_000],
      [DUST1, Date.now() - 60_000],
      [DUST2, Date.now() - 60_000],
    ]),
    truncated: false,
    checkedTxCount: entries.length,
  });
  assert.ok(r.patterns.includes("dusting"), `patterns: ${JSON.stringify(r.patterns)}`);
});

test("history-only gelistete Adresse: selfListed 'bad', −10, contacts[].source 'history', knowledgeSources", () => {
  const entries = [payEntry(HISTONLY, P1, "1000000")];
  const r = buildAccountReport({
    address: HISTONLY,
    network: "mainnet",
    entries,
    threatsByAddress: threats({
      [HISTONLY]: {
        risk: "malicious",
        reason: "In der öffentlichen Maliziös-Historie gelistet (Clusterfixture).",
        firstSeen: null,
        sources: ["history"],
      },
    }),
    truncated: false,
    checkedTxCount: entries.length,
  });
  assert.equal(r.selfListed, true);
  assert.equal(r.verdict, "bad");
  assert.equal(r.score, 90); // 100 − 10 (self-listed)
  assert.deepEqual(r.knowledgeSources, ["history"]);
  assert.ok(r.patterns.includes("known-bad-hit"));
});

test("contacts[].source + knowledgeSources: Quelle der gelisteten Gegenpartei (additiv, Score unverändert)", () => {
  const entries = [
    payEntry(T, M1, "1000000"),
    payEntry(T, S1, "1000000"),
  ];
  const r = buildAccountReport({
    address: T,
    network: "mainnet",
    entries,
    threatsByAddress: threats({
      [M1]: { risk: "malicious", reason: "Externe Payment-Transaktion an Köder #1", firstSeen: null, sources: ["bait", "history"] },
      [S1]: { risk: "suspect", reason: "Live-Engine", firstSeen: null, sources: ["flow-state"] },
    }),
    truncated: false,
    checkedTxCount: entries.length,
  });
  assert.equal(r.contacts.length, 2);
  const byCp = Object.fromEntries(r.contacts.map((c) => [c.counterparty, c.source]));
  assert.equal(byCp[M1], "bait", "erste Quelle gewinnt (sources[0])");
  assert.equal(byCp[S1], "flow-state");
  assert.deepEqual(r.knowledgeSources, ["bait", "flow-state", "history"]);
  assert.equal(r.score, 80); // 100 − 15 − 5 — unverändert
});

test("Regression: criteria/scoreBreakdown-Struktur und -Labels bei Engine-ctx unverändert", () => {
  const entries = [
    payEntry(T, M1, "1000000"),
    payEntry(T, S1, "1000000"),
  ];
  const r = buildAccountReport({
    address: T,
    network: "mainnet",
    entries,
    threatsByAddress: threats({ [M1]: mal(), [S1]: { risk: "suspect", reason: "Verdacht", firstSeen: null } }),
    knownBad: new Set([M1, S1]),
    firstSeenAt: new Map([[M1, Date.now() - 3_600_000]]),
    history: new Map(),
    truncated: false,
    checkedTxCount: entries.length,
  });
  assert.deepEqual(r.scoreBreakdown, [
    { kriterium: "Kontakte zu bekannten Malicious-Adressen (verschiedene Gegenparteien)", wert: 1, abzug: 15 },
    { kriterium: "Kontakte zu Verdachts-Adressen (verschiedene Gegenparteien)", wert: 1, abzug: 5 },
    { kriterium: "Adresse selbst in der Bedrohungsliste gelistet", wert: "nein", abzug: 0 },
  ]);
  assert.equal(r.criteria.length, 3);
  assert.deepEqual(r.criteria.map((c) => c.id), ["known-bad-contacts", "suspect-contacts", "self-listed"]);
  assert.equal(r.score, 80);
});

// Registry-Guard im Report-Pfad (Prüfer-Befund 2026-10-03): der Exchange-
// Registry-Ausschluss wird im Resolver (getThreatKnowledge) auf der
// Wissens-Map selbst angewandt — buildAccountReport erhält sie bereits
// registry-frei und fügt sie über die knownBad-Union auch nicht wieder
// hinzu. data/history.json enthält reale Exchange-Hot-Wallets als Members;
// eine Berührung einer solchen Adresse darf den Score nicht drücken.
test("Registry-Guard im Report-Pfad: Exchange-Hot-Wallet aus history ist weder Kontakt noch knownBad", async () => {
  const REG_BINANCE = "rEb8TK3gBgk5auZkwc6sHnwrGVJH8DuaLh"; // Exchange-Registry (Binance, hot)
  const opts = {
    readThreats: async () => [],
    readHistory: async () => ({
      list: [
        {
          members: [REG_BINANCE, M1],
          label: "Clusterfixture",
          firstSeen: Date.parse("2026-09-01T00:00:00Z"),
          lastSeen: Date.parse("2026-09-20T00:00:00Z"),
          rules: ["known-bad-hit"],
          severity: "malicious",
        },
      ],
    }),
    readFlowState: async () => ({ doc: null }),
  };
  const kr = await getThreatKnowledge(opts);
  assert.ok(!kr.knowledge.has(REG_BINANCE), "Registry-Treffer ist aus der Wissens-Map entfernt");
  assert.ok(kr.knowledge.has(M1), "Nicht-Registry-Mitglied bleibt gelistet");
  const ctx = buildCheckCtx(kr);
  assert.ok(!ctx.knownBad.has(REG_BINANCE), "Registry-Adresse ist nicht in knownBad");
  const entries = [payEntry(T, REG_BINANCE, "1000000"), payEntry(T, M1, "1000000")];
  const r = buildAccountReport({
    address: T,
    network: "mainnet",
    entries,
    threatsByAddress: kr.knowledge,
    knownBad: ctx.knownBad,
    firstSeenAt: ctx.firstSeenAt,
    history: ctx.history,
    truncated: false,
    checkedTxCount: entries.length,
  });
  assert.equal(r.contacts.length, 1, "nur die Nicht-Registry-Gegenpartei zählt als Kontakt");
  assert.equal(r.contacts[0].counterparty, M1);
  assert.equal(r.score, 85, "100 − 15 (malicious Kontakt M1) — die Exchange-Adresse drückt den Score nicht");
});
