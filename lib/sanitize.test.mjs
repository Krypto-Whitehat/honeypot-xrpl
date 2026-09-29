// lib/sanitize.test.mjs — node:test-Unit-Tests der zentralen
// Anonymitätsschicht (lib/sanitize.mjs). Synthetische rTEST…-Adressen
// (keine echten, keine echten Köder — Kollision mit bait.json/
// bait-history.json per Check ausgeschlossen). Ausführen:
// node --test lib/sanitize.test.mjs
//
// Gesicherte Invarianten (Befund 2026-09-29):
//   (1) Köder-Ersetzung bleibt: jede Köder-Adresse (aktuell + historisch via
//       baitLabels-Union) wird durch ihr generisches Label 'Köder #n' ersetzt —
//       in Text, Threat-Adresse, Evidence, Funding und Graph-Knoten.
//   (2) Nicht-köder XRPL-Adressen werden unverändert vollständig durchgereicht
//       — keine Kürzung, kein Defang in der Engine (Kurzform ist allein Sache
//       der UI, public/app.js shortAddr/displayFindingAddr).
import test from "node:test";
import assert from "node:assert/strict";
import {
  honeypotPublicLabel,
  honeypotNodeId,
  sanitizeText,
  sanitizeEvidence,
  sanitizeFunding,
  sanitizeThreat,
  buildGraph,
  computeStats,
} from "./sanitize.mjs";

// Synthetische Fixtures (keine echten Adressen, keine echten Köder).
const BAIT1 = "rTESTBAIT10000000000000000000001";
const BAIT2 = "rTESTBAIT20000000000000000000002";
const ATTACKER = "rTESTATTACKER0000000000000000001";
const FAUCET = "rTESTFAUCET000000000000000000001";
const baitLabels = new Map([[BAIT1, "HP-1"], [BAIT2, "HP-2"]]);
const faucetAddresses = new Set([FAUCET]);

// ---------- 1) Text-Ebene: Köder -> Label, HP-n normalisiert ----------
test("sanitizeText: jede Köder-Adresse wird durch 'Köder #n' ersetzt, interne HP-n normalisiert", () => {
  const out = sanitizeText(`Treffer an ${BAIT1}; historisch HP-2 und ${BAIT2}.`, baitLabels);
  assert.equal(out, "Treffer an Köder #1; historisch Köder #2 und Köder #2.");
  assert.ok(!out.includes(BAIT1), "Köder-Adresse im Text durchgeleakt");
  assert.ok(!out.includes(BAIT2), "historische Köder-Adresse durchgeleakt");
  assert.ok(!out.includes("HP-1") && !out.includes("HP-2"), "internes HP-n-Label nicht normalisiert");
});

// ---------- 2) Invariante (2): Nicht-köder Adresse bleibt vollständig ----------
test("sanitizeThreat: nicht-köder Adresse unverändert vollständig (keine Kürzung/Defang)", () => {
  const t = sanitizeThreat(
    {
      address: ATTACKER,
      risk: "malicious",
      reason: `Zahlung an ${ATTACKER} mit Phishing-Memo.`,
      evidence: [],
      funding: [],
      firstSeen: "2026-09-28T10:00:00Z",
    },
    { baitLabels, faucetAddresses }
  );
  assert.equal(t.address, ATTACKER);
  assert.ok(!t.address.includes("…"), "Adresse gekürzt (Ellipsis) statt voll");
  assert.equal(t.reason, `Zahlung an ${ATTACKER} mit Phishing-Memo.`);
  assert.equal(t.firstSeen, "2026-09-28T10:00:00Z");
});

// ---------- 3) Invariante (1): Köder-Adresse im Threat -> Label ----------
test("sanitizeThreat: Köder-Adresse -> 'Köder #1', niemals die Adresse", () => {
  const t = sanitizeThreat(
    { address: BAIT1, risk: "suspect", reason: `Köder ${BAIT1} getroffen.`, evidence: [], funding: [] },
    { baitLabels, faucetAddresses }
  );
  assert.equal(t.address, "Köder #1");
  assert.equal(t.reason, "Köder Köder #1 getroffen.");
  assert.ok(!JSON.stringify(t).includes(BAIT1), "Köder-Adresse im Threat durchgeleakt");
});

// ---------- 4) Evidence: kein txHash, honeypot gelabelt ----------
test("sanitizeEvidence: kein txHash-Feld, honeypot-Adresse -> Label", () => {
  const ev = sanitizeEvidence(
    [{ honeypot: BAIT1, type: "Payment", time: "2026-09-28T10:00:00Z", txHash: "DEADBEEF" }],
    baitLabels
  );
  assert.deepEqual(ev, [{ ref: "E-1", type: "Payment", time: "2026-09-28T10:00:00Z", honeypot: "Köder #1" }]);
  assert.ok(!("txHash" in ev[0]), "txHash in öffentlicher Evidence");
  assert.ok(!JSON.stringify(ev).includes(BAIT1), "Köder-Adresse in Evidence");
});

// ---------- 5) Funding: nur Labels, niemals Adressen ----------
test("sanitizeFunding: Köder und Faucet nur als Label, keine Adresse", () => {
  const f = sanitizeFunding(
    [{ address: BAIT1 }, { address: FAUCET }, { label: "Externe Quelle" }],
    baitLabels,
    faucetAddresses
  );
  assert.deepEqual(f, [{ label: "Köder #1" }, { label: "Faucet (benign)" }, { label: "Externe Quelle" }]);
  assert.ok(!JSON.stringify(f).includes(BAIT1), "Köder-Adresse in Funding");
  assert.ok(!JSON.stringify(f).includes(FAUCET), "Faucet-Adresse in Funding");
});

// ---------- 6) Graph: öffentliche Angreifer-Adresse voll, Köder nur honeypot:N ----------
test("buildGraph: Angreifer-Knoten mit voller Adresse, Köder-Knoten ohne Adresse", () => {
  const g = buildGraph(
    [
      { address: ATTACKER, evidence: [{ honeypot: BAIT1, type: "Payment" }] },
      { address: BAIT2, evidence: [] },
    ],
    { baitLabels }
  );
  const attackerNode = g.nodes.find((n) => n.id === `attacker:${ATTACKER}`);
  assert.ok(attackerNode, "Angreifer-Knoten fehlt");
  assert.equal(attackerNode.label, ATTACKER); // volle Adresse, nicht gekürzt
  assert.ok(!attackerNode.label.includes("…"), "Angreifer-Adresse im Graph gekürzt");
  const hp1 = g.nodes.find((n) => n.id === "honeypot:1");
  assert.ok(hp1 && hp1.label === "Köder #1" && hp1.type === "honeypot");
  const hp2 = g.nodes.find((n) => n.id === "honeypot:2");
  assert.ok(hp2 && hp2.label === "Köder #2");
  assert.deepEqual(g.edges, [{ from: `attacker:${ATTACKER}`, to: "honeypot:1", type: "Payment" }]);
  assert.ok(!JSON.stringify(g).includes(BAIT1), "Köder-Adresse im Graph");
  assert.ok(!JSON.stringify(g).includes(BAIT2), "historische Köder-Adresse im Graph");
});

// ---------- 7) Label-Helfer ----------
test("honeypotNodeId/honeypotPublicLabel: stabile Node-Id, öffentliches Label", () => {
  assert.equal(honeypotNodeId(BAIT1, baitLabels), "honeypot:1");
  assert.equal(honeypotNodeId("HP-7", baitLabels), "honeypot:7");
  assert.equal(honeypotPublicLabel("HP-3"), "Köder #3");
  assert.equal(honeypotPublicLabel("Köder #4"), "Köder #4");
});

// ---------- 8) computeStats: reine Zählung, keine Adress-Ausgabe ----------
test("computeStats: Zählungen korrekt, keine Adresse im Output", () => {
  const threats = [
    { risk: "malicious", evidence: [{ time: "2026-09-28T10:00:00Z" }] },
    { risk: "suspect", evidence: [{ time: "2026-09-28T11:00:00Z" }, { time: "2026-09-28T09:00:00Z" }] },
  ];
  const s = computeStats(threats, "main");
  assert.deepEqual(s, {
    maliciousCount: 1,
    suspectCount: 1,
    eventCount: 3,
    lastEventTime: "2026-09-28T11:00:00Z",
    network: "main",
  });
});
