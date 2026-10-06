'use strict';
// public/cluster-views.test.mjs — Tests der DOM-freien Cluster-Akkumulations-
// Helfer (Fix 2026-10-06, zweite Runde). Kern-Reproduktion des Live-Befunds:
// der Mega-Cluster (46.660 Accounts) verschwand als Karte, weil
// mergeClusterViews jeden persistierten Cluster bei ≥1 gemeinsamer Member-
// Adresse komplett verwarf (Absorption) — der Mega teilt mit fast jedem
// Fenster-Cluster ein Exchange-Konto. Neu: Dedup ausschließlich über die id
// mit Statistik-Union; Mitglieder-Überlappung berührt die Karte nicht mehr.

import test from "node:test";
import assert from "node:assert/strict";
import { SEV_RANK, serverClustersFromView, unionClusterWith, mergeClusterViews } from "./cluster-views.mjs";

const A1 = "rTESTexchangeAccount11111111";
const A2 = "rTESTcheckAccount8888888888";
const A3 = "rTESTthirdAccount33333333333";
const MEGA_ID = "cluster:rTESTmegaAccount000000000";

test("serverClustersFromView: rolesByAddress wird zu memberAddresses, Defaults fail-closed", () => {
  const view = {
    clusters: [
      {
        id: MEGA_ID,
        label: "Mega",
        rolesByAddress: { [A1]: "drainer", [A2]: "collector" },
        severityByAddress: { [A1]: "malicious" },
        edges: [{ from: A1, to: A2, type: "payment", toTag: 123 }],
        totalDrops: 100650561424874960,
        txCount: 585982,
        distinctAccounts: 46660,
        firstSeen: "2026-10-01T00:00:00Z",
        lastSeen: "2026-10-06T03:36:35Z",
        peelingChains: [{ addresses: [A1, A2], bridges: [] }],
      },
      { /* leerer Eintrag: Defaults, kein Crash */ },
    ],
  };
  const out = serverClustersFromView(view);
  assert.equal(out.length, 2);
  const mega = out[0];
  assert.deepEqual(mega.memberAddresses, [A1, A2]);
  assert.equal(mega.roles[A1], "drainer");
  assert.equal(mega.severityByAddress[A1], "malicious");
  assert.equal(mega.edges.length, 1);
  assert.equal(mega.txCount, 585982);
  assert.equal(mega.distinctAccounts, 46660);
  assert.equal(mega.peelingChains.length, 1);
  const empty = out[1];
  assert.equal(empty.id, "");
  assert.deepEqual(empty.memberAddresses, []);
  assert.equal(empty.totalDrops, 0);
  // Keine View (null/undefined/ohne clusters): leere Liste, kein Wurf.
  assert.deepEqual(serverClustersFromView(null), []);
  assert.deepEqual(serverClustersFromView({}), []);
});

test("mergeClusterViews: Mega-Cluster bleibt bei Member-Überlappung stehen (Live-Repro 2026-10-06)", () => {
  const mega = {
    id: MEGA_ID,
    memberAddresses: [A1, A2, A3],
    rolesByAddress: { [A1]: "drainer", [A2]: "collector", [A3]: "relay" },
    severityByAddress: { [A1]: "malicious", [A2]: "suspect" },
    edges: [],
    totalDrops: 100650561424874960,
    txCount: 585982,
    distinctAccounts: 46660,
    firstSeen: "2026-10-01T00:00:00Z",
    lastSeen: "2026-10-06T03:36:35Z",
  };
  // Fenster-Cluster mit ANDERER id, teilt genau EIN Mitglied (A1) mit dem
  // Mega — früher wurde der Mega dadurch komplett verworfen.
  const windowTwin = {
    id: `cluster:${A1}`,
    memberAddresses: [A1],
    rolesByAddress: { [A1]: "source" },
    severityByAddress: { [A1]: "info" },
    edges: [{ from: A1, to: A3, type: "payment" }],
    totalDrops: 500,
    txCount: 2,
    distinctAccounts: 1,
    firstSeen: "2026-10-06T04:28:00Z",
    lastSeen: "2026-10-06T04:30:00Z",
  };
  const merged = mergeClusterViews([windowTwin], [mega]);
  assert.equal(merged.length, 2, "beide Karten bleiben (keine Absorption bei ≥1 gemeinsamem Mitglied)");
  const megaCard = merged.find((c) => c.id === MEGA_ID);
  assert.ok(megaCard, "Mega-Cluster bleibt als Karte in der Liste");
  assert.equal(megaCard.totalDrops, 100650561424874960, "akkumulierte Statistik unangetastet");
  assert.equal(megaCard.distinctAccounts, 46660);
  assert.equal(megaCard.memberAddresses.length, 3);
});

test("unionClusterWith: gleiche id — Zähler max, Zeitstempel earliest/latest, Rollen frisch, Severity nach Rang", () => {
  const w = {
    id: MEGA_ID,
    label: "",
    memberAddresses: [A1, A2],
    rolesByAddress: { [A1]: "drainer" },
    severityByAddress: { [A1]: "info", [A2]: "info" },
    edges: [{ from: A1, to: A2, type: "payment", txHash: "H1" }],
    totalDrops: 500,
    txCount: 5,
    distinctAccounts: 2,
    firstSeen: "2026-10-06T10:00:00Z",
    lastSeen: "2026-10-06T10:05:00Z",
    peelingChains: [{ addresses: [A1, A2], bridges: [] }],
  };
  const p = {
    id: MEGA_ID,
    label: "Mega",
    memberAddresses: [A1, A3],
    rolesByAddress: { [A1]: "source", [A3]: "relay" },
    severityByAddress: { [A1]: "malicious", [A3]: "suspect" },
    edges: [
      { from: A1, to: A2, type: "payment", txHash: "H1" }, // Duplikat
      { from: A3, to: A1, type: "payment", txHash: "H9" },
    ],
    totalDrops: 100000,
    txCount: 999,
    distinctAccounts: 46660,
    firstSeen: "2026-10-01T00:00:00Z",
    lastSeen: "2026-10-05T00:00:00Z",
    peelingChains: [{ addresses: [A3, A1], bridges: [A2] }],
  };
  const u = unionClusterWith(w, p);
  assert.equal(u.id, MEGA_ID, "id bleibt die Fenster-id (Knoten tragen clusterId === id)");
  assert.equal(u.totalDrops, 100000, "Zähler: Maximum der Akkumulation");
  assert.equal(u.txCount, 999);
  assert.equal(u.distinctAccounts, 46660, "distinctAccounts bleibt der wahre Stand");
  assert.equal(u.firstSeen, "2026-10-01T00:00:00Z", "firstSeen: frühester");
  assert.equal(u.lastSeen, "2026-10-06T10:05:00Z", "lastSeen: spätester (frische Aktivität)");
  assert.deepEqual(u.memberAddresses, [A1, A2, A3], "Mitglieder-Union, Fenster-Reihenfolge zuerst");
  assert.equal(u.rolesByAddress[A1], "drainer", "Fenster-Rolle schlägt persistierte (frisch)");
  assert.equal(u.rolesByAddress[A3], "relay", "persistierte Nur-Server-Mitglieder behalten ihre Rolle");
  assert.equal(u.severityByAddress[A1], "malicious", "Severity-Union nach Rang");
  assert.equal(u.severityByAddress[A2], "info");
  assert.equal(u.severityByAddress[A3], "suspect");
  assert.equal(u.edges.length, 2, "Kanten-Union dedupliziert (H1 doppelt, H9 neu)");
  assert.equal(u.peelingChains.length, 2, "Peeling-Ketten beider Schichten");
  // Unparsebare Zeitstempel verlieren nie gegen parsebare.
  const u2 = unionClusterWith({ ...w, firstSeen: null, lastSeen: null }, p);
  assert.equal(u2.firstSeen, "2026-10-01T00:00:00Z");
  assert.equal(u2.lastSeen, "2026-10-05T00:00:00Z");
});

test("mergeClusterViews: Dedup über id, Mehrfach-Zwillinge unionen sequenziell", () => {
  const w = {
    id: "cluster:X", memberAddresses: ["rX1"], rolesByAddress: { rX1: "source" },
    severityByAddress: {}, edges: [], totalDrops: 10, txCount: 1, distinctAccounts: 1,
    firstSeen: "2026-10-06T10:00:00Z", lastSeen: "2026-10-06T10:01:00Z",
  };
  const serverTwin = { ...w, id: "cluster:X", totalDrops: 700, txCount: 70 };
  const sessionTwin = { ...w, id: "cluster:X", totalDrops: 300, txCount: 30 };
  const other = { ...w, id: "cluster:Y", totalDrops: 1 };
  const merged = mergeClusterViews([w], [serverTwin, sessionTwin, other]);
  assert.equal(merged.length, 2, "eine Karte pro id, andere id bleibt");
  const x = merged.find((c) => c.id === "cluster:X");
  assert.equal(x.totalDrops, 700, "Server- und Session-Zwilling unionen in dieselbe Karte (max gewinnt)");
  assert.equal(x.txCount, 70);
  assert.ok(merged.some((c) => c.id === "cluster:Y"));
});

test("mergeClusterViews: Sortierung Schwere desc, lastSeen desc, totalDrops desc, id asc", () => {
  const base = (over) => ({
    memberAddresses: [], rolesByAddress: {}, severityByAddress: {}, edges: [],
    firstSeen: null, lastSeen: null, totalDrops: 0, txCount: 0, distinctAccounts: 0,
    ...over,
  });
  const info = base({ id: "cluster:a", severityByAddress: { r1: "info" }, lastSeen: "2026-10-06T10:00:00Z", totalDrops: 5 });
  const suspect = base({ id: "cluster:b", severityByAddress: { r1: "suspect" }, lastSeen: "2026-10-06T09:00:00Z", totalDrops: 999 });
  const malicious = base({ id: "cluster:c", severityByAddress: { r1: "malicious" }, lastSeen: "2026-10-05T00:00:00Z", totalDrops: 1 });
  // Gleichstand Schwere+lastSeen+totalDrops -> id asc.
  const t1 = base({ id: "cluster:t1", lastSeen: "2026-10-06T08:00:00Z", totalDrops: 42 });
  const t2 = base({ id: "cluster:t2", lastSeen: "2026-10-06T08:00:00Z", totalDrops: 42 });
  const merged = mergeClusterViews([info, t2, suspect, t1, malicious], []);
  assert.deepEqual(merged.map((c) => c.id), ["cluster:c", "cluster:b", "cluster:a", "cluster:t1", "cluster:t2"]);
});

test("mergeClusterViews: robust gegen Null-Einträge und fehlende ids", () => {
  const w = { id: "cluster:w", memberAddresses: [], rolesByAddress: {}, severityByAddress: {}, edges: [], totalDrops: 1, firstSeen: null, lastSeen: null };
  // Ein persistierter Eintrag OHNE id ist nicht dedup-fähig und wird (wie im
  // bisherigen Verhalten) als eigene Karte durchgereicht — kein Crash, kein
  // stiller Verlust; Null/undefined-Einträge fallen auf beiden Seiten raus.
  const merged = mergeClusterViews([null, w, undefined], [null, { totalDrops: 3 }, { id: "cluster:p", memberAddresses: [], rolesByAddress: {}, severityByAddress: {}, edges: [], totalDrops: 2, firstSeen: null, lastSeen: null }]);
  assert.equal(merged.length, 3);
  assert.ok(merged.some((c) => c.id === "cluster:w"));
  assert.ok(merged.some((c) => c.id === "cluster:p"));
  assert.ok(merged.some((c) => c.totalDrops === 3), "id-loser Eintrag bleibt sichtbar (fail-open, kein stiller Verlust)");
  // Keine Arrays/Views: leere Ergebnisse statt Wurf.
  assert.deepEqual(mergeClusterViews(null, null), []);
});

test("SEV_RANK: malicious > suspect > info (Spiegel des Hosts app.js)", () => {
  assert.ok(SEV_RANK.malicious > SEV_RANK.suspect && SEV_RANK.suspect > SEV_RANK.info);
  assert.equal(SEV_RANK.info, 0);
});
