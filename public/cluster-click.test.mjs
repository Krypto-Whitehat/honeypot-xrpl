// public/cluster-click.test.mjs — Regression: Klick auf Cluster-Karte geht auch bei Neurender
// zwischen Mausdruck und Loslassen (Live-Takt rendert die Liste ~alle 4 s neu).
import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const app = fs.readFileSync(path.join(here, "app.js"), "utf8").replace(/\r\n/g, "\n");

test("Cluster-Liste merkt die Cluster-ID beim Mausdruck (pointerdown) und nutzt sie als Fallback im click", () => {
  assert.match(app, /listEl\.addEventListener\('pointerdown'/);
  assert.match(app, /const id = card \? clusterIdOfCard\(card\) : pressedClusterId;/);
  assert.match(app, /if \(id\) openClusterModal\(id\);/);
});

test("Fallback arbeitet mit der ID, nicht mit dem Index (kein Verwechseln nach Umsortierung)", () => {
  const block = app.slice(app.indexOf("let pressedClusterId = null;"), app.indexOf("let pressedClusterId = null;") + 900);
  assert.ok(block.includes("clusters[idx] ? clusters[idx].id : null"));
  assert.ok(!/openClusterModal\(\s*(idx|pressedIdx)\s*\)/.test(app));
});
