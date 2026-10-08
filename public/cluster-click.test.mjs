// public/cluster-click.test.mjs — Regression: Klick auf Cluster-Karte geht auch bei Neurender
// zwischen Mausdruck und Loslassen (Live-Takt rendert die Liste ~alle 4 s neu).
import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const app = fs.readFileSync(path.join(here, "app.js"), "utf8").replace(/\r\n/g, "\n");

test("Cluster-Liste: pointerdown merkt Karte und ID, pointerup öffnet bei ersetztem Knoten, click bleibt Fallback", () => {
  assert.match(app, /listEl\.addEventListener\('pointerdown'/);
  assert.match(app, /listEl\.addEventListener\('pointerup'/);
  assert.match(app, /if \(!pressed \|\| pressed\.node\.isConnected\) return;/);
  assert.match(app, /if \(same\) openClusterModal\(id\);/);
  assert.match(app, /if \(id\) openClusterModal\(id\);/);
});

test("Fallback arbeitet mit der Cluster-ID, nicht mit dem Index (kein Verwechseln nach Umsortierung)", () => {
  const start = app.indexOf("let pressed = null;");
  assert.ok(start > 0, "Block vorhanden");
  const block = app.slice(start, start + 900);
  assert.ok(block.includes("clusters[idx] ? clusters[idx].id : null"));
  assert.ok(!/openClusterModal\(\s*(idx|pressedIdx)\s*\)/.test(app));
});
