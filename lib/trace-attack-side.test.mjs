import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { test } from "node:test";
import assert from "node:assert/strict";
import { fileURLToPath } from "node:url";
import { loadLocalHistory } from "./history.mjs";

/* Guard gegen die Angriffsseiten-Falle (gemessen 2026-10-16 auf der Live-Site): die Produktion
 * rief traceForValidator OHNE clusters, der lokale Server MIT ihnen. Die Angriffs-Wirkungs-Ebene
 * ist aber an Cluster geknuepft - ohne sie ist impact null, und die live ausgelieferte Antwort
 * enthielt weder impact noch die Angriffsstunde als Ursache. Dasselbe Bild lokal im Schlucken:
 * "catch { clusters = [] }" machte eine unlesbare (korrumpierte) Historie zu einem Befund ohne
 * Angriffe. Beides ist derselbe Fehler: ein fehlender Eingang sieht aus wie ein messbarer Nullwert. */

const here = path.dirname(fileURLToPath(import.meta.url));
const read = (rel) => fs.readFileSync(path.join(here, rel), "utf8");
const server = read("../server/index.mjs");
const stats = read("../api/stats.js");
const query = read("./validator-trace-query.mjs");

test("Produktions-Paritaet: beide Einstiegspunkte geben der Ursachen-Engine die Cluster", () => {
  assert.match(query, /impact\s*=\s*Array\.isArray\(clusters\)\s*&&\s*clusters\.length\s*\?\s*attackImpact/,
    "impact haengt nicht an den Clustern - dann ist die Paritaet keine Aussage");
  for (const [name, src] of [["server/index.mjs", server], ["api/stats.js", stats]]) {
    assert.match(src, /traceForValidator\(\s*days,\s*\w+,\s*\{[^}]*\bclusters:/,
      name + ": traceForValidator bekommt keine Cluster - die Angriffsseite fehlt in dieser Fassung");
    assert.match(src, /crossValidatorPatterns\(\s*days,\s*\{[^}]*\bclusters:/,
      name + ": crossValidatorPatterns bekommt keine Cluster");
    assert.match(src, /validatorReport\(\s*days,\s*\w+,\s*\{[^}]*\bclusters:/,
      name + ": validatorReport bekommt keine Cluster - der maschinenlesbare Selbst-Report bleibt ohne Angriffsseite");
  }
});

test("Der Selbst-Report bekommt die Angriffsseite nicht nur dem Namen nach", () => {
  const report = read("./validator-report.mjs");
  assert.match(report, /attackImpact\(\s*days,\s*clusters,/, "validatorReport ruft attackImpact ohne die Cluster");
  assert.match(report, /clusters\s*=\s*\[\]/, "validatorReport hat keinen Cluster-Eingang");
  assert.match(report, /impact:\s*impact \?/, "kein impact-Feld im Report");
  assert.match(report, /verdictReason/, "ein Urteil ohne Grund ist keine Aussage");
});

test("Kein Schlucken: eine unlesbare Historie ist keine leere Cluster-Liste", () => {
  for (const [name, src] of [["server/index.mjs", server], ["api/stats.js", stats]]) {
    assert.doesNotMatch(src, /catch\s*\{\s*clusters\s*=\s*\[\]\s*\}/,
      name + ": catch { clusters = [] } verschluckt echte Korruption als 'keine Angriffe'");
    assert.match(src, /historyError/, name + ": die Antwort meldet keine Luecke der Angriffsseite");
  }
  assert.match(server, /err\.code === "ENOENT"/, 'server/index.mjs: der Anlege-Fall (Datei fehlt) ist nicht von echten Fehlern getrennt');
  assert.match(stats, /function historyErrorOf\(/, "api/stats.js: kein Hinweis-Text fuer die nicht lesbare Historie");
  assert.equal((stats.match(/historyError: historyErrorOf\(/g) || []).length, 2,
    "api/stats.js: nur ein Einstiegspunkt meldet die Luecke");
  assert.equal((server.match(/historyError: side\.historyError/g) || []).length, 2,
    "server/index.mjs: nur ein Einstiegspunkt meldet die Luecke");
});

test("Der Lader selbst unterscheidet Anlege-Fall und Korruption", async () => {
  const missing = path.join(os.tmpdir(), "hx-fehlt-" + process.pid + "-" + Date.now() + ".json");
  assert.deepEqual(await loadLocalHistory(missing), [], "fehlende Datei muss der Anlege-Fall sein");
  const corrupt = path.join(os.tmpdir(), "hx-korrupt-" + process.pid + "-" + Date.now() + ".json");
  fs.writeFileSync(corrupt, "[{\"a\":1}]]", "utf8");
  await assert.rejects(() => loadLocalHistory(corrupt), /parsebar|korrumpiert/,
    "korrumpierte Historie muss geworfen werden - sonst heilt der Lader den Fehler still");
  fs.rmSync(corrupt);
});
