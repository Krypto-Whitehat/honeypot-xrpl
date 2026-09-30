// lib/index.mjs — Test-Aggregator: lädt alle Unit-Tests dieses Ordners.
// Hintergrund: Node >= 26 behandelt ein als Testpfad übergebenes Verzeichnis
// (node --test lib) als auszuführende Test-Datei statt es zu durchsuchen.
// Über lib/package.json "main" (die Root-package.json hat kein main-Feld)
// wird dieser Einstiegspunkt geladen und führt die echten Tests aus.
// Einzelne Dateien laufen weiterhin direkt, z. B.:
//   node --test lib/cluster.test.mjs
import "./cluster.test.mjs";
import "./detector.test.mjs";
import "./sanitize.test.mjs";
import "./attribution.test.mjs";
import "./history.test.mjs";
import "./account-report.test.mjs";
