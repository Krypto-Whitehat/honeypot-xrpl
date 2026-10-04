// scripts/restore-flow-state.mjs — EINMAL-Daten-Restore data/flow-state.json
// (Wisch-Zyklus-Aufräumung, Plan Schritt 11).
//
// EINMAL-SKRIPT: nach erfolgreicher Ausführung LÖSCHEN (berührt das 12-
// Function-Limit nicht — scripts/ zählt nicht zu api/). KEIN Commit-Pfad über
// git revert: Restore ist die UNION aus historischem Blob und aktuellem
// main-Bestand, cursor = max, blocksProcessedTotal = max.
//
// REIHENFOLGE (harte Regel): erst den Fix deployen (Blob-Fallback + Caps +
// Seed-Guard), DANN dieses Skript ausführen — alter Code wischt jede
// wiederhergestellte >1-MiB-Datei im nächsten Cron-Tick (live belegt:
// df96f1a4 1.125.252 B -> e48a6164 126 B, zweiter Zyklus 2026-10-04.json).
//
// AUTH: ausschließlich die lokal authentifizierte gh-CLI (push-Rechte auf
// Krypto-Whitehat/honeypot-xrpl-history live verifiziert). Der Skript-Code
// kennt und loggt NIEMALS GITHUB_HISTORY_TOKEN oder andere Secrets.
//
// KEINE festgeschriebenen Union-Zahlen: der main-Bestand wird ZUR
// AUSFÜHRUNGSZEIT live gelesen (sha=current — kein blinder Overschreib-
// Commit). Der Blob-anker unten ist ein git-Objekt (unveränderlich), keine
// Momentaufnahme: Blob 15b51a7c546cba99b92453c8f72d93035e1b9c66 trägt den
// rekonstruierten Bestand von 2026-10-04 15:52:06Z (77 Cluster, cursor
// 107404045, bpt 1874, 1.125.252 B — live dekodiert).
//
// EHRLICHE GRENZE (Kritik-Punkt 4, bewusst im Commit-Message dokumentiert):
// der nächste advance-Tick schreibt die Union mit dem effektiven Byte-Cap
// (~FLOW_STATE_MAX_BYTES 900_000 B -> Kappe durch Halbirung) neu —
// wiederhergestellte BENIGN Cluster jenseits des Caps fallen erneut raus.
// Betrugsevidenz-Cluster bleiben durch die Archiv-Kopplung erhalten
// (archiveFromFlowState archiviert, was mergeFlowState kappt —
// lib/flow-state.mjs). Die Union ist ein Wiederherstellungs-Fenster, keine
// dauerhafte Rückholung benign Cluster.
//
// Ausführen (nach dem Deploy):  node scripts/restore-flow-state.mjs
import { execFileSync } from "node:child_process";
import { parseFlowStateText, serializeFlowState } from "../lib/flow-state.mjs";

const REPO = "Krypto-Whitehat/honeypot-xrpl-history";
const FILE_PATH = "data/flow-state.json";
const BRANCH = "main";
// Git-Objekt-Anker (unveränderlich): der rekonstruierte Vor-Wisch-Bestand.
const HISTORIC_BLOB_SHA = "15b51a7c546cba99b92453c8f72d93035e1b9c66";

function ghJson(args, input) {
  const out = execFileSync("gh", ["api", "--paginate=false", ...args], {
    encoding: "utf8",
    maxBuffer: 64 * 1024 * 1024,
    ...(input != null ? { input } : {}),
  });
  return JSON.parse(out);
}

function decodeB64(b64) {
  // GitHub bricht base64 mit Newlines — identischer Strip wie der Transport
  // (lib/history.mjs readGitHubContents).
  return Buffer.from(String(b64 ?? "").replace(/\s+/g, ""), "base64").toString("utf8");
}

// 1) Aktueller main-Bestand ZUR AUSFÜHRUNGSZEIT (live; sha = PUT-Anker).
const cur = ghJson([`repos/${REPO}/contents/${FILE_PATH}?ref=${BRANCH}`]);
const curSha = cur.sha;
let curText = "";
if (typeof cur.content === "string" && cur.content.trim()) {
  curText = decodeB64(cur.content);
} else if (Number(cur.size) > 0 && curSha) {
  // >1 MiB: Contents-API liefert keinen content -> Blob-Fallback (derselbe
  // Mechanismus, den der deployte Fix in lib/history.mjs nutzt).
  const blob = ghJson([`repos/${REPO}/git/blobs/${curSha}`]);
  curText = decodeB64(blob.content);
}
const curDoc = parseFlowStateText(curText || "{}");

// 2) Historischer Blob-Bestand (git-Objekt, unveränderlich).
const histBlob = ghJson([`repos/${REPO}/git/blobs/${HISTORIC_BLOB_SHA}`]);
const histDoc = parseFlowStateText(decodeB64(histBlob.content));

// 3) Union: Cluster-Key — aktueller main gewinnt (jüngere Sicht behält
// Rollen/Volumen/lastSeen des laufenden Walks); cursor = max; bpt = max.
const clusters = { ...(histDoc.state.clusters ?? {}), ...(curDoc.state.clusters ?? {}) };
const unionDoc = {
  cursor: Math.max(curDoc.cursor, histDoc.cursor),
  state: {
    ...(histDoc.state ?? {}),
    ...(curDoc.state ?? {}),
    clusters,
    blocksProcessedTotal: Math.max(
      Number(curDoc.state?.blocksProcessedTotal) || 0,
      Number(histDoc.state?.blocksProcessedTotal) || 0
    ),
  },
  updatedAt: Date.now(),
};

const serialized = serializeFlowState(unionDoc);
const bytes = Buffer.byteLength(serialized, "utf8");
const clusterCount = Object.keys(unionDoc.state.clusters).length;

// 4) Commit via gh api PUT (branch main, sha=current — kein Force-Push).
// Body über stdin (--input -): die Union ist >1 MiB, ein Argument auf der
// Kommandozeile würde das Limit sprengen.
const message =
  "restore: flow-state Union (historischer Blob 15b51a7c + main live) — " +
  "cursor=max, bpt=max, Cluster-Key-Union (main gewinnt). Wiederherstellungs-" +
  "Fenster: naechster Tick kappt auf den effektiven Byte-Cap; Betrugsevidenz " +
  "bleibt via Archiv-Kopplung (lib/flow-state.mjs archiveFromFlowState).";
ghJson(
  ["-X", "PUT", `repos/${REPO}/contents/${FILE_PATH}`, "--input", "-"],
  JSON.stringify({
    message,
    branch: BRANCH,
    ...(curSha ? { sha: curSha } : {}),
    content: Buffer.from(serialized, "utf8").toString("base64"),
  })
);

console.log(
  `restore-flow-state: OK — cursor ${unionDoc.cursor}, clusters ${clusterCount}, ` +
    `bpt ${unionDoc.state.blocksProcessedTotal}, ${bytes} B, sha-Anker ${curSha ?? "(neu angelegt)"}`
);
console.log(
  "Hinweis: naechster advance-Tick wendet den Byte-Cap an (benign Cluster " +
    "jenseits des Caps fallen; Betrugsevidenz bleibt im data/flow-archive). " +
    "Skript nach Erfolg loeschen."
);
