// Vercel Function: GET /api/stats — Live-Statistiken.
// Route ?route=validators (Rewrite /api/validators): Validator-Gesundheit aus xrpscan
// (lib/validator-service.mjs). Eine Funktion mehr wäre über das Hobby-Limit (12).
import { getStats } from "../lib/threats-service.mjs";
import { validatorView } from "../lib/validator-service.mjs";
import { loadDays, traceForValidator, crossValidatorPatterns } from "../lib/validator-trace-query.mjs";
import { REPORT_RANGES, reportCsv, validatorReport } from "../lib/validator-report.mjs";
import { loadDaysRemote, traceTokenConfigured } from "../lib/validator-trace-store.mjs";
import { groundOf, groundTruthMap } from "../lib/validator-ground.mjs";
import { readHistoryGitHub } from "../lib/history.mjs";
import path from "node:path";
import { fileURLToPath } from "node:url";
const TRACE_DIR = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "data", "validator-trace");

export const maxDuration = 30;

// Angriffsseite der Zeit-Ebene: die Cluster der History-Persistenz (separates GitHub-Repo).
// 60-s-Cache wie in api/history.js - der Bestand ist mehrstellig MB gross und wird pro Netz-
// Anfrage nicht neu geholt. Read-Fehler wird NICHT als leerer Bestand gecacht.
const CLUSTER_CACHE_MS = 60000;
let clusterCache = null;

async function impactClusters(now) {
  if (clusterCache && now - clusterCache.time < CLUSTER_CACHE_MS) return clusterCache.list;
  try {
    const { list } = await readHistoryGitHub();
    clusterCache = { time: now, list: Array.isArray(list) ? list : [] };
    return clusterCache.list;
  } catch {
    // null ist ein eigener Zustand, nicht dasselbe wie []: die Historie ist nicht lesbar,
    // es gibt also keine Angriffsstunden. Als [] waere das ein Befund ohne Angriffe.
    return null;
  }
}

// Eine nicht lesbare Historie muss in der Antwort stehen, sonst sieht ein Betreiber die
// fehlende Angriffsseite wie einen sauberen Befund.
function historyErrorOf(clusters) {
  return clusters === null
    ? "Betrugs-Historie aus dem Daten-Repo nicht lesbar - die Angriffsseite (Angriffsstunden) fehlt in dieser Antwort."
    : null;
}

export default async function handler(req, res) {
  try {
    if (req.query?.route === "validators") {
      return res.status(200).json(await validatorView());
    }
    if (req.query?.route === "trace") {
      const range = String(req.query.range || "24h");
      const remote = traceTokenConfigured();
      const days = remote ? await loadDaysRemote(range) : loadDays(TRACE_DIR);
      const source = remote ? "github-daten-repo" : "lokal";
      if (!days.length) return res.status(200).json({ available: false, source, note: remote ? "Noch keine Trace-Daten im Speicher – der Recorder (monitor/validator-trace.mjs) hat noch nicht geschrieben." : "Kein lokaler Trace-Speicher." });
      if (req.query.patterns) {
        const clusters = await impactClusters(Date.now());
        return res.status(200).json({ available: true, source, days: days.length, historyError: historyErrorOf(clusters), ...crossValidatorPatterns(days, { range, clusters: clusters || [], groundPeers: await groundTruthMap() }) });
      }
      const master = String(req.query.master || "");
      const format = String(req.query.format || "");
      // Maschinenlesbarer Selbst-Report: ein Betreiber soll seinen Knoten per Cron auswerten
      // koennen, ohne das Overlay zu oeffnen. csv = Tabellenform, json = nur der Report.
      const attackClusters = await impactClusters(Date.now());
      // Die Netz-Referenz je Knoten steht beiden Ausgaengen zur Verfuegung: dem Overlay-Trace
      // und dem maschinenlesbaren Selbst-Report. Ein Report ohne Gegenprobe enthaelt die Zahl
      // affectedValidators ohne die Zahl, die sie traegt oder widerlegt.
      const groundMap = await groundTruthMap();
      const ground = groundOf(groundMap, master);
      if (master && (format === "csv" || format === "json")) {
        const report = validatorReport(days, master, { range, now: Date.now(), clusters: attackClusters || [], ground });
        if (format === "json") return res.status(200).json(report);
        const safeRange = REPORT_RANGES.includes(range) ? range : "7d";
        const name = "validator-report-" + master.slice(0, 8) + "-" + safeRange + ".csv";
        return res.status(200)
          .setHeader("content-type", "text/csv; charset=utf-8")
          .setHeader("content-disposition", "attachment; filename=\"" + name + "\"")
          .send(reportCsv(report));
      }
      // Produktions-Paritaet: beide Einstiegspunkte muessen mit derselben Gegenprobe urteilen.
      // Ohne Netz-Referenz je Knoten bleibt die Erfassungs-Luecke offen und der Endpoint
      // behauptet weniger, als er weiss: lokal die eine, live die andere Auskunft.
      const body = traceForValidator(days, master, {
        range, clusters: attackClusters || [], ground: groundOf(groundMap, master), groundPeers: groundMap,
      });
      return res.status(200).json({ available: true, source, days: days.length, historyError: historyErrorOf(attackClusters), ...body });
    }
    res.status(200).json(await getStats());
  } catch (err) {
    res.status(502).json({ error: "Ledger-Abfrage fehlgeschlagen." });
  }
}
