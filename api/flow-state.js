// Vercel Function: GET /api/flow-state — Lesezweig des akkumulierten Flow-States.
//
// METHOD-TRENNSUNG: Der POST-Advance-Write-Vertrag (api/advance.js: Advance +
// {cursor, summary}, kein State-Leak) bleibt UNANTASTET. Diese Route ist strikt
// GET und liefert ausschließlich die NORMALISIERTE renderbare Projektion des
// persistierten Flow-State-Dokuments (projectFlowStateView, lib/flow-state.mjs)
// — Cluster-View-Form mit Cursor-Stand + updatedAt. Keine Roh-Internals
// (blocksProcessedTotal, lastAdvancedAt), keine ungefilterten Member-Listen,
// kein State-Leak.
//
// SICHERHEIT:
//   - FAIL-CLOSED ohne Token: ohne GITHUB_HISTORY_TOKEN liefert der Endpunkt
//     den ehrlichen Nicht-Konfiguriert-Zustand (Muster api/history.js GET:
//     HTTP 200 + reason — kein Erfolgs-Vortäuschen, aber auch kein
//     Fehlerzustand). Token NUR aus process.env, nie geloggt.
//   - Read-Fehler -> 502/503 (429 des Upstream -> 503), wie api/advance.js.
//     Neutrale Messages — keine Token-/Repo-Werte in Fehlermeldungen.
//
// GET -> { cursor, updatedAt, validatedIndex, clusters: [ {id, label, roles,
//         rolesByAddress, edges, totalDrops, txCount, distinctAccounts,
//         firstSeen, lastSeen} ] }
//         (deterministisch sortiert + gelabelt, Konvention lib/cluster.mjs;
//         edges/rolesByAddress versorgen die Flow-Graph-/Weltkugel-View)
//
// validatedIndex (Neu 2026-10-02): der aktuell validierte Ledger-Index — die
// Referenz für die Rückstands-Anzeige des Flow-Hosts (validatedIndex − cursor).
// EIN rpc ledger_index:'validated'-Call (Muster api/ledger.js:131) mit 60-s-
// Prozess-Cache (Muster api/ledger.js:50, 122-124): begrenzt die Kosten auf
// <= 1 RPC/Minute pro warmem Prozess, unabhängig von der Besucherzahl — ohne
// Cache wäre dieser Endpunkt ein ungedeckter dritter Egress-Verbraucher im
// geteilten 10.000-Units-Fenster (Bilanz im README). Fehler/Timeout -> null
// (ehrlicher Leerzustand im Client, kein 502 — der State ist trotzdem gültig).
import { readFlowStateGitHub, projectFlowStateView } from "../lib/flow-state.mjs";

export const maxDuration = 30;

const RPC_URL =
  process.env.RPC_URL ||
  (process.env.WSS_URL || "wss://xrplcluster.com").replace(/^wss:/, "https:");
const VALIDATED_CACHE_MS = 60000; // 60-s-Cache wie api/ledger.js:50
let validatedCache = null;        // { time, index } — nur im Prozess-Speicher

// Aktuelles validiertes Ledger-Index (1 Call, cached; Fehler -> null, ebenfalls
// kurz gecacht, damit ein fehlschlagender Endpunkt nicht jede Anfrage erneut
// einen RPC kosten lässt). Exportiert für Fixture-Tests (lib/flow-state-validated.test.mjs)
// — Handler-intern unverändert nur über fetch auf globalThis.
export async function fetchValidatedIndex() {
  if (validatedCache && Date.now() - validatedCache.time < VALIDATED_CACHE_MS) {
    return validatedCache.index;
  }
  let index = null;
  try {
    const res = await fetch(RPC_URL, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ method: "ledger", params: [{ ledger_index: "validated" }] }),
    });
    if (res.ok) {
      const data = await res.json().catch(() => null);
      const n = Number(data?.result?.ledger_index);
      if (Number.isFinite(n) && n > 0) index = Math.floor(n);
    }
  } catch {
    /* null -> ehrlicher Leerzustand im Client */
  }
  validatedCache = { time: Date.now(), index };
  return index;
}

// Test-Helfer (lib/flow-state-validated.test.mjs): setzt den Prozess-Cache
// zurück, damit Fixture-Tests den Cache-Zustand unabhängig von vorangegangenen
// Tests prüfen können. Kein Handler-Pfad, keine Produktionsnutzung.
export function resetValidatedCacheForTests() {
  validatedCache = null;
}

// Fail-closed: Persistenz erfordert den Token (nur aus ENV).
const hasPersistence = () => Boolean(process.env.GITHUB_HISTORY_TOKEN);

export default async function handler(req, res) {
  res.setHeader("Cache-Control", "no-store");
  const method = String(req?.method ?? "GET").toUpperCase();
  if (method !== "GET") {
    res.setHeader("Allow", "GET");
    return res.status(405).json({ error: "Methode nicht erlaubt." });
  }
  if (!hasPersistence()) {
    // Ohne Persistenz gibt es keinen Cursor, gegen den validatedIndex sinnvoll
    // wäre — der RPC bleibt in diesem Zweig komplett aus (Egress-Schonung).
    return res.status(200).json({
      cursor: 0,
      updatedAt: null,
      validatedIndex: null,
      clusters: [],
      reason: "Persistenz nicht konfiguriert",
    });
  }
  try {
    const { doc } = await readFlowStateGitHub();
    const view = projectFlowStateView(doc);
    const validatedIndex = await fetchValidatedIndex();
    return res.status(200).json({ ...view, validatedIndex });
  } catch (err) {
    // Read-Fehler (403/429, Netzwerk) -> kein Erfolg ohne Persistenz.
    // 429 des Upstream -> 503, alles andere 502.
    const status = err?.status === 429 ? 503 : 502;
    return res.status(status).json({ error: "Flow-State nicht erreichbar." });
  }
}
