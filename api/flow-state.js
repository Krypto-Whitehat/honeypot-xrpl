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
// GET -> { cursor, updatedAt, clusters: [ {id, label, roles, rolesByAddress,
//         edges, totalDrops, txCount, distinctAccounts, firstSeen, lastSeen} ] }
//         (deterministisch sortiert + gelabelt, Konvention lib/cluster.mjs;
//         edges/rolesByAddress versorgen die Flow-Graph-/Weltkugel-View)
import { readFlowStateGitHub, projectFlowStateView } from "../lib/flow-state.mjs";

export const maxDuration = 30;

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
    return res.status(200).json({
      cursor: 0,
      updatedAt: null,
      clusters: [],
      reason: "Persistenz nicht konfiguriert",
    });
  }
  try {
    const { doc } = await readFlowStateGitHub();
    return res.status(200).json(projectFlowStateView(doc));
  } catch (err) {
    // Read-Fehler (403/429, Netzwerk) -> kein Erfolg ohne Persistenz.
    // 429 des Upstream -> 503, alles andere 502.
    const status = err?.status === 429 ? 503 : 502;
    return res.status(status).json({ error: "Flow-State nicht erreichbar." });
  }
}
