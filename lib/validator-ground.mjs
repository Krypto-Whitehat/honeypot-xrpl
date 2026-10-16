// lib/validator-ground.mjs - die Netz-Referenz je Knoten, gemeinsam fuer beide Einstiegspunkte.
//
// WARUM EIGENE DATEI: /api/validator-trace laeuft lokal in server/index.mjs, produktiv in
// api/stats.js (Vercel-Rewrite). Hat jede Fassung ihre eigene Referenz-Beschaffung, urteilt der
// eine Endpoint mit Gegenprobe und der andere ohne - genau die Divergenz, die am 2026-10-16
// aufgefallen ist: lokal 'widerlegt', live 'ohne Referenz'. Beide rufen deshalb dieselbe
// Funktion, und beide Antworten tragen denselben truth-Wert.
//
// WAS GELIEFERT WIRD: je Master-Key die Fensterzahl der Referenz in allen drei Fenstern der
// Netzauskunft (1 h / 24 h / 30 d), je Fenster missed / total / score / incomplete, dazu asOfMs,
// weil die Referenz ein rollendes Fenster ab dem Zeitpunkt ihrer Auskunft ist. Ohne asOfMs ist
// keine Fensterzuordnung moeglich - die Gegenprobe bleibt dann offen, sie wird nicht als
// Entlastung gelesen. Kein Zugriff ist ein eigener Zustand, nicht eine Nullzahl.
//
// WARUM ALLE DREI FENSTER: die eigene Frage wechselt das Fenster (range 1 h bis 30 d). Wird nur
// das Tagesfenster mitgenommen, muss die 30-Tage-Frage gegen eine Tageszahl gerechnet werden und
// ein Teil der eigenen Spanne bleibt unbetrachtet. lib/validator-truth.mjs waehlt daraus das
// kleinste Fenster, das die eigene Spanne deckt.
import { validatorView } from "./validator-service.mjs";

// Die Schluessel sind die Fenster von TRUTH_WINDOWS (1 h / 24 h / 30 d), nicht die Stunden dahinter.
const WINDOW_FIELDS = [[1, "agreement1h"], [24, "agreement24h"], [30, "agreement30d"]];

export async function groundTruthMap() {
  try {
    const view = await validatorView();
    const asOfMs = view?.updatedAt ?? null;
    const map = new Map();
    for (const v of view?.validators ?? []) {
      if (!v?.key) continue;
      const windows = {};
      for (const [hours, field] of WINDOW_FIELDS) {
        const a = v[field] ?? {};
        windows[hours] = {
          missed: a.missed ?? null, total: a.total ?? null, score: a.score ?? null,
          incomplete: a.incomplete === true,
        };
      }
      map.set(v.key, { asOfMs, windows });
    }
    return map;
  } catch {
    // null ist ein eigener Zustand: die Referenz ist nicht erreichbar. Das ist nicht
    // "keiner hat etwas verpasst".
    return null;
  }
}

// Der Einstiegspunkt uebergibt die ganze Fenster-Karte; welches Fenster gerechnet wird, waehlt
// lib/validator-truth.mjs nach der eigenen Spanne. Hier wird nur nach dem Knoten gegriffen.
// Kein Treffer ist null: ohne Auskunft bleibt die Gegenprobe offen, nicht entlastet.
export function groundOf(map, master) {
  return map && master ? map.get(master) ?? null : null;
}
