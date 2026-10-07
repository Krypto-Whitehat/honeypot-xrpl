'use strict';

/* Honeypot XRPL – Cluster-Drilldown-Modal (public/drilldown.js)
 *
 * Vollbild-Modal zu einem Cluster: 3D-Visualisierung (3d-force-graph@1.80.0,
 * dynamisch per <script>-Injektion beim ersten Öffnen — das Bundle wird nie
 * eager geladen), graceful Fallback auf 2D vis-network, Rollen-Verteilung,
 * SVG-Zeitachse, Start-bis-Ende-Flusskette und Konten-Tabelle.
 *
 * cluster.id-Zentrierung: das Modal hält die cluster.id und re-looked sie bei
 * jedem Daten-Update gegen den aktuellen Cluster-Graphen (lastClusterGraph
 * wird pro Ledger ersetzt, Cluster sortieren neu) — nie ein stale Listen-
 * index. Die id ist instabil (sie wandert mit dem alphabetisch kleinsten
 * Mitglied, lib/cluster.mjs): Fehlt sie im aktuellen Graphen, zeigt das Modal
 * den LETZTEN bekannten Stand mit Alterungshinweis weiter ('Stand HH:MM:SS –
 * Cluster nicht mehr im aktuellen Beobachtungsfenster'); ein Fallback-Lookup
 * über die Mitglieder-Schnittmenge (≥2 gemeinsame Mitglieder UND ≥50 %,
 * jeweils gegen die Mitglieder des ORIGINÄR geöffneten Clusters als Anker)
 * übernimmt denselben Cluster nahtlos unter neuer id und meldet die Übernahme
 * mit einem Hinweis. Der Anker verhindert transitives Wandern: Nur der
 * ursprünglich geöffnete Cluster (oder ein Nachfolger mit ausreichend
 * Ursprungs-Überlappung) kann übernommen werden — schrittweises Hüpfen über
 * Zwischen-Snapshots hinaus ist ausgeschlossen (Befund 2026-09-30).
 * Total-Leerung nur bei openCluster auf einen bereits verschwundenen Cluster,
 * nach Snapshot-Kappe oder — immer vorrangig — bei Köder-Treffer in der
 * Deny-Reprüfung je refresh-Tick.
 *
 * GRUNDSATZ: c.id ('cluster:<Adresse>') wird NIE im DOM gerendert — er ist
 * ausschließlich interner Lookup-Schlüssel. Adressen laufen ausschließlich
 * durch die vom Host (app.js) gelieferten Funktionen displayAddr (im Host
 * gebunden an displayFindingAddr — die eigentliche Köder-Maske) /
 * isFullShownAddr: volle Anzeige nur bei geladener Bait-Hash-Allowlist und
 * Nicht-Treffer auf der Deny-Liste; sonst Kurzform ohne Kopier-Button und
 * ohne XRPScan-Link. Köder-Adressen und Seeds tauchen in keinem
 * Modal-Artefakt auf. Host-ctx ohne displayAddr-Funktion wird von
 * initClusterDrilldown fail-closed verworfen (Guard unten) — ohne
 * displayFindingAddr-Maske rendert das Modul keinerlei Adresse.
 */

import { t, fmtNum, fmtClock, sevText, getLang } from './i18n.mjs';
// Tx-Typ -> Kanten-Kategorie + Legende-Reihenfolge (DOM-frei, edge-colors.mjs;
// Farb-WERTE kommen theme-geführt aus ctx.edgeColors/EDGE_DEFAULT — app.js).
import { txCategory, EDGE_CATEGORY_ORDER } from './edge-colors.mjs';

// Lokales Vendoren (Performance-Umbau 2026-10-05): 3d-force-graph@1.80.0
// liegt in public/vendor/ (same-origin, vercel.json Rewrite /vendor/*). Der
// sha384-Hash wurde vor dem Vendoren gegen die exakten Bytes der gepinnten
// unpkg-URL verifiziert (1.313.897 B) — damit trägt auch dieses Bundle SRI
// (vorher: nur src+async, die einzige SRI-Lücke).
const FORCE_GRAPH_URL = 'vendor/3d-force-graph.min.js';
const FORCE_GRAPH_INTEGRITY = 'sha384-Y7bC2PBKu8ujxtvo5+Z61OeGdSVRzFsYWBK4i5dnL/U6aFDTodk61qOUkTfInaxS';

/* ---------------- 3D-Layout-Helfer (Entstapelung 2026-10-06) ----------------
 * Deterministisches Startlayout + Skalierung für build3D: Fibonacci-Kugel-
 * Startpositionen (kein Math.random — identische Cluster geben identische
 * Koordinaten), Radius-/Abstoßungs-/Link-Distanz-Skalierung nach Knotenanzahl
 * N, plus eine eigene Collide-Kraft: das vendorte Bundle (3d-force-graph@
 * 1.80.0) enthält keine forceCollide (grep 'collide' im Bundle: 0 Treffer),
 * d3-force-3d akzeptiert aber beliebige Kräfte mit initialize(nodes) über
 * fg3d.d3Force('collide', force) (Bundle: force:function(e,t){…u.set(e,g(t))},
 * Tick: u.forEach(function(e){e(alpha)})).
 * Die drei Helfer sind bewusst Modul-Level und exportiert: public/
 * drilldown-freeze.test.mjs prüft Determinismus, Skalierung (N=5..300) und
 * Überlappungsfreiheit der Startpositionen ohne Browser. */

// Volumen-Skalierung (3D-Forensik 2026-10-07): val = max(FLOOR, 1 + GAIN·
// ln(1 + drops/1e6)) — weiche logarithmische Skala mit hartem Floor, EINE
// Formel in EINEM Helper: cluster3dLayoutParams.valOf (unten) UND der
// nodeVal-Accessor in build3D rufen beide computeNodeVal auf (kein Formel-
// Drift; der Bundle-Radius bleibt r = nodeRelSize·cbrt(val)). Der Floor 8
// (cbrt(8) = 2) gibt drops-losen Knoten den Mindestradius 2·nodeRelSize —
// vorher saßen sie auf dem val=1-Fundament (r = nodeRelSize) und wurden im
// Mega-Cluster sub-pixel, weil seedRadius/chargeDistanceMax mit maxR des
// Mega-Knotens wuchsen und zoomToFit herausfuhr (514× Radius-Vorsprung,
// Live-readPixels 2026-10-07). Der Log-Anteil (GAIN 2) dämpft genau das:
// 135.4M XRP → 1.69× Unknown-Radius statt 514× — Drainer dominieren weiter
// (Farbe + 1.45×-Ring + Größe), das Layout bleibt kompakt. NaN/±Infinity
// fallen fail-closed auf den Floor (kein NaN-Radius im Physik-Lauf).
export const NODE_VAL_FLOOR = 8;
export const NODE_VAL_LOG_GAIN = 2;
export function computeNodeVal(totalDrops) {
  const drops = Math.max(0, totalDrops ?? 0);
  const val = 1 + NODE_VAL_LOG_GAIN * Math.log1p(drops / 1e6);
  return Number.isFinite(val) ? Math.max(NODE_VAL_FLOOR, val) : NODE_VAL_FLOOR;
}

export function cluster3dLayoutParams(nodes) {
  const N = Math.max(1, nodes.length);
  const k = Math.cbrt(N);
  // Radius-Formel des Bundles: r = nodeRelSize * cbrt(val); nodeRelSize
  // schrumpft mit cbrt(N) (Deckel 1.2), damit 300 Knoten auf der 520-px-
  // Bühne getrennt bleiben und 5 Knoten nicht unter ~3 px fallen.
  const nodeRelSize = Math.max(1.2, 4 / k);
  // val-Zugriff identisch zum nodeVal-Accessor in build3D — gemeinsamer
  // Helper computeNodeVal (oben), nicht zwei Formel-Kopien.
  const valOf = (n) => computeNodeVal((n.inDrops ?? 0) + (n.outDrops ?? 0));
  const radiusOf = (n) => Math.cbrt(valOf(n)) * nodeRelSize;
  let maxR = 0;
  for (const n of nodes) maxR = Math.max(maxR, radiusOf(n));
  // Startkugel so groß, dass die Sehnenlänge die größten Radien-Summen
  // (nahezu) trägt; der Warmup (Collide) restlos macht es ohnehin.
  const seedRadius = Math.max(12 * k * k, 0.6 * maxR * Math.sqrt(N));
  // Synchroner Warmup im Bundle (for(B=0;B<warmupTicks;B++)layout.tick() vor
  // Engine-Start) — Deckel 120 Ticks gegen Main-Thread-Jank.
  const warmupTicks = Math.min(120, Math.max(30, 2 * N));
  return {
    N, k, nodeRelSize, valOf, radiusOf, seedRadius, warmupTicks,
    chargeStrength: -60 * k * k,  // Bundle-Default -60 (numDimensions 3) * k²
    chargeDistanceMax: 6 * maxR,  // manyBody-Reichweite: ohne Deckel bläht die
                                  // Global-Abstoßung (unbegrenzte Reichweite)
                                  // Ketten-Layouts auf (Probe 2026-10-06:
                                  // bbox/maxR 132-347, Bubbles ~3 px); mit
                                  // 6·maxR bleibt das Layout kompakt UND
                                  // getrennt (bbox/maxR 10-70, 0 Überlappungen
                                  // bei N=5..300)
    // Link-Distanz radien-basiert statt 30·k: verbundene Knoten halten knapp
    // über ihrer Radien-Summe — kompakt bei großen Hubs, weit genug bei
    // kleinen Knoten (Collide-Kraft garantiert die Radien-Summen zusätzlich).
    linkDistance: (l) => 1.4 * (radiusOf(l.source) + radiusOf(l.target)),
  };
}

// Fibonacci-Kugel (Golden Angle, Muster der Bundle-eigenen Phyllotaxis-
// Initialisierung, dort aber mit Radius 10*cbrt(0.5+n) — viel zu klein für
// reale Knotenradien). Rein deterministisch: kein Math.random.
export function seedCluster3dPositions(nodes, radius) {
  const n = nodes.length;
  const golden = Math.PI * (3 - Math.sqrt(5));
  nodes.forEach((node, i) => {
    const z = n < 2 ? 0 : 1 - (i / (n - 1)) * 2;
    const r = Math.sqrt(Math.max(0, 1 - z * z));
    const theta = golden * i;
    node.x = Math.cos(theta) * r * radius;
    node.y = Math.sin(theta) * r * radius;
    node.z = z * radius;
  });
  return nodes;
}

// Kollisionstreiter (d3-force-3d-kompatibel): schiebt überlappende Paare
// geschwindigkeitsbasiert auseinander; schwere Knoten bewegen sich weniger
// (Gewichtung rb²/(ra²+rb²), Muster der d3-Collide). Deckungsgleiche Punkte
// bekommen eine feste Richtung — bleibt deterministisch.
// Kosten-Deckel der asynchronen Köder-Nachprüfung im Modal-Refresh (Live-
// Befund 2026-10-06): die vollständige sequenzielle Nachprüfung hasht JEDE
// Knoten-Adresse (webcrypto) — der 46.660-Knoten-Mega-Cluster blockierte das
// Öffnen/Refreshen des Modals im Browser >75 s (dazu LRU-Verdrängung: der
// Hash-Cache des Hosts fasst 10.000 Adressen, app.js ADDR_HASH_CACHE_MAX —
// die Nachprüfung lief also ohnehin nie stabil über den vollen Bestand).
// Deterministische Auswahl statt Zeitbudget: Top-N nach Drops-Summe (desc),
// dann Adresse asc — dieselbe Ordnung wie die 3D-Knoten-Kappe
// (GRAPH3D_MAX_NODES) in build3D. Adressen jenseits der Kappe bleiben vom
// SYNCHRONEN isDeniedAddr-Knoten-Gate (unten, fail-closed) und der
// Anzeige-Maske displayAddr gedeckt; der JSON-Export trägt sie wie bisher
// (unter LRU-Verdrängung war die Abdeckung zuvor ohnehin unvollständig —
// jetzt ist die Grenze deterministisch und dokumentiert).
export const DENY_RECHECK_MAX = 2000;

export function makeCluster3dCollideForce(radiusOf, strength = 0.8) {
  let nodes = [];
  const force = () => {
    const n = nodes.length;
    for (let i = 0; i < n; i++) {
      const a = nodes[i];
      const ra = radiusOf(a);
      for (let j = i + 1; j < n; j++) {
        const b = nodes[j];
        const rb = radiusOf(b);
        const need = ra + rb;
        let dx = a.x - b.x;
        let dy = a.y - b.y;
        let dz = a.z - b.z;
        const d2 = dx * dx + dy * dy + dz * dz;
        if (d2 >= need * need) continue;
        let d = Math.sqrt(d2);
        if (d < 1e-6) { dx = 1; dy = 0; dz = 0; d = 1; }
        const push = ((need - d) / d) * strength * 0.5;
        const wa = (rb * rb) / (ra * ra + rb * rb);
        const wb = 1 - wa;
        a.vx += dx * push * wa; a.vy += dy * push * wa; a.vz += dz * push * wa;
        b.vx -= dx * push * wb; b.vy -= dy * push * wb; b.vz -= dz * push * wb;
      }
    }
  };
  force.initialize = (n) => { nodes = n; };
  return force;
}

/* ---------------- 3D-Stil-Konstanten (Design P3, 2026-10-06) ----------------
 * Sichtbare Kanten-Staffelung statt Einheitsbreite: Payments tragen den
 * Geldfluss (breiteste Kante), strukturierte Mehrfach-Kontroll-Operationen
 * (Escrow/Check/NFToken) bleiben mittel, alles Übrige (TrustSet, Offers,
 * AccountSet, PaymentChannel) tritt auf 0.8 zurück. Basis-Deckkraft 0.85
 * (Bundle-Default wäre 0.2 — Kanten wären neben den Knoten kaum lesbar).
 * Alle Werte bewusst Modul-Level und exportiert: drilldown-freeze.test.mjs
 * prüft die Staffelung deterministisch ohne Browser. */
export const GRAPH3D_LINK_WIDTHS = Object.freeze({ payment: 1.4, structured: 1, other: 0.8 });
export const GRAPH3D_LINK_OPACITY = 0.85;
// ausgegraute Kantenfarbe für den Hover-Fokus (nicht beteiligte Kanten);
// Kontrolllinien-Ton — kein neues Farbsystem, keine Severity-Überladung.
// Bewusst exportiertes const (Import-Vertrag drilldown-freeze.test.mjs) und
// bewusst der HELL-Wert: THREE.Color parst kein rgba, die graute Farbe kann
// also nicht aus dem Alpha-Token --a6-line-strong gelesen werden. Noir
// erhält den Pendants GRAPH3D_LINK_FADED_NOIR; der Accessor wählt je
// jsTheme() (beide Töne absichtlich UNTER 3:1 — ausgegraute Kanten sind
// wie in Hell die bewusst rezessive Ebene hinter dem Hover-Fokus).
export const GRAPH3D_LINK_FADED = '#c9c9cf';
export const GRAPH3D_LINK_FADED_NOIR = '#514e66';
// Deckel der Drainer-Ringe (Design P3.2: „Customizing ≤ 12 Knoten ist der
// Performance-Schlüssel" — genau ein zusätzliches Mesh je markiertem Knoten).
export const GRAPH3D_RING_CAP = 12;

/* ---------------- Theme (Noir, 2026-10-06) ----------------
 * Die Farb-TABELLEN dieses Moduls (ctx.roleColors/ctx.edgeColors) mutiert
 * der Host in place (app.js applyThemeColors) — die Accessoren lesen sie je
 * Aufruf und brauchen keine eigene Kopie. Neue Unknown-Tinte (3D-Forensik
 * 2026-10-07: Noir Eisblau #bfe3ff / Hell Stahlblau #4a6478) läuft deshalb
 * ohne eigenen Listener über denselben Pfad: i18n feuert 'hx:themechange',
 * der Host mutiert THEME_JS_COLORS/ROLE_COLORS in place, der Theme-Listener
 * unten re-setzt die Accessoren + Ring-Material. Layer-Regel: Kugeln tragen
 * die ROLLEN-Farbe (hier nur base.background — der Rand wird im 3D-Bundle
 * bewusst NICHT gerendert: kein Extra-Geometry-Mesh je Knoten, sparsames
 * Glow-/Rand-Verhalten; die Rand-Töne leben in 2D/Legende), Kanten den Tx-
 * Typ. Nur die CANVAS-FONTS der 2D-Ausweichansicht folgen hier dem
 * dokumentierten Token-Weg: --a6-ink/--a6-body LIVE aus dem computed style
 * (Fallback = heutige Hell-Literale, damit Node-Tests ohne DOM unverändert
 * bleiben); jsTheme() liest das angewandte body[data-theme] (Default Hell
 * ohne DOM). */
function jsTheme() {
  try {
    const th = typeof document !== 'undefined' && document.body && document.body.dataset
      ? document.body.dataset.theme
      : null;
    return th === 'noir' ? 'noir' : 'light';
  } catch { return 'light'; }
}

function canvasInkColor() {
  try { return (getComputedStyle(document.body).getPropertyValue('--a6-ink') || '').trim() || '#141416'; }
  catch { return '#141416'; }
}

function canvasBodyColor() {
  try { return (getComputedStyle(document.body).getPropertyValue('--a6-body') || '').trim() || '#484850'; }
  catch { return '#484850'; }
}

function graph3dLinkFaded() {
  return jsTheme() === 'noir' ? GRAPH3D_LINK_FADED_NOIR : GRAPH3D_LINK_FADED;
}

// Kantenbreite nach Transaktionstyp. Schlüssel wie EDGE_COLORS (app.js):
// großgeschriebene XRPL-Typnamen; unbekannte Typen fallen auf 0.8 zurück.
export function cluster3dLinkWidth(type) {
  const ty = String(type ?? '');
  if (ty === 'Payment') return GRAPH3D_LINK_WIDTHS.payment;
  if (ty.startsWith('Escrow') || ty.startsWith('Check') || ty.startsWith('NFToken')) {
    return GRAPH3D_LINK_WIDTHS.structured;
  }
  return GRAPH3D_LINK_WIDTHS.other;
}

// Deterministische Ring-Auswahl: Drainer-Rolle, Top-Cap nach Drops-Summe
// (desc), Gleichstand über Adresse asc — dieselbe Ordnung wie die 3D-Knoten-
// Kappe und die Deny-Nachprüfung (Drops desc, dann id asc). Der Aggregat-
// knoten (role 'unknown') bleibt ausgeschlossen.
export function selectDrainerRingNodes(nodes, cap = GRAPH3D_RING_CAP) {
  const drainers = [];
  for (const n of nodes) {
    if (n && String(n.role) === 'drainer') drainers.push(n);
  }
  drainers.sort((a, b) =>
    ((Number(b?.inDrops) || 0) + (Number(b?.outDrops) || 0)) - ((Number(a?.inDrops) || 0) + (Number(a?.outDrops) || 0))
    || (String(a?.id) < String(b?.id) ? -1 : String(a?.id) > String(b?.id) ? 1 : 0));
  return new Set(drainers.slice(0, Math.max(0, cap)).map((n) => String(n.id)));
}

export function initClusterDrilldown(ctx) {
  const esc = ctx.esc;
  // Fail-closed-Anzeige-Maske (TRUNC-Invariante 2026-10-06): Der Host (app.js)
  // injiziert mit ctx.displayAddr seine displayFindingAddr — volle Adresse nur
  // bei geladener Allowlist und ohne Deny-Treffer, sonst Kurzform. Fehlt die
  // Funktion, initialisiert das Drilldown bewusst nicht: der Import-catch in
  // app.js lässt Karten-Klicks dann still wirkungslos, statt irgendeine
  // Adresse unmaskiert zu rendern. Der Guard härtet zugleich den
  // shortAddrFn-Fallback unten ab (Fallback displayAddr ist seither
  // garantiert eine Funktion).
  if (typeof ctx.displayAddr !== 'function') {
    throw new Error(
      'initClusterDrilldown: ctx.displayAddr fehlt — ohne die displayFindingAddr-Maske des Hosts (app.js) wird das Drilldown fail-closed nicht initialisiert'
    );
  }
  const displayAddr = ctx.displayAddr;
  const isFullShownAddr = ctx.isFullShownAddr;
  const isDeniedAddr = ctx.isDeniedAddr;
  // Asynchrone Deny-Prüfung für den JSON-Export (Kritik 2026-10-04): die
  // synchrone isDeniedAddr verneint ungehashte Adressen (LRU-Kappung des
  // addrHashCache möglich) — der Export darf keine ungeprüfte Adresse als
  // Volladresse liefern, also wird vor dem Export gehasht und dann geprüft
  // (Host-Funktion isDeniedAddrAsync, app.js). Fallback ohne Host-Funktion:
  // synchrone isDeniedAddr (Anzeige-Maske displayAddr greift zusätzlich).
  const isDeniedAddrAsync = typeof ctx.isDeniedAddrAsync === 'function' ? ctx.isDeniedAddrAsync : null;
  const flowPaths = ctx.flowPaths;
  const fmtXrp = ctx.fmtXrp;
  const fmtClock = ctx.fmtClock;
  const roleColors = ctx.roleColors;
  const edgeColors = ctx.edgeColors;
  // Theme-Thunk (Noir): app.js übergibt () => EDGE_DEFAULT — der Fallback-Ton
  // unbekannter Kantentypen wird je ZUGRIFF gelesen, nicht beim Init
  // eingefroren. Abwärtskompatibel: ein String-ctx (Node-Tests, makeCtx)
  // bleibt als Konstante nutzbar.
  const edgeDefaultOf = typeof ctx.edgeDefault === 'function' ? ctx.edgeDefault : () => ctx.edgeDefault;
  // Kantenfarbe je Tx-KATEGORIE (Audit 2026-10-07): ctx.edgeColors ist
  // kategorie-geählt (EDGE_COLORS, app.js); der Lookup läuft über
  // txCategory(edge-colors.mjs). Fallback ohne Host-Adapter (Node-Test-ctx):
  // Roh-Typ-Lookup — unbekannt bleibt es beim edgeDefaultOf.
  const edgeCategoryOf = typeof ctx.edgeCategory === 'function' ? ctx.edgeCategory : (ty) => String(ty ?? '');
  // Fraud-Override-Grundlage (Kritiker-Pflichtkorrektur 4): Adressen mit
  // severity 'malicious' im AKTUELLEN Cluster (Knoten tragen severity;
  // Cluster-Kanten aus dem Live-Pfad zusätzlich e.severity — Flow-State-
  // Kanten nicht). paintCluster setzt die Menge je Render; die Accessoren
  // (3D/2D/Zeitachse) lesen sie je Kante.
  let fraudAddrSet = new Set();
  const edgeIsFraud = (e) => {
    if (String(e?.severity ?? '') === 'malicious') return true;
    const from = e && typeof e.source === 'object' ? String(e.source.id ?? '') : String((e && e.from) ?? '');
    const to = e && typeof e.target === 'object' ? String(e.target.id ?? '') : String((e && e.to) ?? '');
    return fraudAddrSet.has(from) || fraudAddrSet.has(to);
  };
  const roleLabels = ctx.roleLabels;
  const addrActionsHtml = ctx.addrActionsHtml;
  // Namens-Badge-Lookup (XRPScan-Aliase): HOST-SEITIG GEGATET —
  // ctx.accountNameOf (app.js) liefert null für jede maskierte oder
  // Deny-Treffer-Adresse, das Modul kann das Gate nicht umgehen. Fallback
  // ohne Host-Funktion: () => null (fail-closed — ohne Lookup fehlt nur das
  // Badge, die Anzeige bleibt unverändert; Muster isDeniedAddrAsync oben).
  const accountNameOf = typeof ctx.accountNameOf === 'function' ? ctx.accountNameOf : () => null;
  const nameChipHtml = (addr) => {
    const entry = accountNameOf(addr);
    if (!entry) return '';
    const label = String(entry.name ?? '').trim();
    if (!label) return '';
    const verified = entry.verified === true;
    const aria = verified ? t('name.chipAria') : t('name.unverifiedAria');
    const mark = verified ? '<span class="name-chip-verified" aria-hidden="true">✓</span>' : '';
    const domain = typeof entry.domain === 'string' && entry.domain.trim()
      ? `<span class="name-chip-domain">${esc(entry.domain.trim())}</span>`
      : '';
    return `<span class="name-chip" role="img" aria-label="${esc(aria)}" title="${esc(aria)}">${mark}${esc(label)}${domain}</span>`;
  };
  // Multi-User-Lookup (Destination-Tag-Identität, Registry ∪ verifizierte
  // well-known-Namen — Coverage-Fix 2026-10-05): HOST-SEITIG GEGATET —
  // ctx.multiUserEntryOf (app.js) liefert null für jede maskierte oder
  // Deny-Treffer-Adresse und ohne Registry-/verifizierten Namens-Treffer.
  // Fallback ohne Host-Funktion: der frühere reine Registry-Lookup
  // ctx.exchangeEntryOf, sonst () => null (fail-closed — ohne Lookup fehlt
  // nur der Tag-Chip, die Anzeige bleibt unverändert; Muster accountNameOf
  // oben).
  const multiUserEntryOf = typeof ctx.multiUserEntryOf === 'function'
    ? ctx.multiUserEntryOf
    : (typeof ctx.exchangeEntryOf === 'function' ? ctx.exchangeEntryOf : () => null);
  // Tag-Chip-Markup (Muster nameChipHtml): Mono-Pill '#<Tag>' nur bei
  // Multi-User-Treffer der Adresse (Registry ODER verifizierter well-known-
  // Name, host-seitig gegatet) UND gültigem Tag. Tag 0 ist ein echter Tag
  // (lib/tag-identity.mjs) und zeigt '#0'.
  const tagChipHtml = (addr, tag) => {
    if (tag == null || typeof tag !== 'number' || !Number.isInteger(tag)) return '';
    if (!multiUserEntryOf(addr)) return '';
    const aria = t('tag.chipAria');
    return `<span class="tag-chip" role="img" aria-label="${esc(aria)}" title="${esc(aria)}">#${esc(String(tag))}</span>`;
  };
  // 2D-Canvas-Label in Kurzform (Design-Fix): shortAddr kommt bereits im ctx
  // des Hosts (app.js); Fallback displayAddr, falls ein Host es nicht liefert.
  const shortAddrFn = (typeof ctx.shortAddr === 'function') ? ctx.shortAddr : ctx.displayAddr;
  // Nachladen aus dem persistierten Bestand (Stale-Overlay-Fix 2026-10-06):
  // HOST-SEITIG GEGATET — ctx.getPersistedClusterById (app.js) liefert das
  // gemergte Cluster-Objekt (memberAddresses/rolesByAddress/severityByAddress/
  // edges) samt Knoten-Rekonstruktion. Fallback ohne Host-Funktion: null
  // (fail-closed — das Nachladen ist dann schlicht nicht möglich und der
  // Aufrufer fällt auf die Missing-Semantik zurück; Muster isDeniedAddrAsync
  // oben). Die Köder-Gates bleiben in jedem Fall beim Host bzw. im Modul
  // (sync isDeniedAddr-Knoten-Gate + Anzeige-Maske + Export-Nachprüfung).
  const getPersistedClusterById = typeof ctx.getPersistedClusterById === 'function'
    ? ctx.getPersistedClusterById
    : null;

  // Zwei-Zeilen-Graphlabel (B8, Muster B2 in app.js): volle Adresse nur bei
  // isFullShownAddr (Allowlist geladen, kein Deny-Treffer), sonst unverändert
  // Kurzform. Bei voller Adresse wird ein Zeilenumbruch nach Zeichen 24
  // eingefügt — vis-network rendert '\n' im Knotenlabel (Label-Clipping bei
  // 25–35 Zeichen langen Base58-Adressen war der Ausgangspunkt).
  // Name-Zusatz (XRPScan-Alias) NUR hinter dem Host-Gate: accountNameOf
  // liefert null für maskierte Adressen, also hängt der Name nie an einer
  // Kurzform. Adresse bleibt der primäre Label-Inhalt, der Name Zeile 2.
  const graphLabel = (id) => {
    const s = String(id ?? '');
    const name = accountNameOf(s);
    const nameSuffix = name ? `\n${name.name}` : '';
    if (s && isFullShownAddr(s)) return (s.length > 24 ? `${s.slice(0, 24)}\n${s.slice(24)}` : s) + nameSuffix;
    return shortAddrFn(id) + nameSuffix;
  };

  const num = (v) => fmtNum(v);
  // Rollen-Beschriftung übersetzt über die Legenden-Keys (EN: Collector,
  // DE: Kollektor); ctx.roleLabels bleibt Fallback für unbekannte Rollen.
  const roleLabelText = (role) => {
    const viaI18n = t('legend.' + role);
    if (viaI18n !== 'legend.' + role) return viaI18n;
    return ctx.roleLabels && ctx.roleLabels[role] ? ctx.roleLabels[role] : role;
  };
  const cssEscape = (s) => (window.CSS && typeof window.CSS.escape === 'function')
    ? window.CSS.escape(String(s))
    : String(s).replace(/[^a-zA-Z0-9_-]/g, (c) => `\\${c}`);

  let overlay = null;           // .cluster-modal (Shell)
  let surface = null;           // Dialog-Fläche
  let currentClusterId = null;  // cluster.id — nie der Listen-Index
  let isOpen = false;
  let renderToken = 0;          // Guard gegen überlappende async-Render

  // Konten-Tabelle mit Zeilen-Deckel (Diagnose: 25.458 <tr>, 329.289
  // DOM-Knoten, 6.118 ms Klick→Canvas). Standard 200 Zeilen, 'Mehr laden'
  // blendet je 200 weitere ein; openCluster setzt das Limit zurück.
  const TABLE_MAX_ROWS = 200;
  const TABLE_STEP = 200;
  let tableRowLimit = TABLE_MAX_ROWS;
  let lastTableNodes = null;    // letzter renderTable-Input für 'Mehr laden'
  let lastTableEdges = null;    // zugehörige Cluster-Kanten (Tag-Zuordnung je Zeile)
  let lastTableEl = null;       // zugehöriges Container-Element

  // 3D-Graph-Deckel (build3D): Top-N Knoten nach Drops-Summe + ein
  // Aggregatknoten für die nicht dargestellten Knoten.
  const GRAPH3D_MAX_NODES = 300;

  // 3d-force-graph: Singleton-Ladezustand (loadPromise + Injektions-Flag)
  let fg3dPromise = null;
  let fg3d = null;              // aktive 3D-Instanz
  let fg3dResizeObs = null;     // ResizeObserver der 3D-Bühne
  let vis2d = null;             // 2D-Ausweich-Instanz
  // Letzter build2D-Input (Knoten/Kanten/Container): der Theme-Wechsel baut
  // die 2D-Ausweichansicht daraus neu (per-node-Farben sind Konstruktions-
  // werte, ein reines setOptions reicht nicht); teardown2D löscht ihn.
  let last2dBuild = null;
  const highlightSet = new Set();
  // Hover-Fokus (Design P3.4): rohe Knoten-Id des gehoverten Knotens plus
  // ihr Anzeige-Wert-Pendant im highlightSet (Tabellen-Hover nutzt denselben
  // Mechanismus über displayAddr). null = kein aktiver Hover.
  let hover3dNodeId = null;
  let hover3dShown = null;
  let fg3dStageEl = null;       // Bühnen-Container (.cluster-3d) für die Cursor-Klasse
  // Drainer-Ring (Design P3.2): Auswahl + Layout des aktuellen Builds, die
  // gemeinsame Einheits-Geometrie/Material (ein Mesh je Ring) und der
  // Klassen-Abruf aus dem Bundle. Dispose ausschließlich in teardown3D.
  let ring3dIds = new Set();
  let ring3dLayout = null;
  let ring3dUnitGeo = null;     // Kugelgürtel-Band (Radius 1), gemeinsam für alle Ringe
  let ring3dMat = null;         // MeshLambertMaterial, Drainer-Rot, opacity 0.9, OHNE Emissive
  let ring3dClasses = null;     // {Mesh, SphereGeometry, MeshLambertMaterial} aus dem Bundle
  let ring3dClassesFailed = false;

  // Export-Payload (A3/A4): Cluster-Rohobjekt aus dem letzten Vollrender —
  // wird ausschließlich in render() gesetzt und in openCluster/close/
  // clearToEmptyState gelöscht. Der Download-Button ist hidden, solange kein
  // Payload existiert; der Export hängt damit an denselben Cluster-Gates wie
  // die Anzeige. exportToken guardiert überlappende async Nachprüfungen.
  let exportPayload = null;
  let exportToken = 0;

  /* Modal-Lebenszyklus (Symptom 3, Diagnose 2026-09-30): cluster.id ist
   * instabil — sie wird aus dem alphabetisch kleinsten Mitglied gebildet
   * (lib/cluster.mjs) und wechselt, sobald dieser ID-Träger aus dem rollenden
   * Fenster rollt, obwohl der Cluster unter neuer id weiterlebt. Fehlt die id
   * im aktuellen Graphen, zeigt render() deshalb den LETZTEN bekannten Stand
   * mit Alterungshinweis weiter (statt sofort total zu leeren); ein Fallback-
   * Lookup über die Mitglieder-Schnittmenge nimmt den Cluster unter neuer id
   * nahtlos auf. */
  const STALE_SNAPSHOT_MAX_MS = 300000; // Kappe des eingefrorenen Standes
                                        // (Akzeptanz fordert ≥60 s Lesbarkeit;
                                        // der Köder-Recheck läuft je refresh-
                                        // Tick unabhängig davon zusätzlich)
  let snapshot = null;          // letzter voll gerenderter Stand:
                                // {clusterId, at, members[]}
  let staleShown = false;       // Alterungshinweis aktuell sichtbar?
  let lastRenderDigest = null;  // Änderungs-Gate: unveränderte Inhalte → kein Vollrender
  let graphClusterId = null;    // Cluster-id des 3D-Graphen — zoomToFit nur bei
                                // Cluster-Wechsel/Erstrender (Kamera bleibt
                                // bei reinen Inhalts-Updates erhalten); dasselbe
                                // Gate steuert den 3D-Warmup (Entstapelung
                                // 2026-10-06): Live-Updates desselben Clusters
                                // warmen nicht erneut (kein synchroner Main-
                                // Thread-Jank je Poll)
  let originMembers = null;     // Fallback-ANKER (Befund 2026-09-30): Mitglieder
                                // des originär geöffneten Clusters, eingefroren
                                // bei der ersten erfolgreichen Renderung nach
                                // openCluster — bleibt stabil, damit der
                                // Fallback-Lookup nicht transitiv wandern kann
  let takeoverNoticeTimer = 0;  // Auto-Ausblendung des Übernahme-Hinweises

  /* Freeze (Inhalts-Einfrierung des OFFENEN Modals, Plan 2026-10-05):
   * Nach dem ersten erfolgreichen Vollrender kopiert das Modal Cluster,
   * Knoten und Kanten in `frozen`. Jeder Poll-Tick (live ~4-5 s, Archiv
   * 60 s, bait 60 s, hx:langchange) erreicht dann den Live-Lookup
   * (getClusterGraph), die Übernahme, das Digest-Gate, den
   * graphData-Austausch und den Camera-Reset NICHT mehr — kein Titel-
   * wechsel, kein Umsortieren, kein Layout-/Kamera-Neustart. Einzige
   * Ausnahmen je Tick: unveränderter Köder-Recheck (Deny-Liste rotiert
   * serverseitig alle 5 s — 'KÖDER-SCHUTZ SCHLÄGT ALTERUNGSANZEIGE'),
   * Sprachwechsel (Labels neu, Daten identisch) und der ehrliche
   * Zeitstempel-Hinweis. close() setzt frozen zurück; die Liste hinter
   * dem Modal bleibt live.
   * Bewusste Verhaltensänderung (Akzeptanzpunkt): die 300-s-Kappe
   * STALE_SNAPSHOT_MAX_MS greift das offene Modal nicht mehr — sie wirkt
   * nur im Missing-Cluster-Pfad. Gewollt: Freeze bis zum Schließen. */
  let frozen = null;            // {clusterId, at, lang, cluster, nodes, edges, members}
  let frozenLang = null;        // Sprache des zuletzt gemalten Freeze-Standes

  function reducedMotion() {
    try { return window.matchMedia('(prefers-reduced-motion: reduce)').matches; }
    catch { return false; }
  }

  // WebGL-Probe VOR der Konstruktion — Konstruktor-Fehler greift denselben
  // Fallback wie ein Fetch-Fehler des Bundles.
  function webglAvailable() {
    try {
      const c = document.createElement('canvas');
      return Boolean(c.getContext('webgl2') || c.getContext('webgl'));
    } catch {
      return false;
    }
  }

  function loadForceGraph3D() {
    if (typeof window.ForceGraph3D === 'function') return Promise.resolve(true);
    if (fg3dPromise) return fg3dPromise;
    fg3dPromise = new Promise((resolve) => {
      const s = document.createElement('script');
      s.src = FORCE_GRAPH_URL;
      s.integrity = FORCE_GRAPH_INTEGRITY; // SRI wie globe.js: Hash-Mismatch → Browser verwirft
      s.crossOrigin = 'anonymous';
      s.async = true;
      s.onload = () => resolve(typeof window.ForceGraph3D === 'function');
      s.onerror = () => resolve(false);
      document.head.appendChild(s);
    });
    return fg3dPromise;
  }

  /* ---------------- Shell ---------------- */

  function ensureShell() {
    if (overlay) return;
    overlay = document.createElement('div');
    overlay.className = 'cluster-modal';
    overlay.hidden = true;
    overlay.innerHTML = `
      <div class="cluster-modal-backdrop"></div>
      <div class="cluster-modal-surface" role="dialog" aria-modal="true" aria-labelledby="cluster-modal-title">
        <header class="cluster-modal-head">
          <div class="cluster-modal-title-wrap">
            <span class="cluster-label" id="cluster-modal-title"></span>
            <span class="cluster-modal-badge"></span>
          </div>
          <div class="cluster-modal-metrics"></div>
          <button type="button" class="cluster-modal-close" aria-label="${esc(t('modal.closeAria'))}">&times;</button>
        </header>
        <p class="graph-note cluster-modal-stale" role="status" hidden></p>
        <div class="cluster-modal-body">
          <section class="cluster-modal-graph" aria-label="${esc(t('modal.graphAria'))}">
            <div class="cluster-3d"></div>
            <!-- Kanten-Kategorien-Legende (Audit 2026-10-07): dasselbe
                 .legend/.legend-item/.swatch-Muster wie im Dashboard — Farben
                 ausschließlich über die --a6-edge-* Tokens (swatch-* Regeln,
                 style.css). Inhalt erst beim Graph-Render (renderEdgeLegend). -->
            <div class="legend cluster-graph-legend" id="cluster-graph-legend" hidden></div>
            <p class="graph-note cluster-graph-note" hidden></p>
          </section>
          <aside class="cluster-modal-side" aria-label="${esc(t('modal.detailsAria'))}">
            <section class="cluster-modal-roles" aria-label="${esc(t('modal.rolesAria'))}"></section>
            <section class="cluster-modal-timeline" aria-label="${esc(t('modal.timelineAria'))}"></section>
            <section class="cluster-modal-chain" aria-label="${esc(t('modal.chainAria'))}"></section>
            <!-- JSON-Export des Clusters (A1): verbleibt als letztes Kind der
                 Side-Spalte (Rollen/Zeitachse/Kette darüber). Die Konten-Tabelle
                 ist seit dem Layout-Fix 2026-10-06 kein Side-Kind mehr — sie
                 steht als letztes direktes Kind von .cluster-modal-body hinter
                 der aside und spannt via grid-column:1/-1 (drilldown.css) die
                 volle Modal-Breite. Label initial per t() und zusätzlich
                 data-i18n, damit applyStatic bei hx:langchange (app.js) den
                 Text in der neuen Sprache setzt — das Digest-Gate in render()
                 überspringt ein Retranslate sonst möglicherweise. -->
            <div class="cluster-modal-export">
              <button type="button" class="download-btn cluster-json-download" id="cluster-json-download" data-i18n="modal.downloadJson" hidden>${esc(t('modal.downloadJson'))}</button>
              <!-- PNG-Export des Cluster-Graphen (Fix 2026-10-07): Geschwister
                   des JSON-Buttons, gleiches .download-btn-Muster wie
                   index.html (graph.downloadPng). initial hidden; Sichtbarkeit
                   steuert renderGraph (setPngBtnVisible) — nur wenn ein
                   exportierbarer Canvas steht (3D mit preserveDrawingBuffer
                   oder 2D-vis-Fallback), nie im noGraph-Zustand. -->
              <button type="button" class="download-btn cluster-png-download" id="cluster-png-download" data-i18n="modal.downloadPng3d" hidden>${esc(t('modal.downloadPng3d'))}</button>
              <p class="graph-note cluster-export-note" data-i18n="export.clusterNote" hidden>${esc(t('export.clusterNote'))}</p>
            </div>
          </aside>
          <!-- Konten-Tabelle (Layout-Fix 2026-10-06): bewusst LETZTES direktes
               Kind von .cluster-modal-body HINTER der aside — vorher steckte sie
               in der Side-Spalte und lief auf 45 % Body-Breite (gemessen 606 px
               Client-Breite bei 1283 px Naturbreite → horizontaler Scroll ab
               jeder Desktop-Größe). drilldown.css setzt grid-column:1/-1: Das
               2-Spalten-Grid (Graph + Side) bleibt für die erste Zeile
               erhalten, die Tabelle läuft als zweite, volle Zeile darunter;
               der Body scrollt dafür vertikal (overflow:auto, dokumentiert in
               drilldown.css). renderTable füllt sie positionsunabhängig per
               querySelector('.cluster-modal-table'). -->
          <section class="cluster-modal-table" aria-label="${esc(t('modal.tableAria'))}"></section>
        </div>
      </div>`;
    document.body.appendChild(overlay);
    surface = overlay.querySelector('.cluster-modal-surface');

    overlay.querySelector('.cluster-modal-backdrop').addEventListener('click', close);
    overlay.querySelector('.cluster-modal-close').addEventListener('click', close);
    // A2: Klick auf den JSON-Download — Handler ruft den Blob-Export auf.
    overlay.querySelector('#cluster-json-download').addEventListener('click', downloadClusterJson);
    // PNG-Download des Cluster-Graphen (Fix 2026-10-07): analoge Bindung.
    overlay.querySelector('#cluster-png-download').addEventListener('click', downloadClusterPng);
    document.addEventListener('keydown', (e) => {
      if (!isOpen) return;
      if (e.key === 'Escape') { e.preventDefault(); close(); return; }
      if (e.key === 'Tab') trapFocus(e);
    });
    // Hover auf Tabellenzeile -> Knoten im 3D-Graph einfärben.
    surface.addEventListener('mouseover', (e) => {
      const row = e.target.closest('tr[data-addr]');
      if (!row) return;
      highlightSet.add(String(row.dataset.addr));
      if (fg3d) fg3d.nodeColor(nodeColorAccessor());
    });
    surface.addEventListener('mouseout', (e) => {
      const row = e.target.closest('tr[data-addr]');
      if (!row) return;
      highlightSet.delete(String(row.dataset.addr));
      if (fg3d) fg3d.nodeColor(nodeColorAccessor());
    });
    // 'Mehr laden' in der Konten-Tabelle (delegiert wie die addr-Actions im
    // Host): erhöht das Zeilenlimit und baut die Tabelle aus dem zuletzt
    // gerenderten Input neu auf.
    surface.addEventListener('click', (e) => {
      const btn = e.target.closest('.cluster-table-more');
      if (!btn) return;
      tableRowLimit += TABLE_STEP;
      if (lastTableNodes && lastTableEl) renderTable(lastTableNodes, lastTableEl);
    });
    // Sprachwechsel (hx:langchange, app.js): das Modal hatte bisher KEINEN
    // eigenen Listener — der Retranslate lief über den Live-Pfad von
    // refresh() und wurde vom sprachblinden Digest-Gate möglicherweise
    // übersprungen (dokumentierter Mangel, Kommentar im Shell-Export-Block).
    // Jetzt: Freeze-Pfad malt Labels in der neuen Sprache (recheckFrozen),
    // Live-Pfad ist über den Sprache-Digest-Anteil nicht mehr sprachblind.
    try {
      document.addEventListener('hx:langchange', () => { if (isOpen) render(); });
    } catch { /* Noop ohne addEventListener */ }
    // Theme-Wechsel (hx:themechange, i18n.mjs initThemeSwitcher): die Farb-
    // Tabellen des Hosts (roleColors/edgeColors) sind zu diesem Zeitpunkt
    // bereits in place mutiert. Nachziehen: (1) Drainer-Ring-Material —
    // einmalig gebaut und für die Modal-Lebensdauer gecacht, ohne explizites
    // color.set bliebe es im alten Rot; (2) 3D-Stil über den etablierten
    // Accessor-Re-Set-Pfad (Muster on3dNodeHover); (3) 2D-Fallback aus den
    // zuletzt gebauten Daten neu erzeugen (per-node-Farben sind
    // Konstruktionswerte — ein reines setOptions reicht nicht).
    try {
      document.addEventListener('hx:themechange', () => {
        try {
          if (ring3dMat && roleColors.drainer && roleColors.drainer.background) {
            ring3dMat.color.set(roleColors.drainer.background);
          }
        } catch { /* Material-API fehlt: Rebuild-Pfad greift beim nächsten Öffnen */ }
        try {
          if (fg3d) {
            fg3d.nodeColor(nodeColorAccessor());
            fg3d.linkColor(linkColor3dAccessor());
            fg3d.linkWidth(linkWidth3dAccessor());
          }
        } catch { /* Accessor-Set nicht verfügbar */ }
        try {
          if (vis2d && last2dBuild) {
            teardown2D();
            build2D(last2dBuild.nodes, last2dBuild.edges, last2dBuild.el);
          }
        } catch { /* 2D-Rebuild optional — Modal bleibt funktionsfähig */ }
      });
    } catch { /* Noop ohne addEventListener */ }
  }

  function getFocusables() {
    // D8: !el.disabled ergänzt — ein deaktivierter Download-Button darf den
    // Tab-Fokustrap nicht blockieren (hidden/deaktivierte Elemente scheiden aus).
    return [...surface.querySelectorAll('button, a[href], [tabindex="0"]')]
      .filter((el) => !el.hidden && !el.disabled && el.offsetParent !== null);
  }

  function trapFocus(e) {
    const focusables = getFocusables();
    if (!focusables.length) return;
    const first = focusables[0];
    const last = focusables[focusables.length - 1];
    if (e.shiftKey && document.activeElement === first) {
      e.preventDefault();
      last.focus();
    } else if (!e.shiftKey && document.activeElement === last) {
      e.preventDefault();
      first.focus();
    }
  }

  /* ---------------- Öffnen / Schließen / Aktualisieren ---------------- */

  function openCluster(clusterId) {
    ensureShell();
    currentClusterId = String(clusterId);
    isOpen = true;
    // openCluster beginnt IMMER bei null Stand: Ein überalterter Snapshot eines
    // früher geöffneten Clusters wird verworfen — klickt der Nutzer auf einen
    // inzwischen verschwundenen Cluster (stale Karte/Bubble), zeigt das Modal
    // die ehrliche Total-Leerung statt eines fremden Letztstandes.
    snapshot = null;
    staleShown = false;
    originMembers = null; // Fallback-ANKER neu einfrieren (Befund 2026-09-30)
    frozen = null;        // Freeze neu beginnen: openCluster startet immer bei null Stand
    frozenLang = null;
    exportPayload = null; // A4: Export-Grundlage gilt nur für den nächsten Vollrender
    exportToken += 1;     // laufende async-Nachprüfung verwerfen
    // Hidden-Invariante (Fix 2026-10-07, P1-Hygiene): openCluster beginnt —
    // wie close() und clearToEmptyState — mit verborgenen Export-Buttons.
    // Vorher nullte nur der Live-Zweig die Grundlage, ohne die Buttons zu
    // verstecken: ein zuvor live gerenderter Cluster ließ JSON-/PNG-Button
    // sichtbar, obwohl der Early-Return in downloadClusterJson/
    // downloadClusterPng den Download verwirft ('sichtbar aber tot').
    const openDlBtn = overlay.querySelector('#cluster-json-download');
    if (openDlBtn) openDlBtn.hidden = true;
    const openDlNote = overlay.querySelector('.cluster-export-note');
    if (openDlNote) openDlNote.hidden = true;
    setPngBtnVisible(false);
    tableRowLimit = TABLE_MAX_ROWS; // Tabellen-Deckel pro Cluster neu beginnen
    clearTakeoverNotice();
    const staleNote = overlay.querySelector('.cluster-modal-stale');
    if (staleNote) staleNote.hidden = true;
    lastRenderDigest = null; // Vollrender erzwingen (Modul-eigenes Änderungs-Gate)
    graphClusterId = null;   // zoomToFit/Camera-Reset als Erstrender zulassen
    overlay.hidden = false;
    document.body.classList.add('cluster-modal-open');
    render();
    const closeBtn = overlay.querySelector('.cluster-modal-close');
    if (closeBtn) closeBtn.focus();
  }

  // Wird von app.js nach jedem Cluster-Neubau aufgerufen: das Modal re-looked
  // die cluster.id gegen den aktuellen Graphen — nie ein stale Index.
  function refresh() {
    if (!isOpen) return;
    render();
  }

  function close() {
    if (!isOpen) return;
    const id = currentClusterId;
    isOpen = false;
    currentClusterId = null;
    originMembers = null; // Anker verfällt mit dem Modal (neues Öffnen friert neu)
    frozen = null;        // ab dem Schließen greift wieder Live-Rendering
    frozenLang = null;
    exportPayload = null; // A4: kein Export über die Lebensdauer des Modals hinaus
    exportToken += 1;
    // Hidden-Invariante (Fix 2026-10-07, P1): close() nullt die
    // Export-Grundlage — also müssen JSON-Button, Export-Hinweis und
    // PNG-Button ebenfalls verborgen werden (dasselbe Muster wie
    // clearToEmptyState 874-877). Ohne das bliebe nach einem Live-Render
    // ein toter, aber sichtbarer Button im Shell stehen.
    const closeDlBtn = overlay.querySelector('#cluster-json-download');
    if (closeDlBtn) closeDlBtn.hidden = true;
    const closeDlNote = overlay.querySelector('.cluster-export-note');
    if (closeDlNote) closeDlNote.hidden = true;
    setPngBtnVisible(false);
    clearTakeoverNotice();
    renderToken += 1;
    overlay.hidden = true;
    document.body.classList.remove('cluster-modal-open');
    highlightSet.clear();
    reset3dHover(); // Hover-Fokus bleibt nicht über das geschlossene Modal stehen
    if (fg3d) { try { fg3d.pauseAnimation(); } catch { /* egal */ } }
    // Fokus-Rückkehr: Karte, deren aktueller Index dieselbe cluster.id trägt,
    // sonst die Cluster-Liste.
    const card = findCardForClusterId(id);
    const target = card || document.getElementById('cluster-list');
    if (target && typeof target.focus === 'function') target.focus();
  }

  function findCardForClusterId(id) {
    const cg = ctx.getClusterGraph();
    const clusters = cg && Array.isArray(cg.clusters) ? cg.clusters : [];
    const idx = clusters.findIndex((c) => c.id === id);
    if (idx < 0) return null;
    return document.querySelector(`#cluster-list .cluster-card[data-cluster-index="${idx}"]`);
  }

  /* ---------------- Rendern ---------------- */

  // Fallback-Lookup mit GEKOPPELTER Schwelle, verankert am ORIGINÄR geöffneten
  // Cluster (Befund 2026-09-30): Die neue cluster.id wird nur übernommen, wenn
  // ≥2 gemeinsame Mitglieder mit dem ANKER (nicht dem jeweils letzten
  // Snapshot) UND eine Schnittmenge von ≥50 % (bezogen auf die kleinere der
  // beiden Mitgliederzahlen) vorliegen. Eine reine 50-%-Schwelle matcht bei
  // 2er-Clustern jeden Cluster mit nur EINEM gemeinsamen Mitglied — genau das
  // koppelt die zweite Bedingung ab. Das Matching gegen den Vorgänger-Snapshot
  // ließ das Modal dagegen transitiv wandern (jeder Hopp verschob den
  // Maßstab mit); der Anker bleibt über die Lebensdauer des geöffneten Modals
  // stabil, sodass nur Nachfolger des ORIGINÄLLEN Clusters übernommen werden
  // können — ein Cluster ohne gemeinsame Ursprungs-Mitglieder wird abgelehnt.
  function findFallbackCluster(clusters) {
    if (!originMembers || originMembers.size < 2) return null;
    let best = null;
    let bestInter = 0;
    for (const c of clusters) {
      const members = Array.isArray(c.memberAddresses) ? c.memberAddresses : [];
      let inter = 0;
      for (const m of members) {
        if (originMembers.has(String(m))) inter += 1;
      }
      if (inter < 2) continue; // Bedingung 1: ≥2 gemeinsame Mitglieder mit dem Anker
      const denom = Math.min(originMembers.size, members.length);
      if (denom > 0 && inter / denom < 0.5) continue; // Bedingung 2: ≥50 %
      if (inter > bestInter) { best = c; bestInter = inter; }
    }
    return best;
  }

  // Übernahme-Hinweis (Befund 2026-09-30): Der verankerte Fallback-Lookup hat
  // denselben Cluster unter neuer id aufgenommen — der Titel wechselt mit,
  // deshalb wird die Übernahme ehrlich gemeldet statt still vollzogen. Der
  // Hinweis blendet sich nach kurzer Zeit selbst aus; ein aktiver
  // Alterungshinweis bleibt unangetastet (dieser ist vorrangig).
  function clearTakeoverNotice() {
    if (takeoverNoticeTimer) { clearTimeout(takeoverNoticeTimer); takeoverNoticeTimer = 0; }
  }

  function showTakeoverNotice() {
    const note = overlay && overlay.querySelector('.cluster-modal-stale');
    if (note) {
      note.textContent = t('modal.takeover');
      note.hidden = false;
    }
    clearTakeoverNotice();
    takeoverNoticeTimer = setTimeout(() => {
      takeoverNoticeTimer = 0;
      if (staleShown) return; // Alterungshinweis ist aktiv und bleibt stehen
      const n = overlay && overlay.querySelector('.cluster-modal-stale');
      if (n) n.hidden = true;
    }, 10000);
  }

  // Änderungs-Gate INHALTLICH (im Modul, nicht im Aufrufer): Vergleicht id,
  // Metriken, Mitglieder (inkl. Rollen/Drops/Schweregrad/Grade) und Kanten des
  // ANGEZEIGTEN Clusters gegen den zuletzt gerenderten Stand. app.js bleibt der
  // einfache Aufrufer (drilldown.refresh()), denn nur das Modul kennt seinen
  // gerenderten Stand — sonst bliebe das ~4-s-Vollrender des offenen Modals bei
  // Änderung IRGENDeines Clusters bestehen.
  function clusterDigest(cluster, clusterNodes, clusterEdges) {
    const nodes = clusterNodes
      .map((n) => `${n.id}:${n.role ?? ''}:${n.inDrops ?? 0}:${n.outDrops ?? 0}:${n.degreeIn ?? 0}:${n.degreeOut ?? 0}:${n.severity ?? ''}`)
      .sort()
      .join('|');
    // Tag-Anteil (tagIdentityDesign): toTag/transit gehören in den Digest —
    // ohne sie würde ein nachträglich mit Tags angereicherter Kantenstand
    // das offene Modal nicht aktualisieren (Freeze-Semantik unverändert:
    // der Digest entscheidet nur über "neu rendern oder nicht").
    const edges = clusterEdges
      .map((e) => `${e.from}>${e.to}:${e.type ?? ''}:${e.txHash ?? ''}:${e.closeTime ?? ''}:${e.toTag ?? ''}:${e.transit ? 1 : 0}`)
      .sort()
      .join('|');
    return `${cluster.id}#${cluster.label ?? ''}#${cluster.totalDrops ?? 0}#${cluster.txCount ?? 0}`
      + `#${cluster.distinctAccounts ?? 0}#${cluster.firstSeen ?? ''}#${cluster.lastSeen ?? ''}#${nodes}#${edges}`;
  }

  // Alterungszustand lösen (Cluster wieder da): Hinweis verbergen, Graph fortsetzen.
  function endStaleState() {
    if (!staleShown) return;
    staleShown = false;
    const note = overlay.querySelector('.cluster-modal-stale');
    if (note) note.hidden = true;
    if (fg3d) { try { fg3d.resumeAnimation(); } catch { /* egal */ } }
  }

  // Ehrliche Total-Leerung (früher das Standardverhalten bei fehlender id):
  // nur noch bei openCluster auf bereits verschwundenen Cluster, nach Ablauf
  // der Snapshot-Kappe oder — vor allen anderen Gründen — bei Köder-Treffer.
  function clearToEmptyState(els) {
    snapshot = null;
    staleShown = false;
    frozen = null;   // Total-Leerung (Köder-Treffer/leerer Freeze-Satz) wirft
    frozenLang = null; // auch den Freeze-Satz ersatzlos raus
    clearTakeoverNotice(); // Übernahme-Hinweis hat seinen Cluster verloren
    // A4: Total-Leerung löscht auch die Export-Grundlage; Button und Hinweis
    // bleiben verborgen, bis ein erfolgreicher Vollrender sie wieder setzt.
    exportPayload = null;
    exportToken += 1;
    const dlBtn = overlay.querySelector('#cluster-json-download');
    if (dlBtn) dlBtn.hidden = true;
    const dlNote = overlay.querySelector('.cluster-export-note');
    if (dlNote) dlNote.hidden = true;
    const note = overlay.querySelector('.cluster-modal-stale');
    if (note) note.hidden = true;
    els.titleEl.textContent = t('cluster.labelDefault');
    els.badgeEl.innerHTML = '';
    els.metricsEl.innerHTML = '';
    els.rolesEl.innerHTML = '';
    els.timelineEl.innerHTML = '';
    els.chainEl.innerHTML = '';
    els.tableEl.innerHTML = '';
    teardown3D();
    teardown2D();
    setPngBtnVisible(false); // kein Graph -> kein PNG-Export (Fix 2026-10-07)
    els.graphEl.innerHTML = `<p class="graph-note">${esc(t('modal.gone'))}</p>`;
    els.noteEl.hidden = true;
  }

  // cluster.id fehlt im aktuellen Graphen: LETZTEN bekannten Stand weiterzeigen
  // (Titel/Badge/Metriken/Rollen/Zeitachse/Kette/Tabelle bleiben im DOM, Graph
  // pausiert) plus Alterungshinweis mit Stand-Zeitpunkt.
  function renderMissingCluster(els) {
    // KÖDER-SCHUTZ SCHLÄGT ALTERUNGSANZEIGE IN JEDEM FALL: Die Deny-Liste
    // rotiert serverseitig alle 5 s, rebuildDisplayAndKnownBad bewertet bei
    // jedem Load neu — der eingefrorene Snapshot darf diese Fail-closed-
    // Neubewertung nie umgehen. Deshalb bei JEDEM refresh-Tick die Member-
    // Hashes gegen die AKTUELLE baitHashDeny prüfen (isDeniedAddr synchron
    // über den geprimten addrHashCache) und bei Treffer sofort leeren.
    if (snapshot && typeof isDeniedAddr === 'function') {
      for (const m of snapshot.members) {
        if (isDeniedAddr(m)) {
          clearToEmptyState(els);
          return;
        }
      }
    }
    if (!snapshot || Date.now() - snapshot.at > STALE_SNAPSHOT_MAX_MS) {
      clearToEmptyState(els);
      return;
    }
    if (!staleShown) {
      staleShown = true;
      const note = overlay.querySelector('.cluster-modal-stale');
      if (note) {
        note.textContent = t('modal.stale', { time: fmtClock(snapshot.at) });
        note.hidden = false;
      }
      if (fg3d) { try { fg3d.pauseAnimation(); } catch { /* egal */ } }
    }
  }

  /* Freeze-Hilfe: verweigerte Adressen aus dem Freeze-Satz schneiden —
   * Knoten, Kanten (beide Enden müssen bleiben) und members-Fallback.
   * Muster der asynchronen Deny-Nachprüfung im Vollrender unten. */
  function removeFrozenMembers(denied) {
    if (!frozen || !denied || !denied.size) return;
    frozen.nodes = frozen.nodes.filter((n) => !denied.has(String(n.id)));
    frozen.edges = frozen.edges.filter((e) =>
      !denied.has(String(e.from)) && !denied.has(String(e.to)));
    frozen.members = frozen.members.filter((a) => !denied.has(String(a)));
  }

  // Freeze-Hinweis (ehrlicher Zeitstempel): wiederverwendet die
  // .cluster-modal-stale-Zeile. staleShown=true hält den Auto-Ausblend-
  // Timer des Übernahme-Hinweises fern (showTakeoverNotice: 'if (staleShown)
  // return') und wird je Tick neu gesetzt, weil paintCluster/endStaleState
  // die Zeile im Sprachwechsel-Pfad kurz ausräumen. Freezes, die aus dem
  // persistierten Bestand nachgeladen wurden (frozen.fromPersisted), zeigen
  // stattdessen modal.persisted — der Hinweis bleibt so je Tick erhalten,
  // statt sich nach einem Tick zum modal.frozen-Text zu wandeln.
  function showFrozenNote() {
    if (!frozen) return;
    staleShown = true;
    const note = overlay.querySelector('.cluster-modal-stale');
    if (note) {
      note.textContent = frozen.fromPersisted
        ? t('modal.persisted', { time: fmtClock(frozen.persistedAt ?? frozen.at) })
        : t('modal.frozen', { time: fmtClock(frozen.at) });
      note.hidden = false;
    }
  }

  /* Nachladen aus dem persistierten Bestand (Stale-Overlay-Fix 2026-10-06,
   * Richtung b): Ein Cluster, dessen Karte im akkumulierten Bestand lebt
   * (mergeClusterViews/Session-Schicht), dessen Knoten aber aus dem FIFO-
   * Fenster gerollt sind, wird hier aus dem persistierten Stand rekonstruiert
   * und voll gemalt — statt einer leeren Hülle mit nachfolgendem modal.gone-
   * Flapping. Köder-Sicherheit: der rekonstruierte Knotensatz durchläuft
   * DASSELBE synchrone isDeniedAddr-Knoten-Gate wie der Vollrender; bleiben
   * 0 Knoten übrig (alles Köder), gewinnt der Köder-Deny als Terminalzustand
   * (clearToEmptyState, KEIN Reload-Wiederversuch, Invariante Plan-Korrektur
   * 1). Die asynchrone Nachprüfung bleibt unverändert vor dem Export (je
   * Download) und je Freeze-Tick (recheckFrozen) aktiv. Liefert der Bestand
   * nichts, kehrt die Funktion mit false zurück — der Aufrufer routet dann
   * explizit in die Missing-Semantik (renderMissingCluster). */
  async function tryRestorePersistedCluster(els, cluster, token) {
    if (!getPersistedClusterById) return false;
    let persisted = null;
    try {
      persisted = await getPersistedClusterById(String(cluster.id));
    } catch { /* Bestand nicht erreichbar: ehrlicher Fallback unten */ }
    if (token !== renderToken || !isOpen) return true; // zwischenzeitlich neu gerendert/geschlossen
    if (!persisted || !Array.isArray(persisted.nodes) || !persisted.nodes.length) return false;
    // SYNC KÖDER-GATE (Muster des Knoten-Gates im Vollrender): rekonstruierte
    // Knoten filtern wie Live-Knoten — Köder erreichen nie Tabelle oder Graph.
    const restoredNodes = (typeof isDeniedAddr === 'function')
      ? persisted.nodes.filter((n) => !isDeniedAddr(String(n.id)))
      : persisted.nodes;
    if (!restoredNodes.length) {
      // ALLES Köder: Total-Leerung — Köder-Deny > Freeze/Nachladen bleibt
      // die erste Auswertungsreihenfolge (Sicherheitsinvariante).
      clearToEmptyState(els);
      return true;
    }
    const restoredIds = new Set(restoredNodes.map((n) => String(n.id)));
    const restoredEdges = (Array.isArray(persisted.edges) ? persisted.edges : [])
      .filter((e) => restoredIds.has(String(e.from)) && restoredIds.has(String(e.to)));
    // Fallback-ANKER aus dem restaurierten Bestand (Semantik der ersten
    // erfolgreichen Renderung) — nie aus einer leeren Knotenmenge setzen,
    // sonst bliebe der Anker dauerhaft unbrauchbar.
    if (!originMembers) originMembers = new Set(restoredIds);
    await paintCluster(els, persisted.cluster, restoredNodes, restoredEdges, token, false, true, persisted.at ?? null);
    if (token !== renderToken || !isOpen) return true; // zwischenzeitlich neu gerendert/geschlossen
    // EXPORT-AKTIVIERUNG IM NACHLADE-PFAD (Fix 2026-10-07, P1): der
    // node-lose Restore-Zweig umlief den Aktivierungs-Block des Live-Pfads
    // (render() 1200-1204) komplett — exportPayload blieb null, der Button
    // unsichtbar, downloadClusterJson lief in den Early-Return. Derselbe
    // Block jetzt auch hier: Payload aus dem restaurierten Satz (die
    // asynchrone Deny-Nachprüfung je Download und der Freeze-Tick-Schnitt
    // recheckFrozen bleiben unverändert aktiv), Button/Hinweis erst nach
    // erfolgreichem paintCluster sichtbar.
    exportPayload = buildExportPayload(persisted.cluster, restoredNodes, restoredEdges);
    const dlBtnEl = overlay.querySelector('#cluster-json-download');
    if (dlBtnEl) dlBtnEl.hidden = false;
    const dlNoteEl = overlay.querySelector('.cluster-export-note');
    if (dlNoteEl) dlNoteEl.hidden = false;
    return true;
  }

  /* Freeze-Tick (render() leitet jeden Tick hierher um): der offene Stand
   * wird NIE gegen den Live-Graphen neu gemalet — kein Lookup, keine
   * Übernahme, kein Digest-Gate, kein graphData-Austausch, kein
   * Camera-Reset. Einzige Ausnahmen: (1) unveränderter Köder-Recheck —
   * Deny-Liste rotiert serverseitig alle 5 s, 'KÖDER-SCHUTZ SCHLÄGT
   * ALTERUNGSANZEIGE' (Muster renderMissingCluster + Export-Gate): Treffer
   * fallen einzeln aus Knoten/Kanten/Export; ist danach nichts mehr übrig,
   * ehrliche Total-Leerung. (2) Sprachwechsel: Labels werden neu gemalt,
   * Daten bleiben der Freeze-Satz. (3) der Zeitstempel-Hinweis. */
  async function recheckFrozen(els, token) {
    let removed = false;
    if (typeof isDeniedAddr === 'function') {
      const hits = new Set();
      for (const n of frozen.nodes) {
        if (isDeniedAddr(String(n.id))) hits.add(String(n.id));
      }
      if (hits.size) { removeFrozenMembers(hits); removed = true; }
    }
    if (isDeniedAddrAsync) {
      try {
        const denied = new Set();
        for (const a of frozen.members) {
          if (await isDeniedAddrAsync(a)) denied.add(a);
        }
        if (denied.size) { removeFrozenMembers(denied); removed = true; }
      } catch { /* Nachprüfung fehlgeschlagen: Freeze bleibt auf bisheriger Basis */ }
      if (token !== renderToken || !isOpen) return; // zwischenzeitlich neu gerendert/geschlossen
    }
    if (!frozen) return; // clearToEmptyState hat den Freeze bereits verworfen
    if (!frozen.nodes.length) {
      // Köder-Deny Kompletttreffer (removed): Total-Leerung bleibt der
      // legitime Terminalzustand — Köder-Deny schlägt Freeze (Invariante).
      if (removed) { clearToEmptyState(els); return; }
      // Leerer Freeze-Satz OHNE Deny-Treffer (seit dem paintCluster-Guard
      // 'Freeze nur bei clusterNodes.length > 0' unerreichbar, defensiv
      // gehalten): Zustand halten und Hinweis zeigen — NIE total leeren,
      // sonst degeneriert das offene Modal zur leeren Hülle mit Banner
      // (Massenbefund 2026-10-06) und flappt je Tick zwischen leerer Hülle
      // und modal.gone.
      showFrozenNote();
      return;
    }
    if (removed || getLang() !== frozenLang) {
      // Deny-Treffer ODER Sprachwechsel: Title/Badge/Metriken/Rollen/
      // Zeitachse/Kette/Tabelle/Graph aus dem (gekappten) Freeze-Satz neu
      // malen — ein nachträglich verweigertes Mitglied darf nicht als
      // DOM-Zeile im offenen Modal stehen bleiben (KÖDER-SCHUTZ SCHLÄGT
      // FREEZE, Grundsatz 'Total-Leerung ... bei Köder-Treffer').
      await paintCluster(els, frozen.cluster, frozen.nodes, frozen.edges, token, false);
      if (token !== renderToken || !isOpen) return;
      frozenLang = getLang();
    }
    if (exportPayload) {
      // Export-Grundlage je Tick gegen die gekappte Freeze-Knotenmenge
      // neu schneiden — kein Deny-Ende darf als Phantom im Download stehen.
      exportPayload = buildExportPayload(frozen.cluster, frozen.nodes, frozen.edges);
    }
    showFrozenNote();
  }

  /* Modal-Elementbündel (render() und der Pre-Export-Re-Paint von
   * downloadClusterPng): dieselben neun Selektoren — eine Quelle, damit der
   * Download-Pfad nicht vom Tick-Pfad abdriften kann. */
  function modalEls() {
    return {
      titleEl: overlay.querySelector('#cluster-modal-title'),
      badgeEl: overlay.querySelector('.cluster-modal-badge'),
      metricsEl: overlay.querySelector('.cluster-modal-metrics'),
      rolesEl: overlay.querySelector('.cluster-modal-roles'),
      timelineEl: overlay.querySelector('.cluster-modal-timeline'),
      chainEl: overlay.querySelector('.cluster-modal-chain'),
      tableEl: overlay.querySelector('.cluster-modal-table'),
      graphEl: overlay.querySelector('.cluster-3d'),
      noteEl: overlay.querySelector('.cluster-graph-note'),
    };
  }

  async function render() {
    const token = ++renderToken;
    const els = modalEls();

    // FREEZE-BRANCHE (Plan 2026-10-05): nach dem ersten erfolgreichen
    // Vollrender läuft jeder Tick ausschließlich über recheckFrozen — der
    // Live-Lookup (getClusterGraph) wird nicht mehr gelesen. Bewusste
    // Akzeptanzpunkt-Änderung: die STALE_SNAPSHOT_MAX_MS-Kappe und der
    // Missing-Cluster-Pfad leeren das OFFENE Modal nicht mehr; der Freeze
    // hält bis close()/openCluster()/Total-Leerung.
    if (frozen) { await recheckFrozen(els, token); return; }

    const cg = ctx.getClusterGraph();
    const clusters = cg && Array.isArray(cg.clusters) ? cg.clusters : [];
    const allNodes = cg && Array.isArray(cg.nodes) ? cg.nodes : [];
    const allEdges = cg && Array.isArray(cg.edges) ? cg.edges : [];

    // Exakter Lookup über die cluster.id; bei Verfehlen (ID-Träger aus dem
    // rollenden Fenster gerollt) Fallback über die Mitglieder-Schnittmenge
    // gegen den ORIGIN-ANKER (Befund 2026-09-30).
    let cluster = clusters.find((c) => c.id === currentClusterId);
    if (!cluster) cluster = findFallbackCluster(clusters);

    if (!cluster) {
      renderMissingCluster(els);
      return;
    }
    let takeoverPending = false;
    if (cluster.id !== currentClusterId) {
      // Nahtlose Übernahme: derselbe Cluster lebt unter neuer id weiter — der
      // exakte Lookup kann keine fremde id liefern, jede Abweichung stammt
      // aus dem verankerten Fallback. Hinweis folgt nach dem Vollrender.
      currentClusterId = cluster.id;
      takeoverPending = true;
    }

    // KNOTEN-GATE (Defense-in-Depth, Befund 2026-09-29): isDeniedAddr filtert
    // Köder-Adressen aus der Knotenmenge — sie erreichen weder Tabelle noch
    // Graph; Kanten fallen automatisch mit (beide Enden müssen im sichtbaren
    // Set liegen). Der Host (app.js) filtert bereits vor buildClusterGraph;
    // diese Schicht sichert zusätzlich Graphen ab, die diesen Weg nicht
    // gegangen sind. Fail-closed: ohne isDeniedAddr wird nicht gefiltert
    // (die Anzeige-Maske displayAddr greift dann weiterhin).
    // RAW-Menge VOR dem Gate (Stale-Overlay-Fix 2026-10-06): sie trennt
    // 'alle Fenster-Knoten Köder' (Deny-Kompletttreffer → Leerung) vom
    // 'Cluster ohne Fenster-Knoten' (persistierte Merged-Karte → Nachladen).
    const rawClusterNodes = allNodes.filter((n) => n.clusterId === cluster.id);
    const visibleNodes = (typeof isDeniedAddr === 'function')
      ? allNodes.filter((n) => !isDeniedAddr(String(n.id)))
      : allNodes;
    // let statt const: die asynchrone Deny-Nachprüfung vor dem Export- Gate
    // kann clusterNodes nachträglich um Deny-Treffer verkleinern.
    let clusterNodes = visibleNodes.filter((n) => n.clusterId === cluster.id);
    // KÖDER-DENY KOMPLETTTREFFER (Invariante, Plan-Korrektur 1): Fenster-
    // Knoten existierten, nach dem sync-Gate bleibt keiner übrig → Total-
    // Leerung. Köder-Deny gewinnt vor Freeze/Nachladen; die Anzeige-Maske
    // displayAddr bleibt zusätzlich aktiv.
    if (clusterNodes.length === 0 && rawClusterNodes.length > 0) {
      clearToEmptyState(els);
      return;
    }
    // NODE-LOS (Massenfall, Forensik 2026-10-06): die Karte lebt im
    // akkumulierten Bestand (mergeClusterViews/Session-Schicht), aber
    // cg.nodes trägt keinen Fenster-Zwilling — der alte Pfad malte eine
    // leere Hülle, fror einen LEEREN Freeze-Satz ein, und recheckFrozen
    // leerte ihn je Tick (modal.gone-Flapping alle ~4-5 s, live 12/30
    // Karten betroffen). Stattdessen: aus dem persistierten Bestand
    // nachladen; scheitert das, greift explizit die Missing-Semantik
    // (renderMissingCluster: Köder-Gate → !snapshot/Kappe → modal.gone-
    // Leerung, sonst LETZTER Stand + Alterungshinweis — Plan-Korrektur 2:
    // dieser Zweig liegt NACH dem Cluster-Fund und muss das Verhalten
    // selbst herbeiführen, renderMissingCluster läuft hier sonst nie).
    if (rawClusterNodes.length === 0) {
      const restored = await tryRestorePersistedCluster(els, cluster, token);
      if (token !== renderToken || !isOpen) return;
      if (!restored) renderMissingCluster(els);
      return;
    }
    const nodeIds = new Set(clusterNodes.map((n) => String(n.id)));
    // Fallback-ANKER einfrieren (Befund 2026-09-30): Mitglieder des originär
    // geöffneten Clusters bei der ERSTEN erfolgreichen Renderung nach
    // openCluster. Erst wenn der exakte Lookup diesen Stand bestätigt hat,
    // darf der Fallback später gegen ihn matchen — so ist der Anker stets der
    // vom Nutzer geöffnete Cluster, nicht ein Zwischen-Snapshot.
    if (!originMembers) originMembers = new Set(nodeIds);
    // let: die asynchrone Deny-Nachprüfung kann Kanten verwerfen, deren Ende
    // aus der sichtbaren Knotenmenge fallen.
    let clusterEdges = allEdges.filter((e) => nodeIds.has(String(e.from)) && nodeIds.has(String(e.to)));

    // Export-Grundlage (A3/A4) VOR dem Änderungs-Gate aufbauen (Kritik
    // 2026-10-04): identischer Inhalt überspringt das Vollrender, aber der
    // Payload muss auch dann aktuell und deny-geprüft bleiben. Asynchrone
    // Nachprüfung gegen die AKTUELLE Deny-Liste (rotiert serverseitig alle
    // 5 s): verweigerte Adressen werden ersatzlos entfernt; ungehashte
    // Adressen werden vorher gehasht (isDeniedAddrAsync füllt den
    // addrHashCache des Hosts). Ohne Host-Funktion greift der sync
    // isDeniedAddr (Defense-in-Depth wie oben).
    if (isDeniedAddrAsync) {
      try {
        // Nachprüfung mit Kosten-Deckel DENY_RECHECK_MAX (Modul-Level,
        // Begründung dort): Top-N nach Drops-Summe, dann Adresse asc —
        // deterministisch, unabhängig von Insertions-Reihenfolge und
        // Cache-Zustand. Synchrone isDeniedAddr-Knoten-Gate-Filterung und
        // Anzeige-Maske displayAddr greifen weiterhin für ALLE Adressen.
        const recheck = [...clusterNodes]
          .sort((a, b) =>
            ((Number(b?.inDrops) || 0) + (Number(b?.outDrops) || 0)) - ((Number(a?.inDrops) || 0) + (Number(a?.outDrops) || 0)) ||
            (String(a?.id) < String(b?.id) ? -1 : String(a?.id) > String(b?.id) ? 1 : 0))
          .slice(0, DENY_RECHECK_MAX);
        const denied = new Set();
        for (const n of recheck) {
          if (await isDeniedAddrAsync(String(n.id))) denied.add(String(n.id));
        }
        if (denied.size) {
          for (const a of denied) nodeIds.delete(a);
          clusterNodes = clusterNodes.filter((n) => !denied.has(String(n.id)));
          // Kanten gegen die GEFILTERTE Knotenmenge neu schneiden: ein Ende
          // darf nie als Phantom-Knoten in Graph oder Export landen.
          clusterEdges = clusterEdges.filter((e) => nodeIds.has(String(e.from)) && nodeIds.has(String(e.to)));
        }
      } catch { /* Nachprüfung fehlgeschlagen: Payload bleibt auf sync gefilterter Basis */ }
      if (token !== renderToken || !isOpen) return; // zwischenzeitlich neu gerendert/geschlossen
      if (!clusterNodes.length) {
        // ASYNC Komplett-Deny (Invariante wie beim sync-Gate): Köder-Deny
        // gewinnt — Total-Leerung statt leerem Freeze/Vollrender. Kein
        // Wiederversuch im selben Tick; der nächste Tick durchläuft erneut
        // alle Gates (Deny-Rotation darf den Cluster später freigeben).
        clearToEmptyState(els);
        return;
      }
    }
    exportPayload = buildExportPayload(cluster, clusterNodes, clusterEdges);
    const dlBtnEl = overlay.querySelector('#cluster-json-download');
    if (dlBtnEl) dlBtnEl.hidden = false;
    const dlNoteEl = overlay.querySelector('.cluster-export-note');
    if (dlNoteEl) dlNoteEl.hidden = false;

    // Änderungs-Gate: identischer Inhalt wie beim letzten Vollrender → nur
    // einen eventuellen Alterungszustand lösen und zurück (kein Re-Render,
    // kein graphData-Austausch, kein zoomToFit). Sprach-Anteil (Fix
    // 2026-10-05): clusterDigest ist sprachblind — ohne den
    // frozenLang-Vergleich würde ein Sprachwechsel bei identischen Daten
    // übersprungen und das Modal bliebe in der alten Sprache stehen.
    const digest = clusterDigest(cluster, clusterNodes, clusterEdges);
    if (digest === lastRenderDigest && getLang() === frozenLang) {
      endStaleState();
      return;
    }
    lastRenderDigest = digest;

    await paintCluster(els, cluster, clusterNodes, clusterEdges, token, takeoverPending);
  }

  /* Vollrender des Inhalts (aus render() extrahiert, Plan 2026-10-05):
   * Title/Badge/Metriken/Rollen/Zeitachse/Kette/Tabelle/Graph aus dem
   * (freeze-geprüften) Knoten- und Kantensatz. Läuft im Live-Pfad beim
   * ersten Vollrender und im Freeze-Pfad beim Sprachwechsel — die Daten
   * stammen dann aus dem Freeze-Satz, nicht aus dem Live-Graphen. Der
   * Nachlade-Pfad (tryRestorePersistedCluster) ruft mit fromPersisted=true
   * auf: Der Freeze-Satz trägt dann fromPersisted/persistedAt, und der
   * Hinweis zeigt modal.persisted statt modal.frozen (showFrozenNote). */
  async function paintCluster(els, cluster, clusterNodes, clusterEdges, token, takeoverPending, fromPersisted = false, persistedAt = null) {
    const { titleEl, badgeEl, metricsEl, rolesEl, timelineEl, chainEl, tableEl, graphEl, noteEl } = els;
    titleEl.textContent = cluster.label ?? t('cluster.labelDefault');
    const sev = clusterSeverity(cluster, clusterNodes);
    badgeEl.innerHTML = sev === 'malicious' || sev === 'suspect'
      ? `<span class="risk-badge risk-${esc(sev)}">${esc(sevText(sev))}</span>`
      : '';
    metricsEl.innerHTML = `
      <span class="cluster-xrp">${esc(fmtXrp(cluster.totalDrops))} XRP</span>
      <span class="cluster-txs">${num(cluster.txCount)} ${esc(t('cluster.txUnit'))}</span>
      <span class="cluster-accounts">${num(cluster.distinctAccounts)} ${esc(t('cluster.accountUnit'))}</span>
      <span class="cluster-times">
        <span>${esc(t('cluster.firstSeen'))}${esc(fmtClock(cluster.firstSeen))}</span>
        <span>${esc(t('cluster.lastSeen'))}${esc(fmtClock(cluster.lastSeen))}</span>
      </span>`;

    // Fraud-Menge des aktuellen Clusters (Kritiker-Pflichtkorrektur 4):
    // Knoten mit severity 'malicious' — Basis des Kanten-Overrides in
    // 3D/2D/Zeitachse (edgeIsFraud oben). Vor JEDEM Teilrender gesetzt,
    // damit Freezes/Persistierte dieselbe Regel erfahren.
    fraudAddrSet = new Set(
      (Array.isArray(clusterNodes) ? clusterNodes : [])
        .filter((n) => String(n?.severity ?? '') === 'malicious')
        .map((n) => String(n.id))
    );
    renderRoles(cluster, clusterNodes, rolesEl);
    renderEdgeLegend();
    renderTimeline(cluster, clusterEdges, timelineEl);
    renderChain(cluster, clusterNodes, clusterEdges, chainEl);
    renderTable(clusterNodes, tableEl, clusterEdges);
    const memberIds = new Set(clusterNodes.map((n) => String(n.id)));
    // Letztstand einfrieren — Grundlage für Alterungsanzeige (members+at);
    // das Fallback-Matching läuft seit Befund 2026-09-30 gegen den stabilen
    // ORIGIN-ANKER (originMembers), nicht gegen diesen Snapshot.
    snapshot = { clusterId: cluster.id, at: Date.now(), members: [...memberIds] };
    endStaleState();
    if (takeoverPending) showTakeoverNotice();
    await renderGraph(clusterNodes, clusterEdges, graphEl, noteEl, token, cluster.id);
    if (token !== renderToken || !isOpen) return; // renderGraph war async

    // FREEZE-SETZUNG (nur der ERSTE erfolgreiche Vollrender eines geöffneten
    // Clusters): tiefe Kopie — die Live-Objekte wandern/rotieren weiter,
    // der Freeze-Satz bleibt davon unberührt. cooldownTicks(0) friest die
    // Physik ein (graphData-Austausch als einziger Wiederaufheiz-Punkt
    // liegt im Live-Pfad, den der Freeze nie wieder erreicht).
    // HARTER INVARIANTEN-GUARD (Stale-Overlay-Fix 2026-10-06, Plan-
    // Korrektur 1): ein LEERER Knotensatz wird nie eingefroren — ein leerer
    // Freeze-Satz war die Wurzel des modal.gone-Flappings (recheckFrozen
    // leerte ihn je Tick). Alle 0-Knoten-Pfade werden upstream abgefangen
    // (Köder-Komplett-Deny → clearToEmptyState, node-los → Nachladen/
    // Missing-Semantik); dieser Guard hält die Invariante auch dann, wenn
    // ein neuer Pfad paintCluster mit leerer Menge erreicht.
    if (!frozen && clusterNodes.length > 0) {
      frozen = {
        clusterId: cluster.id,
        at: Date.now(),
        lang: getLang(),
        cluster: { ...cluster },
        nodes: clusterNodes.map((n) => ({ ...n })),
        edges: clusterEdges.map((e) => ({ ...e })),
        members: [...memberIds],
        // Nachgeladene Bestands-Freezes (Stale-Overlay-Fix): Hinweis-Kennung
        // für showFrozenNote (modal.persisted statt modal.frozen).
        fromPersisted: fromPersisted === true,
        persistedAt: fromPersisted === true ? (persistedAt ?? Date.now()) : null,
      };
    }
    frozenLang = getLang();
    if (fg3d) { try { fg3d.cooldownTicks(0); } catch { /* egal */ } }
    showFrozenNote();
  }

  /* ---------------- JSON-Export des Clusters (A3/A5) ----------------
   * Payload aus dem Vollrender: Cluster-Kopf, Metriken, Mitglieder (nur nicht
   * verweigerte Adressen), Rollen und Schweregrade je Adresse, Kanten (from/
   * to/txHash/closeTime/type) und — nur in der Server-View vorhanden — die
   * Peeling-Ketten (lib/flow-state.mjs; in lib/cluster.mjs existieren sie
   * nicht, grep 0 Treffer). Ein 'rules'-Feld (ruleId/noteKey) wird NICHT
   * exportiert: kein Cluster-Objekt beider Pfade führt es (per grep belegt) —
   * erfundene Felder wären ein Verstoß gegen die Ehrlichkeitsregel.
   * Der Download folgt exakt dem etablierten Blob-Muster aus downloadLog
   * (app.js): Blob -> createObjectURL -> temporäres <a download> -> revoke
   * nach 2 s. Kein api/-Endpunkt (api/ umfasst bereits 12 Funktionen —
   * Vercel-Hobby-Limit, null Spielraum). */
  function buildExportPayload(cluster, clusterNodes, clusterEdges) {
    const rolesByAddress = {};
    const severityByAddress = {};
    for (const n of clusterNodes) {
      const a = String(n.id);
      rolesByAddress[a] = roleLabels[n.role] ? n.role : 'unknown';
      severityByAddress[a] = String(n.severity ?? 'info');
    }
    const chains = (Array.isArray(cluster.peelingChains) ? cluster.peelingChains : [])
      .map((ch) => ({
        seed: String(ch?.seed ?? ''),
        addresses: (Array.isArray(ch?.addresses) ? ch.addresses : []).map(String),
        bridges: (Array.isArray(ch?.bridges) ? ch.bridges : []).map(String),
        hopsCount: Number(ch?.hopsCount ?? 0) || 0,
      }))
      .filter((ch) => ch.addresses.length >= 2);
    return {
      cluster: { id: cluster.id, label: cluster.label ?? null },
      totalDrops: Number(cluster.totalDrops ?? 0) || 0,
      txCount: Number(cluster.txCount ?? 0) || 0,
      distinctAccounts: Number(cluster.distinctAccounts ?? 0) || 0,
      firstSeen: cluster.firstSeen ?? null,
      lastSeen: cluster.lastSeen ?? null,
      members: clusterNodes.map((n) => String(n.id)),
      rolesByAddress,
      severityByAddress,
      edges: clusterEdges.map((e) => ({
        from: String(e.from),
        to: String(e.to),
        txHash: e.txHash != null ? String(e.txHash) : null,
        closeTime: e.closeTime != null ? String(e.closeTime) : null,
        type: String(e.type ?? ''),
        // Tag-Felder (tagIdentityDesign, additiv): nur wenn belegt — kein
        // null-Feld für Kanten ohne Tag (Export bleibt schlank).
        ...(e.toTag != null ? { toTag: e.toTag } : {}),
        ...(e.transit === true ? { transit: true } : {}),
      })),
      peelingChains: chains,
      exportAt: new Date().toISOString(),
    };
  }

  async function downloadClusterJson() {
    if (!exportPayload) return; // Button ist ohne Payload ohnehin hidden
    const token = ++exportToken;
    let payload = exportPayload;
    // Nachprüfung gegen die AKTUELLE Deny-Liste (rotiert serverseitig alle
    // 5 s): verweigerte Adressen entfallen ersatzlos — Maskierung statt
    // Entfernen wäre ein Leak der Kurzform-Zuordnung.
    if (isDeniedAddrAsync) {
      try {
        const denied = new Set();
        const addrs = new Set(payload.members);
        for (const e of payload.edges) { addrs.add(e.from); addrs.add(e.to); }
        for (const ch of payload.peelingChains) { addrs.add(ch.seed); for (const a of ch.addresses) addrs.add(a); }
        for (const a of addrs) {
          if (await isDeniedAddrAsync(a)) denied.add(a);
        }
        if (denied.size) {
          payload = {
            ...payload,
            members: payload.members.filter((a) => !denied.has(a)),
            rolesByAddress: Object.fromEntries(Object.entries(payload.rolesByAddress).filter(([a]) => !denied.has(a))),
            severityByAddress: Object.fromEntries(Object.entries(payload.severityByAddress).filter(([a]) => !denied.has(a))),
            edges: payload.edges.filter((e) => !denied.has(e.from) && !denied.has(e.to)),
            peelingChains: payload.peelingChains
              .map((ch) => ({ ...ch, addresses: ch.addresses.filter((a) => !denied.has(a)) }))
              .filter((ch) => ch.addresses.length >= 2),
          };
        }
      } catch { /* Nachprüfung fehlgeschlagen: Payload bleibt auf render-gefilterter Basis */ }
      if (token !== exportToken) return; // Payload wurde unterdessen ersetzt
    }
    const blob = new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = `cluster-${String(payload.cluster.id ?? '').replace(/[^A-Za-z0-9_-]/g, '_')}-${new Date().toISOString().replace(/[:T]/g, '-').slice(0, 16)}.json`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(a.href), 2000);
  }

  /* PNG-Export des Cluster-Graphen (Fix 2026-10-07): Der 3D-Renderer läuft
   * jetzt mit rendererConfig.preserveDrawingBuffer (build3D) — ohne diese
   * Option wäre der WebGL-Canvas nach dem Frame-Clear schwarz (app.js
   * 1911-1913 schloss WebGL-Exporte deshalb aus). Fallback-Pfad: der
   * vis-Canvas des 2D-Fallbacks (build2D) ist ohne Weiteres exportierbar.
   * Der Blob-/Anchor-/Revoke-Pfad folgt exakt exportGraphPng (app.js) und
   * downloadClusterJson oben. Der 3D-Canvas ist transparent
   * (backgroundColor 'rgba(0,0,0,0)'), deshalb wird wie im Haupt-Pfad auf
   * die Bühnenfarbe (--a6-graph-canvas, Noir: dunkle Bühne) gezeichnet.
   * Review 2026-10-07: Pre-Export-Deny-Recheck gegen den Freeze-Satz —
   * Treffer kappen den Satz und malen ihn neu, bevor der Canvas erfasst
   * wird (Parität zum JSON-Pfad: 'Export-Grundlage je Download
   * deny-geprüft'). */
  function setPngBtnVisible(visible) {
    // PNG-Button-Sichtbarkeit gehört dem Graph-Aufbau (renderGraph), nicht
    // dem Payload-Gate: exportPayload wird VOR renderGraph gesetzt
    // (render() 1200 vs. paintCluster-Aufruf von renderGraph) — ein
    // Payload-Gate gäbe im noGraph-Endzustand einen sichtbaren toten
    // Button, genau das P1-Muster.
    if (!overlay) return;
    const btn = overlay.querySelector('#cluster-png-download');
    if (btn) btn.hidden = !visible;
  }

  function setPngBtnLabel(mode) {
    // Label-Semantik (Review 2026-10-07): Der Button exportiert den
    // stehenden Canvas — im 3D-Pfad den 3D-Graphen, im vis-Fallback die
    // 2D-Ausweichansicht. Das Label folgt der tatsächlichen
    // Export-Grundlage; data-i18n wird mitgeschrieben, damit applyStatic
    // bei hx:langchange (i18n.mjs) in der neuen Sprache die richtige
    // Variante setzt (Muster app.js 3123).
    if (!overlay) return;
    const btn = overlay.querySelector('#cluster-png-download');
    if (!btn) return;
    const key = mode === '2d' ? 'modal.downloadPng2d' : 'modal.downloadPng3d';
    btn.setAttribute('data-i18n', key);
    btn.textContent = t(key);
  }

  async function downloadClusterPng() {
    if (!overlay) return;
    // Pre-Export-Deny-Recheck (Review 2026-10-07, Parität zum JSON-Pfad):
    // Der Canvas wird nur je Freeze-Tick neu gemalt (recheckFrozen →
    // paintCluster, getrieben vom 60-s-Refresh), die serverseitige
    // Deny-Liste rotiert alle 5 s — ein nach dem letzten Paint neu
    // verweigertes Mitglied kann noch auf dem Canvas stehen (2D-Fallback:
    // graphLabel trägt die Adresse). Bei Treffer: Freeze-Satz kappen und
    // daraus neu malen, bevor erfasst wird — das PNG basiert dann auf dem
    // aktuellen Deny-Stand wie der JSON-Export.
    const token = renderToken;
    if (frozen && isDeniedAddrAsync) {
      try {
        const denied = new Set();
        for (const n of frozen.nodes) {
          const a = String(n.id);
          if (typeof isDeniedAddr === 'function' && isDeniedAddr(a)) { denied.add(a); continue; }
          if (await isDeniedAddrAsync(a)) denied.add(a);
        }
        if (denied.size) {
          removeFrozenMembers(denied);
          if (token !== renderToken || !isOpen) return; // zwischenzeitlich neu gerendert/geschlossen
          const els = modalEls();
          if (!frozen || !frozen.nodes.length) {
            // Kompletttreffer: Köder-Deny schlägt Freeze (Invariante wie in
            // recheckFrozen) — nichts Exportierbares übrig, ehrliche Leere.
            clearToEmptyState(els);
            return;
          }
          await paintCluster(els, frozen.cluster, frozen.nodes, frozen.edges, token, false);
          if (token !== renderToken || !isOpen) return; // zwischenzeitlich neu gerendert/geschlossen
          if (exportPayload) {
            // Export-Grundlage aus dem gekappten Satz neu schneiden (Muster
            // recheckFrozen) — kein nachträglich Verweigertes darf auch im
            // JSON-Payload stehen bleiben.
            exportPayload = buildExportPayload(frozen.cluster, frozen.nodes, frozen.edges);
          }
        }
      } catch { /* Nachprüfung fehlgeschlagen: Export auf render-gefilterter Basis (wie JSON-Pfad) */ }
    }
    // Canvas-Quelle: 3D-Instanz (preserveDrawingBuffer) oder vis-Canvas des
    // 2D-Fallbacks im selben .cluster-3d — guardiert wie exportGraphPng.
    let src = null;
    try {
      if (fg3d && typeof fg3d.renderer === 'function') src = fg3d.renderer().domElement;
    } catch { /* Renderer-API nicht verfügbar: DOM-Fallback unten */ }
    if (!src || typeof src.toBlob !== 'function') {
      try {
        const stage = overlay.querySelector('.cluster-3d');
        src = stage ? stage.querySelector('canvas') : null;
      } catch { src = null; }
    }
    if (!src || typeof src.toBlob !== 'function') return; // kein exportierbarer Canvas
    const w = src.width || 0;
    const h = src.height || 0;
    if (!w || !h) return;
    const target = document.createElement('canvas');
    target.width = w;
    target.height = h;
    const ctx2d = target.getContext('2d');
    if (!ctx2d) return;
    // Bühnenfarbe live aus dem Token (Muster exportGraphPng, app.js): ohne
    // Füllung wäre das PNG transparent.
    let stageColor = '#ffffff';
    try {
      stageColor = getComputedStyle(document.body).getPropertyValue('--a6-graph-canvas').trim() || '#ffffff';
    } catch { /* ohne CSS-Zugang: Hell-Fallback */ }
    ctx2d.fillStyle = stageColor;
    ctx2d.fillRect(0, 0, w, h);
    ctx2d.drawImage(src, 0, 0);
    // Dateiname: cluster-ID VOR dem async Callback einfangen — close() nullt
    // currentClusterId (Review 2026-10-07); der JSON-Pfad hält analog das
    // vorher eingefangene payload.cluster.id.
    const cid = String(currentClusterId ?? '').replace(/[^A-Za-z0-9_-]/g, '_');
    target.toBlob((blob) => {
      if (!blob) return;
      const a = document.createElement('a');
      a.href = URL.createObjectURL(blob);
      a.download = `cluster-${cid}-${new Date().toISOString().replace(/[:T]/g, '-').slice(0, 16)}.png`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      setTimeout(() => URL.revokeObjectURL(a.href), 2000);
    }, 'image/png');
  }

  function clusterSeverity(cluster, clusterNodes) {
    const rank = { info: 0, suspect: 1, malicious: 2 };
    let sev = 'info';
    for (const n of clusterNodes) {
      const s = String(n.severity ?? 'info');
      if ((rank[s] ?? 0) > (rank[sev] ?? 0)) sev = s;
    }
    return sev;
  }

  /* ---------------- Rollen-Verteilung (Balken) ---------------- */

  function renderRoles(cluster, clusterNodes, el) {
    const counts = new Map();
    for (const n of clusterNodes) {
      const r = roleLabels[n.role] ? n.role : 'unknown';
      counts.set(r, (counts.get(r) ?? 0) + 1);
    }
    const total = clusterNodes.length || 1;
    const rows = ['source', 'drainer', 'collector', 'relay', 'unknown']
      .filter((r) => counts.get(r))
      .map((r) => {
        const count = counts.get(r);
        const pct = Math.round((count / total) * 100);
        return `
          <div class="role-bar-row">
            <span class="role-bar-label"><span class="swatch swatch-${esc(r)}"></span>${esc(roleLabelText(r))}</span>
            <span class="role-bar-track" role="img" aria-label="${esc(t('modal.roleBarAria', { role: roleLabelText(r), count, total: clusterNodes.length, pct }))}">
              <span class="role-bar-fill role-bar-${esc(r)}" style="width:${pct}%"></span>
            </span>
            <span class="role-bar-count">${num(count)}</span>
          </div>`;
      }).join('');
    el.innerHTML = `<h3 class="cluster-modal-h">${esc(t('modal.rolesTitle'))}</h3>
      <div class="role-bars">${rows}</div>
      <p class="graph-note">${esc(t('graph.disclaimer'))}</p>`;
  }

  /* ---------------- Zeitachse (SVG, epoch-basiert) ---------------- */

  function renderTimeline(cluster, clusterEdges, el) {
    const points = [];
    for (const e of clusterEdges) {
      const ep = Date.parse(String(e.closeTime ?? ''));
      if (Number.isFinite(ep)) points.push({ ep, type: String(e.type ?? ''), fraud: edgeIsFraud(e) });
    }
    if (!points.length) {
      el.innerHTML = `<h3 class="cluster-modal-h">${esc(t('modal.timelineTitle'))}</h3>`
        + `<p class="graph-note">${esc(t('modal.timelineEmpty'))}</p>`;
      return;
    }
    let min = points[0].ep;
    let max = points[0].ep;
    for (const p of points) {
      if (p.ep < min) min = p.ep;
      if (p.ep > max) max = p.ep;
    }
    const span = max - min || 1;
    // Kreisrunde Zeitachse OHNE viewBox/preserveAspectRatio='none' (Befund
    // 2026-09-29): Nicht-uniforme Streckung des viewBox 0 0 300 46 auf ~500 px
    // Spaltenbreite renderte die r=3-Kreise als Ellipsen (~10x6 px). Stattdessen
    // feste Benutzer-Einheiten (CSS-px) mit Prozent-Koordinaten für die
    // Position: Kreise bleiben Kreise, die Achse füllt trotzdem die volle
    // Breite der Seitenspalte.
    const H = 46;
    const CY = H / 2;
    const PAD_PCT = 4;
    const xOf = (ep) => (PAD_PCT + ((ep - min) / span) * (100 - 2 * PAD_PCT)).toFixed(2);
    // Kantenfarbe je KATEGORIE + Fraud-Override (Kritiker-Pflichtkorrektur 4/6):
    // Betrugs-Punkte als Konturkreis (ungefüllt) — der nicht-farbliche
    // Zweitkanal, weil ein Punkt keine Dash-Form tragen kann.
    const dotColor = (p) => (edgeIsFraud(p) ? edgeColors.fraud : edgeColors[edgeCategoryOf(p.type)]) || edgeDefaultOf();
    const dots = points.map((p) =>
      p.fraud
        ? `<circle cx="${xOf(p.ep)}%" cy="${CY}" r="3" fill="none" stroke="${esc(dotColor(p))}" stroke-width="2" opacity="0.9"></circle>`
        : `<circle cx="${xOf(p.ep)}%" cy="${CY}" r="3" fill="${esc(dotColor(p))}" opacity="0.85"></circle>`
    ).join('');
    const minIso = new Date(min).toISOString();
    const maxIso = new Date(max).toISOString();
    el.innerHTML = `<h3 class="cluster-modal-h">${esc(t('modal.timelineTitle'))}</h3>
      <svg class="cluster-timeline" role="img"
           aria-label="${esc(t('modal.timelineAriaRange', { from: fmtClock(minIso), to: fmtClock(maxIso), n: points.length }))}">
        <line class="timeline-axis" x1="${PAD_PCT}%" y1="${CY}" x2="${100 - PAD_PCT}%" y2="${CY}"></line>
        ${dots}
      </svg>
      <div class="cluster-timeline-labels">
        <span>${esc(t('cluster.firstSeen'))}${esc(fmtClock(cluster.firstSeen ?? minIso))}</span>
        <span>${esc(t('cluster.lastSeen'))}${esc(fmtClock(cluster.lastSeen ?? maxIso))}</span>
      </div>`;
  }

  /* ---------------- Flusskette: echte Kantenpfade Start → … → Kollektor ---------------- */

  function renderChain(cluster, clusterNodes, clusterEdges, el) {
    // Edge-Tag-Lookup (from→to → toTag) aus den Cluster-Kanten: Tags sind
    // Edge-Attribute, der Chip hängt am Ziel-Knoten der Kette.
    const tagByPair = new Map();
    for (const e of clusterEdges) {
      if (e && e.toTag != null) tagByPair.set(`${String(e.from)}\u0001${String(e.to)}`, e.toTag);
    }
    const chip = (x, prevId) => {
      const address = String(x?.id ?? '');
      const shown = displayAddr(address);
      const actions = isFullShownAddr(address) ? addrActionsHtml(address) : '';
      // Name nur hinter dem Host-Gate (accountNameOf) und nur ergänzend —
      // der Anzeigewert bleibt die Adresse.
      const nameChip = nameChipHtml(address);
      // Tag-Chip nur bei Multi-User-Treffer des Ziels (Registry ODER
      // verifizierter well-known-Name, multiUserEntryOf-Host-Gate) und
      // belegter Kante mit toTag — nie an der Kurzform.
      const tag = prevId != null ? tagByPair.get(`${String(prevId)}\u0001${address}`) : null;
      const tagChip = tagChipHtml(address, tag);
      return `<span class="chain-node chain-${esc(x?.role ?? 'unknown')}">${esc(shown)}${actions}${nameChip}${tagChip}</span>`;
    };
    // Pfade NUR aus echten Kanten des Clusters (flowPaths, lib/cluster.mjs):
    // '→' verbindet ausschließlich Adressen entlang belegter Transaktionen —
    // rollenweise aneinandergereihte Chips implizierten Flüsse, die es im
    // Beobachtungsfenster nicht gibt (Befund 2026-09-29).
    const traceFn = typeof flowPaths === 'function' ? flowPaths() : null;
    const paths = traceFn
      ? traceFn(
          clusterNodes.map((n) => ({ id: String(n.id), role: n.role })),
          clusterEdges.map((e) => ({ from: String(e.from), to: String(e.to) })),
          { maxPaths: 3, maxPathLen: 6 },
        ).filter((p) => Array.isArray(p) && p.length >= 2)
      : [];
    if (paths.length) {
      const rows = paths
        .map((p) => p.map((x, i) => chip(x, i > 0 ? p[i - 1]?.id : null)).join('<span class="chain-arrow" aria-hidden="true">→</span>'))
        .join('<span class="chain-path-sep" aria-hidden="true">·</span>');
      // Transit-Hinweis (tagIdentityDesign): nur bei belegter transit-Kante.
      const transitNote = clusterEdges.some((e) => e && e.transit === true)
        ? `<p class="graph-note cluster-transit-note">${esc(t('cluster.transitNote'))}</p>`
        : '';
      el.innerHTML = `<h3 class="cluster-modal-h">${esc(t('modal.chainTitle'))}</h3>
        <div class="cluster-chain" aria-label="${esc(t('cluster.chainAria'))}">${rows}</div>
        <p class="graph-note">${esc(t('modal.chainNote'))}</p>${transitNote}`;
      return;
    }
    // Fallback (keine Kante im Fenster bzw. flowPaths offline): Rollen-Chips
    // OHNE '→' — die Trennung ist ein '·', damit keine Transaktion impliziert
    // wird, die nicht belegt ist.
    const entries = [];
    for (const role of ['source', 'drainer', 'relay', 'collector']) {
      const list = clusterNodes.filter((n) => n.role === role);
      if (role === 'drainer') list.sort((a, b) => (b.outDrops ?? 0) - (a.outDrops ?? 0) || String(a.id).localeCompare(String(b.id)));
      if (role === 'collector') list.sort((a, b) => (b.inDrops ?? 0) - (a.inDrops ?? 0) || String(a.id).localeCompare(String(b.id)));
      for (const n of list) entries.push({ address: String(n.id), role });
    }
    if (!entries.length) {
      el.innerHTML = `<h3 class="cluster-modal-h">${esc(t('modal.chainTitle'))}</h3>`
        + `<p class="graph-note">${esc(t('modal.chainEmpty'))}</p>`;
      return;
    }
    const chips = entries.map((x) => chip({ id: x.address, role: x.role })).join('<span class="chain-path-sep" aria-hidden="true">·</span>');
    el.innerHTML = `<h3 class="cluster-modal-h">${esc(t('modal.chainTitle'))}</h3>
      <div class="cluster-chain" aria-label="${esc(t('modal.chainRoleAria'))}">${chips}</div>`;
  }

  /* ---------------- Konten-Tabelle ---------------- */

  function renderTable(clusterNodes, el, clusterEdges) {
    lastTableNodes = clusterNodes;
    lastTableEl = el;
    if (Array.isArray(clusterEdges)) lastTableEdges = clusterEdges;
    // Tag-Sammlung je Adresse (distinct toTags der eingehenden Cluster-Kanten):
    // Tags sind Edge-Attribute — die Tabellenzeile zeigt die im Cluster
    // belegten Tags des Kontos (aufsteigend, Deckel 3 + '+' bei mehr).
    const tagsByAddr = new Map();
    for (const e of lastTableEdges ?? []) {
      if (!e || e.toTag == null) continue;
      const key = String(e.to);
      if (!tagsByAddr.has(key)) tagsByAddr.set(key, new Set());
      tagsByAddr.get(key).add(e.toTag);
    }
    const sorted = [...clusterNodes]
      .sort((a, b) =>
        ((b.inDrops ?? 0) + (b.outDrops ?? 0)) - ((a.inDrops ?? 0) + (a.outDrops ?? 0))
        || String(a.id).localeCompare(String(b.id)));
    const visibleRows = sorted.slice(0, tableRowLimit);
    const remaining = sorted.length - visibleRows.length;
    const rows = visibleRows
      .map((n) => {
        const id = String(n.id);
        const full = isFullShownAddr(id);
        const shown = displayAddr(id);
        const sev = String(n.severity ?? 'info');
        const badge = sev === 'malicious' || sev === 'suspect'
          ? `<span class="risk-badge risk-${esc(sev)}">${esc(sevText(sev))}</span>`
          : '<span class="cluster-table-dash">–</span>';
        const actions = full ? addrActionsHtml(id) : '<span class="cluster-table-dash">–</span>';
        const role = roleLabels[n.role] ? n.role : 'unknown';
        // data-addr trägt NUR den Anzeigewert (volle Adresse ausschließlich
        // bei erlaubter Vollanzeige, sonst Kurzform) — die ROHE Knoten-Id
        // darf nie als DOM-Attribut landen (Befund 2026-09-29). Hover-
        // Highlight und Klick-Scroll vergleichen deshalb gegen
        // displayAddr(n.id), nicht gegen die rohe Id.
        // Name-Chip (Exchange-Spalte) nur hinter dem Host-Gate
        // (accountNameOf) und nur bei Vollanzeige. Tag-Chips (Tag-Spalte)
        // ebenso (multiUserEntryOf-Gate): distinct toTags der eingehenden
        // Cluster-Kanten, aufsteigend, Cap 3. Die Adress-Zelle trägt nur
        // noch Adresse + Aktionen (Layout-Fix 2026-10-05: Chips klebten
        // vorher übereinander an der Adresse).
        const nameChip = full ? nameChipHtml(id) : '';
        const tagSet = full ? tagsByAddr.get(id) : null;
        let tagChips = '';
        if (tagSet && tagSet.size) {
          const tags = [...tagSet].sort((a, b) => a - b);
          tagChips = tags.slice(0, 3).map((tg) => tagChipHtml(id, tg)).join('');
          if (tags.length > 3) tagChips += '<span class="cluster-table-dash">+</span>';
        }
        // Drops/Grade (Stale-Overlay-Fix 2026-10-06): Knoten aus dem
        // nachgeladenen persistierten Bestand tragen diese Metadaten nicht —
        // ehrlich '–' statt 0 erfinden (cluster-table-dash wie bei Severity/
        // Aktionen ohne Wert).
        const inCell = n.inDrops == null ? '<span class="cluster-table-dash">–</span>' : esc(fmtXrp(n.inDrops));
        const outCell = n.outDrops == null ? '<span class="cluster-table-dash">–</span>' : esc(fmtXrp(n.outDrops));
        const degreeCell = (n.degreeIn == null && n.degreeOut == null)
          ? '<span class="cluster-table-dash">–</span>'
          : `${n.degreeIn == null ? '–' : num(n.degreeIn)} / ${n.degreeOut == null ? '–' : num(n.degreeOut)}`;
        return `<tr data-addr="${esc(full ? id : shown)}">
          <td class="cluster-td-addr" title="${esc(shown)}">${esc(shown)}</td>
          <td class="cluster-td-exchange">${nameChip}</td>
          <td class="cluster-td-tag">${tagChips}</td>
          <td><span class="role-chip role-${esc(role)}"><span class="swatch swatch-${esc(role)}"></span>${esc(roleLabelText(role))}</span></td>
          <td>${badge}</td>
          <td class="cluster-td-num">${inCell}</td>
          <td class="cluster-td-num">${outCell}</td>
          <td class="cluster-td-num">${degreeCell}</td>
          <td>${actions}</td>
        </tr>`;
      }).join('');
    // Deckel-Button: ehrlicher Hinweis auf die noch nicht gerenderten Zeilen
    // (Caption nennt weiterhin die Gesamtzahl). Label nutzt den bestehenden
    // i18n-Key 'feed.loadMore' (EN 'Load more' / DE 'Mehr laden').
    const moreBtn = remaining > 0
      ? `<div class="feed-more-row"><button type="button" class="download-btn cluster-table-more" data-i18n="feed.loadMore" aria-label="${esc(t('feed.loadMoreAria'))}">${esc(t('feed.loadMore'))} (${num(remaining)})</button></div>`
      : '';
    el.innerHTML = `<h3 class="cluster-modal-h">${esc(t('modal.tableTitle'))}</h3>
      <div class="cluster-table-wrap" tabindex="0" role="region" aria-label="${esc(t('modal.tableWrapAria'))}">
        <table class="cluster-table">
          <caption>${esc(t('modal.tableCaption', { n: num(clusterNodes.length) }))}</caption>
          <thead>
            <tr>
              <th scope="col">${esc(t('modal.thAddr'))}</th>
              <th scope="col">${esc(t('modal.thExchange'))}</th>
              <th scope="col">${esc(t('modal.thTag'))}</th>
              <th scope="col">${esc(t('modal.thRole'))}</th>
              <th scope="col">${esc(t('modal.thSeverity'))}</th>
              <th scope="col">${esc(t('modal.thIn'))}</th>
              <th scope="col">${esc(t('modal.thOut'))}</th>
              <th scope="col">${esc(t('modal.thEdges'))}</th>
              <th scope="col">${esc(t('modal.thActions'))}</th>
            </tr>
          </thead>
          <tbody>${rows}</tbody>
        </table>
      </div>${moreBtn}`;
  }

  /* ---------------- Graph: 3D mit 2D-Ausweichansicht ---------------- */

  async function renderGraph(clusterNodes, clusterEdges, graphEl, noteEl, token, clusterId) {
    noteEl.hidden = true;
    if (typeof window.ForceGraph3D !== 'function') {
      graphEl.innerHTML = `<p class="graph-note">${esc(t('modal.loading3d'))}</p>`;
    }
    const ok3d = await loadForceGraph3D();
    if (token !== renderToken || !isOpen) return; // zwischenzeitlich neu gerendert/geschlossen

    if (ok3d && webglAvailable()) {
      try {
        build3D(clusterNodes, clusterEdges, graphEl, clusterId);
        // PNG-Button nur bei stehendem exportierbarem Canvas (Fix 2026-10-07):
        // 3D-Renderer läuft mit preserveDrawingBuffer (build3D).
        setPngBtnVisible(true);
        setPngBtnLabel('3d'); // Label = tatsächliche Export-Grundlage
        return;
      } catch {
        // Konstruktor-Fehler -> Fallback unten
      }
    }
    teardown3D();
    if (typeof window.vis !== 'undefined') {
      try {
        build2D(clusterNodes, clusterEdges, graphEl);
        noteEl.textContent = t('modal.fallback2d');
        noteEl.hidden = false;
        setPngBtnVisible(true); // vis-Canvas ist ohne Guard exportierbar
        setPngBtnLabel('2d'); // exportiert wird der 2D-Canvas — das Label darf keinen 3D-Graphen versprechen
        return;
      } catch {
        // vis-Fehler -> statischer Zustand unten
      }
    }
    teardown2D();
    setPngBtnVisible(false); // noGraph-Endzustand: kein Canvas -> kein PNG-Export
    graphEl.innerHTML = `<p class="graph-note">${esc(t('modal.noGraph'))}</p>`;
  }

  function nodeColorAccessor() {
    return (n) => {
      const role = roleColors[n.role] ? n.role : 'unknown';
      const base = roleColors[role];
      // Vergleich über den Anzeigewert: tr[data-addr] trägt nicht mehr die
      // rohe Knoten-Id (Befund 2026-09-29), sondern displayAddr(id).
      if (highlightSet.has(displayAddr(String(n.id)))) return base.highlight.background;
      return base.background;
    };
  }

  /* ---------------- 3D-Stil (Design P3, 2026-10-06) ----------------
   * Tiefenstaffelung/Kanten-Fokus ohne Speed-Verlust: kein Postprocessing
   * (kein EffectComposer/Bloom), keine per-Frame-Materialwechsel — Farb- und
   * Breitenwechsel laufen ausschließlich ereignisgesteuert über EINEN
   * Accessor-Set je Hover-Wechsel; das Punkt-Substrat unter der Bühne ist
   * reines CSS (drilldown.css). */

  // Kante berührt den Knoten? source/target sind nach dem Digest Knoten-
  // Objekte (wie im linkLabel-Callback oben behandelt).
  function linkTouches3d(l, nodeId) {
    if (!l) return false;
    const s = l.source && typeof l.source === 'object' ? String(l.source.id ?? '') : String(l.source ?? '');
    const t = l.target && typeof l.target === 'object' ? String(l.target.id ?? '') : String(l.target ?? '');
    return s === nodeId || t === nodeId;
  }

  // Kantenfarbe: Tx-KATEGORIE (edge-colors.mjs) mit Fraud-Override VOR der
  // Kategorie (Kritiker-Pflichtkorrektur 4 — severity auf der Kante oder
  // malicious-Endpunkt im Cluster); im Hover-Fokus treten nicht beteiligte
  // Kanten auf den Kontrolllinien-Ton zurück (pro Kante steuerbar — das
  // Bundle kennt KEINE pro-Kanten-Deckkraft, linkOpacity ist global; eine
  // globale Abblendung auf 0.35 würde die fokussierten Kanten mit treffen).
  function linkColor3dAccessor() {
    return (l) => {
      const base = (edgeIsFraud(l) ? edgeColors.fraud : edgeColors[edgeCategoryOf(l.type)]) || edgeDefaultOf();
      if (!hover3dNodeId) return base;
      return linkTouches3d(l, hover3dNodeId) ? base : graph3dLinkFaded();
    };
  }

  // Kantenbreite: Typ-Staffelung (Payment 1.4 / Escrow-Check-NFT 1 / Rest
  // 0.8); im Hover-Fokus beteiligte Kanten ×1.5.
  function linkWidth3dAccessor() {
    return (l) => {
      const base = cluster3dLinkWidth(l.type);
      if (!hover3dNodeId) return base;
      return linkTouches3d(l, hover3dNodeId) ? base * 1.5 : base;
    };
  }

  // Hover-Fokus (Design P3.4): Cursor + Knoten-Highlight über das bestehende
  // highlightSet-Muster (Anzeige-Maske displayAddr wie beim Tabellen-Hover)
  // + EIN Farb-/Breiten-Setter je Wechsel. Degradation prefers-reduced-
  // motion: Der Zeiger-Cursor bleibt, der Farb-/Breiten-Fokus (großflächige
  // Helligkeitswechsel beim schnellen Überfahren) entfällt — Tabellen-Sync
  // bleibt ohnehin an den Klick gebunden.
  function reset3dHover() {
    if (hover3dShown) highlightSet.delete(hover3dShown);
    hover3dNodeId = null;
    hover3dShown = null;
    if (fg3dStageEl) fg3dStageEl.classList.remove('is-hover-node');
  }

  function on3dNodeHover(node) {
    if (!fg3d) return;
    if (fg3dStageEl) fg3dStageEl.classList.toggle('is-hover-node', Boolean(node));
    if (reducedMotion()) return;
    if (hover3dShown) highlightSet.delete(hover3dShown);
    hover3dNodeId = node ? String(node.id ?? '') : null;
    hover3dShown = node ? displayAddr(hover3dNodeId) : null;
    if (hover3dShown) highlightSet.add(hover3dShown);
    try {
      fg3d.nodeColor(nodeColorAccessor());
      fg3d.linkColor(linkColor3dAccessor());
      fg3d.linkWidth(linkWidth3dAccessor());
    } catch { /* Accessor-Set nicht verfügbar -> nur Cursor-Fokus */ }
  }

  /* Drainer-Ring (Design P3.2, Plan-Kritik 7b/8): ADDITIV über
   * nodeThreeObjectExtend(true) — das Bundle behält seine Default-Sphere
   * inkl. nodeVal/nodeRelSize-Skalierung und hängt das zurückgegebene Objekt
   * als Kind an (Bundle-Nachweis: onCreateObj -> n = new vf.Mesh … n.add(s)).
   * Der Ring selbst ist ein äquatorialer Band-Ausschnitt einer Einheits-
   * kugel (dünn, 24 radiale Segmente), per einheitlicher Skalierung auf das
   * 1.45-Fache des Knotenradius gesetzt — von jeder Kameraseite sichtbar,
   * opak (opacity 0.9) und bewusst OHNE Emissive (lab_graphite: kein Glow).
   * Die three-Klassen werden aus bereits verdauten Knoten-Meshes der Instanz
   * rekonstruiert (fg3d.scene() -> traverse): das Bundle legt die Klassen
   * nicht global ab (window.THREE wird vom Bundle nur gelesen, nie
   * geschrieben — grep-Nachweis), aber Mesh/SphereGeometry/
   * MeshLambertMaterial sind über Instanz-Konstruktoren erreichbar und
   * identisch mit den bundle-eigenen Klassen. Browser-verifiziert am
   * gepinnten Bundle 2026-10-06 (Magenta-Transparenz-Probe). */
  function resolve3dRingClasses() {
    if (ring3dClassesFailed) return null;
    if (ring3dClasses) return ring3dClasses;
    try {
      const scene = typeof fg3d.scene === 'function' ? fg3d.scene() : null;
      if (!scene || typeof scene.traverse !== 'function') return null;
      let mesh = null;
      scene.traverse((o) => {
        if (mesh || !o || o.__graphObjType !== 'node' || !o.geometry) return;
        if (String(o.geometry.type).indexOf('Sphere') === 0) mesh = o;
      });
      if (!mesh) return null; // noch kein Default-Knoten-Mesh verdaut -> später erneut
      ring3dClasses = {
        Mesh: mesh.constructor,
        SphereGeometry: mesh.geometry.constructor,
        MeshLambertMaterial: mesh.material.constructor,
      };
      return ring3dClasses;
    } catch {
      ring3dClassesFailed = true; // kein Endlos-Retry gegen kaputte Szene
      return null;
    }
  }

  function drainerRing3d(n) {
    if (!ring3dIds.has(String(n?.id ?? ''))) return null;
    const cls = resolve3dRingClasses();
    if (!cls || !ring3dLayout) return null; // Retry-Rahmen in build3D setzt nach
    if (!ring3dUnitGeo) {
      // Einheits-Band (Radius 1, äquatorial 0.46π..0.54π): eine Geometrie für
      // alle Ringe, Knotenbezug nur über mesh.scale (uniform — Normalen
      // bleiben korrekt).
      ring3dUnitGeo = new cls.SphereGeometry(1, 24, 1, 0, Math.PI * 2, 0.46 * Math.PI, 0.08 * Math.PI);
    }
    if (!ring3dMat) {
      const drainer = roleColors.drainer;
      ring3dMat = new cls.MeshLambertMaterial({
        // Severity-/Rollen-Token --a6-role-drainer (#b3261e) via Host-ctx;
        // Fallback derselbe Wert (konsistente Farb-Sprache, kein zweites Rot).
        color: drainer && drainer.background ? drainer.background : '#b3261e',
        transparent: true,
        opacity: 0.9,
        side: 2, // 2 = three-Konstante DoubleSide (Band-Innenseite mitrendern)
      });
    }
    const mesh = new cls.Mesh(ring3dUnitGeo, ring3dMat);
    mesh.scale.setScalar(1.45 * ring3dLayout.radiusOf(n));
    return mesh;
  }

  // Ring-Legende (ehrlich: nur zeigen, was auch gerendert wurde): zählt
  // Knoten-Objekte mit Custom-Kind in der Szene.
  function count3dRings() {
    let count = 0;
    try {
      const scene = typeof fg3d.scene === 'function' ? fg3d.scene() : null;
      if (scene && typeof scene.traverse === 'function') {
        scene.traverse((o) => {
          if (o && o.__graphObjType === 'node' && o.children && o.children.length) count += 1;
        });
      }
    } catch { /* egal */ }
    return count;
  }

  function updateRingLegend(count) {
    const note = overlay && overlay.querySelector('.cluster-graph-note');
    if (!note) return;
    if (count > 0) {
      note.textContent = t('modal.graph3dLegend');
      note.hidden = false;
    } else {
      note.hidden = true;
    }
  }

  // Kanten-Kategorien-Legende im Graph-Overlay (Audit 2026-10-07): dieselben
  // .legend/.legend-item/.swatch-Klassen wie die Dashboard-Legende — Farben
  // ausschließlich aus den swatch-* Token-Regeln (style.css, themenbewusst),
  // Labels über legend.* (DE/EN; data-i18n hält hx:langchange aktuell, Muster
  // cluster-json-download oben). Reihenfolge: EDGE_CATEGORY_ORDER
  // (public/edge-colors.mjs).
  function renderEdgeLegend() {
    const el = overlay && typeof overlay.querySelector === 'function' ? overlay.querySelector('.cluster-graph-legend') : null;
    if (!el) return;
    // Stub-sicher (Node-Tests fahren minimale DOM-Stubs ohne setAttribute):
    // aria und Markup sind Best-Effort, hidden bleibt das ehrliche Signal.
    if (typeof el.setAttribute === 'function') el.setAttribute('aria-label', t('legend.aria'));
    try {
      el.innerHTML = EDGE_CATEGORY_ORDER
        .map((cat) => `<span class="legend-item"><span class="swatch swatch-${esc(cat)}"></span><span data-i18n="legend.${esc(cat)}">${esc(t(`legend.${cat}`))}</span></span>`)
        .join('');
      el.hidden = false;
    } catch { /* Node-Stub ohne Markup-Fähigkeit: Legende bleibt verborgen */ }
  }

  // Der erste Accessor-Durchlauf läuft, bevor irgendein Default-Knoten-Mesh
  // existiert (Klassen-Recovery braucht ein Vorbild in der Szene). Einmal je
  // Frame: Klassen lösen (Meshes der letzten Digest sind dann da), Accessor
  // erneut setzen (Mapper baut die Knoten-Objekte NEU — Positionen wohnen auf
  // den Datenobjekten und bleiben erhalten), danach Ringe zählen. Deckel 11
  // Frames; ohne requestAnimationFrame (Node-Test-Stub) kein Retry und keine
  // Legende — nie eine Legende ohne gerenderte Ringe.
  function schedule3dRingRetry(attempt) {
    if (!fg3d || !isOpen) return;
    if (attempt > 11) { updateRingLegend(0); return; }
    requestAnimationFrame(() => {
      if (!fg3d || !isOpen) return;
      if (count3dRings() > 0) { updateRingLegend(count3dRings()); return; }
      const cls = resolve3dRingClasses();
      if (!cls) {
        if (ring3dClassesFailed) { updateRingLegend(0); return; }
        schedule3dRingRetry(attempt + 1);
        return;
      }
      try { fg3d.nodeThreeObject((n) => drainerRing3d(n)); } catch { updateRingLegend(0); return; }
      requestAnimationFrame(() => {
        if (!fg3d || !isOpen) return;
        updateRingLegend(count3dRings());
      });
    });
  }

  function build3D(clusterNodes, clusterEdges, graphEl, clusterId) {
    teardown2D();
    // Deckel (Diagnose-Performance): Top-N Knoten nach Drops-Summe; die
    // übrigen Knoten bündelt EIN Aggregatknoten (Label '+N', Drops-Summe
    // der gebündelten Knoten). Der Aggregatknoten bekommt KEINE erfundenen
    // Kanten — Kanten laufen ausschließlich zwischen gehaltenen Knoten.
    let nodesIn = clusterNodes;
    let linksIn = clusterEdges;
    if (clusterNodes.length > GRAPH3D_MAX_NODES) {
      const sorted = [...clusterNodes].sort((a, b) =>
        ((b.inDrops ?? 0) + (b.outDrops ?? 0)) - ((a.inDrops ?? 0) + (a.outDrops ?? 0))
        || String(a.id).localeCompare(String(b.id)));
      const kept = sorted.slice(0, GRAPH3D_MAX_NODES);
      const hidden = sorted.slice(GRAPH3D_MAX_NODES);
      const keptIds = new Set(kept.map((n) => String(n.id)));
      let hidIn = 0;
      let hidOut = 0;
      for (const n of hidden) {
        hidIn += Math.max(0, Number(n.inDrops ?? 0));
        hidOut += Math.max(0, Number(n.outDrops ?? 0));
      }
      nodesIn = [...kept, { id: '__aggregate__', role: 'unknown', inDrops: hidIn, outDrops: hidOut, aggregateCount: hidden.length }];
      linksIn = clusterEdges.filter((e) => keptIds.has(String(e.from)) && keptIds.has(String(e.to)));
    }
    const data = {
      nodes: nodesIn.map((n) => ({
        id: String(n.id),
        role: roleColors[n.role] ? n.role : 'unknown',
        inDrops: n.inDrops ?? 0,
        outDrops: n.outDrops ?? 0,
        aggregateCount: n.aggregateCount ?? 0,
      })),
      links: linksIn.map((e) => ({
        source: String(e.from),
        target: String(e.to),
        type: String(e.type ?? ''),
        // severity durchreichen (Live-Kanten, lib/cluster.mjs:394): der
        // Fraud-Override im linkColor3dAccessor liest sie je Kante; die
        // Endpunkt-Prüfung läuft über fraudAddrSet (Knoten-Sverities).
        ...(e.severity != null ? { severity: e.severity } : {}),
        // Tag-Felder durchreichen (linkLabel liest sie; Gate im Label-Callback).
        ...(e.toTag != null ? { toTag: e.toTag } : {}),
      })),
    };
    // Gleicher Cluster wie im aktuellen Graphen? Dann NUR die Daten
    // aktualisieren — Kamera/Zoom bleiben erhalten. zoomToFit/Camera-Reset
    // (und mit ihm der sichtbare Layout-Neustart) feuern ausschließlich bei
    // Cluster-Wechsel oder Erstrender.
    const sameCluster = Boolean(fg3d) && graphClusterId === clusterId;
    // Entstapelung (2026-10-06): deterministisches Startlayout statt der
    // Bibliotheks-Phyllotaxis (Startabstand ~4–10 Einheiten bei Knotenradien
    // 40–180 aus realen Drops → der Freeze auf den Startpositionen stapelt
    // Tausende Paare übereinander). Positionen: Fibonacci-Kugel, skaliert
    // nach Knotenanzahl und größtem Radius. Bei Live-Updates desselben
    // Clusters werden die eingesessenen Koordinaten übernommen (kein
    // sichtbarer Layout-Neustart, kein Warmup-Jank).
    const layout = cluster3dLayoutParams(data.nodes);
    if (sameCluster) {
      try {
        const prevPos = new Map();
        for (const pn of fg3d.graphData().nodes) {
          if (Number.isFinite(pn.x) && Number.isFinite(pn.y) && Number.isFinite(pn.z)) {
            prevPos.set(String(pn.id), { x: pn.x, y: pn.y, z: pn.z });
          }
        }
        for (const n of data.nodes) {
          const p = prevPos.get(n.id);
          if (p) { n.x = p.x; n.y = p.y; n.z = p.z; }
        }
      } catch { /* fg3d.graphData() nicht lesbar -> alle neu geseedet */ }
    }
    seedCluster3dPositions(data.nodes.filter((n) => !Number.isFinite(n.x)), layout.seedRadius);
    // Drainer-Ring-Auswahl des Builds (deterministisch, Deckel 12) und Hover-
    // Reset: Der gehoverte Knoten des Vorgänger-Stands darf keinen Fokus
    // tragen, wenn der Datensatz ihn nicht mehr enthält.
    ring3dIds = selectDrainerRingNodes(data.nodes);
    ring3dLayout = layout;
    reset3dHover();
    if (!fg3d) {
      graphEl.innerHTML = '';
      // preserveDrawingBuffer (Fix 2026-10-07, PNG-Export): das Bundle
      // (3d-force-graph@1.80.0) reicht rendererConfig per
      // Object.assign({antialias:!0,alpha:!0}, rendererConfig) direkt an den
      // THREE.WebGLRenderer durch (Bundle-Nachweis: stateInit liest
      // e.rendererConfig; Default preserveDrawingBuffer:false). Ohne diese
      // Option wäre der Canvas nach dem Frame-Clear nicht mehr lesbar —
      // toBlob/toDataURL lieferten ein schwarzes Bild (app.js 1911-1913
      // schloss WebGL-Exporte deshalb aus). downloadClusterPng malt damit
      // über fg3d.renderer().domElement.
      fg3d = window.ForceGraph3D({ rendererConfig: { preserveDrawingBuffer: true } })(graphEl);
      // Containergröße statt Fenstergröße (Befund 2026-09-29): das Bundle
      // initialisiert width/height mit window.innerWidth/innerHeight — auf
      // der .cluster-3d-Bühne (520 px, overflow:hidden) wurde das Canvas
      // dadurch fensterbreit gerendert und abgeschnitten. Größe explizit auf
      // den Container setzen und per ResizeObserver nachführen (Fenster-
      // Resize, responsive Höhenstufen der Bühne).
      const sizeToContainer = () => {
        if (!fg3d) return;
        const w = Math.max(1, Math.floor(graphEl.clientWidth));
        const h = Math.max(1, Math.floor(graphEl.clientHeight));
        try { fg3d.width(w).height(h); } catch { /* egal */ }
      };
      sizeToContainer();
      if (typeof ResizeObserver === 'function') {
        fg3dResizeObs = new ResizeObserver(sizeToContainer);
        fg3dResizeObs.observe(graphEl);
      }
      fg3dStageEl = graphEl;
      fg3d
        // Transparenter Clear statt Vollweiß (Design P3.1): das Bundle parst
        // den Alpha-Anteil der Farbe und ruft renderer.setClearColor(Farbe,
        // Alpha); der Renderer läuft mit alpha:true (Bundle-Grep-Nachweis).
        // Browser-verifiziert am gepinnten Bundle 3d-force-graph@1.80.0
        // (2026-10-06, Magenta-Probe): das CSS-Punkt-Substrat der Bühne
        // (drilldown.css) scheint durch. Der 2D-Fallback (build2D) und der
        // PNG-Export (app.js, vis-2D-Canvas) sind davon unberührt.
        .backgroundColor('rgba(0,0,0,0)')
        // Aggregatknoten: zahlenmäßiges Label '+N' (sprachneutral, keine
        // Adresse — der Knoten steht für N nicht einzeln gezeigte Knoten).
        // Labels: Adresse bleibt primär, XRPScan-Name als ergänzte zweite
        // Zeile — nur hinter dem Host-Gate (accountNameOf, null bei Maske).
        .nodeLabel((n) => {
          if (n.aggregateCount) return esc(`+${n.aggregateCount}`);
          const name = accountNameOf(String(n.id ?? ''));
          return esc(displayAddr(n.id) + (name ? `\n${name.name}` : ''));
        })
        .linkLabel((l) => {
          const from = l.source && typeof l.source === 'object' ? l.source.id : l.source;
          const to = l.target && typeof l.target === 'object' ? l.target.id : l.target;
          const nameFrom = accountNameOf(String(from ?? ''));
          const nameTo = accountNameOf(String(to ?? ''));
          // Tag-Suffix nur bei Multi-User-Treffer des Ziels (Registry ODER
          // verifizierter well-known-Name, multiUserEntryOf-Host-Gate) und
          // belegtem toTag — an der Kurzform nie (fail-closed).
          const tagSuffix = l.toTag != null && multiUserEntryOf(String(to ?? '')) ? ` · #${l.toTag}` : '';
          return `${esc(displayAddr(from) + (nameFrom ? ` (${nameFrom.name})` : ''))} → ${esc(displayAddr(to) + (nameTo ? ` (${nameTo.name})` : ''))} (${esc(String(l.type ?? ''))})${tagSuffix ? esc(tagSuffix) : ''}`;
        })
        // Kanten-Grunddeckkraft (Bundle-Default 0.2 wäre neben den Knoten
        // nicht lesbar); die Breite staffelt der Accessor je Typ (unten).
        .linkOpacity(GRAPH3D_LINK_OPACITY)
        // Drainer-Ring ADDITIV (Plan-Kritik 8): das Bundle behält Default-
        // Sphere + nodeVal/nodeRelSize-Skalierung und hängt das Ring-Mesh
        // als Kind an — keine manuelle Sphären-Replikation.
        .nodeThreeObjectExtend(true)
        // Hover-Fokus (P3.4): nur Ereignis-Setter, keine per-Frame-Arbeit.
        .onNodeHover((node) => on3dNodeHover(node))
        .linkDirectionalArrowLength(3)
        .onNodeClick((node) => on3dNodeClick(node));
    }
    // Physik-Konfiguration VOR graphData (Entstapelung 2026-10-06): das
    // Bundle kennt keine Collide-Kraft (grep 0 Treffer) und lädt nur charge
    // -60 mit Link-Distanz 30 — beides unter den Knotenradien realer Drops.
    // Abstoßung skaliert mit cbrt(N)², ihre Reichweite ist auf 6·maxRadius
    // gedeckelt (ohne Deckel streckt die Global-Abstoßung Ketten-Cluster auf
    // ein Vielfaches der Knotengröße — Bubbles schrumpfen auf ~3 px, Probe/
    // Browser-Check 2026-10-06); die Link-Distanz ist radien-basiert; die
    // eigene Collide-Kraft hält die Radien-Summen ein. Der Warmup läuft im
    // Bundle synchron im graphData-Setter (for(B=0;B<warmupTicks;B++)
    // layout.tick() vor Engine-Start) — das cooldownTicks(0)-Freeze in
    // paintCluster friert damit ein bereits auseinandergezogenes Layout ein,
    // nie den Stapel. Warmup nur bei Cluster-Wechsel (Deckel 120 Ticks):
    // Live-Updates desselben Clusters übernehmen die eingesessenen
    // Positionen stattdessen.
    try {
      fg3d.d3Force('charge').strength(layout.chargeStrength).distanceMax(layout.chargeDistanceMax);
      fg3d.d3Force('link').distance(layout.linkDistance);
      fg3d.d3Force('collide', makeCluster3dCollideForce(layout.radiusOf));
      fg3d.warmupTicks(sameCluster ? 0 : layout.warmupTicks);
    } catch { /* Physik-Zugriff nicht verfügbar -> Graph bleibt mit Startlayout lesbar */ }
    // graphData bei JEDER inhaltlichen Änderung des angezeigten Clusters —
    // Mitglieder/Kanten/Metriken werden nie blockiert. Ein vorheriger
    // Alterungs-Pause (Cluster war kurzzeitig verschwunden) wird gelöst.
    // Reihenfolge: Accessor-Konfiguration VOR graphData, damit der Digest
    // der Knoten-/Kanten-Objekte die Stil-Accessoren bereits sieht (ein
    //digest statt zweier). Physik-Zugriffe stehen ohnehin schon davor.
    fg3d
      .nodeColor(nodeColorAccessor())
      .nodeRelSize(layout.nodeRelSize) // Radius skaliert mit Knotenanzahl (5..300 lesbar)
      // dieselbe Volumen-Skalierung wie cluster3dLayoutParams.valOf —
      // gemeinsamer Helper computeNodeVal (Floor 8, Log-Gain 2).
      .nodeVal((n) => computeNodeVal((n.inDrops ?? 0) + (n.outDrops ?? 0)))
      // Ring-Accessor (P3.2): null für alle Knoten außerhalb der Auswahl —
      // das Bundle erzeugt dann nur die Default-Sphere (kein Extra-Mesh).
      .nodeThreeObject((n) => drainerRing3d(n))
      .linkColor(linkColor3dAccessor())
      .linkWidth(linkWidth3dAccessor())
      .linkDirectionalParticles((l) => (String(l.type) === 'Payment' && !reducedMotion() ? 2 : 0))
      .linkDirectionalParticleWidth(2)
      .graphData(data);
    // Ring-Nachziehen + Legende nur im Browser (rAF vorhanden) und nur bei
    // Auswahl — siehe schedule3dRingRetry.
    if (ring3dIds.size && typeof requestAnimationFrame === 'function') {
      schedule3dRingRetry(0);
    }
    try { fg3d.resumeAnimation(); } catch { /* egal */ }
    if (reducedMotion()) {
      // Reduced Motion (Befund 2026-09-29): Kraft-Simulation einfrieren —
      // Pendant zum 2D-Fallback, der die Physik per cooldownTicks 0 stoppt.
      // Auch nach Inhalts-Updates (graphData tauet die Simulation wieder auf).
      try { fg3d.cooldownTicks(0); } catch { /* egal */ }
    }
    if (!sameCluster) {
      graphClusterId = clusterId;
      // Camera-Reset/zoomToFit nur bei Cluster-Wechsel oder Erstrender.
      const dur = reducedMotion() ? 0 : 400; // statische Bildfassung ohne Animation
      setTimeout(() => { try { if (fg3d) fg3d.zoomToFit(dur); } catch { /* egal */ } }, 350);
    }
  }

  function on3dNodeClick(node) {
    const id = String(node.id ?? '');
    // Zeilen-Lookup über den Anzeigewert: tr[data-addr] trägt nicht mehr die
    // rohe Knoten-Id, sondern displayAddr(id) (Befund 2026-09-29).
    const row = surface.querySelector(`tr[data-addr="${cssEscape(displayAddr(id))}"]`);
    if (row) row.scrollIntoView({ block: 'center', behavior: reducedMotion() ? 'auto' : 'smooth' });
    if (!reducedMotion()) {
      try {
        const d = 220;
        fg3d.cameraPosition(
          { x: node.x + d * 0.5, y: node.y + d * 0.4, z: node.z + d },
          { x: node.x, y: node.y, z: node.z },
          500
        );
      } catch { /* egal */ }
    }
  }

  function build2D(clusterNodes, clusterEdges, graphEl) {
    teardown3D();
    graphEl.innerHTML = '';
    last2dBuild = { nodes: clusterNodes, edges: clusterEdges, el: graphEl };
    const vNodes = new window.vis.DataSet(clusterNodes.map((n) => {
      const role = roleColors[n.role] ? n.role : 'unknown';
      return {
        id: String(n.id),
        label: graphLabel(n.id), // B8: Zwei-Zeilen-Helfer wie B2 (voll nur bei isFullShownAddr)
        title: `${displayAddr(n.id)} (${roleLabelText(role)})`,
        shape: 'dot',
        size: 14,
        color: roleColors[role],
      };
    }));
    const vEdges = new window.vis.DataSet(clusterEdges.map((e) => {
      // Fraud-Override + Kategorie-Farbe (Kritiker-Pflichtkorrektur 4/6) wie
      // im 3D-Accessor; gestrichelte Betrugskanten als Deutan-Zweitkanal.
      const fraud = edgeIsFraud(e);
      return {
        id: String(e.txHash || `${e.from}->${e.to}::${e.type}`),
        from: String(e.from),
        to: String(e.to),
        label: String(e.type ?? ''),
        // Tag-Suffix im Kanten-Tooltip nur bei Multi-User-Treffer des Ziels
        // (Registry ODER verifizierter well-known-Name, multiUserEntryOf-Host-
        // Gate) und belegtem toTag (fail-closed).
        title: `${displayAddr(e.from)} → ${displayAddr(e.to)} (${String(e.type ?? '')})`
          + (e.toTag != null && multiUserEntryOf(String(e.to)) ? ` · #${e.toTag}` : ''),
        color: { color: (fraud ? edgeColors.fraud : edgeColors[edgeCategoryOf(e.type)]) || edgeDefaultOf(), highlight: canvasInkColor(), hover: canvasInkColor() },
        ...(fraud ? { dashes: [6, 4] } : {}),
        arrows: { to: { enabled: true, scaleFactor: 0.5 } },
        width: 1,
      };
    }));
    vis2d = new window.vis.Network(graphEl, { nodes: vNodes, edges: vEdges }, {
      autoResize: true,
      physics: ctx.physicsCluster,
      interaction: { hover: true, tooltipDelay: 120, zoomView: true, dragView: true },
      nodes: {
        borderWidth: 1,
        // Canvas-Fonts über den Token-Weg (--a6-ink, live gelesen; Noir
        // liefert die helle Tinte) — Literale nur als Node-Test-Fallback.
        font: { color: canvasInkColor(), size: 12, face: '"JetBrains Mono", ui-monospace, Consolas, monospace' },
      },
      edges: {
        smooth: { type: 'curvedCW', roundness: 0.14 },
        // size 12 wie der Hauptpfad (app.js): Schrift unter 12 px ist
        // Astra-6-Microtype und verboten (globe.css-Designprinzipien) —
        // Befund 2026-09-29 (war 10 px). Kanten-Labels in --a6-body-Töne.
        font: { color: canvasBodyColor(), size: 12, face: '"JetBrains Mono", ui-monospace, Consolas, monospace', strokeWidth: 0, align: 'middle' },
      },
    });
    if (reducedMotion()) {
      // Reduced Motion: Physik nach Stabilisierung einfrieren (cooldownTicks 0).
      try {
        vis2d.once('stabilizationIterationsDone', () => {
          vis2d.setOptions({ physics: { enabled: false, cooldownTicks: 0 } });
        });
      } catch { /* egal */ }
    }
  }

  function teardown3D() {
    if (fg3dResizeObs) {
      try { fg3dResizeObs.disconnect(); } catch { /* egal */ }
      fg3dResizeObs = null;
    }
    // Ring-Ressourcen der Instanz freigeben (ein Mesh je Drainer, Geometrie/
    // Material geteilt): dispose ist idempotent — auch wenn der Mapper des
    // Bundles die Kind-Geometrien bereits freigegeben hat.
    try { if (ring3dUnitGeo && typeof ring3dUnitGeo.dispose === 'function') ring3dUnitGeo.dispose(); } catch { /* egal */ }
    try { if (ring3dMat && typeof ring3dMat.dispose === 'function') ring3dMat.dispose(); } catch { /* egal */ }
    ring3dUnitGeo = null;
    ring3dMat = null;
    ring3dClasses = null;
    ring3dClassesFailed = false;
    ring3dIds = new Set();
    ring3dLayout = null;
    reset3dHover();
    fg3dStageEl = null;
    if (!fg3d) return;
    try { fg3d.pauseAnimation(); } catch { /* egal */ }
    // ECHTES Freigeben (Symptom 2b, WebGL-Context-Leck): Nur pause+null ließ
    // den WebGL-Context der Instanz weiterleben — jeder Zyklus 'Cluster fiel
    // aus dem Fenster → Modal geleert → neu geöffnet' leakte einen Live-
    // Context; ab ~16 aktiven Contexten erzwingt Chrome Context-Loss am
    // ältesten Context (= Weltkugel). _destructor() (kapsule-Standard)
    // entsorgt Instanz, DOM und WebGL-Ressourcen.
    try {
      if (typeof fg3d._destructor === 'function') fg3d._destructor();
    } catch { /* egal — fg3d=null bleibt als Minimum */ }
    fg3d = null;
    graphClusterId = null;
  }

  function teardown2D() {
    if (!vis2d) return;
    try { vis2d.destroy(); } catch { /* egal */ }
    vis2d = null;
    last2dBuild = null;
  }

  return { openCluster, refresh };
}
