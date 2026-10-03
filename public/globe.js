'use strict';

/* Honeypot XRPL – Weltkugel-Tab (public/globe.js)
 *
 * Dritter Graph-Tab „Weltkugel": symbolische 3D-Aktivitätskugel auf Basis
 * globe.gl@2.46.2 (UMD, https://unpkg.com/globe.gl@2.46.2/dist/globe.gl.min.js
 * — vom Design-Planer curl-verifiziert und hier am Bundle nachgeprüft:
 * 1.885.160 Bytes, alle unten genutzten Accessors sind im Bundle enthalten).
 * Das Bundle wird nie eager geladen: Erst der erste activate()-Aufruf
 * injiziert das <script> lazy (Singleton-Promise, Muster drilldown.js:75-87).
 *
 * Für den Länder-Layer kommt topojson-client@3.1.0 GEPINNT dazu (UMD,
 * https://unpkg.com/topojson-client@3.1.0/dist/topojson-client.min.js — ohne
 * Patch-Angabe leitet unpkg nur um; am Bundle window.topojson.feature
 * verifiziert), gleiches Lazy-Muster beim ersten activate(). Die Attribution-
 * Logik (Registry-Parsing, Länder-Matching, Fluss-Aggregation) liegt im
 * same-origin ESM public/attribution.mjs (dynamischer Import; läuft identisch
 * in Node, getestet in lib/attribution.test.mjs).
 *
 * MODUL-VERTRAG: export function initGlobe(ctx) -> { activate, deactivate, refresh }
 *   activate()   – erster Aufruf injiziert globe.gl und baut die Kugel;
 *                  weitere Aufrufe führen nur resumeAnimation aus.
 *   deactivate() – pauseAnimation() (Tab/View inaktiv).
 *   refresh(force) – bietet Punkte/Bögen/Ring-Quellen aus ctx.getClusterGraph()
 *                  an (leerer/fehlender Graph leert die Datensätze, statt zu
 *                  crashen). Die Anwendung ist GEDÄMPFT (FIX-B, siehe
 *                  Konstantenblock): Anwendetakt-Deckel primär, Signatur-Skip
 *                  sekundär, Puls-Ringe im eigenen Takt. Trifft refresh() ein,
 *                  bevor die Konstruktion aus activate() abgeschlossen ist,
 *                  wird der Datensatz intern gepuffert (latestDs) und beim
 *                  Konstruktions-Abschluss angewandt — frühe Ledger-Events
 *                  gehen nicht verloren.
 * Selbstverwaltung ohne Host-Beteiligung (app.js bleibt unberührt):
 *   – IntersectionObserver auf #globe + visibilitychange: unsichtbar →
 *     pauseAnimation, wieder sichtbar → resumeAnimation plus GENAU EIN
 *     refresh (idempotent zur bedingten Tab-Pause des Hosts).
 *   – webglcontextlost/-restored am Canvas: klarer Hinweis statt schwarzem
 *     Stand, GENAU EIN vollständiger Neuaufbau-Versuch, danach Terminal-
 *     zustand wie showFallback (kein Retry-Loop).
 *
 * ctx (nur Host-Funktionen des Hosts app.js): getClusterGraph, displayAddr
 * (displayFindingAddr), isDeniedAddr, shortAddr, esc, fmtXrp, roleColors
 * (ROLE_COLORS), edgeColors (EDGE_COLORS), edgeDefault, hashOf (SHA-256-Cache),
 * openCluster(clusterId).
 *
 * SICHERHEIT (Grundprinzip drilldown.js:16-23): Adressen werden NIEMALS roh
 * gerendert — ausschließlich über ctx.displayAddr (fail-closed). Zusätzlich
 * KNOTEN-GATE isDeniedAddr als Defense-in-Depth vor jeder Datensetzung
 * (Muster drilldown.js:252-254): Köder-Adressen erreichen weder Punkt noch
 * Bogen noch Ring noch Label. Dieses Modul enthält keine Köder-Adressen und
 * keine Seeds als Literale, öffnet selbst keine WebSocket-Verbindung und
 * loggt keine Adressen.
 *
 * Ehrliche Platzierung: das XRPL-Ledger enthält KEINE Geodaten. Positionen
 * UNZUGEORDNETER Adressen sind deterministisch aus der Adresse abgeleitet
 * (SHA-256 über ctx.hashOf; der Cache wird vom Host via primeAddrHashes
 * gefüllt) — kein Math.random und kein Date.now für Positionen. KEIN
 * globeImageUrl. Seit dem Attribution-Layer (2026-09-30) zeigen zusätzlich
 * LÄNDER-POLYGONE (Natural Earth, /data/countries-50m.json via topojson-
 * client) die Grenzen; Börsen-Registry-Adressen (/data/exchange-registry.json)
 * werden über ihr Sitzland platziert (aggregateCountryFlows aus
 * public/attribution.mjs) — Zuordnung ausschließlich über die Registry,
 * alles andere bleibt symbolisch hash-platziert. Die Kugel-OBERFLÄCHE selbst
 * wird über globeMaterial() auf die Token-Farbe der Bühne (--a6-graph-canvas,
 * Weiß) gesetzt — der Bundle-Default wäre opak schwarz (Befund 2026-09-30).
 *
 * Der zugehörige Tab-Button #tab-globe, der Container #globe und der
 * dynamische Import kommen vom Verdrahtungs-Agenten (app.js/index.html).
 * Dieses Modul ist auch allein lauffähig: Ohne #globe im DOM bleibt
 * initGlobe passiv (Null-Guard).
 */

import { t, sevText } from './i18n.mjs';

const GLOBE_GL_URL = 'https://unpkg.com/globe.gl@2.46.2/dist/globe.gl.min.js';
// SRI-Integrität (Lieferketten-Hygiene, Befund 2026-09-30): Beide CDN-
// Bundles laufen mit Subresource-Integrity — ein kompromittiertes CDN kann
// den Bundle-Inhalt nicht unbemerkt tauschen. Hashes über die exakten Bytes
// der gepinnten URLs (globe.gl: 1.885.160 Bytes, wie oben im Modul-Kommentar
// dokumentiert), Format sha384-Base64. crossorigin="anonymous" ist zu SRI
// Pflicht (CORS-Modus); unpkg sendet Access-Control-Allow-Origin: *.
const GLOBE_GL_INTEGRITY = 'sha384-1uolMBZ25k3zJcNwCLEv49+L+m2dZudqAzsoSAJfQTzDCSBxJzrMuZ2dkp/5JKiT';
const TOPOJSON_URL = 'https://unpkg.com/topojson-client@3.1.0/dist/topojson-client.min.js'; // GEPINNT mit Patch: die ungepatchte @3-URL leitet auf unpkg um
const TOPOJSON_INTEGRITY = 'sha384-Ukv1p/xTma6P4/2bY5KzWBw+ydSpXmhCMtyciIQVDJ1RmOxtCYNMF1uXT9T63H67';
const EXCHANGE_REGISTRY_URL = '/data/exchange-registry.json'; // same-origin (express.static, server/index.mjs)
const COUNTRIES_URL = '/data/countries-50m.json';             // Natural-Earth-TopoJSON (241 Länder)
const GLOBE_MAX_ARCS = 300;        // Deckel: zuletzt 300 Kanten (Analogon CLUSTER_MAX_EDGES, app.js:106)
const RING_WINDOW_MS = 30000;      // Puls-Ringe nur für Kanten mit closeTime jünger als 30 s
const RING_REPEAT_MS = 1200;       // ringRepeatPeriod laut Plan
const RING_MAX_RADIUS_DEG = 5;     // Ring-Radius in Grad (Kugel-Oberfläche)
const RING_PROPAGATION_SPEED = 4;  // Grad pro Sekunde
const ARC_STROKE_DEFAULT = 0.8;    // Strichstärke Standard-Kanten
const ARC_STROKE_FLAGGED = 1.6;    // Strichstärke bei malicious-Beteiligung
const ARC_DASH_LEN_FLAGGED = 0.45; // Strichlänge (relativ zur Bogenlänge, Bundle-Shader prüft mod(relDist, len+gap) > len)
const ARC_DASH_GAP_FLAGGED = 0.25; // Strichlücke (relativ)
const ARC_DASH_ANIMATE_MS = 2500;  // wandernde Striche nur ohne prefers-reduced-motion
const AUTO_ROTATE_SPEED = 0.4;     // autoRotate-Geschwindigkeit (OrbitControls)
const POV_START = { lat: 20, lng: 0, altitude: 2.2 };
const SEV_RANK = { info: 1, suspect: 2, malicious: 3 }; // wie SEVERITY_RANK, lib/cluster.mjs:43
/* Hinweis-/aria-Texte stehen jetzt im i18n-Wörterbuch (Keys globe.*);
 * GLOBE_ARIA_BASE ist identisch zum data-i18n-aria-Key globe.aria in
 * index.html (Duplikat-Muster aufgelöst — beide lesen dasselbe Dict). */
const GLOBE_ARIA_BASE = 'globe.aria';
const GLOBE_ARIA_COUNTRIES = 'globe.ariaCountries';
const GLOBE_ARIA_FAILED = 'globe.ariaFailed';
const GLOBE_NOTE = 'globe.note';
const GLOBE_NOTE_COUNTRIES = 'globe.noteCountries';
const GLOBE_CTX_LOST_NOTE = 'globe.ctxLost';
/* Länder-Layer (Attribution): dezent — Grenzen sichtbar, Fläche transparent */
const GLOBE_POLYGON_ALTITUDE = 0.006;   // Polygone knapp über der Kugel-Oberfläche
const GLOBE_POLYGON_FILL = 'rgba(255, 255, 255, 0)'; // neutrale Kappe/Seiten (Bühnen-Weiß, Alpha 0): nur Grenzlinien sichtbar
const GLOBE_COUNTRY_LABELS_MAX = 12;    // Beschriftung nur der aktivsten Länder (klafterfrei)
const GLOBE_COUNTRY_REF_ACTIVITY = 20;  // Skalenreferenz: ab 20 Aktivitäten voller Länderpunkt-Radius (log-skaliert)
const GLOBE_ARC_FLOW_REF_COUNT = 10;    // Skalenreferenz: ab 10 Kanten volle Fluss-Bogen-Strichstärke
// SEV_TEXT ersetzt: Bogen-Labels nutzen sevText() aus ./i18n.mjs.

/* FIX-B „Update statt Rebuild": globe.gl baut bei jedem pointsData-/arcsData-/
 * ringsData-Setter alle Szenen-Objekte neu auf; der ~4-s-Takt des Hosts
 * (rebuildClusterGraph → refresh, app.js:1040) ließ die Bogen-Dash-Animation
 * dadurch ~15×/min neu starten („Weltkugel reloaded ständig“). Zwei getrennte
 * Dämpfungs-Mechanismen:
 *   1. PRIMÄR: Anwendetakt-Deckel — höchstens eine vollständige Punkte/Bögen-
 *      Anwendung je APPLY_MIN_INTERVAL_MS. Unter WSS-Last ändern sich Kanten-
 *      mengen real pro Ledger, ein reiner Signaturvergleich entlastet kaum.
 *   2. SEKUNDÄR: Signatur-Skip bei inhaltlich unveränderten Daten. Die
 *      Signatur umfasst VERPFLICHTEND die visuell kodierenden Felder:
 *      Punkte lat/lng/color/radius/altitude (Radius/Höhe codieren in-/outDrops)
 *      und Bögen Endpunkte/color/stroke/dashLen/dashGap (codieren malicious-
 *      Beteiligung) — sonst veralten Security-Signalisierung und Punktgrößen
 *      bei gleichbleibenden Ids.
 * Puls-Ringe sind ZEITFENSTERIG (RING_WINDOW_MS gegen now) und ändern sich
 * ohne Graph-Änderung: Sie stehen NICHT in der Signatur, sondern laufen in
 * einem eigenen Takt (RINGS_TICK_MS), der gegen das aktuelle now filtert.
 * AUSNAHMEN ohne Deckel (nur über globe-sichtbare Daten definiert — der
 * Modal-Zustand ist hier nicht zugänglich): allererste Daten nach der
 * Konstruktion, Wechsel des clusterId-Sets der Punkte (point.clusterId) sowie
 * refresh(true) — der Host ruft Letzteres nach Bait-Hash-Rotation, damit ein
 * frisch aktivierter Köder-Ausschluss (Deny-Set-Änderung) SOFORT greift und
 * nicht erst zum Fensterende des Deckels (Befund 2026-09-30). BEKANNTE
 * BEGRENZUNG: Bei gewöhnlichen refresh()-Aufrufen ohne force veralten
 * Labels/Filter um ≤ APPLY_MIN_INTERVAL_MS (u. a. displayAddr-Voll-/Kurzform);
 * der Deny-Ausschluss selbst veraltet maximal bis zur nächsten erkannten
 * Deny-Set-Änderung, die der Host mit refresh(true) sofort durchschlägt. */
const APPLY_MIN_INTERVAL_MS = 10000; // Deckel: max. eine Punkte/Bögen-Anwendung je 10 s (≤ 6/min)
const RINGS_TICK_MS = 10000;         // eigener Takt der Puls-Ringe (≤ 10 s), außerhalb der Signatur
const RING_SOURCE_EXTRA_MS = 60000;  // Ring-Quellen breiter sammeln; der Takt filtert gegen das aktuelle now
const CTX_RESTORE_GRACE_MS = 3000;   // Frist für webglcontextrestored, danach der eine Neuaufbau-Versuch
const GLOBE_FALLBACK_NOTE = 'globe.fallback';

export function initGlobe(ctx) {
  if (!ctx || typeof ctx.getClusterGraph !== 'function') {
    // Ohne Host-Draht bleibt das Modul wirkungslos passiv (Null-Guard-Muster
    // app.js:48-51: kein Top-Level-Crash, der Rest des Dashboards läuft weiter).
    return { activate() {}, deactivate() {}, refresh() {} };
  }

  const displayAddr = typeof ctx.displayAddr === 'function' ? ctx.displayAddr
    : (typeof ctx.shortAddr === 'function' ? ctx.shortAddr : () => '–');
  const isDeniedAddr = typeof ctx.isDeniedAddr === 'function' ? ctx.isDeniedAddr : null;
  const escHost = typeof ctx.esc === 'function' ? ctx.esc : null;
  const hashOf = typeof ctx.hashOf === 'function' ? ctx.hashOf : null;
  const roleColors = ctx.roleColors || {};
  const edgeColors = ctx.edgeColors || {};
  const edgeDefault = typeof ctx.edgeDefault === 'string' ? ctx.edgeDefault : null;
  const openCluster = typeof ctx.openCluster === 'function' ? ctx.openCluster : null;

  let container = null;      // #globe (Mount des Verdrahtungs-Agenten)
  let globe = null;          // globe.gl-Instanz
  let controls = null;       // OrbitControls (globe.controls())
  let noteEl = null;         // Pflicht-Hinweis .graph-note.globe-note
  let resizeObs = null;      // ResizeObserver der Bühne
  let scriptPromise = null;  // Singleton-Ladezustand globe.gl
  let buildStarted = false;  // activate() hat die Konstruktion angestoßen
  let buildDone = false;     // Konstruktion abgeschlossen
  let buildFailed = false;   // WebGL/CDN/Konstruktion gescheitert -> Fallback
  let wantActive = false;    // gewünschter Aktiv-Zustand (Tab sichtbar)
  let userGrabbed = false;   // erste Nutzereingabe: autoRotate bleibt dauerhaft aus
  let refreshSeq = 0;        // Guard gegen überlappte async-Datenaufbauten
  /* FIX-B-Zustand: Dämpfung (latestDs puffert Vor-Konstruktion-Angebote) */
  let latestDs = null;       // neuester Datensatz (Puffer bis zum Konstruktions-Abschluss)
  let hasAppliedData = false;  // Erstdaten-Ausnahme: erste Anwendung ohne Deckel
  let lastApplyAt = 0;         // Zeitpunkt der letzten Punkte/Bögen-Anwendung
  let lastPointsSig = '';      // Signatur des zuletzt angewandten Punktdatensatzes
  let lastArcsSig = '';        // Signatur des zuletzt angewandten Bogendatensatzes
  let lastClusterSetSig = '';  // clusterId-Set der Punkte (Ausnahme-Trigger)
  let applyTimer = 0;          // Deckel-Verzögerung (Anwendung zum Fensterende)
  /* FIX-B-Zustand: Puls-Ringe im eigenen Takt */
  let ringSources = [];        // Zeitfenster-Quellen { key, lat, lng, sev, ep }
  let lastRingsSig = '';       // Signatur der zuletzt gesetzten Ringdaten
  let ringTimer = 0;           // Eigen-Takt der Ringe (nur laufend, wenn sichtbar)
  /* FIX-B-Zustand: Sichtbarkeit (IntersectionObserver + Dokument-Tab) */
  let io = null;               // IntersectionObserver auf dem #globe-Container
  let ioVisible = false;       // Observer-Entscheidung (nur bei nachweislicher Sichtbarkeit resume)
  let visBound = false;        // visibilitychange-Listener vorhanden
  /* FIX-B-Zustand: WebGL-Kontextverlust */
  let ctxLost = false;         // webglcontextlost aktiv
  let ctxRestoreTried = false; // GENAU EIN Restaurationsversuch pro Seitenleben
  let ctxRestoreTimer = 0;     // Frist-Timer für webglcontextrestored
  /* Länder-Layer (Attribution): Drei-Zustands-Maschine countryData.state
   *   'loading' — Daten werden (einmalig) geladen; Kugel läuft symbolisch
   *               weiter, ein hängender Fetch ist KEIN Fehler (kein Retry,
   *               kein Blockieren, kein Blinken).
   *   'ready'   — Registry + Länder-Index gecacht; applyCountryLayer() an
   *               die Instanz anwenden (falls konstruiert), DANACH EINEN
   *               refresh() anstoßen.
   *   'failed'  — terminal bis Seiten-Reload (Script-onerror, Fetch-Fehler,
   *               Parse-Fehler, leere Registry/leerer Länder-Index):
   *               symbolischer Modus mit ehrlichem Hinweis, kein Retry-Loop. */
  let countryData = { state: 'loading', registry: null, countryIndex: null, features: [] };
  let countryLoadStarted = false; // EINMALiges Laden (Lazy beim ersten activate())
  let topojsonPromise = null;     // Singleton-Ladezustand topojson-client
  let attributionMod = null;      // dynamisch importiertes public/attribution.mjs
  let countryLayerApplied = false; // Instanz-Flag: Polygone an DIESE Instanz gesetzt (Reset in buildGlobe)
  let legendEl = null;            // Legende .globe-legend (Re-Erzeugen nach showNote-Muster)
  let lastLabelsSig = '';         // Signatur der zuletzt angewandten Länder-Labels
  let lastLegendSig = '';         // Signatur der zuletzt angewandten Legende

  /* ---------------- Hilfen ---------------- */

  const esc = (v) => {
    const s = String(v ?? '');
    if (escHost) {
      try { return escHost(s); } catch { /* Fallback unten */ }
    }
    return s.replace(/[&<>"']/g, (c) => ({
      '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
    })[c]);
  };

  function reducedMotion() {
    try { return window.matchMedia('(prefers-reduced-motion: reduce)').matches; }
    catch { return false; }
  }

  // WebGL-Probe VOR der Konstruktion (Muster drilldown.js:66-73): Ein fehlendes
  // WebGL greift denselben Fallback wie ein CDN-Fehler des Bundles.
  function webglAvailable() {
    try {
      const c = document.createElement('canvas');
      return Boolean(c.getContext('webgl2') || c.getContext('webgl'));
    } catch {
      return false;
    }
  }

  function cssToken(name) {
    try { return getComputedStyle(document.body).getPropertyValue(name).trim(); }
    catch { return ''; }
  }

  // globe.gl lazy laden (Singleton-Promise + onerror → Fallback, Muster
  // drilldown.js:75-87). Nach einem Fehler bleibt der Zustand gesetzt: der
  // statische Hinweis regiert bis zum Neu Laden, kein Blink-Loop.
  function loadGlobeGl() {
    if (typeof window.Globe === 'function') return Promise.resolve(true);
    if (scriptPromise) return scriptPromise;
    scriptPromise = new Promise((resolve) => {
      const s = document.createElement('script');
      s.src = GLOBE_GL_URL;
      s.integrity = GLOBE_GL_INTEGRITY; // SRI: bei Hash-Mismatch verweigert der Browser die Ausführung
      s.crossOrigin = 'anonymous';
      s.async = true;
      s.onload = () => resolve(typeof window.Globe === 'function');
      s.onerror = () => resolve(false);
      document.head.appendChild(s);
    });
    return scriptPromise;
  }

  // topojson-client lazy laden — gleiche Singleton-Mechanik wie loadGlobeGl.
  // GEPINNTE URL mit Patch-Version: die ungepatchte @3-URL antwortet nur mit
  // einem Redirect-Body; das gepinnte Bundle stellt window.topojson.feature
  // bereit (am Bundle verifiziert).
  function loadTopojson() {
    if (window.topojson && typeof window.topojson.feature === 'function') return Promise.resolve(true);
    if (topojsonPromise) return topojsonPromise;
    topojsonPromise = new Promise((resolve) => {
      const s = document.createElement('script');
      s.src = TOPOJSON_URL;
      s.integrity = TOPOJSON_INTEGRITY; // SRI wie bei globe.gl (gleiche Lieferkette, gleicher Schutz)
      s.crossOrigin = 'anonymous';
      s.async = true;
      s.onload = () => resolve(Boolean(window.topojson && typeof window.topojson.feature === 'function'));
      s.onerror = () => resolve(false);
      document.head.appendChild(s);
    });
    return topojsonPromise;
  }

  // Nutzbarer Centroid: Array der Länge 2 mit endlichen Zahlen ([lat, lng]).
  // Definiert „platzierbar" für Länderpunkte, Per-Edge-Positionen, Fluss-
  // Bögen und den Legenden-Zähler (schließt noPolygon- und centroid:null-
  // Treffer ausdrücklich NICHT als zugeordnet ein).
  function isUsableCentroid(c) {
    return Array.isArray(c) && c.length === 2 && Number.isFinite(c[0]) && Number.isFinite(c[1]);
  }

  // Der Länder-Layer gilt als aktiv, wenn die Polygone an die aktuelle
  // Instanz gesetzt wurden UND die Daten bereitstehen (Notiz- und Legenden-
  // Ehrlichkeit: keine Grenzen behaupten, die gerade fehlen).
  function countryLayerActive() {
    return countryLayerApplied && countryData.state === 'ready';
  }

  // aria-label des #globe-Containers an den Länder-Layer-Zustand koppeln
  // (Befund 2026-09-30): Ein statisches Label hätte im Terminalzustand
  // 'failed' Grenzen behauptet, die es nicht gibt. Aufgerufen bei jedem
  // Zustandsübergang (ensureCountryData) und nach jedem (Neu-)Aufbau der
  // Instanz (buildGlobe); ohne Container bleibt das statische Label stehen.
  function syncGlobeAria() {
    if (!container) return;
    try {
      container.setAttribute(
        'aria-label',
        t(countryLayerActive() ? GLOBE_ARIA_COUNTRIES
          : countryData.state === 'failed' ? GLOBE_ARIA_FAILED
            : GLOBE_ARIA_BASE)
      );
    } catch { /* DOM nicht schreibbar: statisches Label bleibt, wirft nicht */ }
  }

  /* Grenzlinien-Farbe: Vertragskette cssToken('--a6-line') || EDGE_DEFAULT —
   * mit einer am gepinnten Bundle verifizierten Bewertung (2026-09-30):
   * --a6-line ist ein UI-Border-Token MIT Alpha (rgba(20, 20, 22, 0.12)); im
   * DOM ergibt das die feinen 1px-Ränder der Flächen, in WebGL-Linien wird
   * dasselbe Alpha dagegen als Material-Deckkraft angewandt (opacity 0.12,
   * transparent — live nachgeprüft). 12 % Ink über weißer Bühne liegt mit
   * ≈ #E3E3E5 unter dem WCAG-Grafikkontrast (3:1) und wäre praktisch
   * unsichtbar (gleiche Größenordnung wie die Graticules). Damit der
   * Layer-Zweck „Grenzen sichtbar" hält, fällt die Kette bei rgba-Alpha
   * unter 0.5 auf den dokumentierten Fallback derselben Kette durch:
   * EDGE_DEFAULT (#62626b, neutral, Kontrast ≈ 5,6:1). Opake Token-Werte
   * und solche mit Alpha >= 0.5 werden unverändert übernommen. */
  function resolveStrokeColor() {
    const raw = cssToken('--a6-line');
    if (raw) {
      const m = raw.match(/^rgba?\(\s*[\d.]+\s*[,\s]+[\d.]+\s*[,\s]+[\d.]+\s*[,/]\s*([\d.]+)%?\s*\)$/i);
      if (!m) return raw; // opake Farbe (#hex/named): direkt durchreichen
      const a = m[1].endsWith('%') ? parseFloat(m[1]) / 100 : parseFloat(m[1]);
      if (Number.isFinite(a) && a >= 0.5) return raw; // ausreichend deckend
    }
    return edgeDefault; // dokumentierter Fallback der Vertragskette
  }

  /* Länder-Daten EINMAL lazy laden (erster activate()): Registry + TopoJSON
   * + Attribution-Modul, alles fail-soft — kein Fehler hier darf die Kugel
   * oder den Tab reißen (der dynamische import mit .catch ist reine
   * Laufzeit-Robustheit für Produktions-404, kein Ersatz für die Datei).
   * Zustandsübergänge siehe countryData-Kommentar oben. */
  async function ensureCountryData() {
    if (countryLoadStarted) return;
    countryLoadStarted = true;
    countryData = { state: 'loading', registry: null, countryIndex: null, features: [] };
    try {
      const mod = await import('./attribution.mjs'); // same-origin ESM (Vertragspartner)
      if (!mod || typeof mod.parseExchangeRegistry !== 'function'
        || typeof mod.indexCountryFeatures !== 'function'
        || typeof mod.aggregateCountryFlows !== 'function') throw new Error('attribution-modul');
      const topoOk = await loadTopojson();
      if (!topoOk) throw new Error('topojson-cdn');
      const [regRaw, topoRaw] = await Promise.all([
        fetch(EXCHANGE_REGISTRY_URL).then((r) => { if (!r.ok) throw new Error('registry-http'); return r.json(); }),
        fetch(COUNTRIES_URL).then((r) => { if (!r.ok) throw new Error('countries-http'); return r.json(); }),
      ]);
      const registry = mod.parseExchangeRegistry(regRaw);
      if (!registry || registry.ok !== true) throw new Error('registry-leer');
      if (!topoRaw || typeof topoRaw !== 'object' || !topoRaw.objects
        || !topoRaw.objects.countries) throw new Error('topologie-ungueltig');
      let features = null;
      try { features = window.topojson.feature(topoRaw, topoRaw.objects.countries).features; } catch { features = null; }
      if (!Array.isArray(features) || features.length === 0) throw new Error('features-leer');
      const countryIndex = mod.indexCountryFeatures(features);
      if (!countryIndex || !(countryIndex.byName instanceof Map) || countryIndex.count === 0) {
        throw new Error('laender-index-leer');
      }
      attributionMod = mod;
      countryData = { state: 'ready', registry, countryIndex, features };
    } catch {
      attributionMod = null;
      countryData = { state: 'failed', registry: null, countryIndex: null, features: [] };
    }
    // Zustand anwenden (idempotent; ist die Kugel noch unkonstruiert, zieht
    // buildGlobe den Zustand beim Konstruktions-Abschluss selbst nach).
    if (countryData.state === 'ready') {
      if (buildDone && globe && container) {
        applyCountryLayer();
        showNote(container, t(GLOBE_NOTE_COUNTRIES));
        syncGlobeAria(); // Grenzen existieren nachweislich -> aria-label ergänzen
      }
      refresh(); // GENAU EIN Daten-Refresh nach Bereitstellen des Layers
    } else if (countryData.state === 'failed' && buildDone && globe && container) {
      showNote(container, t(GLOBE_NOTE)); // symbolische Variante: keine Grenzen behaupten
      syncGlobeAria(); // Terminalzustand: aria-label ehrlich einschränken
    }
  }

  /* Länder-Polygone an die AKTUELLE Instanz setzen — idempotent über das
   * Instanz-Flag (Reset zu Beginn von buildGlobe): rebuildGlobe() erzeugt
   * eine NEUE Instanz und leert den Container; Accessors und Daten müssen
   * je Instanz gesetzt werden (Accessors in buildGlobe, Daten hier). */
  function applyCountryLayer() {
    if (!globe || !buildDone || countryLayerApplied) return;
    if (countryData.state !== 'ready') return;
    try {
      globe.polygonsData(countryData.features);
      countryLayerApplied = true;
    } catch { /* Polygon-Setter fehlt: kein Länder-Layer, Rest läuft weiter */ }
  }

  /* Legende des Länder-Layers (Overlay .globe-legend in #globe): Re-Erzeugen,
   * sobald der Knoten nicht mehr im Container hängt — showNote-Muster
   * (globe.js, Detach durch rebuildGlobe/el.innerHTML=''). Der Zähler wird
   * vom Anwendungspfad (applyPointsArcs) mit dem frischen Datensatz versorgt;
   * Severity-Swatches nutzen die bestehenden Klassen .swatch/.swatch-sev-*
   * (style.css:632-658) — kein zweites Farbsystem. */
  function ensureLegend(unassignedCount) {
    if (!container) return;
    try {
      if (!legendEl || legendEl.parentElement !== container) {
        legendEl = document.createElement('div');
        legendEl.className = 'globe-legend';
        const title = document.createElement('p');
        title.className = 'globe-legend-title';
        title.textContent = t('globe.legendTitle');
        legendEl.appendChild(title);
        const rows = [
          ['swatch-sev-malicious', sevText('malicious')],
          ['swatch-sev-suspect', sevText('suspect')],
          ['swatch-sev-info', sevText('info')],
        ];
        for (const [swatchClass, text] of rows) {
          const row = document.createElement('p');
          row.className = 'globe-legend-row';
          const sw = document.createElement('span');
          sw.className = 'swatch ' + swatchClass;
          row.appendChild(sw);
          row.appendChild(document.createTextNode(text));
          legendEl.appendChild(row);
        }
        const count = document.createElement('p');
        count.className = 'globe-legend-count';
        legendEl.appendChild(count);
        const src = document.createElement('p');
        src.className = 'globe-legend-src';
        src.textContent = t('globe.legendSrc');
        legendEl.appendChild(src);
        container.appendChild(legendEl);
      }
      const countEl = legendEl.querySelector('.globe-legend-count');
      if (countEl) countEl.textContent = t('globe.legendUnassigned', { n: unassignedCount });
    } catch { /* DOM nicht schreibbar: Legende entfällt, wirft aber nicht */ }
  }

  function removeLegend() {
    try {
      if (legendEl && legendEl.parentElement) legendEl.parentElement.removeChild(legendEl);
    } catch { /* egal */ }
    legendEl = null;
  }

  // Legende nur mit aktivem Länder-Layer zeigen — ein Overlay mit Quellen-
  // Hinweis darf keine Grenzen behaupten, die gerade fehlen.
  function syncLegend(legend) {
    if (legend && legend.show && countryLayerActive()) ensureLegend(legend.unassigned);
    else removeLegend();
  }

  // Deterministische Koordinaten aus dem Adress-Hash (SHA-256-Hex, vom Host
  // bereitgestellt): lat = −90 + 180 · (uint32(hex[0..7]) / 2^32),
  // lng = −180 + 360 · (uint32(hex[8..15]) / 2^32). Kein Math.random, kein
  // Date.now — Positionen sind sitzungsübergreifend stabil.
  function coordsFromHash(hex) {
    const latFrac = parseInt(hex.slice(0, 8), 16) / 4294967296;
    const lngFrac = parseInt(hex.slice(8, 16), 16) / 4294967296;
    if (!Number.isFinite(latFrac) || !Number.isFinite(lngFrac)) return null;
    return [-90 + 180 * latFrac, -180 + 360 * lngFrac];
  }

  // Relative Luminanz (WCAG-Formel) einer #rrggbb-Farbe; andere Formate -> null
  // (dann bleibt die Originalfarbe unverändert — kein Raten). globe.gl-Punkte
  // haben keine Border-Option (nur color/radius/altitude, Bundle-nachgeprüft),
  // deshalb dient die Luminanz als Kriterium für den Sichtbarkeits-Fallback.
  function relLuminance(color) {
    const m = String(color ?? '').match(/^#([0-9a-f]{6})$/i);
    if (!m) return null;
    const lin = (h) => {
      const v = parseInt(h, 16) / 255;
      return v <= 0.03928 ? v / 12.92 : ((v + 0.055) / 1.055) ** 2.4;
    };
    return 0.2126 * lin(m[1].slice(0, 2)) + 0.7152 * lin(m[1].slice(2, 4)) + 0.0722 * lin(m[1].slice(4, 6));
  }

  // Atmosphärenfarbe aus dem Token --a6-globe-atmosphere (globe.css). Der
  // Alpha-Anteil wird über Weiß geblendet, weil die WebGL-Atmosphärenfarbe
  // (new THREE.Color, Bundle-Check) keinen Alphakanal auswertet — so bleibt
  // der hauchzarte Charakter des Tokens erhalten.
  function resolveAtmosphereColor() {
    const raw = cssToken('--a6-globe-atmosphere');
    if (!raw) return null;
    const m = raw.match(/^rgba?\(\s*([\d.]+)[,\s]+([\d.]+)[,\s]+([\d.]+)(?:[,\s/]+([\d.%]+))?\s*\)$/i);
    if (!m) return raw; // Hex- oder benannte Farbe: direkt durchreichen
    const r = parseFloat(m[1]);
    const g = parseFloat(m[2]);
    const b = parseFloat(m[3]);
    if (![r, g, b].every(Number.isFinite)) return null;
    let a = 1;
    if (m[4] !== undefined) {
      a = m[4].endsWith('%') ? parseFloat(m[4]) / 100 : parseFloat(m[4]);
      if (!Number.isFinite(a)) a = 1;
    }
    a = Math.min(1, Math.max(0, a));
    if (a >= 1) return `rgb(${Math.round(r)}, ${Math.round(g)}, ${Math.round(b)})`;
    const mix = (ch) => Math.round(ch * a + 255 * (1 - a)); // Bühne ist weiß
    return `rgb(${mix(r)}, ${mix(g)}, ${mix(b)})`;
  }

  // Schweregrad-Farben ausschließlich aus den bestehenden CSS-Tokens
  // (style.css:70-73, --a6-sev-*) — kein zweites Farbsystem in diesem Modul.
  // Letzter Fallback ist die neutrale Kantenfarbe des Hosts (edgeDefault).
  function sevTokenColor(sev) {
    const primary = cssToken(`--a6-sev-${sev}`);
    if (primary) return primary;
    const alt = sev === 'malicious' ? '--a6-error' : sev === 'suspect' ? '--a6-warn' : '--a6-info';
    return cssToken(alt) || cssToken('--a6-sev-neutral') || edgeDefault || null;
  }

  function showNote(el, text, isAlert) {
    try {
      // globe.gl ERSETZT den Container-Inhalt beim Mount (window.Globe()(el)):
      // Ein vor dem Mount angehängter Hinweis wird dabei DETACHED — der alte
      // Guard (!noteEl) verhinderte dann das Neu-Anhängen und der Pflicht-
      // Hinweis erschien im Erfolgs-Pfad nie (Befund 2026-09-29). Neu
      // erstellen und anhängen, sobald der Knoten nicht mehr im Container
      // hängt; die Overlay-Positionierung liefert #globe .globe-note
      // (globe.css, absolute, pointer-events none) — die Szene bleibt unberührt.
      if (!noteEl || noteEl.parentElement !== el) {
        noteEl = document.createElement('p');
        noteEl.className = 'graph-note globe-note';
        // role=status (impliziert aria-live=polite; Muster showFallback,
        // globe.js showFallback-Box): Der Zustandswechsel des Länder-Layers
        // (ready/failed) wird damit auch Screenreadern angekündigt, nicht
        // nur visuell (Befund 2026-09-30 — zuvor war die Korrektur rein
        // optisch und das aria-label behauptete Grenzen weiter).
        noteEl.setAttribute('role', 'status');
        el.appendChild(noteEl);
      }
      // isAlert (WebGL-Kontextverlust): nur eine Zustandsvariante desselben
      // Hinweises — .globe-note-alert färbt in globe.css ausschließlich die
      // Linienfarbe um (Astra-6: Fläche, Typografie und Touchziele bleiben).
      noteEl.className = isAlert ? 'graph-note globe-note globe-note-alert' : 'graph-note globe-note';
      noteEl.textContent = text;
    } catch { /* DOM nicht schreibbar: Hinweis entfällt, wirft aber nicht */ }
  }

  // Dreistufiger Fallback, Stufe 2 (Muster drilldown.js:469-498): statischer
  // Hinweis statt leerem Canvas, kein Erfolgs-Vortäuschen. Graph-Tabs und
  // Cluster-Liste bleiben unberührt.
  function showFallback(el) {
    try {
      el.innerHTML = '';
      noteEl = null;
      const box = document.createElement('div');
      box.className = 'globe-fallback';
      box.setAttribute('role', 'status');
      const p = document.createElement('p');
      p.className = 'graph-note';
      p.textContent = t(GLOBE_FALLBACK_NOTE);
      box.appendChild(p);
      el.appendChild(box);
    } catch { /* DOM nicht schreibbar: Tab bleibt leer, wirft aber nicht */ }
  }

  // Containergröße statt Fenstergröße (Muster sizeToContainer,
  // drilldown.js:535-545): Das Bundle initialisiert width/height mit
  // window.innerWidth/innerHeight und renderte sonst fensterbreit.
  function sizeToContainer() {
    if (!globe || !container) return;
    const w = Math.max(1, Math.floor(container.clientWidth));
    const h = Math.max(1, Math.floor(container.clientHeight));
    try { globe.width(w).height(h); } catch { /* egal */ }
  }

  function syncAutoRotate() {
    if (!controls) return;
    try { controls.autoRotate = !reducedMotion() && !userGrabbed; } catch { /* egal */ }
  }

  /* ---------------- Datenaufbau ---------------- */

  async function buildDatasets() {
    let cg = null;
    try { cg = ctx.getClusterGraph(); } catch { cg = null; }
    const nodes = cg && Array.isArray(cg.nodes) ? cg.nodes : [];
    const edges = cg && Array.isArray(cg.edges) ? cg.edges : [];

    // KNOTEN-GATE (Defense-in-Depth, Muster drilldown.js:252-254): Der Host
    // filtert bereits vor buildClusterGraph; diese Schicht sichert zusätzlich
    // Graphen ab, die diesen Weg nicht gegangen sind. Kanten fallen automatisch
    // mit (beide Enden müssen verortet sein). Fail-closed: Ohne isDeniedAddr
    // greift weiterhin die Anzeige-Maske displayAddr.
    const visibleNodes = isDeniedAddr
      ? nodes.filter((n) => !isDeniedAddr(String(n.id ?? '')))
      : nodes;

    // Deterministische Koordinaten je Knoten (Cache vom Host geprimt).
    // Fail-closed: Ohne Hash keinen Punkt — keine Ersatzposition, kein
    // Math.random, kein Date.now.
    const coords = new Map();
    if (hashOf) {
      await Promise.all(visibleNodes.map(async (n) => {
        const id = String(n.id ?? '');
        if (!id || coords.has(id)) return;
        let hex = '';
        try { hex = String(await hashOf(id)); } catch { hex = ''; }
        const c = /^[0-9a-f]{16}/i.test(hex) ? coordsFromHash(hex) : null;
        if (c) coords.set(id, c);
      }));
    }

    // LÄNDER-ATTRIBUTION (NACH dem Deny-Gate, auf visibleNodes): Registry-
    // Zuordnung + Fluss-Aggregation aus public/attribution.mjs. Fail-soft:
    // null/undefiniert -> symbolischer Modus wie zuvor.
    let attribution = null;
    if (countryData.state === 'ready' && attributionMod) {
      try {
        const visibleIds = new Set(visibleNodes.map((n) => String(n.id ?? '')));
        const graphEdges = edges.filter((e) => visibleIds.has(String(e.from ?? ''))
          && visibleIds.has(String(e.to ?? '')));
        attribution = attributionMod.aggregateCountryFlows({
          nodes: visibleNodes,
          edges: graphEdges,
          registry: countryData.registry,
          countryIndex: countryData.countryIndex,
        });
      } catch { attribution = null; }
    }

    // Positionen je Node: CENTROID-ODER-HASH — Registry-Adressen mit nutzbarem
    // Sitzland-Centroid stehen am Land (Börsen-Sitz, keine Standortdaten des
    // Ledgers), alles andere bleibt deterministisch Hash-platziert.
    const centroidPos = new Map();
    if (attribution) {
      for (const n of visibleNodes) {
        const id = String(n.id ?? '');
        if (!id || centroidPos.has(id)) continue;
        const info = attribution.assignedByAddress.get(id);
        if (info && isUsableCentroid(info.centroid)) centroidPos.set(id, info.centroid);
      }
    }
    const posOf = new Map();
    const sevByNode = new Map();
    for (const n of visibleNodes) {
      const id = String(n.id ?? '');
      if (!id || posOf.has(id)) continue;
      const c = centroidPos.get(id) || coords.get(id);
      if (!c) continue;
      posOf.set(id, c);
      sevByNode.set(id, String(n.severity ?? 'info'));
    }

    const points = [];
    for (const n of visibleNodes) {
      const id = String(n.id ?? '');
      // Attribuierte Adresse mit nutzbarem Centroid: KEIN eigener Punkt — der
      // Länderpunkt vertritt das Land (s. u.); ihr Klick-zu-Cluster entfällt
      // bewusst (clusterId null, onPointClick bleibt No-op), Cluster-Details
      // bleiben über Cluster-Tab und Cluster-Karten erreichbar.
      if (centroidPos.has(id)) continue;
      const c = coords.get(id);
      if (!c) continue;
      const rc = roleColors[n.role] || roleColors.unknown;
      // Farbe exakt aus ROLE_COLORS (kein zweites Farbsystem): die Werte sind
      // Objekte mit .background (app.js:399-425) — die Hintergrundfarbe ist
      // die codierende Fläche, identisch zur Legende (index.html:90-94).
      // ABER: globe.gl-Punkte haben KEINE Border-Option (nur color/radius/
      // altitude, Bundle-nachgeprüft), und die Bühne ist weiß. Eine zu helle
      // Fläche wäre praktisch unsichtbar (unknown: #f0f0f2 auf #ffffff,
      // Kontrast ≈ 1,1:1, Befund 2026-09-29). Fallback auf die Border-Farbe
      // derselben Rolle (#62626b, Kontrast ≈ 5,3:1) — genau der Rand, den die
      // Legende für unknown zeigt; dunkle Rollenfarben bleiben unverändert.
      const bg = typeof rc === 'string' ? rc
        : (rc && typeof rc.background === 'string' ? rc.background : edgeDefault);
      let color = bg;
      const lum = relLuminance(bg);
      if (lum !== null && lum > 0.82) {
        const border = rc && typeof rc === 'object' && typeof rc.border === 'string' ? rc.border : null;
        if (border && relLuminance(border) !== null && relLuminance(border) <= lum) color = border;
      }
      if (typeof color !== 'string') continue;
      // Punktgröße und -höhe nach in+out Drops (log10-skaliert; 1e6 Drops = 1 XRP).
      const drops = Math.max(0, Number(n.inDrops ?? 0)) + Math.max(0, Number(n.outDrops ?? 0));
      const t = Math.log10(1 + drops / 1e6);
      points.push({
        lat: c[0],
        lng: c[1],
        color,
        radius: 0.16 + Math.min(0.64, t * 0.13),
        altitude: 0.012 + Math.min(0.1, t * 0.02),
        label: esc(displayAddr(id)),
        clusterId: n.clusterId != null ? String(n.clusterId) : null,
      });
    }

    // LÄNDERPUNKTE und LABELS (aus countries[]): Zufluss/Abfluss (I/O) zählt
    // die Kugel selbst aus flows[] — I = Summe count aller Flows mit
    // toCountry === Name, O = Summe count mit fromCountry === Name; die
    // null-seitigen Off-Ramp-Flows (null->Land, Land->null) sind ausdrück-
    // lich ZÄHLDATEN und fließen genau hier ein (definierter Konsument).
    // CUSTODY (Grenze 4): attribution.custodyFlows (Endhop tier 'cold',
    // public/attribution.mjs:497) sind Umbuchungen in Verwahr-/Cold-Wallets,
    // KEINE Off-Ramps — sie werden NICHT in die I/O-Summen gemischt, sondern
    // als eigener Custody-Zähler am Länderpunkt ausgewiesen (definierter
    // Konsument der Hot-Off-Ramp-vs-Cold-Custody-Differenzierung).
    const labels = [];
    if (attribution) {
      const centroidByName = new Map();
      const inflowByCountry = new Map();
      const outflowByCountry = new Map();
      const custodyByCountry = new Map();
      for (const c of attribution.countries) {
        if (isUsableCentroid(c.centroid)) centroidByName.set(c.name, c.centroid);
      }
      for (const f of attribution.flows) {
        if (f.toCountry) inflowByCountry.set(f.toCountry, (inflowByCountry.get(f.toCountry) || 0) + f.count);
        if (f.fromCountry) outflowByCountry.set(f.fromCountry, (outflowByCountry.get(f.fromCountry) || 0) + f.count);
      }
      for (const f of attribution.custodyFlows ?? []) {
        if (f.toCountry) custodyByCountry.set(f.toCountry, (custodyByCountry.get(f.toCountry) || 0) + f.count);
      }
      for (const c of attribution.countries) {
        if (!isUsableCentroid(c.centroid)) continue;
        const color = sevTokenColor(c.worstSeverity);
        if (!color) continue;
        const t = Math.max(0, Math.min(1,
          Math.log10(1 + Math.max(0, c.activity)) / Math.log10(1 + GLOBE_COUNTRY_REF_ACTIVITY)));
        const inflow = inflowByCountry.get(c.name) || 0;
        const outflow = outflowByCountry.get(c.name) || 0;
        const custody = custodyByCountry.get(c.name) || 0;
        const exchanges = c.exchanges.length ? c.exchanges.join(', ') : '–';
        points.push({
          lat: c.centroid[0],
          lng: c.centroid[1],
          color,
          radius: 0.22 + 0.5 * t,
          altitude: 0.02,
          label: `<strong>${esc(c.name)}</strong> · ${c.activity} ${c.activity === 1 ? t('globe.activity1') : t('globe.activityN')} · ${c.severities.malicious} ${sevText('malicious')} · ${t('globe.inflow')}: ${inflow} ${inflow === 1 ? t('globe.edge1') : t('globe.edgeN')} · ${t('globe.outflow')}: ${outflow} ${outflow === 1 ? t('globe.edge1') : t('globe.edgeN')}${custody > 0 ? ` · ${t('globe.custody')}: ${custody} ${custody === 1 ? t('globe.edge1') : t('globe.edgeN')}` : ''} · ${t('globe.exchanges')}: ${esc(exchanges)}`,
          clusterId: null, // bewusst: onPointClick ist für Länderpunkte ein No-op
        });
      }
      // Beschriftung nur der aktivsten Länder (countries[] ist nach activity
      // desc sortiert) — gesetzt im gedämpften Takt der Punkte/Bögen-Anwendung.
      let labelled = 0;
      for (const c of attribution.countries) {
        if (labelled >= GLOBE_COUNTRY_LABELS_MAX) break;
        if (!isUsableCentroid(c.centroid)) continue;
        labels.push({
          lat: c.centroid[0],
          lng: c.centroid[1],
          text: esc(c.name),
          size: 0.5,
          color: cssToken('--a6-ink') || edgeDefault,
          dotRadius: 0.1,
          altitude: 0.01, // knapp über der Polygon-Fläche (0.006)
        });
        labelled += 1;
      }
    }

    // Kanten: nur zwischen verorteten Knoten; deterministisch chronologisch
    // sortiert (binärer Stringvergleich, kein localeCompare), dann die
    // zuletzt GLOBE_MAX_ARCS behalten.
    const cmpStr = (a, b) => (a < b ? -1 : a > b ? 1 : 0);
    const epochOf = (e) => {
      const ms = Date.parse(String(e.closeTime ?? ''));
      return Number.isFinite(ms) ? ms : -1;
    };
    const cmpEdges = (a, b) => {
      const ta = epochOf(a);
      const tb = epochOf(b);
      if (ta !== tb) return ta - tb;
      const la = a.ledgerSeq == null ? -1 : a.ledgerSeq;
      const lb = b.ledgerSeq == null ? -1 : b.ledgerSeq;
      if (la !== lb) return la - lb;
      const f = cmpStr(String(a.from ?? ''), String(b.from ?? ''));
      if (f !== 0) return f;
      return cmpStr(String(a.to ?? ''), String(b.to ?? ''));
    };
    // Per-Edge-Kanten: Positionen centroid-oder-Hash; Kanten, bei denen BEIDE
    // Endpunkte attribuiert-mit-centroid sind, laufen stattdessen im
    // AGGREGIERTEN Land-zu-Land-Bogen (s. u.) — GLOBE_MAX_ARCS-Deckel und
    // chronologische Sortierung gelten unverändert für diesen Per-Edge-Anteil.
    // Die einseitig zugeordneten Off-Ramp-Kanten werden über diesen Pfad
    // sichtbar (Centroid auf der Länder-, Hash-Position auf der offenen Seite).
    const keptEdges = edges
      .filter((e) => {
        const f = String(e.from ?? '');
        const t = String(e.to ?? '');
        return posOf.has(f) && posOf.has(t) && !(centroidPos.has(f) && centroidPos.has(t));
      })
      .sort(cmpEdges)
      .slice(-GLOBE_MAX_ARCS);

    const now = Date.now(); // nur für das Zeitfenster der Puls-Ringe, nie für Positionen
    const ringSources = [];
    const arcs = [];
    for (const e of keptEdges) {
      const from = String(e.from);
      const to = String(e.to);
      const a = posOf.get(from); // centroid-oder-Hash
      const b = posOf.get(to);
      // Farbe exakt EDGE_COLORS/EDGE_DEFAULT (app.js:382-395) — dieselbe
      // Codierung wie Legende und Graph-Tab.
      const color = edgeColors[String(e.type ?? '')] || edgeDefault;
      if (typeof color !== 'string') continue;
      const flagged = (SEV_RANK[sevByNode.get(from)] ?? 1) >= SEV_RANK.malicious
        || (SEV_RANK[sevByNode.get(to)] ?? 1) >= SEV_RANK.malicious;
      arcs.push({
        startLat: a[0],
        startLng: a[1],
        endLat: b[0],
        endLng: b[1],
        color,
        stroke: flagged ? ARC_STROKE_FLAGGED : ARC_STROKE_DEFAULT,
        // Bundle-Shader: mod(relDist, dashLen + dashGap) > dashLen verwirft.
        // dashLen 1 / dashGap 0 ist der Bibliotheks-Default und zeichnet
        // durchgezogen; 0 wäre dagegen fast unsichtbar (Bundle-nachgeprüft).
        dashLen: flagged ? ARC_DASH_LEN_FLAGGED : 1,
        dashGap: flagged ? ARC_DASH_GAP_FLAGGED : 0,
        label: `${esc(displayAddr(from))} → ${esc(displayAddr(to))}`,
      });
      // Puls-Ring-Quellen: Kanten mit closeTime im erweiterten Fenster
      // (RING_WINDOW_MS + Takt-Vorlauf). Die Aggregation (Farbe nach
      // Schweregrad der Endknoten, schlimmer gewinnt; je Knoten ein Ring)
      // macht applyRingsNow im eigenen Takt gegen das AKTUELLE now — so
      // veralten die Ringe nicht, ohne den Punkte/Bögen-Digest zu triggern.
      const ep = epochOf(e);
      if (ep >= now - RING_WINDOW_MS - RING_SOURCE_EXTRA_MS && ep <= now + 60000) {
        ringSources.push(
          { key: a[0] + ',' + a[1], lat: a[0], lng: a[1], sev: String(sevByNode.get(from) ?? 'info'), ep },
          { key: b[0] + ',' + b[1], lat: b[0], lng: b[1], sev: String(sevByNode.get(to) ?? 'info'), ep },
        );
      }
    }

    // AGGREGIERTE Land-zu-Land-Bögen: nur Flows, bei denen BEIDE Seiten über
    // die name->centroid-Map aus countries[] auflösbar sind; null-seitige
    // Flows (null->Land, Land->null) sind per Definition nicht bogenfähig
    // (die null-Seite hat keinen Centroid) — ihre Kanten laufen oben im
    // Per-Edge-Pfad, ihre counts als Zufluss/Abfluss in den Länderpunkt-
    // Labels. Konstanten nicht mischen: 1.6 ist Strichstärke (Stroke),
    // 0.45/0.25 sind Strichlänge/-lücke (Dash) — Dash nur bei malicious.
    if (attribution) {
      const centroidByName = new Map();
      for (const c of attribution.countries) {
        if (isUsableCentroid(c.centroid)) centroidByName.set(c.name, c.centroid);
      }
      for (const f of attribution.flows) {
        if (f.fromCountry === null || f.toCountry === null) continue;
        const a = centroidByName.get(f.fromCountry);
        const b = centroidByName.get(f.toCountry);
        if (!a || !b) continue;
        // start==end: kein Bogen. Seit der Intra-Land-Ausschluss in
        // aggregateCountryFlows (attribution.mjs, Befund 2026-09-30) kann
        // dieser Fall aus flows[] nicht mehr eintreten — der Guard bleibt
        // als defensive Prüfung bestehen.
        if (a[0] === b[0] && a[1] === b[1]) continue;
        const color = sevTokenColor(f.worstSeverity);
        if (!color) continue;
        const t = Math.max(0, Math.min(1, (f.count - 1) / (GLOBE_ARC_FLOW_REF_COUNT - 1)));
        arcs.push({
          startLat: a[0],
          startLng: a[1],
          endLat: b[0],
          endLng: b[1],
          color,
          stroke: ARC_STROKE_DEFAULT + (ARC_STROKE_FLAGGED - ARC_STROKE_DEFAULT) * t,
          dashLen: f.worstSeverity === 'malicious' ? ARC_DASH_LEN_FLAGGED : 1,
          dashGap: f.worstSeverity === 'malicious' ? ARC_DASH_GAP_FLAGGED : 0,
          label: `${esc(f.fromCountry)} → ${esc(f.toCountry)}: ${f.count} ${f.count === 1 ? t('globe.tx1') : t('globe.txN')} · ${sevText(f.worstSeverity)} · ${t('globe.exchanges')}: ${esc(f.exchanges.length ? f.exchanges.join(', ') : '–')}`,
        });
      }
    }

    // LEGENDEN-ZÄHLER (OPERATIONELL definiert): Anzahl sichtbarer Nodes, für
    // die assignedByAddress KEIN Eintrag mit nutzbarem Centroid (Array der
    // Länge 2 mit endlichen Zahlen) vorliegt — umfasst Unzugeordnete,
    // noPolygon-Treffer UND matchCountry-Treffer mit degeneriertem centroid:
    // null; keine Summenformel. Ohne Attribution wäre jeder Node unzugeordnet
    // (show:false blendet die Legende dann aus, der Wert bleibt ehrlich).
    let unassignedCount = visibleNodes.length;
    if (attribution) {
      unassignedCount = 0;
      for (const n of visibleNodes) {
        const info = attribution.assignedByAddress.get(String(n.id ?? ''));
        if (!(info && isUsableCentroid(info.centroid))) unassignedCount += 1;
      }
    }
    const legend = { show: countryData.state === 'ready', unassigned: unassignedCount };

    return {
      points,
      arcs,
      labels,
      legend,
      ringSources,
      // Signaturen (SEKUNDÄR-Skip, s. Konstantenblock): umfassen die visuell
      // kodierenden Felder, sortiert — reine Umordnungen zählen nicht als
      // Änderung; Labels hinzugefügt, damit reine Label-Änderungen (u. a.
      // displayAddr-Voll-/Kurzform) höchstens um den Deckel veralten. Länder-
      // punkte laufen über pointsSig (gleichen Felder), Fluss-Bögen über
      // arcsSig, Länder-Beschriftungen und Legende über ihre eigenen Sigs.
      pointsSig: sigOfPoints(points),
      arcsSig: sigOfArcs(arcs),
      clusterSetSig: sigOfClusterSet(points),
      labelsSig: sigOfLabels(labels),
      legendSig: JSON.stringify(legend),
    };
  }

  /* ---------------- Anwenden / Dämpfung / Ringe / refresh (FIX-B) ---------------- */

  // Signatur-Helfer: JSON.stringify je Element (exakte Zahlendarstellung),
  // dann sortiert — inhaltlich gleiche Datensätze in anderer Reihenfolge
  // erzeugen dieselbe Signatur (kein Neustart durch reine Umordnung).
  function sigOfPoints(points) {
    return points
      .map((p) => JSON.stringify([p.lat, p.lng, p.color, p.radius, p.altitude, p.label]))
      .sort()
      .join('\n');
  }

  function sigOfArcs(arcs) {
    return arcs
      .map((a) => JSON.stringify([a.startLat, a.startLng, a.endLat, a.endLng, a.color, a.stroke, a.dashLen, a.dashGap, a.label]))
      .sort()
      .join('\n');
  }

  function sigOfClusterSet(points) {
    const ids = new Set();
    for (const p of points) ids.add(p.clusterId == null ? '\u0000' : String(p.clusterId));
    return Array.from(ids).sort().join('\n');
  }

  // Signatur der Länder-Beschriftungen (gleiches Muster wie Punkte/Bögen):
  // Ländernamen sind englisch und unverändert; reine Umordnungen zählen nicht.
  function sigOfLabels(labels) {
    return labels
      .map((l) => JSON.stringify([l.lat, l.lng, l.text, l.size, l.color, l.dotRadius, l.altitude]))
      .sort()
      .join('\n');
  }

  function clearApplyTimer() {
    if (applyTimer) { clearTimeout(applyTimer); applyTimer = 0; }
  }

  function stopRingTimer() {
    if (ringTimer) { clearInterval(ringTimer); ringTimer = 0; }
  }

  // Vollständige Anwendung von Punkten, Bögen und Länder-Beschriftungen —
  // JEDER dieser Setter baut bei globe.gl die komplette Szene neu auf
  // (sichtbarer „Reload”), deshalb nur unter dem Deckel bzw. über die
  // definierten Ausnahmen. Die Legende (DOM-Overlay) läuft im selben Takt.
  function applyPointsArcs(ds) {
    if (!buildDone || !globe) return false;
    try {
      globe.pointsData(ds.points).arcsData(ds.arcs).labelsData(ds.labels);
    } catch { /* Renderer-Fehler: alter Stand bleibt, kein Crash */ return false; }
    lastApplyAt = Date.now();
    lastPointsSig = ds.pointsSig;
    lastArcsSig = ds.arcsSig;
    lastClusterSetSig = ds.clusterSetSig;
    lastLabelsSig = ds.labelsSig;
    lastLegendSig = ds.legendSig;
    syncLegend(ds.legend);
    hasAppliedData = true;
    // Reduced Motion: keine animierte Kamera, statische Bildfassung
    // (zoomToFit(0), Muster drilldown.js:565-574) — wie bisher je Anwendung.
    if (reducedMotion() && ds.points.length) {
      try { globe.zoomToFit(0); } catch { /* egal */ }
    }
    return true;
  }

  // Puls-Ringe gegen das AKTUELLE now (die Quellen stammen aus buildDatasets
  // mit erweitertem Fenster): schlimmster Schweregrad je Knoten gewinnt,
  // Farbe über sevTokenColor — Aggregation wie zuvor, nur zeitfrisch.
  function computeRings(now) {
    const sevByKey = new Map();
    for (const r of ringSources) {
      if (r.ep < now - RING_WINDOW_MS || r.ep > now + 60000) continue;
      const cur = sevByKey.get(r.key);
      if (!cur || (SEV_RANK[r.sev] ?? 1) > (SEV_RANK[cur.sev] ?? 1)) sevByKey.set(r.key, r);
    }
    const rings = [];
    for (const r of sevByKey.values()) {
      const color = sevTokenColor(r.sev);
      if (color) rings.push({ lat: r.lat, lng: r.lng, color });
    }
    return rings;
  }

  function applyRingsNow() {
    if (!buildDone || !globe) return;
    const rings = reducedMotion() ? [] : computeRings(Date.now());
    const sig = rings.map((r) => JSON.stringify([r.lat, r.lng, r.color])).join('\n');
    if (sig === lastRingsSig) return; // unverändert: kein Setter, kein Neuaufbau
    lastRingsSig = sig;
    try { globe.ringsData(rings); } catch { /* egal */ }
  }

  function shallRun() {
    return wantActive && ioVisible && !document.hidden && buildDone && Boolean(globe)
      && !buildFailed && !ctxLost;
  }

  // Zentrale Animationsschaltung: die Renderloop läuft nur, wenn Tab UND
  // Container sichtbar sind (wantActive aus activate/deactivate des Hosts,
  // ioVisible aus dem IntersectionObserver). Idempotent — die bedingte
  // Tab-Pause des Hosts und die Selbst-Pause koordinieren sich schadfrei.
  function syncAnimation() {
    if (buildFailed) { stopRingTimer(); return; }
    if (!buildDone || !globe) return;
    const run = shallRun();
    try { run ? globe.resumeAnimation() : globe.pauseAnimation(); } catch { /* egal */ }
    if (run) {
      if (!ringTimer) {
        // Eigener Ring-Takt (≤ RINGS_TICK_MS): zeitfensterige Ringe bleiben
        // frisch, ohne den Punkte/Bögen-Digest oder deren Deckel zu berühren.
        ringTimer = setInterval(() => {
          if (!shallRun()) { stopRingTimer(); return; }
          applyRingsNow();
        }, RINGS_TICK_MS);
      }
    } else {
      stopRingTimer();
    }
  }

  // Kern der Dämpfung: entscheidet über die Anwendung des neuesten Datensatzes.
  // force = true nur nach (Neu-)Aufbau der Szene — diese ist dann leer, eine
  // sofortige Anwendung kostet keinen sichtbaren Neustart.
  function maybeApplyNow(force) {
    if (!buildDone || !globe) return; // latestDs bleibt als Puffer erhalten
    const ds = latestDs;
    if (!ds) return;
    const first = !hasAppliedData;
    // AUSNAHMEN ohne Deckel: Erstdaten, Wechsel des clusterId-Sets der Punkte
    // (neuer Cluster erschienen/verschwunden — globe-seitig berechenbar) bzw.
    // erzwungene Anwendung nach Konstruktion.
    if (force || first || ds.clusterSetSig !== lastClusterSetSig) {
      clearApplyTimer();
      applyPointsArcs(ds);
      applyRingsNow();
      return;
    }
    // SEKUNDÄR: inhaltlich unverändert — keine Anwendung, kein nachlaufender
    // Timer (0 Anwendungen trotz refresh-Aufrufen bei Cache-Treffern). Die
    // Bedingung umfasst auch Länder-Beschriftungen und Legende (neue Felder
    // des Länder-Layers) — Helfer unverändert, nur zusätzliche Prüfung.
    if (ds.pointsSig === lastPointsSig && ds.arcsSig === lastArcsSig
      && ds.labelsSig === lastLabelsSig && ds.legendSig === lastLegendSig) {
      clearApplyTimer();
      return;
    }
    // PRIMÄR: Anwendetakt-Deckel — Änderungen werden spätestens zum
    // Fensterende angewandt, auch wenn kein weiteres refresh() mehr kommt.
    const dueAt = lastApplyAt + APPLY_MIN_INTERVAL_MS;
    if (Date.now() >= dueAt) {
      clearApplyTimer();
      applyPointsArcs(ds);
      applyRingsNow();
    } else if (!applyTimer) {
      applyTimer = setTimeout(() => {
        applyTimer = 0;
        maybeApplyNow(false);
      }, Math.max(0, dueAt - Date.now()));
    }
  }

  function offerData(ds, force) {
    latestDs = ds;
    ringSources = Array.isArray(ds.ringSources) ? ds.ringSources : [];
    maybeApplyNow(Boolean(force));
  }

  /* Sichtbarkeit ohne Host-Beteiligung: IntersectionObserver auf den
   * #globe-Container (View-Wechsel und Rauscrollen erkennen) plus
   * visibilitychange am Dokument (Tab in den Hintergrund). Unsichtbar →
   * pauseAnimation; wieder sichtbar → resumeAnimation plus GENAU EIN
   * refresh. resume feuert nur bei nachweislich sichtbarem Container. */
  function onVisibilityChanged() {
    if (buildFailed) return;
    if (ioVisible && !document.hidden && wantActive) {
      syncAnimation(); // resume, sofern konstruiert
      refresh();       // GENAU EIN Daten-Refresh pro Sichtbarkeits-Wechsel
    } else {
      syncAnimation(); // pause + Ring-Takt stoppen
    }
  }

  function watchVisibility(el) {
    if (typeof IntersectionObserver === 'function') {
      if (!io) {
        io = new IntersectionObserver((entries) => {
          let visible = null;
          for (const en of entries) visible = en.isIntersecting; // letzter Eintrag zählt
          if (visible === null || visible === ioVisible) return;
          ioVisible = visible;
          onVisibilityChanged();
        });
        try {
          io.observe(el);
        } catch {
          ioVisible = true; // Beobachtung fehlgeschlagen: sichtbar annehmen
        }
      }
    } else if (!io) {
      ioVisible = true; // ohne IntersectionObserver: Sichtbarkeit über wantActive/hidden allein
    }
    if (!visBound) {
      visBound = true;
      document.addEventListener('visibilitychange', onVisibilityChanged);
    }
  }

  /* WebGL-Kontextverlust (Symptom 2b-Mitverursacher): klarer Hinweis statt
   * schwarzem Stand, GENAU EIN Restaurationsversuch als vollständiger
   * Neuaufbau — ausgelöst durch webglcontextrestored oder, bleibt das
   * Ereignis aus, nach kurzer Frist. Ein zweiter Verlust führt in den
   * Terminalzustand wie showFallback; kein Retry-Loop. */
  function onContextLost(ev) {
    try { ev.preventDefault(); } catch { /* egal */ } // erlaubt dem Browser die Restaurierung
    if (ctxLost || buildFailed || !globe) return;
    ctxLost = true;
    if (ctxRestoreTried) { terminalContextLoss(); return; } // Budget verbraucht
    syncAnimation(); // pausiert (ctxLost) und stoppt den Ring-Takt
    if (container) showNote(container, t(GLOBE_CTX_LOST_NOTE), true);
    if (ctxRestoreTimer) clearTimeout(ctxRestoreTimer);
    ctxRestoreTimer = setTimeout(() => {
      ctxRestoreTimer = 0;
      attemptContextRestore();
    }, CTX_RESTORE_GRACE_MS);
  }

  function onContextRestored() {
    if (!ctxLost || ctxRestoreTried || buildFailed) return;
    if (ctxRestoreTimer) { clearTimeout(ctxRestoreTimer); ctxRestoreTimer = 0; }
    attemptContextRestore();
  }

  function attemptContextRestore() {
    if (!ctxLost || ctxRestoreTried || buildFailed) return;
    ctxRestoreTried = true; // einmalig pro Seitenleben — kein Retry-Loop
    ctxLost = false;
    rebuildGlobe();
  }

  function terminalContextLoss() {
    buildFailed = true;
    buildDone = false;
    stopRingTimer();
    clearApplyTimer();
    if (ctxRestoreTimer) { clearTimeout(ctxRestoreTimer); ctxRestoreTimer = 0; }
    try { if (globe) globe.pauseAnimation(); } catch { /* egal */ }
    globe = null;
    controls = null;
    if (resizeObs) {
      try { resizeObs.disconnect(); } catch { /* egal */ }
      resizeObs = null;
    }
    const el = container || document.getElementById('globe');
    if (el) showFallback(el);
  }

  // Der EINE Neuaufbau nach Kontextverlust: alte Instanz wegwerfen (deren
  // GPU-Ressourcen hat der Browser bereits freigegeben — innerHTML'' genügt,
  // auf undokumentierte Destruktoren wird bewusst verzichtet), dann den
  // gemeinsamen Konstruktions-Rumpf mit dem gepufferten Datensatz neu laufen
  // lassen. Misslingt er: Terminalzustand (showFallback).
  async function rebuildGlobe() {
    const el = container || document.getElementById('globe');
    stopRingTimer();
    clearApplyTimer();
    if (resizeObs) {
      try { resizeObs.disconnect(); } catch { /* egal */ }
      resizeObs = null;
    }
    globe = null;
    controls = null;
    buildDone = false;
    if (el) {
      try { el.innerHTML = ''; } catch { /* egal */ }
      noteEl = null;
      showNote(el, t('globe.rebuild'));
    }
    try {
      if (!el) throw new Error('no-container');
      await buildGlobe(el);
    } catch {
      globe = null;
      container = null;
      controls = null;
      buildDone = false;
      buildFailed = true;
      if (resizeObs) {
        try { resizeObs.disconnect(); } catch { /* egal */ }
        resizeObs = null;
      }
      if (el) showFallback(el);
    }
  }

  function bindContextEvents(el) {
    try {
      const canvas = el.querySelector('canvas');
      if (!canvas) return;
      // Capture-Phase: das Ereignis targetet den Canvas selbst; capture
      // wertet es aus, bevor etwaige Bibliotheks-Listener reagieren.
      canvas.addEventListener('webglcontextlost', onContextLost, true);
      canvas.addEventListener('webglcontextrestored', onContextRestored, true);
    } catch { /* egal */ }
  }

  // force=true erzwingt die sofortige Anwendung des frischen Datensatzes
  // (Ausnahme vom Deckel, siehe Konstantenblock): Der Host nutzt es nach
  // erkannter Bait-Hash-Rotation, damit der aktualisierte Deny-Ausschluss
  // und die Anzeige-Stände ohne Deckel-Verzögerung greifen (Befund 2026-09-30).
  function refresh(force) {
    if (buildFailed) return;
    // Vor dem ersten activate() passiv: Der Konstruktions-Abschluss zieht
    // selbst frische Daten (kein Verlust, da getClusterGraph live ist).
    if (!buildStarted && !buildDone) return;
    const seq = ++refreshSeq;
    const applyForce = Boolean(force);
    buildDatasets()
      .then((ds) => {
        if (seq !== refreshSeq) return; // veraltet: neuere Anfrage läuft
        offerData(ds, applyForce); // PUFFERN (latestDs); force DÄMPFUNG umgeht offerData/maybeApplyNow
      })
      .catch(() => { /* Datenaufbau gescheitert: alter Stand bleibt, kein Crash */ });
  }

  /* ---------------- Konstruktion / Lebenszyklus ---------------- */

  async function construct() {
    const el = document.getElementById('globe');
    if (!el) return; // Null-Guard: kein #globe im DOM -> initGlobe bleibt passiv
    buildStarted = true;
    showNote(el, t('globe.loading'));
    // Länder-Layer parallel zur Kugel laden (Lazy beim ersten activate(),
    // fire-and-forget, fail-soft über die Drei-Zustands-Maschine).
    ensureCountryData();
    try {
      await buildGlobe(el);
    } catch {
      globe = null;
      container = null;
      controls = null;
      buildDone = false;
      buildFailed = true;
      stopRingTimer();
      clearApplyTimer();
      if (resizeObs) {
        try { resizeObs.disconnect(); } catch { /* egal */ }
        resizeObs = null;
      }
      showFallback(el);
    }
  }

  // Gemeinsamer Konstruktions-Rumpf für den Erstbau (construct) und den EINEN
  // Neuaufbau nach WebGL-Kontextverlust (rebuildGlobe). Wirft bei WebGL-/CDN-/
  // Konstruktionsfehlern — die Aufrufer zeigen showFallback.
  async function buildGlobe(el) {
    countryLayerApplied = false; // Instanz-Flag zurücksetzen: NEUE Instanz, Polygone noch nicht gesetzt
    const strokeColor = resolveStrokeColor(); // einmal je Instanz (getComputedStyle ist teuer)
    if (!webglAvailable()) throw new Error('webgl');
      const loaded = await loadGlobeGl();
      if (!loaded || typeof window.Globe !== 'function') throw new Error('cdn');
      const g = window.Globe({ animateIn: !reducedMotion() })(el);

      // Hintergrund transparent statt Bundle-Default #000011 (opak): Der
      // Alpha-Weg ist im Bundle verifiziert (setClearColor mit geparstem
      // Alpha), die weiße Punkt-Bühne von #globe scheint durch.
      g.backgroundColor('rgba(0, 0, 0, 0)');
      // KUGEL-MATERIAL auf Bühnen-Weiß (Befund 2026-09-30): Der Bundle-Default
      // ist ein opak schwarzes Phong-Material (new THREE.MeshPhongMaterial
      // ({color:0}), am gepinnten Bundle nachgeprüft) — die transparente Szene
      // allein ließ die Kugel-Silhouette dunkel auf der weißen Bühne rendern.
      // globeMaterial() (Bundle-Getter auf globeObj.material) liefert das
      // Material; seine Farbe wird aus dem bestehenden Token --a6-graph-canvas
      // (style.css:37, #ffffff) gelesen, damit der Astra-6-Weiß-Standard auch
      // im Silhouetten-Bereich gilt und kein zweites Farbsystem entsteht.
      // Fail-closed: Ungültiges/fehlendes Token oder fehlende Material-API
      // lässt den Bundle-Default unverändert — Punkte/Bögen/Ringe laufen
      // unabhängig davon.
      try {
        const tokenSurface = cssToken('--a6-graph-canvas');
        const surface = /^#([0-9a-f]{3}|[0-9a-f]{6})$/i.test(String(tokenSurface ?? '')) ? tokenSurface : '#ffffff';
        const mat = g.globeMaterial();
        if (mat && mat.color && typeof mat.color.set === 'function') mat.color.set(surface);
      } catch { /* Material-API fehlt: Bundle-Default bleibt, kein Crash */ }
      // DESIGN-ABWEICHUNG, bewusst akzeptiert (Prüfer-Fund 2026-09-29): Die
      // Graticule-Farbe ist im Bundle-LineBasicMaterial hardcoded
      // ('lightgrey', transparent, Opazität 0.1); eine Farb-API für
      // Graticules existiert nicht (0 Treffer im Bundle) und CSS-Tokens
      // können WebGL-Linien nicht färben. Der Bundle-Default wird übernommen;
      // ein Material-Patch über die three-szene wäre nicht API-stabil.
      g.showGraticules(true);
      const atmosphere = resolveAtmosphereColor();
      if (atmosphere) g.atmosphereColor(atmosphere);
      if (!reducedMotion()) g.arcDashAnimateTime(ARC_DASH_ANIMATE_MS);

      g.pointLat((d) => d.lat)
        .pointLng((d) => d.lng)
        .pointColor((d) => d.color)
        .pointRadius((d) => d.radius)
        .pointAltitude((d) => d.altitude)
        .pointLabel((d) => d.label)
        .onPointClick((d) => {
          const cid = d && d.clusterId ? String(d.clusterId) : '';
          if (!cid || !openCluster) return;
          // FIX-B Klick-Zeit-Validierung: Die Punktdaten stammen aus dem
          // zuletzt ANGEWANDTEN Satz; ist der Cluster inzwischen aus dem
          // Graph gefallen (rollendes Fenster, instabile Cluster-id), wird
          // der Klick ignoriert, statt das Modal in den Leerezustand zu
          // öffnen.
          let cg = null;
          try { cg = ctx.getClusterGraph(); } catch { cg = null; }
          const clusters = cg && Array.isArray(cg.clusters) ? cg.clusters : null;
          if (!clusters || !clusters.some((c) => c && String(c.id) === cid)) return;
          openCluster(cid);
        })
        .pointsData([])
        .arcStartLat((d) => d.startLat)
        .arcStartLng((d) => d.startLng)
        .arcEndLat((d) => d.endLat)
        .arcEndLng((d) => d.endLng)
        .arcColor((d) => d.color)
        .arcStroke((d) => d.stroke)
        .arcDashLength((d) => d.dashLen)
        .arcDashGap((d) => d.dashGap)
        .arcAltitudeAutoScale(0.4)
        .arcLabel((d) => d.label)
        .arcsData([])
        .ringLat((d) => d.lat)
        .ringLng((d) => d.lng)
        .ringColor((d) => d.color)
        .ringMaxRadius(RING_MAX_RADIUS_DEG)
        .ringPropagationSpeed(RING_PROPAGATION_SPEED)
        .ringRepeatPeriod(RING_REPEAT_MS)
        .ringsData([])
        // LÄNDER-LAYER (Attribution): Accessor-Verdrahtung PRO INSTANZ hier in
        // buildGlobe — rebuildGlobe() erzeugt eine NEUE Instanz und leert den
        // Container (el.innerHTML=''), außerhalb gesetzte Layer wären danach
        // weg (Detach-Problem wie noteEl). Die Polygon-DATEN setzt die
        // idempotente applyCountryLayer() (Instanz-Flag, Reset oben) am Ende
        // dieser Funktion bzw. aus der Fetch-Fortsetzung; onPolygonClick/
        // onPolygonHover werden bewusst NICHT verwendet — der Hover-Tooltip
        // entsteht allein durch polygonLabel (immer-wahrer englischer Name).
        // WICHTIG (Bundle-Fund 2026-09-30, live am gepinnten globe.gl@2.46.2
        // verifiziert): Konstante STRING-/Zahl-Werte sind für die Polygon-
        // Accessors WIRKUNGSLOS — der Accessor-Aufruf liefert dann undefined,
        // die Grenzlinien bleiben unsichtbares Bundle-Weiß (visible=false).
        // Alle konstanten Werte stehen deshalb als FUNKTIONEN (Muster der
        // offiziellen globe.gl-Polygon-Beispiele).
        .polygonsData([])
        .polygonCapColor(() => GLOBE_POLYGON_FILL)
        .polygonSideColor(() => GLOBE_POLYGON_FILL)
        .polygonStrokeColor(() => strokeColor)
        .polygonAltitude(() => GLOBE_POLYGON_ALTITUDE)
        .polygonLabel((f) => esc(f && f.properties ? f.properties.name : ''))
        // AKTIVE LÄNDER: labelsData hier initialisieren (leer), im Anwendungs-
        // pfad (applyPointsArcs, gedämpfter Takt) neu gesetzt — so überlebt
        // der gesamte Länder-Layer den einen WebGL-Kontext-Restore.
        .labelsData([])
        .labelLat((d) => d.lat)
        .labelLng((d) => d.lng)
        .labelText((d) => d.text)
        .labelSize((d) => d.size)
        .labelColor((d) => d.color)
        .labelDotRadius((d) => d.dotRadius)
        .labelAltitude((d) => d.altitude)
        .labelResolution(2);

      // Start-Perspektive ohne ms-Argument: sofort, keine Kamerafahrt.
      g.pointOfView(POV_START);

      try {
        const c = g.controls();
        controls = c;
        c.autoRotateSpeed = AUTO_ROTATE_SPEED;
        // Stop beim ersten pointerdown bzw. jeder Interaktion ('start'-Event
        // der OrbitControls): autoRotate bleibt danach dauerhaft aus.
        c.addEventListener('start', () => {
          userGrabbed = true;
          syncAutoRotate();
        });
        syncAutoRotate(); // nur ohne prefers-reduced-motion
      } catch { controls = null; /* Kugel läuft ohne Auto-Rotation weiter */ }

      container = el;
      globe = g;
      sizeToContainer();
      if (typeof ResizeObserver === 'function') {
        resizeObs = new ResizeObserver(sizeToContainer);
        resizeObs.observe(el);
      }
      buildDone = true;
      // Länder-Layer anwenden, falls die Daten schon bereit sind (Reihenfolge
      // vor der Notiz, damit der Hinweis den tatsächlichen Zustand trifft);
      // sonst zieht die Fetch-Fortsetzung (ensureCountryData) ihn nach.
      applyCountryLayer();
      showNote(el, t(countryLayerActive() ? GLOBE_NOTE_COUNTRIES : GLOBE_NOTE));
      syncGlobeAria(); // aria-label an den tatsächlichen Layer-Zustand koppeln
      // FIX-B: Kontextverlust-Ereignisse am Canvas (Capture-Phase) und
      // Sichtbarkeitsbeobachtung (IntersectionObserver + visibilitychange).
      bindContextEvents(el);
      watchVisibility(el);
      // Animation nur bei aktivem UND nachweislich sichtbarem Zustand — die
      // bisherige !wantActive-Bedingung ist darin enthalten.
      syncAnimation();
      if (latestDs) {
        // Szene ist leer (Erstbau oder Neuaufbau nach Kontextverlust):
        // sofortige Anwendung; der Deckel regelt erst danach.
        offerData(latestDs, true);
      } else {
        refresh();
      }
  }

  function activate() {
    wantActive = true;
    if (buildFailed) return;
    if (buildStarted) {
      // resume nur bei konstruierter UND sichtbarer Kugel (syncAnimation
      // prüft wantActive/ioVisible/document.hidden intern); autoRotate wird
      // wie bisher bei jedem activate nachgezogen.
      syncAnimation();
      if (buildDone && globe) syncAutoRotate();
      return;
    }
    construct();
  }

  function deactivate() {
    wantActive = false;
    // pausiert nur bei konstruierter Kugel (interne Guards) und stoppt den
    // Ring-Takt — idempotent zur Sichtbarkeits-Selbstpause des Observers.
    syncAnimation();
  }

  return { activate, deactivate, refresh };
}
