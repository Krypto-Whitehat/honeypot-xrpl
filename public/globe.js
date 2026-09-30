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
 * sind deterministisch aus der Adresse abgeleitet (SHA-256 über ctx.hashOf;
 * der Cache wird vom Host via primeAddrHashes gefüllt) — kein Math.random
 * und kein Date.now für Positionen. KEIN globeImageUrl, KEINE Länder-Polygone;
 * stattdessen showGraticules(true) als neutrales Liniennetz. Die Kugel-
 * OBERFLÄCHE selbst wird über globeMaterial() auf die Token-Farbe der Bühne
 * (--a6-graph-canvas, Weiß) gesetzt — der Bundle-Default wäre opak schwarz
 * (Befund 2026-09-30).
 *
 * Der zugehörige Tab-Button #tab-globe, der Container #globe und der
 * dynamische Import kommen vom Verdrahtungs-Agenten (app.js/index.html).
 * Dieses Modul ist auch allein lauffähig: Ohne #globe im DOM bleibt
 * initGlobe passiv (Null-Guard).
 */

const GLOBE_GL_URL = 'https://unpkg.com/globe.gl@2.46.2/dist/globe.gl.min.js';
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
const GLOBE_NOTE = 'Positionen sind deterministisch aus der Adresse abgeleitet (Hash) — das XRPL-Ledger enthält keine Standortdaten. Die Kugel ist eine symbolische Aktivitätsansicht, keine geografische Zuordnung.';
const GLOBE_CTX_LOST_NOTE = 'WebGL-Grafikkontext verloren — genau ein Wiederherstellungsversuch wird gestartet …';

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
const GLOBE_FALLBACK_NOTE = 'Weltkugel nicht verfügbar (WebGL oder CDN nicht erreichbar) — dieselben Daten stehen in den Cluster-Karten und in der Konten-Tabelle des Drilldowns.';

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
      s.async = true;
      s.onload = () => resolve(typeof window.Globe === 'function');
      s.onerror = () => resolve(false);
      document.head.appendChild(s);
    });
    return scriptPromise;
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
      p.textContent = GLOBE_FALLBACK_NOTE;
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

    const sevByNode = new Map();
    const points = [];
    for (const n of visibleNodes) {
      const id = String(n.id ?? '');
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
      sevByNode.set(id, String(n.severity ?? 'info'));
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
    const keptEdges = edges
      .filter((e) => coords.has(String(e.from ?? '')) && coords.has(String(e.to ?? '')))
      .sort(cmpEdges)
      .slice(-GLOBE_MAX_ARCS);

    const now = Date.now(); // nur für das Zeitfenster der Puls-Ringe, nie für Positionen
    const ringSources = [];
    const arcs = [];
    for (const e of keptEdges) {
      const from = String(e.from);
      const to = String(e.to);
      const a = coords.get(from);
      const b = coords.get(to);
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

    return {
      points,
      arcs,
      ringSources,
      // Signaturen (SEKUNDÄR-Skip, s. Konstantenblock): umfassen die visuell
      // kodierenden Felder, sortiert — reine Umordnungen zählen nicht als
      // Änderung; Labels hinzugefügt, damit reine Label-Änderungen (u. a.
      // displayAddr-Voll-/Kurzform) höchstens um den Deckel veralten.
      pointsSig: sigOfPoints(points),
      arcsSig: sigOfArcs(arcs),
      clusterSetSig: sigOfClusterSet(points),
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

  function clearApplyTimer() {
    if (applyTimer) { clearTimeout(applyTimer); applyTimer = 0; }
  }

  function stopRingTimer() {
    if (ringTimer) { clearInterval(ringTimer); ringTimer = 0; }
  }

  // Vollständige Anwendung von Punkten und Bögen — JEDER dieser Setter baut
  // bei globe.gl die komplette Szene neu auf (sichtbarer „Reload“), deshalb
  // nur unter dem Deckel bzw. über die definierten Ausnahmen.
  function applyPointsArcs(ds) {
    if (!buildDone || !globe) return false;
    try {
      globe.pointsData(ds.points).arcsData(ds.arcs);
    } catch { /* Renderer-Fehler: alter Stand bleibt, kein Crash */ return false; }
    lastApplyAt = Date.now();
    lastPointsSig = ds.pointsSig;
    lastArcsSig = ds.arcsSig;
    lastClusterSetSig = ds.clusterSetSig;
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
    // Timer (0 Anwendungen trotz refresh-Aufrufen bei Cache-Treffern).
    if (ds.pointsSig === lastPointsSig && ds.arcsSig === lastArcsSig) {
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
    if (container) showNote(container, GLOBE_CTX_LOST_NOTE, true);
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
      showNote(el, 'Weltkugel wird neu aufgebaut …');
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
    showNote(el, 'Weltkugel wird geladen …');
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
        .ringsData([]);

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
      showNote(el, GLOBE_NOTE);
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
