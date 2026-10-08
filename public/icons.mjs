'use strict';
/* public/icons.mjs — Unikat-SVG-Sprache für Leerzustände, Panel-Signet und
 * Diagramm-Marker (Design P0, 2026-10-06).
 *
 * STILVERTRAG (im Test icons.test.mjs erzwungen):
 *  - Illustrationen auf 160×120-Grid, Icons auf 24×24-Grid; viewBox exakt.
 *  - fill="none", stroke="currentColor", stroke-width 1.1, linecap/linejoin
 *    "round" auf dem Wurzel-<svg> — Kinder erben; Theme-Treue über
 *    currentColor (Leerzustand: var(--a6-control-line) via .empty-illu).
 *  - Koordinaten auf 0.5-px-Raster (Strichgravur, scharf auf HiDPI);
 *    verdeckte Kanten über stroke-opacity 0.55; außer genau EINEM
 *    Akzent-Element (class="icon-accent", Farbe via CSS-Token
 *    --a6-icon-accent) keine Flächen-Fills.
 *  - Security-präzise statt Klischee: Fadenkreuz-Marker, Hash-Rauten,
 *    Rastlinien — kein gefülltes Schild, keine Emoji-Ersatz-Bildsprache.
 *
 * EIGENLEISTUNG statt Stock-SVG (Plan-Kritik 7d): alle Formen sind für diese
 * Stelle gezeichnete Gravuren im lab_graphite-Duktus (weiße Fläche, Ink-Linie,
 * ein Akzent) — bewusst kleine, strenge Strichzeichnungen, keine gefüllten
 * Illustrations-Flächen (Anti-Slop: „SVG-imagery as substitute for real
 * assets" ist kein Ersatz für Inhalte, nur Rahmung der Leerzustände).
 *
 * UNIKAT-REGEL (harte Vorgabe): jeder Export hat GENAU EINE Rolle (Kommentar
 * „// Rolle: …" direkt über der Funktion); dasselbe SVG wird nie in zwei
 * Rollen verwendet. Das Marken-Logo (.brand-mark, inline in index.html und
 * history-host.html) und das Favicon (favicon.svg) sind KEINE Bestandteile
 * dieses Moduls und teilen mit keiner Rolle Forminhalte (Hash-Test).
 * Die Chart-Flächen selbst (app.js renderWindowChart, drilldown.js
 * Zeitachse, history-host.html renderFlowGraph) bleiben unangetastete
 * Daten-SVGs — nur chartMarkerFlagged darf als Marker IN einem Chart sitzen.
 *
 * MODUL-VERTRAG (Muster cluster-chips.mjs:1-27): DOM-frei beim Import, kein
 * fetch, kein window/document — einzig mountEmptyIllu() greift guarded aufs
 * DOM zu und ist im Node-Test ohne Dokument eine No-op. */
const SVG_ATTRS = 'fill="none" stroke="currentColor" stroke-width="1.1" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"';

const illu = (inner) => `<svg viewBox="0 0 160 120" ${SVG_ATTRS}>${inner}</svg>`;
const icon = (inner, extra = '') => `<svg ${extra} viewBox="0 0 24 24" ${SVG_ATTRS}>${inner}</svg>`;

// Rolle: Leerzustand Live-Block-Feed (#feed-empty, index.html) — isometrische
// Block-Säule des Ledger (zwei gestapelte Quader, verdeckte Kanten 0.55) mit
// Scan-Lupe; der EINE Akzent ist die Scan-Linie über dem Stapel.
export function svgEmptyFeed() {
  return illu([
    /* unterer Quader: Deck-Raute + sichtbare Stirn-, Boden-Vorderkante */
    '<path d="M36,82 L68,64 L100,82 L68,100 Z" />',
    '<path d="M100,82 V96 L68,114 M68,100 V114" />',
    /* verdeckte hintere Bodenkanten des unteren Quaders */
    '<path d="M68,64 V78 M68,78 L36,96 M68,78 L100,96" stroke-width="1" stroke-opacity="0.55" />',
    /* oberer Quader: sitzt auf der Deck-Raute des unteren */
    '<path d="M36,66 L68,48 L100,66 L68,86 Z" />',
    '<path d="M100,82 V66 M68,100 V86" />',
    '<path d="M68,64 V48" stroke-width="1" stroke-opacity="0.55" />',
    /* Scan-Lupe über dem Stapel */
    '<circle cx="122" cy="34" r="13" />',
    '<path d="M131.5,43.5 L142,54" />',
    /* Akzent: Scan-Linie mit End-Ticks (ein Element, ein Akzent) */
    '<path class="icon-accent" d="M42,22 H94 M42,18.5 V25.5 M94,18.5 V25.5" />',
  ].join(''));
}

// Rolle: Leerzustand Analyse-Log (#log-empty, index.html) — Gravur-Platte mit
// Log-Zeilen, darüber ein leeres Fadenkreuz (Kreis um das Zentrum, Striche
// außen); Akzent ist der unbesetzte Zentrumspunkt.
export function svgEmptyLog() {
  return illu([
    '<rect x="44" y="30" width="72" height="60" rx="4" />',
    /* Log-Zeilen (Gravur), Mittelpunkt um den Zielpunkt frei gehalten */
    '<path d="M54,48 H88 M54,60 H72 M54,72 H92 M92,46 H104 M90,72 H104" stroke-width="1.25" />',
    /* Fadenkreuz: Innenkreis + vier Außenstriche über den Plattenrändern */
    '<circle cx="80" cy="60" r="10" stroke-dasharray="3 3" />',
    '<path d="M80,20 V30 M80,90 V100 M34,60 H44 M116,60 H126" />',
    '<circle class="icon-accent" cx="80" cy="60" r="2.5" fill="currentColor" stroke="none" />',
  ].join(''));
}

// Rolle: Leerzustand Cluster-Liste (#cluster-empty, index.html) — verstreute
// Knoten ohne jede Kante (noch keine Cluster-Bindung); Akzent ist der eine
// gefüllte Knoten als „erster gesichteter Akteur".
export function svgEmptyCluster() {
  return illu([
    '<circle cx="46" cy="42" r="5" />',
    '<circle cx="94" cy="26" r="3.5" />',
    '<circle cx="128" cy="60" r="6" />',
    '<circle cx="38" cy="96" r="3.5" />',
    '<circle cx="106" cy="100" r="5" />',
    '<circle class="icon-accent" cx="72" cy="72" r="4.5" fill="currentColor" stroke="none" />',
  ].join(''));
}

// Rolle: Leerzustand Flow-Graph (#fh-graph-empty, history-host.html) —
// Bruchstück-Topologie: eine durchgezogene Kante, die übrigen gebrochen
// gestrichelt; Akzent ist der zentrale Knotenring (retained edges fehlen).
export function svgEmptyGraph2D() {
  return illu([
    '<path d="M80,60 L42,38" />',
    '<path d="M80,60 L118,32 M80,60 L58,92 M118,32 L124,88" stroke-dasharray="4 4" stroke-opacity="0.55" />',
    '<circle cx="42" cy="38" r="5" />',
    '<circle cx="118" cy="32" r="4" />',
    '<circle cx="58" cy="92" r="4" />',
    '<circle cx="124" cy="88" r="5" />',
    '<circle class="icon-accent" cx="80" cy="60" r="6" />',
  ].join(''));
}

// Rolle: Leerzustand Flow-State (#fh-empty, history-host.html) — Walk-Orbit:
// gestrichelte Cursor-Bahn mit vereinzelten Bahn-Knoten, im Zentrum die leere
// Hash-Raute (noch nichts akkumuliert); Akzent ist der Startpunkt auf der Bahn.
export function svgEmptyFlowState() {
  return illu([
    '<circle cx="80" cy="62" r="36" stroke-dasharray="3 6" />',
    '<circle cx="80" cy="26" r="3" />',
    '<circle cx="116" cy="62" r="3" />',
    '<circle cx="54.5" cy="87.5" r="3" />',
    '<path d="M80,54.5 L87.5,62 L80,69.5 L72.5,62 Z" />',
    '<circle class="icon-accent" cx="48.5" cy="44" r="3" fill="currentColor" stroke="none" />',
  ].join(''));
}

// Rolle: Leerzustand Account-Check (.check-empty in account-check.js — dieselbe
// Rolle „Abschnitt ohne Treffer" in den drei Abschnitten Rolle/Muster/Kontakte,
// kontextuell verkleinert via account-check.css) — Lupe über einem Hash-Deficit:
// Dokument mit Zeilen, Akzent ist die Hash-Raute am unteren Dokumentrand.
export function svgEmptyCheck() {
  return illu([
    '<path d="M46,34 H90 L102,46 V92 A4,4 0 0,1 98,96 H50 A4,4 0 0,1 46,92 Z" />',
    '<path d="M90,34 V42 A4,4 0 0,0 94,46 H102" />',
    '<path d="M56,60 H86 M56,72 H72" />',
    '<circle cx="112" cy="42" r="15" />',
    '<path d="M123,53 L136,66" />',
    '<path class="icon-accent" d="M74,80.5 L79.5,86 L74,91.5 L68.5,86 Z" fill="currentColor" stroke="none" />',
  ].join(''));
}

// Rolle: Globe-Fallback (globe.js showFallback — WebGL/CDN nicht erreichbar) —
// Kugelgratul (Meridian, Äquator, ein Breitenkreis) mit genau einem punktierten
// Standpunkt als Akzent: die Welt ist da, die Daten fehlen.
export function svgGlobeFallback() {
  return illu([
    '<circle cx="80" cy="60" r="42" />',
    '<ellipse cx="80" cy="60" rx="16" ry="42" stroke-opacity="0.55" />',
    '<ellipse cx="80" cy="60" rx="42" ry="15" stroke-opacity="0.55" />',
    '<ellipse cx="80" cy="38" rx="34" ry="10" stroke-opacity="0.55" />',
    '<circle class="icon-accent" cx="108" cy="36" r="3" fill="currentColor" stroke="none" />',
  ].join(''));
}

// Rolle: Panel-Signet Activity Graph (panel-marker im <h2 id="graph-title">,
// index.html — per JS eingehängt, 20 px Wiedergabe) — Mini-Topologie aus drei
// Knoten und zwei Kanten; KEIN Akzent (Icon-Rolle, reine Gravur) und bewusst
// kein Hexagon (das Waben-Motiv gehört exklusiv zur Marke .brand-mark).
export function panelMarkerGraph() {
  return icon([
    '<circle cx="6.5" cy="16.5" r="2.5" />',
    '<circle cx="16.5" cy="7.5" r="2.5" />',
    '<circle cx="17.5" cy="17.5" r="2.5" />',
    '<path d="M8.7,15 L14.6,9.4 M16.8,10 L17.4,15" />',
  ].join(''));
}

/* ---------- Panel-Signete der Info-Seite (about.html, 2026-10-06) ----------
 * Vier eigene Icon-Rollen im Graphit-Gravurduktus (24×24, kein Akzent, keine
 * Flächen) — jedes Signet markiert GENAU EIN Panel der Info-Seite. Der Titel-
 * Text der Panels liegt in einem Kindelement mit data-i18n, damit applyStatic
 * (textContent) das eingehängte Signet nicht entfernt — Mount-Skript in
 * about.html, Guards in public/icons.test.mjs und public/about.test.mjs. */

// Rolle: Panel-Signet Zweck/Über (panel-marker im <h2 id="about-mission-title">,
// about.html) — Radar: Außenring, Messkreis und ein Sweep-Strahl vom Zentrum
// zur Kante; KEIN Akzent (Icon-Rolle), Kreis-Motive bewusst anders geschnitten
// als Marke/Chart-Marker (kein Hexagon, keine Wimpel-Raute).
export function panelMarkerRadar() {
  return icon([
    '<circle cx="12" cy="12" r="8.5" />',
    '<circle cx="12" cy="12" r="3.5" />',
    '<path d="M12,3.5 V12 L18.1,15.5" />',
  ].join(''));
}

// Rolle: Panel-Signet Erkennung (panel-marker im <h2 id="about-detect-title">,
// about.html) — Sieb: Trichter mit eingeschlossener Prüfpellette — Muster
// fallen durch die Regeln, die Treffer bleiben sichtbar hängen.
export function panelMarkerSieve() {
  return icon([
    '<path d="M4.5,6.5 H19.5 L13.5,12.5 V18.5 L10.5,20.5 V12.5 Z" />',
    '<circle cx="12" cy="8.5" r="1.75" />',
  ].join(''));
}

// Rolle: Panel-Signet Glossar (panel-marker im <h2 id="about-glossary-title">,
// about.html) — Lexikon: aufgeschlagenes Doppelblatt mit Mittelfalte und
// Kurzzeilen beidseitig; abgesetzt vom Dokument-Motiv der Check-Leerzustands-
// Illustration (svgEmptyCheck: einseitiges Blatt mit Falz und Lupe).
export function panelMarkerLexicon() {
  return icon([
    '<path d="M12,6.5 C10,5 7,4.5 4.5,5 V17.5 C7,17 10,17.5 12,19 C14,17.5 17,17 19.5,17.5 V5 C17,4.5 14,5 12,6.5 Z" />',
    '<path d="M12,6.5 V19" />',
    '<path d="M7,9 H9.5 M14.5,9 H17 M7,12 H9.5 M14.5,12 H17" stroke-width="1" />',
  ].join(''));
}

// Rolle: Panel-Signet Grenzen (panel-marker im <h2 id="about-limits-title">,
// about.html) — Rahmen im Rahmen: solider Außenrand, gestrichelte
// Aussagegrenze (0.55) und der eine Prüfpunkt dazwischen — ehrliche
// Begrenzung der Aussagekraft, kein Schloss- oder Schild-Klischee.
export function panelMarkerFrame() {
  return icon([
    '<path d="M5.5,5.5 H18.5 V18.5 H5.5 Z" />',
    '<path d="M8.5,8.5 H15.5 V15.5 H8.5 Z" stroke-width="1" stroke-dasharray="3 3" stroke-opacity="0.55" />',
    '<circle cx="12" cy="12" r="1.75" />',
  ].join(''));
}

// Rolle: Diagramm-Marker geflaggte Stunde (renderWindowChart in app.js — sitzt
// als 12-px-Pin über jedem Balken mit flagged>0; Farbe dort über
// style="color:var(--a6-sev-malicious)", die Signale <title> und die
// Meta-Zeile chart.flagged bleiben die tragende Auskunft). Wimpel-Raute mit
// kurzem Stift; KEIN Akzent (Icon-Rolle). Der optionale attrs-String setzt
// x/y/width/height/style für den Einbau als verschachteltes SVG im Chart —
// ohne Argument bleibt der String eigenständig gültig.
export function chartMarkerFlagged(attrs = '') {
  return icon([
    '<path d="M12,4.5 L18,11 L12,17.5 L6,11 Z" />',
    '<path d="M12,17.5 V21" />',
  ].join(''), attrs);
}

/* Leerzustands-Illustration idempotent in ein bestehendes .empty-<p> hängen
 * (als erstes Kind, Text bleibt Inhalt des <p>; i18n unberührt — die
 * Illustration ist textlos und aria-hidden). Aufrufer, die den <p>-Inhalt per
 * textContent überschreiben, mounten danach erneut (idempotent). */
export function mountEmptyIllu(el, svg) {
  if (typeof document === 'undefined' || !el || !svg) return;
  try {
    if (el.querySelector('.empty-illu')) return;
    el.insertAdjacentHTML('afterbegin', '<span class="empty-illu" aria-hidden="true">' + svg + '</span>');
  } catch { /* DOM nicht schreibbar: Illustration entfällt, wirft aber nicht */ }
}
