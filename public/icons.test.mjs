/* Icons-/Marke-Regressionstests (Design P0/P1, 2026-10-06)
 *
 * Statische Guards für die Unikat-SVG-Sprache (public/icons.mjs), das
 * Header-Logo (.brand-mark in index.html/history-host.html) und das Favicon
 * (public/favicon.svg) — kein Browser nötig:
 *  1) Stilvertrag: viewBox-Grids (Illustrationen 160×120, Icons 24×24),
 *     fill="none"/stroke="currentColor"/1.1 px/runde Kappen auf der Wurzel.
 *  2) Unikat-Regel (harte Auftrags-Vorgabe): kein SVG-Inhalt in zwei Rollen —
 *     normalisierter Hash UND Teilstring-Vergleich über alle Rollen.
 *  3) Marke ≠ Icons: das Logo teilt mit keiner Icon-Rolle Forminhalte; die
 *     Logo-Marke ist in beiden Dokumenten identisch gepflegt; das Favicon
 *     ist eine eigene, vereinfachte Rolle.
 *  4) Größenbudget: jede SVG-Funktion ≤ 2048 B, Inline-Logo ≤ 1536 B,
 *     favicon.svg ≤ 2048 B (Speed-Budget „SVGs klein").
 *  5) Akzent-Disziplin: Illustrationen genau EIN .icon-accent mit
 *     fill="currentColor", Icons (24×24) ohne Akzent und ohne Flächen-Fill.
 *  6) Favicon Token-Konformität: kein #f5a623 mehr, Akzent #ec5b00,
 *     Verlinkung als Datei (favicon.svg) in beiden Dokumenten.
 *  7) Einbau-Verdrahtung: Mounts laufen über icons.mjs-Funktionen (kein
 *     SVG-Duplikat im HTML-Markup), inkl. der Re-Mounts nach den
 *     textContent-Überschreibungen von #feed-empty/#fh-empty.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

import {
  svgEmptyFeed, svgEmptyLog, svgEmptyCluster, svgEmptyGraph2D,
  svgEmptyFlowState, svgEmptyCheck, svgGlobeFallback,
  panelMarkerGraph, chartMarkerFlagged, mountEmptyIllu,
  panelMarkerRadar, panelMarkerSieve, panelMarkerLexicon, panelMarkerFrame,
} from './icons.mjs';

const here = path.dirname(fileURLToPath(import.meta.url));
const read = (rel) => readFileSync(path.join(here, rel), 'utf8');

const indexHtml = read('index.html');
const historyHostHtml = read('history-host.html');
const aboutHtml = read('about.html');
const appJs = read('app.js');
const globeJs = read('globe.js');
const accountCheckJs = read('account-check.js');
const accountCheckCss = read('account-check.css');
const styleCss = read('style.css');

const ILLUSTRATIONS = {
  svgEmptyFeed, svgEmptyLog, svgEmptyCluster, svgEmptyGraph2D,
  svgEmptyFlowState, svgEmptyCheck, svgGlobeFallback,
};
const ICONS = {
  panelMarkerGraph, chartMarkerFlagged,
  panelMarkerRadar, panelMarkerSieve, panelMarkerLexicon, panelMarkerFrame,
};
const ALL = { ...ILLUSTRATIONS, ...ICONS };

/* Innenleben eines SVG-Strings (zwischen Wurzel-Tag und </svg>),
 * whitespace-normalisiert — die Vergleichsbasis für den Unikat-Hash. */
const sig = (s) => {
  const a = s.indexOf('<svg');
  assert.ok(a >= 0, 'SVG-Wurzel gefunden');
  const b = s.indexOf('>', a);
  const e = s.lastIndexOf('</svg>');
  assert.ok(b >= 0 && e > b, 'SVG vollständig');
  return s.slice(b + 1, e).replace(/\s+/g, ' ').trim();
};

const brandMarkInner = (html) => {
  const m = html.match(/<span class="brand-mark"[^>]*>([\s\S]*?)<\/span>/);
  assert.ok(m, '.brand-mark im Markup gefunden');
  return m[1];
};

test('Stilvertrag: viewBox-Grids, currentColor-Gravur, runde Kappen auf der Wurzel', () => {
  for (const [name, fn] of Object.entries(ALL)) {
    const s = fn();
    assert.ok(s.startsWith('<svg') && s.endsWith('</svg>'), `${name}: komplettes <svg>-Element`);
    const expectVb = name in ILLUSTRATIONS ? '0 0 160 120' : '0 0 24 24';
    assert.ok(s.includes(`viewBox="${expectVb}"`), `${name}: viewBox ${expectVb}`);
    for (const attr of [
      'fill="none"', 'stroke="currentColor"', 'stroke-width="1.1"',
      'stroke-linecap="round"', 'stroke-linejoin="round"', 'aria-hidden="true"',
    ]) {
      assert.ok(s.includes(attr), `${name}: ${attr} fehlt`);
    }
  }
  // chartMarkerFlagged(attrs) bleibt mit Einbau-Attributen ein gültiges SVG.
  assert.match(
    chartMarkerFlagged('x="1" y="2" width="12" height="12"'),
    /^<svg x="1" y="2" width="12" height="12" viewBox="0 0 24 24" /,
  );
});

test('Unikat-Regel: kein SVG-Inhalt in zwei Rollen (Hash + Teilstring)', () => {
  const entries = Object.entries(ALL).map(([name, fn]) => [name, sig(fn())]);
  for (let i = 0; i < entries.length; i++) {
    for (let j = i + 1; j < entries.length; j++) {
      const [na, sa] = entries[i];
      const [nb, sb] = entries[j];
      assert.notEqual(sa, sb, `${na} und ${nb} tragen identischen SVG-Inhalt`);
      assert.ok(!sa.includes(sb) && !sb.includes(sa), `${na}/${nb}: kein Inhaltsteil-Duplikat`);
    }
  }
});

test('Rollen-Docstrings: Kommentarblock direkt über jeder Exportfunktion nennt die Rolle', () => {
  const src = read('icons.mjs');
  for (const name of Object.keys(ALL)) {
    // Der unmittelbar vorangehende, zusammenhängende //-Kommentarblock muss
    // eine „// Rolle:"-Zeile tragen — der Block darf mehrzeilig sein.
    const m = src.match(new RegExp(`((?:\\/\\/[^\\n]*\\n)+)export function ${name}\\(`));
    assert.ok(m, `${name}: Kommentarblock über der Funktion`);
    assert.match(m[1], /\/\/ Rolle: /, `${name}: Rollen-Zeile im Block`);
  }
});

test('Akzent-Disziplin: Illustrationen genau EIN Akzent, Flächen-Fill nur dort, Icons ohne', () => {
  for (const [name, fn] of Object.entries(ILLUSTRATIONS)) {
    const s = fn();
    assert.equal((s.match(/class="icon-accent"/g) ?? []).length, 1, `${name}: genau ein Akzent-Element`);
    // Flächen-Fills sind NUR am Akzent erlaubt (Stilvertrag: „außer genau EIN
    // Akzent-Element keine Flächen-Fills") — der Akzent darf Kontur ODER
    // Fläche sein, deshalb ≤ statt ==.
    assert.ok(
      (s.match(/fill="currentColor"/g) ?? []).length <= (s.match(/class="icon-accent"/g) ?? []).length,
      `${name}: Flächen-Fill nur am Akzent-Element`,
    );
  }
  for (const [name, fn] of Object.entries(ICONS)) {
    assert.equal((fn().match(/icon-accent/g) ?? []).length, 0, `${name}: Icon-Rolle ohne Akzent`);
    assert.equal((fn().match(/fill="currentColor"/g) ?? []).length, 0, `${name}: Icon-Rolle ohne Flächen-Fill`);
  }
});

test('Größenbudget: SVG-Funktion ≤ 2048 B, Inline-Logo ≤ 1536 B, favicon.svg ≤ 2048 B', () => {
  for (const [name, fn] of Object.entries(ALL)) {
    assert.ok(fn().length <= 2048, `${name}: ${fn().length} B > 2048 B`);
  }
  const logo = brandMarkInner(indexHtml);
  assert.ok(logo.length <= 1536, `Inline-Logo: ${logo.length} B > 1536 B`);
  const fav = read('favicon.svg');
  assert.ok(fav.length <= 2048, `favicon.svg: ${fav.length} B > 2048 B`);
});

test('Marke ≠ Icons: Logo-Inhalt in keiner Rolle, Favicon eigene Rolle', () => {
  const logo = sig(brandMarkInner(indexHtml));
  const fav = sig(read('favicon.svg'));
  for (const [name, fn] of Object.entries(ALL)) {
    const s = sig(fn());
    assert.notEqual(logo, s, `Logo-Inhalt identisch mit Rolle ${name}`);
    assert.ok(!logo.includes(s) && !s.includes(logo), `Logo/${name}: kein Inhaltsteil-Duplikat`);
    assert.notEqual(fav, s, `Favicon-Inhalt identisch mit Rolle ${name}`);
    assert.ok(!fav.includes(s) && !s.includes(fav), `Favicon/${name}: kein Inhaltsteil-Duplikat`);
  }
  assert.notEqual(logo, fav, 'Favicon ist keine Kopie des Header-Logos');
});

test('Marke konsistent: brand-mark identisch in allen drei Dokumenten, Tropfen-Klasse vorhanden', () => {
  assert.equal(brandMarkInner(indexHtml), brandMarkInner(historyHostHtml), 'identische Logo-Marke');
  assert.equal(brandMarkInner(indexHtml), brandMarkInner(aboutHtml), 'Logo-Marke auch in about.html identisch');
  assert.match(brandMarkInner(indexHtml), /class="hp-drop"/, 'Köder-Tropfen .hp-drop');
  assert.match(indexHtml, /<span class="brand-xrpl">XRPL<\/span>/, 'Wortmarken-Anhang index');
  assert.match(historyHostHtml, /<span class="brand-xrpl">XRPL<\/span>/, 'Wortmarken-Anhang flow-host');
  assert.match(aboutHtml, /<span class="brand-xrpl">XRPL<\/span>/, 'Wortmarken-Anhang about');
});

test('Favicon: Datei vorhanden, Token-konform (#ec5b00 statt #f5a623), als Datei verlinkt', () => {
  assert.ok(existsSync(path.join(here, 'favicon.svg')), 'public/favicon.svg fehlt');
  const fav = read('favicon.svg');
  assert.match(fav, /<svg[^>]*xmlns=/, 'eigenständige SVG-Datei mit xmlns');
  assert.doesNotMatch(fav, /f5a623/i, 'Token-fremder Orange-Ton entfernt');
  assert.match(fav, /#ec5b00/, 'Akzent-Ton der Marke');
  for (const [name, html] of [['index.html', indexHtml], ['history-host.html', historyHostHtml]]) {
    const link = html.match(/<link rel="icon"[^>]*>/);
    assert.ok(link, `${name}: icon-Link vorhanden`);
    assert.match(link[0], /type="image\/svg\+xml" href="favicon\.svg"/, `${name}: verlinkt favicon.svg`);
    assert.doesNotMatch(link[0], /data:image/, `${name}: keine Data-URI mehr`);
    assert.doesNotMatch(html, /f5a623/i, `${name}: alter Favicon-Ton vollständig entfernt`);
  }
});

test('Einbau: SVG-Mounts nur per JS — kein Icon-Inhalt als Inline-Duplikat im HTML', () => {
  for (const [name, fn] of Object.entries(ALL)) {
    const s = sig(fn());
    assert.ok(!indexHtml.includes(s), `${name}: kein Inline-Duplikat in index.html`);
    assert.ok(!historyHostHtml.includes(s), `${name}: kein Inline-Duplikat in history-host.html`);
    assert.ok(!aboutHtml.includes(s), `${name}: kein Inline-Duplikat in about.html`);
  }
});

test('Einbau-Verdrahtung: Rollen werden an ihren Stellen aufgerufen (inkl. Re-Mounts)', () => {
  // app.js: Initial-Mounts der drei Dashboard-Empties + Panel-Signet.
  assert.match(appJs, /mountEmptyIllu\(document\.getElementById\('feed-empty'\), svgEmptyFeed\(\)\)/, 'feed-empty initial');
  assert.match(appJs, /mountEmptyIllu\(document\.getElementById\('log-empty'\), svgEmptyLog\(\)\)/, 'log-empty initial');
  assert.match(appJs, /mountEmptyIllu\(document\.getElementById\('cluster-empty'\), svgEmptyCluster\(\)\)/, 'cluster-empty initial');
  assert.match(appJs, /panelMarkerGraph\(\)/, 'Panel-Signet');
  assert.match(appJs, /mountEmptyIllu\(emptyEl, svgEmptyFeed\(\)\)/, 'Re-Mount renderWindowFeed');
  assert.match(appJs, /mountEmptyIllu\(liveEmptyEl, svgEmptyFeed\(\)\)/, 'Re-Mount startLiveMode');
  // app.js: Chart-Marker nur im flagged-Zweig von renderWindowChart.
  assert.match(appJs, /if \(flagged > 0\) \{[\s\S]{0,600}chartMarkerFlagged\(/, 'Chart-Marker an geflaggte Stunden gebunden');
  assert.match(appJs, /chartMarkerFlagged\('x="/, 'Chart-Marker mit Einbau-Attributen');
  // globe.js / account-check.js / history-host.html.
  assert.match(globeJs, /svgGlobeFallback\(\)/, 'Globe-Fallback-Illustration');
  assert.match(accountCheckJs, /svgEmptyCheck\(\)/, 'Account-Check-Illustration');
  assert.equal((accountCheckJs.match(/CHECK_EMPTY_ILLU\}/g) ?? []).length, 3, 'drei Abschnitts-Emptys im Account-Check');
  assert.match(historyHostHtml, /mountEmptyIllu\(els\.graphEmpty, svgEmptyGraph2D\(\)\)/, 'fh-graph-empty initial');
  assert.match(historyHostHtml, /svgEmptyFlowState\(\)/, 'fh-empty-Illustration');
  assert.equal(
    (historyHostHtml.match(/mountEmptyIllu\(els\.empty, svgEmptyFlowState\(\)\)/g) ?? []).length,
    3,
    'fh-empty: 1 Initial- + 2 Re-Mounts nach textContent',
  );
});

test('CSS-Verdrahtung: .empty-illu/.panel-marker/.icon-accent-Token + Account-Check-Skalierung', () => {
  assert.match(styleCss, /--a6-icon-accent:\s*var\(--a6-brand-blue\)/, 'Akzent-Token definiert');
  assert.match(styleCss, /\.empty-illu\s*\{/, '.empty-illu-Regel');
  assert.match(styleCss, /\.empty-illu \.icon-accent\s*\{[^}]*var\(--a6-icon-accent, var\(--a6-brand-blue\)\)/, 'Akzent läuft über den Token');
  assert.match(styleCss, /\.panel-marker\s*\{[^}]*width: 20px/, 'Panel-Signet 20 px');
  assert.match(styleCss, /@media \(forced-colors: active\)\s*\{[\s\S]{0,300}\.empty-illu \.icon-accent\s*\{\s*color: Highlight/, 'forced-colors-Pendant');
  assert.match(accountCheckCss, /\.check-empty \.empty-illu\s*\{[^}]*width: 96px/, 'Account-Check: verkleinerte Illustration (96×72)');
});

test('Info-Seite about.html: vier Panel-Signete per JS gemountet, Titel-i18n im Kindelement', () => {
  // Mount-Skript importiert alle vier neuen Icon-Rollen und hängt sie an die
  // Panel-<h2> (mountMarker-Muster app.js:3125-3132).
  assert.match(aboutHtml, /import \{[\s\S]*?panelMarkerRadar, panelMarkerSieve, panelMarkerLexicon, panelMarkerFrame,/, 'Import der vier Signete');
  assert.match(aboutHtml, /mountMarker\('about-mission-title', panelMarkerRadar\(\)\)/, 'Signet Zweck gemountet');
  assert.match(aboutHtml, /mountMarker\('about-detect-title', panelMarkerSieve\(\)\)/, 'Signet Erkennung gemountet');
  assert.match(aboutHtml, /mountMarker\('about-glossary-title', panelMarkerLexicon\(\)\)/, 'Signet Glossar gemountet');
  assert.match(aboutHtml, /mountMarker\('about-limits-title', panelMarkerFrame\(\)\)/, 'Signet Grenzen gemountet');
  // applyStatic überschreibt [data-i18n]-Elemente per textContent — der Titel-
  // Text jedes Panels liegt deshalb in einem Kindelement MIT data-i18n, das
  // Signet-Span bleibt vom Sprachwechsel unberührt (idempotenter Mount).
  for (const id of ['about-mission-title', 'about-detect-title', 'about-glossary-title', 'about-limits-title']) {
    assert.match(aboutHtml, new RegExp(`<h2 id="${id}"><span data-i18n="about\\.`), `${id}: Titel-text in data-i18n-Kindelement`);
  }
  // Sprachwechsel-Handler rendert nur die statischen Texte neu (Signete bleiben).
  assert.match(aboutHtml, /document\.addEventListener\('hx:langchange', \(\) => applyStatic\(document\)\);/, 'langchange-Handler ohne Signet-Rebuild nötig');
});

test('mountEmptyIllu: ohne DOM eine No-op (Modul bleibt Node-testbar)', () => {
  assert.doesNotThrow(() => mountEmptyIllu(null, '<svg></svg>'));
  assert.doesNotThrow(() => mountEmptyIllu(undefined, undefined));
});
