/* Design-Assets-Regressionstests (Design-Umsetzung 2026-10-06)
 *
 * Statische Guards für den CSS/Markup-Feinschliff — kein Browser nötig:
 *  1) Selbst-gehostete Schriften: sechs woff2 mit gültigem Magic-Bytes in
 *     public/fonts/, @font-face-Deklarationen mit font-display:swap in
 *     style.css, kein Google-Fonts-Link in den HTML-Dokumenten.
 *  2) Inline-Style-Entfernung: das .cluster-modal-stale-Markup in drilldown.js
 *     trägt keinen style-Attribut mehr (Stil wohnt in drilldown.css).
 *  3) Initialtext von #feed-more ist englisch (lang="en"-Dokument; data-i18n
 *     überschreibt ohnehin zur Laufzeit).
 *  4) Kernregeln des Audits bleiben vorhanden: Fokus-Ringe, Disabled-Look,
 *     gemeinsame Bühnenhöhen-Leiter, Primäraktion auf Token.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const here = path.dirname(fileURLToPath(import.meta.url));
const read = (rel) => readFileSync(path.join(here, rel), 'utf8');

const styleCss = read('style.css');
const drilldownCss = read('drilldown.css');
const globeCss = read('globe.css');
const drilldownJs = read('drilldown.js');
const indexHtml = read('index.html');
const historyHostHtml = read('history-host.html');

test('fonts: sechs woff2-Dateien mit WOFF2-Magic in public/fonts/', () => {
  const fonts = [
    'inter-latin-400.woff2',
    'inter-latin-600.woff2',
    'inter-latin-700.woff2',
    'inter-latin-800.woff2',
    'jetbrains-mono-latin-400.woff2',
    'jetbrains-mono-latin-700.woff2',
  ];
  for (const f of fonts) {
    const p = path.join(here, 'fonts', f);
    assert.ok(existsSync(p), `Datei fehlt: fonts/${f}`);
    const buf = readFileSync(p);
    assert.equal(buf.slice(0, 4).toString('latin1'), 'wOF2', `${f} ist kein woff2`);
    assert.ok(buf.length > 1024, `${f} suspicious klein (${buf.length} B)`);
  }
  assert.ok(existsSync(path.join(here, 'fonts', 'LICENSES.md')), 'Lizenzdokumentation fehlt');
});

test('style.css: je Familie/Gewicht eine @font-face mit font-display:swap auf /fonts/', () => {
  const faces = styleCss.match(/@font-face\s*\{[^}]*\}/g) ?? [];
  assert.equal(faces.length, 6, 'erwartet genau 6 @font-face-Blöcke');
  for (const face of faces) {
    assert.match(face, /font-display:\s*swap/, 'font-display:swap fehlt');
    assert.match(face, /url\("\/fonts\//, 'Pfad muss unter /fonts/ liegen');
  }
  const families = faces.map((f) => f.match(/font-family:\s*"([^"]+)"/)?.[1] ?? '');
  assert.equal(families.filter((f) => f === 'Inter').length, 4, 'Inter in 4 Gewichten');
  assert.equal(families.filter((f) => f === 'JetBrains Mono').length, 2, 'JetBrains Mono in 2 Gewichten');
  assert.deepEqual(
    faces.map((f) => f.match(/font-weight:\s*(\d+)/)?.[1]),
    ['400', '600', '700', '800', '400', '700'],
    'Gewichte in deklarierter Reihenfolge',
  );
});

test('HTML: kein Google-Fonts-Link (Selbst-Hosting, keine Dritt-Anfrage)', () => {
  assert.doesNotMatch(indexHtml, /fonts\.googleapis\.com|fonts\.gstatic\.com/);
  assert.doesNotMatch(historyHostHtml, /fonts\.googleapis\.com|fonts\.gstatic\.com/);
});

test('drilldown.js: .cluster-modal-stale ohne Inline-Style (Stil in drilldown.css)', () => {
  const m = drilldownJs.match(/<p class="graph-note cluster-modal-stale"[^>]*>/);
  assert.ok(m, 'cluster-modal-stale-Markup gefunden');
  assert.doesNotMatch(m[0], /\sstyle\s*=/, 'kein style-Attribut mehr im Markup');
  assert.match(drilldownCss, /\.cluster-modal-stale\s*\{/, 'Regel existiert in drilldown.css');
});

test('index.html: #feed-more-Initialtext englisch (lang="en"-Dokument)', () => {
  const m = indexHtml.match(/<button[^>]*id="feed-more"[^>]*>([^<]*)<\/button>/);
  assert.ok(m, 'feed-more-Button gefunden');
  assert.equal(m[1].trim(), 'Load more');
});

test('style.css: Fokus-, Disabled- und Token-Kernregeln des Audits', () => {
  assert.match(styleCss, /\.cluster-card:focus-visible\s*\{/, 'Fokus-Ring für Cluster-Karten');
  assert.match(drilldownCss, /\.cluster-table-wrap:focus-visible\s*\{/, 'Fokus-Ring für Tabellen-Wrapper');
  assert.match(styleCss, /\.download-btn:disabled,\s*\n\s*\.filter-select:disabled\s*\{/, 'Disabled-Look');
  assert.match(styleCss, /--a6-ink-fill:\s*#141416;/, 'Primär-Token definiert');
  assert.match(styleCss, /\.graph-tab\[aria-selected="true"\]\s*\{[^}]*var\(--a6-ink-fill\)/, 'Tab-Auswahl auf Token');
  assert.match(styleCss, /\.lang-btn\[aria-pressed="true"\]\s*\{[^}]*var\(--a6-ink-fill\)/, 'Sprachwahl auf Token');
  assert.match(styleCss, /\.cluster-transit-note\s*\{/, 'Transit-Note-Regel');
});

test('Bühnen-Leiter: ein gemeinsamer --a6-stage-height-Token für alle drei Bühnen', () => {
  assert.match(styleCss, /--a6-stage-height:\s*720px;/, 'Basis-Token');
  const stages = (styleCss.match(/--a6-stage-height:\s*\d+px/g) ?? []).length;
  assert.equal(stages, 4, 'Leiter mit 4 Stufen (720/640/560/480) in style.css');
  assert.match(styleCss, /#graph\s*\{[^}]*var\(--a6-stage-height/, '#graph nutzt Token');
  assert.match(globeCss, /#globe\s*\{[^}]*var\(--a6-stage-height/, '#globe nutzt Token');
  assert.match(drilldownCss, /\.cluster-3d\s*\{[^}]*var\(--a6-stage-height/, '.cluster-3d nutzt Token');
});

test('Modal: Metrik-Zeilen-Ausgleich und Entry-Transition nur opacity/transform', () => {
  assert.match(drilldownCss, /\.cluster-modal-metrics \.cluster-times\s*\{[^}]*margin-top:\s*0/, 'Zeitblock auf Baseline');
  assert.match(drilldownCss, /@starting-style/, 'Entry-Transition deklariert');
  const t = drilldownCss.match(/\.cluster-modal-surface\s*\{[^}]*transition:\s*([^;]+);/s);
  assert.ok(t, 'transition auf .cluster-modal-surface');
  assert.match(t[1], /opacity|transform/, 'nur opacity/transform animiert');
  assert.doesNotMatch(t[1], /all/, 'kein transition:all');
});
