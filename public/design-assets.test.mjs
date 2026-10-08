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
 *  5) Layout-Fix 2026-10-06 (Forensik-Messung): .view-tab-Textzentrierung
 *     (inline-flex + align/justify center, keine UA-Unterstreichung),
 *     Modal-Konten-Tabelle auf voller Body-Breite (grid-column:1/-1, Tabelle
 *     als letztes direktes Kind von .cluster-modal-body statt Side-Kind,
 *     width:100% statt max-content, th umbrechbar bei nowrap-td), Info-Boxen
 *     Historie/Archiv (renderShell-details + #feed-archive-hint + i18n-Keys).
 *  6) Cluster-Liste/Mega-Cluster (Design P2): Bedeutungs-Vollrahmen statt
 *     Linksbändchen (1px border-color je Severity/Rolle in derselben Token-
 *     Farbe; KEIN border-left-Band, KEIN Band-Token — Vollrahmen-Umbau
 *     2026-10-07), solide sev-malicious-Kopf-Tönung (kein Gradient),
 *     Drainer-Rollen-
 *     Chip, --a6-r-xs für Swatches, Verdichtungs-Segment-Control mit
 *     aria-pressed + localStorage 'hx-density', data-size="mega" mit EINEM
 *     gemeinsamen '+N weitere Konten'-i18n-Wortfeld (Plan-Kritik 10).
 *  7) Marke/SVG-System (Design P0/P1): Speed-Budget 200 KB je App-Eigendatei
 *     direkt in public/ als statische Größe (Plan-Kritik 11 — die Grenze
 *     existierte sonst nirgends im Repo), Logo-CSS (.brand-mark/.hp-drop/
 *     Wortmarke .brand-xrpl). Die SVG-Unikat-/Favicon-/Stilvertrags-Tests
 *     liegen in public/icons.test.mjs.
 *  8) 3D-Bühnen (Design P3, 2026-10-06): transparenter WebGL-Clear statt
 *     Vollweiß (Browser-verifiziert am gepinnten Bundle), sparsames Punkt-
 *     substrat (24 px + versetztes 96 px, --a6-graph-grid) + dezente inset-
 *     Vignette auf .cluster-3d UND #globe, Hover-Cursor-Klasse, additiver
 *     Drainer-Ring (nodeThreeObjectExtend, Deckel 12, kein Emissive —
 *     Plan-Kritik 7b/8), Ring-Legende über i18n in beiden Wörterbüchern,
 *     forced-colors-Rücknahme der Vignette.
 *  9) Noir-Theme (2026-10-06): data-theme="noir" als zweites VOLLTHEMA über
 *     die Token-SSOT — vollständiger Override-Block (inkl. color-scheme:
 *     dark), KEINE hartcodierten Hex außerhalb der beiden Token-Blöcke,
 *     --a6-on-ink/--a6-info-soft/--a6-stage-bg/--a6-stage-glow statt der
 *     früheren Hell-Literale, Theme-Mechanik (Bootstrap 'hx-theme', Toggle-
 *     Fixture, aria) und Kontrast-Regeltests der Kern-Paare in BEIDEN Themes
 *     (WCAG 2.x: Text ≥ 4.5:1, UI ≥ 3:1, Soft-Flächen komposit über der
 *     Surface), JS-Canvas-Paletten (app.js THEME_JS_COLORS inkl. unknown)
 *     und die Module-Verdrahtung (drilldown/globe/Flow-Host).
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, existsSync, readdirSync, statSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
/* Noir-Theme (2026-10-06): die Theme-Mechanik (i18n.mjs) ist DOM-frei
 * importierbar (Modul-Vertrag) — der Fixture-Test unten stubt
 * document/localStorage je Test und räumt in finally auf. */
import {
  DEFAULT_THEME, THEMES, THEME_KEY, THEME_META_COLORS,
  getTheme, resolveTheme, setTheme, initThemeSwitcher,
} from './i18n.mjs';

const here = path.dirname(fileURLToPath(import.meta.url));
const read = (rel) => readFileSync(path.join(here, rel), 'utf8');

const styleCss = read('style.css');
const drilldownCss = read('drilldown.css');
const globeCss = read('globe.css');
const drilldownJs = read('drilldown.js');
const indexHtml = read('index.html');
const historyHostHtml = read('history-host.html');
const aboutHtml = read('about.html');
const historyJs = read('history.js');
const historyCss = read('history.css');
const accountCheckCss = read('account-check.css');
const globeJs = read('globe.js');
const i18nMjs = read('i18n.mjs');
const appJs = read('app.js');

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
  assert.doesNotMatch(aboutHtml, /fonts\.googleapis\.com|fonts\.gstatic\.com/);
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

/* ---------------- Layout-Fix 2026-10-06 (Forensik-Messung) ---------------- */

test('view-tab: Textzentrierung über inline-flex — gilt für <a>- und <button>-Tabs beider Seiten', () => {
  const rule = styleCss.match(/\.view-tab\s*\{[^}]*\}/);
  assert.ok(rule, '.view-tab-Regel in style.css vorhanden');
  assert.match(rule[0], /display:\s*inline-flex/, 'inline-flex zentriert die Zeilenbox im Element');
  assert.match(rule[0], /align-items:\s*center/, 'Kreuzachse zentriert');
  assert.match(rule[0], /justify-content:\s*center/, 'Hauptachse zentriert');
  assert.match(rule[0], /text-decoration:\s*none/, 'UA-Unterstreichung des Anker-Tabs entfernt');
  // Beide betroffenen Elemente (Messung: <a>-Tabs mit −6 px Abweichung,
  // Buttons mit 0 px als Referenzmuster) tragen die Doppelklasse view-tab.
  assert.match(indexHtml, /<a class="view-tab graph-tab" href="history-host\.html"/, 'index.html: Flow-Host-Anker-Tab');
  assert.match(historyHostHtml, /<a class="view-tab graph-tab" href="index\.html"/, 'history-host.html: Dashboard-Anker-Tab');
  assert.ok((indexHtml.match(/class="view-tab graph-tab"/g) ?? []).length >= 4, 'vier view-tab-Tags im Dashboard (3 Buttons + 1 Anker)');
});

test('Modal-Tabelle: volle Body-Breite — grid-column, schrumpfbare Tabelle, th umbrechbar, td nowrap', () => {
  const secRule = drilldownCss.match(/\.cluster-modal-table\s*\{[^}]*\}/);
  assert.ok(secRule, '.cluster-modal-table-Regel vorhanden');
  assert.match(secRule[0], /grid-column:\s*1\s*\/\s*-1/, 'spannt beide Grid-Spalten');
  assert.match(secRule[0], /min-inline-size:\s*0/, 'Grid-Kind schrumpffähig');
  // Der eigentliche Container-Constraint (Messung 2026-10-06): max-content
  // ließ die Tabelle nie schrumpfen (th-Umbruch wirkungslos, horizontaler
  // Scroll ab jeder Desktop-Größe) — width:100% aktiviert den Umbruch-Hebel.
  // Kommentare werden gestriffen, damit der erläuternde CSS-Kommentar den
  // Deklarations-Check nicht triggert.
  const stripComments = (block) => block.replace(/\/\*[\s\S]*?\*\//g, '');
  const tbl = drilldownCss.match(/\.cluster-table\s*\{[^}]*\}/);
  assert.ok(tbl, '.cluster-table-Regel vorhanden');
  assert.match(stripComments(tbl[0]), /width:\s*100%/, 'Tabelle füllt/folgt der verfügbaren Breite');
  assert.doesNotMatch(stripComments(tbl[0]), /max-content/, 'kein max-content mehr');
  // th darf umbrechen (mehrwortige DE/EN-Header), td bleiben einzeilig
  // (gleiche Spezifität — der th-Block muss der gemeinsamen Regel folgen).
  const thBlock = drilldownCss.match(/\.cluster-table th\s*\{[^}]*\}/);
  assert.ok(thBlock, 'th-Block vorhanden');
  assert.match(thBlock[0], /white-space:\s*normal/, 'th umbrechbar');
  const sharedIdx = drilldownCss.indexOf('.cluster-table th,');
  const ownIdx = drilldownCss.indexOf(thBlock[0]);
  assert.ok(sharedIdx >= 0 && ownIdx >= 0 && sharedIdx < ownIdx, 'th-Block steht NACH der gemeinsamen th/td-Regel (Quellenreihenfolge gewinnt)');
  const thTd = drilldownCss.match(/\.cluster-table th,\s*\n\s*\.cluster-table td\s*\{[^}]*\}/);
  assert.ok(thTd, 'gemeinsame th/td-Regel vorhanden');
  assert.match(thTd[0], /white-space:\s*nowrap/, 'td-Zellen bleiben einzeilig (Zahlen, Badges, Aktionen)');
  // Adress-Spalte: min-width 220 → 200 (Layout-Fix), Volldresse bleibt
  // inhaltsgetrieben; overflow-wrap:anywhere (Mobile-Defense) bleibt.
  const addr = drilldownCss.match(/\.cluster-td-addr\s*\{[^}]*\}/);
  assert.ok(addr, '.cluster-td-addr-Regel vorhanden');
  assert.match(addr[0], /min-width:\s*200px/, 'min-width 200 px');
  assert.match(addr[0], /overflow-wrap:\s*anywhere/, 'kontrollierter Adress-Umbruch erhalten');
});

test('Modal-Shell (drilldown.js): Konten-Tabelle ist letztes direktes Kind von .cluster-modal-body — nicht mehr Kind der aside', () => {
  const start = drilldownJs.indexOf('<div class="cluster-modal-body">');
  assert.ok(start >= 0, 'Shell-Template gefunden');
  const tpl = drilldownJs.slice(start, drilldownJs.indexOf('document.body.appendChild', start));
  assert.ok(tpl.length > 100, 'Shell-Abschnitt isoliert');
  const asideStart = tpl.indexOf('<aside class="cluster-modal-side"');
  const asideEnd = tpl.indexOf('</aside>');
  assert.ok(asideStart > 0 && asideEnd > asideStart, 'aside im Shell-Template');
  const asideBody = tpl.slice(asideStart, asideEnd);
  assert.ok(asideBody.includes('cluster-modal-roles'), 'Fixture: aside-Inhalt erkannt');
  assert.ok(!asideBody.includes('cluster-modal-table'), 'Tabelle ist kein Kind der aside mehr');
  const tbl = tpl.indexOf('<section class="cluster-modal-table"');
  assert.ok(tbl > asideEnd, 'Tabelle folgt NACH der aside (direktes body-Kind)');
  assert.match(
    tpl,
    /<section class="cluster-modal-table"[^>]*><\/section>\s*\n\s*<\/div>\s*\n\s*<\/div>/,
    'Tabelle schließt direkt vor body/surface-Ende (letztes Element)',
  );
  // Export-Block bleibt das letzte aside-Kind (Kommentar-Invariante).
  assert.ok(asideBody.indexOf('cluster-modal-export') > asideBody.indexOf('cluster-modal-chain'), 'Export-Block nach Kette in der aside');
});

test('Info-Boxen Historie/Archiv: renderShell-details, #feed-archive-hint, i18n-Keys in beiden Wörterbüchern', () => {
  // (1) Historie-Panel: Details-Box in renderShell (NICHT statisch in
  // index.html — renderShell überschreibt #history-root innerHTML).
  assert.match(historyJs, /<details class="history-info">/, 'renderShell baut die Details-Box');
  assert.match(historyJs, /t\('tab\.historyHint'\)/, 'Kurzhinweis-Key gebunden');
  assert.match(historyJs, /t\('tab\.historyHintLong'\)/, 'Langtext-Key gebunden');
  assert.doesNotMatch(indexHtml, /history-info/, 'keine statische Info-Box in index.html (würde vom renderShell-Neuaufbau entfernt)');
  assert.match(historyCss, /\.history-info summary\s*\{[^}]*min-height:\s*44px/, 'summary mit 44-px-Touch-Ziel');
  assert.match(historyCss, /\.history-info-long\s*\{/, 'Langtext-Regel vorhanden');
  // (2) Feed-Panel: sichtbarer Archiv-Hinweis + aria-describedby an BEIDEN
  // Modus-Buttons (title/aria-Ergänzung, Persistenz-Scout).
  assert.match(indexHtml, /id="feed-archive-hint"[^>]*data-i18n="mode\.archiveHint"/, 'Hinweis-Zeile #feed-archive-hint');
  assert.equal((indexHtml.match(/aria-describedby="feed-archive-hint"/g) ?? []).length, 2, 'beide Modus-Buttons beschreiben den Hinweis');
  // (3) Wörterbuch-Verdrahtung: alle drei Keys je genau in EN und DE.
  for (const key of ['tab.historyHint', 'tab.historyHintLong', 'mode.archiveHint']) {
    assert.equal((i18nMjs.match(new RegExp(`'${key.replace(/\./g, '\\.')}':`, 'g')) ?? []).length, 2, `${key} in EN und DE`);
  }
});

/* ---------------- Cluster-Liste/Mega-Cluster (Design P2, 2026-10-06) ---------------- */

test('Bedeutungs-Vollrahmen: kein Linksbändchen, Bedeutung als border-color (Umbau 2026-10-07)', () => {
  // Das 3-px-Linksbändchen ist ersatzlos entfernt: Bedeutung (Severity/Rolle)
  // trägt jetzt der 1-px-Vollrahmen in derselben Token-Farbe (WCAG 1.4.11 —
  // alle Bedeutungsfarben ≥ 3:1 gegen beide Theme-Surfaces, siehe
  // CONTRAST_PAIRS). Kein Band-Token, kein border-left mehr im Stylesheet.
  assert.doesNotMatch(styleCss, /border-left/, 'kein border-left-Band mehr');
  assert.doesNotMatch(styleCss, /--a6-band-width/, 'Band-Token ersatzlos entfernt');
  // Basis-Vollrahmen: 1 px in neutraler Token-Farbe (1:1 die bisherige
  // Bandfarbe; .cluster-card steigt von der Alpha-card-line-Kante auf
  // control-line ≥ 3:1 — .hx-kpi behält --a6-card-line).
  const baseBorders = [
    ['.stat', 'var\\(--a6-line-strong\\)'],
    ['.block-card', 'var\\(--a6-line-strong\\)'],
    ['.log-row', 'var\\(--a6-muted\\)'],
    ['.cluster-card', 'var\\(--a6-control-line\\)'],
  ];
  for (const [sel, tokenRx] of baseBorders) {
    const block = styleCss.match(new RegExp(`${sel.replace('.', '\\.')}\\s*\\{[^}]*\\}`));
    assert.ok(block, `Regelblock ${sel} vorhanden`);
    assert.match(block[0], new RegExp(`border:\\s*1px solid ${tokenRx}`), `${sel}: 1px-Vollrahmen`);
  }
  // Varianten tragen die Bedeutung als border-color (alle vier Seiten).
  const variants = [
    ['.stat-malicious', '--a6-error'], ['.stat-suspect', '--a6-warn'],
    ['.stat-events', '--a6-brand-blue'],
    ['.block-card.has-malicious', '--a6-error'], ['.block-card.has-suspect', '--a6-warn'],
    ['.log-row.sev-malicious', '--a6-error'], ['.log-row.sev-suspect', '--a6-warn'],
    ['.log-row.sev-info', '--a6-info'],
    ['.cluster-card.role-source', '--a6-role-source'],
    ['.cluster-card.role-drainer', '--a6-role-drainer'],
    ['.cluster-card.role-collector', '--a6-role-collector'],
    ['.cluster-card.role-relay', '--a6-role-relay'],
    ['.cluster-card.role-unknown', '--a6-role-unknown'],
  ];
  for (const [sel, token] of variants) {
    const rx = sel.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    const rule = styleCss.match(new RegExp(`${rx}\\s*\\{[^}]*\\}`));
    assert.ok(rule, `Regel ${sel} vorhanden`);
    assert.match(rule[0], new RegExp(`border-color:\\s*var\\(${token}\\)`), `${sel} in ${token}`);
  }
  // Forced colors: die Band-Nachzieh-Blöcke sind ersatzlos weg — der
  // 1-px-CanvasText-Vollrahmen in den Sammellisten bleibt.
  assert.doesNotMatch(styleCss, /border-left-width/, 'kein forced-colors-Bandblock mehr (style.css)');
  // account-check.css (hardcodiertes 3px-Band) und drilldown.css (Forced-
  // colors-Artefakt ohne Normalmodus-Pendant) folgen demselben Muster.
  assert.doesNotMatch(accountCheckCss, /border-left/, 'check-card/check-report auf Vollrahmen');
  assert.doesNotMatch(drilldownCss, /border-left/, 'drilldown-Band-Artefakt entfernt');
  const checkCard = accountCheckCss.match(/\.check-card\s*\{[^}]*\}/);
  assert.ok(checkCard, '.check-card-Regel vorhanden');
  assert.match(checkCard[0], /border:\s*1px solid var\(--a6-control-line\)/, '.check-card: 1px-Vollrahmen');
  const checkReport = accountCheckCss.match(/\.check-report\s*\{[^}]*\}/);
  assert.ok(checkReport, '.check-report-Regel vorhanden');
  assert.match(checkReport[0], /border:\s*1px solid var\(--a6-line-strong\)/, '.check-report: 1px-Vollrahmen');
  const checkErr = accountCheckCss.match(/\.check-card-error\s*\{[^}]*\}/);
  assert.ok(checkErr, '.check-card-error-Regel vorhanden');
  assert.match(checkErr[0], /border-color:\s*var\(--a6-error\)/, 'Fehlerzustand als border-color');
});

test('Kleinradius-Token: --a6-r-xs definiert und von .swatch referenziert', () => {
  assert.match(styleCss, /--a6-r-xs:\s*3px;/, 'Token definiert');
  const swatch = styleCss.match(/\.swatch\s*\{[^}]*\}/);
  assert.ok(swatch, '.swatch-Regel vorhanden');
  assert.match(swatch[0], /border-radius:\s*var\(--a6-r-xs\)/, '.swatch auf Token');
});

test('Kopf-Tönung sev-malicious: SOLIDE error-soft-Fläche, kein Gradient (Plan-Kritik 7a)', () => {
  const rule = styleCss.match(/\.cluster-card\.sev-malicious \.cluster-head\s*\{[^}]*\}/);
  assert.ok(rule, 'Regel vorhanden');
  assert.match(rule[0], /background:\s*var\(--a6-error-soft\)/, 'solide Token-Fläche');
  assert.doesNotMatch(rule[0], /gradient/, 'kein Gradient im Kopf');
});

test('Drainer-Hervorhebung: Rollen-Chip auf error-soft + Rollen-Tokens', () => {
  const rule = styleCss.match(/\.role-chip\.role-drainer\s*\{[^}]*\}/);
  assert.ok(rule, 'Regel vorhanden');
  assert.match(rule[0], /background:\s*var\(--a6-error-soft\)/, 'error-soft-Fläche');
  assert.match(rule[0], /border-color:\s*var\(--a6-role-drainer-border\)/, 'Rollen-Randton');
  assert.match(rule[0], /color:\s*var\(--a6-role-drainer\)/, 'Rollen-Textton');
});

test('Verdichtung: Segment-Control (aria-pressed) in index.html, Persistierung + data-density in app.js', () => {
  assert.match(indexHtml, /<div class="cluster-density" role="group" id="cluster-density"/, 'Gruppe im panel-head');
  assert.equal((indexHtml.match(/class="graph-tab density-btn"/g) ?? []).length, 3, 'drei Stufen-Buttons auf .graph-tab-Basis (44-px-Ziel)');
  assert.match(indexHtml, /id="density-comfortable" aria-pressed="true"/, 'comfortable ist Initialzustand');
  assert.match(indexHtml, /id="density-compact" aria-pressed="false"/, 'compact inaktiv');
  assert.match(indexHtml, /id="density-dense" aria-pressed="false"/, 'dense inaktiv');
  assert.match(appJs, /DENSITY_KEY = 'hx-density'/, 'localStorage-Schlüssel hx-density');
  assert.match(appJs, /listEl\.setAttribute\('data-density', clusterDensity\)/, 'renderClusterList setzt data-density selbstheilend');
  assert.match(styleCss, /\.cluster-list\[data-density="compact"\] \.cluster-card\s*\{/, 'compact-Kartenregel');
  assert.match(styleCss, /\.cluster-list\[data-density="dense"\] \.cluster-xrp\s*\{/, 'dense-Primärmetrik-Regel');
  assert.match(styleCss, /\.density-btn\[aria-pressed="true"\]\s*\{[^}]*var\(--a6-ink-fill\)/, 'Auswahlfläche über aria-pressed auf Token');
});

test('Mega-Cluster: data-size="mega", Schwelle 100, EIN gemeinsamer +N-Hinweis (Plan-Kritik 10)', () => {
  assert.match(appJs, /MEGA_MEMBER_THRESHOLD = 100/, 'Schwellen-Konstante 100');
  assert.match(appJs, /' data-size="mega"'/, 'data-size-Attribut im Karten-Markup');
  assert.match(appJs, /t\('cluster\.megaNote'/, 'Meta-Zeile über i18n');
  assert.match(appJs, /t\('cluster\.moreAccounts',/, 'geteilter +N-Key mit der Chip-Zeile');
  assert.match(appJs, /t\('cluster\.moreAccountsTitle'/, 'title mit voller Mitgliederzahl');
  // Mega-Karten unterdrücken den Zweit-Hinweis in der Chip-Zeile und sammeln
  // stattdessen die gezeigte Zahl für die Meta-Zeile (keine Doppel-Hinweise).
  assert.match(appJs, /shownChipEntries = shown; return '';/, 'Mega: moreChip liefert leer und sammelt shown');
  assert.match(styleCss, /\.cluster-metrics-mega\s*\{/, 'zweizeiliger Mega-Metrik-Block');
  assert.match(styleCss, /\.cluster-mega-note\s*\{/, 'Mega-Meta-Zeile');
});

test('Cluster-Karten-i18n: alle neuen Keys in BEIDEN Wörterbüchern, DE-Umlaute korrekt', () => {
  const keys = [
    'cluster.moreAccounts', 'cluster.moreAccountsTitle', 'cluster.megaNote',
    'cluster.densityAria', 'cluster.densityComfortable', 'cluster.densityCompact', 'cluster.densityDense',
  ];
  for (const key of keys) {
    assert.equal((i18nMjs.match(new RegExp(`'${key.replace(/\./g, '\\.')}':`, 'g')) ?? []).length, 2, `${key} in EN und DE`);
  }
  // Deutsche Werte mit korrekten Umlauten (keine ASCII-Varianten, kein Mojibake).
  assert.match(i18nMjs, /'cluster\.moreAccounts': '\+\{n\} weitere Konten'/);
  assert.match(i18nMjs, /'cluster\.densityComfortable': 'Übersichtlich'/);
  assert.match(i18nMjs, /'cluster\.densityAria': 'Dichte der Cluster-Karten'/);
});

/* ---------------- Marke/SVG-System (Design P0/P1, 2026-10-06) ---------------- */

test('Speed-Budget: jede App-Eigendatei direkt in public/ ≤ 200 KB (Plan-Kritik 11)', () => {
  // Die 200-KB-Grenze gilt den App-Eigendateien direkt in public/ (HTML/CSS/
  // JS/MJS/SVG/JSON). vendor/ (gebündelte Fremd-Bundles mit eigenen Budgets),
  // fonts/ (woff2) und data/ (Lazy-Daten-Assets wie countries-50m.json) sind
  // bewusst außerhalb — sie werden nicht mit dem kritischen Pfad geladen.
  const files = readdirSync(here).filter((f) => /\.(html?|css|mjs|js|svg|json)$/i.test(f));
  assert.ok(files.length >= 24, `Dateiliste plausibel (bekannt: 28 Dateien), gefunden: ${files.length}`);
  let largest = '';
  let largestSize = 0;
  for (const f of files) {
    const size = statSync(path.join(here, f)).size;
    if (size > largestSize) { largest = f; largestSize = size; }
    assert.ok(size <= 200_000, `${f}: ${size} B > 200000 B Speed-Budget`);
  }
  // Größte Eigendatei bleibt app.js (bekannt ~148 KB nach Design P2) —
  // bricht dieser Schwellwert, hat eine Datei app.js überholt.
  assert.equal(largest, 'app.js', `app.js bleibt die größte Eigendatei (jetzt: ${largest})`);
});

test('Logo-/Wortmarken-CSS: .brand-Grid, .hp-drop auf Akzent-Token, XRPL in Mono ab 900 px', () => {
  assert.match(styleCss, /\.brand\s*\{[^}]*display: flex/, '.brand als Marke+Text-Zeile');
  assert.match(styleCss, /\.brand-mark\s*\{[^}]*width: 34px/, 'Logo-Box 34 px');
  assert.match(styleCss, /\.brand-mark \.hp-drop\s*\{[^}]*fill: var\(--a6-accent\)/, 'Tropfen auf Akzent-Token');
  assert.match(styleCss, /\.brand-mark \.hp-drop\s*\{[^}]*transition: fill var\(--a6-fast\)/, 'Hover-Transition 180 ms');
  assert.match(styleCss, /@media \(hover: hover\) and \(pointer: fine\)\s*\{[\s\S]{0,200}\.brand:hover \.brand-mark \.hp-drop\s*\{\s*fill: var\(--a6-accent-hi\)/, 'Hover nur bei echtem Zeiger');
  assert.match(styleCss, /@media \(prefers-reduced-motion: reduce\)\s*\{[\s\S]{0,200}\.brand-mark \.hp-drop\s*\{\s*transition: none/, 'reduced-motion-Pendant');
  // Wortmarke ohne dritte Schriftfamilie: XRPL-Anhang in JetBrains Mono.
  assert.match(styleCss, /@media \(min-width: 900px\)\s*\{[\s\S]{0,400}\.brand h1\s*\{[^}]*text-transform: uppercase/, 'Versalen ab 900 px');
  assert.match(styleCss, /\.brand h1 \.brand-xrpl\s*\{[^}]*font-family: var\(--a6-mono\)/, 'XRPL in Mono');
});

/* ---------------- 3D-Bühnen (Design P3, 2026-10-06) ---------------- */

test('3D-Canvas: transparenter Clear statt Vollweiß — Punkt-Substrat + Vignette auf .cluster-3d', () => {
  // drilldown.js: backgroundColor('rgba(0,0,0,0)') (am gepinnten Bundle
  // 3d-force-graph@1.80.0 Browser-verifiziert: Alpha wird an setClearColor
  // gereicht, Renderer läuft mit alpha:true).
  assert.match(drilldownJs, /\.backgroundColor\('rgba\(0,0,0,0\)'\)/, 'transparenter Clear gesetzt');
  assert.doesNotMatch(drilldownJs, /backgroundColor\('#ffffff'\)/, 'kein Vollweiß-Fallback mehr im Canvas-Clear');
  // .cluster-3d: zwei Rasterebenen (24 px fein + 96 px versetzt) über der
  // Token-Bühnenfläche — sparsames Substrat statt Partikel-Meer, reines CSS.
  const stage = drilldownCss.match(/\.cluster-3d\s*\{[^}]*\}/);
  assert.ok(stage, '.cluster-3d-Regel vorhanden');
  assert.match(stage[0], /radial-gradient\(var\(--a6-graph-grid\) 1px, transparent 1px\) 0 0 \/ 24px 24px/, 'feines 24-px-Punktraster');
  assert.match(stage[0], /radial-gradient\(var\(--a6-graph-grid\) 1px, transparent 1px\) 12px 12px \/ 96px 96px/, 'versetztes 96-px-Sekundärraster');
  assert.match(stage[0], /var\(--a6-graph-canvas\)/, 'Token-Bühnenfläche als Untergrund');
  assert.doesNotMatch(stage[0], /#fff/, 'keine Weiß-Literale in der Bühne');
  // Dezente inset-Vignette (Raumtiefe ohne Glow) …
  assert.match(stage[0], /box-shadow:\s*inset 0 -40px 80px -60px rgba\(20, 20, 22, 0\.06\)/, 'Vignette');
  // … die forced-colors zurücknimmt (bestehender Block erweitert .cluster-3d).
  const fc = drilldownCss.slice(drilldownCss.indexOf('@media (forced-colors: active)'));
  assert.match(fc, /\.cluster-3d,[\s\S]{0,500}?box-shadow:\s*none/, 'forced-colors: Vignette aus');
});

test('3D-Hover-Cursor: .is-hover-node-Klasse an drilldown.js gebunden, Regel in drilldown.css', () => {
  assert.match(drilldownJs, /classList\.toggle\('is-hover-node'/, 'drilldown.js toggelt die Cursor-Klasse (onNodeHover)');
  assert.match(drilldownCss, /\.cluster-3d\.is-hover-node canvas\s*\{[^}]*cursor:\s*pointer/, 'Zeiger-Cursor über Knoten');
  // Degradation prefers-reduced-motion: Farb-/Breiten-Fokus im Hover-Handler
  // vor den Accessor-Settern abgebrochen (Cursor bleibt erlaubt).
  assert.match(
    drilldownJs,
    /function on3dNodeHover[\s\S]{0,400}?if \(reducedMotion\(\)\) return;/,
    'Hover-Fokus unter reduced motion deaktiviert',
  );
});

test('Drainer-Ring: additiver Extend (Plan-Kritik 8), Deckel 12, opak ohne Emissive (Plan-Kritik 7b), Legende via i18n', () => {
  assert.match(drilldownJs, /nodeThreeObjectExtend\(true\)/, 'Ring ADDITIV — Bundle-Default-Sphere bleibt erhalten');
  assert.match(drilldownJs, /export const GRAPH3D_RING_CAP = 12;/, 'Halo-Deckel 12 als Konstante');
  // Material-Optionsblock des Rings: opacity 0.9 und bewusst KEIN emissive.
  const mat = drilldownJs.match(/new cls\.MeshLambertMaterial\(\{[\s\S]{0,400}?\}\)/);
  assert.ok(mat, 'Ring-Material-Konstruktion gefunden');
  assert.match(mat[0], /opacity:\s*0\.9/, 'opak 0.9');
  assert.doesNotMatch(mat[0], /emissive/, 'kein Emissive (lab_graphite: kein Glow)');
  // Ring-Farbe über die Rollen-/Severity-Token der Host-ctx (#b3261e =
  // --a6-role-drainer = --a6-sev-malicious), Fallback derselbe Wert.
  assert.match(mat[0], /drainer && drainer\.background \? drainer\.background : '#b3261e'/, 'Rollen-Token mit identischem Fallback');
  // Legende: nur anzeigen, was gerendert wurde (Zähl-Verdrahtung) …
  assert.match(drilldownJs, /updateRingLegend\(count3dRings\(\)\)/, 'Legende an tatsächliche Ringzahl gekoppelt');
  assert.match(drilldownJs, /t\('modal\.graph3dLegend'\)/, 'Legendentext über i18n');
  // … und der Schlüssel in BEIDEN Wörterbüchern (EN/DE-Parität).
  assert.equal((i18nMjs.match(/'modal\.graph3dLegend':/g) ?? []).length, 2, 'modal.graph3dLegend in EN und DE');
  assert.match(i18nMjs, /'modal\.graph3dLegend': 'Ring um einen Knoten = Drainer-Konto\.'/, 'DE-Legende mit korrektem Umlaut/Graden');
});

test('Globe-Bühne: dasselbe Punkt-Substrat (96-px-Ebene) + Vignette, forced-colors-Rücknahme, globe.js unangetastet', () => {
  const globeRule = globeCss.match(/#globe\s*\{[^}]*\}/);
  assert.ok(globeRule, '#globe-Regel vorhanden');
  assert.match(globeRule[0], /radial-gradient\(var\(--a6-graph-grid\) 1px, transparent 1px\) 0 0 \/ 24px 24px/, '24-px-Raster bleibt');
  assert.match(globeRule[0], /radial-gradient\(var\(--a6-graph-grid\) 1px, transparent 1px\) 12px 12px \/ 96px 96px/, '96-px-Sekundärraster wie .cluster-3d');
  assert.match(globeRule[0], /box-shadow:\s*inset 0 -40px 80px -60px rgba\(20, 20, 22, 0\.06\)/, 'Vignette identisch zur Drilldown-Bühne');
  const fc = globeCss.slice(globeCss.indexOf('@media (forced-colors: active)'));
  assert.match(fc, /#globe\s*\{[^}]*box-shadow:\s*none/, 'forced-colors: Vignette aus');
  assert.match(globeCss, /globe\.js selbst bleibt unangetastet/, 'Dokumentation: WebGL-Seite unverändert');
});

test('3D-Speed-Budget: kein Postprocessing, keine neue Abhängigkeit, Deckel unverändert', () => {
  // Kommentare streifen: die Doku nennt die verbotenen Stichworte selbst
  // („kein EffectComposer/Bloom") — geprüft wird der CODE.
  const code = drilldownJs.replace(/\/\*[\s\S]*?\*\//g, '').replace(/\/\/[^\n]*/g, '');
  assert.doesNotMatch(code, /EffectComposer|Bloom|SSAO|postprocessing/i, 'kein Postprocessing');
  assert.match(code, /GRAPH3D_MAX_NODES = 300;/, 'Knoten-Deckel 300 bleibt');
  assert.match(code, /linkDirectionalParticles\(\(l\) => \(String\(l\.type\) === 'Payment' && !reducedMotion\(\) \? 2 : 0\)\)/, 'Partikel-Deckel 2 mit reduced-motion-Gate bleibt');
  // Kein neues Vendor-Asset und kein window.THREE-Injektionsversuch (das
  // Bundle LIEST window.THREE nur — eigene three-Kopie wäre ein neues
  // schweres Asset und verletzt das Speed-Budget). Die Ring-Klassen werden
  // aus Instanzen der aktiven Instanz rekonstruiert (resolve3dRingClasses).
  assert.doesNotMatch(code, /window\.THREE\s*=/, 'kein injiziertes window.THREE');
  assert.match(code, /import \{ t, fmtNum, fmtClock, sevText, getLang \} from '\.\/i18n\.mjs';/, 'Import-Set unverändert (keine neue Abhängigkeit)');
});

/* ---------------- Noir-Theme (data-theme="noir", 2026-10-06) ----------------
 * Extraktion der Token-Blöcke: [data-a6] (Hell/SSOT) und
 * [data-a6][data-theme="noir"] (Overrides). Beide Blöcke sind
 * klammerfrei in den Deklarationen — die non-grease \n}-Grenze greift. */

const lightBlock = styleCss.match(/\[data-a6\]\s*\{[\s\S]*?\n\}/);
const noirBlock = styleCss.match(/\[data-a6\]\[data-theme="noir"\]\s*\{[\s\S]*?\n\}/);

function parseTokens(block) {
  const map = {};
  for (const m of block.matchAll(/(--a6-[a-z0-9-]+)\s*:\s*([^;]+);/g)) {
    map[m[1]] = m[2].trim();
  }
  return map;
}

const lightTokens = parseTokens(lightBlock[0]);
const noirTokens = parseTokens(noirBlock[0]);
const noirView = { ...lightTokens, ...noirTokens }; // Noir = Light + Overrides

test('Noir: Token-Override-Block vollständig (Flächen, Status, Akzent, Graph, Kanten, Rollen, Swatches, Stage) + color-scheme: dark', () => {
  assert.ok(lightBlock, '[data-a6]-Light-Block gefunden');
  assert.ok(noirBlock, '[data-a6][data-theme="noir"]-Block gefunden');
  assert.match(noirBlock[0], /color-scheme:\s*dark/, 'Scrollbars/Form-Controls dunkel');
  // Vollständigkeitsliste: jeder Token, den eine Komponente in Noir anders
  // braucht, MUSS im Override-Block stehen (sonst leckt Hell durch).
  const required = [
    '--a6-bg', '--a6-surface', '--a6-surface-alt', '--a6-ink', '--a6-body', '--a6-muted',
    '--a6-line', '--a6-line-strong', '--a6-control-line', '--a6-focus',
    '--a6-error', '--a6-error-soft', '--a6-warn', '--a6-warn-soft',
    '--a6-success', '--a6-success-soft', '--a6-info', '--a6-info-soft',
    '--a6-inset-highlight', '--a6-e1', '--a6-e2', '--a6-e3',
    '--a6-accent', '--a6-accent-hi', '--a6-accent-text', '--a6-on-accent', '--a6-accent-soft',
    '--a6-brand-blue', '--a6-brand-teal', '--a6-brand-amber',
    '--a6-graph-canvas', '--a6-graph-grid', '--a6-graph-line', '--a6-graph-line-soft',
    '--a6-cluster-fill', '--a6-cluster-border', '--a6-cluster-hover',
    '--a6-edge-payment', '--a6-edge-market', '--a6-edge-escrow',
    '--a6-edge-admin', '--a6-edge-check', '--a6-edge-nft', '--a6-edge-fraud', '--a6-edge-neutral', '--a6-edge-ink',
    '--a6-role-source', '--a6-role-source-border', '--a6-role-drainer', '--a6-role-drainer-border',
    '--a6-role-collector', '--a6-role-collector-border', '--a6-role-relay', '--a6-role-relay-border',
    '--a6-role-unknown',
    '--a6-sev-malicious', '--a6-sev-suspect', '--a6-sev-info', '--a6-sev-neutral',
    '--a6-ink-fill', '--a6-on-ink', '--a6-card-line',
    '--a6-swatch-payment', '--a6-swatch-other', '--a6-swatch-unknown', '--a6-swatch-unknown-line',
    '--a6-swatch-cluster-line', '--a6-unknown-fill',
    '--a6-stage-bg', '--a6-stage-glow', '--a6-globe-atmosphere',
  ];
  const missing = required.filter((t) => !(t in noirTokens));
  assert.deepEqual(missing, [], 'fehlende Noir-Overrides');
  // Spot-Werte: die Noir-Identität (Indigo-Schwarz + Violett-Akzent) und die
  // PFLICHTKORREKTUR-8-unknown-Tafel.
  assert.equal(noirTokens['--a6-bg'], '#0a0c0f');
  assert.equal(noirTokens['--a6-ink'], '#eef2f6');
  assert.equal(noirTokens['--a6-accent'], '#8fb8dc');
  assert.equal(noirTokens['--a6-edge-neutral'], '#8c96a2');
  assert.equal(noirTokens['--a6-on-ink'], '#0a0c0f');
  assert.equal(noirTokens['--a6-cluster-fill'], '#161a20');
  // Unknown-Tafel (3D-Farb-Audit 2026-10-07): swatch = --a6-role-unknown
  // (Eisblau, 13.69:1 auf der Bühne), Rand #46587e = 5.29:1 auf der Füllung.
  assert.equal(noirTokens['--a6-swatch-unknown'], '#bfe3ff');
  assert.equal(noirTokens['--a6-swatch-unknown-line'], '#46587e');
  assert.equal(noirTokens['--a6-role-unknown'], '#bfe3ff');
  // Hell bleibt unangetastet (Spot): die SSOT-Werte stehen weiter im Light-Block.
  assert.equal(lightTokens['--a6-bg'], '#f6f6f7');
  assert.equal(lightTokens['--a6-accent'], '#ec5b00');
  assert.equal(lightTokens['--a6-on-ink'], '#ffffff');
  assert.equal(lightTokens['--a6-role-unknown'], '#4a6478');
});

test('Noir: keine hartcodierten Hex außerhalb der beiden Token-Blöcke (style.css)', () => {
  const stripped = styleCss.replace(/\/\*[\s\S]*?\*\//g, '');
  const rest = stripped
    .replace(/\[data-a6\]\s*\{[\s\S]*?\n\}/, '') // erster Treffer = Light-Block
    .replace(/\[data-a6\]\[data-theme="noir"\]\s*\{[\s\S]*?\n\}/, '');
  // \b-Grenze: ID-Selektoren (#feed-more) matchen nicht (Wortzeichen nach
  // dem Hex-Präfix erzeugen keine Grenze); Farbwerte (#fff/#ffffff) schon.
  const leaks = [...rest.matchAll(/#[0-9a-fA-F]{3,8}\b/g)].map((m) => m[0]);
  assert.deepEqual(leaks, [], 'Hex-Literale außerhalb der Token-Blöcke');
});

test('Noir: color:#fff entfernt — Auswahl-/Pressed-/Primär-Regeln auf --a6-on-ink', () => {
  for (const [name, css] of [['style.css', styleCss], ['account-check.css', accountCheckCss]]) {
    assert.doesNotMatch(css, /color:\s*#fff(?:fff)?\s*;/, `${name}: kein hartcodiertes Weiß als Textfarbe`);
  }
  for (const sel of [
    String.raw`\.graph-tab\[aria-selected="true"\]`,
    String.raw`\.view-tab\[aria-current="page"\]`,
    String.raw`\.density-btn\[aria-pressed="true"\]`,
    String.raw`\.lang-btn\[aria-pressed="true"\]`,
  ]) {
    const rule = styleCss.match(new RegExp(`${sel}\\s*\\{[^}]*\\}`));
    assert.ok(rule, `Regel ${sel} vorhanden`);
    assert.match(rule[0], /color:\s*var\(--a6-on-ink\)/, `${sel} auf on-ink`);
  }
  const go = accountCheckCss.match(/#check-go\s*\{[^}]*\}/);
  assert.ok(go, '#check-go-Regel vorhanden');
  assert.match(go[0], /color:\s*var\(--a6-on-ink\)/, '#check-go auf on-ink');
  // Weitere Tokenisierungen des Noir-Umbaus (Spot-Guards):
  assert.match(styleCss, /\.badge-info\s*\{[^}]*var\(--a6-info-soft\)/, 'badge-info-Fläche auf Token');
  assert.match(styleCss, /\.swatch-cluster\s*\{[^}]*var\(--a6-cluster-fill\)/, 'Cluster-Swatch auf Token');
  assert.match(styleCss, /\.swatch-escrow\s*\{[^}]*var\(--a6-edge-escrow\)/, 'escrow-Swatch auf Token');
  assert.match(styleCss, /\.swatch-check\s*\{[^}]*var\(--a6-edge-check\)/, 'check-Swatch auf Token');
  assert.match(styleCss, /\.hx-stage\s*\{[^}]*background:\s*var\(--a6-stage-bg\)/, 'Bühnen-Verlauf auf Token');
  assert.match(styleCss, /\.hx-stage::before\s*\{[^}]*background:\s*var\(--a6-stage-glow\)/, 'Bühnen-Glow auf Token');
  assert.match(styleCss, /\.hx-kpi\s*\{[^}]*border:\s*1px solid var\(--a6-card-line\)/, 'KPI-Rand auf card-line');
  assert.match(styleCss, /--a6-e1:\s*var\(--a6-inset-highlight\)/, 'Elevation nutzt das Inset-Token');
});

test('Noir: Theme-Default + Bootstrap + Toggle-Container in allen drei HTML-Seiten', () => {
  for (const [name, html] of [
    ['index.html', indexHtml],
    ['about.html', aboutHtml],
    ['history-host.html', historyHostHtml],
  ]) {
    assert.match(html, /<body data-a6 data-theme="noir">/, `${name}: Noir als statischer Default (kein FOUC)`);
    assert.match(html, /meta name="theme-color" content="#0a0c0f"/, `${name}: Browser-Chrome in Noir-Farbe`);
    assert.match(html, /localStorage\.getItem\('hx-theme'\)\s*===\s*'light'/, `${name}: Bootstrap liest 'hx-theme'`);
    assert.match(html, /document\.body\.dataset\.theme = 'light'/, `${name}: Bootstrap schaltet Hell vor dem ersten Paint`);
    assert.match(html, /<div class="theme-switch" id="theme-switch"><\/div>/, `${name}: Toggle-Container neben dem Sprachumschalter`);
    // index.html verdrahtet über app.js (Host-Modul), die Nebenseiten über
    // ihr Inline-Modul.
    if (html === indexHtml) {
      assert.match(appJs, /initThemeSwitcher\(document\.getElementById\('theme-switch'\)\)/, 'app.js verdrahtet den Umschalter');
    } else {
      assert.match(html, /initThemeSwitcher\(document\.getElementById\('theme-switch'\)\)/, `${name}: Umschalter verdrahtet`);
    }
  }
  // Schlüssel-Hygiene: 'hx-theme' kollidiert nicht mit 'hx-lang'/'hx-density'.
  assert.equal(THEME_KEY, 'hx-theme');
  assert.notEqual(THEME_KEY, 'hx-lang');
  assert.notEqual(THEME_KEY, 'hx-density');
});

test('Noir: Theme-Mechanik im DOM-Fixture — Toggle, Persistenz, Event, aria', () => {
  // Stubs (Muster lib/i18n.test.mjs: globalThis je Test setzen, in finally
  // zurückstellen). CustomEvent nur stubben, wenn die Laufzeit ihn fehlt.
  const store = new Map();
  const storageStub = {
    getItem: (k) => (store.has(k) ? store.get(k) : null),
    setItem: (k, v) => { store.set(k, String(v)); },
  };
  const listeners = {};
  const metaAttrs = {};
  const docStub = {
    body: { dataset: { theme: 'noir' } }, // HTML-Default: Noir statisch
    querySelector: (sel) => (sel === 'meta[name="theme-color"]'
      ? { setAttribute: (k, v) => { metaAttrs[k] = v; } }
      : null),
    addEventListener: (type, fn) => { (listeners[type] = listeners[type] || []).push(fn); },
    dispatchEvent: (ev) => { for (const fn of listeners[ev.type] ?? []) fn(ev); return true; },
    createElement: () => {
      const attrs = {};
      const elListeners = {};
      return {
        type: '', className: '', textContent: '',
        attrs, elListeners,
        setAttribute(k, v) { attrs[k] = v; },
        getAttribute(k) { return k in attrs ? attrs[k] : null; },
        addEventListener(type, fn) { (elListeners[type] = elListeners[type] || []).push(fn); },
      };
    },
  };
  const prevStorage = globalThis.localStorage;
  const prevDoc = globalThis.document;
  const prevCustomEvent = globalThis.CustomEvent;
  if (prevCustomEvent === undefined) {
    globalThis.CustomEvent = class { constructor(type, opts) { this.type = type; this.detail = opts?.detail; } };
  }
  globalThis.localStorage = storageStub;
  globalThis.document = docStub;
  try {
    // Default und Validierung.
    assert.equal(DEFAULT_THEME, 'noir');
    assert.deepEqual(THEMES, ['noir', 'light']);
    assert.equal(getTheme(), 'noir', 'ohne Storage: Noir');
    // setTheme validiert, persistiert, wendet an und sendet das Event.
    let themeEvents = 0;
    docStub.addEventListener('hx:themechange', () => { themeEvents += 1; });
    assert.equal(setTheme('light'), 'light');
    assert.equal(docStub.body.dataset.theme, 'light');
    assert.equal(store.get(THEME_KEY), 'light');
    assert.equal(metaAttrs.content, THEME_META_COLORS.light, 'meta theme-color hell');
    assert.equal(themeEvents, 1, 'hx:themechange gesendet');
    assert.equal(setTheme('bogus'), 'noir', 'ungültiger Wert fällt auf den Default');
    assert.equal(docStub.body.dataset.theme, 'noir');
    assert.equal(metaAttrs.content, THEME_META_COLORS.noir, 'meta theme-color noir');
    assert.equal(resolveTheme('light', storageStub), 'light', 'resolveTheme persistiert injiziert');
    assert.equal(store.get(THEME_KEY), 'light');
    // Toggle-Fixture: EIN Button, aria-pressed spiegelt Noir, Klick wechselt.
    // Deterministischer Start: Storage/Body zurück auf Noir (HTML-Default).
    store.delete(THEME_KEY);
    docStub.body.dataset.theme = 'noir';
    const themeEventsBefore = themeEvents;
    const container = {
      attrs: {},
      children: [],
      setAttribute(k, v) { this.attrs[k] = v; },
      appendChild(el) { this.children.push(el); },
    };
    const switcher = initThemeSwitcher(container);
    assert.ok(switcher && typeof switcher.sync === 'function', 'initThemeSwitcher liefert sync');
    assert.equal(container.attrs.role, 'group');
    assert.ok(container.attrs['aria-label'] && container.attrs['aria-label'].length > 0, 'Gruppe trägt aria-label');
    const btn = container.children[0];
    assert.ok(btn, 'genau ein Button im Container');
    assert.equal(container.children.length, 1, 'EIN Toggle-Button (kein zweites Sprach-Muster)');
    assert.equal(btn.className, 'lang-btn theme-btn', 'Pille via .lang-btn-Komposition, Identität via .theme-btn');
    assert.equal(btn.getAttribute('aria-pressed'), 'true', 'Noir aktiv → pressed');
    assert.ok(btn.getAttribute('aria-label'), 'Button trägt die Aktions-Beschreibung');
    // Echter Klick-Pfad über den registrierten Button-Handler:
    assert.equal(themeEvents, themeEventsBefore, 'Vorbedingung: noch kein Theme-Event');
    for (const fn of btn.elListeners.click ?? []) fn();
    assert.equal(docStub.body.dataset.theme, 'light', 'Klick wechselt Noir → Hell');
    assert.equal(btn.getAttribute('aria-pressed'), 'false', 'aria-pressed nach dem Wechsel');
    assert.equal(store.get(THEME_KEY), 'light', 'Wahl persistiert');
    assert.equal(themeEvents, themeEventsBefore + 1, 'Klick sendet genau ein Event');
    assert.ok(btn.textContent.length > 0, 'Label zeigt den aktuellen Theme-Namen');
    // sync-Rückruf (z. B. nach hx:langchange) stellt Label/aria wieder her.
    switcher.sync();
    assert.equal(btn.getAttribute('aria-pressed'), 'false');
    // Ungültiger Wert fällt auf den Default und sendet ebenfalls ehrlich.
    assert.equal(setTheme('bogus'), 'noir');
    assert.equal(docStub.body.dataset.theme, 'noir');
    assert.equal(metaAttrs.content, THEME_META_COLORS.noir, 'meta theme-color noir');
    assert.equal(resolveTheme('light', storageStub), 'light', 'resolveTheme persistiert injiziert');
    assert.equal(store.get(THEME_KEY), 'light');
  } finally {
    if (prevStorage === undefined) delete globalThis.localStorage; else globalThis.localStorage = prevStorage;
    if (prevDoc === undefined) delete globalThis.document; else globalThis.document = prevDoc;
    if (prevCustomEvent === undefined) delete globalThis.CustomEvent; else globalThis.CustomEvent = prevCustomEvent;
  }
});

/* ---------------- Noir-Kontrast (WCAG 2.x, beide Themes) ---------------- */

function hexLuminance(hex) {
  const m = /^#([0-9a-f]{6})$/i.exec(String(hex ?? ''));
  if (!m) return null;
  const lin = (h) => {
    const v = parseInt(h, 16) / 255;
    return v <= 0.03928 ? v / 12.92 : ((v + 0.055) / 1.055) ** 2.4;
  };
  return 0.2126 * lin(m[1].slice(0, 2)) + 0.7152 * lin(m[1].slice(2, 4)) + 0.0722 * lin(m[1].slice(4, 6));
}

function contrastRatio(fg, bg) {
  const l1 = hexLuminance(fg);
  const l2 = hexLuminance(bg);
  if (l1 === null || l2 === null) return null;
  return (Math.max(l1, l2) + 0.05) / (Math.min(l1, l2) + 0.05);
}

// rgba-Soft-Fläche komposit über der Surface (so rendert der Browser sie).
function compositeOver(rgba, bgHex) {
  const m = /^rgba?\(\s*(\d+)[,\s]+(\d+)[,\s]+(\d+)(?:[,\s/]+([\d.]+))?\s*\)$/i.exec(String(rgba ?? ''));
  if (!m) return rgba; // opak
  const bg = bgHex.replace('#', '');
  const a = m[4] !== undefined ? parseFloat(m[4]) : 1;
  const ch = (fg, i) => Math.round(parseInt(fg, 10) * a + parseInt(bg.slice(i, i + 2), 16) * (1 - a));
  const c = [ch(m[1], 0), ch(m[2], 2), ch(m[3], 4)];
  return '#' + c.map((v) => v.toString(16).padStart(2, '0')).join('');
}

const CONTRAST_PAIRS = [
  // [Token fg, Token bg, Mindestkontrast, Art]
  ['ink', 'bg', 4.5, 'Text'], ['ink', 'surface', 4.5, 'Text'], ['ink', 'surface-alt', 4.5, 'Text'],
  ['body', 'surface', 4.5, 'Text'], ['body', 'surface-alt', 4.5, 'Text'],
  ['muted', 'surface', 4.5, 'Text'], ['muted', 'surface-alt', 4.5, 'Text'],
  ['control-line', 'surface', 3, 'UI'], ['control-line', 'surface-alt', 3, 'UI'],
  ['sev-neutral', 'surface-alt', 3, 'UI'],
  ['error', 'surface', 4.5, 'Text'], ['warn', 'surface', 4.5, 'Text'],
  ['success', 'surface', 4.5, 'Text'], ['info', 'surface', 4.5, 'Text'],
  ['error', 'surface-alt', 4.5, 'Text'], ['warn', 'surface-alt', 4.5, 'Text'],
  ['success', 'surface-alt', 4.5, 'Text'], ['info', 'surface-alt', 4.5, 'Text'],
  ['on-ink', 'ink-fill', 4.5, 'Text'],
  ['brand-blue', 'surface', 4.5, 'Text'], ['brand-teal', 'surface', 4.5, 'Text'], ['brand-amber', 'surface', 4.5, 'Text'],
  ['accent', 'surface', 3, 'UI'], ['on-accent', 'accent', 4.5, 'Text'], ['accent-text', 'surface', 4.5, 'Text'],
  ['cluster-border', 'cluster-fill', 3, 'UI'],
  ['edge-payment', 'surface', 3, 'UI'], ['edge-market', 'surface', 3, 'UI'],
  ['edge-escrow', 'surface', 3, 'UI'], ['edge-admin', 'surface', 3, 'UI'], ['edge-check', 'surface', 3, 'UI'],
  ['edge-nft', 'surface', 3, 'UI'], ['edge-fraud', 'surface', 3, 'UI'],
  ['edge-nft', 'surface', 3, 'UI'], ['edge-neutral', 'surface', 3, 'UI'], ['edge-neutral', 'surface-alt', 3, 'UI'],
  ['edge-ink', 'surface', 3, 'UI'],
  ['role-source', 'surface', 3, 'UI'], ['role-source-border', 'surface', 3, 'UI'],
  ['role-drainer', 'surface', 3, 'UI'], ['role-drainer-border', 'surface', 3, 'UI'],
  ['role-collector', 'surface', 3, 'UI'], ['role-collector-border', 'surface', 3, 'UI'],
  ['role-relay', 'surface', 3, 'UI'], ['role-relay-border', 'surface', 3, 'UI'],
  ['role-unknown', 'surface', 3, 'UI'], ['role-unknown', 'surface-alt', 3, 'UI'],
  ['swatch-unknown-line', 'swatch-unknown', 3, 'UI'],
  // 3D-Farb-Audit 2026-10-07: die Unknown-Swatch ist die 3D-Kugelfarbe —
  // dauerhaft ≥3:1 gegen BEIDE Bühnen-Token (graph-canvas) und die Karten-
  // Surface verankert (Hell 6.20 / Noir 13.69, vorher 1.14 bzw. 1.21 FAIL).
  ['swatch-unknown', 'graph-canvas', 3, 'UI'], ['swatch-unknown', 'surface', 3, 'UI'],
  ['swatch-other', 'surface', 3, 'UI'],
];

test('Noir: Kontrast-Regeltests der Kern-Paare — berechnet aus den Token-Werten, BEIDE Themes (Text ≥ 4.5, UI ≥ 3)', () => {
  for (const [themeName, tokens] of [['Hell', lightTokens], ['Noir', noirView]]) {
    const messages = [];
    for (const [fgKey, bgKey, min, kind] of CONTRAST_PAIRS) {
      const fg = tokens[`--a6-${fgKey}`];
      const bg = tokens[`--a6-${bgKey}`];
      assert.ok(fg, `${themeName}: Token --a6-${fgKey} fehlt`);
      assert.ok(bg, `${themeName}: Token --a6-${bgKey} fehlt`);
      const ratio = contrastRatio(fg, bg);
      assert.ok(ratio !== null, `${themeName}: --a6-${fgKey} ist kein 6-stelliger Hex (${fg})`);
      if (ratio < min) messages.push(`--a6-${fgKey} auf --a6-${bgKey}: ${ratio.toFixed(2)} < ${min} (${kind})`);
    }
    // Severity-Text auf der KOMPOSITEN Soft-Fläche (rgba über Surface).
    for (const [softKey, fgKey] of [
      ['error-soft', 'error'], ['warn-soft', 'warn'], ['success-soft', 'success'], ['info-soft', 'info'],
    ]) {
      const surfaceComposite = compositeOver(tokens[`--a6-${softKey}`], tokens['--a6-surface']);
      const ratio = contrastRatio(tokens[`--a6-${fgKey}`], surfaceComposite);
      assert.ok(ratio !== null, `${themeName}: Soft-Komposit ${softKey} nicht berechenbar`);
      if (ratio < 4.5) messages.push(`--a6-${fgKey} auf ${softKey}(komposit): ${ratio.toFixed(2)} < 4.5 (Text)`);
    }
    assert.deepEqual(messages, [], `${themeName}: Kontrast-Verletzungen`);
  }
});

test('Noir: JS-Canvas-Paletten — THEME_JS_COLORS deckt Kanten/Rollen (inkl. unknown)/Cluster+Fonts ab, Module folgen', () => {
  // app.js: Tafel vorhanden, Light-Werte = heutige Literale, Noir-Werte =
  // Token-Tafel (Spot), unknown AUSDRÜCKLICH in beiden Themes.
  assert.match(appJs, /const THEME_JS_COLORS = \{/, 'THEME_JS_COLORS definiert');
  assert.match(appJs, /function applyThemeColors\(theme\)/, 'applyThemeColors definiert');
  assert.match(appJs, /applyThemeColors\(currentJsTheme\(\)\);/, 'Startwert vor dem ersten Canvas-Render angewandt');
  assert.match(appJs, /network\.setOptions\(/, 'vis-Options-Defaults über setOptions nachgeführt (Konstruktions-Lesezeit)');
  assert.match(appJs, /edgeDefault: \(\) => EDGE_DEFAULT/, 'edgeDefault als Theme-Thunk in beiden ctx');
  // Light-Spots (Farb-Audit 2026-10-07: Kanten je Tx-KATEGORIE — payment =
  // success-Grün statt Rot, nft Fuchsia statt Alt-Violett):
  assert.match(appJs, /payment: '#066348', \/\/ = --a6-edge-payment = --a6-success/, 'Light-Payment = success-Familie (grün)');
  assert.match(appJs, /nft: '#c026d3'/, 'Light-NFT = Fuchsia (escrow-Abstand 1.51:1)');
  assert.match(appJs, /fraud: '#b3261e'/, 'Fraud-Override-Token Hell');
  // Noir-Spots: payment = --a6-success exakt, nft Fuchsia (escrow 1.52 / payment 1.98).
  assert.match(appJs, /payment: '#4ade80'/, 'Noir-Payment = --a6-success (Bundlung dokumentiert)');
  assert.match(appJs, /nft: '#d946ef'/, 'Noir-NFT = Fuchsia');
  // Unknown-Spots (3D-Farb-Audit 2026-10-07): Stahlblau (Hell) / Eisblau
  // (Noir), dieselben Werte wie --a6-swatch-unknown/--a6-role-unknown.
  assert.match(appJs, /background: '#4a6478', border: '#dbe6f2'/, 'Light-unknown = Stahlblau (6.20:1 auf der Bühne)');
  // Noir-Spots (PFLICHTKORREKTUR 7/8: unknown + Canvas-Fonts):
  assert.match(appJs, /canvasInk: '#eef2f6'/, 'Noir-Canvas-Ink = --a6-ink');
  assert.match(appJs, /canvasBody: '#c9c7d6'/, 'Noir-Canvas-Body = --a6-body');
  assert.match(appJs, /unknown: \{ background: '#bfe3ff', border: '#46587e'/, 'Noir-unknown = Eisblau auf Swatch-Teller (13.69:1 auf der Bühne)');
  assert.match(appJs, /fontColor: '#eef2f6'/, 'Noir-Cluster-Font hell');
  // Renderpfade lesen die theme-geführten Variablen statt Hex (die
  // Initialwerte der Tabellen selbst sind bewusst die Hell-Literale —
  // applyThemeColors mutiert sie in place; geprüft wird der RENDER-PFAD):
  assert.match(appJs, /font: \{ color: canvasInk, size: 13/, 'initGraph-Knotenfont theme-geführt');
  assert.match(appJs, /color: \{ color: EDGE_DEFAULT, highlight: canvasInk, hover: canvasInk \}/, 'Rohkanten theme-geführt');
  assert.match(appJs, /font: \{ color: canvasBody, size: 12/, 'Rohkanten-Font theme-geführt');
  assert.match(appJs, /getPropertyValue\('--a6-graph-canvas'\)/, 'PNG-Export über den Bühnen-Token');
  assert.doesNotMatch(appJs.replace(/\/\*[\s\S]*?\*\//g, '').replace(/\/\/[^\n]*/g, '').replace(/const THEME_JS_COLORS = \{[\s\S]*?\n\};/, ''), /highlight: '#141416'/, 'Kanten-Highlight nicht mehr hartcodiert');
  assert.match(appJs, /document\.addEventListener\('hx:themechange'/, 'Host-Listener für hx:themechange');
  // drilldown.js: Ring-Material-Refresh (PFLICHTKORREKTUR 9), Accessor-Re-Set,
  // Noir-Faded-Ton, Token-Fonts, edgeDefault-Adapter.
  assert.match(drilldownJs, /GRAPH3D_LINK_FADED_NOIR = '#514e66'/, 'Noir-Kontrolllinien-Ton definiert');
  assert.match(drilldownJs, /export const GRAPH3D_LINK_FADED = '#c9c9cf';/, 'Import-Vertrag des Freeze-Tests bleibt (Hell-Wert)');
  assert.match(drilldownJs, /document\.addEventListener\('hx:themechange'/, 'Drilldown-Theme-Listener');
  assert.match(drilldownJs, /ring3dMat\.color\.set\(roleColors\.drainer\.background\)/, 'Ring-Material folgt dem Theme (kein Stale-Rot)');
  assert.match(drilldownJs, /fg3d\.linkColor\(linkColor3dAccessor\(\)\)/, '3D-Kanten über Accessor-Re-Set');
  assert.match(drilldownJs, /const edgeDefaultOf = typeof ctx\.edgeDefault === 'function'/, 'edgeDefault-Adapter (Thunk abwärtskompatibel)');
  assert.match(drilldownJs, /getPropertyValue\('--a6-ink'\)/, '2D-Fonts über Token-Weg (ink)');
  assert.match(drilldownJs, /getPropertyValue\('--a6-body'\)/, '2D-Fonts über Token-Weg (body)');
  assert.doesNotMatch(
    drilldownJs.replace(/\/\*[\s\S]*?\*\//g, '').replace(/\/\/[^\n]*/g, ''),
    /font: \{ color: '#141416'|font: \{ color: '#484850'/,
    'keine hartcodierten Canvas-Fonts im 2D-Fallback',
  );
  // globe.js: Stroke-Fallback über den neutralen Kanten-Token (Noir 5.7:1),
  // Atmosphären-Mischziel = Bühnen-Token, Theme-Wechsel über rebuildGlobe.
  assert.match(globeJs, /cssToken\('--a6-edge-neutral'\) \|\| edgeDefaultOf\(\)/, 'Stroke-Vertragskette mit edge-neutral');
  assert.match(globeJs, /cssToken\('--a6-graph-canvas'\)/, 'Mischziel/Material über Bühnen-Token');
  assert.match(globeJs, /document\.addEventListener\('hx:themechange'[\s\S]{0,200}rebuildGlobe\(\)/, 'Theme-Wechsel: echter Rebuild (Bauzeit-Werte)');
  // Flow-Host-SVG (history-host.html): Token-Lese statt Hell-Literale.
  assert.match(historyHostHtml, /cssToken\('--a6-swatch-unknown'\)/, 'Flow-Graph unknown über Token');
  assert.match(historyHostHtml, /cssToken\('--a6-ink'\) \|\| '#141416'/, 'Flow-Graph Labels über Ink-Token');
  assert.match(historyHostHtml, /cssToken\('--a6-cluster-border'\) \|\| '#17171b'/, 'Flow-Graph Kontur über Token');
  assert.match(historyHostHtml, /document\.addEventListener\('hx:themechange'/, 'Flow-Host rendert bei Theme-Wechsel neu');
});
