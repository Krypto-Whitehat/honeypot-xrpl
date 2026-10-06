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
 *  6) Cluster-Liste/Mega-Cluster (Design P2): Band-Breiten-Token statt
 *     hardcodeder 3-px-Bänder (einheitlich, KEIN strong-Token — Plan-Kritik
 *     7a), solide sev-malicious-Kopf-Tönung (kein Gradient), Drainer-Rollen-
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
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, existsSync, readdirSync, statSync } from 'node:fs';
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
const aboutHtml = read('about.html');
const historyJs = read('history.js');
const historyCss = read('history.css');
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

test('Band-Token: --a6-band-width ersetzt alle hardcodeden 3-px-Bänder, kein strong-Token', () => {
  assert.match(styleCss, /--a6-band-width:\s*3px;/, 'Token definiert');
  // Plan-Kritik 7a: das Band bleibt EINHEITLICH 3 px — ein verstärkendes
  // strong-Token (4 px für sev-malicious) darf nicht existieren.
  assert.doesNotMatch(styleCss, /--a6-band-width-strong/, 'kein Band-Verstärkungs-Token');
  assert.doesNotMatch(styleCss, /border-left:\s*3px/, 'kein hardcodedes border-left: 3px mehr');
  assert.doesNotMatch(styleCss, /border-left-width:\s*3px/, 'forced-colors-Block nutzt den Token');
  for (const sel of ['.stat', '.block-card', '.log-row', '.cluster-card']) {
    const block = styleCss.match(new RegExp(`${sel.replace('.', '\\.')}\\s*\\{[^}]*\\}`, ''));
    assert.ok(block, `Regelblock ${sel} vorhanden`);
    assert.match(block[0], /border-left:\s*var\(--a6-band-width\)/, `${sel} nutzt den Band-Token`);
  }
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
