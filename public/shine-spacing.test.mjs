/* Shine-Clipping- und Panel-Abstand-Regressionstests (Forensik 2026-10-07)
 *
 * Statische Guards für die zwei CSS-Fixes in public/style.css — kein Browser:
 *  1) Hover-Shine-Clipping: .download-btn und .graph-tab tragen overflow:
 *     hidden (Haus-Pattern wie drilldown.css/globe.css) — isolation allein
 *     schneidet nichts, ohne Clipping malt das inset:0-Band (-120 %→+120 %)
 *     außerhalb der Button-Pille und parkt im Hover-Ruhezustand statisch
 *     daneben.
 *  2) Ink-Ausschluss: der Shine-Selektor schließt die ink-gefüllte
 *     Primäraktion #check-go aus — der ID-Selektor in account-check.css
 *     (1,0,0) schlägt .download-btn:hover (0,2,0), die Ink-Füllung bleibt
 *     auch im Hover; auf --a6-ink-fill wäre das Band ein Flickern.
 *  3) Shine-Invariante: Gradient/Animation des ::after-Blocks und die
 *     @keyframes bleiben unverändert — der Fix clippt nur, er erfindet
 *     den Shine nicht neu.
 *  4) Panel-Abstand: #exchange-outflows-panel trägt margin 22 px
 *     (Sektions-Rhythmus console-grid/console-col/main) oben UND unten,
 *     mobil 14 px wie .hx-stage; die .panel-Grundregel bleibt margin-frei
 *     (eine globale Margin würde die 22-px-Gaps in main verdoppeln).
 *  5) Fokus-Ring-Integrität: outline+offset-Regel unverändert — Clipping
 *     beschneidet die eigene outline eines Elements nicht (live gemessen:
 *     computed outline bleibt am fokussierten Button mit overflow:hidden).
 *  6) Reduced-Motion-Pendant: animation:none !important auf *::after bleibt
 *     — das bei -120 % geparkte Band ist durch das Clipping unsichtbar.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const here = path.dirname(fileURLToPath(import.meta.url));
const read = (rel) => readFileSync(path.join(here, rel), 'utf8');

const styleCss = read('style.css');
const accountCheckCss = read('account-check.css');
const accountCheckJs = read('account-check.js');
const indexHtml = read('index.html');

/* Kommentare streifen (Muster design-assets.test.mjs): die Doku nennt die
 * geprüften Stichworte selbst — geprüft wird die Deklaration. */
const stripComments = (block) => block.replace(/\/\*[\s\S]*?\*\//g, '');

/* Der Shine-Block wird über sein exaktes Selektor-Paar isoliert (nicht über
 * die Media-Klammer — im File gibt es zehn hover-Media-Blöcke). */
const shineRx = new RegExp(
  String.raw`\.download-btn:not\(:disabled\):not\(#check-go\):hover::after,\s*\n\s*` +
  String.raw`\.graph-tab:not\(\[aria-selected="true"\]\):not\(\[aria-pressed="true"\]\):hover::after\s*\{[^}]*\}`,
);

test('Clipping: .download-btn und .graph-tab clippen das Shine-Band (overflow:hidden)', () => {
  for (const sel of ['.download-btn', '.graph-tab']) {
    const rule = styleCss.match(new RegExp(`${sel.replace('.', '\\.')}\\s*\\{[^}]*\\}`));
    assert.ok(rule, `Basisregel ${sel} vorhanden`);
    const body = stripComments(rule[0]);
    assert.match(body, /position:\s*relative/, `${sel}: Shine-Anker bleibt`);
    assert.match(body, /isolation:\s*isolate/, `${sel}: Stacking-Kontext bleibt`);
    assert.match(body, /overflow:\s*hidden/, `${sel}: Clipping-Regel vorhanden`);
    assert.doesNotMatch(body, /overflow:\s*clip/, `${sel}: Haus-Pattern hidden, kein clip`);
    assert.match(body, /border-radius:\s*var\(--a6-r-pill\)/, `${sel}: Clip-Kante folgt der Pille`);
  }
  // Kein Eltern-Container clippt (und soll es nicht): .graph-tabs/.view-nav
  // bleiben overflow-frei — sonst beschnitten sie eigene Nachkommen.
  for (const sel of ['.graph-tabs', '.view-nav']) {
    const rule = styleCss.match(new RegExp(`${sel.replace('.', '\\.')}\\s*\\{[^}]*\\}`));
    assert.ok(rule, `Regel ${sel} vorhanden`);
    assert.doesNotMatch(stripComments(rule[0]), /overflow:\s*(hidden|clip|auto)/, `${sel} clippt nicht`);
  }
});

test('Ink-Ausschluss: Shine-Selektor schließt #check-go aus (Ink-Fläche bleibt shine-frei)', () => {
  const block = styleCss.match(shineRx);
  assert.ok(block, 'Shine-Block mit #check-go-Ausschluss vorhanden');
  // Der alte Selektor ohne Ausschluss darf nicht mehr existieren:
  assert.doesNotMatch(
    styleCss,
    /\.download-btn:not\(:disabled\):hover::after/,
    'kein Shine mehr auf .download-btn ohne :not(#check-go)',
  );
  // Der Block sitzt weiterhin in der hover-Media-Query (kein Zeiger → kein Shine):
  const mediaIdx = styleCss.slice(0, block.index).lastIndexOf('@media (hover: hover) and (pointer: fine)');
  assert.ok(mediaIdx >= 0, 'hover-Media-Query vor dem Shine-Block');
  assert.doesNotMatch(styleCss.slice(mediaIdx, block.index), /\}/, 'Selektor gehört direkt zur Media-Regel');
  // Die Ink-Füllung selbst, gegen die der Ausschluss schützt, ist unverändert:
  const go = accountCheckCss.match(/#check-go\s*\{[^}]*\}/);
  assert.ok(go, '#check-go-Regel vorhanden (ID (1,0,0) schlägt .download-btn:hover (0,2,0))');
  assert.match(stripComments(go[0]), /background:\s*var\(--a6-ink-fill\)/, 'Ink-Füllung bleibt');
  // #check-go ist ein .download-btn (der Ausschluss greift also überhaupt) —
  // das Markup baut account-check.js (kein statisches Button-Markup in index.html):
  assert.match(accountCheckJs, /<button id="check-go" type="submit" class="download-btn">/, 'Markup in account-check.js');
});

test('Shine-Invariante: ::after-Block und @keyframes bleiben unverändert (nur clippt)', () => {
  const block = styleCss.match(shineRx);
  const body = stripComments(block[0]);
  assert.match(body, /content:\s*""/, 'Pseudo-Element');
  assert.match(body, /position:\s*absolute/, 'Band liegt auf der Fläche');
  assert.match(body, /inset:\s*0/, 'Band füllt die Box');
  assert.match(body, /border-radius:\s*inherit/, 'Band folgt der Pillen-Rundung');
  assert.match(body, /linear-gradient\(105deg, transparent 30%, var\(--a6-accent-soft\) 48%, transparent 66%\)/, '105°-Band auf Akzent-Token (beide Themes)');
  assert.match(body, /opacity:\s*0\.6/, 'Band-Deckkraft');
  assert.match(body, /transform:\s*translateX\(-120%\)/, 'Ruheposition außerhalb (jetzt weggeclipped)');
  assert.match(body, /animation:\s*a6-btn-shine 700ms var\(--a6-ease\)/, 'EINMAL-Sweep beim Hover');
  assert.match(body, /pointer-events:\s*none/, 'Band ist nicht klickbar');
  // Keyframes-Block: innere Klammern — Grenze ist die Block-Klammer am Zeilenanfang.
  const kf = styleCss.match(/@keyframes a6-btn-shine\s*\{[\s\S]*?\n\}/);
  assert.ok(kf, 'Keyframes vorhanden');
  assert.match(kf[0], /from\s*\{\s*transform:\s*translateX\(-120%\);\s*\}/, 'Start -120 %');
  assert.match(kf[0], /to\s*\{\s*transform:\s*translateX\(120%\);\s*\}/, 'Ende +120 %');
});

test('Panel-Abstand: #exchange-outflows-panel trägt margin 22px auto (oben UND unten)', () => {
  const rule = styleCss.match(/#exchange-outflows-panel\s*\{[^}]*\}/);
  assert.ok(rule, 'Panel-Regel vorhanden');
  const body = stripComments(rule[0]);
  assert.match(body, /margin:\s*22px auto/, '22 px = Sektions-Rhythmus (console-grid/console-col/main), auto horizontal');
  // Frost-Optik der Regel bleibt unangetastet (der Fix ergänzt nur Margin):
  assert.match(body, /background:\s*var\(--a6-frost-fill\)/, 'Frost-Füllung bleibt');
  assert.match(body, /backdrop-filter:\s*var\(--a6-frost-blur\)/, 'Blur bleibt');
  assert.match(body, /border-color:\s*var\(--a6-frost-border\)/, 'Frost-Rand bleibt');
  // Die .panel-Grundregel bleibt margin-frei: eine globale Margin würde die
  // bestehenden 22-px-Gaps in main (gap) verdoppeln.
  const panelBase = styleCss.match(/\.panel\s*\{[^}]*\}/);
  assert.ok(panelBase, '.panel-Grundregel vorhanden');
  assert.doesNotMatch(stripComments(panelBase[0]), /margin/, '.panel bleibt margin-frei');
  // main-Rhythmus unverändert 22 px (Abstand referenziert ihn, ersetzt ihn nicht):
  const mainRule = styleCss.match(/main\s*\{[^}]*\}/);
  assert.ok(mainRule, 'main-Regel vorhanden');
  assert.match(stripComments(mainRule[0]), /gap:\s*22px/, 'main gap 22 px bleibt');
  // Mobiler Rhythmus: im 560-px-Block 14 px wie .hx-stage margin-top.
  const mobile = styleCss.match(/@media \(max-width: 560px\)\s*\{[\s\S]*?\n\}/);
  assert.ok(mobile, 'Mobile-Block vorhanden');
  assert.match(mobile[0], /#exchange-outflows-panel\s*\{\s*margin:\s*14px auto;\s*\}/, 'mobil 14 px');
  assert.match(mobile[0], /\.hx-stage\s*\{\s*margin-top:\s*14px;\s*\}/, '.hx-stage-Rhythmus unverändert 14 px');
  // Das Panel bleibt direktes body-Kind zwischen Bühne und view-nav
  // (der Abstand entsteht als Margin, nicht durch Umsortierung):
  assert.ok(
    indexHtml.indexOf('class="hx-stage"') < indexHtml.indexOf('id="exchange-outflows-panel"') &&
    indexHtml.indexOf('id="exchange-outflows-panel"') < indexHtml.indexOf('<nav class="view-nav graph-tabs"'),
    'Markup-Reihenfolge Bühne → Panel → Nav unverändert',
  );
});

test('Fokus-Ring-Integrität: outline+offset-Regel unverändert (Clipping beschneidet sie nicht)', () => {
  const focus = styleCss.match(/:where\(a, button, input, select, summary\):focus-visible\s*\{[^}]*\}/);
  assert.ok(focus, 'Fokus-Ring-Regel vorhanden');
  assert.match(focus[0], /outline:\s*3px solid var\(--a6-focus\)/, 'Ring bleibt outline (nicht box-shadow)');
  assert.match(focus[0], /outline-offset:\s*3px/, 'Offset bleibt');
});

test('Reduced Motion: animation:none !important auf *::after bleibt (geparktes Band ist weggeclipped)', () => {
  // Zwei reduced-motion-Blöcke im File (Marke, Console) — der Console-Block
  // ist der mit dem Global-Ansatz.
  const blocks = [...styleCss.matchAll(/@media \(prefers-reduced-motion: reduce\)\s*\{[\s\S]*?\n\}/g)].map((m) => m[0]);
  const rm = blocks.find((b) => /animation:\s*none !important/.test(b));
  assert.ok(rm, 'Console-Reduced-Motion-Block vorhanden');
  assert.match(rm, /\*,\s*\n\s*\*::before,\s*\n\s*\*::after\s*\{[^}]*animation:\s*none !important/, 'Pseudo-Bänder ohne Animation');
  assert.match(rm, /\.download-btn\s*\{\s*transform:\s*none !important;\s*\}/, 'Klassen-transform:none bleibt');
});
