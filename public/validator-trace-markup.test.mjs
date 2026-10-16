/* Incident-Profil-Markup-Guards (Forensik 2026-10-16)
 *
 * Der Bug saß nicht in der CSS-Geometrie, sondern im Markup: die Säulen wurden
 * als Array konkateniert ('+ cols'), und JavaScript wandelt ein Array beim
 * String-Zusammenbau mit Komma um. Zwischen jeder Säule landete ein Textknoten
 * ",". In einem Flex-Container wird daraus ein anonymes Flex-Item (Komma-Breite
 * ~4,3 px bei 15 px Inter), das links UND rechts je ein gap verbraucht.
 * Gemessen: Säulen 24,44 px statt 33,19 px, effektiver Abstand 13,92 px statt
 * 4,805 px, der Kohortenstreifen driftete bis 8,75 px weg. Mit der alten Tiefe
 * 15 px > 13,92 px ragten die Deckflächen in die Nachbarsäule und verschmolzen
 * zum Schrägband – die eigentliche Ursache des „schrägen" Profils.
 *
 * Guards:
 *  1) Kein Array darf ungejoint in ein HTML-Stück konkateniert werden.
 *  2) Die Säulen-Zeile wird als joined-String gebaut.
 *  3) Säulen-Zeile und Kohortenstreifen teilen Ränder, Abstand und Flex-Basis –
 *     sonst sind Intervall und Kohorten-Kachel nicht dieselbe Zeitachse.
 *  4) --d <= --gap in jedem clamp-Zweig: die Deckfläche ragt exakt --d über die
 *     Vorderfläche hinaus, der Überstand in die Nachbarspalte ist --d - --gap.
 *  5) --dz ist aus --skew abgeleitet (--dz-k = tan 41°), nicht paarweise gesetzt.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const here = path.dirname(fileURLToPath(import.meta.url));
const read = (rel) => readFileSync(path.join(here, rel), 'utf8');

const traceJs = read('validator-trace.mjs');
const styleCss = read('style.css');

/* Kommentare streifen (Muster design-assets.test.mjs): die Doku nennt die
 * geprüften Stichworte selbst – geprüft wird die Deklaration. */
const stripComments = (s) => s.replace(/\/\*[\s\S]*?\*\//g, '').replace(/^\s*\/\/.*$/gm, '');
const src = stripComments(traceJs);

/* Guard 1: eine Zuweisung const/let NAME = <Array-Ausdruck> darf nicht als
 * + NAME oder NAME + in einen String laufen, ohne .join( im Initializer.
 * Statement-Ende = erste Zeile mit ausgeglichener Klammer-Tiefe und ';' –
 * sonst endet die Suche am ersten inneren Semikolon und übersieht das .join. */
const ARRAY_PRODUCER = /\.(map|flatMap|filter)\(|Array\.from\(/;
const DECL_LINE = /^([ \t]*)(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=/;
const statementEnd = (lines, start) => {
  let depth = 0;
  for (let i = start; i < lines.length; i++) {
    for (const ch of lines[i]) {
      if (ch === '{' || ch === '(' || ch === '[') depth++;
      else if (ch === '}' || ch === ')' || ch === ']') depth--;
    }
    if (depth <= 0 && /;\s*$/.test(lines[i])) return i;
  }
  return lines.length - 1;
};

test('Markup: jedes Array wird vor der HTML-Konkatenation joined', () => {
  const lines = src.split('\n');
  const offenders = [];
  for (let i = 0; i < lines.length; i++) {
    const m = lines[i].match(DECL_LINE);
    if (!m) continue;
    const end = statementEnd(lines, i);
    const stmt = lines.slice(i, end + 1).join('\n');
    const name = m[2];
    if (ARRAY_PRODUCER.test(stmt)) {
      const usedInConcat = new RegExp('\\+\\s*' + name + '\\b|\\b' + name + '\\s*\\+').test(src);
      if (usedInConcat && !/\.join\(/.test(stmt)) offenders.push(name + ' (Zeile ' + (i + 1) + ')');
    }
    i = end;
  }
  assert.deepEqual(offenders, [], 'ungejonte Arrays im HTML: ' + offenders.join(', '));
});

test('Markup: die Säulen-Zeile wird als joined-String gebaut', () => {
  assert.match(src, /const cols = cells\.map\([\s\S]{0,4000}?\}\)\.join\(""\);/,
    'cols muss mit .join("") abgeschlossen sein – sonst stehen Komma-Textknoten zwischen den Säulen');
});

/* CSS-Regel-Extraktion: Selektor -> flacher Regel-Body. Der Selektor muss
 * exakt auftreten – ".vt-grid, .vt-bars" ist eine andere Regel als ".vt-bars". */
const cssRules = (() => {
  const css = styleCss.replace(/\/\*[\s\S]*?\*\//g, '');
  const map = new Map();
  for (const m of css.matchAll(/([^{}]+)\{([^{}]*)\}/g)) {
    for (const sel of m[1].split(',').map((s) => s.replace(/\s+/g, ' ').trim())) {
      if (!map.has(sel)) map.set(sel, []);
      map.get(sel).push(m[2]);
    }
  }
  return map;
})();
/* Alle Regel-Bodye eines Selektors zusammen: die Media-Query (.vt-profile mit
 * --plot-h: 132px) ist eine zweite Regel desselben Selektors, kein Ersatz. */
const ruleBody = (sel) => {
  assert.ok(cssRules.has(sel), 'Regel fehlt: ' + sel);
  return cssRules.get(sel).join('\n');
};
const clampOf = (body, token) => {
  const m = body.match(new RegExp('--' + token + ':\\s*clamp\\(\\s*([\\d.]+)px,\\s*([\\d.]+)cqw,\\s*([\\d.]+)px\\s*\\)'));
  assert.ok(m, 'clamp fehlt für --' + token);
  return { min: +m[1], k: +m[2], max: +m[3] };
};

const profile = ruleBody('.vt-profile');
const d = clampOf(profile, 'd');
const gap = clampOf(profile, 'gap');

test('Geometrie: --d <= --gap in jedem clamp-Zweig (kein Überstand in die Nachbarspalte)', () => {
  assert.ok(d.min <= gap.min, 'Untergrenze: --d ' + d.min + ' > --gap ' + gap.min);
  assert.ok(d.k <= gap.k, 'cqw-Koeffizient: --d ' + d.k + ' > --gap ' + gap.k);
  assert.ok(d.max <= gap.max, 'Obergrenze: --d ' + d.max + ' > --gap ' + gap.max);
});

test('Geometrie: --dz ist aus --skew abgeleitet, nicht paarweise gesetzt', () => {
  const skew = profile.match(/--skew:\s*([\d.]+)deg/);
  const dzk = profile.match(/--dz-k:\s*([\d.]+)/);
  const dz = profile.match(/--dz:\s*calc\(var\(--d\)\s*\*\s*var\(--dz-k\)\)/);
  assert.ok(skew && dzk && dz, '--skew / --dz-k / --dz-Kalkül fehlen');
  const tan = Math.tan((Number(skew[1]) * Math.PI) / 180);
  assert.ok(Math.abs(Number(dzk[1]) - tan) < 1e-4, '--dz-k ' + dzk[1] + ' != tan(' + skew[1] + '°) = ' + tan.toFixed(6));
});

test('Raster: Säulen-Zeile und Kohortenstreifen teilen Ränder, Abstand und Flex-Basis', () => {
  assert.match(ruleBody('.vt-plot'), /margin:\s*0\s+calc\(var\(--d\)\s*\+\s*3px\)\s+0\s+var\(--gutter\)/,
    '.vt-plot-Ränder nicht wie definiert (d+3 / gutter)');
  assert.match(ruleBody('.vt-heat'), /margin:\s*3px\s+calc\(var\(--d\)\s*\+\s*3px\)\s+0\s+var\(--gutter\)/,
    '.vt-heat-Ränder weichen von .vt-plot ab');
  assert.match(ruleBody('.vt-bars'), /gap:\s*var\(--gap\)/, '.vt-bars gap != var(--gap)');
  assert.match(ruleBody('.vt-heat'), /gap:\s*var\(--gap\)/, '.vt-heat gap != var(--gap)');
  for (const sel of ['.vt-col', '.vt-heat-cell']) {
    const body = ruleBody(sel);
    assert.match(body, /flex:\s*1 1 0/, sel + ' flex-Basis != 1 1 0');
    assert.match(body, /min-width:\s*0/, sel + ' min-width != 0');
  }
});

/* Intervall-Zustand und Signaturzustand (Forensik 2026-10-16): das Profil unterscheidet
 * jetzt sechs Intervall-Zustaende (clean / solo / cohort / network / unknown / none) und vier
 * Signatur-Zustaende (hit / clear / unknown / none). Guard ist die Paarung: jede Klasse, die
 * das Markup erzeugt, muss eine CSS-Regel haben - ein Zustand ohne Regel ist eine Aussage,
 * die der Leser nicht sieht. Der Signaturstreifen muss ausserdem auf denselben Intervallen
 * sitzen wie die Saulen, sonst ist er eine zweite, verschobene Zeitachse. */
const STATES = ["clean", "solo", "cohort", "network", "unknown", "none"];
const SIGN_STATES = ["hit", "clear", "unknown", "none"];

test('Raster: Signaturstreifen teilt Raender, Abstand und Flex-Basis mit Achse und Kohortenstreifen', () => {
  assert.match(ruleBody('.vt-sign'), /margin:\s*3px\s+calc\(var\(--d\)\s*\+\s*3px\)\s+0\s+var\(--gutter\)/,
    '.vt-sign-Raender weichen von .vt-plot ab');
  assert.match(ruleBody('.vt-sign'), /gap:\s*var\(--gap\)/, '.vt-sign gap != var(--gap)');
  const body = ruleBody('.vt-sign-cell');
  assert.match(body, /flex:\s*1 1 0/, '.vt-sign-cell flex-Basis != 1 1 0');
  assert.match(body, /min-width:\s*0/, '.vt-sign-cell min-width != 0');
});

test('Zustaende: Markup nutzt vt-state-*, und jeder Zustand hat Grundriss-, Streifen- und Legenden-Regel', () => {
  assert.doesNotMatch(src, /vt-breadth-/, 'vt-breadth-* ist durch vt-state-* ersetzt');
  assert.match(src, /class="vt-col vt-state-' \+ state/, 'Saeule traegt keinen Intervall-Zustand');
  assert.match(src, /vt-heat-cell vt-state-/, 'Kohortenstreifen traegt keinen Intervall-Zustand');
  for (const k of STATES) {
    assert.ok(cssRules.has('.vt-col.vt-state-' + k + ' .vt-foot'), 'Grundriss-Regel fehlt: vt-state-' + k);
    assert.ok(cssRules.has('.vt-heat-cell.vt-state-' + k), 'Streifen-Regel fehlt: vt-state-' + k);
    assert.ok(cssRules.has('.vt-heat-key.vt-state-' + k), 'Legenden-Regel fehlt: vt-state-' + k);
  }
});

test('Signaturen: Marker und Streifen haengen an derselben Messung - und an derselben Saule', () => {
  assert.match(src, /vt-sign-cell vt-sign-/, 'Signaturstreifen fehlt im Markup');
  assert.match(src, /class="vt-mark"/, 'Signatur-Marker fehlt im Markup');
  for (const k of SIGN_STATES) {
    assert.ok(cssRules.has('.vt-sign-cell.vt-sign-' + k), 'Streifen-Regel fehlt: vt-sign-' + k);
    assert.ok(cssRules.has('.vt-sign-key.vt-sign-' + k), 'Legenden-Regel fehlt: vt-sign-' + k);
  }
  /* --n und --i stehen auf .vt-col: .vt-bar und .vt-mark erben sie. Der Marker berechnet
     seine Hohe aus --u * --n; steht --n nur auf .vt-bar, sitzt er auf Hoehe 0 im Grundriss,
     und die Animationsverzogerung der Spalte (auf .vt-col deklariert) verpufft. */
  assert.match(src, /class="vt-col vt-state-' \+ state \+ '" tabindex="0" role="group" style="' \+ style/,
    'style mit --n/--i muss auf .vt-col stehen');
  assert.doesNotMatch(src, /<div class="vt-bar" style="/, '.vt-bar darf den Style nicht mehr tragen');
  assert.match(ruleBody('.vt-mark'), /bottom:\s*calc\(var\(--u\)\s*\*\s*var\(--n,\s*0\)\s*\+\s*var\(--dz\)\s*\+\s*5px\)/,
    '.vt-mark sitzt nicht auf der Oberkante des Prismas');
  assert.match(ruleBody('.vt-col'), /animation-delay:\s*calc\(var\(--i,\s*0\)\s*\*\s*16ms\)/,
    '.vt-col Animationsverzogerung fehlt');
});

test('Kontrastfarben: Streifen und Marker behalten ihre Flaeche, nicht nur die Prismen', () => {
  for (const sel of ['.vt-bar', '.vt-sign-cell', '.vt-sign-key', '.vt-mark']) {
    assert.ok(ruleBody(sel).includes('forced-color-adjust: none'), sel + ' fehlt in der forced-colors-Liste');
  }
});
