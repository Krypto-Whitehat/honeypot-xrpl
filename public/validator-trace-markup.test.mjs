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
 *  4) --col-w ist nachgerechnet (Plotbreite minus 23 Abstand, durch 24) und --d ist
 *     ein Anteil davon: die Vorderfläche kürzt um --dc (right: var(--dc)) und die
 *     Tiefenfläche füllt den Rest derselben Zelle - kein Überstand in die Nachbarspalte.
 *  5) --dz und --dzc sind aus --skew abgeleitet (--dz-k = tan 45°), nicht paarweise
 *     gesetzt. Die Deckfläche schert um --dzc * cot(--skew) = --dc -> Zellenkante.
 *  6) Tiefe je Profil konstant (--dc = --d für jede Säule): die je-Säule-Klammer
 *     --dc = min(--d, --bh) machte Säulen nebeneinander unterschiedlich dick
 *     (10,48 px gegen 3,52 px Tiefenfläche im 24-h-Fenster, peak 50) - das Profil
 *     las sich schräg. Neu: gleiche Tiefe für alle, eine durchgehende Bodenplatte
 *     (--base-h) unter allen 24 Intervallen und die Zahl als Wertemarke über dem Prisma.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { PEER_VERDICTS } from '../lib/validator-peer-benchmark.mjs';
import { LATENCY_VERDICTS } from '../lib/validator-vote-latency.mjs';
import { DIVERGENCE_VERDICTS } from '../lib/validator-divergence.mjs';
import { CAUSE_KINDS } from '../lib/validator-cause.mjs';
import { SURFACE_VERDICTS } from '../lib/validator-quorum-surface.mjs';

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
const gap = clampOf(profile, 'gap');
const gutter = clampOf(profile, 'gutter');
/* Die Scherung ist aus --skew abgeleitet, nicht paarweise gesetzt: tan(45deg) = 1.
 * Sie wird hier frueher gebraucht, weil die groesste Kappe die Achs-Schwelle bestimmt. */
const SKEW_DEG = Number(profile.match(/--skew:\s*([\d.]+)deg/)[1]);
const DZ_K = Math.tan((SKEW_DEG * Math.PI) / 180);
/* Die Zellenbreite ist keine gesetzte Zahl, sondern die Breite, die .vt-bars dem
 * einzelnen flex: 1 1 0-Item lässt. Das Modell unten muss auf dieselbe Zahl kommen. */
const colwRule = profile.match(/--col-w:\s*calc\(\(100cqw - var\(--gutter\) - 3px - 23 \* var\(--gap\)\) \/ 24\)/);
const dRule = profile.match(/--d:\s*min\(max\(([\d.]+)px,\s*calc\(var\(--col-w\) \* ([\d.]+)\)\),\s*([\d.]+)px,\s*calc\(var\(--plot-h\) \* var\(--dmax,\s*1\)\)\)/);
assert.ok(colwRule && dRule, '--col-w / --d Ableitung fehlt');
const DEPTH_MIN = Number(dRule[1]);
const DEPTH_K = Number(dRule[2]);
const DEPTH_MAX = Number(dRule[3]);
const PLOT_HS = [...profile.matchAll(/--plot-h:\s*([\d.]+)px/g)].map((m) => Number(m[1]));
const PLOT_H = Math.max(...PLOT_HS);
/* Die groesste Kappe, die je gezeichnet wird, wenn die Achse genug Raum laesst. Sie haengt an
 * keiner Saeulenhohe - deshalb ist sie die Grenze, die die lineare Achse einhalten muss, damit
 * das Profil sein Volumen behaelt. */
const DZC_MAX = DEPTH_MAX * DZ_K;
const clampV = (v, lo, hi) => Math.min(Math.max(lo, v), hi);
/* dmaxRatio ist die Achsen-Grenze aus profile3d. Ohne Argument ist sie offen: Plot-Hoehe ist
 * weiter als jede Zellenbreite, also begrenzt sie die Tiefe nicht. */
const cellAt = (contentPx, dmaxRatio = 1) => {
  const g = clampV(gap.k * contentPx / 100, gap.min, gap.max);
  const gu = clampV(gutter.k * contentPx / 100, gutter.min, gutter.max);
  const plot = contentPx - gu - 3;
  const col = (plot - 23 * g) / 24;
  const d = Math.min(Math.max(DEPTH_MIN, col * DEPTH_K), DEPTH_MAX, PLOT_H * dmaxRatio);
  return { content: contentPx, gap: g, gutter: gu, plot, col, d, dzc: d * DZ_K, front: col - d };
};

test('Geometrie: die Zelle ist die Breite, die der Flex-Raster wirklich lässt', () => {
  // Kontrolle an der live gemessenen Fassung 2026-10-16 (altes --gap 1,15cqw, rechter
  // Rand --d + 3px, altes --d 0,85cqw): Content 961 px, Plot 909,48 px, Abstand 11,04 px,
  // Säule 27,31 px - gemessen 27,3 px. Dasselbe Modell, neue Werte.
  const oldGap = clampV(1.15 * 961 / 100, 4, 15);
  const oldD = clampV(0.85 * 961 / 100, 3, 11);
  const oldPlot = 961 - clampV(4.2 * 961 / 100, 20, 42) - (oldD + 3);
  const oldCol = (oldPlot - 23 * oldGap) / 24;
  assert.ok(Math.abs(oldCol - 27.31) < 0.05, 'Modell-Saeule ' + oldCol.toFixed(2) + ' px gegen gemessen 27,3 px');
  const c = cellAt(961);
  assert.ok(Math.abs(c.gap - 7.69) < 0.01, '--gap ' + c.gap.toFixed(2) + ' px bei Content 961');
  assert.ok(c.col > 28 && c.col < 32, 'Saeulenbreite ' + c.col.toFixed(2) + ' px - zu schmal fuer 24 Intervalle');
  assert.ok(c.col / c.gap > 3.5, 'Zelle nur ' + (c.col / c.gap).toFixed(2) + '-mal so breit wie der Abstand - Kamm, kein Saeulenfeld');
  assert.ok(c.front >= (1 - DEPTH_K) * c.col - 1e-9, 'Vorderflaeche ' + c.front.toFixed(2) + ' px unter 78 % der Zelle');
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
  assert.match(ruleBody('.vt-plot'), /margin:\s*0\s+3px\s+0\s+var\(--gutter\)/,
    '.vt-plot-Ränder nicht wie definiert (3px / gutter)');
  assert.match(ruleBody('.vt-heat'), /margin:\s*3px\s+3px\s+0\s+var\(--gutter\)/,
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
  assert.match(ruleBody('.vt-sign'), /margin:\s*3px\s+3px\s+0\s+var\(--gutter\)/,
    '.vt-sign-Raender weichen von .vt-plot ab');
  assert.match(ruleBody('.vt-sign'), /gap:\s*var\(--gap\)/, '.vt-sign gap != var(--gap)');
  const body = ruleBody('.vt-sign-cell');
  assert.match(body, /flex:\s*1 1 0/, '.vt-sign-cell flex-Basis != 1 1 0');
  assert.match(body, /min-width:\s*0/, '.vt-sign-cell min-width != 0');
});

test('Zustaende: Markup nutzt vt-state-*, und jeder Zustand hat Platten-, Streifen- und Legenden-Regel', () => {
  assert.doesNotMatch(src, /vt-breadth-/, 'vt-breadth-* ist durch vt-state-* ersetzt');
  assert.match(src, /class="vt-col vt-state-' \+ state/, 'Saeule traegt keinen Intervall-Zustand');
  assert.match(src, /vt-heat-cell vt-state-/, 'Kohortenstreifen traegt keinen Intervall-Zustand');
  for (const k of STATES) {
    assert.ok(cssRules.has('.vt-col.vt-state-' + k + ' .vt-base'), 'Bodenplatten-Regel fehlt: vt-state-' + k);
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
  /* --n und --i stehen auf .vt-col: .vt-bar, .vt-mark und .vt-value erben sie. Marker und
     Wertemarke berechnen ihre Hohe aus --bh; steht --n nur auf .vt-bar, sitzen sie auf Hoehe 0
     auf der Bodenplatte, und die Animationsverzogerung der Spalte (auf .vt-col deklariert)
     verpufft. */
  assert.match(src, /class="vt-col vt-state-' \+ state \+ \(cell\.total \? " vt-nonzero" : ""\) \+ '" tabindex="0" role="group" style="' \+ style/,
    'style mit --n/--i muss auf .vt-col stehen (und vt-nonzero nur bei Vorfaellen)');
  assert.doesNotMatch(src, /<div class="vt-bar" style="/, '.vt-bar darf den Style nicht mehr tragen');
  assert.match(ruleBody('.vt-mark'), /bottom:\s*calc\(var\(--bh\)\s*\+\s*var\(--dzc\)\s*\+\s*1px\)/,
    '.vt-mark sitzt nicht auf der Oberkante des Prismas (Tiefe --dzc, je Profil konstant)');
  assert.match(src, /class="vt-value" aria-hidden="true">' \+ h\.esc\(String\(cell\.total\)\)/,
    'Wertemarke fehlt im Markup - die Zahl ist nur in aria-label und data-tip');
  assert.match(src, /\+ \(cell\.total \? '<span class="vt-value"/, 'Wertemarke wird auch fur leere Intervalle gebaut');
  assert.match(ruleBody('.vt-col'), /animation-delay:\s*calc\(var\(--i,\s*0\)\s*\*\s*16ms\)/,
    '.vt-col Animationsverzogerung fehlt');
});

test('Kontrastfarben: Streifen und Marker behalten ihre Flaeche, nicht nur die Prismen', () => {
  for (const sel of ['.vt-bar', '.vt-sign-cell', '.vt-sign-key', '.vt-mark']) {
    assert.ok(ruleBody(sel).includes('forced-color-adjust: none'), sel + ' fehlt in der forced-colors-Liste');
  }
});

/* --- Achsenskalierung -------------------------------------------------------
 * Gemessen am 2026-10-16 live (7d-Fenster, peak 5000): eine lineare Achse gab Hoehen
 * 0,03 / 0,06 / 4,53 / 138 / 158 px. Ein Intervall mit einem Vorfall war unsichtbar -
 * das Profil wirkte leer, obwohl etwas gemessen wurde. Die Achse ist deshalb
 * wurzel-bezogen; die Gitterlinien bleiben die wahren Zahlen, nur ihre Abstaende
 * folgen derselben Skala. */
const { axisScale, axisUnit, LINEAR_PEAK, DEPTH_SKEW_K } = await import('./validator-trace.mjs');
assert.ok(Math.abs(DEPTH_SKEW_K - DZ_K) < 1e-5,
  'JS DEPTH_SKEW_K ' + DEPTH_SKEW_K + ' gegen CSS tan(--skew) ' + DZ_K.toFixed(6));
/* Die Achsen-Grenze fuer ein Achsenmaximum: der kurzeste gezeichnete Koerper, umgerechnet in
 * die groesste Tiefe, auf der darauf noch eine geschlossene Kappe sitzt. */
const dmaxRatioAt = (peak) => (axisUnit(1, peak) / peak) / DEPTH_SKEW_K;

test('Achse: leeres Intervall hat keine Hoehe (null bleibt null, kein Mindestbalken)', () => {
  assert.equal(axisUnit(0, 5000), 0);
  assert.equal(axisUnit(null, 5000), 0);
  assert.equal(axisUnit(-4, 5000), 0);
});

test('Achse: peak bleibt die wahre Achsenspitze, die Skala ist streng monoton', () => {
  const { peak, step } = axisScale(4502);
  assert.equal(peak, 5000);
  assert.equal(step, 1000);
  assert.equal(axisUnit(5000, peak), 5000);
  const vals = [1, 2, 3, 6, 129, 1250, 3931, 4502, 5000];
  const units = vals.map((v) => axisUnit(v, peak));
  for (let i = 1; i < units.length; i++) {
    assert.ok(units[i] > units[i - 1], 'nicht monoton bei ' + vals[i] + ': ' + units[i] + ' <= ' + units[i - 1]);
  }
});

test('Achse: wurzel-bezogene Abbildung ist exakt (1250 von 5000 = halbe Plot-Hoehe)', () => {
  assert.equal(axisUnit(1250, 5000), 2500);
  assert.equal(axisUnit(500, 5000), 5000 * Math.sqrt(0.1));
});

test('Achse: kleine Achsen sind linear (die Wurzel war bei peak 4 eine Verschlechterung)', () => {
  // Nachgerechnet bei Plot-Hoehe 176 px: linear 44 / 88 / 132 / 176 px - jede Stufe genau ein
  // Gitterintervall. Aus der alten Wurzel-Skala: 88 / 124,4 / 152,4 / 176 px, also ein einziger
  // Vorfall auf halber Plot-Hoehe und drei Stufen, die auf 36 px zusammengeschoben sind.
  const peak = 4, plotH = 176;
  const lin = [1, 2, 3, 4].map((v) => (axisUnit(v, peak) / peak) * plotH);
  assert.deepEqual(lin, [44, 88, 132, 176], 'lineare Stufen bei peak 4: ' + lin.join(' / '));
  assert.equal(axisUnit(1, 4), 1);
  assert.equal(axisUnit(4, 4), 4);
  assert.equal(axisUnit(7, 15), 7);
  assert.equal(axisUnit(15, 15), 15);
  assert.equal(axisUnit(10, 10), 10);
});

test('Achse: die Schwelle ist das Volumen (linear bis peak 20, ab peak 25 wurzel)', () => {
  assert.equal(LINEAR_PEAK, 20, 'LINEAR_PEAK ist ' + LINEAR_PEAK);
  /* Linear bleibt das Profil in voller Tiefe, solange der kurzeste Koerper (plotH / peak) nicht
     unter die groesste Kappe faellt. 176 / 20 = 8,80 px gegen 8,50 px Kappe - 3,5 % Luft. */
  assert.ok(PLOT_H / LINEAR_PEAK >= DZC_MAX, 'linear bei peak ' + LINEAR_PEAK + ': kurzester Koerper '
    + (PLOT_H / LINEAR_PEAK).toFixed(2) + ' px unter der groessten Kappe ' + DZC_MAX.toFixed(2) + ' px');
  /* Der alte Wert 50 war die Ursache der Haarlinie: 176 / 50 = 3,52 px Koerper gegen 6,79 px
     Kappe bei 961 px Content. Die Achse war linear, die Kappe hoeher als jeder 1-Vorfall-Koerper,
     und die Tiefe wurde auf Kappenhoehe zusammengezogen. */
  assert.ok(PLOT_H / 50 < cellAt(961).dzc, 'die alte Schwelle 50 ist wieder drin: ' + (PLOT_H / 50).toFixed(2)
    + ' px gegen Kappe ' + cellAt(961).dzc.toFixed(2) + ' px');
  /* peak 20 ist der letzte Sprung des Achsleiters, der die groesste Kappe linear zulaesst. Der
     naechste (peak 25) waere linear 176 / 25 = 7,04 px kurz - unter der Kappe - und ist
     wurzel-bezogen 176 * sqrt(1 / 25) = 35,20 px. */
  const at20linear = (axisUnit(1, 20) / 20) * PLOT_H;
  assert.ok(Math.abs(at20linear - 8.8) < 1e-9, 'peak 20 linear: 1 Vorfall = ' + at20linear.toFixed(2) + ' px');
  assert.ok(at20linear >= DZC_MAX && at20linear - DZC_MAX < 1, 'peak 20: kurzester Koerper '
    + at20linear.toFixed(2) + ' px gegen Kappe ' + DZC_MAX.toFixed(2) + ' px');
  const at25linear = (1 / 25) * PLOT_H;
  assert.ok(at25linear < DZC_MAX, 'peak 25 linear waere ' + at25linear.toFixed(2) + ' px - unter der Kappe');
  const at25root = (axisUnit(1, 25) / 25) * PLOT_H;
  assert.ok(Math.abs(at25root - 35.2) < 1e-9, 'peak 25 wurzel: 1 Vorfall = ' + at25root.toFixed(2) + ' px');
  /* Was der Achsleiter in der linearen Zone wirklich liefert (peak / step <= 5): */
  for (const max of [1, 4, 6, 11, 15, 16, 20]) {
    const { peak } = axisScale(max);
    assert.ok(peak <= LINEAR_PEAK, 'max ' + max + ': peak ' + peak + ' faellt aus der linearen Zone');
    assert.ok(PLOT_H / peak >= DZC_MAX, 'max ' + max + ': peak ' + peak + ' -> '
      + (PLOT_H / peak).toFixed(2) + ' px kurzester Koerper unter der Kappe');
  }
  for (const max of [21, 25, 50, 129]) {
    const { peak } = axisScale(max);
    assert.ok(peak > LINEAR_PEAK, 'max ' + max + ': peak ' + peak + ' waere noch linear');
    const body = (axisUnit(1, peak) / peak) * PLOT_H;
    assert.ok(body >= DZC_MAX, 'max ' + max + ': peak ' + peak + ' -> kurzester Koerper '
      + body.toFixed(2) + ' px unter der Kappe');
  }
  // Monotonie in beiden Zweigen: die Skala darf Vergleiche nicht umdrehen.
  for (const p of [4, 15, 20, 50, 5000]) {
    const vals = [1, 2, 3, 6, 129, 1250, 3931].filter((v) => v <= p);
    const units = vals.map((v) => axisUnit(v, p));
    for (let i = 1; i < units.length; i++) {
      assert.ok(units[i] > units[i - 1], 'nicht monoton bei peak ' + p + ': ' + units[i] + ' <= ' + units[i - 1]);
    }
  }
});

test('Achse: der kleinste Wert bleibt unter einem Gitterintervall (kein uebertriebener Balken)', () => {
  // peak 5000, step 1000: die Gitterlinie bei 1000 steht auf sqrt(1000/5000) = 44,72 % der Hoehe.
  const gridline = axisUnit(1000, 5000) / 5000;
  assert.ok(Math.abs(gridline - Math.sqrt(0.2)) < 1e-12, 'Gitterlinien-Position ' + gridline);
  const smallest = axisUnit(1, 5000) / 5000;
  assert.ok(smallest < gridline / 4, 'kleinster Wert ' + smallest + ' raeumt zu viel Plot-Raum ein');
  // Die groesste Kappe (8,50 px) ist bei 176 px Plot-Hoehe 4,83 % und bei 132 px 6,44 % - weit
  // unter einem Gitterintervall. Sie ist keine Untergrenze am Balken: die Balkenhoehe bleibt
  // der Achsenwert (Invarianz-Test unten), die Kappe ist das, was begrenzt wird.
  assert.ok(DZC_MAX / PLOT_H < gridline / 4, 'Kappe zu hoch (Desktop): ' + (DZC_MAX / PLOT_H * 100).toFixed(2) + ' %');
  assert.ok(DZC_MAX / Math.min(...PLOT_HS) < gridline / 4,
    'Kappe zu hoch (Mobil): ' + (DZC_MAX / Math.min(...PLOT_HS) * 100).toFixed(2) + ' %');
});

test('Achse: lineare Hoehen waeren unter der Sichtbarkeit (der Grund der Wurzel-Skala)', () => {
  const plotH = 176;
  // Nachrechnen (peak 5000, Plot-Hoehe 176 px): linear 1 -> 0,035 px, 2 -> 0,07 px,
  // 6 -> 0,21 px, 129 -> 4,54 px. Die ersten drei sind unter jeder Kantensichtbarkeit.
  const linear = [1, 2, 6].map((v) => (v / 5000) * plotH);
  for (const h of linear) assert.ok(h < 1, 'linear war ' + h + ' px - unter der Kanten-Sichtbarkeit');
  assert.ok((129 / 5000) * plotH < 5, '129 Vorfaelle waren linear ' + (129 / 5000) * plotH + ' px');
  // Wurzel-Skala: 1 -> 2,49 px, 2 -> 3,52 px, 6 -> 6,10 px, 129 -> 28,27 px, 3931 -> 156,06 px.
  const root = [1, 2, 6, 129, 3931].map((v) => (axisUnit(v, 5000) / 5000) * plotH);
  assert.ok(root[0] > 2.4 && root[0] < 2.6, 'Wurzel: 1 Vorfall = ' + root[0] + ' px');
  assert.ok(root[1] > 3.4 && root[1] < 3.6, 'Wurzel: 2 Vorfaelle = ' + root[1] + ' px');
  assert.ok(root[2] > 6 && root[2] < 6.2, 'Wurzel: 6 Vorfaelle = ' + root[2] + ' px');
  assert.ok(root[3] > 28 && root[3] < 28.4, 'Wurzel: 129 Vorfaelle = ' + root[3] + ' px');
  assert.ok(root[4] > 156 && root[4] < 156.2, 'Wurzel: 3931 Vorfaelle = ' + root[4] + ' px');
  // Die Abstufung bleibt erhalten: 129 ist weiterhin gut ein Zehntel von 3931, nicht ein
  // Unsichtbarer und kein Gleichstand mit 1.
  assert.ok(root[4] / root[3] > 5 && root[4] / root[3] < 6, 'Verhaeltnis 3931/129 = ' + root[4] / root[3]);
});

test('Markup: Gitterlinie und Saulenhoehe haengen an derselben Achsenfunktion', () => {
  assert.match(src, /axisUnit\(v,\s*peak\)\s*\/\s*peak/, 'Gitterlinie muss axisUnit nutzen');
  assert.match(src, /"--n:"\s*\+\s*axisUnit\(cell\.total,\s*peak\)/, 'Saulenhoehe muss axisUnit nutzen');
  assert.doesNotMatch(src, /"--n:"\s*\+\s*cell\.total/, 'rohe Zahl auf der Achse waere wieder linear');
  assert.doesNotMatch(src, /\(\s*v\s*\/\s*peak\s*\)\s*\*\s*100/, 'Gitterlinie darf nicht linear stehen');
});

test('CSS: Hoeheneinheit --bh ist dieselbe fuer Balken und Marker, ohne Untergrenze am Balken', () => {
  const css = stripComments(styleCss);
  assert.match(css, /\.vt-col\s*\{[^}]*--bh:\s*calc\(var\(--u\)\s*\*\s*var\(--n,\s*0\)\)/, '--bh Grundregel');
  assert.doesNotMatch(css, /--bh:\s*max\(/, 'eine Untergrenze auf --bh hebt wieder Balken ueber ihren Achsenwert');
  assert.match(css, /\.vt-bar\s*\{[^}]*height:\s*var\(--bh\)/, 'Balkenhoehe aus --bh');
  assert.match(css, /\.vt-mark\s*\{[^}]*bottom:\s*calc\(var\(--bh\)\s*\+\s*var\(--dzc\)\s*\+\s*1px\)/, 'Markerhoehe aus --bh und --dzc');
  assert.doesNotMatch(css, /\.vt-bar\s*\{[^}]*height:\s*calc\(var\(--u\)\s*\*\s*var\(--n/, 'Balken darf nicht mehr ein eigenes Mass haben');
  assert.match(src, /vt-state-'\s*\+\s*state\s*\+\s*\(cell\.total\s*\?\s*" vt-nonzero"\s*:\s*""\)/, 'vt-nonzero genau bei Vorfaellen');
});

/* --- Prisma in der eigenen Zelle, Platte unter der Achse ------------------
 * Gemessen 2026-10-16 live im ausgelieferten Overlay (7d-Fenster, Aussenbreite 987 px
 * = Content 961 px, 24 Intervalle, altes Profil): Plot 909,48 px, Abstand 11,04 px,
 * Säule 27,31 px, Profiltiefe 8,16 px, Deckfläche 7,09 px. Die Zelle war nur 2,5-mal
 * so breit wie ihr Abstand und die Tiefenfläche eine 8-px-Scheibe an einer 27-px-Säule
 * - ein Kamm aus dünnen Stäben, kein Säulenfeld. Deshalb wird die Zelle nachgerechnet
 * und die Tiefe als Anteil davon gesetzt:
 *   --col-w = (100cqw - --gutter - 3px - 23 * --gap) / 24
 *   --d     = max(5px, min(0.30 * --col-w, 13px))
 *   --dc    = --d für jede Säule (je Profil konstant); --dzc = --dc * tan(--skew)
 * Closure der Zelle: die Vorderfläche kürzt um --dc (right: var(--dc)), die Tiefenfläche
 * sitzt auf left: 100% der Vorderfläche und füllt den Rest (width: --dc), die Deckfläche
 * schert um --dzc * cot(--skew) = --dc und endet exakt an der Zellenkante.
 * (col-w - dc) + dc = col-w - kein Prisma ragt in die Nachbarspalte, deshalb braucht
 * --dc keine Untergrenze gegen --gap mehr (die alte --dc-Klammer --dc-k ist weg).
 */
test('Tiefe: --dc/--dzc sind je Profil konstant, die je-Saeule-Klammer ist weg', () => {
  const css = stripComments(styleCss);
  assert.match(css, /\.vt-col\s*\{[^}]*--dc:\s*var\(--d\)/, 'Standard-Tiefe --dc != --d');
  assert.match(css, /\.vt-col\s*\{[^}]*--dzc:\s*calc\(var\(--dc\)\s*\*\s*var\(--dz-k\)\)/, '--dzc nicht aus --dc abgeleitet');
  assert.doesNotMatch(css, /--dc:\s*min\(/, '--dc ist wieder je Säule begrenzt - zwei Körperbreiten nebeneinander');
  assert.doesNotMatch(css, /\.vt-col\.vt-nonzero\s*\{[^}]*--dc/, 'vt-nonzero ändert wieder die Tiefe');
  assert.doesNotMatch(css, /\.vt-col\.vt-nonzero\s*\{[^}]*--dzc/, 'vt-nonzero ändert wieder die Deckflächenhöhe');
  assert.doesNotMatch(css, /--dc-k/, 'die alte gap-abhängige Tiefen-Klammer --dc-k ist noch drin');
  assert.doesNotMatch(css, /--d:\s*clamp\(/, '--d ist noch eine Raster-Klammer statt Zellenanteil');
  assert.match(css, /\.vt-profile\s*\{[^}]*--col-w:\s*calc\(\(100cqw - var\(--gutter\) - 3px - 23 \* var\(--gap\)\) \/ 24\)/, '--col-w nicht nachgerechnet');
});

test('Tiefe: Vorder-, Tiefen- und Deckfläche schließen die Zelle exakt', () => {
  assert.match(ruleBody('.vt-bar'), /left:\s*0;\s*right:\s*var\(--dc\)/, 'Vorderfläche kürzt nicht um --dc');
  assert.match(ruleBody('.vt-side'), /left:\s*100%/, 'Tiefenfläche sitzt nicht an der Vorderflächenkante');
  assert.match(ruleBody('.vt-side'), /width:\s*var\(--dc\)/, '.vt-side Breite != --dc');
  assert.match(ruleBody('.vt-top'), /width:\s*100%/, 'Deckfläche ist nicht so breit wie die Vorderfläche');
  assert.match(ruleBody('.vt-top'), /height:\s*var\(--dzc\)/, '.vt-top Höhe != --dzc');
  assert.match(ruleBody('.vt-base'), /height:\s*var\(--base-h\)/, '.vt-base Höhe != --base-h');
  assert.match(ruleBody('.vt-top'), /transform:\s*skewX\(calc\(var\(--skew\)\s*-\s*90deg\)\)/, 'Deckfläche schert nicht um --skew');
  assert.doesNotMatch(ruleBody('.vt-side'), /width:\s*var\(--d\)/, '.vt-side hält noch die Profiltiefe --d');
  assert.doesNotMatch(ruleBody('.vt-top'), /height:\s*var\(--dz\)/, '.vt-top hält noch die Profiltiefe --dz');
  assert.doesNotMatch(ruleBody('.vt-base'), /height:\s*var\(--dz\)/, '.vt-base hält noch die Profiltiefe --dz');
  // Die Scherung der Deckfläche ist genau der Rest der Zelle: tan(skew) * tan(90 - skew) = 1.
  assert.ok(Math.abs(DZ_K * Math.tan(((90 - SKEW_DEG) * Math.PI) / 180) - 1) < 1e-9,
    'dzc * cot(skew) != dc (skew ' + SKEW_DEG + 'deg, dz-k ' + DZ_K.toFixed(6) + ')');
});

test('Bodenplatte: dieselbe Platte unter jeder Säule, Gitter und Balken sitzen auf ihr', () => {
  const css = stripComments(styleCss);
  const base = ruleBody('.vt-base');
  assert.match(base, /height:\s*var\(--base-h\)/, '.vt-base Hoehe != --base-h');
  assert.match(base, /bottom:\s*calc\(-1 \* var\(--base-h\)\)/, '.vt-base ragt nicht in den Plattenstreifen unter der Null-Linie');
  assert.match(base, /left:\s*0;\s*right:\s*0/, '.vt-base ist nicht so breit wie die Zelle');
  assert.match(ruleBody('.vt-grid'), /bottom:\s*var\(--base-h\)/, 'Gitter sitzt nicht auf der Plattenoberkante');
  assert.match(ruleBody('.vt-bars'), /bottom:\s*var\(--base-h\)/, 'Saeulen sitzen nicht auf der Plattenoberkante');
  assert.match(ruleBody('.vt-plot'), /height:\s*calc\(var\(--plot-h\) \+ var\(--dz\) \+ var\(--base-h\) \+ var\(--label-h\)\)/, '.vt-plot plant Platte und Wertemarke nicht ein');
  assert.match(ruleBody('.vt-profile'), /--base-h:\s*[\d.]+px/, '--base-h fehlt');
  assert.match(ruleBody('.vt-profile'), /--label-h:\s*[\d.]+px/, '--label-h fehlt');
  // Kein Regelwerk darf die Plattenhoehe je Säule ändern - das war der Zacken am Boden.
  assert.doesNotMatch(css, /\.vt-col:not\(\.vt-nonzero\)[^{]*\{[^{]*\.vt-base/, 'Plattenhoehe ist wieder je Säule verschieden');
  assert.doesNotMatch(css, /\.vt-base[^{}]*min-height/, '.vt-base hat eine zweite Hoehe');
  // Die Wertemarke: ueber dem Prisma, tabular, ohne Zeigerfang zu sein.
  const value = ruleBody('.vt-value');
  assert.match(value, /bottom:\s*calc\(var\(--bh\) \+ var\(--dzc\) \+ 2px\)/, 'Wertemarke sitzt nicht ueber dem Prisma');
  assert.match(value, /font-variant-numeric:\s*tabular-nums/, 'Wertemarke ist nicht tabular (Ziffern springen)');
  assert.match(value, /pointer-events:\s*none/, 'Wertemarke faengt Zeiger ab (Hover auf der Säule waere gestoert)');
  assert.match(value, /text-align:\s*center/, 'Wertemarke ist nicht mittig ueber der Zelle');
  assert.match(value, /font-size:\s*11px/, 'Wertemarke ist nicht 11px (10 px Mono ist zu klein fuer vier Ziffern)');
  for (const k of STATES) assert.ok(cssRules.has('.vt-col.vt-state-' + k + ' .vt-base'), 'Plattenfarbe fehlt: vt-state-' + k);
  assert.ok(cssRules.has('.vt-base'), '.vt-base Grundregel fehlt');
  assert.doesNotMatch(css, /\.vt-foot/, 'vt-foot ist noch da (umbenannt in vt-base)');
});

test('Zelle: das Prisma bleibt in jeder Größe in seiner Spalte (Vorderfläche + Tiefe = Zelle)', () => {
  for (const content of [260, 340, 380, 460, 700, 961, 1200, 1330, 1600, 2600]) {
    const c = cellAt(content);
    assert.ok(c.col > 0, content + ' px: Zelle ' + c.col.toFixed(2) + ' px - der Raster trägt nicht');
    assert.ok(Math.abs(c.front + c.d - c.col) < 1e-9, content + ' px: Vorderflaeche + Tiefe != Zelle');
    assert.ok(c.d >= DEPTH_MIN, content + ' px: Tiefe ' + c.d.toFixed(2) + ' px - unter der Untergrenze');
    assert.ok(c.d <= DEPTH_MAX + 1e-9, content + ' px: Tiefe ' + c.d.toFixed(2) + ' px ueber dem Deckel');
    /* Unter der Mobil-Kante (380 px) wird die Tiefe zurueckgebaut - dort wird sie nicht
       gezeichnet und die Zellenrechnung gilt ohne Kuerzung. */
    if (content <= 380) continue;
    const proportional = Math.abs(c.d - DEPTH_K * c.col) < 1e-9;
    if (proportional) {
      assert.ok(Math.abs(c.front - (1 - DEPTH_K) * c.col) < 1e-9, content + ' px: Vorderflaeche nicht 70 % der Zelle');
    } else {
      assert.ok(c.front >= 0.5 * c.col, content + ' px: Vorderflaeche ' + c.front.toFixed(2) + ' px von ' + c.col.toFixed(2) + ' px');
    }
  }
});

test('Höhe: Prisma und Wertemarke der hoechsten Säule bleiben im Plot', () => {
  const peak = 5000;
  const plotHs = [...profile.matchAll(/--plot-h:\s*([\d.]+)px/g)].map((m) => Number(m[1]));
  const plotH = Math.max(...plotHs);
  const baseH = Number(profile.match(/--base-h:\s*([\d.]+)px/)[1]);
  const labelH = Number(profile.match(/--label-h:\s*([\d.]+)px/)[1]);
  const value = ruleBody('.vt-value');
  const labelFont = Number(value.match(/font-size:\s*([\d.]+)px/)[1]);
  const labelGap = Number(value.match(/bottom:\s*calc\(var\(--bh\) \+ var\(--dzc\) \+ ([\d.]+)px\)/)[1]);
  const d = cellAt(961).d, dz = d * DZ_K;
  /* Der Plot hat Luft ueber der Balkenflaeche: --dz (Tiefenflaeche der hoechsten Säule) und
     --label-h (Wertemarke). Die Marke darf nicht ueber den Plot hinausragen. */
  assert.ok(labelH >= labelFont + labelGap, '--label-h ' + labelH + ' px < Wertemarke ' + labelFont + ' + ' + labelGap + ' px');
  assert.ok(baseH >= 4 && baseH <= 8, '--base-h ' + baseH + ' px - ausserhalb 4..8 px (Bodenplatte zu hoch oder zu flach)');
  for (const incidents of [1, 2, 6, 129, 1250, 3931, 4502, peak]) {
    const bh = (axisUnit(incidents, peak) / peak) * plotH;
    const top = baseH + bh + dz + labelGap + labelFont;
    const room = baseH + plotH + dz + labelH;
    assert.ok(top <= room, incidents + ' Vorfaelle: Oberkante ' + top.toFixed(2) + ' px ueber dem Plot (' + room.toFixed(2) + ' px)');
  }
  /* Extremfall: bei peak fuellt die Säule die volle Plot-Hoehe, die Marke haengt voll in der
     Luft ueber der Balkenflaeche - dort entscheidet sich, ob der Plot hoch genug ist. */
  const bhMax = (axisUnit(peak, peak) / peak) * plotH;
  assert.ok(Math.abs(bhMax - plotH) < 1e-9, 'Säule bei peak fuellt nicht die volle Plot-Hoehe');
  assert.ok(baseH + bhMax + dz + labelGap + labelFont <= baseH + plotH + dz + labelH,
    'Wertemarke der peak-Säule ragt ueber den Plot');
  /* peak 5000 ist der Extremfall der Achse: die Grenze senkt die Tiefe von 6,79 px auf 2,49 px,
     und die Kappe sitzt dann exakt auf dem kleinsten Koerper (2,49 px). Die Balkenhoehe bleibt
     dabei der Achsenwert - sie wird nicht angehoben. */
  const bounded = cellAt(961, dmaxRatioAt(peak));
  const bh1 = (axisUnit(1, peak) / peak) * plotH;
  assert.ok(bounded.d < d, 'peak ' + peak + ': die Achsen-Grenze begrenzt die Tiefe nicht ('
    + bounded.d.toFixed(2) + ' px gegen ' + d.toFixed(2) + ' px)');
  assert.ok(Math.abs(bounded.d * DEPTH_SKEW_K - bh1) < 1e-9, 'peak ' + peak + ': Kappe '
    + (bounded.d * DEPTH_SKEW_K).toFixed(2) + ' px gegen kurzesten Koerper ' + bh1.toFixed(2) + ' px');
});

test('Mobil: unter 380 px Content fallen die Scherflächen, die Zellenrechnung bleibt wahr', () => {
  const css = stripComments(styleCss);
  const mq = css.match(/@container\s*\(max-width:\s*(\d+)px\)\s*\{\s*\.vt-side,\s*\.vt-top,\s*\.vt-value\s*\{\s*display:\s*none/);
  assert.ok(mq, 'Mobil-Regel fuer die Scherflaechen fehlt');
  const edge = Number(mq[1]);
  /* Die Kante wird aufgegeben, nicht nur versteckt: ohne --dc/--dzc gilt die
     Zellenrechnung (Vorderflaeche = Zelle) auch flach, nichts ragt in die Nachbarspalte. */
  assert.match(css, /@container\s*\(max-width:\s*\d+px\)\s*\{[^@]{0,200}?\.vt-col\s*\{\s*--dc:\s*0px;\s*--dzc:\s*0px/, 'Mobil: Tiefe-Rueckbau (--dc/--dzc = 0) fehlt');
  // Die Kante darf nicht zu früh aufgegeben werden: bei edge ist --dc noch ein Volumen.
  assert.ok(edge <= 400, 'Mobil-Kante bei ' + edge + ' px - zu früh, die Säulen wären noch Prismen');
  assert.ok(cellAt(edge).d >= 3.7, 'Mobil-Kante ' + edge + ' px: Tiefe ' + cellAt(edge).d.toFixed(2) + ' px - dort wäre noch ein Prisma');
  // Anker an der Messung 2026-10-16 (390 px Viewport): 286 px Aussenbreite = 260 px Content.
  const mob = cellAt(260);
  assert.ok(Math.abs(mob.plot - 237) < 1, 'Modell-Plot ' + mob.plot.toFixed(2) + ' px gegen 237 px bei 260 px Content');
  assert.ok(mob.col > 5 && mob.col < 8, 'Mobil-Zelle ' + mob.col.toFixed(2) + ' px');
  /* Die Modell-Tiefe von 4 px wird unterhalb der Mobil-Kante nicht gezeichnet (--dc = 0):
     das Intervall bleibt eine flache Platte, die Zellenrechnung gilt ohne Kuerzung. */
  assert.ok(260 <= edge, 'Mobil-Kante ' + edge + ' px: bei 260 px Content waere noch ein Prisma gezeichnet');
  assert.ok(mob.front + mob.d >= mob.col - 1e-9, 'flaches Intervall: Zellenrechnung gilt nicht');
  assert.ok(cellAt(460).d >= 4 && cellAt(460).col >= 12, '460 px: Zelle ' + cellAt(460).col.toFixed(2) + ' px, Tiefe ' + cellAt(460).d.toFixed(2) + ' px - Prisma');
  assert.ok(cellAt(381).col > cellAt(340).col, 'Zellenbreite wächst nicht mit dem Content');
});

test('Tiefe: die Kante ist ein Volumen, Untergrenze bis 568 px und Deckel ab 1192 px Content', () => {
  const narrow = cellAt(260);
  assert.ok(narrow.col > 5, 'schmalste gemessene Zelle ' + narrow.col.toFixed(2) + ' px');
  assert.ok(narrow.d >= DEPTH_MIN, 'Tiefe ' + narrow.d.toFixed(2) + ' px - unter der Untergrenze');
  /* Nachgerechnete Uebergaelle: 0,22 * col-w = 4 px bei col-w = 18,18 px (Content 567,7 px),
     0,22 * col-w = 8,5 px bei col-w = 38,64 px (Content 1191,5 px). */
  assert.ok(Math.abs(cellAt(460).d - DEPTH_MIN) < 1e-9, '460 px: Zelle ' + cellAt(460).col.toFixed(2)
    + ' px, Tiefe ' + cellAt(460).d.toFixed(2) + ' px - die Untergrenze greift nicht');
  assert.ok(Math.abs(cellAt(1190).d - DEPTH_K * cellAt(1190).col) < 1e-9, '1190 px: der 8,5-px-Deckel greift zu frueh');
  assert.ok(cellAt(1191).d < DEPTH_MAX - 1e-9, '1191 px: Deckel greift zu frueh (' + cellAt(1191).d.toFixed(2) + ' px)');
  assert.ok(Math.abs(cellAt(1192).d - DEPTH_MAX) < 1e-9, '1192 px: Deckel greift nicht (' + cellAt(1192).d.toFixed(2) + ' px)');
  const cap = cellAt(2600);
  assert.ok(Math.abs(cap.d - DEPTH_MAX) < 1e-9, '2600 px: Kappe greift nicht (' + cap.d.toFixed(2) + ' px)');
  assert.ok(cap.d < DEPTH_K * cap.col, '2600 px: Tiefe noch 22 % der Zelle - zu tief fuer eine breite Säule');
  // Der Abstand bleibt Luft zwischen zwei Deckflächen (nur dort, wo Prismen gezeichnet werden).
  for (const c of [460, 961, 1600, 2600]) {
    const m = cellAt(c);
    assert.ok(m.gap >= 4, c + ' px: Abstand ' + m.gap.toFixed(2) + ' px - Deckflächen berühren sich fast');
    assert.ok(m.gap / m.col <= 0.6, c + ' px: Abstand ' + (m.gap / m.col).toFixed(2) + ' der Zellenbreite');
  }
});

/* Wertemarken-Duennung (Forensik 2026-10-16): die Marke sitzt mittig ueber der Zelle und ragt bei
 * langen Zahlen ueber sie hinaus. Zwei Nachbarmarken beruehren sich, sobald die Textbreite den
 * Zentrenabstand --col-w + --gap uebersteigt. Gemessener Ziffernvorschub 0,60 em (zwei Ziffern
 * 12 px bei 10 px Mono), also 26,4 px fuer vier Ziffern und 33,0 px fuer fuenf bei 11 px. */
test('Wertemarken: Duennung ist nachgerechnet und die Zahl bleibt ohne Marke erreichbar', () => {
  const css = stripComments(styleCss);
  const thin = css.match(/@container\s*\(max-width:\s*(\d+)px\)\s*\{\s*\.vt-col:nth-child\(even\)\s+\.vt-value\s*\{\s*display:\s*none/);
  assert.ok(thin, 'Duennungs-Regel fuer die Wertemarken fehlt');
  const edge = Number(thin[1]);
  const labelFont = Number(ruleBody('.vt-value').match(/font-size:\s*([\d.]+)px/)[1]);
  const ADV = 0.6;
  const widest4 = 4 * ADV * labelFont, widest5 = 5 * ADV * labelFont;
  const pitch = (c) => cellAt(c).col + cellAt(c).gap;
  assert.ok(labelFont >= 11, 'Wertemarke auf ' + labelFont + ' px gesenkt - unter der Lesbarkeitsgrenze');
  assert.ok(edge > 380, 'Duennung bei ' + edge + ' px - die Mobil-Regel versteckt die Marken schon vorher');
  assert.ok(pitch(edge + 1) >= widest4, 'Content ' + (edge + 1) + ' px: Zentrenabstand '
    + pitch(edge + 1).toFixed(2) + ' px unter ' + widest4.toFixed(1) + ' px fuer vier Ziffern');
  assert.ok(2 * pitch(381) >= widest4, 'Content 381 px: geduennter Pitch ' + (2 * pitch(381)).toFixed(2)
    + ' px unter ' + widest4.toFixed(1) + ' px');
  assert.ok(2 * pitch(460) >= widest5, 'Content 460 px: geduennter Pitch ' + (2 * pitch(460)).toFixed(2)
    + ' px unter ' + widest5.toFixed(1) + ' px fuer fuenf Ziffern');
  /* Duennung ist kein Hover-only-Verlust: die Spalte ist per Tastatur erreichbar und der Readout
     nennt dieselbe Zahl wie aria-label und Marke. */
  assert.ok(src.includes('tabindex="0"'), 'Saeule ist nicht per Tastatur erreichbar');
  assert.ok(src.includes('addEventListener("focus", show)'), 'Readout haengt nicht am Tastatur-Fokus');
  assert.ok(src.includes('aria-label="'), 'Intervall traegt kein aria-label mit der Zahl');
});

/* Achsen-Grenze der Tiefe: die Kappe ist 1 * Tiefe hoch und darf auf keiner Saeule hoeher
 * sein als ihr Koerper - sonst steht ein Deckel auf einer Bodenplatte, und die scheinbare Hoehe
 * ist ein Vielfaches des wahren Wertes. profile3d begrenzt die Tiefe auf
 * (kurzeste gezeichnete Saeulenhoehe / Achsenmaximum) / 1 * Plot-Hoehe. Damit ist die
 * Invarianz eine Gleichung, keine nachtraegliche Klammer am Balken. */
test('Tiefe: profile3d begrenzt die Tiefe auf den kurzesten Koerper (Kappe <= Koerper)', () => {
  const css = stripComments(styleCss);
  assert.match(ruleBody('.vt-profile'), /--d:\s*min\(max\(4px,\s*calc\(var\(--col-w\) \* 0\.22\)\),\s*8\.5px,\s*calc\(var\(--plot-h\) \* var\(--dmax,\s*1\)\)\)/,
    '--d ist nicht durch die Achsen-Grenze begrenzt');
  assert.match(src, /const depthRatio = \(smallestUnit \/ peak\) \/ DEPTH_SKEW_K;/, 'depthRatio fehlt in profile3d');
  assert.match(src, /--dmax:' \+ depthRatio\.toFixed\(4\)/, '--dmax laeuft nicht in die Profil-Wurzel');
  assert.doesNotMatch(src, /depthCap|--dcap/, 'der alte Daten-Deckel --dcap ist zurueck');
  assert.doesNotMatch(css, /--dcap/, '--dcap ist in der CSS zurueck');
  assert.doesNotMatch(css, /--bh:\s*max\(/, 'CSS heilt die Invarianz wieder an der Saeulenhoehe');
  const plotH = Number(ruleBody('.vt-profile').match(/--plot-h:\s*([\d.]+)px/)[1]);
  assert.ok(plotH >= 120 && plotH <= 220, '--plot-h ' + plotH + ' px - ausserhalb 120..220 px');
  /* Jede Achse, die axisScale fuer realistische Maxima liefert, ueber jede Zellenbreite:
     die Kappe muss auf den kurzesten Koerper passen. */
  for (const max of [1, 4, 6, 11, 15, 16, 20, 21, 50, 129, 1250, 4502]) {
    const { peak } = axisScale(max);
    const ratio = dmaxRatioAt(peak);
    for (const content of [460, 961, 1600]) {
      const c = cellAt(content, ratio);
      const body = (axisUnit(1, peak) / peak) * plotH;
      assert.ok(c.d * DEPTH_SKEW_K <= body + 1e-9, 'peak ' + peak + ' / ' + content + ' px: Kappe '
        + (c.d * DEPTH_SKEW_K).toFixed(2) + ' px auf kurzem Koerper ' + body.toFixed(2) + ' px');
      assert.ok(c.d >= 2, 'peak ' + peak + ' / ' + content + ' px: Tiefe ' + c.d.toFixed(2)
        + ' px - unter der Kantensichtbarkeit');
    }
  }
  /* Das live gezeichnete 24-h-Profil (peak 50, Content 961 px): die Grenze laesst die volle
     Tiefe, das Profil behaelt sein Volumen. 1 Vorfall = 24,89 px Koerper, Grenze 24,89 px. */
  const rich = cellAt(961, dmaxRatioAt(50));
  assert.ok(Math.abs(rich.d - DEPTH_K * cellAt(961).col) < 1e-9, 'peak 50: Tiefe ' + rich.d.toFixed(2)
    + ' px - die Achsen-Grenze nimmt dem Profil das Volumen');
  assert.ok((axisUnit(1, 50) / 50) * plotH > rich.dzc, 'peak 50: kurzester Koerper '
    + ((axisUnit(1, 50) / 50) * plotH).toFixed(2) + ' px unter der Kappe ' + rich.dzc.toFixed(2) + ' px');
  /* Der alte Fehler bleibt nachgerechnet: lineare Achse bis peak 50 mit Daten-Deckel. */
  const oldBody = (1 / 50) * plotH;
  assert.ok(oldBody < 4, 'mit der alten linearen Achse bis peak 50 waere der kurzeste Koerper '
    + oldBody.toFixed(2) + ' px - eine Haarlinie, kein Prisma');
  /* Ausserhalb dieses Bereichs folgt die Tiefe der Achse: peak 40000 (ein 40.000-Vorfall-
     Intervall neben einem 1-Vorfall-Intervall) laesst nur 0,88 px Tiefe - das Profil wird
     duenn, weil die kurzeste Saeule 0,88 px hoch ist. Ein Balken, der auf diese Hoehe angehoben
     wuerde, zeigte eine Zahl, die nicht gemessen wurde. */
  const extreme = cellAt(961, dmaxRatioAt(axisScale(40000).peak));
  assert.ok(extreme.d < 2, 'peak 40000: Tiefe ' + extreme.d.toFixed(2) + ' px - die Grenze wurde uebergangen');
  assert.ok(extreme.d * DEPTH_SKEW_K <= (axisUnit(1, 40000) / 40000) * plotH + 1e-9,
    'peak 40000: Kappe ' + (extreme.d * DEPTH_SKEW_K).toFixed(2) + ' px ueber dem Koerper');
});

/* Peer-Ebene (Vergleichs-Ebene 2026-10-16): die Ausfallrate bekommt ihren Vergleich erst durch
 * diese Ebene. Guard ist die Verdrahtung - Markup, alle vier Label-Präfixe und eine Badge-Farbe
 * je Urteil. Ein Urteil ohne Farbe ist eine Aussage, die der Leser nicht sieht. */
test('Peer-Ebene: Block, Label-Präfixe und jede Urteil-Farbe sind verdrahtet', () => {
  assert.match(src, /function peerBlock\(peer\)/, 'peerBlock fehlt im Overlay');
  assert.match(src, /peerBlock\(d\.peer\)/, 'peerBlock hängt nicht an der Trace-Antwort');
  assert.match(src, /h\.t\("vt\.peer\.verdict\." \+ peer\.verdict\)/, 'Urteil ohne Label-Präfix');
  assert.match(src, /h\.t\("vt\.peer\.reason\." \+ peer\.verdictReason\)/, 'Urteilsgrund ohne Label');
  assert.match(src, /h\.t\("vt\.peer\.authority\." \+ peer\.verdictAuthority\)/, 'Mess-Autorität ohne Label');
  assert.match(src, /h\.t\("vt\.peer\.type\." \+ t\.type\)/, 'Typ-Ebene ohne Label (missed / partial / wrong-hash getrennt)');
  for (const v of PEER_VERDICTS) assert.ok(cssRules.has('.vt-badge.vt-peerv-' + v), 'Badge-Farbe fehlt: ' + v);
  // Zu wenig Stichprobe ist ein eigener Zustand, nicht eine Rate von 0.
  assert.match(src, /peer\.verdict === "insufficient-sample"/, 'kein Zustand fuer zu wenig Stichprobe');
  assert.match(src, /vt\.peer\.aloneNone/, 'Alleinstunden ohne Befund muss eine Aussage bleiben');
  assert.match(src, /vt\.peer\.estimated/, 'geschaetzte Rate muss als geschaetzt ausgewiesen werden');
  // Kleiner als 0,01 % darf nicht auf "0" verundet werden: der Peer-Median liegt bei 0,0014 %,
  // und eine 0 an dieser Stelle loescht den Unterschied, um den es dem Urteil geht.
  assert.match(src, /pct < 0\.01[\s\S]{0,80}toPrecision/, 'Peer-Rate unter 0,01 % wird auf 0 verundet');
});

test('Latenz-Ebene: Block, Label-Präfixe und jede Urteil-Farbe sind verdrahtet', () => {
  assert.match(src, /function latencyBlock\(lat\)/, 'latencyBlock fehlt im Overlay');
  assert.match(src, /latencyBlock\(d\.diagnosis && d\.diagnosis\.latency\)/, 'latencyBlock hängt nicht an der Trace-Antwort');
  assert.match(src, /h\.t\("vt\.lat\.verdict\." \+ lat\.verdict\)/, 'Urteil ohne Label-Präfix');
  assert.match(src, /h\.t\("vt\.lat\.reason\." \+ lat\.verdictReason\)/, 'Urteilsgrund ohne Label');
  assert.match(src, /h\.t\("vt\.lat\.authority\." \+ lat\.verdictAuthority\)/, 'Mess-Autorität ohne Label');
  assert.match(src, /h\.t\("vt\.lat\.class\." \+ k\)/, 'Klassen-Zeile ohne Label (spät / nie / im Fenster / unbekannt)');
  for (const v of LATENCY_VERDICTS) assert.ok(cssRules.has('.vt-badge.vt-latv-' + v), 'Badge-Farbe fehlt: ' + v);
  // Die Ring-Grenze ist Teil der Aussage: Spaetvotes gibt es nur innerhalb des Bewertungs-Rings.
  assert.match(src, /vt\.lat\.ringLine/, 'Ring-Grenze der Spaetaufzeichnung fehlt');
  assert.match(src, /lat\.verdict === "not-recorded" \|\| lat\.verdict === "insufficient-sample"/, 'fehlende Aufzeichnung und duenne Stichprobe sind eine Aussage');
});

test('Divergenz-Ebene: Linien-Tabelle, Feature-Lift und jede Urteil-Farbe sind verdrahtet', () => {
  assert.match(src, /function divergenceBlock\(div\)/, 'divergenceBlock fehlt im Overlay');
  assert.match(src, /divergenceBlock\(d\.divergence\)/, 'divergenceBlock hängt nicht an der Trace-Antwort');
  assert.match(src, /h\.t\("vt\.div\.verdict\." \+ div\.verdict\)/, 'Urteil ohne Label-Präfix');
  assert.match(src, /h\.t\("vt\.div\.reason\." \+ div\.verdictReason\)/, 'Urteilsgrund ohne Label');
  assert.match(src, /h\.t\("vt\.div\.authority\." \+ div\.verdictAuthority\)/, 'Mess-Autorität ohne Label');
  assert.match(src, /h\.t\("vt\.div\.lineage\." \+ k\)/, 'Linien-Zeile ohne Label');
  assert.match(src, /h\.t\("vt\.div\.gap\." \+ g\)/, 'Datenlücke ohne Label');
  for (const v of DIVERGENCE_VERDICTS) assert.ok(cssRules.has('.vt-badge.vt-divv-' + v), 'Badge-Farbe fehlt: ' + v);
  // noVote ist eine Messung, unknown eine Lücke - beide dürfen nicht in einer Zeile landen.
  assert.match(src, /"accepted", "runner", "own", "unknown", "noVote"/, 'noVote fehlt als eigene Linien-Zeile');
  // Ohne Hash-Aufzeichnung ist jede Zahl darunter eine Lücke: leere Tabellen würden wie ein
  // Null-Befund wirken, deshalb endet der Block dort.
  assert.match(src, /div\.verdict === "not-recorded"/, 'not-recorded zeigt Tabellen, die nichts gemessen haben');
  // Der Lift ist nur eine Aussage, wenn Grundgesamtheit und Vergleichsgruppe gefüllt sind.
  assert.match(src, /f\.reliable \? "" : "[^"]*" \+ h\.esc\(h\.t\("vt\.div\.thin"\)\)/, 'duenne Feature-Stichprobe ohne Vorbehalt im Text');
  assert.match(src, /rate\(f\.rateWith\)[\s\S]{0,140}rate\(f\.rateWithout\)/, 'Vergleichsgruppe (Rate ohne Feature) fehlt neben dem Lift');
  assert.match(src, /fac\(f\.lift\)/, 'Lift ohne Formatierung');
  // Die Feature-Bezeichnung kommt aus der Engine, nicht aus einer zweiten Uebersetzung im UI.
  assert.match(src, /r\.featureLabels/, 'Feature-Kuerzel wird im UI selbst gebaut statt aus der Engine');
});

/* Textfarbe eines Urteils-Badges als Token, nicht als Hex: die Farbe ist eine Design-Zusage,
 * und zwei Urteile mit derselben Farbe sind dem Leser dasselbe Versprechen. */
const badgeToken = (cls) => {
  const body = ruleBody('.vt-badge.' + cls);
  const m = body.match(/(?:^|;)\s*color:\s*var\((--[\w-]+)\)/);
  assert.ok(m, 'Badge-Textfarbe fehlt als Token: ' + cls);
  return m[1];
};

/* Ursachen-Ebene (Re-Trace je Validator): missed / partial / no-quorum / wrong-hash ist hier
 * nicht der Endpunkt, sondern jeder Vorfall bekommt pro Ledger einen Kandidaten mit Art,
 * Sicherheit, Pruefebenen und der naechsten Pruefung. Guard ist die Verdrahtung - Markup, eine
 * Badge-Farbe je Kandidat-Art und die Unterscheidung von Grund, Ort, Folge und Entlastung. */
test('Ursachen-Ebene: Block, Ledger-Zeilen und jede Kandidat-Art ist verdrahtet', () => {
  assert.match(src, /function causeBlock\(c\)/, 'causeBlock fehlt im Overlay');
  assert.match(src, /causeBlock\(d\.cause\)/, 'causeBlock haengt nicht an der Trace-Antwort');
  assert.match(src, /vt-causek-' \+ h\.esc\(r\.verdictKind\)/, 'Kandidat-Art ohne Badge-Klasse');
  assert.match(src, /h\.t\("vt\.cause\.confidence\." \+ r\.verdictConfidence\)/, 'Sicherheit ohne Label');
  assert.match(src, /h\.t\("vt\.cause\.layer\." \+ l\)/, 'Pruefebene ohne Label');
  assert.match(src, /r\.nextCheck/, 'naechste Pruefung fehlt in der Ledger-Zeile');
  assert.match(src, /vt\.cause\.reductionLine/, 'wie viele erklaerbare Faelle die Engine loest, muss ausgewiesen werden');
  assert.match(src, /vt\.cause\.coverageLine/, 'Abdeckung je Pruefebene fehlt');
  assert.match(src, /vt\.cause\.gap\./, 'Datenluecke ohne Label');
  for (const k of CAUSE_KINDS) assert.ok(cssRules.has('.vt-badge.vt-causek-' + k), 'Badge-Farbe fehlt: ' + k);
  assert.ok(cssRules.has('.vt-badge.vt-causek-none'), 'Badge-Farbe fehlt: none (kein Kandidat)');
  // Kein Kandidat ist keine Entlastung: die Luecke bleibt als gestrichelte Kante sichtbar.
  assert.match(ruleBody('.vt-badge.vt-causek-none'), /border-style:\s*dashed/, 'kein Kandidat sieht aus wie eine Entlastung');
  // Grund, Ort, Folge und Entlastung sind vier verschiedene Aussagen - sie duerfen nicht
  // dieselbe Farbe tragen, sonst weiss das Auge vor dem Text das Falsche.
  const kinds = CAUSE_KINDS.map((k) => badgeToken('vt-causek-' + k));
  assert.notEqual(kinds[0], kinds[3], 'Grund und Entlastung sind dieselbe Farbe');
  assert.notEqual(kinds[0], badgeToken('vt-causek-none'), 'kein Kandidat und ein Grund sind dieselbe Farbe');
  assert.notEqual(kinds[1], kinds[3], 'Ort und Entlastung sind dieselbe Farbe');
});

/* Risikoflaeche: die eigene Ausfallrate haengt an einer Achse - Quorum-Reserve, Ledger-Last,
 * beide zusammen, oder der eigene Knoten. Guard ist die Verdrahtung der Achsen-Aussage, der
 * heissen Bande in der Tabelle selbst und der duennen Last-x-Quorum-Zeile. */
test('Risikoflaeche: Block, heisse Bande, duenne Zeile und jede Achsen-Aussage ist verdrahtet', () => {
  assert.match(src, /function surfaceBlock\(s\)/, 'surfaceBlock fehlt im Overlay');
  assert.match(src, /surfaceBlock\(d\.surface\)/, 'surfaceBlock haengt nicht an der Trace-Antwort');
  assert.match(src, /vt-surfv-' \+ h\.esc\(s\.verdict\)/, 'Achsen-Urteil ohne Badge-Klasse');
  assert.match(src, /h\.t\("vt\.surface\.reason\." \+ s\.verdictReason\)/, 'Urteilsgrund ohne Label');
  assert.match(src, /h\.t\("vt\.surface\.authority\." \+ s\.verdictAuthority\)/, 'Mess-Autoritaet ohne Label');
  assert.match(src, /class="vt-hot"/, 'heisse Bande ist in der Tabelle nicht markiert');
  assert.match(src, /class="vt-thin"/, 'duenne Last-x-Quorum-Zeile ist nicht markiert');
  assert.match(src, /vt\.surface\.groupLine/, 'Gruppe mit Ledger- und Ausfallzahl fehlt neben der Share');
  for (const v of SURFACE_VERDICTS) assert.ok(cssRules.has('.vt-badge.vt-surfv-' + v), 'Badge-Farbe fehlt: ' + v);
  assert.ok(cssRules.has('.vt-table tr.vt-hot td'), 'heisse Bande ohne Tonung');
  assert.ok(cssRules.has('.vt-table tr.vt-thin td'), 'duenne Zeile ohne Markierung');
  // Beide Achsen auf duennen Gruppen ist eine andere Aussage als keine dominante Bande.
  assert.notEqual(badgeToken('vt-surfv-both-bound'), badgeToken('vt-surfv-mixed'),
    'beide Achsen bound und keine dominante Bande sind dieselbe Farbe');
  assert.notEqual(badgeToken('vt-surfv-both-bound'), badgeToken('vt-surfv-unknown'),
    'ein Urteil und keine Messung sind dieselbe Farbe');
  assert.notEqual(badgeToken('vt-surfv-load-bound'), badgeToken('vt-surfv-quorum-bound'),
    'Last und Quorum-Reserve sind verschiedene naechste Pruefungen');
});
