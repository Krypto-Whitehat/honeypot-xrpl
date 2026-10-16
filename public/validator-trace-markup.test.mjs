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
import { SENSITIVITY_VERDICTS } from '../lib/validator-sensitivity.mjs';

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
 * Gemessen 2026-10-16 live im ausgelieferten Overlay (7d-Fenster, peak 400, Plot 176 px,
 * Zelle 30,88 px): die wurzel-bezogene Achse gab den kurzesten gezeichneten Koerper 8,80 px an
 * einer Kappe von 6,78 px - 77 % der sichtbaren Hoehe einer 1-Vorfall-Saeule waren Deckflaeche,
 * und ihre Silhouette war 30,88 px breit gegen 15,58 px hoch. Das Profil las sich als schraeger
 * Kamm, nicht als Saeulenfeld. Die Achse ist jetzt logarithmisch, und die Kappe ist an ein
 * festes Verhaeltnis zum kurzesten Koerper gebunden (CAP_RATIO). */
const { axisScale, axisUnit, axisTicks, CAP_RATIO, DEPTH_SKEW_K } = await import('./validator-trace.mjs');
assert.ok(Math.abs(DEPTH_SKEW_K - DZ_K) < 1e-5,
  'JS DEPTH_SKEW_K ' + DEPTH_SKEW_K + ' gegen CSS tan(--skew) ' + DZ_K.toFixed(6));
/* Die Achsen-Grenze fuer ein Achsenmaximum: der kurzeste moegliche Koerper, umgerechnet in die
 * groesste Tiefe, auf der seine Kappe noch unter CAP_RATIO seiner Hoehe bleibt. */
const dmaxRatioAt = (peak) => ((axisUnit(1, peak) / peak) * CAP_RATIO) / DEPTH_SKEW_K;
/* Koerperhoehe eines Intervalls in px - dieselbe Kette wie CSS (--u * --n). */
const bodyAt = (value, peak, plotH) => (axisUnit(value, peak) / peak) * plotH;
/* Die Kappe, die CSS bei einer Plot-Hoehe wirklich zeichnet: dieselbe min-Klammer wie --d. */
const capAt = (peak, plotH) =>
  Math.min(Math.max(DEPTH_MIN, cellAt(961).col * DEPTH_K), DEPTH_MAX, plotH * dmaxRatioAt(peak));

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

test('Achse: Dekadenabstaende wachsen monoton gegen den Dekadenabstand der Skala', () => {
  assert.equal(axisUnit(1, 400), 400 * (Math.log(2) / Math.log(401)));
  assert.equal(axisUnit(400, 400), 400);
  /* log(1 + v) ist NICHT dekadengleichabstaendig. Der Abstand zweier Dekaden a und 10a an der
     Achse peak p ist p * (ln(1 + 10a) - ln(1 + a)) / ln(1 + p): er waechst mit a und naehert
     sich von unten dem asymptotischen Dekadenabstand p * ln(10) / ln(1 + p). Nachgerechnet bei
     peak 1000 (Achseneinheiten): 1 -> 10 = 246,75, 10 -> 100 = 320,93, 100 -> 1000 = 331,99,
     asymptotisch 333,29. Die Gitterlinien stehen also nicht gleich weit - die Achse behauptet
     nirgends etwas anderes, und die wahren Zahlen stehen in jeder Gitterlinie selbst. */
  for (const peak of [1000, 5000, 40000]) {
    const u = [1, 10, 100, 1000].map((v) => axisUnit(v, peak));
    const gaps = u.slice(1).map((x, i) => x - u[i]);
    const asym = (Math.log(10) / Math.log(1 + peak)) * peak;
    for (let i = 1; i < gaps.length; i++) {
      assert.ok(gaps[i] > gaps[i - 1], 'peak ' + peak + ': Dekadenabstand faellt: '
        + gaps.map((g) => g.toFixed(2)).join(' / '));
    }
    for (const g of gaps) {
      assert.ok(g < asym, 'peak ' + peak + ': Abstand ' + g.toFixed(2) + ' ueber dem asymptotischen ' + asym.toFixed(2));
    }
    /* Die Randverhaeltnisse sind peak-unabhaengig, weil der Faktor peak in Zaehler und Nenner
       steht: (ln 11 - ln 2) / ln 10 = 0,740363 fuer 1 -> 10 und (ln 1001 - ln 101) / ln 10 =
       0,996112 fuer 100 -> 1000. Die unterste Dekade ist rund ein Viertel schmaler als die
       oberen - das ist der Preis von log(1 + v) ohne Untergrenze. */
    const firstRatio = gaps[0] / asym;
    const lastRatio = gaps[gaps.length - 1] / asym;
    assert.ok(Math.abs(firstRatio - (Math.log(11) - Math.log(2)) / Math.log(10)) < 1e-9,
      'peak ' + peak + ': unterster Dekadenabstand ' + firstRatio.toFixed(6) + ' gegen 0,740363');
    assert.ok(Math.abs(lastRatio - (Math.log(1001) - Math.log(101)) / Math.log(10)) < 1e-9,
      'peak ' + peak + ': oberster Dekadenabstand ' + lastRatio.toFixed(6) + ' gegen 0,996112');
  }
  // Die Abbildung hat keine Untergrenze: 1 und 2 duerfen nicht auf derselben Hoehe stehen.
  assert.ok(axisUnit(2, 5000) > axisUnit(1, 5000), '1 und 2 standen auf derselben Hoehe');
});

test('Achse: die Gitterlinien sind Dekaden und Spitze, hoechstens fuenf Intervalle', () => {
  assert.deepEqual(axisTicks(5000), [0, 1, 10, 100, 1000, 5000]);
  assert.deepEqual(axisTicks(400), [0, 1, 10, 100, 400]);
  assert.deepEqual(axisTicks(250), [0, 1, 10, 100, 250]);
  assert.deepEqual(axisTicks(20), [0, 1, 10, 20]);
  assert.deepEqual(axisTicks(10), [0, 1, 10]);
  assert.deepEqual(axisTicks(5), [0, 1, 2, 3, 4, 5]);
  assert.deepEqual(axisTicks(6), [0, 2, 4, 6]);
  assert.deepEqual(axisTicks(1), [0, 1]);
  for (const max of [1, 4, 6, 11, 15, 16, 21, 25, 50, 129, 400, 4502, 9000]) {
    const { peak, ticks } = axisScale(max);
    assert.ok(peak >= max, 'peak ' + peak + ' unter dem groessten Intervall ' + max);
    assert.equal(ticks[0], 0, 'keine Null-Linie bei peak ' + peak);
    assert.equal(ticks[ticks.length - 1], peak, 'die Spitze fehlt bei peak ' + peak);
    assert.ok(ticks.length - 1 <= 5, 'peak ' + peak + ': ' + (ticks.length - 1) + ' Gitterintervalle');
    for (let i = 1; i < ticks.length; i++) {
      assert.ok(ticks[i] > ticks[i - 1], 'Gitterlinien nicht steigend bei peak ' + peak);
      const gapPx = bodyAt(ticks[i], peak, Math.min(...PLOT_HS)) - bodyAt(ticks[i - 1], peak, Math.min(...PLOT_HS));
      assert.ok(gapPx >= 8, 'peak ' + peak + ': Intervall ' + ticks[i - 1] + ' -> ' + ticks[i]
        + ' nur ' + gapPx.toFixed(2) + ' px - die Linien kleben aneinander');
    }
  }
});

test('Achse: die Kappe bleibt unter einem Drittel des Korpers - der Grund gegen den Keil', () => {
  assert.equal(CAP_RATIO, 1 / 3, 'CAP_RATIO ist ' + CAP_RATIO);
  // Die Ausgangslage, nachgerechnet: Wurzel bei peak 400 und Plot 176 px gab 8,80 px Koerper,
  // die alte --dmax 0,05 gab 6,79 px Kappe (6,7908 px bei 961 px Content, Zelle 30,87 px).
  const oldBody = Math.sqrt(1 / 400) * 176;
  const oldCap = cellAt(961, 0.05).dzc;
  assert.ok(Math.abs(oldBody - 8.8) < 1e-9 && Math.abs(oldCap - 6.79) < 0.01,
    'Ausgangslage: Koerper ' + oldBody.toFixed(2) + ' px, Kappe ' + oldCap.toFixed(2) + ' px');
  assert.ok(oldCap / oldBody > 0.7, 'die alte Kappe war ' + (oldCap / oldBody).toFixed(2)
    + '-mal so hoch wie ihr eigener Koerper');
  for (const max of [1, 4, 6, 11, 15, 16, 20, 21, 25, 50, 129, 400, 4502, 9000]) {
    const { peak } = axisScale(max);
    for (const plotH of PLOT_HS) {
      const body = bodyAt(1, peak, plotH);
      const cap = capAt(peak, plotH);
      assert.ok(cap <= body * CAP_RATIO + 1e-9, 'peak ' + peak + ' bei Plot ' + plotH + ' px: Kappe '
        + cap.toFixed(2) + ' px ueber einem Drittel des Korpers ' + body.toFixed(2) + ' px');
      assert.ok(cap >= 1, 'peak ' + peak + ' bei Plot ' + plotH + ' px: Kappe ' + cap.toFixed(2)
        + ' px - unter 1 px ist keine Flaeche mehr zu sehen');
      assert.ok(body >= cap, 'peak ' + peak + ' bei Plot ' + plotH + ' px: Koerper '
        + body.toFixed(2) + ' px unter seiner eigenen Kappe');
    }
  }
  // Die groesste Kappe, die je gezeichnet wird, bleibt klein gegen die Plot-Hoehe.
  assert.ok(DZC_MAX / PLOT_H < 0.05, 'groesste Kappe ' + (DZC_MAX / PLOT_H * 100).toFixed(2) + ' % der Plot-Hoehe');
});

test('Achse: linear waere bei grossen Spitzen unsichtbar (der Grund der Log-Skala)', () => {
  const linear = [1, 2, 6].map((v) => (v / 5000) * PLOT_H);
  for (const h of linear) assert.ok(h < 1, 'linear war ' + h.toFixed(3) + ' px - unter der Kanten-Sichtbarkeit');
  const log = [1, 2, 6, 129, 3931].map((v) => bodyAt(v, 5000, PLOT_H));
  assert.ok(log[0] > 15, 'log: 1 Vorfall = ' + log[0].toFixed(2) + ' px - zu klein, um verglichen zu werden');
  assert.ok(log[4] / log[3] < 3, 'log: 3.931 gegen 129 = ' + (log[4] / log[3]).toFixed(2)
    + ' - die Spitze darf den Rest nicht erschlagen');
  assert.ok(log[4] / log[0] > 10, 'log: 3.931 gegen 1 = ' + (log[4] / log[0]).toFixed(2) + ' - die Spitze verschwindet nicht');
  // Der kleinste Wert raumt deutlich weniger als ein Viertel des Plots ein.
  assert.ok(bodyAt(1, 5000, PLOT_H) / PLOT_H < 0.15, '1 Vorfall bei peak 5000 = '
    + (bodyAt(1, 5000, PLOT_H) / PLOT_H * 100).toFixed(2) + ' % der Plot-Hoehe');
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
  /* peak 5000 ist der Extremfall der Achse: die Grenze senkt die Tiefe von 6,79 px auf 5,64 px,
     und die Kappe ist dann genau ein Drittel des kurzesten Korpers (16,93 px). Die Balkenhoehe
     bleibt dabei der Achsenwert - sie wird nicht angehoben. */
  const bounded = cellAt(961, dmaxRatioAt(peak));
  const bh1 = (axisUnit(1, peak) / peak) * plotH;
  assert.ok(bounded.d < d, 'peak ' + peak + ': die Achsen-Grenze begrenzt die Tiefe nicht ('
    + bounded.d.toFixed(2) + ' px gegen ' + d.toFixed(2) + ' px)');
  assert.ok(Math.abs(bounded.d * DEPTH_SKEW_K - bh1 * CAP_RATIO) < 1e-9, 'peak ' + peak + ': Kappe '
    + (bounded.d * DEPTH_SKEW_K).toFixed(2) + ' px gegen ein Drittel des kurzesten Korpers '
    + (bh1 * CAP_RATIO).toFixed(2) + ' px');
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

/* Achsen-Grenze der Tiefe: die Kappe ist 1 * Tiefe hoch und darf auf keiner Saeule hoeher sein
 * als ein Drittel ihres Korpers - sonst steht ein Deckel auf einer Bodenplatte, und die
 * scheinbare Hoehe ist ein Vielfaches des wahren Wertes. profile3d begrenzt die Tiefe auf
 * CAP_RATIO * (kurzeste gezeichnete Saeulenhoehe / Achsenmaximum) / 1 * Plot-Hoehe. Damit ist
 * die Invarianz eine Gleichung, keine nachtraegliche Klammer am Balken. */
test('Tiefe: profile3d begrenzt die Tiefe auf ein Drittel des kurzesten Korpers', () => {
  const css = stripComments(styleCss);
  assert.match(ruleBody('.vt-profile'), /--d:\s*min\(max\(4px,\s*calc\(var\(--col-w\) \* 0\.22\)\),\s*8\.5px,\s*calc\(var\(--plot-h\) \* var\(--dmax,\s*1\)\)\)/,
    '--d ist nicht durch die Achsen-Grenze begrenzt');
  assert.match(src, /const depthRatio = \(\(smallestUnit \/ peak\) \* CAP_RATIO\) \/ DEPTH_SKEW_K;/, 'depthRatio fehlt in profile3d');
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
      assert.ok(c.d * DEPTH_SKEW_K <= body * CAP_RATIO + 1e-9, 'peak ' + peak + ' / ' + content + ' px: Kappe '
        + (c.d * DEPTH_SKEW_K).toFixed(2) + ' px ueber einem Drittel des kurzesten Korpers ' + body.toFixed(2) + ' px');
      assert.ok(c.d >= 2, 'peak ' + peak + ' / ' + content + ' px: Tiefe ' + c.d.toFixed(2)
        + ' px - unter der Kantensichtbarkeit');
    }
  }
  /* Das live gezeichnete 24-h-Profil (peak 50, Content 961 px): die Grenze laesst die volle
     Tiefe, das Profil behaelt sein Volumen. 1 Vorfall = 36,67 px Koerper, Kappe 6,79 px = 0,19
     davon - die Grenze greift hier noch gar nicht (sie laesst 12,22 px). */
  const rich = cellAt(961, dmaxRatioAt(50));
  assert.ok(Math.abs(rich.d - DEPTH_K * cellAt(961).col) < 1e-9, 'peak 50: Tiefe ' + rich.d.toFixed(2)
    + ' px - die Achsen-Grenze nimmt dem Profil das Volumen');
  assert.ok((axisUnit(1, 50) / 50) * plotH > rich.dzc, 'peak 50: kurzester Koerper '
    + ((axisUnit(1, 50) / 50) * plotH).toFixed(2) + ' px unter der Kappe ' + rich.dzc.toFixed(2) + ' px');
  /* Der alte Fehler bleibt nachgerechnet: die lineare Achse bis peak 50 gab 4,16 px - kaum ueber
     der 4-px-Untergrenze, und bei peak 5000 waere es ein 0,04-px-Streifen gewesen. Log gibt an
     derselben Stelle 36,67 px, also das 8,8-fache. */
  const oldBody = (1 / 50) * plotH;
  assert.ok(oldBody < 4.5, 'lineare Achse bis peak 50: kurzester Koerper ' + oldBody.toFixed(2)
    + ' px - der Abstand zur 4-px-Untergrenze ist kein Spielraum');
  assert.ok(((axisUnit(1, 50) / 50) * plotH) / oldBody > 8, 'peak 50: Log gibt '
    + (((axisUnit(1, 50) / 50) * plotH) / oldBody).toFixed(2) + '-mal so viel Koerper wie linear');
  /* Ausserhalb dieses Bereichs folgt die Tiefe der Achse: peak 40000 (ein 40.000-Vorfall-Intervall
     neben einem 1-Vorfall-Intervall) laesst 4,54 px Tiefe gegen 6,79 px - das Profil wird duenner,
     weil die kurzeste Saeule nur 13,61 px hoch ist, und die Kappe bleibt ein Drittel davon. Ein
     Balken, der auf diese Hoehe angehoben wuerde, zeigte eine Zahl, die nicht gemessen wurde. */
  const extremePeak = axisScale(40000).peak;
  const extreme = cellAt(961, dmaxRatioAt(extremePeak));
  const extremeBody = (axisUnit(1, extremePeak) / extremePeak) * plotH;
  assert.ok(extreme.d < cellAt(961).d, 'peak ' + extremePeak + ': Tiefe ' + extreme.d.toFixed(2)
    + ' px - die Grenze wurde uebergangen');
  assert.ok(Math.abs(extreme.d * DEPTH_SKEW_K - extremeBody * CAP_RATIO) < 1e-9, 'peak ' + extremePeak
    + ': Kappe ' + (extreme.d * DEPTH_SKEW_K).toFixed(2) + ' px gegen ein Drittel von ' + extremeBody.toFixed(2) + ' px');
  /* Die Grenze trifft die 4-px-Untergrenze der Tiefe erst bei peak ~165.000, geloest aus
     208 * ln(2) / (3 * ln(1 + peak)) = 4. Bis dahin ist die Kappe immer mindestens 4 px und damit
     noch eine Flaeche. Darueber gewinnt die Invarianz: die Kappe sinkt unter die Untergrenze,
     weil ein Deckel, der hoeher ist als sein Koerper, die Skala bricht. */
  const atFloor = (peak) => cellAt(961, dmaxRatioAt(peak)).d;
  assert.ok(atFloor(160000) >= 4, 'peak 160000: Tiefe ' + atFloor(160000).toFixed(2)
    + ' px - die Grenze liegt frueher als nachgerechnet');
  assert.ok(atFloor(170000) < 4, 'peak 170000: Tiefe ' + atFloor(170000).toFixed(2)
    + ' px - die Grenze liegt spaeter als nachgerechnet');
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

/* Empfindlichkeits-Ebene: die Kohorten-Gegenprobe erst trennt Knotenproblem von Netzstockung
 * und Last auf einer Transaktionsform. Guard ist die Verdrahtung - Block an der Trace-Antwort,
 * jedes Urteil in eigener Farbe, jede Messluecke als Text, duenne Zeile als eigener Zustand. */
test('Empfindlichkeits-Ebene: Block, jede Urteil-Farbe und jede Messluecke ist verdrahtet', () => {
  assert.match(src, /function sensitivityBlock\(s\)/, 'sensitivityBlock fehlt im Overlay');
  assert.match(src, /sensitivityBlock\(d\.sensitivity\)/, 'sensitivityBlock haengt nicht an der Trace-Antwort');
  assert.match(src, /h\.t\("vt\.sens\.verdict\." \+ r\.verdict\)/, 'Urteil ohne Label-Präfix');
  assert.match(src, /h\.t\("vt\.sens\.gap\." \+ g\)/, 'Messlücke ohne Label');
  assert.match(src, /h\.t\("vt\.sens\.head\." \+ hv\)/, 'Form-Urteil ohne Label');
  assert.match(src, /h\.t\("vt\.sens\.family\." \+ f\.family\)/, 'Prüffamilie ohne Label');
  for (const v of SENSITIVITY_VERDICTS) assert.ok(cssRules.has('.vt-sensv-' + v), 'Urteils-Farbe fehlt: ' + v);
  // Duenne Stichprobe ist ein Zeilenzustand, nicht eine Rate von 0.
  assert.match(src, /r\.measurable \? "" : ' class="vt-thin"'/, 'Zeile ohne duennen Zustand');
  assert.ok(cssRules.has('.vt-table tr.vt-thin td'), 'duenne Zeile ohne Markierung');
  // Ohne den Kohorten-Lift daneben ist das eigene Urteil kein Gegenbeweis.
  assert.match(src, /r\.cohortLift/, 'Kohorten-Lift fehlt in der Tabelle');
  assert.match(src, /vt\.sensNote/, 'Messbasis (Ledger, Tage mit/ohne Signatur, Peers) fehlt');
  assert.match(src, /vt\.sensGaps/, 'Messlücken werden nicht benannt');
  // Sieben Spalten auf schmalem Schirm: ohne Ueberlauf fehlt die Urteilsspalte.
  assert.ok(cssRules.has('.vt-tablewrap'), 'Tabellen-Ueberlauf fehlt');
  assert.ok(cssRules.has('.vt-table-hint'), 'Hinweis auf den Ueberlauf fehlt');
  // Die Basis-Regel steht SPAETER als die Media-Regel; ohne hoehere Spezifik gewinnt sie und der
  // Hinweis bleibt auf dem Handy versteckt, obwohl die Tabelle quer scrollbar ist.
  assert.match(ruleBody('.vt-note.vt-table-hint'), /display:\s*block/, 'Hinweis auf schmalem Schirm von der Basis-Regel erschlagen');
  assert.notEqual(ruleBody('.vt-sensv-signature-specific'), ruleBody('.vt-sensv-signature-network'),
    'Knotenproblem und Kohortenstockung sind dieselbe Farbe');
  assert.notEqual(ruleBody('.vt-sensv-signature-blind'), ruleBody('.vt-sensv-signature-specific'),
    'blind dagegen und koppelnd an deinen Knoten sind dieselbe Farbe');
});

/* Kohorten-Namen (2026-10-16): "6 Validatoren betroffen" ohne die Knoten ist keine Retrace-Spur.
 * Guard ist die Verdrahtung der dUNL-Namen in Retrace-Zeile und Sammelblock. */
test('Kohorten-Namen: Retrace und Sammelblock nennen die betroffenen dUNL-Knoten', () => {
  assert.match(src, /const peerChips = \(/, 'peerChips fehlt - Peer-Namen haben keinen gemeinsamen Aufbau');
  assert.match(src, /peerChips\(peers\)/, 'Retrace-Zeile zeigt die Peers nicht');
  assert.match(src, /peerChips\(s\.masters\)/, 'Sammelblock zeigt die Peers nicht');
  assert.match(src, /vt\.peersLine/, 'Retrace-Zeile ohne Aussage, wie viele Knoten mitfielen');
  assert.match(src, /vt\.attackPeers/, 'Sammelblock ohne Aussage ueber die betroffenen Knoten');
  assert.match(src, /vt\.peersMore/, 'abgeschnittene Peer-Liste bleibt ohne Hinweis');
  assert.match(src, /PEER_SHOWN/, 'keine Obergrenze der angezeigten Knoten');
  assert.match(src, /nameMap/, 'Master-Name hat keine Zuordnung aus der Antwort');
  assert.ok(cssRules.has('.vt-rc-peers'), 'Peer-Zeile im Retrace ohne Regel');
  assert.ok(cssRules.has('.vt-atk-peers'), 'Peer-Zeile im Sammelblock ohne Regel');
  assert.ok(cssRules.has('.vt-peer'), 'Knoten-Chip ohne Regel');
  assert.ok(cssRules.has('.vt-peer-more'), 'abgeschnittene Liste ohne eigene Form');
});

/* Netz-Kohorte (2026-10-16): die Kohorten-Hypothese fehlte genau auf den netzweiten Karten.
 * Guard ist ihre Verdrahtung im Retrace-Karton - Namen, eigenes Label, und die Trennung des
 * Belegtexts vom Timeline-Raster (der Belegtext stand in einer 180-px-Spalte). */
test('Netz-Kohorte: die Hypothese nennt die Knoten und hat ein eigenes Label', () => {
  assert.match(src, /vt-ev-peers/, 'Kohorten-Hypothese ohne Namen-Zeile');
  assert.match(src, /hy\.evidence\.peerMasters/, 'Hypothese ohne Rueckgriff auf die volle Peer-Liste');
  assert.match(src, /vt\.tag\.cohortEventNetwork/, 'netzweiter Vorfall ohne eigenes Label');
  assert.ok(cssRules.has('.vt-ev-peers'), 'Namen-Zeile in der Hypothese ohne Regel');
  assert.ok(cssRules.has('.vt-timeline .vt-ev'), 'Timeline-Zeile ohne eigenes Raster');
  assert.ok(!/180px/.test(ruleBody('.vt-ev')), 'Belegtext in der Hypothese bekommt das Timeline-Raster');
  assert.match(ruleBody('.vt-hyp .vt-ev'), /display:\s*block/, 'Belegtext ohne eigene Darstellung');
});
/* Dasselbe Problem (2026-10-16): "19 andere" ohne Vorfallstyp vermischt Knoten, die auf
 * demselben Ledger Verschiedenes hatten. Guard ist die nach Typ getrennte Nennung - in der
 * Peer-Zeile des Kartons und in der Kohorten-Hypothese. */
test('Kohorte nach Vorfallstyp: gleichfallende Knoten stehen getrennt von anderen Abweichungen', () => {
  assert.match(src, /a\.sameTypeMasters/, 'Peer-Zeile kennt die gleichfallenden Knoten nicht');
  assert.match(src, /a\.otherTypeMasters/, 'Peer-Zeile kennt die anders fallenden Knoten nicht');
  assert.match(src, /vt\.peersLineSame/, 'gleichfallende Knoten ohne eigene Aussage');
  assert.match(src, /vt\.peersLineOther/, 'anders fallende Knoten ohne eigene Aussage');
  assert.match(src, /vt-peer-group/, 'Peer-Gruppen ohne eigene Klasse');
  assert.ok(cssRules.has('.vt-peer-group'), 'Peer-Gruppe ohne Regel');
  assert.match(src, /vt\.evCohortAll/, 'Kohorte ohne Aussage, dass alle denselben Typ hatten');
  assert.match(src, /vt\.evCohortSame/, 'Kohorte ohne Zahl der gleichen Vorfallstypen');
  assert.match(src, /peerChips\(peerList\)/, 'Hypothese nennt die gleichfallenden Knoten nicht');
});
/* Gekuerzte Ranglisten (2026-10-16): 8.609 Vorfaelle waren 25 MB JSON. Guard ist, dass das
 * Overlay die Gesamtzahl aus der Antwort nimmt - nicht die Laenge der gekuerzten Liste. */
test('Gekuerzte Ranglisten: die Gesamtzahl kommt aus der Antwort, nicht aus der Liste', () => {
  assert.match(src, /retraceBlock\(d\.retrace, d\.retraceTotal\)/, 'Retrace ohne Gesamtzahl aus der Antwort');
  assert.match(src, /c\.rowTotal/, 'Ursachen-Rangliste ohne Gesamtzahl aus der Antwort');
  assert.match(src, /vt\.retraceShowing/, 'Retrace-Kuerzung ohne Hinweis auf die Gesamtzahl');
  assert.match(src, /vt\.cause\.rowsMore/, 'Ursachen-Kuerzung ohne Hinweis auf die Gesamtzahl');
});
/* Aeltere Retrace-Karten (2026-10-16): 12 Karten gezeichnet, 60 gesendet. Ohne Aufdecken
 * blieben aeltere Vorfaelle fuer den Betreiber unerreichbar - Retrace heisst aber genau:
 * den Vorfall von vor drei Tagen noch erreichen. Guard ist die Verdrahtung des Aufdeckens. */
test('Retrace-Aufdecken: gesendete Karten sind erreichbar, die Kappung ist benannt', () => {
  assert.match(src, /vt-rc-rest/, 'verborgene Karten ohne eigener Block');
  assert.match(src, /vt-rc-more/, 'Aufdecken-Button fehlt');
  assert.match(src, /vt\.retraceMore/, 'Aufdecken ohne Beschriftung');
  assert.match(src, /vt\.retraceCapped/, 'Kappung der gesendeten Karten ohne Hinweis');
  assert.ok(cssRules.has('.vt-rc-rest'), 'verborgener Kartenblock ohne Regel');
  assert.match(ruleBody('.vt-rc-rest[hidden]'), /display:\s*none/, 'verborgener Block bleibt trotz hidden sichtbar');
  assert.ok(cssRules.has('.vt-rc-more'), 'Aufdecken-Button ohne Regel');
});

test('Deckungs-Luecke: halbe Tage und geschaetzte Ledger sind im Overlay benannt', () => {
  assert.match(src, /vt\.inWindowDayOnly/, 'Tages-Koernung im Fenster ohne Hinweis');
  assert.match(src, /w\.observedDayOnly > 0/, 'der geschaetzte Anteil wird nicht ausgewertet');
  assert.match(src, /vt\.peer\.estimated", \{\s*ledgers: num\(s\.observedDaily\)/, 'Peer-Hinweis ohne Ledger-Zahl');
  assert.match(src, /partialDays: num\(s\.daysPartial/, 'halbe Tage im Peer-Hinweis fehlen');
});

/* Der Nenner des Profils ist nicht ueberall gemessen. Ein Profil, das Abweichungen bei
 * "0 Ledger beobachtet" zeigt, ist kein Messwert - und ein geschaetzter Nenner, der nicht
 * benannt wird, ist eine Zahl ohne Herkunft. */
test('Profil-Nenner: geschaetzte Ledger werden benannt, nicht still gerechnet', () => {
  assert.match(src, /vt\.profileLedgersEstimated/, 'Profil-Fussnote fehlt');
  assert.match(src, /profile\.estimatedLedgers > 0/, 'die Gesamtzahl wird nicht ausgewertet');
  assert.match(src, /vt\.bucketLedgersEstimated/, 'Intervall-Hinweis fehlt');
  assert.match(src, /cell\.ledgersEstimated > 0/, 'der geschaetzte Anteil je Intervall wird nicht ausgewertet');
});

/* "+19 weitere" ohne Weg, sie zu sehen, war eine Zahl ohne Spur. Die Keys sind schon in der
 * Antwort - Aufdecken darf keine zweite Anfrage kosten. */
test('Peer-Listen: die gekuerzte Liste laesst sich aufdecken', () => {
  assert.match(src, /data-peer-more/, 'kein Aufdecken-Knopf');
  assert.match(src, /class="vt-peer-rest" hidden/, 'die restlichen Keys sind nicht vorgemerkt');
  assert.match(src, /querySelectorAll\("\[data-peer-more\]"\)/, 'der Handler fehlt');
});
