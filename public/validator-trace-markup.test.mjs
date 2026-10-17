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
import { TRUTH_VERDICTS } from '../lib/validator-truth.mjs';
import { LATENCY_VERDICTS } from '../lib/validator-vote-latency.mjs';
import { DIVERGENCE_VERDICTS } from '../lib/validator-divergence.mjs';
import { CAUSE_KINDS } from '../lib/validator-cause.mjs';
import { SURFACE_VERDICTS } from '../lib/validator-quorum-surface.mjs';
import { COUPLING_GAPS, COUPLING_VERDICTS, LOAD_TREND_VERDICTS } from '../lib/validator-stress-coupling.mjs';
import { WATCH_TYPES } from '../lib/validator-watch.mjs';
import { SENSITIVITY_VERDICTS } from '../lib/validator-sensitivity.mjs';
import { CAPTURE_GAP_BASES_MEASURED } from '../lib/validator-trace.mjs';
import { WATCH_VERDICTS } from '../lib/validator-watch.mjs';

const here = path.dirname(fileURLToPath(import.meta.url));
const read = (rel) => readFileSync(path.join(here, rel), 'utf8');

const traceJs = read('validator-trace.mjs');

/* Beleg-Arten der Erfassungs-Luecke: die UI zaehlt sie selbst auf. Diese Aufzaehlung war am
 * 2026-10-17 bereits gegen die Bibliothek gedriftet (neue Basis in lib, alte Liste im Audit).
 * Guard: UI-Liste und Bibliothek muessen wortgleich dieselben Beleg-Arten nennen. */
test('Erfassungs-Basen: UI und Bibliothek nennen dieselben Beleg-Arten', () => {
  const decl = src.match(/const CAPTURE_BASES = new Set\(\[([^\]]*)\]\)/);
  assert.ok(decl, 'die UI listet ihre Beleg-Arten nicht mehr explizit');
  const ui = (decl[1].match(/"([^"]+)"/g) || []).map((x) => x.slice(1, -1));
  assert.deepEqual(ui, CAPTURE_GAP_BASES_MEASURED, 'UI und Bibliothek beschreiben verschiedene Beleg-Arten');
});
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
const { axisScale, axisUnit, axisTicks, AXIS_MIN_PEAK, CAP_RATIO, DEPTH_SKEW_K } = await import('./validator-trace.mjs');
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
  assert.match(base, /left:\s*0;\s*right:\s*0;/, '.vt-base fuellt die Zelle nicht - der Zustand ist wieder 24 einzelne Platten');
  assert.doesNotMatch(base, /box-shadow:\s*inset 0 0 0 1px/, '.vt-base hat wieder einen Rundum-Rand - 24 gefasste Fliesen unter einer durchgehenden Ebene');
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
  assert.match(src, /function peerBlock\(peer, absence\)/, 'peerBlock fehlt im Overlay');
  assert.match(src, /peerBlock\(d\.peer, d\.absence\)/, 'peerBlock hängt nicht an der Trace-Antwort samt Zuordnungs-Bilanz');
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
  // Das Erfassungs-Urteil zeigt seinen Beleg in der Zahl, nicht als Behauptung: proven / denied /
  // unknown und die Quelle des Close-Hash stehen in der Zeile.
  assert.match(src, /lat\.verdict === "capture-only"/, 'Erfassungs-Urteil hat keinen eigenen Pfad');
  assert.match(src, /vt\.lat\.closureLine/, 'Schliess-Beleg der Latenz-Ebene fehlt');
  assert.match(src, /CLOSURE_BASIS_KEY/, 'Quelle des Close-Hash wird nicht benannt');
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
/* Kopplungs-Ebene: die Frage 'welche dUNL-Knoten auf genau diesem Ledger' wird nur beantwortet,
 * wenn die benannten Knoten an der Ledger-Zeile haengen - nicht an einer Tageszahl. Guard ist
 * die Verdrahtung: Block an der Trace-Antwort, Master-Liste an der Peak-Zeile, jede Achse mit
 * eigenem Urteil, jede Luecke als Text, jedes Urteil in eigener Farbe. */
test('Kopplungs-Ebene: benannte Knoten je Ledger, beide Achsen und jede Luecke ist verdrahtet', () => {
  assert.match(src, /function couplingBlock\(c\)/, 'couplingBlock fehlt im Overlay');
  assert.match(src, /couplingBlock\(d\.coupling\)/, 'couplingBlock haengt nicht an der Trace-Antwort');
  assert.match(src, /peerChips\(named, p\.peerTruth, p\.peerNames\)/, 'Peak-Zeile ohne benannte dUNL-Knoten oder ohne Gegenurteil');
  assert.match(src, /p\.mastersTotal/, 'volle Zahl der abweichenden Knoten fehlt neben der benannten Kante');
  assert.match(src, /vt\.coupling\.mastersMore/, 'Cap der benannten Knoten wird nicht ausgewiesen');
  assert.match(src, /h\.t\("vt\.coupling\.verdict\." \+ c\.verdict\)/, 'Kopplungs-Urteil ohne Label');
  assert.match(src, /h\.t\("vt\.coupling\.axis\." \+ c\.verdictAxis\)/, 'Urteils-Achse ohne Label');
  assert.match(src, /h\.t\("vt\.coupling\.authority\." \+ c\.verdictAuthority\)/, 'Mess-Autoritaet ohne Label');
  assert.match(src, /h\.t\("vt\.coupling\.gap\." \+ g\)/, 'Messluecke ohne Label');
  assert.match(src, /String\(c\.verdictReason\)/, 'Urteilsgrund als Code fehlt - die Begruendung muss nachlesbar bleiben');
  assert.match(src, /cov\.namedMastersIncompleteRows/, 'gezaehlte Abweichung ohne benannten Knoten wird nicht ausgewiesen');
  assert.match(src, /s\.ownVerdict/, 'Knoten-Urteil fehlt neben dem Kohorten-Urteil');
  assert.match(src, /p\.closureClosed/, 'Schliess-Beweis fehlt an der Peak-Zeile');
  for (const v of COUPLING_VERDICTS) assert.ok(cssRules.has('.vt-badge.vt-coupl-' + v), 'Badge-Farbe fehlt: ' + v);
  assert.notEqual(badgeToken('vt-coupl-stress-coupled'), badgeToken('vt-coupl-no-coupling-measured'),
    'eine gemessene Kopplung und ein gemessenes Nicht-Vorhandensein sind dieselbe Farbe');
  assert.notEqual(badgeToken('vt-coupl-stress-coupled'), badgeToken('vt-coupl-not-recorded'),
    'eine Messung und keine Messung sind dieselbe Farbe');
  assert.ok(cssRules.has('.vt-tablewrap'), 'Kopplungs-Tabellen ohne Ueberlauf');
  assert.ok(cssRules.has('.vt-code'), 'Urteils-Code ohne Regel');
});

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
  assert.match(src, /peerChips\(peers, truthOf\(peers\), namesOf\(peers\)\)/, 'Retrace-Zeile zeigt die Peers nicht oder ohne Gegenurteil');
  assert.match(src, /peerChips\(s\.masters, s\.peerTruth, s\.peerNames\)/, 'Sammelblock zeigt die Peers nicht oder ohne Gegenurteil');
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
  assert.match(src, /peerChips\(peerList, truthOf\(peerList\), namesOf\(peerList\)\)/, 'Hypothese nennt die gleichfallenden Knoten nicht');
  assert.match(src, /peerChips\(list, truthOf\(list\), namesOf\(list\)\)/, 'Peer-Gruppe nennt die Knoten ohne Gegenurteil');
  assert.match(src, /a\.peerTruth/, 'Karton ohne Gegenurteil je benanntem Knoten');
  assert.match(src, /a\.peerNames/, 'Karton ohne Namen aus der Netz-Auskunft');
  assert.match(src, /vt\.peersTruth/, 'Kohorten-Gegenprobe des Kartons ohne eigene Aussage');
  assert.ok(cssRules.has('.vt-rc-peerstruth'), 'Gegenprobe-Zeile ohne Regel');
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

// Guard: die Betroffenheits-Zeile muss dieselbe Breite haben wie die Tabelle. Ein colspan,
// der nicht mit der Zahl der Spaltenkoepfe uebereinstimmt, verschiebt die ganze Tabelle.
test("Kritikalitaets-Tabelle: Betroffenheits-Zeile deckt genau die Spalten der Kopfzeile", () => {
  const head = traceJs.match(/const head = \[([^\]]*vt\.cq\.hLedger[^\]]*)\]/);
  assert.ok(head, "Kopfzeile der Kritikalitaets-Tabelle nicht gefunden");
  const cols = head[1].split(",").filter((x) => x.trim() !== "").length;
  const colspan = [...traceJs.matchAll(/colspan="(\d+)"/g)].map((m) => Number(m[1]));
  assert.ok(colspan.includes(cols), 'Betroffenheits-Zeile braucht colspan="' + cols + '" (Spalten: ' + cols + ")");
  assert.ok(/vt-cq-affected/.test(traceJs), "die Betroffenheits-Zeile fehlt im Overlay");
  assert.ok(/affectedCount/.test(traceJs), "ohne affectedCount darf keine Kohorte behauptet werden");
});

/* Bodenplatte und Prisma muessen auf derselben Platte stehen. Live-Nachweis 2026-10-16 im
 * 24-h-Fenster von xrp.vet (Content 961 px, Plot 917,64 px, Zelle 30,86 px, Abstand 7,69 px,
 * --dc = --dzc = 6,78 px): die Bodenplatte war so breit wie die ganze Zelle, ihre gescherte
 * Deckflaeche reichte deshalb 6,78 px in den 7,69 px breiten Abstand - 0,91 px frei.
 * elementFromPoint traf bei 6 von 8 nicht-leeren Saeulen die .vt-base der eigenen Saeule, und
 * 258 von 864 Pixeln in den Abstaenden nahe der Null-Linie waren bemalt (29,9 %). */
test('Bodenplatte: Fuss und Prisma teilen dieselbe Grundflaeche, der Abstand bleibt frei', () => {
  // Die Kuerzung um --dc war noetig, solange je Saule eine eigene Scherflaeche hatte. Die hat
  // die Platte nicht mehr (siehe Regel unten: keine .vt-base::after); die Grundflaeche ist der
  // eine Koerper .vt-floor / .vt-floor-top. Vollbreite bemalt deshalb keinen Abstand: die Platte
  // endet mit der Zelle, und der Abstand bleibt die Luecke, die zeigt, wie weit die Ebene reicht.
  assert.match(ruleBody('.vt-base'), /left:\s*0;\s*right:\s*0;/,
    '.vt-base fuellt die Zelle nicht - der Fuss ist wieder in 24 Stuecke zerschnitten');
  assert.doesNotMatch(stripComments(styleCss), /\.vt-base::after/, 'die je-Saeulen-Scherplatte ist zurueck - Vollbreite wuerde sie in den Abstand legen');
  const c = cellAt(961);
  const reach = (c.col - c.d) + c.dzc;
  assert.ok(Math.abs(reach - c.col) < 1e-9,
    'Scherflaeche endet bei ' + reach.toFixed(2) + ' px statt an der Zellenkante ' + c.col.toFixed(2) + ' px');
  assert.ok(Math.abs(c.dzc - c.d) < 1e-9, '--dzc != --dc - Scherung und Tiefe divergieren');
  // Der alte Zustand, nachgerechnet: Fuss = volle Zellenbreite, die Scherflaeche reichte um
  // --dzc in den Abstand und liess nur gap - dzc frei (6,78 px von 7,69 px verbraucht).
  const freiAlt = c.gap - c.dzc;
  assert.ok(freiAlt > 0 && freiAlt < 1,
    'der alte Ueberstand ist nicht nachgerechnet (frei waren ' + freiAlt.toFixed(2) + ' px)');
});

/* Ein nachgetragener Schliess-Hash ist ein Nachweis von ausserhalb. Nennt die Zelle nicht, woher
 * er kommt und wer ihn gegengeprueft hat, liest sich die Spalte wie eigener Moerbeweis. Und eine
 * Kohorte ohne Namen ist eine Zahl ohne Spur. */
test('Kritikalitaets-Zelle: Fremdquelle, Gegenpruefung und Kohorten-Namen sind benannt', () => {
  assert.match(src, /c\.basis === "xrpscan"/, 'der nachgetragene Hash wird nicht als Fremdquelle ausgewertet');
  assert.match(src, /vt\.cq\.closureSource/, 'Quelle des nachgetragenen Hashes hat keine Beschriftung');
  assert.match(src, /c\.verifiedBy/, 'die zweite Autoritaet wird nicht ausgewertet');
  assert.match(src, /vt\.cq\.closureVerified/, 'Gegenpruefung hat keine Beschriftung');
  assert.match(src, /peerChips\(allM, allT, allN\)/, 'die Betroffenheits-Zeile nennt die Knoten nicht oder ohne Gegenurteil');
  assert.match(src, /typeof n\.name === "string" && n\.name \? n\.name : null/, 'der Name aus der Netz-Auskunft wird nicht ausgewertet');
  assert.match(src, /e\.name \?\? nameOf\(m\)/, 'ohne Netz-Name faellt der Chip nicht auf die geladene dUNL-Liste zurueck');
  // Ein Name ohne Gegenurteil ist eine Beschuldigung. Die Lib liefert je Knoten das Urteil,
  // und die UI darf es nicht wegwerfen.
  assert.match(src, /vt\.cq\.truth\.summary/, 'die Kohorten-Bilanz fehlt im Overlay');
  assert.match(src, /vt-peer-\' \+ verdict/, 'der Chip tragt sein Gegenurteil nicht sichtbar');
});

/* Die Chip-Liste wird in zwei Stuecke geschnitten (shown / rest), und map liefert die Position
 * innerhalb des Schnitts. Wer Namen und Gegenurteil ueber diese Position gegen die Gesamtliste
 * indexiert, haengt ab dem 13. Knoten den Namen des ersten an. Live gemessen am 2026-10-17 auf
 * #107694001: 34 benannte Knoten, die 22 verborgenen trugen die Namen 1-22, die Knoten 23-34
 * blieben ganz ungenannt. */
test('Kohorten-Chips: Name und Gegenurteil haengen am Knoten, nicht an seiner Position', () => {
  assert.match(src, /const byMaster = new Map\(\)/, 'Name und Gegenurteil werden nicht je Master-Key abgelegt');
  assert.match(src, /const chip = \(m\) =>/, 'der Chip wird ueber die Position im Schnitt aufgerufen - die Liste ist geschnitten, die Namen sind es nicht');
  assert.match(src, /byMaster\.get\(m\)/, 'der Chip holt Name und Gegenurteil nicht ueber den Master-Key');
  const body = src.slice(src.indexOf("const chip = (m) =>"), src.indexOf("const shown = list.slice(0, PEER_SHOWN)"));
  assert.ok(body.length > 0, "der Chip ist nicht auffindbar - der Guard prueft ins Leere");
  assert.doesNotMatch(body, /names\[i\]|truth\[i\]/, 'innerhalb des Chips wird gegen die Gesamtliste indexiert - ab dem 13. Knoten steht ein fremder Name da');
});

/* Die Gegenliste steht in derselben Zelle wie die angeklagten Knoten. Ohne eigenes Etikett
 * liese sie sich als weitere Vorwurfsliste lesen. */
test('Gegenliste: die Abgestimmten haben ein eigenes Etikett, nicht das der Angeklagten', () => {
  assert.match(ruleBody(".vt-cq-voters > small"), /var\(--a6-success\)/, "die Abgestimmten stehen in derselben Farbe wie die Vorwuerfe");
  assert.match(ruleBody(".vt-cq-voters-none > small"), /var\(--a6-muted\)/, "keine Signierung gesehen zu haben ist ein Messstatus, kein Vorwurf");
  assert.doesNotMatch(ruleBody(".vt-cq-voters > small"), /--a6-error|--a6-sev-suspect/, "die Gegenliste steht in Vorwurfsfarbe");
});

/* Die Grenze, die aus der Schliessung folgt, muss an drei Stellen lesbar sein: in der
 * Kritikalitaets-Zelle, in der Messung 'vote-coverage-thin' und im Sammelereignis. Fehlt sie,
 * steht '19 Validatoren ohne Vote' als Netz-Urteil da, obwohl der Schliess-Beweis in derselben
 * Zeile sagt, dass hoechstens 7 davon echt sein koennen. */
test('Erfassungs-Grenze: Zelle, Messung und Sammelereignis tragen die nachrechenbare Zahl', () => {
  assert.match(src, /r.capture/, 'die Kritikalitaets-Zelle wertet die Grenze nicht aus');
  assert.match(src, /vt.cq.bound/, 'die Grenze in der Zelle hat keine Beschriftung');
  assert.match(src, /e.genuineAbsentMax/, 'die Messung nennt die Obergrenze echter Nicht-Signierer nicht');
  assert.match(src, /vt.evCoverageBound/, 'die Messung hat keine Beschriftung fuer die Grenze');
  assert.match(src, /s.capture/, 'das Sammelereignis wertet die Grenze nicht aus');
  assert.match(src, /vt.atkBound/, 'das Sammelereignis hat keine Beschriftung fuer die Grenze');
  // Ohne Forensik-Zeile darf die Betroffenheits-Zahl nicht unqualifiziert stehen.
  assert.match(src, /vt.atkBoundMissing/, 'das Sammelereignis behauptet eine Zahl ohne Grenze, wo keine Forensik da ist');
});

test('null ist nicht 0: eine nicht erfasste Zahl darf nicht als Messwert erscheinen', () => {
  // Number(null) === 0. Ohne die null-Vorpruefung wird aus 'nicht erfasst' im Text eine 0.
  assert.match(src, /v === null \|\| v === undefined/, 'num() unterscheidet null nicht von 0');
  assert.doesNotMatch(src, /const num = \(v\) => \(Number\.isFinite\(Number\(v\)\)/, 'num() prueft zuerst die Zahl, nicht die Erfassung');
  // Live am 2026-10-17 auf #107709532: ovb war im Rekorder null, die Zelle zeigte "eigener
  // Empfang 38 von 0 Validierungen". Die Basis fehlt dort - sie ist nicht gemessen null.
  assert.match(src, /Number\.isFinite\(r\.observedBaseline\)/, 'ohne eigene Empfangs-Basis wird der Satz nicht gerendert');
  assert.match(src, /Number\.isFinite\(r\.capture\.coverageBaseline\)/, 'ohne Abdeckungs-Niveau wird die Zurechnung nicht gerendert');
});

test("Gegenprobe-Text: das Fenster wird benannt, nicht als 24 h gesetzt", () => {
  assert.match(src, /function truthWindowLabel\(/, "die Fensterzahl hat keine gemeinsame Quelle im Overlay");
  assert.match(src, /vt\.truth\.window30d/, "das 30-Tage-Fenster hat keine Beschriftung");
  assert.match(src, /min: n\(t\.falsePositiveMin\), window \}\)/, "der Widerspruchstext kennt keine Fensterzahl");
  assert.match(src, /window: truthWindowLabel\(cq\.affectedTruth\.windowHours\)/, "die Kohorten-Bilanz nennt ihr Fenster nicht");
  assert.match(src, /vt\.truth\.outside/, "consistent ohne die offene Zahl ausserhalb des Fensters ist ein Halbfreispruch");
  const i18n = read("i18n-validator.mjs");
  assert.equal((i18n.match(/vt\.truth\.contradicted.*\{window\}/g) || []).length, 2, "der Widerspruchstext nennt das Fenster nicht in beiden Sprachen");
  assert.equal((i18n.match(/vt\.cq\.truth\.summary.*\{window\}/g) || []).length, 2, "die Kohorten-Bilanz nennt das Fenster nicht in beiden Sprachen");
  assert.doesNotMatch(i18n, /im selben 24-h-Fenster|in the same 24 h window/, "ein Fenster steht fest im Text, obwohl die Auswahl an der eigenen Spanne haengt");
});

/* Kohorten-Aufteilung (2026-10-17): '19 Validatoren betroffen' auf einem geschlossenen Ledger
 * ist eine Zahl, die Ausfall und Erfassungs-Luecke vermischt. Der Sammelblock und der
 * Retrace-Karton muessen beide getrennt nennen, was gemessen ist. */
test('Kohorten-Aufteilung: Sammelblock trennt Knoten-Ausfall und Erfassungs-Luecke', () => {
  assert.match(src, /vt\.attackSplit/, 'Sammelblock ohne Aufteilung der abweichenden Knoten');
  assert.match(src, /s\.faultValidators/, 'Sammelblock liest die Zahl der zurechenbaren Abweichungen nicht');
  assert.match(src, /s\.captureOnlyValidators/, 'Sammelblock liest die Zahl der Unerfassten nicht');
  assert.match(src, /vt\.peersLineCapture/, 'Retrace ohne Gruppe der Knoten ohne Knotenfehler');
  assert.ok(cssRules.has('.vt-atk-split'), 'Aufteilung im Sammelblock ohne eigene Form');
  assert.ok(cssRules.has('.vt-badge.vt-scope-capture-cohort'), 'Scope-Abzeichen ohne Regel');
  const i18n = read('i18n-validator.mjs');
  assert.equal((i18n.match(/'vt\.attackSplit'/g) || []).length, 2, 'die Aufteilung fehlt in einer Sprache');
  assert.equal((i18n.match(/'vt\.attackSplitOpen'/g) || []).length, 2, 'die offene Zuordnung fehlt in einer Sprache');
  assert.match(src, /s\.unattributedValidators/, 'Sammelblock liest die Zahl der offenen Zuordnungen nicht');
  assert.match(src, /vt\.peersLineOpen/, 'Retrace ohne Gruppe der Knoten mit offener Zuordnung');
  assert.ok(cssRules.has('.vt-atk-split-open'), 'offene Zuordnung im Sammelblock ohne eigene Form');
  assert.equal((i18n.match(/vt\.peersLineCapture/g) || []).length, 2, 'die Unerfassten-Gruppe fehlt in einer Sprache');
  assert.equal((i18n.match(/vt\.scope\.capture-cohort/g) || []).length, 2, 'der neue Scope hat kein Label in beiden Sprachen');
  assert.doesNotMatch(i18n, /'vt\.attackAffected': '\{n\} (validators|Validatoren)'/, 'die Sammelzahl spricht weiterhin pauschal von betroffenen Validatoren');
  assert.doesNotMatch(i18n, /Simultaneous failures|Gleichzeitige Ausf\u00e4lle/, 'der Titel behauptet Ausfaelle, gemessen ist Abweichen in dieser Erfassung');
});

/* Scope-Labels (2026-10-17): 'netzweit' und 'die ganze Kohorte fiel' sind Netz-Aussagen, die
 * auf einem bewiesen geschlossenen Ledger nicht belegt sind. Gemessen ist, was diese Erfassung
 * auf diesem Ledger nicht sah - die Schliess-Spalte traegt den Gegenbeweis. */
test('Scope-Label: die Netz-Formel ist durch die Erfassungs-Formel ersetzt', () => {
  const i18n = read('i18n-validator.mjs');
  assert.doesNotMatch(i18n, /'vt\.scope\.network': '(network-wide|netzweit)'/, 'der Scope spricht pauschal netzweit, obwohl die Schliessung das widerlegt');
  assert.doesNotMatch(i18n, /cohortEventNetwork.*?(whole cohort fell|ganze Kohorte fiel)/s, 'die Kohorten-Formel behauptet ein Fallen, gemessen ist Unerfasstsein');
  assert.equal((i18n.match(/'vt\.scope\.network'/g) || []).length, 2, 'das Scope-Label fehlt in einer Sprache');
  assert.equal((i18n.match(/'vt\.tag\.cohortEventNetwork'/g) || []).length, 2, 'die Kohorten-Formel fehlt in einer Sprache');
});

/* Deklarations-Guard (2026-10-17): TRUTH_STATES wurde im Code benutzt, die Deklaration ging in
 * 47a5583 verloren - der Overlay warf bei jedem Offnen und zeigte nur 'Trace could not be
 * loaded.'. Eine Zustands-Menge, die der Code als Wert anfasst, muss im Modul stehen. */
test('Overlay: jede als Wert benutzte Zustands-Menge ist deklariert', () => {
  const used = [...new Set([...src.matchAll(/\b([A-Z][A-Z0-9_]{2,})\s*(?:\.has\(|\.map\(|\.filter\(|\.includes\(|\[)/g)].map((m) => m[1]))];
  const undeclared = used.filter((n) => !new RegExp('(?:export\\s+)?(?:const|let|var)\\s+' + n + '\\b').test(src)
    && !new RegExp('import[^\\n]*\\b' + n + '\\b').test(traceJs));
  assert.deepEqual(undeclared, [], 'benutzt ohne Deklaration: ' + undeclared.join(', '));
});

test('Gegenprobe: die Zustands-Menge ist deklariert, gleich der Lib, jeder Status mit Form', () => {
  const m = src.match(/const TRUTH_STATES = new Set\(\[([^\]]*)\]\)/);
  assert.ok(m, 'TRUTH_STATES ist nicht deklariert - die UI kann kein Gegenurteil faerben');
  const states = m[1].split(',').map((s) => s.trim().replace(/^["']|["']$/g, '')).filter(Boolean);
  assert.deepEqual(states.slice().sort(), [...TRUTH_VERDICTS].sort(), 'UI-Zustande weichen von TRUTH_VERDICTS der Lib ab');
  for (const s of [...states, 'none']) assert.ok(cssRules.has('.vt-truth-' + s), 'Status ohne Form: vt-truth-' + s);
});

/* Zurechnung (2026-10-17): die Zaehlerkarten fuehren 'kein Vote erfasst'. Auf einem bewiesen
 * geschlossenen Ledger ist das erst dann eine Abweichung dieses Knoten, wenn die Netz-Referenz
 * dieselbe Abwesenheit fuer denselben Knoten im selben Fenster nennt. Die Ebene muss in der Lib
 * stehen, in der Antwort gefuehrt werden und in der Oberflaeche eine Form je Status haben -
 * sonst bleibt die Karte eine Zahl, die niemand einordnen kann. */
test('Zurechnung: Lib-Ebene, Antwortfeld und Oberflaeche haengen aneinander', () => {
  const lib = read('../lib/validator-truth.mjs');
  const query = read('../lib/validator-trace-query.mjs');
  const i18n = read('i18n-validator.mjs');
  assert.ok(lib.includes('export const ATTRIBUTION_STATES'), 'ATTRIBUTION_STATES fehlt in der Lib');
  assert.ok(lib.includes('export function attributeAbsences'), 'attributeAbsences fehlt in der Lib');
  assert.ok(query.includes('attributeAbsences'), 'die Leseschicht ruft die Zurechnung nicht');
  assert.ok(query.includes('attribution,'), 'die Antwort fuehrt kein attribution-Feld');
  for (const k of ['absenceClaims', 'absenceAttributableMax', 'absenceArtifactMin', 'absenceOpen'])
    assert.ok(query.includes(k), 'die Zaehlerkarte fuehrt ' + k + ' nicht');
  assert.ok(src.includes('function attributionBlock('), 'attributionBlock fehlt in der Oberflaeche');
  assert.ok(src.includes('attributionBlock(d.attribution)'), 'die Zurechnung der Antwort wird nicht gerendert');
  assert.ok(src.includes('+ attributionLine +'), 'die Zurechnungszeile haengt nicht an den Karten');
  for (const s of ['bounded', 'open']) assert.ok(lib.includes('"' + s + '"'), 'Zurechnungs-Status fehlt: ' + s);
  for (const s of ['contradicted', 'covered', 'open']) assert.ok(cssRules.has('.vt-attr-' + s), 'Status ohne Form: vt-attr-' + s);
  for (const k of ['vt.attr.title', 'vt.attr.bounded', 'vt.attr.open', 'vt.attr.partial', 'vt.attr.unusable'])
    assert.equal(i18n.split("'" + k + "'").length - 1, 2, k + ' fehlt in einer Sprache');
});

/* Forensik-Deckung (2026-10-17): die Risikolehne rechnet statsLedgers gegen allIncidentLedgers
 * und zaehlt daysWithoutForensics - aber keine Zeile der Oberflaeche nannte es. Ein Lift, der auf
 * einem Bruchteil der Ausfall-Ledger steht, ist ohne diesen Nenner eine Zahl, die zu hoch gelesen
 * wird. Fehlende Forensik ist eine Luecke, kein Befund ohne Abweichung. */
test('Risikobasis: die Forensik-Deckung wird ausgesprochen, nicht nur gerechnet', () => {
  const retrace = read('../lib/validator-retrace.mjs');
  const i18n = read('i18n-validator.mjs');
  for (const k of ['allIncidentLedgers', 'forensicsShare', 'daysWithoutForensics', 'daysWithStats', 'statsLedgers'])
    assert.ok(retrace.includes(k), 'die Lib fuehrt ' + k + ' nicht');
  assert.ok(src.includes('vt.riskForensics'), 'die Oberflaeche nennt die Forensik-Deckung nicht');
  assert.equal(i18n.split("'vt.riskForensics'").length - 1, 2, 'vt.riskForensics fehlt in einer Sprache');
});

/* 'erfasste Stimmen / Ziel' ist die einzige Zeile, die ein Betreiber als Quorum-Aussage liest.
 * Das Ziel selbst war eine Rechnung, die nie als solche benannt war. Seit 2026-10-17 fuehrt jede
 * Zeile ihre Herleitung: gemessen am Endpunkt, gerechnet aus der dUNL-Liste, oder nicht erfasst. */
test('Quorum-Ziel: jede Zeile nennt die Herleitung ihres Ziels', () => {
  assert.match(src, /NEEDED_BASES = new Set\(\["measured", "derived", "not-recorded", "day-measured"\]\)/,
    'das Overlay kennt die Herleitungs-Menge der Lib nicht');
  assert.match(src, /r\.neededBasis/, 'die Kritikalitaets-Zelle liest die Herleitung nicht');
  assert.match(src, /vt\.cq\.neededBasis\./, 'die Herleitung hat keine Beschriftung');
  assert.match(src, /own \+ neededNote \+ evt/, 'die Herleitung haengt nicht an der Zeile');
  const i18n = read('i18n-validator.mjs');
  assert.equal((i18n.match(/vt\.cq\.neededBasis\./g) || []).length, 8,
    'die Herleitung muss in beiden Sprachen fuer alle vier Zustaende da sein');
});
/* Warm-Lauf und Ziel-Nachrechnung (2026-10-17): die Kritikalitaets-Zelle muss beide Belege
 * zeigen - die Erfassungs-Basis des Warm-Laufs und die aus der dUNL-Groesse nachrechenbare
 * Zielzahl. Beides sind Zahlen, die ein Betreiber selbst pruefen kann. */
test("Kritikalitaets-Zelle: Warm-Lauf-Basis und nachrechenbares Ziel sind lesbar", () => {
  assert.match(src, /CAPTURE_BASES = new Set\(\["ledger-index", "stream-gap", "stream-open"\]\)/,
    "das Overlay kennt die Warm-Lauf-Basis nicht");
  assert.match(src, /r\.capture\.neededMatches/, "die Oberflaeche liest die Ziel-Nachrechnung nicht");
  assert.match(src, /vt\.cq\.neededCheck/, "die Nachrechnung hat keine Beschriftung");
  assert.match(src, /own \+ neededNote \+ evt \+ neededCheck/, "die Nachrechnung haengt nicht an der Zeile");
  const i18n = read("i18n-validator.mjs");
  assert.equal(i18n.split("'vt.cq.neededCheck'").length - 1, 2, "vt.cq.neededCheck fehlt in einer Sprache");
  assert.equal(i18n.split("'vt.cq.basis.stream-open'").length - 1, 2, "vt.cq.basis.stream-open fehlt in einer Sprache");
});
/* Zuordnungs-Beleg (2026-10-17): ein fehlender Vote auf einem geschlossenen Ledger ist nur
 * dann ein Knoten-Befund, wenn die eigene dUNL-Abdeckung am eigenen Niveau lag. Die Zeile
 * muss diesen Beleg zeigen, sonst steht dort ein Knoten-Vorwurf ohne Zahl. */
test("Kritikalitaets-Zelle: ein Knoten-Befund zeigt seinen Vollstaendigkeitsbeleg", () => {
  assert.match(src, /r\.capture\.attributableAbsence/, "die Oberflaeche liest die Zuordnungsgrenze nicht");
  assert.match(src, /vt\.cq\.attribution\.missed/, "der Beleg hat keine Beschriftung");
  assert.match(src, /own \+ neededNote \+ evt \+ neededCheck \+ attrib/, "der Beleg haengt nicht an der Zeile");
  const i18n = read("i18n-validator.mjs");
  assert.equal(i18n.split("'vt.cq.attribution.missed'").length - 1, 2, "vt.cq.attribution.missed fehlt in einer Sprache");
});

/* Peer-Rate ohne Beleg (Akkuratz 2026-10-17): die Peer-Ebene zaehlt 'missed' aus Tages-
 * und Stunden-Zaehlern, und die haben keine ledger-genaue Zuordnung. Die Zahl bleibt
 * sichtbar, aber sie darf nicht mehr als Knotenausfall ausgesprochen werden. */
test('Peer-Block nennt die Beleg-Deckung seiner Abwesenheits-Zahlen', () => {
  assert.match(src, /peerBlock\(d\.peer, d\.absence\)/, 'der Peer-Block bekommt die Zuordnungs-Bilanz nicht');
  assert.match(src, /vt\.peer\.attribution/, 'die Beleg-Deckung wird nicht gezeigt');
  const i18n = read('i18n-validator.mjs');
  assert.equal((i18n.match(/'vt\.peer\.attribution'/g) || []).length, 2, 'die Beleg-Deckung fehlt in einer Sprache');
  assert.doesNotMatch(i18n, /'vt\.peer\.summary': '[^']*node failures/, 'die englische Peer-Zeile spricht weiterhin von Knotenausfaellen');
  assert.doesNotMatch(i18n, /'vt\.peer\.summary': '[^']*Knotenausf/, 'die deutsche Peer-Zeile spricht weiterhin von Knotenausfaellen');
});
/* Grundebene (Design-Korrektur 2026-10-17): die Scherflaeche der Bodenplatte gab es je
 * Saule und nur unter nicht-leeren Intervallen. Im 24-h-Fenster (6 Saulen, 18 leere
 * Intervalle, Zelle 30,86 px, --dc 6,78 px) standen 6 Sockel mit 6,78 px Deckflaeche neben
 * 18 Sockeln ohne Deckflaeche: der Sockel wechselte seine Form von Intervall zu Intervall,
 * und das wird als Kippung der ganzen Grafik gelesen - derselbe schraege Eindruck, den die
 * Komma-Fuege und die je-Saeulen-Tiefe vorher schon erzeugt hatten. Die Korrektur ist
 * geometrisch, nicht dekorativ: eine Ebene ueber die ganze Plot-Breite mit derselben Tiefe
 * --dc und derselben Deckflaechen-Hoehe --dzc wie jedes Prisma, damit alle Kappen auf
 * derselben Flaechen stehen und nicht auf 24 unterschiedlich geformten Sockeln. */
test('Grundebene: ein Koerper unter allen 24 Intervallen, keine je-Saeulen-Scherplatte', () => {
  const css = stripComments(styleCss);
  const floor = ruleBody('.vt-floor');
  const top = ruleBody('.vt-floor-top');
  assert.match(floor, /left:\s*0;\s*right:\s*var\(--dc\)/, '.vt-floor kuerzt nicht um --dc - die Ebene ist breiter als ihre Prismen');
  assert.match(floor, /height:\s*var\(--base-h\)/, '.vt-floor Hoehe != --base-h');
  assert.match(top, /bottom:\s*var\(--base-h\)/, '.vt-floor-top sitzt nicht auf der Vorderkante der Ebene');
  assert.match(top, /height:\s*var\(--dzc\)/, '.vt-floor-top Hoehe != --dzc - die Ebene hat nicht dieselbe Tiefe wie die Prismen');
  assert.match(top, /transform:\s*skewX\(calc\(var\(--skew\) - 90deg\)\)/, '.vt-floor-top schert nicht aus --skew - Ebene und Kappen haetten verschiedene Projektionen');
  assert.doesNotMatch(css, /\.vt-base::after/, 'die je-Saeulen-Scherplatte ist zurueck - 24 Sockel mit unterschiedlicher Form');
  assert.doesNotMatch(css, /\.vt-nonzero[^{}]*::after/, 'eine Scherflaeche haengt wieder an der Zahl der Vorfaelle statt an der Ebene');
  const prof = ruleBody('.vt-profile');
  assert.match(prof, /--dc:\s*var\(--d\)/, '--dc ist nicht auf Profilebene definiert - die Ebene kennt ihre Tiefe nicht');
  assert.match(prof, /--dzc:\s*calc\(var\(--d\) \* var\(--dz-k\)\)/, '--dzc der Ebene ist nicht aus --skew abgeleitet');
  assert.match(src, /<span class=\"vt-floor\" aria-hidden=\"true\"><\/span><span class=\"vt-floor-top\" aria-hidden=\"true\"><\/span><div class=\"vt-grid\"/,
    'die Ebene wird nicht vor dem Gitter gerendert - sie laege vor den Saulen');
  assert.match(css, /@container\s*\(max-width:\s*\d+px\)\s*\{[^@]{0,260}?\.vt-floor-top\s*\{\s*display:\s*none/,
    'Mobil: die Deckflaeche der Ebene bleibt stehen, obwohl die Scherflaechen fallen');
});

/* Beleuchtungs-Hierarchie der Prismen (Design-Korrektur 2026-10-17, live im Overlay gemessen):
 * die Kappe hatte background-image: none. Ein color-mix-Anteil von 130 % liegt ausserhalb des
 * gueltigen Bereichs (0..100 %), die ganze background-image-Deklaration war damit ungueltig,
 * und die Kappe zeigte genau die Farbe der Vorderflaeche. Ohne Tonstufen zwischen Vorder-,
 * Tief- und Deckflaeche ist ein Prisma ein flacher Balken mit schraeger Oberkante - derselbe
 * schraege Eindruck, den vorher die Komma-Fuege und die je-Saeulen-Tiefe erzeugt hatten. Guard:
 * jeder color-mix-Anteil der Datei gueltig, und die Tonstufen an jeder Signaturfarbe beider
 * Themes nachgerechnet - nicht als Geschmack, sondern als Kontrastschritt. */
const colorMixCalls = (css) => {
  const out = [];
  const needle = "color-mix(";
  let i = 0;
  while ((i = css.indexOf(needle, i)) !== -1) {
    let depth = 1;
    let j = i + needle.length;
    while (j < css.length && depth > 0) {
      if (css[j] === "(") depth += 1;
      else if (css[j] === ")") depth -= 1;
      j += 1;
    }
    out.push(css.slice(i, j));
    i = j;
  }
  return out;
};
const hexRgb = (hex) => [1, 3, 5].map((k) => parseInt(hex.slice(k, k + 2), 16));
const mixToward = (base, pct, partner) => base.map((c, k) => c * (pct / 100) + partner[k] * (1 - pct / 100));
const overAlpha = (base, rgb, alpha) => base.map((c, k) => c * (1 - alpha) + rgb[k] * alpha);
const meanDelta = (base, tone) => tone.reduce((sum, c, k) => sum + (c - base[k]), 0) / base.length;
const THEMES = ["[data-a6]", "[data-a6][data-theme=\"noir\"]"];

test('color-mix: jeder Anteil liegt in 0..100 Prozent (130 % machte die Kappe leer)', () => {
  const calls = colorMixCalls(stripComments(styleCss));
  assert.ok(calls.length > 20, 'nur ' + calls.length + ' color-mix-Klammern - der Helper greift nicht');
  for (const call of calls) {
    for (const m of call.matchAll(/(\d+(?:\.\d+)?)\s*%/g)) {
      const pct = Number(m[1]);
      assert.ok(pct >= 0 && pct <= 100, 'Anteil ' + pct + ' % ausserhalb 0..100 % in: ' + call);
    }
  }
});

test('Kappe: zwei aus der Grundfarbe abgeleitete Tonstufen und eine eigene Naht', () => {
  const cap = ruleBody('.vt-top');
  const mix = [...cap.matchAll(/color-mix\(in srgb,\s*var\(--vt-cap-face\)\s+(\d+(?:\.\d+)?)%,\s*white\)/g)]
    .map((m) => Number(m[1]));
  assert.equal(mix.length, 2, 'die Kappe hat nicht zwei abgeleitete Tonstufen');
  assert.ok(mix[0] < mix[1], 'die Kappe wird nach hinten heller statt dunkler - die Tiefe wird nicht rueckwaerts schattiert');
  assert.match(cap, /background-color:\s*var\(--vt-cap-face\)/, 'die Kappe haelt einen Aufloesungs-Fallback statt der aufgelsten Grundfarbe');
  assert.match(cap, /inset 0 -1px 0 var\(--vt-seam\)/, 'die Naht zwischen Kappe und Koerper fehlt');
  assert.match(ruleBody('.vt-profile'), /--vt-seam:\s*var\(--a6-face-seam\)/, '--vt-seam ist kein Theme-Token');
  assert.match(ruleBody('.vt-col'), /--vt-cap-face:\s*var\(--vt-cap,\s*var\(--a6-sev-neutral\)\)/, '--vt-cap-face loest die Kappenfarbe nicht einmal auf');
  for (const sel of THEMES) {
    assert.match(ruleBody(sel), /--a6-face-seam:\s*rgba\(\s*\d+,\s*\d+,\s*\d+,\s*0?\.\d+\s*\)/, sel + ' hat keine eigene Naht-Stufe');
  }
});

test('Tiefflaeche: schattiert entlang der Tiefe ab und traegt eine eigene Kantenstufe', () => {
  const side = ruleBody('.vt-side');
  assert.match(side, /background-image:\s*linear-gradient\(\s*to right,/, 'die Tiefflaeche schattiert nicht entlang der Tiefe');
  assert.match(side, /,\s*var\(--vt-shade\)\),\s*var\(--vt-grad\)/, 'unter der Schattierung fehlt der Typstapel der Vorderflaeche');
  const front = Number(side.match(/var\(--vt-shade\)\s+(\d+(?:\.\d+)?)%/)[1]);
  assert.ok(front < 100, 'die Schattierung startet an der Vorderkante bei 100 % - es gibt kein Tiefengefaelle');
  assert.match(side, /box-shadow:\s*inset 0 0 0 1px var\(--vt-edge-side\)/, 'die Tiefflaeche traegt weiterhin die helle Vorderkantenlinie');
  const edge = ruleBody('.vt-profile').match(/--vt-edge-side:\s*color-mix\(in srgb,\s*var\(--a6-face-edge\)\s+(\d+(?:\.\d+)?)%,\s*transparent\)/);
  assert.ok(edge, '--vt-edge-side ist keine abgeleitete Stufe aus --a6-face-edge');
  assert.ok(Number(edge[1]) < 100, '--vt-edge-side ist so hell wie die Vorderkante');
});

test('Tonstufen: an jeder Signaturfarbe beider Themes nachgerechnet, nicht gefuehlt', () => {
  const capMix = [...ruleBody('.vt-top').matchAll(/var\(--vt-cap-face\)\s+(\d+(?:\.\d+)?)%,\s*white/g)].map((m) => Number(m[1]));
  const sideStart = Number(ruleBody('.vt-side').match(/var\(--vt-shade\)\s+(\d+(?:\.\d+)?)%/)[1]);
  const WHITE = [255, 255, 255];
  let checked = 0;
  for (const sel of THEMES) {
    const body = ruleBody(sel);
    const shade = body.match(/--a6-face-shade:\s*rgba\(\s*(\d+),\s*(\d+),\s*(\d+),\s*([\d.]+)\s*\)/);
    assert.ok(shade, sel + ': --a6-face-shade fehlt');
    const shadeRgb = [Number(shade[1]), Number(shade[2]), Number(shade[3])];
    const shadeAlpha = Number(shade[4]);
    for (const m of body.matchAll(/--a6-sev-(malicious|suspect|info|neutral):\s*(#[0-9a-f]{6})/g)) {
      const base = hexRgb(m[2]);
      const capFront = meanDelta(base, mixToward(base, capMix[0], WHITE));
      const capBack = meanDelta(base, mixToward(base, capMix[1], WHITE));
      const sideFront = meanDelta(base, overAlpha(base, shadeRgb, shadeAlpha * (sideStart / 100)));
      const sideBack = meanDelta(base, overAlpha(base, shadeRgb, shadeAlpha));
      const at = sel + ' ' + m[1] + ' ' + m[2];
      assert.ok(capFront >= 12, at + ': Kappe nur ' + capFront.toFixed(1) + ' im Mittel heller als die Vorderflaeche');
      assert.ok(capBack >= 6, at + ': Kappe an der hinteren Kante nur ' + capBack.toFixed(1) + ' heller');
      assert.ok(capBack < capFront, at + ': die Kappe faellt nach hinten nicht ab');
      assert.ok(sideFront <= -14, at + ': Tiefflaeche nur ' + sideFront.toFixed(1) + ' im Mittel dunkler');
      assert.ok(sideBack <= -20, at + ': Tiefflaeche an der Hinterkante nur ' + sideBack.toFixed(1) + ' dunkler');
      assert.ok(sideBack < sideFront, at + ': die Tiefe wird nach hinten nicht dunkler');
      checked += 1;
    }
  }
  assert.equal(checked, 8, 'nur ' + checked + ' Signaturfarben geprueft - beide Themes brauchen vier');
});

/* Die Last-Dosis-Achse der Kopplungsebene wird gerechnet (lib/validator-stress-coupling.mjs:
 * loadAxis + loadTrend) und war zunachst nirgends sichtbar: couplingBlock renderte verdict,
 * coverage, axes, findings, peaks, signatures, local, gaps - nur die Achse selbst fehlte.
 * Ein gerechneter Wert, den niemand sieht, ist eine Zahl im JSON, keine Auskunft.
 * Guard: die Kurve haengt an der Achse, ihr Urteil an den zwei Haelften, jedes der funf Urteile
 * hat ein Label, und der Namensraum ist vt.dose.* - vt.load.* fuehrt schon die Last-Kurve der
 * Diagnose-Ebene, und zwei Ebenen duerfen sich kein Label ueberschreiben. */
test('Dosis-Kurve: die gerechnete Lastachse wird gerendert, nicht nur mitgeliefert', () => {
  assert.match(src, /const loadBlock = \(\(\) => \{/, 'die Kurve hat kein eigenes Render-Stueck');
  assert.match(src, /const la = c\.loadAxis;/, 'die Kurve liest nicht die Achse der Lib');
  assert.match(src, /const tr = la\.trend \|\| \{\};/, 'das gerechnete Urteil der Lib wird nicht gelesen');
  assert.match(src, /return verdictLine \+ covLine \+ axisLine \+ loadBlock \+ findingsBlock/,
    'die Kurve haengt nicht in der Ausgabekette der Kopplungs-Ebene');
  // Sieben Spalten: Band, Nenner, Zaehler, Rate, dieser Knoten, seine Rate, Nenner-Art. Ohne die
  // letzte Spalte ist eine duenne Rate von einer vollen nicht zu unterscheiden.
  assert.match(src, /\["vt\.dose\.hBand", "vt\.dose\.hLedgers", "vt\.dose\.hFails", "vt\.dose\.hRate",\s*"vt\.dose\.hOwn", "vt\.dose\.hOwnRate", "vt\.dose\.hSample"\]/,
    'die Achse hat nicht ihre sieben Spalten - Nenner oder Nenner-Art fehlen');
  assert.match(src, /h\.t\("vt\.dose\.sample\." \+ \(r\.sample === "measured" \? "measured" : "thin"\)\)/,
    'die Nenner-Art je Band wird nicht uebersetzt');
  assert.match(src, /h\.t\("vt\.dose\.verdict\." \+ verdict\)/, 'Urteil ohne Label');
  // Ein Urteil, das dieser UI unbekannt ist, wird nicht still als "flach" gezeigt: offen bleibt offen.
  assert.match(src, /LOAD_TREND_VERDICTS\.has\(tr\.verdict\) \? tr\.verdict : "insufficient-sample"/,
    'ein unbekanntes Dosis-Urteil faellt nicht auf offen zurueck');
  assert.match(src, /vt-badge vt-load-/, 'das Dosis-Urteil hat keine Badge-Klasse');
  assert.match(src, /h\.t\(tr\.monotone === true \? "vt\.dose\.monotone\.yes" : "vt\.dose\.monotone\.no"/,
    'die fallenden Schritte werden nicht gezeigt - eine Achse gilt sonst als streng monoton');
  assert.match(src, /vt\.dose\.authority/, 'die Autoritaet der Achse fehlt - ohne sie wird Korrelation als Ursache gelesen');
  const from = src.indexOf('const loadBlock');
  const to = src.indexOf('return verdictLine + covLine + axisLine + loadBlock');
  assert.ok(from > 0 && to > from, 'die Render-Stueck und ihre Ausgabekette stehen nicht in der Reihenfolge');
  assert.doesNotMatch(src.slice(from, to), /vt\.load\./,
    'die Kurve greift in den Namensraum der Diagnose-Ebene - ein Label wird ueberschrieben');
  // UI-Menge und Lib-Menge sind dieselbe Menge: driftet eine, ist die andere unverprobt.
  const uiSet = src.match(/const LOAD_TREND_VERDICTS = new Set\(\[([^\]]+)\]\)/);
  assert.ok(uiSet, 'die UI deklariert ihre Dosis-Urteile nicht');
  assert.deepEqual(uiSet[1].match(/"([^"]+)"/g).map((q) => q.slice(1, -1)).sort(),
    [...LOAD_TREND_VERDICTS].sort(), 'UI und Lib haben verschiedene Dosis-Urteile');
  // CSS: jedes Urteil der Lib hat eine Badge-Farbe, auch das offene.
  const cssDose = stripComments(styleCss);
  for (const v of LOAD_TREND_VERDICTS) {
    // Ein Selector darf zwei Urteile teilen - dann steht hinter dem ersten ein Komma, nicht
    // die Klammer. Beide Formen muessen gelten, sonst fehlt ein Badge, obwohl einer da ist.
    assert.ok(new RegExp('\\.vt-badge\\.vt-load-' + v + '(,|\\s*\\{)').test(cssDose), 'kein Badge fuer Dosis-Urteil ' + v);
  }
});

/* Erfassungs-Ereignis ohne Ledger-Koordinate (Genauigkeit 2026-10-17): die Produktion zeigte
 * "stream rebuilt at ledger -, 5 s from this ledger". Ein Ereignis ohne Ledger-Koordinate hat
 * keine Koordinate - die Zelle darf sie nicht durch einen Strich in der Ledger-Position ersetzen,
 * weil genau dort der Leser eine Ledgerzahl erwartet. Guard: die Koordinate ist ein eigenes
 * Textstueck, und ohne Koordinate steht kein Ledger-Platzhalter in der Zeile. */
test('Erfassungs-Ereignis: eine fehlende Ledger-Koordinate wird nicht als Strich gezeichnet', () => {
  assert.match(src, /at: Number\.isFinite\(r\.captureEvent\.ledger\)/, 'die Zelle prueft die Koordinate nicht');
  assert.match(src, /h\.t\("vt\.cq\.event\.at"/, 'die Koordinate hat kein eigenes Textstueck');
  assert.match(src, /h\.t\("vt\.cq\.event\.atUnknown"\)/, 'die koordinatenlose Variante fehlt');
  // Die Koordinate darf nur im geprüften Zweig gelesen werden: im anderen Zweich steht die
  // koordinatenlose Beschriftung, nicht ein Strich an der Stelle, wo der Leser eine Zahl erwartet.
  assert.match(src, /at: Number\.isFinite\(r\.captureEvent\.ledger\)\s*\?\s*h\.t\("vt\.cq\.event\.at",\s*\{\s*l: num\(r\.captureEvent\.ledger\)\s*\}\s*\)\s*:\s*h\.t\("vt\.cq\.event\.atUnknown"\)/,
    'die Koordinate wird nicht abgesichert gelesen - ohne Wert wird daraus ein Strich');
  const i18n = read('i18n-validator.mjs');
  assert.equal(i18n.split("'vt.cq.event.at'").length - 1, 2, 'vt.cq.event.at fehlt in einer Sprache');
  assert.equal(i18n.split("'vt.cq.event.atUnknown'").length - 1, 2, 'vt.cq.event.atUnknown fehlt in einer Sprache');
  // Die Ereignis-Texte selbst nennen keine Ledgerzahl mehr: sonst staende die Koordinate
  // zweimal in der Zeile, einmal belegt und einmal als Strich.
  for (const kind of ['open', 'close', 'stall', 'near']) {
    assert.equal((i18n.match(new RegExp("'vt\\.cq\\.event\\." + kind + "': '[^']*\\{at\\}[^']*'", 'g')) || []).length, 2,
      'vt.cq.event.' + kind + ' nutzt {at} nicht in beiden Sprachen');
    assert.equal((i18n.match(new RegExp("'vt\\.cq\\.event\\." + kind + "': '[^']*\\{l\\}[^']*'", 'g')) || []).length, 0,
      'vt.cq.event.' + kind + ' nennt weiterhin eine Ledgerzahl');
  }
});

/* Warm-Lauf-Lesart (Genauigkeit 2026-10-17): die Zelle zeigte "own reception 38 of 0 validations".
 * Gelesen wird das als Anteil mit Nenner Null - eine Bruchaussage, die die Lib nie trifft. Gemeint
 * sind zwei Zahlen: der eigene Empfang auf diesem Ledger und der eigene Median der Erfassung. */
test('Warm-Lauf-Zelle: eigener Empfang und eigener Median stehen als zwei Zahlen da', () => {
  const i18n = read('i18n-validator.mjs');
  assert.equal(i18n.split("'vt.cq.ownBaseline'").length - 1, 2, 'vt.cq.ownBaseline fehlt in einer Sprache');
  assert.doesNotMatch(i18n, /'vt\.cq\.ownBaseline': '[^']*\{seen\} of \{base\}/,
    'die englische Zeile liest sich weiterhin als Anteil');
  assert.doesNotMatch(i18n, /'vt\.cq\.ownBaseline': '[^']*\{seen\} von \{base\}/,
    'die deutsche Zeile liest sich weiterhin als Anteil');
  assert.match(i18n, /'vt\.cq\.ownBaseline': '[^']*\{seen\}[^']*\{base\}[^']*'/,
    'die Zelle nennt beide Zahlen nicht');
});

/* Netz-Stall-Etikett in der Kritikalitaets-Tafel (2026-10-17, durch die Historie belegt).
 * cd3762a (2026-10-16 15:08) brachte die Wirkungs-Spalte mit 'quorum-critical' und die
 * Abweichungs-Spalte mit 'no vote (network stall)'. 2883ef9 (2026-10-16 18:30) nahm beide
 * heraus: xrpscan und xrplcluster.com weisen genau diese Ledger (107690236, 107694001,
 * 107695059) als geschlossen aus - eine Netzstockung waere dort eine Behauptung gegen zwei
 * Autoritaeten. Guard: die beiden Spalten haengen an deklarierten Mengen, kein Etikett dieser
 * Spalten darf eine Netzstockung oder ein Quorum-Urteil behaupten, und das tote Etikett
 * 'vt.cq.critical' (von keiner Zeile mehr benutzt) ist aus beiden Sprachen heraus. */
test('Kritikalitaets-Tafel: ein geschlossener Ledger wird nicht zur Netzstockung', () => {
  assert.match(src, /h\.t\("vt\.type\." \+ \(DIAG_TYPE\[r\.type\] \|\| r\.type\)\)/,
    'die Abweichungs-Spalte haengt nicht an den Typ-Etiketten');
  assert.match(src, /h\.t\("vt\.cq\.verdict\." \+ r\.verdict\)/, 'die Wirkungs-Spalte haengt nicht an den Verdikt-Etiketten');
  assert.match(src, /\+ closureCell\(r\) \+/, 'die Schliess-Spalte fehlt in der Zeile');
  const i18n = read('i18n-validator.mjs');
  const labels = [...i18n.matchAll(/'(vt\.type\.[a-z-]+|vt\.cq\.verdict\.[a-z-]+)': '([^']*)'/g)];
  assert.ok(labels.length >= 14, 'die Etiketten der beiden Spalten sind nicht vollstaendig auffindbar');
  for (const [key, text] of labels) {
    assert.ok(!/stall|stockung/i.test(text), key + ' behauptet eine Netzstockung in der Tafel: ' + text);
    assert.ok(!/quorum-critical|quorum-kritisch/i.test(text), key + ' behauptet ein Quorum-Urteil in der Tafel: ' + text);
  }
  assert.equal(i18n.split("'vt.cq.critical'").length - 1, 0, 'das alte Wirkungs-Etikett ist nicht mehr im Woerterbuch');
});

/* Messluecken der Kopplungsebene (2026-10-17).
 * Jede Luecke, die lib/validator-stress-coupling.mjs deklarativ in COUPLING_GAPS aufnimmt,
 * muss in beiden Sprachen ein Etikett haben: das Overlay rendert sie ueber 'vt.coupling.gap.' + id.
 * Eine Luecke ohne Etikett waere eine Zahl ohne Aussage - und eine Achse, die duenn ist, ohne
 * dass sie es benennt, ist genau die Schaetzung, die die Engine nicht produzieren darf. */
test('Kopplungs-Luecken: jede deklarierte Luecke hat ein Etikett in beiden Sprachen', () => {
  assert.ok(COUPLING_GAPS.has('population-counters-partial'), 'die Duennheit der Bevoelkerungs-Achse ist nicht deklariert');
  const i18n = read('i18n-validator.mjs');
  for (const g of COUPLING_GAPS) {
    const key = "'vt.coupling.gap." + g + "'";
    assert.equal(i18n.split(key).length - 1, 2, 'Etikett nicht in beiden Sprachen: ' + g);
  }
});
test('Quorum-Ziel: die Herkunft eines am Tag gemessenen Ziels ist in der Zeile lesbar', () => {
  assert.match(src, /nb === "day-measured"/, 'die Provenienz haengt nur an einem am Tag gemessenen Ziel');
  assert.match(src, /vt\.cq\.neededProvenance/, 'Endpunkt, Samplezahl und Zeitpunkt haben keine Beschriftung');
  assert.match(src, /networkQuorumSource/, 'die Zeile liest den benannten Endpunkt nicht');
  assert.match(src, /networkQuorumSamples/, 'die Zeile liest die Samplezahl nicht');
  const i18n = read('i18n-validator.mjs');
  for (const key of ['vt.cq.neededProvenance', 'vt.cq.neededSamples', 'vt.cq.neededProvenanceAt']) {
    const quoted = String.fromCharCode(39) + key + String.fromCharCode(39);
    assert.equal(i18n.split(quoted).length - 1, 2, 'Etikett nicht in beiden Sprachen: ' + key);
  }
});
/* Der Rekorder-Loecher zwischen Tagesdateien (gemessen 2026-10-16 22:20:52Z -> 2026-10-17
 * 01:49:22Z auf dem Daten-Repo). Die Spanne steht in keiner Datei, die existiert. Wird sie
 * nicht benannt, wirkt ein Rekorder-Stop wie nichts passiert - und das ist eine Schaetzung
 * ueber ein Urteil, das die Engine nicht produzieren darf. */
test("Rekorder-Loecher: die unbeobachtete Spanne zwischen Tagesdateien ist lesbar", () => {
  assert.match(src, /const holeNote = Number\(c\.unobservedRanges\) > 0/, "die Spanne wird nicht aus der Zahl gebaut");
  assert.match(src, /coverageLine \+ quorumNote \+ holeNote \+ scopeTag/, "die Zeile haengt nicht an der Aufzeichnungs-Zeile");
  assert.match(src, /unobservedLargest/, "die groesste Spanne hat keinen Lesestoff");
  const i18n = read("i18n-validator.mjs");
  for (const key of ["vt.coverageHoleLabel", "vt.coverageHole"]) {
    const quoted = String.fromCharCode(39) + key + String.fromCharCode(39);
    assert.equal(i18n.split(quoted).length - 1, 2, "Etikett nicht in beiden Sprachen: " + key);
  }
});


/* Eine geklemmte Achse ohne Auskunft ist eine Aussparung, die der Leser nicht sieht. Die
 * Klemmung muss als Zahl am Profil stehen - Fensterbeginn und Achsenbeginn nebeneinander. */
test("Profilachse: die Klemmung auf die Aufnahme ist ausgewiesen, nicht stillschweigend", () => {
  assert.match(src, /profile\.clamped === true && Number\.isFinite\(profile\.windowFrom\)/,
    "die Klemmung wird nicht an die gelieferte Fensterzahl der API gebunden");
  assert.match(src, /vt\.profileWindowClamped/, "die Klemmung hat keine Beschriftung");
  assert.match(src, /window: spanLabel\(profile\.windowFrom\), axis: spanLabel\(from\)/,
    "Fensterbeginn und Achsenbeginn stehen nicht beide als Zeit da");
  assert.match(src, /vt-clamp-note/, "die Klemmung wird nicht unter dem Profil gerendert");
});

/* --- Achsen-Untergrenze -----------------------------------------------------
 * Gemessen 2026-10-17 live im ausgelieferten Overlay eines 24-h-Fensters mit einem Vorfall je
 * Intervall: peak 1, Gitterlinien nur "0" und "1", jede Saeule exakt auf Plot-Hoehe. Die Achse
 * hatte genau ein Intervall - auf dieser Skala ist nichts zu vergleichen, und das Profil war ein
 * Kamm identischer Monolithen. AXIS_MIN_PEAK gibt der Skala vier Intervalle, ohne eine Zahl zu
 * erfinden: die wahren Zahlen stehen weiterhin in Gitterlinie, Wertemarke, Readout und aria-label.
 */
test('Achse: kleine Maxima bekommen eine Skala, die vergleichen kann', () => {
  assert.equal(AXIS_MIN_PEAK, 4, 'AXIS_MIN_PEAK ist ' + AXIS_MIN_PEAK);
  for (const max of [0, 1, 2, 3]) {
    const { peak, step, ticks } = axisScale(max);
    assert.ok(peak >= AXIS_MIN_PEAK, 'max ' + max + ': peak ' + peak + ' unter der Untergrenze');
    assert.ok(peak >= max, 'max ' + max + ': peak ' + peak + ' unter dem groessten Intervall');
    assert.equal(ticks[0], 0, 'max ' + max + ': keine Null-Linie');
    assert.equal(ticks[ticks.length - 1], peak, 'max ' + max + ': die Spitze fehlt');
    assert.ok(ticks.length - 1 >= 4, 'max ' + max + ': nur ' + (ticks.length - 1)
      + ' Gitterintervalle - die Skala kann nichts vergleichen');
    assert.ok(ticks.length - 1 <= 5, 'max ' + max + ': ' + (ticks.length - 1) + ' Intervalle ueber der Grenze');
    assert.equal(peak % step, 0, 'peak ' + peak + ' ist kein Vielfaches von step ' + step);
    const top = axisUnit(Math.max(1, max), peak);
    assert.ok(top < peak, 'max ' + max + ': hoechstes Intervall ' + top.toFixed(4) + ' von '
      + peak + ' - die Saeule fuellt die Achse');
    for (const plotH of PLOT_HS) {
      const body = bodyAt(Math.max(1, max), peak, plotH);
      assert.ok(body < plotH, 'max ' + max + ' bei Plot ' + plotH + ' px: Saeule '
        + body.toFixed(2) + ' px auf voller Hoehe');
      assert.ok(capAt(peak, plotH) <= body * CAP_RATIO + 1e-9, 'max ' + max + ' bei Plot '
        + plotH + ' px: Kappe ueber einem Drittel des Korpers');
    }
  }
  /* Ab einem groessten Intervall von 5 ist peak wieder genau die naechste Achsenspitze der
     Daten: die Untergrenze darf eine volle Achse nicht strecken. */
  for (const max of [5, 6, 11, 15, 25, 129, 1250, 4502, 40000]) {
    const { peak, step } = axisScale(max);
    assert.ok(peak >= max && peak < max + step, 'max ' + max + ': peak ' + peak + ' / step '
      + step + ' ist nicht die naechste Spitze der Daten');
  }
});

test('Betroffenheits-Zeile: gleiche und andere Abweichung werden getrennt benannt', () => {
  assert.match(src, /const affectedRow = \(r\) => \{/, 'die Betroffenheits-Zeile fehlt');
  assert.match(src, /const allM = \[\], allT = \[\], allN = \[\]/,
    'die benannten Knoten werden nicht in indexgleichen Spuren gefuehrt');
  assert.match(src, /if \(types\[i\] === r\.type\)/, 'die Teilung nach demselben Vorfallstyp fehlt');
  assert.match(src, /group\("vt\.peersLineSame", sameM, sameT, sameN\)/,
    'Knoten mit demselben Vorfall werden nicht beim Namen genannt');
  assert.match(src, /group\("vt\.peersLineOther", restM, restT, restN\)/,
    'Knoten mit anderem Vorfall werden nicht beim Namen genannt');
  assert.match(src, /peerChips\(masters, truths, names\)/,
    'Name und Gegenurteil verlassen die indexgleiche Spur zum Master-Key');
  assert.match(src, /: peerChips\(allM, allT, allN\);/,
    'ohne Typ je Knoten wird eine Gruppierung erfunden, die die Daten nicht hergeben');
});

/* Signer-Beleg (2026-10-17): die Betroffenheits-Zeile nannte nur die scheinbar Fehlenden. Die
 * Gegenseite - wer auf demselben Ledger abgestimmt hat - ist die Entlastungsseite derselben
 * Beobachtung und muss an derselben Zeile stehen. Ohne Beleg darf keine leere Liste stehen:
 * eine leere Liste ist die Aussage 'niemand hat abgestimmt', und die ist nie gemessen. */
test('Betroffenheits-Zeile: die Abgestimmten stehen daneben, sonst die Herkunft der Luecke', () => {
  assert.match(src, /const voters = Array\.isArray\(r\.voters\) \? r\.voters : null;/,
    'der Signer-Beleg wird nicht in vorhanden und fehlend getrennt');
  assert.match(src, /peerChips\(voters, \[\], Array\.isArray\(r\.voterNames\) \? r\.voterNames : \[\]\)/,
    'die Abgestimmten werden nicht aus derselben Auskunft benannt');
  assert.match(src, /body \+ voterPart/,
    'die Abgestimmten stehen nicht in derselben Zeile wie die Fehlenden');
  assert.match(src, /h\.t\("vt\.cq\.voters\." \+/,
    'ohne Beleg steht eine leere Liste statt der Herkunft der Luecke');
});
/* --- Kappenfarbe = groesster Stapel ----------------------------------------
 * Die Kappe traegt die Signaturfarbe eines Vorfallstyps. Bis 2026-10-17 war das der in
 * PROFILE_TYPES zuletzt gestapelte Typ, nicht der groessten: eine Saeule aus 20 missed und
 * 1 noQuorum zeigte die noQuorum-Farbe, die Readout-Zahlen sagten das Gegenteil. In den
 * ausgelieferten Fenstern (24 h / 7 d / 30 d) mischt keine Zelle Typen, der Fehler war also
 * latent - er ist einer, sobald zwei Typen in einem Intervall vorkommen. */
test('Kappenfarbe: die Kappe zeigt den groessten Stapel, nicht den zuletzt gestapelten', () => {
  assert.match(src, /let capCount = 0;/, 'der Stapelzaehler der Kappe fehlt');
  assert.match(src, /if \(cell\[k\] > capCount\) \{ capCount = cell\[k\]; cap = k; \}/,
    'die Kappenfarbe folgt nicht dem groessten Stapel');
  assert.doesNotMatch(src, /^\s*cap = k;$/m, 'der zuletzt gestapelte Typ bestimmt wieder die Kappe');
  assert.match(src, /--vt-cap:var\(--vt-" \+ cap/, 'die Kappenfarbe verlaesst die Typsignatur');
});

/* Nachgerechnete Entlastung (Akkuratz 2026-10-17): wo die Zeile kein eigenes Abdeckungs-Niveau
 * traegt, wird es aus derselben Tagesdatei gerechnet. Die Oberflaeche muss dann die Zahl UND ihre
 * Herkunfft zeigen - sonst steht in der Zeile eine Entlastung ohne Nachrechnen zu koennen. */
test("Kritikalitaets-Zelle: die nachgerechnete Entlastung steht mit ihren Zahlen da", () => {
  assert.match(src, /c2\.coverageBasis === "day-recomputed"/, "die Oberflaeche unterscheidet nicht zwischen aufgezeichnetem und gerechnetem Niveau");
  assert.match(src, /Number\.isFinite\(c2\.coverageLevel\)/, "das gerechnete Niveau wird nicht auf eine Zahl geprueft");
  assert.match(src, /Number\.isFinite\(c2\.coverageSamples\)/, "die Samplezahl der Nachrechnung wird nicht geprueft");
  assert.match(src, /vt\.cq\.attribution\.notAttributable/, "die Entlastung hat keine Beschriftung");
  assert.match(src, /attrib \+ notAttrib \+ bound/, "die Entlastung haengt nicht an der Zeile");
  const i18n = read("i18n-validator.mjs");
  assert.equal(i18n.split("'vt.cq.attribution.notAttributable'").length - 1, 2, "vt.cq.attribution.notAttributable fehlt in einer Sprache");
});

/* Beobachtungsliste (2026-10-17): "seit deinem letzten Besuch" ist ein Urteil ueber ein Fenster,
 * nicht ueber einen Tag. Die Lib kennt sieben Urteile; die UI muss dieselben sieben kennen und
 * jedem eine Form geben - sonst steht ein Lib-Urteil als roher Schluessel in der Zeile oder,
 * schlimmer, es verschwindet still als "nichts Neues". */
test("Beobachtungsliste: Lib-Urteil, UI-Menge, Endpunkt und Form haengen aneinander", () => {
  const lib = read("../lib/validator-watch.mjs");
  const server = read("../server/index.mjs");
  const i18n = read("i18n-validator.mjs");
  assert.ok(lib.includes("export function watchDelta"), "watchDelta fehlt in der Lib");
  assert.ok(lib.includes("export const WATCH_VERDICTS"), "WATCH_VERDICTS fehlt in der Lib");
  assert.ok(lib.includes("estimated: 0"), "die Lib fuehrt ihre Schaetzungs-Grenze nicht in der Zeile");
  // Laeuft die Typ-Vokabel auseinander, verschwindet ein Zaehler still aus der Zeile. Besonders
  // gefaehrlich: vote-not-observed (Ledger geschlossen) unter no-quorum (Schliessung unbelegt).
  const at = src.indexOf("const WATCH_TYPES = [");
  assert.ok(at >= 0, "die UI listet ihre Typ-Vokabeln nicht explizit");
  const uiTypes = src.slice(at + 21, src.indexOf("]", at)).split(",").map((s) => s.trim().replace(/^"|"$/g, ""));
  assert.deepEqual(uiTypes, WATCH_TYPES, "Lib und UI zahlen verschiedene Typen");
  for (const k of WATCH_TYPES) assert.equal(i18n.split("'vt.k." + k + "'").length - 1, 2, "vt.k." + k + " fehlt in einer Sprache");
  // Retrace braucht Namen: eine Kohorte aus Master-Anfaengen ist fuer einen Betreiber nicht
  // nachvollziehbar. Die UI muss die benannten Knoten nehmen und den Master nur als Rest zeigen.
  assert.ok(src.includes("othersNames"), "die UI benennt die Kohorten-Knoten nicht aus der Auskunft");
  assert.ok(src.includes("row.name"), "die UI zeigt den eigenen Knoten nicht mit seinem Namen");
  assert.ok(server.includes("groundPeers: await groundTruthMap()"), "der Endpunkt holt die Namen nicht aus der Netz-Auskunft");
  assert.ok(server.includes("/api/validator-watch"), "der Endpunkt fehlt");
  assert.ok(server.includes("watchDelta("), "der Endpunkt ruft die Lib nicht");
  assert.ok(server.includes("watchEntriesFromQuery"), "die Abfrage-Form liegt nicht im Endpunkt");
  const decl = src.match(/const WATCH_VERDICTS = new Set\(\[([^\]]*)\]\)/);
  assert.ok(decl, "die UI listet ihre Urteile nicht explizit");
  const ui = (decl[1].match(/"([^"]+)"/g) || []).map((x) => x.slice(1, -1));
  assert.deepEqual(ui.slice().sort(), [...WATCH_VERDICTS].sort(), "UI und Bibliothek urteilen nach verschiedenen Vokabeln");
  for (const v of ui) {
    assert.ok(cssRules.has(".vt-watch-" + v), "Urteil ohne Form: vt-watch-" + v);
    assert.equal(i18n.split("'vt.watch.verdict." + v + "'").length - 1, 2, "vt.watch.verdict." + v + " fehlt in einer Sprache");
  }
  // Die Marke liegt im Browser des Betreibers. Ohne sie gibt es kein "seit" - die UI muss das
  // sagen, statt einen Vergleich mit einer erfundenen Besuchszeit zu zeigen.
  assert.match(src, /const WATCH_KEY = "hx-watch"/, "die Besuchs-Marke fehlt");
  assert.match(src, /vt\.watch\.first/, "der erste Besuch hat keinen Text");
  assert.match(src, /vt\.watch\.error/, "ein Abruf-Fehler loescht die Marke oder verschwindet still");
  // Der Vergleich wird erst nach dem Rendern markiert: sonst vergliche ich den Besuch mit sich selbst.
  assert.match(src, /watchMarkup\(row, data\.windowCap\)\);[\s\S]{0,120}watchMarkVisit\(master\)/, "die Marke geht dem Vergleich voraus");
});
