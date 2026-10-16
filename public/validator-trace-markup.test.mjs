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
 *  4) --d <= --gap in jedem clamp-Zweig: die Deckfläche ragt exakt --dc über die
 *     Vorderfläche hinaus, der Überstand in die Nachbarspalte ist --dc - --gap.
 *  5) --dz ist aus --skew abgeleitet (--dz-k = tan 41°), nicht paarweise gesetzt.
 *  6) Tiefe je Säule (--dc = min(--d, --bh)): Deckfläche und Grundriss-Rückkante
 *     bleiben unter der Balken-Oberkante. Feste Tiefe machte aus 1 Vorfall (2,48 px
 *     Balken) ein 6,63 px hohes Schrägband - gemessen 2026-10-16 live.
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
  assert.match(src, /class="vt-col vt-state-' \+ state \+ \(cell\.total \? " vt-nonzero" : ""\) \+ '" tabindex="0" role="group" style="' \+ style/,
    'style mit --n/--i muss auf .vt-col stehen (und vt-nonzero nur bei Vorfaellen)');
  assert.doesNotMatch(src, /<div class="vt-bar" style="/, '.vt-bar darf den Style nicht mehr tragen');
  assert.match(ruleBody('.vt-mark'), /bottom:\s*calc\(var\(--bh\)\s*\+\s*var\(--dzc\)\s*\+\s*1px\)/,
    '.vt-mark sitzt nicht auf der Oberkante des Prismas (Tiefe DIESER Saeule)');
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
const { axisScale, axisUnit } = await import('./validator-trace.mjs');

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
  assert.equal(axisUnit(7, 50), 7);
  assert.equal(axisUnit(50, 50), 50);
});

test('Achse: die Schwelle ist die Kanten-Sichtbarkeit (peak 50 linear, peak 150 wurzel)', () => {
  const plotH = 176;
  const at50 = (axisUnit(1, 50) / 50) * plotH;
  const at150linear = (1 / 150) * plotH;
  const at150root = (axisUnit(1, 150) / 150) * plotH;
  assert.ok(at50 >= 3.5, 'peak 50 linear: 1 Vorfall = ' + at50 + ' px - unter der Kantensichtbarkeit');
  assert.ok(at150linear < 1.2, 'peak 150 linear waere ' + at150linear.toFixed(2) + ' px - die 2-px-Untergrenze griffe fuer so gut wie jede Saeule');
  assert.ok(at150root > 14 && at150root < 14.5, 'peak 150 wurzel: 1 Vorfall = ' + at150root.toFixed(2) + ' px');
  // Monotonie in beiden Zweigen: die Skala darf Vergleiche nicht umdrehen.
  for (const p of [4, 50, 150, 5000]) {
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
  // Nach der Rendering-Untergrenze (2 px) ist er bei 176 px Plot-Hoehe 2 px hoch = 1,14 %,
  // bei 132 px 1,52 % - immer noch weit unter einem Gitterintervall.
  assert.ok(2 / 176 < gridline / 4, 'Untergrenze zu hoch (Desktop)');
  assert.ok(2 / 132 < gridline / 4, 'Untergrenze zu hoch (Mobil)');
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

test('CSS: Hoeheneinheit --bh ist dieselbe fuer Balken und Marker, Untergrenze nur fuer nicht-leere Saulen', () => {
  const css = stripComments(styleCss);
  assert.match(css, /\.vt-col\s*\{[^}]*--bh:\s*calc\(var\(--u\)\s*\*\s*var\(--n,\s*0\)\)/, '--bh Grundregel');
  assert.match(css, /\.vt-col\.vt-nonzero\s*\{[^}]*--bh:\s*max\(2px,\s*calc\(var\(--u\)\s*\*\s*var\(--n,\s*0\)\)\)/, 'Untergrenze nur fuer nicht-leere Saulen');
  assert.match(css, /\.vt-bar\s*\{[^}]*height:\s*var\(--bh\)/, 'Balkenhoehe aus --bh');
  assert.match(css, /\.vt-mark\s*\{[^}]*bottom:\s*calc\(var\(--bh\)\s*\+\s*var\(--dzc\)\s*\+\s*1px\)/, 'Markerhoehe aus --bh und --dzc');
  assert.doesNotMatch(css, /\.vt-bar\s*\{[^}]*height:\s*calc\(var\(--u\)\s*\*\s*var\(--n/, 'Balken darf nicht mehr ein eigenes Mass haben');
  assert.match(src, /vt-state-'\s*\+\s*state\s*\+\s*\(cell\.total\s*\?\s*" vt-nonzero"\s*:\s*""\)/, 'vt-nonzero genau bei Vorfaellen');
});

/* --- Tiefe je Säule ---------------------------------------------------------
 * Gemessen 2026-10-16 live (7d-Fenster, peak 5000, Profiltiefe --d 7,63 px, --dz 6,63 px):
 * ein Intervall mit 1 Vorfall war 2,48 px hoch. Bei fester Tiefe ragten Grundriss-
 * Rückkante und Deckfläche 6,63 px über die Balken-Oberkante, und die Deckflächen
 * benachbarter Säulen berührten sich (Säule 29 px + Tiefe 7,63 px gegen Schrittweite
 * 39 px). Das Profil las sich als Schrägband. Deshalb je Säule:
 *   --dc = min(--d, --bh), --dzc = --dc * tan 41deg  ->  dzc <= 0,86929 * bh < bh.
 */
const DZ_K = 0.86929;

test('Tiefe: --dc/--dzc sind je Säule abgeleitet, nicht paarweise gesetzt', () => {
  const css = stripComments(styleCss);
  assert.match(css, /\.vt-col\s*\{[^}]*--dc:\s*var\(--d\)/, 'Standard-Tiefe --dc fehlt');
  assert.match(css, /\.vt-col\s*\{[^}]*--dzc:\s*calc\(var\(--dc\)\s*\*\s*var\(--dz-k\)\)/, '--dzc nicht aus --dc abgeleitet');
  assert.match(css, /\.vt-col\.vt-nonzero\s*\{[^}]*--dc:\s*min\(var\(--d\),\s*var\(--bh\)\)/, 'Tiefe nicht auf die Balkenhöhe begrenzt');
  assert.match(css, /\.vt-col\.vt-nonzero\s*\{[^}]*--dzc:\s*calc\(var\(--dc\)\s*\*\s*var\(--dz-k\)\)/, '--dzc der nicht-leeren Säule nicht abgeleitet');
  assert.match(css, /\.vt-profile\s*\{[^}]*--d:\s*clamp\(\s*([\d.]+)px,\s*([\d.]+)cqw,\s*([\d.]+)px\s*\)/, 'Profiltiefe --d fehlt');
});

test('Tiefe: Tiefen-, Deck- und Grundrissfläche nutzen dieselbe Säulen-Tiefe', () => {
  assert.match(ruleBody('.vt-side'), /width:\s*var\(--dc\)/, '.vt-side Breite != --dc');
  assert.match(ruleBody('.vt-top'), /height:\s*var\(--dzc\)/, '.vt-top Höhe != --dzc');
  assert.match(ruleBody('.vt-foot'), /height:\s*var\(--dzc\)/, '.vt-foot Höhe != --dzc');
  assert.doesNotMatch(ruleBody('.vt-side'), /width:\s*var\(--d\)/, '.vt-side hält noch die Profiltiefe --d');
  assert.doesNotMatch(ruleBody('.vt-top'), /height:\s*var\(--dz\)/, '.vt-top hält noch die Profiltiefe --dz');
  assert.doesNotMatch(ruleBody('.vt-foot'), /height:\s*var\(--dz\)/, '.vt-foot hält noch die Profiltiefe --dz');
});

test('Tiefe: Deckfläche und Grundriss-Rückkante bleiben unter der Balken-Oberkante', () => {
  const peak = 5000, plotH = 176, d = 7.63;
  for (const incidents of [1, 2, 6, 129, 1250, 3931, 4502]) {
    const bh = Math.max(2, (axisUnit(incidents, peak) / peak) * plotH);
    const dc = Math.min(d, bh);
    const dzc = dc * DZ_K;
    assert.ok(dzc < bh, incidents + ' Vorfälle: dzc ' + dzc.toFixed(2) + ' px ueber dem Balken (bh ' + bh.toFixed(2) + ' px)');
    assert.ok(dc <= d, incidents + ' Vorfaelle: dc ' + dc + ' ueber der Profiltiefe');
    assert.ok(Math.abs(dzc - dc * Math.tan(41 * Math.PI / 180)) < 1e-4, 'dzc != dc * tan(41deg)');
  }
  // Der alte Fehler bleibt nachgerechnet: feste Tiefe 7,63 px gegen 2,48 px Balkenhöhe.
  const bh1 = Math.max(2, (axisUnit(1, peak) / peak) * plotH);
  assert.ok(d * DZ_K > bh1, 'feste Tiefe war ' + (d * DZ_K).toFixed(2) + ' px gegen Balken ' + bh1.toFixed(2) + ' px');
  // Höchste Säule + ihre Deckfläche passen in den Plot (Plot-Hoehe + max. --dz).
  const bhMax = (axisUnit(peak, peak) / peak) * plotH;
  assert.ok(bhMax + Math.min(d, bhMax) * DZ_K <= plotH + d * DZ_K, 'hoechste Saeule ragt ueber den Plot');
});

test('Mobil: unter 460 px Containerbreite wird das Prisma flach (kein 3D-Brei auf 6 px Säulen)', () => {
  const css = stripComments(styleCss);
  assert.match(css, /@container\s*\(max-width:\s*460px\)\s*\{\s*\.vt-side,\s*\.vt-top\s*\{\s*display:\s*none/, 'Mobil-Regel fuer die Scherflaechen fehlt');
  assert.match(css, /\.vt-col:not\(\.vt-nonzero\)\s+\.vt-foot[^}]*min-height:\s*4px/, 'Grundriss-Kachel ohne Balken hat keine Mobil-Untergrenze');
  // Nachgerechnet, nicht gefuehlt. cqw = Content-Breite des Containers; .vt-plot zieht links
  // --gutter und rechts calc(--d + 3px) ab; uebrig bleiben 24 Säulen und 23 gap.
  const cols = 24;
  const clamp = (v, lo, hi) => Math.min(Math.max(lo, v), hi);
  const at = (c) => {
    const g = clamp(1.15 * c / 100, 4, 15);
    const d = clamp(0.85 * c / 100, 3, 11);
    const gutter = clamp(4.2 * c / 100, 20, 42);
    const plot = c - gutter - (d + 3);
    return { col: (plot - (cols - 1) * g) / cols, d, plot };
  };
  const a = at(460), b = at(480);
  // Der Kipppunkt der Kantenbreite liegt zwischen 470 und 471 px (4 / 0,0085 = 470,6).
  assert.ok(at(471).d >= 4 && at(470).d < 4, 'Kipppunkt der 4-px-Kante liegt nicht bei 470,6 px');
  assert.ok(a.d < 4, '460 px: Tiefe ' + a.d.toFixed(2) + ' px - unter der Kantenbreite, also flach');
  assert.ok(b.d >= 4 && b.col >= 12, '480 px: Saeule ' + b.col.toFixed(2) + ' px, Tiefe ' + b.d.toFixed(2) + ' px - ab hier Prisma');
  // Anker an der Messung 2026-10-16 (390 px Viewport): 286 px Aussenbreite = 260 px Content,
  // Plot 234 px, Säule 5,91 px, Deckflaeche 2,59 px. Das Modell muss die Messung treffen.
  const mob = at(260);
  assert.ok(Math.abs(mob.plot - 234) < 1, 'Modell-Plot ' + mob.plot.toFixed(2) + ' px gegen gemessen 234 px');
  assert.ok(mob.col < 8 && mob.d <= 3, 'gemessener Mobil-Container 260 px Content: Saeule ' + mob.col.toFixed(2) + ' px, Tiefe ' + mob.d.toFixed(2) + ' px');
  // Die Achsen-Invariante bleibt: ohne Scherflaechen darf kein Grundriss ueber den Balken ragen.
  assert.match(css, /\.vt-col\.vt-nonzero\s*\{[^}]*--dc:\s*min\(var\(--d\),\s*var\(--bh\)\)/, 'Tiefen-Begrenzung fehlt');
});

test('Tiefe: Profiltiefe ist ein Volumen und hält die Deckflächen getrennt', () => {
  const css = stripComments(styleCss);
  const pick = (token) => {
    const m = css.match(new RegExp('--' + token + ':\\s*clamp\\(\\s*([\\d.]+)px,\\s*([\\d.]+)cqw,\\s*([\\d.]+)px\\s*\\)'));
    if (!m) throw new Error('clamp fehlt für --' + token);
    return { min: +m[1], k: +m[2], max: +m[3] };
  };
  const d = pick('d'), gap = pick('gap');
  // Die Tiefe muss eine eigene Fläche sein, kein Rasterzeichen: gemessen 2026-10-16 war sie bei
  // 0,5cqw 4,82 px, die Deckfläche pixelgleich zum Balken (Luminanz 0,55 gegen 0,54) - ohne
  // unterscheidbare Kante. Untergrenze 3 px (Mobil), Volumen-Untergrenze 8 px, Obergrenze 12 px.
  assert.ok(d.max >= 8, 'Profiltiefe ' + d.max + ' px - die Tiefenfläche wäre kein Volumen mehr');
  assert.ok(d.max <= 12, 'Profiltiefe ' + d.max + ' px ist zu tief für 24 schmale Säulen');
  // Säulenbreite + Tiefe gegen Schrittweite: der Luft zwischen zwei Deckflächen.
  const container = 978, cols = 24;
  const g = Math.min(Math.max(gap.min, gap.k * container / 100), gap.max);
  const dd = Math.min(Math.max(d.min, d.k * container / 100), d.max);
  const col = (container - (cols - 1) * g) / cols;
  const clearance = col + g - dd;
  assert.ok(clearance >= 5, 'Deckflächen-Abstand ' + clearance.toFixed(2) + ' px - zu nah an der Berührung');
  assert.ok(dd <= g, 'dc <= gap verletzt (dc ' + dd + ' > gap ' + g + ')');
  // Dieselbe Invariante am mobilen Container (760 px Panel, 340 px Profiltiefe).
  const mobile = 340;
  const gm = Math.min(Math.max(gap.min, gap.k * mobile / 100), gap.max);
  const dm = Math.min(Math.max(d.min, d.k * mobile / 100), d.max);
  assert.ok(dm <= gm, 'dc <= gap verletzt (mobil dc ' + dm + ' > gap ' + gm + ')');
  const colm = (mobile - (cols - 1) * gm) / cols;
  assert.ok(colm + gm - dm >= 5, 'Deckflächen-Abstand mobil ' + (colm + gm - dm).toFixed(2) + ' px');
  assert.ok(dm >= 3, 'Profiltiefe mobil ' + dm + ' px - unter der Kantensichtbarkeit');
});
