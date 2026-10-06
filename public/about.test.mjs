/* Info-Seite about.html — Regressionstests (2026-10-06)
 *
 * Statische Guards für die eigenständige Info-/About-Seite der XRPL-Community
 * (App-Shell-Look, Muster history-host.html) — kein Browser nötig:
 *  1) Route/View: about.html existiert im App-Shell-Gerüst (topbar-Marke,
 *     Sprachumschalter-Container, view-nav mit aria-current, vier Panels,
 *     Footer); /about ist per vercel.json-Rewrite erreichbar; index.html
 *     (Nav + Footer) und history-host.html (Nav) verlinken sie prominent.
 *  2) i18n: JEDER data-i18n/data-i18n-aria-Key der Seite existiert in BEIDEN
 *     Wörterbüchern; DE- und EN-Schlüsselmenge sind identisch (Anforderung
 *     der Aufgabe, zusätzlich zu lib/i18n.test.mjs); PAGE_TITLE/PAGE_DESC
 *     tragen einen about-Eintrag.
 *  3) Pflichtbegriffe: alle geforderten Rollen/Muster und Glossarbegriffe
 *     sind in BEIDEN Sprachen in den about.*-Texten vorhanden.
 *  4) Statisch/Speed: keine externen Stylesheets/Scripts, kein fetch, keine
 *     API-Aufrufe — die Seite bleibt fetch-frei; deutsche Orthografie der
 *     DE-Werte (Umlaute/Scharfes-S, kein ASCII-Ersatz, kein Mojibake).
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

import { DICT, PAGE_TITLE, PAGE_DESC } from './i18n.mjs';

const here = path.dirname(fileURLToPath(import.meta.url));
const read = (rel) => readFileSync(path.join(here, rel), 'utf8');
const root = (rel) => readFileSync(path.join(here, '..', rel), 'utf8');

const aboutHtml = read('about.html');
const indexHtml = read('index.html');
const historyHostHtml = read('history-host.html');
const vercelJson = root('vercel.json');
const i18nMjs = read('i18n.mjs');
const styleCss = read('style.css');

/* ---------------- 1) Route/View existiert ---------------- */

test('about.html: App-Shell-Gerüst (Marke, Sprachumschalter, Nav mit aria-current, vier Panels, Footer)', () => {
  assert.match(aboutHtml, /<!DOCTYPE html>/, 'Dokumentdeklaration');
  assert.match(aboutHtml, /<html lang="en">/, 'lang="en"-Initialdokument wie index.html');
  assert.match(aboutHtml, /<body data-a6>/, 'data-a6-Shell (Design-Tokens)');
  assert.match(aboutHtml, /<span class="brand-mark" aria-hidden="true">/, 'Marke .brand-mark');
  assert.match(aboutHtml, /<div class="lang-switch" id="lang-switch"><\/div>/, 'Sprachumschalter-Container');
  assert.match(aboutHtml, /<nav class="view-nav graph-tabs"[^>]*data-i18n-aria="fh\.navAria"/, 'view-nav wie history-host');
  assert.match(
    aboutHtml,
    /<a class="view-tab graph-tab" href="about\.html" aria-current="page" data-i18n="tab\.about">/,
    'About-Tab trägt aria-current="page"',
  );
  for (const id of ['about-mission-title', 'about-detect-title', 'about-glossary-title', 'about-limits-title']) {
    assert.match(aboutHtml, new RegExp(`<section class="panel" aria-labelledby="${id}">`), `Panel ${id}`);
  }
  assert.match(aboutHtml, /<footer class="footbar">/, 'Footbar vorhanden');
  assert.match(aboutHtml, /<link rel="icon" type="image\/svg\+xml" href="favicon\.svg">/, 'Favicon als Datei verlinkt');
});

test('Route: vercel.json mappet /about und /about.html auf public/about.html (Muster history-host)', () => {
  const cfg = JSON.parse(vercelJson);
  const rewrites = Array.isArray(cfg.rewrites) ? cfg.rewrites : [];
  for (const source of ['/about', '/about.html']) {
    const hit = rewrites.find((r) => r.source === source);
    assert.ok(hit, `Rewrite für ${source} fehlt`);
    assert.equal(hit.destination, '/public/about.html', `${source} -> public/about.html`);
  }
  // Keine neue Function: beide about-Ziele sind rein statisch (Vercel-Hobby-
  // Limit 12 Functions bleibt unberührt — die Info-Seite braucht keinen api/-Pfad).
  for (const hit of rewrites.filter((r) => String(r.source).startsWith('/about'))) {
    assert.doesNotMatch(String(hit.destination), /\/api\//, `${hit.source}: Ziel ist keine Function`);
  }
});

test('Prominente Verlinkung: index.html in Nav UND Footer, history-host.html in Nav', () => {
  assert.match(
    indexHtml,
    /<a class="view-tab graph-tab" href="about\.html" data-i18n="tab\.about">/,
    'index.html: About-Anker-Tab in der view-nav',
  );
  assert.match(
    indexHtml,
    /<a class="foot-link" href="about\.html" data-i18n="tab\.about">/,
    'index.html: About-Link im Footer',
  );
  assert.match(
    historyHostHtml,
    /<a class="view-tab graph-tab" href="about\.html" data-i18n="tab\.about">/,
    'history-host.html: About-Anker-Tab in der view-nav',
  );
});

/* ---------------- 2) i18n: Keys DE == EN, Verdrahtung ---------------- */

test('about.html: jeder data-i18n-Key der Seite existiert in EN und DE', () => {
  const keys = [...new Set([
    ...(aboutHtml.match(/data-i18n="([^"]+)"/g) ?? []).map((m) => m.slice('data-i18n="'.length, -1)),
    ...(aboutHtml.match(/data-i18n-aria="([^"]+)"/g) ?? []).map((m) => m.slice('data-i18n-aria="'.length, -1)),
  ])];
  assert.ok(keys.length >= 40, `erwartet umfangreiche Textmenge, gefunden: ${keys.length}`);
  for (const key of keys) {
    assert.equal(typeof DICT.en[key], 'string', `EN-Wert fehlt: ${key}`);
    assert.equal(typeof DICT.de[key], 'string', `DE-Wert fehlt: ${key}`);
    assert.ok(DICT.en[key].length > 0 && DICT.de[key].length > 0, `leerer Wert: ${key}`);
  }
  // Kern-Keys der vier Panels sind tatsächlich verdrahtet.
  for (const key of [
    'tab.about', 'about.sub', 'about.missionTitle', 'about.detectTitle',
    'about.glossaryTitle', 'about.limitsTitle', 'about.sourcesNote',
  ]) {
    assert.ok(keys.includes(key), `Key nicht in about.html verdrahtet: ${key}`);
  }
});

test('DICT: EN- und DE-Schlüsselmenge weiterhin identisch (Anforderung dieser Aufgabe)', () => {
  assert.deepEqual(Object.keys(DICT.en).sort(), Object.keys(DICT.de).sort());
});

test('i18n: PAGE_TITLE/PAGE_DESC/about-pageKind vorhanden', () => {
  for (const lang of ['en', 'de']) {
    assert.equal(typeof PAGE_TITLE.about?.[lang], 'string', `PAGE_TITLE.about.${lang}`);
    assert.ok(PAGE_TITLE.about[lang].length > 0);
    assert.equal(typeof PAGE_DESC.about?.[lang], 'string', `PAGE_DESC.about.${lang}`);
    assert.ok(PAGE_DESC.about[lang].length > 0);
  }
  assert.match(i18nMjs, /\/about\/i\.test\(p\)\) return 'about';/, 'pageKind erkennt about-Pfad');
  assert.match(i18nMjs, /'about\.missionTitle':/, 'about-Keys im Wörterbuch');
});

/* ---------------- 3) Pflichtbegriffe in beiden Sprachen ---------------- */

const aboutText = (lang) =>
  Object.entries(DICT[lang])
    .filter(([k]) => k.startsWith('about.') || k === 'tab.about')
    .map(([, v]) => v)
    .join(' \n ');

test('Pflichtbegriffe EN: Rollen, Muster, Glossar und Grenzen', () => {
  const text = aboutText('en');
  for (const term of [
    'Drainer', 'Collector', 'Source', 'Relay',
    'Peeling chains', 'Wash trading', 'Cross-ledger sweep', 'Hub connections', 'Known-bad contact',
    'Cluster', 'Severity', 'malicious', 'suspect', 'benign', 'risk-associated', 'worth reviewing',
    'Destination tag', 'transit', 'Entity resolution',
    'Block window', 'History vs. archive',
    'honeycluster.io', 'xrpscan.com',
  ]) {
    assert.ok(text.includes(term), `EN-Pflichtbegriff fehlt: ${term}`);
  }
});

test('Pflichtbegriffe DE: Rollen, Muster, Glossar und Grenzen', () => {
  const text = aboutText('de');
  for (const term of [
    'Drainer', 'Kollektor', 'Source', 'Relay',
    'Peeling-Ketten', 'Wash Trading', 'Cross-Ledger-Sweep', 'Hub-Verbindungen', 'Known-Bad-Kontakt',
    'Cluster', 'Schweregrad', 'maliziös', 'verdächtig', 'benigne', 'risikobehaftet', 'prüfungswürdig',
    'Destination-Tag', 'Transit', 'Entity-Auflösung',
    'Block-Fenster', 'Historie vs. Archiv',
    'honeycluster.io', 'xrpscan.com',
  ]) {
    assert.ok(text.includes(term), `DE-Pflichtbegriff fehlt: ${term}`);
  }
});

/* ---------------- 4) Statisch, Speed, Orthografie ---------------- */

test('about.html: fetch-frei und ohne externe Assets — nur style.css, Favicon und Inline-Modul', () => {
  const stylesheets = aboutHtml.match(/<link rel="stylesheet"[^>]*>/g) ?? [];
  assert.equal(stylesheets.length, 1, 'genau ein Stylesheet');
  assert.match(stylesheets[0], /href="style\.css"/, 'Stylesheet ist style.css');
  assert.doesNotMatch(aboutHtml, /<script[^>]+src=/, 'kein externes Script (Inline-Modul wie history-host)');
  assert.doesNotMatch(aboutHtml, /\bfetch\(/, 'kein fetch');
  assert.doesNotMatch(aboutHtml, /\/api\//, 'keine API-Aufrufe');
  assert.doesNotMatch(aboutHtml, /vendor\//, 'keine Vendor-Assets');
});

test('DE-Orthografie der about.*-Texte: Umlaute/Scharfes-S intakt, kein ASCII-Ersatz, kein Mojibake', () => {
  const deValues = Object.entries(DICT.de)
    .filter(([k]) => k.startsWith('about.') || k === 'tab.about')
    .map(([, v]) => v);
  assert.ok(deValues.length >= 55, `about-DE-Keymenge erwartet (>=55), gefunden: ${deValues.length}`);
  const joined = deValues.join('\n');
  assert.match(joined, /ä|ö|ü|ß/, 'DE-Texte ohne jeden Umlaut (Verdacht auf ASCII-Zersetzung)');
  assert.doesNotMatch(joined, /Ã/, 'Mojibake in DE-Texten');
  assert.doesNotMatch(joined, /\b(ae|oe|ue)\b/, 'ASCII-Umlaut-Ersatz als eigenständiges Wort in DE-Texten');
  // EN-Texte ebenfalls mojibake-frei.
  assert.doesNotMatch(aboutText('en'), /Ã/, 'Mojibake in EN-Texten');
});

test('style.css: About-Seiten-Regeln und Footer-/Nav-Verlinkung verdrahtet', () => {
  assert.match(styleCss, /\.about-defs\s*\{/, '.about-defs-Raster');
  assert.match(styleCss, /\.about-subsection h3\s*\{/, 'Abschnittstitel-Regel');
  assert.match(styleCss, /\.about-limits\s*\{/, '.about-limits-Liste');
  assert.match(styleCss, /\.view-tab\[aria-current="page"\]\s*\{[^}]*var\(--a6-ink-fill\)/, 'aktueller Tab auf Ink-Token');
  assert.match(styleCss, /\.foot-link\s*\{/, '.foot-link-Regel');
});
