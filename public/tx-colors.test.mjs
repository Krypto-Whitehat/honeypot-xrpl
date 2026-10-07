/* public/tx-colors.test.mjs — Farb-Mapping deterministisch (Audit 2026-10-07)
 *
 * Kein Browser nötig (Muster design-assets.test.mjs):
 *  1) txCategory: je Ledger-Tx-Typ -> Kategorie (public/edge-colors.mjs,
 *     DOM-frei) — Typnamen exakt laut xrpl.org-Transaktionsreferenz
 *     (live abgerufen 2026-10-07); Unbekannte -> 'other', nie Wurf.
 *  2) Kategorie-Palette: --a6-edge-* Tokens in BEIDEN Themes (style.css ist
 *     SSOT) — exakte Werte, UI-Kontrast >= 3:1 gegen beide Surfaces und die
 *     vom Audit-Kritiker bemängelten Paar-Abstände (>= 1.25:1 bzw. die
 *     dokumentierte Ausnahme: Noir payment = --a6-success, 1.11:1 zum
 *     Check-Teal, bewusste 'grün=gut'-Bundlung).
 *  3) JS-Spiegel-Konsistenz: THEME_JS_COLORS.edge (app.js) deckt dieselben
 *     Kategorie-Schlüssel mit denselben Werten wie die CSS-Tokens.
 *  4) Verdrahtung: Fraud-Override (severity ∪ severityByAddress beider
 *     Endpunkte) in app.js/drilldown.js/globe.js/history-host.html, Dash-
 *     Muster für Betrugskanten als Deutan-Zweitkanal, Legenden in Dashboard,
 *     3D-Overlay und Flow-Host, i18n-Keys DE/EN vollständig.
 *
 * Lauf: node --test public/tx-colors.test.mjs
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { txCategory, isKnownEdgeCategory, EDGE_CATEGORY_ORDER } from './edge-colors.mjs';

const here = path.dirname(fileURLToPath(import.meta.url));
const read = (rel) => readFileSync(path.join(here, rel), 'utf8');
const styleCss = read('style.css');
const appJs = read('app.js');
const drilldownJs = read('drilldown.js');
const globeJs = read('globe.js');
const historyHostHtml = read('history-host.html');
const indexHtml = read('index.html');
const i18nMjs = read('i18n.mjs');

/* ---------------- 1) Tx-Typ -> Kategorie (deterministisch) ---------------- */

const MAPPING = {
  // payment
  Payment: 'payment',
  // escrow
  EscrowCreate: 'escrow', EscrowFinish: 'escrow', EscrowCancel: 'escrow',
  // check (Check* + PaymentChannel*)
  CheckCreate: 'check', CheckCash: 'check', CheckCancel: 'check',
  PaymentChannelCreate: 'check', PaymentChannelFund: 'check', PaymentChannelClaim: 'check',
  // market (DEX + AMM + Issuer/Token-Familie — zusammengelegt, 1.02:1-Fix)
  OfferCreate: 'market', OfferCancel: 'market', TrustSet: 'market', Clawback: 'market',
  AMMCreate: 'market', AMMDeposit: 'market', AMMWithdraw: 'market',
  AMMVote: 'market', AMMBid: 'market', AMMDelete: 'market', AMMClawback: 'market',
  MPTokenIssuanceCreate: 'market',
  // nft (alle NFToken*)
  NFTokenMint: 'nft', NFTokenBurn: 'nft', NFTokenCreateOffer: 'nft',
  NFTokenCancelOffer: 'nft', NFTokenAcceptOffer: 'nft', NFTokenModify: 'nft',
  // admin
  AccountSet: 'admin', AccountDelete: 'admin', SetRegularKey: 'admin',
  SignerListSet: 'admin', TicketCreate: 'admin', DepositPreauth: 'admin',
  DIDSet: 'admin', DIDDelete: 'admin',
  CredentialCreate: 'admin', CredentialAccept: 'admin', CredentialDelete: 'admin',
  PermissionedDomainSet: 'admin', PermissionedDomainDelete: 'admin',
  XChainCommit: 'admin', XChainClaim: 'admin', XChainCreateBridge: 'admin',
  XChainAccountCreateCommit: 'admin', XChainModifyBridge: 'admin',
  OracleSet: 'admin', OracleDelete: 'admin',
  VaultWithdraw: 'admin', VaultCreate: 'admin',
  Batch: 'admin', DelegateSet: 'admin', LedgerStateFix: 'admin',
  EnableAmendment: 'admin', SetFee: 'admin', UNLModify: 'admin',
};

test('txCategory: jeder bekannte Ledger-Tx-Typ landet in seiner Kategorie', () => {
  for (const [type, expected] of Object.entries(MAPPING)) {
    assert.equal(txCategory(type), expected, `${type} -> ${expected}`);
  }
});

test('txCategory: unbekannt/defekt -> immer other (deterministisch, kein Wurf)', () => {
  assert.equal(txCategory('OfferPreview'), 'other', 'erfundener/alter Platzhalter (AMMSwap-Nachfolger existiert nicht)');
  assert.equal(txCategory('AMMSwap'), 'other', 'AMMSwap: nie Mainnet (durch AMMClawback ersetzt)');
  assert.equal(txCategory(''), 'other');
  assert.equal(txCategory(null), 'other');
  assert.equal(txCategory(undefined), 'other');
  assert.equal(txCategory(42), 'other');
  assert.equal(txCategory('payment'), 'other', 'Case-sensitiv: Ledger-Namen sind PascalCase');
});

test('txCategory: Kategorie-Set und Legende-Reihenfolge wohlgeformt', () => {
  for (const c of EDGE_CATEGORY_ORDER) assert.ok(isKnownEdgeCategory(c));
  assert.deepEqual([...EDGE_CATEGORY_ORDER], ['fraud', 'payment', 'market', 'escrow', 'check', 'admin', 'nft', 'other']);
});

/* ---------------- 2) Kategorie-Palette (beide Themes, style.css) ---------------- */

function parseBlock(rx) {
  const block = styleCss.match(rx);
  assert.ok(block, 'Token-Block gefunden');
  const map = {};
  for (const m of block[0].matchAll(/(--a6-[a-z0-9-]+)\s*:\s*([^;]+);/g)) map[m[1]] = m[2].trim();
  return map;
}
const lightTokens = parseBlock(/\[data-a6\]\s*\{[\s\S]*?\n\}/);
const noirTokens = parseBlock(/\[data-a6\]\[data-theme="noir"\]\s*\{[\s\S]*?\n\}/);
const noirView = { ...lightTokens, ...noirTokens };

function hexLuminance(hex) {
  const m = /^#([0-9a-f]{6})$/i.exec(String(hex ?? ''));
  assert.ok(m, `6-stelliger Hex erwartet, erhalten: ${hex}`);
  const lin = (h) => {
    const v = parseInt(h, 16) / 255;
    return v <= 0.03928 ? v / 12.92 : ((v + 0.055) / 1.055) ** 2.4;
  };
  return 0.2126 * lin(m[1].slice(0, 2)) + 0.7152 * lin(m[1].slice(2, 4)) + 0.0722 * lin(m[1].slice(4, 6));
}
const contrastRatio = (a, b) => {
  const l1 = hexLuminance(a);
  const l2 = hexLuminance(b);
  return (Math.max(l1, l2) + 0.05) / (Math.min(l1, l2) + 0.05);
};

const CATEGORY_HEX = {
  Hell: {
    '--a6-edge-payment': '#066348',
    '--a6-edge-market': '#b45309',
    '--a6-edge-escrow': '#6d28d9',
    '--a6-edge-check': '#0f766e',
    '--a6-edge-admin': '#1d4ed8',
    '--a6-edge-nft': '#c026d3',
    '--a6-edge-fraud': '#b3261e',
    '--a6-edge-neutral': '#62626b',
  },
  Noir: {
    '--a6-edge-payment': '#4ade80',
    '--a6-edge-market': '#ffb45e',
    '--a6-edge-escrow': '#b79cff',
    '--a6-edge-check': '#3ecfbb',
    '--a6-edge-admin': '#8ab4ff',
    '--a6-edge-nft': '#d946ef',
    '--a6-edge-fraud': '#ff7a70',
    '--a6-edge-neutral': '#8f8da0',
  },
};
const SURFACE = { Hell: '#ffffff', Noir: '#14131f' };

test('Kategorie-Palette: exakte Token-Werte in beiden Themes (style.css SSOT)', () => {
  for (const [theme, tokens] of [['Hell', lightTokens], ['Noir', noirView]]) {
    for (const [token, hex] of Object.entries(CATEGORY_HEX[theme])) {
      assert.equal(tokens[token], hex, `${theme}: ${token} = ${hex}`);
    }
  }
});

test('Kategorie-Palette: jede Kantenkategorie >= 3:1 UI gegen die Theme-Surface', () => {
  for (const theme of ['Hell', 'Noir']) {
    for (const [token, hex] of Object.entries(CATEGORY_HEX[theme])) {
      const ratio = contrastRatio(hex, SURFACE[theme]);
      assert.ok(ratio >= 3, `${theme}: ${token} auf Surface ${ratio.toFixed(2)} < 3`);
    }
  }
});

test('Kategorie-Palette: kritische Paar-Abstände der Audit-Korrektur', () => {
  // Pflicht 5: DEX+AMM zusammengelegt — die alten Fast-Zwillings-Tokens
  // (trustset/offer/accountset, 1.02:1 auseinander) sind ersatzlos entfernt.
  for (const legacy of ['--a6-edge-trustset', '--a6-edge-offer', '--a6-edge-accountset']) {
    assert.equal(lightTokens[legacy], undefined, `${legacy} entfernt`);
    assert.equal(noirTokens[legacy], undefined, `${legacy} im Noir-Block entfernt`);
  }
  // Pflicht 6 (light): Payment-Grün vs Check-Teal >= 1.25 (alt: 1.08).
  const payTealLight = contrastRatio(CATEGORY_HEX.Hell['--a6-edge-payment'], CATEGORY_HEX.Hell['--a6-edge-check']);
  assert.ok(payTealLight >= 1.25, `Hell payment/check ${payTealLight.toFixed(2)} < 1.25`);
  // Pflicht 6 (noir): payment = --a6-success exakt — bewusste Bundlung,
  // dokumentiert (1.11:1 zum Teal bleibt, Deutan-Kanal = gestrichelte Fraud-Kanten).
  assert.equal(noirView['--a6-edge-payment'], noirView['--a6-success'], 'Noir-Payment = --a6-success (dokumentierte Bundlung)');
  // Pflicht 6: NFT vs Escrow >= 1.25 in BEIDEN Themes (alt: 1.12 / 1.08).
  const nftEscrowLight = contrastRatio(CATEGORY_HEX.Hell['--a6-edge-nft'], CATEGORY_HEX.Hell['--a6-edge-escrow']);
  const nftEscrowNoir = contrastRatio(CATEGORY_HEX.Noir['--a6-edge-nft'], CATEGORY_HEX.Noir['--a6-edge-escrow']);
  assert.ok(nftEscrowLight >= 1.25, `Hell nft/escrow ${nftEscrowLight.toFixed(2)} < 1.25`);
  assert.ok(nftEscrowNoir >= 1.25, `Noir nft/escrow ${nftEscrowNoir.toFixed(2)} < 1.25`);
  // Betrugskante bleibt in der Severity-Rot-Familie (Nutzervorgabe Betrug=Rot).
  assert.equal(lightTokens['--a6-edge-fraud'], lightTokens['--a6-sev-malicious']);
  assert.equal(noirView['--a6-edge-fraud'], noirView['--a6-sev-malicious']);
});

test('Kategorie-Palette: Payment-Kante ist GRÜN und kollidiert nicht mehr mit Fraud-Rot', () => {
  assert.notEqual(lightTokens['--a6-edge-payment'], lightTokens['--a6-edge-fraud']);
  assert.notEqual(lightTokens['--a6-swatch-payment'], lightTokens['--a6-sev-malicious']);
  assert.notEqual(noirView['--a6-swatch-payment'], noirView['--a6-sev-malicious']);
});

/* ---------------- 3) JS-Spiegel (THEME_JS_COLORS.edge = Tokens) ---------------- */

test('JS-Spiegel: THEME_JS_COLORS.edge deckt dieselben Kategorien mit denselben Werten', () => {
  const edgeBlocks = [...appJs.matchAll(/edge: \{([^}]*)\}/g)].map((m) => m[1]);
  assert.equal(edgeBlocks.length, 2, 'genau zwei edge-Blöcke (Hell + Noir)');
  const parse = (block) => {
    const map = {};
    for (const m of block.matchAll(/([a-z]+):\s*'(#[0-9a-f]{6})'/g)) map[m[1]] = m[2];
    return map;
  };
  const lightMirror = parse(edgeBlocks[0]);
  const noirMirror = parse(edgeBlocks[1]);
  const keys = ['fraud', 'payment', 'market', 'escrow', 'check', 'admin', 'nft'];
  for (const k of keys) {
    assert.equal(lightMirror[k], CATEGORY_HEX.Hell[`--a6-edge-${k}`], `Hell-Mirror ${k}`);
    assert.equal(noirMirror[k], CATEGORY_HEX.Noir[`--a6-edge-${k}`], `Noir-Mirror ${k}`);
  }
  // Die initiale EDGE_COLORS-Tabelle trägt dieselben Hell-Werte (in-place-
  // Mutation durch applyThemeColors).
  for (const k of keys) {
    assert.match(appJs, new RegExp(`${k}: '${CATEGORY_HEX.Hell[`--a6-edge-${k}`]}'`), `EDGE_COLORS ${k} Hell`);
  }
});

/* ---------------- 4) Verdrahtung: Override, Dash, Legenden, i18n ---------------- */

test('app.js: Fraud-Override (severity ∪ severityByAddress beider Endpunkte) vor der Kategorie', () => {
  // severityByAddress-Union über alle Cluster (Pflichtkorrektur 4).
  assert.match(appJs, /sevByAddr\[/, 'Union der Cluster-severityByAddress');
  assert.match(appJs, /const fraud = edgeIsFraud\(e, sevByAddr\)/, 'Override je Kante');
  assert.match(appJs, /fraud \? EDGE_COLORS\.fraud : \(EDGE_COLORS\[txCategory\(type\)\] \|\| EDGE_DEFAULT\)/, 'Override VOR der Kategorie-Farbe');
  // Deutan-Zweitkanal: gestrichelte Betrugskanten.
  assert.match(appJs, /\.\.\.\(fraud \? \{ dashes: \[6, 4\] \} : \{\}\)/, 'Dash-Muster nur für Betrugskanten');
  // ctx-Adapter für drilldown/globe.
  assert.equal((appJs.match(/edgeCategory: txCategory,/g) ?? []).length, 2, 'edgeCategory in beiden ctx (drilldown + globe)');
});

test('drilldown.js: 3D-Accessor, 2D-Fallback und Zeitachse tragen Kategorie + Override', () => {
  assert.match(drilldownJs, /import \{ txCategory, EDGE_CATEGORY_ORDER \} from '\.\/edge-colors\.mjs';/);
  assert.match(drilldownJs, /edgeIsFraud\(l\) \? edgeColors\.fraud : edgeColors\[edgeCategoryOf\(l\.type\)\]/, '3D-Accessor');
  assert.match(drilldownJs, /\(fraud \? edgeColors\.fraud : edgeColors\[edgeCategoryOf\(e\.type\)\]\)/, '2D-Fallback');
  assert.match(drilldownJs, /\.\.\.\(fraud \? \{ dashes: \[6, 4\] \} : \{\}\)/, '2D-Dash (Deutan-Zweitkanal)');
  assert.match(drilldownJs, /fraudAddrSet = new Set\(/, 'Fraud-Menge je paintCluster-Render');
  assert.match(drilldownJs, /\.\.\.\(e\.severity != null \? \{ severity: e\.severity \} : \{\}\)/, 'severity wandert in die 3D-Links');
  // Zeitachse: Betrugs-Punkte als Konturkreis (nicht-farblicher Zweitkanal).
  assert.match(drilldownJs, /p\.fraud\s*\n\s*\? `<circle[^`]*fill="none" stroke=/, 'Timeline-Fraud als Konturkreis');
  // 3D-Overlay-Legende über dieselben swatch-Klassen.
  assert.match(drilldownJs, /cluster-graph-legend/, 'Legende-Container im Overlay');
  assert.match(drilldownJs, /function renderEdgeLegend\(/, 'renderEdgeLegend definiert');
  assert.match(drilldownJs, /renderEdgeLegend\(\);/, 'renderEdgeLegend im paintCluster aufgerufen');
});

test('globe.js: Arc-Farbe = Fraud-Override (sevTokenColor malicious) sonst Kategorie', () => {
  assert.match(globeJs, /import \{ txCategory \} from '\.\/edge-colors\.mjs';/);
  assert.match(
    globeJs,
    /flagged\s*\n\s*\? \(sevTokenColor\('malicious'\) \|\| edgeDefaultOf\(\)\)\s*\n\s*: \(edgeColors\[edgeCategoryOf\(e\.type \?\? ''\)\] \|\| edgeDefaultOf\(\)\)/,
    'Override VOR der Kategorie-Farbe (theme-geführt via Token)',
  );
});

test('history-host.html: Flow-Graph-Kanten je Kategorie aus Tokens, Fraud gestrichelt, Legende erweitert', () => {
  assert.match(historyHostHtml, /import \{ txCategory, EDGE_CATEGORY_ORDER \} from '\.\/edge-colors\.mjs';/);
  assert.match(historyHostHtml, /function fraudAddrSetOf\(clusters\)/, 'severityByAddress-Union (Kanten ohne severity-Feld)');
  assert.match(historyHostHtml, /const stroke = fraud \? fraudColor : edgeCategoryColor\(e\.type\);/, 'Override VOR der Kategorie');
  assert.match(historyHostHtml, /const dashes = fraud \? ' stroke-dasharray="6 4"' : '';/, 'SVG-Dash (Deutan-Zweitkanal)');
  assert.match(historyHostHtml, /cssToken\('--a6-edge-fraud'\)/, 'Fraud-Farbe über Token');
  assert.match(historyHostHtml, /payment: '--a6-edge-payment'/, 'Payment-Farbe über Token (Kategorie-Map)');
  assert.match(historyHostHtml, /renderFlowGraph\(graph, fraudAddrSetOf\(clusters\)\)/, 'Fraud-Menge fließt in den Graph');
  assert.match(historyHostHtml, /const edgeRows = EDGE_CATEGORY_ORDER/, 'Kanten-Kategorien in der Flow-Host-Legende');
});

test('Legende + i18n: neue Kategorien-Keys in Dashboard, DE/EN-Parität, deutsche Umlaute korrekt', () => {
  for (const key of ['legend.market', 'legend.nft', 'legend.admin', 'legend.fraud']) {
    assert.equal((i18nMjs.match(new RegExp(`'${key.replace(/\./g, '\\.')}':`, 'g')) ?? []).length, 2, `${key} in EN und DE`);
  }
  assert.match(indexHtml, /data-i18n="legend\.market"/);
  assert.match(indexHtml, /data-i18n="legend\.nft"/);
  assert.match(indexHtml, /data-i18n="legend\.admin"/);
  assert.match(indexHtml, /data-i18n="legend\.fraud"/);
  assert.match(i18nMjs, /'legend\.fraud': 'Betrug \(Kante\)'/, 'DE-Label mit Umlaut-freier, korrekter Form');
  assert.match(i18nMjs, /'legend\.market': 'DEX\/AMM'/);
  // Swatch-Klassen für die neuen Kategorien existieren (Token-Regeln, kein Hex).
  for (const cat of ['market', 'nft', 'admin', 'fraud']) {
    assert.match(styleCss, new RegExp(`\\.swatch-${cat}\\s*\\{\\s*background:\\s*var\\(--a6-edge-${cat}\\);\\s*\\}`));
  }
});
