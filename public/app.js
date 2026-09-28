'use strict';

/* Honeypot XRPL – Frontend
 * Pollt die Server-API alle 5 Sekunden und rendert:
 *   - Kopfzeilen-Stats   (GET /api/stats)
 *   - Echtzeit-Graph     (GET /api/graph, vis-network via CDN)
 *   - Threat-Tabelle     (GET /api/threats, aufklappbare Evidenz)
 *
 * Anonymitätsregel: Köder (Honeypots) werden NUR als Label dargestellt.
 * Sieht ein Knoten-Label trotzdem wie eine XRPL-Adresse aus, wird es
 * defensiv durch "Köder" ersetzt – Adressen von Ködern landen nie im DOM.
 */

const POLL_MS = 5000;

/* ------------------------------------------------------------------ */
/* Hilfsfunktionen                                                     */
/* ------------------------------------------------------------------ */

function esc(value) {
  return String(value ?? '').replace(/[&<>"']/g, (c) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
  })[c]);
}

// XRPL-Adressmuster (Base58, beginnt mit 'r', 25–35 Zeichen)
const XRPL_ADDR_RE = /^r[1-9A-HJ-NP-Za-km-z]{24,34}$/;

// Defensiv (Defense-in-Depth): Ein Wert, der wie eine XRPL-Adresse aussieht,
// darf NIE als Köder-Bezeichnung, Evidenz-Label oder Funding-Label im DOM
// landen — der Server sanitisiert bereits, hier wird das doppelt abgesichert.
function defang(value) {
  const s = String(value ?? '');
  if (XRPL_ADDR_RE.test(s)) return 'Köder (Adresse verborgen)';
  return s;
}

// Honeypot-Knoten dürfen nie eine echte Adresse als Label/Id tragen.
function honeypotLabel(node) {
  return defang(node.label || node.id || '');
}

function fmtTime(value) {
  if (value === null || value === undefined || value === '') return '–';
  const d = new Date(typeof value === 'number' ? value : value);
  if (Number.isNaN(d.getTime())) return String(value);
  return d.toLocaleString('de-DE', { dateStyle: 'medium', timeStyle: 'medium' });
}

function fmtClock(value) {
  if (value === null || value === undefined || value === '') return '–';
  const d = new Date(typeof value === 'number' ? value : value);
  if (Number.isNaN(d.getTime())) return String(value);
  return d.toLocaleTimeString('de-DE');
}

/* ------------------------------------------------------------------ */
/* Kopfzeilen-Stats                                                    */
/* ------------------------------------------------------------------ */

function renderStats(stats) {
  document.getElementById('stat-malicious').textContent =
    Number(stats.maliciousCount ?? 0).toLocaleString('de-DE');
  document.getElementById('stat-suspect').textContent =
    Number(stats.suspectCount ?? 0).toLocaleString('de-DE');
  document.getElementById('stat-events').textContent =
    Number(stats.eventCount ?? 0).toLocaleString('de-DE');
  document.getElementById('stat-network').textContent =
    String(stats.network ?? '–');
  document.getElementById('stat-last').textContent = fmtClock(stats.lastEventTime);
}

function setConnection(ok, detail) {
  const dot = document.getElementById('conn-dot');
  const text = document.getElementById('conn-text');
  dot.classList.toggle('ok', ok);
  dot.classList.toggle('err', !ok);
  text.textContent = ok ? 'Live – verbunden' : ('API nicht erreichbar' + (detail ? ` (${detail})` : ''));
}

/* ------------------------------------------------------------------ */
/* Graph (vis-network)                                                 */
/* ------------------------------------------------------------------ */

const EDGE_COLORS = {
  Payment: '#b3261e',
  TrustSet: '#b45309',
  OfferCreate: '#a16207',
  OfferCancel: '#a16207',
  AccountSet: '#1d4ed8',
  EscrowCreate: '#6d28d9',
  EscrowFinish: '#6d28d9',
  CheckCreate: '#0f766e',
  PaymentChannelCreate: '#0f766e',
  NFTokenMint: '#a21caf',
  NFTokenAcceptOffer: '#a21caf',
};
const EDGE_DEFAULT = '#62626b';

let nodesDS = null;
let edgesDS = null;
let network = null;

function initGraph() {
  if (typeof vis === 'undefined') {
    document.getElementById('graph').innerHTML =
      '<p class="graph-error">vis-network konnte nicht geladen werden (CDN nicht erreichbar).</p>';
    return false;
  }
  nodesDS = new vis.DataSet([]);
  edgesDS = new vis.DataSet([]);
  network = new vis.Network(
    document.getElementById('graph'),
    { nodes: nodesDS, edges: edgesDS },
    {
      autoResize: true,
      physics: {
        enabled: true,
        barnesHut: {
          gravitationalConstant: -4200,
          centralGravity: 0.25,
          springLength: 130,
          springConstant: 0.045,
          damping: 0.55,
        },
        stabilization: { iterations: 200 },
      },
      interaction: { hover: true, tooltipDelay: 120, zoomView: true, dragView: true },
      nodes: {
        borderWidth: 2,
        font: { color: '#141416', size: 14, face: '"JetBrains Mono", ui-monospace, Consolas, monospace' },
      },
      edges: {
        width: 2,
        smooth: { type: 'curvedCW', roundness: 0.14 },
        arrows: { to: { enabled: true, scaleFactor: 0.55 } },
      },
    }
  );
  return true;
}

function renderGraph(graph) {
  if (!network) return;

  const rawNodes = Array.isArray(graph.nodes) ? graph.nodes : [];
  const rawEdges = Array.isArray(graph.edges) ? graph.edges : [];

  // id -> Label für Kanten-Tooltips (NUR Labels, MEDIUM-5-Fix).
  const labelById = new Map(
    rawNodes.map((n) => [String(n.id), String(n.type === 'honeypot' ? honeypotLabel(n) : (n.label || n.id))])
  );

  const nextNodes = rawNodes.map((n) => {
    const isHoneypot = n.type === 'honeypot';
    const label = isHoneypot ? honeypotLabel(n) : String(n.label || n.id);
    return {
      id: String(n.id),
      label,
      // Titel-Tooltip NUR mit Labels: Honeypot-Knoten zeigen ihr Label,
      // Angreifer-Knoten ihre (öffentliche) Adresse als Label. Niemals rohe
      // Node-Ids mit Köder-Anteilen (MEDIUM-5-Fix).
      title: label,
      shape: isHoneypot ? 'hexagon' : 'dot',
      size: isHoneypot ? 14 : 18,
      color: isHoneypot
        ? { background: '#141416', border: '#141416', highlight: { background: '#33333a', border: '#141416' } }
        : { background: '#b3261e', border: '#7f1d1d', highlight: { background: '#d03b33', border: '#7f1d1d' } },
      margin: 8,
    };
  });

  const nextEdges = rawEdges.map((e) => {
    const type = String(e.type || 'Sonstige');
    return {
      id: `${e.from}->${e.to}::${type}`,
      from: String(e.from),
      to: String(e.to),
      label: type,
      // Kanten-Tooltip nur mit Labels (MEDIUM-5-Fix): Honeypot-Enden zeigen
      // "Köder #n", Angreifer-Enden die öffentliche Adresse.
      title: `${defang(labelById.get(String(e.from)) ?? e.from)} → ${defang(labelById.get(String(e.to)) ?? e.to)} (${type})`,
      color: { color: EDGE_COLORS[type] || EDGE_DEFAULT, highlight: '#141416', hover: '#141416' },
      font: { color: '#484850', size: 11, face: '"JetBrains Mono", ui-monospace, Consolas, monospace', strokeWidth: 0, align: 'middle' },
    };
  });

  // Inkrementell aktualisieren: bestehende Knoten/Kanten updaten, neue hinzufügen,
  // verschwundene entfernen – verhindert Flackern beim 5-Sekunden-Polling.
  nodesDS.update(nextNodes);
  const keepNodeIds = new Set(nextNodes.map((n) => n.id));
  const staleNodes = nodesDS.getIds().filter((id) => !keepNodeIds.has(id));
  if (staleNodes.length) nodesDS.remove(staleNodes);

  edgesDS.update(nextEdges);
  const keepEdgeIds = new Set(nextEdges.map((e) => e.id));
  const staleEdges = edgesDS.getIds().filter((id) => !keepEdgeIds.has(id));
  if (staleEdges.length) edgesDS.remove(staleEdges);
}

/* ------------------------------------------------------------------ */
/* Threat-Tabelle mit aufklappbarer Evidenz                            */
/* ------------------------------------------------------------------ */

const expandedAddresses = new Set(); // überlebt Neu-Renderings
let lastThreats = []; // letzte API-Liste für die clientseitige Suche

function evidenceRows(evidence) {
  // Öffentliche Evidenz enthält keinen txHash mehr, nur ref/type/time/honeypot.
  const rows = (Array.isArray(evidence) ? evidence : []).map((ev) => `
      <tr>
        <td class="tx-type">${esc(ev.type ?? '–')}</td>
        <td>${esc(fmtTime(ev.time))}</td>
        <td class="ev-ref">${esc(ev.ref ?? '–')}</td>
        <td class="bait-label">${esc(defang(ev.honeypot ?? '–'))}</td>
      </tr>`).join('');
  return rows || '<tr><td colspan="4">Keine Evidenz vorhanden.</td></tr>';
}

function fundingRows(funding) {
  // Funding wird nur als Label dargestellt (der Server liefert keine Adressen);
  // defensiv wird jede adresseähnliche Angabe verschleiert (MEDIUM-4-Fix).
  const list = Array.isArray(funding) ? funding : [];
  if (!list.length) return '';
  const items = list.map((f) => {
    const labelText = defang(f.label ?? 'Funding-Quelle');
    const hiddenAddr = f.address ? ' <span class="funding-label">(Adresse nicht öffentlich)</span>' : '';
    return `<li><span class="funding-addr">${esc(labelText)}</span>${hiddenAddr}</li>`;
  });
  return `<div class="funding"><h4>Finanzierungskette</h4><ul>${items.join('')}</ul></div>`;
}

function renderThreats(threats) {
  lastThreats = Array.isArray(threats) ? threats : [];
  applyThreatFilter();
}

function applyThreatFilter() {
  const body = document.getElementById('threat-body');
  const empty = document.getElementById('threats-empty');
  const q = (document.getElementById('threat-search').value ?? '').trim().toLowerCase();
  const list = lastThreats
    .filter((t) => t.risk === 'malicious')
    .filter((t) => !q || String(t.address ?? '').toLowerCase().includes(q) || String(t.reason ?? '').toLowerCase().includes(q));

  if (!list.length) {
    body.innerHTML = '';
    empty.hidden = false;
    return;
  }
  empty.hidden = true;

  body.innerHTML = list.map((t) => {
    const addr = String(t.address ?? '');
    const isOpen = expandedAddresses.has(addr);
    const evidenceCount = Array.isArray(t.evidence) ? t.evidence.length : 0;
    const detail = `
      <table class="evidence-table">
        <thead>
          <tr><th scope="col">Tx-Typ</th><th scope="col">Zeit</th><th scope="col">Ref</th><th scope="col">Köder</th></tr>
        </thead>
        <tbody>${evidenceRows(t.evidence)}</tbody>
      </table>
      ${fundingRows(t.funding)}`;
    return `
      <tr class="threat-row${isOpen ? ' open' : ''}" data-addr="${esc(addr)}" tabindex="0" aria-expanded="${isOpen}">
        <td class="addr">${esc(addr)}</td>
        <td>${esc(defang(t.reason ?? '–'))}</td>
        <td>${esc(fmtTime(t.firstSeen))}</td>
        <td>${evidenceCount}</td>
        <td class="col-toggle"><span class="chevron">${isOpen ? '▾' : '▸'}</span></td>
      </tr>
      <tr class="detail-row"${isOpen ? '' : ' hidden'} data-for="${esc(addr)}">
        <td colspan="5">${detail}</td>
      </tr>`;
  }).join('');
}

function toggleRow(row) {
  const addr = row.dataset.addr;
  const detail = document.querySelector(`.detail-row[data-for="${CSS.escape(addr)}"]`);
  if (!detail) return;
  const open = expandedAddresses.has(addr);
  if (open) {
    expandedAddresses.delete(addr);
    detail.hidden = true;
    row.classList.remove('open');
    row.setAttribute('aria-expanded', 'false');
    row.querySelector('.chevron').textContent = '▸';
  } else {
    expandedAddresses.add(addr);
    detail.hidden = false;
    row.classList.add('open');
    row.setAttribute('aria-expanded', 'true');
    row.querySelector('.chevron').textContent = '▾';
  }
}

function bindTable() {
  const body = document.getElementById('threat-body');
  body.addEventListener('click', (e) => {
    const row = e.target.closest('.threat-row');
    if (row) toggleRow(row);
  });
  body.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' || e.key === ' ') {
      const row = e.target.closest('.threat-row');
      if (row) { e.preventDefault(); toggleRow(row); }
    }
  });
}

/* ------------------------------------------------------------------ */
/* Selbst-Check: eigene Adresse gegen die Bedrohungsliste              */
/* ------------------------------------------------------------------ */

async function runSelfCheck(address) {
  const resultBox = document.getElementById('check-result');
  const btn = document.getElementById('check-btn');
  btn.disabled = true;
  btn.textContent = 'Prüfe …';
  resultBox.hidden = false;
  resultBox.className = 'check-result pending';
  resultBox.textContent = 'Transaktionshistorie wird auf dem Ledger geprüft …';
  try {
    const res = await fetch(`/api/check/${encodeURIComponent(address)}`, { cache: 'no-store' });
    const data = await res.json();
    if (!res.ok) {
      resultBox.className = 'check-result error';
      resultBox.textContent = (data && data.error) ? data.error : `Fehler (HTTP ${res.status}).`;
      return;
    }
    renderCheckResult(data);
  } catch (err) {
    resultBox.className = 'check-result error';
    resultBox.textContent = `Check fehlgeschlagen: ${err && err.message}`;
  } finally {
    btn.disabled = false;
    btn.textContent = 'Prüfen';
  }
}

function renderCheckResult(data) {
  const box = document.getElementById('check-result');
  const contacts = Array.isArray(data.contacts) ? data.contacts : [];
  let cls = 'clean';
  let head = '';
  if (data.verdict === 'contact') {
    cls = 'contact';
    head = contacts.length === 1
      ? '1 Kontakt zu einer bekannten Bedrohungs-Adresse gefunden:'
      : `${contacts.length} Kontakte zu bekannten Bedrohungs-Adressen gefunden:`;
  } else if (data.verdict === 'unknown') {
    cls = 'unknown';
    head = data.hint ?? 'Konto nicht gefunden.';
  } else {
    head = `Keine Kontakte zu bekannten maliziösen Adressen (geprüft: ${Number(data.checkedTxCount ?? 0).toLocaleString('de-DE')} Transaktionen${data.truncated ? ', Historie abgeschnitten' : ''}).`;
  }
  const selfNote = data.selfListed
    ? '<p class="check-self">Hinweis: Diese Adresse steht selbst auf der Bedrohungsliste.</p>'
    : '';
  const hint = data.hint && data.verdict !== 'unknown'
    ? `<p class="check-hint">${esc(data.hint)}</p>`
    : '';
  let table = '';
  if (contacts.length) {
    const rows = contacts.map((c) => `
      <tr>
        <td class="tx-type">${esc(c.txType ?? '–')}</td>
        <td>${esc(fmtTime(c.time))}</td>
        <td>${esc(c.direction ?? '–')}</td>
        <td>${esc(c.note ?? '')}</td>
        <td class="addr">${esc(c.counterparty ?? '–')}</td>
        <td><span class="risk-badge ${c.risk === 'malicious' ? 'risk-malicious' : 'risk-suspect'}">${esc(c.risk ?? '–')}</span></td>
      </tr>`).join('');
    table = `
      <table class="evidence-table">
        <thead>
          <tr><th scope="col">Tx-Typ</th><th scope="col">Zeit</th><th scope="col">Richtung</th><th scope="col">Vorgang</th><th scope="col">Gegenpartei</th><th scope="col">Risiko</th></tr>
        </thead>
        <tbody>${rows}</tbody>
      </table>`;
  }
  box.className = `check-result ${cls}`;
  box.innerHTML = `<p class="check-head">${esc(head)}</p>${selfNote}${table}${hint}`;
}

function bindSelfCheck() {
  document.getElementById('check-form').addEventListener('submit', (e) => {
    e.preventDefault();
    const addr = document.getElementById('check-address').value.trim();
    const box = document.getElementById('check-result');
    if (!XRPL_ADDR_RE.test(addr)) {
      box.hidden = false;
      box.className = 'check-result error';
      box.textContent = 'Bitte eine gültige XRPL-Adresse eingeben (beginnt mit „r", 25–35 Zeichen).';
      return;
    }
    runSelfCheck(addr);
  });
}

/* ------------------------------------------------------------------ */
/* Polling                                                             */
/* ------------------------------------------------------------------ */

async function fetchJson(path) {
  const res = await fetch(path, { cache: 'no-store' });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return res.json();
}

async function poll() {
  try {
    const [stats, graph, threats] = await Promise.all([
      fetchJson('/api/stats'),
      fetchJson('/api/graph'),
      fetchJson('/api/threats'),
    ]);
    renderStats(stats);
    renderGraph(graph);
    renderThreats(threats);
    setConnection(true);
    document.getElementById('last-update').textContent =
      'Stand: ' + new Date().toLocaleTimeString('de-DE');
  } catch (err) {
    setConnection(false, err && err.message);
  }
}

document.addEventListener('DOMContentLoaded', () => {
  initGraph();
  bindTable();
  bindSelfCheck();
  document.getElementById('threat-search').addEventListener('input', applyThreatFilter);
  poll();
  setInterval(poll, POLL_MS);
});
