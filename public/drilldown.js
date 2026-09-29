'use strict';

/* Honeypot XRPL – Cluster-Drilldown-Modal (public/drilldown.js)
 *
 * Vollbild-Modal zu einem Cluster: 3D-Visualisierung (3d-force-graph@1.80.0,
 * dynamisch per <script>-Injektion beim ersten Öffnen — das Bundle wird nie
 * eager geladen), graceful Fallback auf 2D vis-network, Rollen-Verteilung,
 * SVG-Zeitachse, Start-bis-Ende-Flusskette und Konten-Tabelle.
 *
 * cluster.id-Zentrierung: das Modal hält die cluster.id und re-looked sie bei
 * jedem Daten-Update gegen den aktuellen Cluster-Graphen (lastClusterGraph
 * wird pro Ledger ersetzt, Cluster sortieren neu) — nie ein stale Listen-
 * index. Verschwindet der Cluster, zeigt das Modal einen eleganten
 * 'Cluster nicht mehr aktuell'-Zustand.
 *
 * GRUNDSATZ: c.id ('cluster:<Adresse>') wird NIE im DOM gerendert — er ist
 * ausschließlich interner Lookup-Schlüssel. Adressen laufen ausschließlich
 * durch die vom Host (app.js) gelieferten Funktionen displayAddr /
 * isFullShownAddr: volle Anzeige nur bei geladener Bait-Hash-Allowlist und
 * Nicht-Treffer auf der Deny-Liste; sonst Kurzform ohne Kopier-Button und
 * ohne xrplcharts-Link. Köder-Adressen und Seeds tauchen in keinem
 * Modal-Artefakt auf.
 */

const FORCE_GRAPH_URL = 'https://unpkg.com/3d-force-graph@1.80.0/dist/3d-force-graph.min.js';

export function initClusterDrilldown(ctx) {
  const esc = ctx.esc;
  const displayAddr = ctx.displayAddr;
  const isFullShownAddr = ctx.isFullShownAddr;
  const isDeniedAddr = ctx.isDeniedAddr;
  const flowPaths = ctx.flowPaths;
  const fmtXrp = ctx.fmtXrp;
  const fmtClock = ctx.fmtClock;
  const roleColors = ctx.roleColors;
  const edgeColors = ctx.edgeColors;
  const edgeDefault = ctx.edgeDefault;
  const roleLabels = ctx.roleLabels;
  const addrActionsHtml = ctx.addrActionsHtml;

  const num = (v) => Number(v ?? 0).toLocaleString('de-DE');
  const cssEscape = (s) => (window.CSS && typeof window.CSS.escape === 'function')
    ? window.CSS.escape(String(s))
    : String(s).replace(/[^a-zA-Z0-9_-]/g, (c) => `\\${c}`);

  let overlay = null;           // .cluster-modal (Shell)
  let surface = null;           // Dialog-Fläche
  let currentClusterId = null;  // cluster.id — nie der Listen-Index
  let isOpen = false;
  let renderToken = 0;          // Guard gegen überlappende async-Render

  // 3d-force-graph: Singleton-Ladezustand (loadPromise + Injektions-Flag)
  let fg3dPromise = null;
  let fg3d = null;              // aktive 3D-Instanz
  let fg3dResizeObs = null;     // ResizeObserver der 3D-Bühne
  let vis2d = null;             // 2D-Ausweich-Instanz
  const highlightSet = new Set();

  function reducedMotion() {
    try { return window.matchMedia('(prefers-reduced-motion: reduce)').matches; }
    catch { return false; }
  }

  // WebGL-Probe VOR der Konstruktion — Konstruktor-Fehler greift denselben
  // Fallback wie ein Fetch-Fehler des Bundles.
  function webglAvailable() {
    try {
      const c = document.createElement('canvas');
      return Boolean(c.getContext('webgl2') || c.getContext('webgl'));
    } catch {
      return false;
    }
  }

  function loadForceGraph3D() {
    if (typeof window.ForceGraph3D === 'function') return Promise.resolve(true);
    if (fg3dPromise) return fg3dPromise;
    fg3dPromise = new Promise((resolve) => {
      const s = document.createElement('script');
      s.src = FORCE_GRAPH_URL;
      s.async = true;
      s.onload = () => resolve(typeof window.ForceGraph3D === 'function');
      s.onerror = () => resolve(false);
      document.head.appendChild(s);
    });
    return fg3dPromise;
  }

  /* ---------------- Shell ---------------- */

  function ensureShell() {
    if (overlay) return;
    overlay = document.createElement('div');
    overlay.className = 'cluster-modal';
    overlay.hidden = true;
    overlay.innerHTML = `
      <div class="cluster-modal-backdrop"></div>
      <div class="cluster-modal-surface" role="dialog" aria-modal="true" aria-labelledby="cluster-modal-title">
        <header class="cluster-modal-head">
          <div class="cluster-modal-title-wrap">
            <span class="cluster-label" id="cluster-modal-title"></span>
            <span class="cluster-modal-badge"></span>
          </div>
          <div class="cluster-modal-metrics"></div>
          <button type="button" class="cluster-modal-close" aria-label="Schließen">&times;</button>
        </header>
        <div class="cluster-modal-body">
          <section class="cluster-modal-graph" aria-label="Cluster-Graph">
            <div class="cluster-3d"></div>
            <p class="graph-note cluster-graph-note" hidden></p>
          </section>
          <aside class="cluster-modal-side" aria-label="Cluster-Details">
            <section class="cluster-modal-roles" aria-label="Rollen-Verteilung"></section>
            <section class="cluster-modal-timeline" aria-label="Zeitachse der Transaktionen"></section>
            <section class="cluster-modal-chain" aria-label="Flusskette Source bis Kollektor"></section>
            <section class="cluster-modal-table" aria-label="Konten des Clusters"></section>
          </aside>
        </div>
      </div>`;
    document.body.appendChild(overlay);
    surface = overlay.querySelector('.cluster-modal-surface');

    overlay.querySelector('.cluster-modal-backdrop').addEventListener('click', close);
    overlay.querySelector('.cluster-modal-close').addEventListener('click', close);
    document.addEventListener('keydown', (e) => {
      if (!isOpen) return;
      if (e.key === 'Escape') { e.preventDefault(); close(); return; }
      if (e.key === 'Tab') trapFocus(e);
    });
    // Hover auf Tabellenzeile -> Knoten im 3D-Graph einfärben.
    surface.addEventListener('mouseover', (e) => {
      const row = e.target.closest('tr[data-addr]');
      if (!row) return;
      highlightSet.add(String(row.dataset.addr));
      if (fg3d) fg3d.nodeColor(nodeColorAccessor());
    });
    surface.addEventListener('mouseout', (e) => {
      const row = e.target.closest('tr[data-addr]');
      if (!row) return;
      highlightSet.delete(String(row.dataset.addr));
      if (fg3d) fg3d.nodeColor(nodeColorAccessor());
    });
  }

  function getFocusables() {
    return [...surface.querySelectorAll('button, a[href], [tabindex="0"]')]
      .filter((el) => !el.hidden && el.offsetParent !== null);
  }

  function trapFocus(e) {
    const focusables = getFocusables();
    if (!focusables.length) return;
    const first = focusables[0];
    const last = focusables[focusables.length - 1];
    if (e.shiftKey && document.activeElement === first) {
      e.preventDefault();
      last.focus();
    } else if (!e.shiftKey && document.activeElement === last) {
      e.preventDefault();
      first.focus();
    }
  }

  /* ---------------- Öffnen / Schließen / Aktualisieren ---------------- */

  function openCluster(clusterId) {
    ensureShell();
    currentClusterId = String(clusterId);
    isOpen = true;
    overlay.hidden = false;
    document.body.classList.add('cluster-modal-open');
    render();
    const closeBtn = overlay.querySelector('.cluster-modal-close');
    if (closeBtn) closeBtn.focus();
  }

  // Wird von app.js nach jedem Cluster-Neubau aufgerufen: das Modal re-looked
  // die cluster.id gegen den aktuellen Graphen — nie ein stale Index.
  function refresh() {
    if (!isOpen) return;
    render();
  }

  function close() {
    if (!isOpen) return;
    const id = currentClusterId;
    isOpen = false;
    currentClusterId = null;
    renderToken += 1;
    overlay.hidden = true;
    document.body.classList.remove('cluster-modal-open');
    highlightSet.clear();
    if (fg3d) { try { fg3d.pauseAnimation(); } catch { /* egal */ } }
    // Fokus-Rückkehr: Karte, deren aktueller Index dieselbe cluster.id trägt,
    // sonst die Cluster-Liste.
    const card = findCardForClusterId(id);
    const target = card || document.getElementById('cluster-list');
    if (target && typeof target.focus === 'function') target.focus();
  }

  function findCardForClusterId(id) {
    const cg = ctx.getClusterGraph();
    const clusters = cg && Array.isArray(cg.clusters) ? cg.clusters : [];
    const idx = clusters.findIndex((c) => c.id === id);
    if (idx < 0) return null;
    return document.querySelector(`#cluster-list .cluster-card[data-cluster-index="${idx}"]`);
  }

  /* ---------------- Rendern ---------------- */

  async function render() {
    const token = ++renderToken;
    const cg = ctx.getClusterGraph();
    const clusters = cg && Array.isArray(cg.clusters) ? cg.clusters : [];
    const allNodes = cg && Array.isArray(cg.nodes) ? cg.nodes : [];
    const allEdges = cg && Array.isArray(cg.edges) ? cg.edges : [];
    const cluster = clusters.find((c) => c.id === currentClusterId);

    const titleEl = overlay.querySelector('#cluster-modal-title');
    const badgeEl = overlay.querySelector('.cluster-modal-badge');
    const metricsEl = overlay.querySelector('.cluster-modal-metrics');
    const rolesEl = overlay.querySelector('.cluster-modal-roles');
    const timelineEl = overlay.querySelector('.cluster-modal-timeline');
    const chainEl = overlay.querySelector('.cluster-modal-chain');
    const tableEl = overlay.querySelector('.cluster-modal-table');
    const graphEl = overlay.querySelector('.cluster-3d');
    const noteEl = overlay.querySelector('.cluster-graph-note');

    if (!cluster) {
      // Cluster ist aus dem aktuellen Beobachtungsfenster gefallen.
      titleEl.textContent = 'Cluster';
      badgeEl.innerHTML = '';
      metricsEl.innerHTML = '';
      rolesEl.innerHTML = '';
      timelineEl.innerHTML = '';
      chainEl.innerHTML = '';
      tableEl.innerHTML = '';
      teardown3D();
      teardown2D();
      graphEl.innerHTML = '<p class="graph-note">Cluster nicht mehr aktuell – dieser Cluster gehört nicht mehr zum aktuellen Beobachtungsfenster.</p>';
      noteEl.hidden = true;
      return;
    }

    // KNOTEN-GATE (Defense-in-Depth, Befund 2026-09-29): isDeniedAddr filtert
    // Köder-Adressen aus der Knotenmenge — sie erreichen weder Tabelle noch
    // Graph; Kanten fallen automatisch mit (beide Enden müssen im sichtbaren
    // Set liegen). Der Host (app.js) filtert bereits vor buildClusterGraph;
    // diese Schicht sichert zusätzlich Graphen ab, die diesen Weg nicht
    // gegangen sind. Fail-closed: ohne isDeniedAddr wird nicht gefiltert
    // (die Anzeige-Maske displayAddr greift dann weiterhin).
    const visibleNodes = (typeof isDeniedAddr === 'function')
      ? allNodes.filter((n) => !isDeniedAddr(String(n.id)))
      : allNodes;
    const clusterNodes = visibleNodes.filter((n) => n.clusterId === cluster.id);
    const nodeIds = new Set(clusterNodes.map((n) => String(n.id)));
    const clusterEdges = allEdges.filter((e) => nodeIds.has(String(e.from)) && nodeIds.has(String(e.to)));

    titleEl.textContent = cluster.label ?? 'Cluster';
    const sev = clusterSeverity(cluster, clusterNodes);
    badgeEl.innerHTML = sev === 'malicious' || sev === 'suspect'
      ? `<span class="risk-badge risk-${esc(sev)}">${sev === 'malicious' ? 'maliziös' : 'verdächtig'}</span>`
      : '';
    metricsEl.innerHTML = `
      <span class="cluster-xrp">${esc(fmtXrp(cluster.totalDrops))} XRP</span>
      <span class="cluster-txs">${num(cluster.txCount)} Tx</span>
      <span class="cluster-accounts">${num(cluster.distinctAccounts)} Konten</span>
      <span class="cluster-times">
        <span>Erste Sichtung: ${esc(fmtClock(cluster.firstSeen))}</span>
        <span>Letzte Sichtung: ${esc(fmtClock(cluster.lastSeen))}</span>
      </span>`;

    renderRoles(cluster, clusterNodes, rolesEl);
    renderTimeline(cluster, clusterEdges, timelineEl);
    renderChain(cluster, clusterNodes, clusterEdges, chainEl);
    renderTable(clusterNodes, tableEl);
    await renderGraph(clusterNodes, clusterEdges, graphEl, noteEl, token);
  }

  function clusterSeverity(cluster, clusterNodes) {
    const rank = { info: 0, suspect: 1, malicious: 2 };
    let sev = 'info';
    for (const n of clusterNodes) {
      const s = String(n.severity ?? 'info');
      if ((rank[s] ?? 0) > (rank[sev] ?? 0)) sev = s;
    }
    return sev;
  }

  /* ---------------- Rollen-Verteilung (Balken) ---------------- */

  function renderRoles(cluster, clusterNodes, el) {
    const counts = new Map();
    for (const n of clusterNodes) {
      const r = roleLabels[n.role] ? n.role : 'unknown';
      counts.set(r, (counts.get(r) ?? 0) + 1);
    }
    const total = clusterNodes.length || 1;
    const rows = ['source', 'drainer', 'collector', 'relay', 'unknown']
      .filter((r) => counts.get(r))
      .map((r) => {
        const count = counts.get(r);
        const pct = Math.round((count / total) * 100);
        return `
          <div class="role-bar-row">
            <span class="role-bar-label"><span class="swatch swatch-${esc(r)}"></span>${esc(roleLabels[r] ?? r)}</span>
            <span class="role-bar-track" role="img" aria-label="${esc(roleLabels[r] ?? r)}: ${count} von ${clusterNodes.length} Konten (${pct} %)">
              <span class="role-bar-fill role-bar-${esc(r)}" style="width:${pct}%"></span>
            </span>
            <span class="role-bar-count">${num(count)}</span>
          </div>`;
      }).join('');
    el.innerHTML = `<h3 class="cluster-modal-h">Rollen-Verteilung</h3>
      <div class="role-bars">${rows}</div>
      <p class="graph-note">Rollen (Source, Drainer, Kollektor, Relay) sind Heuristiken aus Ein-/Ausgrad und Geldfluss – kein Schuldnachweis.</p>`;
  }

  /* ---------------- Zeitachse (SVG, epoch-basiert) ---------------- */

  function renderTimeline(cluster, clusterEdges, el) {
    const points = [];
    for (const e of clusterEdges) {
      const ep = Date.parse(String(e.closeTime ?? ''));
      if (Number.isFinite(ep)) points.push({ ep, type: String(e.type ?? '') });
    }
    if (!points.length) {
      el.innerHTML = '<h3 class="cluster-modal-h">Zeitachse der Transaktionen</h3>'
        + '<p class="graph-note">Keine Zeitstempel im aktuellen Beobachtungsfenster.</p>';
      return;
    }
    let min = points[0].ep;
    let max = points[0].ep;
    for (const p of points) {
      if (p.ep < min) min = p.ep;
      if (p.ep > max) max = p.ep;
    }
    const span = max - min || 1;
    // Kreisrunde Zeitachse OHNE viewBox/preserveAspectRatio='none' (Befund
    // 2026-09-29): Nicht-uniforme Streckung des viewBox 0 0 300 46 auf ~500 px
    // Spaltenbreite renderte die r=3-Kreise als Ellipsen (~10x6 px). Stattdessen
    // feste Benutzer-Einheiten (CSS-px) mit Prozent-Koordinaten für die
    // Position: Kreise bleiben Kreise, die Achse füllt trotzdem die volle
    // Breite der Seitenspalte.
    const H = 46;
    const CY = H / 2;
    const PAD_PCT = 4;
    const xOf = (ep) => (PAD_PCT + ((ep - min) / span) * (100 - 2 * PAD_PCT)).toFixed(2);
    const dots = points.map((p) =>
      `<circle cx="${xOf(p.ep)}%" cy="${CY}" r="3" fill="${esc(edgeColors[p.type] || edgeDefault)}" opacity="0.85"></circle>`
    ).join('');
    const minIso = new Date(min).toISOString();
    const maxIso = new Date(max).toISOString();
    el.innerHTML = `<h3 class="cluster-modal-h">Zeitachse der Transaktionen</h3>
      <svg class="cluster-timeline" role="img"
           aria-label="Zeitachse von ${esc(fmtClock(minIso))} bis ${esc(fmtClock(maxIso))} – ${points.length} Transaktionen">
        <line class="timeline-axis" x1="${PAD_PCT}%" y1="${CY}" x2="${100 - PAD_PCT}%" y2="${CY}"></line>
        ${dots}
      </svg>
      <div class="cluster-timeline-labels">
        <span>Erste Sichtung: ${esc(fmtClock(cluster.firstSeen ?? minIso))}</span>
        <span>Letzte Sichtung: ${esc(fmtClock(cluster.lastSeen ?? maxIso))}</span>
      </div>`;
  }

  /* ---------------- Flusskette: echte Kantenpfade Start → … → Kollektor ---------------- */

  function renderChain(cluster, clusterNodes, clusterEdges, el) {
    const chip = (x) => {
      const address = String(x?.id ?? '');
      const shown = displayAddr(address);
      const actions = isFullShownAddr(address) ? addrActionsHtml(address) : '';
      return `<span class="chain-node chain-${esc(x?.role ?? 'unknown')}">${esc(shown)}${actions}</span>`;
    };
    // Pfade NUR aus echten Kanten des Clusters (flowPaths, lib/cluster.mjs):
    // '→' verbindet ausschließlich Adressen entlang belegter Transaktionen —
    // rollenweise aneinandergereihte Chips implizierten Flüsse, die es im
    // Beobachtungsfenster nicht gibt (Befund 2026-09-29).
    const traceFn = typeof flowPaths === 'function' ? flowPaths() : null;
    const paths = traceFn
      ? traceFn(
          clusterNodes.map((n) => ({ id: String(n.id), role: n.role })),
          clusterEdges.map((e) => ({ from: String(e.from), to: String(e.to) })),
          { maxPaths: 3, maxPathLen: 6 },
        ).filter((p) => Array.isArray(p) && p.length >= 2)
      : [];
    if (paths.length) {
      const rows = paths
        .map((p) => p.map(chip).join('<span class="chain-arrow" aria-hidden="true">→</span>'))
        .join('<span class="chain-path-sep" aria-hidden="true">·</span>');
      el.innerHTML = `<h3 class="cluster-modal-h">Flusskette</h3>
        <div class="cluster-chain" aria-label="Geldfluss: Start bis Kollektor entlang echter Kanten">${rows}</div>
        <p class="graph-note">Pfade folgen nur Transaktionen des Beobachtungsfensters – keine vollständige Wallet-Historie, kein Schuldnachweis.</p>`;
      return;
    }
    // Fallback (keine Kante im Fenster bzw. flowPaths offline): Rollen-Chips
    // OHNE '→' — die Trennung ist ein '·', damit keine Transaktion impliziert
    // wird, die nicht belegt ist.
    const entries = [];
    for (const role of ['source', 'drainer', 'relay', 'collector']) {
      const list = clusterNodes.filter((n) => n.role === role);
      if (role === 'drainer') list.sort((a, b) => (b.outDrops ?? 0) - (a.outDrops ?? 0) || String(a.id).localeCompare(String(b.id)));
      if (role === 'collector') list.sort((a, b) => (b.inDrops ?? 0) - (a.inDrops ?? 0) || String(a.id).localeCompare(String(b.id)));
      for (const n of list) entries.push({ address: String(n.id), role });
    }
    if (!entries.length) {
      el.innerHTML = '<h3 class="cluster-modal-h">Flusskette</h3>'
        + '<p class="graph-note">Keine Rollen-Kette im aktuellen Beobachtungsfenster.</p>';
      return;
    }
    const chips = entries.map((x) => chip({ id: x.address, role: x.role })).join('<span class="chain-path-sep" aria-hidden="true">·</span>');
    el.innerHTML = `<h3 class="cluster-modal-h">Flusskette</h3>
      <div class="cluster-chain" aria-label="Konten des Clusters nach Rolle – keine Kanten im Beobachtungsfenster">${chips}</div>`;
  }

  /* ---------------- Konten-Tabelle ---------------- */

  function renderTable(clusterNodes, el) {
    const rows = [...clusterNodes]
      .sort((a, b) =>
        ((b.inDrops ?? 0) + (b.outDrops ?? 0)) - ((a.inDrops ?? 0) + (a.outDrops ?? 0))
        || String(a.id).localeCompare(String(b.id)))
      .map((n) => {
        const id = String(n.id);
        const full = isFullShownAddr(id);
        const shown = displayAddr(id);
        const sev = String(n.severity ?? 'info');
        const badge = sev === 'malicious' || sev === 'suspect'
          ? `<span class="risk-badge risk-${esc(sev)}">${sev === 'malicious' ? 'maliziös' : 'verdächtig'}</span>`
          : '<span class="cluster-table-dash">–</span>';
        const actions = full ? addrActionsHtml(id) : '<span class="cluster-table-dash">–</span>';
        const role = roleLabels[n.role] ? n.role : 'unknown';
        // data-addr trägt NUR den Anzeigewert (volle Adresse ausschließlich
        // bei erlaubter Vollanzeige, sonst Kurzform) — die ROHE Knoten-Id
        // darf nie als DOM-Attribut landen (Befund 2026-09-29). Hover-
        // Highlight und Klick-Scroll vergleichen deshalb gegen
        // displayAddr(n.id), nicht gegen die rohe Id.
        return `<tr data-addr="${esc(full ? id : shown)}">
          <td class="cluster-td-addr">${esc(shown)}</td>
          <td><span class="role-chip role-${esc(role)}"><span class="swatch swatch-${esc(role)}"></span>${esc(roleLabels[role] ?? role)}</span></td>
          <td>${badge}</td>
          <td class="cluster-td-num">${esc(fmtXrp(n.inDrops))}</td>
          <td class="cluster-td-num">${esc(fmtXrp(n.outDrops))}</td>
          <td class="cluster-td-num">${num(n.degreeIn)} / ${num(n.degreeOut)}</td>
          <td>${actions}</td>
        </tr>`;
      }).join('');
    el.innerHTML = `<h3 class="cluster-modal-h">Konten des Clusters</h3>
      <div class="cluster-table-wrap" tabindex="0" role="region" aria-label="Konten-Tabelle, horizontal scrollbar">
        <table class="cluster-table">
          <caption>${num(clusterNodes.length)} Konten – Rollen sind Heuristiken, kein Schuldnachweis</caption>
          <thead>
            <tr>
              <th scope="col">Adresse</th>
              <th scope="col">Rolle</th>
              <th scope="col">Schweregrad</th>
              <th scope="col">Eingehende Drops</th>
              <th scope="col">Ausgehende Drops</th>
              <th scope="col">Kanten (in / aus)</th>
              <th scope="col">Aktionen</th>
            </tr>
          </thead>
          <tbody>${rows}</tbody>
        </table>
      </div>`;
  }

  /* ---------------- Graph: 3D mit 2D-Ausweichansicht ---------------- */

  async function renderGraph(clusterNodes, clusterEdges, graphEl, noteEl, token) {
    noteEl.hidden = true;
    if (typeof window.ForceGraph3D !== 'function') {
      graphEl.innerHTML = '<p class="graph-note">3D-Ansicht wird geladen …</p>';
    }
    const ok3d = await loadForceGraph3D();
    if (token !== renderToken || !isOpen) return; // zwischenzeitlich neu gerendert/geschlossen

    if (ok3d && webglAvailable()) {
      try {
        build3D(clusterNodes, clusterEdges, graphEl);
        return;
      } catch {
        // Konstruktor-Fehler -> Fallback unten
      }
    }
    teardown3D();
    if (typeof window.vis !== 'undefined') {
      try {
        build2D(clusterNodes, clusterEdges, graphEl);
        noteEl.textContent = '3D-Ansicht nicht verfügbar – 2D-Ausweichansicht (vis-network).';
        noteEl.hidden = false;
        return;
      } catch {
        // vis-Fehler -> statischer Zustand unten
      }
    }
    teardown2D();
    graphEl.innerHTML = '<p class="graph-note">Kein Graph verfügbar – Detaildaten in Rollen-Verteilung, Flusskette und Konten-Tabelle.</p>';
  }

  function nodeColorAccessor() {
    return (n) => {
      const role = roleColors[n.role] ? n.role : 'unknown';
      const base = roleColors[role];
      // Vergleich über den Anzeigewert: tr[data-addr] trägt nicht mehr die
      // rohe Knoten-Id (Befund 2026-09-29), sondern displayAddr(id).
      if (highlightSet.has(displayAddr(String(n.id)))) return base.highlight.background;
      return base.background;
    };
  }

  function build3D(clusterNodes, clusterEdges, graphEl) {
    teardown2D();
    const data = {
      nodes: clusterNodes.map((n) => ({
        id: String(n.id),
        role: roleColors[n.role] ? n.role : 'unknown',
        inDrops: n.inDrops ?? 0,
        outDrops: n.outDrops ?? 0,
      })),
      links: clusterEdges.map((e) => ({
        source: String(e.from),
        target: String(e.to),
        type: String(e.type ?? ''),
      })),
    };
    if (!fg3d) {
      graphEl.innerHTML = '';
      fg3d = window.ForceGraph3D()(graphEl);
      // Containergröße statt Fenstergröße (Befund 2026-09-29): das Bundle
      // initialisiert width/height mit window.innerWidth/innerHeight — auf
      // der .cluster-3d-Bühne (520 px, overflow:hidden) wurde das Canvas
      // dadurch fensterbreit gerendert und abgeschnitten. Größe explizit auf
      // den Container setzen und per ResizeObserver nachführen (Fenster-
      // Resize, responsive Höhenstufen der Bühne).
      const sizeToContainer = () => {
        if (!fg3d) return;
        const w = Math.max(1, Math.floor(graphEl.clientWidth));
        const h = Math.max(1, Math.floor(graphEl.clientHeight));
        try { fg3d.width(w).height(h); } catch { /* egal */ }
      };
      sizeToContainer();
      if (typeof ResizeObserver === 'function') {
        fg3dResizeObs = new ResizeObserver(sizeToContainer);
        fg3dResizeObs.observe(graphEl);
      }
      fg3d
        .backgroundColor('#ffffff')
        .nodeLabel((n) => esc(displayAddr(n.id)))
        .linkLabel((l) => {
          const from = l.source && typeof l.source === 'object' ? l.source.id : l.source;
          const to = l.target && typeof l.target === 'object' ? l.target.id : l.target;
          return `${esc(displayAddr(from))} → ${esc(displayAddr(to))} (${esc(String(l.type ?? ''))})`;
        })
        .linkWidth(1)
        .linkDirectionalArrowLength(3)
        .onNodeClick((node) => on3dNodeClick(node));
    }
    fg3d
      .graphData(data)
      .nodeColor(nodeColorAccessor())
      .nodeVal((n) => 1 + ((n.inDrops ?? 0) + (n.outDrops ?? 0)) / 1e6)
      .linkColor((l) => edgeColors[String(l.type)] || edgeDefault)
      .linkDirectionalParticles((l) => (String(l.type) === 'Payment' && !reducedMotion() ? 2 : 0))
      .linkDirectionalParticleWidth(2);
    if (reducedMotion()) {
      // Reduced Motion (Befund 2026-09-29): Kraft-Simulation einfrieren —
      // Pendant zum 2D-Fallback, der die Physik per cooldownTicks 0 stoppt.
      // Knoten driften nicht weiter; Kamera-Interaktion bleibt erhalten.
      try { fg3d.cooldownTicks(0); } catch { /* egal */ }
      // Statische Bildfassung ohne Animation (Dauer 0 statt 400 ms).
      setTimeout(() => { try { fg3d.zoomToFit(0); } catch { /* egal */ } }, 350);
    } else {
      setTimeout(() => { try { fg3d.zoomToFit(400); } catch { /* egal */ } }, 350);
    }
  }

  function on3dNodeClick(node) {
    const id = String(node.id ?? '');
    // Zeilen-Lookup über den Anzeigewert: tr[data-addr] trägt nicht mehr die
    // rohe Knoten-Id, sondern displayAddr(id) (Befund 2026-09-29).
    const row = surface.querySelector(`tr[data-addr="${cssEscape(displayAddr(id))}"]`);
    if (row) row.scrollIntoView({ block: 'center', behavior: reducedMotion() ? 'auto' : 'smooth' });
    if (!reducedMotion()) {
      try {
        const d = 220;
        fg3d.cameraPosition(
          { x: node.x + d * 0.5, y: node.y + d * 0.4, z: node.z + d },
          { x: node.x, y: node.y, z: node.z },
          500
        );
      } catch { /* egal */ }
    }
  }

  function build2D(clusterNodes, clusterEdges, graphEl) {
    teardown3D();
    graphEl.innerHTML = '';
    const vNodes = new window.vis.DataSet(clusterNodes.map((n) => {
      const role = roleColors[n.role] ? n.role : 'unknown';
      return {
        id: String(n.id),
        label: displayAddr(n.id),
        title: `${displayAddr(n.id)} (${roleLabels[role] ?? role})`,
        shape: 'dot',
        size: 14,
        color: roleColors[role],
      };
    }));
    const vEdges = new window.vis.DataSet(clusterEdges.map((e) => ({
      id: String(e.txHash || `${e.from}->${e.to}::${e.type}`),
      from: String(e.from),
      to: String(e.to),
      label: String(e.type ?? ''),
      title: `${displayAddr(e.from)} → ${displayAddr(e.to)} (${String(e.type ?? '')})`,
      color: { color: edgeColors[String(e.type)] || edgeDefault, highlight: '#141416', hover: '#141416' },
      arrows: { to: { enabled: true, scaleFactor: 0.5 } },
      width: 1,
    })));
    vis2d = new window.vis.Network(graphEl, { nodes: vNodes, edges: vEdges }, {
      autoResize: true,
      physics: ctx.physicsCluster,
      interaction: { hover: true, tooltipDelay: 120, zoomView: true, dragView: true },
      nodes: {
        borderWidth: 1,
        font: { color: '#141416', size: 12, face: '"JetBrains Mono", ui-monospace, Consolas, monospace' },
      },
      edges: {
        smooth: { type: 'curvedCW', roundness: 0.14 },
        font: { color: '#484850', size: 10, face: '"JetBrains Mono", ui-monospace, Consolas, monospace', strokeWidth: 0, align: 'middle' },
      },
    });
    if (reducedMotion()) {
      // Reduced Motion: Physik nach Stabilisierung einfrieren (cooldownTicks 0).
      try {
        vis2d.once('stabilizationIterationsDone', () => {
          vis2d.setOptions({ physics: { enabled: false, cooldownTicks: 0 } });
        });
      } catch { /* egal */ }
    }
  }

  function teardown3D() {
    if (fg3dResizeObs) {
      try { fg3dResizeObs.disconnect(); } catch { /* egal */ }
      fg3dResizeObs = null;
    }
    if (!fg3d) return;
    try { fg3d.pauseAnimation(); } catch { /* egal */ }
    fg3d = null;
  }

  function teardown2D() {
    if (!vis2d) return;
    try { vis2d.destroy(); } catch { /* egal */ }
    vis2d = null;
  }

  return { openCluster, refresh };
}
