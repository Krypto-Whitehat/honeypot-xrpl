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
 * index. Die id ist instabil (sie wandert mit dem alphabetisch kleinsten
 * Mitglied, lib/cluster.mjs): Fehlt sie im aktuellen Graphen, zeigt das Modal
 * den LETZTEN bekannten Stand mit Alterungshinweis weiter ('Stand HH:MM:SS –
 * Cluster nicht mehr im aktuellen Beobachtungsfenster'); ein Fallback-Lookup
 * über die Mitglieder-Schnittmenge (≥2 gemeinsame Mitglieder UND ≥50 %,
 * jeweils gegen die Mitglieder des ORIGINÄR geöffneten Clusters als Anker)
 * übernimmt denselben Cluster nahtlos unter neuer id und meldet die Übernahme
 * mit einem Hinweis. Der Anker verhindert transitives Wandern: Nur der
 * ursprünglich geöffnete Cluster (oder ein Nachfolger mit ausreichend
 * Ursprungs-Überlappung) kann übernommen werden — schrittweises Hüpfen über
 * Zwischen-Snapshots hinaus ist ausgeschlossen (Befund 2026-09-30).
 * Total-Leerung nur bei openCluster auf einen bereits verschwundenen Cluster,
 * nach Snapshot-Kappe oder — immer vorrangig — bei Köder-Treffer in der
 * Deny-Reprüfung je refresh-Tick.
 *
 * GRUNDSATZ: c.id ('cluster:<Adresse>') wird NIE im DOM gerendert — er ist
 * ausschließlich interner Lookup-Schlüssel. Adressen laufen ausschließlich
 * durch die vom Host (app.js) gelieferten Funktionen displayAddr /
 * isFullShownAddr: volle Anzeige nur bei geladener Bait-Hash-Allowlist und
 * Nicht-Treffer auf der Deny-Liste; sonst Kurzform ohne Kopier-Button und
 * ohne xrplcharts-Link. Köder-Adressen und Seeds tauchen in keinem
 * Modal-Artefakt auf.
 */

import { t, fmtNum, sevText } from './i18n.mjs';

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
  // 2D-Canvas-Label in Kurzform (Design-Fix): shortAddr kommt bereits im ctx
  // des Hosts (app.js); Fallback displayAddr, falls ein Host es nicht liefert.
  const shortAddrFn = (typeof ctx.shortAddr === 'function') ? ctx.shortAddr : ctx.displayAddr;

  const num = (v) => fmtNum(v);
  // Rollen-Beschriftung übersetzt über die Legenden-Keys (EN: Collector,
  // DE: Kollektor); ctx.roleLabels bleibt Fallback für unbekannte Rollen.
  const roleLabelText = (role) => {
    const viaI18n = t('legend.' + role);
    if (viaI18n !== 'legend.' + role) return viaI18n;
    return ctx.roleLabels && ctx.roleLabels[role] ? ctx.roleLabels[role] : role;
  };
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

  /* Modal-Lebenszyklus (Symptom 3, Diagnose 2026-09-30): cluster.id ist
   * instabil — sie wird aus dem alphabetisch kleinsten Mitglied gebildet
   * (lib/cluster.mjs) und wechselt, sobald dieser ID-Träger aus dem rollenden
   * Fenster rollt, obwohl der Cluster unter neuer id weiterlebt. Fehlt die id
   * im aktuellen Graphen, zeigt render() deshalb den LETZTEN bekannten Stand
   * mit Alterungshinweis weiter (statt sofort total zu leeren); ein Fallback-
   * Lookup über die Mitglieder-Schnittmenge nimmt den Cluster unter neuer id
   * nahtlos auf. */
  const STALE_SNAPSHOT_MAX_MS = 300000; // Kappe des eingefrorenen Standes
                                        // (Akzeptanz fordert ≥60 s Lesbarkeit;
                                        // der Köder-Recheck läuft je refresh-
                                        // Tick unabhängig davon zusätzlich)
  let snapshot = null;          // letzter voll gerenderter Stand:
                                // {clusterId, at, members[]}
  let staleShown = false;       // Alterungshinweis aktuell sichtbar?
  let lastRenderDigest = null;  // Änderungs-Gate: unveränderte Inhalte → kein Vollrender
  let graphClusterId = null;    // Cluster-id des 3D-Graphen — zoomToFit nur bei
                                // Cluster-Wechsel/Erstrender (Kamera bleibt
                                // bei reinen Inhalts-Updates erhalten)
  let originMembers = null;     // Fallback-ANKER (Befund 2026-09-30): Mitglieder
                                // des originär geöffneten Clusters, eingefroren
                                // bei der ersten erfolgreichen Renderung nach
                                // openCluster — bleibt stabil, damit der
                                // Fallback-Lookup nicht transitiv wandern kann
  let takeoverNoticeTimer = 0;  // Auto-Ausblendung des Übernahme-Hinweises

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
          <button type="button" class="cluster-modal-close" aria-label="${esc(t('modal.closeAria'))}">&times;</button>
        </header>
        <p class="graph-note cluster-modal-stale" role="status" hidden
           style="margin:0;padding:10px 18px;border-bottom:1px solid var(--a6-line);background:var(--a6-surface-alt);"></p>
        <div class="cluster-modal-body">
          <section class="cluster-modal-graph" aria-label="${esc(t('modal.graphAria'))}">
            <div class="cluster-3d"></div>
            <p class="graph-note cluster-graph-note" hidden></p>
          </section>
          <aside class="cluster-modal-side" aria-label="${esc(t('modal.detailsAria'))}">
            <section class="cluster-modal-roles" aria-label="${esc(t('modal.rolesAria'))}"></section>
            <section class="cluster-modal-timeline" aria-label="${esc(t('modal.timelineAria'))}"></section>
            <section class="cluster-modal-chain" aria-label="${esc(t('modal.chainAria'))}"></section>
            <section class="cluster-modal-table" aria-label="${esc(t('modal.tableAria'))}"></section>
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
    // openCluster beginnt IMMER bei null Stand: Ein überalterter Snapshot eines
    // früher geöffneten Clusters wird verworfen — klickt der Nutzer auf einen
    // inzwischen verschwundenen Cluster (stale Karte/Bubble), zeigt das Modal
    // die ehrliche Total-Leerung statt eines fremden Letztstandes.
    snapshot = null;
    staleShown = false;
    originMembers = null; // Fallback-ANKER neu einfrieren (Befund 2026-09-30)
    clearTakeoverNotice();
    const staleNote = overlay.querySelector('.cluster-modal-stale');
    if (staleNote) staleNote.hidden = true;
    lastRenderDigest = null; // Vollrender erzwingen (Modul-eigenes Änderungs-Gate)
    graphClusterId = null;   // zoomToFit/Camera-Reset als Erstrender zulassen
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
    originMembers = null; // Anker verfällt mit dem Modal (neues Öffnen friert neu)
    clearTakeoverNotice();
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

  // Fallback-Lookup mit GEKOPPELTER Schwelle, verankert am ORIGINÄR geöffneten
  // Cluster (Befund 2026-09-30): Die neue cluster.id wird nur übernommen, wenn
  // ≥2 gemeinsame Mitglieder mit dem ANKER (nicht dem jeweils letzten
  // Snapshot) UND eine Schnittmenge von ≥50 % (bezogen auf die kleinere der
  // beiden Mitgliederzahlen) vorliegen. Eine reine 50-%-Schwelle matcht bei
  // 2er-Clustern jeden Cluster mit nur EINEM gemeinsamen Mitglied — genau das
  // koppelt die zweite Bedingung ab. Das Matching gegen den Vorgänger-Snapshot
  // ließ das Modal dagegen transitiv wandern (jeder Hopp verschob den
  // Maßstab mit); der Anker bleibt über die Lebensdauer des geöffneten Modals
  // stabil, sodass nur Nachfolger des ORIGINÄLLEN Clusters übernommen werden
  // können — ein Cluster ohne gemeinsame Ursprungs-Mitglieder wird abgelehnt.
  function findFallbackCluster(clusters) {
    if (!originMembers || originMembers.size < 2) return null;
    let best = null;
    let bestInter = 0;
    for (const c of clusters) {
      const members = Array.isArray(c.memberAddresses) ? c.memberAddresses : [];
      let inter = 0;
      for (const m of members) {
        if (originMembers.has(String(m))) inter += 1;
      }
      if (inter < 2) continue; // Bedingung 1: ≥2 gemeinsame Mitglieder mit dem Anker
      const denom = Math.min(originMembers.size, members.length);
      if (denom > 0 && inter / denom < 0.5) continue; // Bedingung 2: ≥50 %
      if (inter > bestInter) { best = c; bestInter = inter; }
    }
    return best;
  }

  // Übernahme-Hinweis (Befund 2026-09-30): Der verankerte Fallback-Lookup hat
  // denselben Cluster unter neuer id aufgenommen — der Titel wechselt mit,
  // deshalb wird die Übernahme ehrlich gemeldet statt still vollzogen. Der
  // Hinweis blendet sich nach kurzer Zeit selbst aus; ein aktiver
  // Alterungshinweis bleibt unangetastet (dieser ist vorrangig).
  function clearTakeoverNotice() {
    if (takeoverNoticeTimer) { clearTimeout(takeoverNoticeTimer); takeoverNoticeTimer = 0; }
  }

  function showTakeoverNotice() {
    const note = overlay && overlay.querySelector('.cluster-modal-stale');
    if (note) {
      note.textContent = t('modal.takeover');
      note.hidden = false;
    }
    clearTakeoverNotice();
    takeoverNoticeTimer = setTimeout(() => {
      takeoverNoticeTimer = 0;
      if (staleShown) return; // Alterungshinweis ist aktiv und bleibt stehen
      const n = overlay && overlay.querySelector('.cluster-modal-stale');
      if (n) n.hidden = true;
    }, 10000);
  }

  // Änderungs-Gate INHALTLICH (im Modul, nicht im Aufrufer): Vergleicht id,
  // Metriken, Mitglieder (inkl. Rollen/Drops/Schweregrad/Grade) und Kanten des
  // ANGEZEIGTEN Clusters gegen den zuletzt gerenderten Stand. app.js bleibt der
  // einfache Aufrufer (drilldown.refresh()), denn nur das Modul kennt seinen
  // gerenderten Stand — sonst bliebe das ~4-s-Vollrender des offenen Modals bei
  // Änderung IRGENDeines Clusters bestehen.
  function clusterDigest(cluster, clusterNodes, clusterEdges) {
    const nodes = clusterNodes
      .map((n) => `${n.id}:${n.role ?? ''}:${n.inDrops ?? 0}:${n.outDrops ?? 0}:${n.degreeIn ?? 0}:${n.degreeOut ?? 0}:${n.severity ?? ''}`)
      .sort()
      .join('|');
    const edges = clusterEdges
      .map((e) => `${e.from}>${e.to}:${e.type ?? ''}:${e.txHash ?? ''}:${e.closeTime ?? ''}`)
      .sort()
      .join('|');
    return `${cluster.id}#${cluster.label ?? ''}#${cluster.totalDrops ?? 0}#${cluster.txCount ?? 0}`
      + `#${cluster.distinctAccounts ?? 0}#${cluster.firstSeen ?? ''}#${cluster.lastSeen ?? ''}#${nodes}#${edges}`;
  }

  // Alterungszustand lösen (Cluster wieder da): Hinweis verbergen, Graph fortsetzen.
  function endStaleState() {
    if (!staleShown) return;
    staleShown = false;
    const note = overlay.querySelector('.cluster-modal-stale');
    if (note) note.hidden = true;
    if (fg3d) { try { fg3d.resumeAnimation(); } catch { /* egal */ } }
  }

  // Ehrliche Total-Leerung (früher das Standardverhalten bei fehlender id):
  // nur noch bei openCluster auf bereits verschwundenen Cluster, nach Ablauf
  // der Snapshot-Kappe oder — vor allen anderen Gründen — bei Köder-Treffer.
  function clearToEmptyState(els) {
    snapshot = null;
    staleShown = false;
    clearTakeoverNotice(); // Übernahme-Hinweis hat seinen Cluster verloren
    const note = overlay.querySelector('.cluster-modal-stale');
    if (note) note.hidden = true;
    els.titleEl.textContent = t('cluster.labelDefault');
    els.badgeEl.innerHTML = '';
    els.metricsEl.innerHTML = '';
    els.rolesEl.innerHTML = '';
    els.timelineEl.innerHTML = '';
    els.chainEl.innerHTML = '';
    els.tableEl.innerHTML = '';
    teardown3D();
    teardown2D();
    els.graphEl.innerHTML = `<p class="graph-note">${esc(t('modal.gone'))}</p>`;
    els.noteEl.hidden = true;
  }

  // cluster.id fehlt im aktuellen Graphen: LETZTEN bekannten Stand weiterzeigen
  // (Titel/Badge/Metriken/Rollen/Zeitachse/Kette/Tabelle bleiben im DOM, Graph
  // pausiert) plus Alterungshinweis mit Stand-Zeitpunkt.
  function renderMissingCluster(els) {
    // KÖDER-SCHUTZ SCHLÄGT ALTERUNGSANZEIGE IN JEDEM FALL: Die Deny-Liste
    // rotiert serverseitig alle 5 s, rebuildDisplayAndKnownBad bewertet bei
    // jedem Load neu — der eingefrorene Snapshot darf diese Fail-closed-
    // Neubewertung nie umgehen. Deshalb bei JEDEM refresh-Tick die Member-
    // Hashes gegen die AKTUELLE baitHashDeny prüfen (isDeniedAddr synchron
    // über den geprimten addrHashCache) und bei Treffer sofort leeren.
    if (snapshot && typeof isDeniedAddr === 'function') {
      for (const m of snapshot.members) {
        if (isDeniedAddr(m)) {
          clearToEmptyState(els);
          return;
        }
      }
    }
    if (!snapshot || Date.now() - snapshot.at > STALE_SNAPSHOT_MAX_MS) {
      clearToEmptyState(els);
      return;
    }
    if (!staleShown) {
      staleShown = true;
      const note = overlay.querySelector('.cluster-modal-stale');
      if (note) {
        note.textContent = t('modal.stale', { time: fmtClock(snapshot.at) });
        note.hidden = false;
      }
      if (fg3d) { try { fg3d.pauseAnimation(); } catch { /* egal */ } }
    }
  }

  async function render() {
    const token = ++renderToken;
    const cg = ctx.getClusterGraph();
    const clusters = cg && Array.isArray(cg.clusters) ? cg.clusters : [];
    const allNodes = cg && Array.isArray(cg.nodes) ? cg.nodes : [];
    const allEdges = cg && Array.isArray(cg.edges) ? cg.edges : [];

    const titleEl = overlay.querySelector('#cluster-modal-title');
    const badgeEl = overlay.querySelector('.cluster-modal-badge');
    const metricsEl = overlay.querySelector('.cluster-modal-metrics');
    const rolesEl = overlay.querySelector('.cluster-modal-roles');
    const timelineEl = overlay.querySelector('.cluster-modal-timeline');
    const chainEl = overlay.querySelector('.cluster-modal-chain');
    const tableEl = overlay.querySelector('.cluster-modal-table');
    const graphEl = overlay.querySelector('.cluster-3d');
    const noteEl = overlay.querySelector('.cluster-graph-note');
    const els = { titleEl, badgeEl, metricsEl, rolesEl, timelineEl, chainEl, tableEl, graphEl, noteEl };

    // Exakter Lookup über die cluster.id; bei Verfehlen (ID-Träger aus dem
    // rollenden Fenster gerollt) Fallback über die Mitglieder-Schnittmenge
    // gegen den ORIGIN-ANKER (Befund 2026-09-30).
    let cluster = clusters.find((c) => c.id === currentClusterId);
    if (!cluster) cluster = findFallbackCluster(clusters);

    if (!cluster) {
      renderMissingCluster(els);
      return;
    }
    let takeoverPending = false;
    if (cluster.id !== currentClusterId) {
      // Nahtlose Übernahme: derselbe Cluster lebt unter neuer id weiter — der
      // exakte Lookup kann keine fremde id liefern, jede Abweichung stammt
      // aus dem verankerten Fallback. Hinweis folgt nach dem Vollrender.
      currentClusterId = cluster.id;
      takeoverPending = true;
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
    // Fallback-ANKER einfrieren (Befund 2026-09-30): Mitglieder des originär
    // geöffneten Clusters bei der ERSTEN erfolgreichen Renderung nach
    // openCluster. Erst wenn der exakte Lookup diesen Stand bestätigt hat,
    // darf der Fallback später gegen ihn matchen — so ist der Anker stets der
    // vom Nutzer geöffnete Cluster, nicht ein Zwischen-Snapshot.
    if (!originMembers) originMembers = new Set(nodeIds);
    const clusterEdges = allEdges.filter((e) => nodeIds.has(String(e.from)) && nodeIds.has(String(e.to)));

    // Änderungs-Gate: identischer Inhalt wie beim letzten Vollrender → nur
    // einen eventuellen Alterungszustand lösen und zurück (kein Re-Render,
    // kein graphData-Austausch, kein zoomToFit).
    const digest = clusterDigest(cluster, clusterNodes, clusterEdges);
    if (digest === lastRenderDigest) {
      endStaleState();
      return;
    }
    lastRenderDigest = digest;

    titleEl.textContent = cluster.label ?? t('cluster.labelDefault');
    const sev = clusterSeverity(cluster, clusterNodes);
    badgeEl.innerHTML = sev === 'malicious' || sev === 'suspect'
      ? `<span class="risk-badge risk-${esc(sev)}">${esc(sevText(sev))}</span>`
      : '';
    metricsEl.innerHTML = `
      <span class="cluster-xrp">${esc(fmtXrp(cluster.totalDrops))} XRP</span>
      <span class="cluster-txs">${num(cluster.txCount)} ${esc(t('cluster.txUnit'))}</span>
      <span class="cluster-accounts">${num(cluster.distinctAccounts)} ${esc(t('cluster.accountUnit'))}</span>
      <span class="cluster-times">
        <span>${esc(t('cluster.firstSeen'))}${esc(fmtClock(cluster.firstSeen))}</span>
        <span>${esc(t('cluster.lastSeen'))}${esc(fmtClock(cluster.lastSeen))}</span>
      </span>`;

    renderRoles(cluster, clusterNodes, rolesEl);
    renderTimeline(cluster, clusterEdges, timelineEl);
    renderChain(cluster, clusterNodes, clusterEdges, chainEl);
    renderTable(clusterNodes, tableEl);
    // Letztstand einfrieren — Grundlage für Alterungsanzeige (members+at);
    // das Fallback-Matching läuft seit Befund 2026-09-30 gegen den stabilen
    // ORIGIN-ANKER (originMembers), nicht gegen diesen Snapshot.
    snapshot = { clusterId: cluster.id, at: Date.now(), members: [...nodeIds] };
    endStaleState();
    if (takeoverPending) showTakeoverNotice();
    await renderGraph(clusterNodes, clusterEdges, graphEl, noteEl, token, cluster.id);
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
            <span class="role-bar-label"><span class="swatch swatch-${esc(r)}"></span>${esc(roleLabelText(r))}</span>
            <span class="role-bar-track" role="img" aria-label="${esc(t('modal.roleBarAria', { role: roleLabelText(r), count, total: clusterNodes.length, pct }))}">
              <span class="role-bar-fill role-bar-${esc(r)}" style="width:${pct}%"></span>
            </span>
            <span class="role-bar-count">${num(count)}</span>
          </div>`;
      }).join('');
    el.innerHTML = `<h3 class="cluster-modal-h">${esc(t('modal.rolesTitle'))}</h3>
      <div class="role-bars">${rows}</div>
      <p class="graph-note">${esc(t('graph.disclaimer'))}</p>`;
  }

  /* ---------------- Zeitachse (SVG, epoch-basiert) ---------------- */

  function renderTimeline(cluster, clusterEdges, el) {
    const points = [];
    for (const e of clusterEdges) {
      const ep = Date.parse(String(e.closeTime ?? ''));
      if (Number.isFinite(ep)) points.push({ ep, type: String(e.type ?? '') });
    }
    if (!points.length) {
      el.innerHTML = `<h3 class="cluster-modal-h">${esc(t('modal.timelineTitle'))}</h3>`
        + `<p class="graph-note">${esc(t('modal.timelineEmpty'))}</p>`;
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
    el.innerHTML = `<h3 class="cluster-modal-h">${esc(t('modal.timelineTitle'))}</h3>
      <svg class="cluster-timeline" role="img"
           aria-label="${esc(t('modal.timelineAriaRange', { from: fmtClock(minIso), to: fmtClock(maxIso), n: points.length }))}">
        <line class="timeline-axis" x1="${PAD_PCT}%" y1="${CY}" x2="${100 - PAD_PCT}%" y2="${CY}"></line>
        ${dots}
      </svg>
      <div class="cluster-timeline-labels">
        <span>${esc(t('cluster.firstSeen'))}${esc(fmtClock(cluster.firstSeen ?? minIso))}</span>
        <span>${esc(t('cluster.lastSeen'))}${esc(fmtClock(cluster.lastSeen ?? maxIso))}</span>
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
      el.innerHTML = `<h3 class="cluster-modal-h">${esc(t('modal.chainTitle'))}</h3>
        <div class="cluster-chain" aria-label="${esc(t('cluster.chainAria'))}">${rows}</div>
        <p class="graph-note">${esc(t('modal.chainNote'))}</p>`;
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
      el.innerHTML = `<h3 class="cluster-modal-h">${esc(t('modal.chainTitle'))}</h3>`
        + `<p class="graph-note">${esc(t('modal.chainEmpty'))}</p>`;
      return;
    }
    const chips = entries.map((x) => chip({ id: x.address, role: x.role })).join('<span class="chain-path-sep" aria-hidden="true">·</span>');
    el.innerHTML = `<h3 class="cluster-modal-h">${esc(t('modal.chainTitle'))}</h3>
      <div class="cluster-chain" aria-label="${esc(t('modal.chainRoleAria'))}">${chips}</div>`;
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
          ? `<span class="risk-badge risk-${esc(sev)}">${esc(sevText(sev))}</span>`
          : '<span class="cluster-table-dash">–</span>';
        const actions = full ? addrActionsHtml(id) : '<span class="cluster-table-dash">–</span>';
        const role = roleLabels[n.role] ? n.role : 'unknown';
        // data-addr trägt NUR den Anzeigewert (volle Adresse ausschließlich
        // bei erlaubter Vollanzeige, sonst Kurzform) — die ROHE Knoten-Id
        // darf nie als DOM-Attribut landen (Befund 2026-09-29). Hover-
        // Highlight und Klick-Scroll vergleichen deshalb gegen
        // displayAddr(n.id), nicht gegen die rohe Id.
        return `<tr data-addr="${esc(full ? id : shown)}">
          <td class="cluster-td-addr" title="${esc(shown)}">${esc(shown)}</td>
          <td><span class="role-chip role-${esc(role)}"><span class="swatch swatch-${esc(role)}"></span>${esc(roleLabelText(role))}</span></td>
          <td>${badge}</td>
          <td class="cluster-td-num">${esc(fmtXrp(n.inDrops))}</td>
          <td class="cluster-td-num">${esc(fmtXrp(n.outDrops))}</td>
          <td class="cluster-td-num">${num(n.degreeIn)} / ${num(n.degreeOut)}</td>
          <td>${actions}</td>
        </tr>`;
      }).join('');
    el.innerHTML = `<h3 class="cluster-modal-h">${esc(t('modal.tableTitle'))}</h3>
      <div class="cluster-table-wrap" tabindex="0" role="region" aria-label="${esc(t('modal.tableWrapAria'))}">
        <table class="cluster-table">
          <caption>${esc(t('modal.tableCaption', { n: num(clusterNodes.length) }))}</caption>
          <thead>
            <tr>
              <th scope="col">${esc(t('modal.thAddr'))}</th>
              <th scope="col">${esc(t('modal.thRole'))}</th>
              <th scope="col">${esc(t('modal.thSeverity'))}</th>
              <th scope="col">${esc(t('modal.thIn'))}</th>
              <th scope="col">${esc(t('modal.thOut'))}</th>
              <th scope="col">${esc(t('modal.thEdges'))}</th>
              <th scope="col">${esc(t('modal.thActions'))}</th>
            </tr>
          </thead>
          <tbody>${rows}</tbody>
        </table>
      </div>`;
  }

  /* ---------------- Graph: 3D mit 2D-Ausweichansicht ---------------- */

  async function renderGraph(clusterNodes, clusterEdges, graphEl, noteEl, token, clusterId) {
    noteEl.hidden = true;
    if (typeof window.ForceGraph3D !== 'function') {
      graphEl.innerHTML = `<p class="graph-note">${esc(t('modal.loading3d'))}</p>`;
    }
    const ok3d = await loadForceGraph3D();
    if (token !== renderToken || !isOpen) return; // zwischenzeitlich neu gerendert/geschlossen

    if (ok3d && webglAvailable()) {
      try {
        build3D(clusterNodes, clusterEdges, graphEl, clusterId);
        return;
      } catch {
        // Konstruktor-Fehler -> Fallback unten
      }
    }
    teardown3D();
    if (typeof window.vis !== 'undefined') {
      try {
        build2D(clusterNodes, clusterEdges, graphEl);
        noteEl.textContent = t('modal.fallback2d');
        noteEl.hidden = false;
        return;
      } catch {
        // vis-Fehler -> statischer Zustand unten
      }
    }
    teardown2D();
    graphEl.innerHTML = `<p class="graph-note">${esc(t('modal.noGraph'))}</p>`;
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

  function build3D(clusterNodes, clusterEdges, graphEl, clusterId) {
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
    // Gleicher Cluster wie im aktuellen Graphen? Dann NUR die Daten
    // aktualisieren — Kamera/Zoom bleiben erhalten. zoomToFit/Camera-Reset
    // (und mit ihm der sichtbare Layout-Neustart) feuern ausschließlich bei
    // Cluster-Wechsel oder Erstrender.
    const sameCluster = Boolean(fg3d) && graphClusterId === clusterId;
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
    // graphData bei JEDER inhaltlichen Änderung des angezeigten Clusters —
    // Mitglieder/Kanten/Metriken werden nie blockiert. Ein vorheriger
    // Alterungs-Pause (Cluster war kurzzeitig verschwunden) wird gelöst.
    fg3d
      .graphData(data)
      .nodeColor(nodeColorAccessor())
      .nodeVal((n) => 1 + ((n.inDrops ?? 0) + (n.outDrops ?? 0)) / 1e6)
      .linkColor((l) => edgeColors[String(l.type)] || edgeDefault)
      .linkDirectionalParticles((l) => (String(l.type) === 'Payment' && !reducedMotion() ? 2 : 0))
      .linkDirectionalParticleWidth(2);
    try { fg3d.resumeAnimation(); } catch { /* egal */ }
    if (reducedMotion()) {
      // Reduced Motion (Befund 2026-09-29): Kraft-Simulation einfrieren —
      // Pendant zum 2D-Fallback, der die Physik per cooldownTicks 0 stoppt.
      // Auch nach Inhalts-Updates (graphData tauet die Simulation wieder auf).
      try { fg3d.cooldownTicks(0); } catch { /* egal */ }
    }
    if (!sameCluster) {
      graphClusterId = clusterId;
      // Camera-Reset/zoomToFit nur bei Cluster-Wechsel oder Erstrender.
      const dur = reducedMotion() ? 0 : 400; // statische Bildfassung ohne Animation
      setTimeout(() => { try { if (fg3d) fg3d.zoomToFit(dur); } catch { /* egal */ } }, 350);
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
        label: shortAddrFn(n.id),
        title: `${displayAddr(n.id)} (${roleLabelText(role)})`,
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
        // size 12 wie der Hauptpfad (app.js): Schrift unter 12 px ist
        // Astra-6-Microtype und verboten (globe.css-Designprinzipien) —
        // Befund 2026-09-29 (war 10 px).
        font: { color: '#484850', size: 12, face: '"JetBrains Mono", ui-monospace, Consolas, monospace', strokeWidth: 0, align: 'middle' },
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
    // ECHTES Freigeben (Symptom 2b, WebGL-Context-Leck): Nur pause+null ließ
    // den WebGL-Context der Instanz weiterleben — jeder Zyklus 'Cluster fiel
    // aus dem Fenster → Modal geleert → neu geöffnet' leakte einen Live-
    // Context; ab ~16 aktiven Contexten erzwingt Chrome Context-Loss am
    // ältesten Context (= Weltkugel). _destructor() (kapsule-Standard)
    // entsorgt Instanz, DOM und WebGL-Ressourcen.
    try {
      if (typeof fg3d._destructor === 'function') fg3d._destructor();
    } catch { /* egal — fg3d=null bleibt als Minimum */ }
    fg3d = null;
    graphClusterId = null;
  }

  function teardown2D() {
    if (!vis2d) return;
    try { vis2d.destroy(); } catch { /* egal */ }
    vis2d = null;
  }

  return { openCluster, refresh };
}
