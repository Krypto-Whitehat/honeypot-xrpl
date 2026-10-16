'use strict';

/* Honeypot XRPL – i18n (public/i18n.mjs)
 *
 * Zweisprachigkeit EN/DE für die gesamte Frontend-Oberfläche.
 *
 * MODUL-VERTRAG (DOM-frei beim Import — zwingend, weil lib/history.test.mjs
 * public/history.js importiert, das seinerseits './i18n.mjs' importiert;
 * läuft identisch in Node, Muster public/attribution.mjs):
 *   - Kein document-/localStorage-Zugriff auf Modulebene. Alle DOM-/
 *     Storage-Zugriffe stehen in Funktionen mit typeof-Guards.
 *   - Standard-Sprache ist 'en'; die Wahl wird unter localStorage-Schlüssel
 *     'hx-lang' persistiert (guardiert — ohne Storage bleibt sie flüchtig).
 *   - t(key, params): Lookup in der aktuellen Sprache, Fallback auf 'en',
 *     dann auf den Key selbst (sichtbar, kein stiller Ausfall).
 *     {name}-Platzhalter werden aus params interpoliert.
 *   - Sprachwechsel: setLang() setzt documentElement.lang, Titel und Meta-
 *     Description neu und sendet CustomEvent 'hx:langchange' am document —
 *     dynamische Sichten (Graph, Cluster-Karten, Log, Drilldown, Weltkugel,
 *     Historie, Konto-Check) re-rendern daraufhin.
 *   - Theme (Noir-Theme, 2026-10-06): dieselbe Vertragsform —
 *     getTheme()/setTheme()/applyTheme()/initThemeSwitcher(), Persistenz
 *     unter 'hx-theme' (Default 'noir'), Event 'hx:themechange' nach
 *     body[data-theme]- und meta-theme-color-Setzung (Canvas-Layer färben
 *     darauf um; CSS-Seite läuft allein über die Token-Overrides in
 *     style.css).
 *
 * PROTOKOLL-GRENZE (bewusst, siehe Plan-Tradeoff): Serverseitige deutsche
 * Strings bleiben Protokollwerte, weil Clients sie per String-Vergleich
 * auswerten (history.js / history-host.html prüfen body.reason ===
 * 'Persistenz nicht konfiguriert') und Tests sie asserten
 * (account-report.test.mjs). Übersetzt wird clientseitig über
 * serverPhrase() (Exact-Match auf die bekannten Werte) sowie über
 * ruleName()/noteText()/summaryText() aus strukturierten Feldern
 * (ruleId/noteKey/noteParams/verdict/score). Nicht rekonstruierbare
 * Kuratierungstexte (criteria[2].evidence = selfReason) bleiben raw —
 * dokumentierter Fallback.
 */

export const LANG_KEY = 'hx-lang';
export const LANGS = ['en', 'de'];
export const DEFAULT_LANG = 'en';

/* Theme (Noir-Theme 2026-10-06): dieselbe Vertragsform wie die Sprache —
 * Konstanten, validierte Persistenz unter eigenem Schlüssel ('hx-theme',
 * kollidiert nicht mit 'hx-lang'/'hx-density'), DOM-frei beim Import.
 * Noir ist DEFAULT (statisch im Markup der drei HTML-Seiten über
 * data-theme="noir"); das Inline-Bootstrap direkt nach <body> schaltet bei
 * persistiertem 'light' vor dem ersten Paint zurück (kein FOUC). */
export const THEME_KEY = 'hx-theme';
export const THEMES = ['noir', 'light'];
export const DEFAULT_THEME = 'noir';
/* meta[name=theme-color]-Werte der Browser-Chrome je Theme (alle drei Heads
 * tragen den Noir-Wert statisch; applyTheme hält das Meta aktuell). */
export const THEME_META_COLORS = { noir: '#0a0c0f', light: '#ffffff' };

/* ------------------------------------------------------------------ */
/* Wörterbuch (flache Keys; EN und DE haben dieselbe Schlüsselmenge —  */
/* maschinell geprüft in lib/i18n.test.mjs)                            */
/* ------------------------------------------------------------------ */

export const DICT = {
  en: {
    /* index.html — Kopf */
    'brand.sub': 'Live ledger analysis and threat dashboard for the XRPL community',
    'stats.aria': 'Live statistics',
    'stat.malicious': 'Findings malicious (live)',
    'stat.suspect': 'Findings suspect (live)',
    'stat.events': 'Transactions (live)',
    'stat.network': 'Network',
    'stat.last': 'As of',
    'conn.init': 'Establishing live connection …',

    /* index.html — Live-Statusleiste (.hx-stage) */
    'hero.title': 'Live threat radar for the XRP Ledger',
    'hero.lead': 'Every validated ledger block is analyzed in real time — findings and clusters, live from the public ledger.',
    'hero.kpisAria': 'Live key figures',
    'hero.kpiMalicious': 'malicious',
    'hero.kpiSuspect': 'suspect',
    'hero.kpiTxs': 'checked txs',

    'nav.aria': 'Views',
    'tab.dashboard': 'Dashboard',
    'tab.history': 'History',
    'tab.check': 'Account Check',
    'tab.flowhost': 'Flow-Host',
    'tab.about': 'About',
    /* Info-Boxen Historie/Archiv (2026-10-06): Kurzhinweis als summary der
       Details-Box in history.js renderShell, Langtext im Box-Körper. */
    'tab.historyHint': 'Permanently stored malicious clusters — independent of the live feed and the dashboard archive mode.',
    'tab.historyHintLong': 'The history permanently collects every cluster classified as malicious, even after it has left the current observation window. It fills through live analysis and visitor reports. The “Archive” data source on the dashboard, by contrast, only shows the persisted block window (24 hours to 7 days) — the history is independent of it.',

    /* index.html — Live-Block-Feed */
    'live.title': 'Live Block Feed',
    'live.hint': 'Validated ledger blocks in real time – analysis in the browser with the same engine as on the server',
    'live.aria': 'Live analysis statistics',
    'live.ledgers': 'ledgers',
    'live.txs': 'checked txs',
    'live.malicious': 'malicious',
    'live.suspect': 'suspect',
    'live.info': 'info',
    'feed.aria': 'Sequence of analyzed ledger blocks',
    'feed.empty': 'Waiting for the first validated ledger …',
    'log.title': 'Analysis Log',
    'log.severity': 'Severity',
    'log.filter.all': 'All',
    'log.filter.malicious': 'Malicious',
    'log.filter.suspect': 'Suspect',
    'log.filter.info': 'Info',
    'log.rule': 'Rule',
    'log.filter.allRules': 'All rules',
    'log.download': 'Download log as JSON',
    'log.empty': 'No rule hits in the observation window yet.',
    'feed.note': 'Fund addresses are exclusively actor addresses visible in the public ledger and are shown in full as soon as the bait-hash allowlist is loaded. Bait accounts never appear in the log – the server sanitizes them to labels and the client blocks them via the hash deny-list.',

    /* index.html — Aktivitäts-Graph */
    'graph.title': 'Activity Graph',
    'legend.aria': 'Legend',
    'legend.source': 'Source',
    'legend.drainer': 'Drainer',
    'legend.collector': 'Collector',
    'legend.relay': 'Relay',
    'legend.unknown': 'Unknown',
    'legend.cluster': 'Cluster',
    'legend.payment': 'Payment',
    'legend.check': 'Check/Channel',
    'legend.escrow': 'Escrow',
    'legend.market': 'DEX/AMM',
    'legend.nft': 'NFT',
    'legend.admin': 'Admin',
    'legend.fraud': 'Fraud edge',
    'legend.other': 'Other',
    'legend.malicious': 'Malicious',
    'legend.suspect': 'Suspect',
    'legend.info': 'Info',
    'graph.tabsAria': 'Graph view',
    'tab.live': 'Live Network',
    'tab.cluster': 'Cluster',
    'tab.globe': 'Globe',
    'graph.disclaimer': 'Roles (source, drainer, collector, relay) are heuristics based on in/out degree and money flow – not proof of guilt.',
    'graph.aria': 'Network graph of detected activity',
    'globe.aria': 'Globe of live activity; country assignment exclusively via the exchange registry, addresses without assignment placed symbolically',
    'cluster.aria': 'Cluster summary',
    'cluster.empty': 'No clusters yet – waiting for ledgers.',
    'graph.note': 'Nodes are actors visible in the public ledger from the live analysis – addresses are shown in full as soon as the bait-hash allowlist is loaded (bait addresses always remain hidden via the hash deny-list). Clicking a cluster card or a cluster bubble opens the cluster detail view.',
    /* Archiv-Graph-Parität + ehrliche Fenster (Kritik-Runde 3): Notiz im
       Archiv-Modus (app.js renderGraphArchiveNote) und truncated-Kennzeichnung
       des Bühnenfensters (renderGraphWindowNote, nur bei belegter Überschreitung). */
    'graph.noteArchive': 'Archive graph: edges carry the recorded transaction type (color = category, dashed = fraud), nodes their recorded role. Retention: block window 7 d, fraud state 30 d (malicious), archive 30 d (malicious) / 180 d (registry-linked) – older evidence is removed from the state, capped fields are marked on the cards.',
    'graph.windowTruncated': 'Window {range}: the oldest evidence in the state is from {depth} – the window reaches beyond the retained data.',

    /* index.html — Fuß */
    'foot.updated': 'As of: ',
    'foot.note': 'Bait anonymity: seeds and bait addresses are never served by the server and never rendered by the client.',

    /* Sprachumschalter */
    'lang.switchAria': 'Language',
    'lang.en': 'EN',
    'lang.de': 'DE',
    'lang.enAria': 'Switch language to English',
    'lang.deAria': 'Sprache auf Deutsch umstellen',

    /* Theme-Umschalter (initThemeSwitcher, Noir-Theme 2026-10-06): EIN Button,
       Label = aktueller Theme-Name, aria-pressed spiegelt 'noir', der
       aria-/title-Text beschreibt die Aktion (Wechsel zum anderen Theme). */
    'theme.switchAria': 'Color theme',
    'theme.noir': 'Noir',
    'theme.light': 'Light',
    'theme.toNoirAria': 'Switch to the noir theme',
    'theme.toLightAria': 'Switch to the light theme',

    /* app.js — Adressaktionen */
    'defang.bait': 'Bait (address hidden)',
    'addr.copy': 'Copy',
    'addr.copied': 'Copied',
    'addr.error': 'Error',
    'addr.copyAria': 'Copy address',
    'addr.linkAria': 'Open on xrpscan.com',

    /* app.js / Module — XRPScan-Namens-Badges (public/name-index.mjs) */
    'name.chipAria': 'Verified name from xrpscan.com',
    'name.unverifiedAria': 'Unverified name from xrpscan.com',
    'name.sourceNote': 'Account names: xrpscan.com (CC BY-NC-SA 4.0)',

    /* app.js / Module — Destination-Tag-Chips (Exchange-Registry) */
    'tag.chipAria': 'Destination tag — hosted account at this exchange',
    'tag.sourceAria': 'Source tag — informative, set by the sender',
    'cluster.transitNote': 'Connection runs through a shared exchange account (different destination tags)',
    'check.transitNote': 'Connection runs through a shared exchange account (different destination tags)',

    /* app.js — Graph */
    'graph.visError': 'vis-network could not be loaded (CDN unreachable).',
    'edge.other': 'Other',
    'cluster.members': '{n} members',
    'cluster.labelDefault': 'Cluster',

    /* app.js — Cluster-Karten */
    'cluster.ariaDetails': 'Open details for {label} – {xrp} XRP, {txs} tx, {accounts} accounts',
    'cluster.firstSeen': 'First seen: ',
    'cluster.lastSeen': 'Last seen: ',
    'cluster.txUnit': 'tx',
    'cluster.accountUnit': 'accounts',
    /* Kap-Kennzeichnung der Cluster-Karte (Kritik-Runde 3): distinctAccounts
       ist nach dem Monotonie-Fix der je gesehene Bestand, die Mitgliederliste
       ist auf 300 gekappt (FLOW_STATE_MEMBER_CAP, lib/flow-state.mjs). */
    'cluster.membersCapped': 'Field cap: {n} distinct accounts seen – the member list is capped at 300.',
    'cluster.chainAria': 'Money flow: start to collector along real edges',
    /* Cluster-Karten — Verdichtung + Mega-Cluster (Design P2, 2026-10-06):
       EINE gemeinsame '+N more accounts'-Wortfamilie für Adress-Chip-Zeile
       und Mega-Meta-Zeile (Plan-Kritik 10: keine Doppel-Hinweise). */
    'cluster.moreAccounts': '+{n} more accounts',
    'cluster.moreAccountsTitle': '{n} accounts in this cluster in total',
    'cluster.megaNote': '+{n} more accounts — aggregate in the detail view',
    'cluster.densityAria': 'Cluster card density',
    'cluster.densityComfortable': 'Comfortable',
    'cluster.densityCompact': 'Compact',
    'cluster.densityDense': 'Dense',

    /* app.js — Block-Karten und Log */
    'block.txs': 'txs',
    'block.analyzing': 'Analyzing …',
    'block.clean': 'no findings',
    'block.resolved': '{resolved}/{total} txs resolved',
    'block.quotaPaused': 'Ledger quota exhausted – analysis paused',
    'block.quotaSkipped': 'Ledger quota exhausted – analysis skipped',
    'block.sampled': 'Block not analyzed (sampling quota)',
    'block.busy': 'Analysis already running – this block is not resolved',
    'block.budgetSkipped': 'Command quota exhausted – analysis skipped',
    'block.flagged': '{n} flagged tx',
    'block.notFlagged': 'no flagged txs in window',
    'log.sevMalicious': 'malicious',
    'log.sevSuspect': 'suspect',
    'log.sevInfo': 'info',

    /* app.js — Log-Export */
    'export.source': 'Honeypot XRPL – live ledger analysis log',
    'export.note': 'Addresses in full where the bait-hash allowlist is loaded and the address is not on the deny-list; otherwise short form. Bait addresses are never exported. Full attribution via ledgerIndex on the public ledger.',
    'export.clusterList': 'Download cluster list as JSON',
    'export.clusterNote': 'Only addresses not on the internal protection list are exported.',
    'graph.downloadPng': 'Download as PNG',

    /* app.js — Live-Status */
    'net.mainnet': 'XRPL Mainnet (honeycluster.io)',
    'conn.wss': 'Live – WSS connected',
    'conn.wssConnecting': 'WSS connected – waiting for ledgers …',
    'conn.throttled': 'Live – snapshot fallback (endpoint throttling: rate limit{est})',
    'conn.rejected': 'Live – snapshot fallback (WSS subscription rejected: {error}{est})',
    'conn.noEvents': 'Live – snapshot fallback (WSS without events)',
    'conn.estSuffix': ', endpoint estimate {dur}',
    'conn.estWarn': ' – endpoint estimate {dur}, probe earlier',
    'conn.closed': 'Connection closed – retrying in {s} s',
    'conn.snapshotUnreachable': '{label} – ledger snapshot unreachable ({msg})',
    'conn.noData': 'No ledger data reachable ({msg})',
    'conn.unknownError': 'unknown error',
    'log.consoleSubscribeRejected': 'WSS subscription rejected ({error}){msg}. Server data remains the source.',
    'log.consoleDenyFailed': 'Bait-hash allowlist unreachable – full display permanently disabled (fail-closed).',
    'log.consoleDenyAttempt': 'Bait-hash allowlist: attempt {n} failed ({err})',

    /* app.js — Server-Fenster-Modus (Standard) und Opt-in-LIVE */
    'mode.label': 'Data source',
    'mode.archive': 'Archive',
    'mode.archiveAria': 'Show the persisted block window (24 h / 3 d / 7 d) from the server, or the fraud-state windows 30 d / 90 d',
    /* Sichtbarer Hinweis unter der Modus-Auswahl (index.html #feed-archive-
       hint), per aria-describedby an beide Modus-Buttons gebunden. */
    'mode.archiveHint': 'Archive mode: persisted block window (24 h / 3 d / 7 d) from the server — the 30 d / 90 d windows show the persisted fraud state instead. Also available when no live feed is connected.',
    'mode.live': 'Live',
    'mode.liveAria': 'Opt-in: direct WSS to honeycluster.io – one ledger command per block, no sampling',
    'range.label': 'Window',
    'range.24h': '24 h',
    'range.3d': '3 d',
    'range.7d': '7 d',
    'range.30d': '30 d',
    'range.90d': '90 d',
    'feed.loadMore': 'Load more',
    'feed.loadMoreAria': 'Load more block entries',
    'feed.serverEmpty': 'No blocks in the window yet – the server walk fills the window every 5 minutes.',
    'feed.windowNote': 'Server window: {range} · {blocks} blocks · {txns} txs · {flagged} flagged blocks · as of {time}',
    'feed.persistOff': 'Persistence not configured – the server window is empty. Activate the Live mode for direct analysis.',
    'feed.windowError': 'Server window unreachable ({msg})',
    /* Ehrliche Retention-Grenze (Kritik-Runde 3): das Block-Fenster endet bei
       7 d — 30 d/90d zeigen den persistierten Fraud-Bestand, nie Blockkarten. */
    'feed.windowBeyondBlockRetention': 'The block window covers 24 h / 3 d / 7 d only – the 30 d / 90 d windows show the persisted fraud state in graph, cluster cards and drilldown, not block cards.',
    'chart.aria': 'Hourly activity in the selected window: transactions per hour, flagged hours highlighted',
    'chart.flagged': 'flagged hours: {n}',
    'conn.server': 'Server data – window updated',
    'conn.serverLoading': 'Server data – loading window …',
    'conn.serverNoData': 'Server data – no blocks in the window',
    'conn.serverError': 'Server data unreachable ({msg})',
    'conn.liveInit': 'Live mode – connecting to honeycluster.io …',
    'conn.liveOff': 'Live mode stopped – server data active again',
    'conn.liveClosed': 'Live mode ended – retrying in {s} s',
    'conn.liveNoEvents': 'Live mode – WSS connected, waiting for ledgers …',
    'conn.liveThrottled': 'Live mode – endpoint throttling: rate limit{est}',
    'conn.liveRejected': 'Live mode – WSS subscription rejected: {error}{est}',
    'log.consoleLiveUnavailable': 'Rate limiter unavailable – Live mode cannot start (fail-closed).',
    'log.consoleLiveThrottled': 'Live mode: ledger command throttled ({error}){msg}.',

    /* drilldown.js — Modal */
    'modal.closeAria': 'Close',
    'modal.graphAria': 'Cluster graph',
    'modal.detailsAria': 'Cluster details',
    'modal.rolesAria': 'Role distribution',
    'modal.timelineAria': 'Transaction timeline',
    'modal.chainAria': 'Flow chain source to collector',
    'modal.tableAria': 'Cluster accounts',
    'modal.takeover': 'Cluster continues under a new identifier – automatically adopted (seamless takeover via member overlap).',
    'modal.stale': 'As of {time} – cluster no longer in the current observation window.',
    'modal.frozen': 'Snapshot from {time} – contents stay frozen until you close; the list behind keeps updating.',
    'modal.gone': 'Cluster no longer current – it no longer belongs to the current observation window.',
    'modal.persisted': 'As of {time} from the persisted inventory – cluster is no longer in the live window.',
    'modal.rolesTitle': 'Role distribution',
    'modal.roleBarAria': '{role}: {count} of {total} accounts ({pct} %)',
    'modal.timelineTitle': 'Transaction timeline',
    'modal.timelineAriaRange': 'Timeline from {from} to {to} – {n} transactions',
    'modal.timelineEmpty': 'No timestamps in the current observation window.',
    'modal.timelineTxUnit': 'transactions',
    'modal.chainTitle': 'Flow chain',
    'modal.chainNote': 'Paths follow only transactions of the observation window – no complete wallet history, no proof of guilt.',
    'modal.chainRoleAria': 'Cluster accounts by role – no edges in the observation window',
    'modal.chainEmpty': 'No role chain in the current observation window.',
    'modal.tableTitle': 'Cluster accounts',
    'modal.tableCaption': '{n} accounts – roles are heuristics, not proof of guilt',
    'modal.tableWrapAria': 'Accounts table, horizontally scrollable',
    'modal.thAddr': 'Address',
    'modal.thExchange': 'Exchange',
    'modal.thTag': 'Tag',
    'modal.thRole': 'Role',
    'modal.thSeverity': 'Severity',
    'modal.thIn': 'Incoming drops',
    'modal.thOut': 'Outgoing drops',
    'modal.thEdges': 'Edges (in / out)',
    'modal.thActions': 'Actions',
    'modal.loading3d': 'Loading 3D view …',
    'modal.fallback2d': '3D view not available – 2D fallback view (vis-network).',
    'modal.noGraph': 'No graph available – details in role distribution, flow chain and accounts table.',
    'modal.downloadJson': 'Download as JSON',
    'modal.downloadPng3d': 'Download 3D graph as PNG',
    'modal.downloadPng2d': 'Download graph as PNG (2D fallback view)',
    'modal.graph3dLegend': 'Ring around a node = drainer account.',

    /* globe.js */
    'globe.note': 'Positions are derived deterministically from the address hash – the XRPL ledger contains no location data. The globe is a symbolic activity view; country assignment via the exchange registry is currently unavailable.',
    'globe.noteCountries': 'Country borders: Natural Earth (TopoJSON). Country assignment exclusively via the exchange registry (countries where the exchanges are based); addresses without assignment remain placed deterministically from the address hash – the XRPL ledger itself contains no location data.',
    'globe.ariaCountries': 'Globe of live activity with country borders; country assignment exclusively via the exchange registry, addresses without assignment placed symbolically',
    'globe.ariaFailed': 'Globe of live activity; country assignment via the exchange registry is currently unavailable, positions remain symbolically derived from the address hash',
    'globe.ctxLost': 'WebGL graphics context lost – exactly one recovery attempt is starting …',
    'globe.fallback': 'Globe unavailable (WebGL or CDN unreachable) — the same data is available in the cluster cards and in the drilldown accounts table.',
    'globe.rebuild': 'Rebuilding globe …',
    'globe.loading': 'Loading globe …',
    'globe.legendTitle': 'Country activity',
    'globe.legendSrc': 'Assignment exclusively via the exchange registry · borders: Natural Earth (TopoJSON)',
    'globe.legendUnassigned': 'Addresses without country assignment: {n}',
    'globe.activity1': 'activity',
    'globe.activityN': 'activities',
    'globe.edge1': 'edge',
    'globe.edgeN': 'edges',
    'globe.inflow': 'inflow',
    'globe.outflow': 'outflow',
    'globe.custody': 'custody',
    'globe.exchanges': 'exchanges',
    'globe.tx1': 'transaction',
    'globe.txN': 'transactions',

    /* account-check.js */
    'check.title': 'Account Check',
    'check.hint': 'Profiling report of an XRPL address against the threat list, pattern detection and cluster heuristics.',
    'check.label': 'XRPL address (required)',
    'check.go': 'Check',
    'check.loading': 'Checking account …',
    'check.verdict.clean': 'clean',
    'check.verdict.contact': 'risk-associated',
    'check.verdict.bad': 'known malicious',
    'check.verdict.unknown': 'unknown',
    'check.elig.ok': 'Likely unproblematic',
    'check.elig.review': 'Worth reviewing',
    'check.elig.unknown': 'Not assessable',
    'check.noAbzug': 'no deduction',
    'check.metaChecked': 'Checked transactions: ',
    'check.metaNetwork': 'Network: ',
    'check.metaAt': 'Checked on: ',
    'check.metaTruncated': 'max. 300 txs checked – statement limited',
    'check.roleEmpty': 'No role involvement in the checked window.',
    'check.roleIn': 'Inflow: {n} edges ({xrp} XRP)',
    'check.roleOut': 'Outflow: {n} edges ({xrp} XRP)',
    'check.roleNote': 'The role applies only to the checked window – heuristic from in/out degree and money flow, not proof of guilt.',
    'check.patternsEmpty': 'No known patterns in the checked window.',
    'check.contactsEmpty': 'No contacts to listed addresses in the checked window.',
    'check.contactsAria': 'Contacts to listed addresses',
    'check.thCounterparty': 'Counterparty',
    'check.thDirection': 'Direction',
    'check.thTxType': 'Tx type',
    'check.thTime': 'Time',
    'check.thRisk': 'Risk',
    'check.thNote': 'Note',
    'check.reportAria': 'Check report of the checked address',
    'check.scoreAria': 'Score out of 100',
    'check.sectionScore': 'Score composition',
    'check.sectionRole': 'Role involvement',
    'check.sectionPatterns': 'Known patterns',
    'check.sectionContacts': 'Contacts to listed addresses',
    'check.sectionEligibility': 'Off-ramp assessment',
    'check.errInvalidAddr': 'Invalid XRPL address (expected: r followed by 24–34 Base58 characters).',
    'check.errInvalid400': 'Invalid or non-checkable address.',
    'check.errLedger502': 'Ledger query failed',
    'check.errUnexpected': 'Unexpected response (HTTP {status}).',
    'check.errNetworkTitle': 'Network error',
    'check.errNetworkDetail': 'The account check is currently unreachable — please try again later.',

    /* Zusammenfassung (Rebuild aus strukturierten Report-Feldern) */
    'summary.unknown': 'Not assessable — no or incomplete data.',
    'summary.score': 'Score {score} out of 100.',
    'summary.selfListed': 'The address itself is listed in the threat list.',
    'summary.malicious': '{n} distinct counterparty/parties with known malicious status.',
    'summary.suspect': '{n} distinct counterparty/parties with suspect status.',
    'summary.noContacts': 'No contacts to listed addresses in the checked window.',
    'summary.patterns': 'Pattern findings: {list}.',

    /* Server-Phrasen (Exact-Match; Rohwerte bleiben Protokoll) */
    'srv.persistenz': 'Persistence not configured',
    'srv.persistenzHost': 'Persistence not configured — without persistence authorization the endpoint delivers no flow state.',
    'srv.eligUnknown': 'Not assessable — no or incomplete data.',
    'srv.eligOk': 'Likely unproblematic for off-ramps (heuristic).',
    'srv.eligReview': 'Worth reviewing — rejection or manual review by the provider is likely.',
    'srv.disc1': 'The assessment is a heuristic over at most the last 300 transactions — older contacts and patterns are not covered.',
    'srv.disc2': 'Roles and patterns are heuristics (in/out degree, money flow) — not proof of guilt, no legal or liability statement.',
    'srv.disc3': 'The eligibility assessment is a heuristic — the decision rests with the off-ramp provider.',
    'srv.disc4': 'The queried address is not stored.',

    /* history.js */
    'history.title': 'Malicious History',
    'history.hint': 'Persistent history exclusively of clusters classified as malicious — suspect clusters are deliberately not persisted.',
    'history.searchLabel': 'Search',
    'history.searchPlaceholder': 'Address, cluster label or rule',
    'history.loading': 'Loading history …',
    'history.unconfigured': 'History persistence is not configured on this server — reports are not stored permanently.',
    'history.empty': 'No malicious clusters in the history yet — it fills through live observation and visitor reports.',
    'history.errorHttp': 'History unreachable (HTTP {status})',
    'history.errorNet': 'History unreachable (network)',
    'history.moreMembers': '{n} more members',
    'history.sightings': 'Reported by visitors: {n}×',
    'history.unbestaetigt': 'unconfirmed · 1 sighting',
    'history.maliciousBadge': 'malicious',

    /* history-host.html */
    'fh.title': 'Flow-Host: accumulated cross-block flow state',
    'fh.navAria': 'Navigation',
    'fh.stateTitle': 'Accumulated Flow State',
    'fh.stateHint': 'Cross-block accumulation of the ledger walk — cursor position and cluster view',
    'fh.refresh': 'Refresh',
    'fh.walkAria': 'Walk status',
    'fh.cursor': 'cursor position',
    'fh.lag': 'lag',
    'fh.updated': 'as of',
    'fh.graphEmpty': 'No retained flow edges in the accumulated state — the flow graph remains empty.',
    'fh.graphNote': 'Flow graph from the LIMITED retained flow edges + roles of the accumulated state (lib/ledger-walk.mjs). Positions are derived deterministically in a circle — the XRPL ledger contains no location data; the view is a symbolic flow view.',
    'fh.clustersTitle': 'Clusters',
    'fh.clustersHint': 'Sorted by volume (descending), then transaction count (descending)',
    'fh.empty': 'No accumulated flow state yet — the walk has not formed clusters yet.',
    'fh.emptyNoPersist': 'No flow state available.',
    'fh.statusPersist': 'Persistence not configured — without persistence authorization the endpoint delivers no flow state.',
    'fh.statusHint': 'Note: {reason}',
    'fh.unreachable': 'Flow state unreachable — please try again later.',
    'fh.graphAria': 'Flow graph of the accumulated state',

    /* about.html — Info-Seite für die XRPL-Community (eigenständige Seite im
       App-Shell-Look, Muster history-host.html). Alle Inhalte via data-i18n;
       Begriffe folgen exakt der Engine-Forensik (lib/detector.mjs,
       lib/cluster.mjs, lib/tag-identity.mjs, lib/entity-resolve.mjs,
       lib/flow-state.mjs, lib/block-window.mjs, lib/account-report.mjs). */
    'about.sub': 'Purpose, detection methods, glossary and limits of the dashboard',
    'about.missionTitle': 'What this dashboard is for',
    'about.missionHint': 'Bait-independent real-time analysis of the public ledger',
    'about.lead1': 'Honeypot XRPL is an open real-time threat dashboard for the XRPL community. Every validated block of the XRP Ledger mainnet is checked in real time for fraud, phishing and draining patterns; detected actors are connected into clusters by their money flow and assigned roles (source, drainer, collector, relay).',
    'about.lead2': 'The analysis is bait-independent: no own honeypot or decoy accounts are operated for detection anymore. The data comes exclusively from the public ledger — in live mode through a direct WSS connection to honeycluster.io (one ledger command per block, no sampling), in archive mode through the persisted server window (24 hours to 7 days). Account names and exchange attributions come from xrpscan.com (CC BY-NC-SA 4.0).',
    'about.lead3': 'The same analysis module (lib/detector.mjs) runs in the browser and on the server — the live analysis in the browser produces the same findings as the server walk that fills the window in the background.',
    'about.addressNote': 'Every address shown is an actor address publicly visible in the ledger and is displayed in full. The protective layers around the historical bait accounts (hash deny-list, server-side sanitization) remain active regardless.',
    'about.detectTitle': 'What is detected',
    'about.detectHint': 'Roles and patterns of the detector engine — heuristics, not proof of guilt',
    'about.rolesTitle': 'Roles in the cluster graph',
    'about.roleDrainerT': 'Drainer',
    'about.roleDrainerD': 'An account funded by at least two different senders that forwards at least 90 % of its inflow to a single target in one payment — the typical pattern of a victim account being swept.',
    'about.roleCollectorT': 'Collector',
    'about.roleCollectorD': 'A collection account with at least three inflows from different senders (at least one of them flagged), at most two outflows and clear accumulation — where the money gets bundled.',
    'about.roleSourceT': 'Source',
    'about.roleSourceD': 'An account with at least three small outgoing payments (at most 0.1 XRP each) to flagged targets — a typical sender of dust and lure payments.',
    'about.roleRelayT': 'Relay',
    'about.roleRelayD': 'A pass-through account with balanced inflow and outflow (difference at most 50 % of the larger value) — a waypoint for the money, not an offender by itself.',
    'about.patternsTitle': 'Patterns and connections',
    'about.patDrainerT': 'Draining (drainer sweep)',
    'about.patDrainerD': 'A freshly funded account is swept immediately: at least 90 % of the balance leaves to a single target in one payment. Only with ledger proof of account creation — or with an entity-snapshot proof of fresh account activity across ticks — is the finding classified as malicious; without it, it stays suspect.',
    'about.patFreshProofT': 'Fresh-activity proof (verifiedFresh)',
    'about.patFreshProofD': 'The malicious classification of a drainer sweep rests on a second proof of freshness: a ledger proof of account creation, or an entity-snapshot proof of fresh account activity within the last 21,600 ledgers (about 24 hours). verifiedFresh is a second evidence path — never a finding source by itself and never a downgrade; the threshold is published as verifiedFreshGapLedgers in the dashboard\u2019s machine-readable rules catalog.',
    'about.patCrossLedgerT': 'Cross-ledger sweep',
    'about.patCrossLedgerD': 'Funding and sweeping across block boundaries: when an account is funded in ledger N and only swept in ledger N+1, the cross-ledger memory of the engine keeps the sweep visible. Stretched dusting campaigns are caught the same way, via the union of their tiny destinations over the window.',
    'about.patPeelingT': 'Peeling chains',
    'about.patPeelingD': 'Staged forwarding of 60 to 95 % of the inflow across unflagged 1:1 relays, from three hops onwards. Detection runs on the transaction view and follows inconspicuous intermediate accounts without assigning them a role.',
    'about.patWashT': 'Wash trading (self-transfers)',
    'about.patWashD': 'At least three self-payments of the same account within one ledger (sender and destination are identical) — volume generation without a real counterparty, a typical washing pattern.',
    'about.patWashCycleT': 'Wash cycle (cross-account)',
    'about.patWashCycleD': 'At least two payments in each direction between the same two accounts (A→B and B→A) with at least 80 % volume conservation within one hour — volume generated across two identities. Single payment pairs stay exempt (normal refunds and market moves), exchanges never take part as cycle members; the finding class is suspect.',
    'about.patMotifT': 'Motif counters (gather-scatter)',
    'about.patMotifD': 'Deterministic counters over the accumulated flow edges — no learning architecture, zero extra requests. Gather-scatter (fan-in and fan-out of at least 3 different counterparties at one node) is recorded as a purely informative note; the wash-cycle thresholds above come from the same machinery. A cluster carries the motifs field only when a qualified pattern exists — no field means no motif. All counters and caps appear in the dashboard\u2019s machine-readable rules catalog.',
    'about.patHubT': 'Hub connections',
    'about.patHubD': 'Unflagged nodes with more than 20 finding edges (exchange, faucet or aggregation accounts) are cut out of the cluster union: two independent scenes never merge through a shared exchange. Connections that run through a shared exchange account (transit) are marked as pass-through, not as direct adjacency.',
    'about.patKnownBadT': 'Known-bad contact',
    'about.patKnownBadD': 'When a transaction touches an address from the threat list (curated and derived from the honeypot history), this is reported as a hit — direct account or payment contact as malicious, mere trustline or NFT positions only as suspect.',
    'about.detectNote': 'The engine rule catalog holds fifteen rules — besides the ones above, among others memo phishing (URLs and seed patterns in payment memos), dusting (mini XRP to fresh accounts), fake NFT fraud, airdrop TrustSet spam, payment bursts, offer spam, AMM washing, thin-pool exploits and spoof offer cycles. Every rule carries a severity; all assignments are heuristics, not proof of guilt.',
    'about.detectApi': 'Every threshold of the rules with numeric thresholds is machine-readable in the dashboard\u2019s rules catalog (thresholds per rule), and the deployed commit is reported in the x-deploy-commit response header of the same endpoint.',
    'about.glossaryTitle': 'Glossary',
    'about.glossaryHint': 'The terms of the interface — short and precise',
    'about.gClusterT': 'Cluster',
    'about.gClusterD': 'A group of addresses connected through money-flow edges (transactions with at least one flagged endpoint). Clusters form via union-find, carry labels such as “Cluster A” and track members, roles, volume and first/last sighting.',
    'about.gSeverityT': 'Severity',
    'about.gSeverityD': 'The engine assigns the levels malicious, suspect and info. The account check reports its verdict as known malicious, risk-associated (contact to listed addresses), clean or unknown, plus an off-ramp assessment (likely unproblematic, worth reviewing, not assessable). Addresses on whitelists (known gateways, exchanges) count as benign — exemption from the broad rules as false-positive protection, not a value judgment.',
    'about.gTagT': 'Destination tag and transit',
    'about.gTagD': 'Exchange accounts are hosted accounts: many users share one r-address and are told apart by the 32-bit destination tag. If inflows at the same exchange account show at least two different tag identities, the connection counts as transit — it runs through a shared exchange account and is not a direct adjacency.',
    'about.gEntityT': 'Entity resolution',
    'about.gEntityD': 'Control clusters from cryptographic signals instead of money flow: regular key, signer-list fingerprint, email hash and a shared sponsor address (funding source) unite accounts into one entity. Domains only count after two-way verification via xrp-ledger.toml; join keys carried by more than 20 addresses (hubs) are excluded.',
    'about.gWindowT': 'Block window vs. persistent cluster stock',
    'about.gWindowD': 'The block window is the rolling persisted stock behind the archive view (24 hours / 3 days / 7 days): hourly rollups plus details of flagged transactions only, seven days of retention. The persistent cluster stock (flow state) is independent of it: it accumulates clusters across the run of a server walk with a cursor, keeps them at most seven days after their last sighting (then the top 200 by volume) and feeds the flow host.',
    'about.gHistArchT': 'History vs. archive',
    'about.gHistArchD': 'The history permanently collects every cluster classified as malicious — independent of the live feed, among others through visitor reports. The dashboard archive only shows the persisted block window (24 hours to 7 days). For the backwards search per address there is a separate archive of daily chunks: registry-linked clusters stay retrievable for 180 days, malicious ones for 30 days.',
    'about.limitsTitle': 'Honest limits',
    'about.limitsHint': 'What this dashboard can do — and what it cannot',
    'about.limit1': 'All roles and patterns are heuristics from in/out degree and money flow. They name anomalies, not offenders — no proof of guilt, no legal statement or liability.',
    'about.limit2': 'There is no 100 % promise: not every scheme matches a rule, and rules can misfire without context. Cross-checking the transactions on the public ledger is explicitly encouraged.',
    'about.limit3': 'The account check assesses at most the last 300 transactions of the queried address — older contacts and patterns are not covered. The queried address is not stored.',
    'about.limit4': 'The analysis runs against public endpoints with rate limits (honeycluster.io). The server walk fills the window every five minutes; live mode and endpoints throttle and cache (60 s) — under load, views may briefly lag or drop out (fail-closed instead of pretending success).',
    'about.limit5': 'The archive backwards search reads day blocks on a limited read budget (62 days by default): the 180-day retention of registry-linked clusters exceeds what is queryable — old windows may be cut short (marked as truncated).',
    'about.limit6': 'The off-ramp assessment of the account check is a heuristic — the decision about payouts rests with the respective provider.',
    'about.sourcesTitle': 'Data sources',
    'about.sourcesNote': 'Ledger data: XRP Ledger mainnet via honeycluster.io (WSS/JSON-RPC). Account names and exchange attribution: xrpscan.com (CC BY-NC-SA 4.0). Country borders on the globe: Natural Earth (TopoJSON). Every finding address can be verified directly on the public ledger.',

    /* Schweregrade */
    'sev.malicious': 'malicious',
    'sev.suspect': 'suspect',
    'sev.info': 'info',

    /* Regel-Namen (lib/detector.mjs RULES, ids unverändert) */
    'rule.known-bad-hit': 'Known-bad hit (honeypot-derived + curation)',
    'rule.memo-phishing': 'Memo phishing (URLs/seed patterns in payments)',
    'rule.drainer-sweep': 'Drainer — freshly funded, swept immediately',
    'rule.airdrop-trustset-spam': 'Fake airdrop TrustSet spam',
    'rule.dusting': 'Dusting — mini XRP to fresh accounts',
    'rule.fake-nft-fraud': 'Fake NFT fraud',
    'rule.escrow-check-bait': 'Escrow/check bait to fresh accounts',
    'rule.payment-burst': 'Payment burst (airdrop distribution)',
    'rule.offer-spam': 'Offer spam (OfferCreate cascades without fill)',
    'rule.wash-self-transfer': 'Self-Transfer Washing',
    'rule.peeling-chain': 'Peeling chain (staged forwarding 60–90 %)',
    'rule.wash-cycle': 'Wash cycle (cross-account loop with volume conservation)',
    'rule.amm-wash-swap': 'AMM washing — bidirectional self-cycle with volume conservation',
    'rule.thin-pool-exploit': 'Thin-pool exploit — price impact in thin liquidity',
    'rule.spoof-offer-cycle': 'Spoof offers — place-and-pull cycles in the order book',
    'rule.amm-pool-drain': 'AMM pool outflow — at least 50 % of the XRP pool in one transaction',
    'rule.validator-unl-change': 'Validator UNL changed (ttUNL_MODIFY)',
    'rule.amendment-enabled': 'Amendment enabled (ttAMENDMENT)',
    'rule.fee-change': 'Network fee changed (ttFEE)',
    'rule.account-delete-sweep': 'Account-deletion wave — several AccountDelete to one target',
    'rule.mass-sweep-convergence': 'Mass sweep — many accounts send their full balance to one target',
    'rule.batch-inner-control': 'Batch inner: account control transaction hidden inside a batch (XLS-56)',
    'note.account-delete-sweep': '{n} account deletions with remaining balance to the same target in one ledger.',
    'note.mass-sweep-convergence': '{n} accounts sent their full balance to the same target in one ledger.',
    'note.batch-inner-control': '{type} hidden as an inner transaction of a batch (parent {parent}) — a control change disguised as an innocuous signature.',
    'pattern.title': 'Network load patterns',
    'validator.title': 'Validator health',
    'vt.close': 'Close',
    'vt.gaps': 'Recording gaps – no statement possible in these spans',
    'vt.loading': 'Loading trace …',
    'vt.error': 'Trace could not be loaded.',
    'vt.unavailable': 'No trace store on this host – the recorder (monitor/validator-trace.mjs) must run continuously to collect history.',
    'vt.note': 'The trace shows WHAT happened per ledger. The reason tags are correlations inside the same ledger (load, amendments, new transaction types, UNL changes) – hints for the investigation, not proven causes.',
    'vt.range.1h': 'Last hour', 'vt.range.24h': '24 h', 'vt.range.7d': '7 days', 'vt.range.all': 'Since start',
    'vt.k.ok': 'ok', 'vt.k.partial': 'partial', 'vt.k.missed': 'missed', 'vt.k.no-quorum': 'no quorum', 'vt.k.wrong-hash': 'wrong hash', 'vt.k.observed': 'observed',
    'vt.model3d': 'Incident profile (3D)', 'vt.patterns': 'Correlations', 'vt.timeline': 'Timeline',
    'vt.noIncidents': 'No deviations in this window.', 'vt.noPatterns': 'No recurring correlations.',
    'vt.type.missed': 'missed', 'vt.type.partial': 'partial validation', 'vt.type.wrong-hash': 'wrong hash', 'vt.type.no-quorum': 'no vote (network stall)',
    'vt.ledger': 'Ledger', 'vt.validators': 'validators', 'vt.ledgers': 'ledgers',
    'vt.crossTitle': 'Patterns across validators', 'vt.incidentsTotal': '{n} deviations in this window',
    'vt.recurring': 'Recurring correlations', 'vt.noRecurring': 'No correlation recurs across several validators yet.',
    'vt.perValidator': 'Per validator', 'vt.openPatterns': 'Patterns across validators',
    'vt.tag.load-spike': 'load spike', 'vt.tag.amendment-activity': 'amendment activity', 'vt.tag.unl-change': 'UNL change',
    'vt.tag.new-tx-type': 'new transaction type', 'vt.tag.no-quorum': 'no quorum', 'vt.tag.partial-validation': 'partial validation',
    'vt.tag.signed-different-hash': 'signed a different hash', 'vt.tag.no-correlated-cause': 'no correlated cause in this ledger',
    'vt.tag.detail-unavailable': 'ledger details unavailable', 'vt.tag.detail-skipped': 'ledger details skipped (load)',
    'vt.master': 'Master key', 'vt.ref': 'Reference (xrpscan agreement)',
    'vt.coverage': 'Recording', 'vt.coverageVal': '{ledgers} ledgers over {days} day(s) · {span} · {gaps} gap ledgers · {qf} no-quorum',
    'vt.inWindow': 'in the selected window', 'vt.estimated': 'estimated', 'vt.totals': 'total since recording start',
    'vt.nodata': 'No recording data for this validator in the loaded days — it was healthy during the recorded spans or not yet observed.',
    'vt.profileEmpty': 'No deviations in this window – the profile has nothing to draw.',
    'vt.profileMeta': '{buckets} time buckets · {from} → {to} UTC · axis peak {peak} ({scale})',
    'vt.axisScaleLinear': 'linear scale: one grid interval per incident',
    'vt.axisScaleRoot': 'square-root scale, so small counts stay visible',
    'vt.profileHint': 'Walk the columns with the mouse or Tab for the breakdown of each interval; the first strip shows the interval state, the second the measured transaction signature.',
    'vt.bucketAria': '{label} UTC · {total} deviations: {missed} missed, {partial} partial, {wrongHash} wrong hash, {noQuorum} no quorum · {ledgers} ledgers observed · {cohort} · {signatures} tx signatures',
    'vt.bucketReadout': '{label} UTC · {total} deviations ({missed} missed, {partial} partial, {wrongHash} wrong hash, {noQuorum} no quorum) · {ledgers} ledgers observed · {cohort} · {signatures} tx signatures',
  'vt.cohortCount': '{n} validators affected in the same ledger',
  'vt.cohortUnknown': 'cohort not recorded for this day',
  'vt.heatAria': 'Interval strip: observed without deviation, deviation by cohort width, or an interval without observation',
  'vt.state.clean': 'observed, no deviation',
  'vt.state.solo': 'solo – only this validator',
  'vt.state.cohort': 'few peers – 2 to 4 validators',
  'vt.state.network': 'network event – 5 or more validators',
  'vt.state.unknown': 'deviation, cohort not recorded',
  'vt.state.none': 'no ledger observed in this interval',
  'vt.sign.hit': 'transaction signature measured',
  'vt.sign.clear': 'observed, no signature',
  'vt.sign.unknown': 'tx forensics not recorded',
  'vt.sign.none': 'not observed',
  'vt.signAria': 'Signature strip: whether the transaction forensics measured a pattern on the failed ledgers of this validator',
  'vt.signCoverage': 'Transaction forensics: {seen} ledgers with a recorded transaction shape, {missing} ledgers had transactions but no recorded shape.',
  'vt.signAbsent': 'Transaction forensics has no recorded ledger yet – the signature layer stays empty until the recorder runs with the transactions stream.',
  'vt.profileNoProfile': 'The profile could not be built: the API sent no interval data.',
    'vt.retraceTitle': 'Retrace – why this happened',
    'vt.retraceNote': 'Per deviation: what was measured on this ledger, how many other validators the same ledger affected, and what the failure risk is for ledgers with this anomaly. Correlation inside one ledger, never a proven cause.',
    'vt.noRetrace': 'No retrace data for this validator in this window.',
    'vt.retraceShowing': 'showing {shown} of {total} retraced deviations',
    'vt.hypotheses': 'Hypotheses (ranked)',
    'vt.nextCheck': 'Next check',
    'vt.dataGaps': 'Data gaps',
    'vt.strength.measured': 'measured on this ledger',
    'vt.strength.correlated': 'correlated in this ledger',
    'vt.strength.cohort': 'cohort pattern',
    'vt.strength.none': 'nothing correlated found',
    'vt.scope.solo': 'this node only',
    'vt.scope.cohort': 'several validators',
    'vt.scope.network': 'network-wide',
    'vt.scope.unknown': 'unclassified',
    'vt.metric.quorum': 'Quorum', 'vt.metric.split': 'Hash split', 'vt.metric.load': 'Load', 'vt.metric.gap': 'Close gap', 'vt.metric.cohort': 'Cohort',
    'vt.mQuorum': '{top}/{needed} votes · margin {margin}',
    'vt.mSplit': '{runner} of {votes} votes on a second hash line',
    'vt.mLoad': '{tx} tx vs median {med} ({ratio}×)',
    'vt.mGap': '{gap} s since previous close',
    'vt.mCohort': '{n} validators affected · {others} others',
    'vt.evMargin': '{top}/{needed} votes reached, margin {margin}',
    'vt.evSplit': 'second hash line with {runner} votes ({votes} total)',
    'vt.evLoad': '{tx} tx against median {med} = {ratio}×',
    'vt.evGap': '{gap} s since previous close, median {med} s',
    'vt.evCohort': '{n} validators affected on this ledger, {others} others',
    'vt.evFanout': '{fanout} different destinations from one account with {txs} tx in this ledger ({ledgerTx} tx total)',
    'vt.evBurst': '{accountTx} tx from one account = {share} % of this ledger',
    'vt.evFailure': '{failed} failed transactions = {share} % of this ledger',
    'vt.evBatch': '{batchTx} batch tx carrying {innerTx} inner transactions',
    'vt.evFee': 'highest fee {maxFee} drops against median {medianFee} drops',
    'vt.evFeature': '{featureTx} network-level transaction(s) in this ledger',
    'vt.evCount': '{count} against baseline median {baseline}',
    'vt.evRatio': '{count} against baseline {baseline} = {ratio}×',
    'vt.evSweep': '{destinations} different destinations across {ledgers} ledgers ({txs} tx)',
    'vt.sigTitle': 'Transaction signature board',
    'vt.sigNote': 'Which transaction shapes appear in ledgers and how strongly they go together with validator failures. Counted over every observed ledger, not over a selection – a signature without a ledger counter stays unreliable.',
    'vt.sigEmpty': 'No transaction signature measured yet – this layer needs ledgers with a recorded transaction shape.',
    'vt.sig.hTag': 'signature',
    'vt.sig.hLedgers': 'ledgers',
    'vt.sig.hFails': 'with failure',
    'vt.sig.hLift': 'failure lift',
    'vt.sig.hSample': 'example ledger',
    'vt.sigSample': 'ledger {ledger} at {time} UTC',
    'vt.sigCoverage': '{seen} ledgers with a recorded transaction shape, {missing} without',
    'vt.liftVal': 'risk ×{lift} ({with} % with this anomaly vs {without} % without)',
    'vt.datagap.forensics-not-recorded': 'ledger forensics for this day were not recorded yet',
    'vt.datagap.forensics-truncated': 'ledger forensics are truncated (daily cap reached)',
    'vt.datagap.tx-shape-not-recorded': 'transaction shape for this ledger was not recorded (transactions stream off or data from before this level)',
    'vt.riskTitle': 'Failure risk per anomaly',
    'vt.riskNote': 'How often a ledger fails when this anomaly is present, against ledgers without it. Without that second number every cause is an anecdote. Small samples stay marked as small samples.',
    'vt.riskNone': 'No anomaly statistics yet – the recorder must observe anomaly ledgers first.',
    'vt.risk.hAnomaly': 'Anomaly', 'vt.risk.hLedgers': 'ledgers with it', 'vt.risk.hFails': 'of them failed', 'vt.risk.hRate': 'failure rate with', 'vt.risk.hBase': 'without', 'vt.risk.hLift': 'risk factor',
    'vt.riskSmall': 'sample too small',
    'vt.riskBase': 'basis: {ledgers} observed ledgers, {fails} of them with a deviation',
    'vt.riskTrunc': 'Ledger forensics are truncated (daily cap), so the anomaly counts are a lower bound.',
    'vt.attackTitle': 'Simultaneous failures',
    'vt.attackNote': 'Many validators, the same ledger. This is where network stalls, version conflicts and attacks on validators show up – ranked by how many were affected at once, not by guesswork.',
    'vt.attackNone': 'No ledger in this window affected several validators at once.',
    'vt.attackThreshold': 'from {n} validators affected on one ledger · {total} such ledgers in this window',
    'vt.attackAffected': '{n} validators',
    'vt.tag.quorum-thin': 'quorum reached only marginally',
    'vt.tag.hash-split': 'two hash lines in the vote',
    'vt.tag.load-extreme': 'extreme transaction load',
    'vt.tag.close-gap': 'unusually long time between closes',
    'vt.tag.cohort-event': 'several validators affected',
    'vt.tag.solo-failure': 'only this validator affected',
    'vt.g.network-stall': 'Check network stall and peer connectivity of the node',
    'vt.g.cohort-network': 'Compare with peers – several validators missed the same ledger',
    'vt.g.solo-peering': 'Check peering and the UNL view of this node',
    'vt.g.solo-resources': 'Check node resources, disk I/O and the rippled log at that time',
    'vt.g.version-state': 'Check rippled version and amendment state',
    'vt.g.report-split': 'Two hash lines existed – check which line this node signed',
    'vt.g.load-backlog': 'Check ledger throughput and the validation backlog',
    'vt.g.unl-membership': 'Check UNL membership changes around this ledger',
    'vt.g.parser-version': 'Check whether this node supports the transaction type',
    'vt.g.quorum-margin': 'Check quorum settings and the number of trusted peers',
    'vt.g.unknown-cause': 'No correlated cause – inspect the node log for this ledger',
    'vt.g.attack-drainer': 'Drainer pattern measured on this ledger – check which account fanned out here and freeze the affected payment lines',
    'vt.g.attack-burst': 'One account dominated this ledger – check the account, its fee setting and its sequence',
    'vt.g.attack-spam': 'Spam-like activity in this ledger (order book, NFT or accounts) – check the markets affected',
    'vt.g.attack-failed-tx': 'Many transactions failed in this ledger – check engine results and the ledger state',
    'vt.g.attack-amplify': 'Batch transactions amplified this ledger – check the inner transactions of those batches',
    'vt.g.attack-fee': 'Extreme fees in this ledger – check fee spikes and fee escalation',
    'vt.g.attack-type-burst': 'One transaction type far above its own baseline – check the type and its cost',
     'vt.g.node-offline-window': 'Node was away across a run of consecutive ledgers – check process uptime, restarts and the rippled log from the first ledger of that run',
     'vt.g.degraded-signing': 'Node signed but incompletely – check validation completeness and how loaded the node was at that time',
     'vt.verdict.offline-window': 'node away across a run of ledgers',
     'vt.verdict.brief-outage': 'short outage',
     'vt.verdict.short-series': 'two ledgers in a row, below the outage threshold',
     'vt.verdict.degraded-window': 'signed incompletely across a run',
     'vt.verdict.degraded-single': 'signed incompletely in this ledger',
     'vt.verdict.cohort-window': 'shared window with other validators',
     'vt.verdict.network-window': 'no quorum across the whole run',
     'vt.verdict.network-stall': 'no quorum reached',
     'vt.verdict.hash-divergence': 'signed a different hash',
     'vt.verdict.isolated-miss': 'single missed ledger',
     'vt.fpverdict.clean': 'no recorded deviation',
     'vt.fpverdict.network-driven': 'healthy node – it only fails when the network fails',
     'vt.fpverdict.chronic-outage': 'chronic outage – its failures come in runs of their own',
     'vt.fpverdict.solo-only': 'affected only on ledgers without a network event',
     'vt.fpverdict.outlier-node': 'far above the network median',
     'vt.fpverdict.intermittent': 'scattered single misses',
     'vt.fpverdict.mixed': 'mixed pattern',
     'vt.win.class.cohort-under-attack': 'shared window while the ledgers carried attack load',
     'vt.win.class.network-window': 'network window',
     'vt.win.class.targeted-under-load': "this node's own window while the ledgers carried attack load",
     'vt.win.class.overlapping-outage': 'overlapping with other validators',
     'vt.win.class.targeted-outage': "this node's own window",
     'vt.series.label': 'Series',
     'vt.series.run': 'ledgers {from}-{to}, position {position} of {ledgers} in this run, {duration}, verdict: {verdict}',
     'vt.series.single': 'single ledger – no series',
     'vt.series.break': 'after the run: {ledgers} ledger(s) in between – {cause}',
     'vt.series.cause.validated': 'the node validated again',
     'vt.series.cause.recorder-gap': 'not recorded, so no statement is possible there',
     'vt.series.cause.unknown': 'recording unclear at that point',
     'vt.fpTitle': 'Node signature',
     'vt.fpNone': 'No node signature yet – the recorder has not observed this validator in the selected window.',
     'vt.fpNote': 'Network problem or my problem? Own failure rate against the network median, and how much of it lands on ledgers where almost the whole network failed at once.',
     'vt.fp.rate': 'own failure rate',
     'vt.fp.medianRate': 'network median',
     'vt.fp.networkRate': 'network average',
     'vt.fp.split': 'network events against own ledgers',
     'vt.fp.splitVal': '{network} of {total} failures on network-event ledgers ({share} %), {private} on ledgers where only this node was affected',
     'vt.fp.series': 'inside runs of consecutive ledgers',
     'vt.fp.seriesVal': '{share} % of its failures ({isolated} single ledgers)',
     'vt.fp.longest': 'longest run',
     'vt.fp.longestVal': '{ledgers} consecutive ledgers ({duration})',
     'vt.fp.peak': 'peak hours (UTC)',
     'vt.fp.peakVal': '{share} % of failures concentrate in {hours}',
     'vt.cqTitle': 'Was my absence quorum-critical?',
     'vt.cqNote': 'Margin is the lead of the leading hash line over the quorum threshold. Margin 0 means the line only stood because enough others were present – the missing vote mattered. Where no forensics row was recorded, the question stays open.',
     'vt.cq.none': 'No ledger forensics row exists for the ledgers this node missed – the question is open, not answered.',
     'vt.cq.summary': '{checked} of {absent} deviating ledgers have a forensics row: {critical} at the quorum margin, {followOn} with room to spare.',
     'vt.cq.hLedger': 'ledger',
     'vt.cq.hType': 'deviation',
     'vt.cq.hVotes': 'votes / needed',
     'vt.cq.hTop': 'leading line',
     'vt.cq.hMargin': 'margin',
     'vt.cq.hEffect': 'effect',
     'vt.cq.critical': 'quorum-critical',
     'vt.cq.followOn': 'network had room',
     'vt.netTitle': 'Network event or own problem?',
     'vt.netNote': 'Ledgers where at least {n} validators failed at once are network events; everything else is private. Counting both together produces a cluster of nearly every validator and turns a network event into shared infrastructure – that is a measurement error, not a finding.',
     'vt.net.summary': '{network} network-event ledgers, {private} ledgers with one or a few validators affected',
     'vt.net.none': 'No validator failures in this window.',
     'vt.net.hValidator': 'validator',
     'vt.net.hTotal': 'failures',
     'vt.net.hNetwork': 'on network events',
     'vt.net.hOwn': 'own ledgers',
     'vt.net.hShare': 'network share',
     'vt.clTitle': 'Shared-infrastructure candidates',
     'vt.clNote': 'Only private ledgers count here. A pair needs at least {co} shared ledgers, at least {lift} times the independent chance and a mutual overlap of at least {mutual} %. Below that it stays a candidate, never a conclusion.',
     'vt.cl.none': 'No pair reaches the thresholds – no indication of shared infrastructure in this window.',
     'vt.cl.summary': '{pairs} candidate pairs over {private} private ledgers, {strong} reach the thresholds',
     'vt.cl.members': 'shared node group',
     'vt.cl.pairRow': '{a} + {b}: {co} shared ledgers, lift ×{lift}, mutual {mutual} %',
     'vt.winTitle': 'Failure windows across validators',
     'vt.win.none': 'No run of consecutive ledgers reached the reporting threshold in this window.',
     'vt.loadTitle': 'Load-Failure Curve',
     'vt.loadNote': 'At which transactions-per-ledger level this node starts falling behind - and at which level the cohort still keeps up. The failure rate alone cannot answer that: a node that fails at any load has a different problem than one that fails only under load.',
     'vt.loadNetNote': 'Network view: the load level at which the dUNL cohort as a whole starts falling behind. Without this comparison the curve of a single node is a number without meaning.',
     'vt.load.none': 'No load axis in this window - the recorder counts transactions per ledger only since 2026-10-16. Older days are a data gap, not "load-resistant".',
     'vt.load.hLoad': 'Tx per ledger',
     'vt.load.hLedgers': 'Ledgers',
     'vt.load.hFails': 'Failed ledgers',
     'vt.load.hNetwork': 'Network failure rate',
     'vt.load.hCohort': 'Cohort median',
     'vt.load.hOwn': 'Own failure rate',
     'vt.load.thin': 'too thin',
     'vt.load.baseline': 'Normal operation: {label} tx/ledger ({n} ledgers)',
     'vt.load.ownCeiling': 'Own load ceiling: {label} tx/ledger ({rate} % failing)',
     'vt.load.cohortCeiling': 'Cohort-median load ceiling: {label} tx/ledger',
     'vt.load.netCeiling': 'Network load ceiling: {label} tx/ledger ({rate} % failing)',
     'vt.load.verdict.load-limited': 'Falls behind under load - a capacity finding with a way to act',
     'vt.load.verdict.load-resilient': 'No load ceiling measured - the failures are not load-driven',
     'vt.load.verdict.always-failing': 'Already failing in normal operation - not a capacity problem',
     'vt.load.verdict.unknown': 'Not judgeable - too few ledgers per level',
     'vt.winNote': 'One window per validator run of consecutive ledgers, classified by how many of those ledgers other validators missed as well – together with the transaction shape measured inside the window.',
     'vt.win.row': '{class} – {master} – ledgers {from}-{to} ({ledgers} in a row, {duration}) – {coShare} % shared with others',
    'validator.coverage': 'dUNL coverage: {matched} of {listed} validators from the Ripple validator list (sequence {seq})',
    'validator.coverageFallback': 'dUNL list unavailable – showing {n} validators from registry tags (not verified against the signed list)',
    'validator.hint': 'Agreement scores of the public UNL validators, refreshed every minute',
    'validator.empty': 'No validator data yet.',
    'validator.error': 'Validator data currently unavailable (xrpscan) – nothing is estimated.',
    'validator.missed': 'missed',
    'validator.partial': '(partial)',
    'validator.attribution': 'Data: xrpscan.com (CC BY-NC-SA 4.0)',
    'validator.alert.validator-revoked': 'Validator revoked',
    'validator.alert.agreement-drop': 'Agreement drop (1 h)',
    'validator.alert.missed-surge': 'Missed-validation surge (1 h)',
    'validator.alert.signing-key-rotated': 'Signing key rotated',
    'validator.alert.unl-membership-changed': 'UNL membership changed',
    'pattern.hint': 'Ledger-level anomalies (load spikes, close gaps, finding bursts) with UTC timestamps',
    'pattern.empty': 'No anomalies in the sample window – the baseline is still forming or the network is quiet.',
    'pattern.chartAria': 'Transactions per validated ledger in the sample window',
    'pattern.type.load-spike': 'Load spike',
    'pattern.type.close-gap': 'Close gap',
    'pattern.type.fund-burst': 'Finding burst',
    'ticker.title': 'Live drainer ticker',
    'ticker.hint': 'Findings of the latest validated ledgers, newest first',
    'ticker.empty': 'No drainer activity observed yet.',
    'note.amm-pool-drain': '{type}: {pct} % of the {side} side of the pool drained in one transaction.',
    'note.validator-unl-change': 'Validator UNL changed (pseudo-transaction, validator set change).',
    'note.amendment-enabled': 'Amendment enabled (pseudo-transaction).',
    'note.fee-change': 'Network fee parameters changed (pseudo-transaction).',

    /* Detector-Notes (noteKey/noteParams aus lib/detector.mjs) */
    'note.known-bad-hit': 'Known-malicious address involved ({type}).',
    'note.memo-phishing-seed': 'Memo contains seed pattern.',
    'note.memo-phishing-url': 'Memo contains URL with claim-/airdrop-/verify- keyword.',
    'note.fake-nft-fraud-uri': 'NFTokenMint URI contains phishing/claim pattern.',
    'note.escrow-check-bait-single': '{type} with tiny amount and phishing memo to fresh target {addr}.',
    'note.dusting-many': '{n} mini XRP payments to different targets in the observation window.',
    'note.dusting-fresh': '{n} mini XRP payments to fresh targets in one ledger.',
    'note.drainer-sweep': 'Freshly funded and {pct} % swept to one target.',
    'note.offer-spam': '{n} OfferCreate without fill in one ledger.',
    'note.fake-nft-fraud-accept': '{n} NFTokenAcceptOffer without payment in one ledger.',
    'note.escrow-check-bait-burst': '{n} escrow/check baits to different fresh targets.',
    'note.payment-burst': '{n} payments to different targets, {tiny} of them tiny (airdrop distribution pattern).',
    'note.airdrop-trustset-spam': '{n} TrustSets with tiny limit from different accounts to issuer {issuer} in one ledger.',
    'note.wash-self-transfer': '{n} self-payments in one ledger (volume washing).',
    'note.peeling-chain': 'Peeling chain: {hops} staged hops (avg {ratio} % forwarding).',
    'note.fake-nft-fraud-fee': 'NFTokenMint with usurious transfer fee ({pct} %).',
    'note.fake-nft-fraud-offer': '{n} NFTokenCreateOffer to the same target {addr} in one ledger.',
    'note.amm-wash-swap': 'Bidirectional OfferCreate fills on {pair} in volume balance (conservation {conserve} %, drift {drift} %).',
    'note.thin-pool-exploit': '{n} fills on {pair} with >= {devPct} % price deviation from the window median in the favorable direction (thin pool).',
    'note.spoof-offer-cycle': '{n} place-and-pull cycles (create→cancel <= {maxCancel} ledgers) across {levels} price levels in the order book.',

    /* index.html — Top-10-Börsen-Zuflüsse (Daten-Forensik 2026-10-07,
       public/exchange-outflows.mjs): ehrliche Box — Grenzen (50-Kanten-Deckel,
       Betrugs-Retention statt Wallet-Historie, Union-Erkennung) stehen in der
       Fußnote, der reale Abdeckungszeitraum (coverageFrom→generatedAt) wird
       dynamisch gerendert (#exout-coverage, Pflicht 11), der Cap-Hinweis nur
       bei belegter Kappung (#exout-capped). */
    'exout.title': 'Top exchanges receiving drained funds',
    'exout.subtitle': 'Where the most drained funds land — the exchanges themselves are not the perpetrators.',
    'exout.window7': '7 days',
    'exout.window30': '30 days',
    'exout.windowAll': 'All',
    'exout.windowAria': 'Coverage window of the exchange inflows',
    'exout.rank': 'Rank {n}',
    'exout.inflows': '{n} edges',
    'exout.inflows1': '1 edge',
    'exout.clusters': '{n} clusters',
    'exout.clusters1': '1 cluster',
    'exout.transit': 'Transit share: {xrp} XRP',
    'exout.empty': 'No inflows from drainer context to registry exchanges in the selected window yet.',
    'exout.capped': '{n} of the considered clusters sit at the 50-edge cap of the state — all sums are a lower bound.',
    'exout.coverage': 'Covered period: {from} – {to}',
    'exout.note': 'Only the 50 largest edges by volume per cluster are kept by the state (lower bound); 30 days reflects the fraud retention of the live state, not a complete wallet history; exchange detection = registry ∪ verified well-known names.',
    'exout.aria': 'Top 10 exchanges by incoming drops from drainer context',
    'exout.wellKnown': 'well-known',

    /* index.html — Top-10 Drainer-Rangliste (Drainer-Tranche 2026-10-07,
       public/drainer-top10.mjs): rechte Duo-Box — Qualifikation nur über die
       Drainer-Rolle (Heuristik, kein Schuldbeweis — im Untertitel), Union-
       Ausschluss gegen Doppelzählung mit der Börsen-Box (in der Fußnote),
       Grenzen (50-Kanten-Deckel, 300er-Rollen-Feldkappe, Betrugs-Retention)
       ehrlich in der Fußnote, Abdeckungszeitraum dynamisch (#drout-coverage),
       Cap-Hinweis nur bei belegter Kappung (#drout-capped). Eigener
       Tag-Aria-Schlüssel: 'tag.chipAria' behauptet ein Börse-Hosted-Konto —
       für ein Drainer-Konto falsch. */
    'drout.title': 'Top drainer accounts by received funds',
    'drout.subtitle': 'The drainer role is a heuristic from in/out degree and money flow — a signal, not a proven verdict.',
    'drout.window7': '7 days',
    'drout.window30': '30 days',
    'drout.windowAll': 'All',
    'drout.windowAria': 'Coverage window of the drainer inflows',
    'drout.rank': 'Rank {n}',
    'drout.inflows': '{n} inflows',
    'drout.inflows1': '1 inflow',
    'drout.clusters': '{n} clusters',
    'drout.clusters1': '1 cluster',
    'drout.forwarded': 'Forwarded: {xrp} XRP',
    'drout.tagAria': 'Destination tag recorded on inflows to this account',
    'drout.empty': 'No drainer account with received funds in the considered state within the selected window yet.',
    'drout.capped': '{n} of the considered clusters sit at the 50-edge cap of the state — all sums are a lower bound.',
    'drout.coverage': 'Covered period: {from} – {to}',
    'drout.note': 'Only the 50 largest edges by volume per cluster are kept by the state (lower bound); role fields are capped at 300 entries per cluster; accounts of the exchange union rank in the left box and are excluded here; 30 days reflects the fraud retention of the live state, not a complete wallet history.',
    'drout.aria': 'Top 10 drainer accounts by received drops',
  },

  de: {
    /* index.html — Kopf */
    'brand.sub': 'Live-Ledger-Analyse und Bedrohungs-Dashboard für die XRPL-Community',
    'stats.aria': 'Live-Statistiken',
    'stat.malicious': 'Funde maliziös (live)',
    'stat.suspect': 'Funde verdächtig (live)',
    'stat.events': 'Transaktionen (live)',
    'stat.network': 'Netzwerk',
    'stat.last': 'Stand',
    'conn.init': 'Live-Verbindung wird aufgebaut …',

    /* index.html — Live-Statusleiste (.hx-stage) */
    'hero.title': 'Live-Bedrohungsradar für das XRP-Ledger',
    'hero.lead': 'Jeder validierte Ledger-Block wird in Echtzeit analysiert — Funde und Cluster, live aus dem öffentlichen Ledger.',
    'hero.kpisAria': 'Live-Kennzahlen',
    'hero.kpiMalicious': 'maliziös',
    'hero.kpiSuspect': 'verdächtig',
    'hero.kpiTxs': 'geprüfte Txs',

    'nav.aria': 'Ansichten',
    'tab.dashboard': 'Dashboard',
    'tab.history': 'Historie',
    'tab.check': 'Konto-Check',
    'tab.flowhost': 'Flow-Host',
    'tab.about': 'Info',
    /* Info-Boxen Historie/Archiv (2026-10-06): Kurzhinweis als summary der
       Details-Box in history.js renderShell, Langtext im Box-Körper. */
    'tab.historyHint': 'Dauerhaft gespeicherte maliziöse Cluster — unabhängig vom Live-Feed und vom Archiv-Modus des Dashboards.',
    'tab.historyHintLong': 'Die Historie sammelt dauerhaft jeden Cluster, der als maliziös eingestuft wurde — auch wenn er das aktuelle Beobachtungsfenster längst verlassen hat. Gefüllt wird sie durch die Live-Analyse und durch Meldungen von Besuchern. Die Datenquelle „Archiv“ im Dashboard zeigt hingegen nur das persistierte Block-Fenster (24 Stunden bis 7 Tage) — die Historie ist davon unabhängig.',

    /* index.html — Live-Block-Feed */
    'live.title': 'Live-Block-Feed',
    'live.hint': 'Validierte Ledger-Blöcke in Echtzeit – Analyse im Browser mit derselben Engine wie serverseitig',
    'live.aria': 'Live-Analyse-Statistiken',
    'live.ledgers': 'Ledger',
    'live.txs': 'geprüfte Txs',
    'live.malicious': 'maliziös',
    'live.suspect': 'verdächtig',
    'live.info': 'Info',
    'feed.aria': 'Folge der analysierten Ledger-Blöcke',
    'feed.empty': 'Warte auf den ersten validierten Ledger …',
    'log.title': 'Analyse-Log',
    'log.severity': 'Schweregrad',
    'log.filter.all': 'Alle',
    'log.filter.malicious': 'Maliziös',
    'log.filter.suspect': 'Verdächtig',
    'log.filter.info': 'Info',
    'log.rule': 'Regel',
    'log.filter.allRules': 'Alle Regeln',
    'log.download': 'Log als JSON',
    'log.empty': 'Noch keine Regel-Treffer im Beobachtungsfenster.',
    'feed.note': 'Fund-Adressen sind ausschließlich öffentlich im Ledger sichtbare Akteur-Adressen und werden vollständig angezeigt, sobald die Bait-Hash-Allowlist geladen ist. Köder-Konten erscheinen nie im Log – sie werden vom Server zu Labels sanitisiert und clientseitig über die Hash-Deny-Liste gesperrt.',

    /* index.html — Aktivitäts-Graph */
    'graph.title': 'Aktivitäts-Graph',
    'legend.aria': 'Legende',
    'legend.source': 'Source',
    'legend.drainer': 'Drainer',
    'legend.collector': 'Kollektor',
    'legend.relay': 'Relay',
    'legend.unknown': 'Unbekannt',
    'legend.cluster': 'Cluster',
    'legend.payment': 'Payment',
    'legend.check': 'Check/Channel',
    'legend.escrow': 'Escrow',
    'legend.market': 'DEX/AMM',
    'legend.nft': 'NFT',
    'legend.admin': 'Admin',
    'legend.fraud': 'Betrug (Kante)',
    'legend.other': 'Sonstige',
    'legend.malicious': 'Maliziös',
    'legend.suspect': 'Verdächtig',
    'legend.info': 'Info',
    'graph.tabsAria': 'Graph-Ansicht',
    'tab.live': 'Live-Netz',
    'tab.cluster': 'Cluster',
    'tab.globe': 'Weltkugel',
    'graph.disclaimer': 'Rollen (Source, Drainer, Kollektor, Relay) sind Heuristiken aus Ein-/Ausgrad und Geldfluss – kein Schuldnachweis.',
    'graph.aria': 'Netzwerkgraph der erkannten Aktivitäten',
    'globe.aria': 'Weltkugel der Live-Aktivität; Länderzuordnung ausschließlich über die Börsen-Registry, Adressen ohne Zuordnung symbolisch platziert',
    'cluster.aria': 'Cluster-Zusammenfassung',
    'cluster.empty': 'Noch keine Cluster – warte auf Ledger.',
    'graph.note': 'Knoten sind öffentlich im Ledger sichtbare Akteure aus der Live-Analyse – Adressen werden vollständig angezeigt, sobald die Bait-Hash-Allowlist geladen ist (Köder-Adressen bleiben über die Hash-Deny-Liste stets verborgen). Klick auf eine Cluster-Karte oder eine Cluster-Bubble öffnet die Cluster-Detailansicht.',
    /* Archiv-Graph-Parität + ehrliche Fenster (Kritik-Runde 3): Notiz im
       Archiv-Modus (app.js renderGraphArchiveNote) und truncated-Kennzeichnung
       des Bühnenfensters (renderGraphWindowNote, nur bei belegter Überschreitung). */
    'graph.noteArchive': 'Archiv-Graph: Kanten tragen den aufgezeichneten Transaktionstyp (Farbe = Kategorie, gestrichelt = Betrug), Knoten ihre aufgezeichnete Rolle. Retention: Block-Fenster 7 Tage, Betrugsgestand 30 Tage (maliziös), Archiv 30 Tage (maliziös) / 180 Tage (registry-verknüpft) – ältere Evidenz wird aus dem Bestand entfernt, gekappte Felder sind auf den Karten gekennzeichnet.',
    'graph.windowTruncated': 'Fenster {range}: die älteste Evidenz im Bestand stammt vom {depth} – das Fenster greift über die gespeicherten Daten hinaus.',

    /* index.html — Fuß */
    'foot.updated': 'Stand: ',
    'foot.note': 'Anonymität der Köder: Seeds und Köder-Adressen werden vom Server nie ausgeliefert und vom Client nie gerendert.',

    /* Sprachumschalter */
    'lang.switchAria': 'Sprache',
    'lang.en': 'EN',
    'lang.de': 'DE',
    'lang.enAria': 'Sprache auf Englisch umstellen',
    'lang.deAria': 'Sprache auf Deutsch umstellen',

    /* Theme-Umschalter (initThemeSwitcher, Noir-Theme 2026-10-06): EIN Button,
       Label = aktueller Theme-Name, aria-pressed spiegelt 'noir', der
       aria-/title-Text beschreibt die Aktion (Wechsel zum anderen Theme). */
    'theme.switchAria': 'Farbthema',
    'theme.noir': 'Noir',
    'theme.light': 'Hell',
    'theme.toNoirAria': 'Zum Noir-Thema wechseln',
    'theme.toLightAria': 'Zum hellen Thema wechseln',

    /* app.js — Adressaktionen */
    'defang.bait': 'Köder (Adresse verborgen)',
    'addr.copy': 'Kopieren',
    'addr.copied': 'Kopiert',
    'addr.error': 'Fehler',
    'addr.copyAria': 'Adresse kopieren',
    'addr.linkAria': 'Auf xrpscan.com öffnen',

    /* app.js / Module — XRPScan-Namens-Badges (public/name-index.mjs) */
    'name.chipAria': 'Verifizierter Name von xrpscan.com',
    'name.unverifiedAria': 'Unverifizierter Name von xrpscan.com',
    'name.sourceNote': 'Kontonamen: xrpscan.com (CC BY-NC-SA 4.0)',

    /* app.js / Module — Destination-Tag-Chips (Exchange-Registry) */
    'tag.chipAria': 'Destination-Tag — Hosted-Account bei dieser Börse',
    'tag.sourceAria': 'Source-Tag — informativ, vom Absender gesetzt',
    'cluster.transitNote': 'Verbindung läuft über ein gemeinsames Börsen-Konto (unterschiedliche Destination-Tags)',
    'check.transitNote': 'Verbindung läuft über ein gemeinsames Börsen-Konto (unterschiedliche Destination-Tags)',

    /* app.js — Graph */
    'graph.visError': 'vis-network konnte nicht geladen werden (CDN nicht erreichbar).',
    'edge.other': 'Sonstige',
    'cluster.members': '{n} Mitglieder',
    'cluster.labelDefault': 'Cluster',

    /* app.js — Cluster-Karten */
    'cluster.ariaDetails': 'Details zu {label} öffnen – {xrp} XRP, {txs} Tx, {accounts} Konten',
    'cluster.firstSeen': 'Erste Sichtung: ',
    'cluster.lastSeen': 'Letzte Sichtung: ',
    'cluster.txUnit': 'Tx',
    'cluster.accountUnit': 'Konten',
    /* Kap-Kennzeichnung der Cluster-Karte (Kritik-Runde 3): distinctAccounts
       ist nach dem Monotonie-Fix der je gesehene Bestand, die Mitgliederliste
       ist auf 300 gekappt (FLOW_STATE_MEMBER_CAP, lib/flow-state.mjs). */
    'cluster.membersCapped': 'Feldkappe: {n} verschiedene Konten je gesehen – die Mitgliederliste ist auf 300 gekappt.',
    'cluster.chainAria': 'Geldfluss: Start bis Kollektor entlang echter Kanten',
    /* Cluster-Karten — Verdichtung + Mega-Cluster (Design P2, 2026-10-06):
       EINE gemeinsame „+N weitere Konten“-Wortfamilie für Adress-Chip-Zeile
       und Mega-Meta-Zeile (Plan-Kritik 10: keine Doppel-Hinweise). */
    'cluster.moreAccounts': '+{n} weitere Konten',
    'cluster.moreAccountsTitle': '{n} Konten insgesamt in diesem Cluster',
    'cluster.megaNote': '+{n} weitere Konten — Aggregat im Detail',
    'cluster.densityAria': 'Dichte der Cluster-Karten',
    'cluster.densityComfortable': 'Übersichtlich',
    'cluster.densityCompact': 'Kompakt',
    'cluster.densityDense': 'Dicht',

    /* app.js — Block-Karten und Log */
    'block.txs': 'Txs',
    'block.analyzing': 'Analysiere …',
    'block.clean': 'keine Funde',
    'block.resolved': '{resolved}/{total} Txs aufgelöst',
    'block.quotaPaused': 'Ledger-Quota erschöpft – Analyse pausiert',
    'block.quotaSkipped': 'Ledger-Quota erschöpft – Analyse übersprungen',
    'block.sampled': 'Block nicht analysiert (Stichproben-Kontingent)',
    'block.busy': 'Analyse läuft bereits – dieser Block wird nicht aufgelöst',
    'block.budgetSkipped': 'Kommandokontingent erschöpft – Analyse übersprungen',
    'block.flagged': '{n} geflaggte Tx',
    'block.notFlagged': 'keine geflaggten Txs im Fenster',
    'log.sevMalicious': 'maliziös',
    'log.sevSuspect': 'verdächtig',
    'log.sevInfo': 'info',

    /* app.js — Log-Export */
    'export.source': 'Honeypot XRPL – Live-Ledger-Analyse-Log',
    'export.note': 'Adressen vollständig, sofern die Bait-Hash-Allowlist geladen ist und die Adresse nicht auf der Deny-Liste steht; sonst Kurzform. Köder-Adressen werden nie exportiert. Vollständige Zuordnung über ledgerIndex auf dem öffentlichen Ledger möglich.',
    'export.clusterList': 'Clusterliste als JSON herunterladen',
    'export.clusterNote': 'Exportiert werden nur Adressen, die nicht auf der internen Schutzliste stehen.',
    'graph.downloadPng': 'Als PNG herunterladen',

    /* app.js — Live-Status */
    'net.mainnet': 'XRPL Mainnet (honeycluster.io)',
    'conn.wss': 'Live – WSS verbunden',
    'conn.wssConnecting': 'WSS verbunden – warte auf Ledger …',
    'conn.throttled': 'Live – Snapshot-Fallback (Endpunkt-Drosselung: rate limit{est})',
    'conn.rejected': 'Live – Snapshot-Fallback (WSS-Abo abgelehnt: {error}{est})',
    'conn.noEvents': 'Live – Snapshot-Fallback (WSS ohne Events)',
    'conn.estSuffix': ', Endpunkt-Schätzung {dur}',
    'conn.estWarn': ' – Endpunkt-Schätzung {dur}, Sonde früher',
    'conn.closed': 'Verbindung getrennt – erneuter Versuch in {s} s',
    'conn.snapshotUnreachable': '{label} – Ledger-Snapshot nicht erreichbar ({msg})',
    'conn.noData': 'Keine Ledger-Daten erreichbar ({msg})',
    'conn.unknownError': 'unbekannter Fehler',
    'log.consoleSubscribeRejected': 'WSS-Abo abgelehnt ({error}){msg}. Server-Daten bleiben die Quelle.',
    'log.consoleDenyFailed': 'Bait-Hash-Allowlist nicht erreichbar – Vollanzeige dauerhaft deaktiviert (fail-closed).',
    'log.consoleDenyAttempt': 'Bait-Hash-Allowlist: Versuch {n} fehlgeschlagen ({err})',

    /* app.js — Server-Fenster-Modus (Standard) und Opt-in-LIVE */
    'mode.label': 'Datenquelle',
    'mode.archive': 'Archiv',
    'mode.archiveAria': 'Persistiertes Block-Fenster (24 h / 3 T / 7 T) vom Server anzeigen, oder die Betrugsbestands-Fenster 30 T / 90 T',
    /* Sichtbarer Hinweis unter der Modus-Auswahl (index.html #feed-archive-
       hint), per aria-describedby an beide Modus-Buttons gebunden. */
    'mode.archiveHint': 'Archiv-Modus: persistiertes Block-Fenster (24 h / 3 T / 7 T) vom Server – die Fenster 30 T / 90 T zeigen stattdessen den persistierten Betrugsbestand. Auch verfügbar, wenn kein Live-Feed verbunden ist.',
    'mode.live': 'Live',
    'mode.liveAria': 'Opt-in: direkter WSS zu honeycluster.io – ein Ledger-Kommando pro Block, ohne Stichprobe',
    'range.label': 'Fenster',
    'range.24h': '24 h',
    'range.3d': '3 T',
    'range.7d': '7 T',
    'range.30d': '30 T',
    'range.90d': '90 T',
    'feed.loadMore': 'Mehr laden',
    'feed.loadMoreAria': 'Weitere Block-Einträge laden',
    'feed.serverEmpty': 'Noch keine Blöcke im Fenster – der Server-Walk füllt es alle 5 Minuten.',
    'feed.windowNote': 'Server-Fenster: {range} · {blocks} Blöcke · {txns} Txs · {flagged} geflaggte Blöcke · Stand {time}',
    'feed.persistOff': 'Persistenz nicht konfiguriert – das Server-Fenster ist leer. Aktiviere den Live-Modus für die direkte Analyse.',
    'feed.windowError': 'Server-Fenster nicht erreichbar ({msg})',
    /* Ehrliche Retention-Grenze (Kritik-Runde 3): das Block-Fenster endet bei
       7 Tagen — 30 T/90 T zeigen den persistierten Betrugsgestand, nie Blockkarten. */
    'feed.windowBeyondBlockRetention': 'Das Block-Fenster deckt nur 24 h / 3 T / 7 T ab – die Fenster 30 T / 90 T zeigen den persistierten Betrugsbestand in Graph, Cluster-Karten und Drilldown, nicht als Block-Karten.',
    'chart.aria': 'Stündliche Aktivität im gewählten Fenster: Transaktionen pro Stunde, geflaggte Stunden hervorgehoben',
    'chart.flagged': 'geflaggte Stunden: {n}',
    'conn.server': 'Server-Daten – Fenster aktualisiert',
    'conn.serverLoading': 'Server-Daten – Fenster wird geladen …',
    'conn.serverNoData': 'Server-Daten – keine Blöcke im Fenster',
    'conn.serverError': 'Server-Daten nicht erreichbar ({msg})',
    'conn.liveInit': 'Live-Modus – verbinde zu honeycluster.io …',
    'conn.liveOff': 'Live-Modus beendet – Server-Daten wieder aktiv',
    'conn.liveClosed': 'Live-Modus getrennt – erneuter Versuch in {s} s',
    'conn.liveNoEvents': 'Live-Modus – WSS verbunden, warte auf Ledger …',
    'conn.liveThrottled': 'Live-Modus – Endpunkt-Drosselung: rate limit{est}',
    'conn.liveRejected': 'Live-Modus – WSS-Abo abgelehnt: {error}{est}',
    'log.consoleLiveUnavailable': 'Ratenbegrenzer nicht verfügbar – Live-Modus kann nicht starten (fail-closed).',
    'log.consoleLiveThrottled': 'Live-Modus: Ledger-Kommando gedrosselt ({error}){msg}.',

    /* drilldown.js — Modal */
    'modal.closeAria': 'Schließen',
    'modal.graphAria': 'Cluster-Graph',
    'modal.detailsAria': 'Cluster-Details',
    'modal.rolesAria': 'Rollen-Verteilung',
    'modal.timelineAria': 'Zeitachse der Transaktionen',
    'modal.chainAria': 'Flusskette Source bis Kollektor',
    'modal.tableAria': 'Konten des Clusters',
    'modal.takeover': 'Cluster läuft unter neuer Kennung weiter – automatisch übernommen (nahtlose Übernahme über die Mitglieder-Schnittmenge).',
    'modal.stale': 'Stand {time} – Cluster nicht mehr im aktuellen Beobachtungsfenster.',
    'modal.frozen': 'Momentaufnahme vom {time} – Inhalte bleiben bis zum Schließen erhalten; die Liste dahinter läuft weiter.',
    'modal.gone': 'Cluster nicht mehr aktuell – dieser Cluster gehört nicht mehr zum aktuellen Beobachtungsfenster.',
    'modal.persisted': 'Stand {time} aus dem persistierten Bestand – Cluster ist nicht mehr im Live-Fenster.',
    'modal.rolesTitle': 'Rollen-Verteilung',
    'modal.roleBarAria': '{role}: {count} von {total} Konten ({pct} %)',
    'modal.timelineTitle': 'Zeitachse der Transaktionen',
    'modal.timelineAriaRange': 'Zeitachse von {from} bis {to} – {n} Transaktionen',
    'modal.timelineEmpty': 'Keine Zeitstempel im aktuellen Beobachtungsfenster.',
    'modal.timelineTxUnit': 'Transaktionen',
    'modal.chainTitle': 'Flusskette',
    'modal.chainNote': 'Pfade folgen nur Transaktionen des Beobachtungsfensters – keine vollständige Wallet-Historie, kein Schuldnachweis.',
    'modal.chainRoleAria': 'Konten des Clusters nach Rolle – keine Kanten im Beobachtungsfenster',
    'modal.chainEmpty': 'Keine Rollen-Kette im aktuellen Beobachtungsfenster.',
    'modal.tableTitle': 'Konten des Clusters',
    'modal.tableCaption': '{n} Konten – Rollen sind Heuristiken, kein Schuldnachweis',
    'modal.tableWrapAria': 'Konten-Tabelle, horizontal scrollbar',
    'modal.thAddr': 'Adresse',
    'modal.thExchange': 'Börse',
    'modal.thTag': 'Tag',
    'modal.thRole': 'Rolle',
    'modal.thSeverity': 'Schweregrad',
    'modal.thIn': 'Eingehende Drops',
    'modal.thOut': 'Ausgehende Drops',
    'modal.thEdges': 'Kanten (in / aus)',
    'modal.thActions': 'Aktionen',
    'modal.loading3d': '3D-Ansicht wird geladen …',
    'modal.fallback2d': '3D-Ansicht nicht verfügbar – 2D-Ausweichansicht (vis-network).',
    'modal.noGraph': 'Kein Graph verfügbar – Detaildaten in Rollen-Verteilung, Flusskette und Konten-Tabelle.',
    'modal.downloadJson': 'Als JSON herunterladen',
    'modal.downloadPng3d': '3D-Graph als PNG herunterladen',
    'modal.downloadPng2d': 'Graph als PNG herunterladen (2D-Ausweichansicht)',
    'modal.graph3dLegend': 'Ring um einen Knoten = Drainer-Konto.',

    /* globe.js */
    'globe.note': 'Positionen sind deterministisch aus dem Adress-Hash abgeleitet — das XRPL-Ledger enthält keine Standortdaten. Die Kugel ist eine symbolische Aktivitätsansicht; die Länderzuordnung über die Börsen-Registry ist derzeit nicht verfügbar.',
    'globe.noteCountries': 'Ländergrenzen: Natural Earth (TopoJSON). Länderzuordnung ausschließlich über die Börsen-Registry (Sitzländer der Börsen); Adressen ohne Zuordnung bleiben deterministisch aus dem Adress-Hash platziert — das XRPL-Ledger selbst enthält keine Standortdaten.',
    'globe.ariaCountries': 'Weltkugel der Live-Aktivität mit Ländergrenzen; Länderzuordnung ausschließlich über die Börsen-Registry, Adressen ohne Zuordnung symbolisch platziert',
    'globe.ariaFailed': 'Weltkugel der Live-Aktivität; die Länderzuordnung über die Börsen-Registry ist derzeit nicht verfügbar, Positionen bleiben symbolisch aus dem Adress-Hash abgeleitet',
    'globe.ctxLost': 'WebGL-Grafikkontext verloren — genau ein Wiederherstellungsversuch wird gestartet …',
    'globe.fallback': 'Weltkugel nicht verfügbar (WebGL oder CDN nicht erreichbar) — dieselben Daten stehen in den Cluster-Karten und in der Konten-Tabelle des Drilldowns.',
    'globe.rebuild': 'Weltkugel wird neu aufgebaut …',
    'globe.loading': 'Weltkugel wird geladen …',
    'globe.legendTitle': 'Länderaktivität',
    'globe.legendSrc': 'Zuordnung ausschließlich über die Börsen-Registry · Grenzen: Natural Earth (TopoJSON)',
    'globe.legendUnassigned': 'Adressen ohne Länderzuordnung: {n}',
    'globe.activity1': 'Aktivität',
    'globe.activityN': 'Aktivitäten',
    'globe.edge1': 'Kante',
    'globe.edgeN': 'Kanten',
    'globe.inflow': 'Zufluss',
    'globe.outflow': 'Abfluss',
    'globe.custody': 'Custody',
    'globe.exchanges': 'Börsen',
    'globe.tx1': 'Transaktion',
    'globe.txN': 'Transaktionen',

    /* account-check.js */
    'check.title': 'Konto-Check',
    'check.hint': 'Profiling-Report einer XRPL-Adresse gegen Threat-Liste, Muster-Erkennung und Cluster-Heuristik.',
    'check.label': 'XRPL-Adresse (Pflichtfeld)',
    'check.go': 'Prüfen',
    'check.loading': 'Prüfe Konto …',
    'check.verdict.clean': 'sauber',
    'check.verdict.contact': 'risikobehaftet',
    'check.verdict.bad': 'bekannt maliziös',
    'check.verdict.unknown': 'unbekannt',
    'check.elig.ok': 'Voraussichtlich unproblematisch',
    'check.elig.review': 'Prüfungswürdig',
    'check.elig.unknown': 'Nicht bewertbar',
    'check.noAbzug': 'kein Abzug',
    'check.metaChecked': 'Geprüfte Transaktionen: ',
    'check.metaNetwork': 'Netzwerk: ',
    'check.metaAt': 'Geprüft am: ',
    'check.metaTruncated': 'max. 300 Txs geprüft — Aussage begrenzt',
    'check.roleEmpty': 'Keine Rollenbeteiligung im geprüften Fenster.',
    'check.roleIn': 'Eingang: {n} Kanten ({xrp} XRP)',
    'check.roleOut': 'Ausgang: {n} Kanten ({xrp} XRP)',
    'check.roleNote': 'Rolle gilt nur für das geprüfte Fenster — Heuristik aus Ein-/Ausgrad und Geldfluss, kein Schuldnachweis.',
    'check.patternsEmpty': 'Keine bekannten Muster im geprüften Fenster.',
    'check.contactsEmpty': 'Keine Kontakte zu gelisteten Adressen im geprüften Fenster.',
    'check.contactsAria': 'Kontakte zu gelisteten Adressen',
    'check.thCounterparty': 'Gegenpartei',
    'check.thDirection': 'Richtung',
    'check.thTxType': 'Tx-Typ',
    'check.thTime': 'Zeit',
    'check.thRisk': 'Risiko',
    'check.thNote': 'Notiz',
    'check.reportAria': 'Prüfbericht der geprüften Adresse',
    'check.scoreAria': 'Score von 100',
    'check.sectionScore': 'Score-Zusammensetzung',
    'check.sectionRole': 'Rollenbeteiligung',
    'check.sectionPatterns': 'Bekannte Muster',
    'check.sectionContacts': 'Kontakte zu gelisteten Adressen',
    'check.sectionEligibility': 'Off-Ramp-Einschätzung',
    'check.errInvalidAddr': 'Ungültige XRPL-Adresse (erwartet: r gefolgt von 24–34 Base58-Zeichen).',
    'check.errInvalid400': 'Ungültige oder nicht prüfbare Adresse.',
    'check.errLedger502': 'Ledger-Abfrage fehlgeschlagen',
    'check.errUnexpected': 'Unerwartete Antwort (HTTP {status}).',
    'check.errNetworkTitle': 'Netzwerkfehler',
    'check.errNetworkDetail': 'Der Konto-Check ist derzeit nicht erreichbar — bitte später erneut versuchen.',

    /* Zusammenfassung (Rebuild aus strukturierten Report-Feldern) */
    'summary.unknown': 'Nicht bewertbar — keine oder unvollständige Daten.',
    'summary.score': 'Score {score} von 100.',
    'summary.selfListed': 'Die Adresse ist selbst in der Bedrohungsliste gelistet.',
    'summary.malicious': '{n} verschiedene Gegenpartei(en) mit bekanntem Malicious-Status.',
    'summary.suspect': '{n} verschiedene Gegenpartei(en) mit Verdachts-Status.',
    'summary.noContacts': 'Keine Kontakte zu gelisteten Adressen im geprüften Fenster.',
    'summary.patterns': 'Muster-Funde: {list}.',

    /* Server-Phrasen (Exact-Match; Rohwerte bleiben Protokoll) */
    'srv.persistenz': 'Persistenz nicht konfiguriert',
    'srv.persistenzHost': 'Persistenz nicht konfiguriert — ohne Persistenz-Berechtigung liefert der Endpunkt keinen Flow-State.',
    'srv.eligUnknown': 'Nicht bewertbar — keine oder unvollständige Daten.',
    'srv.eligOk': 'Voraussichtlich unproblematisch für Off-Ramps (heuristisch).',
    'srv.eligReview': 'Prüfungswürdig — Ablehnung oder manuelle Prüfung durch den Anbieter ist wahrscheinlich.',
    'srv.disc1': 'Die Bewertung ist eine Heuristik über maximal die letzten 300 Transaktionen — ältere Kontakte und Muster sind nicht erfasst.',
    'srv.disc2': 'Rollen und Muster sind Heuristiken (Ein-/Ausgrad, Geldfluss) — kein Schuldnachweis, keine Rechts- oder Haftaussage.',
    'srv.disc3': 'Die Eligibility-Einschätzung ist eine Heuristik — die Entscheidung liegt beim Off-Ramp-Anbieter.',
    'srv.disc4': 'Die abgefragte Adresse wird nicht gespeichert.',

    /* history.js */
    'history.title': 'Maliziöse Historie',
    'history.hint': 'Persistente Historie ausschließlich als maliziös eingestufter Cluster — verdächtige (suspect) Cluster werden bewusst nicht persistiert.',
    'history.searchLabel': 'Suchen',
    'history.searchPlaceholder': 'Adresse, Cluster-Label oder Regel',
    'history.loading': 'Historie wird geladen …',
    'history.unconfigured': 'Historie-Persistenz ist auf diesem Server nicht konfiguriert — Meldungen werden nicht dauerhaft gespeichert.',
    'history.empty': 'Noch keine maliziösen Cluster in der Historie — sie füllt sich durch Live-Beobachtung und Besucher-Meldungen.',
    'history.errorHttp': 'Historie nicht erreichbar (HTTP {status})',
    'history.errorNet': 'Historie nicht erreichbar (Netzwerk)',
    'history.moreMembers': 'weitere {n} Mitglieder',
    'history.sightings': 'Von Besuchern gemeldet: {n}×',
    'history.unbestaetigt': 'unbestätigt · 1 Sichtung',
    'history.maliciousBadge': 'maliziös',

    /* history-host.html */
    'fh.title': 'Flow-Host: akkumulierter Cross-Block-Flow-State',
    'fh.navAria': 'Navigation',
    'fh.stateTitle': 'Akkumulierter Flow-State',
    'fh.stateHint': 'Cross-Block-Akkumulation des Ledger-Walks — Cursor-Stand und Cluster-View',
    'fh.refresh': 'Aktualisieren',
    'fh.walkAria': 'Walk-Status',
    'fh.cursor': 'Cursor-Stand',
    'fh.lag': 'Rückstand',
    'fh.updated': 'Stand',
    'fh.graphEmpty': 'Keine retained Fluss-Kanten im akkumulierten State — der Flow-Graph bleibt leer.',
    'fh.graphNote': 'Flow-Graph aus den BEGRENZTEN retained Fluss-Kanten + Rollen des akkumulierten States (lib/ledger-walk.mjs). Positionen sind deterministisch kreisförmig abgeleitet — das XRPL-Ledger enthält keine Standortdaten; die Darstellung ist eine symbolische Flussansicht.',
    'fh.clustersTitle': 'Cluster',
    'fh.clustersHint': 'Sortiert nach Volumen (absteigend), dann Transaktionszahl (absteigend)',
    'fh.empty': 'Noch kein akkumulierter Flow-State — der Walk hat noch keine Cluster gebildet.',
    'fh.emptyNoPersist': 'Kein Flow-State verfügbar.',
    'fh.statusPersist': 'Persistenz nicht konfiguriert — ohne Persistenz-Berechtigung liefert der Endpunkt keinen Flow-State.',
    'fh.statusHint': 'Hinweis: {reason}',
    'fh.unreachable': 'Flow-State nicht erreichbar — bitte später erneut versuchen.',
    'fh.graphAria': 'Flow-Graph des akkumulierten States',

    /* about.html — Info-Seite für die XRPL-Community (eigenständige Seite im
       App-Shell-Look, Muster history-host.html). Alle Inhalte via data-i18n;
       Begriffe folgen exakt der Engine-Forensik (lib/detector.mjs,
       lib/cluster.mjs, lib/tag-identity.mjs, lib/entity-resolve.mjs,
       lib/flow-state.mjs, lib/block-window.mjs, lib/account-report.mjs). */
    'about.sub': 'Zweck, Erkennungsmethoden, Glossar und Grenzen des Dashboards',
    'about.missionTitle': 'Wofür dieses Dashboard gedacht ist',
    'about.missionHint': 'Köderunabhängige Echtzeit-Analyse des öffentlichen Ledgers',
    'about.lead1': 'Honeypot XRPL ist ein offenes Echtzeit-Bedrohungs-Dashboard für die XRPL-Community. Jeder validierte Block des XRP-Ledger-Mainnet wird in Echtzeit auf Betrugs-, Phishing- und Draining-Muster geprüft; erkannte Akteure werden über ihren Geldfluss zu Clustern verbunden und mit Rollen (Source, Drainer, Kollektor, Relay) versehen.',
    'about.lead2': 'Die Analyse ist köderunabhängig: Zur Erkennung werden keine eigenen Köder- oder Honigfallen-Konten mehr eingesetzt. Die Daten stammen ausschließlich aus dem öffentlichen Ledger — im Live-Modus über eine direkte WSS-Verbindung zu honeycluster.io (ein Ledger-Kommando pro Block, ohne Stichproben), im Archiv-Modus über das persistierte Server-Fenster (24 Stunden bis 7 Tage). Kontonamen und Börsen-Zuordnungen kommen von xrpscan.com (CC BY-NC-SA 4.0).',
    'about.lead3': 'Dasselbe Analyse-Modul (lib/detector.mjs) läuft im Browser wie auf dem Server — die Live-Analyse im Browser liefert dieselben Funde wie der Server-Walk, der das Fenster im Hintergrund füllt.',
    'about.addressNote': 'Jede angezeigte Adresse ist eine Akteur-Adresse, die öffentlich im Ledger sichtbar ist, und wird vollständig angezeigt. Die Schutzschichten um die historischen Köder-Konten (Hash-Deny-Liste, serverseitige Sanitisierung) bleiben davon unberührt aktiv.',
    'about.detectTitle': 'Was erkannt wird',
    'about.detectHint': 'Rollen und Muster der Detektor-Engine — Heuristiken, kein Schuldnachweis',
    'about.rolesTitle': 'Rollen im Cluster-Graph',
    'about.roleDrainerT': 'Drainer',
    'about.roleDrainerD': 'Ein Konto, das von mindestens zwei verschiedenen Sendern aufgefüllt wurde und mindestens 90 % des Eingangs in einer Zahlung an ein einziges Ziel weiterleitet — das typische Muster eines abgeräumten Opfer-Kontos.',
    'about.roleCollectorT': 'Kollektor',
    'about.roleCollectorD': 'Ein Sammel-Konto mit mindestens drei Eingängen verschiedener Sender (davon mindestens einer geflaggt), höchstens zwei Ausgängen und klarer Akkumulation — dort, wo das Geld gebündelt wird.',
    'about.roleSourceT': 'Source',
    'about.roleSourceD': 'Ein Konto mit mindestens drei kleinen Ausgangs-Zahlungen (je höchstens 0,1 XRP) an geflaggte Ziele — typischer Absender von Dust- und Lockzahlungen.',
    'about.roleRelayT': 'Relay',
    'about.roleRelayD': 'Ein Durchleitungskonto mit ausgeglichenem Ein- und Ausgang (Differenz höchstens 50 % des größeren Werts) — Zwischenstation auf dem Weg des Geldes, nicht selbst Täter.',
    'about.patternsTitle': 'Muster und Verbindungen',
    'about.patDrainerT': 'Draining (Drainer-Sweep)',
    'about.patDrainerD': 'Ein frisch finanziertes Konto wird sofort wieder abgeräumt: Mindestens 90 % des Guthabens gehen in einer Zahlung an ein einziges Ziel. Nur mit Ledger-Beleg der Kontoerstellung — oder mit Entity-Snapshot-Beleg frischer Kontoaktivität über Tick-Grenzen hinweg — wird der Fund als maliziös eingestuft, ohne Beleg bleibt er verdächtig.',
    'about.patFreshProofT': 'Frische-Beleg (verifiedFresh)',
    'about.patFreshProofD': 'Die maliziöse Einstufung eines Drainer-Sweeps ruht auf einem zweiten Frische-Beleg: ein Ledger-Beleg der Kontoerstellung oder ein Entity-Snapshot-Beleg frischer Kontoaktivität innerhalb der letzten 21.600 Ledger (rund 24 Stunden). verifiedFresh ist ein zweiter Belegweg — nie alleinige Fundquelle und nie ein Downgrade; der Schwellenwert steht als verifiedFreshGapLedgers im maschinenlesbaren Regeln-Katalog des Dashboards.',
    'about.patCrossLedgerT': 'Cross-Ledger-Sweep',
    'about.patCrossLedgerD': 'Füttern und Abräumen über Blockgrenzen hinweg: Wird ein Konto in Ledger N finanziert und erst in Ledger N+1 abgeräumt, hält das Fenster-Gedächtnis der Engine den Sweep sichtbar. Auch zeitlich gestreckte Dusting-Kampagnen werden auf dieselbe Weise erkannt — über die Vereinigung ihrer Mini-Ziele im Fenster.',
    'about.patPeelingT': 'Peeling-Ketten',
    'about.patPeelingD': 'Gestaffelte Weiterleitung von 60 bis 95 % des Eingangs über ungeflaggte 1:1-Relays, ab drei Hops. Die Erkennung läuft über die Transaktionssicht und folgt auch unauffälligen Zwischenkonten, ohne ihnen eine Rolle zuzuweisen.',
    'about.patWashT': 'Wash Trading (Selbsttransfers)',
    'about.patWashD': 'Mindestens drei Selbstzahlungen desselben Kontos in einem Ledger (Absender und Empfänger sind identisch) — Volumenerzeugung ohne echte Gegenpartei, ein typisches Washing-Muster.',
    'about.patWashCycleT': 'Wash-Zyklus (Kreuz-Konto-Kreislauf)',
    'about.patWashCycleD': 'Mindestens zwei Zahlungen je Richtung zwischen denselben zwei Konten (A→B und B→A) mit mindestens 80 % Volumenerhalt innerhalb einer Stunde — Volumenerzeugung über zwei Identitäten. Einzelpaare bleiben ausgenommen (normale Rückerstattungen und Marktbewegungen), Börsen sind nie Zykelglied; die Fundklasse ist verdächtig.',
    'about.patMotifT': 'Motiv-Zähler (Gather-Scatter)',
    'about.patMotifD': 'Deterministische Zähler über die akkumulierten Fluss-Kanten — keine Lernarchitektur, null zusätzliche Requests. Gather-Scatter (Fan-In und Fan-Out von je mindestens 3 verschiedenen Gegenparteien an einem Knoten) wird als rein informative Notiz erfasst; die Wash-Zyklus-Schwellen oben stammen aus derselben Maschinerie. Ein Cluster trägt das motifs-Feld nur, wenn ein qualifiziertes Muster vorliegt — feldlos bedeutet kein Motiv. Alle Zähler und Kappen stehen im maschinenlesbaren Regeln-Katalog des Dashboards.',
    'about.patHubT': 'Hub-Verbindungen',
    'about.patHubD': 'Ungeflaggte Knoten mit mehr als 20 Fund-Kanten (Börsen-, Faucet- oder Sammel-Konten) werden aus der Cluster-Vereinigung herausgeschnitten: Zwei unabhängige Szenen verschmelzen nicht über eine gemeinsame Börse. Verbindungen, die über ein gemeinsames Börsen-Konto laufen (transit), werden als Durchleitung gekennzeichnet, nicht als direkte Nachbarschaft.',
    'about.patKnownBadT': 'Known-Bad-Kontakt',
    'about.patKnownBadD': 'Berührt eine Transaktion eine Adresse aus der Bedrohungsliste (kuratiert und aus der Honeypot-Historie abgeleitet), wird das als Treffer gemeldet — direkte Konto- oder Zahlungsberührung als maliziös, bloße Trustline- oder NFT-Positionen nur als verdächtig.',
    'about.detectNote': 'Der Regelkatalog der Engine umfasst fünfzehn Regeln — neben den obigen unter anderem Memo-Phishing (URLs und Seed-Muster in Zahlungsmemos), Dusting (Mini-XRP an frische Konten), Fake-NFT-Betrug, Airdrop-TrustSet-Spam, Zahlungs-Bursts, Offer-Spam, AMM-Washing, Thin-Pool-Exploits und Spoof-Offer-Zyklen. Jede Regel trägt einen Schweregrad; alle Zuordnungen sind Heuristiken, kein Schuldnachweis.',
    'about.detectApi': 'Alle Schwellen der Regeln mit numerischen Schwellen sind im Regeln-Katalog des Dashboards (thresholds je Regel) maschinenlesbar, und der ausgelieferte Commit steht im Response-Header x-deploy-commit desselben Endpoints.',
    'about.glossaryTitle': 'Begriffs-Glossar',
    'about.glossaryHint': 'Die Begriffe der Oberfläche — kurz und präzise',
    'about.gClusterT': 'Cluster',
    'about.gClusterD': 'Eine Gruppe von Adressen, die über Geldfluss-Kanten (Transaktionen mit mindestens einem geflaggten Endpunkt) zusammenhängen. Cluster entstehen per Union-Find, tragen Label wie „Cluster A“ und verfolgen Mitglieder, Rollen, Volumen sowie erste und letzte Sichtung.',
    'about.gSeverityT': 'Schweregrad (Severity)',
    'about.gSeverityD': 'Die Engine vergibt die Stufen maliziös, verdächtig und info. Der Konto-Check nennt in seinem Urteil bekannt maliziös, risikobehaftet (Kontakt zu gelisteten Adressen), sauber oder unbekannt und ergänzt eine Off-Ramp-Einschätzung (voraussichtlich unproblematisch, prüfungswürdig, nicht bewertbar). Adressen auf Whitelists (bekannte Gateways, Börsen) gelten als benigne — Ausnahme von den Breiten-Regeln als False-Positive-Schutz, keine Wertung.',
    'about.gTagT': 'Destination-Tag und Transit',
    'about.gTagD': 'Börsen-Konten sind Hosted-Accounts: Viele Nutzer teilen eine r-Adresse und werden über den 32-Bit-Destination-Tag unterschieden. Zeigen die Eingänge am selben Börsen-Konto mindestens zwei verschiedene Tag-Identitäten, gilt die Verbindung als transit — sie läuft über ein gemeinsames Börsen-Konto und ist keine direkte Nachbarschaft.',
    'about.gEntityT': 'Entity-Auflösung',
    'about.gEntityD': 'Kontroll-Cluster über kryptografische Signale statt Geldfluss: RegularKey, Signer-Listen-Fingerprint, EmailHash und gemeinsame Sponsor-Adresse (Finanzierungsquelle) vereinigen Konten zu einer Entität. Domains zählen erst nach beidseitiger Verifikation über xrp-ledger.toml; Join-Keys, die mehr als 20 Adressen tragen (Hubs), werden ausgeschlossen.',
    'about.gWindowT': 'Block-Fenster vs. persistenter Cluster-Bestand',
    'about.gWindowD': 'Das Block-Fenster ist der rollende, persistierte Bestand hinter der Archiv-Ansicht (24 Stunden / 3 Tage / 7 Tage): stündliche Rollups plus Details ausschließlich der geflaggten Transaktionen, sieben Tage Retention. Der persistente Cluster-Bestand (Flow-State) ist davon unabhängig: Er akkumuliert Cluster über den Lauf eines Server-Walks mit Cursor, hält sie höchstens sieben Tage nach der letzten Sichtung (danach die Top 200 nach Volumen) und füllt den Flow-Host.',
    'about.gHistArchT': 'Historie vs. Archiv',
    'about.gHistArchD': 'Die Historie sammelt dauerhaft jeden Cluster, der als maliziös eingestuft wurde — unabhängig vom Live-Feed, unter anderem durch Meldungen von Besuchern. Das Archiv im Dashboard zeigt nur das persistierte Block-Fenster (24 Stunden bis 7 Tage). Für die Rückwärtssuche pro Adresse existiert ein eigenes Archiv aus Tages-Chunks: Registry-verknüpfte Cluster bleiben 180 Tage abrufbar, maliziöse 30 Tage.',
    'about.limitsTitle': 'Ehrliche Grenzen',
    'about.limitsHint': 'Was dieses Dashboard leisten kann — und was nicht',
    'about.limit1': 'Alle Rollen und Muster sind Heuristiken aus Ein-/Ausgrad und Geldfluss. Sie benennen Auffälligkeiten, keine Täter — kein Schuldnachweis, keine Rechts- oder Haftaussage.',
    'about.limit2': 'Es gibt kein 100-%-Versprechen: Nicht jede Masche trifft eine Regel, und Regeln können ohne Kontext danebenliegen. Gegenlesen über die Transaktionen auf dem öffentlichen Ledger ist ausdrücklich erwünscht.',
    'about.limit3': 'Der Konto-Check bewertet höchstens die letzten 300 Transaktionen der abgefragten Adresse — ältere Kontakte und Muster sind nicht erfasst. Die abgefragte Adresse wird nicht gespeichert.',
    'about.limit4': 'Die Analyse läuft gegen öffentliche Endpunkte mit Rate-Limits (honeycluster.io). Der Server-Walk füllt das Fenster alle fünf Minuten; Live-Modus und Endpunkte drosseln und cachen (60 s) — unter Last können Ansichten kurz hinterherlaufen oder ausfallen (fail-closed statt Erfolgs-Vortäuschung).',
    'about.limit5': 'Die Archiv-Rückwärtssuche liest Tages-Blöcke mit begrenztem Lese-Budget (standardmäßig 62 Tage): Die 180-Tage-Retention registry-verknüpfter Cluster übersteigt die Abfragbarkeit — alte Fenster können abgeschnitten sein (als truncated gekennzeichnet).',
    'about.limit6': 'Die Off-Ramp-Einschätzung des Konto-Checks ist eine Heuristik — die Entscheidung über Auszahlungen liegt beim jeweiligen Anbieter.',
    'about.sourcesTitle': 'Datenquellen',
    'about.sourcesNote': 'Ledger-Daten: XRP-Ledger-Mainnet über honeycluster.io (WSS/JSON-RPC). Kontonamen und Börsen-Zuordnung: xrpscan.com (CC BY-NC-SA 4.0). Ländergrenzen der Weltkugel: Natural Earth (TopoJSON). Jede Fund-Adresse ist direkt auf dem öffentlichen Ledger nachvollziehbar.',

    /* Schweregrade */
    'sev.malicious': 'maliziös',
    'sev.suspect': 'verdächtig',
    'sev.info': 'info',

    /* Regel-Namen (lib/detector.mjs RULES, ids unverändert) */
    'rule.known-bad-hit': 'Known-Bad-Treffer (Honeypot-abgeleitet + Kuratierung)',
    'rule.memo-phishing': 'Memo-Phishing (URLs/Seed-Muster in Zahlungen)',
    'rule.drainer-sweep': 'Drainer — frisch finanziert, sofort abgeräumt',
    'rule.airdrop-trustset-spam': 'Fake-Airdrop-TrustSet-Spam',
    'rule.dusting': 'Dusting — Mini-XRP an frische Konten',
    'rule.fake-nft-fraud': 'Fake-NFT-Betrug',
    'rule.escrow-check-bait': 'Escrow/Check-Köder an frische Konten',
    'rule.payment-burst': 'Zahlungs-Burst (Airdrop-Verteilung)',
    'rule.offer-spam': 'Offer-Spam (OfferCreate-Kaskaden ohne Fill)',
    'rule.wash-self-transfer': 'Washing — Selbsttransfer (Volumenerzeugung)',
    'rule.peeling-chain': 'Peeling-Kette (gestaffelte Weiterleitung 60–90 %)',
    'rule.wash-cycle': 'Wash-Zyklus (Kreuz-Konto-Kreislauf mit Volumenerhalt)',
    'rule.amm-wash-swap': 'AMM-Washing — bidirektionaler Selbstzyklus mit Volumenerhalt',
    'rule.thin-pool-exploit': 'Thin-Pool-Exploit — Preisimpact in dünner Liquidität',
    'rule.spoof-offer-cycle': 'Spoof-Offers — Place-and-Pull-Zyklen im Orderbuch',
    'rule.amm-pool-drain': 'AMM-Pool-Abfluss — >= 50 % des XRP-Pools in einer Transaktion',
    'rule.validator-unl-change': 'Validator-UNL geändert (ttUNL_MODIFY)',
    'rule.amendment-enabled': 'Amendment aktiviert (ttAMENDMENT)',
    'rule.fee-change': 'Netzwerk-Gebühr geändert (ttFEE)',
    'rule.account-delete-sweep': 'Kontolöschung-Welle — mehrere AccountDelete an ein Ziel',
    'rule.mass-sweep-convergence': 'Massen-Sweep — viele Konten leeren Vollsaldo an ein Ziel',
    'rule.batch-inner-control': 'Batch-Inner: Konto-Steuerung versteckt in einem Batch (XLS-56)',
    'note.account-delete-sweep': '{n} Kontolöschungen mit Restguthaben an dasselbe Ziel in einem Ledger.',
    'note.mass-sweep-convergence': '{n} Konten leeren Vollsaldo an dasselbe Ziel in einem Ledger.',
    'note.batch-inner-control': '{type} als Inner-Transaktion in einem Batch versteckt (Parent {parent}) — Kontrollwechsel getarnt als harmlose Signatur.',
    'pattern.title': 'Netzwerk-Lastmuster',
    'validator.title': 'Validator-Gesundheit',
    'vt.close': 'Schließen',
    'vt.gaps': 'Aufzeichnungslücken – in diesen Spannen ist keine Aussage möglich',
    'vt.loading': 'Trace wird geladen …',
    'vt.error': 'Trace konnte nicht geladen werden.',
    'vt.unavailable': 'Kein Trace-Speicher auf diesem Host – der Recorder (monitor/validator-trace.mjs) muss dauerhaft laufen, um Historie zu sammeln.',
    'vt.note': 'Der Trace zeigt WAS je Ledger passiert ist. Die Ursachen-Tags sind Korrelationen im selben Ledger (Last, Amendments, neue Transaktionstypen, UNL-Änderungen) – Hinweise für die Untersuchung, keine bewiesenen Ursachen.',
    'vt.range.1h': 'letzte Stunde', 'vt.range.24h': '24 h', 'vt.range.7d': '7 Tage', 'vt.range.all': 'seit Start',
    'vt.k.ok': 'ok', 'vt.k.partial': 'partiell', 'vt.k.missed': 'verpasst', 'vt.k.no-quorum': 'kein Quorum', 'vt.k.wrong-hash': 'falscher Hash', 'vt.k.observed': 'beobachtet',
    'vt.model3d': 'Abweichungsprofil (3D)', 'vt.patterns': 'Korrelationen', 'vt.timeline': 'Zeitleiste',
    'vt.noIncidents': 'Keine Abweichungen in diesem Zeitraum.', 'vt.noPatterns': 'Keine wiederkehrenden Korrelationen.',
    'vt.type.missed': 'verpasst', 'vt.type.partial': 'partielle Validierung', 'vt.type.wrong-hash': 'falscher Hash', 'vt.type.no-quorum': 'nicht abgestimmt (Netzstockung)',
    'vt.ledger': 'Ledger', 'vt.validators': 'Validatoren', 'vt.ledgers': 'Ledger',
    'vt.crossTitle': 'Muster über alle Validatoren', 'vt.incidentsTotal': '{n} Abweichungen in diesem Zeitraum',
    'vt.recurring': 'Wiederkehrende Korrelationen', 'vt.noRecurring': 'Noch keine Korrelation über mehrere Validatoren hinweg.',
    'vt.perValidator': 'Je Validator', 'vt.openPatterns': 'Muster über alle Validatoren',
    'vt.tag.load-spike': 'Lastspitze', 'vt.tag.amendment-activity': 'Amendment-Aktivität', 'vt.tag.unl-change': 'UNL-Änderung',
    'vt.tag.new-tx-type': 'neuer Transaktionstyp', 'vt.tag.no-quorum': 'kein Quorum', 'vt.tag.partial-validation': 'partielle Validierung',
    'vt.tag.signed-different-hash': 'anderen Hash signiert', 'vt.tag.no-correlated-cause': 'keine Korrelation in diesem Ledger',
    'vt.tag.detail-unavailable': 'Ledger-Details nicht verfügbar', 'vt.tag.detail-skipped': 'Ledger-Details übersprungen (Last)',
    'vt.master': 'Master-Schlüssel', 'vt.ref': 'Referenz (xrpscan-Agreement)',
    'vt.coverage': 'Aufzeichnung', 'vt.coverageVal': '{ledgers} Ledger über {days} Tag(e) · {span} · {gaps} Lücken-Ledger · {qf} ohne Quorum',
    'vt.inWindow': 'im gewählten Zeitraum', 'vt.estimated': 'geschätzt', 'vt.totals': 'gesamt seit Aufzeichnungsbeginn',
    'vt.nodata': 'Keine Aufzeichnungsdaten für diesen Validator in den geladenen Tagen – in den aufgezeichneten Spannen war er unauffällig oder noch nicht beobachtet.',
    'vt.profileEmpty': 'Keine Abweichungen in diesem Zeitraum – das Profil hat nichts zu zeichnen.',
    'vt.profileMeta': '{buckets} Zeitintervalle · {from} → {to} UTC · Achsenspitze {peak} ({scale})',
    'vt.axisScaleLinear': 'lineare Skala: ein Gitterintervall je Vorfall',
    'vt.axisScaleRoot': 'Wurzel-Skala, damit kleine Werte sichtbar bleiben',
    'vt.profileHint': 'Säulen mit der Maus oder per Tab durchgehen – je Intervall die Aufschlüsselung; der erste Streifen zeigt den Intervallzustand, der zweite die gemessene Transaktions-Signatur.',
    'vt.bucketAria': '{label} UTC · {total} Abweichungen: {missed} verpasst, {partial} partiell, {wrongHash} falscher Hash, {noQuorum} kein Quorum · {ledgers} Ledger beobachtet · {cohort} · {signatures} Tx-Signaturen',
    'vt.bucketReadout': '{label} UTC · {total} Abweichungen ({missed} verpasst, {partial} partiell, {wrongHash} falscher Hash, {noQuorum} kein Quorum) · {ledgers} Ledger beobachtet · {cohort} · {signatures} Tx-Signaturen',
  'vt.cohortCount': '{n} Validaten betroffen im selben Ledger',
  'vt.cohortUnknown': 'Kohorte für diesen Tag nicht erfasst',
  'vt.heatAria': 'Intervallstreifen: beobachtet ohne Abweichung, Abweichung nach Kohortenbreite, oder Intervall ohne Aufzeichnung',
  'vt.state.clean': 'beobachtet, keine Abweichung',
  'vt.state.solo': 'solo – nur dieser Validator',
  'vt.state.cohort': 'wenige Mit-Validatoren – 2 bis 4',
  'vt.state.network': 'Netzereignis – 5 oder mehr Validatoren',
  'vt.state.unknown': 'Abweichung, Kohorte nicht erfasst',
  'vt.state.none': 'kein Ledger in diesem Intervall beobachtet',
  'vt.sign.hit': 'Transaktions-Signatur gemessen',
  'vt.sign.clear': 'beobachtet, keine Signatur',
  'vt.sign.unknown': 'Tx-Forensik nicht erfasst',
  'vt.sign.none': 'nicht beobachtet',
  'vt.signAria': 'Signaturstreifen: ob die Transaktions-Forensik an den Ausfall-Ledern dieses Validators eine Form gemessen hat',
  'vt.signCoverage': 'Transaktions-Forensik: {seen} Ledger mit erfasster Transaktions-Form, {missing} Ledger hatten Transaktionen ohne erfasste Form.',
  'vt.signAbsent': 'Transaktions-Forensik hat noch keinen erfassten Ledger – die Signaturebene bleibt leer, bis der Recorder mit dem transactions-Stream läuft.',
  'vt.profileNoProfile': 'Profil nicht möglich: die API hat keine Intervall-Daten geliefert.',
    'vt.retraceTitle': 'Retrace – warum das passierte',
    'vt.retraceNote': 'Je Abweichung: was auf diesem Ledger gemessen wurde, wie viele andere Validatoren derselbe Ledger betraf, und wie hoch das Ausfallrisiko bei dieser Anomalie ist. Korrelation in einem Ledger, nie eine bewiesene Ursache.',
    'vt.noRetrace': 'Keine Retrace-Daten für diesen Validator in diesem Zeitraum.',
    'vt.retraceShowing': '{shown} von {total} retraceten Abweichungen gezeigt',
    'vt.hypotheses': 'Hypothesen (Rangfolge)',
    'vt.nextCheck': 'Nächster Prüfschritt',
    'vt.dataGaps': 'Datenlücken',
    'vt.strength.measured': 'auf diesem Ledger gemessen',
    'vt.strength.correlated': 'in diesem Ledger korreliert',
    'vt.strength.cohort': 'Kohorten-Muster',
    'vt.strength.none': 'keine Korrelation gefunden',
    'vt.scope.solo': 'nur dieser Knoten',
    'vt.scope.cohort': 'mehrere Validatoren',
    'vt.scope.network': 'netzweit',
    'vt.scope.unknown': 'nicht eingeordnet',
    'vt.metric.quorum': 'Quorum', 'vt.metric.split': 'Hash-Spaltung', 'vt.metric.load': 'Last', 'vt.metric.gap': 'Close-Abstand', 'vt.metric.cohort': 'Kohorte',
    'vt.mQuorum': '{top}/{needed} Stimmen · Rand {margin}',
    'vt.mSplit': '{runner} von {votes} Stimmen auf zweiter Hash-Linie',
    'vt.mLoad': '{tx} Txs gegen Median {med} ({ratio}×)',
    'vt.mGap': '{gap} s seit vorherigem Close',
    'vt.mCohort': '{n} Validatoren betroffen · {others} andere',
    'vt.evMargin': '{top}/{needed} Stimmen erreicht, Rand {margin}',
    'vt.evSplit': 'zweite Hash-Linie mit {runner} Stimmen ({votes} gesamt)',
    'vt.evLoad': '{tx} Txs gegen Median {med} = {ratio}×',
    'vt.evGap': '{gap} s seit vorherigem Close, Median {med} s',
    'vt.evCohort': '{n} Validatoren auf diesem Ledger betroffen, {others} andere',
    'vt.evFanout': '{fanout} verschiedene Empfänger eines Kontos mit {txs} Txs in diesem Ledger ({ledgerTx} Txs gesamt)',
    'vt.evBurst': '{accountTx} Txs eines Kontos = {share} % dieses Ledgers',
    'vt.evFailure': '{failed} gescheiterte Txs = {share} % dieses Ledgers',
    'vt.evBatch': '{batchTx} Batch-Txs mit {innerTx} Inner-Transaktionen',
    'vt.evFee': 'höchste Gebühr {maxFee} Drops gegen Median {medianFee} Drops',
    'vt.evFeature': '{featureTx} Netzwerk-Transaktion(en) in diesem Ledger',
    'vt.evCount': '{count} gegen Basis-Median {baseline}',
    'vt.evRatio': '{count} gegen Basis {baseline} = {ratio}×',
    'vt.evSweep': '{destinations} verschiedene Empfänger über {ledgers} Ledger ({txs} Txs)',
    'vt.sigTitle': 'Transaktions-Signaturbord',
    'vt.sigNote': 'Welche Transaktionsformen in Ledgern auftreten und wie stark sie mit Validator-Ausfällen zusammengehen. Gezählt über jeden beobachteten Ledger, nicht über eine Auswahl – eine Signatur ohne Ledger-Zähler bleibt unzuverlässig.',
    'vt.sigEmpty': 'Noch keine Transaktions-Signatur gemessen – diese Ebene braucht Ledger mit erfasster Transaktions-Form.',
    'vt.sig.hTag': 'Signatur',
    'vt.sig.hLedgers': 'Ledger',
    'vt.sig.hFails': 'mit Ausfall',
    'vt.sig.hLift': 'Ausfall-Anstieg',
    'vt.sig.hSample': 'Beispiel-Ledger',
    'vt.sigSample': 'Ledger {ledger} um {time} UTC',
    'vt.sigCoverage': '{seen} Ledger mit erfasster Transaktions-Form, {missing} ohne',
    'vt.liftVal': 'Risiko ×{lift} ({with} % mit dieser Anomalie gegen {without} % ohne)',
    'vt.datagap.forensics-not-recorded': 'Ledger-Forensik für diesen Tag wurde noch nicht aufgezeichnet',
    'vt.datagap.forensics-truncated': 'Ledger-Forensik ist gekürzt (Tageslimit erreicht)',
    'vt.datagap.tx-shape-not-recorded': 'Transaktions-Form für diesen Ledger wurde nicht aufgezeichnet (transactions-Stream aus oder Daten vor dieser Stufe)',
    'vt.riskTitle': 'Ausfallrisiko je Anomalie',
    'vt.riskNote': 'Wie oft ein Ledger ausfällt, wenn diese Anomalie vorliegt, gegen Ledger ohne sie. Ohne diese Vergleichszahl ist jede Ursache eine Anekdote. Zu kleine Stichproben bleiben als solche gekennzeichnet.',
    'vt.riskNone': 'Noch keine Anomalie-Statistik – der Recorder muss zuerst Ledger mit Anomalien beobachten.',
    'vt.risk.hAnomaly': 'Anomalie', 'vt.risk.hLedgers': 'Ledger damit', 'vt.risk.hFails': 'davon fehlgeschlagen', 'vt.risk.hRate': 'Ausfallrate damit', 'vt.risk.hBase': 'ohne', 'vt.risk.hLift': 'Risikofaktor',
    'vt.riskSmall': 'Stichprobe zu klein',
    'vt.riskBase': 'Grundlage: {ledgers} beobachtete Ledger, {fails} davon mit einer Abweichung',
    'vt.riskTrunc': 'Die Ledger-Forensik ist gekürzt (Tageslimit), die Anomalie-Zahlen sind deshalb eine Untergrenze.',
    'vt.attackTitle': 'Gleichzeitige Ausfälle',
    'vt.attackNote': 'Viele Validatoren, derselbe Ledger. Hier zeigen sich Netzstockungen, Versionskonflikte und Angriffe auf Validatoren – gereiht nach der Zahl gleichzeitig Betroffener, nicht nach Bauchgefühl.',
    'vt.attackNone': 'Kein Ledger in diesem Zeitraum betraf mehrere Validatoren gleichzeitig.',
    'vt.attackThreshold': 'ab {n} betroffenen Validatoren je Ledger · {total} solche Ledger in diesem Zeitraum',
    'vt.attackAffected': '{n} Validatoren',
    'vt.tag.quorum-thin': 'Quorum nur knapp erreicht',
    'vt.tag.hash-split': 'zwei Hash-Linien in der Abstimmung',
    'vt.tag.load-extreme': 'extreme Transaktionslast',
    'vt.tag.close-gap': 'ungewöhnlich lange Zeit zwischen Closes',
    'vt.tag.cohort-event': 'mehrere Validatoren betroffen',
    'vt.tag.solo-failure': 'nur dieser Validator betroffen',
    'vt.g.network-stall': 'Netzstockung und Peer-Verbindung des Knotens prüfen',
    'vt.g.cohort-network': 'Mit Peers vergleichen – mehrere Validatoren verfehlten denselben Ledger',
    'vt.g.solo-peering': 'Peering und UNL-Sicht dieses Knotens prüfen',
    'vt.g.solo-resources': 'Ressourcen, Disk-I/O und rippled-Log zum Zeitpunkt prüfen',
    'vt.g.version-state': 'rippled-Version und Amendment-Status prüfen',
    'vt.g.report-split': 'Zwei Hash-Linien vorhanden – prüfen, welche Linie dieser Knoten signiert hat',
    'vt.g.load-backlog': 'Ledger-Durchsatz und Validierungs-Rückstau prüfen',
    'vt.g.unl-membership': 'UNL-Mitgliedschaften um diesen Ledger prüfen',
    'vt.g.parser-version': 'Prüfen, ob dieser Knoten den Transaktionstyp unterstützt',
    'vt.g.quorum-margin': 'Quorum-Einstellungen und Anzahl vertrauter Peers prüfen',
    'vt.g.unknown-cause': 'Keine Korrelation – Knoten-Log für diesen Ledger prüfen',
    'vt.g.attack-drainer': 'Drainer-Muster auf diesem Ledger gemessen – prüfen, welches Konto hier fächerte, und betroffene Zahlungen einfrieren',
    'vt.g.attack-burst': 'Ein Konto dominierte diesen Ledger – Konto, Gebührensatz und Sequenz prüfen',
    'vt.g.attack-spam': 'Spam-Artige Aktivität in diesem Ledger (Orderbuch, NFT oder Konten) – betroffene Märkte prüfen',
    'vt.g.attack-failed-tx': 'Viele Transaktionen scheiterten in diesem Ledger – Engine-Ergebnisse und Ledger-Zustand prüfen',
    'vt.g.attack-amplify': 'Batch-Transaktionen verstärkten diesen Ledger – Inner-Transaktionen prüfen',
    'vt.g.attack-fee': 'Extreme Gebühren in diesem Ledger – Gebührenspitzen und Gebühreneskalation prüfen',
    'vt.g.attack-type-burst': 'Ein Transaktionstyp weit über seiner Basis – Typ und dessen Kosten prüfen',
     'vt.g.node-offline-window': 'Knoten war über eine Serie aufeinanderfolgender Ledger weg – Prozess-Laufzeit, Neustarts und rippled-Log ab dem ersten Ledger dieser Serie prüfen',
     'vt.g.degraded-signing': 'Knoten hat signiert, aber unvollständig – Vollständigkeit der Validierung und Auslastung des Knotens zu diesem Zeitpunkt prüfen',
     'vt.verdict.offline-window': 'Knoten über eine Ledger-Serie weg',
     'vt.verdict.brief-outage': 'kurzer Ausfall',
     'vt.verdict.short-series': 'zwei Ledger am Stück, unter der Ausfallschwelle',
     'vt.verdict.degraded-window': 'über eine Serie unvollständig signiert',
     'vt.verdict.degraded-single': 'in diesem Ledger unvollständig signiert',
     'vt.verdict.cohort-window': 'gemeinsames Fenster mit anderen Validatoren',
     'vt.verdict.network-window': 'über die ganze Serie kein Quorum',
     'vt.verdict.network-stall': 'kein Quorum erreicht',
     'vt.verdict.hash-divergence': 'anderen Hash signiert',
     'vt.verdict.isolated-miss': 'einzelner verpasster Ledger',
     'vt.fpverdict.clean': 'keine aufgezeichnete Abweichung',
     'vt.fpverdict.network-driven': 'gesunder Knoten – er fällt nur, wenn das Netz fällt',
     'vt.fpverdict.chronic-outage': 'chronischer Ausfall – seine Ausfälle kommen in eigenen Serien',
     'vt.fpverdict.solo-only': 'nur auf Ledgern ohne Netzereignis betroffen',
     'vt.fpverdict.outlier-node': 'weit über dem Netz-Median',
     'vt.fpverdict.intermittent': 'verstreute Einzelfälle',
     'vt.fpverdict.mixed': 'gemischtes Muster',
     'vt.win.class.cohort-under-attack': 'gemeinsames Fenster bei Angriffs-Last in diesen Ledgern',
     'vt.win.class.network-window': 'Netzfenster',
     'vt.win.class.targeted-under-load': 'eigenes Fenster dieses Knotens bei Angriffs-Last',
     'vt.win.class.overlapping-outage': 'überschneidend mit anderen Validatoren',
     'vt.win.class.targeted-outage': 'eigenes Fenster dieses Knotens',
     'vt.series.label': 'Serie',
     'vt.series.run': 'Ledger {from}-{to}, Position {position} von {ledgers} dieser Serie, {duration}, Urteil: {verdict}',
     'vt.series.single': 'einzelner Ledger – keine Serie',
     'vt.series.break': 'nach der Serie: {ledgers} Ledger dazwischen – {cause}',
     'vt.series.cause.validated': 'der Knoten validierte wieder',
     'vt.series.cause.recorder-gap': 'nicht aufgezeichnet, dort ist keine Aussage möglich',
     'vt.series.cause.unknown': 'Aufzeichnung an dieser Stelle unklar',
     'vt.fpTitle': 'Knoten-Signatur',
     'vt.fpNone': 'Noch keine Knoten-Signatur – der Recorder hat diesen Validator im gewählten Fenster nicht beobachtet.',
     'vt.fpNote': 'Netzproblem oder mein Problem? Eigene Ausfallrate gegen den Netz-Median, und wie viel davon auf Ledger fällt, in denen fast das ganze Netz gleichzeitig ausfiel.',
     'vt.fp.rate': 'eigene Ausfallrate',
     'vt.fp.medianRate': 'Netz-Median',
     'vt.fp.networkRate': 'Netz-Durchschnitt',
     'vt.fp.split': 'Netzereignisse gegen eigene Ledger',
     'vt.fp.splitVal': '{network} von {total} Ausfällen auf Netzereignis-Ledern ({share} %), {private} auf Ledgern, an denen nur dieser Knoten betroffen war',
     'vt.fp.series': 'in Serien aufeinanderfolgender Ledger',
     'vt.fp.seriesVal': '{share} % seiner Ausfälle ({isolated} Einzelfälle)',
     'vt.fp.longest': 'längste Serie',
     'vt.fp.longestVal': '{ledgers} Ledger am Stück ({duration})',
     'vt.fp.peak': 'Stoßzeiten (UTC)',
     'vt.fp.peakVal': '{share} % der Ausfälle konzentrieren sich auf {hours}',
     'vt.cqTitle': 'War mein Fehlen quorum-kritisch?',
     'vt.cqNote': 'Die Marge ist der Vorsprung der führenden Hash-Linie über die Quorum-Schwelle. Marge 0 heißt: Die Linie stand nur, weil genug andere da waren – die fehlende Stimme zählte. Ohne aufgezeichnete Forensik-Zeile bleibt die Frage offen.',
     'vt.cq.none': 'Für die verpassten Ledger dieses Knoten existiert keine Forensik-Zeile – die Frage ist offen, nicht beantwortet.',
     'vt.cq.summary': '{checked} von {absent} Abweichungs-Ledern haben eine Forensik-Zeile: {critical} an der Quorum-Marge, {followOn} mit Spielraum.',
     'vt.cq.hLedger': 'Ledger',
     'vt.cq.hType': 'Abweichung',
     'vt.cq.hVotes': 'Stimmen / nötig',
     'vt.cq.hTop': 'führende Linie',
     'vt.cq.hMargin': 'Marge',
     'vt.cq.hEffect': 'Wirkung',
     'vt.cq.critical': 'quorum-kritisch',
     'vt.cq.followOn': 'Netz hatte Spielraum',
     'vt.netTitle': 'Netzereignis oder eigenes Problem?',
     'vt.netNote': 'Ledger, in denen mindestens {n} Validatoren gleichzeitig ausfielen, sind Netzereignisse; alles andere ist privat. Beides zusammenzählen erzeugt einen Cluster aus fast allen Validatoren und macht aus einem Netzereignis geteilte Infrastruktur – das ist ein Messfehler, kein Befund.',
     'vt.net.summary': '{network} Netzereignis-Ledger, {private} Ledger mit einem oder wenigen betroffenen Knoten',
     'vt.net.none': 'Keine Validator-Ausfälle in diesem Fenster.',
     'vt.net.hValidator': 'Validator',
     'vt.net.hTotal': 'Ausfälle',
     'vt.net.hNetwork': 'auf Netzereignissen',
     'vt.net.hOwn': 'eigene Ledger',
     'vt.net.hShare': 'Netzanteil',
     'vt.clTitle': 'Kandidaten für geteilte Infrastruktur',
     'vt.clNote': 'Hier zählen nur private Ledger. Ein Paar braucht mindestens {co} gemeinsame Ledger, mindestens {lift} mal die unabhängige Zufallserwartung und eine Überlappung von mindestens {mutual} % in beide Richtungen. Darunter bleibt es ein Kandidat, nie ein Schluss.',
     'vt.cl.none': 'Kein Paar erreicht die Schwellen – in diesem Fenster kein Hinweis auf geteilte Infrastruktur.',
     'vt.cl.summary': '{pairs} Kandidaten-Paare über {private} private Ledger, {strong} erreichen die Schwellen',
     'vt.cl.members': 'gemeinsame Knotengruppe',
     'vt.cl.pairRow': '{a} + {b}: {co} gemeinsame Ledger, Lift ×{lift}, überlappend {mutual} %',
     'vt.winTitle': 'Ausfallfenster über die Validatoren',
     'vt.win.none': 'Keine Serie aufeinanderfolgender Ledger erreichte in diesem Fenster die Melde-Schwelle.',
     'vt.loadTitle': 'Last-Ausfall-Kurve',
     'vt.loadNote': 'Ab welcher Transaktions-Last pro Ledger dieser Knoten zurückfällt – und ab welcher die Kohorte dieselbe Last noch durchsteht. Die Ausfallrate allein beantwortet das nicht: ein Knoten, der bei jeder Last ausfällt, hat ein anderes Problem als einer, der erst unter Last ausfällt.',
     'vt.loadNetNote': 'Netz-Sicht: ab welcher Last die dUNL-Kohorte insgesamt zurückfällt. Ohne diesen Vergleich ist die Kurve eines einzelnen Knotens eine Zahl ohne Bedeutung.',
     'vt.load.none': 'Keine Last-Achse in diesem Fenster – der Recorder zählt Transaktionen je Ledger erst seit 2026-10-16. Ältere Tage sind eine Datenlücke, nicht „lastfest“.',
     'vt.load.hLoad': 'Tx je Ledger',
     'vt.load.hLedgers': 'Ledger',
     'vt.load.hFails': 'Ausfall-Ledger',
     'vt.load.hNetwork': 'Netz-Ausfallrate',
     'vt.load.hCohort': 'Kohortenmedian',
     'vt.load.hOwn': 'Eigene Ausfallrate',
     'vt.load.thin': 'zu dünn',
     'vt.load.baseline': 'Normalbetrieb: {label} Tx/Ledger ({n} Ledger)',
     'vt.load.ownCeiling': 'Eigene Lastgrenze: {label} Tx/Ledger ({rate} % Ausfall)',
     'vt.load.cohortCeiling': 'Lastgrenze des Kohortenmedians: {label} Tx/Ledger',
     'vt.load.netCeiling': 'Netz-Lastgrenze: {label} Tx/Ledger ({rate} % Ausfall)',
     'vt.load.verdict.load-limited': 'Fällt unter Last zurück – Kapazitätsbefund mit Handlungsweg',
     'vt.load.verdict.load-resilient': 'Keine Lastgrenze gemessen – die Ausfälle sind nicht lastgetrieben',
     'vt.load.verdict.always-failing': 'Fällt schon im Normalbetrieb aus – kein Kapazitätsproblem',
     'vt.load.verdict.unknown': 'Nicht urteilbar – zu wenige Ledger je Stufe',
     'vt.winNote': 'Ein Fenster pro Validator-Serie, eingeordnet nach dem Anteil dieser Ledger, den andere Validatoren ebenfalls verfehlten – zusammen mit der Transaktions-Form, die in dem Fenster gemessen wurde.',
     'vt.win.row': '{class} – {master} – Ledger {from}-{to} ({ledgers} am Stück, {duration}) – {coShare} % gemeinsam mit anderen',
    'validator.coverage': 'dUNL-Abdeckung: {matched} von {listed} Validatoren aus der Ripple-Validator-Liste (Sequenz {seq})',
    'validator.coverageFallback': 'dUNL-Liste nicht erreichbar – {n} Validatoren aus Registry-Tags (nicht gegen die signierte Liste geprüft)',
    'validator.hint': 'Agreement-Werte der öffentlichen UNL-Validatoren, jede Minute aktualisiert',
    'validator.empty': 'Noch keine Validator-Daten.',
    'validator.error': 'Validator-Daten derzeit nicht verfügbar (xrpscan) – es wird nichts geschätzt.',
    'validator.missed': 'verpasst',
    'validator.partial': '(teilweise)',
    'validator.attribution': 'Daten: xrpscan.com (CC BY-NC-SA 4.0)',
    'validator.alert.validator-revoked': 'Validator widerrufen',
    'validator.alert.agreement-drop': 'Agreement-Einbruch (1 h)',
    'validator.alert.missed-surge': 'Verpasst-Anstieg (1 h)',
    'validator.alert.signing-key-rotated': 'Signierschlüssel gewechselt',
    'validator.alert.unl-membership-changed': 'UNL-Zugehörigkeit geändert',
    'pattern.hint': 'Anomalien auf Ledger-Ebene (Lastspitzen, Close-Lücken, Fund-Bursts) mit UTC-Zeitstempel',
    'pattern.empty': 'Keine Anomalien im Stichprobenfenster – die Basis bildet sich noch oder das Netz ist ruhig.',
    'pattern.chartAria': 'Transaktionen je validiertem Ledger im Stichprobenfenster',
    'pattern.type.load-spike': 'Lastspitze',
    'pattern.type.close-gap': 'Close-Lücke',
    'pattern.type.fund-burst': 'Fund-Burst',
    'ticker.title': 'Live-Drainer-Ticker',
    'ticker.hint': 'Funde der letzten validierten Ledger, neueste zuerst',
    'ticker.empty': 'Noch keine Drainer-Aktivität beobachtet.',
    'note.amm-pool-drain': '{type}: {pct} % der {side}-Seite des Pools in einer Transaktion abgeflossen.',
    'note.validator-unl-change': 'Validator-UNL geändert (Pseudo-Transaktion, Validator-Set-Änderung).',
    'note.amendment-enabled': 'Amendment aktiviert (Pseudo-Transaktion).',
    'note.fee-change': 'Netzwerk-Gebühr-Parameter geändert (Pseudo-Transaktion).',

    /* Detector-Notes (noteKey/noteParams aus lib/detector.mjs) */
    'note.known-bad-hit': 'Bekannt-maliziöse Adresse beteiligt ({type}).',
    'note.memo-phishing-seed': 'Memo enthält Seed-Muster.',
    'note.memo-phishing-url': 'Memo enthält URL mit claim-/airdrop-/verify-Keyword.',
    'note.fake-nft-fraud-uri': 'NFTokenMint-URI enthält Phishing-/claim-Muster.',
    'note.escrow-check-bait-single': '{type} mit winziger Summe und Phishing-Memo an frisches Ziel {addr}.',
    'note.dusting-many': '{n} Mini-XRP-Zahlungen an verschiedene Ziele im Beobachtungsfenster.',
    'note.dusting-fresh': '{n} Mini-XRP-Zahlungen an frische Ziele in einem Ledger.',
    'note.drainer-sweep': 'Frisch finanziert und {pct} % an ein Ziel abgeräumt.',
    'note.offer-spam': '{n} OfferCreate ohne Fill in einem Ledger.',
    'note.fake-nft-fraud-accept': '{n} NFTokenAcceptOffer ohne Zahlung in einem Ledger.',
    'note.escrow-check-bait-burst': '{n} Escrow/Check-Köder an verschiedene frische Ziele.',
    'note.payment-burst': '{n} Zahlungen an verschiedene Ziele, davon {tiny} winzig (Airdrop-Verteilungsmuster).',
    'note.airdrop-trustset-spam': '{n} TrustSets mit winzigem Limit von verschiedenen Konten auf Issuer {issuer} in einem Ledger.',
    'note.wash-self-transfer': '{n} Selbstzahlungen in einem Ledger (Volumen-Washing).',
    'note.peeling-chain': 'Peeling-Kette: {hops} gestaffelte Hops (Ø {ratio} % Weiterleitung).',
    'note.fake-nft-fraud-fee': 'NFTokenMint mit Wucher-TransferFee ({pct} %).',
    'note.fake-nft-fraud-offer': '{n} NFTokenCreateOffer auf dasselbe Ziel {addr} in einem Ledger.',
    'note.amm-wash-swap': 'Bidirektionale OfferCreate-Fills auf {pair} im Volumen-Gleichgewicht (Volumenerhalt {conserve} %, Drift {drift} %).',
    'note.thin-pool-exploit': '{n} Fills auf {pair} mit >= {devPct} % Preisabweichung vom Fenster-Median in die günstige Richtung (dünner Pool).',
    'note.spoof-offer-cycle': '{n} Place-and-Pull-Zyklen (Create→Cancel <= {maxCancel} Ledger) auf {levels} Preislevel im Orderbuch.',

    /* index.html — Top-10-Börsen-Zuflüsse (Daten-Forensik 2026-10-07,
       public/exchange-outflows.mjs): ehrliche Box — Grenzen (50-Kanten-Deckel,
       Betrugs-Retention statt Wallet-Historie, Union-Erkennung) stehen in der
       Fußnote, der reale Abdeckungszeitraum (coverageFrom→generatedAt) wird
       dynamisch gerendert (#exout-coverage, Pflicht 11), der Cap-Hinweis nur
       bei belegter Kappung (#exout-capped). */
    'exout.title': 'Top-Börsen für abgeflossene Mittel',
    'exout.subtitle': 'Wo das meiste abgeflossene Geld landet — die Börsen selbst sind nicht die Täter.',
    'exout.window7': '7 Tage',
    'exout.window30': '30 Tage',
    'exout.windowAll': 'Gesamt',
    'exout.windowAria': 'Zeitfenster der Börsen-Zuflüsse',
    'exout.rank': 'Rang {n}',
    'exout.inflows': '{n} Kanten',
    'exout.inflows1': '1 Kante',
    'exout.clusters': '{n} Cluster',
    'exout.clusters1': '1 Cluster',
    'exout.transit': 'Transit-Anteil: {xrp} XRP',
    'exout.empty': 'Noch keine Zuflüsse aus Drainer-Kontext an Registry-Börsen im gewählten Fenster.',
    'exout.capped': '{n} der betrachteten Cluster liegen am 50-Kanten-Deckel des States — alle Summen sind eine Untergrenze.',
    'exout.coverage': 'Abgedeckter Zeitraum: {from} – {to}',
    'exout.note': 'Vom State bleiben nur die 50 nach Volumen größten Kanten je Cluster erhalten (Untergrenze); 30 Tage entspricht der Betrugs-Retention des Live-States, keiner vollständigen Wallet-Historie; Börsen-Erkennung = Registry ∪ verifizierte well-known-Namen.',
    'exout.aria': 'Top 10 Börsen nach eingehenden Drops aus Drainer-Kontext',
    'exout.wellKnown': 'well-known',

    /* index.html — Top-10 Drainer-Rangliste (Drainer-Tranche 2026-10-07,
       public/drainer-top10.mjs): rechte Duo-Box — Qualifikation nur über die
       Drainer-Rolle (Heuristik, kein Schuldbeweis — im Untertitel), Union-
       Ausschluss gegen Doppelzählung mit der Börsen-Box (in der Fußnote),
       Grenzen (50-Kanten-Deckel, 300er-Rollen-Feldkappe, Betrugs-Retention)
       ehrlich in der Fußnote, Abdeckungszeitraum dynamisch (#drout-coverage),
       Cap-Hinweis nur bei belegter Kappung (#drout-capped). Eigener
       Tag-Aria-Schlüssel: 'tag.chipAria' behauptet ein Börse-Hosted-Konto —
       für ein Drainer-Konto falsch. */
    'drout.title': 'Top-Drainer-Konten nach empfangenen Mitteln',
    'drout.subtitle': 'Die Drainer-Rolle ist eine Heuristik aus Ein-/Ausgangsgrad und Geldfluss — ein Signal, kein Schuldbeweis.',
    'drout.window7': '7 Tage',
    'drout.window30': '30 Tage',
    'drout.windowAll': 'Gesamt',
    'drout.windowAria': 'Zeitfenster der Drainer-Zuflüsse',
    'drout.rank': 'Rang {n}',
    'drout.inflows': '{n} Zuflüsse',
    'drout.inflows1': '1 Zufluss',
    'drout.clusters': '{n} Cluster',
    'drout.clusters1': '1 Cluster',
    'drout.forwarded': 'Weitergeleitet: {xrp} XRP',
    'drout.tagAria': 'Destination-Tag aus den Zuflüssen auf dieses Konto',
    'drout.empty': 'Kein Drainer-Konto mit empfangenen Mitteln im betrachteten Bestand im gewählten Fenster.',
    'drout.capped': '{n} der betrachteten Cluster liegen am 50-Kanten-Deckel des States — alle Summen sind eine Untergrenze.',
    'drout.coverage': 'Abgedeckter Zeitraum: {from} – {to}',
    'drout.note': 'Vom State bleiben nur die 50 nach Volumen größten Kanten je Cluster erhalten (Untergrenze); Rollen-Felder sind je Cluster auf 300 Einträge gekappt; Konten der Börsen-Union werden in der linken Box geführt und sind hier ausgeschlossen; 30 Tage entspricht der Betrugs-Retention des Live-States, keiner vollständigen Wallet-Historie.',
    'drout.aria': 'Top 10 Drainer-Konten nach eingehenden Drops',
  },
};

/* ------------------------------------------------------------------ */
/* Sprache: Persistenz + Lookup                                          */
/* ------------------------------------------------------------------ */

function storageGet() {
  try {
    if (typeof localStorage === 'undefined' || localStorage === null) return null;
    return localStorage.getItem(LANG_KEY);
  } catch { return null; } // Private Mode / Storage gesperrt
}

function storageSet(value) {
  try {
    if (typeof localStorage === 'undefined' || localStorage === null) return;
    localStorage.setItem(LANG_KEY, value);
  } catch { /* Speicher voll / Private Mode: Sprache bleibt flüchtig */ }
}

// Aktuelle Sprache: persistierter Wert (validiert), sonst Default 'en'.
export function getLang() {
  const raw = storageGet();
  return LANGS.includes(raw) ? raw : DEFAULT_LANG;
}

// Persistierbare Sprache als reine Funktion (getestet in lib/i18n.test.mjs):
// validiert gegen LANGS, sonst Default; schreibt über den übergebenen
// Storage (Injektion für Tests; ohne Argument das globale localStorage).
export function resolveLang(raw, storage) {
  const s = storage !== undefined ? storage : (typeof localStorage !== 'undefined' ? localStorage : null);
  const value = LANGS.includes(raw) ? raw : DEFAULT_LANG;
  try { if (s) s.setItem(LANG_KEY, value); } catch { /* flüchtig */ }
  return value;
}

/* ---------- Theme: Persistenz + Lookup (Vertrag wie Sprache) ---------- */

function themeStorageGet() {
  try {
    if (typeof localStorage === 'undefined' || localStorage === null) return null;
    return localStorage.getItem(THEME_KEY);
  } catch { return null; } // Private Mode / Storage gesperrt
}

// Aktuelles Theme: persistierter Wert (validiert), sonst Default 'noir'.
export function getTheme() {
  const raw = themeStorageGet();
  return THEMES.includes(raw) ? raw : DEFAULT_THEME;
}

// Persistierbares Theme als reine Funktion (Muster resolveLang): validiert
// gegen THEMES, sonst Default; schreibt über den übergebenen Storage
// (Injektion für Tests; ohne Argument das globale localStorage).
export function resolveTheme(raw, storage) {
  const s = storage !== undefined ? storage : (typeof localStorage !== 'undefined' ? localStorage : null);
  const value = THEMES.includes(raw) ? raw : DEFAULT_THEME;
  try { if (s) s.setItem(THEME_KEY, value); } catch { /* flüchtig */ }
  return value;
}

function interpolate(template, params) {
  if (params == null) return template;
  return String(template).replace(/\{([A-Za-z0-9_]+)\}/g, (m, name) =>
    params[name] !== undefined && params[name] !== null ? String(params[name]) : m);
}

// Lookup: aktuelle Sprache -> 'en' -> Key selbst (sichtbarer Fallback).
export function t(key, params) {
  const lang = getLang();
  const dict = DICT[lang] || DICT[DEFAULT_LANG];
  let value = dict[key];
  if (value === undefined) value = DICT[DEFAULT_LANG][key];
  if (value === undefined) return key;
  return interpolate(value, params);
}

/* ------------------------------------------------------------------ */
/* Formatter (Locale folgt der aktuellen Sprache)                       */
/* ------------------------------------------------------------------ */

export function locale() {
  return getLang() === 'de' ? 'de-DE' : 'en-US';
}

export function fmtNum(v) {
  return Number(v ?? 0).toLocaleString(locale());
}

export function fmtXrp(drops) {
  const n = Number(drops ?? 0) / 1e6;
  return n.toLocaleString(locale(), { maximumFractionDigits: 2 });
}

export function fmtClock(value) {
  if (value === null || value === undefined || value === '') return '–';
  const d = new Date(typeof value === 'number' ? value : value);
  if (Number.isNaN(d.getTime())) return String(value);
  return d.toLocaleTimeString(locale());
}

export function fmtDateTime(value) {
  if (value === null || value === undefined || value === '') return '–';
  const d = new Date(typeof value === 'number' ? value : value);
  if (Number.isNaN(d.getTime())) return String(value);
  return d.toLocaleString(locale());
}

/* ------------------------------------------------------------------ */
/* Strukturierte Übersetzung serverseitiger Fund-/Report-Daten          */
/* ------------------------------------------------------------------ */

// Regelname aus ruleId (die 9 ids aus lib/detector.mjs RULES).
export function ruleName(ruleId) {
  const id = String(ruleId ?? '');
  const key = 'rule.' + id;
  const lang = getLang();
  const dict = DICT[lang] || DICT[DEFAULT_LANG];
  if (dict[key] !== undefined) return dict[key];
  if (DICT[DEFAULT_LANG][key] !== undefined) return DICT[DEFAULT_LANG][key];
  return id; // unbekannte id: sichtbar roh
}

// Note aus noteKey + noteParams (additive Felder aus lib/detector.mjs);
// ohne noteKey Fallback auf die (sanitisierte) deutsche note des Servers.
export function noteText(finding) {
  if (!finding || typeof finding !== 'object') return '';
  const key = finding.noteKey;
  if (typeof key === 'string' && key) {
    const dictKey = 'note.' + key;
    const lang = getLang();
    const dict = DICT[lang] || DICT[DEFAULT_LANG];
    const template = dict[dictKey] !== undefined ? dict[dictKey] : DICT[DEFAULT_LANG][dictKey];
    if (template !== undefined) return interpolate(template, finding.noteParams);
  }
  return String(finding.note ?? '');
}

export function sevText(sev) {
  const s = String(sev ?? '');
  const key = 'sev.' + s;
  const dict = DICT[getLang()] || DICT[DEFAULT_LANG];
  if (dict[key] !== undefined) return dict[key];
  return s;
}

// Exact-Match-Übersetzung bekannter deutscher Server-Phrasen
// (account-report eligibilityReason/Disclaimers, Persistenz-Grund).
// Unbekannte Werte bleiben roh (Protokollgrenze, dokumentierter Fallback).
export function serverPhrase(s) {
  const raw = String(s ?? '');
  const lang = getLang();
  if (lang === 'de') return raw;
  const en = DICT[DEFAULT_LANG];
  for (const key of [
    'srv.persistenz', 'srv.eligUnknown', 'srv.eligOk', 'srv.eligReview',
    'srv.disc1', 'srv.disc2', 'srv.disc3', 'srv.disc4',
  ]) {
    if (DICT.de[key] === raw) return en[key];
  }
  return raw;
}

// Zusammenfassung des Konto-Reports neu aufgebaut aus strukturierten
// Feldern (verdict/score/contacts/patterns) — dieselbe Satzfolge wie
// buildSummary in lib/account-report.mjs, in der aktuellen Sprache.
// report.patterns sind Regel-ids; sie werden wie im Original roh gelistet.
export function summaryText(report) {
  if (!report || typeof report !== 'object') return '';
  const verdict = String(report.verdict ?? 'unknown');
  if (verdict === 'unknown') return t('summary.unknown');
  const contacts = Array.isArray(report.contacts) ? report.contacts : [];
  const malicious = new Set();
  const suspect = new Set();
  for (const c of contacts) {
    if (!c || typeof c !== 'object') continue;
    const addr = String(c.counterparty ?? '');
    if (!addr) continue;
    if (c.risk === 'malicious') malicious.add(addr);
    else if (c.risk === 'suspect') suspect.add(addr);
  }
  const patterns = Array.isArray(report.patterns) ? report.patterns : [];
  const parts = [t('summary.score', { score: report.score })];
  if (verdict === 'bad') parts.push(t('summary.selfListed'));
  if (malicious.size > 0) parts.push(t('summary.malicious', { n: malicious.size }));
  if (suspect.size > 0) parts.push(t('summary.suspect', { n: suspect.size }));
  if (verdict === 'clean' && malicious.size === 0 && suspect.size === 0) {
    parts.push(t('summary.noContacts'));
  }
  if (patterns.length > 0) parts.push(t('summary.patterns', { list: patterns.join(', ') }));
  return parts.join(' ');
}

/* ------------------------------------------------------------------ */
/* DOM-Anwendung (guardiert — ohne DOM Noop)                            */
/* ------------------------------------------------------------------ */

export function applyStatic(root) {
  const scope = root && typeof root.querySelectorAll === 'function' ? root
    : (typeof document !== 'undefined' ? document : null);
  if (!scope) return;
  for (const el of scope.querySelectorAll('[data-i18n]')) {
    el.textContent = t(el.getAttribute('data-i18n'));
  }
  for (const el of scope.querySelectorAll('[data-i18n-aria]')) {
    el.setAttribute('aria-label', t(el.getAttribute('data-i18n-aria')));
  }
  for (const el of scope.querySelectorAll('[data-i18n-placeholder]')) {
    el.setAttribute('placeholder', t(el.getAttribute('data-i18n-placeholder')));
  }
  for (const el of scope.querySelectorAll('[data-i18n-title]')) {
    el.setAttribute('title', t(el.getAttribute('data-i18n-title')));
  }
}

// Exportiert seit der Info-Seite (2026-10-06): about.test.mjs prüft die
// Vollständigkeit der about-Einträge (Titel/Meta je Sprache).
export const PAGE_TITLE = {
  index: { en: 'Honeypot XRPL – Live Ledger Analysis', de: 'Honeypot XRPL – Live-Ledger-Analyse' },
  flowhost: { en: 'Honeypot XRPL – Flow-Host', de: 'Honeypot XRPL – Flow-Host' },
  about: { en: 'Honeypot XRPL – About', de: 'Honeypot XRPL – Info' },
};
export const PAGE_DESC = {
  index: {
    en: 'Live ledger analysis of the XRPL: validated blocks are checked in real time for malware, spam and draining patterns, and the detected actors are grouped into clusters (source, drainer, collector, relay).',
    de: 'Live-Ledger-Analyse der XRPL: validierte Blöcke werden in Echtzeit auf Malware-, Spam- und Draining-Muster geprüft und die erkannten Akteure zu Clustern gruppiert (Source, Drainer, Kollektor, Relay).',
  },
  flowhost: {
    en: 'Accumulated cross-block flow state of the XRPL ledger walk: cluster view with roles, volume and sighting times, plus the cursor position of the walk.',
    de: 'Akkumulierter Cross-Block-Flow-State des XRPL-Ledger-Walks: Cluster-View mit Rollen, Volumen und Sichtungszeiten sowie Cursor-Stand des Walks.',
  },
  about: {
    en: 'What Honeypot XRPL detects on the XRP Ledger: drainer, collector, source and relay roles, peeling chains, wash trading, cross-ledger sweeps, hub connections and known-bad contacts — plus glossary and honest limits.',
    de: 'Was Honeypot XRPL auf dem XRP-Ledger erkennt: Rollen Drainer, Kollektor, Source und Relay, Peeling-Ketten, Wash Trading, Cross-Ledger-Sweeps, Hub-Verbindungen und Known-Bad-Kontakte — dazu Glossar und ehrliche Grenzen.',
  },
};

function pageKind() {
  try {
    if (typeof location !== 'undefined') {
      const p = String(location.pathname ?? '');
      if (/history-host/i.test(p)) return 'flowhost';
      if (/about/i.test(p)) return 'about';
    }
  } catch { /* ohne location: index */ }
  return 'index';
}

// documentElement.lang, Titel und Meta-Description auf die aktuelle Sprache
// stellen und 'hx:langchange' senden (dynamische Sichten re-rendern darauf).
export function applyLang() {
  const lang = getLang();
  if (typeof document === 'undefined' || document === null) return lang;
  try { document.documentElement.setAttribute('lang', lang); } catch { /* Noop */ }
  const kind = pageKind();
  try { if (PAGE_TITLE[kind]) document.title = PAGE_TITLE[kind][lang]; } catch { /* Noop */ }
  try {
    const meta = document.querySelector('meta[name="description"]');
    if (meta && PAGE_DESC[kind]) meta.setAttribute('content', PAGE_DESC[kind][lang]);
  } catch { /* Noop */ }
  try { document.dispatchEvent(new CustomEvent('hx:langchange', { detail: { lang } })); } catch { /* Noop */ }
  return lang;
}

// Sprache setzen: validieren, persistieren, DOM anwenden, Event senden.
export function setLang(lang) {
  const value = resolveLang(lang);
  applyLang();
  return value;
}

/* ---------- Theme: DOM-Anwendung + Umschalter (guardiert — ohne DOM Noop) --
 * applyTheme setzt body[data-theme] (die Token-Overrides in style.css),
 * hält meta[name=theme-color] auf der Browser-Chrome-Farbe des Themes und
 * sendet 'hx:themechange' am document — dynamische Sichten (2D-/3D-Graph,
 * Weltkugel, Flow-Host-SVG) färben daraufhin ihre Canvas-Layer um. */
export function applyTheme() {
  const theme = getTheme();
  if (typeof document === 'undefined' || document === null) return theme;
  try { document.body.dataset.theme = theme; } catch { /* Noop */ }
  try {
    const meta = document.querySelector('meta[name="theme-color"]');
    if (meta && THEME_META_COLORS[theme]) meta.setAttribute('content', THEME_META_COLORS[theme]);
  } catch { /* Noop */ }
  try { document.dispatchEvent(new CustomEvent('hx:themechange', { detail: { theme } })); } catch { /* Noop */ }
  return theme;
}

// Theme setzen: validieren, persistieren, DOM anwenden, Event senden
// (Vertragsform setLang).
export function setTheme(theme) {
  const value = resolveTheme(theme);
  applyTheme();
  return value;
}

// Theme-Umschalter: EIN native Button (44-px-Zielhöhe via .lang-btn-Basis,
// Zusatzklasse .theme-btn für Identität), Label zeigt den AKTUELLEN Theme-
// Namen, aria-pressed spiegelt 'noir', title/aria-label beschreiben die
// Aktion (Wechsel zum anderen Theme).
export function initThemeSwitcher(container) {
  if (!container || typeof document === 'undefined' || document === null) return null;
  container.setAttribute('role', 'group');
  container.setAttribute('aria-label', t('theme.switchAria'));
  const btn = document.createElement('button');
  btn.type = 'button';
  btn.className = 'lang-btn theme-btn';
  const sync = () => {
    const current = getTheme();
    btn.textContent = t('theme.' + current);
    btn.setAttribute('aria-pressed', String(current === 'noir'));
    const actionKey = current === 'noir' ? 'theme.toLightAria' : 'theme.toNoirAria';
    btn.setAttribute('title', t(actionKey));
    btn.setAttribute('aria-label', t(actionKey));
  };
  btn.addEventListener('click', () => {
    setTheme(getTheme() === 'noir' ? 'light' : 'noir');
  });
  container.appendChild(btn);
  try { document.addEventListener('hx:themechange', sync); } catch { /* Noop */ }
  try { document.addEventListener('hx:langchange', sync); } catch { /* Noop */ } // Labels in der neuen Sprache
  sync();
  return { sync };
}

// Sprachumschalter: zwei native Buttons EN/DE (44-px-Zielhöhe via CSS),
// aria-pressed spiegelt die aktuelle Sprache.
export function initLangSwitcher(container) {
  if (!container || typeof document === 'undefined' || document === null) return null;
  container.setAttribute('role', 'group');
  container.setAttribute('aria-label', t('lang.switchAria'));
  const buttons = new Map();
  for (const lang of LANGS) {
    const btn = document.createElement('button');
    btn.type = 'button';
    btn.className = 'lang-btn lang-btn-' + lang;
    btn.textContent = t('lang.' + lang);
    btn.setAttribute('aria-pressed', String(getLang() === lang));
    btn.setAttribute('title', t('lang.' + lang + 'Aria'));
    btn.addEventListener('click', () => setLang(lang));
    container.appendChild(btn);
    buttons.set(lang, btn);
  }
  const sync = () => {
    const current = getLang();
    for (const [lang, btn] of buttons) btn.setAttribute('aria-pressed', String(current === lang));
    try { container.setAttribute('aria-label', t('lang.switchAria')); } catch { /* Noop */ }
  };
  try { document.addEventListener('hx:langchange', sync); } catch { /* Noop */ }
  sync();
  return { sync };
}
