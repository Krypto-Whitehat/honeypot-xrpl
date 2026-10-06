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

    /* index.html — Fuß */
    'foot.updated': 'As of: ',
    'foot.note': 'Bait anonymity: seeds and bait addresses are never served by the server and never rendered by the client.',

    /* Sprachumschalter */
    'lang.switchAria': 'Language',
    'lang.en': 'EN',
    'lang.de': 'DE',
    'lang.enAria': 'Switch language to English',
    'lang.deAria': 'Sprache auf Deutsch umstellen',

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
    'mode.archiveAria': 'Show the persisted block window (24 h / 3 d / 7 d) from the server',
    /* Sichtbarer Hinweis unter der Modus-Auswahl (index.html #feed-archive-
       hint), per aria-describedby an beide Modus-Buttons gebunden. */
    'mode.archiveHint': 'Archive mode: persisted block window (24 h / 3 d / 7 d) from the server — also available when no live feed is connected.',
    'mode.live': 'Live',
    'mode.liveAria': 'Opt-in: direct WSS to honeycluster.io – one ledger command per block, no sampling',
    'range.label': 'Window',
    'range.24h': '24 h',
    'range.3d': '3 d',
    'range.7d': '7 d',
    'feed.loadMore': 'Load more',
    'feed.loadMoreAria': 'Load more block entries',
    'feed.serverEmpty': 'No blocks in the window yet – the server walk fills the window every 5 minutes.',
    'feed.windowNote': 'Server window: {range} · {blocks} blocks · {txns} txs · {flagged} flagged blocks · as of {time}',
    'feed.persistOff': 'Persistence not configured – the server window is empty. Activate the Live mode for direct analysis.',
    'feed.windowError': 'Server window unreachable ({msg})',
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
    'about.patDrainerD': 'A freshly funded account is swept immediately: at least 90 % of the balance leaves to a single target in one payment. Only with ledger proof of account creation is the finding classified as malicious; without it, it stays suspect.',
    'about.patCrossLedgerT': 'Cross-ledger sweep',
    'about.patCrossLedgerD': 'Funding and sweeping across block boundaries: when an account is funded in ledger N and only swept in ledger N+1, the cross-ledger memory of the engine keeps the sweep visible. Stretched dusting campaigns are caught the same way, via the union of their tiny destinations over the window.',
    'about.patPeelingT': 'Peeling chains',
    'about.patPeelingD': 'Staged forwarding of 60 to 95 % of the inflow across unflagged 1:1 relays, from three hops onwards. Detection runs on the transaction view and follows inconspicuous intermediate accounts without assigning them a role.',
    'about.patWashT': 'Wash trading (self-transfers)',
    'about.patWashD': 'At least three self-payments of the same account within one ledger (sender and destination are identical) — volume generation without a real counterparty, a typical washing pattern.',
    'about.patHubT': 'Hub connections',
    'about.patHubD': 'Unflagged nodes with more than 20 finding edges (exchange, faucet or aggregation accounts) are cut out of the cluster union: two independent scenes never merge through a shared exchange. Connections that run through a shared exchange account (transit) are marked as pass-through, not as direct adjacency.',
    'about.patKnownBadT': 'Known-bad contact',
    'about.patKnownBadD': 'When a transaction touches an address from the threat list (curated and derived from the honeypot history), this is reported as a hit — direct account or payment contact as malicious, mere trustline or NFT positions only as suspect.',
    'about.detectNote': 'The engine rule catalog holds eleven rules — besides the ones above, among others memo phishing (URLs and seed patterns in payment memos), dusting (mini XRP to fresh accounts), fake NFT fraud, airdrop TrustSet spam, payment bursts and offer spam. Every rule carries a severity; all assignments are heuristics, not proof of guilt.',
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
    'legend.unknown': 'Unknown',
    'legend.cluster': 'Cluster',
    'legend.payment': 'Payment',
    'legend.check': 'Check/Channel',
    'legend.escrow': 'Escrow',
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

    /* index.html — Fuß */
    'foot.updated': 'Stand: ',
    'foot.note': 'Anonymität der Köder: Seeds und Köder-Adressen werden vom Server nie ausgeliefert und vom Client nie gerendert.',

    /* Sprachumschalter */
    'lang.switchAria': 'Sprache',
    'lang.en': 'EN',
    'lang.de': 'DE',
    'lang.enAria': 'Sprache auf Englisch umstellen',
    'lang.deAria': 'Sprache auf Deutsch umstellen',

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
    'mode.archiveAria': 'Persistiertes Block-Fenster (24 h / 3 d / 7 d) vom Server anzeigen',
    /* Sichtbarer Hinweis unter der Modus-Auswahl (index.html #feed-archive-
       hint), per aria-describedby an beide Modus-Buttons gebunden. */
    'mode.archiveHint': 'Archiv-Modus: persistiertes Block-Fenster (24 h / 3 T / 7 T) vom Server — auch verfügbar, wenn kein Live-Feed verbunden ist.',
    'mode.live': 'Live',
    'mode.liveAria': 'Opt-in: direkter WSS zu honeycluster.io – ein Ledger-Kommando pro Block, ohne Stichprobe',
    'range.label': 'Fenster',
    'range.24h': '24 h',
    'range.3d': '3 T',
    'range.7d': '7 T',
    'feed.loadMore': 'Mehr laden',
    'feed.loadMoreAria': 'Weitere Block-Einträge laden',
    'feed.serverEmpty': 'Noch keine Blöcke im Fenster – der Server-Walk füllt es alle 5 Minuten.',
    'feed.windowNote': 'Server-Fenster: {range} · {blocks} Blöcke · {txns} Txs · {flagged} geflaggte Blöcke · Stand {time}',
    'feed.persistOff': 'Persistenz nicht konfiguriert – das Server-Fenster ist leer. Aktiviere den Live-Modus für die direkte Analyse.',
    'feed.windowError': 'Server-Fenster nicht erreichbar ({msg})',
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
    'about.patDrainerD': 'Ein frisch finanziertes Konto wird sofort wieder abgeräumt: Mindestens 90 % des Guthabens gehen in einer Zahlung an ein einziges Ziel. Nur mit Ledger-Beleg der Kontoerstellung wird der Fund als maliziös eingestuft, ohne Beleg bleibt er verdächtig.',
    'about.patCrossLedgerT': 'Cross-Ledger-Sweep',
    'about.patCrossLedgerD': 'Füttern und Abräumen über Blockgrenzen hinweg: Wird ein Konto in Ledger N finanziert und erst in Ledger N+1 abgeräumt, hält das Fenster-Gedächtnis der Engine den Sweep sichtbar. Auch zeitlich gestreckte Dusting-Kampagnen werden auf dieselbe Weise erkannt — über die Vereinigung ihrer Mini-Ziele im Fenster.',
    'about.patPeelingT': 'Peeling-Ketten',
    'about.patPeelingD': 'Gestaffelte Weiterleitung von 60 bis 95 % des Eingangs über ungeflaggte 1:1-Relays, ab drei Hops. Die Erkennung läuft über die Transaktionssicht und folgt auch unauffälligen Zwischenkonten, ohne ihnen eine Rolle zuzuweisen.',
    'about.patWashT': 'Wash Trading (Selbsttransfers)',
    'about.patWashD': 'Mindestens drei Selbstzahlungen desselben Kontos in einem Ledger (Absender und Empfänger sind identisch) — Volumenerzeugung ohne echte Gegenpartei, ein typisches Washing-Muster.',
    'about.patHubT': 'Hub-Verbindungen',
    'about.patHubD': 'Ungeflaggte Knoten mit mehr als 20 Fund-Kanten (Börsen-, Faucet- oder Sammel-Konten) werden aus der Cluster-Vereinigung herausgeschnitten: Zwei unabhängige Szenen verschmelzen nicht über eine gemeinsame Börse. Verbindungen, die über ein gemeinsames Börsen-Konto laufen (transit), werden als Durchleitung gekennzeichnet, nicht als direkte Nachbarschaft.',
    'about.patKnownBadT': 'Known-Bad-Kontakt',
    'about.patKnownBadD': 'Berührt eine Transaktion eine Adresse aus der Bedrohungsliste (kuratiert und aus der Honeypot-Historie abgeleitet), wird das als Treffer gemeldet — direkte Konto- oder Zahlungsberührung als maliziös, bloße Trustline- oder NFT-Positionen nur als verdächtig.',
    'about.detectNote': 'Der Regelkatalog der Engine umfasst elf Regeln — neben den obigen unter anderem Memo-Phishing (URLs und Seed-Muster in Zahlungsmemos), Dusting (Mini-XRP an frische Konten), Fake-NFT-Betrug, Airdrop-TrustSet-Spam, Zahlungs-Bursts und Offer-Spam. Jede Regel trägt einen Schweregrad; alle Zuordnungen sind Heuristiken, kein Schuldnachweis.',
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
