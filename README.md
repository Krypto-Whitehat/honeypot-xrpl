# Honeypot XRPL

Öffentliches Echtzeit-Bedrohungs-Dashboard für die XRPL-Community: Köder-Konten
(Honeypots) auf dem XRP Ledger **Mainnet** werden überwacht; jede Transaktion,
die ein Köder-Konto berührt, wird als Threat erfasst und über eine JSON-API an
das Frontend (vanilla HTML/CSS/JS + vis-network, Whitehat-Design nach
Astra-6) ausgeliefert.

**Kernanforderung — zweischichtige Honeypot-Anonymität:**

1. **Interner Store (Wahrheitsbestand):** Der Monitor schreibt
   `data/threats.json` inklusive voller Evidenz (`txHash`) und — für interne
   Zwecke — der beteiligten Adressen.
2. **Pflicht-Sanitisierung im Server:** Jede öffentliche Antwort
   (`/api/threats`, `/api/graph`, `/api/stats`) wird vor Auslieferung durch
   eine zentrale Anonymitätsschicht gefiltert:
   - Evidence-Felder enthalten **keinen txHash**, sondern
     `{ ref: "E-<n>", type, time, honeypot }`. Ein öffentlicher Hash würde
     on-chain (`xrpl tx <hash>`) direkt über das Destination-Feld auf die
     Köder-Adresse zurückführen.
   - **Keine Köder-Adresse** — weder aktuell noch historisch — erscheint in
     einem öffentlichen Feld: nicht in Threat-Adressen, nicht in Graph-Node-Ids,
     nicht in Edge-Enden, nicht in Funding-Einträgen, nicht in Reason-Texten.
     Sanitisiert wird gegen die UNION aus `bait.json` + `bait-history.json`.
   - Graph-Node-Ids sind stabile Label-Ids: `honeypot:N` bzw.
     `attacker:<öffentliche Adresse>`. Honeypot-Knoten tragen nur Labels
     (`Köder #1`, intern `HP-1`).
   - Funding-Einträge werden nur als Label veröffentlicht; Faucet-Konten
     erscheinen als `Testnet-Faucet (benign)` ohne Adresse.
   - Seeds erscheinen in keiner Antwort; der Server liest sie nicht einmal ein.

## Stack

- Node.js >= 18, ESM (`.mjs`), kein Build-Schritt
- Abhängigkeiten: nur `express` und `xrpl` (beide pure JS)
- Frontend in `public/` (vanilla HTML/CSS/JS, vis-network über CDN)

## Verzeichnisstruktur

```
honeypot-xrpl/
├── package.json
├── config.json          # network / wss / port / faucet_addresses / operator_addresses
├── vercel.json          # Deployment-Konfiguration für Vercel (Rewrites, cleanUrls)
├── .gitignore           # bait.json, bait-history.json, data/, node_modules/, logs/, .env*
├── bait.json            # lokal, gitignored: [{address, seed, label}]
├── bait-history.json    # lokal, gitignored: bei Rotation verschobene alte Köder
├── data/threats.json    # Threat-Store, interner Wahrheitsbestand (atomar, gitignored)
├── logs/monitor.log     # Monitor-Log (gitignored)
├── lib/
│   ├── sanitize.mjs         # ZENTRALE Anonymitätsschicht (single source, Server + Vercel)
│   └── threats-service.mjs  # Serverlose Threat-Ableitung für Vercel (account_tx, 60s-Cache)
├── api/                 # Vercel-Functions (ESM): threats, graph, stats, check/[address]
├── server/index.mjs     # API + Static-Server (lokaler Dauerbetrieb), Port 3000
└── monitor/
    ├── monitor.mjs          # WSS-Subscription auf alle Köder-Konten (inkl. History)
    ├── provision-bait.mjs   # 3 Köder via client.fundWallet() (Testnet), Rotation
    └── simulate-attack.mjs  # simulierter Angreifer: 1 XRP an Köder #1
```

## config.json

```json
{
  "network": "mainnet",
  "wss": "wss://honeycluster.io",
  "port": 3000,
  "faucet_addresses": [],
  "operator_addresses": []
}
```

- `faucet_addresses`: Testnet-Faucet-Konten (benign). Der Monitor listet sie
  nicht als Threat; der Server veröffentlicht sie nur als Label
  `Testnet-Faucet (benign)` **ohne Adresse** (Adresse bleibt nur intern).
  `rJjHY…` ist der aktuelle Faucet-Funder (2026-09-28 empirisch via
  fundWallet + account_tx verifiziert), `rHb9…` das Testnet-Genesis-Konto.
- `operator_addresses`: **Eigene Betriebs-Adressen des Betreibers** (z. B.
  Sweep-/Cold-Wallets, auf Mainnet zwingend vor Inbetriebnahme füllen).
  Zahlungen eines Köder-Kontos an eine dieser Adressen erzeugen **keinen**
  Threat (False-Positive-Schutz; die Betriebsadresse wird nie publiziert).

## Köder-Rotation (bait-history.json)

`npm run provision` verschiebt beim Anlegen eines neuen Köder-Satzes die alten
`bait.json`-Einträge nach `bait-history.json` (gleiche `.gitignore`-Regel).
Neue Köder erhalten fortlaufende Labels (`HP-4`, `HP-5`, …), damit die
öffentlichen Graph-Ids `honeypot:N` über Rotationen eindeutig bleiben.
Server **und** Monitor lesen die UNION aus beiden Dateien: Die alte Köder-Adresse
bleibt so überwacht und wird weiterhin in jeder öffentlichen Antwort ersetzt —
auch wenn sie noch als `funding[].address` im internen Store steht.

## Dateirechte (Windows)

NTFS ignoriert POSIX-`mode 0o600`. Nach der Provisionierung (und manuell nach
dem Anlegen der Dateien) die Rechte beschränken:

```bat
icacls bait.json /inheritance:r /grant:r "%USERNAME%:F"
icacls bait-history.json /inheritance:r /grant:r "%USERNAME%:F"
```

## Setup (Testnet)

```bash
npm install

# 1) Drei Köder-Konten auf dem Testnet anlegen (Faucet-Finanzierung),
#    schreibt bait.json (gitignored, Seed wird nie ausgegeben; stdout zeigt
#    nur Label + letzte 4 Zeichen der Adresse):
npm run provision

# 2) Monitor starten — abonniert alle Köder-Konten, schreibt data/threats.json:
npm run monitor

# 3) Server starten (API + public/ auf http://localhost:3000):
npm start

# 4) Demo-Angriff auslösen: faucet-finanziertes Konto sendet 1 XRP an Köder #1:
npm run simulate
```

Danach zeigt das Dashboard unter `http://localhost:3000` den Angreifer als
malicious Threat; der Monitor hat die Funding-Kette (Testnet-Faucet, gelabelt
als benign) rückverfolgt.

Monitor und Server können in zwei Terminals parallel laufen; der Server pollt
`data/threats.json` alle 2 s per mtime und liefert Live-Daten.

## API-Vertrag (Port 3000, same-origin — kein CORS-Header)

| Endpunkt      | Antwort |
|---------------|---------|
| `GET /api/health`  | `{ "ok": true }` |
| `GET /api/stats`   | `{ maliciousCount, suspectCount, eventCount, lastEventTime, network }` |
| `GET /api/threats` | `[{ address, risk: "malicious"\|"suspect", reason, evidence: [{ ref: "E-1", type, time, honeypot: "Köder #1" }], firstSeen, funding: [{ label }] }]` — **kein txHash, keine Funding-Adressen** |
| `GET /api/threats?q=<text>` | wie oben, gefiltert nach Adresse/Grund (Case-insensitive Substring) |
| `GET /api/check/:address` | `{ address, network, checkedTxCount, truncated, selfListed, verdict: "clean"\|"contact"\|"unknown", contacts: [{ txType, time, direction, note, counterparty, risk }], hint }` |
| `GET /api/graph`   | `{ nodes: [{ id: "attacker:r…" \| "honeypot:1", label, type }], edges: [{ from, to, type }] }` |
| `GET /api/flow-state` | `{ cursor, updatedAt, validatedIndex, clusters: [{ id, label, roles, rolesByAddress, edges, totalDrops, txCount, distinctAccounts, firstSeen, lastSeen, fieldsCapped? }] }` — normalisierte Projektion des persistierten Flow-States (serverseitig baitLabels-gefiltert, Top-200, 7-Tage-Fenster, 30 Tage für Cluster mit Betrugsevidenz — `FLOW_STATE_MALICIOUS_RETENTION_MS`); `fieldsCapped: true` nur wenn die Write-Pfad-Feldkappe (`FLOW_STATE_MEMBER_CAP` 300) `memberAddresses` gekürzt hat — `distinctAccounts` bleibt der je gesehene WAHRE Bestand (monoton, `lib/ledger-walk.mjs` mergeCluster; Vergleich bait-inklusiv vor dem STILL-Filter); ohne Token `200 + reason` (fail-closed) |
| `GET /api/flow-state?route=archive&address=…&from=…&to=…&range=30d\|90d` | `{ address, from, to, hops: [{ from, to, type, amountDrops, txHash, ledgerSeq }], truncated, queryDays, range? }` — Rückwärts-Replay über die Flow-Archiv-Tages-Chunks; `type` je Hop seit Kritik-Runde 3 (Parität zum Live-Kantenvertrag); `range` steuert die Lese-Tiefe (30 d = 1 Block, 90 d = 3 Blöcke nötig — bei Default-Kappe 2 ehrlich `truncated: true` + `queryDays: 62`); ungültiger `range` → 400 |
| `GET /api/block-window?range=24h\|3d\|7d` | `{ range, from, to, updatedAt, buckets: [{ t, blocks, txns, flaggedBlocks, maxSeverity }], flagged: [{ i, t, n, f: [{ from, to, type, amountDrops, txHash, ledgerSeq }] }], cursor, validatedIndex }` — rollender Block-Fenster-Bestand (Stunden-Rollups ≤ 168 Zeilen bei 7 d, geflaggte Details im Volltext); Default `24h`, ungültiger `range` → 400; ohne Token `200 + reason` (fail-closed). Bedient von der Function `api/flow-state.js` (Zweig `route=block-window`) via Rewrite — Hobby-Limit: max. 12 Serverless Functions pro Deployment |
| `GET /api/validator-trace?master=<master>&range=1h\|24h\|7d\|all` | `{ available, source, days, master, range, summary, inWindow, coverage, incidents, gaps, patterns, retrace, diagnosis, profile, risk }` — Retrace eines dUNL-Validators: Vorfalls-Zeitachse, Intervall-Profil (24 Intervalle mit Ledger-Abdeckung, Kohorte und Signatur), je Vorfall die messbare Ursache mit Stärkenrang und der Lift-Wert dieser Anomalie, dazu Fingerprint, Ausfallserien, Quorum-Kritikalität und Last-Ausfall-Kurve dieses Knotens |
| `GET /api/validator-trace?patterns=1&range=…` | `{ incidents, tags, recurring, perValidator, risk, attacks, signatures, split, clusters, windows, load, impact }` — Netz-Sicht: wiederkehrende Muster über alle Validatoren, Risikozeilen (Rate mit Signatur gegen ohne, `lift`), Angriffs-Signale, Signatur-Bord der Transaktions-Formen, Netz-Serien, Kohorten-Cluster und die Last-Ausfall-Kurve des Netzdurchschnitts |
| `GET /…`           | statische Files aus `public/` |

**Datenquellen der Endpunkte (Doku 2026-10-04):** `/api/threats`, `/api/stats`
und `/api/graph` zeigen die **live abgeleitete** Köder-Historie
(`deriveThreats` in `lib/threats-service.mjs` — `account_tx` gegen die
Köder-Konten); `/api/flow-state`, `/api/block-window` und `/api/history`
zeigen den **persistierten** Server-Walk (`data/flow-state.json`,
`data/block-window/`, `data/history.json` im GitHub-Datenrepo). Die Zählung
kann deshalb zwischen beiden Seiten abweichen (live-Ableitung ohne Walk-
Pruning vs. akkumulierter Walk). Ein Umbau von threats/stats/graph auf den
merged Wissens-Layer `getThreatKnowledge` wäre eine Produktentscheidung mit
neuer öffentlicher Semantik — als Follow-up vorgesehen, nicht umgesetzt.

## Suche und Selbst-Check

- **Suchfeld** (Dashboard, Tabelle „Maliziöse Adressen"): Community-Mitglieder
  können die Bedrohungsliste nach Adress-Teilen oder Grund durchsuchen
  (clientseitiger Filter + `?q=`-Parameter der API).
- **Selbst-Check** (`GET /api/check/:address`, Panel im Dashboard): Man gibt
  die eigene XRPL-Adresse ein und prüft, ob sie je in Kontakt mit einer
  erkannten Bedrohungs-Adresse stand — Zahlungen (ein-/ausgehend), Trustlines
  (zu einem Issuer / von einer Adresse angefragt), DEX-Orders,
  Escrow/Check/Payment-Kanäle und generische Absender-/Ziel-Beteiligung.
  Geprüft werden bis zu 300 validierte Transaktionen der Historie
  (`account_tx`, paginiert); `truncated: true` signalisiert eine abgeschnittene
  Historie.
- **Privatsphäre:** Die abgefragte Adresse wird **nicht geloggt und nicht
  persistiert** (kein Eintrag in `logs/` oder `data/`); der 60-Sekunden-
  Ergebnis-Cache liegt nur im Prozess-Speicher.
- **Köderschutz:** Adressen aus der Bait-Union werden mit derselben generischen
  Fehlerantwort abgewiesen wie ungültige Adressen — der Check-Endpunkt gibt
  nicht preis, ob eine Adresse ein Köder ist.

Evidenz ist über `ref` (`E-<n>` pro Threat, stabil) referenzierbar; die
txHashes liegen ausschließlich im internen Store `data/threats.json`.

Monitor-Logik:

- `risk "malicious"` — Payment/TrustSet von extern gegen ein Köder-Konto
  **oder** Kompromittierungs-Alarm: das Köder-Konto selbst initiiert eine
  Transaktion (Payment an externes Ziel, AccountSet, AccountDelete,
  SetRegularKey, …). Im Alarm-Reason-Text steht bewusst **keine** Zieladresse.
- `risk "suspect"` — alle anderen berührten Transaktionen, einschließlich
  DEX-Offer-Berührung (`OfferCreate`/`OfferCancel` des Köders sowie externe
  Transaktionen gegen Offer-Ledger-Objekte des Köders, Gegenpartei dann die
  tx-Absenderadresse) und `NFTokenAcceptOffer`/NFTokenOffer-Berührung.
- Nur **validierte** Transaktionen werden verarbeitet (`validated === true`),
  dedupliziert per txHash.
- Funding-Kette via `account_tx` mit Marker-Pagination (bis 100 Einträge,
  Tiefe 2). `firstSeen` ist die Ledger-Zeit (`close_time_iso`) der ersten
  Evidence — nicht die Wanduhrzeit des Monitors.

## Validator-Trace: dUNL-Ausfall-Rekonstruktion + Transaktions-Forensik

Der Recorder (`monitor/validator-trace.mjs`, Workflow
`.github/workflows/validator-trace.yml`, cron `5 */5 * * *`, max. 5 h je Lauf)
zeichnet den **Validations-Stream** der dUNL dauerhaft auf und schreibt
Tagesdateien in das private Daten-Repo
(`Krypto-Whitehat/honeypot-xrpl-history`, `data/validator-trace/<YYYY-MM-DD>.json`,
Push alle 5 min). Der Stream kommt von `wss://xrplcluster.com` (xrpld) — Clio-
Endpunkte wie honeycluster liefern **keine** Validations und würden einen
vollständigen Ausfall vortäuschen.

**Ebene 1 — Validations-Ebene (was passierte):** je Validator und je Ledger
`missed` / `partial` / `wrong-hash` / `vote-not-observed` (Bestand vor 2026-10-17:
`no-quorum`), plus die **Ledger-Kohorte**
(wie viele dUNL-Validatoren denselben Ledger gleichzeitig falsch standen),
Quorum-Rand (Top-Stimmen vs. benötigte Stimmen), Hash-Split, Last
(Tx vs. Median) und Takt-Lücke (Ledger-Abstand vs. Median).

**Schliess-Beweis vor jedem Stimmen-Zähler (Akkuratz-Regel, 2026-10-16):** der abonnierte
`ledger`-Stream liefert ausschließlich **validierte** Ledger — jeder aufgezeichnete Ledger ist
damit bewiesen geschlossen, das Netz hat sein Quorum erreicht. `vote-not-observed` beschreibt deshalb
**nur die eigene Beobachtung** („kein Vote dieses Recorders erfasst“), nie ein zu kleines
Netz-Quorum; `network-stall` darf nur dort stehen, wo die Schließung ausdrücklich verneint wird
(`cl === false`). Seit 2026-10-17 heißt auch der Typname selbst den Befund und nicht die
Ursache: auf einem bewiesen geschlossenen Ledger schreibt der Recorder `vote-not-observed`, und
`no-quorum` bleibt ausschließlich dem Fall vorbehalten, dessen Schließung nicht belegt ist. Der
Bestand vor diesem Datum behält seinen Typ in den Bytes der Tagesdateien und zählt in dasselbe Feld
`noQuorum`; die UI liest ihn über dieselbe Vokabel wie `vote-not-observed`, und `no-quorum` hat seit
2026-10-17 ein eigenes Label: „kein Quorum erfasst (Schließung nicht belegt)“ — ein Name, der eine
Schließung behauptet, darf nicht auf einer Zeile stehen, deren Schließung verneint ist. Definiert ist das an genau einer Stelle: `ledgerClosure` in
`lib/validator-trace.mjs` — Diagnose, Retrace und Ursachen-Ebene lesen dieselbe Funktion. Die
Verdikte der Kritikalitäts-Zelle sind eine Kette mit Vorrang: `not-closed` →
`closed-capture-gap` → `closed-quorum-observed` → `closed-reception-thin` →
`closed-observation-gap`.

**Prüfhinweise folgen derselben Regel (2026-10-16):** ein bewiesen geschlossener Ledger empfiehlt
keine Netzstockung. In der Retrace-Guidance steht dort `capture-window` („was dieser Rekorder
empfing“) statt `network-stall`, und in der Prüfliste der Ursachen-Ebene wird
`cause-check-network-stall` unterdrückt — außer dieser Ledger hat einen **gemessenen
Close-Abstand** (`close-gap`) **bei nachweislich lückenloser Index-Folge** (`captureGap === false`,
also `pg === l - 1`). Nur dann ist der Abstand ein Netz-Befund; springt die eigene Index-Folge,
enthält er die Ledger, die dieser Rekorder nie sah, und die nächste Prüfung bleibt die eigene
Erfassung. Wo die Schließung
ausdrücklich verneint ist, bleibt die Netzstockung die naheliegende Gegenprobe; wo sie **nicht
erfasst** ist, steht ebenfalls die Erfassungs-Prüfung — eine Datenlücke des Recorders ist kein
Verdacht gegen das Netz. Dieselbe Regel gilt seit 2026-10-17 auch auf der **Serien-Ebene**: eine
Serie, deren Ledger alle als geschlossen belegt sind (`closedLedgers == ledgers` in
`failureRuns`), wird als `capture-window` klassifiziert statt als `network-window`, und
`applySeries` empfiehlt dann `capture-window` statt `network-stall`. Ohne Schließ-Beweis
bleibt die Klasse `network-window` stehen — die Frage bleibt offen, sie wird nicht zur
Entlastung umgeschrieben.

**Die Latenz-Ebene spricht dieselbe Sprache (2026-10-17, nachgerechnet an #107695059 /
#107694001 / #107690236):** wo kein Vorfall knotenzurechenbar war, stand früher `network-only`
(„Nur Netzstockungen“). Diese Aussage ist aus dem eigenen Mithören nie belegbar: der Rekorder
wertet ausschließlich Ledger aus dem validierten Strom aus (`evaluate()` sieht nur Ledger, die
`onLedger` aus diesem Strom erhalten hat) — ein fehlendes Netz-Quorum kann er damit nicht
beobachten. Die Ebene entscheidet jetzt über den Schließ-Beleg und weist ihn offen aus
(`closure`: `proven` / `denied` / `unknown` mit der Quelle jedes Close-Hash):
`capture-only` (alle bewiesen geschlossen → Erfassungs-Lücke dieses Recorders, Autorität
`trace-closure-proof`), `closure-unproven` (kein Close-Beleg → weder Knotenfehler noch
Netzstockung ist belegt) und `partially-proven` (gemischte Beleglage). `network-only` ist aus
dem Vokabular entfernt, weil nichts in dieser Engine eine Netzstockung beweist.

**Invariante der Schreibpfade (2026-10-17):** `cl` und `ch` entstehen aus derselben Zeile des
Recorders (`monitor/validator-trace.mjs`: `ch = closedHash`, `cl = closed === true`, und `closed`
heißt `closedHash !== null`). Eine Forensik-Zeile mit `cl: true` ohne 64-Hex-Hash ist deshalb
kein Schließ-Beweis, sondern ein zerstörter Nachweis. `normalizeDay` setzt sie auf `null` zurück
— "nicht erfasst"; `false` wäre die Gegenbehauptung, der Ledger sei nicht geschlossen, und die
ist gegenüber einem validierten Stream nicht belegbar. `npm run audit:truth` zählt genau das als
eigene Invariantzeile. Nachgetragen wird nur über denselben Zwei-Quellen-Nachweis:
`scripts/backfill-closure.mjs` schreibt `ch` nur, wenn `api.xrpscan.com` und die JSON-RPC-
Schnittstelle von `xrplcluster.com` denselben Hash für genau diesen Index melden (`chSource`,
`chVerifiedBy`, `xc`). #107696565 vom 2026-10-16 war genau so ein zerstörter Nachweis und ist am
2026-10-17 auf diesem Weg repariert: Hash deckungsgleich, Tx 49 und Close-Zeit beider Quellen
gleich.

**Nachführung beim Lesen: keine Quorum-Behauptung ohne Schließ-Beweis (2026-10-17):** Der Typname
allein reicht nicht. Der Bestand behauptete weiterhin `no-quorum` für Ledger, deren Schließung längst
belegt war — #107695059, #107694001 und #107690236, für die `api.xrpscan.com` und `xrplcluster.com`
denselben validierten Hash melden (986E8D51…34602, 20444972…8736, FB3ABE4A…5962), während dieselbe
Datei ihre Forensik-Zeile schon mit genau diesem Hash führte. `normalizeDay` stellt deshalb **beim
Lesen** um: `no-quorum` → `vote-not-observed`, außer die Schließung ist ausdrücklich verneint
(`nc: true` am Incident oder `cl === false` in der Forensik-Zeile). Der gespeicherte Typ bleibt als
`ts` erhalten, `cb` nennt die Autorität der Schließ-Aussage (`xrpscan`, `recorder` oder
`validated-ledger-stream`), `ch`/`chv` tragen Hash und Gegenprüfung an die Zeile, die sie braucht.
Die API gibt das als `typeStored`, `closureBasis` und `closureHash` zurück — die Umstellung ist
nachprüfbar, nicht bloß ein anderes Etikett. Die Zähler bleiben unangetastet: umgestellt wird die
Aussage, nicht die Zahl.

**Schließ-Beweis bis in die Incident-Zeile (`closureProofs`):** Eine Incident-Zeile ohne Forensik-Zeile
war bisher eine offene Frage — die Behauptung stand, der Beleg fehlte. `scripts/backfill-closure.mjs`
prüft deshalb seit 2026-10-17 auch über die Incidents: jeder Ledger, der eine Quorum-Behauptung
trägt und keine Forensik-Zeile hat, bekommt seinen Hash in `closureProofs`, wieder nur nach dem
Zwei-Quellen-Nachweis. Der Lauf über den Bestand: 412 Forensik-Zeilen nachgeprüft (0 Abweichung bei
Hash, Tx-Zahl und Close-Zeit), 70 Claim-Ledger ohne Forensik-Zeile, alle 70 mit Zwei-Quellen-Beweis,
0 ohne Nachweis. `npm run audit:truth` meldet diese Deckung als eigene Zeile und jede
Quorum-Behauptung ohne Beweis als Befund. `mergeClosureAddendum` trägt `closureProofs` durch jeden
Flush — sonst würde der nächste Schreibvorgang des Recorders die nachgetragenen Beweise löschen.

**Was eine Erfassungs-Lücke belegt — und was nicht:** Beleg ist die **Index-Folge dieses
Recorders** (`pg` in `ledgerStats`: die Lücke gilt genau dann, wenn `l !== pg + 1`) und der
**Lücken-Log** `gaps` mit `reason: "stream-gap"`. Der Close-Abstand ist kein Beleg: die
Live-Messung auf `xrplcluster.com` (`npm run verify:votes`) zeigte 8 000–9 000 ms Abstand bei
1 000 ms Median-Takt bei **35 von 35** gesehenen dUNL-Mitgliedern — normaler Netzbetrieb. Ebenso
ist ein Index-Sprung *innerhalb* `ledgerStats` kein Beleg, weil diese Liste nur
Abweichungs-Ledger enthält. Seit demselben Nachweis gibt es die **Empfangsbasis**: `ov` zählt alle
empfangenen Validierungen (dUNL plus Signierer außerhalb der dUNL), `ovb` ist ihr Median über die
letzten `baselineSize` Ledger, `ot` markiert Empfang unter `receptionRatio` (Tuning-Default
0.75) des eigenen Niveaus. Gemessen wird der Empfang und **nicht** die Zahl der dUNL-Stimmen, weil
die Zahl der dUNL-Stimmen teilweise aus der eigenen Zuordnung folgt und kein Empfangsbefund ist —
der Live-Nachweis: 103–107 Validierungen bei vollen 35 Mitgliedern gegen 53 bei dem Ledger, an dem
nur 30 Mitglieder gesehen wurden. Zusätzlich zeichnet der Monitor Verbindungsverlust und
Wiederaufbau als `captureEvents` auf (Art, Zeit, Index, Endpunkt); zuordenbar ist nur das
**nächste** Ereignis mit Abstand (`captureEvent.deltaMs`), und `null` heißt „nichts
aufgezeichnet“, nie „kein Ereignis“. Ohne jeden dieser Belege bleibt die Erfassungs-Frage offen
(`captureGapUnknown`) — eine offene Frage wird nicht zur Entlastung umgeschrieben. Die dUNL selbst
wird während eines Laufs nachgezogen (`TRACE_DUNL_REFRESH_MS`, Default 600 000 ms), sonst werden
ausgetauschte Mitglieder als nicht-abstimmend gezählt.

**Gegenprobe nach außen:** `npm run verify:votes` deckt dieselben Ledger index-gleich gegen
xrpscan und `xrplcluster.com` (Hash, Tx-Zahl, Close-Zeit). xrpscan antwortet in zwei Formaten —
die Close-Zeit wird deshalb über `close_time_human` gehalten, nicht über `close_time`. Am
2026-10-16 war die Deckung für 107690236, 107694001, 107695059 und 107695739 in Hash, Tx-Zahl und
Close-Zeit **identisch**; abweichend war allein die bisherige *Deutung* der Stimmenzahl. Am
107694001 ist diese Deutung durch die Sequenz des Netzes selbst widerlegt: `xrplcluster.com`
schloss 107694000 um 11:25:42Z und 107694001 um 11:25:50Z — **8 000 ms** Abstand, während der
Recorder an derselben Stelle 70 000 ms misst und **0 von 28** notwendigen Stimmen sieht. Dazwischen
liegen 17 Ledger, die dieser Rekorder nie sah (Lücken-Log `gaps` bei 107693984). „Netzstockung"
war dort also keine Messung, sondern ein Lesefehler über die eigene Lücke.
`npm run backfill:closure` trägt fehlende Hashes von außen nach; so ein Hash steht als
Fremdquelle (`chSource: "xrpscan"`) mit benannter Gegenprüfung (`chVerifiedBy`) in der Datei.
**Der Nachtrag überlebt den Flush (2026-10-17):** Nachtrag und Rekorder schreiben dieselbe
Tagesdatei. Der Rekorder hält das Tag im Speicher und schreibt es alle 30 s (lokal) bzw. alle
5 min (remote) neu - der Nachtrag war bisher beim nächsten Flush weg, weil beide Schreibpfade
das eigene Tag zurückgaben statt des frisch gelesenen Bestands. Damit war auf diesen Zeilen
plötzlich wieder keine Autorität für „Ledger geschlossen", und die Diagnose konnte unbemerkt auf
die alte Netzstockungs-Deutung zurückfallen. Beide Pfade lesen jetzt den Bestand und führen die
Nachweis-Felder zurück (`mergeClosureAddendum` / `writeDayLocal` in `lib/validator-trace-store.mjs`).
Uebernommen werden ausschliesslich `ch`, `chSource`, `chVerifiedBy`, `chAt` und `xc` einer Zeile
mit gleichem Ledger-Index; Zaehler, Incidents und Luecken bleiben, was dieser Rekorder sah. Ein
eigener Hash aus dem validierten Stream wird nie durch den Fremd-Hash ersetzt - die Fremdquelle
kann ihn nur als Gegenpruefer bestaetigen. Am echten Tag vom 16.10.2026 sind es 290 Zeilen, die
sonst ihren Nachweis verloren haetten.

**Close-Abstand braucht die Index-Folge (2026-10-17):** `close-gap` misst die Zeit zwischen zwei
**bewerteten** Ledgern. Fehlt dazwischen ein Index, ist der Abstand die Summe der Ledger, die dieser
Rekorder nie sah - kein Netz-Befund. Deshalb setzt `classifyReasons` den Tag nicht mehr, wenn
`indexGap === true`, und die Takt-Basis `gapBaseline` nimmt nur Abstände zwischen
aufeinanderfolgenden Indizes auf. Dasselbe Kriterium gilt je Ebene: Retrace-Hypothese
(`evidence.indexContinuity` mit `true` / `false` / `null`), Ledger-Karte `attackSignals`
(Mindestabstand **und** Ratio gegen den eigenen Takt, nicht nur Mindestabstand) und Muster-Monitor
`lib/pattern-watch.mjs`. Die Netz-Deutung `network-stall` folgt nur bei `indexContinuity === true`;
bei `null` (Bestand ohne `pg`) bleibt die Messung stehen und die nächste Prüfung ist die eigene
Erfassung. Nachgerechnet am Live-Fall: 107694001 mit 70 000 ms Abstand gegen 1 000 ms eigenen Takt
und Index-Sprung über 107694000 - kein `close-gap`; derselbe Abstand mit lückenloser Folge -
`close-gap`.

**Grenze aus der Schließung (Akkuratz-Regel, 2026-10-17):** ein bewiesen geschlossener Ledger hat
sein Netz-Quorum erreicht — also können von den als „kein Vote erfasst" geführten dUNL-Knoten
höchstens `dUNL − Ziel` echt gefehlt haben; jeder darüber ist nachweisbar Erfassungs-Lücke dieses
Recorders. `captureBound` in `lib/validator-trace.mjs` rechnet das je Zeile und steht an der
Kritikalitäts-Zelle, an der Messung `vote-coverage-thin` und im Sammelereignis: `members`
(aufgezeichnet als `mm`, sonst aus der Identität des Rekorder-Loops — gesehene
Mitglieder-Stimmen plus ohne-Vote-Flags), `genuineAbsentMax`, `captureArtifactMin`.
Nachgerechnet am 2026-10-16 (dUNL 35, Ziel 28), alle neun Zeilen mit gesehenen Stimmen unter Ziel:
107690236 → 8, 107694001 → 28, 107694020 → 4, 107695059 → 12, 107695739 → 17, 107696265 → 18,
107698041 → 3, 107699073 → 12, 107699400 → 10; zusammen **112 Knoten-Ledger, die nicht echt sein
können**. Welche Knoten wirklich fehlten, ist aus einem einzelnen Mithörstrom nicht bestimmbar und
wird nicht geraten.

**Dauer-Kontrolle:** `npm run audit:truth` (`scripts/audit-ground-truth.mjs`) prüft jede
Forensik-Zeile gegen ihre eigenen Rechenregeln (`need == ceil(members × 0.8)`,
`mg == top − need`, Rekorder-Identität, Hash-Pflicht bei geschlossener Zeile) und jede Zeile mit
abstreitbarem Vote-Anspruch index-gleich gegen xrpscan **und** `xrplcluster.com` — Hash, Tx-Zahl
und Close-Zeit, inklusive der gespeicherten Gegenprüf-Vermerke (`xc`), die dabei facettenweise
erneut gehalten werden. Exit 1 bei jeder Abweichung, `--all` prüft jede Forensik-Zeile.

Der Voll-Lauf am 2026-10-17 über **alle 367** Forensik-Zeilen des 16.10.: 367 deckungsgleich,
0 Abweichungen, 0 ungeprüfte Zeilen, alle Invariantzen 0. Dabei zeigte sich, dass
`xrplcluster.com` ein **Pool** ist: `ledgerNotFound` heißt „dieser Knoten hat den Ledger
nicht", nicht „der Ledger existiert nicht" — 107698656 und 107698657 wurden nach einem
Knotenwechsel gefunden. Das Audit holt die Absenz deshalb mehrfach bei verschiedenen Knoten und
unterscheidet drei Zustände: **Exit 0** = jede Zeile gegen mindestens eine Quelle gedeckt,
**Exit 1** = echte Abweichung (Zahl oder Hash widerspricht der Quelle oder sich selbst),
**Exit 2** = keine Abweichung gefunden, aber Zeilen blieben ungeprüft. Eine erreichbare Quelle
prüft die Zeile auch dann, wenn die andere ablehnt; fehlende Deckung steht als „ungeprüft" da,
nie als Bestätigung.

**Ebene 2 — Transaktions-Ebene (warum es passierte):** `lib/tx-forensics.mjs`
liest den `transactions`-Stream und misst die **Form** der Transaktionen genau
dieses Ledgers — Absender-/Empfänger-Streuung, Fächerung, Fehlerrate,
Typ-Mischung, Gebühren, Batch-Verstärkung (`Batch`-Tx mit `InnerTransactions` /
`RawTransactions`), Kontenerstellungen, Orderbuch- und NFT-Aktivität — gegen die
rollende Basis der vorangegangenen Ledger. Gemeldete Signaturen:
`drainer-fanout`, `sweep-window` (dasselbe Konto erreicht über Ledger hinweg
immer neue Empfänger — die Form, die ein Einzel-Ledger-Fächer nicht zeigt),
`sender-burst`, `failure-spike`, `batch-amplify`, `fee-spike`, `offer-flood`,
`nft-flood`, `create-wave`, `feature-change`, `type-burst:<T>`.

**Korrelation (das eigentliche Werkzeug für Validator-Betreiber):**
`riskProfile` in `lib/validator-retrace.mjs` vergleicht die Ausfallwahrscheinlichkeit
eines Ledgers **mit** dieser Signatur gegen Ledger **ohne** sie — Nenner und Zähler
aus vollständigen Tageszählern (`anomaly` / `anomalyFail` über alle beobachteten
Ledger), nie aus einer Teilmenge. `lift` ist das Verhältnis; `reliable: false` +
`note: "sample-too-small"` bleibt stehen, solange zu wenige Ledger gezählt wurden —
ein einzelner Fall ist keine Rate.

**Retrace je Vorfall** (`retraceIncident`, `retraceForValidator`): die messbare
Ursache mit Stärkenrang `measured` (direkte Ledger-Messung: Quorum-Rand, Hash-Split,
Last, Takt) > `cohort` (wie viele Nachbarn gleichzeitig betroffen — Netzereignis vs.
nur dieser Validator) > `correlated` (Ledger-Kontext/Signatur) > `none` (nichts
Korreliertes gefunden), plus `guidanceFor` (welcher Prüfschritt als nächstes) und
`dataGaps` (was die Aufzeichnung dazu nicht hergibt).

**Diagnose-Ebene (warum eine Serie, nicht ein Ledger)** (`lib/validator-diagnose.mjs`, `diagnosis`
im Antwortkörper): die Retrace erklärt einen Vorfall aus seinem Ledger — die Zeitfolge und die
Last kann sie nicht. Beides ist gemessen die Haupterklärung, also sitzt die Diagnose **nach**
der Retrace, nicht statt ihr. `fingerprint`: eigene Ausfallrate gegen Netzmedian und Netzmittel,
Anteil der eigenen Vorfälle auf Netzereignis-Ledgern, Anteil in Serien, längste Serie,
Spitzenstunden, mit Urteil `clean` / `network-driven` / `chronic-outage` / `solo-only` /
`outlier-node` / `intermittent` / `mixed`. `runs`: Ausfallserien mit Länge, Dauer und wie viele
Nachbarn dieselben Ledger gleichzeitig verfehlten. `criticality`: Quorum-Kritikalität (wie knapp
das Quorum auf den betroffenen Ledgern stand). `load`: `loadResponseCurve` — Ausfallrate je
**absoluter** Tx-Stufe aus `LOAD_BUCKETS` (10/25/50/100/200/400/800/1600/3200), Urteil
`load-limited` / `load-resilient` / `always-failing` / `unknown`. Relative Last-Tags vergleichen
einen Ledger nur mit seinem eigenen Median; damit ist die Betreiberfrage („ab wie vielen Tx fällt
MEIN Knoten zurück, und halten die anderen dieselbe Last?“) nicht beantwortbar — nur absolute
Stufen sind über Tage und Validatoren hinweg vergleichbar. Dieselbe Kurve ohne `master` ist die
Netzseite: ohne den Vergleich wäre die Kurve eines einzelnen Knotens eine Zahl ohne Bedeutung.

**Angriffs-Wirkungs-Ebene (wann es passierte)** (`lib/attack-impact.mjs`, `impact` im Antwortkörper
der Netz-Sicht): alle bisherigen Ebenen fragen den **Ledger** — Quorum-Rand, Last, Tx-Form dieses
einen Ledgers. Diese Ebene fragt die **Zeit**: in den Stunden, in denen der Honeypot Drainer,
Dusting-Wellen und Sweeps sieht, steigt die Ausfallrate der dUNL-Knoten — oder sie steigt nicht.
Eingabe sind die Stunden-Buckets des Trace-Tagesfiles und die Cluster der Betrugs-Historie
(`data/history.json`), deshalb sitzt die Ebene dort, wo beide Quellen zusammenkommen:
`crossValidatorPatterns` (lokaler Server) und `api/stats.js` (Produktion, Cluster über
`readHistoryGitHub` aus dem Daten-Repo). Beides zu verdrahten ist kein Detail: `vercel.json`
rewritet `/api/validator-trace` auf `/api/stats?route=trace`, die Produktion läuft also nicht über
`server/index.mjs`.

Drei Fallen, die die Engine ausdrücklich entschärft — jede einzelne macht ein Werkzeug glaubwürdig,
das zu früh jubelt:

1. **Tageszeit.** Angriffe und Ausfälle haben Stoßzeiten. Das Urteil hängt an der **gepaarten
   Gegenprobe** (Angriffsstunden gegen ruhige Stunden derselben UTC-Stunde), nicht am rohen Lift.
   Der rohe Wert bleibt sichtbar (`zRaw`, `rateWithout`), damit die Falle selbst lesbar bleibt.
2. **Aufzeichnungs-Lücken.** Eine Stunde ohne Ledger ist keine ruhige Stunde, sondern eine
   unbeobachtete. Sie verwässert die Gegenprobe nicht, sie wird ausgezählt
   (`thinCells`, `clustersOutsideRecording`, `incidentsOutsideMeasuredCells`).
3. **Ein einzelner Knoten.** Gemessen wird auf **Validator-Ledger-Paaren** (Nenner = alle
   beobachteten Knoten-Slots der Stunde, Zähler = die zurückgefallenen), nicht auf Ledger-Ebene.
   Auf Ledger-Ebene macht ein einziger Knoten, der eine Stunde komplett verpasst, die Rate zu
   100 % — genau das ist am 14.10.2026 zwischen 05 und 09 UTC gemessen: ein Knoten verpasste dort
   jeden einzelnen Ledger (920/920, 921/921, 918/918, 916/916) und ließ jede dieser Stunden wie
   einen Netz-Zusammenbruch aussehen. Die Ledger-Ebene bleibt sichtbar (`ledgerRateWith` /
   `ledgerRateWithout`), weil sie die Knoten-Diagnose ist — aber sie trägt kein Netz-Urteil:
   trägt der Effekt nur eine Minderheit der Knoten
   (`contributingValidators < minContributingValidators`), heißt das Urteil `node-driven` und
   nicht `attack-linked`.

Urteile (`IMPACT_VERDICTS`): `attack-linked` / `node-driven` / `no-link` / `thin-overlap` /
`no-overlap` / `unknown`. `unknown` ist bewusst **nicht** gleich 'kein Zusammenhang': ohne
Angriffssichtung im Fenster gibt es keine Vergleichsbasis, und eine leere Historie wie einen
sauberen Befund aussehen zu lassen ist der teuerste Fehler, den diese Ebene machen kann.
Schwellen (`IMPACT_DEFAULTS`: Stunden-Zelle 60 min, 60 Ledger je Stunde für eine Rate, 4
Überlappungsstunden, 600 Knoten-Slots je Gruppe, |z| ≥ 2, 3 tragende Validatoren) sind
Tuning-Defaults und per `opts` überschreibbar — die Zeit-Ebene ist eine Korrelation, kein Beweis.

**3D-Intervall-Profil** (`profileCells`, UI `profile3d`): 24 Intervalle über das
gewählte Fenster. Säulenöhe = eigene Abweichungen (Achsenmaß identisch zu den
Gitterlinien), Stapelfarben = Vorfallstyp, Grundriss + Kohortenstreifen =
Intervall-Zustand (`clean` / `solo` / `few peers` / `network event` /
`deviation, cohort not recorded` / `no ledger observed`), Signaturmarker +
Signaturstreifen = Transaktions-Signatur an einem Ausfall-Ledger dieses Intervalls.
Geometrie ist deterministisch und **nachgerechnet, nicht gesetzt**: `--skew: 45deg` mit
`--dz-k = 1` (`DEPTH_SKEW_K`), also `--dz = --d`. Eine feste Tiefe machte aus kleinen Werten
schiefe Bänder (live gemessen 2026-10-16: peak 5000, `--d` 7,63 px, ein Intervall mit einem
Vorfall 2,48 px hoch); bei 45deg ist die Scherfläche so hoch wie die Säule tief ist — kanonische
Kavaliere-Projektion und die Obergrenze dessen, was eine Ansicht von oben zeigen kann.
Zellenbreite `--col-w = (100cqw - --gutter - 3px - 23 x --gap) / 24` (gemessen 30,87 px bei
961 px Content), Tiefe `--d = min(max(4px, 0,22 x --col-w), 8,5px, --plot-h x --dmax)`: die
4-px-Untergrenze greift unter 568 px Content, der 8,5-px-Deckel über 1192 px, und `--dmax`
(`CAP_RATIO` x kürzeste gezeichnete Säulenhöhe / Achsenmaximum, aus `profile3d`) hält die Kappe
auf höchstens ein Drittel des kürzesten Körpers (`CAP_RATIO = 1/3`): eine Kappe, die höher ist als
ihr Körper, macht aus der Säule einen Keil und ihre scheinbare Höhe ein Vielfaches des gemessenen
Wertes (live gemessen 2026-10-16: 6,79 px Kappe auf 8,80 px Körper = 0,77, Silhouette breiter als
hoch). Säulen-Zeile, Kohortenstreifen und Signaturstreifen teilen dieselben Ränder, denselben
Abstand und dieselbe Flex-Basis; unter jeder Säule steht dieselbe Bodenplatte (`--base-h: 6px`) mit
eigener Deckfläche (`.vt-base::after`, Höhe `--dzc`), und `.vt-plot` reserviert
`--plot-h + --dz + --base-h + --label-h` (208 + 6,79 + 6 + 15 = 235,79 px), sodass höchste Säule
und Wertemarke nie abgeschnitten werden (Guards: `public/validator-trace-markup.test.mjs`).
Achse logarithmisch in `log(1 + v)`: `axisUnit(v, peak) = peak x ln(1 + v) / ln(1 + peak)`, damit
`peak -> peak` ohne Untergrenze und ohne Mindestbalken. Linear wäre ein Vorfall bei peak 5000 ein
0,04-px-Streifen (208 px Plot); die alte Wurzel gab bei peak 400 nur 8,80 px Körper — zu kurz für
eine Kappe, die als Fläche lesbar bleibt (log an derselben Stelle: 24,05 px). Gitterlinien sind
Dekaden und Spitze (`axisTicks`, höchstens fünf Intervalle); ihre Abstände sind **nicht gleich**,
sondern wachsen monoton gegen den asymptotischen Dekadenabstand `peak x ln(10) / ln(1 + peak)` —
1 -> 10 misst immer 0,7404 davon, 100 -> 1000 immer 0,9961, weil sich der peak-Faktor kürzt.
Unter 660 px Content-Breite des Containers dünnen `@container`-Regeln die Wertemarken (jede zweite
fällt weg), weil vier Ziffern den Abstand ihrer Zentren übersteigen.

**Ehrliche Grenzen (bewusst sichtbar, nicht still null):**
`shapeSeen` / `shapeMissing` trennen „keine Signatur gemessen“ von „Transaktionen
waren da, Form aber nicht erfasst“; `ledgerStatsTruncated` markiert verworfene
Forensik-Details (Deckel `LEDGER_STATS_CAP` 6000); `estimated: true` kennzeichnet
aus Stunden-Buckets verteilte Ledger-Zähler; `note: "no-ledger-counter"` lässt eine
Signatur ohne Zähler ohne Rate stehen. Alle Schwellen
(`TRACE_DEFAULTS`, `TX_FORENSICS_DEFAULTS`, `RETRACE_DEFAULTS`) sind
**TUNING-DEFAULTS ohne Kampagnen-Nachweis** und per `opts` überschreibbar — die
Signatur ist eine Korrelation im selben Ledger, kein Beweis.

**Umgebungsvariablen des Recorders:** `TRACE_WSS` (Komma-Liste, Default
`wss://xrplcluster.com`), `TRACE_TX_SHAPE` (Forensik an, nur `=0` aus — dann weist
die Retrace die ganze Ebene als Datenlücke aus), `TRACE_RUN_SECONDS` (0 = bis zum
Abbruch; Workflow setzt 18000), `TRACE_DATA_DIR` (Ziel der Tagesdateien),
`GITHUB_HISTORY_TOKEN` / `GITHUB_HISTORY_REPO` (Schreibweg; im Workflow stattdessen
`HISTORY_DEPLOY_KEY`).

**Produktions-Parität der Angriffsseite (gemessen 2026-10-16 an der Live-Site):** die
Wirkungs-Ebene hängt an den Clustern der Betrugs-Historie — `traceForValidator` erhält sie nur,
wenn sie mitgegeben werden. Auf Vercel fehlten sie, während der lokale Server sie gab: live war
`impact` null und die Angriffsstunde fehlte als Ursache. Beide Einstiegspunkte
(`api/stats.js` für Vercel, `server/index.mjs` für den lokalen Betrieb) geben sie jetzt allen
drei Konsumenten — `traceForValidator`, `crossValidatorPatterns` und `validatorReport` (der
maschinenlesbare Selbst-Report trägt `impact` mit `verdict`, `verdictAuthority`,
`verdictReason`, `attackHours`, `overlapHours`, `clustersInWindow`). Guard:
`lib/trace-attack-side.test.mjs`.

**`historyError` ist ein Vertrag, kein Fehlerfeld:** eine nicht lesbare Historie ist ein
anderer Zustand als eine ohne Cluster. `catch { clusters = [] }` machte eine korrumpierte
Bestandsdatei zu einem Befund ohne Angriffe. Getrennt wird jetzt der Anlege-Fall
(`ENOENT` → leere Liste, kein Hinweis) von echten Lesefehlern (`historyError`-Text in der
Antwort, `impact` urteilt `unknown`). Guard: `lib/trace-attack-side.test.mjs`.

**Bestands-Integrität von `data/history.json`:** zwei Defekte, beide gemessen.
(1) `saveLocalHistory` schrieb immer in denselben `history.json.tmp`. Zwei gleichzeitige
Schreibende — zwei `server/index.mjs`-Prozesse auf demselben Bestand, Request-Handler plus
Drainer-Pfad — verzahnten ihre Schreibpositionen in derselben Datei, und der `rename` machte aus
dem Gemisch den Bestand: valider Kopf (1000 Cluster) plus 6.821 Bytes Fremdschwanz, nicht mehr
parsebar. Jetzt eigener tmp-Name pro Vorgang (`Datei.PID.Zeit_seqenz.tmp`) und
Byte-Laengen-Prüfung **vor** dem `rename`; ein fehlgeschlagener Schreibvorgang ersetzt den
bisherigen Bestand nicht. (2) `sanitizeHistoryList` setzte bei einer Schlüsselkollision den
Rückgabewert von `mergeFields` (ein Boolean) als Listenwert ein — aus dem Cluster wurde `true`,
und der nächste Ladevorgang verwarf ihn still; über `mergeHistory` wanderte das bis in den
GitHub-Bestand. Jetzt bleibt der Cluster erhalten, und `serializeHistoryList` verweigert
Nicht-Cluster-Einträge laut. Guards: `lib/history-integrity.test.mjs`. Korrumpierte Stände sind
als `data/history.json.corrupt-<datum>.bak` gesichert.

**Port:** `server/index.mjs` nimmt `PORT` aus der Umgebung und fällt auf `config.json` zurück
(`Number(process.env.PORT) || config.port`). Vercel setzt `PORT` selbst — ein hart gesetzter
Port in `config.json` würde die App gegen die Umgebung laufen lassen.

## Bekannte Grenzen

- **Path-Payment-Zwischenhops:** Adressen entlang des Zahlungs-Pfads
  (intermediate hops) werden derzeit **nicht** als Gegenpartei erfasst — die
  Stream-Nachricht enthält die Pfad-Konten nur indirekt über die
  Meta-Bilanzänderungen. Erfasst werden Absender und Ziel; Zwischenhops
  bleiben unbeobachtet.
- **NFTokenAcceptOffer-Angebotsauflösung:** Die direkte **Sell-Annahme**
  (`NFTokenSellOffer`, ohne `NFTokenBuyOffer`) wird seit dem Lücken-Audit
  2026-10-07 meta-basiert aufgelöst: das im selben Ledger konsumierte
  NFTokenOffer-Objekt (DeletedNode) liefert Owner (Verkäufer) und Amount —
  daraus entsteht die Kante Käufer → Verkäufer. Bewusst **unmapped** bleiben:
  die **Buy-Annahme** (Zahlung läuft Owner → tx.Account — Richtung im
  Kanten-Vertrag nicht ausdrückbar) und der **Brokered Mode** (`NFTokenBrokerFee`,
  zwei konsumierte Offers — Owner-Auflösung mehrdeutig); ohne Meta im Entry
  entsteht ebenfalls keine Kante. Nicht per `ledger_entry` nachgelöst wird
  weiterhin (kein Request-Budget für Offer-Ids).
- **CheckCash/Clawback kantenlos:** CheckCash kennt kein Empfänger-Feld
  (nur CheckID/Amount/DeliverMin — der Casher ist selbst Empfänger; der
  ursprüngliche Check-Empfänger steckt nur im Check-Ledger-Objekt), und
  Clawbacks laufen Issuer → Holder-Adresse als Absender — die Flussrichtung
  ist im Kanten-Vertrag (account → destination) nicht ausdrückbar. Beide
  Typen zählen als Berührung/Evidenz, erzeugen aber keine Kante.
- **AMM-Kanten meta-basiert (Kritik-Runde 3):** AMMCreate/AMMDeposit
  erzeugen jetzt eine Kante `tx.Account → AMM-Konto` — die Gegenpartei
  kommt aus der Ledger-Meta des expand:true-Entries (CreatedNode/
  ModifiedNode `LedgerEntryType: "AMM"`, `FinalFields.Account` bzw.
  `NewFields.Account`, xrpl@4.0.0 `ledger/AMM.d.ts:12`; ohne Meta keine
  Kante, keine erfundene Adresse, +0 Requests). **Bewusst kantenlos
  bleiben** AMMWithdraw/AMMDelete/AMMVote/AMMBid (kein Gegenpartei-Feld
  in der Spec, Richtung AMM → Account im Kanten-Vertrag nicht
  ausdrückbar) sowie AMMClawback/VaultClawback (Holder → Issuer nicht
  ausdrückbar) und die **NFTokenCreateOffer-Owner-Zuordnung** (kein
  Owner-Feld in der Tx; `Destination` funktioniert über die generische
  Empfänger-Zeile). Tot gelesene Felder (`tx.NFTokenOfferAmount`,
  `tx.VaultOwner` — existieren in keiner Spec) sind entfernt.
  Sofort gefüllte OfferCreates erzeugen weiterhin keine Kante
  (Balance-Deltas in der Meta, keine Gegenpartei-Adresse).
- **Kanten-Codierung (Tx-Kategorie):** Kanten färben je Tx-Kategorie
  (`txCategory`, edge-colors.mjs): Betrug = Rot (Severity-Override VOR der
  Kategorie), Payment = Grün (success-Familie; im Noir-Theme exakt
  `--a6-success` — bewusste „grün=gut"-Bundlung), DEX+AMM zusammen als
  „Market" (die Einzeltöne waren praktisch ununterscheidbar), NFT = Fuchsia,
  Escrow/Check-Channel/Admin in der Tokensprache. Betrugskanten tragen
  zusätzlich ein Strichel-Muster (nicht-farblicher Kanal für Rot-Grün-
  Schwäche); einzige Ausnahme ist die 3D-Bühne, deren Bundle keine
  Kanten-Dashes kennt (dort trägt Farbe + Kanten-Tooltip die Information).
- **Funding/Sweep-Messung Payment-only:** `traceFunding` und
  `measureSweepRatio` werten ausschließlich Payments aus — Abflüsse über
  EscrowFinish/CheckCash/AMM-/NFT-Verkäufe zählen nicht in `sweepRatio`
  und unterschätzen non-Payment-Sweeps (bewusste Grenze der
  Drainer-Bestätigung).
- **Market-Regeln (Kritik-Runde 3, `lib/detector.mjs`):** `amm-wash-swap`,
  `thin-pool-exploit` und `spoof-offer-cycle` sind deterministische
  Volumen-/Zyklus-Heuristiken auf OfferCreate/OfferCancel-Fills und
  Ledger-Meta (expand:true liefert beides bereits, +0 Requests), alle
  `suspect` — kein Schuldnachweis, keine 30-Tage-malicious-Retention
  (`HISTORY_FRAUD_RULES` bleibt dreiköpfig). Dünne Pools brauchen **≥ 5
  beobachtete Fills desselben Pairs** im Fenster — darunter gilt
  „nicht messbar statt raten" (kein Fund). Börsen-/Multi-User-Konten
  fallen über `marketExcludes` raus (Advance-Pfad: Exchange-Registry ∪
  multiUser ∪ config-benign ∪ Köder; Snapshot-Pfade: config-benign ∪
  Köder — dokumentierte Guard-Grenze). Schwellen sind Tuning-Defaults,
  maschinenlesbar über `/api/rules` (Re-Export von `MARKET_THRESHOLDS`).
- **Selbst-Check nur gegen Bekanntes:** Der Check findet ausschließlich
  Kontakte zu Adressen, die dieser Monitor bereits als Bedrohung erfasst hat.
  Eine Adresse, die von einer noch unbekannten Scam-Adresse angeschrieben
  wurde, gilt als `clean` — die Aussagekraft wächst mit der Bedrohungs-Datenbank.
  Auf dem Testnet sind echte Community-Adressen meist nicht vorhanden
  (`verdict: "unknown"`); die sinnvolle Prüfung läuft auf Mainnet.

## Mainnet-Betrieb (aktiv seit 2026-09-28)

1. **`config.json`:** bereits umgestellt auf `mainnet` / `wss://honeycluster.io`
   (Umstellung 2026-10-02: offiziell auf xrpl.org gelisteter Full-History-
   Server mit Clio; alternativ `wss://xrplcluster.com` oder eigener Node
   `wss://s1.ripple.com:51233` via `WSS_URL`/`RPC_URL`). Auf Mainnet
   **zwingend** `operator_addresses` setzen (Sweep-/Cold-Wallets), sonst
   erzeugt jede eigene Sammelzahlung einen Kompromittierungs-Alarm.
2. **Köder-Konten finanzieren:** `npm run provision` funktioniert auf Mainnet
   **nicht** (kein Faucet; das Skript bricht mit Hinweis ab). Die bestehenden
   `bait.json`-Keypaare sind netzwerkunabhängig — dieselben Adressen existieren
   auf Mainnet, sobald sie finanziert werden:
   - Jede Köder-Adresse mit einer kleinen, bewusst begrenzten Menge XRP
     finanzieren (Börsen-Auszahlung oder eigene Wallet). Empfohlen: **5 XRP
     pro Köder** (1 XRP Konto-Reserve + Köder-Guthaben).
   - Mainnet-Reserven live verifiziert am 2026-09-28 via `server_info`:
     **1 XRP Basis-Reserve, 0,2 XRP pro Owner-Objekt**.
   - `bait.json` bleibt unverändert (gleiche Seeds → gleiche Adressen);
     bei Rotation alte Einträge nach `bait-history.json` verschieben.
3. **Code bleibt unverändert:** `monitor/monitor.mjs` und `server/index.mjs`
   lesen Netz und WSS-URL ausschließlich aus `config.json`.
4. **`npm run simulate` ist Testnet-only** (bricht auf Mainnet ab) — auf
   Mainnet beobachtet man reale Angriffe, keine simulierten.
5. **Sicherheit:** `bait.json` mit den echten Seeds ist auf Mainnet ein
   Vermögenswert. Dateirechte beschränken (`icacls` siehe oben bzw.
   `chmod 600`), niemals committen (`.gitignore` ist für beide Bait-Dateien
   gesetzt), Köder-Budget klein halten.

## Deployment auf Vercel (kostenlos, Hobby-Plan)

Vercel ist Serverless — ein dauerhafter Monitor (WebSocket-Abo) läuft dort
**nicht**. Dafür leitet `lib/threats-service.mjs` die Bedrohungsliste bei jedem
API-Aufruf direkt aus der Transaktionshistorie der Köder-Konten ab
(`account_tx`, neuste 50 pro Köder, 60-Sekunden-Cache pro Function-Instanz)
und liefert sie durch **dieselbe** Anonymitätsschicht (`lib/sanitize.mjs`).

**Voraussetzungen:**
1. GitHub-Repo (dieses Projekt) + Vercel-Konto (Hobby, kostenlos) — Repo
   importieren, Framework-Presets: „Other" (keins), kein Build-Schritt.
2. **Env-Variable `BAIT_ADDRESSES`** in Vercel setzen: die drei
   Köder-Adressen, Komma-getrennt (nur Adressen — **nie Seeds**). Seeds
   verlassen das lokale `bait.json` niemals. Optional: `FAUCET_ADDRESSES`,
   `WSS_URL`, `NETWORK`.
3. `vercel.json` (bereits vorhanden) mappt `/`, `/app.js`, `/style.css` auf
   `public/` und die `api/`-Functions auf `/api/*`.

**Einschränkungen der Serverless-Variante (ehrlich):**
- Keine Echtzeit-Subscription: Datenstand maximal 60 s alt (Cache) plus
  Polling-Intervall des Frontends (5 s).
- Funding-Rückverfolgung Tiefe 1 statt 2 (Serverless-Zeitbudget).
- Für Vollständigkeit (Echtzeit, Tiefe 2, Kompromittierungs-Alarme in
  Echtzeit) lokal `npm run monitor` + `npm start` betreiben; Vercel ist die
  öffentliche Lese-Ansicht.

## Live-Ledger-Analyse, Cron-Trigger und Request-Budget (honeycluster, Stand 2026-10-02)

**Server-Walk (Standard-Datenquelle):** Der Server-Walk (`api/advance.js`)
läuft gegen **honeycluster.io** (offiziell auf xrpl.org/docs/tutorials/
public-servers gelisteter Mainnet-Full-History-Server mit Clio, complete_
ledgers ab Genesis-Nähe — live geprobt 2026-10-02). Pro Block GENAU EIN
Request `{method:'ledger', params:[{ledger_index, transactions:true,
expand:true}]}` — expand:true liefert alle Tx-Objekte mit metaData (live
belegt: ohne expand 0 volle Objekte, mit expand vollständig inkl.
PreviousFields.Balance; Adapter stempelt meta/ledger_index/close_time_iso).
Die Hash-Auflösung über separate tx-Kommandos (Units-Modell mit
`MAX_RESOLVE`/`strideHashes`) entfällt im Walk; sie bleibt defensiver
Fallback in `api/ledger.js`/`lib/live-gate.mjs` für Endpunkte ohne
expand-Support.

**Request-Budget statt Units-Quota:** honeycluster-Raten (Nutzer-Angabe
2026-10-02): 10 req/s steady, 20 Requests beim Start, Burst 50 req/5-s-
Fenster, Resett nach 30 s Inaktivität. `api/advance.js`: `REQUESTS_PER_SEC
= 10`, `TICK_REQUEST_BUDGET = 250` (25 s nutzbare Tick-Zeit × 10/s,
konservativ unter der simulierten Obergrenze 270 — Simulation in
`lib/rate-gate.test.mjs`: 70 req/5 s, 270 req/25 s, 320 req/30 s),
`DEFAULT_BUDGET = 140` Blöcke/Tick (Aufhol-Beschaltung 05.10.2026; Bilanz
140 + Replay 40 + Entity 20 + Seed 1 = 201 ≤ 250). `FETCH_PARALLEL = 4`
(expand:true-Latenz gemessen Ø ~0,7 s → ~5,7 req/s < 10/s steady); der
Token-Bucket `lib/rate-gate.mjs` kappt **pro Request**, nicht pro Tick.
429/5xx werden behandelt wie slowDown/tooBusy (retry-after-Header,
Deadline-Guard). Throttle-Semantik bei echtem Überschreiten ist UNVERIFIED
(bewusst nicht bis zur Grenze belastet).

**Vollabdeckung und Catch-up:** 1 Request/Block → 12,6–15,3 req/min
(0,21–0,25 req/s, ~2,5 % des steady-Limits). 5-min-Bedarf 63–77 Blöcke;
ein Tick Budget 140 → Headroom ~1,8–2,2×. Catch-up 1 h Rückstand
(758–915 Blöcke): ~6–7 Ticks Budget-seitig (Wall-Deckel ~19-s-Walk-Fenster
macht live ~8–14); mit drei versetzten Crons (Tick alle ~100 s, bis zu
420 Blöcke/5 min) ≈ 13–15 min. Blockrate gemessen 15,25/min
(60-s-Probe), dokumentiert 12,63/min — NICHT 181k Blöcke/Tag (das wäre
0,5-s-Takt); real 18.187–21.960 Blöcke/Tag.

**Historie (Block-Fenster):** `GET /api/block-window?range=24h|3d|7d`
liefert Stunden-Rollups (≤ 168 Zeilen/7 d) + geflaggte Blockdetails im
Volltext; ungeflaggte Txs nur zählbar. Persistenz als Tages-Chunks
`data/block-window/<YYYY-MM-DD>.json` (gemessen Ø 64,2 B/Block →
1,1–2,3 MB/Tag, 7,8–16,2 MB/7 d; GitHub-Limit 100 MB/Datei), Retention
7 Tage (Delete im Advance-Tick). Köder-Endpunkte werden vor Persistenz
UND Auslieferung gefiltert (`lib/block-window.mjs`).

**Warum Sampling (historisch, xrplcluster-Pfad 2026-10-01/02):** xrplcluster
drosselte pro Egress-IP per Units-Quota („units quota (10000 per 60s)",
live beobachtet; „(500000 per 3600s)"). Der `ledgerClosed`-Event liefert
keine Hashes, eine volle Blockanalyse kostete 1 `ledger`- plus bis zu 6
`tx`-Kommandos → 88 Kommandos/min gegen den kalibrierten Deckel 14 —
deshalb Sampling `ANALYZE_EVERY_N_BLOCKS = 7` mit Tx-Kappe. Für den
Server-Walk ist das durch honeycluster + expand:true obsolet (1 Request/
Block); die clientseitige Sampling-Schicht wird mit dem Opt-in-LIVE-Modus
abgelöst (public/*, separater Umbau).

**Automatischer Advance-Trigger (GitHub Actions, versetzt, ~100-s-Takt):**
`.github/workflows/advance-cron.yml` (Offset 0), `advance-cron-b.yml`
(Offset 2) und `advance-cron-c.yml` (Offset 4) rufen zusammen alle ~100 s
`POST https://honeypot-xrpl.vercel.app/api/advance` auf (GitHub Actions
`schedule`, kleinste erlaubte Frequenz 5 min pro Workflow; `workflow_
dispatch` für manuelle Ticks). Gemeinsamer `concurrency: advance-tick` mit
`cancel-in-progress: false` — nie zwei parallele Walks. Kein Actions-Secret
nötig — der Endpunkt ist ein öffentlicher POST; die GitHub-Token für das
Datenrepo liegt ausschließlich als ENV `GITHUB_HISTORY_TOKEN` im
Vercel-Projekt. Ohne Token antwortet der Endpunkt fail-closed mit 503;
der Tick bleibt dann harmlos.

**Warum kein `vercel.json`-Cron (Befund 2026-10-02):** Ein `*/2 * * * *`-Cron
in `vercel.json` wurde versucht und **ließ den Vercel-Deploy fehlschlagen** —
der Hobby-Plan (dieses Projekt, siehe oben) erlaubt laut Vercel-Doku nur
Cron-Expressions mit höchstens einem Lauf pro Tag: „Expressions that run more
frequently will fail deployment". Der `crons`-Block wurde daher entfernt.
Alternativen für höhere Taktung: Upgrade auf Pro/Team (dann ist ein
Vercel-Cron `*/2` wieder möglich) oder ein externer Scheduler — jeweils ohne
neue Secrets im Repo.

**ENV-Liste (Vercel):**
| Variable | Pflicht? | Zweck |
|---|---|---|
| `GITHUB_HISTORY_TOKEN` | **Pflicht** für Advance/Flow-State/Block-Fenster (fail-closed 503 sonst) | GitHub-Token fürs Datenrepo (`lib/history.mjs`) |
| `GITHUB_HISTORY_REPO` | optional (Default `Krypto-Whitehat/honeypot-xrpl-history`) | Datenrepo (`lib/history.mjs`) |
| `GITHUB_HISTORY_BRANCH` | optional (Default `main`) | Branch (`lib/history.mjs`) |
| `ADVANCE_BUDGET` | optional (Default 140, `api/advance.js` `DEFAULT_BUDGET`) | Blöcke pro Tick |
| `ADVANCE_LOOKBACK` | optional (Default 0 = Live-Edge) | initialer Catch-up (`api/advance.js`) |
| `RPC_URL` | optional (Default aus `config.json` → honeycluster.io) | HTTP-JSON-RPC-Endpunkt aller Server-Pfade |
| `BAIT_ADDRESSES`, `WSS_URL`, `NETWORK` | optional | wie oben |

**Kalibrierungsfahrt (vor jeder Budget-Erhöhung):**
`node scripts/calibrate-quota.mjs ledger` bzw. `... tx` misst real, wie viele
Requests pro 60-s-Fenster durchgehen, bevor HTTP 429/tooBusy/slowDown kommt
(429-aware, retry-after-Header wird protokolliert; Import der Request-Budget-
Konstanten aus `api/advance.js`). **Ergebnis 2026-10-02 (honeycluster):**
60 Requests in 1,5 s (Parallelität 12) gingen alle als 200 durch, kein
429/tooBusy ausgelöst — bewusst nicht weiter belastet; die **Throttle-
Semantik bei echtem Überschreiten bleibt UNVERIFIED**. Budgets bleiben
deshalb auf dem konservativen Request-Modell (10 req/s steady, Burst 50/5 s
nach Nutzer-Angabe); Kalibrierung nachholen, bevor `TICK_REQUEST_BUDGET`/
`ADVANCE_BUDGET` erhöht werden.

**Egress-Bilanz (honeycluster: 10 req/s steady pro Egress-IP, Burst 50/5 s):**

| Verbraucher | Requests |
|---|---|
| Actions-Tick `/api/advance` (3 versetzte Workflows ≈ Tick alle 100 s, Budget 140 Blöcke = 140 Requests worst case, Parallelität 4 → ~5,7 req/s, pro Request gated; Wall-Deckel maxDuration 30 s kappt live auf ~55–108 Blöcke/Tick) | ≤ **140 req/100 s = 84/min-Spitze**, mittig unter 10/s |
| `/api/ledger`-Snapshot (expand:true, 1 Request, 60-s-Cache) | ≤ **1/min** pro Instanz |
| `/api/flow-state` validatedIndex (1 RPC, 60-s-Prozess-Cache) | ≤ **1/min** pro Instanz |
| `/api/block-window` (0 RPC — liest nur GitHub-Contents, 60-s-Cache) | **0** |
| **Summe Server-Egress gegen honeycluster** | **deutlich unter 10 req/s** (Walk dominiert: ≤ 140 req in ≤ 30 s Function-Zeit, durch Gate ≤ 10/s) |
| Browser-Opt-in-LIVE (pro Besucher-IP, WSS + 1 ledger-Kommando/Block, clientseitiger rate-gate) | ≤ **0,25 req/s pro Tab** |

Der Server-Walk teilt die honeycluster-Rate nur mit sich selbst (concurrency-
group `advance-tick` verhindert parallele Walks; Rate-Gate pro Request).
Browser-Besucher gehen pro eigener IP und sind damit kein Server-Egress.
**Im Lokalbetrieb** (`npm run monitor` + `npm start` + Browser, dieselbe
Entwickler-IP) addieren sich Monitor-account_tx und Browser-LIVE — der
clientseitige rate-gate und der serverseitige 429-Backoff federn das ab.

**Tradeoff Live-Frische vs. Request-Budget (ehrlich):** Der Server-Walk
(3 versetzte Crons, Budget 140 Blöcke/Tick) hält die Blockrate
(12,6–15,3 Blöcke/min) mit Headroom ~1,8–2,2× und holt 1 h Rückstand in
~13–15 min auf — der Flow-State ist Akkumulator mit Vollabdeckung, kein
Live-Graph; die Rückstands-Anzeige im Flow-Host (`validatedIndex − cursor`)
macht den Stand sichtbar. Ungeflaggte Txs sind im 24h/3d/7d-Fenster nur
zählbar, nie im Detail (7 Volltext-Tage à ~18 Mio. Tx-Objekte wären > 6 GB
und werden bewusst NICHT persistiert). Cron-Concurrency: die drei Workflows
teilen `concurrency: advance-tick` (`cancel-in-progress: false`); zusätzlich
erlaubt `lib/history.mjs` nur EINEN 409-Retry pro Write. Commit-Volumen:
Tick alle ~100 s = bis zu ~864 Flow-State-Commits/Tag plus 1 Block-Fenster-
Commit pro Tick (Tages-Chunks, ≤ ~2,4 MB/Datei).

## Flow-Archiv (jenseits des Flow-State-Fensters)

Der Flow-State wird im Advance-Tick beschnitten (7-Tage-Fenster, 30 Tage für
Cluster mit Betrugsevidenz — `FLOW_STATE_RETENTION_MS` /
`FLOW_STATE_MALICIOUS_RETENTION_MS`, `lib/flow-state.mjs`). **Vor** dem
Pruning archiviert `archiveFromFlowState`
die Cluster, die das Prädikat verlieren, als Tages-Chunks
`data/flow-archive/<YYYY-MM-DD>.json` (`api/advance.js`, Schritt (iii.5)) —
Betrugsevidenz bleibt rückwärts lesbar, obwohl sie aus dem Live-State fällt.
Reine Benign-Cluster werden nicht archiviert.

- **Retention:** 30 Tage für malicious-Cluster, 180 Tage für
  registry-verknüpfte Cluster (`ARCHIVE_RETENTION_MALICIOUS_MS` /
  `ARCHIVE_RETENTION_REGISTRY_MS`, `lib/flow-state.mjs`); Tages-Chunks löscht
  der Advance-Tick im Muster des Block-Fensters (404-sicher).
- **Checkpoint-Zeilen und Verdrängungspriorität:** Der Tages-Checkpoint
  (`checkpointFromFlowState`) archiviert alle Betrugsevidenz-Cluster des
  live Bestandes mit `reason: 'checkpoint'`. Bei Byte-Druck kappt
  `capArchiveDoc` in dieser Reihenfolge: ZUERST Checkpoint-Zeilen
  (reproduzierbare Snapshots lebender Cluster), DANN die ältesten
  Verlust-Zeilen — Checkpoints dürfen Verlust-Archiv-Evidenz nie
  verdrängen.
- **Rückwärts-Lesen:** `GET /api/flow-state?route=archive&address=…&from=…&to=…`
  (Zweig in `api/flow-state.js`, keine eigene Function — Hobby-Limit 12
  Serverless Functions) rekonstruiert Hops über `replayArchive`;
  Köder-Endpunkte fallen STILL raus (B2). Die Hops tragen ab Kritik-Runde 3
  den **Tx-Typ** pro Hop (`type`, Parität zum Live-Kantenvertrag —
  Archivzeilen persistieren `type`/Tags plus `roles`/`severityByAddress`
  je Cluster; ältere Bestände ohne Felder bleiben feldlos/`null`, defensiv).
- **Lese-Fenster:** rückwärts in Blöcken à 31 Tagen mit harter Kappe von
  2 Blöcken → max. 62 Tage / 62 GitHub-Reads pro Aufruf (`ARCHIVE_QUERY_DAYS`
  / `ARCHIVE_MAX_DAY_BLOCKS`, ENV `ARCHIVE_MAX_DAY_BLOCKS` überschreibbar,
  Kappe 6); `truncated: true` signalisiert die Kappe ohne Fensterabdeckung.
- **Range-Parameter (Kritik-Runde 3):** `?range=30d|90d` auf
  `route=archive` steuert die Lese-Tiefe — 30 d = 1 Block (voll abfragbar,
  `truncated: false` bei Abdeckung), 90 d = 3 Blöcke nötig; bei Default-Kappe
  2 werden ehrlich 62 d gelesen (`queryDays: 62`) und `truncated: true`
  gemeldet — erst ENV `ARCHIVE_MAX_DAY_BLOCKS>=3` macht 90 d voll abfragbar.
  Die block-window-Route bleibt bei 24h|3d|7d: ihre Daten-Retention ist
  7 Tage, 30d/90d wären dort ein Fenster-Versprechen auf nicht mehr
  existierende Daten (ehrliche Obergrenze, `lib/block-window.mjs`).
- **Dokumentierte Restlücke (ehrlich):** die Retention (180 d) übersteigt
  die Abfragbarkeit (62 d bei Default) — ältere registry-verknüpfte Cluster
  sind über diese Route nicht erreichbar.

## Hinweise

- `data/threats.json` wird atomar geschrieben (temp-Datei + `rename`), damit
  der Server nie halbe Dateien liest.
- Der Server kennt die Köder-Adressen ausschließlich zur **Ersetzung** in
  eigenen Antworten; gelernt werden nur `address`/`label`-Paare, nie Seeds.
- `logs/`, `data/`, `bait.json`, `bait-history.json`, `node_modules/` sind
  gitignored.
