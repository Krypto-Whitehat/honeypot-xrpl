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
| `GET /api/flow-state` | `{ cursor, updatedAt, validatedIndex, clusters: [{ id, label, roles, rolesByAddress, edges, totalDrops, txCount, distinctAccounts, firstSeen, lastSeen }] }` — normalisierte Projektion des persistierten Flow-States (serverseitig baitLabels-gefiltert, Top-200, 7-Tage-Fenster); ohne Token `200 + reason` (fail-closed) |
| `GET /api/block-window?range=24h\|3d\|7d` | `{ range, from, to, updatedAt, buckets: [{ t, blocks, txns, flaggedBlocks, maxSeverity }], flagged: [{ i, t, n, f: [{ from, to, type, amountDrops, txHash, ledgerSeq }] }], cursor, validatedIndex }` — rollender Block-Fenster-Bestand (Stunden-Rollups ≤ 168 Zeilen bei 7 d, geflaggte Details im Volltext); Default `24h`, ungültiger `range` → 400; ohne Token `200 + reason` (fail-closed). Bedient von der Function `api/flow-state.js` (Zweig `route=block-window`) via Rewrite — Hobby-Limit: max. 12 Serverless Functions pro Deployment |
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

## Bekannte Grenzen

- **Path-Payment-Zwischenhops:** Adressen entlang des Zahlungs-Pfads
  (intermediate hops) werden derzeit **nicht** als Gegenpartei erfasst — die
  Stream-Nachricht enthält die Pfad-Konten nur indirekt über die
  Meta-Bilanzänderungen. Erfasst werden Absender und Ziel; Zwischenhops
  bleiben unbeobachtet.
- **NFTokenAcceptOffer-Angebotsauflösung:** Erfasst wird die Transaktion,
  wenn Köder als Absender oder als Owner eines betroffenen NFTokenOffer-
  Ledger-Objekts beteiligt sind. Die Käufer-/Verkäufer-Adressen aus den
  Offer-Ids (`NFTokenBuyOffer`/`NFTokenSellOffer`) werden nicht per
  `ledger_entry` aufgelöst.
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
`DEFAULT_BUDGET = 100` Blöcke/Tick. `FETCH_PARALLEL = 4` (expand:true-
Latenz gemessen Ø ~0,7 s → ~5,7 req/s < 10/s steady); der Token-Bucket
`lib/rate-gate.mjs` kappt **pro Request**, nicht pro Tick. 429/5xx werden
behandelt wie slowDown/tooBusy (retry-after-Header, Deadline-Guard).
Throttle-Semantik bei echtem Überschreiten ist UNVERIFIED (bewusst nicht
bis zur Grenze belastet).

**Vollabdeckung und Catch-up:** 1 Request/Block → 12,6–15,3 req/min
(0,21–0,25 req/s, ~2,5 % des steady-Limits). 5-min-Bedarf 63–77 Blöcke;
ein Tick Budget 100 → Headroom 1,3–1,6×. Catch-up 1 h Rückstand
(758–915 Blöcke): ~8–10 Ticks; mit drei versetzten Crons (Tick alle
~100 s, 300 Blöcke/5 min) ≈ 13–15 min. Blockrate gemessen 15,25/min
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
| `ADVANCE_BUDGET` | optional (Default 100, `api/advance.js` `DEFAULT_BUDGET`) | Blöcke pro Tick |
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
| Actions-Tick `/api/advance` (3 versetzte Workflows ≈ Tick alle 100 s, Budget 100 Blöcke = 100 Requests, Parallelität 4 → ~5,7 req/s, pro Request gated) | ≤ **100 req/100 s = 60/min-Spitze**, mittig unter 10/s |
| `/api/ledger`-Snapshot (expand:true, 1 Request, 60-s-Cache) | ≤ **1/min** pro Instanz |
| `/api/flow-state` validatedIndex (1 RPC, 60-s-Prozess-Cache) | ≤ **1/min** pro Instanz |
| `/api/block-window` (0 RPC — liest nur GitHub-Contents, 60-s-Cache) | **0** |
| **Summe Server-Egress gegen honeycluster** | **deutlich unter 10 req/s** (Walk dominiert: 100 req in ≤ 30 s Function-Zeit, durch Gate ≤ 10/s) |
| Browser-Opt-in-LIVE (pro Besucher-IP, WSS + 1 ledger-Kommando/Block, clientseitiger rate-gate) | ≤ **0,25 req/s pro Tab** |

Der Server-Walk teilt die honeycluster-Rate nur mit sich selbst (concurrency-
group `advance-tick` verhindert parallele Walks; Rate-Gate pro Request).
Browser-Besucher gehen pro eigener IP und sind damit kein Server-Egress.
**Im Lokalbetrieb** (`npm run monitor` + `npm start` + Browser, dieselbe
Entwickler-IP) addieren sich Monitor-account_tx und Browser-LIVE — der
clientseitige rate-gate und der serverseitige 429-Backoff federn das ab.

**Tradeoff Live-Frische vs. Request-Budget (ehrlich):** Der Server-Walk
(3 versetzte Crons, Budget 100 Blöcke/Tick) hält die Blockrate
(12,6–15,3 Blöcke/min) mit Headroom 1,3–1,6× und holt 1 h Rückstand in
~13–15 min auf — der Flow-State ist Akkumulator mit Vollabdeckung, kein
Live-Graph; die Rückstands-Anzeige im Flow-Host (`validatedIndex − cursor`)
macht den Stand sichtbar. Ungeflaggte Txs sind im 24h/3d/7d-Fenster nur
zählbar, nie im Detail (7 Volltext-Tage à ~18 Mio. Tx-Objekte wären > 6 GB
und werden bewusst NICHT persistiert). Cron-Concurrency: die drei Workflows
teilen `concurrency: advance-tick` (`cancel-in-progress: false`); zusätzlich
erlaubt `lib/history.mjs` nur EINEN 409-Retry pro Write. Commit-Volumen:
Tick alle ~100 s = bis zu ~864 Flow-State-Commits/Tag plus 1 Block-Fenster-
Commit pro Tick (Tages-Chunks, ≤ ~2,4 MB/Datei).

## Flow-Archiv (jenseits des 7-Tage-Fensters)

Der Flow-State wird im Advance-Tick beschnitten (7-Tage-Fenster,
`lib/flow-state.mjs`). **Vor** dem Pruning archiviert `archiveFromFlowState`
die Cluster, die das Prädikat verlieren, als Tages-Chunks
`data/flow-archive/<YYYY-MM-DD>.json` (`api/advance.js`, Schritt (iii.5)) —
Betrugsevidenz bleibt rückwärts lesbar, obwohl sie aus dem Live-State fällt.
Reine Benign-Cluster werden nicht archiviert.

- **Retention:** 30 Tage für malicious-Cluster, 180 Tage für
  registry-verknüpfte Cluster (`ARCHIVE_RETENTION_MALICIOUS_MS` /
  `ARCHIVE_RETENTION_REGISTRY_MS`, `lib/flow-state.mjs`); Tages-Chunks löscht
  der Advance-Tick im Muster des Block-Fensters (404-sicher).
- **Rückwärts-Lesen:** `GET /api/flow-state?route=archive&address=…&from=…&to=…`
  (Zweig in `api/flow-state.js`, keine eigene Function — Hobby-Limit 12
  Serverless Functions) rekonstruiert Hops über `replayArchive`;
  Köder-Endpunkte fallen STILL raus (B2).
- **Lese-Fenster:** rückwärts in Blöcken à 31 Tagen mit harter Kappe von
  2 Blöcken → max. 62 Tage / 62 GitHub-Reads pro Aufruf (`ARCHIVE_QUERY_DAYS`
  / `ARCHIVE_MAX_DAY_BLOCKS`, ENV `ARCHIVE_MAX_DAY_BLOCKS` überschreibbar,
  Kappe 6); `truncated: true` signalisiert die Kappe ohne Fensterabdeckung.
- **Dokumentierte Restlücke (ehrlich):** die Retention (180 d) übersteigt
  die Abfragbarkeit (62 d) — ältere registry-verknüpfte Cluster sind über
  diese Route nicht erreichbar.

## Hinweise

- `data/threats.json` wird atomar geschrieben (temp-Datei + `rename`), damit
  der Server nie halbe Dateien liest.
- Der Server kennt die Köder-Adressen ausschließlich zur **Ersetzung** in
  eigenen Antworten; gelernt werden nur `address`/`label`-Paare, nie Seeds.
- `logs/`, `data/`, `bait.json`, `bait-history.json`, `node_modules/` sind
  gitignored.
