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
  "wss": "wss://xrplcluster.com",
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
| `GET /…`           | statische Files aus `public/` |

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

1. **`config.json`:** bereits umgestellt auf `mainnet` / `wss://xrplcluster.com`
   (alternativ eigener Node `wss://s1.ripple.com:51233`). Auf Mainnet
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

## Hinweise

- `data/threats.json` wird atomar geschrieben (temp-Datei + `rename`), damit
  der Server nie halbe Dateien liest.
- Der Server kennt die Köder-Adressen ausschließlich zur **Ersetzung** in
  eigenen Antworten; gelernt werden nur `address`/`label`-Paare, nie Seeds.
- `logs/`, `data/`, `bait.json`, `bait-history.json`, `node_modules/` sind
  gitignored.
