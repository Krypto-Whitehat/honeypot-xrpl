// lib/validator-trace.mjs — Validator-Trace: Ledger-genaue Auswertung der dUNL (rein, ohne I/O).
//
// Datenbasis: Validations-Stream (xrpld, xrplcluster.com) + Ledger-Stream. Pro validiertem
// Ledger wird je dUNL-Mitglied bewertet:
//   ok           signiert den Quorum-Hash, full=true
//   partial      signiert den Quorum-Hash, aber full=false (Teilvalidierung)
//   wrong-hash   signiert einen anderen Hash für denselben Index (Fork-/Bug-Signal)
//   missed       keine Validierung für diesen Index innerhalb des Gnadenfensters
// Quorum: >= quorumFrac * dUNL-Größe Stimmen auf denselben Hash; sonst 'no-quorum'.
//
// URSACHEN: Der Stream zeigt WAS passiert ist, nicht WARUM. Die Reason-Tags sind KORRELATIONEN
// im selben Ledger (Lastspitze, Amendment-Aktivität, neuer Tx-Typ, UNL-Änderung). Sie sind
// Hinweise für die Untersuchung, keine bewiesenen Ursachen. Ohne passende Korrelation steht
// bewusst 'no-correlated-cause'.
//
// Schwellen sind TUNING-DEFAULTS (wie PEELING_THRESHOLDS), explizit ausgewiesen.
import { SIGNATURE_TAGS } from "./tx-forensics.mjs";

export const TRACE_DEFAULTS = {
  graceMs: 20000,       // Validierungen dürfen bis 20 s nach dem Close eintreffen
  quorumFrac: 0.8,      // 80 % der dUNL (XRPL-Quorum)
  spikeMinTx: 50,       // Lastspitze: mindestens 50 Tx ...
  spikeRatio: 3,        // ... und mindestens 3 × Median der letzten Ledger
  baselineSize: 60,     // rollende Basis (Ledger)
  maxPending: 2000,     // Speicherdeckel für offene Ledger
  // Forensik-Schwellen (TUNING-DEFAULTS, ebenso ohne Kampagnen-Nachweis):
  thinMarginMax: 2,     // Quorum nur mit < 2 Stimmen Reserve -> 'quorum-thin'
  splitMinVotes: 2,     // >= 2 Validatoren auf einem verlierenden Hash -> 'hash-split'
  extremeRatio: 10,     // >= 10 × Median (bei mindestens spikeMinTx Tx) -> 'load-extreme'
  gapMinMs: 15000,      // Close-Abstand mindestens 15 s -> 'close-gap'
  gapRatio: 4,          // Close-Abstand >= 4 × Median-Takt
  // Spaet-Validierungen: zuletzt bewertete Ledger, fuer die eine eintreffende Validation noch
  // als "zu spaet abgestimmt" zaehlt (TUNING-DEFAULT). 512 Ledger sind bei ~4 s Takt rund
  // 34 Minuten - lang genug fuer einen langsamen Pfad, kurz genug, damit ein tagelang
  // abgestuerzter Knoten nicht nachtraeglich als "spaet aber dabei" erscheint.
  lateRingSize: 512,
};

// NULL-VERTRAG ueber alle Trace-Ebenen: null heisst "nicht gemessen", nicht 0.
// Number(null) === 0 und Number("") === 0. Eine ungepruefte Number()-Umwandlung macht aus
// einem fehlenden Messwert eine Messung von 0 - bei einer Vote-Latenz ist das die
// gefaehrlichste Zahl des ganzen Repos: sie entlastet einen Knoten, der nie abgestimmt hat.
// Jede Latenz-Lesung im Trace laeuft deshalb durch diese Funktion.
export const measured = (x) => {
  if (typeof x === "number") return Number.isFinite(x) ? x : null;
  if (typeof x === "string" && x.trim() !== "") { const v = Number(x); return Number.isFinite(v) ? v : null; }
  return null;
};

// LAST-ACHSE (TUNING-DEFAULTS, absolute Tx-Grenzen): die relativen Last-Tags (load-spike /
// load-extreme) vergleichen ein Ledger mit seinem eigenen Median. Damit ist die Frage eines
// Betreibers nicht beantwortbar - "ab wie vielen Tx pro Ledger faellt MEIN Knoten zurueck, und
// ab wie vielen halten die anderen?". Vergleichbar ueber Tage und Validatoren hinweg sind nur
// absolute Stufen. Die Grenzen decken den gemessenen Bereich ab: der Normalbetrieb liegt um
// 30-60 Tx je Ledger, Ausreisser reichen bis mehrere hundert.
export const LOAD_BUCKETS = [10, 25, 50, 100, 200, 400, 800, 1600, 3200, Infinity];
export const LOAD_BUCKET_COUNT = LOAD_BUCKETS.length;

// Stufe fuer eine Tx-Zahl. Fehlende oder negative Werte fallen in die unterste Stufe: ein Ledger
// ohne Tx ist eine Messung mit dem Wert 0, keine fehlende Messung.
export function loadBucket(txCount) {
  const n = Number(txCount);
  const v = Number.isFinite(n) && n > 0 ? n : 0;
  for (let i = 0; i < LOAD_BUCKETS.length; i += 1) if (v < LOAD_BUCKETS[i]) return i;
  return LOAD_BUCKETS.length - 1;
}

// Lesbare Stufengrenze: 0 -> "0-9", 3 -> "50-99", letzte -> ">= 3200".
export function loadBucketLabel(idx) {
  const hi = LOAD_BUCKETS[idx];
  const lo = idx === 0 ? 0 : LOAD_BUCKETS[idx - 1];
  return hi === Infinity ? ">= " + lo : lo + "-" + (hi - 1);
}

// Ein Ledger auf der Last-Achse verbuchen. Gezaehlt wird JEDES Ledger - ohne die Ledger ohne
// Ausfall als Nenner waere jede Ausfallrate je Laststufe eine Selbstbestaetigung.
// l = Ledger dieser Stufe, f = Ledger dieser Stufe mit mindestens einem Ausfall,
// v = je Validator die Zahl seiner Ausfall-Ledger in dieser Stufe.
export function addLoadSample(day, txCount, failedMasters) {
  if (!day || typeof day !== "object" || Array.isArray(day)) return null;
  const idx = loadBucket(txCount);
  const list = (day.loadBuckets ??= []);
  // Leere Stufen vorfuellen: ein Loch im Array serialisiert als null, und jeder Leser
  // muesste dann normalisieren, statt "kein Ledger in dieser Stufe" zu lesen.
  for (let i = list.length; i < LOAD_BUCKET_COUNT; i += 1) list[i] = { l: 0, f: 0, v: {} };
  const b = (list[idx] ??= { l: 0, f: 0, v: {} });
  b.l += 1;
  const bad = Array.isArray(failedMasters) ? [...new Set(failedMasters)] : [];
  if (bad.length) {
    b.f += 1;
    for (const m of bad) b.v[m] = (b.v[m] ?? 0) + 1;
  }
  return b;
}

// QUORUM-MARGIN-ACHSE (TUNING-DEFAULTS, absolute Stimmen-Reserve): margin = topVotes - needed.
// Die Last-Achse beantwortet "ab wie viel Tx faellt mein Knoten zurueck". Diese Achse beantwortet
// die andere Haelfte derselben Frage: "ab wie viel Quorum-Reserve faellt er zurueck". Ein Miss auf
// einem Ledger mit margin -3 ist eine Netzstockung, ein Miss auf margin +9 ist der eigene Knoten.
// Beides ist ohne Nenner nicht beantwortbar - ohne die Ledger derselben Bandbreite OHNE Ausfall
// waere jede Ausfallrate je Band eine Selbstbestaetigung. Deshalb wird JEDES bewertete Ledger
// verbucht, nicht nur das mit Ausfall.
export const MARGIN_BUCKETS = [0, 1, 2, 3, 5, 8, Infinity];
export const MARGIN_BUCKET_COUNT = MARGIN_BUCKETS.length;

// null bleibt null (NULL-VERTRAG): ein Ledger ohne Quorum-Bewertung hat keine Margin von 0, er hat
// keine Messung. Ueber measured() statt Number(): Number(null) === 0 wuerde aus "nicht gemessen"
// die Bandbreite "Quorum exakt erreicht" machen und den Knoten entlasten, der nie abgestimmt hat.
export function marginBucket(margin) {
  const m = measured(margin);
  if (m === null) return null;
  for (let i = 0; i < MARGIN_BUCKETS.length; i += 1) if (m < MARGIN_BUCKETS[i]) return i;
  return MARGIN_BUCKETS.length - 1;
}

// Bandbreite lesbar: 0 -> "< 0", 1 -> "0-0", 4 -> "3-4", letzte -> ">= 8".
export function marginBucketLabel(idx) {
  const hi = MARGIN_BUCKETS[idx];
  const lo = idx === 0 ? -Infinity : MARGIN_BUCKETS[idx - 1];
  if (hi === Infinity) return ">= " + lo;
  if (lo === -Infinity) return "< " + hi;
  return lo + "-" + (hi - 1);
}

// Ein Ledger auf der Quorum-Achse verbuchen. l = Ledger dieser Bandbreite, f = Ledger dieser
// Bandbreite mit mindestens einem Ausfall, v = je Validator seine Ausfall-Ledger in dieser Bandbreite.
export function addQuorumSample(day, margin, failedMasters) {
  if (!day || typeof day !== "object" || Array.isArray(day)) return null;
  const idx = marginBucket(margin);
  // Wer hier verbucht, ist ein Recorder, der diese Achse messen kann. Der Marker ist die einzige
  // Stelle, die einen Altbestand von einem Tag mit leerer Achse trennt - er muss am Messvorgang
  // haengen, nicht an einem nachtraeglichen Rueckschluss aus dem Array.
  day.quorumRecorded = true;
  if (idx === null) {
    // Nicht verbuchbar ist eine Messluecke, keine Bandbreite: gezaehlt, damit der Nenner der
    // Risikoflaeche die Luecke zeigt statt sie zu verschlucken.
    day.quorumMissing = (day.quorumMissing ?? 0) + 1;
    return null;
  }
  const list = (day.quorumBuckets ??= []);
  for (let i = list.length; i < MARGIN_BUCKET_COUNT; i += 1) list[i] = { l: 0, f: 0, v: {} };
  const b = (list[idx] ??= { l: 0, f: 0, v: {} });
  b.l += 1;
  const bad = Array.isArray(failedMasters) ? [...new Set(failedMasters)] : [];
  if (bad.length) {
    b.f += 1;
    for (const m of bad) b.v[m] = (b.v[m] ?? 0) + 1;
  }
  return b;
}

// Gemeinsame Zelle der Last- und Quorum-Achse: die einzige Zahl, die einem Betreiber sagt, in
// WELCHER Kombination sein Knoten zurueckfaellt - "Last hoch UND Quorum knapp" ist eine
// Netzaktion, "Last normal UND Quorum komfortabel" ist der eigene Knoten.
// Index = Laststufe * MARGIN_BUCKET_COUNT + Marginstufe.
export function riskCellIndex(txCount, margin) {
  const m = marginBucket(margin);
  if (m === null) return null;
  return loadBucket(txCount) * MARGIN_BUCKET_COUNT + m;
}

export function addRiskCell(day, txCount, margin, failed) {
  if (!day || typeof day !== "object" || Array.isArray(day)) return null;
  const idx = riskCellIndex(txCount, margin);
  if (idx === null) return null;
  const grid = (day.riskCross ??= []);
  const c = (grid[idx] ??= { n: 0, f: 0 });
  c.n += 1;
  if (failed) c.f += 1;
  return c;
}

// Ein bewertetes Ledger auf beiden Achsen und in ihrer gemeinsamen Zelle verbuchen. Ersetzt den
// einzelnen Last-Aufruf im Recorder: beide Achsen muessen aus demselben Ledger stammen, sonst
// vergleicht die Risikoflaeche Last und Quorum auf verschiedenen Ledger-Mengen.
export function addLedgerRiskSample(day, { txCount, margin, failedMasters } = {}) {
  const bad = Array.isArray(failedMasters) ? [...new Set(failedMasters)] : [];
  return {
    load: addLoadSample(day, txCount, bad),
    quorum: addQuorumSample(day, margin, bad),
    cell: addRiskCell(day, txCount, margin, bad.length > 0),
  };
}

// Etablierte XRPL-Transaktionstypen (rippled-Transaktorliste, Stand XLS-66d/80/75d):
// 'new-tx-type' markiert nur Typen AUSSERHALB dieser Liste UND noch nicht gesehen.
// Sonst würde jeder Standardtyp als 'neu' getaggt, sobald ein frischer Recorder-Lauf
// den ersten detaillierten Ledger damit sieht (gemessener Fehler: Payment/OfferCreate/
// TrustSet erschienen als new-tx-type in echten Incidents).
export const ESTABLISHED_TX_TYPES = new Set([
  "AccountDelete", "AccountSet", "AMMClawback", "AMMBid", "AMMCreate", "AMMDelete", "AMMDeposit",
  "AMMVote", "AMMWithdraw", "Batch", "CheckCancel", "CheckCash", "CheckCreate", "Clawback",
  "ContractSet", "CredentialAccept", "CredentialCreate", "CredentialDelete", "DelegateSet",
  "DepositPreauth", "DIDDelete", "DIDSet", "EnableAmendment", "EscrowCancel", "EscrowCreate",
  "EscrowFinish", "GenesisMint", "LoanBrokerSet", "LoanCharge", "LoanDefault", "LoanManage",
  "LoanRepay", "LoanRequest", "LoanRetract", "MPTokenAuthorize", "MPTokenIssuanceCreate",
  "MPTokenIssuanceDestroy", "MPTokenIssuanceSet", "NFTokenAcceptOffer", "NFTokenBurn",
  "NFTokenCancelOffer", "NFTokenCreateOffer", "NFTokenMint", "NFTokenModify", "NickNameSet",
  "OfferCancel", "OfferCreate", "OracleDelete", "OracleSet", "Payment", "PaymentChannelClaim",
  "PaymentChannelCreate", "PaymentChannelFund", "PermissionedDomainDelete", "PermissionedDomainSet",
  "SetFee", "SetRegularKey", "SignerListSet", "TicketCancel", "TicketCreate", "TrustSet",
  "UNLModify", "VaultClawback", "VaultCreate", "VaultDelete", "VaultDeposit", "VaultSet",
  "VaultWithdraw", "XChainAccountCreateCommit", "XChainBridge", "XChainClaim", "XChainCommit",
  "XChainCreateBridge", "XChainCreateClaimID", "XChainModifyBridge",
]);

const isIndex = (x) => Number.isFinite(Number(x));
const median = (arr) => {
  if (!arr.length) return 0;
  const s = [...arr].sort((a, b) => a - b);
  const m = Math.floor(s.length / 2);
  return s.length % 2 ? s[m] : (s[m - 1] + s[m]) / 2;
};

// members: Master-Schlüssel der dUNL; ephemeralToMaster: Map Signierschlüssel -> Master
export function createTracker({ members, ephemeralToMaster, opts = {} }) {
  const o = { ...TRACE_DEFAULTS, ...opts };
  const memberSet = new Set(members);
  const quorum = Math.ceil(members.length * o.quorumFrac);
  const ledgers = new Map();      // index -> { hash, closeMs, txCount, amendments, unlModify, types }
  const votes = new Map();        // index -> Map(master -> { hash, full, t })
  // recentlyEvaluated ist der Ring, der "zu spaet" von "nie" trennt: ohne ihn gibt es fuer
  // einen bereits bewerteten Ledger keine Referenzzeit, und die Spaet-Validierung waer wertlos.
  const recentlyEvaluated = new Map(); // index -> closeMs (zuletzt bewertet)
  const lateVotes = new Map();         // index -> Map(master -> { hash, full, t }) nach der Bewertung
  let lateDropped = 0;                 // Spaet-Validierungen, die dem Ring-Raster zum Opfer fielen
  const baseline = [];            // txCount der letzten Ledger
  const gapBaseline = [];         // rollende Basis der Close-Abstände (Ledger-Takt)
  let lastCloseMs = null;         // Close des zuletzt bewerteten Ledgers
  let lastEvaluated = 0;
  let nonMemberSigners = 0;
  const knownTypes = new Set();   // Tx-Typen aus bereits bewerteten Ledgern (Neuheit)
  let evaluatedCount = 0;

  function onLedger(l) {
    const idx = Number(l?.ledgerIndex);
    if (!isIndex(idx)) return;
    ledgers.set(idx, {
      hash: l.hash ?? null,
      closeMs: Number(l.closeMs) || Date.now(),
      txCount: Number(l.txCount) || 0,
      amendments: Array.isArray(l.amendments) ? l.amendments : [],
      unlModify: l.unlModify === true,
      types: Array.isArray(l.types) ? l.types : null,
    });
    baseline.push(Number(l.txCount) || 0);
    while (baseline.length > o.baselineSize) baseline.shift();
    while (ledgers.size > o.maxPending) ledgers.delete(ledgers.keys().next().value);
  }

  function onValidation(v) {
    const idx = Number(v?.ledgerIndex);
    if (!isIndex(idx)) return;
    const master = ephemeralToMaster.get(v.signingKey) ?? (memberSet.has(v.signingKey) ? v.signingKey : null);
    if (!master || !memberSet.has(master)) { nonMemberSigners++; return; }
    const t = Number(v.t) || Date.now();
    // Spaet-Validierung: der Ledger ist schon bewertet. Bis hierher wurde sie still verworfen
    // ('idx <= lastEvaluated -> return'), und damit war "zu spaet abgestimmt" ununterscheidbar
    // von "nie abgestimmt". Die Trennung ist der Befund, den ein Betreiber braucht: zu spaet ist
    // ein Pfad-/Lastproblem mit Handlungsweg, nie ist ein Offline-Problem.
    if (idx <= lastEvaluated) {
      if (!recentlyEvaluated.has(idx)) return;
      if (!lateVotes.has(idx)) lateVotes.set(idx, new Map());
      lateVotes.get(idx).set(master, { hash: v.ledgerHash, full: v.full !== false, t });
      return;
    }
    if (!votes.has(idx)) votes.set(idx, new Map());
    votes.get(idx).set(master, { hash: v.ledgerHash, full: v.full !== false, t });
  }

  // Bewertet alle Ledger, deren Gnadenfenster abgelaufen ist. Liefert Ergebnisse in Index-Reihenfolge.
  function evaluate(nowMs = Date.now()) {
    const due = [...ledgers.entries()]
      .filter(([idx, l]) => idx > lastEvaluated && l.closeMs + o.graceMs <= nowMs)
      .sort((a, b) => a[0] - b[0]);
    const out = [];
    for (const [idx, l] of due) {
      const seen = votes.get(idx) ?? new Map();
      // Vote-Latenz je Ledger: der erste und der letzte Vote nach dem Close. Der Zeitstempel t
      // war in jedem Vote vorhanden und wurde in der Forensik nie benutzt. Er ist der
      // Unterschied zwischen "das Netz war langsam" (erster Vote spaet) und "dieser Knoten war
      // langsam" (erster Vote schnell, eigener Vote spaet).
      let firstVoteMs = null, lastVoteMs = null;
      for (const vv of seen.values()) {
        const dm = vv.t - l.closeMs;
        if (firstVoteMs === null || dm < firstVoteMs) firstVoteMs = dm;
        if (lastVoteMs === null || dm > lastVoteMs) lastVoteMs = dm;
      }
      const tally = new Map();
      for (const v of seen.values()) tally.set(v.hash, (tally.get(v.hash) ?? 0) + 1);
      let top = null, topN = 0;
      for (const [h, n] of tally) if (n > topN) { top = h; topN = n; }
      // Runner-Up: zweitstärkste Hash-Linie im selben Ledger. Mehr als eine Stimme darauf
      // heißt: das Netzwerk war gespalten (Versions-/Zustandsdifferenz), nicht nur ein
      // Validator hat sich geirrt. Das ist ein eigenständiges Signal und wird getrennt geführt.
      let runnerHash = null, runnerN = 0;
      for (const [h, n] of tally) if (h !== top && n > runnerN) { runnerHash = h; runnerN = n; }
      const votesTotal = [...tally.values()].reduce((a, n) => a + n, 0);
      const hasQuorum = top !== null && topN >= quorum;
      const med = median(baseline);
      // Close-Abstand: ein übermäßiger Abstand zum Takt davor ist das Muster einer Netzstockung
      // oder Überlastung — genau die Lage, in der Validatoren Ledger verpassen, ohne selbst
      // schuld zu sein.
      const ctx = {
        hasQuorum,
        txCount: l.txCount,
        medianTx: med,
        amendments: l.amendments,
        unlModify: l.unlModify,
        margin: topN - quorum,
        runnerVotes: runnerN,
        closeGapMs: lastCloseMs === null ? null : l.closeMs - lastCloseMs,
        medianGap: median(gapBaseline),
        // Neuheit erst nach Anlaufphase (200 Ledger) UND nur Nicht-Standardtypen.
        novelTypes: l.types && evaluatedCount >= 200 ? l.types.filter((t) => !ESTABLISHED_TX_TYPES.has(t) && !knownTypes.has(t)) : [],
      };
      const incidents = [];
      let ok = 0;
      // Incident-Typ (Kebab, so steht er in den Incidents) und Zaehlerfeld (Kamel, so steht
      // es in der Tagesdatei) sind verschiedene Namen. Ohne diese Zuordnung landet 'no-quorum'
      // als neuer Schluessel in counts und der Wert wird NaN -> in JSON null.
      const COUNT_KEY = { missed: "missed", partial: "partial", "wrong-hash": "wrongHash", "no-quorum": "noQuorum" };
      const counts = { missed: 0, partial: 0, wrongHash: 0, noQuorum: 0 };
      for (const m of members) {
        const v = seen.get(m);
        let type = null;
        // 'missed' = Quorum stand, Validator fehlte -> echter Validator-Fehler.
        // Bei 'no-quorum' (Netzwerk-Stockung) ist nicht-Abstimmen KEIN Einzelfehler:
        // eigener Typ, damit Zähler und Diagnose das trennen können.
        if (!v) type = hasQuorum ? "missed" : "no-quorum";
        else if (hasQuorum && v.hash !== top) type = "wrong-hash";
        else if (!v.full) type = "partial";
        // voteDelayMs: die Latenz des eigenen Votes, wenn es einen gab (partial / wrong-hash).
        // Fuer 'missed' gibt es zum Bewertungszeitpunkt keinen Vote - die Spaet-Validierung
        // liefert ihn nachtraeglich (takeLateVotes) und der Monitor haengt ihn dem Incident an.
        // votedHash: die Hash-Linie, die DIESER Knoten tatsaechlich abgestimmt hat. Ohne sie ist
        // 'wrong-hash' ein Etikett ohne Inhalt: man weiss, dass er abwich, aber nicht wovon, ob
        // dieselbe Abweichung wiederkehrt und ob andere Knoten dieselbe Linie waelten. Erst das
        // Paar aus votedHash und acceptedHash macht eine Rekonstruktion der Ursache moeglich.
        if (type) { incidents.push({ master: m, type, voteDelayMs: v ? v.t - l.closeMs : null, votedHash: v ? v.hash : null }); counts[COUNT_KEY[type]] += 1; }
        else ok++;
      }
      const reasons = classifyReasons(ctx);
      out.push({
        ledgerIndex: idx,
        hash: top,
        closeMs: l.closeMs,
        txCount: l.txCount,
        medianTx: med,
        closeGapMs: lastCloseMs === null ? null : l.closeMs - lastCloseMs,
        medianGap: median(gapBaseline),
        hasQuorum,
        validators: members.length,
        okCount: ok,
        // Quorum-Forensik: die Zahlen, an denen eine Rekonstruktion hängt — wie knapp war
        // das Quorum, gab es eine zweite Hash-Linie, wie viele Validatoren je Typ betroffen.
        forensics: {
          members: members.length,
          needed: quorum,
          votes: votesTotal,
          // acceptedHash: die Linie, auf die sich die Mehrheit geeinigt hat. runnerHash ist die
          // zweitstaerkste Linie. Beide zusammen mit votedHash ergeben die Divergenz-Klasse eines
          // Vorfalls: Netzmehrheit, Runner-Up-Linie oder eine eigene dritte Linie.
          acceptedHash: top,
          topVotes: topN,
          margin: topN - quorum,
          runnerHash: runnerN ? runnerHash : null,
          runnerVotes: runnerN,
          firstVoteMs,
          lastVoteMs,
          counts,
        },
        detailNeeded: incidents.length > 0 && !l.types,
        // ledgerTags: die Ledger-Ebene unverändert, ohne Incident-Zusatz-Tags. Nur so ist
        // später zählbar, wie oft ein Ledger AUFFÄLLIG war und wie oft er trotzdem ausfiel.
        ledgerTags: reasons,
        incidents: incidents.map((i) => ({ ...i, reasons: reasonsFor(i.type, reasons) })),
      });
      if (l.types) for (const t of l.types) knownTypes.add(t);
      evaluatedCount++;
      if (lastCloseMs !== null) gapBaseline.push(l.closeMs - lastCloseMs);
      while (gapBaseline.length > o.baselineSize) gapBaseline.shift();
      lastCloseMs = l.closeMs;
      // Detail (Tx-Typen/Amendments) wird später per attachDetail nachgereicht, wenn Incidents da sind.
      lastEvaluated = idx;
      votes.delete(idx);
      ledgers.delete(idx);
      // Ring der zuletzt bewerteten Ledger. Was herausfaellt, ist nicht mehr "zu spaet" - es ist
      // "nicht mehr beurteilbar", und das wird gezaehlt statt still verschluckt.
      recentlyEvaluated.set(idx, l.closeMs);
      while (recentlyEvaluated.size > o.lateRingSize) {
        const oldest = recentlyEvaluated.keys().next().value;
        recentlyEvaluated.delete(oldest);
        if (lateVotes.delete(oldest)) lateDropped += 1;
      }
    }
    return out;
  }

  // Nachträgliche Ledger-Details (Tx-Typen, Amendments, UNL-Änderung) für ein bewertetes Ledger.
  // Wird nur für Ledger mit Incidents abgerufen. Setzt Korrelations-Tags und Neuheit neu.
  function attachDetail(result, detail) {
    if (!result || !detail) return result;
    const types = Array.isArray(detail.types) ? detail.types : [];
    const novel = evaluatedCount >= 200 ? types.filter((t) => !ESTABLISHED_TX_TYPES.has(t) && !knownTypes.has(t)) : [];
    const tags = classifyReasons({
      hasQuorum: result.hasQuorum, txCount: result.txCount, medianTx: result.medianTx,
      amendments: detail.amendments ?? [], unlModify: detail.unlModify === true, novelTypes: novel,
      margin: result.forensics?.margin ?? 0, runnerVotes: result.forensics?.runnerVotes ?? 0,
    });
    for (const inc of result.incidents) inc.reasons = reasonsFor(inc.type, tags);
    // Die Amendment-IDs selbst, nicht nur das Korrelations-Tag: erst mit den IDs ist die Frage
    // beantwortbar, ob ein Knoten ausgerechnet auf Ledgern MIT einem bestimmten Feature ausfaellt.
    result.amendments = detail.amendments ?? [];
    for (const t of types) knownTypes.add(t);
    result.detailNeeded = false;
    return result;
  }

  // Spaet-Validierungen seit dem letzten Aufruf, in Ledger-Reihenfolge. Der Monitor schreibt sie
  // in die Tagesdatei und vermerkt sie am 'missed'-Incident desselben Knotens - sonst bleibt
  // "verpasst" ein Wort fuer zwei verschiedene Fehler.
  function takeLateVotes() {
    const out = [];
    for (const [idx, byMaster] of lateVotes) {
      const closedAt = recentlyEvaluated.get(idx) ?? null;
      for (const [master, v] of byMaster) {
        out.push({
          ledgerIndex: idx, master, closeMs: closedAt, arrivalMs: v.t,
          delayMs: closedAt === null ? null : v.t - closedAt, hash: v.hash, full: v.full,
        });
      }
      lateVotes.delete(idx);
    }
    out.sort((a, b) => a.ledgerIndex - b.ledgerIndex);
    return out;
  }

  return { attachDetail, onLedger, onValidation, evaluate, quorum, takeLateVotes, stats: () => ({ nonMemberSigners, pendingLedgers: ledgers.size, lastEvaluated, pendingLateVotes: lateVotes.size, lateVotesDropped: lateDropped }) };
}

// Ledger-Ebene: Korrelationen aus demselben Ledger.
export function classifyReasons(ctx) {
  const tags = [];
  if (!ctx.hasQuorum) tags.push("no-quorum");
  // quorum-thin gehört hierher nicht: der Quorum-Abstand ist eine Messgröße, keine Ursache.
  // Er steht in der Forensik und erscheint erst in der Diagnose (lib/validator-retrace.mjs).
  if ((ctx.runnerVotes ?? 0) >= TRACE_DEFAULTS.splitMinVotes) tags.push("hash-split");
  if (ctx.txCount >= TRACE_DEFAULTS.spikeMinTx && ctx.medianTx > 0 && ctx.txCount >= TRACE_DEFAULTS.spikeRatio * ctx.medianTx) tags.push("load-spike");
  if (ctx.txCount >= TRACE_DEFAULTS.spikeMinTx && ctx.medianTx > 0 && ctx.txCount >= TRACE_DEFAULTS.extremeRatio * ctx.medianTx) tags.push("load-extreme");
  if (Number.isFinite(ctx.closeGapMs) && ctx.medianGap > 0 && ctx.closeGapMs >= TRACE_DEFAULTS.gapMinMs && ctx.closeGapMs >= TRACE_DEFAULTS.gapRatio * ctx.medianGap) tags.push("close-gap");
  if (ctx.amendments && ctx.amendments.length) tags.push("amendment-activity");
  if (ctx.unlModify) tags.push("unl-change");
  for (const t of ctx.novelTypes ?? []) tags.push("new-tx-type:" + t);
  return tags;
}

// Signatur-Ebene eines Tages: nur was nachweislich geprueft wurde. Der Marker ist die Aussage
// des Recorders ("an diesem Tag wurde nach Abweichungen gesehen"), Zaehler sind ihr Produkt.
// Ein leeres Objekt ohne Marker ist von einem beim Lesen ergaenzten nicht zu unterscheiden -
// das ist eine Luecke, kein "geprueft und nichts gefunden". Gibt die Zaehler zurück, oder null,
// wenn der Tag zu keiner Rate beitragen darf (auch nicht zu ihrer Vergleichsgruppe).
export function anomalyLayer(d) {
  if (!d || typeof d !== "object") return null;
  if (!(d.anomaly && typeof d.anomaly === "object")) return null;
  if (d.anomalyRecorded === false) return null;
  if (d.anomalyRecorded === true) return d.anomaly;
  const hasCounters = (v) => Object.values(v ?? {}).some((x) => Number(x) > 0);
  return hasCounters(d.anomaly) || hasCounters(d.anomalyFail) ? d.anomaly : null;
}

// Die Anomalie-Vokabel: welche Ledger-Tags in eine Risiko- oder Empfindlichkeitsrechnung
// dürfen und welche das UI übersetzen muss. Sie ist die SSOT - der Recorder (monitor) und die
// Analyse-Ebenen lesen dieselbe Menge, damit ein neuer Tag nicht still aus der Vergleichung
// fällt. new-tx-type:* und type-burst:* sind über das Präfix zählbar.
export const ANOMALY_TAGS = new Set(["no-quorum", "hash-split", "load-spike", "load-extreme", "close-gap", "amendment-activity", "unl-change", ...SIGNATURE_TAGS]);
export const isAnomalyTag = (tag) => {
  const t = String(tag);
  return ANOMALY_TAGS.has(t) || t.startsWith("new-tx-type:") || t.startsWith("type-burst:");
};

// Incident-Ebene: Ledger-Korrelationen plus Typ-spezifische Befunde.
export function reasonsFor(type, ledgerTags) {
  const tags = [...ledgerTags];
  if (type === "wrong-hash") tags.unshift("signed-different-hash");
  if (type === "partial") tags.unshift("partial-validation");
  if (type === "missed" && !ledgerTags.length) tags.push("no-correlated-cause");
  return tags;
}

// Muster über viele Incidents: welche Korrelation taucht wie oft, bei wie vielen Validatoren auf.
export function aggregatePatterns(incidents, { minCount = 3, minValidators = 2, minLedgers = 2 } = {}) {
  const byTag = new Map();
  for (const inc of incidents) {
    for (const tag of inc.reasons ?? []) {
      if (!byTag.has(tag)) byTag.set(tag, { tag, count: 0, validators: new Set(), ledgers: new Set(), types: {} });
      const e = byTag.get(tag);
      e.count++;
      e.validators.add(inc.master);
      e.ledgers.add(inc.ledgerIndex);
      e.types[inc.type] = (e.types[inc.type] ?? 0) + 1;
    }
  }
  const rows = [...byTag.values()].map((e) => ({
    tag: e.tag, count: e.count, validators: e.validators.size, ledgers: e.ledgers.size, types: e.types,
  }));
  rows.sort((a, b) => b.count - a.count);
  // Wiederkehrend heißt: über mehrere LEDGER verteilt. 13 Ausfälle im selben Ledger sind EIN Ereignis.
  const recurring = rows.filter((r) => r.count >= minCount && r.validators >= minValidators && r.ledgers >= minLedgers && r.tag !== "no-correlated-cause");
  return { tags: rows, recurring };
}
