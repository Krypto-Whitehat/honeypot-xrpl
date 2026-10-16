// lib/validator-cause.mjs — Ursachen-Engine: die Rangliste moeglicher Gruende je Vorfall.
// Rein, ohne I/O. Eingabe: dieselben Tagesobjekte plus die bereits berechneten Ebenen.
//
// Die Retrace erklaert einen Vorfall aus seinem Ledger, die Diagnose aus der Zeitfolge, die
// Peer-Ebene aus der Vergleichsgruppe, die Lastkurve aus der Kapazitaet, die Divergenz aus der
// Hash-Linie und die Zeit-Ebene aus den Angriffsstunden. Jede Ebene hat ihre eigene Grenze.
// Was fehlte, ist die eine Antwort, die ein Betreiber haben will: WELCHER Grund hier der
// wahrscheinlichste ist, wie sicher er ist, und was er als Naechstes pruefen soll.
//
// Diese Engine erfindet keine Ursachen. Sie gewichtet die Belege, die die anderen Ebenen
// gemessen haben, nach Starke und selbstaendiger Quelle, und sie benennt ausdruecklich, was
// nicht erfasst ist. "unexplained" steht nur dort, wo wirklich kein Beleg liegt - dann mit der
// Liste der fehlenden Messungen, nie als Entlastung des Knotens.
//
// Grenzen, ehrlich benannt:
//   - eine Serie ist wiederholte Beobachtung, kein Messwert dieses Ledgers
//   - eine Kohorte ist Gleichzeitigkeit, kein nachgewiesener gemeinsamer Fehlergrund
//   - eine Angriffsstunde ist ein Zeitfenster, kein Nachweis, dass der Angriff diesen Knoten traf
//   - eine Laststufe ist Kopplung, nicht Kapazitaetsnachweis
// Deshalb ist die Konfidenz Teil des Ergebnisses und kein nachtraeglicher Zuschlag.
import { ledgerClosure, measured, loadBucket, marginBucket, TRACE_DEFAULTS } from "./validator-trace.mjs";
import { SERIES_VERDICTS } from "./validator-diagnose.mjs";

export const CAUSE_DEFAULTS = {
  minSignatureLedgers: 3,      // Angriffsstunde: ab so vielen signatur-markierten Ledgern (wie attack-impact)
  minCellLedgers: 60,          // darunter ist die Stunde zu duenn fuer eine Rate
  minCoShare: 0.05,            // Kohorten-Anteil unter dem der Fensterfenster diesem Knoten gehoert
  cohortShareStrong: 0.5,      // ab hier ist das Fenster ein Gemeinschaftsereignis
  minLoadCouplingRate: 0.05,   // eigene Ausfallrate in einer Laststufe ab hier als Last-Kopplung
  loadCouplingRatio: 2,        // ...und mindestens das Doppelte der eigenen Baseline-Rate
  bandRiskLift: 1.5,           // Bandbreite mit >= 1,5 x der Netz-Ausfallrate ist ein Risiko-Band
  bandComfortLift: 0.5,        // <= 0,5 x ist ein Komfort-Band: hier faellt sonst niemand aus
  minPeakHourIncidents: 5,     // Haufung: so viele Vorfaelle in einer UTC-Tageszeit
  minChecklistIncidents: 3,    // ein Pruefschritt ab so vielen Vorfällen in der Rangliste
  topCandidates: 6,
  topChecklist: 8,
  // TUNING-DEFAULT: Zeilen der Vorfall-Rangliste in der Antwort. Ein knotenreicher Validator
  // hat 8.609 Vorfaelle; die volle Liste ist 14 MB JSON, die niemand liest. Die Zaehlungen
  // (tally/coverage/reduction) bleiben ueber allen Vorfällen, nur die Zeilen sind gekuerzt -
  // und rowTotal nennt die Gesamtzahl, damit die Kuerzung keine verschleierte Aussage ist.
  rowLimit: 200,
};

// Die Starke eines Belegs. gemessener Wert > zwei selbstaendige Ebenen > eine wiederholte
// Beobachtung > Zeitfenster-Kontext > Einordnung ohne Beleg.
export const CAUSE_STRENGTHS = ["measured", "corroborated", "correlated", "context", "none"];
export const CAUSE_CONFIDENCE = ["high", "medium", "low", "none"];
// cause = Ursache, localization = eingrenzt auf Knoten oder Netz, consequence = Auswirkung des
// Fehlens, exoneration = entlastet einen Verdacht, category = Etikett ohne Ursachen-Aussage.
export const CAUSE_KINDS = ["cause", "localization", "consequence", "exoneration", "category"];
// Die von dieser Engine neu erzeugten Kandidaten. Die uebrigen Kandidaten uebernehmen die Tags
// der Retrace- und Serien-Ebene unveraendert, damit ein Vorfall nicht zwei Namen bekommt.
export const CAUSE_TAGS = [
  "load-coupled", "load-independent", "quorum-critical", "quorum-follow-on", "vote-not-observed",
  "quorum-band-risk", "quorum-band-comfort",
  "attack-window", "attack-window-clear", "recurrent-hour", "node-local-window", "network-window-localization",
  "signed-accepted-lineage",
];
export const CAUSE_GAPS = [
  "ledger-forensics", "vote-lineage", "quorum-counterfactual", "quorum-band-rate", "load-axis", "vote-timing", "attack-hours",
];
export const CAUSE_CHECKS = [
  "cause-check-uptime", "cause-check-clock", "cause-check-resources", "cause-check-version",
  "cause-check-quorum-settings", "cause-check-load-ceiling", "cause-check-peer-audit",
  "cause-check-attack-ledger", "cause-check-network-stall", "cause-check-capture-window", "cause-check-unknown",
];
export const CAUSE_LAYERS = ["ledger", "series", "quorum", "load", "peer", "hour", "attack", "lineage", "timing"];
export const UNEXPLAINED = "unexplained";

const num = measured;
const HOUR_MS = 3600000;
const hourOf = (ms) => (Number.isFinite(ms) ? Math.floor(ms / HOUR_MS) : null);
const utcHourOfDay = (ms) => (Number.isFinite(ms) ? new Date(ms).getUTCHours() : null);
const TYPES = ["missed", "partial", "wrongHash", "noQuorum"];
const COUNTER_KEYS = ["ok", ...TYPES];
const STRENGTH_BASE = { measured: 4, corroborated: 3, correlated: 2, context: 1, none: 0 };

// Die Pruefschritte, die aus einem Kandidaten folgen. Neue Tags, weil die Ledger-Ebene diese
// Fragen nicht stellt: "war mein Knoten am Stueck weg" und "laeuft mein Restart zur selben
// UTC-Stunde" sind keine Pruefung der Peering-Einstellungen.
const CHECKS_BY_TAG = {
  "offline-window": ["cause-check-uptime", "cause-check-resources"],
  "brief-outage": ["cause-check-uptime", "cause-check-resources"],
  "short-series": ["cause-check-uptime"],
  "degraded-window": ["cause-check-load-ceiling", "cause-check-version"],
  "degraded-single": ["cause-check-load-ceiling", "cause-check-version"],
  "cohort-window": ["cause-check-peer-audit", "cause-check-network-stall"],
  "network-window": ["cause-check-network-stall"],
  "network-stall": ["cause-check-network-stall"],
  "vote-not-observed": ["cause-check-capture-window", "cause-check-peer-audit"],
  "capture-window": ["cause-check-capture-window", "cause-check-peer-audit"],
  "hash-divergence": ["cause-check-version", "cause-check-peer-audit"],
  "isolated-miss": ["cause-check-uptime"],
  "node-local-window": ["cause-check-uptime", "cause-check-peer-audit"],
  "network-window-localization": ["cause-check-network-stall", "cause-check-peer-audit"],
  "quorum-thin": ["cause-check-quorum-settings"],
  "quorum-critical": ["cause-check-quorum-settings"],
  "quorum-follow-on": [],
  "quorum-band-risk": ["cause-check-quorum-settings", "cause-check-peer-audit"],
  "quorum-band-comfort": ["cause-check-uptime", "cause-check-resources"],
  "hash-split": ["cause-check-version", "cause-check-peer-audit"],
  "load-spike": ["cause-check-load-ceiling", "cause-check-resources"],
  "load-extreme": ["cause-check-load-ceiling", "cause-check-resources"],
  "load-coupled": ["cause-check-load-ceiling", "cause-check-resources"],
  "load-independent": ["cause-check-uptime"],
  "close-gap": ["cause-check-network-stall"],
  "vote-late": ["cause-check-clock", "cause-check-load-ceiling"],
  "recurrent-hour": ["cause-check-uptime", "cause-check-clock"],
  "attack-window": ["cause-check-attack-ledger"],
  "attack-window-clear": [],
  "sweep-window": ["cause-check-attack-ledger"],
  "drainer-fanout": ["cause-check-attack-ledger"],
  "sender-burst": ["cause-check-attack-ledger"],
  "offer-flood": ["cause-check-attack-ledger"],
  "nft-spam": ["cause-check-attack-ledger"],
  "account-create-burst": ["cause-check-attack-ledger"],
  "failure-spike": ["cause-check-attack-ledger"],
  "batch-amplify": ["cause-check-attack-ledger"],
  "fee-spike": ["cause-check-attack-ledger"],
  "new-tx-type": ["cause-check-version"],
  "amendment-activity": ["cause-check-version"],
  "unl-change": ["cause-check-version"],
  "signed-different-hash": ["cause-check-version"],
  "solo-failure": ["cause-check-uptime", "cause-check-resources"],
  "cohort-event": ["cause-check-peer-audit"],
  [UNEXPLAINED]: ["cause-check-unknown"],
};
const ATTACK_TAGS = new Set(["sweep-window", "drainer-fanout", "sender-burst", "offer-flood", "nft-spam",
  "account-create-burst", "failure-spike", "batch-amplify", "fee-spike", "new-tx-type"]);

const isAttackTag = (tag) => ATTACK_TAGS.has(String(tag)) || String(tag).startsWith("type-burst:");

function confidenceOf(weight) {
  if (weight >= 6) return "high";
  if (weight >= 4) return "medium";
  if (weight >= 2) return "low";
  return "none";
}

// Stunden-Zellen aus dem Trace. Die Schluessel von d.hourly sind absolute Epoch-Stunden, ein
// Schluessel gehoert also genau einem Tag - deshalb gibt es hier keine Zusammenrechnung ueber
// Tage hinweg und keine Mehrdeutigkeit, wenn ein Zaehler auf einem Tag fehlt und auf einem
// anderen da ist. Fehlende Zaehler bleiben null: "nicht erfasst" ist nicht "null Angriffe".
export function hourCells(days, master) {
  const cells = new Map();
  for (const d of Array.isArray(days) ? days : []) {
    const hourly = d.hourly ?? null;
    if (!hourly) continue;
    for (const [key, hb] of Object.entries(hourly)) {
      const hour = Number(key);
      if (!Number.isFinite(hour)) continue;
      const own = hb?.v?.[master] ?? null;
      const ownLedgers = own ? COUNTER_KEYS.reduce((n, k) => n + (num(own[k]) ?? 0), 0) : null;
      const ownFails = own ? TYPES.reduce((n, k) => n + (num(own[k]) ?? 0), 0) : null;
      cells.set(hour, {
        hour, hourMs: hour * HOUR_MS,
        ledgers: num(hb?.l) ?? 0,
        ownLedgers, ownFails,
        signatureLedgers: hb && hb.s !== undefined ? (num(hb.s) ?? 0) : null,
        anomalyLedgers: hb && hb.a !== undefined ? (num(hb.a) ?? 0) : null,
        txSum: hb && hb.tx !== undefined ? (num(hb.tx) ?? 0) : null,
        maxTx: hb && hb.mx !== undefined ? (num(hb.mx) ?? 0) : null,
      });
    }
  }
  return cells;
}

// Kategorie eines Retrace-Kandidaten. Solo/Kohorte bleibt ein Etikett, eine Messung im Ledger
// bleibt eine Ursache, eine Hash-Spaltung ist beides: Ursache und Auswirkung.
function hypothesisKind(tag, type) {
  const t = String(tag);
  if (t === "solo-failure" || t === "cohort-event") return "category";
  if (t === "quorum-thin" || t === "hash-split") return "cause";
  if (t === "close-gap" || t === "vote-late") return "cause";
  if (t === "load-spike" || t === "load-extreme") return "cause";
  if (isAttackTag(t) || t === "new-tx-type" || t === "amendment-activity" || t === "unl-change") return "cause";
  if (t === "signed-different-hash") return "cause";
  if (SERIES_SET.has(t)) return "cause";
  if (t === "no-quorum" || t === "vote-not-observed") return "cause";
  void type;
  return "cause";
}

const KIND_ORDER = { cause: 0, localization: 1, consequence: 2, exoneration: 3, category: 4 };

function mergeCandidate(map, tag, kind, strength, layer, evidence, lift) {
  if (!tag) return;
  const key = tag + "|" + kind;
  const cur = map.get(key);
  if (!cur) {
    map.set(key, { tag, kind, strength, layers: [layer], evidence: evidence ?? {}, lift: lift ?? null });
    return;
  }
  if (STRENGTH_BASE[strength] > STRENGTH_BASE[cur.strength]) cur.strength = strength;
  if (!cur.layers.includes(layer)) cur.layers.push(layer);
  if (cur.lift === null && lift) cur.lift = lift;
  if (evidence && Object.keys(cur.evidence).length === 0) cur.evidence = evidence;
}

// Ein Vorfall, eine Rangliste. Die Ebenen werden in der Reihenfolge ihres Belegs gelesen, nicht
// in der Reihenfolge ihrer Auffaelligkeit.
function rankIncident(row, c, p) {
  const ledgerIndex = row.ledgerIndex;
  const timeMs = row.timeMs ?? null;
  const hour = hourOf(timeMs);
  const cell = hour !== null ? c.cells.get(hour) ?? null : null;
  const map = new Map();
  const gaps = new Set();
  const add = (tag, kind, strength, layer, evidence, lift) => mergeCandidate(map, tag, kind, strength, layer, evidence, lift);

  // 1. Ledger-Ebene (Retrace): die direkten Messungen dieses Ledgers.
  for (const h of row.hypotheses ?? []) {
    if (h.tag === "no-correlated-cause") continue;
    const strength = h.strength === "measured" ? "measured"
      : h.strength === "correlated" ? "correlated"
        : h.strength === "cohort" ? "correlated"
          : h.strength === "none" ? "none" : "correlated";
    // Eine Serien-Einordnung ist kein Messwert dieses Ledgers: sie kommt aus der Zeitfolge.
    // Wer sie als Ledger-Ebene verbucht, zaehlt eine selbstaendige Quelle doppelt.
    add(h.tag, hypothesisKind(h.tag, row.type), strength, SERIES_SET.has(h.tag) ? "series" : "ledger", h.evidence, h.lift);
  }
  // 3. Quorum-Gegenprobe: haette das Fehlen dieses Knotens den Ausgang geaendert?
  const cq = c.criticalByLedger.get(ledgerIndex) ?? null;
  if (row.type === "no-quorum" || row.type === "vote-not-observed") {
    // 'no-quorum' ist die Grenze der eigenen Erfassung, kein Urteil ueber das Netz: der Ledger ist
    // aus dem validierten Stream bewiesen geschlossen. Die Ursache heisst deshalb 'vote-not-observed'
    // und nennt den Schliess-Hash, damit die Aussage an einer nachpruefbaren Zahl haengt.
    // 'network-stall' bleibt nur dort stehen, wo die Schliess-Ebene die Schliessung verneint.
    const closure = cq?.closure ?? c.closureByLedger.get(ledgerIndex) ?? ledgerClosure(null);
    add("vote-not-observed", "cause", "measured", "ledger", {
      scope: row.scope ?? null, closedHash: closure.hash, closureBasis: closure.basis,
      observedVotes: cq?.votes ?? null, needed: cq?.needed ?? null,
      // Beide Quellen kennen die Erfassungs-Luecke: die Kritikalitaets-Zeile und die
      // Schliess-Ebene der Tagesdatei. 'true' nur, wenn eine von beiden sie gemessen hat.
      captureGap: cq?.captureGap === true || closure.captureGap === true,
    });
    // 'network-stall' ist die einzige Aussage, die ein fehlendes Netz-Quorum behauptet. Sie
    // steht ausschliesslich dort, wo die Schliess-Ebene die Schliessung verneint.
    if (closure.closed === false) add("network-stall", "cause", "measured", "ledger", { scope: row.scope ?? null });
  }

  // 2. Spaet-Validierung auch dann, wenn der Reason-Tag fehlt: der Messwert ist da, das Etikett
  //    nicht. Ohne diese Zeile bleibt ein gemessener spaeter Vote ein Etikett ohne Ursache.
  const delay = Number.isFinite(row.voteDelayMs) ? row.voteDelayMs : null;
  if (delay !== null && delay > c.graceMs) {
    add("vote-late", "cause", "measured", "timing", { voteDelayMs: delay, graceMs: c.graceMs, source: "measured-delay" });
  } else if (delay === null && row.type === "missed") gaps.add("vote-timing");

  if (cq) {
    const ev = { votes: cq.votes, needed: cq.needed, topVotes: cq.topVotes, margin: cq.margin, runnerVotes: cq.runnerVotes };
    if (cq.critical) add("quorum-critical", "consequence", "measured", "quorum", ev);
    else add("quorum-follow-on", "exoneration", "measured", "quorum", ev);
    // Die Gegenprobe dieses Ledgers sagt, ob dein Fehlen den Ausgang geaendert haette. Sie sagt
    // nicht, wie gefaehrlich dieser Ledger fuer alle war. Das ist die Bandbreite der Risikoflaeche:
    // Ausfallrate aller Knoten in DIESER Quorum-Reserve gegen die Rate ueber alle Reserve-Stufen.
    // Ein Miss in einem Risiko-Band ist eine Netzlage, ein Miss in einem Komfort-Band ist der
    // eigene Knoten - und ohne diesen Nenner waere beides nur ein Etikett.
    const bi = marginBucket(cq.margin);
    const band = bi === null ? null : c.bandByIndex.get(bi) ?? null;
    if (band && band.reliable && band.networkRate !== null && c.overallBandRate !== null && c.overallBandRate > 0) {
      // Der Lift wird vor der Entscheidung gerundet, nicht danach. Ohne das steht in der JSON
      // ein Lift von 2,9999999999999996 neben einem bandLift von 3, und ein Betreiber vergleicht
      // zwei Zahlen, die dieselbe Aussage haben sollten.
      const lift = round(band.networkRate / c.overallBandRate, 4);
      const ev2 = { ...ev, marginBand: band.label, bandFailRate: band.networkRate, overallFailRate: c.overallBandRate, bandLift: lift, bandLedgers: band.ledgers };
      if (lift >= p.bandRiskLift) add("quorum-band-risk", "cause", "corroborated", "quorum", ev2, lift);
      else if (lift <= p.bandComfortLift) add("quorum-band-comfort", "exoneration", "corroborated", "quorum", ev2, lift);
    } else gaps.add("quorum-band-rate");
  } else gaps.add("quorum-counterfactual");

  // 4. Last-Kopplung: faellt dieser Knoten in genau den Laststufen, in denen die Kohorte dieselbe
  //    Last noch durchhaelt? Das ist der Kapazitaetsbefund, den die Ledger-Ebene nicht liefern kann.
  const txCount = row.load && Number.isFinite(row.load.txCount) ? row.load.txCount : null;
  if (txCount === null) gaps.add("load-axis");
  else if (c.curve && c.curve.baseline) {
    const idx = loadBucket(txCount);
    const at = c.curveByIndex.get(idx) ?? null;
    const base = c.curveByIndex.get(c.curve.baseline.index) ?? null;
    if (!at || !base) gaps.add("load-axis");
    else {
      const ownRate = num(at.validatorRate);
      const baseRate = num(base.validatorRate);
      const aboveBaseline = idx > c.curve.baseline.index;
      const coupled = aboveBaseline && at.sample !== "thin" && ownRate !== null && ownRate >= p.minLoadCouplingRate
        && (baseRate === null || baseRate === 0 || ownRate >= p.loadCouplingRatio * baseRate);
      const ev = { txCount, bucket: at.label, ledgers: at.validatorLedgers, fails: at.validatorFails, ownRate, baseRate, cohortMedianRate: at.cohortMedianRate };
      if (coupled) add("load-coupled", "cause", "corroborated", "load", ev);
      else if (!aboveBaseline) {
        const resilient = c.curve.validator && c.curve.validator.verdict === "load-resilient";
        add("load-independent", "exoneration", resilient ? "corroborated" : "correlated", "load", ev);
      }
    }
  } else gaps.add("load-axis");

  // 5. Kohorten-Ortung: gehoert dieses Zeitfenster anderen mit oder nur diesem Knoten?
  const coShare = row.series && Number.isFinite(row.series.coShare) ? row.series.coShare : null;
  if (coShare !== null) {
    if (coShare >= p.cohortShareStrong) add("network-window-localization", "localization", "corroborated", "peer", { coShare, coValidators: row.series.coValidators ?? null });
    else if (coShare < p.minCoShare) add("node-local-window", "localization", "correlated", "peer", { coShare });
  } else if (row.scope === "solo") add("node-local-window", "localization", "correlated", "peer", { others: 0 });
  else if (row.scope === "network") add("network-window-localization", "localization", "corroborated", "peer", { type: row.type });
  if (c.peer && c.peer.verdict && c.peer.verdict !== "insufficient-sample" && c.peer.verdict !== "not-observed") {
    const ev = { peerVerdict: c.peer.verdict, ratioToMedian: c.peer.comparison?.ratioToMedian ?? null, percentile: c.peer.comparison?.percentile ?? null };
    if (c.peer.verdict === "peer-baseline") add("network-window-localization", "localization", "context", "peer", ev);
    else add("node-local-window", "localization", "context", "peer", ev);
  }

  // 6. Hash-Linie: hat dieser Knoten eine andere Linie signiert als die, die validated wurde?
  const lin = c.lineageByLedger.get(ledgerIndex) ?? null;
  if (!lin) gaps.add("vote-lineage");
  else if (lin.lineage === "own" || lin.lineage === "runner") add("hash-divergence", "cause", "measured", "lineage", { lineage: lin.lineage, votedHash: lin.votedHash, acceptedHash: lin.acceptedHash });
  else if (lin.lineage === "accepted") add("signed-accepted-lineage", "exoneration", "measured", "lineage", { votedHash: lin.votedHash, acceptedHash: lin.acceptedHash });

  // 7. Zeitfenster-Angriff: fuehrte diese Stunde Signaturen, und was sagt die Netz-Gegenprobe?
  //    Die Stunde wird von zwei Autoritaeten beurteilt: dem eigenen Trace (stunden-genau
  //    gemessene Signatur-Ledger) und der Betrugs-Historie (Cluster-Stunden, die mit der
  //    Aufzeichnung zusammenfielen). Fehlt die eigene Messung, ist die Stunde nicht unbekannt,
  //    wenn die Historie sie fuehrt - und eine Stunde, die eine Autoritaet mit Abdeckung als
  //    ruhig ausweist, entlastet: dieser Vorfall liegt nachweislich ausserhalb eines
  //    Angriffszeitfensters. Duenn abgedeckte Stunden fehlen in beiden Listen, weil ueber einer
  //    duennen Stunde kein Urteil steht, nicht ihre Ruhe.
  const cellHour = cell?.hour ?? null;
  const measuredHour = cell !== null && cell.ledgers >= p.minCellLedgers;
  const traceSaysAttack = cell !== null && cell.signatureLedgers !== null
    && cell.signatureLedgers >= p.minSignatureLedgers && measuredHour;
  const historySaysAttack = cellHour !== null && c.historyAttackSet.has(cellHour);
  const traceSaysQuiet = cell !== null && cell.signatureLedgers !== null && measuredHour
    && !c.traceAttackSet.has(cellHour) && cell.signatureLedgers < p.minSignatureLedgers;
  const headSaysQuiet = cellHour !== null && c.quietHourSet.has(cellHour);
  const control = c.impact ? c.impact.verdict : null;
  if (traceSaysAttack || historySaysAttack) {
    add("attack-window", "cause", control === "attack-linked" ? "corroborated" : "context", "attack", {
      source: traceSaysAttack ? "trace" : "history",
      hourMs: cell?.hourMs ?? null, signatureLedgers: cell?.signatureLedgers ?? null,
      anomalyLedgers: cell?.anomalyLedgers ?? null, ledgers: cell?.ledgers ?? null,
      controlVerdict: control, controlAuthority: c.impact?.verdictAuthority ?? null,
      controlLift: c.impact?.network?.lift ?? null, controlZ: c.impact?.network?.zRaw ?? null,
    });
  } else if (traceSaysQuiet && headSaysQuiet) {
    // Die eigene Messung und die Gegenprobe derselben Autoritaet: zwei unabhaengige Blicke auf
    // dieselbe Stunde, beide ohne Signatur und ohne Cluster.
    add("attack-window-clear", "exoneration", "corroborated", "attack", {
      source: "trace+" + (c.impact?.hours?.authority ?? "history"), hourMs: cell.hourMs,
      signatureLedgers: cell.signatureLedgers, ledgers: cell.ledgers,
      controlVerdict: control, controlAuthority: c.impact?.verdictAuthority ?? null,
    });
  } else if (headSaysQuiet) {
    // Nur die Gegenprobe hat diese Stunde geprueft - die eigene Messung fehlt. Das ist eine
    // Entlastung mit einer Quelle, nicht mit zweien.
    add("attack-window-clear", "exoneration", "correlated", "attack", {
      source: c.impact?.hours?.authority ?? "history", hourMs: cell?.hourMs ?? null,
      ledgers: cell?.ledgers ?? null, controlVerdict: control, controlAuthority: c.impact?.verdictAuthority ?? null,
    });
  } else if (!cell || (cell.signatureLedgers === null && cellHour !== null
    && !c.attackHourSet.has(cellHour) && !c.quietHourSet.has(cellHour))) {
    gaps.add("attack-hours");
  }

  // 8. Haufung zur selben UTC-Tageszeit: ein Muster, das auf Restart, Wartung oder NTP-Fenster
  //    zeigt - die Ledger-Ebene kennt die Uhrzeit nicht.
  const hod = utcHourOfDay(timeMs);
  const peak = hod !== null ? c.peakHours.get(hod) ?? null : null;
  if (peak && peak.incidents >= p.minPeakHourIncidents) {
    add("recurrent-hour", "cause", "correlated", "hour", { utcHour: hod, incidents: peak.incidents, hours: peak.hours, ownFailsInHour: cell?.ownFails ?? null });
  }

  const candidates = [...map.values()].map((x) => {
    let w = STRENGTH_BASE[x.strength] ?? 0;
    if (x.layers.length >= 2) w += 1;
    if (x.lift && x.lift.reliable) w += 1;
    // Beobachtungsstaerke: wie deutlich sich der Befund von der Zufallsstreuung abhebt. Das ist
    // kein Mechanismus-Beweis - eine Serie von 35 Ledgern erklaert nicht, WARUM der Knoten weg
    // war. Aber sie entscheidet, ob "am Stueck weg" eine Beobachtung ist oder ein Etikett.
    if (x.tag === "offline-window" || x.tag === "brief-outage" || x.tag === "short-series"
      || x.tag === "degraded-window" || x.tag === "cohort-window" || x.tag === "network-window") {
      const len = num(x.evidence?.ledgers);
      if (len !== null && len >= 15) w += 2;
      else if (len !== null && len >= 5) w += 1;
    }
    if (x.tag === "recurrent-hour") {
      // Die Haufung darf einer konkreten Ausfallserie nicht zuvorkommen: "deine Ausfaelle
      // haufen sich um 21 UTC" ist ein Hinweis auf den Mechanismus, "du warst 9 Ledger am Stueck
      // weg" ist die Beobachtung selbst. Deshalb hier eine hoehere Schwelle.
      const n = num(x.evidence?.incidents);
      if (n !== null && n >= 20) w += 1;
    }
    if (x.kind === "exoneration") w -= 1;
    if (x.kind === "category") w = 0;
    w = Math.max(0, w);
    return { ...x, weight: w, confidence: confidenceOf(w) };
  });
  candidates.sort((a, b) => (b.weight - a.weight) || (KIND_ORDER[a.kind] - KIND_ORDER[b.kind]) || a.tag.localeCompare(b.tag));

  const head = candidates.find((x) => (x.kind === "cause" || x.kind === "localization") && x.confidence !== "none") ?? null;
  const verdict = head ? head.tag : UNEXPLAINED;
  // Pruefschritte folgen dem Urteil und den Kandidaten ab Gewicht 3. Alle Kandidaten einer
  // Rangliste liefern zusammen eine Pruefliste, die bei jedem Vorfall gleich lang ist - die
  // beantwortet nichts. Was zehlt, ist, was dieses Urteil naechst legt.
  // Akkuratz-Regel (2026-10-16): die Pruefung auf Netzstockung behauptet ein ausstehendes
  // Netz-Quorum. Beleg dafuer ist allein die ausdrucklich verneinte Schliessung dieses Ledgers.
  // Bewiesen geschlossen heisst: das Netz hat sein Quorum erreicht. Schliessung nicht erfasst
  // heisst: eine Datenluecke dieses Recorders, kein Verdacht gegen das Netz.
  const closureProof = cq?.closure ?? c.closureByLedger.get(ledgerIndex) ?? null;
  const stallBasis = closureProof?.closed === false;
  // Akkuratz-Regel (2026-10-17): der Close-Abstand belegt eine verlangsamte Taktung nur zwischen
  // aufeinanderfolgenden Ledger-Indizes. 'captureGap === false' ist der Beleg, dass die Index-
  // Folge dieses Recorders durchgehend ist; 'true' erklaert den Abstand durch die eigene Luecke
  // und null heisst nicht erfasst. In beiden Faellen ist die Netzstockung hier keine
  // naechstliegende Pruefung, sondern die eigene Erfassung.
  const gapBasis = closureProof?.captureGap === false;
  const checks = [];
  const pushChecks = (tag) => { for (const c of CHECKS_BY_TAG[tag] ?? []) {
    if (c === "cause-check-network-stall" && !stallBasis && !(tag === "close-gap" && gapBasis)) continue;
    if (!checks.includes(c)) checks.push(c);
  } };
  if (head) pushChecks(head.tag);
  for (const cand of candidates) {
    if (head && cand.tag === head.tag) continue;
    if (cand.weight >= 3) pushChecks(cand.tag);
  }
  if (!head) for (const tag of CHECKS_BY_TAG[UNEXPLAINED]) if (!checks.includes(tag)) checks.push(tag);

  return {
    ledgerIndex, timeMs, type: row.type, verdict,
    verdictKind: head ? head.kind : "none",
    verdictStrength: head ? head.strength : "none",
    verdictConfidence: head ? head.confidence : "none",
    verdictLayers: head ? head.layers : [],
    verdictEvidence: head ? head.evidence : {},
    candidates: candidates.slice(0, p.topCandidates),
    candidateTotal: candidates.length,
    nextCheck: checks.slice(0, p.topChecklist),
    dataGaps: [...gaps].sort(),
    series: row.series ? { ledgers: row.series.ledgers, position: row.series.position, verdict: row.series.verdict, coShare: row.series.coShare } : null,
    scope: row.scope ?? null,
  };
}

const SERIES_SET = new Set(SERIES_VERDICTS);
const round = (x, n) => (Number.isFinite(x) ? Math.round(x * 10 ** n) / 10 ** n : null);

// Die Vorher/Nachher-Zahl: die rohen Reason-Tags der Tagesdatei gegen die Urteile dieser Engine.
// "rohe Ursache" ist, was die Ledger-Ebene allein lieferte. "erklaert" ist, was nach den
// selbstaendigen Ebenen uebrig bleibt. Beide Zahlen stehen nebeneinander, weil die Engine keine
// Ursache erfindet - sie verschiebt nur Belege in die Rangliste, die wirklich gemessen wurden.
export function causeLedger(context = {}, opts = {}) {
  const p = { ...CAUSE_DEFAULTS, ...opts };
  const master = context.master ?? null;
  const range = context.range ?? "24h";
  const days = Array.isArray(context.days) ? context.days : [];
  const retrace = Array.isArray(context.retrace) ? context.retrace : [];
  const diagnosis = context.diagnosis ?? {};
  const incidents = Array.isArray(context.incidents) ? context.incidents : [];

  const cells = hourCells(days, master);
  const criticalByLedger = new Map();
  for (const r of diagnosis.criticality?.rows ?? []) criticalByLedger.set(r.ledgerIndex, r);
  // Die Kritikalitaets-Tabelle zeigt zwolf Zeilen, die Forensik-Aufzeichnung hat alle. Ohne
  // diesen Index bekam jeder Vorfall ausserhalb jener zwolf Zeilen gar keine Schliess-Ebene -
  // und die Ursachen-Ebene behauptete auf ihnen 'network-stall' ohne jeden Beleg.
  const closureByLedger = new Map();
  for (const d of days) for (const st of d.ledgerStats ?? []) {
    if (closureByLedger.has(st.l)) continue;
    closureByLedger.set(st.l, ledgerClosure(st));
  }
  const curveByIndex = new Map();
  for (const r of diagnosis.load?.rows ?? []) curveByIndex.set(r.index, r);
  const peakHours = new Map();
  for (const r of diagnosis.fingerprint?.peakUtcHours ?? []) peakHours.set(r.utcHour, r);
  // Risikoflaeche: die Bandbreiten-Nenner, die der Ledger-Ebene fehlen. Ohne sie ist
  // "Quorum war knapp" eine Einzelbeobachtung; mit ihr ist es eine Rate mit Vergleichswert.
  const bandByIndex = new Map();
  for (const b of context.surface?.bands ?? []) if (b.axis === "quorum") bandByIndex.set(b.idx, b);
  const bandLedgers = [...bandByIndex.values()].reduce((a, b) => a + (num(b.ledgers) ?? 0), 0);
  const bandFails = [...bandByIndex.values()].reduce((a, b) => a + (num(b.failLedgers) ?? 0), 0);
  const overallBandRate = bandLedgers > 0 ? bandFails / bandLedgers : null;
  const lineageByLedger = new Map();
  for (const d of context.divergence?.divergences ?? []) lineageByLedger.set(d.ledgerIndex, d);
  for (const r of context.divergence?.lateLineage?.rows ?? []) if (!lineageByLedger.has(r.ledgerIndex)) lineageByLedger.set(r.ledgerIndex, r);

  // Die Stunden der Gegenprobe. Das ist die einzige Angriffsseite, die auch dann entscheidet,
  // wenn der eigene Trace keine Signatur-Zaehler hat - in aelteren Tagesdateien der Regelfall.
  // Fehlende Zeilen bedeuten keine ruhige Stunde, sondern keine Aussage: ein leerer Set darf
  // nicht als Entlastung gelesen werden, sonst wird eine leere Historie zum sauberen Befund.
  const impactHours = context.impact?.hours ?? null;
  const attackHourSet = new Set(impactHours?.attack ?? []);
  const historyAttackSet = new Set(impactHours?.bySource?.history ?? []);
  const traceAttackSet = new Set(impactHours?.bySource?.trace ?? []);
  const quietHourSet = new Set(impactHours?.quiet ?? []);
  const ctx = {
    cells, criticalByLedger, closureByLedger, curveByIndex, peakHours, lineageByLedger,
    curve: diagnosis.load ?? null, peer: context.peer ?? null,
    impact: context.impact ?? null, graceMs: TRACE_DEFAULTS.graceMs,
    bandByIndex, overallBandRate,
    attackHourSet, historyAttackSet, traceAttackSet, quietHourSet,
  };
  const rows = retrace.map((row) => rankIncident(row, ctx, p));

  const rawReasons = new Map();
  for (const i of incidents) rawReasons.set(i.ledgerIndex + "|" + i.type, i.reasons ?? []);
  const isRawNoCause = (reasons) => !Array.isArray(reasons) || reasons.length === 0
    || (reasons.length === 1 && reasons[0] === "no-correlated-cause");

  const tally = {}; const strengthTally = {}; const confidenceTally = {}; const kindTally = {};
  const layerTally = {}; const exonerationTally = {}; const gapTally = {};
  const checkTally = new Map();
  let rawNoCause = 0, rawResolved = 0, rawMatched = 0, rawUnmatched = 0;

  for (const r of rows) {
    tally[r.verdict] = (tally[r.verdict] ?? 0) + 1;
    strengthTally[r.verdictStrength] = (strengthTally[r.verdictStrength] ?? 0) + 1;
    confidenceTally[r.verdictConfidence] = (confidenceTally[r.verdictConfidence] ?? 0) + 1;
    kindTally[r.verdictKind] = (kindTally[r.verdictKind] ?? 0) + 1;
    for (const l of r.verdictLayers) layerTally[l] = (layerTally[l] ?? 0) + 1;
    for (const g of r.dataGaps) gapTally[g] = (gapTally[g] ?? 0) + 1;
    const key = r.ledgerIndex + "|" + r.type;
    if (rawReasons.has(key)) {
      rawMatched += 1;
      if (isRawNoCause(rawReasons.get(key))) { rawNoCause += 1; if (r.verdict !== UNEXPLAINED) rawResolved += 1; }
    } else rawUnmatched += 1;
    for (const cand of r.candidates) if (cand.kind === "exoneration") exonerationTally[cand.tag] = (exonerationTally[cand.tag] ?? 0) + 1;
    for (const tag of r.nextCheck) {
      const e = checkTally.get(tag) ?? { tag, incidents: 0, verdicts: new Set() };
      e.incidents += 1;
      if (r.nextCheck[0] === tag) e.verdicts.add(r.verdict);
      checkTally.set(tag, e);
    }
  }

  const unexplained = tally[UNEXPLAINED] ?? 0;
  const explained = rows.length - unexplained;
  const verdictRows = Object.entries(tally).filter(([tag]) => tag !== UNEXPLAINED)
    .map(([tag, count]) => ({ tag, incidents: count, share: rows.length ? round(count / rows.length, 4) : null }))
    .sort((a, b) => (b.incidents - a.incidents) || a.tag.localeCompare(b.tag));

  const checklist = [...checkTally.values()]
    .filter((e) => e.incidents >= p.minChecklistIncidents)
    .map((e) => ({ tag: e.tag, incidents: e.incidents, share: rows.length ? round(e.incidents / rows.length, 4) : null, verdicts: [...e.verdicts].slice(0, 4) }))
    .sort((a, b) => (b.incidents - a.incidents) || a.tag.localeCompare(b.tag))
    .slice(0, p.topChecklist);

  const hourList = [...cells.values()];
  const coverage = {
    incidents: rows.length,
    rawIncidents: incidents.length,
    matchedIncidents: rawMatched,
    unmatchedIncidents: rawUnmatched,
    withLedgerMeasurement: rows.filter((r) => r.candidates.some((c) => c.layers.includes("ledger") && c.strength === "measured")).length,
    withQuorumCounterfactual: rows.filter((r) => !r.dataGaps.includes("quorum-counterfactual")).length,
    withQuorumBandRate: rows.filter((r) => !r.dataGaps.includes("quorum-band-rate")).length,
    quorumBandRate: overallBandRate === null ? null : round(overallBandRate, 4),
    quorumBandLedgers: bandLedgers,
    withLoadAxis: rows.filter((r) => !r.dataGaps.includes("load-axis")).length,
    withVoteLineage: rows.filter((r) => !r.dataGaps.includes("vote-lineage")).length,
    withVoteTiming: rows.filter((r) => !r.dataGaps.includes("vote-timing")).length,
    hoursRecorded: cells.size,
    hoursThin: hourList.filter((h) => h.ledgers < p.minCellLedgers).length,
    // Angriffsstunden nach Autoritaet getrennt: die eigene Messung und die Historie duerfen
    // sich widersprechen, und eine Stunde, die keine von beiden fuehrt, ist nur dann unbekannt,
    // wenn auch die Gegenprobe keine Aussage hat. Sonst verschwindet der Unterschied zwischen
    // "ruhig geprueft" und "nie geprueft".
    attackHours: hourList.filter((h) => (h.signatureLedgers ?? 0) >= p.minSignatureLedgers || attackHourSet.has(h.hour)).length,
    attackHoursTrace: hourList.filter((h) => (h.signatureLedgers ?? 0) >= p.minSignatureLedgers).length,
    attackHoursHistory: hourList.filter((h) => historyAttackSet.has(h.hour)).length,
    quietHours: hourList.filter((h) => quietHourSet.has(h.hour)).length,
    attackHoursUnknown: hourList.filter((h) => h.signatureLedgers === null && !attackHourSet.has(h.hour) && !quietHourSet.has(h.hour)).length,
    withAttackWindow: rows.filter((r) => !r.dataGaps.includes("attack-hours")).length,
    impactVerdict: context.impact?.verdict ?? null,
    impactAuthority: context.impact?.verdictAuthority ?? null,
  };

  return {
    master, range,
    thresholds: {
      minSignatureLedgers: p.minSignatureLedgers, minCellLedgers: p.minCellLedgers,
      cohortShareStrong: p.cohortShareStrong, minCoShare: p.minCoShare,
      minLoadCouplingRate: p.minLoadCouplingRate, loadCouplingRatio: p.loadCouplingRatio,
      bandRiskLift: p.bandRiskLift, bandComfortLift: p.bandComfortLift,
      minPeakHourIncidents: p.minPeakHourIncidents, graceMs: ctx.graceMs,
    },
    coverage,
    reduction: {
      rawNoCause, rawNoCauseShare: rows.length ? round(rawNoCause / rows.length, 4) : null,
      resolvedByCauseEngine: rawResolved,
      remainingRawNoCause: rawNoCause - rawResolved,
      unexplainedTotal: unexplained,
      unexplainedShare: rows.length ? round(unexplained / rows.length, 4) : null,
      explainedShare: rows.length ? round(explained / rows.length, 4) : null,
    },
    tally, strengthTally, confidenceTally, kindTally, layerTally,
    exonerationTally, gapTally,
    verdicts: verdictRows,
    primary: verdictRows[0] ?? null,
    checklist,
    rows: rows.slice(0, p.rowLimit),
    rowTotal: rows.length,
  };
}
