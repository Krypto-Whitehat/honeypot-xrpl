// lib/tx-forensics.mjs — Transaktions-Forensik auf Ledger-Ebene (rein, ohne I/O).
//
// Was der Validations-Stream zeigt, ist die FOLGE (Validator verpasst / partial / wrong-hash /
// no-quorum). Diese Modul liefert die MIT-URSACHE auf der Ledger-Seite: die FORM der
// Transaktionen in genau diesem Ledger. Ein Ledger mit 300 Tx ist nicht gleich ein Ledger mit
// 300 Tx — 300 Zahlungen von 300 Konten ist Normalbetrieb, 300 Zahlungen von EINEM Konto auf
// 280 verschiedene Konten ist ein Sweep. Genau diese Form unterscheidet Lastspitze von
// Angriffssignatur, und sie ist der Grund, warum ein Validator zurückfällt, ohne selbst schuld
// zu sein (Queue-Rückstau, Zustandsneuberechnung, Amendment-Umbau, Orderbuch-Flut).
//
// Zwei Ebenen:
//   1. Form je Ledger  — Absender-/Empfänger-Streuung, Fächerung, Fehlerrate, Typ-Mischung,
//                        Gebühren, Batch-Verstärkung, Kontenerstellung, Orderbuch-/NFT-Aktivität.
//   2. Muster je Ledger — benannte Signaturen (drainer-fanout, sender-burst, offer-flood, ...)
//                        gegen die rollende Basis der letzten Ledger. Ohne Basis wird NICHTS
//                        gemeldet: kein Wert ohne Vergleich, keine Signatur ohne Grund.
//
// Schwellen sind TUNING-DEFAULTS ohne Kampagnen-Nachweis (wie TRACE_DEFAULTS, PEELING_THRESHOLDS)
// und per opts überschreibbar. Die Signatur ist eine KORRELATION im selben Ledger, kein Beweis.
export const TX_FORENSICS_DEFAULTS = {
  baselineSize: 60,        // rollende Basis (Ledger) für alle Mediane
  minBaseline: 10,         // darunter keine Signatur (kein Raten)
  minTx: 20,               // absolute Untergrenze für Form-Signaturen
  fanoutMinAccounts: 8,    // ein Konto erreicht im Ledger >= 8 verschiedene Empfänger
  fanoutMinTxs: 10,        // ... und sendet dafür >= 10 Tx in diesem Ledger
  burstMinTxs: 25,         // ein Konto sendet >= 25 Tx im selben Ledger
  burstShare: 0.4,         // ... und stellt >= 40 % dieses Ledgers
  createMin: 10,           // >= 10 AccountCreate im selben Ledger
  createRatio: 4,          // ... und >= 4 x Basis-Median
  failureMin: 10,          // >= 10 fehlgeschlagene Tx im selben Ledger
  failureShare: 0.25,      // ... und >= 25 % dieses Ledgers
  offerMin: 40,            // >= 40 OfferCreate/OfferCancel
  offerRatio: 4,
  nftMin: 40,              // >= 40 NFT-Angebote/Mints
  nftRatio: 4,
  batchMinTxs: 5,          // >= 5 Batch-Tx (XLS-56d) ...
  batchInnerMin: 50,       // ... mit insgesamt >= 50 Inner-Tx -> Verstärkung
  typeMin: 20,             // ein Typ >= 20 Tx ...
  typeRatio: 4,            // ... und >= 4 x seinem eigenen Median -> neuer Vektor
  feeMinDrops: 100000,     // einzelne Tx mit >= 0.1 XRP Gebühr
  feeRatio: 20,            // ... und >= 20 x Median-Gebühr
  sweepWindowLedgers: 12,  // Sweep-Fenster über Ledger hinweg (12 Ledger ~ 2 min)
  sweepMinDestinations: 12,// ein Konto erreicht im Fenster >= 12 verschiedene Empfänger
  maxTrackedAccounts: 4000,// Speicherdeckel der Konto-Beobachtung
};

const num = (x) => { const n = Number(x); return Number.isFinite(n) ? n : 0; };
export function median(values) {
  const v = (Array.isArray(values) ? values : []).filter((x) => Number.isFinite(x));
  if (!v.length) return 0;
  const s = [...v].sort((a, b) => a - b);
  const m = Math.floor(s.length / 2);
  return s.length % 2 ? s[m] : (s[m - 1] + s[m]) / 2;
}

// Stream-Nachricht -> kompakte Form. Der "transactions"-Stream liefert die Tx unter
// "transaction" (xrplcluster/rippled so gemessen), neuere API-Stufen unter "tx_json", und die
// Ledger-Form (command:"ledger", expand:true) ist der Tx-Objekt selbst. Alle drei werden
// akzeptiert; die Reihenfolge ist absichtlich: explizite Huelle vor dem Objekt selbst.
export function normalizeTx(m) {
  const tx = m?.tx ?? m?.tx_json ?? m?.transaction ?? m ?? null;
  if (!tx || !tx.TransactionType) return null;
  // Batch-Innen-Tx: im Ledger-Objekt "InnerTransactions", im Stream-Rohformat "RawTransactions".
  const inner = Array.isArray(tx.InnerTransactions) ? tx.InnerTransactions.length
    : Array.isArray(tx.RawTransactions) ? tx.RawTransactions.length : 0;
  const meta = m?.meta ?? null;
  const state = meta && typeof meta.transaction_state === "string" ? meta.transaction_state : null;
  const engine = typeof m?.engine_result === "string" ? m.engine_result : null;
  const success = state ? state === "tesSUCCESS" : engine ? engine === "tesSUCCESS" : true;
  return {
    type: tx.TransactionType,
    account: typeof tx.Account === "string" ? tx.Account : null,
    destination: typeof tx.Destination === "string" ? tx.Destination : null,
    fee: num(tx.Fee),
    inner,
    success,
  };
}

export function emptyShape() {
  return { n: 0, senders: new Set(), destinations: new Set(), byAccount: new Map(), byAccountDest: new Map(),
    byType: new Map(), fees: [], failed: 0, inner: 0, batch: 0 };
}

export function addTx(shape, t) {
  if (!shape || !t) return shape;
  shape.n += 1;
  if (t.account) {
    shape.senders.add(t.account);
    shape.byAccount.set(t.account, (shape.byAccount.get(t.account) ?? 0) + 1);
    if (t.destination) {
      const set = shape.byAccountDest.get(t.account) ?? new Set();
      set.add(t.destination);
      shape.byAccountDest.set(t.account, set);
    }
  }
  if (t.destination) shape.destinations.add(t.destination);
  shape.byType.set(t.type, (shape.byType.get(t.type) ?? 0) + 1);
  if (t.fee > 0) shape.fees.push(t.fee);
  if (!t.success) shape.failed += 1;
  if (t.inner > 0) { shape.batch += 1; shape.inner += t.inner; }
  return shape;
}

// Form je Ledger als kompakte Messgröße (die Keys sind bewusst kurz: sie landen in der Tagesdatei).
export function finishShape(shape) {
  if (!shape || !shape.n) return null;
  // Zwei verschiedene Fächerungs-Messgrößen: das aktivste Konto nach Tx-Zahl (Burst) und das
  // Konto mit den meisten verschiedenen Empfängern (Fächer). Beides sind unterschiedliche
  // Angriffsnaturen und dürfen nicht vermischt werden.
  let topTxs = 0, topAccount = null, fanoutDests = 0, fanoutTxs = 0, fanoutAccount = null;
  for (const [acc, n] of shape.byAccount) {
    const dests = shape.byAccountDest.get(acc)?.size ?? 0;
    if (n > topTxs) { topTxs = n; topAccount = acc; }
    if (dests > fanoutDests) { fanoutDests = dests; fanoutTxs = n; fanoutAccount = acc; }
  }
  const countOf = (...types) => types.reduce((a, t) => a + (shape.byType.get(t) ?? 0), 0);
  return {
    n: shape.n,
    s: shape.senders.size,
    d: shape.destinations.size,
    fo: topTxs,                    // Tx des aktivsten Kontos
    fd: fanoutDests,               // verschiedene Empfänger des größten Fächers
    fa: fanoutTxs,
    ta: topTxs >= fanoutTxs ? topAccount : fanoutAccount,   // das verantwortliche Konto
    fl: shape.failed,
    ac: countOf("AccountCreate", "AccountDelete"),
    oc: countOf("OfferCreate", "OfferCancel"),
    nf: countOf("NFTokenCreateOffer", "NFTokenMint", "NFTokenAcceptOffer", "NFTokenCancelOffer"),
    bt: shape.batch,
    bi: shape.inner,
    fx: countOf("EnableAmendment", "SetFee", "UNLModify", "EnableFeature"),
    fm: shape.fees.length ? Math.max(...shape.fees) : 0,
    fs: median(shape.fees),
    types: Object.fromEntries([...shape.byType.entries()].sort((a, b) => b[1] - a[1]).slice(0, 12)),
  };
}

// Signatur je Ledger gegen die rollende Basis. base ist { tx:[], ac:[], oc:[], nf:[], fee:[], byType:{} }.
// Ohne ausreichende Basis: leere Signaturliste (kein Wert ohne Vergleich).
export function classifyShape(form, base, opts = {}) {
  const p = { ...TX_FORENSICS_DEFAULTS, ...opts };
  const out = [];
  if (!form || !form.n) return out;
  const ready = (Array.isArray(base?.tx) ? base.tx.length : 0) >= p.minBaseline;
  const medTx = median(base?.tx);
  const add = (tag, evidence) => out.push({ tag, evidence });

  if (form.fd >= p.fanoutMinAccounts && form.fa >= p.fanoutMinTxs) {
    add("drainer-fanout", { fanoutAccounts: form.fd, fanoutTxs: form.fa, ledgerTx: form.n });
  }
  if (form.fo >= p.burstMinTxs && form.n >= p.minTx && form.fo / form.n >= p.burstShare) {
    add("sender-burst", { accountTx: form.fo, ledgerTx: form.n, share: form.fo / form.n });
  }
  if (form.fl >= p.failureMin && form.fl / form.n >= p.failureShare) {
    add("failure-spike", { failed: form.fl, ledgerTx: form.n, share: form.fl / form.n });
  }
  if (form.bt >= p.batchMinTxs && form.bi >= p.batchInnerMin) {
    add("batch-amplify", { batchTx: form.bt, innerTx: form.bi });
  }
  if (form.fm >= p.feeMinDrops && form.fs > 0 && form.fm >= p.feeRatio * form.fs) {
    add("fee-spike", { maxFee: form.fm, medianFee: form.fs });
  }
  if (form.fx > 0) add("feature-change", { featureTx: form.fx });

  // Basis-abhängige Signaturen: erst mit Vergleichswert.
  if (ready) {
    if (form.ac >= p.createMin && form.ac >= p.createRatio * median(base.ac)) {
      add("account-create-burst", { count: form.ac, baseline: median(base.ac) });
    }
    if (form.oc >= p.offerMin && form.oc >= p.offerRatio * median(base.oc)) {
      add("offer-flood", { count: form.oc, baseline: median(base.oc) });
    }
    if (form.nf >= p.nftMin && form.nf >= p.nftRatio * median(base.nf)) {
      add("nft-spam", { count: form.nf, baseline: median(base.nf) });
    }
    if (medTx > 0 && form.n >= p.minTx && form.n >= p.typeRatio * medTx) {
      add(form.n >= 10 * medTx ? "load-extreme" : "load-spike", { ledgerTx: form.n, baseline: medTx, ratio: form.n / medTx });
    }
    for (const [type, n] of Object.entries(form.types ?? {})) {
      const b = median(base?.byType?.[type] ?? []);
      if (n >= p.typeMin && b > 0 && n >= p.typeRatio * b) add("type-burst:" + type, { count: n, baseline: b, ratio: n / b });
    }
  }
  return out;
}

// Zustandsbehalter für den Recorder: Form je offenes Ledger, rollende Basis, Sweep-Fenster.
// Alle Grenzen sind hart: ein Dauerlauf darf nie unbegrenzt wachsen (GitHub-Runner, 5 h).
export function createShapeTracker(opts = {}) {
  const p = { ...TX_FORENSICS_DEFAULTS, ...opts };
  const open = new Map();          // ledgerIndex -> shape
  const base = { tx: [], ac: [], oc: [], nf: [], fee: [], byType: new Map() };
  const swept = new Map();         // account -> { ledgers:Set<number>, destinations:Set<string> }
  const seenSweep = new Set();     // Sweep-Signaturen, die schon gemeldet wurden (je Konto)

  const shapeFor = (ledgerIndex) => open.get(ledgerIndex) ?? null;

  function addTxTo(ledgerIndex, msg) {
    const t = normalizeTx(msg);
    if (!t || !Number.isFinite(Number(ledgerIndex))) return null;
    const idx = Number(ledgerIndex);
    let shape = open.get(idx);
    if (!shape) {
      if (open.size > 64) { const oldest = [...open.keys()].sort((a, b) => a - b)[0]; open.delete(oldest); }
      shape = emptyShape();
      open.set(idx, shape);
    }
    return addTx(shape, t);
  }

  // Ledger abgeschlossen: Form fertig, Basis fortschreiben, Sweep-Fenster altern.
  function commit(ledgerIndex) {
    const shape = open.get(ledgerIndex);
    open.delete(ledgerIndex);
    const form = finishShape(shape);
    if (!form) return null;
    const push = (arr, v) => { arr.push(v); while (arr.length > p.baselineSize) arr.shift(); };
    push(base.tx, form.n);
    push(base.ac, form.ac);
    push(base.oc, form.oc);
    push(base.nf, form.nf);
    push(base.fee, form.fs);
    for (const [type, n] of Object.entries(form.types ?? {})) {
      if (!base.byType.has(type)) base.byType.set(type, []);
      push(base.byType.get(type), n);
    }
    for (const [type] of base.byType) if (!form.types?.[type]) push(base.byType.get(type), 0);
    while (base.byType.size > 80) { const first = base.byType.keys().next().value; base.byType.delete(first); }

    // Sweep-Fenster: ein Konto, das über mehrere Ledger hinweg immer neue Empfänger erreicht.
    // Das ist die Drainer-Form, die ein Einzel-Ledger-Fächer nicht zeigt.
    for (const [acc, n] of shape.byAccount) {
      const e = swept.get(acc) ?? { ledgers: new Set(), destinations: new Set(), txs: 0 };
      if (!e.ledgers.has(ledgerIndex)) { e.ledgers.add(ledgerIndex); e.txs += n; }
      for (const dst of shape.byAccountDest.get(acc) ?? []) e.destinations.add(dst);
      swept.set(acc, e);
    }
    const floor = ledgerIndex - p.sweepWindowLedgers;
    for (const [acc, e] of swept) {
      for (const l of e.ledgers) if (l < floor) e.ledgers.delete(l);
      if (!e.ledgers.size) swept.delete(acc);
    }
    while (swept.size > p.maxTrackedAccounts) { const first = swept.keys().next().value; swept.delete(first); }
    while (seenSweep.size > p.maxTrackedAccounts) { const first = seenSweep.values().next().value; seenSweep.delete(first); }

    let sweep = null;
    for (const [acc, e] of swept) {
      if (e.destinations.size >= p.sweepMinDestinations && e.ledgers.size >= 2 && !seenSweep.has(acc)) {
        seenSweep.add(acc);
        sweep = { sweepDestinations: e.destinations.size, sweepLedgers: e.ledgers.size, sweepTxs: e.txs };
        break;
      }
    }
    return { form, base: { tx: [...base.tx], ac: [...base.ac], oc: [...base.oc], nf: [...base.nf], fee: [...base.fee], byType: Object.fromEntries(base.byType) }, sweep };
  }

  return { addTxTo, commit, shapeFor, stats: () => ({ open: open.size, baseline: base.tx.length, tracked: swept.size }) };
}

// Die Signatur-Tags selbst (ohne das dynamische type-burst:<T> Präfix). Sie sind die SSOT dafür,
// welche Tags in die Risikovergleichsrechnung dürfen und welche das UI übersetzt.
export const SIGNATURE_TAGS = new Set([
  "drainer-fanout", "sender-burst", "failure-spike", "batch-amplify", "fee-spike", "feature-change",
  "account-create-burst", "offer-flood", "nft-spam", "sweep-window",
]);

// Signatur-Namen für UI/i18n (Tags sind die SSOT, Namen nur Anzeige).
export const SIGNATURE_LABELS = {
  "drainer-fanout": "Ein Konto fächert in diesem Ledger auf viele Empfänger",
  "sender-burst": "Ein Konto dominiert diesen Ledger",
  "failure-spike": "Überdurchschnittlich viele Transaktionen scheitern",
  "batch-amplify": "Batch-Tx verstärken die Last in diesem Ledger",
  "fee-spike": "Einzelne Transaktionen mit extrem hoher Gebühr",
  "feature-change": "Netzwerk-Ebene in diesem Ledger (Amendment/SetFee/UNL)",
  "account-create-burst": "Konten werden in diesem Ledger massenhaft angelegt oder gelöscht",
  "offer-flood": "Orderbuch-Flut in diesem Ledger",
  "nft-spam": "NFT-Aktivität weit über der Basis",
  "sweep-window": "Dasselbe Konto erreicht über mehrere Ledger immer neue Empfänger",
  "type-burst": "Ein Transaktionstyp weit über seiner eigenen Basis",
};
