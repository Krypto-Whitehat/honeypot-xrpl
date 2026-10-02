// lib/rate-gate.mjs — reiner Token-Bucket-Ratenbegrenzer (pure ESM, DOM-frei).
//
// HINTERGRUND (honeycluster.io, Nutzer-Angabe 2026-10-02, live nicht bis zur
// Throttle-Grenze belastet — Semantik bei echtem Überschreiten UNVERIFIED):
//   10 req/s steady; 20 Requests sofort beim Start; Burst 50 req pro
//   5-Sekunden-Fenster; Burst-Fenster resettet nach 30 s Inaktivität.
// Der Bucket modelliert das konservativ: refill 10/s, Kapazität 50, Start 20.
//
// EINSATZ:
//   - Server: api/advance.js erwirbt pro RPC-Request (nicht pro Tick) —
//     Parallelität im Block-Fetch wird pro Request gekappt.
//   - Browser (Opt-in-LIVE, public/app.js): dieselbe Klasse via
//     api/lib-detector.js-Whitelist (rate-gate.mjs) — DOM-frei, keine
//     node:-Imports, keine ENV-Lesung.
//
// HARTE GRENZEN: pure ESM, KEINE npm-Imports, KEIN node:-Import, KEIN DOM,
// KEINE Secrets. Uhr ist injizierbar (now-Funktion) — Tests fahren eine
// Fake-Uhr; Produktion nutzt Date.now. Keine Netzwerkaufrufe hier — der Gate
// entscheidet nur, ob/wann ein Call des Aufrufers gehen darf.
//
// EXPORT-VERTRAG:
//   createRateGate({ ratePerSec = 10, burstCapacity = 50, initialTokens = 20, now })
//     -> { tryAcquire(n=1) -> {ok, waitMs}, acquire(n=1) -> Promise<void>,
//          available() -> number }
//   parseRetryAfterMs(value) -> number|null   (retry-after-Header: Sekunden
//     oder HTTP-Datum; Garbage -> null)

// retry-after-Header-Wert -> ms. HTTP-Seconds (Zahl) oder HTTP-Date
// ("Wed, 21 Oct 2015 07:28:00 GMT"); beides live-spec-konform. Garbage -> null.
export function parseRetryAfterMs(value) {
  if (value == null) return null;
  const s = String(value).trim();
  if (!s) return null;
  const secs = Number(s);
  if (Number.isFinite(secs)) {
    return secs >= 0 ? Math.floor(secs * 1000) : null;
  }
  const t = Date.parse(s);
  if (Number.isFinite(t)) {
    const delta = t - Date.now();
    return delta > 0 ? Math.floor(delta) : 0;
  }
  return null;
}

export function createRateGate(opts = {}) {
  const ratePerSec = positiveOr(opts.ratePerSec, 10);
  const burstCapacity = positiveOr(opts.burstCapacity, 50);
  const initialTokens = Math.min(positiveOr(opts.initialTokens, 20), burstCapacity);
  const now = typeof opts.now === "function" ? opts.now : () => Date.now();

  let tokens = initialTokens;
  let lastRefill = now();

  function positiveOr(v, dflt) {
    const n = Number(v);
    return Number.isFinite(n) && n > 0 ? n : dflt;
  }

  // Refill linear mit ratePerSec, gedeckelt auf burstCapacity.
  function refill() {
    const t = now();
    const elapsedMs = Math.max(0, t - lastRefill);
    if (elapsedMs > 0) {
      tokens = Math.min(burstCapacity, tokens + (elapsedMs / 1000) * ratePerSec);
      lastRefill = t;
    }
    return t;
  }

  // tryAcquire(n): Tokens vorhanden -> verbrauchen, {ok:true, waitMs:0}.
  // Sonst {ok:false, waitMs} — waitMs = Zeit bis n Tokens aufgefüllt sind
  // (bei n > burstCapacity unmöglich -> Number.POSITIVE_INFINITY).
  function tryAcquire(n = 1) {
    const k = Math.max(1, Math.floor(Number(n) || 1));
    refill();
    if (k > burstCapacity) return { ok: false, waitMs: Number.POSITIVE_INFINITY };
    if (tokens >= k) {
      tokens -= k;
      return { ok: true, waitMs: 0 };
    }
    const waitMs = Math.ceil(((k - tokens) / ratePerSec) * 1000);
    return { ok: false, waitMs };
  }

  // acquire(n): wartet (setTimeout) bis der Gate die n Tokens freigibt.
  // Ein extern gesetztes Warte-Fenster (z. B. retry-after nach HTTP 429)
  // entwertet den Token-Vorrat bis zu diesem Zeitpunkt — der Caller muss
  // den Gate nicht selbst nachfüllen.
  async function acquire(n = 1) {
    for (;;) {
      const r = tryAcquire(n);
      if (r.ok) return;
      if (!Number.isFinite(r.waitMs)) {
        throw new Error("rate-gate: Anfrage übersteigt die Burst-Kapazität.");
      }
      await new Promise((res) => setTimeout(res, r.waitMs));
    }
  }

  // Aktuelles Token-Konto (nach Refill) — für Tests und ehrliche Diagnose.
  function available() {
    refill();
    return tokens;
  }

  return { tryAcquire, acquire, available };
}
