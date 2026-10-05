// public/name-index.test.mjs — Contract-Tests für die Client-Seite der
// XRPScan-Namensauflösung. Injizierter globalThis.fetch-Stub (das Modul holt
// fetch erst zur Aufrufzeit über globalThis — Muster public/i18n.test.mjs mit
// localStorage-Stub). Prüft: GENAU EIN Bulk-Fetch pro Session (In-Flight-
// Guard + TTL), Fail-closed ohne Retry-Loop, Einzel-Konto-Cache mit Cap 200
// und TTL 24 h, AbortController-Signal an jedem Fetch. Alle Adressen
// synthetisch (rTEST…); es wird kein echter Endpunkt getroffen.
//
// Testreihenfolge ist bewusst: erst die Fail-closed-Pfade OHNE guten Stand
// (bulkMap null), dann der erfolgreiche Bulk (danach greift der TTL-Guard —
// ensureNameIndex fetcht innerhalb von 6 h nie wieder), dann der
// Fail-closed-mit-gutem-Stand-Nachweis über einen gesetzten Zeit-Offset
// (TTL abgelaufen -> Fetch versucht -> Fehler -> letzter guter Stand bleibt).

import test from "node:test";
import assert from "node:assert/strict";
import {
  ensureNameIndex,
  nameIndexOf,
  lookupNameCached,
  lookupAccountName,
  mergeWithFallback,
  NAME_INDEX_TTL_MS,
  ACCOUNT_TTL_MS,
  ACCOUNT_CACHE_MAX,
} from "./name-index.mjs";

const BULK_URL = "https://api.xrpscan.com/api/v1/names/well-known";
const ACCOUNT_BASE = "https://api.xrpscan.com/api/v1/account/";

// Synthetische Bulk-Antwort im XRPScan-Format (Felder name/desc/account/
// domain/twitter/verified). Adressen Base58-gültig (ohne 0/O/I/l).
const A1 = "rTESTexchangeAccount11111111";
const A2 = "rTESTsecondAccount2222222222";
const BULK_FIXTURE = [
  { account: A1, name: "Test Exchange One", domain: "testone.example", verified: true },
  { account: A2, name: "Test Exchange Two" },
];

/* ---------- fetch-Stub (Aufrufzähler + Response-Kontrolle) ---------- */

let fetchCalls = []; // { url, opts }
let bulkResponder = () => ({ ok: true, json: async () => BULK_FIXTURE });
let accountResponder = () => ({ ok: false });

function installFetch() {
  const prev = globalThis.fetch;
  globalThis.fetch = async (url, opts) => {
    fetchCalls.push({ url: String(url), opts });
    if (String(url) === BULK_URL) return bulkResponder();
    if (String(url).startsWith(ACCOUNT_BASE)) return accountResponder();
    throw new Error("unexpected fetch url: " + url);
  };
  return () => {
    if (prev === undefined) delete globalThis.fetch;
    else globalThis.fetch = prev;
  };
}

function resetStubs() {
  fetchCalls = [];
  bulkResponder = () => ({ ok: true, json: async () => BULK_FIXTURE });
  accountResponder = () => ({ ok: false });
}

const bulkCount = () => fetchCalls.filter((c) => c.url === BULK_URL).length;
const accountCount = () => fetchCalls.filter((c) => c.url.startsWith(ACCOUNT_BASE)).length;

// Zeit-Offset für TTL-Ablauf-Tests: das Modul ruft Date.now() zur Aufrufzeit;
// der Stub verschiebt nur die Wahrnehmung, der finally stellt her.
async function withTimeOffset(offsetMs, fn) {
  const realNow = Date.now;
  const base = realNow();
  Date.now = () => base + offsetMs;
  try {
    return await fn();
  } finally {
    Date.now = realNow;
  }
}

/* ---------- Konstanten des Plans ---------- */

test("Konstanten: Bulk-TTL 6 h, Einzel-TTL 24 h, Cache-Cap 200", () => {
  assert.equal(NAME_INDEX_TTL_MS, 6 * 60 * 60 * 1000);
  assert.equal(ACCOUNT_TTL_MS, 24 * 60 * 60 * 1000);
  assert.equal(ACCOUNT_CACHE_MAX, 200);
});

/* ---------- Fail-closed OHNE guten Stand: leere Map, kein Retry-Loop ---------- */

test("Fail-closed ohne Stand: HTTP-Fehler, Wurf und Parse-Fehler liefern die leere Map", async () => {
  const restore = installFetch();
  try {
    resetStubs();
    bulkResponder = () => ({ ok: false, status: 500 });
    const m1 = await ensureNameIndex();
    assert.ok(m1 instanceof Map);
    assert.equal(m1.size, 0);
    assert.equal(bulkCount(), 1);

    bulkResponder = () => { throw new Error("netz weg"); };
    const m2 = await ensureNameIndex();
    assert.equal(m2.size, 0);
    assert.equal(bulkCount(), 2); // nur der explizite Aufruf — kein versteckter Retry

    bulkResponder = () => ({ ok: true, json: async () => { throw new Error("kaputtes JSON"); } });
    const m3 = await ensureNameIndex();
    assert.equal(m3.size, 0);
    assert.equal(bulkCount(), 3);

    assert.equal(nameIndexOf(A1), null); // kein Stand -> kein Lookup-Ergebnis
  } finally {
    restore();
  }
});

/* ---------- GENAU EIN Bulk-Fetch (In-Flight-Guard + TTL) ---------- */

test("ensureNameIndex: parallele und sequentielle Aufrufe erzeugen GENAU EINEN Bulk-Fetch", async () => {
  const restore = installFetch();
  try {
    resetStubs();
    const [a, b, c] = await Promise.all([ensureNameIndex(), ensureNameIndex(), ensureNameIndex()]);
    const d = await ensureNameIndex();
    assert.equal(bulkCount(), 1, "In-Flight-Guard + TTL: genau ein Bulk-Fetch");
    for (const m of [a, b, c, d]) {
      assert.ok(m instanceof Map);
      assert.equal(m.get(A1).name, "Test Exchange One");
    }
    // Fetch-Contract: AbortController-Signal + no-store (kein Browser-Cache).
    const call = fetchCalls.find((c2) => c2.url === BULK_URL);
    assert.ok(call.opts && call.opts.signal, "AbortController-Signal fehlt");
    assert.equal(call.opts.cache, "no-store");
  } finally {
    restore();
  }
});

test("TTL: weitere ensureNameIndex-Aufrufe innerhalb von 6 h fetchen nie erneut", async () => {
  const restore = installFetch();
  try {
    resetStubs();
    const m = await ensureNameIndex();
    assert.equal(bulkCount(), 0, "TTL-Guard: kein Fetch, Bulk-Stand besteht");
    assert.equal(m.get(A1).name, "Test Exchange One");
  } finally {
    restore();
  }
});

test("nameIndexOf/lookupNameCached: synchroner Lookup gegen den Bulk-Stand", () => {
  // Bulk-Stand besteht aus dem erfolgreichen Fetch weiter oben (Modul-Singleton).
  assert.equal(nameIndexOf(A1).name, "Test Exchange One");
  assert.equal(nameIndexOf(A2).verified, false);
  assert.equal(nameIndexOf("rTESTunbekannt11111111111111"), null);
  assert.equal(nameIndexOf(null), null);
  assert.equal(lookupNameCached(""), null);
  assert.equal(lookupNameCached(A1).name, "Test Exchange One");
});

/* ---------- Fail-closed MIT gutem Stand: letzter guter Stand bleibt ---------- */

test("Fail-closed mit Stand: TTL abgelaufen + Fehler -> letzter guter Stand bleibt erhalten", async () => {
  const restore = installFetch();
  try {
    resetStubs();
    await withTimeOffset(NAME_INDEX_TTL_MS + 1000, async () => {
      bulkResponder = () => ({ ok: false, status: 503 });
      const m1 = await ensureNameIndex();
      assert.equal(bulkCount(), 1); // TTL abgelaufen -> Fetch versucht
      assert.equal(m1.get(A1).name, "Test Exchange One"); // guter Stand bleibt

      bulkResponder = () => { throw new Error("netz weg"); };
      const m2 = await ensureNameIndex();
      assert.equal(bulkCount(), 2);
      assert.equal(m2, m1); // identische Map-Instanz = unveränderter Stand
      // Kein Retry-Loop: jeder weitere Fetch entsteht nur durch einen
      // expliziten Aufruf (genau einer pro Aufruf), nie automatisch.
      const m2b = await ensureNameIndex();
      assert.equal(bulkCount(), 3);
      assert.equal(m2b, m1);
    });
  } finally {
    restore();
  }
});

/* ---------- Einzel-Konto-Ergänzung (nur im Check-Pfad, Cap 200, TTL 24 h) ---------- */

test("lookupAccountName: Fetch, Parset und cacht; zweiter Lookup ohne neuen Fetch", async () => {
  const restore = installFetch();
  try {
    resetStubs();
    const A9 = "rTESTkontoNeun99999999999999"; // Base58-gültig (kein l/I/O/0)
    accountResponder = () => ({
      ok: true,
      json: async () => ({ accountName: { name: "EinzelKonto Neun", domain: "neun.example", verified: true } }),
    });
    const e1 = await lookupAccountName(A9);
    assert.equal(e1.name, "EinzelKonto Neun");
    assert.equal(e1.verified, true);
    assert.equal(bulkCount(), 0, "Einzel-Pfad löst keinen Bulk-Fetch aus");
    assert.equal(accountCount(), 1);
    assert.ok(fetchCalls[0].opts.signal, "AbortController-Signal fehlt");

    // Cache: zweiter Aufruf ohne Fetch, lookupNameCached sieht den Eintrag.
    const e2 = await lookupAccountName(A9);
    assert.equal(e2.name, "EinzelKonto Neun");
    assert.equal(accountCount(), 1);
    assert.equal(lookupNameCached(A9).name, "EinzelKonto Neun");
  } finally {
    restore();
  }
});

test("lookupAccountName: Fehler und unbrauchbare Antworten liefern null ohne Cache", async () => {
  const restore = installFetch();
  try {
    resetStubs();
    const A8 = "rTESTcheckAccount8888888888"; // Base58-gültig (kein l/I/O/0)
    accountResponder = () => ({ ok: false, status: 404 });
    assert.equal(await lookupAccountName(A8), null);
    assert.equal(lookupNameCached(A8), null); // nichts gecacht

    accountResponder = () => ({ ok: true, json: async () => ({}) }); // kein accountName
    assert.equal(await lookupAccountName(A8), null);

    accountResponder = () => { throw new Error("netz weg"); };
    assert.equal(await lookupAccountName(A8), null);

    // Ungültige Adresse wird nie abgefragt (Base58-Vorprüfung im Modul):
    assert.equal(await lookupAccountName("rkurz"), null);
    assert.equal(await lookupAccountName("rTESTinvalid0OIl1111111111111"), null);
    assert.equal(accountCount(), 3);
    assert.equal(await lookupAccountName(""), null);
    assert.equal(await lookupAccountName(null), null);
    assert.equal(accountCount(), 3);
  } finally {
    restore();
  }
});

test("lookupAccountName: Cache-Deckel 200 — ältester Eintrag fällt (FIFO)", async () => {
  const restore = installFetch();
  try {
    resetStubs();
    accountResponder = () => ({ ok: true, json: async () => ({ accountName: { name: "Cap-Konto" } }) });
    const addrs = [];
    for (let i = 0; i < ACCOUNT_CACHE_MAX + 2; i++) {
      // Eindeutige Base58-Adressen: feste 4-stellige Basis-9-Codierung,
      // Ziffern 1-9 (0 verboten), Füllzeichen 9.
      const code = (i + 1).toString(9).padStart(4, "0").split("").map((d) => String(Number(d) + 1)).join("");
      addrs.push("rTESTcapacct" + code + "9".repeat(12));
    }
    for (const a of addrs) {
      const e = await lookupAccountName(a);
      assert.equal(e.name, "Cap-Konto");
    }
    // Die ersten zwei sind aus dem Cache geflogen, die letzten sind drin.
    assert.equal(lookupNameCached(addrs[0]), null);
    assert.equal(lookupNameCached(addrs[1]), null);
    assert.equal(lookupNameCached(addrs[2]).name, "Cap-Konto");
    assert.equal(lookupNameCached(addrs[addrs.length - 1]).name, "Cap-Konto");
  } finally {
    restore();
  }
});

/* ---------- Merge-Helfer ---------- */

test("mergeWithFallback: Bulk-Stand schlägt statische Fallback-Map", async () => {
  const restore = installFetch();
  try {
    // TTL gültig: kein neuer Fetch, der Bulk-Stand wird nur gelesen.
    const bulk = await ensureNameIndex();
    assert.equal(bulkCount(), 0);
    const fallbackKey = "rTESTnurFallback111111111111";
    const fallback = new Map([[A1, { name: "Registry-Name" }], [fallbackKey, { name: "Nur Fallback" }]]);
    const merged = mergeWithFallback(bulk, fallback);
    assert.equal(merged.get(A1).name, "Test Exchange One"); // Bulk gewinnt
    assert.equal(merged.get(fallbackKey).name, "Nur Fallback");
  } finally {
    restore();
  }
});
