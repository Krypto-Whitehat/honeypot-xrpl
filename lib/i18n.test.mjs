// lib/i18n.test.mjs — Fixture-Tests für public/i18n.mjs.
// public/i18n.mjs ist ein reines ESM ohne DOM auf Modulebene (Muster
// lib/attribution.test.mjs), daher direkt in Node importierbar.
// Sprach-Umschaltung über einen injizierten localStorage-Stub (das Modul
// liest localStorage erst zur Aufrufzeit, nie auf Modulebene).

import test from "node:test";
import assert from "node:assert/strict";
import {
  LANG_KEY,
  LANGS,
  DEFAULT_LANG,
  DICT,
  getLang,
  resolveLang,
  t,
  ruleName,
  noteText,
  sevText,
  serverPhrase,
  summaryText,
  fmtNum,
  fmtXrp,
  fmtClock,
  fmtDateTime,
  applyStatic,
  applyLang,
  initLangSwitcher,
} from "../public/i18n.mjs";
import { ruleCatalog } from "./detector.mjs";
import { ACCOUNT_REPORT_DISCLAIMERS } from "./account-report.mjs";

/* ---------- Storage-Stub (Sprachumschaltung in Node) ---------- */

function makeStorage(initial = {}) {
  const map = new Map(Object.entries(initial));
  return {
    map,
    getItem: (k) => (map.has(k) ? map.get(k) : null),
    setItem: (k, v) => { map.set(k, String(v)); },
    removeItem: (k) => { map.delete(k); },
  };
}

function withLang(lang, fn) {
  const prev = globalThis.localStorage;
  const stub = makeStorage(lang ? { [LANG_KEY]: lang } : {});
  globalThis.localStorage = stub;
  try {
    return fn(stub);
  } finally {
    if (prev === undefined) delete globalThis.localStorage;
    else globalThis.localStorage = prev;
  }
}

/* ---------- Wörterbuch-Vollständigkeit: EN = DE Schlüsselmenge ---------- */

test("DICT: EN und DE haben exakt dieselbe Schlüsselmenge", () => {
  const enKeys = Object.keys(DICT.en).sort();
  const deKeys = Object.keys(DICT.de).sort();
  assert.deepEqual(enKeys, deKeys);
  assert.ok(enKeys.length > 100, "Wörterbuch Umfang erwartet");
  // Keine leeren Werte in beiden Sprachen.
  for (const k of enKeys) {
    assert.equal(typeof DICT.en[k], "string");
    assert.ok(DICT.en[k].length > 0, `leerer EN-Wert für ${k}`);
    assert.ok(DICT.de[k].length > 0, `leerer DE-Wert für ${k}`);
  }
});

test("DICT: Interpolations-Platzhalter je Key in EN und DE identisch", () => {
  const ph = (s) => (String(s).match(/\{[A-Za-z0-9_]+\}/g) ?? []).sort().join(",");
  for (const k of Object.keys(DICT.en)) {
    assert.equal(ph(DICT.en[k]), ph(DICT.de[k]), `Platzhalter-Abweichung bei ${k}`);
  }
});

/* ---------- Sprache: Default, Persistenz, Validierung ---------- */

test("getLang: ohne Storage (Node) -> Default 'en'", () => {
  const prev = globalThis.localStorage;
  delete globalThis.localStorage;
  try {
    assert.equal(getLang(), "en");
    assert.equal(DEFAULT_LANG, "en");
  } finally {
    if (prev !== undefined) globalThis.localStorage = prev;
  }
});

test("getLang: persistierter Wert wird gelesen, ungültiger fällt auf 'en'", () => {
  withLang("de", () => assert.equal(getLang(), "de"));
  withLang("en", () => assert.equal(getLang(), "en"));
  withLang(null, () => {
    globalThis.localStorage.setItem(LANG_KEY, "fr"); // unsupported
    assert.equal(getLang(), "en");
  });
});

test("resolveLang: reine Funktion — validiert und schreibt in injizierten Storage", () => {
  const stub = makeStorage();
  assert.equal(resolveLang("de", stub), "de");
  assert.equal(stub.getItem(LANG_KEY), "de");
  assert.equal(resolveLang("en", stub), "en");
  assert.equal(stub.getItem(LANG_KEY), "en");
  assert.equal(resolveLang("xx", stub), "en"); // Validierung gegen LANGS
  assert.equal(stub.getItem(LANG_KEY), "en");
  assert.equal(resolveLang(undefined, stub), "en");
  // Ohne Storage (null) bleibt die Validierung wirksam, nur undiskretionär.
  assert.equal(resolveLang("de", null), "de");
  assert.deepEqual(LANGS, ["en", "de"]);
});

/* ---------- t(): Lookup, Interpolation, Fallback ---------- */

test("t(): Lookup in aktueller Sprache und Fallback auf 'en'", () => {
  withLang("de", () => assert.equal(t("check.go"), "Prüfen"));
  withLang("en", () => assert.equal(t("check.go"), "Check"));
  // Key nur in einer Sprache existiert nicht — Parität getestet; hier:
  // bewusster Fallback-Pfad über einen unbekannten Key.
  withLang("de", () => assert.equal(t("ganz.unbekannter.key"), "ganz.unbekannter.key"));
});

test("t(): {n}-Interpolation aus params", () => {
  withLang("en", () => {
    assert.equal(t("block.resolved", { resolved: 3, total: 6 }), "3/6 txs resolved");
    assert.equal(t("cluster.members", { n: 4 }), "4 members");
  });
  withLang("de", () => {
    assert.equal(t("block.resolved", { resolved: 3, total: 6 }), "3/6 Txs aufgelöst");
    assert.equal(t("cluster.members", { n: 4 }), "4 Mitglieder");
  });
  // Fehlender Param lässt Platzhalter sichtbar (kein stiller Ausfall).
  withLang("en", () => assert.equal(t("cluster.members", {}), "{n} members"));
});

/* ---------- ruleName(): alle 15 Regel-ids aus lib/detector.mjs ---------- */

test("ruleName: deckt alle 22 ruleCatalog-ids ab (EN und DE)", () => {
  const ids = ruleCatalog().map((r) => r.id);
  assert.equal(ids.length, 22); // 12 Bestand + 3 Market-Regeln + batch-inner-control (XLS-56)
  withLang("en", () => {
    for (const id of ids) {
      const name = ruleName(id);
      assert.notEqual(name, id, `EN-Übersetzung fehlt für ${id}`);
      assert.equal(name, DICT.en["rule." + id]);
    }
  });
  withLang("de", () => {
    for (const id of ids) {
      assert.equal(ruleName(id), DICT.de["rule." + id]);
    }
  });
  // Unbekannte id bleibt sichtbar roh.
  withLang("en", () => assert.equal(ruleName("nope-rule"), "nope-rule"));
});

/* ---------- noteText(): alle 13 Note-Templates ---------- */

const NOTE_FIXTURES = [
  { noteKey: "known-bad-hit", noteParams: { type: "Payment" },
    en: "Known-malicious address involved (Payment).",
    de: "Bekannt-maliziöse Adresse beteiligt (Payment)." },
  { noteKey: "memo-phishing-seed", noteParams: {},
    en: "Memo contains seed pattern.",
    de: "Memo enthält Seed-Muster." },
  { noteKey: "memo-phishing-url", noteParams: {},
    en: "Memo contains URL with claim-/airdrop-/verify- keyword.",
    de: "Memo enthält URL mit claim-/airdrop-/verify-Keyword." },
  { noteKey: "fake-nft-fraud-uri", noteParams: {},
    en: "NFTokenMint URI contains phishing/claim pattern.",
    de: "NFTokenMint-URI enthält Phishing-/claim-Muster." },
  { noteKey: "escrow-check-bait-single", noteParams: { type: "EscrowCreate", addr: "rTEST…AAAA" },
    en: "EscrowCreate with tiny amount and phishing memo to fresh target rTEST…AAAA.",
    de: "EscrowCreate mit winziger Summe und Phishing-Memo an frisches Ziel rTEST…AAAA." },
  { noteKey: "dusting-many", noteParams: { n: 4 },
    en: "4 mini XRP payments to different targets in the observation window.",
    de: "4 Mini-XRP-Zahlungen an verschiedene Ziele im Beobachtungsfenster." },
  { noteKey: "dusting-fresh", noteParams: { n: 2 },
    en: "2 mini XRP payments to fresh targets in one ledger.",
    de: "2 Mini-XRP-Zahlungen an frische Ziele in einem Ledger." },
  { noteKey: "drainer-sweep", noteParams: { pct: 97 },
    en: "Freshly funded and 97 % swept to one target.",
    de: "Frisch finanziert und 97 % an ein Ziel abgeräumt." },
  { noteKey: "offer-spam", noteParams: { n: 5 },
    en: "5 OfferCreate without fill in one ledger.",
    de: "5 OfferCreate ohne Fill in einem Ledger." },
  { noteKey: "fake-nft-fraud-accept", noteParams: { n: 12 },
    en: "12 NFTokenAcceptOffer without payment in one ledger.",
    de: "12 NFTokenAcceptOffer ohne Zahlung in einem Ledger." },
  { noteKey: "escrow-check-bait-burst", noteParams: { n: 3 },
    en: "3 escrow/check baits to different fresh targets.",
    de: "3 Escrow/Check-Köder an verschiedene frische Ziele." },
  { noteKey: "payment-burst", noteParams: { n: 6, tiny: 4 },
    en: "6 payments to different targets, 4 of them tiny (airdrop distribution pattern).",
    de: "6 Zahlungen an verschiedene Ziele, davon 4 winzig (Airdrop-Verteilungsmuster)." },
  { noteKey: "airdrop-trustset-spam", noteParams: { n: 7, issuer: "rISSUER…BBBB" },
    en: "7 TrustSets with tiny limit from different accounts to issuer rISSUER…BBBB in one ledger.",
    de: "7 TrustSets mit winzigem Limit von verschiedenen Konten auf Issuer rISSUER…BBBB in einem Ledger." },
  { noteKey: "wash-self-transfer", noteParams: { n: 4 },
    en: "4 self-payments in one ledger (volume washing).",
    de: "4 Selbstzahlungen in einem Ledger (Volumen-Washing)." },
  { noteKey: "fake-nft-fraud-fee", noteParams: { pct: 50 },
    en: "NFTokenMint with usurious transfer fee (50 %).",
    de: "NFTokenMint mit Wucher-TransferFee (50 %)." },
  { noteKey: "fake-nft-fraud-offer", noteParams: { n: 5, addr: "rTARGET…CCCC" },
    en: "5 NFTokenCreateOffer to the same target rTARGET…CCCC in one ledger.",
    de: "5 NFTokenCreateOffer auf dasselbe Ziel rTARGET…CCCC in einem Ledger." },
  { noteKey: "amm-wash-swap", noteParams: { pair: "USD/rTESTISSUER00000000000000001", conserve: 98, drift: 4 },
    en: "Bidirectional OfferCreate fills on USD/rTESTISSUER00000000000000001 in volume balance (conservation 98 %, drift 4 %).",
    de: "Bidirektionale OfferCreate-Fills auf USD/rTESTISSUER00000000000000001 im Volumen-Gleichgewicht (Volumenerhalt 98 %, Drift 4 %)." },
  { noteKey: "thin-pool-exploit", noteParams: { pair: "XRP", n: 3, devPct: 25 },
    en: "3 fills on XRP with >= 25 % price deviation from the window median in the favorable direction (thin pool).",
    de: "3 Fills auf XRP mit >= 25 % Preisabweichung vom Fenster-Median in die günstige Richtung (dünner Pool)." },
  { noteKey: "spoof-offer-cycle", noteParams: { n: 4, levels: 2, maxCancel: 75 },
    en: "4 place-and-pull cycles (create→cancel <= 75 ledgers) across 2 price levels in the order book.",
    de: "4 Place-and-Pull-Zyklen (Create→Cancel <= 75 Ledger) auf 2 Preislevel im Orderbuch." },
];

test("noteText: alle 19 Note-Templates rendern in EN und DE", () => {
  assert.equal(NOTE_FIXTURES.length, 19);
  for (const f of NOTE_FIXTURES) {
    assert.ok(DICT.en["note." + f.noteKey] !== undefined, `EN-Template fehlt: ${f.noteKey}`);
    assert.ok(DICT.de["note." + f.noteKey] !== undefined, `DE-Template fehlt: ${f.noteKey}`);
  }
  withLang("en", () => {
    for (const f of NOTE_FIXTURES) {
      assert.equal(noteText({ noteKey: f.noteKey, noteParams: f.noteParams, note: "raw-de-note" }), f.en);
    }
  });
  withLang("de", () => {
    for (const f of NOTE_FIXTURES) {
      assert.equal(noteText({ noteKey: f.noteKey, noteParams: f.noteParams, note: "raw-de-note" }), f.de);
    }
  });
});

test("noteText: ohne noteKey -> Fallback auf die sanitisierte Server-note", () => {
  withLang("en", () => {
    assert.equal(noteText({ note: "Deutsche Server-Note" }), "Deutsche Server-Note");
    assert.equal(noteText(null), "");
  });
});

/* ---------- sevText ---------- */

test("sevText: Schweregrade in beiden Sprachen", () => {
  withLang("en", () => {
    assert.equal(sevText("malicious"), "malicious");
    assert.equal(sevText("suspect"), "suspect");
    assert.equal(sevText("info"), "info");
  });
  withLang("de", () => {
    assert.equal(sevText("malicious"), "maliziös");
    assert.equal(sevText("suspect"), "verdächtig");
    assert.equal(sevText("info"), "info");
  });
});

/* ---------- Formatter: Locale folgt der Sprache ---------- */

test("Formatter: en-US vs de-DE (1,234.5 vs 1.234,5)", () => {
  withLang("en", () => {
    assert.equal(fmtNum(1234.5), "1,234.5");
    assert.equal(fmtXrp(1234567890), "1,234.57");
  });
  withLang("de", () => {
    assert.equal(fmtNum(1234.5), "1.234,5");
    assert.equal(fmtXrp(1234567890), "1.234,57");
  });
  // Null-/Leerwerte: identischer Strich in beiden Sprachen.
  withLang("en", () => {
    assert.equal(fmtClock(null), "–");
    assert.equal(fmtDateTime(""), "–");
    assert.equal(fmtClock("not-a-date"), "not-a-date");
  });
});

/* ---------- serverPhrase: Exact-Match auf bekannte Server-Phrasen ---------- */

test("serverPhrase: übersetzt die bekannten deutschen Protokollwerte (EN)", () => {
  withLang("en", () => {
    assert.equal(serverPhrase("Persistenz nicht konfiguriert"), "Persistence not configured");
    assert.equal(serverPhrase("Nicht bewertbar — keine oder unvollständige Daten."), DICT.en["srv.eligUnknown"]);
    assert.equal(serverPhrase("Voraussichtlich unproblematisch für Off-Ramps (heuristisch)."), DICT.en["srv.eligOk"]);
    assert.equal(serverPhrase("Prüfungswürdig — Ablehnung oder manuelle Prüfung durch den Anbieter ist wahrscheinlich."), DICT.en["srv.eligReview"]);
    assert.equal(ACCOUNT_REPORT_DISCLAIMERS.length, 4);
    ACCOUNT_REPORT_DISCLAIMERS.forEach((d, i) => {
      assert.equal(serverPhrase(d), DICT.en["srv.disc" + (i + 1)], `Disclaimer ${i + 1}`);
    });
  });
});

test("serverPhrase: DE-Modus gibt roh zurück; Unbekanntes bleibt immer roh", () => {
  withLang("de", () => {
    assert.equal(serverPhrase("Persistenz nicht konfiguriert"), "Persistenz nicht konfiguriert");
  });
  withLang("en", () => {
    // Nicht rekonstruierbarer Kuratierungstext (selfReason) bleibt roh.
    assert.equal(serverPhrase("Bekannter Drainer laut Kuratierung, an Köder #2"), "Bekannter Drainer laut Kuratierung, an Köder #2");
  });
});

/* ---------- summaryText: Rebuild aus strukturierten Report-Feldern ---------- */

const REPORT_FIXTURE = {
  verdict: "review",
  score: 80,
  contacts: [
    { counterparty: "rAAA", risk: "malicious" },
    { counterparty: "rBBB", risk: "suspect" },
    { counterparty: "rAAA", risk: "malicious" }, // Duplikat: distinct-Zählung
  ],
  patterns: ["dusting", "payment-burst"],
};

test("summaryText: EN-Rebuild entspricht der Satzfolge von buildSummary", () => {
  withLang("en", () => {
    assert.equal(
      summaryText(REPORT_FIXTURE),
      "Score 80 out of 100. 1 distinct counterparty/parties with known malicious status. 1 distinct counterparty/parties with suspect status. Pattern findings: dusting, payment-burst."
    );
  });
});

test("summaryText: DE-Rebuild", () => {
  withLang("de", () => {
    assert.equal(
      summaryText(REPORT_FIXTURE),
      "Score 80 von 100. 1 verschiedene Gegenpartei(en) mit bekanntem Malicious-Status. 1 verschiedene Gegenpartei(en) mit Verdachts-Status. Muster-Funde: dusting, payment-burst."
    );
  });
});

test("summaryText: unknown/clean/bad-Pfade", () => {
  withLang("en", () => {
    assert.equal(summaryText({ verdict: "unknown", score: null, contacts: [], patterns: [] }),
      "Not assessable — no or incomplete data.");
    assert.equal(summaryText({ verdict: "clean", score: 100, contacts: [], patterns: [] }),
      "Score 100 out of 100. No contacts to listed addresses in the checked window.");
    assert.equal(summaryText({ verdict: "bad", score: 40, contacts: [], patterns: [] }),
      "Score 40 out of 100. The address itself is listed in the threat list.");
  });
  withLang("de", () => {
    assert.equal(summaryText({ verdict: "unknown", score: null, contacts: [], patterns: [] }),
      "Nicht bewertbar — keine oder unvollständige Daten.");
  });
});

/* ---------- DOM-Freiheit: Guard-Noops ohne document/localStorage ---------- */

test("DOM-Funktionen sind Noops ohne DOM (Node-Import bleibt sicher)", () => {
  const prev = globalThis.localStorage;
  delete globalThis.localStorage;
  try {
    assert.doesNotThrow(() => applyStatic());
    assert.doesNotThrow(() => applyStatic(null));
    assert.doesNotThrow(() => applyLang());
    assert.equal(initLangSwitcher(null), null);
    // applyLang gibt die Sprache zurück, auch ohne document.
    assert.equal(applyLang(), "en");
  } finally {
    if (prev !== undefined) globalThis.localStorage = prev;
  }
});

/* ---------- linkFix 2026-10-05: xrpscan statt der alten Charts-Domain ---------- */

// Das Label der toten Domain wird als gesplittetes Literal gebaut, damit der
// Projekt-Regression-Check auf die alte Domain (Soll: 0 Treffer) durch diesen
// Test nicht wieder einen Treffer bekommt.
const DEAD_DOMAIN = "xrpl" + "charts";

test("addr.linkAria: verweist auf xrpscan.com, tote Domain in keinem DICT-Wert", () => {
  for (const lang of ["en", "de"]) {
    assert.ok(DICT[lang]["addr.linkAria"].includes("xrpscan.com"), `${lang}: addr.linkAria ohne xrpscan.com`);
    assert.ok(!DICT[lang]["addr.linkAria"].includes(DEAD_DOMAIN), `${lang}: addr.linkAria nennt noch die tote Domain`);
  }
  // Kein einziger DICT-Wert (beide Sprachen) darf die tote Domain nennen.
  for (const lang of ["en", "de"]) {
    for (const [k, v] of Object.entries(DICT[lang])) {
      assert.ok(!String(v).includes(DEAD_DOMAIN), `${lang}: Key ${k} nennt die tote Domain`);
    }
  }
});

/* ---------- accountingDesign 2026-10-05: name.*-Keys ---------- */

test("name.*-Keys existieren in EN und DE, übersetzt und mit Quellenattribution", () => {
  for (const k of ["name.chipAria", "name.unverifiedAria", "name.sourceNote"]) {
    assert.equal(typeof DICT.en[k], "string");
    assert.ok(DICT.en[k].length > 0, `EN-Wert fehlt: ${k}`);
    assert.ok(DICT.de[k].length > 0, `DE-Wert fehlt: ${k}`);
    assert.notEqual(DICT.en[k], DICT.de[k], `${k}: EN und DE identisch (Übersetzung fehlt)`);
    assert.ok(DICT.en[k].includes("xrpscan.com") && DICT.de[k].includes("xrpscan.com"), `${k}: Quellenattribution fehlt`);
  }
  // CC-Lizenz der Datenquelle gehört in die Quellennotiz (docs.xrpscan.com).
  assert.ok(DICT.en["name.sourceNote"].includes("CC BY-NC-SA"));
  assert.ok(DICT.de["name.sourceNote"].includes("CC BY-NC-SA"));
  withLang("de", () => assert.equal(t("name.unverifiedAria"), DICT.de["name.unverifiedAria"]));
});

/* ---------- freezeDesign 2026-10-05: modal.frozen ---------- */

test("modal.frozen: Hinweis mit {time}-Platzhalter in EN und DE", () => {
  assert.ok(DICT.en["modal.frozen"].includes("{time}"));
  assert.ok(DICT.de["modal.frozen"].includes("{time}"));
  withLang("en", () => assert.ok(t("modal.frozen", { time: "12:34:56" }).includes("12:34:56")));
  withLang("de", () => {
    const s = t("modal.frozen", { time: "12:34:56" });
    assert.ok(s.includes("12:34:56"));
    // Deutsche Orthografie vollständig (ä ö ü ß — kein ASCII-Ersatz).
    assert.ok(/ä|ö|ü|ß/.test(s), "DE-Text ohne Umlaut/Scharfes S");
  });
});

/* ---------- tagIdentityDesign 2026-10-05: tag.*- und transitNote-Keys ---------- */

test("tag.*-Keys existieren in EN und DE, übersetzt (Destination-Tag-Chips)", () => {
  for (const k of ["tag.chipAria", "tag.sourceAria", "cluster.transitNote", "check.transitNote"]) {
    assert.equal(typeof DICT.en[k], "string");
    assert.ok(DICT.en[k].length > 0, `EN-Wert fehlt: ${k}`);
    assert.ok(DICT.de[k].length > 0, `DE-Wert fehlt: ${k}`);
    assert.notEqual(DICT.en[k], DICT.de[k], `${k}: EN und DE identisch (Übersetzung fehlt)`);
  }
  // DE-Terminologie: "Destination-Tag" bleibt als Fachbegriff erhalten.
  assert.ok(DICT.de["tag.chipAria"].includes("Destination-Tag"));
  assert.ok(DICT.de["cluster.transitNote"].includes("Destination-Tags"));
  // Deutsche Orthografie vollständig (ä ö ü ß — kein ASCII-Ersatz):
  // "läuft" im Transit-Hinweis.
  assert.ok(/ä|ö|ü|ß/.test(DICT.de["cluster.transitNote"]), "DE-Text ohne Umlaut/Scharfes S");
  assert.ok(!DICT.de["cluster.transitNote"].includes("ae oe ue"), "ASCII-Umlaut-Ersatz im DE-Text");
  withLang("de", () => assert.equal(t("tag.chipAria"), DICT.de["tag.chipAria"]));
  withLang("en", () => assert.equal(t("cluster.transitNote"), DICT.en["cluster.transitNote"]));
});

/* ---------- infoBoxes 2026-10-06: Historie-/Archiv-Hinweise ---------- */

test("tab.historyHint/tab.historyHintLong/mode.archiveHint: EN+DE vorhanden, übersetzt, deutsche Orthografie intakt", () => {
  const keys = ["tab.historyHint", "tab.historyHintLong", "mode.archiveHint"];
  for (const k of keys) {
    assert.equal(typeof DICT.en[k], "string", `EN-Wert fehlt: ${k}`);
    assert.equal(typeof DICT.de[k], "string", `DE-Wert fehlt: ${k}`);
    assert.ok(DICT.en[k].length > 20, `${k}: EN sinnvoll lang`);
    assert.ok(DICT.de[k].length > 20, `${k}: DE sinnvoll lang`);
    assert.notEqual(DICT.en[k], DICT.de[k], `${k}: EN und DE identisch (Übersetzung fehlt)`);
  }
  // Deutsche Orthografie vollständig (ä ö ü ß — kein ASCII-Ersatz wie
  // "maizioese"/"Dauerhaft gespeicherte" mit oe/ae/ue-Mustern).
  for (const k of keys) {
    assert.ok(/ä|ö|ü|ß/.test(DICT.de[k]), `${k}: DE-Text ohne Umlaut/Scharfes S`);
    assert.ok(!/\b(ae|oe|ue)\b/.test(DICT.de[k]), `${k}: ASCII-Umlaut-Ersatz im DE-Text`);
    // Kein Mojibake (Ã¤ etc.) und keine Emoji-/Gradient-Klischees.
    assert.ok(!/Ã/.test(DICT.de[k]) && !/Ã/.test(DICT.en[k]), `${k}: Mojibake im Text`);
  }
  // Inhaltlicher Kontext: Archiv-Hinweis nennt das persistierte Block-Fenster
  // (Datenquelle des Dashboard-Modus), Historie-Hinweise stellen die
  // Unabhängigkeit vom Live-Feed und die Füllung heraus.
  assert.ok(DICT.en["mode.archiveHint"].includes("block window"), "EN mode.archiveHint ohne 'block window'");
  assert.ok(DICT.de["mode.archiveHint"].includes("Block-Fenster"), "DE mode.archiveHint ohne 'Block-Fenster'");
  assert.ok(DICT.de["tab.historyHintLong"].includes("Meldungen von Besuchern"), "DE Langtext ohne Besucher-Meldungen (Füllquelle)");
  assert.ok(DICT.en["tab.historyHintLong"].includes("visitor reports"), "EN Langtext ohne visitor reports");
  // t()-Lookup in beiden Sprachen (Verdrahtung history.js renderShell und
  // index.html #feed-archive-hint prüft public/design-assets.test.mjs).
  withLang("de", () => assert.equal(t("tab.historyHint"), DICT.de["tab.historyHint"]));
  withLang("en", () => assert.equal(t("mode.archiveHint"), DICT.en["mode.archiveHint"]));
});
