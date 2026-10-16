// public/validator-trace.mjs — Validator-Trace-Overlay (lazy geladen aus live-monitor.mjs).
// Ein Validator: Karten, 3D-Abweichungsprofil, Retrace-Diagnose je Ledger, Risikoprofil,
// Korrelationen und Zeitleiste. Musterblick: wiederkehrende Muster und Sammelereignisse
// über alle dUNL-Validatoren.
// Alle Inhalte laufen durch h.esc; Schlüssel werden gekürzt angezeigt.
//
// 3D ist CSS-Geometrie (kein WebGL, keine neue Abhängigkeit). Je Zeitintervall ein Prisma aus
// Vorder-, Seiten- und Deckelfläche, gestapelt nach Vorfallstyp. Der Tiefenvektor ist (+d, -dz);
// Seitenfläche skewY, Deckelfläche skewX mit demselben Winkel, damit die Kanten zusammenlaufen
// (tan 41° ≈ dz/d). Balkenhöhe und Achse teilen sich ein Maß: --u = Plot-Höhe / Achsenmaximum,
// ein Balken mit --n Vorfällen ist deshalb zwingend so hoch, wie die Gitterlinie bei n sagt.
const RANGES = ["1h", "24h", "7d", "all"];
const BUCKETS = 24;
const AXIS_TICKS = [0, 6, 12, 18];
const PROFILE_TYPES = ["missed", "partial", "wrongHash", "noQuorum"];
const TYPE_KEY = { missed: "missed", partial: "partial", "wrong-hash": "wrongHash", "no-quorum": "noQuorum" };
const SPAN_MS = { "1h": 3600000, "24h": 86400000, "7d": 7 * 86400000, all: null };
const RETRACE_SHOWN = 12;
const RISK_ROWS = 12;

// Kohorten-Breite eines Intervalls -> Stufe für Grundriss-Farbe und Kohortenstreifen.
// NETZ_AB ist dieselbe Schwelle wie RETRACE_DEFAULTS.attackMinValidators in der
// Retrace-Engine: dasselbe Wort "Netzereignis" muss an beiden Stellen dasselbe meinen,
// sonst widersprechen sich Profil und Diagnose.
const NETZ_AB = 5;
// Intervall-Zustande fur Grundriss, Kohortenstreifen und Legende. clean und none kommen aus der
// gemessenen Ledger-Abdeckung, solo/cohort/network/unknown aus der Kohorten-Breite.
const STATES = ["clean", "solo", "cohort", "network", "unknown", "none"];
// Signaturstreifen: gemessene Transaktions-Signatur / beobachtet ohne Signatur / Ebene nicht
// erfasst / Intervall nicht beobachtet.
const SIGN_STATES = ["hit", "clear", "unknown", "none"];

// null/undefined = für dieses Ledger ist die Betroffenheit nicht aufgezeichnet (Tage vor
// der Forensik-Stufe). Das ist NICHT "solo": solo ist eine Messung, unknown eine Lücke.
export function breadthOf(cohort) {
  if (!Number.isFinite(cohort)) return "unknown";
  if (cohort >= NETZ_AB) return "network";
  if (cohort >= 2) return "cohort";
  return "solo";
}

// Korrelations-Tag -> lesbare Bezeichnung (Übersetzung, sonst Rohname; nie eine erfundene Ursache).
export function tagLabel(h, tag) {
  const base = String(tag).split(":")[0];
  const key = "vt.tag." + base;
  const txt = h.t(key);
  if (!txt || txt === key) return String(tag);
  // new-tx-type:<TYP> und type-burst:<TYP> tragen den Typ im Tag - ohne ihn waere die Anzeige
  // eine allgemeine Floskel ohne den eigentlichen Transaktionstyp.
  return base === "new-tx-type" || base === "type-burst" ? txt + " " + String(tag).slice(base.length + 1) : txt;
}

// Achsenmaß: peak ist ein Vielfaches von step, und es entstehen höchstens 5 Gitterintervalle.
export function axisScale(max) {
  const m = Math.max(1, max);
  for (const s of [1, 2, 5, 10, 20, 25, 50, 100, 200, 250, 500, 1000, 2000, 5000]) {
    const peak = Math.ceil(m / s) * s;
    if (peak / s <= 5) return { peak, step: s };
  }
  const s = Math.ceil(m / 5);
  return { peak: s * 5, step: s };
}

// Achsenposition eines Wertes, in Achseneinheiten (peak entspricht --peak / 100 %).
//
// Die Skala ist quadratwurzel-bezogen, weil die Vorfall-Zahlen ueber ein Fenster extrem schief
// liegen: 4.502 Abweichungen in einem Intervall neben 1 in einem anderen. Linear waere das
// Intervall mit 1 ein 0,03-px-Streifen - unsichtbar, und das Profil wirkte leer, obwohl etwas
// gemessen wurde (gemessen am 2026-10-16 live: peak 5000, Hoehen 0,03 / 0,06 / 4,53 / 138 / 158 px).
// sqrt erhaelt die Reihenfolge und die Vergleiche zwischen Intervallen, macht kleine Werte aber
// sichtbar; die Gitterlinien bleiben die wahren Zahlen, nur ihre Abstaende folgen derselben Skala.
// Die Abbildung selbst ist ohne Untergrenze: sonst werden 1 und 2 auf derselben Hoehe gleich
// (eine flache Stelle in einer Skala, die vergleichen soll). Die Sichtbarkeit kleiner Werte ist
// eine Rendering-Regel und steht in CSS (--bh, max 2 px fur nicht-leere Saulen); die Achse bleibt
// exakt. Die wahren Zahlen stehen in Readout und aria-label.
//
// Die Wurzel-Skala gilt ab peak 50. Darunter ist sie eine Verschlechterung: gemessen
// 2026-10-16 (7-Tage-Fenster, peak 4, Plot-Hoehe 176 px) standen 1 / 2 / 3 / 4 Vorfaelle auf
// 88,0 / 124,4 / 152,4 / 176,0 px - ein einziger Vorfall auf der halben Plot-Hoehe, die
// Stufen auf 36 px zusammengeschoben, und das Profil las sich als Kamm lauter halbhher Saeulen.
// Linear sind es 44,0 / 88,0 / 132,0 / 176,0 px: jede Stufe genau ein Gitterintervall.
// Die Schwelle ist nachgerechnet, nicht gefuehlt: linear bleibt sichtbar, solange plotH / peak
// nicht unter die Kanten-Untergrenze faellt (176 / 50 = 3,52 px). Ab peak 150 waere ein
// Vorfall linear 1,17 px (unsichtbar, 2-px-Untergrenze griffe fuer fast jede Saeule) - dort
// ist die Wurzel noetig (14,43 px).
export const LINEAR_PEAK = 50;

export function axisUnit(value, peak) {
  const v = Number(value) || 0;
  const p = Math.max(1, Number(peak) || 1);
  if (v <= 0) return 0;
  if (p <= LINEAR_PEAK) return Math.min(v, p);
  return p * Math.sqrt(v / p);
}

export function createValidatorTrace(h) {
  let overlay = null;
  const tl = (tag) => tagLabel(h, tag);
  let current = { mode: "validator", master: null, title: "", range: "24h" };

  const num = (v) => (Number.isFinite(Number(v)) ? String(Number(v)) : "–");
  const sec = (ms) => (Number.isFinite(ms) ? (Math.round(ms / 100) / 10).toFixed(1) : "–");
  const fac = (r) => (Number.isFinite(r) ? (Math.round(r * 10) / 10).toFixed(1) : "–");
  // Nach einer Nachkommastelle kollabiert eine seltene Rate auf 0,0 % - eigene Rate, Median
  // und Netzmittel waeren dann ununterscheidbar. Unter 0,05 % auf zwei gueltige Ziffern.
  const pc = (v) => {
    if (!Number.isFinite(v)) return "–";
    if (v !== 0 && Math.abs(v) < 0.05) {
      return (Math.abs(v) < 1e-4 ? "< " + (1e-4).toFixed(4) : v.toPrecision(2)) + " %";
    }
    return (Math.round(v * 10) / 10).toFixed(1) + " %";
  };
  // Prozentzahl ohne Einheit: für Sätze, in denen das Prozentzeichen in der Übersetzung steht
  // (und damit je Sprache an anderer Stelle sitzen darf).
  const pcn = (v) => (Number.isFinite(v) ? (Math.round(v * 10) / 10).toFixed(1) : "–");
  const stamp = (ms) => (Number.isFinite(ms) ? new Date(ms).toISOString().replace("T", " ").slice(0, 19) : "–");
  // Dauer einer Serie: Sekunden, Minuten oder Stunden - die Serie ist eine Zeit-Aussage, eine
  // Ledger-Zahl allein waere dafuer zu abstrakt.
  const dur = (ms) => {
    if (!Number.isFinite(ms) || ms < 0) return "–";
    const s = Math.round(ms / 1000);
    if (s < 60) return s + " s";
    const m = Math.round(s / 60);
    if (m < 60) return m + " min";
    return Math.floor(m / 60) + " h " + (m % 60) + " min";
  };
  // Die Diagnose-Engine nennt Typen in camelCase, die Uebersetzung fuehrt sie in kebab-case.
  const DIAG_TYPE = { missed: "missed", partial: "partial", wrongHash: "wrong-hash", noQuorum: "no-quorum" };

  // Kohorten-Zahl lesbar machen. Ohne Messung steht die Lücke da, nicht "0" – eine 0 wäre
  // die Aussage "kein anderer Validator", die aus Altdaten nicht folgt.
  const cohortText = (c) => (Number.isFinite(c) ? h.t("vt.cohortCount", { n: c }) : h.t("vt.cohortUnknown"));

  function close() {
    if (overlay) { overlay.remove(); overlay = null; }
    document.removeEventListener("keydown", onKey);
  }
  function onKey(e) { if (e.key === "Escape") close(); }

  function ensureOverlay() {
    if (overlay) return overlay;
    overlay = document.createElement("div");
    overlay.className = "vt-overlay";
    overlay.innerHTML = '<div class="vt-panel" role="dialog" aria-modal="true" aria-labelledby="vt-title">'
      + '<header class="vt-head"><h2 id="vt-title"></h2><button type="button" class="vt-close" id="vt-close">' + h.esc(h.t("vt.close")) + "</button></header>"
      + '<div class="vt-tabs" role="group" id="vt-range"></div>'
      + '<div class="vt-body" id="vt-body" aria-live="polite"></div>'
      + '<p class="vt-note">' + h.esc(h.t("vt.note")) + "</p></div>";
    overlay.addEventListener("click", (e) => { if (e.target === overlay) close(); });
    overlay.querySelector("#vt-close").addEventListener("click", close);
    document.body.appendChild(overlay);
    document.addEventListener("keydown", onKey);
    return overlay;
  }

  function renderRangeTabs() {
    const box = overlay.querySelector("#vt-range");
    box.innerHTML = RANGES.map((r) => '<button type="button" class="vt-tab" data-range="' + r + '" aria-pressed="' + (r === current.range) + '">' + h.esc(h.t("vt.range." + r)) + "</button>").join("");
    box.querySelectorAll("[data-range]").forEach((b) => b.addEventListener("click", () => { current.range = b.dataset.range; load(); }));
    box.hidden = current.mode !== "validator" && current.mode !== "patterns";
  }

  async function load() {
    ensureOverlay();
    renderRangeTabs();
    const body = overlay.querySelector("#vt-body");
    body.textContent = h.t("vt.loading");
    const q = current.mode === "patterns" ? "patterns=1&range=" + current.range : "master=" + encodeURIComponent(current.master) + "&range=" + current.range;
    try {
      const res = await fetch("/api/validator-trace?" + q, { cache: "no-store" });
      if (!res.ok) throw new Error("HTTP " + res.status);
      const data = await res.json();
      if (data.available === false) { body.innerHTML = '<p class="vt-empty">' + h.esc(h.t("vt.unavailable")) + "</p>"; return; }
      if (current.mode === "patterns") renderPatterns(body, data); else renderValidator(body, data);
      wire(body);
    } catch {
      body.innerHTML = '<p class="vt-empty">' + h.esc(h.t("vt.error")) + "</p>";
    }
  }
  function renderValidator(body, d) {
    overlay.querySelector("#vt-title").textContent = current.title;
    // xrpscan-Referenz (Agreement-Scores aus der Liste) + Master-Key, damit klar ist,
    // WELCHER Validator mit WELCHER Referenzmetrik untersucht wird.
    const ref = current.ref;
    const refLine = ref && (ref.a1h || ref.a24h || ref.a30d)
      ? '<p class="vt-ref"><small>' + h.esc(h.t("vt.ref")) + "</small> "
        + "1 h " + h.esc(ref.a1h || "–") + " · 24 h " + h.esc(ref.a24h || "–") + " · 30 d " + h.esc(ref.a30d || "–") + "</p>"
      : "";
    const keyLine = '<p class="vt-key-full"><small>' + h.esc(h.t("vt.master")) + "</small> " + h.esc(d.master || current.master || "") + "</p>";
    // Aufzeichnungs-Deckung: wieviele Ledger wurden beobachtet, über welche Spanne,
    // wieviele Lücken-Ledger. Macht sichtbar, WAS überhaupt untersucht wurde.
    const c = d.coverage || {};
    const span = c.firstMs && c.lastMs
      ? new Date(c.firstMs).toISOString().slice(5, 16).replace("T", " ") + " – " + new Date(c.lastMs).toISOString().slice(5, 16).replace("T", " ") + " UTC"
      : "–";
    const coverageLine = '<p class="vt-coverage"><small>' + h.esc(h.t("vt.coverage")) + "</small> "
      + h.esc(h.t("vt.coverageVal", { ledgers: c.ledgers ?? 0, days: c.days ?? 0, span, gaps: c.gapLedgers ?? 0, qf: c.quorumFail ?? 0 })) + "</p>";
    // Fenster-genaue Karten (Stundenzähler), sonst Tages-Gesamtzähler mit Hinweis.
    const w = d.inWindow;
    const src = w || d.summary;
    const scopeTag = w
      ? '<p class="vt-scope"><small>' + h.esc(h.t("vt.inWindow")) + (w.estimated ? " · " + h.esc(h.t("vt.estimated")) : "") + "</small></p>"
      : '<p class="vt-scope"><small>' + h.esc(h.t("vt.totals")) + "</small></p>";
    const cards = [["ok", src.ok], ["partial", src.partial], ["missed", src.missed], ["no-quorum", src.noQuorum ?? 0], ["wrong-hash", src.wrongHash], ["observed", src.observed]]
      .map(([k, v]) => '<div class="vt-card vt-' + k + '"><small>' + h.esc(h.t("vt.k." + k)) + "</small><b>" + h.esc(String(v)) + "</b></div>").join("");
    const totalLine = w
      ? '<p class="vt-scope"><small>' + h.esc(h.t("vt.totals")) + "</small> ok " + h.esc(String(d.summary.ok)) + " · " + h.esc(h.t("vt.k.missed")) + " " + h.esc(String(d.summary.missed)) + " · " + h.esc(h.t("vt.k.no-quorum")) + " " + h.esc(String(d.summary.noQuorum ?? 0)) + " · " + h.esc(h.t("vt.k.wrong-hash")) + " " + h.esc(String(d.summary.wrongHash)) + "</p>"
      : "";
    const noData = !d.summary.observed && !(d.incidents || []).length
      ? '<p class="vt-empty">' + h.esc(h.t("vt.nodata")) + "</p>"
      : "";
    body.innerHTML = keyLine + refLine + coverageLine + scopeTag
      + '<div class="vt-cards">' + cards + "</div>" + totalLine + noData
      + '<h3 class="vt-h">' + h.esc(h.t("vt.model3d")) + "</h3>" + profile3d(d.incidents, d.range, d.profile, d.coverage)
      + '<h3 class="vt-h">' + h.esc(h.t("vt.retraceTitle")) + "</h3>"
      + '<p class="vt-sub">' + h.esc(h.t("vt.retraceNote")) + "</p>" + retraceBlock(d.retrace)
      + '<h3 class="vt-h">' + h.esc(h.t("vt.fpTitle")) + '</h3><p class="vt-sub">' + h.esc(h.t("vt.fpNote")) + "</p>"
      + fingerprintBlock(d.diagnosis && d.diagnosis.fingerprint)
      + '<h3 class="vt-h">' + h.esc(h.t("vt.cqTitle")) + '</h3><p class="vt-sub">' + h.esc(h.t("vt.cqNote")) + "</p>"
      + criticalityBlock(d.diagnosis && d.diagnosis.criticality)
      + '<h3 class="vt-h">' + h.esc(h.t("vt.loadTitle")) + '</h3><p class="vt-sub">' + h.esc(h.t("vt.loadNote")) + "</p>"
      + loadCurveBlock(d.diagnosis && d.diagnosis.load, true)
      + '<h3 class="vt-h">' + h.esc(h.t("vt.riskTitle")) + "</h3>"
      + '<p class="vt-sub">' + h.esc(h.t("vt.riskNote")) + "</p>" + riskBlock(d.risk)
      + '<h3 class="vt-h">' + h.esc(h.t("vt.patterns")) + "</h3>" + chips(d.patterns)
      + gapsBlock(d.gaps)
      + '<h3 class="vt-h">' + h.esc(h.t("vt.timeline")) + "</h3>" + timeline(d.incidents);
  }

  // Achsenbeschriftung je Intervall: Stunden/Minuten bei kurzen Fenstern, Datum bei langen.
  function bucketLabel(from, width, i, range) {
    const iso = new Date(from + (i / BUCKETS) * width).toISOString();
    return range === "7d" || range === "all" ? iso.slice(5, 10) : iso.slice(11, 16);
  }

  // 3D-Profil: ein Prisma je Zeitintervall auf eigenem Grundriss. Höhe = eigene Abweichungen,
  // Stapel = Vorfallstyp, Grundriss und Kohortenstreifen = wie viele dUNL-Validatoren im
  // selben Intervall ebenfalls ausfielen. Die dritte Dimension ist also eine Messgröße der
  // Retrace-Engine, keine Dekoration.
  // Keine erfundenen Werte: leere Intervalle zeigen nur ihre Grundriss-Kachel, die Achse endet
  // bei der Achsenrunde, und ohne Kohortenmessung steht "nicht erfasst" – nicht "solo".
  // Intervall-Zustand: vier getrennte Aussagen, nie vermischt.
  //   clean   Intervall beobachtet, keine Abweichung dieses Validators
  //   none    kein beobachteter Ledger in diesem Intervall (Aufzeichnungsluecke)
  //   solo / cohort / network  Abweichungen, sortiert nach der Zahl betroffener dUNL-Validatoren
  //   unknown Abweichungen, aber Kohorten-Breite fuer diese Tage nicht erfasst
  // clean und none sind Messungen der Aufzeichnung, solo/cohort/network sind Messungen der
  // Kohorte. Ein leeres Intervall ohne Abdeckungsdaten ist none - nicht "sauber".
  function stateOf(cell) {
    if (!cell.total) return cell.ledgers > 0 ? "clean" : "none";
    return breadthOf(cell.cohort);
  }

  // Signatur-Zustand eines Intervalls: hat die Transaktions-Forensik an den Ausfall-Ledern
  // dieses Validators eine Form-Signatur gemessen? Ohne erfasste Ledger der Ebene ist der
  // Zustand unknown, nicht "keine Signatur" - das waere eine Aussage ueber etwas, das nicht
  // beobachtet wurde.
  function signStateOf(cell, layerRecorded) {
    if (!layerRecorded) return "unknown";
    if (cell.signatures > 0) return "hit";
    if (!cell.ledgers && !cell.total) return "none";
    return "clear";
  }

  // 3D-Profil: ein Prisma je Zeitintervall auf eigenem Grundriss.
  //
  // Die Achse, die Intervalle und die gemessene Ledger-Abdeckung kommen vom Server
  // (profileCells in lib/validator-trace-query.mjs): dasselbe Fenster, dieselbe Achse, kein
  // Uhrversatz zwischen Daten und Darstellung. Die Abdeckung je Intervall ist der Grund, warum
  // "beobachtet, alles in Ordnung" und "hier nichts aufgezeichnet" jetzt verschieden aussehen:
  // vorher waren beide leer und wurden als "nicht erfasst" schraffiert.
  //
  // Ebenen des Profils:
  //   Balkenhoehe        = eigene Abweichungen (Achsenmass --u, identisch zu den Gitterlinien)
  //   Stapelfarben       = Vorfallstyp
  //   Grundriss + Streifen = Intervall-Zustand (clean / solo / cohort / network / unknown / none)
  //   Marker + Signaturstreifen = Transaktions-Signatur an den Ausfall-Ledern dieses Validators
  function profile3d(incidents, range, profile, coverage) {
    const list = (incidents || []).filter((i) => Number.isFinite(i.timeMs) && TYPE_KEY[i.type]);
    if (!list.length) return '<p class="vt-empty">' + h.esc(h.t("vt.profileEmpty")) + "</p>";
    if (!profile || !Array.isArray(profile.cells) || profile.cells.length !== BUCKETS) {
      return '<p class="vt-empty">' + h.esc(h.t("vt.profileNoProfile")) + "</p>";
    }
    const cells = profile.cells;
    // Liegt die Transaktions-Forensik uberhaupt vor? Ohne erfasste Ledger dieser Ebene darf das
    // Profil nicht "keine Signatur" zeigen, sondern nur "nicht erfasst".
    const shapeLayer = Boolean(coverage && Number(coverage.shapeSeen) > 0);
    const from = profile.from;
    const now = profile.to;
    const width = Math.max(1, now - from);
    const legend = { missed: 0, partial: 0, wrongHash: 0, noQuorum: 0 };
    const states = { clean: 0, solo: 0, cohort: 0, network: 0, unknown: 0, none: 0 };
    const signs = { hit: 0, clear: 0, unknown: 0, none: 0 };
    for (const cell of cells) {
      for (const k of PROFILE_TYPES) legend[k] += cell[k] || 0;
      states[stateOf(cell)] += 1;
      signs[signStateOf(cell, shapeLayer)] += 1;
    }
    const { peak, step } = axisScale(Math.max(...cells.map((x) => x.total)));
    const grid = [];
    for (let v = 0; v <= peak; v += step) {
      grid.push('<div class="vt-gridline' + (v === 0 ? " vt-zero" : "") + '" style="bottom:'
        + ((axisUnit(v, peak) / peak) * 100).toFixed(3) + '%"><span class="vt-gridlabel">' + h.esc(String(v)) + "</span></div>");
    }
    const cols = cells.map((cell) => {
      const i = cell.index;
      const state = stateOf(cell);
      const sign = signStateOf(cell, shapeLayer);
      const stops = [];
      let acc = 0;
      let cap = null;
      for (const k of PROFILE_TYPES) {
        if (!cell[k]) continue;
        const a = (acc / cell.total) * 100;
        acc += cell[k];
        stops.push("var(--vt-" + k + ") " + a.toFixed(2) + "% " + ((acc / cell.total) * 100).toFixed(2) + "%");
        cap = k;
      }
      const topTags = Object.entries(cell.tags).sort((x, y) => y[1] - x[1] || x[0].localeCompare(y[0])).slice(0, 3)
        .map(([tag, n]) => tl(tag) + " x" + n).join(" . ");
      const args = {
        label: bucketLabel(from, width, i, range), total: cell.total, missed: cell.missed, partial: cell.partial,
        wrongHash: cell.wrongHash, noQuorum: cell.noQuorum, cohort: cohortText(cell.cohort),
        ledgers: num(cell.ledgers), signatures: num(cell.signatures),
      };
      const style = "--n:" + axisUnit(cell.total, peak).toFixed(3) + ";--i:" + i
        + (stops.length ? ";--vt-grad:linear-gradient(to top," + stops.join(",") + ")" : "")
        + (cap ? ";--vt-cap:var(--vt-" + cap + ")" : "");
      return '<div class="vt-col vt-state-' + state + (cell.total ? " vt-nonzero" : "") + '" tabindex="0" role="group" style="' + style + '" data-tip="'
        + h.esc(h.t("vt.bucketReadout", args) + (topTags ? " . " + topTags : "")) + '" aria-label="'
        + h.esc(h.t("vt.bucketAria", args)) + '">'
        + '<span class="vt-foot" aria-hidden="true"></span>'
        + '<div class="vt-bar">'
        + (cell.total ? '<span class="vt-side" aria-hidden="true"></span><span class="vt-top" aria-hidden="true"></span>' : "")
        + "</div>"
        + (sign === "hit" ? '<span class="vt-mark" aria-hidden="true"></span>' : "")
        + "</div>";
    }).join("");
    const heat = cells.map((cell) => '<span class="vt-heat-cell vt-state-' + stateOf(cell) + '"></span>').join("");
    const signStrip = cells.map((cell) => '<span class="vt-sign-cell vt-sign-' + signStateOf(cell, shapeLayer) + '"></span>').join("");
    const ticks = AXIS_TICKS.map((i) => '<span style="left:' + (((i + 0.5) / BUCKETS) * 100).toFixed(3) + '%">'
      + h.esc(bucketLabel(from, width, i, range)) + "</span>").join("");
    const legendHtml = PROFILE_TYPES.map((k) => '<li><span class="vt-swatch vt-c-' + k + '"></span>'
      + h.esc(h.t("vt.k." + (k === "wrongHash" ? "wrong-hash" : k === "noQuorum" ? "no-quorum" : k))) + " " + h.esc(String(legend[k])) + "</li>").join("");
    const stateLegend = STATES.map((k) => '<li><span class="vt-heat-key vt-state-' + k + '"></span>'
      + h.esc(h.t("vt.state." + k)) + " " + h.esc(String(states[k])) + "</li>").join("");
    const signLegend = SIGN_STATES.map((k) => '<li><span class="vt-sign-key vt-sign-' + k + '"></span>'
      + h.esc(h.t("vt.sign." + k)) + " " + h.esc(String(signs[k])) + "</li>").join("");
    const spanLabel = (ms) => new Date(ms).toISOString().slice(5, 16).replace("T", " ");
    const scale = peak <= LINEAR_PEAK ? h.t("vt.axisScaleLinear") : h.t("vt.axisScaleRoot");
    const meta = h.t("vt.profileMeta", { buckets: BUCKETS, from: spanLabel(from), to: spanLabel(now), peak, scale });
    const shapeNote = shapeLayer
      ? h.t("vt.signCoverage", { seen: num(coverage.shapeSeen), missing: num(coverage.shapeMissing) })
      : h.t("vt.signAbsent");
    return '<div class="vt-profile" style="--peak:' + peak + '">'
      + '<div class="vt-profile-top"><p class="vt-profile-meta">' + h.esc(meta) + "</p>"
      + '<p class="vt-readout" id="vt-readout" aria-live="polite">' + h.esc(h.t("vt.profileHint")) + "</p></div>"
      + '<div class="vt-plot"><div class="vt-grid" aria-hidden="true">' + grid.join("") + "</div>"
      + '<div class="vt-bars">' + cols + "</div></div>"
      + '<div class="vt-axis" aria-hidden="true">' + ticks + "</div>"
      + '<div class="vt-heat" role="img" aria-label="' + h.esc(h.t("vt.heatAria")) + '">' + heat + "</div>"
      + '<div class="vt-sign" role="img" aria-label="' + h.esc(h.t("vt.signAria")) + '">' + signStrip + "</div>"
      + '<ul class="vt-legend">' + legendHtml + "</ul>"
      + '<ul class="vt-legend vt-heat-legend">' + stateLegend + "</ul>"
      + '<ul class="vt-legend vt-sign-legend">' + signLegend + "</ul>"
      + '<p class="vt-note vt-sign-note">' + h.esc(shapeNote) + "</p></div>";
  }

  function evidenceText(hy) {
    const e = hy.evidence || {};
    if (hy.tag === "quorum-thin") return h.t("vt.evMargin", { top: num(e.topVotes), needed: num(e.needed), margin: num(e.margin) });
    if (hy.tag === "hash-split") return h.t("vt.evSplit", { runner: num(e.runnerVotes), votes: num(e.votes) });
    if (hy.tag === "load-spike" || hy.tag === "load-extreme") return h.t("vt.evLoad", { tx: num(e.txCount), med: num(e.medianTx), ratio: fac(e.ratio) });
    if (hy.tag === "close-gap") return h.t("vt.evGap", { gap: sec(e.closeGapMs), med: sec(e.medianGapMs) });
    if (hy.tag === "cohort-event") return h.t("vt.evCohort", { n: num(e.affectedValidators), others: num(e.others) });
    if (hy.tag === "drainer-fanout") return h.t("vt.evFanout", { fanout: num(e.fanoutAccounts), txs: num(e.fanoutTxs), ledgerTx: num(e.ledgerTx) });
    if (hy.tag === "sender-burst") return h.t("vt.evBurst", { accountTx: num(e.accountTx), share: pcn(e.share * 100) });
    if (hy.tag === "failure-spike") return h.t("vt.evFailure", { failed: num(e.failed), share: pcn(e.share * 100) });
    if (hy.tag === "batch-amplify") return h.t("vt.evBatch", { batchTx: num(e.batchTx), innerTx: num(e.innerTx) });
    if (hy.tag === "fee-spike") return h.t("vt.evFee", { maxFee: num(e.maxFee), medianFee: num(e.medianFee) });
    if (hy.tag === "feature-change") return h.t("vt.evFeature", { featureTx: num(e.featureTx) });
    if (hy.tag === "sweep-window") return h.t("vt.evSweep", { destinations: num(e.sweepDestinations), ledgers: num(e.sweepLedgers), txs: num(e.sweepTxs) });
    if (hy.tag === "account-create-burst" || hy.tag === "offer-flood" || hy.tag === "nft-spam") return h.t("vt.evCount", { count: num(e.count), baseline: num(e.baseline) });
    if (String(hy.tag).startsWith("type-burst:")) return h.t("vt.evRatio", { count: num(e.count), baseline: num(e.baseline), ratio: fac(e.ratio) });
    return "";
  }

  // Ein Retrace-Karton: Messwerte, gereihte Hypothesen mit Stärke, Prüfschritte, Datenlücken.
  function retraceCard(r) {
    const a = r.affected || {};
    const cohort = (a.missed || 0) + (a.partial || 0) + (a.wrongHash || 0);
    const q = r.quorum || null;
    const l = r.load || null;
    const metrics = [];
    if (q && Number.isFinite(q.needed) && q.needed > 0) metrics.push(["vt.metric.quorum", h.t("vt.mQuorum", { top: num(q.topVotes), needed: num(q.needed), margin: num(q.margin) })]);
    if (q && Number.isFinite(q.runnerVotes) && q.runnerVotes > 0) metrics.push(["vt.metric.split", h.t("vt.mSplit", { runner: num(q.runnerVotes), votes: num(q.votes) })]);
    if (l && Number.isFinite(l.txCount)) metrics.push(["vt.metric.load", h.t("vt.mLoad", { tx: num(l.txCount), med: num(l.medianTx), ratio: fac(l.ratio) })]);
    if (Number.isFinite(r.closeGapMs)) metrics.push(["vt.metric.gap", h.t("vt.mGap", { gap: sec(r.closeGapMs) })]);
    metrics.push(["vt.metric.cohort", h.t("vt.mCohort", { n: num(cohort), others: num(a.others) })]);
    const metricHtml = metrics.map(([labelKey, value]) => '<li><small>' + h.esc(h.t(labelKey)) + "</small><b>" + h.esc(value) + "</b></li>").join("");
    const hyps = (r.hypotheses || []).map((hy) => {
      const lift = hy.lift && hy.lift.reliable && Number.isFinite(hy.lift.lift)
        ? h.t("vt.liftVal", { lift: fac(hy.lift.lift), with: pcn(hy.lift.rateWith * 100), without: pcn(hy.lift.rateWithout * 100) })
        : "";
      const ev = evidenceText(hy);
      return '<li class="vt-hyp vt-st-' + h.esc(hy.strength) + '"><b>' + h.esc(tl(hy.tag)) + "</b>"
        + '<span class="vt-strength">' + h.esc(h.t("vt.strength." + hy.strength)) + "</span>"
        + (ev ? '<span class="vt-ev">' + h.esc(ev) + "</span>" : "")
        + (lift ? '<span class="vt-lift">' + h.esc(lift) + "</span>" : "") + "</li>";
    }).join("");
    const next = (r.guidance || []).map((g) => "<li>" + h.esc(h.t("vt.g." + g)) + "</li>").join("");
    const gaps = (r.dataGaps || []).map((g) => h.t("vt.datagap." + g)).join(" · ");
    const when = Number.isFinite(r.timeMs) ? stamp(r.timeMs) + " UTC" : "–";
    return '<article class="vt-rc">'
      + '<header class="vt-rc-head"><span class="vt-rc-led">' + h.esc(h.t("vt.ledger")) + " #" + h.esc(String(r.ledgerIndex)) + "</span>"
      + '<span class="vt-rc-when">' + h.esc(when) + "</span>"
      + '<span class="vt-badge vt-type-' + h.esc(r.type) + '">' + h.esc(h.t("vt.type." + r.type)) + "</span>"
      + '<span class="vt-badge vt-scope-' + h.esc(r.scope) + '">' + h.esc(h.t("vt.scope." + r.scope)) + "</span></header>"
      + seriesLine(r.series)
      + '<ul class="vt-rc-metrics">' + metricHtml + "</ul>"
      + '<h4 class="vt-h4">' + h.esc(h.t("vt.hypotheses")) + '</h4><ul class="vt-hyps">' + hyps + "</ul>"
      + (next ? '<h4 class="vt-h4">' + h.esc(h.t("vt.nextCheck")) + '</h4><ul class="vt-next">' + next + "</ul>" : "")
      + (gaps ? '<p class="vt-rc-gaps"><small>' + h.esc(h.t("vt.dataGaps")) + "</small> " + h.esc(gaps) + "</p>" : "")
      + "</article>";
  }

  function retraceBlock(rows) {
    if (!Array.isArray(rows) || !rows.length) return '<p class="vt-empty">' + h.esc(h.t("vt.noRetrace")) + "</p>";
    const shown = rows.slice(0, RETRACE_SHOWN);
    const more = rows.length > shown.length
      ? '<p class="vt-scope"><small>' + h.esc(h.t("vt.retraceShowing", { shown: shown.length, total: rows.length })) + "</small></p>" : "";
    return '<div class="vt-rc-list">' + shown.map(retraceCard).join("") + "</div>" + more;
  }

  // Risikoprofil: Ausfallrate mit Anomalie gegen Ausfallrate ohne Anomalie. Zu kleine
  // Stichproben bleiben als solche stehen, statt zu einer Zahl verdichtet zu werden.
  function riskBlock(risk) {
    if (!risk || !Array.isArray(risk.rows) || !risk.rows.length) return '<p class="vt-empty">' + h.esc(h.t("vt.riskNone")) + "</p>";
    const head = ["vt.risk.hAnomaly", "vt.risk.hLedgers", "vt.risk.hFails", "vt.risk.hRate", "vt.risk.hBase", "vt.risk.hLift"]
      .map((k, i) => '<th scope="col"' + (i === 0 ? ' class="vt-th-l"' : "") + ">" + h.esc(h.t(k)) + "</th>").join("");
    const rows = risk.rows.slice(0, RISK_ROWS).map((r) => "<tr>"
      + '<th scope="row">' + h.esc(tl(r.tag)) + (r.reliable ? "" : '<small class="vt-small">' + h.esc(h.t("vt.riskSmall")) + "</small>") + "</th>"
      + "<td>" + h.esc(num(r.anomalyLedgers)) + "</td>"
      + "<td>" + h.esc(num(r.anomalyFailLedgers)) + "</td>"
      + "<td>" + h.esc(pc(r.rateWith === null ? null : r.rateWith * 100)) + "</td>"
      + "<td>" + h.esc(pc(r.rateWithout === null ? null : r.rateWithout * 100)) + "</td>"
      + "<td>" + h.esc(Number.isFinite(r.lift) ? "×" + fac(r.lift) : "–") + "</td></tr>").join("");
    const note = h.t("vt.riskBase", { ledgers: num(risk.totalLedgers), fails: num(risk.incidentLedgers) })
      + (risk.statsTruncated ? " " + h.t("vt.riskTrunc") : "");
    return '<table class="vt-table"><thead><tr>' + head + "</tr></thead><tbody>" + rows + "</tbody></table>"
      + '<p class="vt-note">' + h.esc(note) + "</p>";
  }

  // Sammelereignisse: viele Validatoren, dasselbe Ledger. Die Spur, auf der Netzstockungen,
  // Versionskonflikte und Angriffe liegen - ausgewählt nach Betroffenheit, nicht nach Bauchgefühl.
  function attackBlock(a) {
    if (!a || !Array.isArray(a.signals) || !a.signals.length) return '<p class="vt-empty">' + h.esc(h.t("vt.attackNone")) + "</p>";
    const rows = a.signals.map((s) => '<li class="vt-atk"><span class="vt-atk-led">' + h.esc(h.t("vt.ledger")) + " #" + h.esc(String(s.ledgerIndex)) + "</span>"
      + '<span class="vt-atk-when">' + h.esc(stamp(s.timeMs)) + " UTC</span>"
      + '<span class="vt-atk-n">' + h.esc(h.t("vt.attackAffected", { n: num(s.affectedValidators) })) + "</span>"
      + '<span class="vt-reasons">' + (s.anomalies || []).map((tag) => '<span class="vt-chip">' + h.esc(tl(tag)) + "</span>").join("") + "</span></li>").join("");
    return '<p class="vt-scope"><small>' + h.esc(h.t("vt.attackThreshold", { n: num(a.threshold), total: num(a.total) })) + "</small></p>"
      + '<ul class="vt-list vt-atk-list">' + rows + "</ul>";
  }

  // Signaturbord: Form -> Ausfallwahrscheinlichkeit. Die Zahlen kommen aus den vollstaendigen
  // Ledger-Zaehlern; der Beispiel-Ledger zeigt, dass die Signatur real aufgetreten ist.
  function signatureBlock(sig) {
    if (!sig || !Array.isArray(sig.rows) || !sig.rows.length) return '<p class="vt-empty">' + h.esc(h.t("vt.sigEmpty")) + "</p>";
    const head = ["vt.sig.hTag", "vt.sig.hLedgers", "vt.sig.hFails", "vt.sig.hLift", "vt.sig.hSample"]
      .map((k, i) => '<th scope="col"' + (i === 0 ? ' class="vt-th-l"' : "") + ">" + h.esc(h.t(k)) + "</th>").join("");
    const rows = sig.rows.map((r) => {
      const s = r.sample || null;
      const sample = s ? h.t("vt.sigSample", { ledger: num(s.ledgerIndex), time: s.timeMs ? stamp(s.timeMs) : "–" }) : "–";
      return "<tr>"
        + '<th scope="row">' + h.esc(tl(r.tag)) + (r.reliable ? "" : '<small class="vt-small">' + h.esc(h.t("vt.riskSmall")) + "</small>") + "</th>"
        + "<td>" + h.esc(num(r.anomalyLedgers)) + "</td>"
        + "<td>" + h.esc(num(r.anomalyFailLedgers)) + "</td>"
        + "<td>" + h.esc(Number.isFinite(r.lift) ? "×" + fac(r.lift) : "–") + "</td>"
        + "<td>" + h.esc(sample) + "</td></tr>";
    }).join("");
    const cov = (sig.coverage) || {};
    const note = h.t("vt.sigCoverage", { seen: num(cov.shapeSeen), missing: num(cov.shapeMissing) })
      + (sig.statsTruncated ? " " + h.t("vt.riskTrunc") : "");
    return '<table class="vt-table"><thead><tr>' + head + "</tr></thead><tbody>" + rows + "</tbody></table>"
      + '<p class="vt-note">' + h.esc(note) + "</p>";
  }

  function gapsBlock(gaps) {
    if (!gaps || !gaps.length) return "";
    return '<h3 class="vt-h">' + h.esc(h.t("vt.gaps")) + '</h3><ul class="vt-list">' + gaps.slice(0, 50).map((g) =>
      '<li class="vt-row"><span>' + h.esc(new Date(g.timeMs).toISOString().replace("T", " ").slice(0, 19)) + " UTC</span><span>" + h.esc(h.t("vt.ledger")) + " #" + h.esc(String(g.from)) + "–" + h.esc(String(g.to)) + "</span></li>").join("") + "</ul>";
  }

  // Serien-Einordnung desselben Vorfalls: die Zeitfolge ist die Erklaerung, wenn der Ledger
  // selbst keine Ursache hergibt. Die Pause nach der Serie ist genauso wichtig wie die Serie -
  // validiert der Knoten dazwischen, war er weg; fehlt die Spur, ist es eine Aufzeichnungsluecke.
  function seriesLine(sc) {
    if (!sc) return "";
    const label = '<small>' + h.esc(h.t("vt.series.label")) + "</small> ";
    if (sc.isolated) return '<p class="vt-rc-series">' + label + h.esc(h.t("vt.series.single")) + "</p>";
    const main = h.t("vt.series.run", {
      from: num(sc.fromLedger), to: num(sc.toLedger), position: num(sc.position), ledgers: num(sc.ledgers),
      duration: dur(sc.durationMs), verdict: h.t("vt.verdict." + sc.verdict),
    });
    const br = sc.breakAfter ? " · " + h.t("vt.series.break", {
      ledgers: num(sc.breakAfter.ledgers), cause: h.t("vt.series.cause." + sc.breakAfter.cause),
    }) : "";
    return '<p class="vt-rc-series">' + label + h.esc(main + br) + "</p>";
  }

  // Knoten-Signatur: die Antwort auf "Netzproblem oder mein Problem". Eigene Rate gegen den
  // Netz-Median, der Anteil der eigenen Ausfaelle, der auf Netzereignisse faellt, Serien-Anteil,
  // laengste Serie und die Stoßzeiten. Ein Knoten mit hohem Netzanteil ist gesund.
  function fingerprintBlock(fp) {
    if (!fp || !Number.isFinite(fp.incidents)) return '<p class="vt-empty">' + h.esc(h.t("vt.fpNone")) + "</p>";
    const rows = [
      ["vt.fp.rate", pc(fp.rate === null ? null : fp.rate * 100) + " · " + num(fp.ledgers) + " " + h.t("vt.ledgers")],
      ["vt.fp.medianRate", pc(fp.medianRate === null ? null : fp.medianRate * 100) + " · ×" + fac(fp.ratioVsMedian)],
      ["vt.fp.networkRate", pc(fp.networkRate === null ? null : fp.networkRate * 100) + " · ×" + fac(fp.ratioVsNetwork)],
      ["vt.fp.split", h.t("vt.fp.splitVal", {
        network: num(fp.networkLedgers), total: num(fp.incidents), private: num(fp.privateLedgers),
        share: pcn((fp.networkShare ?? 0) * 100),
      })],
      ["vt.fp.series", h.t("vt.fp.seriesVal", { share: pcn((fp.seriesShare ?? 0) * 100), isolated: num(fp.isolatedIncidents) })],
      ["vt.fp.longest", fp.longestRun ? h.t("vt.fp.longestVal", { ledgers: num(fp.longestRun.ledgers), duration: dur(fp.longestRun.durationMs) }) : "–"],
      ["vt.fp.peak", h.t("vt.fp.peakVal", {
        share: pcn((fp.peakShare ?? 0) * 100),
        hours: (fp.peakUtcHours || []).map((x) => String(x.utcHour).padStart(2, "0") + " UTC").join(" · "),
      })],
    ];
    const fpRows = rows.map(([k, v]) => '<div class="vt-fp-row"><dt>' + h.esc(h.t(k)) + "</dt><dd>" + h.esc(v) + "</dd></div>").join("");
    return '<dl class="vt-fp">' + fpRows + "</dl>"
      + '<p class="vt-scope"><span class="vt-badge vt-fp-verdict vt-fpv-' + h.esc(fp.verdict) + '">' + h.esc(h.t("vt.fpverdict." + fp.verdict)) + "</span></p>";
  }

  // Quorum-Kritikalitaet: die Frage, die jeder Betreiber stellt und die kein Dashboard liefert.
  function criticalityBlock(cq) {
    if (!cq || !Number.isFinite(cq.checked)) return "";
    if (!cq.checked) return '<p class="vt-empty">' + h.esc(h.t("vt.cq.none")) + "</p>";
    const head = ["vt.cq.hLedger", "vt.cq.hType", "vt.cq.hVotes", "vt.cq.hTop", "vt.cq.hMargin", "vt.cq.hEffect"]
      .map((k, i) => '<th scope="col"' + (i === 0 ? ' class="vt-th-l"' : "") + ">" + h.esc(h.t(k)) + "</th>").join("");
    const rows = cq.rows.map((r) => "<tr>"
      + '<th scope="row">#' + h.esc(num(r.ledgerIndex)) + "</th>"
      + "<td>" + h.esc(h.t("vt.type." + (DIAG_TYPE[r.type] || r.type))) + "</td>"
      + "<td>" + h.esc(num(r.votes) + " / " + num(r.needed)) + "</td>"
      + "<td>" + h.esc(num(r.topVotes)) + "</td>"
      + "<td>" + h.esc(num(r.margin)) + "</td>"
      + "<td>" + h.esc(h.t(r.critical ? "vt.cq.critical" : "vt.cq.followOn")) + "</td></tr>").join("");
    const summary = h.t("vt.cq.summary", {
      checked: num(cq.checked), absent: num(cq.checked + cq.unanswered),
      critical: num(cq.critical), followOn: num(cq.followOn),
    });
    return '<table class="vt-table"><thead><tr>' + head + "</tr></thead><tbody>" + rows + "</tbody></table>"
      + '<p class="vt-note">' + h.esc(summary) + "</p>";
  }

  // Last-Ausfall-Kurve: ab welcher Tx-Last dieser Knoten zurueckfaellt und ab welcher die
  // Kohorte dieselbe Last durchsteht. Die Ausfallrate allein beantwortet das nicht - eine Rate
  // sagt nichts ueber Kapazitaet. Die Normalbetriebsstufe ist in der Tabelle markiert.
  function loadCurveBlock(curve, own) {
    if (!curve || !curve.coverage || !curve.coverage.recorded || !Array.isArray(curve.rows) || !curve.rows.length) {
      return '<p class="vt-empty">' + h.esc(h.t("vt.load.none")) + "</p>";
    }
    const cols = ["vt.load.hLoad", "vt.load.hLedgers", "vt.load.hFails", "vt.load.hNetwork", "vt.load.hCohort"];
    if (own) cols.push("vt.load.hOwn");
    const head = cols.map((k, i) => '<th scope="col"' + (i === 0 ? ' class="vt-th-l"' : "") + ">" + h.esc(h.t(k)) + "</th>").join("");
    const rows = curve.rows.map((r) => "<tr" + (curve.baseline && curve.baseline.index === r.index ? ' class="vt-load-base"' : "") + ">"
      + '<th scope="row">' + h.esc(r.label) + (r.sample === "thin" ? ' <small class="vt-small">' + h.esc(h.t("vt.load.thin")) + "</small>" : "") + "</th>"
      + "<td>" + h.esc(num(r.ledgers)) + "</td>"
      + "<td>" + h.esc(num(r.failLedgers)) + "</td>"
      + "<td>" + h.esc(pcn((r.networkRate ?? 0) * 100)) + "</td>"
      + "<td>" + h.esc(r.cohortMedianRate === null ? "–" : pcn(r.cohortMedianRate * 100)) + "</td>"
      + (own ? "<td>" + h.esc(r.validatorRate === null ? "–" : pcn(r.validatorRate * 100)) + "</td>" : "")
      + "</tr>").join("");
    const judge = own && curve.validator ? curve.validator : curve.network;
    const lines = [h.t("vt.load.baseline", {
      label: curve.baseline ? curve.baseline.label : "–",
      n: num(curve.baseline ? curve.baseline.ledgers : 0),
    })];
    if (own && curve.validator && curve.validator.ceilingLabel) {
      lines.push(h.t("vt.load.ownCeiling", { label: curve.validator.ceilingLabel, rate: pcn((curve.validator.ceilingRate ?? 0) * 100) }));
    }
    if (curve.cohort && curve.cohort.ceilingLabel) lines.push(h.t("vt.load.cohortCeiling", { label: curve.cohort.ceilingLabel }));
    if (curve.network && curve.network.ceilingLabel) lines.push(h.t("vt.load.netCeiling", { label: curve.network.ceilingLabel, rate: pcn((curve.network.ceilingRate ?? 0) * 100) }));
    return '<table class="vt-table"><thead><tr>' + head + "</tr></thead><tbody>" + rows + "</tbody></table>"
      + '<p class="vt-note">' + h.esc(lines.join(" · ")) + "</p>"
      + '<p class="vt-scope"><span class="vt-badge vt-load-verdict vt-loadv-' + h.esc(judge.verdict) + '">'
      + h.esc(h.t("vt.load.verdict." + judge.verdict)) + "</span></p>";
  }

  // Netz-Sicht: erst die Trennung Netzereignis / privat, dann Kandidaten fuer geteilte
  // Infrastruktur (nur privat), dann die Fenster je Validator. Ohne diese Trennung zaehlt man
  // ein Netzereignis als Infrastruktur - der Messfehler, den diese Ebene zuerst selbst hatte.
  function networkBlock(split, clusters, windows) {
    const parts = [];
    if (split && Array.isArray(split.rows) && split.rows.length) {
      const head = ["vt.net.hValidator", "vt.net.hTotal", "vt.net.hNetwork", "vt.net.hOwn", "vt.net.hShare"]
        .map((k, i) => '<th scope="col"' + (i === 0 ? ' class="vt-th-l"' : "") + ">" + h.esc(h.t(k)) + "</th>").join("");
      const rows = split.rows.slice(0, 14).map((r) => "<tr>"
        + '<th scope="row">' + h.esc(r.master.slice(0, 12) + "…") + "</th>"
        + "<td>" + h.esc(num(r.total)) + "</td>"
        + "<td>" + h.esc(num(r.networkLedgers)) + "</td>"
        + "<td>" + h.esc(num(r.privateLedgers)) + "</td>"
        + "<td>" + h.esc(pc(r.networkShare === null ? null : r.networkShare * 100)) + "</td></tr>").join("");
      parts.push('<p class="vt-scope"><small>' + h.esc(h.t("vt.net.summary", { network: num(split.networkLedgers), private: num(split.privateLedgers) })) + "</small></p>"
        + '<table class="vt-table"><thead><tr>' + head + "</tr></thead><tbody>" + rows + "</tbody></table>");
    }
    if (clusters && clusters.coverage) {
      const th = clusters.thresholds || {};
      const summary = h.t("vt.cl.summary", { pairs: num((clusters.pairs || []).length), private: num(clusters.coverage.privateLedgers), strong: num(clusters.strongPairs) });
      const strong = (clusters.clusters || []).map((c) => '<li class="vt-row"><span>' + h.esc(h.t("vt.cl.members") + ": " + c.members.map((m) => m.slice(0, 10) + "…").join(", ")) + "</span>"
        + "<span>" + h.esc(num(c.sharedLedgers) + " " + h.t("vt.ledgers") + (Number.isFinite(c.medianLift) ? " · ×" + fac(c.medianLift) : "")) + "</span></li>").join("");
      const cand = (clusters.pairs || []).filter((p) => p.coLedgers >= (th.coMinLedgers || 4)).slice(0, 12)
        .map((p) => '<li class="vt-row">' + h.esc(h.t("vt.cl.pairRow", {
          a: p.a.slice(0, 10) + "…", b: p.b.slice(0, 10) + "…", co: num(p.coLedgers),
          lift: fac(p.lift), mutual: pcn((p.mutual ?? 0) * 100),
        })) + "</li>").join("");
      const body = strong || cand || '<p class="vt-empty">' + h.esc(h.t("vt.cl.none")) + "</p>";
      parts.push('<p class="vt-scope"><small>' + h.esc(summary) + "</small></p>" + '<ul class="vt-list">' + body + "</ul>");
    }
    if (windows && Array.isArray(windows.windows) && windows.windows.length) {
      const tally = Object.entries(windows.tally || {}).map(([k, n]) => h.t("vt.win.class." + k) + " × " + num(n)).join(" · ");
      const rows = windows.windows.map((w) => '<li class="vt-row">' + h.esc(h.t("vt.win.row", {
        class: h.t("vt.win.class." + w.classification), master: w.master.slice(0, 10) + "…",
        from: num(w.fromLedger), to: num(w.toLedger), ledgers: num(w.ledgers),
        duration: dur(w.durationMs), coShare: pcn((w.coShare ?? 0) * 100),
      })) + ((w.shapeTags || []).length ? " · " + h.esc((w.shapeTags || []).map(tl).join(" · ")) : "") + "</li>").join("");
      parts.push('<p class="vt-scope"><small>' + h.esc(tally) + "</small></p>" + '<ul class="vt-list">' + rows + "</ul>");
    }
    if (!parts.length) return '<p class="vt-empty">' + h.esc(h.t("vt.net.none")) + "</p>";
    return parts.join("");
  }

  function renderPatterns(body, d) {
    overlay.querySelector("#vt-title").textContent = h.t("vt.crossTitle");
    const rec = (d.recurring || []).map((r) => '<li class="vt-rec"><b>' + h.esc(tl(r.tag)) + "</b> <small>× " + h.esc(String(r.count)) + " · " + h.esc(String(r.validators)) + " " + h.esc(h.t("vt.validators")) + " · " + h.esc(String(r.ledgers)) + " " + h.esc(h.t("vt.ledgers")) + "</small></li>").join("");
    const per = Object.entries(d.perValidator || {}).sort((a, b) => (b[1].missed + b[1].wrongHash) - (a[1].missed + a[1].wrongHash))
      .map(([k, v]) => '<li class="vt-row"><span class="vt-key">' + h.esc(k.slice(0, 12)) + "…</span><span>missed " + h.esc(String(v.missed)) + " · no-quorum " + h.esc(String(v.noQuorum ?? 0)) + " · partial " + h.esc(String(v.partial)) + " · wrong-hash " + h.esc(String(v.wrongHash)) + "</span></li>").join("");
    body.innerHTML = '<p class="vt-h">' + h.esc(h.t("vt.incidentsTotal", { n: d.incidents })) + "</p>"
      + '<h3 class="vt-h">' + h.esc(h.t("vt.recurring")) + "</h3>" + (rec ? '<ul class="vt-list">' + rec + "</ul>" : '<p class="vt-empty">' + h.esc(h.t("vt.noRecurring")) + "</p>")
      + '<h3 class="vt-h">' + h.esc(h.t("vt.attackTitle")) + '</h3><p class="vt-sub">' + h.esc(h.t("vt.attackNote")) + "</p>" + attackBlock(d.attacks)
      + '<h3 class="vt-h">' + h.esc(h.t("vt.sigTitle")) + '</h3><p class="vt-sub">' + h.esc(h.t("vt.sigNote")) + "</p>" + signatureBlock(d.signatures)
      + '<h3 class="vt-h">' + h.esc(h.t("vt.loadTitle")) + '</h3><p class="vt-sub">' + h.esc(h.t("vt.loadNetNote")) + "</p>"
      + loadCurveBlock(d.load, false)
      + '<h3 class="vt-h">' + h.esc(h.t("vt.riskTitle")) + '</h3><p class="vt-sub">' + h.esc(h.t("vt.riskNote")) + "</p>" + riskBlock(d.risk)
      + '<h3 class="vt-h">' + h.esc(h.t("vt.netTitle")) + '</h3><p class="vt-sub">' + h.esc(h.t("vt.netNote", { n: num(d.split && d.split.threshold) })) + "</p>" + networkBlock(d.split, d.clusters, d.windows)
      + '<h3 class="vt-h">' + h.esc(h.t("vt.perValidator")) + '</h3><ul class="vt-list">' + (per || "") + "</ul>";
  }

  function chips(tags) {
    if (!tags || !tags.length) return '<p class="vt-empty">' + h.esc(h.t("vt.noPatterns")) + "</p>";
    return '<div class="vt-chips">' + tags.slice(0, 12).map((t) => '<span class="vt-chip">' + h.esc(tl(t.tag)) + " × " + h.esc(String(t.count)) + "</span>").join("") + "</div>";
  }

  function timeline(incidents) {
    if (!incidents || !incidents.length) return '<p class="vt-empty">' + h.esc(h.t("vt.noIncidents")) + "</p>";
    return '<ol class="vt-timeline">' + incidents.slice(0, 200).map((i) => {
      const when = new Date(i.timeMs).toISOString().replace("T", " ").slice(0, 19) + " UTC";
      return '<li class="vt-ev vt-' + h.esc(i.type) + '"><span class="vt-when">' + h.esc(when) + "</span>"
        + '<span class="vt-type">' + h.esc(h.t("vt.type." + i.type)) + "</span>"
        + '<span class="vt-led">' + h.esc(h.t("vt.ledger")) + " #" + h.esc(String(i.ledgerIndex)) + "</span>"
        + '<span class="vt-reasons">' + (i.reasons || []).map((r) => '<span class="vt-chip">' + h.esc(tl(r)) + "</span>").join("") + "</span></li>";
    }).join("") + "</ol>";
  }

  // Readout-Zeile: dieselbe Information wie der Tooltip, aber für Tastatur und Screenreader.
  function wire(body) {
    const readout = body.querySelector("#vt-readout");
    if (!readout) return;
    body.querySelectorAll(".vt-col").forEach((col) => {
      const show = () => { readout.textContent = col.dataset.tip || h.t("vt.profileHint"); };
      col.addEventListener("mouseenter", show);
      col.addEventListener("focus", show);
    });
  }

  function openValidator(master, title, ref) {
    current = { mode: "validator", master, title: title || master.slice(0, 14) + "…", range: "24h", ref: ref || null };
    load();
  }
  function openPatterns() {
    current = { mode: "patterns", master: null, title: "", range: "24h" };
    load();
  }
  return { openValidator, openPatterns, close };
}