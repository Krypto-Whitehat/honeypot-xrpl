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

export function createValidatorTrace(h) {
  let overlay = null;
  const tl = (tag) => tagLabel(h, tag);
  let current = { mode: "validator", master: null, title: "", range: "24h" };

  const num = (v) => (Number.isFinite(Number(v)) ? String(Number(v)) : "–");
  const sec = (ms) => (Number.isFinite(ms) ? (Math.round(ms / 100) / 10).toFixed(1) : "–");
  const fac = (r) => (Number.isFinite(r) ? (Math.round(r * 10) / 10).toFixed(1) : "–");
  const pc = (v) => (Number.isFinite(v) ? (Math.round(v * 10) / 10).toFixed(1) + " %" : "–");
  // Prozentzahl ohne Einheit: für Sätze, in denen das Prozentzeichen in der Übersetzung steht
  // (und damit je Sprache an anderer Stelle sitzen darf).
  const pcn = (v) => (Number.isFinite(v) ? (Math.round(v * 10) / 10).toFixed(1) : "–");
  const stamp = (ms) => (Number.isFinite(ms) ? new Date(ms).toISOString().replace("T", " ").slice(0, 19) : "–");

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
        + ((v / peak) * 100).toFixed(3) + '%"><span class="vt-gridlabel">' + h.esc(String(v)) + "</span></div>");
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
      const style = "--n:" + cell.total + ";--i:" + i
        + (stops.length ? ";--vt-grad:linear-gradient(to top," + stops.join(",") + ")" : "")
        + (cap ? ";--vt-cap:var(--vt-" + cap + ")" : "");
      return '<div class="vt-col vt-state-' + state + '" tabindex="0" role="group" style="' + style + '" data-tip="'
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
    const meta = h.t("vt.profileMeta", { buckets: BUCKETS, from: spanLabel(from), to: spanLabel(now), peak });
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

  function renderPatterns(body, d) {
    overlay.querySelector("#vt-title").textContent = h.t("vt.crossTitle");
    const rec = (d.recurring || []).map((r) => '<li class="vt-rec"><b>' + h.esc(tl(r.tag)) + "</b> <small>× " + h.esc(String(r.count)) + " · " + h.esc(String(r.validators)) + " " + h.esc(h.t("vt.validators")) + " · " + h.esc(String(r.ledgers)) + " " + h.esc(h.t("vt.ledgers")) + "</small></li>").join("");
    const per = Object.entries(d.perValidator || {}).sort((a, b) => (b[1].missed + b[1].wrongHash) - (a[1].missed + a[1].wrongHash))
      .map(([k, v]) => '<li class="vt-row"><span class="vt-key">' + h.esc(k.slice(0, 12)) + "…</span><span>missed " + h.esc(String(v.missed)) + " · no-quorum " + h.esc(String(v.noQuorum ?? 0)) + " · partial " + h.esc(String(v.partial)) + " · wrong-hash " + h.esc(String(v.wrongHash)) + "</span></li>").join("");
    body.innerHTML = '<p class="vt-h">' + h.esc(h.t("vt.incidentsTotal", { n: d.incidents })) + "</p>"
      + '<h3 class="vt-h">' + h.esc(h.t("vt.recurring")) + "</h3>" + (rec ? '<ul class="vt-list">' + rec + "</ul>" : '<p class="vt-empty">' + h.esc(h.t("vt.noRecurring")) + "</p>")
      + '<h3 class="vt-h">' + h.esc(h.t("vt.attackTitle")) + '</h3><p class="vt-sub">' + h.esc(h.t("vt.attackNote")) + "</p>" + attackBlock(d.attacks)
      + '<h3 class="vt-h">' + h.esc(h.t("vt.sigTitle")) + '</h3><p class="vt-sub">' + h.esc(h.t("vt.sigNote")) + "</p>" + signatureBlock(d.signatures)
      + '<h3 class="vt-h">' + h.esc(h.t("vt.riskTitle")) + '</h3><p class="vt-sub">' + h.esc(h.t("vt.riskNote")) + "</p>" + riskBlock(d.risk)
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