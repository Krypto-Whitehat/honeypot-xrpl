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

// Korrelations-Tag -> lesbare Bezeichnung (Übersetzung, sonst Rohname; nie eine erfundene Ursache).
export function tagLabel(h, tag) {
  const base = String(tag).split(":")[0];
  const key = "vt.tag." + base;
  const txt = h.t(key);
  if (!txt || txt === key) return String(tag);
  return base === "new-tx-type" ? txt + " " + String(tag).slice(base.length + 1) : txt;
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
      + '<h3 class="vt-h">' + h.esc(h.t("vt.model3d")) + "</h3>" + profile3d(d.incidents, d.range)
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

  // 3D-Profil: ein Prisma je Zeitintervall, Höhe = Anzahl Abweichungen, Stapel = Vorfallstyp.
  // Keine erfundenen Werte: leere Intervalle bleiben leer, die Achse endet bei der Achsenrunde.
  function profile3d(incidents, range) {
    const list = (incidents || []).filter((i) => Number.isFinite(i.timeMs) && TYPE_KEY[i.type]);
    if (!list.length) return '<p class="vt-empty">' + h.esc(h.t("vt.profileEmpty")) + "</p>";
    const span = SPAN_MS[range];
    const now = Date.now();
    const times = list.map((i) => i.timeMs);
    const from = span ? now - span : Math.min(...times);
    const width = Math.max(1, now - from);
    const cells = Array.from({ length: BUCKETS }, () => ({ missed: 0, partial: 0, wrongHash: 0, noQuorum: 0, total: 0, tags: new Map() }));
    const legend = { missed: 0, partial: 0, wrongHash: 0, noQuorum: 0 };
    for (const i of list) {
      const key = TYPE_KEY[i.type];
      const idx = Math.min(BUCKETS - 1, Math.max(0, Math.floor(((i.timeMs - from) / width) * BUCKETS)));
      const cell = cells[idx];
      cell[key] += 1;
      cell.total += 1;
      legend[key] += 1;
      for (const r of i.reasons || []) cell.tags.set(r, (cell.tags.get(r) || 0) + 1);
    }
    const { peak, step } = axisScale(Math.max(...cells.map((x) => x.total)));
    const grid = [];
    for (let v = 0; v <= peak; v += step) {
      grid.push('<div class="vt-gridline' + (v === 0 ? " vt-zero" : "") + '" style="bottom:'
        + ((v / peak) * 100).toFixed(3) + '%"><span class="vt-gridlabel">' + h.esc(String(v)) + "</span></div>");
    }
    const cols = cells.map((cell, i) => {
      const label = bucketLabel(from, width, i, range);
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
      const topTags = [...cell.tags.entries()].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0])).slice(0, 3)
        .map(([tag, n]) => tl(tag) + " ×" + n).join(" · ");
      const tip = h.t("vt.bucketReadout", { label, total: cell.total, missed: cell.missed, partial: cell.partial, wrongHash: cell.wrongHash, noQuorum: cell.noQuorum })
        + (topTags ? " · " + topTags : "");
      const style = "--n:" + cell.total + (stops.length ? ";--vt-grad:linear-gradient(to top," + stops.join(",") + ")" : "")
        + (cap ? ";--vt-cap:var(--vt-" + cap + ")" : "");
      const aria = h.t("vt.bucketAria", { label, total: cell.total, missed: cell.missed, partial: cell.partial, wrongHash: cell.wrongHash, noQuorum: cell.noQuorum });
      return '<div class="vt-col" tabindex="0" role="group" data-tip="' + h.esc(tip) + '" aria-label="' + h.esc(aria) + '">'
        + '<div class="vt-bar" style="' + style + '">'
        + (cell.total ? '<span class="vt-side" aria-hidden="true"></span><span class="vt-top" aria-hidden="true"></span>' : "")
        + "</div></div>";
    }).join("");
    const ticks = AXIS_TICKS.map((i) => '<span style="left:' + (((i + 0.5) / BUCKETS) * 100).toFixed(3) + '%">'
      + h.esc(bucketLabel(from, width, i, range)) + "</span>").join("");
    const legendHtml = PROFILE_TYPES.map((k) => '<li><span class="vt-swatch vt-c-' + k + '"></span>'
      + h.esc(h.t("vt.k." + (k === "wrongHash" ? "wrong-hash" : k === "noQuorum" ? "no-quorum" : k))) + " " + h.esc(String(legend[k])) + "</li>").join("");
    // Spanne exakt benennen, nicht über die Intervall-Etiketten: überspringt das Fenster die
    // Mitternacht, läge die Startmarke des letzten Intervalls sonst vor der des ersten.
    const spanLabel = (ms) => new Date(ms).toISOString().slice(5, 16).replace("T", " ");
    const meta = h.t("vt.profileMeta", { buckets: BUCKETS, from: spanLabel(from), to: spanLabel(now), peak });
    return '<div class="vt-profile" style="--peak:' + peak + '">'
      + '<div class="vt-profile-top"><p class="vt-profile-meta">' + h.esc(meta) + "</p>"
      + '<p class="vt-readout" id="vt-readout" aria-live="polite">' + h.esc(h.t("vt.profileHint")) + "</p></div>"
      + '<div class="vt-plot"><div class="vt-grid" aria-hidden="true">' + grid.join("") + "</div>"
      + '<div class="vt-floor" aria-hidden="true">' + Array.from({ length: BUCKETS + 1 }, (_, i) => '<i style="left:' + ((i / BUCKETS) * 100).toFixed(3) + '%"></i>').join("") + "</div>"
      + '<div class="vt-bars">' + cols + "</div></div>"
      + '<div class="vt-axis" aria-hidden="true">' + ticks + "</div>"
      + '<ul class="vt-legend">' + legendHtml + "</ul></div>";
  }

  function evidenceText(hy) {
    const e = hy.evidence || {};
    if (hy.tag === "quorum-thin") return h.t("vt.evMargin", { top: num(e.topVotes), needed: num(e.needed), margin: num(e.margin) });
    if (hy.tag === "hash-split") return h.t("vt.evSplit", { runner: num(e.runnerVotes), votes: num(e.votes) });
    if (hy.tag === "load-spike" || hy.tag === "load-extreme") return h.t("vt.evLoad", { tx: num(e.txCount), med: num(e.medianTx), ratio: fac(e.ratio) });
    if (hy.tag === "close-gap") return h.t("vt.evGap", { gap: sec(e.closeGapMs), med: sec(e.medianGapMs) });
    if (hy.tag === "cohort-event") return h.t("vt.evCohort", { n: num(e.affectedValidators), others: num(e.others) });
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