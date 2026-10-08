// public/validator-trace.mjs — Validator-Trace-Overlay (lazy geladen aus live-monitor.mjs).
// Ein Validator: Zusammenfassung, Ledger-genaue Zeitleiste der Abweichungen mit Grund-Tags,
// Muster, und eine 3D-Ansicht der Ausfälle (CSS-Transformationen, kein WebGL).
// Mustersicht: wiederkehrende Korrelationen über alle dUNL-Validatoren.
// Alle Inhalte laufen durch h.esc; Schlüssel werden gekürzt angezeigt.
const RANGES = ["1h", "24h", "7d", "all"];
const BUCKETS = 24;

// Korrelations-Tag -> lesbare Bezeichnung (Übersetzung, sonst Rohname; nie eine erfundene Ursache).
export function tagLabel(h, tag) {
  const base = String(tag).split(":")[0];
  const key = "vt.tag." + base;
  const txt = h.t(key);
  if (!txt || txt === key) return String(tag);
  return base === "new-tx-type" ? txt + " " + String(tag).slice(base.length + 1) : txt;
}
export function createValidatorTrace(h) {
  let overlay = null;
  const tl = (tag) => tagLabel(h, tag);
  let current = { mode: "validator", master: null, title: "", range: "24h" };

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
    } catch {
      body.innerHTML = '<p class="vt-empty">' + h.esc(h.t("vt.error")) + "</p>";
    }
  }

  function renderValidator(body, d) {
    overlay.querySelector("#vt-title").textContent = current.title;
    const s = d.summary;
    const cards = [["ok", s.ok], ["partial", s.partial], ["missed", s.missed], ["wrong-hash", s.wrongHash], ["observed", s.observed]]
      .map(([k, v]) => '<div class="vt-card vt-' + k + '"><small>' + h.esc(h.t("vt.k." + k)) + "</small><b>" + h.esc(String(v)) + "</b></div>").join("");
    body.innerHTML = '<div class="vt-cards">' + cards + "</div>"
      + '<h3 class="vt-h">' + h.esc(h.t("vt.model3d")) + "</h3>" + bars3d(d.incidents, d.range)
      + '<h3 class="vt-h">' + h.esc(h.t("vt.patterns")) + "</h3>" + chips(d.patterns)
      + '<h3 class="vt-h">' + h.esc(h.t("vt.timeline")) + "</h3>" + timeline(d.incidents);
  }

  function renderPatterns(body, d) {
    overlay.querySelector("#vt-title").textContent = h.t("vt.crossTitle");
    const rec = (d.recurring || []).map((r) => '<li class="vt-rec"><b>' + h.esc(r.tag) + "</b> <small>× " + h.esc(String(r.count)) + " · " + h.esc(String(r.validators)) + " " + h.esc(h.t("vt.validators")) + " · " + h.esc(String(r.ledgers)) + " " + h.esc(h.t("vt.ledgers")) + "</small></li>").join("");
    const per = Object.entries(d.perValidator || {}).sort((a, b) => (b[1].missed + b[1].wrongHash) - (a[1].missed + a[1].wrongHash))
      .map(([k, v]) => '<li class="vt-row"><span class="vt-key">' + h.esc(k.slice(0, 12)) + "…</span><span>missed " + h.esc(String(v.missed)) + " · partial " + h.esc(String(v.partial)) + " · wrong-hash " + h.esc(String(v.wrongHash)) + "</span></li>").join("");
    body.innerHTML = '<p class="vt-h">' + h.esc(h.t("vt.incidentsTotal", { n: d.incidents })) + "</p>"
      + '<h3 class="vt-h">' + h.esc(h.t("vt.recurring")) + "</h3>" + (rec ? '<ul class="vt-list">' + rec + "</ul>" : '<p class="vt-empty">' + h.esc(h.t("vt.noRecurring")) + "</p>")
      + '<h3 class="vt-h">' + h.esc(h.t("vt.perValidator")) + '</h3><ul class="vt-list">' + (per || "") + "</ul>";
  }

  // 3D: Säulen je Zeit-Bucket (Anzahl Abweichungen), im Raster gekippt. Höhe nur aus Zählern.
  function bars3d(incidents, range) {
    const span = range === "1h" ? 3600000 : range === "24h" ? 86400000 : range === "7d" ? 7 * 86400000 : null;
    const times = (incidents || []).map((i) => i.timeMs);
    const now = Date.now();
    const from = span ? now - span : (times.length ? Math.min(...times) : now - 1);
    const width = Math.max(1, now - from);
    const counts = new Array(BUCKETS).fill(0);
    for (const t of times) {
      const idx = Math.min(BUCKETS - 1, Math.max(0, Math.floor(((t - from) / width) * BUCKETS)));
      counts[idx]++;
    }
    const max = Math.max(1, ...counts);
    const cols = counts.map((c, i) => '<div class="vt-bar" style="--h:' + Math.round((c / max) * 120) + '" title="' + h.esc(String(c)) + '" data-i="' + i + '"></div>').join("");
    return '<div class="vt-3d"><div class="vt-floor">' + cols + "</div></div>";
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

  function openValidator(master, title) {
    current = { mode: "validator", master, title: title || master.slice(0, 14) + "…", range: "24h" };
    load();
  }
  function openPatterns() {
    current = { mode: "patterns", master: null, title: "", range: "24h" };
    load();
  }
  return { openValidator, openPatterns, close };
}
