// public/live-monitor.mjs — Muster-Monitor (Lastmuster-Panel) und Drainer-Ticker.
// Lazy geladen aus app.js (Speed-Budget ≤ 200 KB je App-Datei). Die Host-Funktionen
// (t, esc, ruleName, noteText, defang, displayFindingAddr) kommen injiziert — das
// Modul rendert nie eine rohe Adresse und nie ungefiltertes Freitext-HTML.
// Eingabe ist bereits köder-gefiltert (visibleFindings aus analyzeLedgerBlock).
import { detectPatterns } from '/lib/pattern-watch.mjs';
import { liveEdgesOf } from '/lib/live-edges.mjs';

const PATTERN_SAMPLES_MAX = 240;   // ≈ 16 min Ledger-Historie
const PANEL_PAINT_MS = 2000;       // Panel höchstens alle 2 s neu zeichnen
const TICKER_MAX = 60;
const TICKER_SHOWN = 30;

export function createLiveMonitor(h) {
  const samples = [];
  let anomalies = [];
  const rows = [];
  let paintAt = 0;

  function record(ledgerIndex, closeIso, txCount, findings, entries) {
    const closeMs = Date.parse(String(closeIso ?? '')) || Date.now();
    let malicious = 0, suspect = 0;
    for (const f of findings || []) {
      if (f.severity === 'malicious') malicious += 1;
      else if (f.severity === 'suspect') suspect += 1;
    }
    samples.push({ ledgerIndex: Number(ledgerIndex), closeMs, txCount: Number(txCount) || 0, malicious, suspect });
    while (samples.length > PATTERN_SAMPLES_MAX) samples.shift();
    anomalies = detectPatterns(samples).slice(-40);
    ticker(findings, ledgerIndex);
    if (h.pushGlobe) { const edges = liveEdgesOf(entries, findings); if (edges.length) h.pushGlobe(edges); }
    const now = Date.now();
    if (now - paintAt >= PANEL_PAINT_MS) { paintAt = now; paintPattern(); }
  }

  function paintPattern() {
    const chart = document.getElementById('pattern-chart');
    const list = document.getElementById('pattern-list');
    const empty = document.getElementById('pattern-empty');
    if (!chart || !list || !empty) return;
    const W = 600, H = 120, n = samples.length;
    if (n < 2) { chart.innerHTML = ''; list.innerHTML = ''; empty.hidden = false; return; }
    const maxTx = Math.max(1, ...samples.map((s) => s.txCount));
    const xOf = (i) => (i / (n - 1)) * W;
    const yOf = (v) => H - (v / maxTx) * (H - 12) - 6;
    const pts = samples.map((s, i) => xOf(i).toFixed(1) + ',' + yOf(s.txCount).toFixed(1)).join(' ');
    const idxOf = new Map(samples.map((s, i) => [s.ledgerIndex, i]));
    const marks = anomalies.map((a) => {
      const i = idxOf.get(a.ledgerIndex);
      if (i == null) return '';
      const cls = a.type === 'load-spike' ? 'pm-mark-load' : a.type === 'close-gap' ? 'pm-mark-gap' : 'pm-mark-burst';
      return '<circle class="pm-mark ' + cls + '" cx="' + xOf(i).toFixed(1) + '" cy="' + yOf(samples[i].txCount).toFixed(1) + '" r="3.5"></circle>';
    }).join('');
    chart.innerHTML = '<svg viewBox="0 0 ' + W + ' ' + H + '" preserveAspectRatio="none" role="img" aria-label="' + h.esc(h.t('pattern.chartAria')) + '">'
      + '<polyline class="pm-line" points="' + pts + '"></polyline>' + marks + '</svg>';
    const recent = anomalies.slice().reverse().slice(0, 12);
    empty.hidden = recent.length > 0;
    list.innerHTML = recent.map((a) => {
      const time = new Date(a.timeMs).toISOString().replace('T', ' ').slice(0, 19) + ' UTC';
      const ratio = a.ratio == null ? '–' : (Math.round(a.ratio * 10) / 10) + '×';
      return '<li class="pm-row pm-' + h.esc(a.type) + '"><span class="pm-time">' + h.esc(time) + '</span>'
        + '<span class="pm-type">' + h.esc(h.t('pattern.type.' + a.type)) + '</span>'
        + '<span class="pm-ledger">#' + h.esc(String(a.ledgerIndex)) + '</span>'
        + '<span class="pm-val">' + h.esc(String(a.value)) + ' <small>/ ' + h.esc(String(Math.round(a.baseline * 10) / 10)) + ' · ' + h.esc(ratio) + '</small></span></li>';
    }).join('');
  }

  function ticker(findings, ledgerIndex) {
    let added = false;
    for (const f of findings || []) {
      if (f.severity !== 'malicious' && f.severity !== 'suspect') continue;
      const name = h.nameOf ? h.nameOf(String(f.address ?? '')) : null;
      rows.unshift({ t: Date.now(), ledgerIndex, severity: f.severity, ruleId: String(f.ruleId ?? ''), address: String(f.address ?? ''), name: typeof name === 'string' ? name : null,
        note: f.noteKey ? h.noteText(f) : h.defang(String(f.note ?? '')) });
      added = true;
    }
    while (rows.length > TICKER_MAX) rows.pop();
    if (added) paintTicker();
  }

  function paintTicker() {
    const list = document.getElementById('ticker-list');
    const empty = document.getElementById('ticker-empty');
    if (!list || !empty) return;
    empty.hidden = rows.length > 0;
    list.innerHTML = rows.slice(0, TICKER_SHOWN).map((r) => {
      const time = new Date(r.t).toISOString().slice(11, 19);
      return '<li class="tk-row tk-' + h.esc(r.severity) + '"><span class="tk-time">' + h.esc(time) + '</span>'
        + '<span class="tk-rule">' + h.esc(h.ruleName(r.ruleId)) + '</span>'
        + '<span class="tk-addr">' + h.esc(h.displayFindingAddr(r.address)) + (r.name ? ' <span class="tk-name">' + h.esc(r.name) + '</span>' : '') + '</span>'
        + '<span class="tk-note">' + h.esc(r.note) + '</span></li>';
    }).join('');
  }

  function paintValidators(body) {
    const list = document.getElementById("validator-list");
    const empty = document.getElementById("validator-empty");
    const alerts = document.getElementById("validator-alerts");
    if (!list || !empty || !alerts) return;
    const vals = Array.isArray(body?.validators) ? body.validators : [];
    empty.hidden = vals.length > 0;
    const pct = (x) => (x && x.total ? Math.round((x.missed / x.total) * 1000) / 10 : null);
    const score = (x) => (x && x.score != null ? (Math.round(x.score * 10000) / 100).toFixed(2) + " %" + (x.incomplete ? " " + h.t("validator.partial") : "") : "–");
    list.innerHTML = vals.map((v) => {
      const bad = v.revoked || (v.agreement1h && v.agreement1h.score != null && v.agreement1h.score < 0.95);
      const cls = v.revoked ? "vl-bad" : bad ? "vl-warn" : "vl-ok";
      const short = String(v.key || "").slice(0, 10) + "…" + String(v.key || "").slice(-6);
      return "<li class=\"vl-row " + cls + "\"><span class=\"vl-domain\">" + h.esc(v.domain || "–") + "</span>"
        + "<span class=\"vl-key\">" + h.esc(short) + "</span>"
        + "<span class=\"vl-metric\"><small>1 h</small> " + h.esc(score(v.agreement1h)) + "</span>"
        + "<span class=\"vl-metric\"><small>" + h.esc(h.t("validator.missed")) + "</small> " + h.esc(pct(v.agreement1h) == null ? "–" : pct(v.agreement1h) + " %") + "</span>"
        + "<span class=\"vl-metric\"><small>24 h</small> " + h.esc(score(v.agreement24h)) + "</span>"
        + "<span class=\"vl-metric\"><small>30 d</small> " + h.esc(score(v.agreement30d)) + "</span></li>";
    }).join("");
    alerts.innerHTML = (Array.isArray(body?.alerts) ? body.alerts : []).slice(0, 12).map((a) =>
      "<li class=\"vl-alert vl-" + (a.severity === "malicious" ? "bad" : "warn") + "\"><span class=\"vl-type\">" + h.esc(h.t("validator.alert." + a.type)) + "</span>"
      + "<span class=\"vl-key\">" + h.esc(String(a.key || "").slice(0, 16)) + "…</span></li>").join("");
  }

  function paintValidatorError() {
    const empty = document.getElementById("validator-empty");
    if (empty) { empty.textContent = h.t("validator.error"); empty.hidden = false; }
  }

  // Validator-Gesundheit (xrpscan, serverseitig gecacht): Takt 60 s, nur wenn das Panel existiert.
  function startValidatorPanel() {
    if (!document.getElementById("validator-list")) return;
    const tick = async () => {
      try {
        const res = await fetch("/api/validators", { cache: "no-store" });
        if (!res.ok) throw new Error("HTTP " + res.status);
        paintValidators(await res.json());
      } catch { paintValidatorError(); }
    };
    void tick();
    setInterval(tick, 60000);
  }

  function init() { paintPattern(); paintTicker(); startValidatorPanel(); }

  return { record, init };
}
