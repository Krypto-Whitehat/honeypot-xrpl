// public/validator-trace.mjs — Validator-Trace-Overlay (lazy geladen aus live-monitor.mjs).
// Ein Validator: Karten, 3D-Abweichungsprofil, Retrace-Diagnose je Ledger, Risikoprofil,
// Korrelationen und Zeitleiste. Musterblick: wiederkehrende Muster und Sammelereignisse
// über alle dUNL-Validatoren.
// Alle Inhalte laufen durch h.esc; Schlüssel werden gekürzt angezeigt.
//
// 3D ist CSS-Geometrie (kein WebGL, keine neue Abhängigkeit). Je Zeitintervall ein Prisma aus
// Vorder-, Seiten- und Deckelfläche, gestapelt nach Vorfallstyp. Der Tiefenvektor ist (+d, -dz);
// Seitenfläche skewY, Deckelfläche skewX mit demselben Winkel, damit die Kanten zusammenlaufen
// (tan 45° ≈ dz/d). Balkenhöhe und Achse teilen sich ein Maß: --u = Plot-Höhe / Achsenmaximum,
// ein Balken mit --n Vorfällen ist deshalb zwingend so hoch, wie die Gitterlinie bei n sagt.
import { registerDict } from './i18n.mjs';
import { VALIDATOR_DICT } from './i18n-validator.mjs';

// Die vt.*-Texte liegen in public/i18n-validator.mjs und werden erst hier angemeldet.
// Dieses Modul laedt live-monitor.mjs dynamisch - die Startseite zahlt sie nicht.
registerDict(VALIDATOR_DICT);

const RANGES = ["1h", "24h", "7d", "30d", "all"];
const BUCKETS = 24;
const AXIS_TICKS = [0, 6, 12, 18];
const PROFILE_TYPES = ["missed", "partial", "wrongHash", "noQuorum"];
const TYPE_KEY = { missed: "missed", partial: "partial", "wrong-hash": "wrongHash", "no-quorum": "noQuorum", "vote-not-observed": "noQuorum" };
const SPAN_MS = { "1h": 3600000, "24h": 86400000, "7d": 7 * 86400000, "30d": 30 * 86400000, all: null };
const RETRACE_SHOWN = 12;
const RISK_ROWS = 12;
// Ursache-Tabelle: die Vorfaelle mit Urteil, nicht die rohe Zeitleiste. 12 Zeilen sind auf einem
// Bildschirm lesbar; die Zahl der erklaerten Vorfaelle steht in der Reduktions-Zeile.
const CAUSE_ROWS = 12;
// Beleg-Arten der Erfassungs-Luecke, dieselben Namen wie CAPTURE_GAP_BASES in lib/validator-trace.mjs.
// Nur diese beiden fuehren die Beschriftung des Belegs; 'not-recorded' bekommt keine Basis, weil es
// keine gibt. Der UI-Name ist absichtlich identisch: dieselbe Vokabel in Analyse und Anzeige.
const CAPTURE_BASES = new Set(["ledger-index", "stream-gap", "stream-open"]);
// Die Dosis-Urteile, dieselbe Menge wie in der Lib (lib/validator-stress-coupling.mjs): ein
// Urteil, das hier nicht bekannt ist, wird nicht still als "flach" gezeigt, sondern als offen.
const LOAD_TREND_VERDICTS = new Set(["load-dose-rising", "load-dose-flat", "load-dose-falling", "not-comparable", "insufficient-sample"]);
// Herleitung des Quorum-Ziels mit denselben Namen wie NEEDED_BASES in lib/validator-trace.mjs.
// "not-recorded" hat ein Label, weil die Zeile trotzdem ein Ziel zeigt: ohne Beschriftung
// waere "16 / 28" ein Ziel, dessen Herkunft niemand pruefen kann. "day-measured" = die
// Zeile nennt ihre Herleitung nicht, aber derselbe Tag hat genau dieses Ziel am Endpunkt
// gemessen - ohne diesen Zustand wuerfe die Overlay-Menge jede solche Zeile auf "nicht erfasst".
const NEEDED_BASES = new Set(["measured", "derived", "not-recorded", "day-measured"]);
// Ereignis-Arten mit denselben Namen wie CAPTURE_EVENT_KINDS in lib/validator-trace.mjs und wie
// sie der Rekorder schreibt. 'near' ist kein Ereignis-Typ, sondern die Beschriftung fuer einen
// Typ, den dieses Overlay nicht kennt: ohne sie waere ein unbekanntes Ereignis als 'Stream neu
// aufgebaut' dargestellt - eine Aussage, die nicht belegt ist.
const CAPTURE_EVENT_KINDS = new Set(["open", "close", "stall", "ledger-no-hash"]);
// Gegenprobe-Zustaende mit denselben Namen wie TRUTH_VERDICTS in lib/validator-truth.mjs:
// die UI zeigt genau die drei Urteile, die die Lib rechnen kann - kein eigener Zustand, keine
// eigene Deutung, kein zusaetzlicher Puffer zwischen Messung und Text.
const TRUTH_STATES = new Set(["consistent", "contradicted", "not-comparable"]);

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
  let txt = h.t(key);
  if (!txt || txt === key) {
    // Serien-Tags (offline-window, brief-outage, cohort-window) haben ihr Label in der
    // Urteils-Namensraum-Gruppe vt.verdict.* - ohne diesen Griff stand der Rohname in der
    // Hypothesenliste, obwohl beide Sprachen lang laengst ein Label fuer genau diesen Tag haben.
    const alt = "vt.verdict." + base;
    const altTxt = h.t(alt);
    txt = altTxt && altTxt !== alt ? altTxt : null;
  }
  if (!txt) return String(tag);
  // new-tx-type:<TYP> und type-burst:<TYP> tragen den Typ im Tag - ohne ihn waere die Anzeige
  // eine allgemeine Floskel ohne den eigentlichen Transaktionstyp.
  return base === "new-tx-type" || base === "type-burst" ? txt + " " + String(tag).slice(base.length + 1) : txt;
}

// Achsenmaß: peak ist ein Vielfaches von step, und es entstehen höchstens 5 Gitterintervalle.
export function axisScale(max) {
  const m = Math.max(1, max);
  for (const s of [1, 2, 5, 10, 20, 25, 50, 100, 200, 250, 500, 1000, 2000, 5000]) {
    const peak = Math.ceil(m / s) * s;
    if (peak / s <= 5) return { peak, step: s, ticks: axisTicks(peak) };
  }
  const s = Math.ceil(m / 5);
  const peak = s * 5;
  return { peak, step: s, ticks: axisTicks(peak) };
}

// Die Gitterlinien einer logarithmischen Achse: Dekaden und die Spitze, nicht Achsschritte.
// Achsschritte waeren auf einer Log-Achse oben zusammengedrueckt - bei peak 5000 stuenden
// 1000 / 2000 / 3000 / 4000 / 5000 auf 81 / 89 / 94 / 97 / 100 % der Hoehe, vier Linien auf den
// letzten 19 %. Dekaden tragen die wahren Zahlen und sind nahezu gleich abstaendig - den Preis
// (und die nachgerechneten Verhaeltnisse 0,7404 / 0,9961) steht in axisUnit.
// Unterhalb von peak 10 sind es die ganzen Zahlen selbst. Die Zahl der Intervalle bleibt durch
// den Achsleiter (peak / step <= 5) auf fuenf begrenzt.
export function axisTicks(peak) {
  const p = Math.max(1, Math.round(Number(peak) || 1));
  const ticks = [0];
  if (p < 10) {
    const st = p <= 5 ? 1 : 2;
    for (let v = st; v < p; v += st) ticks.push(v);
    ticks.push(p);
    return ticks;
  }
  for (let d = 1; d <= p; d *= 10) ticks.push(d);
  if (ticks[ticks.length - 1] !== p) ticks.push(p);
  return ticks;
}

// Kappe zu Koerper: eine Deckflaeche, die hoeher ist als der Koerper darunter, kippt die Lesung
// - aus einer Saeule wird ein Keil, und die scheinbare Hoehe ist ein Vielfaches des wahren
// Wertes in einer Skala, die vergleichen soll. Ein Drittel ist die Grenze, bei der die Kappe
// noch als Flaeche und der Koerper noch als Saeule gelesen wird. Gemessen 2026-10-16 live im
// ausgelieferten Overlay (7d-Fenster, peak 400, Plot 176 px, Zelle 30,88 px): 6,78 px Kappe an
// 8,80 px Koerper = 0,77, Silhouette 30,88 px breit gegen 15,58 px hoch. Das war der schraegen
// Eindruck - nicht der Winkel, und auch nicht die Tiefe allein.
export const CAP_RATIO = 1 / 3;

// Dasselbe tan(45deg) wie CSS --dz-k: die Kappe ist --dc * 1 hoch, also ist die groesste Tiefe,
// die auf einen Koerper von einer gegebenen Hoehe passt, genau diese Hoehe / 1. Eine waagerechte
// Deckflaeche kann in einer Ansicht von oben nie hoeher sein als sie tief ist (tan <= 1); bei
// tan 1 sind Kappe und Tiefe derselbe Wert - kanonische Kavaliere-Projektion und die obere
// Grenze dessen, was eine Ansicht von oben ueberhaupt zeigen kann.
// Ein Wertepaar wie 15/13 ware nur fuer eine einzige Breite geschlossen - hier ist es eine Zahl.
export const DEPTH_SKEW_K = 1;

// Achsenposition eines Wertes, in Achseneinheiten (peak entspricht --peak / 100 %).
//
// Die Skala ist logarithmisch in log(1 + v), weil die Vorfall-Zahlen ueber ein Fenster extrem
// schief liegen: 4.502 Abweichungen in einem Intervall neben 1 in einem anderen. Linear waere
// ein Vorfall bei peak 5000 ein 0,04-px-Streifen (208 px Plot) - unsichtbar, und das Profil
// wirkte leer, obwohl etwas gemessen wurde. log(1 + v) ist ohne Untergrenze exakt (peak -> peak),
// macht kleine Werte sichtbar und legt 1 und 2 nicht auf dieselbe Hoehe. Die Dekaden sind dabei
// gerade NICHT gleich abstaendig: der Abstand waechst mit den Werten und bleibt von unten unter
// dem asymptotischen Dekadenabstand peak * ln(10) / ln(1 + peak). 1 -> 10 misst immer 0,7404
// davon, 100 -> 1000 immer 0,9961 - die peak-Faktoren kuerzen sich heraus, die Verhaeltnisse sind
// also unabhaengig von der Achshoehe. Nachgerechnet im Guard der Markup-Tests.
//
// Warum Log und nicht die alte Wurzel: die Kappe --dzc ist je Profil eine feste Zahl, und die
// Wurzel gab bei peak 400 den kurzesten gezeichneten Koerper 8,80 px (Plot 176 px) - zu kurz fuer
// jede Kappe, die als Flaeche lesbar bleibt. Log gibt bei demselben peak 24,05 px (Plot 208 px):
// die Kappe bleibt unter einem Drittel des Korpers, siehe CAP_RATIO.
// Die wahren Zahlen stehen in Gitterlinie, Wertemarke, Readout und aria-label.
export function axisUnit(value, peak) {
  const v = Number(value) || 0;
  const p = Math.max(1, Number(peak) || 1);
  if (v <= 0) return 0;
  return (p * Math.log1p(v)) / Math.log1p(p);
}

export function createValidatorTrace(h) {
  let overlay = null;
  const tl = (tag) => tagLabel(h, tag);
  // "1 others" ist kein Deutsch und kein Englisch. Das Zahlwort haengt an der Zahl, nicht an
  // der Sprache des Lesers - beide Sprachen haben dafuer eigene Schluessel.
  const otherWord = (n) => h.t(n === 1 ? "vt.otherOne" : "vt.otherMany");
  let current = { mode: "validator", master: null, title: "", range: "24h" };
  // Master-Key -> Domain. Die Namen kommen aus der bereits gezeichneten Validatorenliste
  // (live-monitor.mjs): kein zusätzlicher Request, keine erfundene Bezeichnung. Ohne Eintrag
  // steht der gekuerzte Key da - ein Key ist kein Name.
  let nameMap = new Map();
  const shortKey = (m) => String(m).slice(0, 10) + "…" + String(m).slice(-6);
  const nameOf = (m) => nameMap.get(m) || shortKey(m);
  const PEER_SHOWN = 12;
  // truth (optional, indexgleich zu keys): das Gegenurteil je Knoten aus der Lib. Ohne es
  // bleibt der Chip eine reine Namensnennung - mit ihm steht an jedem Knoten, ob die Referenz
  // seine Abwesenheit traegt oder widerlegt. Der Titel ist der Text, den die Lib rechnet.
  const peerChips = (keys, truth, names) => {
    const list = Array.isArray(keys) ? keys : [];
    // names (indexgleich zu keys) kommt aus der Lib und damit aus der Netz-Auskunft: ein Knoten,
    // der die gerade geladene dUNL-Liste verlassen hat, ist dann trotzdem benannt.
    // Name und Gegenurteil werden ueber den Master-Key geholt, nicht ueber die Position.
    // names und truth sind indexgleich zu keys. Die Darstellung schneidet keys aber in zwei
    // Stuecke (shown / rest), und map liefert die Position innerhalb des Schnitts. Ueber die
    // Position haette der zweite Schnitt die Namen und Urteile des ersten: ab dem 13. Knoten
    // stuende ein Knoten mit dem Namen eines anderen da. Live nachgerechnet am 2026-10-17 auf
    // #107694001: 34 benannte Knoten, die 22 verborgenen trugen die Namen 1-22, die Knoten
    // 23-34 blieben ganz ungenannt.
    const byMaster = new Map();
    for (let i = 0; i < list.length; i++) {
      const n = Array.isArray(names) ? names[i] : null;
      const t = Array.isArray(truth) ? truth[i] : null;
      const entry = byMaster.get(list[i]) ?? {};
      if (entry.name === undefined) entry.name = n && typeof n.name === "string" && n.name ? n.name : null;
      if (entry.truth === undefined) entry.truth = t ?? null;
      byMaster.set(list[i], entry);
    }
    const chip = (m) => {
      const e = byMaster.get(m) ?? {};
      const label = e.name ?? nameOf(m);
      const t = e.truth;
      if (!t) return '<span class="vt-peer">' + h.esc(label) + "</span>";
      const verdict = TRUTH_STATES.has(t.verdict) ? t.verdict : "not-comparable";
      const tip = h.t("vt.cq.truth." + verdict, { claims: num(t.claims), ground: num(t.groundMissed),
        total: num(t.groundTotal), min: num(t.falsePositiveMin) });
      return '<span class="vt-peer vt-peer-' + verdict + '" title="' + h.esc(tip) + '">' + h.esc(label) + "</span>";
    };
    const shown = list.slice(0, PEER_SHOWN).map(chip).join("");
    if (list.length <= PEER_SHOWN) return shown;
    const rest = list.slice(PEER_SHOWN).map(chip).join("");
    return shown
      + '<span class="vt-peer-rest" hidden>' + rest + "</span>"
      + '<button type="button" class="vt-peer-more" data-peer-more>'
      + h.esc(h.t("vt.peersMore", { n: list.length - PEER_SHOWN })) + "</button>";
  };

  // null ist 'nicht erfasst', 0 ist 'gemessen null'. Number(null) === 0 machte aus jeder
  // nicht erfassten Zahl eine 0 im Text - eine vorgetaeuschte Messung, die einen Knoten
  // entlastet oder belastet, fuer den nichts aufgezeichnet wurde.
  const num = (v) => (v === null || v === undefined
    ? "–" : Number.isFinite(Number(v)) ? String(Number(v)) : "–");
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
  const DIAG_TYPE = { missed: "missed", partial: "partial", wrongHash: "wrong-hash", noQuorum: "no-quorum", "vote-not-observed": "vote-not-observed", "no-quorum": "no-quorum" };
  // Die Schliess-Autoritaet gehoert zum Urteil, nicht in eine Fussnote: eigener Strom, validierter
  // Ledger-Strom und die Fremdquelle xrpscan sind verschiedene Belege und werden benannt.
  const CLOSURE_BASIS_KEY = { recorder: "vt.lat.basis.recorder", "validated-ledger-stream": "vt.lat.basis.stream", xrpscan: "vt.lat.basis.xrpscan" };

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
    } catch (err) { console.error("validator-trace render failed:", err);
      body.innerHTML = '<p class="vt-empty">' + h.esc(h.t("vt.error")) + "</p>";
    }
  }
// Ground-Truth-Gegenprobe je Knoten: die eigene Abwesenheits-Zahl gegen die Zahl, die das
// Netz fuer denselben Knoten im selben Fenster nennt. Die Differenz ist eine nachrechenbare
// Untergrenze fuer die eigene Erfassung - keine Deutung, keine Schaetzung. Ohne Referenz
// steht die Frage offen; sie wird nie als Entlastung gelesen.
// Die Fensterzahl der Gegenprobe ist eine Auswahl, keine Konstante: sie haengt an der eigenen
// Spanne (1 h / 24 h / 30 d). Der Text muss sie nennen, sonst ist "dasselbe Fenster" eine
// Behauptung statt eine nachrechenbare Angabe.
function truthWindowLabel(hours) {
  const span = Number.isFinite(hours) ? hours : null;
  if (span === null) return "–";
  return span >= 720 ? h.t("vt.truth.window30d") : span <= 1 ? h.t("vt.truth.window1h") : h.t("vt.truth.window24h");
}

function truthBlock(t) {
  if (!t) return "";
  const n = (x) => (Number.isFinite(Number(x)) ? String(Number(x)) : "–");
  const state = TRUTH_STATES.has(t.verdict) ? t.verdict : "none";
  // Das Fenster ist keine Konstante mehr: die Gegenprobe rechnet gegen das Fenster, das die
  // eigene Spanne deckt (1 h / 24 h / 30 d). Ohne die Zahl im Text waere "dasselbe Fenster"
  // eine Behauptung statt eine nachrechenbare Angabe.
  const window = truthWindowLabel(t.window?.hours);
  // consistent mit Behauptungen nur ausserhalb des Fensters ist kein Freispruch: die Zahl sagt
  // nur, dass in diesem Fenster nichts steht. Das muss dabeistehen.
  const outside = Number.isFinite(t.claimsOutside) && t.claimsOutside > 0
    ? " " + h.esc(h.t("vt.truth.outside", { outside: n(t.claimsOutside) })) : "";
  // Die Deckung der Referenz ist Teil des Urteils: eine 24-h-Referenz beantwortet von einer
  // 30-Tage-Frage 24 h und laesst 696 h offen. Ohne diesen Satz wuerde die Teildeckung als
  // Antwort auf die ganze Spanne gelesen.
  const cover = t.coverage === "partial"
    ? " " + h.esc(h.t("vt.truth.partial", { covered: n(t.coveredHours) + " h", open: n(t.openHours) + " h" }))
    : t.coverage === "unusable" ? " " + h.esc(h.t("vt.truth.unusable")) : "";
  const body = state === "contradicted"
    ? h.t("vt.truth.contradicted", { claims: n(t.claims), ground: n(t.groundMissed), total: n(t.groundTotal), min: n(t.falsePositiveMin), window })
    : state === "consistent"
      ? h.t("vt.truth.consistent", { claims: n(t.claims), ground: n(t.groundMissed), total: n(t.groundTotal) })
      : h.t("vt.truth.none");
  return '<p class="vt-truth vt-truth-' + state + '"><small>' + h.esc(h.t("vt.truth.title")) + "</small> "
    + h.esc(body) + outside + cover + " " + h.esc(h.t("vt.truth.ledgerIdentity")) + "</p>";
}

// Die Zurechnung der Abwesenheits-Zaehler. Sie steht direkt unter den Karten, weil die Karten
// sonst als Knoten-Urteil gelesen werden, obwohl sie eine Erfassungsbeobachtung sind: auf
// bewiesen geschlossenen Ledern ist 'kein Vote erfasst' erst dann eine Abweichung dieses Knoten,
// wenn die Netz-Referenz dieselbe Abwesenheit fuer denselben Knoten im selben Fenster nennt.
function attributionBlock(a) {
  if (!a || !Number.isFinite(a.absenceClaims)) return "";
  const n = (x) => (Number.isFinite(Number(x)) ? String(Number(x)) : "–");
  const rate = (v) => (Number.isFinite(v) ? (Math.round(v * 1000) / 10).toFixed(1) : "–");
  const state = a.state === "bounded" ? (a.artifactMin > 0 ? "contradicted" : "covered") : "open";
  const body = a.state === "bounded"
    ? h.t("vt.attr.bounded", { claims: n(a.absenceClaims), attributable: n(a.attributableMax), artifact: n(a.artifactMin), open: n(a.openClaims), ground: n(a.groundMissed), rate: rate(a.rateMax) })
    : h.t("vt.attr.open", { claims: n(a.absenceClaims) });
  const cover = a.coverage === "partial"
    ? " " + h.t("vt.attr.partial", { covered: n(a.coveredHours) + " h", open: n(a.openHours) + " h" })
    : a.coverage === "unusable" ? " " + h.t("vt.attr.unusable") : "";
  return '<p class="vt-attr vt-attr-' + state + '"><small>' + h.t("vt.attr.title") + "</small> "
    + h.esc(body) + h.esc(cover) + "</p>";
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
    // Der Quorum-Zaehler bekommt seinen nachrechenbaren Anteil direkt daneben: die
    // Zahl der Ledger, deren Ziel und fuehrende Linie in einer Forensik-Zeile steht,
    // und die Zahl der Ledger, die nur im Zaehler stehen. Ohne diese Zeile waere
    // '11 unter Ziel' eine Aussage, die kein Betreiber nachschlagen kann.
    const quorumNote = Number(c.quorumFail) > 0
      ? '<p class="vt-coverage"><small>' + h.esc(h.t("vt.coverageQuorumLabel")) + "</small> "
        + h.esc(h.t("vt.coverageQuorum", { named: c.quorumShortRows ?? 0, rest: c.quorumCounterUnattributed ?? 0 })) + "</p>"
      : "";
    // Die Spanne zwischen zwei Tagesdateien: hier wurde kein Ledger bewertet. Das ist eine
    // Aussage ueber die Aufzeichnung, nicht ueber das Netz, und sie darf nicht zu nichts
    // passiert zusammengefasst werden.
    const holeNote = Number(c.unobservedRanges) > 0
      ? '<p class="vt-coverage"><small>' + h.esc(h.t("vt.coverageHoleLabel")) + "</small> "
        + h.esc(h.t("vt.coverageHole", { ranges: c.unobservedRanges ?? 0, minutes: Math.round((c.unobservedMs ?? 0) / 60000),
          from: c.unobservedLargest?.fromIso ? c.unobservedLargest.fromIso.slice(5, 16).replace("T", " ") : "–",
          to: c.unobservedLargest?.toIso ? c.unobservedLargest.toIso.slice(5, 16).replace("T", " ") : "–" })) + "</p>"
      : "";
    // Fenster-genaue Karten (Stundenzähler), sonst Tages-Gesamtzähler mit Hinweis.
    const w = d.inWindow;
    const src = w || d.summary;
    const scopeTag = w
      ? '<p class="vt-scope"><small>' + h.esc(h.t("vt.inWindow")) + (w.estimated ? " · " + h.esc(h.t("vt.estimated")) : "")
        + (w.observedDayOnly > 0 ? " · " + h.esc(h.t("vt.inWindowDayOnly", { ledgers: w.observedDayOnly, days: w.daysPartial ?? 0 })) : "") + "</small></p>"
      : '<p class="vt-scope"><small>' + h.esc(h.t("vt.totals")) + "</small></p>";
    const attributionLine = attributionBlock(d.attribution);
    const cards = [["ok", src.ok], ["partial", src.partial], ["missed", src.missed], ["no-quorum", src.noQuorum ?? 0], ["wrong-hash", src.wrongHash], ["observed", src.observed]]
      .map(([k, v]) => '<div class="vt-card vt-' + k + '"><small>' + h.esc(h.t("vt.k." + k)) + "</small><b>" + h.esc(String(v)) + "</b></div>").join("");
    const totalLine = w
      ? '<p class="vt-scope"><small>' + h.esc(h.t("vt.totals")) + "</small> ok " + h.esc(String(d.summary.ok)) + " · " + h.esc(h.t("vt.k.missed")) + " " + h.esc(String(d.summary.missed)) + " · " + h.esc(h.t("vt.k.no-quorum")) + " " + h.esc(String(d.summary.noQuorum ?? 0)) + " · " + h.esc(h.t("vt.k.wrong-hash")) + " " + h.esc(String(d.summary.wrongHash)) + "</p>"
      : "";
    const noData = !d.summary.observed && !(d.incidents || []).length
      ? '<p class="vt-empty">' + h.esc(h.t("vt.nodata")) + "</p>"
      : "";
    body.innerHTML = keyLine + refLine + truthBlock(d.truth) + coverageLine + quorumNote + holeNote + scopeTag
      + '<div class="vt-cards">' + cards + "</div>" + attributionLine + totalLine + noData
      + '<h3 class="vt-h">' + h.esc(h.t("vt.model3d")) + "</h3>" + profile3d(d.incidents, d.range, d.profile, d.coverage)
      + '<h3 class="vt-h">' + h.esc(h.t("vt.causeTitle")) + '</h3><p class="vt-sub">' + h.esc(h.t("vt.causeNote")) + "</p>"
      + causeBlock(d.cause)
      + '<h3 class="vt-h">' + h.esc(h.t("vt.surfaceTitle")) + '</h3><p class="vt-sub">' + h.esc(h.t("vt.surfaceNote")) + "</p>"
      + surfaceBlock(d.surface)
      + '<h3 class="vt-h">' + h.esc(h.t("vt.couplingTitle")) + '</h3><p class="vt-sub">' + h.esc(h.t("vt.couplingNote")) + "</p>"
      + couplingBlock(d.coupling)      + '<h3 class="vt-h">' + h.esc(h.t("vt.peerTitle")) + '</h3><p class="vt-sub">' + h.esc(h.t("vt.peerNote")) + "</p>"
      + peerBlock(d.peer, d.absence)
      + '<h3 class="vt-h">' + h.esc(h.t("vt.latTitle")) + '</h3><p class="vt-sub">' + h.esc(h.t("vt.latNote")) + "</p>"
      + latencyBlock(d.diagnosis && d.diagnosis.latency)
      + '<h3 class="vt-h">' + h.esc(h.t("vt.divTitle")) + '</h3><p class="vt-sub">' + h.esc(h.t("vt.divNote")) + "</p>"
      + divergenceBlock(d.divergence)
      + '<h3 class="vt-h">' + h.esc(h.t("vt.retraceTitle")) + "</h3>"
      + '<p class="vt-sub">' + h.esc(h.t("vt.retraceNote")) + "</p>" + retraceBlock(d.retrace, d.retraceTotal)
      + '<h3 class="vt-h">' + h.esc(h.t("vt.fpTitle")) + '</h3><p class="vt-sub">' + h.esc(h.t("vt.fpNote")) + "</p>"
      + fingerprintBlock(d.diagnosis && d.diagnosis.fingerprint)
      + '<h3 class="vt-h">' + h.esc(h.t("vt.cqTitle")) + '</h3><p class="vt-sub">' + h.esc(h.t("vt.cqNote")) + "</p>"
      + criticalityBlock(d.diagnosis && d.diagnosis.criticality)
      + '<h3 class="vt-h">' + h.esc(h.t("vt.loadTitle")) + '</h3><p class="vt-sub">' + h.esc(h.t("vt.loadNote")) + "</p>"
      + loadCurveBlock(d.diagnosis && d.diagnosis.load, true)
      + '<h3 class="vt-h">' + h.esc(h.t("vt.riskTitle")) + "</h3>"
      + '<p class="vt-sub">' + h.esc(h.t("vt.riskNote")) + "</p>" + riskBlock(d.risk)
      + '<h3 class="vt-h">' + h.esc(h.t("vt.sensTitle")) + "</h3>"
      + '<p class="vt-sub">' + h.esc(h.t("vt.sensIntro")) + "</p>" + sensitivityBlock(d.sensitivity)
      + '<h3 class="vt-h">' + h.esc(h.t("vt.patterns")) + "</h3>" + chips(d.patterns)
      + gapsBlock(d.gaps)
      + '<h3 class="vt-h">' + h.esc(h.t("vt.timeline")) + "</h3>" + timeline(d.incidents);
  }

  // Achsenbeschriftung je Intervall: Stunden/Minuten bei kurzen Fenstern, Datum bei langen.
  function bucketLabel(from, width, i, range) {
    const iso = new Date(from + (i / BUCKETS) * width).toISOString();
    return range === "7d" || range === "30d" || range === "all" ? iso.slice(5, 10) : iso.slice(11, 16);
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
  //   Wertemarke         = dieselbe Zahl als Text (die Balkenhoehe ist eine Sichtbarkeitsregel)
  //   Stapelfarben       = Vorfallstyp
  //   Bodenplatte + Streifen = Intervall-Zustand (clean / solo / cohort / network / unknown / none)
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
    const { peak, ticks: gridTicks } = axisScale(Math.max(...cells.map((x) => x.total)));
    // Die Kappe muss auf ihren Koerper passen, und zwar fuer die kurzeste Saeule des Profils.
    // --dzc = --dc * tan(45deg), also ist die groesste zeichnbare Tiefe die kurzeste
    // Saeulenhoehe / tan. Angegeben als Anteil der Plot-Hoehe, damit sie mit der kleineren
    // Mobile-Plot-Hoehe mitgeht. Ohne diese Grenze wird aus einem 1-Vorfall-Intervall neben
    // einem 4.502-Vorfall-Intervall eine Kappe, die hoeher ist als ihr eigener Koerper, und die
    // scheinbare Hoehe ist dann ein Vielfaches des wahren Wertes - in einer Skala, die
    // Vergleichen soll. Die Grenze ist je Profil eine Zahl, nicht je Saeule eine Klammer:
    // alle 24 Intervalle behalten dieselbe Projektion. Die Grenze ist CAP_RATIO mal dem
    // kurzesten gezeichneten Koerper: eine Kappe ueber einem Drittel davon macht aus der Saeule
    // einen Keil, und der Keil ist das, was schraeg aussieht.
    const heights = cells.map((cell) => axisUnit(cell.total, peak));
    const drawn = heights.filter((u) => u > 0);
    const smallestUnit = drawn.length ? Math.min(...drawn) : peak;
    const depthRatio = ((smallestUnit / peak) * CAP_RATIO) / DEPTH_SKEW_K;
    const grid = [];
    for (const v of gridTicks) {
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
      const est = cell.ledgersEstimated > 0
        ? " . " + h.t(cell.ledgers > 0 ? "vt.bucketLedgersEstimated" : "vt.bucketLedgersOnlyEstimated",
          { n: num(cell.ledgersEstimated) }) : "";
      return '<div class="vt-col vt-state-' + state + (cell.total ? " vt-nonzero" : "") + '" tabindex="0" role="group" style="' + style + '" data-tip="'
        + h.esc(h.t("vt.bucketReadout", args) + (topTags ? " . " + topTags : "") + est) + '" aria-label="'
        + h.esc(h.t("vt.bucketAria", args) + est) + '">'
        + '<span class="vt-base" aria-hidden="true"></span>'
        + '<div class="vt-bar">'
        + (cell.total ? '<span class="vt-side" aria-hidden="true"></span><span class="vt-top" aria-hidden="true"></span>' : "")
        + "</div>"
        + (cell.total ? '<span class="vt-value" aria-hidden="true">' + h.esc(String(cell.total)) + "</span>" : "")
        + (sign === "hit" ? '<span class="vt-mark" aria-hidden="true"></span>' : "")
        + "</div>";
    }).join("");
    const heat = cells.map((cell) => '<span class="vt-heat-cell vt-state-' + stateOf(cell) + '"></span>').join("");
    const signStrip = cells.map((cell) => '<span class="vt-sign-cell vt-sign-' + signStateOf(cell, shapeLayer) + '"></span>').join("");
    // Die Achse muss auf denselben Intervallen stehen wie die Saulen und die Streifen
    // darunter. Die Saulen haben eine Flex-Teilung (Saulenbreite + Abstand), die Achse war
    // gleichmaessig ueber die Plot-Breite verteilt. Nachgerechnet im 24-Intervall-Fenster:
    // der erste Tick 3,7 px rechts von seiner Saule, der letzte 3,7 px links davon - die
    // Achse driftet uber das Fenster, obwohl Saulen und Streifen exakt deckungsgleich sind.
    const ticks = AXIS_TICKS.map((i) => '<span style="left:calc((var(--col-w) + var(--gap)) * ' + i + ' + var(--col-w) / 2)">'
      + h.esc(bucketLabel(from, width, i, range)) + "</span>").join("");
    const legendHtml = PROFILE_TYPES.map((k) => '<li><span class="vt-swatch vt-c-' + k + '"></span>'
      + h.esc(h.t("vt.k." + (k === "wrongHash" ? "wrong-hash" : k === "noQuorum" ? "no-quorum" : k))) + " " + h.esc(String(legend[k])) + "</li>").join("");
    const stateLegend = STATES.map((k) => '<li><span class="vt-heat-key vt-state-' + k + '"></span>'
      + h.esc(h.t("vt.state." + k)) + " " + h.esc(String(states[k])) + "</li>").join("");
    const signLegend = SIGN_STATES.map((k) => '<li><span class="vt-sign-key vt-sign-' + k + '"></span>'
      + h.esc(h.t("vt.sign." + k)) + " " + h.esc(String(signs[k])) + "</li>").join("");
    const spanLabel = (ms) => new Date(ms).toISOString().slice(5, 16).replace("T", " ");
    const scale = h.t("vt.axisScaleLog");
    const meta = h.t("vt.profileMeta", { buckets: BUCKETS, from: spanLabel(from), to: spanLabel(now), peak, scale });
    const shapeNote = shapeLayer
      ? h.t("vt.signCoverage", { seen: num(coverage.shapeSeen), missing: num(coverage.shapeMissing) })
      : h.t("vt.signAbsent");
    // Der Nenner des Profils ist nicht ueberall gemessen: Tage ohne Stunden-Buckets liefern
    // Ledger auf Tages-Koernung. Diese Zahl gehoert unters Profil, nicht in eine Fussnote.
    const estNote = profile.estimatedLedgers > 0
      ? h.t("vt.profileLedgersEstimated", { n: num(profile.estimatedLedgers) }) : "";
    return '<div class="vt-profile" style="--peak:' + peak + ';--dmax:' + depthRatio.toFixed(4) + '">'
      + '<div class="vt-profile-top"><p class="vt-profile-meta">' + h.esc(meta) + "</p>"
      + '<p class="vt-readout" id="vt-readout" aria-live="polite">' + h.esc(h.t("vt.profileHint")) + "</p></div>"
      + '<div class="vt-plot"><span class="vt-floor" aria-hidden="true"></span><span class="vt-floor-top" aria-hidden="true"></span><div class="vt-grid" aria-hidden="true">' + grid.join("") + "</div>"
      + '<div class="vt-bars">' + cols + "</div></div>"
      + '<div class="vt-axis" aria-hidden="true">' + ticks + "</div>"
      + '<div class="vt-heat" role="img" aria-label="' + h.esc(h.t("vt.heatAria")) + '">' + heat + "</div>"
      + '<div class="vt-sign" role="img" aria-label="' + h.esc(h.t("vt.signAria")) + '">' + signStrip + "</div>"
      + '<ul class="vt-legend">' + legendHtml + "</ul>"
      + '<ul class="vt-legend vt-heat-legend">' + stateLegend + "</ul>"
      + '<ul class="vt-legend vt-sign-legend">' + signLegend + "</ul>"
      + '<p class="vt-note vt-sign-note">' + h.esc(shapeNote) + "</p>"
      + (estNote ? '<p class="vt-note vt-est-note">' + h.esc(estNote) + "</p>" : "")
      + "</div>";
  }

  function evidenceText(hy) {
    const e = hy.evidence || {};
    if (hy.tag === "quorum-thin") return h.t("vt.evMargin", { top: num(e.topVotes), needed: num(e.needed), margin: num(e.margin) });
    if (hy.tag === "vote-coverage-thin") {
      const base = h.t("vt.evCoverage", {
        top: num(e.topVotes), needed: num(e.needed), observed: num(e.observedValidations),
        hash: e.closedHash ? h.esc(String(e.closedHash).slice(0, 12)) + "…" : h.t("vt.cq.hashMissing"),
        gap: e.captureGap === true ? h.t("vt.cq.captureGap")
          : e.captureGap === false ? h.t("vt.cq.noCaptureGap")
            : h.t("vt.cq.captureGapUnknown"),
      });
      const bound = Number.isFinite(e.genuineAbsentMax) && Number.isFinite(e.captureArtifactMin)
        ? " · " + h.t("vt.evCoverageBound", {
          absent: num(e.absentCount), max: num(e.genuineAbsentMax), min: num(e.captureArtifactMin) })
        : "";
      return base + bound;
    }
    if (hy.tag === "hash-split") return h.t("vt.evSplit", { runner: num(e.runnerVotes), votes: num(e.votes) });
    if (hy.tag === "load-spike" || hy.tag === "load-extreme") return h.t("vt.evLoad", { tx: num(e.txCount), med: num(e.medianTx), ratio: fac(e.ratio) });
    if (hy.tag === "close-gap") {
      // Der Abstand ist nur dann ein Netz-Takt, wenn die Index-Folge dieses Recorders als
      // durchgehend gemessen ist. Sonst steht die Grenze daneben, nicht versteckt.
      const basis = e.indexContinuity === true ? "" : " " + h.t("vt.evGapIndexUnknown");
      return h.t("vt.evGap", { gap: sec(e.closeGapMs), med: sec(e.medianGapMs) }) + basis;
    }
    if (hy.tag === "cohort-event") {
      // "19 andere" ist nur die Hälfte der Aussage: erst der gleiche Vorfallstyp zeigt, ob
      // dieselben Knoten auf demselben Ledger dasselbe Problem hatten.
      const same = Array.isArray(e.sameTypeMasters) ? e.sameTypeMasters.length : null;
      const word = otherWord(e.others || 0);
      const base = same === null
        ? h.t("vt.evCohort", { n: num(e.affectedValidators), others: num(e.others), otherWord: word })
        : same === (e.others || 0)
          ? h.t("vt.evCohortAll", { n: num(e.affectedValidators), others: num(e.others), otherWord: word })
          : h.t("vt.evCohortSame", { n: num(e.affectedValidators), others: num(e.others), same: num(same), otherWord: word });
      // Die Grenze direkt an der Kohorten-Zahl, nicht erst zwei Zeilen weiter unten: ohne sie
      // wirkt "19 Validatoren betroffen" wie 19 Knoten-Ausfaelle, obwohl die eigene Rechnung
      // auf diesem Ledger nur 'max' echte Fehlende zulaesst.
      const bound = Number.isFinite(e.genuineAbsentMax) && Number.isFinite(e.captureArtifactMin)
        ? " · " + h.t("vt.evCohortBound", { max: num(e.genuineAbsentMax), min: num(e.captureArtifactMin) })
        : "";
      return base + bound;
    }
    if (hy.tag === "drainer-fanout") return h.t("vt.evFanout", { fanout: num(e.fanoutAccounts), txs: num(e.fanoutTxs), ledgerTx: num(e.ledgerTx) });
    if (hy.tag === "sender-burst") return h.t("vt.evBurst", { accountTx: num(e.accountTx), share: pcn(e.share * 100) });
    if (hy.tag === "failure-spike") return h.t("vt.evFailure", { failed: num(e.failed), share: pcn(e.share * 100) });
    if (hy.tag === "batch-amplify") return h.t("vt.evBatch", { batchTx: num(e.batchTx), innerTx: num(e.innerTx) });
    if (hy.tag === "fee-spike") return h.t("vt.evFee", { maxFee: num(e.maxFee), medianFee: num(e.medianFee) });
    if (hy.tag === "feature-change") return h.t("vt.evFeature", { featureTx: num(e.featureTx) });
    if (hy.tag === "sweep-window") return h.t("vt.evSweep", { destinations: num(e.sweepDestinations), ledgers: num(e.sweepLedgers), txs: num(e.sweepTxs) });
    if (hy.tag === "account-create-burst" || hy.tag === "offer-flood" || hy.tag === "nft-spam") return h.t("vt.evCount", { count: num(e.count), baseline: num(e.baseline) });
    if (String(hy.tag).startsWith("type-burst:")) return h.t("vt.evRatio", { count: num(e.count), baseline: num(e.baseline), ratio: fac(e.ratio) });
    if (hy.tag === "vote-late") return h.t("vt.evLate", { delay: sec(e.voteDelayMs), grace: sec(e.graceMs) });
    return "";
  }

  // Ein Retrace-Karton: Messwerte, gereihte Hypothesen mit Stärke, Prüfschritte, Datenlücken.
  function retraceCard(r) {
    const a = r.affected || {};
    // noQuorum mitzählen: auf einem Netz-Ledger ist "nicht abgestimmt" die Abweichung
    // der anderen Knoten. Ohne sie steht "0 Validatoren betroffen" neben "19 andere".
    const cohort = (a.missed || 0) + (a.partial || 0) + (a.wrongHash || 0) + (a.noQuorum || 0);
    const q = r.quorum || null;
    const l = r.load || null;
    const metrics = [];
    if (q && Number.isFinite(q.needed) && q.needed > 0) metrics.push(["vt.metric.quorum", h.t("vt.mQuorum", { top: num(q.topVotes), needed: num(q.needed), margin: num(q.margin) })]);
    if (q && Number.isFinite(q.runnerVotes) && q.runnerVotes > 0) metrics.push(["vt.metric.split", h.t("vt.mSplit", { runner: num(q.runnerVotes), votes: num(q.votes) })]);
    if (l && Number.isFinite(l.txCount)) metrics.push(["vt.metric.load", h.t("vt.mLoad", { tx: num(l.txCount), med: num(l.medianTx), ratio: fac(l.ratio) })]);
    if (Number.isFinite(r.closeGapMs)) metrics.push(["vt.metric.gap", h.t("vt.mGap", { gap: sec(r.closeGapMs) })]);
    metrics.push(["vt.metric.cohort", h.t("vt.mCohort", { n: num(cohort), others: num(a.others), otherWord: otherWord(a.others) })]);
    const metricHtml = metrics.map(([labelKey, value]) => '<li><small>' + h.esc(h.t(labelKey)) + "</small><b>" + h.esc(value) + "</b></li>").join("");
    // Wer sonst auf diesem Ledger fiel: erst die Keys machen die Zahl nachvollziehbar.
    // Gleichfallende Knoten sind die Spur auf gemeinsame Infrastruktur, denselben Anbieter oder
    // dieselben Knoten, die immer zusammen ausfallen - das ist der Retrace-Anfang.
    const peers = Array.isArray(a.peerMasters) ? a.peerMasters : [];
    const samePeers = Array.isArray(a.sameTypeMasters) ? a.sameTypeMasters : [];
    const otherPeers = Array.isArray(a.otherTypeMasters) ? a.otherTypeMasters : [];
    // Unerfasste Knoten ohne jede zurechenbare Abweichung sind eine eigene Gruppe: sie erklaeren
    // die Kohortenzahl dieser Erfassung, ohne als Ausfall in die Vergleichsgruppe zu gehoeren.
    const capturePeers = Array.isArray(a.captureOnlyMasters) ? a.captureOnlyMasters : [];
    // Gegenurteil und Name je benanntem Knoten, indexgleich zur jeweiligen Liste. Die Lib
    // liefert beides aus derselben Netz-Auskunft, die auch die Kohorten-Bilanz traegt.
    const peerTruth = a.peerTruth || null;
    const peerNames = a.peerNames || null;
    const truthOf = (list) => list.map((m) => (peerTruth && peerTruth[m]) || null);
    const namesOf = (list) => list.map((m) => ({ master: m, name: (peerNames && peerNames[m]) || null }));
    const peerGroup = (labelKey, list) => '<span class="vt-peer-group"><small>' + h.esc(h.t(labelKey, { n: num(list.length) })) + "</small> " + peerChips(list, truthOf(list), namesOf(list)) + "</span>";
    const groups = [];
    if (samePeers.length) groups.push(peerGroup("vt.peersLineSame", samePeers));
    if (otherPeers.length) groups.push(peerGroup("vt.peersLineOther", otherPeers));
    if (capturePeers.length) groups.push(peerGroup("vt.peersLineCapture", capturePeers));
    const openPeers = Array.isArray(a.openMasters) ? a.openMasters : [];
    if (openPeers.length) groups.push(peerGroup("vt.peersLineOpen", openPeers));
    const peerLine = !peers.length ? "" : groups.length
      ? '<p class="vt-rc-peers">' + groups.join("") + "</p>"
      : '<p class="vt-rc-peers"><small>' + h.esc(h.t("vt.peersLine", { n: peers.length })) + "</small> " + peerChips(peers, truthOf(peers), namesOf(peers)) + "</p>";
    // Gegenprobe der benannten Kohorte je Karton: widerlegt heisst, die Netz-Referenz sagt,
    // dieser Knoten hat in seinem Fenster nicht gefehlt. Offen heisst, es gibt keine Zahl, die
    // ihn belastet oder entlastet. Beides ist nicht dasselbe wie betroffen.
    const truthSeen = new Map();
    for (const list of [samePeers, otherPeers, capturePeers, openPeers]) {
      for (const m of list) {
        if (truthSeen.has(m)) continue;
        const t = peerTruth && peerTruth[m];
        truthSeen.set(m, t && TRUTH_STATES.has(t.verdict) ? t.verdict : "not-comparable");
      }
    }
    const truthCount = { contradicted: 0, consistent: 0, "not-comparable": 0 };
    for (const v of truthSeen.values()) truthCount[v] += 1;
    const peersTruthLine = truthSeen.size
      ? '<p class="vt-rc-peerstruth"><small>' + h.esc(h.t("vt.peersTruth", {
        n: num(truthSeen.size), contradicted: num(truthCount.contradicted),
        consistent: num(truthCount.consistent), open: num(truthCount["not-comparable"]),
      })) + "</small></p>"
      : "";
    const hyps = (r.hypotheses || []).map((hy) => {
      const lift = hy.lift && hy.lift.reliable && Number.isFinite(hy.lift.lift)
        ? h.t("vt.liftVal", { lift: fac(hy.lift.lift), with: pcn(hy.lift.rateWith * 100), without: pcn(hy.lift.rateWithout * 100) })
        : "";
      const ev = evidenceText(hy);
      // Netzweit heißt dieselbe Messung anderes als "mehrere": hier fiel die ganze Kohorte.
      const label = hy.tag === "cohort-event" && r.scope === "network"
        ? h.t("vt.tag.cohortEventNetwork") : tl(hy.tag);
      // Die Kohorten-Zahl ohne Namen ist eine Häufung ohne Spur: erst die Keys zeigen,
      // ob dieselben Knoten immer zusammen fallen (Anbieter, Infrastruktur, Peering).
      // Genannt werden die Knoten mit demselben Vorfallstyp - die Vergleichsgruppe, nach der
      // der Betreiber suchen soll. Andere Typen stehen in der Peer-Zeile des Kartons.
      const peerList = Array.isArray(hy.evidence?.sameTypeMasters)
        ? hy.evidence.sameTypeMasters
        : (Array.isArray(hy.evidence?.peerMasters) ? hy.evidence.peerMasters : []);
      const hypPeers = peerList.length ? '<span class="vt-ev vt-ev-peers">' + peerChips(peerList, truthOf(peerList), namesOf(peerList)) + "</span>" : "";
      return '<li class="vt-hyp vt-st-' + h.esc(hy.strength) + '"><b>' + h.esc(label) + "</b>"
        + '<span class="vt-strength">' + h.esc(h.t("vt.strength." + hy.strength)) + "</span>"
        + (ev ? '<span class="vt-ev">' + h.esc(ev) + "</span>" : "")
        + hypPeers
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
      + '<ul class="vt-rc-metrics">' + metricHtml + "</ul>" + peerLine + peersTruthLine
      + '<h4 class="vt-h4">' + h.esc(h.t("vt.hypotheses")) + '</h4><ul class="vt-hyps">' + hyps + "</ul>"
      + (next ? '<h4 class="vt-h4">' + h.esc(h.t("vt.nextCheck")) + '</h4><ul class="vt-next">' + next + "</ul>" : "")
      + (gaps ? '<p class="vt-rc-gaps"><small>' + h.esc(h.t("vt.dataGaps")) + "</small> " + h.esc(gaps) + "</p>" : "")
      + "</article>";
  }

  function retraceBlock(rows, total) {
    if (!Array.isArray(rows) || !rows.length) return '<p class="vt-empty">' + h.esc(h.t("vt.noRetrace")) + "</p>";
    const shown = rows.slice(0, RETRACE_SHOWN);
    // Die Antwort kann mehr Vorfaelle haben als Karten gesendet werden (retraceTotal). Ohne die
    // Gesamtzahl wirkt "12 von 12" vollständig, obwohl 8.609 Vorfälle dahinter liegen.
    const rest = rows.slice(RETRACE_SHOWN);
    const notes = [];
    if (rest.length) notes.push(h.t("vt.retraceShowing", { shown: shown.length, total: num(rows.length) }));
    if (Number.isFinite(total) && total > rows.length) notes.push(h.t("vt.retraceCapped", { sent: num(rows.length), total: num(total) }));
    const noteHtml = notes.length ? '<p class="vt-scope"><small>' + notes.map((n) => h.esc(n)).join(" · ") + "</small></p>" : "";
    const moreBtn = rest.length ? '<button type="button" class="vt-rc-more">' + h.esc(h.t("vt.retraceMore", { n: num(rest.length) })) + "</button>" : "";
    return '<div class="vt-rc-list">' + shown.map(retraceCard).join("") + "</div>"
      + (rest.length ? '<div class="vt-rc-rest" hidden>' + rest.map(retraceCard).join("") + "</div>" : "")
      + moreBtn + noteHtml;
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
    // Die Grundlage benennt auch, WELCHE Tage in die Vergleichung gehen: nur Tage mit
    // Signatur-Ebene. Tage ohne sie sind Luecke, nicht "geprueft und nichts gefunden".
    const rc = risk.coverage || {};
    const basis = Number.isFinite(rc.daysWithAnomaly)
      ? " " + h.t("vt.riskBasis", { with: num(rc.daysWithAnomaly), without: num(rc.daysWithoutAnomaly ?? 0) }) : "";
    // Die Forensik-Deckung steht in der Lib, aber niemand sah sie: ohne diese Zeile wirkt die
    // Risikolehne wie ein Befund ueber alle Abweichungen, obwohl ein Teil der Ausfall-Ledger
    // gar keine Forensik-Zeile hat (Tage vor dieser Recorder-Stufe). Fehlend ist kein Befund.
    const fc = Number.isFinite(rc.allIncidentLedgers) && rc.allIncidentLedgers > 0
      ? " " + h.t("vt.riskForensics", { rows: num(rc.statsLedgers), incidents: num(rc.allIncidentLedgers),
          share: pc(rc.forensicsShare === null ? null : rc.forensicsShare * 100),
          with: num(rc.daysWithStats), days: num(rc.daysTotal), without: num(rc.daysWithoutForensics) })
      : "";
    const note = h.t("vt.riskBase", { ledgers: num(risk.totalLedgers), fails: num(risk.incidentLedgers) })
      + basis + fc + (risk.statsTruncated ? " " + h.t("vt.riskTrunc") : "");
    return '<table class="vt-table"><thead><tr>' + head + "</tr></thead><tbody>" + rows + "</tbody></table>"
      + '<p class="vt-note">' + h.esc(note) + "</p>";
  }

  // Signatur-Empfindlichkeit: auf welchen Ledger-Signaturen faellt DIESER Knoten ueberproportional
  // zurueck - und tun die anderen Knoten desselben Fensters dasselbe? Die Risikolehne oben
  // antwortet auf "wie oft faellt ein Ledger mit dieser Signatur ueberhaupt" (Netzlage). Erst die
  // Kohorten-Gegenprobe trennt Knotenproblem von Netzstockung von Last auf einer Transaktionsform.
  function sensitivityBlock(s) {
    if (!s || !Array.isArray(s.rows) || !s.rows.length) return '<p class="vt-empty">' + h.esc(h.t("vt.sensNone")) + "</p>";
    const head = ["vt.sens.hTag", "vt.sens.hExp", "vt.sens.hFails", "vt.sens.hOwn", "vt.sens.hLift", "vt.sens.hCohort", "vt.sens.hVerdict"]
      .map((k, i) => '<th scope="col"' + (i === 0 ? ' class="vt-th-l"' : "") + ">" + h.esc(h.t(k)) + "</th>").join("");
    const rows = s.rows.map((r) => "<tr" + (r.measurable ? "" : ' class="vt-thin"') + ">"
      + '<th scope="row">' + h.esc(tl(r.tag)) + "</th>"
      + "<td>" + h.esc(num(r.exposureLedgers)) + "</td>"
      + "<td>" + h.esc(num(r.fails)) + "</td>"
      + "<td>" + h.esc(pc(r.rateWith === null ? null : r.rateWith * 100)) + " / " + h.esc(pc(r.rateWithout === null ? null : r.rateWithout * 100)) + "</td>"
      + "<td>" + h.esc(Number.isFinite(r.lift) ? "×" + fac(r.lift) : "–") + "</td>"
      + "<td>" + h.esc(Number.isFinite(r.cohortLift) ? "×" + fac(r.cohortLift) + " · " + num(r.cohortPeers) : "–") + "</td>"
      + '<td class="vt-sensv vt-sensv-' + h.esc(r.verdict) + '">' + h.esc(h.t("vt.sens.verdict." + r.verdict)) + "</td></tr>").join("");
    const cov = s.coverage || {};
    const gapText = (s.gaps || []).map((g) => h.t("vt.sens.gap." + g)).join(" · ");
    const note = h.t("vt.sensNote", {
      ledgers: num(cov.ledgers), with: num(cov.daysWithAnomaly), without: num(cov.daysWithoutAnomaly), peers: num(cov.peers),
    }) + (gapText ? " " + h.t("vt.sensGaps", { gaps: gapText }) : "");
    const hv = (s.headline && s.headline.verdict) || "thin";
    const chips = ((s.headline && s.headline.tags) || []).slice(0, 6).map((t) => '<span class="vt-chip">' + h.esc(tl(t)) + "</span>").join("");
    const headline = '<p class="vt-sens-head"><b>' + h.esc(h.t("vt.sens.head." + hv)) + "</b>" + chips + "</p>";
    const fams = (s.families || []).map((f) => '<span class="vt-chip">' + h.esc(h.t("vt.sens.family." + f.family)) + " " + num(f.specific) + "/" + num(f.tags) + "</span>").join("");
    const famLine = fams ? '<p class="vt-sens-fam"><small>' + h.esc(h.t("vt.sens.famLabel")) + "</small> " + fams + "</p>" : "";
    return headline + '<div class="vt-tablewrap"><table class="vt-table vt-sens-table"><thead><tr>' + head
      + "</tr></thead><tbody>" + rows + "</tbody></table>"
      + '<p class="vt-note vt-table-hint">' + h.esc(h.t("vt.tableScroll")) + "</p></div>" + famLine
      + '<p class="vt-note">' + h.esc(note) + "</p>";
  }

  // Sammelereignisse: viele Validatoren, dasselbe Ledger. Die Spur, auf der Netzstockungen,
  // Versionskonflikte und Angriffe liegen - ausgewählt nach Betroffenheit, nicht nach Bauchgefühl.
  function attackBlock(a) {
    if (!a || !Array.isArray(a.signals) || !a.signals.length) return '<p class="vt-empty">' + h.esc(h.t("vt.attackNone")) + "</p>";
    const rows = a.signals.map((s) => '<li class="vt-atk"><span class="vt-atk-led">' + h.esc(h.t("vt.ledger")) + " #" + h.esc(String(s.ledgerIndex)) + "</span>"
      + '<span class="vt-atk-when">' + h.esc(stamp(s.timeMs)) + " UTC</span>"
      + '<span class="vt-atk-n">' + h.esc(h.t("vt.attackAffected", { n: num(s.affectedValidators) })) + "</span>"
      + '<span class="vt-atk-split">' + h.esc(h.t("vt.attackSplit", {
        fault: num(s.faultValidators), capture: num(s.captureOnlyValidators) })) + "</span>"
      + (Number.isFinite(s.unattributedValidators) && s.unattributedValidators > 0
        ? '<span class="vt-atk-split-open">' + h.esc(h.t("vt.attackSplitOpen", { n: num(s.unattributedValidators) })) + "</span>" : "")
      + '<span class="vt-reasons">' + (s.anomalies || []).map((tag) => '<span class="vt-chip">' + h.esc(tl(tag)) + "</span>").join("") + "</span>"
      + (Array.isArray(s.masters) && s.masters.length
        ? '<span class="vt-atk-peers"><small>' + h.esc(h.t("vt.attackPeers", { n: s.masters.length })) + "</small> " + peerChips(s.masters) + "</span>" : "")
      + (s.capture && Number.isFinite(s.capture.genuineAbsentMax) && Number.isFinite(s.capture.captureArtifactMin)
        ? '<span class="vt-atk-bound">' + h.esc(h.t("vt.atkBound", {
          absent: num(s.capture.absentCount), max: num(s.capture.genuineAbsentMax), min: num(s.capture.captureArtifactMin) })) + "</span>"
        // Ohne Forensik-Zeile dieses Ledgers ist die Grenze nicht berechenbar. Die Zahl bleibt
        // stehen, aber nicht unqualifiziert: es fehlt genau die Ebene, die sie begrenzen koennte.
        : !s.capture ? '<span class="vt-atk-bound vt-atk-bound-none">' + h.esc(h.t("vt.atkBoundMissing")) + "</span>" : "")
      + "</li>").join("");
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
  // Die Spalte 'Schliess-Beweis' ist der Grund, warum diese Zeile ueberhaupt etwas behaupten darf:
  // der Recorder wertet nur Ledger aus dem validierten Stream aus. Ein bewiesen geschlossener
  // Ledger hat das Netz-Quorum erreicht - eine Marge unter null beschreibt dann nur, wie viele
  // Stimmen dieser Rekorder selbst sah, niemals ein fehlendes Quorum.
  function criticalityBlock(cq) {
    if (!cq || !Number.isFinite(cq.checked)) return "";
    if (!cq.checked) return '<p class="vt-empty">' + h.esc(h.t("vt.cq.none")) + "</p>";
    const head = ["vt.cq.hLedger", "vt.cq.hType", "vt.cq.hVotes", "vt.cq.hTop", "vt.cq.hMargin", "vt.cq.hClosure", "vt.cq.hEffect"]
      .map((k, i) => '<th scope="col"' + (i === 0 ? ' class="vt-th-l"' : "") + ">" + h.esc(h.t(k)) + "</th>").join("");
    const closureCell = (r) => {
      const c = r.closure ?? { closed: null, basis: "validated-ledger-stream", hash: null };
      const hash = c.hash ? h.esc(String(c.hash).slice(0, 12)) + "…" : h.esc(h.t("vt.cq.hashMissing"));
      // Quelle des Hashes, nicht nur der Hash: ein nachgetragener Wert von ausserhalb ist ein
      // Fremd-Nachweis, kein eigener Mithoerbeweis, und muss lesbar bleiben.
      const source = c.hash && c.basis === "xrpscan" ? " · " + h.esc(h.t("vt.cq.closureSource")) : "";
      const verified = c.hash && c.verifiedBy
        ? " · " + h.esc(h.t("vt.cq.closureVerified", { by: c.verifiedBy }))
        : "";
      // Drei Zustaende, nie zwei: gemessene Luecke, gemessen keine Luecke, und nicht erfasst.
      // 'nicht erfasst' als 'keine Luecke' zu zeigen waere eine Entlastung ohne Beleg - genau die
      // Art Aussage, die diese Spalte seit dem 2026-10-16 nicht mehr machen darf.
      const gap = r.captureGap === true
        ? " · " + h.esc(h.t("vt.cq.captureGap"))
          + (CAPTURE_BASES.has(r.captureGapBasis) ? " · " + h.esc(h.t("vt.cq.basis." + r.captureGapBasis)) : "")
        : r.captureGap === false
          ? " · " + h.esc(h.t("vt.cq.noCaptureGap"))
          : " · " + h.esc(h.t("vt.cq.captureGapUnknown"));
      // Das eigene Empfangsniveau, nicht das Netz-Ziel: 'erfasst 16 / Ziel 28' ist erst mit
      // dem eigenen Median einordbar. Ohne ovb (aeltere Zeilen) steht nichts - fehlend bleibt
      // fehlend.
      const own = Number.isFinite(r.observedBaseline)
        ? " · " + h.esc(h.t("vt.cq.ownBaseline", { seen: num(r.observedValidations), base: num(r.observedBaseline) }))
        : "";
      // Naechstes Erfassungs-Ereignis mit Abstand, nie ein Ereignis "irgendwann an dem Tag":
      // eine Zuordnung ohne Abstand ist eine Behauptung. Ohne Protokoll (Altbestand) steht nichts.
      // Das Ziel selbst hat eine Herkunft: gemessen am Endpunkt oder aus der dUNL-Groesse
      // gerechnet. Ohne diese Angabe ist "16 / 28" ein Ziel ohne Nachweis.
      const nb = NEEDED_BASES.has(r.neededBasis) ? r.neededBasis : "not-recorded";
      // Die Herkunft der Herkunft: ein am Tag gemessenes Ziel nennt Endpunkt, Samplezahl und
      // Zeitpunkt, damit die Zahl bis zur Messung zurueckverfolgbar bleibt. Fehlende Stuecke
      // fehlen in der Zeile - sie werden nicht mit einem Strich gefuellt.
      const nqText = nb === "day-measured" && r.capture && typeof r.capture.networkQuorumSource === "string"
        && r.capture.networkQuorumSource
        ? " " + h.t("vt.cq.neededProvenance", {
          endpoint: r.capture.networkQuorumSource,
          samples: Number.isFinite(r.capture.networkQuorumSamples)
            ? h.t("vt.cq.neededSamples", { n: num(r.capture.networkQuorumSamples) }) : "",
          at: Number.isFinite(r.capture.networkQuorumAtMs)
            ? h.t("vt.cq.neededProvenanceAt", {
              at: new Date(r.capture.networkQuorumAtMs).toISOString().slice(0, 16).replace("T", " ") + " UTC",
            }) : "",
        })
        : "";
      const neededNote = " \u00b7 " + h.esc(h.t("vt.cq.neededBasis." + nb) + nqText);
      // Die Nachrechnung des Ziels, wo die Zeile ihre dUNL-Groesse selbst traegt: jeder kann
      // ceil(35 * 0,8) = 28 selbst nachrechnen. Ohne diesen Beleg steht nichts - die Lib
      // behauptet keine Herleitung, sie prueft die aufgezeichnete Zahl gegen die eigene Groesse.
      const neededCheck = r.capture && r.capture.neededMatches === true
        && Number.isFinite(r.capture.members) && Number.isFinite(r.capture.needed)
        ? " \u00b7 " + h.esc(h.t("vt.cq.neededCheck", { members: num(r.capture.members), needed: num(r.capture.needed) }))
        : "";
      const evt = r.captureEvent
        ? " · " + h.esc(h.t("vt.cq.event." + (CAPTURE_EVENT_KINDS.has(r.captureEvent.kind) ? r.captureEvent.kind : "near"), {
          // Ein Ereignis ohne Ledger-Koordinate darf nicht als "at ledger -" gelesen werden:
          // der Abstand zum Ledger bleibt gemessen, die Koordinate des Ereignisses ist unbekannt.
          at: Number.isFinite(r.captureEvent.ledger)
            ? h.t("vt.cq.event.at", { l: num(r.captureEvent.ledger) })
            : h.t("vt.cq.event.atUnknown"),
          s: Math.round(num(r.captureEvent.deltaMs) / 1000) }))
        : "";
      // Die Grenze aus der Schliessung, nicht aus einer Schaetzung: auf einem geschlossenen
      // Ledger koennen hoechstens (dUNL - Ziel) der nicht erfassten Knoten echt gefehlt haben.
      // Ohne diese Zahl waere die Betroffenheits-Zeile ein Knoten-Urteil, das der Schliess-Beweis
      // in derselben Zeile widerlegt.
      const b = r.capture;
      const bound = b && Number.isFinite(b.genuineAbsentMax) && Number.isFinite(b.captureArtifactMin)
        ? " · " + h.esc(h.t("vt.cq.bound", {
          absent: num(b.absentCount), max: num(b.genuineAbsentMax), min: num(b.captureArtifactMin) }))
        : "";
      // Der Beleg hinter einem 'missed': diese Erfassung hat in diesem Ledger so viele
      // dUNL-Mitglieder gesehen wie in ihren eigenen Ledgern davor, und die Zahl der
      // fehlenden bleibt im Rahmen des Schliess-Beweises. Ohne diesen Beleg (aeltere
      // Zeilen) bleibt die Zuordnung offen - die Zeile behauptet dann keinen Knoten-Fehler.
      const attrib = r.capture && r.capture.attributableAbsence === true
        && Number.isFinite(r.capture.membersSeen) && Number.isFinite(r.capture.coverageBaseline)
        ? " \u00b7 " + h.esc(h.t("vt.cq.attribution.missed", {
          seen: num(r.capture.membersSeen), base: num(r.capture.coverageBaseline), absent: num(r.capture.absentCount) }))
        : "";
      return hash + source + verified + gap + own + neededNote + evt + neededCheck + attrib + bound;
    };
    // Betroffenheit als eigene Zeile unter dem Ledger, nicht als achte Spalte: die Namen sind
    // lang, die Tabelle ist es schon. Ohne affectedCount (aeltere Antwort) bleibt die Zeile weg -
    // "nicht erfasst" ist hier besser als eine gemutmasste Kohorte.
    const affectedRow = (r) => {
      if (!Number.isFinite(r.affectedCount)) return "";
      const others = Array.isArray(r.affectedMasters) ? r.affectedMasters : [];
      const body = others.length
        ? peerChips(others, r.affectedTruth, r.affectedNames)
        : '<span class="vt-peer vt-peer-none">' + h.esc(h.t("vt.cq.affectedSolo")) + "</span>";
      return '<tr class="vt-cq-affected"><td colspan="7">'
        + '<span class="vt-cq-affected-label">'
        + h.esc(h.t("vt.cq.affected", { n: num(r.affectedCount), others: num(others.length) }))
        + "</span>" + body + "</td></tr>";
    };
    const rows = cq.rows.map((r) => "<tr>"
      + '<th scope="row">#' + h.esc(num(r.ledgerIndex)) + "</th>"
      + "<td>" + h.esc(h.t("vt.type." + (DIAG_TYPE[r.type] || r.type))) + "</td>"
      + "<td>" + h.esc(num(r.votes) + " / " + num(r.needed)) + "</td>"
      + "<td>" + h.esc(num(r.topVotes)) + "</td>"
      + "<td>" + h.esc(num(r.margin)) + "</td>"
      + "<td>" + closureCell(r) + "</td>"
      + "<td>" + h.esc(h.t("vt.cq.verdict." + r.verdict)) + "</td></tr>"
      + affectedRow(r)).join("");
    const summary = h.t("vt.cq.summary", {
      checked: num(cq.checked), absent: num(cq.checked + cq.unanswered),
      critical: num(cq.critical), followOn: num(cq.followOn),
      closed: num(cq.closed ?? 0), captureGaps: num(cq.captureGaps ?? 0),
      captureGapUnknown: num(cq.captureGapUnknown ?? 0),
      receptionThin: num(cq.receptionThin ?? 0),
      captureEvents: num(cq.captureEvents ?? 0),
    });
    // Die Kohorten-Bilanz: benannte Knoten sind nur so viel wert wie die Referenz, die ihre
    // Abwesenheit traegt. Ohne diese Zeile waere die Namenliste eine Aufzaehlung von Beschuldigten.
    const peerTruth = cq.affectedTruth && cq.affectedTruth.nodes
      ? '<p class="vt-cq-peer-truth"><small>' + h.esc(h.t("vt.cq.truth.summary", {
          nodes: num(cq.affectedTruth.nodes), contradicted: num(cq.affectedTruth.contradicted),
          consistent: num(cq.affectedTruth.consistent), open: num(cq.affectedTruth.notComparable),
          min: num(cq.affectedTruth.falsePositiveMin),
          window: truthWindowLabel(cq.affectedTruth.windowHours),
        })) + (cq.affectedTruth.partialWindows > 0
          ? " " + h.esc(h.t("vt.cq.truth.partial", {
            partial: num(cq.affectedTruth.partialWindows),
            window: truthWindowLabel(cq.affectedTruth.windowHours),
          })) : "") + "</small></p>"
      : "";
    return '<table class="vt-table"><thead><tr>' + head + "</tr></thead><tbody>" + rows + "</tbody></table>"
      + '<p class="vt-note">' + h.esc(summary) + "</p>" + peerTruth;
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
  // Peer-Benchmark: eine Ausfallrate ohne Vergleich ist keine Diagnose. Dieser Block rechnet
  // die eigenen Ausfaelle auf die Ledger, die dieser Knoten wirklich beobachtet hat, und stellt
  // sie gegen dieselbe Messung aller anderen dUNL-Knoten desselben Fensters. Getrennt nach
  // Zustaendigkeit: missed / partial / wrong-hash sind knotenzurechenbar, no-quorum ist
  // Netz-Aussetzung und laeuft ausserhalb der Rate, nach der das Urteil gefaellt wird.
  function peerBlock(peer, absence) {
    if (!peer || !peer.sample) return '<p class="vt-empty">' + h.esc(h.t("vt.peer.none")) + "</p>";
    const s = peer.sample;
    const hourLabel = (ms) => (Number.isFinite(ms) ? new Date(ms).toISOString().slice(5, 16).replace("T", " ") : "–");
    // Kleine Raten duerfen nicht zu 0 werden: der Peer-Median liegt bei 0,0014 %, und "0,0 %"
    // laest den Befund verschwinden, der den Unterschied macht (Ausreisser gegen Grundrate).
    const rate = (v) => {
      if (!Number.isFinite(v)) return "–";
      const pct = v * 100;
      if (pct === 0) return "0";
      if (pct < 0.01) return pct.toPrecision(2);
      if (pct < 1) return pct.toFixed(3);
      return pcn(pct);
    };
    const verdictLine = '<p class="vt-scope"><span class="vt-badge vt-peerv-' + h.esc(peer.verdict) + '">'
      + h.esc(h.t("vt.peer.verdict." + peer.verdict)) + "</span> · " + h.esc(h.t("vt.peer.reason." + peer.verdictReason))
      + " · " + h.esc(h.t("vt.peer.authority." + peer.verdictAuthority)) + "</p>";
    if (!peer.own) return verdictLine;
    if (peer.verdict === "insufficient-sample") {
      return verdictLine + '<p class="vt-note">' + h.esc(h.t("vt.peer.sampleLine", {
        observed: num(s.observed), minLedgers: num(s.minLedgers), peers: num(s.peers), minPeers: num(s.minPeers),
      })) + "</p>";
    }
    const head = ["vt.peer.hType", "vt.peer.hOwn", "vt.peer.hRate", "vt.peer.hMedian", "vt.peer.hP90", "vt.peer.hRatio", "vt.peer.hFlag"]
      .map((k, i) => '<th scope="col"' + (i === 0 ? ' class="vt-th-l"' : "") + ">" + h.esc(h.t(k)) + "</th>").join("");
    const rows = (peer.types || []).map((t) => "<tr>"
      + '<th scope="row">' + h.esc(h.t("vt.peer.type." + t.type)) + "</th>"
      + "<td>" + h.esc(num(t.own)) + "</td>"
      + "<td>" + h.esc(rate(t.ownRate)) + "</td>"
      + "<td>" + h.esc(rate(t.peerMedianRate)) + "</td>"
      + "<td>" + h.esc(rate(t.peerP90Rate)) + "</td>"
      + "<td>" + h.esc(fac(t.ratio)) + "</td>"
      + "<td>" + h.esc(h.t(t.abovePeerP90 ? "vt.peer.above" : "vt.peer.within")) + "</td></tr>").join("");
    const cmp = peer.comparison || {};
    const pr = peer.peers || {};
    const co = peer.cohort || {};
    const nq = peer.network || {};
    const lines = [h.t("vt.peer.summary", {
      observed: num(s.observed), own: num(peer.own.failures), ownRate: rate(peer.own.rate),
      peers: num(pr.count), median: rate(pr.medianRate), p90: rate(pr.p90Rate), pooled: rate(pr.pooledRate),
    })];
    // Die Rate dieses Fensters ist nur so viel wert wie ihr Beleg: ein 'missed' aus einer Zeile
    // ohne Abdeckungs-Messung ist weder ein Knoten-Ausfall noch eine Entlastung. Die Zahl bleibt
    // stehen, aber sie steht nicht mehr als Knoten-Aussage da.
    if (absence && Number.isFinite(absence.claims) && absence.claims > 0) {
      lines.push(h.t("vt.peer.attribution", {
        proven: num(absence.proven), claims: num(absence.claims), fault: num(absence.fault),
        capture: num(absence.capture), open: num(absence.open),
      }));
    }
    // Vor der Grundrate und ueber der Grundrate sind verschiedene Aussagen: ein negatives excess
    // als "ueber der Grundrate" zu lesen ist das Gegenteil von dem, was gemessen wurde.
    if (Number.isFinite(cmp.excessFailures)) lines.push(cmp.excessFailures < 0
      ? h.t("vt.peer.excessBelow", { excess: num(Math.abs(cmp.excessFailures)) })
      : h.t("vt.peer.excessAbove", { excess: num(cmp.excessFailures) }));
    // p unter der Rundungsgrenze als 0,0000 zu zeigen liest sich wie Gewissheit - es ist die
    // Nachweisgrenze der Naeherung, kein Beweis.
    if (Number.isFinite(cmp.z)) lines.push(h.t("vt.peer.z", {
      z: fac(cmp.z), p: !Number.isFinite(cmp.pValue) ? "–" : cmp.pValue < 1e-4 ? "< 0.0001" : cmp.pValue.toFixed(4),
    }));
    if (cmp.direction) lines.push(h.t("vt.peer.direction." + cmp.direction));
    lines.push(h.t("vt.peer.cohort", {
      solo: num(co.solo), shared: num(co.shared), unrecorded: num(co.unrecorded),
      share: Number.isFinite(co.soloShare) ? pcn(co.soloShare * 100) : "–",
      max: Number.isFinite(co.maxCohort) ? num(co.maxCohort) : "–",
    }));
    lines.push(h.t("vt.peer.network", { own: num(nq.ownNoQuorum), ownRate: rate(nq.ownNoQuorumRate), peerMedian: rate(nq.peerMedianNoQuorumRate) }));
    if (s.estimated) lines.push(h.t("vt.peer.estimated", {
      ledgers: num(s.observedDaily), observed: num(s.observed),
      legacyDays: num(s.daysDaily), partialDays: num(s.daysPartial ?? 0),
    }));
    const alone = (peer.aloneHours || []).slice(0, 6).map((a) => "<li>" + h.esc(h.t("vt.peer.aloneLine", {
      hour: hourLabel(a.hourMs), own: num(a.ownFailures), peers: num(a.observedPeers), ledgers: num(a.ledgers),
    })) + "</li>").join("");
    const aloneBlock = '<h4 class="vt-h4">' + h.esc(h.t("vt.peer.aloneTitle")) + "</h4>"
      + (alone ? "<ul class=\"vt-list\">" + alone + "</ul>" : '<p class="vt-empty">' + h.esc(h.t("vt.peer.aloneNone")) + "</p>");
    return verdictLine
      + '<table class="vt-table"><thead><tr>' + head + "</tr></thead><tbody>" + rows + "</tbody></table>"
      + '<p class="vt-note">' + h.esc(lines.join(" · ")) + "</p>"
      + aloneBlock;
  }

  // Timing-Ebene: die Klassifizierung sagt, WELCHER Fehler passierte. Diese Ebene sagt, ob dieser
  // Knoten fuer diesen Ledger ueberhaupt abgestimmt hat - nur zu spaet - oder gar nicht, und stellt
  // beides gegen den ersten Vote des Netzes. Ohne diese Gegenprobe ist "mein Vote war spaet" eine
  // Zahl ohne Bedeutung; mit ihr ist sie eine Zustandsdiagnose (Knotenpfad oder Netzstockung).
  function latencyBlock(lat) {
    if (!lat || !lat.verdict) return '<p class="vt-empty">' + h.esc(h.t("vt.lat.none")) + "</p>";
    const th = lat.thresholds || {};
    const cov = lat.coverage || {};
    const pct = (v) => (Number.isFinite(v) ? pcn(v * 100) : "–");
    const verdictLine = '<p class="vt-scope"><span class="vt-badge vt-latv-' + h.esc(lat.verdict) + '">'
      + h.esc(h.t("vt.lat.verdict." + lat.verdict)) + "</span> · " + h.esc(h.t("vt.lat.reason." + lat.verdictReason))
      + " · " + h.esc(h.t("vt.lat.authority." + lat.verdictAuthority)) + "</p>";
    const ringLine = '<p class="vt-note">' + h.esc(h.t("vt.lat.ringLine", {
      ring: num(th.ringLedgers), truncated: num(cov.truncatedDays),
    })) + "</p>";
    if (lat.verdict === "no-deviations") return verdictLine;
    if (lat.verdict === "not-recorded" || lat.verdict === "insufficient-sample") {
      return verdictLine + '<p class="vt-note">' + h.esc(h.t("vt.lat.coverageLine", {
        recorded: num(cov.daysRecorded), days: num(cov.days),
        incidents: num((lat.counts || {}).incidents), minIncidents: num(th.minIncidents),
      })) + "</p>" + ringLine;
    }
    // Erfassungs-Urteil: keine Latenz-Tabelle, sondern der eigene Beleg. Ohne diese Zeile waere
    // "Ledger geschlossen, Stimme nicht gesehen" eine Behauptung ohne Zahl und ohne Quelle.
    if (lat.verdict === "capture-only" || lat.verdict === "closure-unproven" || lat.verdict === "partially-proven") {
      const cl = lat.closure || {};
      const bases = Object.keys(cl.bases || {}).sort()
        .map((b) => (CLOSURE_BASIS_KEY[b] ? h.t(CLOSURE_BASIS_KEY[b]) : b) + " " + num(cl.bases[b])).join(", ");
      const closureLine = '<p class="vt-note">' + h.esc(h.t("vt.lat.closureLine", {
        incidents: num(cl.incidents), proven: num(cl.proven), denied: num(cl.denied), unknown: num(cl.unknown),
      })) + (bases ? " - " + h.t("vt.lat.closureBases", { bases }) : "") + "</p>";
      return verdictLine + closureLine + ringLine;
    }
    const cls = lat.classes || {};
    const head = ["vt.lat.hClass", "vt.lat.hCount", "vt.lat.hShare"]
      .map((k, i) => '<th scope="col"' + (i === 0 ? ' class="vt-th-l"' : "") + ">" + h.esc(h.t(k)) + "</th>").join("");
    const rows = [["late", cls.late, cls.lateShare], ["never", cls.never, cls.neverShare],
      ["inWindow", cls.inWindow, cls.inWindowShare], ["unknown", cls.unknown, cls.unknownShare]]
      .map(([k, n, s]) => "<tr>"
        + '<th scope="row">' + h.esc(h.t("vt.lat.class." + k)) + "</th>"
        + "<td>" + h.esc(num(n)) + "</td>"
        + "<td>" + h.esc(Number.isFinite(s) ? pct(s) : "–") + "</td></tr>").join("");
    const own = (lat.own && lat.own.delay) || {};
    const net = lat.network || {};
    const onOwn = net.onOwnIncidentLedgers || {};
    const onPeer = net.onPeerIncidentLedgers || {};
    const cmp = lat.comparison || {};
    const beh = cmp.behind || {};
    const hr = net.hourly || {};
    const pat = lat.pattern || {};
    const lines = [];
    if (own.n) lines.push(h.t("vt.lat.ownLine", { median: sec(own.median), p90: sec(own.p90), max: sec(own.max), n: num(own.n) }));
    if (onOwn.n || onPeer.n) lines.push(h.t("vt.lat.networkLine", { median: sec(onOwn.median), p90: sec(onOwn.p90), n: num(onOwn.n), other: sec(onPeer.median) }));
    if (beh.n) lines.push(h.t("vt.lat.behindLine", { median: sec(beh.median), p90: sec(beh.p90), ratio: fac(cmp.ratioOwnToNetworkMedian) }));
    if (hr.ledgers) lines.push(h.t("vt.lat.hourlyLine", {
      ledgers: num(hr.ledgers), hours: num(hr.hours), mean: sec(hr.meanFvMs), max: sec(hr.maxFvMs),
      late: num(hr.lateLedgers), lateShare: pct(hr.lateShare),
    }));
    if (pat.kind) lines.push(h.t("vt.lat.patternLine", { kind: h.t("vt.lat.pattern." + pat.kind), spread: sec(pat.spreadMs), samples: num(pat.samples) }));
    const late = (lat.lateVotes || []).slice(0, 8).map((r) => "<li>" + h.esc(h.t("vt.lat.lateLine", {
      ledger: num(r.ledgerIndex), own: sec(r.ownMs), net: sec(r.networkFirstMs), behind: sec(r.behindMs),
    })) + "</li>").join("");
    const lateBlock = '<h4 class="vt-h4">' + h.esc(h.t("vt.lat.lateTitle")) + "</h4>"
      + (late ? '<ul class="vt-list">' + late + "</ul>" : '<p class="vt-empty">' + h.esc(h.t("vt.lat.lateNone")) + "</p>");
    return verdictLine
      + '<table class="vt-table"><thead><tr>' + head + "</tr></thead><tbody>" + rows + "</tbody></table>"
      + '<p class="vt-note">' + h.esc(lines.join(" · ")) + "</p>"
      + lateBlock + ringLine;
  }

  // Divergenz-Ebene: die Latenz sagt, ob ein Vote zu spaet war. Diese Ebene sagt, WAS dieser
  // Knoten ueberhaupt signiert hat - die Linie der Netzmehrheit, die Runner-Up-Linie oder eine
  // eigene dritte Linie. Ein Knoten, der zeitig auf einer falschen Linie stimmt, hat ein Stand-
  // problem, kein Pfadproblem; die Latenz-Ebene kann das nicht unterscheiden, weil ihr dafuer
  // der Inhalt des Votes fehlt.
  // Feature-Ledger (Amendment / UNLModify) sind die Ledger, auf denen das Netz seine eigenen
  // Bewertungsregeln aendert. Faellen Ausfaelle dort haeufiger aus als ohne dieses Feature, ist
  // die naechste Pruefung die Version und die Amendment-Unterstützung - nicht das Peering.
  function divergenceBlock(div) {
    if (!div || !div.verdict) return '<p class="vt-empty">' + h.esc(h.t("vt.div.none")) + "</p>";
    const cov = div.coverage || {};
    const short = (x) => (typeof x === "string" && x.length >= 8 ? x.slice(0, 8).toLowerCase() : "–");
    const rate = (v) => (Number.isFinite(v) ? pcn(v * 100) : "–");
    const verdictLine = '<p class="vt-scope"><span class="vt-badge vt-divv-' + h.esc(div.verdict) + '">'
      + h.esc(h.t("vt.div.verdict." + div.verdict)) + "</span> · " + h.esc(h.t("vt.div.reason." + div.verdictReason))
      + " · " + h.esc(h.t("vt.div.authority." + div.verdictAuthority)) + "</p>";
    const covLine = '<p class="vt-note">' + h.esc(h.t("vt.div.coverageLine", {
      incidents: num(cov.incidents), withHash: num(cov.incidentsWithVoteHash),
      accepted: num(cov.ledgersWithAcceptedHash), ledgers: num(cov.totalLedgers),
    })) + "</p>";
    // Ohne aufgezeichnete Hashes ist jede Zahl darunter eine Luecke, kein Befund: die Zeile bleibt,
    // die Tabellen darunter bleiben weg, damit keine leere Tabelle wie ein Null-Befund wirkt.
    if (div.verdict === "not-recorded") return verdictLine + covLine;
    const counts = div.lineageCounts || {};
    const head = ["vt.div.hLineage", "vt.div.hCount"]
      .map((k, i) => '<th scope="col"' + (i === 0 ? ' class="vt-th-l"' : "") + ">" + h.esc(h.t(k)) + "</th>").join("");
    const rows = ["accepted", "runner", "own", "unknown", "noVote"].map((k) => "<tr>"
      + '<th scope="row">' + h.esc(h.t("vt.div.lineage." + k)) + "</th>"
      + "<td>" + h.esc(num(counts[k])) + "</td></tr>").join("");
    const losing = (div.losingLineages || []).slice(0, 6).map((r) => "<li>" + h.esc(h.t("vt.div.losingLine", {
      hash: short(r.hash), mine: num(r.mineCount), masters: num(r.masterCount), count: num(r.count),
      ledgers: (r.ledgers || []).slice(0, 4).map((l) => num(l)).join(", "),
      features: (r.featureLabels || []).join(", ") || "–",
    })) + "</li>").join("");
    const losingBlock = '<h4 class="vt-h4">' + h.esc(h.t("vt.div.losingTitle")) + "</h4>"
      + (losing ? '<ul class="vt-list">' + losing + "</ul>" : '<p class="vt-empty">' + h.esc(h.t("vt.div.losingNone")) + "</p>");
    const feats = div.features || [];
    const fhead = ["vt.div.hFeature", "vt.div.hFeatLedgers", "vt.div.hFeatFails", "vt.div.hRateWith", "vt.div.hRateWithout", "vt.div.hLift", "vt.div.hMine"]
      .map((k, i) => '<th scope="col"' + (i === 0 ? ' class="vt-th-l"' : "") + ">" + h.esc(h.t(k)) + "</th>").join("");
    const frows = feats.slice(0, 6).map((f) => "<tr>"
      + '<th scope="row">' + h.esc(f.label) + (f.reliable ? "" : " · " + h.esc(h.t("vt.div.thin"))) + "</th>"
      + "<td>" + h.esc(num(f.ledgers)) + "</td>"
      + "<td>" + h.esc(num(f.failLedgers)) + "</td>"
      + "<td>" + h.esc(rate(f.rateWith)) + "</td>"
      + "<td>" + h.esc(rate(f.rateWithout)) + "</td>"
      + "<td>" + h.esc(fac(f.lift)) + "</td>"
      + "<td>" + h.esc(num(f.mineDivergences)) + "</td></tr>").join("");
    const featureBlock = feats.length
      ? '<h4 class="vt-h4">' + h.esc(h.t("vt.div.featureTitle")) + '</h4><table class="vt-table"><thead><tr>' + fhead + "</tr></thead><tbody>" + frows + "</tbody></table>"
      : '<p class="vt-empty">' + h.esc(h.t("vt.div.featureNone")) + "</p>";
    const late = div.lateLineage || {};
    const lateLine = late.recorded && late.total
      ? '<p class="vt-note">' + h.esc(h.t("vt.div.lateLine", {
        total: num(late.total), accepted: num(late.accepted), divergent: num(late.divergent), unknown: num(late.unknown),
      })) + "</p>"
      : "";
    const gaps = (div.dataGaps || []).map((g) => h.t("vt.div.gap." + g)).join(" · ");
    const gapLine = gaps ? '<p class="vt-note">' + h.esc(gaps) + "</p>" : "";
    const guide = (div.guidance || []).map((g) => "<li>" + h.esc(h.t("vt.g." + g)) + "</li>").join("");
    const guideBlock = guide ? '<h4 class="vt-h4">' + h.esc(h.t("vt.div.guideTitle")) + '</h4><ul class="vt-list">' + guide + "</ul>" : "";
    return verdictLine + covLine
      + '<table class="vt-table"><thead><tr>' + head + "</tr></thead><tbody>" + rows + "</tbody></table>"
      + losingBlock + featureBlock + lateLine + gapLine + guideBlock;
  }

  // Tag-Namen haben drei moegliche Home-Registrierungen: die neuen Tags der Cause-Engine, die
  // Serien-Urteile (vt.verdict.*) und die Forensik-Tags (vt.tag.*). Ein Vorfall darf nicht zwei
  // Namen bekommen - deshalb wird in dieser Reihenfolge nachgeschlagen, nie erfunden.
  function causeTagLabel(tag) {
    const base = String(tag).split(":")[0];
    const ck = "vt.cause.tag." + base;
    const ct = h.t(ck);
    if (ct && ct !== ck) {
      return base === "type-burst" || base === "new-tx-type" ? ct + " " + String(tag).slice(base.length + 1) : ct;
    }
    const vk = "vt.verdict." + base;
    const vs = h.t(vk);
    if (vs && vs !== vk) return vs;
    return tl(tag);
  }

  // Ursache je Vorfall: die selbstaendigen Ebenen (Ledger-Forensik, Serie, Quorum-Bandbreite,
  // Last, Kohorte, UTC-Stunde, Angriffs-Ledger, Vote-Linie, Vote-Zeit) werden pro Vorfall zu
  // Kandidaten gewichtet und nach Beobachtungsstaerke sortiert. Das ist die Ebene, mit der ein
  // Validator fuer sich selbst nachvollziehen kann, woran ein missed / partial / no-quorum /
  // wrong-hash gelegen haben kann - nicht nur, dass einer der vier Faelle vorliegt.
  function causeBlock(c) {
    if (!c || !Array.isArray(c.rows)) return '<p class="vt-empty">' + h.esc(h.t("vt.cause.empty")) + "</p>";
    const cov = c.coverage || {};
    const red = c.reduction || {};
    const share = (v) => (Number.isFinite(v) ? pcn(v * 100) : "–");
    const pct = (v) => (Number.isFinite(v) ? pc(v * 100) : "–");
    const reductionLine = '<p class="vt-scope vt-cause-reduction">' + h.esc(h.t("vt.cause.reductionLine", {
      raw: num(red.rawNoCause), total: num(cov.incidents), rawShare: share(red.rawNoCauseShare),
      resolved: num(red.resolvedByCauseEngine), remaining: num(red.remainingRawNoCause),
      unexplained: num(red.unexplainedTotal), explained: share(red.explainedShare),
    })) + "</p>";
    const covLine = '<p class="vt-note">' + h.esc(h.t("vt.cause.coverageLine", {
      incidents: num(cov.incidents), matched: num(cov.matchedIncidents), unmatched: num(cov.unmatchedIncidents),
      ledger: num(cov.withLedgerMeasurement), band: num(cov.withQuorumBandRate),
      bandRate: pct(cov.quorumBandRate), bandLedgers: num(cov.quorumBandLedgers),
      load: num(cov.withLoadAxis), lineage: num(cov.withVoteLineage), timing: num(cov.withVoteTiming),
      hours: num(cov.hoursRecorded), thinHours: num(cov.hoursThin),
      attackHours: num(cov.attackHours), attackUnknown: num(cov.attackHoursUnknown),
    })) + "</p>";
    const vhead = ["vt.cause.hTag", "vt.cause.hIncidents", "vt.cause.hShare"]
      .map((k, i) => '<th scope="col"' + (i === 0 ? ' class="vt-th-l"' : "") + ">" + h.esc(h.t(k)) + "</th>").join("");
    const vrows = (c.verdicts || []).slice(0, 8).map((v) => "<tr>"
      + '<th scope="row">' + h.esc(causeTagLabel(v.tag)) + "</th>"
      + "<td>" + h.esc(num(v.incidents)) + "</td>"
      + "<td>" + h.esc(share(v.share)) + "</td></tr>").join("");
    const verdictTable = vrows
      ? '<table class="vt-table"><thead><tr>' + vhead + "</tr></thead><tbody>" + vrows + "</tbody></table>"
      : '<p class="vt-empty">' + h.esc(h.t("vt.cause.none")) + "</p>";
    const primaryLine = c.primary
      ? '<p class="vt-note">' + h.esc(h.t("vt.cause.primaryLine", {
        tag: causeTagLabel(c.primary.tag), incidents: num(c.primary.incidents), share: share(c.primary.share),
      })) + "</p>"
      : "";
    const checks = (c.checklist || []).map((x) => "<li>" + h.esc(h.t("vt.cause." + x.tag))
      + ' <small>' + h.esc(h.t("vt.cause.checkMeta", {
        incidents: num(x.incidents), share: share(x.share),
        verdicts: (x.verdicts || []).map(causeTagLabel).join(", ") || "–",
      })) + "</small></li>").join("");
    const checkBlock = checks
      ? '<h4 class="vt-h4">' + h.esc(h.t("vt.cause.checkTitle")) + '</h4><ul class="vt-list vt-checklist">' + checks + "</ul>"
      : "";
    const rhead = ["vt.cause.hLedger", "vt.cause.hType", "vt.cause.hVerdict", "vt.cause.hConfidence",
      "vt.cause.hLayers", "vt.cause.hCheck"]
      .map((k, i) => '<th scope="col"' + (i === 0 ? ' class="vt-th-l"' : "") + ">" + h.esc(h.t(k)) + "</th>").join("");
    const rowTotal = Number.isFinite(c.rowTotal) && c.rowTotal >= c.rows.length ? c.rowTotal : c.rows.length;
    const rrows = c.rows.slice(0, CAUSE_ROWS).map((r) => "<tr>"
      + '<th scope="row">#' + h.esc(num(r.ledgerIndex)) + "</th>"
      + "<td>" + h.esc(h.t("vt.k." + r.type)) + "</td>"
      + '<td><span class="vt-badge vt-causek-' + h.esc(r.verdictKind) + '">' + h.esc(causeTagLabel(r.verdict)) + "</span>"
      + " <small>" + h.esc(h.t("vt.cause.confidence." + r.verdictConfidence)) + "</small></td>"
      + "<td>" + h.esc((r.verdictLayers || []).map((l) => h.t("vt.cause.layer." + l)).join(", ") || "–") + "</td>"
      + "<td>" + h.esc((r.nextCheck || []).slice(0, 2).map((k) => h.t("vt.cause." + k)).join(" · ") || "–") + "</td>"
      + "</tr>").join("");
    const rowsBlock = c.rows.length
      ? '<h4 class="vt-h4">' + h.esc(h.t("vt.cause.rowsTitle")) + '</h4><div class="vt-tablewrap"><table class="vt-table vt-cause-rows"><thead><tr>'
        + rhead + "</tr></thead><tbody>" + rrows + "</tbody></table>"
        + '<p class="vt-note vt-table-hint">' + h.esc(h.t("vt.tableScroll")) + "</p></div>"
        + (rowTotal > CAUSE_ROWS ? '<p class="vt-note">' + h.esc(h.t("vt.cause.rowsMore", { shown: CAUSE_ROWS, total: num(rowTotal) })) + "</p>" : "")
      : '<p class="vt-empty">' + h.esc(h.t("vt.cause.rowsNone")) + "</p>";
    const gaps = Object.keys(c.gapTally || {}).sort().map((g) => h.t("vt.cause.gap." + g) + " (" + num(c.gapTally[g]) + ")").join(" · ");
    const gapLine = gaps ? '<p class="vt-note">' + h.esc(gaps) + "</p>" : "";
    return reductionLine + covLine + verdictTable + primaryLine + checkBlock + rowsBlock + gapLine;
  }

  // Risikoflaeche: an welcher Achse die eigenen Ausfaelle wirklich haengen - Quorum-Reserve,
  // Ledger-Last, beide zusammen, oder der eigene Knoten. Beide Achsen sind auf denselben Ledgern
  // gemessen, die Interaktion Last x Quorum ist deshalb eine Messung und keine Vermutung.
  function surfaceBlock(s) {
    if (!s || !s.verdict) return '<p class="vt-empty">' + h.esc(h.t("vt.surface.empty")) + "</p>";
    const cov = s.coverage || {};
    const th = s.thresholds || {};
    const sh = s.shares || {};
    const share = (v) => (Number.isFinite(v) ? pcn(v * 100) : "–");
    const pct = (v) => (Number.isFinite(v) ? pc(v * 100) : "–");
    const verdictLine = '<p class="vt-scope"><span class="vt-badge vt-surfv-' + h.esc(s.verdict) + '">'
      + h.esc(h.t("vt.surface.verdict." + s.verdict)) + "</span> · " + h.esc(h.t("vt.surface.reason." + s.verdictReason))
      + " · " + h.esc(h.t("vt.surface.authority." + s.verdictAuthority)) + "</p>";
    const covLine = '<p class="vt-note">' + h.esc(h.t("vt.surface.coverageLine", {
      days: num(cov.days), axisDays: num(cov.daysWithQuorumAxis), q: num(cov.ledgersQuorum),
      l: num(cov.ledgersLoad), mineQ: num(cov.ownFailLedgersByQuorum), mineL: num(cov.ownFailLedgersByLoad),
      cells: num(cov.cellsRecorded), minBand: num(th.minBandLedgers), minMine: num(th.minBandMine),
    })) + "</p>";
    const sharesLine = '<p class="vt-note">' + h.esc(h.t("vt.surface.sharesLine", {
      quorum: share(sh.quorumShare), comfort: share(sh.comfortableShare), load: share(sh.loadShare),
      normal: share(sh.normalLoadShare), rate: pct(s.overallMineRate),
    })) + "</p>";
    // Die Share ist eine Relation, kein Beweis. Neben das Urteil gehoert deshalb die Zahl der
    // Ledgers und der eigenen Ausfaelle, auf der die jeweilige Aussage steht.
    const groups = cov.bandGroups || {};
    const groupText = (key) => h.t("vt.surface.group." + key) + " " + num(groups[key].ledgers) + "/"
      + num(groups[key].mineFails) + " " + h.t(groups[key].measurable ? "vt.surface.groupMeasurable" : "vt.surface.groupThin");
    const groupKeys = ["quorumThin", "quorumComfort", "loadHigh", "loadNormal"].filter((k) => groups[k]);
    const groupLine = groupKeys.length
      ? '<p class="vt-note">' + h.esc(h.t("vt.surface.groupLine", {
        qThin: groupText("quorumThin"), qComfort: groupText("quorumComfort"),
        lHigh: groupText("loadHigh"), lNormal: groupText("loadNormal"),
      })) + "</p>"
      : "";
    const head = ["vt.surface.hAxis", "vt.surface.hBand", "vt.surface.hLedgers", "vt.surface.hFails",
      "vt.surface.hRate", "vt.surface.hMine", "vt.surface.hMineRate", "vt.surface.hShare", "vt.surface.hConc"]
      .map((k, i) => '<th scope="col"' + (i === 0 ? ' class="vt-th-l"' : "") + ">" + h.esc(h.t(k)) + "</th>").join("");
    const visibleBands = (s.bands || []).filter((b) => b.ledgers > 0 || b.mineFails > 0);
    const body = visibleBands.map((b) => "<tr" + (b.hot ? ' class="vt-hot"' : "") + ">"
      + '<th scope="row">' + h.esc(h.t("vt.surface.axis." + b.axis)) + " · " + h.esc(b.label)
      + (b.reliable ? "" : " · " + h.esc(h.t("vt.surface.thin"))) + "</th>"
      + "<td>" + h.esc(num(b.ledgers)) + "</td>"
      + "<td>" + h.esc(num(b.failLedgers)) + "</td>"
      + "<td>" + h.esc(pct(b.networkRate)) + "</td>"
      + "<td>" + h.esc(num(b.mineFails)) + "</td>"
      + "<td>" + h.esc(pct(b.mineRate)) + "</td>"
      + "<td>" + h.esc(share(b.shareOfMine)) + "</td>"
      + "<td>" + h.esc(fac(b.concentration)) + "</td></tr>").join("");
    const table = visibleBands.length
      ? '<table class="vt-table"><thead><tr>' + head + "</tr></thead><tbody>" + body + "</tbody></table>"
      : '<p class="vt-empty">' + h.esc(h.t("vt.surface.bandsNone")) + "</p>";
    const hot = (s.hotspots || []).map((b) => "<li>" + h.esc(h.t("vt.surface.hotLine", {
      axis: h.t("vt.surface.axis." + b.axis), band: b.label, mine: num(b.mineFails),
      mineRate: pct(b.mineRate), conc: fac(b.concentration), netRate: pct(b.networkRate),
    })) + "</li>").join("");
    const hotBlock = hot
      ? '<h4 class="vt-h4">' + h.esc(h.t("vt.surface.hotTitle")) + '</h4><ul class="vt-list">' + hot + "</ul>"
      : "";
    const ihead = ["vt.surface.hCell", "vt.surface.hCellLedgers", "vt.surface.hCellFails",
      "vt.surface.hObserved", "vt.surface.hExpected", "vt.surface.hLift"]
      .map((k, i) => '<th scope="col"' + (i === 0 ? ' class="vt-th-l"' : "") + ">" + h.esc(h.t(k)) + "</th>").join("");
    const inter = (s.interactions || []).filter((x) => x.ledgers > 0).slice(0, 8).map((x) => "<tr"
      + (x.reliable ? "" : ' class="vt-thin"') + ">"
      + '<th scope="row">' + h.esc(x.loadLabel) + " × " + h.esc(x.marginLabel)
      + (x.reliable ? "" : " · " + h.esc(h.t("vt.surface.thin"))) + "</th>"
      + "<td>" + h.esc(num(x.ledgers)) + "</td>"
      + "<td>" + h.esc(num(x.failLedgers)) + "</td>"
      + "<td>" + h.esc(pct(x.rate)) + "</td>"
      + "<td>" + h.esc(pct(x.expected)) + "</td>"
      + "<td>" + h.esc(fac(x.interaction)) + "</td></tr>").join("");
    const interBlock = inter
      ? '<h4 class="vt-h4">' + h.esc(h.t("vt.surface.interTitle")) + '</h4><table class="vt-table"><thead><tr>' + ihead
        + "</tr></thead><tbody>" + inter + "</tbody></table>"
      : '<p class="vt-empty">' + h.esc(h.t("vt.surface.interNone")) + "</p>";
    const gapLine = (s.gaps || []).length
      ? '<p class="vt-note">' + h.esc(s.gaps.map((g) => h.t("vt.surface.gap." + g)).join(" · ")) + "</p>"
      : "";
    return verdictLine + covLine + sharesLine + groupLine + table + hotBlock + interBlock + gapLine;
  }

  // Kopplungs-Ebene: die Antwort auf die Frage, die eine Zahl nicht beantwortet - WELCHE
  // dUNL-Knoten auf GENAU diesem Ledger abwichen, und ob dieselbe Ledger-Form diesen Knoten
  // oefter traf als die Kohorten-Knoten unter derselben Last ohne diese Form. Jede Rate hat
  // ihren Nenner, jeder Ledger seine benannten Knoten, jede Luecke ihren Namen.
  function couplingBlock(c) {
    if (!c || !c.verdict) return '<p class="vt-empty">' + h.esc(h.t("vt.coupling.empty")) + "</p>";
    const cov = c.coverage || {};
    const th = c.thresholds || {};
    const ax = c.axes || {};
    const mass = c.simultaneity || {};
    const local = c.nodeLocal || {};
    // Prozentpunkte mit Vorzeichen: ein Lift ohne Richtung ist keine Auskunft, weil der Leser
    // die Richtung erst raten muesste.
    const pp = (v) => (Number.isFinite(v) ? (v >= 0 ? "+" : "") + (Math.round(v * 1000) / 10).toFixed(1) : "–");
    const verdictLine = '<p class="vt-scope"><span class="vt-badge vt-coupl-' + h.esc(c.verdict) + '">'
      + h.esc(h.t("vt.coupling.verdict." + c.verdict)) + "</span> · "
      + h.esc(h.t("vt.coupling.axis." + c.verdictAxis)) + " · "
      + h.esc(h.t("vt.coupling.authority." + c.verdictAuthority))
      + ' <code class="vt-code">' + h.esc(String(c.verdictReason)) + "</code></p>";
    const covLine = '<p class="vt-note">' + h.esc(h.t("vt.coupling.coverageLine", {
      rows: num(cov.forensicsRows), samples: num(cov.samples), dev: num(cov.deviatingLedgers),
      withRow: num(cov.deviatingLedgersWithRow), noRow: num(cov.deviatingLedgersWithoutRow),
      cohort: num(cov.cohortRows), unnamed: num(cov.namedMastersIncompleteRows),
      shape: num(cov.shapeRows), latency: num(cov.latencyRows), cadence: num(cov.cadenceRows),
    })) + "</p>";
    // Die Bevoelkerungs-Achse ist die einzige der vier, die nicht auf Forensik-Zeilen steht:
    // ihr Nenner ist jeder erfasste Ledger. Ein Befund auf dieser Achse gehoert deshalb an die
    // Achsen-Zeile, nicht nur in die Liste der Befunde. Ohne Antwort steht ein Gedankenstrich.
    const axisLine = '<p class="vt-note">' + h.esc(h.t("vt.coupling.axesLine", {
      node: h.t("vt.coupling.verdict." + ax.node), mass: h.t("vt.coupling.verdict." + ax.mass),
      network: h.t("vt.coupling.verdict." + ax.network), netLift: pp(ax.networkLift),
      population: ax.population ? h.t("vt.coupling.verdict." + ax.population) : "–",
      massNodes: num(th.simultaneityNodes), highNodes: num(th.massNodes), minSample: num(th.minSample),
    })) + "</p>";
    const findings = (c.findings || []).map((f) => "<li>" + h.esc(h.t("vt.coupling.axis." + f.axis)) + " · "
      + h.esc(f.tag === "signature-share-mass-vs-solo" ? h.t("vt.coupling.netTag") : tl(f.tag)) + " · "
      + h.esc(h.t("vt.coupling.verdict." + f.strength)) + " · "
      + h.esc(h.t("vt.coupling.findingLine", {
        lift: pp(f.lift), exposed: num(f.exposedLedgers), control: num(f.controlLedgers),
        failures: num(f.failures),
      })) + "</li>").join("");
    const findingsBlock = findings
      ? '<h4 class="vt-h4">' + h.esc(h.t("vt.coupling.findTitle")) + '</h4><ul class="vt-list">' + findings + "</ul>"
      : '<p class="vt-empty">' + h.esc(h.t("vt.coupling.findNone")) + "</p>";
    // Peaks: die Ledger mit Massen-Abweichung und die Knoten, die dort abwichen - beim Namen.
    // Die Gegenprobe der Lib (affectedTruth) haengt an denselben Knoten, deshalb wird sie hier
    // nicht nochmal erfunden, sondern aus derselben Zeile gelesen.
    const phead = ["vt.coupling.hLedger", "vt.coupling.hNodes", "vt.coupling.hTx", "vt.coupling.hBand",
      "vt.coupling.hSign", "vt.coupling.hMargin", "vt.coupling.hClosure"]
      .map((k, i) => '<th scope="col"' + (i === 0 ? ' class="vt-th-l"' : "") + ">" + h.esc(h.t(k)) + "</th>").join("");
    const pbody = (mass.peaks || []).map((p) => {
      const named = Array.isArray(p.masters) ? p.masters : [];
      const total = Number.isFinite(p.mastersTotal) ? p.mastersTotal : null;
      const rest = total !== null && total > named.length
        ? '<small class="vt-note">' + h.esc(h.t("vt.coupling.mastersMore", { n: total - named.length })) + "</small>"
        : "";
      return "<tr>"
        + '<th scope="row">#' + h.esc(num(p.ledgerIndex)) + " · " + h.esc(num(p.deviatingNodes)) + "</th>"
        + "<td>" + peerChips(named) + rest + "</td>"
        + "<td>" + h.esc(num(p.txCount)) + "</td>"
        + "<td>" + h.esc(p.loadLabel ?? "–") + "</td>"
        + "<td>" + h.esc((p.signatures || []).map((s) => tl(s)).join(", ") || "–") + "</td>"
        + "<td>" + h.esc(num(p.margin)) + " / " + h.esc(num(p.needed)) + "</td>"
        + "<td>" + h.esc(h.t(p.closureClosed === true ? "vt.coupling.closed" : "vt.coupling.open")) + "</td></tr>";
    }).join("");
    const peakTable = pbody
      ? '<h4 class="vt-h4">' + h.esc(h.t("vt.coupling.peakTitle")) + '</h4><div class="vt-tablewrap"><table class="vt-table vt-coupling-peaks"><thead><tr>'
        + phead + "</tr></thead><tbody>" + pbody + "</tbody></table></div>"
      : '<p class="vt-empty">' + h.esc(h.t("vt.coupling.peakNone")) + "</p>";
    const shead = ["vt.coupling.hSignTag", "vt.coupling.hExposed", "vt.coupling.hMass", "vt.coupling.hMassLift",
      "vt.coupling.hOwn", "vt.coupling.hOwnLift", "vt.coupling.hVerdict"]
      .map((k, i) => '<th scope="col"' + (i === 0 ? ' class="vt-th-l"' : "") + ">" + h.esc(h.t(k)) + "</th>").join("");
    const sbody = (c.signatures || []).map((s) => "<tr>"
      + '<th scope="row">' + h.esc(tl(s.tag)) + "</th>"
      + "<td>" + h.esc(num(s.ledgersTotal)) + " / " + h.esc(num(s.controlTotal)) + "</td>"
      + "<td>" + h.esc(num(s.massDeviationExposed)) + " / " + h.esc(num(s.massDeviationControl))
      + " · " + h.esc(pcn((s.rateExposed ?? 0) * 100)) + " % / " + h.esc(pcn((s.rateControl ?? 0) * 100)) + " %</td>"
      + "<td>" + h.esc(pp(s.lift)) + "</td>"
      + "<td>" + h.esc(num(s.ownFailures)) + " / " + h.esc(num(s.ownFailureLedgers ? s.ownFailureLedgers.length : 0))
      + " · " + h.esc(pcn((s.ownRateExposed ?? 0) * 100)) + " % / " + h.esc(pcn((s.ownRateControl ?? 0) * 100)) + " %</td>"
      + "<td>" + h.esc(pp(s.ownLift)) + "</td>"
      + "<td>" + h.esc(h.t("vt.coupling.verdict." + s.verdict)) + " / "
      + h.esc(h.t("vt.coupling.verdict." + s.ownVerdict)) + "</td></tr>").join("");
    const sigTable = sbody
      ? '<h4 class="vt-h4">' + h.esc(h.t("vt.coupling.sigTitle")) + '</h4><div class="vt-tablewrap"><table class="vt-table vt-coupling-sig"><thead><tr>'
        + shead + "</tr></thead><tbody>" + sbody + "</tbody></table></div>"
      : '<p class="vt-empty">' + h.esc(h.t("vt.coupling.sigNone")) + "</p>";
    const localLine = '<p class="vt-note">' + h.esc(h.t("vt.coupling.localLine", {
      own: num(local.ownFailureLedgers), stressed: num(local.ownFailureLedgersWithStress),
      quiet: num(local.ownFailureLedgersWithoutStress), solo: num(local.soloUnderStress),
      share: Number.isFinite(local.stressShare) ? pcn(local.stressShare * 100) + " %" : "–",
    })) + "</p>";
    const gapLine = (c.gaps || []).length
      ? '<p class="vt-note">' + h.esc(c.gaps.map((g) => h.t("vt.coupling.gap." + g)).join(" · ")) + "</p>"
      : "";
    // Die Dosis-Kurve: eine Rate je Ledger-Groessenband und ein Urteil ueber die Achse hinweg.
    // Ohne sie ist die Lastachse eine Zahlensammlung; mit ihr ist die Richtung sichtbar -
    // inklusive der Stufe, die nicht steigt. Eine Achse als 'streng monoton' zu melden, wo eine
    // Stufe faellt, waere eine Schaetzung ueber die eigene Messung hinweg. Das Urteil zaehlt nur
    // Baelnder mit vollem Nenner, und der Nenner steht in jeder Zeile der Tabelle.
    const loadBlock = (() => {
      const la = c.loadAxis;
      if (!la || !Array.isArray(la.rows) || la.rows.length === 0)
        return '<p class="vt-empty">' + h.esc(h.t("vt.dose.none")) + "</p>";
      const tr = la.trend || {};
      const lhead = ["vt.dose.hBand", "vt.dose.hLedgers", "vt.dose.hFails", "vt.dose.hRate",
        "vt.dose.hOwn", "vt.dose.hOwnRate", "vt.dose.hSample"]
        .map((k, i) => '<th scope="col"' + (i === 0 ? ' class="vt-th-l"' : "") + ">" + h.esc(h.t(k)) + "</th>").join("");
      const lbody = la.rows.map((r) => "<tr>"
        + '<th scope="row">' + h.esc(String(r.label ?? "–")) + "</th>"
        + "<td>" + h.esc(num(r.ledgers)) + "</td>"
        + "<td>" + h.esc(num(r.fails)) + "</td>"
        + "<td>" + h.esc(pcn((r.networkRate ?? 0) * 100) + " %") + "</td>"
        + "<td>" + h.esc(num(r.own)) + "</td>"
        + "<td>" + h.esc(pcn((r.ownRate ?? 0) * 100) + " %") + "</td>"
        + "<td>" + h.esc(h.t("vt.dose.sample." + (r.sample === "measured" ? "measured" : "thin"))) + "</td></tr>").join("");
      const verdict = LOAD_TREND_VERDICTS.has(tr.verdict) ? tr.verdict : "insufficient-sample";
      const head = '<p class="vt-scope"><span class="vt-badge vt-load-' + h.esc(verdict) + '">'
        + h.esc(h.t("vt.dose.verdict." + verdict)) + "</span>"
        + (Number.isFinite(tr.bandsMeasured) ? " · " + h.esc(h.t("vt.dose.sample." + (tr.bandsMeasured > 0 ? "measured" : "thin")))
          + " " + num(tr.bandsMeasured) + " / " + num(la.rows.length) : "") + "</p>";
      const trendLine = Number.isFinite(tr.lowerRate) && Number.isFinite(tr.upperRate)
        ? '<p class="vt-note">' + h.esc(h.t("vt.dose.trendLine", {
            bands: num(tr.bandsMeasured), ledgers: num(tr.ledgersMeasured),
            lower: pcn(tr.lowerRate * 100), upper: pcn(tr.upperRate * 100),
            ratio: Number.isFinite(tr.halfRatio) ? (Math.round(tr.halfRatio * 100) / 100).toFixed(2) : "–",
            rising: num(tr.risingSteps), steps: num(tr.steps),
            peak: String((tr.peakBand && tr.peakBand.label) ?? "–"),
          }) + " · " + h.esc(h.t(tr.monotone === true ? "vt.dose.monotone.yes" : "vt.dose.monotone.no",
            { falling: num(tr.fallingSteps) }))) + "</p>"
        : "";
      const ownLine = Number.isFinite(tr.rateMeasured)
        ? '<p class="vt-note">' + h.esc(h.t("vt.dose.ownLine", {
            own: num(tr.ownMeasured), ledgers: num(tr.ledgersMeasured),
            ownRate: pcn((tr.ownRateMeasured ?? 0) * 100) + " %", rate: pcn(tr.rateMeasured * 100) + " %",
          })) + "</p>" : "";
      const axisGap = Number.isFinite(la.ledgersWithoutAxis) && la.ledgersWithoutAxis > 0
        ? '<p class="vt-note">' + h.esc(h.t("vt.dose.withoutAxis", { n: num(la.ledgersWithoutAxis) })) + "</p>" : "";
      return '<h4 class="vt-h4">' + h.esc(h.t("vt.dose.title")) + '</h4>' + head
        + '<div class="vt-tablewrap"><table class="vt-table vt-load-axis"><thead><tr>' + lhead
        + "</tr></thead><tbody>" + lbody + "</tbody></table></div>"
        + trendLine + ownLine + axisGap
        + '<p class="vt-note"><small>' + h.esc(h.t("vt.dose.authority")) + "</small></p>";
    })();
    return verdictLine + covLine + axisLine + loadBlock + findingsBlock + peakTable + sigTable + localLine + gapLine;
  }

  // Netz-Sicht: erst die Trennung Netzereignis / privat, dann Kandidaten fuer geteilte
  // Infrastruktur (nur privat), dann die Fenster je Validator. Ohne diese Trennung zaehlt man
  // ein Netzereignis als Infrastruktur - der Messfehler, den diese Ebene zuerst selbst hatte.
  // Zeit-Ebene: Honeypot-Sichtungen gegen die Ausfallserien aller dUNL-Knoten. Das Urteil hängt
  // an der gepaarten Gegenprobe (Angriffsstunde gegen dieselbe UTC-Stunde an ruhigen Tagen),
  // nicht am rohen Lift - der rohe Lift ist in einem Netz mit Stoßzeiten meist die Uhrzeit.
  // Beides bleibt sichtbar: der rohe Wert, damit die Falle erkennbar bleibt, die Gegenprobe,
  // damit das Urteil an ihr hängt und nicht an der Zahl, die am schönsten aussieht.
  // Die Vergleichs-Details werden nur gezeigt, wenn es Überlappungsstunden gibt. Eine Tabelle
  // voller Nullen wirkt wie ein Befund, ist aber nur eine Lücke - und Lücken haben hier schon
  // eine eigene Zeile (Aufzeichnungs-Abdeckung).
  function impactBlock(imp) {
    if (!imp || !imp.verdict) return '<p class="vt-empty">' + h.esc(h.t("vt.impact.empty")) + "</p>";
    const cov = imp.coverage || {};
    const net = imp.network || {};
    const mt = imp.matched || {};
    const lag = imp.lag || {};
    const th = imp.thresholds || {};
    // null ist hier "nicht gemessen", nicht 0. num() würde null zu "0" machen.
    const nz = (v) => (Number.isFinite(v) ? String(v) : "–");
    // Kleine Raten duerfen nicht wie Null aussehen. 0,015 % als "0,0 %" zu zeigen ist eine
    // Luege durch Rundung - und genau die Raten der ruhigen Gegenprobe liegen in diesem Bereich.
    const rate = (v) => {
      if (!Number.isFinite(v)) return "–";
      const p = v * 100;
      if (p >= 10) return p.toFixed(1) + " %";
      if (p >= 0.1) return p.toFixed(2) + " %";
      if (p > 0) return p.toFixed(3) + " %";
      return "0 %";
    };
    const share = (v) => (Number.isFinite(v) ? Math.round(v * 100) + " %" : "–");
    const has = Number.isFinite(cov.overlapCells) && cov.overlapCells > 0;
    const cards = [["vt.impact.k.clusters", nz(cov.clustersInWindow)],
      ["vt.impact.k.overlap", nz(cov.overlapCells) + " / " + nz(cov.attackCells)],
      ["vt.impact.k.attackLedgers", nz(cov.attackLedgers)],
      ["vt.impact.k.quietLedgers", nz(cov.quietLedgers)],
      ["vt.impact.k.rateWith", rate(net.rateWith)],
      ["vt.impact.k.rateMatched", rate(mt.rateMatched)]]
      .map(([k, v]) => '<div class="vt-card"><small>' + h.esc(h.t(k)) + "</small><b>" + h.esc(v) + "</b></div>").join("");
    const badge = '<p class="vt-scope"><span class="vt-badge vt-impv-' + h.esc(imp.verdict) + '">'
      + h.esc(h.t("vt.impact.verdict." + imp.verdict)) + "</span> <small>"
      + h.esc(h.t("vt.impact.scope", { measured: nz(cov.measuredCells), attack: nz(cov.attackCells), thin: nz(cov.thinCells) }))
      + "</small> <small>"
      + h.esc(h.t("vt.impact.authority", {
        authority: h.t("vt.impact.authority." + imp.verdictAuthority), reason: h.t("vt.impact.reason." + imp.verdictReason),
      })) + "</small></p>";
    const head = (keys) => keys.map((k, i) => '<th scope="col"' + (i === 0 ? ' class="vt-th-l"' : "") + ">" + h.esc(h.t(k)) + "</th>").join("");
    const table = (keys, rows) => '<table class="vt-table"><thead><tr>' + head(keys) + "</tr></thead><tbody>" + rows + "</tbody></table>";
    const wRows = (imp.windows || []).map((w) => "<tr>"
      + '<th scope="row">' + h.esc(stamp(w.timeMs)) + "</th>"
      + "<td>" + nz(w.clusters) + "</td><td>" + nz(w.txCount) + "</td><td>" + nz(w.ledgerTxMax) + "</td>"
      + "<td>" + nz(w.accounts) + "</td><td>" + nz(w.drops) + "</td>"
      + "<td>" + nz(w.ledgers) + "</td><td>" + nz(w.incidentLedgers) + "</td>"
      + "<td>" + rate(w.rate) + "</td>"
      + '<td class="vt-imp-rules">' + (w.rules || []).map((r) => '<span class="vt-chip">' + h.esc(tl(r.rule))
      + " × " + h.esc(String(r.count)) + "</span>").join("") + "</td></tr>").join("");
    const rRows = (imp.rules || []).map((r) => "<tr>"
      + '<th scope="row">' + h.esc(tl(r.rule)) + "</th>"
      + "<td>" + nz(r.clustersSeen) + "</td><td>" + nz(r.clustersInRecording) + "</td>"
      + "<td>" + share(r.share) + "</td></tr>").join("");
    const vRows = (imp.validators || []).map((v) => "<tr>"
      + '<th scope="row">' + h.esc(String(v.master).slice(0, 12)) + "…"
      + (v.reliable ? "" : '<small class="vt-small">' + h.esc(h.t("vt.impact.reliableNo")) + "</small>") + "</th>"
      + "<td>" + nz(v.ledgersWith) + "</td><td>" + rate(v.rateWith) + "</td>"
      + "<td>" + rate(v.rateMatched) + "</td>"
      + "<td>" + (Number.isFinite(v.liftMatched) ? "×" + fac(v.liftMatched) : "–") + "</td>"
      + "<td>" + (Number.isFinite(v.zMatched) ? v.zMatched.toFixed(2) : "–") + "</td></tr>").join("");
    // Zwei Autoritaeten, eine Tabelle: die History ist die Behauptung des Clients, der Trace die
    // eigene Messung. Beide Zeilen stehen nebeneinander, damit ein Widerspruch sichtbar bleibt,
    // statt dass eine einzelne Zahl das Urteil traegt. Eine fehlende Ebene zeigt "–", nicht 0.
    const src = imp.sources || {};
    const srcRow = (label, s) => {
      const an = (s && s.analysis) || {};
      const basis = label === "trace" ? (s ? s.signatureCells : null) : (s ? s.attackCells : null);
      return "<tr>"
        + '<th scope="row">' + h.esc(h.t("vt.impact.authority." + label))
        + (s && s.available ? "" : '<small class="vt-small">' + h.esc(h.t("vt.impact.srcOff")) + "</small>") + "</th>"
        + "<td>" + nz(basis) + "</td><td>" + nz(s ? s.overlapCells : null) + "</td>"
        + "<td>" + rate(an.rateWith) + "</td><td>" + rate(an.rateMatched) + "</td>"
        + "<td>" + nz(an.contributingValidators) + "</td></tr>";
    };
    const sourcesBlock = (src.history || src.trace)
      ? '<p class="vt-note">' + h.esc(h.t("vt.impact.srcTitle", {
        threshold: nz(th.minTraceSignatureLedgers), hours: nz(cov.traceForensicsHours), cells: nz(cov.signatureCells),
      })) + "</p>"
      + table(["vt.impact.hSource", "vt.impact.hBasis", "vt.impact.hOverlap", "vt.impact.hRateWith",
        "vt.impact.hRateMatched", "vt.impact.hContrib"], srcRow("history", src.history) + srcRow("trace", src.trace))
      : "";
    const tw = net.typesWith || {};
    const tq = net.typesWithout || {};
    const compare = has
      ? '<p class="vt-note">' + h.esc(h.t("vt.impact.rawLift", { lift: fac(net.lift), z: nz(net.zRaw) })) + "</p>"
        + '<p class="vt-note">' + h.esc(h.t("vt.impact.matched", {
          cells: nz(mt.cells), matched: nz(mt.matchedCells), uncontrolled: nz(mt.uncontrolledCells),
          attack: rate(mt.rateAttack), quiet: rate(mt.rateMatched), ratio: fac(mt.ratio), z: nz(mt.z),
        })) + "</p>"
        + '<p class="vt-note">' + h.esc(h.t("vt.impact.pairNote", {
          fails: nz(net.pairFailsWith), pairs: nz(net.pairsWith),
          quietFails: nz(net.pairFailsWithout), quietPairs: nz(net.pairsWithout),
          ledgerWith: rate(net.ledgerRateWith), ledgerWithout: rate(net.ledgerRateWithout),
        })) + "</p>"
        + (Number.isFinite(lag.cells) && lag.cells > 0
          ? '<p class="vt-note">' + h.esc(h.t("vt.impact.lag", {
            before: rate(lag.before), during: rate(lag.during), after: rate(lag.after), cells: nz(lag.cells),
          })) + "</p>" : "")
        + (wRows ? table(["vt.impact.hTime", "vt.impact.hClusters", "vt.impact.hTx", "vt.impact.hTxPeak", "vt.impact.hAccounts",
          "vt.impact.hDrops", "vt.impact.hLedgers", "vt.impact.hFails", "vt.impact.hRate", "vt.impact.hRules"], wRows)
          : '<p class="vt-empty">' + h.esc(h.t("vt.impact.noWindows")) + "</p>")
        + '<p class="vt-note">' + h.esc(h.t("vt.impact.typesNote", {
          missed: nz(tw.missed), partial: nz(tw.partial), wrongHash: nz(tw.wrongHash), noQuorum: nz(tw.noQuorum),
          qMissed: nz(tq.missed), qPartial: nz(tq.partial), qWrongHash: nz(tq.wrongHash), qNoQuorum: nz(tq.noQuorum),
        })) + "</p>"
        + (vRows ? table(["vt.impact.hValidator", "vt.impact.hLedgersWith", "vt.impact.hRateWith",
          "vt.impact.hRateMatched", "vt.impact.hLiftMatched", "vt.impact.hZ"], vRows)
          : '<p class="vt-empty">' + h.esc(h.t("vt.impact.noValidators")) + "</p>")
      : '<p class="vt-empty">' + h.esc(h.t("vt.impact.noWindows")) + "</p>";
    // Ohne Uberlappungsstunde gibt es keinen Effekt, dessen Trager man zahlen koennte.
    const contrib = has && Number.isFinite(net.observedValidators) && net.observedValidators > 0
      ? '<p class="vt-note">' + h.esc(h.t("vt.impact.contrib", {
        contributing: nz(net.contributingValidators), observed: nz(net.observedValidators),
        min: nz(th.minContributingValidators),
      })) + "</p>" : "";
    const gap = Number.isFinite(cov.clustersOutsideRecording) && cov.clustersOutsideRecording > 0
      ? '<p class="vt-note">' + h.esc(h.t("vt.impact.gapNote", {
        outside: nz(cov.clustersOutsideRecording), total: nz(cov.clustersInWindow),
      })) + "</p>" : "";
    const thresholds = '<p class="vt-note">' + h.esc(h.t("vt.impact.thresholdNote", {
      cell: nz((cov.cellMs || 0) / 60000), cellMin: nz(th.minCellLedgers), attackMin: nz(th.minAttackCells),
      groupMin: nz(th.minGroupPairs), z: nz(th.zThreshold), contribMin: nz(th.minContributingValidators),
    })) + "</p>";
    return badge
      + '<div class="vt-cards">' + cards + "</div>"
      + contrib + gap + sourcesBlock + compare
      + '<h3 class="vt-h">' + h.esc(h.t("vt.impact.rulesTitle")) + "</h3>"
      + (rRows ? table(["vt.impact.hRule", "vt.impact.hSeen", "vt.impact.hInRecording", "vt.impact.hShare"], rRows)
        : '<p class="vt-empty">' + h.esc(h.t("vt.impact.noRules")) + "</p>")
      + thresholds;
  }  function networkBlock(split, clusters, windows) {
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
      .map(([k, v]) => '<li class="vt-row"><span class="vt-key">' + h.esc(k.slice(0, 12)) + "…</span><span>" + h.esc(h.t("vt.k.missed")) + " " + h.esc(String(v.missed)) + " · " + h.esc(h.t("vt.k.no-quorum")) + " " + h.esc(String(v.noQuorum ?? 0)) + " · " + h.esc(h.t("vt.k.partial")) + " " + h.esc(String(v.partial)) + " · " + h.esc(h.t("vt.k.wrong-hash")) + " " + h.esc(String(v.wrongHash)) + "</span></li>").join("");
    body.innerHTML = '<p class="vt-h">' + h.esc(h.t("vt.incidentsTotal", { n: d.incidents })) + "</p>"
      + '<h3 class="vt-h">' + h.esc(h.t("vt.impactTitle")) + '</h3><p class="vt-sub">' + h.esc(h.t("vt.impactNote")) + "</p>" + impactBlock(d.impact)
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
    // Aeltere Vorfaelle waren bisher unerreichbar: gezeichnet wurden 12 Karten, gesendet werden
    // mehr. Aufdecken kostet keine neue Anfrage - die Karten sind schon in der Antwort.
    const more = body.querySelector(".vt-rc-more");
    if (more) {
      more.addEventListener("click", () => {
        const hidden = body.querySelector(".vt-rc-rest");
        if (hidden) hidden.hidden = false;
        more.remove();
      });
    }
    body.querySelectorAll("[data-peer-more]").forEach((btn) => {
      btn.addEventListener("click", () => {
        const rest = btn.parentElement && btn.parentElement.querySelector(".vt-peer-rest");
        if (rest) rest.hidden = false;
        btn.remove();
      });
    });
    const readout = body.querySelector("#vt-readout");
    if (!readout) return;
    body.querySelectorAll(".vt-col").forEach((col) => {
      const show = () => { readout.textContent = col.dataset.tip || h.t("vt.profileHint"); };
      col.addEventListener("mouseenter", show);
      col.addEventListener("focus", show);
    });
  }

  // names: Map (oder Array von [master, domain]) aus der bereits gezeichneten Validatorenliste.
  // Wer ohne Namen aufgerufen wird, sieht gekuerzte Keys - nie eine erfundene Bezeichnung.
  function rememberNames(names) {
    if (names instanceof Map) nameMap = names;
    else if (Array.isArray(names)) nameMap = new Map(names);
  }
  function openValidator(master, title, ref, names) {
    rememberNames(names);
    current = { mode: "validator", master, title: title || master.slice(0, 14) + "…", range: "24h", ref: ref || null };
    load();
  }
  function openPatterns(names) {
    rememberNames(names);
    current = { mode: "patterns", master: null, title: "", range: "24h" };
    load();
  }
  return { openValidator, openPatterns, close };
}
