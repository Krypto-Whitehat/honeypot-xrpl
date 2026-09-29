// lib/sanitize.mjs — zentrale Anonymitätsschicht (single source of truth).
// Wird vom lokalen Server (server/index.mjs) UND von den Vercel-Functions
// (api/*.js via lib/threats-service.mjs) genutzt. Jede öffentliche Antwort
// MUSS dadurch laufen.
//
// Regeln:
//   (a) Evidence enthält KEINEN txHash — nur { ref, type, time, honeypot }.
//   (b) Jede Köder-Adresse (Union aktuell + historisch) wird durch ihr Label
//       ersetzt — in Adressen, Reason-Texten, Funding und Graph-Knoten.
//   (c) Graph-Node-Ids: "honeypot:N" / "attacker:<öffentliche Adresse>".
//   (d) Funding-Einträge werden nur als Label veröffentlicht.
// Seeds werden niemals gelesen oder ausgegeben.

// Interne Labels "HP-1" -> öffentliche Labels "Köder #1".
export function honeypotPublicLabel(label) {
  return String(label ?? "").replace(/^HP-/, "Köder #");
}

// Stabile öffentliche Node-Id für einen Köder: "honeypot:<n>" — niemals eine Adresse.
export function honeypotNodeId(labelOrAddress, baitLabels) {
  let label = String(labelOrAddress ?? "");
  if (baitLabels.has(labelOrAddress)) label = baitLabels.get(labelOrAddress);
  const m = /^HP-(\d+)$/.exec(label);
  if (m) return `honeypot:${m[1]}`;
  const digits = label.replace(/[^0-9]/g, "");
  return `honeypot:${digits || label.replace(/[^A-Za-z0-9-]/g, "") || "x"}`;
}

// Ersetzt in freiem Text jede Bait-Adresse durch ihr Label und normalisiert
// interne HP-n-Labels zu "Köder #n".
export function sanitizeText(text, baitLabels) {
  let s = String(text ?? "");
  for (const [addr, label] of baitLabels) {
    if (s.includes(addr)) s = s.split(addr).join(honeypotPublicLabel(label));
  }
  return s.replace(/\bHP-(\d+)\b/g, "Köder #$1");
}

// Evidence: KEIN txHash — nur ref/type/time/honeypot.
export function sanitizeEvidence(evidence, baitLabels) {
  return (Array.isArray(evidence) ? evidence : []).map((ev, i) => {
    let honeypot = String(ev?.honeypot ?? "");
    if (baitLabels.has(ev?.honeypot)) honeypot = baitLabels.get(ev.honeypot);
    return {
      ref: `E-${i + 1}`,
      type: ev?.type ?? "tx",
      time: ev?.time ?? null,
      honeypot: honeypotPublicLabel(sanitizeText(honeypot, baitLabels)),
    };
  });
}

// Funding: nur Labels, niemals Adressen. Faucet-Konten erscheinen als
// Faucet-Label ohne Adresse.
export function sanitizeFunding(funding, baitLabels, faucetAddresses, faucetLabel = "Faucet (benign)") {
  return (Array.isArray(funding) ? funding : []).map((f) => {
    if (f?.address && faucetAddresses.has(f.address)) {
      return { label: faucetLabel };
    }
    if (f?.address && baitLabels.has(f.address)) {
      return { label: honeypotPublicLabel(baitLabels.get(f.address)) };
    }
    return { label: sanitizeText(f?.label ?? "Funding-Quelle", baitLabels) };
  });
}

export function sanitizeThreat(t, { baitLabels, faucetAddresses, faucetLabel }) {
  const isBaitAddress = t?.address && baitLabels.has(t.address);
  return {
    address: isBaitAddress
      ? honeypotPublicLabel(baitLabels.get(t.address))
      : String(t?.address ?? ""),
    risk: t?.risk ?? "suspect",
    reason: sanitizeText(t?.reason, baitLabels),
    evidence: sanitizeEvidence(t?.evidence, baitLabels),
    firstSeen: t?.firstSeen ?? null,
    funding: sanitizeFunding(t?.funding, baitLabels, faucetAddresses, faucetLabel),
  };
}

// Graph-Aufbau aus rohen Threats — Knoten/Ids bereits anonymisiert.
export function buildGraph(threats, { baitLabels }) {
  const nodes = new Map();
  const edges = [];
  for (const raw of threats) {
    if (!raw?.address) continue;
    if (baitLabels.has(raw.address)) {
      const hpId = honeypotNodeId(raw.address, baitLabels);
      if (!nodes.has(hpId)) {
        nodes.set(hpId, {
          id: hpId,
          label: honeypotPublicLabel(baitLabels.get(raw.address)),
          type: "honeypot",
        });
      }
      continue;
    }
    nodes.set(raw.address, { id: raw.address, label: raw.address, type: "attacker" });
    for (const ev of raw.evidence ?? []) {
      if (!ev.honeypot) continue;
      const hpId = honeypotNodeId(ev.honeypot, baitLabels);
      if (!nodes.has(hpId)) {
        // Label-Auflösung wie in sanitizeEvidence (:42-48): trägt die Evidence
        // eine rohe Köder-Adresse statt eines HP-n-Labels, muss sie über die
        // baitLabels-Union ins Label übersetzt werden — sonst landet die volle
        // Köder-Adresse als Knoten-Label im öffentlichen Graph.
        let hpLabel = String(ev.honeypot);
        if (baitLabels.has(ev.honeypot)) hpLabel = baitLabels.get(ev.honeypot);
        nodes.set(hpId, {
          id: hpId,
          label: honeypotPublicLabel(sanitizeText(hpLabel, baitLabels)),
          type: "honeypot",
        });
      }
      edges.push({ from: raw.address, to: hpId, type: ev.type ?? "tx" });
    }
  }
  return {
    nodes: [...nodes.values()].map((n) =>
      n.type === "attacker" ? { ...n, id: `attacker:${n.id}` } : n
    ),
    edges: edges.map((e) => ({ from: `attacker:${e.from}`, to: e.to, type: e.type })),
  };
}

export function computeStats(threats, network) {
  let maliciousCount = 0;
  let suspectCount = 0;
  let eventCount = 0;
  let lastEventTime = null;
  for (const t of threats) {
    if (t.risk === "malicious") maliciousCount += 1;
    else if (t.risk === "suspect") suspectCount += 1;
    for (const ev of t.evidence ?? []) {
      eventCount += 1;
      if (ev.time && (!lastEventTime || ev.time > lastEventTime)) lastEventTime = ev.time;
    }
  }
  return { maliciousCount, suspectCount, eventCount, lastEventTime, network };
}
