'use strict';
// public/cluster-chips.mjs — DOM-freie Helfer für die Adress-Chip-Zeile
// (Börsen-Name-Chip + Destination-Tag-Chip) in Cluster-Karten: Live-Host
// (public/app.js clusterCardHtml) und Flow-Host (public/history-host.html
// clusterCardHtml). Muster: Drilldown-Konten-Tabelle (public/drilldown.js
// renderTable — tagsByAddr :1081-1087, Tag-Chips aufsteigend Cap 3 + '+'
// :1117-1123).
//
// MODUL-VERTRAG (Muster public/name-index.mjs:4-27, public/exchange-registry.mjs:5-25):
// DOM-frei beim Import, kein fetch, kein window/document. Das Chip-MARKUP
// ist Host-Sache und wird als Funktion injiziert — der Host gatet es
// (app.js: isFullShownAddr + accountNameOf/multiUserEntryOf; history-host:
// verified===true + multiUserEntryOf). Dieses Modul wählt, sortiert und
// kappt nur — es erfindet nie ein Chip-Markup und nie einen Tag.
//
// Fail-closed: injizierte Chip-Funktion liefert '' → kein Chip, kein
// Eintrag. Tags kommen ausschließlich aus aufgezeichnetem edge.toTag
// (lib/cluster.mjs:344-345 WSS-Pfad, lib/flow-state.mjs viewEdge
// Server-Pfad — dort bereits Registry-/verified-gegatet).

// Distinct toTags je Ziel-Adresse aus Cluster-Kanten (Drilldown-Muster).
// memberSet (optional): filtert Kanten auf Cluster-Mitglieder — der WSS-Pfad
// führt Kanten global im Graphen, die Karte braucht nur die internen
// (dieselbe Filterung wie app.js clusterCardHtml Flusskette).
export function collectTagsByAddr(edges, memberSet = null) {
  const tagsByAddr = new Map();
  for (const e of Array.isArray(edges) ? edges : []) {
    if (!e || e.toTag == null) continue;
    const key = String(e.to ?? '');
    if (!key) continue;
    if (memberSet && !memberSet.has(key)) continue;
    if (!tagsByAddr.has(key)) tagsByAddr.set(key, new Set());
    tagsByAddr.get(key).add(e.toTag);
  }
  return tagsByAddr;
}

// Tag-Chips einer Adresse: aufsteigend sortiert, Cap tagCap, '+'-Hinweis
// bei mehr (Muster drilldown.js :1119-1123). tagChipFn ist Host-Gate-Sache
// (liefert '' ohne Multi-User-Treffer / ohne ganzzahligen Tag).
export function tagChipsHtml(addr, tagSet, tagChipFn, tagCap = 3) {
  if (!tagSet || typeof tagSet.size !== 'number' || !tagSet.size) return '';
  if (typeof tagChipFn !== 'function') return ''; // fail-closed ohne Host-Lookup
  const tags = [...tagSet].sort((a, b) => a - b);
  let html = tags.slice(0, tagCap).map((tg) => tagChipFn(addr, tg)).join('');
  if (tags.length > tagCap) html += '<span class="cluster-addr-more" aria-hidden="true">+</span>';
  return html;
}

// Adress-Chip-Zeile einer Cluster-Karte: Mitglieder MIT Name- ODER
// Tag-Chip (Coverage-Fix 2026-10-06: Exchange-Konten mit belegtem Tag ohne
// XRPScan-Namen waren bisher unsichtbar — die Zeile zeigte nur Name-Treffer).
// Harte Cap pro Karte; deterministische Auswahl:
//   sort 'drops' (Live-Host): Drops desc (wie bisher), dann Tags desc,
//     dann Adresse asc — Totalordnung, keine Render-Reihenfolge-Zufälle.
//   sort 'tags'  (Flow-Host): Tags desc, dann Adresse asc — der
//     akkumulierte State führt keine Drops je Adresse, und rolesByAddress
//     kann zehntausende Einträge tragen; ohne Cap und ohne dieses
//     Kriterium wäre die Zeile nicht begrenzt und nicht deterministisch.
export function addrChipsRowHtml(opts) {
  const {
    members, tagsByAddr, nameChipHtml, tagChipHtml,
    dropsByAddr = null, cap = 5, tagCap = 3, sort = 'drops',
  } = opts ?? {};
  const entries = [];
  for (const a of Array.isArray(members) ? members : []) {
    const addr = String(a);
    const nameHtml = typeof nameChipHtml === 'function' ? nameChipHtml(addr) : '';
    const tagSet = tagsByAddr instanceof Map ? tagsByAddr.get(addr) : null;
    const tagHtml = tagChipsHtml(addr, tagSet, tagChipHtml, tagCap);
    if (!nameHtml && !tagHtml) continue; // fail-closed: kein Chip → kein Eintrag
    entries.push({
      a: addr,
      html: nameHtml + tagHtml,
      tags: tagSet ? tagSet.size : 0,
      drops: dropsByAddr instanceof Map ? (Number(dropsByAddr.get(addr)) || 0) : 0,
    });
  }
  if (!entries.length) return '';
  if (sort === 'tags') {
    entries.sort((x, y) => (y.tags - x.tags) || x.a.localeCompare(y.a));
  } else {
    entries.sort((x, y) => (y.drops - x.drops) || (y.tags - x.tags) || x.a.localeCompare(y.a));
  }
  const chips = entries.slice(0, Math.max(1, Math.floor(Number(cap) || 5)))
    .map((x) => `<span class="cluster-addr-chips">${x.html}</span>`)
    .join('');
  return `<div class="cluster-names cluster-addr-row">${chips}</div>`;
}
