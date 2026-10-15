/* render.js — draws the ladder (waterfall) view and the timeline view as SVG.
   All colours are written inline so the SVG exports exactly as it looks on screen. */
(function () {
  'use strict';
  const NS = 'http://www.w3.org/2000/svg';

  const THEMES = {
    light: { surface: '#fcfcfb', page: '#f9f9f7', ink: '#0b0b0b', ink2: '#52514e', muted: '#898781', grid: '#e1e0d9', axis: '#c3c2b7', highlight: 'rgba(11,11,11,0.06)', select: 'rgba(42,120,214,0.12)',
      families: { TCP: '#2a78d6', TLS: '#eb6834', HTTP: '#1baf7a', DNS: '#eda100', UDP: '#e87ba4', ICMP: '#008300', ARP: '#6250d6', Other: '#898781' } },
    dark: { surface: '#1a1a19', page: '#0d0d0d', ink: '#f0efec', ink2: '#c3c2b7', muted: '#898781', grid: '#2c2c2a', axis: '#383835', highlight: 'rgba(255,255,255,0.07)', select: 'rgba(57,135,229,0.22)',
      families: { TCP: '#3987e5', TLS: '#d95926', HTTP: '#199e70', DNS: '#c98500', UDP: '#d55181', ICMP: '#008300', ARP: '#9085e9', Other: '#898781' } },
  };

  const FAMILY_OF = { TCP: 'TCP', TLS: 'TLS', QUIC: 'TLS', HTTP: 'HTTP', HTTP2: 'HTTP', SSDP: 'HTTP', DNS: 'DNS', mDNS: 'DNS', LLMNR: 'DNS', NBNS: 'DNS', UDP: 'UDP', ICMP: 'ICMP', ICMPv6: 'ICMP', ARP: 'ARP' };

  function colorFor(project, theme, ev) {
    if (ev.color) return ev.color;
    const pc = project.protoColors || {};
    if (pc[ev.proto]) return pc[ev.proto];
    const fam = ev.family || FAMILY_OF[ev.proto] || 'Other';
    if (pc[fam]) return pc[fam];
    return theme.families[fam] || theme.families.Other;
  }
  function protoColor(project, theme, proto) { return colorFor(project, theme, { proto, family: FAMILY_OF[proto] || (theme.families[proto] ? proto : 'Other') }); }

  // ---------- text measurement ----------
  const canvas = document.createElement('canvas');
  const ctx = canvas.getContext('2d');
  const FONT = 'system-ui, -apple-system, "Segoe UI", sans-serif';
  function measure(text, size, weight) { ctx.font = `${weight || 400} ${size}px ${FONT}`; return ctx.measureText(text).width; }
  function truncate(text, size, maxW, weight) {
    if (measure(text, size, weight) <= maxW) return text;
    let lo = 0, hi = text.length;
    while (lo < hi) { const mid = (lo + hi + 1) >> 1; if (measure(text.slice(0, mid) + '…', size, weight) <= maxW) lo = mid; else hi = mid - 1; }
    return lo <= 0 ? '' : text.slice(0, lo).trimEnd() + '…';
  }
  function wrap(text, size, maxW, maxLines) {
    const out = []; const paras = String(text).split(/\n/);
    for (const para of paras) {
      const words = para.split(/\s+/).filter(Boolean); let line = '';
      for (const w of words) {
        const cand = line ? line + ' ' + w : w;
        if (measure(cand, size) <= maxW || !line) line = cand; else { out.push(line); line = w; }
        if (out.length >= maxLines) break;
      }
      if (line && out.length < maxLines) out.push(line);
      if (out.length >= maxLines) break;
    }
    if (out.length >= maxLines) out[maxLines - 1] = truncate(out[maxLines - 1] + ' …', size, maxW);
    return out;
  }

  // ---------- svg helpers ----------
  function el(name, attrs, children) {
    const e = document.createElementNS(NS, name);
    for (const k in attrs) if (attrs[k] != null) e.setAttribute(k, attrs[k]);
    if (children) for (const c of children) if (c) e.appendChild(typeof c === 'string' ? document.createTextNode(c) : c);
    return e;
  }
  function text(x, y, str, o) {
    o = o || {};
    const t = el('text', { x, y, fill: o.fill, 'font-size': o.size || 12, 'font-weight': o.weight || 400, 'text-anchor': o.anchor || 'start', 'dominant-baseline': o.baseline || 'auto', 'font-family': FONT, 'font-variant-numeric': o.tabular ? 'tabular-nums' : null, opacity: o.opacity });
    t.textContent = str;
    return t;
  }

  function fmtTick(t, mode, t0) {
    if (mode === 'absolute') { const d = new Date(t * 1000); return d.toLocaleTimeString([], { hour12: false }) + (t0 !== undefined && (t - t0) % 1 ? '.' + Math.floor((t % 1) * 1000).toString().padStart(3, '0') : ''); }
    const r = t - t0;
    if (Math.abs(r) < 1e-9) return '0';
    if (Math.abs(r) < 0.001) return (r * 1e6).toFixed(0) + ' µs';
    if (Math.abs(r) < 1) return (r * 1000).toFixed(r * 1000 % 1 ? 1 : 0) + ' ms';
    if (Math.abs(r) < 60) return r.toFixed(r % 1 ? (r * 10 % 1 ? 2 : 1) : 0) + ' s';
    return (r / 60).toFixed(1) + ' min';
  }

  // =====================================================================
  // LADDER / WATERFALL VIEW
  // =====================================================================
  function renderLadder(project, built, opts) {
    const s = project.settings; const theme = THEMES[s.theme] || THEMES.light;
    const fs = s.fontSize || 12; const pad = 24;
    const lanes = built.lanes; const events = built.events;
    const laneGap = Math.max(120, s.laneGap || 230);
    const timeCol = s.timeMode === 'none' ? 24 : 124;
    const hasComments = s.showComments && events.some(e => e.comment);
    const notesW = hasComments ? Math.max(140, s.notesWidth || 240) : 0;
    const titleH = project.title ? (project.subtitle ? 58 : 40) : 0;
    const headerH = 58;
    const laneX = (i) => pad + timeCol + laneGap / 2 + i * laneGap;
    const laneIdx = new Map(lanes.map((l, i) => [l.addr, i]));
    const lanesW = Math.max(1, lanes.length) * laneGap;
    const notesX = pad + timeCol + lanesW + 16;
    const width = pad + timeCol + lanesW + (notesW ? 16 + notesW : 0) + pad;
    const top = pad + titleH + headerH;
    const rowH = Math.max(18, s.rowHeight || 34);

    // ----- layout rows -----
    const rows = []; let y = top; let prevT = null;
    const scale = s.layout === 'scaled' && built.tN > built.t0 && events.length > 1 ? (events.length * rowH) / Math.max(1e-9, events[events.length - 1].t - events[0].t) : null;
    for (const ev of events) {
      const lines = (hasComments && ev.comment) ? wrap(ev.comment, 11, notesW - 14, 6) : [];
      const h = Math.max(rowH, lines.length * 14 + 10);
      let dt = prevT == null ? 0 : ev.t - prevT;
      if (scale != null && prevT != null) {
        const want = dt * scale;
        if (want > rowH * 3) { rows.push({ type: 'gap', y, h: 24, dt }); y += 24; }
        else if (want > rowH) y += want - rowH; // stretch
      } else if (prevT != null && dt > (s.gapMarker || 1)) { rows.push({ type: 'gap', y, h: 24, dt }); y += 24; }
      rows.push({ type: 'event', ev, y, h, lines, prevT });
      y += h; prevT = ev.t;
    }
    const rowsBottom = y;
    const legendProtos = s.showLegend ? built.protosPresent : [];
    const legendH = legendProtos.length > 1 ? 34 : 0;
    const height = rowsBottom + 12 + legendH + pad;

    const svg = el('svg', { xmlns: NS, width, height, viewBox: `0 0 ${width} ${height}`, 'font-family': FONT, 'data-view': 'ladder' });
    svg.appendChild(el('rect', { x: 0, y: 0, width, height, fill: theme.surface, rx: 0 }));

    // ----- title -----
    if (project.title) {
      svg.appendChild(text(pad, pad + 18, project.title, { fill: theme.ink, size: 18, weight: 600 }));
      if (project.subtitle) svg.appendChild(text(pad, pad + 38, project.subtitle, { fill: theme.ink2, size: 12 }));
    }

    // ----- lanes -----
    const gLanes = el('g', { class: 'lanes' });
    lanes.forEach((l, i) => {
      const x = laneX(i);
      const hy = pad + titleH + 18;
      const g = el('g', { class: 'lane', 'data-host': l.addr, cursor: 'pointer' });
      g.appendChild(el('rect', { x: x - laneGap / 2 + 4, y: pad + titleH, width: laneGap - 8, height: headerH - 8, fill: 'transparent' }));
      if (l.color) g.appendChild(el('circle', { cx: x, cy: hy - 1, r: 4, fill: l.color }));
      g.appendChild(text(x, hy + (l.color ? 16 : 8), truncate(l.name, 13, laneGap - 16, 600), { fill: theme.ink, size: 13, weight: 600, anchor: 'middle' }));
      if (l.name !== l.addr) g.appendChild(text(x, hy + (l.color ? 31 : 24), truncate(l.addr, 10.5, laneGap - 16), { fill: theme.muted, size: 10.5, anchor: 'middle' }));
      g.appendChild(el('line', { x1: x, y1: pad + titleH + headerH - 6, x2: x, y2: rowsBottom + 6, stroke: theme.grid, 'stroke-width': 1 }));
      gLanes.appendChild(g);
    });
    svg.appendChild(gLanes);

    // ----- rows -----
    const gRows = el('g', { class: 'rows' });
    for (const r of rows) {
      if (r.type === 'gap') {
        const cy = r.y + r.h / 2;
        const g = el('g', { class: 'gap' });
        g.appendChild(el('line', { x1: pad + timeCol, y1: cy, x2: pad + timeCol + lanesW, y2: cy, stroke: theme.axis, 'stroke-width': 1, 'stroke-dasharray': '3 4' }));
        const label = `⋯ ${Model.fmtDur(r.dt)} pause`;
        const w = measure(label, 10.5) + 12;
        g.appendChild(el('rect', { x: pad + timeCol + lanesW / 2 - w / 2, y: cy - 8, width: w, height: 16, fill: theme.surface }));
        g.appendChild(text(pad + timeCol + lanesW / 2, cy + 3.5, label, { fill: theme.muted, size: 10.5, anchor: 'middle' }));
        gRows.appendChild(g);
        continue;
      }
      const ev = r.ev; const cy = r.y + r.h / 2 + 4;
      const color = colorFor(project, theme, ev);
      const sel = opts.selectedId === ev.id;
      const g = el('g', { class: 'row' + (ev.hidden ? ' hidden-row' : ''), 'data-id': ev.id, cursor: 'pointer', opacity: ev.hidden ? 0.4 : null });
      g.appendChild(el('rect', { class: 'rowbg', x: pad + 2, y: r.y, width: width - pad * 2 - 4, height: r.h, rx: 4, fill: sel ? theme.select : 'transparent' }));
      // time
      if (s.timeMode !== 'none') g.appendChild(text(pad + timeCol - 12, cy + 1, Model.fmtTime(ev.t, s.timeMode, built.t0, r.prevT), { fill: theme.muted, size: 11, anchor: 'end', tabular: true }));
      const si = laneIdx.get(ev.src), di = laneIdx.get(ev.dst);
      if (si === undefined || di === undefined) { gRows.appendChild(g); continue; }
      const x1 = laneX(si), x2 = laneX(di);
      const twoWay = ev.kind === 'flow' || ev.kind === 'conversation';
      const dashed = ev.hidden ? '6 4' : null;
      if (x1 === x2) {
        // self-loop
        g.appendChild(el('path', { d: `M${x1},${cy - 7} C${x1 + 44},${cy - 7} ${x1 + 44},${cy + 7} ${x1 + 6},${cy + 7}`, fill: 'none', stroke: color, 'stroke-width': 2, 'stroke-linecap': 'round', 'stroke-dasharray': dashed }));
        g.appendChild(el('polygon', { points: `${x1},${cy + 7} ${x1 + 9},${cy + 2.5} ${x1 + 9},${cy + 11.5}`, fill: color }));
        const label = truncate(ev.label, fs, laneGap - 70);
        g.appendChild(text(x1 + 52, cy + 4, label, { fill: theme.ink, size: fs }));
      } else {
        const dir = x2 > x1 ? 1 : -1;
        const head = 9;
        g.appendChild(el('line', { x1: x1 + (twoWay ? dir * head : 0), y1: cy, x2: x2 - dir * head, y2: cy, stroke: color, 'stroke-width': 2, 'stroke-linecap': 'round', 'stroke-dasharray': dashed }));
        g.appendChild(el('polygon', { points: `${x2},${cy} ${x2 - dir * head},${cy - 4.5} ${x2 - dir * head},${cy + 4.5}`, fill: color }));
        if (twoWay) g.appendChild(el('polygon', { points: `${x1},${cy} ${x1 + dir * head},${cy - 4.5} ${x1 + dir * head},${cy + 4.5}`, fill: color }));
        const mid = (x1 + x2) / 2, avail = Math.abs(x2 - x1) - 28;
        g.appendChild(text(mid, cy - 6, truncate(ev.label, fs, avail), { fill: theme.ink, size: fs, anchor: 'middle' }));
        const sub = [];
        if (s.showBytes && ev.kind !== 'flow' && ev.kind !== 'conversation') sub.push(Model.fmtBytes(ev.bytes));
        if (ev.nPackets > 1 && ev.kind === 'message') sub.push(ev.nPackets + ' pkts');
        if (sub.length) g.appendChild(text(mid, cy + 13, truncate(sub.join(' · '), 10, avail), { fill: theme.muted, size: 10, anchor: 'middle' }));
        if (s.showPorts && ev.srcPort != null) {
          g.appendChild(text(x1 + dir * 6, cy + 13, ':' + ev.srcPort, { fill: theme.muted, size: 10, anchor: dir > 0 ? 'start' : 'end' }));
          g.appendChild(text(x2 - dir * 12, cy + 13, ':' + ev.dstPort, { fill: theme.muted, size: 10, anchor: dir > 0 ? 'end' : 'start' }));
        }
      }
      // comment
      if (r.lines.length) {
        const ty = r.y + (r.h - r.lines.length * 14) / 2 + 11;
        g.appendChild(el('rect', { x: notesX, y: ty - 10, width: 3, height: r.lines.length * 14, rx: 1.5, fill: color }));
        r.lines.forEach((ln, i) => g.appendChild(text(notesX + 10, ty + i * 14, ln, { fill: theme.ink2, size: 11 })));
      } else if (ev.comment && !s.showComments) {
        // comment exists but notes column off — small dot marker at the row end
        g.appendChild(el('circle', { cx: pad + timeCol + lanesW + 6, cy, r: 3, fill: theme.muted }));
      }
      gRows.appendChild(g);
    }
    svg.appendChild(gRows);

    if (!events.length) {
      svg.appendChild(text(width / 2, top + 40, built.total ? 'No events match the current filters.' : 'No packets yet — open a capture or add events in the Events panel.', { fill: theme.muted, size: 13, anchor: 'middle' }));
    }
    if (legendH) drawLegend(svg, project, theme, legendProtos, pad, rowsBottom + 16, width - pad * 2);
    return svg;
  }

  function drawLegend(svg, project, theme, protos, x0, y0, maxW) {
    const g = el('g', { class: 'legend' });
    let x = x0, y = y0;
    for (const p of protos) {
      const w = 18 + measure(p, 11) + 18;
      if (x + w > x0 + maxW && x > x0) { x = x0; y += 18; }
      g.appendChild(el('rect', { x, y, width: 12, height: 12, rx: 3, fill: protoColor(project, theme, p) }));
      g.appendChild(text(x + 17, y + 10, p, { fill: theme.ink2, size: 11 }));
      x += w;
    }
    svg.appendChild(g);
  }

  // =====================================================================
  // TIMELINE VIEW
  // =====================================================================
  function niceStep(span, target) {
    const raw = span / target; const p = Math.pow(10, Math.floor(Math.log10(raw)));
    for (const m of [1, 2, 5, 10]) if (m * p >= raw) return m * p;
    return 10 * p;
  }

  function renderTimeline(project, built, opts) {
    const s = project.settings; const theme = THEMES[s.theme] || THEMES.light;
    const fs = s.fontSize || 12; const pad = 24;
    const events = built.events;
    const labelW = 250;
    const titleH = project.title ? (project.subtitle ? 58 : 40) : 0;
    const axisH = 36;
    const rowH = Math.max(18, Math.min(40, s.rowHeight || 34) - 6);
    const width = Math.max(600, s.timelineWidth || 1100);
    const plotX = pad + labelW, plotW = width - plotX - pad;
    const top = pad + titleH + axisH;
    const legendProtos = s.showLegend ? built.protosPresent : [];
    const legendH = legendProtos.length > 1 ? 34 : 0;
    const height = top + events.length * rowH + 12 + legendH + pad;
    const tMin = events.length ? Math.min(...events.map(e => e.t)) : 0;
    const tMax = events.length ? Math.max(...events.map(e => e.tEnd)) : 1;
    const span = Math.max(tMax - tMin, 1e-6);
    const x = (t) => plotX + ((t - tMin) / span) * (plotW - 8) + 4;

    const svg = el('svg', { xmlns: NS, width, height, viewBox: `0 0 ${width} ${height}`, 'font-family': FONT, 'data-view': 'timeline' });
    svg.appendChild(el('rect', { x: 0, y: 0, width, height, fill: theme.surface }));
    if (project.title) {
      svg.appendChild(text(pad, pad + 18, project.title, { fill: theme.ink, size: 18, weight: 600 }));
      if (project.subtitle) svg.appendChild(text(pad, pad + 38, project.subtitle, { fill: theme.ink2, size: 12 }));
    }
    // axis + grid
    const gAxis = el('g', { class: 'axis' });
    const step = niceStep(span, Math.max(3, Math.floor(plotW / 110)));
    const axisY = top - 8;
    gAxis.appendChild(el('line', { x1: plotX, y1: axisY, x2: plotX + plotW, y2: axisY, stroke: theme.axis, 'stroke-width': 1 }));
    const firstTick = Math.ceil((tMin - built.t0) / step) * step + built.t0;
    for (let t = firstTick; t <= tMax + 1e-12; t += step) {
      const tx = x(t);
      gAxis.appendChild(el('line', { x1: tx, y1: axisY, x2: tx, y2: top + events.length * rowH, stroke: theme.grid, 'stroke-width': 1 }));
      gAxis.appendChild(text(tx, axisY - 6, fmtTick(t, s.timeMode === 'absolute' ? 'absolute' : 'relative', built.t0), { fill: theme.muted, size: 10.5, anchor: 'middle', tabular: true }));
    }
    svg.appendChild(gAxis);

    const gRows = el('g', { class: 'rows' });
    events.forEach((ev, i) => {
      const ry = top + i * rowH; const cy = ry + rowH / 2;
      const color = colorFor(project, theme, ev);
      const sel = opts.selectedId === ev.id;
      const g = el('g', { class: 'row', 'data-id': ev.id, cursor: 'pointer', opacity: ev.hidden ? 0.4 : null });
      g.appendChild(el('rect', { class: 'rowbg', x: pad + 2, y: ry, width: width - pad * 2 - 4, height: rowH, rx: 4, fill: sel ? theme.select : 'transparent' }));
      const srcN = Model.hostName(project, ev.src), dstN = Model.hostName(project, ev.dst);
      const twoWay = ev.kind === 'flow' || ev.kind === 'conversation';
      const ports = s.showPorts && ev.srcPort != null ? [`:${ev.srcPort}`, `:${ev.dstPort}`] : ['', ''];
      const rowLabel = `${srcN}${ports[0]} ${twoWay ? '⇄' : '→'} ${dstN}${ports[1]}`;
      g.appendChild(el('rect', { x: pad, y: cy - 5, width: 10, height: 10, rx: 2.5, fill: color }));
      g.appendChild(text(pad + 16, cy + 4, truncate(rowLabel, 11.5, labelW - 28), { fill: theme.ink2, size: 11.5 }));
      const bx1 = x(ev.t), bx2 = Math.max(x(ev.tEnd), bx1 + 4);
      const barH = Math.min(14, rowH - 6);
      g.appendChild(el('rect', { x: bx1, y: cy - barH / 2, width: bx2 - bx1, height: barH, rx: 3, fill: color, 'stroke-dasharray': ev.hidden ? '4 3' : null }));
      let label = ev.label;
      if (s.showBytes && !twoWay) label += ` (${Model.fmtBytes(ev.bytes)})`;
      if (ev.comment) label += `  —  ${ev.comment.replace(/\s+/g, ' ')}`;
      const right = plotX + plotW - bx2 - 8;
      if (right > 40) g.appendChild(text(bx2 + 6, cy + 4, truncate(label, fs, right), { fill: theme.ink, size: fs }));
      else if (bx2 - bx1 > 60) g.appendChild(text(bx1 + 6, cy + 4, truncate(label, fs, bx2 - bx1 - 12), { fill: '#ffffff', size: fs }));
      gRows.appendChild(g);
    });
    svg.appendChild(gRows);
    if (!events.length) svg.appendChild(text(width / 2, top + 40, built.total ? 'No events match the current filters.' : 'No packets yet — open a capture or add events in the Events panel.', { fill: theme.muted, size: 13, anchor: 'middle' }));
    if (legendH) drawLegend(svg, project, theme, legendProtos, pad, top + events.length * rowH + 16, width - pad * 2);
    return svg;
  }

  function render(project, built, opts) {
    opts = opts || {};
    return project.settings.view === 'timeline' ? renderTimeline(project, built, opts) : renderLadder(project, built, opts);
  }

  function svgString(svg) {
    const clone = svg.cloneNode(true);
    clone.setAttribute('xmlns', NS);
    for (const r of clone.querySelectorAll('rect.rowbg')) r.remove();
    return '<?xml version="1.0" encoding="UTF-8"?>\n' + new XMLSerializer().serializeToString(clone);
  }

  function svgToPng(svg, scale) {
    return new Promise((resolve, reject) => {
      const str = svgString(svg);
      const blob = new Blob([str], { type: 'image/svg+xml;charset=utf-8' });
      const url = URL.createObjectURL(blob);
      const img = new Image();
      img.onload = () => {
        const c = document.createElement('canvas');
        c.width = Math.ceil(svg.width.baseVal.value * scale); c.height = Math.ceil(svg.height.baseVal.value * scale);
        const g = c.getContext('2d'); g.scale(scale, scale); g.drawImage(img, 0, 0);
        URL.revokeObjectURL(url);
        c.toBlob(b => b ? resolve(b) : reject(new Error('PNG encode failed')), 'image/png');
      };
      img.onerror = () => { URL.revokeObjectURL(url); reject(new Error('Could not rasterise SVG')); };
      img.src = url;
    });
  }

  window.Render = { render, svgString, svgToPng, THEMES, colorFor, protoColor, FAMILY_OF };
})();
