/* compare.js — the Compare view of compare.html: open two captures and line their packets up.

   Each capture is turned into "units" (packets or messages, using the same filters as the chart),
   every unit gets a few features — direction relative to the client host, kind (SYN, DNS query,
   TLS Client Hello, TLS data, …), payload size, names it mentions (SNI, DNS, Host) and its relative
   position — and the two sequences are aligned with global sequence alignment (Needleman–Wunsch),
   like a diff. Manual links act as fixed anchors; unlinking forbids a pair.
   The engine (Compare.*) has no DOM dependencies; the UI below only runs in a browser. */
(function () {
  'use strict';
  const root = typeof window !== 'undefined' ? window : globalThis;

  // =========================== loading ===========================
  function loadCapture(buffer, name) {
    const parsed = Pcap.parse(buffer);
    const packets = Pcap.decodeAll(parsed.frames, new Map());
    return { name, format: parsed.format, packets, client: guessClient(packets), filter: '' };
  }

  const isPrivate = (a) => /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|fe80:|fd|fc|127\.|::1$)/i.test(a);
  function hostCounts(packets) {
    const n = {};
    for (const p of packets) { n[p.src] = (n[p.src] || 0) + 1; n[p.dst] = (n[p.dst] || 0) + 1; }
    return Object.entries(n).sort((a, b) => b[1] - a[1]);
  }
  // The "client" is the host that opens connections: most SYNs sent, else most DNS queries, else
  // the busiest private address, else the busiest address.
  function guessClient(packets) {
    const syn = {}, dns = {};
    for (const p of packets) {
      if (p.tcp && p.tcp.flags.includes('SYN') && !p.tcp.flags.includes('ACK')) syn[p.src] = (syn[p.src] || 0) + 1;
      if (p.family === 'DNS' && !/response/.test(p.info)) dns[p.src] = (dns[p.src] || 0) + 1;
    }
    const best = (m) => { let k = null; for (const x in m) if (k === null || m[x] > m[k]) k = x; return k; };
    const counts = hostCounts(packets);
    return best(syn) || best(dns) || (counts.find(([a]) => isPrivate(a)) || counts[0] || [null])[0];
  }

  // =========================== features ===========================
  const GROUP = {
    syn: 'tcpctl', synack: 'tcpctl', fin: 'tcpctl', rst: 'tcpctl',
    'tls-ch': 'hs', 'tls-sh': 'hs', 'tls-hs': 'hs', 'quic-hs': 'hs',
    'tls-data': 'data', 'quic-data': 'data', data: 'data', 'http-req': 'data', 'http-resp': 'data',
    'dns-query': 'dns', 'dns-resp': 'dns',
  };
  const KIND_NAMES = {
    syn: 'TCP SYN', synack: 'TCP SYN-ACK', fin: 'TCP FIN', rst: 'TCP RST', ack: 'TCP ACK', ctl: 'control',
    'tls-ch': 'TLS Client Hello', 'tls-sh': 'TLS Server Hello', 'tls-hs': 'TLS handshake', 'tls-alert': 'TLS alert', 'tls-data': 'TLS data',
    'quic-hs': 'QUIC handshake', 'quic-data': 'QUIC data', 'dns-query': 'DNS query', 'dns-resp': 'DNS response',
    'http-req': 'HTTP request', 'http-resp': 'HTTP response', data: 'data', icmp: 'ICMP', arp: 'ARP',
  };

  function classify(ev) {
    const p = ev.packets[0];
    const info = ev.packets.length > 1 ? ev.packets.slice(0, 20).map(x => x.info).join(' | ') : p.info;
    if (p.tcp) {
      const f = p.tcp.flags;
      if (f.includes('SYN')) return f.includes('ACK') ? 'synack' : 'syn';
      if (f.includes('RST')) return 'rst';
      if (f.includes('FIN') && !ev.payload) return 'fin';
    }
    if (p.family === 'DNS') return /response/.test(p.info) ? 'dns-resp' : 'dns-query';
    if (p.proto === 'QUIC') return /Initial|Handshake/.test(info) ? 'quic-hs' : 'quic-data';
    if (/Client Hello/.test(info)) return 'tls-ch';
    if (/Server Hello/.test(info)) return 'tls-sh';
    if (p.family === 'TLS') {
      if (/Alert/.test(info) && !/Application Data/.test(info)) return 'tls-alert';
      if (/Change Cipher Spec|Finished|Encrypted Handshake|Certificate|Key Exchange|Hello Done/.test(info) && !/Application Data/.test(info)) return 'tls-hs';
      return ev.payload ? 'tls-data' : 'ctl';
    }
    if (p.proto === 'HTTP' && !p.continuation) return /^HTTP\//.test(p.info) ? 'http-resp' : 'http-req';
    if (p.family === 'ICMP') return 'icmp';
    if (p.family === 'ARP') return 'arp';
    if (ev.pureAck || (p.pureAck && ev.nPackets === 1)) return 'ack';
    return ev.payload ? 'data' : 'ctl';
  }

  const normName = (s) => s.toLowerCase().replace(/\.$/, '').replace(/^www\./, '');
  function namesOf(ev) {
    const out = new Set();
    for (const p of ev.packets.slice(0, 8)) {
      const t = p.info || '';
      for (const m of t.matchAll(/SNI=([^\s),]+)/g)) out.add(normName(m[1]));
      for (const m of t.matchAll(/Host: ([^\s)]+)/g)) out.add(normName(m[1].replace(/:\d+$/, '')));
      if (p.family === 'DNS') for (const m of t.matchAll(/(?:^|\s)(?:A|AAAA|HTTPS|CNAME|SVCB)\s+([a-z0-9_-]+(?:\.[a-z0-9_-]+)*\.[a-z]{2,})(?=\s|,|$)/gi)) out.add(normName(m[1]));
    }
    return [...out];
  }

  function buildUnits(cap, opts) {
    const project = Model.newProject({ packets: cap.packets });
    Object.assign(project.settings, { granularity: opts.unit, hideAcks: opts.hideAcks, hideControl: opts.hideControl, filter: cap.filter || '', limit: 1e9, offset: 0, laneBy: 'host', hideUnusedLanes: false });
    const evs = Model.build(project).events;
    const t0 = evs.length ? evs[0].t : 0, n = evs.length;
    return evs.map((ev, i) => {
      const kind = classify(ev);
      return {
        i, id: ev.id, ev, kind, group: GROUP[kind] || kind,
        dir: ev.src === cap.client ? 'out' : ev.dst === cap.client ? 'in' : 'other',
        size: ev.payload, wire: ev.bytes, t: ev.t - t0, frac: n > 1 ? i / (n - 1) : 0,
        names: namesOf(ev),
      };
    });
  }

  // =========================== scoring & alignment ===========================
  const DIR_MISMATCH = -4, FORBIDDEN = -1e9;
  function defaultOptions() { return { unit: 'packet', hideAcks: true, hideControl: false, tunnel: true, sizeWeight: 1, timeWeight: 1, gap: 1 }; }

  // Score breakdown for one pair (used for the detail pane; the aligner uses the same maths, precomputed).
  function scoreParts(a, b, o) {
    if (a.dir !== b.dir) return { kind: 0, size: 0, names: 0, pos: 0, dir: DIR_MISMATCH, total: DIR_MISMATCH };
    let kind;
    if (a.kind === b.kind) kind = 2;
    else if (a.group === b.group) kind = 1;
    else if (o.tunnel && ((a.group === 'hs' && b.group === 'data') || (a.group === 'data' && b.group === 'hs'))) kind = 0.6;
    else kind = -1.2;
    const r = Math.abs(Math.log((a.size + 64) / (b.size + 64)));
    const size = o.sizeWeight * Math.max(-1, Math.min(1, 1 - r / Math.log(o.tunnel ? 2 : 1.4)));
    const names = a.names.length && b.names.length ? (a.names.some(x => b.names.includes(x)) ? 1.5 : -0.5) : 0;
    const pos = -o.timeWeight * 3 * Math.abs(a.frac - b.frac);
    return { kind, size, names, pos, dir: 0, total: kind + size + names + pos };
  }

  function makeScorer(A, B, o, forbid) {
    const kinds = [...new Set([...A, ...B].map(u => u.kind))];
    const kix = new Map(kinds.map((k, i) => [k, i])), K = kinds.length;
    const KT = new Float64Array(K * K);
    for (let x = 0; x < K; x++) for (let y = 0; y < K; y++) {
      const ka = kinds[x], kb = kinds[y], ga = GROUP[ka] || ka, gb = GROUP[kb] || kb;
      KT[x * K + y] = ka === kb ? 2 : ga === gb ? 1 : (o.tunnel && ((ga === 'hs' && gb === 'data') || (ga === 'data' && gb === 'hs'))) ? 0.6 : -1.2;
    }
    const DIRC = { out: 0, in: 1, other: 2 };
    const prep = (U) => ({
      d: Int8Array.from(U, u => DIRC[u.dir]), k: Int32Array.from(U, u => kix.get(u.kind)),
      l: Float64Array.from(U, u => Math.log(u.size + 64)), f: Float64Array.from(U, u => u.frac), n: U.map(u => u.names),
    });
    const a = prep(A), b = prep(B);
    const invTol = 1 / Math.log(o.tunnel ? 2 : 1.4), sw = o.sizeWeight, tw = o.timeWeight * 3;
    const W = B.length + 1;
    return function (i, j) {
      if (a.d[i] !== b.d[j]) return DIR_MISMATCH;
      if (forbid && forbid.has(i * W + j)) return FORBIDDEN;
      let s = KT[a.k[i] * K + b.k[j]];
      let z = 1 - Math.abs(a.l[i] - b.l[j]) * invTol; s += sw * (z > 1 ? 1 : z < -1 ? -1 : z);
      if (a.n[i].length && b.n[j].length) s += a.n[i].some(x => b.n[j].includes(x)) ? 1.5 : -0.5;
      return s - tw * Math.abs(a.f[i] - b.f[j]);
    };
  }

  const CELL_BUDGET = 30e6;
  // Global alignment of A[a0..a1) with B[b0..b1). Rows are appended to `out`.
  // Large inputs use a band around the diagonal so memory stays bounded.
  function alignSegment(sc, gap, a0, a1, b0, b1, out) {
    const n = a1 - a0, m = b1 - b0;
    if (!n || !m) { for (let i = a0; i < a1; i++) out.push({ a: i, b: null }); for (let j = b0; j < b1; j++) out.push({ a: null, b: j }); return; }
    const full = (n + 1) * (m + 1) <= CELL_BUDGET;
    const W = full ? m : Math.max(300, Math.floor(CELL_BUDGET / (2 * (n + 1))) + Math.abs(n - m));
    const lo = new Int32Array(n + 1), hi = new Int32Array(n + 1), rs = new Float64Array(n + 2);
    for (let i = 0; i <= n; i++) {
      const c = i * m / n;
      lo[i] = full ? 0 : Math.max(0, Math.floor(c) - W);
      hi[i] = full ? m : Math.min(m, Math.ceil(c) + W);
      rs[i + 1] = rs[i] + (hi[i] - lo[i] + 1);
    }
    const tb = new Uint8Array(rs[n + 1]); // 1 = pair, 2 = B only (left), 3 = A only (up)
    let prev = new Float64Array(m + 1), cur = new Float64Array(m + 1);
    for (let j = lo[0]; j <= hi[0]; j++) { prev[j] = -gap * j; tb[j - lo[0]] = j ? 2 : 0; }
    for (let i = 1; i <= n; i++) {
      const plo = lo[i - 1], phi = hi[i - 1], base = rs[i] - lo[i];
      for (let j = lo[i]; j <= hi[i]; j++) {
        let best = -Infinity, t = 0;
        if (j > 0 && j - 1 >= plo && j - 1 <= phi) { const v = prev[j - 1] + sc(a0 + i - 1, b0 + j - 1); if (v > best) { best = v; t = 1; } }
        if (j >= plo && j <= phi) { const v = prev[j] - gap; if (v > best) { best = v; t = 3; } }
        if (j > lo[i]) { const v = cur[j - 1] - gap; if (v > best) { best = v; t = 2; } }
        cur[j] = best; tb[base + j] = t;
      }
      const tmp = prev; prev = cur; cur = tmp;
    }
    const seg = [];
    let i = n, j = m;
    while (i > 0 || j > 0) {
      const t = i === 0 ? 2 : j === 0 ? 3 : tb[rs[i] - lo[i] + j];
      if (t === 1) { seg.push({ a: a0 + i - 1, b: b0 + j - 1 }); i--; j--; }
      else if (t === 3) { seg.push({ a: a0 + i - 1, b: null }); i--; }
      else { seg.push({ a: null, b: b0 + j - 1 }); j--; }
    }
    for (let k = seg.length - 1; k >= 0; k--) out.push(seg[k]);
  }

  // pins: [[ia, ib]] (must not cross); forbid: Set of "ia:ib" strings.
  function align(A, B, o, pins, forbid) {
    const W = B.length + 1;
    const fset = new Set(); for (const k of forbid || []) { const [x, y] = k.split(':').map(Number); fset.add(x * W + y); }
    const sc = makeScorer(A, B, o, fset);
    const rows = []; let pa = 0, pb = 0;
    for (const [ia, ib] of (pins || []).slice().sort((x, y) => x[0] - y[0])) {
      alignSegment(sc, o.gap, pa, ia, pb, ib, rows);
      rows.push({ a: ia, b: ib, pinned: true });
      pa = ia + 1; pb = ib + 1;
    }
    alignSegment(sc, o.gap, pa, A.length, pb, B.length, rows);
    // A pair the aligner only accepted to avoid two gaps is not a real match: show both sides as unmatched.
    const outRows = [];
    for (const r of rows) {
      if (r.a != null && r.b != null) {
        r.score = sc(r.a, r.b);
        if (!r.pinned && r.score < 0) { outRows.push({ a: r.a, b: null }, { a: null, b: r.b }); continue; }
        r.strong = r.pinned || r.score >= 1.5;
      }
      outRows.push(r);
    }
    return outRows;
  }

  function stats(A, B, rows) {
    const s = { matched: 0, strong: 0, onlyA: 0, onlyB: 0, bytes: { A: { out: 0, in: 0 }, B: { out: 0, in: 0 } }, delta: { out: [], in: [] }, durA: 0, durB: 0 };
    for (const u of A) if (u.dir !== 'other') s.bytes.A[u.dir] += u.size;
    for (const u of B) if (u.dir !== 'other') s.bytes.B[u.dir] += u.size;
    for (const r of rows) {
      if (r.a != null && r.b != null) { s.matched++; if (r.strong) s.strong++; const a = A[r.a], b = B[r.b]; if (a.dir !== 'other' && a.size && b.size) s.delta[a.dir].push(b.size - a.size); }
      else if (r.a != null) s.onlyA++; else s.onlyB++;
    }
    const med = (xs) => { if (!xs.length) return null; const v = xs.slice().sort((x, y) => x - y); return v[v.length >> 1]; };
    s.medianDelta = { out: med(s.delta.out), in: med(s.delta.in) };
    s.durA = A.length ? A[A.length - 1].t : 0; s.durB = B.length ? B[B.length - 1].t : 0;
    return s;
  }

  root.Compare = { loadCapture, guessClient, hostCounts, buildUnits, classify, namesOf, align, scoreParts, stats, defaultOptions, KIND_NAMES };
  if (typeof document === 'undefined') return;

  // =====================================================================
  // UI
  // =====================================================================
  const $ = (s, r) => (r || document).querySelector(s);
  const $$ = (s, r) => Array.from((r || document).querySelectorAll(s));
  function h(tag, attrs, ...children) {
    const e = document.createElement(tag);
    if (attrs) for (const k in attrs) {
      const v = attrs[k]; if (v == null || v === false) continue;
      if (k === 'class') e.className = v; else if (k === 'text') e.textContent = v;
      else if (k.startsWith('on')) e.addEventListener(k.slice(2), v);
      else if (k === 'value') e.value = v; else if (k === 'checked') e.checked = !!v;
      else e.setAttribute(k, v);
    }
    for (const c of children.flat()) if (c != null && c !== false) e.appendChild(typeof c === 'string' ? document.createTextNode(c) : c);
    return e;
  }
  const fmtBytes = (n) => Model.fmtBytes(n);
  const fmtT = (t) => t.toFixed(t < 10 ? 4 : 2) + ' s';
  const signed = (n) => (n > 0 ? '+' : n < 0 ? '−' : '±') + fmtBytes(Math.abs(n));
  const ARROW = { out: '→', in: '←', other: '·' };
  const PAGE = 1000;

  const ui = {
    mode: 'waterfall',
    caps: { A: null, B: null }, files: { A: null, B: null },
    opts: defaultOptions(), show: 'all',
    units: { A: [], B: [] }, rows: [], st: null,
    pins: [], forbid: new Set(),   // stored by unit id so they survive filter changes
    sel: null, linkFrom: null, limit: PAGE, pendingSide: 'A',
  };

  // ---------- mode ----------
  function setMode(mode) {
    ui.mode = mode;
    document.body.classList.toggle('mode-compare', mode === 'compare');
    $('#compareView').hidden = mode !== 'compare';
    for (const b of $$('#modeSeg button')) b.classList.toggle('active', b.dataset.mode === mode);
    $('#tooltip').hidden = true;
    if (mode === 'compare') { document.title = 'Compare captures — Waterfall Chart Tool'; render(); }
    else if (root.WaterfallApp) root.WaterfallApp.rerender();
    try { const u = new URL(location.href); if (mode === 'compare') u.searchParams.set('mode', 'compare'); else u.searchParams.delete('mode'); history.replaceState(null, '', u); } catch (e) { }
  }

  let toastTimer = null;
  function toast(msg, isError) {
    const t = $('#toast'); t.textContent = msg; t.hidden = false; t.classList.toggle('error', !!isError);
    clearTimeout(toastTimer); toastTimer = setTimeout(() => { t.hidden = true; }, isError ? 6000 : 3000);
  }

  // ---------- loading ----------
  async function openFile(side, file) {
    try {
      const cap = loadCapture(await file.arrayBuffer(), file.name);
      if (!cap.packets.length) throw new Error('no packets in this file');
      ui.caps[side] = cap; ui.files[side] = file;
      ui.pins = []; ui.forbid.clear(); ui.sel = null; ui.linkFrom = null;
      toast(`Capture ${side}: ${cap.packets.length.toLocaleString()} packets from ${file.name}`);
      recompute();
    } catch (e) { toast(`Could not open ${file.name}: ${e.message}`, true); console.error(e); }
  }
  function openFiles(files, side) {
    files = files.filter(f => !/\.json$/i.test(f.name));
    if (!files.length) return;
    if (files.length >= 2) { openFile('A', files[0]).then(() => openFile('B', files[1])); return; }
    openFile(side || (!ui.caps.A ? 'A' : !ui.caps.B ? 'B' : 'B'), files[0]);
  }
  function pickFile(side) { ui.pendingSide = side; $('#cmpFile').click(); }

  // ---------- compute ----------
  function recompute() {
    for (const side of ['A', 'B']) ui.units[side] = ui.caps[side] ? buildUnits(ui.caps[side], ui.opts) : [];
    const A = ui.units.A, B = ui.units.B;
    if (A.length && B.length) {
      const ia = new Map(A.map(u => [u.id, u.i])), ib = new Map(B.map(u => [u.id, u.i]));
      // keep pins that still resolve and do not cross an earlier one
      let pins = ui.pins.map(([x, y]) => [ia.get(x), ib.get(y)]).filter(([x, y]) => x != null && y != null).sort((p, q) => p[0] - q[0]);
      const kept = []; for (const p of pins) if (!kept.length || p[1] > kept[kept.length - 1][1]) kept.push(p);
      const forbid = [...ui.forbid].map(k => { const [x, y] = k.split('|'); return ia.has(x) && ib.has(y) ? ia.get(x) + ':' + ib.get(y) : null; }).filter(Boolean);
      const t0 = performance.now();
      ui.rows = align(A, B, ui.opts, kept, forbid);
      ui.alignMs = performance.now() - t0;
    } else {
      ui.rows = A.length ? A.map(u => ({ a: u.i, b: null })) : B.map(u => ({ a: null, b: u.i }));
    }
    ui.st = A.length && B.length ? stats(A, B, ui.rows) : null;
    if (ui.sel != null && ui.sel >= ui.rows.length) ui.sel = null;
    ui.limit = PAGE;
    render();
  }
  let recomputeTimer = null;
  const recomputeSoon = () => { clearTimeout(recomputeTimer); recomputeTimer = setTimeout(recompute, 200); };

  // ---------- rendering ----------
  function theme() { return Render.THEMES[document.documentElement.getAttribute('data-theme') === 'dark' ? 'dark' : 'light']; }
  const dotColor = (u) => Render.colorFor({ protoColors: {} }, theme(), { proto: u.ev.proto, family: u.ev.family });
  const hostPair = (u) => `${u.ev.src}${u.ev.srcPort != null ? ':' + u.ev.srcPort : ''} → ${u.ev.dst}${u.ev.dstPort != null ? ':' + u.ev.dstPort : ''}`;

  function render() {
    if (ui.mode !== 'compare') return;
    renderSide('A'); renderSide('B');
    for (const seg of $$('#compareView .seg[data-copt]')) for (const b of $$('button', seg)) b.classList.toggle('active', b.dataset.v === (seg.dataset.copt === 'show' ? ui.show : ui.opts[seg.dataset.copt]));
    for (const inp of $$('#compareView input[data-copt]')) { const v = ui.opts[inp.dataset.copt]; if (inp.type === 'checkbox') inp.checked = !!v; else if (document.activeElement !== inp) inp.value = v; }
    const any = ui.caps.A || ui.caps.B;
    $('#cmpEmpty').hidden = !!any;
    $('#cmpScroll').hidden = !any;
    renderSummary(); renderTable(); renderDetail();
  }

  function renderSide(side) {
    const box = $('#cap' + side), cap = ui.caps[side];
    $('.cmp-name', box).textContent = cap ? cap.name : 'No capture';
    $('.cmp-meta', box).textContent = cap ? `${cap.packets.length.toLocaleString()} packets · ${cap.format} · ${ui.units[side].length.toLocaleString()} ${ui.opts.unit}s compared` : 'Open or drop a .pcap / .pcapng';
    $('[data-act="waterfall"]', box).disabled = !cap;
    const sel = $('select[data-k="client"]', box); sel.replaceChildren(); sel.disabled = !cap;
    if (cap) for (const [addr, n] of hostCounts(cap.packets).slice(0, 60)) sel.appendChild(h('option', { value: addr, text: `${addr}  (${n.toLocaleString()} pkts)` }));
    if (cap) sel.value = cap.client;
    const f = $('input[data-k="filter"]', box); f.disabled = !cap; if (document.activeElement !== f) f.value = cap ? cap.filter : '';
  }

  function renderSummary() {
    const box = $('#cmpSummary'); box.replaceChildren();
    const A = ui.units.A, B = ui.units.B, st = ui.st;
    $('#cmpStatus').textContent = st ? `${A.length.toLocaleString()} vs ${B.length.toLocaleString()} ${ui.opts.unit}s · aligned in ${Math.max(1, Math.round(ui.alignMs))} ms` : (ui.caps.A || ui.caps.B) ? 'Open a second capture to compare' : '';
    box.hidden = !st;
    if (!st) return;
    const pct = (b, a) => a ? ` (${b >= a ? '+' : '−'}${Math.abs(Math.round((b - a) / a * 100))}%)` : '';
    box.appendChild(h('div', { class: 'cmp-cards' },
      h('div', { class: 'cmp-card m' }, h('b', { text: st.matched.toLocaleString() }), ` matched`, h('span', { text: ` · ${st.strong.toLocaleString()} strong` })),
      h('div', { class: 'cmp-card a' }, h('b', { text: st.onlyA.toLocaleString() }), ' only in A'),
      h('div', { class: 'cmp-card b' }, h('b', { text: st.onlyB.toLocaleString() }), ' only in B')));
    const md = st.medianDelta;
    box.appendChild(h('table', { class: 'cmp-bytes' },
      h('tr', {}, h('th', { text: 'Payload bytes' }), h('th', { text: '→ sent by client' }), h('th', { text: '← received' }), h('th', { text: 'Duration' })),
      h('tr', {}, h('td', {}, h('span', { class: 'cmp-badge a', text: 'A' }), ui.caps.A.name), h('td', { text: fmtBytes(st.bytes.A.out) }), h('td', { text: fmtBytes(st.bytes.A.in) }), h('td', { text: fmtT(st.durA) })),
      h('tr', {}, h('td', {}, h('span', { class: 'cmp-badge b', text: 'B' }), ui.caps.B.name), h('td', { text: fmtBytes(st.bytes.B.out) + pct(st.bytes.B.out, st.bytes.A.out) }), h('td', { text: fmtBytes(st.bytes.B.in) + pct(st.bytes.B.in, st.bytes.A.in) }), h('td', { text: fmtT(st.durB) }))));
    if (md.out != null || md.in != null) box.appendChild(h('p', { class: 'hint', text: `Matched ${ui.opts.unit}s: B is typically ${md.out != null ? signed(md.out) + ' per outgoing' : ''}${md.out != null && md.in != null ? ' and ' : ''}${md.in != null ? signed(md.in) + ' per incoming' : ''} ${ui.opts.unit} compared with A (median payload difference).` }));
  }

  function unitCells(u, side) {
    if (!u) return [h('td', { class: 'n' }), h('td', { class: 't' }), h('td', { class: 'd' }), h('td', { class: 'l empty', text: side === 'A' ? 'not in A' : 'not in B' }), h('td', { class: 'z' })];
    return [
      h('td', { class: 'n', text: '#' + (u.ev.packets[0].index + 1) }),
      h('td', { class: 't', text: fmtT(u.t) }),
      h('td', { class: 'd ' + u.dir, text: ARROW[u.dir], title: hostPair(u) }),
      h('td', { class: 'l', title: `${u.ev.label}\n${hostPair(u)}` }, h('span', { class: 'dot', style: 'background:' + dotColor(u) }), u.ev.label),
      h('td', { class: 'z', text: fmtBytes(u.size) }),
    ];
  }

  function visibleRows() {
    const out = [];
    ui.rows.forEach((r, i) => {
      const m = r.a != null && r.b != null;
      if (ui.show === 'matched' && !m) return;
      if (ui.show === 'unmatched' && m) return;
      out.push(i);
    });
    return out;
  }

  function renderTable() {
    const table = $('#cmpTable'); table.replaceChildren();
    const A = ui.units.A, B = ui.units.B;
    if (!A.length && !B.length) { $('#cmpMore').replaceChildren(); return; }
    const cols = () => [h('col', { class: 'c-n' }), h('col', { class: 'c-t' }), h('col', { class: 'c-d' }), h('col', {}), h('col', { class: 'c-z' })];
    table.appendChild(h('colgroup', {}, ...cols(), h('col', { class: 'c-mid' }), ...cols()));
    table.appendChild(h('thead', {}, h('tr', {},
      h('th', { colspan: 5, class: 'side a' }, h('span', { class: 'cmp-badge a', text: 'A' }), ui.caps.A ? ui.caps.A.name : '—'),
      h('th', { class: 'mid', text: 'match' }),
      h('th', { colspan: 5, class: 'side b' }, h('span', { class: 'cmp-badge b', text: 'B' }), ui.caps.B ? ui.caps.B.name : '—'))));
    const body = h('tbody', {});
    const vis = visibleRows();
    for (const ri of vis.slice(0, ui.limit)) {
      const r = ui.rows[ri], a = r.a != null ? A[r.a] : null, b = r.b != null ? B[r.b] : null;
      const cls = ['r', a && b ? (r.strong ? 'm-strong' : 'm-weak') : a ? 'only-a' : 'only-b', r.pinned ? 'pinned' : '', ri === ui.sel ? 'sel' : '', ui.linkFrom && ((ui.linkFrom.side === 'A' && b && !a) || (ui.linkFrom.side === 'B' && a && !b)) ? 'link-target' : ''].filter(Boolean).join(' ');
      let mid;
      if (a && b) mid = h('td', { class: 'mid', title: `score ${r.score.toFixed(2)}${r.pinned ? ' · linked by hand' : ''}` }, h('span', { class: 'pill', text: r.pinned ? '📌' : r.strong ? '=' : '≈' }), a.size || b.size ? h('span', { class: 'delta', text: signed(b.size - a.size) }) : null);
      else mid = h('td', { class: 'mid' }, h('span', { class: 'pill gap', text: a ? '−' : '+' }));
      body.appendChild(h('tr', { class: cls, 'data-row': ri }, ...unitCells(a, 'A'), mid, ...unitCells(b, 'B')));
    }
    table.appendChild(body);
    const more = $('#cmpMore'); more.replaceChildren();
    if (vis.length > ui.limit) more.appendChild(h('button', { class: 'small', text: `Show ${Math.min(PAGE, vis.length - ui.limit).toLocaleString()} more rows (${(vis.length - ui.limit).toLocaleString()} hidden)`, onclick: () => { ui.limit += PAGE; renderTable(); } }));
    else if (!vis.length) more.appendChild(h('p', { class: 'hint', text: 'No rows for this view.' }));
  }

  function unitDetail(u, side) {
    const wrap = h('div', { class: 'cmp-unit' });
    wrap.appendChild(h('div', { class: 'kind' }, h('span', { class: 'cmp-badge ' + side.toLowerCase(), text: side }), ` ${KIND_NAMES[u.kind] || u.kind} · ${u.dir === 'out' ? 'client → remote' : u.dir === 'in' ? 'remote → client' : 'not involving the client host'}`));
    wrap.appendChild(h('h3', { text: u.ev.label }));
    const kv = h('dl', { class: 'kv' });
    const add = (k, v) => { kv.appendChild(h('dt', { text: k })); kv.appendChild(h('dd', { text: String(v) })); };
    add('Hosts', hostPair(u)); add('Time', fmtT(u.t)); add('Payload', `${u.size.toLocaleString()} B (${u.wire.toLocaleString()} B on the wire)`);
    add('Frames', u.ev.packets.slice(0, 12).map(p => '#' + (p.index + 1)).join(' ') + (u.ev.packets.length > 12 ? ` … (${u.ev.packets.length})` : ''));
    if (u.names.length) add('Names', u.names.join(', '));
    wrap.appendChild(kv);
    wrap.appendChild(h('div', { class: 'row-buttons' }, h('button', { class: 'small', text: `Show in waterfall`, onclick: () => showInWaterfall(side, u) })));
    return wrap;
  }

  function renderDetail() {
    const box = $('#cmpDetail'); box.replaceChildren();
    const r = ui.sel != null ? ui.rows[ui.sel] : null;
    if (ui.linkFrom) {
      box.appendChild(h('div', { class: 'cmp-linking' }, h('strong', { text: 'Linking…' }), ` Click a row that has only a ${ui.linkFrom.side === 'A' ? 'B' : 'A'} packet to pair it with the selected ${ui.linkFrom.side} packet.`, h('div', { class: 'row-buttons' }, h('button', { class: 'small', text: 'Cancel', onclick: () => { ui.linkFrom = null; render(); } }))));
    }
    if (!r) {
      box.appendChild(h('h3', { text: 'Comparison' }));
      box.appendChild(h('p', { class: 'empty', text: 'Click a row to see both sides, the match score, and to link or unlink packets by hand.' }));
      box.appendChild(h('p', { class: 'empty' }, h('kbd', { text: '↑' }), ' ', h('kbd', { text: '↓' }), ' move · ', h('kbd', { text: 'Esc' }), ' deselect'));
      box.appendChild(h('p', { class: 'empty' }, h('span', { class: 'pill', text: '=' }), ' strong match · ', h('span', { class: 'pill weak', text: '≈' }), ' weak match · 📌 linked by hand · ', h('span', { class: 'pill gap', text: '−' }), '/', h('span', { class: 'pill gap', text: '+' }), ' only in A / only in B'));
      return;
    }
    const A = ui.units.A, B = ui.units.B, a = r.a != null ? A[r.a] : null, b = r.b != null ? B[r.b] : null;
    if (a && b) {
      const p = scoreParts(a, b, ui.opts);
      box.appendChild(h('div', { class: 'kind', text: r.pinned ? 'linked by hand' : r.strong ? 'strong match' : 'weak match' }));
      const kv = h('dl', { class: 'kv' });
      const add = (k, v) => { kv.appendChild(h('dt', { text: k })); kv.appendChild(h('dd', { text: v })); };
      if (p.dir) add('Direction', p.dir.toFixed(2) + ' (different directions)');
      else {
        add('Kind', `${p.kind >= 0 ? '+' : ''}${p.kind.toFixed(2)}  ${a.kind === b.kind ? 'same' : (KIND_NAMES[a.kind] || a.kind) + ' vs ' + (KIND_NAMES[b.kind] || b.kind)}`);
        add('Size', `${p.size >= 0 ? '+' : ''}${p.size.toFixed(2)}  ${a.size} vs ${b.size} B (${signed(b.size - a.size)})`);
        if (p.names) add('Names', `${p.names > 0 ? '+' : ''}${p.names.toFixed(2)}`);
        add('Position', p.pos.toFixed(2));
      }
      add('Score', p.total.toFixed(2));
      add('Time offset', `${b.t - a.t >= 0 ? '+' : '−'}${Math.abs(b.t - a.t).toFixed(4)} s (B relative to A)`);
      box.appendChild(kv);
      box.appendChild(h('div', { class: 'row-buttons' },
        h('button', { class: 'small', text: 'Unlink', title: 'Never pair these two', onclick: () => { ui.pins = ui.pins.filter(([x, y]) => !(x === a.id && y === b.id)); ui.forbid.add(a.id + '|' + b.id); recompute(); toast('Unlinked. The pair is now forbidden; "Reset manual links" undoes this.'); } }),
        r.pinned ? null : h('button', { class: 'small', text: 'Keep this match', title: 'Pin it so it survives weight changes', onclick: () => { pin(a.id, b.id); } })));
    } else {
      const side = a ? 'A' : 'B';
      box.appendChild(h('div', { class: 'kind', text: `only in ${side}` }));
      box.appendChild(h('div', { class: 'row-buttons' }, h('button', { class: 'small primary', text: `Link to a ${side === 'A' ? 'B' : 'A'} packet…`, onclick: () => { ui.linkFrom = { side, id: (a || b).id }; render(); } })));
    }
    if (a) box.appendChild(unitDetail(a, 'A'));
    if (b) box.appendChild(unitDetail(b, 'B'));
  }

  function pin(aId, bId) {
    const A = ui.units.A, B = ui.units.B;
    const ia = A.findIndex(u => u.id === aId), ib = B.findIndex(u => u.id === bId);
    const crossing = ui.pins.filter(([x, y]) => { const px = A.findIndex(u => u.id === x), py = B.findIndex(u => u.id === y); return (px < ia && py > ib) || (px > ia && py < ib) || px === ia || py === ib; });
    ui.pins = ui.pins.filter(p => !crossing.includes(p));
    ui.pins.push([aId, bId]); ui.forbid.delete(aId + '|' + bId);
    if (crossing.length) toast(`Linked. ${crossing.length} earlier link${crossing.length > 1 ? 's' : ''} that crossed this one ${crossing.length > 1 ? 'were' : 'was'} removed.`);
    recompute();
    const ri = ui.rows.findIndex(r => r.a === ia && r.b === ib);
    if (ri >= 0) { ui.sel = ri; render(); scrollToRow(ri); }
  }

  function clickRow(ri) {
    const r = ui.rows[ri];
    if (ui.linkFrom) {
      const other = ui.linkFrom.side === 'A' ? r.b : r.a;
      const otherOnly = ui.linkFrom.side === 'A' ? (r.b != null && r.a == null) : (r.a != null && r.b == null);
      if (other != null && otherOnly) {
        const lf = ui.linkFrom; ui.linkFrom = null;
        const aId = lf.side === 'A' ? lf.id : ui.units.A[r.a].id, bId = lf.side === 'B' ? lf.id : ui.units.B[r.b].id;
        pin(aId, bId); return;
      }
      toast(`Pick a row that has only a ${ui.linkFrom.side === 'A' ? 'B' : 'A'} packet, or press Esc.`, true); return;
    }
    ui.sel = ri === ui.sel ? null : ri;
    for (const tr of $$('#cmpTable tr.sel')) tr.classList.remove('sel');
    if (ui.sel != null) { const tr = $(`#cmpTable tr[data-row="${ui.sel}"]`); if (tr) tr.classList.add('sel'); }
    renderDetail();
  }
  function scrollToRow(ri) { const tr = $(`#cmpTable tr[data-row="${ri}"]`); if (tr) tr.scrollIntoView({ block: 'nearest' }); }

  // ---------- waterfall hand-off ----------
  async function showInWaterfall(side, u) {
    const file = ui.files[side]; if (!file || !root.WaterfallApp) return;
    const W = root.WaterfallApp;
    if (W.state.dirty && !confirm('Replace the chart in the Waterfall view? Unsaved edits there will be lost.')) return;
    setMode('waterfall');
    await W.openCapture(file);
    if (!u) return;
    const s = W.state.project.settings;
    s.granularity = ui.opts.unit === 'message' ? 'message' : 'packet';
    s.hideAcks = ui.opts.hideAcks; s.filter = ''; $('#filter').value = '';
    // page to the row: build once without paging to find its index
    const limit = s.limit; s.limit = 1e9; s.offset = 0;
    const idx = Model.build(W.state.project).events.findIndex(e => e.id === u.id);
    s.limit = limit; s.offset = idx >= 0 ? Math.floor(idx / limit) * limit : 0;
    W.state.selectedId = idx >= 0 ? u.id : null;
    for (const seg of $$('.layout .seg[data-setting]')) for (const b of $$('button', seg)) b.classList.toggle('active', b.dataset.v === s[seg.dataset.setting]);
    for (const inp of $$('.layout input[data-setting]')) if (inp.type === 'checkbox') inp.checked = !!s[inp.dataset.setting];
    W.rerender();
    const row = document.querySelector(`#chartScroll .row[data-id="${CSS.escape(u.id)}"]`);
    if (row) row.scrollIntoView({ block: 'center' });
  }

  // ---------- export ----------
  function exportCsv() {
    if (!ui.rows.length) { toast('Nothing to export yet.', true); return; }
    const A = ui.units.A, B = ui.units.B;
    const q = (v) => { const s = v == null ? '' : String(v); return /[",\n]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s; };
    const side = (u) => u ? [u.ev.packets[0].index + 1, u.t.toFixed(6), u.dir, KIND_NAMES[u.kind] || u.kind, u.ev.proto, u.size, u.ev.src, u.ev.dst, u.ev.label] : ['', '', '', '', '', '', '', '', ''];
    const lines = [['a_frame', 'a_time', 'a_dir', 'a_kind', 'a_proto', 'a_payload', 'a_src', 'a_dst', 'a_label', 'match', 'score', 'b_frame', 'b_time', 'b_dir', 'b_kind', 'b_proto', 'b_payload', 'b_src', 'b_dst', 'b_label'].join(',')];
    for (const r of ui.rows) {
      const a = r.a != null ? A[r.a] : null, b = r.b != null ? B[r.b] : null;
      const m = a && b ? (r.pinned ? 'manual' : r.strong ? 'strong' : 'weak') : a ? 'only_a' : 'only_b';
      lines.push([...side(a), m, a && b ? r.score.toFixed(3) : '', ...side(b)].map(q).join(','));
    }
    const name = `${(ui.caps.A ? ui.caps.A.name : 'A').replace(/\.\w+$/, '')}_vs_${(ui.caps.B ? ui.caps.B.name : 'B').replace(/\.\w+$/, '')}.csv`.replace(/[^\w.-]+/g, '_');
    const a = document.createElement('a'); a.href = URL.createObjectURL(new Blob([lines.join('\n')], { type: 'text/csv' })); a.download = name;
    document.body.appendChild(a); a.click(); a.remove(); setTimeout(() => URL.revokeObjectURL(a.href), 2000);
  }

  // ---------- wiring ----------
  function wire() {
    $$('#modeSeg button').forEach(b => b.addEventListener('click', () => setMode(b.dataset.mode)));
    $('#cmpFile').addEventListener('change', (e) => { const fs = [...e.target.files]; e.target.value = ''; if (fs.length) openFiles(fs, fs.length === 1 ? ui.pendingSide : null); });
    for (const side of ['A', 'B']) {
      const box = $('#cap' + side);
      $('[data-act="open"]', box).addEventListener('click', () => pickFile(side));
      $('[data-act="waterfall"]', box).addEventListener('click', () => showInWaterfall(side, null));
      $('select[data-k="client"]', box).addEventListener('change', (e) => { ui.caps[side].client = e.target.value; recompute(); });
      $('input[data-k="filter"]', box).addEventListener('input', (e) => { ui.caps[side].filter = e.target.value; recomputeSoon(); });
    }
    $('#cmpOpenA').addEventListener('click', () => pickFile('A'));
    $('#cmpOpenB').addEventListener('click', () => pickFile('B'));
    const sampleBtn = $('#cmpSamples');
    if (/^https?:$/.test(location.protocol)) sampleBtn.addEventListener('click', () => loadUrls('samples/compare-direct.pcap', 'samples/compare-tunneled.pcap'));
    else sampleBtn.hidden = true;
    $('#cmpSwap').addEventListener('click', () => {
      [ui.caps.A, ui.caps.B] = [ui.caps.B, ui.caps.A]; [ui.files.A, ui.files.B] = [ui.files.B, ui.files.A];
      ui.pins = ui.pins.map(([x, y]) => [y, x]); ui.forbid = new Set([...ui.forbid].map(k => k.split('|').reverse().join('|')));
      ui.sel = null; recompute();
    });
    for (const seg of $$('#compareView .seg[data-copt]')) seg.addEventListener('click', (e) => {
      const b = e.target.closest('button'); if (!b) return;
      if (seg.dataset.copt === 'show') { ui.show = b.dataset.v; ui.limit = PAGE; render(); return; }
      ui.opts[seg.dataset.copt] = b.dataset.v; ui.sel = null; recompute();
    });
    for (const inp of $$('#compareView input[data-copt]')) inp.addEventListener(inp.type === 'checkbox' ? 'change' : 'input', () => {
      const k = inp.dataset.copt;
      if (inp.type === 'checkbox') { ui.opts[k] = inp.checked; ui.sel = null; recompute(); }
      else { const v = parseFloat(inp.value); if (isFinite(v) && v >= 0) { ui.opts[k] = v; recomputeSoon(); } }
    });
    $('#cmpResetLinks').addEventListener('click', () => { ui.pins = []; ui.forbid.clear(); ui.linkFrom = null; recompute(); toast('Manual links cleared.'); });
    $('#cmpResetWeights').addEventListener('click', () => { const d = defaultOptions(); ui.opts.sizeWeight = d.sizeWeight; ui.opts.timeWeight = d.timeWeight; ui.opts.gap = d.gap; recompute(); });
    $('#cmpExport').addEventListener('click', exportCsv);
    $('#cmpTable').addEventListener('click', (e) => { const tr = e.target.closest('tr[data-row]'); if (tr) clickRow(+tr.dataset.row); });

    // In Compare mode, drops and keys belong to this view; keep them away from the Waterfall handlers.
    const area = $('#cmpMain'); let depth = 0;
    const guard = (e) => ui.mode === 'compare';
    window.addEventListener('dragenter', (e) => { if (!guard(e)) return; e.stopPropagation(); e.preventDefault(); depth++; area.classList.add('dragging'); }, true);
    window.addEventListener('dragleave', (e) => { if (!guard(e)) return; e.stopPropagation(); depth = Math.max(0, depth - 1); if (!depth) area.classList.remove('dragging'); }, true);
    window.addEventListener('dragover', (e) => { if (!guard(e)) return; e.stopPropagation(); e.preventDefault(); }, true);
    window.addEventListener('drop', (e) => {
      if (!guard(e)) return;
      e.stopPropagation(); e.preventDefault(); depth = 0; area.classList.remove('dragging');
      const files = [...e.dataTransfer.files]; if (!files.length) return;
      const card = e.target.closest && e.target.closest('.cmp-cap');
      openFiles(files, card ? card.dataset.side : null);
    }, true);
    window.addEventListener('keydown', (e) => {
      if (ui.mode !== 'compare') return;
      const tag = (e.target.tagName || '').toLowerCase();
      if (tag === 'input' || tag === 'textarea' || tag === 'select') return;
      e.stopPropagation();
      if (e.key === 'Escape') { if (ui.linkFrom) ui.linkFrom = null; else ui.sel = null; render(); }
      else if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
        const vis = visibleRows().slice(0, ui.limit); if (!vis.length) return;
        e.preventDefault();
        const k = vis.indexOf(ui.sel);
        const next = e.key === 'ArrowDown' ? vis[Math.min(vis.length - 1, k + 1)] : vis[Math.max(0, k < 0 ? 0 : k - 1)];
        ui.sel = null; clickRow(next); scrollToRow(next);
      }
      else if ((e.metaKey || e.ctrlKey) && e.key === 'o') { e.preventDefault(); pickFile(!ui.caps.A ? 'A' : 'B'); }
    }, true);
    new MutationObserver(() => { if (ui.mode === 'compare') renderTable(); }).observe(document.documentElement, { attributes: true, attributeFilter: ['data-theme'] });
  }

  async function loadUrls(a, b) {
    for (const [side, url] of [['A', a], ['B', b]]) {
      if (!url) continue;
      try {
        const res = await fetch(url); if (!res.ok) throw new Error(res.status + ' ' + res.statusText);
        await openFile(side, new File([await res.blob()], url.split('/').pop()));
      } catch (e) { toast(`Could not load ${url}: ${e.message}`, true); }
    }
  }

  // URL parameters (when served over http): ?mode=compare&compareA=a.pcap&compareB=b.pcap
  function boot() {
    wire();
    const q = new URLSearchParams(location.search);
    if (q.get('mode') === 'compare' || q.get('compareA') || q.get('compareB')) setMode('compare'); else setMode('waterfall');
    if (q.get('compareA') || q.get('compareB')) loadUrls(q.get('compareA'), q.get('compareB'));
  }
  boot();
  root.CompareApp = { ui, setMode, openFile, recompute };
})();
