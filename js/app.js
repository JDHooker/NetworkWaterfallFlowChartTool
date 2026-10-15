/* app.js — UI wiring: loading captures, settings panels, editing, inspector, export. */
(function () {
  'use strict';
  const $ = (s, r) => (r || document).querySelector(s);
  const $$ = (s, r) => Array.from((r || document).querySelectorAll(s));
  function h(tag, attrs, ...children) {
    const e = document.createElement(tag);
    if (attrs) for (const k in attrs) {
      const v = attrs[k]; if (v == null) continue;
      if (k === 'class') e.className = v;
      else if (k === 'text') e.textContent = v;
      else if (k.startsWith('on')) e.addEventListener(k.slice(2), v);
      else if (k === 'value') e.value = v;
      else if (k === 'checked') e.checked = !!v;
      else e.setAttribute(k, v);
    }
    for (const c of children.flat()) if (c != null && c !== false) e.appendChild(typeof c === 'string' ? document.createTextNode(c) : c);
    return e;
  }

  const PROTO_CHOICES = ['TCP', 'TLS', 'HTTP', 'DNS', 'UDP', 'ICMP', 'ARP', 'QUIC', 'SSH', 'DHCP', 'NTP', 'mDNS', 'ICMPv6', 'Other'];
  const TRANSPORT_OF = { TCP: 'TCP', TLS: 'TCP', HTTP: 'TCP', HTTP2: 'TCP', SSH: 'TCP', DNS: 'UDP', UDP: 'UDP', QUIC: 'UDP', DHCP: 'UDP', NTP: 'UDP', mDNS: 'UDP', ICMP: 'ICMP', ICMPv6: 'ICMPv6', ARP: 'ARP' };
  const GRAN_HINT = {
    packet: 'One row per packet, exactly as captured.',
    message: 'Consecutive segments in one direction are merged into a single message; pure ACKs are dropped.',
    flow: 'One row per connection (5-tuple). Arrow runs from the initiator; label shows the application, packet count, bytes and duration.',
    conversation: 'One row per pair of hosts, all their flows combined.',
  };

  // Template steps: [from, proto, label, bytes, extra]. {a}/{b} are replaced by host names.
  const HS = [['a', 'TCP', '[SYN] Seq=0 Win=65535 Len=0 MSS=1460', 74, { control: true }], ['b', 'TCP', '[SYN, ACK] Seq=0 Ack=1 Win=65535 Len=0 MSS=1460', 74, { control: true }], ['a', 'TCP', '[ACK] Seq=1 Ack=1 Win=131072 Len=0', 66, { pureAck: true }]];
  const TD = [['a', 'TCP', '[FIN, ACK] Seq=1200 Ack=5400 Len=0', 66, { control: true }], ['b', 'TCP', '[ACK] Seq=5400 Ack=1201 Len=0', 66, { pureAck: true }], ['b', 'TCP', '[FIN, ACK] Seq=5400 Ack=1201 Len=0', 66, { control: true }], ['a', 'TCP', '[ACK] Seq=1201 Ack=5401 Len=0', 66, { pureAck: true }]];
  const TLS13 = [['a', 'TLS', 'TLSv1.3 Client Hello (SNI={b})', 583, { control: true }], ['b', 'TLS', 'TLSv1.3 Server Hello, Change Cipher Spec, Encrypted Extensions, Certificate, Certificate Verify, Finished', 2941, { control: true }], ['a', 'TLS', 'TLSv1.3 Change Cipher Spec, Finished', 130, { control: true }], ['a', 'TLS', 'TLSv1.3 Application Data (517 bytes)', 583], ['b', 'TLS', 'TLSv1.3 New Session Ticket, Application Data (4120 bytes)', 4300, { dt: 0.06 }]];
  const TEMPLATES = {
    'tcp-handshake': { name: 'TCP three-way handshake', port: 443, steps: HS },
    'tcp-teardown': { name: 'TCP connection close', port: 443, steps: TD },
    'dns': { name: 'DNS lookup (A = client, B = resolver)', port: 53, steps: [['a', 'DNS', 'Standard query 0x1a2b A example.com', 74], ['b', 'DNS', 'Standard query response 0x1a2b A example.com A 93.184.216.34', 90]] },
    'tls13': { name: 'TLS 1.3 handshake + data', port: 443, steps: TLS13 },
    'tls12': { name: 'TLS 1.2 handshake + data', port: 443, steps: [['a', 'TLS', 'TLSv1.2 Client Hello (SNI={b})', 571, { control: true }], ['b', 'TLS', 'TLSv1.2 Server Hello, Certificate, Server Key Exchange, Server Hello Done', 3200, { control: true }], ['a', 'TLS', 'TLSv1.2 Client Key Exchange, Change Cipher Spec, Finished', 192, { control: true }], ['b', 'TLS', 'TLSv1.2 New Session Ticket, Change Cipher Spec, Finished', 300, { control: true }], ['a', 'TLS', 'TLSv1.2 Application Data (480 bytes)', 546], ['b', 'TLS', 'TLSv1.2 Application Data (3900 bytes)', 3966, { dt: 0.06 }]] },
    'http': { name: 'HTTP request / response', port: 80, steps: [['a', 'HTTP', 'GET / HTTP/1.1 (Host: {b})', 412], ['b', 'HTTP', 'HTTP/1.1 200 OK (text/html), 1256 bytes', 1622, { dt: 0.05 }]] },
    'https-page': { name: 'HTTPS page load (handshake → TLS → close)', port: 443, steps: [...HS, ...TLS13, ...TD] },
    'ping': { name: 'ICMP ping (3 echoes)', steps: [['a', 'ICMP', 'Echo (ping) request id=0x0001 seq=1', 98], ['b', 'ICMP', 'Echo (ping) reply id=0x0001 seq=1', 98, { dt: 0.012 }], ['a', 'ICMP', 'Echo (ping) request id=0x0001 seq=2', 98, { dt: 1 }], ['b', 'ICMP', 'Echo (ping) reply id=0x0001 seq=2', 98, { dt: 0.012 }], ['a', 'ICMP', 'Echo (ping) request id=0x0001 seq=3', 98, { dt: 1 }], ['b', 'ICMP', 'Echo (ping) reply id=0x0001 seq=3', 98, { dt: 0.012 }]] },
    'dhcp': { name: 'DHCP lease (Discover / Offer / Request / ACK)', port: 67, sport: 68, steps: [['a', 'DHCP', 'DHCP Discover - Transaction ID 0x3d1d', 342, { control: true }], ['b', 'DHCP', 'DHCP Offer - Transaction ID 0x3d1d (10.0.0.42)', 342, { control: true }], ['a', 'DHCP', 'DHCP Request - Transaction ID 0x3d1d (requests 10.0.0.42)', 342, { control: true }], ['b', 'DHCP', 'DHCP ACK - Transaction ID 0x3d1d (10.0.0.42)', 342, { control: true }]] },
    'arp': { name: 'ARP resolution', steps: [['a', 'ARP', 'Who has {b}? Tell {a}', 42, { control: true }], ['b', 'ARP', '{b} is at 00:1a:2b:3c:4d:5e', 42, { control: true }]] },
    'quic': { name: 'QUIC / HTTP3 connection', port: 443, steps: [['a', 'QUIC', 'QUIC Initial, Client Hello (SNI={b})', 1250, { control: true }], ['b', 'QUIC', 'QUIC Initial, Server Hello', 1250, { control: true }], ['b', 'QUIC', 'QUIC Handshake, Encrypted Extensions, Certificate, Finished', 2400, { control: true, dt: 0.002 }], ['a', 'QUIC', 'QUIC Handshake, Finished', 120, { control: true }], ['a', 'QUIC', 'QUIC protected payload (HTTP/3 request)', 300], ['b', 'QUIC', 'QUIC protected payload (HTTP/3 response)', 5200, { dt: 0.05 }]] },
    'ssh': { name: 'SSH session start', port: 22, steps: [...HS, ['a', 'SSH', 'Protocol: SSH-2.0-OpenSSH_9.6', 87], ['b', 'SSH', 'Protocol: SSH-2.0-OpenSSH_9.4', 87], ['a', 'SSH', 'Key Exchange Init', 1500, { control: true }], ['b', 'SSH', 'Key Exchange Init', 1100, { control: true }], ['a', 'SSH', 'ECDH Key Exchange Init', 100, { control: true }], ['b', 'SSH', 'ECDH Key Exchange Reply, New Keys', 600, { control: true }], ['a', 'SSH', 'New Keys', 82, { control: true }], ['a', 'SSH', 'Encrypted packet (44 bytes)', 110], ['b', 'SSH', 'Encrypted packet (28 bytes)', 94]] },
  };

  const state = { project: null, flows: new Map(), built: null, svg: null, selectedId: null, dirty: false, zoom: 1, eventSearch: '' };

  // =========================== project lifecycle ===========================
  function currentTheme() { return document.documentElement.getAttribute('data-theme') === 'dark' ? 'dark' : 'light'; }

  function setProject(project) {
    state.project = project;
    project.settings.theme = currentTheme();
    state.selectedId = null; state.dirty = false; state.zoom = 1;
    $('#title').value = project.title || '';
    $('#subtitle').value = project.subtitle || '';
    $('#filter').value = project.settings.filter || '';
    syncSettingsUI();
    rerender();
  }

  function rebuildFlows(project) {
    state.flows = new Map();
    const sorted = project.packets.slice().sort((a, b) => a.ts - b.ts || a.id - b.id);
    for (const p of sorted) Pcap.finishPacket(p, state.flows);
  }

  async function openCapture(file) {
    try {
      toast('Parsing ' + file.name + '…');
      const buf = await file.arrayBuffer();
      const parsed = Pcap.parse(buf);
      state.flows = new Map();
      const packets = Pcap.decodeAll(parsed.frames, state.flows);
      const project = Model.newProject({ title: file.name.replace(/\.(pcapng|pcap|cap|dmp)$/i, ''), source: file.name, packets, nextPid: packets.length + 1, baseTime: packets.length ? packets[0].ts : Date.now() / 1000 });
      for (const p of packets) { Model.hostEntry(project, p.src); Model.hostEntry(project, p.dst); }
      if (packets.length > 2000) { project.settings.granularity = 'message'; project.settings.hideAcks = true; }
      setProject(project);
      toast(`Loaded ${packets.length.toLocaleString()} packets from ${file.name} (${parsed.format}).`);
    } catch (e) { toast('Could not open capture: ' + e.message, true); console.error(e); }
  }

  function newBlank() {
    if (state.dirty && !confirm('Discard unsaved changes?')) return;
    const project = Model.newProject({ title: 'New diagram', baseTime: Math.floor(Date.now() / 1000) });
    setProject(project);
    showTab('add');
  }

  function serializeProject() {
    const p = state.project;
    return JSON.stringify({ ...p, packets: p.packets.map(({ flow, ...rest }) => rest) });
  }
  function loadProjectText(text, name) {
    const obj = JSON.parse(text);
    if (!obj || !Array.isArray(obj.packets) || !obj.settings) throw new Error('Not a Waterfall project file.');
    const project = Model.newProject();
    Object.assign(project, obj);
    project.settings = Object.assign(Model.defaultSettings(), obj.settings);
    project.hosts = obj.hosts || {}; project.annotations = obj.annotations || {}; project.protoColors = obj.protoColors || {};
    rebuildFlows(project);
    setProject(project);
    toast(`Opened project ${name}`);
  }

  function download(blob, filename) {
    const a = document.createElement('a'); a.href = URL.createObjectURL(blob); a.download = filename; document.body.appendChild(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(a.href), 2000);
  }
  function safeName() { return (state.project.title || 'waterfall').replace(/[^\w.-]+/g, '_'); }

  // =========================== manual packets ===========================
  function familyOf(proto) { return Render.FAMILY_OF[proto] || (Render.THEMES.light.families[proto] ? proto : 'Other'); }
  function addManualPacket(opts) {
    const project = state.project;
    const proto = opts.proto || 'Other';
    const p = {
      id: project.nextPid++, manual: true, ts: opts.ts, len: opts.bytes || 0, caplen: opts.bytes || 0,
      src: opts.src, dst: opts.dst, srcPort: opts.srcPort ?? null, dstPort: opts.dstPort ?? null, srcMac: null, dstMac: null,
      proto, family: familyOf(proto), transport: TRANSPORT_OF[proto] || proto,
      info: opts.label || proto, layers: [], payloadLen: opts.bytes || 0, tcp: null, flags: [],
      pureAck: !!opts.pureAck, mergeKey: null, control: !!opts.control, appName: TRANSPORT_OF[proto] && TRANSPORT_OF[proto] !== proto ? proto : null, flowName: null,
    };
    Model.hostEntry(project, p.src); Model.hostEntry(project, p.dst);
    project.packets.push(p);
    Pcap.finishPacket(p, state.flows);
    if (opts.comment) project.annotations['p:' + p.id] = { comment: opts.comment };
    markDirty();
    return p;
  }

  function relTime(ts) { return ts - (state.project.baseTime || 0); }
  function absTime(rel) { return (state.project.baseTime || 0) + rel; }

  function insertTemplate(key, a, b, start, spacing) {
    const tpl = TEMPLATES[key]; if (!tpl) return;
    const project = state.project;
    const nameA = Model.hostName(project, a), nameB = Model.hostName(project, b);
    const sport = tpl.sport || (49152 + Math.floor(Math.random() * 16000));
    let t = start;
    for (const [from, proto, label, bytes, extra] of tpl.steps) {
      const ex = extra || {};
      t += ex.dt != null ? ex.dt : spacing;
      const src = from === 'a' ? a : b, dst = from === 'a' ? b : a;
      addManualPacket({ ts: absTime(t), src, dst, proto, label: label.replace(/\{a\}/g, nameA).replace(/\{b\}/g, nameB), bytes, srcPort: tpl.port ? (from === 'a' ? sport : tpl.port) : null, dstPort: tpl.port ? (from === 'a' ? tpl.port : sport) : null, pureAck: ex.pureAck, control: ex.control });
    }
    $('#tplStart').value = (t + spacing).toFixed(3);
    $('#evTime').value = (t + spacing).toFixed(3);
    rerender();
    toast(`Inserted ${tpl.steps.length} events (${tpl.name}).`);
  }

  // =========================== rendering ===========================
  let renderTimer = null;
  function scheduleRender() { clearTimeout(renderTimer); renderTimer = setTimeout(rerender, 120); }

  function rerender() {
    const project = state.project;
    const built = Model.build(project);
    state.built = built;
    const svg = Render.render(project, built, { selectedId: state.selectedId });
    const scroll = $('#chartScroll');
    const sx = scroll.scrollLeft, sy = scroll.scrollTop;
    scroll.replaceChildren(svg);
    state.svg = svg;
    applyZoom();
    scroll.scrollLeft = sx; scroll.scrollTop = sy;
    bindSvg(svg);
    $('#chartArea').classList.toggle('empty', project.packets.length === 0);
    const s = project.settings;
    const from = built.matched ? built.offset + 1 : 0, to = Math.min(built.matched, built.offset + built.limit);
    $('#status').textContent = `${from.toLocaleString()}–${to.toLocaleString()} of ${built.matched.toLocaleString()} ${s.granularity === 'conversation' ? 'host pairs' : s.granularity + 's'}` + (built.total !== built.matched ? ` (${(built.total - built.matched).toLocaleString()} filtered)` : '') + ` · ${built.packetCount.toLocaleString()} packets`;
    $('#pagePrev').disabled = built.offset <= 0; $('#pageNext').disabled = to >= built.matched;
    $('#granHint').textContent = GRAN_HINT[s.granularity];
    renderProtoList(); renderHostList(); renderEventList(); renderInspector(); renderHostOptions();
    document.title = (project.title ? project.title + ' — ' : '') + 'Waterfall Chart Tool';
  }

  function applyZoom() {
    const svg = state.svg; if (!svg) return;
    const w = svg.viewBox.baseVal.width, hgt = svg.viewBox.baseVal.height;
    svg.style.width = (w * state.zoom) + 'px'; svg.style.height = (hgt * state.zoom) + 'px';
    $('#zoomLabel').textContent = Math.round(state.zoom * 100) + '%';
  }

  function bindSvg(svg) {
    const tip = $('#tooltip');
    svg.addEventListener('mousemove', (e) => {
      const row = e.target.closest('.row'); if (!row) { tip.hidden = true; return; }
      const ev = findEvent(row.getAttribute('data-id')); if (!ev) return;
      tip.replaceChildren(tooltipContent(ev));
      tip.hidden = false;
      const x = Math.min(e.clientX + 14, window.innerWidth - tip.offsetWidth - 10), y = Math.min(e.clientY + 14, window.innerHeight - tip.offsetHeight - 10);
      tip.style.left = x + 'px'; tip.style.top = y + 'px';
    });
    svg.addEventListener('mouseleave', () => { tip.hidden = true; });
    svg.addEventListener('click', (e) => {
      const row = e.target.closest('.row');
      if (row) { select(row.getAttribute('data-id')); return; }
      const lane = e.target.closest('.lane');
      if (lane) { showTab('hosts'); const inp = $(`#hostList [data-addr="${CSS.escape(lane.getAttribute('data-host'))}"] input[type=text]`); if (inp) { inp.focus(); inp.select(); } return; }
      select(null);
    });
  }

  function tooltipContent(ev) {
    const p = state.project; const b = state.built;
    const frag = document.createDocumentFragment();
    frag.appendChild(h('strong', { text: ev.label }));
    frag.appendChild(h('div', { class: 'm', text: `${Model.hostName(p, ev.src)}${ev.srcPort != null ? ':' + ev.srcPort : ''} → ${Model.hostName(p, ev.dst)}${ev.dstPort != null ? ':' + ev.dstPort : ''}` }));
    frag.appendChild(h('div', { class: 'm', text: `${ev.proto} · t=${(ev.t - b.t0).toFixed(6)} s${ev.tEnd > ev.t ? ' · ' + Model.fmtDur(ev.tEnd - ev.t) : ''} · ${Model.fmtBytes(ev.bytes)} · ${ev.nPackets} pkt${ev.nPackets > 1 ? 's' : ''}` }));
    if (ev.label !== ev.autoLabel) frag.appendChild(h('div', { class: 'm', text: 'Original: ' + ev.autoLabel }));
    if (ev.comment) frag.appendChild(h('div', { class: 'c', text: ev.comment }));
    return frag;
  }

  function findEvent(id) { return state.built && state.built.events.find(e => e.id === id); }

  function select(id) {
    if (state.selectedId === id) return;
    const prev = state.selectedId; state.selectedId = id;
    const theme = Render.THEMES[state.project.settings.theme];
    for (const rid of [prev, id]) {
      if (!rid || !state.svg) continue;
      const bg = state.svg.querySelector(`.row[data-id="${CSS.escape(rid)}"] .rowbg`);
      if (bg) bg.setAttribute('fill', rid === id ? theme.select : 'transparent');
    }
    renderInspector(); renderEventList();
  }
  function scrollRowIntoView(id) {
    const row = state.svg && state.svg.querySelector(`.row[data-id="${CSS.escape(id)}"]`);
    if (row) row.scrollIntoView({ block: 'center', behavior: 'smooth' });
  }

  // =========================== annotations ===========================
  function annot(id) { const a = state.project.annotations; return a[id] || (a[id] = {}); }
  function setAnnot(id, patch) {
    const a = annot(id); Object.assign(a, patch);
    for (const k of Object.keys(a)) if (a[k] === '' || a[k] == null || a[k] === false) delete a[k];
    if (!Object.keys(a).length) delete state.project.annotations[id];
    markDirty();
  }
  function markDirty() { state.dirty = true; }

  // =========================== side panels ===========================
  function syncSettingsUI() {
    const s = state.project.settings;
    for (const seg of $$('.seg[data-setting]')) { const key = seg.dataset.setting; for (const b of $$('button', seg)) b.classList.toggle('active', b.dataset.v === s[key]); }
    for (const inp of $$('input[data-setting]')) { const key = inp.dataset.setting; if (inp.type === 'checkbox') inp.checked = !!s[key]; else inp.value = s[key] == null ? '' : s[key]; }
    $('#btnTheme').textContent = s.theme === 'dark' ? 'Light' : 'Dark';
  }

  function renderProtoList() {
    const project = state.project; const theme = Render.THEMES[project.settings.theme];
    const stats = Model.protocolStats(project);
    const hidden = new Set(project.settings.hiddenProtos || []);
    const list = $('#protoList'); list.replaceChildren();
    if (!stats.length) { list.appendChild(h('p', { class: 'hint', text: 'No packets yet.' })); return; }
    for (const [proto, n] of stats) {
      const color = Render.protoColor(project, theme, proto);
      const overridden = !!(project.protoColors && project.protoColors[proto]);
      list.appendChild(h('div', { class: 'proto' },
        h('input', { type: 'checkbox', checked: !hidden.has(proto), title: 'Show / hide this protocol', onchange: (e) => { const set = new Set(project.settings.hiddenProtos); e.target.checked ? set.delete(proto) : set.add(proto); project.settings.hiddenProtos = [...set]; markDirty(); rerender(); } }),
        h('input', { type: 'color', value: color, title: 'Colour for ' + proto, oninput: (e) => { project.protoColors[proto] = e.target.value; markDirty(); scheduleRender(); } }),
        h('span', { text: proto }),
        h('span', { class: 'count', text: n.toLocaleString() }),
        overridden ? h('button', { class: 'reset', title: 'Reset colour', text: '×', onclick: () => { delete project.protoColors[proto]; markDirty(); rerender(); } }) : h('span')));
    }
  }

  function renderHostOptions() {
    const dl = $('#hostOptions'); dl.replaceChildren();
    const project = state.project;
    for (const addr of Object.keys(project.hosts).sort((a, b) => project.hosts[a].order - project.hosts[b].order)) {
      dl.appendChild(h('option', { value: addr, text: project.hosts[addr].name || '' }));
    }
  }

  function renderHostList() {
    const project = state.project; const counts = Model.hostStats(project);
    const list = $('#hostList'); list.replaceChildren();
    const addrs = Object.keys(project.hosts).sort((a, b) => project.hosts[a].order - project.hosts[b].order);
    if (!addrs.length) { list.appendChild(h('p', { class: 'hint', text: 'No hosts yet. Open a capture or add hosts in the Add tab.' })); return; }
    addrs.forEach((addr, i) => {
      const hst = project.hosts[addr];
      const move = (d) => { const other = addrs[i + d]; if (!other) return; const o = project.hosts[other].order; project.hosts[other].order = hst.order; hst.order = o; normalizeOrder(); markDirty(); rerender(); };
      list.appendChild(h('div', { class: 'host' + (hst.hidden ? ' hidden-host' : ''), 'data-addr': addr },
        h('input', { type: 'color', value: hst.color || '#898781', title: 'Lane colour marker', oninput: (e) => { hst.color = e.target.value; markDirty(); scheduleRender(); } }),
        h('div', {}, h('div', { class: 'addr', text: addr }), h('div', { class: 'meta', text: `${(counts[addr] || 0).toLocaleString()} pkts` })),
        h('input', { type: 'text', value: hst.name || '', placeholder: 'display name', spellcheck: 'false', oninput: (e) => { hst.name = e.target.value; markDirty(); scheduleRender(); } }),
        h('div', { class: 'ctl' },
          h('button', { title: 'Move lane left', text: '◀', disabled: i === 0 ? '' : null, onclick: () => move(-1) }),
          h('button', { title: 'Move lane right', text: '▶', disabled: i === addrs.length - 1 ? '' : null, onclick: () => move(1) }),
          h('button', { title: hst.hidden ? 'Show this host and its traffic' : 'Hide this host and all its traffic', text: hst.hidden ? '👁' : '✕', onclick: () => { hst.hidden = !hst.hidden; markDirty(); rerender(); } }),
          hst.color ? h('button', { title: 'Clear colour', text: '○', onclick: () => { hst.color = ''; markDirty(); rerender(); } }) : null,
          project.packets.every(p => p.src !== addr && p.dst !== addr) ? h('button', { title: 'Remove unused host', text: '🗑', onclick: () => { delete project.hosts[addr]; normalizeOrder(); markDirty(); rerender(); } }) : null)));
    });
  }
  function normalizeOrder() { const p = state.project; Object.keys(p.hosts).sort((a, b) => p.hosts[a].order - p.hosts[b].order).forEach((a, i) => { p.hosts[a].order = i; }); }
  function orderHosts(mode) {
    const p = state.project; const counts = Model.hostStats(p);
    const firstSeen = {}; p.packets.slice().sort((a, b) => a.ts - b.ts).forEach((pk, i) => { if (firstSeen[pk.src] === undefined) firstSeen[pk.src] = i; if (firstSeen[pk.dst] === undefined) firstSeen[pk.dst] = i + 0.5; });
    const isLocal = (a) => /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|fe80:|fd|fc|127\.|::1$|0\.0\.0\.0)/i.test(a);
    const keys = Object.keys(p.hosts);
    const cmp = mode === 'busiest' ? (a, b) => (counts[b] || 0) - (counts[a] || 0)
      : mode === 'local' ? (a, b) => (isLocal(b) - isLocal(a)) || ((firstSeen[a] ?? 1e9) - (firstSeen[b] ?? 1e9))
        : (a, b) => (firstSeen[a] ?? 1e9) - (firstSeen[b] ?? 1e9);
    keys.sort(cmp).forEach((a, i) => { p.hosts[a].order = i; });
    markDirty(); rerender();
  }

  function renderEventList() {
    const list = $('#eventList'); list.replaceChildren();
    const b = state.built; if (!b) return;
    const q = state.eventSearch.toLowerCase();
    const project = state.project; const theme = Render.THEMES[project.settings.theme];
    let shown = 0;
    for (const ev of b.events) {
      if (q && !(ev.label.toLowerCase().includes(q) || (ev.comment || '').toLowerCase().includes(q) || ev.proto.toLowerCase().includes(q) || Model.hostName(project, ev.src).toLowerCase().includes(q) || Model.hostName(project, ev.dst).toLowerCase().includes(q))) continue;
      shown++;
      const row = h('div', { class: 'ev' + (ev.id === state.selectedId ? ' selected' : '') + (ev.hidden ? ' is-hidden' : ''), onclick: () => { select(ev.id); scrollRowIntoView(ev.id); } },
        h('input', { type: 'checkbox', checked: !ev.hidden, title: 'Show / hide this row', onclick: (e) => e.stopPropagation(), onchange: (e) => { setAnnot(ev.id, { hidden: !e.target.checked }); rerender(); } }),
        h('span', { class: 't', text: (ev.t - b.t0).toFixed(3) + 's' }),
        h('span', { class: 'l' }, h('span', { class: 'dot', style: 'background:' + Render.colorFor(project, theme, ev) }), ev.label, ev.comment ? h('span', { class: 'c', text: '✎ ' + ev.comment }) : null));
      list.appendChild(row);
    }
    $('#eventsHint').textContent = b.events.length ? `${shown} of ${b.events.length} rows on this page. Untick to hide a row; click to edit it.` : 'Nothing on this page.';
  }

  // =========================== inspector ===========================
  function renderInspector() {
    const box = $('#inspector'); box.replaceChildren();
    const ev = state.selectedId && findEvent(state.selectedId);
    const project = state.project;
    if (!ev) {
      box.appendChild(h('h3', { text: 'Inspector' }));
      box.appendChild(h('p', { class: 'empty', text: 'Click a row in the chart to rename it, add a comment, change its colour or hide it. Click a lane header to rename a host.' }));
      box.appendChild(h('p', { class: 'empty' }, 'Shortcuts: ', h('kbd', { text: 'Del' }), ' hide row · ', h('kbd', { text: '↑' }), ' ', h('kbd', { text: '↓' }), ' move · ', h('kbd', { text: 'Esc' }), ' deselect'));
      const st = project.source ? `Source: ${project.source}` : 'Manual diagram';
      box.appendChild(h('p', { class: 'empty', text: st }));
      return;
    }
    const a = project.annotations[ev.id] || {};
    const theme = Render.THEMES[project.settings.theme];
    box.appendChild(h('div', { class: 'kind', text: ev.kind + (ev.nPackets > 1 ? ` · ${ev.nPackets} packets` : '') + (ev.packets[0].manual && ev.kind === 'packet' ? ' · manual' : '') }));
    box.appendChild(h('h3', { text: ev.autoLabel }));
    box.appendChild(h('label', { class: 'block' }, 'Display label', h('input', { type: 'text', value: a.label || '', placeholder: ev.autoLabel, spellcheck: 'false', oninput: (e) => { setAnnot(ev.id, { label: e.target.value }); scheduleRender(); } })));
    box.appendChild(h('label', { class: 'block' }, 'Comment', h('textarea', { rows: 3, placeholder: 'Shown in the notes column / tooltip', oninput: (e) => { setAnnot(ev.id, { comment: e.target.value }); scheduleRender(); } }, a.comment || '')));
    box.appendChild(h('div', { class: 'row-buttons' },
      h('label', { class: 'inline' }, 'Colour ', h('input', { type: 'color', value: a.color || Render.colorFor(project, theme, ev), oninput: (e) => { setAnnot(ev.id, { color: e.target.value }); scheduleRender(); } })),
      a.color ? h('button', { class: 'small', text: 'Reset colour', onclick: () => { setAnnot(ev.id, { color: '' }); rerender(); } }) : null,
      h('button', { class: 'small', text: ev.hidden ? 'Unhide row' : 'Hide row', onclick: () => { setAnnot(ev.id, { hidden: !ev.hidden }); rerender(); } }),
      Object.keys(a).length ? h('button', { class: 'small', text: 'Reset edits', onclick: () => { delete project.annotations[ev.id]; markDirty(); rerender(); } }) : null));

    const b = state.built;
    const kv = h('dl', { class: 'kv' });
    const add = (k, v) => { kv.appendChild(h('dt', { text: k })); kv.appendChild(h('dd', { text: String(v) })); };
    add('From', Model.hostName(project, ev.src) + (ev.srcPort != null ? ':' + ev.srcPort : ''));
    add('To', Model.hostName(project, ev.dst) + (ev.dstPort != null ? ':' + ev.dstPort : ''));
    add('Time', `${(ev.t - b.t0).toFixed(6)} s`);
    if (ev.tEnd > ev.t) add('Duration', Model.fmtDur(ev.tEnd - ev.t));
    add('Protocol', ev.protos && ev.protos.length > 1 ? ev.protos.join(', ') : ev.proto);
    add('Bytes', `${ev.bytes.toLocaleString()} (payload ${ev.payload.toLocaleString()})`);
    box.appendChild(kv);

    const pk = ev.packets[0];
    if (ev.kind === 'packet' && pk.manual) {
      box.appendChild(manualEditor(pk));
    } else if (ev.kind === 'packet') {
      add('Frame', `#${pk.index + 1}`);
      if (pk.srcMac) add('MAC', `${pk.srcMac} → ${pk.dstMac}`);
      for (const layer of pk.layers) {
        const l = h('div', { class: 'layer' }, h('h4', { text: layer.name }));
        const d = h('dl', { class: 'kv' });
        for (const k in layer.fields) { d.appendChild(h('dt', { text: k })); d.appendChild(h('dd', { text: String(layer.fields[k]) })); }
        l.appendChild(d); box.appendChild(l);
      }
    } else {
      box.appendChild(h('h4', { text: `Packets in this ${ev.kind}` }));
      const list = h('div', { class: 'pkts' });
      ev.packets.slice(0, 300).forEach(p => list.appendChild(h('div', { title: p.info, onclick: () => { project.settings.granularity = 'packet'; syncSettingsUI(); state.selectedId = 'p:' + p.id; ensureVisible(p.ts); rerender(); scrollRowIntoView('p:' + p.id); } }, h('span', { class: 't', text: (p.ts - b.t0).toFixed(4) }), `${p.proto} ${p.info}`)));
      if (ev.packets.length > 300) list.appendChild(h('div', { text: `… ${ev.packets.length - 300} more` }));
      box.appendChild(list);
      box.appendChild(h('p', { class: 'hint', text: 'Click a packet to jump to it at packet granularity.' }));
    }
  }

  // Make sure the paging window includes the given time (used when drilling down).
  function ensureVisible(ts) {
    const s = state.project.settings;
    const sorted = state.project.packets.slice().sort((a, b) => a.ts - b.ts);
    const idx = sorted.findIndex(p => p.ts >= ts);
    if (idx >= 0) s.offset = Math.max(0, idx - Math.floor(s.limit / 2));
  }

  function manualEditor(pk) {
    const project = state.project;
    const wrap = h('div', { class: 'layer' }, h('h4', { text: 'Edit event' }));
    const fields = {};
    const grid = h('div', { class: 'grid2' });
    const f = (key, label, type, value, extra) => { const inp = h('input', Object.assign({ type, value, spellcheck: 'false' }, extra || {})); fields[key] = inp; grid.appendChild(h('label', {}, label, inp)); };
    f('ts', 'Time (s)', 'number', relTime(pk.ts).toFixed(6), { step: 'any' });
    const sel = h('select', {}); for (const p of PROTO_CHOICES) sel.appendChild(h('option', { value: p, text: p })); if (!PROTO_CHOICES.includes(pk.proto)) sel.appendChild(h('option', { value: pk.proto, text: pk.proto })); sel.value = pk.proto; fields.proto = sel; grid.appendChild(h('label', {}, 'Protocol', sel));
    f('src', 'From', 'text', pk.src, { list: 'hostOptions' });
    f('dst', 'To', 'text', pk.dst, { list: 'hostOptions' });
    f('srcPort', 'From port', 'number', pk.srcPort ?? '');
    f('dstPort', 'To port', 'number', pk.dstPort ?? '');
    f('len', 'Bytes', 'number', pk.len);
    f('protoCustom', 'Custom protocol', 'text', PROTO_CHOICES.includes(pk.proto) ? '' : pk.proto);
    wrap.appendChild(grid);
    const info = h('input', { type: 'text', value: pk.info, spellcheck: 'false' });
    wrap.appendChild(h('label', { class: 'block' }, 'Text', info));
    wrap.appendChild(h('div', { class: 'row-buttons' },
      h('button', { class: 'small primary', text: 'Apply', onclick: () => {
        pk.ts = absTime(parseFloat(fields.ts.value) || 0);
        pk.proto = fields.protoCustom.value.trim() || fields.proto.value; pk.family = familyOf(pk.proto); pk.transport = TRANSPORT_OF[pk.proto] || pk.proto;
        pk.src = fields.src.value.trim() || pk.src; pk.dst = fields.dst.value.trim() || pk.dst;
        pk.srcPort = fields.srcPort.value === '' ? null : parseInt(fields.srcPort.value, 10); pk.dstPort = fields.dstPort.value === '' ? null : parseInt(fields.dstPort.value, 10);
        pk.len = pk.caplen = pk.payloadLen = parseInt(fields.len.value, 10) || 0;
        pk.info = info.value;
        Model.hostEntry(project, pk.src); Model.hostEntry(project, pk.dst);
        rebuildFlows(project); markDirty(); rerender();
      } }),
      h('button', { class: 'small', text: 'Duplicate', onclick: () => { const np = addManualPacket({ ts: pk.ts + 0.01, src: pk.src, dst: pk.dst, proto: pk.proto, label: pk.info, bytes: pk.len, srcPort: pk.srcPort, dstPort: pk.dstPort, pureAck: pk.pureAck, control: pk.control }); state.selectedId = 'p:' + np.id; rerender(); } }),
      h('button', { class: 'small danger', text: 'Delete', onclick: () => { project.packets = project.packets.filter(x => x !== pk); delete project.annotations['p:' + pk.id]; state.selectedId = null; rebuildFlows(project); markDirty(); rerender(); } })));
    return wrap;
  }

  // =========================== tabs, toasts ===========================
  function showTab(name) {
    for (const b of $$('.tabs button')) b.classList.toggle('active', b.dataset.tab === name);
    for (const t of $$('.tab')) t.classList.toggle('active', t.id === 'tab-' + name);
  }
  let toastTimer = null;
  function toast(msg, isError) {
    const t = $('#toast'); t.textContent = msg; t.hidden = false; t.classList.toggle('error', !!isError);
    clearTimeout(toastTimer); toastTimer = setTimeout(() => { t.hidden = true; }, isError ? 6000 : 3000);
  }

  // =========================== wiring ===========================
  function wire() {
    $$('.tabs button').forEach(b => b.addEventListener('click', () => showTab(b.dataset.tab)));
    $('#btnOpen').addEventListener('click', () => $('#fileCapture').click());
    $('#fileCapture').addEventListener('change', (e) => { if (e.target.files[0]) openCapture(e.target.files[0]); e.target.value = ''; });
    $('#btnOpenProject').addEventListener('click', () => $('#fileProject').click());
    $('#fileProject').addEventListener('change', async (e) => { const f = e.target.files[0]; e.target.value = ''; if (!f) return; try { loadProjectText(await f.text(), f.name); } catch (err) { toast('Could not open project: ' + err.message, true); } });
    $('#btnSaveProject').addEventListener('click', () => { download(new Blob([serializeProject()], { type: 'application/json' }), safeName() + '.waterfall.json'); state.dirty = false; toast('Project saved.'); });
    $('#btnNew').addEventListener('click', newBlank);
    $('#btnExportSvg').addEventListener('click', () => download(new Blob([Render.svgString(state.svg)], { type: 'image/svg+xml' }), safeName() + '.svg'));
    $('#btnExportPng').addEventListener('click', async () => { try { download(await Render.svgToPng(state.svg, 2), safeName() + '.png'); } catch (e) { toast(e.message, true); } });
    $('#btnTheme').addEventListener('click', () => { const next = currentTheme() === 'dark' ? 'light' : 'dark'; document.documentElement.setAttribute('data-theme', next); state.project.settings.theme = next; try { localStorage.setItem('wf-theme', next); } catch (e) { } syncSettingsUI(); rerender(); });

    $('#title').addEventListener('input', (e) => { state.project.title = e.target.value; markDirty(); scheduleRender(); });
    $('#subtitle').addEventListener('input', (e) => { state.project.subtitle = e.target.value; markDirty(); scheduleRender(); });
    $('#filter').addEventListener('input', (e) => { state.project.settings.filter = e.target.value; state.project.settings.offset = 0; scheduleRender(); });

    for (const seg of $$('.seg[data-setting]')) seg.addEventListener('click', (e) => { const b = e.target.closest('button'); if (!b) return; state.project.settings[seg.dataset.setting] = b.dataset.v; state.project.settings.offset = 0; markDirty(); syncSettingsUI(); rerender(); });
    for (const inp of $$('input[data-setting]')) {
      inp.addEventListener(inp.type === 'checkbox' ? 'change' : 'input', (e) => {
        const key = inp.dataset.setting; const s = state.project.settings;
        if (inp.type === 'checkbox') s[key] = e.target.checked;
        else s[key] = e.target.value === '' ? null : parseFloat(e.target.value);
        if (key === 'limit' && !s.limit) s.limit = 400;
        if (key !== 'limit' && key !== 'laneGap' && key !== 'rowHeight' && key !== 'fontSize' && key !== 'notesWidth' && key !== 'timelineWidth') s.offset = 0;
        markDirty(); inp.type === 'checkbox' ? rerender() : scheduleRender();
      });
    }
    $('#btnFit').addEventListener('click', () => {
      const s = state.project.settings; const n = Math.max(1, state.built.lanes.length);
      const avail = $('#chartScroll').clientWidth - 32 - 48 - (s.timeMode === 'none' ? 24 : 124) - (s.showComments && state.built.events.some(e => e.comment) ? 16 + s.notesWidth : 0);
      s.laneGap = Math.max(120, Math.floor(avail / n)); state.zoom = 1; markDirty(); syncSettingsUI(); rerender();
    });
    $('#btnUnhideAll').addEventListener('click', () => { const a = state.project.annotations; for (const k in a) { delete a[k].hidden; if (!Object.keys(a[k]).length) delete a[k]; } for (const hst of Object.values(state.project.hosts)) hst.hidden = false; markDirty(); rerender(); toast('All rows and hosts are visible again.'); });
    $('#btnClearNotes').addEventListener('click', () => { if (!confirm('Remove every comment, custom label and custom colour?')) return; const a = state.project.annotations; for (const k in a) { delete a[k].label; delete a[k].comment; delete a[k].color; if (!Object.keys(a[k]).length) delete a[k]; } markDirty(); rerender(); });
    $('#btnResetSettings').addEventListener('click', () => { const theme = state.project.settings.theme; state.project.settings = Model.defaultSettings(); state.project.settings.theme = theme; $('#filter').value = ''; syncSettingsUI(); rerender(); });
    $('#btnHostsFirstSeen').addEventListener('click', () => orderHosts('first'));
    $('#btnHostsLocalFirst').addEventListener('click', () => orderHosts('local'));
    $('#btnHostsBusiest').addEventListener('click', () => orderHosts('busiest'));
    $('#eventSearch').addEventListener('input', (e) => { state.eventSearch = e.target.value; renderEventList(); });

    $('#pagePrev').addEventListener('click', () => { const s = state.project.settings; s.offset = Math.max(0, s.offset - s.limit); rerender(); });
    $('#pageNext').addEventListener('click', () => { const s = state.project.settings; s.offset = s.offset + s.limit; rerender(); });
    $('#zoomIn').addEventListener('click', () => { state.zoom = Math.min(3, state.zoom * 1.2); applyZoom(); });
    $('#zoomOut').addEventListener('click', () => { state.zoom = Math.max(0.2, state.zoom / 1.2); applyZoom(); });
    $('#zoomReset').addEventListener('click', () => { state.zoom = 1; applyZoom(); });

    // add tab
    const protoSel = $('#evProto'); for (const p of PROTO_CHOICES) protoSel.appendChild(h('option', { value: p, text: p }));
    const tplSel = $('#tplSelect'); for (const k in TEMPLATES) tplSel.appendChild(h('option', { value: k, text: TEMPLATES[k].name }));
    $('#btnAddHost').addEventListener('click', () => {
      const addr = $('#newHostAddr').value.trim(); if (!addr) { toast('Enter an address or identifier for the host.', true); return; }
      const hst = Model.hostEntry(state.project, addr); hst.name = $('#newHostName').value.trim(); hst.hidden = false;
      $('#newHostAddr').value = ''; $('#newHostName').value = ''; markDirty(); rerender(); toast(`Added host ${hst.name || addr}.`);
    });
    $('#btnAddEvent').addEventListener('click', () => {
      const src = $('#evSrc').value.trim(), dst = $('#evDst').value.trim();
      if (!src || !dst) { toast('Choose both a From and a To host.', true); return; }
      const proto = $('#evProto').value === 'Other' && $('#evProtoCustom').value.trim() ? $('#evProtoCustom').value.trim() : $('#evProto').value;
      const t = parseFloat($('#evTime').value) || 0;
      const p = addManualPacket({ ts: absTime(t), src, dst, proto, label: $('#evLabel').value.trim() || proto, bytes: parseInt($('#evBytes').value, 10) || 0, srcPort: $('#evSport').value === '' ? null : parseInt($('#evSport').value, 10), dstPort: $('#evDport').value === '' ? null : parseInt($('#evDport').value, 10), comment: $('#evComment').value.trim() });
      if ($('#evAutoAdvance').checked) $('#evTime').value = (t + (parseFloat($('#evStep').value) || 0.02)).toFixed(3);
      $('#evLabel').value = ''; $('#evComment').value = '';
      state.selectedId = 'p:' + p.id;
      rerender(); scrollRowIntoView('p:' + p.id);
    });
    $('#btnInsertTemplate').addEventListener('click', () => {
      const a = $('#tplA').value.trim(), b = $('#tplB').value.trim();
      if (!a || !b) { toast('Choose the two hosts for the template.', true); return; }
      Model.hostEntry(state.project, a); Model.hostEntry(state.project, b);
      insertTemplate($('#tplSelect').value, a, b, parseFloat($('#tplStart').value) || 0, parseFloat($('#tplSpacing').value) || 0.02);
    });

    // drag & drop
    const area = $('#chartArea'); let dragDepth = 0;
    document.addEventListener('dragenter', (e) => { e.preventDefault(); dragDepth++; area.classList.add('dragging'); });
    document.addEventListener('dragleave', () => { dragDepth = Math.max(0, dragDepth - 1); if (!dragDepth) area.classList.remove('dragging'); });
    document.addEventListener('dragover', (e) => e.preventDefault());
    document.addEventListener('drop', async (e) => {
      e.preventDefault(); dragDepth = 0; area.classList.remove('dragging');
      const f = e.dataTransfer.files[0]; if (!f) return;
      if (/\.json$/i.test(f.name)) { try { loadProjectText(await f.text(), f.name); } catch (err) { toast(err.message, true); } }
      else openCapture(f);
    });

    // keyboard
    document.addEventListener('keydown', (e) => {
      const tag = (e.target.tagName || '').toLowerCase();
      if (tag === 'input' || tag === 'textarea' || tag === 'select') { if (e.key === 'Escape') e.target.blur(); return; }
      if (!state.built) return;
      const evs = state.built.events; const i = evs.findIndex(x => x.id === state.selectedId);
      if (e.key === 'Escape') select(null);
      else if ((e.key === 'Delete' || e.key === 'Backspace') && state.selectedId) { e.preventDefault(); const ev = findEvent(state.selectedId); setAnnot(ev.id, { hidden: !ev.hidden }); const next = evs[i + 1] || evs[i - 1]; state.selectedId = state.project.settings.showHidden ? ev.id : (next ? next.id : null); rerender(); }
      else if (e.key === 'ArrowDown' && evs.length) { e.preventDefault(); const n = evs[Math.min(evs.length - 1, i + 1)]; select(n.id); scrollRowIntoView(n.id); }
      else if (e.key === 'ArrowUp' && evs.length) { e.preventDefault(); const n = evs[Math.max(0, i - 1)]; select(n.id); scrollRowIntoView(n.id); }
      else if ((e.metaKey || e.ctrlKey) && e.key === 's') { e.preventDefault(); $('#btnSaveProject').click(); }
      else if ((e.metaKey || e.ctrlKey) && e.key === 'o') { e.preventDefault(); $('#btnOpen').click(); }
    });
    window.addEventListener('beforeunload', (e) => { if (state.dirty) { e.preventDefault(); e.returnValue = ''; } });
  }

  // =========================== boot ===========================
  function boot() {
    let theme = 'light';
    try { theme = localStorage.getItem('wf-theme') || (matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light'); } catch (e) { }
    document.documentElement.setAttribute('data-theme', theme);
    wire();
    setProject(Model.newProject({ title: '', baseTime: Math.floor(Date.now() / 1000) }));
    showTab('chart');
    applyUrlParams();
  }

  // Optional URL parameters (only useful when the tool is served over http):
  //   ?load=samples/sample.pcap   fetch and open a capture or .waterfall.json project
  //   &view=timeline &granularity=flow &theme=dark &hideAcks=1 &filter=tls ... (any setting key)
  async function applyUrlParams() {
    const q = new URLSearchParams(location.search);
    if (![...q.keys()].length) return;
    const applySettings = () => {
      const s = state.project.settings;
      for (const [k, v] of q) {
        if (k === 'load') continue;
        if (k === 'theme') { document.documentElement.setAttribute('data-theme', v); s.theme = v; continue; }
        if (k in s) { s[k] = typeof s[k] === 'boolean' ? (v === '1' || v === 'true') : typeof s[k] === 'number' || s[k] === null ? (v === '' ? null : Number(v)) : v; }
      }
      $('#filter').value = s.filter || ''; syncSettingsUI(); rerender();
    };
    const url = q.get('load');
    if (url) {
      try {
        const res = await fetch(url); if (!res.ok) throw new Error(res.status + ' ' + res.statusText);
        const name = url.split('/').pop();
        if (/\.json$/i.test(name)) loadProjectText(await res.text(), name);
        else { const blob = await res.blob(); await openCapture(new File([blob], name)); }
      } catch (e) { toast('Could not load ' + url + ': ' + e.message, true); }
    }
    applySettings();
  }
  boot();
  window.WaterfallApp = { state, openCapture, loadProjectText, rerender, addManualPacket, insertTemplate, TEMPLATES };
})();
