/* model.js — turns packets into chart "events" at a chosen granularity, applies
   user annotations (renames, comments, hidden rows, colours) and display filters. */
(function () {
  'use strict';

  const FAMILY_ORDER = ['TCP', 'TLS', 'HTTP', 'DNS', 'UDP', 'ICMP', 'ARP', 'Other'];

  function defaultSettings() {
    return {
      view: 'ladder',            // 'ladder' | 'timeline'
      granularity: 'packet',     // 'packet' | 'message' | 'flow' | 'conversation'
      layout: 'even',            // 'even' | 'scaled'
      timeMode: 'relative',      // 'relative' | 'absolute' | 'delta' | 'none'
      hideAcks: false,
      hideControl: false,        // hide SYN/FIN/RST/ARP/ICMP-level chatter
      showHidden: false,
      showComments: true,
      showBytes: true,
      showPorts: false,
      showLegend: true,
      hideUnusedLanes: true,
      hiddenProtos: [],
      filter: '',
      timeFrom: null, timeTo: null,
      offset: 0, limit: 400,
      messageGap: 0.25,          // seconds — max silence inside one "message"
      gapMarker: 1.0,            // seconds — draw a gap divider when the pause is longer
      laneGap: 230, rowHeight: 34, fontSize: 12, notesWidth: 240, timelineWidth: 1100,
      theme: 'light',
    };
  }

  function newProject(opts) {
    return Object.assign({
      version: 1,
      title: 'Untitled capture',
      subtitle: '',
      source: null,
      settings: defaultSettings(),
      hosts: {},        // addr -> { name, color, hidden, order }
      annotations: {},  // eventId -> { label, comment, color, hidden }
      protoColors: {},  // proto -> hex override
      packets: [],
      nextPid: 1,
    }, opts || {});
  }

  // ---------- host helpers ----------
  function hostEntry(project, addr) {
    if (!project.hosts[addr]) {
      const order = Object.keys(project.hosts).length;
      project.hosts[addr] = { name: '', color: '', hidden: false, order };
    }
    return project.hosts[addr];
  }
  function hostName(project, addr) { const h = project.hosts[addr]; return (h && h.name) || addr; }

  // ---------- display filter ----------
  // terms separated by spaces; all must match. forms: text | host:x | port:n | proto:x | -term (negate)
  function compileFilter(text) {
    const terms = (text || '').trim().split(/\s+/).filter(Boolean).map(t => {
      let neg = false; if (t.startsWith('-') || t.startsWith('!')) { neg = true; t = t.slice(1); }
      const m = t.match(/^(host|port|proto|src|dst|label|comment):(.+)$/i);
      return { neg, key: m ? m[1].toLowerCase() : null, val: (m ? m[2] : t).toLowerCase() };
    });
    if (!terms.length) return null;
    return (ev, project) => terms.every(tm => {
      let ok;
      const srcN = hostName(project, ev.src).toLowerCase(), dstN = hostName(project, ev.dst).toLowerCase();
      switch (tm.key) {
        case 'host': ok = ev.src.toLowerCase().includes(tm.val) || ev.dst.toLowerCase().includes(tm.val) || srcN.includes(tm.val) || dstN.includes(tm.val); break;
        case 'src': ok = ev.src.toLowerCase().includes(tm.val) || srcN.includes(tm.val); break;
        case 'dst': ok = ev.dst.toLowerCase().includes(tm.val) || dstN.includes(tm.val); break;
        case 'port': ok = String(ev.srcPort) === tm.val || String(ev.dstPort) === tm.val; break;
        case 'proto': ok = ev.proto.toLowerCase() === tm.val || ev.family.toLowerCase() === tm.val || (ev.protos || []).some(x => x.toLowerCase() === tm.val); break;
        case 'label': ok = ev.label.toLowerCase().includes(tm.val); break;
        case 'comment': ok = (ev.comment || '').toLowerCase().includes(tm.val); break;
        default: ok = ev.label.toLowerCase().includes(tm.val) || ev.proto.toLowerCase() === tm.val || ev.family.toLowerCase() === tm.val || ev.src.toLowerCase().includes(tm.val) || ev.dst.toLowerCase().includes(tm.val) || srcN.includes(tm.val) || dstN.includes(tm.val) || (ev.comment || '').toLowerCase().includes(tm.val) || (ev.protos || []).some(x => x.toLowerCase() === tm.val);
      }
      return tm.neg ? !ok : ok;
    });
  }

  // ---------- formatting ----------
  function fmtBytes(n) { if (n < 1024) return n + ' B'; if (n < 1048576) return (n / 1024).toFixed(1) + ' KB'; return (n / 1048576).toFixed(2) + ' MB'; }
  function fmtDur(s) { if (s < 0.001) return (s * 1e6).toFixed(0) + ' µs'; if (s < 1) return (s * 1000).toFixed(1) + ' ms'; if (s < 60) return s.toFixed(3) + ' s'; return (s / 60).toFixed(1) + ' min'; }
  function fmtTime(t, mode, t0, prev) {
    if (mode === 'none') return '';
    if (mode === 'absolute') { const d = new Date(t * 1000); const ms = Math.floor((t % 1) * 1000).toString().padStart(3, '0'); return d.toLocaleTimeString([], { hour12: false }) + '.' + ms; }
    if (mode === 'delta') { return (prev == null ? '+0.000' : '+' + (t - prev).toFixed(t - prev < 0.01 ? 6 : 3)) + ' s'; }
    return (t - t0).toFixed(6) + ' s';
  }

  // ---------- event construction ----------
  function packetEvent(p) {
    return {
      id: 'p:' + p.id, kind: 'packet', t: p.ts, tEnd: p.ts,
      src: p.src, dst: p.dst, srcPort: p.srcPort, dstPort: p.dstPort,
      proto: p.proto, family: p.family, label: p.info, bytes: p.len, payload: p.payloadLen,
      nPackets: 1, packets: [p], flowKey: p.flowKey, dir: p.dir, control: p.control, pureAck: p.pureAck,
      protos: [p.proto],
    };
  }

  function buildMessages(packets, gap) {
    const events = []; let last = null;
    for (const p of packets) {
      if (p.pureAck) continue;
      const canMerge = last && last.flowKey === p.flowKey && last.dir === p.dir && !p.control && !last.control
        && (p.ts - last.tEnd) <= gap && p.mergeKey && (p.mergeKey === 'cont' || p.mergeKey === last.mergeKey);
      // also require that no other flow's event interleaved (last is the most recent event overall)
      if (canMerge) {
        last.tEnd = p.ts; last.nPackets++; last.bytes += p.len; last.payload += p.payloadLen; last.packets.push(p);
        if (!last.protos.includes(p.proto)) last.protos.push(p.proto);
        continue;
      }
      const ev = packetEvent(p);
      ev.id = 'm:' + p.id; ev.kind = 'message'; ev.mergeKey = p.mergeKey;
      events.push(ev); last = ev;
    }
    for (const ev of events) {
      if (ev.nPackets > 1) {
        const base = ev.packets[0].info.replace(/\s*\(\d+ bytes\)$/, '').replace(/Continuation data/, 'Data');
        ev.label = `${base} · ${ev.nPackets} segments, ${fmtBytes(ev.payload)}`;
        // if the first packet was TLS app data, say so plainly
        if (ev.mergeKey === 'tls-app') ev.label = `${ev.packets[0].info.split(' ')[0]} Application Data · ${ev.nPackets} records, ${fmtBytes(ev.payload)}`;
      }
    }
    return events;
  }

  function flowLabel(f, ev) {
    const app = f.app ? f.app + (f.name ? ' ' + f.name : '') : null;
    const tp = ev.packets[0].transport || ev.packets[0].proto;
    const dur = ev.tEnd - ev.t;
    return `${app || tp} · ${ev.nPackets} pkts, ${fmtBytes(ev.bytes)}${dur > 0 ? ', ' + fmtDur(dur) : ''}`;
  }

  function buildFlows(packets, byHostPair) {
    const map = new Map(); const events = [];
    for (const p of packets) {
      let key;
      if (byHostPair) { key = p.src <= p.dst ? `${p.src}|${p.dst}` : `${p.dst}|${p.src}`; }
      else key = p.flowKey;
      let ev = map.get(key);
      if (!ev) {
        ev = packetEvent(p);
        ev.id = (byHostPair ? 'c:' : 'f:') + key; ev.kind = byHostPair ? 'conversation' : 'flow';
        ev.flows = new Set([p.flowKey]);
        ev.flowObj = p.flow;
        map.set(key, ev); events.push(ev);
      } else {
        ev.tEnd = Math.max(ev.tEnd, p.ts); ev.nPackets++; ev.bytes += p.len; ev.payload += p.payloadLen; ev.packets.push(p);
        ev.flows.add(p.flowKey);
        if (!ev.protos.includes(p.proto)) ev.protos.push(p.proto);
        // prefer the richest application protocol for the colour
        if (rank(p.family) > rank(ev.family)) { ev.family = p.family; ev.proto = p.proto; }
      }
    }
    for (const ev of events) {
      if (byHostPair) {
        const apps = [...new Set(ev.packets.map(p => p.flow && p.flow.app ? p.flow.app : p.transport || p.proto))];
        ev.label = `${ev.flows.size} flow${ev.flows.size > 1 ? 's' : ''} (${apps.slice(0, 4).join(', ')}${apps.length > 4 ? '…' : ''}) · ${ev.nPackets} pkts, ${fmtBytes(ev.bytes)}${ev.tEnd > ev.t ? ', ' + fmtDur(ev.tEnd - ev.t) : ''}`;
        ev.srcPort = null; ev.dstPort = null;
      } else {
        ev.label = flowLabel(ev.flowObj, ev);
      }
    }
    return events;
  }
  const RANK = { Other: 0, ARP: 1, ICMP: 2, UDP: 3, TCP: 4, DNS: 5, TLS: 6, HTTP: 7 };
  const rank = (f) => RANK[f] || 0;

  // ---------- main entry ----------
  function build(project) {
    const s = project.settings;
    const hidden = new Set(s.hiddenProtos || []);
    let packets = project.packets.slice().sort((a, b) => a.ts - b.ts || a.id - b.id);
    const t0 = packets.length ? packets[0].ts : 0;
    const tN = packets.length ? packets[packets.length - 1].ts : 0;

    // packet-level exclusions (these apply at every granularity)
    packets = packets.filter(p => {
      const a = project.annotations['p:' + p.id];
      if (a && a.hidden && !s.showHidden) return false;
      if (hidden.has(p.proto) || hidden.has(p.family)) return false;
      if (s.hideAcks && p.pureAck) return false;
      if (s.hideControl && p.control && p.payloadLen === 0 && p.transport === 'TCP') return false;
      if (s.timeFrom != null && p.ts - t0 < s.timeFrom) return false;
      if (s.timeTo != null && p.ts - t0 > s.timeTo) return false;
      const hs = project.hosts[p.src], hd = project.hosts[p.dst];
      if ((hs && hs.hidden) || (hd && hd.hidden)) return false;
      return true;
    });

    let events;
    switch (s.granularity) {
      case 'message': events = buildMessages(packets, s.messageGap); break;
      case 'flow': events = buildFlows(packets, false); break;
      case 'conversation': events = buildFlows(packets, true); break;
      default: events = packets.map(packetEvent);
    }
    events.sort((a, b) => a.t - b.t);

    // annotations
    for (const ev of events) {
      const a = project.annotations[ev.id];
      ev.autoLabel = ev.label;
      if (a) {
        if (a.label) ev.label = a.label;
        ev.comment = a.comment || '';
        ev.color = a.color || null;
        ev.hidden = !!a.hidden;
      }
      if (s.granularity === 'packet') { const pa = project.annotations['p:' + ev.packets[0].id]; if (pa && pa.hidden) ev.hidden = true; }
      else {
        // Inherit edits made at packet level so a comment survives a change of granularity.
        const pas = ev.packets.map(p => project.annotations['p:' + p.id]).filter(Boolean);
        if (pas.length) {
          const comments = pas.map(x => x.comment).filter(Boolean);
          if (!ev.comment && comments.length) ev.comment = comments.join('\n');
          if (!ev.color) ev.color = (pas.find(x => x.color) || {}).color || null;
          if ((!a || !a.label) && ev.nPackets === 1 && pas[0].label) ev.label = pas[0].label;
        }
      }
    }
    const total = events.length;
    const fn = compileFilter(s.filter);
    if (fn) events = events.filter(ev => fn(ev, project));
    if (!s.showHidden) events = events.filter(ev => !ev.hidden);
    const matched = events.length;
    const offset = Math.max(0, Math.min(s.offset || 0, Math.max(0, matched - 1)));
    const limit = Math.max(1, s.limit || 400);
    const windowed = events.slice(offset, offset + limit);

    // lanes
    const used = new Set();
    for (const ev of windowed) { used.add(ev.src); used.add(ev.dst); }
    const allHosts = new Set(project.packets.flatMap(p => [p.src, p.dst]));
    for (const h of Object.keys(project.hosts)) allHosts.add(h);
    let lanes = [...allHosts].filter(h => !(project.hosts[h] && project.hosts[h].hidden));
    if (s.hideUnusedLanes) lanes = lanes.filter(h => used.has(h));
    lanes.sort((a, b) => laneOrder(project, a) - laneOrder(project, b));
    const laneInfo = lanes.map(addr => ({ addr, name: hostName(project, addr), color: (project.hosts[addr] && project.hosts[addr].color) || null }));

    const protosPresent = [...new Set(windowed.map(e => e.proto))];
    return { events: windowed, total, matched, offset, limit, lanes: laneInfo, t0, tN, protosPresent, packetCount: packets.length };
  }

  function laneOrder(project, addr) { const h = project.hosts[addr]; return h ? h.order : 1e9; }

  // Stats used by panels
  function protocolStats(project) {
    const counts = {};
    for (const p of project.packets) { counts[p.proto] = (counts[p.proto] || 0) + 1; }
    return Object.entries(counts).sort((a, b) => b[1] - a[1]);
  }
  function hostStats(project) {
    const counts = {};
    for (const p of project.packets) { counts[p.src] = (counts[p.src] || 0) + 1; counts[p.dst] = (counts[p.dst] || 0) + 1; }
    return counts;
  }

  window.Model = { defaultSettings, newProject, build, hostEntry, hostName, fmtBytes, fmtDur, fmtTime, protocolStats, hostStats, FAMILY_ORDER };
})();
