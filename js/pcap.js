/* pcap.js — pcap / pcapng parsing and protocol decoding, entirely in the browser.
   Exposes window.Pcap = { parse(arrayBuffer) -> { format, frames }, decodeAll(frames) -> packets[] } */
(function () {
  'use strict';

  // ---------- byte helpers ----------
  const u8 = (d, o) => d[o];
  const u16 = (d, o) => (d[o] << 8) | d[o + 1];
  const u32 = (d, o) => ((d[o] << 24) >>> 0) + (d[o + 1] << 16) + (d[o + 2] << 8) + d[o + 3];
  const hex2 = (n) => n.toString(16).padStart(2, '0');
  const mac = (d, o) => Array.from(d.subarray(o, o + 6), hex2).join(':');
  const ipv4 = (d, o) => `${d[o]}.${d[o + 1]}.${d[o + 2]}.${d[o + 3]}`;
  function ipv6(d, o) {
    const g = [];
    for (let i = 0; i < 8; i++) g.push(u16(d, o + i * 2));
    // find longest run of zeros for :: compression
    let best = -1, bestLen = 0, cur = -1, curLen = 0;
    for (let i = 0; i < 8; i++) {
      if (g[i] === 0) { if (cur < 0) { cur = i; curLen = 1; } else curLen++; if (curLen > bestLen) { best = cur; bestLen = curLen; } }
      else { cur = -1; curLen = 0; }
    }
    if (bestLen < 2) return g.map(x => x.toString(16)).join(':');
    const left = g.slice(0, best).map(x => x.toString(16)).join(':');
    const right = g.slice(best + bestLen).map(x => x.toString(16)).join(':');
    return `${left}::${right}`;
  }
  function ascii(d, o, n) {
    let s = '';
    for (let i = o; i < Math.min(d.length, o + n); i++) { const c = d[i]; s += (c >= 32 && c < 127) ? String.fromCharCode(c) : (c === 10 || c === 13 || c === 9 ? String.fromCharCode(c) : '.'); }
    return s;
  }
  const isPrintableStart = (d, o, n) => { for (let i = o; i < Math.min(d.length, o + n); i++) { const c = d[i]; if (!(c >= 32 && c < 127) && c !== 10 && c !== 13 && c !== 9) return false; } return true; };

  // ---------- container parsing ----------
  function parse(buffer) {
    if (buffer.byteLength < 24) throw new Error('File is too small to be a capture.');
    const dv = new DataView(buffer);
    const magic = dv.getUint32(0, false);
    if (magic === 0x0a0d0d0a) return parsePcapng(buffer);
    if ([0xa1b2c3d4, 0xd4c3b2a1, 0xa1b23c4d, 0x4d3cb2a1].includes(magic)) return parsePcap(buffer);
    throw new Error('Not a recognised pcap or pcapng file (bad magic number).');
  }

  function parsePcap(buffer) {
    const dv = new DataView(buffer);
    const magic = dv.getUint32(0, false);
    const le = (magic === 0xd4c3b2a1 || magic === 0x4d3cb2a1);
    const nano = (magic === 0xa1b23c4d || magic === 0x4d3cb2a1);
    const linktype = dv.getUint32(20, le) & 0x0fffffff;
    const frames = [];
    let off = 24;
    while (off + 16 <= buffer.byteLength) {
      const sec = dv.getUint32(off, le), frac = dv.getUint32(off + 4, le);
      const incl = dv.getUint32(off + 8, le), orig = dv.getUint32(off + 12, le);
      off += 16;
      if (off + incl > buffer.byteLength) break;
      frames.push({ ts: sec + frac / (nano ? 1e9 : 1e6), caplen: incl, len: orig, linktype, data: new Uint8Array(buffer, off, incl) });
      off += incl;
    }
    return { format: 'pcap', linktype, frames };
  }

  function parsePcapng(buffer) {
    const dv = new DataView(buffer);
    let off = 0, le = true, ifaces = [];
    const frames = [];
    let firstLink = null;
    while (off + 12 <= buffer.byteLength) {
      let type = dv.getUint32(off, le);
      if (dv.getUint32(off, true) === 0x0a0d0d0a) {
        le = (dv.getUint32(off + 8, true) === 0x1a2b3c4d);
        type = 0x0a0d0d0a;
        ifaces = [];
      }
      const blen = dv.getUint32(off + 4, le);
      if (blen < 12 || off + blen > buffer.byteLength) break;
      const body = off + 8, bodyLen = blen - 12;
      if (type === 1) {
        const linktype = dv.getUint16(body, le);
        const snaplen = dv.getUint32(body + 4, le);
        let tsres = 1e-6;
        let o = body + 8;
        while (o + 4 <= body + bodyLen) {
          const code = dv.getUint16(o, le), l = dv.getUint16(o + 2, le);
          if (code === 0) break;
          if (code === 9 && l >= 1) { const v = dv.getUint8(o + 4); tsres = (v & 0x80) ? Math.pow(2, -(v & 0x7f)) : Math.pow(10, -v); }
          o += 4 + ((l + 3) & ~3);
        }
        ifaces.push({ linktype, snaplen, tsres });
        if (firstLink === null) firstLink = linktype;
      } else if (type === 6 || type === 2) {
        const ifid = type === 6 ? dv.getUint32(body, le) : dv.getUint16(body, le);
        const tsh = dv.getUint32(body + 4, le), tsl = dv.getUint32(body + 8, le);
        const caplen = dv.getUint32(body + 12, le), orig = dv.getUint32(body + 16, le);
        const iface = ifaces[ifid] || { linktype: 1, tsres: 1e-6 };
        const ts = (tsh * 4294967296 + tsl) * iface.tsres;
        if (20 + caplen <= bodyLen) frames.push({ ts, caplen, len: orig, linktype: iface.linktype, data: new Uint8Array(buffer, body + 20, caplen) });
      } else if (type === 3) {
        const orig = dv.getUint32(body, le);
        const iface = ifaces[0] || { linktype: 1, snaplen: 0 };
        const caplen = Math.min(orig, iface.snaplen || orig, bodyLen - 4);
        frames.push({ ts: frames.length ? frames[frames.length - 1].ts : 0, caplen, len: orig, linktype: iface.linktype, data: new Uint8Array(buffer, body + 4, caplen) });
      }
      off += blen;
    }
    return { format: 'pcapng', linktype: firstLink, frames };
  }

  // ---------- decoding ----------
  const TCP_FLAG_NAMES = [['FIN', 0x01], ['SYN', 0x02], ['RST', 0x04], ['PSH', 0x08], ['ACK', 0x10], ['URG', 0x20], ['ECE', 0x40], ['CWR', 0x80]];
  const DNS_TYPES = { 1: 'A', 2: 'NS', 5: 'CNAME', 6: 'SOA', 12: 'PTR', 15: 'MX', 16: 'TXT', 28: 'AAAA', 33: 'SRV', 35: 'NAPTR', 41: 'OPT', 43: 'DS', 46: 'RRSIG', 47: 'NSEC', 48: 'DNSKEY', 64: 'SVCB', 65: 'HTTPS', 255: 'ANY' };
  const ICMP4_TYPES = { 0: 'Echo (ping) reply', 3: 'Destination unreachable', 4: 'Source quench', 5: 'Redirect', 8: 'Echo (ping) request', 11: 'Time-to-live exceeded', 12: 'Parameter problem', 13: 'Timestamp request', 14: 'Timestamp reply' };
  const ICMP4_UNREACH = { 0: 'Network unreachable', 1: 'Host unreachable', 2: 'Protocol unreachable', 3: 'Port unreachable', 4: 'Fragmentation needed', 13: 'Administratively prohibited' };
  const ICMP6_TYPES = { 1: 'Destination unreachable', 2: 'Packet too big', 3: 'Time exceeded', 4: 'Parameter problem', 128: 'Echo (ping) request', 129: 'Echo (ping) reply', 130: 'Multicast listener query', 131: 'Multicast listener report', 132: 'Multicast listener done', 133: 'Router solicitation', 134: 'Router advertisement', 135: 'Neighbor solicitation', 136: 'Neighbor advertisement', 137: 'Redirect', 143: 'Multicast listener report v2' };
  const TLS_HS = { 0: 'Hello Request', 1: 'Client Hello', 2: 'Server Hello', 4: 'New Session Ticket', 5: 'End of Early Data', 8: 'Encrypted Extensions', 11: 'Certificate', 12: 'Server Key Exchange', 13: 'Certificate Request', 14: 'Server Hello Done', 15: 'Certificate Verify', 16: 'Client Key Exchange', 20: 'Finished', 24: 'Key Update' };
  const TLS_VER = { 0x0300: 'SSLv3', 0x0301: 'TLSv1.0', 0x0302: 'TLSv1.1', 0x0303: 'TLSv1.2', 0x0304: 'TLSv1.3' };
  const DHCP_MSG = { 1: 'Discover', 2: 'Offer', 3: 'Request', 4: 'Decline', 5: 'ACK', 6: 'NAK', 7: 'Release', 8: 'Inform' };
  const HTTP_METHODS = ['GET ', 'POST ', 'PUT ', 'HEAD ', 'DELETE ', 'OPTIONS ', 'PATCH ', 'CONNECT ', 'TRACE '];
  const IP_PROTO_NAMES = { 1: 'ICMP', 2: 'IGMP', 6: 'TCP', 17: 'UDP', 41: 'IPv6', 47: 'GRE', 50: 'ESP', 51: 'AH', 58: 'ICMPv6', 89: 'OSPF', 132: 'SCTP' };

  function newPacket(frame, index) {
    return {
      index, ts: frame.ts, len: frame.len, caplen: frame.caplen,
      src: null, dst: null, srcPort: null, dstPort: null,
      srcMac: null, dstMac: null,
      proto: 'Other', family: 'Other', transport: null,
      info: '', layers: [], payloadLen: 0,
      tcp: null, flags: [], pureAck: false, mergeKey: null, control: false,
      appName: null, flowName: null,
    };
  }

  function decodeFrame(frame, index) {
    const d = frame.data;
    const p = newPacket(frame, index);
    try {
      let net = null; // ['ipv4'|'ipv6'|'arp', offset]
      switch (frame.linktype) {
        case 1: net = decodeEthernet(p, d, 0); break;
        case 113: { // Linux cooked v1
          if (d.length < 16) break;
          const arphrd = u16(d, 2);
          p.layers.push({ name: 'Linux cooked capture', fields: { 'Packet type': u16(d, 0), 'Link type': arphrd, 'Protocol': '0x' + u16(d, 14).toString(16) } });
          net = etherNext(u16(d, 14), 16);
          break;
        }
        case 276: { // Linux cooked v2
          if (d.length < 20) break;
          p.layers.push({ name: 'Linux cooked capture v2', fields: { 'Protocol': '0x' + u16(d, 0).toString(16), 'Interface index': u32(d, 4) } });
          net = etherNext(u16(d, 0), 20);
          break;
        }
        case 0: case 108: { // BSD loopback / null
          if (d.length < 4) break;
          const fam = d[0] || d[3];
          p.layers.push({ name: 'Null/Loopback', fields: { 'Family': fam } });
          net = fam === 2 ? ['ipv4', 4] : (fam === 24 || fam === 28 || fam === 30) ? ['ipv6', 4] : null;
          break;
        }
        case 12: case 101: case 228: case 229: { // raw IP
          const v = d[0] >> 4;
          net = v === 4 ? ['ipv4', 0] : v === 6 ? ['ipv6', 0] : null;
          break;
        }
        case 105: case 127: { // 802.11 (optionally with radiotap) — we only pull addresses
          let o = 0;
          if (frame.linktype === 127) { o = d[2] | (d[3] << 8); p.layers.push({ name: 'Radiotap', fields: { 'Header length': o } }); }
          if (d.length >= o + 24) {
            const fc = d[o], type = (fc >> 2) & 3, sub = (fc >> 4) & 15;
            p.srcMac = mac(d, o + 10); p.dstMac = mac(d, o + 4);
            p.src = p.srcMac; p.dst = p.dstMac;
            p.proto = '802.11'; p.family = 'Other';
            p.info = ['Management', 'Control', 'Data', 'Extension'][type] + ' frame (subtype ' + sub + ')';
            p.layers.push({ name: 'IEEE 802.11', fields: { 'Type': type, 'Subtype': sub, 'Destination': p.dstMac, 'Source': p.srcMac } });
          }
          break;
        }
        default:
          p.info = 'Link type ' + frame.linktype + ' (not decoded)';
      }
      if (net) decodeNetwork(p, d, net[0], net[1]);
      else if (!p.info) p.info = 'Unknown link-layer payload';
    } catch (e) {
      p.info = p.info || ('Decode error: ' + e.message);
      p.error = e.message;
    }
    if (!p.src) { p.src = p.srcMac || 'unknown'; p.dst = p.dstMac || 'unknown'; }
    return p;
  }

  function etherNext(type, off) {
    if (type === 0x0800) return ['ipv4', off];
    if (type === 0x86dd) return ['ipv6', off];
    if (type === 0x0806) return ['arp', off];
    return ['ether:' + type, off];
  }

  function decodeEthernet(p, d, o) {
    if (d.length < o + 14) return null;
    p.dstMac = mac(d, o); p.srcMac = mac(d, o + 6);
    let type = u16(d, o + 12); o += 14;
    const fields = { 'Destination': p.dstMac, 'Source': p.srcMac };
    const vlans = [];
    while ((type === 0x8100 || type === 0x88a8 || type === 0x9100) && d.length >= o + 4) {
      vlans.push(u16(d, o) & 0x0fff); type = u16(d, o + 2); o += 4;
    }
    if (vlans.length) fields['VLAN'] = vlans.join(', ');
    fields['Type'] = '0x' + type.toString(16).padStart(4, '0');
    p.layers.push({ name: 'Ethernet II', fields });
    p.vlan = vlans[0];
    const n = etherNext(type, o);
    if (n[0].startsWith('ether:')) {
      p.src = p.srcMac; p.dst = p.dstMac;
      const names = { 0x88cc: 'LLDP', 0x8899: 'RRCP', 0x888e: 'EAPOL', 0x88e1: 'HomePlug', 0x8847: 'MPLS', 0x8863: 'PPPoE Discovery', 0x8864: 'PPPoE Session', 0x9000: 'Loopback', 0x80f3: 'AARP', 0x809b: 'AppleTalk', 0x22f0: 'AVTP', 0x88f7: 'PTP' };
      if (type <= 1500) { p.proto = 'LLC'; p.info = 'IEEE 802.3 LLC frame (' + type + ' bytes)'; if (d.length >= o + 3 && d[o] === 0x42) { p.proto = 'STP'; p.info = 'Spanning Tree BPDU'; } }
      else { p.proto = names[type] || 'Ethernet'; p.info = (names[type] || ('EtherType 0x' + type.toString(16))) + ' frame'; }
      p.family = 'Other';
      return null;
    }
    return n;
  }

  function decodeNetwork(p, d, kind, o) {
    if (kind === 'arp') return decodeArp(p, d, o);
    if (kind === 'ipv4') {
      if (d.length < o + 20) return;
      const ihl = (d[o] & 0x0f) * 4, total = u16(d, o + 2), id = u16(d, o + 4);
      const flagsFrag = u16(d, o + 6), ttl = d[o + 8], proto = d[o + 9];
      p.src = ipv4(d, o + 12); p.dst = ipv4(d, o + 16);
      const df = !!(flagsFrag & 0x4000), mf = !!(flagsFrag & 0x2000), fragOff = flagsFrag & 0x1fff;
      p.layers.push({ name: 'Internet Protocol Version 4', fields: { 'Source': p.src, 'Destination': p.dst, 'Identification': '0x' + id.toString(16), 'TTL': ttl, 'Protocol': `${IP_PROTO_NAMES[proto] || proto} (${proto})`, 'Total length': total, 'Flags': (df ? 'DF ' : '') + (mf ? 'MF' : '') || 'none', 'Fragment offset': fragOff } });
      p.ipProto = proto;
      const end = Math.min(d.length, o + (total || d.length - o));
      if (fragOff > 0) { p.proto = 'IPv4'; p.family = 'Other'; p.info = `Fragmented IP protocol (proto=${proto}, off=${fragOff * 8}, ID=0x${id.toString(16)})`; return; }
      return decodeTransport(p, d, proto, o + ihl, end);
    }
    if (kind === 'ipv6') {
      if (d.length < o + 40) return;
      let next = d[o + 6]; const plen = u16(d, o + 4), hlim = d[o + 7];
      p.src = ipv6(d, o + 8); p.dst = ipv6(d, o + 24);
      p.layers.push({ name: 'Internet Protocol Version 6', fields: { 'Source': p.src, 'Destination': p.dst, 'Next header': `${IP_PROTO_NAMES[next] || next} (${next})`, 'Hop limit': hlim, 'Payload length': plen } });
      let end = Math.min(d.length, o + 40 + plen); o += 40;
      // walk extension headers
      for (let guard = 0; guard < 8; guard++) {
        if (next === 0 || next === 43 || next === 60) { if (d.length < o + 2) return; const nn = d[o]; o += (d[o + 1] + 1) * 8; next = nn; }
        else if (next === 44) { if (d.length < o + 8) return; const nn = d[o]; o += 8; next = nn; }
        else if (next === 51) { if (d.length < o + 2) return; const nn = d[o]; o += (d[o + 1] + 2) * 4; next = nn; }
        else break;
      }
      p.ipProto = next;
      return decodeTransport(p, d, next, o, end);
    }
  }

  function decodeArp(p, d, o) {
    if (d.length < o + 28) return;
    const op = u16(d, o + 6);
    const sha = mac(d, o + 8), spa = ipv4(d, o + 14), tha = mac(d, o + 18), tpa = ipv4(d, o + 24);
    p.proto = 'ARP'; p.family = 'ARP'; p.transport = 'ARP';
    p.src = spa; p.dst = tpa;
    if (op === 1) { p.info = `Who has ${tpa}? Tell ${spa}`; if (spa === tpa) p.info = `ARP announcement for ${spa}`; if (spa === '0.0.0.0') p.info = `ARP probe for ${tpa}`; }
    else if (op === 2) { p.info = `${spa} is at ${sha}`; }
    else p.info = `ARP opcode ${op}`;
    if (op === 1 && p.dstMac === 'ff:ff:ff:ff:ff:ff') p.broadcast = true;
    p.control = true;
    p.layers.push({ name: 'Address Resolution Protocol', fields: { 'Opcode': op === 1 ? 'request (1)' : op === 2 ? 'reply (2)' : op, 'Sender MAC': sha, 'Sender IP': spa, 'Target MAC': tha, 'Target IP': tpa } });
  }

  function decodeTransport(p, d, proto, o, end) {
    if (proto === 6) return decodeTcp(p, d, o, end);
    if (proto === 17) return decodeUdp(p, d, o, end);
    if (proto === 1) return decodeIcmp(p, d, o, end);
    if (proto === 58) return decodeIcmp6(p, d, o, end);
    p.transport = IP_PROTO_NAMES[proto] || ('IP proto ' + proto);
    p.proto = p.transport; p.family = 'Other';
    p.payloadLen = Math.max(0, end - o);
    p.info = `${p.transport} (${p.payloadLen} bytes)`;
    if (proto === 2) { p.proto = 'IGMP'; const t = d[o]; p.info = ({ 0x11: 'Membership query', 0x16: 'Membership report v2', 0x17: 'Leave group', 0x22: 'Membership report v3' })[t] || ('IGMP type 0x' + t.toString(16)); p.control = true; }
    if (proto === 41) { // 6in4
      p.info = 'IPv6 in IPv4 tunnel';
    }
  }

  function decodeTcp(p, d, o, end) {
    if (d.length < o + 20) return;
    const sp = u16(d, o), dp = u16(d, o + 2), seq = u32(d, o + 4), ack = u32(d, o + 8);
    const doff = (d[o + 12] >> 4) * 4, fl = d[o + 13], win = u16(d, o + 14);
    const flags = TCP_FLAG_NAMES.filter(([, b]) => fl & b).map(([n]) => n);
    p.transport = 'TCP'; p.proto = 'TCP'; p.family = 'TCP';
    p.srcPort = sp; p.dstPort = dp;
    const pStart = o + doff, pEnd = Math.max(pStart, end);
    p.payloadLen = Math.max(0, pEnd - pStart);
    p.tcp = { seq, ack, win, flags, flagBits: fl, hdrLen: doff };
    p.flags = flags;
    p.control = !!(fl & 0x07); // SYN, FIN or RST
    p.pureAck = (fl & 0x07) === 0 && p.payloadLen === 0 && !!(fl & 0x10);
    const fields = { 'Source port': sp, 'Destination port': dp, 'Sequence number': seq, 'Acknowledgment number': ack, 'Flags': flags.join(', ') || 'none', 'Window': win, 'Header length': doff, 'Payload length': p.payloadLen };
    // options (MSS, WS, SACK permitted)
    let oo = o + 20; const opts = [];
    while (oo < pStart && oo < d.length) {
      const k = d[oo]; if (k === 0) break; if (k === 1) { oo++; continue; }
      const l = d[oo + 1] || 2;
      if (k === 2 && l === 4) opts.push('MSS=' + u16(d, oo + 2));
      else if (k === 3 && l === 3) opts.push('WS=' + d[oo + 2]);
      else if (k === 4) opts.push('SACK_PERM');
      else if (k === 8) opts.push('TSval');
      else if (k === 5) opts.push('SACK');
      oo += l;
    }
    if (opts.length) fields['Options'] = opts.join(' ');
    p.layers.push({ name: 'Transmission Control Protocol', fields });
    p.info = `${sp} → ${dp} [${flags.join(', ')}]`; // seq/ack added relative later
    if (p.payloadLen > 0) decodeApp(p, d, pStart, pEnd, 'TCP');
  }

  function decodeUdp(p, d, o, end) {
    if (d.length < o + 8) return;
    const sp = u16(d, o), dp = u16(d, o + 2), len = u16(d, o + 4);
    p.transport = 'UDP'; p.proto = 'UDP'; p.family = 'UDP';
    p.srcPort = sp; p.dstPort = dp;
    const pStart = o + 8, pEnd = Math.min(d.length, len >= 8 ? o + len : end);
    p.payloadLen = Math.max(0, pEnd - pStart);
    p.layers.push({ name: 'User Datagram Protocol', fields: { 'Source port': sp, 'Destination port': dp, 'Length': len, 'Payload length': p.payloadLen } });
    p.info = `${sp} → ${dp} Len=${p.payloadLen}`;
    decodeApp(p, d, pStart, pEnd, 'UDP');
  }

  function decodeIcmp(p, d, o, end) {
    if (d.length < o + 4) return;
    const type = d[o], code = d[o + 1];
    p.transport = 'ICMP'; p.proto = 'ICMP'; p.family = 'ICMP'; p.control = true;
    let info = ICMP4_TYPES[type] || ('ICMP type ' + type);
    const fields = { 'Type': type, 'Code': code };
    if (type === 0 || type === 8) { const id = u16(d, o + 4), seq = u16(d, o + 6); info += ` id=0x${id.toString(16).padStart(4, '0')} seq=${seq}`; fields['Identifier'] = id; fields['Sequence'] = seq; }
    else if (type === 3) { info += ` (${ICMP4_UNREACH[code] || 'code ' + code})`; }
    if ((type === 3 || type === 11 || type === 5) && d.length >= o + 8 + 20) {
      const io = o + 8; const ip = d[io + 9]; const ihl = (d[io] & 0xf) * 4;
      let inner = `${IP_PROTO_NAMES[ip] || ip} ${ipv4(d, io + 12)} → ${ipv4(d, io + 16)}`;
      if ((ip === 6 || ip === 17) && d.length >= io + ihl + 4) inner += `:${u16(d, io + ihl + 2)}`;
      fields['Original datagram'] = inner;
      info += ` [${inner}]`;
    }
    p.layers.push({ name: 'Internet Control Message Protocol', fields });
    p.info = info; p.payloadLen = Math.max(0, end - o - 8);
  }

  function decodeIcmp6(p, d, o, end) {
    if (d.length < o + 4) return;
    const type = d[o], code = d[o + 1];
    p.transport = 'ICMPv6'; p.proto = 'ICMPv6'; p.family = 'ICMP'; p.control = true;
    let info = ICMP6_TYPES[type] || ('ICMPv6 type ' + type);
    const fields = { 'Type': type, 'Code': code };
    if (type === 128 || type === 129) { info += ` id=0x${u16(d, o + 4).toString(16)} seq=${u16(d, o + 6)}`; }
    if ((type === 135 || type === 136) && d.length >= o + 24) { const t = ipv6(d, o + 8); fields['Target'] = t; info += ` for ${t}`; }
    p.layers.push({ name: 'Internet Control Message Protocol v6', fields });
    p.info = info; p.payloadLen = Math.max(0, end - o - 4);
  }

  // ---------- application layer ----------
  function decodeApp(p, d, s, e, tp) {
    const n = e - s;
    if (n <= 0) return;
    const sp = p.srcPort, dp = p.dstPort;
    const port = (a) => sp === a || dp === a;
    if (tp === 'UDP') {
      if (port(53) || port(5353) || port(5355)) return decodeDns(p, d, s, e, port(5353) ? 'mDNS' : port(5355) ? 'LLMNR' : 'DNS');
      if (port(67) || port(68)) return decodeDhcp(p, d, s, e);
      if (port(123) && n >= 48) { const li = d[s] >> 6, vn = (d[s] >> 3) & 7, mode = d[s] & 7; p.proto = 'NTP'; p.family = 'Other'; p.appName = 'NTP'; p.info = `NTP v${vn} ${({ 1: 'symmetric active', 2: 'symmetric passive', 3: 'client', 4: 'server', 5: 'broadcast' })[mode] || 'mode ' + mode}`; p.layers.push({ name: 'Network Time Protocol', fields: { 'Version': vn, 'Mode': mode, 'Leap indicator': li } }); return; }
      if (port(443) || port(80) || (d[s] & 0x80 && n > 1200)) { if (decodeQuic(p, d, s, e)) return; }
      if (port(1900) && isPrintableStart(d, s, 10)) { p.proto = 'SSDP'; p.family = 'HTTP'; p.appName = 'SSDP'; p.info = firstLine(d, s, e); return; }
      if (port(137)) { p.proto = 'NBNS'; p.family = 'DNS'; p.appName = 'NBNS'; p.info = 'NetBIOS name service'; return; }
      if (port(514)) { p.proto = 'Syslog'; p.family = 'Other'; p.info = ascii(d, s, Math.min(n, 80)); return; }
      if (port(4789) && n >= 8) { p.proto = 'VXLAN'; p.family = 'Other'; p.info = 'VXLAN VNI ' + (u32(d, s + 4) >>> 8); return; }
      p.mergeKey = 'udp';
      return;
    }
    // TCP
    if (n >= 3 && d[s] >= 20 && d[s] <= 23 && d[s + 1] === 3 && d[s + 2] <= 4) return decodeTls(p, d, s, e);
    if (n >= 4) {
      const head = ascii(d, s, Math.min(n, 12));
      if (HTTP_METHODS.some(m => head.startsWith(m))) return decodeHttp(p, d, s, e, 'request');
      if (head.startsWith('HTTP/1.') || head.startsWith('HTTP/0.')) return decodeHttp(p, d, s, e, 'response');
      if (head.startsWith('SSH-')) { p.proto = 'SSH'; p.family = 'Other'; p.appName = 'SSH'; p.info = 'Protocol: ' + firstLine(d, s, e); p.layers.push({ name: 'SSH', fields: { 'Banner': firstLine(d, s, e) } }); return; }
      if (head.startsWith('PRI * HTTP/2')) { p.proto = 'HTTP2'; p.family = 'HTTP'; p.appName = 'HTTP/2'; p.info = 'HTTP/2 connection preface'; return; }
    }
    if (port(22)) { p.proto = 'SSH'; p.family = 'Other'; p.appName = 'SSH'; p.info = `Encrypted packet (${n} bytes)`; p.mergeKey = 'ssh'; return; }
    if (port(53)) return decodeDns(p, d, s + 2, e, 'DNS');
    if (port(80) || port(8080)) { p.proto = 'HTTP'; p.family = 'HTTP'; p.info = `Continuation (${n} bytes)`; p.mergeKey = 'cont'; p.continuation = true; return; }
    if (port(443)) { p.proto = 'TLS'; p.family = 'TLS'; p.info = `Continuation data (${n} bytes)`; p.mergeKey = 'cont'; p.continuation = true; return; }
    // unknown TCP payload
    p.mergeKey = 'cont'; p.continuation = true;
    p.info = `${sp} → ${dp} [${p.flags.join(', ')}] data (${n} bytes)`;
    if (isPrintableStart(d, s, Math.min(n, 24))) p.layers.push({ name: 'Data', fields: { 'Text': ascii(d, s, Math.min(n, 120)) } });
  }

  function firstLine(d, s, e) { let t = ''; for (let i = s; i < e && i < s + 200; i++) { if (d[i] === 13 || d[i] === 10) break; t += String.fromCharCode(d[i]); } return t; }

  function decodeHttp(p, d, s, e, kind) {
    const text = ascii(d, s, Math.min(e - s, 4096));
    const lines = text.split(/\r?\n/);
    const first = lines[0];
    const headers = {};
    for (let i = 1; i < lines.length; i++) { const l = lines[i]; if (!l) break; const k = l.indexOf(':'); if (k > 0) headers[l.slice(0, k).trim()] = l.slice(k + 1).trim(); }
    p.proto = 'HTTP'; p.family = 'HTTP'; p.appName = 'HTTP';
    if (kind === 'request') {
      const parts = first.split(' ');
      p.info = `${parts[0]} ${parts[1] || ''}`.trim();
      if (headers.Host) { p.info += ` (Host: ${headers.Host})`; p.flowName = headers.Host; }
      p.mergeKey = 'http-req';
    } else {
      p.info = first;
      if (headers['Content-Type']) p.info += ` (${headers['Content-Type'].split(';')[0]})`;
      if (headers['Content-Length']) p.info += `, ${headers['Content-Length']} bytes`;
      p.mergeKey = 'http-resp';
    }
    const fields = { [kind === 'request' ? 'Request line' : 'Status line']: first };
    for (const k of Object.keys(headers).slice(0, 20)) fields[k] = headers[k];
    p.layers.push({ name: 'Hypertext Transfer Protocol', fields });
  }

  function dnsName(d, o, end, depth) {
    depth = depth || 0;
    const labels = []; let jumped = false, next = o;
    for (let guard = 0; guard < 64 && o < end; guard++) {
      const l = d[o];
      if (l === 0) { if (!jumped) next = o + 1; break; }
      if ((l & 0xc0) === 0xc0) { if (!jumped) next = o + 2; if (depth > 5) break; o = ((l & 0x3f) << 8) | d[o + 1]; jumped = true; depth++; continue; }
      labels.push(ascii(d, o + 1, l)); o += l + 1;
    }
    return { name: labels.join('.') || '<root>', next };
  }

  function decodeDns(p, d, s, e, name) {
    if (e - s < 12) return;
    const id = u16(d, s), fl = u16(d, s + 2), qd = u16(d, s + 4), an = u16(d, s + 6);
    const qr = fl & 0x8000, rcode = fl & 0xf, opcode = (fl >> 11) & 0xf;
    p.proto = name; p.family = 'DNS'; p.appName = name;
    let o = s + 12; const qs = []; const ans = [];
    for (let i = 0; i < qd && o < e; i++) { const r = dnsName(d, o, e); o = r.next; const t = u16(d, o); o += 4; qs.push(`${DNS_TYPES[t] || 'TYPE' + t} ${r.name}`); if (i === 0) p.flowName = r.name; }
    if (qr) for (let i = 0; i < an && o + 10 <= e; i++) {
      const r = dnsName(d, o, e); o = r.next; const t = u16(d, o), rdl = u16(d, o + 8); const ro = o + 10; o = ro + rdl;
      if (t === 1 && rdl === 4) ans.push('A ' + ipv4(d, ro)); else if (t === 28 && rdl === 16) ans.push('AAAA ' + ipv6(d, ro)); else if (t === 5 || t === 12 || t === 2) ans.push(`${DNS_TYPES[t]} ${dnsName(d, ro, e).name}`); else ans.push(DNS_TYPES[t] || 'TYPE' + t);
    }
    const kind = opcode === 0 ? 'Standard query' : opcode === 2 ? 'Status request' : opcode === 5 ? 'Dynamic update' : 'Query op ' + opcode;
    const rc = rcode ? ({ 1: 'Format error', 2: 'Server failure', 3: 'No such name', 5: 'Refused' })[rcode] || 'rcode ' + rcode : '';
    p.info = `${kind}${qr ? ' response' : ''} 0x${id.toString(16).padStart(4, '0')} ${qs.join(', ')}${ans.length ? ' ' + ans.slice(0, 4).join(', ') + (ans.length > 4 ? ` (+${ans.length - 4})` : '') : ''}${rc ? ' ' + rc : ''}`;
    p.layers.push({ name: 'Domain Name System', fields: { 'Transaction ID': '0x' + id.toString(16), 'Kind': qr ? 'response' : 'query', 'Questions': qs.join('; ') || '-', 'Answers': ans.join('; ') || '-', 'Response code': rcode } });
  }

  function decodeDhcp(p, d, s, e) {
    if (e - s < 240 || u32(d, s + 236) !== 0x63825363) { p.proto = 'DHCP'; p.family = 'Other'; p.info = 'BOOTP'; return; }
    p.proto = 'DHCP'; p.family = 'Other'; p.appName = 'DHCP'; p.control = true;
    const xid = u32(d, s + 4); let o = s + 240, mt = 0, reqIp = null, srvId = null, host = null;
    while (o + 1 < e) { const k = d[o]; if (k === 255) break; if (k === 0) { o++; continue; } const l = d[o + 1]; if (k === 53) mt = d[o + 2]; if (k === 50) reqIp = ipv4(d, o + 2); if (k === 54) srvId = ipv4(d, o + 2); if (k === 12) host = ascii(d, o + 2, l); o += 2 + l; }
    const yiaddr = ipv4(d, s + 16);
    p.info = `DHCP ${DHCP_MSG[mt] || 'message ' + mt} - Transaction ID 0x${xid.toString(16)}`;
    if (mt === 2 || mt === 5) p.info += ` (${yiaddr})`;
    if (mt === 3 && reqIp) p.info += ` (requests ${reqIp})`;
    p.layers.push({ name: 'Dynamic Host Configuration Protocol', fields: { 'Message type': DHCP_MSG[mt] || mt, 'Transaction ID': '0x' + xid.toString(16), 'Your IP': yiaddr, 'Client MAC': mac(d, s + 28), 'Requested IP': reqIp || '-', 'Server identifier': srvId || '-', 'Host name': host || '-' } });
  }

  function decodeQuic(p, d, s, e) {
    const b = d[s]; const n = e - s;
    if (n < 5) return false;
    if (b & 0x80) {
      const ver = u32(d, s + 1);
      if (ver !== 1 && ver !== 0x6b3343cf && (ver & 0xffff0000) !== 0xff000000 && ver !== 0) return false;
      const t = (b >> 4) & 3;
      const type = ver === 0 ? 'Version Negotiation' : (ver === 0x6b3343cf ? ['Retry', 'Initial', '0-RTT', 'Handshake'] : ['Initial', '0-RTT', 'Handshake', 'Retry'])[t];
      p.proto = 'QUIC'; p.family = 'TLS'; p.appName = 'QUIC';
      p.info = `QUIC ${type}${ver === 1 ? '' : ' v0x' + ver.toString(16)} (${n} bytes)`;
      p.control = type === 'Initial' || type === 'Handshake';
      p.layers.push({ name: 'QUIC', fields: { 'Header form': 'long', 'Packet type': type, 'Version': '0x' + ver.toString(16) } });
      if (type === '0-RTT') p.mergeKey = 'quic';
      return true;
    }
    if (p.srcPort === 443 || p.dstPort === 443) { p.proto = 'QUIC'; p.family = 'TLS'; p.appName = 'QUIC'; p.info = `QUIC protected payload (${n} bytes)`; p.mergeKey = 'quic'; p.layers.push({ name: 'QUIC', fields: { 'Header form': 'short' } }); return true; }
    return false;
  }

  function decodeTls(p, d, s, e) {
    p.proto = 'TLS'; p.family = 'TLS'; p.appName = 'TLS';
    const recs = []; const fields = {}; let o = s, ver = null, hasCcs = false, hsVer = null;
    while (o + 5 <= e && recs.length < 32) {
      const ct = d[o], rv = u16(d, o + 1), len = u16(d, o + 3);
      if (ct < 20 || ct > 23 || d[o + 1] !== 3) break;
      ver = ver || rv;
      const ro = o + 5, rend = Math.min(e, ro + len);
      const rec = { ct, len, hs: [], afterCcs: hasCcs, truncated: rend < ro + len };
      if (ct === 22) {
        let ho = ro;
        while (ho + 4 <= rend) {
          const ht = d[ho], hl = (d[ho + 1] << 16) | u16(d, ho + 2);
          if (!TLS_HS[ht] || hl > 65536 || (ht === 0 && hl !== 0)) break;
          let label = TLS_HS[ht];
          const bodyEnd = Math.min(rend, ho + 4 + hl);
          if (ht === 1 || ht === 2) {
            const hello = parseHello(d, ho + 4, bodyEnd, ht === 1);
            if (hello.ver) hsVer = Math.max(hsVer || 0, hello.ver);
            if (hello.sni) { label += ` (SNI=${hello.sni})`; p.flowName = hello.sni; fields['Server name'] = hello.sni; }
            if (hello.alpn) fields['ALPN'] = hello.alpn;
            if (hello.cipher) fields['Cipher suite'] = hello.cipher;
            if (ht === 2) rec.serverHello = true;
            if (ht === 1) rec.clientHello = true;
          }
          rec.hs.push(label); ho = ho + 4 + hl;
        }
        // a run of zero-length "Hello Request"s is ciphertext that happens to start with zeros
        if (rec.hs.length > 2 && rec.hs.every(x => x === 'Hello Request')) rec.hs = [];
      } else if (ct === 21) {
        rec.alert = len === 2 ? `Alert (${d[ro] === 1 ? 'warning' : 'fatal'}, ${({ 0: 'close_notify', 10: 'unexpected_message', 40: 'handshake_failure', 42: 'bad_certificate', 46: 'certificate_unknown', 48: 'unknown_ca', 70: 'protocol_version', 80: 'internal_error', 112: 'unrecognized_name' })[d[ro + 1]] || 'code ' + d[ro + 1]})` : 'Encrypted Alert';
      } else if (ct === 20) { hasCcs = true; }
      recs.push(rec);
      o = ro + len;
    }
    p.tlsRecs = recs; p.tlsRecordVer = ver; p.tlsHelloVer = hsVer; p.tlsCcs = hasCcs; p.tlsTrailing = o < e;
    p.tlsFields = fields;
    if (!recs.length) { p.info = `TLS record fragment (${e - s} bytes)`; p.mergeKey = 'cont'; p.continuation = true; p.layers.push({ name: 'Transport Layer Security', fields: { 'Note': 'record continues from a previous segment' } }); return; }
    buildTlsInfo(p, false, null);
  }

  // Builds the TLS summary. `encrypted` = the flow already saw Change Cipher Spec in this direction;
  // `flowVer` = negotiated version learned from the handshake earlier in the flow.
  function buildTlsInfo(p, encrypted, flowVer) {
    const parts = []; let appBytes = 0, appCount = 0; let control = false; let mergeKey = null;
    for (const rec of p.tlsRecs) {
      if (rec.ct === 22) {
        control = true; mergeKey = mergeKey || 'tls-hs';
        if ((encrypted || rec.afterCcs) || !rec.hs.length) parts.push('Encrypted Handshake Message');
        else parts.push(...rec.hs);
      } else if (rec.ct === 23) { appCount++; appBytes += rec.len; mergeKey = mergeKey || 'tls-app'; }
      else if (rec.ct === 21) { parts.push(rec.alert); control = true; }
      else if (rec.ct === 20) { parts.push('Change Cipher Spec'); control = true; mergeKey = mergeKey || 'tls-hs'; }
    }
    if (appCount) parts.push(appCount > 1 ? `Application Data ×${appCount} (${appBytes} bytes)` : `Application Data (${appBytes} bytes)`);
    if (p.tlsTrailing) parts.push('Continuation');
    const ver = p.tlsHelloVer || flowVer || p.tlsRecordVer;
    const vname = TLS_VER[ver] || 'TLS';
    p.info = `${vname} ${parts.join(', ')}`;
    p.control = control; p.mergeKey = mergeKey;
    const fields = Object.assign({ 'Version': vname, 'Records': p.tlsRecs.map(r => r.ct === 22 ? 'Handshake' : r.ct === 23 ? 'Application Data' : r.ct === 21 ? 'Alert' : 'Change Cipher Spec').join(', ') }, p.tlsFields);
    const idx = p.layers.findIndex(l => l.name === 'Transport Layer Security');
    const layer = { name: 'Transport Layer Security', fields };
    if (idx >= 0) p.layers[idx] = layer; else p.layers.push(layer);
  }

  function parseHello(d, o, end, isClient) {
    const out = { ver: null, sni: null, alpn: null, cipher: null };
    try {
      out.ver = u16(d, o); o += 2 + 32;
      const sidLen = d[o]; o += 1 + sidLen;
      if (isClient) { const csLen = u16(d, o); o += 2 + csLen; const cmLen = d[o]; o += 1 + cmLen; }
      else { out.cipher = '0x' + u16(d, o).toString(16).padStart(4, '0'); o += 3; }
      if (o + 2 > end) return out;
      const extLen = u16(d, o); o += 2; const extEnd = Math.min(end, o + extLen);
      while (o + 4 <= extEnd) {
        const et = u16(d, o), el = u16(d, o + 2); const eo = o + 4;
        if (et === 0 && isClient && el >= 5) { const nl = u16(d, eo + 3); out.sni = ascii(d, eo + 5, nl); }
        if (et === 16 && el >= 3) { const names = []; let a = eo + 2; while (a < eo + el) { const l = d[a]; names.push(ascii(d, a + 1, l)); a += 1 + l; } out.alpn = names.join(', '); }
        if (et === 43) { if (isClient) { let a = eo + 1; while (a + 1 < eo + el) { if (u16(d, a) === 0x0304) out.ver = 0x0304; a += 2; } } else { out.ver = u16(d, eo); } }
        o = eo + el;
      }
    } catch (e) { /* truncated */ }
    return out;
  }

  // ---------- flow tracking & relative sequence numbers ----------
  function flowKeyFor(p) {
    const a = `${p.src}${p.srcPort != null ? ':' + p.srcPort : ''}`;
    const b = `${p.dst}${p.dstPort != null ? ':' + p.dstPort : ''}`;
    const tp = p.transport || p.proto;
    if (a <= b) return { key: `${tp}|${a}|${b}`, dir: 'A' };
    return { key: `${tp}|${b}|${a}`, dir: 'B' };
  }

  function decodeAll(frames, flows) {
    const packets = [];
    flows = flows || new Map();
    const t0 = frames.length ? frames[0].ts : 0;
    for (let i = 0; i < frames.length; i++) {
      const p = decodeFrame(frames[i], i);
      p.id = i + 1;
      finishPacket(p, flows);
      packets.push(p);
    }
    return packets;
  }

  // Called for decoded and for manually-authored packets alike.
  function finishPacket(p, flows) {
    const fk = flowKeyFor(p);
    p.flowKey = fk.key; p.dir = fk.dir;
    let f = flows.get(fk.key);
    if (!f) { f = { key: fk.key, first: p.id, initiator: p.src, responder: p.dst, isn: {}, app: null, name: null, lastApp: {} }; flows.set(fk.key, f); }
    if (p.appName && !f.app) f.app = p.appName;
    if (p.tlsRecs) {
      f.tlsCcs = f.tlsCcs || {};
      buildTlsInfo(p, !!f.tlsCcs[p.dir], f.tlsVer || null);
      if (p.tlsHelloVer && (!f.tlsVer || p.tlsRecs.some(r => r.serverHello))) f.tlsVer = p.tlsHelloVer;
      if (p.tlsCcs) f.tlsCcs[p.dir] = true;
    }
    if (p.flowName && !f.name) f.name = p.flowName;
    if (p.tcp) {
      const isn = f.isn;
      if (p.tcp.flags.includes('SYN') || isn[p.dir] === undefined) isn[p.dir] = p.tcp.seq;
      const od = p.dir === 'A' ? 'B' : 'A';
      if (p.tcp.flags.includes('ACK') && isn[od] === undefined) isn[od] = p.tcp.ack - 1;
      p.tcp.relSeq = (p.tcp.seq - isn[p.dir]) >>> 0;
      p.tcp.relAck = p.tcp.flags.includes('ACK') && isn[od] !== undefined ? (p.tcp.ack - isn[od]) >>> 0 : null;
      if (p.proto === 'TCP') {
        p.info = `${p.srcPort} → ${p.dstPort} [${p.tcp.flags.join(', ')}] Seq=${p.tcp.relSeq}${p.tcp.relAck != null ? ' Ack=' + p.tcp.relAck : ''} Win=${p.tcp.win} Len=${p.payloadLen}`;
      }
      // continuation packets inherit the flow's application protocol
      if (p.continuation && f.lastApp[p.dir]) { p.proto = f.lastApp[p.dir].proto; p.family = f.lastApp[p.dir].family; }
      if (p.appName && !p.continuation) f.lastApp[p.dir] = { proto: p.proto, family: p.family };
      else if (p.continuation && f.app && !f.lastApp[p.dir]) { /* leave as TCP */ }
    }
    p.flow = f;
    p.summary = p.info;
  }

  window.Pcap = { parse, decodeAll, finishPacket, flowKeyFor, helpers: { ipv4, ipv6, mac } };
})();
