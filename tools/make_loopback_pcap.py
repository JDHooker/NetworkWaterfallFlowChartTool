#!/usr/bin/env python3
"""Generate samples/loopback.pcap: traffic from 127.0.0.1 to itself on different ports
(a local HTTP exchange over the loopback interface, DLT_NULL framing as on macOS)."""
import struct, os, sys
IP = bytes([127, 0, 0, 1])
def csum(b):
    if len(b) % 2: b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b)); s = (s >> 16) + (s & 0xffff); s += s >> 16
    return (~s) & 0xffff
def ipv4(src, dst, proto, payload, ident=1):
    hdr = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), ident, 0x4000, 64, proto, 0, src, dst)
    return hdr[:10] + struct.pack('!H', csum(hdr)) + hdr[12:] + payload
def tcp(sp, dp, seq, ack, flags, payload=b''):
    return struct.pack('!HHIIBBHHH', sp, dp, seq, ack, 5 << 4, flags, 65535, 0, 0) + payload
def frame(payload): return struct.pack('<I', 2) + payload   # DLT_NULL: AF_INET = 2
pk = []; t = 1_700_000_100.0
def add(dt, sp, dp, seq, ack, fl, pl=b''): global t; t += dt; pk.append((t, frame(ipv4(IP, IP, 6, tcp(sp, dp, seq, ack, fl, pl)))))
c, s = 52000, 8080; cs, ss = 100, 900
add(0, c, s, cs, 0, 0x02); add(0.0001, s, c, ss, cs + 1, 0x12); add(0.00005, c, s, cs + 1, ss + 1, 0x10)
req = b'GET /api/status HTTP/1.1\r\nHost: localhost:8080\r\nAccept: application/json\r\n\r\n'
add(0.0003, c, s, cs + 1, ss + 1, 0x18, req)
body = b'{"status":"ok","uptime":4212}'
resp = b'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n' % len(body) + body
add(0.0021, s, c, ss + 1, cs + 1 + len(req), 0x18, resp)
add(0.00004, c, s, cs + 1 + len(req), ss + 1 + len(resp), 0x10)
add(0.0400, c, s, cs + 1 + len(req), ss + 1 + len(resp), 0x11); add(0.0001, s, c, ss + 1 + len(resp), cs + 2 + len(req), 0x11); add(0.00003, c, s, cs + 2 + len(req), ss + 2 + len(resp), 0x10)
# a second client port talking to the same server
c2 = 52001; cs2, ss2 = 300, 1200
add(0.5, c2, s, cs2, 0, 0x02); add(0.0001, s, c2, ss2, cs2 + 1, 0x12); add(0.00005, c2, s, cs2 + 1, ss2 + 1, 0x10)
req2 = b'POST /api/jobs HTTP/1.1\r\nHost: localhost:8080\r\nContent-Length: 2\r\n\r\n{}'
add(0.0002, c2, s, cs2 + 1, ss2 + 1, 0x18, req2)
resp2 = b'HTTP/1.1 202 Accepted\r\nContent-Length: 0\r\n\r\n'
add(0.0050, s, c2, ss2 + 1, cs2 + 1 + len(req2), 0x18, resp2)
add(0.00004, c2, s, cs2 + 1 + len(req2), ss2 + 1 + len(resp2), 0x10)
out = sys.argv[1] if len(sys.argv) > 1 else os.path.join(os.path.dirname(__file__), '..', 'samples', 'loopback.pcap')
with open(out, 'wb') as f:
    f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, 0))
    for ts, fr in pk:
        sec = int(ts); usec = int(round((ts - sec) * 1e6)); f.write(struct.pack('<IIII', sec, usec, len(fr), len(fr)) + fr)
print(f'wrote {len(pk)} packets to {out}')
