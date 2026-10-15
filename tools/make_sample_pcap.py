#!/usr/bin/env python3
"""Generate a small synthetic capture (samples/sample.pcap) for trying the tool.
No third-party packages needed. The capture contains ARP, DNS, a TCP handshake,
a TLS 1.3 handshake with SNI, application data, an HTTP exchange, ICMP pings and a teardown."""
import struct, os, sys

MAC_A = bytes.fromhex('3c22fb1a2b3c'); MAC_GW = bytes.fromhex('a4915b00ff01'); MAC_B = MAC_GW
IP_A = bytes([10, 0, 0, 5]); IP_GW = bytes([10, 0, 0, 1]); IP_DNS = bytes([1, 1, 1, 1]); IP_WEB = bytes([93, 184, 216, 34])

def csum(b):
    if len(b) % 2: b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b)); s = (s >> 16) + (s & 0xffff); s += s >> 16
    return (~s) & 0xffff

def eth(dst, src, t, payload): return dst + src + struct.pack('!H', t) + payload
def ipv4(src, dst, proto, payload, ident=0x1234, ttl=64):
    hdr = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), ident, 0x4000, ttl, proto, 0, src, dst)
    hdr = hdr[:10] + struct.pack('!H', csum(hdr)) + hdr[12:]
    return hdr + payload
def tcp(sp, dp, seq, ack, flags, payload=b'', win=65535, opts=b''):
    doff = (20 + len(opts)) // 4
    return struct.pack('!HHIIBBHHH', sp, dp, seq, ack, doff << 4, flags, win, 0, 0) + opts + payload
def udp(sp, dp, payload): return struct.pack('!HHHH', sp, dp, 8 + len(payload), 0) + payload
def icmp(t, code, ident, seq, payload=b'x' * 56):
    h = struct.pack('!BBHHH', t, code, 0, ident, seq) + payload
    return h[:2] + struct.pack('!H', csum(h)) + h[4:]
def arp(op, sha, spa, tha, tpa): return struct.pack('!HHBBH', 1, 0x0800, 6, 4, op) + sha + spa + tha + tpa

def dns_name(n): return b''.join(bytes([len(l)]) + l.encode() for l in n.split('.')) + b'\0'
def dns_query(xid, name, qtype=1): return struct.pack('!HHHHHH', xid, 0x0100, 1, 0, 0, 0) + dns_name(name) + struct.pack('!HH', qtype, 1)
def dns_response(xid, name, ip):
    q = dns_name(name) + struct.pack('!HH', 1, 1)
    ans = b'\xc0\x0c' + struct.pack('!HHIH', 1, 1, 300, 4) + ip
    return struct.pack('!HHHHHH', xid, 0x8180, 1, 1, 0, 0) + q + ans

def tls_record(ct, body, ver=0x0303): return struct.pack('!BHH', ct, ver, len(body)) + body
def handshake(ht, body): return bytes([ht]) + len(body).to_bytes(3, 'big') + body
def client_hello(sni):
    rnd = bytes(range(32)); sid = b'\x20' + bytes(range(32, 64))
    ciphers = struct.pack('!H', 6) + bytes.fromhex('130113021303'); comp = b'\x01\x00'
    sni_ext = struct.pack('!HH', 0, len(sni) + 5) + struct.pack('!HBH', len(sni) + 3, 0, len(sni)) + sni.encode()
    alpn = b'\x02h2\x08http/1.1'; alpn_ext = struct.pack('!HH', 16, len(alpn) + 2) + struct.pack('!H', len(alpn)) + alpn
    sv = struct.pack('!HHB', 43, 5, 4) + bytes.fromhex('03040303')
    exts = sni_ext + alpn_ext + sv
    body = b'\x03\x03' + rnd + sid + ciphers + comp + struct.pack('!H', len(exts)) + exts
    return tls_record(22, handshake(1, body), 0x0301)
def server_hello():
    body = b'\x03\x03' + bytes(range(32)) + b'\x20' + bytes(range(32, 64)) + b'\x13\x01' + b'\x00' + struct.pack('!H', 6) + struct.pack('!HHH', 43, 2, 0x0304)
    return tls_record(22, handshake(2, body)) + tls_record(20, b'\x01') + tls_record(23, bytes(900))
def app_data(n): return tls_record(23, bytes(n))

packets = []  # (time, bytes)
def add(t, frame): packets.append((t, frame))

t = 1_700_000_000.000000
# ARP
add(t, eth(b'\xff' * 6, MAC_A, 0x0806, arp(1, MAC_A, IP_A, b'\0' * 6, IP_GW)))
add(t + 0.0004, eth(MAC_A, MAC_GW, 0x0806, arp(2, MAC_GW, IP_GW, MAC_A, IP_A)))
# DNS
add(t + 0.0100, eth(MAC_GW, MAC_A, 0x0800, ipv4(IP_A, IP_DNS, 17, udp(51000, 53, dns_query(0x1a2b, 'example.com')))))
add(t + 0.0312, eth(MAC_A, MAC_GW, 0x0800, ipv4(IP_DNS, IP_A, 17, udp(53, 51000, dns_response(0x1a2b, 'example.com', IP_WEB)))))
# TCP handshake
sp, dp = 52344, 443; cs, ss = 1000, 5000
mss = b'\x02\x04\x05\xb4'
add(t + 0.0320, eth(MAC_GW, MAC_A, 0x0800, ipv4(IP_A, IP_WEB, 6, tcp(sp, dp, cs, 0, 0x02, opts=mss))))
add(t + 0.0520, eth(MAC_A, MAC_GW, 0x0800, ipv4(IP_WEB, IP_A, 6, tcp(dp, sp, ss, cs + 1, 0x12, opts=mss))))
add(t + 0.0521, eth(MAC_GW, MAC_A, 0x0800, ipv4(IP_A, IP_WEB, 6, tcp(sp, dp, cs + 1, ss + 1, 0x10))))
# TLS
ch = client_hello('example.com')
add(t + 0.0530, eth(MAC_GW, MAC_A, 0x0800, ipv4(IP_A, IP_WEB, 6, tcp(sp, dp, cs + 1, ss + 1, 0x18, ch))))
sh = server_hello()
add(t + 0.0740, eth(MAC_A, MAC_GW, 0x0800, ipv4(IP_WEB, IP_A, 6, tcp(dp, sp, ss + 1, cs + 1 + len(ch), 0x18, sh))))
add(t + 0.0741, eth(MAC_GW, MAC_A, 0x0800, ipv4(IP_A, IP_WEB, 6, tcp(sp, dp, cs + 1 + len(ch), ss + 1 + len(sh), 0x10))))
fin = tls_record(20, b'\x01') + tls_record(22, bytes(52))
add(t + 0.0750, eth(MAC_GW, MAC_A, 0x0800, ipv4(IP_A, IP_WEB, 6, tcp(sp, dp, cs + 1 + len(ch), ss + 1 + len(sh), 0x18, fin))))
c_seq = cs + 1 + len(ch) + len(fin); s_seq = ss + 1 + len(sh)
req = app_data(517)
add(t + 0.0760, eth(MAC_GW, MAC_A, 0x0800, ipv4(IP_A, IP_WEB, 6, tcp(sp, dp, c_seq, s_seq, 0x18, req))))
c_seq += len(req)
tt = t + 0.1200
for i in range(5):
    seg = app_data(1400)
    add(tt + i * 0.0008, eth(MAC_A, MAC_GW, 0x0800, ipv4(IP_WEB, IP_A, 6, tcp(dp, sp, s_seq, c_seq, 0x18 if i == 4 else 0x10, seg))))
    s_seq += len(seg)
add(tt + 0.0050, eth(MAC_GW, MAC_A, 0x0800, ipv4(IP_A, IP_WEB, 6, tcp(sp, dp, c_seq, s_seq, 0x10))))
# plain HTTP to another host on port 80
hp, hs_ = 52345, 80; hc, hsv = 7000, 9000
add(t + 0.5000, eth(MAC_GW, MAC_A, 0x0800, ipv4(IP_A, IP_GW, 6, tcp(hp, hs_, hc, 0, 0x02, opts=mss))))
add(t + 0.5010, eth(MAC_A, MAC_GW, 0x0800, ipv4(IP_GW, IP_A, 6, tcp(hs_, hp, hsv, hc + 1, 0x12, opts=mss))))
add(t + 0.5011, eth(MAC_GW, MAC_A, 0x0800, ipv4(IP_A, IP_GW, 6, tcp(hp, hs_, hc + 1, hsv + 1, 0x10))))
get = b'GET /index.html HTTP/1.1\r\nHost: router.local\r\nUser-Agent: curl/8.4\r\nAccept: */*\r\n\r\n'
add(t + 0.5020, eth(MAC_GW, MAC_A, 0x0800, ipv4(IP_A, IP_GW, 6, tcp(hp, hs_, hc + 1, hsv + 1, 0x18, get))))
body = b'<html><body>hello</body></html>'
resp = b'HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: %d\r\n\r\n' % len(body) + body
add(t + 0.5400, eth(MAC_A, MAC_GW, 0x0800, ipv4(IP_GW, IP_A, 6, tcp(hs_, hp, hsv + 1, hc + 1 + len(get), 0x18, resp))))
add(t + 0.5401, eth(MAC_GW, MAC_A, 0x0800, ipv4(IP_A, IP_GW, 6, tcp(hp, hs_, hc + 1 + len(get), hsv + 1 + len(resp), 0x10))))
# ICMP pings after a pause
for i in range(3):
    add(t + 3.0 + i, eth(MAC_GW, MAC_A, 0x0800, ipv4(IP_A, IP_WEB, 1, icmp(8, 0, 0x1234, i + 1))))
    add(t + 3.0 + i + 0.0187, eth(MAC_A, MAC_GW, 0x0800, ipv4(IP_WEB, IP_A, 1, icmp(0, 0, 0x1234, i + 1))))
# teardown of TLS connection
add(t + 6.0, eth(MAC_GW, MAC_A, 0x0800, ipv4(IP_A, IP_WEB, 6, tcp(sp, dp, c_seq, s_seq, 0x11))))
add(t + 6.0201, eth(MAC_A, MAC_GW, 0x0800, ipv4(IP_WEB, IP_A, 6, tcp(dp, sp, s_seq, c_seq + 1, 0x11))))
add(t + 6.0202, eth(MAC_GW, MAC_A, 0x0800, ipv4(IP_A, IP_WEB, 6, tcp(sp, dp, c_seq + 1, s_seq + 1, 0x10))))

out = sys.argv[1] if len(sys.argv) > 1 else os.path.join(os.path.dirname(__file__), '..', 'samples', 'sample.pcap')
with open(out, 'wb') as f:
    f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, 1))
    for ts, frame in packets:
        sec = int(ts); usec = int(round((ts - sec) * 1e6))
        f.write(struct.pack('<IIII', sec, usec, len(frame), len(frame)) + frame)
print(f'wrote {len(packets)} packets to {out}')
