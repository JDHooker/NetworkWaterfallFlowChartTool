#!/usr/bin/env python3
"""Generate two synthetic captures for trying the Compare view (compare.html):

  samples/compare-direct.pcap    client fetches https://www.youtube.com/ directly
  samples/compare-tunneled.pcap  the same fetch carried through a TLS proxy
                                 (outer TLS to proxy.example.net, framing overhead + padding)

Only packet sizes, directions and plaintext headers are meaningful; record contents are filler.
No third-party packages needed."""
import os, random, struct

random.seed(7)
MAC_C = bytes.fromhex('3c22fb1a2b3c'); MAC_GW = bytes.fromhex('a4915b00ff01')
IP_C = bytes([192, 168, 1, 20]); IP_DNS = bytes([192, 168, 1, 1])
IP_YT = bytes([142, 250, 72, 14]); IP_PROXY = bytes([203, 0, 113, 50])
MSS = 1448


def csum(b):
    if len(b) % 2: b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b)); s = (s >> 16) + (s & 0xffff); s += s >> 16
    return (~s) & 0xffff

def eth(dst, src, payload): return dst + src + struct.pack('!H', 0x0800) + payload
def ipv4(src, dst, proto, payload, ttl=64):
    hdr = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), random.randint(1, 65535), 0x4000, ttl, proto, 0, src, dst)
    return hdr[:10] + struct.pack('!H', csum(hdr)) + hdr[12:] + payload
def tcp(sp, dp, seq, ack, flags, payload=b'', opts=b''):
    return struct.pack('!HHIIBBHHH', sp, dp, seq, ack, ((20 + len(opts)) // 4) << 4, flags, 65535, 0, 0) + opts + payload
def udp(sp, dp, payload): return struct.pack('!HHHH', sp, dp, 8 + len(payload), 0) + payload

def dns_name(n): return b''.join(bytes([len(l)]) + l.encode() for l in n.split('.')) + b'\0'
def dns_query(xid, name): return struct.pack('!HHHHHH', xid, 0x0100, 1, 0, 0, 0) + dns_name(name) + struct.pack('!HH', 1, 1)
def dns_response(xid, name, ip):
    return struct.pack('!HHHHHH', xid, 0x8180, 1, 1, 0, 0) + dns_name(name) + struct.pack('!HH', 1, 1) + b'\xc0\x0c' + struct.pack('!HHIH', 1, 1, 300, 4) + ip

def rec(ct, body): return struct.pack('!BHH', ct, 0x0303, len(body)) + body
def hs(ht, body): return bytes([ht]) + len(body).to_bytes(3, 'big') + body
def filler(n): return bytes(random.getrandbits(8) for _ in range(n))
def app(n): return rec(23, filler(n))   # n = ciphertext length (plaintext + 17 for TLS 1.3 AEAD)

def client_hello(sni, total=517):
    sni_ext = struct.pack('!HH', 0, len(sni) + 5) + struct.pack('!HBH', len(sni) + 3, 0, len(sni)) + sni.encode()
    alpn = b'\x02h2\x08http/1.1'; alpn_ext = struct.pack('!HHH', 16, len(alpn) + 2, len(alpn)) + alpn
    sv = struct.pack('!HHB', 43, 5, 4) + bytes.fromhex('03040303')
    base = b'\x03\x03' + filler(32) + b'\x20' + filler(32) + struct.pack('!H', 6) + bytes.fromhex('130113021303') + b'\x01\x00'
    exts = sni_ext + alpn_ext + sv
    pad_len = total - 5 - 4 - len(base) - 2 - len(exts) - 4
    exts += struct.pack('!HH', 21, pad_len) + bytes(pad_len)
    return rec(22, hs(1, base + struct.pack('!H', len(exts)) + exts))

def server_flight(cert_bytes):
    body = b'\x03\x03' + filler(32) + b'\x20' + filler(32) + b'\x13\x01\x00' + struct.pack('!H', 6) + struct.pack('!HHH', 43, 2, 0x0304)
    return rec(22, hs(2, body)) + rec(20, b'\x01') + app(cert_bytes)


class Capture:
    def __init__(self): self.frames = []; self.t = 1_760_000_000.0
    def wait(self, dt): self.t += dt
    def add(self, frame): self.frames.append((self.t, frame))
    def write(self, path):
        with open(path, 'wb') as f:
            f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
            for ts, fr in self.frames:
                sec = int(ts); usec = int(round((ts - sec) * 1e6))
                if usec >= 1000000: sec += 1; usec -= 1000000
                f.write(struct.pack('<IIII', sec, usec, len(fr), len(fr)) + fr)

    def dns(self, name, ip, rtt):
        xid = random.randint(1, 65535); sp = random.randint(50000, 60000)
        self.add(eth(MAC_GW, MAC_C, ipv4(IP_C, IP_DNS, 17, udp(sp, 53, dns_query(xid, name)))))
        self.wait(rtt)
        self.add(eth(MAC_C, MAC_GW, ipv4(IP_DNS, IP_C, 17, udp(53, sp, dns_response(xid, name, ip)))))


class Conn:
    """A TCP connection that segments writes at the MSS and ACKs like a real stack (roughly)."""
    def __init__(self, cap, server_ip, rtt):
        self.cap, self.sip, self.rtt = cap, server_ip, rtt
        self.sp, self.dp = random.randint(49152, 65000), 443
        self.cseq, self.sseq = random.getrandbits(32), random.getrandbits(32)
    def _pkt(self, from_client, flags, payload=b''):
        if from_client:
            self.cap.add(eth(MAC_GW, MAC_C, ipv4(IP_C, self.sip, 6, tcp(self.sp, self.dp, self.cseq, self.sseq, flags, payload))))
            self.cseq = (self.cseq + len(payload) + (1 if flags & 0x03 else 0)) & 0xffffffff
        else:
            self.cap.add(eth(MAC_C, MAC_GW, ipv4(self.sip, IP_C, 6, tcp(self.dp, self.sp, self.sseq, self.cseq, flags, payload), ttl=118)))
            self.sseq = (self.sseq + len(payload) + (1 if flags & 0x03 else 0)) & 0xffffffff
    def open(self):
        mss = struct.pack('!BBH', 2, 4, MSS)
        self.cap.add(eth(MAC_GW, MAC_C, ipv4(IP_C, self.sip, 6, tcp(self.sp, self.dp, self.cseq, 0, 0x02, opts=mss))))
        self.cseq = (self.cseq + 1) & 0xffffffff
        self.cap.wait(self.rtt)
        self.cap.add(eth(MAC_C, MAC_GW, ipv4(self.sip, IP_C, 6, tcp(self.dp, self.sp, self.sseq, self.cseq, 0x12, opts=mss), ttl=118)))
        self.sseq = (self.sseq + 1) & 0xffffffff
        self.cap.wait(0.0002); self._pkt(True, 0x10)
    def send(self, from_client, data, think=0.0003):
        self.cap.wait(think)
        for i in range(0, len(data), MSS):
            self._pkt(from_client, 0x18, data[i:i + MSS]); self.cap.wait(0.00005)
        self.cap.wait(self.rtt / 2 if not from_client else 0.0001)
        self._pkt(not from_client, 0x10)   # the receiver ACKs
    def close(self):
        self.cap.wait(0.002); self._pkt(True, 0x11)
        self.cap.wait(self.rtt); self._pkt(False, 0x11)
        self.cap.wait(0.0002); self._pkt(True, 0x10)


# The application exchange (TLS 1.3 + HTTP/2), as (from_client, ciphertext record sizes, think time).
FETCH = [
    (True,  [53 + 17],            0.0005),   # client CCS + Finished (Finished counted as app record)
    (True,  [24 + 27 + 13 + 17, 70 + 17], 0.0001),  # h2 preface + SETTINGS + WINDOW_UPDATE, HEADERS GET /
    (False, [40 + 17, 245 + 17, 245 + 17], 0.020),  # SETTINGS, two NewSessionTickets
    (True,  [9 + 17],             0.0002),   # SETTINGS ACK
    (False, [180 + 17, 1196 + 17], 0.045),   # HEADERS 301, DATA
    (True,  [17 + 17],            0.003),    # GOAWAY
]

def direct(path):
    cap = Capture()
    cap.dns('www.youtube.com', IP_YT, 0.018)
    cap.wait(0.001)
    c = Conn(cap, IP_YT, 0.012); c.open()
    c.send(True, client_hello('www.youtube.com'))
    c.send(False, server_flight(4580), think=0.012)
    for fc, sizes, think in FETCH:
        c.send(fc, b''.join(app(n) for n in sizes), think=think)
    c.close()
    cap.write(path)

# Proxy framing: 7-byte frame header per write plus padding on the first few writes of a session.
FRAME = 7
PAD_TARGETS = {1: (100, 400), 2: (400, 500), 3: (500, 1000)}

def tunneled(path):
    cap = Capture()
    cap.dns('proxy.example.net', IP_PROXY, 0.016)
    cap.wait(0.001)
    rtt = 0.012 + 0.031   # client→proxy plus proxy→youtube
    c = Conn(cap, IP_PROXY, 0.031); c.open()
    # outer TLS handshake with the proxy
    c.send(True, client_hello('proxy.example.net'))
    c.send(False, server_flight(2380), think=0.031)
    c.send(True, app(53 + 17), think=0.0005)
    writes = [0]
    def wrap(n_plain):
        writes[0] += 1
        body = n_plain + FRAME
        lo_hi = PAD_TARGETS.get(writes[0])
        if lo_hi and body < lo_hi[0]: body = random.randint(*lo_hi)
        return app(body + 17)
    # session setup: auth (32 + 2 + padding), settings, SYN, PSH(target address)
    c.send(True, app(34 + 30 + 17) + wrap(40 + 7 + 18 + 7), think=0.0002)
    c.send(False, wrap(10) + wrap(0), think=0.031)        # server settings, SYNACK
    # the inner TLS handshake to youtube, framed and padded
    c.send(True, wrap(517), think=0.0003)
    c.send(False, wrap(4580 + 120), think=rtt)
    for fc, sizes, think in FETCH:
        c.send(fc, b''.join(wrap(n + 5) for n in sizes), think=think + (0.031 if not fc else 0))
    c.close()
    cap.write(path)


if __name__ == '__main__':
    here = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'samples')
    direct(os.path.join(here, 'compare-direct.pcap'))
    tunneled(os.path.join(here, 'compare-tunneled.pcap'))
    print('wrote samples/compare-direct.pcap and samples/compare-tunneled.pcap')
