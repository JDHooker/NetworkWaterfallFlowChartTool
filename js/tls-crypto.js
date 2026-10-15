/* tls-crypto.js — small, dependency-free crypto used to decrypt TLS captures in the browser:
   SHA-256 / SHA-384, HMAC, HKDF-Expand-Label (TLS 1.3), the TLS 1.2 PRF, AES (GCM, CBC) and
   ChaCha20-Poly1305. Everything is synchronous so it also works from file:// pages, where
   WebCrypto is not always available. Exposes window.TlsCrypto. */
(function () {
  'use strict';
  const root = typeof window !== 'undefined' ? window : globalThis;

  // ---------- bytes ----------
  function concat(...arrs) {
    let n = 0; for (const a of arrs) n += a.length;
    const out = new Uint8Array(n); let o = 0;
    for (const a of arrs) { out.set(a, o); o += a.length; }
    return out;
  }
  function hexToBytes(h) { const out = new Uint8Array(h.length >> 1); for (let i = 0; i < out.length; i++) out[i] = parseInt(h.substr(i * 2, 2), 16); return out; }
  function bytesToHex(b) { let s = ''; for (let i = 0; i < b.length; i++) s += b[i].toString(16).padStart(2, '0'); return s; }
  function ascii(s) { const out = new Uint8Array(s.length); for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i) & 0xff; return out; }
  function equal(a, b) { if (a.length !== b.length) return false; let d = 0; for (let i = 0; i < a.length; i++) d |= a[i] ^ b[i]; return d === 0; }

  // ---------- constants, derived instead of typed in (no typos) ----------
  // K = fractional parts of cube roots of primes, IV = fractional parts of square roots.
  function primes(n) { const out = []; for (let c = 2; out.length < n; c++) if (out.every(p => c % p)) out.push(c); return out; }
  function iroot(x, k) { // floor(x^(1/k)) for BigInt x
    if (x < 2n) return x;
    let r = 1n << BigInt(Math.ceil(x.toString(2).length / k));
    for (;;) { const nr = ((BigInt(k) - 1n) * r + x / (r ** BigInt(k - 1))) / BigInt(k); if (nr >= r) return r; r = nr; }
  }
  const PR = primes(80);
  const fracBits = (p, k, bits) => iroot(BigInt(p) << BigInt(bits * k), k) & ((1n << BigInt(bits)) - 1n);
  const K256 = new Uint32Array(PR.slice(0, 64).map(p => Number(fracBits(p, 3, 32))));
  const H256 = PR.slice(0, 8).map(p => Number(fracBits(p, 2, 32)));
  const K512 = PR.map(p => fracBits(p, 3, 64));
  const H384 = PR.slice(8, 16).map(p => fracBits(p, 2, 64));

  // ---------- SHA-256 ----------
  function sha256(msg) {
    const h = H256.slice();
    const len = msg.length, padLen = ((len + 9 + 63) >> 6) << 6;
    const buf = new Uint8Array(padLen); buf.set(msg); buf[len] = 0x80;
    const bits = len * 8; const dv = new DataView(buf.buffer);
    dv.setUint32(padLen - 8, Math.floor(bits / 4294967296)); dv.setUint32(padLen - 4, bits >>> 0);
    const w = new Uint32Array(64);
    for (let off = 0; off < padLen; off += 64) {
      for (let i = 0; i < 16; i++) w[i] = dv.getUint32(off + i * 4);
      for (let i = 16; i < 64; i++) {
        const a = w[i - 15], b = w[i - 2];
        const s0 = ((a >>> 7) | (a << 25)) ^ ((a >>> 18) | (a << 14)) ^ (a >>> 3);
        const s1 = ((b >>> 17) | (b << 15)) ^ ((b >>> 19) | (b << 13)) ^ (b >>> 10);
        w[i] = (w[i - 16] + s0 + w[i - 7] + s1) | 0;
      }
      let [a, b, c, d, e, f, g, hh] = h;
      for (let i = 0; i < 64; i++) {
        const S1 = ((e >>> 6) | (e << 26)) ^ ((e >>> 11) | (e << 21)) ^ ((e >>> 25) | (e << 7));
        const ch = (e & f) ^ (~e & g);
        const t1 = (hh + S1 + ch + K256[i] + w[i]) | 0;
        const S0 = ((a >>> 2) | (a << 30)) ^ ((a >>> 13) | (a << 19)) ^ ((a >>> 22) | (a << 10));
        const mj = (a & b) ^ (a & c) ^ (b & c);
        const t2 = (S0 + mj) | 0;
        hh = g; g = f; f = e; e = (d + t1) | 0; d = c; c = b; b = a; a = (t1 + t2) | 0;
      }
      h[0] = (h[0] + a) | 0; h[1] = (h[1] + b) | 0; h[2] = (h[2] + c) | 0; h[3] = (h[3] + d) | 0;
      h[4] = (h[4] + e) | 0; h[5] = (h[5] + f) | 0; h[6] = (h[6] + g) | 0; h[7] = (h[7] + hh) | 0;
    }
    const out = new Uint8Array(32); const ov = new DataView(out.buffer);
    for (let i = 0; i < 8; i++) ov.setUint32(i * 4, h[i] >>> 0);
    return out;
  }

  // ---------- SHA-384 (SHA-512 core on BigInt; only used for short key-derivation inputs) ----------
  const M64 = (1n << 64n) - 1n;
  const rotr64 = (x, n) => ((x >> n) | (x << (64n - n))) & M64;
  function sha384(msg) {
    const h = H384.slice();
    const len = msg.length, padLen = ((len + 17 + 127) >> 7) << 7;
    const buf = new Uint8Array(padLen); buf.set(msg); buf[len] = 0x80;
    const dv = new DataView(buf.buffer); const bits = len * 8;
    dv.setUint32(padLen - 8, Math.floor(bits / 4294967296)); dv.setUint32(padLen - 4, bits >>> 0);
    const w = new Array(80);
    for (let off = 0; off < padLen; off += 128) {
      for (let i = 0; i < 16; i++) w[i] = (BigInt(dv.getUint32(off + i * 8)) << 32n) | BigInt(dv.getUint32(off + i * 8 + 4));
      for (let i = 16; i < 80; i++) {
        const s0 = rotr64(w[i - 15], 1n) ^ rotr64(w[i - 15], 8n) ^ (w[i - 15] >> 7n);
        const s1 = rotr64(w[i - 2], 19n) ^ rotr64(w[i - 2], 61n) ^ (w[i - 2] >> 6n);
        w[i] = (w[i - 16] + s0 + w[i - 7] + s1) & M64;
      }
      let [a, b, c, d, e, f, g, hh] = h;
      for (let i = 0; i < 80; i++) {
        const S1 = rotr64(e, 14n) ^ rotr64(e, 18n) ^ rotr64(e, 41n);
        const ch = (e & f) ^ ((~e & M64) & g);
        const t1 = (hh + S1 + ch + K512[i] + w[i]) & M64;
        const S0 = rotr64(a, 28n) ^ rotr64(a, 34n) ^ rotr64(a, 39n);
        const mj = (a & b) ^ (a & c) ^ (b & c);
        const t2 = (S0 + mj) & M64;
        hh = g; g = f; f = e; e = (d + t1) & M64; d = c; c = b; b = a; a = (t1 + t2) & M64;
      }
      h[0] = (h[0] + a) & M64; h[1] = (h[1] + b) & M64; h[2] = (h[2] + c) & M64; h[3] = (h[3] + d) & M64;
      h[4] = (h[4] + e) & M64; h[5] = (h[5] + f) & M64; h[6] = (h[6] + g) & M64; h[7] = (h[7] + hh) & M64;
    }
    const out = new Uint8Array(48); const ov = new DataView(out.buffer);
    for (let i = 0; i < 6; i++) { ov.setUint32(i * 8, Number(h[i] >> 32n)); ov.setUint32(i * 8 + 4, Number(h[i] & 0xffffffffn)); }
    return out;
  }

  const HASHES = { sha256: { fn: sha256, len: 32, block: 64 }, sha384: { fn: sha384, len: 48, block: 128 } };

  // ---------- HMAC / HKDF / PRF ----------
  function hmac(hashName, key, msg) {
    const H = HASHES[hashName];
    if (key.length > H.block) key = H.fn(key);
    const k = new Uint8Array(H.block); k.set(key);
    const ipad = new Uint8Array(H.block), opad = new Uint8Array(H.block);
    for (let i = 0; i < H.block; i++) { ipad[i] = k[i] ^ 0x36; opad[i] = k[i] ^ 0x5c; }
    return H.fn(concat(opad, H.fn(concat(ipad, msg))));
  }
  function hkdfExpand(hashName, prk, info, length) {
    const out = new Uint8Array(length); let t = new Uint8Array(0), o = 0;
    for (let i = 1; o < length; i++) {
      t = hmac(hashName, prk, concat(t, info, new Uint8Array([i])));
      out.set(t.subarray(0, Math.min(t.length, length - o)), o); o += t.length;
    }
    return out;
  }
  function hkdfExpandLabel(hashName, secret, label, context, length) {
    const full = ascii('tls13 ' + label);
    const info = concat(new Uint8Array([length >> 8, length & 0xff, full.length]), full, new Uint8Array([context.length]), context);
    return hkdfExpand(hashName, secret, info, length);
  }
  function prf12(hashName, secret, label, seed, length) {
    const ls = concat(ascii(label), seed);
    const out = new Uint8Array(length); let a = ls, o = 0;
    while (o < length) {
      a = hmac(hashName, secret, a);
      const chunk = hmac(hashName, secret, concat(a, ls));
      out.set(chunk.subarray(0, Math.min(chunk.length, length - o)), o); o += chunk.length;
    }
    return out;
  }

  // ---------- AES (table-driven) ----------
  const AES_T = (function () {
    const enc = [[], [], [], [], []], dec = [[], [], [], [], []];
    const sbox = enc[4], sboxInv = dec[4], d = [], th = [];
    for (let i = 0; i < 256; i++) th[(d[i] = i << 1 ^ (i >> 7) * 283) ^ i] = i;
    for (let x = 0, xInv = 0; !sbox[x]; x ^= d[x] || 1, xInv = th[xInv] || 1) {
      let s = xInv ^ xInv << 1 ^ xInv << 2 ^ xInv << 3 ^ xInv << 4;
      s = s >> 8 ^ s & 255 ^ 99;
      sbox[x] = s; sboxInv[s] = x;
      const x2 = d[x], x4 = d[x2], x8 = d[x4];
      let tDec = x8 * 0x1010101 ^ x4 * 0x10001 ^ x2 * 0x101 ^ x * 0x1010100;
      let tEnc = d[s] * 0x101 ^ s * 0x1010100;
      for (let i = 0; i < 4; i++) {
        enc[i][x] = tEnc = tEnc << 24 ^ tEnc >>> 8;
        dec[i][s] = tDec = tDec << 24 ^ tDec >>> 8;
      }
    }
    return { enc: enc.map(a => Int32Array.from(a)), dec: dec.map(a => Int32Array.from(a)) };
  })();

  class AES {
    constructor(keyBytes) {
      const kl = keyBytes.length / 4;
      if (kl !== 4 && kl !== 6 && kl !== 8) throw new Error('bad AES key length');
      const sbox = AES_T.enc[4], decT = AES_T.dec;
      const encKey = []; for (let i = 0; i < kl; i++) encKey.push((keyBytes[i * 4] << 24) | (keyBytes[i * 4 + 1] << 16) | (keyBytes[i * 4 + 2] << 8) | keyBytes[i * 4 + 3]);
      let rcon = 1, i;
      for (i = kl; i < 4 * kl + 28; i++) {
        let tmp = encKey[i - 1];
        if (i % kl === 0 || (kl === 8 && i % kl === 4)) {
          tmp = sbox[tmp >>> 24] << 24 ^ sbox[tmp >> 16 & 255] << 16 ^ sbox[tmp >> 8 & 255] << 8 ^ sbox[tmp & 255];
          if (i % kl === 0) { tmp = tmp << 8 ^ tmp >>> 24 ^ rcon << 24; rcon = rcon << 1 ^ (rcon >> 7) * 283; }
        }
        encKey[i] = encKey[i - kl] ^ tmp;
      }
      const decKey = [];
      for (let j = 0; i; j++, i--) {
        const tmp = encKey[j & 3 ? i : i - 4];
        if (i <= 4 || j < 4) decKey[j] = tmp;
        else decKey[j] = decT[0][sbox[tmp >>> 24]] ^ decT[1][sbox[tmp >> 16 & 255]] ^ decT[2][sbox[tmp >> 8 & 255]] ^ decT[3][sbox[tmp & 255]];
      }
      this.keys = [Int32Array.from(encKey), Int32Array.from(decKey)];
    }
    // input / output: 4 big-endian 32-bit words
    crypt(input, dir) {
      const key = this.keys[dir], table = dir ? AES_T.dec : AES_T.enc;
      const t0 = table[0], t1 = table[1], t2 = table[2], t3 = table[3], sbox = table[4];
      let a = input[0] ^ key[0], b = input[dir ? 3 : 1] ^ key[1], c = input[2] ^ key[2], d = input[dir ? 1 : 3] ^ key[3];
      const rounds = key.length / 4 - 2; let k = 4, a2, b2, c2;
      for (let i = 0; i < rounds; i++) {
        a2 = t0[a >>> 24] ^ t1[b >> 16 & 255] ^ t2[c >> 8 & 255] ^ t3[d & 255] ^ key[k];
        b2 = t0[b >>> 24] ^ t1[c >> 16 & 255] ^ t2[d >> 8 & 255] ^ t3[a & 255] ^ key[k + 1];
        c2 = t0[c >>> 24] ^ t1[d >> 16 & 255] ^ t2[a >> 8 & 255] ^ t3[b & 255] ^ key[k + 2];
        d = t0[d >>> 24] ^ t1[a >> 16 & 255] ^ t2[b >> 8 & 255] ^ t3[c & 255] ^ key[k + 3];
        k += 4; a = a2; b = b2; c = c2;
      }
      const out = [0, 0, 0, 0];
      for (let i = 0; i < 4; i++) {
        out[dir ? 3 & -i : i] = sbox[a >>> 24] << 24 ^ sbox[b >> 16 & 255] << 16 ^ sbox[c >> 8 & 255] << 8 ^ sbox[d & 255] ^ key[k++];
        a2 = a; a = b; b = c; c = d; d = a2;
      }
      return out;
    }
    encryptBlock(w) { return this.crypt(w, 0); }
    decryptBlock(w) { return this.crypt(w, 1); }
  }
  const be32 = (b, o) => (b[o] << 24) | (b[o + 1] << 16) | (b[o + 2] << 8) | b[o + 3];
  const put32 = (b, o, v) => { b[o] = v >>> 24; b[o + 1] = v >>> 16; b[o + 2] = v >>> 8; b[o + 3] = v; };

  // ---------- GCM ----------
  function gmul(x, h) { // in place: x = x * h in GF(2^128), GCM bit order
    let z0 = 0, z1 = 0, z2 = 0, z3 = 0, v0 = h[0], v1 = h[1], v2 = h[2], v3 = h[3];
    for (let i = 0; i < 128; i++) {
      if ((x[i >> 5] >>> (31 - (i & 31))) & 1) { z0 ^= v0; z1 ^= v1; z2 ^= v2; z3 ^= v3; }
      const lsb = v3 & 1;
      v3 = (v3 >>> 1) | (v2 << 31); v2 = (v2 >>> 1) | (v1 << 31); v1 = (v1 >>> 1) | (v0 << 31); v0 = v0 >>> 1;
      if (lsb) v0 ^= 0xe1000000;
    }
    x[0] = z0; x[1] = z1; x[2] = z2; x[3] = z3;
  }
  function ghash(x, h, data) {
    const n = data.length;
    for (let o = 0; o < n; o += 16) {
      if (o + 16 <= n) { x[0] ^= be32(data, o); x[1] ^= be32(data, o + 4); x[2] ^= be32(data, o + 8); x[3] ^= be32(data, o + 12); }
      else { const blk = new Uint8Array(16); blk.set(data.subarray(o)); x[0] ^= be32(blk, 0); x[1] ^= be32(blk, 4); x[2] ^= be32(blk, 8); x[3] ^= be32(blk, 12); }
      gmul(x, h);
    }
  }
  // data = ciphertext || 16-byte tag. Returns plaintext, or null when the tag does not verify.
  function aesGcmOpen(aes, iv, data, aad) {
    if (data.length < 16 || iv.length !== 12) return null;
    const ctLen = data.length - 16, ct = data.subarray(0, ctLen), tag = data.subarray(ctLen);
    const H = aes.encryptBlock([0, 0, 0, 0]);
    const x = [0, 0, 0, 0];
    ghash(x, H, aad); ghash(x, H, ct);
    // length block: bit lengths of AAD and ciphertext (TLS records are far below 2^32 bits)
    const lb = new Uint8Array(16); put32(lb, 4, aad.length * 8); put32(lb, 12, ctLen * 8);
    x[0] ^= be32(lb, 0); x[1] ^= be32(lb, 4); x[2] ^= be32(lb, 8); x[3] ^= be32(lb, 12); gmul(x, H);
    const j0 = [be32(iv, 0), be32(iv, 4), be32(iv, 8), 1];
    const ek = aes.encryptBlock(j0);
    const t = new Uint8Array(16);
    for (let i = 0; i < 4; i++) put32(t, i * 4, x[i] ^ ek[i]);
    if (!equal(t, tag)) return null;
    const out = new Uint8Array(ctLen); const ctr = j0.slice(); const ks = new Uint8Array(16);
    for (let o = 0; o < ctLen; o += 16) {
      ctr[3] = (ctr[3] + 1) | 0;
      const k = aes.encryptBlock(ctr);
      put32(ks, 0, k[0]); put32(ks, 4, k[1]); put32(ks, 8, k[2]); put32(ks, 12, k[3]);
      const e = Math.min(16, ctLen - o);
      for (let i = 0; i < e; i++) out[o + i] = ct[o + i] ^ ks[i];
    }
    return out;
  }

  // ---------- CBC (TLS 1.2 legacy suites) ----------
  function aesCbcDecrypt(aes, iv, ct) {
    if (ct.length % 16 || !ct.length) return null;
    const out = new Uint8Array(ct.length);
    let p0 = be32(iv, 0), p1 = be32(iv, 4), p2 = be32(iv, 8), p3 = be32(iv, 12);
    for (let o = 0; o < ct.length; o += 16) {
      const c = [be32(ct, o), be32(ct, o + 4), be32(ct, o + 8), be32(ct, o + 12)];
      const d = aes.decryptBlock(c);
      put32(out, o, d[0] ^ p0); put32(out, o + 4, d[1] ^ p1); put32(out, o + 8, d[2] ^ p2); put32(out, o + 12, d[3] ^ p3);
      p0 = c[0]; p1 = c[1]; p2 = c[2]; p3 = c[3];
    }
    return out;
  }

  // ---------- ChaCha20-Poly1305 ----------
  const le32 = (b, o) => (b[o] | (b[o + 1] << 8) | (b[o + 2] << 16) | (b[o + 3] << 24)) >>> 0;
  function chachaBlock(key, counter, nonce, out) {
    const s = new Uint32Array(16);
    s[0] = 0x61707865; s[1] = 0x3320646e; s[2] = 0x79622d32; s[3] = 0x6b206574;
    for (let i = 0; i < 8; i++) s[4 + i] = le32(key, i * 4);
    s[12] = counter; s[13] = le32(nonce, 0); s[14] = le32(nonce, 4); s[15] = le32(nonce, 8);
    const x = s.slice();
    const qr = (a, b, c, d) => {
      x[a] += x[b]; x[d] ^= x[a]; x[d] = (x[d] << 16) | (x[d] >>> 16);
      x[c] += x[d]; x[b] ^= x[c]; x[b] = (x[b] << 12) | (x[b] >>> 20);
      x[a] += x[b]; x[d] ^= x[a]; x[d] = (x[d] << 8) | (x[d] >>> 24);
      x[c] += x[d]; x[b] ^= x[c]; x[b] = (x[b] << 7) | (x[b] >>> 25);
    };
    for (let i = 0; i < 10; i++) {
      qr(0, 4, 8, 12); qr(1, 5, 9, 13); qr(2, 6, 10, 14); qr(3, 7, 11, 15);
      qr(0, 5, 10, 15); qr(1, 6, 11, 12); qr(2, 7, 8, 13); qr(3, 4, 9, 14);
    }
    for (let i = 0; i < 16; i++) { const v = (x[i] + s[i]) >>> 0; out[i * 4] = v; out[i * 4 + 1] = v >>> 8; out[i * 4 + 2] = v >>> 16; out[i * 4 + 3] = v >>> 24; }
  }
  function chacha20(key, nonce, counter, data) {
    const out = new Uint8Array(data.length), ks = new Uint8Array(64);
    for (let o = 0; o < data.length; o += 64, counter++) {
      chachaBlock(key, counter >>> 0, nonce, ks);
      const e = Math.min(64, data.length - o);
      for (let i = 0; i < e; i++) out[o + i] = data[o + i] ^ ks[i];
    }
    return out;
  }
  const P1305 = (1n << 130n) - 5n;
  function leBig(b) { let r = 0n; for (let i = b.length - 1; i >= 0; i--) r = (r << 8n) | BigInt(b[i]); return r; }
  function poly1305(key, msg) {
    const r = leBig(key.subarray(0, 16)) & 0x0ffffffc0ffffffc0ffffffc0fffffffn;
    const s = leBig(key.subarray(16, 32));
    let acc = 0n;
    for (let o = 0; o < msg.length; o += 16) {
      const blk = msg.subarray(o, Math.min(msg.length, o + 16));
      acc = ((acc + leBig(blk) + (1n << BigInt(8 * blk.length))) * r) % P1305;
    }
    acc = (acc + s) & ((1n << 128n) - 1n);
    const out = new Uint8Array(16);
    for (let i = 0; i < 16; i++) { out[i] = Number(acc & 0xffn); acc >>= 8n; }
    return out;
  }
  function pad16(n) { return new Uint8Array((16 - (n % 16)) % 16); }
  function le64(n) { const b = new Uint8Array(8); let v = n; for (let i = 0; i < 8; i++) { b[i] = v & 0xff; v = Math.floor(v / 256); } return b; }
  function chachaPolyOpen(key, nonce, data, aad) {
    if (data.length < 16) return null;
    const ctLen = data.length - 16, ct = data.subarray(0, ctLen), tag = data.subarray(ctLen);
    const block0 = new Uint8Array(64); chachaBlock(key, 0, nonce, block0);
    const mac = poly1305(block0.subarray(0, 32), concat(aad, pad16(aad.length), ct, pad16(ctLen), le64(aad.length), le64(ctLen)));
    if (!equal(mac, tag)) return null;
    return chacha20(key, nonce, 1, ct);
  }

  root.TlsCrypto = {
    sha256, sha384, hmac, hkdfExpand, hkdfExpandLabel, prf12, AES, aesGcmOpen, aesCbcDecrypt, chacha20, poly1305, chachaPolyOpen,
    HASHES, concat, hexToBytes, bytesToHex, ascii, equal,
  };
})();
