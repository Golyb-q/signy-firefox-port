#!/usr/bin/env node
// Renders the extension icons (PNG) without external dependencies.
import { writeFileSync, mkdirSync } from 'node:fs';
import { deflateSync } from 'node:zlib';

function crc32(buf) {
  let c;
  const table = crc32.t || (crc32.t = Array.from({ length: 256 }, (_, n) => {
    c = n;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    return c >>> 0;
  }));
  let crc = 0xffffffff;
  for (const b of buf) crc = table[(crc ^ b) & 0xff] ^ (crc >>> 8);
  return (crc ^ 0xffffffff) >>> 0;
}

function png(size, rgba) {
  const chunk = (type, data) => {
    const len = Buffer.alloc(4);
    len.writeUInt32BE(data.length);
    const td = Buffer.concat([Buffer.from(type), data]);
    const crc = Buffer.alloc(4);
    crc.writeUInt32BE(crc32(td));
    return Buffer.concat([len, td, crc]);
  };
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(size, 0);
  ihdr.writeUInt32BE(size, 4);
  ihdr[8] = 8;
  ihdr[9] = 6;
  const raw = Buffer.alloc(size * (size * 4 + 1));
  for (let y = 0; y < size; y++) {
    raw[y * (size * 4 + 1)] = 0;
    rgba.copy(raw, y * (size * 4 + 1) + 1, y * size * 4, (y + 1) * size * 4);
  }
  return Buffer.concat([Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]), chunk('IHDR', ihdr), chunk('IDAT', deflateSync(raw)), chunk('IEND', Buffer.alloc(0))]);
}

function distToSegment(px, py, ax, ay, bx, by) {
  const dx = bx - ax, dy = by - ay;
  const t = Math.max(0, Math.min(1, ((px - ax) * dx + (py - ay) * dy) / (dx * dx + dy * dy)));
  return Math.hypot(px - (ax + t * dx), py - (ay + t * dy));
}

function render(size) {
  const S = 4; // supersampling
  const out = Buffer.alloc(size * size * 4);
  const r = 0.22; // corner radius (fraction)
  // signature stroke: a flowing line + check
  const stroke = [[0.2, 0.62], [0.3, 0.5], [0.38, 0.58], [0.46, 0.46], [0.54, 0.6], [0.62, 0.52]];
  const check = [[0.52, 0.66], [0.62, 0.76], [0.82, 0.32]];
  const w = Math.max(0.055, 1.6 / size);
  for (let y = 0; y < size; y++) {
    for (let x = 0; x < size; x++) {
      let a = 0, rr = 0, gg = 0, bb = 0;
      for (let sy = 0; sy < S; sy++) {
        for (let sx = 0; sx < S; sx++) {
          const u = (x + (sx + 0.5) / S) / size;
          const v = (y + (sy + 0.5) / S) / size;
          // rounded square mask
          const cx = Math.min(Math.max(u, r), 1 - r);
          const cy = Math.min(Math.max(v, r), 1 - r);
          if (Math.hypot(u - cx, v - cy) > r) continue;
          // gradient background
          const t = (u + v) / 2;
          let R = 11 + (17 - 11) * t, G = 110 + (163 - 110) * t, B = 79 + (111 - 79) * t;
          let white = false;
          for (let i = 0; i + 1 < stroke.length; i++) if (distToSegment(u, v, ...stroke[i], ...stroke[i + 1]) < w * 0.75) white = true;
          for (let i = 0; i + 1 < check.length; i++) if (distToSegment(u, v, ...check[i], ...check[i + 1]) < w) white = true;
          if (white) R = G = B = 255;
          rr += R; gg += G; bb += B; a += 1;
        }
      }
      const n = S * S;
      const o = (y * size + x) * 4;
      if (a) {
        out[o] = Math.round(rr / a);
        out[o + 1] = Math.round(gg / a);
        out[o + 2] = Math.round(bb / a);
      }
      out[o + 3] = Math.round((a / n) * 255);
    }
  }
  return png(size, out);
}

const dir = new URL('../extension/icons/', import.meta.url).pathname;
mkdirSync(dir, { recursive: true });
for (const s of [16, 32, 48, 128]) writeFileSync(dir + `icon${s}.png`, render(s));
writeFileSync(new URL('../extension/web/nca.png', import.meta.url).pathname, render(32));
console.log('icons written');
