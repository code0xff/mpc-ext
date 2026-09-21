/**
 * Draws the extension's placeholder icons.
 *
 * A notification needs an icon and the Web Store needs several sizes, and the extension had none.
 * These are plain: a rounded square with three vertical bars, one for each share. They are meant to
 * be replaced by real artwork. Run `node scripts/make-icons.mjs` to regenerate them. It uses only
 * Node's built-in zlib, so it adds no dependency.
 */
import { writeFileSync } from 'node:fs';
import { deflateSync } from 'node:zlib';

const SIZES = [16, 32, 48, 128];
const BACKGROUND = [0x1f, 0x3a, 0x5f, 0xff];
const FOREGROUND = [0xf2, 0xf5, 0xf9, 0xff];
const CLEAR = [0, 0, 0, 0];

function crc32(buffer) {
  let crc = 0xffffffff;
  for (const byte of buffer) {
    crc ^= byte;
    for (let bit = 0; bit < 8; bit += 1) crc = (crc >>> 1) ^ (0xedb88320 & -(crc & 1));
  }
  return (crc ^ 0xffffffff) >>> 0;
}

function chunk(type, data) {
  const body = Buffer.concat([Buffer.from(type), data]);
  const out = Buffer.alloc(8 + data.length + 4);
  out.writeUInt32BE(data.length, 0);
  body.copy(out, 4);
  out.writeUInt32BE(crc32(body), 8 + data.length);
  return out;
}

/** The pixel colour at (x, y) for an icon of `size` pixels. */
function pixel(x, y, size) {
  const unit = size / 16;
  const radius = 3 * unit;
  // A rounded square: outside a corner's circle, the corner is clear.
  const cx = Math.min(Math.max(x + 0.5, radius), size - radius);
  const cy = Math.min(Math.max(y + 0.5, radius), size - radius);
  if (Math.hypot(x + 0.5 - cx, y + 0.5 - cy) > radius) return CLEAR;
  // Three bars, one per share.
  const inBars = [4, 7, 10].some((left) => x + 0.5 >= left * unit && x + 0.5 < (left + 2) * unit);
  const inHeight = y + 0.5 >= 4 * unit && y + 0.5 < 12 * unit;
  return inBars && inHeight ? FOREGROUND : BACKGROUND;
}

function png(size) {
  const rows = [];
  for (let y = 0; y < size; y += 1) {
    const row = Buffer.alloc(1 + size * 4);
    for (let x = 0; x < size; x += 1) Buffer.from(pixel(x, y, size)).copy(row, 1 + x * 4);
    rows.push(row);
  }
  const header = Buffer.alloc(13);
  header.writeUInt32BE(size, 0);
  header.writeUInt32BE(size, 4);
  header[8] = 8; // bit depth
  header[9] = 6; // RGBA
  return Buffer.concat([
    Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
    chunk('IHDR', header),
    chunk('IDAT', deflateSync(Buffer.concat(rows))),
    chunk('IEND', Buffer.alloc(0)),
  ]);
}

for (const size of SIZES) {
  writeFileSync(new URL(`../public/icon/${size}.png`, import.meta.url), png(size));
  console.log(`wrote public/icon/${size}.png`);
}
