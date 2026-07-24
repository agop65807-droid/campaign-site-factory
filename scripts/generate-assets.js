const fs = require('fs');
const path = require('path');
const zlib = require('zlib');

const rootDir = path.resolve(__dirname, '..');
const width = 256;
const height = 256;

function makeCrcTable() {
  return Array.from({ length: 256 }, (_, value) => {
    let crc = value;
    for (let bit = 0; bit < 8; bit += 1) {
      crc = (crc & 1) ? (0xedb88320 ^ (crc >>> 1)) : (crc >>> 1);
    }
    return crc >>> 0;
  });
}

const crcTable = makeCrcTable();

function crc32(buffer) {
  let crc = 0xffffffff;
  for (const byte of buffer) {
    crc = crcTable[(crc ^ byte) & 0xff] ^ (crc >>> 8);
  }
  return (crc ^ 0xffffffff) >>> 0;
}

function pngChunk(type, data) {
  const typeBuffer = Buffer.from(type, 'ascii');
  const size = Buffer.alloc(4);
  size.writeUInt32BE(data.length);
  const checksum = Buffer.alloc(4);
  checksum.writeUInt32BE(crc32(Buffer.concat([typeBuffer, data])));
  return Buffer.concat([size, typeBuffer, data, checksum]);
}

function insideRoundedSquare(x, y, inset, radius) {
  const left = inset;
  const right = width - inset;
  const top = inset;
  const bottom = height - inset;
  if (x < left || x >= right || y < top || y >= bottom) return false;
  const cx = Math.max(left + radius, Math.min(x, right - radius));
  const cy = Math.max(top + radius, Math.min(y, bottom - radius));
  return ((x - cx) ** 2) + ((y - cy) ** 2) <= radius ** 2;
}

function insidePolygon(x, y, points) {
  let inside = false;
  for (let index = 0, previous = points.length - 1; index < points.length; previous = index, index += 1) {
    const [xi, yi] = points[index];
    const [xj, yj] = points[previous];
    const intersects = ((yi > y) !== (yj > y))
      && (x < ((xj - xi) * (y - yi)) / (yj - yi) + xi);
    if (intersects) inside = !inside;
  }
  return inside;
}

function pixelAt(x, y) {
  if (!insideRoundedSquare(x, y, 12, 48)) return [0, 0, 0, 0];

  const progress = (x + y) / (width + height);
  let red = Math.round(4 + (11 * progress));
  let green = Math.round(84 - (58 * progress));
  let blue = Math.round(66 - (20 * progress));

  const glow = Math.max(0, 1 - Math.hypot(x - 66, y - 54) / 150);
  red += Math.round(8 * glow);
  green += Math.round(38 * glow);
  blue += Math.round(28 * glow);

  const horn = insidePolygon(x, y, [[73, 108], [158, 72], [158, 184], [73, 148]]);
  const mouth = x >= 58 && x <= 86 && y >= 105 && y <= 151;
  const handle = insidePolygon(x, y, [[91, 148], [127, 148], [114, 196], [87, 196]]);
  const dx = x - 157;
  const dy = y - 128;
  const distance = Math.hypot(dx, dy);
  const angle = Math.abs(Math.atan2(dy, dx));
  const soundWave = dx > 0 && angle < 0.78
    && ((distance >= 29 && distance <= 39) || (distance >= 53 && distance <= 64));

  if (horn || mouth || handle || soundWave) {
    return [241, 245, 249, 255];
  }

  return [red, green, blue, 255];
}

function createPng() {
  const raw = Buffer.alloc((width * 4 + 1) * height);
  for (let y = 0; y < height; y += 1) {
    const rowOffset = y * (width * 4 + 1);
    raw[rowOffset] = 0;
    for (let x = 0; x < width; x += 1) {
      const offset = rowOffset + 1 + x * 4;
      const pixel = pixelAt(x + 0.5, y + 0.5);
      raw[offset] = pixel[0];
      raw[offset + 1] = pixel[1];
      raw[offset + 2] = pixel[2];
      raw[offset + 3] = pixel[3];
    }
  }

  const header = Buffer.alloc(13);
  header.writeUInt32BE(width, 0);
  header.writeUInt32BE(height, 4);
  header[8] = 8;
  header[9] = 6;

  return Buffer.concat([
    Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]),
    pngChunk('IHDR', header),
    pngChunk('IDAT', zlib.deflateSync(raw, { level: 9 })),
    pngChunk('IEND', Buffer.alloc(0))
  ]);
}

function createIco(png) {
  const header = Buffer.alloc(22);
  header.writeUInt16LE(0, 0);
  header.writeUInt16LE(1, 2);
  header.writeUInt16LE(1, 4);
  header[6] = 0;
  header[7] = 0;
  header[8] = 0;
  header[9] = 0;
  header.writeUInt16LE(1, 10);
  header.writeUInt16LE(32, 12);
  header.writeUInt32LE(png.length, 14);
  header.writeUInt32LE(22, 18);
  return Buffer.concat([header, png]);
}

const logo = createPng();
fs.writeFileSync(path.join(rootDir, 'logo-dark.png'), logo);
fs.writeFileSync(path.join(rootDir, 'favicon.ico'), createIco(logo));

console.log(`Created validated logo and favicon (${logo.length} PNG bytes).`);
console.log('The vendored SheetJS build is managed separately and is not overwritten.');
