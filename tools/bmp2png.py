#!/usr/bin/env python3
"""Convert 24-bit BMPs (rsxcap backbuffers) to PNG with only the stdlib. Usage: bmp2png.py in.bmp out.png"""
import struct, sys, zlib
d = open(sys.argv[1], 'rb').read()
off, w, h, bpp = struct.unpack('<I', d[10:14])[0], *struct.unpack('<ii', d[18:26]), struct.unpack('<H', d[28:30])[0]
assert bpp == 24, bpp
row = (w * 3 + 3) & ~3
flip = h > 0; h = abs(h)
raw = bytearray()
for y in range(h):
    sy = h - 1 - y if flip else y
    r = d[off + sy * row: off + sy * row + w * 3]
    raw.append(0)
    raw += bytes(b for i in range(0, len(r), 3) for b in (r[i + 2], r[i + 1], r[i]))
def chunk(t, b): return struct.pack('>I', len(b)) + t + b + struct.pack('>I', zlib.crc32(t + b) & 0xffffffff)
png = b'\x89PNG\r\n\x1a\n' + chunk(b'IHDR', struct.pack('>IIBBBBB', w, h, 8, 2, 0, 0, 0)) + chunk(b'IDAT', zlib.compress(bytes(raw), 6)) + chunk(b'IEND', b'')
open(sys.argv[2], 'wb').write(png)
