#!/usr/bin/env python3
"""Extract the SPU ELF images we lift into spu_programs/images/<name>.elf.

EBOOT names come from RPCS3's SPUNAME lines in logs/baseline-race.log (image vaddr =
file offset + 0x10000). Havok (hka/hkp) is skipped: those images have several
executable PT_LOADs, which build_spu_workloads.py does not lift yet.
libsre's two embedded SPU programs (SPURS kernel) are named by offset.

Usage: python -I tools/extract_spu_images.py  (run from C:/msa-port)
"""
import os, struct

EBOOT = 'elf/EBOOT.elf'
OUT = 'spu_programs/images'

def elf_size(d, pos):
    phoff, phentsz, phnum = struct.unpack('>I', d[pos+28:pos+32])[0], *struct.unpack('>HH', d[pos+42:pos+46])
    shoff = struct.unpack('>I', d[pos+32:pos+36])[0]
    shentsz, shnum = struct.unpack('>HH', d[pos+46:pos+50])
    end = phoff + phentsz * phnum
    for k in range(phnum):
        o = pos + phoff + k * phentsz
        off, fs = struct.unpack('>I', d[o+4:o+8])[0], struct.unpack('>I', d[o+16:o+20])[0]
        end = max(end, off + fs)
    if shoff:
        end = max(end, shoff + shentsz * shnum)
    return end

def scan(path):
    d = open(path, 'rb').read()
    pos = 0
    while True:
        pos = d.find(b'\x7fELF\x01\x02\x01', pos + 1)
        if pos < 0:
            return
        if struct.unpack('>H', d[pos+18:pos+20])[0] == 0x17:
            yield pos, d[pos:pos + elf_size(d, pos)]

EBOOT_NAMES = {
    0x1148a80: 'msngSPURS_MP3', 0x1160080: 'edgepost_mlaa', 0x1168900: 'edgezlib_inflate',
    0x1217300: 'mstream_dsp_aux_return', 0x1217b80: 'mstream_dsp_aux_send', 0x1218680: 'mstream_dsp_compressor',
    0x1219600: 'mstream_dsp_delay', 0x121ab80: 'mstream_dsp_distortion', 0x121b300: 'mstream_dsp_eq',
    0x121ba00: 'mstream_dsp_filter', 0x121c200: 'mstream_dsp_i3dl2', 0x121ec80: 'mstream_dsp_IR',
    0x121fe00: 'mstream_dsp_multi_compressor', 0x1221000: 'mstream_dsp_multi_compressor_TD',
    0x1222380: 'mstream_dsp_para_eq', 0x1222d00: 'mstream_dsp_pitchshift', 0x1224980: 'mstream_dsp_reverb',
    0x1226c00: 'mstream_dsp_ringmod', 0x1227680: 'mstream_dsp_softclip', 0x1227e80: 'mstream_dsp_vocoder',
}
HAVOK = {0x10a8400, 0x10b5d80, 0x10d3100, 0x10f8e80, 0x1120400}

os.makedirs(OUT, exist_ok=True)
n = 0
for off, img in scan(EBOOT):
    if off in HAVOK:
        continue
    name = EBOOT_NAMES.get(off, 'eboot_%x' % off)
    open(os.path.join(OUT, name + '.elf'), 'wb').write(img); n += 1
for off, img in scan('firmware/libsre.prx'):
    open(os.path.join(OUT, 'libsre_spu_%x.elf' % off), 'wb').write(img); n += 1
print('wrote', n, 'images to', OUT)
