#!/usr/bin/env python3
"""Independent survey of a decrypted PS3 PPU ELF (no ps3recomp code used).

Prints: header, program headers, section headers, OPD-based function count,
sys_process_prx_param, import stubs (library -> NIDs), exports, syscall sites,
embedded SPU ELF images.  Writes JSON with --json.

Usage: python -I elf_survey.py EBOOT.elf [--json out.json]
"""
import hashlib, json, struct, sys, collections

def u8(b, o): return b[o]
def u16(b, o): return struct.unpack_from('>H', b, o)[0]
def u32(b, o): return struct.unpack_from('>I', b, o)[0]
def u64(b, o): return struct.unpack_from('>Q', b, o)[0]

PT_NAMES = {0: 'NULL', 1: 'LOAD', 2: 'DYNAMIC', 3: 'INTERP', 4: 'NOTE', 7: 'TLS',
            0x60000001: 'PROC_PARAM', 0x60000002: 'PROC_PRX_PARAM'}


def main():
    path = sys.argv[1]
    out_json = sys.argv[sys.argv.index('--json') + 1] if '--json' in sys.argv else None
    d = open(path, 'rb').read()
    assert d[:4] == b'\x7fELF' and d[4] == 2 and d[5] == 2, 'need ELF64 big-endian'
    R = {'file': path, 'size': len(d), 'sha256': hashlib.sha256(d).hexdigest()}
    e_type, e_machine = u16(d, 16), u16(d, 18)
    e_entry, e_phoff, e_shoff = u64(d, 24), u64(d, 32), u64(d, 40)
    e_phnum, e_shnum, e_shstrndx = u16(d, 56), u16(d, 60), u16(d, 62)
    R['header'] = dict(type=hex(e_type), machine=e_machine, entry=hex(e_entry),
                       phnum=e_phnum, shnum=e_shnum)

    phdrs = []
    for i in range(e_phnum):
        o = e_phoff + i * 56
        p = dict(type=u32(d, o), flags=u32(d, o + 4), offset=u64(d, o + 8), vaddr=u64(d, o + 16),
                 filesz=u64(d, o + 32), memsz=u64(d, o + 40), align=u64(d, o + 48))
        phdrs.append(p)
    R['segments'] = [dict(type=PT_NAMES.get(p['type'], hex(p['type'])),
                          flags=''.join(c if p['flags'] & m else '-' for c, m in (('R', 4), ('W', 2), ('X', 1))),
                          vaddr=hex(p['vaddr']), filesz=hex(p['filesz']), memsz=hex(p['memsz']),
                          offset=hex(p['offset'])) for p in phdrs]
    loads = [p for p in phdrs if p['type'] == 1]

    def va2off(va):
        for p in loads:
            if p['vaddr'] <= va < p['vaddr'] + p['filesz']:
                return p['offset'] + va - p['vaddr']
        return None

    def cstr(va):
        o = va2off(va)
        return d[o:d.index(b'\0', o)].decode('latin1') if o is not None else None

    # entry point OPD
    eo = va2off(e_entry)
    R['entry_opd'] = dict(code=hex(u32(d, eo)), toc=hex(u32(d, eo + 4))) if eo is not None else None

    # sections
    secs = []
    if e_shoff and e_shnum:
        sho = e_shoff + e_shstrndx * 64
        stroff = u64(d, sho + 24)
        for i in range(e_shnum):
            o = e_shoff + i * 64
            nm = u32(d, o)
            name = d[stroff + nm:d.index(b'\0', stroff + nm)].decode('latin1')
            secs.append(dict(name=name, type=u32(d, o + 4), flags=u64(d, o + 8), addr=u64(d, o + 16),
                             offset=u64(d, o + 24), size=u64(d, o + 32)))
    R['sections'] = [dict(name=s['name'], addr=hex(s['addr']), size=hex(s['size'])) for s in secs]

    # function count from .opd (PS3: 8-byte entries {u32 code, u32 toc})
    code_ranges = [(p['vaddr'], p['vaddr'] + p['filesz']) for p in loads if p['flags'] & 1]
    in_code = lambda a: any(lo <= a < hi for lo, hi in code_ranges)
    opd = next((s for s in secs if s['name'] == '.opd'), None)
    if opd is None and R['entry_opd']:
        # stripped names: the .opd is the section holding the entry descriptor
        for s in secs:
            if s['addr'] <= e_entry < s['addr'] + s['size'] and s['size'] % 8 == 0:
                opd = s
                R['opd_section_index'] = secs.index(s)
    funcs = set()
    if opd:
        for o in range(opd['offset'], opd['offset'] + opd['size'], 8):
            a = u32(d, o)
            if in_code(a):
                funcs.add(a)
        R['opd'] = dict(entries=opd['size'] // 8, unique_code_targets=len(funcs),
                        tocs=sorted({hex(u32(d, o + 4)) for o in range(opd['offset'], opd['offset'] + opd['size'], 8)})[:8])

    # prx param -> imports / exports
    pp = next((p for p in phdrs if p['type'] == 0x60000002), None)
    imports, exports = [], []
    if pp:
        o = pp['offset']
        size, magic, ver = u32(d, o), u32(d, o + 4), u32(d, o + 8)
        libent_s, libent_e, libstub_s, libstub_e = (u32(d, o + 16), u32(d, o + 20), u32(d, o + 24), u32(d, o + 28))
        R['prx_param'] = dict(size=hex(size), magic=hex(magic), version=ver)
        a = libstub_s
        while a < libstub_e:
            so = va2off(a)
            ssz = u8(d, so)
            nf, nv, nt = u16(d, so + 6), u16(d, so + 8), u16(d, so + 10)
            name = cstr(u32(d, so + 16))
            nids_va, stubs_va = u32(d, so + 20), u32(d, so + 24)
            vnids_va = u32(d, so + 28)
            no = va2off(nids_va)
            fn = [u32(d, no + 4 * k) for k in range(nf)]
            sto = va2off(stubs_va)
            stub_slots = [hex(stubs_va + 4 * k) for k in range(nf)]
            vn = []
            if nv:
                vo = va2off(vnids_va)
                vn = [u32(d, vo + 4 * k) for k in range(nv)]
            imports.append(dict(library=name, version=hex(u16(d, so + 2)), attr=hex(u16(d, so + 4)),
                                func_nids=['0x%08X' % x for x in fn], var_nids=['0x%08X' % x for x in vn],
                                tls_vars=nt))
            a += ssz
        a = libent_s
        while a < libent_e:
            eo2 = va2off(a)
            esz = u8(d, eo2)
            nf, nv = u16(d, eo2 + 6), u16(d, eo2 + 8)
            nm_va = u32(d, eo2 + 16)
            exports.append(dict(library=cstr(nm_va) if nm_va else None, funcs=nf, vars=nv))
            a += esz
    R['imports'] = imports
    R['exports'] = exports

    # syscall sites: 'sc' (0x44000002) preceded within 8 insns by 'li r11,N' (0x3960xxxx)
    sc_counter = collections.Counter()
    for lo, hi in code_ranges:
        so = va2off(lo)
        n = (hi - lo) // 4
        words = struct.unpack_from('>%dI' % n, d, so)
        for i, w in enumerate(words):
            if w == 0x44000002:
                num = None
                for j in range(i - 1, max(i - 12, -1), -1):
                    if (words[j] & 0xFFFF0000) == 0x39600000:
                        num = words[j] & 0xFFFF
                        break
                sc_counter[num] += 1
    R['syscall_sites'] = {str(k): v for k, v in sorted(sc_counter.items(), key=lambda kv: (kv[0] is None, kv[0] or 0))}

    # embedded SPU ELFs: ELF32 BE, e_machine 0x17
    spu = []
    pos = 0
    while True:
        pos = d.find(b'\x7fELF\x01\x02\x01', pos + 1)
        if pos < 0:
            break
        if u16(d, pos + 18) != 0x17:
            continue
        phoff, phentsz, phnum = u32(d, pos + 28), u16(d, pos + 42), u16(d, pos + 44)
        shoff, shentsz, shnum = u32(d, pos + 32), u16(d, pos + 46), u16(d, pos + 48)
        end = pos + max([phoff + phentsz * phnum] +
                        [u32(d, pos + phoff + k * phentsz + 4) + u32(d, pos + phoff + k * phentsz + 16) for k in range(phnum)]
                        + ([shoff + shentsz * shnum] if shoff else []))
        img = d[pos:end]
        spu.append(dict(file_offset=hex(pos), size=len(img), entry=hex(u32(d, pos + 24)),
                        segments=phnum, sha1=hashlib.sha1(img).hexdigest()[:16]))
    R['spu_images'] = spu

    # summary
    print('ELF', path, R['size'], 'bytes, sha256', R['sha256'][:16])
    print('header', R['header'], 'entry OPD', R['entry_opd'])
    for s in R['segments']:
        print('  seg', s)
    print('sections:', len(secs), [s['name'] for s in secs][:60])
    if 'opd' in R:
        print('OPD:', R['opd'])
    nf = sum(len(i['func_nids']) for i in imports)
    nv = sum(len(i['var_nids']) for i in imports)
    print('imports: %d libraries, %d functions, %d variables' % (len(imports), nf, nv))
    for i in sorted(imports, key=lambda x: -len(x['func_nids'])):
        print('  %-24s funcs=%3d vars=%d' % (i['library'], len(i['func_nids']), len(i['var_nids'])))
    print('exports:', exports)
    print('syscall sites:', R['syscall_sites'])
    print('SPU ELF images:', len(spu))
    for s in spu:
        print('  ', s)
    if out_json:
        json.dump(R, open(out_json, 'w'), indent=1)


if __name__ == '__main__':
    main()
