#!/usr/bin/env python3
"""Resolve host RVAs (as printed by port/diag.cpp, '... rva=0x...') to symbols
using the lld-link /MAP of MotorStormRecomp.exe.

Usage: python -I symbolize.py build/port/MotorStormRecomp.map 0x4CCA2E4 [...]
       python -I symbolize.py MAP --log logs/port-XXXX.log    (every rva=0x.. in a log)
"""
import bisect, re, sys

def load(mp):
    base = 0x140000000
    syms = []
    for line in open(mp, encoding='latin1'):
        m = re.match(r'\s*[0-9a-f]{4}:[0-9a-f]{8}\s+(\S+)\s+([0-9a-f]{16})\s', line)
        if m:
            syms.append((int(m.group(2), 16) - base, m.group(1)))
    syms.sort()
    return syms

def name(syms, keys, rva):
    i = bisect.bisect_right(keys, rva) - 1
    return '%s+0x%X' % (syms[i][1], rva - syms[i][0]) if i >= 0 else '?'

def main():
    syms = load(sys.argv[1]); keys = [s[0] for s in syms]
    if len(sys.argv) > 3 and sys.argv[2] == '--log':
        seen = set()
        for line in open(sys.argv[3], encoding='latin1'):
            for r in re.findall(r'rva=0x([0-9A-Fa-f]+)', line):
                if r not in seen:
                    seen.add(r); print('0x%s  %s' % (r, name(syms, keys, int(r, 16))))
    else:
        for a in sys.argv[2:]:
            print(a, name(syms, keys, int(a, 16)))

main()
