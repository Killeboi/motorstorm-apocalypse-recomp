#!/usr/bin/env python3
"""Compare the EBOOT's firmware imports and syscalls with what ps3recomp registers.

Reads ps3recomp sources as text only (nothing from the repo is executed).

Inputs:  analysis/elf_survey.json (from elf_survey.py), logs/baseline-race.log,
         repo/ (ps3recomp checkout)
Outputs: analysis/import_coverage.json, analysis/import_coverage.md

Status per imported NID:
  done     - registered in ps3recomp and the body is not trivially a stub
  stub     - registered, but the body looks like a stub (heuristic, see is_stub)
  missing  - nothing registers this NID: ps3recomp fakes CELL_OK at run time
Plus a "used" flag: the function shows up as called in the RPCS3 log.

Usage: python -I import_coverage.py C:/msa-port
"""
import glob, hashlib, json, os, re, struct, sys, collections

ROOT = sys.argv[1] if len(sys.argv) > 1 else '.'
REPO = os.path.join(ROOT, 'repo')
SUFFIX = bytes([0x67, 0x59, 0x65, 0x99, 0x04, 0x25, 0x04, 0x90,
                0x56, 0x64, 0x27, 0x49, 0x94, 0x89, 0x74, 0x1A])


def nid(name):
    return struct.unpack('<I', hashlib.sha1(name.encode() + SUFFIX).digest()[:4])[0]


def read(p):
    return open(p, encoding='latin1').read()


# ---------------------------------------------------------------- ps3recomp side
DEF_RE = re.compile(r"^(?!static)[A-Za-z_][\w \t\*]*?\b(_?(?:cell|sys|sce|_sys)\w+)\s*\([^;]*?\)\s*\{", re.M)
HLE_DIRS = ["system", "filesystem", "input", "audio", "video", "network",
            "spurs", "sync", "codec", "font", "misc", "hardware"]


def body_at(txt, brace):
    depth, i = 0, brace
    while i < len(txt):
        c = txt[i]
        if c == '{':
            depth += 1
        elif c == '}':
            depth -= 1
            if depth == 0:
                return txt[brace + 1:i]
        i += 1
    return txt[brace + 1:]


LOG_RE = re.compile(r'^\s*(\w*(LOG|log|printf|TRACE|trace|WARN|warn|DBG|dbg|UNUSED|UNIMPL|TODO)\w*\s*\(.*?\)\s*;)', re.M | re.S)


def is_stub(body):
    b = re.sub(r'/\*.*?\*/', '', body, flags=re.S)
    b = re.sub(r'//[^\n]*', '', b)
    b = LOG_RE.sub('', b)
    b = re.sub(r'\(void\)\s*\w+\s*;', '', b)
    stmts = [s.strip() for s in b.split(';') if s.strip()]
    if not stmts:
        return True
    if len(stmts) == 1 and re.match(r'^return\s+[\w\(\)\s\-|]*$', stmts[0]):
        return True
    if re.search(r'NOT_SUPPORTED|not implemented|unimplemented', body, re.I) and len(stmts) <= 3:
        return True
    return False


reg = {}  # nid -> dict(name, file, stub)
for d in HLE_DIRS:
    for p in glob.glob(os.path.join(REPO, 'libs', d, '*.c')):
        base = os.path.splitext(os.path.basename(p))[0]
        if not re.match(r'^(cell|sce|sys)', base) or re.match(r'^(test_|validate_)', base):
            continue
        txt = read(p)
        for m in DEF_RE.finditer(txt):
            name = m.group(1)
            body = body_at(txt, m.end() - 1)
            reg.setdefault(nid(name), dict(name=name, file=os.path.relpath(p, REPO).replace('\\', '/'),
                                           stub=is_stub(body), how='generic'))

EXPL_RE = re.compile(r'ps3_hle_register(_ctx|_fast)?\s*\(\s*(0x[0-9A-Fa-f]+)[uU]?\s*,\s*(?:"([^"]+)")?')
for p in glob.glob(os.path.join(REPO, 'runtime', '**', '*.c*'), recursive=True) + \
         glob.glob(os.path.join(REPO, 'libs', '**', '*.c*'), recursive=True):
    if '/tests/' in p.replace('\\', '/') or os.path.basename(p).startswith('test_'):
        continue
    for m in EXPL_RE.finditer(read(p)):
        n = int(m.group(2), 16)
        prev = reg.get(n)
        reg[n] = dict(name=m.group(3) or (prev or {}).get('name'), file=os.path.relpath(p, REPO).replace('\\', '/'),
                      stub=False, how='explicit' + (m.group(1) or ''))
    for m in re.finditer(r'ps3_hle_register(_ctx|_fast)?\s*\(\s*ps3_compute_nid\(\s*"(\w+)"\s*\)', read(p)):
        n = nid(m.group(2))
        reg[n] = dict(name=m.group(2), file=os.path.relpath(p, REPO).replace('\\', '/'),
                      stub=False, how='explicit' + (m.group(1) or ''))

# sys_net host-socket table: registered only with PS3_NET_ONLINE set
_sn = read(os.path.join(REPO, 'libs', 'network', 'sysNet.c'))
for m in re.finditer(r'\{\s*"(\w+)"\s*,\s*\w+\s*\}', _sn):
    n = nid(m.group(1))
    if n not in reg:
        reg[n] = dict(name=m.group(1), file='libs/network/sysNet.c', stub=False, how='online-only table')

# syscalls registered
defines = {}
for p in glob.glob(os.path.join(REPO, 'runtime', '**', '*.h'), recursive=True) + \
         glob.glob(os.path.join(REPO, 'include', '**', '*.h'), recursive=True):
    for m in re.finditer(r'#define\s+(SYS_\w+)\s+(\d+)', read(p)):
        defines.setdefault(m.group(1), int(m.group(2)))
sc_reg = {}
for p in glob.glob(os.path.join(REPO, 'runtime', '**', '*.c*'), recursive=True) + \
         glob.glob(os.path.join(REPO, 'libs', '**', '*.c*'), recursive=True):
    if '/tests/' in p.replace('\\', '/'):
        continue
    for m in re.finditer(r'lv2_syscall_register\s*\(\s*\w+\s*,\s*(\w+)\s*,\s*(\w+)', read(p)):
        k = m.group(1)
        num = int(k) if k.isdigit() else defines.get(k)
        if num is not None:
            sc_reg.setdefault(num, dict(handler=m.group(2), file=os.path.relpath(p, REPO).replace('\\', '/')))

# ---------------------------------------------------------------- game side
S = json.load(open(os.path.join(ROOT, 'analysis', 'elf_survey.json')))
log = read(os.path.join(ROOT, 'logs', 'baseline-race.log'))
# names of the EBOOT imports: main-module loader lines carry no {thread} tag
names = {}
for m in re.finditer(r'^\S+ \S+ ppu_loader: \*\*\*\* (\w+) import: \[(\w+)\] \(0x([0-9a-f]+)\)', log, re.M):
    names.setdefault((m.group(1), int(m.group(3), 16)), m.group(2))
# functions RPCS3 logged as called (HLE tag) + syscall usage stats
called = set(re.findall(r'\[HLE:0x[0-9a-f]+, LR:0x[0-9a-f]+\]\} \w+: (\w+)\(', log))
called |= set(re.findall(r'\u2042 (\w+) \[\d+\]', log))
lle_tags = collections.Counter(re.findall(r'\[(lib\w+): 0x', log))

rows = []
for lib in S['imports']:
    for h in lib['func_nids']:
        n = int(h, 16)
        name = names.get((lib['library'], n)) or ('?' + h)
        r = reg.get(n)
        st = 'missing' if not r else ('stub' if r['stub'] else 'done')
        rows.append(dict(library=lib['library'], nid=h, name=name, status=st,
                         impl=(r or {}).get('file'), how=(r or {}).get('how'),
                         used_in_log=name in called))

# syscalls: numbers from sc sites in EBOOT + names RPCS3 reported as used
sc_rows = []
for k, cnt in S['syscall_sites'].items():
    if k == 'None':
        continue
    k = int(k)
    sc_rows.append(dict(num=k, sites=cnt, registered=k in sc_reg, handler=(sc_reg.get(k) or {}).get('handler')))

out = dict(rows=rows, syscalls=sc_rows, lle_tags=lle_tags, n_registered_nids=len(reg), n_registered_syscalls=len(sc_reg))
json.dump(out, open(os.path.join(ROOT, 'analysis', 'import_coverage.json'), 'w'), indent=1)

# ---------------------------------------------------------------- report
per = collections.OrderedDict()
for r in rows:
    per.setdefault(r['library'], collections.Counter())[r['status']] += 1
    if r['used_in_log']:
        per[r['library']]['used'] += 1
L = []
L.append('| Библиотека | Импортов | Готово | Заглушка | Отсутствует | Видно в логе RPCS3 |')
L.append('|---|---:|---:|---:|---:|---:|')
tot = collections.Counter()
for lib, c in sorted(per.items(), key=lambda kv: -sum(v for k, v in kv[1].items() if k != 'used')):
    n = c['done'] + c['stub'] + c['missing']
    tot.update(c)
    L.append('| %s | %d | %d | %d | %d | %d |' % (lib, n, c['done'], c['stub'], c['missing'], c['used']))
L.append('| **Итого** | **%d** | **%d** | **%d** | **%d** | **%d** |' % (
    tot['done'] + tot['stub'] + tot['missing'], tot['done'], tot['stub'], tot['missing'], tot['used']))
L.append('')
L.append('### Отсутствующие и заглушки (по библиотекам)')
for lib in per:
    bad = [r for r in rows if r['library'] == lib and r['status'] != 'done']
    if bad:
        L.append('- **%s**: ' % lib + ', '.join(('%s%s%s' % ('`' + r['name'] + '`', ' (stub)' if r['status'] == 'stub' else '',
                                                              ' **[вызывается]**' if r['used_in_log'] else '')) for r in bad))
L.append('')
L.append('### Syscalls (по сайтам `sc` в EBOOT)')
miss = [s for s in sc_rows if not s['registered']]
L.append('Всего номеров: %d, зарегистрировано в ps3recomp: %d, нет: %d -> %s' % (
    len(sc_rows), len(sc_rows) - len(miss), len(miss), ', '.join('%d(x%d)' % (s['num'], s['sites']) for s in miss)))
open(os.path.join(ROOT, 'analysis', 'import_coverage.md'), 'w', encoding='utf-8').write('\n'.join(L) + '\n')
print('\n'.join(L))
print('\nregistered NIDs in ps3recomp:', len(reg), ' registered syscalls:', len(sc_reg))
print('names resolved from log:', sum(1 for r in rows if not r['name'].startswith('?')), '/', len(rows))
print('LLE code seen in RPCS3:', dict(lle_tags))
