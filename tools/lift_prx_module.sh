#!/usr/bin/env bash
# Relocate + lift one user-decrypted firmware PRX for LLE.
# Usage: tools/lift_prx_module.sh <name> <base>      e.g.  libfont 0x30100000
# Inputs : firmware/<name>.prx (decrypted by the user; never committed)
# Outputs: firmware/<name>_out/   image, exports, imports, functions, hle_stubs, code range
#          recompiled_prx/<name>/ lifted C++ (symbol prefix <name>_) + <name>_exports.c
set -euo pipefail
cd /c/msa-port
NAME=$1
BASE=$2
PY="py -3.14 -X utf8"
OUT=firmware/${NAME}_out
LIFT=recompiled_prx/$NAME
mkdir -p "$OUT" "$LIFT"

$PY repo/tools/lift_prx.py "firmware/$NAME.prx" --base "$BASE" --output "$OUT/"

# imports.json {lib:{nid:stub}} -> [{library,nid,stub}] for --hle-stubs;
# code range = first executable PT_LOAD, relocated to BASE (code_start/code_end).
py -3.14 -I - "$OUT" "$NAME" "$BASE" <<'EOF'
import json, struct, sys
out, name, base = sys.argv[1], sys.argv[2], int(sys.argv[3], 16)
im = json.load(open(f'{out}/{name}_imports.json'))
rows = [{'library': lib, 'nid': nid.lower(), 'stub': stub.lower()}
        for lib, d in im.items() for nid, stub in d.items()]
json.dump(rows, open(f'{out}/{name}_hle_stubs.json', 'w'), indent=1)
d = open(f'firmware/{name}.prx', 'rb').read()
phoff, phnum = struct.unpack('>Q', d[32:40])[0], struct.unpack('>H', d[56:58])[0]
for i in range(phnum):
    o = phoff + i * 56
    t, fl = struct.unpack('>II', d[o:o + 8])
    va, fs = struct.unpack('>Q', d[o + 16:o + 24])[0], struct.unpack('>Q', d[o + 32:o + 40])[0]
    if t == 1 and fl & 1:
        open(f'{out}/code_range.txt', 'w').write('%#x %#x\n' % (base + va, base + va + fs))
        break
print('hle stubs', len(rows), 'code range', open(f'{out}/code_range.txt').read())
EOF

read CODE_START CODE_END < "$OUT/code_range.txt"
TOC=$(py -3.14 -I -c "import json;print(json.load(open('$OUT/${NAME}_exports.json'))['toc'])")
$PY repo/tools/ppu_lifter.py "$OUT/${NAME}_image.bin" --raw --base "$BASE" --toc "$TOC" \
    --code-end "$CODE_END" \
    --functions "$OUT/${NAME}_functions.json" --hle-stubs "$OUT/${NAME}_hle_stubs.json" \
    --symbol-prefix "${NAME}_" --header-name "${NAME}_recomp.h" --source-name "${NAME}_recomp.cpp" \
    --output "$LIFT/"

# NID -> base-0 OPD vaddr table for prx_module.exports
$PY repo/tools/prx_exports.py "firmware/$NAME.prx" --symbol "$NAME" --out "$LIFT/${NAME}_exports.c"
echo "$NAME base=$BASE toc=$TOC code=$CODE_START..$CODE_END"
