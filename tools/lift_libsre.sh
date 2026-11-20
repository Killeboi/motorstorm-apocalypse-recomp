#!/usr/bin/env bash
# Relocate + lift the user-decrypted firmware libsre.prx for LLE SPURS.
# Inputs : firmware/libsre.prx (decrypted by the user; never committed)
# Outputs: firmware/libsre_out/ (image, exports, imports, functions, hle_stubs.json)
#          recompiled_prx/libsre/ (lifted C++, prefix libsre_)
set -euo pipefail
cd /c/msa-port
PY="py -3.14 -I -X utf8"
BASE=0x30000000
OUT=firmware/libsre_out
LIFT=recompiled_prx/libsre
mkdir -p "$OUT" "$LIFT"

$PY repo/tools/lift_prx.py firmware/libsre.prx --base $BASE --output "$OUT/"

# imports.json {lib:{nid:stub}} -> [{library,nid,stub}] for --hle-stubs;
# code end = end of the first executable PT_LOAD, relocated to BASE.
$PY - "$OUT" $BASE <<'EOF'
import json, struct, sys
out, base = sys.argv[1], int(sys.argv[2], 16)
im = json.load(open(f'{out}/libsre_imports.json'))
rows = [{'library': lib, 'nid': nid.lower(), 'stub': stub.lower()}
        for lib, d in im.items() for nid, stub in d.items()]
json.dump(rows, open(f'{out}/libsre_hle_stubs.json', 'w'), indent=1)
d = open('firmware/libsre.prx', 'rb').read()
phoff, phnum = struct.unpack('>Q', d[32:40])[0], struct.unpack('>H', d[56:58])[0]
for i in range(phnum):
    o = phoff + i * 56
    t, fl = struct.unpack('>II', d[o:o + 8]); va, fs = struct.unpack('>Q', d[o + 16:o + 24])[0], struct.unpack('>Q', d[o + 32:o + 40])[0]
    if t == 1 and fl & 1:
        open(f'{out}/code_end.txt', 'w').write(hex(base + va + fs)); break
print('hle stubs', len(rows), 'code_end', open(f'{out}/code_end.txt').read())
EOF

TOC=$($PY -c "import json;print(json.load(open('$OUT/libsre_exports.json'))['toc'])")
$PY repo/tools/ppu_lifter.py "$OUT/libsre_image.bin" --raw --base $BASE --toc "$TOC" \
    --code-end "$(cat $OUT/code_end.txt)" \
    --functions "$OUT/libsre_functions.json" --hle-stubs "$OUT/libsre_hle_stubs.json" \
    --symbol-prefix libsre_ --header-name libsre_recomp.h --source-name libsre_recomp.cpp \
    --output "$LIFT/"

# NID -> base-0 OPD vaddr table for prx_module.exports
$PY repo/tools/prx_exports.py firmware/libsre.prx --symbol libsre --out "$LIFT/libsre_exports.c" --json "$OUT/libsre_exports_c.json"
