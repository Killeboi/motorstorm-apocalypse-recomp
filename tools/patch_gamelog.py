#!/usr/bin/env python3
"""Instrument the generated PPU source. Re-run after every PPU lift. Idempotent.

1. func_00AE0E68 and func_00B88374 (the title's debug printers, empty in the retail build) call
   port_game_log (PS3_GAME_LOG=1, port/game_fixes.cpp).
2. The functions in TRACE call port_func_trace on entry (PS3_FUNC_TRACE=1). Most calls are direct,
   so ppu_register_function cannot intercept them; the generated source has to change.

Usage: py -3.14 -I tools/patch_gamelog.py [recompiled_dir]
"""
import glob
import sys
from pathlib import Path

LOGGERS = ("func_00AE0E68", "func_00B88374")
# Callers of the audio manager's front-end/prologue music methods (vtable 0xFD16B4).
TRACE = ("001BA2B0", "002A9648", "005392DC",   # slot 57
         "001D16C4", "001EFC20", "004D320C", "004D6620",   # slot 7
         "002A9230", "002A9588", "004FB2B8",   # slot 60
         "00C42CA0", "002A94CC", "002A951C", "002A96C4", "002A97B8", "002A9824",   # class 0x1003E80
         "001ACD50", "001AD900")   # race game mode class 0xFDDBC0
LOG_DECL = 'extern "C" void port_game_log(ppu_context* ctx, int kind);'
TRACE_DECL = 'extern "C" void port_func_trace(ppu_context* ctx, uint32_t addr);'


def insert(data, target, decl, stmt):
    """Returns (data, state) with state one of 'absent', 'present', 'patched'."""
    head = f"void {target}(ppu_context* ctx) {{\n".encode()
    nl = b"\n"
    if head not in data:
        head = head.replace(b"\n", b"\r\n")
        nl = b"\r\n"
    if head not in data:
        return data, "absent"
    call = b"    " + stmt.encode() + nl
    if head + call in data:
        return data, "present"
    return data.replace(head, decl.encode() + nl + head + call, 1), "patched"


def main():
    root = Path(sys.argv[1] if len(sys.argv) > 1 else "recompiled")
    wanted = {name: (LOG_DECL, f"port_game_log(ctx, {kind});") for kind, name in enumerate(LOGGERS)}
    for addr in TRACE:
        wanted[f"func_{addr}"] = (TRACE_DECL, f"port_func_trace(ctx, 0x{addr}u);")
    found = set()
    for name in sorted(glob.glob(str(root / "ppu_recomp_*.cpp"))):
        path = Path(name)
        data = path.read_bytes()
        changed = False
        for target, (decl, stmt) in wanted.items():
            if target in found:
                continue
            data, state = insert(data, target, decl, stmt)
            if state == "absent":
                continue
            found.add(target)
            changed |= state == "patched"
            print(f"{path.name}: {target} {state}")
        if changed:
            path.write_bytes(data)
    missing = sorted(set(wanted) - found)
    if missing:
        sys.exit(f"not found: {missing}")


main()
