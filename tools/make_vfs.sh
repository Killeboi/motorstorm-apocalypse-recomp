#!/usr/bin/env bash
# Build C:\msa-port\vfs from the originals. Originals are only READ (copied):
# ps3recomp has no read-only enforcement for /dev_bdvd, and the game calls
# utime() on ms3.psarc, so a direct mount or hardlink could touch the Steam copy.
#
#   vfs/disc/PS3_GAME/...                    <- Steam disc copy     (PS3_VFS_ROOT=vfs/disc)
#   vfs/dev_hdd0/game/BCUS98242/...          <- RPCS3 update dir: PARAM.SFO + ms3patchv0101..0106
#                                              (unmodified root copies; no modded/, no EBOOT, no .edat DLC)
#   vfs/dev_hdd0/home/00000001/              <- empty user (saves, trophies)  (PS3_HDD0_ROOT=vfs/dev_hdd0)
#   vfs/dev_hdd1/                            <- empty cache partition         (PS3_HDD1_ROOT=vfs/dev_hdd1)
#   vfs/dev_flash/                           <- copy of RPCS3 firmware tree   (PS3_DEV_FLASH=vfs/dev_flash)
set -euo pipefail
DISC="/c/Program Files (x86)/Steam/steamapps/common/MotorStorm - Apocalypse (USA) (En,Fr,De,Es,It,Nl,Pt,Sv,No,Da,Fi,Ko,Pl,Ru) (v02.00)/PS3_GAME"
UPD="/c/rpcs3/dev_hdd0/game/BCUS98242"
FLASH="/c/rpcs3/dev_flash"
V="/c/msa-port/vfs"

mkdir -p "$V/disc" "$V/dev_hdd0/game/BCUS98242/USRDIR" "$V/dev_hdd0/home/00000001" "$V/dev_hdd1" "$V/dev_flash"
[ -d "$V/disc/PS3_GAME" ] || cp -r "$DISC" "$V/disc/PS3_GAME"
for f in "$UPD"/*; do [ -f "$f" ] && cp -n "$f" "$V/dev_hdd0/game/BCUS98242/"; done
for n in 01 02 03 04 05 06; do cp -n "$UPD/USRDIR/ms3patchv01$n.psarc" "$V/dev_hdd0/game/BCUS98242/USRDIR/"; done
[ -d "$V/dev_flash/sys" ] || cp -r "$FLASH"/. "$V/dev_flash/"
# verify the patch copies match the unmodified originals
( cd "$UPD/USRDIR" && sha256sum ms3patchv01*.psarc ) > "$V/patch_src.sha256"
( cd "$V/dev_hdd0/game/BCUS98242/USRDIR" && sha256sum ms3patchv01*.psarc ) > "$V/patch_dst.sha256"
diff "$V/patch_src.sha256" "$V/patch_dst.sha256" && echo "patches verified"
du -sh "$V"/*
