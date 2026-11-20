#!/usr/bin/env bash
# Run the port against vfs/ with a hard time limit; full output goes to logs/port-<stamp>.log.
# Usage: tools/run_port.sh [seconds=120] [extra VAR=value ...]
set -u
SECS="${1:-120}"; shift || true
V=C:/msa-port/vfs
STAMP=$(date +%Y%m%d-%H%M%S)
LOG=/c/msa-port/logs/port-$STAMP.log
export PS3_VFS_ROOT=$V/disc
export PS3_HDD0_ROOT=$V/dev_hdd0
export PS3_HDD1_ROOT=$V/dev_hdd1
export PS3_DEV_FLASH=$V/dev_flash
export PS3_TITLE="MotorStorm Apocalypse (recomp)"
export PS3_HLE_UNRESOLVED=${PS3_HLE_UNRESOLVED:-fail}
# Multistream relocates its DSP .pic plugins into LS at run time: no lift can match them.
export SPU_INTERP_UNLIFTED=${SPU_INTERP_UNLIFTED:-1}
# Multistream's taskset: real taskset PM stops inside its MP3 task; serve its syscalls by HLE.
export SPU_TASKSET_FORCE_HLE=${SPU_TASKSET_FORCE_HLE:-0137A880}
# No PlayStation Eye (as in RPCS3): with the virtual camera the title re-opened it forever after loading.
export PS3_CAMERA=${PS3_CAMERA:-0}
# Present without waiting for vblank: with vsync the frame-start GPU drain cost ~0.2 s per heavy
# frame in automated runs (4.5 fps instead of 8.4, GPU load 1%). D3D12_VSYNC=1 to get it back.
export D3D12_VSYNC=${D3D12_VSYNC:-0}
# Draw the scene target straight from the GPU where the title blits its (SPU post-processed)
# frame from main memory to the display buffer. GCM_RT_BLIT_COMPOSITE=0 to turn off.
export GCM_RT_BLIT_COMPOSITE=${GCM_RT_BLIT_COMPOSITE:-1}
for kv in "$@"; do export "$kv"; done
cd /c/msa-port/vfs
echo "== $(date) secs=$SECS extra=$*" > "$LOG"
timeout -k 5 "$SECS" /c/msa-port/build/port/MotorStormRecomp.exe C:/msa-port/elf/EBOOT.elf >> "$LOG" 2>&1
rc=$?
echo "== exit $rc" >> "$LOG"
echo "$LOG exit=$rc lines=$(wc -l < "$LOG")"
