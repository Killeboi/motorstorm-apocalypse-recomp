#!/usr/bin/env python3
"""Wrapper for repo/tools/spu_lifter.py that adds --return-entries.

SPURS tasks are resumed after a context switch at the SPU PC they yielded from: the
return address of the task-syscall call (bisl to the policy's 0xA70). Without
--return-entries that address is the middle of a lifted function, the dispatcher finds
no entry there, and the task falls back to the interpreter (MotorStorm: Multistream's MP3
task resumed at LS 0x16470 and then stopped inside the policy).

Used via build_spu_workloads.py --lifter tools/spu_lifter_ret.py.
"""
import os, runpy, sys

LIFTER = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'repo', 'tools', 'spu_lifter.py')
if '--return-entries' not in sys.argv:
    sys.argv.append('--return-entries')
sys.argv[0] = LIFTER
sys.path.insert(0, os.path.dirname(LIFTER))
runpy.run_path(LIFTER, run_name='__main__')
