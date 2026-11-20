# Contributing

1. **Never commit game data or generated code**: no ELF/SELF/SPRX/PRX, `.psarc`, lifted
   `recompiled/` or `port/spu*/` output, firmware, screenshots of game assets, or logs.
   PRs containing them will be closed.
2. Changes to ps3recomp go into `patches/` as a new numbered patch (and regenerate
   `ALL-repo-changes.patch`). Title-specific code goes into `port/`.
3. Say how you verified a change: which log/run, what you saw (frame captures, fps, `FAULT` count).
   "Built fine" is not "works".
4. Add a short entry to `NOTES.md` (Russian or English is fine) when you find or fix something.
5. Open an issue before big refactors so work isn't duplicated.
