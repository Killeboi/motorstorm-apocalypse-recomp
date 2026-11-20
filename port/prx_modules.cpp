/*
 * MotorStorm port: LLE firmware modules -- load the user's own decrypted, lifted PRX.
 *
 * Artifacts per module (local only, never committed; tools/lift_prx_module.sh <name> <base>):
 *   firmware/<name>_out/<name>_image.bin   relocated image (read at run time: no firmware
 *                                           bytes are compiled into the exe)
 *   recompiled_prx/<name>/*.cpp            lifted code, symbols prefixed <name>_
 *   recompiled_prx/<name>/<name>_exports.c NID -> base-0 OPD vaddr
 *
 * Once loaded, ps3_hle_call() (runtime/ppu/ppu_hle.cpp) resolves every NID a module exports
 * to the lifted firmware instead of the HLE stub; cross-module imports go the same way.
 *
 * PS3_LLE=<comma list> overrides which modules load (default: all below); PS3_LLE=none -> HLE only.
 * PS3_LLE_DIR=<dir>    directory holding <name>_out/ (default C:/msa-port/firmware).
 */
#include "prx_loader.h"
#include "ppu_recomp.h"   /* ppu_context (lr) */
extern "C" void ppu_register_function(uint64_t addr, void (*fn)(ppu_context*));
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>
#include <map>
#include <mutex>
#include <thread>
#include <chrono>
#include <algorithm>


#define LLE_MODULE_DECL(n)                                                     \
    extern "C" const prx_func_entry n##_function_table[];                     \
    extern "C" const uint64_t       n##_function_table_count;                 \
    extern "C" const prx_export     n##_exports[];                            \
    extern "C" const uint32_t       n##_export_count;
LLE_MODULE_DECL(libsre)
LLE_MODULE_DECL(libfont)
LLE_MODULE_DECL(libfontFT)
LLE_MODULE_DECL(libfreetype)

struct LleModule {
    const char* name;
    uint32_t base, code_start, code_end;          /* code range: firmware/<name>_out/code_range.txt */
    const prx_func_entry* funcs; const uint64_t* func_count;
    const prx_export* exports;   const uint32_t* export_count;
};
#define LLE(n, b, cs, ce) { #n, b, cs, ce, n##_function_table, &n##_function_table_count, n##_exports, &n##_export_count }
static const LleModule kModules[] = {
    LLE(libsre,      0x30000000u, 0x30000000u, 0x3002E000u),   /* SPURS / cellSync */
    LLE(libfont,     0x30100000u, 0x30100000u, 0x3010D860u),   /* cellFont */
    LLE(libfontFT,   0x30200000u, 0x30200000u, 0x30209DDCu),   /* cellFontFT */
    LLE(libfreetype, 0x30300000u, 0x30300000u, 0x3036C7B8u),   /* cell_FreeType2 */
};

static void reg(uint32_t guest, void (*host)(void*))
{
    ppu_register_function(guest, (void (*)(ppu_context*))host);
}

static bool wanted(const char* name)
{
    const char* sel = getenv("PS3_LLE");
    if (!sel || !*sel) return true;
    if (!strcmp(sel, "none")) return false;
    std::string s = std::string(",") + sel + ",";
    return s.find(std::string(",") + name + ",") != std::string::npos;
}

static void load_one(const LleModule& m, const char* dir)
{
    char path[1024];
    snprintf(path, sizeof path, "%s/%s_out/%s_image.bin", dir, m.name, m.name);
    uint32_t size = 0;
    uint8_t* img = prx_image_load_file(path, &size);
    if (!img) { fprintf(stderr, "[lle] %s: image %s not readable -- staying on HLE\n", m.name, path); return; }

    /* The raw-mode lift can emit spurious entries outside the module (tail-entry wrapper
     * artefacts). Registering them would shadow real game functions, so only the module's
     * own code range goes into the dispatch table. */
    std::vector<prx_func_entry> funcs;
    for (uint64_t i = 0; i < *m.func_count; i++) {
        const prx_func_entry& f = m.funcs[i];
        if (f.addr >= m.code_start && f.addr < m.code_end) funcs.push_back(f);
    }
    prx_module pm = {};
    pm.name = m.name; pm.base = m.base; pm.image = img; pm.image_size = size;
    pm.funcs = funcs.data(); pm.func_count = funcs.size();
    pm.exports = m.exports; pm.export_count = *m.export_count;
    prx_load_result r = prx_load_module(&pm, reg);
    fprintf(stderr, "[lle] %-11s %s: %u/%llu funcs, %u exports, image %u bytes @0x%08X\n",
            m.name, r.ok ? "OK" : "FAILED", r.funcs_registered, (unsigned long long)*m.func_count,
            *m.export_count, size, m.base);
    free(img);   /* prx_load_module copied it into guest RAM */
}

/* ---------------------------------------------------------------------------
 * PS3_ZLIB_CHECK=1: verify edgezlib's output against a host inflate.
 *
 * The title decompresses psarc blocks IN PLACE: the compressed block sits at the tail of
 * a 64 KB output buffer (src + srcSize == dst + 0x10000) and is pushed to the edgezlib
 * task through _cellSpursLFQueuePushBody (element: src, dst, srcSize, dstMax, ...).
 * A wrapper module re-exports that NID (last loaded export wins), snapshots the
 * compressed bytes at push time, and on the next push into the same buffer (the
 * previous request has completed and been consumed by then) inflates the snapshot on
 * the host and compares it with guest memory -- excluding the tail the new compressed
 * block already overwrote.
 * -------------------------------------------------------------------------*/
extern "C" int stbi_zlib_decode_noheader_buffer(char* obuffer, int olen, const char* ibuffer, int ilen);
extern "C" uint32_t vm_read32(uint64_t addr);
extern "C" uint8_t* vm_base;

extern "C" __declspec(thread) void (*g_trampoline_fn)(void*);   /* ppu_recomp: cross-fragment chain */
/* Run a lifted function to completion the way lifted callers do (call + DRAIN_TRAMPOLINE):
 * a lifted body may return with the rest of its work queued as a trampoline. */
static void run_lifted(void (*fn)(void*), void* ctx)
{
    fn(ctx);
    while (g_trampoline_fn) { void (*tf)(void*) = g_trampoline_fn; g_trampoline_fn = 0; tf(ctx); }
}
static void (*s_push_orig)(void*) = nullptr;
static void (*s_wait_orig)(void*) = nullptr;
static std::mutex s_z_lock;
static uint32_t s_z_seq, s_z_ok, s_z_bad, s_z_undecodable;
/* Queue element (built at 0x0099DC84): +0 src, +4 dst, +8 compressed size, +0xC bytes to keep,
 * +0x10 &slot.busy|1, +0x14 event flag, +0x18 u16 bits, +0x1A u16 skip head, +0x1C u16 skip tail.
 * The fios layer reads a 64K block in 4K windows (skip 0,0x1000,... ) -- edgezlib inflates the
 * whole stream and PUTs only [skip, skip+keep). */
struct ZPending { uint32_t dst = 0, seq = 0, skip = 0, keep = 0; std::vector<uint8_t> src; };
static thread_local ZPending t_z;
struct ctx_view { uint64_t gpr[32]; };   /* ppu_context starts with gpr[32] */

static void zcheck_push(void* vctx)
{
    const uint32_t el = (uint32_t)((ctx_view*)vctx)->gpr[4];
    const uint32_t src = vm_read32(el), dst = vm_read32(el + 4), ssz = vm_read32(el + 8);
    { std::lock_guard<std::mutex> g(s_z_lock); t_z.seq = ++s_z_seq; }
    t_z.dst = dst;
    t_z.keep = vm_read32(el + 12);
    t_z.skip = vm_read32(el + 0x18) & 0xFFFFu;
    t_z.src.assign(vm_base + src, vm_base + src + ssz);
    run_lifted(s_push_orig, vctx);
}

/* cellSpursEventFlagWait override (always installed).
 *
 * The fios loader waits for edgezlib with push -> clear -> wait. Under the LLE libsre the
 * wait returned CELL_SPURS_TASK_ERROR_BUSY ~98% of the time: the flag kept a stale
 * ppuWaitMask (PPU lwarx/stwcx vs SPU GETLLAR/PUTLLC on the same line), so the loader
 * read the output buffer before the SPU wrote it and re-requested blocks forever.
 * For that one call site the wait goes to ps3recomp's HLE, which polls the guest events
 * word and registers no PPU waiter. Every other flag (Multistream, Havok, ...) keeps the
 * real libsre wait -- the HLE one never wakes for Multistream.
 * PS3_EFWAIT_HLE_LR=<hex lr>[,...] overrides the call-site list (default 0x00E7D278). */
extern "C" int32_t cellSpursEventFlagWait(void* eventFlag, void* bits, uint32_t mode);   /* libs/spurs HLE */

static bool efwait_hle_site(uint32_t lr)
{
    static uint32_t s_lr[8]; static int s_n = -1;
    if (s_n < 0) {
        s_n = 0;
        const char* e = getenv("PS3_EFWAIT_HLE_LR");
        if (!e) e = "00E7D278";
        while (*e && s_n < 8) {
            char* end = nullptr;
            unsigned long v = strtoul(e, &end, 16);
            if (end == e) break;
            s_lr[s_n++] = (uint32_t)v;
            if (*end != ',') break;
            e = end + 1;
        }
    }
    for (int i = 0; i < s_n; i++) if (s_lr[i] == lr) return true;
    return false;
}

/* Lost wake-up of the edgezlib SPURS task (NOTES 2026-11-07): after a pause the task sits in
 * WAIT_SIGNAL (taskset.waiting bit set) while a request lies in the ANY2ANY LFQueue, and the LLE
 * push never set its signalled bit. Wait with TryWait and, if the flag has not come for 50 ms,
 * send the task a signal ourselves (_cellSpursSendSignal, LLE export 0xE0A6DBE4) -- a spurious
 * signal only makes it re-check its queue. PS3_EZ_KICK=<taskset hex>:<task> (default
 * 16332C00:0), PS3_EZ_KICK=0 disables (plain blocking HLE wait). */
extern "C" int32_t cellSpursEventFlagTryWait(void* eventFlag, void* bits, uint32_t mode);
extern "C" uint64_t ppu_guest_call(uint32_t opd, uint64_t a0, uint64_t a1, uint64_t a2, uint64_t a3,
                                   uint64_t a4, uint64_t a5, uint64_t a6, uint64_t a7);
static int32_t efwait_with_kick(ppu_context* ctx)
{
    static uint32_t s_ts = 0, s_task = 0; static int s_on = -1;
    if (s_on < 0) {
        const char* e = getenv("PS3_EZ_KICK");
        if (e && e[0] == '0' && !e[1]) s_on = 0;
        else { s_on = 1; s_ts = 0x16332C00u;
               if (e) { char* d; s_ts = (uint32_t)strtoul(e, &d, 16); if (*d == ':') s_task = (uint32_t)strtoul(d + 1, 0, 10); } }
    }
    void* ef = (void*)(uintptr_t)(uint32_t)ctx->gpr[3];
    void* bits = (void*)(uintptr_t)(uint32_t)ctx->gpr[4];
    const uint32_t mode = (uint32_t)ctx->gpr[5];
    if (!s_on) return cellSpursEventFlagWait(ef, bits, mode);
    const uint16_t pattern = (uint16_t)(vm_base[(uint32_t)ctx->gpr[4]] << 8 | vm_base[(uint32_t)ctx->gpr[4] + 1]);
    static uint32_t s_send = 0; if (!s_send) s_send = prx_resolve_export(0xE0A6DBE4u);
    static long s_kicks = 0;
    for (int ms = 0;; ms++) {
        /* TryWait overwrites *bits with the current events on failure too -- restore it. */
        vm_base[(uint32_t)ctx->gpr[4]] = (uint8_t)(pattern >> 8); vm_base[(uint32_t)ctx->gpr[4] + 1] = (uint8_t)pattern;
        const int32_t rc = cellSpursEventFlagTryWait(ef, bits, mode);
        if (rc != (int32_t)0x8041090Au) return rc;            /* not BUSY: done (or a real error) */
        if (ms >= 50 && (ms % 50) == 0 && s_send) {
            const uint32_t waiting = vm_read32(s_ts + 0x50), signalled = vm_read32(s_ts + 0x40);
            const uint32_t bit = 0x80000000u >> (s_task & 31);
            if ((waiting & bit) && !(signalled & bit)) {
                ppu_guest_call(s_send, s_ts, s_task, 0, 0, 0, 0, 0, 0);
                if (s_kicks++ < 20) fprintf(stderr, "[ez-kick] signalled taskset 0x%08X task %u after %d ms\n", s_ts, s_task, ms);
            }
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
}

static void efwait_override(void* vctx)
{
    ppu_context* ctx = (ppu_context*)vctx;
    if (efwait_hle_site((uint32_t)ctx->lr)) {
        int32_t rc = efwait_with_kick(ctx);
        ctx->gpr[3] = (uint64_t)(int64_t)rc;
    } else {
        run_lifted(s_wait_orig, vctx);
    }
    if (!t_z.dst) return;               /* PS3_ZLIB_CHECK bookkeeping below */
    std::vector<char> out(0x10000);
    const int n = stbi_zlib_decode_noheader_buffer(out.data(), (int)out.size(),
                      (const char*)t_z.src.data(), (int)t_z.src.size());
    std::lock_guard<std::mutex> g(s_z_lock);
    if (n <= 0) {
        if (s_z_undecodable++ < 4)
            fprintf(stderr, "[zcheck] #%u dst=0x%08X: host inflate failed (%d)\n", t_z.seq, t_z.dst, n);
    } else {
        uint32_t bad = 0, first = 0xFFFFFFFFu;
        const int lo = (int)t_z.skip, hi = std::min(n, (int)(t_z.skip + t_z.keep));
        for (int i = lo; i < hi; i++)
            if ((uint8_t)out[i] != vm_base[t_z.dst + i - lo]) { if (first == 0xFFFFFFFFu) first = (uint32_t)(i - lo); bad++; }
        if (bad) {
            if (s_z_bad++ < 12)
                fprintf(stderr, "[zcheck] #%u dst=0x%08X MISMATCH %u/%d bytes, first at +0x%X\n",
                        t_z.seq, t_z.dst, bad, n, first);
        } else {
            s_z_ok++;
        }
        if (((s_z_ok + s_z_bad) % 500) == 0)
            fprintf(stderr, "[zcheck] blocks ok=%u bad=%u undecodable=%u pushes=%u\n",
                    s_z_ok, s_z_bad, s_z_undecodable, s_z_seq);
    }
    t_z.dst = 0;
}

static void (*orig_of(uint32_t nid))(void*)
{
    const uint32_t opd = prx_resolve_export(nid);
    if (!opd) return nullptr;
    const uint32_t code = vm_read32(opd);
    for (uint64_t i = 0; i < libsre_function_table_count; i++)
        if (libsre_function_table[i].addr == code) return libsre_function_table[i].func;
    return nullptr;
}

static void install_overrides(bool zcheck)
{
    const uint32_t kPush = 0x8A85674Du, kWait = 0x373523D4u, kBase = 0x30F00000u, kToc = 0x30039AB0u;
    s_wait_orig = orig_of(kWait);
    if (zcheck) s_push_orig = orig_of(kPush);
    if (!s_wait_orig || (zcheck && !s_push_orig)) { fprintf(stderr, "[lle-fix] libsre push/wait not found\n"); return; }
    /* OPDs {code, toc} at +0x0 (push) / +0x8 (wait), code stubs at +0x20 / +0x30 */
    static uint8_t img[0x40];
    const uint32_t w[4] = { kBase + 0x20, kToc, kBase + 0x30, kToc };
    for (int k = 0; k < 4; k++)
        for (int b = 0; b < 4; b++) img[k * 4 + b] = (uint8_t)(w[k] >> (24 - 8 * b));
    static const prx_func_entry fn[2] = { { kBase + 0x20, zcheck_push,     "zcheck_push" },
                                          { kBase + 0x30, efwait_override, "efwait_override" } };
    static const prx_export ex_all[2] = { { kWait, 0x8 }, { kPush, 0x0 } };
    prx_module pm = {};
    pm.name = "lle-fix"; pm.base = kBase; pm.image = img; pm.image_size = sizeof img;
    pm.funcs = fn; pm.func_count = 2; pm.exports = ex_all; pm.export_count = zcheck ? 2 : 1;
    prx_load_module(&pm, reg);
    fprintf(stderr, "[lle-fix] cellSpursEventFlagWait override installed%s\n",
            zcheck ? " (+ PS3_ZLIB_CHECK push wrapper)" : "");
}

extern "C" void ps3_load_prx_modules(void)
{
    const char* dir = getenv("PS3_LLE_DIR");
    if (!dir || !*dir) dir = "C:/msa-port/firmware";
    for (const LleModule& m : kModules)
        if (wanted(m.name)) load_one(m, dir);
    install_overrides(getenv("PS3_ZLIB_CHECK") != nullptr);
}
