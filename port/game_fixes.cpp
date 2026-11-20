/*
 * MotorStorm port: HLE behaviour fixes that ps3recomp gets wrong for this title.
 * Registered after ppu_hle_init(), so they override the generated NID table.
 *
 * cellGameBootCheck (NID 0xF52639EA): ps3recomp always reports attributes = 0. RPCS3 (and
 * firmware) set CELL_GAME_ATTRIBUTE_PATCH (bit 0) for a disc game whose update is installed
 * in /dev_hdd0/game/<id>. MotorStorm mounts ms3patchv0106..0101.psarc only when
 * type == DISC && (attributes & PATCH) (func_002B185C); without the bit it never sees
 * shaderpatch.rpk and later calls through NULL vtables.
 */
#include "ppu_recomp.h"
#include <cstdio>
#include <cstdlib>
#include <sys/stat.h>
#include <string>
#include <vector>
#include <map>
#include <mutex>
#include <condition_variable>
#include <atomic>
#include <thread>
#include <functional>
#include "ps3emu/nid.h"

extern "C" {
void ps3_hle_register_ctx(uint32_t nid, const char* name, void (*fn)(ppu_context*));
int32_t cellGameBootCheck(uint32_t* type, uint32_t* attributes, void* size, char* dirName);
}

extern "C" uint8_t* vm_base;
#include <cstring>
static const uint32_t CELL_GAME_ATTRIBUTE_PATCH = 1u << 0;

static bool update_installed()
{
    const char* hdd0 = getenv("PS3_HDD0_ROOT");
    if (!hdd0 || !*hdd0) return false;
    char p[1024];
    snprintf(p, sizeof p, "%s/game/BCUS98242/PARAM.SFO", hdd0);
    struct stat st;
    return stat(p, &st) == 0;
}

static void hle_cellGameBootCheck(ppu_context* ctx)
{
    /* cellGame.c takes the GUEST addresses in pointer-typed parameters. */
    uint32_t type_ea = (uint32_t)ctx->gpr[3], attr_ea = (uint32_t)ctx->gpr[4];
    int32_t rc = cellGameBootCheck((uint32_t*)(uintptr_t)type_ea, (uint32_t*)(uintptr_t)attr_ea,
                                   (void*)(uintptr_t)(uint32_t)ctx->gpr[5],
                                   (char*)(uintptr_t)(uint32_t)ctx->gpr[6]);
    if (rc == 0 && attr_ea && type_ea && vm_read32(type_ea) == 1 /* DISC */ && update_installed()) {
        vm_write32(attr_ea, vm_read32(attr_ea) | CELL_GAME_ATTRIBUTE_PATCH);
        fprintf(stderr, "[port] cellGameBootCheck: disc + installed update -> attributes |= PATCH\n");
    }
    ctx->gpr[3] = (uint64_t)(int64_t)rc;
}

/* cellSslCertificateLoader (NID 0x571AFACA): ps3recomp always reports required = 0, and the
 * title's HTTP client then dies with "CellHttpClient.cpp (128): Could not fetch proper cert
 * size", calls through NULL and exitspawns. Same behaviour as RPCS3's HLE: concatenate
 * /dev_flash/data/cert/CA%02d.cer for every set flag bit (bit i-1 -> cert i), with the
 * renumbering RPCS3 applies to the 'normal' set when the Baltimore bit is set.
 * r3 = u64 flag, r4 = buffer EA, r5 = size, r6 = required EA (non-zero: size query only). */
static std::string read_cert(int id, bool normal)
{
    enum { Baltimore = 6, Class3G2V2 = 13, ClassSSV4 = 15, EntrustNet = 18, GTECyberTrustGlobal = 23 };
    int n = id;
    if (normal && id >= Baltimore && id <= GTECyberTrustGlobal) {
        if (id == Baltimore) n = GTECyberTrustGlobal;
        else if (id == Class3G2V2) n = Baltimore;
        else if (id == EntrustNet) n = ClassSSV4;
        else n = id - 1;
    }
    const char* fw = getenv("PS3_DEV_FLASH");
    char p[1024];
    snprintf(p, sizeof p, "%s/data/cert/CA%02d.cer", fw && *fw ? fw : ".", n);
    FILE* f = fopen(p, "rb");
    if (!f) { fprintf(stderr, "[port] cellSsl: missing certificate %s\n", p); return std::string(); }
    std::string s;
    char buf[4096];
    size_t r;
    while ((r = fread(buf, 1, sizeof buf, f)) > 0) s.append(buf, r);
    fclose(f);
    return s;
}

static void hle_cellSslCertificateLoader(ppu_context* ctx)
{
    const uint64_t flag = ctx->gpr[3];
    const uint32_t buf = (uint32_t)ctx->gpr[4], size = (uint32_t)ctx->gpr[5], req = (uint32_t)ctx->gpr[6];
    const bool normal = (flag >> (6 - 1)) & 1;   /* Baltimore bit */
    std::string all;
    for (int i = 1; i <= 58; i++)
        if ((flag >> (i - 1)) & 1) all += read_cert(i, normal);
    if (req) {
        vm_write32(req, (uint32_t)all.size());
    } else if (buf && size) {
        uint32_t n = (uint32_t)all.size() < size ? (uint32_t)all.size() : size - 1;
        for (uint32_t i = 0; i + 1 < size; i++) vm_write8(buf + i, 0);
        for (uint32_t i = 0; i < n; i++) vm_write8(buf + i, (uint8_t)all[i]);
    }
    static int logged = 0;
    if (logged++ < 4)
        fprintf(stderr, "[port] cellSslCertificateLoader(flag=0x%llX, %s) -> %u bytes\n",
                (unsigned long long)flag, req ? "size query" : "fill", (unsigned)all.size());
    ctx->gpr[3] = 0;
}

/* PS3_GAME_LOG=1: print what the title passes to its stubbed debug printers (see
 * tools/patch_gamelog.py). Integer and string arguments only; a repeated format is limited to
 * its first 12 occurrences so a per-frame message cannot flood the log. */
static int game_log_readable(uint32_t ea)
{
    return (ea >= 0x00010000u && ea < 0x013C0000u) || (ea >= 0x0E000000u && ea < 0x1BA00000u) ||
           (ea >= 0xD0000000u && ea < 0xD0400000u);
}

extern "C" void port_game_log(ppu_context* ctx, int kind)
{
    static int s_on = -1;
    if (s_on < 0) s_on = getenv("PS3_GAME_LOG") ? 1 : 0;
    if (!s_on) return;
    const uint32_t fmt = (uint32_t)ctx->gpr[3];
    if (!game_log_readable(fmt)) return;
    enum { SLOTS = 4096 };
    static std::atomic<uint32_t> s_seen[SLOTS];
    static std::atomic<uint32_t> s_count[SLOTS];
    uint32_t h = (fmt * 2654435761u) >> 20;
    int slot = -1;
    for (int probe = 0; probe < 32; probe++, h = (h + 1) & (SLOTS - 1)) {
        uint32_t cur = 0;
        if (s_seen[h].compare_exchange_strong(cur, fmt) || cur == fmt) { slot = (int)h; break; }
    }
    if (slot < 0 || s_count[slot].fetch_add(1) >= 12) return;

    char out[512]; size_t n = 0; int gpr = 4;
    const auto put = [&](char c) { if (n + 1 < sizeof out) out[n++] = c; };
    for (uint32_t p = fmt, end = fmt + 300; p < end; p++) {
        char c = (char)vm_read8(p);
        if (!c) break;
        if (c != '%') { if (c != '\n') put(c); continue; }
        char spec[16]; size_t sn = 0; spec[sn++] = '%';
        char conv = 0;
        while (++p < end && sn + 2 < sizeof spec) {
            conv = (char)vm_read8(p);
            if (!conv) break;
            if (strchr("diuxXpcsfgeEG%", conv)) break;
            if (conv != 'l' && conv != 'h' && conv != 'z') spec[sn++] = conv;
        }
        if (!conv) break;
        char tmp[240]; tmp[0] = 0;
        if (conv == '%') { put('%'); continue; }
        if (conv == 'f' || conv == 'g' || conv == 'e' || conv == 'E' || conv == 'G') { snprintf(tmp, sizeof tmp, "<float>"); }
        else if (gpr > 10) { snprintf(tmp, sizeof tmp, "<stack>"); }
        else if (conv == 's') {
            const uint32_t a = (uint32_t)ctx->gpr[gpr++];
            if (game_log_readable(a)) {
                size_t i = 0;
                for (; i + 1 < sizeof tmp && i < 200; i++) { tmp[i] = (char)vm_read8(a + (uint32_t)i); if (!tmp[i]) break; }
                tmp[i] = 0;
            } else snprintf(tmp, sizeof tmp, "<ptr 0x%08X>", a);
        } else {
            const uint32_t v = (uint32_t)ctx->gpr[gpr++];
            spec[sn++] = conv == 'p' ? 'x' : conv; spec[sn] = 0;
            snprintf(tmp, sizeof tmp, spec, v);
        }
        for (const char* t = tmp; *t; t++) put(*t);
    }
    out[n] = 0;
    fprintf(stderr, "[game%d t%u lr=%08X] %s\n", kind, (unsigned)ctx->thread_id, (uint32_t)ctx->lr, out);
}

/* PS3_FUNC_TRACE=1: entry of the functions tools/patch_gamelog.py instruments. First 8 calls of each,
 * then every 4096th. */
extern "C" void port_func_trace(ppu_context* ctx, uint32_t addr)
{
    static int s_on = -1;
    if (s_on < 0) s_on = getenv("PS3_FUNC_TRACE") ? 1 : 0;
    if (!s_on) return;
    enum { SLOTS = 64 };
    static std::atomic<uint32_t> s_addr[SLOTS];
    static std::atomic<uint32_t> s_n[SLOTS];
    uint32_t c = 0;
    for (uint32_t h = (addr >> 2) % SLOTS, probe = 0; probe < SLOTS; probe++, h = (h + 1) % SLOTS) {
        uint32_t cur = 0;
        if (s_addr[h].compare_exchange_strong(cur, addr) || cur == addr) { c = s_n[h].fetch_add(1); break; }
    }
    if (c < 8 || (c & 0xFFF) == 0)
        fprintf(stderr, "[ftrace] func_%08X #%u r3=%08X r4=%08X r5=%08X lr=%08X t%u\n", addr, c,
                (uint32_t)ctx->gpr[3], (uint32_t)ctx->gpr[4], (uint32_t)ctx->gpr[5], (uint32_t)ctx->lr, (unsigned)ctx->thread_id);
}

/* PS3_MUSIC_TRACE=1: every method of the audio manager (vtable 0xFD16B4, port/music_trace.inc).
 * Slot 57 starts the front-end music and, through func_000AED50, SwapMusicWorkspaceThread; slot 7
 * calls slot 57 when its argument is non-zero. First calls of each method, then every 4096th. */
#define MT(addr, slot) \
    static void mt_##addr(ppu_context* ctx) { \
        static std::atomic<uint32_t> n{0}; const uint32_t c = n.fetch_add(1); \
        if (c < 6 || (c & 0xFFF) == 0) \
            fprintf(stderr, "[music] slot%d %s #%u this=%08X r4=%08X r5=%08X lr=%08X t%u\n", slot, #addr, c, \
                    (uint32_t)ctx->gpr[3], (uint32_t)ctx->gpr[4], (uint32_t)ctx->gpr[5], (uint32_t)ctx->lr, (unsigned)ctx->thread_id); \
        func_##addr(ctx); \
    }
#include "music_trace.inc"
#undef MT

/* cellNetCtlGetState (NID 0x8B3EBA69). ps3recomp fails the query when offline, to suit LBP. This
 * title's [CheckNetwork] state machine (func_00370CA4) treats an error as "ask again next frame",
 * so it polled forever. Answer as a console with no link: success, Disconnected (0). */
static void hle_cellNetCtlGetState(ppu_context* ctx)
{
    const uint32_t state = (uint32_t)ctx->gpr[3];
    static int s_n = 0;
    /* r31 at this call site is the [CheckNetwork] object; +0xC is its state, and the byte at
     * [0x12E74AC]+0x30 is the flag that state 2 waits for. Logged sparsely to see them over time. */
    if (s_n < 8 || (s_n & 0xFF) == 0) {
        const uint32_t obj = (uint32_t)ctx->gpr[31], g = vm_read32(0x012E74ACu);
        fprintf(stderr, "[port] cellNetCtlGetState #%d -> CELL_OK, Disconnected (lr=0x%08X) state=%u flag30=%u\n",
                s_n, (uint32_t)ctx->lr, obj ? vm_read32(obj + 0xC) : 0u, g ? (uint32_t)vm_read8(g + 0x30) : 0u);
    }
    s_n++;
    if (state) vm_write32(state, 0);
    ctx->gpr[3] = 0;
}

/* cellHttpInitCookie (NID 0x9638F766): missing in ps3recomp. Offline port, no cookie jar. */
static void hle_cellHttpInitCookie(ppu_context* ctx)
{
    fprintf(stderr, "[port] cellHttpInitCookie(pool=0x%08X, size=0x%X) -> CELL_OK (no cookies)\n",
            (uint32_t)ctx->gpr[3], (uint32_t)ctx->gpr[4]);
    ctx->gpr[3] = 0;
}

/* cellGameGetHomeDataExportPath (NID 0x59B1EDE1): missing in ps3recomp, so the title read an
 * unwritten buffer and tried to create "<garbage>rewards.xml". RPCS3 (baseline 7:04.29) answers
 * CELL_GAME_ERROR_NOAPP (PlayStation Home is gone) and writes nothing. */
static void hle_cellGameGetHomeDataExportPath(ppu_context* ctx)
{
    ctx->gpr[3] = ctx->gpr[3] ? 0x8002CB08u : 0x8002CB07u;   /* NOAPP / PARAM */
}

/* cellAdecOpenEx (NID 0x8B5551A4): missing in ps3recomp. The movie player (evologo_60.avi: MPEG-4
 * ASP video + AC-3 audio) opens its audio decoder with it; unresolved, the handle stayed unwritten
 * and the audio stream never produced PCM. Same arguments as cellAdecOpen except the resource
 * struct (CellAdecResourceEx), which the HLE decoder ignores. */
extern "C" int cellAdecOpen(const void* type, const void* res, const void* cb, void* handle);
static void hle_cellAdecOpenEx(ppu_context* ctx)
{
    ctx->gpr[3] = (uint32_t)cellAdecOpen((const void*)(uintptr_t)(uint32_t)ctx->gpr[3],
                                         (const void*)(uintptr_t)(uint32_t)ctx->gpr[4],
                                         (const void*)(uintptr_t)(uint32_t)ctx->gpr[5],
                                         (void*)(uintptr_t)(uint32_t)ctx->gpr[6]);
}

/* cellUserInfoGetStat(id, stat): ps3recomp accepted only id 1, but the title asks for
 * CELL_SYSUTIL_USERID_CURRENT (0) -- as RPCS3's baseline shows ("cellUserInfoGetStat(id=0")
 * -- got NOUSER, hashed an empty user and looked for its liveries in Liveries/00000000/
 * (RPCS3: Liveries/44c43595/). Answer for the current user like RPCS3 does.
 * CellUserInfoUserStat = { u32 id; char name[64]; }. */
static void hle_cellUserInfoGetStat(ppu_context* ctx)
{
    const uint32_t id = (uint32_t)ctx->gpr[3], stat = (uint32_t)ctx->gpr[4];
    if (!stat) { ctx->gpr[3] = 0x8002B203u; return; }   /* CELL_USERINFO_ERROR_PARAM */
    if (id != 0 && id != 1) { ctx->gpr[3] = 0x8002B204u; return; }   /* CELL_USERINFO_ERROR_NOUSER */
    vm_write32(stat, 1);
    char* name = (char*)(vm_base + stat + 4);
    memset(name, 0, 64);
    strncpy(name, "User", 63);
    fprintf(stderr, "[port] cellUserInfoGetStat(id=%u) -> user 1 'User'\n", id);
    ctx->gpr[3] = 0;
}

/* sys_mempool_* (sysPrxForUser): missing in ps3recomp; RPCS3 implements them in HLE
 * (Emu/Cell/Modules/sys_mempool.cpp). Same semantics: a pool is a vector of free block EAs
 * carved from the guest chunk, LIFO allocation, ids from 1. Host mutex/condvar instead of
 * guest sys_mutex/sys_cond (nothing in the title inspects those ids). */
struct MemPool { uint32_t chunk; uint64_t chunk_size, block_size; std::vector<uint32_t> free_blocks; };
static std::mutex s_mp_lock;
static std::condition_variable s_mp_cv;
static std::map<uint32_t, MemPool> s_mp;
static uint32_t s_mp_next = 1;

static void hle_sys_mempool_create(ppu_context* ctx)
{
    const uint32_t out = (uint32_t)ctx->gpr[3], chunk = (uint32_t)ctx->gpr[4];
    const uint64_t chunk_size = ctx->gpr[5], block_size = ctx->gpr[6];
    uint64_t align = ctx->gpr[7];
    if (align == 0 || align == 2) align = 4;
    if (!block_size || block_size > chunk_size || (align & (align - 1)) || (chunk & 7)) {
        ctx->gpr[3] = (uint64_t)(int64_t)(int32_t)0x80010002u;   /* CELL_EINVAL */
        return;
    }
    std::lock_guard<std::mutex> g(s_mp_lock);
    uint32_t id = s_mp_next++;
    MemPool& p = s_mp[id];
    p.chunk = chunk; p.chunk_size = chunk_size; p.block_size = block_size;
    for (uint64_t i = 0; i < chunk_size / block_size; i++)
        p.free_blocks.push_back(chunk + (uint32_t)(i * block_size));
    if (out) vm_write32(out, id);
    fprintf(stderr, "[port] sys_mempool_create -> id=%u chunk=0x%08X size=0x%llX block=0x%llX (%zu blocks)\n",
            id, chunk, (unsigned long long)chunk_size, (unsigned long long)block_size, p.free_blocks.size());
    ctx->gpr[3] = 0;
}

static void hle_sys_mempool_destroy(ppu_context* ctx)
{
    std::lock_guard<std::mutex> g(s_mp_lock);
    s_mp.erase((uint32_t)ctx->gpr[3]);
    s_mp_cv.notify_all();
}

static void hle_sys_mempool_free_block(ppu_context* ctx)
{
    const uint32_t id = (uint32_t)ctx->gpr[3], blk = (uint32_t)ctx->gpr[4];
    std::lock_guard<std::mutex> g(s_mp_lock);
    auto it = s_mp.find(id);
    if (it == s_mp.end() || blk > it->second.chunk + it->second.chunk_size) {
        ctx->gpr[3] = (uint64_t)(int64_t)(int32_t)0x80010002u;
        return;
    }
    it->second.free_blocks.push_back(blk);
    s_mp_cv.notify_one();
    ctx->gpr[3] = 0;
}

static void hle_sys_mempool_try_allocate_block(ppu_context* ctx)
{
    std::lock_guard<std::mutex> g(s_mp_lock);
    auto it = s_mp.find((uint32_t)ctx->gpr[3]);
    uint32_t blk = 0;
    if (it != s_mp.end() && !it->second.free_blocks.empty()) {
        blk = it->second.free_blocks.back();
        it->second.free_blocks.pop_back();
    }
    ctx->gpr[3] = blk;
}

static void hle_sys_mempool_allocate_block(ppu_context* ctx)
{
    const uint32_t id = (uint32_t)ctx->gpr[3];
    std::unique_lock<std::mutex> g(s_mp_lock);
    for (;;) {
        auto it = s_mp.find(id);
        if (it == s_mp.end()) { ctx->gpr[3] = 0; return; }
        if (!it->second.free_blocks.empty()) {
            ctx->gpr[3] = it->second.free_blocks.back();
            it->second.free_blocks.pop_back();
            return;
        }
        s_mp_cv.wait(g);
    }
}

static void hle_sys_mempool_get_count(ppu_context* ctx)
{
    std::lock_guard<std::mutex> g(s_mp_lock);
    auto it = s_mp.find((uint32_t)ctx->gpr[3]);
    ctx->gpr[3] = it == s_mp.end() ? (uint64_t)(int64_t)(int32_t)0x80010002u : it->second.free_blocks.size();
}

/* PS3_GATE_TRACE=1: log the title's spinlock "gate" objects (vtable 0x01098A08: +8 guard, +0xC gate
 * word; vtbl+0x08 = func_00E9B97C wait-until-open, vtbl+0x0C = func_00E9B9DC(open?1:close)). The main
 * thread was found waiting forever on one whose name reads "/livery...". */
extern "C" void ppu_register_function(uint64_t addr, void (*fn)(ppu_context*));
static void gate_name(uint32_t x, char* out)
{
    for (int i = 0; i < 24; i++) { uint8_t c = vm_base[x + 0x10 + i]; out[i] = (c >= 32 && c < 127) ? (char)c : '.'; }
    out[24] = 0;
}
static std::atomic<int> s_gate_n{0};
static unsigned host_tid() { return (unsigned)(std::hash<std::thread::id>{}(std::this_thread::get_id()) & 0xFFFF); }
static void gate_wait_hook(ppu_context* ctx)
{
    const uint32_t x = (uint32_t)ctx->gpr[3], lr = (uint32_t)ctx->lr;
    char nm[25]; gate_name(x, nm);
    const int n = s_gate_n++;
    if (n < 3000) fprintf(stderr, "[gate] #%d WAIT  x=0x%08X gate=%u lr=0x%08X tid=%u '%s'\n", n, x, vm_read32(x + 0xC), lr, (unsigned)ctx->thread_id, nm);
    func_00E9B97C(ctx);
}
static void gate_set_hook(ppu_context* ctx)
{
    const uint32_t x = (uint32_t)ctx->gpr[3], lr = (uint32_t)ctx->lr, open = (uint32_t)ctx->gpr[4] & 0xFF;
    char nm[25]; gate_name(x, nm);
    const int n = s_gate_n++;
    if (n < 3000) fprintf(stderr, "[gate] #%d %s x=0x%08X gate=%u lr=0x%08X tid=%u '%s'\n", n, open ? "OPEN " : "CLOSE", x, vm_read32(x + 0xC), lr, (unsigned)ctx->thread_id, nm);
    /* From job start (0x639FDC, lr 0x63A020) / job complete (0x63A3C4, lr 0x63A3FC) r31 = the job. */
    if (n < 3000 && (lr == 0x0063A020u || lr == 0x0063A3FCu)) {
        const uint32_t job = (uint32_t)ctx->gpr[31];
        fprintf(stderr, "[gate]   job=0x%08X vtbl=0x%08X:", job, vm_read32(job));
        for (int i = 0; i < 0x50; i += 4) fprintf(stderr, "%s%08X", (i % 16) ? " " : "\n[gate]     ", vm_read32(job + i));
        fprintf(stderr, "\n");
    }
    func_00E9B9DC(ctx);
}
/* EvoJob queue push (vtbl slot of 0x010989C8 -> 0x0063B5E8) and the job semaphore's
 * wait/post (vtable 0x01098A7C: +8 wait 0xE9BD0C, +0x10 post 0xE9BDA8). */
static void evo_push_hook(ppu_context* ctx)
{
    const int n = s_gate_n++;
    if (n < 3000) fprintf(stderr, "[gate] #%d EVOPUSH this=0x%08X r4=0x%08X r5=0x%08X r6=0x%08X lr=0x%08X tid=%u\n", n,
                          (uint32_t)ctx->gpr[3], (uint32_t)ctx->gpr[4], (uint32_t)ctx->gpr[5], (uint32_t)ctx->gpr[6],
                          (uint32_t)ctx->lr, (unsigned)ctx->thread_id);
    func_0063B5E8(ctx);
}
static void evo_sempost_hook(ppu_context* ctx)
{
    const int n = s_gate_n++;
    if (n < 3000) fprintf(stderr, "[gate] #%d SEMPOST obj=0x%08X sem=%u lr=0x%08X tid=%u\n", n,
                          (uint32_t)ctx->gpr[3], vm_read32((uint32_t)ctx->gpr[3] + 8), (uint32_t)ctx->lr, (unsigned)ctx->thread_id);
    func_00E9BDA8(ctx);
}

/* EvoJob worker class (vtable 0x010989B8): log every slot call. */
static void evo_slot_0063B084(ppu_context* ctx) { const int n = s_gate_n++; if (n < 3000) fprintf(stderr, "[gate] #%d EVOSLOT 0063B084 this=0x%08X r4=0x%08X lr=0x%08X tid=%u\n", n, (uint32_t)ctx->gpr[3], (uint32_t)ctx->gpr[4], (uint32_t)ctx->lr, (unsigned)ctx->thread_id); func_0063B084(ctx); }
static void evo_slot_0063B22C(ppu_context* ctx) { const int n = s_gate_n++; if (n < 3000) fprintf(stderr, "[gate] #%d EVOSLOT 0063B22C this=0x%08X r4=0x%08X lr=0x%08X tid=%u\n", n, (uint32_t)ctx->gpr[3], (uint32_t)ctx->gpr[4], (uint32_t)ctx->lr, (unsigned)ctx->thread_id); func_0063B22C(ctx); }
static void evo_slot_0063B26C(ppu_context* ctx) { const int n = s_gate_n++; if (n < 3000) fprintf(stderr, "[gate] #%d EVOSLOT 0063B26C this=0x%08X r4=0x%08X lr=0x%08X tid=%u\n", n, (uint32_t)ctx->gpr[3], (uint32_t)ctx->gpr[4], (uint32_t)ctx->lr, (unsigned)ctx->thread_id); func_0063B26C(ctx); }
static void evo_slot_0063B768(ppu_context* ctx) { const int n = s_gate_n++; if (n < 3000) fprintf(stderr, "[gate] #%d EVOSLOT 0063B768 this=0x%08X r4=0x%08X lr=0x%08X tid=%u\n", n, (uint32_t)ctx->gpr[3], (uint32_t)ctx->gpr[4], (uint32_t)ctx->lr, (unsigned)ctx->thread_id); func_0063B768(ctx); }
static void evo_slot_0063B7A0(ppu_context* ctx) { const int n = s_gate_n++; if (n < 3000) fprintf(stderr, "[gate] #%d EVOSLOT 0063B7A0 this=0x%08X r4=0x%08X lr=0x%08X tid=%u\n", n, (uint32_t)ctx->gpr[3], (uint32_t)ctx->gpr[4], (uint32_t)ctx->lr, (unsigned)ctx->thread_id); func_0063B7A0(ctx); }
static void evo_slot_0063B7F4(ppu_context* ctx) { const int n = s_gate_n++; if (n < 3000) fprintf(stderr, "[gate] #%d EVOSLOT 0063B7F4 this=0x%08X r4=0x%08X lr=0x%08X tid=%u\n", n, (uint32_t)ctx->gpr[3], (uint32_t)ctx->gpr[4], (uint32_t)ctx->lr, (unsigned)ctx->thread_id); func_0063B7F4(ctx); }
static void evo_slot_0063B800(ppu_context* ctx) { const int n = s_gate_n++; if (n < 3000) fprintf(stderr, "[gate] #%d EVOSLOT 0063B800 this=0x%08X r4=0x%08X lr=0x%08X tid=%u\n", n, (uint32_t)ctx->gpr[3], (uint32_t)ctx->gpr[4], (uint32_t)ctx->lr, (unsigned)ctx->thread_id); func_0063B800(ctx); }
static void evo_slot_0063B848(ppu_context* ctx) { const int n = s_gate_n++; if (n < 3000) fprintf(stderr, "[gate] #%d EVOSLOT 0063B848 this=0x%08X r4=0x%08X lr=0x%08X tid=%u\n", n, (uint32_t)ctx->gpr[3], (uint32_t)ctx->gpr[4], (uint32_t)ctx->lr, (unsigned)ctx->thread_id); func_0063B848(ctx); }

/* SPU (Wws) job worker class (vtable 0x01098900): log every slot call. */
static void spuw_slot_00638EEC(ppu_context* ctx) { const int n = s_gate_n++; if (n < 3000) fprintf(stderr, "[gate] #%d SPUWSLOT 00638EEC this=0x%08X r4=0x%08X r5=0x%08X lr=0x%08X tid=%u\n", n, (uint32_t)ctx->gpr[3], (uint32_t)ctx->gpr[4], (uint32_t)ctx->gpr[5], (uint32_t)ctx->lr, (unsigned)ctx->thread_id); func_00638EEC(ctx); }
static void spuw_slot_00638F2C(ppu_context* ctx) { const int n = s_gate_n++; if (n < 3000) fprintf(stderr, "[gate] #%d SPUWSLOT 00638F2C this=0x%08X r4=0x%08X r5=0x%08X lr=0x%08X tid=%u\n", n, (uint32_t)ctx->gpr[3], (uint32_t)ctx->gpr[4], (uint32_t)ctx->gpr[5], (uint32_t)ctx->lr, (unsigned)ctx->thread_id); func_00638F2C(ctx); }
static void spuw_slot_00639614(ppu_context* ctx) { const int n = s_gate_n++; if (n < 3000) fprintf(stderr, "[gate] #%d SPUWSLOT 00639614 this=0x%08X r4=0x%08X r5=0x%08X lr=0x%08X tid=%u\n", n, (uint32_t)ctx->gpr[3], (uint32_t)ctx->gpr[4], (uint32_t)ctx->gpr[5], (uint32_t)ctx->lr, (unsigned)ctx->thread_id); func_00639614(ctx); }
static void spuw_slot_00639798(ppu_context* ctx) { const int n = s_gate_n++; if (n < 3000) fprintf(stderr, "[gate] #%d SPUWSLOT 00639798 this=0x%08X r4=0x%08X r5=0x%08X lr=0x%08X tid=%u\n", n, (uint32_t)ctx->gpr[3], (uint32_t)ctx->gpr[4], (uint32_t)ctx->gpr[5], (uint32_t)ctx->lr, (unsigned)ctx->thread_id); func_00639798(ctx); }
static void spuw_slot_00639948(ppu_context* ctx) { const int n = s_gate_n++; if (n < 3000) fprintf(stderr, "[gate] #%d SPUWSLOT 00639948 this=0x%08X r4=0x%08X r5=0x%08X lr=0x%08X tid=%u\n", n, (uint32_t)ctx->gpr[3], (uint32_t)ctx->gpr[4], (uint32_t)ctx->gpr[5], (uint32_t)ctx->lr, (unsigned)ctx->thread_id); func_00639948(ctx); }
static void spuw_slot_00639988(ppu_context* ctx) { const int n = s_gate_n++; if (n < 3000) fprintf(stderr, "[gate] #%d SPUWSLOT 00639988 this=0x%08X r4=0x%08X r5=0x%08X lr=0x%08X tid=%u\n", n, (uint32_t)ctx->gpr[3], (uint32_t)ctx->gpr[4], (uint32_t)ctx->gpr[5], (uint32_t)ctx->lr, (unsigned)ctx->thread_id); func_00639988(ctx); }
static void spuw_slot_006399E4(ppu_context* ctx) { const int n = s_gate_n++; if (n < 3000) fprintf(stderr, "[gate] #%d SPUWSLOT 006399E4 this=0x%08X r4=0x%08X r5=0x%08X lr=0x%08X tid=%u\n", n, (uint32_t)ctx->gpr[3], (uint32_t)ctx->gpr[4], (uint32_t)ctx->gpr[5], (uint32_t)ctx->lr, (unsigned)ctx->thread_id); func_006399E4(ctx); }
static void spuw_slot_006399F0(ppu_context* ctx) { const int n = s_gate_n++; if (n < 3000) fprintf(stderr, "[gate] #%d SPUWSLOT 006399F0 this=0x%08X r4=0x%08X r5=0x%08X lr=0x%08X tid=%u\n", n, (uint32_t)ctx->gpr[3], (uint32_t)ctx->gpr[4], (uint32_t)ctx->gpr[5], (uint32_t)ctx->lr, (unsigned)ctx->thread_id); func_006399F0(ctx); }
static void spuw_slot_00639A50(ppu_context* ctx) { const int n = s_gate_n++; if (n < 3000) fprintf(stderr, "[gate] #%d SPUWSLOT 00639A50 this=0x%08X r4=0x%08X r5=0x%08X lr=0x%08X tid=%u\n", n, (uint32_t)ctx->gpr[3], (uint32_t)ctx->gpr[4], (uint32_t)ctx->gpr[5], (uint32_t)ctx->lr, (unsigned)ctx->thread_id); func_00639A50(ctx); }
static void spuw_slot_00639A8C(ppu_context* ctx) { const int n = s_gate_n++; if (n < 3000) fprintf(stderr, "[gate] #%d SPUWSLOT 00639A8C this=0x%08X r4=0x%08X r5=0x%08X lr=0x%08X tid=%u\n", n, (uint32_t)ctx->gpr[3], (uint32_t)ctx->gpr[4], (uint32_t)ctx->gpr[5], (uint32_t)ctx->lr, (unsigned)ctx->thread_id); func_00639A8C(ctx); }

static uint32_t nid_of(const char* name) { return ps3_compute_nid(name); }

extern "C" void port_register_game_fixes(void)
{
    if (getenv("PS3_GATE_TRACE")) { ppu_register_function(0x00E9B97C, gate_wait_hook); ppu_register_function(0x00E9B9DC, gate_set_hook);
                                    ppu_register_function(0x0063B5E8, evo_push_hook); ppu_register_function(0x00E9BDA8, evo_sempost_hook);
                                    ppu_register_function(0x0063B084, evo_slot_0063B084); ppu_register_function(0x0063B22C, evo_slot_0063B22C); ppu_register_function(0x0063B26C, evo_slot_0063B26C); ppu_register_function(0x0063B768, evo_slot_0063B768); ppu_register_function(0x0063B7A0, evo_slot_0063B7A0); ppu_register_function(0x0063B7F4, evo_slot_0063B7F4); ppu_register_function(0x0063B800, evo_slot_0063B800); ppu_register_function(0x0063B848, evo_slot_0063B848);
                                    ppu_register_function(0x00638EEC, spuw_slot_00638EEC); ppu_register_function(0x00638F2C, spuw_slot_00638F2C); ppu_register_function(0x00639614, spuw_slot_00639614); ppu_register_function(0x00639798, spuw_slot_00639798); ppu_register_function(0x00639948, spuw_slot_00639948); ppu_register_function(0x00639988, spuw_slot_00639988); ppu_register_function(0x006399E4, spuw_slot_006399E4); ppu_register_function(0x006399F0, spuw_slot_006399F0); ppu_register_function(0x00639A50, spuw_slot_00639A50); ppu_register_function(0x00639A8C, spuw_slot_00639A8C); }
    ps3_hle_register_ctx(nid_of("sys_mempool_create"),             "sys_mempool_create",             hle_sys_mempool_create);
    ps3_hle_register_ctx(nid_of("sys_mempool_destroy"),            "sys_mempool_destroy",            hle_sys_mempool_destroy);
    ps3_hle_register_ctx(nid_of("sys_mempool_free_block"),         "sys_mempool_free_block",         hle_sys_mempool_free_block);
    ps3_hle_register_ctx(nid_of("sys_mempool_try_allocate_block"), "sys_mempool_try_allocate_block", hle_sys_mempool_try_allocate_block);
    ps3_hle_register_ctx(nid_of("sys_mempool_allocate_block"),     "sys_mempool_allocate_block",     hle_sys_mempool_allocate_block);
    ps3_hle_register_ctx(nid_of("sys_mempool_get_count"),          "sys_mempool_get_count",          hle_sys_mempool_get_count);
    ps3_hle_register_ctx(0xF52639EAu, "cellGameBootCheck", hle_cellGameBootCheck);
    ps3_hle_register_ctx(0x571AFACAu, "cellSslCertificateLoader", hle_cellSslCertificateLoader);
    ps3_hle_register_ctx(0x9638F766u, "cellHttpInitCookie", hle_cellHttpInitCookie);
    if (getenv("PS3_MUSIC_TRACE")) {
#define MT(addr, slot) ppu_register_function(0x##addr, mt_##addr);
#include "music_trace.inc"
#undef MT
    }
    if (!getenv("PS3_NETCTL_ERROR"))
        ps3_hle_register_ctx(0x8B3EBA69u, "cellNetCtlGetState", hle_cellNetCtlGetState);
    ps3_hle_register_ctx(nid_of("cellUserInfoGetStat"), "cellUserInfoGetStat", hle_cellUserInfoGetStat);
    ps3_hle_register_ctx(0x59B1EDE1u, "cellGameGetHomeDataExportPath", hle_cellGameGetHomeDataExportPath);
    ps3_hle_register_ctx(0x8B5551A4u, "cellAdecOpenEx", hle_cellAdecOpenEx);
}
