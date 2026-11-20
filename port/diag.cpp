/*
 * MotorStorm port: hang watchdog.
 *
 * PS3_HANG_DUMP=<seconds>        first dump this long after boot (0/unset = off)
 * PS3_HANG_DUMP_EVERY=<seconds>  repeat interval (default 15)
 *
 * Each dump prints (to stderr):
 *   - which HLE each guest thread is inside right now (g_hle_inflight),
 *   - every guest thread's lr / r3 / sp (ppu_report_guest_lrs),
 *   - for every host thread: where its RIP is, and the lifted guest functions
 *     found as return addresses on its host stack (func_XXXXXXXX+off).
 *
 * Adapted from the watchdog in ps3recomp's runtime/ppu/tests/boot_main.cpp,
 * which the project template does not include.
 */
#ifdef _WIN32
#include <windows.h>
#include <tlhelp32.h>
#include <cstdio>
#include <cstdlib>
#include <cstdint>
#include <cstring>
#include <string>
#include "ppu_recomp.h"

extern "C" const char* g_hle_inflight[];
extern "C" uint32_t    g_last_hle_nid;
extern "C" const char* g_last_hle_name;
extern "C" void        ppu_report_guest_lrs(void);

static const unsigned kInflight = 64;

/* Host pointer -> containing lifted guest function, or 0 when not attributable. */
static uint32_t guest_of(uintptr_t v, uintptr_t* off)
{
    uintptr_t best = 0, next = 0, maxh = 0; uint32_t g = 0;
    for (uint64_t q = 0; q < function_table_count; q++) {
        uintptr_t h = (uintptr_t)function_table[q].func;
        if (h > maxh) maxh = h;
        if (h <= v && h > best) { best = h; g = (uint32_t)function_table[q].addr; }
    }
    for (uint64_t q = 0; q < function_table_count; q++) {
        uintptr_t h = (uintptr_t)function_table[q].func;
        if (h > best && (next == 0 || h < next)) next = h;
    }
    if (!g || best == maxh || v - best > 0x4000u) return 0;
    *off = v - best;
    return g;
}

/* PS3_HOST_WWATCH: the most recent write that left the watched word NON-ZERO (e.g. who took a
 * spinlock and never released it), printed by every hang dump. */
static char s_ww_last[2048];
static volatile LONG s_ww_last_n = 0;
static __declspec(thread) char t_ww_buf[2048];

static void dump_once(HMODULE self, int n)
{
    fprintf(stderr, "[HANG] ===== dump %d; last HLE 0x%08X (%s)\n", n, g_last_hle_nid,
            g_last_hle_name ? g_last_hle_name : "");
    for (unsigned t = 0; t < kInflight; t++)
        if (g_hle_inflight[t]) fprintf(stderr, "[HANG] guest-tid %-3u inside HLE %s\n", t, g_hle_inflight[t]);
    ppu_report_guest_lrs();
    if (s_ww_last_n) fprintf(stderr, "[HANG] last non-zero write to watched word (hit #%ld):\n%s", s_ww_last_n, s_ww_last);

    /* PS3_HANG_FIND=<hex>[,<hex>...]: scan committed guest memory 0x00010000..0x40000000 for
     * big-endian u32 values in [v, v+0x10) and print where they are (first 40 per value) --
     * "who holds a pointer to this counter". */
    if (const char* fl = getenv("PS3_HANG_FIND")) {
        const char* p = fl;
        while (*p) {
            char* endp = nullptr;
            uint32_t v = (uint32_t)strtoul(p, &endp, 16);
            if (endp == p) break;
            int hits = 0;
            for (uint32_t base = 0x00010000u; base < 0x40000000u && hits < 40; ) {
                MEMORY_BASIC_INFORMATION mbi;
                if (!VirtualQuery(vm_base + base, &mbi, sizeof mbi)) break;
                uint32_t rend = (uint32_t)((uint8_t*)mbi.BaseAddress + mbi.RegionSize - vm_base);
                if (rend <= base) break;
                if (mbi.State == MEM_COMMIT && !(mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD))) {
                    for (uint32_t a = base & ~3u; a + 4 <= rend && hits < 40; a += 4) {
                        const uint8_t* b = vm_base + a;
                        uint32_t w = (uint32_t)b[0] << 24 | (uint32_t)b[1] << 16 | (uint32_t)b[2] << 8 | b[3];
                        if (w - v < 0x10u) { fprintf(stderr, "[HANG] find 0x%08X: at 0x%08X = 0x%08X\n", v, a, w); hits++; }
                    }
                }
                base = rend;
            }
            p = (*endp == ',') ? endp + 1 : endp;
            if (!*endp) break;
        }
    }
    /* PS3_HANG_CHAIN=<hex>:<+off>:<+off>...[,...]: follow guest pointers (each step: a = u32[a] + off)
     * and dump 64 bytes at the end -- heap layouts differ from run to run. */
    if (const char* cl = getenv("PS3_HANG_CHAIN")) {
        std::string all(cl); size_t pos = 0;
        while (pos <= all.size()) {
            size_t c = all.find(',', pos); if (c == std::string::npos) c = all.size();
            std::string one = all.substr(pos, c - pos); pos = c + 1;
            if (one.empty()) break;
            uint32_t a = (uint32_t)strtoul(one.c_str(), 0, 16);
            fprintf(stderr, "[HANG] chain %s: %08X", one.c_str(), a);
            size_t q = one.find(':');
            while (q != std::string::npos) {
                uint32_t off = (uint32_t)strtoul(one.c_str() + q + 1, 0, 16);
                const uint8_t* b = vm_base + a;
                a = ((uint32_t)b[0] << 24 | (uint32_t)b[1] << 16 | (uint32_t)b[2] << 8 | b[3]) + off;
                fprintf(stderr, " -> %08X", a);
                q = one.find(':', q + 1);
            }
            fprintf(stderr, "\n");
            for (int r = 0; r < 4; r++) {
                fprintf(stderr, "[HANG]   %08X:", a + 16 * r);
                for (int w = 0; w < 4; w++) { const uint8_t* b = vm_base + a + 16 * r + 4 * w;
                    fprintf(stderr, " %02X%02X%02X%02X", b[0], b[1], b[2], b[3]); }
                fprintf(stderr, "\n");
            }
        }
    }
    /* PS3_HANG_MEM=<hex>[,<hex>...]: big-endian guest u32 at each address (+next 3 words). */
    if (const char* mlist = getenv("PS3_HANG_MEM")) {
        const char* p = mlist;
        while (*p) {
            char* endp = nullptr;
            unsigned long a = strtoul(p, &endp, 16);
            if (endp == p) break;
            fprintf(stderr, "[HANG] mem %08lX:", a);
            for (int w = 0; w < 4; w++) {
                const uint8_t* b = vm_base + (uint32_t)(a + 4 * w);
                fprintf(stderr, " %02X%02X%02X%02X", b[0], b[1], b[2], b[3]);
            }
            fprintf(stderr, "\n");
            p = (*endp == ',') ? endp + 1 : endp;
            if (!*endp) break;
        }
    }

    /* PS3_HANG_SAVE=<hexEA>:<hexLen>:<path>[;...]: write raw guest memory to files (first dump only). */
    if (const char* sl = getenv("PS3_HANG_SAVE")) {
        static int saved = 0;
        if (!saved) {
            saved = 1;
            std::string all(sl);
            size_t pos = 0;
            while (pos < all.size()) {
                size_t semi = all.find(';', pos);
                std::string item = all.substr(pos, semi == std::string::npos ? std::string::npos : semi - pos);
                pos = semi == std::string::npos ? all.size() : semi + 1;
                size_t c1 = item.find(':'), c2 = c1 == std::string::npos ? c1 : item.find(':', c1 + 1);
                if (c2 == std::string::npos) continue;
                uint32_t ea = (uint32_t)strtoul(item.substr(0, c1).c_str(), 0, 16);
                uint32_t len = (uint32_t)strtoul(item.substr(c1 + 1, c2 - c1 - 1).c_str(), 0, 16);
                std::string path = item.substr(c2 + 1);
                if (FILE* f = fopen(path.c_str(), "wb")) {
                    fwrite(vm_base + ea, 1, len, f);
                    fclose(f);
                    fprintf(stderr, "[HANG] saved guest 0x%08X+0x%X -> %s\n", ea, len, path.c_str());
                }
            }
        }
    }

    /* Collect first, print after resume: a suspended thread may hold the CRT lock. */
    static char buf[1 << 16];
    DWORD me = GetCurrentThreadId(), pid = GetCurrentProcessId();
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    THREADENTRY32 te; te.dwSize = sizeof te;
    if (snap == INVALID_HANDLE_VALUE) return;
    if (Thread32First(snap, &te)) do {
        if (te.th32OwnerProcessID != pid || te.th32ThreadID == me) continue;
        HANDLE th = OpenThread(THREAD_GET_CONTEXT | THREAD_SUSPEND_RESUME, FALSE, te.th32ThreadID);
        if (!th) continue;
        size_t len = 0; buf[0] = 0;
        int frames = 0;
        if (SuspendThread(th) != (DWORD)-1) {
            CONTEXT c; c.ContextFlags = CONTEXT_CONTROL;
            if (GetThreadContext(th, &c)) {
                uintptr_t off = 0;
                uint32_t g = guest_of((uintptr_t)c.Rip, &off);
                HMODULE m = NULL;
                GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                                   GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, (LPCSTR)c.Rip, &m);
                char mod[MAX_PATH] = "?";
                if (m && m != self) { GetModuleFileNameA(m, mod, sizeof mod); }
                const char* base = strrchr(mod, '\\');
                len += snprintf(buf + len, sizeof buf - len, "[HANG] tid %5lu rip %s",
                                (unsigned long)te.th32ThreadID,
                                m == self ? "EXE" : (base ? base + 1 : mod));
                if (g) len += snprintf(buf + len, sizeof buf - len, " func_%08X+0x%llX", g, (unsigned long long)off);
                len += snprintf(buf + len, sizeof buf - len, "\n");

                uint64_t* sp = (uint64_t*)c.Rsp;
                MEMORY_BASIC_INFORMATION mbi;
                if (VirtualQuery(sp, &mbi, sizeof mbi) && mbi.State == MEM_COMMIT &&
                    !(mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD))) {
                    uint64_t end = (uint64_t)mbi.BaseAddress + mbi.RegionSize;
                    long maxk = (long)((end - (uint64_t)sp) / 8);
                    if (maxk > 0x200000 / 8) maxk = 0x200000 / 8;
                    uint32_t last = 0;
                    /* PS3_HANG_RVA=1: also print EXE return addresses that are not lifted PPU
                     * code (SPU lifted functions, runtime) as RVAs -- resolve them with the
                     * linker map (tools/symbolize.py). */
                    static int s_rva = -1; if (s_rva < 0) s_rva = getenv("PS3_HANG_RVA") ? 1 : 0;
                    const uintptr_t ib = (uintptr_t)self;
                    const IMAGE_NT_HEADERS* nt = (const IMAGE_NT_HEADERS*)(ib + ((const IMAGE_DOS_HEADER*)ib)->e_lfanew);
                    const uintptr_t ie = ib + nt->OptionalHeader.SizeOfImage;
                    int rvas = 0;
                    for (long k = 0; k < maxk && frames < 24 && len < sizeof buf - 128; k++) {
                        uintptr_t o2 = 0;
                        uint32_t gg = guest_of((uintptr_t)sp[k], &o2);
                        if (gg && gg != last) {
                            len += snprintf(buf + len, sizeof buf - len, "[HANG]        <- func_%08X+0x%llX\n",
                                            gg, (unsigned long long)o2);
                            last = gg; frames++;
                        } else if (!gg && s_rva && rvas < 20 && (uintptr_t)sp[k] > ib + 0x1000 && (uintptr_t)sp[k] < ie) {
                            len += snprintf(buf + len, sizeof buf - len, "[HANG]        <- rva 0x%llX\n",
                                            (unsigned long long)((uintptr_t)sp[k] - ib));
                            rvas++; frames++;
                        }
                    }
                }
            }
            ResumeThread(th);
        }
        CloseHandle(th);
        /* skip host-only threads parked in a DLL with no guest frames: they are noise */
        if (frames || strstr(buf, "func_")) fputs(buf, stderr);
    } while (Thread32Next(snap, &te));
    CloseHandle(snap);
    fflush(stderr);
}

static DWORD WINAPI hang_thread(LPVOID)
{
    const char* e = getenv("PS3_HANG_DUMP");
    unsigned first = e ? (unsigned)atoi(e) : 0;
    const char* r = getenv("PS3_HANG_DUMP_EVERY");
    unsigned every = r ? (unsigned)atoi(r) : 15;
    if (!every) every = 15;
    HMODULE self = GetModuleHandleA(NULL);
    Sleep(first * 1000u);
    for (int n = 1;; n++) { dump_once(self, n); Sleep(every * 1000u); }
    return 0;
}

/* ---------------------------------------------------------------------------
 * PS3_HOST_WWATCH=<hex guest EA>: catch EVERY write to that guest word, including
 * writes made by host code (HLE handlers, loader, memcpy) that PPU_WWATCH cannot
 * see. The 4 KB host page is made read-only; the first-chance AV handler logs
 * writes that hit [ea, ea+4), re-opens the page, single-steps the faulting
 * instruction, and re-protects it. Diagnostic only: slow on a hot page, and a
 * write racing on another thread during the single step can slip through.
 * -------------------------------------------------------------------------*/
static uintptr_t s_ww_host = 0, s_ww_page = 0;
static uint32_t  s_ww_ea = 0;
static volatile LONG s_ww_hits = 0;
static __declspec(thread) int s_ww_stepping = 0;

static LONG WINAPI ww_veh(EXCEPTION_POINTERS* ep)
{
    DWORD code = ep->ExceptionRecord->ExceptionCode;
    if (code == EXCEPTION_ACCESS_VIOLATION && s_ww_page) {
        ULONG_PTR kind = ep->ExceptionRecord->ExceptionInformation[0];  /* 1 = write */
        uintptr_t a = (uintptr_t)ep->ExceptionRecord->ExceptionInformation[1];
        if (kind == 1 && (a & ~(uintptr_t)0xFFF) == s_ww_page) {
            if (a + 8 > s_ww_host && a < s_ww_host + 4) {
                LONG n = InterlockedIncrement(&s_ww_hits);
                {   int k2 = 0; uintptr_t o1 = 0;
                    uint32_t g1 = guest_of((uintptr_t)ep->ContextRecord->Rip, &o1);
                    k2 += snprintf(t_ww_buf + k2, sizeof t_ww_buf - k2, "[HANG]   host tid %lu hit #%ld at func_%08X+0x%llX\n",
                                   GetCurrentThreadId(), n, g1, (unsigned long long)o1);
                    uint64_t* sp1 = (uint64_t*)ep->ContextRecord->Rsp; uint32_t last1 = 0; int fr1 = 0;
                    for (int k = 0; k < 4096 && fr1 < 14 && k2 < (int)sizeof t_ww_buf - 64; k++) {
                        uintptr_t o2 = 0; uint32_t gg = guest_of((uintptr_t)sp1[k], &o2);
                        if (gg && gg != last1) { k2 += snprintf(t_ww_buf + k2, sizeof t_ww_buf - k2, "[HANG]     <- func_%08X+0x%llX\n", gg, (unsigned long long)o2); last1 = gg; fr1++; }
                    }
                    t_ww_buf[sizeof t_ww_buf - 1] = 0; }
                if (n <= 64) {
                    uintptr_t off = 0;
                    HMODULE self = GetModuleHandleA(NULL);
                    uint32_t g = guest_of((uintptr_t)ep->ContextRecord->Rip, &off);
                    const uint8_t* b = (const uint8_t*)s_ww_host;
                    fprintf(stderr, "[hww] #%ld write to 0x%08X (old %02X%02X%02X%02X) host rip rva=0x%llX%s",
                            n, s_ww_ea, b[0], b[1], b[2], b[3],
                            (unsigned long long)(ep->ContextRecord->Rip - (DWORD64)self),
                            g ? "" : "\n");
                    if (g) fprintf(stderr, " func_%08X+0x%llX\n", g, (unsigned long long)off);
                    uint64_t* sp = (uint64_t*)ep->ContextRecord->Rsp;
                    uint32_t last = 0; int fr = 0;
                    for (int k = 0; k < 4096 && fr < 10; k++) {
                        uintptr_t o2 = 0; uint32_t gg = guest_of((uintptr_t)sp[k], &o2);
                        if (gg && gg != last) { fprintf(stderr, "[hww]     <- func_%08X+0x%llX\n", gg, (unsigned long long)o2); last = gg; fr++; }
                    }
                    fflush(stderr);
                }
            }
            DWORD old;
            VirtualProtect((void*)s_ww_page, 0x1000, PAGE_READWRITE, &old);
            ep->ContextRecord->EFlags |= 0x100;   /* trap after this one instruction */
            s_ww_stepping = 1;
            return EXCEPTION_CONTINUE_EXECUTION;
        }
    }
    if (code == EXCEPTION_SINGLE_STEP && s_ww_stepping) {
        s_ww_stepping = 0;
        const uint8_t* b = (const uint8_t*)s_ww_host;
        if (b[0] | b[1] | b[2] | b[3]) { memcpy(s_ww_last, t_ww_buf, sizeof s_ww_last); s_ww_last_n = s_ww_hits; }
        if (s_ww_hits <= 64)
            fprintf(stderr, "[hww]     new %02X%02X%02X%02X\n", b[0], b[1], b[2], b[3]);
        DWORD old;
        VirtualProtect((void*)s_ww_page, 0x1000, PAGE_READONLY, &old);
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

/* Called after the ELF is loaded (the page is committed and holds its initial bytes). */
static void wwatch_arm_now(void);
static DWORD WINAPI wwatch_delay_thread(LPVOID p) { Sleep((DWORD)(uintptr_t)p); wwatch_arm_now(); return 0; }
/* PS3_HOST_WWATCH_DELAY=<s>: arm later -- a heap page that sys_memory maps after boot loses an
 * early PAGE_READONLY when it is (re)committed. */
extern "C" void port_host_wwatch_arm(void)
{
    const char* e = getenv("PS3_HOST_WWATCH");
    if (!e || !*e) return;
    if (const char* d = getenv("PS3_HOST_WWATCH_DELAY")) {
        CreateThread(NULL, 0, wwatch_delay_thread, (LPVOID)(uintptr_t)(atoi(d) * 1000u), 0, NULL);
        return;
    }
    wwatch_arm_now();
}
static void wwatch_arm_now(void)
{
    const char* e = getenv("PS3_HOST_WWATCH");
    s_ww_ea = (uint32_t)strtoul(e, 0, 16);
    s_ww_host = (uintptr_t)(vm_base + s_ww_ea);
    s_ww_page = s_ww_host & ~(uintptr_t)0xFFF;
    volatile uint8_t touch = *(volatile uint8_t*)s_ww_host; (void)touch;   /* commit it */
    AddVectoredExceptionHandler(1, ww_veh);
    DWORD old;
    BOOL ok = VirtualProtect((void*)s_ww_page, 0x1000, PAGE_READONLY, &old);
    const uint8_t* b = (const uint8_t*)s_ww_host;
    fprintf(stderr, "[hww] armed on guest 0x%08X (initial %02X%02X%02X%02X) protect=%s\n",
            s_ww_ea, b[0], b[1], b[2], b[3], ok ? "ok" : "FAILED");
}

extern "C" void port_hang_watchdog_start(void)
{
    const char* e = getenv("PS3_HANG_DUMP");
    if (e && atoi(e) > 0) CreateThread(NULL, 0, hang_thread, NULL, 0, NULL);
}
#else
extern "C" void port_hang_watchdog_start(void) {}
extern "C" void port_host_wwatch_arm(void) {}
#endif
