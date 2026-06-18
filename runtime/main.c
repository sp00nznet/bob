/*
 * main.c - Microsoft Bob recomp runtime entry (bring-up host).
 *
 * Loads the combined flat image (UTOPIA engine + UEXTRA blitter + UTOPIAWA host,
 * with internal relocations applied), builds the selector->base table and the
 * initial CPU/segment state from the NE headers, then:
 *   1) runs the UTOPIA engine DLL entry (LibMain) with the engine DGROUP in DS,
 *   2) runs the UTOPIAWA host entry (Borland C0 -> WinMain), which drives the
 *      engine through the cross-module calls the lifter resolved to direct C.
 *
 * This is the first execution attempt; it is expected to stop on the first
 * unimplemented Win16 shim. That stop *is* the signal for which API to flesh
 * out next (hottest-first; see analysis/utopia_imports.txt). Build with
 * -DBOB_WATCHDOG to dump the call ring if lifted code spins.
 */
#include "cpu.h"
#include "segments.h"
#include "mem_layout.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef CATZ_IMAGE_PATH
#define CATZ_IMAGE_PATH "build_data/mem_image.bin"
#endif

extern CPU *g_cpu;   /* defined below; referenced by the watchdog */

#ifdef BOB_WATCHDOG
#include <windows.h>
/* If lifted code spins, dump the recent call ring (the histogram's top names
 * are the spin loop) and bail. Enable with -DBOB_WATCHDOG. */
static DWORD WINAPI watchdog_thread(LPVOID p) {
    (void)p;
    Sleep(4000);
    fprintf(stderr, "\n[watchdog] 4s elapsed - lifted code still running.\n");
    fprintf(stderr, "--- last 30 calls in order (most recent last) ---\n");
    for (int i = 30; i >= 1; i--) {
        const char *nm = g_fn_ring[(g_fn_ring_pos - (unsigned)i) & (CATZ_FN_RING_SIZE - 1)];
        if (nm) fprintf(stderr, "  %s\n", nm);
    }
    if (g_cpu)
        fprintf(stderr, "regs: ax=%04X bx=%04X cx=%04X dx=%04X si=%04X di=%04X "
                "bp=%04X sp=%04X ds=%04X es=%04X ss=%04X cs=%04X\n",
                g_cpu->ax, g_cpu->bx, g_cpu->cx, g_cpu->dx, g_cpu->si, g_cpu->di,
                g_cpu->bp, g_cpu->sp, g_cpu->ds, g_cpu->es, g_cpu->ss, g_cpu->cs);
    dump_fn_ring(0);
    fflush(stderr);
    _exit(99);
    return 0;
}
#endif

/* Function-entry ring buffer (declared in cpu.h, filled by every TRACE_FN). */
const char *g_fn_ring[CATZ_FN_RING_SIZE];
unsigned g_fn_ring_pos = 0;

/* Global CPU pointer so the Win16 backend / WndProc bridge can invoke guest
 * code (the registered window procedure) on delivered messages, once wired. */
CPU *g_cpu = NULL;

/* Dump the recent call ring as a histogram — the most frequent names are the
 * spin loop if we hang. Called from the assert path in cpu.h and the watchdog. */
void dump_fn_ring(int n)
{
    if (n <= 0 || n > (int)CATZ_FN_RING_SIZE) n = (int)CATZ_FN_RING_SIZE;
    const char *names[256]; int counts[256]; int nd = 0;
    for (unsigned i = 0; i < CATZ_FN_RING_SIZE; i++) {
        const char *nm = g_fn_ring[i];
        if (!nm) continue;
        int j = 0; for (; j < nd; j++) if (names[j] == nm) break;
        if (j == nd && nd < 256) { names[nd] = nm; counts[nd] = 0; nd++; }
        if (j < 256) counts[j]++;
    }
    fprintf(stderr, "--- ring histogram (top spin functions) ---\n");
    for (int top = 0; top < 15; top++) {
        int best = -1;
        for (int j = 0; j < nd; j++)
            if (counts[j] >= 0 && (best < 0 || counts[j] > counts[best])) best = j;
        if (best < 0 || counts[best] <= 0) break;
        fprintf(stderr, "  %5d  %s\n", counts[best], names[best]);
        counts[best] = -1;
    }
    fprintf(stderr, "--- end (total calls=%u) ---\n", g_fn_ring_pos);
}

#ifdef CATZ_WATCH_SP
/* Flag the first time guest SP jumps UP sharply between function entries — a
 * callee that returned with an imbalanced stack (bad epilogue / unrestored
 * push / wrong retf cleanup). Pinpoints the offending function. */
void catz_sp_check(const char *nm)
{
    static uint16_t last = 0xFFFE; static int armed = 0, fired = 0;
    uint16_t sp = g_cpu ? g_cpu->sp : 0xFFFE;
    if (sp < 0xF000) armed = 1;
    if (!fired && armed && sp > last && (uint16_t)(sp - last) > 0x100 && sp > 0xFD00) {
        fired = 1;
        fprintf(stderr, "[SP-RISE] at %s: sp %04X -> %04X (+%04X). recent:",
                nm, last, sp, (uint16_t)(sp - last));
        for (int i = 10; i > 0; i--) {
            const char *r = g_fn_ring[(g_fn_ring_pos - (unsigned)i) & (CATZ_FN_RING_SIZE - 1)];
            if (r) fprintf(stderr, " %s", r);
        }
        fprintf(stderr, "\n");
    }
    last = sp;
}
#endif

static int load_image(CPU *cpu, const char *path)
{
    FILE *f = fopen(path, "rb");
    if (!f) { fprintf(stderr, "cannot open image: %s\n", path); return 0; }
    size_t n = fread(cpu->mem, 1, CATZ_IMAGE_SIZE, f);
    fclose(f);
    if (n != CATZ_IMAGE_SIZE) {
        fprintf(stderr, "short read: %zu of %u\n", n, (unsigned)CATZ_IMAGE_SIZE);
        return 0;
    }
    return 1;
}

int main(int argc, char *argv[])
{
    const char *img = (argc > 1) ? argv[1] : CATZ_IMAGE_PATH;

    CPU cpu;
    cpu_init(&cpu);
    g_cpu = &cpu;

    /* Flat image + a heap for dynamically allocated selectors past the image.
     * Bob targeted ~8 MB machines; 24 MB bounds the engine's free-memory probe
     * (GlobalAlloc-until-fail) to a realistic count. */
    uint32_t total = CATZ_IMAGE_SIZE + (24u << 20);
    if (!cpu_alloc_mem(&cpu, total)) {
        fprintf(stderr, "Failed to allocate %u bytes\n", total);
        return 1;
    }
    if (!load_image(&cpu, img)) { cpu_free(&cpu); return 1; }

    /* selector -> flat base: NE segment n maps to SEG_SEGMENT_BASE[n]; every
     * other selector falls back to the guard region. */
    for (uint32_t s = 0; s < 0x10000; ++s)
        cpu.sel_base[s] = CATZ_GUARD_BASE;
    for (uint32_t n = 0; n <= (uint32_t)CATZ_NUM_SEG; ++n)
        cpu.sel_base[n] = SEG_SEGMENT_BASE[n];

    printf("Microsoft Bob Recomp - starting\n");
    printf("  image: %s (%.2f MB)\n", img, CATZ_IMAGE_SIZE / 1048576.0);
    printf("  engine entry: seg%u:%04X (UTOPIA LibMain), engine-data seg%u\n",
           CATZ_DLL_ENTRY_SEG, CATZ_DLL_ENTRY_IP, CATZ_DLL_AUTO_DATA_SEG);
    printf("  host entry:   seg%u:%04X (UTOPIAWA), host-data seg%u, stack seg%u\n",
           CATZ_ENTRY_SEG, CATZ_ENTRY_IP, CATZ_AUTO_DATA_SEG, CATZ_STACK_SEG);
    fflush(stdout);

    /* 1) Initialize the UTOPIA engine (LibMain). The engine's C-runtime startup
     *    accesses DGROUP globals via ss:[abs] (small-model SS==DS==DGROUP), so
     *    run it with SS=DS=engine DGROUP (now allocated a full 64 KB so the
     *    stack at sp=0xFFFE and the statics at the bottom share one segment). */
#ifdef BOB_WATCHDOG
    CreateThread(NULL, 0, watchdog_thread, NULL, 0, NULL);
#endif

    /* 0.5) MSAJT110 (the Jet 1.1 database engine) is a DEPENDENCY of UTOPIA, so
     *      Windows loads + initializes it BEFORE UTOPIA's LibMain. Mirror that:
     *      run its NE entry (seg45:0 = LibEntry -> Jet C-runtime + LibMain) with
     *      SS=DS=its DGROUP (seg146, full 64 KB) first. LibEntry convention:
     *      DI=hInstance, DS=auto-data, CX=heap, ES:SI=lpszCmdLine. */
    cpu.ds = cpu.es = 146;
    cpu.ss = 146; cpu.sp = 0xFFFE;
    cpu.di = 146; cpu.cx = 0; cpu.si = 0;
    cpu.cs = 45;
    unsigned callsJ = g_fn_ring_pos;
    seg045_0000(&cpu);                      /* MSAJT110 LibEntry (seg45:0) */
    printf("MSAJT110 LibMain returned (ax=%04X) after %u lifted calls\n",
           cpu.ax, g_fn_ring_pos - callsJ);
    fflush(stdout);

    cpu.ds = cpu.es = CATZ_DLL_AUTO_DATA_SEG;
    cpu.ss = CATZ_DLL_AUTO_DATA_SEG;
    cpu.sp = 0xFFFE;
    cpu.cs = CATZ_DLL_ENTRY_SEG;
    unsigned calls0 = g_fn_ring_pos;
    seg005_120D(&cpu);                      /* UTOPIA LibMain (seg5:0x120D) */
    printf("UTOPIA LibMain returned (ax=%04X) after %u lifted calls\n",
           cpu.ax, g_fn_ring_pos - calls0);
    fflush(stdout);

    /* 2) Run the UTOPIAWA host startup (Borland C0 -> WinMain): window +
     *    message loop, driving the engine via resolved cross-module calls. */
    cpu.ds = cpu.es = CATZ_AUTO_DATA_SEG;
    cpu.ss = CATZ_STACK_SEG;
    cpu.sp = CATZ_STACK_SP ? CATZ_STACK_SP : 0xFFFE;
    cpu.cs = CATZ_ENTRY_SEG;
    unsigned calls1 = g_fn_ring_pos;
    seg035_0002(&cpu);                      /* UTOPIAWA entry (seg35:0x0002) */
    printf("UTOPIAWA host returned (ax=%04X) after %u lifted calls\n",
           cpu.ax, g_fn_ring_pos - calls1);
    printf("total lifted calls: %u\n", g_fn_ring_pos);

    cpu_free(&cpu);
    return 0;
}
