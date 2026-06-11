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

#ifdef BOB_WATCHDOG
#include <windows.h>
/* If lifted code spins, dump the recent call ring (the histogram's top names
 * are the spin loop) and bail. Enable with -DBOB_WATCHDOG. */
static DWORD WINAPI watchdog_thread(LPVOID p) {
    (void)p;
    Sleep(4000);
    fprintf(stderr, "\n[watchdog] 4s elapsed - lifted code still running:\n");
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

    /* 1) Initialize the UTOPIA engine (LibMain) with the engine DGROUP in DS. */
    cpu.ds = cpu.es = CATZ_DLL_AUTO_DATA_SEG;
    cpu.ss = CATZ_STACK_SEG;
    cpu.sp = CATZ_STACK_SP ? CATZ_STACK_SP : 0xFFFE;
    cpu.cs = CATZ_DLL_ENTRY_SEG;
#ifdef BOB_WATCHDOG
    CreateThread(NULL, 0, watchdog_thread, NULL, 0, NULL);
#endif
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
