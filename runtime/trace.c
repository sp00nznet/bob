/* trace.c - Definitions for the lifted-code call-trace ring (declared in cpu.h).
 *
 * Every lifted function calls TRACE_FN(name), which records the name in this
 * fixed-size ring so a crash can print the last N frames. The host main loop
 * (added at bringup) reads these; defining them here keeps the lifted engine +
 * host + blitter archive self-contained (only libc remains unresolved). */
#include "cpu.h"

const char *g_fn_ring[CATZ_FN_RING_SIZE];
unsigned g_fn_ring_pos = 0;
