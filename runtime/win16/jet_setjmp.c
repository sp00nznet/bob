/* jet_setjmp.c - see jet_setjmp.h. */
#include "runtime_api.h"
#include "jet_setjmp.h"
#include <stdio.h>

#ifdef ELFISH_TRACE_RUNTIME
#define JMP_LOG(...) fprintf(stderr, __VA_ARGS__)
#else
#define JMP_LOG(...) ((void)0)
#endif

/* ponytail: a flat array, deepest last. Jet nests these a handful deep; if a
 * program ever overflows it the push just drops the oldest anchor, which
 * degrades to the un-unwound behaviour rather than corrupting anything. */
#define JET_ANCHORS 64

typedef struct {
    jmp_buf  buf;
    uint16_t ss;        /* guest stack at the setjmp call site... */
    uint16_t sp;        /* ...so a jmp_buf can be matched to its anchor */
    int      live;
} Anchor;

static Anchor g_anchors[JET_ANCHORS];
static int    g_top;    /* number in use */

jmp_buf *jet_anchor_push(CPU *cpu)
{
    /* Anchors for frames that have already returned are still here -- there is
     * no hook on a lifted function's return. A returned frame is one whose
     * guest sp is BELOW the current one (the stack grows down), so drop those
     * first. Only compare within the same stack: Jet swaps SS:SP for a private
     * stack and the two are not ordered against each other. */
    while (g_top > 0 && g_anchors[g_top - 1].ss == cpu->ss
                     && g_anchors[g_top - 1].sp < cpu->sp)
        g_top--;
    if (g_top >= JET_ANCHORS)
        g_top = JET_ANCHORS - 1;
    g_anchors[g_top].ss = cpu->ss;
    g_anchors[g_top].sp = cpu->sp;
    g_anchors[g_top].live = 1;
    return &g_anchors[g_top++].buf;
}

int jet_longjmp(CPU *cpu, uint16_t env, uint16_t val)
{
    uint16_t ss = cpu->ss;
    uint16_t bp = mem_read16(cpu, ss, env);
    uint16_t di = mem_read16(cpu, ss, (uint16_t)(env + 2));
    uint16_t si = mem_read16(cpu, ss, (uint16_t)(env + 4));
    uint16_t sp = mem_read16(cpu, ss, (uint16_t)(env + 6));
    int i;

    /* The call site pushed a far return frame (4 bytes) before entering
     * setjmp, so the anchor's sp sits 4 above the sp the jmp_buf recorded. */
    for (i = g_top - 1; i >= 0; i--)
        if (g_anchors[i].live && g_anchors[i].ss == ss
            && (uint16_t)(g_anchors[i].sp - 4) == sp)
            break;
    if (i < 0) {
        JMP_LOG("[jet] longjmp to %04X:%04X with no anchor\n", ss, env);
        return 0;                       /* caller falls back to a plain return */
    }

    cpu->bp = bp; cpu->di = di; cpu->si = si;
    /* setjmp's own `retf 2` would leave sp past the return frame and its one
     * word of argument; longjmp fakes that return, so land on the same sp. */
    cpu->sp = (uint16_t)(sp + 6);
    cpu->ax = val ? val : 1;
    g_top = i;                          /* everything above is being discarded */
    longjmp(g_anchors[i].buf, 1);
}

/* ---- MSAJT110's longjmp, replacing the lifted seg072_421A / seg072_4224 ----
 * void longjmp(jmp_buf env, int val) -- PASCAL, so ss:[bp+6]=env, [bp+4]=val.
 * The original sets bp=sp on entry and never pushes it, which is why both
 * entry points can read their arguments the same way. */
static void jet_do_longjmp(CPU *cpu)
{
    uint16_t val, env;
    cpu->bp = cpu->sp;
    val = mem_read16(cpu, cpu->ss, (uint16_t)(cpu->bp + 4));
    env = mem_read16(cpu, cpu->ss, (uint16_t)(cpu->bp + 6));
    jet_longjmp(cpu, env, val);          /* does not return when it matches */

    /* No anchor: the setjmp site is not on the C stack any more. Nothing sane
     * is left to do, so return to our own caller the way the lifted body did
     * and let the miss show up in the log rather than jumping somewhere wild. */
    cpu->ax = val ? val : 1;
    cpu->sp += 4 + 2;
}

void seg072_421A(CPU *cpu) { TRACE_FN("seg072_421A"); jet_do_longjmp(cpu); }
void seg072_4224(CPU *cpu) { TRACE_FN("seg072_4224"); jet_do_longjmp(cpu); }
