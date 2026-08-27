/* jet_setjmp.h - guest setjmp/longjmp, unwound on the host stack.
 *
 * Jet uses setjmp/longjmp for error unwinding: MSAJT110's seg072_41EF is
 * setjmp and seg072_421A/4224 is longjmp, over a jmp_buf of
 *   [0]=bp [2]=di [4]=si [6]=sp [8]=ip [A]=cs  (all near, in SS).
 *
 * Restoring the guest sp is not enough. The lifted call chain has a real C
 * frame per guest frame, and longjmp has to discard the ones between it and
 * the setjmp site. Letting the lifted longjmp just `retf` leaves them alive:
 * control returns into the middle of functions the guest believes it has left,
 * and they carry on with a stack that moved underneath them. That is what put
 * garbage bounds into the Jet page loop this hangs in.
 *
 * So the C stack is unwound with the host's own longjmp. The anchor has to
 * live in the frame that CALLS setjmp -- a helper function's frame is gone by
 * the time anyone jumps to it -- which is why JET_SETJMP is a macro the lifter
 * wraps around each call site rather than something the runtime can do alone.
 */
#ifndef JET_SETJMP_H
#define JET_SETJMP_H
#include <setjmp.h>
#include <stdint.h>

typedef struct CPU CPU;

/* Reserve an anchor for a setjmp about to run at the current guest sp, and
 * hand back its jmp_buf for the caller's own setjmp() to fill in. */
jmp_buf *jet_anchor_push(CPU *cpu);

/* Restore the guest registers a jmp_buf holds and unwind to its anchor.
 * Does not return. Falls back to returning 0 if no anchor matches, so an
 * unmatched longjmp degrades to the old behaviour instead of jumping wild. */
int jet_longjmp(CPU *cpu, uint16_t env, uint16_t val);

/* Wrap a guest setjmp call site. Non-zero means a longjmp landed here; the
 * guest registers are already restored, so the lifted code simply carries on. */
#define JET_SETJMP(cpu) setjmp(*jet_anchor_push(cpu))

#endif
