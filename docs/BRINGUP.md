# Bringup Log — engine init frontier

`bob.exe` boots, loads the combined image, sets up selectors, and runs real
lifted engine code. Current frontier: it stalls inside **UTOPIA's MFC 16-bit
C-runtime / module-state initialization** before LibMain returns.

## How to reproduce / observe

```bash
export PATH="/c/msys64/mingw64/bin:$PATH"
# full call trace (prints "FN <name>" per lifted call):
gcc -c -O0 -DCATZ_TRACE_FN -Iruntime -Iruntime/win16 -o build/obj/<each>.o <each>.c
# or watchdog (dumps ordered call ring + registers after 4s if it spins):
gcc -c -O0 -DBOB_WATCHDOG -Iruntime -Iruntime/win16 -o build/obj/main.o runtime/main.c
./build/bob.exe build_data/mem_image.bin
```

## What runs (clean) and where it stalls

LibMain init proceeds cleanly:
`seg005_120D → 1211 → 123D → 1262 → 1275 → 00CE…00F8` (C0 prologue + early
init), a few C++ ctor-table passes (`seg005_38E4/38F6`), `seg020_*` init, then
it enters the **module-state accessor loop** and does not converge.

Two Win16 calls happen first and are fine: `LOCKSEGMENT`, `DOS3CALL`
(purge values added to `tools/win16.py`). The failing loop calls **no** Win16
shims — it is pure lifted computation over DGROUP globals.

## The mechanism (MFC 16-bit module state)

`seg005_0000` is the MFC module-state accessor (`AfxGetModuleState`-style),
called from a thunk table in `seg001` (many `call seg005_0000` at
`B12C/B12D/…`). It:

```
seg005_0008:  cmp ss, [ds:0x944C]      ; DLL "different stack" model check
              jne seg005_38D0          ; DLL path (normal; [0x944C]=0, ss=0x28)
seg005_38D0:  call seg002_0000         ; returns module-state far ptr (ax:dx)
              or ax,dx
              je  seg005_38DF          ; ptr==0  -> first-time path
              jmp far ds:[0x9446]      ; ptr!=0  -> handler vector
seg002_0000 → … → seg002_0456:
              GetCurrentTask           ; stub returns stable 0x00FF
              cmp [ds:0x7A92], ax      ; per-task state present?
              jne seg002_0469          ; no  -> create (calls back into seg005_0000)
              ; yes -> seg002_0461: ax=[ds:0x7E54], dx=[ds:0x7E56]  (return state ptr)
seg002_044D:  xor ax,ax; cwd           ; return 0:0  (the "not found" answer)
seg003_0000:  … push args; call seg005_0000  (re-entrant create path)
```

The state machine is driven by three DGROUP/stack cells that are **all zero**
in the loaded image and must be populated, in order, by the init itself:

| cell | role | observed |
|------|------|----------|
| `ds:[0x7A92]` | per-task HTASK marker | `0x0000` (converges to `0x00FF`) |
| `ds:[0x7E54:0x7E56]` | module-state far pointer | `0000:0000` |
| `ds:[0x9446]` | handler/continuation vector (`jmp far`) | `0000:0000` |
| `ss:[0x20]` | stack continuation (`seg005_38DF` jmps through it) | — |

When the state pointer never becomes valid / the handler vector at `0x9446`
stays `0:0`, a `jmp far` dispatches to `0:0` (guard) and control unwinds/derails
(the watchdog has caught it reaching host `seg036` with `ds=0`), so LibMain
never returns.

## Likely causes (next-session checklist), highest-leverage first

1. **Re-entrant accessor contract**: `seg003_0000` (create) calls back into
   `seg005_0000` (accessor). Verify the stack args it passes (`ss:[bp+6]`,
   `ss:[bp+8]`) and that the create path actually **writes** `[0x7E54]` and the
   `0x9446` handler before returning. A single mis-lifted store here stalls the
   whole machine. Compare against IDA's view of these functions.
2. **`ss:[0x20]` continuation** (`seg005_38DF: jmp far ss:[0x20]`): confirm the
   caller set up that stack far pointer; if it's our frame garbage, the jmp
   derails. May indicate a stack-frame / `enter`/`leave` lifting mismatch.
3. **DLL DGROUP/SS model**: real Win16 DLLs run on the caller's stack (SS≠DS).
   Our model uses one combined stack (seg 40) and engine DGROUP seg 24. Check
   that the `mov ax,SEG_24; mov ds,ax` (`__loadds`) sites keep DS correct across
   the far-call chain — the watchdog caught `ds=0` at the stall, so DS is being
   clobbered somewhere in this chain.
4. **Data far-pointers needing init**: cells like `0x9446` are runtime-set, not
   load-time relocated (seg 24 has only 22 relocs, none at these offsets) — so
   this is about executing the init correctly, not a missing image relocation.

## Update — two roots found (IDA-verified)

**1. UTOPIA NE seg 1 is a data segment mis-flagged CODE (FIXED).**
IDA reports **zero** code in seg 1 (every other segment is fully covered); its
bytes are a far-pointer dispatch table (`{offset, selector}` pairs, 20 SELECTOR
relocations) and it's only ever referenced as a *selector* (`mov reg, SEG_1`),
never far-called. The lifter was linear-sweeping it into 34 KB of garbage
callable functions that execution derailed into. `lift_combined.py` now skips
any "code" segment IDA found no instruction heads in — it stays in the flat
image as data with its relocations applied. (Unresolved stubs 16 → 10.)

**2. The continuation jmp derails because DS ≠ SS (the open frontier).**
With seg 1 fixed, init gets to `seg005_38DF: jmp ss:off_20` (IDA-confirmed: a
real absolute `jmp far ss:[0x20]`, not a dropped frame base). Runtime probe at
that point:

```
seg005_38DF: ds=0018(24) es=0000 ss=0028(40) sp=FF90 bp=FFA0  ss:[0x20]=0028:0014
```

`ss:[0x20]` resolves into **host DGROUP (seg 40)** static data — `40:0x14`, which
is itself a data table — so `dispatch_far(40,0x14)` misses and control unwinds
into host code (`seg036`) with `ds` later clobbered to 0. Root cause: this
engine C-runtime code accesses a global far-pointer via `ss:[abs]` assuming the
**small-model invariant SS == DS == DGROUP**, but we run LibMain with
`ds=24` (engine DGROUP) and `ss=40` (host stack), so the `ss:`-relative global
read hits the wrong segment.

Neither `40:0x20`→`40:0x14` nor `24:0x20`→`4473:495B` is a valid code pointer,
so `ss:[0x20]` is a **runtime-initialized continuation** that the init is
supposed to populate (setjmp-style) and hasn't — consistent with the DS≠SS
mismatch corrupting which segment the store/läs land in.

### Next hypotheses (highest-leverage)

1. **Run engine LibMain small-model (SS = DS = engine DGROUP 24).** Requires the
   DGROUP/stack segment to be allocated a full 64 KB in `gen_image_bob.py` so
   `sp=0xFFFE` fits (currently segments are packed to actual size). This is the
   most likely single fix — it makes `ss:[abs]` global access read the engine's
   own DGROUP.
2. If small-model SS regresses other code, instead find the writer of
   `ss:[0x20]` (the setjmp-equivalent) and verify it stores a valid continuation
   under our segment model.
3. Confirm DGROUP segments (24, 40) are 64 KB-allocated with the stack at the
   top — the host worked with `sp=0xFFFE` in seg 40 possibly by luck.

## RESOLVED — engine init completes (24,680 calls) ✅

Both roots above were fixed and **`UTOPIA` LibMain now runs to a clean return**
(`ax=0100`, 24,680 lifted calls). The `seg019_0000`-heavy "spin" was legitimate
MFC class registration that converges. Along the way it does real Win16 work:
`GlobalAlloc(2002,4096)->4000`, `RegisterWindowMessage`, `DeferWindowPos`,
`ScreenToClient`, `GetParent`, etc. (purge values added as reached).

The 64 KB-DGROUP + small-model `SS=DS` change was the decisive fix: it took init
from frozen-at-93-calls to completing at 24,680.

## UTOPIAWA host startup — progress + current frontier

After LibMain returns, `main.c` runs the host entry `seg035_0002` (UTOPIAWA's
C0 → WinMain).

**Fixed: the InitTask re-init loop.** `seg035_0002` calls `KERNEL_INITTASK`,
then `add cx,0x100; jb fail`. Our stub returned `CX=0xFFFE` (stack *top*), which
carries → `jb` taken → `10C8` calls `1151` and **jmps back to `0002`** =
infinite re-init. InitTask must return `CX = stack *limit*` (a low offset); set
to `0x4000` (above the host statics, below the stack). The host now runs to
WinMain instead of looping.

**Current frontier: "no main procedure".** The host aborts via `FatalAppExit`
with the message **`no main procedure`** (captured by a real
`KERNEL_FATALAPPEXIT` shim that prints `ds:ax`). Investigation:

- The abort goes through `seg035_10E2 → 1103 → 1113`, which is the MSC C-runtime
  **`_amsg_exit` error reporter**: `seg035_1128` searches the error-message
  table at host DGROUP `0x1540` (`R6025 - pure virtual function call`,
  `R6009 - not enough space for environment`, …) for a code. So "no main
  procedure" is the *message being reported*, not the root check — an earlier
  step decided to abort and routed here.

- **Dead end tried:** the host's C++ ctor targets (`seg036_409F`, `seg031_2D7E`,
  …) are reached only via far-pointer TABLES in the host DGROUP (`{offset,
  selector}` pairs patched through SELECTOR **relocation chains**). IDA never
  makes them functions, so the lifter didn't either, so the ctor `dispatch_far`
  calls miss. I added far-pointer-table → function promotion to
  `lift_combined.py` (walks the reloc chains, only promotes IDA code-heads) —
  it correctly creates `seg036_409F` etc. **But** promoting the *engine's* ctor
  entries regressed engine init (24,680 → 229 calls: ctors that were safely
  skipped now run and break it), and promoting the host's didn't clear
  "no main procedure". Reverted (stashed). The promotion idea is sound but needs
  to be (a) host-only and (b) paired with finding the *actual* failing check.

### RESOLVED root cause: SELECTOR-fixup far calls went to offset 0

Back-tracing the abort: error code `0x15` = `R6021 - no main procedure` (the
table at `0x1540` is the MSC error list). The host startup calls WinMain via
`seg035_070A: call far FFFF:1C2A`, then falls through to the R6021 fallback if
that returns without terminating. But the lifted call was `seg032_0000(cpu)` —
**a stub at offset 0**, not `seg032_1C2A` (the real WinMain). Cause: the far
call's selector word carries a **SELECTOR(2)** relocation (`tseg=2, toff=0`);
the *offset* (`0x1C2A`) is the instruction's own immediate. `ne_lift.py`'s
`_resolve_far_call` used `r.target_off` (0 for selector fixups) → every such
call went to `segNNN_0000`. Fixed: for `src_type==2` FAR calls, take the offset
from `inst.op1.disp`.

Impact: this silently no-op'd cross-segment far calls program-wide. With it
fixed, the host calls the real WinMain and the **engine LibMain is now correct**
(~100 calls → `ax=0001` success). The old "24,680-call" LibMain was the *buggy*
wandering path created by skipped calls. Also needed: `RegisterClass` must
return a non-zero atom (0 = failure made the engine abort init).

### Far-pointer-table promotion is now safe (was a dead end pre-far-call-fix)

WinMain dispatches MFC `CWinApp` virtuals via vtables (`call far es:[di+0x3C]`).
Those vtable slots — like the C++ ctor tables — are data far-pointers whose
targets IDA never makes functions, so the dispatch missed and `InitInstance`
"returned" 0 → WinMain bailed. The earlier far-pointer-table → function
promotion in `lift_combined.py` (walk SELECTOR reloc chains, promote only IDA
code-heads) regressed the engine *before* the far-call fix. **With the far-call
fix in place it is now safe**: engine LibMain stays correct (`ax=0001`, ~714
calls — the promoted ctors/vtable methods now run), and the host advances from
251 → ~1193 calls, running real MFC `InitInstance` (`LoadString`,
`GetModuleHandle`, `SetWindowsHookEx`, …).

### Two more lifter fixes — host now runs deep MFC InitInstance (4,340 calls)

- **`push imm16` SELECTOR fixup** (`ne_lift.py`): the relocated-immediate
  resolver handled only `mov reg,imm`, not `push imm16`. Win16 passes a far
  pointer as `push seg X; push offset Y; call`; the segment push carries a
  SELECTOR(2) fixup, so without resolving it the raw placeholder selector
  (`0x41A`) was pushed and the later `call far [arg]` hit a bogus segment. Now
  `push seg X` → `push16(cpu, SEG_X)`. (IDA confirmed `0x41A` = `seg cseg06`.)
- **Inline `push seg/offset` code-pointer promotion** (`lift_combined.py`): the
  paired offset (`push offset Y`) is a final literal with no relocation, so
  `seg036:0x37F8` was a code label IDA never made a function. New
  `scan_pushed_code_farptrs` detects `push seg(code); push imm16` and promotes
  `(X, Y)` (IDA code-heads only). +185/58/104 entries across the modules.

Result: the 257× `seg=36:37F8` miss is gone, host-phase dispatch misses drop to
a handful, and the host runs **4,340 calls** of MFC `InitInstance` (was ~1,193).
Engine stays correct (`ax=0001`, 724 calls).

### Differential harness (Unicorn) — foundation working

`tools/uni_host.py` runs the **original** Bob host bytes under Unicorn as a
ground-truth oracle to diff against the recomp. The plan: same flat image + same
Win16 shim return values, trace function entries, and `diff` against the recomp's
`TRACE_FN` trace — the first divergence is either a lifting bug (recomp differs
from real instruction semantics) or, if both behave identically, a shim/resource
gap. For "no main window" specifically: if the original bytes (same shims) also
make no window, a shim returns the wrong value; if they do, the recomp mis-lifts.

Foundation (done + validated): builds the same combined image as `gen_image_bob`
but writes SELECTOR fixups as **GDT selectors (`n<<3`)** and installs a GDT whose
descriptor `n` has `base=flat_base[n]`. Unicorn runs in `UC_MODE_32` protected
mode with 16-bit (D=0) descriptors + `CR0.PE`; `emu_start(ip)` (CS base added by
Unicorn). The real host code executes correctly from `seg35:0002` and stops
exactly at the **first Win16 import call** (`KERNEL_INITTASK`) — proving the hard
part (Win16 protected-mode addressing in Unicorn) works.

Import interception (DONE): a trap GDT selector + every import fixup (chained,
all 3 modules) patched to `trap_sel:idx`; a code hook catches `CS==trap_seg`,
runs a shim oracle that **auto-mirrors the recomp's one-line `win16_impl.c` shims**
(regex) plus hand-written stateful ones (InitTask, RegisterClass, the
`__WINFLAGS`=WF_PMODE / `__AHINCR`/`__AHSHIFT` OFFSET16 constants), then
far-returns with the right purge. INT 21h is hooked too. Function entries are
traced using the recomp's OWN `segments.h` (identical granularity) →
`work/uni_trace.log`.

**Result — the recomp's host startup is VALIDATED faithful for the first 20
functions:** `uni_trace.log` matches the recomp's host trace exactly through
`seg035_0002 → 0010 → … → 012E`. Two divergences found along the way were both
**harness shim-fidelity gaps, not recomp bugs**: (1) `__WINFLAGS` needed WF_PMODE
set (real-vs-protected-mode `test cs:[0],1`); (2) `USER_INITAPP` had to return 1
(now auto-mirrored). After those, instruction-level tracing (`--itrace --itfrom N`) showed the real
stall is **not** WIN87EM (the `__FPMATH` init far-calls returned fine). It is a
**selector fault** at `seg035_012E → 0139`:

```
012E: mov es, [ds:0xF8B]   ; es = stored instance selector (seg40)
0132: mov cx, es:[0x2C]    ; cx = a selector from instance data at seg40:0x2C
0137: jcxz 0177            ; (skip if zero)
0139: mov es, cx           ; <- cx = 0x256F : NOT a valid GDT selector -> #GP
```

`seg40:0x2C` holds `0x256F` — static garbage read **as a selector**. In real
Win16 this field is part of the **loader-initialised instance/task data** and
would hold a valid selector (or 0, which `jcxz` skips). Our model never sets it,
so it reads the raw DGROUP bytes. Real hardware (the uni) rejects the bad
selector; the **recomp's lax selector model silently loads es=0x256F (→ the
guard region) and continues** — i.e. the recomp operates on garbage instance
data from here on, a strong candidate for why it never creates the main window.

Tried (b) — make the harness tolerate any selector via a **full 8192-entry GDT**
(real segments at their index, everything else → a guard descriptor). It loads
ordinary unknown selectors, but Unicorn still **#GP-faults on `mov es, 0x256F`**:
the garbage value has RPL=3, and Unicorn rejects RPL=3 into a CPL=0 segreg even
with a DPL=3 guard descriptor (a stricter-than-textbook Unicorn quirk; CPL=3
isn't reachable without a TSS). So the harness can't paper over this particular
load.

**Identified: `seg40:0x2C` is the DOS PSP environment-segment field.**
`seg035_013D` is a `getenv` (it `repz cmpsb` a 13-byte name against `es:[di]`
and `scasb`-skips strings), so `es:[0x2C]` is the **environment block selector**
(PSP:0x2C). The real loader sets it up; our image has static garbage there. The
recomp tolerates it (garbage selector → guard zeros → empty env → continues), so
**this is NOT the recomp bug** — it's a harness gap. Pointing each DGROUP's
`0x2C` at a zeroed env (`ENV_SEL` → guard, via the full GDT) in `uni_host.py`
lets the uni load it as "empty env", matching the recomp.

With that the diff went much deeper. Three more **harness** gaps were closed
(all confirmed NOT recomp bugs): (1) the apparent ctor-walk "off-by-one" was a
**trace-granularity artifact** — the harness logged the loop header on every
real `jmp 0x022D` back-edge, while the recomp's lifted loop uses a `goto` after
`TRACE_FN`; fixed by suppressing back-edges via per-segment function ranges; (2)
`GlobalAlloc` must return an **even** selector backed by real memory (the recomp
does) — added a bump allocator (even GDT selectors → fresh 64 KB regions); (3)
the env-segment field (above). With these the **uni matches the recomp for 165
functions over 40,158 instructions**.

**Then the harness found a REAL recomp lifting bug.** At `seg035_028B` the
original does `call di` (a register-indirect near call → `seg035_0BD5`), but the
lifter emitted only `/* indirect call di - needs dispatch */` — **a no-op** — so
the recomp silently *skipped* the call. Root cause: `lift16` only dispatches
indirect call/jmp when `self.dispatch` is set, and `ne_lift` never set it. Fixed:
`ne_lift` now sets `lifter.dispatch = True`, and the near-indirect path uses
`dispatch_near` (cleans the pushed return word on a miss) instead of
`recomp_dispatch`.

The fix cascades correctly: `seg005_38D0` now reaches the real module-state init
`seg002_7D82` (matching its `307C:7D82` annotation) instead of skipping it →
`seg008_0872 → 0954`, which does `div word es:[si+0x8]` and **#DE-crashes on a
zero divisor** (uninitialised engine data — the same uninit-state theme as the
PSP env field). So the recomp now takes the correct path and the next frontier
is that divide-by-zero. **Next: trace what should populate `es:[si+0x8]` before
that div (engine module-state init), or which earlier value the recomp gets
wrong — verify against the uni harness, which is now the standing oracle.**

### Resource subsystem wired for Bob; frontier refined to "no main window"

`runtime/win16/ne_resources.c` now loads Bob's NE files (was catz's CATZDLL/CATZ):
`register_mod("UTOPIA",24) / ("UEXTRA",27) / ("UTOPIAWA",40)`, the game dir is
`game/install`, and `register_mod` tries `.DLL/.EXE/<base>/<base>.EXE/.WAD`
(the host lives in a subdir). Resources now load (UTOPIA 450, UEXTRA 1,
UTOPIAWA 197) so `LoadString`/`LoadResource` are backed by the real tables.

Refined diagnosis (the earlier "InitInstance returns FALSE" was imprecise):
`seg032_1C6A` dispatches the `CWinApp` vtable — `0x3C` (InitApplication/
InitInstance) returns non-zero, then `0x40` runs and the path ends at
`seg032_39C6` which sets **`ax=1` (success)**. So WinMain's init *succeeds* — but
**no `CreateWindow` is ever called** (none in the win16 trace) and **no message
loop runs** (no `GetMessage`/`PeekMessage`). With no main window, MFC `Run`
returns immediately, WinMain returns, and the C0 startup falls to the R6021
"no main procedure" fallback (which is just the post-WinMain "shouldn't reach
here unless exit didn't terminate" path).

`LoadString(40, 57344=0xE000)` still returns "" even with resources loaded —
that ID isn't in UTOPIAWA's table (host call count is unchanged at 4,340, so it
isn't gating control flow). Next: instrument the vtable dispatch to pin down
which slot is InitInstance vs Run, and find why InitInstance returns success
without creating the main window (a guarded early-return, or a window-creation
API/resource the stubs don't satisfy). Also: make the process-exit path
terminate so a returning WinMain doesn't hit the R6021 fallback.

### (earlier note) Current frontier: MFC InitInstance returns FALSE

WinMain gets past `InitApplication` (virtual `0x3C` now hits) and calls
`InitInstance` (virtual `0x40`), which returns FALSE → straight to teardown
(`seg032_3CB3 → 3D09 → 3D14`), skipping `Run` (the message loop), so the C0
startup falls to the R6021 fallback. Implemented `SetWindowsHook`/`Ex` (purge
6/10, return non-zero HHOOK) — didn't unblock; InitInstance fails deeper.

**Localized lead (hardcoded far pointer `0x41A:0x37F8`):** with `dispatch_far`
miss-tracing (`-DELFISH_TRACE_RUNTIME`) the engine phase is clean (5 misses) but
the host phase has **273 misses, 257 of them to `seg=0x41A off=0x37F8`**. Source:
`seg037_046D/046F` (a *real* IDA function) does
`push 0x41A; push 0x37F8; call seg035_06D0` — `seg035_06D0` is a generic
"call far-proc `di` times" helper (`di=0x101=257`, `si=0x1C2C` stride `8`). So
real host code holds a **hardcoded far pointer `0x41A:0x37F8`** with *no
relocation* — `0x41A` is not one of our flat selectors (host = 31–40), so the
257 `call far` iterations all miss and the loop is a no-op, leaving 257×8-byte
records at `0x1C2C` unprocessed. Open question: what is selector `0x41A`? It
looks like a real Win16 LDT selector value baked into the image (index≈131,
RPL/TI bits) that the flat model doesn't map — needs IDA's view of
`seg037:0x046F` to see whether IDA resolves it to a known segment/thunk, then a
runtime mapping (or a fix-up) for it. The loop is benign (completes) but its
skipped work may be why InitInstance ends up reporting failure.

## Already fixed this milestone

- The 19,421-function early-return bug (`ne_lift.py` stripping lift16's bogus
  file-absolute `recomp_dispatch` fall-through). Without this, none of the above
  ran at all.
- `LOCKSEGMENT/UNLOCKSEGMENT/DOS3CALL` PASCAL purge values.
- Combined flat image + selector table + host `main.c`.

## Milestone: dummy-return sentinel fixes the engine crash (engine now matches oracle 455 funcs)

The engine crashed (#DE div-by-zero at `seg008_0954`) because the recomp's
call-return model pushed a **dummy return offset of 0**. The retf/ret lift
dispatches the popped CS:IP (`recomp_dispatch`/`dispatch_near`), and offset `0`
**collides with the real function at `segNNN_0000`** — so a far `retf` or the
Win16 idiom `push cs; call near proc; (proc: retf)` wrongly *called*
`segNNN_0000` instead of cleanly returning. Concretely `seg005_11F7`'s ctor
walk returned into `seg005_0000` (→ module-state path → div-by-zero) instead of
`seg005_38F6`.

Fix: push a **sentinel offset `0xFFFF`** (never a function entry — verified no
`segNNN_FFFF` exists) for every simulated return frame, so the dispatch on the
dummy frame always MISSES and falls through to a clean C return.

- `tools/ne_lift.py`: far-call frames (lines 121/135) and near-call frames
  (lines 147/199) now push `0xFFFF` instead of `0`.
- shared toolkit `tools/lift/lift16.py`: same change to the near/far call frames
  and the indirect-dispatch push (619/646/660). (Near `ret` is unaffected — it
  just does `sp+=2; return`, discarding the dummy; only the far `retf` and the
  `push cs;call near` idiom dispatch the dummy, which is why the value matters.)

Result: **engine LibMain returns ax=0001 and the whole program now runs to
`exit 0`** (was `exit 127`). Against the Unicorn oracle the engine trace now
matches **455 functions** (was 39 before this fix, 15 before the indirect-call
fix). Remaining engine divergence at line 456 (`seg020_01AE` retf-trampoline:
oracle→`0088`, recomp→`0077`) is a computed-jump target deep in init; the engine
still completes successfully, so the active frontier returns to the **host**
R6021 "no main procedure" (no CreateWindow / no message loop).
