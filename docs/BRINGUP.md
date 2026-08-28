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

## Milestone: CWinApp vtable promoted -> InitInstance now runs (host)

After the sentinel fix the host reached AfxWinMain (seg032_1C2A) cleanly, but
the C++ virtual dispatches `call far [vtable+0x38/0x3C/0x40]`
(InitApplication/InitInstance/Run) all MISSED -> the app did nothing and exited
with R6021 "no main procedure". Root cause: the **CWinApp vtable lives inside a
CODE segment** (UTOPIAWA seg1:0x2028) as a stride-4 table of {offset, selector}
far pointers, and `scan_data_farptrs` only scanned DATA segments. The targets
(seg32:1cad InitApplication, seg36:2e61 InitInstance, seg32:151d Run) were IDA
instruction-heads but never promoted to functions, so `dispatch_far` found
nothing.

Fix: new `scan_vtable_farptrs` in `lift_combined.py` detects far-pointer tables
in code segments as **contiguous stride-4 runs of SELECTOR-reloc locations**
(via chain-expanded `build_reloc_map`) and promotes each entry's offset word
when it is an IDA code head. A broad code-segment chain walk over-promotes
mid-function instruction heads (+2435) and **crashes the engine**, so the scan
requires a stride-4 run (>=3 entries) which cleanly isolates real tables from
scattered far-call operands. Currently **gated to the host module (offset 30)**:
the engine (offset 0) returns ax=0001 cleanly without it and regresses with it
(some promoted entry derails its init) -- TODO understand that before enabling.

Result: InitApplication (seg32:1cad) and **InitInstance (seg36:2e61) now
dispatch and run** -- InitInstance executes real work (SetHandleCount,
CoBuildVersion/OLE, wsprintf, WritePrivateProfileString). NEW FRONTIER:
**InitInstance returns FALSE** (AfxWinMain takes the seg032_66A3 fail path, skips
Run(), no message loop) -> still exits via "no main procedure". Next: find which
check in seg036_2E61 fails (likely a stubbed Win16/OLE/profile/Jet-DB return
value), since the recomp now faithfully runs Bob's real InitInstance.

## Frontier: InitInstance fails on OLE Automation (seg002_7BEC)

Traced exactly why InitInstance (seg036_2E61) returns FALSE. Its body
(seg036_2E83) does, near the top:
  SetMessageQueue(0x60)            -> ok (ax != 0)
  dx = seg002_7BEC(host_ds:0x92A)  -> dx = 0x8004 (negative)
  or dx,dx ; jl 5F50               -> taken -> 5F50: xor ax,ax (return FALSE)

`seg002_7BEC` is an **OLE Automation** engine routine (its call tree uses
OLE2DISP SysAllocString/SysStringLen/SysFreeString). It is handed a far pointer
to `host_ds:0x92A`, which is a statically-NULL far-pointer slot (zeros, no
reloc -- an OLE object/interface pointer meant to be live by now). With OLE
stubbed, 7BEC returns an HRESULT-style error `0x8004792E` (the engine is full of
`mov dx,0x8004` / `mov eax,0x80044E26` OLE error returns), so MFC AfxWinMain
takes the InitInstance-failed path (seg032_66A3), skips Run()/the message loop,
and the process exits via the post-WinMain "no main procedure".

So the recomp now FAITHFULLY runs Bob's real InitInstance up to its first hard
OLE dependency. **Microsoft Bob is fundamentally an OLE Automation app** (it is
an OLE container/automation client over its Access/Jet data store), so the next
milestone is an **OLE Automation shim subsystem** (COMPOBJ + OLE2DISP +
typelib/IDispatch + a minimal class registry), not another lifting fix -- the
differential oracle found zero lifting bugs past the harness gaps. Faking 7BEC
success is not viable: it returns a live interface pointer stored at 0x92A that
later code dereferences. Quick map of OLE error sites: `grep 'mov dx,0x8004'`
across src/seg002.c (engine OLE dispatch).

## Milestone: headless window subsystem -> MFC creates & subclasses the main window

With OLE init working, InitInstance reaches CreateWindowEx to build the main
frame (class "AfxFrameOrView", title "Daemon"). The engine's CWnd::CreateEx
(seg007_21CC) subclasses the new window through a WH_CALLWNDPROC hook:
AfxHookWindowCreate (seg007_0E32) stashes the CWnd* at pWndInit (SEG_24:0x9696)
and installs MFC's _AfxCallWndProc (seg7:0xEFB); during CreateWindowEx the new
window must receive WM_NCCREATE *through that hook* so MFC attaches m_hWnd (adds
to the permanent HWND map) and clears pWndInit -- else AfxUnhookWindowCreate
(seg007_1B74) fails and CreateEx returns FALSE (no window).

Implemented a cross-platform headless window manager in win16_impl.c:
- SetWindowsHook / SetWindowsHookEx capture the guest hook proc into a table.
- CreateWindowEx allocates a guest HWND, synthesizes a WM_NCCREATE CWPSTRUCT
  ({lParam@0, wParam@4, message@6=0x81, hwnd@8}) in a galloc'd scratch selector,
  and re-entrantly calls the registered WH_CALLWNDPROC hook (catz-style
  call_guest: snapshot regs, push HookProc(nCode,wParam,lParam) args + far
  frame, dispatch_far, restore regs but keep allocations). Correct 34-byte purge.

Verified: the hook fires (seg007_0EFB), FromHandlePermanent misses (empty map),
MFC attaches (seg007_1170) and SetWindowLong-subclasses, **pWndInit clears 4000:0356
-> 0000:0000 and the map nCount goes 0 -> 1**. CreateEx returns TRUE -- the main
window is created and attached.

NEXT: InitInstance's big OLE routine seg002_7BEC now runs all the way through
window creation but still returns an HRESULT error (was 0x8004792E, now
**0x80040033** -- a different/later OLE Automation dependency deeper in). Bob's
InitInstance is OLE-Automation-heavy; each stubbed OLE op surfaces as the next
0x8004xxxx. Next: trace where 0x80040033 originates in 7BEC's post-window tree.

## Engine vtable promotion: blocked by loop-header false positives

The OLE-Automation virtual dispatches in InitInstance (e.g. seg021_004B's
`call far es:[bx+0xC]`) need the ENGINE's code-segment vtables promoted, but
enabling scan_vtable_farptrs for the engine (offset 0) makes engine init wander
(48k+ calls) and crash. Root cause: the stride-4 scan false-positives on a far
**jump table** in seg005 -- it promotes mid-function offsets that are *loop
headers* (e.g. seg005_16EA, the target of `je 16EA` from seg005_16F7's lodsw
loop). Promoting a loop header splits the function, so ne_lift emits the
backward `je 16EA` as a tail-call `seg005_16EA(cpu); return;` instead of a
`goto` -- turning the loop into unbounded recursion -> stack blowup.

The stride-4 heuristic cannot tell a real vtable (entries are clean function
starts) from a far jump table (entries are case/loop labels mid-function). Next
options: (a) only promote an offset when the instruction preceding it is a
terminator (ret/retf/jmp) so it's a genuine function start, not a fall-through
target; (b) skip offsets that are targets of intra-function backward jumps;
(c) teach ne_lift to emit a `goto` (not a tail-call) for a backward jump whose
target was promoted from inside the same original IDA function. Until then
engine vtable promotion stays gated to the host (offset 30).

**Update:** added an `is_fn_start` guard to scan_vtable_farptrs -- only promote a
stride-4 entry whose preceding instruction is a `ret`/`retf` (a real vtable
method follows the prior method's `retf`; a jump-table/loop label is preceded by
a `jmp`/fall-through). This cut host false positives 599->473 (host still builds
the window identically) and removes the loop-header class. The engine still
crashes with promotion enabled (other false-positive classes remain), so it
stays gated to the host; the guard is the foundation for enabling it later.

## Engine OLE vtable dispatch: surgical promotion (dispatch_far-miss based)

Rather than the speculative stride-4 engine vtable promotion (which crashes init
via false positives), promote the EXACT engine `call far [mem]` targets that MISS
at runtime: build with -DELFISH_TRACE_RUNTIME, grep `dispatch_far MISS seg=N
off=XXXX`, and force-promote those (FORCE_PROMOTE in lift_combined.py). Key
constraints learned:
- Only `dispatch_far` (indirect CALL) misses -- never `recomp_dispatch` (retf
  return) misses, which are intentional sentinel returns.
- Only HOST-phase misses (after "LibMain returned"). The engine's OWN OLE
  IDispatch vtable (seg13 cluster: 588B/61D2/6747/6E36/770F/7B42/85BB/8756/88E9)
  is dispatched during LibMain on objects not yet constructed; promoting those
  runs them too early and crashes LibMain -- they must stay no-op misses.
- scan_vtable_farptrs's is_fn_start now also (a) accepts a `jmp` terminator and
  (b) rejects intra-segment jump targets, so it no longer needs the host gate to
  avoid loop-header/return-address false positives.

Result: all 4 host-phase engine OLE dispatches resolve (seg2:05E9 seg7:099E
seg11:13EF seg13:681A); engine stays ax=0001; InitInstance advances 5236->5269
calls. **But it still returns FALSE**: the OLE methods now RUN and return an
0x8004xxxx error because Bob's OLE Automation runtime (IDispatch/type-library/
BSTR/Jet data layer) isn't implemented -- the methods execute but fail. That OLE
Automation subsystem is the real remaining work, not more lifting/promotion.

## The frontier is the Jet workspace login, not OLE plumbing

Three rounds of the surgical promotion above emptied the host-phase
`dispatch_far` miss list (seg7:0379 -> seg2:1F76 + seg7:06B9 -> seg8:1E1E),
so every engine OLE Automation call InitInstance makes now lands in lifted
code. InitInstance still returns FALSE, and with the misses gone the reason
is finally legible.

Adding the guest `sp` to the `-DCATZ_TRACE_FN` line is what made it legible.
`TRACE_FN` fires on entry only, so a chain of returns leaves no trace at all
and a flat list of 6,000 names hides all structure. Every lifted call pushes
a return frame, so sp is a stand-in for depth: find a function's entry sp,
then scan forward for the first line at or above it -- that is where it
returned, and the line before it is the last thing it did.

Read that way the failure is a single branch:

```
seg002_7C80:  call seg011_15D7(pObj)      ; engine: open the data session
              or dx, dx
              jge  7C28                   ; success
              jmp  9FF9                   ; Release(pObj) and return the HRESULT
```

and inside the engine:

```
seg011_17BE:  call seg011_0FEC(seg1:5C8C = "", seg1:5F74 = "Admin", ...)
              or ax, ax
              jne 181F                    ; success
              call seg010_52E6            ; DX:AX = last Jet error @ seg24:AEEF
              cmp dx, 0xFFFF              ; 0xFFFF means "no error"
              jne 17FC                    ; -> mov cx, 0x33 -> HRESULT 0x80040033
```

`seg011_17FC` is the error factory: `cx` is the code, `dx` becomes
`0x8004 | (sign & 0xB)`, so `cx = 0x33` is literally where 0x80040033 comes
from. Bob is doing the DAO/Jet default login -- workspace `""`, user
`"Admin"`, no password -- and Jet is refusing it. Nothing above this line is
an OLE problem; **the remaining work is the Jet/DAO layer**, which is what
MSAJT110/MSABC110/MSAES110 were lifted for.

MSAJT110's LibMain is only 5 lifted calls (`seg045_0000` C0 startup ->
`seg052_0000`, which is `mov ax,1; retf`). That is not a bug -- Jet defers
its real initialization to the first DBEngine use -- so the state Jet is
missing is built on the path through `seg011_0FEC`, not at load time.

### "no main procedure" is a red herring

R6021 comes from the MSC startup at `seg035_10DF` (`mov ax, 0x15`), which is
reached only by falling off the end of:

```
call seg035_0706        ; WinMain
add sp, 0xA
push ax
call seg035_019B        ; exit(status)  -- must not return
jmp  seg035_10DF        ; _amsg_exit(R6021)
```

`exit()` bottoms out in `INT 21h/AH=4Ch`, and our DOS3CALL shim returns
instead of terminating, so the CRT falls into the next instruction. The
message says nothing about the app: WinMain ran, AfxWinMain returned, and
`exit()` simply failed to be fatal. Read the InitInstance result, not this.

## By-name imports: why the blitter and the Jet login were both dead

`lift_combined.py` used to note that UTOPIA -> UEXTRA imports were "left as
Win16-style import stubs for now". That was not a cosmetic gap. UTOPIA imports
UEXTRA **entirely by name**, and a type-2 (import-by-name) NE relocation has no
ordinal at all -- the field the parser calls `ordinal` is a byte offset into
the *importing* module's imported names table. Keying `xmod` on it always
missed, so all 19 fixups fell through to no-op stubs called `UEXTRA_Ord173`.

That silently disabled two unrelated things at once:

- **The whole blitter.** RLETRANSEXPAND, COPYDIBBITS, TRANSCOPYDIBBITS,
  HMEMSET, RLEPACKDIB, DOSTRETCHTRANSPARENTDIBITS -- every cel-drawing entry
  point returned 0. Milestones 4 and 5 (first frame, one actor on screen) were
  blocked on a lookup key.
- **The Access Basic runtime.** `B$PEND` and `HOLE` bracket the DGROUP template
  MSABC110 is instantiated from, and `HOLE`'s first word is the size the
  runtime needs. Unresolved, the engine copied 1470 bytes from segment 0xFFFF
  into a segment it had sized from a 0 it read at `es:[0xFFFF]`.

Closing it needed three things beyond the name key, each a different place a
fixup can land:

| Where the fixup sits | Example | Was |
|---|---|---|
| mov/push immediate | `mov si, offset B$PEND` | handled, wrong key |
| arithmetic immediate | `sub ax, offset B$PEND` (ADDITIVE) | not handled at all |
| memory displacement | `mov ax, es:[offset HOLE]` | not handled at all |
| a data segment | `seg HOLE` in UTOPIA's DGROUP | gen_image did internal only |

ADDITIVE is the one that reads wrong at a glance: the word already in the
instruction is an addend to the resolved address, not a chain link.

Including the memory-operand kinds in the fixup pass changes **exactly one
instruction** across all 199 segments -- diff a lift with and without it if you
change this again. It is the `mov ax, es:[0x134]` above.

### The shape of the bug it caused

Worth internalising, because it will recur. A single unresolved fixup made
`GlobalAlloc` ask for 8 KB instead of 21.5 KB. The runtime then copied its
0x265A-byte template into a segment that also held the stack it was running on,
so its own return addresses were overwritten -- and the *symptom* was a
`recomp_dispatch MISS seg=<garbage>` thousands of calls later, in a different
module. Nothing pointed back at the writer.

`-DCATZ_WATCH_MEM=<seg> -DCATZ_WATCH_OFF=<off>` is the tool for this: it prints
every write within a couple of bytes of a guest address, with the call ring.
Reach for it whenever a return address is wrong and the stack pointer is not.

## Frontier: MSABC110's own initialisation

With the above fixed the Access Basic runtime goes from 6 lifted calls to 223.
It copies its template, initialises, and then fails on its own terms:

```
seg147_013E:  call seg158_8040          ; AB runtime init
              or ax, ax
              jne 01C9                  ; -> failure, unwinds to seg011_837C
seg158_8040:  call seg158_970F          ; -> 96B2 -> 96D9 -> 8F8D -> seg153/157
              or ax, ax
              jne 8056                  ; error
```

`seg158_970F` returns non-zero and leaves 13 words on the stack, so `seg147_01C9`
returns through them. Whether the stack imbalance causes the failure or follows
from it is the first thing to establish. Everything above this line -- the
UEXTRA resolution, the template copy, the segment sizing -- is now correct.

## setjmp/longjmp: the guest stack is not the only stack

MSAJT110 unwinds errors with setjmp/longjmp -- `seg072_41EF` is setjmp,
`seg072_421A`/`4224` is longjmp, over a jmp_buf of

```
[0]=bp  [2]=di  [4]=si  [6]=sp  [8]=ip  [A]=cs      (near, in SS)
```

The lifted longjmp restores the guest sp and `retf`s, and that is not enough.
Every guest frame has a real C frame behind it, and longjmp has to discard the
ones between itself and the setjmp site. Returning instead lands in the middle
of C functions the guest believes it has left, which carry on with a stack that
moved underneath them. Fourteen of those per run; the last one landed five
calls before the Jet page loop the run had been hanging in, and its 32-bit
bounds were exactly what the failed unwind left behind.

The C stack is now unwound with the host's own longjmp. The awkward part is
where the anchor lives: **the frame that CALLS setjmp**, because that is the
frame the guest returns to. A helper cannot plant it -- its own frame is gone
by the time anyone jumps there -- so `JET_SETJMP` is a macro the lifter wraps
around each of the 167 setjmp call sites:

```c
if (JET_SETJMP(cpu) == 0) { push16(cpu, cpu->cs); push16(cpu, 0xFFFF);
                            seg072_41EF(cpu); }
```

Anchors match a jmp_buf by guest sp: the call site pushed a 4-byte far frame
before entering setjmp, so the anchor sits 4 above the sp the buffer recorded.
An anchor whose frame returned normally leaves no hook to remove it, so a push
first drops anchors below the current sp in the same stack. An unmatched
longjmp falls back to the lifted behaviour and logs, rather than jumping wild.

`OVERRIDES` in lift_combined.py is the general form of the other half: guest
functions the runtime replaces by hand. They are skipped by the lift and are no
longer stubbed by gen_stubs.

### Two things this made possible

**A guest loop split across two lifted functions is unbounded C recursion.**
`seg057_0926` and `seg057_0940` are the two halves of one Jet loop and tail-call
each other. Build with `-foptimize-sibling-calls` and each `f(cpu); return;`
compiles to a jump, so the loop stays flat. The flag is load-bearing, not an
optimisation -- it is in build.sh and CMakeLists.txt for that reason.

**`3C 58` is two instructions depending on where you enter it.** `cmp al, 58h`
falling through, `pop ax` entered one byte in. MSC uses it to give a shared
epilogue two entries, and only one reading can be an instruction head, so a
branch to the other had nowhere to land -- lift16's fallback aimed it at
`(abs >> 4, abs & 0xF)` of a file-absolute address, a segment that does not
exist. `ne_decode.decode_alt_entries` decodes such a target as its own stream
and lifts it as its own function. 123 sites, now zero.

## Frontier: Jet returns 0xFBFC from the DAO login

Bob's OLE init (`seg002_7BEC`) still fails at the same branch, but everything
under it is now real: the Access Basic runtime initialises, Jet allocates,
creates and reads its RMS scratch files, hits an error, frees all fifteen of
its global handles, and returns cleanly. InitInstance runs 6,049 -> 11,133
lifted calls.

The error itself is `ax = 0xFBFC`, stored to the engine's last-Jet-error slot
at `seg24:0xAEEF` by `seg011_0FEF`. `seg011_85B7` tolerates exactly `0xFBFA`
and turns anything else into `0x80040033`, so the next question is which Jet
ISAM error 0xFBFC (-1028) is and which of `seg045_01DC` / `seg084_00FF` --
the last frames before the unwind -- raises it.

## The file layer was answering yes to everything

Three answers were wrong in the same way, and each one hid the next.

**A zero-length DOS write sets the file's length** -- truncating *or extending*
it. That is how Jet grows a database: `seg061_023A` seeks to `page * 2048`,
writes zero bytes to move EOF there, seeks to the end and compares. Our AH=40h
loop wrote nothing for a count of 0 and left the file its old size, so the
compare failed and the -1808 that came back was remapped to "disk full".
Nothing in the C library says "set this length"; `_chsize` does.

**AH=43h is how Jet asks whether a file exists.** `seg061_00B6` issues it and
reads CF-clear as "already there, do not create". A stub that always succeeded
meant Jet believed its brand-new scratch file was an existing database, skipped
initialising it, and then rejected the empty file it opened.

**DOS open was creating files.** `fio_open_mode` created on any write mode, so
AH=3Dh on a missing file quietly produced an empty one -- which answers "yes"
to every existence question asked by *trying*. Open and create are separate
now: 3Dh/`_lopen` fail if the file is not there, 3Ch/`_lcreat` truncate, and
OpenFile honours OF_CREATE.

Jet takes its scratch databases from nothing to 4 KB to 32 KB, raises no errors
where it used to raise two, and its first DAO call now stores **0** in the
engine's last-error slot.

### How to find the next one

The longjmp override is the choke point for every Jet error: `push <err>; call
<longjmp>` is the idiom, so one function sees them all with the raiser still on
the call ring. Build with `-DELFISH_TRACE_RUNTIME` and read the `[jet] longjmp
val=... from ...` lines. Errors that are *returned* rather than raised land in
the engine's slot at `seg24:0xAEEF`; watch it with
`-DCATZ_WATCH_MEM=24 -DCATZ_WATCH_OFF=0xAEEF`.

## Frontier: Jet -1003, and three databases nobody opens

The DAO login now gets two Jet calls deep. The first succeeds. The second
returns `0xFC15` (-1003) from `seg044_0395`:

```
seg044_0395:  cmp word ss:[bp-6], 0FFFEh     ; -2 == "not found"
              jne 03AA
              mov si, 0FC15h                 ; -> seg011_85CC -> 0x80040033
```

So a lookup by name came back not-found. Bob ships **SYSTEM.MDB**,
**UTOPIA.MDB** and **UPIC.MDB** in the install directory and Jet opens none of
them -- the only files touched in a run are its own RMS scratch files. Jet is
doing its `""` / `"Admin"` login against an empty scratch database, so of
course the account is not there.

The next question is how Bob tells Jet where its workgroup database is.
GetPrivateProfileString/Int now read real .INI files (they were stubs that
returned 0 without touching the caller's buffer), but nothing on this path
consults one yet, so the path is arriving some other way -- most likely as an
argument to the DAO open that is still empty for the same class of reason the
`.ldb` name was garbage earlier.

### What the -1003 is not

Worth writing down so the next pass does not re-run these:

- **It is not a literal in the lift.** All eight `mov ax/si, 0FC15h` sites
  across seg043/seg044 are unreached, so Jet computes the code or maps it
  through a table. Do not grep for the constant.
- **The scratch database is written, not just sized.** Two 2048-byte pages go
  in through DOS AH=40h before it is grown to 32 KB; the file ends up with only
  eight non-zero bytes because a fresh Jet page really is nearly all zeros
  (`"Temp"` lands at 0x406). That is the database name, so the format code is
  running.
- **`seg011_0FEF` runs twice.** The first call stores **0** in the engine's
  error slot -- it succeeds. The second stores 0xFC15. Whatever the second call
  is, it is the one to identify; the trace reaches it through
  `seg044_0CAF -> 0D7E -> ... -> 0D8D -> 0D9E -> 0E0E`, and by `seg044_0D49`
  (`or si,si; jl`) the error is already in si, so it comes from a callee below
  that.
- **`seg011_181F` is the success continuation** of the login and it builds the
  path to `UTOPIA.MDB` (`seg011_1833` appends the name from `seg24:0x7A86`). So
  Bob does not open its real database until the workspace exists -- fixing the
  login is what unblocks the data layer, not the other way round.

Jet's own DGROUP carries `system.mdb`, `admin` and `ADMINS` (MSAJT110 NE seg
106, global 146, at 0x3B/0x12/0x1E), and the ISAM system-table names
(`MSysObjects`, `MSysAccounts`, `MSysACEs`, ...) sit in NE seg 7. Nothing in a
run opens `system.mdb`, so either Bob never points Jet at a workgroup file and
the default unsecured path should be taken, or the pointing happens through a
call we still get wrong.

### The -1003, pinned down

The login itself **succeeds** -- `seg011_85B7` never runs and `seg011_0FEF`
stores 0. The failure is in the call the login's success path makes next:

```
seg011_100F:  push [bp+12h]  ; &out
              push [bp+0Ah]  ; "Admin"
              push [bp+6]    ; ""
              call seg006_3BC6          ; -> Jet stack thunk -> MSAJT110.103
              mov ds:[0AEEFh], ax       ; <- 0xFC15 lands here
              mov ds:[0AEF1h], dx
              or  ax, ds:[0AEEFh]
              jne 85CC                  ; -> 0x80040033
```

Dumping the arguments at the thunk (temporarily overriding `seg006_3BC6`,
which is three instructions) gives:

```
[jet103] arg3 = 1:5C8C ''
[jet103] arg2 = 1:5F74 'Admin'
[jet103] arg1(out) = 40:FF20
```

Inside ordinal 103 (`seg044_0B6A`), `seg044_01B1` normalises an empty string
argument to a NULL far pointer, `seg044_01CC` passes it to the name lookup
`seg046_0442`, and that takes its null path (`0482 -> 04A3`), writes 0xFFFF
into the caller's result and returns. `seg044_01E3` reads the 0xFFFF as
"not found" and falls into `seg044_01F8`, which is `mov ax, 0FC15h`.

So the chain is complete and mechanical: **empty string in, -1 out, -1003
returned, 0x80040033 to MFC.** The open question is whether Bob is right to
pass `""` -- if Jet is supposed to read that as "no workgroup file, default
unsecured Admin" then something upstream should be supplying a name we are
not, and `system.mdb` in Jet's own DGROUP is the likeliest thing it wants.

(Note for whoever greps next: the raise site is `seg044_01F8`, not the
`seg044_0395` / seg043 sites -- those really are unreached.)

### Reading a guest function's arguments

`-DCATZ_ARGS_OF='"segNNN_XXXX"' -DCATZ_ARGS_N=<words>` dumps that function's
arguments on entry, decoding anything that looks like a far pointer into a
placed selector as a string. A guest call site pushes a 4-byte far return
frame, so the arguments start at `ss:[sp+4]`, rightmost first -- PASCAL pushes
left to right, so the LAST parameter is at the lowest address.

It replaces the previous approach of overriding a function to log and then
reimplementing its body, which is how the Jet-103 arguments were first read and
is worse in every way.

### Walking down from Bob's `""`

`seg011_17BE` pushes four arguments to the login:

```
[bp+6]:[bp+8]     SEG_1:5C8C   ""
[bp+0A]:[bp+0C]   SEG_1:5F74   "Admin"
[bp+0E]:[bp+10]   <object>+0CAh
[bp+12]:[bp+14]   ss:&[bp-8]   (out)
```

`seg011_100F` forwards three of them -- `&out`, `"Admin"`, `""` -- to Jet
ordinal 103, dropping the object pointer, which the login itself consumed.

Inside, the argument list is passed down through wrappers
(`seg085_0542` -> `seg085_055C` -> `seg044_0174`, each a straight forward of ten
to twelve words) and by the time it reaches `seg044_0174` the name argument
(`[bp+0E]:[bp+10]`) is **already NULL** -- not nulled locally by
`seg044_01B1`, which takes its already-null branch. `seg044_01CC` hands the
NULL to `seg046_0442`, which takes its null path (`0482 -> 04A3`), writes
0xFFFF, and `seg044_01E3` turns that into -1003.

(The `FFFF:0178` that `seg044_0174` hands `seg086_028A` is **not** an
unrelocated selector -- `seg086_028A` walks a linked list of 0x3E-byte records
at `ds:31C2h` comparing a 32-bit key, so `0xFFFF0178` is a key value, not a
pointer. That thread is closed.)

## The lookup is the ISAM driver table, not an account

`seg046_0442` is not looking up a user or a database. It parses a **connect
string**: `seg046_046A` scans it for `;` or NUL counting characters into `di`,
and then dispatches on the length --

```
di == 9 and matches cs:2Fh "MS Access"   -> the native driver
di == 4 and matches cs:29h "ODBC"        -> result = 0FFFEh (-2)
otherwise                                -> search the installable-ISAM list
di == 0 (the string was empty or NULL)   -> result = 0FFFFh (-1)
```

MSAJT110 NE seg 6 carries exactly the three strings you would expect next to
each other: `ODBC`, `MS Access`, `Installable ISAMs`.

That settles what the two sentinels mean, and they are not both errors:

- **-2 is a real answer** ("ODBC"). `seg044_0266` treats it as "not one of the
  built-ins, go and load it".
- **-1 means "I do not recognise this ISAM"**, and `seg044_01E3` turns it into
  -1003.

So the empty string is not being rejected as a missing *name* -- it is being
rejected as an unrecognised *driver*. Which reframes the question one more
time: for a plain native Jet database the connect string is legitimately empty,
so either it should never have reached this lookup, or the argument that
reaches `seg044_0174` at `[bp+0Eh]` is not the one this call was meant to
receive. `seg044_01B1` normalising empty to NULL immediately before the call
means Jet clearly expects to *see* empty here, so the first of those is the
more likely reading: something upstream should be branching around
`seg044_01CC` and is not.

## `IMUL r16, r/m16, imm` is three operands

Chasing the -1003 down to Jet's ISAM slot allocator turned up a real lifter
bug rather than a Jet one.

`seg084_0022` allocates a slot: `seg084_0000` builds a free list of ten
0x19E-byte records, `seg084_0033` reads the free-list head into `[bp-2]`, and
`seg084_003A` indexes the table with

```
69 5E FE 9E 01     imul bx, word ptr [bp-2], 019Eh
```

That is the 80186 **three-operand** IMUL: the destination is write-only.
decode16 was discarding the r/m operand and keeping only (reg, imm), so the
lifter emitted `bx = bx * 19Eh` -- and bx still held 0x50B4, left over from the
free-list loop. The slot was initialised at a garbage offset, so the
`"system.mdb"` that `seg084_003A` copies from `ds:3Bh` into the slot's name
field never landed at `[si+50D0h]`, and every later ISAM lookup saw an empty
name.

The r/m operand now goes in `op3`, leaving the immediate in `op2` so the
ordinary two-operand form is untouched, and the lifter reads `op3` as the
source when present. **762 instructions across Bob changed.** Both forms are
covered: the memory source above, and the register source in `seg086_02EC`
(`imul si, bx, 3Eh`), which walks a hash chain and was previously squaring its
own index.

This is the kind of bug the differential harness exists for; it survived this
long because nothing had executed that code before the Jet layer came alive.

## Frontier: a circular list in Jet's hash chain

With the multiply fixed the run reaches an order of magnitude more Jet code
(38k trace lines -> 505k) and then spins in `seg086_02EC`/`seg086_0304`, a
walk of the chain at `ds:31F8h` that never reaches its 0xFFFF terminator. The
chain is circular, so something is still building it wrong.

Upstream of that, six `[jet] longjmp ... with no anchor` remain. The anchor
stack no longer discards the anchor it jumps into (a second longjmp to the same
jmp_buf is legal, and Jet retries operations from one setjmp site), but a
longjmp raised from inside another longjmp's aftermath still finds nothing --
the ring shows `seg072_421A seg073_0010 ... seg073_0000 seg072_421A`. Whether
the circular chain is a consequence of those failed unwinds or independent of
them is the first thing to establish.

## The spin was a missing anchor, not a Jet bug

`JET_SETJMP` was only emitted at FAR call sites. The 30 calls to setjmp from
inside its own segment are NEAR calls and went through a different branch of
the lifter, so they planted no anchor. Jet reaches its outermost error handler
through one of those; a longjmp to it found nothing, fell back to returning,
and left the C stack standing while the guest stack moved -- which is what put
the circular link in the hash chain the run was spinning in.

All 197 sites are wrapped now. `jet_longjmp` allows for a near call's 2-byte
return frame as well as a far call's 4 when matching an anchor to a jmp_buf.

## OF_PARSE, and the workgroup database

`OpenFile` with `OF_PARSE` (0100h) fills the OFSTRUCT with a fully-qualified
path and **opens nothing**; 0, not a handle, is success. The shim ignored the
flag and tried to open, so a file that was not there came back -1 -- which Jet
reads as "invalid path" and raises -1023 over. That was `seg082_0202`, and it
was the last thing standing between Jet and its workgroup database.

The OFSTRUCT now also gets a DOS path rather than the host one. `szPathName`
is a field in a 128-byte struct that callers parse and hand back, so writing
`game/install/...` into it was both too long for the field and meaningless to
the guest -- and Jet has its own bounds check on it (`seg058_005F`) that raises
the same -1023. `bob_resolve` takes the basename anyway.

With that in place Jet does what it had been trying to do all along:

```
[file] OpenFile 'system.mdb' style=0100
[file] open 'C:\system.mdb' -> game/install/system.mdb OK
[dos] open 'C:\system.mdb' -> 7
[file] open 'C:\system.ldb' -> game/install/system.ldb OK
```

It opens Bob's shipped SYSTEM.MDB and takes its `.ldb` lock.

## Frontier: an ISAM entry point that is still the "unsupported" stub

Zero Jet errors are raised, zero longjmps go unmatched, zero stack purges are
guessed, and the host runs 18,258 lifted calls. The login still returns
failure, but the code has changed from -1003 to **-1310**, and that one is not
raised anywhere interesting -- it is simply *returned* by `seg055_0000` /
`seg055_0007`.

`seg055` is a table of near-identical three-instruction functions:

```
mov ax, 0FAE2h      ; -1310
cwd
retf <n>            ; n = 8, 0Ch, 10h, ... one per signature
```

That is Jet's **"operation not supported"** placeholder, one entry per calling
convention, and a driver's dispatch table is filled with them for the
operations it does not implement. So Jet is now dispatching a real ISAM
operation through a table whose slot still points at the placeholder.

The next question is which table and which slot -- i.e. what should have
overwritten that entry when the native driver registered itself. That is a
step *past* opening the database, so the direction is right.

## Past the "unsupported" stub: a runtime dispatch table

The -1310 came from a `dispatch_far MISS seg=72 off=1074` a few calls earlier.
`seg072_1074` is `enter 54h, 0` sitting immediately after a `ret 0Eh` and a
`nop` pad -- an unmistakable function start that IDA never marked, because Jet
builds the table that points at it **at runtime**: no relocation names it, so
`scan_vtable_farptrs` cannot find it either. `FORCE_PROMOTE` gained a
`72: [0x1074]` entry, which is what that mechanism is for. Unpromoted, the
indirect call missed and Jet fell through to the "operation not supported"
placeholder in `seg055`.

## GlobalReAlloc must keep the handle

Win16 guarantees the **handle** survives a `GlobalReAlloc` even when the block
moves -- only the address changes. Our shim allocated a new selector, copied,
freed the old one and returned the new selector. Jet reallocates a buffer and
then asks `GlobalSize` about the selector it still holds; a freed one answers
0, and `seg076_0000` raises -1011 ("out of memory") on that.

Selectors here are an index into `sel_base`, so the block can move under the
same handle, which is exactly the Win16 contract. The old block still goes back
to the free pool.

## Frontier: -1022

The error walk this round: **-1003 -> -1310 -> -1011 -> -1022**, each one a
different thing that was wrong, each fixed. -1022 is now raised from two
places, `seg061_1E5B` (via `seg061_1224/1238/1249`) and `seg064_03BE` (via
`seg064_049F/04D0/0F54`), both reached through Jet's DOS-call wrapper
`seg061_004C`. Both call sites look like the same class as the ones already
fixed -- a DOS or Win16 answer Jet reads as a failure -- so the next step is
the same: find which call returns what, and why.

### Every failing DOS call now names itself

`KERNEL_DOS3CALL` logs any call that returns with CF set, with the registers
and the call ring. Jet turns a CF-set answer into an error code, so a failing
DOS call is always worth a line, and this is the cheapest way to tell a
*deliberate* probe from a real problem.

A run currently shows three, and two of them are fine:

```
AH=3D FAILED ax=0002 ... from ... seg061_008B seg061_004C   <- open system.ldb
AH=43 FAILED ax=0002 ... from ... seg061_00B6 seg061_004C   <- does it exist?
```

Both are Jet probing for the lock file before creating it -- `[dos] open
'C:'ldb -> 8` follows immediately. The third is not:

```
AH=42 FAILED ax=0006 bx=043A cx=0000 dx=0000
      from seg061_1DE5 seg061_1E1D seg061_2364 seg061_01A8 seg061_0119 seg061_004C
```

Error 6 is "invalid handle", and 0x043A is not a handle we ever issued -- the
run hands out 5, 6, 7 and 8.

## Frontier: a Jet file-control block whose handle field is wrong

`seg061_0119` is Jet's page read/write: seek to `page << 11`, then read or
write 0x800 bytes, with the DOS handle in `[bp+0Ch]`. `seg061_01A8` forwards
its own arguments to it, and the handle originates one frame further up:

```
seg061_2364:  si = bx                       ; bx is an FCB pointer
              es = ds:[785Ah]               ; Jet's FCB segment
              push es:[si]                  ; the handle field -> 043Ah
```

`ds:[785Ah]` is the same FCB segment `seg057_0908` uses, so the structure is
the right one. Either the FCB was never given the handle of the file Jet
opened, or `bx` is indexing the wrong FCB. Establishing which is the next step:
watch the handle field of the FCB Jet opens `system.mdb` into and see whether
anything writes 7 to it.

### -1022 is DOS error 6, and Jet says so itself

`seg061_0054` is the DOS-failure handler. It calls `AH=59h` (get extended
error), checks for 53h, and then `seg061_0073` / `seg061_007B` walk a table of
nineteen (DOS error, Jet error) pairs sitting at **`seg61:0000`**, in the code
segment. Dumping it settles the whole question:

```
DOS  1 -> -1906     DOS 18 -> -1020     DOS 33 -> -1025
DOS  2 -> -1811     DOS 19 -> -1032     DOS 36 -> -1033
DOS  3 -> -1023     DOS 20 -> -1023     DOS 53 -> -1023
DOS  4 -> -1807     DOS 21 -> -1021     DOS 55 -> -1022
DOS  5 -> -1032     DOS 27 -> -1021     DOS 65 -> -1032
DOS  6 -> -1022     DOS 32 -> -1024     DOS 112 -> -1808
DOS 15 -> -1023
```

**-1022 is the mapping for DOS error 6, invalid handle** -- so it is exactly
the `AH=42 FAILED ax=0006 bx=043A` lseek, and the two are one bug after all.
(0xFC02 is *also* what the loop falls through to when nothing matches, which is
what made it look like "unknown error" at first. It is not: the table hits.)

Correcting the previous note: that failure "not reproducing" under the watch
was my own error. That build had `-DELFISH_TRACE_RUNTIME` but not
`-DCATZ_TRACE_WIN16`, and `FIO_LOG` is gated on the latter, so the line was
compiled out rather than absent. **Run both defines together when correlating
DOS traffic with anything else.**

## Frontier: a null RMS slot pointer

`ds:[785Ah]` is selector **0x4014**, Jet's RMS segment. `seg061_2364` reads the
handle for a transfer out of `es:[si]` there, with `si = bx` -- and `bx` is a
**slot pointer**, not an index. Slots sit at 0x16, 0x228, 0x43A ... 0x212 apart.

Dumping `bx` at every `seg061_2364` entry (`-DCATZ_ARGS_OF='"seg061_2364"'`)
against the DOS log settles it. The calls before the failure use 0x16 and
0x228 and work; the one immediately before it is

```
[ARGS] seg061_2364 #7  ax=0000 bx=0000 cx=0043 si=00EE ...
[dos]  AH=42 FAILED ax=0006 bx=043A from ... seg061_2364 seg061_01A8 seg061_0119
```

**bx = 0.** That is not a slot -- it is the base of the array, and
`4014:[0000]` holds **0x043A**, which is the free-list head (the third slot's
own address). Jet read the list head as a file handle and seeked on it.

Watching `4014:[0x16]` with both trace defines on shows the machinery works
when it is given a real slot: `<- 00` from the clearing `rep stosb`, then
`<- 0005`, the handle of the file just opened. Nothing is wrong with opening or
with the slot layout.

So the defect is upstream: something hands this path a null slot pointer.
`bx` comes from the argument at `[bp+0Eh]`, and it is 0 all the way up through
`seg061_1CDD` (`lea si,[bx+0EEh]` giving the si=0x00EE in the dump above),
`seg061_1DAB` (`test byte es:[bx+106h],1` on the array header),
`seg061_1DE0/1DE5` and `seg061_1E1D`. The whole function was *called* with it.

Next step: keep walking up from `seg061_1CBB` / `seg061_1CDD` to the function's
real entry, then find its caller and what it thinks it is passing. Either a
"find the slot for this file" call returned 0 and the result went unchecked, or
the slot pointer is being lost between there and here.
