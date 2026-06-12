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

### Current frontier: MFC InitInstance returns FALSE

WinMain gets past `InitApplication` (virtual `0x3C` now hits) and calls
`InitInstance` (virtual `0x40`), which returns FALSE → straight to teardown
(`seg032_3CB3 → 3D09 → 3D14`), skipping `Run` (the message loop), so the C0
startup falls to the R6021 fallback. Implemented `SetWindowsHook`/`Ex` (purge
6/10, return non-zero HHOOK) — didn't unblock; InitInstance fails deeper.

**Top lead:** with `dispatch_far` miss-tracing (`-DELFISH_TRACE_RUNTIME`), the
engine phase is clean (5 misses) but the host phase has **273 misses dominated
by 257× `dispatch_far MISS seg=1050 off=37F8`**, all early in host startup
(right after LibMain). Selector `1050` (`0x41A`) is not a real segment (host is
31–40), so an early host far-call loops through a bogus/unrelocated far pointer.
Next: find that call site (a `call/jmp far [mem]` whose pointer reads
`041A:37F8`) — likely an un-relocated far pointer or a Win16 selector value the
flat model doesn't map — and resolve it; it may well be what makes InitInstance
report failure.

## Already fixed this milestone

- The 19,421-function early-return bug (`ne_lift.py` stripping lift16's bogus
  file-absolute `recomp_dispatch` fall-through). Without this, none of the above
  ran at all.
- `LOCKSEGMENT/UNLOCKSEGMENT/DOS3CALL` PASCAL purge values.
- Combined flat image + selector table + host `main.c`.
