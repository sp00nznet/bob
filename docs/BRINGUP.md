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

## Already fixed this milestone

- The 19,421-function early-return bug (`ne_lift.py` stripping lift16's bogus
  file-absolute `recomp_dispatch` fall-through). Without this, none of the above
  ran at all.
- `LOCKSEGMENT/UNLOCKSEGMENT/DOS3CALL` PASCAL purge values.
- Combined flat image + selector table + host `main.c`.
