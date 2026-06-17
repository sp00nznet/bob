# Microsoft Bob — Static Recompilation

Cross-platform static recompilation of **Microsoft Bob** (1995) — Microsoft's
infamous "social interface" for Windows, the cartoon house full of helpful
talking guides (Rover the dog, Java the dinosaur, Scuzz the rat …). This project
lifts Bob's 16-bit NE binaries to portable C and reimplements its Win16/Jet/WinG
dependencies on top of a modern runtime, so the house runs natively on Windows,
macOS, and Linux instead of inside a Windows 3.1 / Win95 VM.

**Long-term goal:** let an LLM drive the guides' speech. Bob's actors ship with
fixed animation sets and pre-recorded voice lines; once the engine renders and
an actor is on screen, we route its dialogue through an LLM + TTS so the guides
can actually *converse* instead of replaying a script. See
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the actor-file analysis.

Built on the [pcrecomp](https://github.com/sp00nznet/pcrecomp) NE toolchain,
following [catz](https://github.com/sp00nznet/catz) as the structural template —
the proven thin-host-EXE + big-engine-DLL Win16 MFC recomp pattern. Bob is the
same shape (UTOPIAWA.EXE host + UTOPIA.DLL engine) with two extra load-bearing
dependencies: the **Jet/Access** database engine (Bob's data store) and
**WAVMIX16** (the actors' mixed-WAV voices).

## Targets

| Binary | Size | Role | Format |
|--------|------|------|--------|
| **UTOPIA.DLL**   | 1.05 MB | Engine: rooms, actors, data store, rendering | NE, MFC, 22 code segs, 71 exports |
| **UTOPIAWA.EXE** | 356 KB  | Host: WinMain, main window, message loop | NE, MFC, 9 code segs |
| **UEXTRA.DLL**   | 11 KB   | RLE / transparent-DIB blit helpers (actor cels) | NE, 2 code segs |
| ACTORS\*.ACT     | ~0.3 MB ea | 12 guides — animation cels + embedded voice WAVs | "LP" actor format |

UTOPIA.DLL's 22 code segments form a **single connected cluster** — one coherent
engine, no dead code islands to triage.

## Pipeline

```
ne_parse   ->  segments, relocations, imports, entry/export tables   [DONE]
ne_xref    ->  segment clusters + per-segment import usage           [DONE]
act_parse  ->  actor (.ACT) header + embedded WAV/string survey      [DONE]
ida_export ->  authoritative function bounds + Win16 ordinal->name   (next)
ne_decode  ->  IDA-assisted 16-bit disassembly (relocations inline)
ne_lift    ->  one C file per code segment; x87 -> native doubles
gen_image / gen_segments_h / gen_dispatch / gen_stubs  ->  glue
runtime/   ->  Win16 shims (KERNEL/USER/GDI/WING/WAVMIX16/Jet) + host loop
```

## Layout

```
tools/       NE toolchain (from catz/pcrecomp) + act_parse.py (actor probe)
runtime/     cpu.h (CPU+FPU model), Win16 shims, host loop (main.c, TBD)
src/         lifted C, one seg*.c per code segment (generated)
analysis/    recon outputs (NE parse dumps, imports, clusters, actor survey)
build_data/  flat memory image (generated, gitignored)
game/        original Bob binaries + media (gitignored, not redistributable)
docs/        ARCHITECTURE.md — module map, imports, actor format, milestones
```

## Building

```bash
cmake -B build            # 16-bit origin -> 32-bit native target
cmake --build build
```

(There is nothing to link yet — the lift stage has not run. The CMake graph is
in place so the build lights up as `src/seg*.c` and `runtime/main.c` land.)

## Getting the binaries

The original Bob files are **not redistributable** and are gitignored. Supply
your own OEM/retail disc, then extract:

```bash
7z x MSBOBOEM.iso -ogame/iso          # EXTRACT.EXE, SETUP.EXE, U1.CAB, ...
7z x game/iso/U1.CAB -ogame/install   # UTOPIA.DLL, UTOPIAWA.EXE, ACTORS\*.ACT, ...
```

## Status: Bringup — OLE init + main window created; MFC InitInstance runs ✅

All three modules lift to link-clean C. The recompiled **engine LibMain
initializes cleanly** (`ax=0001`), the **host runs its full MFC AfxWinMain**,
and **`CWinApp::InitInstance` now dispatches and executes Bob's real startup
code**. A Unicorn differential harness (`tools/uni_host.py`) runs the *original*
binary as a ground-truth oracle: the recompiled engine matches it for **455
functions** and the host for **3677 functions** — i.e. the lift is faithful
(every divergence chased down was a harness gap, not a recomp bug).

```
UTOPIA LibMain returned (ax=0001) after 784 lifted calls    ✅ engine init OK
host -> AfxWinMain (seg032_1C2A) -> InitApplication -> InitInstance (seg036_2E61)
InitInstance: SetHandleCount, CoBuildVersion(OLE), wsprintf, WritePrivateProfile...
```

The fixes that got here (see **[docs/BRINGUP.md](docs/BRINGUP.md)**):
1. **NE seg 1 is data, not code**, **64 KB DGROUP + small-model SS=DS**, and the
   **far-call SELECTOR-fixup offset bug** — early bring-up fixes (details in
   BRINGUP.md) that got the engine + host C-runtime running.
2. **Register-indirect calls were dropped** — `call di`/`call [mem]` were emitted
   as no-ops; the harness caught it. `ne_lift.py` now enables indirect dispatch.
3. **Dummy-return sentinel (`0xFFFF`)** — the call-return model pushed a dummy
   return offset of `0`, which collided with the real function at `segNNN_0000`,
   so far `retf` / the `push cs; call near` idiom *called* `segNNN_0000` instead
   of returning. Pushing a `0xFFFF` sentinel fixed an engine crash and advanced
   the oracle match from 39 → 455 functions.
4. **CWinApp vtable promotion** — the MFC vtable lives inside a *code* segment as
   a stride-4 far-pointer table; the scanner only looked in data segments, so the
   `InitApplication`/`InitInstance`/`Run` virtual dispatches all missed and the
   app did nothing. `scan_vtable_farptrs` now promotes them, so **InitInstance
   runs**.

**OLE init + window creation now work.** Implemented the COM/OLE bring-up shims
(`CoBuildVersion`, `CoInitialize`, `OleInitialize`, `Catch`) and a cross-platform
**headless window subsystem**: `CreateWindowEx` allocates a guest HWND and drives
MFC's subclass-on-`WM_NCCREATE` through the captured `WH_CALLWNDPROC` hook, so the
main window ("AfxFrameOrView" / "Daemon") is created and attached
(`m_hWnd` set, added to MFC's HWND map).

**Current frontier — engine OLE Automation vtables.** InitInstance now runs deep
into Bob's OLE Automation init (`AfxOleInit`), which dispatches through OLE object
vtables that live in the engine's *code* segments. Those engine vtables aren't
promoted yet (the stride-4 promotion is gated to the host because the engine has
jump-table false positives that, once promoted, recurse and crash init — a
`ret`/`retf`-preceded guard now removes the loop-header class; other classes
remain). Resolving engine vtable promotion is the next step to a running message
loop. See docs/BRINGUP.md.

### How it lifts (the three modules → one program)

Recon is complete and **all of Bob's code — engine, host, and blitter — lifts to
C, compiles, and links clean.** The three modules share one global segment space
and one static archive; the only unresolved symbols are standard libc.

| Module | Global segs | Result |
|--------|-------------|--------|
| **UTOPIA.DLL** (engine)   | 1–22  | 22 segs lifted (2,685 IDA funcs / 280,921 heads) |
| **UEXTRA.DLL** (blitter)  | 25–26 | 2 segs lifted |
| **UTOPIAWA.EXE** (host)   | 31–39 | 9 segs lifted (1,541 IDA funcs / 101,829 heads) |

Combined: **34,942 functions across 33 code segments**, dispatcher over all of
them, **16 unresolved stubs out of 32,618 distinct call targets**. Builds with
mingw gcc to a 39-object / 27 MB static archive — **0 errors, 0 warnings**, and
**0 non-libc undefined symbols**. Host→engine calls (`UTOPIAWA`→`UTOPIA`, by
ordinal) are resolved to **direct C calls** via the engine's export table.

Done so far:

- **Module map** established: UTOPIAWA.EXE (host) + UTOPIA.DLL (engine) +
  UEXTRA.DLL (blitter), all 16-bit NE MFC. Companion home-apps deferred.
- **UTOPIA.DLL recon**: 22 code segments (815 KB) in **one cluster**, 2,261
  relocations, 71 exports / 374 entry points; 16 imported Win16 modules
  catalogued per-segment (`analysis/utopia_imports.txt`).
- **Stand-out deps identified**: MSAJT110 (Jet/Access DB — Bob's data store) and
  WAVMIX16 (actor voice mixing) — both load-bearing for a faithful port.
- **Actor (.ACT) format** decoded enough to enumerate: "LP" header, name table,
  and bodies that embed **RIFF/WAVE** voice clips + animation cels. 12 guides
  surveyed (`analysis/actors_summary.txt`), incl. Rover/Java/Scuzz/Ruby/Blythe.
- **IDA code maps** exported via idalib for all three modules (engine: 2,685
  funcs / 280,921 heads; host: 1,541 / 101,829; blitter: 36 / 1,997). Win16
  ordinal→name accumulated across 16 modules / 462 ordinals.
- **All three modules lifted into one global segment space** (UTOPIA 1–22,
  UEXTRA 25–26, UTOPIAWA 31–39) via `lift_combined.py`: per-module segment +
  internal-relocation offsetting, IDA maps re-keyed to the offset numbers, and
  host→engine ordinal imports resolved to **direct C calls** through the engine
  export table. Glue regenerated across all modules (34,942 prototypes,
  dispatcher over 34,942 functions, **16/32,618 unresolved stubs**).
- **Combined build is link-clean**: 39 translation units compile with mingw gcc,
  **0 errors / 0 warnings**, archive has **0 non-libc undefined symbols**.

Toolkit fixes made along the way (folded back into `tools/`):
- `gen_dispatch.py` now emits a public `recomp_dispatch` (the lift16 backend's
  fall-through / computed-jump entry), with a matching decl in the runtime
  header — previously only `dispatch_far`/`dispatch_near` existed.
- `ne_decode.py` zero-pads each segment's decode buffer so an IDA-verified
  instruction head near the segment-data end can't read its trailing operand
  bytes past the file slice (the Win16 loader zero-fills there anyway).
- `lift_module.py` (single module) and `lift_combined.py` (all three, with
  renumbering + cross-module ordinal resolution) replace catz's hardcoded
  `lift_dll.py` / `lift_wad.py`.
- **Critical lift fix in `ne_lift.py`**: the toolkit `lift16` backend appends a
  fall-through as `recomp_dispatch(cpu, abs>>4, abs&0xF)` using a *file*-absolute
  address — meaningless as a (selector,offset) in the NE segmented model, so it
  dispatch-missed and **returned early out of 19,421 functions**, including the
  engine entry. `ne_lift` now drops that bogus tail and keeps its own
  segment-aware fall-through. This is what turned "runs 1 instruction and
  returns" into "runs real init."
- `gen_image_bob.py`: builds the **combined flat image** for all three modules
  (segment placement, internal relocations, selector table) + `mem_layout.h`.
- `runtime/main.c`: the bring-up host — loads the image, sets up selectors,
  runs UTOPIA LibMain then the UTOPIAWA entry. `-DBOB_WATCHDOG` dumps the call
  ring if lifted code spins.
- `win16.py`: PASCAL stack-purge entries for `LOCKSEGMENT`/`UNLOCKSEGMENT`/
  `DOS3CALL`/… so those calls don't corrupt SP.

### Build & lift (full, reproducible)

```bash
# 1. IDA code maps (idalib, py 3.11) — accumulates analysis/win16_imports.json
py -3.11 tools/ida_export.py game/install/UTOPIA.DLL            analysis/utopia_ida.json
py -3.11 tools/ida_export.py game/install/UEXTRA.DLL           analysis/uextra_ida.json
py -3.11 tools/ida_export.py game/install/UTOPIAWA/UTOPIAWA.EXE analysis/utopiawa_ida.json
# 2. Lift all three modules into one segment space
py -3.11 tools/lift_combined.py
# 3. Regenerate glue across all modules
py -3.11 tools/gen_stubs.py && py -3.11 tools/gen_dispatch.py
py -3.11 tools/gen_win16_stubs.py game/install/UTOPIA.DLL game/install/UEXTRA.DLL game/install/UTOPIAWA/UTOPIAWA.EXE
py -3.11 tools/gen_segments_h.py
# 4. Build the combined flat memory image
py -3.11 tools/gen_image_bob.py
# 5. Build + run (mingw gcc must be on PATH: export PATH=/c/msys64/mingw64/bin:$PATH)
cmake -B build -G Ninja && cmake --build build
./build/bob.exe build_data/mem_image.bin
```

### Roadmap

1. ✅ Recon — module map, imports, clusters, actor format
2. ✅ IDA code map + lift — **all three modules lift to link-clean C**
3. 🟦 Bringup — **UTOPIA engine init runs to completion (24,680 calls)**; host startup next
4. ⬜ First frame — render the Bob house room (WinG/DIB)
5. ⬜ One actor on screen — load ROVER.ACT, draw a cel, play a voice clip
6. ⬜ **LLM speech** — LLM + TTS drive the actor's existing animation/voice channel

## License

Recompilation tooling and new code: MIT. Original Microsoft Bob assets and
binaries are © Microsoft and are **not** included or redistributed.
