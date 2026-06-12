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

## Status: Bringup — UTOPIA engine init runs to completion ✅

All three modules lift to link-clean C **and the recompiled engine fully
initializes.** `bob.exe` loads the combined flat image, sets up selectors, and
runs `UTOPIA` LibMain through **24,680 lifted calls to a clean return** —
including real Win16 work (`GlobalAlloc`, `RegisterWindowMessage`,
`DeferWindowPos`, …) and MFC's full module-state + C++ class registration.

```
Microsoft Bob Recomp - starting
  image: build_data/mem_image.bin (1.30 MB)
  engine entry: seg5:120D (UTOPIA LibMain), engine-data seg24
  host entry:   seg35:0002 (UTOPIAWA), host-data seg40, stack seg40
[win16] GlobalAlloc(flags=2002, 4096) -> 4000      <- real engine init
[win16] REGISTERWINDOWMESSAGE / DEFERWINDOWPOS ...
UTOPIA LibMain returned (ax=0100) after 24680 lifted calls   ✅ engine init done
```

Two fixes unlocked this (see **[docs/BRINGUP.md](docs/BRINGUP.md)**):
1. **NE seg 1 is data, not code** — IDA found zero instructions in it (it's a
   far-pointer dispatch table); the lifter was linear-sweeping it into 34 KB of
   garbage functions that execution derailed into. `lift_combined.py` now skips
   any "code" segment with no IDA heads (kept as data in the image).
2. **64 KB DGROUP + small-model SS=DS** — the engine C-runtime accesses globals
   via `ss:[abs]` assuming `SS==DS==DGROUP`. `gen_image_bob.py` now allocates
   DGROUP/stack segments a full 64 KB (statics at the bottom, stack at the top),
   and LibMain runs with `SS=DS=`engine DGROUP. This took init from stalling at
   93 calls to completing at 24,680.

**Current frontier:** the **UTOPIAWA host** now runs past its `InitTask` re-init
loop (fixed: InitTask returns the stack *limit* in CX, not the top) into WinMain,
and aborts via `FatalAppExit` with the MFC message **"no main procedure"** —
`AfxWinMain` can't find the `CWinApp` object because the host's C++ ctor walk
isn't constructing it yet. See [docs/BRINGUP.md](docs/BRINGUP.md).

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
