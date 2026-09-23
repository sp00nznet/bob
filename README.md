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
| MSAJT110.DLL     | —       | Jet 1.1 database engine (Bob's data store) | NE, 104 code + 2 data segs |
| MSABC110.DLL     | —       | Access Basic runtime (Jet's query path calls it) | NE, 73 code segs, no DGROUP |
| MSAES110.DLL     | —       | Access Expression Service | NE, 7 code segs + DGROUP |
| ACTORS\*.ACT     | ~0.3 MB ea | 12 guides — animation cels + embedded voice WAVs | "LP" actor format |

UTOPIA.DLL's 22 code segments form a **single connected cluster** — one coherent
engine, no dead code islands to triage.

## Pipeline

```
ne_parse   ->  segments, relocations, imports, entry/export tables
ne_xref    ->  segment clusters + per-segment import usage
act_parse  ->  actor (.ACT) header + embedded WAV/string survey
ida_export ->  authoritative function bounds + Win16 ordinal->name
ne_decode  ->  IDA-assisted 16-bit disassembly (relocations inline)
lift_combined / ne_lift -> six modules, one segment space, one C file per
              code segment; x87 -> native doubles
gen_image / gen_segments_h / gen_dispatch / gen_stubs  ->  glue
runtime/   ->  Win16 shims (KERNEL/USER/GDI/WING/WAVMIX16/Jet) + host loop
```

## Layout

```
tools/       NE toolchain (from catz/pcrecomp) + act_parse.py (actor probe)
runtime/     cpu.h (CPU+FPU model), Win16 shims, host loop (main.c, TBD)
src/         lifted C, one seg*.c per code segment -- generated locally from
             your own copy, never committed (only _exports.c, a table, is)
analysis/    recon outputs (NE parse dumps, imports, clusters, actor survey)
build_data/  flat memory image (generated, gitignored)
game/        original Bob binaries + media (gitignored, not redistributable)
docs/        ARCHITECTURE.md — module map, imports, actor format, milestones
```

## Building

**The lifted C is not in this repository.** `src/seg*.c`, `src/_dispatch.c`
and `src/_unresolved_stubs.c` are a mechanical translation of Microsoft's code,
so they are a derivative of it and are gitignored. You generate them from your
own copy of Bob — see [Build & lift](#build--lift-full-reproducible) below. A
fresh clone has no `src/seg*.c`, and CMake builds nothing until the lift runs.

## Getting the binaries

The original Bob files are **not redistributable** and are gitignored. Supply
your own OEM/retail disc, then extract:

```bash
7z x MSBOBOEM.iso -ogame/iso          # EXTRACT.EXE, SETUP.EXE, U1.CAB, ...
7z x game/iso/U1.CAB -ogame/install   # UTOPIA.DLL, UTOPIAWA.EXE, ACTORS\*.ACT, ...
```

## Status: Bringup — InitInstance runs Jet for real; frontier is Jet error -1022

All six modules — Bob's three plus the Jet 1.1 stack (MSAJT110, MSABC110,
MSAES110), lifted rather than faked — lift to link-clean C. The recompiled **engine LibMain
initializes cleanly** (`ax=0001`), the **host runs its full MFC AfxWinMain**,
and **`CWinApp::InitInstance` now dispatches and executes Bob's real startup
code**. A Unicorn differential harness (`tools/uni_host.py`) runs the *original*
binary as a ground-truth oracle: the recompiled engine matches it for **455
functions** and the host for **3677 functions** — i.e. the lift is faithful
(every divergence chased down was a harness gap, not a recomp bug).

```
UTOPIA LibMain returned (ax=0001) after 811 lifted calls    ✅ engine init OK
host -> AfxWinMain -> InitApplication -> InitInstance (seg036_2E61)  6049 calls
InitInstance: OLE init, RegisterClass, CreateWindowEx('Daemon'), engine OLE
              Automation -> DAO login (workspace "", user "Admin") -> 0x80040033
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

**Current frontier - Jet error -1022.** The DAO login's error code has walked
**-1003 -> -1310 -> -1011 -> -1022** across this round, each step a different
real defect: a three-operand `IMUL` the decoder was mis-lifting (762
instructions), `JET_SETJMP` missing from near call sites, `OpenFile`'s
`OF_PARSE`, a Jet dispatch-table entry point IDA never marked, and
`GlobalReAlloc` not preserving its handle. Along the way **Jet started opening
Bob's shipped SYSTEM.MDB and taking its `.ldb` lock**.

InitInstance runs 13,102 -> 18,386 lifted calls with zero unmatched longjmps,
zero guessed stack purges and three dispatch misses left (all in engine
LibMain).

**-1022 is now traced end to end.** It is Jet's own mapping of DOS error 6,
*invalid handle*, read out of a nineteen-entry (DOS, Jet) table in Jet's code
segment. The failing call is an `lseek` on handle `043Ah`, which the runtime
never issued: `seg077_0072` passes the `+2` field of the object at
`4014:427Eh` as a file-slot pointer, that field is **0**, and everything below
it correctly reads the slot array's free-list head as a handle. The slot
machinery itself works (other paths use it successfully), so the open question
is why that one object field is never written. See
[docs/BRINGUP.md](docs/BRINGUP.md).

### How it lifts (six modules → one program)

**All of Bob's code — engine, host, blitter, and the Jet stack it depends on —
lifts to C, compiles, and links clean.** The modules share one global segment
space and one static archive; the only unresolved symbols are standard libc.

| Module | Global segs | Result |
|--------|-------------|--------|
| **UTOPIA.DLL** (engine)   | 1–24    | 22 code segs lifted (2,685 IDA funcs / 280,921 heads) |
| **UEXTRA.DLL** (blitter)  | 25–27   | 2 code segs lifted |
| **UTOPIAWA.EXE** (host)   | 31–40   | 9 code segs lifted (1,541 IDA funcs / 101,829 heads) |
| **MSAJT110.DLL** (Jet 1.1) | 41–146  | 104 code segs lifted |
| **MSABC110.DLL** (Access Basic) | 147–219 | 73 code segs lifted |
| **MSAES110.DLL** (Expression Service) | 220–227 | 7 code segs lifted |

The Jet DLLs started as stubs; the Jet/EB query path calls into them, and the
stubs made thunk-dispatched Jet code run away, so they are lifted faithfully
instead — which is what lets Jet open Bob's real `SYSTEM.MDB`.

For the first three modules alone: **34,942 functions across 33 code segments**, dispatcher over all of
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

Everything below runs against **your own** Bob install in `game/install/`
(see [Getting the binaries](#getting-the-binaries)); the Jet DLLs ship on the
same disc. Steps 2–4 write the generated files this repo does not track.

```bash
# 1. IDA code maps (idalib, py 3.11) — accumulates analysis/win16_imports.json.
#    Optional: the analysis/*_ida.json maps are committed (addresses only).
py -3.11 tools/ida_export.py game/install/UTOPIA.DLL            analysis/utopia_ida.json
py -3.11 tools/ida_export.py game/install/UEXTRA.DLL           analysis/uextra_ida.json
py -3.11 tools/ida_export.py game/install/UTOPIAWA/UTOPIAWA.EXE analysis/utopiawa_ida.json
py -3.11 tools/ida_export.py game/install/MSAJT110.DLL          analysis/msajt110_ida.json
py -3.11 tools/ida_export.py game/install/MSABC110.DLL          analysis/msabc110_ida.json
py -3.11 tools/ida_export.py game/install/MSAES110.DLL          analysis/msaes110_ida.json
# 2. Lift all six modules into one segment space -> src/seg*.c, src/_exports.c
py -3.11 tools/lift_combined.py
# 3. Regenerate glue -> src/_unresolved_stubs.c, src/_dispatch.c, runtime stubs
py -3.11 tools/gen_stubs.py && py -3.11 tools/gen_dispatch.py
py -3.11 tools/gen_win16_stubs.py game/install/UTOPIA.DLL game/install/UEXTRA.DLL game/install/UTOPIAWA/UTOPIAWA.EXE
py -3.11 tools/gen_segments_h.py
# 4. Build the combined flat memory image
py -3.11 tools/gen_image_bob.py
# 5. Build + run (mingw gcc must be on PATH: export PATH=/c/msys64/mingw64/bin:$PATH)
cmake -B build -G Ninja && cmake --build build
./build/bob.exe build_data/mem_image.bin
# (or tools/build.sh [trace|normal] — the parallel gcc build the bring-up uses)
```

### Roadmap

1. ✅ Recon — module map, imports, clusters, actor format
2. ✅ IDA code map + lift — **all six modules lift to link-clean C**
3. 🟦 Bringup — engine init + host InitInstance run, Jet opens SYSTEM.MDB;
   **blocked on Jet error -1022** (an uninitialised RMS object field)
4. ⬜ First frame — render the Bob house room (WinG/DIB)
5. ⬜ One actor on screen — load ROVER.ACT, draw a cel, play a voice clip
6. ⬜ **LLM speech** — LLM + TTS drive the actor's existing animation/voice channel

## License

MIT for the tooling, runtime and hand-written code — see [LICENSE](LICENSE).
Microsoft Bob, its binaries, its data files, and the C lifted from them are
© Microsoft and are **not** covered by that grant and **not** included here:
no executables, DLLs, databases, actor files or lifted code are tracked. What
*is* tracked from the binaries is metadata — function addresses and import
tables under `analysis/` — plus a handful of generated tables and stubs
(`src/_exports.c`, `runtime/runtime_api.h`, `runtime/win16/win16_stubs.c`)
that name addresses and imports but contain none of Bob's instructions.
