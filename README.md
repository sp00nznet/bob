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

## Status: Recon complete — module map, imports, and actor format mapped ✅

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
- **Project scaffold** in place: NE toolchain copied in, Win16 shim runtime
  seeded from catz, CMake graph wired, analysis committed.

Next: export an IDA code map (Win16 ordinal→name + verified function bounds),
then lift **UEXTRA.DLL** first (smallest, 11 KB) end-to-end as the pipeline
shakedown, then UTOPIAWA, then UTOPIA.

### Roadmap

1. ✅ Recon — module map, imports, clusters, actor format
2. ⬜ IDA code map + lift (UEXTRA → UTOPIAWA → UTOPIA), link-clean C
3. ⬜ Bringup — host WinMain runs through engine init
4. ⬜ First frame — render the Bob house room (WinG/DIB)
5. ⬜ One actor on screen — load ROVER.ACT, draw a cel, play a voice clip
6. ⬜ **LLM speech** — LLM + TTS drive the actor's existing animation/voice channel

## License

Recompilation tooling and new code: MIT. Original Microsoft Bob assets and
binaries are © Microsoft and are **not** included or redistributed.
