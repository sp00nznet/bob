# Microsoft Bob — Architecture & Recon

Recon notes for the static recompilation. All figures come from the toolkit's
NE tools (`tools/ne_parse.py`, `tools/ne_xref.py`) run against the OEM release
binaries (build date 1995-01-30, the same "BETA1" disc image we extracted).

## Module map

Bob is codenamed **Utopia**. It is a Microsoft Foundation Classes (MFC)
application compiled to **16-bit NE** (New Executable, Win16). Like Catz, it
splits into a thin host EXE plus a large engine DLL:

```
UTOPIAWA.EXE  (356 KB)  the "Welcome Aboard" host — WinMain, main window,
                        message loop. MFC app. Imports UTOPIA + UWAOLE.
UTOPIA.DLL    (1.05 MB) the engine — rooms, actors, the Jet-backed data store,
                        sprite/balloon rendering. 71 exports, 374 entry points.
UEXTRA.DLL    (11 KB)   hand-tuned blit helpers: RLE / transparent-DIB stretch
                        used to draw actor cels (RLETRANSEXPAND, COPYDIBBITS,
                        TRANSCOPYDIBBITS, DOSTRETCHTRANSPARENTDIBITS, ...).
QDOC.DLL      (356 KB)  help/QuickDoc subsystem (secondary target).
ACTORS\*.ACT           the on-screen guides (see "Actor files" below).
```

The companion "home" apps (LETTER, CALENDAR, CHKBOOK, ADDRESS, NOTEBOOK,
SAFARI, GeoSafari, the mail room) are separate NE EXEs that sit on top of the
same engine. They are out of scope for the first milestone — get **the house +
one actor** rendering first.

### UTOPIA.DLL (primary target)

| Metric | Value |
|--------|-------|
| Format | NE (16-bit segmented), Win16 DLL, PROTMODE |
| Toolchain | MSVC C++ / MFC (`_AFX_VERSION`, `CRecordset`, `CDatabase`, MSVC mangling) |
| Code segments | 22 (814,978 bytes) |
| Data segments | 2 |
| Relocations | 2,261 |
| Exports | 71 resident names / 374 entry points |
| Cluster | **all 22 code segments are one connected component** |
| Entry | seg 5:0x120D |

### Imported Win16 modules (the shim TODO list)

From `analysis/utopia_imports.txt`. These are what `runtime/win16/` must back:

| Module | Role | Recomp strategy |
|--------|------|-----------------|
| KERNEL   | memory, files, modules, profiles | GlobalAlloc/Lock/Free -> heap; file I/O; thunks |
| USER     | windows, messages, input, menus  | CreateWindow/messages -> Win32 / SDL2 |
| GDI      | DCs, bitmaps, palettes, BitBlt    | DC/DIB/palette -> GDI32 or SDL2 |
| UEXTRA   | RLE/transparent DIB blitting       | call our own lifted UEXTRA, or native memcpy/blit |
| WING     | WinG fast off-screen blit          | DIB section / SDL2 surface |
| WAVMIX16 | multi-channel WAV mixing (actor voices) | SDL2_mixer / WASAPI |
| MMSYSTEM | multimedia timer / PlaySound       | SDL2 timer + audio |
| OLE2 / OLE2DISP / COMPOBJ | OLE automation (embedding, mail) | stub first; minimal IUnknown later |
| MSAJT110 | **Microsoft Jet (Access) DB engine** — Bob's data store | shim to SQLite, or lift the .MDB access paths |
| MSABC110 | Access Basic runtime               | stub / minimal |
| COMMDLG  | common dialogs                     | Win32 comdlg32 / SDL2 dialogs |
| KEYBOARD / SHELL / WIN87EM | input, shell, x87 emulation | native |

The two stand-out dependencies versus a normal Win16 game are **MSAJT110**
(Bob keeps user data — letters, the address book, finances — in a Jet/Access
database) and **WAVMIX16** (the actors speak via mixed WAV playback). Both are
load-bearing for a faithful recomp.

## Actor files (`ACTORS/*.ACT`)

The on-screen guides are the heart of Bob and the anchor for the long-term
LLM-driven-speech goal. Each is a self-contained `.ACT` bundle. Probed with
`tools/act_parse.py`:

```
Header:
  0x00  "LP"            magic
  0x02  u16  version    = 1 in all shipped actors
  0x04  u32  (flags?)
  0x08  u16  nameLen    name length incl. NUL  (verified: matches each name)
  0x0A  u16  = 0x12 + nameLen   (offset just past the name)
  0x0E  u32  dirOffset  offset of a trailing directory near EOF
  0x12  char[] name     NUL-terminated display name
  ...   section directory, animation cels (RLE/transparent DIBs), and
        embedded RIFF "WAVE" audio clips (the recorded actor voice lines)
```

Shipped actors (display name may differ from filename):

| File | Name | Size | WAV clips | strings |
|------|------|------|-----------|---------|
| ROVER.ACT  | Rover     | 420 KB | many | 4,070 |
| JAVA.ACT   | Java      | 362 KB | 38   | 4,981 |
| SCUZZ.ACT  | Scuzz     | 404 KB | many | 4,024 |
| RUBY.ACT   | Ruby      | 407 KB | many | 4,821 |
| BLYTHE.ACT | Blythe    | 348 KB | many | 6,419 |
| ORBY.ACT   | Orby      | 307 KB | many | 3,439 |
| CHAOS.ACT  | Chaos     | 285 KB | many | 2,209 |
| HOPPER.ACT | Hopper    | 237 KB | few  | 862 |
| SHELLY.ACT | Shelly    | 478 KB | many | 3,434 |
| WORM.ACT   | Digger    | 351 KB | many | 4,405 |
| ZSPEAKER.ACT | Speaker | 6 KB   | 0    | system/voice routing actor |
| ZVISIBLE.ACT | Invisible | 2 KB | 0    | system/visibility actor |

The actors carry their voice as embedded **RIFF/WAVE** chunks plus animation
cels. The original speech is pre-recorded audio paired with on-screen text
balloons; the LLM path replaces/augments the balloon text and routes new lines
through TTS, while reusing the actor's existing animation set.

## Pipeline (planned, mirrors the Catz NE path)

```
ne_parse   ->  segments, relocations, imports, entry/export tables   [DONE]
ne_xref    ->  segment clusters + per-segment import usage           [DONE]
ida_export ->  authoritative function bounds + Win16 ordinal->name   (next)
ne_decode  ->  IDA-assisted 16-bit disassembly, relocations inline
ne_lift    ->  one C file per code segment; x87 -> native doubles
gen_image      ->  flat memory image of data segments + relocations
gen_segments_h ->  cross-segment prototypes
gen_dispatch   ->  indirect call/jmp dispatcher
gen_stubs      ->  stubs for unresolved targets
runtime/       ->  Win16 shims (KERNEL/USER/GDI/WING/WAVMIX16/Jet) + host loop
```

## Milestones

1. **Recon** — module map, imports, clusters, actor format. ✅ (this doc)
2. **IDA code map + lift** — UEXTRA first (11 KB, smallest), then UTOPIAWA,
   then UTOPIA. Link-clean C with 0 unresolved far calls.
3. **Bringup** — host WinMain runs: window creation through engine init.
4. **First frame** — render the Bob house room via WinG/DIB.
5. **One actor on screen** — load ROVER.ACT, draw a cel, play a voice clip.
6. **LLM speech** — replace the scripted balloon text with an LLM, drive the
   existing animation set + TTS through the actor's voice channel.
