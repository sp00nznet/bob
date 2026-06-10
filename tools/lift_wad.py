"""
lift_wad.py - Lift the CATZ.WAD host module, cross-linked to CATZDLL.

CATZ.WAD (the real game host: WinMain + window + message loop) imports CATZDLL
by ordinal. To recompile it alongside the engine in one flat image we:

  - number CATZ.WAD's segments 60.. (CATZDLL keeps 1-59) so the `seg{NNN}_`
    naming and selector model don't collide;
  - resolve CATZ.WAD's CATZDLL import relocations (by ordinal) to the lifted
    CATZDLL export functions via CATZDLL's entry table;
  - leave KERNEL/USER/GDI/etc. imports to the shared Win16 shims.

Output: src/seg060.c .. src/seg06N.c (one per CATZ.WAD code segment).

Run: python tools/lift_wad.py
"""
import os
import sys
import json
import contextlib

sys.path.insert(0, os.path.dirname(__file__))
from ne_parse import parse_ne
import ne_lift

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
DLL_PATH = os.path.join(ROOT, 'game', 'CATZDLL.DLL')
WAD_PATH = os.path.join(ROOT, 'game', 'CATZ.WAD')
SEG_OFFSET = 59          # CATZ.WAD seg N  ->  global seg (59 + N)
SRC = os.path.join(ROOT, 'src')
ANALYSIS = os.path.join(ROOT, 'analysis')


def prepare_ida_bounds():
    """Re-key the WAD IDA code map (NE seg 1..N) to the offset segment numbers
    (60..) and point ne_decode at it via ELFISH_IDA_JSON, so the WAD lift is
    IDA-accurate without colliding with CATZDLL's ida_funcs.json."""
    src = os.path.join(ANALYSIS, 'wad_ida_funcs.json')
    if not os.path.exists(src):
        print("  (no wad_ida_funcs.json — WAD lifts via linear sweep)")
        return
    data = json.load(open(src, encoding='utf-8'))
    off = {str(int(k) + SEG_OFFSET): v for k, v in data.items()}
    dst = os.path.join(ANALYSIS, 'wad_ida_funcs_offset.json')
    json.dump(off, open(dst, 'w', encoding='utf-8'))
    os.environ['ELFISH_IDA_JSON'] = dst
    print(f"  IDA bounds: {len(off)} segs re-keyed -> {dst}")


def main():
    prepare_ida_bounds()
    # CATZDLL export table: ordinal -> (segment, offset) for cross-module calls.
    dll = parse_ne(DLL_PATH)
    xmod = {'CATZDLL': {e.ordinal: (e.segment, e.offset) for e in dll.entries}}
    print(f"CATZDLL export entries: {len(xmod['CATZDLL'])}")

    wad = parse_ne(WAD_PATH)
    # Offset segment numbers + internal relocation targets so they live at 60+.
    for s in wad.segments:
        for r in s.relocations:
            if (r.flags & 3) == 0 and r.target_seg not in (0, 0xFF):
                r.target_seg += SEG_OFFSET
        s.index += SEG_OFFSET

    code_segs = [s for s in wad.segments if s.is_code]
    print(f"CATZ.WAD code segments (offset): {[s.index for s in code_segs]}")

    os.makedirs(SRC, exist_ok=True)
    for s in code_segs:
        out = os.path.join(SRC, f'seg{s.index:03d}.c')
        with open(out, 'w', encoding='utf-8', newline='\n') as f:
            with contextlib.redirect_stdout(f):
                ne_lift.lift_segment(wad, s.index, xmod=xmod)
        print(f"  wrote {out}")


if __name__ == '__main__':
    main()
