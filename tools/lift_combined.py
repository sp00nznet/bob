"""lift_combined.py - Lift all three Bob modules into one global segment space.

Bob is a 3-module NE program: the host EXE imports the engine DLL, which imports
the blit helper DLL (UTOPIAWA -> UTOPIA -> UEXTRA). To recompile them into one
flat image we give each module a disjoint segment range and resolve cross-module
calls to direct C calls where the importer uses ordinals.

  module        seg_offset   global segs   role
  UTOPIA.DLL        0           1..24       engine (base; natural numbering)
  UEXTRA.DLL       24          25..27       blit helpers (imported by name)
  UTOPIAWA.EXE     30          31..40       host (imports UTOPIA by ordinal)

For each module we offset its segment indices and internal relocation targets,
re-key its IDA code map to the offset segment numbers (ne_decode reads it via
ELFISH_IDA_JSON; the map is cached per-NEHeader so each module loads its own),
and lift each CODE segment to src/segNNN.c.

Cross-module resolution (`xmod` = {MODULE: {ordinal: (global_seg, off)}}):
  - UTOPIAWA -> UTOPIA: by ordinal (type 1) -> resolved to direct calls.
  - UTOPIA -> UEXTRA:   by name (type 2) -> left as Win16-style import stubs for
    now (UEXTRA is lifted in 25..27; wiring its call sites is a bringup step).

Run: py -3.11 tools/lift_combined.py
"""
import os, sys, json, contextlib

sys.path.insert(0, os.path.dirname(__file__))
from ne_parse import parse_ne
import ne_lift

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
SRC = os.path.join(ROOT, 'src')
ANALYSIS = os.path.join(ROOT, 'analysis')
os.makedirs(SRC, exist_ok=True)

G = lambda *p: os.path.join(ROOT, 'game', 'install', *p)

# (path, seg_offset, ida_json)
MODULES = [
    (G('UTOPIA.DLL'),            0,  'utopia_ida.json'),
    (G('UEXTRA.DLL'),            24, 'uextra_ida.json'),
    (G('UTOPIAWA', 'UTOPIAWA.EXE'), 30, 'utopiawa_ida.json'),
]


def rekey_ida(src_name, offset):
    """Re-key an IDA code map (NE seg -> data) to offset segment numbers and
    point ELFISH_IDA_JSON at it. Returns False if the source map is missing."""
    src = os.path.join(ANALYSIS, src_name)
    if not os.path.exists(src):
        os.environ.pop('ELFISH_IDA_JSON', None)
        print(f"  (no {src_name} -- linear sweep)")
        return False
    if offset == 0:
        os.environ['ELFISH_IDA_JSON'] = src
        return True
    data = json.load(open(src, encoding='utf-8'))
    off = {str(int(k) + offset): v for k, v in data.items()}
    dst = os.path.join(ANALYSIS, src_name.replace('.json', f'_off{offset}.json'))
    json.dump(off, open(dst, 'w', encoding='utf-8'))
    os.environ['ELFISH_IDA_JSON'] = dst
    return True


def offset_module(ne, offset):
    """Shift a module's segment indices and internal relocation targets."""
    if offset == 0:
        return
    for s in ne.segments:
        for r in s.relocations:
            if (r.flags & 3) == 0 and r.target_seg not in (0, 0xFF):
                r.target_seg += offset
        s.index += offset


def main():
    # Engine export table -> xmod for the host's ordinal imports (engine at off 0).
    engine = parse_ne(MODULES[0][0])
    xmod = {'UTOPIA': {e.ordinal: (e.segment, e.offset) for e in engine.entries}}
    print(f"UTOPIA export entries: {len(xmod['UTOPIA'])}")

    total = 0
    for path, offset, ida in MODULES:
        name = os.path.basename(path)
        ne = engine if offset == 0 else parse_ne(path)
        rekey_ida(ida, offset)
        offset_module(ne, offset)
        code = [s for s in ne.segments if s.is_code]
        print(f"{name}: offset {offset} -> code segs {code[0].index}..{code[-1].index}")
        for s in code:
            out = os.path.join(SRC, f'seg{s.index:03d}.c')
            with open(out, 'w', encoding='utf-8', newline='\n') as f:
                with contextlib.redirect_stdout(f):
                    ne_lift.lift_segment(ne, s.index, xmod=xmod)
            total += 1
        print(f"  wrote {len(code)} segments")
    print(f"lifted {total} segments across {len(MODULES)} modules")


if __name__ == '__main__':
    main()
