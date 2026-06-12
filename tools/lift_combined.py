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
import os, sys, json, struct, contextlib

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


def offset_module(ne, offset):
    """Shift a module's segment indices and internal relocation targets."""
    if offset == 0:
        return
    for s in ne.segments:
        for r in s.relocations:
            if (r.flags & 3) == 0 and r.target_seg not in (0, 0xFF):
                r.target_seg += offset
        s.index += offset


def scan_data_farptrs(ne, ida_off):
    """Find code entry points reached only through far-pointer TABLES in data
    (C++ constructor lists, vtables, ...). Each table entry is {offset,
    selector}; the selector carries a SELECTOR(2) relocation while the offset is
    the data word right before it. IDA's recursive descent never sees these
    (they're data-driven), so it disassembles the bytes as code but never makes
    a function -- and the lifter then has no `segNNN_off` to dispatch to.

    Returns {global_code_seg(str): set(offsets)}, restricted to offsets IDA
    already classified as code heads (so we never promote real data to code).
    Call AFTER offset_module so seg numbers are global. `ida_off` is the
    offset-keyed IDA map."""
    code_idx = {s.index for s in ne.segments if s.is_code}
    out = {}
    for s in ne.segments:
        if s.is_code or not s.data:
            continue
        for r in s.relocations:
            if (r.flags & 3) != 0 or r.src_type != 2:   # internal SELECTOR only
                continue
            if r.target_seg not in code_idx:
                continue
            heads = ida_off.get(str(r.target_seg), {}).get('heads')
            if not heads:
                continue
            heads = set(heads)
            # One SELECTOR reloc patches a CHAIN of locations (a linked list
            # walked through the data, 0xFFFF-terminated). Each patched location
            # is a far-pointer SELECTOR word; the OFFSET word sits just before it.
            loc, seen = r.offset, set()
            while loc != 0xFFFF and loc not in seen and 2 <= loc + 1 < len(s.data):
                seen.add(loc)
                nxt = struct.unpack_from('<H', s.data, loc)[0]   # chain link (pre-reloc)
                off = struct.unpack_from('<H', s.data, loc - 2)[0]
                if off in heads:                         # only IDA-verified code
                    out.setdefault(str(r.target_seg), set()).add(off)
                if r.additive:
                    break
                loc = nxt
    return out


def build_ida_map(src_name, offset, ne):
    """Load the IDA map, re-key to global seg numbers, fold in data far-pointer
    code entries, write to disk and point ELFISH_IDA_JSON at it. Returns the
    augmented offset map (or {} if no IDA source)."""
    src = os.path.join(ANALYSIS, src_name)
    if not os.path.exists(src):
        os.environ.pop('ELFISH_IDA_JSON', None)
        print(f"  (no {src_name} -- linear sweep)")
        return {}
    data = json.load(open(src, encoding='utf-8'))
    off = {str(int(k) + offset): v for k, v in data.items()}
    extra = scan_data_farptrs(ne, off)
    n = 0
    for gseg, offs in extra.items():
        funcs = set(off[gseg].get('functions', []))
        new = offs - funcs
        if new:
            off[gseg]['functions'] = sorted(funcs | offs)
            n += len(new)
    if n:
        print(f"  +{n} far-pointer-table code entries promoted to functions")
    dst = os.path.join(ANALYSIS, src_name.replace('.json', f'_lift{offset}.json'))
    json.dump(off, open(dst, 'w', encoding='utf-8'))
    os.environ['ELFISH_IDA_JSON'] = dst
    return off


def main():
    # Engine export table -> xmod for the host's ordinal imports (engine at off 0).
    engine = parse_ne(MODULES[0][0])
    xmod = {'UTOPIA': {e.ordinal: (e.segment, e.offset) for e in engine.entries}}
    print(f"UTOPIA export entries: {len(xmod['UTOPIA'])}")

    total = 0
    for path, offset, ida in MODULES:
        name = os.path.basename(path)
        ne = engine if offset == 0 else parse_ne(path)
        offset_module(ne, offset)
        ida_map = build_ida_map(ida, offset, ne)
        code = [s for s in ne.segments if s.is_code]
        # A "code" segment that IDA found NO instructions in is really a data
        # blob (e.g. UTOPIA seg 1, a far-pointer dispatch table). Lifting it via
        # linear sweep yields garbage callable functions that execution can
        # derail into. Skip it: it stays in the flat image as data (with its
        # SELECTOR relocations applied by gen_image_bob).
        lift_segs, data_segs = [], []
        for s in code:
            heads = ida_map.get(str(s.index), {}).get('heads', [])
            (lift_segs if heads or not ida_map else data_segs).append(s)
        if data_segs:
            print(f"{name}: offset {offset} -> {len(lift_segs)} code segs; "
                  f"data-only (no IDA code): {[s.index for s in data_segs]}")
        else:
            print(f"{name}: offset {offset} -> code segs "
                  f"{lift_segs[0].index}..{lift_segs[-1].index}")
        for s in lift_segs:
            out = os.path.join(SRC, f'seg{s.index:03d}.c')
            with open(out, 'w', encoding='utf-8', newline='\n') as f:
                with contextlib.redirect_stdout(f):
                    ne_lift.lift_segment(ne, s.index, xmod=xmod)
            total += 1
    print(f"lifted {total} segments across {len(MODULES)} modules")


if __name__ == '__main__':
    main()
