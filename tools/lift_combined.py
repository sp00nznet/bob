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
#   UTOPIA 1..24, UEXTRA 25..27, UTOPIAWA 31..40, MSAJT110 41..146 (104 code +
#   2 data). MSAJT110 = the real Jet 1.1 database engine; the engine accesses
#   its Access .MDB data through it (DAO/CDatabase -> the Jet stack-switching
#   thunk). Lifting it faithfully (vs faking) reads the real databases.
MODULES = [
    (G('UTOPIA.DLL'),            0,  'utopia_ida.json'),
    (G('UEXTRA.DLL'),            24, 'uextra_ida.json'),
    (G('UTOPIAWA', 'UTOPIAWA.EXE'), 30, 'utopiawa_ida.json'),
    (G('MSAJT110.DLL'),          40, 'msajt110_ida.json'),
]

# Exact engine `call far [mem]` (OLE/IDispatch vtable) targets that MISS at
# runtime -- collected by building with -DELFISH_TRACE_RUNTIME and grepping
# `dispatch_far MISS seg=N off=XXXX` (engine global segs 1-24, real offsets;
# the off=FFFF sentinel misses are intentional returns and are excluded).
# {global_seg: [offsets]}. Re-collect after each round as InitInstance advances.
FORCE_PROMOTE = {
    2:  [0x05E9],          # OLE IDispatch method (seg021_004B vtable+0xC)
    7:  [0x099E],
    11: [0x13EF],
    13: [0x681A],
}


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


def scan_pushed_code_farptrs(ne, ida_off):
    """Find code entry points built inline as `push seg X; push offset Y; call`
    (a Win16 far-proc argument). The segment push carries a SELECTOR(2) fixup to
    code segment X; the immediately following instruction is `push imm16` (0x68)
    whose immediate is the code offset Y (Y is NOT relocated -- offsets are final;
    IDA only knows it's code via xref). Promote (X, Y) when Y is an IDA code-head
    so the later `call far [arg]` dispatches to a real function instead of
    missing (e.g. seg036:0x37F8, called 257x as a no-op before this).

    Uses build_reloc_map so chained SELECTOR fixups are covered. Call AFTER
    offset_module (seg numbers global). `ida_off` is the offset-keyed IDA map."""
    from ne_decode import build_reloc_map
    code_idx = {s.index for s in ne.segments if s.is_code}
    out = {}
    for s in ne.segments:
        if not s.data:
            continue
        rm = build_reloc_map(s, ne)
        for off, ann in rm.items():
            r = ann.reloc
            if (r.flags & 3) != 0 or r.src_type != 2:    # internal SELECTOR
                continue
            if r.target_seg not in code_idx:
                continue
            # seg push is `68 <imm16>`; the next op must be `push imm16` (0x68).
            if off + 4 >= len(s.data) or s.data[off + 2] != 0x68:
                continue
            y = struct.unpack_from('<H', s.data, off + 3)[0]
            heads = ida_off.get(str(r.target_seg), {}).get('heads')
            if heads and y in set(heads):
                out.setdefault(str(r.target_seg), set()).add(y)
    return out


def scan_vtable_farptrs(ne, ida_off, min_run=3):
    """Find C++ vtables / far-pointer dispatch tables embedded in CODE segments
    (16-bit MFC places the CWinApp vtable inside a code segment, e.g. UTOPIAWA
    seg1:0x2028). Such a table is a contiguous run of {offset(2), selector(2)}
    far pointers -- i.e. the SELECTOR-reloc-patched words sit at a regular
    stride of 4. Scattered far-call/mov instruction operands also carry SELECTOR
    relocs but never form a stride-4 run, so requiring a run of >= min_run
    entries cleanly separates real tables from code operands (a broad code-seg
    chain walk over-promotes mid-function instruction heads and corrupts the
    lift). For each table entry promote its offset word when it is an IDA code
    head in the target code segment, so `call far [vtable+N]` dispatches to a
    real function instead of missing (InitInstance/Run were dead before this).

    Returns {global_code_seg(str): set(offsets)}. Call AFTER offset_module."""
    from ne_decode import build_reloc_map
    code_idx = {s.index for s in ne.segments if s.is_code}
    seg_by_idx = {s.index: s for s in ne.segments}

    _jt_cache = {}

    def jump_targets(tseg):
        """Set of offsets that are the target of an intra-segment Jcc/jmp/loop.
        A genuine function entry is reached only via call/vtable, never by a
        jump, so a stride-4 entry that IS a jump target is a mid-function
        case/loop label (e.g. seg005_16EA, target of `je 16EA`) -- promoting it
        splits the function and corrupts control flow."""
        if tseg in _jt_cache:
            return _jt_cache[tseg]
        tg = seg_by_idx.get(tseg)
        hs = ida_off.get(str(tseg), {}).get('heads')
        tgt = set()
        if tg and tg.data and hs:
            d = tg.data; n = len(d)
            def s8(b): return b - 256 if b >= 128 else b
            def s16(lo, hi): v = lo | (hi << 8); return v - 65536 if v >= 32768 else v
            for h in hs:
                if h + 1 >= n:
                    continue
                op = d[h]
                if op == 0xEB or 0x70 <= op <= 0x7F or 0xE0 <= op <= 0xE3:  # rel8 jmp/Jcc/loop/jcxz
                    tgt.add((h + 2 + s8(d[h + 1])) & 0xFFFF)
                elif op == 0xE9 and h + 2 < n:                              # jmp rel16
                    tgt.add((h + 3 + s16(d[h + 1], d[h + 2])) & 0xFFFF)
                elif op == 0x0F and h + 3 < n and 0x80 <= d[h + 1] <= 0x8F:  # Jcc rel16
                    tgt.add((h + 4 + s16(d[h + 2], d[h + 3])) & 0xFFFF)
        _jt_cache[tseg] = tgt
        return tgt

    def is_fn_start(tseg, off):
        """True only when `off` is a genuine function entry: (1) the preceding
        instruction is a terminator -- ret/retf or jmp (a vtable method starts
        right after the prior method's `retf`, or after a tail `jmp`); a call
        before it means `off` is a RETURN ADDRESS (skip), a non-terminator means
        `off` is a fall-through mid-function label (skip). AND (2) `off` is not
        an intra-segment jump target (which would make it a loop/case label).
        Walk back over NOP/INT3 padding. This separates real vtable methods from
        far JUMP-TABLE entries / loop headers / return addresses, all of which
        corrupt the lift if split into their own function."""
        if off in jump_targets(tseg):
            return False
        tg = seg_by_idx.get(tseg)
        if not tg or not tg.data:
            return False
        hs = ida_off.get(str(tseg), {}).get('heads')
        if not hs:
            return False
        heads_below = [h for h in hs if h < off]
        if not heads_below:
            return True                              # nothing before -> seg start
        prev = max(heads_below)
        d = tg.data
        for _ in range(8):                           # skip a little padding
            op = d[prev] if prev < len(d) else 0
            if op in (0xC3, 0xCB, 0xC2, 0xCA,        # ret/retf [imm16]
                      0xE9, 0xEB):                   # jmp rel16/rel8 (tail)
                return True
            if op in (0x90, 0xCC):                   # nop / int3 padding
                below = [h for h in hs if h < prev]
                if not below:
                    return True
                prev = max(below); continue
            return False
        return False

    out = {}
    for s in ne.segments:
        if not s.is_code or not s.data:
            continue
        rm = build_reloc_map(s, ne)
        sel = {o: ann.reloc.target_seg for o, ann in rm.items()
               if ann.reloc.src_type == 2 and ann.reloc.target_seg in code_idx}
        locs = sorted(sel)
        i = 0
        while i < len(locs):
            j = i
            while j + 1 < len(locs) and locs[j + 1] == locs[j] + 4:
                j += 1
            if j - i + 1 >= min_run:                  # a stride-4 far-ptr table
                for k in range(i, j + 1):
                    loc = locs[k]
                    if loc - 2 < 0:
                        continue
                    off = struct.unpack_from('<H', s.data, loc - 2)[0]
                    tseg = sel[loc]
                    heads = ida_off.get(str(tseg), {}).get('heads')
                    if heads and off in set(heads) and is_fn_start(tseg, off):
                        out.setdefault(str(tseg), set()).add(off)
            i = j + 1
    return out


def build_ida_map(src_name, offset, ne):
    """Load the IDA map, re-key to global seg numbers, fold in far-pointer code
    entries (data tables + inline `push seg/offset`), write to disk and point
    ELFISH_IDA_JSON at it. Returns the augmented offset map (or {} if no IDA)."""
    src = os.path.join(ANALYSIS, src_name)
    if not os.path.exists(src):
        os.environ.pop('ELFISH_IDA_JSON', None)
        print(f"  (no {src_name} -- linear sweep)")
        return {}
    data = json.load(open(src, encoding='utf-8'))
    off = {str(int(k) + offset): v for k, v in data.items()}
    extra = scan_data_farptrs(ne, off)
    pushed = scan_pushed_code_farptrs(ne, off)
    srcs = [pushed]
    # Code-segment vtable promotion is currently enabled for the HOST module
    # only (offset 30 == UTOPIAWA). The host's MFC AfxWinMain dispatches
    # InitInstance/Run through the CWinApp vtable in code seg1; without these
    # promotions those virtual calls miss and no window is ever created. The
    # engine (offset 0) returns ax=0001 cleanly WITHOUT this and regresses with
    # it (its init path derails through some promoted entry) -- gated off until
    # that is understood. See docs/BRINGUP.md.
    if offset == 30:                          # host module only (see BRINGUP.md)
        srcs.append(scan_vtable_farptrs(ne, off))
    for src in srcs:
        for gseg, offs in src.items():
            extra.setdefault(gseg, set()).update(offs)
    # Surgical engine promotions: exact `call far [mem]` (vtable/IDispatch)
    # targets that MISS at runtime (collected via dispatch_far MISS logging),
    # so the engine's OLE-Automation virtual dispatches resolve. Promoting only
    # genuine indirect-CALL miss targets (never retf/return addresses, which go
    # through recomp_dispatch) avoids the speculative stride-4 over-promotion
    # that wandered/crashed engine init. Grows as InitInstance reaches deeper.
    for gseg, offs in FORCE_PROMOTE.items():
        if str(gseg) in off:
            extra.setdefault(str(gseg), set()).update(
                o for o in offs if o in set(off[str(gseg)].get('heads', [])))
    n = 0
    for gseg, offs in extra.items():
        funcs = set(off[gseg].get('functions', []))
        new = offs - funcs
        if new:
            off[gseg]['functions'] = sorted(funcs | offs)
            n += len(new)
    if n:
        print(f"  +{n} far-pointer code entries promoted to functions")
    dst = os.path.join(ANALYSIS, src_name.replace('.json', f'_lift{offset}.json'))
    json.dump(off, open(dst, 'w', encoding='utf-8'))
    os.environ['ELFISH_IDA_JSON'] = dst
    return off


def main():
    # Engine export table -> xmod for the host's ordinal imports (engine at off 0).
    engine = parse_ne(MODULES[0][0])
    xmod = {'UTOPIA': {e.ordinal: (e.segment, e.offset) for e in engine.entries}}
    print(f"UTOPIA export entries: {len(xmod['UTOPIA'])}")
    # MSAJT110 (Jet) export table -> xmod so the engine's MSAJT110 imports (by
    # name+ordinal) resolve to direct calls into the lifted Jet code. Segments
    # are global (MSAJT110 is offset by its MODULES entry).
    jt_path, jt_off = next((p, o) for p, o, _ in MODULES if 'MSAJT110' in p)
    jt_ne = parse_ne(jt_path)
    xmod['MSAJT110'] = {e.ordinal: (e.segment + jt_off, e.offset) for e in jt_ne.entries}
    print(f"MSAJT110 export entries: {len(xmod['MSAJT110'])}")

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
