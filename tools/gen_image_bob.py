"""
gen_image_bob.py - Build one flat memory image holding all three Bob modules:
the UTOPIA engine (segs 1-24), the UEXTRA blitter (25-27) and the UTOPIAWA host
(31-40). Mirrors lift_combined.py's segment numbering exactly.

Each segment n is placed at SEG_SEGMENT_BASE[n]; selectors are normalized to
these global segment numbers. Internal relocations are applied for every module
(target segments offset the same way the lift did). Cross-module host->engine
far calls were resolved to direct C calls by the lifter, so import relocations
are left alone.

Entry/stack/auto-data come from the UTOPIAWA host EXE. The UTOPIA engine's
auto-data (DGROUP) stays mapped so its exported functions' __loadds prologues
resolve DS correctly.

Outputs:
  build_data/mem_image.bin   flat image
  runtime/mem_layout.h       SEG_SEGMENT_BASE[], sizes, host+engine entry/data

Run: py -3.11 tools/gen_image_bob.py
"""
import os, sys, struct

sys.path.insert(0, os.path.dirname(__file__))
from ne_parse import parse_ne, import_name

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
G = lambda *p: os.path.join(ROOT, 'game', 'install', *p)
PARA = 16
MAX_SEL = 0x10000

# (path, seg_offset) — must match tools/lift_combined.py
MODULES = [
    (G('UTOPIA.DLL'),               0),   # engine (base)
    (G('UEXTRA.DLL'),               24),  # blitter
    (G('UTOPIAWA', 'UTOPIAWA.EXE'), 30),  # host
    (G('MSAJT110.DLL'),             40),  # Jet 1.1 database engine (41..146)
    (G('MSABC110.DLL'),             146), # Access Basic runtime (147..219, no DGROUP)
    (G('MSAES110.DLL'),             219), # Access Expression Service (220..227)
]


def roundup(n, a):
    return (n + a - 1) // a * a


def chain_offsets(seg, r):
    """Borland reloc chains: r.offset is a linked list head walked through the
    segment data until 0xFFFF. Non-additive only."""
    if r.additive or not seg.data:
        return [r.offset]
    offs, off, seen, data = [], r.offset, set(), seg.data
    while off != 0xFFFF and off not in seen and 0 <= off + 1 < len(data):
        seen.add(off); offs.append(off)
        off = struct.unpack_from('<H', data, off)[0]
    return offs


def build_xmod(mods):
    """{MODULE: {ordinal|NAME: (global_seg, offset)}} -- same shape as"""
    """lift_combined's, so a data fixup naming another lifted module"""
    """resolves the same way a code one does."""
    xmod = {}
    for ne, off in mods:
        mod = os.path.basename(ne.filename).rsplit('.', 1)[0].upper()
        m = {}
        for e in ne.entries:
            m[e.ordinal] = (e.segment + off, e.offset)
            if e.name:
                m[e.name.upper()] = (e.segment + off, e.offset)
        xmod[mod] = m
    return xmod


def apply_relocs(image, base, image_size, mods, max_index, xmod):
    applied = 0
    for ne, _off in mods:
      for s in ne.segments:
        for r in s.relocations:
            tt = r.flags & 3
            if tt == 0:
                tseg, toff = r.target_seg, r.target_off
            elif tt in (1, 2):
                # An import fixup naming another LIFTED module is just an
                # internal one in disguise. The lifter resolves these in
                # code; a data segment holding e.g. `seg UEXTRA.HOLE` kept
                # the 0xFFFF placeholder, and the engine loaded 0xFFFF as a
                # selector. Imports of real Win16 modules stay untouched --
                # those are shims, not guest memory.
                mod = (ne.module_names[r.module_idx - 1].upper()
                       if r.module_idx <= len(ne.module_names) else '')
                key = (import_name(ne, r.ordinal).upper() if tt == 2
                       else r.ordinal)
                t = xmod.get(mod, {}).get(key)
                if t is None:
                    continue
                tseg, toff = t
            else:
                continue
            if tseg == 0xFF or not (1 <= tseg <= max_index):
                continue
            for off in chain_offsets(s, r):
                addr = base[s.index] + off
                if addr + 1 >= image_size:
                    continue
                if r.src_type == 2:                # SELECTOR
                    struct.pack_into('<H', image, addr, tseg)
                elif r.src_type == 5:              # OFFSET16
                    struct.pack_into('<H', image, addr, toff & 0xFFFF)
                elif r.src_type == 3 and addr + 3 < image_size:    # FAR_PTR
                    struct.pack_into('<H', image, addr, toff & 0xFFFF)
                    struct.pack_into('<H', image, addr + 2, tseg)
                elif r.src_type == 11 and addr + 5 < image_size:   # PTR48
                    struct.pack_into('<I', image, addr, toff & 0xFFFFFFFF)
                    struct.pack_into('<H', image, addr + 4, tseg)
                else:
                    continue
                applied += 1
    return applied


def main():
    mods = []
    for path, off in MODULES:
        ne = parse_ne(path)
        # Offset segment indices + internal reloc targets into the global range.
        if off:
            for s in ne.segments:
                for r in s.relocations:
                    if (r.flags & 3) == 0 and r.target_seg not in (0, 0xFF):
                        r.target_seg += off
                s.index += off
        mods.append((ne, off))

    engine, _ = mods[0]
    host, host_off = mods[2]

    all_segs = [s for ne, _ in mods for s in ne.segments]
    max_index = max(s.index for s in all_segs)

    # DGROUP / stack segments must be allocated a full 64 KB: Win16 puts a
    # module's statics at the bottom and its stack at the top of the SAME
    # segment, so code that touches ss:[small] (a global) and code that pushes
    # near sp=0xFFFE must land in one contiguous 64 KB region. Packing them to
    # actual size splits those into different image areas and derails any
    # ss:[abs] global access. Collect each module's auto-data + stack segment.
    full64 = set()
    for ne, off in mods:
        if ne.auto_data_seg:
            full64.add(off + ne.auto_data_seg)
        if ne.ss:
            full64.add(off + ne.ss)

    base = [0] * MAX_SEL
    cursor = PARA                               # guard paragraph at offset 0
    for s in all_segs:
        sz = max(s.actual_size, s.alloc_size, 1)
        if s.index in full64:
            sz = max(sz, MAX_SEL)               # full 64 KB DGROUP/stack
        base[s.index] = cursor
        cursor += roundup(sz, PARA)
    guard_base = cursor
    cursor += 0x10000
    image_size = cursor
    for sel in range(MAX_SEL):
        if base[sel] == 0:
            base[sel] = guard_base
    base[0] = guard_base

    image = bytearray(image_size)
    for s in all_segs:
        if s.data:
            image[base[s.index]:base[s.index] + len(s.data)] = s.data

    applied = apply_relocs(image, base, image_size, mods, max_index,
                           build_xmod(mods))

    out_dir = os.path.join(ROOT, 'build_data')
    os.makedirs(out_dir, exist_ok=True)
    with open(os.path.join(out_dir, 'mem_image.bin'), 'wb') as f:
        f.write(image)

    entry_seg = host_off + host.cs
    stack_seg = host_off + host.ss
    host_data = host_off + host.auto_data_seg
    eng_data  = engine.auto_data_seg            # engine at offset 0

    hdr = ['/* mem_layout.h - Auto-generated by gen_image_bob.py. */',
           '#ifndef CATZ_MEM_LAYOUT_H', '#define CATZ_MEM_LAYOUT_H',
           '#include <stdint.h>',
           f'#define CATZ_IMAGE_SIZE {image_size}u',
           f'#define CATZ_GUARD_BASE {guard_base}u',
           f'#define CATZ_NUM_SEG {max_index}',
           f'#define CATZ_ENTRY_SEG {entry_seg}      /* UTOPIAWA host startup (Borland C0 -> WinMain) */',
           f'#define CATZ_ENTRY_IP 0x{host.ip:04X}u',
           f'#define CATZ_STACK_SEG {stack_seg}',
           f'#define CATZ_STACK_SP 0x{host.sp:04X}u',
           f'#define CATZ_AUTO_DATA_SEG {host_data}    /* UTOPIAWA DGROUP */',
           f'#define CATZ_DLL_ENTRY_SEG {engine.cs}      /* UTOPIA LibMain */',
           f'#define CATZ_DLL_ENTRY_IP 0x{engine.ip:04X}u',
           f'#define CATZ_DLL_AUTO_DATA_SEG {eng_data}  /* UTOPIA DGROUP */',
           f'static const uint32_t SEG_SEGMENT_BASE[{max_index + 1}] = {{']
    row = []
    for n in range(0, max_index + 1):
        row.append(str(base[n]))
        if len(row) == 12:
            hdr.append('    ' + ','.join(row) + ','); row = []
    if row:
        hdr.append('    ' + ','.join(row) + ',')
    hdr += ['};', '#endif /* CATZ_MEM_LAYOUT_H */']

    with open(os.path.join(ROOT, 'runtime', 'mem_layout.h'), 'w',
              encoding='utf-8', newline='\n') as f:
        f.write('\n'.join(hdr) + '\n')

    print(f'image: {image_size} bytes ({image_size/1048576:.2f} MB), segs 1..{max_index}, '
          f'relocs applied={applied}')
    print(f'host entry seg{entry_seg}:0x{host.ip:04X}  stack seg{stack_seg}:0x{host.sp:04X}  '
          f'host-data seg{host_data}  engine-data seg{eng_data}  engine-entry seg{engine.cs}:0x{engine.ip:04X}')


if __name__ == '__main__':
    main()
