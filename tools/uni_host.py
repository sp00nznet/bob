#!/usr/bin/env python3
"""
uni_host.py -- run the ORIGINAL Bob host (UTOPIAWA.EXE) under Unicorn as a
ground-truth oracle to diff against the recomp.

Why: the recomp's WinMain init "succeeds" but creates no window. Running the real
bytes with the SAME Win16 shim return values tells us which kind of bug it is --
if the original also makes no window, a shim returns the wrong value; if it does,
the recomp has a lifting bug at the first trace divergence.

Approach (Win16 protected mode):
  - Build the same combined flat image as gen_image_bob (UTOPIA 1-24, UEXTRA
    25-27, UTOPIAWA 31-40) but write SELECTOR fixups as GDT selectors (n<<3) and
    build a GDT where descriptor n has base=flat_base[n], limit=0xFFFF. So the
    real 16-bit code addresses memory correctly under Unicorn.
  - Import far-calls (KERNEL/USER/GDI/...) are redirected to a trap page; a code
    hook decodes (module, ordinal), runs a Python shim that mirrors the recomp's
    win16 shims, and far-returns with the right purge.
  - Trace function entries (named via the IDA map) -> work/uni_trace.log.

Phase 1 (this file as-is): image+GDT+execute host entry, trace CS/function flow.
Run: py -3.11 tools/uni_host.py [--max N]
"""
import os, sys, json, struct
os.environ.setdefault("UC_IGNORE_REG_BREAK", "1")   # quiet 16-bit seg-reg warnings
sys.path.insert(0, os.path.dirname(__file__))
from ne_parse import parse_ne
from unicorn import *
from unicorn.x86_const import *

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
G = lambda *p: os.path.join(ROOT, 'game', 'install', *p)
ANALYSIS = os.path.join(ROOT, 'analysis')
PARA = 16
MODULES = [(G('UTOPIA.DLL'), 0), (G('UEXTRA.DLL'), 24),
           (G('UTOPIAWA', 'UTOPIAWA.EXE'), 30)]


def roundup(n, a): return (n + a - 1) // a * a


def build_image():
    """Place all segments; return (image bytearray, base[], modules, max_index).
    Mirrors gen_image_bob, but selectors written into the image are GDT selectors
    (n<<3) and DGROUP/stack get a full 64 KB."""
    mods = []
    for path, off in MODULES:
        ne = parse_ne(path)
        if off:
            for s in ne.segments:
                for r in s.relocations:
                    if (r.flags & 3) == 0 and r.target_seg not in (0, 0xFF):
                        r.target_seg += off
                s.index += off
        mods.append((ne, off))

    full64 = set()
    for ne, off in mods:
        if ne.auto_data_seg: full64.add(off + ne.auto_data_seg)
        if ne.ss: full64.add(off + ne.ss)

    all_segs = [s for ne, _ in mods for s in ne.segments]
    max_index = max(s.index for s in all_segs)
    base = [0] * (max_index + 1)
    cursor = PARA
    for s in all_segs:
        sz = max(s.actual_size, s.alloc_size, 1)
        if s.index in full64: sz = max(sz, 0x10000)
        base[s.index] = cursor
        cursor += roundup(sz, PARA)
    guard = cursor; cursor += 0x10000
    image = bytearray(cursor)
    for s in all_segs:
        if s.data:
            image[base[s.index]:base[s.index] + len(s.data)] = s.data

    def chain(seg, r):
        if r.additive or not seg.data: return [r.offset]
        offs, o, seen = [], r.offset, set()
        while o != 0xFFFF and o not in seen and 0 <= o + 1 < len(seg.data):
            seen.add(o); offs.append(o); o = struct.unpack_from('<H', seg.data, o)[0]
        return offs

    SELMUL = 8                                  # GDT selector = seg index << 3
    applied = 0
    for s in all_segs:
        for r in s.relocations:
            if (r.flags & 3) != 0: continue
            tseg = r.target_seg
            if tseg == 0xFF or not (1 <= tseg <= max_index): continue
            for o in chain(s, r):
                a = base[s.index] + o
                if a + 1 >= len(image): continue
                if r.src_type == 2:
                    struct.pack_into('<H', image, a, tseg * SELMUL)
                elif r.src_type == 5:
                    struct.pack_into('<H', image, a, r.target_off & 0xFFFF)
                elif r.src_type == 3 and a + 3 < len(image):
                    struct.pack_into('<H', image, a, r.target_off & 0xFFFF)
                    struct.pack_into('<H', image, a + 2, tseg * SELMUL)
                elif r.src_type == 11 and a + 5 < len(image):
                    struct.pack_into('<I', image, a, r.target_off & 0xFFFFFFFF)
                    struct.pack_into('<H', image, a + 4, tseg * SELMUL)
                else: continue
                applied += 1
    iscode = {s.index: s.is_code for s in all_segs}
    return image, base, mods, max_index, applied, iscode


def build_imports(image, base, mods):
    """Patch every import fixup so the far pointer targets trap_seg:idx, and
    return (imports list, trap_seg). FAR_PTR(3) imports -> far call lands in the
    trap segment; OFFSET16(5) imports are huge-pointer constants we fill inline.
    Reloc chains are expanded so every fixup site is patched."""
    from win16 import get_import, module_name
    trap_seg = max(s.index for ne, _ in mods for s in ne.segments) + 1
    imports = []                              # idx -> (module, name)

    def chain(seg, r):
        if r.additive or not seg.data: return [r.offset]
        offs, o, seen = [], r.offset, set()
        while o != 0xFFFF and o not in seen and 0 <= o + 1 < len(seg.data):
            seen.add(o); offs.append(o); o = struct.unpack_from('<H', seg.data, o)[0]
        return offs

    for ne, _ in mods:
        for s in ne.segments:
            for r in s.relocations:
                tt = r.flags & 3
                if tt not in (1, 2):
                    continue
                mod = (module_name(ne, r.module_idx) or "").upper()
                imp = get_import(mod, r.ordinal)
                name = getattr(imp, "name", None) or f"{mod}.{r.ordinal}"
                for o in chain(s, r):
                    a = base[s.index] + o
                    if r.src_type == 5:       # OFFSET16 import constants
                        nu = name.upper()
                        # __WINFLAGS must have WF_PMODE (bit0) set for protected
                        # mode (real-vs-pmode test); match the recomp's GetWinFlags.
                        val = (0x0029 if "WINFLAGS" in nu else
                               8 if "AHINCR" in nu else
                               3 if "AHSHIFT" in nu else 0)
                        if a + 1 < len(image): struct.pack_into('<H', image, a, val)
                        continue
                    # FAR_PTR (and treat anything else as one): off=idx, sel=trap
                    if a + 3 >= len(image): continue
                    idx = len(imports); imports.append((mod, name))
                    struct.pack_into('<H', image, a, idx)
                    struct.pack_into('<H', image, a + 2, trap_seg << 3)
    return imports, trap_seg


def main():
    image, base, mods, maxidx, applied, iscode = build_image()
    engine, _ = mods[0]; host, hoff = mods[2]
    imports, trap_seg = build_imports(image, base, mods)
    print(f"image {len(image)} bytes, segs 1..{maxidx}, internal relocs {applied}, "
          f"imports {len(imports)} (trap seg {trap_seg})")

    # Function-entry set (global seg, off) taken from the recomp's OWN
    # segments.h, so the uni trace uses the exact same function granularity as
    # the recomp's TRACE_FN and the two traces diff cleanly.
    import re as _re
    funcs = {}
    seg_h = os.path.join(ROOT, 'runtime', 'segments.h')
    for m in _re.finditer(r'\bseg(\d+)_([0-9A-Fa-f]{4})\b', open(seg_h).read()):
        funcs[(int(m.group(1)), int(m.group(2), 16))] = f"seg{int(m.group(1)):03d}_{m.group(2).upper()}"

    uc = Uc(UC_ARCH_X86, UC_MODE_32)                 # protected mode; D=0 descs
    GDT_ADDR = roundup(len(image), 0x1000)
    TRAP_BASE = GDT_ADDR + 0x10000                   # GDT is a full 64 KB
    GUARD_BASE = TRAP_BASE + 0x10000
    uc.mem_map(0, roundup(GUARD_BASE + 0x20000, 0x1000))
    uc.mem_write(0, bytes(image))
    uc.mem_write(TRAP_BASE, b"\x90" * 0x10000)       # NOP fill; we stop before exec

    # FULL 8192-entry GDT so EVERY selector loads (matches the recomp's selector
    # model: real segments at their index, the trap selector, and ALL OTHER
    # selectors -> a guard region, exactly like sel_base[unknown]=GUARD. Without
    # this, a `mov es, <bad sel>` (uninitialised Win16 instance data) #GP-faults
    # where the recomp just reads guard zeros and continues.
    def descr(b, acc):
        return struct.pack('<HHBBBB', 0xFFFF, b & 0xFFFF, (b >> 16) & 0xFF,
                           acc, 0x00, (b >> 24) & 0xFF)
    # guard = data r/w, DPL=3 (0xF2) so selectors with any RPL (e.g. garbage
    # 0x256F, RPL=3) load without a privilege #GP at CPL=0.
    gdt = bytearray(descr(GUARD_BASE, 0xF2) * 8192)  # default: guard
    for n in range(1, maxidx + 1):
        gdt[n*8:n*8+8] = descr(base[n], 0x9A if iscode.get(n) else 0x92)
    gdt[trap_seg*8:trap_seg*8+8] = descr(TRAP_BASE, 0x9A)
    uc.mem_write(GDT_ADDR, bytes(gdt))
    uc.reg_write(UC_X86_REG_GDTR, (0, GDT_ADDR, len(gdt) - 1, 0))
    uc.reg_write(UC_X86_REG_CR0, uc.reg_read(UC_X86_REG_CR0) | 1)   # PE

    SEL = lambda n: n << 3
    cs, ip = host.cs + hoff, host.ip
    dgrp = host.auto_data_seg + hoff
    for r, v in ((UC_X86_REG_CS, SEL(cs)), (UC_X86_REG_DS, SEL(dgrp)),
                 (UC_X86_REG_ES, SEL(dgrp)), (UC_X86_REG_SS, SEL(dgrp)),
                 (UC_X86_REG_SP, 0xFFFE)):
        uc.reg_write(r, v)

    R = {n: getattr(sys.modules['unicorn.x86_const'], f'UC_X86_REG_{n.upper()}')
         for n in ('ax','bx','cx','dx','si','di','bp','sp','cs','ds','es','ss','ip')}
    rd = lambda n: uc.reg_read(R[n]); wr = lambda n, v: uc.reg_write(R[n], v & 0xFFFF)

    ITFROM = int(sys.argv[sys.argv.index("--itfrom")+1]) if "--itfrom" in sys.argv else 0
    st = {"n": 0, "last_fn": None}
    from win16 import get_purge
    # Auto-mirror the recomp's simple one-line shims (void X(CPU*){cpu->ax=N; ret(cpu,P);})
    # so uni return values match the recomp and divergences are real bugs, not
    # shim mismatches.
    impl_ax = {}
    impl_src = open(os.path.join(ROOT, 'runtime', 'win16', 'win16_impl.c')).read()
    for m in _re.finditer(r'void\s+([A-Z0-9_]+)\(CPU\s*\*cpu\)\s*\{\s*cpu->ax\s*=\s*(0x[0-9A-Fa-f]+|\d+)\s*;\s*ret\(cpu,\s*(\d+)\)', impl_src):
        impl_ax[m.group(1)] = (int(m.group(2), 0), int(m.group(3)))

    def shim(mod, name):
        """Mirror the recomp's win16 return values for control-flow fidelity.
        Returns purge bytes; default ax=0 like the recomp's stubs. Import names
        are module-prefixed (e.g. KERNEL_INITTASK) -- strip to the API."""
        full = name.upper()
        u = full
        if u.startswith(mod + '_'):
            u = u[len(mod) + 1:]
        # 1) exact one-line recomp shim (auto-mirrored)
        if full in impl_ax:
            ax, p = impl_ax[full]; wr('ax', ax); return p
        wr('ax', 0)
        # 2) stateful / multi-line shims mirrored by hand
        if u == 'INITTASK':
            wr('ax', 1); wr('cx', 0x4000); wr('dx', 1); wr('si', 0)
            wr('di', SEL(dgrp)); wr('es', SEL(dgrp)); wr('bx', 0x80); wr('bp', 0)
        elif u == 'REGISTERCLASS':
            st['atom'] = st.get('atom', 0xC000) + 1; wr('ax', st['atom'])
        elif u in ('GETCURRENTTASK',): wr('ax', 0x00FF)
        elif u in ('GETMODULEHANDLE','GETCURRENTINSTANCE','GETMODULEUSAGE'):
            wr('ax', SEL(dgrp))
        elif u in ('GETVERSION',): wr('ax', 0x0A03)
        elif u in ('GLOBALALLOC','LOCALALLOC','GLOBALLOCK','LOCALLOCK','LOADRESOURCE'):
            st['heap'] = st.get('heap', 0x4000) + 1; wr('ax', st['heap'])
        p = get_purge(mod, u)
        return p if p is not None else 0

    os.makedirs(os.path.join(ROOT, 'work'), exist_ok=True)
    trace = open(os.path.join(ROOT, 'work', 'uni_trace.log'), 'w')
    def hook_code(uc, address, size, _):
        st["n"] += 1
        c = rd('cs'); seg = c >> 3
        if seg == trap_seg:
            idx = rd('ip')
            mod, name = imports[idx] if idx < len(imports) else ("?", f"?{idx}")
            purge = shim(mod, name)
            if "--dbg" in sys.argv and st.get('dbg', 0) < 60:
                st['dbg'] = st.get('dbg', 0) + 1
                print(f"  [imp {st['n']:5}] {name} (idx {idx}) -> ax={rd('ax'):04X} purge={purge}")
            sp = rd('sp'); ss = rd('ss')
            rip = struct.unpack('<H', uc.mem_read(base[ss>>3] + sp, 2))[0]
            rcs = struct.unpack('<H', uc.mem_read(base[ss>>3] + sp + 2, 2))[0]
            wr('cs', rcs); wr('sp', sp + 4 + purge)
            st['resume'] = rip
            uc.emu_stop(); return
        if "--itrace" in sys.argv and st["n"] >= ITFROM:
            print(f"  i[{st['n']:5}] seg{seg}:{rd('ip'):04X} (lin {address:#08x}) "
                  f"bytes={bytes(uc.mem_read(address, min(size,6))).hex()}")
        # function-entry trace (only host/engine code segs, not trap)
        fn = funcs.get((seg, rd('ip')))
        if fn and fn != st["last_fn"]:
            trace.write(fn + "\n"); st["last_fn"] = fn
    uc.hook_add(UC_HOOK_CODE, hook_code)

    def hook_intr(uc, intno, _):
        # DOS INT 21h: the host's C0 uses ah=0x25 (set vector, no-op), ah=0x30
        # (get version), ah=0x4C (exit). Mirror the recomp's dos_int21 minimally.
        if intno == 0x21:
            ah = (rd('ax') >> 8) & 0xFF
            if ah == 0x30: wr('ax', 0x0A03)          # DOS 3.10-ish
            elif ah == 0x4C: uc.emu_stop(); st['exit'] = rd('ax') & 0xFF
            # else no-op (set/get vector etc.)
        # else: ignore
    uc.hook_add(UC_HOOK_INTR, hook_intr)

    budget = 200000
    if "--max" in sys.argv: budget = int(sys.argv[sys.argv.index("--max")+1])
    print(f"start seg{cs}:{ip:04X} DS=seg{dgrp}; budget {budget} ins")
    cur = ip
    while st["n"] < budget:
        try:
            uc.emu_start(cur, 0xFFFFFFF, count=budget - st["n"])
        except UcError as e:
            c = rd('cs'); i = rd('ip')
            print(f"STOP after {st['n']} ins: {e} at seg{c>>3}:{i:04X}")
            break
        if 'resume' in st:
            cur = st.pop('resume'); continue       # returned from an import shim
        break                                       # natural stop
    trace.close()
    why = f"DOS exit {st['exit']:#x}" if 'exit' in st else "count/natural"
    nfn = sum(1 for _ in open(os.path.join(ROOT, 'work', 'uni_trace.log')))
    print(f"ran {st['n']} ins ({why}); {nfn} fn entries -> work/uni_trace.log")


if __name__ == "__main__":
    main()
