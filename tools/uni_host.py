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


def main():
    image, base, mods, maxidx, applied, iscode = build_image()
    engine, _ = mods[0]; host, hoff = mods[2]
    print(f"image {len(image)} bytes, segs 1..{maxidx}, internal relocs {applied}")

    uc = Uc(UC_ARCH_X86, UC_MODE_32)                 # protected mode; D=0 descs
    GDT_ADDR = roundup(len(image), 0x1000)
    uc.mem_map(0, roundup(GDT_ADDR + (maxidx + 1) * 8 + 0x2000, 0x1000))
    uc.mem_write(0, bytes(image))

    # GDT entry n -> base=base[n], limit=0xFFFF, present 16-bit (D=0).
    # access 0x9A = code exec/read, 0x92 = data r/w.
    gdt = bytearray((maxidx + 1) * 8)
    for n in range(1, maxidx + 1):
        b = base[n]
        acc = 0x9A if iscode.get(n) else 0x92
        gdt[n*8:n*8+8] = struct.pack('<HHBBBB', 0xFFFF, b & 0xFFFF,
                                     (b >> 16) & 0xFF, acc, 0x00, (b >> 24) & 0xFF)
    uc.mem_write(GDT_ADDR, bytes(gdt))
    uc.reg_write(UC_X86_REG_GDTR, (0, GDT_ADDR, len(gdt) - 1, 0))
    uc.reg_write(UC_X86_REG_CR0, uc.reg_read(UC_X86_REG_CR0) | 1)   # PE

    SEL = lambda n: n << 3
    cs, ip = host.cs + hoff, host.ip
    dgrp = host.auto_data_seg + hoff
    uc.reg_write(UC_X86_REG_CS, SEL(cs))
    uc.reg_write(UC_X86_REG_DS, SEL(dgrp))
    uc.reg_write(UC_X86_REG_ES, SEL(dgrp))
    uc.reg_write(UC_X86_REG_SS, SEL(dgrp))
    uc.reg_write(UC_X86_REG_SP, 0xFFFE)

    st = {"n": 0, "last_cs": -1}
    def hook_code(uc, address, size, _):
        st["n"] += 1
        c = uc.reg_read(UC_X86_REG_CS)
        if c != st["last_cs"]:
            ipr = uc.reg_read(UC_X86_REG_IP)
            if st["n"] < 400:
                print(f"[{st['n']:7}] CS->seg{c>>3}:{ipr:04X} (lin {address:#08x})")
            st["last_cs"] = c
    uc.hook_add(UC_HOOK_CODE, hook_code)

    maxins = 2000
    if "--max" in sys.argv: maxins = int(sys.argv[sys.argv.index("--max")+1])
    print(f"start seg{cs}:{ip:04X} (sel {SEL(cs):#x}) DS=seg{dgrp}")
    try:
        uc.emu_start(ip, 0xFFFFFFF, count=maxins)
    except UcError as e:
        c = uc.reg_read(UC_X86_REG_CS); i = uc.reg_read(UC_X86_REG_IP)
        print(f"STOP after {st['n']} ins: {e} at seg{c>>3}:{i:04X} (lin {base.__getitem__(c>>3)+i if (c>>3)<len(base) else 0:#08x})")


if __name__ == "__main__":
    main()
