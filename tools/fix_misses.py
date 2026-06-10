"""
fix_misses.py - Seed indirect-call (vtable) targets the disassembler missed.

Indirect calls/jumps (`call far [mem]`) resolve at runtime to (selector,offset)
pairs stored in vtables/function-pointer tables. The disassembler only seeds
functions from prologues, direct-call targets, and IDA's function list, so a
vtable method only ever reached indirectly may not be lifted -> the runtime
dispatcher misses it and the virtual call is silently dropped (often -> abort).

This reads a run log for `dispatch_(far|near) MISS seg=N off=XXXX` lines and
adds each target offset to the right IDA function map (CATZDLL ida_funcs.json
for seg 1-59; CATZ.WAD wad_ida_funcs.json for seg 60-66, de-offset by 59), so a
re-lift turns them into real functions.

Run:  python tools/fix_misses.py build/run.log
Then: re-lift the affected modules, regen glue, rebuild.
"""
import os
import re
import sys
import json

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
ANALYSIS = os.path.join(ROOT, 'analysis')
SEG_OFFSET = 59

DLL_JSON = os.path.join(ANALYSIS, 'ida_funcs.json')
WAD_JSON = os.path.join(ANALYSIS, 'wad_ida_funcs.json')
MISS_RE = re.compile(r'dispatch_(?:far|near) MISS seg=(\d+) off=([0-9A-Fa-f]+)')


def load(p):
    return json.load(open(p, encoding='utf-8')) if os.path.exists(p) else {}


def main():
    log = sys.argv[1] if len(sys.argv) > 1 else os.path.join(ROOT, 'build', 'run.log')
    text = open(log, encoding='utf-8', errors='replace').read()

    misses = {}      # (seg, off) -> count
    for m in MISS_RE.finditer(text):
        seg, off = int(m.group(1)), int(m.group(2), 16)
        misses[(seg, off)] = misses.get((seg, off), 0) + 1
    if not misses:
        print("no dispatch misses found")
        return

    dll = load(DLL_JSON)
    wad = load(WAD_JSON)
    added_dll = added_wad = 0
    for (seg, off), n in sorted(misses.items()):
        if seg <= SEG_OFFSET:
            key = str(seg)
            ent = dll.setdefault(key, {"functions": [], "heads": [], "code_ranges": []})
            if off not in ent["functions"]:
                ent["functions"].append(off); ent["functions"].sort(); added_dll += 1
        else:
            key = str(seg - SEG_OFFSET)        # WAD json keyed by NE seg 1..N
            ent = wad.setdefault(key, {"functions": [], "heads": [], "code_ranges": []})
            if off not in ent["functions"]:
                ent["functions"].append(off); ent["functions"].sort(); added_wad += 1
        print(f"  seg{seg}:0x{off:04X} ({n}x)")

    if added_dll:
        json.dump(dll, open(DLL_JSON, 'w', encoding='utf-8'))
    if added_wad:
        json.dump(wad, open(WAD_JSON, 'w', encoding='utf-8'))
    print(f"added {added_dll} CATZDLL + {added_wad} CATZ.WAD forced entries "
          f"({len(misses)} unique misses)")


if __name__ == '__main__':
    main()
