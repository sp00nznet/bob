"""lift_dll.py - Re-lift all CATZDLL code segments (IDA-accurate) to src/segNNN.c.
Mirrors lift_wad.py but for the base module (no segment offset, CATZDLL IDA map)."""
import os, sys, contextlib
sys.path.insert(0, os.path.dirname(__file__))
from ne_parse import parse_ne
import ne_lift
ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
DLL = os.path.join(ROOT, 'game', 'CATZDLL.DLL')
SRC = os.path.join(ROOT, 'src')
IDA = os.path.join(ROOT, 'analysis', 'ida_funcs.json')
if os.path.exists(IDA):
    os.environ['ELFISH_IDA_JSON'] = IDA
    print(f"  IDA map: {IDA}")
dll = parse_ne(DLL)
code = [s for s in dll.segments if s.is_code]
print(f"CATZDLL code segments: {[s.index for s in code]}")
for s in code:
    out = os.path.join(SRC, f'seg{s.index:03d}.c')
    with open(out, 'w', encoding='utf-8', newline='\n') as f:
        with contextlib.redirect_stdout(f):
            ne_lift.lift_segment(dll, s.index)
print(f"  re-lifted {len(code)} CATZDLL segments")
