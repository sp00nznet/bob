"""lift_module.py - Lift all CODE segments of one NE module to src/segNNN.c.

Generic Bob driver (parameterized version of catz's lift_dll.py). Uses the
module's IDA code map (function bounds + instruction heads) via ELFISH_IDA_JSON
and the shared analysis/win16_imports.json (ordinal->API) auto-loaded by win16.py.

Usage:
  py -3.11 tools/lift_module.py game/install/UEXTRA.DLL analysis/uextra_ida.json
"""
import os, sys, contextlib
sys.path.insert(0, os.path.dirname(__file__))
from ne_parse import parse_ne
import ne_lift

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
SRC = os.path.join(ROOT, 'src')
os.makedirs(SRC, exist_ok=True)

binary = sys.argv[1]
ida = sys.argv[2] if len(sys.argv) > 2 else None
if ida and os.path.exists(ida):
    os.environ['ELFISH_IDA_JSON'] = os.path.abspath(ida)
    print(f"  IDA map: {ida}")

ne = parse_ne(binary)
code = [s for s in ne.segments if s.is_code]
print(f"{os.path.basename(binary)} code segments: {[s.index for s in code]}")
for s in code:
    out = os.path.join(SRC, f'seg{s.index:03d}.c')
    with open(out, 'w', encoding='utf-8', newline='\n') as f:
        with contextlib.redirect_stdout(f):
            ne_lift.lift_segment(ne, s.index)
    print(f"  -> src/seg{s.index:03d}.c ({os.path.getsize(out):,} bytes)")
print(f"lifted {len(code)} segments")
