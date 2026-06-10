#!/usr/bin/env python3
"""
act_parse.py - Microsoft Bob actor (.ACT) file probe.

Bob's on-screen guides (Rover, Java, Scuzz, Hopper, ...) each ship as an
".ACT" actor file. These hold the character's animation cels (RLE/transparent
DIBs blitted via UEXTRA.DLL) plus the *script* that drives what the actor does
and says. Extracting that script is step one toward the long-term goal of
letting an LLM drive actor speech.

This tool does NOT fully decode the format yet. It reports the header, the
embedded actor display name, and harvests printable strings (animation labels,
balloon text, resource names) so we can map the speech/script surface.

Usage:
  python tools/act_parse.py game/install/ACTORS/ROVER.ACT
  python tools/act_parse.py game/install/ACTORS/*.ACT --strings
"""
import sys, struct, glob, os

MAGIC = b"LP"  # 0x4C 0x50

def u16(b, o): return struct.unpack_from("<H", b, o)[0]
def u32(b, o): return struct.unpack_from("<I", b, o)[0]

def cstr(b, o):
    e = b.find(b"\x00", o)
    return b[o:e].decode("latin-1", "replace"), (e + 1 if e >= 0 else len(b))

def parse_header(b):
    if b[:2] != MAGIC:
        return None
    h = {
        "magic": "LP",
        "ver": u16(b, 2),
        "field04": u32(b, 4),
        "field08": u16(b, 8),
        "field0a": u16(b, 0xA),
        "field0c": u16(b, 0xC),
        "field0e": u32(b, 0xE),   # ~ file-size-ish value
    }
    # Display name is a C-string near offset 0x12 in observed samples.
    name, _ = cstr(b, 0x12)
    h["name"] = name if name.isprintable() else "?"
    return h

def harvest_strings(b, minlen=4):
    out, cur, start = [], [], 0
    for i, c in enumerate(b):
        if 32 <= c < 127:
            if not cur:
                start = i
            cur.append(c)
        else:
            if len(cur) >= minlen:
                out.append((start, bytes(cur).decode("latin-1")))
            cur = []
    if len(cur) >= minlen:
        out.append((start, bytes(cur).decode("latin-1")))
    return out

def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    show_strings = "--strings" in sys.argv
    paths = []
    for a in args:
        paths.extend(glob.glob(a))
    if not paths:
        print(__doc__)
        return 1
    for p in sorted(paths):
        b = open(p, "rb").read()
        h = parse_header(b)
        print(f"=== {os.path.basename(p)} ({len(b):,} bytes) ===")
        if not h:
            print("  not an LP/.ACT file (bad magic)\n")
            continue
        print(f"  name='{h['name']}' ver={h['ver']} "
              f"hdr[08..0e]={h['field08']:#06x},{h['field0a']:#06x},"
              f"{h['field0c']:#06x},{h['field0e']:#010x}")
        strs = harvest_strings(b)
        print(f"  printable strings: {len(strs)}")
        if show_strings:
            for off, s in strs:
                print(f"    {off:#08x}  {s}")
        print()
    return 0

if __name__ == "__main__":
    sys.exit(main())
