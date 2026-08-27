"""tracetree.py - turn a -DCATZ_TRACE_FN log into an indented call tree.

TRACE_FN fires on entry only, so a run is a flat list of names and a chain of
returns leaves no line at all. Every lifted call pushes a return frame, so the
guest sp printed alongside each name is a stand-in for depth: a smaller sp is
deeper, and a line whose sp is at or above the caller's entry sp means that
caller (and everything under it) has returned.

Rebuilding the tree from that turns "which call did this result come back
from" from a manual bisect into reading one screen.

  py -3.11 tools/tracetree.py work/trace.log            # whole tree
  py -3.11 tools/tracetree.py work/trace.log --from seg147_013E
  py -3.11 tools/tracetree.py work/trace.log --from seg147_013E --depth 2

Guest code that switches stacks (the Jet/Access Basic thunk swaps SS:SP for a
private stack) makes sp jump by a lot with no call involved. A jump bigger than
--switch bytes is treated as a stack switch, not as depth, and is marked.
"""
import sys

SWITCH = 0x800   # sp deltas larger than this are a stack switch, not a call


def parse(path):
    """Yield (sp, name, note) per FN line; non-FN lines come back as notes."""
    with open(path, encoding='utf-8', errors='replace') as f:
        for line in f:
            line = line.rstrip('\n')
            if line.startswith('FN '):
                parts = line.split()
                if len(parts) >= 3:
                    yield int(parts[1], 16), parts[2], None
            elif line.strip():
                yield None, None, line.strip()


def tree(path, start=None, maxdepth=None, limit=None, switch=SWITCH):
    stack = []          # [(entry_sp, name)]
    armed = start is None
    shown = 0
    for sp, name, note in parse(path):
        if note is not None:
            if armed and (maxdepth is None or len(stack) <= maxdepth):
                print('  ' * len(stack) + '| ' + note)
            continue
        if stack and abs(sp - stack[-1][0]) > switch:
            # SS:SP swapped underneath us -- rebase rather than unwind.
            stack.append((sp, name))
            if armed:
                print('  ' * (len(stack) - 1) + '~ ' + name + '   [stack switch]')
            continue
        while stack and sp >= stack[-1][0]:
            stack.pop()
            if start is not None and armed and not stack:
                return              # the subtree we asked for has returned
        if not armed and name == start:
            armed = True
            stack = []
        if armed and (maxdepth is None or len(stack) <= maxdepth):
            print('  ' * len(stack) + name)
            shown += 1
            if limit and shown >= limit:
                return
        stack.append((sp, name))


def main():
    a = sys.argv[1:]
    if not a:
        print(__doc__)
        return
    def opt(flag, cast=str, default=None):
        return cast(a[a.index(flag) + 1]) if flag in a else default
    tree(a[0], start=opt('--from'), maxdepth=opt('--depth', int),
         limit=opt('--limit', int), switch=opt('--switch', lambda s: int(s, 0), SWITCH))


if __name__ == '__main__':
    main()
