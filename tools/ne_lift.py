"""
ne_lift.py - NE-aware 16-bit x86 to C Lifter for El-Fish Recomp

Extends pcrecomp's lift16.py with:
- NE relocation-aware far call resolution
- x87 FPU instruction lifting to native C double operations
- TSXLIB import resolution to C runtime stubs
- Segment-aware memory access

Usage:
    python ne_lift.py <ne_exe> --seg N [--func OFFSET] [--all]
"""

import sys
import os
from typing import Optional

_PC = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', 'tools', 'tools'))
sys.path.insert(0, os.path.join(_PC, 'disasm'))
sys.path.insert(0, os.path.join(_PC, 'lift'))
sys.path.insert(0, os.path.dirname(__file__))

from decode16 import Decoder, Instruction, OpType, Operand, REG16_NAMES
from lift16 import Lifter, _read, _write, _reg16, _sreg, _mem_addr, _label
from ne_parse import parse_ne, NEHeader, Segment, import_name
from ne_decode import disassemble_segment, build_reloc_map
from fpu_decode import decode_fpu, format_fpu
from win16 import get_import, module_name, is_fpu_module


# Operand kinds a fixup can land on. Including the memory forms changes
# exactly one instruction across all 199 segments -- the one below -- so
# it is targeted, not a broad rewrite.
_RELOC_OPERANDS = (OpType.IMM8, OpType.IMM16, OpType.MEM, OpType.MOFFS)


class NELifter(Lifter):
    """Lifts NE executable segments to C code with FPU and relocation support."""

    def __init__(self, ne: NEHeader, seg: Segment):
        super().__init__()
        self.ne = ne
        self.seg = seg
        self.reloc_map = build_reloc_map(seg, ne)
        # Build function name map: (seg_num, offset) -> name
        self.func_names = {}
        # Segment lookup by (possibly offset) index — robust to segment-number
        # remapping used for multi-module recomp (CATZ.WAD segs become 60+).
        self.seg_by_index = {s.index: s for s in ne.segments}
        # Cross-module call resolution: {MODULE_UPPER: {ordinal: (seg, off)}}.
        # Set externally for the host module (CATZ.WAD -> CATZDLL exports).
        self.xmod = {}

    def _resolve_far_call(self, inst: Instruction) -> Optional[str]:
        """Resolve a far call instruction using relocation data."""
        local_off = inst.offset - self.seg.file_offset
        # Check relocations at offset+1 (the operand bytes of CALL far)
        for off in range(local_off, local_off + inst.length):
            if off in self.reloc_map:
                ann = self.reloc_map[off]
                r = ann.reloc
                target_type = r.flags & 3
                if target_type == 0:  # Internal
                    if r.target_seg > 0 and r.target_seg != 0xFF:
                        target = self.seg_by_index.get(r.target_seg)
                        # A SELECTOR(2) fixup patches ONLY the segment word; the
                        # call's offset is the instruction's own far immediate
                        # (`call far SEG:off`). Using r.target_off there (which is
                        # 0 for selector fixups) sends every such call to off 0 --
                        # e.g. the host's `call WinMain` became seg032_0000 (a
                        # stub) instead of seg032_1C2A, so WinMain never ran.
                        if r.src_type == 2 and inst.op1 and inst.op1.type == OpType.FAR:
                            off = inst.op1.disp & 0xFFFF
                        else:
                            off = r.target_off & 0xFFFF
                        if target is not None and target.is_code:
                            return f'seg{r.target_seg:03d}_{off:04X}'
                        else:
                            return f'/* data ref seg{r.target_seg}:{off:04X} */'
                elif target_type in (1, 2):  # Import by ordinal / by name
                    mod = module_name(self.ne, r.module_idx)
                    # Cross-module call into another lifted module (e.g. CATZDLL):
                    # resolve the ordinal to that module's export entry -> function.
                    t = self._xres(r)
                    if t is not None:
                        s, o = t
                        return f'seg{s:03d}_{o:04X}'
                    imp = get_import(mod, r.ordinal)
                    return imp.name
        return None

    def _xres(self, r) -> Optional[tuple]:
        """Resolve an import fixup to a (global_seg, offset) in a lifted
        module, or None if that module is not one of ours.

        Import-by-ordinal (type 1) keys on the ordinal. Import-by-NAME
        (type 2) has no ordinal at all -- the field the NE calls `ordinal`
        is a byte offset into this module's imported names table -- so it
        keys on the name the target module exports. Looking the offset up
        as an ordinal always missed, which is why every UTOPIA -> UEXTRA
        call landed on a no-op stub named UEXTRA_Ord173."""
        xm = self.xmod.get(module_name(self.ne, r.module_idx).upper())
        if not xm:
            return None
        if (r.flags & 3) == 2:
            return xm.get(import_name(self.ne, r.ordinal).upper())
        return xm.get(r.ordinal)

    def _reloc_imm(self, r) -> Optional[int]:
        """The 16-bit offset an OFFSET16 fixup resolves to, or None."""
        if (r.flags & 3) == 0:
            return r.target_off & 0xFFFF
        t = self._xres(r)
        return None if t is None else t[1] & 0xFFFF

    def _get_reloc_at(self, local_off: int) -> Optional[object]:
        """Get relocation annotation at a given local offset."""
        return self.reloc_map.get(local_off)

    def lift_instruction(self, inst: Instruction, func_start: int):
        """Override to handle FPU instructions and NE-specific features."""
        m = inst.mnemonic
        op1 = inst.op1
        op2 = inst.op2
        local_off = inst.offset - self.seg.file_offset
        orig = repr(inst)

        # Emit label if this address is a jump target
        self._emit_label(inst.address)

        # --- FWAIT / NOP are no-ops in our model ---
        # CATZ uses real x87 instructions (not inline FP-emulation trampolines
        # like El-Fish's TSXLIB), so FWAIT/NOP carry no semantics here. (An NOP
        # may host a fixup site, but the fixup target is what matters, not the
        # NOP itself.) Drop them.
        if m in ('wait', 'nop'):
            if m == 'wait':
                return
            if m == 'nop':
                return

        # --- FPU instructions ---
        if m.startswith('f') and not m.startswith('flags'):
            self._lift_fpu(inst, m, orig)
            return

        # --- Far calls with relocation resolution ---
        if m == 'call' and op1 and op1.type == OpType.FAR:
            func_name = self._resolve_far_call(inst)
            if func_name and func_name == getattr(self, 'setjmp_fn', None):
                # Guest setjmp. The host anchor JET_SETJMP plants has to sit
                # in THIS function's frame -- the one the guest returns to
                # when it longjmps -- so it is a macro at the call site
                # rather than anything the callee could do. A non-zero
                # result means a longjmp landed here with the guest
                # registers already restored, so there is nothing to do but
                # carry on. See runtime/win16/jet_setjmp.h.
                self._emit(f'if (JET_SETJMP(cpu) == 0) {{ push16(cpu, cpu->cs); '
                           f'push16(cpu, 0xFFFF); {func_name}(cpu); }}', orig)
            elif func_name and not func_name.startswith('/*'):
                self._emit(f'push16(cpu, cpu->cs); push16(cpu, 0xFFFF);', 'far call return addr')
                self._emit(f'{func_name}(cpu);', orig)
            elif func_name:
                self._emit(func_name, orig)
            else:
                self._emit(f'/* unresolved far call {orig} */', orig)
            return

        # --- Indirect far call/jmp through memory (function pointer dispatch) ---
        if m in ('call far', 'jmp far') and op1 and op1.type == OpType.MEM:
            seg_e, off_e = _mem_addr(op1)
            read = (f'uint16_t _o = mem_read16(cpu, {seg_e}, {off_e}); '
                    f'uint16_t _s = mem_read16(cpu, {seg_e}, (uint16_t)({off_e} + 2));')
            if m == 'call far':
                self._emit(f'{{ {read} push16(cpu, cpu->cs); push16(cpu, 0xFFFF); '
                           f'dispatch_far(cpu, _s, _o); }}', orig)
            else:  # jmp far -> tail dispatch
                self._emit(f'{{ {read} dispatch_far(cpu, _s, _o); return; }}', orig)
            return

        # --- Indirect near call/jmp through memory (target in this segment) ---
        if m in ('call', 'jmp') and op1 and op1.type == OpType.MEM:
            seg_e, off_e = _mem_addr(op1)
            idx = self.seg.index
            if m == 'call':
                self._emit(f'{{ uint16_t _o = mem_read16(cpu, {seg_e}, {off_e}); '
                           f'push16(cpu, 0xFFFF); dispatch_near(cpu, {idx}, _o); }}', orig)
            else:  # jmp near indirect -> tail dispatch
                self._emit(f'{{ uint16_t _o = mem_read16(cpu, {seg_e}, {off_e}); '
                           f'dispatch_near(cpu, {idx}, _o); return; }}', orig)
            return

        # --- Near jmp/Jcc to another function in this segment -> tail call ---
        # (base lifter would drop these as "out of function" comments)
        _CC = {'jo': 'cc_o', 'jno': 'cc_no', 'jb': 'cc_b', 'jae': 'cc_ae',
               'je': 'cc_e', 'jne': 'cc_ne', 'jbe': 'cc_be', 'ja': 'cc_a',
               'js': 'cc_s', 'jns': 'cc_ns', 'jp': 'cc_p', 'jnp': 'cc_np',
               'jl': 'cc_l', 'jge': 'cc_ge', 'jle': 'cc_le', 'jg': 'cc_g'}
        if (m == 'jmp' or m in _CC) and op1 and op1.type in (OpType.REL8, OpType.REL16):
            target = op1.disp
            if target not in self.valid_addrs:
                if target in getattr(self, 'seg_func_offsets', ()):
                    tail = f'seg{self.seg.index:03d}_{target:04X}(cpu); return;'
                else:
                    # No function there: IDA read those bytes as data, so
                    # nothing was lifted at that offset. Dispatch on the
                    # segment we are IN. lift16's fallback splits a
                    # file-absolute address as (abs >> 4, abs & 0xF), which
                    # names a segment that does not exist -- the miss then
                    # returns early and the caller reads its locals off a
                    # stack nobody unwound. A miss here is still a miss, but
                    # an honest one, and it lands if the target is ever
                    # promoted.
                    tail = (f'recomp_dispatch(cpu, {self.seg.index}, '
                            f'0x{target:04X}); return;')
                if m == 'jmp':
                    self._emit(tail, orig)
                else:
                    self._emit(f'if ({_CC[m]}(cpu)) {{ {tail} }}', orig)
                return

        # --- loop/jcxz to another function in this segment -> tail call ---
        if m in ('loop', 'loopz', 'loopnz', 'jcxz') and op1 and op1.type in (OpType.REL8, OpType.REL16):
            target = op1.disp
            if target not in self.valid_addrs:
                callee = (f'seg{self.seg.index:03d}_{target:04X}(cpu); return;'
                          if target in getattr(self, 'seg_func_offsets', ())
                          else f'recomp_dispatch(cpu, {self.seg.index}, 0x{target:04X}); return;')
                cond = {'loop': 'cpu->cx != 0',
                        'loopz': 'cpu->cx != 0 && zf(cpu)',
                        'loopnz': 'cpu->cx != 0 && !zf(cpu)',
                        'jcxz': 'cpu->cx == 0'}[m]
                dec = 'cpu->cx--; ' if m != 'jcxz' else ''
                self._emit(f'{dec}if ({cond}) {{ {callee} }}', orig)
                return

        # --- Far jumps (resolve via relocation -> tail call) ---
        if m == 'jmp' and op1 and op1.type == OpType.FAR:
            func_name = self._resolve_far_call(inst)
            if func_name and not func_name.startswith('/*'):
                # Tail call: run the target, then return to our caller.
                self._emit(f'{func_name}(cpu); return;', orig)
            else:
                self._emit(f'/* unresolved far jmp {orig} */', orig)
            return

        # --- Near calls ---
        if m == 'call' and op1 and op1.type in (OpType.REL8, OpType.REL16):
            target = op1.disp
            func_name = f'seg{self.seg.index:03d}_{target:04X}'
            self.func_calls.add(func_name)
            self._emit(f'push16(cpu, 0xFFFF);', 'near call return addr')
            self._emit(f'{func_name}(cpu);', orig)
            return

        # --- Relocated immediates: `mov reg/mem, SELECTOR|OFFSET of symbol` ---
        # The immediate in the original bytes is a placeholder (0xFFFF); the real
        # value comes from the relocation. gen_image patches these in DATA, but
        # the lifted CODE uses the immediate directly, so resolve it here.
        # Covers taking the address of a function/data (incl. cross-module, e.g.
        # a CATZDLL export's offset/selector stored as a WAD callback pointer).
        if m == 'mov' and op2 and op2.type in (OpType.IMM8, OpType.IMM16, OpType.IMM32):
            for off in range(local_off + 1, local_off + inst.length):
                ann = self._get_reloc_at(off)
                if not ann:
                    continue
                r = ann.reloc
                tt = r.flags & 3
                if r.src_type == 3:        # POINTER32 (full far ptr seg:off in a 32-bit imm)
                    # `mov eax, <far ptr to symbol>` -- e.g. a far ptr to an
                    # MSAJT110/MSABC110 Jet function loaded into EAX and handed to
                    # the stack-switch thunk. Without this the placeholder
                    # 0xSSSSFFFF is used and the thunk dispatches to garbage.
                    if tt == 0:
                        self._emit(_write(op1, f'(((uint32_t)SEG_{r.target_seg}) << 16) | 0x{r.target_off & 0xFFFF:04X}'),
                                   f'{orig} -- far ptr seg{r.target_seg}:{r.target_off:04X}')
                        return
                    elif tt in (1, 2):
                        mod = module_name(self.ne, r.module_idx)
                        t = self._xres(r)
                        if t is not None:
                            s, o = t
                            self._emit(_write(op1, f'(((uint32_t)SEG_{s}) << 16) | 0x{o & 0xFFFF:04X}'),
                                       f'{orig} -- far ptr {mod}.{r.ordinal}')
                            return
                if r.src_type == 2:        # SELECTOR (segment of a symbol)
                    if tt == 0:
                        self._emit(_write(op1, f'SEG_{r.target_seg}'),
                                   f'{orig} -- selector for seg{r.target_seg}')
                        return
                    elif tt in (1, 2):     # cross-module selector (e.g. CATZDLL)
                        mod = module_name(self.ne, r.module_idx)
                        t = self._xres(r)
                        if t is not None:
                            self._emit(_write(op1, f'SEG_{t[0]}'),
                                       f'{orig} -- selector for {mod}.{r.ordinal}')
                            return
                elif r.src_type == 5:      # OFFSET16 (offset of a symbol)
                    if tt == 0:
                        self._emit(_write(op1, f'0x{r.target_off & 0xFFFF:04X}'),
                                   f'{orig} -- offset of seg{r.target_seg}:{r.target_off:04X}')
                        return
                    elif tt in (1, 2):
                        mod = module_name(self.ne, r.module_idx)
                        t = self._xres(r)
                        if t is not None:
                            self._emit(_write(op1, f'0x{t[1] & 0xFFFF:04X}'),
                                       f'{orig} -- offset of {mod}.{r.ordinal}')
                            return

        # --- Relocated `push imm16`: `push seg X` / `push offset Y` ---
        # Win16 C passes a far pointer argument as `push seg; push offset; call`.
        # The selector/offset immediates carry SELECTOR(2)/OFFSET16(5) fixups (the
        # raw bytes are a placeholder). The mov-immediate path above doesn't cover
        # push, so without this the placeholder selector is pushed verbatim and a
        # later `call far [arg]` dispatches to a bogus segment (e.g. seg035_06D0
        # was handed 0x41A:37F8 instead of seg036:37F8 -> 257 missed calls).
        if m == 'push' and op1 and op1.type in (OpType.IMM8, OpType.IMM16):
            for off in range(local_off + 1, local_off + inst.length):
                ann = self._get_reloc_at(off)
                if not ann:
                    continue
                r = ann.reloc
                tt = r.flags & 3
                if r.src_type == 2 and tt == 0:                 # SELECTOR of a symbol
                    self._emit(f'push16(cpu, SEG_{r.target_seg});',
                               f'{orig} -- selector for seg{r.target_seg}')
                    return
                if r.src_type == 2 and tt in (1, 2):            # cross-module selector
                    mod = module_name(self.ne, r.module_idx)
                    t = self._xres(r)
                    if t is not None:
                        self._emit(f'push16(cpu, SEG_{t[0]});',
                                   f'{orig} -- selector for {mod}.{r.ordinal}')
                        return
                if r.src_type == 5 and tt == 0:                 # OFFSET16 of a symbol
                    self._emit(f'push16(cpu, 0x{r.target_off & 0xFFFF:04X});',
                               f'{orig} -- offset of seg{r.target_seg}:{r.target_off:04X}')
                    return
                if r.src_type == 5 and tt in (1, 2):            # cross-module import OFFSET
                    # `push offset <import>` (e.g. a far ptr to an MSABC110/MSAJT110
                    # Jet/EB function handed to the stack-switch thunk). Without this
                    # the placeholder 0xFFFF is pushed and the thunk dispatches to
                    # seg:FFFF (garbage) -> the Daemon's EB query fails.
                    mod = module_name(self.ne, r.module_idx)
                    t = self._xres(r)
                    if t is not None:
                        self._emit(f'push16(cpu, 0x{t[1] & 0xFFFF:04X});',
                                   f'{orig} -- offset of {mod}.{r.ordinal}')
                        return

        # --- Relocated immediate on anything the two branches above miss ---
        # `sub ax, offset UEXTRA.B$PEND` is the subtraction that sizes the
        # Access Basic DGROUP template copy, and nothing here handled a fixup
        # on an arithmetic immediate -- so the placeholder 0xFFFE survived and
        # the copy ran from a garbage segment. An OFFSET16 target is a plain
        # number, so rewriting the operand lets the base lifter emit it
        # unchanged; SELECTOR needs the symbolic SEG_n and stays above.
        # ADDITIVE means the stored word is an addend, not a chain link.
        # The fixup can sit on an immediate OR on a memory displacement:
        # `mov ax, es:[offset UEXTRA.HOLE]` reads the size the Access Basic
        # runtime needs, and with the placeholder left in place it read
        # es:[0xFFFF], got 0, and the segment allocated for the runtime came
        # out 0x265A bytes too small -- so its own template copy overwrote
        # the stack it was running on.
        imm = next((o for o in (op2, op1)
                    if o is not None and o.type in _RELOC_OPERANDS), None)
        if imm is not None:
            for off in range(local_off + 1, local_off + inst.length):
                ann = self._get_reloc_at(off)
                if ann is None or ann.reloc.src_type != 5:
                    continue
                v = self._reloc_imm(ann.reloc)
                if v is not None:
                    imm.disp = (v + (imm.disp if ann.reloc.additive else 0)) & 0xFFFF
                break

        # --- Default: delegate to base lifter ---
        super().lift_instruction(inst, func_start)

    def _lift_fpu(self, inst: Instruction, m: str, orig: str):
        """Lift an FPU instruction to C double operations."""
        # The FPU mnemonic may include operands (from fpu_decode.py format_fpu)
        # Parse the mnemonic to extract operation and operands
        parts = m.split(' ', 1)
        op = parts[0]
        operand_str = parts[1] if len(parts) > 1 else ''

        # --- FPU Stack Operations ---
        if op == 'fld':
            if 'st(' in operand_str:
                # fld st(i) - push copy of st(i) onto stack
                i = self._parse_st(operand_str)
                self._emit(f'fpu_push(cpu); cpu->st[0] = cpu->st[{i+1}];', orig)
            elif 'dword' in operand_str or 'qword' in operand_str or 'tword' in operand_str:
                mem_expr = self._fpu_mem_read(inst, operand_str)
                self._emit(f'fpu_push(cpu); cpu->st[0] = {mem_expr};', orig)
            else:
                self._emit(f'/* FPU: {orig} */', orig)

        elif op == 'fst':
            if 'st(' in operand_str:
                i = self._parse_st(operand_str)
                self._emit(f'cpu->st[{i}] = cpu->st[0];', orig)
            elif operand_str:
                mem_expr = self._fpu_mem_write(inst, operand_str, 'cpu->st[0]')
                self._emit(mem_expr, orig)
            else:
                self._emit(f'/* FPU: {orig} */', orig)

        elif op == 'fstp':
            if 'st(' in operand_str:
                i = self._parse_st(operand_str)
                self._emit(f'cpu->st[{i}] = cpu->st[0]; fpu_pop(cpu);', orig)
            elif operand_str:
                mem_expr = self._fpu_mem_write(inst, operand_str, 'cpu->st[0]')
                self._emit(f'{mem_expr} fpu_pop(cpu);', orig)
            else:
                self._emit(f'/* FPU: {orig} */', orig)

        elif op == 'fild':
            mem_expr = self._fpu_mem_read_int(inst, operand_str)
            self._emit(f'fpu_push(cpu); cpu->st[0] = (double){mem_expr};', orig)

        elif op == 'fist':
            mem_expr = self._fpu_mem_write_int(inst, operand_str, '(int32_t)cpu->st[0]')
            self._emit(mem_expr, orig)

        elif op == 'fistp':
            mem_expr = self._fpu_mem_write_int(inst, operand_str, '(int32_t)cpu->st[0]')
            self._emit(f'{mem_expr} fpu_pop(cpu);', orig)

        # --- FPU Arithmetic ---
        elif op == 'fadd':
            self._lift_fpu_arith(inst, '+', operand_str, orig)
        elif op == 'faddp':
            self._lift_fpu_arith_pop('+', operand_str, orig)
        elif op == 'fsub':
            self._lift_fpu_arith(inst, '-', operand_str, orig)
        elif op == 'fsubp':
            self._lift_fpu_arith_pop('-', operand_str, orig)
        elif op == 'fsubr':
            self._lift_fpu_arith_r(inst, '-', operand_str, orig)
        elif op == 'fsubrp':
            self._lift_fpu_arith_r_pop('-', operand_str, orig)
        elif op == 'fmul':
            self._lift_fpu_arith(inst, '*', operand_str, orig)
        elif op == 'fmulp':
            self._lift_fpu_arith_pop('*', operand_str, orig)
        elif op == 'fdiv':
            self._lift_fpu_arith(inst, '/', operand_str, orig)
        elif op == 'fdivp':
            self._lift_fpu_arith_pop('/', operand_str, orig)
        elif op == 'fdivr':
            self._lift_fpu_arith_r(inst, '/', operand_str, orig)
        elif op == 'fdivrp':
            self._lift_fpu_arith_r_pop('/', operand_str, orig)

        # --- FPU Integer Arithmetic ---
        elif op == 'fiadd':
            mem = self._fpu_mem_read_int(inst, operand_str)
            self._emit(f'cpu->st[0] += (double){mem};', orig)
        elif op == 'fisub':
            mem = self._fpu_mem_read_int(inst, operand_str)
            self._emit(f'cpu->st[0] -= (double){mem};', orig)
        elif op == 'fisubr':
            mem = self._fpu_mem_read_int(inst, operand_str)
            self._emit(f'cpu->st[0] = (double){mem} - cpu->st[0];', orig)
        elif op == 'fimul':
            mem = self._fpu_mem_read_int(inst, operand_str)
            self._emit(f'cpu->st[0] *= (double){mem};', orig)
        elif op == 'fidiv':
            mem = self._fpu_mem_read_int(inst, operand_str)
            self._emit(f'cpu->st[0] /= (double){mem};', orig)
        elif op == 'fidivr':
            mem = self._fpu_mem_read_int(inst, operand_str)
            self._emit(f'cpu->st[0] = (double){mem} / cpu->st[0];', orig)

        # --- FPU Compare ---
        elif op == 'fcom':
            if 'st(0), st(' in operand_str:
                i = self._parse_st(operand_str.split('st(0), ')[1])
                self._emit(f'fpu_compare(cpu, cpu->st[0], cpu->st[{i}]);', orig)
            elif 'st(' in operand_str:
                i = self._parse_st(operand_str)
                self._emit(f'fpu_compare(cpu, cpu->st[0], cpu->st[{i}]);', orig)
            elif operand_str:
                mem = self._fpu_mem_read(inst, operand_str)
                self._emit(f'fpu_compare(cpu, cpu->st[0], {mem});', orig)
            else:
                self._emit(f'fpu_compare(cpu, cpu->st[0], cpu->st[1]);', orig)
        elif op == 'fcomp':
            if 'st(0), st(' in operand_str:
                i = self._parse_st(operand_str.split('st(0), ')[1])
                self._emit(f'fpu_compare(cpu, cpu->st[0], cpu->st[{i}]); fpu_pop(cpu);', orig)
            elif 'dword' in operand_str or 'qword' in operand_str:
                mem = self._fpu_mem_read(inst, operand_str)
                self._emit(f'fpu_compare(cpu, cpu->st[0], {mem}); fpu_pop(cpu);', orig)
            else:
                self._emit(f'fpu_compare(cpu, cpu->st[0], cpu->st[1]); fpu_pop(cpu);', orig)
        elif op == 'fcompp':
            self._emit(f'fpu_compare(cpu, cpu->st[0], cpu->st[1]); fpu_pop(cpu); fpu_pop(cpu);', orig)
        elif op == 'ftst':
            self._emit(f'fpu_compare(cpu, cpu->st[0], 0.0);', orig)
        elif op == 'fucom':
            if 'st(' in operand_str:
                i = self._parse_st(operand_str)
                self._emit(f'fpu_compare(cpu, cpu->st[0], cpu->st[{i}]);', orig)
            else:
                self._emit(f'fpu_compare(cpu, cpu->st[0], cpu->st[1]);', orig)
        elif op == 'fucomp':
            if 'st(' in operand_str:
                i = self._parse_st(operand_str)
                self._emit(f'fpu_compare(cpu, cpu->st[0], cpu->st[{i}]); fpu_pop(cpu);', orig)
            else:
                self._emit(f'fpu_compare(cpu, cpu->st[0], cpu->st[1]); fpu_pop(cpu);', orig)
        elif op == 'fucompp':
            self._emit(f'fpu_compare(cpu, cpu->st[0], cpu->st[1]); fpu_pop(cpu); fpu_pop(cpu);', orig)

        # --- FPU Constants ---
        elif op == 'fld1':
            self._emit(f'fpu_push(cpu); cpu->st[0] = 1.0;', orig)
        elif op == 'fldz':
            self._emit(f'fpu_push(cpu); cpu->st[0] = 0.0;', orig)
        elif op == 'fldpi':
            self._emit(f'fpu_push(cpu); cpu->st[0] = 3.14159265358979323846;', orig)
        elif op == 'fldl2e':
            self._emit(f'fpu_push(cpu); cpu->st[0] = 1.44269504088896340736;', orig)
        elif op == 'fldl2t':
            self._emit(f'fpu_push(cpu); cpu->st[0] = 3.32192809488736234787;', orig)
        elif op == 'fldlg2':
            self._emit(f'fpu_push(cpu); cpu->st[0] = 0.30102999566398119521;', orig)
        elif op == 'fldln2':
            self._emit(f'fpu_push(cpu); cpu->st[0] = 0.69314718055994530942;', orig)

        # --- FPU Transcendentals ---
        elif op == 'fsqrt':
            self._emit(f'cpu->st[0] = sqrt(cpu->st[0]);', orig)
        elif op == 'fabs':
            self._emit(f'cpu->st[0] = fabs(cpu->st[0]);', orig)
        elif op == 'fchs':
            self._emit(f'cpu->st[0] = -cpu->st[0];', orig)
        elif op == 'fsin':
            self._emit(f'cpu->st[0] = sin(cpu->st[0]);', orig)
        elif op == 'fcos':
            self._emit(f'cpu->st[0] = cos(cpu->st[0]);', orig)
        elif op == 'fpatan':
            self._emit(f'{{ double _y = cpu->st[1], _x = cpu->st[0]; '
                       f'fpu_pop(cpu); cpu->st[0] = atan2(_y, _x); }}', orig)
        elif op == 'fptan':
            self._emit(f'cpu->st[0] = tan(cpu->st[0]); fpu_push(cpu); cpu->st[0] = 1.0;', orig)
        elif op == 'frndint':
            self._emit(f'cpu->st[0] = rint(cpu->st[0]);', orig)
        elif op == 'fscale':
            self._emit(f'cpu->st[0] = ldexp(cpu->st[0], (int)cpu->st[1]);', orig)
        elif op == 'f2xm1':
            self._emit(f'cpu->st[0] = pow(2.0, cpu->st[0]) - 1.0;', orig)
        elif op == 'fyl2x':
            self._emit(f'{{ double _r = cpu->st[1] * log2(cpu->st[0]); '
                       f'fpu_pop(cpu); cpu->st[0] = _r; }}', orig)
        elif op == 'fyl2xp1':
            self._emit(f'{{ double _r = cpu->st[1] * log2(cpu->st[0] + 1.0); '
                       f'fpu_pop(cpu); cpu->st[0] = _r; }}', orig)

        # --- FPU Control ---
        elif op == 'fxch':
            if 'st(' in operand_str:
                i = self._parse_st(operand_str)
                self._emit(f'{{ double _t = cpu->st[0]; cpu->st[0] = cpu->st[{i}]; '
                           f'cpu->st[{i}] = _t; }}', orig)
            else:
                self._emit(f'{{ double _t = cpu->st[0]; cpu->st[0] = cpu->st[1]; '
                           f'cpu->st[1] = _t; }}', orig)
        elif op == 'ffree':
            self._emit(f'/* ffree {operand_str} */', orig)
        elif op == 'finit' or op == 'fninit':
            self._emit(f'fpu_init(cpu);', orig)
        elif op == 'fclex' or op == 'fnclex':
            self._emit(f'cpu->fpu_status &= 0x7F00;', orig)
        elif op == 'fldcw':
            self._emit(f'/* fldcw - load FPU control word */', orig)
        elif op == 'fstcw' or op == 'fnstcw':
            self._emit(f'/* fstcw - store FPU control word */', orig)
        elif op == 'fstsw':
            if 'ax' in operand_str:
                self._emit(f'cpu->ax = cpu->fpu_status;', orig)
            else:
                # `fstsw [bp-N]; mov ah,[bp-N+1]; sahf` is MSVC's float
                # compare. Dropping the store left the caller reading an
                # uninitialized stack slot, so every such compare branched
                # on whatever was on the stack.
                seg, off = self._fpu_mem_expr(inst, operand_str)
                self._emit(f'mem_write16(cpu, {seg}, {off}, cpu->fpu_status);', orig)
        elif op == 'fdecstp':
            self._emit(f'cpu->fpu_top = (cpu->fpu_top - 1) & 7;', orig)
        elif op == 'fincstp':
            self._emit(f'cpu->fpu_top = (cpu->fpu_top + 1) & 7;', orig)
        elif op == 'fnop':
            self._emit(f'/* fnop */', orig)

        # --- Catch-all ---
        else:
            self._emit(f'/* FPU TODO: {orig} */', orig)

    def _lift_fpu_arith(self, inst, op: str, operand_str: str, orig: str):
        """Lift FPU arithmetic: fadd/fsub/fmul/fdiv."""
        if 'st(0), st(' in operand_str:
            i = self._parse_st(operand_str.split('st(0), ')[1])
            self._emit(f'cpu->st[0] = cpu->st[0] {op} cpu->st[{i}];', orig)
        elif 'st(' in operand_str and '), st(0)' in operand_str:
            i = self._parse_st(operand_str)
            self._emit(f'cpu->st[{i}] = cpu->st[{i}] {op} cpu->st[0];', orig)
        elif operand_str:
            mem = self._fpu_mem_read(inst, operand_str)
            self._emit(f'cpu->st[0] = cpu->st[0] {op} {mem};', orig)
        else:
            self._emit(f'cpu->st[0] = cpu->st[0] {op} cpu->st[1];', orig)

    def _lift_fpu_arith_pop(self, op: str, operand_str: str, orig: str):
        """Lift FPU arithmetic with pop: faddp/fsubp/fmulp/fdivp."""
        if 'st(' in operand_str:
            i = self._parse_st(operand_str)
            self._emit(f'cpu->st[{i}] = cpu->st[{i}] {op} cpu->st[0]; fpu_pop(cpu);', orig)
        else:
            self._emit(f'cpu->st[1] = cpu->st[1] {op} cpu->st[0]; fpu_pop(cpu);', orig)

    def _lift_fpu_arith_r(self, inst, op: str, operand_str: str, orig: str):
        """Lift FPU reverse arithmetic: fsubr/fdivr."""
        if 'st(0), st(' in operand_str:
            i = self._parse_st(operand_str.split('st(0), ')[1])
            self._emit(f'cpu->st[0] = cpu->st[{i}] {op} cpu->st[0];', orig)
        elif operand_str:
            mem = self._fpu_mem_read(inst, operand_str)
            self._emit(f'cpu->st[0] = {mem} {op} cpu->st[0];', orig)
        else:
            self._emit(f'cpu->st[0] = cpu->st[1] {op} cpu->st[0];', orig)

    def _lift_fpu_arith_r_pop(self, op: str, operand_str: str, orig: str):
        """Lift FPU reverse arithmetic with pop."""
        if 'st(' in operand_str:
            i = self._parse_st(operand_str)
            self._emit(f'cpu->st[{i}] = cpu->st[0] {op} cpu->st[{i}]; fpu_pop(cpu);', orig)
        else:
            self._emit(f'cpu->st[1] = cpu->st[0] {op} cpu->st[1]; fpu_pop(cpu);', orig)

    def _parse_st(self, operand_str: str) -> int:
        """Extract register number from st(N) pattern, ignoring extra operands."""
        import re
        m = re.search(r'st\((\d+)\)', operand_str)
        return int(m.group(1)) if m else 0

    def _fpu_mem_expr(self, inst, operand_str: str) -> tuple:
        """Get (seg_expr, off_expr) for FPU memory operand.
        Uses inst.op1 if available (preserved from ModR/M decode), otherwise falls back."""
        if inst and inst.op1 and inst.op1.type in (OpType.MEM, OpType.MOFFS):
            seg, off = _mem_addr(inst.op1)
            return seg, off
        # Fallback: can't resolve, emit a comment
        return 'cpu->ds', f'0 /* TODO: {operand_str} */'

    def _fpu_mem_read(self, inst, operand_str: str) -> str:
        """Generate C expression to read FPU memory operand as double."""
        seg, off = self._fpu_mem_expr(inst, operand_str)
        if 'qword' in operand_str:
            return f'fpu_read_f64(cpu, {seg}, {off})'
        elif 'tword' in operand_str:
            return f'fpu_read_f64(cpu, {seg}, {off}) /* tword approx */'
        else:  # dword
            return f'fpu_read_f32(cpu, {seg}, {off})'

    def _fpu_mem_write(self, inst, operand_str: str, value: str) -> str:
        """Generate C statement to write FPU value to memory."""
        seg, off = self._fpu_mem_expr(inst, operand_str)
        if 'qword' in operand_str:
            return f'fpu_write_f64(cpu, {seg}, {off}, {value});'
        elif 'tword' in operand_str:
            return f'fpu_write_f64(cpu, {seg}, {off}, {value}); /* tword approx */'
        else:  # dword
            return f'fpu_write_f32(cpu, {seg}, {off}, {value});'

    def _fpu_mem_read_int(self, inst, operand_str: str) -> str:
        """Generate C expression to read FPU integer memory operand."""
        seg, off = self._fpu_mem_expr(inst, operand_str)
        if 'dword' in operand_str:
            return f'fpu_read_i32(cpu, {seg}, {off})'
        else:  # word
            return f'fpu_read_i16(cpu, {seg}, {off})'

    def _fpu_mem_write_int(self, inst, operand_str: str, value: str) -> str:
        """Generate C statement to write integer to FPU memory."""
        seg, off = self._fpu_mem_expr(inst, operand_str)
        if 'dword' in operand_str:
            return f'fpu_write_i32(cpu, {seg}, {off}, {value});'
        else:  # word
            return f'fpu_write_i16(cpu, {seg}, {off}, {value});'


def lift_segment(ne: NEHeader, seg_num: int, func_offset: int = -1, xmod=None):
    """Lift functions from a segment to C code. `xmod` (optional) maps a module
    name to {ordinal: (seg, off)} for cross-module call resolution (host->DLL)."""
    seg = next((s for s in ne.segments if s.index == seg_num), None)
    if not seg or not seg.is_code:
        print(f"Error: segment {seg_num} not found or not CODE")
        return

    instructions, functions, reloc_map = disassemble_segment(seg, ne)

    if not functions:
        print(f"/* No functions detected in segment {seg_num} */")
        return

    # Header
    print(f'/* Segment {seg_num} - {seg.actual_size} bytes, {len(functions)} functions */')
    print(f'/* Auto-generated by ne_lift.py - CATZ Recomp */')
    print()
    print('#include "segments.h"')
    print()

    # CS-relative memory operands must read from THIS segment, not runtime cpu->cs.
    import lift16
    lift16._CODE_SEG = seg.index

    # Lift each function
    lifter = NELifter(ne, seg)
    lifter.xmod = xmod or {}
    # Enable indirect call/jmp dispatch: `call di` / `jmp bx` etc. resolve to
    # recomp_dispatch(cs, reg) instead of being dropped as a no-op comment.
    # Without this the recomp silently skips register-indirect calls (found via
    # the uni harness: seg035_028B's `call di` -> seg035_0BD5 was never made).
    lifter.dispatch = True
    # Function entry offsets in this segment, for near-jmp-to-another-function.
    lifter.setjmp_fn = getattr(ne, 'setjmp_fn', None)
    lifter.seg_func_offsets = ({f.offset for f in functions}
                               | set(getattr(seg, 'alt_streams', {})))

    # An entry that is not an instruction boundary (the `cmp al, imm8`
    # skip idiom) carries its own decoding; lift it as its own function so
    # branches to it have somewhere to land. Its bytes overlap another
    # function's, which is exactly the point, so it is emitted alongside
    # rather than folded into the boundary list.
    alt = getattr(seg, 'alt_streams', {})
    target_funcs = functions
    if func_offset >= 0:
        target_funcs = [f for f in functions if f.offset == func_offset]
        if not target_funcs:
            print(f"/* Function at offset 0x{func_offset:04X} not found */")
            return

    # Map each function start offset to its label, for fall-through handling.
    off_to_label = {f.offset: f.label for f in functions}
    TERMINATORS = ('ret', 'retf', 'iret', 'jmp')
    NL = chr(10)

    # Functions the runtime replaces by hand (see OVERRIDES in
    # lift_combined.py): emitting the lifted body too would be a duplicate
    # symbol, and the lifted body is the thing being replaced.
    overrides = getattr(ne, 'overrides', set())
    target_funcs = [f for f in target_funcs
                    if (seg.index, f.offset) not in overrides]

    for func in target_funcs:
        # Get instructions for this function
        func_insts = [i for i in instructions
                      if func.offset <= (i.offset - seg.file_offset) < func.end]
        if not func_insts:
            continue

        code = lifter.lift_function(
            func.label, func_insts, seg.file_offset + func.offset, func.is_far)
        # lift16 appends its own fall-through as `recomp_dispatch(cpu, abs>>4,
        # abs&0xF)` using a FILE-absolute address — meaningless as a (selector,
        # offset) in the NE segmented model, so it dispatch-misses and returns
        # early, skipping the real fall-through code. We resolve fall-through
        # below in segment-aware terms, so drop lift16's bogus tail line.
        code = '\n'.join(
            ln for ln in code.split('\n')
            if not (ln.lstrip().startswith('recomp_dispatch(cpu,')
                    and '/* fallthrough 0x' in ln)
        )
        # Inject an entry-trace marker (compiles to nothing without -DELFISH_TRACE_FN)
        code = code.replace('{\n', '{\n    TRACE_FN("%s");\n' % func.label, 1)

        # Fall-through: if the last instruction is not a control-flow terminator,
        # execution flows into the next function. Emit that as a tail call so the
        # control flow isn't lost at the function boundary.
        last = func_insts[-1]
        if last.mnemonic not in TERMINATORS:
            nxt = off_to_label.get(func.end)
            if nxt and nxt != func.label:
                close = code.rfind('}')
                code = (code[:close]
                        + f'    {nxt}(cpu); return; /* fall-through */\n'
                        + code[close:])

        print(code)
        print()

    if func_offset < 0:
        for off, stream in sorted(alt.items()):
            label = f'seg{seg.index:03d}_{off:04X}'
            is_far = any(i.mnemonic in ('retf', 'iret') for i in stream)
            code = lifter.lift_function(label, stream,
                                        seg.file_offset + off, is_far)
            code = NL.join(
                ln for ln in code.split(NL)
                if not (ln.lstrip().startswith('recomp_dispatch(cpu,')
                        and '/* fallthrough 0x' in ln))
            code = code.replace('{' + NL,
                                '{' + NL + '    TRACE_FN("%s");' % label + NL, 1)
            print(code)
            print()


def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <ne_exe> --seg N [--func OFFSET]")
        sys.exit(1)

    filepath = sys.argv[1]
    ne = parse_ne(filepath)

    if '--seg' not in sys.argv:
        print("Error: --seg N required")
        sys.exit(1)

    idx = sys.argv.index('--seg')
    seg_num = int(sys.argv[idx + 1])

    func_offset = -1
    if '--func' in sys.argv:
        idx = sys.argv.index('--func')
        func_offset = int(sys.argv[idx + 1], 0)

    lift_segment(ne, seg_num, func_offset)


if __name__ == '__main__':
    main()
