"""
win16.py - Win16 import resolver for the CATZ recomp.

Unlike El-Fish (a single TSXLIB DOS extender), CATZDLL.DLL is a real Windows
3.1 application that imports from EIGHT modules: KERNEL, USER, GDI, SOSLIB03,
WING, MMSYSTEM, TOOLHELP, WIN87EM. NE import relocations carry a `module_idx`
(1-based into ne.module_names) plus an ordinal, so resolution is module-aware.

Strategy: authoritative names come from IDA (which ships Win16 ordinal->API
maps) and are written to analysis/win16_imports.json by tools/ida_export.py.
This module loads that map when present, falls back to a small built-in seed of
high-confidence ordinals, and finally to a `MODULE_OrdN` stub name so the
recomp always links. Each resolved import becomes a C shim `void NAME(CPU*)`.
"""

import os
import json
from dataclasses import dataclass

_ANALYSIS = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'analysis'))
_JSON = os.path.join(_ANALYSIS, 'win16_imports.json')


@dataclass
class Win16Import:
    module: str         # KERNEL, USER, GDI, SOSLIB03, WING, MMSYSTEM, TOOLHELP, WIN87EM
    ordinal: int        # export ordinal in that module
    name: str           # C shim name, e.g. 'KERNEL_GlobalAlloc'
    api: str            # bare API name, e.g. 'GlobalAlloc' (or 'Ord15' if unknown)
    category: str       # 'mem','file','gdi','user','sound','blit','fpu','sys','unknown'
    known: bool = False # True if resolved from IDA map or built-in seed


# Modules whose imports are floating-point emulation trampolines. CATZ uses real
# x87 instructions in the code stream (only ~6 WIN87EM refs), so unlike El-Fish
# there is no inline FPU-trampoline skipping to do; WIN87EM calls are real calls.
_FPU_MODULES = {'WIN87EM'}

_CATEGORY_BY_MODULE = {
    'KERNEL': 'sys', 'USER': 'user', 'GDI': 'gdi', 'SOSLIB03': 'sound',
    'WING': 'blit', 'MMSYSTEM': 'sound', 'TOOLHELP': 'sys', 'WIN87EM': 'fpu',
}

# High-confidence built-in seed of Win16 system ordinals (Windows 3.1).
# Used only as a fallback before the IDA-derived map is available. Names that
# matter most for bring-up (memory, module, file, basic GDI/USER) are covered;
# everything else resolves to MODULE_OrdN until IDA fills it in.
_SEED = {
    'KERNEL': {
        5: 'LocalAlloc', 6: 'LocalLock', 7: 'LocalFree', 8: 'LocalUnlock',
        15: 'GlobalAlloc', 16: 'GlobalFree', 17: 'GlobalReAlloc', 18: 'GlobalLock',
        19: 'GlobalUnlock', 20: 'GlobalSize', 23: 'LockSegment', 24: 'UnlockSegment',
        30: 'WaitEvent', 47: 'GetModuleHandle', 49: 'GetModuleFileName',
        50: 'GetProcAddress', 51: 'MakeProcInstance', 52: 'FreeProcInstance',
        74: 'OpenFile', 81: '_lclose', 82: '_lread', 83: '_lcreat', 84: '_llseek',
        85: '_lopen', 86: '_lwrite', 88: 'lstrcpy', 89: 'lstrcat', 90: 'lstrlen',
        91: 'InitTask', 95: 'LoadLibrary', 96: 'FreeLibrary', 97: 'GetTempDrive',
        127: 'GetPrivateProfileInt', 128: 'GetPrivateProfileString',
        129: 'WritePrivateProfileString', 130: 'GetProfileInt', 131: 'GetProfileString',
    },
    'GDI': {
        27: 'CreateCompatibleDC', 31: 'SetPixel', 34: 'BitBlt', 35: 'StretchBlt',
        45: 'SelectObject', 53: 'CreateBitmap', 54: 'CreateBitmapIndirect',
        62: 'CreateCompatibleBitmap', 68: 'DeleteDC', 69: 'DeleteObject',
        80: 'GetDeviceCaps', 65: 'RealizePalette', 66: 'GetPaletteEntries',
        360: 'CreatePalette', 361: 'GetPaletteEntries', 363: 'SetPaletteEntries',
        370: 'CreateDIBitmap', 371: 'SetDIBits', 372: 'GetDIBits',
        439: 'SetDIBitsToDevice', 489: 'StretchDIBits',
    },
    'USER': {
        1: 'MessageBox', 10: 'SetTimer', 12: 'KillTimer', 39: 'BeginPaint',
        40: 'EndPaint', 41: 'CreateWindow', 42: 'ShowWindow', 57: 'RegisterClass',
        66: 'GetDC', 68: 'ReleaseDC', 107: 'DefWindowProc', 108: 'GetMessage',
        110: 'PostMessage', 111: 'SendMessage', 113: 'TranslateMessage',
        114: 'DispatchMessage', 124: 'UpdateWindow', 125: 'InvalidateRect',
        173: 'LoadCursor', 174: 'LoadIcon', 420: 'wsprintf',
    },
}

# Win16 PASCAL stack-purge bytes per call (callee pops args). WORD/UINT/HANDLE/
# BOOL/int = 2; DWORD/LONG/COLORREF/far pointer = 4. Each shim must do
# `cpu->sp += 4 (far retaddr) + purge`, or `retf` boundaries corrupt. Keyed by
# (MODULE, API). Functions not listed default to 0 with a runtime warning.
PURGE = {
    # ---- KERNEL ----
    ('KERNEL', 'GLOBALALLOC'): 6, ('KERNEL', 'GLOBALREALLOC'): 8,
    ('KERNEL', 'GLOBALFREE'): 2, ('KERNEL', 'GLOBALLOCK'): 2,
    ('KERNEL', 'GLOBALUNLOCK'): 2, ('KERNEL', 'GLOBALSIZE'): 2,
    ('KERNEL', 'GLOBALHANDLE'): 2, ('KERNEL', 'GLOBALFLAGS'): 2,
    ('KERNEL', 'LOCALINIT'): 6, ('KERNEL', 'GETWINFLAGS'): 0,
    ('KERNEL', 'INITTASK'): 0, ('KERNEL', 'WAITEVENT'): 2, ('KERNEL', 'INITAPP'): 2,
    ('KERNEL', 'GETVERSION'): 0, ('KERNEL', 'GETCURRENTTASK'): 0,
    ('KERNEL', 'GETMODULEUSAGE'): 2, ('KERNEL', 'GETMODULEFILENAME'): 8,
    ('KERNEL', 'GETMODULEHANDLE'): 4, ('KERNEL', 'FINDRESOURCE'): 10,
    ('KERNEL', 'LOADRESOURCE'): 4, ('KERNEL', 'LOCKRESOURCE'): 2,
    ('KERNEL', 'FREERESOURCE'): 2, ('KERNEL', 'SIZEOFRESOURCE'): 4,
    ('KERNEL', 'OPENFILE'): 10, ('KERNEL', '_LCLOSE'): 2, ('KERNEL', '_LREAD'): 8,
    ('KERNEL', '_LLSEEK'): 8, ('KERNEL', '_LOPEN'): 6, ('KERNEL', '_LWRITE'): 8,
    ('KERNEL', '_HREAD'): 10, ('KERNEL', '_LCREAT'): 6,
    ('KERNEL', 'LOADLIBRARY'): 4, ('KERNEL', 'FREELIBRARY'): 2,
    ('KERNEL', 'OUTPUTDEBUGSTRING'): 4, ('KERNEL', 'GETPRIVATEPROFILEINT'): 14,
    ('KERNEL', 'GETPRIVATEPROFILESTRING'): 22,
    ('KERNEL', 'WRITEPRIVATEPROFILESTRING'): 16, ('KERNEL', 'GETPROCADDRESS'): 6,
    ('KERNEL', 'LSTRLEN'): 4, ('KERNEL', 'LSTRCPY'): 8, ('KERNEL', 'LSTRCAT'): 8,
    # ---- USER ----
    ('USER', 'INITAPP'): 2, ('USER', 'SETMESSAGEQUEUE'): 2,
    ('USER', 'REGISTERCLASS'): 4, ('USER', 'CREATEWINDOW'): 30,
    ('USER', 'GETSYSTEMMENU'): 4, ('USER', 'APPENDMENU'): 10, ('USER', 'LOADICON'): 6,
    ('USER', 'DEFWINDOWPROC'): 10, ('USER', 'INVALIDATERECT'): 8, ('USER', 'INVALIDATERGN'): 6,
    ('USER', 'BEGINPAINT'): 6, ('USER', 'ENDPAINT'): 6, ('USER', 'GETUPDATERECT'): 8,
    ('USER', 'FILLRECT'): 8, ('USER', 'GETCLIENTRECT'): 6, ('USER', 'VALIDATERECT'): 6,
    ('USER', 'CHECKMENUITEM'): 6, ('USER', 'ENABLEMENUITEM'): 6, ('USER', 'GETMENU'): 2,
    ('USER', 'GETSUBMENU'): 4, ('USER', 'GETMENUITEMCOUNT'): 2, ('USER', 'GETMENUITEMID'): 4,
    ('USER', 'GETMENUSTATE'): 6, ('USER', 'MODIFYMENU'): 12, ('USER', 'DELETEMENU'): 6,
    ('USER', 'SETMENU'): 4, ('USER', 'DRAWMENUBAR'): 2, ('USER', 'CREATEMENU'): 0,
    ('USER', 'CREATEPOPUPMENU'): 0, ('USER', 'TRACKPOPUPMENU'): 14, ('USER', 'HILITEMENUITEM'): 8,
    ('USER', 'GETSYSTEMMETRICS'): 2, ('KERNEL', 'GETWINDOWSDIRECTORY'): 6,
    ('CTL3DV2', 'CTL3DREGISTER'): 2, ('CTL3DV2', 'CTL3DAUTOSUBCLASS'): 2,
    ('USER', 'MESSAGEBOX'): 12, ('USER', 'MESSAGEBEEP'): 2, ('USER', 'SETTIMER'): 10,
    ('USER', 'KILLTIMER'): 4, ('USER', 'GETTICKCOUNT'): 0, ('USER', 'PEEKMESSAGE'): 12,
    ('USER', 'SENDMESSAGE'): 10, ('USER', 'TRANSLATEMESSAGE'): 4,
    ('USER', 'DISPATCHMESSAGE'): 4, ('USER', 'POSTQUITMESSAGE'): 2,
    ('USER', 'SETCLASSWORD'): 6, ('USER', 'GETWINDOWLONG'): 4,
    ('USER', 'SETWINDOWLONG'): 8, ('USER', 'CLIPCURSOR'): 4, ('USER', 'LOADCURSOR'): 6,
    ('USER', 'LOADSTRING'): 10, ('USER', 'GETSYSCOLOR'): 2, ('USER', 'RELEASECAPTURE'): 0,
    ('USER', 'ENUMTASKWINDOWS'): 10, ('USER', 'ENUMWINDOWS'): 8, ('USER', 'GETFOCUS'): 0,
    ('USER', 'CREATEDIALOGPARAM'): 16, ('USER', 'GETASYNCKEYSTATE'): 2,
    ('USER', 'SELECTPALETTE'): 6, ('USER', 'REALIZEPALETTE'): 2,
    ('USER', 'GETDESKTOPWINDOW'): 0, ('USER', 'REDRAWWINDOW'): 10,
    ('USER', 'GETWINDOWRECT'): 6, ('USER', 'GETCLIENTRECT'): 6,
    ('USER', 'SETWINDOWTEXT'): 6, ('USER', 'SHOWWINDOW'): 4, ('USER', 'DESTROYWINDOW'): 2,
    ('USER', 'MOVEWINDOW'): 12, ('USER', 'SETSCROLLPOS'): 8, ('USER', 'SETSCROLLRANGE'): 10,
    ('USER', 'GETDC'): 2, ('USER', 'RELEASEDC'): 4, ('USER', 'SETCURSOR'): 2,
    ('USER', 'SETCURSORPOS'): 4, ('USER', 'OFFSETRECT'): 8, ('USER', 'FRAMERECT'): 8,
    ('USER', 'DRAWTEXT'): 14, ('USER', 'DIALOGBOX'): 12, ('USER', 'ENDDIALOG'): 4,
    ('USER', 'CREATEDIALOG'): 12, ('USER', 'GETDLGITEM'): 4, ('USER', 'SETDLGITEMTEXT'): 8,
    ('USER', 'GETDLGITEMTEXT'): 10, ('USER', 'SETDLGITEMINT'): 8, ('USER', 'GETDLGITEMINT'): 10,
    ('USER', 'CLIENTTOSCREEN'): 6, ('USER', 'GETWINDOWRECT'): 6,
    # ---- GDI ----
    ('GDI', 'SETBKCOLOR'): 6, ('GDI', 'SETBKMODE'): 4, ('GDI', 'SETTEXTCOLOR'): 6,
    ('GDI', 'CREATEIC'): 16, ('GDI', 'LINETO'): 6, ('GDI', 'MOVETO'): 6,
    ('GDI', 'ELLIPSE'): 10, ('GDI', 'RECTANGLE'): 10, ('GDI', 'PATBLT'): 14,
    ('GDI', 'BITBLT'): 20, ('GDI', 'STRETCHBLT'): 24, ('GDI', 'POLYGON'): 8,
    ('GDI', 'CREATEPALETTE'): 4, ('GDI', 'GETSYSTEMPALETTEUSE'): 2,
    ('GDI', 'GETSYSTEMPALETTEENTRIES'): 10, ('GDI', 'GETPALETTEENTRIES'): 10,
    ('GDI', 'STRETCHDIBITS'): 32, ('GDI', 'GETDIBITS'): 18, ('GDI', 'CREATEDIBITMAP'): 20,
    ('GDI', 'SETDIBITSTODEVICE'): 28, ('GDI', 'SELECTOBJECT'): 4,
    ('GDI', 'SETVIEWPORTORGEX'): 10, ('GDI', 'CREATECOMPATIBLEBITMAP'): 6,
    ('GDI', 'CREATECOMPATIBLEDC'): 2, ('GDI', 'CREATEFONTINDIRECT'): 4,
    ('GDI', 'CREATEPEN'): 8, ('GDI', 'CREATESOLIDBRUSH'): 4, ('GDI', 'DELETEDC'): 2,
    ('GDI', 'DELETEOBJECT'): 2, ('GDI', 'GETDEVICECAPS'): 4, ('GDI', 'GETOBJECT'): 8,
    ('GDI', 'GETSTOCKOBJECT'): 2, ('GDI', 'GETTEXTEXTENT'): 8,
    # ---- MMSYSTEM ----
    ('MMSYSTEM', 'SNDPLAYSOUND'): 6, ('MMSYSTEM', 'TIMEGETDEVCAPS'): 6,
    ('MMSYSTEM', 'TIMEGETTIME'): 0,
    # ---- TOOLHELP ----
    ('TOOLHELP', 'GLOBALENTRYHANDLE'): 6, ('TOOLHELP', 'TIMERCOUNT'): 4,
    # ---- WIN87EM ---- (FP emulator hook; not a PASCAL call, no arg purge)
    ('WIN87EM', '__FPMATH'): 0,
}


def get_purge(module: str, api: str):
    """Return stack-purge bytes for a (module, api) Win16 call, or None if
    unknown (SOS/WinG and rare APIs - filled in as they are reached)."""
    return PURGE.get(((module or '').upper(), (api or '').upper()))


_loaded_map = None


def _load_map():
    """Load the IDA-derived import map (module -> {ordinal: api_name}), cached."""
    global _loaded_map
    if _loaded_map is not None:
        return _loaded_map
    _loaded_map = {}
    if os.path.exists(_JSON):
        try:
            with open(_JSON, encoding='utf-8') as f:
                raw = json.load(f)
            for mod, ords in raw.items():
                _loaded_map[mod.upper()] = {int(k): v for k, v in ords.items()}
        except Exception:
            _loaded_map = {}
    return _loaded_map


def _sanitize(api: str) -> str:
    out = []
    for ch in api:
        out.append(ch if (ch.isalnum() or ch == '_') else '_')
    return ''.join(out)


def get_import(module: str, ordinal: int) -> Win16Import:
    """Resolve a (module, ordinal) import to a Win16Import shim descriptor."""
    mod = (module or 'UNK').upper()
    cat = _CATEGORY_BY_MODULE.get(mod, 'unknown')

    api = None
    known = False
    idamap = _load_map().get(mod)
    if idamap and ordinal in idamap:
        api = idamap[ordinal]
        known = True
    elif mod in _SEED and ordinal in _SEED[mod]:
        api = _SEED[mod][ordinal]
        known = True

    if api:
        # Uppercase so names are consistent whether resolved from IDA (which
        # yields UPPERCASE) or the built-in seed (mixed case) -> shim impls and
        # call sites always agree.
        name = f'{mod}_{_sanitize(api).upper()}'
    else:
        api = f'Ord{ordinal}'
        name = f'{mod}_Ord{ordinal}'

    return Win16Import(module=mod, ordinal=ordinal, name=name, api=api,
                       category=cat, known=known)


def is_fpu_module(module: str) -> bool:
    return (module or '').upper() in _FPU_MODULES


def module_name(ne, module_idx: int) -> str:
    """Map a 1-based NE module_idx to its imported module name."""
    if 1 <= module_idx <= len(ne.module_names):
        return ne.module_names[module_idx - 1]
    return f'MOD{module_idx}'
