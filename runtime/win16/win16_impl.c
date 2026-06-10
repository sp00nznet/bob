/*
 * win16_impl.c - Real implementations of the init-path Win16 shims.
 *
 * These override the generated stubs in win16_stubs.c (gen_win16_stubs.py skips
 * any name defined here). Calling convention: the lifter reaches each shim via
 *   push cs; push 0; NAME(cpu);
 * so on entry the stack is [sp]=retIP(0), [sp+2]=retCS, [sp+4]=last PASCAL arg
 * (lowest address). Each shim reads args with a16/a32 and cleans up like the
 * real __far __pascal routine's RETF would: ret(cpu, purge_bytes).
 *
 * Memory model: a Win16 HANDLE == our flat selector. GlobalAlloc backs at least
 * a full 64K segment per selector, so GlobalLock is just sel:0000 and
 * GlobalReAlloc never has to move a block (a selector addresses <=64K anyway).
 */
#include "runtime_api.h"
#include "ne_resources.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef CATZ_TRACE_WIN16
#define IMPL_LOG(...) fprintf(stderr, __VA_ARGS__)
#else
#define IMPL_LOG(...) ((void)0)
#endif

/* arg word `off` bytes above the first (lowest) arg slot at sp+4 */
static inline uint16_t a16(CPU *cpu, int off) {
    return mem_read16(cpu, cpu->ss, (uint16_t)(cpu->sp + 4 + off));
}
static inline uint32_t a32(CPU *cpu, int off) {
    return (uint32_t)a16(cpu, off) | ((uint32_t)a16(cpu, off + 2) << 16);
}
/* far retaddr (4) + PASCAL arg bytes */
static inline void ret(CPU *cpu, int purge) { cpu->sp += 4 + purge; }

static void read_asciiz(CPU *cpu, uint16_t seg, uint16_t off, char *out, int max) {
    int i = 0;
    for (; i < max - 1; i++) {
        uint8_t c = mem_read8(cpu, seg, (uint16_t)(off + i));
        if (!c) break;
        out[i] = (char)c;
    }
    out[i] = 0;
}

/* ===== KERNEL: memory (handle == selector) =====
 * A real free-list allocator over the flat heap, NOT a pure bump allocator: the
 * Borland RTL startup probes free memory by GlobalAlloc'ing 4K blocks until
 * failure, then GlobalFree's them all and allocates its real heap. Without
 * reclaiming freed blocks the probe permanently drains the heap and the next
 * allocation (in _setargv) fails. Per-selector size lets GlobalSize be exact
 * and GlobalReAlloc copy. Freed blocks are reused first-fit (uniform probe
 * blocks reuse perfectly); no splitting (fine for bring-up). */
static uint32_t g_sel_size[0x10000];   /* requested size per live selector */
static uint32_t g_sel_base[0x10000];   /* flat base per selector (for free)   */
#define MAX_FREE 16384
static uint32_t fl_base[MAX_FREE], fl_size[MAX_FREE];
static int      fl_n;

static uint16_t galloc(CPU *cpu, uint32_t bytes) {
    if (bytes == 0) bytes = 1;
    uint32_t need = (bytes + 0xF) & ~0xFu;
    /* first-fit over freed blocks */
    for (int i = 0; i < fl_n; i++) {
        if (fl_size[i] >= need) {
            uint32_t base = fl_base[i], bsz = fl_size[i];
            fl_base[i] = fl_base[--fl_n]; fl_size[i] = fl_size[fl_n];
            if (cpu->next_sel == 0) return 0;
            uint16_t s = cpu->next_sel++;
            cpu->sel_base[s] = base; g_sel_base[s] = base; g_sel_size[s] = bsz;
            return s;
        }
    }
    uint16_t s = cpu_alloc_selector(cpu, need);   /* bump fresh */
    if (s) { g_sel_base[s] = cpu->sel_base[s]; g_sel_size[s] = need; }
    return s;
}

static void gfree(CPU *cpu, uint16_t sel) {
    if (!sel || !g_sel_size[sel]) return;
    if (fl_n < MAX_FREE) { fl_base[fl_n] = g_sel_base[sel]; fl_size[fl_n] = g_sel_size[sel]; fl_n++; }
    IMPL_LOG("[win16] GlobalFree(%04X) freelist=%d\n", sel, fl_n);
    g_sel_size[sel] = 0;
}

void KERNEL_GLOBALALLOC(CPU *cpu) {
    uint16_t wFlags = a16(cpu, 4);
    uint32_t bytes  = a32(cpu, 0);
    uint16_t sel    = galloc(cpu, bytes);
    IMPL_LOG("[win16] GlobalAlloc(flags=%04X, %u) -> %04X\n", wFlags, bytes, sel);
    cpu->ax = sel;                          /* handle */
    if (sel) cpu->flags &= ~FLAG_CF; else cpu->flags |= FLAG_CF;
    ret(cpu, 6);
}

void KERNEL_GLOBALREALLOC(CPU *cpu) {
    uint16_t hMem  = a16(cpu, 6);
    uint32_t bytes = a32(cpu, 2);
    if (bytes == 0) bytes = 1;
    uint32_t old = (hMem ? g_sel_size[hMem] : 0);
    if (bytes <= old) {                     /* fits: keep handle */
        cpu->ax = hMem;
    } else {                                /* grow: new block, copy, free old */
        uint16_t nsel = galloc(cpu, bytes);
        if (nsel && hMem) {
            for (uint32_t i = 0; i < old; i++)
                mem_write8(cpu, nsel, (uint16_t)i, mem_read8(cpu, hMem, (uint16_t)i));
            gfree(cpu, hMem);
        }
        cpu->ax = nsel;
    }
    if (cpu->ax) cpu->flags &= ~FLAG_CF; else cpu->flags |= FLAG_CF;
    ret(cpu, 8);
}

void KERNEL_GLOBALFREE(CPU *cpu) {
    uint16_t hMem = a16(cpu, 0);
    gfree(cpu, hMem);
    cpu->ax = 0;                            /* NULL == success */
    ret(cpu, 2);
}

void KERNEL_GLOBALLOCK(CPU *cpu) {          /* -> far ptr DX:AX = handle:0000 */
    uint16_t hMem = a16(cpu, 0);
    cpu->dx = hMem; cpu->ax = 0;
    ret(cpu, 2);
}

void KERNEL_GLOBALUNLOCK(CPU *cpu) { cpu->ax = 0; ret(cpu, 2); }

void KERNEL_GLOBALSIZE(CPU *cpu) {          /* -> DWORD size in DX:AX */
    uint16_t hMem = a16(cpu, 0);
    uint32_t sz = (hMem ? g_sel_size[hMem] : 0);
    cpu->ax = (uint16_t)sz; cpu->dx = (uint16_t)(sz >> 16);
    ret(cpu, 2);
}

void KERNEL_GLOBALHANDLE(CPU *cpu) {        /* -> DX:AX = selector:handle (same) */
    uint16_t sel = a16(cpu, 0);
    cpu->dx = sel; cpu->ax = sel;
    ret(cpu, 2);
}

/* ===== KERNEL/USER: modules, string table & resources =====
 * Backed by the original NE binaries (ne_resources.c). The engine LoadLibrary's
 * CATZREZX.DLL (a pure resource container) and reads its config-key names from
 * CATZDLL's STRINGTABLE; without these it throws KatzError "CATZREZX.DLL did not
 * load" at startup. */

void KERNEL_LOADLIBRARY(CPU *cpu) {         /* LoadLibrary(lpLibFileName) */
    char name[128]; read_asciiz(cpu, a16(cpu, 2), a16(cpu, 0), name, sizeof name);
    uint16_t h = ne_loadlib(name);
    if (!h) h = 0x0040;                     /* benign handle for DLLs w/o resources (WIN87EM) */
    IMPL_LOG("[win16] LoadLibrary(%s) -> %04X\n", name, h);
    cpu->ax = h;                            /* >32 == success */
    ret(cpu, 4);
}

void KERNEL_FREELIBRARY(CPU *cpu) { cpu->ax = 1; ret(cpu, 2); }
void KERNEL_FREERESOURCE(CPU *cpu) { cpu->ax = 0; ret(cpu, 2); }  /* FALSE == still in use, ok */

void USER_LOADSTRING(CPU *cpu) {           /* LoadString(hInst,uID,lpBuf,nMax) */
    uint16_t hinst = a16(cpu, 8), id = a16(cpu, 6);
    uint16_t boff = a16(cpu, 2), bseg = a16(cpu, 4);
    int nmax = (int)a16(cpu, 0);
    char s[256];
    int n = ne_load_string(hinst, id, s, sizeof s);
    int k = 0;
    if (nmax > 0) {
        for (; k < n && k < nmax - 1; k++) mem_write8(cpu, bseg, (uint16_t)(boff + k), (uint8_t)s[k]);
        mem_write8(cpu, bseg, (uint16_t)(boff + k), 0);
    }
    IMPL_LOG("[win16] LoadString(%04X,%u) -> \"%s\" (%d)\n", hinst, id, n ? s : "", k);
    cpu->ax = (uint16_t)k;
    ret(cpu, 10);
}

/* Read a FindResource lpName/lpType arg: MAKEINTRESOURCE (seg==0) gives an int
 * id in `off`, otherwise it's a far asciiz string. */
static int res_arg(CPU *cpu, int off_idx, char *strbuf, int strmax) {
    uint16_t off = a16(cpu, off_idx), seg = a16(cpu, off_idx + 2);
    if (seg == 0) { strbuf[0] = 0; return (int)off; }   /* integer id */
    read_asciiz(cpu, seg, off, strbuf, strmax);
    return -1;                                          /* string in strbuf */
}

void KERNEL_FINDRESOURCE(CPU *cpu) {        /* FindResource(hInst,lpName,lpType) */
    uint16_t hinst = a16(cpu, 8);
    char tstr[64], nstr[64];
    int tint = res_arg(cpu, 0, tstr, sizeof tstr);   /* lpType @0/2 */
    int nint = res_arg(cpu, 4, nstr, sizeof nstr);   /* lpName @4/6 */
    uint16_t hrsrc = ne_find_resource(hinst, tint, tstr, nint, nstr);
    IMPL_LOG("[win16] FindResource(hInst=%04X type=%d/%s name=%d/%s) -> %04X\n",
             hinst, tint, tstr, nint, nstr, hrsrc);
    cpu->ax = hrsrc;
    ret(cpu, 10);
}

void KERNEL_LOADRESOURCE(CPU *cpu) {        /* LoadResource(hInst,hResInfo) -> HGLOBAL */
    uint16_t hrsrc = a16(cpu, 0);
    uint32_t len = 0;
    const uint8_t *bytes = ne_resource_bytes(hrsrc, &len);
    if (!bytes) { cpu->ax = 0; ret(cpu, 4); return; }
    uint16_t sel = galloc(cpu, len);
    if (sel) for (uint32_t i = 0; i < len; i++) mem_write8(cpu, sel, (uint16_t)i, bytes[i]);
    IMPL_LOG("[win16] LoadResource(hrsrc=%04X) -> sel=%04X (%u bytes)\n", hrsrc, sel, len);
    cpu->ax = sel;
    ret(cpu, 4);
}

void KERNEL_LOCKRESOURCE(CPU *cpu) {        /* LockResource(hResData) -> far ptr */
    uint16_t sel = a16(cpu, 0);
    cpu->dx = sel; cpu->ax = 0;             /* sel:0000 */
    ret(cpu, 2);
}

void KERNEL_SIZEOFRESOURCE(CPU *cpu) {      /* SizeofResource(hInst,hResInfo) */
    uint16_t hrsrc = a16(cpu, 0);
    uint32_t len = 0;
    ne_resource_bytes(hrsrc, &len);
    cpu->ax = (uint16_t)len;
    ret(cpu, 4);
}

/* ===== WING: WinG offscreen DIB blitting (the engine's render surface) =====
 * The engine WinGCreateDC()s a memory DC, WinGCreateBitmap()s an 8bpp DIB and
 * draws the pet into its pixel buffer, then WinGStretchBlt()s it to the window.
 * We give it a real guest-memory pixel buffer; presentation to the real window
 * is a no-op for now (gets the engine into its render loop). */
#define WING_DC_HANDLE 0x0DC0
static struct { uint16_t hbm, sel; int w, h, bpp; } g_wing[8];
static int g_nwing;

void WING_WINGCREATEDC(CPU *cpu) {          /* WinGCreateDC(void) -> HDC */
    cpu->ax = WING_DC_HANDLE;
    IMPL_LOG("[win16] WinGCreateDC -> %04X\n", cpu->ax);
    ret(cpu, 0);
}

void WING_WINGRECOMMENDDIBFORMAT(CPU *cpu) {/* WinGRecommendDIBFormat(BITMAPINFO*) */
    uint16_t off = a16(cpu, 0), seg = a16(cpu, 2);
    /* Fill a top-down 8bpp BI_RGB BITMAPINFOHEADER. biHeight=-1 signals top-down. */
    mem_write32(cpu, seg, off + 0,  40);    /* biSize */
    mem_write32(cpu, seg, off + 4,  1);     /* biWidth (probe) */
    mem_write32(cpu, seg, off + 8,  (uint32_t)-1); /* biHeight = -1 -> top-down */
    mem_write16(cpu, seg, off + 12, 1);     /* biPlanes */
    mem_write16(cpu, seg, off + 14, 8);     /* biBitCount */
    mem_write32(cpu, seg, off + 16, 0);     /* biCompression = BI_RGB */
    cpu->ax = 1;
    ret(cpu, 4);
}

void WING_WINGCREATEBITMAP(CPU *cpu) {      /* WinGCreateBitmap(HDC,BITMAPINFO*,void**) */
    uint16_t ppoff = a16(cpu, 0), ppseg = a16(cpu, 2);   /* ppBits (void FAR* FAR*) */
    uint16_t hoff  = a16(cpu, 4), hseg  = a16(cpu, 6);   /* pHeader */
    int w = (int)mem_read32(cpu, hseg, hoff + 4);
    int h = (int)mem_read32(cpu, hseg, hoff + 8);
    int bpp = mem_read16(cpu, hseg, hoff + 14); if (!bpp) bpp = 8;
    if (h < 0) h = -h;
    if (w <= 0) w = 1; if (h <= 0) h = 1;
    uint32_t stride = (((uint32_t)w * bpp + 31) / 32) * 4;
    uint32_t size = stride * (uint32_t)h;
    uint16_t sel = galloc(cpu, size ? size : 1);
    /* write the DIB pixel pointer (sel:0000) into *ppBits */
    if (ppseg || ppoff) { mem_write16(cpu, ppseg, ppoff, 0); mem_write16(cpu, ppseg, (uint16_t)(ppoff + 2), sel); }
    uint16_t hbm = (uint16_t)(0x0B00 + (++g_nwing));
    if (g_nwing <= (int)(sizeof g_wing / sizeof g_wing[0]))
        { g_wing[g_nwing-1].hbm = hbm; g_wing[g_nwing-1].sel = sel; g_wing[g_nwing-1].w = w; g_wing[g_nwing-1].h = h; g_wing[g_nwing-1].bpp = bpp; }
    IMPL_LOG("[win16] WinGCreateBitmap %dx%dx%d -> hbm=%04X bits=%04X:0000 (%u B)\n", w, h, bpp, hbm, sel, size);
    cpu->ax = hbm;
    ret(cpu, 10);
}

void WING_WINGSTRETCHBLT(CPU *cpu) {        /* WinGStretchBlt(...) -> BOOL (present; no-op) */
    cpu->ax = 1;
    ret(cpu, 20);
}

/* ===== KERNEL: local heap =====
 * LocalInit(uSegment, uStart, uEnd) registers a segment's local heap with the
 * kernel and returns nonzero on success. Borland's RTL near-malloc (used by
 * _setargv etc.) keys off this succeeding; a stub returning 0 made startup
 * report "Out of memory in _setargv". */
void KERNEL_LOCALINIT(CPU *cpu) {
    uint16_t uEnd = a16(cpu, 0), uStart = a16(cpu, 2), uSeg = a16(cpu, 4);
    IMPL_LOG("[win16] LocalInit(seg=%04X, start=%04X, end=%04X) ds=%04X\n",
             uSeg, uStart, uEnd, cpu->ds);
    cpu->ax = 1;                            /* TRUE - heap initialized */
    ret(cpu, 6);
}

/* ===== KERNEL: task startup =====
 * InitTask is called once at the very start of a Win16 EXE (Borland C0). It
 * returns the startup register block the runtime needs; a stub returning AX=0
 * makes the startup abort. */
void KERNEL_INITTASK(CPU *cpu) {
    uint16_t hinst = CATZ_AUTO_DATA_SEG;   /* fake hInstance == WAD DGROUP sel */
    /* Empty command line in the (fake) PSP at DGROUP:0080: length byte 0, CR. */
    mem_write8(cpu, hinst, 0x80, 0);
    mem_write8(cpu, hinst, 0x81, 0x0D);
    cpu->ax = 1;                 /* success (nonzero) */
    cpu->cx = 0xFFFE;            /* stack top */
    cpu->dx = 1;                 /* nCmdShow = SW_SHOWNORMAL */
    cpu->si = 0;                 /* hPrevInstance = none */
    cpu->di = hinst;             /* hInstance */
    cpu->es = hinst; cpu->bx = 0x0080;   /* ES:BX -> command line */
    cpu->bp = 0;
    ret(cpu, 0);
}

/* ===== KERNEL: module / version / task ===== */

void KERNEL_GETWINFLAGS(CPU *cpu) {         /* DX:AX: WF_PMODE|WF_CPU386|WF_ENHANCED */
    cpu->dx = 0; cpu->ax = 0x0029;
    ret(cpu, 0);
}

void KERNEL_GETVERSION(CPU *cpu) {          /* Windows 3.10 (AX), DOS 5.00 (DX) */
    cpu->ax = 0x0A03; cpu->dx = 0x0005;
    ret(cpu, 0);
}

void KERNEL_GETCURRENTTASK(CPU *cpu) {      /* nonzero fake HTASK */
    cpu->ax = 0x00FF;
    ret(cpu, 0);
}

void KERNEL_GETMODULEUSAGE(CPU *cpu) { cpu->ax = 1; ret(cpu, 2); }

void KERNEL_GETMODULEFILENAME(CPU *cpu) {
    uint16_t nSize = a16(cpu, 0), off = a16(cpu, 2), seg = a16(cpu, 4);
    const char *path = "C:\\CATZ\\CATZDLL.DLL";
    uint16_t i = 0;
    for (; path[i] && i + 1 < nSize; i++)
        mem_write8(cpu, seg, (uint16_t)(off + i), (uint8_t)path[i]);
    mem_write8(cpu, seg, (uint16_t)(off + i), 0);
    cpu->ax = i;
    ret(cpu, 8);
}

/* ===== USER: init-path window/message ===== */

void USER_MESSAGEBOX(CPU *cpu) {
    /* args (sp+4 up): uType@0, lpCaption off@2/seg@4, lpText off@6/seg@8, hWnd@10 */
    uint16_t toff = a16(cpu, 6),  tseg = a16(cpu, 8);    /* lpText */
    uint16_t coff = a16(cpu, 2),  cseg = a16(cpu, 4);    /* lpCaption */
    char text[256] = "", cap[128] = "";
    read_asciiz(cpu, tseg, toff, text, sizeof(text));
    read_asciiz(cpu, cseg, coff, cap, sizeof(cap));
    fprintf(stderr, "[MessageBox] \"%s\" | \"%s\"\n", cap, text);
    if (strstr(text, "memory") || strstr(text, "Memory") || strstr(text, "Abnormal") || strstr(text, "abnormal") || strstr(text, "Abort") || strstr(text, "abort")) {
        extern const char *g_fn_ring[]; extern unsigned g_fn_ring_pos;
        fprintf(stderr, "[abort] recent 120 fns:");
        for (int i = 120; i > 0; i--) { const char *r = g_fn_ring[(g_fn_ring_pos-(unsigned)i) & ((1u<<12)-1)]; if (r) fprintf(stderr, " %s", r+3); }
        fprintf(stderr, "\n");
    }
    cpu->ax = 1;                            /* IDOK */
    ret(cpu, 12);
}

void USER_ENUMTASKWINDOWS(CPU *cpu) {
    /* Return TRUE without invoking the callback: the engine is enumerating to
     * detect an existing instance window; finding none keeps it on the normal
     * first-run path instead of the "already running" branch. */
    cpu->ax = 1;
    ret(cpu, 10);
}

void USER_GETTICKCOUNT(CPU *cpu) {          /* DX:AX ms, monotonic so waits end */
    static uint32_t t = 0;
    t += 16;
    cpu->ax = (uint16_t)t; cpu->dx = (uint16_t)(t >> 16);
    ret(cpu, 0);
}

void USER_MESSAGEBEEP(CPU *cpu) { cpu->ax = 1; ret(cpu, 2); }

/* OutputDebugString(LPCSTR): surface the engine's own debug trace. */
void KERNEL_OUTPUTDEBUGSTRING(CPU *cpu) {
    uint16_t off = a16(cpu, 0), seg = a16(cpu, 2);
    char s[256]; read_asciiz(cpu, seg, off, s, sizeof(s));
    fprintf(stderr, "[OutputDebugString] %s", s);
    cpu->ax = 0; ret(cpu, 4);
}

/* InitApp(hInstance): create the app message queue. Return nonzero on success. */
void USER_INITAPP(CPU *cpu) { cpu->ax = 1; ret(cpu, 2); }

/* WaitEvent(hTask): yield to the event system. No-op (return). */
void KERNEL_WAITEVENT(CPU *cpu) { cpu->ax = 0; ret(cpu, 2); }

/* ===== USER/GDI: window setup (sane fake handles for now) =====
 * Enough to get the host past window creation; replaced with real Win32-backed
 * windows + a WndProc bridge when we wire actual rendering. Screen modeled as
 * 640x480x8 (the Catz target). */
#define FAKE_HWND   0x0CA7
#define FAKE_HDC    0x0DC1
#define FAKE_HANDLE 0x00F0   /* generic non-null GDI/icon/cursor/menu handle */

static void write_rect(CPU *cpu, uint16_t seg, uint16_t off, int l, int t, int r, int b) {
    mem_write16(cpu, seg, (uint16_t)(off + 0), (uint16_t)l);
    mem_write16(cpu, seg, (uint16_t)(off + 2), (uint16_t)t);
    mem_write16(cpu, seg, (uint16_t)(off + 4), (uint16_t)r);
    mem_write16(cpu, seg, (uint16_t)(off + 6), (uint16_t)b);
}

/* USER_REGISTERCLASS, USER_CREATEWINDOW: real Win32 in win32_backend.c */
void USER_GETSYSTEMMENU(CPU *cpu)  { cpu->ax = FAKE_HANDLE; ret(cpu, 4); }
void USER_APPENDMENU(CPU *cpu)     { cpu->ax = 1; ret(cpu, 10); }
void USER_LOADICON(CPU *cpu)       { cpu->ax = FAKE_HANDLE; ret(cpu, 6); }
void USER_GETSYSTEMMETRICS(CPU *cpu) {     /* index@0 */
    uint16_t i = a16(cpu, 0);
    int v;
    switch (i) {
        case 0:  v = 640; break;  /* SM_CXSCREEN */
        case 1:  v = 480; break;  /* SM_CYSCREEN */
        case 2:  v = 16;  break;  /* SM_CXVSCROLL */
        case 3:  v = 16;  break;  /* SM_CYHSCROLL */
        case 4:  v = 18;  break;  /* SM_CYCAPTION */
        case 5:  v = 1;   break;  /* SM_CXBORDER */
        case 6:  v = 1;   break;  /* SM_CYBORDER */
        case 7:  v = 2;   break;  /* SM_CXDLGFRAME */
        case 8:  v = 2;   break;  /* SM_CYDLGFRAME */
        case 15: v = 18;  break;  /* SM_CYMENU */
        case 16: v = 640; break;  /* SM_CXFULLSCREEN */
        case 17: v = 462; break;  /* SM_CYFULLSCREEN */
        case 32: v = 2;   break;  /* SM_CXFRAME */
        case 33: v = 2;   break;  /* SM_CYFRAME */
        default: v = 0;   break;
    }
    cpu->ax = (uint16_t)v; ret(cpu, 2);
}
void USER_SETMESSAGEQUEUE(CPU *cpu){ cpu->ax = 1; ret(cpu, 2); }
void KERNEL_GETWINDOWSDIRECTORY(CPU *cpu) {   /* LPSTR off@2/seg@4, UINT@0 */
    uint16_t nSize = a16(cpu, 0), off = a16(cpu, 2), seg = a16(cpu, 4);
    const char *p = "C:\\WINDOWS";
    uint16_t i = 0;
    for (; p[i] && i + 1 < nSize; i++) mem_write8(cpu, seg, (uint16_t)(off + i), (uint8_t)p[i]);
    mem_write8(cpu, seg, (uint16_t)(off + i), 0);
    cpu->ax = i; ret(cpu, 6);
}

void USER_GETWINDOWRECT(CPU *cpu) {        /* HWND@4, LPRECT off@0/seg@2 */
    write_rect(cpu, a16(cpu, 2), a16(cpu, 0), 0, 0, 640, 480);
    cpu->ax = 1; ret(cpu, 6);
}
void USER_GETCLIENTRECT(CPU *cpu) {
    write_rect(cpu, a16(cpu, 2), a16(cpu, 0), 0, 0, 640, 480);
    cpu->ax = 1; ret(cpu, 6);
}

void GDI_GETDEVICECAPS(CPU *cpu) {         /* HDC@2, index@0 */
    uint16_t idx = a16(cpu, 0);
    int v = 0;
    switch (idx) {
        case 8:  v = 640; break;   /* HORZRES   */
        case 10: v = 480; break;   /* VERTRES   */
        case 12: v = 8;   break;   /* BITSPIXEL */
        case 14: v = 1;   break;   /* PLANES    */
        case 24: v = 256; break;   /* NUMCOLORS */
        case 104:v = 256; break;   /* SIZEPALETTE */
        case 38: v = 0x0100; break;/* RASTERCAPS: RC_PALETTE */
        default: v = 0;   break;
    }
    cpu->ax = (uint16_t)v; ret(cpu, 4);
}
void GDI_CREATEIC(CPU *cpu)         { cpu->ax = FAKE_HDC; ret(cpu, 16); }
void GDI_GETSTOCKOBJECT(CPU *cpu)   { cpu->ax = FAKE_HANDLE; ret(cpu, 2); }

void CTL3DV2_CTL3DREGISTER(CPU *cpu)       { cpu->ax = 1; ret(cpu, 2); }
void CTL3DV2_CTL3DAUTOSUBCLASS(CPU *cpu)   { cpu->ax = 1; ret(cpu, 2); }

/* ===== INT 21h (DOS services occasionally used by the Borland startup) ===== */

/* ===== read-only DOS file I/O backed by the extracted game data tree =====
 * The engine opens data files by absolute guest path (e.g.
 * "C:\CATZ\ptzfiles\cat\resource\catsnd.txt"). We anchor on the "ptzfiles"
 * component and remap it under CATZ_DATA_DIR on the host. */
#ifndef CATZ_DATA_DIR
#define CATZ_DATA_DIR "game"
#endif
static FILE *g_dosfiles[64];          /* DOS handle h (>=5) -> host FILE* (slot h-5) */

static int dos_map_path(CPU *cpu, char *host, int hostsz) {
    char g[192]; read_asciiz(cpu, cpu->ds, cpu->dx, g, sizeof g);
    if (!g[0]) return 0;
    char low[192]; int i = 0;
    for (; g[i]; i++) low[i] = (g[i] >= 'A' && g[i] <= 'Z') ? (char)(g[i] + 32) : g[i];
    low[i] = 0;
    char *p = strstr(low, "ptzfiles");
    if (!p) return 0;                  /* only the game data tree is served */
    snprintf(host, hostsz, "%s/%s", CATZ_DATA_DIR, g + (p - low));
    for (char *q = host; *q; q++) if (*q == '\\') *q = '/';
    return 1;
}

void dos_int21(CPU *cpu) {
    switch (cpu->ah) {
    case 0x4C:                              /* terminate process */
        printf("[INT21/4C] program exit, code=%u\n", cpu->al);
        fflush(stdout);
        exit(cpu->al);
    case 0x30:                              /* DOS version -> 5.00 */
        cpu->al = 5; cpu->ah = 0;
        cpu->flags &= ~FLAG_CF;
        break;
    case 0x3D: {                           /* open existing file */
        char host[256];
        FILE *f = dos_map_path(cpu, host, sizeof host) ? fopen(host, "rb") : NULL;
        int slot = -1;
        if (f) for (int i = 0; i < (int)(sizeof g_dosfiles / sizeof g_dosfiles[0]); i++)
            if (!g_dosfiles[i]) { slot = i; break; }
        if (f && slot >= 0) {
            g_dosfiles[slot] = f;
            cpu->ax = (uint16_t)(slot + 5);    /* handle (0-4 reserved) */
            cpu->flags &= ~FLAG_CF;
            IMPL_LOG("[INT21] open -> handle %u (%s)\n", cpu->ax, host);
        } else {
            if (f) fclose(f);
            cpu->ax = 0x02; cpu->flags |= FLAG_CF;
            IMPL_LOG("[INT21] open -> not found\n");
        }
        break;
    }
    case 0x3F: {                           /* read: bx=handle cx=count buf=ds:dx */
        int slot = (int)cpu->bx - 5;
        uint16_t cnt = cpu->cx, got = 0;
        if (slot >= 0 && slot < (int)(sizeof g_dosfiles/sizeof g_dosfiles[0]) && g_dosfiles[slot]) {
            for (; got < cnt; got++) {
                int c = fgetc(g_dosfiles[slot]);
                if (c < 0) break;
                mem_write8(cpu, cpu->ds, (uint16_t)(cpu->dx + got), (uint8_t)c);
            }
            cpu->ax = got; cpu->flags &= ~FLAG_CF;
        } else { cpu->ax = 0; cpu->flags |= FLAG_CF; }
        break;
    }
    case 0x42: {                           /* lseek: bx=handle al=whence cx:dx=off -> dx:ax pos */
        int slot = (int)cpu->bx - 5;
        if (slot >= 0 && slot < (int)(sizeof g_dosfiles/sizeof g_dosfiles[0]) && g_dosfiles[slot]) {
            long off = (long)(((uint32_t)cpu->cx << 16) | cpu->dx);
            int whence = (cpu->al == 1) ? SEEK_CUR : (cpu->al == 2) ? SEEK_END : SEEK_SET;
            fseek(g_dosfiles[slot], off, whence);
            long pos = ftell(g_dosfiles[slot]);
            cpu->ax = (uint16_t)pos; cpu->dx = (uint16_t)(pos >> 16);
            cpu->flags &= ~FLAG_CF;
        } else { cpu->flags |= FLAG_CF; }
        break;
    }
    case 0x3E: {                           /* close: bx=handle */
        int slot = (int)cpu->bx - 5;
        if (slot >= 0 && slot < (int)(sizeof g_dosfiles/sizeof g_dosfiles[0]) && g_dosfiles[slot]) {
            fclose(g_dosfiles[slot]); g_dosfiles[slot] = NULL;
        }
        cpu->flags &= ~FLAG_CF;
        break;
    }
    case 0x43: {                           /* get attributes = existence check */
        char host[256];
        FILE *f = dos_map_path(cpu, host, sizeof host) ? fopen(host, "rb") : NULL;
        if (f) { fclose(f); cpu->cx = 0; cpu->flags &= ~FLAG_CF; }
        else   { cpu->ax = 0x02; cpu->flags |= FLAG_CF; }
        break;
    }
    case 0x44:                             /* ioctl get-device-info -> regular disk file */
        cpu->dx = 0; cpu->ax = 0; cpu->flags &= ~FLAG_CF;
        break;
    case 0x3C:                             /* create (read-only env) */
    case 0x40:                             /* write (read-only env) */
        cpu->ax = 0x05; cpu->flags |= FLAG_CF;
        break;
    default:
        IMPL_LOG("[INT21] ah=%02X (ignored)\n", cpu->ah);
        cpu->flags &= ~FLAG_CF;
        break;
    }
    /* `int` is not a far call - no stack frame to clean. */
}
