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
#include "ne_exports.h"
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

int ne_get_proc(uint16_t hinst, const char *name, uint16_t ordinal,
                uint16_t *seg, uint16_t *off) {
    for (int i = 0; i < g_ne_nexports; i++) {
        const NEExport *e = &g_ne_exports[i];
        if (e->hinst != hinst) continue;
        if (name ? (e->name[0] && _stricmp(e->name, name) == 0)
                 : (e->ordinal == ordinal)) {
            *seg = e->seg; *off = e->off;
            return 1;
        }
    }
    return 0;
}

/* FARPROC GetProcAddress(HINSTANCE, LPCSTR) -> DX:AX far pointer.
 * A HIWORD of 0 means the low word is an ordinal, not a string pointer.
 * Returning 0 is how a Win16 app decides its component is missing -- Bob's
 * VBX loader put up "unable to find a required file" on exactly that. */
void KERNEL_GETPROCADDRESS(CPU *cpu) {
    uint16_t hmod = a16(cpu, 4);
    uint16_t poff = a16(cpu, 0), pseg = a16(cpu, 2);
    uint16_t seg = 0, off = 0;
    char nm[128];
    int ok;
    if (pseg == 0) {
        ok = ne_get_proc(hmod, NULL, poff, &seg, &off);
        IMPL_LOG("[win16] GetProcAddress(%04X, #%u) -> %u:%04X\n", hmod, poff, seg, off);
    } else {
        read_asciiz(cpu, pseg, poff, nm, sizeof nm);
        ok = ne_get_proc(hmod, nm, 0, &seg, &off);
        IMPL_LOG("[win16] GetProcAddress(%04X, '%s') -> %u:%04X\n", hmod, nm, seg, off);
    }
    if (!ok) { seg = 0; off = 0; }
    cpu->dx = seg; cpu->ax = off;
    ret(cpu, 6);
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
/* ----- Local heap (LocalAlloc family) -----
 * Bob GlobalAlloc's a segment, LocalInit's a heap region in it, then LocalAlloc's
 * from it (the OLE/Jet layer leans on this; the auto-stub returned 0 = failure).
 * Model a per-segment bump heap over the LocalInit'd [start,end). Handles are
 * near offsets (LMEM_FIXED-style) so LocalLock returns the offset unchanged.
 * Key by selector with the RPL/TI bits masked off. */
#define LH_MAX 64
static struct { uint16_t seg, next, end; } g_lheap[LH_MAX];
static int g_lheap_n = 0;
static int lheap_idx(uint16_t seg, int create) {
    seg &= ~7u;
    for (int i = 0; i < g_lheap_n; i++) if (g_lheap[i].seg == seg) return i;
    if (create && g_lheap_n < LH_MAX) {
        int i = g_lheap_n++; g_lheap[i].seg = seg;
        g_lheap[i].next = 0x10; g_lheap[i].end = 0xFE00; return i;
    }
    return -1;
}

void KERNEL_LOCALINIT(CPU *cpu) {
    uint16_t uEnd = a16(cpu, 0), uStart = a16(cpu, 2), uSeg = a16(cpu, 4);
    uint16_t seg = uSeg ? uSeg : cpu->ds;
    int i = lheap_idx(seg, 1);
    if (i >= 0) {
        g_lheap[i].next = uStart ? uStart : 0x10;
        g_lheap[i].end  = uEnd   ? uEnd   : 0xFE00;
    }
    IMPL_LOG("[win16] LocalInit(seg=%04X, start=%04X, end=%04X) ds=%04X\n",
             uSeg, uStart, uEnd, cpu->ds);
    cpu->ax = 1;                            /* TRUE - heap initialized */
    ret(cpu, 6);
}

/* HLOCAL LocalAlloc(UINT uFlags, UINT uBytes): bump-allocate from cpu->ds's heap.
 * PASCAL args: uFlags first (deepest), uBytes last -> a16(0)=uBytes, a16(2)=uFlags. */
void KERNEL_LOCALALLOC(CPU *cpu) {
    uint16_t bytes = a16(cpu, 0), flags = a16(cpu, 2);
    int i = lheap_idx(cpu->ds, 1);
    uint16_t h = 0;
    if (i >= 0) {
        uint16_t sz = (uint16_t)((bytes + 3u) & ~3u); if (sz < 4) sz = 4;
        if ((uint32_t)g_lheap[i].next + sz <= g_lheap[i].end) {
            h = g_lheap[i].next; g_lheap[i].next = (uint16_t)(g_lheap[i].next + sz);
            if (flags & 0x40)                       /* LMEM_ZEROINIT */
                for (uint16_t k = 0; k < sz; k++)
                    mem_write8(cpu, cpu->ds, (uint16_t)(h + k), 0);
        }
    }
    cpu->ax = h;                                    /* handle == near offset */
    ret(cpu, 4);
}

void KERNEL_LOCALLOCK(CPU *cpu)  { cpu->ax = a16(cpu, 0); ret(cpu, 2); } /* fixed: handle is the ptr */
void KERNEL_LOCALUNLOCK(CPU *cpu){ cpu->ax = 0; ret(cpu, 2); }
void KERNEL_LOCALFREE(CPU *cpu)  { cpu->ax = 0; ret(cpu, 2); }           /* NULL == success */
void KERNEL_LOCALSIZE(CPU *cpu)  { cpu->ax = 0; ret(cpu, 2); }
void KERNEL_LOCALFLAGS(CPU *cpu) { cpu->ax = 0; ret(cpu, 2); }
void KERNEL_LOCALHANDLE(CPU *cpu){ cpu->ax = a16(cpu, 0); ret(cpu, 2); }
/* HLOCAL LocalReAlloc(HLOCAL h, UINT uBytes, UINT uFlags): just hand back a fresh block. */
void KERNEL_LOCALREALLOC(CPU *cpu) {
    uint16_t bytes = a16(cpu, 2);
    int i = lheap_idx(cpu->ds, 1);
    uint16_t h = 0;
    if (i >= 0) {
        uint16_t sz = (uint16_t)((bytes + 3u) & ~3u); if (sz < 4) sz = 4;
        if ((uint32_t)g_lheap[i].next + sz <= g_lheap[i].end) {
            h = g_lheap[i].next; g_lheap[i].next = (uint16_t)(g_lheap[i].next + sz);
        }
    }
    cpu->ax = h; ret(cpu, 6);
}

/* ===== KERNEL: task startup =====
 * InitTask is called once at the very start of a Win16 EXE (Borland C0). It
 * returns the startup register block the runtime needs; a stub returning AX=0
 * makes the startup abort. */
/* FatalAppExit(UINT wAction, LPCSTR lpszMsg) — print the message (MSC runtime
 * errors come through here, e.g. "R6009 - not enough space for environment")
 * so we can see WHY the startup aborted, then purge the PASCAL args. */
void KERNEL_FATALAPPEXIT(CPU *cpu) {
    uint16_t off = mem_read16(cpu, cpu->ss, (uint16_t)(cpu->sp + 4));
    uint16_t seg = mem_read16(cpu, cpu->ss, (uint16_t)(cpu->sp + 6));
    char buf[160]; int i = 0;
    for (; i < 159; i++) {
        uint8_t c = mem_read8(cpu, seg, (uint16_t)(off + i));
        if (!c) break;
        buf[i] = (c >= 32 && c < 127) ? (char)c : '.';
    }
    buf[i] = 0;
    fprintf(stderr, "[FatalAppExit] %04X:%04X \"%s\"\n", seg, off, buf);
    cpu->ax = 0; cpu->sp += 4 + 6;
}

void KERNEL_INITTASK(CPU *cpu) {
    uint16_t hinst = CATZ_AUTO_DATA_SEG;   /* fake hInstance == WAD DGROUP sel */
    /* Empty command line in the (fake) PSP at DGROUP:0080: length byte 0, CR. */
    mem_write8(cpu, hinst, 0x80, 0);
    mem_write8(cpu, hinst, 0x81, 0x0D);
    cpu->ax = 1;                 /* success (nonzero) */
    cpu->flags &= ~FLAG_ZF;      /* InitTask returns flags reflecting AX; success => ZF=0 so the
                                    DLL C0 startup's `jne <full-init>` is taken (MSAJT110 was
                                    skipping its engine/session-pool init on stale ZF). */
    /* CX = stack LIMIT (lowest offset the stack may reach), not the top. The
     * C0 startup does `add cx,0x100; jb fail` to verify headroom, so a value
     * near 0xFFFF carries and aborts. Put the limit above the statics/heap
     * (DGROUP is a full 64 KB; stack grows down from sp=0xFFFE). */
    cpu->cx = 0x4000;            /* stack limit */
    cpu->dx = 1;                 /* nCmdShow = SW_SHOWNORMAL */
    cpu->si = 0;                 /* hPrevInstance = none */
    cpu->di = hinst;             /* hInstance */
    cpu->es = hinst; cpu->bx = 0x0080;   /* ES:BX -> command line */
    cpu->bp = 0;
    ret(cpu, 0);
}

/* LPSTR GetDOSEnvironment(void) -> DX:AX far ptr to the environment block.
 * The stub returned AX=0 and left DX garbage, so the C-runtime startup read a
 * stale segment (e.g. seg10 engine DATA) as the env and parsed garbage "VAR="
 * strings into the process environment. Return a real EMPTY env (double-NUL). */
void KERNEL_GETDOSENVIRONMENT(CPU *cpu) {
    static uint16_t env_sel = 0;
    if (!env_sel) {
        env_sel = galloc(cpu, 16);
        if (env_sel) { mem_write8(cpu, env_sel, 0, 0); mem_write8(cpu, env_sel, 1, 0); }
    }
    cpu->dx = env_sel; cpu->ax = 0;   /* env_sel:0000, empty (immediate NUL) */
    ret(cpu, 0);
}

/* ===== KERNEL: profile / temp files / string helpers ===== */

static void write_asciiz(CPU *cpu, uint16_t seg, uint16_t off, const char *s, int max) {
    int i = 0;
    for (; s[i] && i < max - 1; i++) mem_write8(cpu, seg, (uint16_t)(off + i), (uint8_t)s[i]);
    mem_write8(cpu, seg, (uint16_t)(off + i), 0);
}

/* UINT GetProfileInt(LPCSTR app, LPCSTR key, int nDefault)
 * There is no WIN.INI here, so every setting takes its default -- what a clean
 * install would give. Returning 0 instead is a different answer, and for a
 * size or a count it is the one that makes the caller loop. */
void KERNEL_GETPROFILEINT(CPU *cpu) {
    cpu->ax = a16(cpu, 0);
    ret(cpu, 10);
}

/* int GetProfileString(LPCSTR app, LPCSTR key, LPCSTR def, LPSTR buf, int cb) */
void KERNEL_GETPROFILESTRING(CPU *cpu) {
    char def[256] = "";
    int cb = (int)a16(cpu, 0);
    uint16_t boff = a16(cpu, 2), bseg = a16(cpu, 4);
    if (a16(cpu, 8)) read_asciiz(cpu, a16(cpu, 8), a16(cpu, 6), def, sizeof def);
    if (bseg && cb > 0) write_asciiz(cpu, bseg, boff, def, cb);
    cpu->ax = (uint16_t)strlen(def);
    ret(cpu, 18);
}

/* UINT GetTempFileName(BYTE drive, LPCSTR prefix, UINT unique, LPSTR out)
 * Jet builds its scratch database through this. The stub wrote nothing and
 * returned 0, so the caller opened whatever bytes were already in its buffer --
 * the `[file] open '      (((((  ...'` lines in the log.
 * ponytail: the name has no directory, so bob_resolve drops it in the install
 * dir alongside the .MDBs; give it a real temp path if that ever matters. */
void KERNEL_GETTEMPFILENAME(CPU *cpu) {
    static uint16_t next_unique = 1;
    char prefix[8] = "", path[80];
    uint16_t ooff = a16(cpu, 0), oseg = a16(cpu, 2);
    uint16_t unique = a16(cpu, 4);
    if (a16(cpu, 8)) read_asciiz(cpu, a16(cpu, 8), a16(cpu, 6), prefix, sizeof prefix);
    if (!unique) unique = next_unique++;
    snprintf(path, sizeof path, "%.3s%04X.TMP", prefix, unique);
    if (oseg) write_asciiz(cpu, oseg, ooff, path, (int)sizeof path);
    IMPL_LOG("[win16] GetTempFileName -> %s\n", path);
    cpu->ax = unique;
    ret(cpu, 12);
}

/* int lstrcmp / lstrcmpi (LPCSTR, LPCSTR) */
static void lstr_cmp_common(CPU *cpu, int fold) {
    char a[256] = "", b[256] = "";
    int r;
    if (a16(cpu, 6)) read_asciiz(cpu, a16(cpu, 6), a16(cpu, 4), a, sizeof a);
    if (a16(cpu, 2)) read_asciiz(cpu, a16(cpu, 2), a16(cpu, 0), b, sizeof b);
    r = fold ? _stricmp(a, b) : strcmp(a, b);
    cpu->ax = (uint16_t)(int16_t)(r < 0 ? -1 : (r > 0 ? 1 : 0));
    ret(cpu, 8);
}
void USER_LSTRCMPI(CPU *cpu) { lstr_cmp_common(cpu, 1); }
void USER_LSTRCMP(CPU *cpu)  { lstr_cmp_common(cpu, 0); }

/* OemToAnsi / AnsiToOem: identity over the ASCII range, which is all Bob uses.
 * The stub copied nothing, so the destination kept whatever it already held. */
static void oem_ansi_copy(CPU *cpu) {
    char s[512] = "";
    if (a16(cpu, 6)) read_asciiz(cpu, a16(cpu, 6), a16(cpu, 4), s, sizeof s);
    if (a16(cpu, 2)) write_asciiz(cpu, a16(cpu, 2), a16(cpu, 0), s, (int)sizeof s);
    cpu->ax = 1;
    ret(cpu, 8);
}
void KEYBOARD_OEMTOANSI(CPU *cpu) { oem_ansi_copy(cpu); }
void KEYBOARD_ANSITOOEM(CPU *cpu) { oem_ansi_copy(cpu); }

/* ---- private profile (.INI) ----
 * The stub returned 0 without touching the caller's buffer, so the caller read
 * whatever was already there. Jet finds its workgroup database through
 * GetPrivateProfileString, and Bob ships SYSTEM.MDB next to its other data, so
 * this has to answer from a real file when there is one and hand back the
 * caller's own default when there is not.
 * ponytail: a linear scan per call, no cache. These run a handful of times at
 * startup; cache it if a profile read ever shows up in a hot path. */
static int ini_lookup(const char *file, const char *sec, const char *key,
                      char *out, int outsz)
{
    char path[320], line[512], want[130];
    const char *root = getenv("BOB_INSTALL");
    const char *base = file;
    const char *p;
    FILE *f;
    int in_sec = 0, n;

    if (!file || !*file || !sec || !key) return 0;
    for (p = file; *p; p++) if (*p == '/' || *p == '\\') base = p + 1;
    if (!root) root = "game/install";
    snprintf(path, sizeof path, "%s/%s", root, base);
    f = fopen(path, "r");
    if (!f) return 0;

    snprintf(want, sizeof want, "[%s]", sec);
    while (fgets(line, sizeof line, f)) {
        char *s = line, *e;
        while (*s == ' ' || *s == '\t') s++;
        e = s + strlen(s);
        while (e > s && (e[-1] == '\n' || e[-1] == '\r' || e[-1] == ' ')) *--e = 0;
        if (*s == '[') { in_sec = (_stricmp(s, want) == 0); continue; }
        if (!in_sec || *s == ';' || !*s) continue;
        e = strchr(s, '=');
        if (!e) continue;
        *e = 0;
        { char *t = e - 1; while (t >= s && (*t == ' ' || *t == '\t')) *t-- = 0; }
        if (_stricmp(s, key) != 0) continue;
        e++;
        while (*e == ' ' || *e == '\t') e++;
        n = (int)strlen(e);
        if (n > outsz - 1) n = outsz - 1;
        memcpy(out, e, (size_t)n);
        out[n] = 0;
        fclose(f);
        return 1;
    }
    fclose(f);
    return 0;
}

/* int GetPrivateProfileString(app, key, def, buf, cb, file) */
void KERNEL_GETPRIVATEPROFILESTRING(CPU *cpu) {
    char sec[64] = "", key[64] = "", def[256] = "", file[160] = "", val[256] = "";
    int cb = (int)a16(cpu, 4);
    uint16_t boff = a16(cpu, 6), bseg = a16(cpu, 8);
    if (a16(cpu, 20)) read_asciiz(cpu, a16(cpu, 20), a16(cpu, 18), sec, sizeof sec);
    if (a16(cpu, 16)) read_asciiz(cpu, a16(cpu, 16), a16(cpu, 14), key, sizeof key);
    if (a16(cpu, 12)) read_asciiz(cpu, a16(cpu, 12), a16(cpu, 10), def, sizeof def);
    if (a16(cpu, 2))  read_asciiz(cpu, a16(cpu, 2),  a16(cpu, 0),  file, sizeof file);
    if (!ini_lookup(file, sec, key, val, (int)sizeof val))
        snprintf(val, sizeof val, "%s", def);
    if (bseg && cb > 0) write_asciiz(cpu, bseg, boff, val, cb);
    IMPL_LOG("[win16] GetPrivateProfileString %s [%s] %s -> '%s'\n", file, sec, key, val);
    cpu->ax = (uint16_t)strlen(val);
    ret(cpu, 22);
}

/* UINT GetPrivateProfileInt(app, key, nDefault, file) */
void KERNEL_GETPRIVATEPROFILEINT(CPU *cpu) {
    char sec[64] = "", key[64] = "", file[160] = "", val[64] = "";
    if (a16(cpu, 12)) read_asciiz(cpu, a16(cpu, 12), a16(cpu, 10), sec, sizeof sec);
    if (a16(cpu, 8))  read_asciiz(cpu, a16(cpu, 8),  a16(cpu, 6),  key, sizeof key);
    if (a16(cpu, 2))  read_asciiz(cpu, a16(cpu, 2),  a16(cpu, 0),  file, sizeof file);
    cpu->ax = ini_lookup(file, sec, key, val, (int)sizeof val)
              ? (uint16_t)atoi(val) : a16(cpu, 4);
    ret(cpu, 14);
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

/* ===== window class registry + per-window state (real WndProc dispatch) =====
 * Each RegisterClass stores the class WndProc + cbWndExtra under a unique atom.
 * Each window tracks its WndProc (GWL_WNDPROC, which MFC re-points to AfxWndProc
 * via SetWindowLong during the WM_NCCREATE subclass), userdata, style and extra
 * bytes. CreateWindowEx then drives WM_NCCREATE + WM_CREATE through the WndProc
 * so CWnd::OnCreate runs (builds the frame's view, etc.). */
#define MAXCLS 128
static struct { char name[64]; uint16_t atom, wp_seg, wp_off, cbWndExtra; int used; } g_cls[MAXCLS];
#define MAXWIN 512
static struct {
    uint16_t hwnd, wp_seg, wp_off, parent, hmenu, hinst, atom;
    uint32_t userdata, style;
    uint8_t  extra[64];
    int used;
} g_win[MAXWIN];

static int win_find(uint16_t hwnd) {
    for (int i = 0; i < MAXWIN; i++) if (g_win[i].used && g_win[i].hwnd == hwnd) return i;
    return -1;
}
static int cls_find_atom(uint16_t atom) {
    for (int i = 0; i < MAXCLS; i++) if (g_cls[i].used && g_cls[i].atom == atom) return i;
    return -1;
}
static int cls_find_name(const char *n) {
    for (int i = 0; i < MAXCLS; i++) if (g_cls[i].used && !strcmp(g_cls[i].name, n)) return i;
    return -1;
}

/* RegisterClass(lpWndClass): WNDCLASS{style@0,lpfnWndProc@2(far),cbClsExtra@6,
 * cbWndExtra@8,hInstance@A,...,lpszClassName@16(far)}. Returns a non-zero atom. */
void USER_REGISTERCLASS(CPU *cpu) {
    static uint16_t atom = 0xC001;
    uint16_t wc_o = a16(cpu, 0), wc_s = a16(cpu, 2);
    uint16_t wp_off = mem_read16(cpu, wc_s, (uint16_t)(wc_o + 2));
    uint16_t wp_seg = mem_read16(cpu, wc_s, (uint16_t)(wc_o + 4));
    uint16_t cbwe   = mem_read16(cpu, wc_s, (uint16_t)(wc_o + 8));
    uint16_t cn_o   = mem_read16(cpu, wc_s, (uint16_t)(wc_o + 0x16));
    uint16_t cn_s   = mem_read16(cpu, wc_s, (uint16_t)(wc_o + 0x18));
    char name[64] = ""; read_asciiz(cpu, cn_s, cn_o, name, sizeof name);
    int i = cls_find_name(name);
    if (i < 0) for (i = 0; i < MAXCLS; i++) if (!g_cls[i].used) break;
    if (i < MAXCLS) {
        g_cls[i].used = 1; g_cls[i].atom = atom;
        snprintf(g_cls[i].name, sizeof g_cls[i].name, "%s", name);
        g_cls[i].wp_seg = wp_seg; g_cls[i].wp_off = wp_off;
        g_cls[i].cbWndExtra = cbwe > 64 ? 64 : cbwe;
    }
    IMPL_LOG("[win16] RegisterClass '%s' wndproc=%04X:%04X cbWndExtra=%u -> atom=%04X\n",
             name, wp_seg, wp_off, cbwe, atom);
    cpu->ax = atom++;
    if (atom == 0) atom = 0xC001;
    ret(cpu, 4);
}
/* SetWindowsHook(nFilterType, pfnFilterProc): 2+4 = 6 bytes; returns prev hook
 * (non-zero handle). SetWindowsHookEx(idHook, lpfn, hMod, hTask): 2+4+2+2 = 10.
 * The stub guessed purge 0 (corrupting the stack) and returned 0 (= failure,
 * which made MFC InitInstance bail). Return a non-zero HHOOK. */
/* Win16 hook table (index = idHook + 1; idHook ranges WH_MSGFILTER(-1)..15).
 * MFC installs a WH_CALLWNDPROC (idHook 4) hook to subclass windows during
 * creation -- CreateWindowEx replays WM_NCCREATE through it (see below). */
#define WH_TBL_N 17
static struct { uint16_t seg, off; } g_hook[WH_TBL_N];   /* [idHook+1] */
static void set_hook(int idHook, uint16_t seg, uint16_t off) {
    if (idHook >= -1 && idHook + 1 < WH_TBL_N) {
        g_hook[idHook + 1].seg = seg; g_hook[idHook + 1].off = off;
    }
}
static int have_hook(int idHook) {
    return idHook >= -1 && idHook + 1 < WH_TBL_N && g_hook[idHook + 1].seg;
}

/* HHOOK SetWindowsHook(int idHook, HOOKPROC lpfn): idHook(2)+lpfn(4)=6 bytes.
 * a16(0)=lpfn off, a16(2)=lpfn seg, a16(4)=idHook. */
void USER_SETWINDOWSHOOK(CPU *cpu) {
    set_hook((int16_t)a16(cpu, 4), a16(cpu, 2), a16(cpu, 0));
    cpu->ax = 0x4801; cpu->dx = 0; ret(cpu, 6);
}
/* HHOOK SetWindowsHookEx(idHook, lpfn, hMod, hTask): 2+4+2+2 = 10 bytes.
 * a16(4)=lpfn off, a16(6)=lpfn seg, a16(8)=idHook. */
void USER_SETWINDOWSHOOKEX(CPU *cpu) {
    set_hook((int16_t)a16(cpu, 8), a16(cpu, 6), a16(cpu, 4));
    cpu->ax = 0x4802; cpu->dx = 0; ret(cpu, 10);
}
void USER_UNHOOKWINDOWSHOOK(CPU *cpu)   { cpu->ax = 1; ret(cpu, 4); }
void USER_UNHOOKWINDOWSHOOKEX(CPU *cpu) { cpu->ax = 1; ret(cpu, 4); }
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

/* ===== OLE / COM: COMPOBJ + OLE2DISP =====
 * Microsoft Bob is an OLE Automation application (an automation client/server
 * over its Access/Jet data store). MFC's InitInstance calls into the engine's
 * OLE bring-up (seg011), which first validates the OLE build version and then
 * CoInitializes. These shims provide just enough of the COM base + the BSTR
 * Automation layer to let InitInstance proceed toward creating the main window.
 * Returns follow the 16-bit OLE ABI: HRESULT/SCODE in DX:AX (S_OK == 0). */

/* DWORD CoBuildVersion(void) -> HIWORD=major(rmm), LOWORD=build(rup).
 * seg011_1039 requires DX==0x17 (23) and AX>=0x26A (618): OLE2 16-bit. */
void COMPOBJ_COBUILDVERSION(CPU *cpu) {
    cpu->dx = 0x0017; cpu->ax = 0x026A;
    ret(cpu, 0);
}

/* HRESULT CoInitialize(LPMALLOC pMalloc) -> S_OK. One far-pointer arg (4 bytes). */
void COMPOBJ_COINITIALIZE(CPU *cpu) {
    cpu->dx = 0; cpu->ax = 0;              /* S_OK */
    ret(cpu, 4);
}

/* void CoUninitialize(void). */
void COMPOBJ_COUNINITIALIZE(CPU *cpu) {
    ret(cpu, 0);
}

/* HRESULT OleInitialize(LPMALLOC pMalloc) -> S_OK. One far-pointer arg (4 bytes).
 * seg011_15D7 checks DX>=0 after this; a stubbed garbage DX failed it. */
void OLE2_OLEINITIALIZE(CPU *cpu) {
    cpu->dx = 0; cpu->ax = 0;             /* S_OK */
    ret(cpu, 4);
}

/* void OleUninitialize(void). */
void OLE2_OLEUNINITIALIZE(CPU *cpu) {
    ret(cpu, 0);
}

/* int Catch(LPCATCHBUF lpCatchBuf): MSC/MFC exception setjmp. The auto-stub
 * returned 0 but used the wrong purge (it left the 4-byte far-ptr arg on the
 * stack), corrupting every frame after a TRY block. Save a minimal guest
 * context into the CATCHBUF and return 0 on the initial call with the correct
 * 4-byte purge. (Full Throw/longjmp isn't modelled in the flat C-call runtime;
 * this covers the no-exception success path, which is what InitInstance hits.) */
void KERNEL_CATCH(CPU *cpu) {
    uint16_t bo = a16(cpu, 0), bs = a16(cpu, 2);   /* lpCatchBuf seg:off */
    mem_write16(cpu, bs, (uint16_t)(bo + 0), cpu->bp);
    mem_write16(cpu, bs, (uint16_t)(bo + 2), cpu->sp);
    mem_write16(cpu, bs, (uint16_t)(bo + 4), cpu->si);
    mem_write16(cpu, bs, (uint16_t)(bo + 6), cpu->di);
    mem_write16(cpu, bs, (uint16_t)(bo + 8), cpu->ds);
    cpu->ax = 0;                                   /* initial return (no throw) */
    ret(cpu, 4);
}

/* ===== USER: headless window subsystem =====
 * Bob's MFC creates its main window (class "AfxFrameOrView") via CWnd::CreateEx,
 * which subclasses the new window through a WH_CALLWNDPROC hook:
 * AfxHookWindowCreate stashes the CWnd* (pWndInit) and installs MFC's
 * _AfxCallWndProc (seg32:13BD); during CreateWindowEx the window must receive
 * WM_NCCREATE *through that hook* so MFC attaches m_hWnd and clears pWndInit --
 * otherwise AfxUnhookWindowCreate fails and CreateEx returns FALSE (no window).
 *
 * So CreateWindowEx allocates a guest HWND and replays a WM_NCCREATE CWPSTRUCT
 * through the registered WH_CALLWNDPROC hook. This is a headless window manager:
 * the guest message routing / painting logic runs unchanged; a platform display
 * (SDL) can mirror these windows later. */

/* Re-entrantly call a guest far proc with `n` pre-shaped Win16 arg words (pushed
 * in order). Snapshot+restore registers so the interrupted shim caller is left
 * intact; memory effects (the subclass clearing pWndInit) persist. Mirrors the
 * catz win32_backend re-entrant WNDPROC dispatch. */
static uint16_t call_guest(CPU *cpu, uint16_t seg, uint16_t off,
                           const uint16_t *words, int n) {
    CPU save = *cpu;
    for (int i = 0; i < n; i++) push16(cpu, words[i]);
    push16(cpu, cpu->cs); push16(cpu, 0xFFFF);     /* far return frame */
    dispatch_far(cpu, seg, off);
    uint16_t rax = cpu->ax;
    uint32_t hn = cpu->heap_next; uint16_t ns = cpu->next_sel;
    *cpu = save;                                    /* restore regs (incl. SP) */
    cpu->heap_next = hn; cpu->next_sel = ns;        /* but keep any allocations */
    return rax;
}

static uint16_t g_cwp_sel = 0;          /* scratch selector for the CWPSTRUCT */
static uint16_t g_cs_sel = 0;           /* scratch selector for the CREATESTRUCT */
static uint16_t g_next_hwnd = 0x1000;   /* handed-out guest HWNDs */

/* Send a message to a window: first replay it through the WH_CALLWNDPROC hook
 * (MFC's _AfxCallWndProc attaches the CWnd on WM_NCCREATE and may re-point the
 * WndProc to AfxWndProc via SetWindowLong), then call the window's current
 * WndProc. Returns the WndProc's LRESULT (low word). */
static uint32_t send_message(CPU *cpu, uint16_t hwnd, uint16_t msg,
                             uint16_t wParam, uint32_t lParam) {
    if (have_hook(4)) {                              /* WH_CALLWNDPROC */
        if (!g_cwp_sel) g_cwp_sel = galloc(cpu, 16);
        if (g_cwp_sel) {
            mem_write32(cpu, g_cwp_sel, 0, lParam);  /* CWPSTRUCT.lParam */
            mem_write16(cpu, g_cwp_sel, 4, wParam);
            mem_write16(cpu, g_cwp_sel, 6, msg);
            mem_write16(cpu, g_cwp_sel, 8, hwnd);
            uint16_t a[4] = { 0, 0, g_cwp_sel, 0 };  /* nCode, wParam, lParam=CWPSTRUCT */
            call_guest(cpu, g_hook[5].seg, g_hook[5].off, a, 4);
        }
    }
    int wi = win_find(hwnd);
    if (wi < 0 || !g_win[wi].wp_seg) return 0;
    /* WndProc(HWND,UINT,WPARAM,LPARAM): push hwnd,msg,wParam,lParamHi,lParamLo */
    uint16_t a[5] = { hwnd, msg, wParam,
                      (uint16_t)(lParam >> 16), (uint16_t)(lParam & 0xFFFF) };
    return call_guest(cpu, g_win[wi].wp_seg, g_win[wi].wp_off, a, 5);
}

/* HWND CreateWindowEx(dwExStyle,lpClassName,lpWindowName,dwStyle,x,y,w,h,
 *   hWndParent,hMenu,hInstance,lpParam) = 34 arg bytes (PASCAL). */
void USER_CREATEWINDOWEX(CPU *cpu) {
    uint16_t cls_o = a16(cpu, 26), cls_s = a16(cpu, 28);
    uint16_t ttl_o = a16(cpu, 22), ttl_s = a16(cpu, 24);
    uint32_t style = a16(cpu, 18) | ((uint32_t)a16(cpu, 20) << 16);
    uint16_t hparent = a16(cpu, 8), hmenu = a16(cpu, 6), hinst = a16(cpu, 4);
    uint16_t lpp_o = a16(cpu, 0), lpp_s = a16(cpu, 2);
    char cls[64] = "?", ttl[128] = "";
    if (cls_s == 0) snprintf(cls, sizeof cls, "#atom%04X", cls_o);
    else read_asciiz(cpu, cls_s, cls_o, cls, sizeof cls);
    if (ttl_s) read_asciiz(cpu, ttl_s, ttl_o, ttl, sizeof ttl);

    uint16_t hwnd = g_next_hwnd; g_next_hwnd += 4;
    IMPL_LOG("[win16] CreateWindowEx class='%s' title='%s' -> hwnd=%04X\n", cls, ttl, hwnd);

    int ci = (cls_s == 0) ? cls_find_atom(cls_o) : cls_find_name(cls);
    int wi; for (wi = 0; wi < MAXWIN; wi++) if (!g_win[wi].used) break;
    if (wi >= MAXWIN) { cpu->ax = hwnd; ret(cpu, 34); return; }
    memset(&g_win[wi], 0, sizeof g_win[wi]);
    g_win[wi].used = 1; g_win[wi].hwnd = hwnd;
    g_win[wi].parent = hparent; g_win[wi].hmenu = hmenu; g_win[wi].hinst = hinst;
    g_win[wi].style = style;
    if (ci >= 0) { g_win[wi].wp_seg = g_cls[ci].wp_seg; g_win[wi].wp_off = g_cls[ci].wp_off;
                   g_win[wi].atom = g_cls[ci].atom; }

    /* CREATESTRUCT for WM_NCCREATE/WM_CREATE lParam: lpCreateParams@0,hInstance@4,
     * hMenu@6,hwndParent@8,cy@A,cx@C,y@E,x@10,style@12,lpszName@16,lpszClass@1A,
     * dwExStyle@1E. */
    if (!g_cs_sel) g_cs_sel = galloc(cpu, 40);
    uint16_t cs = g_cs_sel;
    if (cs) {
        mem_write16(cpu, cs, 0, lpp_o); mem_write16(cpu, cs, 2, lpp_s);
        mem_write16(cpu, cs, 4, hinst); mem_write16(cpu, cs, 6, hmenu);
        mem_write16(cpu, cs, 8, hparent);
        mem_write16(cpu, cs, 0xA, a16(cpu, 10)); mem_write16(cpu, cs, 0xC, a16(cpu, 12));
        mem_write16(cpu, cs, 0xE, a16(cpu, 14)); mem_write16(cpu, cs, 0x10, a16(cpu, 16));
        mem_write32(cpu, cs, 0x12, style);
        mem_write16(cpu, cs, 0x16, ttl_o); mem_write16(cpu, cs, 0x18, ttl_s);
        mem_write16(cpu, cs, 0x1A, cls_o); mem_write16(cpu, cs, 0x1C, cls_s);
        mem_write32(cpu, cs, 0x1E, a16(cpu, 30) | ((uint32_t)a16(cpu, 32) << 16));
    }
    uint32_t lpcs = (uint32_t)cs << 16;             /* far ptr cs:0 */

    /* WM_NCCREATE (subclass attaches CWnd) then WM_CREATE (-> CWnd::OnCreate). */
    uint32_t nc = send_message(cpu, hwnd, 0x0081 /*WM_NCCREATE*/, 0, lpcs);
    (void)nc;
    uint32_t cr = send_message(cpu, hwnd, 0x0001 /*WM_CREATE*/, 0, lpcs);
    if ((int16_t)(uint16_t)cr == -1) {              /* OnCreate failed -> no window */
        IMPL_LOG("[win16]   WM_CREATE returned -1 (OnCreate failed) hwnd=%04X\n", hwnd);
        g_win[wi].used = 0;
        cpu->ax = 0; ret(cpu, 34); return;
    }
    cpu->ax = hwnd;
    ret(cpu, 34);
}

/* LONG SetWindowLong(HWND,int idx,LONG val): GWL_WNDPROC(-4),GWL_STYLE(-16),
 * GWL_EXSTYLE(-20),GWL_USERDATA(-21),idx>=0 -> cbWndExtra bytes. */
void USER_SETWINDOWLONG(CPU *cpu) {
    uint32_t val = a16(cpu, 0) | ((uint32_t)a16(cpu, 2) << 16);
    int16_t idx = (int16_t)a16(cpu, 4);
    uint16_t hwnd = a16(cpu, 6);
    int wi = win_find(hwnd); uint32_t prev = 0;
    if (wi >= 0) {
        if (idx == -4) { prev = ((uint32_t)g_win[wi].wp_seg << 16) | g_win[wi].wp_off;
                         g_win[wi].wp_off = (uint16_t)val; g_win[wi].wp_seg = (uint16_t)(val >> 16); }
        else if (idx == -21) { prev = g_win[wi].userdata; g_win[wi].userdata = val; }
        else if (idx == -16) { prev = g_win[wi].style;    g_win[wi].style = val; }
        else if (idx >= 0 && idx + 4 <= 64) {
            prev = g_win[wi].extra[idx] | (g_win[wi].extra[idx+1]<<8)
                 | ((uint32_t)g_win[wi].extra[idx+2]<<16) | ((uint32_t)g_win[wi].extra[idx+3]<<24);
            g_win[wi].extra[idx]=val; g_win[wi].extra[idx+1]=val>>8;
            g_win[wi].extra[idx+2]=val>>16; g_win[wi].extra[idx+3]=val>>24;
        }
    }
    cpu->ax = (uint16_t)prev; cpu->dx = (uint16_t)(prev >> 16);
    ret(cpu, 8);
}
void USER_GETWINDOWLONG(CPU *cpu) {
    int16_t idx = (int16_t)a16(cpu, 0); uint16_t hwnd = a16(cpu, 2);
    int wi = win_find(hwnd); uint32_t v = 0;
    if (wi >= 0) {
        if (idx == -4) v = ((uint32_t)g_win[wi].wp_seg << 16) | g_win[wi].wp_off;
        else if (idx == -21) v = g_win[wi].userdata;
        else if (idx == -16) v = g_win[wi].style;
        else if (idx >= 0 && idx + 4 <= 64)
            v = g_win[wi].extra[idx] | (g_win[wi].extra[idx+1]<<8)
              | ((uint32_t)g_win[wi].extra[idx+2]<<16) | ((uint32_t)g_win[wi].extra[idx+3]<<24);
    }
    cpu->ax = (uint16_t)v; cpu->dx = (uint16_t)(v >> 16);
    ret(cpu, 4);
}
/* WORD SetWindowWord/GetWindowWord(HWND,int idx[,WORD]): extra bytes as words. */
void USER_SETWINDOWWORD(CPU *cpu) {
    uint16_t val = a16(cpu, 0); int16_t idx = (int16_t)a16(cpu, 2); uint16_t hwnd = a16(cpu, 4);
    int wi = win_find(hwnd); uint16_t prev = 0;
    if (wi >= 0 && idx >= 0 && idx + 2 <= 64) {
        prev = g_win[wi].extra[idx] | (g_win[wi].extra[idx+1]<<8);
        g_win[wi].extra[idx] = (uint8_t)val; g_win[wi].extra[idx+1] = (uint8_t)(val>>8);
    }
    cpu->ax = prev; ret(cpu, 6);
}
void USER_GETWINDOWWORD(CPU *cpu) {
    int16_t idx = (int16_t)a16(cpu, 0); uint16_t hwnd = a16(cpu, 2);
    int wi = win_find(hwnd); uint16_t v = 0;
    if (wi >= 0 && idx >= 0 && idx + 2 <= 64) v = g_win[wi].extra[idx] | (g_win[wi].extra[idx+1]<<8);
    cpu->ax = v; ret(cpu, 4);
}
/* DefWindowProc(HWND,msg,wParam,lParam): minimal defaults. */
void USER_DEFWINDOWPROC(CPU *cpu) {
    uint16_t msg = a16(cpu, 6);
    uint16_t r = (msg == 0x0081) ? 1 : 0;   /* WM_NCCREATE -> TRUE; else 0 */
    cpu->ax = r; cpu->dx = 0;
    ret(cpu, 10);
}
/* LRESULT SendMessage(HWND,msg,wParam,lParam): dispatch to the WndProc. */
void USER_SENDMESSAGE(CPU *cpu) {
    uint32_t lParam = a16(cpu, 0) | ((uint32_t)a16(cpu, 2) << 16);
    uint16_t wParam = a16(cpu, 4), msg = a16(cpu, 6), hwnd = a16(cpu, 8);
    uint32_t r = send_message(cpu, hwnd, msg, wParam, lParam);
    cpu->ax = (uint16_t)r; cpu->dx = (uint16_t)(r >> 16);
    ret(cpu, 10);
}
void USER_DESTROYWINDOW(CPU *cpu) {
    uint16_t hwnd = a16(cpu, 0);
    int wi = win_find(hwnd);
    if (wi >= 0) { send_message(cpu, hwnd, 0x0002 /*WM_DESTROY*/, 0, 0); g_win[wi].used = 0; }
    cpu->ax = 1; ret(cpu, 2);
}
void USER_SHOWWINDOW(CPU *cpu) { cpu->ax = 0; ret(cpu, 4); }

/* int FAR cdecl wsprintf(LPSTR lpOut, LPCSTR lpFmt, ...). Caller cleans the
 * varargs (cdecl) so we only pop the return address. Renders enough of the
 * format to surface the message (Bob logs errors here). */
void USER__WSPRINTF(CPU *cpu) {
    uint16_t out_o = a16(cpu, 0), out_s = a16(cpu, 2);
    uint16_t fmt_o = a16(cpu, 4), fmt_s = a16(cpu, 6);
    char fmt[256]; read_asciiz(cpu, fmt_s, fmt_o, fmt, sizeof fmt);
    char out[512]; int oi = 0, ai = 8;
    for (int i = 0; fmt[i] && oi < 500; i++) {
        if (fmt[i] != '%') { out[oi++] = fmt[i]; continue; }
        i++;
        while (fmt[i] && (fmt[i]=='-'||fmt[i]=='+'||fmt[i]==' '||fmt[i]=='#'||fmt[i]=='0'
               || (fmt[i]>='1'&&fmt[i]<='9') || fmt[i]=='.')) i++;  /* skip flags/width */
        int lng = 0; if (fmt[i]=='l') { lng = 1; i++; }
        char sp = fmt[i]; char tmp[300]; tmp[0]=0;
        if (sp == 's') {
            uint16_t s_o=a16(cpu,ai), s_s=a16(cpu,ai+2); ai+=4;
            read_asciiz(cpu, s_s, s_o, tmp, sizeof tmp);
        } else if (sp=='d'||sp=='i'||sp=='u'||sp=='x'||sp=='X'||sp=='o'||sp=='c') {
            int32_t v;
            if (lng) { v=(int32_t)(a16(cpu,ai)|((uint32_t)a16(cpu,ai+2)<<16)); ai+=4; }
            else { v=(sp=='d'||sp=='i')?(int16_t)a16(cpu,ai):a16(cpu,ai); ai+=2; }
            if (sp=='x') snprintf(tmp,sizeof tmp,"%x",(unsigned)v);
            else if (sp=='X') snprintf(tmp,sizeof tmp,"%X",(unsigned)v);
            else if (sp=='u') snprintf(tmp,sizeof tmp,"%u",(unsigned)v);
            else if (sp=='o') snprintf(tmp,sizeof tmp,"%o",(unsigned)v);
            else if (sp=='c') { tmp[0]=(char)v; tmp[1]=0; }
            else snprintf(tmp,sizeof tmp,"%d",(int)v);
        } else { tmp[0]='%'; tmp[1]=sp; tmp[2]=0; }
        for (int k=0; tmp[k] && oi<500; k++) out[oi++]=tmp[k];
    }
    out[oi]=0;
    for (int k=0; k<=oi; k++) mem_write8(cpu, out_s, (uint16_t)(out_o+k), (uint8_t)out[k]);
    IMPL_LOG("[win16] wsprintf -> \"%s\"\n", out);
    cpu->ax = (uint16_t)oi; cpu->sp += 4;     /* cdecl: caller cleans varargs */
}

/* WritePrivateProfileString(lpSection,lpKey,lpString,lpFile): log what's written
 * (Bob writes status/errors to an .INI here) and report success. */
void KERNEL_WRITEPRIVATEPROFILESTRING(CPU *cpu) {
    char sec[64]="", key[64]="", val[200]="", file[128]="";
    if (a16(cpu,14)) read_asciiz(cpu, a16(cpu,14), a16(cpu,12), sec, sizeof sec);
    if (a16(cpu,10)) read_asciiz(cpu, a16(cpu,10), a16(cpu,8),  key, sizeof key);
    if (a16(cpu,6))  read_asciiz(cpu, a16(cpu,6),  a16(cpu,4),  val, sizeof val);
    if (a16(cpu,2))  read_asciiz(cpu, a16(cpu,2),  a16(cpu,0),  file, sizeof file);
    IMPL_LOG("[win16] WritePrivateProfileString [%s] %s=%s  (%s)\n", sec, key, val, file);
    cpu->ax = 1; ret(cpu, 16);
}
