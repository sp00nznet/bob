/*
 * win16_file.c - Real file I/O for the Bob recomp, backed by the host
 * filesystem under game/install (override with $BOB_INSTALL).
 *
 * Replaces the no-op stubs for the KERNEL file API (_lopen/_lread/_llseek/
 * _lclose/_lcreat/_lwrite/_hread, OpenFile) and the DOS int-21h file functions
 * dispatched through DOS3CALL (0x3C..0x42). Jet 1.1 / the UTOPIA engine read
 * their .MDB databases (system.mdb, utopia.mdb, upic.mdb, per-app .mdb) through
 * these, so without real I/O Bob never loads its Access-Basic procedures
 * ("no main procedure").
 *
 * Path mapping: guest paths arrive as DOS paths ("C:\MSBOB\address\abook.mdb",
 * or relative). We normalize '\'->'/', drop the drive letter, then search under
 * the install root, progressively stripping leading directories until a file is
 * found (so an absolute guest install prefix collapses to our layout). Windows'
 * host fopen is case-insensitive, which matches DOS semantics for free.
 */
#include "runtime_api.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <io.h>       /* _chsize / _fileno: DOS "set file length" */

#ifdef CATZ_TRACE_WIN16
#define FIO_LOG(...) fprintf(stderr, __VA_ARGS__)
#else
#define FIO_LOG(...) ((void)0)
#endif

/* ---- guest-stack arg helpers (mirror win16_impl.c) ---- */
static inline uint16_t fa16(CPU *cpu, int off) {
    return mem_read16(cpu, cpu->ss, (uint16_t)(cpu->sp + 4 + off));
}
static inline uint32_t fa32(CPU *cpu, int off) {
    return (uint32_t)fa16(cpu, off) | ((uint32_t)fa16(cpu, off + 2) << 16);
}
static inline void fret(CPU *cpu, int purge) { cpu->sp += 4 + purge; }

static void fread_asciiz(CPU *cpu, uint16_t seg, uint16_t off, char *out, int max) {
    int i = 0;
    for (; i < max - 1; i++) {
        uint8_t c = mem_read8(cpu, seg, (uint16_t)(off + i));
        if (!c) break;
        out[i] = (char)c;
    }
    out[i] = 0;
}

/* ---- host-path resolution ---- */
static int bob_resolve(const char *guest, char *host, int hostsz, int for_read) {
    char norm[300]; int j = 0;
    const char *p = guest;
    if (p[0] && p[1] == ':') p += 2;                 /* drop "X:" */
    for (; *p && j < (int)sizeof(norm) - 1; p++)
        norm[j++] = (*p == '\\') ? '/' : *p;
    norm[j] = 0;
    char *n = norm; while (*n == '/') n++;            /* drop leading slashes */
    const char *root = getenv("BOB_INSTALL");
    if (!root) root = "game/install";
    if (for_read) {
        for (const char *seg = n; seg && *seg; ) {
            snprintf(host, hostsz, "%s/%s", root, seg);
            FILE *f = fopen(host, "rb");
            if (f) { fclose(f); return 1; }
            const char *slash = strchr(seg, '/');
            seg = slash ? slash + 1 : NULL;
        }
    }
    snprintf(host, hostsz, "%s/%s", root, n);         /* fallback / create target */
    return 0;
}

/* A zero-length DOS write sets the file's length to the current position --
 * truncating or EXTENDING it. Jet grows its database with exactly that:
 * seg061_023A seeks to page*2048, writes zero bytes, then seeks to the end and
 * compares. Doing nothing for a count of 0 leaves the file its old size, so
 * the compare fails, and the -1808 that comes back is remapped to "disk full".
 * Nothing else in the C library says "set this length", hence _chsize. */
static void fio_set_eof(FILE *f)
{
    long pos = ftell(f);
    if (pos < 0) return;
    fflush(f);
    if (_chsize(_fileno(f), pos) == 0) fseek(f, pos, SEEK_SET);
}

/* ---- guest-handle -> host FILE* table ---- */
#define FIO_MIN 5            /* 0..4 reserved (stdin/out/err/aux/prn) */
#define FIO_MAX 256
static FILE *g_fio[FIO_MAX];

static int fio_alloc(FILE *f) {
    for (int h = FIO_MIN; h < FIO_MAX; h++)
        if (!g_fio[h]) { g_fio[h] = f; return h; }
    fclose(f);
    return -1;
}
static FILE *fio_get(int h) {
    return (h >= FIO_MIN && h < FIO_MAX) ? g_fio[h] : NULL;
}
static void fio_close(int h) {
    if (h >= FIO_MIN && h < FIO_MAX && g_fio[h]) { fclose(g_fio[h]); g_fio[h] = NULL; }
}

/* mode: 0=read, 1=write, 2=read/write (+create on write/rw) */
/* Does the guest path resolve to a file that exists? */
static int bob_exists(const char *guest) {
    char host[320];
    return bob_resolve(guest, host, sizeof host, 1);
}

/* `create` separates DOS open (3Dh) from DOS create (3Ch). Opening a file that
 * is not there has to FAIL: Jet asks "does this exist?" by trying, and an open
 * that quietly creates an empty file answers yes to every question. */
static int fio_open_mode2(const char *guest, int mode, int create) {
    char host[320];
    int found = bob_resolve(guest, host, sizeof host, 1);
    const char *fm;
    FILE *f;
    if (create) fm = "w+b";                  /* create/truncate */
    else if (!found) { FIO_LOG("[file] open '%s' -> not found\n", guest); return -1; }
    else fm = (mode == 0) ? "rb" : "r+b";
    f = fopen(host, fm);
    FIO_LOG("[file] open '%s' -> %s mode=%d %s\n", guest, host, mode, f ? "OK" : "FAIL");
    if (!f) return -1;
    return fio_alloc(f);
}

static int fio_open_mode(const char *guest, int mode) {
    return fio_open_mode2(guest, mode, 0);
}

/* ===================== KERNEL HFILE API ===================== */

void KERNEL__LOPEN(CPU *cpu) {              /* _lopen(lpPathName, iReadWrite) */
    char path[260];
    fread_asciiz(cpu, fa16(cpu, 4), fa16(cpu, 2), path, sizeof path);  /* lpPathName far */
    int rw = (int16_t)fa16(cpu, 0) & 3;                                /* iReadWrite */
    int h = fio_open_mode(path, rw);
    cpu->ax = (uint16_t)(h < 0 ? 0xFFFF : h);
    fret(cpu, 6);
}

void KERNEL__LCREAT(CPU *cpu) {            /* _lcreat(lpPathName, iAttribute) */
    char path[260]; fread_asciiz(cpu, fa16(cpu, 4), fa16(cpu, 2), path, sizeof path);
    int h = fio_open_mode2(path, 2, 1);
    cpu->ax = (uint16_t)(h < 0 ? 0xFFFF : h);
    fret(cpu, 6);
}

void KERNEL__LCLOSE(CPU *cpu) {            /* _lclose(hFile) */
    fio_close((int16_t)fa16(cpu, 0));
    cpu->ax = 0;
    fret(cpu, 2);
}

void KERNEL__LREAD(CPU *cpu) {            /* _lread(hFile, lpBuffer, cbRead) */
    int h = (int16_t)fa16(cpu, 6);
    uint16_t boff = fa16(cpu, 2), bseg = fa16(cpu, 4);
    uint16_t cb = fa16(cpu, 0);
    FILE *f = fio_get(h);
    uint16_t n = 0;
    if (f) {
        for (; n < cb; n++) {
            int c = fgetc(f);
            if (c == EOF) break;
            mem_write8(cpu, bseg, (uint16_t)(boff + n), (uint8_t)c);
        }
    }
    FIO_LOG("[file] _lread h=%d cb=%u -> %u\n", h, cb, n);
    cpu->ax = n;
    fret(cpu, 8);
}

void KERNEL__HREAD(CPU *cpu) {            /* _hread(hFile, lpBuffer, LONG cbRead) */
    int h = (int16_t)fa16(cpu, 8);
    uint16_t boff = fa16(cpu, 4), bseg = fa16(cpu, 6);
    uint32_t cb = fa32(cpu, 0);
    FILE *f = fio_get(h);
    uint32_t n = 0;
    if (f) {
        for (; n < cb; n++) {
            int c = fgetc(f);
            if (c == EOF) break;
            mem_write8(cpu, bseg, (uint16_t)(boff + (n & 0xFFFF)), (uint8_t)c);
        }
    }
    cpu->ax = (uint16_t)(n & 0xFFFF); cpu->dx = (uint16_t)(n >> 16);
    fret(cpu, 10);
}

void KERNEL__LWRITE(CPU *cpu) {           /* _lwrite(hFile, lpBuffer, cbWrite) */
    int h = (int16_t)fa16(cpu, 6);
    uint16_t boff = fa16(cpu, 2), bseg = fa16(cpu, 4);
    uint16_t cb = fa16(cpu, 0);
    FILE *f = fio_get(h);
    uint16_t n = 0;
    if (f && cb == 0) fio_set_eof(f);        /* same rule as the DOS call */
    else if (f) for (; n < cb; n++) fputc(mem_read8(cpu, bseg, (uint16_t)(boff + n)), f);
    cpu->ax = n;
    fret(cpu, 8);
}

void KERNEL__LLSEEK(CPU *cpu) {           /* _llseek(hFile, LONG lOffset, iOrigin) */
    int h = (int16_t)fa16(cpu, 6);
    int32_t off = (int32_t)fa32(cpu, 2);
    int origin = (int16_t)fa16(cpu, 0);
    FILE *f = fio_get(h);
    long pos = -1;
    if (f) {
        int wh = origin == 1 ? SEEK_CUR : origin == 2 ? SEEK_END : SEEK_SET;
        if (fseek(f, off, wh) == 0) pos = ftell(f);
    }
    if (pos < 0) { cpu->ax = 0xFFFF; cpu->dx = 0xFFFF; }
    else { cpu->ax = (uint16_t)(pos & 0xFFFF); cpu->dx = (uint16_t)((pos >> 16) & 0xFFFF); }
    fret(cpu, 8);
}

void KERNEL_OPENFILE(CPU *cpu) {          /* OpenFile(lpFileName, lpOFSTRUCT, wStyle) */
    char path[260]; fread_asciiz(cpu, fa16(cpu, 8), fa16(cpu, 6), path, sizeof path);
    uint16_t ofoff = fa16(cpu, 2), ofseg = fa16(cpu, 4);
    uint16_t style = fa16(cpu, 0);
    char host[320];
    int found = bob_resolve(path, host, sizeof host, !(style & 0x1000) /*OF_CREATE*/);
    /* OFSTRUCT: +0 cBytes, +1 fFixedDisk, +2 nErrCode(word), +4 reserved[4], +8 szPathName[] */
    if (style & 0x4000) {                  /* OF_EXIST: just report existence */
        cpu->ax = (uint16_t)(found ? 1 : 0xFFFF);
        FIO_LOG("[file] OpenFile(OF_EXIST) '%s' -> %s\n", path, found ? "yes" : "NO");
        fret(cpu, 10); return;
    }
    int mode = (style & 3);                 /* OF_READ/WRITE/READWRITE low bits */
    int h = fio_open_mode2(path, mode, (style & 0x1000) != 0 /*OF_CREATE*/);
    if (ofseg) {                            /* fill szPathName so callers can re-read it */
        for (int i = 0; i < (int)sizeof(host) && host[i]; i++)
            mem_write8(cpu, ofseg, (uint16_t)(ofoff + 8 + i), (uint8_t)host[i]);
        mem_write16(cpu, ofseg, (uint16_t)(ofoff + 2), (uint16_t)(h < 0 ? 2 : 0));
    }
    cpu->ax = (uint16_t)(h < 0 ? 0xFFFF : h);
    fret(cpu, 10);
}

/* ===================== DOS int-21h via DOS3CALL ===================== *
 * Register-based: AH=function. CF (in cpu->flags) signals error; AX=result or
 * DOS error code. Jet uses 0x3C..0x42 for the .MDB. */
void KERNEL_DOS3CALL(CPU *cpu) {
    uint8_t ah = (uint8_t)(cpu->ax >> 8);
    cpu->flags &= ~FLAG_CF;
    switch (ah) {
    case 0x3D: {                            /* open: AL=mode, DS:DX=name */
        char path[260]; fread_asciiz(cpu, cpu->ds, cpu->dx, path, sizeof path);
        int h = fio_open_mode(path, cpu->ax & 3);
        if (h < 0) { cpu->ax = 0x02; cpu->flags |= FLAG_CF; }   /* file not found */
        else cpu->ax = (uint16_t)h;
        FIO_LOG("[dos] open '%s' -> %d\n", path, h);
        break;
    }
    case 0x3C: {                            /* create: CX=attr, DS:DX=name */
        char path[260]; fread_asciiz(cpu, cpu->ds, cpu->dx, path, sizeof path);
        int h = fio_open_mode2(path, 2, 1);
        if (h < 0) { cpu->ax = 0x03; cpu->flags |= FLAG_CF; }
        else cpu->ax = (uint16_t)h;
        break;
    }
    case 0x3E:                              /* close: BX=handle */
        fio_close((int16_t)cpu->bx);
        break;
    case 0x3F: {                            /* read: BX=handle, CX=count, DS:DX=buf */
        FILE *f = fio_get((int16_t)cpu->bx); uint16_t n = 0;
        if (f) for (; n < cpu->cx; n++) {
            int c = fgetc(f); if (c == EOF) break;
            mem_write8(cpu, cpu->ds, (uint16_t)(cpu->dx + n), (uint8_t)c);
        } else { cpu->ax = 0x06; cpu->flags |= FLAG_CF; break; }   /* bad handle */
        cpu->ax = n;
        break;
    }
    case 0x40: {                            /* write: BX=handle, CX=count, DS:DX=buf */
        FILE *f = fio_get((int16_t)cpu->bx); uint16_t n = 0;
        if (!f) { cpu->ax = 0x06; cpu->flags |= FLAG_CF; break; }
        if (cpu->cx == 0) { fio_set_eof(f); cpu->ax = 0; break; }
        for (; n < cpu->cx; n++)
            fputc(mem_read8(cpu, cpu->ds, (uint16_t)(cpu->dx + n)), f);
        cpu->ax = n;
        break;
    }
    case 0x42: {                            /* lseek: AL=origin, BX=handle, CX:DX=off */
        FILE *f = fio_get((int16_t)cpu->bx);
        if (f) {
            int32_t off = (int32_t)(((uint32_t)cpu->cx << 16) | cpu->dx);
            int wh = (cpu->ax & 0xFF) == 1 ? SEEK_CUR : (cpu->ax & 0xFF) == 2 ? SEEK_END : SEEK_SET;
            if (fseek(f, off, wh) == 0) {
                long pos = ftell(f);
                cpu->ax = (uint16_t)(pos & 0xFFFF); cpu->dx = (uint16_t)((pos >> 16) & 0xFFFF);
            } else { cpu->ax = 0x19; cpu->flags |= FLAG_CF; }
        } else { cpu->ax = 0x06; cpu->flags |= FLAG_CF; }
        break;
    }
    case 0x30:                              /* get DOS version -> AL=major, AH=minor */
        cpu->ax = 0x0005;                    /* report MS-DOS 5.00 */
        cpu->bx = 0; cpu->cx = 0;
        break;
    case 0x25:                              /* set interrupt vector (DS:DX) - noop */
    case 0x35:                              /* get interrupt vector -> ES:BX=0:0 */
        if (ah == 0x35) { cpu->es = 0; cpu->bx = 0; }
        break;
    case 0x19:                              /* get current drive -> AL (0=A:, 2=C:) */
        cpu->ax = (cpu->ax & 0xFF00) | 0x02;
        break;
    case 0x47:                              /* get current dir -> empty (root) */
        if (cpu->ds) mem_write8(cpu, cpu->ds, cpu->si, 0);
        break;
    case 0x43: {                            /* get/set file attributes */
        /* This is how Jet asks whether a file exists -- seg061_00B6 issues
         * AH=43h and reads CF-clear as "already there, do not create". A stub
         * that always succeeded meant Jet never created and initialised its
         * own scratch database, and then rejected the empty file it opened.
         * AL=1 (set) still just succeeds; nothing here has attributes. */
        char path[260];
        int exists;
        fread_asciiz(cpu, cpu->ds, cpu->dx, path, sizeof path);
        exists = bob_exists(path);
        FIO_LOG("[dos] attrs '%s' -> %s\n", path, exists ? "exists" : "NOT FOUND");
        if (!exists && (cpu->ax & 0xFF) == 0) {
            cpu->ax = 0x02; cpu->flags |= FLAG_CF;      /* file not found */
        } else {
            cpu->cx = 0x20; cpu->ax = cpu->cx; cpu->flags &= ~FLAG_CF;
        }
        break;
    }
    case 0x5C:                              /* lock / unlock file region */
        /* Jet takes byte-range locks on the .ldb to coordinate with other
         * Access instances. Nothing else has these files open, so every lock
         * succeeds. */
        cpu->flags &= ~FLAG_CF;
        break;
    case 0x5E:                              /* network: get machine name */
        /* CH=0 means "no name defined", which is the right answer for a
         * non-networked machine and stops Jet looking for a share. */
        cpu->cx &= 0x00FF;
        cpu->flags &= ~FLAG_CF;
        break;
    case 0x44:                              /* IOCTL. AL=0: get device info */
        /* Jet asks this about every handle it opens. The default branch
         * answered "invalid function" with CF set, which Jet reads as a failed
         * open and unwinds through longjmp. Bit 7 clear says "this is a file,
         * not a character device", which is true of everything we hand back. */
        cpu->dx = 0x0002;                    /* file, on drive C: */
        cpu->ax = cpu->dx;
        cpu->flags &= ~FLAG_CF;
        break;
    case 0x59:                              /* get extended error */
        /* Called after any failure; answering "invalid function" here means the
         * caller cannot even find out what went wrong. Report no error. */
        cpu->ax = 0; cpu->bx = 0; cpu->cx = 0;
        cpu->flags &= ~FLAG_CF;
        break;
    case 0x4C:                              /* terminate - ignore (host loop drives exit) */
        break;
    default:
        FIO_LOG("[dos] unhandled int21 AH=%02X\n", ah);
        cpu->ax = 0x01; cpu->flags |= FLAG_CF;     /* invalid function */
        break;
    }
    cpu->sp += 4;                            /* far return; no stack args */
}
