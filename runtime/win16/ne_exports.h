/* ne_exports.h - the lifted modules' export tables, generated into
 * src/_exports.c by tools/lift_combined.py.
 *
 * GetProcAddress needs a real far pointer: a Win16 app that does
 * LoadLibrary + GetProcAddress treats a 0 as "the file is missing", which is
 * how Bob's VBX loader ended up reporting a bad install. (seg, off) here is
 * the GLOBAL segment number, so dispatch_far lands on the lifted function. */
#ifndef NE_EXPORTS_H
#define NE_EXPORTS_H
#include <stdint.h>

typedef struct {
    uint16_t    hinst;      /* module's DGROUP selector == its LoadLibrary handle */
    const char *name;       /* exported name, "" if the entry is ordinal-only */
    uint16_t    ordinal;
    uint16_t    seg;        /* global segment number */
    uint16_t    off;
} NEExport;

extern const NEExport g_ne_exports[];
extern const int      g_ne_nexports;

/* Resolve by name (case-insensitive) when `name` is non-NULL, else by ordinal.
 * Returns 1 and fills seg/off on success, 0 if the module has no such export. */
int ne_get_proc(uint16_t hinst, const char *name, uint16_t ordinal,
                uint16_t *seg, uint16_t *off);

#endif
