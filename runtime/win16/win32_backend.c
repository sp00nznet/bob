/*
 * win32_backend.c - Back the Win16 USER/GDI window shims with real Win32.
 *
 * We run on Windows, so the recompiled 16-bit engine can drive a real window:
 *   - RegisterClass captures the guest's WNDPROC (a lifted seg:off) and
 *     registers a real Win32 class whose C WndProc bridges back into guest code.
 *   - CreateWindow makes a real top-level window; a small table maps the 16-bit
 *     guest HWND/HDC handles to the real ones.
 *   - GetMessage/DispatchMessage drive the real Win32 message pump; on each
 *     dispatched message Win32 calls host_wndproc, which calls the guest WNDPROC
 *     via the runtime far-call dispatcher (PASCAL args + far frame).
 *
 * Drawing (GDI/WinG) is layered on top as the engine calls it.
 */
#include "runtime_api.h"
#include <stdio.h>
#include <string.h>
#include <windows.h>

extern CPU *g_cpu;

/* arg helpers (shim entry stack: [sp]=retIP, [sp+2]=retCS, [sp+4]=last arg) */
static inline uint16_t b_a16(CPU *cpu, int off) {
    return mem_read16(cpu, cpu->ss, (uint16_t)(cpu->sp + 4 + off));
}
static inline uint32_t b_a32(CPU *cpu, int off) {
    return (uint32_t)b_a16(cpu, off) | ((uint32_t)b_a16(cpu, off + 2) << 16);
}
static inline void b_ret(CPU *cpu, int purge) { cpu->sp += 4 + purge; }

/* ---- guest HWND/HDC handle tables (16-bit guest handle <-> real) ---- */
#define MAXH 64
static HWND g_hwnd[MAXH];
static HDC  g_hdc[MAXH];
static int  g_nhwnd = 1, g_nhdc = 1;   /* 0 reserved as NULL */

static uint16_t put_hwnd(HWND h) {
    for (int i = 1; i < g_nhwnd; i++) if (g_hwnd[i] == h) return (uint16_t)i;
    if (g_nhwnd < MAXH) { g_hwnd[g_nhwnd] = h; return (uint16_t)g_nhwnd++; }
    return 0;
}
static HWND get_hwnd(uint16_t g) { return (g && g < MAXH) ? g_hwnd[g] : NULL; }
static uint16_t put_hdc(HDC h) {
    if (g_nhdc < MAXH) { g_hdc[g_nhdc] = h; return (uint16_t)g_nhdc++; }
    return 0;
}
static HDC get_hdc(uint16_t g) { return (g && g < MAXH) ? g_hdc[g] : NULL; }

/* ---- the guest window procedure captured from RegisterClass ---- */
static uint16_t g_wndproc_seg = 0, g_wndproc_off = 0;

/* Call the guest WNDPROC(hWnd, uMsg, wParam, lParam) via the far dispatcher.
 * Win16 PASCAL: push args left-to-right; lParam is a DWORD (hi word first). */
static uint16_t call_guest_wndproc(uint16_t hwnd, uint16_t msg, uint16_t wparam, uint32_t lparam) {
    CPU *cpu = g_cpu;
    if (!g_wndproc_seg) return 0;
    /* The WNDPROC runs re-entrantly (CreateWindow delivers WM_NCCREATE/CREATE
     * synchronously while the guest is mid-call), so snapshot the FULL guest
     * register state and restore it afterwards. */
    CPU save = *cpu;
    /* The Borland C0 exception/cleanup machinery keeps THREE chain heads in the
     * task's stack segment: ss:[0x10] (CATZDLL cleanup chain), ss:[0x14] (WAD
     * cleanup chain) and ss:[0x16] (the C++ catch/setjmp chain). The WNDPROC runs
     * re-entrantly on the SAME stack and pushes its own frames onto these chains;
     * once we restore the interrupted guest's SP those frames no longer exist, so
     * every head must be put back -- otherwise a head points at a discarded frame
     * (or a foreign module's setjmp buffer) and the interrupted guest's later
     * chain walk derails into a runaway loop. Snapshot all three alongside the
     * CPU. (Restoring only ss:[0x14] left 0x10/0x16 dangling, which corrupted the
     * cross-module EH chain non-deterministically.) */
    uint16_t saved_exc_head_10 = mem_read16(cpu, cpu->ss, 0x10);
    uint16_t saved_exc_head    = mem_read16(cpu, cpu->ss, 0x14);
    uint16_t saved_exc_head_16 = mem_read16(cpu, cpu->ss, 0x16);
    cpu->ds = cpu->es = (g_wndproc_seg <= 59) ? CATZ_DLL_AUTO_DATA_SEG : CATZ_AUTO_DATA_SEG;
    push16(cpu, hwnd);
    push16(cpu, msg);
    push16(cpu, wparam);
    push16(cpu, (uint16_t)(lparam >> 16));
    push16(cpu, (uint16_t)(lparam & 0xFFFF));
    push16(cpu, cpu->cs); push16(cpu, 0);          /* far return frame */
    dispatch_far(cpu, g_wndproc_seg, g_wndproc_off);
    uint16_t ret = cpu->ax;
    /* restore everything except the heap/memory bookkeeping (which the WNDPROC
     * may have legitimately advanced via GlobalAlloc). */
    uint8_t *mem = cpu->mem; uint32_t *sel = cpu->sel_base;
    uint32_t hn = cpu->heap_next; uint16_t ns = cpu->next_sel;
    *cpu = save;
    cpu->mem = mem; cpu->sel_base = sel; cpu->heap_next = hn; cpu->next_sel = ns;
    /* Put the cleanup/catch chain heads back: the WNDPROC's frames no longer exist. */
    mem_write16(cpu, cpu->ss, 0x10, saved_exc_head_10);
    mem_write16(cpu, cpu->ss, 0x14, saved_exc_head);
    mem_write16(cpu, cpu->ss, 0x16, saved_exc_head_16);
    return ret;
}

/* Structural/creation messages carry host-only data (CREATESTRUCT/MINMAXINFO/
 * NCCALCSIZE far pointers the guest can't read) and must not be allowed to
 * fail creation, so we DefWindowProc them. Runtime messages (paint, timers,
 * input, command) are forwarded to the guest WNDPROC. */
static int forward_to_guest(UINT msg) {
    if (getenv("CATZ_NO_WNDPROC")) return 0;   /* diagnostic: never call guest */
    switch (msg) {
        case WM_NCCREATE: case WM_CREATE: case WM_NCCALCSIZE:
        case WM_GETMINMAXINFO: case WM_NCDESTROY: case WM_DESTROY:
        case WM_WINDOWPOSCHANGING: case WM_WINDOWPOSCHANGED:
        case WM_GETICON: case WM_NCPAINT: case WM_NCACTIVATE:
            return 0;
        default:
            return 1;
    }
}

static LRESULT CALLBACK host_wndproc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    if (msg == WM_DESTROY) { PostQuitMessage(0); return 0; }
    if (g_wndproc_seg && forward_to_guest(msg)) {
        uint16_t gh = put_hwnd(hWnd);
        return call_guest_wndproc(gh, (uint16_t)msg, (uint16_t)wParam, (uint32_t)lParam);
    }
    return DefWindowProc(hWnd, msg, wParam, lParam);
}

/* ===== USER: window class + creation ===== */

void USER_REGISTERCLASS(CPU *cpu) {
    /* lpWndClass far ptr: off@0, seg@2. Win16 WNDCLASS: style@0(2),
     * lpfnWndProc@2(4 far), ...  Capture the guest WNDPROC. */
    uint16_t off = b_a16(cpu, 0), seg = b_a16(cpu, 2);
    g_wndproc_off = mem_read16(cpu, seg, (uint16_t)(off + 2));
    g_wndproc_seg = mem_read16(cpu, seg, (uint16_t)(off + 4));
    fprintf(stderr, "[win32] RegisterClass: guest WNDPROC = seg%u:%04X\n",
            g_wndproc_seg, g_wndproc_off);
    static int registered = 0;
    if (!registered) {
        WNDCLASSA wc; memset(&wc, 0, sizeof wc);
        wc.lpfnWndProc = host_wndproc;
        wc.hInstance = GetModuleHandle(NULL);
        wc.hCursor = LoadCursor(NULL, IDC_ARROW);
        wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
        wc.lpszClassName = "CatzRecompWnd";
        RegisterClassA(&wc);
        registered = 1;
    }
    cpu->ax = 0xC001;
    b_ret(cpu, 4);
}

void USER_CREATEWINDOW(CPU *cpu) {
    if (getenv("CATZ_FAKE_WIN")) { cpu->ax = 0x0CA7; b_ret(cpu, 30); return; }
    HWND h = CreateWindowExA(0, "CatzRecompWnd", "Catz (recomp)",
        WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, CW_USEDEFAULT, 640, 480,
        NULL, NULL, GetModuleHandle(NULL), NULL);
    uint16_t gh = h ? put_hwnd(h) : 0;
    fprintf(stderr, "[win32] CreateWindow -> real=%p guest=%u err=%lu\n",
            (void*)h, gh, h ? 0UL : (unsigned long)GetLastError());
    cpu->ax = gh;
    b_ret(cpu, 30);
}

void USER_SHOWWINDOW(CPU *cpu) {
    HWND h = get_hwnd(b_a16(cpu, 2));
    if (h) ShowWindow(h, SW_SHOW);
    cpu->ax = 0; b_ret(cpu, 4);
}

void USER_UPDATEWINDOW(CPU *cpu) {
    HWND h = get_hwnd(b_a16(cpu, 0));
    if (h) UpdateWindow(h);
    cpu->ax = 0; b_ret(cpu, 2);
}

void USER_GETDC(CPU *cpu) {
    HWND h = get_hwnd(b_a16(cpu, 0));
    HDC dc = h ? GetDC(h) : NULL;
    cpu->ax = dc ? put_hdc(dc) : 0;
    b_ret(cpu, 2);
}

void USER_RELEASEDC(CPU *cpu) {
    uint16_t gdc = b_a16(cpu, 0);   /* HWND@2, HDC@0 */
    HWND h = get_hwnd(b_a16(cpu, 2));
    HDC dc = get_hdc(gdc);
    if (h && dc) ReleaseDC(h, dc);
    cpu->ax = 1; b_ret(cpu, 4);
}

/* ===== USER: message loop ===== */

void USER_GETMESSAGE(CPU *cpu) {
    /* GetMessage(LPMSG@2/4, HWND@.., UINT, UINT) -> BOOL. Pump real messages. */
    uint16_t moff = b_a16(cpu, 6), mseg = b_a16(cpu, 8);
    MSG m;
    BOOL r = GetMessageA(&m, NULL, 0, 0);
    if (r) {
        /* Win16 MSG: hwnd@0(2) message@2(2) wParam@4(2) lParam@6(4) time@10(4) pt@14(4) */
        mem_write16(cpu, mseg, (uint16_t)(moff + 0), put_hwnd(m.hwnd));
        mem_write16(cpu, mseg, (uint16_t)(moff + 2), (uint16_t)m.message);
        mem_write16(cpu, mseg, (uint16_t)(moff + 4), (uint16_t)m.wParam);
        mem_write16(cpu, mseg, (uint16_t)(moff + 6), (uint16_t)(m.lParam & 0xFFFF));
        mem_write16(cpu, mseg, (uint16_t)(moff + 8), (uint16_t)(m.lParam >> 16));
    }
    cpu->ax = (uint16_t)(r ? 1 : 0);
    b_ret(cpu, 10);   /* lpMsg(4)+hWnd(2)+min(2)+max(2) */
}

void USER_PEEKMESSAGE(CPU *cpu) {
    uint16_t moff = b_a16(cpu, 8), mseg = b_a16(cpu, 10);
    uint16_t wRemove = b_a16(cpu, 0);
    MSG m;
    BOOL r = PeekMessageA(&m, NULL, 0, 0, wRemove ? PM_REMOVE : PM_NOREMOVE);
    if (r) {
        mem_write16(cpu, mseg, (uint16_t)(moff + 0), put_hwnd(m.hwnd));
        mem_write16(cpu, mseg, (uint16_t)(moff + 2), (uint16_t)m.message);
        mem_write16(cpu, mseg, (uint16_t)(moff + 4), (uint16_t)m.wParam);
        mem_write16(cpu, mseg, (uint16_t)(moff + 6), (uint16_t)(m.lParam & 0xFFFF));
        mem_write16(cpu, mseg, (uint16_t)(moff + 8), (uint16_t)(m.lParam >> 16));
    }
    cpu->ax = (uint16_t)(r ? 1 : 0);
    b_ret(cpu, 12);
}

void USER_TRANSLATEMESSAGE(CPU *cpu) { cpu->ax = 0; b_ret(cpu, 4); }

void USER_DISPATCHMESSAGE(CPU *cpu) {
    /* lpMsg far ptr @0/2: re-read and dispatch via real Win32 -> host_wndproc. */
    uint16_t moff = b_a16(cpu, 0), mseg = b_a16(cpu, 2);
    MSG m; memset(&m, 0, sizeof m);
    m.hwnd    = get_hwnd(mem_read16(cpu, mseg, (uint16_t)(moff + 0)));
    m.message = mem_read16(cpu, mseg, (uint16_t)(moff + 2));
    m.wParam  = mem_read16(cpu, mseg, (uint16_t)(moff + 4));
    m.lParam  = (uint32_t)mem_read16(cpu, mseg, (uint16_t)(moff + 6))
              | ((uint32_t)mem_read16(cpu, mseg, (uint16_t)(moff + 8)) << 16);
    DispatchMessageA(&m);
    cpu->ax = 0; b_ret(cpu, 4);
}
