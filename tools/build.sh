#!/usr/bin/env bash
# build.sh - Full compile+link of the Bob recomp.
#   Usage: tools/build.sh [trace|normal]  (default: normal)
#     normal -> build/obj/*.o   -> build/bob.exe
#     trace  -> build/objt/*.o  -> build/bob_t.exe  (-DCATZ_TRACE_FN)
# Requires mingw gcc on PATH (export PATH="/c/msys64/mingw64/bin:$PATH").
set -e
cd "$(dirname "$0")/.."
MODE="${1:-normal}"
if [ "$MODE" = "trace" ]; then OBJ=build/objt; EXE=build/bob_t.exe; DEF="-DCATZ_TRACE_FN";
else OBJ=build/obj; EXE=build/bob.exe; DEF=""; fi
mkdir -p "$OBJ"
CFLAGS="-O1 -w -Iruntime -Iruntime/win16 -Isrc $DEF"
echo "[build] mode=$MODE -> $EXE"
# Compile every src/*.c and runtime/*.c (+ win16) in parallel, only if newer.
compile() { local c="$1" o="$2"; if [ ! -f "$o" ] || [ "$c" -nt "$o" ]; then gcc $CFLAGS -c "$c" -o "$o"; fi; }
export -f compile; export CFLAGS
ls src/*.c runtime/*.c runtime/win16/*.c 2>/dev/null | \
  xargs -P "$(nproc)" -I{} bash -c 'o="'"$OBJ"'/$(basename {} .c).o"; compile "{}" "$o"'
echo "[build] linking..."
gcc -o "$EXE" "$OBJ"/*.o
echo "[build] done -> $EXE"
