cmake_minimum_required(VERSION 3.16)
project(bob_recomp C)

set(CMAKE_C_STANDARD 11)

# Lifted segment sources (generated into src/ by ne_lift + gen_* tools).
# UTOPIA.DLL (engine), UTOPIAWA.EXE (host) and UEXTRA.DLL (blit helpers) each
# lift to one seg*.c per code segment.
file(GLOB SEGMENT_SOURCES CONFIGURE_DEPENDS src/*.c)

include_directories(runtime)

# Build the lifted engine + host as a static library.
if(SEGMENT_SOURCES)
    add_library(bob_segments STATIC ${SEGMENT_SOURCES})
    target_compile_options(bob_segments PRIVATE
        -Wall
        -Wno-unused-variable
        -Wno-unused-label
        -Wno-unused-but-set-variable
        -Wno-unused-function
    )
endif()

# Win16 API shim runtime (KERNEL/USER/GDI/WING/WAVMIX16/OLE2 -> Win32/SDL2)
# plus the lifted-code support translation units (trace ring, etc.).
file(GLOB RUNTIME_SOURCES CONFIGURE_DEPENDS runtime/win16/*.c runtime/*.c)
if(RUNTIME_SOURCES)
    add_library(bob_runtime STATIC ${RUNTIME_SOURCES})
    target_include_directories(bob_runtime PRIVATE runtime)
    target_compile_definitions(bob_runtime PRIVATE
        BOB_GAME_DIR="${CMAKE_SOURCE_DIR}/game/install")
endif()

# Host: UTOPIAWA-equivalent window shell that loads the engine and drives it.
if(EXISTS "${CMAKE_SOURCE_DIR}/runtime/main.c" AND SEGMENT_SOURCES)
    add_executable(bob runtime/main.c)
    target_compile_definitions(bob PRIVATE
        BOB_IMAGE_PATH="${CMAKE_SOURCE_DIR}/build_data/mem_image.bin")
    target_link_libraries(bob bob_segments bob_runtime m)
    if(WIN32)
        target_link_libraries(bob user32 gdi32)
    endif()
endif()
