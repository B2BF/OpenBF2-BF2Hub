cmake_minimum_required(VERSION 3.21)

# OpenBF2-BF2Hub: a run-time mod module for the OpenBF2 dedicated server that reproduces the parts of
# the shipped BF2Hub client DLL (bf2hub.dll) that make a Battlefield 2 1.50 server rankable on the
# BF2Hub backend. It is loaded by the engine's `openbf2.addModDll bf2hub` console command.
#
# Scope (see README.md for the full rationale):
#   * The shipped bf2hub.dll is a ws2_32.dll proxy whose payload runs from DllMain. This project
#     reproduces ONLY the DllMain payload the user needs:
#       - the Python integration (the `bf2hublib` C extension module + the `bf2.bf2hub` import), and
#       - the "hello" heartbeat to the BF2Hub master/servers list.
#     The ws2_32 socket-proxy / GameSpy redirection is intentionally NOT reproduced; the engine
#     handles master-server/socket routing on its own.
#   * The module is built against the engine's embedded CPython 2.3.4 ABI, exported by dice_py.
#
# Platforms: Windows x86 and x64 for now. Linux (libbf2hub.so, x86/x64) comes later and is stubbed
# out below so the CMake stays honest about what exists.

project(openbf2_bf2hub
    VERSION 1.0.0
    DESCRIPTION "OpenBF2 BF2Hub integration mod module"
    LANGUAGES CXX)

if(NOT WIN32)
    message(FATAL_ERROR
        "Only the Windows build (x86/x64) exists today. The Linux libbf2hub.so port is planned "
        "but not implemented yet; do not configure this project on a non-Windows host.")
endif()

# ---------------------------------------------------------------------------
# Architecture detection. The engine images are bf2_w32ded.exe (x86) and bf2_w64ded.exe (x64);
# this module is loaded into whichever one is running, so it must match that pointer size.
# ---------------------------------------------------------------------------
if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    set(BF2HUB_ARCH "x64")
else()
    set(BF2HUB_ARCH "x86")
endif()
message(STATUS "OpenBF2-BF2Hub: building the ${BF2HUB_ARCH} module (bf2hub.dll)")

# ---------------------------------------------------------------------------
# dice_py ABI. We link against dice_py's import library (the same CPython 2.3.4 the engine embeds)
# so our `bf2hublib` C module uses the exact PyObject layout and allocator the engine uses. The
# import library and runtime DLL are the ones staged beside the dedicated server; point these cache
# variables at that build. See docs in the OpenBF2 tree (Code/Build/python/build_python.cmd).
# ---------------------------------------------------------------------------
set(BF2HUB_DICE_PY_DIR "" CACHE PATH
    "Directory containing the architecture-matched dice_py.lib / dice_py.dll")

# ---------------------------------------------------------------------------
# The module.
# ---------------------------------------------------------------------------
add_library(bf2hub MODULE
    src/DllMain.cpp
    src/HostImage.cpp
    src/IatHook.cpp
    src/Md5.cpp
    src/Config.cpp
    src/PythonModule.cpp
    src/Snapshot.cpp
    src/Heartbeat.cpp)

set_target_properties(bf2hub PROPERTIES
    OUTPUT_NAME "bf2hub"
    PREFIX ""                       # no "lib" prefix: the engine loads ".\bf2hub.dll" by that name
    CXX_STANDARD 14
    CXX_STANDARD_REQUIRED ON
    CXX_EXTENSIONS OFF)

target_include_directories(bf2hub PRIVATE src)

# The engine hands a plugin's optional initDll an IClassManager*. We take a lenient route (no
# initDll; our work is done from DllMain) exactly like the shipped bf2hub, so the loader keeps us
# resident. The define documents that choice for the source.
target_compile_definitions(bf2hub PRIVATE
    BF2HUB_ARCH="${BF2HUB_ARCH}"
    # We use the classic BSD socket names (gethostbyname/inet_addr) and the C string helpers
    # deliberately, to mirror the shipped code; silence the MSVC "use the secure variant" noise.
    _WINSOCK_DEPRECATED_NO_WARNINGS
    _CRT_SECURE_NO_WARNINGS
    $<$<CONFIG:Debug>:BF2HUB_DEBUG=1>)

if(MSVC)
    target_compile_options(bf2hub PRIVATE /W4 /permissive- /EHsc /GR-)
    # Match the shipped module: no CRT surprises across the dice_py heap boundary. dice_py is built
    # against the dynamic CRT, and PyObjects we allocate are freed by the interpreter, so we must
    # share its CRT. Use the dynamic runtime.
    set_property(TARGET bf2hub PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>DLL")
endif()

# dice_py import library (CPython 2.3.4 the engine embeds).
if(BF2HUB_DICE_PY_DIR AND EXISTS "${BF2HUB_DICE_PY_DIR}/dice_py.lib")
    target_link_libraries(bf2hub PRIVATE "${BF2HUB_DICE_PY_DIR}/dice_py.lib")
    target_compile_definitions(bf2hub PRIVATE BF2HUB_HAVE_DICE_PY=1)
else()
    # Keep configuring so the non-Python pieces still build and the layout is reviewable, but make
    # the gap loud: the Python module cannot link without dice_py.lib.
    message(WARNING
        "BF2HUB_DICE_PY_DIR is not set to a directory containing dice_py.lib. The module will "
        "build WITHOUT the Python integration linked (BF2HUB_HAVE_DICE_PY=0). Set it to the "
        "arch-matched dice_py build to get a complete bf2hub.dll.")
endif()

# Winsock for the heartbeat. (This is the engine-independent heartbeat socket, not the ws2_32 proxy.)
target_link_libraries(bf2hub PRIVATE ws2_32 advapi32 shell32 psapi)

# Stage the built module next to the server if an output directory was given.
set(BF2HUB_STAGE_DIR "" CACHE PATH
    "Optional: copy the built bf2hub.dll into this directory (your server's game folder)")
if(BF2HUB_STAGE_DIR)
    add_custom_command(TARGET bf2hub POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "$<TARGET_FILE:bf2hub>" "${BF2HUB_STAGE_DIR}/bf2hub.dll"
        COMMENT "Staging bf2hub.dll into ${BF2HUB_STAGE_DIR}")
endif()
