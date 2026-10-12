cmake_minimum_required(VERSION 3.21)

# OpenBF2-BF2Hub: a run-time mod module for the OpenBF2 dedicated server that reproduces the parts of
# the shipped BF2Hub client (bf2hub.dll on Windows, libbf2hub.so on Linux) that make a Battlefield 2
# 1.50 server rankable on the BF2Hub backend. It is loaded by the engine's console command
# `openbf2.addModDll bf2hub`.
#
# Scope (see README.md):
#   * Reproduces the load-time payload: the Python integration (the `bf2hublib` C module + the
#     `bf2.bf2hub` import) and the "hello" heartbeat. The ws2_32 / socket proxy the retail images
#     also are is intentionally NOT reproduced.
#   * Windows: bf2hub.dll (x86 + x64), hooks via IAT patch, heartbeat tag HHHL3Q + exe fingerprint.
#   * Linux: libbf2hub.so (x86-64), hooks via GOT patch, heartbeat tag HHHL2Q + a fixed key. The
#     Linux libbf2hub.so is a distinct, simpler build; this target reproduces it faithfully.
#
# Platforms: Windows x86/x64 and Linux x86-64.

project(openbf2_bf2hub
    VERSION 1.0.0
    DESCRIPTION "OpenBF2 BF2Hub integration mod module"
    LANGUAGES CXX)

# ---------------------------------------------------------------------------
# Architecture label (for diagnostics only).
# ---------------------------------------------------------------------------
if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    set(BF2HUB_ARCH "x64")
else()
    set(BF2HUB_ARCH "x86")
endif()
message(STATUS "OpenBF2-BF2Hub: building the ${BF2HUB_ARCH} module (${CMAKE_SYSTEM_NAME})")

# ---------------------------------------------------------------------------
# Sources: common + platform-specific hook implementation.
# ---------------------------------------------------------------------------
set(BF2HUB_SOURCES
    src/DllMain.cpp
    src/HostImage.cpp
    src/Md5.cpp
    src/Config.cpp
    src/Platform.cpp
    src/PythonModule.cpp
    src/Snapshot.cpp
    src/Heartbeat.cpp)

if(WIN32)
    list(APPEND BF2HUB_SOURCES src/IatHook.cpp)
else()
    list(APPEND BF2HUB_SOURCES src/GotHook.cpp)
endif()

add_library(bf2hub MODULE ${BF2HUB_SOURCES})

set_target_properties(bf2hub PROPERTIES
    OUTPUT_NAME "bf2hub"
    CXX_STANDARD 14
    CXX_STANDARD_REQUIRED ON
    CXX_EXTENSIONS OFF)

target_include_directories(bf2hub PRIVATE src)
target_compile_definitions(bf2hub PRIVATE BF2HUB_ARCH="${BF2HUB_ARCH}")

# ---------------------------------------------------------------------------
# Windows: bf2hub.dll, loaded by name. Links the engine's dice_py import library and winsock.
# ---------------------------------------------------------------------------
if(WIN32)
    # The engine loads ".\\bf2hub.dll" by that name - no "lib" prefix.
    set_target_properties(bf2hub PROPERTIES PREFIX "")

    target_compile_definitions(bf2hub PRIVATE
        _WINSOCK_DEPRECATED_NO_WARNINGS
        _CRT_SECURE_NO_WARNINGS
        $<$<CONFIG:Debug>:BF2HUB_DEBUG=1>)

    if(MSVC)
        target_compile_options(bf2hub PRIVATE /W4 /permissive- /EHsc /GR-)
        # dice_py is built against the dynamic CRT and frees PyObjects we allocate, so share its CRT.
        set_property(TARGET bf2hub PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>DLL")
    endif()

    set(BF2HUB_DICE_PY_DIR "" CACHE PATH
        "Directory containing the architecture-matched dice_py.lib / dice_py.dll")
    if(BF2HUB_DICE_PY_DIR AND EXISTS "${BF2HUB_DICE_PY_DIR}/dice_py.lib")
        target_link_libraries(bf2hub PRIVATE "${BF2HUB_DICE_PY_DIR}/dice_py.lib")
        target_compile_definitions(bf2hub PRIVATE BF2HUB_HAVE_DICE_PY=1)
    else()
        message(WARNING
            "BF2HUB_DICE_PY_DIR is not set to a directory containing dice_py.lib. The Windows module "
            "will not link the Python integration. Set it to the arch-matched dice_py build.")
    endif()

    target_link_libraries(bf2hub PRIVATE ws2_32 advapi32 shell32 psapi)

# ---------------------------------------------------------------------------
# Linux: libbf2hub.so. The CPython 2.3 symbols (Py_*) stay undefined and resolve at load time from
# libdice_py.so in the server process - exactly as the retail libbf2hub.so does - so no dice_py
# import library is needed to build. Links libdl (dlopen/dlsym/dlinfo for the GOT patch) and
# libpthread.
# ---------------------------------------------------------------------------
else()
    # The engine's addModDll resolves "bf2hub" to lib<stem>.so, so keep the default "lib" prefix:
    # the output is libbf2hub.so.
    target_compile_options(bf2hub PRIVATE -Wall -Wextra -fvisibility=hidden -fno-rtti)
    # Keep libdl/libpthread in DT_NEEDED even on glibc that folds them into libc, for old targets.
    target_link_libraries(bf2hub PRIVATE dl pthread)
    target_link_options(bf2hub PRIVATE "LINKER:--no-as-needed" "LINKER:--allow-shlib-undefined")

    # The CPython symbols live in libdice_py.so. The retail libbf2hub.so lists libdice_py.so in its
    # DT_NEEDED so the loader pulls those symbols in; without that entry the server aborts with
    # "undefined symbol: PyExc_ValueError" when it loads the module. We reproduce the DT_NEEDED
    # either by linking the real libdice_py.so (preferred, BF2HUB_DICE_PY), or by linking a generated
    # link-time stub whose SONAME is libdice_py.so (the real library in the server process resolves
    # the symbols at run time - the stub is never shipped or loaded).
    set(BF2HUB_DICE_PY "" CACHE FILEPATH "Path to the real libdice_py.so (optional; a stub is used if unset)")
    if(BF2HUB_DICE_PY AND EXISTS "${BF2HUB_DICE_PY}")
        target_link_libraries(bf2hub PRIVATE "${BF2HUB_DICE_PY}")
    else()
        set(_stub_cpp "${CMAKE_BINARY_DIR}/dice_py_stub.cpp")
        file(WRITE "${_stub_cpp}"
"/* Auto-generated link-time stub. Defines the CPython 2.3 symbols libbf2hub.so imports so the\n"
" * linker records DT_NEEDED libdice_py.so; the real libdice_py.so provides them at run time. */\n"
"extern \"C\" {\n"
"#define F(n) void n(void){}\n"
"#define D(n) void* n = 0;\n"
"F(PyObject_CallMethod) F(PyLong_FromLong) F(PyString_FromString) F(PyString_AsString)\n"
"F(PyArg_ParseTuple) F(PyString_FromFormat) F(PyType_IsSubtype) F(PyErr_Format)\n"
"D(_Py_ZeroStruct) D(_Py_NoneStruct) D(_Py_TrueStruct) D(PyModule_Type) D(PyString_Type)\n"
"D(PyExc_RuntimeError) D(PyExc_ValueError) D(PyExc_TypeError) D(PyExc_IndexError)\n"
"}\n")
        add_library(dice_py_stub SHARED "${_stub_cpp}")
        set_target_properties(dice_py_stub PROPERTIES OUTPUT_NAME dice_py)  # -> libdice_py.so, SONAME libdice_py.so
        target_link_libraries(bf2hub PRIVATE dice_py_stub)
    endif()

    # Do not bake the build directory into the module's RUNPATH: libdice_py.so must resolve from the
    # server's own environment at run time, never from (or to) the build-time stub.
    set_target_properties(bf2hub PROPERTIES SKIP_BUILD_RPATH ON BUILD_WITH_INSTALL_RPATH ON INSTALL_RPATH "")
endif()

# ---------------------------------------------------------------------------
# Optional staging next to the server.
# ---------------------------------------------------------------------------
set(BF2HUB_STAGE_DIR "" CACHE PATH
    "Optional: copy the built module into this directory (your server's game folder)")
if(BF2HUB_STAGE_DIR)
    add_custom_command(TARGET bf2hub POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "$<TARGET_FILE:bf2hub>" "${BF2HUB_STAGE_DIR}/$<TARGET_FILE_NAME:bf2hub>"
        COMMENT "Staging $<TARGET_FILE_NAME:bf2hub> into ${BF2HUB_STAGE_DIR}")
endif()
