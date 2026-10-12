// Import Address Table patching - the mechanism the shipped bf2hub.dll uses (sub_10003690) to take
// over the engine's calls to dice_py's Py_InitModule4 / PyImport_ImportModule without touching
// dice_py or the engine source. We walk the host image's import directory, find the thunk that
// currently holds the real resolved address of (dllName, procName), and overwrite it with our
// function, returning the original so the hook can call through.
//
// We deliberately drop the retail Win9x path (sub_100037E0, W32SKRNL "_ImteFromHModule"): the
// engine targets modern Windows only.

#ifndef BF2HUB_IATHOOK_H
#define BF2HUB_IATHOOK_H

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

namespace bf2hub {

// Redirect image's import of dllName!procName to newFn. Returns the original resolved address
// (suitable for calling through), or nullptr if the import was not found or could not be patched.
void* patchIatImport(HMODULE image, const char* dllName, const char* procName, void* newFn);

} // namespace bf2hub

#endif // BF2HUB_IATHOOK_H
