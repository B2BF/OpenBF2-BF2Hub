// Import-redirection, the platform-idiomatic way to take over the engine's dice_py calls without
// touching dice_py or the engine source:
//   * Windows: patch the host image's Import Address Table (sub_10003690 in the retail DLL).
//   * Linux:   patch the host executable's GOT/PLT relocation slot. This is the ELF analog of the
//              IAT patch. The retail .so instead relies on symbol interposition (exported wrappers +
//              dlsym), which only works under LD_PRELOAD; GOT patching works with a plain
//              `openbf2.addModDll` dlopen, so we use it to stay loadable the same way on both
//              platforms. [CHOSEN, not recovered]
//
// installImportHook redirects the host's imported `symbol` (resolved from dice_py) to `replacement`
// and returns the original address via `outReal` so the wrapper can call through.

#ifndef BF2HUB_HOOK_H
#define BF2HUB_HOOK_H

namespace bf2hub {

bool installImportHook(const char* symbol, void* replacement, void** outReal);

} // namespace bf2hub

#endif // BF2HUB_HOOK_H
