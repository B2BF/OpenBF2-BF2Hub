#include "IatHook.h"
#include "Hook.h"

#include <cstdint>
#include <cstring>

namespace bf2hub {

void* patchIatImport(HMODULE image, const char* dllName, const char* procName, void* newFn) {
    if (!image || !dllName || !procName || !newFn)
        return nullptr;

    // Resolve the real target so we can find the matching thunk by value, exactly as the shipped
    // code does: GetModuleHandle(dllName) + GetProcAddress. If the engine has not loaded dllName
    // yet there is nothing to patch.
    HMODULE targetModule = ::GetModuleHandleA(dllName);
    if (!targetModule)
        return nullptr;
    void* realProc = reinterpret_cast<void*>(::GetProcAddress(targetModule, procName));
    if (!realProc)
        return nullptr;

    auto base = reinterpret_cast<uint8_t*>(image);
    auto dos = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE)
        return nullptr;
    auto nt = reinterpret_cast<IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE)
        return nullptr;

    const IMAGE_DATA_DIRECTORY& importDir =
        nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (!importDir.VirtualAddress || !importDir.Size)
        return nullptr;

    auto desc = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(base + importDir.VirtualAddress);
    for (; desc->Name; ++desc) {
        const char* name = reinterpret_cast<const char*>(base + desc->Name);
        if (_stricmp(name, dllName) != 0)
            continue;

        // FirstThunk is the IAT: each entry is the resolved function pointer at load time. Find the
        // slot whose value equals the real proc and swap it.
        auto thunk = reinterpret_cast<uintptr_t*>(base + desc->FirstThunk);
        for (; *thunk; ++thunk) {
            if (reinterpret_cast<void*>(*thunk) != realProc)
                continue;

            DWORD oldProtect = 0;
            if (::VirtualProtect(thunk, sizeof(*thunk), PAGE_READWRITE, &oldProtect)) {
                *thunk = reinterpret_cast<uintptr_t>(newFn);
                DWORD tmp = 0;
                ::VirtualProtect(thunk, sizeof(*thunk), oldProtect, &tmp);
            } else {
                *thunk = reinterpret_cast<uintptr_t>(newFn);
            }
            return realProc;
        }
    }
    return nullptr;
}

bool installImportHook(const char* symbol, void* replacement, void** outReal) {
    void* real = patchIatImport(::GetModuleHandleA(nullptr), "dice_py.dll", symbol, replacement);
    if (outReal)
        *outReal = real;
    return real != nullptr;
}

} // namespace bf2hub
