// Linux GOT/PLT patch - the ELF analog of the Windows IAT patch. We walk the host executable's
// relocations (DT_JMPREL for PLT function imports, DT_RELA for data), find the slot bound to
// `symbol` (which the dynamic linker resolved to libdice_py.so's implementation), and overwrite it
// with our replacement, returning the original (via dlsym) so the wrapper can call through.
//
// This runs from the module's constructor, before the engine initialises Python - the same timing
// the Windows DllMain uses - so the slot is patched before the engine's first Py_InitModule4 call.

#if !defined(_WIN32)

#ifndef _GNU_SOURCE
#  define _GNU_SOURCE
#endif

#include "Hook.h"

#include <cstring>
#include <dlfcn.h>
#include <elf.h>
#include <link.h>
#include <sys/mman.h>
#include <unistd.h>

namespace bf2hub {

namespace {

bool patchSlot(ElfW(Addr) slotAddr, void* replacement) {
    void** slot = reinterpret_cast<void**>(slotAddr);
    long pageSize = ::sysconf(_SC_PAGESIZE);
    if (pageSize <= 0)
        pageSize = 4096;
    uintptr_t pageStart = reinterpret_cast<uintptr_t>(slot) & ~(static_cast<uintptr_t>(pageSize) - 1);
    // GOT pages are typically already writable; make sure, then restore to RW (ELF GOT stays RW).
    ::mprotect(reinterpret_cast<void*>(pageStart), static_cast<size_t>(pageSize),
               PROT_READ | PROT_WRITE);
    *slot = replacement;
    return true;
}

// Scan a RELA table for a JUMP_SLOT/GLOB_DAT reloc naming `symbol` and patch it.
bool scanRela(ElfW(Addr) base, const ElfW(Rela)* rela, size_t count,
              const ElfW(Sym)* symtab, const char* strtab,
              const char* symbol, void* replacement) {
    bool patched = false;
    for (size_t i = 0; i < count; ++i) {
        unsigned long symIndex = ELF64_R_SYM(rela[i].r_info);
        const char* name = strtab + symtab[symIndex].st_name;
        if (std::strcmp(name, symbol) == 0) {
            if (patchSlot(base + rela[i].r_offset, replacement))
                patched = true;
        }
    }
    return patched;
}

} // namespace

bool installImportHook(const char* symbol, void* replacement, void** outReal) {
    // The real implementation to call through to: the global-scope definition (libdice_py.so's),
    // since we do not export these symbols ourselves in the GOT-patch design.
    void* real = ::dlsym(RTLD_DEFAULT, symbol);
    if (outReal)
        *outReal = real;

    // Reach the main executable's link_map (its relocations hold the engine's import slots).
    void* self = ::dlopen(nullptr, RTLD_LAZY | RTLD_NOLOAD);
    if (!self)
        return false;
    struct link_map* lm = nullptr;
    if (::dlinfo(self, RTLD_DI_LINKMAP, &lm) != 0 || !lm)
        return false;

    const ElfW(Sym)* symtab = nullptr;
    const char* strtab = nullptr;
    const ElfW(Rela)* jmprel = nullptr;
    size_t jmprelSize = 0;
    const ElfW(Rela)* rela = nullptr;
    size_t relaSize = 0, relaEnt = sizeof(ElfW(Rela));

    for (const ElfW(Dyn)* d = lm->l_ld; d->d_tag != DT_NULL; ++d) {
        switch (d->d_tag) {
            case DT_SYMTAB:   symtab = reinterpret_cast<const ElfW(Sym)*>(d->d_un.d_ptr); break;
            case DT_STRTAB:   strtab = reinterpret_cast<const char*>(d->d_un.d_ptr); break;
            case DT_JMPREL:   jmprel = reinterpret_cast<const ElfW(Rela)*>(d->d_un.d_ptr); break;
            case DT_PLTRELSZ: jmprelSize = d->d_un.d_val; break;
            case DT_RELA:     rela = reinterpret_cast<const ElfW(Rela)*>(d->d_un.d_ptr); break;
            case DT_RELASZ:   relaSize = d->d_un.d_val; break;
            case DT_RELAENT:  relaEnt = d->d_un.d_val; break;
            default: break;
        }
    }
    if (!symtab || !strtab || relaEnt == 0)
        return false;

    bool patched = false;
    if (jmprel && jmprelSize)
        patched |= scanRela(lm->l_addr, jmprel, jmprelSize / sizeof(ElfW(Rela)),
                            symtab, strtab, symbol, replacement);
    if (rela && relaSize)
        patched |= scanRela(lm->l_addr, rela, relaSize / relaEnt,
                            symtab, strtab, symbol, replacement);
    return patched;
}

} // namespace bf2hub

#endif // !_WIN32
