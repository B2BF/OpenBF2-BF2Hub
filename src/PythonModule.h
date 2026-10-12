// The `bf2hublib` C extension module and the hooks that inject it, plus the `bf2.bf2hub` import.
//
// Mechanism (retail sub_10007C90 / sub_10007A00 / sub_10007AF0): we patch the host exe's imports of
// dice_py's Py_InitModule4 and PyImport_ImportModule. When the engine registers its own "host"
// module we register "bf2hublib" alongside it (same method table the retail DLL exposes), and we
// capture the "host" module object so our methods can call back into host.rcon_invoke /
// host.sgl_getModDirectory. When the engine imports "bf2" we additionally import "bf2.bf2hub" if the
// script package is present. This must happen before Python init, which is why the module is loaded
// from openbf2.con / ServerSettings.con via `openbf2.addModDll bf2hub`.

#ifndef BF2HUB_PYTHONMODULE_H
#define BF2HUB_PYTHONMODULE_H

namespace bf2hub {

class Config;
struct Session;

// Installs the dice_py IAT hooks on the running host image. Safe to call once, from the dedicated
// server startup path, before the engine initialises Python.
void installPythonHooks(Config* config, Session* session);

} // namespace bf2hub

#endif // BF2HUB_PYTHONMODULE_H
