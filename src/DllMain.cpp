// Entry point. The module does all its work from the OS load hook and exports no initDll, so
// OpenBF2's `openbf2.addModDll bf2hub` loader keeps it resident after the hook has run - the
// contract the engine documents for a DllMain/constructor-based integration.
//
//   * Windows: DllMain(PROCESS_ATTACH/DETACH) - the shipped bf2hub.dll model (sub_10001730).
//   * Linux:   an .init_array constructor / .fini_array destructor - the shipped libbf2hub.so model.
//
// On attach, inside a dedicated server, we load bf2hub.cfg, install the dice_py import hooks (IAT
// patch on Windows, GOT patch on Linux) so our bf2hublib / bf2.bf2hub modules get injected when the
// engine brings Python up, and start the snapshot worker and the "hello" heartbeat. The ws2_32 /
// socket proxy the retail images also are is intentionally not built here.

#include "Config.h"
#include "Heartbeat.h"
#include "HostImage.h"
#include "Log.h"
#include "Platform.h"
#include "PythonModule.h"
#include "Session.h"
#include "Snapshot.h"

#include <cstring>
#include <new>

#ifndef BF2HUB_ARCH
#  define BF2HUB_ARCH "unknown"
#endif

namespace {

bf2hub::Config*  g_config = nullptr;
bf2hub::Session* g_session = nullptr;

void serverStartup() {
    if (!bf2hub::hostIsDedicated())
        return;

    g_config = new (std::nothrow) bf2hub::Config();
    g_session = new (std::nothrow) bf2hub::Session();
    if (!g_config || !g_session)
        return;
    std::memset(g_session, 0, sizeof(bf2hub::Session));

    g_config->load();
    bf2hub::logLine("bf2hub module loaded into dedicated server (%s)\r\n", BF2HUB_ARCH);

    bf2hub::installPythonHooks(g_config, g_session);
    bf2hub::startSnapshotWorker();
    bf2hub::startHeartbeat(g_config);
}

void serverShutdown() {
    bf2hub::stopHeartbeat();
    bf2hub::stopSnapshotWorker();
    delete g_session;
    g_session = nullptr;
    delete g_config;
    g_config = nullptr;
}

} // namespace

#if defined(_WIN32)

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

BOOL WINAPI DllMain(HINSTANCE hinst, DWORD reason, LPVOID /*reserved*/) {
    switch (reason) {
    case DLL_PROCESS_ATTACH:
        ::DisableThreadLibraryCalls(hinst);
        serverStartup();
        break;
    case DLL_PROCESS_DETACH:
        serverShutdown();
        break;
    default:
        break;
    }
    return TRUE;
}

#else

__attribute__((constructor)) static void bf2hubOnLoad() {
    serverStartup();
}

__attribute__((destructor)) static void bf2hubOnUnload() {
    serverShutdown();
}

#endif
