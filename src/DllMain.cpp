// Entry point. The shipped bf2hub.dll does all its work from DllMain (sub_10001730) and exports no
// initDll, so OpenBF2's `openbf2.addModDll bf2hub` loader keeps it resident after DllMain has run.
// We follow that contract exactly: no initDll export here.
//
// On PROCESS_ATTACH, if we are inside a dedicated server (bf2_w32ded/bf2_w64ded), we:
//   1. load bf2hub.cfg,
//   2. install the dice_py IAT hooks so our bf2hublib / bf2.bf2hub modules get injected when the
//      engine brings Python up (this must happen before Python init - hence loading from
//      openbf2.con / ServerSettings.con), and
//   3. start the BF2Hub "hello" heartbeat thread.
//
// We deliberately reproduce only the DllMain payload the integration needs; the ws2_32 socket proxy
// the retail DLL also is (its exported winsock thunks) is handled elsewhere and is not built here.

#include "Config.h"
#include "Heartbeat.h"
#include "HostImage.h"
#include "Log.h"
#include "PythonModule.h"
#include "Session.h"
#include "Snapshot.h"

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#include <cstring>
#include <new>

namespace {

bf2hub::Config*  g_config = nullptr;
bf2hub::Session* g_session = nullptr;

void serverStartup() {
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

BOOL WINAPI DllMain(HINSTANCE hinst, DWORD reason, LPVOID /*reserved*/) {
    switch (reason) {
    case DLL_PROCESS_ATTACH:
        ::DisableThreadLibraryCalls(hinst);
        if (bf2hub::hostIsDedicated())
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
