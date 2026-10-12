#include "Heartbeat.h"

#include "Config.h"
#include "HostImage.h"
#include "Log.h"
#include "Md5.h"

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>

#include <cstdlib>
#include <cstring>
#include <ctime>

namespace bf2hub {
namespace {

// Protocol constants recovered from sub_10008B80 / sub_10008570.
const char     kHelloTag[6]  = {'H', 'H', 'H', 'L', '3', 'Q'};
const uint32_t kHelloMagic   = 1367436204u;   // a3 in sub_10008570
const uint16_t kHelloPort    = 29960;         // htons(0x7508)
const char*    kServersHost  = "servers.bf2hub.com";
const int      kIntervalSec  = 60;            // dedicated cadence (sub_10008B80 mode 2)
const int      kMaxServers   = 16;

Config*  g_config = nullptr;
HANDLE   g_thread = nullptr;
volatile LONG g_stop = 0;

// A nonzero random byte (sub_10001E00: if rand()>=1 use rand(), else 1 - i.e. never 0).
uint8_t randByte() {
    int r = std::rand();
    return static_cast<uint8_t>(r >= 1 ? r : 1);
}

// Build the hello payload after the 6-byte tag. Returns the payload length (78), or 0 if the
// fingerprint could not be built. Layout (sub_10008570):
//   [0..7]   8 random bytes (the XOR key, kept in clear)
//   [8..11]  time
//   [12..15] magic
//   [16..61] exe fingerprint blob (46 bytes)
//   then keyed-MD5 MAC over [0..62) is appended at [62..78), and [8..62) are XOR'd with key[i%8].
int buildHelloPayload(const Fingerprint& fp, uint8_t* p) {
    for (int i = 0; i < 8; ++i)
        p[i] = randByte();

    uint32_t now = static_cast<uint32_t>(::time(nullptr));
    std::memcpy(p + 8, &now, 4);
    std::memcpy(p + 12, &kHelloMagic, 4);
    std::memcpy(p + 16, &fp, sizeof(Fingerprint)); // 46 bytes

    const int macInput = 16 + static_cast<int>(sizeof(Fingerprint)); // 62

    Md5 ctx;
    ctx.init(kHeartbeatIV, kHeartbeatStartBits);
    ctx.update(p, static_cast<size_t>(macInput));
    uint8_t digest[16];
    ctx.final(digest);

    for (int i = 8; i < macInput; ++i)
        p[i] ^= p[i % 8];

    std::memcpy(p + macInput, digest, 16);
    return macInput + 16; // 78
}

// Resolve the BF2Hub servers list (sub_10008A50). Fills out[] with up to kMaxServers IPv4 addresses
// (network byte order) and returns the count.
int resolveServers(uint32_t* out) {
    addrinfo hints;
    std::memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;

    addrinfo* res = nullptr;
    if (::getaddrinfo(kServersHost, "80", &hints, &res) != 0)
        return 0;

    int n = 0;
    for (addrinfo* ai = res; ai && n < kMaxServers; ai = ai->ai_next) {
        if (ai->ai_family == AF_INET) {
            auto sa = reinterpret_cast<sockaddr_in*>(ai->ai_addr);
            out[n++] = sa->sin_addr.s_addr;
        }
    }
    ::freeaddrinfo(res);
    return n;
}

void sendHello(const Fingerprint& fp) {
    uint32_t servers[kMaxServers];
    int count = resolveServers(servers);
    if (count < 1) {
        logLine("HELLO: could not resolve %s\r\n", kServersHost);
        return;
    }

    SOCKET s = ::socket(AF_INET, SOCK_DGRAM, 0);
    if (s == INVALID_SOCKET)
        return;

    uint8_t packet[6 + 78];
    std::memcpy(packet, kHelloTag, 6);
    int payload = buildHelloPayload(fp, packet + 6);
    if (payload <= 0) {
        ::closesocket(s);
        return;
    }
    const int packetLen = 6 + payload;

    for (int i = 0; i < count; ++i) {
        sockaddr_in to;
        std::memset(&to, 0, sizeof(to));
        to.sin_family = AF_INET;
        to.sin_port = htons(kHelloPort);
        to.sin_addr.s_addr = servers[i];
        ::sendto(s, reinterpret_cast<const char*>(packet), packetLen, 0,
                 reinterpret_cast<sockaddr*>(&to), sizeof(to));
    }
    logLine("HELLO: sent %d-byte hello to %d server(s)\r\n", packetLen, count);

    // Retail reads a response here to refresh its server/rule table for the ws2 proxy filter
    // (sub_10008680 -> network cache). That table only feeds the proxy we do not reproduce, so we
    // intentionally do not parse the reply. [FRONTIER] bf2hub::heartbeatResponse - decode is known
    // (sub_10008680) but unused here.
    ::closesocket(s);
}

DWORD WINAPI threadMain(LPVOID) {
    Fingerprint fp;
    bool haveFp = g_config && buildFingerprint(*g_config, fp);
    if (!haveFp)
        logLine("HELLO: reference exe fingerprint unavailable; heartbeat will keep retrying\r\n");

    std::srand(static_cast<unsigned>(::GetTickCount()));

    while (::InterlockedCompareExchange(&g_stop, 0, 0) == 0) {
        if (!haveFp && g_config)
            haveFp = buildFingerprint(*g_config, fp);
        if (haveFp)
            sendHello(fp);

        for (int slept = 0; slept < kIntervalSec * 10; ++slept) {
            if (::InterlockedCompareExchange(&g_stop, 0, 0) != 0)
                return 0;
            ::Sleep(100);
        }
    }
    return 0;
}

} // namespace

void startHeartbeat(Config* config) {
    if (g_thread)
        return;
    g_config = config;
    g_stop = 0;

    WSADATA wsa;
    ::WSAStartup(MAKEWORD(2, 2), &wsa);

    g_thread = ::CreateThread(nullptr, 0, threadMain, nullptr, 0, nullptr);
    if (!g_thread)
        logLine("HELLO: could not start heartbeat thread\r\n");
}

void stopHeartbeat() {
    if (!g_thread)
        return;
    ::InterlockedExchange(&g_stop, 1);
    ::WaitForSingleObject(g_thread, 3000);
    ::CloseHandle(g_thread);
    g_thread = nullptr;
    ::WSACleanup();
}

} // namespace bf2hub
