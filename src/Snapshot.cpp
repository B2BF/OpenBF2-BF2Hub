#include "Snapshot.h"

#include "Log.h"
#include "Md5.h"
#include "Session.h"

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <winsock2.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <deque>
#include <string>
#include <vector>

namespace bf2hub {
namespace {

// The stats host, as the retail code names it (sub_10001220 for connect, "gamestats.gamespy.com"
// for the Host header). External redirection maps these to the BF2Hub backend.
const char* kConnectHost = "battlefield2.gamestats.gamespy.com";
const char* kHostHeader  = "gamestats.gamespy.com";
const char* kPath        = "/ASP/sendsnapshot.aspx";

struct Request {
    std::vector<uint8_t> body;   // [0..headerReserve) reserved for the HTTP header, then the payload
    size_t   headerReserve = 1000;
    size_t   payloadSize = 0;
    uint32_t authA = 0;
    uint32_t authB = 0;
    uint32_t sessionTime = 0;
    std::string providerId;
    int retries = 0;
};

CRITICAL_SECTION g_lock;
bool             g_lockInit = false;
std::deque<Request> g_queue;
HANDLE           g_thread = nullptr;
volatile LONG    g_stop = 0;

uint8_t randByteNonzero() {
    int r = std::rand();
    return static_cast<uint8_t>(r >= 1 ? r : 1);
}

// Build the authenticated snapshot payload into req.body[headerReserve ..], per sub_10005690.
void packInto(Request& req, const Session& s, const uint8_t* data, size_t len) {
    const uint16_t serverPort = static_cast<uint16_t>(s.serverPort);
    const uint16_t queryPort  = static_cast<uint16_t>(s.queryPort);
    const uint32_t interfaceIp = s.interfaceIp;
    const uint32_t serverIp    = s.serverIp;
    const uint32_t now = static_cast<uint32_t>(std::time(nullptr));

    req.payloadSize = len + 64;
    req.body.assign(req.headerReserve + req.payloadSize, 0);

    // v47: 16 random nonce bytes + 16 identity bytes {now, queryPort<<16|serverPort, if, srv}.
    uint8_t v47[32];
    for (int i = 0; i < 16; ++i)
        v47[i] = randByteNonzero();
    uint32_t idw[4] = { now,
                        (static_cast<uint32_t>(queryPort) << 16) | serverPort,
                        interfaceIp, serverIp };
    std::memcpy(v47 + 16, idw, 16);
    // CBC-obfuscate the identity half, seed 'M' (77), key = nonce[i%16].
    uint8_t prev = 77;
    for (int j = 0; j < 16; ++j) {
        prev = static_cast<uint8_t>(v47[16 + j] ^ prev ^ v47[j % 16]);
        v47[16 + j] = prev;
    }

    char timeStr[16];
    std::snprintf(timeStr, sizeof(timeStr), "%ld", static_cast<long>(now));
    const size_t provLen = std::strlen(s.providerId);
    const size_t timeLen = std::strlen(timeStr);

    uint8_t mac1[16], mac2[16], mac3[16];
    Md5 c;
    c.init();
    c.update(v47, 16);
    c.update(&serverPort, 2); c.update(&queryPort, 2);
    c.update(&serverIp, 4);   c.update(&interfaceIp, 4);
    c.update(s.providerId, provLen);
    c.update(timeStr, timeLen);
    c.final(mac1);

    c.init();
    c.update(v47, 16);
    c.update(&queryPort, 2); c.update(&serverPort, 2);
    c.update(&interfaceIp, 4); c.update(&serverIp, 4);
    c.update(&now, 4);
    c.update(s.providerId, provLen);
    c.final(mac2);

    c.init();
    c.update(v47, 16);
    c.update(s.providerId, provLen);
    c.update(data, len);
    c.update(timeStr, timeLen);
    c.final(mac3);

    uint8_t* p = req.body.data() + req.headerReserve;
    std::memcpy(p, v47, 32);
    std::memcpy(p + 32, mac2, 16);
    std::memcpy(p + 48, mac3, 16);
    // Body: CBC-XOR of the data, seed = nonce byte 3, key = mac1[i%16].
    uint8_t prevb = v47[3];
    for (size_t i = 0; i < len; ++i) {
        prevb = static_cast<uint8_t>(prevb ^ data[i] ^ mac1[i & 15]);
        p[64 + i] = prevb;
    }

    req.authA = s.authA;
    req.authB = s.authB;
    req.sessionTime = s.sessionTime;
    req.providerId.assign(s.providerId, provLen);
}

// Build the HTTP header into the reserved prefix and return the index/length to send, per
// sub_10004B80. Returns false if the header did not fit the reserve.
bool buildHeader(Request& req, size_t& sendOffset, size_t& sendLen) {
    const uint32_t now = static_cast<uint32_t>(std::time(nullptr));
    char tsdata[0x50];
    std::snprintf(tsdata, sizeof(tsdata), "%.8x%.8x%.8x%.8x",
                  req.authB ^ 0xE4D471A2u, req.authA ^ 0x7645E8CCu,
                  req.sessionTime ^ 0xE4D471A2u, now ^ 0x7645E8CCu);

    char header[1000];
    int hlen = std::snprintf(header, sizeof(header),
        "POST %s HTTP/1.1\r\n"
        "Host: %s\r\n"
        "User-Agent: BF2HubLib 1.0\r\n"
        "Connection: close\r\n"
        "Content-Type: application/octet-stream\r\n"
        "Content-Length: %ld\r\n"
        "X-BF2Hub-tsdata: %s\r\n"
        "\r\n"
        "HSNAP1",
        kPath, kHostHeader, static_cast<long>(req.payloadSize + 6), tsdata);

    if (hlen < 60 || static_cast<size_t>(hlen) > req.headerReserve)
        return false;

    // Move the header so it abuts the payload (which sits at [headerReserve ..]).
    sendOffset = req.headerReserve - static_cast<size_t>(hlen);
    std::memcpy(req.body.data() + sendOffset, header, static_cast<size_t>(hlen));
    sendLen = static_cast<size_t>(hlen) + req.payloadSize;
    return true;
}

bool httpPost(Request& req) {
    size_t sendOffset = 0, sendLen = 0;
    if (!buildHeader(req, sendOffset, sendLen))
        return false;

    hostent* he = ::gethostbyname(kConnectHost);
    if (!he || !he->h_addr_list || !he->h_addr_list[0])
        return false;

    SOCKET s = ::socket(AF_INET, SOCK_STREAM, 0);
    if (s == INVALID_SOCKET)
        return false;

    sockaddr_in to;
    std::memset(&to, 0, sizeof(to));
    to.sin_family = AF_INET;
    to.sin_port = htons(80);
    to.sin_addr.s_addr = *reinterpret_cast<uint32_t*>(he->h_addr_list[0]);
    if (::connect(s, reinterpret_cast<sockaddr*>(&to), sizeof(to)) != 0) {
        ::closesocket(s);
        return false;
    }

    const char* buf = reinterpret_cast<const char*>(req.body.data() + sendOffset);
    size_t sent = 0;
    while (sent < sendLen) {
        int n = ::send(s, buf + sent, static_cast<int>(sendLen - sent), 0);
        if (n <= 0) { ::closesocket(s); return false; }
        sent += static_cast<size_t>(n);
    }

    char reply[1024];
    int got = ::recv(s, reply, static_cast<int>(sizeof(reply) - 1), 0);
    ::closesocket(s);
    if (got <= 0)
        return false;
    reply[got] = '\0';
    return std::strstr(reply, " 200 OK") != nullptr;
}

DWORD WINAPI threadMain(LPVOID) {
    WSADATA wsa;
    ::WSAStartup(MAKEWORD(2, 2), &wsa);

    std::srand(static_cast<unsigned>(::GetTickCount()));

    while (::InterlockedCompareExchange(&g_stop, 0, 0) == 0) {
        Request req;
        bool have = false;
        ::EnterCriticalSection(&g_lock);
        if (!g_queue.empty()) {
            req = std::move(g_queue.front());
            g_queue.pop_front();
            have = true;
        }
        ::LeaveCriticalSection(&g_lock);

        if (have) {
            if (httpPost(req)) {
                logLine("SNAPSHOT: %lu bytes sent\r\n",
                        static_cast<unsigned long>(req.payloadSize));
            } else if (++req.retries <= 10) {
                logLine("SNAPSHOT: could not send request - requeued\r\n");
                ::EnterCriticalSection(&g_lock);
                g_queue.push_back(std::move(req));
                ::LeaveCriticalSection(&g_lock);
                ::Sleep(1000);
            } else {
                logLine("SNAPSHOT: giving up on request after %d retries\r\n", req.retries);
            }
        } else {
            ::Sleep(1000);
        }
    }

    ::WSACleanup();
    return 0;
}

} // namespace

bool queueSnapshot(const Session& session, const uint8_t* data, size_t len) {
    if (!g_lockInit)
        return false;
    Request req;
    packInto(req, session, data, len);
    if (req.body.empty())
        return false;
    ::EnterCriticalSection(&g_lock);
    g_queue.push_back(std::move(req));
    ::LeaveCriticalSection(&g_lock);
    return true;
}

void startSnapshotWorker() {
    if (g_thread)
        return;
    if (!g_lockInit) {
        ::InitializeCriticalSection(&g_lock);
        g_lockInit = true;
    }
    g_stop = 0;
    g_thread = ::CreateThread(nullptr, 0, threadMain, nullptr, 0, nullptr);
}

void stopSnapshotWorker() {
    if (!g_thread)
        return;
    ::InterlockedExchange(&g_stop, 1);
    ::WaitForSingleObject(g_thread, 3000);
    ::CloseHandle(g_thread);
    g_thread = nullptr;
    if (g_lockInit) {
        ::DeleteCriticalSection(&g_lock);
        g_lockInit = false;
    }
}

} // namespace bf2hub
