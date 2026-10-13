#include "Snapshot.h"

#include "Log.h"
#include "Md5.h"
#include "Platform.h"
#include "Session.h"

#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <deque>
#include <mutex>
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

std::mutex          g_lock;
std::deque<Request> g_queue;
Thread              g_thread;
std::atomic<bool>   g_stop{false};

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
    // X-BF2Hub-tsdata. Half 1 (both platforms): the XOR quad of the session auth words.
    char tsdata[0x50];
    int tn = std::snprintf(tsdata, sizeof(tsdata), "%.8x%.8x%.8x%.8x",
                  req.authB ^ 0xE4D471A2u, req.authA ^ 0x7645E8CCu,
                  req.sessionTime ^ 0xE4D471A2u, now ^ 0x7645E8CCu);
#if !defined(_WIN32)
    // Half 2 (Linux sub_49E6): MD5(authB | authA | sessionTime | now | providerId), appended as hex,
    // so the Linux tsdata is 64 hex chars, not 32.
    {
        Md5 c;
        c.init();
        c.update(&req.authB, 4);
        c.update(&req.authA, 4);
        c.update(&req.sessionTime, 4);
        c.update(&now, 4);
        c.update(req.providerId.data(), req.providerId.size());
        uint8_t dg[16];
        c.final(dg);
        char hex[33];
        md5HexLower(dg, hex);
        std::snprintf(tsdata + tn, sizeof(tsdata) - tn, "%s", hex);
    }
#else
    (void)tn;
#endif

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

    uint32_t ips[8];
    int n = resolveHostIPv4(kConnectHost, ips, 8);
    if (n < 1)
        return false;

    socket_t s = ::socket(AF_INET, SOCK_STREAM, 0);
    if (s == kInvalidSocket)
        return false;

    sockaddr_in to;
    std::memset(&to, 0, sizeof(to));
    to.sin_family = AF_INET;
    to.sin_port = htons(80);
    to.sin_addr.s_addr = ips[0];
    if (::connect(s, reinterpret_cast<sockaddr*>(&to), sizeof(to)) != 0) {
        closeSock(s);
        return false;
    }

    const char* buf = reinterpret_cast<const char*>(req.body.data() + sendOffset);
    size_t sent = 0;
    while (sent < sendLen) {
        int wn = static_cast<int>(::send(s, buf + sent, static_cast<int>(sendLen - sent), 0));
        if (wn <= 0) { closeSock(s); return false; }
        sent += static_cast<size_t>(wn);
    }

    char reply[1024];
    int got = static_cast<int>(::recv(s, reply, static_cast<int>(sizeof(reply) - 1), 0));
    closeSock(s);
    if (got <= 0)
        return false;
    reply[got] = '\0';
    return std::strstr(reply, " 200 OK") != nullptr;
}

void threadMain() {
    std::srand(static_cast<unsigned>(std::time(nullptr)));

    while (!g_stop.load()) {
        Request req;
        bool have = false;
        {
            std::lock_guard<std::mutex> lk(g_lock);
            if (!g_queue.empty()) {
                req = std::move(g_queue.front());
                g_queue.pop_front();
                have = true;
            }
        }

        if (have) {
            if (httpPost(req)) {
                logLine("SNAPSHOT: %lu bytes sent\r\n",
                        static_cast<unsigned long>(req.payloadSize));
            } else if (++req.retries <= 10) {
                logLine("SNAPSHOT: could not send request - requeued\r\n");
                {
                    std::lock_guard<std::mutex> lk(g_lock);
                    g_queue.push_back(std::move(req));
                }
                sleepMs(1000);
            } else {
                logLine("SNAPSHOT: giving up on request after %d retries\r\n", req.retries);
            }
        } else {
            sleepMs(1000);
        }
    }
}

} // namespace

bool queueSnapshot(const Session& session, const uint8_t* data, size_t len) {
    if (!g_thread.running())
        return false;
    Request req;
    packInto(req, session, data, len);
    if (req.body.empty())
        return false;
    std::lock_guard<std::mutex> lk(g_lock);
    g_queue.push_back(std::move(req));
    return true;
}

void startSnapshotWorker() {
    if (g_thread.running())
        return;
    g_stop.store(false);
    netStartup();
    g_thread.start(&threadMain);
}

void stopSnapshotWorker() {
    if (!g_thread.running())
        return;
    g_stop.store(true);
    g_thread.join(3000);
    netCleanup();
}

} // namespace bf2hub
