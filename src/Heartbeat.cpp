#include "Heartbeat.h"

#include "Config.h"
#include "HostImage.h"
#include "Log.h"
#include "Md5.h"
#include "Platform.h"

#include <atomic>
#include <cstdlib>
#include <cstring>
#include <ctime>

namespace bf2hub {
namespace {

// Shared across both builds.
const uint16_t kHelloPort   = 29960;        // htons(0x7508)
const char*    kServersHost = "servers.bf2hub.com";
const uint32_t kHelloMagic  = 1367436204u;
const int      kIntervalSec = 60;           // dedicated cadence
const int      kMaxServers  = 16;

#if defined(_WIN32)
// Windows bf2hub.dll protocol: "HHHL3Q" + {rand8, time, magic, exe-fingerprint(46)} + keyed MAC.
const char kHelloTag[6] = {'H', 'H', 'H', 'L', '3', 'Q'};
#else
// Linux libbf2hub.so protocol: "HHHL2Q" + a packet built from a 16-byte nonce and a fixed 32-byte
// key (ELF has no PE fingerprint). [FRONTIER] the exact field order inside the payload is
// reconstructed from sub_721D, whose decompiled signature is ambiguous; needs a wire capture to
// confirm. The tag, port (29960), magic (1367436204), host (servers.bf2hub.com) and the key are
// certain.
const char    kHelloTag[6]  = {'H', 'H', 'H', 'L', '2', 'Q'};
const char    kLinuxKey[32] = {'j','z','i','v','B','o','3','F','I','&','A','3','#','L','$','2',
                               'P','p','S','1','m','i','#','u','$','0','G','y','h','q','C','.'};
#endif

Config*          g_config = nullptr;
Thread           g_thread;
std::atomic<bool> g_stop{false};

uint8_t randByteNonzero() {
    int r = std::rand();
    return static_cast<uint8_t>(r >= 1 ? r : 1);
}

#if defined(_WIN32)

// Windows payload (sub_10008570), after the 6-byte tag. Returns the payload length (78).
int buildHelloPayload(const Fingerprint& fp, uint8_t* p) {
    for (int i = 0; i < 8; ++i)
        p[i] = randByteNonzero();
    uint32_t now = static_cast<uint32_t>(std::time(nullptr));
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

int buildHelloPacket(uint8_t* packet, int cap) {
    Fingerprint fp;
    if (!g_config || !buildFingerprint(*g_config, fp))
        return 0;
    if (cap < 6 + 78)
        return 0;
    std::memcpy(packet, kHelloTag, 6);
    int payload = buildHelloPayload(fp, packet + 6);
    return payload > 0 ? 6 + payload : 0;
}

#else

// Linux payload (sub_721D): 16-byte nonce, an obfuscated {time, magic} block, and an 8-byte MD5 MAC
// over {fixed key, nonce, time, magic}. [FRONTIER] field order pending wire validation.
int buildHelloPacket(uint8_t* packet, int cap) {
    if (cap < 6 + 32)
        return 0;
    std::memcpy(packet, kHelloTag, 6);
    uint8_t* p = packet + 6;

    uint8_t nonce[16];
    for (int i = 0; i < 16; ++i)
        nonce[i] = randByteNonzero();
    std::memcpy(p, nonce, 16);

    uint32_t now = static_cast<uint32_t>(std::time(nullptr));
    std::memcpy(p + 16, &now, 4);
    std::memcpy(p + 20, &kHelloMagic, 4);
    for (int i = 0; i < 8; ++i)
        p[16 + i] ^= nonce[i];

    Md5 ctx;
    ctx.init();
    ctx.update(kLinuxKey, 32);
    ctx.update(nonce, 16);
    ctx.update(&now, 4);
    ctx.update(&kHelloMagic, 4);
    uint8_t digest[16];
    ctx.final(digest);
    std::memcpy(p + 24, digest, 8);

    return 6 + 32;
}

#endif

void sendHello() {
    uint32_t servers[kMaxServers];
    int count = resolveHostIPv4(kServersHost, servers, kMaxServers);
    if (count < 1) {
        logLine("HELLO: could not resolve %s\r\n", kServersHost);
        return;
    }

    socket_t s = ::socket(AF_INET, SOCK_DGRAM, 0);
    if (s == kInvalidSocket)
        return;

    uint8_t packet[128];
    int packetLen = buildHelloPacket(packet, sizeof(packet));
    if (packetLen <= 0) {
        closeSock(s);
        return;
    }

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
    closeSock(s);
}

void threadMain() {
    std::srand(static_cast<unsigned>(std::time(nullptr)));
    while (!g_stop.load()) {
        sendHello();
        for (int slept = 0; slept < kIntervalSec * 10 && !g_stop.load(); ++slept)
            sleepMs(100);
    }
}

} // namespace

void startHeartbeat(Config* config) {
    if (g_thread.running())
        return;
    g_config = config;
    g_stop.store(false);
    netStartup();
    if (!g_thread.start(&threadMain))
        logLine("HELLO: could not start heartbeat thread\r\n");
}

void stopHeartbeat() {
    if (!g_thread.running())
        return;
    g_stop.store(true);
    g_thread.join(3000);
    netCleanup();
}

} // namespace bf2hub
