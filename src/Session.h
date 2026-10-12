// The BF2Hub session block. In the shipped DLL this is the 0x1BC (444) byte heap allocation at
// dword_1001FCFC, built in gpaInit (sub_100076D0) and consumed by the Python methods and the
// heartbeat/snapshot code. Its field offsets are a wire contract: the per-request MACs feed these
// fields into MD5 in a fixed order, so the layout must match the retail block byte for byte on both
// x86 and x64. We model it as a packed struct with the offsets recovered from the image and assert
// the size.
//
// Offsets below are the dword/word indices seen in the decompilation:
//   +48  (0x30)  16-byte per-request challenge nonce (gpaGetString/glsCheck fill it with random)
//   +64  (0x40)  provider id string (python/bf2/.../bf2hubProviderID.sec, whitespace-stripped)
//   +364 (0x16C) mod directory (host.sgl_getModDirectory), <=28 bytes, NUL at +391
//   +392 (0x188) session time, decimal string ("%u")
//   +412 (0x19C) server port        (low word of the dword)
//   +416 (0x1A0) gamespy/query port (low word of the dword)
//   +420 (0x1A4) server IP   (inet_addr of sv.serverIP)
//   +424 (0x1A8) interface IP(inet_addr of sv.interfaceIP)
//   +428 (0x1AC) rank flag   (glsGetFlags result; set by gpaProcessResponse)
//   +432 (0x1B0) auth word A (snapshot token material)
//   +436 (0x1B4) auth word B
//   +440 (0x1B8) session time (unix seconds)

#ifndef BF2HUB_SESSION_H
#define BF2HUB_SESSION_H

#include <cstdint>

namespace bf2hub {

#pragma pack(push, 1)
struct Session {
    uint8_t  reserved0[48];     // +0
    uint8_t  challenge[16];     // +48  per-request nonce
    char     providerId[300];   // +64  (abuts modDir at +364)
    char     modDir[28];        // +364
    char     timeStr[20];       // +392
    uint32_t serverPort;        // +412 (low word used)
    uint32_t queryPort;         // +416 (low word used)
    uint32_t serverIp;          // +420
    uint32_t interfaceIp;       // +424
    uint32_t rankFlag;          // +428
    uint32_t authA;             // +432
    uint32_t authB;             // +436
    uint32_t sessionTime;       // +440
};
#pragma pack(pop)

static_assert(sizeof(Session) == 0x1BC, "Session must stay the retail 444-byte wire layout");
static_assert(offsetof(Session, challenge) == 48, "challenge nonce offset");
static_assert(offsetof(Session, providerId) == 64, "provider id offset");
static_assert(offsetof(Session, modDir) == 364, "mod dir offset");
static_assert(offsetof(Session, serverPort) == 412, "server port offset");
static_assert(offsetof(Session, sessionTime) == 440, "session time offset");

} // namespace bf2hub

#endif // BF2HUB_SESSION_H
