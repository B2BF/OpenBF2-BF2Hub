// MD5, as the shipped bf2hub.dll uses it. The DLL ships its own MD5 (the classic IV
// 0x67452301/0xEFCDAB89/0x98BADCFE/0x10325476 and the 64-entry sine table are visible in the
// image), and it also uses a *keyed* variant for the heartbeat/snapshot MAC: a non-standard IV plus
// a bit-counter pre-loaded to 512, i.e. a secret 64-byte prefix block treated as already absorbed.
// Both are the same transform, so we expose one context that takes the IV and the starting bit
// count. This is a wire-format contract with the BF2Hub backend; the digests must match byte for
// byte.

#ifndef BF2HUB_MD5_H
#define BF2HUB_MD5_H

#include <cstddef>
#include <cstdint>

namespace bf2hub {

struct Md5 {
    uint32_t count[2];   // message length in bits, {low, high}
    uint32_t state[4];   // A, B, C, D
    uint8_t  buffer[64];

    // Standard MD5 start (classic IV, zero length).
    void init();

    // Keyed start: custom IV and a pre-loaded bit count. The heartbeat MAC uses
    // init(kHeartbeatIV, 512).
    void init(const uint32_t iv[4], uint32_t startBits);

    void update(const void* data, size_t len);
    void final(uint8_t digest[16]);
};

// The keyed IV used by the heartbeat/snapshot MAC (sub_10008570 / sub_10008680). Paired with a
// starting bit count of 512.
extern const uint32_t kHeartbeatIV[4];
constexpr uint32_t kHeartbeatStartBits = 512;

// One-shot standard MD5.
void md5(const void* data, size_t len, uint8_t digest[16]);

// Lowercase hex of a 16-byte digest into out[0..31], NUL at out[32] (matches sub_100041C0).
void md5HexLower(const uint8_t digest[16], char out[33]);

} // namespace bf2hub

#endif // BF2HUB_MD5_H
