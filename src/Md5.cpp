// MD5 transform. Standard RFC 1321 algorithm; the only bf2hub-specific twist is the keyed start
// (custom IV + pre-loaded bit count), which the context exposes via init(iv, startBits).

#include "Md5.h"

#include <cstring>

namespace bf2hub {

// Keyed IV for the heartbeat/snapshot MAC. These are the four state words the image preloads
// (sub_10008570/sub_10008680: 0xA51A94BF, 0x07462887, 0xED97A312, 0x23940000-class literals) with
// the bit counter started at 512. Kept as the exact 32-bit values the DLL uses.
const uint32_t kHeartbeatIV[4] = {
    static_cast<uint32_t>(-1524778369), //  A
    static_cast<uint32_t>(122022663),   //  B
    static_cast<uint32_t>(-308288814),  //  C
    static_cast<uint32_t>(596988736),   //  D
};

namespace {

inline uint32_t rol(uint32_t x, int c) { return (x << c) | (x >> (32 - c)); }

inline uint32_t F(uint32_t x, uint32_t y, uint32_t z) { return (x & y) | (~x & z); }
inline uint32_t G(uint32_t x, uint32_t y, uint32_t z) { return (x & z) | (y & ~z); }
inline uint32_t H(uint32_t x, uint32_t y, uint32_t z) { return x ^ y ^ z; }
inline uint32_t I(uint32_t x, uint32_t y, uint32_t z) { return y ^ (x | ~z); }

void transform(uint32_t state[4], const uint8_t block[64]) {
    uint32_t M[16];
    for (int i = 0; i < 16; ++i)
        M[i] = static_cast<uint32_t>(block[i * 4]) |
               (static_cast<uint32_t>(block[i * 4 + 1]) << 8) |
               (static_cast<uint32_t>(block[i * 4 + 2]) << 16) |
               (static_cast<uint32_t>(block[i * 4 + 3]) << 24);

    uint32_t a = state[0], b = state[1], c = state[2], d = state[3];

    auto step = [](uint32_t f, uint32_t& w, uint32_t x, uint32_t m, uint32_t t, int s) {
        w = x + rol(w + f + m + t, s);
    };

    static const int Sf[4] = {7, 12, 17, 22};
    static const int Sg[4] = {5, 9, 14, 20};
    static const int Sh[4] = {4, 11, 16, 23};
    static const int Si[4] = {6, 10, 15, 21};
    static const uint32_t T[64] = {
        0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
        0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
        0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
        0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
        0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
        0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
        0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
        0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391,
    };

    for (int i = 0; i < 16; ++i) {
        uint32_t f = F(b, c, d);
        step(f, a, b, M[i], T[i], Sf[i & 3]);
        uint32_t t = d; d = c; c = b; b = a; a = t;
    }
    for (int i = 0; i < 16; ++i) {
        uint32_t g = (1 + 5 * i) & 15;
        uint32_t f = G(b, c, d);
        step(f, a, b, M[g], T[16 + i], Sg[i & 3]);
        uint32_t t = d; d = c; c = b; b = a; a = t;
    }
    for (int i = 0; i < 16; ++i) {
        uint32_t g = (5 + 3 * i) & 15;
        uint32_t f = H(b, c, d);
        step(f, a, b, M[g], T[32 + i], Sh[i & 3]);
        uint32_t t = d; d = c; c = b; b = a; a = t;
    }
    for (int i = 0; i < 16; ++i) {
        uint32_t g = (7 * i) & 15;
        uint32_t f = I(b, c, d);
        step(f, a, b, M[g], T[48 + i], Si[i & 3]);
        uint32_t t = d; d = c; c = b; b = a; a = t;
    }

    state[0] += a; state[1] += b; state[2] += c; state[3] += d;
}

} // namespace

void Md5::init() {
    static const uint32_t classic[4] = {0x67452301u, 0xefcdab89u, 0x98badcfeu, 0x10325476u};
    init(classic, 0);
}

void Md5::init(const uint32_t iv[4], uint32_t startBits) {
    count[0] = startBits;
    count[1] = 0;
    state[0] = iv[0]; state[1] = iv[1]; state[2] = iv[2]; state[3] = iv[3];
    std::memset(buffer, 0, sizeof(buffer));
}

void Md5::update(const void* data, size_t len) {
    const uint8_t* p = static_cast<const uint8_t*>(data);
    uint32_t index = (count[0] >> 3) & 0x3f;
    uint32_t bits = static_cast<uint32_t>(len << 3);
    count[0] += bits;
    if (count[0] < bits)
        ++count[1];
    count[1] += static_cast<uint32_t>(len >> 29);

    size_t part = 64 - index;
    size_t i = 0;
    if (len >= part) {
        std::memcpy(buffer + index, p, part);
        transform(state, buffer);
        for (i = part; i + 63 < len; i += 64)
            transform(state, p + i);
        index = 0;
    }
    std::memcpy(buffer + index, p + i, len - i);
}

void Md5::final(uint8_t digest[16]) {
    uint8_t lengthBytes[8];
    for (int i = 0; i < 8; ++i)
        lengthBytes[i] = static_cast<uint8_t>((count[i < 4 ? 0 : 1] >> (8 * (i & 3))) & 0xff);

    uint32_t index = (count[0] >> 3) & 0x3f;
    size_t padLen = (index < 56) ? (56 - index) : (120 - index);

    static const uint8_t pad[64] = {0x80};
    update(pad, padLen);
    update(lengthBytes, 8);

    for (int i = 0; i < 4; ++i) {
        digest[i * 4]     = static_cast<uint8_t>(state[i] & 0xff);
        digest[i * 4 + 1] = static_cast<uint8_t>((state[i] >> 8) & 0xff);
        digest[i * 4 + 2] = static_cast<uint8_t>((state[i] >> 16) & 0xff);
        digest[i * 4 + 3] = static_cast<uint8_t>((state[i] >> 24) & 0xff);
    }
}

void md5(const void* data, size_t len, uint8_t digest[16]) {
    Md5 ctx;
    ctx.init();
    ctx.update(data, len);
    ctx.final(digest);
}

void md5HexLower(const uint8_t digest[16], char out[33]) {
    static const char lut[] = "0123456789abcdef";
    for (int i = 0; i < 16; ++i) {
        out[i * 2]     = lut[digest[i] >> 4];
        out[i * 2 + 1] = lut[digest[i] & 0xf];
    }
    out[32] = '\0';
}

} // namespace bf2hub
