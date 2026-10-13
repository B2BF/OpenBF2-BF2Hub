#include "HostImage.h"

#include "Config.h"
#include "Md5.h"
#include "Platform.h"

#if defined(_WIN32)
#  include <windows.h>
#endif

#include <cctype>
#include <cstdio>
#include <cstring>
#include <vector>

namespace bf2hub {

// Embedded fingerprint of the BF2Hub-patched retail bf2_w32ded.exe, measured from the operator's
// known-good copy (see HostImage.h). The Windows build reports this by default so no reference exe is
// needed on disk. The Linux heartbeat does not send an exe fingerprint at all (it uses a fixed key),
// so this is Windows-relevant; it is kept here for the shared Fingerprint type.
const Fingerprint kEmbeddedFingerprint = {
    46,
    0x00905A4Du,   // "MZ\x90\0"
    4980736u,      // file size
    3678208u,      // .text SizeOfRawData
    { 0x3c, 0xa1, 0x27, 0xb1, 0xbe, 0x42, 0x75, 0x19,
      0x6a, 0xf9, 0x33, 0x47, 0x71, 0x47, 0x07, 0xf9 },  // whole-file MD5
    { 0x07, 0xfe, 0x4d, 0x04, 0xe3, 0x46, 0xe9, 0xee,
      0x08, 0x58, 0x75, 0xcd, 0x4c, 0x66, 0x86, 0xbe },  // .text MD5
};

#if !defined(_WIN32)
// Whole-file MD5 of the genuine retail Linux `bf2` executable. The Linux auth token (sub_5433)
// folds this into MAC #4; OpenBF2's own binary hashes differently, so without the retail value the
// backend rejects the token. Measure it with tools/bf2_exe_md5.py on a genuine retail `bf2` and fill
// it in here (set kLinuxExeMd5Known = true), or point the `referenceExe` config key at a copy of the
// retail bf2. Until then the module falls back to hashing the running binary, which will not match.
// Measured from the genuine retail Linux `bf2` (md5 416f65cd9987f41d519c281a033e0b3f) with
// tools/bf2_exe_md5.py. Default for Linux so operators need no reference exe on disk; overridable
// with the referenceExe config key.
const bool    kLinuxExeMd5Known = true;
const uint8_t kLinuxExeMd5[16] = {
    0x41, 0x6f, 0x65, 0xcd, 0x99, 0x87, 0xf4, 0x1d,
    0x51, 0x9c, 0x28, 0x1a, 0x03, 0x3e, 0x0b, 0x3f,
};
#endif

namespace {

#if defined(_WIN32)
std::string toLower(std::string s) {
    for (char& c : s)
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return s;
}
#endif

// Stream a whole file through classic MD5. Returns total byte count (0 on open failure) and, via
// firstDword, the first four bytes of the file.
bool md5File(const char* path, uint8_t digest[16], uint32_t& fileSize, uint32_t& firstDword) {
    std::FILE* f = nullptr;
#if defined(_MSC_VER)
    ::fopen_s(&f, path, "rb");
#else
    f = std::fopen(path, "rb");
#endif
    if (!f)
        return false;

    Md5 ctx;
    ctx.init();
    firstDword = 0;
    fileSize = 0;
    std::vector<uint8_t> buf(8000); // 0x1F40, the retail chunk size
    bool gotFirst = false;
    for (;;) {
        size_t n = std::fread(buf.data(), 1, buf.size(), f);
        if (n == 0)
            break;
        if (!gotFirst) {
            std::memcpy(&firstDword, buf.data(), n >= 4 ? 4 : n);
            gotFirst = true;
        }
        ctx.update(buf.data(), n);
        fileSize += static_cast<uint32_t>(n);
    }
    std::fclose(f);
    ctx.final(digest);
    return true;
}

#if defined(_WIN32)

// Parse the PE at `path` and return the .text section's raw size and file offset. Mirrors
// sub_10002210: DOS header -> e_lfanew -> PE signature -> section table -> first ".text". PE-only,
// so Windows-only; the Linux build uses the embedded fingerprint and never measures a PE.
bool findTextSection(const char* path, uint32_t& rawSize, uint32_t& rawPtr) {
    std::FILE* f = nullptr;
    ::fopen_s(&f, path, "rb");
    if (!f)
        return false;
    struct Closer { std::FILE* f; ~Closer() { if (f) std::fclose(f); } } closer{f};

    IMAGE_DOS_HEADER dos{};
    if (std::fread(&dos, sizeof(dos), 1, f) != 1 || dos.e_magic != IMAGE_DOS_SIGNATURE)
        return false;
    if (std::fseek(f, dos.e_lfanew, SEEK_SET) != 0)
        return false;

    DWORD signature = 0;
    IMAGE_FILE_HEADER fileHeader{};
    if (std::fread(&signature, sizeof(signature), 1, f) != 1 || signature != IMAGE_NT_SIGNATURE)
        return false;
    if (std::fread(&fileHeader, sizeof(fileHeader), 1, f) != 1)
        return false;

    long sectionTable = dos.e_lfanew + 4 + static_cast<long>(sizeof(IMAGE_FILE_HEADER)) +
                        fileHeader.SizeOfOptionalHeader;
    if (std::fseek(f, sectionTable, SEEK_SET) != 0)
        return false;

    for (unsigned i = 0; i < fileHeader.NumberOfSections; ++i) {
        IMAGE_SECTION_HEADER sh{};
        if (std::fread(&sh, sizeof(sh), 1, f) != 1)
            return false;
        if (std::memcmp(sh.Name, ".text\0", 6) == 0) {
            rawSize = sh.SizeOfRawData;
            rawPtr = sh.PointerToRawData;
            return true;
        }
    }
    return false;
}

bool md5FileRegion(const char* path, uint32_t offset, uint32_t size, uint8_t digest[16]) {
    std::FILE* f = nullptr;
    ::fopen_s(&f, path, "rb");
    if (!f)
        return false;
    struct Closer { std::FILE* f; ~Closer() { if (f) std::fclose(f); } } closer{f};

    if (std::fseek(f, static_cast<long>(offset), SEEK_SET) != 0)
        return false;

    Md5 ctx;
    ctx.init();
    uint32_t remaining = size;
    std::vector<uint8_t> buf(8000);
    while (remaining > 0) {
        size_t want = remaining < buf.size() ? remaining : buf.size();
        size_t n = std::fread(buf.data(), 1, want, f);
        if (n == 0)
            break;
        ctx.update(buf.data(), n);
        remaining -= static_cast<uint32_t>(n);
    }
    ctx.final(digest);
    return remaining == 0;
}

std::string resolveReferenceExe(const Config& config) {
    std::string ref = config.get(kReferenceExeKey);
    if (!ref.empty())
        return ref;
    return "bf2_w32ded.exe";
}

#endif // _WIN32

} // namespace

bool hostIsDedicated() {
#if defined(_WIN32)
    std::string name = toLower(hostExePath());
    return name.find("w32ded") != std::string::npos ||
           name.find("w64ded") != std::string::npos;
#else
    // The Linux port only targets the dedicated server (`bf2`); OpenBF2 has no Linux client image,
    // and the module is loaded into the server via openbf2.addModDll. Treat as dedicated.
    return true;
#endif
}

std::string runningExeMd5Hex() {
    uint8_t digest[16];
    uint32_t size = 0, first = 0;
    if (!md5File(hostExePath().c_str(), digest, size, first))
        return std::string();
    char hex[33];
    md5HexLower(digest, hex);
    return std::string(hex);
}

bool referenceExeWholeMd5(const Config& config, uint8_t out[16]) {
#if defined(_WIN32)
    // Default: the embedded fingerprint's whole-file MD5 (no reference exe needed).
    if (config.get(kReferenceExeKey).empty()) {
        std::memcpy(out, kEmbeddedFingerprint.wholeMd5, 16);
        return true;
    }
    static bool cached = false;
    static uint8_t cachedDigest[16];
    if (cached) {
        std::memcpy(out, cachedDigest, 16);
        return true;
    }
    uint8_t digest[16];
    uint32_t size = 0, first = 0;
    if (!md5File(resolveReferenceExe(config).c_str(), digest, size, first))
        return false;
    std::memcpy(cachedDigest, digest, 16);
    cached = true;
    std::memcpy(out, digest, 16);
    return true;
#else
    // The Linux auth token folds md5(the bf2 executable) into MAC #4. Priority:
    //   1. referenceExe config override - md5 a copy of the genuine retail bf2 on disk;
    //   2. the embedded retail hash (kLinuxExeMd5) once measured;
    //   3. fallback: the running binary (/proc/self/exe) - will NOT match the backend.
    static bool cached = false;
    static uint8_t cachedDigest[16];
    if (cached) {
        std::memcpy(out, cachedDigest, 16);
        return true;
    }
    uint8_t digest[16];
    uint32_t size = 0, first = 0;
    const std::string ref = config.get(kReferenceExeKey);
    if (!ref.empty()) {
        if (!md5File(ref.c_str(), digest, size, first))
            return false;
    } else if (kLinuxExeMd5Known) {
        std::memcpy(digest, kLinuxExeMd5, 16);
    } else {
        if (!md5File(hostExePath().c_str(), digest, size, first))
            return false;
    }
    std::memcpy(cachedDigest, digest, 16);
    cached = true;
    std::memcpy(out, digest, 16);
    return true;
#endif
}

bool buildFingerprint(const Config& config, Fingerprint& out) {
#if defined(_WIN32)
    // Default: the embedded patched-retail fingerprint, so operators need no reference exe.
    if (config.get(kReferenceExeKey).empty()) {
        out = kEmbeddedFingerprint;
        return true;
    }

    std::memset(&out, 0, sizeof(out));
    out.len = 46;

    const std::string path = resolveReferenceExe(config);

    uint8_t wholeDigest[16];
    uint32_t fileSize = 0, firstDword = 0;
    if (!md5File(path.c_str(), wholeDigest, fileSize, firstDword))
        return false;

    uint32_t textSize = 0, textPtr = 0;
    if (!findTextSection(path.c_str(), textSize, textPtr))
        return false;

    uint8_t textDigest[16];
    if (!md5FileRegion(path.c_str(), textPtr, textSize, textDigest))
        return false;

    out.fileMagic = firstDword;
    out.fileSize = fileSize;
    out.textSize = textSize;
    std::memcpy(out.wholeMd5, wholeDigest, 16);
    std::memcpy(out.textMd5, textDigest, 16);
    return true;
#else
    // The Linux heartbeat uses a fixed key, not an exe fingerprint, so the blob is never sent on
    // Linux; return the embedded constant for any shared caller.
    (void)config;
    out = kEmbeddedFingerprint;
    return true;
#endif
}

} // namespace bf2hub
