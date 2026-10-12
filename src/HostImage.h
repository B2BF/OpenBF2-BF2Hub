// Host-image identity. The shipped DLL does two things here that we must reproduce:
//
//   1. Mode detection (sub_10001730): decide dedicated-server vs client by looking for "w32ded" in
//      the running exe name. We extend the test to "w64ded" too, because OpenBF2's x64 dedicated
//      exe is bf2_w64ded.exe and the retail substring test would otherwise misclassify it as a
//      client. [CHOSEN, not recovered] - a compatibility fix, not retail behaviour.
//
//   2. Executable fingerprint (sub_10002380 + sub_10002210): a 46-byte blob - {u16 len=46,
//      u32 file-magic, u32 file-size, u32 .text-size, md5(whole file), md5(.text raw bytes)} - that
//      the heartbeat/snapshot embeds so the backend knows which server build is talking. OpenBF2's
//      exe is not the retail one, so to be accepted as a normal 1.50 server we fingerprint a
//      REFERENCE copy of the genuine retail bf2_w32ded.exe (config key referenceExe, else
//      "bf2_w32ded.exe" in the working directory) instead of the running module. [CHOSEN]
//
// The fingerprint reconstruction is byte-exact against the recovered layout but has not yet been
// validated against a live backend capture. [FRONTIER] see README "Validation".

#ifndef BF2HUB_HOSTIMAGE_H
#define BF2HUB_HOSTIMAGE_H

#include <cstdint>
#include <string>

namespace bf2hub {

class Config;

#pragma pack(push, 1)
struct Fingerprint {
    uint16_t len;          // always 46 (0x2E)
    uint32_t fileMagic;    // first 4 bytes of the exe ("MZ\x90\0")
    uint32_t fileSize;     // total file size
    uint32_t textSize;     // SizeOfRawData of the .text section
    uint8_t  wholeMd5[16]; // md5 of the whole file
    uint8_t  textMd5[16];  // md5 of the .text raw bytes
};
#pragma pack(pop)
static_assert(sizeof(Fingerprint) == 46, "exe fingerprint blob must be 46 bytes");

// The embedded default fingerprint: the BF2Hub-patched retail bf2_w32ded.exe (file size 4,980,736;
// whole-file MD5 3ca127b1be4275196af93347714707f9). Operators need no reference exe on disk - the
// module reports this by default so the backend accepts the server as a normal 1.50 build. The
// referenceExe config key overrides it (e.g. to re-measure a different patched exe).
extern const Fingerprint kEmbeddedFingerprint;

// True if the running image is a dedicated server (name contains w32ded/w64ded).
bool hostIsDedicated();

// Lowercase md5 (32 hex chars) of the whole running exe file - used by the retail code as a cache
// filename suffix (sub_10008FD0 "network_%d_%s"). Returns empty on failure.
std::string runningExeMd5Hex();

// Populate the fingerprint blob. With no referenceExe override set, this is the embedded default
// (always succeeds). With referenceExe set, it is measured from that file and returns false if the
// file cannot be read or parsed.
bool buildFingerprint(const Config& config, Fingerprint& out);

// Whole-file MD5 of the reference exe (the spoof source gpaGetString folds into its auth token,
// where the retail code uses the running exe's). Defaults to the embedded fingerprint's whole-file
// MD5; measured from referenceExe when that override is set (cached). Returns false only if an
// explicit referenceExe cannot be read.
bool referenceExeWholeMd5(const Config& config, uint8_t out[16]);

} // namespace bf2hub

#endif // BF2HUB_HOSTIMAGE_H
