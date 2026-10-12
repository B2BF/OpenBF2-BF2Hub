// bf2hub.cfg parsing. The shipped DLL reads "bf2hub.cfg" (and a per-exe "bf2hub_<exe>.cfg"), one
// `key = value` per line, '#' comments (sub_100020E0 / sub_10001EF0). Most of the retail keys
// (bf2web, gsqr_mstr, gsqr_key) steer the ws2_32 proxy's DNS/master redirection, which we do not
// reproduce, so we parse the file generically and expose get(). One key is our own addition,
// documented below.

#ifndef BF2HUB_CONFIG_H
#define BF2HUB_CONFIG_H

#include <map>
#include <string>

namespace bf2hub {

class Config {
public:
    // Loads bf2hub.cfg from the process working directory (the server's game folder), if present.
    // Missing file is not an error.
    void load();

    // Returns the trimmed value for key, or the supplied default if absent.
    std::string get(const std::string& key, const std::string& fallback = std::string()) const;

    bool has(const std::string& key) const;

private:
    std::map<std::string, std::string> values_;
};

// [CHOSEN, not recovered] Optional config key. By default the module reports an embedded fingerprint
// of the BF2Hub-patched retail bf2_w32ded.exe (HostImage::kEmbeddedFingerprint), so operators need
// nothing on disk. Set this only to re-measure a different patched exe:
//
//     referenceExe = C:\path\to\patched\bf2_w32ded.exe
extern const char* const kReferenceExeKey;

} // namespace bf2hub

#endif // BF2HUB_CONFIG_H
