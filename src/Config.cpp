#include "Config.h"

#include <cstdio>

namespace bf2hub {

const char* const kReferenceExeKey = "referenceExe";

namespace {

std::string trim(const std::string& s) {
    const char* ws = " \t\r\n";
    const auto b = s.find_first_not_of(ws);
    if (b == std::string::npos)
        return std::string();
    const auto e = s.find_last_not_of(ws);
    return s.substr(b, e - b + 1);
}

} // namespace

void Config::load() {
    std::FILE* f = nullptr;
#if defined(_MSC_VER)
    ::fopen_s(&f, "bf2hub.cfg", "r");
#else
    f = std::fopen("bf2hub.cfg", "r");
#endif
    if (!f)
        return;

    char line[1000];
    while (std::fgets(line, sizeof(line), f)) {
        std::string s = trim(line);
        if (s.empty() || s[0] == '#')
            continue;
        const auto eq = s.find('=');
        if (eq == std::string::npos)
            continue;
        std::string key = trim(s.substr(0, eq));
        std::string value = trim(s.substr(eq + 1));
        if (!key.empty())
            values_[key] = value;
    }
    std::fclose(f);
}

std::string Config::get(const std::string& key, const std::string& fallback) const {
    const auto it = values_.find(key);
    return it == values_.end() ? fallback : it->second;
}

bool Config::has(const std::string& key) const {
    return values_.find(key) != values_.end();
}

} // namespace bf2hub
