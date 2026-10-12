// Lightweight logger, shared by both builds. Writes to logs/bf2hub/<date>.log (the retail path on
// both platforms) plus a [FRONTIER] channel to stderr. The retail DLL/so also emit a UDP debug
// packet; that is part of the networking we intentionally skip. Header-only to keep the build graph
// small.

#ifndef BF2HUB_LOG_H
#define BF2HUB_LOG_H

#include "Platform.h"

#include <cstdarg>
#include <cstdio>
#include <ctime>

namespace bf2hub {

inline void logLine(const char* fmt, ...) {
    makeDir("logs");
    makeDir("logs/bf2hub");

    std::time_t now = std::time(nullptr);
    std::tm tmv;
#if defined(_WIN32)
    ::localtime_s(&tmv, &now);
    unsigned long pid = static_cast<unsigned long>(::GetCurrentProcessId());
#else
    ::localtime_r(&now, &tmv);
    unsigned long pid = static_cast<unsigned long>(::getpid());
#endif

    char name[64];
    std::snprintf(name, sizeof(name), "logs/bf2hub/%04d-%02d-%02d.log",
                  tmv.tm_year + 1900, tmv.tm_mon + 1, tmv.tm_mday);

    std::FILE* f = nullptr;
#if defined(_MSC_VER)
    ::fopen_s(&f, name, "ab");
#else
    f = std::fopen(name, "ab");
#endif
    if (!f)
        return;
    std::fprintf(f, "(%lu) %02d:%02d:%02d > ", pid, tmv.tm_hour, tmv.tm_min, tmv.tm_sec);
    va_list ap;
    va_start(ap, fmt);
    std::vfprintf(f, fmt, ap);
    va_end(ap);
    std::fclose(f);
}

inline void frontier(const char* qualifiedName) {
    std::fprintf(stderr, "[FRONTIER] bf2hub::%s reached (behaviour not yet reconstructed)\n", qualifiedName);
    std::fflush(stderr);
    logLine("[FRONTIER] %s reached\r\n", qualifiedName);
}

} // namespace bf2hub

#endif // BF2HUB_LOG_H
