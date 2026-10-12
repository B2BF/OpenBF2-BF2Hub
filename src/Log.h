// Lightweight logger. The shipped DLL logs to logs/bf2hub/<date>.log and also squirts a UDP debug
// packet (sub_10001BA0); the UDP side is part of the networking we intentionally skip, so we keep
// just the file log plus a [FRONTIER] channel to stderr. Header-only to keep the build graph small.

#ifndef BF2HUB_LOG_H
#define BF2HUB_LOG_H

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#include <cstdarg>
#include <cstdio>

namespace bf2hub {

inline void logLine(const char* fmt, ...) {
    ::CreateDirectoryA("logs", nullptr);
    ::CreateDirectoryA("logs\\bf2hub", nullptr);

    SYSTEMTIME st;
    ::GetLocalTime(&st);
    char name[64];
    std::snprintf(name, sizeof(name), "logs\\bf2hub\\%04d-%02d-%02d.log", st.wYear, st.wMonth, st.wDay);

    std::FILE* f = nullptr;
#if defined(_MSC_VER)
    ::fopen_s(&f, name, "ab");
#else
    f = std::fopen(name, "ab");
#endif
    if (!f)
        return;
    std::fprintf(f, "(%lu) %02d:%02d:%02d > ", ::GetCurrentProcessId(), st.wHour, st.wMinute, st.wSecond);
    va_list ap;
    va_start(ap, fmt);
    std::vfprintf(f, fmt, ap);
    va_end(ap);
    std::fclose(f);
}

// Reports an unrecovered boundary. Names itself fully, to both the log and stderr, and is not a
// fabricated success - callers return a benign value (None/false), never a faked OK.
inline void frontier(const char* qualifiedName) {
    std::fprintf(stderr, "[FRONTIER] bf2hub::%s reached (behaviour not yet reconstructed)\n", qualifiedName);
    std::fflush(stderr);
    logLine("[FRONTIER] %s reached\r\n", qualifiedName);
}

} // namespace bf2hub

#endif // BF2HUB_LOG_H
