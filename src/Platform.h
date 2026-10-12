// Cross-platform shims shared by the Windows DLL and the Linux .so builds. The engine logic (MD5,
// session, MACs, snapshot packing, Python methods) is identical on both platforms; only the OS
// surface differs - sockets, threads, the executable path, and directory creation. This header
// hides that difference so the logic files stay platform-neutral.

#ifndef BF2HUB_PLATFORM_H
#define BF2HUB_PLATFORM_H

#include <cstdint>
#include <string>

#if defined(_WIN32)
#  define WIN32_LEAN_AND_MEAN
#  define NOMINMAX
#  include <winsock2.h>
#  include <ws2tcpip.h>
#  include <windows.h>
#else
#  include <arpa/inet.h>
#  include <netdb.h>
#  include <netinet/in.h>
#  include <pthread.h>
#  include <sys/socket.h>
#  include <sys/stat.h>
#  include <sys/types.h>
#  include <unistd.h>
#endif

namespace bf2hub {

#if defined(_WIN32)
using socket_t = SOCKET;
constexpr socket_t kInvalidSocket = INVALID_SOCKET;
inline void closeSock(socket_t s) { ::closesocket(s); }
inline void netStartup() { WSADATA w; ::WSAStartup(MAKEWORD(2, 2), &w); }
inline void netCleanup() { ::WSACleanup(); }
inline void sleepMs(unsigned ms) { ::Sleep(ms); }
inline void makeDir(const char* p) { ::CreateDirectoryA(p, nullptr); }
#else
using socket_t = int;
constexpr socket_t kInvalidSocket = -1;
inline void closeSock(socket_t s) { ::close(s); }
inline void netStartup() {}
inline void netCleanup() {}
inline void sleepMs(unsigned ms) { ::usleep(ms * 1000u); }
inline void makeDir(const char* p) { ::mkdir(p, 0755); }
#endif

// Absolute path of the running executable (GetModuleFileNameA / readlink("/proc/self/exe")).
std::string hostExePath();

// Resolve an IPv4 host to up to `max` addresses (network byte order). Returns the count. Uses
// getaddrinfo on both platforms; the resolved address is identical regardless of the resolver the
// retail binary happened to use.
int resolveHostIPv4(const char* host, uint32_t* out, int max);

// A worker thread with a cooperative stop flag, joined with a timeout on shutdown.
class Thread {
public:
    using Fn = void (*)();
    bool start(Fn fn);
    void join(unsigned timeoutMs);
    bool running() const { return started_; }

private:
    bool started_ = false;
#if defined(_WIN32)
    void* handle_ = nullptr;
#else
    pthread_t handle_ {};
#endif
};

} // namespace bf2hub

#endif // BF2HUB_PLATFORM_H
