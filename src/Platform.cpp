#include "Platform.h"

#include <cstring>

namespace bf2hub {

std::string hostExePath() {
#if defined(_WIN32)
    char path[MAX_PATH];
    path[0] = '\0';
    ::GetModuleFileNameA(nullptr, path, sizeof(path));
    path[sizeof(path) - 1] = '\0';
    return std::string(path);
#else
    char path[4096];
    ssize_t n = ::readlink("/proc/self/exe", path, sizeof(path) - 1);
    if (n < 0)
        return std::string();
    path[n] = '\0';
    return std::string(path);
#endif
}

int resolveHostIPv4(const char* host, uint32_t* out, int max) {
    addrinfo hints;
    std::memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;

    addrinfo* res = nullptr;
    if (::getaddrinfo(host, "80", &hints, &res) != 0)
        return 0;

    int n = 0;
    for (addrinfo* ai = res; ai && n < max; ai = ai->ai_next) {
        if (ai->ai_family == AF_INET) {
            auto sa = reinterpret_cast<sockaddr_in*>(ai->ai_addr);
            out[n++] = sa->sin_addr.s_addr;
        }
    }
    ::freeaddrinfo(res);
    return n;
}

#if defined(_WIN32)

bool Thread::start(Fn fn) {
    handle_ = ::CreateThread(nullptr, 0,
        reinterpret_cast<LPTHREAD_START_ROUTINE>(reinterpret_cast<void*>(fn)), nullptr, 0, nullptr);
    started_ = handle_ != nullptr;
    return started_;
}

void Thread::join(unsigned timeoutMs) {
    if (!started_)
        return;
    ::WaitForSingleObject(handle_, timeoutMs);
    ::CloseHandle(handle_);
    handle_ = nullptr;
    started_ = false;
}

#else

bool Thread::start(Fn fn) {
    using Trampoline = void* (*)(void*);
    Trampoline tramp = [](void* p) -> void* {
        reinterpret_cast<Fn>(p)();
        return nullptr;
    };
    if (::pthread_create(&handle_, nullptr, tramp, reinterpret_cast<void*>(fn)) != 0)
        return false;
    started_ = true;
    return true;
}

void Thread::join(unsigned /*timeoutMs*/) {
    if (!started_)
        return;
    ::pthread_join(handle_, nullptr);
    started_ = false;
}

#endif

} // namespace bf2hub
