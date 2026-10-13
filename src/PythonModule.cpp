#include "PythonModule.h"

#include "Config.h"
#include "Heartbeat.h"
#include "Hook.h"
#include "HostImage.h"
#include "Log.h"
#include "Md5.h"
#include "Platform.h"
#include "PyAbi.h"
#include "Session.h"
#include "Snapshot.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <string>

#if !defined(_WIN32)
#  include <sys/stat.h>
#endif

namespace bf2hub {
namespace {

// Shared state captured during the hooks.
Config*   g_config = nullptr;
Session*  g_session = nullptr;
PyObject* g_hostModule = nullptr;   // dword_1001FDF4: the engine's "host" module object

using Py_InitModule4_t = PyObject* (*)(const char*, PyMethodDef*, const char*, PyObject*, int);
using PyImport_ImportModule_t = PyObject* (*)(const char*);

Py_InitModule4_t         g_realInitModule4 = nullptr;         // dword_1001FDF8
PyImport_ImportModule_t  g_realImportModule = nullptr;        // dword_1001FDFC

// --- helpers --------------------------------------------------------------

// Call host.rcon_invoke(cmd) and return its string result. The engine's rcon_invoke runs a console
// line and returns the output; the retail code reads server settings this way (sub_10007620).
std::string hostRconInvoke(const std::string& cmd) {
    if (!g_hostModule)
        return std::string();
    PyObject* r = PyObject_CallMethod(g_hostModule, "rcon_invoke", "s", cmd.c_str());
    if (!r)
        return std::string();
    std::string out;
    if (r->ob_type == &PyString_Type || PyType_IsSubtype(r->ob_type, &PyString_Type)) {
        const char* s = PyString_AsString(r);
        if (s)
            out = s;
    }
    bf2hub_Py_DECREF(r);
    return out;
}

std::string hostModDirectory() {
    if (!g_hostModule)
        return std::string();
    PyObject* r = PyObject_CallMethod(g_hostModule, "sgl_getModDirectory", nullptr);
    if (!r)
        return std::string();
    std::string out;
    if (r->ob_type == &PyString_Type || PyType_IsSubtype(r->ob_type, &PyString_Type)) {
        const char* s = PyString_AsString(r);
        if (s)
            out = s;
    }
    bf2hub_Py_DECREF(r);
    return out;
}

// Loads python/bf2/bf2hub/bf2hubProviderID.sec (whitespace-stripped) into dst, as sub_100052F0 does,
// trying the three known locations.
void loadProviderId(char* dst, size_t dstSize) {
    static const char* const candidates[] = {
        "python/bf2/bf2hub/bf2hubProviderID.sec",
        "python/bf2/bf2hub/stats/bf2hubProviderID.sec",
        "python/bf2/stats/bf2hubProviderID.sec",
    };
    dst[0] = '\0';
    for (const char* path : candidates) {
        std::FILE* f = nullptr;
#if defined(_MSC_VER)
        ::fopen_s(&f, path, "rb");
#else
        f = std::fopen(path, "rb");
#endif
        if (!f)
            continue;
        size_t n = 0;
        int c;
        while ((c = std::fgetc(f)) != EOF && n + 1 < dstSize) {
            if (c == '\t' || c == '\r' || c == '\n' || c == ' ')
                continue;
            dst[n++] = static_cast<char>(c);
        }
        dst[n] = '\0';
        std::fclose(f);
        return;
    }
}

// Reads a dotted-decimal setting ("sv.serverIP") into an inet_addr; returns 0 on empty/failure.
uint32_t settingAddr(const char* name) {
    std::string v = hostRconInvoke(name);
    // The reply is "<name> <value>\r\n"-ish; take the last whitespace-delimited token.
    size_t end = v.find_last_not_of(" \t\r\n");
    if (end == std::string::npos)
        return 0;
    size_t begin = v.find_last_of(" \t\r\n", end);
    std::string tok = v.substr(begin == std::string::npos ? 0 : begin + 1, std::string::npos);
    tok = tok.substr(0, tok.find_last_not_of(" \t\r\n") + 1);
    return tok.empty() ? 0 : ::inet_addr(tok.c_str());
}

int settingInt(const char* name) {
    std::string v = hostRconInvoke(name);
    size_t end = v.find_last_not_of(" \t\r\n");
    if (end == std::string::npos)
        return 0;
    size_t begin = v.find_last_of(" \t\r\n", end);
    std::string tok = v.substr(begin == std::string::npos ? 0 : begin + 1);
    return std::atoi(tok.c_str());
}

// A nonzero random byte, matching the shipped generator (sub_10001E00: rand(), floored to 1).
uint8_t randByteNonzero() {
    static bool seeded = false;
    if (!seeded) { std::srand(static_cast<unsigned>(std::time(nullptr))); seeded = true; }
    int r = std::rand();
    return static_cast<uint8_t>(r >= 1 ? r : 1);
}

bool hostIsModule() {
    return g_hostModule &&
           (g_hostModule->ob_type == &PyModule_Type ||
            PyType_IsSubtype(g_hostModule->ob_type, &PyModule_Type));
}

// --- bf2hublib methods ----------------------------------------------------
// The authentication MACs are reconstructed from fresh Hex-Rays decompiles of the shipped routines
// (sub_10005FF0/6910/5BE0/5690) over the test-vector-verified MD5. glsGetAuthInfo returns empty
// because its data source is the ws2 proxy we do not build (see its comment and the README), which
// is the shipped no-data behaviour, not a stub. The end-to-end exchange is not yet validated against
// a live backend capture - see README "Remaining validation".

// gpaInit (sub_100076D0): gather server identity, provider id and mod dir into the session.
PyObject* gpaInit(PyObject*, PyObject*) {
    if (!g_session || !g_hostModule)
        return PyErr_Format(PyExc_RuntimeError, "fatal error (%d)", 1);

    std::string mod = hostModDirectory();
    std::strncpy(g_session->modDir, mod.c_str(), sizeof(g_session->modDir) - 1);
    g_session->modDir[sizeof(g_session->modDir) - 1] = '\0';

    int serverPort = settingInt("sv.serverPort");
    int queryPort  = settingInt("sv.gameSpyPort");
    if (static_cast<unsigned>(serverPort - 1) > 0xFFFE || static_cast<unsigned>(queryPort - 1) > 0xFFFE)
        return PyErr_Format(PyExc_ValueError, "fatal error (%d)", 2);

    g_session->serverPort  = static_cast<uint32_t>(serverPort);
    g_session->queryPort   = static_cast<uint32_t>(queryPort);
    g_session->serverIp    = settingAddr("sv.serverIP");
    g_session->interfaceIp = settingAddr("sv.interfaceIP");
    g_session->sessionTime = static_cast<uint32_t>(::time(nullptr));

    loadProviderId(g_session->providerId, sizeof(g_session->providerId));

    logLine("gpaInit: port=%d query=%d mod='%s'\r\n", serverPort, queryPort, g_session->modDir);
    return bf2hub_Py_INCREF(BF2HUB_Py_True);
}

// gpaGetString (sub_10005FF0): the auth/handshake token "R4-<challenge><id><mac1><mac2><mac3><mac4>".
// Four MD5 MACs over the session identity; MAC #4 folds in the reference exe's whole-file MD5 (the
// retail code hashes the running exe - we hash the spoofed reference, per the fingerprint decision).
// The four digest fields are written at the retail offsets, including the deliberate overlap that
// truncates MAC #2 to its first 16 hex chars.
PyObject* gpaGetString(PyObject*, PyObject*) {
    if (!g_session || !hostIsModule())
        return PyString_FromString("");
    Session& s = *g_session;

    PyObject* md = PyObject_CallMethod(g_hostModule, "sgl_getModDirectory", nullptr);
    if (!md)
        return PyString_FromString("");
    if (!(md->ob_type == &PyString_Type || PyType_IsSubtype(md->ob_type, &PyString_Type))) {
        bf2hub_Py_DECREF(md);
        return PyString_FromString("");
    }

    const uint32_t now = static_cast<uint32_t>(std::time(nullptr));
    std::snprintf(s.timeStr, sizeof(s.timeStr), "%u", now);
    const char* mdstr = PyString_AsString(md);
    std::strncpy(s.modDir, mdstr ? mdstr : "", 0x1C);
    s.modDir[27] = '\0';
    bf2hub_Py_DECREF(md);

    for (int i = 0; i < 16; ++i)
        s.challenge[i] = randByteNonzero();

    const uint16_t sp = static_cast<uint16_t>(s.serverPort);
    const uint16_t qp = static_cast<uint16_t>(s.queryPort);

    // Second hex field: {time, serverPort, queryPort, interfaceIp, serverIp} XORed with the
    // challenge, then CBC-chained with seed 'O' (79).
    uint8_t raw[16], obf[16];
    std::memcpy(raw + 0, &now, 4);
    std::memcpy(raw + 4, &sp, 2);
    std::memcpy(raw + 6, &qp, 2);
    std::memcpy(raw + 8, &s.interfaceIp, 4);
    std::memcpy(raw + 12, &s.serverIp, 4);
    uint8_t prev = 'O';
    for (int i = 0; i < 16; ++i) { prev = static_cast<uint8_t>(prev ^ (raw[i] ^ s.challenge[i])); obf[i] = prev; }

    uint8_t exeMd5[16] = {0};
    referenceExeWholeMd5(*g_config, exeMd5);

    const size_t modLen  = std::strlen(s.modDir);
    const size_t provLen = std::strlen(s.providerId);
    const size_t timeLen = std::strlen(s.timeStr);

    uint8_t d1[16], d2[16], d3[16], d4[16];
    Md5 c;
    c.init();
    c.update(s.challenge, 16);
    c.update(&s.serverPort, 2); c.update(&s.queryPort, 2);
    c.update(&s.interfaceIp, 4); c.update(&s.serverIp, 4);
    c.update(&now, 4);
    c.final(d1);

    c.init();
    c.update(s.challenge, 16);
    c.update(&s.serverPort, 2); c.update(&s.queryPort, 2);
    c.update(&s.interfaceIp, 4); c.update(&s.serverIp, 4);
    c.update(s.modDir, modLen);
    c.update(s.timeStr, timeLen);
    c.final(d2);

    c.init();
    c.update(s.challenge, 16);
    c.update(&s.queryPort, 2); c.update(&s.serverPort, 2);   // note: queryPort first here
    c.update(&s.serverIp, 4); c.update(&s.interfaceIp, 4);   // and serverIp first
    c.update(s.providerId, provLen);
    c.update(s.timeStr, timeLen);
    c.final(d3);

    c.init();
    c.update(s.challenge, 16);
    c.update(exeMd5, 16);
    c.update(s.timeStr, timeLen);
    c.update(&s.serverPort, 2); c.update(&s.queryPort, 2);
    c.update(&s.interfaceIp, 4); c.update(&s.serverIp, 4);
    c.final(d4);

    char out[200];
    std::memset(out, 0, sizeof(out));
    // Token version prefix. The Windows DLL (sub_10005FF0) emits "R4-"; the Linux .so (sub_5433)
    // emits "R3-" - the same protocol-version skew as the heartbeat tag (HHHL3Q vs HHHL2Q). The
    // backend validates the exact string, so this must match the platform's binary.
    out[0] = 'R';
#if defined(_WIN32)
    out[1] = '4';
#else
    out[1] = '3';
#endif
    out[2] = '-';
    md5HexLower(s.challenge, out + 3);    // [3..34]
    md5HexLower(obf,         out + 35);   // [35..66]
    md5HexLower(d1,          out + 67);   // [67..98]
    md5HexLower(d2,          out + 99);   // [99..130] (second half overwritten below)
    md5HexLower(d3,          out + 115);  // [115..146]
    md5HexLower(d4,          out + 147);  // [147..178]
    return PyString_FromString(out);
}

// gpaProcessResponse (sub_10006910): verify the backend reply, and on success run the embedded rcon
// command and store the rank flag. The reply carries two MD5 MACs; the first keys a 16-byte XOR that
// decodes {rankFlag(4), len(1), command(<=11)}, the second authenticates the whole exchange and is
// compared against data[16..31].
PyObject* gpaProcessResponse(PyObject*, PyObject* args) {
    const char* data = nullptr;
    int len = 0;
    if (!PyArg_ParseTuple(args, "s#", &data, &len))
        return bf2hub_Py_INCREF(BF2HUB_Py_Zero);
    if (!g_session || !hostIsModule() || len < 48)
        return bf2hub_Py_INCREF(BF2HUB_Py_Zero);
    Session& s = *g_session;
    const uint8_t* in = reinterpret_cast<const uint8_t*>(data);

    const size_t modLen  = std::strlen(s.modDir);
    const size_t provLen = std::strlen(s.providerId);
    const size_t timeLen = std::strlen(s.timeStr);

    uint8_t m1[16];
    Md5 c;
    c.init();
    c.update(in, 16);
    c.update(&s.serverPort, 2); c.update(&s.queryPort, 2);
    c.update(&s.interfaceIp, 4); c.update(&s.serverIp, 4);
    c.update(s.challenge, 16);
    c.update(s.modDir, modLen);
    c.update(s.providerId, provLen);
    c.update(s.timeStr, timeLen);
    c.final(m1);

    uint8_t dec[16];
    for (int i = 0; i < 16; ++i)
        dec[i] = static_cast<uint8_t>(in[32 + i] ^ m1[i]);
    uint32_t rankFlag;
    std::memcpy(&rankFlag, dec, 4);
    const uint8_t cmdLen = dec[4];
    if (cmdLen >= 16)
        return bf2hub_Py_INCREF(BF2HUB_Py_Zero);
    char cmd[12];
    std::memset(cmd, 0, sizeof(cmd));
    std::memcpy(cmd, dec + 5, 11);
    cmd[cmdLen < 11 ? cmdLen : 11] = '\0';

    uint8_t m2[16];
    c.init();
    c.update(in, 16);
    c.update(s.challenge, 16);
    c.update(s.providerId, provLen);
    c.update(cmd, std::strlen(cmd));
    c.update(dec, 4);                 // the decoded rank flag, raw
    c.update(s.modDir, modLen);
    c.update(&s.serverPort, 2); c.update(&s.queryPort, 2);
    c.update(&s.interfaceIp, 4); c.update(&s.serverIp, 4);
    c.update(s.timeStr, timeLen);
    c.final(m2);

    if (std::memcmp(m2, in + 16, 16) != 0)
        return bf2hub_Py_INCREF(BF2HUB_Py_Zero);

    PyObject* r = PyObject_CallMethod(g_hostModule, "rcon_invoke", "s", cmd);
    if (r)
        bf2hub_Py_DECREF(r);
    s.rankFlag = rankFlag;
    return bf2hub_Py_INCREF(BF2HUB_Py_True);
}

// glsGetFlags (sub_10005BC0): the stored rank flag.
PyObject* glsGetFlags(PyObject*, PyObject*) {
    return PyLong_FromLong(g_session ? static_cast<long>(g_session->rankFlag) : 0);
}

// glsCheck (sub_10005BE0): a per-blob integrity token over the submitted data. Result is
// hex(8 random bytes) + hex(MD5), where the MD5 covers 16 random bytes + the server identity + the
// data + the time string. (The retail body also builds an obfuscated identity block that it never
// emits or hashes - a dead anti-analysis artifact - so we omit it; the output is identical.)
PyObject* glsCheck(PyObject*, PyObject* args) {
    const char* data = nullptr;
    int len = 0;
    if (!PyArg_ParseTuple(args, "s#", &data, &len))
        return bf2hub_ReturnNone();
    if (!g_session)
        return bf2hub_ReturnNone();
    Session& s = *g_session;

    const uint32_t now = static_cast<uint32_t>(std::time(nullptr));
    uint8_t rnd[16];
    for (int i = 0; i < 16; ++i)
        rnd[i] = randByteNonzero();

    char timeStr[16];
    std::snprintf(timeStr, sizeof(timeStr), "%ld", static_cast<long>(now));

    uint8_t dg[16];
    Md5 c;
    c.init();
    c.update(rnd, 16);
    c.update(&s.queryPort, 2); c.update(&s.serverPort, 2);   // queryPort first
    c.update(&s.serverIp, 4);  c.update(&s.interfaceIp, 4);  // serverIp first
    c.update(s.providerId, std::strlen(s.providerId));
    c.update(data, static_cast<size_t>(len));
    c.update(timeStr, std::strlen(timeStr));
    c.final(dg);

    char out[64];
    static const char lut[] = "0123456789abcdef";
    for (int i = 0; i < 8; ++i) {               // only the first 8 random bytes are revealed
        out[i * 2]     = lut[rnd[i] >> 4];
        out[i * 2 + 1] = lut[rnd[i] & 0xf];
    }
    md5HexLower(dg, out + 16);                   // [16..47] + NUL[48]
    return PyString_FromString(out);
}

// glsGetHostname (sub_10006DD0): the stats hostnames, by index. Returned verbatim as the retail
// GameSpy names; routing to the BF2Hub backend is handled outside this module (the ws2 redirection
// we intentionally do not reproduce).
PyObject* glsGetHostname(PyObject*, PyObject* args) {
    int idx = 0;
    if (!PyArg_ParseTuple(args, "i", &idx))
        return nullptr;
    switch (idx) {
        case 1: return PyString_FromString("BF2Web.gamespy.com");
        case 2: return PyString_FromString("gamestats.gamespy.com");
        case 3: return PyString_FromString("battlefield2.gamestats.gamespy.com");
        default: return PyErr_Format(PyExc_IndexError, "Invalid index: %d", idx);
    }
}

// glsGetDocument (sub_10006F20): the stats ASP path, for indices 1..3.
PyObject* glsGetDocument(PyObject*, PyObject* args) {
    int idx = 0;
    if (!PyArg_ParseTuple(args, "i", &idx))
        return nullptr;
    if (idx == 1 || idx == 2 || idx == 3)
        return PyString_FromString("/ASP/getrankstatus.aspx");
    return PyErr_Format(PyExc_IndexError, "Invalid index: %d", idx);
}

// glsSendSnapshot (sub_10007480 -> sub_10005690): build the authenticated snapshot packet and queue
// it for upload. The packet framing (three MD5 MACs + CBC-obfuscated body) is reproduced in
// Snapshot::packSnapshot; the background worker POSTs it to the stats host. A zero-length or
// pack failure returns the retail RuntimeError.
PyObject* glsSendSnapshot(PyObject*, PyObject* args) {
    const char* data = nullptr;
    int len = 0;
    if (!PyArg_ParseTuple(args, "s#", &data, &len))
        return nullptr;
    if (!g_session)
        return PyErr_Format(PyExc_RuntimeError, "fatal error (%d)", 3);
    logLine("SNAPSHOT: %d bytes submitted\r\n", len);
    if (!queueSnapshot(*g_session, reinterpret_cast<const uint8_t*>(data), static_cast<size_t>(len)))
        return PyErr_Format(PyExc_RuntimeError, "fatal error (%d)", 3);
    return bf2hub_Py_INCREF(BF2HUB_Py_True);
}

// glsGetAuthInfo (sub_10007070): a per-player auth token. The token is built from the per-player auth
// cache the retail DLL fills from intercepted GameSpy auth packets (sub_10007F70 ->
// dword_1001FE08, populated by the ws2 proxy's gethostbyname/recvfrom hooks). That proxy is handled
// separately and not built here, so the cache is empty and the faithful result is the retail
// no-data return: an empty string. This is the shipped behaviour when no auth has been captured,
// not a stub.
#if defined(_WIN32)
PyObject* glsGetAuthInfo(PyObject*, PyObject*) {
    return PyString_FromString("");
}
#endif

// netaddr (sub_100072F0): resolve a stats hostname (by index) to a dotted-decimal IP string.
PyObject* netaddr(PyObject*, PyObject* args) {
    int idx = 0;
    if (!PyArg_ParseTuple(args, "i", &idx))
        return nullptr;
    const char* name = nullptr;
    switch (idx) {
        case 1: name = "BF2Web.gamespy.com"; break;
        case 2: name = "gamestats.gamespy.com"; break;
        case 3: name = "battlefield2.gamestats.gamespy.com"; break;
        default: return PyErr_Format(PyExc_ValueError, "Invalid index: %d", idx);
    }
    hostent* he = ::gethostbyname(name);
    if (he && he->h_addr_list && he->h_addr_list[0]) {
        uint32_t a = *reinterpret_cast<uint32_t*>(he->h_addr_list[0]);
        return PyString_FromFormat("%d.%d.%d.%d",
            a & 0xff, (a >> 8) & 0xff, (a >> 16) & 0xff, (a >> 24) & 0xff);
    }
    return PyErr_Format(PyExc_RuntimeError, "Hostname for index %d does not exist", idx);
}

// log (sub_10007030): write a line to the bf2hub log.
PyObject* pyLog(PyObject*, PyObject* args) {
    const char* msg = nullptr;
    if (!PyArg_ParseTuple(args, "s", &msg))
        return nullptr;
    logLine("PY: %s\r\n", msg);
    return bf2hub_ReturnNone();
}

// The method table - order and flags match the retail off_1001F010.
PyMethodDef g_methods[] = {
    { "gpaInit",            gpaInit,            BF2HUB_METH_NOARGS,  nullptr },
    { "gpaGetString",       gpaGetString,       BF2HUB_METH_NOARGS,  nullptr },
    { "gpaProcessResponse", gpaProcessResponse, BF2HUB_METH_VARARGS, nullptr },
    { "glsGetFlags",        glsGetFlags,        BF2HUB_METH_NOARGS,  nullptr },
    { "glsCheck",           glsCheck,           BF2HUB_METH_VARARGS, nullptr },
    { "glsGetHostname",     glsGetHostname,     BF2HUB_METH_VARARGS, nullptr },
    { "glsGetDocument",     glsGetDocument,     BF2HUB_METH_VARARGS, nullptr },
    { "glsSendSnapshot",    glsSendSnapshot,    BF2HUB_METH_VARARGS, nullptr },
#if defined(_WIN32)
    // The Linux libbf2hub.so table has no glsGetAuthInfo; its token comes from the ws2 proxy's
    // per-player auth cache, which neither build reproduces. Kept Windows-only for table parity
    // with the retail DLL.
    { "glsGetAuthInfo",     glsGetAuthInfo,     BF2HUB_METH_VARARGS, nullptr },
#endif
    { "netaddr",            netaddr,            BF2HUB_METH_VARARGS, nullptr },
    { "log",                pyLog,              BF2HUB_METH_VARARGS, nullptr },
    { nullptr, nullptr, 0, nullptr },
};

bool fileExists(const char* path) {
#if defined(_WIN32)
    DWORD a = ::GetFileAttributesA(path);
    return a != INVALID_FILE_ATTRIBUTES && !(a & FILE_ATTRIBUTE_DIRECTORY);
#else
    struct stat st;
    return ::stat(path, &st) == 0 && (st.st_mode & S_IFREG);
#endif
}

// --- hook thunks ----------------------------------------------------------

PyObject* initModule4Hook(const char* name, PyMethodDef* methods, const char* doc,
                          PyObject* self, int apiver) {
    PyObject* result = g_realInitModule4(name, methods, doc, self, apiver);
    if (result && name && std::strcmp(name, "host") == 0) {
        // Register bf2hublib beside host, and remember the host module object.
        g_realInitModule4("bf2hublib", g_methods, nullptr, nullptr, apiver);
        g_hostModule = result;
    }
    return result;
}

PyObject* importModuleHook(const char* name) {
    PyObject* result = g_realImportModule(name);
    if (result && name && std::strcmp(name, "bf2") == 0) {
        if (fileExists("python/bf2/bf2hub/__init__.py") ||
            fileExists("python/bf2/bf2hub/__init__.pyc")) {
            PyObject* sub = g_realImportModule("bf2.bf2hub");
            if (sub)
                bf2hub_Py_DECREF(sub);
        }
    }
    return result;
}

} // namespace

void installPythonHooks(Config* config, Session* session) {
    g_config = config;
    g_session = session;

    void* real1 = nullptr;
    void* real2 = nullptr;
    bool ok1 = installImportHook("Py_InitModule4", reinterpret_cast<void*>(&initModule4Hook), &real1);
    bool ok2 = installImportHook("PyImport_ImportModule", reinterpret_cast<void*>(&importModuleHook), &real2);
    g_realInitModule4 = reinterpret_cast<Py_InitModule4_t>(real1);
    g_realImportModule = reinterpret_cast<PyImport_ImportModule_t>(real2);

    if (!ok1 || !ok2 || !g_realInitModule4 || !g_realImportModule) {
        logLine("installPythonHooks: could not hook dice_py imports (InitModule4=%p ImportModule=%p)\r\n",
                reinterpret_cast<void*>(g_realInitModule4), reinterpret_cast<void*>(g_realImportModule));
    } else {
        logLine("installPythonHooks: dice_py import hooks installed\r\n");
    }
}

} // namespace bf2hub
