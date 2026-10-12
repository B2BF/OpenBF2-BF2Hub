# OpenBF2-BF2Hub

A run-time **mod module** for the [OpenBF2](../OpenBF2) dedicated server that reproduces the parts of
the shipped **BF2Hub client DLL** (`bf2hub.dll`) that make a Battlefield 2 1.50 server rankable on the
BF2Hub backend — but built so it accepts the OpenBF2 server executable as a normal 1.50 server instead
of refusing to run on a modified image.

It is loaded by the engine's console command:

```
openbf2.addModDll bf2hub
```

from a loose server config that runs **before Python initialisation** (`openbf2.con`, `ServerSettings.con`
or `Init.con`). The module does its work from `DllMain` and exports no `initDll`, so the loader keeps it
resident — exactly the contract the engine's loader documents for a `DllMain`-based integration.

## Scope

The genuine `bf2hub.dll` is two things at once:

1. a **`ws2_32.dll` proxy** (it exports every Winsock thunk) that redirects GameSpy/master-server
   traffic at the socket layer, and
2. a **`DllMain` payload** that injects a Python module and sends a heartbeat.

**This project reproduces only (2)**, and only the pieces requested:

* **The Python integration** — a C extension module `bf2hublib` (methods `gpaInit`, `gpaGetString`,
  `gpaProcessResponse`, `glsGetFlags`, `glsCheck`, `glsGetHostname`, `glsGetDocument`,
  `glsSendSnapshot`, `glsGetAuthInfo`, `netaddr`, `log`) plus the `bf2.bf2hub` package import. These are
  injected by patching the host executable's imports of `dice_py`'s `Py_InitModule4` /
  `PyImport_ImportModule`, identical to the retail mechanism — no engine source change required.
* **The "hello" heartbeat** — the BF2Hub-native UDP hello to `servers.bf2hub.com` that keeps the server
  visible to the backend. It carries the executable fingerprint and a keyed-MD5 MAC. It resolves
  `servers.bf2hub.com` on its own and does **not** depend on the socket proxy.

**The `ws2_32` socket proxy is intentionally not built.** Routing of the GameSpy hostnames to the
BF2Hub backend is handled outside this module; the Python methods return the retail GameSpy hostnames
verbatim so that external routing applies.

### "Believe the OpenBF2 exe is a normal server"

The retail DLL fingerprints the running executable (MD5 of the whole file + its `.text` section) and
sends that blob to the backend so it knows which build is talking. OpenBF2's executable is not the
retail one, so the module reports an **embedded fingerprint of the BF2Hub-patched retail
`bf2_w32ded.exe`** instead (`HostImage::kEmbeddedFingerprint`):

```
file size  4,980,736
whole MD5  3ca127b1be4275196af93347714707f9
.text MD5  07fe4d04e346e9ee085875cd4c6686be
```

This is the default — operators need nothing on disk. To re-measure a different patched exe, set the
optional override:

```
# bf2hub.cfg (in the server's working directory)
referenceExe = C:\path\to\patched\bf2_w32ded.exe
```

The dedicated-server detection also accepts `w64ded` (not just the retail `w32ded`) so the x64 server is
recognised. (The exe fingerprint is a **Windows** concern only — the Linux heartbeat uses a fixed key,
not an exe hash; see *Linux* below.)

## Building

### Windows (`bf2hub.dll`)

Requires MSVC (x86 and/or x64), CMake ≥ 3.21, Ninja, and the architecture-matched `dice_py.lib` from the
OpenBF2 Python build (the module links against the engine's embedded CPython 2.3.4 so its `PyObject`
layout and allocator match).

```powershell
# x86 (for bf2_w32ded.exe)
cmake --preset msvc-x86 `
      -DBF2HUB_DICE_PY_DIR="D:\LC\OpenBF2\Code\BF2\External\python-embedded\OBJ\python\release"
cmake --build --preset msvc-x86

# x64 (for bf2_w64ded.exe)
cmake --preset msvc-x64 `
      -DBF2HUB_DICE_PY_DIR="D:\LC\OpenBF2\Code\BF2\External\python-embedded\OBJ\python\x64\release"
cmake --build --preset msvc-x64
```

Run the configure step from a matching Visual Studio developer environment (`VsDevCmd.bat -arch=x86` /
`-arch=x64`). The build writes `bf2hub.dll` into `out/build/<preset>/`. Set `-DBF2HUB_STAGE_DIR=<game dir>`
to copy it next to the server automatically.

### Linux (`libbf2hub.so`)

Requires GCC/Clang, CMake ≥ 3.21, Ninja.

```bash
cmake --preset linux-x64
cmake --build --preset linux-x64        # -> out/build/linux-x64/libbf2hub.so
```

The CPython symbols live in `libdice_py.so`; the module declares it as a `DT_NEEDED` dependency (as
the retail `libbf2hub.so` does) so the loader resolves them at load time — otherwise the server aborts
with `undefined symbol: PyExc_ValueError`. To record that dependency without a dice_py import library,
the build generates a tiny link-time **stub** `libdice_py.so` in the build directory; the real
`libdice_py.so` in the server process provides the symbols at run time.

> **Ship only `libbf2hub.so`.** The `libdice_py.so` in the build directory is a throwaway build-time
> stub — never copy it next to the server (it would shadow the real one). `-DBF2HUB_STAGE_DIR=` copies
> only `libbf2hub.so`. If you prefer to link the real library instead of the stub, pass
> `-DBF2HUB_DICE_PY=/path/to/libdice_py.so`.

⚠ Build on (or for) the **target server's glibc**. The BF2 Linux dedicated server runs on an old
glibc; a `.so` built against a newer glibc will reference symbol versions the target cannot resolve.
Build on a distro matching the server, or with an appropriate sysroot.

## Installing

1. Put the matching module next to the server: `bf2hub.dll` on Windows, `libbf2hub.so` on Linux.
2. Windows only: optionally set `referenceExe` in `bf2hub.cfg` (defaults to the embedded fingerprint).
3. Add `openbf2.addModDll bf2hub` to the mod's `openbf2.con` / `ServerSettings.con`. It resolves to
   `.\bf2hub.dll` on Windows and `libbf2hub.so` on Linux.
4. Logs are written to `logs/bf2hub/<date>.log`.

## Platforms

Windows x86 and x64 (`bf2hub.dll`) and Linux x86-64 (`libbf2hub.so`) all build. The two share the
engine logic (MD5, session, Python methods, MACs, snapshot packing); they differ only where the OS or
the BF2Hub protocol version does:

| | Windows `bf2hub.dll` | Linux `libbf2hub.so` |
|---|---|---|
| Load hook | `DllMain` | `.init_array` constructor |
| Import hook | IAT patch | GOT patch |
| Threads | Win32 | pthread/std |
| Exe path | `GetModuleFileNameA` | `readlink("/proc/self/exe")` |
| Heartbeat | `HHHL3Q` + exe fingerprint | `HHHL2Q` + fixed 32-byte key |
| `glsGetAuthInfo` | present (returns empty) | absent (not in the Linux table) |

The Linux `libbf2hub.so` is a distinct, simpler retail build than the Windows DLL; this port
reproduces its protocol (notably the fixed-key `HHHL2Q` heartbeat — ELF has no PE fingerprint, so
there is nothing to spoof there).

## Status

Implemented, from the recovered `dice_py` ABI and the shipped routines:

* module injection (the `dice_py` import hook — IAT patch on Windows, GOT patch on Linux —
  `bf2hublib` registration, `bf2.bf2hub` import),
* host detection and the executable fingerprint blob (Windows),
* the MD5 (standard and the keyed heartbeat variant) — verified against the RFC 1321 test vectors,
* the "hello" heartbeat packet and sender,
* `glsGetFlags`, `glsGetHostname`, `glsGetDocument`, `netaddr`, `log`,
* the authentication MACs: `gpaGetString` (`sub_10005FF0`, four MD5 MACs + the overlapping token
  layout), `gpaProcessResponse` (`sub_10006910`, MAC-keyed decode of the reply + MAC verify + rcon),
  `glsCheck` (`sub_10005BE0`), and the snapshot packer `glsSendSnapshot` → `packSnapshot`
  (`sub_10005690`, three MD5 MACs + CBC-obfuscated body) with a background HTTP POST uploader
  (header per `sub_10004B80`, send loop per `sub_10004F00`).

Faithful boundaries (the shipped behaviour in our configuration, not stubs):

* **`glsGetAuthInfo`** returns an empty string. Its token is built from the per-player auth cache that
  only the ws2 proxy fills from intercepted GameSpy auth packets (`sub_10007F70` → `dword_1001FE08`);
  that proxy is handled separately, so the cache is empty — exactly the retail no-data return.
* **Snapshot upload auth words** (`X-BF2Hub-tsdata` folds in `authA`/`authB`): the retail DLL obtains
  these from a GameSpy UDP challenge run inside the proxy worker (`sub_10004530`), which is part of the
  separately-handled transport. Until an external layer fills them they are zero — the same packet the
  retail code sends before its GameSpy auth completes.

Remaining validation: the Windows MAC byte layouts are reconstructed from fresh Hex-Rays decompiles and
the MD5 is test-vector-correct, but the end-to-end exchange has **not yet been checked against a live
BF2Hub backend capture**. That is the next step before relying on ranking in production.

### Linux specifics

The Linux build reuses the same methods/MACs (they match the Windows binary) through the platform
shims above. Two Linux items still want a wire capture to confirm:

* the **`HHHL2Q` heartbeat payload layout** (`src/Heartbeat.cpp`, from `sub_721D`) — the tag, port
  29960, magic `1367436204`, host `servers.bf2hub.com` and the fixed 32-byte key are certain, but the
  exact field order inside the 32-byte payload is reconstructed from a decompile whose signature IDA
  could not fully recover; it is marked `[FRONTIER]` in the source;
* `gpaGetString` folds the MD5 of `/proc/self/exe` (the running `bf2`), matching the retail `.so`;
  unlike Windows there is no embedded reference hash, so this is the real server binary's hash.

## License

Licensed under the GNU General Public License v3.0. See [LICENSE](LICENSE).
