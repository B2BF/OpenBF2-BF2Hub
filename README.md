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
recognised.

## Building

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

## Installing

1. Put the matching `bf2hub.dll` in the dedicated server's working directory (next to the exe).
2. Put a genuine retail `bf2_w32ded.exe` somewhere and set `referenceExe` in `bf2hub.cfg`.
3. Add `openbf2.addModDll bf2hub` to the mod's `openbf2.con` / `ServerSettings.con`.
4. Logs are written to `logs/bf2hub/<date>.log`.

## Platforms

Windows x86 and x64 build today. The Linux port (`libbf2hub.so`, x86/x64) is planned; CMake refuses to
configure on non-Windows hosts until it exists.

## Status

Implemented, from the recovered `dice_py` ABI and the shipped routines:

* module injection (the `dice_py` IAT hooks, `bf2hublib` registration, `bf2.bf2hub` import),
* host detection and the executable fingerprint blob,
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

Remaining validation: the MAC byte layouts are reconstructed from fresh Hex-Rays decompiles and the MD5
is test-vector-correct, but the end-to-end exchange has **not yet been checked against a live BF2Hub
backend capture**. That is the next step before relying on ranking in production.

## License

Licensed under the GNU General Public License v3.0. See [LICENSE](LICENSE).
