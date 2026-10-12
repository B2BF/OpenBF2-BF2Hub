// The BF2Hub "hello" heartbeat. The shipped DLL periodically sends a UDP hello to the BF2Hub
// servers list (sub_10008B80, resolving servers.bf2hub.com via getaddrinfo, sub_10008A50) carrying
// the exe fingerprint and a keyed-MD5 MAC (sub_10008570). This is what keeps a server visible to the
// backend; it is BF2Hub-native (servers.bf2hub.com resolves on its own) and does not depend on the
// ws2_32 proxy, so we reproduce it directly.
//
// Retail drives this from the gethostbyname proxy hook; since we do not install that hook, we run it
// from our own timer thread at the dedicated-server cadence (60 s). [CHOSEN, not recovered] - the
// trigger changes, the packet does not.

#ifndef BF2HUB_HEARTBEAT_H
#define BF2HUB_HEARTBEAT_H

namespace bf2hub {

class Config;

// Starts/stops the background heartbeat thread. start() is a no-op if already running.
void startHeartbeat(Config* config);
void stopHeartbeat();

} // namespace bf2hub

#endif // BF2HUB_HEARTBEAT_H
