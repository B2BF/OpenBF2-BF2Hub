// Stats-snapshot channel. glsSendSnapshot hands a stats blob here; packSnapshot builds the
// authenticated packet (three MD5 MACs + a CBC-obfuscated body, exactly as sub_10005690 does), and
// a background worker POSTs it to the BF2Hub stats host (header per sub_10004B80, send loop per
// sub_10004F00).
//
// Note on the auth header: the X-BF2Hub-tsdata token folds in the session's GameSpy auth words
// (authA/authB), which the retail DLL obtains from a GameSpy challenge-response run inside the ws2
// proxy's worker (sub_10004530). That GameSpy exchange is part of the socket/master transport that
// is handled separately and not built here, so those words are whatever the session holds (zero
// until an external layer fills them) - the same packet the retail code sends before its GameSpy
// auth has completed.

#ifndef BF2HUB_SNAPSHOT_H
#define BF2HUB_SNAPSHOT_H

#include <cstddef>
#include <cstdint>

namespace bf2hub {

struct Session;

// Pack the snapshot and enqueue it for upload. Returns false on a pack/allocation failure.
bool queueSnapshot(const Session& session, const uint8_t* data, size_t len);

void startSnapshotWorker();
void stopSnapshotWorker();

} // namespace bf2hub

#endif // BF2HUB_SNAPSHOT_H
