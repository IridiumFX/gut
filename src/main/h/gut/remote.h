#ifndef GUT_REMOTE_H
#define GUT_REMOTE_H

#include "gut/types.h"
#include "gut/oid.h"

/*
 * Git smart HTTP protocol (v1):
 *
 * Clone/Fetch:
 *   GET  <url>/info/refs?service=git-upload-pack
 *     → pkt-line list of refs + capabilities
 *   POST <url>/git-upload-pack
 *     → client sends: want <oid>\n ... flush ... done\n
 *     ← server sends: NAK\n + packfile bytes
 *
 * Push:
 *   GET  <url>/info/refs?service=git-receive-pack
 *   POST <url>/git-receive-pack
 *     → client sends: <old> <new> <ref>\n ... flush + packfile
 *     ← server sends: status
 *
 * Pkt-line format:
 *   4 hex chars = length (including the 4 chars), or "0000" = flush
 */

#define GUT_REMOTE_MAX_REFS 256

typedef struct {
    gut_oid oid;
    char    name[256];
} gut_remote_ref;

typedef struct {
    gut_remote_ref refs[GUT_REMOTE_MAX_REFS];
    u64 count;
    char capabilities[1024];
} gut_remote_refs;

/* Discover refs from a remote URL via smart HTTP.
 * url should be the repo URL (e.g., "https://github.com/user/repo") */
unsigned long remote_discover_refs(gut_remote_refs *out, const char *url);

/* Fetch a packfile from remote for the given want OIDs.
 * have_oids may be NULL (for clone, where we have nothing).
 * Writes the received packfile to pack_path. */
unsigned long remote_fetch_pack(const char *url,
                                gut_oid *want_oids, u64 want_count,
                                gut_oid *have_oids, u64 have_count,
                                const char *pack_path);

#endif /* GUT_REMOTE_H */
