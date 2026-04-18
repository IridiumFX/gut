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
    gut_hash_algo hash_algo;  /* detected from OID width / object-format= cap */
} gut_remote_refs;

/* Discover refs from a remote URL via smart HTTP.
 * url should be the repo URL (e.g., "https://github.com/user/repo") */
unsigned long remote_discover_refs(gut_remote_refs *out, const char *url);

/* Fetch a packfile from remote for the given want OIDs.
 * have_oids may be NULL (for clone, where we have nothing).
 * Writes the received packfile to pack_path.
 *
 * depth > 0 requests a shallow fetch (depth N commits). Server responds
 * with a list of boundary OIDs that become the caller's .git/shallow.
 * If shallow_out is non-NULL, the caller receives the malloc'd boundary
 * OID array; the caller must free it. Pass depth=0 / NULLs to skip. */
unsigned long remote_fetch_pack(const char *url,
                                gut_oid *want_oids, u64 want_count,
                                gut_oid *have_oids, u64 have_count,
                                const char *pack_path,
                                int depth,
                                gut_oid **shallow_out,
                                u64     *shallow_count_out);

/* Same as remote_fetch_pack, but hex width follows `algo`. */
unsigned long remote_fetch_pack_algo(const char *url,
                                     gut_oid *want_oids, u64 want_count,
                                     gut_oid *have_oids, u64 have_count,
                                     const char *pack_path,
                                     int depth,
                                     gut_oid **shallow_out,
                                     u64     *shallow_count_out,
                                     gut_hash_algo algo);

/* Discover refs via git-receive-pack endpoint (used for push). */
unsigned long remote_discover_refs_for_push(gut_remote_refs *out, const char *url,
                                             const char *token);

/* A single ref update command for push */
typedef struct {
    gut_oid old_oid;
    gut_oid new_oid;
    char    ref_name[256];
} gut_remote_update;

/* Send a packfile to the remote via git-receive-pack.
 *   url:      repository URL
 *   token:    optional bearer/basic auth token (passed as Authorization Basic
 *             with username "x-oauth-basic")
 *   updates:  array of (old_oid, new_oid, ref) tuples
 *   pack_data, pack_len: full packfile bytes (PACK header to trailer SHA-1)
 *   Sets *server_msg to the server's textual response (caller frees). */
unsigned long remote_send_pack(char **server_msg, const char *url, const char *token,
                               gut_remote_update *updates, u64 update_count,
                               u8 *pack_data, u64 pack_len);

/* Same as remote_send_pack, but hex width follows `algo`. */
unsigned long remote_send_pack_algo(char **server_msg, const char *url,
                                    const char *token,
                                    gut_remote_update *updates, u64 update_count,
                                    u8 *pack_data, u64 pack_len,
                                    gut_hash_algo algo);

#endif /* GUT_REMOTE_H */
