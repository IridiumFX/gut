#ifndef APENNINES_T3_SSH_KNOWN_HOSTS_H
#define APENNINES_T3_SSH_KNOWN_HOSTS_H

#include "apennines/types.h"

/* ================================================================
 *  OpenSSH known_hosts parser + host-key pinning.
 *
 *  Ported from gut's original implementation (2026-04-19). Matches
 *  OpenSSH's on-disk format including hashed entries and all four
 *  match outcomes (PINNED / MISMATCH / REVOKED / UNKNOWN).
 *
 *  File format (ssh_known_hosts(5)):
 *    <host-patterns> <key-type> <base64-key-blob> [<comment>]
 *
 *  Host patterns:
 *    github.com                  plain name
 *    [github.com]:22             port-qualified; brackets escape the colon
 *    *.example.com, !a.example   wildcards + negation
 *    1.2.3.4, [host]:22          comma-separated list
 *    |1|<base64-salt>|<base64-hmac-sha1>
 *                                hashed (HashKnownHosts) — hostname
 *                                visible only by computing HMAC-SHA1
 *
 *  Line markers (optional prefix):
 *    @revoked ...                key is explicitly revoked
 *    @cert-authority ...         key signs certificates for matched hosts
 *                                (we don't implement SSH cert auth;
 *                                 entries of this type are skipped)
 *
 *  Key types supported here:
 *    ssh-ed25519                 the 32-byte blob after the wrapper parse
 *
 *  RSA and ECDSA host keys parse successfully but aren't matchable
 *  against ed25519-only lookups — they're ignored by
 *  ssh_khosts_lookup_ed25519. Adding them is a trivial extension.
 *
 *  Designed for use as the backend to ssh_hostkey_verifier_fn:
 *    static unsigned long verify_cb(void *ctx, const char *host,
 *                                    u16 port,
 *                                    const u8 *blob, u64 blob_len) {
 *        ssh_khosts *k = (ssh_khosts *)ctx;
 *        // crack blob: string("ssh-ed25519") + string(32B pub)
 *        const u8 *pub = blob + 4 + 11 + 4;
 *        ssh_khosts_match m;
 *        ssh_khosts_lookup_ed25519(&m, k, host, port, pub);
 *        switch (m) {
 *            case SSH_KHOSTS_MATCH_PINNED:   return 0;
 *            case SSH_KHOSTS_MATCH_MISMATCH: return 1;
 *            case SSH_KHOSTS_MATCH_REVOKED:  return 1;
 *            case SSH_KHOSTS_MATCH_UNKNOWN:  return prompt_or_tofu();
 *        }
 *    }
 *    ssh_conn_create_ex(&c, host, port, verify_cb, khosts);
 * ================================================================ */

typedef struct ssh_khosts ssh_khosts;

typedef enum {
    SSH_KHOSTS_MATCH_PINNED   = 0,  /* host pattern matches and key bytes match */
    SSH_KHOSTS_MATCH_MISMATCH = 1,  /* host pattern matches but key bytes differ */
    SSH_KHOSTS_MATCH_REVOKED  = 2,  /* key is explicitly @revoked for this host */
    SSH_KHOSTS_MATCH_UNKNOWN  = 3   /* no entry for this host — TOFU decision */
} ssh_khosts_match;

/* ssh_khosts_open — open and parse a known_hosts file.
 *   out:   receives the parsed handle
 *   path:  path to known_hosts (e.g. ~/.ssh/known_hosts)
 *
 * Missing file is a normal, non-error condition: *out receives an
 * empty entry set and every lookup returns SSH_KHOSTS_MATCH_UNKNOWN.
 * Only returns non-zero on actual parse/alloc errors.
 *
 * Hatches: 1=null out, 2=alloc failure, 3=line-level parse failure */
unsigned long ssh_khosts_open(ssh_khosts **out, const char *path);

/* ssh_khosts_close — free a parsed handle.
 *
 * Hatches: 0 always (NULL is a no-op) */
unsigned long ssh_khosts_close(ssh_khosts *k);

/* ssh_khosts_lookup_ed25519 — match a (host, port, server_pub) tuple
 * against the parsed entries.
 *
 * Port handling: OpenSSH only writes the port in the entry when it
 * differs from 22. A plain "github.com" entry matches any port; an
 * entry "[github.com]:2222" matches only port 2222.
 *
 * Hatches: 1=null match_out, 2=null host, 3=null server_pub
 *         (NULL k is not an error — lookup returns UNKNOWN) */
unsigned long ssh_khosts_lookup_ed25519(ssh_khosts_match *match_out,
                                                       ssh_khosts *k,
                                                       const char *host,
                                                       u16 port,
                                                       const u8 *server_pub);

/* ssh_khosts_append_ed25519 — append a new entry to a known_hosts file.
 * Used to implement TOFU on first connection: after lookup returns
 * SSH_KHOSTS_MATCH_UNKNOWN and policy decides to accept, call this
 * to pin the key for future lookups.
 *
 * Creates the parent directory if missing. Appends (never rewrites)
 * so existing entries survive.
 *
 * Hatches: 1=null path, 2=null host, 3=null server_pub,
 *          4=mkdir/fopen failed, 5=encoding/write failed */
unsigned long ssh_khosts_append_ed25519(const char *path,
                                                       const char *host,
                                                       u16 port,
                                                       const u8 *server_pub);

/* ssh_khosts_default_path — resolve the default known_hosts path
 * (~/.ssh/known_hosts or %USERPROFILE%\.ssh\known_hosts on Windows).
 * Writes the full absolute path to `out` with forward-slash normalisation.
 *
 * Hatches: 1=null out, 2=no HOME/USERPROFILE resolvable,
 *          3=out buffer too small */
unsigned long ssh_khosts_default_path(char *out, u64 out_size);

#endif /* APENNINES_T3_SSH_KNOWN_HOSTS_H */
