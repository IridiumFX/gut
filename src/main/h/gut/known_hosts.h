#ifndef GUT_KNOWN_HOSTS_H
#define GUT_KNOWN_HOSTS_H

#include "gut/types.h"

/*
 * OpenSSH known_hosts parser + host-key pinning.
 *
 * File format (ssh_known_hosts(5)):
 *   <host-patterns> <key-type> <base64-key-blob> [<comment>]
 *
 * Host patterns:
 *   github.com                  plain name
 *   [github.com]:22             port-qualified; brackets escape the colon
 *   *.example.com, !a.example   wildcards + negation
 *   1.2.3.4, [host]:22          comma-separated list
 *   |1|<base64-salt>|<base64-hmac-sha1>
 *                               hashed (HashKnownHosts) — hostname
 *                               visible only by computing HMAC-SHA1
 *
 * Line markers (optional prefix):
 *   @revoked ...                key is explicitly revoked
 *   @cert-authority ...         key signs certificates for matched hosts
 *                               (we don't implement SSH cert auth; entries
 *                                of this type are skipped)
 *
 * Key types supported here:
 *   ssh-ed25519                 the 32-byte blob after the wrapper parse
 *
 * RSA and ECDSA host keys parse successfully but aren't matchable
 * against ed25519-only lookups — they're ignored by
 * khosts_lookup_ed25519. Adding them is a trivial extension once
 * apennines' ssh_conn exposes the server's actual host-key type.
 */

typedef struct gut_khosts gut_khosts;

typedef enum {
    KHOSTS_MATCH_PINNED   = 0,  /* host pattern matches and key bytes match */
    KHOSTS_MATCH_MISMATCH = 1,  /* host pattern matches but key bytes differ */
    KHOSTS_MATCH_REVOKED  = 2,  /* key is explicitly @revoked for this host */
    KHOSTS_MATCH_UNKNOWN  = 3   /* no entry for this host — TOFU decision */
} gut_khosts_match;

/* Open and parse a known_hosts file. Returns 0 even if the file
 * doesn't exist (you'll get an empty entry set and every lookup
 * returns KHOSTS_MATCH_UNKNOWN). Returns non-zero only on actual
 * parse / alloc errors. */
unsigned long khosts_open(gut_khosts **out, const char *path);

/* Free a parsed known_hosts handle. */
unsigned long khosts_close(gut_khosts *k);

/* Look up an ed25519 host key for (host, port) against the parsed
 * entries. `server_pub` is the 32-byte raw ed25519 pubkey the server
 * advertised.
 *
 * Match logic:
 *   1. For each entry, evaluate its pattern list:
 *      - exact match (case-insensitive) on the host, with or without
 *        port bracketing
 *      - wildcard matches via fnmatch-style * and ?
 *      - hashed entries via HMAC-SHA1(salt, host[:port])
 *      - negation patterns remove candidates
 *   2. If an @revoked entry matches — return KHOSTS_MATCH_REVOKED
 *      regardless of key value
 *   3. For remaining ssh-ed25519 entries that match, compare the
 *      pubkey bytes:
 *        - bytes equal → KHOSTS_MATCH_PINNED
 *        - bytes differ → KHOSTS_MATCH_MISMATCH
 *   4. If no entry matched the host at all → KHOSTS_MATCH_UNKNOWN
 *
 * Port handling: OpenSSH only includes the port in the entry when it
 * differs from 22. A plain "github.com" entry matches any port; an
 * entry "[github.com]:2222" matches only port 2222. */
unsigned long khosts_lookup_ed25519(gut_khosts_match *match_out,
                                    gut_khosts *k,
                                    const char *host,
                                    u16 port,
                                    const u8 *server_pub);

/* Append a new entry for (host, port, ed25519 pubkey) to a known_hosts
 * file. Used to implement TOFU on first connection: after a handshake
 * where lookup returned KHOSTS_MATCH_UNKNOWN and the user (or policy)
 * decided to accept the key, call this to pin it for future lookups.
 *
 * Format written:
 *   <host>[:port] ssh-ed25519 <base64-blob>\n
 *
 * Where <base64-blob> is the base64 of the SSH wire blob:
 *   string "ssh-ed25519" || string pubkey(32)
 *
 * Creates the file (and its parent directory) if missing. Appends
 * (never rewrites) so existing entries survive. */
unsigned long khosts_append_ed25519(const char *path,
                                    const char *host,
                                    u16 port,
                                    const u8 *server_pub);

/* Resolve the default known_hosts path for this user. Writes the
 * full absolute path into `out`. On Windows, resolves via USERPROFILE
 * or HOMEDRIVE+HOMEPATH if HOME isn't set. Returns 0 on success. */
unsigned long khosts_default_path(char *out, u64 out_size);

#endif /* GUT_KNOWN_HOSTS_H */
