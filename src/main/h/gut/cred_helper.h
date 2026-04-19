#ifndef GUT_CRED_HELPER_H
#define GUT_CRED_HELPER_H

#include "gut/types.h"

/*
 * Git credential-helper protocol client (get side only for MVP).
 *
 * The helper is an external program (e.g. git-credential-manager-core,
 * git-credential-osxkeychain, git-credential-libsecret) that talks a
 * simple stdin/stdout key=value protocol per gitcredentials(7).
 *
 * Helper-name resolution mirrors git:
 *   - Starts with '/' or drive letter  → absolute path; run directly
 *   - Otherwise                         → "git-credential-<name>" on
 *                                         PATH (we rely on the OS
 *                                         PATH resolver)
 *
 * We deliberately do NOT handle git's "!<shell-cmd>" form for MVP —
 * the shell-exec path has injection surface that deserves its own
 * scrutiny. If/when a user surfaces a real need for it, we gate it
 * behind a config/env opt-in.
 *
 * Store and erase operations are follow-ups; shipping `get` first
 * unblocks the common case (cached credential → HTTPS clone/fetch/push
 * without re-authentication).
 */

/* Input to a credential lookup. `path` and `username` are optional. */
typedef struct {
    char protocol[32];   /* "https", "http", "ssh" */
    char host[256];      /* "github.com" */
    char path[512];      /* "user/repo" — optional, empty = not set */
    char username[256];  /* pre-filled if the URL had user@host syntax */
} gut_cred_request;

typedef struct {
    char username[256];
    char password[512];
} gut_cred_response;

/* Invoke `helper_name` with the `get` subcommand.
 *
 * Returns 0 with `out` populated on success; non-zero if the helper
 * is missing, failed to spawn, exited non-zero, or didn't return
 * both `username=` and `password=` lines.
 *
 * Helper name resolution:
 *   "manager-core"  -> git-credential-manager-core (via PATH)
 *   "/abs/path/to/helper" -> runs the path directly
 *   starts with "!" -> rejected for MVP (shell-exec deferred)
 */
unsigned long cred_helper_get(gut_cred_response *out,
                              const char *helper_name,
                              const gut_cred_request *req);

/* Read `credential.helper` from `<git_dir>/config`. Writes the helper
 * name into `out`. Returns 0 on success, non-zero if the key isn't
 * set or the config can't be read. */
unsigned long cred_helper_from_config(char *out, u64 out_sz,
                                      const char *git_dir);

/* Parse a URL like "https://github.com/user/repo" into the fields of
 * a gut_cred_request. The `username` field is filled if the URL
 * contains `user@host` syntax; otherwise left empty. Returns 0 on
 * success. */
unsigned long cred_request_from_url(gut_cred_request *out, const char *url);

#endif /* GUT_CRED_HELPER_H */
