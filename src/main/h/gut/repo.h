#ifndef GUT_REPO_H
#define GUT_REPO_H

#include "gut/types.h"
#include "gut/oid.h"
#include "gut/odb.h"

typedef struct {
    char          root_dir[1024];     /* working directory */
    char          git_dir[1024];      /* .git directory */
    gut_odb       odb;
    gut_hash_algo hash_algo;          /* read from [extensions] objectformat; SHA-1 default */
} gut_repo;

/* Initialize a new repository at the given path */
unsigned long repo_init(gut_repo *out, const char *path);

/* Open an existing repository (walks up to find .git) */
unsigned long repo_open(gut_repo *out, const char *path);

/* Read the current HEAD ref (branch name or detached OID) */
unsigned long repo_head_ref(char *out, u64 out_size, gut_repo *repo);

/* Resolve a ref name to its OID */
unsigned long repo_resolve_ref(gut_oid *out, gut_repo *repo, const char *ref);

/* Update a ref to point to a new OID.
 *
 * If `reason` is non-NULL, a reflog entry is appended to
 * `.git/logs/<ref>` (and `.git/logs/HEAD` if HEAD currently points to
 * `ref`). Pass NULL to suppress the reflog — useful only for internal
 * bookkeeping writes. Every user-facing ref mutation should pass a
 * human-readable reason ("commit: foo", "reset: moving to HEAD~",
 * "merge topic", "push", ...). */
unsigned long repo_update_ref(gut_repo *repo, const char *ref,
                              gut_oid *oid, const char *reason);

/* Append a reflog entry to `.git/logs/HEAD` without mutating any ref.
 *
 * Used when HEAD's symbolic target changes without the underlying ref
 * value changing — e.g. `gut checkout <branch>` flips HEAD from
 * `refs/heads/X` to `refs/heads/Y`, and git conventionally records that
 * as a HEAD reflog line like `checkout: moving from X to Y`. */
unsigned long repo_reflog_head(gut_repo *repo,
                               const gut_oid *old_oid,
                               const gut_oid *new_oid,
                               const char *reason);

#endif /* GUT_REPO_H */
