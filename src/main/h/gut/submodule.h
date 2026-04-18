#ifndef GUT_SUBMODULE_H
#define GUT_SUBMODULE_H

#include "gut/types.h"
#include "gut/repo.h"

/*
 * Git submodules
 * --------------
 * A submodule is a commit-sha pointer embedded in a parent tree as a
 * mode-160000 entry. The parent repo stores:
 *   - a .gitmodules file at its root listing each submodule's name, path,
 *     and fetch URL
 *   - a 160000 gitlink in the committed tree at the submodule's path,
 *     pinning it to an exact commit OID
 *
 * The submodule itself lives at two places on disk:
 *   - <parent>/<path>/            (working tree; .git is a *gitfile*)
 *   - <parent>/.git/modules/<name>/  (actual .git directory)
 *
 * The gitfile at <parent>/<path>/.git contains one line:
 *     gitdir: ../../.git/modules/<name>
 *
 * On `gut clone --recurse-submodules`, after the parent is checked out we
 * parse .gitmodules, read the pinned commit OID for each path from the
 * parent's HEAD tree, clone the URL into modules/<name>/, write the
 * gitfile, and check out the pinned commit into the submodule's
 * working tree.
 */

typedef struct {
    char *name;   /* logical name from .gitmodules section */
    char *path;   /* workdir-relative path */
    char *url;    /* fetch URL */
} gut_submodule;

/* Parse `.gitmodules` and fill an array of entries. On success returns 0
 * and writes *out / *count (caller frees via submodules_destroy).
 * If the file is missing, returns 0 with *count = 0. */
unsigned long submodules_read(gut_submodule **out, u64 *count,
                              const char *gitmodules_path);

unsigned long submodules_destroy(gut_submodule *arr, u64 count);

/* Perform the per-submodule work: clone the URL into
 * <parent>/.git/modules/<name>, write the gitfile at <parent>/<path>/.git,
 * and check out the pinned commit (obtained by walking parent->HEAD tree).
 * If `recursive` is non-zero, recurses into each submodule's own
 * .gitmodules after materialization. */
unsigned long submodules_update_all(gut_repo *parent, int recursive);

#endif /* GUT_SUBMODULE_H */
