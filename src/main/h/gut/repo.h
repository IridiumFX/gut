#ifndef GUT_REPO_H
#define GUT_REPO_H

#include "gut/types.h"
#include "gut/odb.h"

typedef struct {
    char     root_dir[1024];     /* working directory */
    char     git_dir[1024];      /* .git directory */
    gut_odb  odb;
} gut_repo;

/* Initialize a new repository at the given path */
unsigned long repo_init(gut_repo *out, const char *path);

/* Open an existing repository (walks up to find .git) */
unsigned long repo_open(gut_repo *out, const char *path);

/* Read the current HEAD ref (branch name or detached OID) */
unsigned long repo_head_ref(char *out, u64 out_size, gut_repo *repo);

/* Resolve a ref name to its OID */
unsigned long repo_resolve_ref(gut_oid *out, gut_repo *repo, const char *ref);

/* Update a ref to point to a new OID */
unsigned long repo_update_ref(gut_repo *repo, const char *ref, gut_oid *oid);

#endif /* GUT_REPO_H */
