#ifndef GUT_ODB_H
#define GUT_ODB_H

#include "gut/types.h"
#include "gut/oid.h"
#include "gut/object.h"
#include "apennines/buf.h"

/* Object database: reads/writes loose objects under .git/objects/ */

#define GUT_ODB_MAX_PACKS 16

typedef struct {
    char          objects_dir[1024];
    void         *packs[GUT_ODB_MAX_PACKS]; /* gut_pack pointers, cast in odb.c */
    u32           pack_count;
    u32           packs_loaded;
    gut_hash_algo hash_algo;  /* default SHA-1; repo_open sets this from .git/config */
} gut_odb;

/* Initialize ODB with the path to the objects directory (e.g., ".git/objects") */
unsigned long odb_open(gut_odb *out, const char *objects_dir);

/* Check if an object exists */
unsigned long odb_exists(unsigned long *found, gut_odb *odb, gut_oid *oid);

/* Read an object from the database */
unsigned long odb_read(gut_object *out, gut_odb *odb, gut_oid *oid);

/* Write an object to the database; computes and returns its OID */
unsigned long odb_write(gut_oid *out, gut_odb *odb, gut_obj_type type, u8 *data, u64 len);

/* Write a raw blob from a file path */
unsigned long odb_write_file(gut_oid *out, gut_odb *odb, const char *path);

/* Build the filesystem path for a loose object */
unsigned long odb_object_path(char *out, u64 out_size, gut_odb *odb, gut_oid *oid);

/* Resolve a short hex prefix (minimum 4 chars) to a full OID.
 * Returns 0 on unique match, error if ambiguous or not found. */
unsigned long odb_resolve_prefix(gut_oid *out, gut_odb *odb, const char *prefix);

/* Look up a blob OID by path in a tree hierarchy */
unsigned long tree_lookup_path(gut_oid *out, gut_odb *odb,
                               gut_oid *tree_oid, const char *path);

#endif /* GUT_ODB_H */
