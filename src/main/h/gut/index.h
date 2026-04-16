#ifndef GUT_INDEX_H
#define GUT_INDEX_H

#include "gut/types.h"
#include "gut/oid.h"
#include "gut/odb.h"

/*
 * Git index (version 2) binary format:
 *   Header: "DIRC" + version(4) + entry_count(4)
 *   Entries: sorted by path, each entry is:
 *     ctime_sec(4) ctime_nsec(4) mtime_sec(4) mtime_nsec(4)
 *     dev(4) ino(4) mode(4) uid(4) gid(4) file_size(4)
 *     oid(20) flags(2) path(variable, NUL-padded to 8-byte align)
 *   Trailer: SHA-1 over all preceding bytes
 */

#define GUT_INDEX_SIGNATURE  0x44495243  /* "DIRC" */
#define GUT_INDEX_VERSION    2

typedef struct {
    u32      ctime_sec;
    u32      ctime_nsec;
    u32      mtime_sec;
    u32      mtime_nsec;
    u32      dev;
    u32      ino;
    u32      mode;
    u32      uid;
    u32      gid;
    u32      file_size;
    gut_oid  oid;
    u16      flags;
    char    *path;
} gut_index_entry;

typedef struct {
    gut_index_entry *entries;
    u64              count;
    u64              capacity;
} gut_index;

/* Initialize an empty index */
unsigned long index_init(gut_index *out);

/* Read index from .git/index file */
unsigned long index_read(gut_index *out, const char *path);

/* Write index to .git/index file */
unsigned long index_write(gut_index *idx, const char *path);

/* Add or update an entry (insert sorted by path, replace if exists) */
unsigned long index_add(gut_index *idx, const char *path, gut_oid *oid,
                        u32 mode, u32 file_size, u32 mtime_sec);

/* Remove an entry by path */
unsigned long index_remove(gut_index *idx, const char *path);

/* Find an entry by path; sets *pos to the index, or count if not found */
unsigned long index_find(u64 *pos, gut_index *idx, const char *path);

/* Free all index memory */
unsigned long index_destroy(gut_index *idx);

/* Populate index from a tree OID by recursively walking subtrees.
 * Clears any existing entries first. */
unsigned long index_read_tree(gut_index *out, gut_odb *odb, gut_oid *tree_oid);

/* Build a tree hierarchy from the index and write to ODB.
 * Returns the root tree OID. */
unsigned long index_write_tree(gut_oid *out, gut_index *idx, const char *objects_dir);

#endif /* GUT_INDEX_H */
