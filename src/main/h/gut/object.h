#ifndef GUT_OBJECT_H
#define GUT_OBJECT_H

#include "gut/types.h"
#include "gut/oid.h"
#include "apennines/buf.h"

/* Git object types */
typedef enum {
    GUT_OBJ_BLOB   = 1,
    GUT_OBJ_TREE   = 2,
    GUT_OBJ_COMMIT = 3,
    GUT_OBJ_TAG    = 4
} gut_obj_type;

/* A parsed git object (type + raw content after the header) */
typedef struct {
    gut_obj_type type;
    u64          size;
    buf          data;
} gut_object;

/* Tree entry: mode + name + oid */
typedef struct {
    u32      mode;
    char    *name;
    gut_oid  oid;
} gut_tree_entry;

/* Parsed tree: array of entries */
typedef struct {
    gut_tree_entry *entries;
    u64             count;
    u64             capacity;
} gut_tree;

/* Parsed commit */
typedef struct {
    gut_oid  tree_oid;
    gut_oid *parent_oids;
    u64      parent_count;
    char    *author;
    char    *committer;
    char    *message;
} gut_commit;

/* Return type name string for a given object type */
unsigned long obj_type_name(const char **out, gut_obj_type type);

/* Parse type name string to enum */
unsigned long obj_type_parse(gut_obj_type *out, const char *name, u64 len);

/* Serialize object content with git header: "<type> <size>\0<data>"
 * The result in out is what gets SHA-1 hashed and zlib-compressed. */
unsigned long obj_serialize(buf *out, gut_obj_type type, u8 *data, u64 len);

/* Parse a raw object (header + data) into its type, size, and content */
unsigned long obj_parse_header(gut_obj_type *type, u64 *content_size, u8 **content,
                               u8 *raw, u64 raw_len);

/* Compute the SHA-1 OID of an object given its type and content.
 * Also zeroes bytes[20..31] so the result compares cleanly against wide
 * OID buffers. */
unsigned long obj_hash(gut_oid *out, gut_obj_type type, u8 *data, u64 len);

/* Compute the SHA-256 OID of an object. Fills all 32 bytes. */
unsigned long obj_hash_sha256(gut_oid *out, gut_obj_type type,
                              u8 *data, u64 len);

/* Dispatch by repo's hash algorithm. */
unsigned long obj_hash_algo(gut_oid *out, gut_hash_algo algo,
                            gut_obj_type type, u8 *data, u64 len);

/* Parse tree object data into structured entries.
 * `tree_parse` assumes SHA-1 OIDs (20 bytes); `tree_parse_algo` takes the
 * repo's hash algorithm so it can read 32-byte OIDs for SHA-256 trees. */
unsigned long tree_parse(gut_tree *out, u8 *data, u64 len);
unsigned long tree_parse_algo(gut_tree *out, u8 *data, u64 len,
                              gut_hash_algo algo);

/* Free tree entries */
unsigned long tree_destroy(gut_tree *tree);

/* Add an entry to a tree (for building trees) */
unsigned long tree_add_entry(gut_tree *tree, u32 mode, const char *name, gut_oid *oid);

/* Serialize tree entries into git tree object data format */
unsigned long tree_serialize(buf *out, gut_tree *tree);

/* Parse commit object data */
unsigned long commit_parse(gut_commit *out, u8 *data, u64 len);

/* Free commit fields */
unsigned long commit_destroy(gut_commit *commit);

/* Free a gut_object */
unsigned long object_destroy(gut_object *obj);

#endif /* GUT_OBJECT_H */
