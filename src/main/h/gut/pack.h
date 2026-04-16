#ifndef GUT_PACK_H
#define GUT_PACK_H

#include "gut/types.h"
#include "gut/oid.h"
#include "gut/object.h"
#include "apennines/buf.h"

/*
 * Git packfile format (v2):
 *
 * .pack file:
 *   Header: "PACK" (4) + version (4 BE) + object_count (4 BE)
 *   Objects: each is type+size (varint) + compressed data
 *     Types 1-4: commit, tree, blob, tag (base objects)
 *     Type 6: OFS_DELTA (negative offset to base within same pack)
 *     Type 7: REF_DELTA (20-byte base OID + delta)
 *   Trailer: 20-byte SHA-1 of all preceding bytes
 *
 * .idx file (v2):
 *   Magic: ff744f63 (4) + version 2 (4 BE)
 *   Fan-out: 256 x 4-byte BE cumulative counts
 *   OID table: N x 20-byte sorted OIDs
 *   CRC32 table: N x 4-byte CRC32s
 *   Offset table: N x 4-byte offsets (MSB=1 means use 8-byte table)
 *   Large offset table: (optional) 8-byte offsets
 *   Trailer: 20-byte pack SHA-1 + 20-byte idx SHA-1
 */

#define GUT_PACK_SIGNATURE  0x5041434b  /* "PACK" */
#define GUT_PACK_VERSION    2
#define GUT_IDX_MAGIC       0xff744f63
#define GUT_IDX_VERSION     2

/* Pack type codes */
#define GUT_PACK_OBJ_COMMIT  1
#define GUT_PACK_OBJ_TREE    2
#define GUT_PACK_OBJ_BLOB    3
#define GUT_PACK_OBJ_TAG     4
#define GUT_PACK_OBJ_OFS_DELTA 6
#define GUT_PACK_OBJ_REF_DELTA 7

/* Loaded pack index */
typedef struct {
    u8  *data;          /* mmap'd or malloc'd index file contents */
    u64  data_len;
    u32  object_count;  /* total objects in pack */
    /* Pointers into data for each section */
    u32 *fanout;        /* 256 entries */
    u8  *oids;          /* object_count x 20 bytes, sorted */
    u8  *offsets;       /* object_count x 4 bytes */
    u8  *offsets64;     /* large offsets (may be NULL) */
} gut_pack_idx;

/* Loaded pack file handle */
typedef struct {
    char  path[1024];   /* path to .pack file */
    u8   *data;         /* mmap'd or malloc'd pack file contents */
    u64   data_len;
    u32   object_count;
    gut_pack_idx idx;
} gut_pack;

/* Open a pack + its index from the .pack path */
unsigned long pack_open(gut_pack *out, const char *pack_path);

/* Look up an OID in the pack index. Returns offset into pack, or sets *found=0. */
unsigned long pack_idx_lookup(u64 *offset, unsigned long *found,
                              gut_pack_idx *idx, gut_oid *oid);

/* Read an object from a pack at a given offset.
 * Handles base objects and delta reconstruction. */
unsigned long pack_read_object(gut_object *out, gut_pack *pack, u64 offset);

/* Close pack and free resources */
unsigned long pack_close(gut_pack *pack);

#endif /* GUT_PACK_H */
