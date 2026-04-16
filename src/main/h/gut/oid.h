#ifndef GUT_OID_H
#define GUT_OID_H

#include "gut/types.h"
#include "gut/sha1.h"

#define GUT_OID_RAW_SIZE  GUT_SHA1_DIGEST_SIZE   /* 20 */
#define GUT_OID_HEX_SIZE  (GUT_OID_RAW_SIZE * 2) /* 40 */

typedef struct {
    u8 bytes[GUT_OID_RAW_SIZE];
} gut_oid;

/* Format 20 raw bytes as 40-char hex string (out must hold >= 41 bytes) */
unsigned long oid_to_hex(char *out, gut_oid *oid);

/* Parse 40-char hex string into raw bytes */
unsigned long oid_from_hex(gut_oid *out, const char *hex);

/* Compare two OIDs: *result < 0, == 0, > 0 */
unsigned long oid_compare(long *result, gut_oid *a, gut_oid *b);

/* Check if OID is all zeros */
unsigned long oid_is_zero(unsigned long *result, gut_oid *oid);

/* Compute OID (SHA-1) over arbitrary data */
unsigned long oid_hash(gut_oid *out, const u8 *data, u64 len);

/* Extract first two hex chars (for object path: objects/ab/cd...) */
unsigned long oid_path_prefix(char *out2, gut_oid *oid);

/* Remaining 38 hex chars */
unsigned long oid_path_suffix(char *out38, gut_oid *oid);

#endif /* GUT_OID_H */
