#ifndef GUT_OID_H
#define GUT_OID_H

#include "gut/types.h"
#include "gut/sha1.h"

/* SHA-1 sizes (the historical default). Retained so existing code that
 * uses these constants keeps working unchanged. */
#define GUT_OID_RAW_SIZE  GUT_SHA1_DIGEST_SIZE   /* 20 */
#define GUT_OID_HEX_SIZE  (GUT_OID_RAW_SIZE * 2) /* 40 */

/* SHA-256 sizes — used when repo is SHA-256. */
#define GUT_OID_SHA256_RAW_SIZE  32
#define GUT_OID_SHA256_HEX_SIZE  64

/* Widest OID we can ever carry. Buffer sizing for algo-agnostic code. */
#define GUT_OID_MAX_RAW_SIZE  GUT_OID_SHA256_RAW_SIZE
#define GUT_OID_MAX_HEX_SIZE  GUT_OID_SHA256_HEX_SIZE

/* Hash algorithms supported by gut. */
typedef enum {
    GUT_HASH_SHA1   = 1,
    GUT_HASH_SHA256 = 2
} gut_hash_algo;

/* Return the raw byte size for an algo. */
static inline unsigned gut_oid_raw_size(gut_hash_algo a) {
    return (a == GUT_HASH_SHA256) ? GUT_OID_SHA256_RAW_SIZE : GUT_OID_RAW_SIZE;
}
static inline unsigned gut_oid_hex_size(gut_hash_algo a) {
    return (a == GUT_HASH_SHA256) ? GUT_OID_SHA256_HEX_SIZE : GUT_OID_HEX_SIZE;
}

/* OID buffer is wide enough for SHA-256. SHA-1 usage touches only the
 * first 20 bytes; the remaining bytes are unused but zeroed. */
typedef struct {
    u8 bytes[GUT_OID_MAX_RAW_SIZE];
} gut_oid;

/* Format 20 raw bytes as 40-char hex string (out must hold >= 41 bytes).
 * This is the SHA-1 API — for wider OIDs use oid_to_hex_n. */
unsigned long oid_to_hex(char *out, gut_oid *oid);

/* Parse 40-char hex string into the first 20 bytes. */
unsigned long oid_from_hex(gut_oid *out, const char *hex);

/* Algo-aware variants. n = hex chars on the `hex` side, raw bytes = n/2. */
unsigned long oid_to_hex_n(char *out, gut_oid *oid, unsigned n);
unsigned long oid_from_hex_n(gut_oid *out, const char *hex, unsigned n);

/* Compare two OIDs (SHA-1 — first 20 bytes only) */
unsigned long oid_compare(long *result, gut_oid *a, gut_oid *b);

/* Check if OID is all zeros (first 20 bytes) */
unsigned long oid_is_zero(unsigned long *result, gut_oid *oid);

/* Compute OID (SHA-1) over arbitrary data */
unsigned long oid_hash(gut_oid *out, const u8 *data, u64 len);

/* Extract first two hex chars (for object path: objects/ab/cd...) */
unsigned long oid_path_prefix(char *out2, gut_oid *oid);

/* Remaining 38 hex chars */
unsigned long oid_path_suffix(char *out38, gut_oid *oid);

#endif /* GUT_OID_H */
