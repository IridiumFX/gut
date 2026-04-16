#ifndef GUT_SHA1_H
#define GUT_SHA1_H

#include "gut/types.h"

#define GUT_SHA1_DIGEST_SIZE 20
#define GUT_SHA1_BLOCK_SIZE  64

typedef struct {
    u32 state[5];
    u64 count;
    u8  buf[GUT_SHA1_BLOCK_SIZE];
} sha1_ctx;

unsigned long sha1_init(sha1_ctx *ctx);
unsigned long sha1_update(sha1_ctx *ctx, const u8 *data, u64 len);
unsigned long sha1_final(u8 *out, sha1_ctx *ctx);
unsigned long sha1_digest(u8 *out, const u8 *data, u64 len);

#endif /* GUT_SHA1_H */
