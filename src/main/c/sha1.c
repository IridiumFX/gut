#include "gut/sha1.h"
#include <string.h>

/* SHA-1 (FIPS 180-4) */

static u32 rotl32(u32 x, u32 n) {
    return (x << n) | (x >> (32 - n));
}

static void sha1_transform(u32 state[5], const u8 block[64]) {
    u32 w[80];
    u32 a, b, c, d, e;
    u32 i, f, k, temp;

    for (i = 0; i < 16; i++) {
        w[i] = ((u32)block[i * 4] << 24) |
               ((u32)block[i * 4 + 1] << 16) |
               ((u32)block[i * 4 + 2] << 8) |
               ((u32)block[i * 4 + 3]);
    }
    for (i = 16; i < 80; i++) {
        w[i] = rotl32(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
    }

    a = state[0];
    b = state[1];
    c = state[2];
    d = state[3];
    e = state[4];

    for (i = 0; i < 80; i++) {
        if (i < 20) {
            f = (b & c) | ((~b) & d);
            k = 0x5A827999;
        } else if (i < 40) {
            f = b ^ c ^ d;
            k = 0x6ED9EBA1;
        } else if (i < 60) {
            f = (b & c) | (b & d) | (c & d);
            k = 0x8F1BBCDC;
        } else {
            f = b ^ c ^ d;
            k = 0xCA62C1D6;
        }

        temp = rotl32(a, 5) + f + e + k + w[i];
        e = d;
        d = c;
        c = rotl32(b, 30);
        b = a;
        a = temp;
    }

    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;
}

unsigned long sha1_init(sha1_ctx *ctx) {
    if (!ctx) return __LINE__;
    ctx->state[0] = 0x67452301;
    ctx->state[1] = 0xEFCDAB89;
    ctx->state[2] = 0x98BADCFE;
    ctx->state[3] = 0x10325476;
    ctx->state[4] = 0xC3D2E1F0;
    ctx->count = 0;
    memset(ctx->buf, 0, GUT_SHA1_BLOCK_SIZE);
    return 0;
}

unsigned long sha1_update(sha1_ctx *ctx, const u8 *data, u64 len) {
    u64 buffered;
    u64 i;

    if (!ctx) return __LINE__;
    if (len > 0 && !data) return __LINE__;

    buffered = ctx->count % GUT_SHA1_BLOCK_SIZE;
    ctx->count += len;
    i = 0;

    if (buffered > 0) {
        u64 space = GUT_SHA1_BLOCK_SIZE - buffered;
        if (len >= space) {
            memcpy(ctx->buf + buffered, data, (size_t)space);
            sha1_transform(ctx->state, ctx->buf);
            i = space;
        } else {
            memcpy(ctx->buf + buffered, data, (size_t)len);
            return 0;
        }
    }

    for (; i + GUT_SHA1_BLOCK_SIZE <= len; i += GUT_SHA1_BLOCK_SIZE) {
        sha1_transform(ctx->state, data + i);
    }

    if (i < len) {
        memcpy(ctx->buf, data + i, (size_t)(len - i));
    }

    return 0;
}

unsigned long sha1_final(u8 *out, sha1_ctx *ctx) {
    u64 total_bits;
    u64 buffered;
    u32 i;

    if (!out) return __LINE__;
    if (!ctx) return __LINE__;

    total_bits = ctx->count * 8;
    buffered = ctx->count % GUT_SHA1_BLOCK_SIZE;

    /* Padding: append 0x80, then zeros, then 64-bit big-endian bit count */
    ctx->buf[buffered++] = 0x80;

    if (buffered > 56) {
        memset(ctx->buf + buffered, 0, (size_t)(GUT_SHA1_BLOCK_SIZE - buffered));
        sha1_transform(ctx->state, ctx->buf);
        buffered = 0;
    }

    memset(ctx->buf + buffered, 0, (size_t)(56 - buffered));

    ctx->buf[56] = (u8)(total_bits >> 56);
    ctx->buf[57] = (u8)(total_bits >> 48);
    ctx->buf[58] = (u8)(total_bits >> 40);
    ctx->buf[59] = (u8)(total_bits >> 32);
    ctx->buf[60] = (u8)(total_bits >> 24);
    ctx->buf[61] = (u8)(total_bits >> 16);
    ctx->buf[62] = (u8)(total_bits >> 8);
    ctx->buf[63] = (u8)(total_bits);

    sha1_transform(ctx->state, ctx->buf);

    for (i = 0; i < 5; i++) {
        out[i * 4]     = (u8)(ctx->state[i] >> 24);
        out[i * 4 + 1] = (u8)(ctx->state[i] >> 16);
        out[i * 4 + 2] = (u8)(ctx->state[i] >> 8);
        out[i * 4 + 3] = (u8)(ctx->state[i]);
    }

    memset(ctx, 0, sizeof(*ctx));
    return 0;
}

unsigned long sha1_digest(u8 *out, const u8 *data, u64 len) {
    sha1_ctx ctx;
    unsigned long rc;

    if (!out) return __LINE__;

    rc = sha1_init(&ctx);
    if (rc) return __LINE__;

    rc = sha1_update(&ctx, data, len);
    if (rc) return __LINE__;

    rc = sha1_final(out, &ctx);
    if (rc) return __LINE__;

    return 0;
}
