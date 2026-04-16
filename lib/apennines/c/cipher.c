#include "apennines/cipher.h"
#include <string.h>

/* ================================================================
 *  Constant-time helpers
 * ================================================================ */

static u8 ct_byte_eq(u8 a, u8 b) {
    u32 d = (u32)(a ^ b);
    d = (d - 1) >> 8;
    return (u8)(d & 1);
}

static void ct_memcmp_16(unsigned long *result, const u8 *a, const u8 *b) {
    volatile u8 acc = 0;
    for (int i = 0; i < 16; i++) {
        acc |= (u8)(a[i] ^ b[i]);
    }
    *result = (acc == 0) ? 0UL : 1UL;
}

/* ================================================================
 *  AES S-Box / inverse S-Box
 * ================================================================ */

static const u8 SBOX[256] = {
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
};

static const u8 INV_SBOX[256] = {
    0x52,0x09,0x6a,0xd5,0x30,0x36,0xa5,0x38,0xbf,0x40,0xa3,0x9e,0x81,0xf3,0xd7,0xfb,
    0x7c,0xe3,0x39,0x82,0x9b,0x2f,0xff,0x87,0x34,0x8e,0x43,0x44,0xc4,0xde,0xe9,0xcb,
    0x54,0x7b,0x94,0x32,0xa6,0xc2,0x23,0x3d,0xee,0x4c,0x95,0x0b,0x42,0xfa,0xc3,0x4e,
    0x08,0x2e,0xa1,0x66,0x28,0xd9,0x24,0xb2,0x76,0x5b,0xa2,0x49,0x6d,0x8b,0xd1,0x25,
    0x72,0xf8,0xf6,0x64,0x86,0x68,0x98,0x16,0xd4,0xa4,0x5c,0xcc,0x5d,0x65,0xb6,0x92,
    0x6c,0x70,0x48,0x50,0xfd,0xed,0xb9,0xda,0x5e,0x15,0x46,0x57,0xa7,0x8d,0x9d,0x84,
    0x90,0xd8,0xab,0x00,0x8c,0xbc,0xd3,0x0a,0xf7,0xe4,0x58,0x05,0xb8,0xb3,0x45,0x06,
    0xd0,0x2c,0x1e,0x8f,0xca,0x3f,0x0f,0x02,0xc1,0xaf,0xbd,0x03,0x01,0x13,0x8a,0x6b,
    0x3a,0x91,0x11,0x41,0x4f,0x67,0xdc,0xea,0x97,0xf2,0xcf,0xce,0xf0,0xb4,0xe6,0x73,
    0x96,0xac,0x74,0x22,0xe7,0xad,0x35,0x85,0xe2,0xf9,0x37,0xe8,0x1c,0x75,0xdf,0x6e,
    0x47,0xf1,0x1a,0x71,0x1d,0x29,0xc5,0x89,0x6f,0xb7,0x62,0x0e,0xaa,0x18,0xbe,0x1b,
    0xfc,0x56,0x3e,0x4b,0xc6,0xd2,0x79,0x20,0x9a,0xdb,0xc0,0xfe,0x78,0xcd,0x5a,0xf4,
    0x1f,0xdd,0xa8,0x33,0x88,0x07,0xc7,0x31,0xb1,0x12,0x10,0x59,0x27,0x80,0xec,0x5f,
    0x60,0x51,0x7f,0xa9,0x19,0xb5,0x4a,0x0d,0x2d,0xe5,0x7a,0x9f,0x93,0xc9,0x9c,0xef,
    0xa0,0xe0,0x3b,0x4d,0xae,0x2a,0xf5,0xb0,0xc8,0xeb,0xbb,0x3c,0x83,0x53,0x99,0x61,
    0x17,0x2b,0x04,0x7e,0xba,0x77,0xd6,0x26,0xe1,0x69,0x14,0x63,0x55,0x21,0x0c,0x7d
};

/* ================================================================
 *  T-tables for encryption
 * ================================================================ */

static u32 te_entry(u8 s) {
    u32 s2 = (((u32)s << 1) ^ (((u32)s >> 7) * 0x1b)) & 0xff;
    u32 s3 = s2 ^ (u32)s;
    return (s2 << 24) | ((u32)s << 16) | ((u32)s << 8) | s3;
}

static u32 TE0(u8 i) { return te_entry(SBOX[i]); }
static u32 TE1(u8 i) { u32 v = te_entry(SBOX[i]); return (v >> 8)  | (v << 24); }
static u32 TE2(u8 i) { u32 v = te_entry(SBOX[i]); return (v >> 16) | (v << 16); }
static u32 TE3(u8 i) { u32 v = te_entry(SBOX[i]); return (v >> 24) | (v << 8);  }

/* ================================================================
 *  T-tables for decryption
 * ================================================================ */

static u32 td_entry(u8 s) {
    u32 s2 = (((u32)s << 1) ^ (((u32)s >> 7) * 0x1b)) & 0xff;
    u32 s4 = ((s2 << 1) ^ ((s2 >> 7) * 0x1b)) & 0xff;
    u32 s8 = ((s4 << 1) ^ ((s4 >> 7) * 0x1b)) & 0xff;
    u32 se = s2 ^ s4 ^ s8;
    u32 s9 = s8 ^ (u32)s;
    u32 sd = s4 ^ s8 ^ (u32)s;
    u32 sb = s2 ^ s8 ^ (u32)s;
    return (se << 24) | (s9 << 16) | (sd << 8) | sb;
}

static u32 TD0(u8 i) { return td_entry(INV_SBOX[i]); }
static u32 TD1(u8 i) { u32 v = td_entry(INV_SBOX[i]); return (v >> 8)  | (v << 24); }
static u32 TD2(u8 i) { u32 v = td_entry(INV_SBOX[i]); return (v >> 16) | (v << 16); }
static u32 TD3(u8 i) { u32 v = td_entry(INV_SBOX[i]); return (v >> 24) | (v << 8);  }

/* ================================================================
 *  Byte/word helpers (big-endian for AES state words)
 * ================================================================ */

static u32 load_be32(const u8 *p) {
    return ((u32)p[0] << 24) | ((u32)p[1] << 16) | ((u32)p[2] << 8) | (u32)p[3];
}

static void store_be32(u8 *p, u32 v) {
    p[0] = (u8)(v >> 24);
    p[1] = (u8)(v >> 16);
    p[2] = (u8)(v >> 8);
    p[3] = (u8)v;
}

/* ================================================================
 *  Round constants
 * ================================================================ */

static const u8 RCON[10] = {
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
};

/* ================================================================
 *  Key expansion
 * ================================================================ */

static void aes_key_expand_enc(u32 *rk, const u8 *key, int nk, int nr) {
    int i;
    int total = 4 * (nr + 1);

    for (i = 0; i < nk; i++) {
        rk[i] = load_be32(key + 4 * i);
    }

    for (i = nk; i < total; i++) {
        u32 tmp = rk[i - 1];
        if (i % nk == 0) {
            tmp = ((u32)SBOX[(tmp >> 16) & 0xff] << 24) |
                  ((u32)SBOX[(tmp >>  8) & 0xff] << 16) |
                  ((u32)SBOX[(tmp)       & 0xff] <<  8) |
                  ((u32)SBOX[(tmp >> 24) & 0xff]);
            tmp ^= ((u32)RCON[i / nk - 1] << 24);
        } else if (nk > 6 && (i % nk == 4)) {
            tmp = ((u32)SBOX[(tmp >> 24) & 0xff] << 24) |
                  ((u32)SBOX[(tmp >> 16) & 0xff] << 16) |
                  ((u32)SBOX[(tmp >>  8) & 0xff] <<  8) |
                  ((u32)SBOX[(tmp)       & 0xff]);
        }
        rk[i] = rk[i - nk] ^ tmp;
    }
}

static void aes_key_expand_dec(u32 *dec_rk, const u32 *enc_rk, int nr) {
    int i, j;
    int total = 4 * (nr + 1);

    /* first and last round keys are the same */
    for (j = 0; j < 4; j++) {
        dec_rk[j] = enc_rk[(nr * 4) + j];
        dec_rk[(nr * 4) + j] = enc_rk[j];
    }

    /* middle rounds: apply InvMixColumns */
    for (i = 1; i < nr; i++) {
        for (j = 0; j < 4; j++) {
            u32 w = enc_rk[i * 4 + j];
            u8 b0 = (u8)(w >> 24);
            u8 b1 = (u8)(w >> 16);
            u8 b2 = (u8)(w >> 8);
            u8 b3 = (u8)w;
            /* use TD tables with SBOX to get InvMixColumns of the round key */
            dec_rk[(nr - i) * 4 + j] =
                TD0(SBOX[b0]) ^ TD1(SBOX[b1]) ^ TD2(SBOX[b2]) ^ TD3(SBOX[b3]);
        }
    }

    (void)total;
}

/* ================================================================
 *  AES init / destroy
 * ================================================================ */

unsigned long aes128_init(aes_ctx *ctx, const u8 *key16) {
    if (!ctx)   return 1;
    if (!key16) return 2;

    ctx->nr = 10;
    aes_key_expand_enc(ctx->enc_rk, key16, 4, 10);
    aes_key_expand_dec(ctx->dec_rk, ctx->enc_rk, 10);
    return 0;
}

unsigned long aes256_init(aes_ctx *ctx, const u8 *key32) {
    if (!ctx)   return 1;
    if (!key32) return 2;

    ctx->nr = 14;
    aes_key_expand_enc(ctx->enc_rk, key32, 8, 14);
    aes_key_expand_dec(ctx->dec_rk, ctx->enc_rk, 14);
    return 0;
}

unsigned long aes_destroy(aes_ctx *ctx) {
    if (!ctx) return 1;
    volatile u8 *p = (volatile u8 *)ctx;
    for (unsigned long i = 0; i < sizeof(aes_ctx); i++) {
        p[i] = 0;
    }
    return 0;
}

/* ================================================================
 *  AES single-block encrypt (T-table)
 * ================================================================ */

static void aes_encrypt_block(u8 *out, const u32 *rk, int nr, const u8 *in) {
    u32 s0 = load_be32(in)      ^ rk[0];
    u32 s1 = load_be32(in + 4)  ^ rk[1];
    u32 s2 = load_be32(in + 8)  ^ rk[2];
    u32 s3 = load_be32(in + 12) ^ rk[3];
    u32 t0, t1, t2, t3;

    int r;
    const u32 *rkp = rk + 4;
    for (r = 1; r < nr; r++, rkp += 4) {
        t0 = TE0((u8)(s0 >> 24)) ^ TE1((u8)(s1 >> 16)) ^ TE2((u8)(s2 >> 8)) ^ TE3((u8)s3) ^ rkp[0];
        t1 = TE0((u8)(s1 >> 24)) ^ TE1((u8)(s2 >> 16)) ^ TE2((u8)(s3 >> 8)) ^ TE3((u8)s0) ^ rkp[1];
        t2 = TE0((u8)(s2 >> 24)) ^ TE1((u8)(s3 >> 16)) ^ TE2((u8)(s0 >> 8)) ^ TE3((u8)s1) ^ rkp[2];
        t3 = TE0((u8)(s3 >> 24)) ^ TE1((u8)(s0 >> 16)) ^ TE2((u8)(s1 >> 8)) ^ TE3((u8)s2) ^ rkp[3];
        s0 = t0; s1 = t1; s2 = t2; s3 = t3;
    }

    /* last round: no MixColumns, just SubBytes + ShiftRows + AddRoundKey */
    t0 = ((u32)SBOX[(s0 >> 24)] << 24) | ((u32)SBOX[(s1 >> 16) & 0xff] << 16) |
         ((u32)SBOX[(s2 >> 8) & 0xff] << 8) | (u32)SBOX[s3 & 0xff];
    t1 = ((u32)SBOX[(s1 >> 24)] << 24) | ((u32)SBOX[(s2 >> 16) & 0xff] << 16) |
         ((u32)SBOX[(s3 >> 8) & 0xff] << 8) | (u32)SBOX[s0 & 0xff];
    t2 = ((u32)SBOX[(s2 >> 24)] << 24) | ((u32)SBOX[(s3 >> 16) & 0xff] << 16) |
         ((u32)SBOX[(s0 >> 8) & 0xff] << 8) | (u32)SBOX[s1 & 0xff];
    t3 = ((u32)SBOX[(s3 >> 24)] << 24) | ((u32)SBOX[(s0 >> 16) & 0xff] << 16) |
         ((u32)SBOX[(s1 >> 8) & 0xff] << 8) | (u32)SBOX[s2 & 0xff];

    store_be32(out,      t0 ^ rkp[0]);
    store_be32(out + 4,  t1 ^ rkp[1]);
    store_be32(out + 8,  t2 ^ rkp[2]);
    store_be32(out + 12, t3 ^ rkp[3]);
}

/* ================================================================
 *  AES single-block decrypt (T-table)
 * ================================================================ */

static void aes_decrypt_block(u8 *out, const u32 *rk, int nr, const u8 *in) {
    u32 s0 = load_be32(in)      ^ rk[0];
    u32 s1 = load_be32(in + 4)  ^ rk[1];
    u32 s2 = load_be32(in + 8)  ^ rk[2];
    u32 s3 = load_be32(in + 12) ^ rk[3];
    u32 t0, t1, t2, t3;

    int r;
    const u32 *rkp = rk + 4;
    for (r = 1; r < nr; r++, rkp += 4) {
        t0 = TD0((u8)(s0 >> 24)) ^ TD1((u8)(s3 >> 16)) ^ TD2((u8)(s2 >> 8)) ^ TD3((u8)s1) ^ rkp[0];
        t1 = TD0((u8)(s1 >> 24)) ^ TD1((u8)(s0 >> 16)) ^ TD2((u8)(s3 >> 8)) ^ TD3((u8)s2) ^ rkp[1];
        t2 = TD0((u8)(s2 >> 24)) ^ TD1((u8)(s1 >> 16)) ^ TD2((u8)(s0 >> 8)) ^ TD3((u8)s3) ^ rkp[2];
        t3 = TD0((u8)(s3 >> 24)) ^ TD1((u8)(s2 >> 16)) ^ TD2((u8)(s1 >> 8)) ^ TD3((u8)s0) ^ rkp[3];
        s0 = t0; s1 = t1; s2 = t2; s3 = t3;
    }

    /* last round: InvSubBytes + InvShiftRows + AddRoundKey */
    t0 = ((u32)INV_SBOX[(s0 >> 24)] << 24) | ((u32)INV_SBOX[(s3 >> 16) & 0xff] << 16) |
         ((u32)INV_SBOX[(s2 >> 8) & 0xff] << 8) | (u32)INV_SBOX[s1 & 0xff];
    t1 = ((u32)INV_SBOX[(s1 >> 24)] << 24) | ((u32)INV_SBOX[(s0 >> 16) & 0xff] << 16) |
         ((u32)INV_SBOX[(s3 >> 8) & 0xff] << 8) | (u32)INV_SBOX[s2 & 0xff];
    t2 = ((u32)INV_SBOX[(s2 >> 24)] << 24) | ((u32)INV_SBOX[(s1 >> 16) & 0xff] << 16) |
         ((u32)INV_SBOX[(s0 >> 8) & 0xff] << 8) | (u32)INV_SBOX[s3 & 0xff];
    t3 = ((u32)INV_SBOX[(s3 >> 24)] << 24) | ((u32)INV_SBOX[(s2 >> 16) & 0xff] << 16) |
         ((u32)INV_SBOX[(s1 >> 8) & 0xff] << 8) | (u32)INV_SBOX[s0 & 0xff];

    store_be32(out,      t0 ^ rkp[0]);
    store_be32(out + 4,  t1 ^ rkp[1]);
    store_be32(out + 8,  t2 ^ rkp[2]);
    store_be32(out + 12, t3 ^ rkp[3]);
}

/* ================================================================
 *  ECB public API
 * ================================================================ */

unsigned long aes128_ecb_encrypt(u8 *out16, const aes_ctx *ctx, const u8 *in16) {
    if (!out16) return 1;
    if (!ctx)   return 2;
    if (!in16)  return 3;
    if (ctx->nr != 10) return 4;
    aes_encrypt_block(out16, ctx->enc_rk, 10, in16);
    return 0;
}

unsigned long aes128_ecb_decrypt(u8 *out16, const aes_ctx *ctx, const u8 *in16) {
    if (!out16) return 1;
    if (!ctx)   return 2;
    if (!in16)  return 3;
    if (ctx->nr != 10) return 4;
    aes_decrypt_block(out16, ctx->dec_rk, 10, in16);
    return 0;
}

unsigned long aes256_ecb_encrypt(u8 *out16, const aes_ctx *ctx, const u8 *in16) {
    if (!out16) return 1;
    if (!ctx)   return 2;
    if (!in16)  return 3;
    if (ctx->nr != 14) return 4;
    aes_encrypt_block(out16, ctx->enc_rk, 14, in16);
    return 0;
}

unsigned long aes256_ecb_decrypt(u8 *out16, const aes_ctx *ctx, const u8 *in16) {
    if (!out16) return 1;
    if (!ctx)   return 2;
    if (!in16)  return 3;
    if (ctx->nr != 14) return 4;
    aes_decrypt_block(out16, ctx->dec_rk, 14, in16);
    return 0;
}

/* ================================================================
 *  CBC
 * ================================================================ */

static unsigned long aes_cbc_encrypt_impl(u8 *out, u64 *out_len,
                                          const u32 *enc_rk, int nr,
                                          const u8 *in, u64 in_len,
                                          const u8 *iv16, int pkcs7_pad) {
    if (!out)     return 1;
    if (!out_len) return 2;
    if (!enc_rk)  return 3;
    if (in_len > 0 && !in) return 4;
    if (!iv16)    return 5;

    u64 full_blocks = in_len / 16;
    u64 remainder   = in_len % 16;

    if (!pkcs7_pad) {
        if (remainder != 0) return 6; /* must be block-aligned without padding */
        *out_len = in_len;
    } else {
        /* PKCS#7: always add padding (1..16 bytes) */
        *out_len = (full_blocks + 1) * 16;
    }

    u8 prev[16];
    memcpy(prev, iv16, 16);

    /* process full blocks */
    for (u64 i = 0; i < full_blocks; i++) {
        u8 blk[16];
        for (int j = 0; j < 16; j++) blk[j] = in[i * 16 + j] ^ prev[j];
        aes_encrypt_block(out + i * 16, enc_rk, nr, blk);
        memcpy(prev, out + i * 16, 16);
    }

    /* padding block */
    if (pkcs7_pad) {
        u8 blk[16];
        u8 pad = (u8)(16 - remainder);
        for (u64 j = 0; j < remainder; j++) blk[j] = in[full_blocks * 16 + j];
        for (u64 j = remainder; j < 16; j++) blk[j] = pad;
        for (int j = 0; j < 16; j++) blk[j] ^= prev[j];
        aes_encrypt_block(out + full_blocks * 16, enc_rk, nr, blk);
    }

    return 0;
}

static unsigned long aes_cbc_decrypt_impl(u8 *out, u64 *out_len,
                                          const u32 *dec_rk, const u32 *enc_rk, int nr,
                                          const u8 *in, u64 in_len,
                                          const u8 *iv16, int pkcs7_pad) {
    if (!out)     return 1;
    if (!out_len) return 2;
    if (!dec_rk)  return 3;
    if (in_len > 0 && !in) return 4;
    if (!iv16)    return 5;
    if (in_len == 0 || (in_len % 16) != 0) return 6;

    u64 num_blocks = in_len / 16;
    const u8 *prev = iv16;

    for (u64 i = 0; i < num_blocks; i++) {
        u8 tmp[16];
        aes_decrypt_block(tmp, dec_rk, nr, in + i * 16);
        for (int j = 0; j < 16; j++) out[i * 16 + j] = tmp[j] ^ prev[j];
        prev = in + i * 16;
    }

    if (pkcs7_pad) {
        /* validate and strip PKCS#7 padding (constant-time) */
        u8 pad_val = out[in_len - 1];
        if (pad_val == 0 || pad_val > 16) return 7;
        /* constant-time check all padding bytes */
        u8 ok = 0xff;
        for (u8 k = 0; k < pad_val; k++) {
            ok &= ct_byte_eq(out[in_len - 1 - k], pad_val);
        }
        if (!ok) return 7;
        *out_len = in_len - pad_val;
    } else {
        *out_len = in_len;
    }

    (void)enc_rk;
    return 0;
}

unsigned long aes128_cbc_encrypt(u8 *out, u64 *out_len,
                                 const aes_ctx *ctx,
                                 const u8 *in, u64 in_len,
                                 const u8 *iv16, int pkcs7_pad) {
    if (!ctx) return 3;
    if (ctx->nr != 10) return 3;
    return aes_cbc_encrypt_impl(out, out_len, ctx->enc_rk, 10,
                                in, in_len, iv16, pkcs7_pad);
}

unsigned long aes128_cbc_decrypt(u8 *out, u64 *out_len,
                                 const aes_ctx *ctx,
                                 const u8 *in, u64 in_len,
                                 const u8 *iv16, int pkcs7_pad) {
    if (!ctx) return 3;
    if (ctx->nr != 10) return 3;
    return aes_cbc_decrypt_impl(out, out_len, ctx->dec_rk, ctx->enc_rk, 10,
                                in, in_len, iv16, pkcs7_pad);
}

unsigned long aes256_cbc_encrypt(u8 *out, u64 *out_len,
                                 const aes_ctx *ctx,
                                 const u8 *in, u64 in_len,
                                 const u8 *iv16, int pkcs7_pad) {
    if (!ctx) return 3;
    if (ctx->nr != 14) return 3;
    return aes_cbc_encrypt_impl(out, out_len, ctx->enc_rk, 14,
                                in, in_len, iv16, pkcs7_pad);
}

unsigned long aes256_cbc_decrypt(u8 *out, u64 *out_len,
                                 const aes_ctx *ctx,
                                 const u8 *in, u64 in_len,
                                 const u8 *iv16, int pkcs7_pad) {
    if (!ctx) return 3;
    if (ctx->nr != 14) return 3;
    return aes_cbc_decrypt_impl(out, out_len, ctx->dec_rk, ctx->enc_rk, 14,
                                in, in_len, iv16, pkcs7_pad);
}

/* ================================================================
 *  CTR mode
 * ================================================================ */

static void ctr_increment(u8 *ctr) {
    /* big-endian increment of 128-bit counter */
    for (int i = 15; i >= 0; i--) {
        ctr[i]++;
        if (ctr[i] != 0) break;
    }
}

unsigned long aes128_ctr_init(aes_ctr_ctx *ctx, const aes_ctx *aes,
                              const u8 *nonce16) {
    if (!ctx)     return 1;
    if (!aes)     return 2;
    if (!nonce16) return 3;
    if (aes->nr != 10) return 4;

    memcpy(&ctx->aes, aes, sizeof(aes_ctx));
    memcpy(ctx->ctr, nonce16, 16);
    ctx->nr = 10;
    ctx->offset = 16; /* force keystream generation on first use */
    memset(ctx->keystream, 0, 16);
    return 0;
}

unsigned long aes256_ctr_init(aes_ctr_ctx *ctx, const aes_ctx *aes,
                              const u8 *nonce16) {
    if (!ctx)     return 1;
    if (!aes)     return 2;
    if (!nonce16) return 3;
    if (aes->nr != 14) return 4;

    memcpy(&ctx->aes, aes, sizeof(aes_ctx));
    memcpy(ctx->ctr, nonce16, 16);
    ctx->nr = 14;
    ctx->offset = 16;
    memset(ctx->keystream, 0, 16);
    return 0;
}

static unsigned long aes_ctr_xor_impl(u8 *out, aes_ctr_ctx *ctx,
                                      const u8 *in, u64 len) {
    if (!out) return 1;
    if (!ctx) return 2;
    if (len > 0 && !in) return 3;

    for (u64 i = 0; i < len; i++) {
        if (ctx->offset >= 16) {
            aes_encrypt_block(ctx->keystream, ctx->aes.enc_rk, ctx->nr, ctx->ctr);
            ctr_increment(ctx->ctr);
            ctx->offset = 0;
        }
        out[i] = in[i] ^ ctx->keystream[ctx->offset];
        ctx->offset++;
    }
    return 0;
}

unsigned long aes128_ctr_xor(u8 *out, aes_ctr_ctx *ctx,
                             const u8 *in, u64 len) {
    if (!ctx) return 2;
    if (ctx->nr != 10) return 2;
    return aes_ctr_xor_impl(out, ctx, in, len);
}

unsigned long aes256_ctr_xor(u8 *out, aes_ctr_ctx *ctx,
                             const u8 *in, u64 len) {
    if (!ctx) return 2;
    if (ctx->nr != 14) return 2;
    return aes_ctr_xor_impl(out, ctx, in, len);
}

/* ================================================================
 *  GCM — GHASH (carry-less multiplication in GF(2^128))
 * ================================================================ */

/* GHASH using bit-by-bit multiplication (constant-time via masking). */

static void ghash_mult(u8 *out, const u8 *x, const u8 *h) {
    /* Z = 0, V = H */
    u8 z[16] = {0};
    u8 v[16];
    memcpy(v, h, 16);

    for (int i = 0; i < 128; i++) {
        /* if bit i of X is set, Z ^= V */
        u8 xi = (x[i / 8] >> (7 - (i % 8))) & 1;
        /* constant-time: mask = 0xFF if xi==1, 0x00 if xi==0 */
        u8 mask = (u8)(-(int8_t)xi);
        for (int j = 0; j < 16; j++) {
            z[j] ^= (v[j] & mask);
        }

        /* V = V >> 1 in GF(2^128) with reduction polynomial */
        u8 carry = v[15] & 1;
        u8 reduce_mask = (u8)(-(int8_t)carry);
        /* shift right by 1 */
        for (int j = 15; j > 0; j--) {
            v[j] = (u8)((v[j] >> 1) | ((v[j - 1] & 1) << 7));
        }
        v[0] >>= 1;
        /* if carry, XOR with R = 0xE1 || 0^120 */
        v[0] ^= (0xe1 & reduce_mask);
    }

    memcpy(out, z, 16);
}

static void ghash(u8 *out, const u8 *h,
                  const u8 *data, u64 data_len) {
    u8 y[16] = {0};

    u64 full = data_len / 16;
    for (u64 i = 0; i < full; i++) {
        for (int j = 0; j < 16; j++) y[j] ^= data[i * 16 + j];
        u8 tmp[16];
        ghash_mult(tmp, y, h);
        memcpy(y, tmp, 16);
    }

    u64 rem = data_len % 16;
    if (rem > 0) {
        u8 block[16] = {0};
        memcpy(block, data + full * 16, rem);
        for (int j = 0; j < 16; j++) y[j] ^= block[j];
        u8 tmp[16];
        ghash_mult(tmp, y, h);
        memcpy(y, tmp, 16);
    }

    memcpy(out, y, 16);
}

/* GCM counter block: nonce (12 bytes) || counter (4 bytes, big-endian) */

static void gcm_make_j0(u8 *j0, const u8 *nonce12) {
    memcpy(j0, nonce12, 12);
    j0[12] = 0;
    j0[13] = 0;
    j0[14] = 0;
    j0[15] = 1;
}

static void gcm_inc32(u8 *ctr) {
    /* increment only the last 4 bytes (big-endian) */
    for (int i = 15; i >= 12; i--) {
        ctr[i]++;
        if (ctr[i] != 0) break;
    }
}

static void gcm_compute_tag(u8 *tag, const u32 *enc_rk, int nr,
                             const u8 *h, const u8 *j0,
                             const u8 *aad, u64 aad_len,
                             const u8 *ciphertext, u64 ct_len) {
    /* build the GHASH input: A || pad || C || pad || len(A) || len(C) */
    /* We process in parts to avoid huge allocation */

    u8 y[16] = {0};
    u8 tmp[16];

    /* process AAD blocks */
    u64 full_aad = aad_len / 16;
    for (u64 i = 0; i < full_aad; i++) {
        for (int j = 0; j < 16; j++) y[j] ^= aad[i * 16 + j];
        ghash_mult(tmp, y, h);
        memcpy(y, tmp, 16);
    }
    u64 rem_aad = aad_len % 16;
    if (rem_aad > 0) {
        u8 block[16] = {0};
        memcpy(block, aad + full_aad * 16, rem_aad);
        for (int j = 0; j < 16; j++) y[j] ^= block[j];
        ghash_mult(tmp, y, h);
        memcpy(y, tmp, 16);
    }

    /* process ciphertext blocks */
    u64 full_ct = ct_len / 16;
    for (u64 i = 0; i < full_ct; i++) {
        for (int j = 0; j < 16; j++) y[j] ^= ciphertext[i * 16 + j];
        ghash_mult(tmp, y, h);
        memcpy(y, tmp, 16);
    }
    u64 rem_ct = ct_len % 16;
    if (rem_ct > 0) {
        u8 block[16] = {0};
        memcpy(block, ciphertext + full_ct * 16, rem_ct);
        for (int j = 0; j < 16; j++) y[j] ^= block[j];
        ghash_mult(tmp, y, h);
        memcpy(y, tmp, 16);
    }

    /* length block: len(A) || len(C) in bits, each 64-bit big-endian */
    u8 len_block[16];
    u64 aad_bits = aad_len * 8;
    u64 ct_bits  = ct_len * 8;
    for (int i = 0; i < 8; i++) {
        len_block[i]     = (u8)(aad_bits >> (56 - 8 * i));
        len_block[8 + i] = (u8)(ct_bits  >> (56 - 8 * i));
    }
    for (int j = 0; j < 16; j++) y[j] ^= len_block[j];
    ghash_mult(tmp, y, h);
    memcpy(y, tmp, 16);

    /* encrypt J0 to get the tag mask */
    u8 s[16];
    aes_encrypt_block(s, enc_rk, nr, j0);
    for (int j = 0; j < 16; j++) tag[j] = y[j] ^ s[j];
}

/* ================================================================
 *  GCM encrypt / decrypt
 * ================================================================ */

static unsigned long aes_gcm_encrypt_impl(u8 *out, u8 *tag16,
                                          const u32 *enc_rk, int nr,
                                          const u8 *nonce12,
                                          const u8 *aad, u64 aad_len,
                                          const u8 *in, u64 in_len) {
    if (!out)     return 1;
    if (!tag16)   return 2;
    if (!enc_rk)  return 3;
    if (!nonce12) return 4;
    if (aad_len > 0 && !aad) return 5;
    if (in_len > 0 && !in)   return 6;

    /* compute H = AES_K(0^128) */
    u8 h[16];
    u8 zeros[16] = {0};
    aes_encrypt_block(h, enc_rk, nr, zeros);

    /* J0 = nonce || 0x00000001 */
    u8 j0[16];
    gcm_make_j0(j0, nonce12);

    /* CTR encryption starting at J0 + 1 */
    u8 ctr[16];
    memcpy(ctr, j0, 16);
    gcm_inc32(ctr);

    for (u64 i = 0; i < in_len; i += 16) {
        u8 ks[16];
        aes_encrypt_block(ks, enc_rk, nr, ctr);
        gcm_inc32(ctr);
        u64 chunk = (in_len - i < 16) ? (in_len - i) : 16;
        for (u64 j = 0; j < chunk; j++) {
            out[i + j] = in[i + j] ^ ks[j];
        }
    }

    /* compute tag */
    gcm_compute_tag(tag16, enc_rk, nr, h, j0, aad, aad_len, out, in_len);
    return 0;
}

static unsigned long aes_gcm_decrypt_impl(u8 *out,
                                          const u32 *enc_rk, int nr,
                                          const u8 *nonce12,
                                          const u8 *aad, u64 aad_len,
                                          const u8 *in, u64 in_len,
                                          const u8 *tag16) {
    if (!out)     return 1;
    if (!enc_rk)  return 2;
    if (!nonce12) return 3;
    if (aad_len > 0 && !aad) return 4;
    if (in_len > 0 && !in)   return 5;
    if (!tag16)   return 6;

    /* compute H */
    u8 h[16];
    u8 zeros[16] = {0};
    aes_encrypt_block(h, enc_rk, nr, zeros);

    /* J0 */
    u8 j0[16];
    gcm_make_j0(j0, nonce12);

    /* verify tag first (over ciphertext) */
    u8 computed_tag[16];
    gcm_compute_tag(computed_tag, enc_rk, nr, h, j0, aad, aad_len, in, in_len);

    unsigned long tag_ok;
    ct_memcmp_16(&tag_ok, computed_tag, tag16);
    if (tag_ok != 0) return 7; /* authentication failure */

    /* CTR decryption starting at J0 + 1 */
    u8 ctr[16];
    memcpy(ctr, j0, 16);
    gcm_inc32(ctr);

    for (u64 i = 0; i < in_len; i += 16) {
        u8 ks[16];
        aes_encrypt_block(ks, enc_rk, nr, ctr);
        gcm_inc32(ctr);
        u64 chunk = (in_len - i < 16) ? (in_len - i) : 16;
        for (u64 j = 0; j < chunk; j++) {
            out[i + j] = in[i + j] ^ ks[j];
        }
    }

    return 0;
}

unsigned long aes128_gcm_encrypt(u8 *out, u8 *tag16,
                                 const aes_ctx *ctx,
                                 const u8 *nonce12,
                                 const u8 *aad, u64 aad_len,
                                 const u8 *in, u64 in_len) {
    if (!ctx) return 3;
    if (ctx->nr != 10) return 3;
    return aes_gcm_encrypt_impl(out, tag16, ctx->enc_rk, 10,
                                nonce12, aad, aad_len, in, in_len);
}

unsigned long aes128_gcm_decrypt(u8 *out,
                                 const aes_ctx *ctx,
                                 const u8 *nonce12,
                                 const u8 *aad, u64 aad_len,
                                 const u8 *in, u64 in_len,
                                 const u8 *tag16) {
    if (!ctx) return 2;
    if (ctx->nr != 10) return 2;
    return aes_gcm_decrypt_impl(out, ctx->enc_rk, 10,
                                nonce12, aad, aad_len, in, in_len, tag16);
}

unsigned long aes256_gcm_encrypt(u8 *out, u8 *tag16,
                                 const aes_ctx *ctx,
                                 const u8 *nonce12,
                                 const u8 *aad, u64 aad_len,
                                 const u8 *in, u64 in_len) {
    if (!ctx) return 3;
    if (ctx->nr != 14) return 3;
    return aes_gcm_encrypt_impl(out, tag16, ctx->enc_rk, 14,
                                nonce12, aad, aad_len, in, in_len);
}

unsigned long aes256_gcm_decrypt(u8 *out,
                                 const aes_ctx *ctx,
                                 const u8 *nonce12,
                                 const u8 *aad, u64 aad_len,
                                 const u8 *in, u64 in_len,
                                 const u8 *tag16) {
    if (!ctx) return 2;
    if (ctx->nr != 14) return 2;
    return aes_gcm_decrypt_impl(out, ctx->enc_rk, 14,
                                nonce12, aad, aad_len, in, in_len, tag16);
}

/* ================================================================
 *  ChaCha20 (RFC 8439)
 * ================================================================ */

#define ROTL32(v, n) (((v) << (n)) | ((v) >> (32 - (n))))

#define QR(a, b, c, d) do { \
    a += b; d ^= a; d = ROTL32(d, 16); \
    c += d; b ^= c; b = ROTL32(b, 12); \
    a += b; d ^= a; d = ROTL32(d, 8);  \
    c += d; b ^= c; b = ROTL32(b, 7);  \
} while(0)

static u32 load32_le(const u8 *p) {
    return (u32)p[0]
         | ((u32)p[1] << 8)
         | ((u32)p[2] << 16)
         | ((u32)p[3] << 24);
}

static void store32_le(u8 *p, u32 v) {
    p[0] = (u8)(v);
    p[1] = (u8)(v >> 8);
    p[2] = (u8)(v >> 16);
    p[3] = (u8)(v >> 24);
}

static void store64_le(u8 *p, u64 v) {
    store32_le(p, (u32)v);
    store32_le(p + 4, (u32)(v >> 32));
}

static void chacha20_block(u8 out[64], const u8 key[32],
                            const u8 nonce[12], u32 counter) {
    u32 s[16];
    /* "expand 32-byte k" */
    s[0]  = 0x61707865u;
    s[1]  = 0x3320646eu;
    s[2]  = 0x79622d32u;
    s[3]  = 0x6b206574u;
    /* key */
    for (int i = 0; i < 8; i++)
        s[4 + i] = load32_le(key + 4 * i);
    /* counter */
    s[12] = counter;
    /* nonce */
    for (int i = 0; i < 3; i++)
        s[13 + i] = load32_le(nonce + 4 * i);

    u32 w[16];
    memcpy(w, s, sizeof(w));

    /* 20 rounds = 10 double-rounds */
    for (int i = 0; i < 10; i++) {
        /* column rounds */
        QR(w[0], w[4], w[ 8], w[12]);
        QR(w[1], w[5], w[ 9], w[13]);
        QR(w[2], w[6], w[10], w[14]);
        QR(w[3], w[7], w[11], w[15]);
        /* diagonal rounds */
        QR(w[0], w[5], w[10], w[15]);
        QR(w[1], w[6], w[11], w[12]);
        QR(w[2], w[7], w[ 8], w[13]);
        QR(w[3], w[4], w[ 9], w[14]);
    }

    for (int i = 0; i < 16; i++)
        store32_le(out + 4 * i, w[i] + s[i]);
}

static void chacha20_xor_stream(u8 *out, const u8 *in, u64 len,
                                 const u8 key[32], const u8 nonce[12],
                                 u32 counter) {
    u8 block[64];
    u64 off = 0;
    while (off < len) {
        chacha20_block(block, key, nonce, counter);
        counter++;
        u64 take = len - off;
        if (take > 64) take = 64;
        for (u64 j = 0; j < take; j++)
            out[off + j] = in[off + j] ^ block[j];
        off += take;
    }
    memset(block, 0, sizeof(block));
}

unsigned long chacha20_encrypt(u8 *out, const u8 *key32,
                                const u8 *nonce12, u32 counter,
                                const u8 *in, u64 in_len) {
    if (!out)     return 1;
    if (!key32)   return 2;
    if (!nonce12) return 3;
    if (in_len > 0 && !in) return 1;
    chacha20_xor_stream(out, in, in_len, key32, nonce12, counter);
    return 0;
}

/* ================================================================
 *  Poly1305 MAC (RFC 8439 Section 2.5)
 *  Five 26-bit limbs (donna-style)
 * ================================================================ */

typedef struct {
    u32 r[5];   /* clamped r in 26-bit limbs */
    u32 s[4];   /* s = key[16..31] as four 32-bit words */
    u32 h[5];   /* accumulator in 26-bit limbs */
} poly1305_ctx;

static void poly1305_init(poly1305_ctx *st, const u8 key[32]) {
    /* r with clamping */
    u32 t0 = load32_le(key +  0);
    u32 t1 = load32_le(key +  4);
    u32 t2 = load32_le(key +  8);
    u32 t3 = load32_le(key + 12);

    st->r[0] =  t0                         & 0x3ffffff;
    st->r[1] = ((t0 >> 26) | (t1 <<  6))   & 0x3ffff03;
    st->r[2] = ((t1 >> 20) | (t2 << 12))   & 0x3ffc0ff;
    st->r[3] = ((t2 >> 14) | (t3 << 18))   & 0x3f03fff;
    st->r[4] =  (t3 >>  8)                 & 0x00fffff;

    /* s */
    st->s[0] = load32_le(key + 16);
    st->s[1] = load32_le(key + 20);
    st->s[2] = load32_le(key + 24);
    st->s[3] = load32_le(key + 28);

    /* accumulator = 0 */
    st->h[0] = st->h[1] = st->h[2] = st->h[3] = st->h[4] = 0;
}

static void poly1305_block(poly1305_ctx *st, const u8 *msg, u32 hibit) {
    u32 t0 = load32_le(msg +  0);
    u32 t1 = load32_le(msg +  4);
    u32 t2 = load32_le(msg +  8);
    u32 t3 = load32_le(msg + 12);

    u32 h0 = st->h[0] + ( t0                        & 0x3ffffff);
    u32 h1 = st->h[1] + (((t0 >> 26) | (t1 <<  6)) & 0x3ffffff);
    u32 h2 = st->h[2] + (((t1 >> 20) | (t2 << 12)) & 0x3ffffff);
    u32 h3 = st->h[3] + (((t2 >> 14) | (t3 << 18)) & 0x3ffffff);
    u32 h4 = st->h[4] + ( (t3 >>  8)                | hibit);

    /* multiply: h = h * r mod p */
    u32 r0 = st->r[0], r1 = st->r[1], r2 = st->r[2];
    u32 r3 = st->r[3], r4 = st->r[4];
    u32 s1 = r1 * 5, s2 = r2 * 5, s3 = r3 * 5, s4 = r4 * 5;

    u64 d0 = (u64)h0*r0 + (u64)h1*s4 + (u64)h2*s3 + (u64)h3*s2 + (u64)h4*s1;
    u64 d1 = (u64)h0*r1 + (u64)h1*r0 + (u64)h2*s4 + (u64)h3*s3 + (u64)h4*s2;
    u64 d2 = (u64)h0*r2 + (u64)h1*r1 + (u64)h2*r0 + (u64)h3*s4 + (u64)h4*s3;
    u64 d3 = (u64)h0*r3 + (u64)h1*r2 + (u64)h2*r1 + (u64)h3*r0 + (u64)h4*s4;
    u64 d4 = (u64)h0*r4 + (u64)h1*r3 + (u64)h2*r2 + (u64)h3*r1 + (u64)h4*r0;

    /* carry propagation */
    u32 c;
    c = (u32)(d0 >> 26); h0 = (u32)d0 & 0x3ffffff; d1 += c;
    c = (u32)(d1 >> 26); h1 = (u32)d1 & 0x3ffffff; d2 += c;
    c = (u32)(d2 >> 26); h2 = (u32)d2 & 0x3ffffff; d3 += c;
    c = (u32)(d3 >> 26); h3 = (u32)d3 & 0x3ffffff; d4 += c;
    c = (u32)(d4 >> 26); h4 = (u32)d4 & 0x3ffffff; h0 += c * 5;
    c = h0 >> 26;        h0 &= 0x3ffffff;           h1 += c;

    st->h[0] = h0; st->h[1] = h1; st->h[2] = h2;
    st->h[3] = h3; st->h[4] = h4;
}

static void poly1305_update(poly1305_ctx *st, const u8 *data, u64 len) {
    u64 off = 0;
    while (off + 16 <= len) {
        poly1305_block(st, data + off, 1u << 24); /* hibit = 2^128 in limb 4 */
        off += 16;
    }
    if (off < len) {
        u8 pad[16];
        u64 rem = len - off;
        memcpy(pad, data + off, (size_t)rem);
        memset(pad + rem, 0, 16 - (size_t)rem);
        /* hibit: partial block gets 1 << (8 * rem) in the 130-bit representation.
           In our limb layout limb4 gets the high bits; but the standard approach
           for partial blocks is to append 0x01 byte and set hibit=0 in limb4.
           We follow the donna convention: pad[rem] = 1, hibit = 0. */
        pad[rem] = 1;
        poly1305_block(st, pad, 0);
    }
}

static void poly1305_finish(poly1305_ctx *st, u8 tag[16]) {
    /* full carry */
    u32 h0 = st->h[0], h1 = st->h[1], h2 = st->h[2];
    u32 h3 = st->h[3], h4 = st->h[4];
    u32 c;

    c = h1 >> 26; h1 &= 0x3ffffff; h2 += c;
    c = h2 >> 26; h2 &= 0x3ffffff; h3 += c;
    c = h3 >> 26; h3 &= 0x3ffffff; h4 += c;
    c = h4 >> 26; h4 &= 0x3ffffff; h0 += c * 5;
    c = h0 >> 26; h0 &= 0x3ffffff; h1 += c;

    /* compute h + -(2^130 - 5) = h - p */
    u32 g0 = h0 + 5; c = g0 >> 26; g0 &= 0x3ffffff;
    u32 g1 = h1 + c; c = g1 >> 26; g1 &= 0x3ffffff;
    u32 g2 = h2 + c; c = g2 >> 26; g2 &= 0x3ffffff;
    u32 g3 = h3 + c; c = g3 >> 26; g3 &= 0x3ffffff;
    u32 g4 = h4 + c - (1u << 26);

    /* select h or g based on carry (if g4 top bit is 0, use g) */
    u32 mask = (g4 >> 31) - 1; /* 0xffffffff if g4 >= 0 (use g), 0 if g4 < 0 (use h) */
    /* g4 bit 31 is set if borrow occurred (h < p) => mask=0 => keep h.
       If h >= p, no underflow => g4 bit 31 is 0 => mask=0xffffffff => select g. */
    h0 = (h0 & ~mask) | (g0 & mask);
    h1 = (h1 & ~mask) | (g1 & mask);
    h2 = (h2 & ~mask) | (g2 & mask);
    h3 = (h3 & ~mask) | (g3 & mask);
    h4 = (h4 & ~mask) | (g4 & mask);

    /* assemble h into 4 x 32-bit words */
    u64 f;
    f = (u64)h0 | ((u64)h1 << 26); u32 w0 = (u32)f; f >>= 32;
    f += (u64)h1 >> 6 | ((u64)h2 << 20); u32 w1 = (u32)f; f >>= 32;
    f += (u64)h2 >> 12 | ((u64)h3 << 14); u32 w2 = (u32)f; f >>= 32;
    f += (u64)h3 >> 18 | ((u64)h4 << 8); u32 w3 = (u32)f;

    /* add s */
    f = (u64)w0 + st->s[0]; w0 = (u32)f;
    f = (u64)w1 + st->s[1] + (f >> 32); w1 = (u32)f;
    f = (u64)w2 + st->s[2] + (f >> 32); w2 = (u32)f;
    f = (u64)w3 + st->s[3] + (f >> 32); w3 = (u32)f;

    store32_le(tag +  0, w0);
    store32_le(tag +  4, w1);
    store32_le(tag +  8, w2);
    store32_le(tag + 12, w3);

    /* wipe state */
    memset(st, 0, sizeof(*st));
}

/* ================================================================
 *  ChaCha20-Poly1305 AEAD (RFC 8439 Section 2.8)
 * ================================================================ */

static void pad16(poly1305_ctx *st, u64 len) {
    u64 rem = len & 0xf;
    if (rem) {
        u8 z[16] = {0};
        poly1305_update(st, z, 16 - rem);
    }
}

unsigned long chacha20_poly1305_encrypt(u8 *out, u8 *tag16,
                                         const u8 *key32,
                                         const u8 *nonce12,
                                         const u8 *aad, u64 aad_len,
                                         const u8 *in, u64 in_len) {
    if (!out)     return 1;
    if (!key32)   return 2;
    if (!nonce12) return 3;
    if (!tag16)   return 4;

    /* 1. Generate Poly1305 one-time key (counter=0, first 32 bytes) */
    u8 poly_key[64];
    chacha20_block(poly_key, key32, nonce12, 0);

    /* 2. Encrypt with ChaCha20 starting at counter=1 */
    chacha20_xor_stream(out, in, in_len, key32, nonce12, 1);

    /* 3. Compute Poly1305 tag */
    poly1305_ctx pctx;
    poly1305_init(&pctx, poly_key);
    memset(poly_key, 0, sizeof(poly_key));

    if (aad && aad_len > 0)
        poly1305_update(&pctx, aad, aad_len);
    pad16(&pctx, aad_len);

    if (in_len > 0)
        poly1305_update(&pctx, out, in_len);
    pad16(&pctx, in_len);

    u8 lens[16];
    store64_le(lens, aad_len);
    store64_le(lens + 8, in_len);
    poly1305_update(&pctx, lens, 16);

    poly1305_finish(&pctx, tag16);
    return 0;
}

unsigned long chacha20_poly1305_decrypt(u8 *out,
                                         const u8 *key32,
                                         const u8 *nonce12,
                                         const u8 *aad, u64 aad_len,
                                         const u8 *in, u64 in_len,
                                         const u8 *tag16) {
    if (!out)     return 1;
    if (!key32)   return 2;
    if (!nonce12) return 3;
    if (!tag16)   return 4;

    /* 1. Generate Poly1305 one-time key */
    u8 poly_key[64];
    chacha20_block(poly_key, key32, nonce12, 0);

    /* 2. Verify tag (constant-time) over ciphertext */
    poly1305_ctx pctx;
    poly1305_init(&pctx, poly_key);
    memset(poly_key, 0, sizeof(poly_key));

    if (aad && aad_len > 0)
        poly1305_update(&pctx, aad, aad_len);
    pad16(&pctx, aad_len);

    if (in_len > 0)
        poly1305_update(&pctx, in, in_len);
    pad16(&pctx, in_len);

    u8 lens[16];
    store64_le(lens, aad_len);
    store64_le(lens + 8, in_len);
    poly1305_update(&pctx, lens, 16);

    u8 computed_tag[16];
    poly1305_finish(&pctx, computed_tag);

    unsigned long eq;
    ct_memcmp_16(&eq, computed_tag, tag16);
    memset(computed_tag, 0, sizeof(computed_tag));
    if (eq != 0) {
        memset(out, 0, (size_t)in_len);
        return 4;
    }

    /* 3. Decrypt */
    chacha20_xor_stream(out, in, in_len, key32, nonce12, 1);
    return 0;
}
