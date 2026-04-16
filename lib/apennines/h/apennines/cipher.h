#ifndef APENNINES_T2_CRYPTO_CIPHER_H
#define APENNINES_T2_CRYPTO_CIPHER_H


#include "apennines/types.h"

/* ---- opaque cipher context (forward-declared) ---- */

typedef struct aes_ctx     aes_ctx;
typedef struct aes_ctr_ctx aes_ctr_ctx;

/* ---- AES key expansion ---- */

unsigned long aes128_init(aes_ctx *ctx, const u8 *key16);
unsigned long aes256_init(aes_ctx *ctx, const u8 *key32);
unsigned long aes_destroy(aes_ctx *ctx);

/* ---- ECB (single 16-byte block) ---- */

unsigned long aes128_ecb_encrypt(u8 *out16, const aes_ctx *ctx, const u8 *in16);
unsigned long aes128_ecb_decrypt(u8 *out16, const aes_ctx *ctx, const u8 *in16);
unsigned long aes256_ecb_encrypt(u8 *out16, const aes_ctx *ctx, const u8 *in16);
unsigned long aes256_ecb_decrypt(u8 *out16, const aes_ctx *ctx, const u8 *in16);

/* ---- CBC ---- */

unsigned long aes128_cbc_encrypt(u8 *out, u64 *out_len,
                                               const aes_ctx *ctx,
                                               const u8 *in, u64 in_len,
                                               const u8 *iv16, int pkcs7_pad);
unsigned long aes128_cbc_decrypt(u8 *out, u64 *out_len,
                                               const aes_ctx *ctx,
                                               const u8 *in, u64 in_len,
                                               const u8 *iv16, int pkcs7_pad);
unsigned long aes256_cbc_encrypt(u8 *out, u64 *out_len,
                                               const aes_ctx *ctx,
                                               const u8 *in, u64 in_len,
                                               const u8 *iv16, int pkcs7_pad);
unsigned long aes256_cbc_decrypt(u8 *out, u64 *out_len,
                                               const aes_ctx *ctx,
                                               const u8 *in, u64 in_len,
                                               const u8 *iv16, int pkcs7_pad);

/* ---- CTR (stream) ---- */

unsigned long aes128_ctr_init(aes_ctr_ctx *ctx,
                                            const aes_ctx *aes,
                                            const u8 *nonce16);
unsigned long aes128_ctr_xor(u8 *out, aes_ctr_ctx *ctx,
                                           const u8 *in, u64 len);
unsigned long aes256_ctr_init(aes_ctr_ctx *ctx,
                                            const aes_ctx *aes,
                                            const u8 *nonce16);
unsigned long aes256_ctr_xor(u8 *out, aes_ctr_ctx *ctx,
                                           const u8 *in, u64 len);

/* ---- GCM (AEAD) ---- */

unsigned long aes128_gcm_encrypt(u8 *out, u8 *tag16,
                                               const aes_ctx *ctx,
                                               const u8 *nonce12,
                                               const u8 *aad, u64 aad_len,
                                               const u8 *in, u64 in_len);
unsigned long aes128_gcm_decrypt(u8 *out,
                                               const aes_ctx *ctx,
                                               const u8 *nonce12,
                                               const u8 *aad, u64 aad_len,
                                               const u8 *in, u64 in_len,
                                               const u8 *tag16);
unsigned long aes256_gcm_encrypt(u8 *out, u8 *tag16,
                                               const aes_ctx *ctx,
                                               const u8 *nonce12,
                                               const u8 *aad, u64 aad_len,
                                               const u8 *in, u64 in_len);
unsigned long aes256_gcm_decrypt(u8 *out,
                                               const aes_ctx *ctx,
                                               const u8 *nonce12,
                                               const u8 *aad, u64 aad_len,
                                               const u8 *in, u64 in_len,
                                               const u8 *tag16);

/* ---- context sizes (for stack allocation) ---- */

#define AES_CTX_SIZE     480
#define AES_CTR_CTX_SIZE 512

/* ---- concrete struct definitions (sized for stack allocation) ---- */

struct aes_ctx {
    u32 enc_rk[60];   /* round keys for encryption */
    u32 dec_rk[60];   /* round keys for decryption */
    int nr;           /* number of rounds (10 or 14) */
};

struct aes_ctr_ctx {
    aes_ctx  aes;         /* copy of aes context */
    u8       ctr[16];     /* 128-bit counter block */
    u8       keystream[16];
    int      nr;          /* number of rounds (from aes) */
    u64      offset;      /* bytes consumed in current keystream block */
};

/* ---- ChaCha20-Poly1305 (AEAD, RFC 8439) ---- */

unsigned long chacha20_poly1305_encrypt(u8 *out, u8 *tag16,
                                                       const u8 *key32,
                                                       const u8 *nonce12,
                                                       const u8 *aad, u64 aad_len,
                                                       const u8 *in, u64 in_len);

unsigned long chacha20_poly1305_decrypt(u8 *out,
                                                       const u8 *key32,
                                                       const u8 *nonce12,
                                                       const u8 *aad, u64 aad_len,
                                                       const u8 *in, u64 in_len,
                                                       const u8 *tag16);

/* Raw ChaCha20 stream cipher (RFC 8439 Section 2.4) */
unsigned long chacha20_encrypt(u8 *out, const u8 *key32,
                                              const u8 *nonce12, u32 counter,
                                              const u8 *in, u64 in_len);

#endif /* APENNINES_T2_CRYPTO_CIPHER_H */
