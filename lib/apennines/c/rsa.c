#include "apennines/rsa.h"
#include "apennines/entropy.h"
#include <stdlib.h>
#include <string.h>

/* ================================================================
 * Internal SHA-256 implementation (RFC 6234)
 * ================================================================ */

static const u32 sha256_k[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

#define SHA_ROTR(x, n)  (((x) >> (n)) | ((x) << (32 - (n))))
#define SHA_CH(x,y,z)   (((x) & (y)) ^ (~(x) & (z)))
#define SHA_MAJ(x,y,z)  (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define SHA_EP0(x)       (SHA_ROTR(x,2)  ^ SHA_ROTR(x,13) ^ SHA_ROTR(x,22))
#define SHA_EP1(x)       (SHA_ROTR(x,6)  ^ SHA_ROTR(x,11) ^ SHA_ROTR(x,25))
#define SHA_SIG0(x)      (SHA_ROTR(x,7)  ^ SHA_ROTR(x,18) ^ ((x) >> 3))
#define SHA_SIG1(x)      (SHA_ROTR(x,17) ^ SHA_ROTR(x,19) ^ ((x) >> 10))

static void sha256_transform(u32 state[8], const u8 block[64]) {
    u32 w[64];
    u32 a, b, c, d, e, f, g, h;
    u32 t1, t2;
    int i;

    for (i = 0; i < 16; i++) {
        w[i] = ((u32)block[i*4] << 24) | ((u32)block[i*4+1] << 16)
             | ((u32)block[i*4+2] << 8) | (u32)block[i*4+3];
    }
    for (i = 16; i < 64; i++) {
        w[i] = SHA_SIG1(w[i-2]) + w[i-7] + SHA_SIG0(w[i-15]) + w[i-16];
    }

    a = state[0]; b = state[1]; c = state[2]; d = state[3];
    e = state[4]; f = state[5]; g = state[6]; h = state[7];

    for (i = 0; i < 64; i++) {
        t1 = h + SHA_EP1(e) + SHA_CH(e,f,g) + sha256_k[i] + w[i];
        t2 = SHA_EP0(a) + SHA_MAJ(a,b,c);
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }

    state[0] += a; state[1] += b; state[2] += c; state[3] += d;
    state[4] += e; state[5] += f; state[6] += g; state[7] += h;
}

static void sha256_hash(u8 out[32], const u8 *data, u64 len) {
    u32 state[8] = {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    };
    u8 block[64];
    u64 i;
    u64 total_bits = len * 8;

    /* process full blocks */
    for (i = 0; i + 64 <= len; i += 64) {
        sha256_transform(state, data + i);
    }

    /* final block with padding */
    {
        u64 remaining = len - i;
        memset(block, 0, 64);
        if (remaining > 0) {
            memcpy(block, data + i, (size_t)remaining);
        }
        block[remaining] = 0x80;

        if (remaining >= 56) {
            sha256_transform(state, block);
            memset(block, 0, 64);
        }

        /* append length in bits as big-endian 64-bit */
        block[56] = (u8)(total_bits >> 56);
        block[57] = (u8)(total_bits >> 48);
        block[58] = (u8)(total_bits >> 40);
        block[59] = (u8)(total_bits >> 32);
        block[60] = (u8)(total_bits >> 24);
        block[61] = (u8)(total_bits >> 16);
        block[62] = (u8)(total_bits >> 8);
        block[63] = (u8)(total_bits);
        sha256_transform(state, block);
    }

    for (i = 0; i < 8; i++) {
        out[i*4]   = (u8)(state[i] >> 24);
        out[i*4+1] = (u8)(state[i] >> 16);
        out[i*4+2] = (u8)(state[i] >> 8);
        out[i*4+3] = (u8)(state[i]);
    }
}

/* ================================================================
 * MGF1 (RFC 8017 B.2.1) using SHA-256
 * ================================================================ */

#define HLEN 32  /* SHA-256 output size */

static unsigned long mgf1_sha256(u8 *out, u64 out_len, const u8 *seed, u64 seed_len) {
    u64 counter;
    u64 offset = 0;
    u8 *buf;
    u8 hash[HLEN];
    u8 counter_bytes[4];

    buf = (u8 *)malloc((size_t)(seed_len + 4));
    if (!buf) return 1;
    memcpy(buf, seed, (size_t)seed_len);

    for (counter = 0; offset < out_len; counter++) {
        u64 copy_len;
        counter_bytes[0] = (u8)(counter >> 24);
        counter_bytes[1] = (u8)(counter >> 16);
        counter_bytes[2] = (u8)(counter >> 8);
        counter_bytes[3] = (u8)(counter);
        memcpy(buf + seed_len, counter_bytes, 4);

        sha256_hash(hash, buf, seed_len + 4);

        copy_len = out_len - offset;
        if (copy_len > HLEN) copy_len = HLEN;
        memcpy(out + offset, hash, (size_t)copy_len);
        offset += copy_len;
    }

    free(buf);
    return 0;
}

/* ================================================================
 * RSA primitives
 * ================================================================ */

/* RSAEP: m^e mod n */
static unsigned long rsa_ep(bigint *out, bigint *m, rsa_pubkey *key) {
    return bigint_modpow(out, m, &key->e, &key->n);
}

/* Forward declarations for utility functions defined below */
static unsigned long bigint_copy(bigint *dst, bigint *src);
static unsigned long bigint_to_fixed_bytes(u8 *out, u64 out_len, bigint *val);

/* RSADP with CRT: faster private key operation */
static unsigned long rsa_dp_crt(bigint *out, bigint *c, rsa_privkey *key) {
    bigint s1, s2, h, tmp, result;
    unsigned long rc;
    long cmp;

    memset(&s1, 0, sizeof(bigint));
    memset(&s2, 0, sizeof(bigint));
    memset(&h, 0, sizeof(bigint));
    memset(&tmp, 0, sizeof(bigint));
    memset(&result, 0, sizeof(bigint));

    /* s1 = c^dp mod p */
    rc = bigint_create(&s1, 1);
    if (rc) goto crt_cleanup;
    rc = bigint_modpow(&s1, c, &key->dp, &key->p);
    if (rc) goto crt_cleanup;

    /* s2 = c^dq mod q */
    rc = bigint_create(&s2, 1);
    if (rc) goto crt_cleanup;
    rc = bigint_modpow(&s2, c, &key->dq, &key->q);
    if (rc) goto crt_cleanup;

    /* h = qinv * (s1 - s2) mod p */
    /* Handle s1 < s2 by adding p: h = qinv * (s1 - s2 + p) mod p */
    rc = bigint_create(&tmp, 1);
    if (rc) goto crt_cleanup;

    rc = bigint_compare(&cmp, &s1, &s2);
    if (rc) goto crt_cleanup;

    rc = bigint_create(&h, 1);
    if (rc) goto crt_cleanup;

    if (cmp >= 0) {
        rc = bigint_sub(&tmp, &s1, &s2);
        if (rc) goto crt_cleanup;
    } else {
        /* s1 + p - s2 */
        bigint s1_plus_p;
        memset(&s1_plus_p, 0, sizeof(bigint));
        rc = bigint_create(&s1_plus_p, 1);
        if (rc) goto crt_cleanup;
        rc = bigint_add(&s1_plus_p, &s1, &key->p);
        if (rc) { bigint_destroy(&s1_plus_p); goto crt_cleanup; }
        rc = bigint_sub(&tmp, &s1_plus_p, &s2);
        bigint_destroy(&s1_plus_p);
        if (rc) goto crt_cleanup;
    }

    {
        bigint mul_tmp;
        memset(&mul_tmp, 0, sizeof(bigint));
        rc = bigint_create(&mul_tmp, 1);
        if (rc) goto crt_cleanup;
        rc = bigint_mul(&mul_tmp, &key->qinv, &tmp);
        if (rc) { bigint_destroy(&mul_tmp); goto crt_cleanup; }
        rc = bigint_mod(&h, &mul_tmp, &key->p);
        bigint_destroy(&mul_tmp);
        if (rc) goto crt_cleanup;
    }

    /* m = s2 + h * q */
    {
        bigint hq;
        memset(&hq, 0, sizeof(bigint));
        rc = bigint_create(&hq, 1);
        if (rc) goto crt_cleanup;
        rc = bigint_mul(&hq, &h, &key->q);
        if (rc) { bigint_destroy(&hq); goto crt_cleanup; }
        rc = bigint_create(&result, 1);
        if (rc) { bigint_destroy(&hq); goto crt_cleanup; }
        rc = bigint_add(&result, &s2, &hq);
        bigint_destroy(&hq);
        if (rc) goto crt_cleanup;
    }

    /* copy to out */
    rc = bigint_copy(out, &result);

crt_cleanup:
    bigint_destroy(&s1);
    bigint_destroy(&s2);
    bigint_destroy(&h);
    bigint_destroy(&tmp);
    bigint_destroy(&result);
    return rc;
}

/* ================================================================
 * Utility: bigint <-> fixed-size byte array
 * ================================================================ */

/* Convert bigint to fixed-size big-endian byte array (zero-padded on left) */
static unsigned long bigint_to_fixed_bytes(u8 *out, u64 out_len, bigint *val) {
    u64 actual_len = 0;
    u64 bl = 0;
    u64 natural_len;
    u8 *tmp;
    unsigned long rc;

    memset(out, 0, (size_t)out_len);

    /* Get the natural byte representation */
    rc = bigint_bitlen(&bl, val);
    if (rc) return rc;

    natural_len = (bl + 7) / 8;
    if (natural_len == 0) natural_len = 1;
    if (natural_len > out_len) return 1;

    tmp = (u8 *)malloc((size_t)natural_len);
    if (!tmp) return 1;

    rc = bigint_to_bytes(tmp, &actual_len, natural_len, val);
    if (rc) { free(tmp); return rc; }

    /* Copy right-aligned */
    memcpy(out + (out_len - actual_len), tmp, (size_t)actual_len);
    free(tmp);
    return 0;
}

/* Copy a bigint (using bytes round-trip since bi_copy is static in bigint.c) */
static unsigned long bigint_copy(bigint *dst, bigint *src) {
    u64 bl = 0;
    u64 byte_len;
    u8 *tmp;
    u64 actual_len = 0;
    unsigned long rc;

    rc = bigint_bitlen(&bl, src);
    if (rc) return rc;

    byte_len = (bl + 7) / 8;
    if (byte_len == 0) byte_len = 1;

    tmp = (u8 *)malloc((size_t)byte_len);
    if (!tmp) return 1;

    rc = bigint_to_bytes(tmp, &actual_len, byte_len, src);
    if (rc) { free(tmp); return rc; }

    rc = bigint_from_bytes(dst, tmp, actual_len);
    free(tmp);
    return rc;
}

/* ================================================================
 * Miller-Rabin primality test
 * ================================================================ */

/* Test if n is probably prime using k rounds of Miller-Rabin */
static unsigned long miller_rabin(unsigned long *is_prime, bigint *n, int rounds) {
    bigint n_minus_1, d, two, n_minus_3, a, x, one_bi;
    u64 r_val = 0;
    unsigned long rc;
    int i;

    *is_prime = 0;

    /* n must be > 3 and odd */
    {
        long cmp;
        bigint three;
        rc = bigint_from_u64(&three, 3);
        if (rc) return rc;
        rc = bigint_compare(&cmp, n, &three);
        bigint_destroy(&three);
        if (rc) return rc;
        if (cmp <= 0) {
            /* n <= 3: check if n == 2 or n == 3 */
            bigint two_bi, three_bi;

            rc = bigint_from_u64(&two_bi, 2);
            if (rc) return rc;
            rc = bigint_compare(&cmp, n, &two_bi);
            bigint_destroy(&two_bi);
            if (rc) return rc;
            if (cmp == 0) { *is_prime = 1; return 0; }

            rc = bigint_from_u64(&three_bi, 3);
            if (rc) return rc;
            rc = bigint_compare(&cmp, n, &three_bi);
            bigint_destroy(&three_bi);
            if (rc) return rc;
            if (cmp == 0) { *is_prime = 1; return 0; }

            *is_prime = 0;
            return 0;
        }
    }

    memset(&n_minus_1, 0, sizeof(bigint));
    memset(&d, 0, sizeof(bigint));
    memset(&two, 0, sizeof(bigint));
    memset(&n_minus_3, 0, sizeof(bigint));
    memset(&a, 0, sizeof(bigint));
    memset(&x, 0, sizeof(bigint));
    memset(&one_bi, 0, sizeof(bigint));

    /* n-1 = 2^r * d where d is odd */
    rc = bigint_from_u64(&one_bi, 1);
    if (rc) return rc;
    rc = bigint_create(&n_minus_1, 1);
    if (rc) goto mr_cleanup;
    rc = bigint_sub(&n_minus_1, n, &one_bi);
    if (rc) goto mr_cleanup;

    rc = bigint_create(&d, 1);
    if (rc) goto mr_cleanup;
    rc = bigint_copy(&d, &n_minus_1);
    if (rc) goto mr_cleanup;

    /* Factor out powers of 2 from d */
    r_val = 0;
    for (;;) {
        bigint rem, two_div, d_new;
        unsigned long rem_is_zero;

        /* Check if d is even: d mod 2 */
        memset(&rem, 0, sizeof(bigint));
        memset(&two_div, 0, sizeof(bigint));
        rc = bigint_from_u64(&two_div, 2);
        if (rc) goto mr_cleanup;
        rc = bigint_create(&rem, 1);
        if (rc) { bigint_destroy(&two_div); goto mr_cleanup; }
        rc = bigint_mod(&rem, &d, &two_div);
        if (rc) { bigint_destroy(&rem); bigint_destroy(&two_div); goto mr_cleanup; }

        rc = bigint_is_zero(&rem_is_zero, &rem);
        bigint_destroy(&rem);
        bigint_destroy(&two_div);
        if (rc) goto mr_cleanup;

        if (!rem_is_zero) break;

        /* d = d / 2 (right shift by 1) */
        memset(&d_new, 0, sizeof(bigint));
        rc = bigint_create(&d_new, 1);
        if (rc) goto mr_cleanup;
        rc = bigint_shr(&d_new, &d, 1);
        if (rc) { bigint_destroy(&d_new); goto mr_cleanup; }
        bigint_destroy(&d);
        d = d_new;
        r_val++;
    }

    rc = bigint_from_u64(&two, 2);
    if (rc) goto mr_cleanup;

    /* n-3 for random range */
    rc = bigint_create(&n_minus_3, 1);
    if (rc) goto mr_cleanup;
    {
        bigint three;
        rc = bigint_from_u64(&three, 3);
        if (rc) goto mr_cleanup;
        rc = bigint_sub(&n_minus_3, n, &three);
        bigint_destroy(&three);
        if (rc) goto mr_cleanup;
    }

    /* Perform rounds */
    for (i = 0; i < rounds; i++) {
        u64 j;
        unsigned long continue_outer = 0;

        /* Generate random a in [2, n-2]: a = (random mod (n-3)) + 2 */
        {
            u64 n_bl = 0;
            u64 byte_count;
            u64 excess_bits;
            u8 *rand_bytes;
            bigint rand_bi, a_mod;

            rc = bigint_bitlen(&n_bl, n);
            if (rc) goto mr_cleanup;
            byte_count = (n_bl + 7) / 8;

            rand_bytes = (u8 *)malloc((size_t)byte_count);
            if (!rand_bytes) { rc = 1; goto mr_cleanup; }

            rc = entropy_get_system(rand_bytes, byte_count);
            if (rc) { free(rand_bytes); goto mr_cleanup; }

            /* Clear top bits to keep in range */
            excess_bits = byte_count * 8 - n_bl;
            if (excess_bits > 0 && excess_bits < 8) {
                rand_bytes[0] &= (u8)((1u << (8 - excess_bits)) - 1);
            }

            rc = bigint_from_bytes(&rand_bi, rand_bytes, byte_count);
            free(rand_bytes);
            if (rc) goto mr_cleanup;

            /* a = (rand_bi mod n_minus_3) + 2 */
            memset(&a_mod, 0, sizeof(bigint));
            rc = bigint_create(&a_mod, 1);
            if (rc) { bigint_destroy(&rand_bi); goto mr_cleanup; }

            rc = bigint_mod(&a_mod, &rand_bi, &n_minus_3);
            bigint_destroy(&rand_bi);
            if (rc) { bigint_destroy(&a_mod); goto mr_cleanup; }

            bigint_destroy(&a);
            memset(&a, 0, sizeof(bigint));
            rc = bigint_create(&a, 1);
            if (rc) { bigint_destroy(&a_mod); goto mr_cleanup; }
            rc = bigint_add(&a, &a_mod, &two);
            bigint_destroy(&a_mod);
            if (rc) goto mr_cleanup;
        }

        /* x = a^d mod n */
        bigint_destroy(&x);
        memset(&x, 0, sizeof(bigint));
        rc = bigint_create(&x, 1);
        if (rc) goto mr_cleanup;
        rc = bigint_modpow(&x, &a, &d, n);
        if (rc) goto mr_cleanup;

        /* if x == 1 or x == n-1, continue */
        {
            unsigned long x_is_one;
            long cmp;
            rc = bigint_is_one(&x_is_one, &x);
            if (rc) goto mr_cleanup;
            if (x_is_one) continue;

            rc = bigint_compare(&cmp, &x, &n_minus_1);
            if (rc) goto mr_cleanup;
            if (cmp == 0) continue;
        }

        /* Square r-1 times */
        for (j = 1; j < r_val; j++) {
            bigint x_new, x_sq;
            long cmp_inner;

            memset(&x_new, 0, sizeof(bigint));
            memset(&x_sq, 0, sizeof(bigint));

            rc = bigint_create(&x_new, 1);
            if (rc) goto mr_cleanup;

            /* x = x^2 mod n */
            rc = bigint_create(&x_sq, 1);
            if (rc) { bigint_destroy(&x_new); goto mr_cleanup; }
            rc = bigint_mul(&x_sq, &x, &x);
            if (rc) { bigint_destroy(&x_sq); bigint_destroy(&x_new); goto mr_cleanup; }
            rc = bigint_mod(&x_new, &x_sq, n);
            bigint_destroy(&x_sq);
            if (rc) { bigint_destroy(&x_new); goto mr_cleanup; }

            bigint_destroy(&x);
            x = x_new;

            /* if x == n-1, this round passes */
            rc = bigint_compare(&cmp_inner, &x, &n_minus_1);
            if (rc) goto mr_cleanup;
            if (cmp_inner == 0) { continue_outer = 1; break; }
        }

        if (continue_outer) continue;

        /* composite */
        *is_prime = 0;
        rc = 0;
        goto mr_cleanup;
    }

    *is_prime = 1;
    rc = 0;

mr_cleanup:
    bigint_destroy(&n_minus_1);
    bigint_destroy(&d);
    bigint_destroy(&two);
    bigint_destroy(&n_minus_3);
    bigint_destroy(&a);
    bigint_destroy(&x);
    bigint_destroy(&one_bi);
    return rc;
}

/* ================================================================
 * Prime generation
 * ================================================================ */

/* Generate a random probable prime of the given bit length */
static unsigned long generate_prime(bigint *out, u64 bit_len) {
    u64 byte_len = (bit_len + 7) / 8;
    u8 *candidate_bytes;
    unsigned long rc;
    unsigned long is_prime_result;
    u64 top_byte_bits;

    candidate_bytes = (u8 *)malloc((size_t)byte_len);
    if (!candidate_bytes) return 1;

    rc = entropy_get_system(candidate_bytes, byte_len);
    if (rc) { free(candidate_bytes); return rc; }

    /* Set the top two bits to ensure the number is large enough
       so that p*q will have the full bit_size bits */
    top_byte_bits = bit_len % 8;
    if (top_byte_bits == 0) top_byte_bits = 8;

    /* Clear bits above bit_len in the top byte */
    if (top_byte_bits < 8) {
        candidate_bytes[0] &= (u8)((1u << top_byte_bits) - 1);
    }
    /* Set top two bits */
    candidate_bytes[0] |= (u8)(1u << (top_byte_bits - 1));
    if (top_byte_bits >= 2) {
        candidate_bytes[0] |= (u8)(1u << (top_byte_bits - 2));
    } else {
        /* top_byte_bits == 1: set the top bit of the next byte */
        if (byte_len > 1) {
            candidate_bytes[1] |= 0x80;
        }
    }

    /* Make odd */
    candidate_bytes[byte_len - 1] |= 0x01;

    /* Convert to bigint */
    rc = bigint_from_bytes(out, candidate_bytes, byte_len);
    free(candidate_bytes);
    if (rc) return rc;

    /* Increment by 2 until we find a prime */
    {
        bigint two_bi;
        rc = bigint_from_u64(&two_bi, 2);
        if (rc) return rc;

        for (;;) {
            bigint next;

            rc = miller_rabin(&is_prime_result, out, 40);
            if (rc) { bigint_destroy(&two_bi); return rc; }
            if (is_prime_result) {
                bigint_destroy(&two_bi);
                return 0;
            }

            /* out += 2 */
            memset(&next, 0, sizeof(bigint));
            rc = bigint_create(&next, 1);
            if (rc) { bigint_destroy(&two_bi); return rc; }
            rc = bigint_add(&next, out, &two_bi);
            if (rc) { bigint_destroy(&next); bigint_destroy(&two_bi); return rc; }
            bigint_destroy(out);
            *out = next;
        }
    }
}

/* ================================================================
 * Key generation
 * ================================================================ */

unsigned long rsa_keygen(rsa_keypair *out, u64 bit_size) {
    bigint p, q, one, p1, q1, phi, e_bi, gcd_val, d_val;
    bigint dp, dq, qinv, n;
    unsigned long rc;

    if (!out) return 1;
    if (bit_size < 1024 || (bit_size % 256) != 0) return 2;

    memset(out, 0, sizeof(rsa_keypair));

    memset(&p, 0, sizeof(bigint));
    memset(&q, 0, sizeof(bigint));
    memset(&one, 0, sizeof(bigint));
    memset(&p1, 0, sizeof(bigint));
    memset(&q1, 0, sizeof(bigint));
    memset(&phi, 0, sizeof(bigint));
    memset(&e_bi, 0, sizeof(bigint));
    memset(&gcd_val, 0, sizeof(bigint));
    memset(&d_val, 0, sizeof(bigint));
    memset(&dp, 0, sizeof(bigint));
    memset(&dq, 0, sizeof(bigint));
    memset(&qinv, 0, sizeof(bigint));
    memset(&n, 0, sizeof(bigint));

    rc = bigint_from_u64(&one, 1);
    if (rc) goto kg_cleanup;

    rc = bigint_from_u64(&e_bi, 65537);
    if (rc) goto kg_cleanup;

    /* Generate p and q */
    for (;;) {
        bigint_destroy(&p);
        memset(&p, 0, sizeof(bigint));
        rc = generate_prime(&p, bit_size / 2);
        if (rc) { rc = 3; goto kg_cleanup; }

        bigint_destroy(&q);
        memset(&q, 0, sizeof(bigint));
        rc = generate_prime(&q, bit_size / 2);
        if (rc) { rc = 3; goto kg_cleanup; }

        /* Ensure p != q */
        {
            long cmp;
            rc = bigint_compare(&cmp, &p, &q);
            if (rc) goto kg_cleanup;
            if (cmp == 0) continue;
        }

        /* p-1, q-1 */
        bigint_destroy(&p1);
        memset(&p1, 0, sizeof(bigint));
        rc = bigint_create(&p1, 1);
        if (rc) goto kg_cleanup;
        rc = bigint_sub(&p1, &p, &one);
        if (rc) goto kg_cleanup;

        bigint_destroy(&q1);
        memset(&q1, 0, sizeof(bigint));
        rc = bigint_create(&q1, 1);
        if (rc) goto kg_cleanup;
        rc = bigint_sub(&q1, &q, &one);
        if (rc) goto kg_cleanup;

        /* Check gcd(e, p-1) == 1 and gcd(e, q-1) == 1 */
        {
            bigint gcd_ep, gcd_eq;
            unsigned long g_is_one;
            memset(&gcd_ep, 0, sizeof(bigint));
            memset(&gcd_eq, 0, sizeof(bigint));
            rc = bigint_create(&gcd_ep, 1);
            if (rc) goto kg_cleanup;
            rc = bigint_gcd(&gcd_ep, &e_bi, &p1);
            if (rc) { bigint_destroy(&gcd_ep); goto kg_cleanup; }
            rc = bigint_is_one(&g_is_one, &gcd_ep);
            bigint_destroy(&gcd_ep);
            if (rc) goto kg_cleanup;
            if (!g_is_one) continue;

            rc = bigint_create(&gcd_eq, 1);
            if (rc) goto kg_cleanup;
            rc = bigint_gcd(&gcd_eq, &e_bi, &q1);
            if (rc) { bigint_destroy(&gcd_eq); goto kg_cleanup; }
            rc = bigint_is_one(&g_is_one, &gcd_eq);
            bigint_destroy(&gcd_eq);
            if (rc) goto kg_cleanup;
            if (!g_is_one) continue;
        }

        break;
    }

    /* n = p * q */
    rc = bigint_create(&n, 1);
    if (rc) goto kg_cleanup;
    rc = bigint_mul(&n, &p, &q);
    if (rc) { rc = 4; goto kg_cleanup; }

    /* phi = lcm(p-1, q-1) = (p-1)*(q-1) / gcd(p-1,q-1) */
    rc = bigint_create(&gcd_val, 1);
    if (rc) { rc = 4; goto kg_cleanup; }
    rc = bigint_gcd(&gcd_val, &p1, &q1);
    if (rc) { rc = 4; goto kg_cleanup; }

    {
        bigint p1q1, phi_temp;
        memset(&p1q1, 0, sizeof(bigint));
        memset(&phi_temp, 0, sizeof(bigint));
        rc = bigint_create(&p1q1, 1);
        if (rc) { rc = 4; goto kg_cleanup; }
        rc = bigint_mul(&p1q1, &p1, &q1);
        if (rc) { bigint_destroy(&p1q1); rc = 4; goto kg_cleanup; }

        rc = bigint_create(&phi, 1);
        if (rc) { bigint_destroy(&p1q1); rc = 4; goto kg_cleanup; }
        rc = bigint_create(&phi_temp, 1);
        if (rc) { bigint_destroy(&p1q1); rc = 4; goto kg_cleanup; }
        rc = bigint_div(&phi, &phi_temp, &p1q1, &gcd_val);
        bigint_destroy(&p1q1);
        bigint_destroy(&phi_temp);
        if (rc) { rc = 4; goto kg_cleanup; }
    }

    /* d = e^-1 mod phi */
    rc = bigint_create(&d_val, 1);
    if (rc) { rc = 4; goto kg_cleanup; }
    rc = bigint_modinv(&d_val, &e_bi, &phi);
    if (rc) { rc = 4; goto kg_cleanup; }

    /* CRT components */
    rc = bigint_create(&dp, 1);
    if (rc) { rc = 4; goto kg_cleanup; }
    rc = bigint_mod(&dp, &d_val, &p1);
    if (rc) { rc = 4; goto kg_cleanup; }

    rc = bigint_create(&dq, 1);
    if (rc) { rc = 4; goto kg_cleanup; }
    rc = bigint_mod(&dq, &d_val, &q1);
    if (rc) { rc = 4; goto kg_cleanup; }

    rc = bigint_create(&qinv, 1);
    if (rc) { rc = 4; goto kg_cleanup; }
    rc = bigint_modinv(&qinv, &q, &p);
    if (rc) { rc = 4; goto kg_cleanup; }

    /* Populate output */
    rc = bigint_copy(&out->pub.n, &n);
    if (rc) { rc = 4; goto kg_cleanup; }
    rc = bigint_copy(&out->pub.e, &e_bi);
    if (rc) { rc = 4; goto kg_cleanup; }

    rc = bigint_copy(&out->priv.n, &n);
    if (rc) { rc = 4; goto kg_cleanup; }
    rc = bigint_copy(&out->priv.e, &e_bi);
    if (rc) { rc = 4; goto kg_cleanup; }
    rc = bigint_copy(&out->priv.d, &d_val);
    if (rc) { rc = 4; goto kg_cleanup; }
    rc = bigint_copy(&out->priv.p, &p);
    if (rc) { rc = 4; goto kg_cleanup; }
    rc = bigint_copy(&out->priv.q, &q);
    if (rc) { rc = 4; goto kg_cleanup; }
    rc = bigint_copy(&out->priv.dp, &dp);
    if (rc) { rc = 4; goto kg_cleanup; }
    rc = bigint_copy(&out->priv.dq, &dq);
    if (rc) { rc = 4; goto kg_cleanup; }
    rc = bigint_copy(&out->priv.qinv, &qinv);
    if (rc) { rc = 4; goto kg_cleanup; }

kg_cleanup:
    bigint_destroy(&p);
    bigint_destroy(&q);
    bigint_destroy(&one);
    bigint_destroy(&p1);
    bigint_destroy(&q1);
    bigint_destroy(&phi);
    bigint_destroy(&e_bi);
    bigint_destroy(&gcd_val);
    bigint_destroy(&d_val);
    bigint_destroy(&dp);
    bigint_destroy(&dq);
    bigint_destroy(&qinv);
    bigint_destroy(&n);
    return rc;
}

/* ================================================================
 * OAEP Encrypt (RFC 8017 Section 7.1.1)
 * ================================================================ */

unsigned long rsa_encrypt_oaep(buf *out, rsa_pubkey *key,
                               const u8 *plaintext, u64 pt_len) {
    u64 k;       /* key length in bytes */
    u64 max_msg;
    u8 *em;
    u8 *seed;
    u8 *db;
    u8 lhash[HLEN];
    u64 db_len;
    u64 ps_len;
    unsigned long rc;

    if (!out) return 1;
    if (!key) return 2;
    if (pt_len > 0 && !plaintext) return 3;

    /* k = byte length of modulus */
    {
        u64 n_bits;
        rc = bigint_bitlen(&n_bits, &key->n);
        if (rc) return 6;
        k = (n_bits + 7) / 8;
    }

    /* max message length: k - 2*hLen - 2 */
    if (k < 2 * HLEN + 2) return 4;
    max_msg = k - 2 * HLEN - 2;
    if (pt_len > max_msg) return 4;

    db_len = k - HLEN - 1;  /* DB = lHash || PS || 0x01 || M */

    em = (u8 *)calloc(1, (size_t)k);
    seed = (u8 *)malloc(HLEN);
    db = (u8 *)calloc(1, (size_t)db_len);
    if (!em || !seed || !db) {
        free(em); free(seed); free(db);
        return 5;
    }

    /* lHash = SHA-256("") - hash of empty label */
    sha256_hash(lhash, (const u8 *)"", 0);

    /* Construct DB = lHash || PS || 0x01 || M */
    memcpy(db, lhash, HLEN);
    ps_len = db_len - HLEN - 1 - pt_len;
    /* PS is already zero from calloc */
    db[HLEN + ps_len] = 0x01;
    if (pt_len > 0) {
        memcpy(db + HLEN + ps_len + 1, plaintext, (size_t)pt_len);
    }

    /* Generate random seed */
    rc = entropy_get_system(seed, HLEN);
    if (rc) { free(em); free(seed); free(db); return 5; }

    /* maskedDB = DB XOR MGF1(seed, db_len) */
    {
        u8 *db_mask = (u8 *)malloc((size_t)db_len);
        if (!db_mask) { free(em); free(seed); free(db); return 5; }
        rc = mgf1_sha256(db_mask, db_len, seed, HLEN);
        if (rc) { free(db_mask); free(em); free(seed); free(db); return 5; }
        for (u64 i = 0; i < db_len; i++) db[i] ^= db_mask[i];
        free(db_mask);
    }

    /* maskedSeed = seed XOR MGF1(maskedDB, hLen) */
    {
        u8 seed_mask[HLEN];
        rc = mgf1_sha256(seed_mask, HLEN, db, db_len);
        if (rc) { free(em); free(seed); free(db); return 5; }
        for (u64 i = 0; i < HLEN; i++) seed[i] ^= seed_mask[i];
    }

    /* EM = 0x00 || maskedSeed || maskedDB */
    em[0] = 0x00;
    memcpy(em + 1, seed, HLEN);
    memcpy(em + 1 + HLEN, db, (size_t)db_len);

    free(seed);
    free(db);

    /* Convert EM to bigint and encrypt: c = m^e mod n */
    {
        bigint m_bi, c_bi;
        memset(&m_bi, 0, sizeof(bigint));
        memset(&c_bi, 0, sizeof(bigint));

        rc = bigint_from_bytes(&m_bi, em, k);
        free(em);
        if (rc) return 6;

        rc = bigint_create(&c_bi, 1);
        if (rc) { bigint_destroy(&m_bi); return 6; }

        rc = rsa_ep(&c_bi, &m_bi, key);
        bigint_destroy(&m_bi);
        if (rc) { bigint_destroy(&c_bi); return 6; }

        /* Convert ciphertext to fixed-size byte array */
        {
            u8 *ct_bytes = (u8 *)malloc((size_t)k);
            if (!ct_bytes) { bigint_destroy(&c_bi); return 6; }

            rc = bigint_to_fixed_bytes(ct_bytes, k, &c_bi);
            bigint_destroy(&c_bi);
            if (rc) { free(ct_bytes); return 6; }

            rc = buf_create(out, k);
            if (rc) { free(ct_bytes); return 6; }
            rc = buf_append(out, ct_bytes, k);
            free(ct_bytes);
            if (rc) { buf_destroy(out); return 6; }
        }
    }

    return 0;
}

/* ================================================================
 * OAEP Decrypt (RFC 8017 Section 7.1.2)
 * ================================================================ */

unsigned long rsa_decrypt_oaep(buf *out, rsa_privkey *key,
                               const u8 *ciphertext, u64 ct_len) {
    u64 k;
    u8 *em;
    u8 *masked_seed;
    u8 *masked_db;
    u8 seed[HLEN];
    u8 lhash[HLEN];
    u8 lhash_check[HLEN];
    u64 db_len;
    unsigned long rc;

    if (!out) return 1;
    if (!key) return 2;
    if (!ciphertext) return 3;

    /* k = byte length of modulus */
    {
        u64 n_bits;
        rc = bigint_bitlen(&n_bits, &key->n);
        if (rc) return 5;
        k = (n_bits + 7) / 8;
    }

    if (ct_len != k) return 4;
    if (k < 2 * HLEN + 2) return 5;

    /* RSA decryption */
    {
        bigint c_bi, m_bi;
        memset(&c_bi, 0, sizeof(bigint));
        memset(&m_bi, 0, sizeof(bigint));

        rc = bigint_from_bytes(&c_bi, (u8 *)ciphertext, ct_len);
        if (rc) return 5;

        rc = rsa_dp_crt(&m_bi, &c_bi, key);
        bigint_destroy(&c_bi);
        if (rc) { bigint_destroy(&m_bi); return 5; }

        em = (u8 *)calloc(1, (size_t)k);
        if (!em) { bigint_destroy(&m_bi); return 5; }

        rc = bigint_to_fixed_bytes(em, k, &m_bi);
        bigint_destroy(&m_bi);
        if (rc) { free(em); return 5; }
    }

    /* Check leading byte */
    if (em[0] != 0x00) { free(em); return 6; }

    db_len = k - HLEN - 1;
    masked_seed = em + 1;
    masked_db = em + 1 + HLEN;

    /* Recover seed: seed = maskedSeed XOR MGF1(maskedDB, hLen) */
    {
        u8 seed_mask[HLEN];
        rc = mgf1_sha256(seed_mask, HLEN, masked_db, db_len);
        if (rc) { free(em); return 6; }
        for (u64 i = 0; i < HLEN; i++) {
            seed[i] = masked_seed[i] ^ seed_mask[i];
        }
    }

    /* Recover DB: DB = maskedDB XOR MGF1(seed, db_len) */
    {
        u8 *db_mask = (u8 *)malloc((size_t)db_len);
        if (!db_mask) { free(em); return 6; }
        rc = mgf1_sha256(db_mask, db_len, seed, HLEN);
        if (rc) { free(db_mask); free(em); return 6; }
        for (u64 i = 0; i < db_len; i++) {
            masked_db[i] ^= db_mask[i];
        }
        free(db_mask);
    }

    /* Now masked_db is actually DB = lHash' || PS || 0x01 || M */
    sha256_hash(lhash, (const u8 *)"", 0);
    memcpy(lhash_check, masked_db, HLEN);

    if (memcmp(lhash, lhash_check, HLEN) != 0) {
        free(em);
        return 6;
    }

    /* Find 0x01 separator */
    {
        u64 idx = HLEN;
        u64 recovered_len;

        while (idx < db_len && masked_db[idx] == 0x00) idx++;

        if (idx >= db_len || masked_db[idx] != 0x01) {
            free(em);
            return 6;
        }
        idx++; /* skip 0x01 */

        recovered_len = db_len - idx;
        rc = buf_create(out, recovered_len > 0 ? recovered_len : 1);
        if (rc) { free(em); return 6; }
        if (recovered_len > 0) {
            rc = buf_append(out, masked_db + idx, recovered_len);
            if (rc) { free(em); buf_destroy(out); return 6; }
        }
    }

    free(em);
    return 0;
}

/* ================================================================
 * PSS Sign (RFC 8017 Section 9.1.1)
 * ================================================================ */

unsigned long rsa_sign_pss(buf *out, rsa_privkey *key,
                           const u8 *message, u64 msg_len) {
    u64 k;
    u64 em_bits;
    u64 em_len;
    u8 mhash[HLEN];
    u8 salt[HLEN];
    u8 m_prime[8 + HLEN + HLEN]; /* 8 zeros + mHash + salt */
    u8 h[HLEN];
    u8 *db;
    u8 *em;
    u64 db_len;
    u64 ps_len;
    unsigned long rc;

    if (!out) return 1;
    if (!key) return 2;
    if (msg_len > 0 && !message) return 3;

    /* k = byte length of modulus */
    {
        u64 n_bits;
        rc = bigint_bitlen(&n_bits, &key->n);
        if (rc) return 4;
        k = (n_bits + 7) / 8;
        em_bits = n_bits - 1;
        em_len = (em_bits + 7) / 8;
    }

    if (em_len < HLEN + HLEN + 2) return 4;

    /* mHash = SHA-256(message) */
    sha256_hash(mhash, message, msg_len);

    /* Generate random salt */
    rc = entropy_get_system(salt, HLEN);
    if (rc) return 4;

    /* M' = (0x)00 00 00 00 00 00 00 00 || mHash || salt */
    memset(m_prime, 0, 8);
    memcpy(m_prime + 8, mhash, HLEN);
    memcpy(m_prime + 8 + HLEN, salt, HLEN);

    /* H = SHA-256(M') */
    sha256_hash(h, m_prime, 8 + HLEN + HLEN);

    /* DB = PS || 0x01 || salt */
    db_len = em_len - HLEN - 1;
    db = (u8 *)calloc(1, (size_t)db_len);
    if (!db) return 4;

    ps_len = db_len - HLEN - 1;
    /* PS is already zeros from calloc */
    db[ps_len] = 0x01;
    memcpy(db + ps_len + 1, salt, HLEN);

    /* maskedDB = DB XOR MGF1(H, db_len) */
    {
        u8 *db_mask = (u8 *)malloc((size_t)db_len);
        if (!db_mask) { free(db); return 4; }
        rc = mgf1_sha256(db_mask, db_len, h, HLEN);
        if (rc) { free(db_mask); free(db); return 4; }
        for (u64 i = 0; i < db_len; i++) db[i] ^= db_mask[i];
        free(db_mask);
    }

    /* Set the leftmost (8*emLen - emBits) bits of maskedDB to zero */
    {
        u64 top_bits = 8 * em_len - em_bits;
        if (top_bits > 0 && top_bits < 8) {
            db[0] &= (u8)(0xFF >> top_bits);
        }
    }

    /* EM = maskedDB || H || 0xbc */
    em = (u8 *)malloc((size_t)em_len);
    if (!em) { free(db); return 4; }
    memcpy(em, db, (size_t)db_len);
    memcpy(em + db_len, h, HLEN);
    em[em_len - 1] = 0xBC;

    free(db);

    /* RSA signature: s = em^d mod n (using CRT) */
    {
        bigint m_bi, s_bi;
        memset(&m_bi, 0, sizeof(bigint));
        memset(&s_bi, 0, sizeof(bigint));

        /* Pad em to k bytes if needed (leading zero) */
        u8 *em_padded = (u8 *)calloc(1, (size_t)k);
        if (!em_padded) { free(em); return 4; }
        memcpy(em_padded + (k - em_len), em, (size_t)em_len);
        free(em);

        rc = bigint_from_bytes(&m_bi, em_padded, k);
        free(em_padded);
        if (rc) return 4;

        rc = rsa_dp_crt(&s_bi, &m_bi, key);
        bigint_destroy(&m_bi);
        if (rc) { bigint_destroy(&s_bi); return 4; }

        /* Convert signature to fixed-size byte array */
        {
            u8 *sig_bytes = (u8 *)malloc((size_t)k);
            if (!sig_bytes) { bigint_destroy(&s_bi); return 4; }

            rc = bigint_to_fixed_bytes(sig_bytes, k, &s_bi);
            bigint_destroy(&s_bi);
            if (rc) { free(sig_bytes); return 4; }

            rc = buf_create(out, k);
            if (rc) { free(sig_bytes); return 4; }
            rc = buf_append(out, sig_bytes, k);
            free(sig_bytes);
            if (rc) { buf_destroy(out); return 4; }
        }
    }

    return 0;
}

/* ================================================================
 * PSS Verify (RFC 8017 Section 9.1.2)
 * ================================================================ */

unsigned long rsa_verify_pss(unsigned long *valid, rsa_pubkey *key,
                             const u8 *signature, u64 sig_len,
                             const u8 *message, u64 msg_len) {
    u64 k;
    u64 em_bits;
    u64 em_len;
    u8 *em;
    u8 mhash[HLEN];
    u8 *masked_db;
    u8 *h_from_em;
    u8 h_prime[HLEN];
    u64 db_len;
    unsigned long rc;

    if (!valid) return 1;
    if (!key) return 2;
    if (!signature) return 3;
    if (msg_len > 0 && !message) return 4;

    *valid = 0;

    /* k = byte length of modulus */
    {
        u64 n_bits;
        rc = bigint_bitlen(&n_bits, &key->n);
        if (rc) return 5;
        k = (n_bits + 7) / 8;
        em_bits = n_bits - 1;
        em_len = (em_bits + 7) / 8;
    }

    if (sig_len != k) return 5;
    if (em_len < HLEN + HLEN + 2) return 5;

    /* RSA verification: m = s^e mod n */
    {
        bigint s_bi, m_bi;
        memset(&s_bi, 0, sizeof(bigint));
        memset(&m_bi, 0, sizeof(bigint));

        rc = bigint_from_bytes(&s_bi, (u8 *)signature, sig_len);
        if (rc) return 5;

        rc = bigint_create(&m_bi, 1);
        if (rc) { bigint_destroy(&s_bi); return 5; }

        rc = rsa_ep(&m_bi, &s_bi, key);
        bigint_destroy(&s_bi);
        if (rc) { bigint_destroy(&m_bi); return 5; }

        em = (u8 *)calloc(1, (size_t)k);
        if (!em) { bigint_destroy(&m_bi); return 5; }

        rc = bigint_to_fixed_bytes(em, k, &m_bi);
        bigint_destroy(&m_bi);
        if (rc) { free(em); return 5; }
    }

    /* Extract EM (last em_len bytes of the k-byte value) */
    {
        u8 *em_actual = em + (k - em_len);

        /* Check 0xBC trailer */
        if (em_actual[em_len - 1] != 0xBC) { free(em); return 0; } /* invalid but not an error hatch */

        db_len = em_len - HLEN - 1;
        masked_db = em_actual;
        h_from_em = em_actual + db_len;

        /* Check top bits of maskedDB are zero */
        {
            u64 top_bits = 8 * em_len - em_bits;
            if (top_bits > 0 && top_bits < 8) {
                u8 mask = (u8)(0xFF << (8 - top_bits));
                if (masked_db[0] & mask) { free(em); return 0; }
            }
        }

        /* Recover DB: DB = maskedDB XOR MGF1(H, db_len) */
        {
            u8 *db_mask = (u8 *)malloc((size_t)db_len);
            if (!db_mask) { free(em); return 5; }
            rc = mgf1_sha256(db_mask, db_len, h_from_em, HLEN);
            if (rc) { free(db_mask); free(em); return 5; }
            for (u64 i = 0; i < db_len; i++) masked_db[i] ^= db_mask[i];
            free(db_mask);
        }

        /* Zero top bits of DB */
        {
            u64 top_bits = 8 * em_len - em_bits;
            if (top_bits > 0 && top_bits < 8) {
                masked_db[0] &= (u8)(0xFF >> top_bits);
            }
        }

        /* Check PS (should be all zeros) and find 0x01 */
        {
            u64 ps_end = db_len - HLEN - 1;
            u64 i;
            u8 *salt;
            u8 m_prime[8 + HLEN + HLEN];

            for (i = 0; i < ps_end; i++) {
                if (masked_db[i] != 0x00) { free(em); return 0; }
            }
            if (masked_db[ps_end] != 0x01) { free(em); return 0; }

            /* Extract salt (hLen bytes after 0x01) */
            salt = masked_db + ps_end + 1;

            /* mHash = SHA-256(message) */
            sha256_hash(mhash, message, msg_len);

            /* M' = (0x)00 00 00 00 00 00 00 00 || mHash || salt */
            memset(m_prime, 0, 8);
            memcpy(m_prime + 8, mhash, HLEN);
            memcpy(m_prime + 8 + HLEN, salt, HLEN);

            /* H' = SHA-256(M') */
            sha256_hash(h_prime, m_prime, 8 + HLEN + HLEN);
        }

        /* Compare H and H' */
        if (memcmp(h_from_em, h_prime, HLEN) == 0) {
            *valid = 1;
        }
    }

    free(em);
    return 0;
}

/* ================================================================
 * DER encoding/decoding helpers (PKCS#1 / ASN.1)
 * ================================================================ */

/* Encode a length in DER format, return number of bytes written */
static u64 der_encode_length(u8 *out, u64 length) {
    if (length < 0x80) {
        if (out) out[0] = (u8)length;
        return 1;
    } else if (length < 0x100) {
        if (out) { out[0] = 0x81; out[1] = (u8)length; }
        return 2;
    } else if (length < 0x10000) {
        if (out) { out[0] = 0x82; out[1] = (u8)(length >> 8); out[2] = (u8)length; }
        return 3;
    } else if (length < 0x1000000) {
        if (out) { out[0] = 0x83; out[1] = (u8)(length >> 16); out[2] = (u8)(length >> 8); out[3] = (u8)length; }
        return 4;
    } else {
        if (out) { out[0] = 0x84; out[1] = (u8)(length >> 24); out[2] = (u8)(length >> 16); out[3] = (u8)(length >> 8); out[4] = (u8)length; }
        return 5;
    }
}

/* Encode a bigint as a DER INTEGER, return total size.
   If out is NULL, just compute the size. */
static unsigned long der_encode_integer(u8 *out, u64 *total_size, bigint *val) {
    u64 bl = 0;
    u64 byte_len;
    u8 *bytes;
    u64 actual_len = 0;
    unsigned long rc;
    int need_leading_zero;
    u64 content_len;
    u64 len_size;
    u64 offset;

    rc = bigint_bitlen(&bl, val);
    if (rc) return rc;

    byte_len = (bl + 7) / 8;
    if (byte_len == 0) byte_len = 1;

    bytes = (u8 *)malloc((size_t)byte_len);
    if (!bytes) return 1;

    rc = bigint_to_bytes(bytes, &actual_len, byte_len, val);
    if (rc) { free(bytes); return rc; }

    /* DER integers are signed; if top bit is set, prepend 0x00 */
    need_leading_zero = (actual_len > 0 && (bytes[0] & 0x80)) ? 1 : 0;
    content_len = actual_len + (u64)need_leading_zero;

    /* Handle the zero case */
    if (bl == 0) {
        content_len = 1;
        need_leading_zero = 0;
        actual_len = 1;
        bytes[0] = 0;
    }

    len_size = der_encode_length(NULL, content_len);
    *total_size = 1 + len_size + content_len; /* tag + length + content */

    if (out) {
        offset = 0;
        out[offset++] = 0x02; /* INTEGER tag */
        offset += der_encode_length(out + offset, content_len);
        if (need_leading_zero) out[offset++] = 0x00;
        memcpy(out + offset, bytes, (size_t)actual_len);
    }

    free(bytes);
    return 0;
}

/* Decode a DER length, advance *pos. Returns the length value. */
static unsigned long der_decode_length(u64 *length, const u8 *data, u64 data_len, u64 *pos) {
    if (*pos >= data_len) return 1;

    if (data[*pos] < 0x80) {
        *length = data[*pos];
        (*pos)++;
    } else {
        u64 num_bytes = data[*pos] & 0x7F;
        (*pos)++;
        if (num_bytes == 0 || num_bytes > 4) return 1;
        if (*pos + num_bytes > data_len) return 1;
        *length = 0;
        for (u64 i = 0; i < num_bytes; i++) {
            *length = (*length << 8) | data[*pos];
            (*pos)++;
        }
    }
    return 0;
}

/* Decode a DER INTEGER into a bigint */
static unsigned long der_decode_integer(bigint *out, const u8 *data, u64 data_len, u64 *pos) {
    u64 int_len;
    unsigned long rc;
    const u8 *int_data;

    if (*pos >= data_len || data[*pos] != 0x02) return 1;
    (*pos)++;

    rc = der_decode_length(&int_len, data, data_len, pos);
    if (rc) return rc;
    if (*pos + int_len > data_len) return 1;

    int_data = data + *pos;
    *pos += int_len;

    /* Skip leading zero if present (sign byte) */
    if (int_len > 1 && int_data[0] == 0x00) {
        int_data++;
        int_len--;
    }

    return bigint_from_bytes(out, (u8 *)int_data, int_len);
}

/* ================================================================
 * DER Export: PKCS#1 RSAPublicKey
 * ================================================================ */

/* RSAPublicKey ::= SEQUENCE { modulus INTEGER, publicExponent INTEGER } */

unsigned long rsa_pubkey_export_der(buf *out, rsa_pubkey *key) {
    u64 n_size, e_size;
    u64 seq_content_len;
    u64 seq_len_size;
    u64 total_size;
    u8 *der;
    u64 offset;
    unsigned long rc;

    if (!out) return 1;
    if (!key) return 2;

    /* Compute sizes */
    rc = der_encode_integer(NULL, &n_size, &key->n);
    if (rc) return 3;
    rc = der_encode_integer(NULL, &e_size, &key->e);
    if (rc) return 3;

    seq_content_len = n_size + e_size;
    seq_len_size = der_encode_length(NULL, seq_content_len);
    total_size = 1 + seq_len_size + seq_content_len;

    der = (u8 *)malloc((size_t)total_size);
    if (!der) return 3;

    offset = 0;
    der[offset++] = 0x30; /* SEQUENCE tag */
    offset += der_encode_length(der + offset, seq_content_len);

    rc = der_encode_integer(der + offset, &n_size, &key->n);
    if (rc) { free(der); return 3; }
    offset += n_size;

    rc = der_encode_integer(der + offset, &e_size, &key->e);
    if (rc) { free(der); return 3; }
    offset += e_size;

    rc = buf_create(out, total_size);
    if (rc) { free(der); return 3; }
    rc = buf_append(out, der, total_size);
    free(der);
    if (rc) { buf_destroy(out); return 3; }

    return 0;
}

/* ================================================================
 * DER Export: PKCS#1 RSAPrivateKey
 * ================================================================ */

/* RSAPrivateKey ::= SEQUENCE {
 *   version INTEGER (0),
 *   modulus INTEGER,
 *   publicExponent INTEGER,
 *   privateExponent INTEGER,
 *   prime1 INTEGER,
 *   prime2 INTEGER,
 *   exponent1 INTEGER,
 *   exponent2 INTEGER,
 *   coefficient INTEGER
 * } */

unsigned long rsa_privkey_export_der(buf *out, rsa_privkey *key) {
    u64 sizes[9];
    u64 seq_content_len = 0;
    u64 seq_len_size;
    u64 total_size;
    u8 *der;
    u64 offset;
    unsigned long rc;
    bigint version;
    bigint *fields[9];
    int i;

    if (!out) return 1;
    if (!key) return 2;

    memset(&version, 0, sizeof(bigint));
    rc = bigint_from_u64(&version, 0);
    if (rc) return 3;

    /* Compute sizes for each field */
    fields[0] = &version;
    fields[1] = &key->n;
    fields[2] = &key->e;
    fields[3] = &key->d;
    fields[4] = &key->p;
    fields[5] = &key->q;
    fields[6] = &key->dp;
    fields[7] = &key->dq;
    fields[8] = &key->qinv;

    for (i = 0; i < 9; i++) {
        rc = der_encode_integer(NULL, &sizes[i], fields[i]);
        if (rc) { bigint_destroy(&version); return 3; }
        seq_content_len += sizes[i];
    }

    seq_len_size = der_encode_length(NULL, seq_content_len);
    total_size = 1 + seq_len_size + seq_content_len;

    der = (u8 *)malloc((size_t)total_size);
    if (!der) { bigint_destroy(&version); return 3; }

    offset = 0;
    der[offset++] = 0x30; /* SEQUENCE tag */
    offset += der_encode_length(der + offset, seq_content_len);

    for (i = 0; i < 9; i++) {
        rc = der_encode_integer(der + offset, &sizes[i], fields[i]);
        if (rc) { free(der); bigint_destroy(&version); return 3; }
        offset += sizes[i];
    }

    bigint_destroy(&version);

    rc = buf_create(out, total_size);
    if (rc) { free(der); return 3; }
    rc = buf_append(out, der, total_size);
    free(der);
    if (rc) { buf_destroy(out); return 3; }

    return 0;
}

/* ================================================================
 * DER Import: PKCS#1 RSAPublicKey
 * ================================================================ */

unsigned long rsa_pubkey_import_der(rsa_pubkey *out, const u8 *data, u64 len) {
    u64 pos = 0;
    u64 seq_len;
    unsigned long rc;

    if (!out) return 1;
    if (!data) return 2;

    memset(out, 0, sizeof(rsa_pubkey));

    /* SEQUENCE tag */
    if (pos >= len || data[pos] != 0x30) return 3;
    pos++;

    rc = der_decode_length(&seq_len, data, len, &pos);
    if (rc) return 3;

    rc = der_decode_integer(&out->n, data, len, &pos);
    if (rc) return 3;

    rc = der_decode_integer(&out->e, data, len, &pos);
    if (rc) { bigint_destroy(&out->n); return 3; }

    return 0;
}

/* ================================================================
 * DER Import: PKCS#1 RSAPrivateKey
 * ================================================================ */

unsigned long rsa_privkey_import_der(rsa_privkey *out, const u8 *data, u64 len) {
    u64 pos = 0;
    u64 seq_len;
    unsigned long rc;
    bigint version;

    if (!out) return 1;
    if (!data) return 2;

    memset(out, 0, sizeof(rsa_privkey));
    memset(&version, 0, sizeof(bigint));

    /* SEQUENCE tag */
    if (pos >= len || data[pos] != 0x30) return 3;
    pos++;

    rc = der_decode_length(&seq_len, data, len, &pos);
    if (rc) return 3;

    /* version */
    rc = der_decode_integer(&version, data, len, &pos);
    if (rc) return 3;
    bigint_destroy(&version);

    /* modulus */
    rc = der_decode_integer(&out->n, data, len, &pos);
    if (rc) goto import_priv_fail;

    /* publicExponent */
    rc = der_decode_integer(&out->e, data, len, &pos);
    if (rc) goto import_priv_fail;

    /* privateExponent */
    rc = der_decode_integer(&out->d, data, len, &pos);
    if (rc) goto import_priv_fail;

    /* prime1 */
    rc = der_decode_integer(&out->p, data, len, &pos);
    if (rc) goto import_priv_fail;

    /* prime2 */
    rc = der_decode_integer(&out->q, data, len, &pos);
    if (rc) goto import_priv_fail;

    /* exponent1 (dp) */
    rc = der_decode_integer(&out->dp, data, len, &pos);
    if (rc) goto import_priv_fail;

    /* exponent2 (dq) */
    rc = der_decode_integer(&out->dq, data, len, &pos);
    if (rc) goto import_priv_fail;

    /* coefficient (qinv) */
    rc = der_decode_integer(&out->qinv, data, len, &pos);
    if (rc) goto import_priv_fail;

    return 0;

import_priv_fail:
    rsa_privkey_destroy(out);
    return 3;
}

/* ================================================================
 * Destroy functions
 * ================================================================ */

unsigned long rsa_pubkey_destroy(rsa_pubkey *key) {
    if (!key) return 1;
    bigint_destroy(&key->n);
    bigint_destroy(&key->e);
    return 0;
}

unsigned long rsa_privkey_destroy(rsa_privkey *key) {
    if (!key) return 1;
    bigint_destroy(&key->n);
    bigint_destroy(&key->d);
    bigint_destroy(&key->p);
    bigint_destroy(&key->q);
    bigint_destroy(&key->dp);
    bigint_destroy(&key->dq);
    bigint_destroy(&key->qinv);
    bigint_destroy(&key->e);
    return 0;
}

unsigned long rsa_keypair_destroy(rsa_keypair *kp) {
    if (!kp) return 1;
    rsa_pubkey_destroy(&kp->pub);
    rsa_privkey_destroy(&kp->priv);
    return 0;
}
unsigned long rsa_destroy(void) { return 0; }
unsigned long rsa_privkey_export(void) { return 0; }
unsigned long rsa_privkey_import(void) { return 0; }
unsigned long rsa_pubkey_export(void) { return 0; }
unsigned long rsa_pubkey_import(void) { return 0; }
unsigned long rsa_sign_pkcs1(void) { return 0; }
unsigned long rsa_verify_pkcs1(void) { return 0; }
