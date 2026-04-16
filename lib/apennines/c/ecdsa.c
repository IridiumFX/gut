#include "apennines/ecdsa.h"
#include "apennines/hash.h"
#include "apennines/entropy.h"
#include <string.h>

/* ======================================================================
 * P-256 (secp256r1) field and curve parameters
 *
 * p  = 2^256 - 2^224 + 2^192 + 2^96 - 1
 *    = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
 * a  = p - 3
 * b  = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
 * n  = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
 * Gx = 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296
 * Gy = 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5
 *
 * Field representation: 4 x 64-bit limbs, little-endian (limb[0] is LSB).
 * ====================================================================== */

typedef struct { u64 v[4]; } fiat_p256_felem;   /* mod p */
typedef struct { u64 v[4]; } p256_scalar;        /* mod n */

/* Affine point */
typedef struct {
    fiat_p256_felem x;
    fiat_p256_felem y;
} p256_affine;

/* Jacobian projective point: (X : Y : Z)  where x = X/Z^2, y = Y/Z^3 */
typedef struct {
    fiat_p256_felem x;
    fiat_p256_felem y;
    fiat_p256_felem z;
} p256_jacobian;

/* ---- 128-bit multiply helpers ---- */

#ifdef __SIZEOF_INT128__
typedef unsigned __int128 uint128_t;
#define MUL128(a, b)   ((uint128_t)(a) * (uint128_t)(b))
#define LO128(x)       ((u64)(x))
#define HI128(x)       ((u64)((x) >> 64))
#define ADD128(a, b)   ((a) + (b))
#else
typedef struct { u64 lo; u64 hi; } uint128_t;

static uint128_t p256_mul64(u64 a, u64 b) {
    uint128_t r;
    u64 a_lo = a & 0xFFFFFFFFULL, a_hi = a >> 32;
    u64 b_lo = b & 0xFFFFFFFFULL, b_hi = b >> 32;
    u64 p0 = a_lo * b_lo;
    u64 p1 = a_lo * b_hi;
    u64 p2 = a_hi * b_lo;
    u64 p3 = a_hi * b_hi;
    u64 mid = (p0 >> 32) + (p1 & 0xFFFFFFFFULL) + (p2 & 0xFFFFFFFFULL);
    r.lo = (p0 & 0xFFFFFFFFULL) | ((mid & 0xFFFFFFFFULL) << 32);
    r.hi = p3 + (p1 >> 32) + (p2 >> 32) + (mid >> 32);
    return r;
}

static uint128_t p256_add128(uint128_t a, uint128_t b) {
    uint128_t r;
    r.lo = a.lo + b.lo;
    r.hi = a.hi + b.hi + (r.lo < a.lo ? 1 : 0);
    return r;
}

#define MUL128(a, b)   p256_mul64((a), (b))
#define LO128(x)       ((x).lo)
#define HI128(x)       ((x).hi)
#define ADD128(a, b)   p256_add128((a), (b))
#endif

/* ---- P-256 field prime p ---- */

static const fiat_p256_felem P256_P = {{
    0xFFFFFFFFFFFFFFFFULL,  /* limb 0 */
    0x00000000FFFFFFFFULL,  /* limb 1 */
    0x0000000000000000ULL,  /* limb 2 */
    0xFFFFFFFF00000001ULL   /* limb 3 */
}};

/* ---- P-256 group order n ---- */

static const p256_scalar P256_N = {{
    0xF3B9CAC2FC632551ULL,
    0xBCE6FAADA7179E84ULL,
    0xFFFFFFFFFFFFFFFFULL,
    0xFFFFFFFF00000000ULL
}};

/* ---- Generator G ---- */

static const fiat_p256_felem P256_GX = {{
    0xF4A13945D898C296ULL,
    0x77037D812DEB33A0ULL,
    0xF8BCE6E563A440F2ULL,
    0x6B17D1F2E12C4247ULL
}};

static const fiat_p256_felem P256_GY = {{
    0xCBB6406837BF51F5ULL,
    0x2BCE33576B315ECEULL,
    0x8EE7EB4A7C0F9E16ULL,
    0x4FE342E2FE1A7F9BULL
}};

/* ======================================================================
 * Utility: big-endian <-> limb conversions
 * ====================================================================== */

static void bytes_to_limbs(fiat_p256_felem *out, const u8 *in) {
    /* in is 32 bytes big-endian, out is 4 limbs little-endian */
    out->v[3] = ((u64)in[0]  << 56) | ((u64)in[1]  << 48) | ((u64)in[2]  << 40) | ((u64)in[3]  << 32) |
                ((u64)in[4]  << 24) | ((u64)in[5]  << 16) | ((u64)in[6]  << 8)  | (u64)in[7];
    out->v[2] = ((u64)in[8]  << 56) | ((u64)in[9]  << 48) | ((u64)in[10] << 40) | ((u64)in[11] << 32) |
                ((u64)in[12] << 24) | ((u64)in[13] << 16) | ((u64)in[14] << 8)  | (u64)in[15];
    out->v[1] = ((u64)in[16] << 56) | ((u64)in[17] << 48) | ((u64)in[18] << 40) | ((u64)in[19] << 32) |
                ((u64)in[20] << 24) | ((u64)in[21] << 16) | ((u64)in[22] << 8)  | (u64)in[23];
    out->v[0] = ((u64)in[24] << 56) | ((u64)in[25] << 48) | ((u64)in[26] << 40) | ((u64)in[27] << 32) |
                ((u64)in[28] << 24) | ((u64)in[29] << 16) | ((u64)in[30] << 8)  | (u64)in[31];
}

static void limbs_to_bytes(u8 *out, const fiat_p256_felem *in) {
    u64 v;
    int i;
    v = in->v[3];
    for (i = 0; i < 8; i++) out[7 - i]  = (u8)(v >> (i * 8));
    v = in->v[2];
    for (i = 0; i < 8; i++) out[15 - i] = (u8)(v >> (i * 8));
    v = in->v[1];
    for (i = 0; i < 8; i++) out[23 - i] = (u8)(v >> (i * 8));
    v = in->v[0];
    for (i = 0; i < 8; i++) out[31 - i] = (u8)(v >> (i * 8));
}

static void scalar_to_bytes(u8 *out, const p256_scalar *in) {
    limbs_to_bytes(out, (const fiat_p256_felem *)in);
}

static void bytes_to_scalar(p256_scalar *out, const u8 *in) {
    bytes_to_limbs((fiat_p256_felem *)out, in);
}

/* ======================================================================
 * Constant-time helpers
 * ====================================================================== */

/* Return 0xFFFFFFFFFFFFFFFF if a != 0, else 0 */
static u64 ct_neq_zero(u64 a) {
    return (u64)((i64)(a | (u64)(-(i64)a)) >> 63);
}

/* Return 0xFFFFFFFFFFFFFFFF if a == 0, else 0 */
static u64 ct_eq_zero(u64 a) {
    return ~ct_neq_zero(a);
}

/* Constant-time conditional move: if cond != 0, dst = src */
static void felem_cmov(fiat_p256_felem *dst, const fiat_p256_felem *src, u64 cond) {
    u64 mask = ct_neq_zero(cond);
    dst->v[0] ^= mask & (dst->v[0] ^ src->v[0]);
    dst->v[1] ^= mask & (dst->v[1] ^ src->v[1]);
    dst->v[2] ^= mask & (dst->v[2] ^ src->v[2]);
    dst->v[3] ^= mask & (dst->v[3] ^ src->v[3]);
}

static void jac_cmov(p256_jacobian *dst, const p256_jacobian *src, u64 cond) {
    felem_cmov(&dst->x, &src->x, cond);
    felem_cmov(&dst->y, &src->y, cond);
    felem_cmov(&dst->z, &src->z, cond);
}

/* ======================================================================
 * Field arithmetic mod p
 *
 * We use a simple approach: operations produce results that may be
 * slightly larger than p, and we reduce lazily. Final reduction is
 * done before exporting bytes.
 * ====================================================================== */

/* Check if a >= b (constant time). Returns 1 if a >= b. */
static int felem_gte(const fiat_p256_felem *a, const fiat_p256_felem *b) {
    /* Subtract b from a with borrow */
    u64 borrow = 0;
    int i;
    for (i = 0; i < 4; i++) {
        u64 diff = a->v[i] - b->v[i] - borrow;
        /* borrow if a->v[i] < b->v[i] + old_borrow */
        if (borrow) {
            borrow = (a->v[i] <= b->v[i]) ? 1 : 0;
        } else {
            borrow = (a->v[i] < b->v[i]) ? 1 : 0;
        }
        (void)diff;
    }
    return borrow == 0;
}

/* Fully reduce mod p */
static void felem_reduce_full(fiat_p256_felem *a) {
    while (felem_gte(a, &P256_P)) {
        u64 borrow = 0;
        int i;
        for (i = 0; i < 4; i++) {
            u64 diff = a->v[i] - P256_P.v[i] - borrow;
            borrow = (borrow ? (a->v[i] <= P256_P.v[i]) : (a->v[i] < P256_P.v[i])) ? 1 : 0;
            a->v[i] = diff;
        }
    }
}

static int felem_is_zero(const fiat_p256_felem *a) {
    fiat_p256_felem t = *a;
    felem_reduce_full(&t);
    return (t.v[0] | t.v[1] | t.v[2] | t.v[3]) == 0;
}

/* a + b mod p */
static void felem_add(fiat_p256_felem *r, const fiat_p256_felem *a, const fiat_p256_felem *b) {
    u64 carry = 0;
    int i;
    for (i = 0; i < 4; i++) {
        u64 sum = a->v[i] + b->v[i] + carry;
        carry = (sum < a->v[i]) || (carry && sum == a->v[i]) ? 1 : 0;
        r->v[i] = sum;
    }
    /* Subtract p if needed */
    if (carry || felem_gte(r, &P256_P)) {
        u64 borrow = 0;
        for (i = 0; i < 4; i++) {
            u64 diff = r->v[i] - P256_P.v[i] - borrow;
            borrow = (borrow ? (r->v[i] <= P256_P.v[i]) : (r->v[i] < P256_P.v[i])) ? 1 : 0;
            r->v[i] = diff;
        }
    }
}

/* a - b mod p */
static void felem_sub(fiat_p256_felem *r, const fiat_p256_felem *a, const fiat_p256_felem *b) {
    u64 borrow = 0;
    int i;
    for (i = 0; i < 4; i++) {
        u64 diff = a->v[i] - b->v[i] - borrow;
        borrow = (borrow ? (a->v[i] <= b->v[i]) : (a->v[i] < b->v[i])) ? 1 : 0;
        r->v[i] = diff;
    }
    /* If borrow, add p */
    if (borrow) {
        u64 carry = 0;
        for (i = 0; i < 4; i++) {
            u64 sum = r->v[i] + P256_P.v[i] + carry;
            carry = (sum < r->v[i]) || (carry && sum == r->v[i]) ? 1 : 0;
            r->v[i] = sum;
        }
    }
}

/* Multiplication mod p using schoolbook 4x4 -> 8 limb product, then Barrett-like
   reduction using the special structure of the NIST P-256 prime.

   p = 2^256 - 2^224 + 2^192 + 2^96 - 1

   For a 512-bit product c = c7..c0 (each 64-bit), we reduce using:
   The reduction leverages the identity:
   2^256 = 2^224 - 2^192 - 2^96 + 1 (mod p)

   We implement the NIST reduction from FIPS 186-4 appendix D.1.
*/

/* 4x4 schoolbook multiply -> 8 limbs */
static void mul_4x4(u64 *r, const u64 *a, const u64 *b) {
    uint128_t acc;
    u64 carry;
    int i, j;

    memset(r, 0, 8 * sizeof(u64));

    for (i = 0; i < 4; i++) {
        carry = 0;
        for (j = 0; j < 4; j++) {
            acc = MUL128(a[i], b[j]);
            acc = ADD128(acc, (uint128_t)
#ifdef __SIZEOF_INT128__
                r[i + j]
#else
                (uint128_t){r[i + j], 0}
#endif
            );
            acc = ADD128(acc, (uint128_t)
#ifdef __SIZEOF_INT128__
                carry
#else
                (uint128_t){carry, 0}
#endif
            );
            r[i + j] = LO128(acc);
            carry = HI128(acc);
        }
        r[i + 4] = carry;
    }
}

/* Square: same as multiply but a=b */
static void sqr_4(u64 *r, const u64 *a) {
    mul_4x4(r, a, a);
}

/* NIST P-256 reduction of 8-limb (512-bit) product to 4-limb (256-bit) result mod p.
   Following the method from "Efficient Software Implementation of NIST P-256":

   Let c = (c7, c6, c5, c4, c3, c2, c1, c0) be the 512-bit product.
   We split each 64-bit limb into two 32-bit halves for the NIST reduction formulas.

   Actually, it's simpler to work with 32-bit words. c = (c15, ..., c0) where
   c[i] are 32-bit words, c[0] is least significant.
*/

static void p256_reduce(fiat_p256_felem *r, const u64 *c8) {
    /* Split 8 x 64-bit limbs into 16 x 32-bit words */
    u32 c[16];
    int i;
    for (i = 0; i < 8; i++) {
        c[2*i]     = (u32)(c8[i]);
        c[2*i + 1] = (u32)(c8[i] >> 32);
    }

    /* NIST P-256 reduction (FIPS 186-4 D.1.3):
       result = s1 + 2*s2 + 2*s3 + s4 + s5 - s6 - s7 - s8 - s9 mod p

       where (using 32-bit word indices, 0=LSW):
       s1 = ( c7,  c6,  c5,  c4,  c3,  c2, c1, c0)
       s2 = (c15, c14, c13, c12, c11,   0,  0,  0)
       s3 = (  0, c15, c14, c13, c12,   0,  0,  0)
       s4 = (c15, c14,   0,   0,   0, c10, c9, c8)
       s5 = ( c8, c13, c15, c14, c13, c11, c10, c9)
       s6 = (c10,  c8,   0,   0,   0, c13, c12, c11)
       s7 = (c11,  c9,   0,   0, c15, c14, c13, c12)
       s8 = (c12,  0,  c10,  c9,  c8, c15, c14, c13)
       s9 = (c13,  0,  c11, c10,  c9,   0, c15, c14)
    */

    /* Use i64 accumulators for each 32-bit word position to handle carries */
    i64 acc[8];

    /* s1 */
    acc[0] = (i64)c[0];
    acc[1] = (i64)c[1];
    acc[2] = (i64)c[2];
    acc[3] = (i64)c[3];
    acc[4] = (i64)c[4];
    acc[5] = (i64)c[5];
    acc[6] = (i64)c[6];
    acc[7] = (i64)c[7];

    /* + 2*s2: s2 = (c15, c14, c13, c12, c11, 0, 0, 0) */
    acc[3] += 2 * (i64)c[11];
    acc[4] += 2 * (i64)c[12];
    acc[5] += 2 * (i64)c[13];
    acc[6] += 2 * (i64)c[14];
    acc[7] += 2 * (i64)c[15];

    /* + 2*s3: s3 = (0, c15, c14, c13, c12, 0, 0, 0) */
    acc[3] += 2 * (i64)c[12];
    acc[4] += 2 * (i64)c[13];
    acc[5] += 2 * (i64)c[14];
    acc[6] += 2 * (i64)c[15];

    /* + s4: s4 = (c15, c14, 0, 0, 0, c10, c9, c8) */
    acc[0] += (i64)c[8];
    acc[1] += (i64)c[9];
    acc[2] += (i64)c[10];
    acc[6] += (i64)c[14];
    acc[7] += (i64)c[15];

    /* + s5: s5 = (c8, c13, c15, c14, c13, c11, c10, c9) */
    acc[0] += (i64)c[9];
    acc[1] += (i64)c[10];
    acc[2] += (i64)c[11];
    acc[3] += (i64)c[13];
    acc[4] += (i64)c[14];
    acc[5] += (i64)c[15];
    acc[6] += (i64)c[13];
    acc[7] += (i64)c[8];

    /* - s6: s6 = (c10, c8, 0, 0, 0, c13, c12, c11) */
    acc[0] -= (i64)c[11];
    acc[1] -= (i64)c[12];
    acc[2] -= (i64)c[13];
    acc[6] -= (i64)c[8];
    acc[7] -= (i64)c[10];

    /* - s7: s7 = (c11, c9, 0, 0, c15, c14, c13, c12) */
    acc[0] -= (i64)c[12];
    acc[1] -= (i64)c[13];
    acc[2] -= (i64)c[14];
    acc[3] -= (i64)c[15];
    acc[6] -= (i64)c[9];
    acc[7] -= (i64)c[11];

    /* - s8: s8 = (c12, 0, c10, c9, c8, c15, c14, c13) */
    acc[0] -= (i64)c[13];
    acc[1] -= (i64)c[14];
    acc[2] -= (i64)c[15];
    acc[3] -= (i64)c[8];
    acc[4] -= (i64)c[9];
    acc[5] -= (i64)c[10];
    acc[7] -= (i64)c[12];

    /* - s9: s9 = (c13, 0, c11, c10, c9, 0, c15, c14) */
    acc[0] -= (i64)c[14];
    acc[1] -= (i64)c[15];
    acc[3] -= (i64)c[9];
    acc[4] -= (i64)c[10];
    acc[5] -= (i64)c[11];
    acc[7] -= (i64)c[13];

    /* Propagate carries through the 32-bit word accumulator chain */
    i64 carry = 0;
    for (i = 0; i < 8; i++) {
        acc[i] += carry;
        carry = acc[i] >> 32;
        acc[i] &= 0xFFFFFFFF;
    }

    /* Pack 32-bit words back into 64-bit limbs */
    r->v[0] = (u64)acc[0] | ((u64)acc[1] << 32);
    r->v[1] = (u64)acc[2] | ((u64)acc[3] << 32);
    r->v[2] = (u64)acc[4] | ((u64)acc[5] << 32);
    r->v[3] = (u64)acc[6] | ((u64)acc[7] << 32);

    /* Handle remaining carry or borrow by adding/subtracting p */
    while (carry > 0) {
        u64 c2 = 0;
        for (i = 0; i < 4; i++) {
            u64 sum = r->v[i] + P256_P.v[i] * (u64)0 + c2;
            /* Actually subtract p means: result is already there, just subtract p */
            (void)sum;
        }
        /* Simply: subtract p 'carry' times */
        {
            u64 borrow = 0;
            for (i = 0; i < 4; i++) {
                u64 diff = r->v[i] - P256_P.v[i] - borrow;
                borrow = (borrow ? (r->v[i] <= P256_P.v[i]) : (r->v[i] < P256_P.v[i])) ? 1 : 0;
                r->v[i] = diff;
            }
        }
        carry--;
    }

    while (carry < 0) {
        /* Add p */
        u64 c2 = 0;
        for (i = 0; i < 4; i++) {
            u64 sum = r->v[i] + P256_P.v[i] + c2;
            c2 = (sum < r->v[i]) || (c2 && sum == r->v[i]) ? 1 : 0;
            r->v[i] = sum;
        }
        carry++;
    }

    /* Final reduction: ensure result < p */
    felem_reduce_full(r);
}

/* a * b mod p */
static void felem_mul(fiat_p256_felem *r, const fiat_p256_felem *a, const fiat_p256_felem *b) {
    u64 c8[8];
    mul_4x4(c8, a->v, b->v);
    p256_reduce(r, c8);
}

/* a^2 mod p */
static void felem_sqr(fiat_p256_felem *r, const fiat_p256_felem *a) {
    u64 c8[8];
    sqr_4(c8, a->v);
    p256_reduce(r, c8);
}

/* a * 2 mod p */
static void felem_dbl(fiat_p256_felem *r, const fiat_p256_felem *a) {
    felem_add(r, a, a);
}

/* a * 3 mod p */
static void felem_mul3(fiat_p256_felem *r, const fiat_p256_felem *a) {
    fiat_p256_felem t;
    felem_dbl(&t, a);
    felem_add(r, &t, a);
}

/* a * 8 mod p */
static void felem_mul8(fiat_p256_felem *r, const fiat_p256_felem *a) {
    fiat_p256_felem t;
    felem_dbl(&t, a);
    felem_dbl(&t, &t);
    felem_dbl(r, &t);
}

/* Modular inverse mod p using Fermat's little theorem: a^(p-2) mod p */
static void felem_inv(fiat_p256_felem *r, const fiat_p256_felem *a) {
    /* p-2 = FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFD
       We use a square-and-multiply chain. For P-256 this is well-known. */
    fiat_p256_felem t, t2, t4, t8, t16, t32;
    int i;

    /* t2 = a^(2^2 - 1) */
    felem_sqr(&t, a);       /* a^2 */
    felem_mul(&t2, &t, a);  /* a^3 = a^(2^2-1) */

    /* t4 = a^(2^4 - 1) */
    felem_sqr(&t, &t2);
    felem_sqr(&t, &t);
    felem_mul(&t4, &t, &t2);

    /* t8 = a^(2^8 - 1) */
    felem_sqr(&t, &t4);
    for (i = 0; i < 3; i++) felem_sqr(&t, &t);
    felem_mul(&t8, &t, &t4);

    /* t16 = a^(2^16 - 1) */
    felem_sqr(&t, &t8);
    for (i = 0; i < 7; i++) felem_sqr(&t, &t);
    felem_mul(&t16, &t, &t8);

    /* t32 = a^(2^32 - 1) */
    felem_sqr(&t, &t16);
    for (i = 0; i < 15; i++) felem_sqr(&t, &t);
    felem_mul(&t32, &t, &t16);

    /* Now compute a^(p-2) using the structure of p:
       p - 2 = FFFFFFFF 00000001 00000000 00000000 00000000 FFFFFFFF FFFFFFFF FFFFFFFD

       Start with a^(2^32 - 1) and build up.
    */

    /* Accumulator = t32 = a^(2^32 - 1) */
    /* We need: bits 255..224 = FFFFFFFF => a^(2^32-1) shifted left by 224 bits
                bits 223..192 = 00000001 => a^1 shifted left by 192 bits
                bits 191..96  = 0 (96 zero bits)
                bits 95..64   = FFFFFFFF => a^(2^32-1) shifted left by 64 bits
                bits 63..32   = FFFFFFFF => a^(2^32-1) shifted left by 32 bits
                bits 31..2    = FFFFFFFC => need (a^(2^30-1)) * a^0 ... it's complex
                bits 1..0     = 01

       Better approach: just do the binary exponentiation.
    */

    /* acc = t32 (covers top 32 bits: FFFFFFFF) */
    fiat_p256_felem acc;
    acc = t32;

    /* Next 32 bits of exponent: 00000001
       Shift acc left 32 bits (square 32 times), then multiply by a */
    for (i = 0; i < 32; i++) felem_sqr(&acc, &acc);
    felem_mul(&acc, &acc, a); /* ...00000001 */

    /* Next 64 bits: 00000000 00000000 */
    for (i = 0; i < 64; i++) felem_sqr(&acc, &acc);

    /* Next 32 bits: 00000000 */
    for (i = 0; i < 32; i++) felem_sqr(&acc, &acc);

    /* Next 32 bits: FFFFFFFF */
    for (i = 0; i < 32; i++) felem_sqr(&acc, &acc);
    felem_mul(&acc, &acc, &t32);

    /* Next 32 bits: FFFFFFFF */
    for (i = 0; i < 32; i++) felem_sqr(&acc, &acc);
    felem_mul(&acc, &acc, &t32);

    /* Next 30 bits: FFFFFFFD >> 2 = 3FFFFFFF
       Bottom 2 bits: 01

       Actually the remaining bits are: FFFFFFFD
       = 11111111 11111111 11111111 11111101 in binary
       = (2^32 - 3) = (2^32 - 1) - 2

       So: shift 32 bits, multiply by a^(2^32-1), then we'd get ..FFFFFFFF
       But we need FFFFFFFD = FFFFFFFF - 2.

       Better: FFFFFFFD in binary = 30 ones, then 0, then 1.
       a^FFFFFFFD = a^(2^32 - 3)

       Use: square 30 times from a^(2^30-1), multiply by...
       Let's just do it bit by bit for the last 32 bits.
    */
    for (i = 0; i < 32; i++) felem_sqr(&acc, &acc);

    /* Multiply by a^(FFFFFFFD).
       FFFFFFFD = t32 * a^(-2) but inverse is expensive.
       Instead build a^FFFFFFFD from scratch:
       FFFFFFFD = 2^32 - 3
       a^(2^32-3) = a^(2^32-1) * a^(-2)

       Or: 0xFFFFFFFD = 0b 1111_1111_1111_1111_1111_1111_1111_1101
       That's 30 leading 1s, then 0, then 1.
       a^(2^30-1) can be built from t16, etc.
    */
    {
        /* Build a^(0xFFFFFFFD) */
        fiat_p256_felem e;
        /* a^(2^30 - 1): start from t16 = a^(2^16-1) */
        fiat_p256_felem t14;
        /* t14 = a^(2^14 - 1): from t8 and pieces */
        felem_sqr(&t, &t8);
        for (i = 0; i < 5; i++) felem_sqr(&t, &t);
        /* t is a^(2^14) ... nope. Let me just build carefully. */

        /* For the last 32 bits = 0xFFFFFFFD, direct square-and-multiply: */
        e = *a;  /* a^1 */
        /* bit 31 (MSB) is 1, already in e */
        /* bits 30 down to 2: FFFFFFFD >> 1 = 7FFFFFFE, bit 1 = 0, bit 0 = 1 */
        {
            u32 exp = 0xFFFFFFFDu;
            int bit;
            for (bit = 30; bit >= 0; bit--) {
                felem_sqr(&e, &e);
                if ((exp >> bit) & 1) {
                    felem_mul(&e, &e, a);
                }
            }
        }
        felem_mul(&acc, &acc, &e);
    }

    *r = acc;
}

/* ======================================================================
 * Scalar arithmetic mod n
 * ====================================================================== */

/* Compare scalars. Returns 1 if a >= b */
static int scalar_gte(const p256_scalar *a, const p256_scalar *b) {
    return felem_gte((const fiat_p256_felem *)a, (const fiat_p256_felem *)b);
}

static int scalar_is_zero(const p256_scalar *a) {
    return (a->v[0] | a->v[1] | a->v[2] | a->v[3]) == 0;
}

/* Reduce scalar mod n (single subtraction, assumes a < 2n) */
static void scalar_reduce(p256_scalar *a) {
    if (scalar_gte(a, &P256_N)) {
        u64 borrow = 0;
        int i;
        for (i = 0; i < 4; i++) {
            u64 diff = a->v[i] - P256_N.v[i] - borrow;
            borrow = (borrow ? (a->v[i] <= P256_N.v[i]) : (a->v[i] < P256_N.v[i])) ? 1 : 0;
            a->v[i] = diff;
        }
    }
}

/* Scalar addition mod n */
static void scalar_add(p256_scalar *r, const p256_scalar *a, const p256_scalar *b) {
    u64 carry = 0;
    int i;
    for (i = 0; i < 4; i++) {
        u64 sum = a->v[i] + b->v[i] + carry;
        carry = (sum < a->v[i]) || (carry && sum == a->v[i]) ? 1 : 0;
        r->v[i] = sum;
    }
    /* If carry or >= n, subtract n */
    if (carry || scalar_gte(r, &P256_N)) {
        u64 borrow = 0;
        for (i = 0; i < 4; i++) {
            u64 diff = r->v[i] - P256_N.v[i] - borrow;
            borrow = (borrow ? (r->v[i] <= P256_N.v[i]) : (r->v[i] < P256_N.v[i])) ? 1 : 0;
            r->v[i] = diff;
        }
    }
}

/* Scalar multiplication mod n */
static void scalar_mul(p256_scalar *r, const p256_scalar *a, const p256_scalar *b) {
    u64 c8[8];
    mul_4x4(c8, a->v, b->v);

    /* Reduce mod n. We use Barrett reduction.
       n is close to 2^256, so we can do repeated subtraction from the 512-bit product.

       More precisely, we do:
       q = c8 / n (approximate)
       r = c8 - q * n

       For simplicity, since n ~ 2^256, we just reduce iteratively.
    */

    /* Simple approach: convert to limbs and reduce.
       The product is at most (n-1)^2 < 2^512.
       We need at most a few subtractions of n * 2^(64*k). */

    /* Actually let's implement proper modular reduction for the scalar.
       We'll use the schoolbook long division approach: process from high limb down. */
    p256_scalar result;
    u64 tmp[8];
    int i;
    memcpy(tmp, c8, sizeof(tmp));

    /* Reduce from the top: for each high limb, subtract appropriate multiple of n */
    for (i = 7; i >= 4; i--) {
        while (tmp[i] != 0) {
            /* Subtract tmp[i] * n * 2^(64*(i-4)) from tmp */
            u64 q = tmp[i];
            u64 borrow = 0;
            int j;
            for (j = 0; j < 4; j++) {
                uint128_t prod = MUL128(q, P256_N.v[j]);
                prod = ADD128(prod, (uint128_t)
#ifdef __SIZEOF_INT128__
                    borrow
#else
                    (uint128_t){borrow, 0}
#endif
                );
                u64 sub_lo = LO128(prod);
                u64 sub_hi = HI128(prod);
                u64 prev = tmp[i - 4 + j];
                u64 diff = prev - sub_lo;
                u64 b2 = (diff > prev) ? 1 : 0;
                tmp[i - 4 + j] = diff;
                borrow = sub_hi + b2;
            }
            tmp[i] -= borrow;
        }
    }

    result.v[0] = tmp[0];
    result.v[1] = tmp[1];
    result.v[2] = tmp[2];
    result.v[3] = tmp[3];

    /* Final reduction: ensure < n */
    while (scalar_gte(&result, &P256_N)) {
        u64 borrow = 0;
        for (i = 0; i < 4; i++) {
            u64 diff = result.v[i] - P256_N.v[i] - borrow;
            borrow = (borrow ? (result.v[i] <= P256_N.v[i]) : (result.v[i] < P256_N.v[i])) ? 1 : 0;
            result.v[i] = diff;
        }
    }

    *r = result;
}

/* Scalar modular inverse mod n using Fermat: a^(n-2) mod n */
static void scalar_inv(p256_scalar *r, const p256_scalar *a) {
    /* n-2 as bytes (big-endian):
       FFFFFFFF 00000000 FFFFFFFF FFFFFFFE BCE6FAAD A7179E84 F3B9CAC2 FC63254F
    */
    p256_scalar base = *a;
    p256_scalar acc;
    u8 n_minus_2[32];
    int i, bit;

    /* Compute n-2 */
    {
        p256_scalar nm2 = P256_N;
        u64 borrow = 0;
        u64 sub_val;
        /* Subtract 2 from n */
        sub_val = nm2.v[0] - 2;
        borrow = (sub_val > nm2.v[0]) ? 1 : 0;
        nm2.v[0] = sub_val;
        for (i = 1; i < 4; i++) {
            sub_val = nm2.v[i] - borrow;
            borrow = (sub_val > nm2.v[i]) ? 1 : 0;
            nm2.v[i] = sub_val;
        }
        scalar_to_bytes(n_minus_2, &nm2);
    }

    /* Binary square-and-multiply, MSB first */
    /* Find first set bit */
    acc.v[0] = acc.v[1] = acc.v[2] = acc.v[3] = 0;
    int started = 0;
    for (i = 0; i < 32; i++) {
        for (bit = 7; bit >= 0; bit--) {
            if (started) {
                scalar_mul(&acc, &acc, &acc);
            }
            if ((n_minus_2[i] >> bit) & 1) {
                if (started) {
                    scalar_mul(&acc, &acc, &base);
                } else {
                    acc = base;
                    started = 1;
                }
            }
        }
    }

    *r = acc;
}

/* ======================================================================
 * Point operations in Jacobian coordinates
 * ====================================================================== */

static void jac_set_infinity(p256_jacobian *p) {
    memset(p, 0, sizeof(*p));
    /* Infinity represented as Z = 0 */
}

static int jac_is_infinity(const p256_jacobian *p) {
    return felem_is_zero(&p->z);
}

/* Point doubling in Jacobian coordinates.
   Uses the "dbl-2001-b" formula from https://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-3.html
   (for a = -3 curves like P-256):

   delta = Z1^2
   gamma = Y1^2
   beta = X1*gamma
   alpha = 3*(X1-delta)*(X1+delta)    [since a = -3]
   X3 = alpha^2 - 8*beta
   Y3 = alpha*(4*beta - X3) - 8*gamma^2
   Z3 = (Y1+Z1)^2 - gamma - delta
*/
static void jac_double(p256_jacobian *r, const p256_jacobian *p) {
    fiat_p256_felem delta, gamma, beta, alpha, t1, t2, t3;

    if (jac_is_infinity(p)) {
        *r = *p;
        return;
    }

    felem_sqr(&delta, &p->z);                   /* delta = Z^2 */
    felem_sqr(&gamma, &p->y);                   /* gamma = Y^2 */
    felem_mul(&beta, &p->x, &gamma);            /* beta = X * gamma */

    felem_sub(&t1, &p->x, &delta);              /* X - delta */
    felem_add(&t2, &p->x, &delta);              /* X + delta */
    felem_mul(&t3, &t1, &t2);                   /* (X-delta)(X+delta) */
    felem_mul3(&alpha, &t3);                     /* alpha = 3*(X-delta)(X+delta) */

    /* Compute Z3 first, before overwriting r->x and r->y, since
       when r aliases p, writing r->y would destroy p->y which Z3 needs. */
    felem_add(&t1, &p->y, &p->z);               /* Y+Z */
    felem_sqr(&t1, &t1);                         /* (Y+Z)^2 */
    felem_sub(&t1, &t1, &gamma);                 /* - gamma */
    felem_sub(&t2, &t1, &delta);                 /* Z3 = (Y+Z)^2 - gamma - delta */

    felem_sqr(&t1, &alpha);                      /* alpha^2 */
    felem_mul8(&t3, &beta);                      /* 8*beta */
    felem_sub(&r->x, &t1, &t3);                 /* X3 = alpha^2 - 8*beta */

    fiat_p256_felem four_beta;
    felem_dbl(&four_beta, &beta);
    felem_dbl(&four_beta, &four_beta);           /* 4*beta */
    felem_sub(&t1, &four_beta, &r->x);          /* 4*beta - X3 */
    felem_mul(&t3, &alpha, &t1);                 /* alpha*(4*beta - X3) */
    felem_sqr(&t1, &gamma);                      /* gamma^2 */
    felem_mul8(&alpha, &t1);                     /* 8*gamma^2 (reuse alpha as temp) */
    felem_sub(&r->y, &t3, &alpha);              /* Y3 */

    r->z = t2;                                   /* Z3 */
}

/* Point addition in Jacobian coordinates (mixed: Q is affine, i.e. Z_Q = 1).
   Uses madd-2004-hmv:

   u1 = X1, s1 = Y1  (since Z2=1 => Z2^2=1, Z2^3=1)
   u2 = X2 * Z1^2
   s2 = Y2 * Z1^3
   h = u2 - u1
   r = s2 - s1
   X3 = r^2 - h^3 - 2*u1*h^2
   Y3 = r*(u1*h^2 - X3) - s1*h^3
   Z3 = Z1 * h
*/
static void jac_add_affine(p256_jacobian *res, const p256_jacobian *p, const p256_affine *q) {
    fiat_p256_felem z1z1, u2, s2, h, hh, hhh, rr, t1, t2, t3;
    int p_inf = jac_is_infinity(p);

    felem_sqr(&z1z1, &p->z);                    /* Z1^2 */
    felem_mul(&u2, &q->x, &z1z1);               /* u2 = X2 * Z1^2 */
    felem_mul(&t1, &p->z, &z1z1);               /* Z1^3 */
    felem_mul(&s2, &q->y, &t1);                 /* s2 = Y2 * Z1^3 */

    felem_sub(&h, &u2, &p->x);                  /* h = u2 - X1 */
    felem_sub(&rr, &s2, &p->y);                 /* r = s2 - Y1 */

    /* Check for special cases */
    int h_zero = felem_is_zero(&h);
    int r_zero = felem_is_zero(&rr);

    if (h_zero && r_zero && !p_inf) {
        /* P == Q, do doubling */
        jac_double(res, p);
        return;
    }

    felem_sqr(&hh, &h);                         /* h^2 */
    felem_mul(&hhh, &hh, &h);                   /* h^3 */
    felem_mul(&t2, &p->x, &hh);                 /* u1*h^2 */

    felem_sqr(&t1, &rr);                        /* r^2 */
    felem_sub(&t1, &t1, &hhh);                  /* r^2 - h^3 */
    felem_dbl(&t3, &t2);                         /* 2*u1*h^2 */
    felem_sub(&res->x, &t1, &t3);               /* X3 */

    felem_sub(&t1, &t2, &res->x);               /* u1*h^2 - X3 */
    felem_mul(&t2, &rr, &t1);                   /* r*(u1*h^2 - X3) */
    felem_mul(&t3, &p->y, &hhh);                /* s1*h^3 */
    felem_sub(&res->y, &t2, &t3);               /* Y3 */

    felem_mul(&res->z, &p->z, &h);              /* Z3 = Z1 * h */

    /* If P was infinity, result is Q (in Jacobian: X=Qx, Y=Qy, Z=1) */
    if (p_inf) {
        res->x = q->x;
        res->y = q->y;
        res->z.v[0] = 1; res->z.v[1] = res->z.v[2] = res->z.v[3] = 0;
    }
}

/* General Jacobian + Jacobian addition */
static void jac_add(p256_jacobian *res, const p256_jacobian *p, const p256_jacobian *q) {
    fiat_p256_felem z1z1, z2z2, u1, u2, s1, s2, h, rr, hh, hhh, t1, t2, t3;

    int p_inf = jac_is_infinity(p);
    int q_inf = jac_is_infinity(q);

    if (p_inf) { *res = *q; return; }
    if (q_inf) { *res = *p; return; }

    felem_sqr(&z1z1, &p->z);
    felem_sqr(&z2z2, &q->z);

    felem_mul(&u1, &p->x, &z2z2);
    felem_mul(&u2, &q->x, &z1z1);

    felem_mul(&t1, &p->z, &z1z1);  /* Z1^3 */
    felem_mul(&t2, &q->z, &z2z2);  /* Z2^3 */
    felem_mul(&s1, &p->y, &t2);
    felem_mul(&s2, &q->y, &t1);

    felem_sub(&h, &u2, &u1);
    felem_sub(&rr, &s2, &s1);

    int h_zero = felem_is_zero(&h);
    int r_zero = felem_is_zero(&rr);

    if (h_zero && r_zero) {
        jac_double(res, p);
        return;
    }

    if (h_zero && !r_zero) {
        /* P = -Q, result is infinity */
        jac_set_infinity(res);
        return;
    }

    felem_sqr(&hh, &h);
    felem_mul(&hhh, &hh, &h);
    felem_mul(&t1, &u1, &hh);

    felem_sqr(&t2, &rr);
    felem_sub(&t2, &t2, &hhh);
    felem_dbl(&t3, &t1);
    felem_sub(&res->x, &t2, &t3);

    felem_sub(&t2, &t1, &res->x);
    felem_mul(&t3, &rr, &t2);
    felem_mul(&t1, &s1, &hhh);
    felem_sub(&res->y, &t3, &t1);

    felem_mul(&t1, &p->z, &q->z);
    felem_mul(&res->z, &t1, &h);
}

/* Convert Jacobian -> Affine: x = X/Z^2, y = Y/Z^3 */
static void jac_to_affine(p256_affine *out, const p256_jacobian *p) {
    fiat_p256_felem z_inv, z2, z3;
    felem_inv(&z_inv, &p->z);
    felem_sqr(&z2, &z_inv);
    felem_mul(&z3, &z2, &z_inv);
    felem_mul(&out->x, &p->x, &z2);
    felem_mul(&out->y, &p->y, &z3);
    felem_reduce_full(&out->x);
    felem_reduce_full(&out->y);
}

/* ======================================================================
 * Scalar multiplication: constant-time double-and-add-always
 *
 * For each bit of the scalar (MSB to LSB):
 *   R0 = double(R0)
 *   R1 = R0 + P
 *   cmov(R0, R1, bit)
 * ====================================================================== */

static void scalar_mult(p256_jacobian *r, const p256_scalar *k, const p256_affine *p) {
    p256_jacobian r0, r1;
    u8 k_bytes[32];
    int i, bit;

    scalar_to_bytes(k_bytes, k);

    jac_set_infinity(&r0);

    for (i = 0; i < 32; i++) {
        for (bit = 7; bit >= 0; bit--) {
            jac_double(&r0, &r0);
            jac_add_affine(&r1, &r0, p);
            jac_cmov(&r0, &r1, (k_bytes[i] >> bit) & 1);
        }
    }

    *r = r0;
}

/* Base point multiplication: scalar * G */
static void scalar_mult_base(p256_jacobian *r, const p256_scalar *k) {
    p256_affine g;
    g.x = P256_GX;
    g.y = P256_GY;
    scalar_mult(r, k, &g);
}

/* ======================================================================
 * Point validation
 * ====================================================================== */

/* Check that an affine point is on the P-256 curve: y^2 = x^3 + ax + b mod p
   where a = p - 3 and b = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B */
static int point_on_curve(const p256_affine *p) {
    static const fiat_p256_felem P256_B = {{
        0x3BCE3C3E27D2604BULL,
        0x651D06B0CC53B0F6ULL,
        0xB3EBBD55769886BCULL,
        0x5AC635D8AA3A93E7ULL
    }};

    fiat_p256_felem y2, x3, ax, rhs, three;

    /* y^2 */
    felem_sqr(&y2, &p->y);

    /* x^3 */
    felem_sqr(&x3, &p->x);
    felem_mul(&x3, &x3, &p->x);

    /* a*x = (p-3)*x = -3x mod p */
    three.v[0] = 3; three.v[1] = three.v[2] = three.v[3] = 0;
    felem_mul(&ax, &p->x, &three);

    /* rhs = x^3 - 3x + b */
    felem_sub(&rhs, &x3, &ax);
    felem_add(&rhs, &rhs, &P256_B);

    /* Check y^2 == rhs mod p */
    felem_reduce_full(&y2);
    felem_reduce_full(&rhs);

    return (y2.v[0] == rhs.v[0]) && (y2.v[1] == rhs.v[1]) &&
           (y2.v[2] == rhs.v[2]) && (y2.v[3] == rhs.v[3]);
}

/* ======================================================================
 * Encode / decode public keys (uncompressed format: 04 || x || y)
 * ====================================================================== */

static void encode_pubkey(ecdsa_pubkey *pub, const p256_affine *pt) {
    pub->data[0] = 0x04;
    limbs_to_bytes(pub->data + 1, &pt->x);
    limbs_to_bytes(pub->data + 33, &pt->y);
}

static unsigned long decode_pubkey(p256_affine *pt, const ecdsa_pubkey *pub) {
    if (pub->data[0] != 0x04) return 1; /* not uncompressed */
    bytes_to_limbs(&pt->x, pub->data + 1);
    bytes_to_limbs(&pt->y, pub->data + 33);
    if (!point_on_curve(pt)) return 1;
    return 0;
}

/* ======================================================================
 * RFC 6979: deterministic nonce generation
 * ====================================================================== */

static unsigned long rfc6979_generate_k(p256_scalar *k_out,
                                          const u8 *priv_bytes,
                                          const u8 *hash32) {
    /* RFC 6979 Section 3.2 for SHA-256 (qlen = 256, hlen = 256) */
    u8 V[32], K[32];
    u8 tmp[32 + 1 + 32 + 32]; /* V || 0x00/0x01 || priv || hash */
    unsigned long rc;
    hmac_ctx hctx;
    int attempt;

    /* Step b: V = 0x01 01 01 ... (32 bytes) */
    memset(V, 0x01, 32);

    /* Step c: K = 0x00 00 00 ... (32 bytes) */
    memset(K, 0x00, 32);

    /* Step d: K = HMAC_K(V || 0x00 || int2octets(x) || bits2octets(h1)) */
    memcpy(tmp, V, 32);
    tmp[32] = 0x00;
    memcpy(tmp + 33, priv_bytes, 32);
    memcpy(tmp + 65, hash32, 32);
    rc = hmac_digest(K, HMAC_HASH_SHA256, K, 32, tmp, 97);
    if (rc) return rc;

    /* Step e: V = HMAC_K(V) */
    rc = hmac_digest(V, HMAC_HASH_SHA256, K, 32, V, 32);
    if (rc) return rc;

    /* Step f: K = HMAC_K(V || 0x01 || int2octets(x) || bits2octets(h1)) */
    memcpy(tmp, V, 32);
    tmp[32] = 0x01;
    memcpy(tmp + 33, priv_bytes, 32);
    memcpy(tmp + 65, hash32, 32);
    rc = hmac_digest(K, HMAC_HASH_SHA256, K, 32, tmp, 97);
    if (rc) return rc;

    /* Step g: V = HMAC_K(V) */
    rc = hmac_digest(V, HMAC_HASH_SHA256, K, 32, V, 32);
    if (rc) return rc;

    /* Step h: generate k */
    for (attempt = 0; attempt < 100; attempt++) {
        /* V = HMAC_K(V) */
        rc = hmac_digest(V, HMAC_HASH_SHA256, K, 32, V, 32);
        if (rc) return rc;

        /* T = V (since hlen = qlen = 256, one iteration suffices) */
        bytes_to_scalar(k_out, V);

        /* Check 1 <= k < n */
        if (!scalar_is_zero(k_out) && !scalar_gte(k_out, &P256_N)) {
            /* Wipe temp */
            memset(K, 0, 32);
            memset(V, 0, 32);
            memset(tmp, 0, sizeof(tmp));
            return 0;
        }

        /* k was out of range, update K and V and try again */
        memcpy(tmp, V, 32);
        tmp[32] = 0x00;
        rc = hmac_digest(K, HMAC_HASH_SHA256, K, 32, tmp, 33);
        if (rc) return rc;
        rc = hmac_digest(V, HMAC_HASH_SHA256, K, 32, V, 32);
        if (rc) return rc;
    }

    return 1; /* failed to generate valid k */
}

/* ======================================================================
 * Check if a private key is valid: 0 < priv < n
 * ====================================================================== */

static int privkey_valid(const u8 *priv_bytes) {
    p256_scalar s;
    bytes_to_scalar(&s, priv_bytes);
    if (scalar_is_zero(&s)) return 0;
    if (scalar_gte(&s, &P256_N)) return 0;
    return 1;
}

/* ======================================================================
 * Public API
 * ====================================================================== */

unsigned long ecdsa_keygen(ecdsa_privkey *priv, ecdsa_pubkey *pub) {
    if (!priv) return 1;
    if (!pub)  return 2;

    /* Generate random private key: try up to 100 times to get valid key */
    int i;
    for (i = 0; i < 100; i++) {
        unsigned long rc = entropy_get_system(priv->data, 32);
        if (rc) return 3;
        if (privkey_valid(priv->data)) {
            /* Derive public key */
            rc = ecdsa_pubkey_derive(pub, priv);
            if (rc) return 4;
            return 0;
        }
    }
    return 4; /* extremely unlikely: 100 attempts all invalid */
}

unsigned long ecdsa_keygen_from_seed(ecdsa_privkey *priv,
                                                    ecdsa_pubkey *pub,
                                                    const u8 *seed32) {
    if (!priv)   return 1;
    if (!pub)    return 2;
    if (!seed32) return 3;

    memcpy(priv->data, seed32, 32);
    if (!privkey_valid(priv->data)) return 4;

    unsigned long rc = ecdsa_pubkey_derive(pub, priv);
    if (rc) return 4;
    return 0;
}

unsigned long ecdsa_pubkey_derive(ecdsa_pubkey *pub,
                                                 const ecdsa_privkey *priv) {
    if (!pub)  return 1;
    if (!priv) return 2;
    if (!privkey_valid(priv->data)) return 3;

    p256_scalar k;
    bytes_to_scalar(&k, priv->data);

    p256_jacobian jac;
    scalar_mult_base(&jac, &k);

    if (jac_is_infinity(&jac)) return 3;

    p256_affine aff;
    jac_to_affine(&aff, &jac);
    encode_pubkey(pub, &aff);

    memset(&k, 0, sizeof(k));
    return 0;
}

unsigned long ecdsa_sign(ecdsa_sig *sig,
                                        const ecdsa_privkey *key,
                                        const u8 *msg, u64 msg_len) {
    if (!sig) return 1;
    if (!key) return 2;
    if (!msg && msg_len > 0) return 3;
    if (!privkey_valid(key->data)) return 4;

    /* Hash the message with SHA-256 */
    u8 hash[32];
    unsigned long rc = sha256_digest(hash, msg, msg_len);
    if (rc) return 5;

    /* Generate deterministic k via RFC 6979 */
    p256_scalar k;
    rc = rfc6979_generate_k(&k, key->data, hash);
    if (rc) return 5;

    /* Compute R = k * G */
    p256_jacobian R_jac;
    scalar_mult_base(&R_jac, &k);
    if (jac_is_infinity(&R_jac)) return 5;

    p256_affine R_aff;
    jac_to_affine(&R_aff, &R_jac);

    /* r = R.x mod n */
    p256_scalar r_scalar;
    r_scalar.v[0] = R_aff.x.v[0];
    r_scalar.v[1] = R_aff.x.v[1];
    r_scalar.v[2] = R_aff.x.v[2];
    r_scalar.v[3] = R_aff.x.v[3];
    scalar_reduce(&r_scalar);

    if (scalar_is_zero(&r_scalar)) return 5;

    /* s = k^(-1) * (hash + r * privkey) mod n */
    p256_scalar z, d, k_inv, s, rd;
    bytes_to_scalar(&z, hash);
    /* Reduce z mod n if needed */
    if (scalar_gte(&z, &P256_N)) scalar_reduce(&z);

    bytes_to_scalar(&d, key->data);
    scalar_mul(&rd, &r_scalar, &d);     /* r * d */
    scalar_add(&s, &z, &rd);            /* z + r*d */
    scalar_inv(&k_inv, &k);             /* k^(-1) */
    scalar_mul(&s, &k_inv, &s);         /* s = k^(-1) * (z + r*d) */

    if (scalar_is_zero(&s)) return 5;

    /* Encode r, s as big-endian 32-byte values */
    scalar_to_bytes(sig->r, &r_scalar);
    scalar_to_bytes(sig->s, &s);

    /* Wipe sensitive data */
    memset(&k, 0, sizeof(k));
    memset(&k_inv, 0, sizeof(k_inv));
    memset(&d, 0, sizeof(d));
    memset(hash, 0, 32);

    return 0;
}

unsigned long ecdsa_verify(u64 *valid,
                                          const ecdsa_pubkey *pub,
                                          const u8 *msg, u64 msg_len,
                                          const ecdsa_sig *sig) {
    if (!valid) return 1;
    *valid = 0;
    if (!pub)  return 2;
    if (!msg && msg_len > 0) return 3;
    if (!sig)  return 4;

    /* Decode public key */
    p256_affine Q;
    if (decode_pubkey(&Q, pub)) return 5;

    /* Decode r and s */
    p256_scalar r_scalar, s_scalar;
    bytes_to_scalar(&r_scalar, sig->r);
    bytes_to_scalar(&s_scalar, sig->s);

    /* Check 1 <= r, s < n */
    if (scalar_is_zero(&r_scalar) || scalar_gte(&r_scalar, &P256_N)) return 0;
    if (scalar_is_zero(&s_scalar) || scalar_gte(&s_scalar, &P256_N)) return 0;

    /* Hash the message */
    u8 hash[32];
    unsigned long rc = sha256_digest(hash, msg, msg_len);
    if (rc) return 0; /* can't hash => invalid, not an error hatch */

    p256_scalar z;
    bytes_to_scalar(&z, hash);
    if (scalar_gte(&z, &P256_N)) scalar_reduce(&z);

    /* w = s^(-1) mod n */
    p256_scalar w;
    scalar_inv(&w, &s_scalar);

    /* u1 = z * w mod n, u2 = r * w mod n */
    p256_scalar u1, u2;
    scalar_mul(&u1, &z, &w);
    scalar_mul(&u2, &r_scalar, &w);

    /* R = u1*G + u2*Q */
    p256_jacobian r1_jac, r2_jac, R_jac;
    p256_affine G;
    G.x = P256_GX;
    G.y = P256_GY;
    scalar_mult(&r1_jac, &u1, &G);
    scalar_mult(&r2_jac, &u2, &Q);
    jac_add(&R_jac, &r1_jac, &r2_jac);

    if (jac_is_infinity(&R_jac)) return 0; /* invalid */

    p256_affine R_aff;
    jac_to_affine(&R_aff, &R_jac);

    /* v = R.x mod n */
    p256_scalar v;
    v.v[0] = R_aff.x.v[0];
    v.v[1] = R_aff.x.v[1];
    v.v[2] = R_aff.x.v[2];
    v.v[3] = R_aff.x.v[3];
    scalar_reduce(&v);

    /* Signature valid if v == r */
    if (v.v[0] == r_scalar.v[0] && v.v[1] == r_scalar.v[1] &&
        v.v[2] == r_scalar.v[2] && v.v[3] == r_scalar.v[3]) {
        *valid = 1;
    }

    return 0;
}

unsigned long ecdh_compute(ecdh_secret *out,
                                          const ecdsa_privkey *priv,
                                          const ecdsa_pubkey *peer_pub) {
    if (!out)      return 1;
    if (!priv)     return 2;
    if (!peer_pub) return 3;
    if (!privkey_valid(priv->data)) return 4;

    /* Decode peer public key */
    p256_affine Q;
    if (decode_pubkey(&Q, peer_pub)) return 5;

    /* Compute S = priv * Q */
    p256_scalar k;
    bytes_to_scalar(&k, priv->data);

    p256_jacobian S_jac;
    scalar_mult(&S_jac, &k, &Q);

    if (jac_is_infinity(&S_jac)) return 6;

    p256_affine S_aff;
    jac_to_affine(&S_aff, &S_jac);

    /* Shared secret = x-coordinate */
    limbs_to_bytes(out->data, &S_aff.x);

    memset(&k, 0, sizeof(k));
    return 0;
}
