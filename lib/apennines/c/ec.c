#include "apennines/ec.h"
#include "apennines/hash.h"
#include "apennines/entropy.h"
#include <string.h>


/* ======================================================================
 * Field arithmetic mod p = 2^255 - 19
 * Representation: 5 limbs of 51 bits each.
 * limb[0] holds bits 0..50, limb[1] holds bits 51..101, etc.
 * ====================================================================== */

typedef struct { u64 v[5]; } fe25519;

#define MASK51 ((u64)0x7ffffffffffffULL)

#ifdef __SIZEOF_INT128__
typedef unsigned __int128 u128_t;
#else
/* Portable u128 multiply using 64-bit halves */
typedef struct { u64 lo; u64 hi; } u128_t;

static u128_t u128_mul64(u64 a, u64 b) {
    u128_t r;
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

static u128_t u128_add(u128_t a, u128_t b) {
    u128_t r;
    r.lo = a.lo + b.lo;
    r.hi = a.hi + b.hi + (r.lo < a.lo ? 1 : 0);
    return r;
}

static u64 u128_lo(u128_t x) { return x.lo; }
static u64 u128_shr(u128_t x, int n) {
    if (n == 0) return x.lo;
    if (n < 64) return (x.lo >> n) | (x.hi << (64 - n));
    return x.hi >> (n - 64);
}
#endif

/* Helpers that work with both native __int128 and our portable struct */
#ifdef __SIZEOF_INT128__
static inline u128_t mul64(u64 a, u64 b) { return (u128_t)a * b; }
static inline u128_t add128(u128_t a, u128_t b) { return a + b; }
static inline u64 lo128(u128_t x) { return (u64)x; }
static inline u64 shr128(u128_t x, int n) { return (u64)(x >> n); }
#else
static inline u128_t mul64(u64 a, u64 b) { return u128_mul64(a, b); }
static inline u128_t add128(u128_t a, u128_t b) { return u128_add(a, b); }
static inline u64 lo128(u128_t x) { return u128_lo(x); }
static inline u64 shr128(u128_t x, int n) { return u128_shr(x, n); }
#endif

static void fe_zero(fe25519 *h) {
    h->v[0] = h->v[1] = h->v[2] = h->v[3] = h->v[4] = 0;
}

static void fe_one(fe25519 *h) {
    h->v[0] = 1; h->v[1] = h->v[2] = h->v[3] = h->v[4] = 0;
}

static void fe_copy(fe25519 *h, const fe25519 *f) {
    *h = *f;
}

static void fe_add(fe25519 *h, const fe25519 *f, const fe25519 *g) {
    h->v[0] = f->v[0] + g->v[0];
    h->v[1] = f->v[1] + g->v[1];
    h->v[2] = f->v[2] + g->v[2];
    h->v[3] = f->v[3] + g->v[3];
    h->v[4] = f->v[4] + g->v[4];
}

/* h = f - g. We add 2*p first to avoid underflow. */
static void fe_sub(fe25519 *h, const fe25519 *f, const fe25519 *g) {
    /* 2*p in 5-limb form: each limb = 2 * 0x7ffffffffffff = 0xffffffffffffe
       except limb 0 = 2*(2^51 - 19) = 0xfffffffffffda. Actually:
       p = 2^255-19. In 5-limb radix-2^51:
       p = (2^51-19, 2^51-1, 2^51-1, 2^51-1, 2^51-1)
       2p = (2^52-38, 2^52-2, 2^52-2, 2^52-2, 2^52-2)
    */
    h->v[0] = (f->v[0] + 0xfffffffffffdaULL) - g->v[0];
    h->v[1] = (f->v[1] + 0xffffffffffffeULL) - g->v[1];
    h->v[2] = (f->v[2] + 0xffffffffffffeULL) - g->v[2];
    h->v[3] = (f->v[3] + 0xffffffffffffeULL) - g->v[3];
    h->v[4] = (f->v[4] + 0xffffffffffffeULL) - g->v[4];
}

static void fe_neg(fe25519 *h, const fe25519 *f) {
    fe25519 zero;
    fe_zero(&zero);
    fe_sub(h, &zero, f);
}

/* Carry-propagate to ensure each limb < 2^52 (approximately). */
static void fe_carry(fe25519 *h) {
    u64 c;
    c = h->v[0] >> 51; h->v[1] += c; h->v[0] &= MASK51;
    c = h->v[1] >> 51; h->v[2] += c; h->v[1] &= MASK51;
    c = h->v[2] >> 51; h->v[3] += c; h->v[2] &= MASK51;
    c = h->v[3] >> 51; h->v[4] += c; h->v[3] &= MASK51;
    c = h->v[4] >> 51; h->v[0] += c * 19; h->v[4] &= MASK51;
}

/* Full reduction to canonical [0, p) */
static void fe_reduce(fe25519 *h) {
    u64 c;
    /* First, carry-propagate */
    fe_carry(h);
    /* Might need a second carry after the *19 feedback */
    fe_carry(h);

    /* Now subtract p if h >= p.
       p = (2^51 - 19, 2^51-1, 2^51-1, 2^51-1, 2^51-1). */
    /* Add 19 and see if limb 4 overflows (>=2^51) */
    u64 t0 = h->v[0] + 19;
    c = t0 >> 51; t0 &= MASK51;
    u64 t1 = h->v[1] + c; c = t1 >> 51; t1 &= MASK51;
    u64 t2 = h->v[2] + c; c = t2 >> 51; t2 &= MASK51;
    u64 t3 = h->v[3] + c; c = t3 >> 51; t3 &= MASK51;
    u64 t4 = h->v[4] + c; c = t4 >> 51; t4 &= MASK51;
    /* If c == 1, then h >= p, so use reduced (t) values. If c == 0, keep h. */
    u64 mask = (u64)(-(i64)c); /* all-ones if c==1, all-zeros if c==0 */
    h->v[0] = (h->v[0] & ~mask) | (t0 & mask);
    h->v[1] = (h->v[1] & ~mask) | (t1 & mask);
    h->v[2] = (h->v[2] & ~mask) | (t2 & mask);
    h->v[3] = (h->v[3] & ~mask) | (t3 & mask);
    h->v[4] = (h->v[4] & ~mask) | (t4 & mask);
}

static void fe_tobytes(u8 *s, const fe25519 *h) {
    fe25519 t;
    fe_copy(&t, h);
    fe_reduce(&t);

    /* Pack 5 * 51-bit limbs into 32 bytes little-endian */
    u64 v0 = t.v[0], v1 = t.v[1], v2 = t.v[2], v3 = t.v[3], v4 = t.v[4];
    int i;
    u64 w0 = v0 | (v1 << 51);
    u64 w1 = (v1 >> 13) | (v2 << 38);
    u64 w2 = (v2 >> 26) | (v3 << 25);
    u64 w3 = (v3 >> 39) | (v4 << 12);

    for (i = 0; i < 8; i++) s[i]    = (u8)(w0 >> (8 * i));
    for (i = 0; i < 8; i++) s[8+i]  = (u8)(w1 >> (8 * i));
    for (i = 0; i < 8; i++) s[16+i] = (u8)(w2 >> (8 * i));
    for (i = 0; i < 8; i++) s[24+i] = (u8)(w3 >> (8 * i));
}

static void fe_frombytes(fe25519 *h, const u8 *s) {
    u64 w0 = 0, w1 = 0, w2 = 0, w3 = 0;
    int i;
    for (i = 0; i < 8; i++) w0 |= (u64)s[i]    << (8 * i);
    for (i = 0; i < 8; i++) w1 |= (u64)s[8+i]  << (8 * i);
    for (i = 0; i < 8; i++) w2 |= (u64)s[16+i] << (8 * i);
    for (i = 0; i < 8; i++) w3 |= (u64)s[24+i] << (8 * i);

    h->v[0] = w0 & MASK51;
    h->v[1] = ((w0 >> 51) | (w1 << 13)) & MASK51;
    h->v[2] = ((w1 >> 38) | (w2 << 26)) & MASK51;
    h->v[3] = ((w2 >> 25) | (w3 << 39)) & MASK51;
    h->v[4] = (w3 >> 12) & MASK51;
}

static void fe_mul(fe25519 *h, const fe25519 *f, const fe25519 *g) {
    u64 f0 = f->v[0], f1 = f->v[1], f2 = f->v[2], f3 = f->v[3], f4 = f->v[4];
    u64 g0 = g->v[0], g1 = g->v[1], g2 = g->v[2], g3 = g->v[3], g4 = g->v[4];
    u64 g1_19 = g1 * 19, g2_19 = g2 * 19, g3_19 = g3 * 19, g4_19 = g4 * 19;

    u128_t t0 = add128(add128(add128(add128(
                    mul64(f0, g0), mul64(f1, g4_19)), mul64(f2, g3_19)),
                    mul64(f3, g2_19)), mul64(f4, g1_19));
    u128_t t1 = add128(add128(add128(add128(
                    mul64(f0, g1), mul64(f1, g0)), mul64(f2, g4_19)),
                    mul64(f3, g3_19)), mul64(f4, g2_19));
    u128_t t2 = add128(add128(add128(add128(
                    mul64(f0, g2), mul64(f1, g1)), mul64(f2, g0)),
                    mul64(f3, g4_19)), mul64(f4, g3_19));
    u128_t t3 = add128(add128(add128(add128(
                    mul64(f0, g3), mul64(f1, g2)), mul64(f2, g1)),
                    mul64(f3, g0)), mul64(f4, g4_19));
    u128_t t4 = add128(add128(add128(add128(
                    mul64(f0, g4), mul64(f1, g3)), mul64(f2, g2)),
                    mul64(f3, g1)), mul64(f4, g0));

    u64 c;
    u64 r0 = lo128(t0) & MASK51; c = shr128(t0, 51);
    t1 = add128(t1, mul64(c, 1)); /* just add carry */
    u64 r1 = lo128(t1) & MASK51; c = shr128(t1, 51);
    t2 = add128(t2, mul64(c, 1));
    u64 r2 = lo128(t2) & MASK51; c = shr128(t2, 51);
    t3 = add128(t3, mul64(c, 1));
    u64 r3 = lo128(t3) & MASK51; c = shr128(t3, 51);
    t4 = add128(t4, mul64(c, 1));
    u64 r4 = lo128(t4) & MASK51; c = shr128(t4, 51);
    r0 += c * 19;
    c = r0 >> 51; r0 &= MASK51;
    r1 += c;

    h->v[0] = r0; h->v[1] = r1; h->v[2] = r2; h->v[3] = r3; h->v[4] = r4;
}

static void fe_sq(fe25519 *h, const fe25519 *f) {
    u64 f0 = f->v[0], f1 = f->v[1], f2 = f->v[2], f3 = f->v[3], f4 = f->v[4];
    u64 f0_2 = f0 * 2, f1_2 = f1 * 2, f2_2 = f2 * 2, f3_2 = f3 * 2;
    u64 f4_19 = f4 * 19;

    /* t0 = f0^2 + 2*19*f1*f4 + 2*19*f2*f3 */
    /* t1 = 2*f0*f1 + 2*19*f2*f4 + 19*f3^2 */
    /* t2 = 2*f0*f2 + f1^2 + 2*19*f3*f4 */
    /* t3 = 2*f0*f3 + 2*f1*f2 + 19*f4^2 */
    /* t4 = 2*f0*f4 + 2*f1*f3 + f2^2 */
    u128_t t0 = add128(add128(mul64(f0, f0), mul64(f1_2, f4_19)), mul64(f2_2, f3 * 19));
    u128_t t1 = add128(add128(mul64(f0_2, f1), mul64(f2_2, f4_19)), mul64(f3, f3 * 19));
    u128_t t2 = add128(add128(mul64(f0_2, f2), mul64(f1, f1)), mul64(f3_2, f4_19));
    u128_t t3 = add128(add128(mul64(f0_2, f3), mul64(f1_2, f2)), mul64(f4, f4_19));
    u128_t t4 = add128(add128(mul64(f0_2, f4), mul64(f1_2, f3)), mul64(f2, f2));

    u64 c;
    u64 r0 = lo128(t0) & MASK51; c = shr128(t0, 51);
    t1 = add128(t1, mul64(c, 1));
    u64 r1 = lo128(t1) & MASK51; c = shr128(t1, 51);
    t2 = add128(t2, mul64(c, 1));
    u64 r2 = lo128(t2) & MASK51; c = shr128(t2, 51);
    t3 = add128(t3, mul64(c, 1));
    u64 r3 = lo128(t3) & MASK51; c = shr128(t3, 51);
    t4 = add128(t4, mul64(c, 1));
    u64 r4 = lo128(t4) & MASK51; c = shr128(t4, 51);
    r0 += c * 19;
    c = r0 >> 51; r0 &= MASK51;
    r1 += c;

    h->v[0] = r0; h->v[1] = r1; h->v[2] = r2; h->v[3] = r3; h->v[4] = r4;
}

/* Multiply by small constant */
static void fe_mul_small(fe25519 *h, const fe25519 *f, u64 s) {
    u128_t t0 = mul64(f->v[0], s);
    u128_t t1 = mul64(f->v[1], s);
    u128_t t2 = mul64(f->v[2], s);
    u128_t t3 = mul64(f->v[3], s);
    u128_t t4 = mul64(f->v[4], s);

    u64 c;
    u64 r0 = lo128(t0) & MASK51; c = shr128(t0, 51);
    t1 = add128(t1, mul64(c, 1));
    u64 r1 = lo128(t1) & MASK51; c = shr128(t1, 51);
    t2 = add128(t2, mul64(c, 1));
    u64 r2 = lo128(t2) & MASK51; c = shr128(t2, 51);
    t3 = add128(t3, mul64(c, 1));
    u64 r3 = lo128(t3) & MASK51; c = shr128(t3, 51);
    t4 = add128(t4, mul64(c, 1));
    u64 r4 = lo128(t4) & MASK51; c = shr128(t4, 51);
    r0 += c * 19;
    c = r0 >> 51; r0 &= MASK51;
    r1 += c;

    h->v[0] = r0; h->v[1] = r1; h->v[2] = r2; h->v[3] = r3; h->v[4] = r4;
}

/* Constant-time conditional move: if b==1, set f = g */
static void fe_cmov(fe25519 *f, const fe25519 *g, u64 b) {
    u64 mask = (u64)(-(i64)b);
    f->v[0] ^= mask & (f->v[0] ^ g->v[0]);
    f->v[1] ^= mask & (f->v[1] ^ g->v[1]);
    f->v[2] ^= mask & (f->v[2] ^ g->v[2]);
    f->v[3] ^= mask & (f->v[3] ^ g->v[3]);
    f->v[4] ^= mask & (f->v[4] ^ g->v[4]);
}

/* Constant-time conditional swap: if b==1, swap f and g */
static void fe_cswap(fe25519 *f, fe25519 *g, u64 b) {
    u64 mask = (u64)(-(i64)b);
    u64 x;
    int i;
    for (i = 0; i < 5; i++) {
        x = mask & (f->v[i] ^ g->v[i]);
        f->v[i] ^= x;
        g->v[i] ^= x;
    }
}

static int fe_isnegative(const fe25519 *f) {
    u8 s[32];
    fe_tobytes(s, f);
    return s[0] & 1;
}

static int fe_isnonzero(const fe25519 *f) {
    u8 s[32];
    fe_tobytes(s, f);
    u8 r = 0;
    int i;
    for (i = 0; i < 32; i++) r |= s[i];
    return r != 0;
}

/* z^(p-2) = z^(2^255 - 21) using the standard addition chain from ref10 */
static void fe_invert(fe25519 *out, const fe25519 *z) {
    fe25519 t0, t1, t2, t3;
    int i;

    fe_sq(&t0, z);           /* 2 */
    fe_sq(&t1, &t0);
    fe_sq(&t1, &t1);        /* 8 */
    fe_mul(&t1, z, &t1);    /* 9 */
    fe_mul(&t0, &t0, &t1);  /* 11 */
    fe_sq(&t2, &t0);        /* 22 */
    fe_mul(&t1, &t1, &t2);  /* 2^5 - 2^0 = 31 */

    fe_sq(&t2, &t1);
    for (i = 1; i < 5; i++) fe_sq(&t2, &t2);
    fe_mul(&t1, &t2, &t1);  /* 2^10 - 1 */

    fe_sq(&t2, &t1);
    for (i = 1; i < 10; i++) fe_sq(&t2, &t2);
    fe_mul(&t2, &t2, &t1);  /* 2^20 - 1 */

    fe_sq(&t3, &t2);
    for (i = 1; i < 20; i++) fe_sq(&t3, &t3);
    fe_mul(&t2, &t3, &t2);  /* 2^40 - 1 */

    fe_sq(&t2, &t2);
    for (i = 1; i < 10; i++) fe_sq(&t2, &t2);
    fe_mul(&t1, &t2, &t1);  /* 2^50 - 1 */

    fe_sq(&t2, &t1);
    for (i = 1; i < 50; i++) fe_sq(&t2, &t2);
    fe_mul(&t2, &t2, &t1);  /* 2^100 - 1 */

    fe_sq(&t3, &t2);
    for (i = 1; i < 100; i++) fe_sq(&t3, &t3);
    fe_mul(&t2, &t3, &t2);  /* 2^200 - 1 */

    fe_sq(&t2, &t2);
    for (i = 1; i < 50; i++) fe_sq(&t2, &t2);
    fe_mul(&t1, &t2, &t1);  /* 2^250 - 1 */

    fe_sq(&t1, &t1);
    fe_sq(&t1, &t1);
    fe_sq(&t1, &t1);
    fe_sq(&t1, &t1);
    fe_sq(&t1, &t1);         /* 2^255 - 32 */
    fe_mul(out, &t1, &t0);   /* 2^255 - 21 */
}

/* z^((p-5)/8) = z^(2^252 - 3) for Ed25519 square root */
static void fe_pow22523(fe25519 *out, const fe25519 *z) {
    fe25519 t0, t1, t2, t3;
    int i;

    fe_sq(&t0, z);
    fe_sq(&t1, &t0);
    fe_sq(&t1, &t1);
    fe_mul(&t1, z, &t1);
    fe_mul(&t0, &t0, &t1);
    fe_sq(&t0, &t0);
    fe_mul(&t0, &t1, &t0);

    fe_sq(&t1, &t0);
    for (i = 1; i < 5; i++) fe_sq(&t1, &t1);
    fe_mul(&t0, &t1, &t0);

    fe_sq(&t1, &t0);
    for (i = 1; i < 10; i++) fe_sq(&t1, &t1);
    fe_mul(&t1, &t1, &t0);

    fe_sq(&t2, &t1);
    for (i = 1; i < 20; i++) fe_sq(&t2, &t2);
    fe_mul(&t1, &t2, &t1);

    fe_sq(&t1, &t1);
    for (i = 1; i < 10; i++) fe_sq(&t1, &t1);
    fe_mul(&t0, &t1, &t0);

    fe_sq(&t1, &t0);
    for (i = 1; i < 50; i++) fe_sq(&t1, &t1);
    fe_mul(&t1, &t1, &t0);

    fe_sq(&t2, &t1);
    for (i = 1; i < 100; i++) fe_sq(&t2, &t2);
    fe_mul(&t1, &t2, &t1);

    fe_sq(&t1, &t1);
    for (i = 1; i < 50; i++) fe_sq(&t1, &t1);
    fe_mul(&t0, &t1, &t0);

    fe_sq(&t0, &t0);
    fe_sq(&t0, &t0);
    fe_mul(out, &t0, z);
}

/* ======================================================================
 * Ed25519 group operations
 * Extended twisted Edwards coordinates: -x^2 + y^2 = 1 + d*x^2*y^2
 * d = -121665/121666 mod p
 * Point representation: (X : Y : Z : T) where x = X/Z, y = Y/Z, T = X*Y/Z
 * ====================================================================== */

typedef struct {
    fe25519 X;
    fe25519 Y;
    fe25519 Z;
    fe25519 T;
} ge25519;

/* d = -121665/121666 mod p (precomputed) */
static const fe25519 ED25519_D = {{
    929955233495203ULL,
    466365720129213ULL,
    1662059464998953ULL,
    2033849074728123ULL,
    1442794654840575ULL
}};

/* 2*d */
static const fe25519 ED25519_2D = {{
    1859910466990425ULL,
    932731440258426ULL,
    1072319116312658ULL,
    1815898335770999ULL,
    633789495995903ULL
}};

/* sqrt(-1) mod p */
static const fe25519 SQRT_M1 = {{
    1718705420411056ULL,
    234908883556509ULL,
    2233514472574048ULL,
    2117202627021982ULL,
    765476049583133ULL
}};

/* Base point B (encoded) */
static const u8 ED25519_BASEPOINT[32] = {
    0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
    0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
    0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
    0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66
};

static void ge_zero(ge25519 *h) {
    fe_zero(&h->X);
    fe_one(&h->Y);
    fe_one(&h->Z);
    fe_zero(&h->T);
}

/* Encode point to 32 bytes (compress: y with sign of x in top bit) */
static void ge_tobytes(u8 *s, const ge25519 *h) {
    fe25519 recip, x, y;
    fe_invert(&recip, &h->Z);
    fe_mul(&x, &h->X, &recip);
    fe_mul(&y, &h->Y, &recip);
    fe_tobytes(s, &y);
    s[31] ^= (u8)(fe_isnegative(&x) << 7);
}

/* Decode point from 32 bytes */
static int ge_frombytes(ge25519 *h, const u8 *s) {
    fe25519 u_fe, v, v3, vxx, check;

    int x_sign = (s[31] >> 7) & 1;
    u8 s2[32];
    memcpy(s2, s, 32);
    s2[31] &= 0x7f;

    fe_frombytes(&h->Y, s2);
    fe_one(&h->Z);

    /* u = y^2 - 1, v = d*y^2 + 1 */
    fe_sq(&u_fe, &h->Y);
    fe_mul(&v, &u_fe, &ED25519_D);
    fe_sub(&u_fe, &u_fe, &h->Z); /* u = y^2 - 1 */
    fe_add(&v, &v, &h->Z);       /* v = d*y^2 + 1 */

    /* x = u * v^3 * (u * v^7)^((p-5)/8) */
    fe_sq(&v3, &v);
    fe_mul(&v3, &v3, &v);       /* v^3 */
    fe_sq(&h->X, &v3);
    fe_mul(&h->X, &h->X, &v);  /* v^7 */
    fe_mul(&h->X, &h->X, &u_fe); /* u * v^7 */
    fe_pow22523(&h->X, &h->X);   /* (u * v^7)^((p-5)/8) */
    fe_mul(&h->X, &h->X, &v3);   /* v^3 * ... */
    fe_mul(&h->X, &h->X, &u_fe); /* u * v^3 * ... */

    /* Check: v * x^2 == u ? */
    fe_sq(&vxx, &h->X);
    fe_mul(&vxx, &vxx, &v);
    fe_sub(&check, &vxx, &u_fe);
    if (fe_isnonzero(&check)) {
        fe_add(&check, &vxx, &u_fe);
        if (fe_isnonzero(&check))
            return -1; /* not on curve */
        fe_mul(&h->X, &h->X, &SQRT_M1);
    }

    if (fe_isnegative(&h->X) != x_sign) {
        fe_neg(&h->X, &h->X);
    }

    fe_mul(&h->T, &h->X, &h->Y);
    return 0;
}

/* Unified addition (extended coordinates) */
static void ge_add(ge25519 *r, const ge25519 *p, const ge25519 *q) {
    fe25519 A, B, C, D, E, F, G, H;

    fe_sub(&A, &p->Y, &p->X);
    fe_sub(&B, &q->Y, &q->X);
    fe_mul(&A, &A, &B);       /* A = (Y1-X1)*(Y2-X2) */

    fe_add(&B, &p->Y, &p->X);
    fe_add(&C, &q->Y, &q->X);
    fe_mul(&B, &B, &C);       /* B = (Y1+X1)*(Y2+X2) */

    fe_mul(&C, &p->T, &q->T);
    fe_mul(&C, &C, &ED25519_2D); /* C = T1*T2*2*d */

    fe_mul(&D, &p->Z, &q->Z);
    fe_add(&D, &D, &D);       /* D = 2*Z1*Z2 */

    fe_sub(&E, &B, &A);       /* E = B - A */
    fe_sub(&F, &D, &C);       /* F = D - C */
    fe_add(&G, &D, &C);       /* G = D + C */
    fe_add(&H, &B, &A);       /* H = B + A */

    fe_mul(&r->X, &E, &F);
    fe_mul(&r->Y, &H, &G);
    fe_mul(&r->Z, &G, &F);
    fe_mul(&r->T, &E, &H);
}

/* Point doubling (extended coordinates) */
static void ge_double(ge25519 *r, const ge25519 *p) {
    fe25519 A, B, C, D, E, F, G, H;

    fe_sq(&A, &p->X);         /* A = X1^2 */
    fe_sq(&B, &p->Y);         /* B = Y1^2 */
    fe_sq(&C, &p->Z);
    fe_add(&C, &C, &C);       /* C = 2*Z1^2 */
    fe_neg(&D, &A);           /* D = -A (since a=-1 in twisted Edwards) */

    fe_add(&E, &p->X, &p->Y);
    fe_sq(&E, &E);
    fe_sub(&E, &E, &A);
    fe_sub(&E, &E, &B);       /* E = (X1+Y1)^2 - A - B */

    fe_add(&G, &D, &B);       /* G = D + B */
    fe_sub(&F, &G, &C);       /* F = G - C */
    fe_sub(&H, &D, &B);       /* H = D - B */

    fe_mul(&r->X, &E, &F);
    fe_mul(&r->Y, &G, &H);
    fe_mul(&r->Z, &F, &G);
    fe_mul(&r->T, &E, &H);
}

/* Scalar multiplication: double-and-add, constant-time */
static void ge_scalarmult(ge25519 *r, const u8 *scalar, const ge25519 *p) {
    ge25519 Q, T;
    int i, bit;

    ge_zero(&Q);

    for (i = 254; i >= 0; i--) {
        ge_double(&Q, &Q);
        bit = (scalar[i >> 3] >> (i & 7)) & 1;
        ge_add(&T, &Q, p);
        /* Constant-time select: Q = bit ? T : Q */
        fe_cmov(&Q.X, &T.X, (u64)bit);
        fe_cmov(&Q.Y, &T.Y, (u64)bit);
        fe_cmov(&Q.Z, &T.Z, (u64)bit);
        fe_cmov(&Q.T, &T.T, (u64)bit);
    }

    *r = Q;
}

static void ge_scalarmult_base(ge25519 *r, const u8 *scalar) {
    ge25519 B;
    ge_frombytes(&B, ED25519_BASEPOINT);
    ge_scalarmult(r, scalar, &B);
}

/* ======================================================================
 * Scalar arithmetic mod l
 * l = 2^252 + 27742317777372353535851937790883648493
 * ====================================================================== */

/* l in little-endian bytes */
static const u8 EC_L[32] = {
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
    0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10
};

/* Reduce a 64-byte scalar (from SHA-512 output) mod l to 32 bytes.
 * Uses the standard ref10 two-pass approach. */
static void sc_reduce(u8 out[32], const u8 in[64]) {
    i64 s0, s1, s2, s3, s4, s5, s6, s7, s8, s9, s10, s11;
    i64 s12, s13, s14, s15, s16, s17, s18, s19, s20, s21, s22, s23;
    i64 carry;

    s0  = (i64)(2097151 & (((u64)in[ 0])       | ((u64)in[ 1] <<  8) | ((u64)in[ 2] << 16)));
    s1  = (i64)(2097151 & (((u64)in[ 2] >>  5) | ((u64)in[ 3] <<  3) | ((u64)in[ 4] << 11) | ((u64)in[ 5] << 19)));
    s2  = (i64)(2097151 & (((u64)in[ 5] >>  2) | ((u64)in[ 6] <<  6) | ((u64)in[ 7] << 14)));
    s3  = (i64)(2097151 & (((u64)in[ 7] >>  7) | ((u64)in[ 8] <<  1) | ((u64)in[ 9] <<  9) | ((u64)in[10] << 17)));
    s4  = (i64)(2097151 & (((u64)in[10] >>  4) | ((u64)in[11] <<  4) | ((u64)in[12] << 12) | ((u64)in[13] << 20)));
    s5  = (i64)(2097151 & (((u64)in[13] >>  1) | ((u64)in[14] <<  7) | ((u64)in[15] << 15)));
    s6  = (i64)(2097151 & (((u64)in[15] >>  6) | ((u64)in[16] <<  2) | ((u64)in[17] << 10) | ((u64)in[18] << 18)));
    s7  = (i64)(2097151 & (((u64)in[18] >>  3) | ((u64)in[19] <<  5) | ((u64)in[20] << 13)));
    s8  = (i64)(2097151 & (((u64)in[21])       | ((u64)in[22] <<  8) | ((u64)in[23] << 16)));
    s9  = (i64)(2097151 & (((u64)in[23] >>  5) | ((u64)in[24] <<  3) | ((u64)in[25] << 11) | ((u64)in[26] << 19)));
    s10 = (i64)(2097151 & (((u64)in[26] >>  2) | ((u64)in[27] <<  6) | ((u64)in[28] << 14)));
    s11 = (i64)(2097151 & (((u64)in[28] >>  7) | ((u64)in[29] <<  1) | ((u64)in[30] <<  9) | ((u64)in[31] << 17)));
    s12 = (i64)(2097151 & (((u64)in[31] >>  4) | ((u64)in[32] <<  4) | ((u64)in[33] << 12) | ((u64)in[34] << 20)));
    s13 = (i64)(2097151 & (((u64)in[34] >>  1) | ((u64)in[35] <<  7) | ((u64)in[36] << 15)));
    s14 = (i64)(2097151 & (((u64)in[36] >>  6) | ((u64)in[37] <<  2) | ((u64)in[38] << 10) | ((u64)in[39] << 18)));
    s15 = (i64)(2097151 & (((u64)in[39] >>  3) | ((u64)in[40] <<  5) | ((u64)in[41] << 13)));
    s16 = (i64)(2097151 & (((u64)in[42])       | ((u64)in[43] <<  8) | ((u64)in[44] << 16)));
    s17 = (i64)(2097151 & (((u64)in[44] >>  5) | ((u64)in[45] <<  3) | ((u64)in[46] << 11) | ((u64)in[47] << 19)));
    s18 = (i64)(2097151 & (((u64)in[47] >>  2) | ((u64)in[48] <<  6) | ((u64)in[49] << 14)));
    s19 = (i64)(2097151 & (((u64)in[49] >>  7) | ((u64)in[50] <<  1) | ((u64)in[51] <<  9) | ((u64)in[52] << 17)));
    s20 = (i64)(2097151 & (((u64)in[52] >>  4) | ((u64)in[53] <<  4) | ((u64)in[54] << 12) | ((u64)in[55] << 20)));
    s21 = (i64)(2097151 & (((u64)in[55] >>  1) | ((u64)in[56] <<  7) | ((u64)in[57] << 15)));
    s22 = (i64)(2097151 & (((u64)in[57] >>  6) | ((u64)in[58] <<  2) | ((u64)in[59] << 10) | ((u64)in[60] << 18)));
    s23 = (i64)(((u64)in[60] >>  3) | ((u64)in[61] <<  5) | ((u64)in[62] << 13) | ((u64)in[63] << 21));

    /* Round 1: reduce s[23]..s[18] into s[6]..s[17] */
    s11 += s23 *  666643; s12 += s23 *  470296; s13 += s23 *  654183;
    s14 -= s23 *  997805; s15 += s23 *  136657; s16 -= s23 *  683901; s23 = 0;

    s10 += s22 *  666643; s11 += s22 *  470296; s12 += s22 *  654183;
    s13 -= s22 *  997805; s14 += s22 *  136657; s15 -= s22 *  683901; s22 = 0;

    s9  += s21 *  666643; s10 += s21 *  470296; s11 += s21 *  654183;
    s12 -= s21 *  997805; s13 += s21 *  136657; s14 -= s21 *  683901; s21 = 0;

    s8  += s20 *  666643; s9  += s20 *  470296; s10 += s20 *  654183;
    s11 -= s20 *  997805; s12 += s20 *  136657; s13 -= s20 *  683901; s20 = 0;

    s7  += s19 *  666643; s8  += s19 *  470296; s9  += s19 *  654183;
    s10 -= s19 *  997805; s11 += s19 *  136657; s12 -= s19 *  683901; s19 = 0;

    s6  += s18 *  666643; s7  += s18 *  470296; s8  += s18 *  654183;
    s9  -= s18 *  997805; s10 += s18 *  136657; s11 -= s18 *  683901; s18 = 0;

    /* Carry propagation (first round) */
    carry = (s6  + (1 << 20)) >> 21; s7  += carry; s6  -= carry * (1 << 21);
    carry = (s8  + (1 << 20)) >> 21; s9  += carry; s8  -= carry * (1 << 21);
    carry = (s10 + (1 << 20)) >> 21; s11 += carry; s10 -= carry * (1 << 21);
    carry = (s12 + (1 << 20)) >> 21; s13 += carry; s12 -= carry * (1 << 21);
    carry = (s14 + (1 << 20)) >> 21; s15 += carry; s14 -= carry * (1 << 21);
    carry = (s16 + (1 << 20)) >> 21; s17 += carry; s16 -= carry * (1 << 21);

    carry = (s7  + (1 << 20)) >> 21; s8  += carry; s7  -= carry * (1 << 21);
    carry = (s9  + (1 << 20)) >> 21; s10 += carry; s9  -= carry * (1 << 21);
    carry = (s11 + (1 << 20)) >> 21; s12 += carry; s11 -= carry * (1 << 21);
    carry = (s13 + (1 << 20)) >> 21; s14 += carry; s13 -= carry * (1 << 21);
    carry = (s15 + (1 << 20)) >> 21; s16 += carry; s15 -= carry * (1 << 21);

    /* Round 2: reduce s[17]..s[12] into s[0]..s[11] */
    s5  += s17 *  666643; s6  += s17 *  470296; s7  += s17 *  654183;
    s8  -= s17 *  997805; s9  += s17 *  136657; s10 -= s17 *  683901; s17 = 0;

    s4  += s16 *  666643; s5  += s16 *  470296; s6  += s16 *  654183;
    s7  -= s16 *  997805; s8  += s16 *  136657; s9  -= s16 *  683901; s16 = 0;

    s3  += s15 *  666643; s4  += s15 *  470296; s5  += s15 *  654183;
    s6  -= s15 *  997805; s7  += s15 *  136657; s8  -= s15 *  683901; s15 = 0;

    s2  += s14 *  666643; s3  += s14 *  470296; s4  += s14 *  654183;
    s5  -= s14 *  997805; s6  += s14 *  136657; s7  -= s14 *  683901; s14 = 0;

    s1  += s13 *  666643; s2  += s13 *  470296; s3  += s13 *  654183;
    s4  -= s13 *  997805; s5  += s13 *  136657; s6  -= s13 *  683901; s13 = 0;

    s0  += s12 *  666643; s1  += s12 *  470296; s2  += s12 *  654183;
    s3  -= s12 *  997805; s4  += s12 *  136657; s5  -= s12 *  683901; s12 = 0;

    /* Round A: biased carry (even/odd) on s0..s11 → produces s12 */
    carry = (s0  + (1 << 20)) >> 21; s1  += carry; s0  -= carry * (1 << 21);
    carry = (s2  + (1 << 20)) >> 21; s3  += carry; s2  -= carry * (1 << 21);
    carry = (s4  + (1 << 20)) >> 21; s5  += carry; s4  -= carry * (1 << 21);
    carry = (s6  + (1 << 20)) >> 21; s7  += carry; s6  -= carry * (1 << 21);
    carry = (s8  + (1 << 20)) >> 21; s9  += carry; s8  -= carry * (1 << 21);
    carry = (s10 + (1 << 20)) >> 21; s11 += carry; s10 -= carry * (1 << 21);

    carry = (s1  + (1 << 20)) >> 21; s2  += carry; s1  -= carry * (1 << 21);
    carry = (s3  + (1 << 20)) >> 21; s4  += carry; s3  -= carry * (1 << 21);
    carry = (s5  + (1 << 20)) >> 21; s6  += carry; s5  -= carry * (1 << 21);
    carry = (s7  + (1 << 20)) >> 21; s8  += carry; s7  -= carry * (1 << 21);
    carry = (s9  + (1 << 20)) >> 21; s10 += carry; s9  -= carry * (1 << 21);
    carry = (s11 + (1 << 20)) >> 21; s12 += carry; s11 -= carry * (1 << 21);

    /* First s12 reduction */
    s0  += s12 *  666643; s1  += s12 *  470296; s2  += s12 *  654183;
    s3  -= s12 *  997805; s4  += s12 *  136657; s5  -= s12 *  683901; s12 = 0;

    /* Round B: sequential carry with mask, s0..s11 → s12 */
    carry = s0  >> 21; s1  += carry; s0  &= 0x1fffff;
    carry = s1  >> 21; s2  += carry; s1  &= 0x1fffff;
    carry = s2  >> 21; s3  += carry; s2  &= 0x1fffff;
    carry = s3  >> 21; s4  += carry; s3  &= 0x1fffff;
    carry = s4  >> 21; s5  += carry; s4  &= 0x1fffff;
    carry = s5  >> 21; s6  += carry; s5  &= 0x1fffff;
    carry = s6  >> 21; s7  += carry; s6  &= 0x1fffff;
    carry = s7  >> 21; s8  += carry; s7  &= 0x1fffff;
    carry = s8  >> 21; s9  += carry; s8  &= 0x1fffff;
    carry = s9  >> 21; s10 += carry; s9  &= 0x1fffff;
    carry = s10 >> 21; s11 += carry; s10 &= 0x1fffff;
    carry = s11 >> 21; s12 += carry; s11 &= 0x1fffff;

    /* Second s12 reduction */
    s0  += s12 *  666643; s1  += s12 *  470296; s2  += s12 *  654183;
    s3  -= s12 *  997805; s4  += s12 *  136657; s5  -= s12 *  683901; s12 = 0;

    /* Round C: final sequential carry with mask, s0..s10 only */
    carry = s0  >> 21; s1  += carry; s0  &= 0x1fffff;
    carry = s1  >> 21; s2  += carry; s1  &= 0x1fffff;
    carry = s2  >> 21; s3  += carry; s2  &= 0x1fffff;
    carry = s3  >> 21; s4  += carry; s3  &= 0x1fffff;
    carry = s4  >> 21; s5  += carry; s4  &= 0x1fffff;
    carry = s5  >> 21; s6  += carry; s5  &= 0x1fffff;
    carry = s6  >> 21; s7  += carry; s6  &= 0x1fffff;
    carry = s7  >> 21; s8  += carry; s7  &= 0x1fffff;
    carry = s8  >> 21; s9  += carry; s8  &= 0x1fffff;
    carry = s9  >> 21; s10 += carry; s9  &= 0x1fffff;
    carry = s10 >> 21; s11 += carry; s10 &= 0x1fffff;

    /* Pack into 32 bytes */
    out[ 0] = (u8)(s0  >>  0);
    out[ 1] = (u8)(s0  >>  8);
    out[ 2] = (u8)((s0  >> 16) | (s1  <<  5));
    out[ 3] = (u8)(s1  >>  3);
    out[ 4] = (u8)(s1  >> 11);
    out[ 5] = (u8)((s1  >> 19) | (s2  <<  2));
    out[ 6] = (u8)(s2  >>  6);
    out[ 7] = (u8)((s2  >> 14) | (s3  <<  7));
    out[ 8] = (u8)(s3  >>  1);
    out[ 9] = (u8)(s3  >>  9);
    out[10] = (u8)((s3  >> 17) | (s4  <<  4));
    out[11] = (u8)(s4  >>  4);
    out[12] = (u8)(s4  >> 12);
    out[13] = (u8)((s4  >> 20) | (s5  <<  1));
    out[14] = (u8)(s5  >>  7);
    out[15] = (u8)((s5  >> 15) | (s6  <<  6));
    out[16] = (u8)(s6  >>  2);
    out[17] = (u8)(s6  >> 10);
    out[18] = (u8)((s6  >> 18) | (s7  <<  3));
    out[19] = (u8)(s7  >>  5);
    out[20] = (u8)(s7  >> 13);
    out[21] = (u8)(s8  >>  0);
    out[22] = (u8)(s8  >>  8);
    out[23] = (u8)((s8  >> 16) | (s9  <<  5));
    out[24] = (u8)(s9  >>  3);
    out[25] = (u8)(s9  >> 11);
    out[26] = (u8)((s9  >> 19) | (s10 <<  2));
    out[27] = (u8)(s10 >>  6);
    out[28] = (u8)((s10 >> 14) | (s11 <<  7));
    out[29] = (u8)(s11 >>  1);
    out[30] = (u8)(s11 >>  9);
    out[31] = (u8)(s11 >> 17);
}

/* Compute out = a*b + c mod l, where a, b, c are 32-byte scalars.
 * Uses the standard two-pass reduction approach. */
static void sc_muladd(u8 out[32], const u8 *a, const u8 *b, const u8 *c) {
    i64 a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11;
    i64 b0, b1, b2, b3, b4, b5, b6, b7, b8, b9, b10, b11;
    i64 c0, c1, c2, c3, c4, c5, c6, c7, c8, c9, c10, c11;
    i64 s0, s1, s2, s3, s4, s5, s6, s7, s8, s9, s10, s11;
    i64 s12, s13, s14, s15, s16, s17, s18, s19, s20, s21, s22, s23;
    i64 carry;

    a0  = (i64)(2097151 & (((u64)a[ 0])       | ((u64)a[ 1] <<  8) | ((u64)a[ 2] << 16)));
    a1  = (i64)(2097151 & (((u64)a[ 2] >>  5) | ((u64)a[ 3] <<  3) | ((u64)a[ 4] << 11) | ((u64)a[ 5] << 19)));
    a2  = (i64)(2097151 & (((u64)a[ 5] >>  2) | ((u64)a[ 6] <<  6) | ((u64)a[ 7] << 14)));
    a3  = (i64)(2097151 & (((u64)a[ 7] >>  7) | ((u64)a[ 8] <<  1) | ((u64)a[ 9] <<  9) | ((u64)a[10] << 17)));
    a4  = (i64)(2097151 & (((u64)a[10] >>  4) | ((u64)a[11] <<  4) | ((u64)a[12] << 12) | ((u64)a[13] << 20)));
    a5  = (i64)(2097151 & (((u64)a[13] >>  1) | ((u64)a[14] <<  7) | ((u64)a[15] << 15)));
    a6  = (i64)(2097151 & (((u64)a[15] >>  6) | ((u64)a[16] <<  2) | ((u64)a[17] << 10) | ((u64)a[18] << 18)));
    a7  = (i64)(2097151 & (((u64)a[18] >>  3) | ((u64)a[19] <<  5) | ((u64)a[20] << 13)));
    a8  = (i64)(2097151 & (((u64)a[21])       | ((u64)a[22] <<  8) | ((u64)a[23] << 16)));
    a9  = (i64)(2097151 & (((u64)a[23] >>  5) | ((u64)a[24] <<  3) | ((u64)a[25] << 11) | ((u64)a[26] << 19)));
    a10 = (i64)(2097151 & (((u64)a[26] >>  2) | ((u64)a[27] <<  6) | ((u64)a[28] << 14)));
    a11 = (i64)(((u64)a[28] >>  7) | ((u64)a[29] <<  1) | ((u64)a[30] <<  9) | ((u64)a[31] << 17));

    b0  = (i64)(2097151 & (((u64)b[ 0])       | ((u64)b[ 1] <<  8) | ((u64)b[ 2] << 16)));
    b1  = (i64)(2097151 & (((u64)b[ 2] >>  5) | ((u64)b[ 3] <<  3) | ((u64)b[ 4] << 11) | ((u64)b[ 5] << 19)));
    b2  = (i64)(2097151 & (((u64)b[ 5] >>  2) | ((u64)b[ 6] <<  6) | ((u64)b[ 7] << 14)));
    b3  = (i64)(2097151 & (((u64)b[ 7] >>  7) | ((u64)b[ 8] <<  1) | ((u64)b[ 9] <<  9) | ((u64)b[10] << 17)));
    b4  = (i64)(2097151 & (((u64)b[10] >>  4) | ((u64)b[11] <<  4) | ((u64)b[12] << 12) | ((u64)b[13] << 20)));
    b5  = (i64)(2097151 & (((u64)b[13] >>  1) | ((u64)b[14] <<  7) | ((u64)b[15] << 15)));
    b6  = (i64)(2097151 & (((u64)b[15] >>  6) | ((u64)b[16] <<  2) | ((u64)b[17] << 10) | ((u64)b[18] << 18)));
    b7  = (i64)(2097151 & (((u64)b[18] >>  3) | ((u64)b[19] <<  5) | ((u64)b[20] << 13)));
    b8  = (i64)(2097151 & (((u64)b[21])       | ((u64)b[22] <<  8) | ((u64)b[23] << 16)));
    b9  = (i64)(2097151 & (((u64)b[23] >>  5) | ((u64)b[24] <<  3) | ((u64)b[25] << 11) | ((u64)b[26] << 19)));
    b10 = (i64)(2097151 & (((u64)b[26] >>  2) | ((u64)b[27] <<  6) | ((u64)b[28] << 14)));
    b11 = (i64)(((u64)b[28] >>  7) | ((u64)b[29] <<  1) | ((u64)b[30] <<  9) | ((u64)b[31] << 17));

    c0  = (i64)(2097151 & (((u64)c[ 0])       | ((u64)c[ 1] <<  8) | ((u64)c[ 2] << 16)));
    c1  = (i64)(2097151 & (((u64)c[ 2] >>  5) | ((u64)c[ 3] <<  3) | ((u64)c[ 4] << 11) | ((u64)c[ 5] << 19)));
    c2  = (i64)(2097151 & (((u64)c[ 5] >>  2) | ((u64)c[ 6] <<  6) | ((u64)c[ 7] << 14)));
    c3  = (i64)(2097151 & (((u64)c[ 7] >>  7) | ((u64)c[ 8] <<  1) | ((u64)c[ 9] <<  9) | ((u64)c[10] << 17)));
    c4  = (i64)(2097151 & (((u64)c[10] >>  4) | ((u64)c[11] <<  4) | ((u64)c[12] << 12) | ((u64)c[13] << 20)));
    c5  = (i64)(2097151 & (((u64)c[13] >>  1) | ((u64)c[14] <<  7) | ((u64)c[15] << 15)));
    c6  = (i64)(2097151 & (((u64)c[15] >>  6) | ((u64)c[16] <<  2) | ((u64)c[17] << 10) | ((u64)c[18] << 18)));
    c7  = (i64)(2097151 & (((u64)c[18] >>  3) | ((u64)c[19] <<  5) | ((u64)c[20] << 13)));
    c8  = (i64)(2097151 & (((u64)c[21])       | ((u64)c[22] <<  8) | ((u64)c[23] << 16)));
    c9  = (i64)(2097151 & (((u64)c[23] >>  5) | ((u64)c[24] <<  3) | ((u64)c[25] << 11) | ((u64)c[26] << 19)));
    c10 = (i64)(2097151 & (((u64)c[26] >>  2) | ((u64)c[27] <<  6) | ((u64)c[28] << 14)));
    c11 = (i64)(((u64)c[28] >>  7) | ((u64)c[29] <<  1) | ((u64)c[30] <<  9) | ((u64)c[31] << 17));

    /* s = a*b + c */
    s0  = c0  + a0*b0;
    s1  = c1  + a0*b1  + a1*b0;
    s2  = c2  + a0*b2  + a1*b1  + a2*b0;
    s3  = c3  + a0*b3  + a1*b2  + a2*b1  + a3*b0;
    s4  = c4  + a0*b4  + a1*b3  + a2*b2  + a3*b1  + a4*b0;
    s5  = c5  + a0*b5  + a1*b4  + a2*b3  + a3*b2  + a4*b1  + a5*b0;
    s6  = c6  + a0*b6  + a1*b5  + a2*b4  + a3*b3  + a4*b2  + a5*b1  + a6*b0;
    s7  = c7  + a0*b7  + a1*b6  + a2*b5  + a3*b4  + a4*b3  + a5*b2  + a6*b1  + a7*b0;
    s8  = c8  + a0*b8  + a1*b7  + a2*b6  + a3*b5  + a4*b4  + a5*b3  + a6*b2  + a7*b1  + a8*b0;
    s9  = c9  + a0*b9  + a1*b8  + a2*b7  + a3*b6  + a4*b5  + a5*b4  + a6*b3  + a7*b2  + a8*b1  + a9*b0;
    s10 = c10 + a0*b10 + a1*b9  + a2*b8  + a3*b7  + a4*b6  + a5*b5  + a6*b4  + a7*b3  + a8*b2  + a9*b1  + a10*b0;
    s11 = c11 + a0*b11 + a1*b10 + a2*b9  + a3*b8  + a4*b7  + a5*b6  + a6*b5  + a7*b4  + a8*b3  + a9*b2  + a10*b1 + a11*b0;
    s12 =       a1*b11 + a2*b10 + a3*b9  + a4*b8  + a5*b7  + a6*b6  + a7*b5  + a8*b4  + a9*b3  + a10*b2 + a11*b1;
    s13 =       a2*b11 + a3*b10 + a4*b9  + a5*b8  + a6*b7  + a7*b6  + a8*b5  + a9*b4  + a10*b3 + a11*b2;
    s14 =       a3*b11 + a4*b10 + a5*b9  + a6*b8  + a7*b7  + a8*b6  + a9*b5  + a10*b4 + a11*b3;
    s15 =       a4*b11 + a5*b10 + a6*b9  + a7*b8  + a8*b7  + a9*b6  + a10*b5 + a11*b4;
    s16 =       a5*b11 + a6*b10 + a7*b9  + a8*b8  + a9*b7  + a10*b6 + a11*b5;
    s17 =       a6*b11 + a7*b10 + a8*b9  + a9*b8  + a10*b7 + a11*b6;
    s18 =       a7*b11 + a8*b10 + a9*b9  + a10*b8 + a11*b7;
    s19 =       a8*b11 + a9*b10 + a10*b9 + a11*b8;
    s20 =       a9*b11 + a10*b10+ a11*b9;
    s21 =       a10*b11+ a11*b10;
    s22 =       a11*b11;
    s23 = 0;

    /* Initial carry round: normalize limbs before reduction to prevent i64 overflow.
     * Without this, schoolbook products (~46-bit limbs) multiplied by reduction
     * constants (~20-bit) can exceed 63-bit signed range. */
    carry = (s0  + (1 << 20)) >> 21; s1  += carry; s0  -= carry * (1 << 21);
    carry = (s2  + (1 << 20)) >> 21; s3  += carry; s2  -= carry * (1 << 21);
    carry = (s4  + (1 << 20)) >> 21; s5  += carry; s4  -= carry * (1 << 21);
    carry = (s6  + (1 << 20)) >> 21; s7  += carry; s6  -= carry * (1 << 21);
    carry = (s8  + (1 << 20)) >> 21; s9  += carry; s8  -= carry * (1 << 21);
    carry = (s10 + (1 << 20)) >> 21; s11 += carry; s10 -= carry * (1 << 21);
    carry = (s12 + (1 << 20)) >> 21; s13 += carry; s12 -= carry * (1 << 21);
    carry = (s14 + (1 << 20)) >> 21; s15 += carry; s14 -= carry * (1 << 21);
    carry = (s16 + (1 << 20)) >> 21; s17 += carry; s16 -= carry * (1 << 21);
    carry = (s18 + (1 << 20)) >> 21; s19 += carry; s18 -= carry * (1 << 21);
    carry = (s20 + (1 << 20)) >> 21; s21 += carry; s20 -= carry * (1 << 21);
    carry = (s22 + (1 << 20)) >> 21; s23 += carry; s22 -= carry * (1 << 21);

    carry = (s1  + (1 << 20)) >> 21; s2  += carry; s1  -= carry * (1 << 21);
    carry = (s3  + (1 << 20)) >> 21; s4  += carry; s3  -= carry * (1 << 21);
    carry = (s5  + (1 << 20)) >> 21; s6  += carry; s5  -= carry * (1 << 21);
    carry = (s7  + (1 << 20)) >> 21; s8  += carry; s7  -= carry * (1 << 21);
    carry = (s9  + (1 << 20)) >> 21; s10 += carry; s9  -= carry * (1 << 21);
    carry = (s11 + (1 << 20)) >> 21; s12 += carry; s11 -= carry * (1 << 21);
    carry = (s13 + (1 << 20)) >> 21; s14 += carry; s13 -= carry * (1 << 21);
    carry = (s15 + (1 << 20)) >> 21; s16 += carry; s15 -= carry * (1 << 21);
    carry = (s17 + (1 << 20)) >> 21; s18 += carry; s17 -= carry * (1 << 21);
    carry = (s19 + (1 << 20)) >> 21; s20 += carry; s19 -= carry * (1 << 21);
    carry = (s21 + (1 << 20)) >> 21; s22 += carry; s21 -= carry * (1 << 21);

    /* Round 1: reduce s[23]..s[18] */
    s11 += s23 *  666643; s12 += s23 *  470296; s13 += s23 *  654183;
    s14 -= s23 *  997805; s15 += s23 *  136657; s16 -= s23 *  683901; s23 = 0;

    s10 += s22 *  666643; s11 += s22 *  470296; s12 += s22 *  654183;
    s13 -= s22 *  997805; s14 += s22 *  136657; s15 -= s22 *  683901; s22 = 0;

    s9  += s21 *  666643; s10 += s21 *  470296; s11 += s21 *  654183;
    s12 -= s21 *  997805; s13 += s21 *  136657; s14 -= s21 *  683901; s21 = 0;

    s8  += s20 *  666643; s9  += s20 *  470296; s10 += s20 *  654183;
    s11 -= s20 *  997805; s12 += s20 *  136657; s13 -= s20 *  683901; s20 = 0;

    s7  += s19 *  666643; s8  += s19 *  470296; s9  += s19 *  654183;
    s10 -= s19 *  997805; s11 += s19 *  136657; s12 -= s19 *  683901; s19 = 0;

    s6  += s18 *  666643; s7  += s18 *  470296; s8  += s18 *  654183;
    s9  -= s18 *  997805; s10 += s18 *  136657; s11 -= s18 *  683901; s18 = 0;

    /* Carry propagation (first round) */
    carry = (s6  + (1 << 20)) >> 21; s7  += carry; s6  -= carry * (1 << 21);
    carry = (s8  + (1 << 20)) >> 21; s9  += carry; s8  -= carry * (1 << 21);
    carry = (s10 + (1 << 20)) >> 21; s11 += carry; s10 -= carry * (1 << 21);
    carry = (s12 + (1 << 20)) >> 21; s13 += carry; s12 -= carry * (1 << 21);
    carry = (s14 + (1 << 20)) >> 21; s15 += carry; s14 -= carry * (1 << 21);
    carry = (s16 + (1 << 20)) >> 21; s17 += carry; s16 -= carry * (1 << 21);

    carry = (s7  + (1 << 20)) >> 21; s8  += carry; s7  -= carry * (1 << 21);
    carry = (s9  + (1 << 20)) >> 21; s10 += carry; s9  -= carry * (1 << 21);
    carry = (s11 + (1 << 20)) >> 21; s12 += carry; s11 -= carry * (1 << 21);
    carry = (s13 + (1 << 20)) >> 21; s14 += carry; s13 -= carry * (1 << 21);
    carry = (s15 + (1 << 20)) >> 21; s16 += carry; s15 -= carry * (1 << 21);

    /* Round 2: reduce s[17]..s[12] */
    s5  += s17 *  666643; s6  += s17 *  470296; s7  += s17 *  654183;
    s8  -= s17 *  997805; s9  += s17 *  136657; s10 -= s17 *  683901; s17 = 0;

    s4  += s16 *  666643; s5  += s16 *  470296; s6  += s16 *  654183;
    s7  -= s16 *  997805; s8  += s16 *  136657; s9  -= s16 *  683901; s16 = 0;

    s3  += s15 *  666643; s4  += s15 *  470296; s5  += s15 *  654183;
    s6  -= s15 *  997805; s7  += s15 *  136657; s8  -= s15 *  683901; s15 = 0;

    s2  += s14 *  666643; s3  += s14 *  470296; s4  += s14 *  654183;
    s5  -= s14 *  997805; s6  += s14 *  136657; s7  -= s14 *  683901; s14 = 0;

    s1  += s13 *  666643; s2  += s13 *  470296; s3  += s13 *  654183;
    s4  -= s13 *  997805; s5  += s13 *  136657; s6  -= s13 *  683901; s13 = 0;

    s0  += s12 *  666643; s1  += s12 *  470296; s2  += s12 *  654183;
    s3  -= s12 *  997805; s4  += s12 *  136657; s5  -= s12 *  683901; s12 = 0;

    /* Round A: biased carry (even/odd) on s0..s11 → produces s12 */
    carry = (s0  + (1 << 20)) >> 21; s1  += carry; s0  -= carry * (1 << 21);
    carry = (s2  + (1 << 20)) >> 21; s3  += carry; s2  -= carry * (1 << 21);
    carry = (s4  + (1 << 20)) >> 21; s5  += carry; s4  -= carry * (1 << 21);
    carry = (s6  + (1 << 20)) >> 21; s7  += carry; s6  -= carry * (1 << 21);
    carry = (s8  + (1 << 20)) >> 21; s9  += carry; s8  -= carry * (1 << 21);
    carry = (s10 + (1 << 20)) >> 21; s11 += carry; s10 -= carry * (1 << 21);

    carry = (s1  + (1 << 20)) >> 21; s2  += carry; s1  -= carry * (1 << 21);
    carry = (s3  + (1 << 20)) >> 21; s4  += carry; s3  -= carry * (1 << 21);
    carry = (s5  + (1 << 20)) >> 21; s6  += carry; s5  -= carry * (1 << 21);
    carry = (s7  + (1 << 20)) >> 21; s8  += carry; s7  -= carry * (1 << 21);
    carry = (s9  + (1 << 20)) >> 21; s10 += carry; s9  -= carry * (1 << 21);
    carry = (s11 + (1 << 20)) >> 21; s12 += carry; s11 -= carry * (1 << 21);

    /* First s12 reduction */
    s0  += s12 *  666643; s1  += s12 *  470296; s2  += s12 *  654183;
    s3  -= s12 *  997805; s4  += s12 *  136657; s5  -= s12 *  683901; s12 = 0;

    /* Round B: sequential carry with mask, s0..s11 → s12 */
    carry = s0  >> 21; s1  += carry; s0  &= 0x1fffff;
    carry = s1  >> 21; s2  += carry; s1  &= 0x1fffff;
    carry = s2  >> 21; s3  += carry; s2  &= 0x1fffff;
    carry = s3  >> 21; s4  += carry; s3  &= 0x1fffff;
    carry = s4  >> 21; s5  += carry; s4  &= 0x1fffff;
    carry = s5  >> 21; s6  += carry; s5  &= 0x1fffff;
    carry = s6  >> 21; s7  += carry; s6  &= 0x1fffff;
    carry = s7  >> 21; s8  += carry; s7  &= 0x1fffff;
    carry = s8  >> 21; s9  += carry; s8  &= 0x1fffff;
    carry = s9  >> 21; s10 += carry; s9  &= 0x1fffff;
    carry = s10 >> 21; s11 += carry; s10 &= 0x1fffff;
    carry = s11 >> 21; s12 += carry; s11 &= 0x1fffff;

    /* Second s12 reduction */
    s0  += s12 *  666643; s1  += s12 *  470296; s2  += s12 *  654183;
    s3  -= s12 *  997805; s4  += s12 *  136657; s5  -= s12 *  683901; s12 = 0;

    /* Round C: final sequential carry with mask, s0..s10 only */
    carry = s0  >> 21; s1  += carry; s0  &= 0x1fffff;
    carry = s1  >> 21; s2  += carry; s1  &= 0x1fffff;
    carry = s2  >> 21; s3  += carry; s2  &= 0x1fffff;
    carry = s3  >> 21; s4  += carry; s3  &= 0x1fffff;
    carry = s4  >> 21; s5  += carry; s4  &= 0x1fffff;
    carry = s5  >> 21; s6  += carry; s5  &= 0x1fffff;
    carry = s6  >> 21; s7  += carry; s6  &= 0x1fffff;
    carry = s7  >> 21; s8  += carry; s7  &= 0x1fffff;
    carry = s8  >> 21; s9  += carry; s8  &= 0x1fffff;
    carry = s9  >> 21; s10 += carry; s9  &= 0x1fffff;
    carry = s10 >> 21; s11 += carry; s10 &= 0x1fffff;

    /* Pack into 32 bytes */
    out[ 0] = (u8)(s0  >>  0);
    out[ 1] = (u8)(s0  >>  8);
    out[ 2] = (u8)((s0  >> 16) | (s1  <<  5));
    out[ 3] = (u8)(s1  >>  3);
    out[ 4] = (u8)(s1  >> 11);
    out[ 5] = (u8)((s1  >> 19) | (s2  <<  2));
    out[ 6] = (u8)(s2  >>  6);
    out[ 7] = (u8)((s2  >> 14) | (s3  <<  7));
    out[ 8] = (u8)(s3  >>  1);
    out[ 9] = (u8)(s3  >>  9);
    out[10] = (u8)((s3  >> 17) | (s4  <<  4));
    out[11] = (u8)(s4  >>  4);
    out[12] = (u8)(s4  >> 12);
    out[13] = (u8)((s4  >> 20) | (s5  <<  1));
    out[14] = (u8)(s5  >>  7);
    out[15] = (u8)((s5  >> 15) | (s6  <<  6));
    out[16] = (u8)(s6  >>  2);
    out[17] = (u8)(s6  >> 10);
    out[18] = (u8)((s6  >> 18) | (s7  <<  3));
    out[19] = (u8)(s7  >>  5);
    out[20] = (u8)(s7  >> 13);
    out[21] = (u8)(s8  >>  0);
    out[22] = (u8)(s8  >>  8);
    out[23] = (u8)((s8  >> 16) | (s9  <<  5));
    out[24] = (u8)(s9  >>  3);
    out[25] = (u8)(s9  >> 11);
    out[26] = (u8)((s9  >> 19) | (s10 <<  2));
    out[27] = (u8)(s10 >>  6);
    out[28] = (u8)((s10 >> 14) | (s11 <<  7));
    out[29] = (u8)(s11 >>  1);
    out[30] = (u8)(s11 >>  9);
    out[31] = (u8)(s11 >> 17);
}

/* Check if scalar s < l. Returns 1 if valid (s < l), 0 otherwise. */
static int sc_is_canonical(const u8 s[32]) {
    /* s must be < l. Check in constant time by comparing from MSB. */
    int i;
    unsigned int borrow = 0;
    for (i = 31; i >= 0; i--) {
        unsigned int diff = (unsigned int)s[i] - (unsigned int)EC_L[i] - borrow;
        borrow = (diff >> 8) & 1;
    }
    /* If borrow == 1, s < l */
    return (int)borrow;
}

/* ======================================================================
 * Ed25519 public API
 * ====================================================================== */

unsigned long ed25519_keygen_from_seed(ed25519_keypair *out,
                                                     const ed25519_seed *seed) {
    if (!out) return 1;
    if (!seed) return 2;

    u8 hash[64];
    sha512_digest(hash, seed->data, ED25519_SEED_LEN);

    /* Clamp */
    hash[0] &= 248;   /* clear bits 0,1,2 */
    hash[31] &= 127;  /* clear bit 255 */
    hash[31] |= 64;   /* set bit 254 */

    /* expanded private key: scalar (first 32 bytes) + prefix (last 32 bytes) */
    memcpy(out->priv.data, hash, 64);
    memcpy(out->seed.data, seed->data, ED25519_SEED_LEN);

    /* Compute public key: A = a * B */
    ge25519 A;
    ge_scalarmult_base(&A, hash);
    ge_tobytes(out->pub.data, &A);

    memset(hash, 0, sizeof(hash));
    return 0;
}

unsigned long ed25519_keygen(ed25519_keypair *out) {
    if (!out) return 1;

    ed25519_seed seed;
    unsigned long rc = entropy_get_system(seed.data, ED25519_SEED_LEN);
    if (rc != 0) return 2;

    rc = ed25519_keygen_from_seed(out, &seed);
    memset(&seed, 0, sizeof(seed));
    if (rc != 0) return 3;
    return 0;
}

unsigned long ed25519_sign(u8 *sig_out,
                                         const ed25519_privkey *key,
                                         const ed25519_pubkey *pub,
                                         const u8 *msg, u64 msg_len) {
    if (!sig_out) return 1;
    if (!key) return 2;
    if (!pub) return 3;
    if (!msg && msg_len > 0) return 4;

    /* key->data[0..31] = clamped scalar a
     * key->data[32..63] = prefix (nonce material from SHA-512 of seed) */

    /* r = SHA-512(prefix || msg) mod l */
    u8 nonce_hash[64];
    {
        sha512_ctx ctx;
        if (sha512_init(&ctx) != 0) return 5;
        if (sha512_update(&ctx, key->data + 32, 32) != 0) return 5;
        if (sha512_update(&ctx, msg, msg_len) != 0) return 5;
        if (sha512_final(nonce_hash, &ctx) != 0) return 5;
    }

    u8 nonce[32];
    sc_reduce(nonce, nonce_hash);

    /* R = r * B */
    ge25519 R;
    ge_scalarmult_base(&R, nonce);
    ge_tobytes(sig_out, &R); /* sig_out[0..31] = R */

    /* h = SHA-512(R || A || msg) mod l */
    u8 hram[64];
    {
        sha512_ctx ctx;
        if (sha512_init(&ctx) != 0) return 5;
        if (sha512_update(&ctx, sig_out, 32) != 0) return 5;
        if (sha512_update(&ctx, pub->data, 32) != 0) return 5;
        if (sha512_update(&ctx, msg, msg_len) != 0) return 5;
        if (sha512_final(hram, &ctx) != 0) return 5;
    }

    u8 hram_reduced[32];
    sc_reduce(hram_reduced, hram);

    /* S = r + h * a mod l */
    sc_muladd(sig_out + 32, hram_reduced, key->data, nonce);

    memset(nonce_hash, 0, sizeof(nonce_hash));
    memset(nonce, 0, sizeof(nonce));
    return 0;
}

/* Negate a point */
static void ge_neg(ge25519 *r, const ge25519 *p) {
    fe_neg(&r->X, &p->X);
    fe_copy(&r->Y, &p->Y);
    fe_copy(&r->Z, &p->Z);
    fe_neg(&r->T, &p->T);
}

unsigned long ed25519_verify(unsigned long *valid,
                                           const ed25519_pubkey *pub,
                                           const u8 *sig,
                                           const u8 *msg, u64 msg_len) {
    if (!valid) return 1;
    if (!pub) return 2;
    if (!sig) return 3;
    if (!msg && msg_len > 0) return 4;

    *valid = 0;

    /* Check S < l */
    if (!sc_is_canonical(sig + 32))
        return 0;

    /* Decode R */
    ge25519 R;
    if (ge_frombytes(&R, sig) != 0)
        return 0;

    /* Decode A (public key) */
    ge25519 A;
    if (ge_frombytes(&A, pub->data) != 0)
        return 0;

    /* h = SHA-512(R || A || msg) mod l */
    u8 hram[64];
    {
        sha512_ctx ctx;
        sha512_init(&ctx);
        sha512_update(&ctx, sig, 32);
        sha512_update(&ctx, pub->data, 32);
        sha512_update(&ctx, msg, msg_len);
        sha512_final(hram, &ctx);
    }
    u8 h[32];
    sc_reduce(h, hram);

    /* Check: S*B == R + h*A */
    ge25519 sB, hA;
    ge_scalarmult_base(&sB, sig + 32);
    ge_scalarmult(&hA, h, &A);

    /* negate hA to compute sB - hA and compare with R */
    ge25519 neg_hA;
    ge_neg(&neg_hA, &hA);
    ge25519 check;
    ge_add(&check, &sB, &neg_hA);

    u8 check_bytes[32];
    ge_tobytes(check_bytes, &check);

    u8 R_bytes[32];
    ge_tobytes(R_bytes, &R);

    /* Constant-time comparison */
    u8 diff = 0;
    int i;
    for (i = 0; i < 32; i++)
        diff |= check_bytes[i] ^ R_bytes[i];

    if (diff == 0)
        *valid = 1;

    return 0;
}

unsigned long ed25519_pubkey_from_privkey(ed25519_pubkey *out,
                                                        const ed25519_privkey *priv) {
    if (!out) return 1;
    if (!priv) return 2;

    ge25519 A;
    ge_scalarmult_base(&A, priv->data);
    ge_tobytes(out->data, &A);
    return 0;
}

/* ======================================================================
 * X25519 (RFC 7748) — Montgomery ladder on Curve25519
 * ====================================================================== */

/* Clamp a 32-byte X25519 private key */
static void x25519_clamp(u8 key[32]) {
    key[0] &= 248;
    key[31] &= 127;
    key[31] |= 64;
}

/* Montgomery ladder scalar multiplication.
 * Computes q = scalar * point, where point is an x-coordinate on Curve25519.
 * Uses constant-time Montgomery ladder. */
static void x25519_scalarmult(u8 out[32], const u8 scalar[32], const u8 point[32]) {
    fe25519 x1, x2, z2, x3, z3, tmp0, tmp1;
    int bit, swap, i;
    u8 e[32];

    memcpy(e, scalar, 32);
    x25519_clamp(e);

    fe_frombytes(&x1, point);
    fe_one(&x2);
    fe_zero(&z2);
    fe_copy(&x3, &x1);
    fe_one(&z3);

    swap = 0;
    for (i = 254; i >= 0; i--) {
        bit = (e[i >> 3] >> (i & 7)) & 1;
        swap ^= bit;
        fe_cswap(&x2, &x3, (u64)swap);
        fe_cswap(&z2, &z3, (u64)swap);
        swap = bit;

        fe_sub(&tmp0, &x3, &z3);
        fe_sub(&tmp1, &x2, &z2);
        fe_add(&x2, &x2, &z2);
        fe_add(&z2, &x3, &z3);
        fe_mul(&z3, &tmp0, &x2);
        fe_mul(&z2, &z2, &tmp1);
        fe_sq(&tmp0, &tmp1);
        fe_sq(&tmp1, &x2);
        fe_add(&x3, &z3, &z2);
        fe_sub(&z2, &z3, &z2);
        fe_mul(&x2, &tmp1, &tmp0);
        fe_sub(&tmp1, &tmp1, &tmp0);
        fe_sq(&z2, &z2);
        fe_mul_small(&z3, &tmp1, 121666);
        fe_sq(&x3, &x3);
        fe_add(&tmp0, &tmp0, &z3);
        fe_mul(&z3, &x1, &z2);
        fe_mul(&z2, &tmp1, &tmp0);
    }

    fe_cswap(&x2, &x3, (u64)swap);
    fe_cswap(&z2, &z3, (u64)swap);

    fe_invert(&z2, &z2);
    fe_mul(&x2, &x2, &z2);
    fe_tobytes(out, &x2);
}

/* X25519 base point (9) */
static const u8 X25519_BASEPOINT[32] = {
    9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

unsigned long x25519_keygen(x25519_keypair *out) {
    if (!out) return 1;

    unsigned long rc = entropy_get_system(out->priv.data, X25519_KEY_LEN);
    if (rc != 0) return 2;

    /* Derive public key */
    x25519_scalarmult(out->pub.data, out->priv.data, X25519_BASEPOINT);
    return 0;
}

unsigned long x25519_dh(u8 *shared_out,
                                      const x25519_privkey *priv,
                                      const x25519_pubkey *pub) {
    if (!shared_out) return 1;
    if (!priv) return 2;
    if (!pub) return 3;

    x25519_scalarmult(shared_out, priv->data, pub->data);

    /* Check for low-order point (all zeros output) */
    u8 zero = 0;
    int i;
    for (i = 0; i < 32; i++) zero |= shared_out[i];
    if (zero == 0) {
        return 4;
    }

    return 0;
}

unsigned long x25519_pubkey_from_privkey(x25519_pubkey *out,
                                                       const x25519_privkey *priv) {
    if (!out) return 1;
    if (!priv) return 2;

    x25519_scalarmult(out->data, priv->data, X25519_BASEPOINT);
    return 0;
}
