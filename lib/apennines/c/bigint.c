#include "apennines/bigint.h"
#include <stdlib.h>
#include <string.h>

/* ---- internal helpers ---- */

static void bi_trim(bigint *b) {
    while (b->len > 1 && b->digits[b->len - 1] == 0) {
        b->len--;
    }
}

static unsigned long bi_ensure_cap(bigint *b, u64 need) {
    u32 *p;
    if (need <= b->cap) return 0;
    p = (u32 *)realloc(b->digits, (size_t)(need * sizeof(u32)));
    if (!p) return 1;
    memset(p + b->cap, 0, (size_t)((need - b->cap) * sizeof(u32)));
    b->digits = p;
    b->cap = need;
    return 0;
}

static unsigned long bi_copy(bigint *dst, bigint *src) {
    unsigned long rc;
    rc = bi_ensure_cap(dst, src->len);
    if (rc) return rc;
    memcpy(dst->digits, src->digits, (size_t)(src->len * sizeof(u32)));
    dst->len = src->len;
    return 0;
}

/* ---- public API ---- */

unsigned long bigint_create(bigint *out, u64 digit_count) {
    if (!out) return 1;
    if (digit_count == 0) digit_count = 1;
    out->digits = (u32 *)calloc((size_t)digit_count, sizeof(u32));
    if (!out->digits) return 2;
    out->len = 1;
    out->cap = digit_count;
    return 0;
}

unsigned long bigint_from_u64(bigint *out, u64 val) {
    if (!out) return 1;
    out->digits = (u32 *)calloc(2, sizeof(u32));
    if (!out->digits) return 2;
    out->cap = 2;
    out->digits[0] = (u32)(val & 0xFFFFFFFFu);
    out->digits[1] = (u32)(val >> 32);
    out->len = out->digits[1] ? 2 : 1;
    return 0;
}

unsigned long bigint_from_bytes(bigint *out, u8 *data, u64 len) {
    u64 i;
    u64 nlimbs;

    if (!out) return 1;
    if (!data) return 2;
    if (len == 0) {
        return bigint_from_u64(out, 0);
    }

    /* data is big-endian */
    nlimbs = (len + 3) / 4;
    out->digits = (u32 *)calloc((size_t)nlimbs, sizeof(u32));
    if (!out->digits) return 3;
    out->cap = nlimbs;
    out->len = nlimbs;

    for (i = 0; i < len; i++) {
        u64 byte_pos = len - 1 - i;
        u64 limb_idx = i / 4;
        u64 shift = (i % 4) * 8;
        out->digits[limb_idx] |= ((u32)data[byte_pos]) << shift;
    }

    bi_trim(out);
    return 0;
}

unsigned long bigint_to_bytes(u8 *out, u64 *out_len, u64 out_cap, bigint *val) {
    u64 bit_len;
    u64 byte_len;
    u64 i;
    unsigned long rc;

    if (!out) return 1;
    if (!out_len) return 2;
    if (!val) return 3;

    rc = bigint_bitlen(&bit_len, val);
    if (rc) return 4;

    byte_len = (bit_len + 7) / 8;
    if (byte_len == 0) byte_len = 1;
    if (byte_len > out_cap) return 5;

    memset(out, 0, (size_t)byte_len);

    /* output big-endian */
    for (i = 0; i < byte_len; i++) {
        u64 src_byte = byte_len - 1 - i;
        u64 limb_idx = src_byte / 4;
        u64 shift = (src_byte % 4) * 8;
        if (limb_idx < val->len) {
            out[i] = (u8)((val->digits[limb_idx] >> shift) & 0xFF);
        }
    }

    *out_len = byte_len;
    return 0;
}

unsigned long bigint_add(bigint *out, bigint *a, bigint *b) {
    u64 max_len;
    u64 i;
    u64 carry;
    unsigned long rc;

    if (!out) return 1;
    if (!a) return 2;
    if (!b) return 3;


    max_len = a->len > b->len ? a->len : b->len;
    rc = bi_ensure_cap(out, max_len + 1);
    if (rc) return 4;

    carry = 0;
    for (i = 0; i < max_len || carry; i++) {
        u64 sum = carry;
        if (i < a->len) sum += a->digits[i];
        if (i < b->len) sum += b->digits[i];
        if (i >= out->cap) {
            rc = bi_ensure_cap(out, i + 1);
            if (rc) return 4;
        }
        out->digits[i] = (u32)(sum & 0xFFFFFFFFu);
        carry = sum >> 32;
    }

    out->len = i;
    bi_trim(out);
    return 0;
}

unsigned long bigint_sub(bigint *out, bigint *a, bigint *b) {
    u64 i;
    i64 borrow;
    unsigned long rc;

    if (!out) return 1;
    if (!a) return 2;
    if (!b) return 3;


    /* a must be >= b (unsigned subtraction) */
    {
        long cmp_result;
        rc = bigint_compare(&cmp_result, a, b);
        if (rc) return 4;
        if (cmp_result < 0) return 5; /* underflow */
    }

    rc = bi_ensure_cap(out, a->len);
    if (rc) return 6;

    borrow = 0;
    for (i = 0; i < a->len; i++) {
        i64 diff = (i64)a->digits[i] - borrow;
        if (i < b->len) diff -= (i64)b->digits[i];
        if (diff < 0) {
            diff += (i64)1 << 32;
            borrow = 1;
        } else {
            borrow = 0;
        }
        out->digits[i] = (u32)diff;
    }

    out->len = a->len;
    bi_trim(out);
    return 0;
}

/* schoolbook multiplication */
static unsigned long bi_mul_schoolbook(bigint *out, bigint *a, bigint *b) {
    u64 i;
    u64 j;
    u64 out_len;
    unsigned long rc;

    out_len = a->len + b->len;
    rc = bi_ensure_cap(out, out_len);
    if (rc) return rc;
    memset(out->digits, 0, (size_t)(out_len * sizeof(u32)));
    out->len = out_len;

    for (i = 0; i < a->len; i++) {
        u64 carry = 0;
        for (j = 0; j < b->len; j++) {
            u64 prod = (u64)a->digits[i] * (u64)b->digits[j]
                     + (u64)out->digits[i + j] + carry;
            out->digits[i + j] = (u32)(prod & 0xFFFFFFFFu);
            carry = prod >> 32;
        }
        out->digits[i + b->len] += (u32)carry;
    }

    bi_trim(out);
    return 0;
}

/* Karatsuba multiplication */
static unsigned long bi_mul_karatsuba(bigint *out, bigint *a, bigint *b) {
    u64 half;
    u64 n;
    bigint a0, a1, b0, b1;
    bigint z0, z1, z2;
    bigint a_sum, b_sum, mid_prod;
    bigint tmp1, tmp2;
    unsigned long rc;

    n = a->len > b->len ? a->len : b->len;
    if (n <= 64) {
        return bi_mul_schoolbook(out, a, b);
    }

    half = n / 2;

    memset(&a0, 0, sizeof(bigint));
    memset(&a1, 0, sizeof(bigint));
    memset(&b0, 0, sizeof(bigint));
    memset(&b1, 0, sizeof(bigint));
    memset(&z0, 0, sizeof(bigint));
    memset(&z1, 0, sizeof(bigint));
    memset(&z2, 0, sizeof(bigint));
    memset(&a_sum, 0, sizeof(bigint));
    memset(&b_sum, 0, sizeof(bigint));
    memset(&mid_prod, 0, sizeof(bigint));
    memset(&tmp1, 0, sizeof(bigint));
    memset(&tmp2, 0, sizeof(bigint));

    /* split a = a1 * B^half + a0 */
    rc = bigint_create(&a0, half);
    if (rc) goto cleanup;
    if (half <= a->len) {
        memcpy(a0.digits, a->digits, (size_t)((half < a->len ? half : a->len) * sizeof(u32)));
        a0.len = half < a->len ? half : a->len;
    }
    bi_trim(&a0);

    rc = bigint_create(&a1, a->len > half ? a->len - half : 1);
    if (rc) goto cleanup;
    if (a->len > half) {
        memcpy(a1.digits, a->digits + half, (size_t)((a->len - half) * sizeof(u32)));
        a1.len = a->len - half;
    }
    bi_trim(&a1);

    /* split b = b1 * B^half + b0 */
    rc = bigint_create(&b0, half);
    if (rc) goto cleanup;
    if (half <= b->len) {
        memcpy(b0.digits, b->digits, (size_t)((half < b->len ? half : b->len) * sizeof(u32)));
        b0.len = half < b->len ? half : b->len;
    }
    bi_trim(&b0);

    rc = bigint_create(&b1, b->len > half ? b->len - half : 1);
    if (rc) goto cleanup;
    if (b->len > half) {
        memcpy(b1.digits, b->digits + half, (size_t)((b->len - half) * sizeof(u32)));
        b1.len = b->len - half;
    }
    bi_trim(&b1);

    /* z0 = a0 * b0 */
    rc = bigint_create(&z0, 1);
    if (rc) goto cleanup;
    rc = bigint_mul(&z0, &a0, &b0);
    if (rc) goto cleanup;

    /* z2 = a1 * b1 */
    rc = bigint_create(&z2, 1);
    if (rc) goto cleanup;
    rc = bigint_mul(&z2, &a1, &b1);
    if (rc) goto cleanup;

    /* z1 = (a0+a1)*(b0+b1) - z0 - z2 */
    rc = bigint_create(&a_sum, 1);
    if (rc) goto cleanup;
    rc = bigint_add(&a_sum, &a0, &a1);
    if (rc) goto cleanup;

    rc = bigint_create(&b_sum, 1);
    if (rc) goto cleanup;
    rc = bigint_add(&b_sum, &b0, &b1);
    if (rc) goto cleanup;

    rc = bigint_create(&mid_prod, 1);
    if (rc) goto cleanup;
    rc = bigint_mul(&mid_prod, &a_sum, &b_sum);
    if (rc) goto cleanup;

    rc = bigint_create(&z1, 1);
    if (rc) goto cleanup;
    rc = bigint_sub(&z1, &mid_prod, &z0);
    if (rc) goto cleanup;

    rc = bigint_create(&tmp1, 1);
    if (rc) goto cleanup;
    rc = bi_copy(&tmp1, &z1);
    if (rc) goto cleanup;
    rc = bigint_sub(&z1, &tmp1, &z2);
    if (rc) goto cleanup;

    /* out = z2 * B^(2*half) + z1 * B^half + z0 */
    rc = bigint_create(&tmp2, 1);
    if (rc) goto cleanup;
    rc = bigint_shl(&tmp2, &z2, half * 32 * 2);
    if (rc) goto cleanup;

    rc = bi_copy(&tmp1, &z1);
    if (rc) goto cleanup;
    rc = bigint_shl(&z1, &tmp1, half * 32);
    if (rc) goto cleanup;

    rc = bigint_add(out, &tmp2, &z1);
    if (rc) goto cleanup;

    rc = bi_copy(&tmp1, out);
    if (rc) goto cleanup;
    rc = bigint_add(out, &tmp1, &z0);
    if (rc) goto cleanup;

cleanup:
    bigint_destroy(&a0);
    bigint_destroy(&a1);
    bigint_destroy(&b0);
    bigint_destroy(&b1);
    bigint_destroy(&z0);
    bigint_destroy(&z1);
    bigint_destroy(&z2);
    bigint_destroy(&a_sum);
    bigint_destroy(&b_sum);
    bigint_destroy(&mid_prod);
    bigint_destroy(&tmp1);
    bigint_destroy(&tmp2);
    return rc;
}

unsigned long bigint_mul(bigint *out, bigint *a, bigint *b) {
    u64 n;

    if (!out) return 1;
    if (!a) return 2;
    if (!b) return 3;


    n = a->len > b->len ? a->len : b->len;
    if (n > 64) {
        return bi_mul_karatsuba(out, a, b);
    }
    return bi_mul_schoolbook(out, a, b);
}

/* Knuth's Algorithm D: multi-precision long division */
unsigned long bigint_div(bigint *quot, bigint *rem, bigint *a, bigint *b) {
    unsigned long is_z;
    unsigned long rc;
    u64 n;
    u64 m;
    u64 i;
    u64 j;

    if (!quot) return 1;
    if (!rem) return 2;
    if (!a) return 3;
    if (!b) return 4;


    rc = bigint_is_zero(&is_z, b);
    if (rc) return 5;
    if (is_z) return 6; /* division by zero */

    {
        long cmp;
        rc = bigint_compare(&cmp, a, b);
        if (rc) return 7;
        if (cmp < 0) {
            /* a < b: quot=0, rem=a */
            rc = bi_ensure_cap(quot, 1);
            if (rc) return 8;
            quot->digits[0] = 0;
            quot->len = 1;
            return bi_copy(rem, a);
        }
        if (cmp == 0) {
            rc = bi_ensure_cap(quot, 1);
            if (rc) return 8;
            quot->digits[0] = 1;
            quot->len = 1;
            rc = bi_ensure_cap(rem, 1);
            if (rc) return 9;
            rem->digits[0] = 0;
            rem->len = 1;
            return 0;
        }
    }

    n = b->len;
    m = a->len - n;

    if (n == 1) {
        /* single-limb divisor: simple algorithm */
        u64 r = 0;
        rc = bi_ensure_cap(quot, a->len);
        if (rc) return 8;
        memset(quot->digits, 0, (size_t)(a->len * sizeof(u32)));
        quot->len = a->len;

        for (i = a->len; i > 0; i--) {
            u64 cur = (r << 32) | (u64)a->digits[i - 1];
            quot->digits[i - 1] = (u32)(cur / (u64)b->digits[0]);
            r = cur % (u64)b->digits[0];
        }
        bi_trim(quot);

        rc = bi_ensure_cap(rem, 1);
        if (rc) return 9;
        rem->digits[0] = (u32)r;
        rem->len = 1;
        bi_trim(rem);
        return 0;
    }

    /* Knuth Algorithm D for multi-limb divisor */
    {
        /* normalize: shift so that top bit of divisor is set */
        u32 d_top = b->digits[n - 1];
        u64 shift = 0;
        bigint a_norm, b_norm;

        while (shift < 32 && (d_top & (1u << 31)) == 0) {
            d_top <<= 1;
            shift++;
        }

        memset(&a_norm, 0, sizeof(bigint));
        memset(&b_norm, 0, sizeof(bigint));

        rc = bigint_create(&a_norm, 1);
        if (rc) return 10;
        rc = bigint_shl(&a_norm, a, shift);
        if (rc) { bigint_destroy(&a_norm); return 10; }

        rc = bigint_create(&b_norm, 1);
        if (rc) { bigint_destroy(&a_norm); return 10; }
        rc = bigint_shl(&b_norm, b, shift);
        if (rc) { bigint_destroy(&a_norm); bigint_destroy(&b_norm); return 10; }

        /* ensure a_norm has m+n+1 limbs */
        rc = bi_ensure_cap(&a_norm, m + n + 1);
        if (rc) { bigint_destroy(&a_norm); bigint_destroy(&b_norm); return 10; }
        while (a_norm.len <= m + n) {
            a_norm.digits[a_norm.len] = 0;
            a_norm.len++;
        }

        rc = bi_ensure_cap(quot, m + 1);
        if (rc) { bigint_destroy(&a_norm); bigint_destroy(&b_norm); return 8; }
        memset(quot->digits, 0, (size_t)((m + 1) * sizeof(u32)));
        quot->len = m + 1;

        for (j = m + 1; j > 0; j--) {
            u64 idx = j - 1;
            u64 qhat;
            u64 rhat;
            u64 two_digits;

            /* D3: calculate qhat */
            two_digits = ((u64)a_norm.digits[idx + n] << 32) | (u64)a_norm.digits[idx + n - 1];
            qhat = two_digits / (u64)b_norm.digits[n - 1];
            rhat = two_digits % (u64)b_norm.digits[n - 1];

            while (qhat >= ((u64)1 << 32) ||
                   (n >= 2 && qhat * (u64)b_norm.digits[n - 2] >
                    ((rhat << 32) | (u64)a_norm.digits[idx + n - 2]))) {
                qhat--;
                rhat += (u64)b_norm.digits[n - 1];
                if (rhat >= ((u64)1 << 32)) break;
            }

            /* D4: multiply and subtract */
            {
                i64 borrow_d = 0;
                u64 k;
                for (k = 0; k < n; k++) {
                    u64 prod = qhat * (u64)b_norm.digits[k];
                    i64 diff = (i64)a_norm.digits[idx + k] - (i64)(prod & 0xFFFFFFFFu) + borrow_d;
                    a_norm.digits[idx + k] = (u32)(diff & 0xFFFFFFFF);
                    borrow_d = (diff >> 32) - (i64)(prod >> 32);
                }
                {
                    i64 diff = (i64)a_norm.digits[idx + n] + borrow_d;
                    a_norm.digits[idx + n] = (u32)(diff & 0xFFFFFFFF);

                    /* D5: if negative, add back */
                    if (diff < 0) {
                        u64 carry_ab = 0;
                        qhat--;
                        for (k = 0; k < n; k++) {
                            u64 sum = (u64)a_norm.digits[idx + k] + (u64)b_norm.digits[k] + carry_ab;
                            a_norm.digits[idx + k] = (u32)(sum & 0xFFFFFFFFu);
                            carry_ab = sum >> 32;
                        }
                        a_norm.digits[idx + n] += (u32)carry_ab;
                    }
                }
            }

            quot->digits[idx] = (u32)qhat;
        }

        bi_trim(quot);

        /* remainder = a_norm >> shift */
        rc = bigint_shr(rem, &a_norm, shift);

        bigint_destroy(&a_norm);
        bigint_destroy(&b_norm);

        if (rc) return 9;
        bi_trim(rem);
        return 0;
    }
}

unsigned long bigint_mod(bigint *out, bigint *a, bigint *b) {
    bigint q;
    unsigned long rc;

    if (!out) return 1;
    if (!a) return 2;
    if (!b) return 3;

    memset(&q, 0, sizeof(bigint));
    rc = bigint_create(&q, 1);
    if (rc) return 4;

    rc = bigint_div(&q, out, a, b);
    bigint_destroy(&q);
    return rc ? 5 : 0;
}

unsigned long bigint_modpow(bigint *out, bigint *base, bigint *exp, bigint *mod) {
    bigint result, b_cur, tmp_mp;
    u64 bit_len;
    u64 i;
    unsigned long rc;

    if (!out) return 1;
    if (!base) return 2;
    if (!exp) return 3;
    if (!mod) return 4;


    memset(&result, 0, sizeof(bigint));
    memset(&b_cur, 0, sizeof(bigint));
    memset(&tmp_mp, 0, sizeof(bigint));

    /* result = 1 */
    rc = bigint_from_u64(&result, 1);
    if (rc) goto mp_cleanup;

    /* b_cur = base mod mod */
    rc = bigint_create(&b_cur, 1);
    if (rc) goto mp_cleanup;
    rc = bigint_mod(&b_cur, base, mod);
    if (rc) goto mp_cleanup;

    rc = bigint_bitlen(&bit_len, exp);
    if (rc) goto mp_cleanup;

    rc = bigint_create(&tmp_mp, 1);
    if (rc) goto mp_cleanup;

    /* square-and-multiply */
    for (i = 0; i < bit_len; i++) {
        u64 limb_idx = i / 32;
        u64 bit_idx = i % 32;

        if (limb_idx < exp->len && (exp->digits[limb_idx] & (1u << bit_idx))) {
            /* result = result * b_cur mod mod */
            rc = bigint_mul(&tmp_mp, &result, &b_cur);
            if (rc) goto mp_cleanup;
            rc = bigint_mod(&result, &tmp_mp, mod);
            if (rc) goto mp_cleanup;
        }

        /* b_cur = b_cur * b_cur mod mod */
        rc = bigint_mul(&tmp_mp, &b_cur, &b_cur);
        if (rc) goto mp_cleanup;
        rc = bigint_mod(&b_cur, &tmp_mp, mod);
        if (rc) goto mp_cleanup;
    }

    rc = bi_copy(out, &result);

mp_cleanup:
    bigint_destroy(&result);
    bigint_destroy(&b_cur);
    bigint_destroy(&tmp_mp);
    return rc;
}

unsigned long bigint_modinv(bigint *out, bigint *a, bigint *mod) {
    /* Extended Euclidean algorithm */
    bigint old_r, r, old_s, s, q, tmp, prod, new_r, new_s;
    unsigned long is_z;
    unsigned long rc;

    if (!out) return 1;
    if (!a) return 2;
    if (!mod) return 3;


    memset(&old_r, 0, sizeof(bigint));
    memset(&r, 0, sizeof(bigint));
    memset(&old_s, 0, sizeof(bigint));
    memset(&s, 0, sizeof(bigint));
    memset(&q, 0, sizeof(bigint));
    memset(&tmp, 0, sizeof(bigint));
    memset(&prod, 0, sizeof(bigint));
    memset(&new_r, 0, sizeof(bigint));
    memset(&new_s, 0, sizeof(bigint));

    rc = bigint_create(&old_r, 1);
    if (rc) goto inv_cleanup;
    rc = bi_copy(&old_r, mod);
    if (rc) goto inv_cleanup;

    rc = bigint_create(&r, 1);
    if (rc) goto inv_cleanup;
    rc = bigint_mod(&r, a, mod);
    if (rc) goto inv_cleanup;

    rc = bigint_from_u64(&old_s, 0);
    if (rc) goto inv_cleanup;

    rc = bigint_from_u64(&s, 1);
    if (rc) goto inv_cleanup;

    rc = bigint_create(&q, 1);
    if (rc) goto inv_cleanup;
    rc = bigint_create(&tmp, 1);
    if (rc) goto inv_cleanup;
    rc = bigint_create(&prod, 1);
    if (rc) goto inv_cleanup;
    rc = bigint_create(&new_r, 1);
    if (rc) goto inv_cleanup;
    rc = bigint_create(&new_s, 1);
    if (rc) goto inv_cleanup;

    for (;;) {
        rc = bigint_is_zero(&is_z, &r);
        if (rc) goto inv_cleanup;
        if (is_z) break;

        rc = bigint_div(&q, &new_r, &old_r, &r);
        if (rc) goto inv_cleanup;

        /* new_r = old_r - q * r (which is the remainder, already in new_r from div) */
        rc = bi_copy(&old_r, &r);
        if (rc) goto inv_cleanup;
        rc = bi_copy(&r, &new_r);
        if (rc) goto inv_cleanup;

        /* new_s = old_s + q * s (working in mod arithmetic to keep positive) */
        rc = bigint_mul(&prod, &q, &s);
        if (rc) goto inv_cleanup;

        /* We need old_s - q*s mod mod. Since we can't do signed bigint,
           compute (old_s + mod - (q*s mod mod)) mod mod */
        rc = bigint_mod(&tmp, &prod, mod);
        if (rc) goto inv_cleanup;

        /* new_s = (old_s + mod - tmp) mod mod */
        rc = bigint_add(&prod, &old_s, mod);
        if (rc) goto inv_cleanup;
        rc = bigint_sub(&new_s, &prod, &tmp);
        if (rc) goto inv_cleanup;
        rc = bigint_mod(&tmp, &new_s, mod);
        if (rc) goto inv_cleanup;

        rc = bi_copy(&old_s, &s);
        if (rc) goto inv_cleanup;
        rc = bi_copy(&s, &tmp);
        if (rc) goto inv_cleanup;
    }

    /* check gcd == 1 */
    {
        unsigned long is_one;
        rc = bigint_is_one(&is_one, &old_r);
        if (rc) goto inv_cleanup;
        if (!is_one) {
            rc = 4; /* no inverse exists */
            goto inv_cleanup;
        }
    }

    rc = bigint_mod(out, &old_s, mod);

inv_cleanup:
    bigint_destroy(&old_r);
    bigint_destroy(&r);
    bigint_destroy(&old_s);
    bigint_destroy(&s);
    bigint_destroy(&q);
    bigint_destroy(&tmp);
    bigint_destroy(&prod);
    bigint_destroy(&new_r);
    bigint_destroy(&new_s);
    return rc;
}

unsigned long bigint_gcd(bigint *out, bigint *a, bigint *b) {
    /* Euclidean algorithm */
    bigint x, y, tmp_r, tmp_q;
    unsigned long is_z;
    unsigned long rc;

    if (!out) return 1;
    if (!a) return 2;
    if (!b) return 3;


    memset(&x, 0, sizeof(bigint));
    memset(&y, 0, sizeof(bigint));
    memset(&tmp_r, 0, sizeof(bigint));
    memset(&tmp_q, 0, sizeof(bigint));

    rc = bigint_create(&x, 1);
    if (rc) goto gcd_cleanup;
    rc = bi_copy(&x, a);
    if (rc) goto gcd_cleanup;

    rc = bigint_create(&y, 1);
    if (rc) goto gcd_cleanup;
    rc = bi_copy(&y, b);
    if (rc) goto gcd_cleanup;

    rc = bigint_create(&tmp_r, 1);
    if (rc) goto gcd_cleanup;
    rc = bigint_create(&tmp_q, 1);
    if (rc) goto gcd_cleanup;

    for (;;) {
        rc = bigint_is_zero(&is_z, &y);
        if (rc) goto gcd_cleanup;
        if (is_z) break;

        rc = bigint_div(&tmp_q, &tmp_r, &x, &y);
        if (rc) goto gcd_cleanup;

        rc = bi_copy(&x, &y);
        if (rc) goto gcd_cleanup;
        rc = bi_copy(&y, &tmp_r);
        if (rc) goto gcd_cleanup;
    }

    rc = bi_copy(out, &x);

gcd_cleanup:
    bigint_destroy(&x);
    bigint_destroy(&y);
    bigint_destroy(&tmp_r);
    bigint_destroy(&tmp_q);
    return rc;
}

unsigned long bigint_compare(long *result, bigint *a, bigint *b) {
    u64 i;

    if (!result) return 1;
    if (!a) return 2;
    if (!b) return 3;

    if (a->len != b->len) {
        *result = a->len > b->len ? 1 : -1;
        return 0;
    }

    for (i = a->len; i > 0; i--) {
        if (a->digits[i - 1] != b->digits[i - 1]) {
            *result = a->digits[i - 1] > b->digits[i - 1] ? 1 : -1;
            return 0;
        }
    }

    *result = 0;
    return 0;
}

unsigned long bigint_shl(bigint *out, bigint *a, u64 bits) {
    u64 limb_shift;
    u64 bit_shift;
    u64 new_len;
    u64 i;
    unsigned long rc;

    if (!out) return 1;
    if (!a) return 2;


    if (bits == 0) {
        return bi_copy(out, a);
    }

    limb_shift = bits / 32;
    bit_shift = bits % 32;

    new_len = a->len + limb_shift + 1;
    rc = bi_ensure_cap(out, new_len);
    if (rc) return 3;

    memset(out->digits, 0, (size_t)(new_len * sizeof(u32)));
    out->len = new_len;

    for (i = 0; i < a->len; i++) {
        u64 val = (u64)a->digits[i] << bit_shift;
        out->digits[i + limb_shift] |= (u32)(val & 0xFFFFFFFFu);
        if (i + limb_shift + 1 < new_len) {
            out->digits[i + limb_shift + 1] |= (u32)(val >> 32);
        }
    }

    bi_trim(out);
    return 0;
}

unsigned long bigint_shr(bigint *out, bigint *a, u64 bits) {
    u64 limb_shift;
    u64 bit_shift;
    u64 i;
    unsigned long rc;

    if (!out) return 1;
    if (!a) return 2;


    if (bits == 0) {
        return bi_copy(out, a);
    }

    limb_shift = bits / 32;
    bit_shift = bits % 32;

    if (limb_shift >= a->len) {
        rc = bi_ensure_cap(out, 1);
        if (rc) return 3;
        out->digits[0] = 0;
        out->len = 1;
        return 0;
    }

    {
        u64 new_len = a->len - limb_shift;
        rc = bi_ensure_cap(out, new_len);
        if (rc) return 3;

        for (i = 0; i < new_len; i++) {
            out->digits[i] = a->digits[i + limb_shift] >> bit_shift;
            if (bit_shift > 0 && i + limb_shift + 1 < a->len) {
                out->digits[i] |= a->digits[i + limb_shift + 1] << (32 - bit_shift);
            }
        }

        out->len = new_len;
        bi_trim(out);
    }

    return 0;
}

unsigned long bigint_is_zero(unsigned long *result, bigint *val) {
    u64 i;

    if (!result) return 1;
    if (!val) return 2;

    *result = 1;
    for (i = 0; i < val->len; i++) {
        if (val->digits[i] != 0) {
            *result = 0;
            return 0;
        }
    }
    return 0;
}

unsigned long bigint_is_one(unsigned long *result, bigint *val) {
    u64 i;

    if (!result) return 1;
    if (!val) return 2;

    if (val->digits[0] != 1) {
        *result = 0;
        return 0;
    }

    *result = 1;
    for (i = 1; i < val->len; i++) {
        if (val->digits[i] != 0) {
            *result = 0;
            return 0;
        }
    }
    return 0;
}

unsigned long bigint_bitlen(u64 *out, bigint *val) {
    u64 top_limb_bits;
    u32 top;

    if (!out) return 1;
    if (!val) return 2;

    if (val->len == 1 && val->digits[0] == 0) {
        *out = 0;
        return 0;
    }

    top = val->digits[val->len - 1];
    top_limb_bits = 0;
    while (top) {
        top_limb_bits++;
        top >>= 1;
    }

    *out = (val->len - 1) * 32 + top_limb_bits;
    return 0;
}

unsigned long bigint_destroy(bigint *val) {
    if (!val) return 1;
    if (val->digits) {
        /* zero memory before freeing for security */
        memset(val->digits, 0, (size_t)(val->cap * sizeof(u32)));
        free(val->digits);
    }
    val->digits = NULL;
    val->len = 0;
    val->cap = 0;
    return 0;
}
