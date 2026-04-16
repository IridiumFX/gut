#ifndef APENNINES_T2_BIGINT_H
#define APENNINES_T2_BIGINT_H


#include "apennines/types.h"

typedef struct {
    u32 *digits;    /* little-endian array of 32-bit limbs */
    u64 len;        /* number of used limbs */
    u64 cap;        /* allocated limbs */
} bigint;

unsigned long bigint_create(bigint *out, u64 digit_count);
unsigned long bigint_from_u64(bigint *out, u64 val);
unsigned long bigint_from_bytes(bigint *out, u8 *data, u64 len);
unsigned long bigint_to_bytes(u8 *out, u64 *out_len, u64 out_cap, bigint *val);
unsigned long bigint_add(bigint *out, bigint *a, bigint *b);
unsigned long bigint_sub(bigint *out, bigint *a, bigint *b);
unsigned long bigint_mul(bigint *out, bigint *a, bigint *b);
unsigned long bigint_div(bigint *quot, bigint *rem, bigint *a, bigint *b);
unsigned long bigint_mod(bigint *out, bigint *a, bigint *b);
unsigned long bigint_modpow(bigint *out, bigint *base, bigint *exp, bigint *mod);
unsigned long bigint_modinv(bigint *out, bigint *a, bigint *mod);
unsigned long bigint_gcd(bigint *out, bigint *a, bigint *b);
unsigned long bigint_compare(long *result, bigint *a, bigint *b);
unsigned long bigint_shl(bigint *out, bigint *a, u64 bits);
unsigned long bigint_shr(bigint *out, bigint *a, u64 bits);
unsigned long bigint_is_zero(unsigned long *result, bigint *val);
unsigned long bigint_is_one(unsigned long *result, bigint *val);
unsigned long bigint_bitlen(u64 *out, bigint *val);
unsigned long bigint_destroy(bigint *val);

#endif /* APENNINES_T2_BIGINT_H */
