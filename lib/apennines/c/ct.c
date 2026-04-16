#include "apennines/ct.h"

unsigned long ct_compare(unsigned long *result, const u8 *a, const u8 *b, u64 len) {
    u64 i;
    volatile u8 diff;

    if (!result) return 1;
    if (len > 0 && !a) return 2;
    if (len > 0 && !b) return 3;

    diff = 0;
    for (i = 0; i < len; i++) {
        diff |= a[i] ^ b[i];
    }

    /* Map any non-zero diff to 1 */
    *result = (diff != 0) ? 1UL : 0UL;
    return 0;
}

unsigned long ct_select(u8 *out, const u8 *a, const u8 *b, u64 len, unsigned long selector) {
    u64 i;
    u8 mask;

    if (!out) return 1;
    if (len > 0 && !a) return 2;
    if (len > 0 && !b) return 3;

    /* mask = 0x00 if selector==0 (pick a), 0xFF if selector!=0 (pick b) */
    mask = (u8)(-(unsigned long)(selector != 0));

    for (i = 0; i < len; i++) {
        out[i] = (u8)((a[i] & ~mask) | (b[i] & mask));
    }

    return 0;
}

unsigned long ct_is_zero(unsigned long *result, const u8 *data, u64 len) {
    u64 i;
    volatile u8 acc;

    if (!result) return 1;
    if (len > 0 && !data) return 2;

    acc = 0;
    for (i = 0; i < len; i++) {
        acc |= data[i];
    }

    /* result=1 if all zero, 0 otherwise */
    *result = (acc == 0) ? 1UL : 0UL;
    return 0;
}

unsigned long ct_copy_if(u8 *dst, const u8 *src, u64 len, unsigned long condition) {
    u64 i;
    u8 mask;

    if (!dst) return 1;
    if (len > 0 && !src) return 2;

    /* mask = 0xFF if condition!=0, 0x00 otherwise */
    mask = (u8)(-(unsigned long)(condition != 0));

    for (i = 0; i < len; i++) {
        dst[i] = (u8)((dst[i] & ~mask) | (src[i] & mask));
    }

    return 0;
}
