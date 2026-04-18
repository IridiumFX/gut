#include "gut/oid.h"
#include <string.h>

static const char hex_chars[] = "0123456789abcdef";

static int hex_val(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return 10 + (c - 'a');
    if (c >= 'A' && c <= 'F') return 10 + (c - 'A');
    return -1;
}

unsigned long oid_to_hex(char *out, gut_oid *oid) {
    u32 i;
    if (!out) return __LINE__;
    if (!oid) return __LINE__;
    for (i = 0; i < GUT_OID_RAW_SIZE; i++) {
        out[i * 2]     = hex_chars[(oid->bytes[i] >> 4) & 0x0F];
        out[i * 2 + 1] = hex_chars[oid->bytes[i] & 0x0F];
    }
    out[GUT_OID_HEX_SIZE] = '\0';
    return 0;
}

unsigned long oid_from_hex(gut_oid *out, const char *hex) {
    u32 i;
    if (!out) return __LINE__;
    if (!hex) return __LINE__;
    for (i = 0; i < GUT_OID_RAW_SIZE; i++) {
        int hi = hex_val(hex[i * 2]);
        int lo = hex_val(hex[i * 2 + 1]);
        if (hi < 0 || lo < 0) return __LINE__;
        out->bytes[i] = (u8)((hi << 4) | lo);
    }
    return 0;
}

/* Width-aware variants for SHA-256 callers. n = hex chars (40 or 64). */
unsigned long oid_to_hex_n(char *out, gut_oid *oid, unsigned n) {
    unsigned i;
    if (!out || !oid) return __LINE__;
    if (n != 40 && n != 64) return __LINE__;
    for (i = 0; i < n / 2; i++) {
        out[i * 2]     = hex_chars[(oid->bytes[i] >> 4) & 0x0F];
        out[i * 2 + 1] = hex_chars[oid->bytes[i] & 0x0F];
    }
    out[n] = '\0';
    return 0;
}

unsigned long oid_from_hex_n(gut_oid *out, const char *hex, unsigned n) {
    unsigned i;
    if (!out || !hex) return __LINE__;
    if (n != 40 && n != 64) return __LINE__;
    /* Zero the tail so a SHA-1 OID read via this variant stays comparable. */
    memset(out->bytes, 0, sizeof(out->bytes));
    for (i = 0; i < n / 2; i++) {
        int hi = hex_val(hex[i * 2]);
        int lo = hex_val(hex[i * 2 + 1]);
        if (hi < 0 || lo < 0) return __LINE__;
        out->bytes[i] = (u8)((hi << 4) | lo);
    }
    return 0;
}

unsigned long oid_compare(long *result, gut_oid *a, gut_oid *b) {
    if (!result) return __LINE__;
    if (!a) return __LINE__;
    if (!b) return __LINE__;
    *result = (long)memcmp(a->bytes, b->bytes, GUT_OID_RAW_SIZE);
    return 0;
}

unsigned long oid_is_zero(unsigned long *result, gut_oid *oid) {
    u32 i;
    if (!result) return __LINE__;
    if (!oid) return __LINE__;
    *result = 1;
    for (i = 0; i < GUT_OID_RAW_SIZE; i++) {
        if (oid->bytes[i] != 0) {
            *result = 0;
            return 0;
        }
    }
    return 0;
}

unsigned long oid_hash(gut_oid *out, const u8 *data, u64 len) {
    if (!out) return __LINE__;
    return sha1_digest(out->bytes, data, len);
}

unsigned long oid_path_prefix(char *out2, gut_oid *oid) {
    if (!out2) return __LINE__;
    if (!oid) return __LINE__;
    out2[0] = hex_chars[(oid->bytes[0] >> 4) & 0x0F];
    out2[1] = hex_chars[oid->bytes[0] & 0x0F];
    out2[2] = '\0';
    return 0;
}

unsigned long oid_path_suffix(char *out38, gut_oid *oid) {
    u32 i;
    if (!out38) return __LINE__;
    if (!oid) return __LINE__;
    for (i = 1; i < GUT_OID_RAW_SIZE; i++) {
        out38[(i - 1) * 2]     = hex_chars[(oid->bytes[i] >> 4) & 0x0F];
        out38[(i - 1) * 2 + 1] = hex_chars[oid->bytes[i] & 0x0F];
    }
    out38[38] = '\0';
    return 0;
}
