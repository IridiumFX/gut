#include "apennines/base.h"
#include "apennines/buf.h"
#include <string.h>

/* ---- Base16 (Hex) ---- */

static const char hex_chars[] = "0123456789abcdef";

static int hex_val(u8 c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

unsigned long base16_encode(buf *out, u8 *data, u64 len) {
    u64 i;
    unsigned long rc;

    if (!out) return 1;
    if (len > 0 && !data) return 2;

    for (i = 0; i < len; i++) {
        u8 hi = (u8)hex_chars[(data[i] >> 4) & 0x0F];
        u8 lo = (u8)hex_chars[data[i] & 0x0F];

        rc = buf_append_byte(out, hi);
        if (rc) return 3;
        rc = buf_append_byte(out, lo);
        if (rc) return 4;
    }

    return 0;
}

unsigned long base16_decode(buf *out, u8 *data, u64 len) {
    u64 i;
    unsigned long rc;

    if (!out) return 1;
    if (len > 0 && !data) return 2;
    if (len % 2 != 0) return 3;

    for (i = 0; i < len; i += 2) {
        int hi = hex_val(data[i]);
        int lo = hex_val(data[i + 1]);

        if (hi < 0 || lo < 0) return 4;

        {
            u8 byte = (u8)((hi << 4) | lo);
            rc = buf_append_byte(out, byte);
            if (rc) return 5;
        }
    }

    return 0;
}

/* ---- Base32 (RFC 4648) ---- */

static const char b32_alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

static int b32_val(u8 c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a';
    if (c >= '2' && c <= '7') return c - '2' + 26;
    return -1;
}

unsigned long base32_encode(buf *out, u8 *data, u64 len) {
    u64 i;
    unsigned long rc;

    if (!out) return 1;
    if (len > 0 && !data) return 2;

    i = 0;
    while (i < len) {
        u64 remaining = len - i;
        u32 block = 0;
        int bits = 0;
        int pad = 0;
        int j;

        /* Gather up to 5 bytes into a 40-bit block */
        if (remaining >= 5) {
            block = ((u32)data[i] << 24) | ((u32)data[i+1] << 16) |
                    ((u32)data[i+2] << 8) | (u32)data[i+3];
            bits = 32;
            /* 5th byte handled separately since block is 32 bits */
        } else {
            /* Handle partial blocks */
        }

        /* Encode in groups of 5 input bytes -> 8 output chars */
        if (remaining >= 5) {
            u8 b0 = data[i], b1 = data[i+1], b2 = data[i+2], b3 = data[i+3], b4 = data[i+4];
            u8 out_chars[8];

            out_chars[0] = (u8)b32_alphabet[b0 >> 3];
            out_chars[1] = (u8)b32_alphabet[((b0 & 0x07) << 2) | (b1 >> 6)];
            out_chars[2] = (u8)b32_alphabet[(b1 >> 1) & 0x1F];
            out_chars[3] = (u8)b32_alphabet[((b1 & 0x01) << 4) | (b2 >> 4)];
            out_chars[4] = (u8)b32_alphabet[((b2 & 0x0F) << 1) | (b3 >> 7)];
            out_chars[5] = (u8)b32_alphabet[(b3 >> 2) & 0x1F];
            out_chars[6] = (u8)b32_alphabet[((b3 & 0x03) << 3) | (b4 >> 5)];
            out_chars[7] = (u8)b32_alphabet[b4 & 0x1F];

            rc = buf_append(out, out_chars, 8);
            if (rc) return 3;
            i += 5;
        } else {
            /* Partial block */
            u8 out_chars[8];
            int n_chars;

            memset(out_chars, '=', 8);

            switch (remaining) {
            case 1:
                out_chars[0] = (u8)b32_alphabet[data[i] >> 3];
                out_chars[1] = (u8)b32_alphabet[(data[i] & 0x07) << 2];
                n_chars = 8;
                break;
            case 2:
                out_chars[0] = (u8)b32_alphabet[data[i] >> 3];
                out_chars[1] = (u8)b32_alphabet[((data[i] & 0x07) << 2) | (data[i+1] >> 6)];
                out_chars[2] = (u8)b32_alphabet[(data[i+1] >> 1) & 0x1F];
                out_chars[3] = (u8)b32_alphabet[(data[i+1] & 0x01) << 4];
                n_chars = 8;
                break;
            case 3:
                out_chars[0] = (u8)b32_alphabet[data[i] >> 3];
                out_chars[1] = (u8)b32_alphabet[((data[i] & 0x07) << 2) | (data[i+1] >> 6)];
                out_chars[2] = (u8)b32_alphabet[(data[i+1] >> 1) & 0x1F];
                out_chars[3] = (u8)b32_alphabet[((data[i+1] & 0x01) << 4) | (data[i+2] >> 4)];
                out_chars[4] = (u8)b32_alphabet[(data[i+2] & 0x0F) << 1];
                n_chars = 8;
                break;
            case 4:
                out_chars[0] = (u8)b32_alphabet[data[i] >> 3];
                out_chars[1] = (u8)b32_alphabet[((data[i] & 0x07) << 2) | (data[i+1] >> 6)];
                out_chars[2] = (u8)b32_alphabet[(data[i+1] >> 1) & 0x1F];
                out_chars[3] = (u8)b32_alphabet[((data[i+1] & 0x01) << 4) | (data[i+2] >> 4)];
                out_chars[4] = (u8)b32_alphabet[((data[i+2] & 0x0F) << 1) | (data[i+3] >> 7)];
                out_chars[5] = (u8)b32_alphabet[(data[i+3] >> 2) & 0x1F];
                out_chars[6] = (u8)b32_alphabet[(data[i+3] & 0x03) << 3];
                n_chars = 8;
                break;
            default:
                n_chars = 0;
                break;
            }

            if (n_chars > 0) {
                rc = buf_append(out, out_chars, (u64)n_chars);
                if (rc) return 3;
            }
            i += remaining;
        }
    }

    return 0;
}

unsigned long base32_decode(buf *out, u8 *data, u64 len) {
    u64 i;
    unsigned long rc;
    u64 data_len;

    if (!out) return 1;
    if (len > 0 && !data) return 2;

    /* Strip trailing padding */
    data_len = len;
    while (data_len > 0 && data[data_len - 1] == '=') {
        data_len--;
    }

    /* base32 blocks are 8 chars; padded input length must be multiple of 8 */
    if (len % 8 != 0 && len > 0) return 3;

    i = 0;
    while (i < data_len) {
        u64 remaining = data_len - i;
        int vals[8];
        int j;
        int n_vals;
        u8 out_bytes[5];
        int n_bytes;

        memset(vals, 0, sizeof(vals));
        n_vals = (remaining >= 8) ? 8 : (int)remaining;

        for (j = 0; j < n_vals; j++) {
            vals[j] = b32_val(data[i + j]);
            if (vals[j] < 0) return 4;
        }

        /* Determine number of output bytes from number of significant chars */
        switch (n_vals) {
        case 8: n_bytes = 5; break;
        case 7: n_bytes = 4; break;
        case 5: n_bytes = 3; break;
        case 4: n_bytes = 2; break;
        case 2: n_bytes = 1; break;
        default: return 5; /* invalid grouping */
        }

        out_bytes[0] = (u8)((vals[0] << 3) | (vals[1] >> 2));
        if (n_bytes >= 2)
            out_bytes[1] = (u8)((vals[1] << 6) | (vals[2] << 1) | (vals[3] >> 4));
        if (n_bytes >= 3)
            out_bytes[2] = (u8)((vals[3] << 4) | (vals[4] >> 1));
        if (n_bytes >= 4)
            out_bytes[3] = (u8)((vals[4] << 7) | (vals[5] << 2) | (vals[6] >> 3));
        if (n_bytes >= 5)
            out_bytes[4] = (u8)((vals[6] << 5) | vals[7]);

        rc = buf_append(out, out_bytes, (u64)n_bytes);
        if (rc) return 6;

        i += (u64)n_vals;
    }

    return 0;
}

/* ---- Base64 (RFC 4648) ---- */

static const char b64_alphabet[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static int b64_val(u8 c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

unsigned long base64_encode(buf *out, u8 *data, u64 len) {
    u64 i;
    unsigned long rc;

    if (!out) return 1;
    if (len > 0 && !data) return 2;

    i = 0;
    while (i + 3 <= len) {
        u8 chars[4];
        u32 triple = ((u32)data[i] << 16) | ((u32)data[i+1] << 8) | (u32)data[i+2];

        chars[0] = (u8)b64_alphabet[(triple >> 18) & 0x3F];
        chars[1] = (u8)b64_alphabet[(triple >> 12) & 0x3F];
        chars[2] = (u8)b64_alphabet[(triple >> 6) & 0x3F];
        chars[3] = (u8)b64_alphabet[triple & 0x3F];

        rc = buf_append(out, chars, 4);
        if (rc) return 3;
        i += 3;
    }

    /* Handle remaining 1 or 2 bytes */
    if (i + 2 == len) {
        u8 chars[4];
        u32 pair = ((u32)data[i] << 8) | (u32)data[i+1];

        chars[0] = (u8)b64_alphabet[(pair >> 10) & 0x3F];
        chars[1] = (u8)b64_alphabet[(pair >> 4) & 0x3F];
        chars[2] = (u8)b64_alphabet[(pair << 2) & 0x3F];
        chars[3] = '=';

        rc = buf_append(out, chars, 4);
        if (rc) return 3;
    } else if (i + 1 == len) {
        u8 chars[4];

        chars[0] = (u8)b64_alphabet[(data[i] >> 2) & 0x3F];
        chars[1] = (u8)b64_alphabet[(data[i] << 4) & 0x3F];
        chars[2] = '=';
        chars[3] = '=';

        rc = buf_append(out, chars, 4);
        if (rc) return 3;
    }

    return 0;
}

unsigned long base64_decode(buf *out, u8 *data, u64 len) {
    u64 i;
    unsigned long rc;
    u64 data_len;

    if (!out) return 1;
    if (len > 0 && !data) return 2;

    /* Strip trailing padding */
    data_len = len;
    while (data_len > 0 && data[data_len - 1] == '=') {
        data_len--;
    }

    i = 0;
    while (i + 4 <= data_len) {
        int a = b64_val(data[i]);
        int b = b64_val(data[i+1]);
        int c = b64_val(data[i+2]);
        int d = b64_val(data[i+3]);
        u8 out_bytes[3];

        if (a < 0 || b < 0 || c < 0 || d < 0) return 3;

        out_bytes[0] = (u8)((a << 2) | (b >> 4));
        out_bytes[1] = (u8)((b << 4) | (c >> 2));
        out_bytes[2] = (u8)((c << 6) | d);

        rc = buf_append(out, out_bytes, 3);
        if (rc) return 4;
        i += 4;
    }

    /* Handle remaining 2 or 3 chars */
    if (data_len - i == 3) {
        int a = b64_val(data[i]);
        int b = b64_val(data[i+1]);
        int c = b64_val(data[i+2]);
        u8 out_bytes[2];

        if (a < 0 || b < 0 || c < 0) return 3;

        out_bytes[0] = (u8)((a << 2) | (b >> 4));
        out_bytes[1] = (u8)((b << 4) | (c >> 2));

        rc = buf_append(out, out_bytes, 2);
        if (rc) return 4;
    } else if (data_len - i == 2) {
        int a = b64_val(data[i]);
        int b = b64_val(data[i+1]);
        u8 out_bytes[1];

        if (a < 0 || b < 0) return 3;

        out_bytes[0] = (u8)((a << 2) | (b >> 4));

        rc = buf_append(out, out_bytes, 1);
        if (rc) return 4;
    } else if (data_len - i != 0) {
        return 5; /* invalid length */
    }

    return 0;
}

/* ---- Base64url (RFC 4648 section 5) ---- */

static const char b64url_alphabet[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

static int b64url_val(u8 c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '-') return 62;
    if (c == '_') return 63;
    return -1;
}

unsigned long base64url_encode(buf *out, u8 *data, u64 len) {
    u64 i;
    unsigned long rc;

    if (!out) return 1;
    if (len > 0 && !data) return 2;

    i = 0;
    while (i + 3 <= len) {
        u8 chars[4];
        u32 triple = ((u32)data[i] << 16) | ((u32)data[i+1] << 8) | (u32)data[i+2];

        chars[0] = (u8)b64url_alphabet[(triple >> 18) & 0x3F];
        chars[1] = (u8)b64url_alphabet[(triple >> 12) & 0x3F];
        chars[2] = (u8)b64url_alphabet[(triple >> 6) & 0x3F];
        chars[3] = (u8)b64url_alphabet[triple & 0x3F];

        rc = buf_append(out, chars, 4);
        if (rc) return 3;
        i += 3;
    }

    /* Handle remaining 1 or 2 bytes -- no padding for base64url */
    if (i + 2 == len) {
        u8 chars[3];
        u32 pair = ((u32)data[i] << 8) | (u32)data[i+1];

        chars[0] = (u8)b64url_alphabet[(pair >> 10) & 0x3F];
        chars[1] = (u8)b64url_alphabet[(pair >> 4) & 0x3F];
        chars[2] = (u8)b64url_alphabet[(pair << 2) & 0x3F];

        rc = buf_append(out, chars, 3);
        if (rc) return 3;
    } else if (i + 1 == len) {
        u8 chars[2];

        chars[0] = (u8)b64url_alphabet[(data[i] >> 2) & 0x3F];
        chars[1] = (u8)b64url_alphabet[(data[i] << 4) & 0x3F];

        rc = buf_append(out, chars, 2);
        if (rc) return 3;
    }

    return 0;
}

unsigned long base64url_decode(buf *out, u8 *data, u64 len) {
    u64 i;
    unsigned long rc;
    u64 data_len;

    if (!out) return 1;
    if (len > 0 && !data) return 2;

    /* Strip trailing padding if present (should not be, but be lenient) */
    data_len = len;
    while (data_len > 0 && data[data_len - 1] == '=') {
        data_len--;
    }

    i = 0;
    while (i + 4 <= data_len) {
        int a = b64url_val(data[i]);
        int b = b64url_val(data[i+1]);
        int c = b64url_val(data[i+2]);
        int d = b64url_val(data[i+3]);
        u8 out_bytes[3];

        if (a < 0 || b < 0 || c < 0 || d < 0) return 3;

        out_bytes[0] = (u8)((a << 2) | (b >> 4));
        out_bytes[1] = (u8)((b << 4) | (c >> 2));
        out_bytes[2] = (u8)((c << 6) | d);

        rc = buf_append(out, out_bytes, 3);
        if (rc) return 4;
        i += 4;
    }

    /* Handle remaining 2 or 3 chars */
    if (data_len - i == 3) {
        int a = b64url_val(data[i]);
        int b = b64url_val(data[i+1]);
        int c = b64url_val(data[i+2]);
        u8 out_bytes[2];

        if (a < 0 || b < 0 || c < 0) return 3;

        out_bytes[0] = (u8)((a << 2) | (b >> 4));
        out_bytes[1] = (u8)((b << 4) | (c >> 2));

        rc = buf_append(out, out_bytes, 2);
        if (rc) return 4;
    } else if (data_len - i == 2) {
        int a = b64url_val(data[i]);
        int b = b64url_val(data[i+1]);
        u8 out_bytes[1];

        if (a < 0 || b < 0) return 3;

        out_bytes[0] = (u8)((a << 2) | (b >> 4));

        rc = buf_append(out, out_bytes, 1);
        if (rc) return 4;
    } else if (data_len - i != 0) {
        return 5; /* invalid length */
    }

    return 0;
}
