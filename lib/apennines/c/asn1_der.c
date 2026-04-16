#include "apennines/asn1_der.h"
#include <string.h>

/* ================================================================
 *  Internal helpers
 * ================================================================ */

/* Encode DER length into buffer. Returns 0 on success, non-zero on buf fail. */
static unsigned long encode_length(buf *out, u64 length) {
    unsigned long rc;

    if (length < 128) {
        rc = buf_append_byte(out, (u8)length);
        if (rc) return rc;
    } else {
        /* Count how many bytes we need for the length */
        u8 len_bytes[8];
        int n = 0;
        u64 tmp = length;

        while (tmp > 0) {
            len_bytes[n++] = (u8)(tmp & 0xFF);
            tmp >>= 8;
        }

        /* Write 0x80 | n */
        rc = buf_append_byte(out, (u8)(0x80 | n));
        if (rc) return rc;

        /* Write length bytes big-endian */
        {
            int i;
            for (i = n - 1; i >= 0; i--) {
                rc = buf_append_byte(out, len_bytes[i]);
                if (rc) return rc;
            }
        }
    }

    return 0;
}

/* Decode DER length from data. Sets *out_len and *bytes_consumed.
 * Returns 0 on success, 1 on invalid encoding. */
static unsigned long decode_length(u64 *out_len, u64 *bytes_consumed,
                                   const u8 *data, u64 avail) {
    if (avail < 1) return 1;

    if (data[0] < 128) {
        *out_len = data[0];
        *bytes_consumed = 1;
        return 0;
    }

    if (data[0] == 0x80) return 1; /* indefinite form not allowed in DER */

    {
        int n = data[0] & 0x7F;
        u64 val = 0;
        int i;

        if ((u64)n + 1 > avail) return 1;
        if (n > 8) return 1; /* too large */

        for (i = 0; i < n; i++) {
            val = (val << 8) | data[1 + i];
        }

        /* DER: reject non-minimal length encoding */
        if (n > 1 && data[1] == 0) return 1;
        if (n == 1 && val < 128) return 1;

        *out_len = val;
        *bytes_consumed = (u64)(1 + n);
        return 0;
    }
}

/* ================================================================
 *  asn1_der_encode
 * ================================================================ */

unsigned long asn1_der_encode(buf *out, u8 tag,
                              const u8 *value, u64 value_len) {
    unsigned long rc;

    if (!out) return 1;
    if (value_len > 0 && !value) return 2;

    rc = buf_append_byte(out, tag);
    if (rc) return 3;

    rc = encode_length(out, value_len);
    if (rc) return 3;

    if (value_len > 0) {
        rc = buf_append(out, (u8 *)value, value_len);
        if (rc) return 3;
    }

    return 0;
}

/* ================================================================
 *  asn1_der_encode_integer
 * ================================================================ */

unsigned long asn1_der_encode_integer(buf *out,
                                      const u8 *value, u64 value_len) {
    unsigned long rc;
    const u8 *v;
    u64 vlen;

    if (!out) return 1;
    if (!value) return 2;

    v = value;
    vlen = value_len;

    if (vlen == 0) {
        /* Encode zero */
        u8 zero = 0;
        return asn1_der_encode(out, ASN1_TAG_INTEGER, &zero, 1);
    }

    /* The caller provides a big-endian two's complement integer.
     * DER rules:
     *   - Strip leading 0x00 bytes, BUT if the remaining first byte has bit 7
     *     set, keep one 0x00 (to indicate positive).
     *   - Strip leading 0xFF bytes, BUT if the remaining first byte has bit 7
     *     clear, keep one 0xFF (to indicate negative).
     *   - At least one byte must remain.
     */

    if (v[0] == 0x00) {
        /* Positive number with possible leading zeros */
        while (vlen > 1 && v[0] == 0x00 && !(v[1] & 0x80)) {
            v++;
            vlen--;
        }
    } else if (v[0] == 0xFF) {
        /* Negative number with possible leading 0xFF bytes */
        while (vlen > 1 && v[0] == 0xFF && (v[1] & 0x80)) {
            v++;
            vlen--;
        }
    }

    rc = buf_append_byte(out, ASN1_TAG_INTEGER);
    if (rc) return 3;

    rc = encode_length(out, vlen);
    if (rc) return 3;

    rc = buf_append(out, (u8 *)v, vlen);
    if (rc) return 3;

    return 0;
}

/* ================================================================
 *  asn1_der_encode_boolean
 * ================================================================ */

unsigned long asn1_der_encode_boolean(buf *out, unsigned long value) {
    u8 v;

    if (!out) return 1;

    v = value ? 0xFF : 0x00;
    {
        unsigned long rc = asn1_der_encode(out, ASN1_TAG_BOOLEAN, &v, 1);
        if (rc) return 2;
    }

    return 0;
}

/* ================================================================
 *  asn1_der_encode_null
 * ================================================================ */

unsigned long asn1_der_encode_null(buf *out) {
    unsigned long rc;

    if (!out) return 1;

    rc = asn1_der_encode(out, ASN1_TAG_NULL, NULL, 0);
    if (rc) return 2;

    return 0;
}

/* ================================================================
 *  asn1_der_encode_oid
 * ================================================================ */

unsigned long asn1_der_encode_oid(buf *out, const u32 *components, u64 count) {
    unsigned long rc;
    buf oid_buf;
    u64 i;
    u8 *oid_data;
    u64 oid_len;

    if (!out) return 1;
    if (!components) return 2;
    if (count < 2) return 3;

    memset(&oid_buf, 0, sizeof(oid_buf));
    rc = buf_create(&oid_buf, 32);
    if (rc) return 4;

    /* First two components: 40 * first + second */
    {
        u32 first_byte = 40 * components[0] + components[1];
        /* Encode as base-128 */
        if (first_byte < 128) {
            rc = buf_append_byte(&oid_buf, (u8)first_byte);
        } else {
            /* Base-128 encode */
            u8 base128[5];
            int n = 0;
            u32 tmp = first_byte;

            while (tmp > 0) {
                base128[n++] = (u8)(tmp & 0x7F);
                tmp >>= 7;
            }
            {
                int j;
                for (j = n - 1; j >= 0; j--) {
                    u8 byte = base128[j];
                    if (j > 0) byte |= 0x80;
                    rc = buf_append_byte(&oid_buf, byte);
                    if (rc) { buf_destroy(&oid_buf); return 4; }
                }
            }
        }
        if (rc) { buf_destroy(&oid_buf); return 4; }
    }

    /* Remaining components in base-128 */
    for (i = 2; i < count; i++) {
        u32 val = components[i];

        if (val < 128) {
            rc = buf_append_byte(&oid_buf, (u8)val);
            if (rc) { buf_destroy(&oid_buf); return 4; }
        } else {
            u8 base128[5];
            int n = 0;
            u32 tmp = val;

            while (tmp > 0) {
                base128[n++] = (u8)(tmp & 0x7F);
                tmp >>= 7;
            }
            {
                int j;
                for (j = n - 1; j >= 0; j--) {
                    u8 byte = base128[j];
                    if (j > 0) byte |= 0x80;
                    rc = buf_append_byte(&oid_buf, byte);
                    if (rc) { buf_destroy(&oid_buf); return 4; }
                }
            }
        }
    }

    rc = buf_ptr(&oid_data, &oid_buf);
    if (rc) { buf_destroy(&oid_buf); return 4; }
    rc = buf_len(&oid_len, &oid_buf);
    if (rc) { buf_destroy(&oid_buf); return 4; }

    rc = asn1_der_encode(out, ASN1_TAG_OID, oid_data, oid_len);
    buf_destroy(&oid_buf);
    if (rc) return 4;

    return 0;
}

/* ================================================================
 *  asn1_der_encode_sequence
 * ================================================================ */

unsigned long asn1_der_encode_sequence(buf *out, const u8 *content,
                                       u64 content_len) {
    if (!out) return 1;
    if (content_len > 0 && !content) return 2;

    {
        unsigned long rc = asn1_der_encode(out, ASN1_TAG_SEQUENCE,
                                           content, content_len);
        if (rc) return 3;
    }

    return 0;
}

/* ================================================================
 *  asn1_der_decode
 * ================================================================ */

unsigned long asn1_der_decode(asn1_tlv *out, const u8 *data, u64 len) {
    u64 value_len;
    u64 len_bytes;
    unsigned long rc;

    if (!out) return 1;
    if (!data) return 2;
    if (len < 2) return 3;

    memset(out, 0, sizeof(*out));

    out->tag = data[0];
    out->raw = data;

    rc = decode_length(&value_len, &len_bytes, data + 1, len - 1);
    if (rc) return 4;

    {
        u64 header_len = 1 + len_bytes;
        if (header_len + value_len > len) return 5;

        out->value = data + header_len;
        out->value_len = value_len;
        out->raw_len = header_len + value_len;
    }

    return 0;
}

/* ================================================================
 *  asn1_der_decode_integer
 * ================================================================ */

unsigned long asn1_der_decode_integer(i64 *out, const asn1_tlv *tlv) {
    u64 i;
    i64 val;

    if (!out) return 1;
    if (!tlv) return 2;
    if (tlv->tag != ASN1_TAG_INTEGER) return 3;
    if (tlv->value_len == 0 || tlv->value_len > 8) return 4;

    /* Sign-extend the first byte */
    val = (i64)((i8)tlv->value[0]);

    for (i = 1; i < tlv->value_len; i++) {
        val = (val << 8) | tlv->value[i];
    }

    *out = val;
    return 0;
}

/* ================================================================
 *  asn1_der_decode_boolean
 * ================================================================ */

unsigned long asn1_der_decode_boolean(unsigned long *out,
                                      const asn1_tlv *tlv) {
    if (!out) return 1;
    if (!tlv) return 2;
    if (tlv->tag != ASN1_TAG_BOOLEAN) return 3;
    if (tlv->value_len != 1) return 4;

    /* DER: only 0x00 and 0xFF are valid */
    if (tlv->value[0] != 0x00 && tlv->value[0] != 0xFF) return 4;

    *out = (tlv->value[0] == 0xFF) ? 1 : 0;
    return 0;
}

/* ================================================================
 *  asn1_der_decode_oid
 * ================================================================ */

unsigned long asn1_der_decode_oid(u32 *out, u64 *count,
                                  u64 max_count, const asn1_tlv *tlv) {
    u64 i;
    u64 n;

    if (!out) return 1;
    if (!count) return 2;
    if (!tlv) return 3;
    if (tlv->tag != ASN1_TAG_OID) return 4;
    if (tlv->value_len == 0) return 4;

    /* Decode first byte into two components */
    {
        u32 first_val = 0;
        i = 0;

        /* Base-128 decode the first component(s) */
        do {
            if (i >= tlv->value_len) return 4;
            first_val = (first_val << 7) | (tlv->value[i] & 0x7F);
        } while (tlv->value[i++] & 0x80);

        if (max_count < 2) return 5;

        if (first_val < 40) {
            out[0] = 0;
            out[1] = first_val;
        } else if (first_val < 80) {
            out[0] = 1;
            out[1] = first_val - 40;
        } else {
            out[0] = 2;
            out[1] = first_val - 80;
        }
        n = 2;
    }

    /* Decode remaining components */
    while (i < tlv->value_len) {
        u32 val = 0;

        do {
            if (i >= tlv->value_len) return 4;
            val = (val << 7) | (tlv->value[i] & 0x7F);
        } while (tlv->value[i++] & 0x80);

        if (n >= max_count) return 5;
        out[n++] = val;
    }

    *count = n;
    return 0;
}

/* ================================================================
 *  asn1_der_sequence_next
 * ================================================================ */

unsigned long asn1_der_sequence_next(asn1_tlv *out,
                                     const u8 **cursor, u64 *remaining) {
    unsigned long rc;

    if (!out) return 1;
    if (!cursor) return 2;
    if (!remaining) return 3;
    if (*remaining == 0) return 4;

    rc = asn1_der_decode(out, *cursor, *remaining);
    if (rc) return 5;

    *cursor += out->raw_len;
    *remaining -= out->raw_len;

    return 0;
}

/* ================================================================
 *  asn1_der_get_tag
 * ================================================================ */

unsigned long asn1_der_get_tag(u8 *out, const asn1_tlv *tlv) {
    if (!out) return 1;
    if (!tlv) return 2;

    *out = tlv->tag;
    return 0;
}

/* ================================================================
 *  asn1_der_get_length
 * ================================================================ */

unsigned long asn1_der_get_length(u64 *out, const asn1_tlv *tlv) {
    if (!out) return 1;
    if (!tlv) return 2;

    *out = tlv->value_len;
    return 0;
}

/* ================================================================
 *  asn1_der_get_value
 * ================================================================ */

unsigned long asn1_der_get_value(const u8 **out, u64 *out_len,
                                 const asn1_tlv *tlv) {
    if (!out) return 1;
    if (!out_len) return 2;
    if (!tlv) return 3;

    *out = tlv->value;
    *out_len = tlv->value_len;
    return 0;
}
