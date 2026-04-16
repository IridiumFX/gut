#include "apennines/zlib_wrap.h"
#include "apennines/compress.h"
#include "apennines/buf.h"
#include <string.h>

static u32 adler32(u8 *data, u64 len) {
    u32 a = 1, b = 0;
    u64 i;
    for (i = 0; i < len; i++) {
        a = (a + data[i]) % 65521;
        b = (b + a) % 65521;
    }
    return (b << 16) | a;
}

static unsigned long write_u16_be(buf *out, u16 val) {
    u8 b[2];
    b[0] = (u8)((val >> 8) & 0xFF);
    b[1] = (u8)(val & 0xFF);
    return buf_append(out, b, 2);
}

static unsigned long write_u32_be(buf *out, u32 val) {
    u8 b[4];
    b[0] = (u8)((val >> 24) & 0xFF);
    b[1] = (u8)((val >> 16) & 0xFF);
    b[2] = (u8)((val >> 8) & 0xFF);
    b[3] = (u8)(val & 0xFF);
    return buf_append(out, b, 4);
}

static u32 read_u32_be(u8 *p) {
    return ((u32)p[0] << 24) | ((u32)p[1] << 16) | ((u32)p[2] << 8) | (u32)p[3];
}

unsigned long zlib_compress(buf *out, u8 *data, u64 len) {
    unsigned long rc;
    u32 checksum;
    u16 header;

    if (!out) return __LINE__;
    if (len > 0 && !data) return __LINE__;

    header = 0x789C;
    rc = write_u16_be(out, header);
    if (rc) return __LINE__;

    rc = deflate_compress(out, data, len, COMPRESS_LEVEL_DEFAULT);
    if (rc) return __LINE__;

    checksum = adler32(data, len);
    rc = write_u32_be(out, checksum);
    if (rc) return __LINE__;

    return 0;
}

unsigned long zlib_decompress(buf *out, u8 *data, u64 len) {
    unsigned long rc;
    u32 checksum_expected, checksum_actual;
    u64 saved_len;

    if (!out) return __LINE__;
    if (len > 0 && !data) return __LINE__;
    if (len < 6) return __LINE__;

    {
        u8 cmf = data[0];
        u8 flg = data[1];
        if ((cmf & 0x0F) != 8) return __LINE__;
        if (((u16)cmf * 256 + (u16)flg) % 31 != 0) return __LINE__;
        if (flg & 0x20) return __LINE__;
    }

    saved_len = out->len;

    rc = deflate_decompress(out, data + 2, len - 6);
    if (rc) return __LINE__;

    checksum_expected = read_u32_be(data + len - 4);
    checksum_actual = adler32(out->data + saved_len, out->len - saved_len);
    if (checksum_actual != checksum_expected) return __LINE__;

    return 0;
}
