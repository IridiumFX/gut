#include "apennines/compress.h"
#include "apennines/buf.h"
#include <string.h>
#include <stdlib.h>

/* ================================================================
 *  Deflate Compress / Decompress (RFC 1951, fixed Huffman)
 *  Vendored from apennines t2/compress
 * ================================================================ */

typedef struct {
    buf *out;
    u32 bits;
    u32 nbits;
} bit_writer;

static void bw_init(bit_writer *bw, buf *out) {
    bw->out = out;
    bw->bits = 0;
    bw->nbits = 0;
}

static unsigned long bw_write(bit_writer *bw, u32 value, u32 count) {
    unsigned long rc;
    bw->bits |= (value << bw->nbits);
    bw->nbits += count;
    while (bw->nbits >= 8) {
        u8 b = (u8)(bw->bits & 0xFF);
        rc = buf_append_byte(bw->out, b);
        if (rc) return rc;
        bw->bits >>= 8;
        bw->nbits -= 8;
    }
    return 0;
}

static unsigned long bw_flush(bit_writer *bw) {
    unsigned long rc;
    if (bw->nbits > 0) {
        u8 b = (u8)(bw->bits & 0xFF);
        rc = buf_append_byte(bw->out, b);
        if (rc) return rc;
        bw->bits = 0;
        bw->nbits = 0;
    }
    return 0;
}

static u32 reverse_bits(u32 val, u32 nbits) {
    u32 result = 0;
    u32 i;
    for (i = 0; i < nbits; i++) {
        result = (result << 1) | (val & 1);
        val >>= 1;
    }
    return result;
}

static unsigned long deflate_write_fixed_code(bit_writer *bw, u32 symbol) {
    if (symbol <= 143) {
        return bw_write(bw, reverse_bits(0x30 + symbol, 8), 8);
    } else if (symbol <= 255) {
        return bw_write(bw, reverse_bits(0x190 + (symbol - 144), 9), 9);
    } else if (symbol <= 279) {
        return bw_write(bw, reverse_bits(0x00 + (symbol - 256), 7), 7);
    } else {
        return bw_write(bw, reverse_bits(0xC0 + (symbol - 280), 8), 8);
    }
}

static const u16 len_base[] = {
    3,4,5,6,7,8,9,10, 11,13,15,17, 19,23,27,31,
    35,43,51,59, 67,83,99,115, 131,163,195,227, 258
};
static const u8 len_extra[] = {
    0,0,0,0,0,0,0,0, 1,1,1,1, 2,2,2,2,
    3,3,3,3, 4,4,4,4, 5,5,5,5, 0
};

static const u16 dist_base[] = {
    1,2,3,4, 5,7,9,13, 17,25,33,49, 65,97,129,193,
    257,385,513,769, 1025,1537,2049,3073, 4097,6145,8193,12289,
    16385,24577
};
static const u8 dist_extra[] = {
    0,0,0,0, 1,1,2,2, 3,3,4,4, 5,5,6,6,
    7,7,8,8, 9,9,10,10, 11,11,12,12, 13,13
};

static u32 deflate_find_len_code(u32 length) {
    u32 i;
    for (i = 0; i < 29; i++) {
        u32 top = (i < 28) ? len_base[i + 1] : 259;
        if (length < top) return i;
    }
    return 28;
}

static u32 deflate_find_dist_code(u32 distance) {
    u32 i;
    for (i = 0; i < 30; i++) {
        u32 top = (i < 29) ? dist_base[i + 1] : 32769;
        if (distance < top) return i;
    }
    return 29;
}

static u32 read32(const u8 *p) {
    u32 v;
    memcpy(&v, p, 4);
    return v;
}

#define DEFLATE_HASH_BITS  15
#define DEFLATE_HASH_SIZE  (1 << DEFLATE_HASH_BITS)
#define DEFLATE_WINDOW     32768
#define DEFLATE_MIN_MATCH  3
#define DEFLATE_MAX_MATCH  258

static u32 deflate_hash(u32 val) {
    return (val * 2654435761u) >> (32 - DEFLATE_HASH_BITS);
}

unsigned long deflate_compress(buf *out, u8 *data, u64 len, compress_level level) {
    bit_writer bw;
    u32 *hash_table;
    u64 ip;
    unsigned long rc;

    if (!out) return __LINE__;
    if (len > 0 && !data) return __LINE__;

    (void)level;

    bw_init(&bw, out);

    rc = bw_write(&bw, 1, 1);  /* BFINAL */
    if (rc) return __LINE__;
    rc = bw_write(&bw, 1, 2);  /* BTYPE = 01 fixed */
    if (rc) return __LINE__;

    if (len == 0) {
        rc = deflate_write_fixed_code(&bw, 256);
        if (rc) return __LINE__;
        rc = bw_flush(&bw);
        if (rc) return __LINE__;
        return 0;
    }

    hash_table = (u32 *)calloc(DEFLATE_HASH_SIZE, sizeof(u32));
    if (!hash_table) return __LINE__;

    ip = 0;

    while (ip < len) {
        u64 best_len = 0;
        u64 best_dist = 0;

        if (ip + DEFLATE_MIN_MATCH <= len) {
            u32 h = deflate_hash(read32(data + ip) & 0xFFFFFF);
            u64 raw = hash_table[h];
            hash_table[h] = (u32)(ip + 1);

            if (raw > 0) {
                u64 ref = raw - 1;
                if (ip > ref && ip - ref <= DEFLATE_WINDOW) {
                    u64 ml = 0;
                    while (ip + ml < len && ml < DEFLATE_MAX_MATCH &&
                           data[ref + ml] == data[ip + ml]) {
                        ml++;
                    }
                    if (ml >= DEFLATE_MIN_MATCH) {
                        best_len = ml;
                        best_dist = ip - ref;
                    }
                }
            }
        }

        if (best_len >= DEFLATE_MIN_MATCH) {
            u32 lc = deflate_find_len_code((u32)best_len);
            u32 dc = deflate_find_dist_code((u32)best_dist);

            rc = deflate_write_fixed_code(&bw, 257 + lc);
            if (rc) { free(hash_table); return __LINE__; }

            if (len_extra[lc] > 0) {
                rc = bw_write(&bw, (u32)(best_len - len_base[lc]), len_extra[lc]);
                if (rc) { free(hash_table); return __LINE__; }
            }

            rc = bw_write(&bw, reverse_bits(dc, 5), 5);
            if (rc) { free(hash_table); return __LINE__; }

            if (dist_extra[dc] > 0) {
                rc = bw_write(&bw, (u32)(best_dist - dist_base[dc]), dist_extra[dc]);
                if (rc) { free(hash_table); return __LINE__; }
            }

            {
                u64 j;
                for (j = 1; j < best_len && ip + j + DEFLATE_MIN_MATCH <= len; j++) {
                    u32 hh = deflate_hash(read32(data + ip + j) & 0xFFFFFF);
                    hash_table[hh] = (u32)(ip + j + 1);
                }
            }

            ip += best_len;
        } else {
            rc = deflate_write_fixed_code(&bw, data[ip]);
            if (rc) { free(hash_table); return __LINE__; }
            ip++;
        }
    }

    rc = deflate_write_fixed_code(&bw, 256);
    if (rc) { free(hash_table); return __LINE__; }

    rc = bw_flush(&bw);
    if (rc) { free(hash_table); return __LINE__; }

    free(hash_table);
    return 0;
}

/* ================================================================
 *  Deflate Decompress (RFC 1951)
 * ================================================================ */

typedef struct {
    u8  *data;
    u64  len;
    u64  pos;
    u32  bits;
    u32  nbits;
} bit_reader;

static void br_init(bit_reader *br, u8 *data, u64 len) {
    br->data = data;
    br->len = len;
    br->pos = 0;
    br->bits = 0;
    br->nbits = 0;
}

static unsigned long br_read(bit_reader *br, u32 count, u32 *result) {
    while (br->nbits < count) {
        if (br->pos >= br->len) return 1;
        br->bits |= ((u32)br->data[br->pos++]) << br->nbits;
        br->nbits += 8;
    }
    *result = br->bits & ((1u << count) - 1);
    br->bits >>= count;
    br->nbits -= count;
    return 0;
}

static unsigned long deflate_decode_fixed_symbol(bit_reader *br, u32 *sym) {
    u32 code;
    unsigned long rc;

    rc = br_read(br, 7, &code);
    if (rc) return rc;

    code = reverse_bits(code, 7);

    if (code <= 0x17) {
        *sym = 256 + code;
        return 0;
    }

    {
        u32 extra;
        rc = br_read(br, 1, &extra);
        if (rc) return rc;
        code = (code << 1) | extra;
    }

    if (code >= 0x30 && code <= 0xBF) {
        *sym = code - 0x30;
        return 0;
    }
    if (code >= 0xC0 && code <= 0xC7) {
        *sym = 280 + (code - 0xC0);
        return 0;
    }

    {
        u32 extra;
        rc = br_read(br, 1, &extra);
        if (rc) return rc;
        code = (code << 1) | extra;
    }

    if (code >= 0x190 && code <= 0x1FF) {
        *sym = 144 + (code - 0x190);
        return 0;
    }

    return 1;
}

unsigned long deflate_decompress(buf *out, u8 *data, u64 len) {
    bit_reader br;
    u32 bfinal;
    unsigned long rc;

    if (!out) return __LINE__;
    if (len > 0 && !data) return __LINE__;

    if (len == 0) return 0;

    br_init(&br, data, len);

    do {
        u32 btype;

        rc = br_read(&br, 1, &bfinal);
        if (rc) return __LINE__;

        rc = br_read(&br, 2, &btype);
        if (rc) return __LINE__;

        if (btype == 0) {
            u32 block_len, nlen;
            br.bits = 0;
            br.nbits = 0;

            if (br.pos + 4 > br.len) return __LINE__;
            block_len = (u32)(br.data[br.pos] | ((u32)br.data[br.pos + 1] << 8));
            nlen = (u32)(br.data[br.pos + 2] | ((u32)br.data[br.pos + 3] << 8));
            br.pos += 4;

            if ((block_len ^ 0xFFFF) != nlen) return __LINE__;
            if (br.pos + block_len > br.len) return __LINE__;

            rc = buf_append(out, br.data + br.pos, block_len);
            if (rc) return __LINE__;
            br.pos += block_len;
        } else if (btype == 1) {
            for (;;) {
                u32 sym;
                rc = deflate_decode_fixed_symbol(&br, &sym);
                if (rc) return __LINE__;

                if (sym < 256) {
                    u8 b = (u8)sym;
                    rc = buf_append_byte(out, b);
                    if (rc) return __LINE__;
                } else if (sym == 256) {
                    break;
                } else {
                    u32 lc = sym - 257;
                    u32 length;
                    u32 dc_bits, dc;
                    u32 distance;

                    if (lc >= 29) return __LINE__;

                    length = len_base[lc];
                    if (len_extra[lc] > 0) {
                        u32 extra;
                        rc = br_read(&br, len_extra[lc], &extra);
                        if (rc) return __LINE__;
                        length += extra;
                    }

                    rc = br_read(&br, 5, &dc_bits);
                    if (rc) return __LINE__;
                    dc = reverse_bits(dc_bits, 5);

                    if (dc >= 30) return __LINE__;
                    distance = dist_base[dc];
                    if (dist_extra[dc] > 0) {
                        u32 extra;
                        rc = br_read(&br, dist_extra[dc], &extra);
                        if (rc) return __LINE__;
                        distance += extra;
                    }

                    if (out->len < distance) return __LINE__;
                    {
                        u64 src_pos = out->len - distance;
                        u32 i;
                        for (i = 0; i < length; i++) {
                            u8 b = out->data[src_pos + i];
                            rc = buf_append_byte(out, b);
                            if (rc) return __LINE__;
                        }
                    }
                }
            }
        } else if (btype == 2) {
            return __LINE__; /* dynamic Huffman not yet supported */
        } else {
            return __LINE__;
        }
    } while (!bfinal);

    return 0;
}
