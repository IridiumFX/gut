#include "gut/pack.h"
#include "apennines/zlib_wrap.h"
#include "apennines/compress.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Big-endian readers */
static u32 rd32(const u8 *p) {
    return ((u32)p[0] << 24) | ((u32)p[1] << 16) | ((u32)p[2] << 8) | (u32)p[3];
}

static u64 rd64(const u8 *p) {
    return ((u64)rd32(p) << 32) | (u64)rd32(p + 4);
}

/* Read entire file into malloc'd buffer */
static unsigned long read_file(u8 **out, u64 *out_len, const char *path) {
    FILE *fp;
    long size;

    if (!out || !out_len) return __LINE__;

    fp = fopen(path, "rb");
    if (!fp) return __LINE__;

    fseek(fp, 0, SEEK_END);
    size = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    if (size <= 0) { fclose(fp); return __LINE__; }

    *out = (u8 *)malloc((size_t)size);
    if (!*out) { fclose(fp); return __LINE__; }

    if (fread(*out, 1, (size_t)size, fp) != (size_t)size) {
        free(*out);
        *out = NULL;
        fclose(fp);
        return __LINE__;
    }

    fclose(fp);
    *out_len = (u64)size;
    return 0;
}

/* ---- Index parsing ---- */

static unsigned long pack_idx_open(gut_pack_idx *idx, const char *idx_path) {
    unsigned long rc;
    u32 magic, version;

    if (!idx) return __LINE__;

    rc = read_file(&idx->data, &idx->data_len, idx_path);
    if (rc) return __LINE__;

    /* Validate header */
    if (idx->data_len < 8 + 256 * 4) { free(idx->data); return __LINE__; }

    magic = rd32(idx->data);
    version = rd32(idx->data + 4);

    if (magic != GUT_IDX_MAGIC || version != GUT_IDX_VERSION) {
        free(idx->data);
        return __LINE__;
    }

    /* Fan-out table at offset 8 */
    idx->fanout = (u32 *)(idx->data + 8);

    /* Object count is the last fan-out entry */
    idx->object_count = rd32(idx->data + 8 + 255 * 4);

    /* OID table starts after fan-out */
    idx->oids = idx->data + 8 + 256 * 4;

    /* CRC32 table after OIDs */
    /* Offsets after CRC32s */
    {
        u64 oid_section = (u64)idx->object_count * GUT_OID_RAW_SIZE;
        u64 crc_section = (u64)idx->object_count * 4;
        idx->offsets = idx->oids + oid_section + crc_section;
    }

    /* Large offset table (if any 4-byte offsets have MSB set) */
    {
        u64 off4_section = (u64)idx->object_count * 4;
        u8 *after_off4 = idx->offsets + off4_section;
        /* Large offsets exist between off4 end and the two 20-byte checksums */
        u64 remaining = idx->data_len - (u64)(after_off4 - idx->data) - 40;
        idx->offsets64 = (remaining > 0) ? after_off4 : NULL;
    }

    return 0;
}

unsigned long pack_idx_lookup(u64 *offset, unsigned long *found,
                              gut_pack_idx *idx, gut_oid *oid) {
    u32 lo, hi;
    u8 first_byte;

    if (!offset || !found) return __LINE__;
    if (!idx || !oid) return __LINE__;

    *found = 0;
    first_byte = oid->bytes[0];

    /* Fan-out gives range of entries with this first byte */
    lo = (first_byte > 0) ? rd32((u8 *)idx->fanout + (first_byte - 1) * 4) : 0;
    hi = rd32((u8 *)idx->fanout + first_byte * 4);

    /* Binary search in the OID table */
    while (lo < hi) {
        u32 mid = lo + (hi - lo) / 2;
        u8 *entry_oid = idx->oids + (u64)mid * GUT_OID_RAW_SIZE;
        int cmp = memcmp(oid->bytes, entry_oid, GUT_OID_RAW_SIZE);

        if (cmp == 0) {
            /* Found — read offset */
            u32 off4 = rd32(idx->offsets + (u64)mid * 4);
            if (off4 & 0x80000000) {
                /* Large offset */
                u32 idx64 = off4 & 0x7FFFFFFF;
                if (idx->offsets64) {
                    *offset = rd64(idx->offsets64 + (u64)idx64 * 8);
                } else {
                    return __LINE__;
                }
            } else {
                *offset = (u64)off4;
            }
            *found = 1;
            return 0;
        } else if (cmp < 0) {
            hi = mid;
        } else {
            lo = mid + 1;
        }
    }

    return 0; /* not found, *found = 0 */
}

/* ---- Pack object reading ---- */

/* Parse the variable-length type+size encoding at a pack offset.
 * Returns the type (1-7), uncompressed size, and advances *pos past the header. */
static unsigned long parse_obj_header(u32 *type, u64 *size, u8 *data, u64 data_len, u64 *pos) {
    u8 byte;
    u32 shift;

    if (*pos >= data_len) return __LINE__;

    byte = data[*pos];
    (*pos)++;

    *type = (byte >> 4) & 0x07;
    *size = byte & 0x0F;
    shift = 4;

    while (byte & 0x80) {
        if (*pos >= data_len) return __LINE__;
        byte = data[*pos];
        (*pos)++;
        *size |= ((u64)(byte & 0x7F)) << shift;
        shift += 7;
    }

    return 0;
}

/* Parse variable-length offset encoding for OFS_DELTA.
 * Returns the negative offset (distance back from current position). */
static unsigned long parse_ofs_delta_offset(u64 *delta_offset, u8 *data, u64 data_len, u64 *pos) {
    u8 byte;
    u64 result;

    if (*pos >= data_len) return __LINE__;
    byte = data[*pos];
    (*pos)++;
    result = byte & 0x7F;

    while (byte & 0x80) {
        if (*pos >= data_len) return __LINE__;
        byte = data[*pos];
        (*pos)++;
        result = ((result + 1) << 7) | (byte & 0x7F);
    }

    *delta_offset = result;
    return 0;
}

/* Apply a git delta to a base object, producing the result.
 * Delta format: source_size (varint) + target_size (varint) + instructions
 *   Instructions:
 *     Bit 7 = 1: copy from source (bits 0-3 = offset bytes present, bits 4-6 = size bytes present)
 *     Bit 7 = 0: insert N bytes from delta stream (N = byte value, 1-127) */
static unsigned long apply_delta(buf *out, u8 *base_data, u64 base_len,
                                 u8 *delta, u64 delta_len) {
    u64 pos = 0;
    u64 src_size, tgt_size;
    u32 shift;
    u8 byte;
    unsigned long rc;

    if (!out || !delta) return __LINE__;

    /* Read source size */
    src_size = 0;
    shift = 0;
    do {
        if (pos >= delta_len) return __LINE__;
        byte = delta[pos++];
        src_size |= ((u64)(byte & 0x7F)) << shift;
        shift += 7;
    } while (byte & 0x80);

    /* Read target size */
    tgt_size = 0;
    shift = 0;
    do {
        if (pos >= delta_len) return __LINE__;
        byte = delta[pos++];
        tgt_size |= ((u64)(byte & 0x7F)) << shift;
        shift += 7;
    } while (byte & 0x80);

    (void)src_size; /* validated by base_len */

    rc = buf_create(out, tgt_size);
    if (rc) return __LINE__;

    while (pos < delta_len) {
        u8 cmd = delta[pos++];

        if (cmd & 0x80) {
            /* Copy from source */
            u64 copy_offset = 0;
            u64 copy_size = 0;

            if (cmd & 0x01) { if (pos >= delta_len) return __LINE__; copy_offset  = delta[pos++]; }
            if (cmd & 0x02) { if (pos >= delta_len) return __LINE__; copy_offset |= (u64)delta[pos++] << 8; }
            if (cmd & 0x04) { if (pos >= delta_len) return __LINE__; copy_offset |= (u64)delta[pos++] << 16; }
            if (cmd & 0x08) { if (pos >= delta_len) return __LINE__; copy_offset |= (u64)delta[pos++] << 24; }
            if (cmd & 0x10) { if (pos >= delta_len) return __LINE__; copy_size  = delta[pos++]; }
            if (cmd & 0x20) { if (pos >= delta_len) return __LINE__; copy_size |= (u64)delta[pos++] << 8; }
            if (cmd & 0x40) { if (pos >= delta_len) return __LINE__; copy_size |= (u64)delta[pos++] << 16; }
            if (copy_size == 0) copy_size = 0x10000;

            if (copy_offset + copy_size > base_len) return __LINE__;

            rc = buf_append(out, base_data + copy_offset, copy_size);
            if (rc) return __LINE__;
        } else if (cmd > 0) {
            /* Insert from delta */
            if (pos + cmd > delta_len) return __LINE__;
            rc = buf_append(out, delta + pos, cmd);
            if (rc) return __LINE__;
            pos += cmd;
        } else {
            return __LINE__; /* reserved */
        }
    }

    return 0;
}

/* Convert pack type code to gut_obj_type */
static gut_obj_type pack_type_to_obj_type(u32 pack_type) {
    switch (pack_type) {
        case GUT_PACK_OBJ_COMMIT: return GUT_OBJ_COMMIT;
        case GUT_PACK_OBJ_TREE:   return GUT_OBJ_TREE;
        case GUT_PACK_OBJ_BLOB:   return GUT_OBJ_BLOB;
        case GUT_PACK_OBJ_TAG:    return GUT_OBJ_TAG;
        default: return GUT_OBJ_BLOB; /* shouldn't happen */
    }
}

unsigned long pack_open(gut_pack *out, const char *pack_path) {
    char idx_path[1024];
    unsigned long rc;
    u32 magic, version;
    size_t len;

    if (!out) return __LINE__;
    if (!pack_path) return __LINE__;

    memset(out, 0, sizeof(*out));

    len = strlen(pack_path);
    if (len >= sizeof(out->path)) return __LINE__;
    memcpy(out->path, pack_path, len + 1);

    /* Read pack file */
    rc = read_file(&out->data, &out->data_len, pack_path);
    if (rc) return __LINE__;

    /* Validate pack header */
    if (out->data_len < 12) { free(out->data); return __LINE__; }
    magic = rd32(out->data);
    version = rd32(out->data + 4);
    out->object_count = rd32(out->data + 8);

    if (magic != GUT_PACK_SIGNATURE || version != GUT_PACK_VERSION) {
        free(out->data);
        return __LINE__;
    }

    /* Open corresponding .idx file */
    if (len < 5 || strcmp(pack_path + len - 5, ".pack") != 0) {
        free(out->data);
        return __LINE__;
    }
    memcpy(idx_path, pack_path, len - 5);
    memcpy(idx_path + len - 5, ".idx", 5);

    rc = pack_idx_open(&out->idx, idx_path);
    if (rc) {
        free(out->data);
        return __LINE__;
    }

    return 0;
}

unsigned long pack_read_object(gut_object *out, gut_pack *pack, u64 offset) {
    u32 type;
    u64 size;
    u64 pos;
    unsigned long rc;

    if (!out) return __LINE__;
    if (!pack) return __LINE__;

    pos = offset;
    rc = parse_obj_header(&type, &size, pack->data, pack->data_len, &pos);
    if (rc) return __LINE__;

    if (type >= 1 && type <= 4) {
        /* Base object: zlib-compressed data.
         * Skip 2-byte zlib header, decompress raw deflate.
         * We can't use zlib_decompress because it expects the adler32
         * at a known offset, but in a packfile we don't know the
         * compressed size. deflate_decompress self-terminates at EOB. */
        buf decompressed;
        if (pos + 2 > pack->data_len) return __LINE__;
        rc = buf_create(&decompressed, size + 256);
        if (rc) return __LINE__;

        rc = deflate_decompress(&decompressed, pack->data + pos + 2,
                                pack->data_len - pos - 2);
        if (rc) { buf_destroy(&decompressed); return __LINE__; }

        out->type = pack_type_to_obj_type(type);
        out->size = decompressed.len;
        out->data = decompressed;
        return 0;
    }

    if (type == GUT_PACK_OBJ_OFS_DELTA) {
        u64 delta_offset;
        u64 base_abs_offset;
        buf delta_decompressed;
        gut_object base_obj;
        buf result;

        rc = parse_ofs_delta_offset(&delta_offset, pack->data, pack->data_len, &pos);
        if (rc) return __LINE__;

        base_abs_offset = offset - delta_offset;

        /* Decompress delta data (skip 2-byte zlib header) */
        if (pos + 2 > pack->data_len) return __LINE__;
        rc = buf_create(&delta_decompressed, size + 256);
        if (rc) return __LINE__;

        rc = deflate_decompress(&delta_decompressed, pack->data + pos + 2,
                                pack->data_len - pos - 2);
        if (rc) { buf_destroy(&delta_decompressed); return __LINE__; }

        /* Recursively read base object */
        rc = pack_read_object(&base_obj, pack, base_abs_offset);
        if (rc) { buf_destroy(&delta_decompressed); return __LINE__; }

        /* Apply delta */
        rc = apply_delta(&result, base_obj.data.data, base_obj.data.len,
                         delta_decompressed.data, delta_decompressed.len);
        buf_destroy(&delta_decompressed);

        if (rc) { object_destroy(&base_obj); return __LINE__; }

        out->type = base_obj.type;
        out->size = result.len;
        out->data = result;
        object_destroy(&base_obj);
        return 0;
    }

    if (type == GUT_PACK_OBJ_REF_DELTA) {
        gut_oid base_oid;
        u64 base_offset;
        unsigned long found;
        buf delta_decompressed;
        gut_object base_obj;
        buf result;

        /* 20-byte base OID follows the header */
        if (pos + GUT_OID_RAW_SIZE > pack->data_len) return __LINE__;
        memcpy(base_oid.bytes, pack->data + pos, GUT_OID_RAW_SIZE);
        pos += GUT_OID_RAW_SIZE;

        /* Look up base in this pack's index */
        rc = pack_idx_lookup(&base_offset, &found, &pack->idx, &base_oid);
        if (rc || !found) return __LINE__;

        /* Decompress delta (skip 2-byte zlib header) */
        if (pos + 2 > pack->data_len) return __LINE__;
        rc = buf_create(&delta_decompressed, size + 256);
        if (rc) return __LINE__;

        rc = deflate_decompress(&delta_decompressed, pack->data + pos + 2,
                                pack->data_len - pos - 2);
        if (rc) { buf_destroy(&delta_decompressed); return __LINE__; }

        /* Read base and apply delta */
        rc = pack_read_object(&base_obj, pack, base_offset);
        if (rc) { buf_destroy(&delta_decompressed); return __LINE__; }

        rc = apply_delta(&result, base_obj.data.data, base_obj.data.len,
                         delta_decompressed.data, delta_decompressed.len);
        buf_destroy(&delta_decompressed);

        if (rc) { object_destroy(&base_obj); return __LINE__; }

        out->type = base_obj.type;
        out->size = result.len;
        out->data = result;
        object_destroy(&base_obj);
        return 0;
    }

    return __LINE__; /* unknown type */
}

unsigned long pack_close(gut_pack *pack) {
    if (!pack) return __LINE__;
    free(pack->data);
    free(pack->idx.data);
    pack->data = NULL;
    pack->idx.data = NULL;
    return 0;
}
