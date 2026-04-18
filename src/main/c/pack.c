#include "gut/pack.h"
#include "gut/sha1.h"
#include "gut/delta.h"
#include "apennines/zlib_wrap.h"
#include "apennines/compress.h"
#include "apennines/hash.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#ifdef _WIN32
#include <direct.h>
#include <process.h>
#define gut_getpid() _getpid()
#else
#include <sys/types.h>
#include <unistd.h>
#define gut_getpid() getpid()
#endif

/* ----- Width-aware hash (SHA-1 or SHA-256) ----- */
typedef struct {
    gut_hash_algo algo;
    union {
        sha1_ctx   s1;
        sha256_ctx s256;
    } c;
} pack_hasher;

static void ph_init(pack_hasher *h, gut_hash_algo a) {
    h->algo = a;
    if (a == GUT_HASH_SHA256) sha256_init(&h->c.s256);
    else                      sha1_init  (&h->c.s1);
}
static void ph_update(pack_hasher *h, const u8 *data, u64 len) {
    if (h->algo == GUT_HASH_SHA256) sha256_update(&h->c.s256, data, len);
    else                            sha1_update  (&h->c.s1, data, len);
}
static void ph_final(u8 *out, pack_hasher *h) {
    if (h->algo == GUT_HASH_SHA256) sha256_final(out, &h->c.s256);
    else                            sha1_final  (out, &h->c.s1);
}
static void ph_digest(u8 *out, gut_hash_algo a, const u8 *data, u64 len) {
    if (a == GUT_HASH_SHA256) sha256_digest(out, data, len);
    else                      sha1_digest  (out, data, len);
}

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
        unsigned oid_raw = gut_oid_raw_size(idx->hash_algo);
        u64 oid_section = (u64)idx->object_count * oid_raw;
        u64 crc_section = (u64)idx->object_count * 4;
        idx->offsets = idx->oids + oid_section + crc_section;
    }

    /* Large offset table (if any 4-byte offsets have MSB set).
     * Trailer is pack-SHA + idx-SHA, 2 * (20 or 32) bytes. */
    {
        unsigned trailer = 2 * gut_oid_raw_size(idx->hash_algo);
        u64 off4_section = (u64)idx->object_count * 4;
        u8 *after_off4 = idx->offsets + off4_section;
        u64 remaining = idx->data_len - (u64)(after_off4 - idx->data) - trailer;
        idx->offsets64 = (remaining > 0) ? after_off4 : NULL;
    }

    return 0;
}

unsigned long pack_idx_lookup(u64 *offset, unsigned long *found,
                              gut_pack_idx *idx, gut_oid *oid) {
    u32 lo, hi;
    u8 first_byte;
    unsigned oid_raw;

    if (!offset || !found) return __LINE__;
    if (!idx || !oid) return __LINE__;

    oid_raw = gut_oid_raw_size(idx->hash_algo);
    *found = 0;
    first_byte = oid->bytes[0];

    /* Fan-out gives range of entries with this first byte */
    lo = (first_byte > 0) ? rd32((u8 *)idx->fanout + (first_byte - 1) * 4) : 0;
    hi = rd32((u8 *)idx->fanout + first_byte * 4);

    /* Binary search in the OID table */
    while (lo < hi) {
        u32 mid = lo + (hi - lo) / 2;
        u8 *entry_oid = idx->oids + (u64)mid * oid_raw;
        int cmp = memcmp(oid->bytes, entry_oid, oid_raw);

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

unsigned long pack_open_algo(gut_pack *out, const char *pack_path,
                             gut_hash_algo algo) {
    char idx_path[1024];
    unsigned long rc;
    u32 magic, version;
    size_t len;

    if (!out) return __LINE__;
    if (!pack_path) return __LINE__;

    memset(out, 0, sizeof(*out));
    out->hash_algo = algo;
    out->idx.hash_algo = algo;

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

unsigned long pack_open(gut_pack *out, const char *pack_path) {
    return pack_open_algo(out, pack_path, GUT_HASH_SHA1);
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
        unsigned oid_raw = gut_oid_raw_size(pack->hash_algo);

        /* Base OID follows the header (20 or 32 bytes) */
        if (pos + oid_raw > pack->data_len) return __LINE__;
        memset(base_oid.bytes, 0, sizeof(base_oid.bytes));
        memcpy(base_oid.bytes, pack->data + pos, oid_raw);
        pos += oid_raw;

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

/* ============================================================
 *  Pack writer
 * ============================================================ */

/* Big-endian writers */
static void wr32(u8 *p, u32 v) {
    p[0] = (u8)(v >> 24);
    p[1] = (u8)(v >> 16);
    p[2] = (u8)(v >> 8);
    p[3] = (u8)v;
}

static void wr64(u8 *p, u64 v) {
    wr32(p, (u32)(v >> 32));
    wr32(p + 4, (u32)v);
}

/* CRC32 (IEEE 802.3 polynomial 0xEDB88320) */
static u32 crc32_tab[256];
static int crc32_initialized = 0;

static void crc32_init(void) {
    u32 i, j, c;
    if (crc32_initialized) return;
    for (i = 0; i < 256; i++) {
        c = i;
        for (j = 0; j < 8; j++) {
            c = (c & 1) ? (0xEDB88320u ^ (c >> 1)) : (c >> 1);
        }
        crc32_tab[i] = c;
    }
    crc32_initialized = 1;
}

static u32 crc32_compute(const u8 *data, u64 len) {
    u32 c = 0xFFFFFFFFu;
    u64 i;
    crc32_init();
    for (i = 0; i < len; i++) {
        c = crc32_tab[(c ^ data[i]) & 0xFF] ^ (c >> 8);
    }
    return c ^ 0xFFFFFFFFu;
}

/* Convert our object type to pack type code */
static u32 obj_type_to_pack_type(gut_obj_type t) {
    switch (t) {
        case GUT_OBJ_COMMIT: return GUT_PACK_OBJ_COMMIT;
        case GUT_OBJ_TREE:   return GUT_PACK_OBJ_TREE;
        case GUT_OBJ_BLOB:   return GUT_PACK_OBJ_BLOB;
        case GUT_OBJ_TAG:    return GUT_PACK_OBJ_TAG;
    }
    return GUT_PACK_OBJ_BLOB;
}

/* Encode type+size varint into buf. Returns number of bytes written. */
static u64 encode_type_size(u8 *out, u32 type, u64 size) {
    u64 n = 0;
    u8 byte;
    u64 remaining;

    byte = (u8)((type & 0x07) << 4) | (u8)(size & 0x0F);
    remaining = size >> 4;
    if (remaining > 0) byte |= 0x80;
    out[n++] = byte;

    while (remaining > 0) {
        byte = (u8)(remaining & 0x7F);
        remaining >>= 7;
        if (remaining > 0) byte |= 0x80;
        out[n++] = byte;
    }

    return n;
}

/* Encode the negative-offset varint used by OFS_DELTA. Inverse of
 * parse_ofs_delta_offset above. Returns number of bytes written. */
static u64 encode_ofs_delta_offset(u8 *out, u64 offset) {
    u8 tmp[10];
    int n = 0;
    int i;
    tmp[n++] = (u8)(offset & 0x7F);
    offset >>= 7;
    while (offset > 0) {
        offset--;
        tmp[n++] = (u8)(offset & 0x7F);
        offset >>= 7;
    }
    /* Emit MSB-first; set MSB on all but the last (which must be clear). */
    for (i = n - 1; i >= 0; i--) {
        u8 b = tmp[i];
        if (i != 0) b |= 0x80;
        *out++ = b;
    }
    return (u64)n;
}

/* Entry used during pack build */
typedef struct {
    gut_oid oid;
    u64     offset;    /* offset of this object in the .pack file */
    u32     crc32;     /* CRC32 of the on-disk (compressed) object bytes */
} pack_entry;

/* Sort entries by OID (for the .idx) */
static void sort_entries_by_oid(pack_entry *e, u64 n, unsigned oid_raw) {
    u64 i, j;
    /* Simple insertion sort — fine for typical pack sizes */
    for (i = 1; i < n; i++) {
        pack_entry tmp = e[i];
        j = i;
        while (j > 0 && memcmp(e[j - 1].oid.bytes, tmp.oid.bytes, oid_raw) > 0) {
            e[j] = e[j - 1];
            j--;
        }
        e[j] = tmp;
    }
}

/* Trailing-component extractor: returns pointer to what's after the last
 * '/' (or the full string if none). NULL → "". Used as the name-hash
 * key for path-hint clustering — versions of the same file across commits
 * share a basename so they end up next to each other in the sort. */
static const char *pack_basename_of(const char *path) {
    const char *slash;
    if (!path) return "";
    slash = strrchr(path, '/');
    if (!slash) return path;
    return slash + 1;
}

unsigned long pack_write_hinted(char *out_hex,
                                const char *pack_dir,
                                gut_odb *odb,
                                gut_oid *oids,
                                const char **paths,
                                u64 count);

unsigned long pack_write(char *out_hex,
                         const char *pack_dir,
                         gut_odb *odb,
                         gut_oid *oids, u64 count) {
    return pack_write_hinted(out_hex, pack_dir, odb, oids, NULL, count);
}

unsigned long pack_write_hinted(char *out_hex,
                                const char *pack_dir,
                                gut_odb *odb,
                                gut_oid *oids,
                                const char **paths,
                                u64 count) {
    FILE *fp;
    char tmp_pack_path[2048];
    char tmp_idx_path[2048];
    char final_pack_path[2048];
    char final_idx_path[2048];
    pack_entry *entries = NULL;
    u8 header[12];
    u8 pack_digest[GUT_OID_MAX_RAW_SIZE];
    char pack_hex[GUT_OID_MAX_HEX_SIZE + 1];
    pack_hasher pack_hash;
    unsigned long rc;
    u64 i;
    u64 pack_offset;
    unsigned oid_raw;
    unsigned hex_len;

    if (!pack_dir) return __LINE__;
    if (!odb) return __LINE__;
    if (count > 0 && !oids) return __LINE__;

    oid_raw = gut_oid_raw_size(odb->hash_algo);
    hex_len = gut_oid_hex_size(odb->hash_algo);

    /* Ensure pack dir exists */
#ifdef _WIN32
    {
        char dir_copy[2048];
        snprintf(dir_copy, sizeof(dir_copy), "%s", pack_dir);
        _mkdir(dir_copy);
    }
#else
    {
        char dir_copy[2048];
        snprintf(dir_copy, sizeof(dir_copy), "%s", pack_dir);
        mkdir(dir_copy, 0755);
    }
#endif

    /* Write to temporary files with PID + timestamp to avoid concurrent-writer
     * collisions; we rename to content-addressed name after we know the SHA-1. */
    {
        unsigned long pid = (unsigned long)gut_getpid();
        unsigned long ts = (unsigned long)time(NULL);
        snprintf(tmp_pack_path, sizeof(tmp_pack_path),
                 "%s/pack-tmp-%lu-%lu.pack", pack_dir, pid, ts);
        snprintf(tmp_idx_path, sizeof(tmp_idx_path),
                 "%s/pack-tmp-%lu-%lu.idx", pack_dir, pid, ts);
    }

    fp = fopen(tmp_pack_path, "wb");
    if (!fp) return __LINE__;

    entries = (pack_entry *)calloc((size_t)count, sizeof(pack_entry));
    if (!entries && count > 0) { fclose(fp); return __LINE__; }

    /* Write PACK header, hashing as we go */
    ph_init(&pack_hash, odb->hash_algo);
    wr32(header, GUT_PACK_SIGNATURE);
    wr32(header + 4, GUT_PACK_VERSION);
    wr32(header + 8, (u32)count);
    if (fwrite(header, 1, 12, fp) != 12) goto fail_pack_file;
    ph_update(&pack_hash, header, 12);

    pack_offset = 12;

    /* Preload all objects into memory and sort so the delta window sees
     * good candidates. Two sort strategies:
     *
     *   paths == NULL:   (type asc, size desc)
     *                    — similar types cluster, big objects become bases.
     *
     *   paths != NULL:   (type asc, basename asc, size desc)
     *                    — versions of the same file cluster. Size-desc
     *                      within a basename puts the biggest version
     *                      first as the base. On typical C projects that
     *                      grow monotonically, this also happens to put
     *                      the newest version first.
     *
     *   Blobs without a path (basename = "") cluster together.
     *
     *   A recency-weighted alternative using BFS-discovery order
     *   (newest-first) instead of size-desc was benchmarked:
     *     • gut's own history (monotonic growth): size-desc wins by ~2%.
     *     • non-monotonic synthetic repo:         recency wins by ~2%.
     *   Kept size-desc as the default since real-world C projects
     *   dominate the monotonic case. */
    typedef struct {
        gut_oid     oid;
        gut_object  obj;
        const char *path;
    } preload_entry;
    preload_entry *pre = NULL;
    if (count > 0) {
        pre = (preload_entry *)calloc((size_t)count, sizeof(preload_entry));
        if (!pre) { rc = __LINE__; goto fail_pack_file; }
        for (i = 0; i < count; i++) {
            pre[i].oid = oids[i];
            pre[i].path = paths ? paths[i] : NULL;
            if (odb_read(&pre[i].obj, odb, &pre[i].oid) != 0) {
                u64 j;
                for (j = 0; j < i; j++) object_destroy(&pre[j].obj);
                free(pre); pre = NULL;
                rc = __LINE__; goto fail_pack_file;
            }
        }
        {
            u64 a, b;
            for (a = 1; a < count; a++) {
                preload_entry tmp = pre[a];
                b = a;
                while (b > 0) {
                    int c = 0;
                    if (pre[b - 1].obj.type != tmp.obj.type) {
                        c = (int)pre[b - 1].obj.type - (int)tmp.obj.type;
                    } else if (paths) {
                        const char *bn_prev = pack_basename_of(pre[b - 1].path);
                        const char *bn_curr = pack_basename_of(tmp.path);
                        int nc = strcmp(bn_prev, bn_curr);
                        if (nc != 0) {
                            c = nc;
                        } else if (pre[b - 1].obj.data.len != tmp.obj.data.len) {
                            c = (pre[b - 1].obj.data.len < tmp.obj.data.len) ? 1 : -1;
                        }
                    } else if (pre[b - 1].obj.data.len != tmp.obj.data.len) {
                        c = (pre[b - 1].obj.data.len < tmp.obj.data.len) ? 1 : -1;
                    }
                    if (c <= 0) break;
                    pre[b] = pre[b - 1];
                    b--;
                }
                pre[b] = tmp;
            }
        }
    }

    /* Write each object. For each, attempt delta against recently-written
     * same-type objects in a sliding window; use the best delta if it's
     * meaningfully smaller than the straight-base encoding. */
    {
#define GUT_DELTA_WINDOW 10
        struct {
            int          valid;
            u64          offset;
            gut_obj_type type;
            u8          *content;
            u64          content_len;
        } window[GUT_DELTA_WINDOW];
        int win_size = 0;
        int win_next = 0;
        int w;

        for (w = 0; w < GUT_DELTA_WINDOW; w++) window[w].valid = 0;

        for (i = 0; i < count; i++) {
            gut_object obj = pre[i].obj;
            u64 obj_start_offset = pack_offset;
            int is_delta = 0;
            int best_w = -1;
            buf best_delta;
            memset(&best_delta, 0, sizeof(best_delta));
            u64 best_base_off = 0;
            u8  type_size_buf[16];
            u64 type_size_len;
            u8  ofs_bytes[16];
            u64 ofs_len = 0;
            u32 pack_type;
            u64 size_field;
            u8 *body_bytes;
            u64 body_len;
            buf compressed;

            /* Try each candidate in window — pick smallest delta of same type. */
            for (w = 0; w < win_size; w++) {
                int idx = (win_next - 1 - w + GUT_DELTA_WINDOW) % GUT_DELTA_WINDOW;
                buf cand;
                if (!window[idx].valid) continue;
                if (window[idx].type != obj.type) continue;

                if (delta_encode(&cand,
                                 window[idx].content, window[idx].content_len,
                                 obj.data.data, obj.data.len) != 0) continue;

                if (best_w < 0 || cand.len < best_delta.len) {
                    if (best_w >= 0) buf_destroy(&best_delta);
                    best_delta = cand;
                    best_w = idx;
                    best_base_off = window[idx].offset;
                } else {
                    buf_destroy(&cand);
                }
            }

            /* Accept delta only if it beats the raw size by > 30 bytes
             * (covers zlib overhead + delta headers). */
            if (best_w >= 0 && best_delta.len + 30 < obj.data.len) {
                is_delta = 1;
            } else if (best_w >= 0) {
                buf_destroy(&best_delta);
                best_w = -1;
            }

            if (is_delta) {
                pack_type  = GUT_PACK_OBJ_OFS_DELTA;
                size_field = best_delta.len;
                ofs_len    = encode_ofs_delta_offset(ofs_bytes,
                                                     obj_start_offset - best_base_off);
                body_bytes = best_delta.data;
                body_len   = best_delta.len;
            } else {
                pack_type  = obj_type_to_pack_type(obj.type);
                size_field = obj.data.len;
                body_bytes = obj.data.data;
                body_len   = obj.data.len;
            }

            type_size_len = encode_type_size(type_size_buf, pack_type, size_field);

            rc = buf_create(&compressed, body_len + 64);
            if (rc) {
                if (is_delta) buf_destroy(&best_delta);
                rc = __LINE__; goto fail_pack_file;
            }
            rc = zlib_compress(&compressed, body_bytes, body_len);
            if (rc) {
                buf_destroy(&compressed);
                if (is_delta) buf_destroy(&best_delta);
                rc = __LINE__; goto fail_pack_file;
            }

            memcpy(entries[i].oid.bytes, pre[i].oid.bytes, sizeof(entries[i].oid.bytes));
            entries[i].offset = obj_start_offset;

            /* header */
            if (fwrite(type_size_buf, 1, (size_t)type_size_len, fp) != type_size_len) {
                buf_destroy(&compressed);
                if (is_delta) buf_destroy(&best_delta);
                rc = __LINE__; goto fail_pack_file;
            }
            ph_update(&pack_hash, type_size_buf, type_size_len);

            /* OFS_DELTA prefix */
            if (is_delta) {
                if (fwrite(ofs_bytes, 1, (size_t)ofs_len, fp) != ofs_len) {
                    buf_destroy(&compressed); buf_destroy(&best_delta);
                    rc = __LINE__; goto fail_pack_file;
                }
                ph_update(&pack_hash, ofs_bytes, ofs_len);
            }

            /* zlib body */
            if (fwrite(compressed.data, 1, (size_t)compressed.len, fp) != compressed.len) {
                buf_destroy(&compressed);
                if (is_delta) buf_destroy(&best_delta);
                rc = __LINE__; goto fail_pack_file;
            }
            ph_update(&pack_hash, compressed.data, compressed.len);

            /* CRC over header + optional ofs + compressed */
            {
                u64 total = type_size_len + ofs_len + compressed.len;
                u8 *merged = (u8 *)malloc((size_t)total);
                if (!merged) {
                    buf_destroy(&compressed);
                    if (is_delta) buf_destroy(&best_delta);
                    rc = __LINE__; goto fail_pack_file;
                }
                memcpy(merged, type_size_buf, (size_t)type_size_len);
                if (is_delta) memcpy(merged + type_size_len, ofs_bytes, (size_t)ofs_len);
                memcpy(merged + type_size_len + ofs_len, compressed.data, (size_t)compressed.len);
                entries[i].crc32 = crc32_compute(merged, total);
                free(merged);
            }

            pack_offset += type_size_len + ofs_len + compressed.len;

            buf_destroy(&compressed);
            if (is_delta) buf_destroy(&best_delta);

            /* Cache this object's raw content for future deltas.
             * pre[i].obj stays alive until post-loop cleanup, so we could
             * point the window directly at it — but copying keeps the
             * eviction story simple and memory bounded at CHAIN*size. */
            {
                int slot = win_next;
                if (window[slot].valid) {
                    free(window[slot].content);
                    window[slot].valid = 0;
                }
                window[slot].content = (u8 *)malloc((size_t)obj.data.len);
                if (window[slot].content) {
                    memcpy(window[slot].content, obj.data.data, (size_t)obj.data.len);
                    window[slot].content_len = obj.data.len;
                    window[slot].type        = obj.type;
                    window[slot].offset      = obj_start_offset;
                    window[slot].valid       = 1;
                    win_next = (win_next + 1) % GUT_DELTA_WINDOW;
                    if (win_size < GUT_DELTA_WINDOW) win_size++;
                }
            }
        }

        for (w = 0; w < GUT_DELTA_WINDOW; w++) {
            if (window[w].valid) free(window[w].content);
        }
#undef GUT_DELTA_WINDOW
    }

    /* Release all preloaded objects */
    if (pre) {
        u64 k;
        for (k = 0; k < count; k++) object_destroy(&pre[k].obj);
        free(pre);
        pre = NULL;
    }

    /* Finalize pack hash and write trailer */
    ph_final(pack_digest, &pack_hash);
    if (fwrite(pack_digest, 1, oid_raw, fp) != oid_raw) {
        rc = __LINE__;
        goto fail_pack_file;
    }

    fclose(fp);
    fp = NULL;

    /* Build pack hex name */
    {
        gut_oid pack_oid;
        memset(pack_oid.bytes, 0, sizeof(pack_oid.bytes));
        memcpy(pack_oid.bytes, pack_digest, oid_raw);
        oid_to_hex_n(pack_hex, &pack_oid, hex_len);
    }

    snprintf(final_pack_path, sizeof(final_pack_path), "%s/pack-%s.pack", pack_dir, pack_hex);
    snprintf(final_idx_path, sizeof(final_idx_path), "%s/pack-%s.idx", pack_dir, pack_hex);

    /* Write .idx file */
    {
        FILE *idx_fp;
        u32 fanout[256];
        u8  buf4[4];
        pack_hasher idx_hash;
        u8  idx_digest[GUT_OID_MAX_RAW_SIZE];
        u32 fi;

        sort_entries_by_oid(entries, count, oid_raw);

        /* Compute fan-out table */
        for (fi = 0; fi < 256; fi++) fanout[fi] = 0;
        for (i = 0; i < count; i++) fanout[entries[i].oid.bytes[0]]++;
        {
            u32 cum = 0;
            for (fi = 0; fi < 256; fi++) { cum += fanout[fi]; fanout[fi] = cum; }
        }

        idx_fp = fopen(tmp_idx_path, "wb");
        if (!idx_fp) { rc = __LINE__; goto fail_after_pack; }

        ph_init(&idx_hash, odb->hash_algo);

        /* Magic + version */
        {
            u8 magic_ver[8];
            wr32(magic_ver, GUT_IDX_MAGIC);
            wr32(magic_ver + 4, GUT_IDX_VERSION);
            if (fwrite(magic_ver, 1, 8, idx_fp) != 8) goto fail_idx;
            ph_update(&idx_hash, magic_ver, 8);
        }

        /* Fan-out table */
        for (fi = 0; fi < 256; fi++) {
            wr32(buf4, fanout[fi]);
            if (fwrite(buf4, 1, 4, idx_fp) != 4) goto fail_idx;
            ph_update(&idx_hash, buf4, 4);
        }

        /* OID table */
        for (i = 0; i < count; i++) {
            if (fwrite(entries[i].oid.bytes, 1, oid_raw, idx_fp) != oid_raw)
                goto fail_idx;
            ph_update(&idx_hash, entries[i].oid.bytes, oid_raw);
        }

        /* CRC32 table */
        for (i = 0; i < count; i++) {
            wr32(buf4, entries[i].crc32);
            if (fwrite(buf4, 1, 4, idx_fp) != 4) goto fail_idx;
            ph_update(&idx_hash, buf4, 4);
        }

        /* Offset table. Offsets < 2 GiB fit directly; larger offsets set
         * MSB=1 and index into the large-offset table emitted below. */
        {
            u64 *large = NULL;
            u64 large_count = 0;
            u64 li;

            /* First pass: allocate large-offset slots */
            for (i = 0; i < count; i++) {
                if (entries[i].offset > 0x7FFFFFFFu) large_count++;
            }
            if (large_count > 0) {
                large = (u64 *)malloc(large_count * sizeof(u64));
                if (!large) goto fail_idx;
            }

            li = 0;
            for (i = 0; i < count; i++) {
                if (entries[i].offset > 0x7FFFFFFFu) {
                    if (li > 0x7FFFFFFFu) { free(large); goto fail_idx; }
                    large[li] = entries[i].offset;
                    wr32(buf4, 0x80000000u | (u32)li);
                    li++;
                } else {
                    wr32(buf4, (u32)entries[i].offset);
                }
                if (fwrite(buf4, 1, 4, idx_fp) != 4) {
                    free(large); goto fail_idx;
                }
                ph_update(&idx_hash, buf4, 4);
            }

            /* Large-offset table */
            for (li = 0; li < large_count; li++) {
                u8 buf8[8];
                wr64(buf8, large[li]);
                if (fwrite(buf8, 1, 8, idx_fp) != 8) {
                    free(large); goto fail_idx;
                }
                ph_update(&idx_hash, buf8, 8);
            }
            free(large);
        }

        /* Pack hash trailer (first oid_raw bytes of idx trailer) */
        if (fwrite(pack_digest, 1, oid_raw, idx_fp) != oid_raw)
            goto fail_idx;
        ph_update(&idx_hash, pack_digest, oid_raw);

        /* Idx hash trailer (last oid_raw bytes) */
        ph_final(idx_digest, &idx_hash);
        if (fwrite(idx_digest, 1, oid_raw, idx_fp) != oid_raw)
            goto fail_idx;

        fclose(idx_fp);
    }

    /* Rename temp files to final names */
    remove(final_pack_path);
    remove(final_idx_path);
    if (rename(tmp_pack_path, final_pack_path) != 0) { rc = __LINE__; goto fail_after_pack; }
    if (rename(tmp_idx_path, final_idx_path) != 0) { rc = __LINE__; goto fail_after_pack; }

    if (out_hex) {
        memcpy(out_hex, pack_hex, hex_len + 1);
    }

    free(entries);
    return 0;

fail_idx:
    if (fp) fclose(fp);
    remove(tmp_idx_path);
    rc = __LINE__;
    goto fail_after_pack;

fail_pack_file:
    if (fp) fclose(fp);
    remove(tmp_pack_path);
    free(entries);
    if (pre) {
        u64 k;
        for (k = 0; k < count; k++) object_destroy(&pre[k].obj);
        free(pre);
    }
    return rc;

fail_after_pack:
    remove(tmp_pack_path);
    remove(tmp_idx_path);
    free(entries);
    if (pre) {
        u64 k;
        for (k = 0; k < count; k++) object_destroy(&pre[k].obj);
        free(pre);
    }
    return rc;
}

/* ============================================================
 *  Pack indexer — write .idx for an existing .pack file
 * ============================================================ */

/* Walk-state entry for one object in the pack */
typedef struct {
    u64      offset;            /* byte offset into pack */
    u64      next_offset;       /* byte offset of the next object */
    u32      raw_type;          /* 1..4 base, 6 OFS_DELTA, 7 REF_DELTA */
    u64      decompressed_size; /* size field from the varint header */
    u64      data_start;        /* file offset where zlib stream starts */
    u64      base_abs_offset;   /* OFS_DELTA: resolved absolute offset */
    gut_oid  base_oid;          /* REF_DELTA: base oid */
    int      is_ref_delta;
    /* Filled once resolved */
    int          resolved;
    gut_obj_type obj_type;      /* final resolved base type */
    buf          content;       /* reconstructed object bytes */
    gut_oid      oid;
    u32          crc32;         /* CRC of raw pack bytes [offset, next_offset) */
} idx_walk_entry;

unsigned long pack_index_create_algo(const char *pack_path,
                                     char *pack_sha1_hex_out,
                                     gut_hash_algo algo) {
    u8 *data = NULL;
    u64 data_len = 0;
    u32 object_count = 0;
    idx_walk_entry *entries = NULL;
    u64 pos;
    u64 i;
    unsigned long rc;
    u32 fanout[256];
    u8 pack_trailer[GUT_OID_MAX_RAW_SIZE];
    char idx_path[1024];
    size_t path_len;
    FILE *fp = NULL;
    pack_hasher idx_hash;
    u8 buf4[4];
    u8 idx_digest[GUT_OID_MAX_RAW_SIZE];
    unsigned oid_raw = gut_oid_raw_size(algo);
    unsigned hex_len = gut_oid_hex_size(algo);

    if (!pack_path) return __LINE__;

    rc = read_file(&data, &data_len, pack_path);
    if (rc) return __LINE__;

    if (data_len < 12 + oid_raw) { free(data); return __LINE__; }
    if (rd32(data) != GUT_PACK_SIGNATURE) { free(data); return __LINE__; }
    if (rd32(data + 4) != GUT_PACK_VERSION) { free(data); return __LINE__; }
    object_count = rd32(data + 8);
    if (object_count == 0) { free(data); return __LINE__; }

    memcpy(pack_trailer, data + data_len - oid_raw, oid_raw);

    entries = (idx_walk_entry *)calloc((size_t)object_count, sizeof(idx_walk_entry));
    if (!entries) { free(data); return __LINE__; }

    crc32_init();

    /* Pass 1: walk headers, locate zlib streams, learn next_offset. */
    pos = 12;
    for (i = 0; i < object_count; i++) {
        u32 type;
        u64 size;
        u64 header_start = pos;
        u64 zlib_start;
        u64 zlib_end;
        buf decompressed;
        u64 consumed = 0;

        entries[i].offset = header_start;

        rc = parse_obj_header(&type, &size, data, data_len, &pos);
        if (rc) { rc = __LINE__; goto done; }

        entries[i].raw_type = type;
        entries[i].decompressed_size = size;

        if (type == GUT_PACK_OBJ_OFS_DELTA) {
            u64 delta_back;
            rc = parse_ofs_delta_offset(&delta_back, data, data_len, &pos);
            if (rc) { rc = __LINE__; goto done; }
            entries[i].base_abs_offset = header_start - delta_back;
        } else if (type == GUT_PACK_OBJ_REF_DELTA) {
            if (pos + oid_raw > data_len) { rc = __LINE__; goto done; }
            memset(entries[i].base_oid.bytes, 0,
                   sizeof(entries[i].base_oid.bytes));
            memcpy(entries[i].base_oid.bytes, data + pos, oid_raw);
            pos += oid_raw;
            entries[i].is_ref_delta = 1;
        } else if (type < 1 || type > 4) {
            rc = __LINE__; goto done;
        }

        /* zlib stream: 2-byte header + raw deflate + 4-byte adler32 */
        zlib_start = pos;
        if (zlib_start + 2 > data_len) { rc = __LINE__; goto done; }
        entries[i].data_start = zlib_start;

        rc = buf_create(&decompressed, size + 64);
        if (rc) { rc = __LINE__; goto done; }
        rc = deflate_decompress_consumed(&decompressed,
                                         data + zlib_start + 2,
                                         data_len - (zlib_start + 2),
                                         &consumed);
        buf_destroy(&decompressed);
        if (rc) { rc = __LINE__; goto done; }

        zlib_end = zlib_start + 2 + consumed + 4; /* +4 for adler32 */
        if (zlib_end > data_len - oid_raw) {
            rc = __LINE__; goto done;
        }
        entries[i].next_offset = zlib_end;
        pos = zlib_end;

        entries[i].crc32 = crc32_compute(data + header_start,
                                         zlib_end - header_start);
    }

    /* Pass 2: resolve iteratively until stable. */
    for (;;) {
        int made_progress = 0;
        u64 unresolved = 0;

        for (i = 0; i < object_count; i++) {
            idx_walk_entry *e = &entries[i];
            if (e->resolved) continue;

            if (e->raw_type >= 1 && e->raw_type <= 4) {
                rc = buf_create(&e->content, e->decompressed_size + 64);
                if (rc) { rc = __LINE__; goto done; }
                rc = deflate_decompress(&e->content,
                                        data + e->data_start + 2,
                                        data_len - (e->data_start + 2));
                if (rc) { rc = __LINE__; goto done; }

                e->obj_type = pack_type_to_obj_type(e->raw_type);
                rc = obj_hash_algo(&e->oid, algo, e->obj_type,
                                   e->content.data, e->content.len);
                if (rc) { rc = __LINE__; goto done; }
                e->resolved = 1;
                made_progress = 1;
                continue;
            }

            {
                idx_walk_entry *base = NULL;
                u64 j;

                if (e->is_ref_delta) {
                    for (j = 0; j < object_count; j++) {
                        if (entries[j].resolved &&
                            memcmp(entries[j].oid.bytes,
                                   e->base_oid.bytes,
                                   oid_raw) == 0) {
                            base = &entries[j]; break;
                        }
                    }
                } else {
                    for (j = 0; j < object_count; j++) {
                        if (entries[j].offset == e->base_abs_offset) {
                            base = &entries[j]; break;
                        }
                    }
                }
                if (!base || !base->resolved) { unresolved++; continue; }

                {
                    buf delta_bytes;
                    rc = buf_create(&delta_bytes,
                                    e->decompressed_size + 64);
                    if (rc) { rc = __LINE__; goto done; }
                    rc = deflate_decompress(&delta_bytes,
                                            data + e->data_start + 2,
                                            data_len - (e->data_start + 2));
                    if (rc) {
                        buf_destroy(&delta_bytes);
                        rc = __LINE__; goto done;
                    }
                    rc = apply_delta(&e->content,
                                     base->content.data, base->content.len,
                                     delta_bytes.data, delta_bytes.len);
                    buf_destroy(&delta_bytes);
                    if (rc) { rc = __LINE__; goto done; }
                }
                e->obj_type = base->obj_type;
                rc = obj_hash_algo(&e->oid, algo, e->obj_type,
                                   e->content.data, e->content.len);
                if (rc) { rc = __LINE__; goto done; }
                e->resolved = 1;
                made_progress = 1;
            }
        }
        if (unresolved == 0) break;
        if (!made_progress) { rc = __LINE__; goto done; }
    }

    /* Sort by OID */
    {
        u64 a, b;
        for (a = 1; a < object_count; a++) {
            idx_walk_entry tmp = entries[a];
            b = a;
            while (b > 0 &&
                   memcmp(entries[b - 1].oid.bytes,
                          tmp.oid.bytes, oid_raw) > 0) {
                entries[b] = entries[b - 1];
                b--;
            }
            entries[b] = tmp;
        }
    }

    {
        u64 k;
        int fi;
        memset(fanout, 0, sizeof(fanout));
        for (k = 0; k < object_count; k++) {
            fanout[entries[k].oid.bytes[0]]++;
        }
        for (fi = 1; fi < 256; fi++) fanout[fi] += fanout[fi - 1];
    }

    /* Write the .idx */
    path_len = strlen(pack_path);
    if (path_len < 5 || strcmp(pack_path + path_len - 5, ".pack") != 0) {
        rc = __LINE__; goto done;
    }
    if (path_len >= sizeof(idx_path)) { rc = __LINE__; goto done; }
    memcpy(idx_path, pack_path, path_len - 5);
    memcpy(idx_path + path_len - 5, ".idx", 5);

    fp = fopen(idx_path, "wb");
    if (!fp) {
        fprintf(stderr, "pack_index_create: cannot open '%s' for writing\n", idx_path);
        rc = __LINE__; goto done;
    }

    ph_init(&idx_hash, algo);

    wr32(buf4, GUT_IDX_MAGIC);
    if (fwrite(buf4, 1, 4, fp) != 4) { rc = __LINE__; goto done; }
    ph_update(&idx_hash, buf4, 4);
    wr32(buf4, GUT_IDX_VERSION);
    if (fwrite(buf4, 1, 4, fp) != 4) { rc = __LINE__; goto done; }
    ph_update(&idx_hash, buf4, 4);

    {
        int fi;
        for (fi = 0; fi < 256; fi++) {
            wr32(buf4, fanout[fi]);
            if (fwrite(buf4, 1, 4, fp) != 4) { rc = __LINE__; goto done; }
            ph_update(&idx_hash, buf4, 4);
        }
    }

    for (i = 0; i < object_count; i++) {
        if (fwrite(entries[i].oid.bytes, 1, oid_raw, fp)
            != oid_raw) { rc = __LINE__; goto done; }
        ph_update(&idx_hash, entries[i].oid.bytes, oid_raw);
    }

    for (i = 0; i < object_count; i++) {
        wr32(buf4, entries[i].crc32);
        if (fwrite(buf4, 1, 4, fp) != 4) { rc = __LINE__; goto done; }
        ph_update(&idx_hash, buf4, 4);
    }

    {
        u64 *large = NULL;
        u64 large_count = 0;
        u64 li;

        for (i = 0; i < object_count; i++) {
            if (entries[i].offset > 0x7FFFFFFFu) large_count++;
        }
        if (large_count > 0) {
            large = (u64 *)malloc(large_count * sizeof(u64));
            if (!large) { rc = __LINE__; goto done; }
        }

        li = 0;
        for (i = 0; i < object_count; i++) {
            if (entries[i].offset > 0x7FFFFFFFu) {
                if (li > 0x7FFFFFFFu) {
                    free(large); rc = __LINE__; goto done;
                }
                large[li] = entries[i].offset;
                wr32(buf4, 0x80000000u | (u32)li);
                li++;
            } else {
                wr32(buf4, (u32)entries[i].offset);
            }
            if (fwrite(buf4, 1, 4, fp) != 4) {
                free(large); rc = __LINE__; goto done;
            }
            ph_update(&idx_hash, buf4, 4);
        }

        for (li = 0; li < large_count; li++) {
            u8 buf8[8];
            wr64(buf8, large[li]);
            if (fwrite(buf8, 1, 8, fp) != 8) {
                free(large); rc = __LINE__; goto done;
            }
            ph_update(&idx_hash, buf8, 8);
        }
        free(large);
    }

    if (fwrite(pack_trailer, 1, oid_raw, fp) != oid_raw) {
        rc = __LINE__; goto done;
    }
    ph_update(&idx_hash, pack_trailer, oid_raw);

    ph_final(idx_digest, &idx_hash);
    if (fwrite(idx_digest, 1, oid_raw, fp) != oid_raw) {
        rc = __LINE__; goto done;
    }

    fclose(fp);
    fp = NULL;

    if (pack_sha1_hex_out) {
        u32 k;
        static const char hex[] = "0123456789abcdef";
        for (k = 0; k < oid_raw; k++) {
            pack_sha1_hex_out[k * 2]     = hex[pack_trailer[k] >> 4];
            pack_sha1_hex_out[k * 2 + 1] = hex[pack_trailer[k] & 0xF];
        }
        pack_sha1_hex_out[hex_len] = '\0';
    }

    rc = 0;

done:
    if (fp) fclose(fp);
    if (entries) {
        u32 k;
        for (k = 0; k < object_count; k++) {
            if (entries[k].resolved) buf_destroy(&entries[k].content);
        }
        free(entries);
    }
    free(data);
    return rc;
}

unsigned long pack_index_create(const char *pack_path,
                                char *pack_sha1_hex_out) {
    return pack_index_create_algo(pack_path, pack_sha1_hex_out, GUT_HASH_SHA1);
}
