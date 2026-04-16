#include "gut/odb.h"
#include "gut/pack.h"
#include "apennines/zlib_wrap.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <dirent.h>

#ifdef _WIN32
#include <direct.h>
#define gut_mkdir(p) _mkdir(p)
#else
#include <unistd.h>
#define gut_mkdir(p) mkdir(p, 0755)
#endif

unsigned long odb_open(gut_odb *out, const char *objects_dir) {
    if (!out) return __LINE__;
    if (!objects_dir) return __LINE__;
    if (strlen(objects_dir) >= sizeof(out->objects_dir)) return __LINE__;
    memcpy(out->objects_dir, objects_dir, strlen(objects_dir) + 1);
    out->pack_count = 0;
    out->packs_loaded = 0;
    return 0;
}

/* Lazy-load packfiles from objects/pack/ on first need */
static unsigned long odb_load_packs(gut_odb *odb) {
    char pack_dir[2048];
    DIR *d;
    struct dirent *ent;

    if (odb->packs_loaded) return 0;
    odb->packs_loaded = 1;

    snprintf(pack_dir, sizeof(pack_dir), "%s/pack", odb->objects_dir);
    d = opendir(pack_dir);
    if (!d) return 0; /* no pack dir is fine */

    while ((ent = readdir(d)) != NULL) {
        size_t nlen = strlen(ent->d_name);
        if (nlen > 5 && strcmp(ent->d_name + nlen - 5, ".pack") == 0) {
            if (odb->pack_count >= GUT_ODB_MAX_PACKS) break;
            {
                char pack_path[2048];
                gut_pack *p = (gut_pack *)malloc(sizeof(gut_pack));
                if (!p) continue;
                snprintf(pack_path, sizeof(pack_path), "%s/%s", pack_dir, ent->d_name);
                if (pack_open(p, pack_path) == 0) {
                    odb->packs[odb->pack_count++] = (void *)p;
                } else {
                    free(p);
                }
            }
        }
    }
    closedir(d);
    return 0;
}

/* Try to read an object from packfiles */
static unsigned long odb_read_packed(gut_object *out, gut_odb *odb, gut_oid *oid) {
    u32 i;
    unsigned long rc;

    rc = odb_load_packs(odb);
    if (rc) return __LINE__;

    for (i = 0; i < odb->pack_count; i++) {
        gut_pack *p = (gut_pack *)odb->packs[i];
        u64 offset;
        unsigned long found;

        rc = pack_idx_lookup(&offset, &found, &p->idx, oid);
        if (rc) continue;
        if (!found) continue;

        rc = pack_read_object(out, p, offset);
        if (rc == 0) return 0;
    }

    return __LINE__; /* not found in any pack */
}

unsigned long odb_object_path(char *out, u64 out_size, gut_odb *odb, gut_oid *oid) {
    char prefix[3];
    char suffix[39];
    int n;
    unsigned long rc;

    if (!out) return __LINE__;
    if (!odb) return __LINE__;
    if (!oid) return __LINE__;

    rc = oid_path_prefix(prefix, oid);
    if (rc) return __LINE__;
    rc = oid_path_suffix(suffix, oid);
    if (rc) return __LINE__;

    n = snprintf(out, (size_t)out_size, "%s/%s/%s", odb->objects_dir, prefix, suffix);
    if (n < 0 || (u64)n >= out_size) return __LINE__;

    return 0;
}

unsigned long odb_exists(unsigned long *found, gut_odb *odb, gut_oid *oid) {
    char path[2048];
    struct stat st;
    unsigned long rc;

    if (!found) return __LINE__;
    if (!odb) return __LINE__;
    if (!oid) return __LINE__;

    rc = odb_object_path(path, sizeof(path), odb, oid);
    if (rc) return __LINE__;

    if (stat(path, &st) == 0) {
        *found = 1;
        return 0;
    }

    /* Check packfiles */
    {
        u32 i;
        odb_load_packs(odb);
        for (i = 0; i < odb->pack_count; i++) {
            gut_pack *p = (gut_pack *)odb->packs[i];
            u64 offset;
            unsigned long pack_found;
            if (pack_idx_lookup(&offset, &pack_found, &p->idx, oid) == 0 && pack_found) {
                *found = 1;
                return 0;
            }
        }
    }

    *found = 0;
    return 0;
}

unsigned long odb_read(gut_object *out, gut_odb *odb, gut_oid *oid) {
    char path[2048];
    FILE *fp;
    buf compressed;
    buf raw;
    long file_size;
    unsigned long rc;
    gut_obj_type type;
    u64 content_size;
    u8 *content;

    if (!out) return __LINE__;
    if (!odb) return __LINE__;
    if (!oid) return __LINE__;

    rc = odb_object_path(path, sizeof(path), odb, oid);
    if (rc) return __LINE__;

    fp = fopen(path, "rb");
    if (!fp) {
        /* Loose object not found — try packfiles */
        return odb_read_packed(out, odb, oid);
    }

    fseek(fp, 0, SEEK_END);
    file_size = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    if (file_size <= 0) { fclose(fp); return __LINE__; }

    rc = buf_create(&compressed, (u64)file_size);
    if (rc) { fclose(fp); return __LINE__; }

    if (fread(compressed.data, 1, (size_t)file_size, fp) != (size_t)file_size) {
        fclose(fp);
        buf_destroy(&compressed);
        return __LINE__;
    }
    compressed.len = (u64)file_size;
    fclose(fp);

    /* Decompress */
    rc = buf_create(&raw, (u64)file_size * 4);
    if (rc) { buf_destroy(&compressed); return __LINE__; }

    rc = zlib_decompress(&raw, compressed.data, compressed.len);
    buf_destroy(&compressed);
    if (rc) { buf_destroy(&raw); return __LINE__; }

    /* Parse header */
    rc = obj_parse_header(&type, &content_size, &content, raw.data, raw.len);
    if (rc) { buf_destroy(&raw); return __LINE__; }

    /* Copy content into object */
    out->type = type;
    out->size = content_size;
    rc = buf_create(&out->data, content_size);
    if (rc) { buf_destroy(&raw); return __LINE__; }

    if (content_size > 0) {
        memcpy(out->data.data, content, (size_t)content_size);
        out->data.len = content_size;
    }

    buf_destroy(&raw);
    return 0;
}

unsigned long odb_write(gut_oid *out, gut_odb *odb, gut_obj_type type, u8 *data, u64 len) {
    buf serialized;
    buf compressed;
    gut_oid oid;
    char path[2048];
    char dir_path[2048];
    char prefix[3];
    FILE *fp;
    unsigned long rc;
    unsigned long exists;

    if (!odb) return __LINE__;
    if (len > 0 && !data) return __LINE__;

    /* Serialize: "<type> <size>\0<data>" */
    rc = buf_create(&serialized, len + 64);
    if (rc) return __LINE__;

    rc = obj_serialize(&serialized, type, data, len);
    if (rc) { buf_destroy(&serialized); return __LINE__; }

    /* Compute OID */
    rc = oid_hash(&oid, serialized.data, serialized.len);
    if (rc) { buf_destroy(&serialized); return __LINE__; }

    /* Check if already exists */
    rc = odb_exists(&exists, odb, &oid);
    if (rc) { buf_destroy(&serialized); return __LINE__; }

    if (exists) {
        buf_destroy(&serialized);
        if (out) memcpy(out->bytes, oid.bytes, GUT_OID_RAW_SIZE);
        return 0;
    }

    /* Compress */
    rc = buf_create(&compressed, serialized.len);
    if (rc) { buf_destroy(&serialized); return __LINE__; }

    rc = zlib_compress(&compressed, serialized.data, serialized.len);
    buf_destroy(&serialized);
    if (rc) { buf_destroy(&compressed); return __LINE__; }

    /* Ensure fan-out directory exists */
    rc = oid_path_prefix(prefix, &oid);
    if (rc) { buf_destroy(&compressed); return __LINE__; }

    snprintf(dir_path, sizeof(dir_path), "%s/%s", odb->objects_dir, prefix);
    gut_mkdir(dir_path);

    /* Write file */
    rc = odb_object_path(path, sizeof(path), odb, &oid);
    if (rc) { buf_destroy(&compressed); return __LINE__; }

    fp = fopen(path, "wb");
    if (!fp) { buf_destroy(&compressed); return __LINE__; }

    if (fwrite(compressed.data, 1, (size_t)compressed.len, fp) != (size_t)compressed.len) {
        fclose(fp);
        buf_destroy(&compressed);
        return __LINE__;
    }

    fclose(fp);
    buf_destroy(&compressed);

    if (out) memcpy(out->bytes, oid.bytes, GUT_OID_RAW_SIZE);
    return 0;
}

unsigned long odb_write_file(gut_oid *out, gut_odb *odb, const char *path) {
    FILE *fp;
    long file_size;
    u8 *data;
    unsigned long rc;

    if (!odb) return __LINE__;
    if (!path) return __LINE__;

    fp = fopen(path, "rb");
    if (!fp) return __LINE__;

    fseek(fp, 0, SEEK_END);
    file_size = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    if (file_size < 0) { fclose(fp); return __LINE__; }

    if (file_size == 0) {
        fclose(fp);
        return odb_write(out, odb, GUT_OBJ_BLOB, NULL, 0);
    }

    data = (u8 *)malloc((size_t)file_size);
    if (!data) { fclose(fp); return __LINE__; }

    if (fread(data, 1, (size_t)file_size, fp) != (size_t)file_size) {
        fclose(fp);
        free(data);
        return __LINE__;
    }
    fclose(fp);

    rc = odb_write(out, odb, GUT_OBJ_BLOB, data, (u64)file_size);
    free(data);
    return rc;
}
