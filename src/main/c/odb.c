#include "gut/odb.h"
#include "apennines/zlib_wrap.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

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
    return 0;
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

    *found = (stat(path, &st) == 0) ? 1 : 0;
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
    if (!fp) return __LINE__;

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
