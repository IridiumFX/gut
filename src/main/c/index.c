#include "gut/index.h"
#include "gut/sha1.h"
#include "gut/odb.h"
#include "gut/object.h"
#include "apennines/buf.h"
#include "apennines/hash.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <fcntl.h>
#include <sys/stat.h>

#ifdef _WIN32
#include <windows.h>
#include <io.h>
#else
#include <unistd.h>
#endif

#ifndef O_BINARY
#define O_BINARY 0
#endif

/* Atomic-replace rename */
static int idx_atomic_rename(const char *from, const char *to) {
#ifdef _WIN32
    return MoveFileExA(from, to,
                       MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH) ? 0 : -1;
#else
    return rename(from, to);
#endif
}

/* Big-endian read/write helpers */
static u32 read_u32(const u8 *p) {
    return ((u32)p[0] << 24) | ((u32)p[1] << 16) | ((u32)p[2] << 8) | (u32)p[3];
}

static u16 read_u16(const u8 *p) {
    return (u16)(((u16)p[0] << 8) | (u16)p[1]);
}

static void write_u32(u8 *p, u32 v) {
    p[0] = (u8)(v >> 24);
    p[1] = (u8)(v >> 16);
    p[2] = (u8)(v >> 8);
    p[3] = (u8)(v);
}

static void write_u16(u8 *p, u16 v) {
    p[0] = (u8)(v >> 8);
    p[1] = (u8)(v);
}

unsigned long index_init(gut_index *out) {
    if (!out) return __LINE__;
    out->entries = NULL;
    out->count = 0;
    out->capacity = 0;
    out->hash_algo = GUT_HASH_SHA1; /* callers override from repo */
    return 0;
}

unsigned long index_read(gut_index *out, const char *path) {
    FILE *fp;
    long file_size;
    u8 *data;
    u64 pos;
    u32 sig, ver, entry_count;
    u32 i;
    u8 computed_hash[GUT_OID_MAX_RAW_SIZE];
    unsigned long rc;
    unsigned trailer_size;

    if (!out) return __LINE__;
    if (!path) return __LINE__;

    /* Normalize hash_algo: if caller didn't set a valid value, default
     * to SHA-1 so uninitialized `gut_index idx;` still works. */
    if (out->hash_algo != GUT_HASH_SHA256 && out->hash_algo != GUT_HASH_SHA1) {
        out->hash_algo = GUT_HASH_SHA1;
    }

    fp = fopen(path, "rb");
    if (!fp) {
        gut_hash_algo preserve = out->hash_algo;
        index_init(out);
        out->hash_algo = preserve;
        return 0;
    }

    fseek(fp, 0, SEEK_END);
    file_size = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    trailer_size = (out->hash_algo == GUT_HASH_SHA256) ? 32 : GUT_SHA1_DIGEST_SIZE;

    if (file_size < 12 + trailer_size) {
        fclose(fp);
        return __LINE__;
    }

    data = (u8 *)malloc((size_t)file_size);
    if (!data) { fclose(fp); return __LINE__; }

    if (fread(data, 1, (size_t)file_size, fp) != (size_t)file_size) {
        free(data);
        fclose(fp);
        return __LINE__;
    }
    fclose(fp);

    /* Verify checksum using the repo's hash algo */
    if (out->hash_algo == GUT_HASH_SHA256) {
        rc = sha256_digest(computed_hash, data, (u64)file_size - trailer_size);
    } else {
        rc = sha1_digest(computed_hash, data, (u64)file_size - trailer_size);
    }
    if (rc) { free(data); return __LINE__; }
    if (memcmp(computed_hash, data + file_size - trailer_size,
               trailer_size) != 0) {
        free(data);
        return __LINE__;
    }

    /* Parse header */
    sig = read_u32(data);
    ver = read_u32(data + 4);
    entry_count = read_u32(data + 8);

    if (sig != GUT_INDEX_SIGNATURE) { free(data); return __LINE__; }
    if (ver != GUT_INDEX_VERSION) { free(data); return __LINE__; }

    {
        gut_hash_algo preserve = out->hash_algo;
        rc = index_init(out);
        out->hash_algo = preserve;
    }
    if (rc) { free(data); return __LINE__; }

    pos = 12;

    for (i = 0; i < entry_count; i++) {
        gut_index_entry entry;
        u64 path_start;
        u64 path_len;

        if (pos + (42 + gut_oid_raw_size(out->hash_algo))
            > (u64)file_size - trailer_size) {
            free(data);
            index_destroy(out);
            return __LINE__;
        }

        {
            unsigned oid_raw = gut_oid_raw_size(out->hash_algo);
            u64 flags_off = (u64)40 + oid_raw;
            u64 path_off_from_pos = flags_off + 2;

            entry.ctime_sec  = read_u32(data + pos);
            entry.ctime_nsec = read_u32(data + pos + 4);
            entry.mtime_sec  = read_u32(data + pos + 8);
            entry.mtime_nsec = read_u32(data + pos + 12);
            entry.dev        = read_u32(data + pos + 16);
            entry.ino        = read_u32(data + pos + 20);
            entry.mode       = read_u32(data + pos + 24);
            entry.uid        = read_u32(data + pos + 28);
            entry.gid        = read_u32(data + pos + 32);
            entry.file_size  = read_u32(data + pos + 36);
            memset(entry.oid.bytes, 0, sizeof(entry.oid.bytes));
            memcpy(entry.oid.bytes, data + pos + 40, oid_raw);
            entry.flags      = read_u16(data + pos + flags_off);

            path_start = pos + path_off_from_pos;
        }
        path_len = entry.flags & 0x0FFF;

        /* Find actual NUL terminator in case path_len was truncated */
        {
            unsigned trailer_size =
                (out->hash_algo == GUT_HASH_SHA256) ? 32 : GUT_SHA1_DIGEST_SIZE;
            u64 scan = path_start;
            while (scan < (u64)file_size - trailer_size && data[scan] != '\0') {
                scan++;
            }
            path_len = scan - path_start;
        }

        entry.path = (char *)malloc((size_t)(path_len + 1));
        if (!entry.path) {
            free(data);
            index_destroy(out);
            return __LINE__;
        }
        memcpy(entry.path, data + path_start, (size_t)path_len);
        entry.path[path_len] = '\0';

        /* Entries padded with 1-8 NUL bytes to 8-byte boundary.
         * Entry prelude is (stat:40 + oid:20-or-32 + flags:2) = 62 or 74. */
        {
            u64 prelude = 42 + gut_oid_raw_size(out->hash_algo);
            pos += (prelude + path_len + 8) & ~(u64)7;
        }

        /* Add to index */
        if (out->count >= out->capacity) {
            u64 new_cap = out->capacity == 0 ? 16 : out->capacity * 2;
            gut_index_entry *new_entries = (gut_index_entry *)realloc(
                out->entries, (size_t)(new_cap * sizeof(gut_index_entry)));
            if (!new_entries) {
                free(entry.path);
                free(data);
                index_destroy(out);
                return __LINE__;
            }
            out->entries = new_entries;
            out->capacity = new_cap;
        }
        out->entries[out->count++] = entry;
    }

    free(data);
    return 0;
}

unsigned long index_write(gut_index *idx, const char *path) {
    buf b;
    u8 header[12];
    u8 checksum[GUT_OID_MAX_RAW_SIZE];
    unsigned long rc;
    u64 i;
    unsigned oid_raw = gut_oid_raw_size(idx->hash_algo);
    unsigned trailer_size =
        (idx->hash_algo == GUT_HASH_SHA256) ? 32 : GUT_SHA1_DIGEST_SIZE;
    u64 prelude = 42 + oid_raw;  /* stat(40) + oid + flags(2) */

    if (!idx) return __LINE__;
    if (!path) return __LINE__;

    rc = buf_create(&b, 4096);
    if (rc) return __LINE__;

    /* Header */
    write_u32(header, GUT_INDEX_SIGNATURE);
    write_u32(header + 4, GUT_INDEX_VERSION);
    write_u32(header + 8, (u32)idx->count);
    rc = buf_append(&b, header, 12);
    if (rc) { buf_destroy(&b); return __LINE__; }

    /* Entries */
    for (i = 0; i < idx->count; i++) {
        gut_index_entry *e = &idx->entries[i];
        u8 entry_data[80]; /* big enough for prelude=74 (SHA-256) */
        u64 path_len = strlen(e->path);
        u64 entry_len;
        u64 padded;
        u16 flags;

        write_u32(entry_data,      e->ctime_sec);
        write_u32(entry_data + 4,  e->ctime_nsec);
        write_u32(entry_data + 8,  e->mtime_sec);
        write_u32(entry_data + 12, e->mtime_nsec);
        write_u32(entry_data + 16, e->dev);
        write_u32(entry_data + 20, e->ino);
        write_u32(entry_data + 24, e->mode);
        write_u32(entry_data + 28, e->uid);
        write_u32(entry_data + 32, e->gid);
        write_u32(entry_data + 36, e->file_size);
        memcpy(entry_data + 40, e->oid.bytes, oid_raw);

        flags = (u16)(path_len < 0x0FFF ? path_len : 0x0FFF);
        write_u16(entry_data + 40 + oid_raw, flags);

        rc = buf_append(&b, entry_data, prelude);
        if (rc) { buf_destroy(&b); return __LINE__; }

        rc = buf_append(&b, (u8 *)e->path, path_len);
        if (rc) { buf_destroy(&b); return __LINE__; }

        /* NUL + padding to 8-byte alignment */
        entry_len = prelude + path_len;
        padded = (entry_len + 8) & ~(u64)7;
        {
            u64 pad_count = padded - entry_len;
            u8 zeros[8] = {0};
            rc = buf_append(&b, zeros, pad_count);
            if (rc) { buf_destroy(&b); return __LINE__; }
        }
    }

    /* Compute trailer checksum using the repo's algo */
    if (idx->hash_algo == GUT_HASH_SHA256) {
        rc = sha256_digest(checksum, b.data, b.len);
    } else {
        rc = sha1_digest(checksum, b.data, b.len);
    }
    if (rc) { buf_destroy(&b); return __LINE__; }

    rc = buf_append(&b, checksum, trailer_size);
    if (rc) { buf_destroy(&b); return __LINE__; }

    /* Atomic write: go through <path>.lock with O_EXCL, then rename */
    {
        char lock_path[2048];
        int fd;
        int n = snprintf(lock_path, sizeof(lock_path), "%s.lock", path);
        if (n < 0 || (u64)n >= sizeof(lock_path)) { buf_destroy(&b); return __LINE__; }

#ifdef _WIN32
        fd = _open(lock_path, _O_WRONLY | _O_CREAT | _O_EXCL | _O_BINARY,
                   _S_IREAD | _S_IWRITE);
#else
        fd = open(lock_path, O_WRONLY | O_CREAT | O_EXCL | O_BINARY, 0644);
#endif
        if (fd < 0) {
            /* Lock held by another writer — fail rather than race */
            buf_destroy(&b);
            return __LINE__;
        }

        {
#ifdef _WIN32
            int w = _write(fd, b.data, (unsigned)b.len);
#else
            ssize_t w = write(fd, b.data, (size_t)b.len);
#endif
            if (w != (int)b.len) {
#ifdef _WIN32
                _close(fd);
#else
                close(fd);
#endif
                remove(lock_path);
                buf_destroy(&b);
                return __LINE__;
            }
        }

#ifdef _WIN32
        _close(fd);
#else
        close(fd);
#endif

        if (idx_atomic_rename(lock_path, path) != 0) {
            remove(lock_path);
            buf_destroy(&b);
            return __LINE__;
        }
    }

    buf_destroy(&b);
    return 0;
}

unsigned long index_add(gut_index *idx, const char *path, gut_oid *oid,
                        u32 mode, u32 file_size, u32 mtime_sec) {
    u64 pos;
    unsigned long rc;
    gut_index_entry entry;

    if (!idx) return __LINE__;
    if (!path) return __LINE__;
    if (!oid) return __LINE__;

    /* Check if entry already exists */
    rc = index_find(&pos, idx, path);
    if (rc) return __LINE__;

    if (pos < idx->count && strcmp(idx->entries[pos].path, path) == 0) {
        /* Update existing entry */
        memcpy(idx->entries[pos].oid.bytes, oid->bytes, sizeof(oid->bytes));
        idx->entries[pos].mode = mode;
        idx->entries[pos].file_size = file_size;
        idx->entries[pos].mtime_sec = mtime_sec;
        idx->entries[pos].flags = (u16)(strlen(path) < 0x0FFF ? strlen(path) : 0x0FFF);
        return 0;
    }

    /* Create new entry */
    memset(&entry, 0, sizeof(entry));
    entry.mode = mode;
    entry.file_size = file_size;
    entry.mtime_sec = mtime_sec;
    memcpy(entry.oid.bytes, oid->bytes, sizeof(oid->bytes));
    entry.flags = (u16)(strlen(path) < 0x0FFF ? strlen(path) : 0x0FFF);
    entry.path = (char *)malloc(strlen(path) + 1);
    if (!entry.path) return __LINE__;
    memcpy(entry.path, path, strlen(path) + 1);

    /* Grow if needed */
    if (idx->count >= idx->capacity) {
        u64 new_cap = idx->capacity == 0 ? 16 : idx->capacity * 2;
        gut_index_entry *new_entries = (gut_index_entry *)realloc(
            idx->entries, (size_t)(new_cap * sizeof(gut_index_entry)));
        if (!new_entries) {
            free(entry.path);
            return __LINE__;
        }
        idx->entries = new_entries;
        idx->capacity = new_cap;
    }

    /* Insert at sorted position */
    if (pos < idx->count) {
        memmove(&idx->entries[pos + 1], &idx->entries[pos],
                (size_t)((idx->count - pos) * sizeof(gut_index_entry)));
    }
    idx->entries[pos] = entry;
    idx->count++;

    return 0;
}

unsigned long index_remove(gut_index *idx, const char *path) {
    u64 pos;
    unsigned long rc;

    if (!idx) return __LINE__;
    if (!path) return __LINE__;

    rc = index_find(&pos, idx, path);
    if (rc) return __LINE__;

    if (pos >= idx->count || strcmp(idx->entries[pos].path, path) != 0) {
        return __LINE__; /* not found */
    }

    free(idx->entries[pos].path);

    if (pos < idx->count - 1) {
        memmove(&idx->entries[pos], &idx->entries[pos + 1],
                (size_t)((idx->count - pos - 1) * sizeof(gut_index_entry)));
    }
    idx->count--;
    return 0;
}

unsigned long index_find(u64 *pos, gut_index *idx, const char *path) {
    u64 lo, hi;

    if (!pos) return __LINE__;
    if (!idx) return __LINE__;
    if (!path) return __LINE__;

    lo = 0;
    hi = idx->count;

    while (lo < hi) {
        u64 mid = lo + (hi - lo) / 2;
        int cmp = strcmp(idx->entries[mid].path, path);
        if (cmp < 0) {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }

    *pos = lo;
    return 0;
}

unsigned long index_destroy(gut_index *idx) {
    u64 i;
    if (!idx) return __LINE__;
    for (i = 0; i < idx->count; i++) {
        free(idx->entries[i].path);
    }
    free(idx->entries);
    idx->entries = NULL;
    idx->count = 0;
    idx->capacity = 0;
    return 0;
}

/* Recursive helper: write a tree for entries sharing a common directory prefix */
static unsigned long write_tree_recursive(gut_oid *out, gut_index_entry *entries,
                                          u64 count, const char *prefix,
                                          u64 prefix_len, const char *objects_dir,
                                          gut_hash_algo algo) {
    gut_odb odb;
    buf tree_data;
    u64 i;
    unsigned long rc;
    unsigned oid_raw = gut_oid_raw_size(algo);

    (void)prefix;

    rc = odb_open(&odb, objects_dir);
    if (rc) return __LINE__;
    odb.hash_algo = algo;

    rc = buf_create(&tree_data, 256);
    if (rc) return __LINE__;

    i = 0;
    while (i < count) {
        const char *entry_path = entries[i].path + prefix_len;
        const char *slash = strchr(entry_path, '/');

        if (!slash) {
            /* Leaf entry (file) */
            char mode_str[16];
            int mode_len = snprintf(mode_str, sizeof(mode_str), "%o", entries[i].mode);
            if (mode_len < 0) { buf_destroy(&tree_data); return __LINE__; }

            rc = buf_append(&tree_data, (u8 *)mode_str, (u64)mode_len);
            if (rc) { buf_destroy(&tree_data); return __LINE__; }
            rc = buf_append_byte(&tree_data, ' ');
            if (rc) { buf_destroy(&tree_data); return __LINE__; }
            rc = buf_append(&tree_data, (u8 *)entry_path, (u64)strlen(entry_path));
            if (rc) { buf_destroy(&tree_data); return __LINE__; }
            rc = buf_append_byte(&tree_data, '\0');
            if (rc) { buf_destroy(&tree_data); return __LINE__; }
            rc = buf_append(&tree_data, entries[i].oid.bytes, oid_raw);
            if (rc) { buf_destroy(&tree_data); return __LINE__; }

            i++;
        } else {
            /* Subtree: collect all entries under this directory */
            u64 dir_len = (u64)(slash - entry_path);
            char dir_name[1024];
            char sub_prefix[2048];
            u64 sub_start = i;
            u64 sub_count;
            gut_oid subtree_oid;

            if (dir_len >= sizeof(dir_name)) { buf_destroy(&tree_data); return __LINE__; }
            memcpy(dir_name, entry_path, (size_t)dir_len);
            dir_name[dir_len] = '\0';

            snprintf(sub_prefix, sizeof(sub_prefix), "%.*s%s/",
                     (int)prefix_len, entries[0].path, dir_name);

            /* Count entries in this subtree */
            while (i < count) {
                const char *p = entries[i].path + prefix_len;
                if (strncmp(p, dir_name, (size_t)dir_len) != 0 || p[dir_len] != '/') break;
                i++;
            }
            sub_count = i - sub_start;

            /* Recurse */
            rc = write_tree_recursive(&subtree_oid, entries + sub_start, sub_count,
                                      sub_prefix, (u64)strlen(sub_prefix),
                                      objects_dir, algo);
            if (rc) { buf_destroy(&tree_data); return __LINE__; }

            /* Write "40000 dirname\0<oid>" */
            rc = buf_append(&tree_data, (u8 *)"40000 ", 6);
            if (rc) { buf_destroy(&tree_data); return __LINE__; }
            rc = buf_append(&tree_data, (u8 *)dir_name, dir_len);
            if (rc) { buf_destroy(&tree_data); return __LINE__; }
            rc = buf_append_byte(&tree_data, '\0');
            if (rc) { buf_destroy(&tree_data); return __LINE__; }
            rc = buf_append(&tree_data, subtree_oid.bytes, oid_raw);
            if (rc) { buf_destroy(&tree_data); return __LINE__; }
        }
    }

    /* Write this tree object to ODB */
    rc = odb_write(out, &odb, GUT_OBJ_TREE, tree_data.data, tree_data.len);
    buf_destroy(&tree_data);
    if (rc) return __LINE__;

    return 0;
}

/* Recursive helper for index_read_tree */
static unsigned long read_tree_recursive(gut_index *idx, gut_odb *odb,
                                         gut_oid *tree_oid, const char *prefix) {
    gut_object obj;
    gut_tree tree;
    u64 i;
    unsigned long rc;

    rc = odb_read(&obj, odb, tree_oid);
    if (rc) return __LINE__;
    if (obj.type != GUT_OBJ_TREE) { object_destroy(&obj); return __LINE__; }

    rc = tree_parse_algo(&tree, obj.data.data, obj.data.len, odb->hash_algo);
    object_destroy(&obj);
    if (rc) return __LINE__;

    for (i = 0; i < tree.count; i++) {
        if (tree.entries[i].mode == 040000) {
            /* Subtree: recurse with extended prefix */
            char sub_prefix[2048];
            snprintf(sub_prefix, sizeof(sub_prefix), "%s%s/", prefix, tree.entries[i].name);
            rc = read_tree_recursive(idx, odb, &tree.entries[i].oid, sub_prefix);
            if (rc) { tree_destroy(&tree); return __LINE__; }
        } else if (tree.entries[i].mode == 0160000) {
            /* Submodule gitlink: the pinned commit OID belongs to the
             * *submodule's* object store, not ours — so we can't open
             * it as a blob. Skip the index entry entirely; submodule
             * checkout is a separate pass. */
            continue;
        } else {
            /* File entry: add to index */
            char full_path[2048];
            snprintf(full_path, sizeof(full_path), "%s%s", prefix, tree.entries[i].name);
            rc = index_add(idx, full_path, &tree.entries[i].oid,
                           tree.entries[i].mode, 0, 0);
            if (rc) { tree_destroy(&tree); return __LINE__; }
        }
    }

    tree_destroy(&tree);
    return 0;
}

unsigned long index_read_tree(gut_index *out, gut_odb *odb, gut_oid *tree_oid) {
    if (!out) return __LINE__;
    if (!odb) return __LINE__;
    if (!tree_oid) return __LINE__;

    /* Initialize fresh index (caller must destroy old index if needed) */
    index_init(out);

    return read_tree_recursive(out, odb, tree_oid, "");
}

unsigned long index_write_tree(gut_oid *out, gut_index *idx, const char *objects_dir) {
    if (!out) return __LINE__;
    if (!idx) return __LINE__;
    if (!objects_dir) return __LINE__;

    if (idx->count == 0) {
        /* Empty tree */
        gut_odb odb;
        unsigned long rc = odb_open(&odb, objects_dir);
        if (rc) return __LINE__;
        odb.hash_algo = idx->hash_algo;
        return odb_write(out, &odb, GUT_OBJ_TREE, NULL, 0);
    }

    return write_tree_recursive(out, idx->entries, idx->count, "", 0,
                                objects_dir, idx->hash_algo);
}
