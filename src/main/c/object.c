#include "gut/object.h"
#include "gut/odb.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

unsigned long obj_type_name(const char **out, gut_obj_type type) {
    if (!out) return __LINE__;
    switch (type) {
        case GUT_OBJ_BLOB:   *out = "blob";   return 0;
        case GUT_OBJ_TREE:   *out = "tree";   return 0;
        case GUT_OBJ_COMMIT: *out = "commit"; return 0;
        case GUT_OBJ_TAG:    *out = "tag";    return 0;
    }
    return __LINE__;
}

unsigned long obj_type_parse(gut_obj_type *out, const char *name, u64 len) {
    if (!out) return __LINE__;
    if (!name) return __LINE__;
    if (len == 4 && memcmp(name, "blob", 4) == 0)   { *out = GUT_OBJ_BLOB;   return 0; }
    if (len == 4 && memcmp(name, "tree", 4) == 0)   { *out = GUT_OBJ_TREE;   return 0; }
    if (len == 6 && memcmp(name, "commit", 6) == 0) { *out = GUT_OBJ_COMMIT; return 0; }
    if (len == 3 && memcmp(name, "tag", 3) == 0)    { *out = GUT_OBJ_TAG;    return 0; }
    return __LINE__;
}

unsigned long obj_serialize(buf *out, gut_obj_type type, u8 *data, u64 len) {
    const char *tname;
    char header[64];
    int header_len;
    unsigned long rc;

    if (!out) return __LINE__;
    if (len > 0 && !data) return __LINE__;

    rc = obj_type_name(&tname, type);
    if (rc) return __LINE__;

    header_len = snprintf(header, sizeof(header), "%s %llu", tname, (unsigned long long)len);
    if (header_len < 0) return __LINE__;

    /* header + NUL byte + data */
    rc = buf_append(out, (u8 *)header, (u64)header_len + 1);
    if (rc) return __LINE__;

    if (len > 0) {
        rc = buf_append(out, data, len);
        if (rc) return __LINE__;
    }

    return 0;
}

unsigned long obj_parse_header(gut_obj_type *type, u64 *content_size, u8 **content,
                               u8 *raw, u64 raw_len) {
    u64 i;
    u64 space_pos;
    u64 nul_pos;
    u64 size_val;
    unsigned long rc;

    if (!type) return __LINE__;
    if (!content_size) return __LINE__;
    if (!content) return __LINE__;
    if (!raw) return __LINE__;

    /* Find space separator */
    space_pos = 0;
    for (i = 0; i < raw_len; i++) {
        if (raw[i] == ' ') { space_pos = i; break; }
        if (raw[i] == '\0') return __LINE__;
    }
    if (i == raw_len) return __LINE__;

    /* Parse type */
    rc = obj_type_parse(type, (const char *)raw, space_pos);
    if (rc) return __LINE__;

    /* Find NUL terminator */
    nul_pos = 0;
    for (i = space_pos + 1; i < raw_len; i++) {
        if (raw[i] == '\0') { nul_pos = i; break; }
    }
    if (i == raw_len) return __LINE__;

    /* Parse size */
    size_val = 0;
    for (i = space_pos + 1; i < nul_pos; i++) {
        if (raw[i] < '0' || raw[i] > '9') return __LINE__;
        size_val = size_val * 10 + (raw[i] - '0');
    }

    if (nul_pos + 1 + size_val > raw_len) return __LINE__;

    *content_size = size_val;
    *content = raw + nul_pos + 1;
    return 0;
}

unsigned long obj_hash(gut_oid *out, gut_obj_type type, u8 *data, u64 len) {
    buf serialized;
    unsigned long rc;

    if (!out) return __LINE__;

    rc = buf_create(&serialized, len + 64);
    if (rc) return __LINE__;

    rc = obj_serialize(&serialized, type, data, len);
    if (rc) { buf_destroy(&serialized); return __LINE__; }

    rc = oid_hash(out, serialized.data, serialized.len);
    buf_destroy(&serialized);
    if (rc) return __LINE__;

    return 0;
}

unsigned long tree_parse(gut_tree *out, u8 *data, u64 len) {
    u64 pos;

    if (!out) return __LINE__;
    if (len > 0 && !data) return __LINE__;

    out->entries = NULL;
    out->count = 0;
    out->capacity = 0;

    pos = 0;
    while (pos < len) {
        u64 mode_end, name_start, name_end;
        u32 mode;
        gut_tree_entry entry;

        /* Parse mode (octal digits until space) */
        mode = 0;
        mode_end = pos;
        while (mode_end < len && data[mode_end] != ' ') {
            if (data[mode_end] < '0' || data[mode_end] > '7') return __LINE__;
            mode = mode * 8 + (data[mode_end] - '0');
            mode_end++;
        }
        if (mode_end >= len) return __LINE__;

        /* Skip space */
        name_start = mode_end + 1;

        /* Find NUL terminating the name */
        name_end = name_start;
        while (name_end < len && data[name_end] != '\0') {
            name_end++;
        }
        if (name_end >= len) return __LINE__;

        /* Need 20 bytes of OID after the NUL */
        if (name_end + 1 + GUT_OID_RAW_SIZE > len) return __LINE__;

        entry.mode = mode;
        entry.name = (char *)malloc(name_end - name_start + 1);
        if (!entry.name) return __LINE__;
        memcpy(entry.name, data + name_start, name_end - name_start);
        entry.name[name_end - name_start] = '\0';
        memcpy(entry.oid.bytes, data + name_end + 1, GUT_OID_RAW_SIZE);

        /* Grow entries array if needed */
        if (out->count >= out->capacity) {
            u64 new_cap = out->capacity == 0 ? 8 : out->capacity * 2;
            gut_tree_entry *new_entries = (gut_tree_entry *)realloc(
                out->entries, (size_t)(new_cap * sizeof(gut_tree_entry)));
            if (!new_entries) {
                free(entry.name);
                return __LINE__;
            }
            out->entries = new_entries;
            out->capacity = new_cap;
        }

        out->entries[out->count++] = entry;
        pos = name_end + 1 + GUT_OID_RAW_SIZE;
    }

    return 0;
}

unsigned long tree_destroy(gut_tree *tree) {
    u64 i;
    if (!tree) return __LINE__;
    for (i = 0; i < tree->count; i++) {
        free(tree->entries[i].name);
    }
    free(tree->entries);
    tree->entries = NULL;
    tree->count = 0;
    tree->capacity = 0;
    return 0;
}

unsigned long tree_add_entry(gut_tree *tree, u32 mode, const char *name, gut_oid *oid) {
    gut_tree_entry entry;

    if (!tree) return __LINE__;
    if (!name) return __LINE__;
    if (!oid) return __LINE__;

    entry.mode = mode;
    entry.name = (char *)malloc(strlen(name) + 1);
    if (!entry.name) return __LINE__;
    memcpy(entry.name, name, strlen(name) + 1);
    memcpy(entry.oid.bytes, oid->bytes, GUT_OID_RAW_SIZE);

    if (tree->count >= tree->capacity) {
        u64 new_cap = tree->capacity == 0 ? 8 : tree->capacity * 2;
        gut_tree_entry *new_entries = (gut_tree_entry *)realloc(
            tree->entries, (size_t)(new_cap * sizeof(gut_tree_entry)));
        if (!new_entries) {
            free(entry.name);
            return __LINE__;
        }
        tree->entries = new_entries;
        tree->capacity = new_cap;
    }

    tree->entries[tree->count++] = entry;
    return 0;
}

unsigned long tree_serialize(buf *out, gut_tree *tree) {
    u64 i;
    unsigned long rc;

    if (!out) return __LINE__;
    if (!tree) return __LINE__;

    for (i = 0; i < tree->count; i++) {
        char mode_str[16];
        int mode_len;

        mode_len = snprintf(mode_str, sizeof(mode_str), "%o", tree->entries[i].mode);
        if (mode_len < 0) return __LINE__;

        /* "<mode> <name>\0<20-byte-oid>" */
        rc = buf_append(out, (u8 *)mode_str, (u64)mode_len);
        if (rc) return __LINE__;

        rc = buf_append_byte(out, ' ');
        if (rc) return __LINE__;

        rc = buf_append(out, (u8 *)tree->entries[i].name,
                        (u64)strlen(tree->entries[i].name));
        if (rc) return __LINE__;

        rc = buf_append_byte(out, '\0');
        if (rc) return __LINE__;

        rc = buf_append(out, tree->entries[i].oid.bytes, GUT_OID_RAW_SIZE);
        if (rc) return __LINE__;
    }

    return 0;
}

/* Helper: find a line boundary in commit data */
static u64 find_line_end(u8 *data, u64 len, u64 start) {
    u64 i;
    for (i = start; i < len; i++) {
        if (data[i] == '\n') return i;
    }
    return len;
}

/* Helper: duplicate a substring */
static char *dup_range(u8 *data, u64 start, u64 end) {
    u64 sz = end - start;
    char *s = (char *)malloc((size_t)(sz + 1));
    if (!s) return NULL;
    memcpy(s, data + start, (size_t)sz);
    s[sz] = '\0';
    return s;
}

unsigned long commit_parse(gut_commit *out, u8 *data, u64 len) {
    u64 pos;
    u64 line_end;
    u64 parent_cap;

    if (!out) return __LINE__;
    if (!data) return __LINE__;

    memset(out, 0, sizeof(*out));
    parent_cap = 0;
    pos = 0;

    /* Parse "tree <hex>\n" */
    if (pos + 5 > len || memcmp(data + pos, "tree ", 5) != 0) return __LINE__;
    pos += 5;
    if (pos + GUT_OID_HEX_SIZE > len) return __LINE__;
    {
        unsigned long rc = oid_from_hex(&out->tree_oid, (const char *)(data + pos));
        if (rc) return __LINE__;
    }
    pos += GUT_OID_HEX_SIZE;
    if (pos >= len || data[pos] != '\n') return __LINE__;
    pos++;

    /* Parse zero or more "parent <hex>\n" */
    while (pos + 7 <= len && memcmp(data + pos, "parent ", 7) == 0) {
        pos += 7;
        if (pos + GUT_OID_HEX_SIZE > len) return __LINE__;

        if (out->parent_count >= parent_cap) {
            u64 new_cap = parent_cap == 0 ? 2 : parent_cap * 2;
            gut_oid *new_parents = (gut_oid *)realloc(
                out->parent_oids, (size_t)(new_cap * sizeof(gut_oid)));
            if (!new_parents) return __LINE__;
            out->parent_oids = new_parents;
            parent_cap = new_cap;
        }

        {
            unsigned long rc = oid_from_hex(&out->parent_oids[out->parent_count],
                                            (const char *)(data + pos));
            if (rc) return __LINE__;
        }
        out->parent_count++;
        pos += GUT_OID_HEX_SIZE;
        if (pos >= len || data[pos] != '\n') return __LINE__;
        pos++;
    }

    /* Parse "author ...\n" */
    if (pos + 7 > len || memcmp(data + pos, "author ", 7) != 0) return __LINE__;
    pos += 7;
    line_end = find_line_end(data, len, pos);
    out->author = dup_range(data, pos, line_end);
    if (!out->author) return __LINE__;
    pos = line_end + 1;

    /* Parse "committer ...\n" */
    if (pos + 10 > len || memcmp(data + pos, "committer ", 10) != 0) return __LINE__;
    pos += 10;
    line_end = find_line_end(data, len, pos);
    out->committer = dup_range(data, pos, line_end);
    if (!out->committer) return __LINE__;
    pos = line_end + 1;

    /* Skip blank line */
    if (pos < len && data[pos] == '\n') pos++;

    /* Rest is the commit message */
    out->message = dup_range(data, pos, len);
    if (!out->message) return __LINE__;

    return 0;
}

unsigned long commit_destroy(gut_commit *commit) {
    if (!commit) return __LINE__;
    free(commit->parent_oids);
    free(commit->author);
    free(commit->committer);
    free(commit->message);
    memset(commit, 0, sizeof(*commit));
    return 0;
}

unsigned long tree_lookup_path(gut_oid *out, gut_odb *odb,
                               gut_oid *tree_oid, const char *path) {
    gut_object obj;
    gut_tree tree;
    u64 i;
    unsigned long rc;
    const char *slash;

    if (!out) return __LINE__;
    if (!odb) return __LINE__;
    if (!tree_oid) return __LINE__;
    if (!path) return __LINE__;

    rc = odb_read(&obj, odb, tree_oid);
    if (rc) return __LINE__;
    if (obj.type != GUT_OBJ_TREE) { object_destroy(&obj); return __LINE__; }

    rc = tree_parse(&tree, obj.data.data, obj.data.len);
    object_destroy(&obj);
    if (rc) return __LINE__;

    slash = strchr(path, '/');

    for (i = 0; i < tree.count; i++) {
        if (slash) {
            /* Match directory component */
            size_t dir_len = (size_t)(slash - path);
            if (strlen(tree.entries[i].name) == dir_len &&
                memcmp(tree.entries[i].name, path, dir_len) == 0 &&
                tree.entries[i].mode == 040000) {
                /* Recurse into subtree */
                rc = tree_lookup_path(out, odb, &tree.entries[i].oid, slash + 1);
                tree_destroy(&tree);
                return rc;
            }
        } else {
            /* Match filename */
            if (strcmp(tree.entries[i].name, path) == 0) {
                memcpy(out->bytes, tree.entries[i].oid.bytes, GUT_OID_RAW_SIZE);
                tree_destroy(&tree);
                return 0;
            }
        }
    }

    tree_destroy(&tree);
    return __LINE__; /* not found */
}

unsigned long object_destroy(gut_object *obj) {
    if (!obj) return __LINE__;
    buf_destroy(&obj->data);
    return 0;
}
