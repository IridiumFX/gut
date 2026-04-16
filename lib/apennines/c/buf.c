#include "apennines/buf.h"
#include <stdlib.h>
#include <string.h>

unsigned long buf_create(buf *out, u64 capacity) {
    if (!out) return 1;
    out->data = (u8 *)malloc((size_t)capacity);
    if (capacity > 0 && !out->data) return 2;
    out->len = 0;
    out->cap = capacity;
    out->is_static = 0;
    return 0;
}

unsigned long buf_from_static(buf *out, u8 *data, u64 len) {
    if (!out) return 1;
    if (!data) return 2;
    out->data = data;
    out->len = len;
    out->cap = len;
    out->is_static = 1;
    return 0;
}

unsigned long buf_append(buf *b, u8 *data, u64 len) {
    if (!b) return 1;
    if (!data) return 2;
    if (b->len + len > b->cap) {
        if (b->is_static) return 3;
        u64 new_cap = b->cap * 2;
        if (new_cap < b->len + len) new_cap = b->len + len;
        u8 *new_data = (u8 *)realloc(b->data, (size_t)new_cap);
        if (!new_data) return 3;
        b->data = new_data;
        b->cap = new_cap;
    }
    memcpy(b->data + b->len, data, (size_t)len);
    b->len += len;
    return 0;
}

unsigned long buf_append_byte(buf *b, u8 byte) {
    if (!b) return 1;
    if (b->len + 1 > b->cap) {
        if (b->is_static) return 2;
        u64 new_cap = b->cap * 2;
        if (new_cap < b->len + 1) new_cap = b->len + 1;
        u8 *new_data = (u8 *)realloc(b->data, (size_t)new_cap);
        if (!new_data) return 2;
        b->data = new_data;
        b->cap = new_cap;
    }
    b->data[b->len++] = byte;
    return 0;
}

unsigned long buf_insert(buf *b, u64 offset, u8 *data, u64 len) {
    if (!b) return 1;
    if (offset > b->len) return 2;
    if (!data) return 3;
    if (b->len + len > b->cap) {
        if (b->is_static) return 4;
        u64 new_cap = b->cap * 2;
        if (new_cap < b->len + len) new_cap = b->len + len;
        u8 *new_data = (u8 *)realloc(b->data, (size_t)new_cap);
        if (!new_data) return 4;
        b->data = new_data;
        b->cap = new_cap;
    }
    memmove(b->data + offset + len, b->data + offset, (size_t)(b->len - offset));
    memcpy(b->data + offset, data, (size_t)len);
    b->len += len;
    return 0;
}

unsigned long buf_remove(buf *b, u64 offset, u64 len) {
    if (!b) return 1;
    if (offset + len > b->len) return 2;
    memmove(b->data + offset, b->data + offset + len, (size_t)(b->len - offset - len));
    b->len -= len;
    return 0;
}

unsigned long buf_slice(u8 **out, u64 *out_len, buf *b, u64 offset, u64 len) {
    if (!out) return 1;
    if (!b) return 2;
    if (offset + len > b->len) return 3;
    *out = b->data + offset;
    if (out_len) *out_len = len;
    return 0;
}

unsigned long buf_truncate(buf *b, u64 len) {
    if (!b) return 1;
    if (len > b->len) return 2;
    b->len = len;
    return 0;
}

unsigned long buf_reserve(buf *b, u64 capacity) {
    if (!b) return 1;
    if (capacity > b->cap) {
        if (b->is_static) return 2;
        u8 *new_data = (u8 *)realloc(b->data, (size_t)capacity);
        if (!new_data) return 2;
        b->data = new_data;
        b->cap = capacity;
    }
    return 0;
}

unsigned long buf_shrink(buf *b) {
    if (!b) return 1;
    if (b->is_static) return 2;
    if (b->len == 0) {
        free(b->data);
        b->data = NULL;
        b->cap = 0;
    } else {
        u8 *new_data = (u8 *)realloc(b->data, (size_t)b->len);
        if (new_data) {
            b->data = new_data;
            b->cap = b->len;
        }
    }
    return 0;
}

unsigned long buf_clear(buf *b) {
    if (!b) return 1;
    b->len = 0;
    return 0;
}

unsigned long buf_compare(long *result, buf *a, buf *b) {
    if (!result) return 1;
    if (!a) return 2;
    if (!b) return 3;
    u64 min_len = a->len < b->len ? a->len : b->len;
    int cmp = 0;
    if (min_len > 0) {
        cmp = memcmp(a->data, b->data, (size_t)min_len);
    }
    if (cmp != 0) {
        *result = (long)cmp;
    } else if (a->len < b->len) {
        *result = -1;
    } else if (a->len > b->len) {
        *result = 1;
    } else {
        *result = 0;
    }
    return 0;
}

unsigned long buf_clone(buf *out, buf *src) {
    if (!out) return 1;
    if (!src) return 2;
    out->data = (u8 *)malloc((size_t)src->len);
    if (src->len > 0 && !out->data) return 3;
    if (src->len > 0) {
        memcpy(out->data, src->data, (size_t)src->len);
    }
    out->len = src->len;
    out->cap = src->len;
    out->is_static = 0;
    return 0;
}

unsigned long buf_destroy(buf *b) {
    if (!b) return 1;
    if (!b->is_static) {
        free(b->data);
    }
    b->data = NULL;
    b->len = 0;
    b->cap = 0;
    b->is_static = 0;
    return 0;
}

unsigned long buf_len(u64 *out, buf *b) {
    if (!out) return 1;
    if (!b) return 2;
    *out = b->len;
    return 0;
}

unsigned long buf_cap(u64 *out, buf *b) {
    if (!out) return 1;
    if (!b) return 2;
    *out = b->cap;
    return 0;
}

unsigned long buf_ptr(u8 **out, buf *b) {
    if (!out) return 1;
    if (!b) return 2;
    *out = b->data;
    return 0;
}
