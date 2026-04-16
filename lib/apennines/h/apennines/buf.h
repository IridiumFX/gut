#ifndef APENNINES_BUF_H
#define APENNINES_BUF_H

#include "apennines/types.h"

typedef struct {
    u8 *data;
    u64 len;
    u64 cap;
    u8 is_static;
} buf;

unsigned long buf_create(buf *out, u64 capacity);
unsigned long buf_from_static(buf *out, u8 *data, u64 len);
unsigned long buf_append(buf *b, u8 *data, u64 len);
unsigned long buf_append_byte(buf *b, u8 byte);
unsigned long buf_insert(buf *b, u64 offset, u8 *data, u64 len);
unsigned long buf_remove(buf *b, u64 offset, u64 len);
unsigned long buf_slice(u8 **out, u64 *out_len, buf *b, u64 offset, u64 len);
unsigned long buf_truncate(buf *b, u64 len);
unsigned long buf_reserve(buf *b, u64 capacity);
unsigned long buf_shrink(buf *b);
unsigned long buf_clear(buf *b);
unsigned long buf_compare(long *result, buf *a, buf *b);
unsigned long buf_clone(buf *out, buf *src);
unsigned long buf_destroy(buf *b);
unsigned long buf_len(u64 *out, buf *b);
unsigned long buf_cap(u64 *out, buf *b);
unsigned long buf_ptr(u8 **out, buf *b);

#endif /* APENNINES_BUF_H */
