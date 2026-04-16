#ifndef APENNINES_COMPRESS_H
#define APENNINES_COMPRESS_H

#include "apennines/types.h"
#include "apennines/buf.h"

typedef enum {
    COMPRESS_LEVEL_FAST    = 1,
    COMPRESS_LEVEL_DEFAULT = 6,
    COMPRESS_LEVEL_BEST    = 9
} compress_level;

unsigned long deflate_compress(buf *out, u8 *data, u64 len, compress_level level);
unsigned long deflate_decompress(buf *out, u8 *data, u64 len);

#endif /* APENNINES_COMPRESS_H */
