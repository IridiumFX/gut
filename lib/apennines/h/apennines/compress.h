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

/* Variant of deflate_decompress that also reports how many input bytes
 * were consumed. Useful when decompressing a deflate stream embedded in
 * a larger container (e.g. a git packfile) where the compressed length
 * is not known upfront. On success, *consumed is set to the number of
 * input bytes read, including any trailing byte partially used for
 * Huffman bits. */
unsigned long deflate_decompress_consumed(buf *out, u8 *data, u64 len,
                                          u64 *consumed);

#endif /* APENNINES_COMPRESS_H */
