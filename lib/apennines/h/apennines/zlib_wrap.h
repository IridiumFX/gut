#ifndef APENNINES_ZLIB_WRAP_H
#define APENNINES_ZLIB_WRAP_H

#include "apennines/types.h"
#include "apennines/buf.h"
#include "apennines/compress.h"

unsigned long zlib_compress(buf *out, u8 *data, u64 len);
unsigned long zlib_decompress(buf *out, u8 *data, u64 len);

#endif /* APENNINES_ZLIB_WRAP_H */
