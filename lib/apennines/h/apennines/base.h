#ifndef APENNINES_T2_ENCODING_BASE_H
#define APENNINES_T2_ENCODING_BASE_H


#include "apennines/types.h"
#include "apennines/buf.h"

unsigned long base16_encode(buf *out, u8 *data, u64 len);
unsigned long base16_decode(buf *out, u8 *data, u64 len);
unsigned long base32_encode(buf *out, u8 *data, u64 len);
unsigned long base32_decode(buf *out, u8 *data, u64 len);
unsigned long base64_encode(buf *out, u8 *data, u64 len);
unsigned long base64_decode(buf *out, u8 *data, u64 len);
unsigned long base64url_encode(buf *out, u8 *data, u64 len);
unsigned long base64url_decode(buf *out, u8 *data, u64 len);

#endif /* APENNINES_T2_ENCODING_BASE_H */
