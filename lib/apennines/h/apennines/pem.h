#ifndef APENNINES_T2_ENCODING_PEM_H
#define APENNINES_T2_ENCODING_PEM_H


#include "apennines/types.h"
#include "apennines/buf.h"

unsigned long pem_encode(buf *out, const char *label,
                                       const u8 *der_data, u64 der_len);

unsigned long pem_decode(buf *out, char *label_out,
                                       u64 label_max, const u8 *pem_data,
                                       u64 pem_len);

unsigned long pem_count(u64 *out, const u8 *data, u64 len);

unsigned long pem_decode_next(buf *out, char *label_out,
                                            u64 label_max,
                                            const u8 **cursor,
                                            u64 *remaining);

#endif /* APENNINES_T2_ENCODING_PEM_H */
