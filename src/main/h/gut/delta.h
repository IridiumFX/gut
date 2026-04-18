#ifndef GUT_DELTA_H
#define GUT_DELTA_H

#include "gut/types.h"
#include "apennines/buf.h"

/*
 * Git delta format (used inside OFS_DELTA / REF_DELTA pack objects):
 *
 *   varint src_size
 *   varint tgt_size
 *   ops*:
 *     COPY  (cmd & 0x80): bits 0-3 select 4 offset bytes, bits 4-6 select
 *                         3 size bytes. copy_size == 0 means 0x10000.
 *                         Max copy is 0xFFFFFF (16 MiB - 1); larger copies
 *                         are split into multiple COPY ops.
 *     INSERT (cmd 1..127): cmd literal bytes follow and are appended to
 *                         the output.
 */

/* Compute a delta from `base` to `target`. On success, `out` contains the
 * delta byte stream. The buffer is initialized by this call — caller must
 * buf_destroy it. Safe to call with base_len==0 (produces an all-INSERT
 * delta). */
unsigned long delta_encode(buf *out,
                           const u8 *base,   u64 base_len,
                           const u8 *target, u64 target_len);

/* Apply a delta to `base` and produce `target` in `out`. The `out` buf is
 * initialized by this call. Mirror of delta_encode for round-trips. */
unsigned long delta_apply(buf *out,
                          const u8 *base,  u64 base_len,
                          const u8 *delta, u64 delta_len);

#endif /* GUT_DELTA_H */
