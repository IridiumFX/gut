#ifndef GUT_DIFF_H
#define GUT_DIFF_H

#include "gut/types.h"

typedef enum {
    DIFF_EQUAL  = 0,
    DIFF_INSERT = 1,
    DIFF_DELETE = 2
} diff_op;

typedef struct {
    diff_op op;
    u64     old_idx;
    u64     new_idx;
} diff_edit;

typedef struct {
    diff_edit *edits;
    u64        count;
    u64        capacity;
} diff_result;

/* Split data into lines. Returns array of pointers into a copied buffer.
 * Caller must free *lines AND *buf. */
unsigned long diff_split_lines(char ***lines, u64 *count, u8 **buf,
                               const u8 *data, u64 len);

/* Myers diff: compute minimal edit script */
unsigned long diff_myers(diff_result *out,
                         char **old_lines, u64 old_count,
                         char **new_lines, u64 new_count);

/* Print unified diff to stdout */
unsigned long diff_print_unified(const char *old_path, const char *new_path,
                                 diff_result *result,
                                 char **old_lines, u64 old_count,
                                 char **new_lines, u64 new_count,
                                 u64 context);

unsigned long diff_destroy(diff_result *result);

#endif /* GUT_DIFF_H */
