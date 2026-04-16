#include "gut/diff.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

unsigned long diff_split_lines(char ***lines, u64 *count, u8 **buf_out,
                               const u8 *data, u64 len) {
    u8 *copy;
    u64 n, i, start;
    char **arr;

    if (!lines || !count || !buf_out) return __LINE__;

    *lines = NULL;
    *count = 0;
    *buf_out = NULL;

    if (len == 0 || !data) return 0;

    copy = (u8 *)malloc((size_t)(len + 1));
    if (!copy) return __LINE__;
    memcpy(copy, data, (size_t)len);
    copy[len] = '\0';

    /* Count lines */
    n = 1;
    for (i = 0; i < len; i++) {
        if (copy[i] == '\n') n++;
    }

    arr = (char **)malloc((size_t)(n * sizeof(char *)));
    if (!arr) { free(copy); return __LINE__; }

    n = 0;
    start = 0;
    for (i = 0; i <= len; i++) {
        if (i == len || copy[i] == '\n') {
            copy[i] = '\0';
            arr[n++] = (char *)(copy + start);
            start = i + 1;
        }
    }

    /* Drop empty trailing line from final \n */
    if (n > 0 && arr[n - 1][0] == '\0' && len > 0 && data[len - 1] == '\n') {
        n--;
    }

    *lines = arr;
    *count = n;
    *buf_out = copy;
    return 0;
}

/*
 * Simple O(NM) LCS-based diff.
 * Compute LCS, then derive edit script from it.
 */
unsigned long diff_myers(diff_result *out,
                         char **old_lines, u64 old_count,
                         char **new_lines, u64 new_count) {
    u64 i, j;
    u64 *prev, *curr;
    u64 cap;
    u64 ec;
    diff_edit *edits;

    if (!out) return __LINE__;
    out->edits = NULL;
    out->count = 0;
    out->capacity = 0;

    cap = old_count + new_count;
    if (cap == 0) return 0;

    /* LCS via two rows of DP table */
    prev = (u64 *)calloc((size_t)(new_count + 1), sizeof(u64));
    curr = (u64 *)calloc((size_t)(new_count + 1), sizeof(u64));
    if (!prev || !curr) { free(prev); free(curr); return __LINE__; }

    /* We need the full table for backtracking, so allocate it */
    {
        u64 *table = (u64 *)calloc((size_t)((old_count + 1) * (new_count + 1)), sizeof(u64));
        if (!table) { free(prev); free(curr); return __LINE__; }

        for (i = 1; i <= old_count; i++) {
            for (j = 1; j <= new_count; j++) {
                if (strcmp(old_lines[i - 1], new_lines[j - 1]) == 0) {
                    table[i * (new_count + 1) + j] = table[(i - 1) * (new_count + 1) + (j - 1)] + 1;
                } else {
                    u64 a = table[(i - 1) * (new_count + 1) + j];
                    u64 b = table[i * (new_count + 1) + (j - 1)];
                    table[i * (new_count + 1) + j] = (a > b) ? a : b;
                }
            }
        }

        /* Backtrack to build edit script */
        edits = (diff_edit *)malloc((size_t)(cap * sizeof(diff_edit)));
        if (!edits) { free(table); free(prev); free(curr); return __LINE__; }

        ec = 0;
        i = old_count;
        j = new_count;

        /* Build edits in reverse, then reverse the array */
        while (i > 0 || j > 0) {
            if (i > 0 && j > 0 &&
                strcmp(old_lines[i - 1], new_lines[j - 1]) == 0) {
                edits[ec].op = DIFF_EQUAL;
                edits[ec].old_idx = i - 1;
                edits[ec].new_idx = j - 1;
                ec++;
                i--;
                j--;
            } else if (j > 0 && (i == 0 ||
                       table[i * (new_count + 1) + (j - 1)] >=
                       table[(i - 1) * (new_count + 1) + j])) {
                edits[ec].op = DIFF_INSERT;
                edits[ec].old_idx = i;
                edits[ec].new_idx = j - 1;
                ec++;
                j--;
            } else {
                edits[ec].op = DIFF_DELETE;
                edits[ec].old_idx = i - 1;
                edits[ec].new_idx = j;
                ec++;
                i--;
            }
        }

        free(table);

        /* Reverse edits */
        {
            u64 lo = 0, hi = ec - 1;
            while (lo < hi) {
                diff_edit tmp = edits[lo];
                edits[lo] = edits[hi];
                edits[hi] = tmp;
                lo++;
                hi--;
            }
        }
    }

    free(prev);
    free(curr);

    out->edits = edits;
    out->count = ec;
    out->capacity = cap;
    return 0;
}

unsigned long diff_print_unified(const char *old_path, const char *new_path,
                                 diff_result *result,
                                 char **old_lines, u64 old_count,
                                 char **new_lines, u64 new_count,
                                 u64 context) {
    u64 i;

    if (!result) return __LINE__;
    if (result->count == 0) return 0;

    (void)old_count; (void)new_count;

    printf("--- a/%s\n", old_path);
    printf("+++ b/%s\n", new_path);

    i = 0;
    while (i < result->count) {
        /* Find next change */
        while (i < result->count && result->edits[i].op == DIFF_EQUAL) i++;
        if (i >= result->count) break;

        {
            u64 hunk_old_start, hunk_new_start;
            u64 hunk_old_count = 0, hunk_new_count = 0;
            u64 start = (i > context) ? i - context : 0;
            u64 end;

            /* Find end of hunk (merge nearby changes) */
            {
                u64 j = i;
                while (j < result->count) {
                    if (result->edits[j].op != DIFF_EQUAL) {
                        j++;
                    } else {
                        u64 eq_run = 0;
                        while (j + eq_run < result->count &&
                               result->edits[j + eq_run].op == DIFF_EQUAL)
                            eq_run++;
                        if (eq_run > 2 * context) {
                            j += context;
                            break;
                        }
                        j += eq_run;
                    }
                }
                end = j;
            }

            /* Compute hunk header */
            hunk_old_start = result->edits[start].old_idx + 1;
            hunk_new_start = result->edits[start].new_idx + 1;

            {
                u64 j;
                for (j = start; j < end; j++) {
                    if (result->edits[j].op == DIFF_EQUAL ||
                        result->edits[j].op == DIFF_DELETE)
                        hunk_old_count++;
                    if (result->edits[j].op == DIFF_EQUAL ||
                        result->edits[j].op == DIFF_INSERT)
                        hunk_new_count++;
                }
            }

            printf("@@ -%llu,%llu +%llu,%llu @@\n",
                   (unsigned long long)hunk_old_start,
                   (unsigned long long)hunk_old_count,
                   (unsigned long long)hunk_new_start,
                   (unsigned long long)hunk_new_count);

            {
                u64 j;
                for (j = start; j < end; j++) {
                    switch (result->edits[j].op) {
                        case DIFF_EQUAL:
                            printf(" %s\n", old_lines[result->edits[j].old_idx]);
                            break;
                        case DIFF_DELETE:
                            printf("-%s\n", old_lines[result->edits[j].old_idx]);
                            break;
                        case DIFF_INSERT:
                            printf("+%s\n", new_lines[result->edits[j].new_idx]);
                            break;
                    }
                }
            }

            i = end;
        }
    }

    return 0;
}

unsigned long diff_destroy(diff_result *result) {
    if (!result) return __LINE__;
    free(result->edits);
    result->edits = NULL;
    result->count = 0;
    result->capacity = 0;
    return 0;
}
