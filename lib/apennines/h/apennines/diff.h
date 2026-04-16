#ifndef APENNINES_T2_ALGO_DIFF_H
#define APENNINES_T2_ALGO_DIFF_H

#include "apennines/types.h"

/* Diff: Myers diff algorithm for line-by-line or byte-by-byte comparison.
 * Produces a list of edit operations (insert, delete, equal). */

typedef enum {
    DIFF_EQUAL,
    DIFF_INSERT,
    DIFF_DELETE
} diff_op;

typedef struct {
    diff_op  op;
    u64      off_a;    /* offset into source a */
    u64      off_b;    /* offset into source b */
    u64      len;      /* number of elements */
} diff_edit;

typedef struct {
    diff_edit *edits;
    u64        len;
    u64        cap;
} diff_result;

unsigned long diff_lines(diff_result *out,
                                       const char *a, u64 a_len,
                                       const char *b, u64 b_len);
unsigned long diff_bytes(diff_result *out,
                                       const u8 *a, u64 a_len,
                                       const u8 *b, u64 b_len);
unsigned long diff_apply(char *out, u64 out_cap, u64 *out_len,
                                       const char *base, u64 base_len,
                                       const diff_result *diff,
                                       const char *b, u64 b_len);
unsigned long diff_format_unified(char *out, u64 out_cap, u64 *out_len,
                                                const char *a, u64 a_len,
                                                const char *b, u64 b_len,
                                                const diff_result *diff,
                                                u64 context_lines);
unsigned long diff_destroy(diff_result *diff);

/* ================================================================
 *  Three-Way Merge (diff3)
 *
 *  Given a common base and two diverging versions (ours, theirs),
 *  produce a merged text with conflict markers where the two sides
 *  disagree on a change. Line-based.
 * ================================================================ */

typedef struct {
    char *data;             /* merged content (owned, null-terminated-not-required) */
    u64   len;              /* length of merged content */
    u32   conflict_count;   /* number of conflict regions emitted */
    int   has_conflicts;    /* 1 if any conflicts in output, 0 if clean merge */
} diff_merge_result;

/* Output style for three-way merge */
typedef enum {
    DIFF_MERGE_STYLE_STANDARD = 0,  /* <<<<<<< / ======= / >>>>>>>            */
    DIFF_MERGE_STYLE_DIFF3    = 1   /* <<<<<<< / ||||||| (base) / ======= / >>>>>>>  */
} diff_merge_style;

/* Three-way merge.
 *   base: common ancestor
 *   ours: our version (usually HEAD or current branch)
 *   theirs: their version (usually the branch being merged in)
 *   label_ours / label_theirs: labels printed after the conflict markers
 *     (may be NULL for default "ours" / "theirs")
 *   style: STANDARD (2-way marker) or DIFF3 (includes base in conflicts)
 *
 * *out receives the merged content. out->has_conflicts is set if any
 * region could not be auto-resolved.
 *
 * Hatches: 1=out null, 2=alloc fail, 3=diff failure */
unsigned long diff_three_way(diff_merge_result *out,
                                           const char *base, u64 base_len,
                                           const char *ours, u64 ours_len,
                                           const char *theirs, u64 theirs_len,
                                           const char *label_ours,
                                           const char *label_theirs,
                                           diff_merge_style style);

/* Free memory owned by merge result. */
unsigned long diff_merge_destroy(diff_merge_result *r);

/* ================================================================
 *  Patience Diff (git's default diff algorithm since 2.14)
 *
 *  Identifies "unique anchor" lines shared between the two texts,
 *  then recursively diffs the regions between anchors. Produces
 *  human-readable diffs especially on code with moved blocks.
 * ================================================================ */

unsigned long diff_patience(diff_result *out,
                                          const char *a, u64 a_len,
                                          const char *b, u64 b_len);

/* ================================================================
 *  Histogram Diff (git's --histogram)
 *
 *  Similar quality to patience but uses line frequency histogram
 *  to pick anchor lines. Typically faster on large files.
 * ================================================================ */

unsigned long diff_histogram(diff_result *out,
                                           const char *a, u64 a_len,
                                           const char *b, u64 b_len);

/* ================================================================
 *  Additional utilities
 * ================================================================ */

/* Longest common subsequence length (on lines). */
unsigned long diff_lcs(u64 *out, const char *a, u64 a_len,
                                     const char *b, u64 b_len);

/* Edit (Levenshtein) distance between two byte sequences. */
unsigned long diff_edit_distance(u64 *out,
                                                const u8 *a, u64 a_len,
                                                const u8 *b, u64 b_len);

#endif /* APENNINES_T2_ALGO_DIFF_H */
