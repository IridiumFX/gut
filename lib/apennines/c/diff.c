#include "apennines/diff.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* ---- internal helpers ---- */

/* Split text into array of line pointers + lengths. */
typedef struct {
    const char **starts;
    u64         *lens;
    u64          count;
} line_array;

static unsigned long split_lines(line_array *out, const char *data, u64 data_len) {
    u64 cap, i, start;
    out->count = 0;
    cap = 64;
    out->starts = (const char **)malloc(cap * sizeof(const char *));
    if (!out->starts) return 1;
    out->lens = (u64 *)malloc(cap * sizeof(u64));
    if (!out->lens) { free(out->starts); return 2; }

    start = 0;
    for (i = 0; i <= data_len; i++) {
        if (i == data_len || data[i] == '\n') {
            if (out->count >= cap) {
                cap *= 2;
                out->starts = (const char **)realloc(out->starts, cap * sizeof(const char *));
                out->lens = (u64 *)realloc(out->lens, cap * sizeof(u64));
                if (!out->starts || !out->lens) return 3;
            }
            out->starts[out->count] = data + start;
            out->lens[out->count] = i - start;
            out->count++;
            start = i + 1;
        }
    }
    return 0;
}

static void free_lines(line_array *la) {
    free(la->starts);
    free(la->lens);
}

static int lines_equal(const line_array *a, u64 ai, const line_array *b, u64 bi) {
    if (a->lens[ai] != b->lens[bi]) return 0;
    return memcmp(a->starts[ai], b->starts[bi], (size_t)a->lens[ai]) == 0;
}

static unsigned long result_push(diff_result *r, diff_op op, u64 off_a, u64 off_b, u64 len) {
    if (r->len >= r->cap) {
        u64 new_cap = (r->cap == 0) ? 64 : r->cap * 2;
        diff_edit *ne = (diff_edit *)realloc(r->edits, (size_t)new_cap * sizeof(diff_edit));
        if (!ne) return 1;
        r->edits = ne;
        r->cap = new_cap;
    }
    r->edits[r->len].op = op;
    r->edits[r->len].off_a = off_a;
    r->edits[r->len].off_b = off_b;
    r->edits[r->len].len = len;
    r->len++;
    return 0;
}

/*
 * Simple O(NM) LCS-based diff.  For lines shorter than typical source files
 * this is fine; a full Myers implementation would be O(ND).
 * We compute the LCS length table in two rows to save memory.
 */
static unsigned long lcs_diff(diff_result *out,
                              const line_array *la,
                              const line_array *lb) {
    u64 m = la->count;
    u64 n = lb->count;
    u64 *prev, *curr;
    u64 i, j;
    /* Trace arrays: for each cell, store direction. */
    /* 0=diag (equal), 1=up (delete from a), 2=left (insert from b) */
    u8 *dirs;

    memset(out, 0, sizeof(diff_result));

    if (m == 0 && n == 0) return 0;

    /* If one side is empty, produce bulk insert or delete. */
    if (m == 0) {
        for (j = 0; j < n; j++) {
            if (result_push(out, DIFF_INSERT, 0, j, 1) != 0) return 1;
        }
        return 0;
    }
    if (n == 0) {
        for (i = 0; i < m; i++) {
            if (result_push(out, DIFF_DELETE, i, 0, 1) != 0) return 1;
        }
        return 0;
    }

    /* Full direction table for traceback. */
    dirs = (u8 *)calloc((size_t)((m + 1) * (n + 1)), sizeof(u8));
    if (!dirs) return 2;

    prev = (u64 *)calloc((size_t)(n + 1), sizeof(u64));
    curr = (u64 *)calloc((size_t)(n + 1), sizeof(u64));
    if (!prev || !curr) { free(dirs); free(prev); free(curr); return 3; }

    /* Fill LCS table. */
    for (i = 1; i <= m; i++) {
        for (j = 1; j <= n; j++) {
            if (lines_equal(la, i - 1, lb, j - 1)) {
                curr[j] = prev[j - 1] + 1;
                dirs[i * (n + 1) + j] = 0; /* diagonal */
            } else if (prev[j] >= curr[j - 1]) {
                curr[j] = prev[j];
                dirs[i * (n + 1) + j] = 1; /* up */
            } else {
                curr[j] = curr[j - 1];
                dirs[i * (n + 1) + j] = 2; /* left */
            }
        }
        /* Swap rows. */
        { u64 *tmp = prev; prev = curr; curr = tmp; }
        memset(curr, 0, (size_t)(n + 1) * sizeof(u64));
    }

    /* Traceback from (m, n) to (0, 0). Build edits in reverse. */
    {
        u64 ri = m, rj = n;
        u64 tmp_cap = 128;
        u64 tmp_len = 0;
        diff_edit *tmp = (diff_edit *)malloc(tmp_cap * sizeof(diff_edit));
        if (!tmp) { free(dirs); free(prev); free(curr); return 4; }

        while (ri > 0 || rj > 0) {
            diff_edit e;
            if (ri > 0 && rj > 0 && dirs[ri * (n + 1) + rj] == 0) {
                e.op = DIFF_EQUAL; e.off_a = ri - 1; e.off_b = rj - 1; e.len = 1;
                ri--; rj--;
            } else if (ri > 0 && (rj == 0 || dirs[ri * (n + 1) + rj] == 1)) {
                e.op = DIFF_DELETE; e.off_a = ri - 1; e.off_b = rj; e.len = 1;
                ri--;
            } else {
                e.op = DIFF_INSERT; e.off_a = ri; e.off_b = rj - 1; e.len = 1;
                rj--;
            }
            if (tmp_len >= tmp_cap) {
                tmp_cap *= 2;
                tmp = (diff_edit *)realloc(tmp, tmp_cap * sizeof(diff_edit));
                if (!tmp) { free(dirs); free(prev); free(curr); return 5; }
            }
            tmp[tmp_len++] = e;
        }

        /* Reverse into output. */
        for (i = 0; i < tmp_len; i++) {
            if (result_push(out, tmp[tmp_len - 1 - i].op,
                            tmp[tmp_len - 1 - i].off_a,
                            tmp[tmp_len - 1 - i].off_b,
                            tmp[tmp_len - 1 - i].len) != 0) {
                free(tmp); free(dirs); free(prev); free(curr);
                return 6;
            }
        }
        free(tmp);
    }

    free(dirs);
    free(prev);
    free(curr);
    return 0;
}

/* ---- public API ---- */

unsigned long diff_lines(diff_result *out,
                         const char *a, u64 a_len,
                         const char *b, u64 b_len) {
    line_array la, lb;
    unsigned long rc;
    if (!out) return 1;
    memset(out, 0, sizeof(diff_result));
    if (split_lines(&la, a, a_len) != 0) return 2;
    if (split_lines(&lb, b, b_len) != 0) { free_lines(&la); return 3; }
    rc = lcs_diff(out, &la, &lb);
    free_lines(&la);
    free_lines(&lb);
    return rc == 0 ? 0 : 4;
}

unsigned long diff_bytes(diff_result *out,
                         const u8 *a, u64 a_len,
                         const u8 *b, u64 b_len) {
    /* Treat each byte as a "line" for the LCS algorithm. */
    line_array la, lb;
    unsigned long rc;
    u64 i;
    if (!out) return 1;
    memset(out, 0, sizeof(diff_result));

    /* Build pseudo line-arrays: each "line" is 1 byte. */
    la.count = a_len;
    la.starts = (const char **)malloc(a_len * sizeof(const char *));
    la.lens = (u64 *)malloc(a_len * sizeof(u64));
    lb.count = b_len;
    lb.starts = (const char **)malloc(b_len * sizeof(const char *));
    lb.lens = (u64 *)malloc(b_len * sizeof(u64));
    if (!la.starts || !la.lens || !lb.starts || !lb.lens) {
        free(la.starts); free(la.lens); free(lb.starts); free(lb.lens);
        return 2;
    }
    for (i = 0; i < a_len; i++) { la.starts[i] = (const char *)&a[i]; la.lens[i] = 1; }
    for (i = 0; i < b_len; i++) { lb.starts[i] = (const char *)&b[i]; lb.lens[i] = 1; }

    rc = lcs_diff(out, &la, &lb);
    free(la.starts); free(la.lens);
    free(lb.starts); free(lb.lens);
    return rc == 0 ? 0 : 3;
}

unsigned long diff_apply(char *out, u64 out_cap, u64 *out_len,
                         const char *base, u64 base_len,
                         const diff_result *diff,
                         const char *b, u64 b_len) {
    /* Rebuild text from diff edits applied to base, using b for inserts.
     * This works at line granularity: we split base and b into lines. */
    line_array la, lb;
    u64 pos, i;
    if (!out || out_cap == 0) return 1;
    if (!diff) return 2;

    if (split_lines(&la, base, base_len) != 0) return 3;
    if (split_lines(&lb, b, b_len) != 0) { free_lines(&la); return 4; }

    pos = 0;
    for (i = 0; i < diff->len; i++) {
        const diff_edit *e = &diff->edits[i];
        const char *src = NULL;
        u64 slen = 0;
        if (e->op == DIFF_EQUAL || e->op == DIFF_DELETE) {
            if (e->op == DIFF_DELETE) continue;  /* skip deleted lines */
            if (e->off_a < la.count) { src = la.starts[e->off_a]; slen = la.lens[e->off_a]; }
        }
        if (e->op == DIFF_INSERT) {
            if (e->off_b < lb.count) { src = lb.starts[e->off_b]; slen = lb.lens[e->off_b]; }
        }
        if (e->op == DIFF_EQUAL) {
            if (e->off_a < la.count) { src = la.starts[e->off_a]; slen = la.lens[e->off_a]; }
        }
        if (src && slen > 0 && pos + slen + 1 < out_cap) {
            memcpy(out + pos, src, (size_t)slen);
            pos += slen;
            out[pos++] = '\n';
        }
    }
    if (pos > 0 && out[pos - 1] == '\n') pos--;  /* trim trailing newline */
    out[pos] = '\0';
    if (out_len) *out_len = pos;

    free_lines(&la);
    free_lines(&lb);
    return 0;
}

unsigned long diff_format_unified(char *out, u64 out_cap, u64 *out_len,
                                  const char *a, u64 a_len,
                                  const char *b, u64 b_len,
                                  const diff_result *diff,
                                  u64 context_lines) {
    line_array la, lb;
    u64 pos, i;
    int n;
    if (!out || out_cap == 0) return 1;
    if (!diff) return 2;
    (void)context_lines; /* simplified: show all lines */

    if (split_lines(&la, a, a_len) != 0) return 3;
    if (split_lines(&lb, b, b_len) != 0) { free_lines(&la); return 4; }

    pos = 0;
    n = snprintf(out + pos, (size_t)(out_cap - pos),
                 "--- a\n+++ b\n@@ -%llu,%llu +%llu,%llu @@\n",
                 (unsigned long long)1, (unsigned long long)la.count,
                 (unsigned long long)1, (unsigned long long)lb.count);
    if (n > 0) pos += (u64)n;

    for (i = 0; i < diff->len && pos + 2 < out_cap; i++) {
        const diff_edit *e = &diff->edits[i];
        const char *src = NULL;
        u64 slen = 0;
        char prefix = ' ';

        if (e->op == DIFF_EQUAL) {
            prefix = ' ';
            if (e->off_a < la.count) { src = la.starts[e->off_a]; slen = la.lens[e->off_a]; }
        } else if (e->op == DIFF_DELETE) {
            prefix = '-';
            if (e->off_a < la.count) { src = la.starts[e->off_a]; slen = la.lens[e->off_a]; }
        } else if (e->op == DIFF_INSERT) {
            prefix = '+';
            if (e->off_b < lb.count) { src = lb.starts[e->off_b]; slen = lb.lens[e->off_b]; }
        }

        if (pos + slen + 3 < out_cap) {
            out[pos++] = prefix;
            if (src && slen > 0) {
                memcpy(out + pos, src, (size_t)slen);
                pos += slen;
            }
            out[pos++] = '\n';
        }
    }
    out[pos] = '\0';
    if (out_len) *out_len = pos;

    free_lines(&la);
    free_lines(&lb);
    return 0;
}

unsigned long diff_destroy(diff_result *diff) {
    if (!diff) return 1;
    free(diff->edits);
    diff->edits = NULL;
    diff->len = 0;
    diff->cap = 0;
    return 0;
}
/* ================================================================
 *  Utilities — LCS length, edit distance
 * ================================================================ */

unsigned long diff_lcs(u64 *out, const char *a, u64 a_len,
                       const char *b, u64 b_len) {
    line_array la, lb;
    u64 m, n, i, j;
    u64 *prev, *curr;
    unsigned long rc;

    if (!out) return 1;
    if (split_lines(&la, a, a_len) != 0) return 2;
    if (split_lines(&lb, b, b_len) != 0) { free_lines(&la); return 3; }

    m = la.count; n = lb.count;
    prev = (u64 *)calloc((size_t)(n + 1), sizeof(u64));
    curr = (u64 *)calloc((size_t)(n + 1), sizeof(u64));
    if (!prev || !curr) { free(prev); free(curr); free_lines(&la); free_lines(&lb); return 4; }

    for (i = 1; i <= m; i++) {
        for (j = 1; j <= n; j++) {
            if (lines_equal(&la, i - 1, &lb, j - 1)) {
                curr[j] = prev[j - 1] + 1;
            } else {
                curr[j] = prev[j] > curr[j - 1] ? prev[j] : curr[j - 1];
            }
        }
        { u64 *t = prev; prev = curr; curr = t; }
        memset(curr, 0, (size_t)(n + 1) * sizeof(u64));
    }

    *out = prev[n];
    rc = 0;
    free(prev); free(curr);
    free_lines(&la); free_lines(&lb);
    return rc;
}

unsigned long diff_edit_distance(u64 *out, const u8 *a, u64 a_len,
                                  const u8 *b, u64 b_len) {
    u64 *prev, *curr;
    u64 i, j;
    if (!out) return 1;

    prev = (u64 *)calloc((size_t)(b_len + 1), sizeof(u64));
    curr = (u64 *)calloc((size_t)(b_len + 1), sizeof(u64));
    if (!prev || !curr) { free(prev); free(curr); return 2; }

    for (j = 0; j <= b_len; j++) prev[j] = j;
    for (i = 1; i <= a_len; i++) {
        curr[0] = i;
        for (j = 1; j <= b_len; j++) {
            u64 cost = (a[i - 1] == b[j - 1]) ? 0 : 1;
            u64 del = prev[j] + 1;
            u64 ins = curr[j - 1] + 1;
            u64 sub = prev[j - 1] + cost;
            u64 m = del < ins ? del : ins;
            curr[j] = m < sub ? m : sub;
        }
        { u64 *t = prev; prev = curr; curr = t; }
    }

    *out = prev[b_len];
    free(prev); free(curr);
    return 0;
}

/* ================================================================
 *  Three-Way Merge (diff3)
 *
 *  Algorithm (classic Khanna/Pierce formulation):
 *    1. Compute diffA = diff(base, ours) and diffB = diff(base, theirs)
 *    2. Identify "stable" base ranges: consecutive base lines that are
 *       EQUAL in both diffA and diffB.
 *    3. Between stable regions we have "unstable" chunks. For each:
 *         - If ours has no change in this range → take theirs
 *         - If theirs has no change in this range → take ours
 *         - If ours and theirs produce identical content → take either
 *         - Else → emit a conflict marker block
 *    4. For stable regions → emit base content unchanged.
 * ================================================================ */

/* Per-base-line state from a diff */
typedef struct {
    u8  unchanged;     /* 1 if this base line is EQUAL in the diff */
    u64 other_offset;  /* if unchanged: line offset in 'other' text */
} base_state;

/* Build a per-base-line state array. Also returns an "other_end" array
   giving the offset in 'other' just past the corresponding base line's
   edits (for determining insertions). */
static unsigned long build_base_state(base_state *states, u64 base_count,
                                       const diff_result *d) {
    u64 i;
    u64 ai = 0, bi = 0;  /* position in base / other */
    u64 base_idx = 0;

    for (i = 0; i < base_count; i++) {
        states[i].unchanged = 0;
        states[i].other_offset = 0;
    }

    for (i = 0; i < d->len; i++) {
        const diff_edit *e = &d->edits[i];
        if (e->op == DIFF_EQUAL) {
            u64 k;
            for (k = 0; k < e->len; k++) {
                if (e->off_a + k < base_count) {
                    states[e->off_a + k].unchanged = 1;
                    states[e->off_a + k].other_offset = e->off_b + k;
                }
            }
            ai = e->off_a + e->len;
            bi = e->off_b + e->len;
            (void)base_idx;
        } else if (e->op == DIFF_DELETE) {
            ai = e->off_a + e->len;
        } else { /* INSERT */
            bi = e->off_b + e->len;
        }
    }
    (void)ai; (void)bi;
    return 0;
}

/* Append a buffer segment — grow if needed */
static unsigned long mbuf_append(char **data, u64 *len, u64 *cap,
                                  const char *src, u64 n) {
    if (*len + n > *cap) {
        u64 new_cap = *cap == 0 ? 256 : *cap * 2;
        while (new_cap < *len + n) new_cap *= 2;
        char *nd = (char *)realloc(*data, (size_t)new_cap);
        if (!nd) return 1;
        *data = nd;
        *cap = new_cap;
    }
    memcpy(*data + *len, src, (size_t)n);
    *len += n;
    return 0;
}

/* Compare two ranges for line-equality */
static int ranges_equal(const line_array *la, u64 as, u64 ae,
                         const line_array *lb, u64 bs, u64 be) {
    u64 alen = ae - as;
    u64 blen = be - bs;
    u64 i;
    if (alen != blen) return 0;
    for (i = 0; i < alen; i++) {
        if (!lines_equal(la, as + i, lb, bs + i)) return 0;
    }
    return 1;
}

/* Emit lines [start..end) from a line_array. Appends a newline after each
   line, EXCEPT for the last line of the source if it is empty (which
   indicates the source already ended with '\n' — split_lines produces
   an empty sentinel line in that case). */
static unsigned long emit_lines(char **data, u64 *len, u64 *cap,
                                 const line_array *la, u64 start, u64 end) {
    u64 k;
    for (k = start; k < end; k++) {
        /* Skip the final empty sentinel line of the source entirely */
        if (k == la->count - 1 && la->lens[k] == 0) continue;

        unsigned long rc = mbuf_append(data, len, cap, la->starts[k], la->lens[k]);
        if (rc) return rc;
        rc = mbuf_append(data, len, cap, "\n", 1);
        if (rc) return rc;
    }
    return 0;
}

/* Emit an unstable region: resolve or emit conflict */
static unsigned long emit_unstable(char **buf, u64 *buf_len, u64 *buf_cap,
                                    const line_array *lb, u64 bs, u64 be,
                                    const line_array *lo, u64 os, u64 oe,
                                    const line_array *lt, u64 ts, u64 te,
                                    const char *label_ours,
                                    const char *label_theirs,
                                    diff_merge_style style,
                                    u32 *conflicts) {
    unsigned long rc;
    int ours_theirs_equal = ranges_equal(lo, os, oe, lt, ts, te);
    int ours_is_base      = ranges_equal(lo, os, oe, lb, bs, be);
    int theirs_is_base    = ranges_equal(lt, ts, te, lb, bs, be);

    if (os == oe && ts == te && bs == be) return 0; /* nothing */

    if (ours_theirs_equal || ours_is_base) {
        /* ours didn't change OR ours and theirs agree → take theirs */
        return emit_lines(buf, buf_len, buf_cap, lt, ts, te);
    }
    if (theirs_is_base) {
        return emit_lines(buf, buf_len, buf_cap, lo, os, oe);
    }

    /* Conflict */
    (*conflicts)++;
    rc = mbuf_append(buf, buf_len, buf_cap, "<<<<<<< ", 8); if (rc) return rc;
    rc = mbuf_append(buf, buf_len, buf_cap, label_ours, strlen(label_ours)); if (rc) return rc;
    rc = mbuf_append(buf, buf_len, buf_cap, "\n", 1); if (rc) return rc;

    rc = emit_lines(buf, buf_len, buf_cap, lo, os, oe); if (rc) return rc;

    if (style == DIFF_MERGE_STYLE_DIFF3) {
        rc = mbuf_append(buf, buf_len, buf_cap, "||||||| base\n", 13); if (rc) return rc;
        rc = emit_lines(buf, buf_len, buf_cap, lb, bs, be); if (rc) return rc;
    }

    rc = mbuf_append(buf, buf_len, buf_cap, "=======\n", 8); if (rc) return rc;
    rc = emit_lines(buf, buf_len, buf_cap, lt, ts, te); if (rc) return rc;

    rc = mbuf_append(buf, buf_len, buf_cap, ">>>>>>> ", 8); if (rc) return rc;
    rc = mbuf_append(buf, buf_len, buf_cap, label_theirs, strlen(label_theirs)); if (rc) return rc;
    rc = mbuf_append(buf, buf_len, buf_cap, "\n", 1); if (rc) return rc;
    return 0;
}

unsigned long diff_three_way(diff_merge_result *out,
                              const char *base, u64 base_len,
                              const char *ours, u64 ours_len,
                              const char *theirs, u64 theirs_len,
                              const char *label_ours,
                              const char *label_theirs,
                              diff_merge_style style) {
    line_array lb, lo, lt;
    diff_result da, db;
    base_state *sa = NULL, *sb = NULL;
    char *buf = NULL;
    u64 buf_len = 0, buf_cap = 0;
    unsigned long rc;
    u32 conflicts = 0;
    u64 i;
    u64 chunk_bs = 0, chunk_os = 0, chunk_ts = 0;  /* current chunk start */

    if (!out) return 1;
    memset(out, 0, sizeof(*out));

    if (!label_ours)   label_ours   = "ours";
    if (!label_theirs) label_theirs = "theirs";

    rc = split_lines(&lb, base, base_len);  if (rc) return 2;
    rc = split_lines(&lo, ours, ours_len);  if (rc) { free_lines(&lb); return 2; }
    rc = split_lines(&lt, theirs, theirs_len); if (rc) { free_lines(&lb); free_lines(&lo); return 2; }

    memset(&da, 0, sizeof(da));
    memset(&db, 0, sizeof(db));
    rc = lcs_diff(&da, &lb, &lo);
    if (rc) { free_lines(&lb); free_lines(&lo); free_lines(&lt); return 3; }
    rc = lcs_diff(&db, &lb, &lt);
    if (rc) { free(da.edits); free_lines(&lb); free_lines(&lo); free_lines(&lt); return 3; }

    /* For each base line, determine if unchanged in A (→ where in ours) and B (→ where in theirs) */
    sa = (base_state *)calloc(lb.count + 1, sizeof(base_state));
    sb = (base_state *)calloc(lb.count + 1, sizeof(base_state));
    if (!sa || !sb) {
        free(sa); free(sb); free(da.edits); free(db.edits);
        free_lines(&lb); free_lines(&lo); free_lines(&lt);
        return 2;
    }
    build_base_state(sa, lb.count, &da);
    build_base_state(sb, lb.count, &db);

    /* Walk base lines. A line `i` is "aligned-stable" if sa[i].unchanged &&
       sb[i].unchanged. For each such line, flush the accumulated chunk, then
       emit that one line as part of a stable run. */
    for (i = 0; i <= lb.count; i++) {
        int is_end = (i == lb.count);
        int aligned_stable = 0;
        u64 oi = 0, ti = 0;

        if (!is_end && sa[i].unchanged && sb[i].unchanged) {
            oi = sa[i].other_offset;
            ti = sb[i].other_offset;
            aligned_stable = 1;
        }

        if (aligned_stable || is_end) {
            /* Flush unstable chunk [chunk_bs..i), ours[chunk_os..oi), theirs[chunk_ts..ti)
               (for is_end, oi=lo.count, ti=lt.count) */
            u64 oi_end = aligned_stable ? oi : lo.count;
            u64 ti_end = aligned_stable ? ti : lt.count;
            if (chunk_bs < i || chunk_os < oi_end || chunk_ts < ti_end) {
                rc = emit_unstable(&buf, &buf_len, &buf_cap,
                                    &lb, chunk_bs, i,
                                    &lo, chunk_os, oi_end,
                                    &lt, chunk_ts, ti_end,
                                    label_ours, label_theirs, style, &conflicts);
                if (rc) goto fail;
            }
            if (aligned_stable) {
                /* Emit one stable base line */
                rc = emit_lines(&buf, &buf_len, &buf_cap, &lb, i, i + 1);
                if (rc) goto fail;
                chunk_bs = i + 1;
                chunk_os = oi + 1;
                chunk_ts = ti + 1;
            }
        }
    }

    out->data = buf;
    out->len = buf_len;
    out->conflict_count = conflicts;
    out->has_conflicts = (conflicts > 0) ? 1 : 0;

    free(sa); free(sb); free(da.edits); free(db.edits);
    free_lines(&lb); free_lines(&lo); free_lines(&lt);
    return 0;

fail:
    free(buf);
    free(sa); free(sb); free(da.edits); free(db.edits);
    free_lines(&lb); free_lines(&lo); free_lines(&lt);
    return 2;
}

unsigned long diff_merge_destroy(diff_merge_result *r) {
    if (!r) return 1;
    free(r->data);
    r->data = NULL;
    r->len = 0;
    r->conflict_count = 0;
    r->has_conflicts = 0;
    return 0;
}

/* ================================================================
 *  Patience Diff
 *
 *  Algorithm:
 *    1. Find lines that are unique in both a and b (appear exactly once
 *       in each). These are "anchor" candidates.
 *    2. Among anchors, find the longest increasing subsequence of (a_pos,
 *       b_pos) pairs to get the stable matches.
 *    3. Recursively apply patience to the segments between anchors.
 *    4. For small base cases, fall back to Myers/LCS.
 * ================================================================ */

/* Find LIS indices on an array of u64 pairs, returned as a bitmap or index
   list. We use the classic O(n log n) patience sort LIS. */
static unsigned long patience_lis(u64 *bpos, u32 n, u8 *keep) {
    u32 *tails = NULL;
    u32 *prev = NULL;
    u32 *indices = NULL;
    u32 tails_len = 0;
    u32 i;
    u32 last = (u32)-1;

    if (n == 0) return 0;
    tails   = (u32 *)malloc(n * sizeof(u32));
    prev    = (u32 *)malloc(n * sizeof(u32));
    indices = (u32 *)malloc(n * sizeof(u32));
    if (!tails || !prev || !indices) {
        free(tails); free(prev); free(indices);
        return 1;
    }

    for (i = 0; i < n; i++) {
        /* Binary search in tails for leftmost j such that bpos[tails[j]] >= bpos[i] */
        u32 lo = 0, hi = tails_len;
        while (lo < hi) {
            u32 mid = (lo + hi) / 2;
            if (bpos[tails[mid]] < bpos[i]) lo = mid + 1;
            else hi = mid;
        }
        prev[i] = (lo > 0) ? tails[lo - 1] : (u32)-1;
        if (lo == tails_len) { tails[tails_len++] = i; }
        else tails[lo] = i;
    }

    /* Reconstruct indices of LIS */
    if (tails_len > 0) last = tails[tails_len - 1];
    memset(keep, 0, n);
    while (last != (u32)-1) {
        keep[last] = 1;
        last = prev[last];
    }

    free(tails); free(prev); free(indices);
    return 0;
}

/* FNV-1a 64-bit hash of a byte range */
static u64 fnv1a_range(const char *s, u64 n) {
    u64 h = 14695981039346656037ULL;
    u64 i;
    for (i = 0; i < n; i++) {
        h ^= (u8)s[i];
        h *= 1099511628211ULL;
    }
    return h;
}

/* Produce a diff for a sub-range [a_start..a_end) vs [b_start..b_end).
   Appends edits to 'out'. */
static unsigned long patience_sub(diff_result *out,
                                   const line_array *la, u64 a_start, u64 a_end,
                                   const line_array *lb, u64 b_start, u64 b_end) {
    u64 a_n = a_end - a_start;
    u64 b_n = b_end - b_start;
    u64 i, j;

    /* Base cases */
    if (a_n == 0 && b_n == 0) return 0;
    if (a_n == 0) {
        for (j = 0; j < b_n; j++) {
            unsigned long rc = result_push(out, DIFF_INSERT, a_start, b_start + j, 1);
            if (rc) return rc;
        }
        return 0;
    }
    if (b_n == 0) {
        for (i = 0; i < a_n; i++) {
            unsigned long rc = result_push(out, DIFF_DELETE, a_start + i, b_start, 1);
            if (rc) return rc;
        }
        return 0;
    }

    /* Trim common prefix */
    {
        u64 trim = 0;
        while (trim < a_n && trim < b_n &&
               lines_equal(la, a_start + trim, lb, b_start + trim)) {
            unsigned long rc = result_push(out, DIFF_EQUAL,
                                            a_start + trim, b_start + trim, 1);
            if (rc) return rc;
            trim++;
        }
        if (trim > 0) {
            return patience_sub(out, la, a_start + trim, a_end,
                                     lb, b_start + trim, b_end);
        }
    }

    /* Trim common suffix */
    {
        u64 trim = 0;
        while (trim < a_n && trim < b_n &&
               lines_equal(la, a_end - 1 - trim, lb, b_end - 1 - trim)) {
            trim++;
        }
        if (trim > 0) {
            unsigned long rc = patience_sub(out, la, a_start, a_end - trim,
                                                 lb, b_start, b_end - trim);
            if (rc) return rc;
            for (i = 0; i < trim; i++) {
                rc = result_push(out, DIFF_EQUAL,
                                  a_end - trim + i, b_end - trim + i, 1);
                if (rc) return rc;
            }
            return 0;
        }
    }

    /* Find unique-in-both anchor lines.
       hash each line in A and in B, count occurrences. */
    u64 *ha = (u64 *)malloc(a_n * sizeof(u64));
    u64 *hb = (u64 *)malloc(b_n * sizeof(u64));
    if (!ha || !hb) { free(ha); free(hb); return 1; }
    for (i = 0; i < a_n; i++)
        ha[i] = fnv1a_range(la->starts[a_start + i], la->lens[a_start + i]);
    for (j = 0; j < b_n; j++)
        hb[j] = fnv1a_range(lb->starts[b_start + j], lb->lens[b_start + j]);

    /* Count occurrences and remember positions (linear scan is fine for moderate n).
       For anchors: hash h where count_a[h]==1 AND count_b[h]==1 AND la lines
       really match lb lines. */
    typedef struct { u64 h; u64 ai; u64 bi; } anchor;
    anchor *anchors = (anchor *)malloc((a_n < b_n ? a_n : b_n) * sizeof(anchor));
    u32 anchor_count = 0;
    if (!anchors) { free(ha); free(hb); return 1; }

    for (i = 0; i < a_n; i++) {
        u32 ca = 0; u64 first_a = 0;
        u32 cb = 0; u64 first_b = 0;
        for (u64 k = 0; k < a_n; k++) if (ha[k] == ha[i]) { ca++; first_a = k; }
        if (ca != 1) continue;
        for (u64 k = 0; k < b_n; k++) if (hb[k] == ha[i]) { cb++; first_b = k; }
        if (cb != 1) continue;
        /* Full equality check */
        if (!lines_equal(la, a_start + first_a, lb, b_start + first_b)) continue;
        anchors[anchor_count].h  = ha[i];
        anchors[anchor_count].ai = first_a;
        anchors[anchor_count].bi = first_b;
        anchor_count++;
    }

    free(ha); free(hb);

    if (anchor_count == 0) {
        /* No anchors — fall back to LCS diff on this sub-range */
        line_array sub_a, sub_b;
        diff_result sub;
        memset(&sub, 0, sizeof(sub));
        sub_a.starts = la->starts + a_start;
        sub_a.lens   = la->lens + a_start;
        sub_a.count  = a_n;
        sub_b.starts = lb->starts + b_start;
        sub_b.lens   = lb->lens + b_start;
        sub_b.count  = b_n;
        unsigned long rc = lcs_diff(&sub, &sub_a, &sub_b);
        if (rc) { free(anchors); return rc; }
        for (i = 0; i < sub.len; i++) {
            diff_edit e = sub.edits[i];
            e.off_a += a_start;
            e.off_b += b_start;
            rc = result_push(out, e.op, e.off_a, e.off_b, e.len);
            if (rc) { free(sub.edits); free(anchors); return rc; }
        }
        free(sub.edits);
        free(anchors);
        return 0;
    }

    /* Sort anchors by ai ascending */
    for (i = 1; i < anchor_count; i++) {
        anchor k = anchors[i];
        u32 jj = i;
        while (jj > 0 && anchors[jj - 1].ai > k.ai) {
            anchors[jj] = anchors[jj - 1];
            jj--;
        }
        anchors[jj] = k;
    }

    /* Find longest increasing subsequence by bi (patience sort) */
    u64 *bpos = (u64 *)malloc(anchor_count * sizeof(u64));
    u8  *keep = (u8 *)malloc(anchor_count);
    if (!bpos || !keep) { free(bpos); free(keep); free(anchors); return 1; }
    for (i = 0; i < anchor_count; i++) bpos[i] = anchors[i].bi;
    unsigned long rc = patience_lis(bpos, anchor_count, keep);
    if (rc) { free(bpos); free(keep); free(anchors); return rc; }

    /* Recursively diff between anchors */
    u64 prev_a = 0, prev_b = 0;
    for (i = 0; i < anchor_count; i++) {
        if (!keep[i]) continue;
        /* Recurse on [prev_a..anchors[i].ai), [prev_b..anchors[i].bi) */
        rc = patience_sub(out, la, a_start + prev_a, a_start + anchors[i].ai,
                                lb, b_start + prev_b, b_start + anchors[i].bi);
        if (rc) { free(bpos); free(keep); free(anchors); return rc; }
        /* Emit the anchor itself as EQUAL */
        rc = result_push(out, DIFF_EQUAL,
                          a_start + anchors[i].ai,
                          b_start + anchors[i].bi, 1);
        if (rc) { free(bpos); free(keep); free(anchors); return rc; }
        prev_a = anchors[i].ai + 1;
        prev_b = anchors[i].bi + 1;
    }
    /* Tail after last anchor */
    rc = patience_sub(out, la, a_start + prev_a, a_end,
                            lb, b_start + prev_b, b_end);
    free(bpos); free(keep); free(anchors);
    return rc;
}

unsigned long diff_patience(diff_result *out,
                             const char *a, u64 a_len,
                             const char *b, u64 b_len) {
    line_array la, lb;
    unsigned long rc;
    if (!out) return 1;
    memset(out, 0, sizeof(*out));
    if (split_lines(&la, a, a_len) != 0) return 2;
    if (split_lines(&lb, b, b_len) != 0) { free_lines(&la); return 3; }
    rc = patience_sub(out, &la, 0, la.count, &lb, 0, lb.count);
    free_lines(&la);
    free_lines(&lb);
    return rc == 0 ? 0 : 4;
}

/* ================================================================
 *  Histogram Diff
 *
 *  For each region, find the rarest line that appears in both sides,
 *  use it as a split point, recurse. Fallback to patience/LCS if
 *  no suitable split found.
 * ================================================================ */

static unsigned long histogram_sub(diff_result *out,
                                    const line_array *la, u64 a_start, u64 a_end,
                                    const line_array *lb, u64 b_start, u64 b_end) {
    u64 a_n = a_end - a_start;
    u64 b_n = b_end - b_start;
    u64 i, j;

    if (a_n == 0 && b_n == 0) return 0;
    if (a_n == 0) {
        for (j = 0; j < b_n; j++) {
            unsigned long rc = result_push(out, DIFF_INSERT, a_start, b_start + j, 1);
            if (rc) return rc;
        }
        return 0;
    }
    if (b_n == 0) {
        for (i = 0; i < a_n; i++) {
            unsigned long rc = result_push(out, DIFF_DELETE, a_start + i, b_start, 1);
            if (rc) return rc;
        }
        return 0;
    }

    /* Trim common prefix/suffix */
    {
        u64 trim = 0;
        while (trim < a_n && trim < b_n &&
               lines_equal(la, a_start + trim, lb, b_start + trim)) {
            unsigned long rc = result_push(out, DIFF_EQUAL,
                                            a_start + trim, b_start + trim, 1);
            if (rc) return rc;
            trim++;
        }
        if (trim > 0) {
            return histogram_sub(out, la, a_start + trim, a_end,
                                      lb, b_start + trim, b_end);
        }
    }
    {
        u64 trim = 0;
        while (trim < a_n && trim < b_n &&
               lines_equal(la, a_end - 1 - trim, lb, b_end - 1 - trim)) {
            trim++;
        }
        if (trim > 0) {
            unsigned long rc = histogram_sub(out, la, a_start, a_end - trim,
                                                   lb, b_start, b_end - trim);
            if (rc) return rc;
            for (i = 0; i < trim; i++) {
                rc = result_push(out, DIFF_EQUAL,
                                  a_end - trim + i, b_end - trim + i, 1);
                if (rc) return rc;
            }
            return 0;
        }
    }

    /* Histogram: hash each line in A, count occurrences.
       For each line in A that also appears in B, pick the rarest match. */
    u64 *ha = (u64 *)malloc(a_n * sizeof(u64));
    u64 *hb = (u64 *)malloc(b_n * sizeof(u64));
    if (!ha || !hb) { free(ha); free(hb); return 1; }
    for (i = 0; i < a_n; i++)
        ha[i] = fnv1a_range(la->starts[a_start + i], la->lens[a_start + i]);
    for (j = 0; j < b_n; j++)
        hb[j] = fnv1a_range(lb->starts[b_start + j], lb->lens[b_start + j]);

    u64 best_a = (u64)-1, best_b = (u64)-1;
    u64 best_rarity = (u64)-1;

    for (i = 0; i < a_n; i++) {
        u64 ca = 0;
        for (u64 k = 0; k < a_n; k++) if (ha[k] == ha[i]) ca++;
        u64 cb = 0;
        u64 first_b = (u64)-1;
        for (u64 k = 0; k < b_n; k++) {
            if (hb[k] == ha[i]) {
                if (first_b == (u64)-1) first_b = k;
                cb++;
            }
        }
        if (cb == 0) continue;
        if (!lines_equal(la, a_start + i, lb, b_start + first_b)) continue;
        u64 rarity = ca + cb;
        if (rarity < best_rarity) {
            best_rarity = rarity;
            best_a = i;
            best_b = first_b;
        }
    }

    free(ha); free(hb);

    if (best_a == (u64)-1) {
        /* No common line — fall back to LCS on this region */
        line_array sub_a, sub_b;
        diff_result sub;
        memset(&sub, 0, sizeof(sub));
        sub_a.starts = la->starts + a_start;
        sub_a.lens   = la->lens + a_start;
        sub_a.count  = a_n;
        sub_b.starts = lb->starts + b_start;
        sub_b.lens   = lb->lens + b_start;
        sub_b.count  = b_n;
        unsigned long rc = lcs_diff(&sub, &sub_a, &sub_b);
        if (rc) return rc;
        for (i = 0; i < sub.len; i++) {
            diff_edit e = sub.edits[i];
            e.off_a += a_start;
            e.off_b += b_start;
            rc = result_push(out, e.op, e.off_a, e.off_b, e.len);
            if (rc) { free(sub.edits); return rc; }
        }
        free(sub.edits);
        return 0;
    }

    /* Recurse on left and right halves around the split point */
    unsigned long rc;
    rc = histogram_sub(out, la, a_start, a_start + best_a,
                             lb, b_start, b_start + best_b);
    if (rc) return rc;
    rc = result_push(out, DIFF_EQUAL,
                      a_start + best_a, b_start + best_b, 1);
    if (rc) return rc;
    rc = histogram_sub(out, la, a_start + best_a + 1, a_end,
                             lb, b_start + best_b + 1, b_end);
    return rc;
}

unsigned long diff_histogram(diff_result *out,
                              const char *a, u64 a_len,
                              const char *b, u64 b_len) {
    line_array la, lb;
    unsigned long rc;
    if (!out) return 1;
    memset(out, 0, sizeof(*out));
    if (split_lines(&la, a, a_len) != 0) return 2;
    if (split_lines(&lb, b, b_len) != 0) { free_lines(&la); return 3; }
    rc = histogram_sub(out, &la, 0, la.count, &lb, 0, lb.count);
    free_lines(&la);
    free_lines(&lb);
    return rc == 0 ? 0 : 4;
}
