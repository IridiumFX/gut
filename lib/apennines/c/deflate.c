#include "apennines/compress.h"
#include "apennines/buf.h"
#include <string.h>
#include <stdlib.h>

/* Static copy of read32 (originally lz4_read32 from the LZ4 section) */
static u32 read32(const u8 *p) {
    u32 v;
    memcpy(&v, p, 4);
    return v;
}

/* ================================================================
 *  Deflate Compress (Fixed Huffman only, RFC 1951)
 *
 *  Uses fixed Huffman codes for simplicity:
 *    Lit 0-143:   8 bits  00110000 - 10111111
 *    Lit 144-255: 9 bits  110010000 - 111111111
 *    Lit 256:     7 bits  0000000
 *    Lengths 257-285: 7-8 bits
 *    Distances:   5 bits (fixed codes 0-29)
 *
 *  Hash-chain match finding with 32K window.
 * ================================================================ */

/* Bit-writer state for deflate */
typedef struct {
    buf *out;
    u32 bits;
    u32 nbits;
} bit_writer;

static void bw_init(bit_writer *bw, buf *out) {
    bw->out = out;
    bw->bits = 0;
    bw->nbits = 0;
}

static unsigned long bw_write(bit_writer *bw, u32 value, u32 count) {
    unsigned long rc;
    bw->bits |= (value << bw->nbits);
    bw->nbits += count;
    while (bw->nbits >= 8) {
        u8 b = (u8)(bw->bits & 0xFF);
        rc = buf_append_byte(bw->out, b);
        if (rc) return rc;
        bw->bits >>= 8;
        bw->nbits -= 8;
    }
    return 0;
}

static unsigned long bw_flush(bit_writer *bw) {
    unsigned long rc;
    if (bw->nbits > 0) {
        u8 b = (u8)(bw->bits & 0xFF);
        rc = buf_append_byte(bw->out, b);
        if (rc) return rc;
        bw->bits = 0;
        bw->nbits = 0;
    }
    return 0;
}

/* Write a fixed Huffman literal/length code (RFC 1951 section 3.2.6).
   Codes are written LSB-first. The fixed code values are:
     0-143:   8 bits, codes 0x30-0xBF  (reversed)
     144-255: 9 bits, codes 0x190-0x1FF (reversed)
     256-279: 7 bits, codes 0x00-0x17   (reversed)
     280-287: 8 bits, codes 0xC0-0xC7   (reversed)
*/

static u32 reverse_bits(u32 val, u32 nbits) {
    u32 result = 0;
    u32 i;
    for (i = 0; i < nbits; i++) {
        result = (result << 1) | (val & 1);
        val >>= 1;
    }
    return result;
}

static unsigned long deflate_write_fixed_code(bit_writer *bw, u32 symbol) {
    if (symbol <= 143) {
        /* 8 bits: code = 0x30 + symbol */
        return bw_write(bw, reverse_bits(0x30 + symbol, 8), 8);
    } else if (symbol <= 255) {
        /* 9 bits: code = 0x190 + (symbol - 144) */
        return bw_write(bw, reverse_bits(0x190 + (symbol - 144), 9), 9);
    } else if (symbol <= 279) {
        /* 7 bits: code = 0x00 + (symbol - 256) */
        return bw_write(bw, reverse_bits(0x00 + (symbol - 256), 7), 7);
    } else {
        /* 8 bits: code = 0xC0 + (symbol - 280) */
        return bw_write(bw, reverse_bits(0xC0 + (symbol - 280), 8), 8);
    }
}

/* Length encoding tables (RFC 1951 section 3.2.5) */
static const u16 len_base[] = {
    3,4,5,6,7,8,9,10, 11,13,15,17, 19,23,27,31,
    35,43,51,59, 67,83,99,115, 131,163,195,227, 258
};
static const u8 len_extra[] = {
    0,0,0,0,0,0,0,0, 1,1,1,1, 2,2,2,2,
    3,3,3,3, 4,4,4,4, 5,5,5,5, 0
};

/* Distance encoding tables */
static const u16 dist_base[] = {
    1,2,3,4, 5,7,9,13, 17,25,33,49, 65,97,129,193,
    257,385,513,769, 1025,1537,2049,3073, 4097,6145,8193,12289,
    16385,24577
};
static const u8 dist_extra[] = {
    0,0,0,0, 1,1,2,2, 3,3,4,4, 5,5,6,6,
    7,7,8,8, 9,9,10,10, 11,11,12,12, 13,13
};

static u32 deflate_find_len_code(u32 length) {
    u32 i;
    for (i = 0; i < 29; i++) {
        u32 top = (i < 28) ? len_base[i + 1] : 259;
        if (length < top) return i;
    }
    return 28;
}

static u32 deflate_find_dist_code(u32 distance) {
    u32 i;
    for (i = 0; i < 30; i++) {
        u32 top = (i < 29) ? dist_base[i + 1] : 32769;
        if (distance < top) return i;
    }
    return 29;
}

#define DEFLATE_HASH_BITS  15
#define DEFLATE_HASH_SIZE  (1 << DEFLATE_HASH_BITS)
#define DEFLATE_WINDOW     32768
#define DEFLATE_MIN_MATCH  3
#define DEFLATE_MAX_MATCH  258

static u32 deflate_hash(u32 val) {
    return (val * 2654435761u) >> (32 - DEFLATE_HASH_BITS);
}

/* ================================================================
 *  Token stream for Huffman encoding
 *
 *  LZ77 matching produces a sequence of tokens that both fixed and
 *  dynamic Huffman encoders consume. This decouples match finding
 *  from entropy coding.
 * ================================================================ */

typedef struct {
    u16 lit_or_len;  /* 0-255 literal; 256 EOB; 257-285 length code */
    u16 len_extra;   /* raw extra bits value for length */
    u16 dist_code;   /* 0-29 distance code (valid if lit_or_len >= 257) */
    u16 dist_extra;  /* raw extra bits value for distance */
} deflate_token;

/* Run LZ77 on the input, producing a flat token array.
   Caller frees *out_tokens. */
static unsigned long deflate_tokenize(deflate_token **out_tokens, u64 *out_count,
                                       const u8 *data, u64 len) {
    u32 *hash_table;
    u64 ip;
    u64 cap;
    u64 cnt = 0;
    deflate_token *tokens;

    cap = len + 16;   /* at most 1 token per byte, plus EOB */
    tokens = (deflate_token *)malloc(cap * sizeof(deflate_token));
    if (!tokens) return 1;

    hash_table = (u32 *)calloc(DEFLATE_HASH_SIZE, sizeof(u32));
    if (!hash_table) { free(tokens); return 1; }

    ip = 0;
    while (ip < len) {
        u64 best_len = 0;
        u64 best_dist = 0;

        if (ip + DEFLATE_MIN_MATCH <= len) {
            u32 h = deflate_hash(read32((u8 *)data + ip) & 0xFFFFFF);
            u64 raw = hash_table[h];
            hash_table[h] = (u32)(ip + 1);

            if (raw > 0) {
                u64 ref = raw - 1;
                if (ip > ref && ip - ref <= DEFLATE_WINDOW) {
                    u64 ml = 0;
                    while (ip + ml < len && ml < DEFLATE_MAX_MATCH &&
                           data[ref + ml] == data[ip + ml]) {
                        ml++;
                    }
                    if (ml >= DEFLATE_MIN_MATCH) {
                        best_len = ml;
                        best_dist = ip - ref;
                    }
                }
            }
        }

        if (best_len >= DEFLATE_MIN_MATCH) {
            u32 lc = deflate_find_len_code((u32)best_len);
            u32 dc = deflate_find_dist_code((u32)best_dist);
            tokens[cnt].lit_or_len = (u16)(257 + lc);
            tokens[cnt].len_extra  = (u16)(best_len - len_base[lc]);
            tokens[cnt].dist_code  = (u16)dc;
            tokens[cnt].dist_extra = (u16)(best_dist - dist_base[dc]);
            cnt++;

            {
                u64 j;
                for (j = 1; j < best_len && ip + j + DEFLATE_MIN_MATCH <= len; j++) {
                    u32 hh = deflate_hash(read32((u8 *)data + ip + j) & 0xFFFFFF);
                    hash_table[hh] = (u32)(ip + j + 1);
                }
            }
            ip += best_len;
        } else {
            tokens[cnt].lit_or_len = data[ip];
            tokens[cnt].len_extra  = 0;
            tokens[cnt].dist_code  = 0;
            tokens[cnt].dist_extra = 0;
            cnt++;
            ip++;
        }
    }

    /* End-of-block marker */
    tokens[cnt].lit_or_len = 256;
    tokens[cnt].len_extra  = 0;
    tokens[cnt].dist_code  = 0;
    tokens[cnt].dist_extra = 0;
    cnt++;

    free(hash_table);
    *out_tokens = tokens;
    *out_count  = cnt;
    return 0;
}

/* ================================================================
 *  BTYPE=0 Stored Block Encoder
 *
 *  Each stored block holds up to 65535 bytes of raw data.
 *  Layout: BFINAL(1) + BTYPE=00(2) + pad to byte + LEN(16 LE)
 *          + NLEN(16 LE, = ~LEN) + LEN raw bytes.
 * ================================================================ */

static unsigned long deflate_emit_stored(buf *out, const u8 *data, u64 len) {
    bit_writer bw;
    unsigned long rc;
    u64 pos = 0;

    bw_init(&bw, out);

    if (len == 0) {
        /* Single empty final stored block */
        rc = bw_write(&bw, 1, 1); if (rc) return rc;  /* BFINAL=1 */
        rc = bw_write(&bw, 0, 2); if (rc) return rc;  /* BTYPE=00 */
        rc = bw_flush(&bw);       if (rc) return rc;
        u8 hdr[4] = { 0x00, 0x00, 0xFF, 0xFF };
        return buf_append(out, hdr, 4);
    }

    while (pos < len) {
        u64 block_len = len - pos;
        int is_final;
        u16 lv, nlv;
        u8 hdr[4];

        if (block_len > 65535) block_len = 65535;
        is_final = (pos + block_len == len) ? 1 : 0;

        rc = bw_write(&bw, (u32)is_final, 1); if (rc) return rc;
        rc = bw_write(&bw, 0, 2);             if (rc) return rc;
        rc = bw_flush(&bw);                   if (rc) return rc;

        lv  = (u16)block_len;
        nlv = (u16)(~lv);
        hdr[0] = (u8)(lv  & 0xFF);
        hdr[1] = (u8)(lv  >> 8);
        hdr[2] = (u8)(nlv & 0xFF);
        hdr[3] = (u8)(nlv >> 8);
        rc = buf_append(out, hdr, 4);         if (rc) return rc;
        rc = buf_append(out, (u8 *)data + pos, block_len);
        if (rc) return rc;

        pos += block_len;
    }
    return 0;
}

/* ================================================================
 *  BTYPE=1 Fixed Huffman Encoder (from tokens)
 * ================================================================ */

static unsigned long deflate_emit_fixed(buf *out, const deflate_token *tokens, u64 count) {
    bit_writer bw;
    unsigned long rc;
    u64 i;

    bw_init(&bw, out);

    rc = bw_write(&bw, 1, 1); if (rc) return rc;  /* BFINAL=1 */
    rc = bw_write(&bw, 1, 2); if (rc) return rc;  /* BTYPE=01 */

    for (i = 0; i < count; i++) {
        const deflate_token *t = &tokens[i];
        if (t->lit_or_len < 256) {
            /* Literal */
            rc = deflate_write_fixed_code(&bw, t->lit_or_len); if (rc) return rc;
        } else if (t->lit_or_len == 256) {
            /* End of block */
            rc = deflate_write_fixed_code(&bw, 256); if (rc) return rc;
        } else {
            /* Length code + extras + distance + extras */
            u32 lc = t->lit_or_len - 257;
            rc = deflate_write_fixed_code(&bw, t->lit_or_len); if (rc) return rc;
            if (len_extra[lc] > 0) {
                rc = bw_write(&bw, t->len_extra, len_extra[lc]); if (rc) return rc;
            }
            rc = bw_write(&bw, reverse_bits(t->dist_code, 5), 5); if (rc) return rc;
            if (dist_extra[t->dist_code] > 0) {
                rc = bw_write(&bw, t->dist_extra, dist_extra[t->dist_code]); if (rc) return rc;
            }
        }
    }

    return bw_flush(&bw);
}

/* ================================================================
 *  BTYPE=2 Dynamic Huffman Encoder
 *
 *  Algorithm (RFC 1951 S3.2.7):
 *    1. Count symbol frequencies from tokens (lit/len alphabet 0-285,
 *       distance alphabet 0-29).
 *    2. Build length-limited Huffman code lengths (max 15 bits) for
 *       both alphabets.
 *    3. Compute canonical codes from code lengths.
 *    4. Merge lit/len and distance code-length arrays, RLE-encode them
 *       using symbols 0-15 (length) / 16 (repeat prev 3-6) / 17 (zero
 *       run 3-10) / 18 (zero run 11-138) -> emits a "cl symbol" stream.
 *    5. Count frequencies of cl symbols, build code lengths for the
 *       code-length alphabet (19 symbols), max 7 bits.
 *    6. Trim trailing zeros from the CL code lengths (HCLEN).
 *    7. Write block header: BFINAL + BTYPE=10 + HLIT + HDIST + HCLEN
 *       + CL code lengths (in fixed permuted order) + RLE stream of
 *       lit/len and distance code lengths.
 *    8. Emit compressed data using the new Huffman codes.
 * ================================================================ */

#define DYN_LITLEN_MAX   286     /* literal/length alphabet size */
#define DYN_DIST_MAX     30      /* distance alphabet size */
#define DYN_CL_MAX       19      /* code-length alphabet size */
#define DYN_LITLEN_BITS  15      /* max code length for lit/len */
#define DYN_DIST_BITS    15      /* max code length for distance */
#define DYN_CL_BITS      7       /* max code length for code-length alphabet */

/* Order in which CL code lengths are written in the header (S3.2.7) */
static const u8 cl_order[DYN_CL_MAX] = {
    16,17,18, 0,8,7,9,6,10,5,11,4,12,3,13,2,14,1,15
};

/* Length-limited Huffman: produce code lengths (0 means unused).
   Uses a reliable in-place construction:
     - Build frequency-ordered leaves
     - Apply classic Huffman merging to compute depths
     - If any depth > max_bits, redistribute using the iterative
       "pull longer codes shorter" algorithm.
   freqs[i] = symbol frequency (0 = unused).
   out_lens[i] = code length (0-max_bits).
   n = alphabet size. */
static unsigned long huff_build_lengths(u32 *freqs, u8 *out_lens, u32 n, u32 max_bits) {
    u32 i;
    u32 nsymbols = 0;

    /* Zero-init */
    for (i = 0; i < n; i++) out_lens[i] = 0;

    /* Collect used symbols */
    typedef struct { u32 freq; u32 sym; u32 depth; } leaf;
    leaf *leaves = (leaf *)malloc(n * sizeof(leaf));
    if (!leaves) return 1;
    for (i = 0; i < n; i++) {
        if (freqs[i] > 0) {
            leaves[nsymbols].freq  = freqs[i];
            leaves[nsymbols].sym   = i;
            leaves[nsymbols].depth = 0;
            nsymbols++;
        }
    }

    if (nsymbols == 0) { free(leaves); return 0; }
    if (nsymbols == 1) {
        /* Edge case: single symbol. Assign length 1. */
        out_lens[leaves[0].sym] = 1;
        free(leaves);
        return 0;
    }

    /* Sort leaves by frequency ascending (insertion sort is fine for <=286). */
    for (i = 1; i < nsymbols; i++) {
        leaf k = leaves[i];
        u32 j = i;
        while (j > 0 && leaves[j - 1].freq > k.freq) {
            leaves[j] = leaves[j - 1];
            j--;
        }
        leaves[j] = k;
    }

    /* Build Huffman tree by combining two lowest-frequency items repeatedly.
       We track "virtual" internal nodes as aggregated leaves:
       - node pool holds combined-frequency entries
       - each combination increments depth of all leaves under the merged node.
       To avoid a real tree, we use a two-queue method with fake depth tracking.

       Simpler (and correct) approach: use an explicit tree.
       Each node has parent; we later walk from each leaf to root counting depth. */

    /* Total nodes: nsymbols leaves + (nsymbols - 1) internal */
    typedef struct { u32 freq; i32 parent; } hnode;
    u32 total = nsymbols * 2 - 1;
    hnode *nodes = (hnode *)malloc(total * sizeof(hnode));
    if (!nodes) { free(leaves); return 1; }
    /* Leaves occupy nodes[0..nsymbols-1] in frequency-sorted order */
    for (i = 0; i < nsymbols; i++) {
        nodes[i].freq = leaves[i].freq;
        nodes[i].parent = -1;
    }

    /* Two-queue Huffman: q1 = sorted leaves (consumed left-to-right),
       q2 = internal nodes (grows as we combine). Always take the two
       lowest-frequency heads from either queue. */
    {
        u32 next_internal = nsymbols;   /* where next internal node goes */
        u32 q1_head = 0;                /* head of leaves queue */
        u32 q2_head = nsymbols;         /* head of internals queue */
        u32 q2_tail = nsymbols;         /* one past last internal */

        while (next_internal < total) {
            u32 a, b;
            /* Pick smallest of q1_head, q2_head */
            #define PICK_MIN(out_idx)                                     \
                do {                                                      \
                    int take1 = (q1_head < nsymbols);                     \
                    int take2 = (q2_head < q2_tail);                      \
                    if (take1 && take2) {                                 \
                        if (nodes[q1_head].freq <= nodes[q2_head].freq) { \
                            out_idx = q1_head++;                          \
                        } else {                                          \
                            out_idx = q2_head++;                          \
                        }                                                 \
                    } else if (take1) {                                   \
                        out_idx = q1_head++;                              \
                    } else {                                              \
                        out_idx = q2_head++;                              \
                    }                                                     \
                } while (0)
            PICK_MIN(a);
            PICK_MIN(b);
            #undef PICK_MIN

            nodes[next_internal].freq = nodes[a].freq + nodes[b].freq;
            nodes[next_internal].parent = -1;
            nodes[a].parent = (i32)next_internal;
            nodes[b].parent = (i32)next_internal;
            q2_tail = next_internal + 1;
            next_internal++;
        }
    }

    /* Compute depth of each leaf by walking up to root. */
    for (i = 0; i < nsymbols; i++) {
        u32 d = 0;
        i32 p = nodes[i].parent;
        while (p >= 0) { d++; p = nodes[p].parent; }
        leaves[i].depth = d;
        out_lens[leaves[i].sym] = (u8)d;
    }

    free(nodes);

    /* If any code length exceeds max_bits, enforce the limit.
       Simple iterative rebalancing: find the longest code, shorten it
       by 1 by "pairing" with a shorter code (which we extend by 1).
       Continue until all lengths <= max_bits. */
    for (;;) {
        u32 max_found = 0;
        u32 max_idx = 0;
        for (i = 0; i < n; i++) {
            if (out_lens[i] > max_found) {
                max_found = out_lens[i];
                max_idx   = i;
            }
        }
        if (max_found <= max_bits) break;

        /* Find a shorter code to lengthen. Pick the shortest nonzero. */
        u32 short_len = max_bits;
        u32 short_idx = (u32)-1;
        for (i = 0; i < n; i++) {
            if (out_lens[i] > 0 && out_lens[i] < short_len) {
                short_len = out_lens[i];
                short_idx = i;
            }
        }
        if (short_idx == (u32)-1) break;  /* Can't fix */

        out_lens[max_idx]--;
        out_lens[short_idx]++;
    }

    free(leaves);
    return 0;
}

/* Generate canonical Huffman codes from code lengths.
   Codes are right-justified, LSB-first bit patterns (matching the format
   for writing to the deflate bit stream: we need to reverse them before
   writing since deflate sends bits LSB-first). */
static void huff_gen_codes(const u8 *lens, u16 *codes, u32 n, u32 max_bits) {
    u32 bl_count[16];
    u32 next_code[16];
    u32 i;
    u32 code = 0;

    for (i = 0; i <= max_bits; i++) bl_count[i] = 0;
    for (i = 0; i < n; i++) {
        if (lens[i] > 0 && lens[i] <= max_bits) bl_count[lens[i]]++;
    }
    bl_count[0] = 0;

    for (i = 1; i <= max_bits; i++) {
        code = (code + bl_count[i - 1]) << 1;
        next_code[i] = code;
    }
    for (i = 0; i < n; i++) {
        if (lens[i] > 0) {
            codes[i] = (u16)next_code[lens[i]];
            next_code[lens[i]]++;
        } else {
            codes[i] = 0;
        }
    }
}

/* RLE-encode combined code lengths into cl_symbols + cl_extras.
   Returns the number of cl entries written. */
typedef struct {
    u8  sym;    /* 0-18 cl symbol */
    u8  extra;  /* extra bits value (for 16/17/18) */
} cl_entry;

static u32 rle_encode_code_lengths(const u8 *combined, u32 n, cl_entry *out) {
    u32 i = 0;
    u32 oi = 0;
    while (i < n) {
        u8 v = combined[i];
        u32 run = 1;
        while (i + run < n && combined[i + run] == v) run++;

        if (v == 0) {
            /* Zero run */
            while (run >= 11) {
                u32 r = run > 138 ? 138 : run;
                out[oi].sym = 18;
                out[oi].extra = (u8)(r - 11);  /* 7 bits: 0-127 */
                oi++;
                run -= r;
            }
            if (run >= 3) {
                out[oi].sym = 17;
                out[oi].extra = (u8)(run - 3);  /* 3 bits: 0-7 */
                oi++;
                run = 0;
            }
            while (run > 0) {
                out[oi].sym = 0;
                out[oi].extra = 0;
                oi++;
                run--;
            }
        } else {
            /* Non-zero: emit one literal, then repeat with sym 16 */
            out[oi].sym = v;
            out[oi].extra = 0;
            oi++;
            run--;
            while (run >= 3) {
                u32 r = run > 6 ? 6 : run;
                out[oi].sym = 16;
                out[oi].extra = (u8)(r - 3);  /* 2 bits: 0-3 */
                oi++;
                run -= r;
            }
            while (run > 0) {
                out[oi].sym = v;
                out[oi].extra = 0;
                oi++;
                run--;
            }
        }
        i += 1 + (combined[i] == v ? 0 : 0);
        /* Advance past the run we consumed */
        while (i < n && combined[i] == v) i++;
    }
    return oi;
}

static unsigned long deflate_emit_dynamic(buf *out, const deflate_token *tokens, u64 count) {
    bit_writer bw;
    unsigned long rc;
    u32 lit_freq[DYN_LITLEN_MAX];
    u32 dist_freq[DYN_DIST_MAX];
    u8  lit_lens[DYN_LITLEN_MAX];
    u8  dist_lens[DYN_DIST_MAX];
    u16 lit_codes[DYN_LITLEN_MAX];
    u16 dist_codes[DYN_DIST_MAX];
    u64 i;

    /* 1. Count frequencies */
    for (i = 0; i < DYN_LITLEN_MAX; i++) lit_freq[i] = 0;
    for (i = 0; i < DYN_DIST_MAX; i++)   dist_freq[i] = 0;

    for (i = 0; i < count; i++) {
        const deflate_token *t = &tokens[i];
        lit_freq[t->lit_or_len]++;
        if (t->lit_or_len >= 257) {
            dist_freq[t->dist_code]++;
        }
    }
    /* Ensure EOB has a frequency so it's guaranteed a code */
    if (lit_freq[256] == 0) lit_freq[256] = 1;

    /* RFC 1951: there must always be at least one distance code even if
       no matches were emitted, otherwise the dynamic header is ill-formed.
       Give symbol 0 a phantom frequency so it gets a code. */
    {
        int any_dist = 0;
        for (i = 0; i < DYN_DIST_MAX; i++) if (dist_freq[i]) { any_dist = 1; break; }
        if (!any_dist) dist_freq[0] = 1;
    }

    /* 2. Build code lengths for lit/len and distance alphabets */
    rc = huff_build_lengths(lit_freq,  lit_lens,  DYN_LITLEN_MAX, DYN_LITLEN_BITS);
    if (rc) return rc;
    rc = huff_build_lengths(dist_freq, dist_lens, DYN_DIST_MAX,   DYN_DIST_BITS);
    if (rc) return rc;

    /* 3. Generate canonical codes */
    huff_gen_codes(lit_lens,  lit_codes,  DYN_LITLEN_MAX, DYN_LITLEN_BITS);
    huff_gen_codes(dist_lens, dist_codes, DYN_DIST_MAX,   DYN_DIST_BITS);

    /* 4. Determine HLIT and HDIST (# of codes - base) */
    u32 hlit = DYN_LITLEN_MAX;
    while (hlit > 257 && lit_lens[hlit - 1] == 0) hlit--;
    u32 hdist = DYN_DIST_MAX;
    while (hdist > 1 && dist_lens[hdist - 1] == 0) hdist--;

    /* 5. Concatenate lit_lens[0..hlit-1] and dist_lens[0..hdist-1] and RLE */
    u8 combined[DYN_LITLEN_MAX + DYN_DIST_MAX];
    for (i = 0; i < hlit;  i++) combined[i]          = lit_lens[i];
    for (i = 0; i < hdist; i++) combined[hlit + i]   = dist_lens[i];
    u32 total_lens = hlit + hdist;

    cl_entry cl_entries[DYN_LITLEN_MAX + DYN_DIST_MAX];
    u32 cl_count = rle_encode_code_lengths(combined, total_lens, cl_entries);

    /* 6. Count CL symbol frequencies, build CL Huffman tree */
    u32 cl_freq[DYN_CL_MAX];
    for (i = 0; i < DYN_CL_MAX; i++) cl_freq[i] = 0;
    for (i = 0; i < cl_count; i++) cl_freq[cl_entries[i].sym]++;

    u8  cl_lens[DYN_CL_MAX];
    u16 cl_codes[DYN_CL_MAX];
    rc = huff_build_lengths(cl_freq, cl_lens, DYN_CL_MAX, DYN_CL_BITS);
    if (rc) return rc;
    huff_gen_codes(cl_lens, cl_codes, DYN_CL_MAX, DYN_CL_BITS);

    /* 7. HCLEN: number of CL lengths written, minimum 4.
       We write cl_lens in the permuted cl_order, and only the first HCLEN
       of them. Trim trailing zeros (but not below 4 entries). */
    u32 hclen = DYN_CL_MAX;
    while (hclen > 4 && cl_lens[cl_order[hclen - 1]] == 0) hclen--;

    /* 8. Write header and data */
    bw_init(&bw, out);

    rc = bw_write(&bw, 1, 1); if (rc) return rc;  /* BFINAL */
    rc = bw_write(&bw, 2, 2); if (rc) return rc;  /* BTYPE=10 dynamic */

    rc = bw_write(&bw, hlit  - 257, 5); if (rc) return rc;
    rc = bw_write(&bw, hdist - 1,   5); if (rc) return rc;
    rc = bw_write(&bw, hclen - 4,   4); if (rc) return rc;

    /* CL code lengths in permuted order, 3 bits each */
    for (i = 0; i < hclen; i++) {
        rc = bw_write(&bw, cl_lens[cl_order[i]], 3);
        if (rc) return rc;
    }

    /* Lit/len + distance code lengths via CL Huffman (RLE stream) */
    for (i = 0; i < cl_count; i++) {
        u8 sym = cl_entries[i].sym;
        u8 extra = cl_entries[i].extra;
        /* Emit the CL-Huffman code (reversed, LSB-first) */
        rc = bw_write(&bw, reverse_bits(cl_codes[sym], cl_lens[sym]), cl_lens[sym]);
        if (rc) return rc;
        /* Extra bits for repeat codes */
        if (sym == 16)      { rc = bw_write(&bw, extra, 2); if (rc) return rc; }
        else if (sym == 17) { rc = bw_write(&bw, extra, 3); if (rc) return rc; }
        else if (sym == 18) { rc = bw_write(&bw, extra, 7); if (rc) return rc; }
    }

    /* Compressed data: emit each token using lit/len and dist codes */
    for (i = 0; i < count; i++) {
        const deflate_token *t = &tokens[i];
        u16 sym = t->lit_or_len;
        rc = bw_write(&bw, reverse_bits(lit_codes[sym], lit_lens[sym]), lit_lens[sym]);
        if (rc) return rc;
        if (sym >= 257) {
            u32 lc = sym - 257;
            if (len_extra[lc] > 0) {
                rc = bw_write(&bw, t->len_extra, len_extra[lc]);
                if (rc) return rc;
            }
            rc = bw_write(&bw, reverse_bits(dist_codes[t->dist_code], dist_lens[t->dist_code]),
                          dist_lens[t->dist_code]);
            if (rc) return rc;
            if (dist_extra[t->dist_code] > 0) {
                rc = bw_write(&bw, t->dist_extra, dist_extra[t->dist_code]);
                if (rc) return rc;
            }
        }
    }

    return bw_flush(&bw);
}

/* ================================================================
 *  Public entry point -- dispatch by level
 * ================================================================ */

unsigned long deflate_compress(buf *out, u8 *data, u64 len, compress_level level) {
    unsigned long rc;
    deflate_token *tokens;
    u64 count;

    if (!out) return 1;
    if (len > 0 && !data) return 2;

    /* LEVEL_FAST: stored block (no compression) */
    if ((int)level <= (int)COMPRESS_LEVEL_FAST) {
        return deflate_emit_stored(out, data, len);
    }

    /* LEVEL_DEFAULT and LEVEL_BEST: run LZ77 tokenization first */
    if (len == 0) {
        /* Empty input: emit a fixed-Huffman block with just EOB */
        bit_writer bw;
        bw_init(&bw, out);
        rc = bw_write(&bw, 1, 1); if (rc) return 3;  /* BFINAL */
        rc = bw_write(&bw, 1, 2); if (rc) return 3;  /* BTYPE=01 */
        rc = deflate_write_fixed_code(&bw, 256); if (rc) return 3;
        return bw_flush(&bw);
    }

    rc = deflate_tokenize(&tokens, &count, data, len);
    if (rc) return 4;

    if ((int)level >= (int)COMPRESS_LEVEL_BEST) {
        rc = deflate_emit_dynamic(out, tokens, count);
    } else {
        rc = deflate_emit_fixed(out, tokens, count);
    }
    free(tokens);
    return rc ? 3 : 0;
}

/* ================================================================
 *  Deflate Decompress (RFC 1951, fixed Huffman only)
 * ================================================================ */

typedef struct {
    u8  *data;
    u64  len;
    u64  pos;
    u32  bits;
    u32  nbits;
} bit_reader;

static void br_init(bit_reader *br, u8 *data, u64 len) {
    br->data = data;
    br->len = len;
    br->pos = 0;
    br->bits = 0;
    br->nbits = 0;
}

static unsigned long br_read(bit_reader *br, u32 count, u32 *result) {
    while (br->nbits < count) {
        if (br->pos >= br->len) return 1;
        br->bits |= ((u32)br->data[br->pos++]) << br->nbits;
        br->nbits += 8;
    }
    *result = br->bits & ((1u << count) - 1);
    br->bits >>= count;
    br->nbits -= count;
    return 0;
}

/* Decode a fixed Huffman literal/length symbol.
   We read bits LSB-first and decode:
     7-bit codes 0000000-0010111 -> symbols 256-279
     8-bit codes 00110000-10111111 -> symbols 0-143
     8-bit codes 11000000-11000111 -> symbols 280-287
     9-bit codes 110010000-111111111 -> symbols 144-255
*/
static unsigned long deflate_decode_fixed_symbol(bit_reader *br, u32 *sym) {
    u32 code;
    unsigned long rc;

    /* Read 7 bits */
    rc = br_read(br, 7, &code);
    if (rc) return rc;

    code = reverse_bits(code, 7);

    if (code <= 0x17) {
        /* 7-bit code: symbols 256-279 */
        *sym = 256 + code;
        return 0;
    }

    /* Need 1 more bit (total 8) */
    {
        u32 extra;
        rc = br_read(br, 1, &extra);
        if (rc) return rc;
        code = (code << 1) | extra;
    }

    if (code >= 0x30 && code <= 0xBF) {
        *sym = code - 0x30;
        return 0;
    }
    if (code >= 0xC0 && code <= 0xC7) {
        *sym = 280 + (code - 0xC0);
        return 0;
    }

    /* Need 1 more bit (total 9) */
    {
        u32 extra;
        rc = br_read(br, 1, &extra);
        if (rc) return rc;
        code = (code << 1) | extra;
    }

    if (code >= 0x190 && code <= 0x1FF) {
        *sym = 144 + (code - 0x190);
        return 0;
    }

    return 1; /* invalid code */
}

unsigned long deflate_decompress(buf *out, u8 *data, u64 len) {
    bit_reader br;
    u32 bfinal;
    unsigned long rc;

    if (!out) return 1;
    if (len > 0 && !data) return 2;

    if (len == 0) return 0;

    br_init(&br, data, len);

    do {
        u32 btype;

        rc = br_read(&br, 1, &bfinal);
        if (rc) return 3;

        rc = br_read(&br, 2, &btype);
        if (rc) return 3;

        if (btype == 0) {
            /* Stored block (no compression) */
            u32 block_len, nlen;
            /* Discard remaining bits in current byte */
            br.bits = 0;
            br.nbits = 0;

            if (br.pos + 4 > br.len) return 3;
            block_len = (u32)(br.data[br.pos] | ((u32)br.data[br.pos + 1] << 8));
            nlen = (u32)(br.data[br.pos + 2] | ((u32)br.data[br.pos + 3] << 8));
            br.pos += 4;

            if ((block_len ^ 0xFFFF) != nlen) return 3;
            if (br.pos + block_len > br.len) return 3;

            rc = buf_append(out, br.data + br.pos, block_len);
            if (rc) return 4;
            br.pos += block_len;
        } else if (btype == 1) {
            /* Fixed Huffman codes */
            for (;;) {
                u32 sym;
                rc = deflate_decode_fixed_symbol(&br, &sym);
                if (rc) return 3;

                if (sym < 256) {
                    u8 b = (u8)sym;
                    rc = buf_append_byte(out, b);
                    if (rc) return 4;
                } else if (sym == 256) {
                    break; /* end of block */
                } else {
                    /* Length/distance pair */
                    u32 lc = sym - 257;
                    u32 length;
                    u32 dc_bits, dc;
                    u32 distance;

                    if (lc >= 29) return 3;

                    length = len_base[lc];
                    if (len_extra[lc] > 0) {
                        u32 extra;
                        rc = br_read(&br, len_extra[lc], &extra);
                        if (rc) return 3;
                        length += extra;
                    }

                    /* Distance: 5 bits fixed code, reversed */
                    rc = br_read(&br, 5, &dc_bits);
                    if (rc) return 3;
                    dc = reverse_bits(dc_bits, 5);

                    if (dc >= 30) return 3;
                    distance = dist_base[dc];
                    if (dist_extra[dc] > 0) {
                        u32 extra;
                        rc = br_read(&br, dist_extra[dc], &extra);
                        if (rc) return 3;
                        distance += extra;
                    }

                    /* Copy from output, byte-by-byte for overlap */
                    if (out->len < distance) return 3;
                    {
                        u64 src_pos = out->len - distance;
                        u32 i;
                        for (i = 0; i < length; i++) {
                            u8 b = out->data[src_pos + i];
                            rc = buf_append_byte(out, b);
                            if (rc) return 4;
                        }
                    }
                }
            }
        } else if (btype == 2) {
            /* Dynamic Huffman (RFC 1951 section 3.2.7) */
            u32 hlit, hdist, hclen;

            rc = br_read(&br, 5, &hlit);   if (rc) return 3;
            rc = br_read(&br, 5, &hdist);  if (rc) return 3;
            rc = br_read(&br, 4, &hclen);  if (rc) return 3;
            hlit  += 257;   /* 257-286 literal/length codes */
            hdist += 1;     /* 1-32 distance codes */
            hclen += 4;     /* 4-19 code length codes */

            if (hlit > 286 || hdist > 32) return 3;

            /* Code length alphabet order (RFC 1951 section 3.2.7) */
            static const u8 cl_order[19] = {
                16,17,18, 0,8,7,9,6,10,5,11,4,12,3,13,2,14,1,15
            };

            /* Read code lengths for the code length alphabet */
            u8 cl_lens[19];
            memset(cl_lens, 0, sizeof(cl_lens));
            {
                u32 ci;
                for (ci = 0; ci < hclen; ci++) {
                    u32 v;
                    rc = br_read(&br, 3, &v);
                    if (rc) return 3;
                    cl_lens[cl_order[ci]] = (u8)v;
                }
            }

            /* Build Huffman table for code lengths.
               Max code length for the CL alphabet is 7 bits.
               We use a simple table-based decode: for each bit pattern,
               store the symbol and code length. */
            #define DYN_MAX_BITS  15
            #define DYN_TABLE_SIZE (1 << DYN_MAX_BITS)

            /* Build canonical Huffman table from code lengths.
               bl_count[N] = number of codes with length N
               next_code[N] = next code value to assign at length N */
            {
                u32 bl_count[DYN_MAX_BITS + 1];
                u32 next_code[DYN_MAX_BITS + 1];
                u32 max_cl = 0;
                u32 ci;

                memset(bl_count, 0, sizeof(bl_count));
                for (ci = 0; ci < 19; ci++) {
                    bl_count[cl_lens[ci]]++;
                    if (cl_lens[ci] > max_cl) max_cl = cl_lens[ci];
                }
                bl_count[0] = 0;

                u32 code = 0;
                memset(next_code, 0, sizeof(next_code));
                for (ci = 1; ci <= max_cl; ci++) {
                    code = (code + bl_count[ci - 1]) << 1;
                    next_code[ci] = code;
                }

                /* Assign codes to CL symbols */
                u16 cl_codes[19];
                u8  cl_code_lens[19];
                memset(cl_codes, 0, sizeof(cl_codes));
                memset(cl_code_lens, 0, sizeof(cl_code_lens));
                for (ci = 0; ci < 19; ci++) {
                    if (cl_lens[ci] > 0) {
                        cl_codes[ci] = (u16)next_code[cl_lens[ci]]++;
                        cl_code_lens[ci] = cl_lens[ci];
                    }
                }

                /* Decode literal/length + distance code lengths
                   using the CL Huffman tree */
                u32 total_codes = hlit + hdist;
                u8 *all_lens = (u8 *)calloc(total_codes, 1);
                if (!all_lens) return 4;

                u32 ai = 0;
                while (ai < total_codes) {
                    /* Decode one CL symbol by reading bits and matching
                       against canonical codes */
                    u32 decoded = 0;
                    int found = 0;
                    u32 bits_read = 0;

                    for (bits_read = 1; bits_read <= max_cl && !found; bits_read++) {
                        u32 bit;
                        rc = br_read(&br, 1, &bit);
                        if (rc) { free(all_lens); return 3; }
                        decoded = (decoded << 1) | bit;

                        for (ci = 0; ci < 19; ci++) {
                            if (cl_code_lens[ci] == bits_read &&
                                cl_codes[ci] == decoded) {
                                found = 1;

                                if (ci < 16) {
                                    /* Literal code length 0-15 */
                                    all_lens[ai++] = (u8)ci;
                                } else if (ci == 16) {
                                    /* Repeat previous length 3-6 times */
                                    u32 rep;
                                    rc = br_read(&br, 2, &rep);
                                    if (rc) { free(all_lens); return 3; }
                                    rep += 3;
                                    if (ai == 0) { free(all_lens); return 3; }
                                    u8 prev = all_lens[ai - 1];
                                    while (rep-- && ai < total_codes)
                                        all_lens[ai++] = prev;
                                } else if (ci == 17) {
                                    /* Repeat 0 for 3-10 times */
                                    u32 rep;
                                    rc = br_read(&br, 3, &rep);
                                    if (rc) { free(all_lens); return 3; }
                                    rep += 3;
                                    while (rep-- && ai < total_codes)
                                        all_lens[ai++] = 0;
                                } else { /* ci == 18 */
                                    /* Repeat 0 for 11-138 times */
                                    u32 rep;
                                    rc = br_read(&br, 7, &rep);
                                    if (rc) { free(all_lens); return 3; }
                                    rep += 11;
                                    while (rep-- && ai < total_codes)
                                        all_lens[ai++] = 0;
                                }
                                break;
                            }
                        }
                    }
                    if (!found) { free(all_lens); return 3; }
                }

                /* Split into literal/length and distance code lengths */
                u8 lit_lens[286];
                u8 dst_lens[32];
                memset(lit_lens, 0, sizeof(lit_lens));
                memset(dst_lens, 0, sizeof(dst_lens));
                memcpy(lit_lens, all_lens, hlit);
                memcpy(dst_lens, all_lens + hlit, hdist);
                free(all_lens);

                /* Build canonical code tables for lit/len and distance.
                   For each symbol, store its canonical code and length. */
                u16 lit_codes[286];
                u16 dst_codes[32];
                u8  lit_code_lens[286];
                u8  dst_code_lens[32];
                memset(lit_codes, 0, sizeof(lit_codes));
                memset(dst_codes, 0, sizeof(dst_codes));
                memset(lit_code_lens, 0, sizeof(lit_code_lens));
                memset(dst_code_lens, 0, sizeof(dst_code_lens));

                /* Build literal/length codes */
                {
                    u32 bl[DYN_MAX_BITS + 1];
                    u32 nc[DYN_MAX_BITS + 1];
                    u32 ml = 0;
                    memset(bl, 0, sizeof(bl));
                    for (ci = 0; ci < hlit; ci++) {
                        bl[lit_lens[ci]]++;
                        if (lit_lens[ci] > ml) ml = lit_lens[ci];
                    }
                    bl[0] = 0;
                    code = 0;
                    memset(nc, 0, sizeof(nc));
                    for (ci = 1; ci <= ml; ci++) {
                        code = (code + bl[ci - 1]) << 1;
                        nc[ci] = code;
                    }
                    for (ci = 0; ci < hlit; ci++) {
                        if (lit_lens[ci] > 0) {
                            lit_codes[ci] = (u16)nc[lit_lens[ci]]++;
                            lit_code_lens[ci] = lit_lens[ci];
                        }
                    }
                }

                /* Build distance codes */
                {
                    u32 bl[DYN_MAX_BITS + 1];
                    u32 nc[DYN_MAX_BITS + 1];
                    u32 ml = 0;
                    memset(bl, 0, sizeof(bl));
                    for (ci = 0; ci < hdist; ci++) {
                        bl[dst_lens[ci]]++;
                        if (dst_lens[ci] > ml) ml = dst_lens[ci];
                    }
                    bl[0] = 0;
                    code = 0;
                    memset(nc, 0, sizeof(nc));
                    for (ci = 1; ci <= ml; ci++) {
                        code = (code + bl[ci - 1]) << 1;
                        nc[ci] = code;
                    }
                    for (ci = 0; ci < hdist; ci++) {
                        if (dst_lens[ci] > 0) {
                            dst_codes[ci] = (u16)nc[dst_lens[ci]]++;
                            dst_code_lens[ci] = dst_lens[ci];
                        }
                    }
                }

                /* Decode data using the dynamic Huffman trees.
                   Same structure as BTYPE=1 but using dynamic tables. */
                {
                    u32 lit_max = 0, dst_max = 0;
                    for (ci = 0; ci < hlit; ci++)
                        if (lit_code_lens[ci] > lit_max) lit_max = lit_code_lens[ci];
                    for (ci = 0; ci < hdist; ci++)
                        if (dst_code_lens[ci] > dst_max) dst_max = dst_code_lens[ci];

                    for (;;) {
                        /* Decode literal/length symbol */
                        u32 sym = 0;
                        u32 decoded_val = 0;
                        int sym_found = 0;
                        u32 bk;

                        for (bk = 1; bk <= lit_max && !sym_found; bk++) {
                            u32 bit;
                            rc = br_read(&br, 1, &bit);
                            if (rc) return 3;
                            decoded_val = (decoded_val << 1) | bit;

                            for (ci = 0; ci < hlit; ci++) {
                                if (lit_code_lens[ci] == bk &&
                                    lit_codes[ci] == decoded_val) {
                                    sym = ci;
                                    sym_found = 1;
                                    break;
                                }
                            }
                        }
                        if (!sym_found) return 3;

                        if (sym < 256) {
                            u8 b = (u8)sym;
                            rc = buf_append_byte(out, b);
                            if (rc) return 4;
                        } else if (sym == 256) {
                            break; /* end of block */
                        } else {
                            /* Length/distance pair */
                            u32 lc = sym - 257;
                            u32 length;
                            u32 distance;

                            if (lc >= 29) return 3;
                            length = len_base[lc];
                            if (len_extra[lc] > 0) {
                                u32 extra;
                                rc = br_read(&br, len_extra[lc], &extra);
                                if (rc) return 3;
                                length += extra;
                            }

                            /* Decode distance symbol using dynamic tree */
                            u32 dsym = 0;
                            decoded_val = 0;
                            sym_found = 0;
                            for (bk = 1; bk <= dst_max && !sym_found; bk++) {
                                u32 bit;
                                rc = br_read(&br, 1, &bit);
                                if (rc) return 3;
                                decoded_val = (decoded_val << 1) | bit;

                                for (ci = 0; ci < hdist; ci++) {
                                    if (dst_code_lens[ci] == bk &&
                                        dst_codes[ci] == decoded_val) {
                                        dsym = ci;
                                        sym_found = 1;
                                        break;
                                    }
                                }
                            }
                            if (!sym_found) return 3;

                            if (dsym >= 30) return 3;
                            distance = dist_base[dsym];
                            if (dist_extra[dsym] > 0) {
                                u32 extra;
                                rc = br_read(&br, dist_extra[dsym], &extra);
                                if (rc) return 3;
                                distance += extra;
                            }

                            /* Copy from output */
                            if (out->len < distance) return 3;
                            {
                                u64 src_pos = out->len - distance;
                                u32 i;
                                for (i = 0; i < length; i++) {
                                    u8 b = out->data[src_pos + i];
                                    rc = buf_append_byte(out, b);
                                    if (rc) return 4;
                                }
                            }
                        }
                    }
                }
            }
        } else {
            /* Reserved block type */
            return 3;
        }
    } while (!bfinal);

    return 0;
}
