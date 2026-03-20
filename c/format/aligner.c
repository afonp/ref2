/*
 * aligner.c — Needleman-Wunsch pairwise alignment + conservation scoring +
 *             field boundary segmentation.
 */

#include "format.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <float.h>
#include <stdint.h>

/* GAP sentinel — use 0x100 so it's outside the uint8_t range.
   Previously used 0xff which collides with real protocol bytes. */
#define NW_GAP ((uint16_t)0x100)

/* ── NW scoring ─────────────────────────────────────────────────────────────── */

#define NW_MATCH      2
#define NW_MISMATCH  -1
#define NW_GAP_OPEN  -3
#define NW_GAP_EXT   -1

#define MAX_NW_LEN  4096  /* don't NW-align messages longer than this */

/* Compute alignment score between two byte sequences.
   Returns score; optionally fills aligned_a / aligned_b (caller owns).
   Gap positions have value NW_GAP (0x100) — never a real byte. */
static int nw_align(const uint8_t *a, size_t la,
                     const uint8_t *b, size_t lb,
                     uint16_t **aligned_a_out, uint16_t **aligned_b_out,
                     size_t *aligned_len_out)
{
    /* Clamp to avoid O(n²) blowup. */
    if (la > MAX_NW_LEN) la = MAX_NW_LEN;
    if (lb > MAX_NW_LEN) lb = MAX_NW_LEN;

    size_t rows = la + 1, cols = lb + 1;
    int *dp = malloc(rows * cols * sizeof(int));
    if (!dp) return 0;

    /* Initialise. */
    dp[0] = 0;
    for (size_t j = 1; j < cols; j++) dp[j] = (int)j * NW_GAP_EXT + NW_GAP_OPEN;
    for (size_t i = 1; i < rows; i++) dp[i * cols] = (int)i * NW_GAP_EXT + NW_GAP_OPEN;

    for (size_t i = 1; i < rows; i++) {
        for (size_t j = 1; j < cols; j++) {
            int diag = dp[(i-1)*cols + (j-1)] +
                       (a[i-1] == b[j-1] ? NW_MATCH : NW_MISMATCH);
            int up   = dp[(i-1)*cols + j] + NW_GAP_EXT;
            int left = dp[i*cols + (j-1)] + NW_GAP_EXT;
            dp[i*cols+j] = diag > up ? (diag > left ? diag : left)
                                      : (up   > left ? up   : left);
        }
    }

    int score = dp[la * cols + lb];

    if (aligned_a_out && aligned_b_out && aligned_len_out) {
        /* Traceback — use uint16_t so NW_GAP (0x100) fits without collision. */
        size_t max_align = la + lb + 1;
        uint16_t *ra = malloc(max_align * sizeof(uint16_t));
        uint16_t *rb = malloc(max_align * sizeof(uint16_t));
        if (!ra || !rb) { free(ra); free(rb); free(dp); return score; }

        size_t i = la, j = lb, k = 0;
        while (i > 0 || j > 0) {
            if (i > 0 && j > 0) {
                int diag = dp[(i-1)*cols+(j-1)] +
                           (a[i-1] == b[j-1] ? NW_MATCH : NW_MISMATCH);
                if (dp[i*cols+j] == diag) {
                    ra[k] = a[i-1]; rb[k] = b[j-1]; k++; i--; j--;
                    continue;
                }
            }
            if (i > 0 && dp[i*cols+j] == dp[(i-1)*cols+j] + NW_GAP_EXT) {
                ra[k] = a[i-1]; rb[k] = NW_GAP; k++; i--;
            } else {
                ra[k] = NW_GAP; rb[k] = b[j-1]; k++; j--;
            }
        }
        /* Reverse. */
        for (size_t l = 0; l < k/2; l++) {
            uint16_t tmp;
            tmp = ra[l]; ra[l] = ra[k-1-l]; ra[k-1-l] = tmp;
            tmp = rb[l]; rb[l] = rb[k-1-l]; rb[k-1-l] = tmp;
        }
        *aligned_a_out   = ra;
        *aligned_b_out   = rb;
        *aligned_len_out = k;
    }

    free(dp);
    return score;
}

/* ── Conservation vector ────────────────────────────────────────────────────── */

/*
 * Align all tokens in a cluster progressively and produce a per-position
 * conservation score in [0,1].
 *
 * For small clusters (≤ 50 msgs) we do full pairwise alignment against the
 * running consensus.  For larger clusters we sample 50 pairs to build a
 * guide tree (simplified to a linear merge order by similarity).
 */
/* Sample at most GUIDE_SAMPLE random pairs and compute NW similarity scores.
   Returns an ordering of [0..n) from most-central to least. */
#define GUIDE_SAMPLE 50
#define LARGE_CLUSTER 200

static size_t *guide_tree_order(token_t **msgs, size_t n)
{
    size_t *order = malloc(n * sizeof(size_t));
    double *score = calloc(n, sizeof(double));
    if (!order || !score) { free(order); free(score); return NULL; }
    for (size_t i = 0; i < n; i++) order[i] = i;

    /* sample pairs and accumulate similarity scores per message */
    size_t npairs = n < GUIDE_SAMPLE ? n*(n-1)/2 : GUIDE_SAMPLE;
    for (size_t p = 0; p < npairs; p++) {
        size_t i = (size_t)rand() % n;
        size_t j = (size_t)rand() % n;
        if (i == j) continue;
        int s = nw_align(msgs[i]->data, msgs[i]->len,
                         msgs[j]->data, msgs[j]->len,
                         NULL, NULL, NULL);
        /* accumulate: higher score = more central */
        score[i] += s > 0 ? (double)s : 0.0;
        score[j] += s > 0 ? (double)s : 0.0;
    }

    /* sort descending by score (insertion sort, small enough) */
    for (size_t i = 1; i < n; i++) {
        size_t key = order[i];
        double ks  = score[key];
        long j = (long)i - 1;
        while (j >= 0 && score[order[j]] < ks) {
            order[j+1] = order[j]; j--;
        }
        order[j+1] = key;
    }

    free(score);
    return order;
}

double *align_cluster(token_t **msgs, size_t n, size_t *consensus_len_out)
{
    if (n == 0) { *consensus_len_out = 0; return NULL; }
    if (n == 1) {
        *consensus_len_out = msgs[0]->len;
        double *cons = malloc(msgs[0]->len * sizeof(double));
        if (cons) for (size_t i = 0; i < msgs[0]->len; i++) cons[i] = 1.0;
        return cons;
    }

    size_t *order;

    if (n > LARGE_CLUSTER) {
        /* large cluster: use sampled guide tree ordering */
        order = guide_tree_order(msgs, n);
    } else {
        /* small cluster: insertion-sort by length ascending (cheap heuristic) */
        order = malloc(n * sizeof(size_t));
        if (order) {
            for (size_t i = 0; i < n; i++) order[i] = i;
            for (size_t i = 1; i < n; i++) {
                size_t key = order[i];
                size_t klen = msgs[key]->len;
                long j = (long)i - 1;
                while (j >= 0 && msgs[order[j]]->len > klen) {
                    order[j+1] = order[j]; j--;
                }
                order[j+1] = key;
            }
        }
    }

    /* Build a consensus byte sequence by progressive alignment.
       consensus[pos] = most-common non-gap byte at that position. */
    uint8_t *consensus = malloc(msgs[order[0]]->len);
    size_t   cons_len  = msgs[order[0]]->len;
    if (!consensus) { free(order); return NULL; }
    memcpy(consensus, msgs[order[0]]->data, cons_len);

    /* Per-position match counts (how many messages agree). */
    size_t *match_cnt = calloc(cons_len, sizeof(size_t));
    if (!match_cnt) { free(consensus); free(order); return NULL; }
    for (size_t i = 0; i < cons_len; i++) match_cnt[i] = 1;

    for (size_t idx = 1; idx < n; idx++) {
        token_t *tok = msgs[order[idx]];
        uint16_t *al_a = NULL, *al_b = NULL;
        size_t    al_len = 0;

        nw_align(consensus, cons_len, tok->data, tok->len,
                 &al_a, &al_b, &al_len);
        if (!al_a || al_len == 0) {
            free(al_a); free(al_b);
            continue;
        }

        /* Resize match_cnt and consensus to al_len. */
        uint8_t *new_cons = calloc(al_len, 1);
        size_t  *new_cnt  = calloc(al_len, sizeof(size_t));
        if (!new_cons || !new_cnt) {
            free(new_cons); free(new_cnt);
            free(al_a); free(al_b);
            continue;
        }

        size_t old_pos = 0;
        for (size_t p = 0; p < al_len; p++) {
            if (al_a[p] != NW_GAP) {
                /* Position existed in old consensus. */
                new_cons[p] = (uint8_t)al_a[p];
                new_cnt[p]  = (old_pos < cons_len) ? match_cnt[old_pos] : 1;
                old_pos++;
            }
            if (al_b[p] != NW_GAP) {
                /* Current message agrees at this position. */
                if (al_a[p] == al_b[p])
                    new_cnt[p]++;
            }
        }

        free(al_a); free(al_b);
        free(consensus); free(match_cnt);
        consensus = new_cons;
        match_cnt = new_cnt;
        cons_len  = al_len;
    }

    free(order);

    /* Convert match counts to conservation scores in [0,1]. */
    double *scores = malloc(cons_len * sizeof(double));
    if (scores) {
        for (size_t i = 0; i < cons_len; i++)
            scores[i] = (double)match_cnt[i] / (double)n;
    }

    free(consensus);
    free(match_cnt);

    *consensus_len_out = cons_len;
    return scores;
}

/* ── Field boundary segmentation ────────────────────────────────────────────── */

#define CONSERVED_THRESH 0.7

/* Median of three doubles. */
static double med3(double a, double b, double c)
{
    if (a > b) { double t = a; a = b; b = t; }
    if (b > c) { double t = b; b = c; c = t; }
    if (a > b) { double t = a; a = b; b = t; }
    (void)c;
    return b;
}

/* Smooth conservation vector with window-3 median filter. */
static double *median_smooth(const double *in, size_t n)
{
    double *out = malloc(n * sizeof(double));
    if (!out) return NULL;
    if (n == 0) return out;
    out[0] = in[0];
    for (size_t i = 1; i + 1 < n; i++)
        out[i] = med3(in[i-1], in[i], in[i+1]);
    if (n > 1) out[n-1] = in[n-1];
    return out;
}

/* Returns 1 if byte at position pos is part of a known framing field that
   should always be treated as variable (e.g. length field), regardless of
   how conserved it appears in the corpus. */
static int is_forced_variable(const framing_info_t *framing, size_t pos)
{
    if (!framing) return 0;
    if (framing->has_length_field &&
        pos >= framing->length_offset &&
        pos < framing->length_offset + framing->length_width)
        return 1;
    return 0;
}

/* Returns 1 if position pos is a forced segment boundary (start/end of a known
   framing field: length field or type discriminator field). */
static int is_forced_boundary(const framing_info_t *framing, size_t pos)
{
    if (!framing) return 0;
    if (framing->has_length_field) {
        if (pos == framing->length_offset) return 1;
        if (pos == framing->length_offset + framing->length_width) return 1;
    }
    if (framing->has_type_field) {
        if (pos == framing->type_offset) return 1;
        if (pos == framing->type_offset + framing->type_width) return 1;
    }
    return 0;
}

field_t *segment_fields(const double *conservation, size_t len,
                         const framing_info_t *framing,
                         size_t *field_count_out)
{
    if (len == 0) { *field_count_out = 0; return NULL; }

    /* Run-length encode conservation scores into conserved/variable runs.
       Known framing fields (e.g. length field) are:
       - forced variable (even if their bytes appear conserved in small corpus)
       - forced to be isolated segments via forced boundary positions */
    field_t *fields = malloc(len * sizeof(field_t));  /* worst case: 1 per byte */
    if (!fields) return NULL;
    size_t nfields = 0;

    size_t start = 0;
    int    conserved = (conservation[0] >= CONSERVED_THRESH) &&
                       !is_forced_variable(framing, 0);

    for (size_t i = 1; i <= len; i++) {
        int now;
        if (i < len)
            now = (conservation[i] >= CONSERVED_THRESH) &&
                  !is_forced_variable(framing, i);
        else
            now = !conserved;

        /* Force a segment break at known framing field boundaries. */
        int force_break = is_forced_boundary(framing, i) && i > start;

        if (now != conserved || force_break) {
            field_t *f = &fields[nfields++];
            f->offset     = start;
            f->length     = i - start;
            f->type       = conserved ? FIELD_CONSTANT : FIELD_OPAQUE;
            f->entropy    = 0.0;
            f->enum_count = 0;
            snprintf(f->name, sizeof(f->name), "field_%02zu_%s",
                     nfields - 1, conserved ? "fixed" : "var");

            /* Check if this variable segment is the known length field. */
            if (!conserved && framing && framing->has_length_field &&
                start == framing->length_offset &&
                i - start == framing->length_width) {
                f->type = FIELD_LENGTH;
                snprintf(f->name, sizeof(f->name), "field_%02zu_length", nfields-1);
            }

            start     = i;
            /* After a forced break, re-evaluate the conserved state at new start. */
            if (force_break && i < len)
                conserved = (conservation[i] >= CONSERVED_THRESH) &&
                            !is_forced_variable(framing, i);
            else
                conserved = now;
        }
    }

    *field_count_out = nfields;
    return fields;
}
