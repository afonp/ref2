/*
 * cluster.c — Message clustering via type_hint (fast path) or k-means++
 *             on 256-dim byte-frequency histograms (fallback).
 */

#include "format.h"

#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <float.h>
#include <time.h>

#define KMEANS_RESTARTS  10
#define KMEANS_ITERS     100
#define MAX_K            32

/* ── Histogram feature vector ───────────────────────────────────────────────── */

/* Build a normalised 256-dim byte-frequency histogram for a token. */
static void make_hist(const token_t *tok, double hist[256])
{
    memset(hist, 0, 256 * sizeof(double));
    if (tok->len == 0) return;
    for (size_t i = 0; i < tok->len; i++)
        hist[tok->data[i]] += 1.0;
    double inv = 1.0 / (double)tok->len;
    for (int b = 0; b < 256; b++) hist[b] *= inv;
}

/* Squared Euclidean distance between two 256-dim vectors. */
static double dist2(const double *a, const double *b)
{
    double d = 0.0;
    for (int i = 0; i < 256; i++) {
        double diff = a[i] - b[i];
        d += diff * diff;
    }
    return d;
}

/* ── k-means++ clustering ────────────────────────────────────────────────────── */

static double kmeans_run(double (*hists)[256], size_t n, int k,
                          uint32_t *labels_out)
{
    /* Allocate centroids. */
    double (*centroids)[256] = malloc((size_t)k * sizeof(*centroids));
    double (*new_c)[256]     = malloc((size_t)k * sizeof(*new_c));
    size_t *cnt              = malloc((size_t)k * sizeof(size_t));
    uint32_t *labels         = malloc(n * sizeof(uint32_t));
    if (!centroids || !new_c || !cnt || !labels) {
        free(centroids); free(new_c); free(cnt); free(labels);
        return DBL_MAX;
    }

    /* k-means++ initialisation. */
    size_t first = (size_t)rand() % n;
    memcpy(centroids[0], hists[first], 256 * sizeof(double));

    for (int c = 1; c < k; c++) {
        double *dists = malloc(n * sizeof(double));
        if (!dists) break;
        double total = 0.0;
        for (size_t i = 0; i < n; i++) {
            double mn = DBL_MAX;
            for (int j = 0; j < c; j++) {
                double d = dist2(hists[i], centroids[j]);
                if (d < mn) mn = d;
            }
            dists[i] = mn;
            total += mn;
        }
        /* Sample proportional to distance squared. */
        double r = ((double)rand() / (double)RAND_MAX) * total;
        size_t chosen = 0;
        for (size_t i = 0; i < n; i++) {
            r -= dists[i];
            if (r <= 0.0) { chosen = i; break; }
        }
        memcpy(centroids[c], hists[chosen], 256 * sizeof(double));
        free(dists);
    }

    /* Main k-means loop. */
    for (int iter = 0; iter < KMEANS_ITERS; iter++) {
        /* Assignment. */
        int changed = 0;
        for (size_t i = 0; i < n; i++) {
            double best_d = DBL_MAX;
            uint32_t best_c = 0;
            for (int c = 0; c < k; c++) {
                double d = dist2(hists[i], centroids[c]);
                if (d < best_d) { best_d = d; best_c = (uint32_t)c; }
            }
            if (labels[i] != best_c) changed++;
            labels[i] = best_c;
        }
        if (!changed) break;

        /* Update. */
        memset(new_c, 0, (size_t)k * sizeof(*new_c));
        memset(cnt,   0, (size_t)k * sizeof(size_t));
        for (size_t i = 0; i < n; i++) {
            uint32_t c = labels[i];
            for (int b = 0; b < 256; b++) new_c[c][b] += hists[i][b];
            cnt[c]++;
        }
        for (int c = 0; c < k; c++) {
            if (cnt[c] == 0) continue;
            double inv = 1.0 / (double)cnt[c];
            for (int b = 0; b < 256; b++) centroids[c][b] = new_c[c][b] * inv;
        }
    }

    /* Compute inertia. */
    double inertia = 0.0;
    for (size_t i = 0; i < n; i++)
        inertia += dist2(hists[i], centroids[labels[i]]);

    memcpy(labels_out, labels, n * sizeof(uint32_t));

    free(centroids); free(new_c); free(cnt); free(labels);
    return inertia;
}

/* ── Public API ─────────────────────────────────────────────────────────────── */

uint32_t *cluster_messages(token_stream_t **streams, size_t nstreams,
                            size_t *total_msgs_out, int *k_out)
{
    static int seeded = 0;
    if (!seeded) { srand((unsigned)time(NULL)); seeded = 1; }

    /* Flatten all tokens. */
    size_t total = 0;
    for (size_t si = 0; si < nstreams; si++) total += streams[si]->count;
    *total_msgs_out = total;
    if (total == 0) { *k_out = 0; return NULL; }

    token_t **flat = malloc(total * sizeof(token_t *));
    if (!flat) return NULL;
    size_t idx = 0;
    for (size_t si = 0; si < nstreams; si++)
        for (size_t mi = 0; mi < streams[si]->count; mi++)
            flat[idx++] = &streams[si]->tokens[mi];

    uint32_t *labels = malloc(total * sizeof(uint32_t));
    if (!labels) { free(flat); return NULL; }

    /* Check if direction information is available (any non-zero direction). */
    int has_direction = 0;
    for (size_t i = 0; i < total; i++)
        if (flat[i]->direction != 0) { has_direction = 1; break; }

    /* Determine primary clustering key:
       - all_typed: every token has a non-zero type_hint → use type_hint alone.
         The type discriminator field is authoritative; direction is secondary.
       - !all_typed && has_direction: type_hint is unreliable (some tokens
         have hint=0), but direction is known → split by direction only.
       - otherwise: fall through to k-means. */
    int all_typed = 1;
    for (size_t i = 0; i < total; i++)
        if (flat[i]->type_hint == 0) { all_typed = 0; break; }

    if (all_typed) {
        /* Remap type_hints to dense cluster IDs. */
        uint32_t map[65536] = {0};
        uint8_t  seen[65536] = {0};
        int      k = 0;
        for (size_t i = 0; i < total; i++) {
            uint32_t h = flat[i]->type_hint & 0xffff;
            if (!seen[h]) { seen[h] = 1; map[h] = (uint32_t)k++; }
            labels[i] = map[h];
        }
        *k_out = k;
        free(flat);
        return labels;
    }

    if (has_direction) {
        /* Split only by direction (2 clusters: client→server, server→client). */
        for (size_t i = 0; i < total; i++)
            labels[i] = flat[i]->direction ? 1 : 0;
        *k_out = 2;
        free(flat);
        return labels;
    }

    /* k-means fallback: use sqrt heuristic but cap at a reasonable value. */
    int k = (int)sqrt((double)total / 4.0);
    if (k < 2)  k = 2;
    if (k > MAX_K) k = MAX_K;

    double (*hists)[256] = malloc(total * sizeof(*hists));
    if (!hists) { free(flat); free(labels); return NULL; }
    for (size_t i = 0; i < total; i++) make_hist(flat[i], hists[i]);
    free(flat);

    double best_inertia = DBL_MAX;
    uint32_t *best_labels = malloc(total * sizeof(uint32_t));
    if (!best_labels) { free(hists); free(labels); return NULL; }

    for (int r = 0; r < KMEANS_RESTARTS; r++) {
        double inertia = kmeans_run(hists, total, k, labels);
        if (inertia < best_inertia) {
            best_inertia = inertia;
            memcpy(best_labels, labels, total * sizeof(uint32_t));
        }
    }

    free(hists);
    free(labels);

    *k_out = k;
    return best_labels;
}
