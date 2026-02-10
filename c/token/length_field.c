/*
 * length_field.c — Brute-force inference of length fields in message headers.
 *
 * For each candidate (offset, width, endianness):
 *   read field value across all messages, test if val == payload_len - k
 *   for some constant k, over ≥ 80% of messages.  Best candidate wins.
 */

#include "token.h"

#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <math.h>
#include <float.h>

#define MIN_COVERAGE   0.80   /* fraction of messages that must match */
#define MAX_PROBE_OFF  16     /* max byte offset to probe */

/* ── Helpers ────────────────────────────────────────────────────────────────── */

static uint32_t ru(const uint8_t *b, size_t w, int be)
{
    uint32_t v = 0;
    if (be) { for (size_t i = 0; i < w; i++) v = (v << 8) | b[i]; }
    else    { for (size_t i = 0; i < w; i++) v |= (uint32_t)b[i] << (8*i); }
    return v;
}

/* ── Main detection ─────────────────────────────────────────────────────────── */

void detect_length_field(const session_t *sessions, size_t nsess,
                          framing_info_t *fi)
{
    if (!fi) return;

    /* Collect all messages into a flat array for convenience. */
    size_t total = 0;
    for (size_t si = 0; si < nsess; si++) total += sessions[si].count;
    if (total < 4) return;  /* need at least a few samples */

    const message_t **msgs = malloc(total * sizeof(message_t *));
    if (!msgs) return;
    size_t idx = 0;
    for (size_t si = 0; si < nsess; si++)
        for (size_t mi = 0; mi < sessions[si].count; mi++)
            msgs[idx++] = &sessions[si].messages[mi];

    double best_cov   = 0.0;
    size_t best_off   = 0;
    size_t best_width = 0;
    int    best_be    = 0;
    int32_t best_adj  = 0;

    /* Widths to probe: 1, 2, 4 bytes. */
    static const size_t widths[] = {1, 2, 4};

    for (size_t wi = 0; wi < 3; wi++) {
        size_t w = widths[wi];
        for (size_t off = 0; off + w <= MAX_PROBE_OFF; off++) {
            for (int be = 0; be <= 1; be++) {
                /* Gather (field_value, msg_len) pairs. */
                long *vals  = malloc(total * sizeof(long));
                long *mlens = malloc(total * sizeof(long));
                if (!vals || !mlens) { free(vals); free(mlens); continue; }

                size_t valid = 0;
                for (size_t i = 0; i < total; i++) {
                    if (msgs[i]->payload_len < off + w) continue;
                    vals[valid]  = (long)ru(msgs[i]->payload + off, w, be);
                    mlens[valid] = (long)msgs[i]->payload_len;
                    valid++;
                }

                if (valid < 4) { free(vals); free(mlens); continue; }

                /* Test: does val == mlen - k for constant k? */
                /* Estimate k from the first sample, then verify. */
                long k = mlens[0] - vals[0];
                size_t match = 0;
                for (size_t i = 0; i < valid; i++)
                    if (mlens[i] - vals[i] == k) match++;

                double cov = (double)match / (double)valid;
                if (cov >= MIN_COVERAGE && cov > best_cov) {
                    /* Sanity: k should be non-negative (field ≤ total length). */
                    if (k >= 0) {
                        best_cov   = cov;
                        best_off   = off;
                        best_width = w;
                        best_be    = be;
                        best_adj   = (int32_t)-k;  /* adjustment: total = val - adj */
                    }
                }

                free(vals);
                free(mlens);
            }
        }
    }

    free(msgs);

    if (best_cov >= MIN_COVERAGE) {
        fi->has_length_field   = 1;
        fi->length_offset      = best_off;
        fi->length_width       = best_width;
        fi->length_endian      = best_be;
        fi->length_adjustment  = best_adj;
    }
}
