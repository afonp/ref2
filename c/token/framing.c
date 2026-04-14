/*
 * framing.c — Framing detection: fixed-header entropy analysis, delimiter
 *             scanning, and type-discriminator field detection.
 */

#include "token.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <math.h>
#include <float.h>

#define MAX_HDR_PROBE   32   /* max header length we consider */
#define ENTROPY_THRESH  0.5  /* bits — positions below this are "fixed" */
#define TYPE_MIN_VALS   2
#define TYPE_MAX_VALS   16

/* Shannon entropy of a byte position across all messages (in bits). */
static double position_entropy(const session_t *sessions, size_t nsess,
                                size_t pos)
{
    size_t freq[256] = {0};
    size_t total = 0;

    for (size_t si = 0; si < nsess; si++) {
        const session_t *sess = &sessions[si];
        for (size_t mi = 0; mi < sess->count; mi++) {
            const message_t *m = &sess->messages[mi];
            if (m->payload_len > pos) {
                freq[m->payload[pos]]++;
                total++;
            }
        }
    }
    if (total == 0) return 8.0;  /* unknown → treat as high entropy */

    double H = 0.0;
    for (int b = 0; b < 256; b++) {
        if (freq[b] == 0) continue;
        double p = (double)freq[b] / (double)total;
        H -= p * log2(p);
    }
    return H;
}

/* Minimum message length across all sessions. */
static size_t min_msg_len(const session_t *sessions, size_t nsess)
{
    size_t mn = SIZE_MAX;
    for (size_t si = 0; si < nsess; si++)
        for (size_t mi = 0; mi < sessions[si].count; mi++) {
            size_t l = sessions[si].messages[mi].payload_len;
            if (l < mn) mn = l;
        }
    return mn == SIZE_MAX ? 0 : mn;
}

static size_t infer_header_len(const session_t *sessions, size_t nsess)
{
    size_t limit = min_msg_len(sessions, nsess);
    if (limit > MAX_HDR_PROBE) limit = MAX_HDR_PROBE;

    size_t hdr = 0;
    for (size_t pos = 0; pos < limit; pos++) {
        double H = position_entropy(sessions, nsess, pos);
        if (H < ENTROPY_THRESH)
            hdr = pos + 1;
        else
            break;  /* first high-entropy byte ends the fixed header */
    }
    return hdr;
}

typedef struct {
    uint8_t bytes[4];
    size_t  len;
    size_t  count;
} delim_candidate_t;

static int cmp_delim(const void *a, const void *b)
{
    return (int)((const delim_candidate_t *)b)->count -
           (int)((const delim_candidate_t *)a)->count;
}

static int detect_delimiter(const session_t *sessions, size_t nsess,
                              uint8_t out[4], size_t *out_len)
{
    /* Common single-byte terminators to prioritise. */
    static const uint8_t common1[] = { '\n', '\r', '\0', 0xff };
    /* Common two-byte terminators. */
    static const uint8_t common2[][2] = { {'\r','\n'}, {'\0','\0'} };

    size_t freq1[256] = {0};
    size_t total = 0;

    for (size_t si = 0; si < nsess; si++) {
        for (size_t mi = 0; mi < sessions[si].count; mi++) {
            const message_t *m = &sessions[si].messages[mi];
            if (m->payload_len == 0) continue;
            /* Count the last byte of each message. */
            freq1[m->payload[m->payload_len - 1]]++;
            total++;
        }
    }
    if (total == 0) return 0;

    /* Check common single-byte terminators first. */
    for (size_t i = 0; i < sizeof(common1); i++) {
        uint8_t b = common1[i];
        if (freq1[b] * 100 / total >= 80) {
            out[0] = b; *out_len = 1;
            return 1;
        }
    }

    /* Check common two-byte terminators. */
    for (size_t i = 0; i < sizeof(common2)/sizeof(common2[0]); i++) {
        size_t hits = 0;
        for (size_t si = 0; si < nsess; si++) {
            for (size_t mi = 0; mi < sessions[si].count; mi++) {
                const message_t *m = &sessions[si].messages[mi];
                if (m->payload_len >= 2 &&
                    m->payload[m->payload_len-2] == common2[i][0] &&
                    m->payload[m->payload_len-1] == common2[i][1])
                    hits++;
            }
        }
        if (total > 0 && hits * 100 / total >= 80) {
            out[0] = common2[i][0]; out[1] = common2[i][1]; *out_len = 2;
            return 1;
        }
    }

    return 0;
}

static void detect_type_field(const session_t *sessions, size_t nsess,
                               size_t hdr_len, size_t len_offset, size_t len_width,
                               framing_info_t *out)
{
    /* Search a bit past the header too — type field is often right after the
       length field (e.g. magic(2) + length(1) + opcode(1) pattern). */
    size_t min_len = min_msg_len(sessions, nsess);
    size_t search_limit = hdr_len + len_width + 4;
    if (search_limit > MAX_HDR_PROBE) search_limit = MAX_HDR_PROBE;
    if (search_limit > min_len) search_limit = min_len;
    if (search_limit == 0) return;

    size_t best_pos   = 0;
    size_t best_count = 0;
    double best_score = -1.0;

    for (size_t pos = 0; pos < search_limit; pos++) {
        /* Skip length field bytes. */
        if (out->has_length_field &&
            pos >= len_offset && pos < len_offset + len_width)
            continue;

        /* Count distinct values at this position. */
        uint8_t seen[256] = {0};
        size_t  ndist = 0, total = 0;
        for (size_t si = 0; si < nsess; si++) {
            for (size_t mi = 0; mi < sessions[si].count; mi++) {
                const message_t *m = &sessions[si].messages[mi];
                if (m->payload_len > pos) {
                    if (!seen[m->payload[pos]]) {
                        seen[m->payload[pos]] = 1;
                        ndist++;
                    }
                    total++;
                }
            }
        }

        if (ndist < TYPE_MIN_VALS || ndist > TYPE_MAX_VALS) continue;

        /* Score: prefer few distinct values with roughly equal distribution. */
        double score = (double)(TYPE_MAX_VALS - ndist + 1) * (double)total;
        if (score > best_score) {
            best_score = score;
            best_pos   = pos;
            best_count = ndist;
        }
    }

    /* also try 2-byte windows (some protocols use u16 type fields) */
    for (size_t pos = 0; pos + 1 < search_limit; pos++) {
        if (out->has_length_field &&
            pos >= len_offset && pos < len_offset + len_width)
            continue;

        /* count distinct 2-byte values */
        uint32_t seen2[64];
        size_t   nseen2 = 0, total2 = 0;
        for (size_t si = 0; si < nsess; si++) {
            for (size_t mi = 0; mi < sessions[si].count; mi++) {
                const message_t *m = &sessions[si].messages[mi];
                if (m->payload_len < pos + 2) continue;
                uint32_t v = ((uint32_t)m->payload[pos] << 8) | m->payload[pos+1];
                int found = 0;
                for (size_t k = 0; k < nseen2; k++)
                    if (seen2[k] == v) { found = 1; break; }
                if (!found && nseen2 < 64) seen2[nseen2++] = v;
                total2++;
            }
        }

        if (nseen2 < TYPE_MIN_VALS || nseen2 > TYPE_MAX_VALS) continue;

        double score2 = (double)(TYPE_MAX_VALS - nseen2 + 1) * (double)total2 * 0.9;
        /* slight penalty vs 1-byte so we only prefer 2-byte when 1-byte isn't good */
        if (score2 > best_score) {
            best_score = score2;
            best_pos   = pos;
            best_count = nseen2;
        }
    }
    (void)best_count;

    if (best_score > 0.0) {
        out->has_type_field = 1;
        out->type_offset    = best_pos;
        /* figure out whether the best pos matched 1-byte or 2-byte */
        {
            uint8_t seen1[256] = {0};
            size_t  ndist1 = 0;
            for (size_t si = 0; si < nsess; si++)
                for (size_t mi = 0; mi < sessions[si].count; mi++) {
                    const message_t *m = &sessions[si].messages[mi];
                    if (m->payload_len > best_pos && !seen1[m->payload[best_pos]])
                        seen1[m->payload[best_pos]] = 1, ndist1++;
                }
            out->type_width = (ndist1 >= TYPE_MIN_VALS && ndist1 <= TYPE_MAX_VALS) ? 1 : 2;
        }
    }
}

framing_info_t *detect_framing(const session_t *sessions, size_t nsess)
{
    framing_info_t *fi = calloc(1, sizeof(*fi));
    if (!fi) return NULL;

    fi->header_len = infer_header_len(sessions, nsess);

    /* Delimiter detection (for text-based protocols). */
    {
        uint8_t delim[4];
        size_t  dlen = 0;
        if (detect_delimiter(sessions, nsess, delim, &dlen)) {
            fi->has_delimiter = 1;
            memcpy(fi->delimiter, delim, dlen);
            fi->delimiter_len = dlen;
        }
    }

    /* Type field detection. */
    detect_type_field(sessions, nsess,
                      fi->header_len,
                      fi->length_offset, fi->length_width,
                      fi);

    return fi;
}

static uint32_t read_uint_fi(const uint8_t *buf, size_t width, int big_endian)
{
    uint32_t v = 0;
    if (big_endian) {
        for (size_t i = 0; i < width; i++) v = (v << 8) | buf[i];
    } else {
        for (size_t i = 0; i < width; i++) v |= (uint32_t)buf[i] << (8*i);
    }
    return v;
}

token_stream_t *tokenize_session(const session_t *session,
                                  const framing_info_t *framing)
{
    token_stream_t *ts = malloc(sizeof(*ts));
    if (!ts) return NULL;
    ts->session_id = session->session_id;
    ts->count      = session->count;
    ts->tokens     = malloc(session->count * sizeof(token_t));
    if (!ts->tokens) { free(ts); return NULL; }

    for (size_t i = 0; i < session->count; i++) {
        const message_t *m = &session->messages[i];
        token_t *tok = &ts->tokens[i];

        /* Zero-copy token view into trace-owned payload bytes. */
        tok->data = m->payload;
        tok->len       = m->payload_len;
        tok->direction = m->direction;

        /* Extract type hint. */
        tok->type_hint = 0;
        if (framing && framing->has_type_field &&
            m->payload_len > framing->type_offset + framing->type_width - 1) {
            tok->type_hint = read_uint_fi(
                m->payload + framing->type_offset,
                framing->type_width,
                framing->length_endian);
        }
    }

    return ts;
}

token_stream_t **tokenize_trace(const trace_t *trace,
                                  framing_info_t **framing_out)
{
    framing_info_t *fi = detect_framing(trace->sessions, trace->count);
    if (framing_out) *framing_out = fi;

    /* Apply length-field detection (from length_field.c via header). */
    /* Note: detect_length_field() is called in length_field.c and updates fi
       in-place; we call it here as a two-pass approach. */
    extern void detect_length_field(const session_t *sessions, size_t nsess,
                                    framing_info_t *fi);
    detect_length_field(trace->sessions, trace->count, fi);

    /* Re-run type field detection now that length field is known. */
    if (fi) {
        detect_type_field(trace->sessions, trace->count,
                          fi->header_len,
                          fi->length_offset, fi->length_width, fi);
    }

    token_stream_t **streams = malloc(trace->count * sizeof(token_stream_t *));
    if (!streams) return NULL;

    for (size_t i = 0; i < trace->count; i++) {
        streams[i] = tokenize_session(&trace->sessions[i], fi);
        if (!streams[i]) {
            for (size_t j = 0; j < i; j++) token_stream_free(streams[j]);
            free(streams);
            return NULL;
        }
    }

    return streams;
}

void token_stream_free(token_stream_t *ts)
{
    if (!ts) return;
    free(ts->tokens);
    free(ts);
}

void framing_info_free(framing_info_t *fi)
{
    free(fi);
}
