/*
 * type_classifier.c — Per-field type classification and entropy computation.
 */

#include "format.h"
#include "token.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <math.h>
#include <ctype.h>

/* ── Shannon entropy ────────────────────────────────────────────────────────── */

double field_entropy(token_t **msgs, size_t n, size_t offset, size_t length)
{
    if (n == 0 || length == 0) return 0.0;

    size_t freq[256] = {0};
    size_t total = 0;

    for (size_t i = 0; i < n; i++) {
        size_t end = offset + length;
        if (msgs[i]->len < end) end = msgs[i]->len;
        for (size_t p = offset; p < end; p++) {
            freq[msgs[i]->data[p]]++;
            total++;
        }
    }
    if (total == 0) return 0.0;

    double H = 0.0;
    for (int b = 0; b < 256; b++) {
        if (freq[b] == 0) continue;
        double p = (double)freq[b] / (double)total;
        H -= p * log2(p);
    }
    return H;
}

/* ── Individual classifiers ─────────────────────────────────────────────────── */

static int is_constant(token_t **msgs, size_t n, size_t off, size_t len)
{
    if (n == 0 || len == 0) return 0;
    /* Check all messages have the same bytes at [off, off+len). */
    for (size_t i = 0; i < n; i++)
        if (msgs[i]->len < off + len) return 0;

    for (size_t i = 1; i < n; i++)
        if (memcmp(msgs[0]->data + off, msgs[i]->data + off, len) != 0)
            return 0;
    return 1;
}

/* Returns number of distinct values (up to cap+1). */
static size_t count_distinct(token_t **msgs, size_t n, size_t off, size_t len,
                              uint32_t enum_vals[16])
{
    /* Only handle up to 4-byte fields for enum detection. */
    if (len > 4) return 17;

    uint32_t seen[64];
    size_t   nseen = 0;

    for (size_t i = 0; i < n; i++) {
        if (msgs[i]->len < off + len) continue;
        uint32_t v = 0;
        for (size_t b = 0; b < len; b++)
            v = (v << 8) | msgs[i]->data[off + b];
        /* Linear search (small set). */
        int found = 0;
        for (size_t j = 0; j < nseen; j++)
            if (seen[j] == v) { found = 1; break; }
        if (!found) {
            if (nseen >= 64) return nseen + 1;
            seen[nseen++] = v;
        }
    }
    /* Copy up to 16 values. */
    size_t copy = nseen < 16 ? nseen : 16;
    if (enum_vals)
        for (size_t i = 0; i < copy; i++) enum_vals[i] = seen[i];
    return nseen;
}

static int is_sequence_number(token_t **msgs, size_t n, size_t off, size_t len)
{
    if (n < 3 || len > 4) return 0;
    /* Values should be strictly increasing (or at least non-decreasing)
       across consecutive messages with the same session_id.
       For simplicity: check that values are monotonically non-decreasing. */
    uint32_t prev = 0;
    int init = 0;
    for (size_t i = 0; i < n; i++) {
        if (msgs[i]->len < off + len) return 0;
        uint32_t v = 0;
        for (size_t b = 0; b < len; b++) v = (v << 8) | msgs[i]->data[off+b];
        if (init && v < prev) return 0;
        prev = v; init = 1;
    }
    /* At least some variation required. */
    uint32_t first = 0, last = 0;
    if (msgs[0]->len >= off + len)
        for (size_t b = 0; b < len; b++) first = (first << 8) | msgs[0]->data[off+b];
    if (msgs[n-1]->len >= off + len)
        for (size_t b = 0; b < len; b++) last = (last << 8) | msgs[n-1]->data[off+b];
    return last > first;
}

static int is_length_field(token_t **msgs, size_t n, size_t off, size_t len)
{
    if (n < 4 || len > 4) return 0;
    /* Test correlation: val == payload_len - k for constant k. */
    if (msgs[0]->len < off + len) return 0;
    uint32_t v0 = 0;
    for (size_t b = 0; b < len; b++) v0 = (v0 << 8) | msgs[0]->data[off+b];
    long k = (long)msgs[0]->len - (long)v0;

    size_t match = 0;
    for (size_t i = 0; i < n; i++) {
        if (msgs[i]->len < off + len) continue;
        uint32_t v = 0;
        for (size_t b = 0; b < len; b++) v = (v << 8) | msgs[i]->data[off+b];
        if ((long)msgs[i]->len - (long)v == k) match++;
    }
    return (double)match / (double)n >= 0.85;
}

static int is_nonce(token_t **msgs, size_t n, size_t off, size_t len)
{
    /* High entropy + no repetition across messages. */
    double H = field_entropy(msgs, n, off, len);
    if (H < 7.5) return 0;

    /* Check no two messages share the same bytes at this field. */
    if (n > 64) n = 64;  /* limit for performance */
    for (size_t i = 0; i < n; i++) {
        if (msgs[i]->len < off + len) continue;
        for (size_t j = i + 1; j < n; j++) {
            if (msgs[j]->len < off + len) continue;
            if (memcmp(msgs[i]->data + off, msgs[j]->data + off, len) == 0)
                return 0;
        }
    }
    return 1;
}

static int is_string_field(token_t **msgs, size_t n, size_t off, size_t len)
{
    size_t print_total = 0, total = 0;
    for (size_t i = 0; i < n; i++) {
        size_t end = off + len;
        if (msgs[i]->len < end) end = msgs[i]->len;
        for (size_t p = off; p < end; p++) {
            if (isprint((unsigned char)msgs[i]->data[p])) print_total++;
            total++;
        }
    }
    return total > 0 && print_total * 100 / total >= 80;
}

/* ── Main classifier ────────────────────────────────────────────────────────── */

field_type_t classify_field(token_t **msgs, size_t n,
                              size_t offset, size_t length)
{
    if (n == 0 || length == 0) return FIELD_OPAQUE;

    double H = field_entropy(msgs, n, offset, length);

    /* MAGIC / CONSTANT — both are invariant across all messages.
     * MAGIC: protocol sync bytes. usually at offset 0, or contains
     *        known sentinel values (0xff, 0xfe, non-zero "marker" bytes).
     * CONSTANT: field that just never varies (padding, version byte, etc.) */
    if (is_constant(msgs, n, offset, length)) {
        /* assume magic if at start of message, or value looks sentinel-ish */
        if (msgs[0]->len >= offset + length) {
            int looks_magic = (offset == 0);
            if (!looks_magic) {
                /* check if any byte is 0xff, 0xfe, or a non-trivial marker */
                for (size_t b = 0; b < length && !looks_magic; b++) {
                    uint8_t byte = msgs[0]->data[offset + b];
                    if (byte == 0xff || byte == 0xfe || byte == 0xfd)
                        looks_magic = 1;
                }
            }
            return looks_magic ? FIELD_MAGIC : FIELD_CONSTANT;
        }
        return FIELD_MAGIC;
    }

    /* NONCE */
    if (H > 7.5 && is_nonce(msgs, n, offset, length))
        return FIELD_NONCE;

    /* LENGTH */
    if (is_length_field(msgs, n, offset, length))
        return FIELD_LENGTH;

    /* SEQUENCE_NUMBER */
    if (length <= 4 && is_sequence_number(msgs, n, offset, length))
        return FIELD_SEQUENCE_NUMBER;

    /* ENUM */
    if (H < 3.0 && length <= 4) {
        size_t ndist = count_distinct(msgs, n, offset, length, NULL);
        if (ndist >= 2 && ndist <= 16)
            return FIELD_ENUM;
    }

    /* STRING */
    if (is_string_field(msgs, n, offset, length))
        return FIELD_STRING;

    /* PAYLOAD: high entropy, variable length (length==0 caller), appears last. */
    if (H > 6.5)
        return FIELD_PAYLOAD;

    return FIELD_OPAQUE;
}

const char *field_type_name(field_type_t t)
{
    switch (t) {
        case FIELD_MAGIC:           return "MAGIC";
        case FIELD_CONSTANT:        return "CONSTANT";
        case FIELD_ENUM:            return "ENUM";
        case FIELD_SEQUENCE_NUMBER: return "SEQUENCE_NUMBER";
        case FIELD_LENGTH:          return "LENGTH";
        case FIELD_PAYLOAD:         return "PAYLOAD";
        case FIELD_NONCE:           return "NONCE";
        case FIELD_STRING:          return "STRING";
        case FIELD_OPAQUE:          return "OPAQUE";
    }
    return "UNKNOWN";
}

/* ── Full format inference pipeline ─────────────────────────────────────────── */

protocol_schema_t *infer_format(token_stream_t **streams, size_t nstreams,
                                 const framing_info_t *framing)
{
    /* 1. Cluster. */
    size_t total;
    int    k;
    uint32_t *labels = cluster_messages(streams, nstreams, &total, &k);
    if (!labels || total == 0) { free(labels); return NULL; }

    protocol_schema_t *ps = calloc(1, sizeof(*ps));
    if (!ps) { free(labels); return NULL; }

    ps->schema_count = (size_t)k;
    ps->schemas      = calloc((size_t)k, sizeof(message_schema_t));
    if (!ps->schemas) { free(labels); free(ps); return NULL; }

    for (int c = 0; c < k; c++) {
        ps->schemas[c].type_id = (uint32_t)c;
        snprintf(ps->schemas[c].name, sizeof(ps->schemas[c].name),
                 "msg_type_%02d", c);
    }

    /* 2. Per cluster: gather tokens, align, segment, classify. */
    token_t ***cluster_msgs = calloc((size_t)k, sizeof(token_t **));
    size_t    *cluster_n    = calloc((size_t)k, sizeof(size_t));
    size_t    *cluster_cap  = calloc((size_t)k, sizeof(size_t));
    if (!cluster_msgs || !cluster_n || !cluster_cap) {
        free(labels); protocol_schema_free(ps);
        free(cluster_msgs); free(cluster_n); free(cluster_cap);
        return NULL;
    }

    /* Flatten tokens and assign to clusters. */
    size_t label_idx = 0;
    for (size_t si = 0; si < nstreams; si++) {
        for (size_t mi = 0; mi < streams[si]->count; mi++) {
            uint32_t cl = labels[label_idx++];
            if (cl >= (uint32_t)k) continue;
            if (cluster_n[cl] >= cluster_cap[cl]) {
                cluster_cap[cl] = cluster_cap[cl] ? cluster_cap[cl] * 2 : 16;
                cluster_msgs[cl] = realloc(cluster_msgs[cl],
                                            cluster_cap[cl] * sizeof(token_t *));
            }
            cluster_msgs[cl][cluster_n[cl]++] = &streams[si]->tokens[mi];
        }
    }
    free(labels);

    for (int c = 0; c < k; c++) {
        if (cluster_n[c] == 0) continue;

        size_t  cons_len;
        double *conservation = align_cluster(cluster_msgs[c], cluster_n[c],
                                              &cons_len);
        if (!conservation) continue;

        size_t  nfields;
        field_t *fields = segment_fields(conservation, cons_len, framing, &nfields);
        free(conservation);
        if (!fields) continue;

        /* Classify each field and compute entropy. */
        for (size_t fi = 0; fi < nfields; fi++) {
            field_t *f = &fields[fi];
            size_t   len = f->length ? f->length : 8;  /* variable: probe first 8 */

            f->entropy = field_entropy(cluster_msgs[c], cluster_n[c],
                                        f->offset, len);

            if (f->type == FIELD_OPAQUE || f->type == FIELD_CONSTANT) {
                f->type = classify_field(cluster_msgs[c], cluster_n[c],
                                          f->offset, f->length ? f->length : len);
            }

            snprintf(f->name, sizeof(f->name), "field_%02zu_%s",
                     fi, field_type_name(f->type));

            /* Collect enum values. */
            if (f->type == FIELD_ENUM) {
                f->enum_count = count_distinct(cluster_msgs[c], cluster_n[c],
                                               f->offset, f->length,
                                               f->enum_values);
                if (f->enum_count > 16) f->enum_count = 16;
            }
        }

        ps->schemas[c].fields      = fields;
        ps->schemas[c].field_count = nfields;
        free(cluster_msgs[c]);
    }

    free(cluster_msgs);
    free(cluster_n);
    free(cluster_cap);

    return ps;
}

void message_schema_free(message_schema_t *s)
{
    if (!s) return;
    free(s->fields);
}

void protocol_schema_free(protocol_schema_t *ps)
{
    if (!ps) return;
    for (size_t i = 0; i < ps->schema_count; i++)
        message_schema_free(&ps->schemas[i]);
    free(ps->schemas);
    free(ps);
}
