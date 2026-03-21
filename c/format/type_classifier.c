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
    if (n < 3 || len > 2) return 0;

    /* Collect distinct values (only for small ranges that suggest counters). */
    uint8_t present[256] = {0};
    uint32_t max_val = 0;
    size_t valid = 0;
    for (size_t i = 0; i < n; i++) {
        if (msgs[i]->len < off + len) return 0;
        uint32_t v = 0;
        for (size_t b = 0; b < len; b++) v = (v << 8) | msgs[i]->data[off+b];
        if (v > 255) return 0;  /* values > 255 — not a typical seq counter */
        present[v] = 1;
        if (v > max_val) max_val = v;
        valid++;
    }
    if (valid < 3 || max_val < 2) return 0;

    /* Values must form a mostly-consecutive set covering ≥80% of [0, max_val].
       This distinguishes a repeating 0..N counter (sequence number) from a
       sparse enum or random variable field. */
    size_t ndist = 0;
    for (size_t i = 0; i <= max_val; i++)
        if (present[i]) ndist++;

    if (ndist * 5 < (max_val + 1) * 4) return 0;  /* not dense enough */

    /* Reject if max_val+1 is a power of 2 (e.g. 1,3,7,15,31,63,127,255).
       Bit-flag fields (2-bit, 3-bit masks) also produce exactly-full consecutive
       ranges like {0..3} or {0..7}, which are indistinguishable from counters
       without session context.  Require max_val >= 12 OR non-power-of-2 range. */
    uint32_t m = max_val + 1;
    int is_pow2_range = (m > 0) && ((m & (m - 1)) == 0);
    if (is_pow2_range && max_val < 12) return 0;

    return 1;
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
    /* High entropy + no repetition across messages.
       Require ≥80% of messages to cover the full field; otherwise the field
       is variable-length (NW-padded consensus) and should be PAYLOAD. */
    size_t covered = 0;
    for (size_t i = 0; i < n; i++)
        if (msgs[i]->len >= off + len) covered++;
    if (n > 0 && covered * 5 < n * 4) return 0;

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


        /* Classify each field and compute entropy.
           Once a PAYLOAD (variable-length tail) is emitted, stop — all subsequent
           NW-padded segments are part of the same variable-length tail. */
        size_t actual_nfields = 0;
        int seen_variable = 0;  /* set once we've emitted any variable/non-constant field */
        for (size_t fi = 0; fi < nfields; fi++) {
            field_t *f = &fields[fi];
            size_t   len = f->length ? f->length : 8;  /* variable: probe first 8 */

            f->entropy = field_entropy(cluster_msgs[c], cluster_n[c],
                                        f->offset, len);

            /* For OPAQUE segments of length > 1, scan raw message bytes to find
               the payload boundary.  A position is a "structured header byte" if:
               (a) ≥80% of cluster messages have data at that raw byte position, AND
               (b) it has ≤16 distinct byte values (structured fields have a bounded
                   value space; random bytes across n≥30 messages yield 20+ distinct
                   values, well above this threshold).
               We scan raw bytes rather than using the NW conservation vector because
               progressive NW alignment shifts consensus positions, making
               conservation[pos] unreliable as a proxy for protocol byte position.
               Only emit payload_after when the scan finds a boundary before the end
               of the field (split < f->length); if the entire field is structured
               we leave it alone. */
            int emit_payload_after = 0;
            if (f->type == FIELD_OPAQUE && f->length > 1) {
                size_t split = 0;
                int payload_starts_here = 0;
                for (size_t p = 0; p < f->length; p++) {
                    size_t pos = f->offset + p;

                    /* Count messages with data at this position and collect distinct
                       byte values simultaneously. */
                    uint8_t seen_vals[32]; size_t nseen = 0;
                    size_t present = 0;
                    for (size_t m = 0; m < cluster_n[c]; m++) {
                        if (cluster_msgs[c][m]->len <= pos) continue;
                        present++;
                        uint8_t v = cluster_msgs[c][m]->data[pos];
                        int found = 0;
                        for (size_t j = 0; j < nseen; j++)
                            if (seen_vals[j] == v) { found = 1; break; }
                        if (!found) {
                            if (nseen < 32) seen_vals[nseen++] = v;
                            else { nseen = 33; break; }
                        }
                    }
                    /* Low coverage → entered the variable payload. */
                    if (cluster_n[c] > 0 && present * 5 < cluster_n[c] * 4) {
                        payload_starts_here = 1; break;
                    }
                    /* Too many distinct values → high-entropy / payload data. */
                    if (nseen > 16) { payload_starts_here = 1; break; }
                    split = p + 1;
                }

                if (payload_starts_here && split == 0) {
                    /* No structured prefix — entire segment is payload. */
                    f->type   = FIELD_PAYLOAD;
                    f->length = 0;
                    actual_nfields++;
                    snprintf(f->name, sizeof(f->name), "field_%02zu_PAYLOAD",
                             actual_nfields - 1);
                    break;
                } else if (payload_starts_here && split < f->length) {
                    /* Trim to the structured prefix; emit PAYLOAD right after. */
                    f->length = split;
                    f->entropy = field_entropy(cluster_msgs[c], cluster_n[c],
                                               f->offset, split);
                    emit_payload_after = 1;
                }
                /* split == f->length: whole field is structured — no split needed. */
            }

            if (f->type == FIELD_OPAQUE || f->type == FIELD_CONSTANT) {
                f->type = classify_field(cluster_msgs[c], cluster_n[c],
                                          f->offset, f->length ? f->length : len);
            }

            /* Spurious-field guard: once we've seen any variable/non-constant field,
               an OPAQUE field with high entropy at its first byte is random payload
               data (e.g., a NW-artifact CONSTANT that classify_field demoted to OPAQUE)
               rather than a legitimate structured header field.  Emit PAYLOAD and stop. */
            if (seen_variable && f->type == FIELD_OPAQUE && f->length > 0
                    && cluster_n[c] > 0) {
                uint8_t sbuf[32]; size_t nsbuf = 0;
                for (size_t m = 0; m < cluster_n[c]; m++) {
                    if (cluster_msgs[c][m]->len <= f->offset) continue;
                    uint8_t v = cluster_msgs[c][m]->data[f->offset];
                    int found = 0;
                    for (size_t j = 0; j < nsbuf; j++)
                        if (sbuf[j] == v) { found = 1; break; }
                    if (!found) {
                        if (nsbuf < 32) sbuf[nsbuf++] = v;
                        else { nsbuf = 33; break; }
                    }
                }
                if (nsbuf > 16) {
                    f->length     = 0;
                    f->type       = FIELD_PAYLOAD;
                    f->entropy    = 0.0;
                    f->enum_count = 0;
                    actual_nfields++;
                    snprintf(f->name, sizeof(f->name), "field_%02zu_PAYLOAD",
                             actual_nfields - 1);
                    break;
                }
            }

            actual_nfields++;
            snprintf(f->name, sizeof(f->name), "field_%02zu_%s",
                     actual_nfields - 1, field_type_name(f->type));

            /* Collect enum values; also store constant value so the cross-cluster
               ENUM detection pass can read it from CONSTANT/MAGIC fields. */
            if (f->type == FIELD_ENUM) {
                f->enum_count = count_distinct(cluster_msgs[c], cluster_n[c],
                                               f->offset, f->length,
                                               f->enum_values);
                if (f->enum_count > 16) f->enum_count = 16;
            } else if ((f->type == FIELD_CONSTANT || f->type == FIELD_MAGIC) &&
                       f->length > 0 && f->length <= 4 && cluster_n[c] > 0 &&
                       cluster_msgs[c][0]->len >= f->offset + f->length) {
                uint32_t v = 0;
                for (size_t b = 0; b < f->length; b++)
                    v = (v << 8) | cluster_msgs[c][0]->data[f->offset + b];
                f->enum_values[0] = v;
                f->enum_count = 1;
            }

            /* Update seen_variable: set once we've emitted any non-constant field
               (OPAQUE, ENUM, LENGTH, SEQ, NONCE, STRING, PAYLOAD).  MAGIC and
               CONSTANT fields are "fixed header" and don't count. */
            if (f->type != FIELD_MAGIC && f->type != FIELD_CONSTANT)
                seen_variable = 1;

            if (emit_payload_after) {
                /* Append a synthetic PAYLOAD field for the variable-length tail.
                   Safe: fields was allocated with (cons_len+1) slots. */
                field_t *pf = &fields[actual_nfields];
                pf->offset     = f->offset + f->length;
                pf->length     = 0;
                pf->type       = FIELD_PAYLOAD;
                pf->entropy    = 0.0;
                pf->enum_count = 0;
                actual_nfields++;
                snprintf(pf->name, sizeof(pf->name), "field_%02zu_PAYLOAD",
                         actual_nfields - 1);
                break;
            }
        }

        ps->schemas[c].fields      = fields;
        ps->schemas[c].field_count = actual_nfields;
        free(cluster_msgs[c]);
    }

    free(cluster_msgs);
    free(cluster_n);
    free(cluster_cap);

    /* Cross-cluster ENUM detection: if multiple clusters each have a CONSTANT
       field at the same (offset, length) but with different stored values,
       reclassify all of them as ENUM.  This catches the common pattern where
       each cluster is keyed by an opcode that is constant within the cluster
       but varies across clusters. */
    if (ps->schema_count >= 2) {
        /* Collect (offset, length) pairs that appear as CONSTANT/MAGIC in
           at least 2 clusters and have ≥ 2 distinct values. */
        for (size_t c0 = 0; c0 < ps->schema_count; c0++) {
            for (size_t fi = 0; fi < ps->schemas[c0].field_count; fi++) {
                field_t *f0 = &ps->schemas[c0].fields[fi];
                if (f0->type != FIELD_CONSTANT && f0->type != FIELD_MAGIC) continue;
                if (f0->length == 0 || f0->length > 4) continue;
                if (f0->enum_count != 1) continue;  /* need stored constant value */

                /* Gather distinct values at this (offset, length) across clusters. */
                uint32_t vals[32];
                size_t   nvals = 0;

                for (size_t c1 = 0; c1 < ps->schema_count; c1++) {
                    for (size_t fj = 0; fj < ps->schemas[c1].field_count; fj++) {
                        field_t *f1 = &ps->schemas[c1].fields[fj];
                        if (f1->offset != f0->offset || f1->length != f0->length) continue;
                        if (f1->type != FIELD_CONSTANT && f1->type != FIELD_MAGIC) continue;
                        if (f1->enum_count < 1) continue;
                        uint32_t val = f1->enum_values[0];
                        int dup = 0;
                        for (size_t u = 0; u < nvals; u++)
                            if (vals[u] == val) { dup = 1; break; }
                        if (!dup && nvals < 32) vals[nvals++] = val;
                    }
                }

                /* Need 2–16 distinct values; otherwise skip. */
                if (nvals < 2 || nvals > 16) continue;

                /* Reclassify all matching fields in all clusters as ENUM. */
                for (size_t c1 = 0; c1 < ps->schema_count; c1++) {
                    for (size_t fj = 0; fj < ps->schemas[c1].field_count; fj++) {
                        field_t *f1 = &ps->schemas[c1].fields[fj];
                        if (f1->offset != f0->offset || f1->length != f0->length) continue;
                        if (f1->type != FIELD_CONSTANT && f1->type != FIELD_MAGIC) continue;
                        f1->type = FIELD_ENUM;
                        f1->enum_count = nvals;
                        for (size_t v = 0; v < nvals; v++)
                            f1->enum_values[v] = vals[v];
                        snprintf(f1->name, sizeof(f1->name), "field_%02zu_ENUM", fj);
                    }
                }
            }
        }
    }

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
