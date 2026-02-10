/*
 * raw_reader.c — Binary blob ingestion with optional frame hint.
 *
 * If frame_hint is NULL the entire blob is emitted as one message and the
 * token layer performs auto-framing.  Otherwise the hint is used to slice
 * the blob into discrete messages immediately.
 */

#include "ingest.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ── Helpers ────────────────────────────────────────────────────────────────── */

static uint32_t read_uint(const uint8_t *buf, size_t width, int big_endian)
{
    uint32_t v = 0;
    if (big_endian) {
        for (size_t i = 0; i < width; i++)
            v = (v << 8) | buf[i];
    } else {
        for (size_t i = 0; i < width; i++)
            v |= (uint32_t)buf[i] << (8 * i);
    }
    return v;
}

/* Append a copy of data[0..len) as a new message to sess. */
static int session_add_msg(session_t *sess, const uint8_t *data, size_t len,
                            uint64_t ts, uint8_t dir)
{
    message_t *m = realloc(sess->messages,
                            (sess->count + 1) * sizeof(message_t));
    if (!m) return -1;
    sess->messages = m;

    message_t *msg = &sess->messages[sess->count++];
    msg->timestamp_us = ts;
    msg->direction    = dir;
    msg->payload      = malloc(len);
    if (!msg->payload) { sess->count--; return -1; }
    memcpy(msg->payload, data, len);
    msg->payload_len  = len;
    msg->source       = SOURCE_RAW;
    msg->session_id   = sess->session_id;
    return 0;
}

/* ── Framing strategies ──────────────────────────────────────────────────────── */

static int frame_fixed_header(session_t *sess,
                               const uint8_t *buf, size_t buf_len,
                               const frame_hint_t *hint)
{
    size_t hdr = hint->header_size;
    if (hdr == 0 || hdr > buf_len) {
        /* Emit whole blob as one message. */
        return session_add_msg(sess, buf, buf_len, 0, 0);
    }
    size_t off = 0;
    while (off + hdr <= buf_len) {
        size_t payload = buf_len - off - hdr;
        session_add_msg(sess, buf + off, hdr + payload, 0, 0);
        off += hdr + payload;
    }
    return 0;
}

static int frame_length_field(session_t *sess,
                               const uint8_t *buf, size_t buf_len,
                               const frame_hint_t *hint)
{
    size_t off = 0;
    while (off < buf_len) {
        size_t lo = hint->length_offset;
        size_t lw = hint->length_width;
        if (off + lo + lw > buf_len) break;

        uint32_t fval = read_uint(buf + off + lo, lw, hint->length_endian);

        /* Assume length field encodes total message length. */
        size_t msg_len = (size_t)fval;
        if (msg_len == 0 || off + msg_len > buf_len) {
            /* Consume remaining bytes as one message. */
            session_add_msg(sess, buf + off, buf_len - off, 0, 0);
            break;
        }
        session_add_msg(sess, buf + off, msg_len, 0, 0);
        off += msg_len;
    }
    return 0;
}

static int frame_delimiter(session_t *sess,
                            const uint8_t *buf, size_t buf_len,
                            const frame_hint_t *hint)
{
    const uint8_t *delim = hint->delimiter;
    size_t dlen = hint->delimiter_len;
    if (dlen == 0 || dlen > buf_len) {
        return session_add_msg(sess, buf, buf_len, 0, 0);
    }

    size_t start = 0;
    for (size_t i = 0; i + dlen <= buf_len; ) {
        if (memcmp(buf + i, delim, dlen) == 0) {
            if (i > start)
                session_add_msg(sess, buf + start, i - start, 0, 0);
            i += dlen;
            start = i;
        } else {
            i++;
        }
    }
    /* Tail bytes after last delimiter. */
    if (start < buf_len)
        session_add_msg(sess, buf + start, buf_len - start, 0, 0);
    return 0;
}

/* ── Public API ─────────────────────────────────────────────────────────────── */

trace_t *ingest_raw(const char *path, const frame_hint_t *hint)
{
    FILE *f = fopen(path, "rb");
    if (!f) {
        perror(path);
        return NULL;
    }

    fseek(f, 0, SEEK_END);
    long fsz = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (fsz <= 0) { fclose(f); return NULL; }

    uint8_t *buf = malloc((size_t)fsz);
    if (!buf) { fclose(f); return NULL; }
    if ((long)fread(buf, 1, (size_t)fsz, f) != fsz) {
        free(buf); fclose(f); return NULL;
    }
    fclose(f);

    /* Build single-session trace. */
    trace_t *trace = malloc(sizeof(*trace));
    if (!trace) { free(buf); return NULL; }

    trace->count    = 1;
    trace->sessions = calloc(1, sizeof(session_t));
    if (!trace->sessions) { free(buf); free(trace); return NULL; }
    trace->sessions[0].session_id = 1;

    int rc = 0;
    if (!hint) {
        rc = session_add_msg(&trace->sessions[0], buf, (size_t)fsz, 0, 0);
    } else {
        switch (hint->type) {
            case FRAME_FIXED_HEADER:
                rc = frame_fixed_header(&trace->sessions[0], buf, (size_t)fsz, hint);
                break;
            case FRAME_LENGTH_FIELD:
                rc = frame_length_field(&trace->sessions[0], buf, (size_t)fsz, hint);
                break;
            case FRAME_DELIMITER:
                rc = frame_delimiter(&trace->sessions[0], buf, (size_t)fsz, hint);
                break;
        }
    }

    free(buf);  /* session messages have their own copies */

    if (rc != 0) {
        trace_free(trace);
        return NULL;
    }
    return trace;
}
