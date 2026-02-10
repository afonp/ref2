#ifndef REF2_TOKEN_H
#define REF2_TOKEN_H

#include <stdint.h>
#include <stddef.h>
#include "ingest.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ── Token types ────────────────────────────────────────────────────────────── */

typedef struct {
    uint8_t *data;
    size_t   len;
    uint32_t type_hint;   /* discriminator value from type field; 0 = unknown */
} token_t;

typedef struct {
    token_t  *tokens;
    size_t    count;
    uint32_t  session_id;
} token_stream_t;

/* ── Framing metadata (output of detection) ─────────────────────────────────── */

typedef struct {
    size_t  header_len;           /* length of fixed-header region in bytes */

    int     has_length_field;
    size_t  length_offset;        /* byte offset of length field within header */
    size_t  length_width;         /* 1, 2, or 4 */
    int     length_endian;        /* 0 = LE, 1 = BE */
    int32_t length_adjustment;    /* msg_total_len = field_value + length_adjustment */

    int     has_type_field;
    size_t  type_offset;          /* byte offset of message-type discriminator */
    size_t  type_width;           /* 1 or 2 */

    int     has_delimiter;
    uint8_t delimiter[4];
    size_t  delimiter_len;
} framing_info_t;

/* ── Tokenization API ───────────────────────────────────────────────────────── */

/* Analyse all sessions and infer framing parameters. */
framing_info_t *detect_framing(const session_t *sessions, size_t session_count);

/* Apply inferred framing to one session, producing a token stream. */
token_stream_t *tokenize_session(const session_t *session,
                                 const framing_info_t *framing);

/* Tokenize an entire trace; *framing_out receives ownership of framing_info. */
token_stream_t **tokenize_trace(const trace_t *trace,
                                framing_info_t **framing_out);

/* ── Memory management ──────────────────────────────────────────────────────── */

void token_stream_free (token_stream_t *stream);
void framing_info_free (framing_info_t *info);

#ifdef __cplusplus
}
#endif

#endif /* REF2_TOKEN_H */
