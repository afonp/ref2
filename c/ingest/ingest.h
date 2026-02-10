#ifndef REF2_INGEST_H
#define REF2_INGEST_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ── Source type ────────────────────────────────────────────────────────────── */

typedef enum {
    SOURCE_PCAP      = 0,
    SOURCE_RAW       = 1,
    SOURCE_PLAINTEXT = 2,
    SOURCE_SYSCALL   = 3,
} source_t;

/* ── Core data types ────────────────────────────────────────────────────────── */

typedef struct {
    uint64_t  timestamp_us;
    uint8_t   direction;    /* 0 = client→server, 1 = server→client */
    uint8_t  *payload;
    size_t    payload_len;
    source_t  source;
    uint32_t  session_id;
} message_t;

typedef struct {
    message_t *messages;
    size_t     count;
    uint32_t   session_id;
} session_t;

typedef struct {
    session_t *sessions;
    size_t     count;
} trace_t;

/* ── Frame hint (raw ingestion) ─────────────────────────────────────────────── */

typedef enum {
    FRAME_FIXED_HEADER,
    FRAME_LENGTH_FIELD,
    FRAME_DELIMITER,
} frame_type_t;

typedef struct {
    frame_type_t type;
    size_t       header_size;    /* FRAME_FIXED_HEADER: fixed bytes before payload */
    size_t       length_offset;  /* FRAME_LENGTH_FIELD: byte offset of length field */
    size_t       length_width;   /* 1, 2, or 4 */
    int          length_endian;  /* 0 = little-endian, 1 = big-endian */
    uint8_t      delimiter[4];   /* FRAME_DELIMITER */
    size_t       delimiter_len;
} frame_hint_t;

/* ── Ingestion API ──────────────────────────────────────────────────────────── */

trace_t *ingest_pcap      (const char *path);
trace_t *ingest_raw       (const char *path, const frame_hint_t *hint);
trace_t *ingest_plaintext (const char *path);
trace_t *ingest_syscall   (const char *path);

/* ── Memory management ──────────────────────────────────────────────────────── */

void trace_free   (trace_t   *trace);
void session_free (session_t *session);
void message_free (message_t *msg);

#ifdef __cplusplus
}
#endif

#endif /* REF2_INGEST_H */
