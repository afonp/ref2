/*
 * plaintext_reader.c — Human-readable / text-export ingestion.
 *
 * Supported input formats:
 *   1. Direction-prefixed:  ">> <payload>" or "<< <payload>"
 *      (payload is either ASCII or hex-encoded)
 *   2. Wireshark "Follow TCP Stream" text export:
 *      Lines of hex bytes separated by spaces, preceded by offset lines like
 *      "00000000  de ad be ef ..."
 *   3. Raw line-per-message: one message per line, no direction prefix.
 *
 * Auto-detection order: direction-prefixed → wireshark hex dump → plain lines.
 */

#include "ingest.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <time.h>

#define MAX_LINE  65536

/* ── Utility ─────────────────────────────────────────────────────────────────── */

static int hex_digit(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/* Decode a hex string (with optional spaces/colons) into dst.
   Returns number of bytes written, or -1 on error. */
static long hex_decode(const char *src, uint8_t *dst, size_t dst_cap)
{
    size_t out = 0;
    size_t len = strlen(src);
    for (size_t i = 0; i < len; ) {
        /* skip separators */
        if (src[i] == ' ' || src[i] == ':' || src[i] == '\t') { i++; continue; }
        int hi = hex_digit(src[i]);
        int lo = (i + 1 < len) ? hex_digit(src[i + 1]) : -1;
        if (hi < 0) break;
        if (lo < 0) { /* single nibble — pad low */ lo = 0; i++; }
        else i += 2;
        if (out >= dst_cap) return -1;
        dst[out++] = (uint8_t)((hi << 4) | lo);
    }
    return (long)out;
}

/* >80% printable → treat as ASCII, else hex. */
static int is_mostly_printable(const char *s, size_t len)
{
    size_t print = 0;
    for (size_t i = 0; i < len; i++)
        if (isprint((unsigned char)s[i]) || s[i] == '\t') print++;
    return len > 0 && print * 100 / len >= 80;
}

/* Strip optional ISO-8601 / unix-epoch timestamp prefix.
   Returns pointer past the timestamp, or src if none found. */
static const char *strip_timestamp(const char *src)
{
    /* Unix epoch prefix: digits followed by whitespace */
    const char *p = src;
    while (isdigit((unsigned char)*p)) p++;
    if (p > src && (*p == ' ' || *p == '\t' || *p == '.')) {
        /* might be epoch or partial ISO8601 */
        while (*p == ' ' || *p == '\t' || *p == '.' || *p == 'Z' ||
               *p == '+' || *p == '-' || isdigit((unsigned char)*p) ||
               *p == ':' || *p == 'T')
            p++;
        if (*p == ' ' || *p == '\t') return p + 1;
    }
    return src;
}

/* Append a message to the single session in trace. */
static void add_msg(session_t *sess, const uint8_t *data, size_t len,
                    uint8_t dir, uint32_t idx)
{
    if (len == 0) return;
    message_t *m = realloc(sess->messages,
                            (sess->count + 1) * sizeof(message_t));
    if (!m) return;
    sess->messages = m;
    message_t *msg = &sess->messages[sess->count++];
    msg->timestamp_us = (uint64_t)idx * 1000;
    msg->direction    = dir;
    msg->payload      = malloc(len);
    if (!msg->payload) { sess->count--; return; }
    memcpy(msg->payload, data, len);
    msg->payload_len  = len;
    msg->source       = SOURCE_PLAINTEXT;
    msg->session_id   = sess->session_id;
}

/* ── Format 1: direction-prefixed lines ──────────────────────────────────────── */

static int parse_direction_prefixed(FILE *f, session_t *sess)
{
    char line[MAX_LINE];
    uint8_t buf[MAX_LINE];
    uint32_t idx = 0;

    while (fgets(line, sizeof(line), f)) {
        /* Strip trailing newline. */
        size_t ll = strlen(line);
        while (ll > 0 && (line[ll-1] == '\n' || line[ll-1] == '\r'))
            line[--ll] = '\0';

        uint8_t dir;
        const char *payload_str;

        if (strncmp(line, ">> ", 3) == 0) {
            dir = 0; payload_str = line + 3;
        } else if (strncmp(line, "<< ", 3) == 0) {
            dir = 1; payload_str = line + 3;
        } else {
            continue;  /* skip non-payload lines */
        }

        payload_str = strip_timestamp(payload_str);
        size_t plen = strlen(payload_str);

        if (is_mostly_printable(payload_str, plen)) {
            add_msg(sess, (const uint8_t *)payload_str, plen, dir, idx++);
        } else {
            long n = hex_decode(payload_str, buf, sizeof(buf));
            if (n > 0)
                add_msg(sess, buf, (size_t)n, dir, idx++);
        }
    }
    return sess->count > 0 ? 0 : -1;
}

/* ── Format 2: Wireshark hex dump ───────────────────────────────────────────── */

/*
 * Wireshark "Follow Stream" hex view lines look like:
 *   00000000  de ad be ef  ca fe ba be  00 01 02 03  04 05 06 07  ................
 * Lines NOT starting with a hex offset are section headers or separators.
 */
static int parse_wireshark_hexdump(FILE *f, session_t *sess)
{
    char line[MAX_LINE];
    uint8_t msg_buf[65536];
    size_t msg_len = 0;
    uint8_t cur_dir = 0;
    uint32_t idx = 0;
    int seen_any = 0;

    while (fgets(line, sizeof(line), f)) {
        size_t ll = strlen(line);
        while (ll > 0 && (line[ll-1] == '\n' || line[ll-1] == '\r'))
            line[--ll] = '\0';

        /* Wireshark direction separators */
        if (strstr(line, "===") || strstr(line, "---")) {
            if (msg_len > 0) {
                add_msg(sess, msg_buf, msg_len, cur_dir, idx++);
                msg_len = 0;
            }
            cur_dir ^= 1;
            seen_any = 1;
            continue;
        }

        /* Check for offset prefix: 8 hex digits followed by two spaces */
        if (ll < 10) continue;
        int is_hex_line = 1;
        for (int i = 0; i < 8; i++) {
            if (hex_digit(line[i]) < 0) { is_hex_line = 0; break; }
        }
        if (!is_hex_line || line[8] != ' ' || line[9] != ' ') continue;

        /* Extract hex bytes: positions 10..57 (48 chars = 16 bytes × 3) */
        const char *hex_part = line + 10;
        /* Parse until we hit the ASCII section (two spaces) */
        const char *p = hex_part;
        while (*p) {
            while (*p == ' ') p++;
            if (*p == ' ' || *p == '\0') break;
            int hi = hex_digit(*p);
            if (hi < 0) break;
            int lo = hex_digit(*(p+1));
            if (lo < 0) break;
            if (msg_len < sizeof(msg_buf))
                msg_buf[msg_len++] = (uint8_t)((hi << 4) | lo);
            p += 2;
        }
        seen_any = 1;
    }
    if (msg_len > 0)
        add_msg(sess, msg_buf, msg_len, cur_dir, idx++);

    return seen_any ? 0 : -1;
}

/* ── Format 3: plain lines ───────────────────────────────────────────────────── */

static int parse_plain_lines(FILE *f, session_t *sess)
{
    char line[MAX_LINE];
    uint8_t buf[MAX_LINE];
    uint32_t idx = 0;

    while (fgets(line, sizeof(line), f)) {
        size_t ll = strlen(line);
        while (ll > 0 && (line[ll-1] == '\n' || line[ll-1] == '\r'))
            line[--ll] = '\0';
        if (ll == 0) continue;

        const char *p = strip_timestamp(line);
        size_t plen = strlen(p);

        if (is_mostly_printable(p, plen)) {
            add_msg(sess, (const uint8_t *)p, plen, 0, idx++);
        } else {
            long n = hex_decode(p, buf, sizeof(buf));
            if (n > 0)
                add_msg(sess, buf, (size_t)n, 0, idx++);
        }
    }
    return sess->count > 0 ? 0 : -1;
}

/* ── Auto-detect format ──────────────────────────────────────────────────────── */

typedef enum { FMT_UNKNOWN, FMT_DIR_PREFIX, FMT_WIRESHARK, FMT_PLAIN } text_fmt_t;

static text_fmt_t detect_format(FILE *f)
{
    char line[MAX_LINE];
    int wireshark_hits = 0;
    int dir_prefix_hits = 0;
    int lines = 0;

    while (fgets(line, sizeof(line), f) && lines < 20) {
        lines++;
        if (strncmp(line, ">> ", 3) == 0 || strncmp(line, "<< ", 3) == 0)
            dir_prefix_hits++;
        /* Wireshark: 8 hex chars + 2 spaces */
        int ok = 1;
        for (int i = 0; i < 8 && ok; i++)
            if (hex_digit(line[i]) < 0) ok = 0;
        if (ok && line[8] == ' ' && line[9] == ' ')
            wireshark_hits++;
    }
    rewind(f);

    if (dir_prefix_hits > 0) return FMT_DIR_PREFIX;
    if (wireshark_hits  > 0) return FMT_WIRESHARK;
    return FMT_PLAIN;
}

/* ── Public API ─────────────────────────────────────────────────────────────── */

trace_t *ingest_plaintext(const char *path)
{
    FILE *f = fopen(path, "r");
    if (!f) { perror(path); return NULL; }

    text_fmt_t fmt = detect_format(f);

    trace_t *trace = malloc(sizeof(*trace));
    if (!trace) { fclose(f); return NULL; }
    trace->count    = 1;
    trace->sessions = calloc(1, sizeof(session_t));
    if (!trace->sessions) { free(trace); fclose(f); return NULL; }
    trace->sessions[0].session_id = 1;

    int rc;
    switch (fmt) {
        case FMT_DIR_PREFIX: rc = parse_direction_prefixed(f, &trace->sessions[0]); break;
        case FMT_WIRESHARK:  rc = parse_wireshark_hexdump (f, &trace->sessions[0]); break;
        default:             rc = parse_plain_lines        (f, &trace->sessions[0]); break;
    }
    fclose(f);

    if (rc != 0) { trace_free(trace); return NULL; }
    return trace;
}
