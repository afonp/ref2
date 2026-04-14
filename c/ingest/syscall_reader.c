/*
 * syscall_reader.c — strace output ingestion.
 *
 * Parses output produced by:
 *   strace -e trace=read,write,send,recv,sendto,recvfrom -xx -ttt <prog>
 *
 * Each relevant line looks like:
 *   [pid] <syscall>(<fd>, "\x41\x42...", <len>[, ...]) = <ret>
 *
 * Groups calls by fd. Same-direction consecutive calls on the same fd are
 * concatenated before being emitted as a single message_t.
 *
 * "-xx" causes strace to emit all characters as hex escapes (\xNN), which we
 * parse here.  We also handle printable characters in the string literal.
 */

#include "ingest.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#define MAX_FDS      256
#define MAX_LINE     65536
#define INIT_BUF     4096

typedef struct {
    int      fd;
    uint8_t  cur_dir;      /* 0 = write/send (client→server), 1 = read/recv */
    uint8_t  last_dir;
    uint8_t *buf;
    size_t   buf_len;
    size_t   buf_cap;
    uint64_t buf_ts;

    message_t *msgs;
    size_t     msg_count;
    size_t     msg_cap;

    uint32_t   session_id;
} fd_state_t;

static fd_state_t g_fds[MAX_FDS];
static int        g_fd_count;
static uint32_t   g_next_sid;

static void fds_reset(void)
{
    for (int i = 0; i < g_fd_count; i++) {
        fd_state_t *s = &g_fds[i];
        free(s->buf);
        for (size_t j = 0; j < s->msg_count; j++)
            free(s->msgs[j].payload);
        free(s->msgs);
    }
    memset(g_fds, 0, sizeof(g_fds));
    g_fd_count = 0;
    g_next_sid = 1;
}

static fd_state_t *get_fd(int fd)
{
    for (int i = 0; i < g_fd_count; i++)
        if (g_fds[i].fd == fd) return &g_fds[i];

    if (g_fd_count >= MAX_FDS) return NULL;
    fd_state_t *s = &g_fds[g_fd_count++];
    memset(s, 0, sizeof(*s));
    s->fd         = fd;
    s->last_dir   = 0xff;  /* sentinel: no previous dir */
    s->session_id = g_next_sid++;
    s->msg_cap    = 64;
    s->msgs       = malloc(s->msg_cap * sizeof(message_t));
    return s;
}

static void fd_append(fd_state_t *s, const uint8_t *data, size_t len, uint64_t ts)
{
    if (s->buf_cap < s->buf_len + len) {
        size_t nc = (s->buf_len + len) * 2;
        if (nc < INIT_BUF) nc = INIT_BUF;
        s->buf = realloc(s->buf, nc);
        s->buf_cap = nc;
    }
    if (s->buf_len == 0) s->buf_ts = ts;
    memcpy(s->buf + s->buf_len, data, len);
    s->buf_len += len;
}

static void fd_flush(fd_state_t *s)
{
    if (!s->buf || s->buf_len == 0) return;
    if (s->msg_count >= s->msg_cap) {
        s->msg_cap *= 2;
        s->msgs = realloc(s->msgs, s->msg_cap * sizeof(message_t));
    }
    message_t *m = &s->msgs[s->msg_count++];
    m->timestamp_us = s->buf_ts;
    m->direction    = s->last_dir;
    m->payload      = s->buf;
    m->payload_len  = s->buf_len;
    m->source       = SOURCE_SYSCALL;
    m->session_id   = s->session_id;

    s->buf     = NULL;
    s->buf_len = 0;
    s->buf_cap = 0;
}

/*
 * Parse the strace string literal starting at *src (just after the opening
 * quote).  Writes decoded bytes into dst[0..dst_cap).  Returns byte count.
 * Advances *src to point past the closing quote (or end of string).
 */
static size_t parse_strace_string(const char **src, uint8_t *dst, size_t dst_cap)
{
    const char *p = *src;
    size_t out = 0;

    while (*p && *p != '"' && out < dst_cap) {
        if (*p == '\\') {
            p++;
            if (*p == 'x' || *p == 'X') {
                p++;
                int hi = (*p >= '0' && *p <= '9') ? *p - '0' :
                         (*p >= 'a' && *p <= 'f') ? *p - 'a' + 10 :
                         (*p >= 'A' && *p <= 'F') ? *p - 'A' + 10 : -1;
                p++;
                int lo = (*p >= '0' && *p <= '9') ? *p - '0' :
                         (*p >= 'a' && *p <= 'f') ? *p - 'a' + 10 :
                         (*p >= 'A' && *p <= 'F') ? *p - 'A' + 10 : -1;
                p++;
                if (hi >= 0 && lo >= 0)
                    dst[out++] = (uint8_t)((hi << 4) | lo);
            } else if (*p == 'n') { dst[out++] = '\n'; p++; }
            else if (*p == 'r')   { dst[out++] = '\r'; p++; }
            else if (*p == 't')   { dst[out++] = '\t'; p++; }
            else if (*p == '0')   { dst[out++] = '\0'; p++; }
            else if (*p == '\\')  { dst[out++] = '\\'; p++; }
            else if (*p == '"')   { dst[out++] = '"';  p++; }
            else { /* unknown escape — keep literal backslash */
                dst[out++] = '\\';
            }
        } else {
            dst[out++] = (uint8_t)*p++;
        }
    }
    if (*p == '"') p++;  /* skip closing quote */
    *src = p;
    return out;
}

/*
 * Expected line format (simplified):
 *   [optional_pid ] [optional_timestamp ] syscall(fd, "...", len[, flags]) = ret
 *
 * We only care about the syscall name, fd number, and string payload.
 */
static void process_line(const char *line, uint8_t scratch[MAX_LINE])
{
    const char *p = line;

    /* Skip optional PID (digits + space). */
    while (isdigit((unsigned char)*p)) p++;
    while (*p == ' ' || *p == '\t') p++;

    /* Skip optional timestamp (digits . digits + space). */
    if (isdigit((unsigned char)*p)) {
        const char *q = p;
        while (isdigit((unsigned char)*q) || *q == '.') q++;
        if (*q == ' ') { p = q + 1; }
    }
    while (*p == ' ' || *p == '\t') p++;

    /* Identify syscall name. */
    const char *sc_start = p;
    while (isalnum((unsigned char)*p) || *p == '_') p++;
    size_t sc_len = (size_t)(p - sc_start);
    if (sc_len == 0) return;

    char sc[32] = {0};
    if (sc_len >= sizeof(sc)) return;
    memcpy(sc, sc_start, sc_len);

    uint8_t dir;
    if (strcmp(sc, "write")   == 0 ||
        strcmp(sc, "send")    == 0 ||
        strcmp(sc, "sendto")  == 0 ||
        strcmp(sc, "sendmsg") == 0)
        dir = 0;
    else if (strcmp(sc, "read")     == 0 ||
             strcmp(sc, "recv")     == 0 ||
             strcmp(sc, "recvfrom") == 0 ||
             strcmp(sc, "recvmsg")  == 0)
        dir = 1;
    else
        return;

    /* Expect '(' */
    if (*p != '(') return;
    p++;

    /* Parse fd argument. */
    char *endp;
    long fd = strtol(p, &endp, 10);
    if (endp == p || fd < 0) return;
    p = endp;

    /* Skip to string literal. */
    while (*p && *p != '"') p++;
    if (*p != '"') return;
    p++;  /* skip opening quote */

    uint64_t ts = 0;  /* TODO: parse timestamp if present */

    fd_state_t *s = get_fd((int)fd);
    if (!s) return;

    /* Flush if direction changed. */
    if (s->last_dir != 0xff && s->last_dir != dir && s->buf_len > 0)
        fd_flush(s);
    s->last_dir = dir;

    size_t nbytes = parse_strace_string(&p, scratch, MAX_LINE);
    if (nbytes > 0)
        fd_append(s, scratch, nbytes, ts);
}

trace_t *ingest_syscall(const char *path)
{
    FILE *f = fopen(path, "r");
    if (!f) { perror(path); return NULL; }

    fds_reset();

    char *line = malloc(MAX_LINE);
    uint8_t *scratch = malloc(MAX_LINE);
    if (!line || !scratch) { free(line); free(scratch); fclose(f); return NULL; }

    while (fgets(line, MAX_LINE, f))
        process_line(line, scratch);

    fclose(f);
    free(line);
    free(scratch);

    /* Flush pending buffers. */
    for (int i = 0; i < g_fd_count; i++)
        fd_flush(&g_fds[i]);

    /* Remove fds with zero messages. */
    int valid = 0;
    for (int i = 0; i < g_fd_count; i++)
        if (g_fds[i].msg_count > 0)
            g_fds[valid++] = g_fds[i];
    g_fd_count = valid;

    if (g_fd_count == 0) return NULL;

    trace_t *trace = malloc(sizeof(*trace));
    if (!trace) return NULL;
    trace->count    = (size_t)g_fd_count;
    trace->sessions = malloc(trace->count * sizeof(session_t));
    if (!trace->sessions) { free(trace); return NULL; }

    for (int i = 0; i < g_fd_count; i++) {
        fd_state_t *s = &g_fds[i];
        trace->sessions[i].session_id = s->session_id;
        trace->sessions[i].messages   = s->msgs;
        trace->sessions[i].count      = s->msg_count;
        /* Don't free msgs — ownership transferred. */
        s->msgs      = NULL;
        s->msg_count = 0;
    }
    fds_reset();

    return trace;
}
