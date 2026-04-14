/*
 * pcap_reader.c — TCP stream reassembly from PCAP files.
 *
 * Reconstructs per-session application-layer payloads by tracking TCP seq
 * numbers.  A small per-stream reorder buffer (REORDER_WINDOW segments)
 * handles out-of-order delivery.  Each contiguous same-direction write is
 * emitted as one message_t; the caller (token layer) applies framing later.
 */

#define _DEFAULT_SOURCE
#include "ingest.h"
#include <sys/types.h>
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <arpa/inet.h>

#define ETH_HDR_LEN  14

typedef struct {
    uint8_t  ver_ihl;
    uint8_t  tos;
    uint16_t tot_len;
    uint16_t id;
    uint16_t frag_off;
    uint8_t  ttl;
    uint8_t  protocol;
    uint16_t check;
    uint32_t saddr;
    uint32_t daddr;
} r2_iphdr_t;

typedef struct {
    uint8_t  ver_tc_fl[4];   /* version(4) + traffic class(8) + flow label(20) */
    uint16_t payload_len;
    uint8_t  next_hdr;
    uint8_t  hop_limit;
    uint8_t  src[16];
    uint8_t  dst[16];
} r2_ip6hdr_t;

/* Minimal TCP header. */
typedef struct {
    uint16_t source;
    uint16_t dest;
    uint32_t seq;
    uint32_t ack_seq;
    uint16_t flags;   /* data offset in high 4 bits, flags in low 9 */
    uint16_t window;
    uint16_t check;
    uint16_t urg_ptr;
} r2_tcphdr_t;

#define TCP_DOFF(f)   (((f) >> 12) & 0x0f)
#define TCP_FLAG_SYN  0x002
#define TCP_FLAG_ACK  0x010
#define TCP_FLAG_FIN  0x001
#define TCP_FLAG_RST  0x004
#define IPPROTO_TCP   6

#define MAX_SESSIONS     2048
#define INIT_MSG_CAP     64
#define INIT_BUF_CAP     4096
#define INIT_OOO_CAP     32

typedef struct {
    uint32_t seq;
    uint8_t *data;
    size_t   len;
} ooo_seg_t;   /* out-of-order segment */

typedef struct {
    /* 4-tuple (normalised: smaller addr/port = side 0) */
    uint32_t addr[2];
    uint16_t port[2];

    uint32_t next_seq[2];      /* expected next byte for each direction */
    int      seq_init[2];      /* have we seen the first segment? */

    /* pending accumulation buffer (current in-flight message bytes) */
    uint8_t *buf[2];
    size_t   buf_len[2];
    size_t   buf_cap[2];
    uint64_t buf_ts[2];        /* timestamp of first byte in current buffer */

    /* out-of-order backlog */
    ooo_seg_t *ooo[2];
    size_t     ooo_count[2];
    size_t     ooo_cap[2];

    /* completed messages */
    message_t *msgs;
    size_t     msg_count;
    size_t     msg_cap;

    uint32_t   session_id;
    int        last_dir;       /* direction of last flushed message */
} tcp_stream_t;

static tcp_stream_t *g_streams[MAX_SESSIONS];
static int           g_stream_count;
static uint32_t      g_next_sid;

typedef enum {
    INGEST_OK = 0,
    INGEST_ERR_OOM,
    INGEST_ERR_TOO_MANY_SESSIONS,
} ingest_error_t;

static ingest_error_t g_ingest_error;

static int checked_add_size(size_t a, size_t b, size_t *out)
{
    if (a > SIZE_MAX - b) return 0;
    *out = a + b;
    return 1;
}

static int checked_mul_size(size_t a, size_t b, size_t *out)
{
    if (a != 0 && b > SIZE_MAX / a) return 0;
    *out = a * b;
    return 1;
}

static void set_ingest_error(ingest_error_t err)
{
    if (g_ingest_error == INGEST_OK) g_ingest_error = err;
}

static tcp_stream_t *find_or_alloc(uint32_t sip, uint16_t sp,
                                   uint32_t dip, uint16_t dp,
                                   int *dir_out)
{
    if (g_ingest_error != INGEST_OK) return NULL;

    /* Normalise so addr[0] <= addr[1] (or same addr, port[0] <= port[1]). */
    int flip = (sip > dip) || (sip == dip && sp > dp);
    uint32_t a0 = flip ? dip : sip,  a1 = flip ? sip : dip;
    uint16_t p0 = flip ? dp  : sp,   p1 = flip ? sp  : dp;

    /* TODO: hash table if MAX_SESSIONS gets large */
    for (int i = 0; i < g_stream_count; i++) {
        tcp_stream_t *s = g_streams[i];
        if (s->addr[0] == a0 && s->addr[1] == a1 &&
            s->port[0] == p0 && s->port[1] == p1) {
            *dir_out = flip ? 1 : 0;
            return s;
        }
    }

    if (g_stream_count >= MAX_SESSIONS) {
        set_ingest_error(INGEST_ERR_TOO_MANY_SESSIONS);
        return NULL;
    }

    tcp_stream_t *s = calloc(1, sizeof(*s));
    if (!s) return NULL;

    s->addr[0] = a0; s->addr[1] = a1;
    s->port[0] = p0; s->port[1] = p1;
    s->session_id = g_next_sid++;
    s->last_dir   = -1;

    s->msg_cap = INIT_MSG_CAP;
    s->msgs    = malloc(s->msg_cap * sizeof(message_t));
    if (!s->msgs) { free(s); return NULL; }

    g_streams[g_stream_count++] = s;
    *dir_out = flip ? 1 : 0;
    return s;
}

/* Append bytes to the accumulation buffer for direction dir.
   Returns 0 on success, -1 on allocation/overflow failure. */
static int buf_append(tcp_stream_t *s, int dir, const uint8_t *data, size_t len)
{
    size_t needed;
    if (!checked_add_size(s->buf_len[dir], len, &needed)) {
        set_ingest_error(INGEST_ERR_OOM);
        return -1;
    }

    if (s->buf_cap[dir] < needed) {
        size_t nc;
        if (!checked_mul_size(needed, 2, &nc)) {
            set_ingest_error(INGEST_ERR_OOM);
            return -1;
        }
        if (nc < INIT_BUF_CAP) nc = INIT_BUF_CAP;

        uint8_t *new_buf = realloc(s->buf[dir], nc);
        if (!new_buf) {
            set_ingest_error(INGEST_ERR_OOM);
            return -1;
        }

        s->buf[dir] = new_buf;
        s->buf_cap[dir] = nc;
    }

    memcpy(s->buf[dir] + s->buf_len[dir], data, len);
    s->buf_len[dir] += len;
    return 0;
}

/* Flush the current accumulation buffer as a completed message.
   Returns 0 on success, -1 on allocation/overflow failure. */
static int buf_flush(tcp_stream_t *s, int dir)
{
    if (!s->buf[dir] || s->buf_len[dir] == 0) return 0;

    if (s->msg_count >= s->msg_cap) {
        size_t new_cap;
        size_t bytes;
        if (!checked_mul_size(s->msg_cap, 2, &new_cap) ||
            !checked_mul_size(new_cap, sizeof(message_t), &bytes)) {
            set_ingest_error(INGEST_ERR_OOM);
            return -1;
        }

        message_t *new_msgs = realloc(s->msgs, bytes);
        if (!new_msgs) {
            set_ingest_error(INGEST_ERR_OOM);
            return -1;
        }

        s->msg_cap = new_cap;
        s->msgs = new_msgs;
    }

    message_t *m = &s->msgs[s->msg_count++];
    m->timestamp_us = s->buf_ts[dir];
    m->direction    = (uint8_t)dir;
    m->payload      = s->buf[dir];
    m->payload_len  = s->buf_len[dir];
    m->source       = SOURCE_PCAP;
    m->session_id   = s->session_id;

    /* Buffer ownership transferred to message. */
    s->buf[dir]     = NULL;
    s->buf_len[dir] = 0;
    s->buf_cap[dir] = 0;
    s->last_dir     = dir;
    return 0;
}

static int ooo_store(tcp_stream_t *s, int dir, uint32_t seq,
                     const uint8_t *payload, size_t payload_len)
{
    if (s->ooo_count[dir] >= s->ooo_cap[dir]) {
        size_t new_cap = s->ooo_cap[dir] ? s->ooo_cap[dir] * 2 : INIT_OOO_CAP;
        size_t bytes;
        if (!checked_mul_size(new_cap, sizeof(ooo_seg_t), &bytes)) {
            set_ingest_error(INGEST_ERR_OOM);
            return -1;
        }
        ooo_seg_t *grown = realloc(s->ooo[dir], bytes);
        if (!grown) {
            set_ingest_error(INGEST_ERR_OOM);
            return -1;
        }
        s->ooo[dir] = grown;
        s->ooo_cap[dir] = new_cap;
    }

    ooo_seg_t *seg = &s->ooo[dir][s->ooo_count[dir]++];
    seg->seq = seq;
    seg->len = payload_len;
    seg->data = malloc(payload_len);
    if (!seg->data) {
        s->ooo_count[dir]--;
        set_ingest_error(INGEST_ERR_OOM);
        return -1;
    }
    memcpy(seg->data, payload, payload_len);
    return 0;
}

/* Try to drain any out-of-order segments that are now in sequence. */
static void ooo_drain(tcp_stream_t *s, int dir)
{
    int found;
    do {
        found = 0;
        for (size_t i = 0; i < s->ooo_count[dir]; i++) {
            ooo_seg_t *seg = &s->ooo[dir][i];
            if (seg->seq == s->next_seq[dir]) {
                if (buf_append(s, dir, seg->data, seg->len) != 0) {
                    free(seg->data);
                    return;
                }
                s->next_seq[dir] += (uint32_t)seg->len;
                free(seg->data);
                /* Remove from backlog. */
                s->ooo[dir][i] = s->ooo[dir][--s->ooo_count[dir]];
                found = 1;
                break;
            }
        }
    } while (found);
}

static void pkt_handler(u_char *user, const struct pcap_pkthdr *hdr,
                         const u_char *pkt)
{
    (void)user;

    if (g_ingest_error != INGEST_OK) return;

    size_t cap = hdr->caplen;
    if (cap < ETH_HDR_LEN + 1) return;

    const uint8_t *l3 = pkt + ETH_HDR_LEN;
    int version = (*l3) >> 4;

    const uint8_t *tcp_ptr;
    uint32_t sip, dip;

    if (version == 4) {
        if (cap < ETH_HDR_LEN + sizeof(r2_iphdr_t)) return;
        const r2_iphdr_t *ip = (const r2_iphdr_t *)l3;
        if (ip->protocol != IPPROTO_TCP) return;
        int ip_hlen = (ip->ver_ihl & 0x0f) * 4;
        tcp_ptr = l3 + ip_hlen;
        sip = ntohl(ip->saddr);
        dip = ntohl(ip->daddr);
    } else if (version == 6) {
        if (cap < ETH_HDR_LEN + sizeof(r2_ip6hdr_t)) return;
        const r2_ip6hdr_t *ip6 = (const r2_ip6hdr_t *)l3;
        if (ip6->next_hdr != IPPROTO_TCP) return;
        tcp_ptr = l3 + sizeof(r2_ip6hdr_t);
        /* good enough for flow tracking, collisions are fine */
        uint32_t *s6 = (uint32_t *)ip6->src;
        uint32_t *d6 = (uint32_t *)ip6->dst;
        sip = s6[0] ^ s6[1] ^ s6[2] ^ s6[3];
        dip = d6[0] ^ d6[1] ^ d6[2] ^ d6[3];
    } else {
        return;
    }

    if ((size_t)(tcp_ptr - pkt) + sizeof(r2_tcphdr_t) > cap) return;

    const r2_tcphdr_t *tcp = (const r2_tcphdr_t *)tcp_ptr;
    int tcp_hlen = TCP_DOFF(ntohs(tcp->flags)) * 4;
    if (tcp_hlen < 20) return;

    const uint8_t *payload     = tcp_ptr + tcp_hlen;
    size_t         payload_len = cap - (size_t)(payload - pkt);
    if (payload_len == 0 && !(ntohs(tcp->flags) & (TCP_FLAG_SYN | TCP_FLAG_FIN)))
        return;

    uint16_t sp  = ntohs(tcp->source);
    uint16_t dp  = ntohs(tcp->dest);
    uint32_t seq = ntohl(tcp->seq);
    uint64_t ts  = (uint64_t)hdr->ts.tv_sec * 1000000ULL + hdr->ts.tv_usec;
    uint16_t fl  = ntohs(tcp->flags);

    int dir;
    tcp_stream_t *s = find_or_alloc(sip, sp, dip, dp, &dir);
    if (!s) return;

    /* SYN: record starting sequence number. */
    if ((fl & TCP_FLAG_SYN) && !(fl & TCP_FLAG_ACK)) {
        s->next_seq[dir] = seq + 1;
        s->seq_init[dir] = 1;
        return;
    }

    if (payload_len == 0) return;

    /* Flush if direction changed — new logical message. */
    if (s->last_dir != -1 && s->last_dir != dir && s->buf_len[s->last_dir] > 0)
        if (buf_flush(s, s->last_dir) != 0) return;

    if (!s->seq_init[dir]) {
        /* First data packet without having seen a SYN; bootstrap seq. */
        s->next_seq[dir] = seq;
        s->seq_init[dir] = 1;
    }

    if (seq == s->next_seq[dir]) {
        if (s->buf_len[dir] == 0) s->buf_ts[dir] = ts;
        if (buf_append(s, dir, payload, payload_len) != 0) return;
        s->next_seq[dir] += (uint32_t)payload_len;
        ooo_drain(s, dir);
        if (buf_flush(s, dir) != 0) return;
    } else if ((int32_t)(seq - s->next_seq[dir]) > 0) {
        /* Future segment: store in reorder buffer. */
        if (ooo_store(s, dir, seq, payload, payload_len) != 0) return;
    }
    /* else: duplicate / retransmit, ignore */
}

trace_t *ingest_pcap(const char *path)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *pcap = pcap_open_offline(path, errbuf);
    if (!pcap) {
        fprintf(stderr, "ref2: pcap_open_offline(%s): %s\n", path, errbuf);
        return NULL;
    }

    /* Reset global state. */
    for (int i = 0; i < g_stream_count; i++) {
        tcp_stream_t *s = g_streams[i];
        for (int d = 0; d < 2; d++) {
            free(s->buf[d]);
            for (int j = 0; j < s->ooo_count[d]; j++)
                free(s->ooo[d][j].data);
        }
        /* msgs ownership will transfer to trace */
        free(s);
        g_streams[i] = NULL;
    }
    g_stream_count = 0;
    g_next_sid     = 1;
    g_ingest_error = INGEST_OK;

    pcap_loop(pcap, 0, pkt_handler, NULL);
    pcap_close(pcap);

    if (g_ingest_error != INGEST_OK) {
        for (int i = 0; i < g_stream_count; i++) {
            tcp_stream_t *s = g_streams[i];
            if (!s) continue;
            for (int d = 0; d < 2; d++) {
                free(s->buf[d]);
                for (size_t j = 0; j < s->ooo_count[d]; j++)
                    free(s->ooo[d][j].data);
                free(s->ooo[d]);
            }
            for (size_t m = 0; m < s->msg_count; m++)
                free(s->msgs[m].payload);
            free(s->msgs);
            free(s);
            g_streams[i] = NULL;
        }
        g_stream_count = 0;
        if (g_ingest_error == INGEST_ERR_TOO_MANY_SESSIONS) {
            fprintf(stderr,
                    "ref2: ingest_pcap failed: too many concurrent sessions "
                    "(max %d)\n",
                    MAX_SESSIONS);
        } else {
            fprintf(stderr, "ref2: ingest_pcap failed: insufficient memory\n");
        }
        return NULL;
    }

    /* Build trace. */
    trace_t *trace = malloc(sizeof(*trace));
    if (!trace) return NULL;

    trace->count    = (size_t)g_stream_count;
    size_t sessions_bytes;
    if (!checked_mul_size(trace->count, sizeof(session_t), &sessions_bytes)) {
        free(trace);
        return NULL;
    }
    trace->sessions = malloc(sessions_bytes);
    if (!trace->sessions) { free(trace); return NULL; }

    for (int i = 0; i < g_stream_count; i++) {
        tcp_stream_t *s = g_streams[i];
        /* Flush any pending last direction. */
        for (int d = 0; d < 2; d++) {
            if (buf_flush(s, d) != 0) {
                for (int j = i; j < g_stream_count; j++) {
                    tcp_stream_t *sj = g_streams[j];
                    if (!sj) continue;
                    for (int dd = 0; dd < 2; dd++) {
                        free(sj->buf[dd]);
                        for (size_t k = 0; k < sj->ooo_count[dd]; k++)
                            free(sj->ooo[dd][k].data);
                        free(sj->ooo[dd]);
                    }
                    for (size_t m = 0; m < sj->msg_count; m++)
                        free(sj->msgs[m].payload);
                    free(sj->msgs);
                    free(sj);
                    g_streams[j] = NULL;
                }
                trace_free(trace);
                g_stream_count = 0;
                fprintf(stderr, "ref2: ingest_pcap failed while finalising sessions\n");
                return NULL;
            }
        }

        trace->sessions[i].session_id = s->session_id;
        trace->sessions[i].messages   = s->msgs;
        trace->sessions[i].count      = s->msg_count;

        free(s->buf[0]); free(s->buf[1]);
        free(s->ooo[0]); free(s->ooo[1]);
        free(s);
        g_streams[i] = NULL;
    }
    g_stream_count = 0;

    return trace;
}
