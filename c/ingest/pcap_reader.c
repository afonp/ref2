/*
 * pcap_reader.c — TCP stream reassembly from PCAP files.
 *
 * Reconstructs per-session application-layer payloads by tracking TCP seq
 * numbers.  A small per-stream reorder buffer (REORDER_WINDOW segments)
 * handles out-of-order delivery.  Each contiguous same-direction write is
 * emitted as one message_t; the caller (token layer) applies framing later.
 */

#include "ingest.h"

#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

/* ── Ethernet / IP / TCP header offsets ────────────────────────────────────── */

#define ETH_HDR_LEN  14

/* Minimal IP header (without options). */
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

/* ── Session table ──────────────────────────────────────────────────────────── */

#define MAX_SESSIONS     2048
#define REORDER_WINDOW   16
#define INIT_MSG_CAP     64
#define INIT_BUF_CAP     4096

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
    ooo_seg_t ooo[2][REORDER_WINDOW];
    int       ooo_count[2];

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

/* ── Helpers ────────────────────────────────────────────────────────────────── */

static tcp_stream_t *find_or_alloc(uint32_t sip, uint16_t sp,
                                   uint32_t dip, uint16_t dp,
                                   int *dir_out)
{
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

    if (g_stream_count >= MAX_SESSIONS) return NULL;

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

/* Append bytes to the accumulation buffer for direction dir. */
static void buf_append(tcp_stream_t *s, int dir, const uint8_t *data, size_t len)
{
    if (s->buf_cap[dir] < s->buf_len[dir] + len) {
        size_t nc = (s->buf_len[dir] + len) * 2;
        if (nc < INIT_BUF_CAP) nc = INIT_BUF_CAP;
        s->buf[dir] = realloc(s->buf[dir], nc);
        s->buf_cap[dir] = nc;
    }
    memcpy(s->buf[dir] + s->buf_len[dir], data, len);
    s->buf_len[dir] += len;
}

/* Flush the current accumulation buffer as a completed message. */
static void buf_flush(tcp_stream_t *s, int dir)
{
    if (!s->buf[dir] || s->buf_len[dir] == 0) return;

    if (s->msg_count >= s->msg_cap) {
        s->msg_cap *= 2;
        s->msgs = realloc(s->msgs, s->msg_cap * sizeof(message_t));
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
}

/* Try to drain any out-of-order segments that are now in sequence. */
static void ooo_drain(tcp_stream_t *s, int dir)
{
    int found;
    do {
        found = 0;
        for (int i = 0; i < s->ooo_count[dir]; i++) {
            ooo_seg_t *seg = &s->ooo[dir][i];
            if (seg->seq == s->next_seq[dir]) {
                buf_append(s, dir, seg->data, seg->len);
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

/* ── Libpcap callback ───────────────────────────────────────────────────────── */

static void pkt_handler(u_char *user, const struct pcap_pkthdr *hdr,
                         const u_char *pkt)
{
    (void)user;

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
        buf_flush(s, s->last_dir);

    if (!s->seq_init[dir]) {
        /* First data packet without having seen a SYN; bootstrap seq. */
        s->next_seq[dir] = seq;
        s->seq_init[dir] = 1;
    }

    if (seq == s->next_seq[dir]) {
        if (s->buf_len[dir] == 0) s->buf_ts[dir] = ts;
        buf_append(s, dir, payload, payload_len);
        s->next_seq[dir] += (uint32_t)payload_len;
        ooo_drain(s, dir);
        buf_flush(s, dir);
    } else if ((int32_t)(seq - s->next_seq[dir]) > 0) {
        /* Future segment: store in reorder buffer. */
        if (s->ooo_count[dir] < REORDER_WINDOW) {
            ooo_seg_t *seg = &s->ooo[dir][s->ooo_count[dir]++];
            seg->seq  = seq;
            seg->len  = payload_len;
            seg->data = malloc(payload_len);
            if (seg->data) memcpy(seg->data, payload, payload_len);
        }
        /* else: drop — window exceeded */
    }
    /* else: duplicate / retransmit, ignore */
}

/* ── Public API ─────────────────────────────────────────────────────────────── */

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

    pcap_loop(pcap, 0, pkt_handler, NULL);
    pcap_close(pcap);

    /* Build trace. */
    trace_t *trace = malloc(sizeof(*trace));
    if (!trace) return NULL;

    trace->count    = (size_t)g_stream_count;
    trace->sessions = malloc(trace->count * sizeof(session_t));
    if (!trace->sessions) { free(trace); return NULL; }

    for (int i = 0; i < g_stream_count; i++) {
        tcp_stream_t *s = g_streams[i];
        /* Flush any pending last direction. */
        for (int d = 0; d < 2; d++) buf_flush(s, d);

        trace->sessions[i].session_id = s->session_id;
        trace->sessions[i].messages   = s->msgs;
        trace->sessions[i].count      = s->msg_count;

        free(s->buf[0]); free(s->buf[1]);
        free(s);
        g_streams[i] = NULL;
    }
    g_stream_count = 0;

    return trace;
}
