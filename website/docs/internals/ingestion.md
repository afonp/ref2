---
sidebar_position: 2
---

# phase 1 — ingestion

**source:** `c/ingest/`
**output type:** `trace_t`

the ingestion layer normalises four very different input formats into a single `trace_t` struct: an array of sessions, each containing an ordered array of `message_t` payloads.

```c
typedef struct {
    uint64_t  timestamp_us;
    uint8_t   direction;    /* 0 = client→server, 1 = server→client */
    uint8_t  *payload;
    size_t    payload_len;
    source_t  source;
    uint32_t  session_id;
} message_t;
```

---

## pcap ingestion (`pcap_reader.c`)

reads a pcap file using libpcap. reconstructs tcp streams from raw ethernet/ip/tcp frames.

**stream normalisation:** a 4-tuple `(src_ip, src_port, dst_ip, dst_port)` is normalised to a canonical form (smaller addr:port = side 0) so that packets from both directions land on the same stream.

**direction assignment:** based on which endpoint is "side 0" vs "side 1" after normalisation.

**reorder buffer:** a 16-slot per-stream per-direction buffer holds out-of-order segments until the gap is filled. segments beyond the window are dropped.

**message boundaries:** each contiguous write that arrives in order is flushed as one `message_t`. the token layer applies proper framing boundaries afterwards.

**ipv4 only:** ipv6 is not yet supported. only tcp is reconstructed; udp payloads are not reassembled (though individual datagrams can be added in future).

---

## raw binary ingestion (`raw_reader.c`)

reads a flat binary file as a single session. if no frame hint is provided, the entire file becomes one `message_t`. if a hint is provided, the file is sliced according to it:

- **`FRAME_FIXED_HEADER`** — fixed number of header bytes followed by payload; splits at each header
- **`FRAME_LENGTH_FIELD`** — reads a 1/2/4-byte integer at a given offset to determine message length; slices accordingly
- **`FRAME_DELIMITER`** — splits on a 1–4 byte delimiter pattern (e.g. `\r\n`)

---

## plaintext ingestion (`plaintext_reader.c`)

auto-detects one of three formats by scanning the first 20 lines:

### direction-prefixed

```
>> 48454c4c4f0d0a
<< 2b4f4b0d0a
```

or with ascii:

```
>> EHLO example.com
<< 250 OK
```

payloads are hex-decoded if fewer than 80% of characters are printable ascii. timestamps in iso8601 or unix epoch format are stripped automatically.

### wireshark hex dump

output of wireshark's "follow tcp stream → hex dump" view:

```
00000000  48 45 4c 4c 4f 0d 0a                             HELLO..
```

direction is inferred from `===` / `---` section separators in the export.

### plain lines

fallback: one message per line. no direction info (all assigned direction 0).

---

## syscall trace ingestion (`syscall_reader.c`)

parses strace output produced by:

```bash
strace -e trace=read,write,send,recv,sendto,recvfrom -xx -o trace.log <cmd>
```

**parsing:** extracts the syscall name, file descriptor, and string argument. the `-xx` flag causes strace to emit all characters as `\xNN` hex escapes, which are decoded byte by byte.

**direction mapping:**

| syscall | direction |
|---|---|
| `write`, `send`, `sendto`, `sendmsg` | 0 (client → server) |
| `read`, `recv`, `recvfrom`, `recvmsg` | 1 (server → client) |

**stream grouping:** each file descriptor becomes its own session. consecutive same-direction syscalls on the same fd are concatenated before being emitted as one `message_t`.

**partial reads:** handled naturally by the concatenation logic.

---

## memory model

all `payload` bytes in `message_t` are heap-allocated by the ingestion layer. ownership transfers to the `session_t` / `trace_t` hierarchy. the caller frees the entire tree with `trace_free()`.
