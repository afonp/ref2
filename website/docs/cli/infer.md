---
sidebar_position: 1
---

# ref2 infer

infer a protocol schema and fsm from a network trace or log file.

## synopsis

```
ref2 infer --input <path> --format <format> [options]
```

## required flags

| flag | description |
|---|---|
| `--input <path>` | path to the input file |
| `--format <format>` | input format: `pcap`, `raw`, `plaintext`, or `syscall` |

## options

| flag | default | description |
|---|---|---|
| `--output-dir <path>` | `./ref2_output` | directory to write output files |
| `--frame-hint <spec>` | — | framing hint for `raw` format (see below) |
| `--k <int>` | `2` | k-tails depth — how many future steps to compare when merging states |
| `--algo <algo>` | `ktails` | grammar induction algorithm: `ktails` or `rpni` |
| `--min-sessions <int>` | `5` | minimum number of sessions required to run grammar induction |
| `--endian <hint>` | `auto` | endianness hint for integer fields: `auto`, `le`, `be` |
| `--emit <formats>` | `all` | output formats: `json`, `dot`, `scapy`, or `all` |
| `--cluster <strategy>` | `auto` | message clustering: `auto`, `type-field`, or `kmeans` |

---

## formats

### `pcap`

reads a libpcap-format capture file. reconstructs tcp streams from raw packets, extracts application-layer payloads, and assigns directions based on which side initiated the connection.

```bash
ref2 infer --input capture.pcap --format pcap
```

requires `libpcap` at build time.

### `raw`

reads a raw binary file as a single session. without `--frame-hint`, the entire file is treated as one message and framing is inferred automatically by the token layer.

```bash
# auto-framing
ref2 infer --input dump.bin --format raw

# with hint
ref2 infer --input dump.bin --format raw --frame-hint "length_u16_be@offset=2"
```

### `plaintext`

auto-detects the text format:

- **direction-prefixed** — lines starting with `>> ` (client) or `<< ` (server)
- **wireshark follow tcp stream** — hex offset lines like `00000000  de ad be ef ...`
- **plain lines** — one message per line, no direction info

payloads are interpreted as ascii if >80% bytes are printable, otherwise decoded as hex.

```bash
ref2 infer --input exchange.txt --format plaintext
```

### `syscall`

parses `strace` output. groups syscalls by file descriptor — each fd becomes a session. direction is inferred from the syscall name (`write`/`send` → client, `read`/`recv` → server).

expects strace output generated with:
```bash
strace -e trace=read,write,send,recv,sendto,recvfrom -xx -o trace.log <cmd>
```

```bash
ref2 infer --input trace.log --format syscall
```

---

## `--frame-hint` syntax

only used with `--format raw`. ignored for other formats.

```
length_u<bits>_<endian>@offset=<n>
```

examples:

```bash
--frame-hint "length_u8_be@offset=1"    # 1-byte length at offset 1
--frame-hint "length_u16_le@offset=0"   # 2-byte little-endian length at byte 0
--frame-hint "length_u32_be@offset=4"   # 4-byte big-endian length at offset 4
--frame-hint "delim:\n"                 # newline-terminated messages
--frame-hint "delim:\r\n"               # crlf-terminated messages
```

---

## `--algo` details

### `ktails` (default)

builds a prefix tree acceptor from all session sequences, then merges states whose sets of k-length future suffixes are identical. fast, works with as few as 5 sessions.

increase `--k` for more precise grammars at the cost of fewer merges (larger fsm):

```bash
ref2 infer --input trace.pcap --format pcap --k 3
```

### `rpni`

blue-fringe state merging — more accurate than k-tails when you have ≥ 20 sessions. slower. does not use `--k`.

```bash
ref2 infer --input trace.pcap --format pcap --algo rpni
```

---

## anomaly scoring

after grammar induction, ref2 scores each session against the inferred fsm using viterbi log-probability. sessions with unknown transitions receive a score of 1.0.

anomalous sessions (score > 0.5) are reported to stderr:

```
ref2: 2 anomalous session(s) detected:
  session 3: anomaly_score=1.000
  session 11: anomaly_score=0.812
```

---

## examples

```bash
# basic pcap inference, all outputs
ref2 infer --input capture.pcap --format pcap

# strace log, rpni, json only
ref2 infer --input trace.log --format syscall --algo rpni --emit json

# raw binary with explicit framing
ref2 infer --input dump.bin --format raw --frame-hint "length_u16_be@offset=2"

# plaintext with rpni and higher k
ref2 infer --input chat.txt --format plaintext --algo rpni --k 3 --min-sessions 10

# custom output directory
ref2 infer --input caps/ --format pcap --output-dir ./analysis/myproto
```
