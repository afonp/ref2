---
sidebar_position: 2
---

# quickstart

this walkthrough takes you from a raw pcap to a scapy dissector in under two minutes.

---

## example 1 — pcap capture

grab any pcap (dns traffic works great as a known-ground-truth test):

```bash
ref2 infer --input dns.pcap --format pcap
```

sample output:

```
ref2: ingesting "dns.pcap"
ref2: 47 session(s)
ref2: inferring format…
ref2: 4 message type(s) inferred
ref2: running KTails (k=2)…
ref2: 6 state(s), 8 transition(s)
ref2: wrote ref2_output/schema.json
ref2: wrote ref2_output/fsm.dot
ref2: render with: dot -Tsvg ref2_output/fsm.dot -o ref2_output/fsm.svg
ref2: wrote ref2_output/dissector.py
ref2: done → ref2_output/
```

---

## example 2 — strace log

capture a process's socket writes with strace and feed it directly to ref2:

```bash
strace -e trace=read,write,send,recv,sendto,recvfrom -xx \
       -o trace.log \
       curl -s http://example.com

ref2 infer --input trace.log --format syscall --algo rpni
```

:::tip
use `--algo rpni` when you have ≥ 20 sessions — it's more accurate than k-tails for well-sampled protocols.
:::

---

## example 3 — raw binary dump with a frame hint

if you have a binary stream where you know the framing (e.g. a 2-byte big-endian length field at offset 0):

```bash
ref2 infer \
  --input dump.bin \
  --format raw \
  --frame-hint "length_u16_be@offset=0"
```

supported frame hint syntax:

| pattern | meaning |
|---|---|
| `length_u8_be@offset=N` | 1-byte big-endian length at offset N |
| `length_u16_be@offset=N` | 2-byte big-endian length at offset N |
| `length_u16_le@offset=N` | 2-byte little-endian length at offset N |
| `length_u32_be@offset=N` | 4-byte big-endian length at offset N |
| `delim:\r\n` | crlf-delimited messages |
| `delim:\n` | newline-delimited messages |

---

## example 4 — plaintext direction log

ref2 understands the `>>` / `<<` direction-prefixed format commonly used when pasting captured exchanges:

```
>> 48454c4c4f0d0a
<< 2b4f4b0d0a
>> 47455420 2f20485454502f312e310d0a
```

or with ascii payload:

```
>> HELO mailserver.example.com
<< 250 OK
>> MAIL FROM:<user@example.com>
<< 250 OK
```

```bash
ref2 infer --input exchange.txt --format plaintext
```

---

## viewing the fsm

render and open the state machine diagram:

```bash
dot -Tsvg ref2_output/fsm.dot -o ref2_output/fsm.svg
open ref2_output/fsm.svg      # macos
xdg-open ref2_output/fsm.svg  # linux
```

or use the built-in shortcut:

```bash
ref2 view ref2_output/fsm.dot
```

---

## using the scapy dissector

the generated `dissector.py` is a drop-in scapy packet class:

```python
from scapy.all import *
exec(open('ref2_output/dissector.py').read())

# parse a raw bytes object
pkt = MsgType00(b'\xde\xad\x00\x0f\x01hello world\x00')
pkt.show()
```

---

## selecting output formats

use `--emit` to control which files are written:

```bash
ref2 infer --input capture.pcap --format pcap --emit json    # json only
ref2 infer --input capture.pcap --format pcap --emit dot     # dot only
ref2 infer --input capture.pcap --format pcap --emit scapy   # python only
ref2 infer --input capture.pcap --format pcap --emit all     # everything (default)
```
