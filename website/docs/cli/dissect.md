---
sidebar_position: 2
---

# ref2 dissect

apply a previously inferred schema to a new capture to label and decode messages.

## synopsis

```
ref2 dissect --schema <dir> --input <path>
```

## flags

| flag | description |
|---|---|
| `--schema <dir>` | path to the output directory from a previous `ref2 infer` run (must contain `schema.json`) |
| `--input <path>` | new input file to dissect |

## description

`dissect` loads the `schema.json` produced by a prior `infer` run and uses it as a decoder for a new input file. messages are matched against known message types, fields are extracted, and the session's trace through the inferred fsm is reported.

:::note
`dissect` is not yet fully implemented in this release. use the generated scapy dissector (`dissector.py`) as an alternative — it provides equivalent per-packet decoding within python.
:::

## alternative: scapy dissector

the `dissector.py` output from `ref2 infer` is a fully functional scapy packet class:

```python
from scapy.all import *
exec(open('ref2_output/dissector.py').read())

# decode a single message
raw = b'\x00\x01\x02\x03\x00\x0a\x01hello wrl'
pkt = MsgType00(raw)
pkt.show()

# decode from pcap
pkts = rdpcap('new_capture.pcap')
for pkt in pkts:
    if Raw in pkt:
        decoded = MsgType00(bytes(pkt[Raw]))
        decoded.show()
```
