---
id: intro
slug: /
sidebar_position: 1
---

# ref2

**ref2** is a tool for automatically inferring the grammar and message format of unknown network protocols from packet captures, binary dumps, plaintext logs, or strace output — without any prior knowledge of the protocol.

given a trace, ref2 produces:

- a **message schema** — named fields with inferred types (magic bytes, length fields, enums, nonces, payloads, etc.)
- a **finite-state machine** describing the protocol's conversation grammar
- output in **json**, **graphviz dot**, and **scapy dissector** formats

---

## what problem does it solve?

reverse-engineering network protocols is slow. opening a pcap in wireshark and manually identifying field boundaries, type discriminators, and state machines takes hours or days. ref2 does the first-pass analysis automatically, giving you a structured starting point in seconds.

typical use cases:

- **iot device analysis** — identify what a device sends home before writing firewall rules
- **malware c2 fingerprinting** — extract message structure from captured c2 traffic
- **fuzzing target prep** — generate a scapy dissector to feed a protocol fuzzer
- **protocol documentation** — produce a structured schema from undocumented internal services

---

## how it works (30-second version)

```
pcap / binary / plaintext / strace
         │
         ▼
   [ ingestion ]      reconstruct tcp streams / parse text
         │
         ▼
   [ framing ]        find message boundaries (length field / delimiter)
         │
         ▼
   [ alignment ]      needleman-wunsch across all messages per type cluster
         │
         ▼
   [ classification ] label each field: magic, length, enum, nonce, …
         │
         ▼
   [ grammar ]        k-tails or rpni → finite-state machine
         │
         ▼
   json schema  ·  dot fsm  ·  scapy dissector
```

---

## quick example

```bash
ref2 infer --input capture.pcap --format pcap
```

output in `./ref2_output/`:

```
ref2_output/
├── schema.json      # field-level protocol description
├── fsm.dot          # graphviz state machine
└── dissector.py     # scapy packet class
```

→ see [quickstart](getting-started/quickstart) for a full walkthrough.
