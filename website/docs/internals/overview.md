---
sidebar_position: 1
---

# pipeline overview

ref2 is a six-phase pipeline. each phase has a clean input/output contract and can be tested independently.

```
┌──────────────────────────────────────────────────────────────────┐
│                           ref2 pipeline                          │
│                                                                  │
│  input file                                                      │
│      │                                                           │
│      ▼                                                           │
│  ┌──────────┐   trace_t                                          │
│  │ phase 1  │ ──────────►  session_t[]  message_t[]             │
│  │ ingest   │             (normalised payloads, timestamps,      │
│  └──────────┘              directions, session ids)              │
│      │                                                           │
│      ▼                                                           │
│  ┌──────────┐   framing_info_t + token_stream_t[]               │
│  │ phase 2  │ ──────────►  message boundaries, type hints,      │
│  │ tokenise │             header length, length field location   │
│  └──────────┘                                                    │
│      │                                                           │
│      ▼                                                           │
│  ┌──────────┐   protocol_schema_t                               │
│  │ phase 3  │ ──────────►  per-type field schemas               │
│  │ format   │             (offset, length, type, entropy)        │
│  └──────────┘                                                    │
│      │                                                           │
│      ▼                                                           │
│  ┌──────────┐   Fsm                                             │
│  │ phase 4  │ ──────────►  states + transitions + frequencies   │
│  │ grammar  │             + per-session anomaly scores           │
│  └──────────┘                                                    │
│      │                                                           │
│      ▼                                                           │
│  ┌──────────┐                                                    │
│  │ phase 5  │ ──────────►  schema.json  fsm.dot  dissector.py  │
│  │ output   │                                                    │
│  └──────────┘                                                    │
└──────────────────────────────────────────────────────────────────┘
```

## layer boundaries

| phase | language | library | input | output |
|---|---|---|---|---|
| 1 — ingest | c | `libref2_ingest.a` | file path | `trace_t` |
| 2 — tokenise | c | `libref2_token.a` | `trace_t` | `token_stream_t[]` + `framing_info_t` |
| 3 — format | c | `libref2_format.a` | `token_stream_t[]` | `protocol_schema_t` |
| 4 — grammar | rust | `ref2_grammar` | `Vec<Vec<u32>>` (type sequences) | `Fsm` |
| 5 — output | rust | `ref2_output` | `Fsm` + `protocol_schema_t` | files |
| 6 — cli | rust | `ref2` binary | args | invokes phases 1–5 |

phases 1–3 are compiled to a single static library (`libref2.a`) and called from rust via ffi. phases 4–6 are pure rust.

## data flow details

### phase 1 → phase 2

`trace_t` is an array of `session_t`, each containing an array of `message_t`. each `message_t` has a raw payload, timestamp, direction, and source type. at this point message boundaries may be at tcp packet boundaries (not protocol message boundaries).

### phase 2 → phase 3

`framing_info_t` records where the length field is (if found), how long the fixed header region is, and what the type discriminator field is. `token_stream_t` contains re-sliced messages (proper framing applied) with `type_hint` set from the type discriminator if found.

### phase 3 → phase 4

`protocol_schema_t` contains one `message_schema_t` per inferred message type. each schema has an array of `field_t` with offset, length, type tag, entropy, and (for enums) the distinct values. the rust side receives this as a safe `ProtocolSchema` wrapper and converts type_hint sequences into `Vec<u32>` for grammar induction.

### phase 4 → phase 5

the `Fsm` struct contains states, transitions with frequency annotations, and supports viterbi scoring. the output serialisers consume both the `Fsm` and the `ProtocolSchema`.
