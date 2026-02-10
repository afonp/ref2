---
sidebar_position: 4
---

# phase 3 — format inference

**source:** `c/format/`
**output type:** `protocol_schema_t`

format inference takes the tokenised messages and produces a named field schema for each message type.

---

## step 1: clustering (`cluster.c`)

messages are grouped into clusters — one per distinct message type.

**fast path (type hint available):** if the tokenisation phase found a type discriminator, messages are grouped by their `type_hint` value. this is exact and fast.

**fallback (k-means):** if no type discriminator was found, messages are clustered by their 256-dimensional normalised byte-frequency histogram using k-means++:

```
k = min(32, floor(sqrt(n / 2)))
```

k-means++ initialisation is used for stability. 10 restarts are run and the result with the lowest inertia is kept. each restart runs for up to 100 iterations.

---

## step 2: pairwise alignment (`aligner.c`)

within each cluster, all messages are aligned using **needleman-wunsch** to compute per-position conservation scores.

**scoring parameters:**

| event | score |
|---|---|
| match | +2 |
| mismatch | −1 |
| gap open | −3 |
| gap extend | −1 |

**progressive alignment:** messages are sorted by length (ascending) and aligned one at a time against a running consensus. each new message is aligned against the current consensus; the consensus is updated to reflect the new alignment.

for clusters with >200 messages, only the consensus update strategy is used (not full pairwise) to keep the complexity manageable.

**output:** a `conservation[pos]` vector where `conservation[i] ∈ [0, 1]` represents what fraction of messages have the same byte value at position `i` (after alignment).

```
position:     0    1    2    3    4    5    6    7    8 ...
conservation: 1.0  1.0  1.0  1.0  0.12 0.09 0.11 1.0  0.8 ...
              ├──── fixed header ──────┤├── variable ─┤├─────
```

---

## step 3: field boundary segmentation (`aligner.c`)

the conservation vector is processed to find field boundaries:

1. **median smoothing** — a window-3 median filter removes noise spikes
2. **threshold** — positions with `conservation ≥ 0.7` are "conserved"; below is "variable"
3. **run-length encoding** — consecutive conserved/variable positions are grouped into segments

each segment becomes a `field_t` with `type = FIELD_CONSTANT` or `FIELD_OPAQUE` initially.

a variable segment whose offset and width match the known length field from phase 2 is immediately promoted to `FIELD_LENGTH`.

---

## step 4: type classification (`type_classifier.c`)

each field segment is classified using a priority-ordered set of tests:

| type | test |
|---|---|
| `MAGIC` | all messages have identical bytes at this field |
| `NONCE` | entropy > 7.5 bits + no two messages share the same value |
| `LENGTH` | `val == total_msg_len − k` for constant k in ≥85% of messages |
| `SEQUENCE_NUMBER` | values are monotonically non-decreasing within sessions |
| `ENUM` | 2–16 distinct values, entropy < 3.0 bits |
| `STRING` | >80% of bytes are printable ascii |
| `PAYLOAD` | entropy > 6.5 bits (high entropy, usually variable-length, last field) |
| `OPAQUE` | none of the above |

**auto-naming:** fields are named `field_{idx:02}_{type_lowercase}` — e.g. `field_00_magic`, `field_01_length`, `field_02_enum`.

---

## output: `protocol_schema_t`

```c
typedef struct {
    size_t       offset;
    size_t       length;      /* 0 = variable */
    field_type_t type;
    char         name[64];
    double       entropy;
    uint32_t     enum_values[16];
    size_t       enum_count;
} field_t;

typedef struct {
    uint32_t  type_id;
    field_t  *fields;
    size_t    field_count;
    char      name[64];       /* msg_type_00, msg_type_01, ... */
} message_schema_t;
```

---

## example output

for a hypothetical framed binary protocol:

```json
{
  "id": 0,
  "name": "msg_type_00",
  "fields": [
    { "offset": 0, "length": 4, "type": "MAGIC",   "name": "field_00_magic",   "entropy": 0.0  },
    { "offset": 4, "length": 2, "type": "LENGTH",  "name": "field_01_length",  "entropy": 3.8  },
    { "offset": 6, "length": 1, "type": "ENUM",    "name": "field_02_enum",    "entropy": 1.58,
      "enum_values": [1, 2, 3] },
    { "offset": 7, "length": 0, "type": "PAYLOAD", "name": "field_03_payload", "entropy": 7.9  }
  ]
}
```
