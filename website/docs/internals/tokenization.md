---
sidebar_position: 3
---

# phase 2 — tokenization & framing

**source:** `c/token/`
**output types:** `framing_info_t`, `token_stream_t[]`

the tokenisation phase answers two questions:

1. where do message boundaries actually fall?
2. which byte position in the header is the type discriminator?

it does this entirely statistically, with no protocol knowledge.

---

## framing detection

### step 1: entropy analysis (`framing.c`)

for each byte position `i` from 0 to `min(max_msg_len, 32)`:

```
H(i) = -∑ p(b) · log₂(p(b))   over all bytes b seen at position i
```

positions where `H < 0.5 bits` are nearly constant across all messages — this is the fixed header region. the longest run of low-entropy positions from the start defines `candidate_header_len`.

**example (http):** the first 5 bytes `H T T P /` have near-zero entropy → `header_len = 5`.

### step 2: length field inference (`length_field.c`)

for each candidate `(offset, width, endianness)` triple:

1. read `val = bytes[offset : offset+width]` as a `uint` for every message
2. test: does `val == total_msg_len - k` for some constant `k` across ≥80% of messages?
3. record coverage %, pick the best candidate

**probed combinations:** offsets 0–15 × widths `[1, 2, 4]` × endianness `[LE, BE]` = 96 candidates.

if a length field is found, the stream is re-sliced to produce proper message boundaries.

### step 3: delimiter scanning (`framing.c`)

if no length field is found, scan for recurring byte sequences that appear at the end of messages:

- check common single-byte terminators (`\n`, `\r`, `\0`, `\xff`) — if ≥80% of messages end with one, use it
- check common two-byte terminators (`\r\n`, `\0\0`)

### step 4: type discriminator detection (`framing.c`)

for each byte position in the header region (excluding the length field):

- count distinct values across all messages
- if 2–16 distinct values → candidate type discriminator
- score by: `(16 - num_distinct) × total_messages` (favour fields with few distinct values)
- best-scoring position becomes `type_offset`

the type discriminator value from each message is stored as `token_t.type_hint`.

---

## output: `framing_info_t`

```c
typedef struct {
    size_t  header_len;
    int     has_length_field;
    size_t  length_offset;
    size_t  length_width;      /* 1, 2, or 4 */
    int     length_endian;     /* 0=LE, 1=BE */
    int32_t length_adjustment; /* total_len = field_val + adjustment */
    int     has_type_field;
    size_t  type_offset;
    size_t  type_width;        /* 1 or 2 */
    int     has_delimiter;
    uint8_t delimiter[4];
    size_t  delimiter_len;
} framing_info_t;
```

---

## output: `token_t`

```c
typedef struct {
    uint8_t *data;
    size_t   len;
    uint32_t type_hint;  /* type discriminator value, 0 if unknown */
} token_t;
```

each `token_t` is one properly-framed protocol message. the data buffer is a copy of the payload bytes.

---

## limitations

- works best when all sessions are the same protocol. mixing protocols in one input file will confuse entropy analysis.
- type discriminator detection requires the discriminator to appear at a fixed position in every message. position-independent flags (e.g. tls record type in variable-position extensions) won't be found.
- framing detection needs at least 4 messages to make statistical decisions.
