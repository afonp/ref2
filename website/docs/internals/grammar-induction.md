---
sidebar_position: 5
---

# phase 4 — grammar induction

**source:** `src/grammar/`
**output type:** `Fsm`

grammar induction takes the ordered sequence of message type labels for each session and infers a finite-state machine describing the protocol's conversation structure.

---

## input preparation

each session is mapped to a `Vec<u32>` of type ids:

```
session 0:  [0, 1, 2, 2, 2, 3]       # HELLO → AUTH → DATA×3 → FIN
session 1:  [0, 1, 2, 3]             # HELLO → AUTH → DATA → FIN
session 2:  [0, 1, 3]                # HELLO → AUTH → FIN (no data)
```

sessions with fewer than 3 messages are filtered out — they don't contribute meaningful grammar information.

if fewer sessions remain than `--min-sessions`, grammar induction is skipped and an empty fsm is returned.

---

## k-tails (`src/grammar/ktails.rs`)

k-tails is the default algorithm. it:

1. builds a **prefix tree acceptor (PTA)** from all session sequences
2. for each pair of states `(u, v)` in the PTA, computes their k-suffix sets — all sequences of length ≤ k reachable from that state
3. merges `u` and `v` (via union-find) if their suffix sets are equal
4. determinises the result into a dfa

**k parameter:** controls the look-ahead depth. higher k → fewer merges → more precise but larger fsm.

| k | effect |
|---|---|
| 1 | aggressive merging, may over-generalise |
| 2 | good default, balanced |
| 3+ | conservative, use when you have many long sessions |

**complexity:** O(n² × s^k) where n = number of pta states and s = alphabet size. for k ≤ 3 and typical protocol alphabets (≤32 types) this is fast.

---

## rpni (`src/grammar/rpni.rs`)

rpni (regular positive and negative inference) — specifically the blue-fringe variant — is more accurate than k-tails when you have ≥ 20 sessions.

**algorithm:**

1. build a pta as before
2. maintain a set of **red states** (confirmed) and **blue states** (candidates)
3. for each blue state: try to merge it with each red state
   - if the merge is consistent with all positive examples → perform the merge
   - if no merge is consistent → promote the blue state to red
4. repeat until no blue states remain

a merge is "consistent" if it doesn't create a situation where a state is simultaneously accepting and non-accepting.

rpni does not use the `--k` parameter.

**when to use rpni:**

- ≥ 20 sessions with sufficient diversity
- the protocol has complex state structure that k-tails over-merges

```bash
ref2 infer --input capture.pcap --format pcap --algo rpni
```

---

## fsm structure

```rust
pub struct State {
    pub id:           u32,
    pub label:        String,
    pub is_initial:   bool,
    pub is_accepting: bool,
}

pub struct Transition {
    pub from:         u32,
    pub to:           u32,
    pub message_type: u32,
    pub schema_ref:   String,  // e.g. "msg_type_02"
    pub frequency:    f64,     // fraction of sessions using this transition
}
```

the initial state is always present. accepting states represent valid session endpoints (a session that ends at a non-accepting state is anomalous).

**transition frequency:** computed as `count / total_sessions`. transitions with frequency < 0.02 are present in the fsm but flagged as rare.

---

## anomaly scoring

for each session, ref2 computes a viterbi log-probability:

```
log_prob(session) = ∑ log(freq(transition_i))
```

if any transition is not present in the fsm, `log_prob = -∞` and the session is flagged as fully anomalous.

the raw log-probability is normalised to `[0, 1]` using:

```
anomaly_score = 1 - exp(-(-log_prob / session_length))
```

| score range | interpretation |
|---|---|
| 0.0 – 0.1 | normal |
| 0.1 – 0.5 | mildly unusual |
| 0.5 – 0.9 | suspicious |
| 0.9 – 1.0 | unknown/anomalous sequence |
| 1.0 (exact) | unknown transition (not in fsm) |
