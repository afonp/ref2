---
sidebar_position: 1
---

# accuracy metrics

ref2 is evaluated by comparing its inferred schemas and fsms against ground-truth protocol specifications or established dissectors (e.g. wireshark's built-in dissectors).

---

## field-level metrics

### field recall

```
field recall = # correct field boundaries inferred
               ──────────────────────────────────
               # true field boundaries (ground truth)
```

a "correct field boundary" means ref2 placed a boundary at the correct byte offset.

### field precision

```
field precision = # correct field boundaries inferred
                  ──────────────────────────────────
                  # total field boundaries inferred
```

### field type accuracy

```
type accuracy = # correctly typed fields
                ─────────────────────────
                # total inferred fields
```

a field is "correctly typed" if ref2's classification matches the ground truth (e.g. ref2 says `LENGTH` and the spec says it's a length field).

---

## fsm metrics

### fsm accuracy

measured as normalised edit distance between the inferred fsm and the ground-truth fsm:

```
fsm_accuracy = 1 − (edit_distance(inferred, ground_truth) / max(|inferred|, |ground_truth|))
```

where edit distance counts the minimum number of state additions, state deletions, and transition modifications to transform one fsm into the other.

---

## reporting format

metrics are reported at:

- k ∈ `[1, 2, 3]` for k-tails
- both `ktails` and `rpni` algorithms
- varying numbers of sessions (5, 10, 20, 50) to show sample-size sensitivity

| protocol | algo | k | field recall | field precision | type accuracy | fsm accuracy |
|---|---|---|---|---|---|---|
| dns | ktails | 2 | — | — | — | — |
| http/1.1 | ktails | 2 | — | — | — | — |
| smtp | rpni | — | — | — | — | — |

*these values will be populated once the evaluation suite is run against real captures.*

---

## running the evaluation

evaluation fixtures (pcap files with known ground truth) go in `tests/fixtures/`. once present:

```bash
# run all integration tests
cargo test

# run a specific protocol evaluation
cargo test -- dns --nocapture
```

ground-truth schemas are expressed as json files in `tests/fixtures/<protocol>_schema.json` matching the ref2 output format.
