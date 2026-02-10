---
sidebar_position: 2
---

# test protocols

the evaluation suite uses these protocols as ground truth — all are well-documented with official wireshark dissectors, making them ideal for measuring ref2's accuracy.

---

## dns (udp, binary)

**characteristics:** fixed 12-byte header with well-known field layout, type discriminator in `QR` bit, variable-length labels.

**why it's useful:** small messages, clean framing, several distinct message types (query, response, nxdomain). good test of type-discriminator detection and enum classification.

**expected:** high field precision/recall (the header structure is very regular). the label encoding in the variable section will likely appear as `OPAQUE`.

---

## http/1.1 (text, delimiter-framed)

**characteristics:** newline/crlf-delimited, plaintext, headers as `key: value` pairs followed by a blank line, then optional body.

**why it's useful:** tests the plaintext ingestion path and delimiter-based framing. the method field (`GET`, `POST`, etc.) is a great test for string-type `ENUM` detection.

**expected:** good recall on the request-line boundary. the status code (200, 404, etc.) should be classified as `ENUM`. body may be classified as `PAYLOAD` or `STRING`.

---

## smtp (text, line-delimited)

**characteristics:** one command per line, responses are 3-digit numeric codes. bidirectional session with distinct client-command and server-response types.

**why it's useful:** the 3-digit response code is a good enum candidate. the conversation grammar (helo → mail from → rcpt to → data → quit) is simple enough that k-tails at k=2 should recover it exactly.

---

## smb2 (binary, length-framed)

**characteristics:** 4-byte netbios header + 64-byte smb2 header. the `command` field at offset 12 is the type discriminator (2 bytes). many distinct message types.

**why it's useful:** realistic complex binary protocol. tests length-field inference (netbios length at offset 0), type-discriminator detection, and multi-type clustering. large message variety stresses the k-means fallback.

---

## custom toy protocol

a synthetic protocol with known ground truth, used as a unit test for each phase:

```
message format:
  [0:4]  magic     = 0xDEADBEEF       (MAGIC)
  [4:6]  length    = total msg length  (LENGTH, big-endian)
  [6:7]  type      = 0x01/0x02/0x03   (ENUM, type discriminator)
  [7:N]  payload   = variable          (PAYLOAD)

fsm:
  INIT --[type=01]--> AUTH --[type=02]--> SESSION --[type=02]--> SESSION
  SESSION --[type=03]--> INIT
```

this protocol is fully deterministic, so a well-functioning pipeline should achieve:
- field recall = 1.0
- field precision = 1.0
- type accuracy = 1.0
- fsm accuracy = 1.0

if any of these fall below 1.0, it indicates a regression.

---

## adding a new protocol

to add a protocol to the evaluation suite:

1. capture a representative pcap (≥ 50 sessions recommended) and put it in `tests/fixtures/<proto>.pcap`
2. write the ground-truth schema as `tests/fixtures/<proto>_schema.json` following the ref2 output format
3. add an integration test in `tests/integration/<proto>.rs`:

```rust
#[test]
fn test_dns_field_recall() {
    // run ref2 pipeline on tests/fixtures/dns.pcap
    // compare output schema.json to tests/fixtures/dns_schema.json
    // assert recall >= 0.8
}
```
