# ref2

automatic protocol grammar & message format inference from network traces.

given a pcap, binary dump, plaintext log, or strace output, ref2 infers:

- **message schemas** — named fields with types (magic, length, enum, nonce, payload, …)
- **protocol fsm** — finite-state machine of the conversation grammar (k-tails or rpni)
- **outputs** — json schema · graphviz dot · scapy dissector

---

## quick start

```bash
# build
export PKG_CONFIG_PATH="$(brew --prefix)/lib/pkgconfig:$PKG_CONFIG_PATH"  # macos
cargo build --release

# run
ref2 infer --input capture.pcap --format pcap
```

outputs go to `./ref2_output/`:

```
ref2_output/
├── schema.json      field-level protocol description
├── fsm.dot          graphviz state machine
└── dissector.py     scapy packet class
```

---

## formats

| `--format` | source |
|---|---|
| `pcap` | libpcap capture — tcp stream reassembly |
| `raw` | binary blob — auto-framing or explicit hint |
| `plaintext` | `>> / <<` logs, wireshark hex dumps, plain lines |
| `syscall` | `strace -xx` output — grouped by fd |

---

## algorithms

| `--algo` | when to use |
|---|---|
| `ktails` (default) | fast, works from ≥5 sessions |
| `rpni` | more accurate, recommended with ≥20 sessions |

---

## examples

```bash
# pcap, all outputs, default k-tails
ref2 infer --input capture.pcap --format pcap

# strace log, rpni
ref2 infer --input trace.log --format syscall --algo rpni

# raw binary with explicit length field hint
ref2 infer --input dump.bin --format raw --frame-hint "length_u16_be@offset=2"

# plaintext exchange, json only
ref2 infer --input chat.txt --format plaintext --emit json

# view the inferred fsm
ref2 view ref2_output/fsm.dot
```

---

## dependencies

- **rust** ≥ 1.75
- **cmake** ≥ 3.20
- **libpcap** (dev headers)

no other runtime dependencies.

---

## documentation

```bash
cd website
npm install
npm start        # opens http://localhost:3000
```

---

## project layout

```
ref2/
├── c/
│   ├── ingest/         pcap, raw, plaintext, syscall ingestion
│   ├── token/          framing detection, tokenisation
│   └── format/         nw alignment, clustering, type classification
├── src/
│   ├── grammar/        k-tails, rpni, fsm, anomaly scoring
│   └── output/         json, dot, scapy serialisers
├── website/            docusaurus documentation
├── tests/
│   ├── fixtures/       sample pcaps and ground-truth schemas
│   └── integration/    integration tests
├── CMakeLists.txt
├── Cargo.toml
└── build.rs
```
