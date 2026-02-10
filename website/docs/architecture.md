---
sidebar_position: 99
---

# architecture

## why c + rust?

the hot inner loops — ingestion, needleman-wunsch alignment, k-means, entropy computation — are in c for performance. the orchestration layer, ffi boundary, grammar induction algorithms, and cli are in rust for memory safety and ergonomics.

```
ref2 binary (rust)
 ├── src/main.rs           cli parsing + pipeline driver
 ├── src/ffi.rs            safe wrappers around C ffi
 ├── src/grammar/          k-tails, rpni, fsm, anomaly scoring
 └── src/output/           json, dot, scapy serialisers
        │
        │  ffi (extern "C")
        ▼
libref2.a (c static library)
 ├── c/ingest/             pcap, raw, plaintext, syscall → trace_t
 ├── c/token/              framing detection, tokenisation
 └── c/format/             alignment, clustering, type classification
        │
        │  pkg-config + cmake
        ▼
libpcap                    pcap ingestion only
```

## build system

cmake builds `libref2.a` as three object-library targets combined into one static archive:

```cmake
add_library(ref2 STATIC
    $<TARGET_OBJECTS:ref2_ingest>
    $<TARGET_OBJECTS:ref2_token>
    $<TARGET_OBJECTS:ref2_format>)
```

cargo's `build.rs` invokes cmake via the `cmake` crate and emits `cargo:rustc-link-*` directives to link the archive into the rust binary.

## ffi boundary

the rust `ffi.rs` module defines mirror structs for every C type (`CTraceT`, `CSessionT`, `CMessageT`, etc.) with `#[repr(C)]` to match the C struct layout. all raw pointers are wrapped in safe rust types (`Pipeline`, `ProtocolSchema`) whose `Drop` implementations call the corresponding `*_free()` C functions.

## dependency map

```
ref2 (bin)
 ├── clap        4.x   cli parsing
 ├── serde       1.x   serialisation traits
 ├── serde_json  1.x   json output
 ├── anyhow      1.x   error handling
 └── cmake       0.1   build-time: invoke cmake from build.rs
         │
         └── (build-time) → libref2.a → libpcap
```

zero runtime dependencies other than libpcap.

## adding a new input format

1. add an ingestion function in `c/ingest/new_format.c` with signature:
   ```c
   trace_t *ingest_new_format(const char *path);
   ```
2. declare it in `c/ingest/ingest.h`
3. add the source to `CMakeLists.txt` under `ref2_ingest`
4. add a variant to `IngestFormat` in `src/ffi.rs`
5. wire it into `Pipeline::run()` and the cli `--format` enum in `src/main.rs`

## adding a new output format

1. create `src/output/myformat.rs` with:
   ```rust
   pub fn emit<W: Write>(out: &mut W, schema: &ProtocolSchema, fsm: &Fsm) -> io::Result<()>
   ```
2. add it to `src/output/mod.rs`
3. add a variant to `EmitFormat` and wire it into `write_all()`
4. add `--emit myformat` to the cli in `src/main.rs`

## thread safety

the c layer uses global mutable state (stream tables, session id counters) in `pcap_reader.c` and `syscall_reader.c`. **do not call ingestion functions from multiple threads concurrently.** all other c functions are stateless and re-entrant.

the rust layer is single-threaded throughout (sequential pipeline). `ProtocolSchema` is `Send + Sync` by declaration but should not be accessed from multiple threads without external synchronisation.
