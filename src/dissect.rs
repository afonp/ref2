// ref2 dissect — apply a saved schema to a new input and decode messages
//
// loads schema.json from a prior infer run and tries to match each message
// against the known message types. prints a human-readable field breakdown.

use std::fs;
use std::path::Path;
use serde_json::Value;

use crate::ffi::{IngestFormat, Pipeline};

struct FieldSpec {
    name:    String,
    offset:  usize,
    length:  usize,    // 0 = rest of message
    ftype:   String,
}

struct MsgType {
    id:     u64,
    name:   String,
    fields: Vec<FieldSpec>,
}

struct Schema {
    types: Vec<MsgType>,
    // type discriminator info from framing (if present)
    type_offset: Option<usize>,
    type_width:  Option<usize>,
}

fn load_schema(dir: &Path) -> anyhow::Result<Schema> {
    let path = dir.join("schema.json");
    let raw = fs::read_to_string(&path)?;
    let v: Value = serde_json::from_str(&raw)?;

    let mut types = Vec::new();

    for mt in v["message_types"].as_array().unwrap_or(&vec![]) {
        let id   = mt["id"].as_u64().unwrap_or(0);
        let name = mt["name"].as_str().unwrap_or("unknown").to_string();

        let mut fields = Vec::new();
        for f in mt["fields"].as_array().unwrap_or(&vec![]) {
            fields.push(FieldSpec {
                name:   f["name"].as_str().unwrap_or("?").to_string(),
                offset: f["offset"].as_u64().unwrap_or(0) as usize,
                length: f["length"].as_u64().unwrap_or(0) as usize,
                ftype:  f["type"].as_str().unwrap_or("OPAQUE").to_string(),
            });
        }
        types.push(MsgType { id, name, fields });
    }

    // try to pull type discriminator info out of the fsm transitions
    // (rough heuristic: if all transitions use sequential type ids, we can
    // guess the discriminator position from the field named "enum" or "type")
    let type_offset = None;
    let type_width  = None;

    Ok(Schema { types, type_offset, type_width })
}

fn decode_message(data: &[u8], schema: &Schema) -> String {
    // figure out which message type this is
    let msg_type = if let (Some(off), Some(w)) = (schema.type_offset, schema.type_width) {
        if data.len() >= off + w {
            let mut v = 0u64;
            for i in 0..w { v = (v << 8) | data[off + i] as u64; }
            schema.types.iter().find(|t| t.id == v)
        } else {
            None
        }
    } else {
        // no discriminator info — just pick the first type as a guess
        // TODO: try all types and pick best match (lowest field entropy deviation)
        schema.types.first()
    };

    let Some(mt) = msg_type else {
        return format!("  <unknown message type, {} bytes>", data.len());
    };

    let mut out = format!("  [{}]\n", mt.name);

    for f in &mt.fields {
        let end = if f.length == 0 { data.len() } else { f.offset + f.length };
        if end > data.len() || f.offset > data.len() {
            out.push_str(&format!("    {:<24} <truncated>\n", f.name));
            continue;
        }
        let bytes = &data[f.offset..end.min(data.len())];
        let display = format_field_value(bytes, &f.ftype);
        out.push_str(&format!("    {:<24} {}\n", f.name, display));
    }

    out
}

fn format_field_value(bytes: &[u8], ftype: &str) -> String {
    match ftype {
        "MAGIC" | "CONSTANT" => {
            let hex: String = bytes.iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(" ");
            format!("0x{}", hex.replace(' ', ""))
        }
        "LENGTH" | "SEQUENCE_NUMBER" => {
            let mut v = 0u64;
            for &b in bytes { v = (v << 8) | b as u64; }
            format!("{} (0x{:x})", v, v)
        }
        "ENUM" => {
            let mut v = 0u64;
            for &b in bytes { v = (v << 8) | b as u64; }
            format!("{}", v)
        }
        "STRING" => {
            let s = String::from_utf8_lossy(bytes);
            // trim null terminators
            let s = s.trim_end_matches('\0');
            format!("{:?}", s)
        }
        "NONCE" => {
            let hex: String = bytes.iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join("");
            format!("<nonce: {}>", hex)
        }
        "PAYLOAD" => {
            let printable = bytes.iter().filter(|b| b.is_ascii_graphic()).count();
            if bytes.len() > 0 && printable * 100 / bytes.len() > 80 {
                format!("{:?} ({} bytes)", String::from_utf8_lossy(bytes), bytes.len())
            } else {
                format!("<{} bytes binary>", bytes.len())
            }
        }
        _ => {
            if bytes.len() <= 8 {
                let hex: String = bytes.iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(" ");
                format!("[{}]", hex)
            } else {
                format!("[{} bytes]", bytes.len())
            }
        }
    }
}

pub fn run_dissect(schema_dir: &Path, input: &Path) -> anyhow::Result<()> {
    let schema = load_schema(schema_dir)?;

    if schema.types.is_empty() {
        anyhow::bail!("no message types in schema");
    }

    eprintln!("ref2 dissect: loaded {} message type(s) from {}",
              schema.types.len(), schema_dir.display());

    // ingest — try to auto-detect format from extension
    let fmt = match input.extension().and_then(|e| e.to_str()) {
        Some("pcap") | Some("pcapng") => IngestFormat::Pcap,
        Some("log") | Some("txt")     => IngestFormat::Plaintext,
        _                              => IngestFormat::Raw(None),
    };

    let pipeline = Pipeline::run(input, fmt)
        .ok_or_else(|| anyhow::anyhow!("failed to ingest {:?}", input))?;

    let sess = pipeline.sequences();
    let total_sessions = sess.sequences.len();

    // re-ingest to get raw payload bytes — we need the actual data, not just type ids
    // bit of a hack: run the pipeline again and grab bytes from the token streams
    // TODO: expose raw payloads through Pipeline instead of this double-ingest
    let fmt2 = match input.extension().and_then(|e| e.to_str()) {
        Some("pcap") | Some("pcapng") => IngestFormat::Pcap,
        Some("log") | Some("txt")     => IngestFormat::Plaintext,
        _                              => IngestFormat::Raw(None),
    };
    let pipeline2 = Pipeline::run(input, fmt2)
        .ok_or_else(|| anyhow::anyhow!("failed second ingest"))?;

    let mut total_msgs = 0usize;
    unsafe {
        for si in 0..pipeline2.stream_count() {
            let ts = &*(*pipeline2.streams_ptr()).add(si);
            println!("session {} ({} messages):", si, ts.count);
            for mi in 0..ts.count {
                let tok = &*ts.tokens.add(mi);
                let data = std::slice::from_raw_parts(tok.data, tok.len);
                print!("  msg {}: ", mi);
                let decoded = decode_message(data, &schema);
                print!("{}", decoded);
                total_msgs += 1;
            }
        }
    }

    eprintln!("ref2 dissect: decoded {} message(s) across {} session(s)",
              total_msgs, total_sessions);
    Ok(())
}
