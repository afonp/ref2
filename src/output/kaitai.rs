/// Kaitai Struct (.ksy) output generator.
///
/// Produces a YAML file loadable by the kaitai-struct-compiler.
/// Not all field types map perfectly, but this gets you 80% of the way there.

use std::io::{self, Write};
use crate::ffi::{ProtocolSchema, FieldTypeId};

pub fn emit<W: Write>(out: &mut W, schema: &ProtocolSchema, proto_name: &str) -> io::Result<()> {
    let name = sanitize(proto_name);

    writeln!(out, "meta:")?;
    writeln!(out, "  id: {name}")?;
    writeln!(out, "  title: \"{proto_name} (inferred by ref2)\"")?;
    writeln!(out, "  endian: be")?;
    writeln!(out)?;

    // Top-level type is the first message type; the rest are subtypes.
    if schema.schemas.is_empty() {
        writeln!(out, "seq: []")?;
        return Ok(());
    }

    let first = &schema.schemas[0];
    writeln!(out, "seq:")?;
    emit_seq(out, first, schema, 0)?;

    if schema.schemas.len() > 1 {
        writeln!(out)?;
        writeln!(out, "types:")?;
        for ms in &schema.schemas[1..] {
            let tname = sanitize(&ms.name);
            writeln!(out, "  {tname}:")?;
            writeln!(out, "    seq:")?;
            emit_seq(out, ms, schema, 4)?;
        }
    }

    Ok(())
}

fn emit_seq<W: Write>(
    out: &mut W,
    ms: &crate::ffi::MessageSchema,
    _schema: &ProtocolSchema,
    indent: usize,
) -> io::Result<()> {
    let pad = " ".repeat(indent);
    for f in &ms.fields {
        let fname = sanitize(&f.name);
        writeln!(out, "{pad}  - id: {fname}")?;

        let (ktype, size_line) = kaitai_type(f);
        writeln!(out, "{pad}    type: {ktype}")?;

        if let Some(sl) = size_line {
            writeln!(out, "{pad}    {sl}")?;
        }

        // Add enum values inline if ENUM field.
        if f.field_type == FieldTypeId::Enum && f.enum_count > 0 {
            writeln!(out, "{pad}    enum: {fname}_values")?;
        }

        if let Some(doc) = field_doc(f) {
            writeln!(out, "{pad}    doc: \"{doc}\"")?;
        }
    }

    // Inline enum definitions.
    let has_enums = ms.fields.iter().any(|f| f.field_type == FieldTypeId::Enum && f.enum_count > 0);
    if has_enums {
        writeln!(out)?;
        let epad = " ".repeat(indent);
        writeln!(out, "{epad}  enums:")?;
        for f in &ms.fields {
            if f.field_type != FieldTypeId::Enum || f.enum_count == 0 { continue; }
            let fname = sanitize(&f.name);
            writeln!(out, "{epad}    {fname}_values:")?;
            for i in 0..f.enum_count {
                let v = f.enum_values[i];
                writeln!(out, "{epad}      {v}: val_{i:02}")?;
            }
        }
    }

    Ok(())
}

fn kaitai_type(f: &crate::ffi::Field) -> (&'static str, Option<String>) {
    use FieldTypeId::*;
    match f.field_type {
        Magic | Constant => fixed_int_type(f.length),
        Enum             => (fixed_int_type(f.length).0, None),
        SequenceNumber   => fixed_int_type(f.length),
        Length           => fixed_int_type(f.length),
        Nonce            => ("bytes", Some(format!("size: {}", f.length))),
        Str              => ("strz", Some("encoding: UTF-8".to_string())),
        Payload          => ("bytes", if f.length > 0 {
                                Some(format!("size: {}", f.length))
                            } else {
                                Some("size-eos: true".to_string())
                            }),
        _                => if f.length > 0 {
                                ("bytes", Some(format!("size: {}", f.length)))
                            } else {
                                ("bytes", Some("size-eos: true".to_string()))
                            },
    }
}

fn fixed_int_type(len: usize) -> (&'static str, Option<String>) {
    match len {
        1 => ("u1", None),
        2 => ("u2", None),
        4 => ("u4", None),
        8 => ("u8", None),
        n => ("bytes", Some(format!("size: {n}"))),
    }
}

fn field_doc(f: &crate::ffi::Field) -> Option<String> {
    use FieldTypeId::*;
    let note = match f.field_type {
        Magic          => "protocol magic / sync bytes",
        Constant       => "always-constant field (version, flags?)",
        Enum           => "enumerated type field",
        SequenceNumber => "monotonically increasing sequence number",
        Length         => "payload length field",
        Payload        => "variable-length payload",
        Nonce          => "random/nonce value (high entropy)",
        Str            => "null-terminated string",
        Opaque         => return None,
    };
    Some(format!("{note}; entropy={:.2}", f.entropy))
}

fn sanitize(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '_' { c } else { '_' })
        .collect::<String>()
        .trim_matches('_')
        .to_string()
}
