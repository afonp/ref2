/// JSON schema serialiser.

use std::io::{self, Write};
use serde_json::{json, Value};
use crate::ffi::ProtocolSchema;
use crate::grammar::Fsm;

pub fn emit<W: Write>(
    out: &mut W,
    input_path: &str,
    schema: &ProtocolSchema,
    fsm: &Fsm,
) -> io::Result<()> {
    let message_types: Vec<Value> = schema.schemas.iter().map(|ms| {
        let fields: Vec<Value> = ms.fields.iter().map(|f| {
            let mut fobj = json!({
                "offset":  f.offset,
                "length":  f.length,
                "type":    f.type_name(),
                "name":    f.name,
                "entropy": (f.entropy * 1000.0).round() / 1000.0,
            });
            if f.enum_count > 0 {
                fobj["enum_values"] = json!(&f.enum_values[..f.enum_count]);
            }
            fobj
        }).collect();

        json!({
            "id":     ms.type_id,
            "name":   ms.name,
            "fields": fields,
        })
    }).collect();

    let states_json: Vec<Value> = fsm.states.iter().map(|s| json!({
        "id":          s.id,
        "label":       s.label,
        "is_initial":  s.is_initial,
        "is_accepting":s.is_accepting,
    })).collect();

    let transitions_json: Vec<Value> = fsm.transitions.iter().map(|t| json!({
        "from":         t.from,
        "to":           t.to,
        "message_type": t.message_type,
        "schema_ref":   t.schema_ref,
        "frequency":    (t.frequency * 10000.0).round() / 10000.0,
    })).collect();

    let doc = json!({
        "protocol":      "unknown",
        "inferred_from": input_path,
        "message_types": message_types,
        "fsm": {
            "states":      states_json,
            "transitions": transitions_json,
        },
    });

    let pretty = serde_json::to_string_pretty(&doc)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
    out.write_all(pretty.as_bytes())?;
    out.write_all(b"\n")
}
