pub mod dot;
pub mod json_schema;
pub mod kaitai;
pub mod lua;
pub mod scapy;

use std::fs;
use std::io::BufWriter;
use std::path::Path;
use crate::ffi::ProtocolSchema;
use crate::grammar::Fsm;

/// Which output formats to emit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EmitFormat {
    Json,
    Dot,
    Scapy,
    Lua,
    Kaitai,
    All,
}

impl EmitFormat {
    pub fn json  (&self) -> bool { matches!(self, Self::Json   | Self::All) }
    pub fn dot   (&self) -> bool { matches!(self, Self::Dot    | Self::All) }
    pub fn scapy (&self) -> bool { matches!(self, Self::Scapy  | Self::All) }
    pub fn lua   (&self) -> bool { matches!(self, Self::Lua    | Self::All) }
    pub fn kaitai(&self) -> bool { matches!(self, Self::Kaitai | Self::All) }
}

/// Write all requested output files into `output_dir`.
pub fn write_all(
    output_dir: &Path,
    input_name: &str,
    schema: &ProtocolSchema,
    fsm: &Fsm,
    fmt: EmitFormat,
    anomaly_scores: &[(usize, f64)],
) -> std::io::Result<()> {
    fs::create_dir_all(output_dir)?;

    if fmt.json() {
        let path = output_dir.join("schema.json");
        let f = fs::File::create(&path)?;
        let mut w = BufWriter::new(f);
        json_schema::emit(&mut w, input_name, schema, fsm, anomaly_scores)?;
        eprintln!("ref2: wrote {}", path.display());
    }

    if fmt.dot() {
        let path = output_dir.join("fsm.dot");
        let f = fs::File::create(&path)?;
        let mut w = BufWriter::new(f);
        dot::emit(&mut w, fsm)?;
        eprintln!("ref2: wrote {}", path.display());
        eprintln!("ref2: render with: dot -Tsvg {} -o {}/fsm.svg",
                  path.display(), output_dir.display());
    }

    if fmt.scapy() {
        let path = output_dir.join("dissector.py");
        let f = fs::File::create(&path)?;
        let mut w = BufWriter::new(f);
        scapy::emit(&mut w, schema)?;
        eprintln!("ref2: wrote {}", path.display());
    }

    if fmt.lua() {
        let path = output_dir.join("dissector.lua");
        let f = fs::File::create(&path)?;
        let mut w = BufWriter::new(f);
        lua::emit(&mut w, schema, input_name)?;
        eprintln!("ref2: wrote {}", path.display());
        eprintln!("ref2: install with: cp {} ~/.config/wireshark/plugins/", path.display());
    }

    if fmt.kaitai() {
        let path = output_dir.join("schema.ksy");
        let f = fs::File::create(&path)?;
        let mut w = BufWriter::new(f);
        kaitai::emit(&mut w, schema, input_name)?;
        eprintln!("ref2: wrote {}", path.display());
        eprintln!("ref2: compile with: kaitai-struct-compiler -t python {}", path.display());
    }

    Ok(())
}
