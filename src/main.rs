mod dissect;
mod ffi;
mod grammar;
mod output;

use clap::{Parser, Subcommand, ValueEnum};
use std::collections::HashMap;
use std::path::PathBuf;

use ffi::{IngestFormat, Pipeline};
use grammar::{Algorithm, induce, score_anomalies};
use output::EmitFormat;

// ── CLI definition ────────────────────────────────────────────────────────────

#[derive(Parser, Debug)]
#[command(name = "ref2", version, about = "Automatic protocol grammar & format inference")]
struct Cli {
    /// Print extra progress and debug output.
    #[arg(short, long, global = true)]
    verbose: bool,

    /// Suppress all progress output (only errors go to stderr).
    #[arg(short, long, global = true)]
    quiet: bool,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Infer protocol schema and FSM from a network trace or log.
    Infer(InferArgs),
    /// Dissect new captures using a previously inferred schema.
    Dissect(DissectArgs),
    /// Open a DOT file in the default viewer (renders with dot(1) if available).
    View(ViewArgs),
}

#[derive(Parser, Debug)]
struct InferArgs {
    /// Input file path.
    #[arg(short, long)]
    input: PathBuf,

    /// Input format.
    #[arg(short, long, value_enum)]
    format: InputFormat,

    /// Output directory.
    #[arg(long, default_value = "./ref2_output")]
    output_dir: PathBuf,

    /// Frame hint for raw format (e.g. "length_u16_be@offset=2").
    #[arg(long)]
    frame_hint: Option<String>,

    /// k-tails depth.
    #[arg(long, default_value_t = 2)]
    k: usize,

    /// Grammar induction algorithm.
    #[arg(long, value_enum, default_value_t = AlgoArg::Ktails)]
    algo: AlgoArg,

    /// Minimum sessions required for grammar induction.
    #[arg(long, default_value_t = 5)]
    min_sessions: usize,

    /// Endianness hint (auto, le, be).
    #[arg(long, default_value = "auto")]
    endian: String,

    /// Output formats to emit.
    #[arg(long, value_enum, default_value_t = EmitArg::All)]
    emit: EmitArg,

    /// Clustering strategy (auto, type-field, kmeans).
    #[arg(long, default_value = "auto")]
    cluster: String,

    /// Print per-field entropy and classification details.
    #[arg(short = 'v', long)]
    verbose: bool,

    /// Suppress all progress output.
    #[arg(short = 'q', long)]
    quiet: bool,
}

#[derive(Parser, Debug)]
struct DissectArgs {
    /// Path to schema directory (from a prior `ref2 infer` run).
    #[arg(long)]
    schema: PathBuf,

    /// Input file to dissect.
    #[arg(short, long)]
    input: PathBuf,
}

#[derive(Parser, Debug)]
struct ViewArgs {
    /// DOT file to view.
    dot_file: PathBuf,
}

#[derive(Clone, Debug, ValueEnum)]
enum InputFormat {
    Pcap,
    Raw,
    Plaintext,
    Syscall,
}

#[derive(Clone, Debug, ValueEnum)]
enum AlgoArg {
    Ktails,
    Rpni,
}

#[derive(Clone, Debug, ValueEnum)]
enum EmitArg {
    Json,
    Dot,
    Scapy,
    Lua,
    Kaitai,
    All,
}

// ── Frame hint parsing ────────────────────────────────────────────────────────

/// Parse a frame hint string like "length_u16_be@offset=2".
fn parse_frame_hint(s: &str) -> Option<ffi::CFrameHintT> {
    let mut hint = ffi::CFrameHintT {
        frame_type:    1, // FRAME_LENGTH_FIELD
        header_size:   0,
        length_offset: 0,
        length_width:  2,
        length_endian: 1, // BE
        delimiter:     [0u8; 4],
        delimiter_len: 0,
    };

    // Very simple parser: "length_u<width>_<endian>@offset=<n>"
    let lower = s.to_ascii_lowercase();
    if lower.starts_with("length_u") {
        let rest = &lower[8..];
        if let Some(width_end) = rest.find('_') {
            hint.length_width = rest[..width_end].parse().unwrap_or(2) / 8;
            if rest[width_end + 1..].starts_with("be") {
                hint.length_endian = 1;
            } else {
                hint.length_endian = 0;
            }
        }
        if let Some(at) = lower.find("offset=") {
            hint.length_offset = lower[at + 7..].split_whitespace().next()
                .and_then(|v| v.parse().ok()).unwrap_or(0);
        }
        Some(hint)
    } else if lower.starts_with("delim:") {
        hint.frame_type = 2; // FRAME_DELIMITER
        let delim = &s[6..];
        for (i, c) in delim.bytes().take(4).enumerate() {
            hint.delimiter[i] = c;
        }
        hint.delimiter_len = delim.len().min(4);
        Some(hint)
    } else {
        None
    }
}

// ── Subcommand implementations ────────────────────────────────────────────────

macro_rules! info {
    ($quiet:expr, $($arg:tt)*) => {
        if !$quiet { eprintln!($($arg)*); }
    };
}

fn cmd_infer(args: InferArgs) -> anyhow::Result<()> {
    let q = args.quiet;
    let ingest_fmt = match args.format {
        InputFormat::Pcap      => IngestFormat::Pcap,
        InputFormat::Plaintext => IngestFormat::Plaintext,
        InputFormat::Syscall   => IngestFormat::Syscall,
        InputFormat::Raw       => {
            let hint = args.frame_hint.as_deref()
                .and_then(parse_frame_hint);
            IngestFormat::Raw(hint)
        }
    };

    info!(q, "ref2: ingesting {:?}", args.input);
    let pipeline = Pipeline::run(&args.input, ingest_fmt)
        .ok_or_else(|| anyhow::anyhow!("Failed to ingest {:?}", args.input))?;

    info!(q, "ref2: inferring format…");
    let schema = pipeline.infer_schema()
        .ok_or_else(|| anyhow::anyhow!("Format inference failed"))?;

    info!(q, "ref2: {} message type(s) inferred", schema.schemas.len());
    if args.verbose && !q {
        for ms in &schema.schemas {
            eprintln!("  [{}] {} field(s):", ms.name, ms.fields.len());
            for f in &ms.fields {
                eprintln!("    {:24} off={} len={} type={} H={:.2}",
                          f.name, f.offset, f.length, f.type_name(), f.entropy);
            }
        }
    }

    // Build schema name map for grammar induction.
    let schema_names: HashMap<u32, String> = schema.schemas.iter()
        .map(|ms| (ms.type_id, ms.name.clone()))
        .collect();

    // Extract session sequences.
    let sess = pipeline.sequences();
    info!(q, "ref2: {} session(s) available for grammar induction",
          sess.sequences.len());

    let algo = match args.algo {
        AlgoArg::Ktails => Algorithm::KTails,
        AlgoArg::Rpni   => Algorithm::Rpni,
    };

    info!(q, "ref2: running {:?} (k={})…", algo, args.k);
    let fsm = induce(&sess.sequences, args.k, algo, &schema_names, args.min_sessions);
    info!(q, "ref2: {} state(s), {} transition(s)",
          fsm.states.len(), fsm.transitions.len());

    // Anomaly scoring.
    let scores = score_anomalies(&fsm, &sess.sequences);
    let anomalous: Vec<_> = scores.iter().filter(|&&(_, s)| s > 0.5).collect();
    if !anomalous.is_empty() && !q {
        eprintln!("ref2: {} anomalous session(s) detected:", anomalous.len());
        for &(idx, score) in &anomalous {
            eprintln!("  session {idx}: anomaly_score={score:.3}");
        }
    }

    let emit_fmt = match args.emit {
        EmitArg::Json   => EmitFormat::Json,
        EmitArg::Dot    => EmitFormat::Dot,
        EmitArg::Scapy  => EmitFormat::Scapy,
        EmitArg::Lua    => EmitFormat::Lua,
        EmitArg::Kaitai => EmitFormat::Kaitai,
        EmitArg::All    => EmitFormat::All,
    };

    let input_name = args.input.file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("unknown");

    output::write_all(&args.output_dir, input_name, &schema, &fsm, emit_fmt, &scores)?;

    info!(q, "ref2: done → {}", args.output_dir.display());
    Ok(())
}

fn cmd_dissect(args: DissectArgs) -> anyhow::Result<()> {
    let schema_path = args.schema.join("schema.json");
    if !schema_path.exists() {
        anyhow::bail!("schema.json not found in {}", args.schema.display());
    }
    dissect::run_dissect(&args.schema, &args.input)
}

fn cmd_view(args: ViewArgs) -> anyhow::Result<()> {
    // Try rendering with dot(1) first, then fall back to xdg-open.
    let svg_path = args.dot_file.with_extension("svg");
    let status = std::process::Command::new("dot")
        .args(["-Tsvg", args.dot_file.to_str().unwrap_or(""),
               "-o", svg_path.to_str().unwrap_or("")])
        .status();

    match status {
        Ok(s) if s.success() => {
            eprintln!("ref2: rendered → {}", svg_path.display());
            // Try opening in browser/viewer.
            let _ = std::process::Command::new("open").arg(&svg_path).status()
                .or_else(|_| std::process::Command::new("xdg-open").arg(&svg_path).status());
        }
        _ => {
            eprintln!("ref2: dot(1) not found; open {} manually", args.dot_file.display());
        }
    }
    Ok(())
}

// ── Entry point ───────────────────────────────────────────────────────────────

fn main() {
    let cli = Cli::parse();
    // stash verbose for subcommands that want it
    let _verbose = cli.verbose;
    let result = match cli.command {
        Command::Infer(a)   => cmd_infer(a),
        Command::Dissect(a) => cmd_dissect(a),
        Command::View(a)    => cmd_view(a),
    };
    if let Err(e) = result {
        eprintln!("ref2 error: {e}");
        std::process::exit(1);
    }
}
