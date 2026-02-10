/// FFI bindings to libref2.a (C inference core).
///
/// We expose safe Rust wrappers around the raw C types so the rest of the
/// Rust codebase never touches raw pointers.

use std::ffi::{CString, c_char, c_int, c_double};
use std::path::Path;

// ── Raw C types (must match the C headers exactly) ───────────────────────────

#[repr(C)]
#[allow(dead_code)]
pub enum CSourceT {
    Pcap      = 0,
    Raw       = 1,
    Plaintext = 2,
    Syscall   = 3,
}

#[repr(C)]
pub struct CMessageT {
    pub timestamp_us: u64,
    pub direction:    u8,
    pub payload:      *mut u8,
    pub payload_len:  usize,
    pub source:       CSourceT,
    pub session_id:   u32,
}

#[repr(C)]
pub struct CSessionT {
    pub messages:   *mut CMessageT,
    pub count:      usize,
    pub session_id: u32,
}

#[repr(C)]
pub struct CTraceT {
    pub sessions: *mut CSessionT,
    pub count:    usize,
}

#[repr(C)]
pub struct CFrameHintT {
    pub frame_type:     c_int,
    pub header_size:    usize,
    pub length_offset:  usize,
    pub length_width:   usize,
    pub length_endian:  c_int,
    pub delimiter:      [u8; 4],
    pub delimiter_len:  usize,
}

#[repr(C)]
pub struct CFramingInfoT {
    pub header_len:        usize,
    pub has_length_field:  c_int,
    pub length_offset:     usize,
    pub length_width:      usize,
    pub length_endian:     c_int,
    pub length_adjustment: i32,
    pub has_type_field:    c_int,
    pub type_offset:       usize,
    pub type_width:        usize,
    pub has_delimiter:     c_int,
    pub delimiter:         [u8; 4],
    pub delimiter_len:     usize,
}

#[repr(C)]
pub struct CTokenT {
    pub data:      *mut u8,
    pub len:       usize,
    pub type_hint: u32,
}

#[repr(C)]
pub struct CTokenStreamT {
    pub tokens:     *mut CTokenT,
    pub count:      usize,
    pub session_id: u32,
}

#[repr(C)]
pub struct CFieldT {
    pub offset:      usize,
    pub length:      usize,
    pub field_type:  c_int,
    pub name:        [c_char; 64],
    pub entropy:     c_double,
    pub enum_values: [u32; 16],
    pub enum_count:  usize,
}

#[repr(C)]
pub struct CMessageSchemaT {
    pub type_id:     u32,
    pub fields:      *mut CFieldT,
    pub field_count: usize,
    pub name:        [c_char; 64],
}

#[repr(C)]
pub struct CProtocolSchemaT {
    pub schemas:      *mut CMessageSchemaT,
    pub schema_count: usize,
}

// ── C function signatures ────────────────────────────────────────────────────

extern "C" {
    pub fn ingest_pcap     (path: *const c_char) -> *mut CTraceT;
    pub fn ingest_raw      (path: *const c_char, hint: *const CFrameHintT) -> *mut CTraceT;
    pub fn ingest_plaintext(path: *const c_char) -> *mut CTraceT;
    pub fn ingest_syscall  (path: *const c_char) -> *mut CTraceT;
    pub fn trace_free      (trace: *mut CTraceT);

    pub fn tokenize_trace  (trace: *const CTraceT,
                             framing_out: *mut *mut CFramingInfoT)
                             -> *mut *mut CTokenStreamT;
    pub fn token_stream_free(stream: *mut CTokenStreamT);
    pub fn framing_info_free(fi: *mut CFramingInfoT);

    pub fn infer_format    (streams: *mut *mut CTokenStreamT,
                             stream_count: usize,
                             framing: *const CFramingInfoT)
                             -> *mut CProtocolSchemaT;
    pub fn protocol_schema_free(schema: *mut CProtocolSchemaT);
}

// ── Safe Rust wrappers ───────────────────────────────────────────────────────

/// Safe representation of a field type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FieldTypeId {
    Magic, Constant, Enum, SequenceNumber, Length,
    Payload, Nonce, Str, Opaque,
}

impl From<c_int> for FieldTypeId {
    fn from(v: c_int) -> Self {
        match v {
            0 => Self::Magic,
            1 => Self::Constant,
            2 => Self::Enum,
            3 => Self::SequenceNumber,
            4 => Self::Length,
            5 => Self::Payload,
            6 => Self::Nonce,
            7 => Self::Str,
            _ => Self::Opaque,
        }
    }
}

pub struct Field {
    pub offset:      usize,
    pub length:      usize,
    pub field_type:  FieldTypeId,
    pub name:        String,
    pub entropy:     f64,
    pub enum_values: [u32; 16],
    pub enum_count:  usize,
    /// First byte value seen (for magic constant display). */
    pub example_byte: Option<u8>,
}

impl Field {
    pub fn type_name(&self) -> &'static str {
        match self.field_type {
            FieldTypeId::Magic          => "MAGIC",
            FieldTypeId::Constant       => "CONSTANT",
            FieldTypeId::Enum           => "ENUM",
            FieldTypeId::SequenceNumber => "SEQUENCE_NUMBER",
            FieldTypeId::Length         => "LENGTH",
            FieldTypeId::Payload        => "PAYLOAD",
            FieldTypeId::Nonce          => "NONCE",
            FieldTypeId::Str            => "STRING",
            FieldTypeId::Opaque         => "OPAQUE",
        }
    }
}

pub struct MessageSchema {
    pub type_id:     u32,
    pub name:        String,
    pub fields:      Vec<Field>,
}

pub struct ProtocolSchema {
    pub schemas: Vec<MessageSchema>,
    raw: *mut CProtocolSchemaT,
}

// SAFETY: we never share ProtocolSchema across threads.
unsafe impl Send for ProtocolSchema {}
unsafe impl Sync for ProtocolSchema {}

impl Drop for ProtocolSchema {
    fn drop(&mut self) {
        if !self.raw.is_null() {
            unsafe { protocol_schema_free(self.raw); }
        }
    }
}

/// Safe session/message sequence extraction (for grammar induction).
pub struct SessionSequences {
    pub sequences: Vec<Vec<u32>>,
}

/// Ingest a trace from disk using the specified format.
pub enum IngestFormat { Pcap, Raw(Option<CFrameHintT>), Plaintext, Syscall }

pub struct Pipeline {
    trace:   *mut CTraceT,
    framing: *mut CFramingInfoT,
    streams: *mut *mut CTokenStreamT,
    nstreams: usize,
}

impl Pipeline {
    pub fn run(path: &Path, fmt: IngestFormat) -> Option<Self> {
        let c_path = CString::new(path.to_str()?).ok()?;

        let trace = unsafe {
            match &fmt {
                IngestFormat::Pcap        => ingest_pcap(c_path.as_ptr()),
                IngestFormat::Plaintext   => ingest_plaintext(c_path.as_ptr()),
                IngestFormat::Syscall     => ingest_syscall(c_path.as_ptr()),
                IngestFormat::Raw(hint) => {
                    let p = hint.as_ref().map(|h| h as *const _)
                                .unwrap_or(std::ptr::null());
                    ingest_raw(c_path.as_ptr(), p)
                }
            }
        };
        if trace.is_null() { return None; }

        let mut framing: *mut CFramingInfoT = std::ptr::null_mut();
        let streams = unsafe {
            tokenize_trace(trace, &mut framing as *mut _)
        };
        if streams.is_null() {
            unsafe { trace_free(trace); }
            return None;
        }

        let nstreams = unsafe { (*trace).count };

        Some(Self { trace, framing, streams, nstreams })
    }

    pub fn infer_schema(&self) -> Option<ProtocolSchema> {
        let raw = unsafe {
            infer_format(self.streams, self.nstreams, self.framing)
        };
        if raw.is_null() { return None; }

        Some(self.build_safe_schema(raw))
    }

    fn build_safe_schema(&self, raw: *mut CProtocolSchemaT) -> ProtocolSchema {
        let mut schemas = Vec::new();
        unsafe {
            let ps = &*raw;
            for i in 0..ps.schema_count {
                let ms = &*ps.schemas.add(i);
                let name = c_str_to_string(&ms.name);
                let mut fields = Vec::new();
                for j in 0..ms.field_count {
                    let f = &*ms.fields.add(j);
                    fields.push(Field {
                        offset:      f.offset,
                        length:      f.length,
                        field_type:  FieldTypeId::from(f.field_type),
                        name:        c_str_to_string(&f.name),
                        entropy:     f.entropy,
                        enum_values: f.enum_values,
                        enum_count:  f.enum_count,
                        example_byte: None,
                    });
                }
                schemas.push(MessageSchema { type_id: ms.type_id, name, fields });
            }
        }
        ProtocolSchema { schemas, raw }
    }

    /// Extract per-session message type sequences for grammar induction.
    pub fn sequences(&self) -> SessionSequences {
        let mut sequences = Vec::new();
        unsafe {
            for i in 0..self.nstreams {
                let ts = &**self.streams.add(i);
                let seq: Vec<u32> = (0..ts.count)
                    .map(|j| (*ts.tokens.add(j)).type_hint)
                    .collect();
                sequences.push(seq);
            }
        }
        SessionSequences { sequences }
    }
}

impl Drop for Pipeline {
    fn drop(&mut self) {
        unsafe {
            for i in 0..self.nstreams {
                token_stream_free(*self.streams.add(i));
            }
            // streams itself is malloc'd by C
            if !self.streams.is_null() {
                libc_free(self.streams as *mut _);
            }
            framing_info_free(self.framing);
            trace_free(self.trace);
        }
    }
}

extern "C" {
    fn free(ptr: *mut std::ffi::c_void);
}
fn libc_free(ptr: *mut std::ffi::c_void) {
    unsafe { free(ptr) }
}

fn c_str_to_string(arr: &[c_char]) -> String {
    let bytes: Vec<u8> = arr.iter()
        .take_while(|&&c| c != 0)
        .map(|&c| c as u8)
        .collect();
    String::from_utf8_lossy(&bytes).into_owned()
}
