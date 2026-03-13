// integration test: toy protocol
//
// builds a simple direction-prefixed hex trace, runs `ref2 infer` on it,
// and checks that schema.json appears in the output directory.
//
// requires the binary to be built first (cargo test builds it automatically).

use std::fs;
use std::path::Path;
use std::process::Command;

fn write_toy_trace(path: &Path) {
    // tiny request/response exchange: 8 round trips
    // REQ:  ff fe <len> <seq> hello<i>
    // RESP: ff fe <len> 00    ok
    let mut lines = Vec::new();
    for i in 0u8..8 {
        let payload = format!("hello{i}");
        let plen = (4 + payload.len()) as u8;
        let req: Vec<u8> = [0xff, 0xfe, plen, i]
            .iter().copied().chain(payload.bytes()).collect();
        let req_hex = req.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(" ");
        lines.push(format!(">> {req_hex}"));

        let plen2 = (4 + 2) as u8;
        let resp: Vec<u8> = vec![0xff, 0xfe, plen2, 0x00, b'o', b'k'];
        let resp_hex = resp.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(" ");
        lines.push(format!("<< {resp_hex}"));
    }
    fs::write(path, lines.join("\n") + "\n").unwrap();
}

fn ref2_bin() -> std::path::PathBuf {
    // cargo puts the binary in target/debug or target/release
    let mut p = std::env::current_exe().unwrap();
    // walk up until we find a "target" dir, then look for ref2
    loop {
        p.pop();
        if p.ends_with("target") || p.file_name().map(|n| n == "target").unwrap_or(false) {
            break;
        }
        if p.parent().is_none() { break; }
    }
    // p should be something like …/target/debug/deps — go up one
    p.pop();
    p.push("ref2");
    p
}

#[test]
fn test_infer_toy_protocol() {
    let dir = tempfile::tempdir().expect("need tempdir");
    let trace = dir.path().join("toy.txt");
    let out   = dir.path().join("out");
    write_toy_trace(&trace);

    let bin = ref2_bin();
    if !bin.exists() {
        // binary not built yet — skip rather than fail
        eprintln!("skip: ref2 binary not found at {}", bin.display());
        return;
    }

    let status = Command::new(&bin)
        .args(["infer",
               "--input",      trace.to_str().unwrap(),
               "--format",     "plaintext",
               "--output-dir", out.to_str().unwrap(),
               "--emit",       "json"])
        .status()
        .expect("failed to run ref2");

    assert!(status.success(), "ref2 infer exited with {status}");

    let schema = out.join("schema.json");
    assert!(schema.exists(), "schema.json not written to {}", out.display());

    // basic sanity: file should be valid JSON with a "message_types" array
    let raw = fs::read_to_string(&schema).unwrap();
    let v: serde_json::Value = serde_json::from_str(&raw)
        .expect("schema.json is not valid JSON");
    let types = v["message_types"].as_array().expect("no message_types array");
    assert!(!types.is_empty(), "message_types array is empty");
}
