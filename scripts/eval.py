#!/usr/bin/env python3
"""
eval.py — ref2 evaluation harness

generates synthetic traces with known ground-truth field layouts, runs ref2
on them, then computes field recall, field precision, and type accuracy.

optionally compares against netzob if it's installed.

usage:
    python3 scripts/eval.py [--ref2 path/to/ref2] [--netzob] [--n-sessions N]
"""

import argparse
import json
import math
import os
import random
import shutil
import struct
import subprocess
import sys
import tempfile
import time

# ── synthetic protocol definitions ────────────────────────────────────────────

# each protocol is a dict:
#   name      — display name
#   msg_types — list of message type dicts:
#       encode(seq)  — returns bytes for that message
#       fields       — ground-truth field list: (offset, length, type_hint)
#   sessions  — callable(n) → list of message-type sequences per session

PROTOCOLS = []


def proto(name):
    def dec(fn):
        PROTOCOLS.append({"name": name, "factory": fn})
        return fn
    return dec


@proto("simple_req_resp")
def proto_simple_req_resp():
    """
    ff fe <u8:len> <u8:seq> <payload>  — request
    ff fe <u8:len> 00       "ok"       — response
    ground truth: magic(2), length(1), type_or_seq(1), payload(var)
    """
    gt_req = [(0, 2, "MAGIC"), (2, 1, "LENGTH"), (3, 1, "SEQUENCE_NUMBER"), (4, 0, "PAYLOAD")]
    gt_rsp = [(0, 2, "MAGIC"), (2, 1, "LENGTH"), (3, 1, "CONSTANT"),        (4, 0, "PAYLOAD")]

    def req(seq, payload=None):
        if payload is None:
            payload = os.urandom(random.randint(4, 24))
        total = 4 + len(payload)
        return bytes([0xff, 0xfe, total & 0xff, seq & 0xff]) + payload

    def rsp(seq):
        body = os.urandom(random.randint(2, 12))
        total = 4 + len(body)
        return bytes([0xff, 0xfe, total & 0xff, 0x00]) + body

    def make_sessions(n):
        sessions = []
        for _ in range(n):
            msgs = []
            for i in range(random.randint(4, 12)):
                msgs.append(("req", i))
                msgs.append(("rsp", i))
            sessions.append(msgs)
        return sessions

    def encode(msg_type, seq):
        if msg_type == "req":
            return req(seq)
        return rsp(seq)

    return {
        "sessions": make_sessions,
        "encode": encode,
        "ground_truth": {
            "req": gt_req,
            "rsp": gt_rsp,
        },
        "types": ["req", "rsp"],
    }


@proto("enum_flags_proto")
def proto_enum_flags():
    """
    de ad <u8:len> <u8:opcode> <u8:flags> <payload>
    opcodes: 0x01=HELLO, 0x02=DATA, 0x03=FIN
    flags:   bitmask (low entropy but not constant)
    ground truth: magic(2), length(1), enum(1), opaque(1), payload(var)
    """
    OPCODES = [0x01, 0x02, 0x03]
    gt = [(0, 2, "MAGIC"), (2, 1, "LENGTH"), (3, 1, "ENUM"), (4, 1, "OPAQUE"), (5, 0, "PAYLOAD")]

    def encode(opcode_idx, seq):
        opcode = OPCODES[opcode_idx % len(OPCODES)]
        flags  = random.randint(0, 7)
        payload = os.urandom(random.randint(2, 64))
        total = 5 + len(payload)
        hdr = struct.pack(">H", 0xdead) + bytes([total & 0xff, opcode, flags])
        return hdr + payload

    def make_sessions(n):
        sessions = []
        for _ in range(n):
            msgs = [(i % 3, i) for i in range(random.randint(5, 15))]
            sessions.append(msgs)
        return sessions

    return {
        "sessions": make_sessions,
        "encode": encode,
        "ground_truth": {"default": gt},
        "types": ["default"],
    }


@proto("text_crlf_proto")
def proto_text_crlf():
    """
    simple text-based protocol: CMD arg\r\n  +  OK result\r\n
    no binary fields, delimited by CRLF
    ground truth is less precise — just check delimiter detected
    """
    CMDS = ["GET", "SET", "DEL"]

    def encode(msg_type, seq):
        if msg_type == "cmd":
            cmd = CMDS[seq % len(CMDS)]
            return f"{cmd} key{seq}\r\n".encode()
        else:
            return f"OK {seq}\r\n".encode()

    def make_sessions(n):
        sessions = []
        for _ in range(n):
            msgs = []
            for i in range(random.randint(3, 8)):
                msgs.append(("cmd", i))
                msgs.append(("rsp", i))
            sessions.append(msgs)
        return sessions

    # text protocols: we mainly check delimiter detection
    return {
        "sessions": make_sessions,
        "encode": encode,
        "ground_truth": {"cmd": [], "rsp": []},
        "types": ["cmd", "rsp"],
        "text_proto": True,
    }


# ── trace file generation ─────────────────────────────────────────────────────

def write_trace(proto_def, sessions, path):
    """write a direction-prefixed hex plaintext trace"""
    lines = []
    types = proto_def["types"]
    for sess in sessions:
        for i, entry in enumerate(sess):
            if isinstance(entry, tuple):
                msg_type, seq = entry
            else:
                msg_type, seq = types[entry % len(types)], entry
            raw = proto_def["encode"](msg_type, seq)
            direction = ">>" if i % 2 == 0 else "<<"
            hex_bytes = " ".join(f"{b:02x}" for b in raw)
            lines.append(f"{direction} {hex_bytes}")
        lines.append("")  # session separator (blank line — ref2 treats this as new session)
    with open(path, "w") as f:
        f.write("\n".join(lines) + "\n")


# ── evaluation metrics ────────────────────────────────────────────────────────

def field_boundaries(fields):
    """return set of (offset, offset+length) tuples"""
    bds = set()
    for f in fields:
        offset, length = f[0], f[1]
        if length > 0:
            bds.add((offset, offset + length))
    return bds


def evaluate_schema(inferred_schema, ground_truth_fields):
    """
    compute field-level precision and recall.
    inferred_schema: list of {"offset": N, "length": N, "type": "..."} dicts
    ground_truth_fields: list of (offset, length, type) tuples
    """
    inferred_bounds = set()
    for f in inferred_schema:
        if f.get("length", 0) > 0:
            inferred_bounds.add((f["offset"], f["offset"] + f["length"]))

    gt_bounds = field_boundaries(ground_truth_fields)

    if not gt_bounds and not inferred_bounds:
        return 1.0, 1.0, 0

    tp = len(inferred_bounds & gt_bounds)
    precision = tp / len(inferred_bounds) if inferred_bounds else 0.0
    recall    = tp / len(gt_bounds)       if gt_bounds    else 0.0

    # type accuracy: for fields that matched, check type
    type_correct = 0
    type_total   = 0
    gt_by_offset = {f[0]: f[2] for f in ground_truth_fields}
    for f in inferred_schema:
        off = f.get("offset", -1)
        if off in gt_by_offset:
            type_total += 1
            # loose match: inferred type just needs to start with gt type prefix
            inferred_type = f.get("type", "").upper()
            gt_type = gt_by_offset[off].upper()
            if inferred_type == gt_type or inferred_type.startswith(gt_type[:3]):
                type_correct += 1

    type_acc = type_correct / type_total if type_total else 0.0
    return precision, recall, type_acc


# ── ref2 runner ───────────────────────────────────────────────────────────────

def run_ref2(ref2_bin, trace_path, output_dir):
    t0 = time.monotonic()
    result = subprocess.run(
        [ref2_bin, "infer",
         "--input",      str(trace_path),
         "--format",     "plaintext",
         "--output-dir", str(output_dir),
         "--emit",       "json"],
        capture_output=True, text=True, timeout=60,
    )
    elapsed = time.monotonic() - t0

    if result.returncode != 0:
        return None, elapsed, result.stderr

    schema_path = os.path.join(output_dir, "schema.json")
    if not os.path.exists(schema_path):
        return None, elapsed, "schema.json not written"

    with open(schema_path) as f:
        schema = json.load(f)

    return schema, elapsed, None


# ── netzob comparison (optional) ──────────────────────────────────────────────

def run_netzob(trace_path, output_dir):
    try:
        import netzob
    except ImportError:
        return None, 0.0, "netzob not installed (pip install netzob)"

    # netzob api changes between versions; try common patterns
    try:
        from netzob.Model.Vocabulary.Messages.RawMessage import RawMessage
        from netzob.Inference.Vocabulary.FormatOperations.FieldSplitter import FieldSplitter
    except ImportError:
        return None, 0.0, "netzob api not compatible (need 1.0.x)"

    messages = []
    t0 = time.monotonic()
    with open(trace_path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split()
            if parts[0] in (">>", "<<"):
                try:
                    raw = bytes.fromhex("".join(parts[1:]))
                    messages.append(RawMessage(raw))
                except ValueError:
                    pass

    if not messages:
        return None, 0.0, "no messages parsed"

    try:
        from netzob.Inference.Vocabulary.ClusterByKeyField import ClusterByKeyField
        symbol = netzob.Symbol(messages=messages)
        FieldSplitter.split(symbol, mergeIfHigh=False)
        elapsed = time.monotonic() - t0
        nfields = len(symbol.fields)
        return {"nfields": nfields}, elapsed, None
    except Exception as e:
        return None, time.monotonic() - t0, str(e)


# ── main ──────────────────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser(description="evaluate ref2 field inference")
    ap.add_argument("--ref2",       default=None, help="path to ref2 binary")
    ap.add_argument("--netzob",     action="store_true", help="also run netzob")
    ap.add_argument("--n-sessions", type=int, default=20, help="sessions per protocol")
    ap.add_argument("--seed",       type=int, default=42)
    args = ap.parse_args()

    random.seed(args.seed)

    # find binary
    ref2_bin = args.ref2
    if ref2_bin is None:
        candidates = [
            "./target/release/ref2",
            "./target/debug/ref2",
        ]
        for c in candidates:
            if os.path.isfile(c):
                ref2_bin = c
                break
    if ref2_bin is None or not os.path.isfile(ref2_bin):
        print("error: ref2 binary not found; build with `cargo build` first", file=sys.stderr)
        print("       or pass --ref2 /path/to/ref2", file=sys.stderr)
        sys.exit(1)

    print(f"using ref2: {ref2_bin}")
    print(f"sessions per protocol: {args.n_sessions}")
    print()

    results = []

    for proto_entry in PROTOCOLS:
        name = proto_entry["name"]
        pdef = proto_entry["factory"]()

        sessions = pdef["sessions"](args.n_sessions)
        is_text  = pdef.get("text_proto", False)

        with tempfile.TemporaryDirectory() as tmpdir:
            trace_path  = os.path.join(tmpdir, "trace.txt")
            output_dir  = os.path.join(tmpdir, "out")
            os.makedirs(output_dir, exist_ok=True)

            write_trace(pdef, sessions, trace_path)
            n_msgs = sum(len(s) for s in sessions)

            # run ref2
            schema, elapsed_ref2, err = run_ref2(ref2_bin, trace_path, output_dir)

            if err or schema is None:
                print(f"[{name}] ref2 FAILED: {err}")
                results.append({"proto": name, "ref2_ok": False})
                continue

            n_types = len(schema.get("message_types", []))

            # evaluate against ground truth
            gt = pdef["ground_truth"]
            all_precisions, all_recalls, all_type_accs = [], [], []

            for mt in schema.get("message_types", []):
                inferred_fields = mt.get("fields", [])
                # match to best ground-truth type (pick the one with highest recall)
                best_p, best_r, best_t = 0.0, 0.0, 0.0
                for gt_type, gt_fields in gt.items():
                    if not gt_fields:
                        continue
                    p, r, t = evaluate_schema(inferred_fields, gt_fields)
                    if r > best_r:
                        best_p, best_r, best_t = p, r, t
                if best_r > 0 or best_p > 0:
                    all_precisions.append(best_p)
                    all_recalls.append(best_r)
                    all_type_accs.append(best_t)

            avg_p = sum(all_precisions)/len(all_precisions) if all_precisions else 0.0
            avg_r = sum(all_recalls)/len(all_recalls)       if all_recalls    else 0.0
            avg_t = sum(all_type_accs)/len(all_type_accs)   if all_type_accs  else 0.0

            # netzob comparison
            netzob_nfields = None
            elapsed_netzob = None
            if args.netzob:
                nz_result, nz_elapsed, nz_err = run_netzob(trace_path, output_dir)
                elapsed_netzob = nz_elapsed
                if nz_result:
                    netzob_nfields = nz_result.get("nfields")
                else:
                    netzob_nfields = f"err: {nz_err}"

            row = {
                "proto":          name,
                "n_msgs":         n_msgs,
                "ref2_types":     n_types,
                "ref2_time_s":    elapsed_ref2,
                "field_precision": avg_p,
                "field_recall":   avg_r,
                "type_accuracy":  avg_t,
                "text_proto":     is_text,
            }
            if args.netzob:
                row["netzob_fields"] = netzob_nfields
                row["netzob_time_s"] = elapsed_netzob

            results.append(row)

    # ── print results table ────────────────────────────────────────────────────
    print("=" * 72)
    print(f"{'protocol':<25} {'msgs':>5} {'types':>5} {'prec':>6} {'rec':>6} {'tacc':>6} {'time':>7}")
    print("-" * 72)
    for r in results:
        if not r.get("ref2_ok", True):
            print(f"{r['proto']:<25}  FAILED")
            continue
        text_note = " (text)" if r.get("text_proto") else ""
        print(
            f"{r['proto']:<25} "
            f"{r['n_msgs']:>5} "
            f"{r['ref2_types']:>5} "
            f"{r['field_precision']:>5.1%} "
            f"{r['field_recall']:>5.1%} "
            f"{r['type_accuracy']:>5.1%} "
            f"{r['ref2_time_s']:>6.2f}s"
            f"{text_note}"
        )
        if args.netzob and "netzob_fields" in r:
            nz = r["netzob_fields"]
            nt = r.get("netzob_time_s", 0)
            print(f"  netzob: {nz} fields in {nt:.2f}s")
    print("=" * 72)

    # summary
    ok = [r for r in results if r.get("ref2_ok", True) and not r.get("text_proto")]
    if ok:
        avg_p = sum(r["field_precision"] for r in ok) / len(ok)
        avg_r = sum(r["field_recall"]    for r in ok) / len(ok)
        avg_t = sum(r["type_accuracy"]   for r in ok) / len(ok)
        avg_s = sum(r["ref2_time_s"]     for r in ok) / len(ok)
        print(f"\nbinary proto averages (n={len(ok)}): "
              f"precision={avg_p:.1%}  recall={avg_r:.1%}  "
              f"type_acc={avg_t:.1%}  time={avg_s:.2f}s")

    # messages/sec throughput
    for r in ok:
        if r.get("ref2_time_s", 0) > 0:
            mps = r["n_msgs"] / r["ref2_time_s"]
            print(f"  [{r['proto']}] {mps:.0f} msgs/s")


if __name__ == "__main__":
    main()
