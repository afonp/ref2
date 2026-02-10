pub mod fsm;
pub mod ktails;
pub mod rpni;

pub use fsm::Fsm;
pub use ktails::infer_ktails;
pub use rpni::infer_rpni;

use std::collections::HashMap;

/// Induction algorithm selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Algorithm {
    KTails,
    Rpni,
}

/// Run grammar induction on session sequences.
///
/// `sequences`    — per-session ordered list of message type IDs
/// `k`            — k-tails depth
/// `algo`         — which algorithm to use
/// `schema_names` — maps type_id → schema name for FSM labels
/// `min_sessions` — minimum sessions required; returns empty FSM if below
pub fn induce(
    sequences: &[Vec<u32>],
    k: usize,
    algo: Algorithm,
    schema_names: &HashMap<u32, String>,
    min_sessions: usize,
) -> Fsm {
    let valid: Vec<Vec<u32>> = sequences.iter()
        .filter(|s| s.len() >= 3)
        .cloned()
        .collect();

    if valid.len() < min_sessions {
        eprintln!("ref2: only {} sessions (≥3 msgs); need {}; skipping grammar induction",
                  valid.len(), min_sessions);
        return Fsm::new();
    }

    match algo {
        Algorithm::KTails => infer_ktails(&valid, k, schema_names),
        Algorithm::Rpni   => infer_rpni(&valid, schema_names),
    }
}

/// Score each session for anomalies.  Returns a Vec of (session_idx, score).
pub fn score_anomalies(fsm: &Fsm, sequences: &[Vec<u32>]) -> Vec<(usize, f64)> {
    sequences.iter()
        .enumerate()
        .map(|(i, seq)| (i, fsm.anomaly_score(seq)))
        .collect()
}
