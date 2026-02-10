/// Finite-state machine types produced by grammar induction.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct State {
    pub id: u32,
    pub label: String,
    pub is_initial: bool,
    pub is_accepting: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Transition {
    pub from: u32,
    pub to: u32,
    pub message_type: u32,
    /// Name of the message_schema_t this transition corresponds to.
    pub schema_ref: String,
    /// Fraction of sessions that used this transition.
    pub frequency: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Fsm {
    pub states: Vec<State>,
    pub transitions: Vec<Transition>,
}

impl Fsm {
    pub fn new() -> Self {
        Self {
            states: Vec::new(),
            transitions: Vec::new(),
        }
    }

    /// Add a state, returning its id.
    pub fn add_state(&mut self, label: &str, initial: bool, accepting: bool) -> u32 {
        let id = self.states.len() as u32;
        self.states.push(State {
            id,
            label: label.to_string(),
            is_initial: initial,
            is_accepting: accepting,
        });
        id
    }

    pub fn add_transition(&mut self, from: u32, to: u32, msg_type: u32,
                          schema_ref: &str, freq: f64) {
        self.transitions.push(Transition {
            from,
            to,
            message_type: msg_type,
            schema_ref: schema_ref.to_string(),
            frequency: freq,
        });
    }

    /// Find the single initial state, or 0 if not uniquely defined.
    pub fn initial_state(&self) -> u32 {
        self.states.iter()
            .find(|s| s.is_initial)
            .map(|s| s.id)
            .unwrap_or(0)
    }

    /// Compute Viterbi log-probability for a sequence of message type labels.
    /// Returns `f64::NEG_INFINITY` for sequences with unknown transitions.
    pub fn viterbi_log_prob(&self, sequence: &[u32]) -> f64 {
        if sequence.is_empty() {
            return 0.0;
        }

        let init = self.initial_state();
        let mut current_state = init;
        let mut log_prob = 0.0_f64;

        for &msg_type in sequence {
            let tr = self.transitions.iter().find(|t| {
                t.from == current_state && t.message_type == msg_type
            });
            match tr {
                None => return f64::NEG_INFINITY,
                Some(t) => {
                    let freq = t.frequency.max(1e-9);
                    log_prob += freq.ln();
                    current_state = t.to;
                }
            }
        }

        log_prob
    }

    /// Anomaly score in [0, 1]: 0 = fully normal, 1 = unknown sequence.
    pub fn anomaly_score(&self, sequence: &[u32]) -> f64 {
        let lp = self.viterbi_log_prob(sequence);
        if lp == f64::NEG_INFINITY {
            return 1.0;
        }
        // Normalise: scale to [0,1] using logistic transform.
        let normalised = -lp / (sequence.len().max(1) as f64);
        1.0 - (-normalised).exp()
    }
}

impl Default for Fsm {
    fn default() -> Self { Self::new() }
}
