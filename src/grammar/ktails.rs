/// k-tails grammar induction algorithm.
///
/// Builds a Prefix Tree Acceptor (PTA) from session sequences, then merges
/// states whose k-length suffix sets are identical.

use std::collections::{BTreeSet, HashMap, HashSet, VecDeque};
use super::fsm::Fsm;

/// Prefix Tree Acceptor node.
#[derive(Debug, Default)]
struct PtaNode {
    children: HashMap<u32, usize>,  // msg_type → child node index
    is_terminal: bool,
    count: usize,
}

struct Pta {
    nodes: Vec<PtaNode>,
}

impl Pta {
    fn new() -> Self {
        Self { nodes: vec![PtaNode::default()] }
    }

    fn insert(&mut self, seq: &[u32]) {
        let mut cur = 0usize;
        self.nodes[cur].count += 1;
        for &sym in seq {
            let next = if let Some(&n) = self.nodes[cur].children.get(&sym) {
                n
            } else {
                let n = self.nodes.len();
                self.nodes.push(PtaNode::default());
                self.nodes[cur].children.insert(sym, n);
                n
            };
            cur = next;
            self.nodes[cur].count += 1;
        }
        self.nodes[cur].is_terminal = true;
    }

    /// Collect all suffixes of length ≤ k reachable from `node`.
    fn suffixes(&self, node: usize, k: usize) -> HashSet<Vec<u32>> {
        let mut result = HashSet::new();
        self.suffixes_rec(node, k, &mut Vec::new(), &mut result);
        result
    }

    fn suffixes_rec(&self, node: usize, k: usize,
                     current: &mut Vec<u32>,
                     out: &mut HashSet<Vec<u32>>) {
        out.insert(current.clone());
        if k == 0 { return; }
        for (&sym, &child) in &self.nodes[node].children {
            current.push(sym);
            self.suffixes_rec(child, k - 1, current, out);
            current.pop();
        }
    }
}

/// Union-Find for state merging.
struct UnionFind {
    parent: Vec<usize>,
    rank: Vec<usize>,
}

impl UnionFind {
    fn new(n: usize) -> Self {
        Self {
            parent: (0..n).collect(),
            rank: vec![0; n],
        }
    }

    fn find(&mut self, x: usize) -> usize {
        if self.parent[x] != x {
            self.parent[x] = self.find(self.parent[x]);
        }
        self.parent[x]
    }

    fn union(&mut self, a: usize, b: usize) {
        let ra = self.find(a);
        let rb = self.find(b);
        if ra == rb { return; }
        if self.rank[ra] < self.rank[rb] {
            self.parent[ra] = rb;
        } else if self.rank[ra] > self.rank[rb] {
            self.parent[rb] = ra;
        } else {
            self.parent[rb] = ra;
            self.rank[ra] += 1;
        }
    }
}

/// Determinise an NFA-like FSM via subset construction.
fn determinise(fsm: Fsm) -> Fsm {
    // subset construction — nothing fancy

    // Check if already deterministic: all (from, sym) pairs must be unique.
    let mut seen: HashSet<(u32, u32)> = HashSet::new();
    let mut is_nfa = false;
    for t in &fsm.transitions {
        if !seen.insert((t.from, t.message_type)) {
            is_nfa = true;
            break;
        }
    }
    if !is_nfa {
        // already deterministic, skip
        return fsm;
    }

    // Build adjacency: state_id -> HashMap<msg_type, Vec<state_id>>
    let mut adj: HashMap<u32, HashMap<u32, Vec<u32>>> = HashMap::new();
    // also keep schema_ref lookup (first one wins per sym, they should all match)
    let mut schema_lookup: HashMap<u32, String> = HashMap::new();
    for t in &fsm.transitions {
        adj.entry(t.from)
            .or_default()
            .entry(t.message_type)
            .or_default()
            .push(t.to);
        schema_lookup.entry(t.message_type).or_insert_with(|| t.schema_ref.clone());
    }

    let initial_id = fsm.initial_state();
    let accepting: HashSet<u32> = fsm.states.iter()
        .filter(|s| s.is_accepting)
        .map(|s| s.id)
        .collect();

    // subset -> new state id
    let mut subset_to_id: HashMap<BTreeSet<u32>, u32> = HashMap::new();
    let mut new_fsm = Fsm::new();
    let mut queue: VecDeque<BTreeSet<u32>> = VecDeque::new();

    let start: BTreeSet<u32> = std::iter::once(initial_id).collect();
    let start_is_accepting = start.iter().any(|id| accepting.contains(id));
    let start_id = new_fsm.add_state("INIT", true, start_is_accepting);
    subset_to_id.insert(start.clone(), start_id);
    queue.push_back(start);

    while let Some(subset) = queue.pop_front() {
        let from_new = subset_to_id[&subset];

        // Collect all symbols reachable from any state in this subset.
        let mut sym_targets: HashMap<u32, BTreeSet<u32>> = HashMap::new();
        for &sid in &subset {
            if let Some(edges) = adj.get(&sid) {
                for (&sym, targets) in edges {
                    sym_targets.entry(sym).or_default().extend(targets.iter().copied());
                }
            }
        }

        for (sym, target_subset) in sym_targets {
            let to_new = if let Some(&id) = subset_to_id.get(&target_subset) {
                id
            } else {
                let is_acc = target_subset.iter().any(|id| accepting.contains(id));
                let label = format!("S{}", new_fsm.states.len());
                let id = new_fsm.add_state(&label, false, is_acc);
                subset_to_id.insert(target_subset.clone(), id);
                queue.push_back(target_subset.clone());
                id
            };

            // Sum frequencies from all original transitions in this subset on `sym`.
            let mut freq_sum = 0.0_f64;
            let mut freq_count = 0usize;
            for &sid in &subset {
                for t in &fsm.transitions {
                    if t.from == sid && t.message_type == sym {
                        freq_sum += t.frequency;
                        freq_count += 1;
                    }
                }
            }
            // Normalise by count so we don't exceed 1.0 from duplicates.
            let freq = if freq_count > 0 { freq_sum / freq_count as f64 } else { 0.0 };
            let schema_ref = schema_lookup.get(&sym)
                .cloned()
                .unwrap_or_else(|| format!("msg_type_{:02}", sym));
            new_fsm.add_transition(from_new, to_new, sym, &schema_ref, freq);
        }
    }

    new_fsm
}

/// Run the k-tails algorithm on a set of session sequences.
///
/// `k` controls how many future steps are compared when merging states.
/// `schema_names` maps `msg_type_id → schema name` for transition labels.
pub fn infer_ktails(sequences: &[Vec<u32>], k: usize,
                    schema_names: &HashMap<u32, String>) -> Fsm {
    // Filter sequences shorter than 3.
    let seqs: Vec<&Vec<u32>> = sequences.iter()
        .filter(|s| s.len() >= 3)
        .collect();

    if seqs.is_empty() {
        return Fsm::new();
    }

    // Build PTA.
    let mut pta = Pta::new();
    for seq in &seqs {
        pta.insert(seq);
    }

    let n = pta.nodes.len();
    let mut uf = UnionFind::new(n);

    // Compute suffix sets for all nodes.
    let suffix_sets: Vec<HashSet<Vec<u32>>> = (0..n)
        .map(|i| pta.suffixes(i, k))
        .collect();

    // Merge states with identical k-suffix sets.
    for i in 0..n {
        for j in (i + 1)..n {
            if suffix_sets[i] == suffix_sets[j] {
                uf.union(i, j);
            }
        }
    }

    // Build the merged FSM.
    // Collect unique representative states.
    let mut repr_set: HashSet<usize> = (0..n).map(|i| uf.find(i)).collect();
    let mut repr_list: Vec<usize> = repr_set.drain().collect();
    repr_list.sort_unstable();

    let state_map: HashMap<usize, u32> = repr_list.iter()
        .enumerate()
        .map(|(idx, &repr)| (repr, idx as u32))
        .collect();

    let mut fsm = Fsm::new();

    for &repr in &repr_list {
        let is_initial   = repr == uf.find(0);
        let is_accepting = pta.nodes[repr].is_terminal ||
            (0..n).any(|i| uf.find(i) == repr && pta.nodes[i].is_terminal);
        let label = if is_initial {
            "INIT".to_string()
        } else {
            format!("S{}", state_map[&repr])
        };
        fsm.add_state(&label, is_initial, is_accepting);
    }

    // Emit transitions: for each PTA node, add its edges to the FSM.
    let total_seqs = seqs.len() as f64;
    let mut transition_counts: HashMap<(u32, u32, u32), usize> = HashMap::new();

    for i in 0..n {
        let from_repr = uf.find(i);
        let from_id   = state_map[&from_repr];
        for (&sym, &child) in &pta.nodes[i].children {
            let to_repr = uf.find(child);
            let to_id   = state_map[&to_repr];
            *transition_counts.entry((from_id, to_id, sym)).or_insert(0) +=
                pta.nodes[i].count;
        }
    }

    for ((from, to, sym), cnt) in transition_counts {
        let freq = cnt as f64 / total_seqs;
        let schema_ref = schema_names
            .get(&sym)
            .cloned()
            .unwrap_or_else(|| format!("msg_type_{:02}", sym));
        fsm.add_transition(from, to, sym, &schema_ref, freq);
    }

    determinise(fsm)
}
