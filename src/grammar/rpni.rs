/// RPNI (Regular Positive and Negative Inference) / Blue-Fringe algorithm.
///
/// More accurate than k-tails when ≥ 20 sessions are available.
/// Requires only positive examples (all observed sequences are treated as
/// positive; the algorithm avoids merges that create contradictions).

use std::collections::{HashMap, HashSet, VecDeque};
use super::fsm::Fsm;

// ── PTA ──────────────────────────────────────────────────────────────────────

#[derive(Debug, Default, Clone)]
struct Node {
    children: HashMap<u32, usize>,
    is_accepting: bool,
    count: usize,
}

struct Pta {
    nodes: Vec<Node>,
}

impl Pta {
    fn new() -> Self {
        Self { nodes: vec![Node::default()] }
    }

    fn insert(&mut self, seq: &[u32]) {
        let mut cur = 0usize;
        self.nodes[cur].count += 1;
        for &sym in seq {
            let next = if let Some(&n) = self.nodes[cur].children.get(&sym) {
                n
            } else {
                let n = self.nodes.len();
                self.nodes.push(Node::default());
                self.nodes[cur].children.insert(sym, n);
                n
            };
            cur = next;
            self.nodes[cur].count += 1;
        }
        self.nodes[cur].is_accepting = true;
    }

    fn root(&self) -> usize { 0 }
}

// ── Union-Find (for RPNI merges) ─────────────────────────────────────────────

struct Uf { parent: Vec<usize> }

impl Uf {
    fn new(n: usize) -> Self { Self { parent: (0..n).collect() } }

    fn find(&mut self, x: usize) -> usize {
        if self.parent[x] != x { self.parent[x] = self.find(self.parent[x]); }
        self.parent[x]
    }

    fn union(&mut self, a: usize, b: usize) {
        let (ra, rb) = (self.find(a), self.find(b));
        if ra != rb { self.parent[rb] = ra; }
    }
}

// ── Merge check ──────────────────────────────────────────────────────────────

/// Try to merge state `blue` into `red` in a copy of `uf`.
/// Returns Some(new_uf) if consistent, None if contradictory.
fn try_merge(pta: &Pta, uf: &Uf, red: usize, blue: usize) -> Option<Uf> {
    let n = pta.nodes.len();
    let mut new_uf = Uf { parent: uf.parent.clone() };
    let mut queue: VecDeque<(usize, usize)> = VecDeque::new();
    queue.push_back((red, blue));

    while let Some((r, b)) = queue.pop_front() {
        let rr = new_uf.find(r);
        let rb = new_uf.find(b);
        if rr == rb { continue; }

        // Contradiction: one is accepting, the other is not.
        if pta.nodes[rr].is_accepting != pta.nodes[rb].is_accepting {
            return None;
        }

        new_uf.union(rr, rb);

        // Propagate: merge children that share the same symbol.
        let r_node = &pta.nodes[rr];
        let b_node = &pta.nodes[rb];
        let r_children: HashMap<u32, usize> = r_node.children.clone();
        let b_children: HashMap<u32, usize> = b_node.children.clone();

        for (sym, &rc) in &r_children {
            if let Some(&bc) = b_children.get(sym) {
                let rrc = new_uf.find(rc);
                let rbc = new_uf.find(bc);
                if rrc != rbc {
                    queue.push_back((rrc, rbc));
                }
            }
        }
        let _ = n;
    }
    Some(new_uf)
}

// ── Main RPNI ────────────────────────────────────────────────────────────────

/// Blue-Fringe RPNI on positive examples only.
pub fn infer_rpni(sequences: &[Vec<u32>],
                  schema_names: &HashMap<u32, String>) -> Fsm {
    let seqs: Vec<&Vec<u32>> = sequences.iter()
        .filter(|s| s.len() >= 3)
        .collect();

    if seqs.is_empty() { return Fsm::new(); }

    let mut pta = Pta::new();
    for seq in &seqs { pta.insert(seq); }

    let n = pta.nodes.len();
    let mut uf = Uf::new(n);

    // BFS order of PTA states.
    let mut bfs_order: Vec<usize> = Vec::new();
    {
        let mut visited = vec![false; n];
        let mut queue: VecDeque<usize> = VecDeque::new();
        queue.push_back(pta.root());
        visited[pta.root()] = true;
        while let Some(node) = queue.pop_front() {
            bfs_order.push(node);
            let mut children: Vec<usize> =
                pta.nodes[node].children.values().copied().collect();
            children.sort_unstable();
            for c in children {
                if !visited[c] {
                    visited[c] = true;
                    queue.push_back(c);
                }
            }
        }
    }

    let mut red: Vec<usize> = vec![uf.find(pta.root())];
    let mut i = 1usize; // index into bfs_order for blue candidates

    while i < bfs_order.len() {
        let blue = uf.find(bfs_order[i]);

        // Skip if already red.
        if red.contains(&blue) { i += 1; continue; }

        // Try to merge blue with each red state.
        let mut merged = false;
        for &r in &red {
            if let Some(new_uf) = try_merge(&pta, &uf, r, blue) {
                uf = new_uf;
                merged = true;
                break;
            }
        }

        if !merged {
            // Promote blue to red.
            red.push(blue);
        }
        i += 1;
    }

    // Build FSM from merged PTA.
    let mut repr_set: HashSet<usize> = (0..n).map(|j| uf.find(j)).collect();
    let mut repr_list: Vec<usize> = repr_set.drain().collect();
    repr_list.sort_unstable();

    let state_map: HashMap<usize, u32> = repr_list.iter()
        .enumerate()
        .map(|(idx, &repr)| (repr, idx as u32))
        .collect();

    let mut fsm = Fsm::new();
    let root_repr = uf.find(pta.root());

    for &repr in &repr_list {
        let is_initial   = repr == root_repr;
        let is_accepting = pta.nodes[repr].is_accepting ||
            (0..n).any(|j| uf.find(j) == repr && pta.nodes[j].is_accepting);
        let label = if is_initial { "INIT".to_string() }
                    else { format!("S{}", state_map[&repr]) };
        fsm.add_state(&label, is_initial, is_accepting);
    }

    let total = seqs.len() as f64;
    let mut tr_counts: HashMap<(u32, u32, u32), usize> = HashMap::new();

    for j in 0..n {
        let from_repr = uf.find(j);
        let from_id   = state_map[&from_repr];
        for (&sym, &child) in &pta.nodes[j].children {
            let to_id = state_map[&uf.find(child)];
            *tr_counts.entry((from_id, to_id, sym)).or_insert(0) +=
                pta.nodes[j].count;
        }
    }

    for ((from, to, sym), cnt) in tr_counts {
        let freq = cnt as f64 / total;
        let schema_ref = schema_names.get(&sym).cloned()
            .unwrap_or_else(|| format!("msg_type_{:02}", sym));
        fsm.add_transition(from, to, sym, &schema_ref, freq);
    }

    fsm
}
