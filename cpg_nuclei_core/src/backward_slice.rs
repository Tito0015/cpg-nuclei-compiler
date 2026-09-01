use crate::dfg::{EdgeKind, FunctionDfg, NodeId};
use crate::taint::TaintPath;
use std::collections::{HashSet, VecDeque};

pub fn backward_slice(dfg: &FunctionDfg, sink: NodeId) -> Vec<Vec<NodeId>> {
    let mut rev_adj: Vec<Vec<NodeId>> = vec![Vec::new(); dfg.nodes.len()];
    for edge in &dfg.edges {
        if matches!(edge.kind, EdgeKind::DataFlow | EdgeKind::Argument) {
            rev_adj[edge.to].push(edge.from);
        }
    }

    let mut paths = Vec::new();
    let mut queue: VecDeque<Vec<NodeId>> = VecDeque::new();
    queue.push_back(vec![sink]);
    let mut visited: HashSet<NodeId> = HashSet::new();

    while let Some(path) = queue.pop_front() {
        let current = *path.last().unwrap_or(&sink);
        if dfg.sources.contains(&current) {
            paths.push(path);
            continue;
        }
        if current >= rev_adj.len() {
            continue;
        }
        for pred in &rev_adj[current] {
            if visited.insert(*pred) {
                let mut next = path.clone();
                next.push(*pred);
                queue.push_back(next);
            }
        }
    }
    paths
}

pub fn critical_slices(dfg: &FunctionDfg) -> Vec<TaintPath> {
    let mut out = Vec::new();
    for &sink_id in &dfg.sinks {
        for path in backward_slice(dfg, sink_id) {
            if let Some(crate::dfg::DfgNode::Sink { kind }) = dfg.nodes.get(sink_id) {
                out.push(TaintPath {
                    source: *path.first().unwrap_or(&sink_id),
                    sink: sink_id,
                    sink_kind: *kind,
                    path,
                });
            }
        }
    }
    out
}
