//! Taint propagation engine.
//!
//! Propagates taint from sources to sinks through the DFG.

use crate::dfg::{DfgNode, EdgeKind, FunctionDfg, NodeId, SinkKind};
use crate::types::SinkType;
use std::collections::{HashMap, HashSet, VecDeque};

/// A path from a taint source to a sink.
#[derive(Debug, Clone)]
pub struct TaintPath {
    /// Source node where taint originates
    pub source: NodeId,

    /// Sink node where taint reaches
    pub sink: NodeId,

    /// Type of sink
    pub sink_kind: SinkKind,

    /// Path of nodes from source to sink
    pub path: Vec<NodeId>,
}

/// Propagate taint through the DFG and find source-to-sink paths.
pub fn propagate_taint(dfg: &FunctionDfg) -> Vec<TaintPath> {
    let mut taint_paths = Vec::new();

    // ponytail: NodeId is dense usize — Vec adjacency avoids HashMap overhead
    let mut adjacency: Vec<Vec<NodeId>> = vec![Vec::new(); dfg.nodes.len()];
    for edge in &dfg.edges {
        if matches!(edge.kind, EdgeKind::DataFlow | EdgeKind::Argument) {
            if edge.from < adjacency.len() {
                adjacency[edge.from].push(edge.to);
            }
        }
    }

    // For each source, BFS to find reachable sinks
    for &source_id in &dfg.sources {
        let reachable_sinks = find_reachable_sinks(dfg, &adjacency, source_id);

        for (sink_id, path) in reachable_sinks {
            if let Some(DfgNode::Sink { kind }) = dfg.nodes.get(sink_id) {
                taint_paths.push(TaintPath {
                    source: source_id,
                    sink: sink_id,
                    sink_kind: *kind,
                    path,
                });
            }
        }
    }

    taint_paths
}

/// BFS from a source to find all reachable sinks.
fn find_reachable_sinks(
    dfg: &FunctionDfg,
    adjacency: &[Vec<NodeId>],
    source: NodeId,
) -> Vec<(NodeId, Vec<NodeId>)> {
    let mut results = Vec::new();
    let mut visited: HashSet<NodeId> = HashSet::new();
    let mut queue: VecDeque<(NodeId, Vec<NodeId>)> = VecDeque::new();

    queue.push_back((source, vec![source]));
    visited.insert(source);

    while let Some((current, path)) = queue.pop_front() {
        // Check if current is a sink
        if dfg.sinks.contains(&current) && current != source {
            results.push((current, path.clone()));
            // Continue searching - there may be multiple sinks reachable
        }

        // Explore neighbors
        if current < adjacency.len() {
            for &neighbor in &adjacency[current] {
                if !visited.contains(&neighbor) {
                    visited.insert(neighbor);
                    let mut new_path = path.clone();
                    new_path.push(neighbor);
                    queue.push_back((neighbor, new_path));
                }
            }
        }
    }

    results
}

/// Compute severity score from taint paths.
///
/// Higher severity for:
/// - More dangerous sink types
/// - Direct paths (shorter = more severe)
/// - Multiple paths to same sink
pub fn compute_severity(paths: &[TaintPath]) -> f32 {
    if paths.is_empty() {
        return 0.0;
    }

    let mut max_severity = 0.0f32;
    let mut sink_counts: HashMap<SinkKind, usize> = HashMap::new();

    for path in paths {
        // Base severity from sink type
        let base = match path.sink_kind {
            SinkKind::LowLevelCall => 5.0,
            SinkKind::Division => 3.0,
            SinkKind::Modulo => 2.5,
            SinkKind::StateWrite => 2.0,
            SinkKind::Transfer => 5.0,
            SinkKind::ExternalCall => 4.5,
            SinkKind::SelfDestruct => 10.0,
            SinkKind::Create => 4.0,
        };

        // Shorter paths are more direct = higher risk
        let path_factor = 1.0 + (1.0 / path.path.len() as f32);

        let severity = base * path_factor;
        max_severity = max_severity.max(severity);

        *sink_counts.entry(path.sink_kind).or_default() += 1;
    }

    // Bonus for multiple distinct sink types
    let diversity_bonus = (sink_counts.len() as f32 - 1.0).max(0.0) * 0.5;

    // Clamp to 0.0-10.0
    (max_severity + diversity_bonus).min(10.0)
}

/// Extract unique sink types from taint paths.
pub fn extract_sink_types(paths: &[TaintPath]) -> Vec<SinkType> {
    let mut types: HashSet<SinkType> = HashSet::new();

    for path in paths {
        let sink_type = match path.sink_kind {
            SinkKind::LowLevelCall => SinkType::LowLevelCall,
            SinkKind::Division | SinkKind::Modulo => SinkType::ArithmeticDiv,
            SinkKind::StateWrite => SinkType::StateUpdate,
            SinkKind::Transfer => SinkType::Transfer,
            SinkKind::ExternalCall => SinkType::ExternalCallback,
            SinkKind::SelfDestruct => SinkType::SelfDestruct,
            SinkKind::Create => SinkType::ContractCreation,
        };
        types.insert(sink_type);
    }

    types.into_iter().collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dfg::build_function_dfg;
    use crate::parser::parse_solidity;

    #[test]
    fn test_taint_propagation_division() {
        let source = r#"
            contract Test {
                function divide(uint256 a, uint256 b) public returns (uint256) {
                    return a / b;
                }
            }
        "#;
        let functions = parse_solidity(source).unwrap();
        let dfg = build_function_dfg(&functions[0]);
        let paths = propagate_taint(&dfg);

        // Parameter b flows to division denominator
        assert!(
            !paths.is_empty(),
            "Should find taint path to division sink"
        );
    }

    #[test]
    fn test_severity_computation() {
        let paths = vec![TaintPath {
            source: 0,
            sink: 1,
            sink_kind: SinkKind::LowLevelCall,
            path: vec![0, 1],
        }];

        let severity = compute_severity(&paths);
        assert!(severity > 0.0, "Severity should be positive");
        assert!(severity <= 10.0, "Severity should not exceed 10.0");
    }

    #[test]
    fn test_sink_type_extraction() {
        let paths = vec![
            TaintPath {
                source: 0,
                sink: 1,
                sink_kind: SinkKind::LowLevelCall,
                path: vec![0, 1],
            },
            TaintPath {
                source: 0,
                sink: 2,
                sink_kind: SinkKind::Division,
                path: vec![0, 2],
            },
        ];

        let types = extract_sink_types(&paths);
        assert_eq!(types.len(), 2);
    }
}
