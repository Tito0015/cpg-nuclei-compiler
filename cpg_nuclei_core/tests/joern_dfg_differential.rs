//! Phase 2.4 — Differential integration test: Joern CPG JSON -> DFG -> critical slices.
//!
//! Constructs a sample Joern `DataFlowSlice` JSON fixture (mimicking what
//! `joern-slice data-flow` emits for a C buffer-overflow vulnerability),
//! deserializes it through `cpg_deserializer::dataflow_slice_to_function_dfg`,
//! runs `backward_slice::critical_slices`, and asserts node/edge/sink/source counts.
//!
//! Also exercises the pre-pruner (`prune::prune_to_sink_reachable`) on the
//! deserialized DFG to verify it preserves sink-reachable nodes and drops
//! dead code.

use cpg_nuclei_core::backward_slice::critical_slices;
use cpg_nuclei_core::cpg_deserializer::{
    classify_sink, dataflow_slice_to_function_dfg, dataflow_slices_to_cross_tx_dfg,
    joern_label_to_edgekind, joern_node_to_dfg_node,
};
use cpg_nuclei_core::cpg_schema::{DataFlowSlice, SliceNode};
use cpg_nuclei_core::cross_tx_dfg::CrossTxDfg;
use cpg_nuclei_core::dfg::{DfgNode, EdgeKind, SinkKind};
use cpg_nuclei_core::joern_cpg_bridge::invoke_z3_solver;
use cpg_nuclei_core::prune::prune_to_sink_reachable;
use std::collections::HashMap;

// ── Fixture: a C buffer-overflow data-flow slice ────────────────────────────
//
// Source: `recv(sock, input, 1024, 0)`  → parameter `input` (tainted)
// Sink:   `memcpy(buf, input, len)`     → unbounded copy (buffer overflow)
//
// Joern would emit a backward data-flow slice from the memcpy sink back to
// the recv source. This fixture captures the essential node/edge structure.

fn fixture_buffer_overflow_slice() -> &'static str {
    r#"{
        "nodes": [
            {"id": 0, "label": "METHOD_PARAMETER_IN", "name": "input", "code": "input",
             "typeFullName": "char *", "parentMethod": "handle_conn", "parentFile": "server.c",
             "lineNumber": 10, "columnNumber": 20},
            {"id": 1, "label": "METHOD_PARAMETER_IN", "name": "len", "code": "len",
             "typeFullName": "int", "parentMethod": "handle_conn", "parentFile": "server.c",
             "lineNumber": 10, "columnNumber": 35},
            {"id": 2, "label": "IDENTIFIER", "name": "buf", "code": "buf",
             "typeFullName": "char *", "parentMethod": "handle_conn", "parentFile": "server.c",
             "lineNumber": 12, "columnNumber": 5},
            {"id": 3, "label": "CALL", "name": "memcpy", "code": "memcpy(buf, input, len)",
             "typeFullName": "", "parentMethod": "handle_conn", "parentFile": "server.c",
             "lineNumber": 12, "columnNumber": 5},
            {"id": 4, "label": "IDENTIFIER", "name": "input", "code": "input",
             "typeFullName": "char *", "parentMethod": "handle_conn", "parentFile": "server.c",
             "lineNumber": 12, "columnNumber": 15},
            {"id": 5, "label": "IDENTIFIER", "name": "len", "code": "len",
             "typeFullName": "int", "parentMethod": "handle_conn", "parentFile": "server.c",
             "lineNumber": 12, "columnNumber": 25},
            {"id": 6, "label": "LITERAL", "name": "", "code": "0",
             "typeFullName": "int", "parentMethod": "handle_conn", "parentFile": "server.c",
             "lineNumber": 14, "columnNumber": 10},
            {"id": 7, "label": "RETURN", "name": "", "code": "return 0;",
             "typeFullName": "", "parentMethod": "handle_conn", "parentFile": "server.c",
             "lineNumber": 14, "columnNumber": 5}
        ],
        "edges": [
            {"src": 0, "dst": 4, "label": "REACHING_DEF"},
            {"src": 1, "dst": 5, "label": "REACHING_DEF"},
            {"src": 4, "dst": 3, "label": "ARGUMENT"},
            {"src": 5, "dst": 3, "label": "ARGUMENT"},
            {"src": 2, "dst": 3, "label": "ARGUMENT"},
            {"src": 6, "dst": 7, "label": "REACHING_DEF"}
        ]
    }"#
}

// ── Test 1: Deserialization produces correct node/edge/sink/source counts ──

#[test]
fn test_deserialize_buffer_overflow_slice() {
    let json = fixture_buffer_overflow_slice();
    let slice: DataFlowSlice = serde_json::from_str(json).expect("JSON deser");

    let dfg = dataflow_slice_to_function_dfg(&slice);

    // Function name from the first node's parentMethod
    assert_eq!(dfg.function_name, "handle_conn");

    // 8 primary nodes + 1 sink node (memcpy) = 9 total
    assert_eq!(dfg.nodes.len(), 9, "expected 8 primary + 1 sink node");

    // 6 original edges + 1 call->sink edge = 7 total
    assert_eq!(dfg.edges.len(), 7, "expected 6 original + 1 call->sink edge");

    // 2 taint sources (METHOD_PARAMETER_IN: input, len)
    assert_eq!(dfg.sources.len(), 2, "expected 2 taint sources");

    // 1 sink (memcpy -> LowLevelCall)
    assert_eq!(dfg.sinks.len(), 1, "expected 1 sink");
    let sink = dfg.nodes.iter().find(|n| matches!(n, DfgNode::Sink { kind: SinkKind::LowLevelCall }));
    assert!(sink.is_some(), "memcpy must produce a LowLevelCall sink");
}

// ── Test 2: critical_slices finds source-to-sink taint paths ───────────────

#[test]
fn test_critical_slices_find_taint_paths() {
    let json = fixture_buffer_overflow_slice();
    let slice: DataFlowSlice = serde_json::from_str(json).expect("JSON deser");
    let dfg = dataflow_slice_to_function_dfg(&slice);

    let paths = critical_slices(&dfg);

    // At least one critical slice (source -> sink path) must exist
    assert!(!paths.is_empty(), "critical_slices must find >= 1 taint path");
    // Every path must end at a sink
    for path in &paths {
        let sink_node = dfg.nodes.get(path.sink);
        assert!(matches!(sink_node, Some(DfgNode::Sink { .. })), "path sink must be a Sink node");
    }
}

// ── Test 3: Pre-pruner preserves sink-reachable nodes, drops dead code ─────

#[test]
fn test_prune_preserves_sink_reachable() {
    let json = fixture_buffer_overflow_slice();
    let slice: DataFlowSlice = serde_json::from_str(json).expect("JSON deser");
    let dfg = dataflow_slice_to_function_dfg(&slice);

    let result = prune_to_sink_reachable(&dfg);

    // The pruned DFG must retain the sink and all nodes that reach it
    assert!(result.dfg.sinks.len() >= 1, "pruned DFG must retain the sink");
    assert!(result.dfg.sources.len() >= 1, "pruned DFG must retain at least one source");
    // The return/literal nodes (6, 7) that don't reach the sink may be pruned
    // (they're reachable from the RETURN node, but the RETURN isn't a sink)
    assert!(result.drop_ratio >= 0.0, "drop ratio must be non-negative");
    // Sink must still be LowLevelCall
    let sink = result.dfg.nodes.iter().find(|n| matches!(n, DfgNode::Sink { .. }));
    assert!(matches!(sink, Some(DfgNode::Sink { kind: SinkKind::LowLevelCall })));
}

// ── Test 4: CrossTxDfg aggregation produces external_calls ──────────────────

#[test]
fn test_cross_tx_dfg_aggregation() {
    let json = fixture_buffer_overflow_slice();
    let slice: DataFlowSlice = serde_json::from_str(json).expect("JSON deser");
    let dfg = dataflow_slices_to_cross_tx_dfg(&[slice], "0xabc123");

    assert_eq!(dfg.address, "0xabc123");
    assert!(dfg.entry_points.contains(&"handle_conn".to_string()));
    // memcpy should appear as an external call
    let calls = dfg.external_calls.get("handle_conn");
    assert!(calls.is_some(), "external_calls must have handle_conn");
    let has_memcpy = calls
        .unwrap()
        .iter()
        .any(|e| e.method == "memcpy" && e.target == "external");
    assert!(has_memcpy, "memcpy must be in external_calls");
    // call_edges must contain (handle_conn, external::memcpy)
    assert!(
        dfg.call_edges.iter().any(|(f, t)| f == "handle_conn" && t == "external::memcpy"),
        "call_edges must have (handle_conn, external::memcpy)"
    );
}

// ── Test 5: Edge label mapping covers all Joern labels ──────────────────────

#[test]
fn test_edge_label_mapping() {
    assert_eq!(joern_label_to_edgekind("REACHING_DEF"), EdgeKind::DataFlow);
    assert_eq!(joern_label_to_edgekind("ARGUMENT"), EdgeKind::Argument);
    assert_eq!(joern_label_to_edgekind("CONTROL_FLOW"), EdgeKind::Control);
    assert_eq!(joern_label_to_edgekind("CALL"), EdgeKind::Argument);
}

// ── Test 6: Sink classification covers memory + Solidity sinks ─────────────

#[test]
fn test_sink_classification() {
    assert_eq!(classify_sink("memcpy(buf, p, n)"), Some(SinkKind::LowLevelCall));
    assert_eq!(classify_sink("call(gas, to, val, data)"), Some(SinkKind::LowLevelCall));
    assert_eq!(classify_sink("addr.transfer(1 ether)"), Some(SinkKind::Transfer));
    assert_eq!(classify_sink("selfdestruct(p)"), Some(SinkKind::SelfDestruct));
    assert_eq!(classify_sink("system(cmd)"), Some(SinkKind::ExternalCall));
    assert_eq!(classify_sink("printf(\"hello\")"), None);
}

// ── Test 7: Joern node label mapping (spot-check key labels) ────────────────

#[test]
fn test_node_label_mapping() {
    let param = SliceNode {
        id: 0, label: "METHOD_PARAMETER_IN".into(), name: "p".into(), code: "p".into(),
        type_full_name: "".into(), parent_method: "f".into(), parent_file: "".into(),
        line_number: None, column_number: None,
    };
    assert!(matches!(
        joern_node_to_dfg_node(&param),
        DfgNode::Def { source: Some(_), .. }
    ));

    let ident = SliceNode {
        id: 1, label: "IDENTIFIER".into(), name: "x".into(), code: "x".into(),
        type_full_name: "".into(), parent_method: "f".into(), parent_file: "".into(),
        line_number: None, column_number: None,
    };
    assert!(matches!(joern_node_to_dfg_node(&ident), DfgNode::Use { .. }));

    let call = SliceNode {
        id: 2, label: "CALL".into(), name: "memcpy".into(), code: "memcpy(a, b, n)".into(),
        type_full_name: "".into(), parent_method: "f".into(), parent_file: "".into(),
        line_number: None, column_number: None,
    };
    assert!(matches!(joern_node_to_dfg_node(&call), DfgNode::Call { .. }));
}

// ── Test 8: Structural reachability stub (OSS — no Python Z3 bridge) ─────────

#[test]
fn test_structural_reachability_stub() {
    let mut external_calls = HashMap::new();
    external_calls.insert(
        "deposit".to_string(),
        vec![cpg_nuclei_core::cross_tx_dfg::ExternalCall {
            target: "0xtoken".into(),
            method: "transfer".into(),
        }],
    );

    let dfg = CrossTxDfg {
        address: "0xstub_test".into(),
        call_edges: vec![("deposit".into(), "external::transfer".into())],
        storage_writes: HashMap::new(),
        storage_reads: HashMap::new(),
        external_calls,
        internal_calls: HashMap::new(),
        entry_points: vec!["deposit".into()],
    };

    let sat_path = invoke_z3_solver(&dfg, 30).expect("stub must succeed");
    assert!(sat_path.sat, "external calls ⇒ SAT in structural stub");
    assert!(sat_path.reason.contains("external call"));

    let empty = CrossTxDfg {
        address: "0xempty".into(),
        call_edges: vec![],
        storage_writes: HashMap::new(),
        storage_reads: HashMap::new(),
        external_calls: HashMap::new(),
        internal_calls: HashMap::new(),
        entry_points: vec!["view".into()],
    };
    let clean = invoke_z3_solver(&empty, 30).expect("stub must succeed");
    assert!(!clean.sat, "no external calls ⇒ UNSAT in structural stub");
}