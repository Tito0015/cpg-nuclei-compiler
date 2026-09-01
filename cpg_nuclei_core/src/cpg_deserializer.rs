//! Joern `DataFlowSlice` -> CPG-Nuclei internal DFG deserializer.
//!
//! Maps Joern's node-and-edge JSON graph slices (produced by `joern-slice
//! data-flow`) into the internal `FunctionDfg` and `CrossTxDfg` structures
//! defined in `dfg.rs` and `cross_tx_dfg.rs`.
//!
//! Mapping specification: see `docs/cpg/CPG_COMPILER_BIBLE.md` Section 2.

use crate::cpg_schema::{DataFlowSlice, SliceNode};
use crate::cross_tx_dfg::{CrossTxDfg, ExternalCall};
use crate::dfg::{DfgNode, EdgeKind, FunctionDfg, NodeId, SinkKind};
use crate::types::TaintSource;
use std::collections::HashMap;

// ── Sink classification ─────────────────────────────────────────────────────

/// Patterns that mark a Joern CALL node's `code` as a security sink.
///
/// Returns `Some(SinkKind)` when the code matches a known-dangerous call,
/// `None` for benign calls (e.g. `printf("hello")`).
///
/// Directive signature was `-> SinkKind`; we return `Option<SinkKind>` because
/// not every CALL is a sink and the `SinkKind` enum has no `None` variant.
pub fn classify_sink(code: &str) -> Option<SinkKind> {
    let c = code.trim();

    // Solidity low-level calls
    if c.contains("call(") || c.contains("delegatecall(") || c.contains("staticcall(") {
        return Some(SinkKind::LowLevelCall);
    }
    // Solidity transfers
    if c.contains("transfer(") || c.contains("send(") {
        return Some(SinkKind::Transfer);
    }
    // Self-destruct
    if c.contains("selfdestruct(") {
        return Some(SinkKind::SelfDestruct);
    }
    // C/C++ memory-unsafe sinks (buffer overflow, format string, etc.)
    if c.contains("memcpy(")
        || c.contains("memmove(")
        || c.contains("strcpy(")
        || c.contains("strncpy(")
        || c.contains("sprintf(")
        || c.contains("gets(")
    {
        return Some(SinkKind::LowLevelCall);
    }
    // Command injection sinks
    if c.contains("system(") || c.contains("exec(") || c.contains("popen(") {
        return Some(SinkKind::ExternalCall);
    }
    // Division / modulo as operator-sinks (Joern emits these as OPERATOR nodes,
    // but a CALL wrapper around a division also lands here)
    if c.contains(" / ") || c.starts_with('/') {
        return Some(SinkKind::Division);
    }
    if c.contains(" % ") || c.starts_with('%') {
        return Some(SinkKind::Modulo);
    }
    None
}

// ── Edge label mapping ──────────────────────────────────────────────────────

/// Map a Joern `SliceEdge.label` string to the internal `EdgeKind`.
///
/// Observed labels from `joern-slice data-flow` (per `JOERN_SLICE.md`):
///   `REACHING_DEF` -> DataFlow  (reaching-definition data dependence)
///   `ARGUMENT`     -> Argument  (argument-to-call mapping)
///   `CONTROL_FLOW` -> Control   (intraprocedural CFG)
///   `CALL`         -> Argument  (call-site to callee, treated as argument edge)
pub fn joern_label_to_edgekind(label: &str) -> EdgeKind {
    match label {
        "REACHING_DEF" => EdgeKind::DataFlow,
        "ARGUMENT" => EdgeKind::Argument,
        "CONTROL_FLOW" => EdgeKind::Control,
        "CALL" => EdgeKind::Argument,
        _ => EdgeKind::DataFlow, // default: unknown edges treated as data flow
    }
}

// ── Node label mapping ─────────────────────────────────────────────────────

/// Map a Joern `SliceNode` (by its `label` field) to the internal `DfgNode`.
///
/// Joern CPG node labels handled:
///   `METHOD_PARAMETER_IN` -> `Def` with `TaintSource::Parameter` (taint source)
///   `IDENTIFIER`          -> `Use`  (variable read)
///   `LITERAL`             -> `Def`  (literal value, no taint)
///   `CALL`                -> `Call` (function/method call)
///   `RETURN`              -> `Use`  (return-value read)
///   `FIELD_IDENTIFIER`    -> `Use`  (field access read)
///   `OPERATOR`            -> `BinaryOp` (arithmetic/logical operator)
///   others                -> `Use`  (conservative default for unknown labels)
pub fn joern_node_to_dfg_node(node: &SliceNode) -> DfgNode {
    match node.label.as_str() {
        "METHOD_PARAMETER_IN" => DfgNode::Def {
            var_name: if node.name.is_empty() {
                node.code.clone()
            } else {
                node.name.clone()
            },
            source: Some(TaintSource::Parameter),
        },
        "IDENTIFIER" => DfgNode::Use {
            var_name: if node.name.is_empty() {
                node.code.clone()
            } else {
                node.name.clone()
            },
        },
        "LITERAL" => DfgNode::Def {
            var_name: node.code.clone(),
            source: None,
        },
        "CALL" => {
            let callee = node.code.clone();
            let is_low_level = callee.contains("call(")
                || callee.contains("delegatecall(")
                || callee.contains("staticcall(")
                || callee.contains("memcpy(")
                || callee.contains("strcpy(");
            let is_transfer = callee.contains("transfer(") || callee.contains("send(");
            // An "external" call is one that crosses a contract/method boundary.
            // For Joern slices from C/C++, any function call is "external" to the
            // current function; for Solidity, member-access calls (`x.foo()`) are.
            let is_external = is_low_level || is_transfer || callee.contains('.');
            DfgNode::Call {
                callee,
                is_low_level,
                is_transfer,
                is_external,
            }
        }
        "RETURN" => DfgNode::Use {
            var_name: node.code.clone(),
        },
        "FIELD_IDENTIFIER" => DfgNode::Use {
            var_name: if node.name.is_empty() {
                node.code.clone()
            } else {
                node.name.clone()
            },
        },
        "OPERATOR" => DfgNode::BinaryOp {
            op: classify_operator(&node.code),
        },
        // Conservative default: treat unknown labels as Use (read) nodes.
        _ => DfgNode::Use {
            var_name: node.code.clone(),
        },
    }
}

/// Map a Joern OPERATOR code string to a `BinaryOperator`.
fn classify_operator(code: &str) -> crate::parser::BinaryOperator {
    use crate::parser::BinaryOperator;
    match code.trim() {
        "+" => BinaryOperator::Add,
        "-" => BinaryOperator::Sub,
        "*" => BinaryOperator::Mul,
        "/" => BinaryOperator::Div,
        "%" => BinaryOperator::Mod,
        "&&" => BinaryOperator::And,
        "||" => BinaryOperator::Or,
        "|" => BinaryOperator::BitOr,
        "==" => BinaryOperator::Eq,
        "!=" => BinaryOperator::NotEq,
        "<" => BinaryOperator::Lt,
        ">" => BinaryOperator::Gt,
        "<=" => BinaryOperator::LtEq,
        ">=" => BinaryOperator::GtEq,
        _ => BinaryOperator::Other,
    }
}

// ── Slice -> FunctionDfg ───────────────────────────────────────────────────

/// Deserialize a single Joern `DataFlowSlice` into an intra-procedural `FunctionDfg`.
///
/// 1. Remap Joern node IDs (`i64`) to dense internal `NodeId` (`usize`).
/// 2. Create `DfgNode`s via `joern_node_to_dfg_node`.
/// 3. Wire edges via `joern_label_to_edgekind`.
/// 4. Second pass: for each CALL node whose `code` matches `classify_sink`,
///    add a `DfgNode::Sink` + `DataFlow` edge from the Call to the Sink, and
///    `mark_sink`.
/// 5. Mark `METHOD_PARAMETER_IN` nodes as taint sources.
pub fn dataflow_slice_to_function_dfg(slice: &DataFlowSlice) -> FunctionDfg {
    let func_name = slice
        .nodes
        .first()
        .map(|n| n.parent_method.as_str())
        .filter(|s| !s.is_empty())
        .unwrap_or("joern_slice")
        .to_string();
    let mut dfg = FunctionDfg::new(&func_name);

    // Pass 1 — create all primary nodes, build id remap
    let mut id2nid: HashMap<i64, NodeId> = HashMap::with_capacity(slice.nodes.len());
    // Track which NodeIds are CALL nodes (for the sink-creation second pass)
    let mut call_nodes: Vec<(NodeId, String)> = Vec::new();
    // Track which NodeIds are METHOD_PARAMETER_IN (for source marking)
    let mut param_nodes: Vec<NodeId> = Vec::new();

    for n in &slice.nodes {
        let dfg_node = joern_node_to_dfg_node(n);
        let nid = dfg.add_node(dfg_node);
        id2nid.insert(n.id, nid);

        if n.label == "CALL" {
            call_nodes.push((nid, n.code.clone()));
        }
        if n.label == "METHOD_PARAMETER_IN" {
            param_nodes.push(nid);
        }
    }

    // Pass 2 — wire edges
    for e in &slice.edges {
        if let (Some(&from), Some(&to)) = (id2nid.get(&e.src), id2nid.get(&e.dst)) {
            dfg.add_edge(from, to, joern_label_to_edgekind(&e.label));
        }
    }

    // Pass 3 — for dangerous CALL nodes, add Sink nodes + DataFlow edges
    for (call_nid, code) in &call_nodes {
        if let Some(sink_kind) = classify_sink(code) {
            let sink_nid = dfg.add_node(DfgNode::Sink { kind: sink_kind });
            dfg.add_edge(*call_nid, sink_nid, EdgeKind::DataFlow);
            dfg.mark_sink(sink_nid);
        }
    }

    // Pass 4 — mark METHOD_PARAMETER_IN nodes as taint sources
    for nid in &param_nodes {
        dfg.mark_source(*nid);
    }

    dfg
}

// ── Slices -> CrossTxDfg ────────────────────────────────────────────────────

/// Aggregate multiple `DataFlowSlice`s into a cross-function `CrossTxDfg`.
///
/// Each slice becomes one function-level `FunctionDfg`; CALL nodes within
/// each are parsed into `ExternalCall` entries and `call_edges`.
pub fn dataflow_slices_to_cross_tx_dfg(slices: &[DataFlowSlice], address: &str) -> CrossTxDfg {
    let mut dfg = CrossTxDfg {
        address: address.to_string(),
        call_edges: Vec::new(),
        storage_writes: HashMap::new(),
        storage_reads: HashMap::new(),
        external_calls: HashMap::new(),
        internal_calls: HashMap::new(),
        entry_points: Vec::new(),
    };

    for slice in slices {
        let func_dfg = dataflow_slice_to_function_dfg(slice);
        let func_name = func_dfg.function_name.clone();

        // Collect entry points (every parent_method is a potential entry)
        if !dfg.entry_points.contains(&func_name) {
            dfg.entry_points.push(func_name.clone());
        }

        // Extract external calls from CALL nodes
        for node in &func_dfg.nodes {
            if let DfgNode::Call {
                callee,
                is_external,
                ..
            } = node
            {
                if let Some(ext) = parse_external_call(callee) {
                    let is_dup = dfg
                        .external_calls
                        .get(&func_name)
                        .map(|v| v.iter().any(|e| e.target == ext.target && e.method == ext.method))
                        .unwrap_or(false);
                    if !is_dup {
                        dfg.external_calls
                            .entry(func_name.clone())
                            .or_default()
                            .push(ext.clone());
                        dfg.call_edges
                            .push((func_name.clone(), format!("{}::{}", ext.target, ext.method)));
                    }
                    // Non-external calls become internal_calls
                } else if !is_external {
                    let callee_name = extract_callee_name(callee);
                    if !dfg
                        .internal_calls
                        .get(&func_name)
                        .map(|v| v.contains(&callee_name))
                        .unwrap_or(false)
                    {
                        dfg.internal_calls
                            .entry(func_name.clone())
                            .or_default()
                            .push(callee_name.clone());
                        dfg.call_edges
                            .push((func_name.clone(), format!("internal::{}", callee_name)));
                    }
                }
            }
        }
    }

    dfg
}

/// Parse a Joern CALL `code` string (e.g. `obj.method(args)` or `memcpy(...)`)
/// into an `ExternalCall { target, method }`.
fn parse_external_call(code: &str) -> Option<ExternalCall> {
    let c = code.trim();

    // Pattern: `obj.method(...)` — member-access call
    if let Some(dot_pos) = c.find('.') {
        // Ensure the dot is before the opening paren
        if let Some(paren_pos) = c.find('(') {
            if dot_pos < paren_pos {
                let target = c[..dot_pos].trim().to_string();
                let method = c[dot_pos + 1..paren_pos].trim().to_string();
                if !target.is_empty() && !method.is_empty() {
                    return Some(ExternalCall { target, method });
                }
            }
        }
    }

    // Pattern: `call(...)` / `delegatecall(...)` / `staticcall(...)` — Solidity low-level
    if c.starts_with("call(") || c.starts_with("delegatecall(") || c.starts_with("staticcall(") {
        let paren = c.find('(').unwrap_or(4);
        let method = c[..paren].to_string();
        return Some(ExternalCall {
            target: "address".into(),
            method,
        });
    }

    // Pattern: `memcpy(...)` / `system(...)` etc. — external library call
    if let Some(paren_pos) = c.find('(') {
        let method = c[..paren_pos].trim().to_string();
        if !method.is_empty() && is_external_library(&method) {
            return Some(ExternalCall {
                target: "external".into(),
                method,
            });
        }
    }

    None
}

/// Heuristic: is this function name an external/standard-library call?
fn is_external_library(name: &str) -> bool {
    matches!(
        name,
        "memcpy"
            | "memmove"
            | "memset"
            | "strcpy"
            | "strncpy"
            | "strcat"
            | "strncat"
            | "sprintf"
            | "snprintf"
            | "printf"
            | "scanf"
            | "gets"
            | "system"
            | "exec"
            | "execve"
            | "popen"
            | "recv"
            | "send"
            | "read"
            | "write"
            | "open"
            | "close"
            | "malloc"
            | "free"
            | "realloc"
            | "calloc"
    )
}

/// Extract the bare callee name from a call expression `foo(...)` -> `foo`.
fn extract_callee_name(code: &str) -> String {
    let c = code.trim();
    if let Some(paren_pos) = c.find('(') {
        let name = c[..paren_pos].trim();
        // For `obj.method(...)` return just `method`
        if let Some(dot_pos) = name.rfind('.') {
            return name[dot_pos + 1..].trim().to_string();
        }
        return name.to_string();
    }
    c.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A memcpy slice: parameter `p` flows to `memcpy(buf, p, n)` — the memcpy
    /// must become a `SinkKind::LowLevelCall` and the parameter a taint source.
    #[test]
    fn test_memcpy_slice_deserializes_to_dfg_with_sink_and_source() {
        let json = r#"{
            "nodes": [
                {"id": 0, "label": "METHOD_PARAMETER_IN", "name": "p", "code": "p",
                 "typeFullName": "", "parentMethod": "vuln", "parentFile": "f.c",
                 "lineNumber": 1, "columnNumber": 16},
                {"id": 1, "label": "IDENTIFIER", "name": "buf", "code": "buf",
                 "typeFullName": "", "parentMethod": "vuln", "parentFile": "f.c",
                 "lineNumber": 1, "columnNumber": 23},
                {"id": 2, "label": "CALL", "name": "memcpy", "code": "memcpy(buf, p, n)",
                 "typeFullName": "", "parentMethod": "vuln", "parentFile": "f.c",
                 "lineNumber": 1, "columnNumber": 28}
            ],
            "edges": [
                {"src": 0, "dst": 2, "label": "ARGUMENT"},
                {"src": 1, "dst": 2, "label": "ARGUMENT"}
            ]
        }"#;
        let slice: DataFlowSlice = serde_json::from_str(json).expect("deser");
        let dfg = dataflow_slice_to_function_dfg(&slice);

        assert_eq!(dfg.function_name, "vuln");
        // 3 primary nodes + 1 sink node (memcpy)
        assert_eq!(dfg.nodes.len(), 4);
        // 2 argument edges + 1 dataflow edge (call -> sink)
        assert_eq!(dfg.edges.len(), 3);
        // 1 taint source (METHOD_PARAMETER_IN)
        assert_eq!(dfg.sources.len(), 1);
        // 1 sink (memcpy)
        assert_eq!(dfg.sinks.len(), 1);
        // Verify the sink kind
        let sink_node = dfg.nodes.iter().find(|n| matches!(n, DfgNode::Sink { .. }));
        assert!(matches!(sink_node, Some(DfgNode::Sink { kind: SinkKind::LowLevelCall })));
    }

    #[test]
    fn test_classify_sink_patterns() {
        assert_eq!(classify_sink("call(gas, addr, value, data)"), Some(SinkKind::LowLevelCall));
        assert_eq!(classify_sink("delegatecall(gas, addr, data)"), Some(SinkKind::LowLevelCall));
        assert_eq!(classify_sink("addr.transfer(1 ether)"), Some(SinkKind::Transfer));
        assert_eq!(classify_sink("selfdestruct(p)"), Some(SinkKind::SelfDestruct));
        assert_eq!(classify_sink("memcpy(buf, p, n)"), Some(SinkKind::LowLevelCall));
        assert_eq!(classify_sink("system(cmd)"), Some(SinkKind::ExternalCall));
        assert_eq!(classify_sink("printf(\"hello\")"), None);
    }

    #[test]
    fn test_joern_label_to_edgekind() {
        assert_eq!(joern_label_to_edgekind("REACHING_DEF"), EdgeKind::DataFlow);
        assert_eq!(joern_label_to_edgekind("ARGUMENT"), EdgeKind::Argument);
        assert_eq!(joern_label_to_edgekind("CONTROL_FLOW"), EdgeKind::Control);
        assert_eq!(joern_label_to_edgekind("CALL"), EdgeKind::Argument);
        assert_eq!(joern_label_to_edgekind("UNKNOWN"), EdgeKind::DataFlow);
    }

    #[test]
    fn test_slices_to_cross_tx_dfg_aggregates_external_calls() {
        let json = r#"{
            "nodes": [
                {"id": 0, "label": "METHOD_PARAMETER_IN", "name": "p", "code": "p",
                 "parentMethod": "vuln", "parentFile": "f.c"},
                {"id": 1, "label": "CALL", "code": "memcpy(buf, p, n)",
                 "parentMethod": "vuln", "parentFile": "f.c"}
            ],
            "edges": [{"src": 0, "dst": 1, "label": "ARGUMENT"}]
        }"#;
        let slice: DataFlowSlice = serde_json::from_str(json).expect("deser");
        let dfg = dataflow_slices_to_cross_tx_dfg(&[slice], "0xdeadbeef");

        assert_eq!(dfg.address, "0xdeadbeef");
        assert!(dfg.entry_points.contains(&"vuln".to_string()));
        // memcpy -> ExternalCall { target: "external", method: "memcpy" }
        let calls = dfg.external_calls.get("vuln").expect("external_calls[vuln]");
        assert!(calls.iter().any(|e| e.method == "memcpy" && e.target == "external"));
        // call_edges should have (vuln, external::memcpy)
        assert!(dfg.call_edges.iter().any(|(f, t)| f == "vuln" && t == "external::memcpy"));
    }
}