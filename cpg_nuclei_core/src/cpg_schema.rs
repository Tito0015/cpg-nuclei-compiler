//! Joern `data-flow` slice JSON schema — Serde-camelCase mirror of the
//! `DataFlowSlice` / `SliceNode` / `SliceEdge` case classes exported by
//! `joern-slice data-flow` (see `joern-cli/JOERN_SLICE.md`).
//!
//! Joern uses upickle which emits camelCase field names; we remap them to
//! Rust snake_case via `#[serde(rename_all = "camelCase")]`.
//!
//! Phase 1 scope (this module): the Serde schema only. The mapping from
//! `DataFlowSlice` into `crate::dfg::FunctionDfg` / `crate::cross_tx_dfg::CrossTxDfg`
//! lands in Phase 2 alongside the Z3 reachability wiring.

use serde::{Deserialize, Serialize};

/// Backwards data-flow slice emitted by `joern-slice data-flow`.
///
/// Source: `io.joern.dataflowengineoss.slicing.package` (Scala)
///   `case class DataFlowSlice(nodes: Set[SliceNode], edges: Set[SliceEdge])`
///
/// `Set[...]` serializes as a JSON array under upickle, so `Vec<...>` is the
/// correct Rust deserialization target. Order within a `Set` is unspecified by
/// Joern, so the deserializer must not rely on a particular node/edge ordering.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataFlowSlice {
    pub nodes: Vec<SliceNode>,
    pub edges: Vec<SliceEdge>,
}

/// A single node in a Joern data-flow slice.
///
/// Source:
///   `case class SliceNode(id: Long, label: String, name: String = "", code: String,
///                         typeFullName: String = "", parentMethod: String = "",
///                         parentFile: String = "", lineNumber: Option[Integer] = None,
///                         columnNumber: Option[Integer] = None)`
///
/// `label` is a Joern CPG node label, one of: `IDENTIFIER`, `LITERAL`,
/// `FIELD_IDENTIFIER`, `CALL`, `RETURN`, `BLOCK`, `CONTROL_STRUCTURE`,
/// `METHOD_PARAMETER_IN`, `OPERATOR`, etc. (full enumeration lives in
/// `semanticcpg`'s `NodeTypes`).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SliceNode {
    pub id: i64,
    pub label: String,
    #[serde(default)]
    pub name: String,
    pub code: String,
    #[serde(default)]
    pub type_full_name: String,
    #[serde(default)]
    pub parent_method: String,
    #[serde(default)]
    pub parent_file: String,
    #[serde(default)]
    pub line_number: Option<i32>,
    #[serde(default)]
    pub column_number: Option<i32>,
}

/// A single edge in a Joern data-flow slice.
///
/// Source: `case class SliceEdge(src: Long, dst: Long, label: String)`
///
/// Observed `label` values from `joern-slice data-flow`:
///   * `REACHING_DEF` — a reaching-definition data-dependence edge
///   * `ARGUMENT`     — argument-to-call edge (callee argument mapping)
///   * `CONTROL_FLOW` — intraprocedural CFG edge
///   * `CALL`         — call-site to callee edge
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SliceEdge {
    pub src: i64,
    pub dst: i64,
    pub label: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Round-trip a minimal `DataFlowSlice` JSON through Serde to confirm the
    /// camelCase rename matches what `joern-slice` emits. This is the
    /// Phase-1 fixture-level test; the full bridge integration is wired in
    /// Phase 2 once `joern_cpg_bridge::ingest` deserializes into `FunctionDfg`.
    #[test]
    fn test_dataflow_slice_camelcase_roundtrip() {
        let json = r#"{
            "nodes": [
                {"id": 0, "label": "IDENTIFIER", "name": "userInput", "code": "userInput",
                 "typeFullName": "", "parentMethod": "vuln", "parentFile": "fixture.c",
                 "lineNumber": 1, "columnNumber": 16},
                {"id": 1, "label": "CALL", "name": "memcpy", "code": "memcpy(buf, p, n)",
                 "typeFullName": "", "parentMethod": "vuln", "parentFile": "fixture.c",
                 "lineNumber": 1, "columnNumber": 23}
            ],
            "edges": [
                {"src": 0, "dst": 1, "label": "ARGUMENT"}
            ]
        }"#;
        let slice: DataFlowSlice = serde_json::from_str(json).expect("deser");
        assert_eq!(slice.nodes.len(), 2);
        assert_eq!(slice.edges.len(), 1);
        assert_eq!(slice.nodes[0].label, "IDENTIFIER");
        assert_eq!(slice.nodes[0].name, "userInput");
        assert_eq!(slice.nodes[0].parent_method, "vuln");
        assert_eq!(slice.nodes[0].line_number, Some(1));
        assert_eq!(slice.nodes[1].label, "CALL");
        assert_eq!(slice.edges[0].label, "ARGUMENT");
        assert_eq!(slice.edges[0].src, 0);
        assert_eq!(slice.edges[0].dst, 1);
    }

    /// Joern may omit defaulted fields entirely (rather than emitting the
    /// Scala defaults `""` / `None`). `#[serde(default)]` on every optional
    /// SliceNode field must absorb that.
    #[test]
    fn test_slice_node_missing_optional_fields_default() {
        let json = r#"{"id": 5, "label": "LITERAL", "code": "42"}"#;
        let node: SliceNode = serde_json::from_str(json).expect("deser with defaults");
        assert_eq!(node.id, 5);
        assert_eq!(node.label, "LITERAL");
        assert_eq!(node.code, "42");
        assert_eq!(node.name, "");
        assert_eq!(node.parent_method, "");
        assert_eq!(node.line_number, None);
        assert_eq!(node.column_number, None);
    }

    /// Round-trip back to JSON must preserve camelCase (used by tests +
    /// downstream exporters that quote Joern line numbers).
    #[test]
    fn test_slice_node_serializes_back_to_camelcase() {
        let node = SliceNode {
            id: 7,
            label: "CALL".into(),
            name: "recv".into(),
            code: "recv(s, b, 8, 0)".into(),
            type_full_name: "".into(),
            parent_method: "read".into(),
            parent_file: "f.c".into(),
            line_number: Some(3),
            column_number: None,
        };
        let s = serde_json::to_string(&node).expect("ser");
        assert!(s.contains("\"typeFullName\""), "camelCase keys preserved: {s}");
        assert!(s.contains("\"parentMethod\""), "camelCase keys preserved: {s}");
        assert!(s.contains("\"lineNumber\":3"), "line number round-trips: {s}");
    }
}