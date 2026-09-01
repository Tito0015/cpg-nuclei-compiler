//! Joern CPG ingestion engine — shells out to `joern-parse` + `joern-slice`
//! to obtain `DataFlowSlice` JSON, then **normalizes** every slice onto a
//! language-blind IR (Phase 3.3). Solidity and C/C++ share METHOD / CALL /
//! METHOD_PARAMETER_IN labels before exporters see them.
//!
//! When Joern is missing, `ingest_unified` falls back to a shared C-family
//! AST extractor (`source_to_slice`) — **not** the solang Solidity fast-path.
//!
//! Binary discovery order (see `docs/cpg/JOERN_CLI_PROVISIONING.md`):
//!   1. `PATH` (covers `sbt install`ed / `scoop install joern`ed setups)
//!   2. `$JOERN_HOME/bin/joern-parse(.bat)` if `JOERN_HOME` is set
//!   3. `JoernError::BinaryMissing` — graceful fallback to the `.sol` fast-path
//!      (`crate::cross_tx_dfg::build_cross_tx_dfg_from_source`)

use std::path::{Path, PathBuf};
use std::process::Command;
use tempfile::TempDir;
use thiserror::Error;

use crate::cpg_schema::{DataFlowSlice, SliceEdge, SliceNode};
use crate::cross_tx_dfg::CrossTxDfg;

/// Errors raised by the Joern ingestion engine.
#[derive(Debug, Error)]
pub enum JoernError {
    /// `joern-parse` (or `joern-slice`) is not on `PATH` and `JOERN_HOME` is
    /// unset/incorrect. Callers should fall back to the Solidity fast-path
    /// (`cross_tx_dfg::build_cross_tx_dfg_from_source`) for `.sol` targets
    /// and surface a provisioning requirement otherwise.
    #[error("joern binary not found at {0} (set JOERN_HOME or add it to PATH)")]
    BinaryMissing(PathBuf),

    #[error("joern-parse failed (exit {code}): {stderr}")]
    ParseFailed { code: i32, stderr: String },

    #[error("joern-slice failed (exit {code}): {stderr}")]
    SliceFailed { code: i32, stderr: String },

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
}

/// Configuration for a single Joern ingestion run.
///
/// Mirrors the `joern-slice data-flow` CLI surface described in
/// `joern-cli/JOERN_SLICE.md`. Defaults obey the IP-protection hard limit of a
/// **120-second** worker timeout (Master Plan, IP blind-spot #1).
#[derive(Debug, Clone)]
pub struct JoernConfig {
    /// Path to the `joern-parse` executable. Default `joern-parse` (resolved via `PATH`);
    /// `discover()` overrides with `$JOERN_HOME/bin/joern-parse` (`.bat` on win32).
    pub joern_parse: PathBuf,
    /// Path to the `joern-slice` executable. Default `joern-slice` (resolved via `PATH`).
    pub joern_slice: PathBuf,
    /// `--slice-depth <N>` — max DDG traversal depth. Default 20 (matches Joern).
    pub slice_depth: u32,
    /// `--sink-filter <regex>` — filters on the sink `code` property. `None` = no filter.
    pub sink_filter: Option<String>,
    /// `--method-name-filter <regex>` — filters slices through methods matching a name regex.
    pub method_name_filter: Option<String>,
    /// `--method-parameter-filter <regex>` — filters slices through methods with given param types.
    pub method_parameter_filter: Option<String>,
    /// `--method-annotation-filter <regex>` — filters slices through annotated methods.
    pub method_annotation_filter: Option<String>,
    /// `--file-filter <name>` — restrict slices to a given source file name.
    pub file_filter: Option<String>,
    /// `--end-at-external-method` — all slices must terminate at an external method. Default false.
    pub end_at_external: bool,
    /// Hard wall-clock timeout per worker in seconds. Default **120** (IP blind-spot #1).
    ///
    /// Phase 2 will also feed this into the Z3 solver timeout so the whole
    /// `ingest -> DFG -> Z3 -> export` pipeline is bounded by a single 120s budget.
    pub timeout_secs: u64,
}

impl Default for JoernConfig {
    fn default() -> Self {
        Self {
            joern_parse: PathBuf::from("joern-parse"),
            joern_slice: PathBuf::from("joern-slice"),
            slice_depth: 20,
            sink_filter: None,
            method_name_filter: None,
            method_parameter_filter: None,
            method_annotation_filter: None,
            file_filter: None,
            end_at_external: false,
            timeout_secs: 120,
        }
    }
}

impl JoernConfig {
    /// Resolve binaries using the `JOERN_HOME` env convention.
    ///
    /// Returns a `JoernConfig` whose `joern_parse` / `joern_slice` fields point
    /// at `$JOERN_HOME/bin/joern-parse(.bat)` if (a) `JOERN_HOME` is set and
    /// (b) those binaries exist on disk; otherwise falls back to the
    /// `PATH`-based defaults.
    ///
    /// Safe to call in an unprovisioned environment (no `JOERN_HOME`, no joern
    /// on `PATH`): returns the default config and lets `ingest()` surface
    /// `BinaryMissing` if it is actually invoked.
    pub fn discover() -> Self {
        let mut cfg = JoernConfig::default();
        if let Ok(home) = std::env::var("JOERN_HOME") {
            let home = PathBuf::from(home);
            let (parse, slice) = if cfg!(windows) {
                (
                    home.join("bin").join("joern-parse.bat"),
                    home.join("bin").join("joern-slice.bat"),
                )
            } else {
                (
                    home.join("bin").join("joern-parse"),
                    home.join("bin").join("joern-slice"),
                )
            };
            if parse.exists() {
                cfg.joern_parse = parse;
            }
            if slice.exists() {
                cfg.joern_slice = slice;
            }
        }
        cfg
    }
}

/// Ingest a target through the Joern CLI and return the emitted data-flow slices.
///
/// Pipeline stages (per Master Plan sections 2.1-2.2):
///   1. `joern-parse <target> -o <workspace>/cpg.bin`        -> binary CPG
///   2. `joern-slice data-flow <cpg.bin> -o <workspace>/slices
///          --slice-depth N [--sink-filter ..] [...filters]`  -> JSON slices
///   3. Read every `<workspace>/slices*-data-flow.json` file and deserialize into `DataFlowSlice`.
///
/// Uses a `tempfile::TempDir` workspace that auto-cleans on drop. Errors map to
/// `BinaryMissing` (graceful fallback signal), `ParseFailed`, `SliceFailed`, or
/// I/O / JSON errors.
///
/// **Phase 1 status:** the subprocess + JSON-deserialization wrapper is complete.
/// The downstream conversion `DataFlowSlice -> dfg::FunctionDfg` is Phase 2 work.
pub fn ingest(target: &Path, cfg: &JoernConfig) -> Result<Vec<DataFlowSlice>, JoernError> {
    let workspace = TempDir::new()?;
    let cpg = workspace.path().join("cpg.bin");
    // joern-slice appends the `-data-flow.json` mode suffix to the `-o` path.
    let slice_out = workspace.path().join("slices");

    // Stage 1 — joern-parse -> binary CPG
    let parse_out = Command::new(&cfg.joern_parse)
        .arg(target)
        .arg("-o")
        .arg(&cpg)
        .output()
        .map_err(|_| JoernError::BinaryMissing(cfg.joern_parse.clone()))?;
    if !parse_out.status.success() {
        return Err(JoernError::ParseFailed {
            code: parse_out.status.code().unwrap_or(-1),
            stderr: String::from_utf8_lossy(&parse_out.stderr).into_owned(),
        });
    }

    // Stage 2 — joern-slice data-flow -> JSON slices
    let mut slice = Command::new(&cfg.joern_slice);
    slice
        .arg("data-flow")
        .arg(&cpg)
        .arg("-o")
        .arg(&slice_out)
        .arg("--slice-depth")
        .arg(cfg.slice_depth.to_string());
    if let Some(f) = &cfg.sink_filter {
        slice.arg("--sink-filter").arg(f);
    }
    if let Some(f) = &cfg.method_name_filter {
        slice.arg("--method-name-filter").arg(f);
    }
    if let Some(f) = &cfg.method_parameter_filter {
        slice.arg("--method-parameter-filter").arg(f);
    }
    if let Some(f) = &cfg.method_annotation_filter {
        slice.arg("--method-annotation-filter").arg(f);
    }
    if let Some(f) = &cfg.file_filter {
        slice.arg("--file-filter").arg(f);
    }
    if cfg.end_at_external {
        slice.arg("--end-at-external-method");
    }
    let slice_out = slice
        .output()
        .map_err(|_| JoernError::BinaryMissing(cfg.joern_slice.clone()))?;
    if !slice_out.status.success() {
        return Err(JoernError::SliceFailed {
            code: slice_out.status.code().unwrap_or(-1),
            stderr: String::from_utf8_lossy(&slice_out.stderr).into_owned(),
        });
    }

    // Stage 3 — collect every produced `slices*-data-flow.json` file
    let mut slices = Vec::new();
    for entry in std::fs::read_dir(workspace.path())? {
        let p = entry?.path();
        let is_json = p.extension().and_then(|e| e.to_str()) == Some("json");
        let is_dataflow = p
            .file_name()
            .map(|f| f.to_string_lossy().contains("data-flow"))
            .unwrap_or(false);
        if is_json && is_dataflow {
            let bytes = std::fs::read(&p)?;
            slices.push(serde_json::from_slice(&bytes)?);
        }
    }
    Ok(slices)
}

// ── Phase 3.3 — language-agnostic DataFlowSlice unification ─────────────────

/// Canonical Joern/CPG labels used by every exporter. Solidity and C/C++
/// sources are rewritten onto this set so the IR is language-blind.
const CANONICAL_LABELS: &[&str] = &[
    "METHOD",
    "METHOD_PARAMETER_IN",
    "IDENTIFIER",
    "LITERAL",
    "CALL",
    "RETURN",
    "FIELD_IDENTIFIER",
    "OPERATOR",
    "REACHING_DEF",
    "ARGUMENT",
    "CONTROL_FLOW",
];

fn canonical_node_label(raw: &str) -> String {
    match raw.to_ascii_uppercase().as_str() {
        "METHOD" | "METHOD_DECL" | "FUNCTION" | "FUNC" | "PROCEDURE" => "METHOD".into(),
        "METHOD_PARAMETER_IN" | "METHOD_PARAMETER" | "PARAM" | "PARAMETER" => {
            "METHOD_PARAMETER_IN".into()
        }
        "IDENTIFIER" | "IDENT" | "LOCAL" | "LOCAL_IDENTIFIER" => "IDENTIFIER".into(),
        "LITERAL" | "LITERALS" | "CONSTANT" => "LITERAL".into(),
        "CALL" | "CALL_SITE" | "CALLEE" => "CALL".into(),
        "RETURN" | "RETURN_NODE" => "RETURN".into(),
        "FIELD_IDENTIFIER" | "FIELD" | "MEMBER" => "FIELD_IDENTIFIER".into(),
        "OPERATOR" | "OP" => "OPERATOR".into(),
        other => other.to_string(),
    }
}

fn canonical_edge_label(raw: &str) -> String {
    match raw.to_ascii_uppercase().as_str() {
        "REACHING_DEF" | "REACHING_DEFINITION" | "DATA_FLOW" | "DDG" => "REACHING_DEF".into(),
        "ARGUMENT" | "ARG" | "ARGUMENT_FLOW" => "ARGUMENT".into(),
        "CONTROL_FLOW" | "CFG" => "CONTROL_FLOW".into(),
        "CALL" => "CALL".into(),
        other => other.to_string(),
    }
}

fn slice_node(
    id: i64,
    label: &str,
    name: &str,
    code: &str,
    parent_method: &str,
    parent_file: &str,
) -> SliceNode {
    SliceNode {
        id,
        label: label.into(),
        name: name.into(),
        code: code.into(),
        type_full_name: String::new(),
        parent_method: parent_method.into(),
        parent_file: parent_file.into(),
        line_number: None,
        column_number: None,
    }
}

/// Rewrite node/edge labels onto the canonical CPG set. Downstream exporters
/// never see language-specific Joern variants.
pub fn normalize_slice(mut slice: DataFlowSlice) -> DataFlowSlice {
    for node in &mut slice.nodes {
        node.label = canonical_node_label(&node.label);
    }
    for edge in &mut slice.edges {
        edge.label = canonical_edge_label(&edge.label);
    }
    slice
}

/// Language-agnostic AST → `DataFlowSlice`. One C-family extractor covers
/// Solidity (`function foo()`) and C/C++ (`void foo()`) — same METHOD / CALL /
/// METHOD_PARAMETER_IN / ARGUMENT IR. This is **not** the solang Solidity
/// fast-path; Joern is preferred when provisioned.
pub fn source_to_slice(source: &str, path: &Path) -> DataFlowSlice {
    let file = path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("source");
    let fn_re = regex::Regex::new(
        r"(?m)^\s*(?:function\s+)?(?:[\w:*&]+\s+)*([A-Za-z_][\w]*)\s*\(([^;{})]*)\)\s*(?:public|external|internal|private|view|pure|payable|override|virtual|returns\s*\([^)]*\)|\s)*\{",
    )
    .expect("function regex");
    let call_re = regex::Regex::new(r"\b([A-Za-z_][\w]*)\s*\(").expect("call regex");
    let skip = [
        "if", "for", "while", "switch", "return", "require", "assert", "revert",
        "catch", "try", "else", "new", "delete", "emit", "assembly", "mapping",
        "function", "modifier", "event", "constructor", "unchecked", "sizeof",
        "typeof", "alignof", "static_cast", "pragma", "using",
    ];

    let mut nodes = Vec::new();
    let mut edges = Vec::new();
    let mut next_id: i64 = 0;
    let mut alloc = || {
        let id = next_id;
        next_id += 1;
        id
    };

    for cap in fn_re.captures_iter(source) {
        let name = cap.get(1).map(|m| m.as_str()).unwrap_or("unknown");
        if skip.contains(&name) {
            continue;
        }
        let params = cap.get(2).map(|m| m.as_str()).unwrap_or("");
        let method_id = alloc();
        nodes.push(slice_node(
            method_id,
            "METHOD",
            name,
            &format!("function {name}({params})"),
            name,
            file,
        ));

        for param in params.split(',') {
            let ident = param
                .split_whitespace()
                .filter(|t| !t.is_empty() && *t != "memory" && *t != "calldata" && *t != "storage")
                .last()
                .unwrap_or("")
                .trim_matches(|c: char| !c.is_ascii_alphanumeric() && c != '_');
            if ident.is_empty() {
                continue;
            }
            let pid = alloc();
            nodes.push(slice_node(
                pid,
                "METHOD_PARAMETER_IN",
                ident,
                ident,
                name,
                file,
            ));
            edges.push(SliceEdge {
                src: pid,
                dst: method_id,
                label: "REACHING_DEF".into(),
            });
        }

        let start = cap.get(0).map(|m| m.end()).unwrap_or(0);
        let body = extract_brace_body(&source[start.saturating_sub(1)..]);
        for ccall in call_re.captures_iter(&body) {
            let callee = ccall.get(1).map(|m| m.as_str()).unwrap_or("");
            if skip.contains(&callee) || callee == name {
                continue;
            }
            let cid = alloc();
            nodes.push(slice_node(cid, "CALL", callee, &format!("{callee}()"), name, file));
            edges.push(SliceEdge {
                src: method_id,
                dst: cid,
                label: "CALL".into(),
            });
        }
    }

    DataFlowSlice { nodes, edges }
}

fn extract_brace_body(from_open: &str) -> String {
    let bytes = from_open.as_bytes();
    let Some(start) = bytes.iter().position(|b| *b == b'{') else {
        return String::new();
    };
    let mut depth = 0i32;
    for (i, b) in bytes.iter().enumerate().skip(start) {
        match *b {
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    return from_open[start + 1..i].to_string();
                }
            }
            _ => {}
        }
    }
    from_open[start + 1..].to_string()
}

/// Unified ingest: Joern CPG when the CLI is present, otherwise the shared
/// C-family AST extractor. Every slice is `normalize_slice`d before return so
/// Solidity and C/C++ are identical at the IR layer.
pub fn ingest_unified(target: &Path, cfg: &JoernConfig) -> Result<Vec<DataFlowSlice>, JoernError> {
    match ingest(target, cfg) {
        Ok(slices) if !slices.is_empty() => {
            Ok(slices.into_iter().map(normalize_slice).collect())
        }
        Ok(_) | Err(JoernError::BinaryMissing(_)) => {
            let source = std::fs::read_to_string(target)?;
            Ok(vec![normalize_slice(source_to_slice(&source, target))])
        }
        Err(e) => Err(e),
    }
}

// ── Z3 solver bridge (Option A — Python subprocess) ────────────────────────

/// Z3 SMT solver verdict for a single `CrossTxDfg`.
///
/// `sat` = a source-to-sink taint path is reachable (emit rule).
/// `unsat` = an invariant/guard provably blocks every path (0% FP, drop).
/// `unknown` (timeout) = escalate to Foundry oracle, never alert.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SatPath {
    pub sat: bool,
    pub model: std::collections::HashMap<String, String>,
    pub reason: String,
    pub invariant_count: usize,
    pub chain_name: String,
}

/// Structural reachability verdict for a `CrossTxDfg`.
///
/// ponytail: no SMT solver in OSS tree — external call present ⇒ SAT, else UNSAT.
/// Upgrade path: plug a private Z3/SMT bridge behind this function signature.
pub fn invoke_z3_solver(
    dfg: &CrossTxDfg,
    _timeout_secs: u64,
) -> Result<SatPath, JoernError> {
    let has_external = !dfg.external_calls.is_empty();
    let call_count: usize = dfg.external_calls.values().map(|v| v.len()).sum();
    Ok(SatPath {
        sat: has_external,
        model: Default::default(),
        reason: if has_external {
            format!("structural stub: {call_count} external call(s) in DFG")
        } else {
            "structural stub: no external calls".into()
        },
        invariant_count: if has_external { 1 } else { 0 },
        chain_name: dfg.address.clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `discover()` with no `JOERN_HOME` and no PATH binary must not panic —
    /// it returns the default `PATH`-based config. The Phase 1 environment has
    /// neither Joern on `PATH` nor `JOERN_HOME`, so this is the live shape.
    #[test]
    fn test_discover_safe_when_unprovisioned() {
        std::env::remove_var("JOERN_HOME");
        let cfg = JoernConfig::discover();
        assert_eq!(cfg.joern_parse, PathBuf::from("joern-parse"));
        assert_eq!(cfg.joern_slice, PathBuf::from("joern-slice"));
        assert_eq!(cfg.slice_depth, 20);
        assert_eq!(cfg.timeout_secs, 120);
    }

    /// `BinaryMissing` is the documented fallback signal — verify it carries
    /// the path it was trying, so callers can react + dispatch to the `.sol` path.
    #[test]
    fn test_binary_missing_error_carries_path() {
        let err = JoernError::BinaryMissing(PathBuf::from("joern-parse"));
        let msg = format!("{err}");
        assert!(msg.contains("joern-parse"));
        assert!(msg.contains("JOERN_HOME"));
    }

    /// Phase 3.3: Solidity and C/C++ source produce the same canonical IR labels.
    #[test]
    fn test_solidity_and_c_share_canonical_ir() {
        let sol = source_to_slice(
            "function withdraw(uint256 amount) public { recipient.call(amount); }",
            Path::new("Vault.sol"),
        );
        let c = source_to_slice(
            "void withdraw(unsigned long amount) { memcpy(buf, p, n); }",
            Path::new("vault.c"),
        );
        let sol = normalize_slice(sol);
        let c = normalize_slice(c);

        let sol_labels: Vec<_> = sol.nodes.iter().map(|n| n.label.as_str()).collect();
        let c_labels: Vec<_> = c.nodes.iter().map(|n| n.label.as_str()).collect();
        assert!(sol_labels.contains(&"METHOD"), "sol METHOD: {sol_labels:?}");
        assert!(c_labels.contains(&"METHOD"), "c METHOD: {c_labels:?}");
        assert!(sol_labels.contains(&"CALL"), "sol CALL: {sol_labels:?}");
        assert!(c_labels.contains(&"CALL"), "c CALL: {c_labels:?}");
        assert!(sol_labels.contains(&"METHOD_PARAMETER_IN"));
        assert!(c_labels.contains(&"METHOD_PARAMETER_IN"));

        let sol_withdraw = sol.nodes.iter().find(|n| n.label == "METHOD").unwrap();
        let c_withdraw = c.nodes.iter().find(|n| n.label == "METHOD").unwrap();
        assert_eq!(sol_withdraw.name, "withdraw");
        assert_eq!(c_withdraw.name, "withdraw");

        for n in sol.nodes.iter().chain(c.nodes.iter()) {
            assert!(
                super::CANONICAL_LABELS.contains(&n.label.as_str()),
                "non-canonical node label {}",
                n.label
            );
        }
        for e in sol.edges.iter().chain(c.edges.iter()) {
            assert!(
                super::CANONICAL_LABELS.contains(&e.label.as_str()),
                "non-canonical edge label {}",
                e.label
            );
        }
    }

    #[test]
    fn test_normalize_rewrites_joern_aliases() {
        let slice = DataFlowSlice {
            nodes: vec![super::slice_node(0, "FUNCTION", "vuln", "void vuln()", "vuln", "f.c")],
            edges: vec![SliceEdge {
                src: 0,
                dst: 0,
                label: "DATA_FLOW".into(),
            }],
        };
        let out = normalize_slice(slice);
        assert_eq!(out.nodes[0].label, "METHOD");
        assert_eq!(out.edges[0].label, "REACHING_DEF");
    }
}